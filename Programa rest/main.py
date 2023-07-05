from flask import Flask, redirect, url_for, session, jsonify, request
from authlib.integrations.flask_client import OAuth
from psycopg2 import connect, extras
from cryptography.fernet import Fernet
from datetime import timedelta
import uuid

# decorator agregando @login_required para rutas a las que solo deben tener acceso los usuarios logueados

app = Flask(__name__)
key = Fernet.generate_key()
app.secret_key = '123456789'
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
# Configuración de oAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='341735264361-p7h8bf5eo7hn7pejlu5u91j8jl79j6qe.apps.googleusercontent.com',
    client_secret='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',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',  # Solo necesario si se utiliza openId para obtener información de usuario
    client_kwargs={'scope': 'openid email profile'},
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs',
)

host = '143.198.53.32'
database = 'grupohdb'
username = 'grupoh'
password = 'Zcb,WsX.cm'
port = 6432

def get_db_connection():
    conn = connect(host=host, database=database, user=username, password=password, port=port)
    return conn

@app.route('/grupoh/login')
def login():
    google = oauth.create_client('google')  # crea el cliente oauth de google
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/grupoh/authorize')
def authorize():
    google = oauth.create_client('google')  # crea el cliente oauth de google
    token = google.authorize_access_token()  # Token de acceso de google (necesario para obtener información de usuario)
    resp = google.get('userinfo')  # userinfo contiene la información especificada en el scope
    user_info = resp.json()
    user = oauth.google.userinfo()  # utiliza el endpoint openid para obtener información de usuario
    session['profile'] = user_info
    jwt_token = token['id_token']  # Obtiene el token JWT de 'access_token' en la respuesta
    session.permanent = True  # hace la sesión permanente para que persista después de cerrar el navegador
    emailgoogle = dict(session)['profile']['email']
    return jsonify(jwt_token,user,session)

@app.route('/grupoh/datosusuario')
def datogoogle():
    return jsonify(session)

@app.route('/grupoh/')
def bienvenido():
    return '<h1>HOLA, BIENVENIDO A LA URNA DE VOTACION. PRIMERO DEBES LOGUEARTE EN ESTE LINK:<a href="/grupoh/login">LOGIN</a></h1>'

# Aquí comienza la API de base de datos
@app.get('/grupoh/api/users')
def get_users():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=extras.RealDictCursor)
    cur.execute("SELECT * FROM usuarios")
    users = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(users)

@app.post('/grupoh/api/users')
def create_user():
    new_user = request.get_json()
    username = new_user['username']
    email = new_user['email']
    password = Fernet(key).encrypt(bytes(new_user['password'], 'utf-8'))
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=extras.RealDictCursor)
    cur.execute("INSERT INTO usuarios (username, email, password) VALUES (%s, %s, %s) RETURNING *",(username, email, password))
    new_user = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(new_user)

@app.get('/grupoh/api/users/<id>')
def get_user(id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=extras.RealDictCursor)
    cur.execute("SELECT * FROM usuarios WHERE id_usuario = %s", (id,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if user is None:
        return jsonify({'message': 'Usuario no existente en la base de datos'})

    return jsonify(user)

@app.put('/grupoh/api/users/<id>')
def update_user(id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=extras.RealDictCursor)
    new_user = request.get_json()
    username = new_user['username']
    email = new_user['email']
    password = Fernet(key).encrypt(bytes(new_user['password'], 'utf-8'))
    cur.execute("UPDATE usuarios SET username = %s, email = %s, password = %s WHERE id_usuario = %s RETURNING *",(username, email, password, id))
    updated_user = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    if updated_user is None:
        return jsonify({'message': 'Usuario no encontrado e imposible de editar'})
    return jsonify(updated_user)

@app.delete('/grupoh/api/users/<id>')
def delete_user(id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=extras.RealDictCursor)
    cur.execute("DELETE FROM usuarios WHERE id_usuario = %s RETURNING *", (id,))
    user = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    if user is None:
        return jsonify({'message': 'Usuario no encontrado'}), 404
    return jsonify(user)

@app.get('/grupoh/api/votos')
def get_votos():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=extras.RealDictCursor)
    cur.execute("SELECT * FROM votos")
    votos = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(votos)

@app.route('/grupoh/api/votar', methods=['POST'])
def create_voto():
    new_voto = request.get_json()
    id_usuario = new_voto['id_usuario']
    id_curso = new_voto['id_curso']
    fecha_votacion = new_voto['fecha_votacion']
    eleccion = new_voto['eleccion']

    if eleccion < 1 or eleccion > 10:
        return jsonify({'message': 'El valor de la elección debe estar entre 1 y 10'}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Verificar si el id del curso existe
        cur.execute("SELECT * FROM cursos WHERE id_curso = %s", (id_curso,))
        curso = cur.fetchone()

        if curso is None:
            return jsonify({'message': 'El curso con el id proporcionado no existe'}), 404

        # Si el curso existe, proceder a insertar el voto
        cur.execute("INSERT INTO votos (id_usuario, id_curso, fecha_votacion, eleccion) VALUES (%s, %s, %s, %s) RETURNING *", (id_usuario, id_curso, fecha_votacion, eleccion))
        new_voto = cur.fetchone()
        conn.commit()
    except Exception as e:
        return jsonify({'message': 'Ocurrió un error al crear el voto: {}'.format(str(e))}), 500
    finally:
        cur.close()
        conn.close()

    return jsonify(new_voto)


@app.route('/grupoh/api/cursos', methods=['POST'])
def create_curso():
    new_curso = request.get_json()
    token = uuid.uuid4() # Genera un nuevo UUIDv4.
    codigo = new_curso['codigo']
    nombre = new_curso['nombre']
    semestre = new_curso['semestre']
    anio = new_curso['anio']

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        cur.execute("INSERT INTO cursos (token, codigo, nombre, semestre, anio) VALUES (%s, %s, %s, %s, %s) RETURNING *",(str(token), codigo, nombre, semestre, anio))
        new_curso = cur.fetchone()
        conn.commit()
    except Exception as e:
        return jsonify({'message': 'Ocurrió un error al crear el curso: {}'.format(str(e))}), 500
    finally:
        cur.close()
        conn.close()

    return jsonify(new_curso)

@app.get('/grupoh/api/cursos/<curso_id>/promedio-votos')
def obtener_promedio_votos(curso_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT AVG(eleccion) FROM votos WHERE id_curso = %s", (curso_id,))
    promedio = cur.fetchone()[0]
    cur.close()
    conn.close()

    if promedio is None:
        return jsonify({'message': 'El curso con el ID proporcionado no tiene votos'})

    return jsonify({'promedio': promedio})

@app.route('/grupoh/logout')
def logout():
    for key in list(session.keys()):
        session.pop(key)
    return redirect('/grupoh/')

if __name__== '__main__':
    app.run(debug=True,host='0.0.0.0', port=8887)