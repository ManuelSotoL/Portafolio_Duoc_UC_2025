import os
from dotenv import load_dotenv
from flask import Flask, request, render_template, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from itsdangerous import URLSafeTimedSerializer as Serializer

# Cargar variables de entorno desde el archivo .env
load_dotenv()

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Clave secreta para sesiones
app.secret_key = os.getenv("SECRET_KEY")

# Config de MongoDB Atlas usando variables de entorno
MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    raise ValueError("La variable de entorno MONGO_URI no está configurada.")

try:
    client = MongoClient(MONGO_URI)
    client.admin.command('ping') # Prueba la conexión
    db = client['bd']
    collection = db['usuarios']
    print("Conexión a MongoDB exitosa.")
except Exception as e:
    print(f"Error al conectar a MongoDB: {e}")
    # En un entorno de producción, aquí podrías manejar el error de forma más robusta

# Configuración de SendGrid
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')
if not SENDGRID_API_KEY:
    raise ValueError("La variable de entorno SENDGRID_API_KEY no está configurada.")

# Serializador para crear y verificar tokens
serializer = Serializer(app.secret_key, salt='password-reset-salt')

# fn para enviar correos
def enviar_email(destinatario, asunto, cuerpo):
    mensaje = Mail(
        from_email='inventrack.duoc@gmail.com', 
        to_emails=destinatario,
        subject=asunto,
        html_content=cuerpo
    )
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(mensaje)
        print(f"Correo enviado con éxito! Status code: {response.status_code}")
    except Exception as e:
        print(f"Error al enviar el correo: {e}")

@app.route('/')
def home():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('pagina_principal'))

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        usuario = request.form['usuario']
        email = request.form['email']
        contrasena = request.form['contrasena']

        if collection.find_one({'email': email}):
            flash("El correo electrónico ya está registrado.", "error")
            return redirect(url_for('registro'))

        hashed_password = bcrypt.generate_password_hash(contrasena).decode('utf-8')
        collection.insert_one({
            'usuario': usuario,
            'email': email,
            'contrasena': hashed_password
        })
        
        session['usuario'] = usuario
        flash("¡Registro exitoso! Ya puedes iniciar sesión.", "success")
        return redirect(url_for('pagina_principal'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form['usuario']
        contrasena = request.form['contrasena']

        user = collection.find_one({'usuario': usuario})
        
        if user and bcrypt.check_password_hash(user['contrasena'], contrasena):
            session['usuario'] = usuario
            flash("¡Bienvenido!", "success")
            return redirect(url_for('pagina_principal'))
        else:
            flash("Usuario o contraseña incorrectos.", "error")
            return render_template('login.html')

    return render_template('login.html')

@app.route('/pagina_principal')
def pagina_principal():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', usuario=session['usuario'])

@app.route('/mi_perfil')
def mi_perfil():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    
    usuario = session['usuario']
    user_data = collection.find_one({'usuario': usuario})
    if user_data:
        return render_template('mi_perfil.html', usuario=user_data['usuario'], email=user_data['email'])
    else:
        return redirect(url_for('login'))

@app.route('/recuperar_contrasena', methods=['GET', 'POST'])
def recuperar_contrasena():
    if request.method == 'POST':
        email = request.form['email']
        usuario = collection.find_one({'email': email})

        if usuario:
            token = serializer.dumps(email, salt='password-reset-salt')
            enlace = url_for('restablecer_contrasena', token=token, _external=True)
            asunto = "Recuperación de contraseña"
            cuerpo = f"""
            <p>Hola, hemos recibido una solicitud para restablecer tu contraseña.</p>
            <p>Si no has solicitado este cambio, ignora este mensaje.</p>
            <p>Para restablecer tu contraseña, haz clic en el siguiente enlace:</p>
            <a href="{enlace}">Restablecer contraseña</a>
            """
            enviar_email(email, asunto, cuerpo)
            flash("Te hemos enviado un correo para recuperar tu contraseña.", "success")
        else:
            flash("El correo electrónico no está registrado.", "error")

    return render_template('recuperar_contrasena.html')

@app.route('/restablecer_contrasena/<token>', methods=['GET', 'POST'])
def restablecer_contrasena(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash("El enlace de restablecimiento ha caducado o es inválido.", "error")
        return redirect(url_for('recuperar_contrasena'))

    if request.method == 'POST':
        nueva_contrasena = request.form['nueva_contrasena']
        hashed_password = bcrypt.generate_password_hash(nueva_contrasena).decode('utf-8')
        collection.update_one({'email': email}, {'$set': {'contrasena': hashed_password}})
        flash("Tu contraseña ha sido restablecida con éxito.", "success")
        return redirect(url_for('login'))

    return render_template('restablecer_contrasena.html')

@app.route('/logout')
def logout():
    session.pop('usuario', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)