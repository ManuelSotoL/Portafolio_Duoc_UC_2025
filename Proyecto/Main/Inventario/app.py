import os
from dotenv import load_dotenv
from flask import Flask, request, render_template, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from itsdangerous import URLSafeTimedSerializer as Serializer
from functools import wraps

# Cargar variables de entorno
load_dotenv()

app = Flask(__name__, static_folder="static", template_folder="templates")
bcrypt = Bcrypt(app)

# Clave secreta para sesiones (fallback en dev)
app.secret_key = os.getenv("SECRET_KEY") or "dev-secret-change-me"
# Evitar cache de estáticos en desarrollo
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

# --- MongoDB ---
MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    raise ValueError("La variable de entorno MONGO_URI no está configurada.")
try:
    client = MongoClient(MONGO_URI)
    client.admin.command("ping")
    db = client["bd"]
    collection = db["usuarios"]
    print("Conexión a MongoDB exitosa.")
except Exception as e:
    print(f"Error al conectar a MongoDB: {e}")

# --- SendGrid ---
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
if not SENDGRID_API_KEY:
    raise ValueError("La variable de entorno SENDGRID_API_KEY no está configurada.")

# Serializador para tokens
serializer = Serializer(app.secret_key, salt="password-reset-salt")

# Inyección global de 'usuario' en todas las plantillas
@app.context_processor
def inject_user():
    return {"usuario": session.get("usuario")}

# Decorador simple para exigir sesión
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "usuario" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

# --- Email helper ---
def enviar_email(destinatario, asunto, cuerpo_html):
    mensaje = Mail(
        from_email="inventrack.duoc@gmail.com",
        to_emails=destinatario,
        subject=asunto,
        html_content=cuerpo_html,
    )
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(mensaje)
        print(f"Correo enviado (status {response.status_code})")
    except Exception as e:
        print(f"Error al enviar correo: {e}")

# ====================
#        RUTAS
# ====================

@app.route("/")
def home():
    if "usuario" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("pagina_principal"))

# -------- Autenticación --------
@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        usuario = request.form["usuario"].strip()
        email = request.form["email"].strip().lower()
        contrasena = request.form["contrasena"]

        if collection.find_one({"email": email}):
            flash("El correo electrónico ya está registrado.", "error")
            return redirect(url_for("registro"))

        hashed_password = bcrypt.generate_password_hash(contrasena).decode("utf-8")
        collection.insert_one({
            "usuario": usuario,
            "email": email,
            "contrasena": hashed_password
        })
        session["usuario"] = usuario
        flash("¡Registro exitoso! Ya puedes iniciar sesión.", "success")
        return redirect(url_for("pagina_principal"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario = request.form["usuario"].strip()
        contrasena = request.form["contrasena"]

        user = collection.find_one({"usuario": usuario})
        if user and bcrypt.check_password_hash(user["contrasena"], contrasena):
            session["usuario"] = usuario
            # No mostramos mensaje de "Bienvenido"
            return redirect(url_for("pagina_principal"))

        flash("Usuario o contraseña incorrectos.", "error")
        return render_template("login.html")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("usuario", None)
    flash("Sesión cerrada.", "success")
    return redirect(url_for("login"))

# -------- Recuperación de contraseña --------
@app.route("/recuperar_contrasena", methods=["GET", "POST"])
def recuperar_contrasena():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        usuario = collection.find_one({"email": email})
        if usuario:
            token = serializer.dumps(email, salt="password-reset-salt")
            enlace = url_for("restablecer_contrasena", token=token, _external=True)
            enviar_email(
                email,
                "Recuperación de contraseña",
                f"""
                <p>Hola, hemos recibido una solicitud para restablecer tu contraseña.</p>
                <p>Si no has solicitado este cambio, ignora este mensaje.</p>
                <p>Para restablecer tu contraseña, haz clic en el siguiente enlace:</p>
                <p><a href="{enlace}">Restablecer contraseña</a></p>
                """
            )
            flash("Te enviamos un correo para recuperar tu contraseña.", "success")
        else:
            flash("El correo electrónico no está registrado.", "error")

    return render_template("recuperar_contrasena.html")

@app.route("/restablecer_contrasena/<token>", methods=["GET", "POST"])
def restablecer_contrasena(token):
    try:
        email = serializer.loads(token, salt="password-reset-salt", max_age=3600)
    except Exception:
        flash("El enlace de restablecimiento ha caducado o es inválido.", "error")
        return redirect(url_for("recuperar_contrasena"))

    if request.method == "POST":
        nueva = request.form["nueva_contrasena"]
        hashed = bcrypt.generate_password_hash(nueva).decode("utf-8")
        collection.update_one({"email": email}, {"$set": {"contrasena": hashed}})
        flash("Tu contraseña ha sido restablecida con éxito.", "success")
        return redirect(url_for("login"))

    return render_template("restablecer_contrasena.html")

# -------- Páginas principales --------
@app.route("/pagina_principal")
@login_required
def pagina_principal():
    return render_template("index.html")

@app.route("/mi_perfil")
@login_required
def mi_perfil():
    user = collection.find_one({"usuario": session["usuario"]})
    if not user:
        return redirect(url_for("logout"))
    return render_template("mi_perfil.html", email=user.get("email"))

# -------- Módulos --------
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route("/productos")
@login_required
def productos():
    return render_template("productos.html")

@app.route("/bodegas")
@login_required
def bodegas():
    return render_template("bodegas.html")

@app.route("/movimientos")
@login_required
def movimientos():
    return render_template("movimientos.html")

@app.route("/reportes")
@login_required
def reportes():
    return render_template("reportes.html")

@app.route("/usuarios")
@login_required
def usuarios():
    return render_template("usuarios.html")

# -------- Manejador de 404 (sin redirección ni flash) --------
@app.errorhandler(404)
def not_found(e):
    # Evitar “spam” si falla un estático o el favicon
    if request.path.startswith("/static") or request.path == "/favicon.ico":
        return ("", 404)
    # Muestra 404 simple; si tienes templates/404.html, puedes renderizarlo
    return "Página no encontrada", 404

if __name__ == "__main__":
    app.run(debug=True)
