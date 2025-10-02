import os
from dotenv import load_dotenv
from flask import Flask, request, render_template, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from itsdangerous import URLSafeTimedSerializer as Serializer
from functools import wraps

# ====================
#   Config & Setup
# ====================
load_dotenv()

app = Flask(__name__, static_folder="static", template_folder="templates")
bcrypt = Bcrypt(app)

app.secret_key = os.getenv("SECRET_KEY") or "dev-secret-change-me"
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

# --- Serializer ---
serializer = Serializer(app.secret_key, salt="password-reset-salt")

# ====================
#   Helpers de Roles
# ====================

def seed_admin():
    """
    Crea un usuario admin por defecto si no existe ninguno.
    Variables de entorno opcionales:
      ADMIN_USER (default: 'admin')
      ADMIN_EMAIL (default: 'admin@local')
      ADMIN_PASS (default: '123456')
    """
    try:
        any_admin = collection.find_one({"rol": "admin"})
        if any_admin:
            return
        admin_user = os.getenv("ADMIN_USER", "admin").strip()
        admin_email = os.getenv("ADMIN_EMAIL", "admin@local").strip().lower()
        admin_pass = os.getenv("ADMIN_PASS", "123456")

        # Evita duplicados por usuario o email
        exists = collection.find_one({"$or": [{"usuario": admin_user}, {"email": admin_email}]})
        if exists:
            # Si existe pero sin rol, súbelo a admin
            if exists.get("rol") != "admin":
                collection.update_one({"_id": exists["_id"]}, {"$set": {"rol": "admin"}})
            return

        hashed = bcrypt.generate_password_hash(admin_pass).decode("utf-8")
        collection.insert_one({
            "usuario": admin_user,
            "email": admin_email,
            "contrasena": hashed,
            "rol": "admin"
        })
        print(f"Admin semilla creado: {admin_user} / {admin_email}")
    except Exception as e:
        print(f"Error creando admin semilla: {e}")

seed_admin()

def roles_required(*roles):
    """
    Decorador opcional para exigir uno de los roles dados.
    Uso:
      @app.route('/ruta')
      @roles_required('admin', 'operador')
      def vista():
          ...
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if "usuario" not in session:
                return redirect(url_for("login"))
            user_role = session.get("rol")
            if roles and user_role not in roles:
                flash("No tienes permisos para acceder a esta sección.", "error")
                return redirect(url_for("pagina_principal"))
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# Inyección global de 'usuario' y 'rol' en todas las plantillas
@app.context_processor
def inject_user():
    return {
        "usuario": session.get("usuario"),
        "rol": session.get("rol")
    }

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

        # Por defecto, todo usuario creado desde la UI será 'operador'
        rol_por_defecto = "operador"

        hashed_password = bcrypt.generate_password_hash(contrasena).decode("utf-8")
        collection.insert_one({
            "usuario": usuario,
            "email": email,
            "contrasena": hashed_password,
            "rol": rol_por_defecto
        })
        # Si quieres iniciar sesión de inmediato tras registrarse:
        session["usuario"] = usuario
        session["rol"] = rol_por_defecto

        flash("¡Registro exitoso!", "success")
        return redirect(url_for("pagina_principal"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip()
        contrasena = request.form.get("contrasena", "")

        user = collection.find_one({"usuario": usuario})
        if user and bcrypt.check_password_hash(user["contrasena"], contrasena):
            session["usuario"] = user["usuario"]
            session["rol"] = user.get("rol", "operador")  # fallback por si faltara en BD
            return redirect(url_for("pagina_principal"))

        flash("Usuario o contraseña incorrectos.", "error")
        return render_template("login.html")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("usuario", None)
    session.pop("rol", None)
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
    return render_template("mi_perfil.html", email=user.get("email"), rol=user.get("rol"))

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
    # Si más adelante quieres que sólo 'admin' entre aquí:
    # @roles_required('admin')
    return render_template("usuarios.html")

# -------- Manejador de 404 (sin redirección ni flash) --------
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/static") or request.path == "/favicon.ico":
        return ("", 404)
    return "Página no encontrada", 404

if __name__ == "__main__":
    app.run(debug=True)
