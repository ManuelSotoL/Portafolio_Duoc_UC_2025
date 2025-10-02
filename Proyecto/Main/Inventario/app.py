import os
from dotenv import load_dotenv
from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from itsdangerous import URLSafeTimedSerializer as Serializer
from functools import wraps
from bson.objectid import ObjectId

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
        role = "operador" # Nuevo usuario por defecto es operador

        if collection.find_one({"email": email}):
            flash("El correo electrónico ya está registrado.", "error")
            return redirect(url_for("registro"))

        hashed_password = bcrypt.generate_password_hash(contrasena).decode("utf-8")
        collection.insert_one({
            "usuario": usuario,
            "email": email,
            "contrasena": hashed_password,
            "role": role
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

# --- Rutas de API para gestión de usuarios ---

@app.route("/api/user_role")
@login_required
def get_user_role():
    user = collection.find_one({"usuario": session["usuario"]})
    return jsonify({"role": user.get("role", "operador")})

@app.route("/api/users", methods=["GET", "POST"])
@login_required
def users_api():
    current_user = collection.find_one({"usuario": session["usuario"]})
    user_role = current_user.get("role", "operador")

    if request.method == "GET":
        users = list(collection.find({}, {"_id": 1, "usuario": 1, "role": 1}))
        for user in users:
            user["_id"] = str(user["_id"])
        return jsonify(users), 200

    if request.method == "POST":
        if user_role != "admin":
            return jsonify({"error": "No tienes permiso para realizar esta acción."}), 403

        data = request.json
        name = data.get("name")
        email = data.get("username").lower()
        contrasena = data.get("password")
        role = data.get("role")

        if not all([name, email, contrasena, role]):
            return jsonify({"error": "Faltan datos."}), 400

        if collection.find_one({"email": email}):
            return jsonify({"error": "El correo ya está registrado."}), 409

        hashed_password = bcrypt.generate_password_hash(contrasena).decode("utf-8")
        collection.insert_one({
            "usuario": name,
            "email": email,
            "contrasena": hashed_password,
            "role": role
        })

        return jsonify({"message": "Usuario registrado con éxito."}), 201

@app.route("/api/users/<user_id>", methods=["PUT", "DELETE"])
@login_required
def manage_user(user_id):
    current_user = collection.find_one({"usuario": session["usuario"]})
    if current_user.get("role") != "admin":
        return jsonify({"error": "No tienes permiso para realizar esta acción."}), 403

    try:
        user_obj_id = ObjectId(user_id)
    except:
        return jsonify({"error": "ID de usuario inválido."}), 400

    if request.method == "PUT":
        data = request.json
        new_role = data.get("role")
        
        # Validación: un admin no puede cambiar su propio rol
        if current_user["_id"] == user_obj_id:
            return jsonify({"error": "No puedes cambiar tu propio rol."}), 403

        if new_role not in ["admin", "operador", "visor"]:
            return jsonify({"error": "Rol inválido."}), 400
        
        collection.update_one(
            {"_id": user_obj_id},
            {"$set": {"role": new_role}}
        )
        return jsonify({"message": "Rol actualizado con éxito."}), 200

    if request.method == "DELETE":
        if current_user["_id"] == user_obj_id:
            return jsonify({"error": "No puedes eliminar tu propio usuario."}), 403

        admin_count = collection.count_documents({"role": "admin"})
        user_to_delete = collection.find_one({"_id": user_obj_id})
        
        if user_to_delete and user_to_delete.get("role") == "admin" and admin_count <= 1:
            return jsonify({"error": "Debe haber al menos un administrador en el sistema."}), 403
            
        collection.delete_one({"_id": user_obj_id})
        return jsonify({"message": "Usuario eliminado con éxito."}), 200

# -------- Manejador de 404 (sin redirección ni flash) --------
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/static") or request.path == "/favicon.ico":
        return ("", 404)
    return "Página no encontrada", 404

if __name__ == "__main__":
    app.run(debug=True)