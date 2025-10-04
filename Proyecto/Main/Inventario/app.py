import os
from dotenv import load_dotenv
from flask import (
    Flask, request, render_template, redirect, url_for,
    session, flash, jsonify
)
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from itsdangerous import URLSafeTimedSerializer as Serializer
from functools import wraps
from bson.objectid import ObjectId

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
    productos_collection = db["productos"] 
    bodegas_collection = db["bodegas"]
    movimientos_collection = db["movimientos"]
    reportes_collection = db["reportes"]
    print("Conexión a MongoDB exitosa.")

    # Asegura que 'superadm' sea admin si existe
    collection.update_one({"usuario": "superadm"}, {"$set": {"role": "admin"}})
    print("Rol de 'superadm' verificado/actualizado.")

except Exception as e:
    print(f"Error al conectar a MongoDB: {e}")

# --- SendGrid ---
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
if not SENDGRID_API_KEY:
    raise ValueError("La variable de entorno SENDGRID_API_KEY no está configurada.")

# --- Serializer ---
serializer = Serializer(app.secret_key, salt="password-reset-salt")


# ====================
#   Helpers / Roles
# ====================
def seed_admin():
    """
    Crea un usuario admin por defecto si no existe ninguno.
    """
    try:
        any_admin = collection.find_one({"role": "admin"})
        if any_admin:
            return

        admin_user = os.getenv("ADMIN_USER", "admin").strip()
        admin_email = os.getenv("ADMIN_EMAIL", "admin@local").strip().lower()
        admin_pass = os.getenv("ADMIN_PASS", "123456")

        exists = collection.find_one({"$or": [{"usuario": admin_user}, {"email": admin_email}]})
        if exists:
            if exists.get("role") != "admin":
                collection.update_one({"_id": exists["_id"]}, {"$set": {"role": "admin"}})
            return

        hashed = bcrypt.generate_password_hash(admin_pass).decode("utf-8")
        collection.insert_one({
            "usuario": admin_user,
            "email": admin_email,
            "contrasena": hashed,
            "role": "admin"
        })
        print(f"Admin semilla creado: {admin_user} / {admin_email}")
    except Exception as e:
        print(f"Error creando admin semilla: {e}")

seed_admin()


def roles_required(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if "usuario" not in session:
                return redirect(url_for("login"))
            user_role = session.get("role")
            if roles and user_role not in roles:
                flash("No tienes permisos para acceder a esta sección.", "error")
                return redirect(url_for("pagina_principal"))
            return fn(*args, **kwargs)
        return wrapper
    return decorator


@app.context_processor
def inject_user():
    r = session.get("role")
    return {
        "usuario": session.get("usuario"),
        "rol": r,
        "role": r,
    }


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "usuario" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def role_required(required_roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if "usuario" not in session:
                return jsonify({"error": "Acceso no autorizado."}), 401
            user = collection.find_one({"usuario": session.get("usuario")})
            if not user:
                return jsonify({"error": "Usuario no encontrado."}), 404
            user_role = user.get("role", "visor")
            if user_role not in required_roles:
                return jsonify({"error": "No tienes permiso para esta acción."}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


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
        role = "admin" if usuario == "superadm" else "operador"
        if collection.find_one({"usuario": usuario}):
            flash("El nombre de usuario ya está en uso.", "error")
            return redirect(url_for("registro"))
        if collection.find_one({"email": email}):
            flash("El correo electrónico ya está registrado.", "error")
            return redirect(url_for("registro"))
        hashed_password = bcrypt.generate_password_hash(contrasena).decode("utf-8")
        collection.insert_one({
            "usuario": usuario, "email": email, "contrasena": hashed_password, "role": role
        })
        flash("¡Registro exitoso! Ya puedes iniciar sesión.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip()
        contrasena = request.form.get("contrasena", "")
        user = collection.find_one({"usuario": usuario})
        if user and bcrypt.check_password_hash(user["contrasena"], contrasena):
            session["usuario"] = user["usuario"]
            session["role"] = user.get("role", "visor")
            return redirect(url_for("pagina_principal"))
        flash("Usuario o contraseña incorrectos.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
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
                email, "Recuperación de contraseña",
                f"<p>Para restablecer tu contraseña, haz clic en el siguiente enlace:</p><p><a href='{enlace}'>Restablecer contraseña</a></p>"
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


# -------- Páginas principales y Módulos --------
@app.route("/pagina_principal")
@login_required
def pagina_principal(): return render_template("index.html")

@app.route("/mi_perfil")
@login_required
def mi_perfil():
    user = collection.find_one({"usuario": session["usuario"]})
    if not user: return redirect(url_for("logout"))
    return render_template("mi_perfil.html", email=user.get("email"), rol=user.get("role"))

@app.route("/dashboard")
@login_required
def dashboard(): return render_template("dashboard.html")

@app.route("/productos")
@login_required
def productos(): return render_template("productos.html")

@app.route("/bodegas")
@login_required
def bodegas(): return render_template("bodegas.html")

@app.route("/movimientos")
@login_required
def movimientos(): return render_template("movimientos.html")

@app.route("/reportes")
@login_required
def reportes(): return render_template("reportes.html")

@app.route("/usuarios")
@login_required
def usuarios(): return render_template("usuarios.html")


# =================================
#           RUTAS DE API
# =================================

# --- API Dashboard ---
@app.route("/api/dashboard/stats", methods=["GET"])
@login_required
def get_dashboard_stats():
    """Recopila y devuelve todas las estadísticas para el panel de control."""
    try:
        product_count = productos_collection.count_documents({})
        warehouse_count = bodegas_collection.count_documents({})
        movement_count = movimientos_collection.count_documents({})
        
        # Lógica para encontrar alertas de stock bajo
        low_stock_alerts = []
        bodegas = list(bodegas_collection.find({}, {"_id": 1, "name": 1}))
        bodegas_map = {str(b["_id"]): b["name"] for b in bodegas}
        
        productos_con_stock = productos_collection.find({}, {"name": 1, "sku": 1, "stocks": 1, "minStock": 1})

        for p in productos_con_stock:
            min_stock = p.get("minStock", 0)
            for bodega_id, stock_actual in p.get("stocks", {}).items():
                if stock_actual <= min_stock:
                    bodega_name = bodegas_map.get(bodega_id, "Desconocida")
                    low_stock_alerts.append({
                        "product_name": p["name"],
                        "product_sku": p["sku"],
                        "warehouse_name": bodega_name,
                        "stock": stock_actual,
                        "min_stock": min_stock
                    })

        stats = {
            "product_count": product_count,
            "warehouse_count": warehouse_count,
            "movement_count": movement_count,
            "low_stock_alerts": low_stock_alerts
        }
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- API Usuarios ---
@app.route("/api/user_role")
@login_required
def get_user_role():
    user = collection.find_one({"usuario": session["usuario"]})
    return jsonify({"role": user.get("role", "visor")})

@app.route("/api/users", methods=["GET", "POST"])
@login_required
@role_required(["admin"])
def users_api():
    if request.method == "GET":
        users = list(collection.find({}, {"_id": 1, "usuario": 1, "role": 1, "email": 1}))
        for user in users: user["_id"] = str(user["_id"])
        return jsonify(users)
    data = request.json
    collection.insert_one({
        "usuario": data["name"], "email": data["username"].lower(),
        "contrasena": bcrypt.generate_password_hash(data["password"]).decode("utf-8"), "role": data["role"]
    })
    return jsonify({"message": "Usuario registrado con éxito."}), 201

@app.route("/api/users/<user_id>", methods=["PUT", "DELETE"])
@login_required
@role_required(["admin"])
def manage_user(user_id):
    user_obj_id = ObjectId(user_id)
    if request.method == "PUT":
        collection.update_one({"_id": user_obj_id}, {"$set": {"role": request.json["role"]}})
        return jsonify({"message": "Rol actualizado."})
    collection.delete_one({"_id": user_obj_id})
    return jsonify({"message": "Usuario eliminado."})

# --- API Productos ---
@app.route("/api/productos", methods=["GET", "POST"])
@login_required
def api_productos():
    if request.method == "GET":
        productos = list(productos_collection.find({}))
        bodegas_map = {str(b["_id"]): b["name"] for b in bodegas_collection.find({}, {"name":1})}
        for p in productos:
            p["id"] = str(p.pop("_id"))
            p["bodegas_info"] = [
                {"name": bodegas_map.get(b_id), "stock": s}
                for b_id, s in p.get("stocks", {}).items() if b_id in bodegas_map
            ]
        return jsonify(productos)
    data = request.json
    initial_stocks = {str(b["_id"]): 0 for b in bodegas_collection.find({}, {"_id": 1})}
    result = productos_collection.insert_one({
        "sku": data["sku"], "name": data["name"], "minStock": data.get("minStock", 0), "stocks": initial_stocks
    })
    new_product = productos_collection.find_one({"_id": result.inserted_id})
    new_product["id"] = str(new_product.pop("_id"))
    return jsonify(new_product), 201

@app.route("/api/productos/<product_id>", methods=["PUT", "DELETE"])
@role_required(["admin", "operador"])
def manage_producto(product_id):
    obj_id = ObjectId(product_id)
    if request.method == "PUT":
        data = request.json
        productos_collection.update_one({"_id": obj_id}, {"$set": data})
        return jsonify({"message": "Producto actualizado."})
    productos_collection.delete_one({"_id": obj_id})
    return jsonify({"message": "Producto eliminado."})


# --- API Bodegas y Stock ---
@app.route("/api/bodegas", methods=["GET", "POST"])
@login_required
def api_bodegas():
    if request.method == "GET":
        bodegas = list(bodegas_collection.find({}, {"_id": 1, "name": 1}))
        for b in bodegas: b["id"] = str(b.pop("_id"))
        return jsonify(bodegas)
    name = request.json["name"]
    result = bodegas_collection.insert_one({"name": name})
    return jsonify({"id": str(result.inserted_id), "name": name}), 201

@app.route("/api/bodegas/<bodega_id>", methods=["DELETE"])
@role_required(["admin"])
def delete_bodega(bodega_id):
    bodegas_collection.delete_one({"_id": ObjectId(bodega_id)})
    productos_collection.update_many({}, {"$unset": {f"stocks.{bodega_id}": ""}})
    return jsonify({"message": "Bodega eliminada."})

@app.route("/api/bodegas/<bodega_id>/productos", methods=["GET"])
@login_required
def get_productos_stock(bodega_id):
    productos = list(productos_collection.find({}, {"_id": 1, "name": 1, "sku": 1, "stocks": 1}))
    for p in productos:
        p["id"] = str(p.pop("_id"))
        stocks = p.get("stocks", {})
        p["stock_en_bodega"] = stocks.get(bodega_id, 0)
        p["stock_total"] = sum(stocks.values())
    return jsonify(productos)

@app.route("/api/bodegas/<bodega_id>/stocks", methods=["POST"])
@role_required(["admin"])
def save_stocks(bodega_id):
    for item in request.json:
        productos_collection.update_one(
            {"_id": ObjectId(item["productId"])},
            {"$set": {f"stocks.{bodega_id}": int(item["stock"])}}
        )
    return jsonify({"message": "Stocks actualizados."})


# -------- Manejador de 404 --------
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith(("/static", "/favicon.ico")): return ("", 404)
    return "Página no encontrada", 404

if __name__ == "__main__":
    app.run(debug=True)