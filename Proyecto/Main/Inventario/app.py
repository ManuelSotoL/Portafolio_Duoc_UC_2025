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
from datetime import datetime  # <-- añadido para fechas en movimientos

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
    # Usa lo que haya en sesión y, si no encontramos al usuario en BD,
    # NO cerramos sesión: mostramos el perfil con los datos de la sesión.
    username = session.get("usuario")
    user = collection.find_one({"usuario": username})

    if not user:
        flash("No pudimos cargar tus datos de perfil desde la base de datos. Mostrando la información de tu sesión.", "error")
        return render_template(
            "mi_perfil.html",
            email="",                         # sin email porque no lo obtuvimos de BD
            rol=session.get("role", "visor")  # rol desde sesión como respaldo
        )

    return render_template("mi_perfil.html", email=user.get("email", ""), rol=user.get("role", "visor"))

@app.route("/mi_perfil/cambiar_contrasena", methods=["POST"])
@login_required
def cambiar_contrasena():
    username = session.get("usuario")
    user = collection.find_one({"usuario": username})

    if not user:
        flash("No pudimos verificar tu usuario. Intenta iniciar sesión nuevamente.", "error")
        return redirect(url_for("login"))

    actual   = request.form.get("current_password", "")
    nueva    = request.form.get("new_password", "")
    confirmar = request.form.get("confirm_password", "")

    # Validaciones
    if not actual or not nueva or not confirmar:
        flash("Completa todos los campos.", "error")
        return redirect(url_for("mi_perfil"))

    if not bcrypt.check_password_hash(user["contrasena"], actual):
        flash("La contraseña actual no es correcta.", "error")
        return redirect(url_for("mi_perfil"))

    if len(nueva) < 6:
        flash("La nueva contraseña debe tener al menos 6 caracteres.", "error")
        return redirect(url_for("mi_perfil"))

    if nueva != confirmar:
        flash("La confirmación no coincide con la nueva contraseña.", "error")
        return redirect(url_for("mi_perfil"))

    # Actualizar en BD
    hashed = bcrypt.generate_password_hash(nueva).decode("utf-8")
    collection.update_one({"_id": user["_id"]}, {"$set": {"contrasena": hashed}})

    flash("¡Contraseña actualizada correctamente!", "success")
    return redirect(url_for("mi_perfil"))



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
    username = session.get("usuario")
    user = collection.find_one({"usuario": username})
    role = user.get("role", "visor") if user else session.get("role", "visor")
    return jsonify({"role": role})

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


# --- API Movimientos ---
def _inc_stock(product_id: str, warehouse_id: str, delta: int):
    """
    Incrementa/decrementa el stock de un producto en una bodega específica.
    product_id: string con el _id del producto (ObjectId en texto)
    warehouse_id: string con el _id de la bodega (ObjectId en texto)
    delta: entero (positivo o negativo)
    """
    productos_collection.update_one(
        {"_id": ObjectId(product_id)},
        {"$inc": {f"stocks.{warehouse_id}": int(delta)}},
        upsert=False
    )

@app.route("/api/movimientos", methods=["GET"])
@login_required
def api_list_movimientos():
    """
    Lista los movimientos ordenados del más reciente al más antiguo.
    Devuelve campos: id, type, productId, qty, fromW, toW, note, date
    """
    docs = list(movimientos_collection.find({}).sort([("_id", -1)]))
    for d in docs:
        d["id"] = str(d.pop("_id"))
    return jsonify(docs), 200


@app.route("/api/movimientos", methods=["POST"])
@login_required
@role_required(["admin", "operador"])
def api_create_movimiento():
    """
    Crea un movimiento y actualiza stocks en BD.
    Body JSON: { type: IN|OUT|TRANSFER, productId, qty, fromW?, toW?, note? }
    - IN:   requiere toW
    - OUT:  requiere fromW
    - TRANSFER: requiere fromW y toW distintos
    """
    data = request.get_json(silent=True) or {}
    mtype  = data.get("type")
    pid    = data.get("productId")  # _id del producto en texto
    qty    = int(data.get("qty", 0))
    fromW  = (data.get("fromW") or None)
    toW    = (data.get("toW")   or None)
    note   = (data.get("note")  or "").strip()

    # Validaciones básicas
    if mtype not in ("IN", "OUT", "TRANSFER"):
        return jsonify({"error": "Tipo inválido. Debe ser IN, OUT o TRANSFER"}), 400
    if qty <= 0:
        return jsonify({"error": "Cantidad inválida"}), 400
    if mtype == "IN" and not toW:
        return jsonify({"error": "Entrada requiere bodega destino"}), 400
    if mtype == "OUT" and not fromW:
        return jsonify({"error": "Salida requiere bodega origen"}), 400
    if mtype == "TRANSFER":
        if not fromW or not toW or fromW == toW:
            return jsonify({"error": "Transferencia requiere bodegas distintas (fromW y toW)"}), 400

    # Validar producto
    try:
        prod = productos_collection.find_one({"_id": ObjectId(pid)})
    except Exception:
        prod = None
    if not prod:
        return jsonify({"error": "Producto no encontrado"}), 404

    # Validar bodegas (cuando apliquen)
    if fromW:
        try:
            exists_from = bodegas_collection.find_one({"_id": ObjectId(fromW)})
        except Exception:
            exists_from = None
        if not exists_from:
            return jsonify({"error": "Bodega origen no existe"}), 400

    if toW:
        try:
            exists_to = bodegas_collection.find_one({"_id": ObjectId(toW)})
        except Exception:
            exists_to = None
        if not exists_to:
            return jsonify({"error": "Bodega destino no existe"}), 400

    # Chequear stock suficiente para OUT / TRANSFER
    if mtype in ("OUT", "TRANSFER"):
        current = int(prod.get("stocks", {}).get(fromW, 0))
        if current < qty:
            return jsonify({"error": f"Stock insuficiente en bodega origen. Actual: {current}"}), 400

    # Actualizar stocks en BD
    if mtype == "IN":
        _inc_stock(pid, toW, +qty)
    elif mtype == "OUT":
        _inc_stock(pid, fromW, -qty)
    else:  # TRANSFER
        _inc_stock(pid, fromW, -qty)
        _inc_stock(pid, toW, +qty)

    doc = {
        "type": mtype,
        "productId": pid,
        "qty": qty,
        "fromW": fromW,
        "toW": toW,
        "note": note,
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    ins = movimientos_collection.insert_one(doc)
    doc["id"] = str(ins.inserted_id)
    doc.pop("_id", None)
    return jsonify(doc), 201


@app.route("/api/movimientos/<mid>", methods=["DELETE"])
@login_required
@role_required(["admin", "operador"])
def api_delete_movimiento(mid):
    """
    Elimina un movimiento y revierte su efecto de stock en BD.
    """
    try:
        mov = movimientos_collection.find_one({"_id": ObjectId(mid)})
    except Exception:
        mov = None
    if not mov:
        return jsonify({"error": "Movimiento no encontrado"}), 404

    mtype = mov.get("type")
    pid   = mov.get("productId")
    qty   = int(mov.get("qty", 0))
    fromW = mov.get("fromW")
    toW   = mov.get("toW")

    # Revertir stocks según el tipo
    if mtype == "IN":
        if toW:
            _inc_stock(pid, toW, -qty)
    elif mtype == "OUT":
        if fromW:
            _inc_stock(pid, fromW, +qty)
    elif mtype == "TRANSFER":
        if fromW:
            _inc_stock(pid, fromW, +qty)
        if toW:
            _inc_stock(pid, toW, -qty)

    movimientos_collection.delete_one({"_id": ObjectId(mid)})
    return jsonify({"ok": True}), 200


# --- API Reportes (stock y resúmenes) ---
@app.route("/api/reportes/stock", methods=["GET"])
@login_required
def api_reportes_stock():
    """
    Reporte de:
      - low_stock: productos en/bajo mínimo (filtrable por bodega y texto)
      - summary:   detalle por bodega (con is_low por producto). Si onlyLow=true, solo items en/bajo mínimo.

    Query params:
      q       : texto (nombre o SKU)
      wid     : id de bodega (ObjectId en string). Si vacío, todas.
      onlyLow : true/false  (si true, low_stock y summary mostrarán solo bajo mínimo)
    """
    try:
        q = (request.args.get("q") or "").strip().lower()
        wid = (request.args.get("wid") or "").strip() or None
        only_low = str(request.args.get("onlyLow", "false")).lower() in ("1", "true", "yes")

        # Map de bodegas: { "<_id>": "name" }
        bodegas = list(bodegas_collection.find({}, {"_id": 1, "name": 1}))
        bodegas_map = {str(b["_id"]): b["name"] for b in bodegas}

        # Traer productos con campos necesarios
        productos = list(productos_collection.find({}, {"_id": 1, "name": 1, "sku": 1, "stocks": 1, "minStock": 1}))

        low_stock = []
        summary = []

        for p in productos:
            name = p.get("name", "") or ""
            sku = p.get("sku", "") or ""
            # Filtro por texto (producto o SKU) - aplica a ambos bloques
            if q and (q not in name.lower() and q not in sku.lower()):
                continue

            min_stock = int(p.get("minStock", 0) or 0)
            stocks = p.get("stocks", {}) or {}

            # Determinar las bodegas a revisar
            bodega_ids = [wid] if wid else list(stocks.keys())
            if not bodega_ids:
                # Si no hay claves de stock, no hay nada que reportar
                continue

            for b_id in bodega_ids:
                qty = int(stocks.get(b_id, 0) or 0)
                bname = bodegas_map.get(b_id, "Desconocida")
                is_low = qty <= min_stock

                # low_stock: siempre son solo bajo mínimo; si no hay casos, quedará vacío
                if is_low:
                    low_stock.append({
                        "product_name": name,
                        "product_sku": sku,
                        "warehouse_name": bname,
                        "qty": qty,
                        "min_stock": min_stock
                    })

                # summary: si onlyLow=true, solo incluir bajo mínimo; si false, incluir todo
                if only_low and not is_low:
                    continue

                summary.append({
                    "warehouse_name": bname,
                    "product_name": name,
                    "product_sku": sku,
                    "qty": qty,
                    "min_stock": min_stock,
                    "is_low": is_low
                })

        return jsonify({"low_stock": low_stock, "summary": summary}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500



# -------- Manejador de 404 --------
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith(("/static", "/favicon.ico")): return ("", 404)
    return "Página no encontrada", 404

if __name__ == "__main__":
    app.run(debug=True)
