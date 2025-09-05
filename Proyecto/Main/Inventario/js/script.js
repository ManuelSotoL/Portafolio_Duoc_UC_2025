// ------------------------
// Base de datos (solo en memoria)
// ------------------------
let db = {
    products: [],
    warehouses: [],
    movements: [],
    users: [
        { id: "usr1", username: "admin", password: "123456", role: "admin" }
    ]
};

// ------------------------
// Manejo de sesión
// ------------------------
function checkSession() {
    const user = JSON.parse(sessionStorage.getItem("inventrackUser"));
    if (!user) window.location.href = "../index.html";
    return user;
}

function logout() {
    sessionStorage.removeItem("inventrackUser");
    window.location.href = "../index.html";
}

// ------------------------
// Registro de usuarios
// ------------------------
function registerUser(username, password, role = "visor") {
    if (!username || !password) return alert("Completa los campos");
    if (db.users.some(u => u.username === username)) return alert("Usuario ya existe");

    const newUser = { id: "usr" + Date.now(), username, password, role };
    db.users.push(newUser);
    sessionStorage.setItem("inventrackUser", JSON.stringify(newUser)); // Inicia sesión al registrar
    alert("Registro exitoso ✅");
    window.location.href = "Pages/dashboard.html";
}

// ------------------------
// Login
// ------------------------
function login(username, password) {
    const user = db.users.find(u => u.username === username && u.password === password);
    if (!user) return alert("Usuario o contraseña incorrectos ❌");

    sessionStorage.setItem("inventrackUser", JSON.stringify(user));
    alert("Bienvenido " + user.username + " ✅");
    window.location.href = "Pages/dashboard.html";
}

// ------------------------
// Productos
// ------------------------
function initProducts() {
    checkSession();
    renderProducts();
}

function addProduct() {
    const sku = document.getElementById("inputSku").value.trim();
    const name = document.getElementById("inputName").value.trim();
    const minStock = Number(document.getElementById("inputMin").value) || 0;
    if (!sku || !name) return alert("Completa los campos");

    const id = "prd" + Date.now();
    const stocks = {};
    db.warehouses.forEach(w => stocks[w.id] = 0);

    db.products.push({ id, sku, name, minStock, stocks });
    renderProducts();

    document.getElementById("inputSku").value = "";
    document.getElementById("inputName").value = "";
    document.getElementById("inputMin").value = "";
}

function renderProducts() {
    const q = document.getElementById("searchProduct")?.value.toLowerCase() || "";
    const ul = document.getElementById("listProducts");
    if (!ul) return;

    ul.innerHTML = "";
    db.products
      .filter(p => (p.sku + " " + p.name).toLowerCase().includes(q))
      .forEach(p => {
        const li = document.createElement("li");
        li.className = "list-group-item d-flex justify-content-between align-items-center";
        li.innerHTML = `
            ${p.name} (${p.sku}) - Min: ${p.minStock}
            <button class="btn btn-sm btn-outline-danger" onclick="deleteProduct('${p.id}')">Eliminar</button>
        `;
        ul.appendChild(li);
    });
}

function deleteProduct(id) {
    if (!confirm("¿Eliminar producto?")) return;
    db.products = db.products.filter(p => p.id !== id);
    db.movements = db.movements.filter(m => m.productId !== id);
    renderProducts();
}

// ------------------------
// Bodegas
// ------------------------
function initWarehouses() {
    checkSession();
    renderWarehouses();
}

function addWarehouse() {
    const name = document.getElementById("inputWarehouse").value.trim();
    if (!name) return alert("Ingrese nombre de bodega");

    const id = "bod" + Date.now();
    db.products.forEach(p => p.stocks[id] = 0);
    db.warehouses.push({ id, name });
    document.getElementById("inputWarehouse").value = "";
    renderWarehouses();
}

function renderWarehouses() {
    const container = document.getElementById("listWarehouses");
    if (!container) return;
    container.innerHTML = "";

    db.warehouses.forEach(w => {
        const div = document.createElement("div");
        div.className = "p-3 rounded-xl border d-flex justify-content-between align-items-center mb-2";
        div.innerHTML = `
            ${w.name}
            <button class="btn btn-sm btn-outline-danger" onclick="deleteWarehouse('${w.id}')">Eliminar</button>
        `;
        container.appendChild(div);
    });
}

function deleteWarehouse(id) {
    if (!confirm("¿Eliminar bodega? Se perderán existencias")) return;
    db.warehouses = db.warehouses.filter(w => w.id !== id);
    db.products.forEach(p => delete p.stocks[id]);
    renderWarehouses();
}

// ------------------------
// Movimientos
// ------------------------
function initMovements() {
    checkSession();
    renderMovements();
}

function addMovement() {
    const type = document.getElementById("movType").value;
    const productId = document.getElementById("movProduct").value;
    const qty = Number(document.getElementById("movQty").value);
    const fromW = document.getElementById("movFrom").value;
    const toW = document.getElementById("movTo").value;
    const note = document.getElementById("movNote").value;

    if (!productId || qty <= 0) return alert("Datos inválidos");
    const product = db.products.find(p => p.id === productId);
    if (!product) return;

    const movement = { id: "mov" + Date.now(), type, productId, qty, fromW, toW, date: new Date().toISOString(), note };

    db.products = db.products.map(p => {
        if (p.id !== productId) return p;
        const stocks = { ...p.stocks };
        if (type === "IN" && toW) stocks[toW] = (stocks[toW] ?? 0) + qty;
        if (type === "OUT" && fromW) stocks[fromW] = Math.max(0, (stocks[fromW] ?? 0) - qty);
        if (type === "TRANSFER" && fromW && toW && fromW !== toW) {
            stocks[fromW] = Math.max(0, (stocks[fromW] ?? 0) - qty);
            stocks[toW] = (stocks[toW] ?? 0) + qty;
        }
        return { ...p, stocks };
    });

    db.movements.unshift(movement);
    renderMovements();
}

function renderMovements() {
    const container = document.getElementById("listMovements");
    if (!container) return;
    container.innerHTML = "";

    db.movements.forEach(m => {
        const p = db.products.find(p => p.id === m.productId);
        const from = db.warehouses.find(w => w.id === m.fromW)?.name || "";
        const to = db.warehouses.find(w => w.id === m.toW)?.name || "";
        const li = document.createElement("li");
        li.className = "list-group-item";
        li.innerHTML = `
            ${m.type} - ${p?.name} (${p?.sku}) - ${from} → ${to} - Cantidad: ${m.qty} <small>${m.note}</small>
        `;
        container.appendChild(li);
    });
}

// ------------------------
// Usuarios
// ------------------------
function initUsers() {
    checkSession();
    renderUsers();
}

function addUser() {
    const username = document.getElementById("userUsername").value.trim();
    const password = document.getElementById("userPassword").value.trim();
    const role = document.getElementById("userRole").value;

    registerUser(username, password, role); // usa la función de registro central
    document.getElementById("userUsername").value = "";
    document.getElementById("userPassword").value = "";
}

function renderUsers() {
    const container = document.getElementById("listUsers");
    if (!container) return;
    container.innerHTML = "";

    db.users.forEach(u => {
        const div = document.createElement("div");
        div.className = "p-3 rounded-xl border d-flex justify-content-between align-items-center mb-2";
        div.innerHTML = `
            ${u.username} <span class="badge bg-secondary">${u.role}</span>
            <button class="btn btn-sm btn-outline-danger" onclick="deleteUser('${u.id}')">Eliminar</button>
        `;
        container.appendChild(div);
    });
}

function deleteUser(id) {
    const me = JSON.parse(sessionStorage.getItem("inventrackUser"));
    if (id === me.id) return alert("No puedes eliminar tu propio usuario");
    if (!confirm("Eliminar usuario?")) return;
    db.users = db.users.filter(u => u.id !== id);
    renderUsers();
}

// ------------------------
// Dashboard
// ------------------------
function initDashboard() {
    checkSession();
    renderDashboard();
}

function renderDashboard() {
    const container = document.getElementById("dashboardStats");
    if (!container) return;

    const lowStock = [];
    db.products.forEach(p => {
        db.warehouses.forEach(w => {
            if ((p.stocks[w.id] ?? 0) < p.minStock) lowStock.push({ product: p, warehouse: w, qty: p.stocks[w.id] ?? 0 });
        });
    });

    container.innerHTML = `
        <div class="row mb-4">
            <div class="col-md-4"><div class="card p-3"><h5>Productos</h5><p>${db.products.length}</p></div></div>
            <div class="col-md-4"><div class="card p-3"><h5>Bodegas</h5><p>${db.warehouses.length}</p></div></div>
            <div class="col-md-4"><div class="card p-3"><h5>Movimientos</h5><p>${db.movements.length}</p></div></div>
        </div>
        <h5>Alertas de stock bajo</h5>
        <ul class="list-group">
        ${lowStock.length === 0 ? `<li class="list-group-item text-muted">Todo en orden</li>` :
          lowStock.map(a => `<li class="list-group-item">${a.product.name} (${a.product.sku}) - ${a.warehouse.name} Stock: ${a.qty} / Min: ${a.product.minStock}</li>`).join('')}
        </ul>
    `;
}

// ------------------------
// Export CSV
// ------------------------
function downloadCSV(filename, rows) {
    const csvContent = rows.map(r => r.join(",")).join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    link.click();
}
