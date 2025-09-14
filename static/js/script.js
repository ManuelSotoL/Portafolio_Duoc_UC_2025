// ------------------------
// Config & DB helpers
// ------------------------
const ROUTES = {
  login: "../index.html",
  dashboard: "Pages/dashboard.html",
};
const LS_KEY = "inventrackDB";

let db = (() => {
  try {
    const parsed = JSON.parse(localStorage.getItem(LS_KEY));
    if (parsed && typeof parsed === "object") {
      // Asegura estructuras mínimas
      parsed.products = Array.isArray(parsed.products) ? parsed.products : [];
      parsed.warehouses = Array.isArray(parsed.warehouses)
        ? parsed.warehouses
        : [];
      parsed.movements = Array.isArray(parsed.movements)
        ? parsed.movements
        : [];
      parsed.users = Array.isArray(parsed.users) ? parsed.users : [];
      if (!parsed.users.length) {
        parsed.users.push({
          id: "usr1",
          username: "admin",
          password: "123456",
          role: "admin",
        });
      }
      // Normaliza stocks en productos
      parsed.products = parsed.products.map((p) => ({
        ...p,
        stocks: typeof p.stocks === "object" && p.stocks ? p.stocks : {},
      }));
      // Asegura claves de stock para todas las bodegas
      parsed.products = parsed.products.map((p) => {
        const stocks = { ...p.stocks };
        parsed.warehouses.forEach((w) => {
          if (typeof stocks[w.id] !== "number") stocks[w.id] = 0;
        });
        return { ...p, stocks };
      });
      return parsed;
    }
  } catch {}
  // Seed por defecto
  const seed = {
    products: [],
    warehouses: [],
    movements: [],
    users: [
      { id: "usr1", username: "admin", password: "123456", role: "admin" },
    ],
  };
  localStorage.setItem(LS_KEY, JSON.stringify(seed));
  return seed;
})();

function saveDB() {
  localStorage.setItem(LS_KEY, JSON.stringify(db));
}

// Asegura que TODOS los productos tengan clave de stock para TODAS las bodegas
function ensureStocksForWarehouses() {
  db.products = db.products.map((p) => {
    const stocks = { ...(p.stocks || {}) };
    db.warehouses.forEach((w) => {
      if (typeof stocks[w.id] !== "number") stocks[w.id] = 0;
    });
    return { ...p, stocks };
  });
  saveDB();
}

// ------------------------
// Sesión
// ------------------------
function checkSession() {
  const user = JSON.parse(sessionStorage.getItem("inventrackUser"));
  if (!user) window.location.href = ROUTES.login;
  return user;
}

function logout() {
  sessionStorage.removeItem("inventrackUser");
  window.location.href = ROUTES.login;
}

// ------------------------
// Registro / Login
// ------------------------
function registerUser(username, password, role = "visor") {
  const u = (username || "").trim().toLowerCase();
  const p = (password || "").trim();

  if (!u || !p) return alert("Completa los campos");
  if (p.length < 4)
    return alert("La contraseña debe tener al menos 4 caracteres");
  if (db.users.some((x) => (x.username || "").toLowerCase() === u))
    return alert("Usuario ya existe");

  const newUser = { id: "usr" + Date.now(), username: u, password: p, role };
  db.users.push(newUser);
  saveDB();

  sessionStorage.setItem("inventrackUser", JSON.stringify(newUser));
  alert("Registro exitoso ✅");
  window.location.href = ROUTES.dashboard;
}

function login(username, password) {
  const u = (username || "").trim().toLowerCase();
  const p = (password || "").trim();

  const user = db.users.find(
    (x) => (x.username || "").toLowerCase() === u && x.password === p
  );
  if (!user) return alert("Usuario o contraseña incorrectos ❌");

  sessionStorage.setItem("inventrackUser", JSON.stringify(user));
  alert("Bienvenido " + user.username + " ✅");
  window.location.href = ROUTES.dashboard;
}

// ------------------------
// Productos
// ------------------------
function initProducts() {
  checkSession();
  ensureStocksForWarehouses();
  renderProducts();
}

function addProduct() {
  const sku = document.getElementById("inputSku").value.trim();
  const name = document.getElementById("inputName").value.trim();
  const minStock = Number(document.getElementById("inputMin").value) || 0;

  if (!sku || !name) return alert("Completa los campos");
  // Evita SKUs duplicados (case-insensitive)
  if (
    db.products.some((p) => (p.sku || "").toLowerCase() === sku.toLowerCase())
  ) {
    return alert("El SKU ya existe");
  }

  const id = "prd" + Date.now();
  const stocks = {};
  db.warehouses.forEach((w) => (stocks[w.id] = 0));

  db.products.push({ id, sku, name, minStock, stocks });
  saveDB();
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
    .filter((p) => (p.sku + " " + p.name).toLowerCase().includes(q))
    .forEach((p) => {
      const li = document.createElement("li");
      li.className =
        "list-group-item d-flex justify-content-between align-items-center";
      li.innerHTML = `
        ${p.name} (${p.sku}) - Min: ${p.minStock}
        <button class="btn btn-sm btn-outline-danger" onclick="deleteProduct('${p.id}')">Eliminar</button>
      `;
      ul.appendChild(li);
    });
}

function deleteProduct(id) {
  if (!confirm("¿Eliminar producto?")) return;
  db.products = db.products.filter((p) => p.id !== id);
  db.movements = db.movements.filter((m) => m.productId !== id);
  saveDB();
  renderProducts();
}

// ------------------------
// Bodegas
// ------------------------
function initWarehouses() {
  checkSession();
  ensureStocksForWarehouses();
  renderWarehouses();
}

function addWarehouse() {
  const name = document.getElementById("inputWarehouse").value.trim();
  if (!name) return alert("Ingrese nombre de bodega");

  const id = "bod" + Date.now();
  // Agrega clave de stock 0 para todos los productos
  db.products = db.products.map((p) => ({
    ...p,
    stocks: { ...(p.stocks || {}), [id]: 0 },
  }));
  db.warehouses.push({ id, name });

  saveDB();
  document.getElementById("inputWarehouse").value = "";
  renderWarehouses();
}

function renderWarehouses() {
  const container = document.getElementById("listWarehouses");
  if (!container) return;
  container.innerHTML = "";

  db.warehouses.forEach((w) => {
    const div = document.createElement("div");
    div.className =
      "p-3 rounded-xl border d-flex justify-content-between align-items-center mb-2";
    div.innerHTML = `
      ${w.name}
      <button class="btn btn-sm btn-outline-danger" onclick="deleteWarehouse('${w.id}')">Eliminar</button>
    `;
    container.appendChild(div);
  });
}

function deleteWarehouse(id) {
  if (!confirm("¿Eliminar bodega? Se perderán existencias")) return;
  db.warehouses = db.warehouses.filter((w) => w.id !== id);
  db.products = db.products.map((p) => {
    const { [id]: _drop, ...rest } = p.stocks || {};
    return { ...p, stocks: rest };
  });
  saveDB();
  renderWarehouses();
}

// ------------------------
// Movimientos
// ------------------------
function initMovements() {
  checkSession();
  ensureStocksForWarehouses();
  renderMovements();
}

function addMovement() {
  const type = document.getElementById("movType").value; // IN | OUT | TRANSFER
  const productId = document.getElementById("movProduct").value;
  const qty = Number(document.getElementById("movQty").value);
  const fromW = document.getElementById("movFrom").value; // puede venir vacío según tipo
  const toW = document.getElementById("movTo").value; // puede venir vacío según tipo
  const note = (document.getElementById("movNote").value || "").trim();

  if (!productId || qty <= 0) return alert("Datos inválidos");
  const product = db.products.find((p) => p.id === productId);
  if (!product) return alert("Producto no encontrado");

  // Validaciones por tipo
  if (type === "IN") {
    if (!toW) return alert("Selecciona bodega destino");
  }
  if (type === "OUT") {
    if (!fromW) return alert("Selecciona bodega origen");
    const stockFrom = Number(product.stocks?.[fromW] ?? 0);
    if (qty > stockFrom) return alert("Stock insuficiente en bodega de origen");
  }
  if (type === "TRANSFER") {
    if (!fromW || !toW) return alert("Selecciona bodega origen y destino");
    if (fromW === toW) return alert("Origen y destino no pueden ser iguales");
    const stockFrom = Number(product.stocks?.[fromW] ?? 0);
    if (qty > stockFrom) return alert("Stock insuficiente en bodega de origen");
  }

  // Actualiza stocks
  db.products = db.products.map((p) => {
    if (p.id !== productId) return p;
    const stocks = { ...p.stocks };
    if (type === "IN" && toW) stocks[toW] = (stocks[toW] ?? 0) + qty;
    if (type === "OUT" && fromW) stocks[fromW] = (stocks[fromW] ?? 0) - qty;
    if (type === "TRANSFER" && fromW && toW) {
      stocks[fromW] = (stocks[fromW] ?? 0) - qty;
      stocks[toW] = (stocks[toW] ?? 0) + qty;
    }
    return { ...p, stocks };
  });

  // Guarda movimiento
  const movement = {
    id: "mov" + Date.now(),
    type,
    productId,
    qty,
    fromW,
    toW,
    date: new Date().toISOString(),
    note,
  };
  db.movements.unshift(movement);
  saveDB();

  // Limpia inputs y refresca
  document.getElementById("movQty").value = "";
  document.getElementById("movNote").value = "";
  renderMovements();
}

function renderMovements() {
  const container = document.getElementById("listMovements");
  if (!container) return;
  container.innerHTML = "";

  const typeLabel = { IN: "Entrada", OUT: "Salida", TRANSFER: "Transferencia" };

  db.movements.forEach((m) => {
    const p = db.products.find((pp) => pp.id === m.productId);
    const from = db.warehouses.find((w) => w.id === m.fromW)?.name || "";
    const to = db.warehouses.find((w) => w.id === m.toW)?.name || "";
    const li = document.createElement("li");
    li.className = "list-group-item";
    li.innerHTML = `
      <strong>${typeLabel[m.type] || m.type}</strong> - ${p?.name || "(?)"} (${
      p?.sku || "-"
    }) 
      ${from ? `&nbsp;Desde: ${from}` : ""} ${to ? ` → ${to}` : ""} 
      &nbsp;- Cantidad: ${m.qty} ${
      m.note ? `<small class="text-muted">(${m.note})</small>` : ""
    }
      <div><small class="text-muted">${new Date(
        m.date
      ).toLocaleString()}</small></div>
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

  registerUser(username, password, role);
  document.getElementById("userUsername").value = "";
  document.getElementById("userPassword").value = "";
}

function renderUsers() {
  const container = document.getElementById("listUsers");
  if (!container) return;
  container.innerHTML = "";

  db.users.forEach((u) => {
    const div = document.createElement("div");
    div.className =
      "p-3 rounded-xl border d-flex justify-content-between align-items-center mb-2";
    div.innerHTML = `
      ${u.username} <span class="badge bg-secondary">${u.role}</span>
      <button class="btn btn-sm btn-outline-danger" onclick="deleteUser('${u.id}')">Eliminar</button>
    `;
    container.appendChild(div);
  });
}

function deleteUser(id) {
  const me = JSON.parse(sessionStorage.getItem("inventrackUser"));
  if (me && id === me.id) return alert("No puedes eliminar tu propio usuario");
  if (!confirm("¿Eliminar usuario?")) return;

  db.users = db.users.filter((u) => u.id !== id);
  saveDB();
  renderUsers();
}

// ------------------------
// Dashboard
// ------------------------
function initDashboard() {
  checkSession();
  ensureStocksForWarehouses();
  renderDashboard();
}

function renderDashboard() {
  const container = document.getElementById("dashboardStats");
  if (!container) return;

  const lowStock = [];
  db.products.forEach((p) => {
    db.warehouses.forEach((w) => {
      const have = Number(p.stocks?.[w.id] ?? 0);
      const min = Number(p.minStock ?? 0);
      if (have < min) lowStock.push({ product: p, warehouse: w, qty: have });
    });
  });

  container.innerHTML = `
    <div class="row mb-4">
      <div class="col-md-4"><div class="card p-3 text-center"><h5>Productos</h5><div class="display-6">${
        db.products.length
      }</div></div></div>
      <div class="col-md-4"><div class="card p-3 text-center"><h5>Bodegas</h5><div class="display-6">${
        db.warehouses.length
      }</div></div></div>
      <div class="col-md-4"><div class="card p-3 text-center"><h5>Movimientos</h5><div class="display-6">${
        db.movements.length
      }</div></div></div>
    </div>
    <h5>Alertas de stock bajo</h5>
    <ul class="list-group">
      ${
        lowStock.length === 0
          ? `<li class="list-group-item text-muted">Todo en orden</li>`
          : lowStock
              .map(
                (a) =>
                  `<li class="list-group-item">${a.product.name} (${a.product.sku}) - ${a.warehouse.name} · Stock: ${a.qty} / Min: ${a.product.minStock}</li>`
              )
              .join("")
      }
    </ul>
  `;
}

// ------------------------
// Export CSV
// ------------------------
function downloadCSV(filename, rows) {
  if (!rows || !rows.length) return;
  // Escapa comillas y separadores
  const csv = rows
    .map((r) =>
      r.map((v) => `"${String(v ?? "").replace(/"/g, '""')}"`).join(",")
    )
    .join("\n");

  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  link.click();
}
