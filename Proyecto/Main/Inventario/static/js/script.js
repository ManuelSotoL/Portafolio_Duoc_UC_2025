// ===================================================
// script.js SIN localStorage / sessionStorage
// Mantiene nombres de funciones, pero sin persistencia.
// Las validaciones reales y datos vendrán del BACKEND.
// ===================================================

// Rutas (usadas solo para redirecciones suaves)
const ROUTES = {
  login: (window.URLS && window.URLS.login) || "/login",
  dashboard: "/dashboard",
};

// ---------- Helpers de sesión (solo UX, no persistencia) ----------
function isAuth() {
  return !!window.IS_AUTH; // Inyectado por Flask
}

function checkSession() {
  if (!isAuth()) window.location.href = ROUTES.login;
  return isAuth();
}

function logout() {
  // El backend limpia la sesión; acá solo redirigimos
  const url = (window.URLS && window.URLS.logout) || "/logout";
  window.location.href = url;
}

// ---------- Placeholders de datos (frontend solo lectura por ahora) ----------
function warnDisabled(feature) {
  console.warn(`[Desactivado] ${feature} ahora lo maneja el backend.`);
  alert(`${feature} está desactivado en el frontend.\nLa lógica y los datos ahora los manejará el servidor.`);
}

function renderPlaceholder(el, title = "Sin datos", subtitle = "Los datos vendrán del servidor") {
  if (!el) return;
  el.innerHTML = `
    <div class="card p-3 text-center shadow-sm">
      <div class="fw-bold mb-1">${title}</div>
      <div class="text-muted">${subtitle}</div>
    </div>
  `;
}

// ===================================================
// Productos
// ===================================================
function initProducts() {
  if (!checkSession()) return;
  // Aquí en el futuro: fetch('/api/productos') y pintar
  const container = document.getElementById("productsContainer") || document.getElementById("listProducts");
  renderPlaceholder(container, "Productos", "Se cargarán desde el servidor");
  const newBtn = document.getElementById("btnNuevoProducto");
  if (newBtn) newBtn.style.display = "none"; // UX: oculto crear hasta tener backend
}

function addProduct() {
  warnDisabled("Crear/editar/eliminar productos");
}

function renderProducts() {
  // Placeholder (ya mostrado en initProducts)
}

function deleteProduct(id) {
  warnDisabled("Eliminar producto");
}

function openEdit(id) {
  warnDisabled("Editar producto");
}

function saveEdit() {
  warnDisabled("Guardar edición de producto");
}

// ===================================================
// Bodegas
// ===================================================
function initWarehouses() {
  if (!checkSession()) return;
  renderPlaceholder(document.getElementById("warehousesList"), "Bodegas", "Se cargarán desde el servidor");
  renderPlaceholder(document.getElementById("assignSection"), "Asignación de stock", "Se cargará desde el servidor");
  const btn = document.getElementById("btnSaveStocks");
  if (btn) btn.disabled = true;
}

function addWarehouse() { warnDisabled("Crear bodega"); }
function renderWarehouses() { /* placeholder ya en init */ }
function renderWarehouseSelector() { /* backend luego */ }
function renderProductStocksTable() { /* backend luego */ }
function saveStocksForWarehouse() { warnDisabled("Guardar stocks por bodega"); }
function deleteWarehouse() { warnDisabled("Eliminar bodega"); }

// ===================================================
// Movimientos
// ===================================================
function initMovements() {
  if (!checkSession()) return;
  renderPlaceholder(document.getElementById("movementsList"), "Movimientos", "Se cargarán desde el servidor");
  const form = document.getElementById("movementFormContainer");
  renderPlaceholder(form, "Registrar movimiento", "Formulario vendrá del servidor");
}

function addMovement() {
  warnDisabled("Registrar movimiento");
}

function renderMovements() {
  // Placeholder ya mostrado en initMovements
}

function deleteMovement() {
  warnDisabled("Eliminar movimiento");
}

function exportMovementsCSV() {
  warnDisabled("Exportar movimientos (CSV)");
}

// ===================================================
// Usuarios
// ===================================================
function initUsers() {
  if (!checkSession()) return;
  renderPlaceholder(document.getElementById("listUsers"), "Usuarios", "Se cargarán desde el servidor");
  // Bloquear formulario de creación en frontend
  const formCard = document.getElementById("userFormCard");
  if (formCard) {
    const inputs = formCard.querySelectorAll("input, select, button");
    inputs.forEach(el => (el.disabled = true));
    const body = formCard.querySelector(".card-body") || formCard;
    const tip = document.createElement("div");
    tip.className = "text-muted mt-2";
    tip.textContent = "La creación/eliminación de usuarios ahora la gestiona el servidor.";
    body.appendChild(tip);
  }
}

function addUser() {
  warnDisabled("Crear usuario");
}

function renderUsers() {
  // Placeholder ya mostrado en initUsers
}

function deleteUser() {
  warnDisabled("Eliminar usuario");
}

function togglePassword() {
  warnDisabled("Ver/ocultar contraseña (solo demo)");
}

// ===================================================
// Dashboard
// ===================================================
function initDashboard() {
  if (!checkSession()) return;
  renderDashboard();
}

function renderDashboard() {
  const container = document.getElementById("statsContainer") || document.getElementById("dashboardStats");
  if (container) {
    container.innerHTML = `
      <div class="col-12 col-sm-6 col-lg-4 d-flex">
        <div class="card p-3 text-center shadow-sm h-100 w-100">
          <h5>Productos</h5>
          <div class="display-5 fw-bold">—</div>
          <small>Se cargarán del servidor</small>
        </div>
      </div>
      <div class="col-12 col-sm-6 col-lg-4 d-flex">
        <div class="card p-3 text-center shadow-sm h-100 w-100">
          <h5>Bodegas</h5>
          <div class="display-5 fw-bold">—</div>
          <small>Se cargarán del servidor</small>
        </div>
      </div>
      <div class="col-12 col-sm-6 col-lg-4 d-flex">
        <div class="card p-3 text-center shadow-sm h-100 w-100">
          <h5>Movimientos</h5>
          <div class="display-5 fw-bold">—</div>
          <small>Se cargarán del servidor</small>
        </div>
      </div>
    `;
  }
  const lowC = document.getElementById("lowStockContainer");
  renderPlaceholder(lowC, "Alertas de Stock Bajo", "Se cargarán desde el servidor");
}

// ===================================================
// Utilidad CSV (desactivada por ahora)
// ===================================================
function downloadCSV() {
  warnDisabled("Exportar CSV");
}

// ===================================================
// FIN
// ===================================================
