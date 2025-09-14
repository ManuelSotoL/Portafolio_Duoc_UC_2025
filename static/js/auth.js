// ------------------------
// auth.js
// ------------------------

// Elementos del formulario
let signUpBtn = document.getElementById("signUp");
let signInBtn = document.getElementById("signIn");
let nameInput = document.getElementById("nameInput");
let title = document.getElementById("title");

// Alternar Login/Registro
signInBtn.onclick = function () {
  nameInput.style.maxHeight = "0";
  title.innerHTML = "Login";
  signUpBtn.classList.add("disable");
  signInBtn.classList.remove("disable");
};

signUpBtn.onclick = function () {
  nameInput.style.maxHeight = "60px";
  title.innerHTML = "Registro";
  signUpBtn.classList.remove("disable");
  signInBtn.classList.add("disable");
};

// ------------------------
// Base de datos simulada con localStorage
// ------------------------
let db = JSON.parse(localStorage.getItem("inventrackDB")) || {
  products: [],
  warehouses: [],
  movements: [],
  users: [{ id: "usr1", username: "admin", password: "123456", role: "admin" }],
};

function saveDB() {
  localStorage.setItem("inventrackDB", JSON.stringify(db));
}

// ------------------------
// Manejo de sesión
// ------------------------
function login(username, password) {
  const user = db.users.find(
    (u) => u.username === username && u.password === password
  );
  if (!user) return alert("Usuario o contraseña incorrectos ❌");
  sessionStorage.setItem("inventrackUser", JSON.stringify(user));
  window.location.href = "Pages/dashboard.html";
}

function logout() {
  sessionStorage.removeItem("inventrackUser");
  window.location.href = "../index.html";
}

function checkSession() {
  const user = JSON.parse(sessionStorage.getItem("inventrackUser"));
  if (!user) window.location.href = "../index.html";
  return user;
}

// ------------------------
// Registro/Login desde formulario
// ------------------------
const form = document.getElementById("formulario");

form.addEventListener("submit", function (e) {
  e.preventDefault();
  const nombre = document.getElementById("nombre").value.trim();
  const correo = document.getElementById("correo").value.trim();
  const password = document.getElementById("password").value.trim();

  const errores = [];
  if (title.innerHTML === "Registro" && nombre === "")
    errores.push("El nombre es obligatorio.");
  const regexCorreo = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!regexCorreo.test(correo)) errores.push("El correo no es válido.");
  if (password.length < 6)
    errores.push("La contraseña debe tener al menos 6 caracteres.");

  if (errores.length > 0) {
    alert(errores.join("\n"));
    return;
  }

  if (title.innerHTML === "Registro") {
    if (db.users.some((u) => u.username === correo)) {
      alert("El usuario ya existe ❌");
      return;
    }
    const id = "usr" + Date.now();
    const nuevoUsuario = { id, username: correo, password, role: "visor" };
    db.users.push(nuevoUsuario);
    saveDB();

    sessionStorage.setItem("inventrackUser", JSON.stringify(nuevoUsuario));
    alert("Registro exitoso ✅");
    window.location.href = "Pages/dashboard.html";
  } else {
    login(correo, password);
  }
});
