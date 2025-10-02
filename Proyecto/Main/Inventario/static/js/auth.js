// ------------------------
// auth.js (limpio, sin localStorage / sessionStorage)
// ------------------------

// Botones/elementos (pueden no existir en algunas vistas)
const signUpBtn  = document.getElementById("signUp");
const signInBtn  = document.getElementById("signIn");
const nameInput  = document.getElementById("nameInput");
const titleEl    = document.getElementById("title");

// Alternar Login/Registro (solo UI)
if (signInBtn) {
  signInBtn.onclick = function () {
    if (nameInput) nameInput.style.maxHeight = "0";
    if (titleEl)   titleEl.innerHTML = "Login";
    if (signUpBtn) signUpBtn.classList.add("disable");
    signInBtn.classList.remove("disable");
  };
}

if (signUpBtn) {
  signUpBtn.onclick = function () {
    if (nameInput) nameInput.style.maxHeight = "60px";
    if (titleEl)   titleEl.innerHTML = "Registro";
    signUpBtn.classList.remove("disable");
    if (signInBtn) signInBtn.classList.add("disable");
  };
}

// ------------------------
// Autenticación ahora la maneja el BACKEND (Flask)
// ------------------------

// Rutas inyectadas por Flask (fallbacks por si no están)
const URLS = window.URLS || { login: "/login", logout: "/logout" };

// Estas funciones quedan como “no-op” amigables para no romper HTMLs antiguos
function login(/*username, password*/) {
  alert("La autenticación ahora la maneja el servidor.\nUsa el formulario para iniciar sesión.");
  // No hacemos nada aquí. El <form> hace POST a /login
}

function logout() {
  // Redirige al backend para cerrar sesión real
  window.location.href = URLS.logout;
}

function checkSession() {
  // Si inyectas window.IS_AUTH desde Flask, puedes usarlo aquí
  if (typeof window.IS_AUTH !== "undefined" && !window.IS_AUTH) {
    window.location.href = URLS.login;
    return false;
  }
  return true;
}

// ------------------------
// Formulario (NO interceptamos el submit)
// ------------------------
//
// Antes este archivo hacía:
//  - Validaciones, guardaba en localStorage y setear sessionStorage.
//  - Luego redirigía a Pages/dashboard.html
//
// Ahora dejamos que el <form> haga POST normal a Flask.
// Si quieres validaciones visuales mínimas (opcionales), puedes ponerlas,
// pero sin impedir el submit si todo está ok.

const form = document.getElementById("formulario");

if (form) {
  form.addEventListener("submit", function (e) {
    // Validaciones de cortesía (opcionales). Si están mal, sí bloqueamos el submit.
    const isRegister = titleEl && titleEl.innerHTML.trim().toLowerCase() === "registro";

    const nombre   = document.getElementById("nombre");
    const correo   = document.getElementById("correo");
    const password = document.getElementById("password");

    const errores = [];
    if (isRegister && nombre && nombre.value.trim() === "") {
      errores.push("El nombre es obligatorio.");
    }
    if (correo) {
      const v = (correo.value || "").trim();
      const regexCorreo = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!regexCorreo.test(v)) errores.push("El correo no es válido.");
    }
    if (password) {
      const p = (password.value || "").trim();
      if (p.length < 6) errores.push("La contraseña debe tener al menos 6 caracteres.");
    }

    if (errores.length > 0) {
      e.preventDefault();
      alert(errores.join("\n"));
      return;
    }

  });
}
