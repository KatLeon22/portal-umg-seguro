// Versión SEGURA del manejo del fragmento #filtro=... (XSS basado en DOM).
// Se usa textContent: el navegador trata el valor como texto, no como HTML.
(function () {
  "use strict";
  var crudo = location.hash.startsWith("#filtro=") ? location.hash.slice(8) : "";
  var filtro;
  try { filtro = decodeURIComponent(crudo); } catch (e) { filtro = ""; }
  document.getElementById("filtro-actual").textContent = filtro.slice(0, 50);
})();
