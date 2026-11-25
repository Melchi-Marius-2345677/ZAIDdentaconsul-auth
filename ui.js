/* Actions d'interface génériques (script externe, compatible CSP). */
document.querySelectorAll('[data-print]').forEach(function (btn) {
  btn.addEventListener('click', function () { window.print(); });
});
