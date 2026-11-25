/* Odontogramme interactif — script externe (CSP : pas d'inline). */
(function () {
  var root = document.getElementById('odontogram');
  var input = document.getElementById('odo-input');
  if (!root || !input) return;

  var states = JSON.parse(root.dataset.states);
  var odo = {};

  root.querySelectorAll('.tooth').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var tooth = btn.dataset.tooth;
      var idx = states.findIndex(function (s) { return s[0] === (odo[tooth] || 'sain'); });
      var next = states[(idx + 1) % states.length][0];
      odo[tooth] = next;
      btn.className = 'tooth s-' + next;
      input.value = JSON.stringify(odo);
    });
  });
})();
