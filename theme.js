// v112: Anzeige System/Hell/Dunkel – läuft im <head> vor allem anderen (kein Flackern)
(function () {
  var mq = window.matchMedia('(prefers-color-scheme: dark)');
  function setzen(t) {
    var h = document.documentElement;
    if (t === 'light' || t === 'dark') h.setAttribute('data-theme', t); else h.removeAttribute('data-theme');
    var dunkel = t === 'dark' || (t !== 'light' && mq.matches);
    var m = document.querySelector('meta[name="color-scheme"]'); if (m) m.content = t === 'light' ? 'light' : t === 'dark' ? 'dark' : 'light dark';
    var tc = document.querySelectorAll('meta[name="theme-color"]');
    for (var i = 0; i < tc.length; i++) { tc[i].removeAttribute('media'); tc[i].content = dunkel ? '#1C1C1E' : '#FFFFFF'; }
  }
  window.beakTheme = function (t) { if (t !== undefined) { try { localStorage.setItem('beak-theme', t); } catch (e) {} setzen(t); }
    try { return localStorage.getItem('beak-theme') || 'system'; } catch (e) { return 'system'; } };
  setzen(window.beakTheme());
  mq.addEventListener && mq.addEventListener('change', function () { setzen(window.beakTheme()); });
})();
