// BEAK DB mini – Update-Hinweis nach Service-Worker-Wechsel. Läuft früh (vor app.js), damit 'controllerchange' sicher ankommt.
// Still neu laden nur kurz nach dem Start ohne Interaktion auf Lade-/Start-/Anmeldeschirm; sonst Leiste „Update verfügbar“ + „Neu laden“.
(function () {
  try {
    if (!('serviceWorker' in navigator) || !navigator.serviceWorker.controller) return;
    var t0 = Date.now(), done = false, acted = false;
    var mark = function () { acted = true; };
    ['pointerdown', 'keydown', 'touchstart'].forEach(function (ev) { window.addEventListener(ev, mark, { capture: true, passive: true }); });
    var sichtbar = function (id) { var e = document.getElementById(id); return !!e && !e.hidden; };
    var dialogOffen = function () { return !!document.querySelector('dialog[open]') || ['betrachter', 'bemDlg', 'buDlg', 'dlg'].some(sichtbar); };
    var eingaben = function () {
      return Array.prototype.some.call(document.querySelectorAll('#v-buchen input, #v-buchen textarea, #v-bgbuchen input, #v-bgbuchen textarea'), function (e) {
        return e.type !== 'hidden' && e.type !== 'checkbox' && e.type !== 'radio' && e.type !== 'file' && (function (v) { return v !== '' && v !== e.defaultValue.trim() && !/^0([.,]0*)?$/.test(v); })(e.value.trim());   // Vorgabe „0“ zählt nicht
      });
    };
    var ruhig = function () {
      if (dialogOffen() || eingaben()) return false;
      var lade = document.getElementById('ladeSchirm');
      return (!!lade && !lade.classList.contains('aus')) || sichtbar('v-start') || sichtbar('v-login');
    };
    var neuLaden = function () {
      if (eingaben() && !confirm('Ungespeicherte Eingaben gehen verloren – trotzdem neu laden?')) return;
      location.reload();
    };
    var showHint = function () {
      if (document.getElementById('update-hint')) return;
      var bar = document.createElement('div');
      bar.id = 'update-hint'; bar.className = 'update-hint'; bar.setAttribute('role', 'status');
      var s = document.createElement('span'); s.textContent = 'Update verfügbar';
      var b = document.createElement('button'); b.type = 'button'; b.textContent = 'Neu laden';
      b.addEventListener('click', neuLaden);
      bar.appendChild(s); bar.appendChild(b);
      var place = function () { var host = document.querySelector('dialog[open]') || document.body; if (bar.parentNode !== host) host.appendChild(bar); };
      place();
      document.addEventListener('click', function () { setTimeout(place, 0); }, true);
      document.addEventListener('close', function () { setTimeout(place, 0); }, true);
      // neue Versionsnummer (falls erreichbar) anhängen
      fetch('./index.html', { cache: 'no-store' }).then(function (r) { return r.ok ? r.text() : ''; }).then(function (t) {
        var m = /id="wVersion"[^>]*>[^<]*Version\s*([\d.]+)/.exec(t || '');
        if (m) s.textContent = 'Update verfügbar (Version ' + m[1] + ')';
      }).catch(function () {});
    };
    navigator.serviceWorker.addEventListener('controllerchange', function () {
      if (done) return; done = true;
      if (!acted && Date.now() - t0 < 20000 && ruhig()) location.reload(); else showHint();
    });
  } catch (e) {}
})();
