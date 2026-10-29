/* BEAK-Punkt (Anmeldefenster): Tippen auf den pinken Punkt lässt ihn wachsen (~7×), bis der Bildschirm pink ist.
   Zu langsam getippt → schrumpft wieder zum Punkt. Voll → „Schließen“ oben rechts; Schließen = gleiche Animation rückwärts.
   Eigentliche Funktion im pinken Bereich folgt später (Bernd 29.10.2026). */
(() => {
  const STUFEN = 7, PAUSE = 450, ZERFALL = 0.3;    // Tipps bis voll; ms bis Schrumpfen beginnt; Anteil von Rmax pro Sekunde
  const ZU_MS = 1000;   // Dauer Rückwärts-Animation
  let v = 0, zStart = 0, rStart = 0, ov, knopf, inhalt, r = 0, ziel = 0, letzt = 0, voll = false, zu = false, raf = 0, t0 = 0, mitte = { x: 0, y: 0, r0: 3 };

  function punktMitte() {
    const bd = document.querySelector('#v-login .wbeak .bd');
    if (!bd) return mitte;
    const rg = document.createRange(); rg.selectNodeContents(bd); const b = rg.getBoundingClientRect();
    return { x: b.left + b.width / 2, y: b.top + b.height * 0.56, r0: Math.max(2, b.width * 0.22) };
  }
  const rMax = () => Math.hypot(Math.max(mitte.x, innerWidth - mitte.x), Math.max(mitte.y, innerHeight - mitte.y)) + 2;
  const zeichne = () => { ov.style.clipPath = `circle(${r.toFixed(1)}px at ${mitte.x.toFixed(1)}px ${mitte.y.toFixed(1)}px)`; };

  function overlay() {
    if (ov) return;
    ov = document.createElement('div'); ov.id = 'punktFlaeche'; ov.setAttribute('aria-hidden', 'true');
    knopf = document.createElement('button'); knopf.type = 'button'; knopf.className = 'punktZu'; knopf.textContent = 'Zurück an die Arbeit';
    knopf.addEventListener('click', schliessen);
    inhalt = document.createElement('div'); inhalt.className = 'punktInhalt';   // Minispiel BrEAK•out (Bernd 29.10.2026), wird erst bei voller Fläche geladen
    ov.append(inhalt, knopf); document.body.appendChild(ov);
  }
  function weg() { cancelAnimationFrame(raf); raf = 0; ov?.remove(); ov = null; r = ziel = v = 0; voll = zu = false; }

  function schleife(t) {
    const dt = Math.min(0.05, (t - (t0 || t)) / 1000); t0 = t;
    const R = rMax();
    if (zu) {                                   // rückwärts: gleichmäßig zurück in den Punkt
      const q = Math.max(0, Math.min(1, (performance.now() - zStart) / ZU_MS)), e = q < .5 ? 4 * q * q * q : 1 - Math.pow(-2 * q + 2, 3) / 2;
      r = mitte.r0 + (rStart - mitte.r0) * (1 - e);
      if (q >= 1) { weg(); return; }
    } else if (!voll) {
      if (performance.now() - letzt > PAUSE) ziel = Math.max(0, ziel - R * ZERFALL * dt);   // Zerfall
      // Feder (unterdämpft): wächst über das Ziel hinaus und federt zurück
      v += (170 * (ziel - r) - 13 * v) * dt; r = Math.max(0, r + v * dt);
      if (ziel >= R - 1 && r >= R - 2 && Math.abs(v) < 60) { r = R; v = 0; voll = true; ov.classList.add('voll'); spielStart(); }
      if (ziel <= 0 && r < mitte.r0) { weg(); return; }
    } else r = R;
    zeichne(); raf = requestAnimationFrame(schleife);
  }
  function tipp(e) {
    e.preventDefault();
    if (voll || zu) return;
    mitte = punktMitte(); overlay();
    const R = rMax(); letzt = performance.now();
    ziel = Math.min(R, Math.max(ziel, r, mitte.r0) + R / STUFEN);
    v += R * 0.9;                                   // Impuls → elastischer Überschwinger
    effekt(Math.max(ziel, 20));
    if (!raf) { t0 = 0; if (!r) r = mitte.r0; raf = requestAnimationFrame(schleife); }
  }
  // Tipp-Effekt: weicher Ring aus der Punktmitte + kurzes Aufleuchten (nur transform/opacity → flüssig auf dem iPad)
  function effekt(r0) {
    const rg = document.createElement('div'); rg.className = 'punktRing';
    const g = 2 * Math.max(40, r0);
    Object.assign(rg.style, { width: g + 'px', height: g + 'px', left: (mitte.x - g / 2) + 'px', top: (mitte.y - g / 2) + 'px' });
    document.body.appendChild(rg);
    rg.animate([{ transform: 'scale(.97)', opacity: .9 }, { transform: 'scale(1.45)', opacity: 0 }], { duration: 700, easing: 'cubic-bezier(.2,.7,.3,1)' }).onfinish = () => rg.remove();
    const gl = document.createElement('div'); gl.className = 'punktGlanz'; ov.appendChild(gl);
    gl.animate([{ opacity: .32 }, { opacity: 0 }], { duration: 260, easing: 'ease-out' }).onfinish = () => gl.remove();
    try { navigator.vibrate?.(12); } catch {}
  }
  function spielStart() {
    if (inhalt.firstChild) return;
    const f = document.createElement('iframe'); f.className = 'punktSpiel'; const vn = spielerName(document.getElementById('lName')?.value || '');   // Vorname aus der Anmeldung (Bernd → „Chef“)
    f.src = 'spiel/beak-breakout.html' + (vn ? '?spieler=' + encodeURIComponent(vn) : ''); f.title = 'BrEAK•out';
    f.setAttribute('allow', 'autoplay'); f.addEventListener('load', () => { try { f.contentWindow.focus(); } catch {} });
    inhalt.appendChild(f);
  }
  function schliessen(e) {
    e?.preventDefault(); if (!voll || zu) return;
    const warte = inhalt.firstChild ? 450 : 0;
    zu = true; ov.classList.remove('voll');                 // Spiel + Knopf blenden aus (CSS 0,45 s) …
    mitte = punktMitte(); rStart = r; zStart = performance.now() + warte;   // … danach Pink rückwärts in den Punkt
    setTimeout(() => inhalt?.replaceChildren(), warte);     // Spiel beenden (Ton aus)
    if (!raf) { t0 = 0; raf = requestAnimationFrame(schleife); }
  }

  function init() {
    const karte = document.querySelector('#v-login .wkarte'); if (!karte || karte.querySelector('.punktHit')) return;
    const hit = document.createElement('div'); hit.className = 'punktHit'; hit.setAttribute('aria-hidden', 'true');
    hit.addEventListener('pointerdown', tipp);
    hit.addEventListener('dblclick', e => e.preventDefault());
    hit.addEventListener('touchend', e => e.preventDefault(), { passive: false });   // kein Doppeltipp-Zoom
    karte.appendChild(hit);
    addEventListener('resize', () => { if (ov) { mitte = punktMitte(); if (voll) { r = rMax(); zeichne(); } } });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
  window.BeakPunkt = { tipp: () => tipp(new Event('x')), schliessen: () => schliessen() };   // für Tests
})();

/* 1.13 (Bernd 29.10.2026): Benutzer-Datensatz Bernd Kappler spielt als „Chef“. Abgleich über den vollen Namen des
   gewählten Login-Datensatzes (DB.u[i][0] = Wert von #lName), Groß/Klein, Akzente, Mehrfach-Leerzeichen egal. */
function spielerName(voll) {
  const n = String(voll).normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/\s+/g, ' ').trim();
  if (/^bernd k(appler|\.)?$/.test(n) || /^kappler,? bernd$/.test(n)) return 'Chef';
  return String(voll).trim().split(/\s+/)[0] || '';
}
