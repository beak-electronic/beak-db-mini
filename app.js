/* BEAK DB mini – Web-App für Safari auf dem iPad.
 * Datenbank: beak-db-mini.beakdb (vom Windows-Programm "BEAK Datenbank" erzeugt), AES-256-GCM, Schlüssel per PBKDF2-SHA256.
 * Die Datei wird aus iCloud Drive gewählt, VERSCHLÜSSELT in IndexedDB zwischengespeichert und nur im Arbeitsspeicher entschlüsselt.
 * Buchungen: eine JSON-Datei je Buchung → Safari-Download (Download-Ordner = iCloud Drive/BEAK/Buchungen) bzw. Teilen → "In Dateien sichern".
 * Es werden keine Daten an einen Server geschickt (CSP connect-src 'self', kein fetch von Daten).
 */
'use strict';
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const fmt = new Intl.NumberFormat('de-DE', { maximumFractionDigits: 3 });
const nrFmt = n => new Intl.NumberFormat('de-DE').format(n);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const ls = { get: k => localStorage.getItem('beak.' + k), set: (k, v) => localStorage.setItem('beak.' + k, v) };

let DB = null;          // entschlüsseltes Modell
let BILDER = null;      // Uint8Array mit allen Bildern
let ART = new Map();    // Nr → Artikel
let BGLISTE = [];       // Artikel mit Stückliste
let BGTYP = [];         // Baugruppen (Typ > 1) für BG buchen – wie Windows
const bildUrl = new Map();
/** v81: Datenbank-Stand – „erstellt“ (ISO mit Zeitzone, ab BEAK Datenbank 0.4.2), sonst „erzeugt“ (yyyy-MM-dd HH:mm). */
function dbStandDatum(m) { const t = m?.erstellt || (m?.erzeugt ? m.erzeugt.replace(' ', 'T') : null); const d = t ? new Date(t) : null; return d && !isNaN(d) ? d : null; }
function dbStandText(m) { const d = dbStandDatum(m); return d ? d.toLocaleString('de-DE', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : (m?.erzeugt || '–'); }
function dbAlterText(d) { if (!d) return ''; const h = (Date.now() - d) / 36e5; return h < 1 ? 'vor ' + Math.max(1, Math.round(h * 60)) + ' Min.' : h < 48 ? 'vor ' + Math.round(h) + ' Std.' : 'vor ' + Math.round(h / 24) + ' Tagen'; }

// ---------- IndexedDB: verschlüsselte Datei zwischenspeichern ----------
function idb() { return new Promise((ok, f) => { const r = indexedDB.open('beak-db-mini', 1); r.onupgradeneeded = () => r.result.createObjectStore('db'); r.onsuccess = () => ok(r.result); r.onerror = () => f(r.error); }); }
async function idbPut(v) { const d = await idb(); return new Promise((ok, f) => { const t = d.transaction('db', 'readwrite'); t.objectStore('db').put(v, 'aktuell'); t.oncomplete = ok; t.onerror = () => f(t.error); }); }
async function idbGet() { const d = await idb(); return new Promise((ok, f) => { const r = d.transaction('db').objectStore('db').get('aktuell'); r.onsuccess = () => ok(r.result); r.onerror = () => f(r.error); }); }
async function idbDel() { const d = await idb(); return new Promise(ok => { const t = d.transaction('db', 'readwrite'); t.objectStore('db').delete('aktuell'); t.oncomplete = ok; }); }

// v83: Kennwort merken (wie „Bauteile Suchen“): nicht exportierbarer AES-Schlüssel in IndexedDB, nur das damit verschlüsselte Kennwort wird gespeichert
async function idbK(k, v) { const d = await idb(); return new Promise((ok, f) => { const t = d.transaction('db', v === undefined ? 'readonly' : 'readwrite'), st = t.objectStore('db'); if (v === undefined) { const r = st.get(k); r.onsuccess = () => ok(r.result); r.onerror = () => f(r.error); } else { v === null ? st.delete(k) : st.put(v, k); t.oncomplete = ok; t.onerror = () => f(t.error); } }); }
async function pwMerken(pw) { const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']); const iv = crypto.getRandomValues(new Uint8Array(12)); const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(pw)); await idbK('pw', { key, iv, ct }); }
async function pwHolen() { try { const g = await idbK('pw'); if (!g) return null; return new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: g.iv }, g.key, g.ct)); } catch { return null; } }
async function pwVergessen() { await idbK('pw', null).catch(() => {}); const b = document.querySelector('#bPwWeg'); if (b) b.hidden = true; }

// ---------- Entschlüsseln ----------
async function entschluesseln(buf, kennwort) {
  const b = new Uint8Array(buf);
  if (b.length < 57 || new TextDecoder().decode(b.slice(0, 8)) !== 'BEAKIPAD') throw new Error('Das ist keine BEAK-Geräte-Datenbank.');
  if (b[8] !== 1) throw new Error('Unbekannte Version der Geräte-Datenbank – bitte die App aktualisieren.');
  const it = new DataView(buf).getUint32(9);
  const kopf = b.slice(0, 41), salz = b.slice(13, 29), iv = b.slice(29, 41);
  const basis = await crypto.subtle.importKey('raw', new TextEncoder().encode(kennwort), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: salz, iterations: it, hash: 'SHA-256' }, basis, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  let klar;
  try { klar = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: kopf, tagLength: 128 }, key, b.subarray(41))); }
  catch { throw new Error('Kennwort falsch (oder Datei beschädigt).'); }
  const len = new DataView(klar.buffer).getUint32(0);
  const json = await new Response(new Blob([klar.subarray(4, 4 + len)]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
  return { modell: JSON.parse(json), bilder: klar.subarray(4 + len) };
}

// 1.9 (Bernd 27.10.2026): Personen in der ANZEIGE nur „Vorname N.“ – Login-Wert und Buchungsanfrage behalten den VOLLEN Namen (DB.u unverändert)
const kurzVoll = n => { const w = String(n ?? '').trim().split(/\s+/); return w.length > 1 && !/^\S\.$/.test(w[w.length - 1]) ? w[0] + ' ' + w[w.length - 1][0].toUpperCase() + '.' : String(n ?? ''); };
const PERSON = /^\p{Lu}\p{Ll}+ \p{Lu}[\p{Ll}\-]+$/u;
const kurzName = n => PERSON.test(String(n ?? '').trim()) ? kurzVoll(n) : n;
function namenKuerzen(m) {
  const full = new Set((Array.isArray(m.u) ? m.u : []).map(u => String(u[0] || '').trim()));
  const k = n => full.has(String(n ?? '').trim()) ? kurzVoll(n) : kurzName(n);
  if (m.ba?.w) m.ba.w = m.ba.w.map(k);   // nur Anzeige (Buchungsliste)
  for (const a of m.a || []) for (const b of a.bu || []) if (b[7]) b[7] = k(b[7]);
  // aus 1.8 gespeicherte Kurznamen („Daniel K.“) wieder auf den vollen Namen zurückführen, wenn eindeutig
  for (const key of ['person', 'letzterLogin']) { const v = ls.get(key); if (!v || full.has(v)) continue;
    const t = [...full].filter(f => kurzVoll(f) === v); if (t.length === 1) ls.set(key, t[0]); }
}
function laden(modell, bilder) {
  namenKuerzen(modell);
  DB = modell; VERW = null; BAIDX = null; BILDER = bilder; ART = new Map(); BGLISTE = []; BGTYP = [];
  for (const u of bildUrl.values()) URL.revokeObjectURL(u); bildUrl.clear();
  for (const a of DB.a) { ART.set(a.n, a); if (DB.bg[a.n]) BGLISTE.push(a); if ((a.t || 1) === 2) BGTYP.push(a); }   // v98: am iPad nur Baugruppen (keine Fertiggeräte/Systeme)
  const kst = '<option value="">&lt; Keine KST &gt;</option>' + (DB.kst || []).map(([n, b]) => `<option value="${n}">${n}  ${esc(b)}</option>`).join('');
  $('#bKst').innerHTML = kst; $('#gKst').innerHTML = kst; $('#qKst').innerHTML = kst;
}
// eine Suche für BEAK-Nr. und Volltext – identisch zur Artikel-Datei (suche.js)
const suche = (text, nurBg) => BeakSuche.suche(nurBg ? BGLISTE : DB.a, text);
function bild(i) {
  if (i == null || !DB.img[i]) return null;
  if (!bildUrl.has(i)) { const [o, n] = DB.img[i]; bildUrl.set(i, URL.createObjectURL(new Blob([BILDER.subarray(o, o + n)], { type: 'image/jpeg' }))); }
  return bildUrl.get(i);
}

// ---------- Navigation ----------
let VERLAUF = [], aktV = null, zurueckLaeuft = false;
function zeige(v) {
  if (v === 'buchen' && aktV !== 'buchen' && $('#bModus').selectedIndex !== 0) { $('#bModus').selectedIndex = 0; bModusSetzen(); }   // Bernd 23.10.: beim Öffnen immer „Interne Buchung“
  if (!zurueckLaeuft && aktV && aktV !== v && DB && !['start','person','login'].includes(aktV)) { VERLAUF.push({ v: aktV, art: aktArt, stkl: aktStkl }); if (VERLAUF.length > 50) VERLAUF.shift(); }
  if (!DB || v === 'start' || v === 'person' || v === 'login') VERLAUF = [];
  if (v !== 'start') ladeAus();
  aktV = v; if ($('#zurueck')) $('#zurueck').hidden = !VERLAUF.length;
  $$('.ansicht').forEach(s => s.hidden = s.id !== 'v-' + v);
  $$('.tab').forEach(t => t.classList.toggle('an', t.dataset.v === v));
  $('#tabs').hidden = !DB || v === 'start' || v === 'person' || v === 'login'; tabsSetzen(v); abmeldenKopf();
  if (v === 'info') { infoZeigen(); ordnerAnzeige(); pwAnzeige(); $('#iZurueck').hidden = !!DB; $('#iSperren').hidden = !DB; }
  if (v === 'buchen') { $('#bName').textContent = kurzVoll(ls.get('person') || ''); bSchritt(); }
  if (v === 'bg') gTabelle();
  if (v === 'bgbuchen') { $('#qName').textContent = kurzVoll(ls.get('person') || ''); $('#qAnzahl').textContent = `${nrFmt(BGTYP.length)} Artikel in Liste`; qVorschau(); }
  window.scrollTo(0, 0);
}
$('#sFilter').addEventListener('input', () => { if (aktStkl) stklZeigen(aktStkl); });
$$('.tab').forEach(t => t.addEventListener('click', () => { if (t.dataset.v === 'info' && aktV === 'info') { const iz = $('#iZurueck'); if (iz && !iz.hidden) iz.click(); else if (VERLAUF.length) $('#zurueck').click(); else if (DB) zeige('artikel'); return; } tabVorbelegen(t.dataset.v); zeige(t.dataset.v); }));
// v98: oben nur die Reiter, die zum gewählten Artikel passen
function tabsSetzen(v) { const a = aktArt, t = a ? (a.t || 1) : 0, stk = !!(a && DB && DB.bg[a.n]);
  const zeig = { artikel: true, info: true, buchen: !!a && t <= 1, stkl: stk, bg: stk, bgbuchen: t === 2 };
  $$('.tab[data-v]').forEach(b => { const k = b.dataset.v; b.hidden = !(zeig[k] || k === v); }); abmeldenKopf(); }
// v86: Tabs oben übernehmen den in der Artikel-Datei gewählten Artikel / die Baugruppe (wie die Buttons unten)
function tabVorbelegen(v) {
  if (!DB || !aktArt) return;
  const a = aktArt, istBg = !!DB.bg[a.n];
  try {
    if (v === 'stkl' && istBg) stklZeigen(a);
    else if (v === 'buchen') buchenArtikel(a);
    else if (v === 'bgbuchen' && (a.t || 1) === 2) qWaehlen(a);
    else if (v === 'bg' && istBg) { bgWaehlen(a); gModus(true); }
  } catch (e) { console.warn(e); }
}

// ---------- Start-Ladeschirm ----------
function ladeAus() { const l = document.getElementById('ladeSchirm'); if (!l || l.classList.contains('aus')) return; l.classList.add('aus'); setTimeout(() => l.remove(), 200); }
setTimeout(ladeAus, 8000);   // Sicherheits-Timeout
// ---------- Start ----------
let datei = null;   // ArrayBuffer der gewählten (noch verschlüsselten) Datei
async function startVorbereiten() {
  const c = await idbGet().catch(() => null);
  if (c) { datei = c.bytes; $('#wKennwort').hidden = false; $('#dbStand').textContent = `Gespeichert: ${c.name} (${(c.size / 1048576).toFixed(1)} MB, geladen ${c.geladen})${c.stand ? ` · DB-Stand ${c.stand}` : ''}`; }
  zeige('start'); setTimeout(() => $('#fKennwort').focus(), 50);
  const gpw = await pwHolen(); $('#bPwWeg').hidden = !gpw;
  if (DESKTOP && !autoGeladen && await dbAusOrdner(false)) return;
  if (c && gpw) oeffnen(gpw); else ladeAus();
}
// ---------- v101: Ordner verknüpfen (Windows/Desktop, File System Access API) ----------
const DESKTOP = typeof window.showDirectoryPicker === 'function';
if (DESKTOP) document.documentElement.classList.add('desktop');
let dbOrdnerVerknuepft = false, autoGeladen = false;
const ordnerHolen = k => idbK('ordner-' + k).catch(() => null);
async function ordnerRecht(h, mode, fragen) {
  const o = { mode }; if (await h.queryPermission(o) === 'granted') return true;
  return fragen ? (await h.requestPermission(o)) === 'granted' : false;
}
/** neueste *.beakdb im Datenbank-Ordner laden – gleicher Weg wie „Öffnen“ (Kennwort/Entschlüsseln). */
async function dbAusOrdner(geste) {
  const dir = await ordnerHolen('db'); dbOrdnerVerknuepft = !!dir; if (!dir) return false;
  const m = $('#startMeldung'), btn = $('#wZugriff');
  try {
    if (!await ordnerRecht(dir, 'read', geste)) { btn.hidden = false; m.className = 'meldung'; m.textContent = `Datenbank-Ordner „${dir.name}“ verknüpft – einmal „Zugriff erlauben“ klicken.`; ladeAus(); return true; }
    btn.hidden = true;
    let best = null;
    for await (const h of dir.values()) if (h.kind === 'file' && /\.beakdb$/i.test(h.name)) { const f = await h.getFile(); if (!best || f.lastModified > best.lastModified) best = f; }
    if (!best) { m.className = 'meldung fehler'; m.textContent = `Im Ordner „${dir.name}“ liegt keine .beakdb-Datei.`; ladeAus(); return false; }
    autoGeladen = true;
    datei = await best.arrayBuffer(); datei._name = best.name;
    $('#dbStand').textContent = `Aus Ordner „${dir.name}“: ${best.name} (${(best.size / 1048576).toFixed(1)} MB, ${new Date(best.lastModified).toLocaleString('de-DE')})`;
    $('#wKennwort').hidden = false; m.className = 'meldung'; m.textContent = '';
    const gpw = await pwHolen(); if (gpw) oeffnen(gpw); else { ladeAus(); setTimeout(() => $('#fKennwort').focus(), 50); }
    return true;
  } catch (e) { console.warn(e); m.className = 'meldung fehler'; m.textContent = 'Datenbank-Ordner nicht lesbar: ' + e.message; ladeAus(); return false; }
}
async function ordnerAnzeige() {
  $('#iOrdner').hidden = !DESKTOP; if (!DESKTOP) return;
  for (const k of ['db', 'buch', 'bild']) { const h = await ordnerHolen(k); $('#iOrd-' + k).textContent = h ? h.name : 'nicht verknüpft'; $('#iOrdLoesen-' + k).hidden = !h; }
}
if (DESKTOP) {
  for (const k of ['db', 'buch', 'bild']) {
    $('#iOrdWahl-' + k).addEventListener('click', async () => {
      try { const h = await showDirectoryPicker({ id: 'beak-' + k, mode: k === 'buch' ? 'readwrite' : 'read' }); await idbK('ordner-' + k, h); if (k === 'bild') dateiCache.clear(); if (k === 'db') { dbOrdnerVerknuepft = true; bannerAus(); } ordnerAnzeige(); } catch (e) { if (e.name !== 'AbortError') alert(e.message); }
    });
    $('#iOrdLoesen-' + k).addEventListener('click', async () => { await idbK('ordner-' + k, null); if (k === 'bild') dateiCache.clear(); if (k === 'db') dbOrdnerVerknuepft = false; ordnerAnzeige(); });
  }
  $('#wZugriff').addEventListener('click', () => { autoGeladen = false; dbAusOrdner(true); });
  ordnerHolen('db').then(h => { dbOrdnerVerknuepft = !!h; });
}
$('#fDatei').addEventListener('change', async e => {
  const f = e.target.files[0]; if (!f) return;
  datei = await f.arrayBuffer();
  $('#dbStand').textContent = `Gewählt: ${f.name} (${(f.size / 1048576).toFixed(1)} MB)`;
  $('#wKennwort').hidden = false; setTimeout(() => $('#fKennwort').focus(), 50);
  datei._name = f.name;
  const gpw = await pwHolen(); if (gpw) oeffnen(gpw);
});
async function oeffnen(gespeichert) {
  if (typeof gespeichert !== 'string') gespeichert = null;
  const m = $('#startMeldung'); m.className = 'meldung';
  if (!datei) { m.textContent = 'Bitte zuerst die Datenbank aus iCloud Drive wählen.'; m.classList.add('fehler'); ladeAus(); return; }
  const pw = gespeichert || $('#fKennwort').value; if (!pw) { m.textContent = 'Bitte das Kennwort eingeben.'; m.classList.add('fehler'); return; }
  $('#bOeffnen').disabled = true; m.textContent = gespeichert ? 'Öffne mit gespeichertem Kennwort …' : 'Entschlüssele …';
  try {
    const { modell, bilder } = await entschluesseln(datei, pw);
    if (modell.format !== 'BEAK-iPad-DB') throw new Error('Unbekanntes Datenformat.');
    laden(modell, bilder);
    if (vorherStand) { const neu = dbStandDatum(modell); setTimeout(() => meldungKurz(neu && +neu <= +vorherStand ? 'Das ist dieselbe (oder eine ältere) Datenbankversion wie vorher – auf dem PC gibt es noch keine neuere.' : 'Neue Datenbankversion geladen.'), 300); vorherStand = null; }
    if (!gespeichert && $('#fMerken').checked) { await pwMerken(pw).catch(() => {}); $('#bPwWeg').hidden = false; }
    if (datei._name) await idbPut({ bytes: datei, name: datei._name, size: datei.byteLength, geladen: new Date().toLocaleString('de-DE'), stand: dbStandText(modell) }).catch(() => {});
    bannerAus(); setTimeout(() => neuDbPruefen('alter'), 400);
    navigator.storage?.persist?.().catch(() => {});      // Safari soll den Zwischenspeicher nicht räumen
    $('#fKennwort').value = ''; m.textContent = '';
    nachLaden();
  } catch (err) { if (gespeichert) { await pwVergessen(); m.textContent = 'Das gespeicherte Kennwort passt nicht (mehr) – bitte neu eingeben.'; } else m.textContent = err.message; m.classList.add('fehler'); ladeAus(); }
  finally { $('#bOeffnen').disabled = false; }
}
$('#bOeffnen').addEventListener('click', () => oeffnen());
$('#bPwWeg').addEventListener('click', async () => { await pwVergessen(); pwAnzeige(); });
async function pwAnzeige() { const g = await pwHolen(); $('#iPw').textContent = g ? '●●●●●●●● gespeichert' : 'nicht gespeichert'; $('#bPwWeg').hidden = !g; }
$('#wEinst').addEventListener('click', () => zeige('info'));
$('#iZurueck').addEventListener('click', () => zeige(DB ? 'artikel' : 'start'));
$('#fForm').addEventListener('submit', e => e.preventDefault());
$('#fKennwort').addEventListener('keydown', e => { if (e.key === 'Enter') oeffnen(); });
$('#bPerson').addEventListener('click', () => {
  const p = mitLogin() ? angemeldet() : $('#fPerson').value.trim(); if (!p || p.length < 2) { $('#fPerson').focus(); return; }
  ls.set('person', p); ls.set('geraet', $('#fGeraet').value.trim() || 'Gerät');
  zeige('artikel'); artikelSuchen();
});

// ---------- Anmeldung (Benutzer aus der PC-Datenbank, DB.u = [Name, Recht, Salz, Iterationen, PBKDF2-Prüfwert]) ----------
// Ohne DB.u (ältere .beakdb) wie bisher: Name einmal manuell. Mit DB.u: Anmeldung je App-Sitzung (sessionStorage), Abmelden/Sperren löscht sie.
const mitLogin = () => !!(DB && Array.isArray(DB.u) && DB.u.length);
const angemeldet = () => { const n = sessionStorage.getItem('beak.login'); return mitLogin() && DB.u.some(u => u[0] === n) ? n : null; };
function nachLaden() {
  if (mitLogin() && !angemeldet()) return loginZeigen();
  if (mitLogin()) ls.set('person', angemeldet());
  if (!ls.get('person') || (mitLogin() && !ls.get('geraet'))) personZeigen();
  else { zeige('artikel'); artikelSuchen(); }
}
function personZeigen() {
  const l = mitLogin(); $('#fPerson').hidden = l; $('#fPersonAngemeldet').hidden = !l;
  if (l) $('#fPersonAngemeldet').textContent = `Angemeldet als ${angemeldet()} – bitte noch den Gerätenamen eingeben.`;
  $('#fPerson').value = ls.get('person') || ''; $('#fGeraet').value = ls.get('geraet') || (l ? '' : 'Gerät');
  zeige('person'); (l ? $('#fGeraet') : $('#fPerson')).focus();
}
function loginZeigen() {
  const sel = $('#lName'), vor = ls.get('letzterLogin') || ls.get('person');
  sel.innerHTML = DB.u.map(u => `<option value="${esc(u[0])}"${u[0] === vor ? ' selected' : ''}>${esc(kurzVoll(u[0]))}</option>`).join('');   // Anzeige kurz, Wert voll
  $('#lKennwort').value = ''; $('#lMeldung').textContent = ''; $('#lMeldung').className = 'meldung';
  zeige('login'); setTimeout(() => (vor || DESKTOP ? $('#lKennwort') : sel).focus(), 50);
}
const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
async function kennwortPruefen(u, pw) {
  const basis = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
  const h = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: b64(u[2]), iterations: u[3], hash: 'SHA-256' }, basis, 256)), soll = b64(u[4]);
  let d = h.length ^ soll.length; for (let i = 0; i < h.length && i < soll.length; i++) d |= h[i] ^ soll[i]; return d === 0;
}
$('#lForm').addEventListener('submit', async e => {
  e.preventDefault(); const m = $('#lMeldung'), u = DB?.u?.find(x => x[0] === $('#lName').value), pw = $('#lKennwort').value;
  m.className = 'meldung'; if (!u) return;
  if (!pw) { m.textContent = 'Bitte das Kennwort eingeben.'; m.classList.add('fehler'); $('#lKennwort').focus(); return; }
  $('#bLogin').disabled = true; m.textContent = 'Prüfe …';
  try {
    if (!await kennwortPruefen(u, pw)) { m.textContent = 'Kennwort falsch – bitte erneut versuchen.'; m.classList.add('fehler'); $('#lKennwort').select(); return; }
    sessionStorage.setItem('beak.login', u[0]); ls.set('person', u[0]); ls.set('letzterLogin', u[0]); $('#lKennwort').value = ''; m.textContent = ''; nachLaden();
  } finally { $('#bLogin').disabled = false; }
});
function abmelden() { sessionStorage.removeItem('beak.login'); if (mitLogin()) loginZeigen(); }
// Abmelden-Knopf im Kopf rechts neben Einstellungen (Tür-Symbol, Bernd 23.10.: Variante A)
function abmeldenKopf() {
  const b = $('#tabAbmelden'), n = angemeldet(); b.hidden = !n; if (!n) return;
  b.title = `Abmelden (${n})`;
}
$('#tabAbmelden').addEventListener('click', abmelden);

// ---------- Artikel-Datei ----------
let aktArt = null;
function liste(ul, treffer, akt, klick) {
  ul.innerHTML = treffer.map(a => `<li data-n="${a.n}" class="${a.n === akt ? 'an' : ''}"><span class="nr">${nrFmt(a.n)}</span><span class="bez">${esc(a.b)}</span></li>`).join('');
  ul.onclick = e => { const li = e.target.closest('li'); if (li) klick(ART.get(+li.dataset.n)); };
}
function artikelSuchen() {
  const alle = suche($('#aSuche').value), t = alle.slice(0, 300);
  $('#aTrefferAnz').textContent = alle.length > 300 ? `${nrFmt(alle.length)} Treffer – die ersten 300 angezeigt` : `${alle.length} Treffer`;
  liste($('#aListe'), t, aktArt?.n, artikelZeigen);
  if (t.length && String(t[0].n) === $('#aSuche').value.trim().replace(/\./g, '') && aktArt !== t[0]) artikelZeigen(t[0]);   // BEAK-Nr. exakt → sofort anzeigen
  if (!aktArt && t[0]) artikelZeigen(t[0]);
}
$('#aSuche').addEventListener('input', artikelSuchen);
// Buchungszeile [Gebucht, Fakt, Menge, Code Sys, Sys nach, Code Lager, Lager nach, Name, Bem]
const buZeile = ([d, f, m, cs, sb, ci, bb, n, bem]) => { const z = x => x != null ? fmt.format(x) : ''; return `<tr><td>${esc(d ? d.slice(8, 10) + '.' + d.slice(5, 7) + '.' + d.slice(2, 4) + ' ' + d.slice(11, 16) : '')}</td>
      <td class="r w">${f === '-' ? '−' : '+'}${fmt.format(m)}</td><td>${esc(cs)}</td><td class="r w">${z(sb)}</td><td>${esc(ci)}</td><td class="r w">${z(bb)}</td><td title="${esc(n)}">${esc(n)}</td><td title="${esc(bem)}">${esc(bem)}</td></tr>`; };
// ALLE Buchungen (DB.ba, spaltenweise; ältere .beakdb ohne ba: nur die 3 aus a.bu). Index wird beim ersten Zugriff gebaut.
let BAIDX = null;
function baIndex() { if (BAIDX || !DB?.ba) return BAIDX; BAIDX = new Map(); let s = 0; const { a, c } = DB.ba; for (let i = 0; i < a.length; i++) { BAIDX.set(a[i], [s, c[i]]); s += c[i]; } return BAIDX; }
const buAnz = n => { const x = baIndex()?.get(n); return x ? x[1] : 0; };
const buHole = i => { const b = DB.ba, w = b.w; return [b.d[i], b.f[i], b.m[i], w[b.cs[i]], b.sb[i], w[b.ci[i]], b.bb[i], w[b.nm[i]], b.bem[i]]; };
function buchungenFenster(a) {
  const x = baIndex()?.get(a.n); if (!x) return; const [s, anz] = x;
  let d = document.getElementById('buDlg');
  if (!d) { d = document.createElement('div'); d.id = 'buDlg'; d.className = 'bemdlg';
    d.innerHTML = '<div class="bemkarte bukarte" role="dialog" aria-modal="true"><div class="bemkopf"><b class="butitel"></b><button type="button" class="bemzu" aria-label="Schließen"><svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" fill="none"/></svg></button></div><div class="bemtext buscroll"><table class="letzte"><colgroup><col class="c-dat"><col class="c-me"><col class="c-cd"><col class="c-bs"><col class="c-cd"><col class="c-bs"><col class="c-nm"><col class="c-bem"></colgroup><thead><tr><th>Gebucht</th><th class="r">Menge</th><th></th><th class="r">System</th><th></th><th class="r">Lager</th><th>Name / BG-Bez.</th><th>Bemerkung</th></tr></thead><tbody></tbody></table></div></div>';
    d.addEventListener('click', e => { if (e.target === d || e.target.closest('.bemzu')) d.hidden = true; });
    document.addEventListener('keydown', e => { if (e.key === 'Escape' && !d.hidden) d.hidden = true; }); document.body.appendChild(d); }
  d.querySelector('.butitel').textContent = `Alle Buchungen · ${nrFmt(a.n)} ${a.b || ''} (${nrFmt(anz)})`;
  const tb = d.querySelector('tbody'), sc = d.querySelector('.buscroll'); let fertig = 0;
  const mehr = () => { if (fertig >= anz) return; const bis = Math.min(anz, fertig + 200); let h = ''; for (let i = fertig; i < bis; i++) h += buZeile(buHole(s + i)); tb.insertAdjacentHTML('beforeend', h); fertig = bis; };
  tb.innerHTML = ''; sc.scrollTop = 0; mehr(); sc.onscroll = () => { if (sc.scrollTop + sc.clientHeight > sc.scrollHeight - 600) mehr(); };   // nachladen beim Scrollen (je 200 Zeilen)
  d.hidden = false;
}
document.addEventListener('click', e => { const b = e.target.closest('#aDetail .buchbox.alle'); if (b && aktArt) buchungenFenster(aktArt); });
const W = (l, v, cls = '') => `<div class="wert ${cls}"><label>${l}</label><span>${esc(v ?? '')}</span></div>`;
function artikelZeigen(a) {
  if (!zurueckLaeuft && aktV === 'artikel' && aktArt && aktArt !== a) merkeSchritt();
  aktArt = a;
  $$('#aListe li').forEach(li => li.classList.toggle('an', +li.dataset.n === a.n));
  const url = bild(a.i);
  const z = x => x != null ? fmt.format(x) : '';
  // 1.8: so viele Buchungen laden, wie die Fläche füllen kann (Rest per Scrollen / „mehr anzeigen“)
  const bx = baIndex()?.get(a.n), buListe = bx ? Array.from({ length: Math.min(bx[1], 60) }, (_, k) => buHole(bx[0] + k)) : (a.bu || []);
  const bu = buListe.map(buZeile).join('');
  $('#aDetail').innerHTML = `
    <div class="dkopf"><span class="nr">${nrFmt(a.n)}</span><span class="bez">${esc(a.b)}</span>${a.aus ? '<span class="auslauf">Auslauf</span>' : ''}${(() => { const v = verwendetIn(a.n); return v.length ? `<select id="aInStkl" class="instkl"><option value="">In Stückliste (${v.length}) ▾</option>${v.map(b => `<option value="${b.n}">${nrFmt(b.n)} – ${(b.b || '').replace(/</g, '&lt;')}</option>`).join('')}</select>` : '<select class="instkl" disabled><option>In Stückliste (0)</option></select>'; })()}</div>
    <div class="bestand"><div class="b"><label>System-Bestand (Sys)</label><span>${fmt.format(a.sys ?? 0)}</span></div>
      <div class="b"><label>Lager-Bestand (Ist)</label><span>${fmt.format(a.ist ?? 0)}</span></div></div>
    <div class="werte">${W('Typ', ({1:'Artikel',2:'Baugruppe',3:'Fertiggerät',4:'System'})[a.t] || a.t)}${W('Lagerort', a.lo)}
      ${W('Lagerplatz', [a.lot, a.lp].filter(Boolean).join(' '))}${W('Bauform', a.bf)}${W('Lieferant', (a.l || []).map(n => Array.isArray(n) ? n[0] : n).filter(Boolean).join(', '), 'lieflist')}</div>
    <div class="buchbox${buAnz(a.n) > 0 ? ' alle' : ''}" title="Alle Buchungen anzeigen"><h3>Letzte Buchungen${buAnz(a.n) ? '<span class="bumehr">  … mehr anzeigen</span>' : ''}</h3><div class="buchscroll">${bu ? `<table class="letzte"><colgroup><col class="c-dat"><col class="c-me"><col class="c-cd"><col class="c-bs"><col class="c-cd"><col class="c-bs"><col class="c-nm"><col class="c-bem"></colgroup><thead><tr><th>Gebucht</th><th class="r">Menge</th><th></th><th class="r">System</th><th></th><th class="r">Lager</th><th>Name / BG-Bez.</th><th>Bemerkung</th></tr></thead><tbody>${bu}</tbody></table>` : '<p class="fix klein">Keine Buchungen.</p>'}</div></div>
    <div class="unten">
      <div class="wert bem zu unbem" title="Antippen: Bemerkung ganz anzeigen"><label>Bemerkung</label><span>${esc((a.bem || '').replace(/\r\n?/g, '\n'))}</span></div>
      <div class="bild ${url ? '' : 'leer'}">${url ? `<img src="${url}" alt="Bild ${a.n}" draggable="false">` : 'kein Bild'}</div>
    </div>`;
  fotoEinpassen(true);
  bemEinpassen();
  dateienZeigen(a);
  tabsSetzen('artikel');
  if ($('#aInStkl')) $('#aInStkl').onchange = e => { const b = ART.get(isNaN(+e.target.value) ? e.target.value : +e.target.value) || ART.get(e.target.value); e.target.value = ''; if (b) { stklMark = a.n; stklZeigen(b); zeige('stkl'); setTimeout(() => $('#sDetail tr.markiert')?.scrollIntoView({ block: 'center' }), 50); } };
}

// ---------- Stückliste ----------
let aktStkl = null;
const refText = r => (r || []).map(x => x[0] || '').filter(Boolean).join(', ');
$('#sSuche').addEventListener('input', () => liste($('#sListe'), suche($('#sSuche').value, true).slice(0, 60), aktStkl?.n, a => { stklMark = null; stklZeigen(a); $('#sListe').innerHTML = ''; }));
function stklZeilen(a) {
  return (DB.bg[a.n] || []).map(([nr, anz, refs], i) => { const p = ART.get(nr) || {}; return { i: i + 1, nr, bez: p.b, anz, ref: refText(refs), lo: [p.lo, p.lot, p.lp].filter(Boolean).join(' '), ist: p.sys }; });
}
// v87: Stückliste sortierbar (Tipp auf Spaltenkopf, nochmal = umgekehrt, Pfeil zeigt die Sortierung)
let sSort = { k: 'i', d: 1 };
const S_SPALTEN = [['i', 'Pos', 'r'], ['nr', 'Artikel-Nr', 'r'], ['bez', 'Bezeichnung', ''], ['anz', 'Anz', 'r'], ['ref', 'Referenzen', ''], ['lo', 'Lagerort', ''], ['ist', 'Bestand', 'r']];
const sKoll = new Intl.Collator('de-DE', { numeric: true, sensitivity: 'base' });
function stklSortieren(z) {
  const { k, d } = sSort;
  return z.slice().sort((x, y) => { const a = x[k], b = y[k];
    const leerA = a == null || a === '', leerB = b == null || b === ''; if (leerA || leerB) return leerA - leerB;
    return (typeof a === 'number' && typeof b === 'number' ? a - b : sKoll.compare(String(a), String(b))) * d || x.i - y.i; });
}
let stklMark = null;   // Artikel, von dem aus „In Stückliste“ gewählt wurde → Zeile hinterlegen
function stklTabelle(z, berechnet, sortierbar) {
  const kopf = S_SPALTEN.map(([k, t, c]) => sortierbar ? `<th class="${c} sortk${sSort.k === k ? ' an' : ''}" data-k="${k}">${t}<span class="pfeil">${sSort.k === k ? (sSort.d > 0 ? ' ▲' : ' ▼') : ''}</span></th>` : `<th class="${c}">${t}</th>`).join('');
  // v95: nach Referenzen sortiert → je Referenz eine Zeile
  if (sortierbar && sSort.k === 'ref') z = z.flatMap(r => { const refs = String(r.ref || '').split(/\s*[,;\n]\s*/).map(x => x.trim()).filter(Boolean);
    return refs.length > 1 ? refs.map(ref => ({ ...r, ref, anz: r.anz / refs.length })) : [r]; });
  // v100: Suche in der Stückliste (Artikel-Nr, Bezeichnung, Referenz)
  if (sortierbar) { const w = ($('#sFilter')?.value || '').toLowerCase().split(/\s+/).filter(Boolean);
    if (w.length) { const q = w.join(' '), refsVon = r => String(r.ref || '').toLowerCase().split(/\s*[,;\n]\s*/).map(x => x.trim()).filter(Boolean);
      const treffRef = z.filter(r => refsVon(r).some(x => x === q || x.replace(/\s+/g, '') === q.replace(/\s+/g, '')));
      if (treffRef.length) {   // genaue Referenz gefunden (z. B. „R1“, „IC 3“) → nur diese Zeile(n), Referenz hervorheben
        z = treffRef.map(r => ({ ...r, refHl: q }));
      } else z = z.filter(r => { const t = `${r.nr} ${nrFmt(r.nr)} ${r.bez || ''}`.toLowerCase(); return w.every(x => t.includes(x)); }); } }
  if (sortierbar) z = stklSortieren(z);
  return `<table class="${sortierbar ? 'sortierbar' : ''}"><thead><tr>${kopf}</tr></thead><tbody>
    ${z.map(r => `<tr${sortierbar && stklMark != null && String(r.nr) === String(stklMark) ? ' class="markiert"' : ''}><td class="r">${r.i}</td><td class="r w"><span class="artlink" data-art="${r.nr}">${nrFmt(r.nr)}</span></td><td>${esc(r.bez)}</td><td class="r${berechnet ? ' w' : ''}">${fmt.format(r.anz)}</td><td>${r.refHl ? String(r.ref || '').split(/(\s*[,;\n]\s*)/).map(x => { const k = x.trim().toLowerCase(); return k && (k === r.refHl || k.replace(/\s+/g, '') === r.refHl.replace(/\s+/g, '')) ? `<mark>${esc(x)}</mark>` : esc(x); }).join('') : esc(r.ref)}</td><td>${esc(r.lo)}</td><td class="r">${r.ist != null ? fmt.format(r.ist) : ''}</td></tr>`).join('')}</tbody></table>`;
}
function stklZeigen(a) {
  if (a !== aktStkl && $('#sFilter')) $('#sFilter').value = '';
  aktStkl = a; $('#sSuche').value = nrFmt(a.n) + ' ' + a.b; $('#sMeldung').textContent = '';
  const z = stklZeilen(a);
  $('#sDetail').innerHTML = `<div class="dkopf mt mb"><span class="nr artlink" data-art="${a.n}" title="In der Artikel-Datei öffnen">${nrFmt(a.n)}</span><span class="bez">${esc(a.b)}</span></div>
    <p class="fix klein">${z.length} Positionen · ${fmt.format(z.reduce((s, r) => s + (r.anz || 0), 0))} Teile je Baugruppe</p>${stklTabelle(z, false, true)}`;
  $$('#sDetail th.sortk').forEach(th => th.addEventListener('click', () => { const k = th.dataset.k; sSort = sSort.k === k ? { k, d: -sSort.d } : { k, d: 1 }; stklZeigen(aktStkl); }));
}
let letztesPdf = null;
/** Drucken wie Windows: gewählte "Art der Stückliste" und Anzahl → PDF im gleichen Layout (ohne Preise) → Safari-PDF-Ansicht bzw. Teilen (Drucken / In Dateien sichern). */
function stklPdf() {
  const m = $('#sMeldung'); m.className = 'meldung fehler';
  if (!aktStkl) { m.textContent = 'Bitte zuerst eine Stückliste wählen.'; return null; }
  const art = +$('#sArt').value;
  if (!BeakStklDruck.hatLayout(art)) { m.textContent = 'Für diese Art der Stückliste gibt es noch kein Drucklayout.'; return null; }
  const anz = parseFloat(String($('#sAnzahl').value).replace(',', '.'));
  const a = BeakStklDruck.auftrag(DB, art, aktStkl.n, anz > 0 ? anz : 1, ls.get('person'), new Date());
  // v90: Lager-Stückliste (Art 3): „5x BG-Bezeichnung (22.09.26)“
  const heute = new Date(), dStr = `${String(heute.getDate()).padStart(2, '0')}.${String(heute.getMonth() + 1).padStart(2, '0')}.${String(heute.getFullYear()).slice(2)}`;
  const name = (art === 3 ? `${fmt.format(anz > 0 ? anz : 1)}x ${aktStkl.b || aktStkl.n} (${dStr})` : `${aktStkl.n} ${BeakStklDruck.titel()[art]}`).replace(/[\/:*?"<>|]/g, '-') + '.pdf';
  letztesPdf = new File([BeakStklDruck.pdf(a)], name, { type: 'application/pdf' });
  m.className = 'meldung'; m.textContent = `${name} – ${a.zeilen.length} Zeilen` + ([0, 6].includes(art) ? ' (ohne Preise)' : '');
  return letztesPdf;
}
$('#sDruck').addEventListener('click', () => {
  const f = stklPdf(); if (!f) return;
  if (istStandalone() && navigator.canShare?.({ files: [f] })) navigator.share({ files: [f] }).catch(() => {});
  else { const u = URL.createObjectURL(f); window.open(u, '_blank'); setTimeout(() => URL.revokeObjectURL(u), 120000); }
});

// ---------- Artikel buchen (Windows "Artikel buchen", Modus Interne Buchung) ----------
let bArt = null;
const loBez = a => { const k = (a.lot || '').trim(); const t = (DB.lo || []).find(l => l[0] === k); return t ? t[1] : (a.lo || ''); };
// Lieferanten-Zubuchung (wie Windows Modus "Einkauf"): Lieferant aus den Lieferanten DES Artikels (Hauptlieferant vorbelegt), nur (+);
// EK/Einheit stehen nicht in der DB mini – am PC kommt der EK aus den Lieferantendaten des Artikels (wie am PC), ebenso die Auto-Bemerkung.
const bEinkauf = () => $('#bModus').selectedIndex === 1;
function bLiefFuellen() {
  const l = bArt && Array.isArray(bArt.l) ? bArt.l.map((k, i) => ({ k: String(k || '').trim(), pos: Array.isArray(bArt.ln) ? bArt.ln[i] : null })).filter(x => x.k) : [];
  $('#bLief').innerHTML = l.length ? l.map((x, i) => `<option value="${esc(x.k)}" data-pos="${x.pos ?? ''}">${esc(x.k)}${x.pos != null ? `  · Lieferant ${x.pos}` : ''}${i === 0 ? '  (Hauptlieferant)' : ''}</option>`).join('') : '<option value="">– kein Lieferant beim Artikel –</option>';
  bFirma();
}
function bFirma() { const k = $('#bLief').value; $('#bFirma').textContent = k ? ((DB && DB.lf && DB.lf[k]) || '') : ''; }
function bModusSetzen() {
  const e = bEinkauf();
  $('#bLiefFeld').hidden = !e;
  if (e) { $('#bVz').value = '+'; if ($('#bArt').selectedIndex === 0) $('#bArt').selectedIndex = 1; }   // Einkauf: üblich SYS und Lager (wie PC), nur Zubuchung
  $('#bVz').disabled = e;
  $('#bBem').placeholder = e ? 'leer = EK / Einheit des Lieferanten (wird am PC eingesetzt)' : '';
  bLiefFuellen(); bSchritt();
}
function bSchritt() {
  const m = parseFloat(String($('#bMenge').value).replace(',', '.')) || 0;
  $('#bTitel').textContent = !bArt ? 'Zu buchenden Artikel auswählen' : bEinkauf() && !$('#bLief').value ? 'Lieferant auswählen' : m === 0 ? 'Menge eingeben' : 'Buchungs-Bemerkung eingeben / Buchen';
  $('#bInfo').textContent = bArt ? $('#bVz').selectedOptions[0].text : '';
}
function buchenArtikel(a) {
  if (a && (a.t || 1) > 1) { bArt = null; $('#bListe').innerHTML = ''; ['#bNr', '#bBez', '#bSys', '#bLo'].forEach(x => $(x).textContent = ''); $('#bArtikel').value = String(a.n);
    buchenBild('#bBild', null); bBuchZeigen(null); $('#bMeldung').textContent = 'Das ist eine Baugruppe – Baugruppen bitte über „BG buchen“ buchen.'; bSchritt(); return; }   // v96
  bArt = a; $('#bArtikel').value = String(a.n); $('#bListe').innerHTML = '';
  $('#bNr').textContent = nrFmt(a.n); $('#bBez').textContent = a.b || ''; $('#bSys').textContent = fmt2(a.sys);
  $('#bLo').textContent = [loBez(a), a.lot, a.lp].filter(Boolean).join(' · ');
  $('#bMeldung').textContent = ''; bLiefFuellen(); buchenBild('#bBild', a); bBuchZeigen(a); bSchritt();
}
const fmt2 = v => new Intl.NumberFormat('de-DE', { minimumFractionDigits: 2, maximumFractionDigits: 2 }).format(v || 0);
$('#bArtikel').addEventListener('input', () => { bArt = null; ['#bNr', '#bBez', '#bSys', '#bLo'].forEach(x => $(x).textContent = ''); bLiefFuellen(); buchenBild('#bBild', null); bBuchZeigen(null); bSchritt(); liste($('#bListe'), suche($('#bArtikel').value).filter(a => (a.t || 1) <= 1).slice(0, 40), null, buchenArtikel); });
['#bVz', '#bMenge'].forEach(x => $(x).addEventListener('input', bSchritt));
$('#bModus').addEventListener('change', bModusSetzen);
$('#bLief').addEventListener('change', () => { bFirma(); bSchritt(); });
$('#bBuchen').addEventListener('click', () => {
  const m = $('#bMeldung'); m.className = 'meldung fehler';
  const menge = parseFloat(String($('#bMenge').value).replace(',', '.'));
  if (!bArt) { m.textContent = 'Bitte einen Artikel wählen.'; return; }
  if (!(menge > 0)) { m.textContent = 'Bitte die Menge eingeben.'; return; }
  if (bEinkauf()) {
    const lief = $('#bLief').value;
    if (!lief) { m.textContent = 'Dieser Artikel hat keinen Lieferanten – Lieferanten-Zubuchung nicht möglich.'; return; }
    // Buchungsdatei v3 (ältere PC-Versionen lehnen v3 als ungültig ab, statt sie falsch als interne Buchung zu buchen)
    buchungSpeichern({ version: 3, art: 'Artikel', modus: 'Lieferanten-Zubuchung (Einkauf)', artDerBuchung: $('#bArt').value, vorzeichen: '+', vorzeichenText: '(+) Buchung',
      lieferant: lief, lieferantPos: $('#bLief').selectedOptions[0].dataset.pos ? +$('#bLief').selectedOptions[0].dataset.pos : null, lieferantFirma: $('#bFirma').textContent || null,
      artikelNr: bArt.n, bezeichnung: bArt.b, menge, kstNr: null, kstText: null,
      lagerort: [loBez(bArt), bArt.lot, bArt.lp].filter(Boolean).join(' · ') || null, lagerortDetail: { bez: loBez(bArt) || null, kurz: bArt.lot || null, fach: bArt.lp || null }, bemerkung: $('#bBem').value.trim() || null },
      `Lieferanten-Zubuchung: (+) ${fmt.format(menge)} × ${nrFmt(bArt.n)} ${bArt.b} von ${lief} (${$('#bArt').value})`);
    $('#bMenge').value = '0'; $('#bBem').value = ''; bSchritt(); return;
  }
  const vz = $('#bVz').value, kst = $('#bKst').value;
  buchungSpeichern({ art: 'Artikel', modus: 'Interne Buchung', artDerBuchung: $('#bArt').value, vorzeichen: vz, vorzeichenText: $('#bVz').selectedOptions[0].text,
    artikelNr: bArt.n, bezeichnung: bArt.b, menge, kstNr: kst ? +kst : null, kstText: kst ? $('#bKst').selectedOptions[0].text : null,
    lagerort: [loBez(bArt), bArt.lot, bArt.lp].filter(Boolean).join(' · ') || null, lagerortDetail: { bez: loBez(bArt) || null, kurz: bArt.lot || null, fach: bArt.lp || null }, bemerkung: $('#bBem').value.trim() || null },
    `Artikel buchen: ${$('#bVz').selectedOptions[0].text} ${fmt.format(menge)} × ${nrFmt(bArt.n)} ${bArt.b} (${$('#bArt').value})`);
  $('#bMenge').value = '0'; $('#bBem').value = ''; bSchritt();
});

// ---------- BG buchen (Windows "BG buchen": nur Baugruppen Typ > 1, Teile-Vorschau eine Ebene) ----------
let qBg = null;
const qVeraendert = o => o === 'PlusVeraendert' || o === 'MinusVeraendert';
const qVorzeichen = o => o.startsWith('Plus') ? 1 : o === 'Inventur' ? 0 : -1;
/** Name der Teile-Sätze wie Access/Windows (BgBuchung.TeileName): ohne führendes BG / SMD BG / SYSTEM, max. 30 Zeichen. */
const qTeileName = b => (b || '').replace(/^\s*(SMD\s+BG|BG|SYSTEM)\s+/i, '').trim().slice(0, 30);
/** wie BgBuchung.Vorschau: direkte Stücklisten-Positionen (gleiche Artikel zusammengefasst), Bedarf = Menge × Stückliste-Menge, nur System-Bestand. */
function qTeile(bg, opt, menge) {
  if (!bg || !qVeraendert(opt) || !(menge > 0)) return [];
  const vz = -qVorzeichen(opt), sum = new Map();
  for (const p of DB.bg[bg.n] || []) if (p[0] !== bg.n) sum.set(p[0], (sum.get(p[0]) || 0) + p[1]);
  return [...sum.entries()].sort((x, y) => x[0] - y[0]).map(([nr, stk]) => { const a = ART.get(nr); const bedarf = Math.round(menge * stk * 1e4) / 1e4, alt = a?.sys ?? 0;
    return { artikelNr: nr, bezeichnung: a?.b ?? '(unbekannt)', stklMenge: stk, bedarf, sysAlt: alt, sysNeu: Math.round((alt + vz * bedarf) * 1e4) / 1e4, fakt: vz > 0 ? '+' : '-', unterBg: (a?.t || 1) > 1 }; });
}
function qMenge() { return parseFloat(String($('#qMenge').value).replace(',', '.')) || 0; }
function qVorschau() {
  const opt = $('#qVz').value, m = qMenge(), t = qTeile(qBg, opt, m), npos = qBg ? new Set((DB.bg[qBg.n] || []).map(p => p[0])).size : 0;
  $('#qTitel').textContent = !qBg ? 'Zu buchende Baugruppe auswählen' : m === 0 ? 'Menge eingeben' : 'Buchungs-Bemerkung eingeben / Buchen';
  $('#qInfo').textContent = qBg ? $('#qVz').selectedOptions[0].text : '';
  $('#qTabelle').innerHTML = t.length ? `<table><thead><tr><th class="r">Artikel</th><th>Bezeichnung</th><th></th><th class="r">Bedarf</th><th class="r">SYS-Bestand</th><th class="r">Neuer Bestand</th></tr></thead><tbody>${t.map(p =>
    `<tr><td class="r">${nrFmt(p.artikelNr)}</td><td>${esc(p.bezeichnung)}${p.unterBg ? ' <span class="fix klein">(Unter-BG)</span>' : ''}</td><td>${p.fakt === '-' ? '−' : '+'}</td><td class="r w">${fmt.format(p.bedarf)}</td><td class="r">${fmt.format(p.sysAlt)}</td><td class="r w">${fmt.format(p.sysNeu)}</td></tr>`).join('')}</tbody></table>` : '';
  $('#qVorschauText').textContent = !qBg ? 'Baugruppe auswählen.'
    : !qVeraendert(opt) ? `Unter-BG werden nicht verändert – nur die Baugruppe wird gebucht (${npos} Stücklisten-Positionen bleiben unberührt).`
    : m <= 0 ? `Menge eingeben – ${npos} direkte Stücklisten-Positionen werden ${qVorzeichen(opt) > 0 ? 'abgebucht' : 'zugebucht'} (nur eine Ebene).`
    : `${t.length} Teile-Buchungen (System-Bestand, Code S, ${qVorzeichen(opt) > 0 ? 'abgebucht' : 'zugebucht'}), Name in Buchung: „${qTeileName(qBg.b)}“.`;
  return t;
}
function qWaehlen(a) {
  qBg = a; $('#qArtikel').value = String(a.n); $('#qListe').innerHTML = ''; buchenBild('#qBild', a);
  $('#qNr').textContent = nrFmt(a.n); $('#qBez').textContent = a.b || ''; $('#qSys').textContent = fmt2(a.sys);
  $('#qLo').textContent = [loBez(a), a.lot, a.lp].filter(Boolean).join(' · '); $('#qMeldung').textContent = ''; qVorschau();
}
$('#qArtikel').addEventListener('input', () => { qBg = null; buchenBild('#qBild', null); ['#qNr', '#qBez', '#qSys', '#qLo'].forEach(x => $(x).textContent = ''); qVorschau();
  liste($('#qListe'), BeakSuche.suche(BGTYP, $('#qArtikel').value).slice(0, 40), null, qWaehlen); });
['#qVz', '#qMenge'].forEach(x => $(x).addEventListener('input', qVorschau));
$('#qBuchen').addEventListener('click', () => {
  const m = $('#qMeldung'); m.className = 'meldung fehler'; const menge = qMenge();
  if (!qBg) { m.textContent = 'Bitte eine Baugruppe wählen.'; return; }
  if (!(menge > 0)) { m.textContent = 'Bitte die Menge eingeben.'; return; }
  const o = $('#qVz').selectedOptions[0], kst = $('#qKst').value, teile = qVorschau();
  buchungSpeichern({ art: 'BG buchen', modus: 'Interne Buchung', artDerBuchung: $('#qArt').value, vorzeichen: o.dataset.z, vorzeichenText: o.text, bgOption: o.value,
    artikelNr: qBg.n, bezeichnung: qBg.b, menge, kstNr: kst ? +kst : null, kstText: kst ? $('#qKst').selectedOptions[0].text : null,
    lagerort: [loBez(qBg), qBg.lot, qBg.lp].filter(Boolean).join(' · ') || null, lagerortDetail: { bez: loBez(qBg) || null, kurz: qBg.lot || null, fach: qBg.lp || null },
    bemerkung: $('#qBem').value.trim() || null, teileName: qVeraendert(o.value) ? qTeileName(qBg.b) : null,
    teile: teile.map(t => ({ artikelNr: t.artikelNr, bezeichnung: t.bezeichnung, stklMenge: t.stklMenge, bedarf: t.bedarf, fakt: t.fakt, sysAlt: t.sysAlt, sysNeu: t.sysNeu })) },
    `BG buchen: ${o.text} ${fmt.format(menge)} × ${nrFmt(qBg.n)} ${qBg.b} (${$('#qArt').value})${teile.length ? ` + ${teile.length} Teile-Buchungen` : ''}`);
  $('#qMenge').value = '0'; $('#qBem').value = ''; qVorschau();
});

// ---------- Material-Entnahme ----------
let gBg = null, gListe = [], gModusNeu = true;
function gBemVorbelegen() { if (!gBg) return; const n = String($('#gAnzahl').value || ''); const t = `${n.replace('.', ',')} x ${gBg.b} (${nrFmt(gBg.n)})`; $('#gBem').value = t.slice(0, 60); }
function bgWaehlen(a) { gBg = a; $('#gBg').value = String(a.n); $('#gListe').innerHTML = ''; $('#gBez').textContent = a.b || ''; gBemVorbelegen(); }
$('#gBg').addEventListener('input', () => { gBg = null; $('#gBez').textContent = ''; liste($('#gListe'), suche($('#gBg').value, true).slice(0, 40), null, bgWaehlen); });
$('#gAnzahl').addEventListener('input', gBemVorbelegen);
/** wie AdoArtikelRepository.MaterialEntnahmePositionen: Positionen mit BC, Buchen = Auswahl_MaterialEntnahme, Bedarf = MArt × Anzahl, sortiert nach Artikel-Nr. */
/** v81: Auswahl Buchen JA/NEIN je BG + Artikel auf diesem iPad merken (wie Windows Auswahl_MaterialEntnahme je Stücklisten-Position). */
const meWahl = () => JSON.parse(ls.get('meAuswahl') || '{}');
function meWahlSetzen(bg, nr, ja) { const w = meWahl(); (w[bg] ||= {})[nr] = ja ? 1 : 2; ls.set('meAuswahl', JSON.stringify(w)); }
function mePositionen(bg, anzahl) {
  const wahl = meWahl()[bg.n] || {};
  return (DB.bg[bg.n] || []).filter(p => p[3] && ART.has(p[0])).map(p => { const a = ART.get(p[0]); return { bg: bg.n, artikelNr: a.n, bez: a.b || '', lagerort: a.lo || '', lagerplatz: `${a.lot || ''} ${a.lp || ''}`.trim(),
    bauform: a.bf || '', vpe: a.vpe || 0, bestand: a.ist || 0, bedarfStck: p[1] * anzahl, buchenStck: p[1] * anzahl, buchen: wahl[a.n] ? wahl[a.n] === 1 : p[3] === 1 }; })
    .sort((x, y) => x.artikelNr - y.artikelNr || (x.bez < y.bez ? -1 : x.bez > y.bez ? 1 : 0));
}
$('#gAnfuegen').addEventListener('click', () => {
  const m = $('#gMeldung'); m.className = 'meldung fehler';
  if (!gBg) { m.textContent = 'Bitte einen Artikel / eine Stückliste auswählen.'; return; }
  const n = parseFloat(String($('#gAnzahl').value).replace(',', '.')); if (!(n > 0)) { m.textContent = 'Bitte die Anzahl erfassen.'; return; }
  const pos = mePositionen(gBg, n); if (!pos.length) { m.textContent = 'Keine Artikel zu dieser Stückliste vorhanden.'; return; }
  const kst = $('#gKst').value; if (!$('#gBem').value.trim()) gBemVorbelegen();
  gListe.push({ bg: gBg.n, bez: gBg.b, anzahl: n, kstNr: kst ? +kst : null, kstText: kst ? $('#gKst').selectedOptions[0].text : null, bemerkung: $('#gBem').value.trim(), positionen: pos });
  m.className = 'meldung'; m.textContent = `${pos.length} Position(en) angefügt.`; gTabelle();
});
function gTabelle() {
  if (!gModusNeu) return gJournal();
  const z = gListe.flatMap((b, bi) => b.positionen.map((p, pi) => ({ ...p, kst: b.kstNr, bem: b.bemerkung, bi, pi })));
  $('#gTabelle').innerHTML = z.length ? `<table><thead><tr><th class="r">Artikel-Nr</th><th>Buchen</th><th>Artikel-Bezeichnung</th><th>Lagerort</th><th>Lagerplatz</th><th>Bauform</th><th class="r">VPE</th>
    <th class="r">Aktueller Bestand</th><th class="r">Bedarf Stück</th><th class="r">Buchen Stück</th><th>Bemerkung</th></tr></thead><tbody>${z.map(p => `<tr class="${p.buchen ? '' : 'aus'}"><td class="r w">${nrFmt(p.artikelNr)}</td>
    <td class="buchen ${p.buchen ? 'ja' : 'nein'}" data-bi="${p.bi}" data-pi="${p.pi}" title="Antippen: JA ⇄ NEIN (NEIN = nicht aus dem Lager)"><span class="jn">${p.buchen ? 'JA' : 'NEIN'}</span></td><td>${esc(p.bez)}</td><td>${esc(p.lagerort)}</td><td>${esc(p.lagerplatz)}</td><td>${esc(p.bauform)}</td><td class="r">${p.vpe > 0 ? fmt.format(p.vpe) : ''}</td>
    <td class="r">${fmt.format(p.bestand)}</td><td class="r">${fmt.format(p.bedarfStck)}</td><td class="r w">${fmt.format(p.buchenStck)}</td><td>${esc(p.bem)}</td></tr>`).join('')}</tbody></table>` : '<p class="fix klein">Aktuelle Liste ist leer.</p>';
}
$('#gTabelle').addEventListener('click', e => {
  const td = e.target.closest('td.buchen'); if (!td || !gModusNeu) return;
  const b = gListe[+td.dataset.bi], p = b?.positionen[+td.dataset.pi]; if (!p) return;
  p.buchen = !p.buchen; meWahlSetzen(b.bg, p.artikelNr, p.buchen);
  const n = gListe.reduce((s, x) => s + x.positionen.filter(q => q.buchen).length, 0);
  $('#gMeldung').className = 'meldung'; $('#gMeldung').textContent = `${nrFmt(p.artikelNr)}: Buchen ${p.buchen ? 'JA' : 'NEIN – wird nicht aus dem Lager gebucht'} (für BG ${nrFmt(b.bg)} gemerkt). ${n} Position(en) mit JA.`;
  gTabelle();
});
function gJournal() {
  const j = JSON.parse(ls.get('journal') || '[]').filter(x => x.me);
  $('#gTabelle').innerHTML = j.length ? `<table><thead><tr><th>Gebucht am (Gerät)</th><th>Inhalt</th><th>Datei</th></tr></thead><tbody>${j.map(x => `<tr><td>${esc(x.zeit)}</td><td>${esc(x.text)}</td><td class="klein">${esc(x.name)}</td></tr>`).join('')}</tbody></table>`
    : '<p class="fix klein">Von diesem Gerät wurden noch keine Material-Entnahmen gesendet.</p>';
}
function gModus(neu) { gModusNeu = neu; $('#gModusNeu').classList.toggle('an', neu); $('#gModusGebucht').classList.toggle('an', !neu); ['#gAnzahl', '#gBg', '#gKst', '#gBem', '#gAnfuegen'].forEach(x => $(x).disabled = !neu); $('#gMeldung').textContent = ''; gTabelle(); }
$('#gModusNeu').addEventListener('click', () => gModus(true));
$('#gModusGebucht').addEventListener('click', () => gModus(false));
$('#gLoeschen').addEventListener('click', () => { gListe = []; $('#gMeldung').className = 'meldung'; $('#gMeldung').textContent = 'Aktuelle Liste gelöscht – es wurde nichts gebucht.'; gTabelle(); });
$('#gBuchen').addEventListener('click', () => {
  const m = $('#gMeldung'); m.className = 'meldung fehler';
  if (!gListe.length) { m.textContent = 'Die aktuelle Liste ist leer – bitte zuerst "Artikel anfügen".'; return; }
  const n = gListe.reduce((s, b) => s + b.positionen.filter(p => p.buchen).length, 0);
  buchungSpeichern({ art: 'Material-Entnahme', artikelNr: gListe[0].bg, bezeichnung: gListe[0].bez, liste: gListe },
    `Material-Entnahme: ${gListe.map(b => `${fmt.format(b.anzahl)} × ${nrFmt(b.bg)} ${b.bez}`).join(' + ')} (${n} Positionen mit Buchen JA)`, true);
  gListe = []; gTabelle();
});

// ---------- Buchungsdatei ----------
const zwei = x => String(x).padStart(2, '0');
function isoMitOffset(d) {
  const o = -d.getTimezoneOffset(), s = o >= 0 ? '+' : '-';
  return `${d.getFullYear()}-${zwei(d.getMonth() + 1)}-${zwei(d.getDate())}T${zwei(d.getHours())}:${zwei(d.getMinutes())}:${zwei(d.getSeconds())}${s}${zwei(Math.floor(Math.abs(o) / 60))}:${zwei(Math.abs(o) % 60)}`;
}
const istStandalone = () => matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;
let letzteDatei = null;
function buchungSpeichern(teil, text, me) {
  const d = new Date(), guid = crypto.randomUUID();
  const b = { format: 'BEAK-iPad-Buchung', version: 2, guid, ...teil, person: ls.get('person'), zeitpunkt: isoMitOffset(d), geraet: ls.get('geraet') || 'Gerät', dbStand: DB.erzeugt };
  const name = `BEAK_Buchung_${d.getFullYear()}${zwei(d.getMonth() + 1)}${zwei(d.getDate())}-${zwei(d.getHours())}${zwei(d.getMinutes())}_${teil.artikelNr}_${guid.slice(0, 8)}.json`;
  const file = new File([JSON.stringify(b, null, 2)], name, { type: 'application/json' });
  letzteDatei = file;
  const j = JSON.parse(ls.get('journal') || '[]'); j.unshift({ guid, name, zeit: d.toLocaleString('de-DE'), text, me: !!me }); ls.set('journal', JSON.stringify(j.slice(0, 200)));
  if (DESKTOP) { buchungDesktop(file, name, text); nachBuchung = true; return; }
  let weg;
  if (istStandalone() && navigator.canShare?.({ files: [file] })) { weg = 'Jetzt unten auf „In Dateien sichern …“ tippen und im Teilen-Menü „In Dateien sichern“ → iCloud Drive/BEAK/Buchungen wählen.'; }
  else { download(file); weg = 'Die Datei wird in den Safari-Download-Ordner (iCloud Drive/BEAK/Buchungen) geladen.'; }
  dialog(istStandalone() && navigator.canShare?.({ files: [file] }) ? 'Buchungsanfrage erstellt – bitte sichern' : 'Buchungsanfrage erstellt – gespeichert', `${text}\n\nDatei: ${name}\n${weg}\n\nAm PC erscheint „Neue Buchungsanfragen vorhanden!“, sobald iCloud die Datei synchronisiert hat.\nDatenbank-Stand hier: ${dbStandText(DB)}`, !!navigator.canShare?.({ files: [file] }));
  nachBuchung = true;
}
let nachBuchung = false;
function download(file) { const a = document.createElement('a'); a.href = URL.createObjectURL(file); a.download = file.name; document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 4000); }
// v101: Windows/Desktop – direkt in den verknüpften Buchungs-Ordner schreiben, sonst „Speichern unter“ bzw. Download
async function dateiSchreiben(dir, file) { const h = await dir.getFileHandle(file.name, { create: true }); const w = await h.createWritable(); await w.write(file); await w.close(); }
async function buchungDesktop(file, name, text) {
  const fuss = `\n\nDatenbank-Stand hier: ${dbStandText(DB)}`;
  const dir = await ordnerHolen('buch');
  if (dir) {
    try { if (await ordnerRecht(dir, 'readwrite', true)) { await dateiSchreiben(dir, file); dialog('Buchungsanfrage erstellt – gespeichert', `${text}\n\nGespeichert in ${dir.name}/${name}${fuss}`, false); return; } }
    catch (e) { console.warn(e); }
    letzteDatei = file;
    dialog('Buchungsanfrage erstellt – bitte sichern', `${text}\n\nKein Zugriff auf den Buchungs-Ordner „${dir.name}“. Bitte unten auf „Speichern …“ klicken.${fuss}`, true); return;
  }
  dialog('Buchungsanfrage erstellt – bitte sichern', `${text}\n\nDatei: ${name}\nBitte unten auf „Speichern …“ klicken (oder in den Einstellungen einen Buchungs-Ordner verknüpfen).${fuss}`, true);
}
async function desktopSichern(file) {
  const dir = await ordnerHolen('buch');
  try { if (dir && await ordnerRecht(dir, 'readwrite', true)) { await dateiSchreiben(dir, file); dialog('Buchungsanfrage erstellt – gespeichert', `Gespeichert in ${dir.name}/${file.name}`, false); return; } } catch (e) { console.warn(e); }
  if (window.showSaveFilePicker) { try { const h = await showSaveFilePicker({ suggestedName: file.name, types: [{ description: 'BEAK Buchung', accept: { 'application/json': ['.json'] } }] }); const w = await h.createWritable(); await w.write(file); await w.close(); dialog('Buchungsanfrage erstellt – gespeichert', `Gespeichert: ${h.name}`, false); return; } catch (e) { if (e.name === 'AbortError') return; } }
  download(file); dialog('Buchungsanfrage erstellt – gespeichert', `Als Download gespeichert: ${file.name}`, false);
}
function dialog(titel, text, teilen) {
  $('#dlgTitel').textContent = titel; $('#dlgTeilen').textContent = DESKTOP ? 'Speichern …' : 'In Dateien sichern …'; $('#dlgText').innerText = text; $('#dlgTeilen').hidden = !teilen; $('#dlg').hidden = false;
}
$('#dlgOk').addEventListener('click', () => { $('#dlg').hidden = true; if (nachBuchung) { nachBuchung = false; neuDbPruefen('buchung'); } });
$('#dlgTeilen').addEventListener('click', () => { if (!letzteDatei) return; if (DESKTOP) desktopSichern(letzteDatei); else navigator.share({ files: [letzteDatei] }).catch(() => {}); });

// ---------- Einstellungen ----------
function infoZeigen() {
  $('#iPerson').textContent = kurzVoll((mitLogin() ? angemeldet() : ls.get('person')) || ''); $('#iGeraet').textContent = ls.get('geraet') || 'Gerät';
  $('#iPersonAendern').hidden = mitLogin(); $('#iAbmelden').hidden = !mitLogin(); $('#iGeraetAendern').hidden = !mitLogin();
  $('#iDb').textContent = DB ? `Stand ${dbStandText(DB)} (${dbAlterText(dbStandDatum(DB))}) · ${DB.quelle} · ${nrFmt(DB.a.length)} Artikel · Stückliste: ${nrFmt(Object.keys(DB.bg).length)} · ${nrFmt(DB.img.length)} Bilder` : '';
  $('#iModus').textContent = DESKTOP ? 'Windows/PC: Buchungen in den verknüpften Buchungs-Ordner (sonst „Speichern unter“)' : istStandalone() ? 'Home-Bildschirm-App: Buchungen über „Teilen → In Dateien sichern“' : 'Safari-Tab: Buchungen als Download (Download-Ordner in den Einstellungen auf iCloud Drive/BEAK/Buchungen stellen)';
  const j = JSON.parse(ls.get('journal') || '[]');
  $('#iJournal').innerHTML = j.length ? j.map(x => `<li><span class="anz">${esc(x.zeit)}</span> · ${esc(x.text)}<br><span class="klein">${esc(x.name)}</span></li>`).join('') : '<li class="fix">Noch keine Buchungen.</li>';
}
$('#iPersonAendern').addEventListener('click', personZeigen);
$('#iGeraetAendern').addEventListener('click', personZeigen);
$('#iAbmelden').addEventListener('click', abmelden);
function sperren() { sessionStorage.removeItem('beak.login'); DB = null; BILDER = null; ART = new Map(); BGLISTE = []; aktArt = aktStkl = bArt = gBg = qBg = null; BGTYP = []; gListe = []; $('#aDetail').innerHTML = $('#sDetail').innerHTML = ''; bannerAus(); }
$('#iSperren').addEventListener('click', () => { sperren(); startVorbereiten(); });
$('#iNeueDb').addEventListener('click', async () => { await idbDel(); datei = null; $('#dbStand').textContent = ''; $('#wKennwort').hidden = true; $('#iSperren').click(); });
// beim Verlassen/Ausblenden nach 15 Minuten automatisch sperren
let versteckt = 0;
document.addEventListener('visibilitychange', () => { if (document.hidden) versteckt = Date.now(); else if (DB && versteckt && Date.now() - versteckt > 15 * 60e3) $('#iSperren').click(); else if (DB) neuDbPruefen('vordergrund'); });

if ('serviceWorker' in navigator && isSecureContext) navigator.serviceWorker.register('sw.js').then(reg => {
  const pruef = () => { try { reg.update(); } catch (_) {} };   // Update-Prüfung: Start, Rückkehr in die App, stündlich
  pruef(); document.addEventListener('visibilitychange', () => { if (!document.hidden) pruef(); }); setInterval(pruef, 3600e3);
}).catch(() => {});
if (!isSecureContext || !crypto.subtle) { ladeAus(); $('#startMeldung').textContent = 'Diese Seite muss über https geöffnet werden (Verschlüsselung).'; $('#startMeldung').classList.add('fehler'); }
startVorbereiten();

/* v76: Mengen-/Anzahl-Feld antippen → Inhalt (z. B. „0“) markieren, damit direkt überschrieben wird (iOS-sicher) */
['#bMenge', '#qMenge', '#gAnzahl', '#sAnzahl', '#aSuche', '#sSuche', '#bArtikel', '#qArtikel', '#gBg'].forEach(id => {   // v78: auch Suchzeilen
  const el = $(id); if (!el) return; let frisch = false;
  el.addEventListener('focus', () => { frisch = true; setTimeout(() => { try { el.setSelectionRange(0, el.value.length); } catch { el.select(); } }, 0); });
  el.addEventListener('mouseup', e => { if (frisch) { e.preventDefault(); frisch = false; } });
  el.addEventListener('touchend', () => { if (frisch) setTimeout(() => { try { el.setSelectionRange(0, el.value.length); } catch {} frisch = false; }, 0); });
});

/* v77: Zoomen deaktivieren (Pinch + Doppeltipp) und Platz unter der fixierten Kopfleiste freihalten */
['gesturestart', 'gesturechange', 'gestureend'].forEach(t => document.addEventListener(t, e => e.preventDefault(), { passive: false }));
document.addEventListener('touchmove', e => { if (e.touches && e.touches.length > 1) e.preventDefault(); }, { passive: false });
/* Doppeltipp-Zoom: per CSS touch-action: manipulation (blockiert keine schnellen Tipps) */
(() => { const k = document.getElementById('kopf'); if (!k) return; const setz = () => document.documentElement.style.setProperty('--kopfh', k.offsetHeight + 'px');
  setz(); new ResizeObserver(setz).observe(k); [100,400,1000,2500].forEach(t => setTimeout(() => { setz(); const b = document.getElementById('neuDb'); if (b && !b.hidden) document.documentElement.style.setProperty('--bannerh', b.offsetHeight + 'px'); }, t)); addEventListener('pageshow', setz); if (window.visualViewport) visualViewport.addEventListener('resize', setz); addEventListener('resize', setz); if (document.fonts) document.fonts.ready.then(setz); addEventListener('orientationchange', () => setTimeout(setz, 300)); })();

/* v79: Bemerkung zuerst gekürzt (Artikel-Datei passt mit Foto auf den Bildschirm), Antippen klappt auf/zu */
// v93: Bemerkung als Fenster
const bemFenster = txt => { let d = document.getElementById('bemDlg');
  if (!d) { d = document.createElement('div'); d.id = 'bemDlg'; d.className = 'bemdlg';
    d.innerHTML = '<div class="bemkarte" role="dialog" aria-modal="true"><div class="bemkopf"><b>Bemerkung</b><button type="button" class="bemzu" aria-label="Schließen"><svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" fill="none"/></svg></button></div><div class="bemtext"></div></div>';
    d.addEventListener('click', e => { if (e.target === d || e.target.closest('.bemzu')) d.hidden = true; }); document.body.appendChild(d); }
  d.querySelector('.bemtext').textContent = txt; d.hidden = false; };
document.addEventListener('click', e => { const b = e.target.closest('.wert.bem.lang'); if (b) bemFenster(b.querySelector('span').textContent); });
document.addEventListener('click', e => { const l = e.target.closest('.wert.lieflist'); if (l) l.classList.toggle('auf'); });   // v81: lange Lieferanten-Liste antippen
const bemPruefen = () => document.querySelectorAll('.wert.bem:not(.unbem)').forEach(b => { const s = b.querySelector('span'); if (!s) return;
  const war = b.classList.contains('zu'); b.classList.add('zu'); b.classList.toggle('lang', s.scrollHeight > s.clientHeight + 2); if (!war) b.classList.remove('zu'); });
// v111: Bemerkung unten neben dem Bild – füllt die feste Fläche mit ganzen Zeilen, Rest „… mehr anzeigen“ (Fenster)
// 1.8: „Letzte Buchungen“ – nur ganze Zeilen (iPad: so viele wie passen; iPhone: immer 3), Rest über „… mehr anzeigen“
function buZeilenEinpassen() {
  const sc = document.querySelector('#aDetail .buchscroll'); if (!sc) return; const rows = [...sc.querySelectorAll('tbody tr')]; if (!rows.length) return;
  rows.forEach(r => r.style.display = '');
  let n = 3;   // iPhone: immer nur 3 (Bernd 27.10.2026), mehr über „… mehr anzeigen“
  if (innerWidth > 600) { const th = sc.querySelector('thead')?.getBoundingClientRect().height || 0, rh = rows[0].getBoundingClientRect().height || 24;
    n = Math.max(1, Math.floor((sc.clientHeight - th + 0.5) / rh)); }
  rows.forEach((r, i) => { if (i >= n) r.style.display = 'none'; });
}
function bemEinpassen() { buZeilenEinpassen(); const b = document.querySelector('#aDetail .wert.bem.unbem'); if (!b) return; const s = b.querySelector('span'), l = b.querySelector('label');
  const d = $('#aDetail'), u = d.querySelector('.unten'), bi = d.querySelector('.bild'); d.style.removeProperty('--buchh');   // wenig Höhe: Buchungsliste kürzer, Bild darf nie hineinragen
  const k = innerWidth + 'x' + innerHeight;
  if (u && bi && bemEinpassen.k !== k) { const fehlt = bi.getBoundingClientRect().height - u.getBoundingClientRect().height; bemEinpassen.k = k; bemEinpassen.h = fehlt > 0 ? Math.max(78, Math.floor(156 - fehlt - 1)) : 0; }
  if (bemEinpassen.h) d.style.setProperty('--buchh', bemEinpassen.h + 'px');
  s.style.maxHeight = ''; const lh = parseFloat(getComputedStyle(s).lineHeight) || 18;
  const frei = b.clientHeight - l.offsetHeight - 4, n = Math.max(1, Math.floor(frei / lh));
  s.style.maxHeight = s.style.height = n * lh + 'px'; b.classList.toggle('lang', s.scrollHeight > n * lh + 2); }
addEventListener('resize', () => requestAnimationFrame(bemEinpassen));
document.fonts?.ready.then(() => bemEinpassen());
new MutationObserver(() => requestAnimationFrame(bemPruefen)).observe(document.body, { childList: true, subtree: true });

/* v81: „Neue Datenbankversion verfügbar? – jetzt laden“. iOS/Safari erlaubt keinen dauerhaften Dateizugriff (kein File System Access API,
 * kein showOpenFilePicker, keine gespeicherten Datei-Handles) – eine neue Version kann nur per Antippen über die Dateiauswahl gelesen werden.
 * Darum: Hinweis beim Zurückkehren in die App, nach jeder gespeicherten Buchung und wenn die Datenbank älter als X Stunden ist. */
const neuStd = () => { const v = parseFloat(ls.get('neuDbStunden')); return v > 0 ? v : 12; };
let bannerZu = 0;
function bannerAus() { $('#neuDb').hidden = true; document.documentElement.style.setProperty('--bannerh', '0px'); }
function neuDbPruefen(grund) {
  if (!DB) return;
  if (DESKTOP && dbOrdnerVerknuepft) return;   // v101: Windows lädt beim Start automatisch aus dem verknüpften Ordner
  const d = dbStandDatum(DB), alt = d && (Date.now() - d) / 36e5 > neuStd();
  if (grund !== 'manuell' && !alt) return;   // v88: nur wenn die geöffnete DB wirklich älter als X Std. ist (iOS kann die Datei in iCloud nicht selbst prüfen)
  if (grund !== 'manuell' && Date.now() - bannerZu < 30 * 60e3) return;        // nach „Schließen“ 30 Min. Ruhe für den Alters-Hinweis
  $('#neuDbStand').textContent = `DB-Stand ${dbStandText(DB)} (${dbAlterText(d)})${alt ? ` – älter als ${fmt.format(neuStd())} Std.` : ''}`;
  $('#neuDb').classList.toggle('alt', !!alt); $('#neuDb').hidden = false;
  requestAnimationFrame(() => document.documentElement.style.setProperty('--bannerh', $('#neuDb').offsetHeight + 'px'));
  [300,1000].forEach(t => setTimeout(() => { if (!$('#neuDb').hidden) document.documentElement.style.setProperty('--bannerh', $('#neuDb').offsetHeight + 'px'); }, t));
}
$('#neuDbZu').addEventListener('click', () => { bannerZu = Date.now(); bannerAus(); });
$('#neuDbDatei').addEventListener('change', async e => {
  const f = e.target.files[0]; e.target.value = ''; if (!f) return;
  const buf = await f.arrayBuffer(); buf._name = f.name;
  vorherStand = DB ? dbStandDatum(DB) : null;
  sperren(); await startVorbereiten(); datei = buf;
  $('#dbStand').textContent = `Neu gewählt: ${f.name} (${(f.size / 1048576).toFixed(1)} MB) – Kennwort eingeben und „Öffnen“`;
  $('#wKennwort').hidden = false;
  const m = $('#startMeldung'); m.className = 'meldung'; m.textContent = '';
});
setInterval(() => neuDbPruefen('alter'), 10 * 60e3);
$('#iNeuStd').value = String(neuStd()).replace('.', ',');
$('#iNeuStd').addEventListener('change', () => { const v = parseFloat(String($('#iNeuStd').value).replace(',', '.')); if (v > 0) ls.set('neuDbStunden', String(v)); $('#iNeuStd').value = String(neuStd()).replace('.', ','); });
$('#iNeuJetzt').addEventListener('click', () => neuDbPruefen('manuell'));
(() => { const b = document.getElementById('neuDb'); new ResizeObserver(() => { if (!b.hidden) document.documentElement.style.setProperty('--bannerh', b.offsetHeight + 'px'); }).observe(b); })();

/* v82: Foto in die Resthöhe einpassen – Rahmen liegt direkt am Foto, die Bild-Spalte ist exakt so breit wie das Foto (kein Überdecken der Tabelle) */
function fotoEinpassen(neu) { const _i = document.querySelector("#aDetail .bild img"); if (_i) { _i.style.width = _i.style.height = ""; _i.parentElement.style.width = ""; } return;   // v85: feste Bildgröße wie früher
}
function fotoEinpassenAlt(neu) {
  const u = document.querySelector('#aDetail .unten'), img = u?.querySelector('.bild img'); if (!img) return;
  if (!img.complete || !img.naturalWidth) { if (neu) img.addEventListener('load', () => fotoEinpassen(), { once: true }); return; }
  const b = img.parentElement; img.style.width = img.style.height = ''; b.style.width = '';
  const maxW = Math.min(innerWidth * 0.34, 340), maxH = Math.max(60, u.clientHeight);
  const s = Math.min(1, maxW / img.naturalWidth, maxH / img.naturalHeight);
  const w = Math.floor(img.naturalWidth * s), h = Math.floor(img.naturalHeight * s);
  img.style.width = w + 'px'; img.style.height = h + 'px'; b.style.width = w + 'px';
  if (neu !== false && !u._ro) { u._ro = new ResizeObserver(() => requestAnimationFrame(() => fotoEinpassen(false))); u._ro.observe(u); }
}
addEventListener('resize', () => fotoEinpassen());
addEventListener('orientationchange', () => setTimeout(fotoEinpassen, 300));

// v82: Verwendungsnachweis – in welchen Stücklisten kommt ein Artikel vor
let VERW = null;
function verwendetIn(nr) {
  if (!VERW) { VERW = new Map(); for (const [bg, teile] of Object.entries(DB.bg || {})) for (const t of teile) { if (String(t[0]) === String(bg)) continue; const k = String(t[0]); if (!VERW.has(k)) VERW.set(k, new Set()); VERW.get(k).add(bg); } }
  return [...(VERW.get(String(nr)) || [])].map(bg => ART.get(bg) || ART.get(+bg)).filter(Boolean).sort((x, y) => String(x.n).localeCompare(String(y.n), 'de', { numeric: true }));
}

// v84: iOS meldet beim ersten Start der Home-Bildschirm-App eine falsche 100dvh (erst nach Drehen richtig) → echte Höhe selbst messen
(() => {
  const sonde = document.createElement('div'); sonde.style.cssText = 'position:fixed;top:0;bottom:0;left:0;width:0;visibility:hidden;pointer-events:none'; document.documentElement.appendChild(sonde);
  const setz = () => { const quer = innerWidth > innerHeight; const kand = [innerHeight, window.visualViewport ? visualViewport.height : 0, sonde.offsetHeight];
    // v94: iOS-Homescreen-App meldet beim ersten Start eine zu kleine Höhe → Bildschirmhöhe verwenden
    if (navigator.standalone === true) kand.push(   // v101: nur iOS – Windows-App (Edge/Chrome) hat Taskleiste/Titelleiste, Bildschirmhöhe wäre zu groß
      quer ? Math.min(screen.width, screen.height) : Math.max(screen.width, screen.height));
    const h = Math.round(Math.max(...kand)) || innerHeight; document.documentElement.style.setProperty('--apph', h + 'px'); if (typeof fotoEinpassen === 'function') fotoEinpassen(); };
  setz(); [50, 300, 800, 1500].forEach(t => setTimeout(setz, t));
  addEventListener('resize', setz); addEventListener('pageshow', setz); addEventListener('orientationchange', () => setTimeout(setz, 300));
  window.visualViewport?.addEventListener('resize', setz);
  new MutationObserver(() => requestAnimationFrame(setz)).observe(document.body, { attributes: true, subtree: true, attributeFilter: ['hidden'] });
})();

let vorherStand = null;
function meldungKurz(t) { const d = document.createElement('div'); d.className = 'toast'; d.textContent = t; document.body.appendChild(d); setTimeout(() => d.remove(), 5000); }

// v89: Safari soll die Unschärfe der Kopfzeile nach Scrollen/Umschalten neu berechnen
(() => { const k = document.getElementById('kopf'); if (!k) return; let t = 0; const tick = () => { if (t) return; t = requestAnimationFrame(() => { k.classList.toggle('bf-tick'); t = 0; }); };
  addEventListener('scroll', tick, { passive: true }); addEventListener('resize', tick); setTimeout(tick, 300); })();

// v106: Artikel-Nr in der Stückliste antippen -> Teil in der Artikel-Datei (Reiter oben passen dann zu diesem Teil)
document.addEventListener('click', e => { const l = e.target.closest('.artlink'); if (!l || !DB) return;
  const v = l.dataset.art, a = ART.get(+v) || ART.get(v); if (!a) return;
  merkeSchritt(); zurueckLaeuft = true; try { zeige('artikel'); artikelZeigen(a); } finally { zurueckLaeuft = false; } tabsSetzen('artikel');
  const li = document.querySelector(`#aListe li[data-n="${a.n}"]`); if (li) li.scrollIntoView({ block: 'nearest' }); });

// v107: Zurück – geht immer ins vorherige Fenster (mit dem Artikel/der Stückliste von damals)
function merkeSchritt() { if (aktV && DB) { VERLAUF.push({ v: aktV, art: aktArt, stkl: aktStkl }); $('#zurueck').hidden = false; } }
$('#zurueck').addEventListener('click', () => { const z = VERLAUF.pop(); if (!z) return;
  zurueckLaeuft = true;
  try { if (z.art) artikelZeigen(z.art); if (z.v === 'stkl' && z.stkl) stklZeigen(z.stkl); zeige(z.v); } finally { zurueckLaeuft = false; }
  $('#zurueck').hidden = !VERLAUF.length; });

// Tastatur in Suchfeldern: Enter / Pfeil ab = ersten Treffer zeigen, Pfeiltasten = durch die Treffer gehen
[['#aSuche', '#aListe'], ['#sSuche', '#sListe'], ['#bArtikel', '#bListe'], ['#gBg', '#gListe'], ['#qArtikel', '#qListe']].forEach(([f, l]) => {
  const feld = $(f); if (!feld) return; let pfeil = false;
  feld.addEventListener('input', () => { pfeil = false; });
  feld.addEventListener('keydown', e => {
    const ul = $(l); if (!ul) return; const lis = [...ul.querySelectorAll('li')]; if (!lis.length) return;
    let i = lis.findIndex(x => x.classList.contains('an'));
    if (e.key === 'Enter') i = pfeil && i >= 0 ? i : 0;
    else if (e.key === 'ArrowDown') i = Math.min(lis.length - 1, i + 1);
    else if (e.key === 'ArrowUp') { if (i < 0) return; i = Math.max(0, i - 1); }
    else return;
    e.preventDefault(); if (e.key !== 'Enter') pfeil = true;
    const li = lis[i]; lis.forEach(x => x.classList.toggle('an', x === li));
    li.scrollIntoView({ block: 'nearest' }); li.click();
    const neu = $(l).querySelector(`li[data-n="${li.dataset.n}"]`); if (neu) neu.classList.add('an');
    feld.focus();
  });
});

// ---------- v109: verknüpfte Dateien aus dem Bilder-/Dokumente-Ordner (nur Windows/Desktop) ----------
// a.f = relative Pfade (\u2018/\u2019) unter dem Dokumenten-Basisordner der Windows-App; ohne Ordner/ohne Liste bleibt alles wie bisher.
const dateiCache = new Map();   // rel (klein) → {url, typ, name} | {fehlt:true}
let dateiTok = 0;
const istBildName = n => /\.(jpe?g|png|gif|bmp|webp)$/i.test(n);
const istPdfName = n => /\.pdf$/i.test(n);
async function dateiHolen(dir, rel) {
  const k = rel.toLowerCase(); if (dateiCache.has(k)) return dateiCache.get(k);
  const teile = rel.split('/').filter(Boolean), name = teile.pop() || rel; let e;
  try {
    let d = dir; for (const t of teile) d = await d.getDirectoryHandle(t);
    const f = await (await d.getFileHandle(name)).getFile();
    const typ = istPdfName(name) ? 'application/pdf' : (f.type || '');
    e = { url: URL.createObjectURL(typ ? new Blob([f], { type: typ }) : f), name, typ };
  } catch { e = { fehlt: true, name }; }
  dateiCache.set(k, e); return e;
}
async function dateienZeigen(a, kbox = null) {
  const tok = kbox ? (kbox._tok = (kbox._tok || 0) + 1) : ++dateiTok, aktuell = () => kbox ? kbox._tok === tok : tok === dateiTok;
  if (a.f) a.f = a.f.filter(x => istBildName(x) || istPdfName(x));   // nur Bilder + PDFs
  if (!DESKTOP || !a.f?.length) return;
  const dir = await ordnerHolen('bild'); if (!dir || !aktuell()) return;
  const box = kbox || document.querySelector('#aDetail .bild'); if (!box) return;
  if (!await ordnerRecht(dir, 'read', false)) {
    const b = document.createElement('button'); b.className = 'klein dzugriff'; b.textContent = 'Zugriff auf Bilder erlauben';
    b.onclick = async ev => { ev.stopPropagation(); if (await ordnerRecht(dir, 'read', true)) dateienZeigen(a, kbox); };
    box.appendChild(b); return;
  }
  const iBild = Math.max(0, a.f.findIndex(istBildName));
  const e = istBildName(a.f[iBild]) ? await dateiHolen(dir, a.f[iBild]) : null;
  if (!aktuell() || !box.isConnected) return;
  if (e && !e.fehlt) { box.classList.remove('leer'); box.innerHTML = `<img src="${e.url}" alt="Bild ${a.n}" draggable="false">`; }
  else if (!box.querySelector('img')) box.textContent = istPdfName(a.f[0]) ? 'PDF' : 'Datei';
  box.classList.add('dateien'); box.title = 'Klicken: alle verknüpften Dateien anzeigen';
  if (a.f.length > 1) box.insertAdjacentHTML('beforeend', `<span class="dzahl">${iBild + 1}/${a.f.length}</span>`);
  box.onclick = () => betrachter(a, iBild);
}
/** Bild im Buchen-Fenster (Artikel buchen / BG buchen): gleiche Quelle wie die Artikel-Datei – komprimiertes Bild, am Desktop mit
 * verknüpftem Bilder-Ordner das erste Bild in voller Qualität, Klick öffnet den Betrachter. Fester Platz, ohne Bild dezenter Platzhalter. */
// Letzte Buchungen (3) im Fenster „Artikel buchen“ – gleiche Tabelle wie Artikel-Datei, antippen → alle Buchungen
function bBuchZeigen(a) { const b = $('#bBuch'); if (!b) return; b.hidden = !a; if (!a) { b.innerHTML = ''; return; }
  const n = buAnz(a.n); b.classList.toggle('alle', n > 0); b.title = n ? 'Alle Buchungen anzeigen' : '';
  b.innerHTML = `<h3>Letzte Buchungen${n ? '<span class="bumehr">  … mehr anzeigen</span>' : ''}</h3>${(a.bu || []).length ? `<table class="letzte"><colgroup><col class="c-dat"><col class="c-me"><col class="c-cd"><col class="c-bs"><col class="c-cd"><col class="c-bs"><col class="c-nm"><col class="c-bem"></colgroup><thead><tr><th>Gebucht</th><th class="r">Menge</th><th></th><th class="r">System</th><th></th><th class="r">Lager</th><th>Name / BG-Bez.</th><th>Bemerkung</th></tr></thead><tbody>${a.bu.map(buZeile).join('')}</tbody></table>` : '<p class="fix klein">Keine Buchungen.</p>'}`;
  b.onclick = () => { if (n) buchungenFenster(a); }; }
function buchenBild(sel, a) {
  const box = $(sel); if (!box) return;
  box._tok = (box._tok || 0) + 1; box.onclick = null; box.title = ''; box.classList.remove('dateien');
  const url = a && a.i != null ? bild(a.i) : null;
  box.classList.toggle('leer', !url);
  box.innerHTML = url ? `<img src="${url}" alt="Bild ${a.n}" draggable="false">` : (a ? 'kein Bild' : '');
  if (a) dateienZeigen(a, box);
}
function betrachter(a, start) {
  let i = start; const n = a.f.length;
  const v = document.createElement('div'); v.id = 'betrachter'; v.setAttribute('role', 'dialog'); v.setAttribute('aria-modal', 'true');
  const pfeil = d => `<svg viewBox="0 0 24 24" width="28" height="28" aria-hidden="true"><path d="${d}" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg>`;
  v.innerHTML = `<div class="bvkopf"><span class="bvname"></span><span class="bvzahl"></span><a class="bemzu bvdl bvneu" hidden target="_blank" rel="noopener" title="In neuem Fenster öffnen" aria-label="In neuem Fenster öffnen"><svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg></a><a class="bemzu bvdl" hidden title="Herunterladen" aria-label="Herunterladen"><svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path d="M12 4v11M7 10l5 5 5-5M5 20h14" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg></a><button type="button" class="bemzu bvzu" aria-label="Schließen"><svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" fill="none"/></svg></button></div>
    <div class="bvmitte"><button type="button" class="bvpfeil bvl" aria-label="Vorherige Datei">${pfeil('M15 5l-7 7 7 7')}</button><div class="bvinhalt"></div><button type="button" class="bvpfeil bvr" aria-label="Nächste Datei">${pfeil('M9 5l7 7-7 7')}</button></div>`;
  document.body.appendChild(v);
  v.querySelectorAll('.bvpfeil').forEach(b => b.hidden = n < 2);
  const zu = () => { document.removeEventListener('keydown', taste, true); v.remove(); };
  async function zeigen() {
    const rel = a.f[i], tok = i, inh = v.querySelector('.bvinhalt');
    v.querySelector('.bvname').textContent = rel; v.querySelector('.bvzahl').textContent = n > 1 ? `${i + 1}/${n}` : '';
    inh.innerHTML = '<div class="bvhinweis">Lädt …</div>';
    const dir = await ordnerHolen('bild'); const e = dir ? await dateiHolen(dir, rel) : { fehlt: true, name: rel };
    if (tok !== i || !v.isConnected) return;
    const nm = esc(e.name); const dl = v.querySelector('.bvdl:not(.bvneu)'), nw = v.querySelector('.bvneu');
    nw.hidden = !(DESKTOP && !e.fehlt && istPdfName(e.name)); if (!nw.hidden) nw.href = e.url; else nw.removeAttribute('href');
    if (e.fehlt) { dl.hidden = true; dl.removeAttribute('href'); } else { dl.hidden = false; dl.href = e.url; dl.download = e.name.split('/').pop(); }
    if (e.fehlt) inh.innerHTML = `<div class="bvhinweis"><b>Datei nicht gefunden</b><br>${nm}<br><small>im Bilder-/Dokumente-Ordner „${esc(dir?.name || '')}“</small></div>`;
    else if (istBildName(e.name)) inh.innerHTML = `<img src="${e.url}" alt="${nm}">`;
    else if (istPdfName(e.name)) inh.innerHTML = `<iframe src="${e.url}" title="${nm}"></iframe>`;
    else inh.innerHTML = `<div class="bvhinweis"><b>${nm}</b><br>Dieser Dateityp kann hier nicht angezeigt werden.<br><a href="${e.url}" download="${nm}">Datei speichern</a></div>`;
  }
  const geh = d => { if (n < 2) return; i = (i + d + n) % n; zeigen(); };
  function taste(e) { if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); zu(); } else if (e.key === 'ArrowLeft') { e.preventDefault(); geh(-1); } else if (e.key === 'ArrowRight') { e.preventDefault(); geh(1); } }
  document.addEventListener('keydown', taste, true);
  v.querySelector('.bvzu').onclick = zu; v.querySelector('.bvl').onclick = () => geh(-1); v.querySelector('.bvr').onclick = () => geh(1);
  zeigen();
}

// ---------- Desktop: Cursor in der Artikel-Datei immer im Suchfeld (iPad unverändert – sonst Tastatur) ----------
if (DESKTOP) (() => {
  const offen = () => ['#ladeSchirm', '#dlg', '#bemDlg', '#buDlg', '#betrachter', '[role="dialog"]', '[aria-modal="true"]'].some(s => [...document.querySelectorAll(s)].some(e => !e.hidden && e.offsetParent !== null || (e.id === 'ladeSchirm' && !e.classList.contains('aus'))));
  const fremd = () => { const a = document.activeElement; return a && a !== document.body && a.id !== 'aSuche' && a.matches('input, select, textarea, [contenteditable="true"]'); };
  const fokus = () => { if (aktV !== 'artikel' || !DB || document.hidden || offen() || fremd()) return; const f = $('#aSuche'); if (f && document.activeElement !== f) { f.focus({ preventScroll: true }); f.select(); } };
  let t = 0; const bald = () => { clearTimeout(t); t = setTimeout(fokus, 60); };
  addEventListener('focus', bald); addEventListener('pageshow', bald);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) bald(); });
  new MutationObserver(bald).observe(document.body, { attributes: true, attributeFilter: ['hidden', 'class'], childList: true, subtree: true });
  document.addEventListener('keydown', e => {   // druckbares Zeichen bei leerem Fokus → ins Suchfeld
    if (e.key.length !== 1 || e.ctrlKey || e.metaKey || e.altKey || aktV !== 'artikel' || offen() || fremd() || document.activeElement?.id === 'aSuche') return;
    const f = $('#aSuche'); f.focus({ preventScroll: true }); f.select(); });
})();

// v112: Anzeige System/Hell/Dunkel (theme.js setzt html[data-theme] schon vor dem Laden)
function themeKnoepfe() { const t = window.beakTheme ? beakTheme() : 'system'; $$('#iTheme button').forEach(b => b.classList.toggle('an', b.dataset.t === t)); }
$('#iTheme')?.addEventListener('click', e => { const b = e.target.closest('button[data-t]'); if (!b || !window.beakTheme) return; beakTheme(b.dataset.t); themeKnoepfe(); });
themeKnoepfe();
$('#lName').addEventListener('change', () => $('#lKennwort').focus());   // Name gewählt → Kennwort (Bernd 23.10.)
