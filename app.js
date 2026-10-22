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
  if (b.length < 57 || new TextDecoder().decode(b.slice(0, 8)) !== 'BEAKIPAD') throw new Error('Das ist keine BEAK-iPad-Datenbank.');
  if (b[8] !== 1) throw new Error('Unbekannte Version der iPad-Datenbank – bitte die App aktualisieren.');
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

function laden(modell, bilder) {
  DB = modell; VERW = null; BILDER = bilder; ART = new Map(); BGLISTE = []; BGTYP = [];
  for (const u of bildUrl.values()) URL.revokeObjectURL(u); bildUrl.clear();
  for (const a of DB.a) { ART.set(a.n, a); if (DB.bg[a.n]) BGLISTE.push(a); if ((a.t || 1) > 1) BGTYP.push(a); }
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
function zeige(v) {
  $$('.ansicht').forEach(s => s.hidden = s.id !== 'v-' + v);
  $$('.tab').forEach(t => t.classList.toggle('an', t.dataset.v === v));
  $('#tabs').hidden = !DB || v === 'start' || v === 'person';
  if (v === 'info') { infoZeigen(); pwAnzeige(); $('#iZurueck').hidden = !!DB; $('#iSperren').hidden = !DB; }
  if (v === 'buchen') { $('#bName').textContent = ls.get('person') || ''; bSchritt(); }
  if (v === 'bg') gTabelle();
  if (v === 'bgbuchen') { $('#qName').textContent = ls.get('person') || ''; $('#qAnzahl').textContent = `${nrFmt(BGTYP.length)} Artikel in Liste`; qVorschau(); }
  window.scrollTo(0, 0);
}
$$('.tab').forEach(t => t.addEventListener('click', () => { tabVorbelegen(t.dataset.v); zeige(t.dataset.v); }));
// v86: Tabs oben übernehmen den in der Artikel-Datei gewählten Artikel / die Baugruppe (wie die Buttons unten)
function tabVorbelegen(v) {
  if (!DB || !aktArt || $('#v-artikel').hidden) return;
  const a = aktArt, istBg = !!DB.bg[a.n];
  try {
    if (v === 'stkl' && istBg) stklZeigen(a);
    else if (v === 'buchen') buchenArtikel(a);
    else if (v === 'bgbuchen' && istBg) qWaehlen(a);
    else if (v === 'bg' && istBg) { bgWaehlen(a); gModus(true); }
  } catch (e) { console.warn(e); }
}

// ---------- Start ----------
let datei = null;   // ArrayBuffer der gewählten (noch verschlüsselten) Datei
async function startVorbereiten() {
  const c = await idbGet().catch(() => null);
  if (c) { datei = c.bytes; $('#wKennwort').hidden = false; $('#dbStand').textContent = `Gespeichert: ${c.name} (${(c.size / 1048576).toFixed(1)} MB, geladen ${c.geladen})${c.stand ? ` · DB-Stand ${c.stand}` : ''}`; }
  zeige('start'); setTimeout(() => $('#fKennwort').focus(), 50);
  const gpw = await pwHolen(); $('#bPwWeg').hidden = !gpw;
  if (c && gpw) oeffnen(gpw);
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
  if (!datei) { m.textContent = 'Bitte zuerst die Datenbank aus iCloud Drive wählen.'; m.classList.add('fehler'); return; }
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
    if (!ls.get('person')) { zeige('person'); $('#fGeraet').value = ls.get('geraet') || 'iPad'; $('#fPerson').focus(); }
    else { zeige('artikel'); artikelSuchen(); }
  } catch (err) { if (gespeichert) { await pwVergessen(); m.textContent = 'Das gespeicherte Kennwort passt nicht (mehr) – bitte neu eingeben.'; } else m.textContent = err.message; m.classList.add('fehler'); }
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
  const p = $('#fPerson').value.trim(); if (p.length < 2) { $('#fPerson').focus(); return; }
  ls.set('person', p); ls.set('geraet', $('#fGeraet').value.trim() || 'iPad');
  zeige('artikel'); artikelSuchen();
});

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
const W = (l, v, cls = '') => `<div class="wert ${cls}"><label>${l}</label><span>${esc(v ?? '')}</span></div>`;
function artikelZeigen(a) {
  aktArt = a;
  $$('#aListe li').forEach(li => li.classList.toggle('an', +li.dataset.n === a.n));
  const url = bild(a.i);
  const z = x => x != null ? fmt.format(x) : '';
  const bu = (a.bu || []).map(([d, f, m, cs, sb, ci, bb, n, bem]) => `<tr><td>${esc(d ? d.slice(8, 10) + '.' + d.slice(5, 7) + '.' + d.slice(2, 4) + ' ' + d.slice(11, 16) : '')}</td>
      <td class="r w">${f === '-' ? '−' : '+'}${fmt.format(m)}</td><td>${esc(cs)}</td><td class="r w">${z(sb)}</td><td>${esc(ci)}</td><td class="r w">${z(bb)}</td><td>${esc(n)}</td><td>${esc(bem)}</td></tr>`).join('');
  $('#aDetail').innerHTML = `
    <div class="dkopf"><span class="nr">${nrFmt(a.n)}</span><span class="bez">${esc(a.b)}</span>${a.aus ? '<span class="auslauf">Auslauf</span>' : ''}</div>
    <div class="bestand"><div class="b"><label>Lager-Bestand (Ist)</label><span>${fmt.format(a.ist ?? 0)}</span></div>
      <div class="b"><label>System-Bestand (Sys)</label><span>${fmt.format(a.sys ?? 0)}</span></div></div>
    <div class="werte">${W('Typ', a.t)}${W('Lagerort', a.lo)}
      ${W('Lagerplatz', [a.lot, a.lp].filter(Boolean).join(' '))}${W('Bauform', a.bf)}${W('Lieferant', (a.l || []).map(n => Array.isArray(n) ? n[0] : n).filter(Boolean).join(', '), 'lieflist')}</div>
    <div class="bemlief einspaltig">
      <div class="wert breit bem zu" title="Antippen: Bemerkung ganz anzeigen"><label>Bemerkung</label><span>${esc((a.bem || '').replace(/\r\n?/g, '\n'))}</span></div>
    </div>
    <div class="unten">
      <div><h3>Letzte Buchungen</h3>${bu ? `<table class="letzte"><thead><tr><th>Gebucht</th><th class="r">Menge</th><th></th><th class="r">System</th><th></th><th class="r">Lager</th><th>Name / BG-Bez.</th><th>Bemerkung</th></tr></thead><tbody>${bu}</tbody></table>` : '<p class="fix klein">Keine Buchungen.</p>'}
        <div class="aktionen mt"><button class="pink" id="aBuchen">Diesen Artikel buchen</button>${(() => { const v = verwendetIn(a.n); return v.length ? `<select id="aInStkl" class="instkl"><option value="">In Stückliste (${v.length}) ▾</option>${v.map(b => `<option value="${b.n}">${nrFmt(b.n)} – ${(b.b || '').replace(/</g, '&lt;')}</option>`).join('')}</select>` : ''; })()}${DB.bg[a.n] ? '<button id="aStkl">Stückliste</button><button id="aBg">Material-Entnahme</button>' : ''}</div></div>
      <div class="bild ${url ? '' : 'leer'}">${url ? `<img src="${url}" alt="Bild ${a.n}" draggable="false">` : 'kein Bild'}</div>
    </div>`;
  fotoEinpassen(true);
  $('#aBuchen').onclick = () => { buchenArtikel(a); zeige('buchen'); };
  if ($('#aInStkl')) $('#aInStkl').onchange = e => { const b = ART.get(isNaN(+e.target.value) ? e.target.value : +e.target.value) || ART.get(e.target.value); e.target.value = ''; if (b) { stklZeigen(b); zeige('stkl'); } };
  if (DB.bg[a.n]) { $('#aStkl').onclick = () => { stklZeigen(a); zeige('stkl'); }; $('#aBg').onclick = () => { bgWaehlen(a); gModus(true); zeige('bg'); }; }
}

// ---------- Stückliste ----------
let aktStkl = null;
const refText = r => (r || []).map(x => x[0] || '').filter(Boolean).join(', ');
$('#sSuche').addEventListener('input', () => liste($('#sListe'), suche($('#sSuche').value, true).slice(0, 60), aktStkl?.n, a => { stklZeigen(a); $('#sListe').innerHTML = ''; }));
function stklZeilen(a) {
  return (DB.bg[a.n] || []).map(([nr, anz, refs], i) => { const p = ART.get(nr) || {}; return { i: i + 1, nr, bez: p.b, anz, ref: refText(refs), lo: [p.lo, p.lot, p.lp].filter(Boolean).join(' '), ist: p.ist }; });
}
// v87: Stückliste sortierbar (Tipp auf Spaltenkopf, nochmal = umgekehrt, Pfeil zeigt die Sortierung)
let sSort = { k: 'i', d: 1 };
const S_SPALTEN = [['i', 'Pos', 'r'], ['nr', 'Artikel-Nr', 'r'], ['bez', 'Bezeichnung', ''], ['anz', 'Anz', 'r'], ['ref', 'Referenzen', ''], ['lo', 'Lagerort', ''], ['ist', 'Ist', 'r']];
const sKoll = new Intl.Collator('de-DE', { numeric: true, sensitivity: 'base' });
function stklSortieren(z) {
  const { k, d } = sSort;
  return z.slice().sort((x, y) => { const a = x[k], b = y[k];
    const leerA = a == null || a === '', leerB = b == null || b === ''; if (leerA || leerB) return leerA - leerB;
    return (typeof a === 'number' && typeof b === 'number' ? a - b : sKoll.compare(String(a), String(b))) * d || x.i - y.i; });
}
function stklTabelle(z, berechnet, sortierbar) {
  const kopf = S_SPALTEN.map(([k, t, c]) => sortierbar ? `<th class="${c} sortk${sSort.k === k ? ' an' : ''}" data-k="${k}">${t}<span class="pfeil">${sSort.k === k ? (sSort.d > 0 ? ' ▲' : ' ▼') : ''}</span></th>` : `<th class="${c}">${t}</th>`).join('');
  if (sortierbar) z = stklSortieren(z);
  return `<table class="${sortierbar ? 'sortierbar' : ''}"><thead><tr>${kopf}</tr></thead><tbody>
    ${z.map(r => `<tr><td class="r">${r.i}</td><td class="r w">${nrFmt(r.nr)}</td><td>${esc(r.bez)}</td><td class="r${berechnet ? ' w' : ''}">${fmt.format(r.anz)}</td><td>${esc(r.ref)}</td><td>${esc(r.lo)}</td><td class="r">${r.ist != null ? fmt.format(r.ist) : ''}</td></tr>`).join('')}</tbody></table>`;
}
function stklZeigen(a) {
  aktStkl = a; $('#sSuche').value = nrFmt(a.n) + ' ' + a.b; $('#sMeldung').textContent = '';
  const z = stklZeilen(a);
  $('#sDetail').innerHTML = `<div class="dkopf mt mb"><span class="nr">${nrFmt(a.n)}</span><span class="bez">${esc(a.b)}</span></div>
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
function bSchritt() {
  const m = parseFloat(String($('#bMenge').value).replace(',', '.')) || 0;
  $('#bTitel').textContent = !bArt ? 'Zu buchenden Artikel auswählen' : m === 0 ? 'Menge eingeben' : 'Buchungs-Bemerkung eingeben / Buchen';
  $('#bInfo').textContent = bArt ? $('#bVz').selectedOptions[0].text : '';
}
function buchenArtikel(a) {
  bArt = a; $('#bArtikel').value = String(a.n); $('#bListe').innerHTML = '';
  $('#bNr').textContent = nrFmt(a.n); $('#bBez').textContent = a.b || ''; $('#bSys').textContent = fmt2(a.sys);
  $('#bLo').textContent = [loBez(a), a.lot, a.lp].filter(Boolean).join(' · ');
  $('#bMeldung').textContent = ''; bSchritt();
}
const fmt2 = v => new Intl.NumberFormat('de-DE', { minimumFractionDigits: 2, maximumFractionDigits: 2 }).format(v || 0);
$('#bArtikel').addEventListener('input', () => { bArt = null; ['#bNr', '#bBez', '#bSys', '#bLo'].forEach(x => $(x).textContent = ''); bSchritt(); liste($('#bListe'), suche($('#bArtikel').value).slice(0, 40), null, buchenArtikel); });
['#bVz', '#bMenge'].forEach(x => $(x).addEventListener('input', bSchritt));
$('#bBuchen').addEventListener('click', () => {
  const m = $('#bMeldung'); m.className = 'meldung fehler';
  const menge = parseFloat(String($('#bMenge').value).replace(',', '.'));
  if (!bArt) { m.textContent = 'Bitte einen Artikel wählen.'; return; }
  if (!(menge > 0)) { m.textContent = 'Bitte die Menge eingeben.'; return; }
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
  qBg = a; $('#qArtikel').value = String(a.n); $('#qListe').innerHTML = '';
  $('#qNr').textContent = nrFmt(a.n); $('#qBez').textContent = a.b || ''; $('#qSys').textContent = fmt2(a.sys);
  $('#qLo').textContent = [loBez(a), a.lot, a.lp].filter(Boolean).join(' · '); $('#qMeldung').textContent = ''; qVorschau();
}
$('#qArtikel').addEventListener('input', () => { qBg = null; ['#qNr', '#qBez', '#qSys', '#qLo'].forEach(x => $(x).textContent = ''); qVorschau();
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
  $('#gTabelle').innerHTML = j.length ? `<table><thead><tr><th>Gebucht am (iPad)</th><th>Inhalt</th><th>Datei</th></tr></thead><tbody>${j.map(x => `<tr><td>${esc(x.zeit)}</td><td>${esc(x.text)}</td><td class="klein">${esc(x.name)}</td></tr>`).join('')}</tbody></table>`
    : '<p class="fix klein">Von diesem iPad wurden noch keine Material-Entnahmen gesendet.</p>';
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
  const b = { format: 'BEAK-iPad-Buchung', version: 2, guid, ...teil, person: ls.get('person'), zeitpunkt: isoMitOffset(d), geraet: ls.get('geraet') || 'iPad', dbStand: DB.erzeugt };
  const name = `BEAK_Buchung_${d.getFullYear()}${zwei(d.getMonth() + 1)}${zwei(d.getDate())}-${zwei(d.getHours())}${zwei(d.getMinutes())}_${teil.artikelNr}_${guid.slice(0, 8)}.json`;
  const file = new File([JSON.stringify(b, null, 2)], name, { type: 'application/json' });
  letzteDatei = file;
  const j = JSON.parse(ls.get('journal') || '[]'); j.unshift({ guid, name, zeit: d.toLocaleString('de-DE'), text, me: !!me }); ls.set('journal', JSON.stringify(j.slice(0, 200)));
  let weg;
  if (istStandalone() && navigator.canShare?.({ files: [file] })) { weg = 'Jetzt unten auf „In Dateien sichern …“ tippen und im Teilen-Menü „In Dateien sichern“ → iCloud Drive/BEAK/Buchungen wählen.'; }
  else { const a = document.createElement('a'); a.href = URL.createObjectURL(file); a.download = name; document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 4000); weg = 'Die Datei wird in den Safari-Download-Ordner (iCloud Drive/BEAK/Buchungen) geladen.'; }
  dialog(istStandalone() && navigator.canShare?.({ files: [file] }) ? 'Buchung erstellt – bitte sichern' : 'Buchung gespeichert', `${text}\n\nDatei: ${name}\n${weg}\n\nAm PC erscheint „Neue Buchungen vom iPad vorhanden!“, sobald iCloud die Datei synchronisiert hat.\nDatenbank-Stand hier: ${dbStandText(DB)}`, !!navigator.canShare?.({ files: [file] }));
  nachBuchung = true;
}
let nachBuchung = false;
function dialog(titel, text, teilen) {
  $('#dlgTitel').textContent = titel; $('#dlgText').innerText = text; $('#dlgTeilen').hidden = !teilen; $('#dlg').hidden = false;
}
$('#dlgOk').addEventListener('click', () => { $('#dlg').hidden = true; if (nachBuchung) { nachBuchung = false; neuDbPruefen('buchung'); } });
$('#dlgTeilen').addEventListener('click', () => letzteDatei && navigator.share({ files: [letzteDatei] }).catch(() => {}));

// ---------- Einstellungen ----------
function infoZeigen() {
  $('#iPerson').textContent = ls.get('person') || ''; $('#iGeraet').textContent = ls.get('geraet') || 'iPad';
  $('#iDb').textContent = DB ? `Stand ${dbStandText(DB)} (${dbAlterText(dbStandDatum(DB))}) · ${DB.quelle} · ${nrFmt(DB.a.length)} Artikel · Stückliste: ${nrFmt(Object.keys(DB.bg).length)} · ${nrFmt(DB.img.length)} Bilder` : '';
  $('#iModus').textContent = istStandalone() ? 'Home-Bildschirm-App: Buchungen über „Teilen → In Dateien sichern“' : 'Safari-Tab: Buchungen als Download (Download-Ordner in den Einstellungen auf iCloud Drive/BEAK/Buchungen stellen)';
  const j = JSON.parse(ls.get('journal') || '[]');
  $('#iJournal').innerHTML = j.length ? j.map(x => `<li><span class="anz">${esc(x.zeit)}</span> · ${esc(x.text)}<br><span class="klein">${esc(x.name)}</span></li>`).join('') : '<li class="fix">Noch keine Buchungen.</li>';
}
$('#iPersonAendern').addEventListener('click', () => { $('#fPerson').value = ls.get('person') || ''; $('#fGeraet').value = ls.get('geraet') || 'iPad'; zeige('person'); });
function sperren() { DB = null; BILDER = null; ART = new Map(); BGLISTE = []; aktArt = aktStkl = bArt = gBg = qBg = null; BGTYP = []; gListe = []; $('#aDetail').innerHTML = $('#sDetail').innerHTML = ''; bannerAus(); }
$('#iSperren').addEventListener('click', () => { sperren(); startVorbereiten(); });
$('#iNeueDb').addEventListener('click', async () => { await idbDel(); datei = null; $('#dbStand').textContent = ''; $('#wKennwort').hidden = true; $('#iSperren').click(); });
// beim Verlassen/Ausblenden nach 15 Minuten automatisch sperren
let versteckt = 0;
document.addEventListener('visibilitychange', () => { if (document.hidden) versteckt = Date.now(); else if (DB && versteckt && Date.now() - versteckt > 15 * 60e3) $('#iSperren').click(); else if (DB) neuDbPruefen('vordergrund'); });

if ('serviceWorker' in navigator && isSecureContext) navigator.serviceWorker.register('sw.js').catch(() => {});
if (!isSecureContext || !crypto.subtle) { $('#startMeldung').textContent = 'Diese Seite muss über https geöffnet werden (Verschlüsselung).'; $('#startMeldung').classList.add('fehler'); }
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
  setz(); new ResizeObserver(setz).observe(k); addEventListener('orientationchange', () => setTimeout(setz, 300)); })();

/* v79: Bemerkung zuerst gekürzt (Artikel-Datei passt mit Foto auf den Bildschirm), Antippen klappt auf/zu */
document.addEventListener('click', e => { const b = e.target.closest('.wert.bem'); if (b) b.classList.toggle('zu'); });
document.addEventListener('click', e => { const l = e.target.closest('.wert.lieflist'); if (l) l.classList.toggle('auf'); });   // v81: lange Lieferanten-Liste antippen
const bemPruefen = () => document.querySelectorAll('.wert.bem').forEach(b => { const s = b.querySelector('span'); if (!s) return;
  const war = b.classList.contains('zu'); b.classList.add('zu'); b.classList.toggle('lang', s.scrollHeight > s.clientHeight + 2); if (!war) b.classList.remove('zu'); });
new MutationObserver(() => requestAnimationFrame(bemPruefen)).observe(document.body, { childList: true, subtree: true });

/* v81: „Neue Datenbankversion verfügbar? – jetzt laden“. iOS/Safari erlaubt keinen dauerhaften Dateizugriff (kein File System Access API,
 * kein showOpenFilePicker, keine gespeicherten Datei-Handles) – eine neue Version kann nur per Antippen über die Dateiauswahl gelesen werden.
 * Darum: Hinweis beim Zurückkehren in die App, nach jeder gespeicherten Buchung und wenn die Datenbank älter als X Stunden ist. */
const neuStd = () => { const v = parseFloat(ls.get('neuDbStunden')); return v > 0 ? v : 12; };
let bannerZu = 0;
function bannerAus() { $('#neuDb').hidden = true; document.documentElement.style.setProperty('--bannerh', '0px'); }
function neuDbPruefen(grund) {
  if (!DB) return;
  const d = dbStandDatum(DB), alt = d && (Date.now() - d) / 36e5 > neuStd();
  if (grund !== 'manuell' && !alt) return;   // v88: nur wenn die geöffnete DB wirklich älter als X Std. ist (iOS kann die Datei in iCloud nicht selbst prüfen)
  if (grund !== 'manuell' && Date.now() - bannerZu < 30 * 60e3) return;        // nach „Schließen“ 30 Min. Ruhe für den Alters-Hinweis
  $('#neuDbStand').textContent = `DB-Stand ${dbStandText(DB)} (${dbAlterText(d)})${alt ? ` – älter als ${fmt.format(neuStd())} Std.` : ''}`;
  $('#neuDb').classList.toggle('alt', !!alt); $('#neuDb').hidden = false;
  requestAnimationFrame(() => document.documentElement.style.setProperty('--bannerh', $('#neuDb').offsetHeight + 'px'));
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
  const setz = () => { const h = Math.round(window.visualViewport ? visualViewport.height : innerHeight) || innerHeight; document.documentElement.style.setProperty('--apph', h + 'px'); if (typeof fotoEinpassen === 'function') fotoEinpassen(); };
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
