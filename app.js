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
const bildUrl = new Map();

// ---------- IndexedDB: verschlüsselte Datei zwischenspeichern ----------
function idb() { return new Promise((ok, f) => { const r = indexedDB.open('beak-db-mini', 1); r.onupgradeneeded = () => r.result.createObjectStore('db'); r.onsuccess = () => ok(r.result); r.onerror = () => f(r.error); }); }
async function idbPut(v) { const d = await idb(); return new Promise((ok, f) => { const t = d.transaction('db', 'readwrite'); t.objectStore('db').put(v, 'aktuell'); t.oncomplete = ok; t.onerror = () => f(t.error); }); }
async function idbGet() { const d = await idb(); return new Promise((ok, f) => { const r = d.transaction('db').objectStore('db').get('aktuell'); r.onsuccess = () => ok(r.result); r.onerror = () => f(r.error); }); }
async function idbDel() { const d = await idb(); return new Promise(ok => { const t = d.transaction('db', 'readwrite'); t.objectStore('db').delete('aktuell'); t.oncomplete = ok; }); }

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
  DB = modell; BILDER = bilder; ART = new Map(); BGLISTE = [];
  for (const u of bildUrl.values()) URL.revokeObjectURL(u); bildUrl.clear();
  for (const a of DB.a) { ART.set(a.n, a); if (DB.bg[a.n]) BGLISTE.push(a); }
  const kst = '<option value="">&lt; Keine KST &gt;</option>' + (DB.kst || []).map(([n, b]) => `<option value="${n}">${n}  ${esc(b)}</option>`).join('');
  $('#bKst').innerHTML = kst; $('#gKst').innerHTML = kst;
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
  if (v === 'info') infoZeigen();
  if (v === 'buchen') { $('#bName').textContent = ls.get('person') || ''; bSchritt(); }
  if (v === 'bg') gTabelle();
  window.scrollTo(0, 0);
}
$$('.tab').forEach(t => t.addEventListener('click', () => zeige(t.dataset.v)));

// ---------- Start ----------
let datei = null;   // ArrayBuffer der gewählten (noch verschlüsselten) Datei
async function startVorbereiten() {
  const c = await idbGet().catch(() => null);
  if (c) { datei = c.bytes; $('#fDateiText').textContent = 'Andere Datenbank wählen …'; $('#dbStand').textContent = `Gespeichert: ${c.name} (${(c.size / 1048576).toFixed(1)} MB, geladen ${c.geladen})`; }
  zeige('start'); setTimeout(() => $('#fKennwort').focus(), 50);
}
$('#fDatei').addEventListener('change', async e => {
  const f = e.target.files[0]; if (!f) return;
  datei = await f.arrayBuffer();
  $('#dbStand').textContent = `Gewählt: ${f.name} (${(f.size / 1048576).toFixed(1)} MB)`;
  $('#fDateiText').textContent = 'Andere Datenbank wählen …';
  datei._name = f.name;
});
async function oeffnen() {
  const m = $('#startMeldung'); m.className = 'meldung';
  if (!datei) { m.textContent = 'Bitte zuerst die Datenbank aus iCloud Drive wählen.'; m.classList.add('fehler'); return; }
  const pw = $('#fKennwort').value; if (!pw) { m.textContent = 'Bitte das Kennwort eingeben.'; m.classList.add('fehler'); return; }
  $('#bOeffnen').disabled = true; m.textContent = 'Entschlüssele …';
  try {
    const { modell, bilder } = await entschluesseln(datei, pw);
    if (modell.format !== 'BEAK-iPad-DB') throw new Error('Unbekanntes Datenformat.');
    laden(modell, bilder);
    if (datei._name) await idbPut({ bytes: datei, name: datei._name, size: datei.byteLength, geladen: new Date().toLocaleString('de-DE') }).catch(() => {});
    navigator.storage?.persist?.().catch(() => {});      // Safari soll den Zwischenspeicher nicht räumen
    $('#fKennwort').value = ''; m.textContent = '';
    if (!ls.get('person')) { zeige('person'); $('#fGeraet').value = ls.get('geraet') || 'iPad'; $('#fPerson').focus(); }
    else { zeige('artikel'); artikelSuchen(); }
  } catch (err) { m.textContent = err.message; m.classList.add('fehler'); }
  finally { $('#bOeffnen').disabled = false; }
}
$('#bOeffnen').addEventListener('click', oeffnen);
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
  const url = bild(a.i), s = a.s || [];
  const z = x => x != null ? fmt.format(x) : '';
  const bu = (a.bu || []).map(([d, f, m, cs, sb, ci, bb, n, bem]) => `<tr><td>${esc(d ? d.slice(8, 10) + '.' + d.slice(5, 7) + '.' + d.slice(2, 4) + ' ' + d.slice(11, 16) : '')}</td>
      <td class="r w">${f === '-' ? '−' : '+'}${fmt.format(m)}</td><td>${esc(cs)}</td><td class="r w">${z(sb)}</td><td>${esc(ci)}</td><td class="r w">${z(bb)}</td><td>${esc(n)}</td><td>${esc(bem)}</td></tr>`).join('');
  $('#aDetail').innerHTML = `
    <div class="dkopf"><span class="nr">${nrFmt(a.n)}</span><span class="bez">${esc(a.b)}</span>${a.aus ? '<span class="auslauf">Auslauf</span>' : ''}</div>
    <div class="bestand"><div class="b"><label>Lager-Bestand (Ist)</label><span>${fmt.format(a.ist ?? 0)}</span></div>
      <div class="b"><label>System-Bestand (Sys)</label><span>${fmt.format(a.sys ?? 0)}</span></div></div>
    <div class="werte">${W('Kunden-Art.-Nr.', a.k)}${W('Typ', a.t)}${W('Lagerort', a.lo)}${W('Lagerplatz', [a.lot, a.lp].filter(Boolean).join(' '))}
      ${W('Bauform', a.bf)}${W('Hersteller', a.h)}${W('Einheit', a.e)}${W('VPE', a.vpe ? fmt.format(a.vpe) : '')}${W('EAN', a.ean)}
      ${W('Sachmerkmal 1', s[0])}${W('Sachmerkmal 2', s[1])}${W('Sachmerkmal 3', s[2])}</div>
    <div class="bemlief">
      <div class="wert breit bem"><label>Bemerkung</label><span>${esc((a.bem || '').replace(/\r\n?/g, '\n'))}</span></div>
      <div class="lief"><table><thead><tr><th>Lieferant</th></tr></thead><tbody>${(a.l || []).map(n => `<tr><td>${esc(Array.isArray(n) ? n[0] : n)}</td></tr>`).join('') || '<tr><td class="fix">–</td></tr>'}</tbody></table></div>
    </div>
    <div class="unten">
      <div><h3>Letzte Buchungen</h3>${bu ? `<table><thead><tr><th>Gebucht</th><th class="r">Menge</th><th></th><th class="r">System</th><th></th><th class="r">Lager</th><th>Name / BG-Bez.</th><th>Bemerkung</th></tr></thead><tbody>${bu}</tbody></table>` : '<p class="fix klein">Keine Buchungen.</p>'}
        <div class="aktionen mt"><button class="pink" id="aBuchen">Artikel buchen</button>${DB.bg[a.n] ? '<button id="aStkl">Stückliste</button><button id="aBg">Material-Entnahme</button>' : ''}</div></div>
      <div class="bild ${url ? '' : 'leer'}">${url ? `<img src="${url}" alt="Bild ${a.n}" draggable="false">` : 'kein Bild'}</div>
    </div>`;
  $('#aBuchen').onclick = () => { buchenArtikel(a); zeige('buchen'); };
  if (DB.bg[a.n]) { $('#aStkl').onclick = () => { stklZeigen(a); zeige('stkl'); }; $('#aBg').onclick = () => { bgWaehlen(a); gModus(true); zeige('bg'); }; }
}

// ---------- Stückliste ----------
let aktStkl = null;
const refText = r => (r || []).map(x => x[0] || '').filter(Boolean).join(', ');
$('#sSuche').addEventListener('input', () => liste($('#sListe'), suche($('#sSuche').value, true).slice(0, 60), aktStkl?.n, a => { stklZeigen(a); $('#sListe').innerHTML = ''; }));
function stklZeilen(a) {
  return (DB.bg[a.n] || []).map(([nr, anz, refs], i) => { const p = ART.get(nr) || {}; return { i: i + 1, nr, bez: p.b, anz, ref: refText(refs), lo: [p.lo, p.lot, p.lp].filter(Boolean).join(' '), ist: p.ist }; });
}
function stklTabelle(z, berechnet) {
  return `<table><thead><tr><th class="r">Pos</th><th class="r">Artikel-Nr</th><th>Bezeichnung</th><th class="r">Anz</th><th>Referenzen</th><th>Lagerort</th><th class="r">Ist</th></tr></thead><tbody>
    ${z.map(r => `<tr><td class="r">${r.i}</td><td class="r w">${nrFmt(r.nr)}</td><td>${esc(r.bez)}</td><td class="r${berechnet ? ' w' : ''}">${fmt.format(r.anz)}</td><td>${esc(r.ref)}</td><td>${esc(r.lo)}</td><td class="r">${r.ist != null ? fmt.format(r.ist) : ''}</td></tr>`).join('')}</tbody></table>`;
}
function stklZeigen(a) {
  aktStkl = a; $('#sSuche').value = nrFmt(a.n) + ' ' + a.b; $('#sMeldung').textContent = '';
  const z = stklZeilen(a);
  $('#sDetail').innerHTML = `<div class="dkopf mt mb"><span class="nr">${nrFmt(a.n)}</span><span class="bez">${esc(a.b)}</span></div>
    <p class="fix klein">${z.length} Positionen · ${fmt.format(z.reduce((s, r) => s + (r.anz || 0), 0))} Teile je Baugruppe</p>${stklTabelle(z, false)}`;
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
  const name = `${aktStkl.n} ${BeakStklDruck.titel()[art]}`.replace(/[\/:]/g, '-') + '.pdf';
  letztesPdf = new File([BeakStklDruck.pdf(a)], name, { type: 'application/pdf' });
  m.className = 'meldung'; m.textContent = `${name} – ${a.zeilen.length} Zeilen` + ([0, 6].includes(art) ? ' (ohne Preise)' : '');
  return letztesPdf;
}
$('#sDruck').addEventListener('click', () => {
  const f = stklPdf(); if (!f) return;
  if (istStandalone() && navigator.canShare?.({ files: [f] })) navigator.share({ files: [f], title: f.name }).catch(() => {});
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

// ---------- Material-Entnahme ----------
let gBg = null, gListe = [], gModusNeu = true;
function gBemVorbelegen() { if (!gBg) return; const n = String($('#gAnzahl').value || ''); const t = `${n.replace('.', ',')} x ${gBg.b} (${nrFmt(gBg.n)})`; $('#gBem').value = t.slice(0, 60); }
function bgWaehlen(a) { gBg = a; $('#gBg').value = String(a.n); $('#gListe').innerHTML = ''; $('#gBez').textContent = a.b || ''; gBemVorbelegen(); }
$('#gBg').addEventListener('input', () => { gBg = null; $('#gBez').textContent = ''; liste($('#gListe'), suche($('#gBg').value, true).slice(0, 40), null, bgWaehlen); });
$('#gAnzahl').addEventListener('input', gBemVorbelegen);
/** wie AdoArtikelRepository.MaterialEntnahmePositionen: Positionen mit BC, Buchen = Auswahl_MaterialEntnahme, Bedarf = MArt × Anzahl, sortiert nach Artikel-Nr. */
function mePositionen(bg, anzahl) {
  return (DB.bg[bg.n] || []).filter(p => p[3] && ART.has(p[0])).map(p => { const a = ART.get(p[0]); return { bg: bg.n, artikelNr: a.n, bez: a.b || '', lagerort: a.lo || '', lagerplatz: `${a.lot || ''} ${a.lp || ''}`.trim(),
    bauform: a.bf || '', vpe: a.vpe || 0, bestand: a.ist || 0, bedarfStck: p[1] * anzahl, buchenStck: p[1] * anzahl, buchen: p[3] === 1 }; })
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
  const z = gListe.flatMap(b => b.positionen.map(p => ({ ...p, kst: b.kstNr, bem: b.bemerkung })));
  $('#gTabelle').innerHTML = z.length ? `<table><thead><tr><th class="r">Artikel-Nr</th><th>Buchen</th><th>Artikel-Bezeichnung</th><th>Lagerort</th><th>Lagerplatz</th><th>Bauform</th><th class="r">VPE</th>
    <th class="r">Aktueller Bestand</th><th class="r">Bedarf Stück</th><th class="r">Buchen Stück</th><th>KST</th><th>Bemerkung</th></tr></thead><tbody>${z.map(p => `<tr><td class="r w">${nrFmt(p.artikelNr)}</td>
    <td class="${p.buchen ? 'ja' : 'nein'}">${p.buchen ? 'JA' : 'NEIN'}</td><td>${esc(p.bez)}</td><td>${esc(p.lagerort)}</td><td>${esc(p.lagerplatz)}</td><td>${esc(p.bauform)}</td><td class="r">${p.vpe ? nrFmt(p.vpe) : ''}</td>
    <td class="r">${fmt.format(p.bestand)}</td><td class="r">${fmt.format(p.bedarfStck)}</td><td class="r w">${fmt.format(p.buchenStck)}</td><td>${p.kst ?? ''}</td><td>${esc(p.bem)}</td></tr>`).join('')}</tbody></table>` : '<p class="fix klein">Aktuelle Liste ist leer.</p>';
}
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
  if (istStandalone() && navigator.canShare?.({ files: [file] })) { navigator.share({ files: [file], title: name }).catch(() => {}); weg = 'Bitte im Teilen-Menü „In Dateien sichern“ → iCloud Drive/BEAK/Buchungen wählen.'; }
  else { const a = document.createElement('a'); a.href = URL.createObjectURL(file); a.download = name; document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 4000); weg = 'Die Datei wird in den Safari-Download-Ordner (iCloud Drive/BEAK/Buchungen) geladen.'; }
  dialog('Buchung gespeichert', `${text}\n\nDatei: ${name}\n${weg}\n\nAm PC erscheint „Neue Buchungen vom iPad vorhanden!“, sobald iCloud die Datei synchronisiert hat.`, !!navigator.canShare?.({ files: [file] }));
}
function dialog(titel, text, teilen) {
  $('#dlgTitel').textContent = titel; $('#dlgText').innerText = text; $('#dlgTeilen').hidden = !teilen; $('#dlg').hidden = false;
}
$('#dlgOk').addEventListener('click', () => $('#dlg').hidden = true);
$('#dlgTeilen').addEventListener('click', () => letzteDatei && navigator.share({ files: [letzteDatei] }).catch(() => {}));

// ---------- Einstellungen ----------
function infoZeigen() {
  $('#iPerson').textContent = ls.get('person') || ''; $('#iGeraet').textContent = ls.get('geraet') || 'iPad';
  $('#iDb').textContent = DB ? `Stand ${DB.erzeugt} · ${DB.quelle} · ${nrFmt(DB.a.length)} Artikel · Stückliste: ${nrFmt(Object.keys(DB.bg).length)} · ${nrFmt(DB.img.length)} Bilder` : '';
  $('#iModus').textContent = istStandalone() ? 'Home-Bildschirm-App: Buchungen über „Teilen → In Dateien sichern“' : 'Safari-Tab: Buchungen als Download (Download-Ordner in den Einstellungen auf iCloud Drive/BEAK/Buchungen stellen)';
  const j = JSON.parse(ls.get('journal') || '[]');
  $('#iJournal').innerHTML = j.length ? j.map(x => `<li><span class="anz">${esc(x.zeit)}</span> · ${esc(x.text)}<br><span class="klein">${esc(x.name)}</span></li>`).join('') : '<li class="fix">Noch keine Buchungen.</li>';
}
$('#iPersonAendern').addEventListener('click', () => { $('#fPerson').value = ls.get('person') || ''; $('#fGeraet').value = ls.get('geraet') || 'iPad'; zeige('person'); });
$('#iSperren').addEventListener('click', () => { DB = null; BILDER = null; ART = new Map(); BGLISTE = []; aktArt = aktStkl = bArt = gBg = null; gListe = []; $('#aDetail').innerHTML = $('#sDetail').innerHTML = ''; startVorbereiten(); });
$('#iNeueDb').addEventListener('click', async () => { await idbDel(); datei = null; $('#dbStand').textContent = ''; $('#fDateiText').textContent = 'Datenbank wählen …'; $('#iSperren').click(); });
// beim Verlassen/Ausblenden nach 15 Minuten automatisch sperren
let versteckt = 0;
document.addEventListener('visibilitychange', () => { if (document.hidden) versteckt = Date.now(); else if (DB && versteckt && Date.now() - versteckt > 15 * 60e3) $('#iSperren').click(); });

if ('serviceWorker' in navigator && isSecureContext) navigator.serviceWorker.register('sw.js').catch(() => {});
if (!isSecureContext || !crypto.subtle) { $('#startMeldung').textContent = 'Diese Seite muss über https geöffnet werden (Verschlüsselung).'; $('#startMeldung').classList.add('fehler'); }
startVorbereiten();
