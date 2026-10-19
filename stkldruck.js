/* BEAK DB mini – Stückliste-Druck als PDF, Nachbau von StklDruck.cs (Windows) mit denselben Layouts (stkllayout.js, aus C# erzeugt)
 * und derselben Sortierung (Ränge aus der iPad-Datenbank, in C# mit StuecklisteWindow.DruckSortierung berechnet).
 * Unterschied zum Windows-Druck: KEINE Preise (Spalten Einz.-P / Summe / Einzel-Preis bleiben leer, kein Kostenblock).
 * Schrift: Helvetica (Arial-metrisch); Breiten aus pdfbreiten.js.
 */
'use strict';
var BeakStklDruck = (function () {
  const L = () => BEAK_STKL_LAYOUTS, W = () => BEAK_PDF_BREITEN;
  const SPEZIAL = { '€': 0x80, '‚': 0x82, 'ƒ': 0x83, '„': 0x84, '…': 0x85, '†': 0x86, '‡': 0x87, 'ˆ': 0x88, '‰': 0x89, 'Š': 0x8A, '‹': 0x8B, 'Œ': 0x8C, 'Ž': 0x8E,
    '‘': 0x91, '’': 0x92, '“': 0x93, '”': 0x94, '•': 0x95, '–': 0x96, '—': 0x97, '˜': 0x98, '™': 0x99, 'š': 0x9A, '›': 0x9B, 'œ': 0x9C, 'ž': 0x9E, 'Ÿ': 0x9F };
  const code = ch => { const c = ch.charCodeAt(0); if (SPEZIAL[ch]) return SPEZIAL[ch]; if (c >= 32 && c < 127) return c; if (c >= 0xA0 && c <= 0xFF) return c; return 63; };
  const breite = (s, pt, fett) => { const t = W()[fett ? 'b' : 'n']; let w = 0; for (const ch of s) w += t[code(ch) - 32] || 0; return w * pt / 1000; };
  // Zahlformate wie .NET (de-DE): "0.##", "N0"
  const mg = v => { const r = Math.round(v * 100) / 100; return String(r).replace('.', ','); };
  const n0 = v => new Intl.NumberFormat('de-DE', { maximumFractionDigits: 0 }).format(Math.round(v));
  const nrEdv = n => new Intl.NumberFormat('de-DE').format(n);
  const zwei = x => String(x).padStart(2, '0');

  // ---------- Auftrag (wie StuecklisteWindow.DruckAuftrag) ----------
  function refVergleich(a, b) {
    const t = x => { x = x || ''; let i = 0; while (i < x.length && !/\d/.test(x[i])) i++; const p = x.slice(0, i); let j = i; while (j < x.length && /\d/.test(x[j])) j++; return [p.toUpperCase(), parseInt(x.slice(i, j) || '0', 10)]; };
    const [pa, na] = t(a), [pb, nb] = t(b); if (pa !== pb) return pa < pb ? -1 : 1; return na - nb;
  }
  function stabil(l, cmp) { return l.map((x, i) => [x, i]).sort((p, q) => cmp(p[0], q[0]) || p[1] - q[1]).map(p => p[0]); }
  function auftrag(db, art, bgNr, anzahl, bearbeiter, datum) {
    if (!(anzahl > 0)) anzahl = 1;
    const ART = new Map(db.a.map(a => [a.n, a]));
    const rang = {}; const n = db.dr.n;
    for (const k of ['0', '1', '2', '3', '4', 'j']) { const m = new Map(); db.dr[k].forEach((r, i) => m.set(n[i], r)); rang[k] = m; }
    const pos = db.bg[bgNr] || [];
    // Reihenfolge wie Windows: zuerst Unter-Baugruppen (nach Nr), dann die übrigen Artikel
    const kopf = new Set(db.k || []);
    const alle = [...stabil(pos.filter(p => kopf.has(p[0])), (x, y) => x[0] - y[0]), ...pos.filter(p => !kopf.has(p[0]))].filter(p => p[0] > 0);
    const block = art === 4 || art === 5;
    const Z = (p, ref = '', bem = '') => {
      const a = ART.get(p[0]);
      let f = ((a && a.lp) || '').trim(); if (block && f.length > 0 && f.length < 3 && /^\d+$/.test(f)) f = f.padStart(3, '0');
      return { nr: p[0], bez: a ? (a.b || '') : '(unbekannt)', bauform: (a && a.bf) || '', lief: (a && a.dl) || '', bestnr: '',   // Bestell-Nr. nicht in BEAK DB mini
        edv: nrEdv(p[0]),
        lagerplatz: `${((a && a.lot) || '').trim()} ${f}`.trim(), stck: p[1] * anzahl, vpe: (a && a.vpe) || 0, sys: (a && a.sys) || 0, lager: (a && a.ist) || 0, ref, bem };
    };
    const R = (k, z) => rang[k].has(z.nr) ? rang[k].get(z.nr) : Infinity;
    let zeilen;
    if (art === 7 || art === 8) {
      zeilen = [];
      for (const p of alle) { const refs = p[2] || []; if (!refs.length) zeilen.push(Z(p)); else for (const [r, b] of refs) zeilen.push(Z(p, r || '', b || '')); }
      zeilen = art === 7 ? stabil(zeilen, (x, y) => (R('j', x) - R('j', y)) || refVergleich(x.ref, y.ref))
        : stabil(zeilen, (x, y) => ((x.ref.length === 0) - (y.ref.length === 0)) || refVergleich(x.ref, y.ref));
    } else {
      const k = String({ 0: 0, 6: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 4 }[art]);
      zeilen = stabil(alle.map(p => Z(p)), (x, y) => R(k, x) - R(k, y));
    }
    const bg = ART.get(bgNr);
    return { art, bgBez: (bg && bg.b) || '', bgEdv: nrEdv(bgNr), anzahl, bearbeiter: bearbeiter || '', datum: datum || new Date(), zeilen };
  }

  function wert(f, z) {
    switch (f) {
      case 'bez': case 'bauform': case 'lief': case 'bestnr': case 'edv': case 'lagerplatz': case 'ref': case 'bem': return z[f] || '';
      case 'stck': return mg(z.stck);
      case 'vpe': return z.vpe > 0 ? n0(z.vpe) : '';
      case 'sys': return n0(z.sys); case 'lager': return n0(z.lager);
      case 'differenz': return z.lager < z.stck ? mg(z.stck - z.lager) : '';
      default: return '';            // ek / summe / vk: keine Preise auf dem iPad; "leer" = Notizen
    }
  }

  // ---------- Seiten (wie StklDruck.Seiten, ohne Kostenblock) ----------
  function seiten(a, l) {
    const erste = l.ersteZeileH > 0 ? l.ersteZeileH : l.zeileH;
    const pro = Math.max(1, 1 + Math.floor((l.tabEnde - l.kopfY1 - erste + 0.5) / l.zeileH));
    const s = []; for (let i = 0; i < a.zeilen.length; i += pro) s.push([i, Math.min(a.zeilen.length, i + pro)]);
    if (!s.length) s.push([0, 0]); return s;
  }

  // ---------- PDF ----------
  function seiteZeichnen(a, l, seite, anzahlSeiten, von, bis) {
    const H = l.h, o = [];
    const f = v => (Math.round(v * 1000) / 1000).toString();
    const esc = s => { let r = ''; for (const ch of s) { const c = code(ch); const z = String.fromCharCode(c); r += (z === '(' || z === ')' || z === '\\') ? '\\' + z : z; } return r; };
    const farbe = (g) => `${f(g)} ${f(g)} ${f(g)} RG`;
    const T = (s, x, y, pt, fett, ausr = 'L', x0, x1) => {
      if (!s) return; const w = breite(s, pt, fett); const xx = ausr === 'R' ? x - w : ausr === 'C' ? x - w / 2 : x;
      const txt = `BT /${fett ? 'F2' : 'F1'} ${f(pt)} Tf 1 0 0 1 ${f(xx)} ${f(H - y)} Tm (${esc(s)}) Tj ET`;
      if (x0 != null && x1 != null) o.push(`q ${f(x0)} ${f(H - (y + pt * 0.5))} ${f(x1 - x0)} ${f(pt * 1.7)} re W n ${txt} Q`); else o.push(txt);
    };
    const linie = (x0, y0, x1, y1, w = 0.5, g = 0) => o.push(`${farbe(g)} ${f(w)} w ${f(x0)} ${f(H - y0)} m ${f(x1)} ${f(H - y1)} l S`);
    const HL = (x0, x1, y, w, g) => linie(x0, y, x1, y, w, g), VL = (x, y0, y1, w, g) => linie(x, y0, x, y1, w, g);
    const rect = (x0, y0, x1, y1, w, g) => o.push(`${farbe(g)} ${f(w)} w ${f(x0)} ${f(H - y1)} ${f(x1 - x0)} ${f(y1 - y0)} re S`);
    o.push('0 g');
    rect(l.frameL, l.frameTop, l.frameR, l.kopfY0, 0.5, 0x90 / 255);
    T(l.titel, l.titelX, l.titelY, l.titelSchrift, true);
    HL(l.titelX, l.titelX + breite(l.titel, l.titelSchrift, true), l.titelUl, 0.5, 0);
    const d = a.datum, datum = l.datumText + `${zwei(d.getDate())}.${zwei(d.getMonth() + 1)}.${d.getFullYear()}`;
    const dB = breite(datum, l.titelSchrift, true), dX1 = l.datumUlEnde - 9.5;
    T(datum, dX1, l.titelY + 2, l.titelSchrift, true, 'R');
    HL(dX1 - dB - 3, l.datumUlEnde, l.datumUl, 1.2, 0);
    const anz = a.art === 7 ? '' : `${mg(a.anzahl)} x `;
    T(`${anz}${a.bgBez} ( EDV-Nr: ${a.bgEdv} )`, l.titelX, l.bgY, l.bgSchrift, true);
    const sp = l.spalten, tL = sp[0].x0, tR = sp[sp.length - 1].x1;
    HL(tL, tR, l.kopfY0); HL(tL, tR, l.kopfY1, l.kopfDick, 0);
    sp.forEach((s, i) => {
      const mx = (s.x0 + s.x1) / 2;
      if (s.k1 === 'Mengen') T('Mengen', (s.x0 + sp[i + 1].x1) / 2, l.kopfY1 - l.k1Abst, l.k1Schrift, true, 'C');
      else if (s.k1.length > 0) T(s.k1, mx, l.kopfY1 - l.k1Abst, l.k1Schrift, true, 'C');
      if (s.k2 === 'Notizen' && l.notizX > 0) T(s.k2, l.notizX, l.kopfY1 - l.k2Abst, l.k2Schrift, true);
      else T(s.k2, mx, l.kopfY1 - l.k2Abst, l.k2Schrift, true, 'C');
    });
    let y = l.kopfY1;
    for (let i = von; i < bis; i++) {
      const z = a.zeilen[i], h = i === von && l.ersteZeileH > 0 ? l.ersteZeileH : l.zeileH, yb = y + h;
      const ty = l.notizlinien ? y + h * 0.62 : yb - 3.6;
      for (const s of sp) {
        const w = wert(s.f, z), fett = s.fett;
        const x = s.a === 'R' ? s.x1 - 3 : s.a === 'C' ? (s.x0 + s.x1) / 2 : s.x0 + l.einzug;
        T(w, x, ty, l.schrift, fett, s.a, s.x0 + 1, s.x1 - 1);
      }
      HL(tL, tR, yb); y = yb;
    }
    const yEnde = Math.max(y, l.kopfY1);
    VL(tL, l.kopfY0, yEnde); VL(tR, l.kopfY0, yEnde);
    sp.slice(1).forEach(s => VL(s.x0, l.kopfY0, yEnde));
    HL(tL, tR, yEnde);
    rect(l.frameL, l.fussY0, l.frameR, l.fussY1, 0.5, 0);
    const fy = (l.fussY0 + l.fussY1) / 2 + l.fussSchrift * 0.36;
    T('Gedruckt von ' + a.bearbeiter, l.frameL + 6, fy, l.fussSchrift, true);
    T('BEAK electronic', l.fussBeakX, fy, l.fussSchrift, true);
    T(`Seite ${seite + 1} von ${anzahlSeiten}`, l.frameR - 5, fy, l.fussSchrift, true, 'R');
    return o.join('\n');
  }
  function pdf(a) {
    const l = L().layouts[a.art], s = seiten(a, l);
    const objs = [];   // Index 0 = Objekt 1
    const add = t => { objs.push(t); return objs.length; };
    const kat = add(''), pages = add(''), f1 = add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>'),
      f2 = add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>');
    const kids = [];
    s.forEach(([von, bis], i) => {
      const inhalt = seiteZeichnen(a, l, i, s.length, von, bis);
      const c = add(`<< /Length ${inhalt.length} >>\nstream\n${inhalt}\nendstream`);
      kids.push(add(`<< /Type /Page /Parent ${pages} 0 R /MediaBox [0 0 ${l.b} ${l.h}] /Resources << /Font << /F1 ${f1} 0 R /F2 ${f2} 0 R >> >> /Contents ${c} 0 R >>`));
    });
    objs[kat - 1] = `<< /Type /Catalog /Pages ${pages} 0 R >>`;
    objs[pages - 1] = `<< /Type /Pages /Kids [${kids.map(k => k + ' 0 R').join(' ')}] /Count ${kids.length} >>`;
    const titel = L().titel[a.art] + ' ' + a.bgEdv;
    const info = add(`<< /Title (${titel.replace(/[()\\]/g, m => '\\' + m).replace(/[^\x20-\x7e]/g, '?')}) /Creator (BEAK DB mini) >>`);
    let out = '%PDF-1.4\n%\xE2\xE3\xCF\xD3\n'; const off = [];
    objs.forEach((t, i) => { off.push(out.length); out += `${i + 1} 0 obj\n${t}\nendobj\n`; });
    const x = out.length;
    out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n` + off.map(v => String(v).padStart(10, '0') + ' 00000 n \n').join('');
    out += `trailer\n<< /Size ${objs.length + 1} /Root ${kat} 0 R /Info ${info} 0 R >>\nstartxref\n${x}\n%%EOF\n`;
    const b = new Uint8Array(out.length); for (let i = 0; i < out.length; i++) b[i] = out.charCodeAt(i) & 0xFF; return b;
  }
  return { auftrag, pdf, titel: () => L().titel, hatLayout: art => art >= 0 && art < L().titel.length, refVergleich };
})();
if (typeof module !== 'undefined') module.exports = BeakStklDruck;
