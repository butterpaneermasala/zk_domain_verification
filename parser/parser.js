#!/usr/bin/env node
/**
 * Email parser (Node.js)
 * - Usage: node index.js [path/to/email.eml]
 * - Or: cat email.eml | node index.js
 *
 * Dependencies: mailparser, iconv-lite, quoted-printable
 * npm install mailparser iconv-lite quoted-printable
 *
 * Output: JSON printed to stdout
 */

const fs = require('fs');
const { simpleParser } = require('mailparser');
const iconv = require('iconv-lite');
const qp = require('quoted-printable');

// ---------- Helpers ----------
const CRLF = '\r\n';

function toUTF8String(buf, charset) {
  if (!charset) {
    // try to detect or assume utf-8
    return buf.toString('utf8');
  }
  try {
    const name = charset.toLowerCase();
    if (name === 'utf-8' || name === 'utf8') return buf.toString('utf8');
    // iconv-lite supports many legacy encodings
    if (iconv.encodingExists(name)) return iconv.decode(buf, name);
    return buf.toString('utf8');
  } catch (e) {
    // fallback
    return buf.toString('utf8');
  }
}

function normalizeLineEndings(s) {
  // Ensure we operate on a string with CRLF normalized
  // 1) convert CRLF -> LF, CR -> LF, then LF -> CRLF
  return s.replace(/\r\n/g, '\n').replace(/\r/g, '\n').replace(/\n/g, '\r\n');
}

function ensureCRLFString(bufOrStr) {
  let s = Buffer.isBuffer(bufOrStr) ? bufOrStr.toString('binary') : String(bufOrStr);
  return normalizeLineEndings(s);
}

function splitHeadersAndBody(normalizedText) {
  const sep = '\r\n\r\n';
  const idx = normalizedText.indexOf(sep);
  if (idx === -1) {
    return { headersRaw: normalizedText, bodyRaw: '' };
  }
  const headersRaw = normalizedText.substring(0, idx + 2); // keep trailing CRLF on last header line
  const bodyRaw = normalizedText.substring(idx + 4); // after CRLF CRLF
  return { headersRaw, bodyRaw };
}

function parseHeaders(headersRaw) {
  // returns ordered array [{ name, value, raw, index }]
  const lines = headersRaw.split(/\r\n/);
  const headers = [];
  let current = null;
  let index = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line === '') continue; // skip accidental empty
    if (/^[ \t]/.test(line)) {
      // continuation
      if (current) {
        current.raw += '\r\n' + line;
        current.value += ' ' + line.trim();
      } else {
        // ignore stray continuation
      }
    } else {
      const pos = line.indexOf(':');
      let name = '', value = '';
      if (pos === -1) {
        value = line;
      } else {
        name = line.substring(0, pos);
        value = line.substring(pos + 1).trim();
      }
      const hdr = { name, value, raw: line + '\r\n', index };
      headers.push(hdr);
      current = hdr;
      index++;
    }
  }
  return headers;
}

function findDKIMSignatureHeaders(headersList) {
  return headersList.filter(h => h.name.toLowerCase() === 'dkim-signature');
}

function unfoldDKIMValue(value) {
  // Replace CRLF + WSP with single space. For our header values (already unfolded in parseHeaders),
  // this may be enough. Keep robust: collapse multiple spaces.
  return value.replace(/\r\n[ \t]+/g, ' ').replace(/\s+/g, ' ').trim();
}

function parseDKIMHeaderIntoTags(dkimHeader) {
  // dkimHeader.value is the unfolded value (but we still unfold defensively)
  const raw = dkimHeader.raw;
  const v = unfoldDKIMValue(dkimHeader.value);
  // split on semicolons not inside quotes - naive split is sufficient for most DKIM headers
  const pieces = v.split(';');
  const tags = {};
  for (let piece of pieces) {
    piece = piece.trim();
    if (!piece) continue;
    const eq = piece.indexOf('=');
    if (eq === -1) {
      tags[piece] = true;
      continue;
    }
    let tag = piece.substring(0, eq).trim();
    let val = piece.substring(eq + 1).trim();
    if (val.startsWith('"') && val.endsWith('"')) {
      val = val.substring(1, val.length - 1);
    }
    tags[tag] = val;
  }
  if (tags.h) {
    // split h list by colon
    tags._h_list = tags.h.split(':').map(x => x.trim()).filter(x => x.length > 0);
  } else {
    tags._h_list = [];
  }
  return { raw, tags };
}

function decodeContent(rawBuffer, cte, charset) {
  if (!rawBuffer) return '';
  let buf = Buffer.from(rawBuffer);
  if (!cte) {
    // no CTE: assume raw
  } else {
    const lower = cte.toLowerCase();
    if (lower === 'base64') {
      try {
        buf = Buffer.from(buf.toString('utf8').replace(/\r?\n/g, ''), 'base64');
      } catch (e) {
        // fallback keep buf
      }
    } else if (lower === 'quoted-printable' || lower === 'quotedprintable') {
      try {
        const decoded = qp.decode(buf.toString('binary'));
        buf = Buffer.from(decoded, 'binary');
      } catch (e) {}
    } else {
      // 7bit/8bit/binary - nothing to do
    }
  }
  return toUTF8String(buf, charset);
}

// DKIM canonicalization (body)
function canonicalizeBody(bodyRawString, dkimTags) {
  // bodyRawString must be a string with CRLF normalized
  // choose body canonicalization mode
  let bodyMode = 'simple';
  if (dkimTags && dkimTags.c) {
    const ctag = dkimTags.c;
    const parts = ctag.split('/');
    if (parts.length === 2) {
      bodyMode = parts[1] || 'simple';
    } else if (parts.length === 1) {
      bodyMode = 'simple';
    }
  }

  // split into lines by CRLF
  const lines = bodyRawString.length === 0 ? [] : bodyRawString.split('\r\n');

  if (bodyMode === 'simple') {
    // remove trailing empty lines
    let end = lines.length;
    while (end > 0 && lines[end - 1] === '') end--;
    const kept = lines.slice(0, end);
    const res = kept.join('\r\n') + '\r\n';
    return res;
  } else {
    // relaxed
    const newlines = [];
    for (let ln of lines) {
      // remove trailing WSP
      ln = ln.replace(/[ \t]+$/g, '');
      // compress WSP inside line to single SP
      ln = ln.replace(/[ \t]+/g, ' ');
      newlines.push(ln);
    }
    // remove trailing empty lines
    let end = newlines.length;
    while (end > 0 && newlines[end - 1] === '') end--;
    const kept = newlines.slice(0, end);
    const res = kept.join('\r\n') + '\r\n';
    return res;
  }
}

// Header canonicalization (simple + relaxed), input headerObj {name, value, raw, index}
function canonicalizeHeader(headerObj, headerMode) {
  headerMode = (headerMode || 'simple').toLowerCase();
  if (headerMode === 'simple') {
    // ensure CRLF end
    let s = headerObj.raw;
    if (!s.endsWith('\r\n')) s = s + '\r\n';
    return s;
  } else {
    // relaxed:
    const name = headerObj.name.toLowerCase();
    // unfold raw value: replace CRLF + WSP with single space
    let value = headerObj.value.replace(/\r\n[ \t]+/g, ' ');
    // remove leading and trailing WSP
    value = value.replace(/^[ \t]+|[ \t]+$/g, '');
    // compress runs of WSP to single SP
    value = value.replace(/[ \t]+/g, ' ');
    return name + ':' + value + '\r\n';
  }
}

function assembleCanonicalizedHeaderBlock(chosenDKIM, headersList) {
  if (!chosenDKIM) return null;
  const hlist = chosenDKIM.tags._h_list || [];
  const headerMode = (chosenDKIM.tags.c || 'simple').split('/')[0] || 'simple';
  const usedIndices = new Set();
  const blockPieces = [];

  function findRightmostUnused(headersList, headerName) {
    const lname = headerName.toLowerCase();
    for (let i = headersList.length - 1; i >= 0; i--) {
      const h = headersList[i];
      if (h.name.toLowerCase() === lname && !usedIndices.has(h.index)) return h;
    }
    return null;
  }

  for (let name of hlist) {
    const found = findRightmostUnused(headersList, name);
    if (!found) {
      // skip but record nothing
      continue;
    }
    usedIndices.add(found.index);
    const canonicalized = canonicalizeHeader(found, headerMode);
    blockPieces.push(canonicalized);
  }

  // DKIM-Signature header appended with b= emptied
  const originalDkimRaw = chosenDKIM.raw; // raw includes the header name and folded parts
  // find b= and replace its value with empty (but keep 'b=')
  // This replacement should be done on the unfolded value to be safe
  const dkimValueUnfold = unfoldDKIMValue(chosenDKIM.raw.replace(/^DKIM-Signature:\s*/i, ''));
  // replace b=... (first occurrence) with b=
  const replaced = dkimValueUnfold.replace(/(^|;)\s*b\s*=\s*([^;]*)/i, '$1b=');
  // reconstruct header string
  const dkimHeaderForCanon = 'dkim-signature:' + replaced + '\r\n';
  // canonicalize
  const fakeHeaderObj = { name: 'dkim-signature', value: replaced, raw: dkimHeaderForCanon, index: -1 };
  const dkimCanon = canonicalizeHeader(fakeHeaderObj, headerMode);
  blockPieces.push(dkimCanon);

  // join pieces
  return blockPieces.join('');
}

function chooseDKIMSignature(parsedDKIMs, claimedDomain) {
  if (!parsedDKIMs || parsedDKIMs.length === 0) return null;
  if (claimedDomain) {
    for (const p of parsedDKIMs) {
      if (p.tags.d && p.tags.d.toLowerCase() === claimedDomain.toLowerCase()) return p;
    }
  }
  // prefer supported algorithms
  const supported = ['rsa-sha256', 'ed25519-sha256'];
  for (const p of parsedDKIMs) {
    if (p.tags.a && supported.includes(p.tags.a.toLowerCase())) return p;
  }
  // pick first
  return parsedDKIMs[0];
}

function findNonce(decodedText, patterns) {
  if (!decodedText) return null;
  for (const pat of patterns) {
    const re = new RegExp(pat);
    const m = decodedText.match(re);
    if (m) {
      return { match: m[0], index: m.index, context: decodedText.substring(Math.max(0, m.index - 40), Math.min(decodedText.length, m.index + m[0].length + 40)) };
    }
  }
  return null;
}

// ---------- Main parse flow ----------
async function parseEmailRawBuffer(rawBuf, options = {}) {
  options = Object.assign({ noncePatterns: ['\\b[A-Z0-9]{4}-[A-Z0-9]{4}\\b'] }, options);

  // preserve raw bytes
  const rawBytes = Buffer.from(rawBuf);

  // produce normalized string for parsing (but keep rawBytes)
  const normalized = normalizeLineEndings(rawBytes.toString('binary'));

  const { headersRaw, bodyRaw } = splitHeadersAndBody(normalized);

  const headersList = parseHeaders(headersRaw);

  // extract DKIM Signature headers
  const dkimHeaders = findDKIMSignatureHeaders(headersList);
  const parsedDKIMs = dkimHeaders.map(h => parseDKIMHeaderIntoTags(h));

  // Use mailparser to parse MIME & decoded text/parts (it expects a stream or buffer of entire email)
  let parsedMail = null;
  try {
    parsedMail = await simpleParser(rawBytes);
  } catch (e) {
    // best-effort fallback: parsedMail remains null
    parsedMail = null;
  }

  // assemble parts summary from mailparser if available; otherwise attempt simple fallback
  const parts = [];
  if (parsedMail) {
    // mailparser exposes text, html, attachments, headers map, etc.
    if (parsedMail.text) {
      parts.push({ contentType: 'text/plain', cte: null, charset: null, decoded: parsedMail.text, size: Buffer.byteLength(parsedMail.text, 'utf8'), isAttachment: false });
    }
    if (parsedMail.html) {
      parts.push({ contentType: 'text/html', cte: null, charset: null, decoded: parsedMail.html, size: Buffer.byteLength(parsedMail.html, 'utf8'), isAttachment: false });
    }
    if (parsedMail.attachments && parsedMail.attachments.length) {
      for (const a of parsedMail.attachments) {
        parts.push({
          contentType: a.contentType || 'application/octet-stream',
          cte: null,
          charset: null,
          decoded: undefined,
          size: a.size || (a.content ? a.content.length : 0),
          filename: a.filename,
          isAttachment: true
        });
      }
    }
  } else {
    // fallback: put raw body as single part
    const fallbackDecoded = decodeContent(Buffer.from(bodyRaw, 'binary'), null, 'utf8');
    parts.push({ contentType: 'text/plain', cte: null, charset: 'utf8', decoded: fallbackDecoded, size: Buffer.byteLength(fallbackDecoded, 'utf8'), isAttachment: false });
  }

  // pick human text
  let decodedText = null;
  // prefer text/plain part
  const txtPart = parts.find(p => p.contentType && p.contentType.startsWith('text/plain') && !p.isAttachment);
  if (txtPart) decodedText = txtPart.decoded;
  else {
    const htmlPart = parts.find(p => p.contentType && p.contentType.startsWith('text/html') && !p.isAttachment);
    if (htmlPart) {
      // naive HTML->text: strip tags (simple)
      decodedText = htmlPart.decoded.replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, '').replace(/<\/?[^>]+(>|$)/g, '');
    } else if (parsedMail && parsedMail.text) {
      decodedText = parsedMail.text;
    } else {
      decodedText = decodeContent(Buffer.from(bodyRaw, 'binary'), null, 'utf8');
    }
  }

  // canonicalize body according to chosen DKIM (choose first DKIM for canonicalization if any)
  const chosenDKIM = parsedDKIMs.length ? parsedDKIMs[0] : null;
  const canonicalizedBody = canonicalizeBody(bodyRaw, chosenDKIM ? chosenDKIM.tags : null);

  // assemble canonicalized header block for chosen DKIM (use header mode)
  const canonicalizedHeaderBlock = assembleCanonicalizedHeaderBlock(chosenDKIM, headersList);

  // find nonce with provided patterns
  const nonce = findNonce(decodedText, options.noncePatterns);

  // compute some meta
  const meta = {
    hasMultipleDKIM: parsedDKIMs.length > 1,
    contentType: parsedMail ? (parsedMail.headers.get('content-type') || null) : null,
    charset: parsedMail && parsedMail.headers.get('content-type') ? (parsedMail.headers.get('content-type').value && parsedMail.headers.get('content-type').value.charset ? parsedMail.headers.get('content-type').value.charset : null) : null,
    sizeBytes: rawBytes.length
  };

  // prepare output
  const out = {
    dkim: parsedDKIMs.map((d, i) => ({ raw: d.raw, tags: d.tags, selected: i === 0 })),
    headers: headersList.map(h => ({ name: h.name, value: h.value, index: h.index })),
    body: {
      rawBase64: rawBytes.slice(rawBytes.length - Buffer.byteLength(bodyRaw, 'binary')).length ? Buffer.from(bodyRaw, 'binary').toString('base64') : Buffer.from('').toString('base64'),
      // rawBase64 derived from the bodyRaw string we used (CRLF-normalized). Keep it binary-safe.
      canonicalized: canonicalizedBody,
      parts: parts.map(p => ({ contentType: p.contentType, size: p.size || null, isAttachment: p.isAttachment || false })),
      decodedTextSnippet: decodedText ? decodedText.slice(0, 1024) : '',
    },
    canonicalizedHeaderBlock: canonicalizedHeaderBlock,
    nonce,
    meta,
    errors: []
  };

  return out;
}

// ---------- CLI ----------
async function main() {
  try {
    let inputBuffer = null;
    const arg = process.argv[2];
    if (arg && fs.existsSync(arg)) {
      inputBuffer = fs.readFileSync(arg);
    } else {
      // read stdin
      const stat = fs.fstatSync(0);
      if (stat && stat.size > 0) {
        // piped input
        inputBuffer = fs.readFileSync(0);
      } else {
        console.error('Usage: node index.js [email.eml]  OR pipe raw email into stdin');
        process.exit(2);
      }
    }

    const result = await parseEmailRawBuffer(inputBuffer);
    // pretty print
    process.stdout.write(JSON.stringify(result, null, 2));
  } catch (err) {
    console.error('Fatal error:', err);
    process.exit(1);
  }
}

if (require.main === module) main();
