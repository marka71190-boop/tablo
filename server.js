'use strict';
/*
 * Табло «Пирамида» — сервер.
 * Переменные окружения:
 *   PORT            порт (по умолчанию 8080)
 *   ADMIN_PASSWORD  пароль оператора (обязательно задайте!)
 *   SESSION_SECRET  секрет для подписи входа (необязательно)
 *   DATABASE_URL    postgresql://user:pass@host:5432/db?sslmode=require — постоянное хранение (рекомендуется)
 *   DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME, DB_SSLMODE — то же самое отдельными переменными
 *   DATABASE_CA     содержимое root.crt (необязательно, для проверки сертификата базы)
 *   DATA_DIR        папка для файлового хранения, если базы нет (по умолчанию ./data)
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = +process.env.PORT || 8080;
const PASSWORD = process.env.ADMIN_PASSWORD || 'admin';
const SECRET = process.env.SESSION_SECRET || crypto.createHash('sha256').update('tablo:' + PASSWORD).digest('hex');
const PUB = path.join(__dirname, 'public');
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const MAX_BODY = 8 * 1024 * 1024;
const MAX_MEDIA = 40 * 1024 * 1024; // картинка или видео для заставки перерыва

/* ===================== storage ===================== */
const store = { kind: 'file', ready: null };
let mem = {};
function dbConfig() {
  const env = process.env;
  let cfg, sslmode;
  if (env.DATABASE_URL) {
    // sslmode / sslrootcert из строки убираем: pg иначе перекрывает ими наши настройки SSL
    const u = new URL(env.DATABASE_URL.trim());
    sslmode = u.searchParams.get('sslmode') || (u.searchParams.get('ssl') === 'true' ? 'require' : null);
    for (const k of ['sslmode', 'ssl', 'sslrootcert', 'sslcert', 'sslkey', 'uselibpqcompat']) u.searchParams.delete(k);
    cfg = { connectionString: u.toString() };
  } else if (env.DB_HOST) {
    // отдельные переменные — удобно, если в пароле есть символы вроде @ # / ?
    cfg = { host: env.DB_HOST, port: +env.DB_PORT || 5432, user: env.DB_USER, password: env.DB_PASSWORD, database: env.DB_NAME || 'default_db' };
    sslmode = env.DB_SSLMODE || null;
  } else return null;
  if (env.DB_SSLMODE) sslmode = env.DB_SSLMODE;
  if (sslmode && sslmode !== 'disable') {
    // Корневой сертификат Timeweb: содержимое root.crt в DATABASE_CA или путь к файлу в PGSSLROOTCERT
    let ca = env.DATABASE_CA ? env.DATABASE_CA.replace(/\\n/g, '\n') : null;
    if (!ca && env.PGSSLROOTCERT && fs.existsSync(env.PGSSLROOTCERT)) ca = fs.readFileSync(env.PGSSLROOTCERT, 'utf8');
    cfg.ssl = ca ? { ca, rejectUnauthorized: true, checkServerIdentity: sslmode === 'verify-full' ? undefined : () => undefined } : { rejectUnauthorized: false };
  } else cfg.ssl = false;
  return cfg;
}
const DB = dbConfig();
if (DB) {
  const { Pool } = require('pg');
  const pool = new Pool({ ...DB, max: 5, connectionTimeoutMillis: 15000 });
  pool.on('error', e => console.error('DB pool error:', e.message));
  store.kind = 'postgres';
  store.ready = (async () => {
    await pool.query('CREATE TABLE IF NOT EXISTS tablo_kv (k TEXT PRIMARY KEY, v TEXT NOT NULL, updated TIMESTAMPTZ DEFAULT now())');
    const r = await pool.query('SELECT k, v FROM tablo_kv');
    for (const row of r.rows) { try { mem[row.k] = JSON.parse(row.v); } catch (e) {} }
  })();
  const pending = new Map(); let timer = null;
  store.flush = async () => {
    timer = null; const items = [...pending]; pending.clear();
    for (const [k, del] of items) {
      try {
        if (del || mem[k] === undefined) await pool.query('DELETE FROM tablo_kv WHERE k=$1', [k]);
        else await pool.query('INSERT INTO tablo_kv(k,v,updated) VALUES($1,$2,now()) ON CONFLICT (k) DO UPDATE SET v=EXCLUDED.v, updated=now()', [k, JSON.stringify(mem[k])]);
      } catch (e) { console.error('DB write failed', k, e.message); pending.set(k, del); }
    }
  };
  store.mark = (k, del) => { pending.set(k, !!del); if (!timer) timer = setTimeout(store.flush, 400); };
} else {
  const file = path.join(DATA_DIR, 'tablo.json');
  store.ready = (async () => {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    try { mem = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { mem = {}; }
  })();
  let timer = null;
  store.flush = async () => {
    timer = null;
    const tmp = file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(mem)); fs.renameSync(tmp, file);
  };
  store.mark = () => { if (!timer) timer = setTimeout(store.flush, 500); };
}
const get = (k, d) => (mem[k] === undefined ? d : mem[k]);
const set = (k, v) => { mem[k] = v; store.mark(k, false); };
const del = (k) => { delete mem[k]; store.mark(k, true); };

/* ===================== helpers ===================== */
const uid = (n = 8) => crypto.randomBytes(n).toString('base64url').replace(/[^a-zA-Z0-9]/g, '').slice(0, n + 2) || uid(n);
const sign = (s) => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
function makeToken() { const p = Date.now().toString(36) + '.' + uid(6); return p + '.' + sign(p); }
function checkToken(t) {
  if (!t) return false;
  const i = t.lastIndexOf('.'); if (i < 0) return false;
  const p = t.slice(0, i), s = t.slice(i + 1);
  const exp = sign(p);
  if (s.length !== exp.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(exp))) return false;
  const ts = parseInt(p.split('.')[0], 36);
  return Date.now() - ts < 1000 * 60 * 60 * 24 * 60; // 60 дней
}
function cookies(req) {
  const o = {}; (req.headers.cookie || '').split(';').forEach(c => { const i = c.indexOf('='); if (i > 0) o[c.slice(0, i).trim()] = decodeURIComponent(c.slice(i + 1).trim()); });
  return o;
}
const authed = (req) => checkToken(cookies(req).sid);
function send(res, code, body, type = 'application/json; charset=utf-8', extra = {}) {
  const data = typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body);
  res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store', ...extra });
  res.end(data);
}
const json = (res, body, code = 200) => send(res, code, body);
function readBody(req) {
  return new Promise((ok, no) => {
    let n = 0; const chunks = [];
    req.on('data', c => { n += c.length; if (n > MAX_BODY) { no(new Error('too big')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { ok(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); } catch (e) { no(e); } });
    req.on('error', no);
  });
}
function readRaw(req, max) {
  return new Promise((ok, no) => {
    let n = 0; const chunks = [];
    req.on('data', c => { n += c.length; if (n > max) { no(new Error('too big')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => ok(Buffer.concat(chunks)));
    req.on('error', no);
  });
}
const MIME = { '.webp': 'image/webp', '.jpg': 'image/jpeg', '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.woff2': 'font/woff2', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };
function serveFile(res, rel, cache) {
  const f = path.normalize(path.join(PUB, rel));
  if (!f.startsWith(PUB)) return send(res, 404, 'Not found', 'text/plain');
  fs.readFile(f, (e, d) => {
    if (e) return send(res, 404, 'Not found', 'text/plain');
    res.writeHead(200, { 'Content-Type': MIME[path.extname(f)] || 'application/octet-stream', 'Cache-Control': cache ? 'public, max-age=604800' : 'no-cache' });
    res.end(d);
  });
}
const clean = (s, n = 80) => String(s == null ? '' : s).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
function savePhoto(dataUrl) {
  const m = /^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/.exec(dataUrl || '');
  if (!m) return null;
  if (m[2].length > 6 * 1024 * 1024) return null;
  const id = uid(10); set('photo:' + id, { t: m[1], b: m[2] }); return id;
}

const INFO_KEYS = ['country', 'city', 'age', 'height', 'rank', 'club', 'cue'];
function setInfo(pl, b) { for (const k of INFO_KEYS) if (b[k] != null) pl[k] = clean(b[k], 60); }

function broadcastPoll(id) {
  const pl = get('poll:' + id, { open: false, votes: {} }), cnt = [0, 0];
  for (const v of Object.values(pl.votes)) cnt[v]++;
  const msg = JSON.stringify({ type: 'poll', open: pl.open, a: cnt[0], b: cnt[1], total: cnt[0] + cnt[1] });
  for (const c of clients) if (c.table === id && c.readyState === 1) c.send(msg);
}

/* login rate limit */
const tries = new Map();
function limited(ip, max = 10) {
  const now = Date.now(), t = (tries.get(ip) || []).filter(x => now - x < 10 * 60 * 1000);
  tries.set(ip, t); return t.length >= max;
}

/* ===================== tables & live state ===================== */
const tables = () => get('tables', []);
const tableById = (id) => tables().find(t => t.id === id);
const live = new Map(); // id -> {state, rev, el, at}
function liveOf(id) {
  if (!live.has(id)) { const s = get('state:' + id, null); live.set(id, s ? s : { state: null, rev: 0, el: 0, at: Date.now() }); }
  return live.get(id);
}
function elNow(L) { return L.state && L.state.clock && L.state.clock.running ? L.el + (Date.now() - L.at) : L.el; }
function snapshot(id) { const L = liveOf(id); return { type: 'state', rev: L.rev, state: L.state, el: elNow(L), age: Date.now() - L.at, serverTime: Date.now() }; }
function putState(id, state, el, from) {
  const L = liveOf(id);
  L.state = state; L.rev++; L.el = +el || 0; L.at = Date.now();
  set('state:' + id, L);
  const msg = JSON.stringify(snapshot(id));
  for (const c of clients) if (c.table === id && c !== from && c.readyState === 1) c.send(msg);
  return L.rev;
}

/* ===================== matches ===================== */
const STAT_KEYS = ['frames', 'balls', 'foreign', 'own', 'luck', 'best', 'attacks', 'safeties', 'safFail', 'fouls', 'time', 'shots', 'breaks', 'breaksOk', 'fpts'];
function matchFrom(tableId, st) {
  const t = tableById(tableId) || { name: '' };
  const players = (st.players || []).slice(0, 2).map(p => {
    const o = { name: clean(p.name), playerId: p.playerId || null, photoId: ((/\/photos\/([\w-]+)\.jpg/.exec(p.photo || '') || [])[1]) || null };
    STAT_KEYS.forEach(k => o[k] = +p[k] || 0); return o;
  });
  const race = +st.raceTo || 0;
  let winner = players.findIndex(p => race && p.frames >= race);
  if (winner < 0 && players.length === 2 && players[0].frames !== players[1].frames) winner = players[0].frames > players[1].frames ? 0 : 1;
  // счёт каждой партии / пирамиды: сыгранные + текущая (в длинной пирамиде)
  const long = st.game === 'long';
  const parts = (Array.isArray(st.frameLog) ? st.frameLog : []).slice(0, 300).map(f => ({ a: +f.a || 0, b: +f.b || 0, k: f.k === 'cut' ? 'cut' : (long ? 'full' : undefined) }));
  if (long && st.fs && Array.isArray(st.fs.sc) && players.length === 2) {
    const a = players[0].frames - (+st.fs.sc[0] || 0), b = players[1].frames - (+st.fs.sc[1] || 0);
    if (a || b) parts.push({ a, b, k: st.rk === 'cut' ? 'cut' : 'full' });
  }
  return { id: uid(8), at: Date.now(), tableId, tableName: t.name, title: clean(st.title, 120), subtitle: clean(st.subtitle, 120), raceTo: race, players, winner, game: long ? 'long' : 'classic', parts };
}
function csvEscape(v) { v = String(v == null ? '' : v); return /[",;\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }

/* ===================== tournament bracket ===================== */
const normName = (s) => String(s || '').toLowerCase().replace(/ё/g, 'е').replace(/\s+/g, ' ').trim();
const num = (v) => (v === '' || v == null || isNaN(+v) ? null : +v);
function cleanBracket(b) {
  const rounds = (Array.isArray(b && b.rounds) ? b.rounds : []).slice(0, 24).map(r => ({
    name: clean(r && r.name, 40),
    side: ['upper', 'lower'].includes(r && r.side) ? r.side : '',
    matches: (Array.isArray(r && r.matches) ? r.matches : []).slice(0, 256).map(m => ({
      no: num(m && m.no), a: clean(m && m.a, 60), b: clean(m && m.b, 60),
      ca: clean(m && m.ca, 3).toLowerCase(), cb: clean(m && m.cb, 3).toLowerCase(),
      sa: num(m && m.sa), sb: num(m && m.sb),
      ta: clean(m && m.ta, 4), tb: clean(m && m.tb, 4),           // «ТП» — техническое поражение
      xa: !!(m && m.xa), xb: !!(m && m.xb),
      seedA: num(m && m.seedA), seedB: num(m && m.seedB),                       // «X» — пустое место (проход без игры)
      wTo: num(m && m.wTo), lTo: num(m && m.lTo),                 // куда идут победитель и проигравший (номер матча)
      table: clean(m && m.table, 30), time: clean(m && m.time, 30)
    }))
  }));
  return { title: clean(b && b.title, 120), rounds, updated: Date.now() };
}
// индекс победителя: 0 — первый игрок, 1 — второй, null — ещё не определён
function mWinIdx(m) {
  if (m.xa && m.b && !m.xb) return 1;
  if (m.xb && m.a && !m.xa) return 0;
  if (!m.a || !m.b) return null;
  if (/тп/i.test(m.ta) && !/тп/i.test(m.tb)) return 1;
  if (/тп/i.test(m.tb) && !/тп/i.test(m.ta)) return 0;
  if (m.sa != null && m.sb != null && m.sa !== m.sb) return m.sa > m.sb ? 0 : 1;
  return null;
}
const mWinner = (m) => { const i = mWinIdx(m); return i == null ? null : (i ? m.b : m.a); };
function placeIn(t, name, pref) {
  if (!t || !name || t.a === name || t.b === name) return;
  const o = pref === 'b' ? 'a' : 'b';
  if (!t[pref] && !t['x' + pref]) t[pref] = name; else if (!t[o] && !t['x' + o]) t[o] = name;
}
// продвижение по сетке: явные переходы «победитель/проигравший на #N»,
// иначе в следующий раунд той же стороны: вдвое меньше матчей — матч k/2, столько же — матч k
function propagate(br) {
  const byNo = {}; br.rounds.forEach(r => r.matches.forEach(m => { if (m.no != null) byNo[m.no] = m; }));
  br.rounds.forEach((r, ri) => {
    let next = null; for (let j = ri + 1; j < br.rounds.length; j++) if (br.rounds[j].side === r.side) { next = br.rounds[j]; break; }
    r.matches.forEach((m, k) => {
      const wi = mWinIdx(m); if (wi == null) return;
      const w = wi ? m.b : m.a, l = wi ? m.a : m.b;
      if (m.wTo != null) placeIn(byNo[m.wTo], w, 'a');
      else if (next && next.matches.length * 2 === r.matches.length) placeIn(next.matches[k >> 1], w, k % 2 ? 'b' : 'a');
      else if (next && next.matches.length === r.matches.length) placeIn(next.matches[k], w, 'a');
      if (m.lTo != null && l) placeIn(byNo[m.lTo], l, 'a');
    });
  });
  return br;
}
function bracketResult(mt) {
  const br = get('bracket', null); if (!br || mt.players.length < 2) return;
  const [p, q] = mt.players.map(x => normName(x.name));
  for (const r of br.rounds) for (const m of r.matches) {
    if (m.sa != null || m.sb != null || m.ta || m.tb) continue;
    const a = normName(m.a), b = normName(m.b);
    if (a === p && b === q) { m.sa = mt.players[0].frames; m.sb = mt.players[1].frames; }
    else if (a === q && b === p) { m.sa = mt.players[1].frames; m.sb = mt.players[0].frames; }
    else continue;
    br.updated = Date.now(); set('bracket', propagate(br)); return;
  }
}

/* ===================== HTTP ===================== */
async function api(req, res, url) {
  const p = url.pathname, m = req.method;
  const need = () => { if (!authed(req)) { json(res, { error: 'auth' }, 401); return false; } return true; };

  if (p === '/api/login' && m === 'POST') {
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    if (limited(ip)) return json(res, { error: 'Слишком много попыток. Подождите 10 минут.' }, 429);
    const b = await readBody(req);
    const a = Buffer.from(String(b.password || '')), e = Buffer.from(PASSWORD);
    if (a.length !== e.length || !crypto.timingSafeEqual(a, e)) { tries.get(ip).push(Date.now()); return json(res, { error: 'Неверный пароль' }, 403); }
    const secure = (req.headers['x-forwarded-proto'] || '').includes('https') ? '; Secure' : '';
    return send(res, 200, { ok: true }, undefined, { 'Set-Cookie': `sid=${makeToken()}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60 * 60 * 24 * 60}${secure}` });
  }
  if (p === '/api/logout') return send(res, 200, { ok: true }, undefined, { 'Set-Cookie': 'sid=; Path=/; Max-Age=0' });
  if (p === '/api/me') return json(res, { auth: authed(req), storage: store.kind, defaultPassword: !process.env.ADMIN_PASSWORD });

  // public read of a table state (polling fallback for overlay)
  let mm;
  if ((mm = /^\/api\/state\/([\w-]+)$/.exec(p))) {
    const id = mm[1]; if (!tableById(id)) return json(res, { error: 'Стол не найден' }, 404);
    if (m === 'GET') return json(res, snapshot(id));
    if (m === 'POST') { if (!need()) return; const b = await readBody(req); return json(res, { rev: putState(id, b.state, b.el, null) }); }
  }
  if ((mm = /^\/api\/table\/([\w-]+)$/.exec(p)) && m === 'GET') {
    const t = tableById(mm[1]); return t ? json(res, t) : json(res, { error: 'Стол не найден' }, 404);
  }

  if (p === '/api/bracket' && m === 'GET') return json(res, get('bracket', null));

  // опрос зрителей «Кто победит?»: голосовать может кто угодно по ссылке/QR, один голос с устройства
  if ((mm = /^\/api\/poll\/([\w-]+)$/.exec(p))) {
    const id = mm[1]; if (!tableById(id)) return json(res, { error: 'Стол не найден' }, 404);
    const pl = get('poll:' + id, { open: false, votes: {} }), cnt = [0, 0];
    for (const v of Object.values(pl.votes)) cnt[v]++;
    const out = (extra) => json(res, Object.assign({ open: pl.open, a: cnt[0], b: cnt[1], total: cnt[0] + cnt[1] }, extra || {}));
    if (m === 'GET') return out({ mine: pl.votes[cookies(req).vid] ?? null });
    if (m === 'POST') {
      const b = await readBody(req);
      if (b.action) { // управление — только оператор
        if (!authed(req)) return json(res, { error: 'auth' }, 401);
        if (b.action === 'open') pl.open = true; else if (b.action === 'close') pl.open = false; else if (b.action === 'reset') pl.votes = {};
        set('poll:' + id, pl); broadcastPoll(id); return json(res, { ok: true });
      }
      if (!pl.open) return json(res, { error: 'Голосование закрыто' }, 400);
      const v = +b.v; if (v !== 0 && v !== 1) return json(res, { error: 'bad vote' }, 400);
      let vid = cookies(req).vid; const head = {};
      if (!vid || !/^[\w-]{6,30}$/.test(vid)) { vid = uid(12); head['Set-Cookie'] = `vid=${vid}; Path=/; Max-Age=${60 * 60 * 24 * 365}; SameSite=Lax`; }
      const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
      if (limited('poll:' + ip, 300)) return json(res, { error: 'Слишком часто' }, 429);
      (tries.get('poll:' + ip) || tries.set('poll:' + ip, []).get('poll:' + ip)).push(Date.now());
      pl.votes[vid] = v; set('poll:' + id, pl); broadcastPoll(id);
      cnt[0] = cnt[1] = 0; for (const x of Object.values(pl.votes)) cnt[x]++;
      return send(res, 200, { open: pl.open, a: cnt[0], b: cnt[1], total: cnt[0] + cnt[1], mine: v }, undefined, head);
    }
  }

  if (!need()) return;

  // шаблоны турниров: набор настроек, который можно применить к одному или ко всем столам
  if (p === '/api/templates' && m === 'GET') return json(res, get('templates', []));
  if (p === '/api/templates' && m === 'POST') {
    const b = await readBody(req); const list = get('templates', []);
    const t = { id: uid(6), name: clean(b.name, 60) || 'Шаблон', at: Date.now(), data: b.data && typeof b.data === 'object' ? b.data : {} };
    list.push(t); set('templates', list); return json(res, t);
  }
  if ((mm = /^\/api\/templates\/([\w-]+)$/.exec(p)) && m === 'DELETE') { set('templates', get('templates', []).filter(t => t.id !== mm[1])); return json(res, { ok: true }); }
  if ((mm = /^\/api\/templates\/([\w-]+)\/apply$/.exec(p)) && m === 'POST') {
    const t = get('templates', []).find(x => x.id === mm[1]); if (!t) return json(res, { error: 'Шаблон не найден' }, 404);
    const b = await readBody(req), ids = b.table === 'all' ? tables().map(x => x.id) : [b.table].filter(x => tableById(x));
    const busy = [];
    for (const id of ids) {
      const L = liveOf(id), st = Object.assign({}, L.state || {}), d = t.data, playing = Array.isArray(st.log) && st.log.length > 0;
      for (const k of ['title', 'subtitle', 'raceTo', 'ballsTo', 'foulBall', 'pairs', 'shot', 'pdur', 'firstKind']) if (d[k] !== undefined) st[k] = d[k];
      if (d.game !== undefined) { if (!playing || st.game === d.game) st.game = d.game; else busy.push(tableById(id).name); }
      if (d.cfg) st.cfg = Object.assign({}, st.cfg || {}, d.cfg);
      st.updatedAt = Date.now();
      putState(id, st, elNow(L), null);
    }
    return json(res, { ok: true, applied: ids.length, busy });
  }
  if (p === '/api/bracket' && m === 'PUT') { const b = await readBody(req); const br = propagate(cleanBracket(b)); set('bracket', br); return json(res, br); }
  if (p === '/api/bracket' && m === 'DELETE') { del('bracket'); return json(res, { ok: true }); }
  if (p === '/api/media' && m === 'POST') {
    const type = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    if (!/^(image\/(jpeg|png|webp|gif)|video\/(mp4|webm))$/.test(type)) return json(res, { error: 'Нужна картинка (JPG, PNG, WebP, GIF) или видео (MP4, WebM)' }, 400);
    let buf; try { buf = await readRaw(req, MAX_MEDIA); } catch (e) { return json(res, { error: 'Файл больше 40 МБ' }, 413); }
    if (!buf.length) return json(res, { error: 'Пустой файл' }, 400);
    const id = uid(10); set('media:' + id, { m: type, b: buf.toString('base64') });
    return json(res, { id, url: '/media/' + id, kind: type.startsWith('video') ? 'video' : 'image' });
  }

  // tables
  if (p === '/api/tables' && m === 'GET') {
    return json(res, tables().map(t => { const L = liveOf(t.id), s = L.state; return { ...t, live: s ? { title: s.title, players: (s.players || []).map(x => ({ name: x.name, frames: x.frames, balls: x.balls })), mode: s.mode } : null }; }));
  }
  if (p === '/api/tables' && m === 'POST') {
    const b = await readBody(req); const list = tables();
    const t = { id: uid(6).toLowerCase(), name: clean(b.name) || ('Стол ' + (list.length + 1)), createdAt: Date.now() };
    list.push(t); set('tables', list); return json(res, t);
  }
  if ((mm = /^\/api\/tables\/([\w-]+)$/.exec(p))) {
    const list = tables(), i = list.findIndex(t => t.id === mm[1]);
    if (i < 0) return json(res, { error: 'Стол не найден' }, 404);
    if (m === 'PATCH') { const b = await readBody(req); list[i].name = clean(b.name) || list[i].name; set('tables', list); return json(res, list[i]); }
    if (m === 'DELETE') { list.splice(i, 1); set('tables', list); del('state:' + mm[1]); live.delete(mm[1]); return json(res, { ok: true }); }
  }

  // players
  if (p === '/api/players' && m === 'GET') return json(res, get('players', []));
  if (p === '/api/players' && m === 'POST') {
    const b = await readBody(req); const list = get('players', []);
    const pl = { id: uid(6), name: clean(b.name) || 'Игрок', photoId: b.photo ? savePhoto(b.photo) : null, bodyId: b.body ? savePhoto(b.body) : null, note: clean(b.note, 120) };
    setInfo(pl, b);
    list.push(pl); list.sort((a, b2) => a.name.localeCompare(b2.name, 'ru')); set('players', list); return json(res, pl);
  }
  if ((mm = /^\/api\/players\/([\w-]+)$/.exec(p))) {
    const list = get('players', []), i = list.findIndex(x => x.id === mm[1]);
    if (i < 0) return json(res, { error: 'Игрок не найден' }, 404);
    if (m === 'PATCH') {
      const b = await readBody(req);
      if (b.name != null) list[i].name = clean(b.name) || list[i].name;
      if (b.note != null) list[i].note = clean(b.note, 120);
      if (b.photo) { const old = list[i].photoId; const id = savePhoto(b.photo); if (id) { list[i].photoId = id; if (old) del('photo:' + old); } }
      if (b.photo === '') list[i].photoId = null;
      // фото, уже загруженное на пульте, — привязать к профилю без повторной загрузки
      if (b.photoRef && get('photo:' + b.photoRef)) list[i].photoId = String(b.photoRef);
      if (b.bodyRef && get('photo:' + b.bodyRef)) list[i].bodyId = String(b.bodyRef);
      if (b.body) { const old = list[i].bodyId; const id = savePhoto(b.body); if (id) { list[i].bodyId = id; if (old) del('photo:' + old); } }
      if (b.body === '') list[i].bodyId = null;
      setInfo(list[i], b);
      list.sort((a, b2) => a.name.localeCompare(b2.name, 'ru')); set('players', list); return json(res, list.find(x => x.id === mm[1]));
    }
    if (m === 'DELETE') { list.splice(i, 1); set('players', list); return json(res, { ok: true }); }
  }
  if (p === '/api/photo' && m === 'POST') {
    const b = await readBody(req); const id = savePhoto(b.photo);
    return id ? json(res, { id }) : json(res, { error: 'Неверное изображение' }, 400);
  }

  // matches
  if (p === '/api/matches' && m === 'GET') return json(res, get('matches', []));
  if (p === '/api/matches' && m === 'POST') {
    const b = await readBody(req);
    const st = b.state || liveOf(b.table).state; if (!st) return json(res, { error: 'Нет данных матча' }, 400);
    const mt = matchFrom(b.table, st); const list = get('matches', []); list.unshift(mt);
    try { bracketResult(mt); } catch (e) { console.error('bracket', e.message); }
    if (list.length > 10000) list.length = 10000;
    set('matches', list); return json(res, mt);
  }
  if ((mm = /^\/api\/matches\/([\w-]+)$/.exec(p)) && m === 'DELETE') {
    const list = get('matches', []).filter(x => x.id !== mm[1]); set('matches', list); return json(res, { ok: true });
  }
  if (p === '/api/matches.csv') {
    const rows = [['Дата', 'Стол', 'Турнир', 'Стадия', 'Игрок 1', 'Партии 1', 'Игрок 2', 'Партии 2', 'Победитель',
      'Забито 1', 'Чужих 1', 'Своих 1', 'Случайных 1', 'Серия 1', 'Атаки 1', 'Отыгрыши 1', 'Фолы 1', 'Разбой 1',
      'Забито 2', 'Чужих 2', 'Своих 2', 'Случайных 2', 'Серия 2', 'Атаки 2', 'Отыгрыши 2', 'Фолы 2', 'Разбой 2']];
    for (const x of get('matches', [])) {
      const [a, b] = x.players; const d = new Date(x.at);
      const st = q => [q.foreign + q.own + (q.luck || 0), q.foreign, q.own, q.luck || 0, q.best, q.attacks, q.safeties, q.fouls, (q.breaksOk || 0) + '/' + (q.breaks || 0)];
      rows.push([d.toLocaleString('ru-RU', { timeZone: 'Europe/Moscow' }), x.tableName, x.title, x.subtitle, a.name, a.frames, b.name, b.frames, x.winner >= 0 ? x.players[x.winner].name : '', ...st(a), ...st(b)]);
    }
    const csv = '﻿' + rows.map(r => r.map(csvEscape).join(';')).join('\r\n');
    return send(res, 200, csv, 'text/csv; charset=utf-8', { 'Content-Disposition': 'attachment; filename="matches.csv"' });
  }

  // backup / restore
  if (p === '/api/backup' && m === 'GET') {
    return send(res, 200, JSON.stringify({ app: 'piramida-tablo', at: Date.now(), data: mem }), 'application/json; charset=utf-8',
      { 'Content-Disposition': `attachment; filename="tablo-backup-${new Date().toISOString().slice(0, 10)}.json"` });
  }
  if (p === '/api/restore' && m === 'POST') {
    const b = await readBody(req);
    if (!b || b.app !== 'piramida-tablo' || typeof b.data !== 'object') return json(res, { error: 'Это не файл резервной копии табло' }, 400);
    for (const k of Object.keys(mem)) if (!(k in b.data)) del(k);
    for (const [k, v] of Object.entries(b.data)) set(k, v);
    live.clear(); return json(res, { ok: true });
  }
  json(res, { error: 'not found' }, 404);
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    const p = url.pathname;
    if (p === '/health') return send(res, 200, 'ok', 'text/plain');
    if (p.startsWith('/api/')) return await api(req, res, url);
    let mm;
    if ((mm = /^\/photos\/([\w-]+)\.jpg$/.exec(p))) {
      const ph = get('photo:' + mm[1]); if (!ph) return send(res, 404, 'Not found', 'text/plain');
      const dn = clean(url.searchParams.get('dl'), 100).replace(/[\\/:*?"<>|]/g, ''); // ?dl=Имя — скачать файлом с понятным именем
      const disp = dn ? { 'Content-Disposition': `attachment; filename="photo.${ph.t === 'jpeg' ? 'jpg' : ph.t}"; filename*=UTF-8''${encodeURIComponent(dn + '.' + (ph.t === 'jpeg' ? 'jpg' : ph.t))}` } : {};
      res.writeHead(200, { 'Content-Type': 'image/' + ph.t, 'Cache-Control': 'public, max-age=31536000, immutable', ...disp });
      return res.end(Buffer.from(ph.b, 'base64'));
    }
    if ((mm = /^\/media\/([\w-]+)$/.exec(p))) {
      const md = get('media:' + mm[1]); if (!md) return send(res, 404, 'Not found', 'text/plain');
      const buf = md._buf || (md._buf = Buffer.from(md.b, 'base64'));
      Object.defineProperty(md, '_buf', { value: buf, enumerable: false, configurable: true, writable: true });
      const head = { 'Content-Type': md.m, 'Accept-Ranges': 'bytes', 'Cache-Control': 'public, max-age=31536000, immutable' };
      const r = /bytes=(\d*)-(\d*)/.exec(req.headers.range || '');
      if (r) {
        let a = r[1] === '' ? buf.length - +r[2] : +r[1], e = r[1] !== '' && r[2] !== '' ? +r[2] : buf.length - 1;
        a = Math.max(0, a); e = Math.min(buf.length - 1, e);
        if (a > e) { res.writeHead(416, { 'Content-Range': `bytes */${buf.length}` }); return res.end(); }
        res.writeHead(206, { ...head, 'Content-Range': `bytes ${a}-${e}/${buf.length}`, 'Content-Length': e - a + 1 });
        return res.end(buf.subarray(a, e + 1));
      }
      res.writeHead(200, { ...head, 'Content-Length': buf.length }); return res.end(buf);
    }
    if (p.startsWith('/fonts/') || p.startsWith('/js/')) return serveFile(res, p, true);
    if (p === '/login') return serveFile(res, 'login.html');
    if ((mm = /^\/o\/([\w-]+)$/.exec(p))) return serveFile(res, 'control.html');
    if ((mm = /^\/k\/([\w-]+)$/.exec(p))) return serveFile(res, 'control.html'); // экран комментатора (только просмотр)
    if ((mm = /^\/v\/([\w-]+)$/.exec(p))) return serveFile(res, 'vote.html');    // голосование зрителей с телефона
    if ((mm = /^\/t\/([\w-]+)$/.exec(p))) {
      if (!authed(req)) return send(res, 302, '', 'text/plain', { Location: '/login?next=' + encodeURIComponent(p) });
      return serveFile(res, 'control.html');
    }
    if (p === '/') {
      if (!authed(req)) return send(res, 302, '', 'text/plain', { Location: '/login' });
      return serveFile(res, 'dashboard.html');
    }
    send(res, 404, 'Not found', 'text/plain');
  } catch (e) {
    console.error(e);
    if (!res.headersSent) json(res, { error: 'Ошибка сервера' }, 500);
  }
});

/* ===================== WebSocket ===================== */
const clients = new Set();
const wss = new WebSocketServer({ noServer: true, maxPayload: 2 * 1024 * 1024 });
server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname !== '/ws') return socket.destroy();
  const id = url.searchParams.get('table') || '';
  if (!tableById(id)) return socket.destroy();
  wss.handleUpgrade(req, socket, head, ws => {
    ws.table = id; ws.canWrite = authed(req); ws.alive = true;
    ws.role = ['o', 'side', 'k', 't', 'v'].includes(url.searchParams.get('role')) ? url.searchParams.get('role') : 'o';
    clients.add(ws);
    ws.send(JSON.stringify(snapshot(id)));
    presence(id);
    ws.on('pong', () => ws.alive = true);
    ws.on('message', raw => {
      let m; try { m = JSON.parse(raw); } catch (e) { return; }
      if (m.type === 'ping') return ws.send('{"type":"pong"}');
      if (m.type === 'state' && ws.canWrite && m.state) {
        const rev = putState(id, m.state, m.el, ws);
        ws.send(JSON.stringify({ type: 'ack', rev }));
      }
    });
    ws.on('close', () => { clients.delete(ws); presence(id); });
    ws.on('error', () => { clients.delete(ws); presence(id); });
  });
});
// сколько экранов этого стола сейчас подключено: табло в OBS, мини-счёт, комментатор, пульты
function presence(id) {
  const n = { o: 0, side: 0, k: 0, t: 0, v: 0 };
  for (const c of clients) if (c.table === id && c.readyState === 1) n[c.role]++;
  const msg = JSON.stringify({ type: 'presence', n });
  for (const c of clients) if (c.table === id && c.role === 't' && c.readyState === 1) c.send(msg);
}
setInterval(() => { for (const c of clients) { if (!c.alive) { c.terminate(); clients.delete(c); presence(c.table); continue; } c.alive = false; try { c.ping(); } catch (e) {} } }, 25000);

store.ready.then(() => {
  if (!get('tables', []).length) set('tables', [{ id: 'stol1', name: 'Стол 1', createdAt: Date.now() }]);
  server.listen(PORT, '0.0.0.0', () => console.log(`Табло запущено на порту ${PORT}, хранилище: ${store.kind}${process.env.ADMIN_PASSWORD ? '' : ' (ВНИМАНИЕ: пароль по умолчанию «admin» — задайте ADMIN_PASSWORD)'}`));
}).catch(e => { console.error('Не удалось подключиться к хранилищу:', e); process.exit(1); });

const bye = async () => { try { await store.flush(); } catch (e) {} process.exit(0); };
process.on('SIGTERM', bye); process.on('SIGINT', bye);
