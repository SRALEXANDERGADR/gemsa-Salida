// src/index.js
// Worker único de "Control de Salidas" (GEMSA).
// Sirve los archivos estáticos de /public y expone la API bajo /api/*.
// Usa un repo de GitHub como "base de datos" (dos archivos JSON: usuarios y
// registros), leyendo/escribiendo vía la API de contenidos de GitHub con
// reintento ante conflicto de escritura (409/422).
//
// Variables/secretos a configurar en Cloudflare → Settings → Variables and secrets:
//   GITHUB_TOKEN    (secreto)  Personal Access Token con permiso sobre el repo (contents: read/write)
//   GITHUB_REPO     (variable) ej. "SRALEXANDERGADR/gemsa-Salida"
//   SESSION_SECRET  (secreto)  cualquier cadena larga y aleatoria, para firmar las sesiones
// Opcionales:
//   GITHUB_BRANCH        (default "main")
//   ENTRIES_FILE_PATH    (default "data/entries.json")
//   USERS_FILE_PATH      (default "data/users.json")
//
// NOTA sobre ACCESS_CODE: la clave compartida de la versión anterior queda
// reemplazada por cuentas individuales (usuario + clave por persona). Si el
// secreto ACCESS_CODE sigue configurado en Cloudflare no pasa nada, ya no se
// usa en este archivo.

const GITHUB_API = 'https://api.github.com';
const RETENTION_MS = 30 * 24 * 60 * 60 * 1000; // 30 días
const SESSION_MS = 30 * 24 * 60 * 60 * 1000; // sesión válida 30 días

// ---------- utilidades genéricas ----------

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' }
  });
}

function errorResponse(message, status = 400) {
  return json({ error: message }, status);
}

function b64EncodeUtf8(str) {
  const bytes = new TextEncoder().encode(str);
  let binary = '';
  bytes.forEach(b => (binary += String.fromCharCode(b)));
  return btoa(binary);
}

function b64DecodeUtf8(b64) {
  const binary = atob(b64.replace(/\n/g, ''));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

function b64urlEncode(bytesOrStr) {
  const str = typeof bytesOrStr === 'string' ? bytesOrStr : String.fromCharCode(...new Uint8Array(bytesOrStr));
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecodeToString(b64url) {
  let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  return atob(b64);
}

function toHex(buffer) {
  return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function randomHex(byteLength) {
  const arr = new Uint8Array(byteLength);
  crypto.getRandomValues(arr);
  return toHex(arr.buffer);
}

// ---------- contraseñas (hash + salt con SHA-256 vía Web Crypto) ----------
// Nota: al no tener una base de datos real ni poder instalar librerías como
// bcrypt, se usa SHA-256 con salt aleatorio por usuario. Es razonable para
// una herramienta interna de equipo; no es de nivel bancario.

async function hashPassword(password, saltHex) {
  const salt = saltHex || randomHex(16);
  const data = new TextEncoder().encode(salt + ':' + password);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return { salt, hash: toHex(digest) };
}

async function verifyPassword(password, salt, expectedHash) {
  const { hash } = await hashPassword(password, salt);
  return hash === expectedHash;
}

// ---------- sesiones firmadas (HMAC-SHA256), sin cookies: se guardan en el
// localStorage del navegador y se envían como "Authorization: Bearer <token>" ----------

async function getHmacKey(env) {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(env.SESSION_SECRET || 'clave-de-desarrollo-cambiar'),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

async function createToken(env, payload) {
  const key = await getHmacKey(env);
  const body = JSON.stringify(payload);
  const bodyB64 = b64urlEncode(body);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(bodyB64));
  const sigB64 = b64urlEncode(sig);
  return `${bodyB64}.${sigB64}`;
}

async function verifyToken(env, token) {
  if (!token || token.indexOf('.') === -1) return null;
  const [bodyB64, sigB64] = token.split('.');
  const key = await getHmacKey(env);
  const expectedSig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(bodyB64));
  const expectedSigB64 = b64urlEncode(expectedSig);
  if (expectedSigB64 !== sigB64) return null;
  let payload;
  try { payload = JSON.parse(b64urlDecodeToString(bodyB64)); } catch (e) { return null; }
  if (!payload.exp || payload.exp < Date.now()) return null;
  return payload;
}

async function getAuthUser(request, env) {
  const auth = request.headers.get('authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return null;
  const payload = await verifyToken(env, token);
  if (!payload) return null;
  return payload; // { uid, role, name, exp }
}

function requireAuth(user) {
  return !!user;
}

function requireSupervisor(user) {
  return !!user && user.role === 'supervisor';
}

// ---------- GitHub como "base de datos": leer/escribir un JSON con reintento ----------

async function githubGetFile(env, path) {
  const branch = env.GITHUB_BRANCH || 'main';
  const url = `${GITHUB_API}/repos/${env.GITHUB_REPO}/contents/${path}?ref=${branch}`;
  const res = await fetch(url, {
    headers: {
      Authorization: `token ${env.GITHUB_TOKEN}`,
      'User-Agent': 'control-salidas-worker',
      Accept: 'application/vnd.github+json'
    }
  });
  if (res.status === 404) return { sha: null, data: [] };
  if (!res.ok) throw new Error(`GitHub GET (${path}) falló: ${res.status}`);
  const body = await res.json();
  let data = [];
  try { data = JSON.parse(b64DecodeUtf8(body.content)); } catch (e) { data = []; }
  return { sha: body.sha, data };
}

async function githubPutFile(env, path, data, sha, message) {
  const branch = env.GITHUB_BRANCH || 'main';
  const url = `${GITHUB_API}/repos/${env.GITHUB_REPO}/contents/${path}`;
  const body = {
    message,
    content: b64EncodeUtf8(JSON.stringify(data, null, 2)),
    branch
  };
  if (sha) body.sha = sha;
  const res = await fetch(url, {
    method: 'PUT',
    headers: {
      Authorization: `token ${env.GITHUB_TOKEN}`,
      'User-Agent': 'control-salidas-worker',
      Accept: 'application/vnd.github+json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });
  if (!res.ok) {
    const errText = await res.text();
    const err = new Error(`GitHub PUT (${path}) falló: ${res.status} ${errText}`);
    err.status = res.status;
    throw err;
  }
}

// mutateFn recibe el array actual y devuelve { data, value } (nuevo array + lo
// que se quiere retornar) o { noop: true, value } si no hay que escribir nada.
async function withRetry(env, path, mutateFn, message, maxAttempts = 3) {
  let attempt = 0;
  while (attempt < maxAttempts) {
    attempt++;
    const { sha, data } = await githubGetFile(env, path);
    const result = mutateFn(data);
    if (result.noop) return result.value;
    try {
      await githubPutFile(env, path, result.data, sha, message);
      return result.value;
    } catch (e) {
      if (e.status === 409 || e.status === 422) continue; // conflicto: reintenta
      throw e;
    }
  }
  throw new Error('No se pudo guardar tras varios intentos (conflicto de escritura).');
}

function entriesPath(env) { return env.ENTRIES_FILE_PATH || 'data/entries.json'; }
function usersPath(env) { return env.USERS_FILE_PATH || 'data/users.json'; }

// ---------- limpieza / retención ----------
// Registros activos: se purgan definitivamente 30 días después de su última
// actividad (creación o edición), individualmente (no hay borrado masivo).
// Registros en papelera: se purgan definitivamente 30 días después de
// haberse borrado (deletedAt).
function cleanEntries(entries) {
  const now = Date.now();
  return entries.filter(e => {
    const lastActivity = Math.max(e.updatedAt || 0, e.createdAt || 0);
    if (e.deletedAt) return now - e.deletedAt < RETENTION_MS;
    return now - lastActivity < RETENTION_MS;
  });
}

// ---------- handlers: setup / login / sesión ----------

async function handleStatus(request, env) {
  const { data: users } = await githubGetFile(env, usersPath(env));
  return json({ needsSetup: users.length === 0 });
}

async function handleSetup(request, env) {
  let body;
  try { body = await request.json(); } catch (e) { return errorResponse('JSON inválido'); }
  const username = (body.username || '').trim().toLowerCase();
  const name = (body.name || '').trim();
  const password = body.password || '';
  if (!username || !name || password.length < 4) {
    return errorResponse('Faltan datos o la clave es muy corta (mínimo 4 caracteres)');
  }
  try {
    const { salt, hash } = await hashPassword(password);
    const value = await withRetry(env, usersPath(env), users => {
      if (users.length > 0) return { noop: true, value: { alreadySetup: true } };
      const user = {
        id: crypto.randomUUID(), username, name, role: 'supervisor',
        passwordHash: hash, passwordSalt: salt, createdAt: Date.now(), createdBy: null
      };
      return { data: [user], value: { alreadySetup: false, user } };
    }, `Configuración inicial: crear supervisor ${username}`);
    if (value.alreadySetup) return errorResponse('El sistema ya fue configurado', 409);

    const user = value.user;
    const token = await createToken(env, { uid: user.id, role: user.role, name: user.name, exp: Date.now() + SESSION_MS });
    return json({ token, user: { id: user.id, username: user.username, name: user.name, role: user.role } });
  } catch (e) { return errorResponse(e.message, 500); }
}

async function handleLogin(request, env) {
  let body;
  try { body = await request.json(); } catch (e) { return errorResponse('JSON inválido'); }
  const username = (body.username || '').trim().toLowerCase();
  const password = body.password || '';
  if (!username || !password) return errorResponse('Falta usuario o clave');
  try {
    const { data: users } = await githubGetFile(env, usersPath(env));
    const user = users.find(u => u.username === username);
    if (!user) return errorResponse('Usuario o clave incorrectos', 401);
    const ok = await verifyPassword(password, user.passwordSalt, user.passwordHash);
    if (!ok) return errorResponse('Usuario o clave incorrectos', 401);
    const token = await createToken(env, { uid: user.id, role: user.role, name: user.name, exp: Date.now() + SESSION_MS });
    return json({ token, user: { id: user.id, username: user.username, name: user.name, role: user.role } });
  } catch (e) { return errorResponse(e.message, 500); }
}

async function handleMe(request, env, user) {
  if (!requireAuth(user)) return errorResponse('No autorizado', 401);
  return json({ user: { id: user.uid, name: user.name, role: user.role } });
}

// ---------- handlers: usuarios (solo supervisor) ----------

async function handleUsersGet(request, env, user) {
  if (!requireSupervisor(user)) return errorResponse('Solo un supervisor puede ver el personal', 403);
  const { data: users } = await githubGetFile(env, usersPath(env));
  const safe = users.map(u => ({ id: u.id, username: u.username, name: u.name, role: u.role, createdAt: u.createdAt }));
  return json({ users: safe });
}

async function handleUsersPost(request, env, user) {
  if (!requireSupervisor(user)) return errorResponse('Solo un supervisor puede crear personal', 403);
  let body;
  try { body = await request.json(); } catch (e) { return errorResponse('JSON inválido'); }
  const username = (body.username || '').trim().toLowerCase();
  const name = (body.name || '').trim();
  const password = body.password || '';
  const role = body.role === 'supervisor' ? 'supervisor' : 'worker';
  if (!username || !name || password.length < 4) {
    return errorResponse('Faltan datos o la clave es muy corta (mínimo 4 caracteres)');
  }
  try {
    const { salt, hash } = await hashPassword(password);
    const newUser = {
      id: crypto.randomUUID(), username, name, role,
      passwordHash: hash, passwordSalt: salt, createdAt: Date.now(), createdBy: user.uid
    };
    const value = await withRetry(env, usersPath(env), users => {
      if (users.some(u => u.username === username)) return { noop: true, value: { duplicate: true } };
      users.push(newUser);
      return { data: users, value: { duplicate: false } };
    }, `Crear cuenta: ${username} (${role})`);
    if (value.duplicate) return errorResponse('Ese nombre de usuario ya existe', 409);
    return json({ user: { id: newUser.id, username: newUser.username, name: newUser.name, role: newUser.role, createdAt: newUser.createdAt } });
  } catch (e) { return errorResponse(e.message, 500); }
}

async function handleUsersDelete(request, env, user) {
  if (!requireSupervisor(user)) return errorResponse('Solo un supervisor puede eliminar personal', 403);
  const url = new URL(request.url);
  const id = url.searchParams.get('id');
  if (!id) return errorResponse('Falta id');
  try {
    const value = await withRetry(env, usersPath(env), users => {
      const target = users.find(u => u.id === id);
      if (!target) return { noop: true, value: { error: 'No encontrado' } };
      const supervisores = users.filter(u => u.role === 'supervisor');
      if (target.role === 'supervisor' && supervisores.length <= 1) {
        return { noop: true, value: { error: 'No se puede eliminar al único supervisor' } };
      }
      return { data: users.filter(u => u.id !== id), value: { ok: true } };
    }, `Eliminar cuenta: ${id}`);
    if (value.error) return errorResponse(value.error, 400);
    return json({ ok: true });
  } catch (e) { return errorResponse(e.message, 500); }
}

// ---------- handlers: registros (entries) ----------

function serializeEntry(e) {
  return e; // ya son planos; se filtran campos internos si algún día hace falta
}

async function handleEntriesGet(request, env, user) {
  if (!requireAuth(user)) return errorResponse('No autorizado', 401);
  try {
    const value = await withRetry(env, entriesPath(env), entries => {
      const cleaned = cleanEntries(entries);
      const active = cleaned.filter(e => !e.deletedAt);
      const visible = user.role === 'supervisor' ? active : active.filter(e => e.workerId === user.uid);
      if (cleaned.length === entries.length) return { noop: true, value: visible.map(serializeEntry) };
      return { data: cleaned, value: visible.map(serializeEntry) };
    }, 'Limpieza automática: registros con más de 30 días');
    return json({ entries: value });
  } catch (e) { return errorResponse(e.message, 500); }
}

async function handleEntriesPost(request, env, user) {
  if (!requireAuth(user)) return errorResponse('No autorizado', 401);
  let body;
  try { body = await request.json(); } catch (e) { return errorResponse('JSON inválido'); }
  const code = (body.code || '').trim().toUpperCase();
  const name = (body.name || '').trim() || user.name;
  const time = (body.time || '').trim();
  const obs = (body.obs || '').trim();
  if (!code || !name || !time) return errorResponse('Falta código, nombre u hora');
  const now = Date.now();
  const entry = {
    id: crypto.randomUUID(), code, name, time, obs,
    status: 'fuera', returnTime: null,
    createdAt: now, updatedAt: now, deletedAt: null,
    workerId: user.uid, workerName: user.name,
    history: [{ at: now, by: user.uid, byName: user.name, field: 'salida', from: null, to: time }]
  };
  try {
    await withRetry(env, entriesPath(env), entries => {
      const cleaned = cleanEntries(entries);
      cleaned.push(entry);
      return { data: cleaned, value: entry };
    }, `Registrar salida: ${code} - ${name}`);
    return json({ entry });
  } catch (e) { return errorResponse(e.message, 500); }
}

async function handleEntriesPut(request, env, user) {
  if (!requireAuth(user)) return errorResponse('No autorizado', 401);
  let body;
  try { body = await request.json(); } catch (e) { return errorResponse('JSON inválido'); }
  const { id } = body;
  if (!id) return errorResponse('Falta id');
  try {
    const value = await withRetry(env, entriesPath(env), entries => {
      const idx = entries.findIndex(e => e.id === id);
      if (idx === -1) return { noop: true, value: { error: 'No encontrado' } };
      const entry = entries[idx];
      if (user.role !== 'supervisor' && entry.workerId !== user.uid) {
        return { noop: true, value: { error: 'No puedes editar un registro de otra persona' } };
      }
      const now = Date.now();
      const fieldsMap = [
        ['time', 'salida'], ['returnTime', 'regreso'], ['status', 'estado'],
        ['obs', 'observación'], ['code', 'código'], ['name', 'nombre']
      ];
      let changed = false;
      for (const [field, label] of fieldsMap) {
        if (body[field] !== undefined && body[field] !== entry[field]) {
          entry.history = entry.history || [];
          entry.history.push({ at: now, by: user.uid, byName: user.name, field: label, from: entry[field] ?? null, to: body[field] });
          entry[field] = body[field];
          changed = true;
        }
      }
      if (!changed) return { noop: true, value: { entry } };
      entry.updatedAt = now;
      entries[idx] = entry;
      return { data: entries, value: { entry } };
    }, body.status === 'regreso' ? `Marcar regreso: ${id}` : `Editar registro: ${id}`);
    if (value.error) return errorResponse(value.error, value.error.includes('otra persona') ? 403 : 404);
    return json({ entry: value.entry });
  } catch (e) { return errorResponse(e.message, 500); }
}

async function handleEntriesDelete(request, env, user) {
  if (!requireAuth(user)) return errorResponse('No autorizado', 401);
  const url = new URL(request.url);
  const id = url.searchParams.get('id');
  if (!id) return errorResponse('Falta id');
  try {
    const value = await withRetry(env, entriesPath(env), entries => {
      const idx = entries.findIndex(e => e.id === id);
      if (idx === -1) return { noop: true, value: { error: 'No encontrado' } };
      const entry = entries[idx];
      if (user.role !== 'supervisor' && entry.workerId !== user.uid) {
        return { noop: true, value: { error: 'No puedes eliminar un registro de otra persona' } };
      }
      entry.deletedAt = Date.now();
      entry.updatedAt = entry.deletedAt;
      entries[idx] = entry;
      return { data: entries, value: { ok: true } };
    }, `Enviar a papelera: ${id}`);
    if (value.error) return errorResponse(value.error, value.error.includes('otra persona') ? 403 : 404);
    return json({ ok: true });
  } catch (e) { return errorResponse(e.message, 500); }
}

// ---------- handlers: papelera (solo supervisor) ----------

async function handleTrashGet(request, env, user) {
  if (!requireSupervisor(user)) return errorResponse('Solo un supervisor puede ver la papelera', 403);
  try {
    const value = await withRetry(env, entriesPath(env), entries => {
      const cleaned = cleanEntries(entries);
      const trashed = cleaned.filter(e => e.deletedAt);
      if (cleaned.length === entries.length) return { noop: true, value: trashed };
      return { data: cleaned, value: trashed };
    }, 'Limpieza automática de la papelera');
    return json({ entries: value });
  } catch (e) { return errorResponse(e.message, 500); }
}

async function handleTrashRestore(request, env, user) {
  if (!requireSupervisor(user)) return errorResponse('Solo un supervisor puede restaurar', 403);
  let body;
  try { body = await request.json(); } catch (e) { return errorResponse('JSON inválido'); }
  const { id } = body;
  if (!id) return errorResponse('Falta id');
  try {
    const value = await withRetry(env, entriesPath(env), entries => {
      const idx = entries.findIndex(e => e.id === id);
      if (idx === -1) return { noop: true, value: { error: 'No encontrado' } };
      const now = Date.now();
      entries[idx].history = entries[idx].history || [];
      entries[idx].history.push({ at: now, by: user.uid, byName: user.name, field: 'papelera', from: 'eliminado', to: 'restaurado' });
      entries[idx].deletedAt = null;
      entries[idx].updatedAt = now;
      return { data: entries, value: { entry: entries[idx] } };
    }, `Restaurar de papelera: ${id}`);
    if (value.error) return errorResponse(value.error, 404);
    return json({ entry: value.entry });
  } catch (e) { return errorResponse(e.message, 500); }
}

async function handleTrashDelete(request, env, user) {
  if (!requireSupervisor(user)) return errorResponse('Solo un supervisor puede vaciar la papelera', 403);
  const url = new URL(request.url);
  const id = url.searchParams.get('id');
  if (!id) return errorResponse('Falta id');
  try {
    await withRetry(env, entriesPath(env), entries => ({
      data: entries.filter(e => e.id !== id), value: true
    }), `Eliminar definitivamente: ${id}`);
    return json({ ok: true });
  } catch (e) { return errorResponse(e.message, 500); }
}

// ---------- enrutador ----------

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (path.startsWith('/api/')) {
      try {
        if (path === '/api/status' && method === 'GET') return handleStatus(request, env);
        if (path === '/api/setup' && method === 'POST') return handleSetup(request, env);
        if (path === '/api/login' && method === 'POST') return handleLogin(request, env);

        const user = await getAuthUser(request, env);

        if (path === '/api/me' && method === 'GET') return handleMe(request, env, user);

        if (path === '/api/users' && method === 'GET') return handleUsersGet(request, env, user);
        if (path === '/api/users' && method === 'POST') return handleUsersPost(request, env, user);
        if (path === '/api/users' && method === 'DELETE') return handleUsersDelete(request, env, user);

        if (path === '/api/entries' && method === 'GET') return handleEntriesGet(request, env, user);
        if (path === '/api/entries' && method === 'POST') return handleEntriesPost(request, env, user);
        if (path === '/api/entries' && method === 'PUT') return handleEntriesPut(request, env, user);
        if (path === '/api/entries' && method === 'DELETE') return handleEntriesDelete(request, env, user);

        if (path === '/api/trash' && method === 'GET') return handleTrashGet(request, env, user);
        if (path === '/api/trash/restore' && method === 'POST') return handleTrashRestore(request, env, user);
        if (path === '/api/trash' && method === 'DELETE') return handleTrashDelete(request, env, user);

        return errorResponse('Ruta no encontrada', 404);
      } catch (e) {
        return errorResponse(e.message || 'Error interno', 500);
      }
    }

    return env.ASSETS.fetch(request);
  }
};
