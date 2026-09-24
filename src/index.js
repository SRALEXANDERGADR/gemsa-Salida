// src/index.js
// Worker único: sirve public/ (estáticos) y maneja /api/* usando dos archivos
// JSON dentro de este mismo repo de GitHub como "base de datos":
//   data/entries.json -> registros de salida/regreso
//   data/users.json   -> cuentas del personal (creadas por supervisores)
//
// Variables/secretos a configurar en Cloudflare (Settings del Worker):
//   GITHUB_TOKEN  (secreto)  -> Personal Access Token con permiso sobre el repo
//   GITHUB_REPO   (variable) -> ej. "SRALEXANDERGADR/gemsa-Salida"
//   ACCESS_CODE   (secreto)  -> clave de supervisor/admin (acceso total)
// Opcionales: GITHUB_BRANCH, GITHUB_FILE_PATH, GITHUB_USERS_PATH
//
// Roles:
//   admin  -> header x-access-code == ACCESS_CODE. Ve y gestiona todo:
//             todos los registros, papelera, y cuentas del personal.
//   worker -> header x-worker-token, validado contra data/users.json.
//             Solo ve y puede crear/editar SUS PROPIOS registros. Sin papelera.

const GITHUB_API = 'https://api.github.com';
const RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const PBKDF2_ITERATIONS = 50000;

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
}
function entriesPath(env) { return env.GITHUB_FILE_PATH || 'data/entries.json'; }
function usersPath(env) { return env.GITHUB_USERS_PATH || 'data/users.json'; }

// ---------- utilidades de texto/binario ----------
function b64EncodeUtf8(str) {
  const bytes = new TextEncoder().encode(str);
  let binary = ''; bytes.forEach(b => (binary += String.fromCharCode(b)));
  return btoa(binary);
}
function b64DecodeUtf8(b64) {
  const binary = atob(b64.replace(/\n/g, ''));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}
function bytesToHex(bytes) { return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''); }
function hexToBytes(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) arr[i] = parseInt(hex.substr(i * 2, 2), 16);
  return arr;
}

// ---------- criptografía (claves y tokens de sesión) ----------
async function sha256Hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return bytesToHex(new Uint8Array(buf));
}
async function pbkdf2Hex(password, saltBytes) {
  const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: saltBytes, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' }, keyMaterial, 256);
  return bytesToHex(new Uint8Array(bits));
}
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return { hash: await pbkdf2Hex(password, salt), salt: bytesToHex(salt) };
}
async function verifyPassword(password, saltHex, hashHex) {
  return (await pbkdf2Hex(password, hexToBytes(saltHex))) === hashHex;
}
function generateToken() { return bytesToHex(crypto.getRandomValues(new Uint8Array(32))); }

// ---------- GitHub como base de datos (genérico para cualquier archivo JSON) ----------
async function githubGetJsonFile(env, path) {
  const branch = env.GITHUB_BRANCH || 'main';
  const url = `${GITHUB_API}/repos/${env.GITHUB_REPO}/contents/${path}?ref=${branch}`;
  const res = await fetch(url, { headers: { Authorization: `token ${env.GITHUB_TOKEN}`, 'User-Agent': 'control-salidas-worker', Accept: 'application/vnd.github+json' } });
  if (res.status === 404) return { sha: null, data: [] };
  if (!res.ok) throw new Error(`GitHub GET falló: ${res.status}`);
  const resData = await res.json();
  let data = [];
  try { data = JSON.parse(b64DecodeUtf8(resData.content)); } catch (e) { data = []; }
  return { sha: resData.sha, data };
}
async function githubPutJsonFile(env, path, data, sha, message) {
  const branch = env.GITHUB_BRANCH || 'main';
  const url = `${GITHUB_API}/repos/${env.GITHUB_REPO}/contents/${path}`;
  const body = { message, content: b64EncodeUtf8(JSON.stringify(data, null, 2)), branch };
  if (sha) body.sha = sha;
  const res = await fetch(url, {
    method: 'PUT',
    headers: { Authorization: `token ${env.GITHUB_TOKEN}`, 'User-Agent': 'control-salidas-worker', Accept: 'application/vnd.github+json', 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  if (!res.ok) {
    const errText = await res.text();
    const err = new Error(`GitHub PUT falló: ${res.status} ${errText}`);
    err.status = res.status;
    throw err;
  }
}
async function withRetryFile(env, path, mutateFn, message, maxAttempts = 3) {
  let attempt = 0;
  while (attempt < maxAttempts) {
    attempt++;
    const { sha, data } = await githubGetJsonFile(env, path);
    const result = mutateFn(data);
    if (result.noop) return result.value;
    try {
      await githubPutJsonFile(env, path, result.data, sha, message);
      return result.value;
    } catch (e) {
      if (e.status === 409 || e.status === 422) continue;
      throw e;
    }
  }
  throw new Error('No se pudo guardar tras varios intentos (conflicto de escritura).');
}

// ---------- autenticación ----------
async function checkAuth(request, env) {
  const accessCode = request.headers.get('x-access-code');
  if (accessCode && env.ACCESS_CODE && accessCode === env.ACCESS_CODE) {
    return { ok: true, role: 'admin' };
  }
  const workerToken = request.headers.get('x-worker-token');
  if (workerToken) {
    const tokenHash = await sha256Hex(workerToken);
    const { data: users } = await githubGetJsonFile(env, usersPath(env));
    const user = users.find(u => u.tokenHash === tokenHash);
    if (user) return { ok: true, role: 'worker', worker: { id: user.id, username: user.username, name: user.name } };
  }
  return { ok: false };
}

// ---------- entries: helpers de retención/papelera ----------
function refTime(e) { return e.deletedAt || e.editedAt || e.createdAt; }
function purgeExpired(entries) {
  const cutoff = Date.now() - RETENTION_MS;
  return entries.filter(e => refTime(e) >= cutoff);
}

// ---------- handlers: entries ----------
async function handleGet(request, env) {
  const auth = await checkAuth(request, env);
  if (!auth.ok) return json({ error: 'unauthorized' }, 401);
  try {
    const result = await withRetryFile(env, entriesPath(env), entries => {
      const cleaned = purgeExpired(entries);
      let active = cleaned.filter(e => !e.deletedAt);
      if (auth.role === 'worker') active = active.filter(e => e.workerId === auth.worker.id);
      if (cleaned.length === entries.length) return { noop: true, value: active };
      return { data: cleaned, value: active };
    }, 'Limpieza automática: registros con más de 30 días');
    return json({ entries: result });
  } catch (e) { return json({ error: e.message }, 500); }
}

async function handleGetTrash(request, env) {
  const auth = await checkAuth(request, env);
  if (!auth.ok || auth.role !== 'admin') return json({ error: 'unauthorized' }, 401);
  try {
    const result = await withRetryFile(env, entriesPath(env), entries => {
      const cleaned = purgeExpired(entries);
      const trashed = cleaned.filter(e => !!e.deletedAt);
      if (cleaned.length === entries.length) return { noop: true, value: trashed };
      return { data: cleaned, value: trashed };
    }, 'Limpieza automática: registros con más de 30 días');
    return json({ entries: result });
  } catch (e) { return json({ error: e.message }, 500); }
}

async function handlePost(request, env) {
  const auth = await checkAuth(request, env);
  if (!auth.ok) return json({ error: 'unauthorized' }, 401);
  let body;
  try { body = await request.json(); } catch (e) { return json({ error: 'JSON inválido' }, 400); }
  const code = (body.code || '').trim().toUpperCase();
  const time = (body.time || '').trim();
  const obs = (body.obs || '').trim();

  let name, workerId = null, workerUsername = null;
  if (auth.role === 'worker') {
    name = auth.worker.name; workerId = auth.worker.id; workerUsername = auth.worker.username;
  } else {
    name = (body.name || '').trim();
  }
  if (!code || !name) return json({ error: 'Falta código o nombre' }, 400);

  const entry = {
    id: crypto.randomUUID(), code, name, time, obs, status: 'fuera', returnTime: null,
    workerId, workerUsername,
    createdAt: Date.now(), editedAt: null, deletedAt: null, history: []
  };
  try {
    await withRetryFile(env, entriesPath(env), entries => {
      const cleaned = purgeExpired(entries);
      cleaned.push(entry);
      return { data: cleaned, value: entry };
    }, `Registrar salida: ${code} - ${name}`);
    return json({ entry });
  } catch (e) { return json({ error: e.message }, 500); }
}

async function handlePut(request, env) {
  const auth = await checkAuth(request, env);
  if (!auth.ok) return json({ error: 'unauthorized' }, 401);
  let body;
  try { body = await request.json(); } catch (e) { return json({ error: 'JSON inválido' }, 400); }
  const { id } = body;
  if (!id) return json({ error: 'Falta id' }, 400);
  try {
    const value = await withRetryFile(env, entriesPath(env), entries => {
      const idx = entries.findIndex(e => e.id === id);
      if (idx === -1) return { noop: true, value: null };
      const current = entries[idx];
      if (auth.role === 'worker' && current.workerId !== auth.worker.id) {
        const err = new Error('forbidden'); err.forbidden = true; throw err;
      }
      if (!current.history) current.history = [];
      const isMarkingReturn = body.status !== undefined && body.status !== current.status;
      const isEditingTime = body.time !== undefined && body.time !== current.time;
      if (isEditingTime || (isMarkingReturn && current.status === 'regreso')) {
        current.history.push({ time: current.time, obs: current.obs, status: current.status, returnTime: current.returnTime, changedAt: Date.now() });
        current.editedAt = Date.now();
      }
      if (body.time !== undefined) current.time = body.time;
      if (body.obs !== undefined) current.obs = body.obs;
      if (body.status !== undefined) current.status = body.status;
      if (body.returnTime !== undefined) current.returnTime = body.returnTime;
      return { data: entries, value: current };
    }, body.status === 'regreso' ? `Marcar regreso: ${id}` : `Editar registro: ${id}`);
    if (!value) return json({ error: 'Registro no encontrado' }, 404);
    return json({ entry: value });
  } catch (e) {
    if (e.forbidden) return json({ error: 'No autorizado para editar este registro' }, 403);
    return json({ error: e.message }, 500);
  }
}

async function handleDelete(request, env) {
  const auth = await checkAuth(request, env);
  if (!auth.ok || auth.role !== 'admin') return json({ error: 'unauthorized' }, 401);
  const url = new URL(request.url);
  const id = url.searchParams.get('id');
  if (!id) return json({ error: 'Falta id' }, 400);
  try {
    const value = await withRetryFile(env, entriesPath(env), entries => {
      const idx = entries.findIndex(e => e.id === id);
      if (idx === -1) return { noop: true, value: null };
      entries[idx].deletedAt = Date.now();
      return { data: entries, value: true };
    }, `Mover a papelera: ${id}`);
    if (!value) return json({ error: 'Registro no encontrado' }, 404);
    return json({ ok: true });
  } catch (e) { return json({ error: e.message }, 500); }
}

async function handleRestore(request, env) {
  const auth = await checkAuth(request, env);
  if (!auth.ok || auth.role !== 'admin') return json({ error: 'unauthorized' }, 401);
  let body;
  try { body = await request.json(); } catch (e) { return json({ error: 'JSON inválido' }, 400); }
  const { id } = body;
  if (!id) return json({ error: 'Falta id' }, 400);
  try {
    const value = await withRetryFile(env, entriesPath(env), entries => {
      const idx = entries.findIndex(e => e.id === id);
      if (idx === -1) return { noop: true, value: null };
      entries[idx].deletedAt = null;
      return { data: entries, value: entries[idx] };
    }, `Restaurar de papelera: ${id}`);
    if (!value) return json({ error: 'Registro no encontrado' }, 404);
    return json({ entry: value });
  } catch (e) { return json({ error: e.message }, 500); }
}

async function handlePurge(request, env) {
  const auth = await checkAuth(request, env);
  if (!auth.ok || auth.role !== 'admin') return json({ error: 'unauthorized' }, 401);
  const url = new URL(request.url);
  const id = url.searchParams.get('id');
  if (!id) return json({ error: 'Falta id' }, 400);
  try {
    await withRetryFile(env, entriesPath(env), entries => ({ data: entries.filter(e => e.id !== id), value: true }), `Eliminar para siempre: ${id}`);
    return json({ ok: true });
  } catch (e) { return json({ error: e.message }, 500); }
}

// ---------- handlers: auth de trabajadores ----------
async function handleLogin(request, env) {
  let body;
  try { body = await request.json(); } catch (e) { return json({ error: 'JSON inválido' }, 400); }
  const username = (body.username || '').trim().toLowerCase();
  const password = body.password || '';
  if (!username || !password) return json({ error: 'Falta usuario o clave' }, 400);
  const { data: users } = await githubGetJsonFile(env, usersPath(env));
  const user = users.find(u => u.username === username);
  if (!user || !(await verifyPassword(password, user.salt, user.hash))) {
    return json({ error: 'Usuario o clave incorrectos' }, 401);
  }
  const token = generateToken();
  const tokenHash = await sha256Hex(token);
  try {
    await withRetryFile(env, usersPath(env), usersArr => {
      const idx = usersArr.findIndex(u => u.id === user.id);
      if (idx === -1) return { noop: true, value: null };
      usersArr[idx].tokenHash = tokenHash;
      return { data: usersArr, value: true };
    }, `Inicio de sesión: ${username}`);
  } catch (e) { return json({ error: e.message }, 500); }
  return json({ token, worker: { id: user.id, username: user.username, name: user.name } });
}

async function handleMe(request, env) {
  const auth = await checkAuth(request, env);
  if (!auth.ok || auth.role !== 'worker') return json({ error: 'unauthorized' }, 401);
  return json({ worker: auth.worker });
}

async function handleLogout(request, env) {
  const token = request.headers.get('x-worker-token');
  if (!token) return json({ ok: true });
  const tokenHash = await sha256Hex(token);
  try {
    await withRetryFile(env, usersPath(env), usersArr => {
      const idx = usersArr.findIndex(u => u.tokenHash === tokenHash);
      if (idx === -1) return { noop: true, value: true };
      usersArr[idx].tokenHash = null;
      return { data: usersArr, value: true };
    }, 'Cerrar sesión');
  } catch (e) { /* no bloquear el logout del lado del cliente por esto */ }
  return json({ ok: true });
}

// ---------- handlers: gestión de personal (solo admin) ----------
async function handleListUsers(request, env) {
  const auth = await checkAuth(request, env);
  if (!auth.ok || auth.role !== 'admin') return json({ error: 'unauthorized' }, 401);
  const { data: users } = await githubGetJsonFile(env, usersPath(env));
  return json({ users: users.map(u => ({ id: u.id, username: u.username, name: u.name, createdAt: u.createdAt })) });
}

async function handleCreateUser(request, env) {
  const auth = await checkAuth(request, env);
  if (!auth.ok || auth.role !== 'admin') return json({ error: 'unauthorized' }, 401);
  let body;
  try { body = await request.json(); } catch (e) { return json({ error: 'JSON inválido' }, 400); }
  const username = (body.username || '').trim().toLowerCase();
  const name = (body.name || '').trim();
  const password = body.password || '';
  if (!username || !name || !password) return json({ error: 'Faltan datos' }, 400);
  if (password.length < 4) return json({ error: 'La clave debe tener al menos 4 caracteres' }, 400);
  if (!/^[a-z0-9._-]+$/.test(username)) return json({ error: 'Usuario inválido: solo letras, números, punto, guion' }, 400);

  const { hash, salt } = await hashPassword(password);
  const newUser = { id: crypto.randomUUID(), username, name, hash, salt, tokenHash: null, createdAt: Date.now() };
  try {
    await withRetryFile(env, usersPath(env), usersArr => {
      if (usersArr.some(u => u.username === username)) { const err = new Error('dup'); err.dup = true; throw err; }
      usersArr.push(newUser);
      return { data: usersArr, value: newUser };
    }, `Crear cuenta de personal: ${username}`);
  } catch (e) {
    if (e.dup) return json({ error: 'Ese usuario ya existe' }, 409);
    return json({ error: e.message }, 500);
  }
  return json({ user: { id: newUser.id, username: newUser.username, name: newUser.name, createdAt: newUser.createdAt } });
}

async function handleDeleteUser(request, env) {
  const auth = await checkAuth(request, env);
  if (!auth.ok || auth.role !== 'admin') return json({ error: 'unauthorized' }, 401);
  const url = new URL(request.url);
  const id = url.searchParams.get('id');
  if (!id) return json({ error: 'Falta id' }, 400);
  try {
    await withRetryFile(env, usersPath(env), usersArr => ({ data: usersArr.filter(u => u.id !== id), value: true }), `Eliminar cuenta de personal: ${id}`);
    return json({ ok: true });
  } catch (e) { return json({ error: e.message }, 500); }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const method = request.method;

    if (url.pathname === '/api/auth/login' && method === 'POST') return handleLogin(request, env);
    if (url.pathname === '/api/auth/me' && method === 'GET') return handleMe(request, env);
    if (url.pathname === '/api/auth/logout' && method === 'POST') return handleLogout(request, env);

    if (url.pathname === '/api/users' && method === 'GET') return handleListUsers(request, env);
    if (url.pathname === '/api/users' && method === 'POST') return handleCreateUser(request, env);
    if (url.pathname === '/api/users' && method === 'DELETE') return handleDeleteUser(request, env);

    if (url.pathname === '/api/entries/trash' && method === 'GET') return handleGetTrash(request, env);
    if (url.pathname === '/api/entries/restore' && method === 'POST') return handleRestore(request, env);
    if (url.pathname === '/api/entries/purge' && method === 'DELETE') return handlePurge(request, env);

    if (url.pathname === '/api/entries') {
      switch (method) {
        case 'GET': return handleGet(request, env);
        case 'POST': return handlePost(request, env);
        case 'PUT': return handlePut(request, env);
        case 'DELETE': return handleDelete(request, env);
        default: return json({ error: 'Método no permitido' }, 405);
      }
    }
    return env.ASSETS.fetch(request);
  }
};
