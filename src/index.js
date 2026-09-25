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
//   PASSWORD_KEY  (secreto)  -> llave para cifrar las claves del personal, para que
//                               el supervisor pueda verlas. Cadena larga y aleatoria.
// Opcionales: GITHUB_BRANCH, GITHUB_FILE_PATH, GITHUB_USERS_PATH, GITHUB_VEHICLES_PATH
//
// Archivos de datos:
//   data/entries.json  -> registros de salida/regreso
//   data/users.json    -> cuentas del personal
//   data/vehicles.json -> flota de unidades (la carga el supervisor)
//
// Roles:
//   admin  -> header x-access-code == ACCESS_CODE. Ve y gestiona todo:
//             todos los registros, papelera, y cuentas del personal.
//   worker -> header x-worker-token, validado contra data/users.json.
//             Solo ve y puede crear/editar SUS PROPIOS registros. Sin papelera.

const GITHUB_API = 'https://api.github.com';
const RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const PBKDF2_ITERATIONS = 50000;
// Formato de las unidades de GEMSA: 1-4 letras, guion, 1-5 numeros (GD-156, G-101, GD-21)
const CODE_PATTERN = /^[A-Z]{1,4}-\d{1,5}$/;
const TIME_PATTERN = /^([01]\d|2[0-3]):[0-5]\d$/;

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
}
function entriesPath(env) { return env.GITHUB_FILE_PATH || 'data/entries.json'; }
function usersPath(env) { return env.GITHUB_USERS_PATH || 'data/users.json'; }
function vehiclesPath(env) { return env.GITHUB_VEHICLES_PATH || 'data/vehicles.json'; }

// ---------- horas en los mensajes ----------
// Se guardan en 24 h ("16:20"); en los mensajes se dicen en 12 h, como la gente las lee.
function hora12(t) {
  if (!t || !/^\d{1,2}:\d{2}$/.test(String(t))) return t || '';
  const [h, m] = String(t).split(':').map(Number);
  return `${(h % 12) || 12}:${String(m).padStart(2, '0')} ${h < 12 ? 'AM' : 'PM'}`;
}
// "a la 1:05 PM" / "a las 4:20 PM"
function laHora(t) { const h = hora12(t); return (/^1:/.test(h) ? 'la ' : 'las ') + h; }

// ---------- ocupacion de unidades ----------
// Una unidad esta "fuera" si tiene un registro activo (no en papelera) sin regreso.
function registroActivoDeUnidad(entries, code, exceptoId) {
  return entries.find(e => e.code === code && e.status === 'fuera' && !e.deletedAt && e.id !== exceptoId) || null;
}
function errorUnidadOcupada(code, activo) {
  const quien = activo.name || 'otra persona';
  const err = new Error(`La unidad ${code} ya está fuera: salió con ${quien} a ${laHora(activo.time)}. Márcale el regreso antes de volver a sacarla.`);
  err.conflict = true;
  return err;
}

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

// ---------- claves consultables por el supervisor ----------
// Cada clave se guarda dos veces:
//   hash + salt -> PBKDF2, de una sola via. Es lo que se usa para iniciar sesion.
//   passEnc     -> AES-GCM con una llave derivada de PASSWORD_KEY (secreto de Cloudflare).
// El repo solo ve texto cifrado: sin PASSWORD_KEY no se puede leer. Si falta la
// llave, las cuentas funcionan igual pero su clave no queda consultable.
async function llaveDeClaves(env) {
  if (!env.PASSWORD_KEY) return null;
  const material = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('gemsa-claves-v1:' + env.PASSWORD_KEY));
  return crypto.subtle.importKey('raw', material, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
async function cifrarClave(env, password) {
  const llave = await llaveDeClaves(env);
  if (!llave) return null;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cifrado = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, llave, new TextEncoder().encode(password));
  return 'v1:' + bytesToHex(iv) + ':' + bytesToHex(new Uint8Array(cifrado));
}
async function descifrarClave(env, passEnc) {
  const llave = await llaveDeClaves(env);
  if (!llave || !passEnc) return null;
  const [ver, ivHex, datosHex] = passEnc.split(':');
  if (ver !== 'v1' || !ivHex || !datosHex) return null;
  try {
    const claro = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: hexToBytes(ivHex) }, llave, hexToBytes(datosHex));
    return new TextDecoder().decode(claro);
  } catch (e) { return null; } // llave distinta (se cambio PASSWORD_KEY) o dato alterado
}

// ---------- GitHub como base de datos (genérico para cualquier archivo JSON) ----------
async function githubGetJsonFile(env, path) {
  const branch = env.GITHUB_BRANCH || 'main';
  const url = `${GITHUB_API}/repos/${env.GITHUB_REPO}/contents/${path}?ref=${branch}`;
  const headers = { Authorization: `token ${env.GITHUB_TOKEN}`, 'User-Agent': 'control-salidas-worker', Accept: 'application/vnd.github+json' };
  const res = await fetch(url, { headers });
  if (res.status === 404) return { sha: null, data: [] };   // el archivo aún no existe: se crea al primer guardado
  if (!res.ok) throw new Error(`GitHub GET falló: ${res.status}`);
  const resData = await res.json();
  if (resData.size === 0) return { sha: resData.sha, data: [] };

  // A partir de 1 MB la API de contenidos ya no trae el contenido (encoding "none").
  // En ese caso se pide el blob por su sha, que admite archivos de hasta 100 MB.
  let b64 = resData.content;
  if (!b64 || resData.encoding === 'none') {
    const blobRes = await fetch(`${GITHUB_API}/repos/${env.GITHUB_REPO}/git/blobs/${resData.sha}`, { headers });
    if (!blobRes.ok) throw new Error(`GitHub GET (blob) falló: ${blobRes.status}`);
    b64 = (await blobRes.json()).content;
  }

  // NUNCA tratar un archivo ilegible como vacío: la siguiente escritura lo
  // sobrescribiría con un solo registro y se perdería todo el historial.
  let data;
  try { data = JSON.parse(b64DecodeUtf8(b64 || '')); }
  catch (e) { throw new Error(`No se pudo leer ${path}: el archivo está dañado o incompleto. No se guardó nada, para no perder datos.`); }
  if (!Array.isArray(data)) throw new Error(`${path} no tiene el formato esperado. No se guardó nada, para no perder datos.`);
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
  if (!code) return json({ error: 'Elige la unidad que sale' }, 400);
  if (!name) return json({ error: 'Falta el nombre de quien sale' }, 400);
  if (name.length > 120) return json({ error: 'El nombre es demasiado largo' }, 400);
  if (!TIME_PATTERN.test(time)) return json({ error: 'Hora inválida' }, 400);
  if (obs.length > 200) return json({ error: 'La observación es demasiado larga' }, 400);

  // Solo se pueden sacar unidades que el supervisor haya dado de alta.
  let flota;
  try { flota = (await githubGetJsonFile(env, vehiclesPath(env))).data; }
  catch (e) { return json({ error: e.message }, 500); }
  if (flota.length === 0) {
    return json({ error: 'Todavía no hay unidades registradas. El supervisor debe agregarlas en la pestaña Unidades.' }, 400);
  }
  if (!flota.some(v => v.code === code)) {
    return json({ error: `La unidad ${code} no está en la flota. Pide al supervisor que la agregue.` }, 400);
  }

  const entry = {
    id: crypto.randomUUID(), code, name, time, obs, status: 'fuera', returnTime: null,
    workerId, workerUsername,
    createdAt: Date.now(), editedAt: null, deletedAt: null,
    createdBy: auth.role === 'worker' ? auth.worker.name : 'Supervisor',
    history: []
  };
  try {
    await withRetryFile(env, entriesPath(env), entries => {
      const cleaned = purgeExpired(entries);
      // Se comprueba DENTRO del reintento: si dos personas eligen la misma unidad
      // a la vez, GitHub rechaza la segunda escritura (sha viejo), se vuelve a leer
      // el archivo ya con la primera salida y esta comprobacion la detiene.
      const activo = registroActivoDeUnidad(cleaned, code, null);
      if (activo) throw errorUnidadOcupada(code, activo);
      cleaned.push(entry);
      return { data: cleaned, value: entry };
    }, `Registrar salida: ${code} - ${name}`);
    return json({ entry });
  } catch (e) {
    if (e.conflict) return json({ error: e.message }, 409);
    return json({ error: e.message }, 500);
  }
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
      if (body.time !== undefined && !TIME_PATTERN.test(body.time)) {
        const err = new Error('Hora inválida'); err.badInput = true; throw err;
      }
      if (body.returnTime !== undefined && body.returnTime !== null && !TIME_PATTERN.test(body.returnTime)) {
        const err = new Error('Hora de regreso inválida'); err.badInput = true; throw err;
      }
      if (body.status !== undefined && body.status !== 'fuera' && body.status !== 'regreso') {
        const err = new Error('Estado inválido'); err.badInput = true; throw err;
      }
      // Deshacer un regreso vuelve a poner la unidad "fuera". Si mientras tanto otra
      // persona ya la saco, quedarian dos salidas abiertas de la misma unidad.
      if (body.status === 'fuera' && current.status !== 'fuera' && !current.deletedAt) {
        const activo = registroActivoDeUnidad(entries, current.code, current.id);
        if (activo) {
          const err = new Error(`No se puede deshacer el regreso: la unidad ${current.code} ya volvió a salir con ${activo.name} a ${laHora(activo.time)}.`);
          err.conflict = true; throw err;
        }
      }
      if (body.status === 'fuera') body.returnTime = null; // si esta fuera, no tiene hora de regreso

      // El historial guarda una linea por cambio REAL (que cambio, de que a que).
      // Antes guardaba una foto completa del registro y, si llegaban dos peticiones
      // iguales (doble toque), quedaban dos filas identicas en pantalla.
      const now = Date.now();
      const who = auth.role === 'worker' ? auth.worker.name : 'Supervisor';
      const changes = [];
      if (body.time !== undefined && body.time !== current.time) {
        changes.push({ changedAt: now, by: who, type: 'salida', from: current.time, to: body.time });
      }
      if (body.status !== undefined && body.status !== current.status) {
        if (body.status === 'regreso') {
          changes.push({ changedAt: now, by: who, type: 'regreso_marcado', from: null, to: body.returnTime || null });
        } else {
          changes.push({ changedAt: now, by: who, type: 'regreso_deshecho', from: current.returnTime || null, to: null });
        }
      } else if (body.returnTime !== undefined && body.returnTime !== current.returnTime && current.returnTime) {
        changes.push({ changedAt: now, by: who, type: 'regreso_hora', from: current.returnTime, to: body.returnTime });
      }
      if (body.obs !== undefined && body.obs !== current.obs) {
        changes.push({ changedAt: now, by: who, type: 'observacion', from: current.obs || null, to: body.obs || null });
      }

      // Nada cambio realmente: no se escribe nada ni se ensucia el historial.
      if (changes.length === 0) return { noop: true, value: current };

      // "Regreso marcado" no cuenta como edicion: es parte del flujo normal.
      const isRealEdit = changes.some(c => c.type !== 'regreso_marcado');
      for (const c of changes) current.history.push(c);
      if (isRealEdit) current.editedAt = now;

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
    if (e.badInput) return json({ error: e.message }, 400);
    if (e.conflict) return json({ error: e.message }, 409);
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
      const reg = entries[idx];
      // Restaurar una salida sin regreso reabre la unidad; no puede chocar con otra.
      if (reg.status === 'fuera') {
        const activo = registroActivoDeUnidad(entries, reg.code, reg.id);
        if (activo) {
          const err = new Error(`No se puede restaurar: la unidad ${reg.code} está fuera con ${activo.name} desde ${laHora(activo.time)}.`);
          err.conflict = true; throw err;
        }
      }
      reg.deletedAt = null;
      return { data: entries, value: reg };
    }, `Restaurar de papelera: ${id}`);
    if (!value) return json({ error: 'Registro no encontrado' }, 404);
    return json({ entry: value });
  } catch (e) {
    if (e.conflict) return json({ error: e.message }, 409);
    return json({ error: e.message }, 500);
  }
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
  // La clave nunca viaja en el listado: solo si se puede consultar.
  return json({ users: users.map(u => ({ id: u.id, username: u.username, name: u.name, createdAt: u.createdAt, claveConsultable: !!u.passEnc })) });
}

// Ver la clave de una cuenta (solo supervisor, una cuenta a la vez, bajo pedido)
async function handleGetUserPassword(request, env) {
  const auth = await checkAuth(request, env);
  if (!auth.ok || auth.role !== 'admin') return json({ error: 'unauthorized' }, 401);
  if (!env.PASSWORD_KEY) return json({ error: 'Falta configurar PASSWORD_KEY en Cloudflare para poder ver claves.' }, 503);
  const id = new URL(request.url).searchParams.get('id');
  if (!id) return json({ error: 'Falta id' }, 400);
  const { data: users } = await githubGetJsonFile(env, usersPath(env));
  const u = users.find(x => x.id === id);
  if (!u) return json({ error: 'Cuenta no encontrada' }, 404);
  if (!u.passEnc) return json({ error: 'Esta cuenta se creó antes de poder ver claves. Cámbiale la clave y desde ahí se podrá ver.' }, 404);
  const password = await descifrarClave(env, u.passEnc);
  if (password === null) return json({ error: 'No se pudo leer esta clave (¿cambió PASSWORD_KEY?). Cámbiala para poder verla.' }, 409);
  return json({ password });
}

// Cambiar la clave de una cuenta (solo supervisor). Cierra la sesión que tenga abierta.
async function handleSetUserPassword(request, env) {
  const auth = await checkAuth(request, env);
  if (!auth.ok || auth.role !== 'admin') return json({ error: 'unauthorized' }, 401);
  let body;
  try { body = await request.json(); } catch (e) { return json({ error: 'JSON inválido' }, 400); }
  const id = body.id, password = body.password || '';
  if (!id) return json({ error: 'Falta id' }, 400);
  if (password.length < 4) return json({ error: 'La clave debe tener al menos 4 caracteres' }, 400);
  if (password.length > 64) return json({ error: 'La clave es demasiado larga' }, 400);
  const { hash, salt } = await hashPassword(password);
  const passEnc = await cifrarClave(env, password);
  try {
    const value = await withRetryFile(env, usersPath(env), usersArr => {
      const u = usersArr.find(x => x.id === id);
      if (!u) return { noop: true, value: null };
      u.hash = hash; u.salt = salt; u.passEnc = passEnc;
      u.tokenHash = null;              // la sesión vieja deja de valer: entra con la clave nueva
      u.passChangedAt = Date.now();
      return { data: usersArr, value: { username: u.username } };
    }, 'Cambiar clave de una cuenta');  // el mensaje del commit no lleva ni la clave ni el usuario
    if (!value) return json({ error: 'Cuenta no encontrada' }, 404);
    return json({ ok: true, claveConsultable: !!passEnc });
  } catch (e) { return json({ error: e.message }, 500); }
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
  if (password.length > 64) return json({ error: 'La clave es demasiado larga' }, 400);
  if (!/^[a-z0-9._-]+$/.test(username)) return json({ error: 'Usuario inválido: solo letras, números, punto, guion' }, 400);

  const { hash, salt } = await hashPassword(password);
  const passEnc = await cifrarClave(env, password);
  const newUser = { id: crypto.randomUUID(), username, name, hash, salt, passEnc, tokenHash: null, createdAt: Date.now() };
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
  return json({ user: { id: newUser.id, username: newUser.username, name: newUser.name, createdAt: newUser.createdAt, claveConsultable: !!passEnc } });
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

// ---------- handlers: flota de unidades ----------
function ordenarUnidades(a, b) {
  return a.code.localeCompare(b.code, 'es', { numeric: true });
}

// Todo el mundo con sesion ve la flota y cual unidad esta fuera (y con quien),
// para poder elegir una libre. Solo el supervisor la modifica.
async function handleListVehicles(request, env) {
  const auth = await checkAuth(request, env);
  if (!auth.ok) return json({ error: 'unauthorized' }, 401);
  try {
    const [{ data: flota }, { data: entries }] = await Promise.all([
      githubGetJsonFile(env, vehiclesPath(env)),
      githubGetJsonFile(env, entriesPath(env))
    ]);
    const vehicles = flota.slice().sort(ordenarUnidades).map(v => {
      const activo = registroActivoDeUnidad(entries, v.code, null);
      return {
        id: v.id, code: v.code, desc: v.desc || '', createdAt: v.createdAt,
        enUso: !!activo,
        porQuien: activo ? activo.name : null,
        desde: activo ? activo.time : null
      };
    });
    return json({ vehicles });
  } catch (e) { return json({ error: e.message }, 500); }
}

// Acepta una o varias unidades de golpe ("GD-21, GD-156 G-107"), para no tener
// que cargar la flota una por una.
async function handleAddVehicles(request, env) {
  const auth = await checkAuth(request, env);
  if (!auth.ok || auth.role !== 'admin') return json({ error: 'unauthorized' }, 401);
  let body;
  try { body = await request.json(); } catch (e) { return json({ error: 'JSON inválido' }, 400); }
  const desc = (body.desc || '').trim().slice(0, 60);
  const crudos = String(body.codes || '').toUpperCase().split(/[\s,;]+/).filter(Boolean);
  if (crudos.length === 0) return json({ error: 'Escribe al menos un código' }, 400);
  if (crudos.length > 100) return json({ error: 'Máximo 100 unidades por vez' }, 400);

  const validos = [], invalidos = [];
  for (const c of crudos) {
    // Acepta "gd156" o "GD-156" y lo deja siempre como GD-156
    const m = c.replace(/[^A-Z0-9]/g, '').match(/^([A-Z]{1,4})(\d{1,5})$/);
    const code = m ? `${m[1]}-${m[2]}` : c;
    if (CODE_PATTERN.test(code)) { if (!validos.includes(code)) validos.push(code); }
    else invalidos.push(c);
  }
  try {
    const result = await withRetryFile(env, vehiclesPath(env), flota => {
      const existentes = new Set(flota.map(v => v.code));
      const nuevos = validos.filter(c => !existentes.has(c));
      const repetidos = validos.filter(c => existentes.has(c));
      if (nuevos.length === 0) return { noop: true, value: { agregadas: [], repetidas: repetidos } };
      const now = Date.now();
      for (const code of nuevos) flota.push({ id: crypto.randomUUID(), code, desc: nuevos.length === 1 ? desc : '', createdAt: now });
      return { data: flota, value: { agregadas: nuevos, repetidas: repetidos } };
    }, validos.length === 1 ? `Agregar unidad: ${validos[0]}` : `Agregar ${validos.length} unidades`);
    return json({ ...result, invalidas: invalidos });
  } catch (e) { return json({ error: e.message }, 500); }
}

async function handleDeleteVehicle(request, env) {
  const auth = await checkAuth(request, env);
  if (!auth.ok || auth.role !== 'admin') return json({ error: 'unauthorized' }, 401);
  const id = new URL(request.url).searchParams.get('id');
  if (!id) return json({ error: 'Falta id' }, 400);
  try {
    const { data: entries } = await githubGetJsonFile(env, entriesPath(env));
    const value = await withRetryFile(env, vehiclesPath(env), flota => {
      const v = flota.find(x => x.id === id);
      if (!v) return { noop: true, value: null };
      const activo = registroActivoDeUnidad(entries, v.code, null);
      if (activo) {
        const err = new Error(`La unidad ${v.code} está fuera con ${activo.name}. Márcale el regreso antes de quitarla.`);
        err.conflict = true; throw err;
      }
      // Los registros viejos de esta unidad se quedan como estan: solo sale de la lista.
      return { data: flota.filter(x => x.id !== id), value: v };
    }, `Quitar unidad: ${id}`);
    if (!value) return json({ error: 'Unidad no encontrada' }, 404);
    return json({ ok: true });
  } catch (e) {
    if (e.conflict) return json({ error: e.message }, 409);
    return json({ error: e.message }, 500);
  }
}

// App de Android (GEMSA Salidas). Android lee este archivo para confirmar que la
// app es de este sitio y así abrirla a pantalla completa, sin la barra de Chrome.
// La huella es la de la llave de firma (firma/gemsa-salidas.keystore). Si algún día
// se firma la app con otra llave, hay que poner aquí la huella nueva.
const APP_ANDROID = {
  paquete: 'com.gadrnet.gemsa',
  huellas: ['EC:5A:DB:88:2E:F4:73:C8:3B:AF:17:7A:70:C6:B5:08:01:6F:81:1F:BC:67:05:F7:30:51:F8:A7:7C:25:DD:6C'],
};

function assetLinks() {
  return new Response(JSON.stringify([{
    relation: ['delegate_permission/common.handle_all_urls'],
    target: { namespace: 'android_app', package_name: APP_ANDROID.paquete, sha256_cert_fingerprints: APP_ANDROID.huellas },
  }]), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=3600' } });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const method = request.method;

    if (url.pathname === '/.well-known/assetlinks.json' && (method === 'GET' || method === 'HEAD')) return assetLinks();

    if (url.pathname === '/api/auth/login' && method === 'POST') return handleLogin(request, env);
    if (url.pathname === '/api/auth/me' && method === 'GET') return handleMe(request, env);
    if (url.pathname === '/api/auth/logout' && method === 'POST') return handleLogout(request, env);

    if (url.pathname === '/api/users/password' && method === 'GET') return handleGetUserPassword(request, env);
    if (url.pathname === '/api/users/password' && method === 'PUT') return handleSetUserPassword(request, env);
    if (url.pathname === '/api/users' && method === 'GET') return handleListUsers(request, env);
    if (url.pathname === '/api/users' && method === 'POST') return handleCreateUser(request, env);
    if (url.pathname === '/api/users' && method === 'DELETE') return handleDeleteUser(request, env);

    if (url.pathname === '/api/vehicles' && method === 'GET') return handleListVehicles(request, env);
    if (url.pathname === '/api/vehicles' && method === 'POST') return handleAddVehicles(request, env);
    if (url.pathname === '/api/vehicles' && method === 'DELETE') return handleDeleteVehicle(request, env);

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
