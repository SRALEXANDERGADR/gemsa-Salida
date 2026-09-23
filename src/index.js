// src/index.js
// Worker único: sirve public/ (estáticos) y maneja /api/entries* usando
// un archivo JSON dentro de este mismo repo de GitHub como "base de datos".
//
// Variables/secretos a configurar en Cloudflare (Settings del Worker):
//   GITHUB_TOKEN  (secreto)  -> Personal Access Token con permiso sobre el repo
//   GITHUB_REPO   (variable) -> ej. "SRALEXANDERGADR/gemsa-Salida"
//   ACCESS_CODE   (secreto)  -> clave compartida del equipo
// Opcionales: GITHUB_BRANCH (default "main"), GITHUB_FILE_PATH (default "data/entries.json")
//
// Modelo de cada registro:
//   { id, code, name, time, obs, status, returnTime,
//     createdAt, editedAt, deletedAt, history: [{time,obs,status,returnTime,changedAt}] }
//
// Retención: un registro activo se purga para siempre 30 días después de
// createdAt/editedAt (lo que sea más reciente). Un registro borrado (papelera)
// se purga para siempre 30 días después de deletedAt. Borrar nunca es
// inmediato: siempre pasa primero por la papelera.

const GITHUB_API = 'https://api.github.com';
const RETENTION_MS = 30 * 24 * 60 * 60 * 1000;

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
}

function checkAuth(request, env) {
  const code = request.headers.get('x-access-code') || '';
  return !!env.ACCESS_CODE && code === env.ACCESS_CODE;
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

// Momento de referencia para calcular expiración de un registro
function refTime(e) {
  return e.deletedAt || e.editedAt || e.createdAt;
}

function purgeExpired(entries) {
  const cutoff = Date.now() - RETENTION_MS;
  return entries.filter(e => refTime(e) >= cutoff);
}

async function githubGetFile(env) {
  const branch = env.GITHUB_BRANCH || 'main';
  const path = env.GITHUB_FILE_PATH || 'data/entries.json';
  const url = `${GITHUB_API}/repos/${env.GITHUB_REPO}/contents/${path}?ref=${branch}`;
  const res = await fetch(url, {
    headers: { Authorization: `token ${env.GITHUB_TOKEN}`, 'User-Agent': 'control-salidas-worker', Accept: 'application/vnd.github+json' }
  });
  if (res.status === 404) return { sha: null, entries: [] };
  if (!res.ok) throw new Error(`GitHub GET falló: ${res.status}`);
  const data = await res.json();
  let entries = [];
  try { entries = JSON.parse(b64DecodeUtf8(data.content)); } catch (e) { entries = []; }
  return { sha: data.sha, entries };
}

async function githubPutFile(env, entries, sha, message) {
  const branch = env.GITHUB_BRANCH || 'main';
  const path = env.GITHUB_FILE_PATH || 'data/entries.json';
  const url = `${GITHUB_API}/repos/${env.GITHUB_REPO}/contents/${path}`;
  const body = { message, content: b64EncodeUtf8(JSON.stringify(entries, null, 2)), branch };
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

async function withRetry(env, mutateFn, message, maxAttempts = 3) {
  let attempt = 0;
  while (attempt < maxAttempts) {
    attempt++;
    const { sha, entries } = await githubGetFile(env);
    const result = mutateFn(entries);
    if (result.noop) return result.value;
    try {
      await githubPutFile(env, result.entries, sha, message);
      return result.value;
    } catch (e) {
      if (e.status === 409 || e.status === 422) continue;
      throw e;
    }
  }
  throw new Error('No se pudo guardar tras varios intentos (conflicto de escritura).');
}

// GET /api/entries -> registros activos (no borrados)
async function handleGet(request, env) {
  if (!checkAuth(request, env)) return json({ error: 'unauthorized' }, 401);
  try {
    const result = await withRetry(env, entries => {
      const cleaned = purgeExpired(entries);
      const active = cleaned.filter(e => !e.deletedAt);
      if (cleaned.length === entries.length) return { noop: true, value: active };
      return { entries: cleaned, value: active };
    }, 'Limpieza automática: registros con más de 30 días');
    return json({ entries: result });
  } catch (e) { return json({ error: e.message }, 500); }
}

// GET /api/entries/trash -> registros en papelera (aún no purgados)
async function handleGetTrash(request, env) {
  if (!checkAuth(request, env)) return json({ error: 'unauthorized' }, 401);
  try {
    const result = await withRetry(env, entries => {
      const cleaned = purgeExpired(entries);
      const trashed = cleaned.filter(e => !!e.deletedAt);
      if (cleaned.length === entries.length) return { noop: true, value: trashed };
      return { entries: cleaned, value: trashed };
    }, 'Limpieza automática: registros con más de 30 días');
    return json({ entries: result });
  } catch (e) { return json({ error: e.message }, 500); }
}

async function handlePost(request, env) {
  if (!checkAuth(request, env)) return json({ error: 'unauthorized' }, 401);
  let body;
  try { body = await request.json(); } catch (e) { return json({ error: 'JSON inválido' }, 400); }
  const code = (body.code || '').trim().toUpperCase();
  const name = (body.name || '').trim();
  const time = (body.time || '').trim();
  const obs = (body.obs || '').trim();
  if (!code || !name) return json({ error: 'Falta código o nombre' }, 400);
  const entry = {
    id: crypto.randomUUID(), code, name, time, obs,
    status: 'fuera', returnTime: null,
    createdAt: Date.now(), editedAt: null, deletedAt: null, history: []
  };
  try {
    await withRetry(env, entries => {
      const cleaned = purgeExpired(entries);
      cleaned.push(entry);
      return { entries: cleaned, value: entry };
    }, `Registrar salida: ${code} - ${name}`);
    return json({ entry });
  } catch (e) { return json({ error: e.message }, 500); }
}

// PUT /api/entries -> editar campos, guardando el valor anterior en history
async function handlePut(request, env) {
  if (!checkAuth(request, env)) return json({ error: 'unauthorized' }, 401);
  let body;
  try { body = await request.json(); } catch (e) { return json({ error: 'JSON inválido' }, 400); }
  const { id } = body;
  if (!id) return json({ error: 'Falta id' }, 400);
  try {
    const value = await withRetry(env, entries => {
      const idx = entries.findIndex(e => e.id === id);
      if (idx === -1) return { noop: true, value: null };
      const current = entries[idx];
      if (!current.history) current.history = [];

      const isMarkingReturn = body.status !== undefined && body.status !== current.status;
      const isEditingTime = body.time !== undefined && body.time !== current.time;

      // Solo guardamos historial para ediciones reales del registro (no para el
      // primer "marcar regreso", que es progreso normal, no una corrección).
      if (isEditingTime || (isMarkingReturn && current.status === 'regreso')) {
        current.history.push({
          time: current.time, obs: current.obs, status: current.status,
          returnTime: current.returnTime, changedAt: Date.now()
        });
        current.editedAt = Date.now();
      }

      if (body.time !== undefined) current.time = body.time;
      if (body.obs !== undefined) current.obs = body.obs;
      if (body.status !== undefined) current.status = body.status;
      if (body.returnTime !== undefined) current.returnTime = body.returnTime;

      return { entries, value: current };
    }, body.status === 'regreso' ? `Marcar regreso: ${id}` : `Editar registro: ${id}`);
    if (!value) return json({ error: 'Registro no encontrado' }, 404);
    return json({ entry: value });
  } catch (e) { return json({ error: e.message }, 500); }
}

// DELETE /api/entries?id=... -> mueve a la papelera (no borra para siempre)
async function handleDelete(request, env) {
  if (!checkAuth(request, env)) return json({ error: 'unauthorized' }, 401);
  const url = new URL(request.url);
  const id = url.searchParams.get('id');
  if (!id) return json({ error: 'Falta id' }, 400);
  try {
    const value = await withRetry(env, entries => {
      const idx = entries.findIndex(e => e.id === id);
      if (idx === -1) return { noop: true, value: null };
      entries[idx].deletedAt = Date.now();
      return { entries, value: true };
    }, `Mover a papelera: ${id}`);
    if (!value) return json({ error: 'Registro no encontrado' }, 404);
    return json({ ok: true });
  } catch (e) { return json({ error: e.message }, 500); }
}

// POST /api/entries/restore  body:{id} -> saca de la papelera
async function handleRestore(request, env) {
  if (!checkAuth(request, env)) return json({ error: 'unauthorized' }, 401);
  let body;
  try { body = await request.json(); } catch (e) { return json({ error: 'JSON inválido' }, 400); }
  const { id } = body;
  if (!id) return json({ error: 'Falta id' }, 400);
  try {
    const value = await withRetry(env, entries => {
      const idx = entries.findIndex(e => e.id === id);
      if (idx === -1) return { noop: true, value: null };
      entries[idx].deletedAt = null;
      return { entries, value: entries[idx] };
    }, `Restaurar de papelera: ${id}`);
    if (!value) return json({ error: 'Registro no encontrado' }, 404);
    return json({ entry: value });
  } catch (e) { return json({ error: e.message }, 500); }
}

// DELETE /api/entries/purge?id=... -> borrado permanente desde la papelera
async function handlePurge(request, env) {
  if (!checkAuth(request, env)) return json({ error: 'unauthorized' }, 401);
  const url = new URL(request.url);
  const id = url.searchParams.get('id');
  if (!id) return json({ error: 'Falta id' }, 400);
  try {
    await withRetry(env, entries => ({
      entries: entries.filter(e => e.id !== id), value: true
    }), `Eliminar para siempre: ${id}`);
    return json({ ok: true });
  } catch (e) { return json({ error: e.message }, 500); }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === '/api/entries/trash' && request.method === 'GET') {
      return handleGetTrash(request, env);
    }
    if (url.pathname === '/api/entries/restore' && request.method === 'POST') {
      return handleRestore(request, env);
    }
    if (url.pathname === '/api/entries/purge' && request.method === 'DELETE') {
      return handlePurge(request, env);
    }
    if (url.pathname === '/api/entries') {
      switch (request.method) {
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
