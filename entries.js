// functions/api/entries.js
// Usa un archivo JSON dentro del propio repo de GitHub como "base de datos".
// Requiere estos secretos configurados en el proyecto de Cloudflare Pages:
//   GITHUB_TOKEN       -> Personal Access Token con permiso sobre el repo (contents: read/write)
//   GITHUB_REPO        -> "SRALEXANDERGADR/Control-Salidas"
// Opcionales (tienen valor por defecto si no los configuras):
//   GITHUB_BRANCH      -> por defecto "main"
//   GITHUB_FILE_PATH   -> por defecto "data/entries.json"

const GITHUB_API = 'https://api.github.com';
const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
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

function cleanExpired(entries) {
  const cutoff = Date.now() - SEVEN_DAYS_MS;
  return entries.filter(e => e.createdAt >= cutoff);
}

async function githubGetFile(env) {
  const branch = env.GITHUB_BRANCH || 'main';
  const path = env.GITHUB_FILE_PATH || 'data/entries.json';
  const url = `${GITHUB_API}/repos/${env.GITHUB_REPO}/contents/${path}?ref=${branch}`;
  const res = await fetch(url, {
    headers: {
      Authorization: `token ${env.GITHUB_TOKEN}`,
      'User-Agent': 'control-salidas-worker',
      Accept: 'application/vnd.github+json'
    }
  });
  if (res.status === 404) return { sha: null, entries: [] };
  if (!res.ok) throw new Error(`GitHub GET falló: ${res.status}`);
  const data = await res.json();
  let entries = [];
  try {
    entries = JSON.parse(b64DecodeUtf8(data.content));
  } catch (e) {
    entries = [];
  }
  return { sha: data.sha, entries };
}

async function githubPutFile(env, entries, sha, message) {
  const branch = env.GITHUB_BRANCH || 'main';
  const path = env.GITHUB_FILE_PATH || 'data/entries.json';
  const url = `${GITHUB_API}/repos/${env.GITHUB_REPO}/contents/${path}`;
  const body = {
    message,
    content: b64EncodeUtf8(JSON.stringify(entries, null, 2)),
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
    const err = new Error(`GitHub PUT falló: ${res.status} ${errText}`);
    err.status = res.status;
    throw err;
  }
}

// Reintenta la operación si hay conflicto de escritura (otro commit cambió el sha mientras tanto)
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
      if (e.status === 409 || e.status === 422) continue; // reintenta con sha fresco
      throw e;
    }
  }
  throw new Error('No se pudo guardar tras varios intentos (conflicto de escritura).');
}

export async function onRequestGet(context) {
  try {
    const result = await withRetry(
      context.env,
      entries => {
        const cleaned = cleanExpired(entries);
        if (cleaned.length === entries.length) return { noop: true, value: cleaned };
        return { entries: cleaned, value: cleaned };
      },
      'Limpieza automática: registros con más de 7 días'
    );
    return json({ entries: result });
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}

export async function onRequestPost(context) {
  let body;
  try {
    body = await context.request.json();
  } catch (e) {
    return json({ error: 'JSON inválido' }, 400);
  }
  const code = (body.code || '').trim().toUpperCase();
  const name = (body.name || '').trim();
  const time = (body.time || '').trim();
  const obs = (body.obs || '').trim();
  if (!code || !name) return json({ error: 'Falta código o nombre' }, 400);

  const entry = { id: crypto.randomUUID(), code, name, time, obs, createdAt: Date.now() };

  try {
    await withRetry(
      context.env,
      entries => {
        const cleaned = cleanExpired(entries);
        cleaned.push(entry);
        return { entries: cleaned, value: entry };
      },
      `Registrar salida: ${code} - ${name}`
    );
    return json({ entry });
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}

export async function onRequestPut(context) {
  let body;
  try {
    body = await context.request.json();
  } catch (e) {
    return json({ error: 'JSON inválido' }, 400);
  }
  const { id, time } = body;
  if (!id) return json({ error: 'Falta id' }, 400);

  try {
    const value = await withRetry(
      context.env,
      entries => {
        const idx = entries.findIndex(e => e.id === id);
        if (idx === -1) return { noop: true, value: null };
        entries[idx].time = time;
        return { entries, value: entries[idx] };
      },
      `Editar hora de salida: ${id}`
    );
    if (!value) return json({ error: 'Registro no encontrado' }, 404);
    return json({ entry: value });
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}

export async function onRequestDelete(context) {
  const url = new URL(context.request.url);
  const id = url.searchParams.get('id');
  if (!id) return json({ error: 'Falta id' }, 400);

  try {
    await withRetry(
      context.env,
      entries => ({ entries: entries.filter(e => e.id !== id), value: true }),
      `Eliminar registro: ${id}`
    );
    return json({ ok: true });
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}
