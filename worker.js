/**
 * SystemSeg Core OS - Cloudflare Worker
 * Backend seguro para OAuth Google Drive persistente + pareamento por QR Code.
 *
 * Bindings obrigatórios:
 *   KV Namespace: AUTH_KV
 * Variables / Secrets:
 *   GOOGLE_CLIENT_ID
 *   GOOGLE_CLIENT_SECRET
 *   SITE_ORIGIN   (ex.: https://seuusuario.github.io)
 */

const DRIVE_SCOPE = 'https://www.googleapis.com/auth/drive.file';
const OAUTH_SCOPES = `openid email profile ${DRIVE_SCOPE}`;
const PAIR_TTL = 600;
const MAX_PDF_BYTES = 20 * 1024 * 1024;
const MONTHS_PT = ['Janeiro','Fevereiro','Março','Abril','Maio','Junho','Julho','Agosto','Setembro','Outubro','Novembro','Dezembro'];

export default {
  async fetch(request, env) {
    try {
      return await handleRequest(request, env);
    } catch (error) {
      console.error(error);
      return json({ error: friendlyError(error) }, error?.status || 500, request, env);
    }
  }
};

async function handleRequest(request, env) {
  const url = new URL(request.url);

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders(request, env) });
  }

  if (url.pathname === '/health' && request.method === 'GET') {
    return json({
      ok: true,
      service: 'SystemSeg Core OS API',
      configured: Boolean(env.AUTH_KV && env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET && env.SITE_ORIGIN)
    }, 200, request, env);
  }

  if (url.pathname === '/api/pair/start' && request.method === 'POST') {
    assertCorsOrigin(request, env);
    assertConfig(env);
    return startPair(request, env);
  }

  if (url.pathname === '/api/pair/status' && request.method === 'GET') {
    assertCorsOrigin(request, env);
    assertConfig(env);
    return pairStatus(request, env, url);
  }

  if (url.pathname === '/connect' && request.method === 'GET') {
    assertConfig(env);
    return beginGoogleOAuth(request, env, url);
  }

  if (url.pathname === '/oauth/callback' && request.method === 'GET') {
    assertConfig(env);
    return finishGoogleOAuth(request, env, url);
  }

  if (url.pathname === '/api/status' && request.method === 'GET') {
    assertCorsOrigin(request, env);
    await authenticateDevice(request, env);
    const email = await env.AUTH_KV.get('google:email');
    const refresh = await env.AUTH_KV.get('google:refresh_token');
    if (!refresh) throw httpError(401, 'A conta Google Drive não está conectada.');
    return json({ connected: true, email: email || 'Conta Google conectada' }, 200, request, env);
  }

  if (url.pathname === '/api/disconnect' && request.method === 'POST') {
    assertCorsOrigin(request, env);
    await authenticateDevice(request, env);
    return disconnectGoogle(request, env);
  }

  if (url.pathname === '/api/upload' && request.method === 'POST') {
    assertCorsOrigin(request, env);
    await authenticateDevice(request, env);
    return uploadPdf(request, env);
  }

  if (url.pathname === '/api/folders' && request.method === 'GET') {
    assertCorsOrigin(request, env);
    await authenticateDevice(request, env);
    return listOsFolders(request, env);
  }

  return json({ error: 'Rota não encontrada.' }, 404, request, env);
}

function assertConfig(env) {
  if (!env.AUTH_KV) throw new Error('Binding KV AUTH_KV não configurado.');
  if (!env.GOOGLE_CLIENT_ID) throw new Error('GOOGLE_CLIENT_ID não configurado.');
  if (!env.GOOGLE_CLIENT_SECRET) throw new Error('GOOGLE_CLIENT_SECRET não configurado.');
  if (!env.SITE_ORIGIN) throw new Error('SITE_ORIGIN não configurado.');
}

function allowedOrigins(env) {
  return String(env.SITE_ORIGIN || '')
    .split(',')
    .map(v => v.trim().replace(/\/$/, ''))
    .filter(Boolean);
}

function assertCorsOrigin(request, env) {
  const origin = request.headers.get('Origin');
  if (!origin) return;
  if (!allowedOrigins(env).includes(origin.replace(/\/$/, ''))) {
    throw httpError(403, 'Origem do site não autorizada no servidor. Confira SITE_ORIGIN no Cloudflare Worker.');
  }
}

function corsHeaders(request, env) {
  const origin = request.headers.get('Origin');
  const allowed = allowedOrigins(env);
  const headers = {
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type, X-OS-File-Name, X-OS-Date, X-OS-Client',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
  if (origin && allowed.includes(origin.replace(/\/$/, ''))) headers['Access-Control-Allow-Origin'] = origin;
  return headers;
}

function json(data, status, request, env) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...corsHeaders(request, env) }
  });
}

function httpError(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

function friendlyError(error) {
  if (!error) return 'Erro interno.';
  if (error.message) return error.message;
  return String(error);
}

function bytesToBase64Url(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function randomToken(bytes = 24) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return bytesToBase64Url(a);
}

async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function safeDecodeHeader(value) {
  if (!value) return '';
  try { return decodeURIComponent(value); } catch { return value; }
}

function sanitizeFileName(name) {
  return String(name || 'O.S Sem nome.pdf')
    .replace(/[\\/:*?"<>|]+/g, '-')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 180);
}

function escapeDriveQuery(s) {
  return String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

async function startPair(request, env) {
  const pairId = randomToken(12);
  const pairSecret = randomToken(18);
  const displayCode = pairId.replace(/[^a-z0-9]/gi, '').slice(0, 6).toUpperCase();
  const record = {
    status: 'pending',
    secretHash: await sha256Hex(pairSecret),
    createdAt: Date.now()
  };
  await env.AUTH_KV.put(`pair:${pairId}`, JSON.stringify(record), { expirationTtl: PAIR_TTL });
  const workerOrigin = new URL(request.url).origin;
  const connectUrl = `${workerOrigin}/connect?pair=${encodeURIComponent(pairId)}&code=${encodeURIComponent(pairSecret)}`;
  return json({ pair_id: pairId, pair_secret: pairSecret, display_code: displayCode, connect_url: connectUrl, expires_in: PAIR_TTL }, 200, request, env);
}

async function loadAndVerifyPair(env, pairId, secret) {
  if (!pairId || !secret) throw httpError(400, 'Pareamento incompleto. Gere um novo QR Code.');
  const raw = await env.AUTH_KV.get(`pair:${pairId}`);
  if (!raw) throw httpError(404, 'QR Code expirado ou não encontrado. Gere outro.');
  let pair;
  try { pair = JSON.parse(raw); } catch { throw httpError(400, 'Pareamento inválido.'); }
  const hash = await sha256Hex(secret);
  if (hash !== pair.secretHash) throw httpError(403, 'Código de pareamento inválido.');
  return pair;
}

async function pairStatus(request, env, url) {
  const pairId = url.searchParams.get('pair');
  const secret = url.searchParams.get('code');
  const pair = await loadAndVerifyPair(env, pairId, secret);
  if (pair.status !== 'approved') return json({ status: 'pending' }, 200, request, env);

  const response = {
    status: 'approved',
    device_token: pair.deviceToken,
    email: pair.email || ''
  };
  await env.AUTH_KV.delete(`pair:${pairId}`);
  return json(response, 200, request, env);
}

async function beginGoogleOAuth(request, env, url) {
  const pairId = url.searchParams.get('pair');
  const secret = url.searchParams.get('code');
  await loadAndVerifyPair(env, pairId, secret);

  const state = randomToken(24);
  await env.AUTH_KV.put(`oauthstate:${state}`, JSON.stringify({ pairId }), { expirationTtl: PAIR_TTL });

  const redirectUri = `${url.origin}/oauth/callback`;
  const p = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: OAUTH_SCOPES,
    access_type: 'offline',
    prompt: 'consent',
    include_granted_scopes: 'true',
    state
  });

  return Response.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${p.toString()}`, 302);
}

async function finishGoogleOAuth(request, env, url) {
  const oauthError = url.searchParams.get('error');
  if (oauthError) return htmlResult(false, `Autorização cancelada: ${oauthError}`);

  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  if (!code || !state) return htmlResult(false, 'Resposta do Google incompleta. Gere um novo QR Code.');

  const stateRaw = await env.AUTH_KV.get(`oauthstate:${state}`);
  if (!stateRaw) return htmlResult(false, 'Autorização expirada. Gere um novo QR Code.');
  await env.AUTH_KV.delete(`oauthstate:${state}`);
  const { pairId } = JSON.parse(stateRaw);

  const pairRaw = await env.AUTH_KV.get(`pair:${pairId}`);
  if (!pairRaw) return htmlResult(false, 'Pareamento expirado. Gere um novo QR Code.');
  const pair = JSON.parse(pairRaw);

  const redirectUri = `${url.origin}/oauth/callback`;
  const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code'
    })
  });
  const tokenData = await tokenResponse.json();
  if (!tokenResponse.ok) return htmlResult(false, `Falha ao receber token do Google: ${tokenData.error_description || tokenData.error || tokenResponse.status}`);
  if (!tokenData.refresh_token) return htmlResult(false, 'O Google não forneceu um token de atualização. Tente novamente e confirme a permissão solicitada.');

  const userInfoResponse = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
    headers: { 'Authorization': `Bearer ${tokenData.access_token}` }
  });
  const userInfo = await userInfoResponse.json();
  if (!userInfoResponse.ok || !userInfo.email) return htmlResult(false, 'Não foi possível identificar a conta Google autorizada.');

  const previousEmail = await env.AUTH_KV.get('google:email');
  const previousRefresh = await env.AUTH_KV.get('google:refresh_token');
  if (previousEmail && previousEmail !== userInfo.email) {
    await invalidateAllDevices(env);
    if (previousRefresh) revokeGoogleToken(previousRefresh).catch(() => {});
  }

  await env.AUTH_KV.put('google:refresh_token', tokenData.refresh_token);
  await env.AUTH_KV.put('google:email', userInfo.email);

  const deviceToken = randomToken(32);
  const deviceHash = await sha256Hex(deviceToken);
  await env.AUTH_KV.put(`device:${deviceHash}`, JSON.stringify({ email: userInfo.email, createdAt: Date.now() }));

  pair.status = 'approved';
  pair.deviceToken = deviceToken;
  pair.email = userInfo.email;
  pair.approvedAt = Date.now();
  await env.AUTH_KV.put(`pair:${pairId}`, JSON.stringify(pair), { expirationTtl: PAIR_TTL });

  return htmlResult(true, `Google Drive conectado com sucesso à conta ${userInfo.email}. Você já pode voltar ao SystemSeg Core OS.`);
}

function htmlResult(ok, message) {
  const safe = escapeHtml(message);
  return new Response(`<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SystemSeg Core OS</title><style>body{margin:0;font-family:system-ui;background:#07141f;color:#ecf5fb;min-height:100vh;display:grid;place-items:center;padding:20px}.box{max-width:620px;background:#0d1d2a;border:1px solid #24445a;border-radius:20px;padding:28px;text-align:center;box-shadow:0 20px 50px rgba(0,0,0,.35)}h1{color:${ok ? '#62d993' : '#ff8e8e'}}p{line-height:1.55;color:#cbdbe6}</style></head><body><div class="box"><h1>${ok ? 'Conexão concluída' : 'Não foi possível conectar'}</h1><p>${safe}</p><p>${ok ? 'Você pode fechar esta página.' : 'Volte ao sistema e tente novamente.'}</p></div><script>${ok ? 'setTimeout(()=>{try{window.close()}catch(e){}},1800);' : ''}</script></body></html>`, {
    status: ok ? 200 : 400,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }
  });
}

function escapeHtml(s) {
  return String(s).replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
}

async function authenticateDevice(request, env) {
  assertConfig(env);
  const auth = request.headers.get('Authorization') || '';
  if (!auth.startsWith('Bearer ')) throw httpError(401, 'Dispositivo não autorizado. Conecte pelo QR Code.');
  const token = auth.slice(7).trim();
  if (!token) throw httpError(401, 'Dispositivo não autorizado.');
  const hash = await sha256Hex(token);
  const device = await env.AUTH_KV.get(`device:${hash}`);
  if (!device) throw httpError(401, 'A autorização deste dispositivo não é mais válida.');
  const refresh = await env.AUTH_KV.get('google:refresh_token');
  if (!refresh) throw httpError(401, 'A conta Google Drive foi desconectada.');
  return JSON.parse(device);
}

async function invalidateAllDevices(env) {
  let cursor;
  do {
    const list = await env.AUTH_KV.list({ prefix: 'device:', cursor });
    await Promise.all(list.keys.map(k => env.AUTH_KV.delete(k.name)));
    cursor = list.list_complete ? undefined : list.cursor;
  } while (cursor);
}

async function disconnectGoogle(request, env) {
  const refresh = await env.AUTH_KV.get('google:refresh_token');
  if (refresh) await revokeGoogleToken(refresh).catch(() => {});
  await env.AUTH_KV.delete('google:refresh_token');
  await env.AUTH_KV.delete('google:email');
  await invalidateAllDevices(env);
  return json({ disconnected: true }, 200, request, env);
}

async function revokeGoogleToken(token) {
  await fetch('https://oauth2.googleapis.com/revoke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ token })
  });
}

async function getGoogleAccessToken(env) {
  const refreshToken = await env.AUTH_KV.get('google:refresh_token');
  if (!refreshToken) throw httpError(401, 'Google Drive não conectado.');
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      refresh_token: refreshToken,
      grant_type: 'refresh_token'
    })
  });
  const data = await response.json();
  if (!response.ok || !data.access_token) {
    if (data.error === 'invalid_grant') throw httpError(401, 'A autorização do Google expirou ou foi revogada. Conecte novamente pelo QR Code.');
    throw new Error(`Falha ao renovar acesso do Google: ${data.error_description || data.error || response.status}`);
  }
  return data.access_token;
}

async function driveJson(accessToken, url, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set('Authorization', `Bearer ${accessToken}`);
  const response = await fetch(url, { ...options, headers });
  const text = await response.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!response.ok) throw new Error(data?.error?.message || `Erro Google Drive (${response.status}).`);
  return data;
}

async function listDriveFiles(accessToken, query, fields = 'files(id,name,mimeType,modifiedTime,size,webViewLink,parents)', pageSize = 100) {
  const u = new URL('https://www.googleapis.com/drive/v3/files');
  u.searchParams.set('q', query);
  u.searchParams.set('fields', fields);
  u.searchParams.set('pageSize', String(pageSize));
  u.searchParams.set('orderBy', 'name');
  const data = await driveJson(accessToken, u.toString());
  return data.files || [];
}

async function getOrCreateMonthFolder(accessToken, dateIso) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(dateIso || '');
  if (!m) throw httpError(400, 'Data da O.S. inválida.');
  const year = Number(m[1]);
  const month = Number(m[2]);
  if (month < 1 || month > 12) throw httpError(400, 'Mês da O.S. inválido.');
  const folderName = `O.S ${MONTHS_PT[month - 1]} ${year}`;
  const query = `name = '${escapeDriveQuery(folderName)}' and mimeType = 'application/vnd.google-apps.folder' and trashed = false`;
  const found = await listDriveFiles(accessToken, query, 'files(id,name,webViewLink)');
  if (found[0]) return found[0];
  return driveJson(accessToken, 'https://www.googleapis.com/drive/v3/files?fields=id,name,webViewLink', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: folderName, mimeType: 'application/vnd.google-apps.folder' })
  });
}

async function uploadPdf(request, env) {
  const length = Number(request.headers.get('Content-Length') || 0);
  if (length && length > MAX_PDF_BYTES) throw httpError(413, 'PDF muito grande. Limite deste sistema: 20 MB.');
  if (!String(request.headers.get('Content-Type') || '').toLowerCase().includes('application/pdf')) throw httpError(415, 'Envie um arquivo PDF.');

  const fileName = sanitizeFileName(safeDecodeHeader(request.headers.get('X-OS-File-Name')));
  const dateIso = String(request.headers.get('X-OS-Date') || '').trim();
  const pdfBytes = await request.arrayBuffer();
  if (!pdfBytes.byteLength || pdfBytes.byteLength > MAX_PDF_BYTES) throw httpError(413, 'PDF vazio ou acima de 20 MB.');

  const accessToken = await getGoogleAccessToken(env);
  const folder = await getOrCreateMonthFolder(accessToken, dateIso);
  const query = `name = '${escapeDriveQuery(fileName)}' and '${folder.id}' in parents and trashed = false`;
  const existing = await listDriveFiles(accessToken, query, 'files(id,name,webViewLink)');

  let result;
  if (existing[0]) {
    const response = await fetch(`https://www.googleapis.com/upload/drive/v3/files/${encodeURIComponent(existing[0].id)}?uploadType=media&fields=id,name,webViewLink`, {
      method: 'PATCH',
      headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/pdf' },
      body: pdfBytes
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data?.error?.message || `Falha ao atualizar PDF (${response.status}).`);
    result = data;
  } else {
    const boundary = `sysseg_${crypto.randomUUID().replace(/-/g, '')}`;
    const metadata = JSON.stringify({ name: fileName, mimeType: 'application/pdf', parents: [folder.id] });
    const body = new Blob([
      `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${metadata}\r\n`,
      `--${boundary}\r\nContent-Type: application/pdf\r\n\r\n`,
      pdfBytes,
      `\r\n--${boundary}--`
    ], { type: `multipart/related; boundary=${boundary}` });
    const response = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name,webViewLink', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': `multipart/related; boundary=${boundary}` },
      body
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data?.error?.message || `Falha ao salvar PDF (${response.status}).`);
    result = data;
  }

  return json({ saved: true, folder: folder.name, file: result }, 200, request, env);
}

async function listOsFolders(request, env) {
  const accessToken = await getGoogleAccessToken(env);
  const folders = await listDriveFiles(
    accessToken,
    "mimeType = 'application/vnd.google-apps.folder' and trashed = false and name contains 'O.S '",
    'files(id,name,modifiedTime,webViewLink)',
    100
  );
  const pdfs = await listDriveFiles(
    accessToken,
    "mimeType = 'application/pdf' and trashed = false",
    'files(id,name,modifiedTime,size,webViewLink,parents)',
    1000
  );

  const folderMap = new Map(folders.map(f => [f.id, { ...f, files: [] }]));
  for (const file of pdfs) {
    for (const parent of file.parents || []) {
      const folder = folderMap.get(parent);
      if (folder) folder.files.push(file);
    }
  }

  const result = [...folderMap.values()]
    .map(f => ({ ...f, files: f.files.sort((a,b) => String(b.modifiedTime || '').localeCompare(String(a.modifiedTime || ''))) }))
    .sort((a,b) => b.name.localeCompare(a.name, 'pt-BR'));

  return json({ folders: result }, 200, request, env);
}
