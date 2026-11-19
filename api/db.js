import crypto from 'node:crypto';

export const config = {
  api: {
    bodyParser: {
      sizeLimit: '6mb'
    }
  }
};

function signToken(payloadObj, secret) {
  const payloadB64 = Buffer.from(JSON.stringify(payloadObj), 'utf-8').toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(payloadB64).digest('base64url');
  return `${payloadB64}.${sig}`;
}

function verifyToken(token, secret) {
  if (!token || typeof token !== 'string') return null;
  // Compatibilidade legada caso o token seja exatamente a senha mestra
  if (token === secret) {
    return { id: 'admin', username: 'admin', name: 'Administrador', isAdmin: true };
  }
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payloadB64, sig] = parts;
  const expectedSig = crypto.createHmac('sha256', secret).update(payloadB64).digest('base64url');
  if (sig.length !== expectedSig.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig))) return null;
  try {
    const data = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf-8'));
    if (data.exp && Date.now() > data.exp) return null;
    return data;
  } catch (_) {
    return null;
  }
}

// -----------------------------------------------------------
// PERÍODO DE ACESSO (calculado SEMPRE no servidor, com o relógio do servidor)
// -----------------------------------------------------------
const DAY_MS = 24 * 60 * 60 * 1000;
const ACCESS_PERIODS = {
  '7d': { days: 7 },
  '30d': { days: 30 },
  '3m': { months: 3 },
  '6m': { months: 6 },
  '1y': { months: 12 },
  lifetime: {}
};

function addPeriod(baseMs, key) {
  const def = ACCESS_PERIODS[key];
  const d = new Date(baseMs);
  if (def.days) {
    d.setUTCDate(d.getUTCDate() + def.days);
  } else if (def.months) {
    const day = d.getUTCDate();
    d.setUTCDate(1);
    d.setUTCMonth(d.getUTCMonth() + def.months);
    const last = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 0)).getUTCDate();
    d.setUTCDate(Math.min(day, last));
  }
  return d.getTime();
}

// Usuários sem campos de acesso (criados na v1.00) são tratados como vitalícios.
// Dados de acesso corrompidos NUNCA liberam o acesso (falha fechada).
function getAccessInfo(user, now = Date.now()) {
  const raw = user && user.accessExpiresAt;
  if (!raw) {
    const corrupted = user && user.accessPeriod && user.accessPeriod !== 'lifetime';
    if (corrupted) return { lifetime: false, expired: true, expiresAt: null, remainingDays: 0 };
    return { lifetime: true, expired: false, expiresAt: null, remainingDays: null };
  }
  const exp = Date.parse(raw);
  if (Number.isNaN(exp)) return { lifetime: false, expired: true, expiresAt: null, remainingDays: 0 };
  const remainingMs = exp - now;
  return {
    lifetime: false,
    expired: remainingMs <= 0,
    expiresAt: new Date(exp).toISOString(),
    remainingDays: remainingMs <= 0 ? 0 : Math.ceil(remainingMs / DAY_MS)
  };
}

function formatDateBR(iso) {
  const d = new Date(iso);
  return d.toLocaleDateString('pt-BR', { timeZone: 'America/Sao_Paulo' });
}

// Cache curto (15 s) só da lista de usuários, para validar o acesso em toda requisição
// sem consultar o GitHub a cada miniatura/anexo.
let accessCache = { at: 0, users: null };

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  const APP_PASSWORD = process.env.APP_PASSWORD;
  const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
  const GITHUB_REPO = process.env.GITHUB_REPO; // Ex: "ronando13/djc-travel-planner-data"
  const GITHUB_BRANCH = process.env.GITHUB_BRANCH || 'main';
  const DB_FILE_PATH = process.env.DB_FILE_PATH || 'djc_travel_planner_bd.json';

  if (!APP_PASSWORD || !GITHUB_TOKEN || !GITHUB_REPO) {
    console.error('Variáveis de ambiente ausentes na Vercel (APP_PASSWORD, GITHUB_TOKEN, GITHUB_REPO).');
    return res.status(500).json({ error: 'Banco de dados em nuvem não configurado. Avise o administrador.' });
  }

  const ghHeaders = {
    Authorization: `Bearer ${GITHUB_TOKEN}`,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'Kisuco-Planner-Vercel'
  };

  const apiUrl = `https://api.github.com/repos/${GITHUB_REPO}/contents/${DB_FILE_PATH}`;
  const action = String(req.query?.action || '');

  async function readDbFromGithub() {
    const ghRes = await fetch(`${apiUrl}?ref=${encodeURIComponent(GITHUB_BRANCH)}`, {
      method: 'GET',
      headers: ghHeaders
    });
    if (ghRes.status === 404) return { notFound: true };
    if (!ghRes.ok) {
      const errText = await ghRes.text();
      throw new Error(`GitHub GET error (${ghRes.status}): ${errText}`);
    }
    const fileData = await ghRes.json();
    const contentStr = Buffer.from(fileData.content || '', 'base64').toString('utf-8');
    return { sha: fileData.sha, data: JSON.parse(contentStr) };
  }

  async function writeDbToGithub(payload, currentSha) {
    const encodedContent = Buffer.from(JSON.stringify(payload, null, 2), 'utf-8').toString('base64');
    const putBody = {
      message: `chore(db): atualiza ${DB_FILE_PATH} via Kisuco Planner`,
      content: encodedContent,
      branch: GITHUB_BRANCH
    };
    if (currentSha) putBody.sha = currentSha;

    const putRes = await fetch(apiUrl, {
      method: 'PUT',
      headers: { ...ghHeaders, 'Content-Type': 'application/json' },
      body: JSON.stringify(putBody)
    });
    if (!putRes.ok) {
      const errText = await putRes.text();
      throw new Error(`GitHub PUT error (${putRes.status}): ${errText}`);
    }
    return await putRes.json();
  }

  // -----------------------------------------------------------
  // 0. ENDPOINT DE LOGIN (ADMIN OU USUÁRIO CADASTRADO)
  // -----------------------------------------------------------
  if (action === 'login' && req.method === 'POST') {
    try {
      const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
      const username = String(body?.username || '').trim().toLowerCase();
      const password = String(body?.password || '').trim();

      if (!username || !password) {
        return res.status(400).json({ error: 'Informe usuário e senha.' });
      }

      // 1) Verifica se é o Administrador Mestre
      if (username === 'admin') {
        if (password !== APP_PASSWORD) {
          return res.status(401).json({ error: 'Senha do administrador incorreta.' });
        }
        const user = { id: 'admin', username: 'admin', name: 'Administrador', isAdmin: true };
        const token = signToken({ ...user, exp: Date.now() + 30 * 24 * 60 * 60 * 1000 }, APP_PASSWORD);
        return res.status(200).json({ ok: true, token, user });
      }

      // 2) Busca o usuário no djc_travel_planner_bd.json do GitHub
      const dbResult = await readDbFromGithub();
      if (dbResult.notFound || !dbResult.data || !Array.isArray(dbResult.data.users)) {
        return res.status(401).json({ error: 'Usuário não encontrado.' });
      }

      const foundUser = dbResult.data.users.find(
        u => String(u.username || '').trim().toLowerCase() === username
      );

      if (!foundUser || String(foundUser.password || '') !== password) {
        return res.status(401).json({ error: 'Usuário ou senha incorretos.' });
      }

      if (foundUser.active === false) {
        return res.status(403).json({ error: 'Este usuário está bloqueado pelo administrador.' });
      }

      const access = getAccessInfo(foundUser);
      if (access.expired) {
        return res.status(403).json({
          code: 'ACCESS_EXPIRED',
          error: access.expiresAt
            ? `Seu período de acesso expirou em ${formatDateBR(access.expiresAt)}. Fale com o administrador para renovar.`
            : 'Seu período de acesso expirou. Fale com o administrador para renovar.'
        });
      }

      const userPayload = {
        id: foundUser.id,
        username: foundUser.username,
        name: foundUser.name || foundUser.username,
        isAdmin: false
      };
      const tokenExp = access.expiresAt
        ? Math.min(Date.now() + 30 * DAY_MS, Date.parse(access.expiresAt))
        : Date.now() + 30 * DAY_MS;
      const token = signToken({ ...userPayload, exp: tokenExp }, APP_PASSWORD);
      return res.status(200).json({ ok: true, token, user: userPayload, access });
    } catch (err) {
      console.error('Erro no login:', err);
      return res.status(500).json({ error: 'Erro ao validar credenciais.' });
    }
  }

  // -----------------------------------------------------------
  // VALIDAÇÃO DO TOKEN PARA TODAS AS DEMAIS ROTAS
  // -----------------------------------------------------------
  const authHeader = req.headers.authorization || '';
  const rawToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
  const sessionUser = verifyToken(rawToken, APP_PASSWORD);

  if (!sessionUser) {
    return res.status(401).json({ error: 'Não autorizado. Faça login novamente.' });
  }

  // -----------------------------------------------------------
  // CONTROLE DE ACESSO DO USUÁRIO COMUM (a cada requisição, no servidor):
  // usuário precisa existir, estar ativo e com o período de acesso vigente.
  // -----------------------------------------------------------
  let sessionAccess = { lifetime: true, expired: false, expiresAt: null, remainingDays: null };
  if (!sessionUser.isAdmin) {
    try {
      if (!accessCache.users || Date.now() - accessCache.at > 15000) {
        const r = await readDbFromGithub();
        accessCache = { at: Date.now(), users: r.notFound ? [] : ((r.data && r.data.users) || []) };
      }
    } catch (err) {
      console.error('Falha ao validar acesso:', err);
      return res.status(503).json({ error: 'Não foi possível validar seu acesso agora. Tente novamente.' });
    }
    const rec = (accessCache.users || []).find(u => u.id === sessionUser.id);
    if (!rec) return res.status(403).json({ code: 'USER_NOT_FOUND', error: 'Usuário não encontrado ou removido.' });
    if (rec.active === false) return res.status(403).json({ code: 'USER_BLOCKED', error: 'Este usuário está bloqueado pelo administrador.' });
    sessionAccess = getAccessInfo(rec);
    if (sessionAccess.expired) {
      return res.status(403).json({
        code: 'ACCESS_EXPIRED',
        error: sessionAccess.expiresAt
          ? `Seu período de acesso expirou em ${formatDateBR(sessionAccess.expiresAt)}. Fale com o administrador para renovar.`
          : 'Seu período de acesso expirou. Fale com o administrador para renovar.'
      });
    }
  }

  if (action === 'session' && req.method === 'GET') {
    return res.status(200).json({
      ok: true,
      user: { id: sessionUser.id, username: sessionUser.username, name: sessionUser.name, isAdmin: Boolean(sessionUser.isAdmin) },
      access: sessionAccess
    });
  }

  // -----------------------------------------------------------
  // 0.5 ALTERAR PRÓPRIA SENHA (USUÁRIO COMUM)
  // -----------------------------------------------------------
  if (action === 'change-password' && req.method === 'POST') {
    try {
      if (sessionUser.isAdmin) {
        return res.status(400).json({ error: 'A senha do administrador deve ser alterada na Vercel (APP_PASSWORD).' });
      }

      const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
      const currentPassword = String(body?.currentPassword || '').trim();
      const newPassword = String(body?.newPassword || '').trim();

      if (!currentPassword || !newPassword || newPassword.length < 4) {
        return res.status(400).json({ error: 'Informe a senha atual e uma nova senha com pelo menos 4 caracteres.' });
      }

      const dbResult = await readDbFromGithub();
      if (dbResult.notFound || !dbResult.data || !Array.isArray(dbResult.data.users)) {
        return res.status(404).json({ error: 'Banco de usuários não encontrado.' });
      }

      const idx = dbResult.data.users.findIndex(u => u.id === sessionUser.id);
      if (idx === -1) {
        return res.status(404).json({ error: 'Usuário não encontrado.' });
      }

      const userRecord = dbResult.data.users[idx];
      if (String(userRecord.password || '') !== currentPassword) {
        return res.status(401).json({ error: 'Senha atual incorreta.' });
      }

      // Atualiza a senha no array users do djc_travel_planner_bd.json (permanece visível para o admin)
      dbResult.data.users[idx] = {
        ...userRecord,
        password: newPassword,
        passwordUpdatedAt: new Date().toISOString()
      };

      await writeDbToGithub(dbResult.data, dbResult.sha);
      return res.status(200).json({ ok: true });
    } catch (err) {
      console.error('Erro ao alterar senha do usuário:', err);
      return res.status(500).json({ error: 'Erro interno ao salvar nova senha.' });
    }
  }

  function sanitizeAttachmentPath(rawPath) {
    const clean = String(rawPath || '').replace(/^\/+/, '').trim();
    if (!clean.startsWith('anexos/') || clean.includes('..')) return null;
    return clean;
  }

  try {
    // -----------------------------------------------------------
    // 0.8 DEFINIR / RENOVAR PERÍODO DE ACESSO (SOMENTE ADMIN)
    // Renovação soma ao tempo restante; "replace" recomeça a contar de hoje.
    // -----------------------------------------------------------
    if (action === 'set-access' && req.method === 'POST') {
      if (!sessionUser.isAdmin) return res.status(403).json({ error: 'Apenas o administrador pode alterar períodos de acesso.' });
      const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
      const userId = String(body?.userId || '');
      const period = String(body?.period || '');
      const replace = body?.replace === true;
      if (!Object.prototype.hasOwnProperty.call(ACCESS_PERIODS, period)) {
        return res.status(400).json({ error: 'Período inválido.' });
      }

      const dbResult = await readDbFromGithub();
      if (dbResult.notFound || !Array.isArray(dbResult.data?.users)) {
        return res.status(404).json({ error: 'Banco de usuários não encontrado.' });
      }
      const idx = dbResult.data.users.findIndex(u => u.id === userId);
      if (idx === -1) return res.status(404).json({ error: 'Usuário não encontrado.' });

      const now = Date.now();
      const rec = dbResult.data.users[idx];
      const cur = getAccessInfo(rec, now);
      let expiresAt = null;
      if (period !== 'lifetime') {
        const base = (replace || cur.lifetime) ? now : Math.max(now, Date.parse(cur.expiresAt));
        expiresAt = new Date(addPeriod(base, period)).toISOString();
      }
      dbResult.data.users[idx] = {
        ...rec,
        accessPeriod: period,
        accessExpiresAt: expiresAt,
        accessUpdatedAt: new Date(now).toISOString()
      };
      await writeDbToGithub(dbResult.data, dbResult.sha);
      accessCache.at = 0;
      return res.status(200).json({
        ok: true,
        user: {
          id: userId,
          accessPeriod: period,
          accessExpiresAt: expiresAt,
          accessUpdatedAt: dbResult.data.users[idx].accessUpdatedAt
        },
        access: getAccessInfo(dbResult.data.users[idx], now)
      });
    }

    // -----------------------------------------------------------
    // 1. BAIXAR ANEXO BINÁRIO DA PASTA anexos/ NO GITHUB
    // -----------------------------------------------------------
    if (action === 'get-file' && req.method === 'GET') {
      const filePath = sanitizeAttachmentPath(req.query?.filePath);
      if (!filePath) return res.status(400).json({ error: 'Caminho de anexo inválido.' });

      const mime = String(req.query?.mime || 'application/octet-stream');
      const fileApiUrl = `https://api.github.com/repos/${GITHUB_REPO}/contents/${filePath}?ref=${encodeURIComponent(GITHUB_BRANCH)}`;

      const ghRes = await fetch(fileApiUrl, {
        method: 'GET',
        headers: { ...ghHeaders, Accept: 'application/vnd.github.raw+json' }
      });

      if (!ghRes.ok) {
        return res.status(ghRes.status).json({ error: 'Anexo não encontrado no banco de dados em nuvem.' });
      }

      const arrayBuf = await ghRes.arrayBuffer();
      const buffer = Buffer.from(arrayBuf);
      res.setHeader('Content-Type', mime);
      res.setHeader('Cache-Control', 'private, max-age=3600');
      return res.status(200).send(buffer);
    }

    // -----------------------------------------------------------
    // 2. ENVIAR ANEXO BINÁRIO PARA A PASTA anexos/ NO GITHUB
    // -----------------------------------------------------------
    if (action === 'upload-file' && req.method === 'POST') {
      const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
      const filePath = sanitizeAttachmentPath(body?.filePath);
      const base64 = String(body?.base64 || '');

      if (!filePath || !base64) {
        return res.status(400).json({ error: 'Dados de upload inválidos.' });
      }

      const fileApiUrl = `https://api.github.com/repos/${GITHUB_REPO}/contents/${filePath}`;

      let currentSha = undefined;
      const checkRes = await fetch(`${fileApiUrl}?ref=${encodeURIComponent(GITHUB_BRANCH)}`, {
        method: 'GET',
        headers: ghHeaders
      });
      if (checkRes.ok) {
        const existing = await checkRes.json();
        currentSha = existing.sha;
      }

      const putBody = {
        message: `chore(anexos): salva ${filePath} por ${sessionUser.username}`,
        content: base64,
        branch: GITHUB_BRANCH
      };
      if (currentSha) putBody.sha = currentSha;

      const putRes = await fetch(fileApiUrl, {
        method: 'PUT',
        headers: { ...ghHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify(putBody)
      });

      if (!putRes.ok) {
        const errText = await putRes.text();
        console.error('Erro ao salvar anexo:', errText);
        return res.status(putRes.status).json({ error: 'Erro ao salvar anexo no banco de dados em nuvem.' });
      }

      return res.status(200).json({ ok: true, filePath });
    }

    // -----------------------------------------------------------
    // 3. EXCLUIR ANEXO DA PASTA anexos/ NO GITHUB
    // -----------------------------------------------------------
    if (action === 'delete-file' && (req.method === 'DELETE' || req.method === 'POST')) {
      const filePath = sanitizeAttachmentPath(req.query?.filePath || req.body?.filePath);
      if (!filePath) return res.status(400).json({ error: 'Caminho de anexo inválido.' });

      const fileApiUrl = `https://api.github.com/repos/${GITHUB_REPO}/contents/${filePath}`;
      const checkRes = await fetch(`${fileApiUrl}?ref=${encodeURIComponent(GITHUB_BRANCH)}`, {
        method: 'GET',
        headers: ghHeaders
      });

      if (checkRes.status === 404) {
        return res.status(200).json({ ok: true, alreadyDeleted: true });
      }
      if (!checkRes.ok) {
        return res.status(checkRes.status).json({ error: 'Erro ao localizar anexo para exclusão.' });
      }

      const existing = await checkRes.json();
      const delRes = await fetch(fileApiUrl, {
        method: 'DELETE',
        headers: { ...ghHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: `chore(anexos): remove ${filePath} por ${sessionUser.username}`,
          sha: existing.sha,
          branch: GITHUB_BRANCH
        })
      });

      if (!delRes.ok) {
        return res.status(delRes.status).json({ error: 'Erro ao excluir anexo no banco de dados em nuvem.' });
      }

      return res.status(200).json({ ok: true });
    }

    // -----------------------------------------------------------
    // 4. LER BANCO (FILTRA SENHAS DE OUTROS USUÁRIOS SE NÃO FOR ADMIN)
    // -----------------------------------------------------------
    if (req.method === 'GET') {
      const dbResult = await readDbFromGithub();
      if (dbResult.notFound) {
        return res.status(200).json({ empty: true });
      }

      const jsonData = dbResult.data;

      // Segurança: usuários comuns não recebem as senhas de outras famílias
      if (!sessionUser.isAdmin && Array.isArray(jsonData.users)) {
        const me = sessionUser.id;
        const meRec = jsonData.users.find(u => u.id === me) || {};
        const allowed = Array.isArray(meRec.shareWith) ? meRec.shareWith : [];
        const trips = Array.isArray(jsonData.trips) ? jsonData.trips : [];
        const visible = new Set([me, ...allowed]);
        trips.forEach(t => {
          if (Array.isArray(t.sharedWith) && t.sharedWith.includes(me)) visible.add(t.ownerId || 'admin');
          if ((t.ownerId || 'admin') === me && Array.isArray(t.sharedWith)) t.sharedWith.forEach(id => visible.add(id));
        });
        jsonData._shareableUserIds = allowed;
        jsonData.users = jsonData.users.filter(u => visible.has(u.id)).map(u => ({
          id: u.id,
          name: u.name,
          username: u.username,
          active: u.active !== false
        }));
      }

      return res.status(200).json(jsonData);
    }

    // -----------------------------------------------------------
    // 5. GRAVAR BANCO (PRESERVA LISTA DE USUÁRIOS/SENHAS SE NÃO FOR ADMIN)
    // -----------------------------------------------------------
    if (req.method === 'POST' || req.method === 'PUT') {
      const incoming = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
      if (!incoming || typeof incoming !== 'object') {
        return res.status(400).json({ error: 'Payload JSON inválido.' });
      }

      const currentDb = await readDbFromGithub();
      const currentSha = currentDb.notFound ? undefined : currentDb.sha;
      const existingData = currentDb.notFound ? {} : (currentDb.data || {});

      let finalPayload = { ...incoming };
      delete finalPayload._shareableUserIds;

      const PASSEIOS_MAX = 10;
      const countP = t => (Array.isArray(t && t.attachments) ? t.attachments : []).filter(a => a && a.category === 'passeios').length;
      const exTripsAll = Array.isArray(existingData.trips) ? existingData.trips : [];
      const exById = new Map(exTripsAll.map(t => [t.id, t]));
      for (const t of (Array.isArray(incoming.trips) ? incoming.trips : [])) {
        const c = countP(t);
        if (c > PASSEIOS_MAX && c > countP(exById.get(t.id))) {
          return res.status(400).json({ error: `Limite de ${PASSEIOS_MAX} fotos de passeios por viagem.` });
        }
      }

      if (!sessionUser.isAdmin) {
        // Usuário comum não pode alterar a tabela de usuários/senhas nem viagens a que não tem acesso
        finalPayload.users = Array.isArray(existingData.users) ? existingData.users : [];

        // Garante que viagens privadas de outros usuários existentes no servidor não sejam apagadas
        const existingTrips = Array.isArray(existingData.trips) ? existingData.trips : [];
        const myRec = (existingData.users || []).find(u => u.id === sessionUser.id) || {};
        const allowedShare = new Set(Array.isArray(myRec.shareWith) ? myRec.shareWith : []);
        const incomingTrips = (Array.isArray(incoming.trips) ? incoming.trips : []).map(t => {
          const ex = exById.get(t.id);
          const incShared = Array.isArray(t.sharedWith) ? t.sharedWith : [];
          if (!ex) return { ...t, ownerId: sessionUser.id, sharedWith: incShared.filter(id => allowedShare.has(id)) };
          const ownerId = ex.ownerId || 'admin';
          const exShared = Array.isArray(ex.sharedWith) ? ex.sharedWith : [];
          if (ownerId !== sessionUser.id) return { ...t, ownerId, sharedWith: exShared };
          return { ...t, ownerId, sharedWith: incShared.filter(id => allowedShare.has(id) || exShared.includes(id)) };
        });
        const incomingIds = new Set(incomingTrips.map(t => t.id));

        const otherPrivateTrips = existingTrips.filter(t => {
          const isOwner = t.ownerId === sessionUser.id;
          const isShared = Array.isArray(t.sharedWith) && t.sharedWith.includes(sessionUser.id);
          return !isOwner && !isShared && !incomingIds.has(t.id);
        });

        finalPayload.trips = [...incomingTrips, ...otherPrivateTrips];

        // Preserva mapas de conquistas dos demais usuários
        finalPayload.userMaps = {
          ...(existingData.userMaps || {}),
          ...(incoming.userMaps || {})
        };
      }

      const result = await writeDbToGithub(finalPayload, currentSha);
      return res.status(200).json({ ok: true, sha: result.content?.sha });
    }

    res.setHeader('Allow', ['GET', 'POST', 'PUT', 'DELETE']);
    return res.status(405).json({ error: `Método ${req.method} não permitido.` });
  } catch (error) {
    console.error('Erro na API /api/db:', error);
    return res.status(500).json({ error: 'Erro interno no servidor.' });
  }
}
