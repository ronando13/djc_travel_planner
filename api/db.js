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
    return res.status(500).json({
      error: 'Variáveis de ambiente ausentes na Vercel (APP_PASSWORD, GITHUB_TOKEN, GITHUB_REPO).'
    });
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

      const userPayload = {
        id: foundUser.id,
        username: foundUser.username,
        name: foundUser.name || foundUser.username,
        isAdmin: false
      };
      const token = signToken({ ...userPayload, exp: Date.now() + 30 * 24 * 60 * 60 * 1000 }, APP_PASSWORD);
      return res.status(200).json({ ok: true, token, user: userPayload });
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

  function sanitizeAttachmentPath(rawPath) {
    const clean = String(rawPath || '').replace(/^\/+/, '').trim();
    if (!clean.startsWith('anexos/') || clean.includes('..')) return null;
    return clean;
  }

  try {
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
        return res.status(ghRes.status).json({ error: 'Anexo não encontrado no GitHub.' });
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
        return res.status(putRes.status).json({ error: 'Erro ao salvar anexo no GitHub', details: errText });
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
        return res.status(delRes.status).json({ error: 'Erro ao excluir anexo no GitHub.' });
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
        jsonData.users = jsonData.users.map(u => ({
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

      if (!sessionUser.isAdmin) {
        // Usuário comum não pode alterar a tabela de usuários/senhas nem viagens a que não tem acesso
        finalPayload.users = Array.isArray(existingData.users) ? existingData.users : [];

        // Garante que viagens privadas de outros usuários existentes no servidor não sejam apagadas
        const existingTrips = Array.isArray(existingData.trips) ? existingData.trips : [];
        const incomingTrips = Array.isArray(incoming.trips) ? incoming.trips : [];
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
    return res.status(500).json({ error: 'Erro interno no servidor', message: error.message });
  }
}
