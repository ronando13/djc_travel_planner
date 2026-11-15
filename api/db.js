export const config = {
  api: {
    bodyParser: {
      sizeLimit: '6mb'
    }
  }
};

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

  // Autenticação Bearer Token
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';

  if (!token || token !== APP_PASSWORD) {
    return res.status(401).json({ error: 'Não autorizado. Senha incorreta.' });
  }

  const ghHeaders = {
    Authorization: `Bearer ${GITHUB_TOKEN}`,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'Kisuco-Planner-Vercel'
  };

  const action = String(req.query?.action || '');

  // Valida caminho seguro dentro de anexos/
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
        headers: {
          ...ghHeaders,
          Accept: 'application/vnd.github.raw+json'
        }
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
        message: `chore(anexos): salva ${filePath} via Kisuco Planner`,
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
          message: `chore(anexos): remove ${filePath} via Kisuco Planner`,
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
    // 4. LER / GRAVAR O BANCO PRINCIPAL (djc_travel_planner_bd.json)
    // -----------------------------------------------------------
    const apiUrl = `https://api.github.com/repos/${GITHUB_REPO}/contents/${DB_FILE_PATH}`;

    if (req.method === 'GET') {
      const ghRes = await fetch(`${apiUrl}?ref=${encodeURIComponent(GITHUB_BRANCH)}`, {
        method: 'GET',
        headers: ghHeaders
      });

      if (ghRes.status === 404) {
        return res.status(200).json({ empty: true });
      }

      if (!ghRes.ok) {
        const errText = await ghRes.text();
        return res.status(ghRes.status).json({ error: 'Erro ao ler do GitHub', details: errText });
      }

      const fileData = await ghRes.json();
      const contentStr = Buffer.from(fileData.content || '', 'base64').toString('utf-8');
      const jsonData = JSON.parse(contentStr);
      return res.status(200).json(jsonData);
    }

    if (req.method === 'POST' || req.method === 'PUT') {
      const payload = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
      if (!payload || typeof payload !== 'object') {
        return res.status(400).json({ error: 'Payload JSON inválido.' });
      }

      let currentSha = undefined;
      const checkRes = await fetch(`${apiUrl}?ref=${encodeURIComponent(GITHUB_BRANCH)}`, {
        method: 'GET',
        headers: ghHeaders
      });

      if (checkRes.ok) {
        const existing = await checkRes.json();
        currentSha = existing.sha;
      }

      const encodedContent = Buffer.from(JSON.stringify(payload, null, 2), 'utf-8').toString('base64');
      const putBody = {
        message: `chore(db): atualiza ${DB_FILE_PATH} via Kisuco Planner`,
        content: encodedContent,
        branch: GITHUB_BRANCH
      };
      if (currentSha) {
        putBody.sha = currentSha;
      }

      const putRes = await fetch(apiUrl, {
        method: 'PUT',
        headers: {
          ...ghHeaders,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(putBody)
      });

      if (!putRes.ok) {
        const errText = await putRes.text();
        return res.status(putRes.status).json({ error: 'Erro ao gravar no GitHub', details: errText });
      }

      const result = await putRes.json();
      return res.status(200).json({ ok: true, sha: result.content?.sha });
    }

    res.setHeader('Allow', ['GET', 'POST', 'PUT', 'DELETE']);
    return res.status(405).json({ error: `Método ${req.method} não permitido.` });
  } catch (error) {
    console.error('Erro na API /api/db:', error);
    return res.status(500).json({ error: 'Erro interno no servidor', message: error.message });
  }
}
