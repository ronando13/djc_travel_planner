export default async function handler(req, res) {
  // CORS & No-Cache headers
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  const APP_PASSWORD = process.env.APP_PASSWORD;
  const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
  const GITHUB_REPO = process.env.GITHUB_REPO; // Ex: "seu-usuario/seu-repositorio-privado"
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

  const apiUrl = `https://api.github.com/repos/${GITHUB_REPO}/contents/${DB_FILE_PATH}`;
  const ghHeaders = {
    Authorization: `Bearer ${GITHUB_TOKEN}`,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'DJC-Travel-Planner-Vercel'
  };

  try {
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

      // Obtém o SHA atual do arquivo (se já existir) para atualizar sem conflito
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
        message: `chore(db): atualiza ${DB_FILE_PATH} via Kisuco Travel Planner`,
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

    res.setHeader('Allow', ['GET', 'POST', 'PUT']);
    return res.status(405).json({ error: `Método ${req.method} não permitido.` });
  } catch (error) {
    console.error('Erro na API /api/db:', error);
    return res.status(500).json({ error: 'Erro interno no servidor', message: error.message });
  }
}
