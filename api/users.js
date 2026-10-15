const URL = process.env.SUPABASE_URL || 'https://mddbdahjcxvmluiwrooh.supabase.co';
const PUBLIC_KEY = process.env.SUPABASE_PUBLISHABLE_KEY || 'sb_publishable_4daQrcNfFLrqzewllcqv6A_oCxqxqa8';

async function json(url, options = {}) {
  const response = await fetch(url, options);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw Object.assign(new Error(body.message || body.msg || 'request failed'), { status: response.status });
  return body;
}

module.exports = async function handler(request, response) {
  response.setHeader('Cache-Control', 'private, no-store, max-age=0');
  response.setHeader('Vary', 'Authorization');
  response.setHeader('Cache-Control', 'no-store');
  const token = String(request.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!token) return response.status(401).json({ error: '로그인이 필요합니다.' });
  if (!serviceKey) return response.status(503).json({ error: '사용자 관리 서버 키 설정이 필요합니다.' });
  try {
    const me = await json(`${URL}/auth/v1/user`, { headers: { apikey: PUBLIC_KEY, authorization: `Bearer ${token}` } });
    if (me.email !== 'admin@opswatch.local' && me.app_metadata?.role !== 'admin') return response.status(403).json({ error: '관리자만 사용할 수 있습니다.' });
    const headers = { apikey: serviceKey, authorization: `Bearer ${serviceKey}`, 'content-type': 'application/json' };
    if (request.method === 'GET') {
      const result = await json(`${URL}/auth/v1/admin/users?page=1&per_page=200`, { headers });
      return response.status(200).json({ users: (result.users || []).map(user => ({ id: user.id, email: user.email, username: user.email?.split('@')[0], app_metadata: { role: user.app_metadata?.role || (user.email === 'admin@opswatch.local' ? 'admin' : 'viewer') }, created_at: user.created_at, last_sign_in_at: user.last_sign_in_at })) });
    }
    const body = request.body || {};
    if (request.method === 'POST') {
      if (!/^[a-z0-9._-]{3,30}$/i.test(body.username || '') || String(body.password || '').length < 6) return response.status(400).json({ error: 'ID와 6자 이상의 비밀번호를 입력하세요.' });
      const user = await json(`${URL}/auth/v1/admin/users`, { method: 'POST', headers, body: JSON.stringify({ email: `${body.username.toLowerCase()}@opswatch.local`, password: body.password, email_confirm: true, app_metadata: { role: body.role === 'admin' ? 'admin' : 'viewer' } }) });
      return response.status(201).json({ id: user.id });
    }
    if (request.method === 'PATCH') {
      if (!body.id) return response.status(400).json({ error: '사용자 ID가 필요합니다.' });
      const patch = { app_metadata: { role: body.role === 'admin' ? 'admin' : 'viewer' } };
      if (body.password) patch.password = body.password;
      const user = await json(`${URL}/auth/v1/admin/users/${body.id}`, { method: 'PUT', headers, body: JSON.stringify(patch) });
      return response.status(200).json({ id: user.id });
    }
    if (request.method === 'DELETE') {
      if (!body.id) return response.status(400).json({ error: '사용자 ID가 필요합니다.' });
      const target = await json(`${URL}/auth/v1/admin/users/${body.id}`, { headers });
      if (target.email === 'admin@opswatch.local') return response.status(400).json({ error: '기본 admin 계정은 삭제할 수 없습니다.' });
      await json(`${URL}/auth/v1/admin/users/${body.id}`, { method: 'DELETE', headers });
      return response.status(204).end();
    }
    response.status(405).json({ error: '지원하지 않는 요청입니다.' });
  } catch (error) {
    response.status(error.status || 500).json({ error: error.message || '사용자 관리에 실패했습니다.' });
  }
};
