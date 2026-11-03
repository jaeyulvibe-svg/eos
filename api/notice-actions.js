const URL = process.env.SUPABASE_URL || 'https://mddbdahjcxvmluiwrooh.supabase.co';
const PUBLIC_KEY = process.env.SUPABASE_PUBLISHABLE_KEY || 'sb_publishable_4daQrcNfFLrqzewllcqv6A_oCxqxqa8';

async function json(url, options = {}) {
  const result = await fetch(url, options);
  const body = await result.json().catch(() => ({}));
  if (!result.ok) {
    const message = body.message || body.msg || body.error_description || body.details || 'request failed';
    throw Object.assign(new Error(message), { status: result.status, code: body.code });
  }
  return body;
}

module.exports = async function handler(request, response) {
  response.setHeader('Cache-Control', 'private, no-store, max-age=0');
  response.setHeader('Vary', 'Authorization');
  const token = String(request.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!token) return response.status(401).json({ error: '로그인이 필요합니다.' });
  if (!serviceKey) return response.status(503).json({ error: '공지 저장 서버 설정이 필요합니다.' });

  try {
    const me = await json(`${URL}/auth/v1/user`, { headers: { apikey: PUBLIC_KEY, authorization: `Bearer ${token}` } });
    if (!me.id || !String(me.email || '').endsWith('@opswatch.local')) return response.status(403).json({ error: '운영 포털 사용자만 사용할 수 있습니다.' });
    const isAdmin = me.email === 'admin@opswatch.local' || me.app_metadata?.role === 'admin';
    const headers = { apikey: serviceKey, authorization: `Bearer ${serviceKey}`, 'content-type': 'application/json', prefer: 'return=representation' };

    if (request.method === 'GET') {
      const rows = await json(`${URL}/rest/v1/notice_actions?select=*&order=acknowledged_at.desc`, { headers });
      return response.status(200).json({ actions: rows });
    }

    if (request.method === 'POST') {
      const row = { ...(request.body || {}), acknowledged_by: me.id, acknowledged_email: me.email, acknowledged_role: isAdmin ? 'admin' : 'viewer' };
      row.notice_type = row.notice_type === 'EOS' ? 'EOS' : '보안 패치';
      delete row.id;
      delete row.acknowledged_at;
      delete row.updated_at;
      const rows = await json(`${URL}/rest/v1/notice_actions`, { method: 'POST', headers, body: JSON.stringify(row) });
      return response.status(201).json({ action: rows[0] });
    }

    if (request.method === 'PATCH') {
      const body = request.body || {};
      if (!body.id) return response.status(400).json({ error: '대응 항목 ID가 필요합니다.' });
      const allowed = ['plan_start_date','plan_end_date','next_action_date','assignee_name','reviewer_name','approver_name'];
      if (isAdmin) allowed.push('action_status');
      const patch = Object.fromEntries(Object.entries(body.patch || {}).filter(([key]) => allowed.includes(key)));
      if (!Object.keys(patch).length) return response.status(400).json({ error: '수정할 항목이 없습니다.' });
      const rows = await json(`${URL}/rest/v1/notice_actions?id=eq.${encodeURIComponent(body.id)}`, { method: 'PATCH', headers, body: JSON.stringify(patch) });
      return response.status(200).json({ action: rows[0] });
    }

    return response.status(405).json({ error: '지원하지 않는 요청입니다.' });
  } catch (error) {
    const duplicate = error.code === '23505';
    response.status(duplicate ? 409 : error.status || 500).json({ error: duplicate ? '다른 사용자가 이미 확인한 공지입니다.' : error.message || '공지 저장에 실패했습니다.', code: error.code });
  }
};
