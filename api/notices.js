const SOURCES = {
  tmax: 'https://www.tmaxsoft.com/kr/developer/notice/list',
  postgres: 'https://www.postgresql.org/support/security/',
};

const strip = value => value
  .replace(/<script[\s\S]*?<\/script>/gi, ' ')
  .replace(/<style[\s\S]*?<\/style>/gi, ' ')
  .replace(/<[^>]+>/g, ' ')
  .replace(/&nbsp;/g, ' ')
  .replace(/&amp;/g, '&')
  .replace(/&#39;/g, "'")
  .replace(/&quot;/g, '"')
  .replace(/\s+/g, ' ')
  .trim();

async function getJson(url) {
  const response = await fetch(url, { headers: { 'user-agent': 'OpsWatch/1.0' }, signal: AbortSignal.timeout(8000) });
  if (!response.ok) throw new Error(`${response.status} ${url}`);
  return response.json();
}

async function getText(url) {
  const response = await fetch(url, { headers: { 'user-agent': 'OpsWatch/1.0' }, signal: AbortSignal.timeout(8000) });
  if (!response.ok) throw new Error(`${response.status} ${url}`);
  return response.text();
}

function lifecycleNotices(product, label, releases, allowedVersions) {
  return releases.filter(release => allowedVersions.includes(release.name)).map(release => ({
    id: `eos-${product}-${release.name}`,
    product: label,
    version: release.name,
    type: 'EOS',
    severity: release.isEol ? 'critical' : 'info',
    title: release.isEol
      ? `${label} ${release.name} 지원 종료`
      : `${label} ${release.name} EOS ${release.eolFrom || '미정'}`,
    summary: `최신 패치 ${release.latest?.name || '미확인'} · EOS ${release.eolFrom || '미정'}`,
    publishedAt: release.eolFrom || release.latest?.date || null,
    fixedVersion: release.latest?.name || null,
    url: `https://endoflife.date/${product}`,
    source: 'endoflife.date',
  }));
}

function tomcatSecurityNotices(version, html) {
  const text = strip(html);
  const section = /([0-9]{4}-[0-9]{2}-[0-9]{2})\s+Fixed in Apache Tomcat\s+([^\s]+)([\s\S]*?)(?=[0-9]{4}-[0-9]{2}-[0-9]{2}\s+Fixed in Apache Tomcat|$)/g;
  const notices = [];
  let match;
  while ((match = section.exec(text)) && notices.length < 12) {
    const [, date, fixedVersion, body] = match;
    const issue = /(Critical|Important|Moderate|Low):\s+(.+?)\s+(CVE-[0-9]{4}-[0-9]+)\b/i;
    let found;
    const issueMatcher = new RegExp(issue.source, 'gi');
    while ((found = issueMatcher.exec(body)) && notices.length < 12) {
      const severity = found[1].toLowerCase();
      notices.push({
        id: `tomcat-${version}-${found[3]}`,
        product: 'Apache Tomcat',
        version,
        type: '보안 패치',
        severity: severity === 'critical' ? 'critical' : severity === 'important' ? 'high' : severity,
        title: `${found[3]} · ${found[2].trim()}`,
        summary: `${fixedVersion} 이상으로 업데이트 필요`,
        publishedAt: date,
        fixedVersion,
        url: `https://tomcat.apache.org/security-${version.split('.')[0]}.html`,
        source: 'Apache Tomcat Security',
      });
    }
  }
  return notices;
}

function postgresNotices(html) {
  const text = strip(html);
  const ids = [...new Set(text.match(/CVE-[0-9]{4}-[0-9]+/g) || [])].slice(0, 10);
  return ids.map(id => ({
    id: `postgresql-${id}`,
    product: 'PostgreSQL',
    version: '지원 버전',
    type: '보안 패치',
    severity: 'high',
    title: `${id} PostgreSQL 보안 권고`,
    summary: '영향 버전과 수정 버전을 공식 보안 공지에서 확인하세요.',
    publishedAt: null,
    fixedVersion: null,
    url: SOURCES.postgres,
    source: 'PostgreSQL Security',
  }));
}

function tmaxNotices(html) {
  const matches = [...html.matchAll(/<tr[^>]*onclick\s*=\s*["'][^"']*fnView\s*\(\s*["']\.\/view["']\s*,\s*["']([0-9]+)["']\s*\)[^"']*["'][^>]*>([\s\S]*?)<\/tr>/gi)];
  const seen = new Set();
  return matches.map(([, seq, body], index) => {
    const titleMatch = body.match(/<div[^>]*class=["'][^"']*text-clamp-1[^"']*["'][^>]*>([\s\S]*?)<\/div>/i);
    const dateMatch = body.match(/([0-9]{4})\.([0-9]{2})\.([0-9]{2})/);
    const title = strip(titleMatch?.[1] || body);
    if (!title || !/(JEUS|WebtoB|웹투비|제우스)/i.test(title) || !/(보안|패치|취약점|EOL|EOS)/i.test(title)) return null;
    const key = title.toLowerCase();
    if (seen.has(key)) return null;
    seen.add(key);
    return {
      id: `tmax-${index}-${Buffer.from(title).toString('base64url').slice(0, 16)}`,
      product: /webtob|웹투비/i.test(title) ? 'WebtoB' : 'JEUS',
      version: /webtob|웹투비/i.test(title) ? '5' : '7 / 8 / 9',
      type: /eol|eos/i.test(title) ? 'EOS' : '보안 패치',
      severity: /긴급|critical|중요/i.test(title) ? 'critical' : 'high',
      title,
      summary: 'TmaxSoft 공식 공지의 영향 버전과 패치 절차를 확인하세요.',
      publishedAt: dateMatch ? `${dateMatch[1]}-${dateMatch[2]}-${dateMatch[3]}` : null,
      fixedVersion: null,
      url: `https://www.tmaxsoft.com/kr/developer/notice/view?seq=${seq}`,
      source: 'TmaxSoft 공지',
    };
  }).filter(Boolean).slice(0, 12);
}

module.exports = async function handler(request, response) {
  response.setHeader('Access-Control-Allow-Origin', '*');
  response.setHeader('Cache-Control', 's-maxage=900, stale-while-revalidate=3600');
  try {
    const tasks = await Promise.allSettled([
      getJson('https://endoflife.date/api/v1/products/tomcat/'),
      getJson('https://endoflife.date/api/v1/products/postgresql/'),
      getText('https://tomcat.apache.org/security-9.html'),
      getText('https://tomcat.apache.org/security-10.html'),
      getText('https://tomcat.apache.org/security-11.html'),
      getText(SOURCES.postgres),
      getText(SOURCES.tmax),
    ]);
    const value = index => tasks[index].status === 'fulfilled' ? tasks[index].value : null;
    const notices = [];
    if (value(0)?.result) notices.push(...lifecycleNotices('tomcat', 'Apache Tomcat', value(0).result.releases, ['11.0','10.1','10.0','9.0','8.5','8.0','7']));
    if (value(1)?.result) notices.push(...lifecycleNotices('postgresql', 'PostgreSQL', value(1).result.releases, ['18','17','16','15','14','13','12']));
    if (value(2)) notices.push(...tomcatSecurityNotices('9.0', value(2)));
    if (value(3)) notices.push(...tomcatSecurityNotices('10.1', value(3)));
    if (value(4)) notices.push(...tomcatSecurityNotices('11.0', value(4)));
    if (value(5)) notices.push(...postgresNotices(value(5)));
    if (value(6)) notices.push(...tmaxNotices(value(6)));
    response.status(200).json({ generatedAt: new Date().toISOString(), notices });
  } catch (error) {
    response.status(500).json({ error: '공지 정보를 불러오지 못했습니다.' });
  }
}
