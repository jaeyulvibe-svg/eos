# OpsWatch

JEUS, WebtoB, Apache Tomcat, PostgreSQL, Nginx의 EOS/EOL과 보안 패치 대응을 관리하는 운영 포털입니다.

## 데이터 소스

- Tomcat, PostgreSQL, Nginx EOS 및 최신 버전: `endoflife.date` API
- 오픈소스 취약점: 각 프로젝트의 공식 보안 권고
- JEUS, WebtoB: TmaxSoft 기술 공지 및 고객지원 포털

Supabase 프로젝트 연결 정보는 `dist/config.js`에 있으며, 초기 스키마는 `supabase/schema.sql`에 있습니다. 데이터 수정 권한은 Supabase Auth의 인증 사용자에게만 허용됩니다.

## Supabase 초기화

Supabase SQL Editor에서 `supabase/schema.sql` 전체를 실행한 뒤 Authentication에서 운영 사용자 계정을 생성합니다. `service_role` 키는 브라우저나 저장소에 넣지 않습니다.

## 배포

Vercel 프로젝트의 Output Directory를 `dist`로 설정하거나 저장소의 `vercel.json`을 사용합니다.
