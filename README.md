# OpsWatch

JEUS, WebtoB, Apache Tomcat, PostgreSQL, Nginx의 EOS/EOL과 보안 패치 대응을 관리하는 운영 포털입니다.

## 데이터 소스

- Tomcat, PostgreSQL, Nginx EOS 및 최신 버전: `endoflife.date` API
- 오픈소스 취약점: 각 프로젝트의 공식 보안 권고
- JEUS, WebtoB: TmaxSoft 기술 공지 및 고객지원 포털

현재 자산 데이터는 브라우저에 저장됩니다. Supabase 연결 정보가 준비되면 공용 운영 데이터로 전환합니다.

## 배포

Vercel 프로젝트의 Output Directory를 `dist`로 설정하거나 저장소의 `vercel.json`을 사용합니다.
