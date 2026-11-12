# dashboard/frontend — MINOBOX 대시보드 화면

`python -m dashboard`가 보여 주는 화면의 소스다(React + Vite + TypeScript).
빌드하면 결과물이 `../static/`에 바로 들어가고, 대시보드 서버가 그 폴더를 `/`로 내보낸다.
API 계약은 [`../README.md`](../README.md)를 따른다.

## 처음 받을 때 (다른 PC 포함)

Node.js 18 이상이 필요하다.

```powershell
cd dashboard\frontend
npm ci
```

## 화면 고치기

```powershell
npm run dev      # http://localhost:5173 — 주소에 ?token= 이 없으면 목업 데이터로 뜬다
```

실제 백엔드에 붙여 보려면 `npm run build` 후 `python -m dashboard --open`으로 연다.

## 반영하기

```powershell
npm run build    # ../static/ 을 지우고 새로 만든다
```

`src/`와 `../static/`을 **같이 커밋**한다. `static/`은 직접 고치지 않는다.

## 데이터 연결 (`src/api/client.ts`)

- 서버가 연 주소의 `?token=`이 있으면 실제 API, 없으면 `src/api/mock.ts` 목업을 쓴다.
- dev에서도 실제 API를 쓰려면 `.env`에 `VITE_USE_MOCK=false`를 두고, 서버 토큰을 주소에 붙여 연다
  (`vite.config.ts`가 `/api`를 `127.0.0.1:17480`으로 넘긴다).

- 파일 반출 로그는 overview의 `exports`(`types.ts`의 `ExportEntry`)를 쓴다. **백엔드 미구현** —
  지금은 목업에만 있고, 실제 API에서는 `exports`가 없어 "반출 기록을 아직 받지 않아요"로 보인다.

## 구조

```
src/
  types.ts              API 응답 타입과 상태색(statusOf)
  utils.ts              메모리·경과시간·퍼센트 표시
  theme.tsx             다크/라이트 (localStorage에 저장)
  api/client.ts         getOverview() · screenshotUrl() — 토큰, 목업 전환
  api/mock.ts           목업 overview
  hooks/useDashboardData.ts   overview를 3초마다 받음
  components/
    ResourceSessionTab  → RuntimePanel · ResourcePanel · SessionsTable
    LiveViewTab         → ScreenCapture · DetailPanel (목록 · 모니터 · 상세)
                          + ExportLog (아래로 스크롤하면 파일 반출 로그)
    Header · Tabs · BullIcon · MeterBar
  styles.css            색은 CSS 변수. .app(다크) / .app.light(라이트)
```

## 지킬 것

- API에서 온 글자(`task`, `risk_type`, 파일 이름)는 JSX로만 넣는다. `innerHTML`·`dangerouslySetInnerHTML` 금지.
- 실행·승인·종료 버튼을 두지 않는다(읽기 전용).
- 외부 CDN·외부 서버를 부르지 않는다.
