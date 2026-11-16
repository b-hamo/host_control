# dashboard/ — 로컬 대시보드 백엔드

Windows Sandbox와 micro VM에서 무엇이 돌고 있는지 보여 주는 **이 PC 전용, 읽기 전용** 서버다.
프론트 요청서(`minobox-dashboard-backend.md`)의 API를 제공한다. 요청서와 다른 점은 [요청서와 다른 점](#요청서와-다른-점)에 모았다.

```
Host(대화마다 하나) ──--dashboard-dir──▶ %LOCALAPPDATA%\SecureCUA\dashboard\hosts\<세션>.json / .png
Sandbox Manager ──────────────────────▶ <root>\sessions\<세션>\state.json
                                              │ (읽기만)
                          python -m dashboard ─┴─▶ http://127.0.0.1:17480  (페이지 + /api/*)
```

Host에 붙이지 않고 따로 도는 이유: Host는 Agent 대화마다 뜨고 끝나며 여러 개가 동시에 돈다. 대시보드는 그것들을 모아서
보고, 보안 관문(Host)에 웹 서버를 붙이지 않는다.

## 실행

```powershell
.venv\Scripts\python.exe -m dashboard --open
# SCRP dashboard: http://127.0.0.1:17480/?token=...   ← 이 주소로 연다 (토큰은 시작할 때마다 새로 만든다)
```

| 옵션 | 기본 | 뜻 |
|---|---|---|
| `--root DIR` | `%LOCALAPPDATA%\SecureCUA\sandbox-manager` (항상 읽음) | 더 읽을 Manager 폴더. 돌고 있는 Host가 알려 준 `--sandbox-root`는 자동으로 더한다 |
| `--dashboard-dir DIR` | `%LOCALAPPDATA%\SecureCUA\dashboard` | Host가 상태를 쓰는 곳 (Host `--dashboard-dir`와 같아야 함). 통합 설치(`host/solution.py`)는 기본값으로 켠다 |
| `--static DIR` | `dashboard/static` | 프론트 페이지(`index.html`과 그 파일들)를 두는 곳 |
| `--output-root DIR` | 없음 | 기존 Host의 차단된 Output 영수증을 읽을 신뢰된 폴더. 반복 지정 가능. 파일 내용은 읽지 않음 |
| `--port N` | 17480 | |
| `--vm-max N` | 8 | micro VM 동시 실행 상한. micro VM Host가 `--micro-vm-max-active`로 떠 있으면 그 값을 쓴다 |
| `--keep-ended S` | 600 | 끝난 세션을 목록에 남겨 두는 시간(초) |

## API

파일 반출 목록의 **악성 감지** 필터는 `MALWARE_DETECTED` 및 Windows 바이러스 차단 오류 225/226을 센다.
후자는 원래 결과 코드를 보존하면서 표시용 `scan_code=WINDOWS_MALWARE_BLOCKED`로 구분하며, 툴팁에 탐지 출처를 표시한다.
일반 검사 오류·시간 초과를 악성으로 분류하지 않는다.
기존 Host를 재시작하지 않고 기록을 연결하려면 `--output-root`에 해당 Host의 Output 수신 루트를 지정한다.
이 호환 경로의 시각은 정확한 판정 시각 대신 영수증 파일 갱신 시각이며, 화면의 시각 툴팁에 이를 표시한다.
최신 Host 상태가 같은 세션·artifact 결과를 제공하면 그 상태를 우선한다. 최근 24시간, 최대 200건을 표시한다.

모든 `/api` 요청은 토큰이 필요하다. 페이지 주소의 `?token=`을 읽어 `Authorization: Bearer <token>` 헤더로 보낸다.
`<img src>`처럼 헤더를 못 붙이는 곳은 `?token=`을 붙인다. 페이지와 API가 같은 서버라 **CORS 설정은 필요 없다**.
`Host` 헤더가 `127.0.0.1:<port>`나 `localhost:<port>`가 아니면 403 (다른 사이트가 DNS rebinding으로 읽는 것을 막음).
GET만 받는다(그 밖은 405). 시각은 모두 ISO-8601 UTC(`...Z`).

### `GET /api/dashboard/overview`

2~5초마다 폴링한다. 서버는 1초 동안 같은 결과를 돌려준다. 예시: [`sample-overview.json`](sample-overview.json).

```jsonc
{
  "updated_at": "2026-11-10T05:00:00Z",
  "runtimes": {
    "windows_sandbox": {"running": 1, "state": "RUNNING", "window_state": "OPEN"},
    "micro_vm": {"running": 2, "max": 8, "starting": 1, "failed": 0, "free_slots": 5}
  },
  "host_resources": {"cpu_percent": 64.0, "mem_percent": 72},
  "metrics": {"per_session": "unavailable", "reason": "needs administrator (HCS_E_ACCESS_DENIED)"},
  "sessions": [ /* 아래 표 */ ],
  "exports": [ /* 파일 반출 로그, 아래 표 */ ]
}
```

| `runtimes` 필드 | 값 |
|---|---|
| `windows_sandbox.running` | 0 또는 1 (`wsb list`) |
| `windows_sandbox.state` | 지금 Sandbox 세션의 상태. 없으면 `STOPPED` |
| `windows_sandbox.window_state` | `UNSEEN` `OPEN` `MISSING` `CLOSED` `UNKNOWN` `UNAVAILABLE` (Sandbox 창. Host가 2초마다 갱신) |
| `micro_vm.running` / `starting` / `failed` | `STARTED·RUNNING·RESTARTING` / `PREPARED·STARTING` / `FAILED` 개수 |
| `micro_vm.max`, `free_slots` | 상한, `max - running - starting` (0 미만이면 0) |
| `host_resources.cpu_percent` | PC 전체 CPU %. 서버를 켠 직후 첫 응답은 `null`일 수 있음 |
| `host_resources.mem_percent` | PC 전체 메모리 사용률 % |
| `metrics.per_session` | `hcs`면 세션별 CPU·메모리가 채워짐. `unavailable`이면 `reason`에 이유 |

`sessions[]` (시작 순서. 진행 중인 세션 + 끝난 지 10분 안 된 세션):

| 필드 | 예 | 설명 |
|---|---|---|
| `id` | `SES-…` | 세션 ID. 스크린샷 API에 쓴다 |
| `label` | `GUI-01`, `VM-03` | 화면 표시용 짧은 이름 (Sandbox는 GUI, micro VM은 VM, 시작 순 번호) |
| `runtime` | `windows_sandbox` · `micro_vm` | |
| `state` | `PREPARED` `STARTING` `STARTED` `RUNNING` `RESTARTING` `TERMINATED` `FAILED` | sandbox_manager 상태 그대로 |
| `display_state` | 위 값 또는 `VIOLATION` | 보안 위반으로 끝난 세션(`termination_reason=SECURITY_VIOLATION`)만 `VIOLATION`. 화면에는 이걸 쓴다 |
| `termination_reason` | `TASK_COMPLETE` `USER_STOP` `SECURITY_VIOLATION` `TIMEOUT` `RUNTIME_ERROR` / `null` | |
| `risk_type` | `미확인 실행파일 (setup.exe)` | 이 세션이 격리된 이유. 아래 표 |
| `task` | `7-Zip 받아서 설치해 줘` / `null` | Agent가 맡은 일 (최대 200자) |
| `last_activity` | `{"tool": "computer_click", "file": null, "ok": true, "at": "…"}` / `null` | 마지막 도구 호출 |
| `cpu_percent`, `mem_bytes` | `41.0`, `2576980378` / `null` | 세션 VM의 CPU(PC 전체 대비 %)·메모리. `metrics.per_session`이 `hcs`일 때만 숫자 |
| `started_at`, `ended_at` | ISO 시각 / `null` | 경과 시간은 프론트가 계산 |
| `network` | `enabled` · `blocked` | Sandbox는 인터넷 연결, micro VM은 기본 차단 |
| `window_state` | Sandbox만 (micro VM은 `null`) | |
| `host_alive` | `true` · `false` / `null` | 진행 중인 세션을 맡은 Host 프로세스가 살아 있는지. `false`면 대화가 끊긴 세션 |
| `screenshot` | `{"available": true, "captured_at": "…"}` | 스크린샷이 있는지와 찍힌 시각 |

`risk_type` 라벨 (세션이 받은 마지막 파일 기준, 없으면 마지막 도구 기준):

| 라벨 | 조건 |
|---|---|
| `미확인 실행파일 (이름)` | exe, msi, msix, appx, com, scr |
| `스크립트 실행 (이름)` | ps1, bat, cmd, vbs, js, wsf, hta, py, rb, sh, … |
| `매크로 문서 (이름)` | docm, xlsm, pptm, doc, xls, ppt |
| `외부 프로젝트 (이름)` | zip, 7z, rar, tar, gz |
| `받은 파일 열기 (이름)` | 그 밖의 받은 파일 |
| `웹페이지 명령` · `파일 받기` · `결과 반출` · `화면 작업` · `일반 작업` | 받은 파일이 없을 때 마지막 도구로 |

`exports[]` — 파일 반출 로그 (최신이 먼저, 최대 200건, 결과가 정해진 지 24시간이 지난 것은 빠짐):

| 필드 | 예 | 설명 |
|---|---|---|
| `artifact_id` | `ART-000017` | 반출 한 건의 ID (Host가 붙임) |
| `session_id`, `session_label` | `SES-…`, `GUI-01` / `null` | 어느 세션의 파일인지. 세션이 목록에서 빠졌으면 `session_label`은 `null` |
| `name` | `사진.7z` | 파일 이름 (Guest가 알린 경로의 마지막 부분, 표시용) |
| `stage` | 아래 표 | 지금 단계 |
| `code` | `EXPORTED` `BLOCKED` `QUARANTINED` `OUTPUT_FAILED` … / `null` | 결과 코드 (`result.code`) |
| `scan_code` | `MALWARE_DETECTED` `SCAN_ERROR` `FILE_TOO_LARGE` `CONTENT_CHANGED` … / `null` | 검사기가 막은 이유. 반출된 것은 `null` |
| `observed_at` | ISO 시각 | Guest가 파일을 알린 시각 |
| `finished_at` | ISO 시각 / `null` | 결과가 정해진 시각 (Host가 2초 간격으로 기록하므로 최대 2초 늦음). 진행 중이면 `null` |
| `export_path` | `SandboxOutput\SES-…\ART-000017\사진.7z` / `null` | 반출된 경우만. 다운로드 폴더 기준 상대 경로 |

| `stage` | 뜻 |
|---|---|
| `CANDIDATE` `AUTHORIZED` `RECEIVING` `RECEIVED` `STAGED` `SCANNING` | 진행 중 (받는 중, 검사 중) |
| `EXPORTED` | 검사 통과, 다운로드 폴더에 저장됨 |
| `BLOCKED` `QUARANTINED` `FAILED` | 막힘 또는 실패 (`code`, `scan_code`로 이유) |
| `HELD` | 보류 (받은 사본은 남아 있음) |
| `SUPERSEDED` `CANCELLED` `DELETED` | 같은 파일의 새 사본으로 바뀌었거나, 세션이 끝나 취소되었거나, 지워짐 (화면에서 숨겨도 됨) |

반출 상태는 Host 메모리(`ArtifactBroker`)에만 있으므로, Host가 상태 파일(`hosts/<세션>.json`의 `exports`)에 2초마다 옮겨 적고
대시보드가 모든 Host의 것을 합친다. Host가 끝난 뒤에도 마지막 목록은 파일에 남는다.

### `GET /api/runtimes/{id}/screenshot`

`{id}`는 `id`(`SES-…`)나 `label`(`GUI-01`). `image/png`와 `X-Captured-At` 헤더를 돌려준다.
`?format=json`이면 `{"image_url": "/api/runtimes/SES-…/screenshot", "captured_at": "…", "width": 1280, "height": 720}`.
없으면 404 `{"error": "NO_SCREENSHOT"}`.

**실시간 화면이 아니라 "AI가 마지막으로 본 화면"이다.** Runner와 연결된 것은 Host뿐이라 대시보드가 따로 찍지 않는다.
Agent가 화면을 볼 때(computer_observe)마다 바뀌므로, `screenshot.captured_at`이 바뀌었을 때만 다시 받으면 된다.
Host가 끝나면 화면 파일을 지운다(사용자 화면을 남기지 않음).

### 오류

| 코드 | 본문 `error` | 언제 |
|---|---|---|
| 401 | `UNAUTHORIZED` | 토큰 없음·틀림 |
| 403 | `FORBIDDEN_HOST` | Host 헤더가 이 서버가 아님 |
| 404 | `NOT_FOUND` · `NO_SCREENSHOT` | |
| 405 | `READ_ONLY` | GET 아닌 요청 |

## 요청서와 다른 점

| 요청서 | 실제 | 이유 |
|---|---|---|
| 인증: 기존 Host 세션·토큰, CORS 허용 | 대시보드 자체 토큰, 같은 서버에서 페이지 제공(CORS 불필요) | Host에는 대시보드용 API가 없고, Host 토큰은 Runner 전용이다. CORS를 열면 다른 사이트도 읽을 수 있다 |
| `risk_type` = Router 판정 라벨 | 세션이 받은 파일·마지막 도구로 붙인 라벨 | Router는 위험 유형을 판정하지 않는다(출처 기준: 밖에서 온 것은 모두 격리). 판정이 아니라 "무엇을 다뤘나"다 |
| `state: VIOLATION` | `state`는 Manager 값 그대로, `display_state`가 `VIOLATION` | 요청서의 두 번째 안. 상태 기계 값을 바꾸지 않는다 |
| `network: "desktop"` | `enabled` · `blocked` | 의미가 드러나게 |
| `id`가 `GUI-01` 같은 표시 이름 | `id`는 세션 ID, `label`이 표시 이름 | 세션 ID가 있어야 다른 기록과 맞출 수 있다 |
| 세션별 CPU·메모리 | 관리자 권한으로 실행할 때만 숫자, 아니면 `null` | Windows가 Hyper-V 통계(HCS)를 관리자에게만 준다. 대시보드를 관리자로 띄우는 것은 권하지 않는다 |
| 스크린샷: Runner 캡처 / `minobox screenshot` | Host가 저장한 마지막 관찰 화면 (두 런타임 같음) | 대시보드가 Runner·VM에 직접 붙으면 Host를 거치지 않는 두 번째 제어 경로가 생긴다 |
| 라이브 썸네일 1~3초 | `captured_at`이 바뀔 때만 | 위와 같음 |
| 추가 | `label`, `display_state`, `task`, `last_activity`, `ended_at`, `host_alive`, `screenshot`, `metrics`, `exports`(반출 로그, 프론트 `ExportEntry` 형식) | |

## 보안

- `127.0.0.1`에만 열린다. 토큰은 시작할 때마다 새로 만들고, 응답에 `Cache-Control: no-store`와 `Referrer-Policy: no-referrer`를 붙인다.
- 읽기 전용이다. 같은 PC의 Agent도 이 주소를 부를 수 있으므로, 실행·승인·종료 같은 버튼은 여기에 두지 않는다
  (승인은 Host의 Windows 승인 창).
- Host 상태 파일에는 도구 이름과 파일 이름만 남는다. 입력한 글자, URL의 쿼리, 그 밖의 인자는 남기지 않는다.

## 파일

| 파일 | 하는 일 |
|---|---|
| `collect.py` | Manager `state.json`, Host 상태 파일, `wsb list`, PC CPU·메모리, HCS 통계를 모아 overview를 만든다 |
| `export_history.py` | 명시한 Output 루트의 차단 영수증 메타데이터를 읽어 기존 Host 기록을 연결한다. 파일 본문은 읽지 않는다 |
| `liveness.py` | PID와 생성 FILETIME을 대조하고 `wsb list`·HCS 실행 목록을 읽는다. 조회 불가는 미확인으로 구분한다 |
| `server.py` | 페이지와 `/api/*`를 주는 HTTP 서버 (토큰, Host 헤더, 읽기 전용) |
| `__main__.py` | `python -m dashboard` |
| `sample-overview.json` | 프론트 개발용 예시 응답 |
| `frontend/` | 프론트 소스 (React + Vite + TypeScript). `npm run build`가 결과물을 `static/`에 바로 쓴다. 자세한 건 `frontend/README.md` |
| `static/` | 프론트 빌드 결과물. 직접 고치지 말고 `frontend/`에서 다시 빌드한다 |

프론트 페이지는 `dashboard/static/index.html`에 두면 `python -m dashboard`가 같이 준다(다른 폴더는 `--static`).
화면을 고쳤으면 `cd dashboard/frontend; npm ci; npm run build`로 `static/`을 다시 만들고 같이 커밋한다.

시험: `tests/test_dashboard.py` (overview 계약, CPU 계산, 관리자 아님, 토큰·Host 헤더·경로 탈출, 실제 MCP Host가 상태와 화면을 남기고 끝나면 지움).

## 오래된 세션과 실행 개수

`state.json`의 `RUNNING`만으로 실행 개수를 세지 않는다. Windows Sandbox는 `wsb list`의 실제 ID,
micro VM은 HCS에서 확인한 container ID와 대조한다. 실제 목록에 없는 종료 기록은 표시에서 제외한다.
HCS 조회 권한이 없는 경우에는 Manager가 기록한 Host의 PID **및 생성 FILETIME**이 모두 일치하는 활성 기록을 사용한다.
이 대체 경로의 `runtimes.micro_vm.count_source`는 `host_owner`, HCS 경로는 `hcs`다.
따라서 관리자 권한 없는 집계는 Host가 관리 중인 세션 기준이며, Host 없이 남은 micro VM까지 확인한 OS 전체 VM 개수는 아니다.
실제 ID가 확인되면 Host가 없어도 목록과 개수에 남긴다. 동일 container ID는 한 번만 센다.

프로세스 조회 권한 부족이나 생성 시각 누락은 종료로 단정하지 않는다. 원본 `state`를 보존하고
`display_state=UNKNOWN`, `host_alive=null`로 표시하며 실행·시작 개수에는 넣지 않는다.
`micro_vm.unknown`이 0보다 크면 `free_slots=null`이고 화면은 남은 슬롯을 `—`로 표시한다.
Sandbox 조회 실패도 `running=null`, `state=UNKNOWN`으로 표현한다.
오래된 Manager 파일은 수정·삭제하지 않고, 반출 이력은 세션 표시 여부와 독립적으로 유지한다.
중복 세션 ID는 Host가 명시한 Manager root를 우선한다. 시작 중인 살아 있는 Host는 VM 생성 전에도 유지한다.

추가 시험: `tests/test_dashboard_liveness.py` (PID 재사용·권한 부족·실제 런타임 대조·중복·시작 중·원본 불변).
