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
| `--port N` | 17480 | |
| `--vm-max N` | 8 | micro VM 동시 실행 상한. micro VM Host가 `--micro-vm-max-active`로 떠 있으면 그 값을 쓴다 |
| `--keep-ended S` | 600 | 끝난 세션을 목록에 남겨 두는 시간(초) |

## API

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
  "sessions": [ /* 아래 표 */ ]
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
| 추가 | `label`, `display_state`, `task`, `last_activity`, `ended_at`, `host_alive`, `screenshot`, `metrics` | |

## 보안

- `127.0.0.1`에만 열린다. 토큰은 시작할 때마다 새로 만들고, 응답에 `Cache-Control: no-store`와 `Referrer-Policy: no-referrer`를 붙인다.
- 읽기 전용이다. 같은 PC의 Agent도 이 주소를 부를 수 있으므로, 실행·승인·종료 같은 버튼은 여기에 두지 않는다
  (승인은 Host의 Windows 승인 창).
- Host 상태 파일에는 도구 이름과 파일 이름만 남는다. 입력한 글자, URL의 쿼리, 그 밖의 인자는 남기지 않는다.

## 파일

| 파일 | 하는 일 |
|---|---|
| `collect.py` | Manager `state.json`, Host 상태 파일, `wsb list`, PC CPU·메모리, HCS 통계를 모아 overview를 만든다 |
| `server.py` | 페이지와 `/api/*`를 주는 HTTP 서버 (토큰, Host 헤더, 읽기 전용) |
| `__main__.py` | `python -m dashboard` |
| `sample-overview.json` | 프론트 개발용 예시 응답 |
| `example-wiring.js` | 프론트 페이지(`minobox-dashboard.html`)를 이 API에 붙이는 예시. 페이지 끝에 넣으면 두 탭을 2초마다 채운다. 제품 코드가 아니라 연동 참고용 (API에서 온 글자는 escape한다) |

프론트 페이지는 `dashboard/static/index.html`에 두면 `python -m dashboard`가 같이 준다(다른 폴더는 `--static`).

시험: `tests/test_dashboard.py` (overview 계약, CPU 계산, 관리자 아님, 토큰·Host 헤더·경로 탈출, 실제 MCP Host가 상태와 화면을 남기고 끝나면 지움).
