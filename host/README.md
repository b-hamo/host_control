# host/ — Host 쪽 코드 안내

Agent(Codex)의 요청을 받아 검사하고, 격리된 Sandbox 안의 Runner로 전달하는 Host 프로그램이다.
파일 21개가 **4개 층**으로 나뉘어 있고, 요청은 위층에서 아래층으로 흐른다.

```
Codex (AI)
   │  MCP (stdin/stdout)
   ▼
┌─ ① Codex와 대화하는 층 ─────────────────────────────────┐
│  mcp_server.py   tool_availability.py   tool_catalog.py   │
└───────────────────────────────────────────────────────────┘
   ▼
┌─ ② 요청을 검사하는 층 (Broker) ─────────────────────────┐
│  broker.py   policy.py   audit.py   approval.py            │
└───────────────────────────────────────────────────────────┘
   ▼
┌─ ③ 세션을 관리하는 층 ───────────────────────────────────┐
│  runtime_session.py   startup.py   lifecycle.py            │
│  artifacts.py   artifact_scan.py   (파일 반출)             │
└───────────────────────────────────────────────────────────┘
   ▼
┌─ ④ Sandbox와 통신하는 층 ────────────────────────────────┐
│  sender.py   connection.py   session_registry.py           │
│  tls.py      bootstrap.py                                  │
│  upload_server.py   observation_store.py   telemetry.py    │
└───────────────────────────────────────────────────────────┘
   │  wss (TLS 1.2+, 1회용 token) + https PUT (스크린샷·반출 파일)
   ▼
Sandbox 안 Runner
```

## ① Codex와 대화하는 층

| 파일 | 하는 일 | WBS |
|---|---|---|
| `mcp_server.py` | Codex가 자식 프로세스로 켜는 MCP Server. `tools/list`에 도구 목록을 주고, `tools/call`을 Broker에 넘겨 결과를 돌려준다. 켜질 때 ④층(wss 서버, 세션 등록, bootstrap 파일)도 함께 시작한다 | 5.7 |
| `tool_availability.py` | 이 세션에서 보여줄 도구를 정하는 규칙. Codex는 약 0.5초 안에 도구 목록을 못 받으면 서버를 빼버리므로, 무거운 라이브러리 없이 쓸 수 있게 따로 뺐다 | 5.7 |
| `tool_catalog.py` | `schema/mcp-tools/`의 도구 13개를 읽고, 입력값을 규격(타입·필수·범위·모르는 필드)으로 검사한 뒤 생략된 값을 기본값으로 채운다 | 5.6 |

## ② 요청을 검사하는 층 (Broker)

| 파일 | 하는 일 | WBS |
|---|---|---|
| `broker.py` | **모든 도구 호출의 입구 `Broker.call()`.** 도구 확인 → 입력 검사 → 세션 상태 → 호출 빈도 → 정책 → 좌표·화면 신선도 → Action ID 발급 → SCRP 메시지로 번역·전송 → 오류 정리 → 감사 로그. 하나라도 걸리면 Runner로 보내지 않는다. 입력은 절대 재전송하지 않는다 | 5.6 |
| `policy.py` | 보안 규칙. 요청마다 ALLOW / REQUIRE_APPROVAL / DENY와 규칙 ID를 정한다 (예: Win+R 거부 `P-DENY-HOTKEY`). 나중에 Translator의 판단이 들어올 자리 | 5.6 |
| `audit.py` | 호출마다 JSON 한 줄 기록 (`host/.audit/<session>.jsonl`). `computer_type`의 글자는 길이와 SHA-256만 남긴다 | 5.6 |

## ③ 세션을 관리하는 층

| 파일 | 하는 일 | WBS |
|---|---|---|
| `runtime_session.py` | 연결이 끊겨도 이어지는 세션. 5초마다 HEARTBEAT, 연속 2회 누락 DEGRADED · 3회 UNRESPONSIVE. 끊길 때 결과를 못 받은 Action은 재전송하지 않고 재접속 후 STATE_REQUEST로 확인. task_id·action_id 발급, 마지막 화면과 받은 시각 보관, `status()`로 상태 조회 | 4.4, 4.5 |
| `artifacts.py` | 파일 반출 본체 (artifact-export-v1). 후보 등록·artifact_id, 승인 뒤 업로드 권한(upload_id·token·기한·상한) 먼저 등록 → ARTIFACT_REQUEST → 수신 기록과 ARTIFACT_RESULT 대조 → 검사 → 같은 바이트만 공개. 세션 종료·세대 변경·채널 끊김 시 취소 | 5.8 |
| `artifact_scan.py` | 반출 전 검사. 형식 정책(UTF-8 `.txt`) + 백신. 기본은 검사기 없음 = 차단. AMSI는 EICAR 자체 시험을 통과해야만 사용 | 5.8 |
| `approval.py` | 사용자 승인 창. Host 화면에 뜨고 AI는 답할 수 없음. 2분 무응답 = 거부 | 5.6 |
| `lifecycle.py` | Sandbox 켜고 끄기 (Lifecycle 담당의 Sandbox Manager 호출). `task_submit` 때 백그라운드로 켜기 시작 → Sandbox가 보는 Host 주소로 인증서·bootstrap 작성 → READY면 token 파일 삭제 → 세션이 끝나면(정상·실패·Codex 종료) 끄고 치운다. Runner가 응답이 없으면 같은 Sandbox에서 Runner만 다시 켜거나 Sandbox를 새로 켠다(다음 세대). `mcp_server.py --runner-exe`일 때만 쓴다 | 5.9 |
| `startup.py` | Startup Verification. Runner가 "준비됐다"고 해도 Host가 7가지(버전·Capability·Monitor·시계 / Worker 생존·첫 캡처·Heartbeat)를 확인한 뒤에만 READY. 등록 후 120초 안에 안 되면 실패 | 4.5 |

## ④ Sandbox와 통신하는 층

| 파일 | 하는 일 | WBS |
|---|---|---|
| `sender.py` | wss 서버를 열고 Runner 접속을 받는다. 업그레이드 전에 token 확인(401/404), HELLO를 받으면 token을 사용 처리하고 세션에 연결. 시험용 데모(`--demo protocol` / `--demo broker`)도 여기 있다 | 3.4, 4.6 |
| `telemetry.py` | Telemetry 채널 `/scrp/v1/telemetry` (artifact-export-v1 세션만). 전용 1회용 token, CHANNEL_HELLO/ACK, 후보 SECURITY_EVENT → EVENT_ACK(STORED/REJECTED) | 5.8 |
| `connection.py` | 연결 1개. 받은 메시지를 검사(세션 신원, connection_id, sequence, message_id·nonce 중복, 시계 오차)하고 요청·응답을 짝 맞춘다. 끊기면 버리고 새로 만든다 | 3.4 |
| `session_registry.py` | 1회용 token 발급·확인·폐기. 처음 접속용(bootstrap, 5분)과 재접속용(reconnect, 새로 받으면 이전 것 폐기), Telemetry용(telemetry). 채널마다 자기 종류의 token만 받는다. TERMINATE 시 전부 폐기 | 4.6, 4.4 |
| `tls.py` | TLS 설정(최소 1.2)과 개발용 자체 서명 인증서 생성 (`host/.certs/`) | 4.6 |
| `bootstrap.py` | Runner가 읽을 접속 안내서 `host/.bootstrap/bootstrap.json` 생성 (세션 값, 포트·경로, token, Host 인증서, 스크린샷 업로드 주소) | 4.6 |
| `upload_server.py` | 스크린샷을 받는 작은 HTTPS 서버 (17444, `PUT /scrp/v1/observations/<upload_id>`). 제어 채널과 같은 인증서. 크기 제한·시간 제한을 본문을 읽기 전에 건다. WebSocket 라이브러리가 요청 본문을 못 받아서 포트를 따로 쓴다. artifact-export-v1이면 같은 서버에 파일 반출 경로 `PUT /scrp/v1/artifacts/<upload_id>`(Bearer token, 디스크 스트리밍, 빈 201)가 따로 붙는다 | 5.6, 5.8 |
| `observation_store.py` | 1회용 upload_id 발급(30초), 받은 PNG 검사(구조·16 MP·sha256), OBSERVE_RESULT와 맞는지 대조. 맞은 화면만 메모리에 두고(세션당 8장) 세션이 끝나면 지운다 | 5.6 |
| `__init__.py` | 비어 있음. `host`를 Python 패키지로 인식시키는 표시 | - |

같이 쓰는 저장소의 다른 곳:
- `scrp/validate.py`: 모든 메시지를 크기·인코딩·스키마로 검사
- `scrp/envelope.py`: 메시지 봉투(ID·sequence·nonce·timestamp) 생성
- `schema/`: Host ↔ Runner 메시지 규격, `schema/mcp-tools/`: Codex 도구 규격

## 요청 하나가 지나가는 길

Codex가 `computer_click(x=640, y=420)`을 부르면:

```
1. mcp_server.py        tools/call 수신 → Broker.call()
2. broker.py            검사
   ├ tool_catalog.py      입력값 규격 검사, button·click_count 기본값 채움
   ├ broker.py            세션 READY? task_submit 했나? 초당 5회 이하?
   ├ policy.py            DENY 규칙에 걸리나?
   └ broker.py            좌표가 마지막 화면 안인가? 화면을 받은 지 10초 이내인가?
                          → ACT-000003 발급, computer_click → mouse.click 번역
3. runtime_session.py   READY 확인, Action 기록 "SENT"
4. connection.py        ACTION_REQUEST 전송 → ACK → ACTION_RESULT 대기
5. (Runner가 Sandbox 안에서 클릭하고 응답)
6. connection.py        응답 검사 (sequence, 중복, 시각)
7. broker.py            결과 정리 (SUCCESS / Runner가 보낸 오류 이유)
   └ audit.py             한 줄 기록
8. mcp_server.py        Codex에게 결과 반환
```

## 무엇을 고치려면 어디를 보나

| 하고 싶은 것 | 볼 파일 |
|---|---|
| 새 도구 추가, 도구 입력 규칙 변경 | `schema/mcp-tools/*.json` → `broker.py`의 `OPERATIONS`·`translate()` |
| 보안 규칙 추가 (차단할 요청) | `policy.py` |
| 호출 빈도 제한 변경 | `broker.py`의 `RATE_LIMITS` |
| 오류별로 Agent에게 안내할 다음 행동 | `broker.py`의 `ERROR_HINTS` |
| READY 전에 확인할 항목 | `startup.py`의 `StartupProfile`, `check_hello()`, `verify_runtime()` |
| Heartbeat 간격, 이상 판정 기준 | `runtime_session.py` 위쪽 상수 |
| token 유효시간 | `session_registry.py`의 `TOKEN_TTL_S`, `RECONNECT_TTL_S` |
| Runner에게서 받는 메시지 검사 | `connection.py`의 `check()`, `scrp/validate.py` |

## 테스트

| 테스트 파일 | 확인하는 것 |
|---|---|
| `tests/test_auth.py` | TLS, token(없음·틀림·만료·재사용·다른 세션), nonce 재사용, 로그에 token 노출 |
| `tests/test_heartbeat_reconnect.py` | Health 전이, 재접속 token, 연결 교체, 끊긴 Action 재동기화 |
| `tests/test_startup.py` | 정상 승격, 고장 Runner 거부, 시간 초과, 시계 오차 |
| `tests/test_broker.py` | 검사별 거부, 정책, 빈도 제한, 감사 로그 마스킹, 도구 규격 ↔ 프로토콜 교차 검사 |
| `tests/test_mcp_server.py` | 실제 자식 프로세스로 기동, 도구 목록 속도, Codex → Runner 전 구간, 스크린샷이 MCP image로 전달 |
| `tests/test_observation_upload.py` | upload_id(1회용·만료), PNG 검사, HTTPS 수신 거부 코드, 해시·크기 대조, 조작된 업로드 차단, 세션 종료 시 삭제 |
| `tests/test_sandbox_recovery.py` | Runner만 다시 켜기, 창 닫힘은 다시 안 켬, 먹통이면 Sandbox 새로 켜기, 실패 시 넘어가기·종료, 옛 세대 token 거부, 실제 Sandbox Manager로 재시작 확인 |
| `tests/test_sandbox_launch.py` | task_submit에 Sandbox 켜기(바로 PREPARING), READY 대기, 켜기 실패·시간 초과·Codex 종료 시 끄고 정리, Lifecycle의 실제 Sandbox Manager로 파일 전달 확인 |
| `tests/test_artifact_export.py` | 파일 반출: Runner 계약 예제 14개, bootstrap 선택, token 종류 분리, Telemetry 없으면 READY 안 됨, 중복 후보, 한글·빈 파일 반출(바이트·해시 일치, 빈 201), 승인 거부, 검사 통과·차단·오류·시간 초과·형식, Runner 거부·결과 불일치·결과 없음, 채널·연결 끊김·세션 종료 취소, 수신 거부 코드, AMSI EICAR 자체 시험 |
| `tests/artifact_runner.py` | 테스트용 artifact-export-v1 Runner (MiniRunner 확장, 테스트가 아니라 도구) |
| `tests/mini_runner.py` | 테스트용 최소 Runner (테스트가 아니라 도구) |

```bash
.venv/Scripts/python.exe -m pytest -q tests
```

## Git에 올리지 않는 폴더

실행하면 생기지만 `.gitignore`로 제외된다. 개인 키와 token이 들어 있으므로 공유하지 않는다.

| 폴더 | 내용 |
|---|---|
| `host/.certs/` | 개발용 인증서와 **개인 키** |
| `host/.bootstrap/` | bootstrap 파일 (**1회용 token** 포함) |
| `host/.audit/` | 감사 로그 |
| `host/.logs/` | MCP Server 로그 |
| `host/.artifacts/` | 반출 대기 중 받은 파일 (격리, 검사 전) |
| `host/.exports/` | 검사를 통과해 공개된 파일 |
