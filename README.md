# host_control

Host에서 Agent 요청을 통제·전달하는 프로그램.
AI Agent(Codex)의 요청을 검사해서 격리된 Sandbox 안의 Runner(`b-hamo/sandbox_runner`)로 전달하고,
돌아온 결과를 검증한다.

```
Codex ──MCP──▶ [ MCP Server ] ──▶ [ Broker ] ──▶ [ RuntimeSession ] ──WSS──▶ [ Runner ]
               host/mcp_server.py host/broker.py   host/runtime_session.py      sandbox_runner
                                  (도구 호출 검사)  (연결·재연결·READY 관리)      Sandbox 안
```

## 현재 포함된 것

| 경로 | 내용 | WBS |
|---|---|---|
| `host/sender.py` | Host 송신기. Runner 접속 수락, 인증, 데모 실행 | 3.4, 4.6 |
| `host/mcp_server.py` | MCP Server: Codex가 자식 프로세스로 켜고 stdio로 도구를 부르는 창구 | 5.7 |
| `host/broker.py` | Broker 코어: 도구 호출 검사 → SCRP 메시지로 변환 → 결과·오류 정규화 | 5.6 |
| `host/tool_catalog.py` | 도구 13개 목록, 입력 스키마 검사, 이 세션에서 쓸 수 있는 도구만 노출 | 5.6 |
| `host/policy.py` | 중앙 정책: ALLOW / REQUIRE_APPROVAL / DENY + 규칙 ID | 5.6 |
| `host/audit.py` | 감사 로그 (호출마다 1줄, 입력 글자는 가림) | 5.6 |
| `host/tool_availability.py` | 도구 노출 규칙 (표준 라이브러리만 사용, MCP Server가 빠르게 뜨도록) | 5.7 |
| `host/connection.py` | 연결 1개: 수신 메시지 검증, 요청·응답 짝 맞춤 | 3.4 |
| `host/runtime_session.py` | 재연결해도 이어지는 세션: Heartbeat·Health, 재연결 후 재동기화, 상태 조회 | 4.4, 4.5 |
| `host/startup.py` | Startup Verification: Host가 확인한 뒤에만 READY | 4.5 |
| `host/session_registry.py` | 세션 등록부. 세션별 1회용 bootstrap token 발급·확인 | 4.6 |
| `host/tls.py` | TLS 설정(최소 TLS 1.2), 개발용 자체 서명 인증서 생성 | 4.6 |
| `host/bootstrap.py` | Runner가 읽을 bootstrap 설정 파일 생성 | 4.6 |
| `scrp/validate.py` | 메시지 검증기 (크기·인코딩·스키마) | 2.2 |
| `scrp/envelope.py` | 메시지 봉투 생성기 (ID·sequence·nonce·timestamp) | 2.2 |
| `schema/` | Host ↔ Runner 메시지 규격. **Runner도 이 파일을 기준으로 구현** | 2.2, 2.3 |
| `schema/mcp-tools/` | Agent(Codex)에게 보여줄 도구 13개의 입력 규격 | 2.4 |
| `tests/` | 인증·TLS·replay 거부, Heartbeat·재연결, Startup Verification, Broker 자동 테스트 | 4.4~4.6, 5.6 |

규격의 결정 사항과 노션 초기 표와의 차이는 [schema/README.md](schema/README.md)에 있다.

`host/` 파일별 역할, 층 구조, 요청이 지나가는 길은 [host/README.md](host/README.md)에 있다.

## 실행

Python 3.13 (팀 공통 3.13.15).

```bash
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt
.venv/Scripts/python.exe host/sender.py
```

시작하면 Host가 다음을 한다.

1. `host/.certs/`에 개발용 인증서가 없으면 만든다 (90일 유효, 이후 재사용)
2. 세션 1개(`SES-001 / RT-SBX-001 / gen 1`, `--session` 등으로 변경)를 등록하고 1회용 token을 발급한다
3. `host/.bootstrap/bootstrap.json`을 쓴다. Runner는 이 파일만 있으면 접속할 수 있다
4. `listening on wss://0.0.0.0:17443/scrp/v1/control` → Runner 접속 대기
   (스크린샷 업로드는 `https://0.0.0.0:17444/scrp/v1/observations/`, 아래 참고)
5. Runner가 접속하면 **Startup Verification**을 한 뒤에만 READY (아래). 등록 후 120초(`--startup-timeout`) 안에 READY가 안 되면 세션 실패

Runner가 Host에 접속할 주소(Windows Sandbox가 보는 Host 주소, Sandbox Manager의 `start()`가 돌려주는 값)를 알면
`--advertise-address 192.168.208.1`처럼 넘긴다. 그 주소가 bootstrap의 `host`에 들어가고, 인증서 SAN에도 들어간다.
주소가 바뀌면 인증서를 새로 만든다 (재부팅하면 바뀐다). `sender.py`와 `mcp_server.py` 둘 다 같은 옵션이 있다.

Runner가 접속해 HELLO를 보내면 데모 순서(화면 관찰 → 클릭 → 입력 → 생존 확인 → 상태 조회 → 종료)를
실행하고 결과를 출력한다. `--no-demo`는 핸드셰이크와 Heartbeat만 하고 대기한다.
bootstrap token은 한 번 쓰면 끝이므로, 새 세션을 시작하려면 Host를 재시작해 새 token을 받는다.
연결이 끊긴 경우의 재접속은 HELLO_ACK로 받은 reconnect token으로 한다 (아래).

Windows Sandbox에서 접속받으려면 Host 방화벽에서 TCP **17443**(제어 채널)과 **17444**(스크린샷 업로드) 인바운드를 허용해야 한다.

테스트:

```bash
.venv/Scripts/python.exe -m pip install pytest
.venv/Scripts/python.exe -m pytest -q tests
```

## Broker (WBS 5.6)

Agent의 도구 호출은 모두 `Broker.call(tool, arguments)` 하나로 들어온다. 순서대로 검사하고, 하나라도 걸리면 Runner까지 가지 않는다.

| 순서 | 검사 | 걸리면 | 명세서 |
|---|---|---|---|
| 1 | 알려진 도구인가, 이 세션에서 쓸 수 있는가 (Capability, 미구현 Artifact 도구는 숨김) | `POLICY_DENIED` | B-11 |
| 2 | 입력 스키마 (타입·필수·enum·길이·범위, 모르는 필드 거부). 생략한 선택 인자는 기본값으로 채움 | `INVALID_ARGUMENT` | B-2 |
| 3 | 세션: 종료됐나, READY인가, `task_submit`을 먼저 했나 | `SESSION_TERMINATED` / `RUNTIME_UNAVAILABLE` / `POLICY_DENIED` | B-3 |
| 4 | 호출 빈도: 관찰 초당 2회, 입력 초당 5회, 제어 초당 5회. 기다리게 하지 않고 바로 거절 | `RATE_LIMITED` (+`retry_after`) | B-7 |
| 5 | 정책: DENY 규칙(예: Win+R 등 명령 실행 창을 여는 단축키), 승인 필요 도구 | `POLICY_DENIED` (+`rule_id`) | B-5, B-8 |
| 6 | 좌표가 마지막 화면 안인가, 화면이 10초 이내인가, 글자가 4 KiB 이하인가 | `INVALID_ARGUMENT` / `STALE_OBSERVATION` | 프로토콜 §6 |
| 7 | Action ID 발급 → SCRP 메시지로 변환해 전송 (`computer_click` → `mouse.click`) | | B-4 |
| 8 | 결과·오류를 표준 형식으로: `error`, `message`, `retryable`, `retry_after`, `recommended_next_step` | | B-10 |
| 9 | 감사 로그 1줄: 시각, 세션, task, action, 도구, 인자(입력 글자는 길이+해시만), 정책 결과, 결과, 지연 | | B-9 |

- Broker는 입력을 **절대 다시 보내지 않는다.** `ACTION_TIMEOUT`이면 `recommended_next_step: runtime_get_state`로 Agent가 먼저 확인하게 한다
- Agent는 `session_id`를 넘기지 않는다. Broker 하나가 세션 하나에 묶인다 (다른 세션 조작 불가)
- 데모: `python host/sender.py --demo broker` — 도구 호출 9개 중 3개(작업 등록 전 관찰, 화면 밖 클릭, Win+R)가 거부되고 Runner에는 2개만 도착한다. 감사 로그는 `host/.audit/<session>.jsonl`

## MCP Server와 Codex 연결 (WBS 5.7)

Codex가 `host/mcp_server.py`를 자식 프로세스로 켜고 stdin/stdout으로 MCP(JSON-RPC)를 주고받는다.
켜지면 Host(wss 서버, 세션 등록, bootstrap 파일 생성)도 함께 시작하므로 `host/sender.py`를 따로 켜지 않는다.

- Codex는 켠 뒤 약 0.5초 안에 도구 목록을 받지 못하면 그 서버의 도구를 빼버린다. 그래서 도구 목록은 표준 라이브러리만으로 즉시 답하고, 무거운 부분(Broker, TLS, wss 서버)은 백그라운드에서 뒤이어 띄운다
- stdout은 MCP 전용이다. 로그는 stderr와 `host/.logs/mcp_server.log`에 남는다
- 오류는 MCP 도구 오류(`isError: true`)로 돌려주고, 내용은 Broker의 표준 오류 JSON이다

### Codex에 연결하기

`~/.codex/config.toml`을 고치지 않고 실행할 때만 붙이는 방법 (PowerShell, 경로는 본인 환경에 맞게):

```powershell
$py = "C:/path/to/host_control/.venv/Scripts/python.exe"
$server = "C:/path/to/host_control/host/mcp_server.py"
codex -s read-only `
  -c "mcp_servers.scrp.command='$py'" `
  -c "mcp_servers.scrp.args=['$server']" `
  -c "mcp_servers.scrp.default_tools_approval_mode='approve'" `
  -c "mcp_servers.scrp.startup_timeout_sec=60"
```

1. 위 명령으로 Codex를 켠다 → MCP Server가 켜지면서 `host/.bootstrap/bootstrap.json`이 새로 생긴다
2. **2분(120초) 안에** Sandbox를 켜서 Runner가 READY가 되게 한다 (Startup 제한시간, 프로토콜 §7). 로그에 `STARTUP OK`가 뜨면 준비 완료
3. Codex에 명령한다. 예: `scrp 도구만 써서 작업을 등록하고, 준비될 때까지 기다린 다음, 화면을 보고 (640, 420)을 클릭하고 '안녕하세요'를 입력해줘`

주의:
- Codex에 기본으로 들어 있는 화면 제어 기능이 대신 나설 수 있으니 명령에 "scrp 도구만 써서"를 넣는다
- `default_tools_approval_mode='approve'`는 시험용으로 모든 도구 호출을 자동 승인한다. 도구마다 `annotations`(읽기 전용·파괴적)가 있으므로 `auto`/`prompt`로 바꾸면 Codex가 입력 도구 호출 전에 사용자에게 묻는다
- 켤 때마다 새 세션(`SES-<날짜>-<시각>`)과 새 token이 만들어진다

## Runner가 접속하는 방법

프로토콜 문서 §4의 Host 측 구현이다. Runner(C++)는 같은 방식으로 접속해야 한다.

1. bootstrap 설정 파일(JSON)을 읽는다. Sandbox 안에서는 읽기 전용 폴더로 들어온다

   | 필드 | 뜻 |
   |---|---|
   | `session_id`, `runtime_id`, `generation` | HELLO에 그대로 넣을 값. 다르면 Host가 거부 |
   | `host` | 접속할 Host 주소 (`--advertise-address`로 준 값). `null`이면 기본 게이트웨이(Windows Sandbox에서는 Host) |
   | `port`, `path` | `17443`, `/scrp/v1/control` |
   | `token` | 1회용 접속 token (256-bit, 5분 유효). **로그에 남기지 말 것** |
   | `token_expires_at` | token 만료 시각 (UTC) |
   | `host_certificate_pem` | 신뢰할 Host 인증서. **이 인증서만 신뢰** |
   | `host_certificate_sha256` | 그 인증서의 SHA-256 지문 (DER 바이트, 소문자 16진수). pinning할 때 이 값과 비교 |
   | `observation_upload` | 스크린샷 업로드 주소 `{"port": 17444, "path": "/scrp/v1/observations/"}`. host는 위와 같은 규칙 |

2. `wss://<host>:<port><path>`로 접속한다. TLS 1.2 이상. 인증서는 `host_certificate_pem` 하나만 신뢰하고,
   주소가 부팅마다 바뀌므로 호스트명 검사는 끈다. 인증서가 다르면 접속하지 않는다. **평문 ws://로 재시도하지 않는다**

   **Host 인증서를 Windows 인증서 저장소에 설치하지 않는다.** 신뢰 루트에 넣으려고 하면 Sandbox를 켤 때마다
   "CA 인증서를 설치하시겠습니까?" 창이 뜨고 (Sandbox는 매번 초기화되므로), 자동 실행이 막힌다.
   대신 연결할 때 직접 비교한다 (pinning). WinHTTP 기준:
   1. 발급 기관 검사만 끈다: `WINHTTP_OPTION_SECURITY_FLAGS`에 `SECURITY_FLAG_IGNORE_UNKNOWN_CA`
   2. 연결된 뒤 서버 인증서를 꺼낸다: `WINHTTP_OPTION_SERVER_CERT_CONTEXT`
   3. 그 인증서 DER 바이트의 SHA-256이 `host_certificate_sha256`과 같은지 비교하고, 다르면 **바로 끊는다**

   1번만 하고 2·3번을 빼면 아무 서버나 믿게 되므로 셋 다 해야 한다. 호스트명 검사를 계속 쓰는 Runner라면
   `--advertise-address`로 준 주소가 인증서 SAN에 들어 있으므로 통과한다 (이때도 인증서를 신뢰시키는 방법이 필요해서 pinning을 권장)
3. WebSocket 업그레이드 요청에 `Authorization: Bearer <token>` 헤더를 넣는다 (URL에 넣지 않는다)
4. 첫 메시지로 HELLO를 보낸다
5. HELLO_ACK의 `channel_credentials.reconnect.token`을 **메모리에만** 보관한다 (재연결용, 1회용)

Startup Verification (WBS 4.5): HELLO_ACK를 받았다고 READY가 아니다. Host가 다음을 차례로 확인한다.

| 항목 | 확인 방법 | 기준 |
|---|---|---|
| version | HELLO `supported_versions` | `1.0` 포함 |
| capabilities | HELLO `capabilities` | `gui.observe`, `gui.input` 포함 (초기값, 협의 대상) |
| monitoring | HELLO `monitoring_coverage` | `file: true` (초기값, 협의 대상) |
| clock | HELLO `timestamp` | Host 시계와 60초 이내 |
| worker | STATE_REQUEST(`action_id: null`) → STATE_RESULT | `worker_alive: true`, FROZEN·TERMINATED 아님 |
| first_capture | OBSERVE → OBSERVE_RESULT | 응답이 오고 `captured_at`이 10초 이내 |
| heartbeat | HEARTBEAT → ALIVE | 응답이 옴 |

앞의 4개(HELLO 검사)는 **HELLO_ACK 전에** 확인하므로 실패하면 재연결 token도 받지 못한다. 재연결 때도 다시 확인한다.
하나라도 실패하면 연결을 1008 `RUNTIME_START_FAILED`로 끊고 세션의 모든 token을 폐기한다. 같은 세션으로는 다시 접속할 수 없다 (새 generation 필요).

연결 중 (WBS 4.4):

- Host가 5초마다 HEARTBEAT를 보낸다. **3초 안에 ALIVE**로 답한다. 연속 2회 누락이면 DEGRADED, 3회면 UNRESPONSIVE로 기록되고 새 Action이 멈춘다
- 연결이 끊기면 (정상 종료 1000, 정책 위반 1008, 교체 4001이 아닌 경우) **1·2·4·8초 간격 + jitter**로 reconnect token을 넣어 다시 접속하고 HELLO부터 다시 시작한다. sequence·message_id 중복 검사는 연결마다 새로 시작한다. 4번 실패하면 멈추고 Host의 복구 판단을 기다린다
- 재연결 후 Host는 결과를 못 받은 Action을 **다시 보내지 않고** STATE_REQUEST로 물어본다. 그래서 Runner는 실행한 action_id와 결과를 **연결이 바뀌어도 기억**해야 한다. 모르는 action_id면 `action_state: null`로 답한다
- 같은 Runtime의 새 연결이 오면 Host는 이전 연결을 close code **4001 (REPLACED)**로 끊는다. 4001을 받으면 재접속하지 않는다
- TERMINATE 이후에는 모든 token이 폐기되어 재접속할 수 없다

스크린샷 업로드 (프로토콜 §8):

1. Host가 OBSERVE에 1회용 `upload_id`를 넣어 보낸다 (256-bit, 30초 유효, 세션·Action에 묶임)
2. Runner는 캡처한 PNG를 `PUT https://<host>:<observation_upload.port><path><upload_id>`로 올린다
   - 헤더: `Content-Type: image/png`, `Content-Length` 필수 (chunked 안 됨), 8 MiB 이하
   - TLS·인증서는 제어 채널과 같다 (`host_certificate_pem` 하나만 신뢰, 호스트명 검사 끔, 평문 http로 재시도하지 않음)
   - 성공하면 `201`. 본문은 Host가 계산한 sha256
3. **업로드가 끝난 뒤** OBSERVE_RESULT(`sha256`, `width`, `height`, `upload_id`)를 보낸다
4. Host가 PNG를 직접 다시 검사한다: PNG 구조(시그니처·IHDR·IEND), 16 MP 이하, sha256·크기가 OBSERVE_RESULT와 같은지.
   맞으면 그때 Agent에게 이미지로 보여준다. 다르면 그 화면은 버리고 `ACTION_FAILED`로 알린다
5. 스크린샷은 Host 메모리에만 있고 (세션당 최근 8장) 세션이 끝나면 지운다. 화면에는 비밀번호도 보일 수 있기 때문

업로드를 안 한 Runner도 동작은 한다. 그때 `computer_observe`는 크기·해시만 돌려준다 (`image_state: MISSING`).

| 업로드 거부 | HTTP |
|---|---|
| 모르는 · 만료된 · 이미 쓴 `upload_id` | 401 |
| 경로가 다름 / PUT이 아님 | 404 / 405 |
| `Content-Length` 없음, chunked | 411 |
| 8 MiB 초과, 16 MP 초과 | 413 |
| `image/png`가 아님, PNG 시그니처가 아님 | 415 |
| PNG가 잘렸거나 CRC가 틀림, IHDR로 시작 안 함 | 400 |
| 헤더 5초 · 본문 15초 안에 다 안 옴 | 408 |

Host가 거부하는 경우:

| 상황 | 결과 |
|---|---|
| token 없음 · 틀림 · 만료 · 이미 사용 | HTTP 401 (이유는 알려주지 않음, Host 로그에만 기록) |
| 경로가 `/scrp/v1/control`이 아님 | HTTP 404 |
| HELLO의 session_id·runtime_id·generation이 token 발급 대상과 다름 | 연결 종료 1008 |
| 같은 연결에서 nonce 또는 message_id 재사용 | ERROR(PROTOCOL_DENIED) 후 연결 종료 1008 |
| 이미 쓴 reconnect token, 더 새 token이 발급된 뒤의 옛 token, TERMINATE 이후의 token | HTTP 401 |
| Startup Verification 실패, 재연결 시 Capability·Monitor 감소 | 연결 종료 1008 `RUNTIME_START_FAILED`, 이후 이 세션 token은 전부 401 |

## 현재 한계

- 인증서는 개발용 자체 서명이다. 운영 인증서 발급·교체는 정해지지 않았다
- Host 1회 실행 = bootstrap 세션 1개. 여러 세션 동시 관리는 Lifecycle Manager(WBS 3.2·3.3)와 연결할 때 한다
- Workspace 준비(매핑 폴더 등) 확인은 Startup Verification에 없다. Sandbox 기동 쪽(WBS 3.2·3.3)과 연결 필요
- 세션 상태·검사 결과는 `RuntimeSession.status()`로 조회한다. 아직 파일·API로 내보내지 않는다 (Dashboard는 K 파트)
- Health 변화는 로그와 콜백(`on_health`)으로만 알린다. 받아서 재시작·Reset을 결정할 Runtime Manager(명세서 D-7·D-9)는 아직 없다
- reconnect token은 1시간 유효하고 연결 중 갱신 메시지가 없다. 1시간 넘게 연결된 뒤 끊기면 Lifecycle Manager가 bootstrap을 다시 발급해야 한다
- HELLO_ACK의 telemetry token은 발급만 하고 아직 쓰지 않는다
- Action timeout(연속 Timeout → Health 저하, 명세서 E-6)은 아직 Health에 반영하지 않는다. Heartbeat 누락만 반영
- 데모(`--demo protocol`)는 Broker를 거치지 않고 세션을 직접 부른다. `--demo broker`가 실제 경로다
- Broker의 정책 규칙은 초기값이다. FORCE_SANDBOX·FORCE_VM 같은 실행 위치 결정은 Translator(WBS 7.x, 8.8) 몫이라 아직 없다
- 스크린샷 안의 글자로 Agent를 속이는 경우(화면 프롬프트 인젝션) 검사는 아직 없다. `ObservationUploads`의 `inspectors`에 W8~9 탐지기가 들어올 자리만 있다
- 스크린샷은 원본 크기 그대로 Agent에게 간다 (Sandbox 화면 2048×1232 기준 약 2.5 MB). AI 비용이 문제가 되면 줄여서 보내고 좌표를 원본으로 환산하는 기능을 넣는다
- Artifact(파일) 업로드 경로 `/scrp/v1/artifacts/`는 아직 없다
- MCP Server 1개 = 세션 1개. Codex를 다시 켜면 새 세션이 만들어지고 Sandbox도 다시 접속해야 한다
- 승인 Workflow(B-8)는 `approver` 콜백 자리만 있다. 사용자에게 묻는 UI는 없으므로 승인 필요 도구는 지금은 거부된다
