# host_control

Host에서 Agent 요청을 통제·전달하는 프로그램.
AI Agent(Codex)의 요청을 검사해서 격리된 Sandbox 안의 Runner(`b-hamo/sandbox_runner`)로 전달하고,
돌아온 결과를 검증한다.

```
Codex ──MCP──▶ [ MCP Server ] ──▶ [ Broker ] ──▶ [ RuntimeSession ] ──WSS──▶ [ Runner ]
                  5.7 예정        host/broker.py   host/runtime_session.py      sandbox_runner
                                  (도구 호출 검사)  (연결·재연결·READY 관리)      Sandbox 안
```

## 현재 포함된 것

| 경로 | 내용 | WBS |
|---|---|---|
| `host/sender.py` | Host 송신기. Runner 접속 수락, 인증, 데모 실행 | 3.4, 4.6 |
| `host/broker.py` | Broker 코어: 도구 호출 검사 → SCRP 메시지로 변환 → 결과·오류 정규화 | 5.6 |
| `host/tool_catalog.py` | 도구 13개 목록, 입력 스키마 검사, 이 세션에서 쓸 수 있는 도구만 노출 | 5.6 |
| `host/policy.py` | 중앙 정책: ALLOW / REQUIRE_APPROVAL / DENY + 규칙 ID | 5.6 |
| `host/audit.py` | 감사 로그 (호출마다 1줄, 입력 글자는 가림) | 5.6 |
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

## 실행

Python 3.11 이상.

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
5. Runner가 접속하면 **Startup Verification**을 한 뒤에만 READY (아래). 등록 후 120초(`--startup-timeout`) 안에 READY가 안 되면 세션 실패

Runner가 접속해 HELLO를 보내면 데모 순서(화면 관찰 → 클릭 → 입력 → 생존 확인 → 상태 조회 → 종료)를
실행하고 결과를 출력한다. `--no-demo`는 핸드셰이크와 Heartbeat만 하고 대기한다.
bootstrap token은 한 번 쓰면 끝이므로, 새 세션을 시작하려면 Host를 재시작해 새 token을 받는다.
연결이 끊긴 경우의 재접속은 HELLO_ACK로 받은 reconnect token으로 한다 (아래).

Windows Sandbox에서 접속받으려면 Host 방화벽에서 TCP 17443 인바운드를 허용해야 한다.

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

## Runner가 접속하는 방법

프로토콜 문서 §4의 Host 측 구현이다. Runner(C++)는 같은 방식으로 접속해야 한다.

1. bootstrap 설정 파일(JSON)을 읽는다. Sandbox 안에서는 읽기 전용 폴더로 들어온다

   | 필드 | 뜻 |
   |---|---|
   | `session_id`, `runtime_id`, `generation` | HELLO에 그대로 넣을 값. 다르면 Host가 거부 |
   | `host` | Host 주소. `null`이면 기본 게이트웨이(Windows Sandbox에서는 Host) |
   | `port`, `path` | `17443`, `/scrp/v1/control` |
   | `token` | 1회용 접속 token (256-bit, 5분 유효). **로그에 남기지 말 것** |
   | `token_expires_at` | token 만료 시각 (UTC) |
   | `host_certificate_pem` | 신뢰할 Host 인증서. **이 인증서만 신뢰** |

2. `wss://<host>:<port><path>`로 접속한다. TLS 1.2 이상. 인증서는 `host_certificate_pem` 하나만 신뢰하고,
   주소가 부팅마다 바뀌므로 호스트명 검사는 끈다. 인증서가 다르면 접속하지 않는다. **평문 ws://로 재시도하지 않는다**
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
- `computer_observe`는 화면 메타데이터(크기·해시)만 돌려준다. PNG 자체를 받는 업로드 경로(프로토콜 §8)는 아직 없다
- 승인 Workflow(B-8)는 `approver` 콜백 자리만 있다. 사용자에게 묻는 UI는 없으므로 승인 필요 도구는 지금은 거부된다
