# host_control

Host에서 Agent 요청을 통제·전달하는 프로그램.
AI Agent(Codex)의 요청을 검사해서 격리된 Sandbox 안의 Runner(`b-hamo/sandbox_runner`)로 전달하고,
돌아온 결과를 검증한다.

```
Codex ──MCP──▶ [ MCP Server + Broker ] ──▶ [ Host 송신기 ] ──WSS──▶ [ Runner ]
                  W5 예정                   host/sender.py          sandbox_runner
                                           (현재 포함)              Sandbox 안
```

## 현재 포함된 것

| 경로 | 내용 | WBS |
|---|---|---|
| `host/sender.py` | Host 송신기. Runner 접속 수락, 제어 메시지 전송, 응답 검증 | 3.4, 4.6 |
| `host/session_registry.py` | 세션 등록부. 세션별 1회용 bootstrap token 발급·확인 | 4.6 |
| `host/tls.py` | TLS 설정(최소 TLS 1.2), 개발용 자체 서명 인증서 생성 | 4.6 |
| `host/bootstrap.py` | Runner가 읽을 bootstrap 설정 파일 생성 | 4.6 |
| `scrp/validate.py` | 메시지 검증기 (크기·인코딩·스키마) | 2.2 |
| `scrp/envelope.py` | 메시지 봉투 생성기 (ID·sequence·nonce·timestamp) | 2.2 |
| `schema/` | Host ↔ Runner 메시지 규격. **Runner도 이 파일을 기준으로 구현** | 2.2, 2.3 |
| `tests/` | 인증·TLS·replay 거부 자동 테스트 | 4.6 |

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

Runner가 접속해 HELLO를 보내면 데모 순서(화면 관찰 → 클릭 → 입력 → 생존 확인 → 상태 조회 → 종료)를
실행하고 결과를 출력한다. `--no-demo`는 핸드셰이크만 하고 대기한다.
token은 한 번 쓰면 끝이므로, 다시 접속하려면 Host를 재시작해 새 token을 받는다.

Windows Sandbox에서 접속받으려면 Host 방화벽에서 TCP 17443 인바운드를 허용해야 한다.

테스트:

```bash
.venv/Scripts/python.exe -m pip install pytest
.venv/Scripts/python.exe -m pytest -q tests
```

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

Host가 거부하는 경우:

| 상황 | 결과 |
|---|---|
| token 없음 · 틀림 · 만료 · 이미 사용 | HTTP 401 (이유는 알려주지 않음, Host 로그에만 기록) |
| 경로가 `/scrp/v1/control`이 아님 | HTTP 404 |
| HELLO의 session_id·runtime_id·generation이 token 발급 대상과 다름 | 연결 종료 1008 |
| 같은 연결에서 nonce 또는 message_id 재사용 | ERROR(PROTOCOL_DENIED) 후 연결 종료 1008 |

## 현재 한계

- 인증서는 개발용 자체 서명이다. 운영 인증서 발급·교체는 정해지지 않았다
- Host 1회 실행 = 세션 1개. 여러 세션 동시 관리는 Lifecycle Manager(WBS 3.2·3.3)와 연결할 때 한다
- HELLO_ACK의 telemetry·reconnect token은 발급만 하고 아직 쓰지 않는다. 재연결은 4.4
- Heartbeat는 1회만 주고받는다. 주기 전송과 재연결은 4.4
- task_id·action_id를 송신기가 임시로 발급한다. W5에 Broker(명세서 B-4)로 옮긴다
