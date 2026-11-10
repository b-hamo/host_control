# host/ — Host 쪽 코드 안내

micro_VM 앱 창 연결은 `mcp_server.py`의 Manager 선택, `lifecycle.py`의 Guest 경로,
`inbox_download.py`의 입력 위치, `sandbox_run.py`의 전송 대기·결과 판정에서 처리한다.
[구성과 검증 절차](../docs/micro-vm-app-window.md)를 따른다.
`tests/test_micro_vm_transport.py`는 전송 해시·명령 제한과 중복 결과의 검사/충돌 처리를 검증한다.
`--auto-vm-app-window`는 앱 창 제한에 동의한 구성에서만 자동 배정을 사용한다.
Manager 선택 후 `sandbox_run.py`에 실제 Guest 입력 경로를 연결하며,
`lifecycle.py`는 고정 VM의 통신 장애를 자동 종료·재생성으로 처리하지 않는다.
실제 혼합 실행과 미완료 복구 항목은 [후속 검증 보고서](../docs/mixed-vm-followup-20261108.md)에 구분했다.
전송 중 장애 복구, 최초 자동 WSB listener, 설치 Manager 및 동시 한도 거부의 최신 결과는
[2026-11-09 검증](../docs/mixed-vm-hardening-20261109.md)을 따른다.
`output_export.py`/`artifacts.py`의 재연결 reset과 수신 중 취소는 `test_output_export.py`/`test_artifact_export.py`에서,
선택적 설치 backend·바이너리 pin·세션 경로는 `test_solution_config.py`에서 검증한다.
관리 서비스 바이너리·설정 pin 및 배포 복구 설정도 같은 테스트에서 검사한다.
`solution.py`는 다중 VM 프로필의 채팅 전용 매핑을 먼저 만든 뒤 그 경로에서 실행 차단을 검사한다.
기존 WSB가 매핑한 공용 inbox에는 probe를 쓰지 않는다. `test_solution.py`에서 실제 Host 인자와
검사 경로 일치, 두 클라이언트 격리, inbox·output·검사 서비스 실패 시 시작 거부를 검증한다.
일반 권한 Host의 실제 B·C 화면·입력·반출 결과는 [관리 서비스 검증](../docs/management-service-validation-20261109.md)에 있다.

Agent(Codex)의 요청을 받아 검사하고, 격리된 Sandbox 안의 Runner로 전달하는 Host 프로그램이다.
핵심 파일은 **4개 층**으로 나뉘어 있고, 요청은 위층에서 아래층으로 흐른다.
Router 부품(`router_*.py`)과 통합 솔루션(`solution*.py` 등)은 층 표 아래에 따로 정리했다.

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
│  inbox_download.py   (받는 폴더로 내려받기)                │
│  sandbox_run.py      (받은 파일을 Sandbox에서 실행)        │
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
| `tool_catalog.py` | `schema/mcp-tools/`의 도구 22개를 읽고, 입력값을 규격(타입·필수·범위·모르는 필드)으로 검사한 뒤 생략된 값을 기본값으로 채운다 | 5.6 |
| `mcp_runtime.py` | 오래 연결된 stdio MCP 뒤에서 실제 실행 Host를 필요할 때 켜고 바꾼다. 끝난 세션은 새 작업 요청으로만 대신하고, 조회·GUI 호출은 작업을 다시 돌리거나 다른 프로세스의 포트를 가져오지 않는다 (#54) | 5.7 |
| `single_host.py` | 이전 통합용 무동작 호환 API. 다른 채팅의 Host 종료와 Sandbox 회수를 하지 않는다. 포트 충돌은 시작 실패로 보고한다 (#113) | 5.7 |

## ② 요청을 검사하는 층 (Broker)

| 파일 | 하는 일 | WBS |
|---|---|---|
| `broker.py` | **모든 도구 호출의 입구 `Broker.call()`.** 도구 확인 → 입력 검사 → 세션 상태 → 호출 빈도 → 정책 → 좌표·화면 신선도 → Action ID 발급 → SCRP 메시지로 번역·전송 → 오류 정리 → 감사 로그. 하나라도 걸리면 Runner로 보내지 않는다. 입력은 절대 재전송하지 않는다 | 5.6 |
| `policy.py` | 보안 규칙. 요청마다 ALLOW / REQUIRE_APPROVAL / DENY와 규칙 ID를 정한다 (예: Win+X 거부 `P-DENY-HOTKEY`, Win+R 허용). 나중에 Translator의 판단이 들어올 자리 | 5.6 |
| `audit.py` | 호출마다 JSON 한 줄 기록 (`host/.audit/<session>.jsonl`). `computer_type`의 글자는 길이와 SHA-256만 남긴다 | 5.6 |

## ③ 세션을 관리하는 층

| 파일 | 하는 일 | WBS |
|---|---|---|
| `runtime_session.py` | 연결이 끊겨도 이어지는 세션. 5초마다 HEARTBEAT, 연속 2회 누락 DEGRADED · 3회 UNRESPONSIVE. 끊길 때 결과를 못 받은 Action은 재전송하지 않고 재접속 후 STATE_REQUEST로 확인. task_id·action_id 발급, 마지막 화면과 받은 시각 보관, `status()`로 상태 조회 | 4.4, 4.5 |
| `inbox_download.py` | `inbox_download` 도구의 본체. 공개 https만, 확인한 IP로 접속(DNS rebinding 차단), 리다이렉트마다 검사, 크기·개수 한도, 다 받은 뒤에만 받는 폴더로, MOTW 표시, zip은 Host에서 안 풂. 받는 폴더가 Host에서 실행 금지인지 시작 때 시험 | 5.9 |
| `local_compile.py` | `router_execute`의 컴파일 형식(`c-source`·`cpp-source`·`go-source`·`zig-source`·`java-source`·`csharp-source`). 파일 하나짜리 코드를 이 PC 컴파일러로 빈 임시 폴더에서 번역만 함(실행 안 함), 결과만 Sandbox에서 실행. 다른 파일을 읽게 하는 코드(UNC·절대 경로·`..`·`#embed`·`.incbin`·인라인 어셈블리·`@cImport`·`#:package`)는 거부, 전처리 뒤 읽은 파일은 컴파일러 폴더 안만. Java·C#은 java·dotnet을 빌려 실행. 컴파일러가 없으면 설치 안내 | 7.x |
| `sandbox_project.py` | `sandbox_run`의 프로젝트 zip(②). Host는 zip의 이름 목록만 읽고 표시 파일(go.mod·package.json·*.csproj·CMakeLists.txt·Gemfile·requirements.txt 등)로 정해진 순서를 고름. 도구는 program_share로 빌려주고, Sandbox가 실행할 PowerShell 하나를 만듦: zip 도착(SHA-256) 확인 → tar 풀기 → 라이브러리 설치 → 빌드 → 실행. Agent는 파일·entry·인자만 고름. Rust·Maven/Gradle·make는 아직 | 7.x |
| `signature_check.py` | `--signed-downloads`의 서명 검사. exe·msi만. 기본은 공인 서명이면 제작사와 상관없이 통과(Windows 11 Smart App Control과 같은 기준), `--trusted-publishers`로 좁힘(B2B). 다른 코드를 실행하는 프로그램(Microsoft 권장 차단 목록 + 인터프리터)과 원격 제어 도구는 이름·버전 정보의 원래 이름·서명자로 제외, 서명 뒤·서명 표 안에 덧붙인 바이트 거부(CVE-2013-3900), 루트는 이 PC의 컴퓨터 저장소만, 폐기 확인(10초 안에 못 하면 불신). "신뢰"는 안전이 아니라 "공인된 유효한 서명" | 5.9 |
| `exec_guard.py` | 에이전트 hook(Codex·Claude Code PreToolUse). 셸 명령·파일 수정을 실행 **직전에** 규칙으로 검사: 밖에서 온 파일(인터넷 표시 Zone.Identifier, 다운로드 폴더, inbox)의 실행·복사·압축 풀기 차단(서명 검사를 통과한 exe·msi만 예외), 받아서 바로 실행(`iwr | iex`, `curl | sh`, `-EncodedCommand`, mshta·regsvr32·msiexec URL) 차단, hook·에이전트 설정 수정과 Defender 끄기·예외 추가 차단. 차단은 `%LOCALAPPDATA%\SCRP\exec_guard.jsonl`에 기록. `install --codex --claude`로 등록. 명령 문자열 검사라 난독화는 못 막음(inbox 실행 금지와 함께 쓰는 한 겹) | — |
| `dashboard_status.py` | `--dashboard-dir`: 이 Host가 하는 일을 로컬 대시보드(`dashboard/`)가 읽게 세션마다 `hosts/<세션>.json`(맡은 일, 마지막 도구·파일 이름, Sandbox 창 상태 2초 갱신, sandbox root, micro VM 상한)과 `.png`(Agent가 마지막으로 본 화면)로 남긴다. 입력한 글자·URL 쿼리·그 밖의 인자는 쓰지 않고, Host가 끝나면 화면 파일을 지운다. 통합 설치가 켠다 | — |
| `sandbox_run.py` | `sandbox_run`·`sandbox_run_status` 본체 (`--sandbox-run`). 이 세션에서 받은 파일만, Host가 받을 때 남긴 해시가 출처. 정확한 명령에 묶인 Router `Authority` 위임을 이번 한 번 만들고(승인 창 없음, 기록), `RouterGuiPolicy`로 Win+R·한 줄·Enter만 허용(Enter 직전 재확인). 도우미 `sandbox_run_guest.ps1`과 명령서는 받는 폴더로 전달, 결과는 Guest 영수증을 반출 검사로 확인 | 7.x |
| `artifacts.py` | 파일 반출 전송 (artifact-export-v1). 후보 등록·artifact_id → 일회용 업로드 권한 → ARTIFACT_REQUEST → 수신 기록과 ARTIFACT_RESULT 대조. Output 사전 수신은 검사 전 임시 보관이며, 공개는 CLEAN 검사 후 자동 진행한다. 종료 때 미완료 전송을 취소하고 검증된 Output 수신본은 보존한다 | 5.8 |
| `artifact_scan.py` | 반출 전 검사. 형식 정책(UTF-8 `.txt`) + 백신. 기본은 검사기 없음 = 차단. AMSI는 EICAR 자체 시험을 통과해야만 사용. `defender-service`는 SecureArtifactScanner 서비스의 상태 확인·검사 결과 해석 | 5.8 |
| `scanner_client.py` | `defender-service`의 Named Pipe 클라이언트: 업로드 청크 전송·검사·상태·공개·취소, 응답 ID·Job 신원 확인, 서비스 PID 확인, 모든 호출을 작업 스레드에서 | 5.8 |
| `shared_scanner.py` | 기존 파일명을 유지한 공통 검사·공개 처리. Output 수신본을 잠근 채 검사 서비스 격리·Defender 검사 → CLEAN 확인 → 다운로드 복사를 수행한다. 검사기 대체나 Shared 매핑은 사용하지 않는다 | 5.8 |
| `output_export.py` | Output 단일 반출. 후보 사전 수신·영수증 보관, 전체 잠금 목록 확보·해시 대조·종료 전 확인, CLEAN 자동 다운로드 저장·MCP 결과 응답을 연결한다. 확보 실패 시 정상 종료를 막고 파일을 보류한다 (#105, #109) | 5.8 |
| `approval.py` | 종료·inbox·레거시 반출의 사용자 확인 창. 통합 Output 자동 반출은 목록 확인·최종 보관·결과 알림 창을 호출하지 않는다 | 5.6 |
| `lifecycle.py` | Sandbox 켜고 끄기 (Lifecycle 담당의 Sandbox Manager 호출). `task_submit` 때 백그라운드로 켜기 시작 → Sandbox가 보는 Host 주소로 인증서·bootstrap 작성 → READY면 token 파일 삭제 → 세션이 끝나면(정상·실패·Codex 종료) 끄고 치운다. Runner가 응답이 없으면 같은 Sandbox에서 Runner만 다시 켜거나 Sandbox를 새로 켠다(다음 세대). `mcp_server.py --runner-exe`일 때만 쓴다 | 5.9 |
| `startup.py` | Startup Verification. Runner가 "준비됐다"고 해도 Host가 7가지(버전·Capability·Monitor·시계 / Worker 생존·첫 캡처·Heartbeat)를 확인한 뒤에만 READY. 등록 후 120초 안에 안 되면 실패 | 4.5 |

## ④ Sandbox와 통신하는 층

| 파일 | 하는 일 | WBS |
|---|---|---|
| `sender.py` | wss 서버를 열고 Runner 접속을 받는다. 업그레이드 전에 token 확인(401/404), HELLO를 받으면 token을 사용 처리하고 세션에 연결. 시험용 데모(`--demo protocol` / `--demo broker`)도 여기 있다 | 3.4, 4.6 |
| `telemetry.py` | Telemetry 채널 `/scrp/v1/telemetry` (artifact-export-v1 세션만). 전용 1회용 token, CHANNEL_HELLO/ACK, 후보 SECURITY_EVENT → EVENT_ACK(STORED/REJECTED) | 5.8 |
| `connection.py` | 연결 1개. 받은 메시지를 검사(세션 신원, connection_id, sequence, message_id·nonce 중복, 시계 오차)하고 요청·응답을 짝 맞춘다. 끊기면 버리고 새로 만든다 | 3.4 |
| `session_registry.py` | 1회용 token 발급·확인·폐기. 처음 접속용(bootstrap, 5분)과 재접속용(reconnect, 새로 받으면 이전 것 폐기), Telemetry용(telemetry, 8시간: Runner가 연결 중에도 만료를 검사해 끊기 때문에 세션보다 길게. 여전히 1회용). 채널마다 자기 종류의 token만 받는다. TERMINATE 시 전부 폐기 | 4.6, 4.4 |
| `tls.py` | TLS 설정(최소 1.2)과 개발용 자체 서명 인증서 생성 (`host/.certs/`) | 4.6 |
| `bootstrap.py` | Runner가 읽을 접속 안내서 `host/.bootstrap/bootstrap.json` 생성 (세션 값, 포트·경로, token, Host 인증서, 스크린샷 업로드 주소) | 4.6 |
| `upload_server.py` | 스크린샷을 받는 작은 HTTPS 서버 (17444, `PUT /scrp/v1/observations/<upload_id>`). 제어 채널과 같은 인증서. 크기 제한·시간 제한을 본문을 읽기 전에 건다. WebSocket 라이브러리가 요청 본문을 못 받아서 포트를 따로 쓴다. artifact-export-v1이면 같은 서버에 파일 반출 경로 `PUT /scrp/v1/artifacts/<upload_id>`(Bearer token, 디스크 스트리밍, 빈 201)가 따로 붙는다 | 5.6, 5.8 |
| `observation_store.py` | 1회용 upload_id 발급(30초), 받은 PNG 검사(구조·16 MP·sha256), OBSERVE_RESULT와 맞는지 대조. 맞은 화면만 메모리에 두고(세션당 8장) 세션이 끝나면 지운다 | 5.6 |
| `__init__.py` | 비어 있음. `host`를 Python 패키지로 인식시키는 표시 | - |

같이 쓰는 저장소의 다른 곳:
- `scrp/validate.py`: 모든 메시지를 크기·인코딩·스키마로 검사
- `scrp/envelope.py`: 메시지 봉투(ID·sequence·nonce·timestamp) 생성
- `schema/`: Host ↔ Runner 메시지 규격, `schema/mcp-tools/`: Codex 도구 규격

## Router 부품

`router/`의 Router 엔진(engine·models·ports, Host를 모르는 순수 도메인)을 Host에 연결하는 어댑터다.
#32에서 독립 Router로 들어왔고 #94에서 SCRP MCP 하나로 합쳐졌다. `sandbox_run`·`router_capture`·`router_execute`가
이 부품을 쓴다. 설계는 [docs/unified-router-design.md](../docs/unified-router-design.md)에 있다.

| 파일 | 하는 일 | WBS |
|---|---|---|
| `router_capture.py` | `router_capture` 본체 (`--router-capture`). 웹 페이지에서 본 명령 글자를 신뢰하지 않는 데이터로 보관한다. AI가 본 글자와 Host가 직접 읽은 클립보드를 따로 해시하고, URL을 열거나 무엇을 실행하지 않는다 | 7.x |
| `router_command_intake.py` | 클립보드 글자를 분석용 데이터로 바꾸는 순수 변환. 지원하지 않는 형태는 보류로 남고, 어떤 분류 결과도 Host 실행을 허가하지 않는다 | 7.x |
| `router_authority.py` | Host가 가진 출처·위임 기록. Agent의 주장과 분리되며, 신뢰된 Host 구성 코드에서만 채운다 | 7.x |
| `router_gateway.py` | Router가 관리하는 요청에 대한 Host의 최종 결정과 실행 경계 | 7.x |
| `router_gui_policy.py` | 위임받은 정확한 Guest 명령 실행 순서만 허용하는 선택형 정책. 기본 `Policy`를 바꾸지 않고, 다른 규칙의 DENY는 그대로 DENY | 7.x |
| `router_gui_driver.py` | Manager 입력 파일과 검사한 실행 영수증으로 Guest 명령을 실행하는 GUI 드라이버. 영수증은 Guest 쪽 증거일 뿐 하드웨어 증명이 아니다. Host에서는 아무것도 실행하지 않는다 | 7.x |
| `router_command_bundle.py` | 정확한 Windows 프로세스 요청을 실행되지 않는 Manager 입력 파일로 만든다. Host 서브프로세스가 없고 인자를 셸로 해석하지 않는다 | 7.x |
| `router_inputs.py` | Host가 확인한 Router 입력 파일을 Sandbox Manager의 읽기 전용 입력 API에 묶는 어댑터. Agent는 Host 경로를 넘길 수 없다 | 7.x |
| `router_sandbox.py` | Broker의 수명주기·반출을 재사용하는 Sandbox 실행 포트. 키보드 ACK를 명령 종료로 보지 않는다. 드라이버가 없으면 Sandbox를 켜기 전에 보류 | 7.x |
| `router_ledger.py` | Host 전용 영속 멱등성 기록. 명령·글자·원본 오류는 남기지 않는다 | 7.x |
| `router_local.py` | 고정된 Local 데이터 도구. 루트는 Host 소유의 데이터 전용 폴더여야 하고, 프로세스 API는 없다 | 7.x |

## 통합 솔루션

`installer/`의 통합 설치가 Codex에 등록하는 진입점과 그 설정·검증 도구다. 설치와 갱신은
[docs/solution-install.md](../docs/solution-install.md), Output 반출은 [docs/output-only-export.md](../docs/output-only-export.md)에 있다.

| 파일 | 하는 일 | 이슈 |
|---|---|---|
| `solution.py` | Host·Manager·Runner를 묶은 진입점. 설치기가 만드는 Codex MCP 설정이 이 파일을 켠다. 검사 서비스가 필수이고 로컬 검사기로 대체하지 않는다. 시작 전에 경로(사용자 폴더·OneDrive와 분리)와 서비스 상태를 확인한다 | #99 |
| `solution_config.py` | 옮겨 쓸 수 있는 설치 프로필과 Codex MCP 등록. 등록하면서 다른 설정이 하나라도 바뀌면 거부한다 (표준 라이브러리만) | #101 |
| `solution_session.py` | 일반 사용자 권한의 MCP 클라이언트. 단독 시작과 대화형 반출 검증에 쓴다. Sandbox 닫기와 남기기·지우기 선택은 사람이 실제 Host 창에서 한다 | #101 |
| `unified_verification.py` | 실제 MCP·Manager·Runner·검사 서비스와 사람의 확인 창으로 하는 대화형 검증. 다른 시험용 Sandbox를 닫고 돌린다. 창에 대신 답하거나 VM을 끄지 않는다 | #103 |
| `output_verification.py` | 한 검증 세션을 유지하는 일반 사용자 MCP 진단 클라이언트. 요청 결과와 화면을 증거 폴더에 기록하며, 승인 창을 우회하거나 입력 종료만으로 VM을 끄지 않는다 | #105 |

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
| 새 도구 추가, 도구 입력 규칙 변경 | `schema/mcp-tools/*.json` → `broker.py`의 `OPERATIONS`·`translate()` (같이 고칠 곳 전체는 [AGENTS.md](../AGENTS.md) 규칙 1) |
| 보안 규칙 추가 (차단할 요청) | `policy.py` |
| 호출 빈도 제한 변경 | `broker.py`의 `RATE_LIMITS` |
| 다른 채팅의 Host·VM 보존 | `mcp_server.py`, `mcp_runtime.py`, `single_host.py`(무동작 호환 API), Manager의 배정 잠금 |
| 오류별로 Agent에게 안내할 다음 행동 | `broker.py`의 `ERROR_HINTS` |
| READY 전에 확인할 항목 | `startup.py`의 `StartupProfile`, `check_hello()`, `verify_runtime()` |
| Heartbeat 간격, 이상 판정 기준 | `runtime_session.py` 위쪽 상수 |
| token 유효시간 | `session_registry.py`의 `TOKEN_TTL_S`, `RECONNECT_TTL_S` |
| Runner에게서 받는 메시지 검사 | `connection.py`의 `check()`, `scrp/validate.py` |
| Output 수신·종료 전 확보·중복 방지·자동 검사와 MCP 결과 | `output_export.py`, `artifacts.py`, `shared_scanner.py`, `lifecycle.py`, `mcp_runtime.py`, `mcp_server.py` |
| Output 바로가기와 잠금 목록 계약 | sandbox_runner의 `output_shortcut`·`output_snapshot`, `schema/payload/OUTPUT_SNAPSHOT_*.schema.json` |

## 테스트

| 테스트 파일 | 확인하는 것 |
|---|---|
| `tests/test_auth.py` | TLS, token(없음·틀림·만료·재사용·다른 세션), nonce 재사용, 로그에 token 노출 |
| `tests/test_heartbeat_reconnect.py` | Health 전이, 재접속 token, 연결 교체, 끊긴 Action 재동기화 |
| `tests/test_startup.py` | 정상 승격, 고장 Runner 거부, 시간 초과, 시계 오차 |
| `tests/test_broker.py` | 검사별 거부, 정책, 빈도 제한, 감사 로그 마스킹, 도구 규격 ↔ 프로토콜 교차 검사 |
| `tests/test_mcp_server.py` | 실제 자식 프로세스로 기동, 도구 목록 속도, Codex → Runner 전 구간, 스크린샷이 MCP image로 전달 |
| `tests/test_single_host.py` | 이전 HostBackend 진입점도 다른 Host·부모 프로세스·VM을 종료하거나 회수하지 않음 |
| `tests/test_observation_upload.py` | upload_id(1회용·만료), PNG 검사, HTTPS 수신 거부 코드, 해시·크기 대조, 조작된 업로드 차단, 세션 종료 시 삭제 |
| `tests/test_sandbox_recovery.py` | Runner만 다시 켜기, 창 닫힘은 다시 안 켬, 먹통이면 Sandbox 새로 켜기, 실패 시 넘어가기·종료, 옛 세대 token 거부, 실제 Sandbox Manager로 재시작 확인 |
| `tests/test_sandbox_launch.py` | task_submit에 Sandbox 켜기(바로 PREPARING), READY 대기, 켜기 실패·시간 초과·Codex 종료 시 끄고 정리, Lifecycle의 실제 Sandbox Manager로 파일 전달 확인 |
| `tests/test_local_compile.py` | 컴파일 형식: 다른 파일 읽기 거부(UNC·절대·`..`·`#embed`·어셈블리), 읽은 파일 확인, 컴파일 결과가 실행 입력(캡처가 부모), C#은 빌린 dotnet과 SDK runtimeconfig, 컴파일러 오류·없음 |
| `tests/test_sandbox_project.py` | 프로젝트 zip: 표시 파일로 순서 결정, 지원 안 함·entry 없음·위험한 이름 거부, 스크립트가 zip 지문을 기다리고 정해진 순서만 실행, 스크립트가 실행 입력(zip이 부모), 도구 모두 빌려주기 |
| `tests/test_sandbox_run.py` | 받은 파일 실행: 받은 파일만·정확한 명령 표시·바뀐 파일 거부, 실행은 세 입력만(Win+R은 `POL-0.1.1`부터 Agent에게도 허용), Enter 직전 파일·도우미 변조 시 Enter 안 보냄, 영수증 대조, 자기 결과만 승인 없이 반출, MCP 전 구간(승인 창 없음·감사·도우미 삭제), 옵션 |
| `tests/test_inbox_download.py` | 내려받기: 공개 https만·사설/메타데이터 주소 거부, 확인한 IP로만 접속(두 번째 DNS 없음), 리다이렉트 검사, 크기·개수 한도, 이름 정리·덮어쓰기 없음·MOTW, zip 안 풂, 실행 금지 시험, MCP 경로(정책·감사·쿼리 제거·받는 폴더 연결·감시 시작/종료), 잘못된 옵션 |
| `tests/test_signature_check.py` | 서명 판정(스크립트·인터프리터·Microsoft 권장 차단 목록·원격 제어 도구 제외, 무효·폐기·확인 불가·사용자 루트 거부, 시간 초과, 기본은 공인 서명이면 통과·`--trusted-publishers`로 좁힘), 실제 Windows: Microsoft 서명 프로그램 통과, 이름 바꾼 python 거부, 서명 뒤·표 안 덧붙임 거부, `--signed-downloads`로 신뢰된 것만 다운로드 폴더에 |
| `tests/test_exec_guard.py` | 받아서 바로 실행 차단, 다운로드·inbox·인터넷 표시 파일 실행·복사·압축 풀기 차단과 서명 통과 exe 허용, 읽기만 하는 명령 허용, 읽어서 iex로 넘기면 차단, hook·설정·Defender 보호, Codex·Claude Code 입력 형식과 차단 출력, 판단 못 하면 차단, 설치가 기존 hook을 지키고 다시 돌려도 하나만 |
| `tests/test_dashboard.py` | 대시보드 overview가 프론트 계약대로(세션 상태·VIOLATION·risk_type·Host가 알려 준 root·micro VM 상한), VM CPU 계산과 관리자 아님, 서버 토큰·Host 헤더·읽기 전용·경로 탈출, Host 상태 파일에 글자·URL 쿼리가 안 남음, 실제 MCP Host가 상태와 화면을 남기고 끝나면 지움, 통합 설치가 켬 |
| `tests/test_scanner_client.py` | `scanner_client.py`를 스크립트형 가짜 파이프 서버로: 다른 요청·다른 Job의 응답, 끊김·무응답, 서비스 없음, 이벤트 루프 비차단, 종료 전 ABORT 완료 |
| `tests/test_scanner_security.py` | `defender-service`의 공격·장애: 업로드 중단, 파이프 단절, 한도·용량, 승인 없음, 다른 세션·세대, 공개 중 취소·실패, 공개 파일 ACL, 링크, Host 종료 |
| `tests/test_scanner_integration.py` | 실제 Windows (환경 변수로 켬): MpCmdRun 판정 근거, 설치된 서비스를 일반 사용자로(ACL·패키징·전 구간), 관리자로(중지·강제 종료·재설치). `scanner_service/README.md` §18 |
| `tests/test_artifact_scanner_service.py` | `defender-service` 반출: HTTPS → 파이프 → 서비스 Job(프로세스 안 서비스, 가짜 Defender), 한글·빈·큰 파일, 판정별 차단, 시간 초과, 해시 불일치, 서비스 없음·다른 공개 폴더·중간 중단, 수신 규칙, 결과 불일치, 채널 끊김·세션 종료, 재공개 거부. `SCANNER_SERVICE_TESTS=1`이면 설치된 실제 서비스로 정상 TXT·EICAR |
| `tests/test_artifact_export.py` | 파일 반출: Runner 계약 예제 14개, bootstrap 선택, token 종류 분리, Telemetry 없으면 READY 안 됨, 중복 후보, 한글·빈 파일 반출(바이트·해시 일치, 빈 201), 승인 거부, 검사 통과·차단·오류·시간 초과·형식, Runner 거부·결과 불일치·결과 없음, 채널·연결 끊김·세션 종료 취소, 수신 거부 코드, AMSI EICAR 자체 시험 |
| `tests/test_repo_rules.py` | 저장소 규칙([AGENTS.md](../AGENTS.md)): 코드가 비교하는 도구 이름·도구 표·거부 단축키가 도구 규격과 맞는지, Agent에게 가는 오류 코드마다 `ERROR_HINTS`가 있는지, 패키지 의존 방향, 한글 .ps1의 BOM, README의 도구 수와 모듈 표, AGENTS.md가 가리키는 파일 |
| `tests/test_codex_skill.py` | 팀 공용 코덱스 Skill이 이 Host에 있는 도구·옵션만 부르는지 |
| `tests/test_output_export.py` | CLEAN 자동 저장·악성/오류 차단·팝업 없음·혼합 파일 종료 처리, MCP 완료 대기·취소·중복 방지, 레거시 승인 순서, 정리 실패·잠금 오류·확보 실패 시 종료 금지·세대 교체 |
| `tests/test_mcp_runtime.py` | MCP 수명주기, 종료와 창 닫기 후 반출 결과 보존·조회, 조회 시 VM 재시작 없음 |
| `tests/test_shared_folder.py`, `tests/test_window_close.py` | Shared 옵션 거부, Output 승인 창, 창 닫힘 시 확보 → 종료 → 반출 순서와 확보 실패 시 VM 유지 |
| `tests/test_unified_verification.py`, `tests/test_solution_session.py` | 실제 Output 바로가기 기반 검증 명령, 반출 해시·MOTW·중복 확인, 통합 실행 진입점 |
| `tests/test_solution.py`, `tests/test_solution_config.py` | 설치 프로필·바이너리 pin, 실제 사용 매핑의 사전검사, 기존 WSB와 새 채팅 경로 격리 및 실패 시 시작 거부 |
| `tests/artifact_runner.py` | 테스트용 artifact-export-v1 Runner (MiniRunner 확장, 테스트가 아니라 도구) |
| `tests/mini_runner.py` | 테스트용 최소 Runner (테스트가 아니라 도구) |

```bash
.venv/Scripts/python.exe -m pytest -q tests
```

## Git에 올리지 않는 폴더

혼합 VM의 연결 복구와 반출은 [artifact-reconnect.md](../docs/artifact-reconnect.md)를 따른다.
수정 위치는 `sender.py`·`session_registry.py`의 Control 연결에 결합한 자격,
`telemetry.py`·`artifacts.py`의 현재 채널 검사, `output_export.py`의 유휴 재개 경계다.
`test_artifact_export.py`는 새 TLS 연결과 이전 자격 거부를,
`test_output_export.py`는 이전 채널 종료·전송 중 상태·종료 세대의 재개 차단을 검사한다.
`sandbox_run.py`와 `test_sandbox_run.py`는 결과 반출의 `ARTIFACT_BUSY`/`RATE_LIMITED`를
실행 재전송 없이 다음 결과 확인으로 넘기고, 정책 거부와 불확실한 시간 초과는 계속 보류한다.

실행하면 생기지만 `.gitignore`로 제외된다. 개인 키와 token이 들어 있으므로 공유하지 않는다.

| 폴더 | 내용 |
|---|---|
| `host/.certs/` | 개발용 인증서와 **개인 키** |
| `host/.bootstrap/` | bootstrap 파일 (**1회용 token** 포함) |
| `host/.audit/` | 감사 로그 |
| `host/.logs/` | MCP Server 로그 |
| `host/.artifacts/` | 반출 대기 중 받은 파일 (격리, 검사 전) |
| `host/.exports/` | 검사를 통과해 공개된 파일 |
