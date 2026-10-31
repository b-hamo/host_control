# host_control

Host에서 Agent 요청을 통제·전달하는 프로그램.
AI Agent(Codex)의 요청을 검사해서 격리된 Sandbox 안의 Runner(`b-hamo/sandbox_runner`)로 전달하고,
돌아온 결과를 검증한다.

```
Codex ──MCP──▶ [ MCP Server ] ──▶ [ Broker ] ──▶ [ RuntimeSession ] ──WSS──▶ [ Runner ]
               host/mcp_server.py host/broker.py   host/runtime_session.py      sandbox_runner
                                  (도구 호출 검사)  (연결·재연결·READY 관리)      Sandbox 안
```

## Sandbox 화면 창을 닫을 때 (#78)

`--runner-exe`로 Host가 시작한 Sandbox 화면 창을 닫으면 해당 세션도 종료한다.
Sandbox Manager가 최초 관찰한 창의 소멸을 5초 유예 후 확정하면, Host의
`SandboxLauncher`가 `USER_STOP` 흐름을 실행한다. 최소화·숨김은 종료가 아니다.
`runtime_get_state`의 `sandbox.window_state`에서 `UNSEEN/OPEN/MISSING/CLOSED/UNKNOWN/UNAVAILABLE`을 확인할 수 있다.

1. 해당 Sandbox ID의 창 종료 확정. `MISSING` 유예 중에는 Runner/VM 복구를 보류한다.
2. 연결된 Runner가 준비됐다면 `TERMINATE(USER_STOP)` 전송. 연결/응답 실패에도 종료를 계속한다.
3. Manager `stop()`이 `wsb list`로 VM 종료를 확인한 뒤 `cleanup()`을 수행한다.
4. `--shared`가 설정된 경우 크기·링크·Defender 검사 후 보존/삭제/보류 선택을 실행한다.
   `--artifact-scanner defender-service`를 함께 지정하면 Shared도 SecureArtifactScanner 서비스로 검사한다.
   서비스 재빌드 및 `installer/install.ps1 -EnableSharedScan` 설치가 필요하다.
   검사 통과 후 보관 위치는 그대로 `Downloads/SandboxShared/<세션>`이다.
   파일당 50 MiB 제한 등 설정과 동작은 [Shared 서비스 연동](scanner_service/README.md#19-shared-파일의-서비스-검사와-다운로드-보관-99)을 참고한다.
   빈 폴더에는 질문하지 않으며 검사 실패·무응답 처리는 기존 정책을 따른다.

창 닫기는 사용자의 종료 의사이므로 별도의 `session_stop` 승인창을 다시 요청하지 않는다.
창이 처음부터 관찰되지 않거나 조회에 실패한 경우에는 임의 종료하지 않는다.
사용자 종료와 자동 복구가 겹쳐도 닫힌 창 때문에 Sandbox를 다시 켜지 않는다.
VM 종료를 확인하지 못하면 실패 상태로 보고하며 Shared 파일 반출도 진행하지 않는다.

의존성: sandbox_manager#46의 `window_state()` API와 창 감시가 필요하다. 기존 실행 중인
Host/Sandbox에는 소급 적용되지 않으며 변경 버전으로 새 세션을 시작해야 한다.
Shared 옵션은 여전히 명시적으로 설정한다. 현재 세션의 설치 상태 전체를 보존하거나,
마지막 Shared 미러링 주기 이후 Guest에만 남은 파일까지 자동 회수하는 기능은 아니다.

검증: `tests/test_window_close.py`는 실제 Host/MiniRunner 통신을 사용해 창 종료,
시작 중 종료, 연결 끊김과 복구 경쟁, 종료 실패, Shared keep/delete/hold를 검사한다.
VM 및 창 backend와 Defender 판정/사용자 선택은 테스트 대역이다.
실제 Windows 창 수명 검증은 Manager의 `tests/test_window_session.py`에서 수행한다.

## 현재 포함된 것

| 경로 | 내용 | WBS |
|---|---|---|
| `host/sender.py` | Host 송신기. Runner 접속 수락, 인증, 데모 실행 | 3.4, 4.6 |
| `host/mcp_server.py` | MCP Server: Codex가 자식 프로세스로 켜고 stdio로 도구를 부르는 창구 | 5.7 |
| `host/inbox_download.py` | 받는 폴더(inbox)로 내려받기: Host가 https로 받고 실행은 Sandbox에서만. 다운로드 폴더에 이미 있는 파일은 `inbox_import`로 복사 | 5.9 |
| `host/sandbox_run.py` | 받은 파일을 Sandbox 안에서 실행 (GUI 모드 + Router 부품): 정확한 명령 하나만 Win+R로 → 영수증 확인 (승인 없음, 기록) | 7.x |
| `host/router_capture.py` | 웹 페이지 명령 기록 (`router_capture`, #94): AI가 본 글자와 Host가 직접 읽은 클립보드를 따로 해시해 보관. `router_execute`가 같은 Sandbox에서 분석 | 7.x |
| `host/artifacts.py` | 파일 반출 (artifact-export-v1): 후보 등록, 승인 후 업로드 권한, 결과 대조, 검사, 최종 공개, 취소 | 5.8 |
| `host/telemetry.py` | Telemetry 채널 (`/scrp/v1/telemetry`): 후보 SECURITY_EVENT 수신, EVENT_ACK | 5.8 |
| `host/artifact_scan.py` | 반출 전 검사: 형식 정책(UTF-8 TXT) + 백신 (기본 미설정 = 차단) | 5.8 |
| `host/approval.py` | 사용자 승인 창 (Host 화면) | 5.6 |
| `host/lifecycle.py` | Sandbox Manager(Lifecycle) 연결: task_submit 때 Sandbox 켜기, 세션이 끝나면 끄고 치우기 | 5.9 |
| `host/broker.py` | Broker 코어: 도구 호출 검사 → SCRP 메시지로 변환 → 결과·오류 정규화 | 5.6 |
| `host/tool_catalog.py` | 도구 20개 목록(GUI 18 + `router_capture`·`router_execute`), 입력 스키마 검사, 이 세션에서 쓸 수 있는 도구만 노출 | 5.6 |
| `host/policy.py` | 중앙 정책: ALLOW / REQUIRE_APPROVAL / DENY + 규칙 ID | 5.6 |
| `host/audit.py` | 감사 로그 (호출마다 1줄, 입력 글자는 가림) | 5.6 |
| `host/tool_availability.py` | 도구 노출 규칙 (표준 라이브러리만 사용, MCP Server가 빠르게 뜨도록) | 5.7 |
| `host/connection.py` | 연결 1개: 수신 메시지 검증, 요청·응답 짝 맞춤 | 3.4 |
| `host/runtime_session.py` | 재연결해도 이어지는 세션: Heartbeat·Health, 재연결 후 재동기화, 상태 조회 | 4.4, 4.5 |
| `host/startup.py` | Startup Verification: Host가 확인한 뒤에만 READY | 4.5 |
| `host/session_registry.py` | 세션 등록부. 세션별 1회용 bootstrap token 발급·확인 | 4.6 |
| `host/tls.py` | TLS 설정(최소 TLS 1.2), 개발용 자체 서명 인증서 생성 | 4.6 |
| `host/bootstrap.py` | Runner가 읽을 bootstrap 설정 파일 생성 | 4.6 |
| `scanner_service/` | **SecureArtifactScanner**: 반출 후보를 격리·Defender(MpCmdRun) 검사·공개·폐기하는 별도 Windows 서비스 (`NT SERVICE\SecureArtifactScanner`, Named Pipe). `--artifact-scanner defender-service`로 사용 | 5.8 |
| `installer/` | SecureArtifactScanner 빌드(PyInstaller onedir)·설치·검증·제거 스크립트 | 5.8 |
| `scrp/validate.py` | 메시지 검증기 (크기·인코딩·스키마) | 2.2 |
| `scrp/envelope.py` | 메시지 봉투 생성기 (ID·sequence·nonce·timestamp) | 2.2 |
| `schema/` | Host ↔ Runner 메시지 규격. **Runner도 이 파일을 기준으로 구현** | 2.2, 2.3 |
| `schema/mcp-tools/` | Agent(Codex)에게 보여줄 도구 18개의 입력 규격 | 2.4 |
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
| 5 | 정책: DENY 규칙(Win+X, Ctrl+Alt+Delete, Ctrl+Shift+Escape), 승인 필요 도구. Win+R은 허용 | `POLICY_DENIED` (+`rule_id`) | B-5, B-8 |
| 6 | 좌표가 마지막 화면 안인가, 화면이 10초 이내인가, 글자가 4 KiB 이하인가 | `INVALID_ARGUMENT` / `STALE_OBSERVATION` | 프로토콜 §6 |
| 7 | Action ID 발급 → SCRP 메시지로 변환해 전송 (`computer_click` → `mouse.click`) | | B-4 |
| 8 | 결과·오류를 표준 형식으로: `error`, `message`, `retryable`, `retry_after`, `recommended_next_step` | | B-10 |
| 9 | 감사 로그 1줄: 시각, 세션, task, action, 도구, 인자(입력 글자는 길이+해시만), 정책 결과, 결과, 지연 | | B-9 |

- Broker는 입력을 **절대 다시 보내지 않는다.** `ACTION_TIMEOUT`이면 `recommended_next_step: runtime_get_state`로 Agent가 먼저 확인하게 한다
- Agent는 `session_id`를 넘기지 않는다. Broker 하나가 세션 하나에 묶인다 (다른 세션 조작 불가)
- Win+R은 Sandbox 안 실행 창을 여는 일반 GUI 입력으로 허용한다(`POL-0.1.1`, 팀 결정 2026-10-13). Runner도 `POL-0.1.1`을 받아야 해서(sandbox_runner #32) 두 쪽 버전이 다르면 모든 입력이 거부된다. `task_submit`·READY·최신 관찰 등 기존 입력 조건은 그대로 적용된다. Sandbox 생성 설정이 아니라 Host Broker의 입력 정책이 결정하므로, 변경된 Host로 새 세션을 시작해야 한다.
- 데모: `python host/sender.py --demo broker` — 도구 호출 9개 중 3개(작업 등록 전 관찰, 화면 밖 클릭, Win+X)가 거부되고 Runner에는 2개만 도착한다. 감사 로그는 `host/.audit/<session>.jsonl`

## MCP Server와 Codex 연결 (WBS 5.7)

Codex가 `host/mcp_server.py`를 자식 프로세스로 켜고 stdin/stdout으로 MCP(JSON-RPC)를 주고받는다.
켜지면 Host(wss 서버, 세션 등록, bootstrap 파일 생성)도 함께 시작하므로 `host/sender.py`를 따로 켜지 않는다.

- Codex는 켠 뒤 약 0.5초 안에 도구 목록을 받지 못하면 그 서버의 도구를 빼버린다. 그래서 도구 목록은 표준 라이브러리만으로 즉시 답하고, 무거운 부분(Broker, TLS, wss 서버)은 백그라운드에서 뒤이어 띄운다
- stdout은 MCP 전용이다. 로그는 stderr와 `host/.logs/mcp_server.log`에 남는다
- 오류는 MCP 도구 오류(`isError: true`)로 돌려주고, 내용은 Broker의 표준 오류 JSON이다

### 코덱스로 쓰기: 통합 솔루션 설치와 등록

코덱스에게 "7-Zip 받아서 설치해 줘"처럼 시키면 **이 PC가 받아서 다운로드 폴더에 저장 → Sandbox가 그 파일을
`Input`에서 실행 → 설치 결과는 Sandbox 바탕화면 `Shared`로 이 PC에** 오게 하는 절차가 Skill
`codex/skills/secure-sandbox-run/SKILL.md`에 있다(배주한 Skill + 곽재혁 `scrp-sandbox-execution`의 좋은 규칙을 합침).
**팀원 모두 이 Skill 하나를 쓴다.** 코덱스는 저장소가 아니라 PC마다 `%USERPROFILE%\.codex\skills`를 읽으므로:

1. 세 레포를 준비하고 [통합 설치 가이드](docs/solution-install.md)에 따라 일반 PowerShell에서 `installer/install_solution.ps1 -Mode Dev -RegisterCodex`를 실행한다. Manager는 로컬 설치하고 Runner와 검사 서비스를 빌드한다.
2. 팀 공용 Skill은 `codex/install_skill.ps1`로 설치한다.
3. `-RegisterCodex`는 기존 설정을 백업하고 해당 MCP 등록만 갱신한다. 직접 연결할 때는 생성된 `mcp.toml`을 사용한다. `host/solution.py`가 Shared·artifact 검사 서비스를 기본 연결한다.
4. 현재 Sandbox 작업을 마친 뒤 MCP를 다시 연결한다. 서비스·Defender·실행 금지 ACL 점검 실패 시 시작하지 않는다.

Skill이 부르는 도구·옵션이 이 Host에 실제로 있는지는 `tests/test_codex_skill.py`가 확인한다. Host 도구를 바꾸면 Skill도
같은 PR에서 고친다. 일반 탐색은 이 PC의 브라우저로 하고, 페이지가 실행을 요구하는 명령은
[웹 페이지 명령 분석](#웹-페이지-명령-분석-router_capture--router_execute-94)으로 같은 Sandbox에서 처리한다.

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

### Sandbox 자동 시작 (Sandbox Manager 연동)

`--runner-exe`를 주면 Sandbox를 손으로 켤 필요가 없다. Codex가 `task_submit`을 부르는 순간
Lifecycle 담당의 Sandbox Manager(`b-hamo/sandbox_manager`)로 Windows Sandbox를 켜고, 세션이 끝나면 끈다.

```powershell
codex -s read-only `
  -c "mcp_servers.scrp.command='$py'" `
  -c "mcp_servers.scrp.args=['$server', '--runner-exe', 'C:/path/to/sandbox_runner.exe']" `
  -c "mcp_servers.scrp.default_tools_approval_mode='approve'" `
  -c "mcp_servers.scrp.startup_timeout_sec=60"
```

| 언제 | Host가 하는 일 |
|---|---|
| Codex가 켜질 때 | wss·업로드 서버만 연다. Sandbox는 아직 켜지 않는다 |
| `task_submit` | Sandbox 켜기를 **백그라운드로 시작하고 바로** `PREPARING`으로 답한다 (Codex를 붙잡아 두지 않음) |
| Sandbox가 켜지면 | Sandbox가 보는 Host 주소로 인증서(SAN)·token·bootstrap을 만들어 `publish_bootstrap` → Guest 안 시작 스크립트가 Runner 실행 |
| Runner가 검사 통과(READY) | `mark_ready`: 다 쓴 token 파일을 지운다. READY는 Host의 Startup Verification만 정한다 |
| `session_stop` | Runner에게 TERMINATE → 답을 받고 Runner가 끊으면 `stop`(`wsb list`로 꺼졌는지 확인) → `cleanup` |
| 켜기 실패·120초 안에 READY 안 됨 | 세션 실패(`RUNTIME_START_FAILED`), Sandbox 비상 종료 후 정리 |
| Codex 종료 (stdin 닫힘) | READY면 TERMINATE(USER_STOP) 후 끄고 정리, 아니면 바로 끄고 정리 |

#### 끊겼을 때 자동 복구

Host가 언제 할지 정하고, 실제로 끄고 켜는 건 Sandbox Manager(`restart_runner`, `reset_sandbox`)가 한다.

| 상황 | Host가 하는 일 |
|---|---|
| 연결이 끊기고 30초(재접속 유예) 안에 Runner가 안 돌아옴, **Sandbox는 켜져 있음** | `restart_runner`: 같은 Sandbox 안에서 Runner만 다시 켬 (열린 창 등은 그대로) |
| 연결이 끊기고 30초 안에 안 돌아옴, **Sandbox가 사라짐** | **다시 켜지 않음**: 사용자가 창을 닫은 것으로 보고 세션 종료(`RUNTIME_GONE`) |
| 연결은 있는데 Heartbeat에 3번 연속 무응답 (Sandbox 먹통) | `reset_sandbox`: Sandbox를 새로 켬 |
| `restart_runner` 실패 | `reset_sandbox`로 넘어감 |
| `reset_sandbox`도 실패, 또는 재시작 횟수 초과(세션당 3번) | 세션 실패, Sandbox 비상 종료 후 정리 |
| 보안 문제로 끝난 세션(재접속 때 권한·감시 기능 감소 등), 첫 Startup Verification 실패 | 다시 켜지 않음 |

- 복구할 때마다 **같은 세션의 다음 세대(generation 2, 3…)**가 된다. 새 token·새 bootstrap으로 처음처럼 Startup Verification을 거쳐야 READY. 옛 세대의 token과 메시지는 전부 거부
- 끊길 때 결과를 몰랐던 클릭·입력은 `UNKNOWN`으로 남기고 **다시 보내지 않는다**. task_id·action_id 번호는 이어서 쓴다
- 복구 중 `computer_*`는 "준비 중, 다시 시도"(`RUNTIME_UNAVAILABLE`)로 답하고, `computer_observe(wait_ms)`는 READY까지 기다린다
- 복구 뒤 첫 성공 결과에 `notice`가 한 번 붙는다: 다시 켜졌으니 화면부터 다시 보라는 안내와 `UNKNOWN`으로 남은 Action 목록
- `runtime_get_state`의 `sandbox`에 `generation`, `recoveries`(한 일 목록)가 붙는다
- `--no-auto-restart`: 다시 켜지 않고 세션을 끝낸다 (Sandbox는 끄고 정리)

- Codex에게는 "켜지는 데 20~60초, `computer_observe`를 `wait_ms=10000`으로 부르면 기다린다"고 알려준다.
  켜지는 중에 `wait_ms`를 준 `computer_observe`는 READY까지 기다렸다가 바로 캡처한다
- `runtime_get_state`에 `sandbox` 항목(`LAUNCHING`/`PUBLISHED`/`READY`/`RECOVERING`/`STOPPED`/`FAILED`, 오류)이 붙는다
- `task_submit`을 여러 번 불러도 Sandbox는 한 번만 켠다 (MCP Server 1개 = 세션 1개)
- `--runner-exe`를 쓰면 bootstrap 위치와 Host 주소는 Sandbox Manager가 정하므로 `--advertise-address`, `--bootstrap-out`은 같이 못 쓴다
- 작업 폴더는 `%LOCALAPPDATA%\SecureCUA\sandbox-manager` (`--sandbox-root`로 변경). OneDrive 안이면 거부된다 (token이 동기화되므로)

먼저 준비할 것 (한 번만):
- `pip install -r requirements.txt` (Sandbox Manager 포함, Python 3.13)
- **방화벽 규칙**: Sandbox Manager가 켤 때 `SCRP PoC*` 규칙(17443·17444 허용, 나머지 차단, Sandbox 스위치에 연결)을 확인하고,
  없으면 `firewall not ready`로 거부한다. Lifecycle 저장소의 `tools/install_firewall.ps1`을 **관리자 권한으로** 한 번 실행한다
- Windows Sandbox는 PC당 1개. 이미 켜져 있으면 `a Windows Sandbox is already running`으로 거부된다

## 받는 폴더 (inbox): 내려받기는 Host, 실행은 Sandbox

Router 설계("외부 출처 + 실행은 Sandbox로")대로, 인터넷 파일을 **Host가 받아서 Sandbox 안에서만 실행**하게 한다.
Sandbox Manager `acf5f9f`의 받는 폴더 기능을 연결했다.

```powershell
# 한 번만: 받는 폴더 만들기 (이 폴더 안 파일은 Host에서 실행 금지, 관리자 권한 불필요)
powershell -ExecutionPolicy Bypass -File <sandbox_manager>\tools\setup_inbox.ps1
# Codex 등록 인자에 추가
--runner-exe <sandbox_runner.exe> --inbox %USERPROFILE%\SecureCUA\codex-work\inbox
```

| 단계 | 누가 | 무엇을 |
|---|---|---|
| 내려받기 | Agent → Host | `inbox_download(url)` (Broker 경유: 정책 `P-INBOX-DOWNLOAD`, 호출 빈도, 감사). 승인 없음(팀 결정 2026-10-08) |
| 끝날 때 | Host / Agent → Host | **기본은 삭제**: 세션이 끝나면(stop → cleanup 뒤) 받는 폴더를 비움(`clear_inbox`). 사용자가 남기라고 하면 `inbox_finish(keep)` → PC 확인 창(`P-INBOX-KEEP`) → 고른 것만 다운로드 폴더로 **복사**(인터넷 표시), 나머지 삭제. 팀 요청 2026-10-11 |
| 이미 받아 둔 파일 | Agent → Host | `inbox_import(name)`: 사용자 **다운로드 폴더 바로 안** 파일을 이름만으로 받는 폴더에 **복사**(원본 유지). 정책 `P-INBOX-IMPORT`. 경로·`..`·링크·hard link·받는 중 파일·50 MiB 초과는 거부(검사는 sandbox_manager `import_to_inbox`). 팀 요청 2026-10-10 |
| 저장 | Host | 임시 폴더에 다 받은 뒤 받는 폴더에 최종 이름으로 바로 씀. 다 쓸 때까지 다른 프로그램이 못 열게 잠금(Sandbox가 켜져 있으면 받는 폴더 안 이름 바꾸기가 막히기 때문), 이름 정리·덮어쓰기 없음, "인터넷에서 받음" 표시(MOTW) |
| 연결 | Sandbox Manager | 받는 폴더를 Sandbox `C:\Inbox`에 **읽기 전용**으로 계속 연결. 1초마다 다 받아진 파일만 SHA-256과 함께 목록에 올리고, 링크가 생기면 바로 지움 |
| 확인 | Sandbox 안 지킴이 | 바탕화면 `Input`에 복사 → 해시 비교 → `Desktop\input-check.html`에 OK/FAIL |
| 실행 | Agent | 기존 GUI 도구로 Sandbox 안에서만. 셸·원격 실행 경로는 없음 |

내려받기 제한 (`host/inbox_download.py`, Lifecycle 시연 도구 기반에 보완):
- https만, 리다이렉트도 매번 같은 검사(최대 5번). 주소 안 비밀번호 거부
- **공개 주소만**: 이름이 사설·루프백·링크로컬(169.254 클라우드 메타데이터 포함) 주소로 하나라도 풀리면 거부
- **확인한 IP로 바로 접속**: 이름을 두 번 찾지 않아서, 확인과 접속 사이에 내부 주소로 바뀌는 공격(DNS rebinding)이 안 됨. 인증서·SNI는 원래 이름으로 검사
- 파일당 50 MiB, 받는 폴더 합계 200 MiB·200개, 전체 45초(MCP 호출 60초 안)
- **zip은 Host에서 풀지 않는다** (신뢰할 수 없는 압축을 Host가 처리하지 않게). Sandbox 안에서 푼다
- 감사 로그에 주소·최종 주소·크기·SHA-256. **주소의 쿼리는 남기지 않는다** (서명된 링크는 쿼리가 비밀값)

켤 때 확인: `--inbox`는 `--runner-exe`와 같이만 쓸 수 있고, 사용자 폴더(문서·바탕화면·다운로드·AppData 등)·OneDrive·드라이브 최상위는 거부한다.
그리고 **받는 폴더에서 프로그램이 정말 실행되지 않는지** 무해한 시스템 프로그램(whoami) 사본으로 시험하고, 실행되면 시작하지 않는다(`setup_inbox.ps1`을 안 한 경우).

보안 이벤트: 받는 폴더에 링크가 생겨 지운 경우(`INBOX_LINK_REMOVED`, `INBOX_HARDLINK_REMOVED`)는 누가 다른 Host 파일을 Sandbox에 보이게 하려던 흔적이라
경고 로그와 감사 로그(`SECURITY_EVENT`)에 남긴다.

전제: Codex는 `-s read-only`로 실행한다. 받는 폴더는 사본이 아니라 폴더째 연결이라, Codex가 그 폴더에 링크를 만들 수 있으면 지워지기 전 1초 안에 Host 파일이 보일 수 있다.

### 받은 파일 실행 (sandbox_run): GUI 모드 + Router 부품

GUI 모드 한 세션 안에서 **받기 → Sandbox에서 실행 → 그 창을 화면 조작**까지 이어서 한다.
Router(#33·#35)의 부품을 GUI 모드에 붙인 것이다. Router 전용 서버는 #94에서 이 서버로 합치고 지웠다.

```powershell
# Codex 등록 인자에 추가 (--inbox, --artifact-export와 같이)
--runner-exe <sandbox_runner.exe> --inbox <받는 폴더> --artifact-export --sandbox-run --agent-guard
```

`--agent-guard` (코덱스 같은 Agent 앱용, 2026-10-13): 코덱스 앱 시험에서 Agent가 규칙 파일을 건너뛰고 스스로 세션을 끝내거나,
다운로드 폴더에 있는 파일 대신 웹에서 다른 설치 파일을 받은 일이 있어서 다음은 **PC 확인 창**을 거친다(45초 무응답 = 아니요).

| Agent가 하려는 것 | 정책 | "아니요"면 |
|---|---|---|
| `session_stop` (`SUSPICIOUS_CONTENT` 제외: 보안 종료는 바로) | `P-SESSION-STOP` | Sandbox 유지, Agent에 "사용자가 끝내라고 할 때만" |
| `inbox_download`인데 다운로드 폴더에 이름이 비슷한 파일이 있음 | `P-INBOX-DUPLICATE` | 받지 않음, "inbox_import로 그 파일을" |

같은 규칙을 두 도구의 설명에도 붙인다(Agent는 규칙 파일을 건너뛰어도 도구 설명은 본다). 옵션을 빼면 지금까지와 같다.

`--save-downloads` (`--inbox`와 같이, 배주한 결정 2026-10-15, #74): `inbox_download`로 받은 파일을 **사용자 다운로드 폴더에도
한 부 저장**한다(브라우저로 받은 것처럼 인터넷 표시 ZoneId=3). 이 사본은 세션이 끝나도 **지우지 않는다**. Sandbox에는 지금처럼 받는
폴더 사본이 간다(다운로드 폴더는 Sandbox에 연결하지 않음). 같은 파일이 이미 있으면 다시 만들지 않고, 다른 파일이면 `이름-2`로 저장한다.
결과의 `downloads_copy`에 위치가 나온다. 사본 저장에 실패해도 다운로드 자체는 실패로 치지 않는다.
파일 이름은 서버가 알려 준 이름(Content-Disposition) → 요청한 주소의 이름 → 최종 주소의 이름 순으로 정한다
(`www.7-zip.org/a/7z2604-x64.exe`가 GitHub로 넘어가면 최종 주소는 확장자 없는 id라서 `7z2604-x64.exe`를 유지).

`--shared <폴더>` (배주한 요청 2026-10-15, sandbox_manager #34): 세션마다 `<폴더>\<세션>`을 새로 만들어 Sandbox `C:\Shared`에
**쓰기 가능**하게 연결한다. Agent는 **말하지 않아도 기본으로** 설치 폴더를 Sandbox 바탕화면 `Shared\<프로그램>`으로 하고 포터블·PDF도 거기 풀거나 저장한다(도구 설명에 규칙, 10/15 배주한 결정). 그것이 몇 초 안에 이 PC에도 보인다
(여기서는 실행 금지). 세션이 끝나면 Microsoft Defender로 검사하고, 위협·검사 오류면 실행 금지 상태로 그대로 둔다. 깨끗하면
**PC 확인 창**(`SCRP 공유 폴더 남기기`, 파일 목록)으로 묻는다: **예** = `다운로드\SandboxShared\<세션>`으로 복사(인터넷 표시),
**아니요** = 지움, **취소·45초 무응답** = 지우지 않고 공유 폴더에 실행 금지 상태로 보관(배주한 결정 2026-10-15, #68).
결과는 `runtime_get_state`의 `sandbox.shared`(EXPORTED·DELETED·HELD·BLOCKED·QUARANTINED·EMPTY). 서비스·드라이버를 까는 설치형은
파일만 와서 이 PC에서 동작하지 않는다. `<폴더>`는 받는 폴더처럼 `setup_inbox.ps1`로 준비한 곳 아래(예: `codex-work\shared`)여야
하고, 실행이 막히지 않으면 시작을 거부한다. 옵션을 빼면 지금까지와 같다.

| 단계 | 누가 | 무엇을 |
|---|---|---|
| 요청 | Agent | `sandbox_run(file, arguments, reason)`. 이 세션에서 `inbox_download`로 받거나 `inbox_import`로 가져온 `.exe`·`.msi`·`.ps1`만 |
| 출처 | Host | Agent 말이 아니라 **Host가 받을 때 남긴 기록**(최종 주소, SHA-256). 파일이 바뀌었으면 거부 |
| 위임 | Host | **승인 창 없이** Host가 받은 기록으로 정확한 명령을 만들고, 그 명령 지문에 묶인 위임(Router `Authority`)을 이번 한 번 만든다(`P-SANDBOX-RUN` ALLOW). 팀 결정(2026-10-13): Sandbox는 버리는 공간이라 실행은 자동, 사람 승인은 파일이 내 PC로 넘어올 때(`artifact_export`, `inbox_finish` 남기기) |
| 전달 | Host | 도우미(`sandbox_run_guest.ps1`)와 명령서를 받는 폴더(`C:\Inbox`, 읽기 전용)로. 실행 파일은 Sandbox 지킴이가 해시를 확인한 `Desktop\Input` 사본 |
| 실행 | Host → Runner | Router의 `RouterGuiPolicy`가 **이 명령의 Win+R → 한 줄 입력 → Enter 세 입력만** 허용. Enter 직전에 파일·도우미·위임을 다시 확인. 실행 중에는 다른 입력이 끼어들지 못한다. `POL-0.1.1`부터 Agent도 Win+R 자체는 쓸 수 있어서, 출처 기록·명령·영수증이 남는 실행은 `sandbox_run`을 거친 것뿐이다.<br>입력 전후로 화면을 비교한다: 실행 창이 화면에 나타난 뒤에만 한 줄을 입력하고, 그 줄이 화면에 보인 뒤에만 Enter (Runner가 앞 창을 알려 주지 못해서, 작업 표시줄을 뺀 스크린샷 행 비교). 안 보이면 거기서 멈춘다(`LAUNCH_SURFACE_NOT_SEEN`, `LAUNCH_TEXT_NOT_SEEN`) |
| 결과 | Guest → Host | 도우미가 영수증(종료 코드, stdout 해시)을 남기면 반출 검사를 거쳐 확인. 이 실행의 영수증·stdout 반출은 따로 묻지 않는다 |

`sandbox_run_status` 상태: `RUNNING`(시작됨, GUI 프로그램은 창이 열려 있는 동안 계속) → `SUCCEEDED`/`FAILED`(영수증 확인, 종료 코드·stdout).
`HELD`(결과가 검사를 못 넘음), `UNKNOWN`(실행됐을 수도 있음: 다시 실행하지 않는다), `DENIED`(시작 안 함).

실제 Sandbox 확인: Sandbox가 켜진 뒤 ZoomIt 받기 → `sandbox_run` → Sandbox 안에서 ZoomIt 창이 뜸(실행 기록·도우미·해시 확인 사본·프로세스 확인).
내 PC로 가져와 직접 실행하려면 `inbox_finish`로 남길 파일을 고르고, Host 화면 승인 창에서 사람이 허락한다(`P-INBOX-KEEP`).

### 웹 페이지 명령 분석 (router_capture → router_execute, #94)

"Win+R을 누르고 붙여 넣으세요" 같은 페이지(ClickFix)의 명령을 **이 PC에서는 읽기만, 실행은 같은 Sandbox에서만** 한다.
예전 Router 전용 서버 두 개(`router_mcp_server.py`, `router_workflow_server.py`)를 이 GUI 모드 서버로 합쳤다
([설계](docs/unified-router-design.md)). Sandbox를 따로 띄우지 않으므로, 실행 뒤 뜬 창을 `computer_*`로 이어서 조작한다.

```powershell
# --sandbox-run과 같이
--runner-exe <sandbox_runner.exe> --inbox <받는 폴더> --artifact-export --sandbox-run --router-capture
```

```
[이 PC]    브라우저로 페이지 열기 → 복사 버튼 → 클립보드 → router_capture(clipboard=true): Host가 읽어서 기록
                                                              │
[Sandbox]  router_execute: 파생 스크립트를 inbox로 → sandbox_run과 같은 Win+R 실행 → 영수증 → sandbox_run_status
```

| 단계 | 누가 | 무엇을 |
|---|---|---|
| 기록 | Agent → Host | `router_capture(request_id, source_url, text, clipboard)`. `text`는 Agent가 본 글자, `clipboard=true`면 **Host가 이 PC 클립보드를 직접 읽는다**. 둘 다 따로 저장·SHA-256(`CAP-0001-AGENT`, `CAP-0001-CLIP`)하고 같은지(`agent_text_matches_clipboard`)를 남긴다. ClickFix는 보이는 글자와 복사되는 명령이 달라서, 다르면 Host가 읽은 쪽을 쓰라고 알린다. URL은 열지 않고, 쿼리는 지운다. 원문은 세션 전용 폴더(`artifact_dir/<세션>/captures`)에만, 감사 기록에는 길이·해시만 |
| 파생 | Host | `router_execute(request_id, source_id, form)`. 캡처를 **데이터로만** 변환해 PowerShell 스크립트(UTF-8 BOM)를 받는 폴더에 둔다. `powershell-script`(전체가 스크립트), `powershell-command`(`powershell ... -Command "..."`/`-EncodedCommand` 한 줄, Host가 읽은 클립보드 출처만), `powershell-command-literal`(페이지 코드 안 작은따옴표 문자열). **클립보드 출처는 `powershell-command`로만** 실행한다: 사용자가 따로 복사해 둔 글자가 스크립트로 돌지 않게 |
| 출처 | Host | 파생 스크립트(`CAP-0001-CLIP-PS1`)의 부모는 캡처. `Authority`가 둘 다 지금 바이트로 다시 해시한다. 어느 쪽이 바뀌어도 실행 전·Enter 직전에 거부(`REASSESSMENT_REQUIRED`) |
| 실행·결과 | Host → Runner → Host | `sandbox_run`과 같다(`P-ROUTER-EXECUTE`, 승인 창 없음, 세 입력만, 영수증). 상태는 `sandbox_run_status` |
| 중복 | Host | 같은 `request_id`·같은 인자 = 같은 결과(다시 실행하지 않음), 다른 인자 = `IDEMPOTENCY_CONFLICT`. 캡처 ID와 실행 ID는 따로 |
| 끝난 뒤 | Host | 세션이 끝나도 `sandbox_run_status`와 같은 `request_id`의 재요청은 보존된 결과를 돌려준다. 영수증 없는 실행은 Enter를 보냈으면 `UNKNOWN`, 아니면 `FAILED`. 새 작업은 `task_submit`부터 |

복사 시점: 복사 버튼을 누르기 **전에** `router_capture(mark=true)`로 클립보드 순번만 적어 두고, 누른 뒤
`router_capture(clipboard=true, after_mark=<그 id>)`로 읽으면 순번이 바뀌었는지 확인한다. 안 바뀌었으면(복사가 안 됨) 아무것도
기록하지 않고 거부한다. 결과의 `copied_after_mark`가 `true`면 "누른 뒤에 들어온 내용", `null`이면 표시 없이 읽은 것.
그 사이 다른 프로그램이 클립보드를 쓰지 않았다는 증명은 아니다.

## 파일 반출 (artifact-export-v1)

Sandbox 안에서 만들어진 파일 하나를 **사람의 승인 → 수신 → 검사 → 공개** 순서로 Host로 꺼낸다.
계약은 Runner 담당이 정의·구현한 `artifact-export-v1`
(`b-hamo/sandbox_runner` `32700916f4e7074051a109aaf6b4728dbeba7df4`, `docs/artifact-export-contract.md`)을 그대로 채택했다.
메시지 규격은 [schema/profiles/artifact-export-v1/](schema/profiles/artifact-export-v1/README.md).

```powershell
codex ... -c "mcp_servers.scrp.args=['$server', '--runner-exe', '<sandbox_runner.exe>', '--artifact-export', '--artifact-scanner', 'amsi']"
```

`--artifact-export`를 줄 때만 켜진다. 안 주면 기존 동작 그대로다 (bootstrap·HELLO_ACK·도구 목록 모두 이전과 같음).

| 단계 | 누가 | 무엇을 |
|---|---|---|
| 선택 | Host | bootstrap에 `control_contract: "artifact-export-v1"` + `artifact_upload {port, path}`. HELLO에 `artifact.export.v1`이 있어야 하고 HELLO_ACK에서 허용 |
| Telemetry | Runner → Host | HELLO_ACK의 telemetry token으로 `wss://…/scrp/v1/telemetry` 접속 (그 채널 전용, 1회용). CHANNEL_HELLO/ACK |
| 시작 검사 | Host | 기존 Startup Verification + **Telemetry 채널이 붙어야 READY** (Runner는 채널이 붙은 뒤에 생긴 파일만 보고) |
| 후보 | Runner → Host | SECURITY_EVENT 4필드(`event_id/observed_at/category/relative_path`) → EVENT_ACK `STORED` (같은 id·같은 내용 재전송도 STORED, 같은 id·다른 내용은 `REJECTED`). Host가 `ART-000001` 같은 artifact_id 발급. 크기·해시·형식은 아직 모름 |
| 요청 | Agent → Host | `artifact_export(artifact_id, reason)`: READY·task_submit 필요 → 정책 `REQUIRE_APPROVAL` → **Host 화면 확인 창** (45초, 무응답 = 거부) |
| 권한 | Host | 새 `upload_id`(192-bit)·token(256-bit, 43자)·기한(120초)·상한(기본 1 MiB)을 **먼저 등록**한 뒤 ARTIFACT_REQUEST. token은 Agent·로그에 안 나감 |
| 수신 | Runner → Host | `PUT /scrp/v1/artifacts/<upload_id>` + Bearer token. 디스크로 스트리밍, 크기·SHA-256 확정 후 **본문 없는 201** |
| 결과 | Runner → Host | ARTIFACT_RESULT가 원 요청과 짝이 맞고, candidate·upload_id·bytes_sent가 **실제 수신 기록과 같을 때만** 검사 |
| 검사 | Host | 같은 바이트(해시 재확인)로 형식(UTF-8 `.txt`) + 백신. 오류·미설치·시간 초과(30초)는 통과 아님 |
| 공개 | Host | 검사한 파일을 그대로 `host/.exports/<세션>/<artifact_id>/<파일명>`으로 옮김 → `EXPORTED`, `export_path` 제공 |

`artifact_list` 상태: PENDING(후보·전송 중) / QUARANTINED(수신, 결과 대기) / SCANNING / EXPORTED / BLOCKED(`result.code`가 이유).
같은 artifact_id로 다시 부르면 진행·완료 상태만 돌려준다(승인 창도 다시 안 뜸). 전송 실패(`UPLOAD_FAILED` 등)만 새 승인으로 다시 시도할 수 있다.

**취소:** 세션 종료, Runtime 세대 변경(복구), Control 연결 끊김(진행 중 전송), Telemetry 채널 끊김(그 Runtime의 반출 전부 중지).
취소된 권한으로 온 PUT은 410. 받은 파일은 지운다. Host를 다시 켜면 남은 임시 파일은 공개하지 않고 지운다.

**수신 거부 코드:** 401 token 없음 · 403 token 틀림 또는 모르는 upload_id(구분 안 함) · 409 이미 사용 · 410 만료·취소 ·
411 길이 없음 · 413 상한 초과 · 415 `application/octet-stream`이 아니거나 Transfer/Content-Encoding·Content-Range · 408 기한 초과.
인증 전 거부(415·411)는 권한을 소모하지 않고, 인증 뒤 실패는 권한을 소모한다(재사용 없음).

**백신 (`--artifact-scanner`):** 어떤 엔진을 쓸지는 아직 팀 결정이 필요하다.
- `none` (기본): 검사기 없음 → 모든 반출이 `BLOCKED` (`SCANNER_UNAVAILABLE`). 성공으로 대신하지 않는다
- `amsi`: Windows AMSI에 등록된 백신(Defender, 또는 AMSI 제공자로 등록한 제품)에 메모리로 검사 요청.
  **처음 쓸 때 EICAR 테스트 문자열(메모리에서만)로 자체 시험**해서 탐지하지 못하면 사용 불가로 본다.
  예: 개발 PC의 McAfee AMSI 제공자는 EICAR를 "탐지 안 됨"으로 답했다 → 그 PC에서는 `amsi`도 `SCANNER_UNAVAILABLE`

**승인 (`--approval`):** `dialog`(기본) Host 화면에 확인 창. Sandbox가 보고한 경로와 AI가 적은 이유를 "확인되지 않은 내용"으로 표시.
`deny` 모두 거부. 창은 **45초** 기다린다: MCP 도구 호출 제한(60초, Codex 기본도 60초) 안에 답이 돌아가야 하기 때문이다.
그 호출이 먼저 끝나면(시간 초과·Host 종료) 열린 창에 "아니요"를 눌러 닫고, 늦은 "예"는 권한을 만들지 않는다.

**공개 순서:** 받은 파일을 다른 프로그램이 쓰지 못하게 잠근 채 해시를 다시 확인하고, 같을 때만 결과 폴더로 옮기며 동시에 `EXPORTED`가 된다.
그 전까지 `artifact_list`는 `SCANNING`이고 결과 폴더에도 파일이 없다.

**`--artifact-scanner defender-service`:** 수신·검사·공개를 Host 프로세스 밖의 SecureArtifactScanner Windows 서비스
(관리자 권한 없는 `NT SERVICE\SecureArtifactScanner`, Microsoft Defender `MpCmdRun.exe`)가 한다. HTTPS 수신 규칙·빈 201·
`ARTIFACT_RESULT` 대조·승인 창은 그대로이고, 본문은 Host 파일 없이 64 KiB씩 Named Pipe로 서비스 Job에 들어간다.
검사 통과 + 승인 뒤 서비스가 `--export-dir`에 공개하고, Host가 그 파일(경로·링크·해시)을 다시 확인한 뒤에만 `EXPORTED`.
서비스가 없거나 다른 폴더로 공개하도록 설치됐으면 `artifact_export`는 승인 창 전에 `SCANNER_UNAVAILABLE`.
서비스 설치: `installer\install.ps1 -ExportRoot <--export-dir와 같은 폴더>`. 설계·판정 기준·연동 계약: [scanner_service/README.md](scanner_service/README.md) §15.

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

2. `wss://<host>:<port><path>`로 접속한다. TLS 1.2 이상. 인증서가 다르면 접속하지 않는다. **평문 ws://로 재시도하지 않는다**

   **현재 Runner(`sandbox_runner` 3270091)의 방식**: Windows 기본 검증(인증서 체인 + 호스트명)을 **켜 둔 채**
   bootstrap의 `host_certificate_sha256`과 서버 인증서 지문을 추가로 비교한다(leaf pin). 이 방식이 동작하려면 두 가지가 필요하다.
   - 접속 주소가 인증서 SAN에 있어야 한다: Host가 Sandbox Manager의 `start()` 주소(또는 `--advertise-address`)를 SAN에 넣는다
   - Guest가 Host 인증서를 신뢰해야 한다: Sandbox Manager의 Guest 시작 스크립트가 Runner 실행 전에
     `certutil -addstore -f Root`로 창 없이 등록한다(Sandbox는 매번 초기화되므로 매번 등록)

   검증을 끄는 방식(`SECURITY_FLAG_IGNORE_UNKNOWN_CA` + 지문 비교만)은 쓰지 않는다. 다른 Runner를 붙일 때도
   인증서 검증을 임의로 끄지 말고 위 두 조건을 맞춘다
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
   - TLS·인증서는 제어 채널과 같다 (같은 인증서, 같은 검증 방식, 평문 http로 재시도하지 않음)
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
- 파일 반출의 백신 엔진은 미정이다 (`--artifact-scanner` 기본 `none` = 모두 차단). 형식 정책은 발표용 UTF-8 `.txt` 한 가지
- 후보 무효화 메시지가 계약에 없어서 `artifact_list`는 "보고된 후보" 목록이다. 지워지거나 바뀐 파일은 반출할 때 Runner가 거부한다
- 반출은 한 번에 하나만 (`ARTIFACT_BUSY`). 후보·전송 상태는 메모리에만 있다 (Host를 다시 켜면 새로 시작)
- 받는 폴더는 폴더째 연결이다(사본 아님). 링크는 1초 안에 지우지만 그 사이는 열려 있을 수 있다 → Codex `-s read-only` 전제
- 내려받은 파일을 넣은 세션의 "외부 출처" 표시(Router 오염 규칙)는 아직 없다
- MCP Server 1개 = 세션 1개. Codex를 다시 켜면 새 세션이 만들어지고 Sandbox도 다시 접속해야 한다
- Codex가 MCP Server를 강제로 죽이면(stdin을 닫지 않고) Sandbox가 남는다. 다음 `task_submit` 때 Sandbox Manager가
  켠 Host가 죽은 세션의 Sandbox를 먼저 정리하고 시작한다 (손으로 켠 Sandbox는 건드리지 않고 거부)
- 실제 Runner는 아직 재접속(재접속 token으로 다시 붙기)을 하지 않는다. 그래서 잠깐 끊겨도 30초 뒤 Runner를 다시 켜고,
  그 Sandbox에서 하던 작업 상태는 화면에 남은 것만 이어진다
- Sandbox 켜기에 실패한 세션은 다시 켜지 않는다. Codex를 다시 켜서 새 세션으로 시작한다
- 승인 Workflow(B-8)는 `approver` 콜백 자리만 있다. 사용자에게 묻는 UI는 없으므로 승인 필요 도구는 지금은 거부된다
