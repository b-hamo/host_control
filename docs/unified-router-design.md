# Router를 SCRP MCP 하나로 통합 (#94)

상태: 구현(자동화 시험까지). 실제 Windows Sandbox 시험과 11절 보류 항목이 남았다.

## 1. 문제

지금 Router 기능은 GUI 모드와 다른 MCP 서버에 있다.

| 서버 | 파일 | 도구 | Sandbox |
|---|---|---|---|
| GUI 모드 | `host/mcp_server.py` | computer_*, inbox_*, sandbox_run, artifact_* 등 | 세션 시작 시 하나 |
| Router 전용 | `host/router_mcp_server.py` | router_plan/submit/status/result/start/stop | plan마다 새로 |
| Router workflow (feat/91, 미병합) | `host/router_workflow_server.py` | router_capture/read/execute/status/result/stop | 실행 시 새로 |

- 코덱스 Skill은 GUI 모드만 연결한다. Router 서버를 따로 등록하지 않으면 Router를 거치지 않는다.
- Router workflow는 실행할 때 자기 Host(17443)와 Sandbox를 새로 띄운다(`router_workflow.py` `open_execution`).
  Sandbox가 이미 있으면 거부하므로, GUI 모드로 작업하던 Sandbox에서 이어서 실행할 수 없다.

## 2. 목표

SCRP MCP 하나(`mcp_server.py`), 세션 하나, Sandbox 하나에서 다음을 이어서 한다.

1. 외부 페이지에서 본 명령을 "믿지 않는 데이터"로 기록한다.
2. 그 명령을 **이미 떠 있는 Sandbox에서** 실행하고 영수증을 받는다.
3. 실행 뒤 뜬 창(설치 프로그램 등)을 GUI 도구로 이어서 조작한다.

완료 조건(#94): Router가 별도 Sandbox를 만들지 않는다. 변조·위조 경로·중복 실행을 거부한다.
반입·반출 검사를 그대로 유지한다. 자동화 시험과 실제 Guest 시험 범위를 구분해 기록한다.

## 3. 핵심 아이디어: sandbox_run 경로 재사용

`sandbox_run`(#39, #64)은 이미 GUI 모드 안에서 Router 부품으로 실행한다.

- 출처: Host가 받은 파일 기록(SHA-256)으로 `Source`를 등록한다. Agent 주장은 쓰지 않는다.
- 위임: 정확한 명령의 지문(fingerprint)에 묶인 1회용 `Delegation`을 만든다(`P-SANDBOX-RUN`).
- 입력: `RouterGuiPolicy`가 그 명령의 Win+R, 한 줄, Enter 세 입력만 연다.
- 전달: 실시간 inbox(`C:\Inbox`, Guest 읽기 전용)로 파일과 도우미를 넣는다.
- 완료: Guest 영수증(종료 코드, stdout 해시)이 반출 검사를 거쳐 돌아와야 성공이다. 아니면 HELD 또는 UNKNOWN이고, 재전송하지 않는다.

이미 `.ps1`을 실행할 수 있다. 따라서 **캡처한 명령을 `.ps1`로 만들어 inbox에 넣고 같은 경로로 실행**하면 된다.

```
inbox_download / inbox_import ─▶ 받은 파일 ─────────────────┐
                                                            ├─▶ SandboxRunner ─▶ 같은 Sandbox
router_capture ─▶ 캡처 원문 ─▶ router_execute ─▶ 파생 .ps1 ─┘
```

## 4. 도구

| 도구 | 하는 일 | 상태·결과 조회 |
|---|---|---|
| `router_capture` (`host/router_capture.py`) | `text`(Agent가 본 글자)와 `clipboard=true`(Host가 이 PC 클립보드를 직접 읽음)를 따로 세션 전용 폴더(`artifact_dir/<세션>/captures`)에 저장, SHA-256으로 `Source` 등록(`CAP-0001-AGENT`, `CAP-0001-CLIP`, origin `external`). 둘이 같은지(`agent_text_matches_clipboard`) 남기고, 다르면 Host가 읽은 쪽을 쓰라고 알린다. URL을 열거나 실행하지 않는다. 권한을 주지 않는다 | 같은 인자로 재호출하면 원래 기록 반환 |
| `router_execute` (`SandboxRunner.plan_capture`) | 캡처에서 스크립트를 뽑아(`script_from_source`, `decode_powershell`) 파생 `.ps1`(UTF-8 BOM)을 inbox에 쓰고, 부모가 캡처인 `Source`(`CAP-0001-CLIP-PS1`)로 등록한 뒤 `SandboxRunner`로 실행. 클립보드 출처는 `powershell-command` 형식으로만 | `sandbox_run_status` 재사용 |

- 웹 탐색은 지금처럼 내 PC(Local)에서 한다. Router 기준(탐색 = Local)을 따른다.
  `router_capture`는 브라우저와 무관하게 텍스트를 받으므로 Edge, Chrome, 코덱스 내장 브라우저 어디서 본 명령이든 기록할 수 있다.
- 실행 위치는 Sandbox 하나뿐이다. Host 실행 대체 경로는 없다.
- 두 도구는 `--router-capture`(`--sandbox-run` 필요)로만 켠다. 기본은 꺼져 있다. 정책 `P-ROUTER-CAPTURE`, `P-ROUTER-EXECUTE`(둘 다 ALLOW, 승인 창 없음).
- 기존 `router_status/result/stop`은 GUI 모드의 `sandbox_run_status`, `session_stop`으로 대신한다.

## 5. 출처 체인

```
CAP-0001-CLIP      origin=external   reference=clipboard:host:<순번>:<출처 URL>  sha256(원문)
   └─ CAP-0001-CLIP-PS1  origin=generated  parents=(CAP-0001-CLIP)            sha256(파생 .ps1)
```

- `Authority.check`는 부모까지 재귀로 확인한다. 실행 `Action.sources`에 두 출처를 모두 넣는다.
- `_verify_source`는 캡처 원문과 파생 파일의 현재 바이트를 다시 해시한다. 하나라도 바뀌면 `PROVENANCE_UNVERIFIED`.
- 출처 URL은 호출자가 준 값이다. 독립 확인한 출처가 아님을 감사 기록과 도구 설명에 남긴다(feat/91과 같다).

## 6. 보안 기준

- **신뢰 경계는 그대로다.** 판단(출처, 위임, 승인)은 Host가 하고, Sandbox는 비신뢰다.
- **Router 경로의 의미**: 실행을 막는 장치가 아니라, **검증된 실행 증거를 남기는 유일한 경로**다.
  Agent는 Sandbox 안에서 GUI 도구로 다른 프로그램을 띄울 수 있지만(팀 결정 2026-10-13: Sandbox는 버리는 공간),
  그 실행에는 출처·명령·영수증이 남지 않는다.
- **사람 승인 위치는 그대로다.** 파일이 내 PC로 넘어올 때(`artifact_export`, `inbox_finish` 남기기).
- 실행 중에는 다른 입력이 끼어들지 못한다(`sandbox_run`의 실행 잠금 재사용).
- 캡처 원문은 감사 기록에 그대로 남기지 않는다. 길이와 SHA-256만 남긴다(`computer_type`과 같다).

## 7. 재사용 / 이동 / 제외

| 구분 | 대상 |
|---|---|
| 그대로 재사용 | `SandboxRunner`(plan/start/status/영수증 검증), `RouterGuiPolicy`, `Authority`/`Delegation`, inbox 기록, 반출 검사, 감사 기록, 세션 수명주기 |
| feat/91에서 이동 | `script_from_source`, `router_command_intake.decode_powershell`, 캡처·실행 요청 ID 분리(#92), 클립보드 초기화 안내(#93) |
| feat/91에서 이동 | `router_local_browser.clipboard_snapshot`(Host 클립보드 읽기)만 `router_capture.py`로. Router가 직접 띄우는 Edge 탭(`router_gui`)은 #91에서 이미 꺼져 있었고 옮기지 않았다. 탐색은 Agent가 쓰는 브라우저(Edge, Chrome, 코덱스 내장)로 하므로 브라우저 종류와 무관하다 |
| 삭제 | 서버 2개(`router_mcp_server.py`, `router_workflow_server.py`)와 그 서버에만 쓰이던 `router_mcp_service`, `router_connection`, `router_provisioning`, `router_codec`, `router_runtime`, `router_workflow`, `router_workflow_connection`, `router_interactive`, `router_local_browser`, `router_task_scope`, `router_web_policy`, 시험 11개, `scripts/launch_router_workflow.py`, `scripts/verify_browser_handoff_live.py`, `schema/router-tools/`, `schema/router-list.json`, `schema/router-start.json`, 관련 문서 4개 |
| 남김 | `router/` 엔진·모델, `router_authority`, `router_gui_policy`, `router_command_bundle`, `router_command_intake`(`sandbox_run`이 씀). 지금은 어디서도 부르지 않지만 단위 시험이 있는 `router_gateway`, `router_ledger`, `router_local`, `router_sandbox`, `router_gui_driver`, `router_inputs`도 "현재 미사용"으로 남겼다(8절 5) |

## 8. 결정 사항

1. **웹 탐색 위치: 내 PC(Local).** Router 기준(탐색 = Local)을 유지한다. Edge만이 아니라 Chrome도 쓸 수 있게 한다.
   외부 페이지를 내 PC 브라우저로 여는 위험은 브라우저 자체 샌드박스에 맡기며, 이 설계의 범위 밖이다.
2. **클립보드 원문 확인: 유지.** 확인(읽기)은 내 PC에서, 실행은 Sandbox에서 한다.
   - ClickFix는 화면에 보이는 글자와 복사 버튼이 클립보드에 넣는 명령이 다르다. AI가 화면 글자를 옮기면 실제 공격 명령을 분석하지 못한다.
   - Host가 내 PC 클립보드를 직접 읽어 원문을 기록한다(feat/91 `clipboard_snapshot` 재사용). 읽기만 하며 실행하지 않는다.
   - 기록에는 "AI가 넘긴 텍스트"와 "Host가 클립보드에서 직접 읽은 텍스트"를 구분해 남긴다.

   ```
   [내 PC]   페이지 열기 → 복사 버튼 → 클립보드 → Host가 읽어서 기록
                                                     │
   [Sandbox]                                     여기서만 실행
   ```
3. **기존 Router 서버: 삭제.** `router_mcp_server.py`, `router_workflow_server.py`를 지운다.
   이 서버를 쓰는 실험 브랜치(#89 등)는 통합 뒤 SCRP MCP 기준으로 다시 맞춘다.
4. **클립보드 출처는 `powershell-command`로만 실행** (구현 중 추가). 클립보드에는 사용자가 따로 복사한 글자(비밀번호 등)가
   있을 수 있다. 완전한 `powershell ... -Command/-EncodedCommand` 한 줄(ClickFix가 넣는 형태)만 실행하고, 원문은 Agent에게 돌려주지 않는다(해시만).
5. **남은 Router 부품: 남기고 "현재 미사용" 표시.** `router_gateway`, `router_ledger`, `router_local`, `router_sandbox`,
   `router_gui_driver`, `router_inputs`와 `router/engine.py`의 `Router` 클래스는 지금 어디서도 부르지 않는다.
   Router 구조(관문의 위임·출처 확인) 설명과 다음 단계(plan 단위 작업)를 위해 단위 시험과 함께 남긴다.
6. **팀 등록 예시에 기본으로 켬.** `codex/config.example.toml`에 `--artifact-export --artifact-scanner amsi --sandbox-run --router-capture`.
   켜지 않으면 팀원 PC에서 Router 도구가 보이지 않는다(원래 문제). 이 PC 백신이 AMSI에 응답하지 않으면 실행 결과가 HELD가 된다.
7. **병합 순서: #95 먼저.** 이 브랜치가 그 위에 맞춘다(`mcp_server.py` 한 곳 충돌).
8. **복사 시점 확인 추가** (구현 중 추가). `router_capture(mark=true)`로 클릭 전 클립보드 순번만 적고,
   `after_mark`로 읽을 때 순번이 바뀌었는지 확인한다. 안 바뀌었으면 거부(사용자가 예전에 복사한 글자를 캡처하지 않게).

## 9. 작업 단계 (PR 단위)

| 단계 | 내용 |
|---|---|
| 0 | feat/91을 최신 develop에 맞추고(테스트 충돌 2개: `test_sandbox_run.py`, `test_router_retirement.py`) 병합. #95와 병합 순서 확정 |
| 1 | 이 문서 확정 |
| 2 | `router_capture`를 SCRP MCP로 이동, 출처 등록·감사 기록 |
| 3 | `router_execute`: 파생 `.ps1` → inbox → `SandboxRunner`, 출처 체인 검증 |
| 4 | 요청 ID 분리, 같은 ID 재요청 시 원래 결과, `session_stop` 뒤 조회 |
| 5 | 같은 Sandbox에서 실행 후 GUI 조작 시험 |
| 6 | Skill·README·설정 예시, 기존 Router 서버 처리, 실제 Windows Sandbox 시험 |

## 10. 시험

- 자동화: 캡처 재호출, 원문·파생 파일 변조, 부모 없는 파생 출처, 같은 ID 다른 내용, 실행 중 입력 끼어들기, 종료 뒤 조회.
- 실제 Guest: 이미 떠 있는 Sandbox에서 캡처 → 실행 → 영수증 SUCCEEDED → 같은 Sandbox에서 GUI 조작.
  새 Sandbox가 생기지 않았는지(`wsb list`) 확인한다.
- 모의 시험 결과를 실제 Guest 증거로 표현하지 않는다.

## 11. 보류

1. **코덱스 내장 브라우저의 복사가 Windows 클립보드에 닿는지**: 실제 코덱스 앱에서 확인하지 않았다. 닿지 않으면 그 브라우저에서는
   `clipboard=true`가 빈 값이 되고, `text`(Agent가 본 글자)만 남는다.
2. **`router_read`(메일함·HTTP 읽기)**: 옮기지 않았다. 발표용 메일 시나리오가 필요하면 Local 읽기 도구로 따로 넣는다.
3. **실제 Windows Sandbox 시험.** 이 PC에서 시작 단계에 방화벽 규칙이 현재 Default Switch 어댑터에 묶여 있지 않아
   멈췄다(관리자 권한으로 고친 뒤 다시).
