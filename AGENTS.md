# AGENTS.md — host_control 작업 지도

Codex·Claude Code 같은 코딩 에이전트가 이 저장소를 고치기 전에 읽는 파일이다.
자세한 설명은 아래 문서에 있고, 이 파일에는 어디를 봐야 하는지와 지켜야 할 규칙만 적는다.
규칙은 되도록 테스트(`tests/test_repo_rules.py`)로 검사하고, 테스트로 못 잡는 것만 글로 남긴다.

## 이 저장소

AI Agent(Codex)의 도구 호출을 검사해 Windows Sandbox 안의 Runner로 전달하는 Host와,
반출 파일을 격리·검사하는 Windows 서비스(SecureArtifactScanner)가 들어 있다.

```
Codex ─MCP─▶ host/mcp_server.py ─▶ host/broker.py ─▶ host/runtime_session.py ─WSS─▶ Runner (sandbox_runner)
```

같이 움직이는 b-hamo 저장소는 sandbox_runner(C++ Runner), sandbox_manager(Sandbox 켜고 끄기,
`requirements.txt`에 커밋으로 고정), integration-tests(실제 Sandbox 전 구간 시험)다.

## 어디를 보나

| 알고 싶은 것 | 문서 |
|---|---|
| host/ 파일별 역할, 4개 층, 요청 하나가 지나가는 길, 무엇을 고치려면 어디를 보나 | `host/README.md` |
| 실행 옵션, Broker 검사 순서, Codex 연결, inbox·sandbox_run·Router·반출 | `README.md` |
| Host ↔ Runner 메시지 규격, 담당, 동결 | `schema/README.md` |
| 파일 반출 Runner 계약 | `schema/profiles/artifact-export-v1/README.md` |
| 검사 서비스 구조·판정 기준·실제 검증 결과 | `scanner_service/README.md` |
| Router 통합 설계 | `docs/unified-router-design.md` |
| 통합 설치, Shared·Output 반출 통합 | `docs/solution-install.md`, `docs/unified-export.md` |
| Codex가 SCRP 도구를 쓰는 방법 (팀 공용 스킬) | `codex/skills/secure-sandbox-run/SKILL.md` |

## 명령

Python 3.13 (팀 공통 3.13.15). pytest는 requirements에 없어서 따로 설치한다.

```bash
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt pytest
# 고칠 때마다 (몇 초)
.venv/Scripts/python.exe -m pytest -q tests/test_repo_rules.py tests/test_codex_skill.py
# 커밋 전 (약 5분). 임시 폴더를 AppData 밖에 둔다(아래 첫 항목)
.venv/Scripts/python.exe -m pytest -q tests --basetemp=C:/Users/Public/pytest-host
```

- pytest 기본 임시 폴더(%LOCALAPPDATA%\Temp)를 쓰면 `tests/test_solution.py`의 2개가 실패한다.
  sandbox_manager가 사용자 폴더(AppData 포함) 안의 작업 폴더를 거부하기 때문이다. 코드 문제가 아니므로 `--basetemp`로 돌린다.
- `requirements.txt`가 바뀌면 다시 설치한다. pywin32가 없는 예전 venv에서는 `tests/test_solution.py`가 import 오류로 실패한다.
- 실제 Defender·설치된 서비스 시험은 환경 변수 SCANNER_DEFENDER_TESTS, SCANNER_SERVICE_TESTS, SCANNER_SERVICE_ADMIN_TESTS를
  켤 때만 돈다. 관리자 권한이나 서비스 설치가 필요하므로 에이전트는 켜지 않는다.
- 기본 테스트는 실제 Windows Sandbox를 켜지 않는다(가짜 wsb, `tests/mini_runner.py`). 실제 Sandbox로 하는 검증
  (`host/unified_verification.py`, `scripts/verify_solution.ps1`, integration-tests)은 사람이 PC 상태를 보고 돌린다.

## 규칙

괄호 안은 그 규칙을 검사하는 테스트다. 실패 메시지에 고칠 곳이 나온다.

1. 도구 정의는 `schema/mcp-tools/*.json` 한 곳에만 둔다. 도구를 더하거나 이름을 바꾸면 같이 고칠 곳:
   `host/broker.py`의 `OPERATIONS`·`translate()` 또는 `_dispatch()` 분기, `host/tool_availability.py`의 `REQUIRED_CAPABILITY`,
   필요하면 `host/policy.py`, 스킬(`codex/skills/secure-sandbox-run/SKILL.md`), README 두 곳의 도구 수
   (`tests/test_repo_rules.py`, `tests/test_codex_skill.py`).
2. Agent에게 돌려주는 오류 코드는 `host/broker.py`의 `ERROR_HINTS`에 넣는다. 없으면 `retryable`이 항상 false가 되고,
   `next_step`을 따로 넘기지 않으면 다음 행동 안내도 빠진다 (`tests/test_repo_rules.py`).
3. Broker는 입력을 다시 보내지 않는다. `ACTION_TIMEOUT`이면 `runtime_get_state`로 먼저 확인하게 한다.
4. MCP Server가 tools/list에 답하는 경로는 jsonschema·websockets·cryptography와 Broker를 import하지 않는다.
   Codex는 약 0.5초 안에 도구 목록을 못 받으면 서버를 뺀다 (`tests/test_mcp_server.py`의 `test_tool_list_needs_no_heavy_imports`).
5. `host/policy.py`의 `POLICY_VERSION`은 sandbox_runner와 같이 바꾼다. 다르면 Runner가 모든 입력을 거부한다. 테스트로 못 잡는다.
6. `schema/`는 Runner가 구현하는 계약이다. 메시지 규격을 바꾸기 전에 Runner 담당과 합의한다 (`schema/README.md`의 동결).
7. 의존 방향 (`tests/test_repo_rules.py`):
   - `router/`는 Host를 모르는 Router 핵심이다. host·scanner_service를 import하지 않고, Host 쪽 어댑터는 `host/router_*.py`에 둔다.
   - `scrp/`는 모든 패키지가 같이 쓰는 규격 라이브러리라 다른 패키지를 import하지 않는다.
   - `scanner_service/`는 별도 Windows 서비스로 묶여 배포되므로 host 중에서는 `host/artifact_scan.py`만 import한다.
   - host/README의 ④ 통신 층(connection, session_registry, tls, bootstrap, upload_server, observation_store)은
     Broker·MCP 층을 import하지 않는다.
8. 한글이 들어간 .ps1은 UTF-8 BOM으로 저장한다. Sandbox 안의 Windows PowerShell 5.1은 BOM이 없으면 ANSI로 읽어
   글자가 깨진다 (`tests/test_repo_rules.py`).
9. host/와 scanner_service/에 모듈을 더하면 그 폴더 README 표에 한 줄 넣는다 (`tests/test_repo_rules.py`).
10. 실행하면 생기는 host/.certs, host/.bootstrap, host/.audit 등에는 개인 키와 token이 있다. 커밋하지 않는다(.gitignore).

## 자주 밟는 함정

- 종료 코드 0을 성공으로 믿지 않는다. sandbox_manager가 쓰는 wsb exec는 Guest 프로세스가 시작되기만 하면 0으로 끝나고,
  Guest 프로그램의 실제 종료 코드는 출력 글자("Process exited with code N")에만 있다.
  MpCmdRun도 종료 코드 0만으로 통과시키지 않는다(`scanner_service/README.md` 7·8절).
- 키보드 입력의 ACK는 명령이 끝났다는 뜻이 아니다. 실행 결과는 Guest 영수증과 반출 검사로 확인한다(`host/router_sandbox.py`).
- 걸린 시간으로 단언하는 테스트는 Windows에서 자주 깨졌다(2026-10-22 Fix(tests)). 상태나 이벤트로 단언한다.
- PowerShell을 띄우는 테스트와 스크립트는 -ExecutionPolicy Bypass를 준다. Windows 기본 정책에서는 스크립트를 점 소싱할 수 없다.
- Windows Sandbox는 한 PC에서 한 번에 하나만 뜨고, 첫 부팅은 몇 분 걸릴 수 있다.
- Codex 앱은 대화마다 MCP Server를 하나씩 띄우고 창을 닫아도 살려 둔다. 시작할 때 포트를 잡으면 두 번째 대화부터
  실패한다(`host/single_host.py`).
- 실제 Runner 없이 전 구간을 시험할 때는 `tests/mini_runner.py`와 `tests/artifact_runner.py`를 쓴다.

## 작업 방식

- 기준 브랜치는 develop이다(main에는 초기 커밋만 있다). 브랜치 이름은 feat/<이슈>-<요약>, fix/<요약>, chore/<요약>.
- 커밋 제목은 `#<이슈> Type(scope): 한국어 요약` 형식이다. Type은 Feat·Fix·Docs·Test·Chore·Revert.
  예: `#103 Fix(export): 검증 명령 길이 제한과 실제 세 경로 반출 증거 반영`
- 문서·이슈·PR에는 실명 대신 역할(Runner 담당, Lifecycle 담당)을 쓴다.
- 실제 Windows나 Sandbox에서 확인하지 못한 동작은 "미검증"이라고 적는다.

## 끝내기 전에

1. 빠른 점검과 전체 테스트를 통과시킨다. 실패를 "원래 실패하던 것"으로 넘기려면 develop에서도 같은 실패가 나는지 확인한다.
2. 고친 곳의 문서 표를 갱신한다(`host/README.md`의 "무엇을 고치려면 어디를 보나"와 테스트 표).
3. 같은 실수를 두 번 했다면 다시 못 하게 만든다. 기계로 검사할 수 있으면 `tests/test_repo_rules.py`에 규칙을 더하고,
   아니면 이 파일의 "자주 밟는 함정"에 한 줄 더한다.
