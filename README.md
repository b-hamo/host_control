# minoBox · host_control

**AI 에이전트가 속아도 내 PC는 안전하게.**

Codex, Claude Code 같은 AI 에이전트에게 전체 권한을 주고 일을 맡기면, 에이전트는 웹페이지나 GitHub에서 받은 코드를
사람 확인 없이 실행합니다. minoBox는 에이전트를 막는 대신, **밖에서 온 코드는 격리 공간(Windows Sandbox, micro VM)에서만
실행되게** 하고, 결과물은 검사를 거쳐서만 내 PC로 가져옵니다.

이 저장소(host_control)는 minoBox의 **Host**입니다. 에이전트와 격리 공간 사이에서 요청을 검사하고 전달하는 MCP 서버,
다운로드 서명 검사, 실행 전 검사 hook, 결과물 반출 검사, 로컬 대시보드가 들어 있습니다.

```
Codex · Claude Code ──MCP──▶ Host (이 저장소) ──TLS──▶ Runner (Windows Sandbox · micro VM 안)
        │                     정책 검사 · 감사 기록 · 서명 검사 · 반출 검사
        └── 실행 전 검사 hook: 내 PC에서 위험한 실행을 차단
```

## 무엇을 해 주나

| 기능 | 설명 |
|---|---|
| **격리 실행** | 받은 프로그램, 스크립트, 외부 프로젝트는 Windows Sandbox(또는 micro VM) 안에서만 실행합니다. 끄면 흔적까지 사라집니다 |
| **받는 폴더 (inbox)** | 인터넷에서 받은 파일은 내 PC에서 실행이 금지된 폴더에 둡니다 |
| **서명 검사** | Windows가 신뢰하는 공인 인증 기관의 유효한 서명이 있는 프로그램(.exe, .msi)만 다운로드 폴더로 보내 바로 쓰게 합니다. 서명이 없으면 격리 공간에서만 실행합니다 |
| **실행 전 검사 hook** | 에이전트가 내 PC에서 밖에서 온 파일을 실행하거나, 인터넷에서 받아 바로 실행하는 명령(`iwr … \| iex` 등)을 쓰거나, 보호 설정을 끄려 하면 실행 전에 막습니다 |
| **출처 표시** | 에이전트가 명령으로 받은 파일(`curl`, `iwr` 등)과 `git clone`한 프로젝트에 "밖에서 온 것" 표시를 자동으로 붙입니다. 표시된 프로젝트는 내 PC에서 빌드·실행(`npm install`, `python` 등)할 수 없고, 에이전트가 표시를 지울 수도 없습니다. 격리 공간이 아직 못 돌리는 종류(Maven·Gradle·make·PHP·VBScript·Visual Studio C++)는 사용자에게 허용 여부를 묻습니다(Claude Code는 자체 확인 창, Codex는 minoBox 확인 창). 허용해야만 실행됩니다 |
| **웹 명령·외부 코드 분석** | 웹페이지가 시킨 명령과 GitHub 코드는 데이터로만 받아 격리 공간에서 실행합니다 |
| **결과물 반출** | 격리 공간의 결과물은 Microsoft Defender 검사를 통과한 것만 다운로드 폴더(`SandboxOutput`)로 가져옵니다 |
| **병렬 실행** | Windows Sandbox가 사용 중이면 micro VM을 띄워 작업을 동시에 처리합니다 |
| **대시보드** | 켜진 격리 공간, 진행 중인 작업, AI가 본 화면, 반출 기록을 이 PC에서만 열리는 웹 화면으로 보여 줍니다 |

## 필요한 환경

- Windows 11 **Pro 또는 Enterprise** x64, **Windows Sandbox 기능**과 하드웨어 가상화 켜짐 (Home 에디션은 지원하지 않습니다)
- Microsoft Defender
- Python 3.13 x64, Git
- MSYS2 UCRT64의 gcc, cmake, ninja, jsoncpp (Runner 빌드용)
- AI 에이전트: **Codex** 또는 **Claude Code** (둘 다 써도 됩니다)
- micro VM 병렬 실행은 선택입니다. minoBox 관리 서비스가 따로 필요합니다 ([설치 안내](docs/solution-install.md))

## 설치

세 저장소를 같은 폴더에 받습니다.

```powershell
git clone https://github.com/b-hamo/host_control
git clone https://github.com/b-hamo/sandbox_manager
git clone https://github.com/b-hamo/sandbox_runner
```

**일반 PowerShell**에서 host_control 폴더로 이동해 설치하고 쓰는 에이전트에 등록합니다. 검사 서비스·방화벽 단계에서 UAC 승인을 한 번 묻습니다.

```powershell
cd host_control
# Codex
powershell -NoProfile -ExecutionPolicy Bypass -File installer/install_solution.ps1 -Mode Deploy -RegisterCodex
# Claude Code (claude CLI가 PATH에 있어야 합니다)
powershell -NoProfile -ExecutionPolicy Bypass -File installer/install_solution.ps1 -Mode Deploy -RegisterClaude
```

둘 다 쓰면 `-RegisterCodex -RegisterClaude`를 함께 줍니다. 이미 설치한 뒤 나중에 Claude Code만 추가하려면
`installer/register_claude.ps1`을 실행합니다. Claude Code에는 사용자 범위(모든 프로젝트)로 `scrp_sandbox`라는 이름으로 등록됩니다.

등록할 때 다음 두 가지도 함께 설치됩니다.

- **팀 Skill**: 에이전트에게 "밖에서 온 코드는 Sandbox로" 같은 사용법을 알려 주는 지침
- **실행 전 검사 hook**: 위 규칙을 지침이 아니라 코드로 강제합니다. 에이전트가 속거나 지침을 무시해도 같은 결과가 나옵니다

Codex는 새 hook을 신뢰해야 실행하므로 Codex 앱의 **설정 → Hooks**에서 신뢰로 등록합니다. 설치가 끝나면 에이전트를 다시 시작합니다. 설치가 하는 일, 옵션, 갱신 방법은 [통합 설치 안내](docs/solution-install.md)에 있습니다.

### 설치 확인

```powershell
powershell -ExecutionPolicy Bypass -File scripts/check_solution.ps1
```

`SOLUTION_READY`가 나오면 준비된 것입니다. Claude Code는 `claude mcp list`에서 `scrp_sandbox`가 `Connected`로 보여야 합니다.
실제 동작까지 확인하려면 에이전트에게 **"7-Zip 콘솔판(7zr.exe) 받아서 실행해 줘"**라고
시켜 보세요. Windows Sandbox 창이 뜨고 그 안에서 실행되면 정상입니다.

### Skill과 hook만 따로 설치하기

등록 스크립트에 `-NoGuard`를 주면 Skill과 hook을 건너뜁니다. 나중에 따로 넣으려면:

```powershell
powershell -ExecutionPolicy Bypass -File codex/install_skill.ps1 -Agent Both    # Codex | Claude | Both
py -3.13 host\exec_guard.py install --codex --claude --inbox "$env:USERPROFILE\SecureCUA\solution"
```

## 사용하기

평소처럼 Codex나 Claude Code에게 말하면 됩니다. 밖에서 온 것은 minoBox가 알아서 격리 공간으로 보냅니다.

| 이렇게 말하면 | 이렇게 됩니다 |
|---|---|
| "7-Zip 받아서 사진 압축해 줘" | 서명이 없는 7zr.exe는 받는 폴더에만 두고 Sandbox에서 실행, 압축 파일만 검사 후 다운로드 폴더로 |
| "PuTTY 설치해 줘" | 공인 서명이 확인되어 다운로드 폴더에 저장, 바로 사용 |
| "이 GitHub 프로젝트 실행해 줘" | 빌드부터 실행까지 Sandbox 안에서만 |
| "이 페이지에 나온 명령 실행해 줘" | 명령을 데이터로 받아 Sandbox에서 실행, 내 PC에서는 실행하지 않음 |

결과물은 `다운로드\SandboxOutput\<세션>\` 아래에 들어옵니다. 에이전트가 직접 짠 코드와 사용자 자신의 프로젝트는 평소처럼 내 PC에서 실행됩니다.

## 대시보드

```powershell
py -3.13 -m dashboard --open
```

`http://127.0.0.1:17480`에서 격리 공간 상태, 진행 중인 작업, AI가 마지막으로 본 화면, 파일 반출 기록을 봅니다.
이 PC에서만 열리고 보기 전용입니다. 자세한 내용은 [대시보드 문서](dashboard/README.md)에 있습니다.

## 보안 모델과 한계

- **보호 대상은 AI 에이전트의 실행**입니다. 사용자가 직접 실행하는 프로그램은 기존 백신의 영역이며, minoBox는 관여하지 않습니다.
- minoBox는 악성 여부를 **탐지하지 않고 격리**합니다. Microsoft Defender를 대체하지 않고 함께 씁니다(반출 검사에도 Defender를 사용).
- 서명은 "누가 만들었는지"의 증거이지 안전 보증이 아닙니다. 다른 코드를 실행하는 프로그램(PowerShell, Python 등)과 원격 제어 도구(AnyDesk 등)는 서명이 있어도 바로 쓰게 하지 않습니다.
- 실행 전 검사 hook은 명령 문자열을 보고 판단하므로 일부러 난독화한 명령은 놓칠 수 있습니다. 그래서 격리 실행을 2차 방어로 둡니다.
- 출처 표시는 에이전트가 **명령으로** 받은 것에만 붙습니다. 에이전트가 직접 짠 다운로드 스크립트를 실행해 받은 파일은 표시가 붙지 않을 수 있습니다.
- micro VM은 Windows Sandbox 플랫폼의 문서화되지 않은 인터페이스를 쓰는 시험 단계 기능입니다.

## 문서

| 문서 | 내용 |
|---|---|
| [통합 설치](docs/solution-install.md) | 설치·갱신·제거, micro VM 관리 서비스 |
| [상세 참조](docs/reference.md) | 실행 옵션, Broker 검사 순서, 도구별 동작, Runner 접속 방식 (개발자용) |
| [host/README.md](host/README.md) | Host 코드 구조와 파일별 역할 |
| [dashboard/README.md](dashboard/README.md) | 대시보드 API |
| [scanner_service/README.md](scanner_service/README.md) | 반출 검사 서비스 |
| [schema/README.md](schema/README.md) | Host ↔ Runner 메시지 규격 |
| [docs/validation/](docs/validation/) | 실제 PC 검증 기록 |
| [AGENTS.md](AGENTS.md) | 이 저장소를 고치는 사람(과 코딩 에이전트)을 위한 규칙 |

## 저장소 구성

| 폴더 | 내용 |
|---|---|
| `host/` | MCP 서버, Broker(정책·감사), Runner 연결, 다운로드·서명 검사, 반출, 실행 전 검사 hook |
| `router/` | 웹 명령·외부 코드 분석 엔진 |
| `scanner_service/` | 반출 파일을 검사하는 Windows 서비스 |
| `dashboard/` | 로컬 대시보드 (백엔드, 프론트 소스 `frontend/`, 빌드 결과 `static/`) |
| `scrp/` | Host ↔ Runner 프로토콜 라이브러리 |
| `schema/` | MCP 도구 정의와 메시지 스키마 |
| `installer/`, `scripts/` | 통합 설치·확인·실행 스크립트 |
| `codex/` | 팀 Skill(Codex·Claude Code 공용)과 Codex 설정 예시 |
| `tests/` | 테스트 |
| `tools/lab/` | 실제 VM 장애·통합 시험 도구 (개발용) |

함께 쓰는 저장소: [sandbox_manager](https://github.com/b-hamo/sandbox_manager) (격리 공간 켜고 끄기),
[sandbox_runner](https://github.com/b-hamo/sandbox_runner) (격리 공간 안의 Runner), micro_VM (minoBox micro VM).

## 개발

```powershell
py -3.13 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt pytest
.venv\Scripts\python.exe -m pytest -q tests --basetemp=C:/Users/Public/pytest-host
```

규칙과 확인 방법은 [AGENTS.md](AGENTS.md)를 따릅니다.
