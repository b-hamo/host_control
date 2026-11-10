# 세 레포 통합 설치와 개발 갱신

`host_control`이 설치와 실행을 조정한다. 같은 PC의 `sandbox_manager`를 Python
패키지로 설치하고 `sandbox_runner`를 빌드하며, Output 반출에
SecureArtifactScanner를 기본 적용한다. Manager 소스 변경은 필요 없다.

통합 실행은 Output 단일 반출을 기본 선택한다. Sandbox 바탕화면의 Output 바로가기에
결과물을 저장하고 서비스 검사에서 CLEAN인 파일을 다운로드에 자동 저장한다. 결과는 알림창 대신 MCP 응답으로 확인한다.
정상 종료 전에도 Output을 확보하고 같은 절차를 사용한다. [Output 반출 정책](output-only-export.md).

> 재검증 상태: Defender 정의 갱신 후 동일 해시의 기존 EXE가 탐지되지 않았다.
> 새 배포 묶음 검사, 통합 설치, 정상 파일/EICAR 검사, 실제 Manager/Runner READY까지
> 통과했다. 사용자 종료·보관 승인 후 다운로드 EXPORTED와 파일 해시/MOTW까지 확인했다.
> [탐지 조사와 재검증](defender-investigation-101.md), [초기 검증 기록](solution-automation-validation.md).

## 지원 환경과 사전 준비

Windows Sandbox와 `wsb` CLI를 지원하고 기능이 활성화된 Windows x64, 가상화, Microsoft Defender,
Python 3.13 x64, Git, MSYS2 UCRT64가 필요하다. OS 기능 활성화·재부팅·개발 도구 설치와
조직의 실행 정책 승인은 사전 준비다. 설치기는 보안 기능을 끄거나 백신 제외를 만들지 않는다.
관리자 그룹에 속한 사용자가 **일반 PowerShell**에서 시작하고, 서비스/ACL/방화벽 단계만
같은 계정으로 UAC를 승인한다. 별도 관리자 계정으로 자격 증명을 바꾸는 설치는 지원하지 않는다.

MSYS2 UCRT64에 gcc, cmake, ninja, jsoncpp 패키지가 필요하다. 세 레포는 호환되는
브랜치/커밋으로 받아 둔다. Output 전환에는 Host #105와 Runner #35 변경이 함께 필요하다.
기존 Runner에 `artifact.output.v1`이 없으면 READY 단계에서 거부한다.
스크립트는 사용자의 Git checkout을 pull/reset하거나 브랜치를 바꾸지 않는다.

```text
workspace/
  host_control/
  sandbox_manager/
  sandbox_runner/
```

Host 저장소에서 한 명령으로 준비 후 독립 실행:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File installer/install_solution.ps1 -Mode Dev -Start
```

Codex에 연결해 사용할 때는 `-Start` 대신 `-RegisterCodex`를 지정한 뒤 MCP를 다시 연결한다.
독립 세션과 Codex 세션을 동시에 시작하지 않는다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File installer/install_solution.ps1 -Mode Dev -RegisterCodex
```

다른 폴더 구조에서는 `-ManagerRepo`, `-RunnerRepo`, `-UcrtRoot C:\msys64\ucrt64`를
지정한다. `-PythonExe`는 Python 3.13 x64 실행 파일이며 미지정 시 `py -3.13`을 사용한다.
`-CheckOnly`는 레포·도구 사전 점검만 한다. 서비스/Defender/ACL 정상 판정이 아니다.

## 설치가 하는 일

1. 기존 Sandbox가 있으면 종료하지 않고 중단한다. State의 설치 잠금으로 같은 구성의 동시 갱신을 막는다.
2. `State/envs/<고유 ID>`에 새 Python 환경을 만든다. Host 의존성과 로컬 Manager를 설치한다.
   Dev는 editable 설치, Deploy는 일반 패키지 설치다. Host는 두 모드 모두 해당 소스 checkout을 사용한다.
3. Runner의 `scripts/build.ps1`을 호출하고 산출물 경로·SHA-256을 확인한다.
4. 검사 서비스를 새로 빌드한다. Defender 정의 갱신 후 배포 묶음 전체를 검사하고 파일 해시/탐지 이벤트를 대조한다. UAC 설치에서도 기존 서비스 교체 전에 다시 검사한다. UAC 단계에서 Work 실행 금지 ACL, 전용 서비스 계정,
   Output 검사에 쓰는 scan-only 기능, artifact ExportRoot를 설정하고 서비스의 정상 파일/EICAR 검증을 수행한다.
   서비스 설치 옵션의 기존 이름 `EnableSharedScan`은 scan-only API 사용 여부이며 Shared 매핑을 만들지 않는다.
5. Manager의 `tools/install_firewall.ps1`을 호출한다. Sandbox 스위치의 TCP 17443/17444 허용,
   다른 Host 포트 차단, 재부팅 후 어댑터 재연결용 SYSTEM 작업을 기존 Manager 방식으로 설정한다.
   실제 어댑터 적용은 첫 VM 시작 시 Manager가 확인한다.
6. 일반 사용자 preflight를 통과하면 `solution.json`과 `mcp.toml`을 기록한다.
   선택한 경우 기존 Codex 설정을 백업하고 `scrp_sandbox` 부분만 교체한다.

기본 Work는 `~/SecureCUA/solution`, State는 `~/SecureCUAState/solution`이다.
`-Work`, `-State`로 바꿀 수 있지만 코드/사용자 폴더/상태 파일과 쓰기 공유 영역은 분리해야 한다.
프로필에는 세 레포 경로, 커밋, 미커밋 변경 여부, Python 경로, Runner 해시, 모드를 기록한다.
빌드 기록은 서명이나 프로토콜 호환성 증명이 아니다. 설치는 PC의 단일 검사 서비스와 Manager
방화벽 규칙을 구성하므로 여러 Work/State 설치를 동시에 운용하는 기능은 아니다.

## 개발 중 실행과 갱신

Shared 구성에서 처음 전환할 때는 세 레포의 호환 버전을 받은 뒤 `-Component All`로 갱신한다.
새 실행 금지 `Work/output` 폴더와 새 Runner가 함께 필요하므로 Host 소스 교체만으로 이전하지 않는다.
이전 `Work/shared` 및 `Downloads/SandboxShared` 파일은 그대로 남으며 사용자가 별도로 관리한다.

```powershell
powershell -ExecutionPolicy Bypass -File scripts/check_solution.ps1
powershell -ExecutionPolicy Bypass -File scripts/start_solution.ps1
powershell -ExecutionPolicy Bypass -File installer/update_solution.ps1 -Component Runner
```

명령에 `-State`를 주면 사용자 지정 프로필을 사용한다. 갱신 전에 Sandbox를 직접 종료하고
해당 MCP 연결을 끊는다. 환경을 사용하는 Python이 남으면 일부 갱신을 거부한다.

| 변경 대상 | 갱신 방법 |
|---|---|
| Host Python 소스 | MCP 재연결. 의존성도 변경했으면 `-Component Host` |
| Manager 소스 | Dev는 재연결로 반영. 의존성/일반 설치 갱신은 `-Component Manager` |
| Runner C++ | `-Component Runner` 후 MCP 재연결/새 Sandbox |
| Scanner | `-Component Scanner`로 재빌드·UAC 설치·검증 |
| 전체 | `-Component All`로 새 Python 환경을 준비한 뒤 MCP 재연결 |

자동 생성한 MCP 설정은 `scripts/start_solution.ps1 -Stdio -State ...`를 실행한다.
이 스크립트가 현재 `solution.json`의 Python을 선택하므로 전체 갱신 때 Codex 설정을 다시
수정할 필요가 없다. 레포나 State 자체를 옮기면 설치/등록을 다시 한다.

Codex 등록만 다시 하려면 `installer/register_codex.ps1`을 사용한다. 기본 대상은
`CODEX_HOME/config.toml` 또는 `~/.codex/config.toml`이며 `-ConfigPath`로 바꿀 수 있다.
설치 명령에서는 `-CodexConfig`를 사용한다. 이전 MCP 이름 `scrp`가 있으면 중복 실행을
피하도록 거부하므로 사용자가 기존 등록을 제거/이름 변경해야 한다. 복잡한 TOML을 안전하게
교체할 수 없으면 기존 파일을 유지하고 생성된 `mcp.toml`의 수동 적용을 안내한다.
팀 Skill은 선택적으로 `codex/install_skill.ps1`로 설치한다. MCP 등록과 별개다.

## 실패 처리와 재실행

### micro_VM 관리 서비스와 일반 권한 Host

수정된 micro_VM 묶음의 `install-management-service.ps1`은 동일 계정의 관리자 승인으로
`MinoVmManagement`를 최초 설치한다. 자세한 설치·권한·제거 제한은 해당 묶음의
`management-service.md`를 따른다. 현재는 UAC 분리 토큰이 있는 관리자 그룹 계정에서
**Host·중계를 일반 권한(Medium)으로 실행하는 구성**이다. 연결된 High 토큰이 없는
표준 계정 지원과 혼동하지 않는다.

`install_solution.ps1 -Mode Deploy -VmMode AutoAppWindow`에 다음 값을 추가한다.

```powershell
-MicroVmPackage 'C:\Program Files\MinoBox-Management' `
-MicroVmRoot 'C:\ProgramData\MinoBox-Management\runtime' `
-MicroVmRelay 'C:\reviewed\minoBox-package\ScrpRelay.exe' `
-MicroVmMaxActive 8
```

root와 max_active는 설치된 `management.json`과 일치해야 한다. 프로필은 dbictl·relay·Runner와
함께 `MinoVmService.exe` 및 `management.json`의 SHA-256을 고정한다. 내용이 바뀌거나 고정값이
없으면 시작을 거부한다. 최초 이미지 준비를 위해 micro_VM 경로의 시작 대기는 1,200초이며,
세션 고정·기존 Runner 종료 확인을 전제로 한 복구를 일반 배포에서도 사용한다.
설치·업데이트의 기존 활성 세션 보호 조건은 유지한다. 사용 중인 서비스를 덮어쓰지 않는다.

기본 requirements의 Manager 고정 커밋은 `e20fc2bdf0bd1994a5aa5b9048d8428b2e19f683`이다.
별도 `ManagerRepo`로 wheel을 만드는 설치에서는 같은 변경이 포함된 checkout을 지정한다.
Host·Manager·Runner·micro_VM의 대응 PR을 함께 검토해 배포한다.

2026-11-09 실제 PC에서는 설치된 관리 서비스와 별도 venv에 설치한 Manager wheel을 사용해
Medium Host의 B·C READY, 화면·한글 입력, Router 완료 영수증, Defender 반출을 검증했다.
WSB A와 기존 세션은 유지했다. Host 소스는 작업 checkout이며, 모든 의존성·서비스를 처음부터
설치하는 `install_solution.ps1` 전체 실행, 표준 계정 및 재부팅 후 검증은 별도 범위다.
근거는 `docs/management-service-validation-20261109.md`를 참조한다.

서비스·Defender·scan-only 기능·ExportRoot·Output ACL·Runner 해시 검사에 실패하면 VM을 시작하지 않는다.
검사기를 우회하거나 자동 대체하지 않는다. 설치 후 서비스가 사라져도 다음 시작이 차단된다.
서비스 검증이 실패하면 새 프로필과 Codex 등록을 공개하지 않는다. Codex 등록 단계만 실패하면
준비된 프로필은 남고 등록 명령만 재시도할 수 있다.

새 환경은 기존 MCP가 사용하던 환경을 덮어쓰지 않는다. 이전 환경/프로필 백업/실패 로그는
자동 삭제하지 않으며, 필요한 진단 후 사용하지 않는 것을 사용자가 정리한다. 부분 업데이트와
관리자 단계는 전체 트랜잭션이 아니다. 실패해도 이미 설치한 패키지·ACL·서비스·방화벽은
자동 롤백되지 않는다. 백업 프로필 복원만으로 이전 서비스가 복원되지는 않는다.
`setup.log`, `setup-elevated.log`, `update.log`, `install-*.result.json`에서 실패 단계를 확인한다.

## 실제 반출 검증

```powershell
powershell -ExecutionPolicy Bypass -File scripts/verify_solution.ps1
```

검증 클라이언트는 실제 MCP → Manager VM → Runner READY를 기다리고 Guest 바탕화면의
Output 바로가기를 통해 무해한 BIN·ZIP·TXT 샘플을 만든다. 실행 중 BIN·ZIP을 반출한 뒤
사용자가 Sandbox 창을 닫으면 남은 TXT를 같은 검사·CLEAN 자동 저장 절차로 처리한다.
도구가 사용자 종료를 대신하지 않는다. Host EXPORTED 상태, 다운로드 파일 바이트·해시,
MOTW의 ZoneId=3과 단일 사본을 확인해 `State/unified-export-verification.json`에 결과를 남긴다.
실패/시간 초과 때 기존 Sandbox를 임의 종료하지 않으며 사용자가 닫을 때까지 연결을 유지한다.

반출 경로는 Guest의 세션별 `output` → HTTPS → `Work/output/<세션>/<반출 ID>` (실행 금지)
→ 서비스 Quarantine 검사 → CLEAN 확인 → Windows 다운로드 Known Folder의
`SandboxOutput/<세션>/<반출 ID>`이다. 실행 중 artifact_export와 종료 후 처리가 같은 경로를 쓴다.
정상 종료 전에는 전체 Output의 잠긴 목록을 받아 각 파일 수신·해시 대조·목록 재확인을 마친다.
파일당 50 MiB, 목록당 총 200 MiB, 탐색 파일/폴더 각각 4,096개 및 목록 응답 크기 한도를 적용한다.
한도를 넘거나 파일이 계속 쓰이는 등 확보에 실패하면 정상 종료를 진행하지 않는다.
악성·미확인·검사 오류는 공개하지 않는다. [#105 검증 기록](output-only-validation.md)은 이전 승인 창 방식의 기록이다.
[#109 자동 반출](automatic-output-export.md)은 Sandbox 전체 테스트 717개 통과와 실서비스 정상 로그 자동 반출을 확인했다.
실제 악성 파일과 새 세션 종료 후 전체 자동 저장은 별도 검증 범위이며 자동 회귀와 구분한다.

## 이전 PR #100 배포 검증 기록 (현재 자동화의 검증 결과 아님)

위 설치기로 Host venv·고정 Manager·서비스·ACL·MCP 설정을 설치하고 일반 사용자
권한에서 `--check`를 통과했다. 생성된 MCP 설정의 명령/인수/환경 그대로 stdio
클라이언트에서 실제 Host를 실행했다. Runner는 기존 빌드 바이너리를 사용했다.
Codex 설정도 같은 생성 내용으로 교체했으며, 기존 연결의 자동 재로드는 검증 범위가 아니다.

- Windows Sandbox / Python 3.13.7: 관련 12개 테스트 파일 **195 passed, 35 skipped**,
  42.49초, 종료 코드 0. 제외: 일반 사용자 실행이 필요한 33개, opt-in Defender 2개.
  Guest 로그 화면으로 확인했으며 기존 연결의 RUN-0008 결과 전송은
  `RESULT_EXPORT_REFUSED`로 HELD였으므로 성공 영수증으로 계산하지 않았다.
- Host 서비스 빌드/설치 검증: Python 3.13.16 x64, 전용
  `NT SERVICE\SecureArtifactScanner`, 자동 시작. 정상 파일 CLEAN 및 EICAR BLOCKED.
- 실제 Manager/Runner READY → Guest에서 `C:\Shared\solution99.txt` 생성
  → VM 종료 확인/정리 → 서비스 Shared 검사 CLEAN → 실제 승인 창 keep → 다운로드 저장.
- 세션 `SES-c4341a243fd14244a349f2ab222f4e94`, 파일 42바이트,
  SHA-256 `33033e2cfd3768b57372fe7d119d1e800d211ee1e75b570144bd58cff79f73da`.
  다운로드의 `SandboxShared/<세션>/solution99.txt`는 원본과 내용·크기·해시가 같고
  `Zone.Identifier`의 `ZoneId=3`을 확인했다.
- 서비스 Job `job-db4e5052b0bf1182075109f0b5ba8032`: `scan_profile=shared`,
  `defender_verdict=CLEAN`, 종료 코드 0, 위 해시와 일치. Shared는 scan-only이므로
  검사 후 서비스 사본을 ABORT/DISPOSE한다. 감사 기록의 최종 `CANCELLED/ABORTED`는
  사본 정리이며 반출 실패를 뜻하지 않는다. 실제 공개 결과는 Host의 `EXPORTED` 기록이다.
- Defender platform 4.18.26100.4-0 / engine 1.1.26100.4 / signature 1.463.47.0.
  EICAR는 설치 검증에서 차단을 확인했고 Shared 악성 파일의 전체 UI 경로는 별도로
  실행하지 않았다. 무해한 파일의 실제 반출과 자동 테스트의 차단 경로를 구분한다.
