# 세 구성요소 통합 설치와 반출

`host_control`이 MCP와 승인·검사를 담당하고, requirements.txt에 고정된
`sandbox_manager`가 VM과 공유 매핑을 관리하며, `sandbox_runner.exe`가 Guest에서
실행된다. 통합 진입점 `host/solution.py`는 Shared와 artifact_export를 모두
SecureArtifactScanner에 연결한다. 별도 검사기 옵션을 기억할 필요가 없다.

## 설치

Windows Sandbox를 사용할 수 있는 Windows, Microsoft Defender, Python 3.13 x64,
Git, 현재 프로토콜에 맞춰 빌드한 `sandbox_runner.exe`가 필요하다. Runner 바이너리는
해당 저장소의 빌드 절차로 준비한다. 이 설치기는 Runner를 재빌드하지 않는다.

Host를 사용할 **같은 사용자 계정**의 관리자 PowerShell에서:

```powershell
./installer/install_solution.ps1 -RunnerExe 'C:\solution\sandbox_runner\build\sandbox_runner.exe'
```

1. Host venv를 만들고 requirements.txt의 고정된 Manager 등 의존성을 설치한다.
2. 전용 `~/SecureCUA/solution/inbox`, `shared`를 만들고 Host 실행 금지 ACL을 설정한다.
3. 검사 서비스를 빌드·설치하고 Shared 검사를 활성화한다. 전용 비관리자 서비스
   계정, 자동 시작, 파이프 사용자, artifact ExportRoot도 함께 설정한다.
4. 실제 서비스·Defender·Shared 활성화·ExportRoot·실행 금지 ACL을 확인한 뒤
   `~/SecureCUAState/solution/mcp.toml`을 만든다. 실패하면 새 설정을 공개하지 않는다.

기존 Python/검사 서비스 배포 묶음을 사용하려면 `-PythonExe`, `-ScannerSourceDir`,
오프라인 의존성이 이미 준비된 경우 `-SkipDependencyInstall`을 사용한다.
`-Work`, `-State`, `-ConfigOut`으로 경로를 지정할 수 있다. Work는 코드, 사용자
폴더, 상태 저장소와 분리해야 한다. 설치/재설치는 기존 검사 서비스를 교체·재시작한다.
설치 검증은 EICAR 테스트를 포함하므로 Defender 탐지 기록이 남을 수 있다.

생성된 mcp.toml로 기존 Codex 설정의 `scrp`/`scrp_sandbox` 등록을 **교체**한다.
다른 MCP 설정은 유지한다. 현재 Sandbox 작업을 마친 후 MCP를 다시 연결한다.
설치기는 열린 Sandbox를 종료하거나 Codex 설정을 덮어쓰지 않는다.
Host는 관리자 권한이 아닌 평소 사용자로 실행한다.

## 실행과 실패 처리

MCP는 `solution.py`를 실행한다. 이 진입점은 서비스의 SCM PID·전용 계정,
Defender 사용 가능 상태, Shared 검사 활성화, artifact ExportRoot 일치,
inbox와 Shared의 실행 금지 상태를 검사한다. 실패하면 `SOLUTION_NOT_READY`로
종료하며 VM을 시작하지 않는다. 실행 후 서비스가 중단돼도 각 반출 단계의 재검사가
실패하므로 공개하지 않는다. 다른 검사기로 자동 전환하지 않는다.

수동 사전 점검은 생성된 실행 인수에 `--check`를 붙인다. VM을 시작하지 않는다.
저수준 `host/mcp_server.py`는 개별 기능 시험용 옵션을 계속 제공하지만 통합 솔루션은
`solution.py`를 사용한다.

## 반출 흐름과 실제 검증

Guest `Desktop/Shared` → Work/shared/<세션> (Host 실행 금지) → VM 종료/정리 확인
→ 서비스 전용 Quarantine으로 업로드·Defender 검사 → 전부 CLEAN이고 사용자가 보관 선택
→ Windows Known Folder 다운로드/SandboxShared/<세션>에 원본 핸들의 같은 바이트 복사.
파일 크기·SHA-256과 MOTW를 확인한다. 승인 창은 종료 직후 미리 표시될 수 있지만,
보관 선택만으로 검사 완료 전에 파일이 공개되지는 않는다.

Shared는 파일당 최대 50 MiB, 전체 2 GiB/20,000개다. 한 파일이라도 악성·미확인·오류·한도
초과이면 전체 반출을 보류/차단한다. artifact_export는 기존 UTF-8 TXT 정책을 유지하며
State/exports에 저장한다.

실제 배포 검증은 다음 증거를 함께 확인한다.

- 서비스가 전용 계정으로 실행되고 preflight가 통과한다.
- task_submit 뒤 실제 Manager VM과 Runner 연결이 READY가 된다.
- Guest에서 무해한 테스트 파일을 Shared에 만들고 원본 SHA-256을 기록한다.
- 사용자가 세션 종료와 보관을 선택한다. Host의 `SHARED ... at session end: EXPORTED`
  로그를 확인한다. 연결이 유지되는 동안에는 `shared.at_end`도 확인할 수 있다.
- 호스트 다운로드 파일의 내용·크기·SHA-256·ZoneId=3과 서비스 감사 로그의 CLEAN을 대조한다.

자동 테스트의 가짜 Defender/VM 판정은 위 실제 배포 증거를 대신하지 않는다.

## 2026-10-31 배포 검증 기록

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
