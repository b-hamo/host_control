# 통합 설치 자동화 검증 기록 — 이슈 #101

## 결과

자동화 구현과 제한된 회귀 검증은 완료했다. **이번 변경을 적용한 전체 설치·새 Sandbox
READY·실제 반출은 미완료**다. 새 SecureArtifactScanner 실행 파일이 Defender에 격리되었고,
설치기가 성공으로 처리하지 않았다. PR은 이 차단 사유를 해결하기 전까지 Draft로 유지한다.
이전 PR #100의 실제 반출 성공 기록을 이번 자동화의 성공 증거로 재사용하지 않는다.

## 실행한 검증

- Runner develop `91421020388cb9265335630b1b40649c18b0e955` 위 빌드 스크립트 변경:
  MSYS2 UCRT64 GCC 16.2.0 / CMake / Ninja, 공백·한글 경로에서 실제 제품 빌드 성공.
  SHA-256 `3b3648f50db8f6139406a5cded20f3f7be6cf16f0c3362d459bab0ea17bfeb6f`.
  `build/solution/build-info.json`의 산출물 해시와 경로 확인. 도구 부재 시 종료 코드 1과 Windows PowerShell 파싱도 확인. EXE의 Guest 실행은 미검증.
- Windows Host / Python 3.13.16: 사용자 허용 범위에서 아래 회귀 테스트 **32 passed**.
  Windows PowerShell 파싱, 설정 백업·반복 등록·관련 없는 TOML 보존, 잘못된 설정 거부,
  설치 잠금, 열린 Sandbox/사용 중인 Python 갱신 거부, 외부 명령 실패 전파,
  Scanner preflight 실패 시 시작/설정 공개 거부, MCP 오류/시간 초과 시 입력 재전송 금지, 실제 PowerShell stdio 실행기의 JSON-RPC 입출력 보존.
  서비스·VM은 대역으로 검사했다. 실제 검사 서비스 복원/재설치/백신 제외는 하지 않았다.

```text
python -m pytest tests/test_solution.py tests/test_solution_config.py
  tests/test_solution_powershell.py tests/test_solution_session.py
  tests/test_codex_skill.py -q --tb=short --basetemp <허용된 임시 경로>
```

## 실제 설치 시도에서 확인한 실패

2026-10-31 21:58:42 KST, 서비스 빌드/설치 중 Microsoft Defender가 다음을 탐지했다.
서비스·계정·ACL 및 정상 파일 CLEAN 확인 후 설치의 남은 검증 단계에서 실행 파일과 서비스가
제거되었다. 설치 결과는 실패이고 새 solution.json/Codex 등록을 공개하지 않았다.

- 탐지: `Trojan:Win32/Bearfoos.A!ml`, ThreatID `2147731250`
- 파일: `C:\Program Files\SecureRuntime\ScannerService\SecureArtifactScanner.exe`
- SHA-256: `9642dc2243234171e9aa96275badcf0ca7f00fd5771dd1ec97a5ab00db3ba1f1`
- Defender platform `4.18.26100.4-0`, engine `1.1.26100.4`, signature `1.463.47.0`
- 설치 결과: `install-c0dfb9d59f2a4e2db749aa90a0f0d0c5.result.json`의 `ok=false`
- 근거: Defender 탐지/조치 이벤트 1116/1117, State의 setup.log/setup-elevated.log.
- 후속 읽기 확인: `SecureArtifactScanner` 서비스와 설치 실행 파일이 없음.

EICAR 검증용 탐지와 위 실행 파일 탐지는 별개다. 오탐 여부를 확정하지 않았다.
검사기를 우회하거나 Defender 예외를 추가하지 않았다. 기존 MCP 설정 자체는 유지했지만
검사 서비스가 없어 현재 통합 진입점의 다음 시작은 preflight에서 차단된다.

연결된 기존 MCP의 Python 환경에 Manager를 editable 재설치한 초기 시도에서는,
이전 패키지를 메모리에 읽어 둔 프로세스가 새 모듈을 찾지 못했다.
`SES-e8f149bd9d514665a3f6ad7ecf549a65` 시작 실패:
`ModuleNotFoundError: No module named 'sandbox_manager.window_session'`.
런타임은 TERMINATED/host_released 상태가 됐다. 이후 Sandbox 테스트 대신 사용자가
Host의 제한된 회귀 테스트를 허용했다.

최종 코드는 전체 설치마다 새 환경을 만들고 일부 갱신 전에는 환경 사용 여부를 검사한다.
새 환경을 참조하는 고정 MCP 실행 스크립트, Manager 방화벽 설치 호출도 추가했다.
이 최종 설치 흐름과 방화벽 UAC 단계는 차단 이후 **실환경에서 다시 실행하지 않았다**.

## Draft 해제 전 필요한 작업

- [ ] 탐지된 산출물/소스/빌드 의존성 검토와 Defender 판정 원인 확인. 필요한 경우 공급자에
  샘플 판정을 요청하고 검증된 배포 산출물을 준비한다. 근거 없이 오탐/예외 처리를 하지 않는다.
- [ ] 검토된 서비스 산출물로 설치·유지·정상 파일 CLEAN·EICAR BLOCKED를 다시 검증한다.
- [ ] 새 Python 환경을 사용하는 MCP 재연결, 실제 방화벽 적용, Manager/Runner READY를 확인한다.
- [ ] `scripts/verify_solution.ps1`에서 사용자 종료·보관 승인 후 EXPORTED, 원본 바이트/해시,
  MOTW, 서비스 CLEAN 감사 기록을 대조한다.
- [ ] 사전 도구만 설치된 별도 지원 PC에서 설치/재설치 및 Dev/Deploy/구성요소 갱신을 확인한다.
