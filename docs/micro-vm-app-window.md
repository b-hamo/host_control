# micro_VM 앱 창 SCRP 연결 (#113)

전체 Windows 바탕화면을 요청하지 않고 VM마다 Runner의 앱 창을 제어한다.
Win+R은 Runner의 전용 명령 입력 창이며 Windows Shell의 Run 창·작업 표시줄·IME는 아니다.
기존 MCP/Broker, TLS, 정책, 세대, heartbeat, 입력 중복 방지와 파일 검사 경로를 사용한다.

## 구성과 재현

1. 수정한 sandbox_manager checkout을 Host의 PYTHONPATH에 지정한다. 설치된 고정 의존성으로 대체하지 않는다.
2. Runner를 `scripts/build.ps1 -BuildDir <별도 빌드 폴더>`로 빌드한다.
3. micro_VM 실행 문맥 수정 패키지와 ScrpRelay CMake target을 빌드한다.
4. 기존 host.mcp_server에 `--micro-vm-package <dbictl 패키지> --micro-vm-root <broker root> --micro-vm-relay <ScrpRelay.exe>`를 추가한다.
5. Host마다 다른 세션, sandbox root, 인증서·감사·로그·inbox·artifact·output 경로를 지정한다. `--port 0 --upload-port 0`으로 충돌을 피한다.
6. 검사 서비스가 허용하는 export-dir을 사용한다. 최종 공개 경로는 세션별 Downloads/SandboxOutput이다.

관리 작업은 관리자 권한이 필요하다. 실행 요청의 프로그램은 VM에서만 실행된다.
tools/micro_vm_session_lab.py는 실제 두 MCP Host를 실행한다. SCRP_APP_LAB_ROOT를 새 증거 폴더로 지정한다.
SCRP_LAB_MANAGER, SCRP_LAB_RUNNER, SCRP_LAB_PACKAGE, SCRP_LAB_VM_ROOT, SCRP_LAB_RELAY, SCRP_LAB_EXPORT에 해당 절대 경로를 지정한다.
tools/scrp-app-window-proof.ps1을 Downloads에 복사한 뒤 inbox_import로 가져와 각 세션에서 -Slot B 또는 C와 -Session 값을 전달한다.
requests/<id>.json의 `{slot, tool, arguments}`를 한 번만 소비한다. ready.json은 MCP 준비이며 VM READY가 아니다.
task_submit 뒤 SCRP READY와 실제 스크린샷을 확인한다. 인증서·bootstrap을 커밋하지 않는다.

B에서 inbox_import → sandbox_run → sandbox_run_status로 앱을 열고 한글을 입력한다.
B 화면을 보존한 채 C를 같은 절차로 시작하고 입력 전후 B 화면과 전체 VM ID를 비교한다.
동일 이름의 파일을 각각 저장하고 영수증/stdout의 종료 코드·nonce·해시·실행 횟수를 검사한다.
router_capture/router_execute도 호출하고 동일 request_id가 같은 run_id를 반환하는지 확인한다.
반출은 artifact_export EXPORTED 이후 실제 내용·해시·세션 경로까지 대조한다.

## 실패 처리와 제한

VMSMB 파일 가시성 지연 때문에 Guest에서 도우미와 manifest를 최대 120초 기다린다.
두 SHA-256을 확인하고 쓰기를 막는 읽기 핸들을 유지한 채 도우미를 한 번 실행한다. 입력은 재전송하지 않는다.
Output watcher와 snapshot의 중복 artifact는 동일 해시·크기의 검사된 결과만 선택한다.
서로 다른 내용이나 현재 BLOCKED 결과는 성공으로 합치지 않는다.

WSB 점유 시 자동 micro_VM 배정, Runner 재시작 후 앱 소유권 복원, 전체 바탕화면은 구현되지 않았다.
장애 때 자동 VM 이동·재생성은 하지 않으며 --no-auto-restart로 실험한다.
기본 회귀 테스트와 실제 VM 시험은 별개다. 실제 결과는 별도 보고서의 세션·바이너리·화면·영수증으로 확인한다.
