# 자동 VM 선택의 listener 충돌 (#131)

## 문제와 수정

AutoAppWindow의 기존 계획은 `wsb list`가 비어 있으면 WSB용 0.0.0.0:17443/17444를 선택했다.
첫 Host가 listener를 열고 아직 VM을 부팅하지 않았거나, VM 없이 listener를 유지하면 두 번째
Host도 같은 포트를 열다가 task_submit 이전에 RUNTIME_UNAVAILABLE로 실패할 수 있었다.
단순히 첫 Host의 프로세스를 종료하면 그 세션의 작업을 끊을 수 있다.

새 Host는 자동 모드의 고정 포트 bind에서 EADDRINUSE/WinError 10048을 확인한 경우에만,
자기가 만든 부분 listener를 정리하고 Manager에 micro_VM 계획을 요청한다. 127.0.0.1의
동적 포트 두 개로 다시 열고 VM 생성 전에 선택을 확정한다. 기존 listener와 다른 Host/VM은
건드리지 않는다. 권한 오류, 점유 조회 실패, 이미 선택된 VM의 시작/작업 실패에는 적용하지 않는다.

## 다른 PC에 적용

Host #131과 Manager #66을 함께 반영한다. Host만 바꾸면 이전 Manager가 새 선택 인자를 지원하지 않는다.
일반 requirements 설치는 이 변경을 포함한 Manager 커밋을 사용한다. 별도 ManagerRepo로 wheel을
만드는 통합 설치는 해당 Manager checkout도 갱신해야 한다.

- `solution.json`의 `host_repo`, `manager_repo`, `python`, `manager_source`, `micro_vm.mode`를 확인한다.
- Dev + `manager_source: checkout`이면 두 소스 경로 모두 이번 수정 버전이어야 한다.
- Deploy/설치 패키지 방식이면 설정에 적힌 Python 환경의 Manager 패키지도 새 버전으로 설치한다.
- `micro_vm.mode`가 `AutoAppWindow`이고 관리 서비스 package/root/relay가 그 PC의 설치와 일치해야 한다.
- 실패한 두 번째 Claude 채팅의 SCRP 연결만 다시 시작하여 새 코드를 읽게 한다. 실행 중인 첫 Host/VM은 유지한다.
- 두 번째 task_submit → micro_VM READY → hello_world.txt를 Guest Output에 저장 → artifact_export의
  EXPORTED 및 반출 내용 `hello world`를 확인한다. 입력 전달 ACK를 완료로 간주하지 않는다.

## 검증 범위

2026-11-12 실제 TCP 포트를 점유한 회귀에서 업로드/제어 각각의 충돌과 기존 연결 응답 유지,
서로 다른 새 포트 할당, 부분 생성 listener 정리를 검증했다. 권한 거부, 명시적 WSB 모드,
두 번째 bind 실패 및 listener 진입 후 실패에 대해 재전송/전환이 일어나지 않음도 확인했다.
Host 집중 검사 32개, 전체 956 passed / 23 skipped를 통과했다.
Manager 자동 선택 15개, 전체 264 passed / 1 skipped / 8 subtests passed를 통과했다.
requirements의 Manager 커밋으로 wheel 설치를 수행하고 설치된 모듈의 API와 실제 커밋을 확인했다.
checkout 경로 없이 설치 패키지를 로드한 Host 집중 검사 32개도 통과했다.

사용자가 보고한 Claude는 다른 PC에서 실행 중이다. 이 PC의 회귀는 실제 TCP 통신을 사용하지만
VM 선택 자체는 대역으로 검증하므로, 다른 PC의 VM READY/파일 반출이 완료됐다는 증거는 아니다.
진행 중인 다른 세션을 재시작하거나 종료하지 않았다.
