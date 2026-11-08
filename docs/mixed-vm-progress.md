# WSB + micro_VM 다중 세션 작업 상태

관련 이슈: Host #113, sandbox_manager #57, sandbox_runner #37, micro_VM #1.

2026-11-07 기준 **전체 목표는 미완료**다. 실제 WSB + micro_VM B + micro_VM C의
동시 동작 증거는 없다. 다음 변경은 타 세션 보호를 위한 선행 작업이다.

## 코드 변경

- `McpServer._start_backend()`의 다른 Host 프로세스 종료/고아 VM 회수 경로를 제거했다.
- `single_host`의 기존 공개 함수는 무동작 호환 API로 남겨 이전 호출자도 다른 세션을 종료하지 않는다.
- Manager 변경은 별도 #57에서 머신 전체 WSB 시작 mutex와 자동 고아 회수 제거를 다룬다.
- 현재 Host 기본 Manager 의존성 고정값과 배포 환경은 변경하지 않았다. 테스트는 새 Manager 소스의 경로를
  우선 등록하고 `sandbox_manager.__file__`을 기록·단언한다. 실제 설치/혼합 VM 검증은 아직 아니다.

이 문서는 초기 점검 이력이다. 현재 실행 결과는 [2026-11-08 후속 검증](mixed-vm-followup-20261108.md)을 참조한다.

## 고정한 원격 기준

| 저장소 | 브랜치 | 커밋 |
|---|---|---|
| host_control | develop | `2f86894950731d6bc56fc3cb0acbebe029bda900` |
| sandbox_manager | develop | `66923d381e7090a880e4b9000beb4a0c946ba332` |
| sandbox_runner | develop | `cee101389f438be006f093e8fdb40d79e8cc2195` |
| micro_VM | main | `7acf05df60f5ce9589e88114398e2fc61bca410f` |

## 실제 환경 점검과 막힌 단계

처음 연결은 NOT_STARTED였고 실행 중인 WSB A는 확인되지 않았다. 새 SCRP 점검 세션을 시작해
WSB Guest에서 Router로 환경을 조사했다. 관리자 계정이지만 CmService/vmcompute/hns/vmms,
cmclient.dll, 중첩 가상화 확장 및 컴파일 도구가 없었다. `RUN-0001` 영수증 exit_code=0,
환경 JSON은 서비스 검사 통과 뒤 반출했다. 점검 성공을 micro_VM 실행 성공으로 해석하지 않는다.

이후 사용자가 **Host의 micro_VM 빌드·시작 등 VM 관리만 허용**했다. 동일 main 커밋을
MSVC x64로 빌드·실험용 패키징하고 관리자 권한으로 B 시작을 시도했다.
`environment_drift`에 따른 qualify에서 실행 중인 WSB를 감지해 종료 코드 1로 거부됐다.
전후 HCS 전체 ID와 Running 상태는 같았다. Runner 연결 전 단계이며 B/C는 부팅하지 않았다.

micro_VM의 `docs/platform-support.md`, `CHANGELOG.md`, `console_logon.hpp`는 두 번째 전체 desktop
로그온이 STATUS_REMOTE_SESSION_LIMIT로 거부되는 이전 실험실 관측을 명시한다.
이번 작업에서는 그 OS 오류를 직접 재현하지 않았다. 제한 검사나 로그온 보호를 삭제하지 않았다.
독립 Windows 게스트 이미지 방식의 백엔드 검토에 필요한 VHDX/준비된 VM도 없다고 사용자가 확인했다.

## 검증한 선행 변경

SCRP WSB 안의 Python 3.13.7에서 수정 Manager 소스를 명시 로드했다.
실제 경로는 `C:\MixedVmVerification\manager\sandbox_manager\__init__.py`, 버전은 `0.1.0`이다.
Manager 전체 159개(+7 subtests), Host 빠른 점검 23개가 통과했다.
Host 전체는 `--basetemp=C:/MixedVmVerification/pytest-host-v4`로 **753 passed, 55 skipped**였다.
RUN-0009의 checked receipt가 SUCCEEDED/exit 0이며 로그는 SecureArtifactScanner 검사 후 반출했다.
수집한 화면은 같은 점검용 WSB의 3050×1668 전체 화면이다. B/C의 화면은 없다.

기본 테스트에는 가짜 wsb와 mini_runner가 포함되며 실제 Defender/서비스 통합용 환경 변수는 켜지 않았다.
머신 전체 mutex 테스트는 WSB 안의 실제 Windows 프로세스/스레드 잠금이며 실제 VM을 시작하지 않는다.
테스트에 전달한 ZIP과 작업 트리의 Python 파일 149개를 비교해 차이가 없음을 확인했다.
초기 환경 설정 실패(DLL 경로, basetemp 누락)는 후속 실행에서 해결했고 원래 실패 기록도 보존했다.

## 남은 구현·실제 VM 검증

micro_VM 전체 desktop 동시 실행, 세션별 VM 고정 배정 및 전체 ID 소유권 검사, WSS/HTTPS 중계,
Guest 경로 계약, 세션별 모든 경로/포트 분리, 새 Runner 빌드/설치, B/C의 독립 입력·복구·종료,
동시 Router·파일 반출 통합 검증이 남아 있다. 앱 창 모드나 단위 테스트를 완료 증거로 쓰지 않는다.
