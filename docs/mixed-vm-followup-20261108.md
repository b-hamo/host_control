# 혼합 VM 후속 검증 — 2026-11-08

관련: Host #113/#114/PR #115, Manager #57/#58/PR #59, Runner #37/#38/PR #39.
이 보고서는 초기 환경 점검 기록 `mixed-vm-progress.md` 이후의 결과다.
전체 목표는 미완료다. 아래의 실제 혼합 실행은 WSB 전체 바탕화면 A와 **앱 창 모드** micro_VM B/C이며,
B/C 전체 바탕화면·OS Win+R·IME 조합을 구현했다는 뜻이 아니다.

## 실제 혼합 실행

Host Windows 26200.9711에서 A를 먼저 READY로 만들고, B와 C를 차례로 시작했다.
세 세션이 동시에 READY/heartbeat를 유지한 상태에서 각각 proof 앱을 SCRP로 열고 서로 다른 한글을 입력했다.
화면에는 각 세션 ID와 `A/B/C 독립 한글 검증 1108`이 표시됐다.
입력 호출은 순서대로 수행했다. 세 입력을 같은 순간에 제출하는 부하 시험으로 표현하지 않는다.

| 슬롯 | 세션 | VM |
|---|---|---|
| A | SES-c574aa88d7c2424c99c417089b73393c | WSB 0a930afc-f1b6-4009-bf59-359211d627f6 |
| B | SES-cf328b897f7848cb89420304a30d8236 | workspace a57f3750-6e05-4ef5-b2d8-8187e6b4606b / container 124f0940-0b52-45ee-9d89-af13106ea3a1 |
| C | SES-16209b7a9f05430b8814819ff27765a2 | workspace c354cc84-8922-40e7-90cb-3f69e0ffa578 / container 10388a40-66c7-4e74-8019-eaa69c762727 |

로컬 증거 루트: `C:\SCRPAppLab\mixed-20261108`.
화면 파일: `1794104106714-A-computer_observe-0.png`, `1794104106754-B-computer_observe-0.png`,
`1794104113578-C-computer_observe-0.png`. 슬롯별 host.log·audit·Manager state.json에 전체 ID와 heartbeat가 있다.
인증서·토큰·원본 감사 로그는 저장소에 올리지 않는다.

## 장애 시험에서 발견한 결함과 수정

1. B 소유의 control relay 프로세스만 종료하고 3초 뒤 같은 VM/service GUID로 복원했다.
   기존 Runner는 재접속하지 않았다. 30초 후 기존 Host가 B를 종료·정리했다. A/C의 READY와 앱은 유지됐다.
2. 첫 재연결 수정본으로 별도 B를 만들었다. 자동 배정은 실행 중인 A의 정확한 WSB ID를 보고 micro_VM을 선택했다.
   세션 SES-2dc94ea9909346089ff43ff143b8e02e, workspace e8675c9d-b143-4070-a2f7-f9165a4b7523,
   container 25a30f43-c0f4-412d-964a-eb49ac5215ca. 한글 입력과 실제 캡처는 성공했다.
   중계 장애 복구는 다시 실패했고 이 B도 종료됐다. 증거: `C:\SCRPAppLab\reconnect-20261108`.
3. 현재 수정은 reconnect 자격을 소비한 연결에서 다시 쓰지 않고, 같은 Runtime/Job/action 기록을 유지한다.
   첫 연결에만 이동되던 artifact 목적지 설정도 연결마다 보존한다. 이 설정 결함이 두 번째 실제 실패의
   유일한 원인이라고 단정하지 않는다. 수정 후 B 시작의 UAC 요청은 Windows에서 취소 오류를 반환했다.
   최신 수정본의 실제 중계 장애 시험은 시작되지 않았으며 다른 실행 경로로 우회하지 않았다.
4. Host는 fixed_vm_binding Manager의 연결 장애를 자동 종료·VM 재생성 근거로 삼지 않는다.
   입력은 차단하고 인증된 동일 세대의 재연결을 기다린다. 명시적 종료와 보안 실패 처리에는 적용하지 않는다.

## 소스와 바이너리

시험 당시 Host HEAD `92bb9c0be265223c99d8b6c163b32e9b3fe0b2bb`와 작업 트리 변경을 사용했다.
Manager는 설치 의존성 대신
`C:\Users\tkwk9\.codex\worktrees\mixed-vm-manager\sandbox_manager\sandbox_manager\__init__.py`를 로드했다.
패키지 버전은 0.1.0, HEAD는 `9f8d52e828adf5d7eb26d45a6b7d3d08c95b47f1`이다.
동작 중인 A/C에는 이후 편집한 코드가 소급 적용되지 않는다.

| 바이너리 | SHA-256 | 실제 사용 |
|---|---|---|
| Runner scrp-app | 06dfba6ea24ba9b38646c4812e71a01204b48aa8e391741605397615b1e25b99 | 최초 A/B/C |
| Runner 첫 재연결 수정본 | c9bac421c180a22f173c161d85b702aa5621eb64afe40713d17f10f3ccd0cf07 | 두 번째 B; 복구 실패 |
| Runner 최신 수정본 | 3c0d8fbe948d2db3077c395dd8d53b3eab4880d257fbcc37a037d34c2df7e880 | 빌드 완료, B 시작 UAC 취소 |
| ScrpRelay | 08006d0def45796e8e0385d79c51ca8c0a61e7f7a878af317e081ad6ed62e1ab | 모든 micro_VM 시험 |
| dbictl | 37a3e97f21571dd07fd61295ab419a0a74145dc9a489f475b9e2923fd8cf1e4d | launch-context-fix 패키지 |

Runner는 UCRT64 GCC 16.2.0으로 빌드했다. micro_VM manifest의 빌드 경로는
`C:\minobox\tmp\build\launch-context-final`, 생성 시각은 2026-11-07T21:16:22+09:00,
계약은 windows-26200.9711-x64다. 초기 시험은 HEAD와 dirty 여부만 기록했으므로
그때 로드한 모든 Python 파일의 정확한 바이트를 사후 재현했다고 주장하지 않는다.
후속 실행기에는 Manager 버전·Host/Manager 개별 소스 해시 기록을 추가했다.

## 회귀검증과 남은 실제 시험

최종 Host 전체 793 passed/23 skipped, Manager 전체 173 passed/1 skipped/8 subtests passed.
fixed VM 보존을 포함한 Host 복구 모음은 11 passed다.
최종 로그·JUnit 결과는 `C:\SCRPAppLab\regression2-20261108`에 보관했다.
기본 pytest에는 VM 대역이 포함되며 실제 VM 증거와 구분한다.

Runner `reconnect_ledger_test`는 A의 기존 SCRP sandbox_run으로 실행했다.
확장 검증 EXE SHA-256: 24f6a2ca2ef65a2a41e2022ba5ab86a5e911b448c9e0bfc26cc0d22ed03a4153.
RUN-0003, execution_count=1, exit_code=0, SUCCEEDED/GUEST_PROCESS_VERIFIED.
중복·상충 입력, 연결 ID 교체, 실행 기록 유지, 전송/프로토콜 실패 분류를 대역으로 검사한다.
Defender 검사 완료 영수증은 A의 Downloads/SandboxOutput/세션/ART-000004,
stdout은 ART-000003에 있다. 이것은 실제 중계 재연결 성공 증거가 아니다.

이번 후속 실행에서 남은 항목:

- 최신 수정본의 실제 B 중계 장애 복구, 같은 화면/작업/VM 유지, 복구 후 입력·반출.
- 세 세션의 동일 이름 파일 동시 반출·Router 완료 영수증 대조.
- 실제 뷰어 창을 닫아도 VM/작업이 유지되는지 확인. 창 상태 UNAVAILABLE만으로 통과 처리하지 않는다.
- B만 명시적으로 종료하고 A/C 작업을 재확인하는 최종 시험.
- 동시 시작·실제 자원 부족 시험. 자동 배정 대역 통과와 구분한다.
- 최초 자동 WSB 배정의 수신 주소/포트 구성. WSB 점유 후 micro_VM 자동 선택만 실제 확인했다.
- Runner 프로세스 자체가 사라진 뒤 앱 소유권 복구, B/C 전체 바탕화면.

## 재현

`micro-vm-app-window.md`에 따라 checkout Manager, 빌드 Runner, micro_VM 패키지/relay를 지정한다.
새 SCRP_APP_LAB_ROOT와 SCRP_LAB_SLOTS=A,B,C로 실행하고 A READY 후 B, C를 시작한다.
각 슬롯별 inbox_import → sandbox_run → computer_observe → 클릭/한글 입력을 수행한다.
각 GUI 작업은 최신 화면을 기준으로 실행하고, 실패하거나 불확실한 입력은 재전송하지 않는다.
장애 주입은 전체 VM ID·소유 SID·세션 label·Host 부모 PID·service GUID가 일치하는 relay 하나만 대상으로 한다.
복구는 새 HELLO_ACK·재동기화·READY·실제 화면과 작업 유지로 판정한다. listener ready 파일은 성공 기준이 아니다.
모든 반출은 검사된 EXPORTED 경로의 내용/해시를 영수증과 대조한다.
