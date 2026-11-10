# 혼합 VM 후속 검증 (2026-11-09)

관련 이슈: Host #113/#114, Manager #57/#58, Runner #37/#38, micro_VM #2/#3.
사용자가 승인한 실제 Windows PC의 Host 관리·빌드·통합 시험 범위에서 수행했다.
작업 프로그램과 장애 시험 payload는 SCRP Guest에서 실행했다. 중첩 Hyper-V 실험실 시험은 아니다.
아래 성공은 앱 창 모드 기준이며 **전체 바탕화면/Windows 기본 Run 창까지 완료한 것이 아니다**.

## 기준 소스와 실행 바이너리

기존 PR 병합 후 원격 develop을 다시 받아 다음 커밋에서 작업 브랜치를 만들었다.
micro_VM도 사용자 요청에 따라 develop을 기준으로 한다. 아래 커밋에 미커밋 수정이 더해져 있다.
실제 실행 시점의 소스 해시는 각 증거 폴더의 `versions.json`에 기록한다.

| 저장소 | 기준 커밋 | 작업 브랜치 |
|---|---|---|
| Host | 9e11b8de0ad13085aa95b223342613435525b571 | feat/113-mixed-vm-hardening |
| Manager | de1cfde6b134c01b398eddfe2e0c9a8da72dcdbf | feat/57-mixed-vm-hardening |
| Runner | e692bd91fde58187693949639cb390fa3cd1f58d | feat/37-mixed-vm-hardening |
| micro_VM | 795b6729653b773181cf037a18eee5d3fa1cc844 | codex/3-mixed-vm-hardening |

B/C에서 실제 로드한 Manager는 checkout import가 아니라 별도 venv에 설치한 비편집 wheel이다.
`C:\SCRPAppLab\hardening-deploy-20261109\venv\Lib\site-packages\sandbox_manager\__init__.py`, 버전 0.1.0.
이 wheel은 자동 listen 주소 선택/할당 잠금 수정을 포함하며, 이후 추가한 VM 수 한도는 포함하지 않는다.
한도 시험은 새 Host 두 개가 수정 Manager checkout을 로드해 별도로 수행했다.

| 실행 대상 | SHA-256 |
|---|---|
| 실제 A Runner (기존 빌드) | 06dfba6ea24ba9b38646c4812e71a01204b48aa8e391741605397615b1e25b99 |
| 실제 B/C Runner (reset capability 포함) | c5fb9e5b78800612ae86a0e0e628945c303acc328b8f6a01b08521377850108c |
| 실제 dbictl.exe (`launch-context-fix` 묶음) | 37a3e97f21571dd07fd61295ab419a0a74145dc9a489f475b9e2923fd8cf1e4d |
| 실제 ScrpRelay.exe | 08006d0def45796e8e0385d79c51ca8c0a61e7f7a878af317e081ad6ed62e1ab |
| 후속 Job keeper 포함 Runner (빌드만, 위 B/C에 미적용) | 3e717ac9b9beff113eb208793076c923379e28de20f8517140f648cb5bccae2c |

## 실제 세션과 증거

| 대상 | 세션 ID | VM 전체 ID |
|---|---|---|
| WSB A | SES-d49a03a2660b4a4ba95aa32e16093137 | f2b8693b-41b1-45cf-98db-46e33dcf79fc |
| micro_VM B | SES-5746b1d08c8542a1bad452ab2439a34a | workspace 8a05e05c-41d9-4e9b-a43a-fff08b2f25a5 / container 16246889-7f02-45e7-a032-d0aadb5b3868 |
| micro_VM C | SES-d87d00a0c1d540ffb33f56092c39cad2 | workspace 21d11e2d-4fd7-4d93-9c9b-79f7fc0f0374 / container 18cc348b-d656-4330-8e81-a55128dbb411 |

증거 경로는 로컬 `C:\SCRPAppLab` 아래다. 원본에는 사용자 경로/세션 정보가 있으므로 일괄 Git 게시하지 않는다.

- `hardening-20261109`: A, 먼저 생성한 진단용 C0, 빌드/회귀 로그.
- `hardening-bc2-20261109`: 설치 Manager를 사용한 실제 B/C.
- `hardening-capacity-20261109`: 신규 요청 두 개의 한도 거부 시험.
- `hardening-bc-20261109`: 초기 HELLO schema 누락으로 실패한 시도. 성공 증거에서 제외하며 정리 확인 기록을 보존한다.

## 확인 결과

1. WSB가 비어 있을 때 Auto 경로로 A를 최초 시작했다. Host listen 0.0.0.0:17443/17444,
   Guest에 게시한 주소 172.29.80.1로 SCRP READY를 확인했다. 고정 loopback 주소를 WSB에 잘못 전달하던 구성을 수정했다.
2. A 유지 중 B/C는 서로 다른 micro_VM으로 연결됐다. `012-BC-type-*`와 A `028-A-type`의 호출 구간이 겹치며,
   각기 다른 한글을 해당 화면에서 확인했다(`013-BC-text-observe-*`, A `029-A-text-observe`). 장시간 부하 시험은 아니다.
3. 동일 이름 `same-name.txt`를 각 세션에서 생성하고 동시 반출했다(A `033`, B/C `016`).
   Defender service 검사 후 각 세션별 Downloads/SandboxOutput 경로에 저장됐고 내용/해시가 서로 일치하지 않음을 확인했다.
4. B 파일 7,340,069바이트 전송 중 61,324바이트에서 lab relay가 연결을 끊었다.
   Host는 불완전 본문을 거부했고 ART-000008은 CANCELLED로 남았다. 동일 VM/세대에서 인증 재연결 후
   새 snapshot/후보 ART-000019로 전부 다시 수신·검사했다(`045-B-cut-file-export`).
   SHA-256 `e9048dc1e8f08e22a7562cf64b31887a040e1e849a8f88179fef6d76774bcd55`가 원본과 같았다.
   B의 열린 앱/한글 상태가 유지됐고 A/C도 READY였다. 입력 재전송은 하지 않았다.
5. 한도 5에서 신규 요청 두 건을 동시에 시작했다. 두 요청 모두 `capacity exhausted: 5/5`로 거부됐다.
   전후 workspace 기록 전체 해시가 동일하고 A/B/C는 READY/connected=true였다(A `057`, B/C `046`).
   5개는 실행 기록 3개와 정리 불확실 기록 2개다. 기존 기록을 회수하지 않았다. **실제 RAM 고갈 시험은 아니다**.
6. Runner의 앱 소유권 복구 구성요소를 A에서 native fixture로 확인했다(RUN-0006, `056-A-ownership-v5-status`).
   이름 있는 Job만 사용하면 마지막 핸들 종료 뒤 OpenJobObject가 WinError 2로 실패했다.
   Guest keeper가 Job 조회 핸들을 유지하도록 수정한 뒤 제어 프로세스 종료, 기존 앱 생존, 동일 Job 재확보,
   한글 입력, 다른 세션의 앱 미획득을 확인했다. 실제 B Runner 전체 재시작 시험은 아니다.
7. micro_VM의 원래 프로세스 핸들 상태 조회 코드를 B의 native fixture에서 검증했다(RUN-0008,
   `052-B-process-probe-status`). RUNNING→EXITED(259), 생성 시각 유지, PID 불일치/핸들 부재 UNKNOWN을 확인했다.
   수정 WorkspaceAgent를 새 VM에서 실행한 종단 검증과 Manager 재시작 연결은 아직 남아 있다.

첫 장애 주입은 파일 수신 완료 뒤에 발생해 전송 중 장애 통과로 계산하지 않았다.
두 번째 진단 스크립트의 Get-Content 결과에 PowerShell provider 메타데이터가 붙어 약 98MB proof가 생성됐고,
8MiB 제한에서 올바르게 차단됐다. ReadAllText로 수정했으며 원본은 Guest 로그에 보존하고 필요한 필드만
1,474바이트로 추출해 검사 반출했다(`044-B-compact-export`). 제한을 완화하지 않았다.

## 회귀 검증과 재현

- Host 전체: 882 passed, 23 skipped, 240.43초 (`host-final.log/xml`). 실제 Defender 서비스용 테스트 환경 변수는 켜지 않았다.
- Manager 전체: 216 passed, 1 skipped, 8 subtests passed (`manager-capacity-tests.log/xml`).
- Runner: UCRT64 GCC 16.2.0 빌드 성공 (`runner-recovery-build.log`, build-info.json).
- WorkspaceAgent/RunProcessProbe/Agent start 테스트 target: MSVC 빌드 성공. 이번 micro_VM 변경 후 전체 CTest는 아직 재실행하지 않았다.
- Agent start native 테스트는 WSB A에서 20개 검사 통과(RUN-0009, `072-A-agent-start-status-v3`).
  첫 실패는 pending 결과에 완료 전용 필드를 조회한 새 테스트의 오류였고, 완료된 결과로 검사 위치를 수정했다.
  실패 기록과 성공 영수증을 모두 보존한다.

`tools/micro_vm_session_lab.py`에 새 증거 root, Manager, Runner, package, VM root, relay, 검사 서비스 export 경로를 지정한다.
`SCRP_LAB_AUTO=1`은 자동 배정, `SCRP_LAB_INSTALLED_MANAGER=1`은 해당 Python 환경의 설치 Manager,
`SCRP_LAB_MAX_ACTIVE`는 VM 수 한도를 선택한다. ready.json은 MCP client 준비이며 VM READY가 아니다.
requests 폴더에 고유 이름의 도구 요청 JSON을 쓰고 결과/영수증을 기다린다. batch에는 서로 다른 slot만 넣는다.
실행 중인 증거 root를 재사용하거나 불확실한 입력 요청을 다시 쓰지 않는다.
실제 Guest 전송 장애에는 `guest-transfer-cut.ps1`과 별도 `ScrpRelayFault` target을 사용하며,
정확한 VM/channel/프로세스 핸들 및 fixture SHA를 검증한다. 해당 target은 제품 패키지에 포함하지 않는다.

## 남은 경계

- C0에서 OpenDesktop(Default)는 성공했으나 SwitchDesktop은 false, input desktop은 Winlogon에 머물렀고
  CopyFromScreen은 invalid handle이었다. 전체 바탕화면/기본 Win+R 성공도, 두 번째 로그온 거부의 정확한 커널 원인 확정도 아니다.
- Runner 프로세스 소실 후 같은 VM에서 새 인증 세대로 연결하는 후속 실제 시험은 아래에서 통과했다.
  증거가 없는 프로세스 종료 추정과 입력 재전송은 여전히 거부한다.
- 일반 비관리자 설치 실행은 아직 검증하지 않았다. start_solution의 비관리자 요구와 native broker의 High integrity 요구를
  잇는 관리 경로가 필요하다. 관리자 통합 시험이나 wheel 설치 성공을 일반 배포 완료로 간주하지 않는다.
- 설치 프로필의 backend 경로/바이너리 해시/세션별 경로/max_active 저장을 추가했지만 기본 Manager 의존성 pin을
  미게시 커밋으로 바꾸지는 않았다. 배포 가능한 수정 Manager 버전 고정이 필요하다.
- 장시간 동시 부하, 물리 메모리 고갈, B/C 전체 desktop 검증은 남아 있다. 기존 VM은 유지한다.

## Runner 프로세스 종료 후 실제 복구 (후속 시험)

증거 root는 `C:\SCRPAppLab\scrp-recovery3-20261109`다. 기존 A/B/C를 유지하고 별도 검증 VM 1개에서 수행했다.
앞의 빌드·테스트 수치는 이전 단계 기록이며 다음 표가 이 복구 시험의 버전이다.

| 항목 | 실제 값 |
|---|---|
| Host 기준 커밋 | `9e11b8de0ad13085aa95b223342613435525b571` + 작업 트리 변경 |
| Manager 기준 커밋 | `de1cfde6b134c01b398eddfe2e0c9a8da72dcdbf` + 작업 트리 변경 |
| Manager 경로·버전 | `C:\Users\<user>\.codex\worktrees\mixed-vm-manager\sandbox_manager\sandbox_manager`, 0.1.0; 실제 파일별 해시는 versions.json |
| Runner 기준 커밋 | `e692bd91fde58187693949639cb390fa3cd1f58d` + 작업 트리 변경 |
| Runner SHA-256 | `e010e6f4d22f9b0470705bb51bbb0f290eb619eb4c0c6cd405e312b99ddbdd08` |
| micro_VM 기준 커밋 | `795b6729653b773181cf037a18eee5d3fa1cc844` + 작업 트리 변경 |
| dbictl SHA-256 | `f34ace242c4f11d3d59d0fa250592e8df28ab0e3e8cf87f01af7fda053285a69` |
| WorkspaceAgent SHA-256 | `3adf3de40f5d8882e7275d9516979709566c2318011f4667d69b5d865b8fbd95` |
| VM workspace / container | `da5ec67e-e25e-4555-9f2e-3e013b1bacac` / `fb597029-9e7f-403c-83fb-f96167f2544d` |
| 검증 세션 | `SES-dc5fcacef3eb4e25a1963766a6fe6aee` |

### 결과

| 검사 | 실제 증거·판정 |
|---|---|
| 원래 Runner 종료 | PID 4764 / 생성 시각 134386637277086802의 원래 핸들로 종료. `runner-crash-proof.json`의 execution_count=1; ART-000019 검사 반출 |
| 같은 VM 재연결 | VM 두 GUID와 Agent PID 4164·생성 시각 유지, 새 Runner PID 2488. generation 1→2. host.log 11:15:31 STARTUP OK/READY |
| 앱 소유권·한글 보존 | 같은 앱 PID 1056, 시작 횟수 1. `030-before-verified-crash-0.png`와 `033-after-recovery-observe-0.png`의 보존 화면, `041-recovered-text-0.png`의 추가 한글 입력 |
| Output 저장 경로 | 인증은 generation 2, 저장 경로는 generation-1/output 유지. 기존 종료 증거와 새 Router 파일 모두 새 generation 후보로 검사 반출 |
| 불확실한 작업 | 종료를 일으킨 RUN-0006은 `UNKNOWN / RUNTIME_CHANGED`로 남음(`044-crash-command-status`). 자동 재전송하지 않음 |
| 복구 후 Router | RUN-0007 `SUCCEEDED / GUEST_PROCESS_VERIFIED`, exit 0(`052-post-recovery-final`) |
| 복구 후 파일 반출 | ART-000020 `post-recovery-router.json`, generation 2, Defender EXPORTED. SHA `04cd2df106102d4c542b500f10e84053dc6059f472313336c3b164a25655f6d6` |
| 다른 세션 보존 | 기존 A `082-A-during-crash`, B/C `056-BC-during-crash-*` 모두 READY, connected=true, generation 1 유지 |
| 저장 버튼 | 클릭 전달 성공 뒤 앱 저장 파일 없음(`saved_app_file=false`). 앱 버튼 저장 성공으로 주장하지 않음. 위 반출은 새 Router가 만든 파일 |

### 실패 기록과 재현 조건

1. `scrp-recovery-20261109`는 새 패키지에 이 PC의 profiles.local/contracts.local이 없어
   environment_drift로 VM 생성 전 거부됐다. 준비 기록의 cleanup_confirmed=true와 runtime_creation=not_attempted를
   Manager가 해석하지 못한 문제를 수정했고, 부족한 증거에는 여전히 stop을 보내지 않는다.
2. 기존 시험 패키지의 동일 PC 로컬 프로파일/계약을 별도 설정으로 적용하고 현재 host fingerprint 일치를 확인했다.
   원래 manifest를 덮어쓰지 않았으며 local-configuration.json에 출처·해시를 남겼다. 일반 설치 검증 완료가 아니다.
3. `scrp-recovery2-20261109`는 새 이미지의 패키지 설치 중 Manager의 180초 제한에 걸렸다.
   네이티브 준비 완료 뒤 이 시험의 전체 ID·소유권을 확인해 해당 VM만 정상 정리했다(settle-result.json).
   Manager가 Host --startup-timeout을 따르도록 수정했다(1..3600초). 최종 시험은 1200초, 준비된 이미지 사용이다.
4. 처음 종료 fixture는 이미지 경로 문자열 차이로 종료 전에 거부됐다. 원래 PID·생성 시각 유지 및
   종료 시도 marker 없음 확인 후 읽기 전용 파일 ID 대조를 통과시켰다. 수정 fixture는 실행 파일 ID·해시·
   프로세스 생성 시각을 확인하고 정확한 Runner만 한 번 종료했다. 첫 명령의 exit 0을 종료 성공으로 처리하지 않았다.
5. `SCRP_LAB_AUTO_RESTART=1`, `SCRP_LAB_STARTUP_TIMEOUT=1200`, 새 증거 root와 명시된 Manager/Runner/package/relay를
   설정한다. 서로 다른 dbictl 빌드는 기존 broker root를 공유하지 않는다. `guest-recovery-app.ps1`은 Router로 실행하고
   한글 화면을 확인한다. `guest-runner-crash.ps1`에는 Manager가 보유한 정확한 PID·생성 시각을 넣는다.
   모호한 종료 요청을 반복하지 않으며 새 인증 READY·실제 화면·검사 반출을 각각 확인한다.

Host 전체 885 passed / 23 skipped, Manager 전체 236 passed / 1 skipped / 8 subtests passed.
micro_VM 전체 target 빌드 성공. 기존 뷰어와 충돌하는 owned_workspace_and_real_ipc를 제외한 CTest 40건 중
38 passed / 1 skipped / 1 failed였고, 실패한 actual_execution_identity_boundaries는 관리자 문맥에서 별도로 통과했다.
전체 CTest를 한 번에 모두 통과했다고 기록하지 않는다. Agent 생성 시각 추가 회귀는 후속 수정·빌드 뒤 별도 통과했다.
Runner 실제 Output 고정·이동 거부 구성요소는 WSB A RUN-0010에서 통과했다.

### 세 세션의 반복 파일 반출 부하

이미 실행 중인 A/B/C에서 각 8개, 총 24개 파일을 생성하고 반출했다. 모든 세션에서 파일명은
mixed-load-20261109-1.txt부터 8.txt까지 같으며 내용은 자신의 세션 ID와 번호로 구분했다.
파일당 67,624바이트, 총 1,622,976바이트를 Defender 검사 후 반출했다.
8회 모두 A/B/C의 artifact_export 요청 처리 구간이 겹쳤다. 실제 반출 파일을 다시 읽어 기대 내용,
SHA-256, 크기, 각 세션의 Downloads/SandboxOutput 하위 경로를 전부 대조해 24/24 일치를 확인했다.
load-verified.json에 각 경로·해시·요청 시각과 8회의 겹침을 기록했다.
A의 첫 ART-000029는 SUPERSEDED로 남고 같은 SHA의 ART-000030이 정식 후보가 됐다. 이전 후보를 재전송하지 않았다.
Guest stdout도 세션별 파일 8개·실행 횟수 1회를 검사 반출했다.

이 시험은 기존 A/B/C 프로세스와 각 시작 시점 versions.json의 구성에서 수행했다. 새 복구 검증 VM의
Manager/Runner를 기존 세션에 몰래 교체하지 않았다. 종료 시 A/B/C는 generation 1 READY/connected,
별도 복구 VM은 generation 2 READY/connected다. 장시간 스트레스나 물리 메모리 고갈 시험은 아니다.
증거: A 083~098 요청, B/C 057~072 요청, scrp-recovery3-20261109/load-verified.json.
