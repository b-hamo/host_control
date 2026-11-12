# 관리 서비스와 일반 권한 Host 실측 (2026-11-09)

## 결과와 범위

로그온 원인 진단의 최종 결과는 micro_VM의 [desktop-session-limit.md](https://github.com/b-hamo/micro_VM/blob/develop/docs/desktop-session-limit.md)에 기록했다. Host LSM 전체 컨테이너 로그온 한도와 A의 점유를 확인했다. 아래 화면 수집·스택 진단 절은 각 시험 당시의 결과를 보존한 기록이며, 후속 원인 확인 전의 미확정 상태와 구분한다.

실제 Windows PC에서 `MinoVmManagement`를 설치하고, 일반 권한(Medium, `S-1-16-8192`) Host 두 개가 서로 다른 micro_VM에 연결되는 것을 확인했다. WSB A는 먼저 실행돼 있었으며 계속 READY였다. 새 B·C의 SCRP 인증, 첫 화면, heartbeat, 앱 창 한글 입력, Router 완료 영수증, Defender 검사 후 파일 반출을 확인했다. 이 결과는 **앱 창 모드**이며 전체 바탕화면/native Win+R 성공 증거가 아니다.

현재 서비스는 동일 관리자 그룹 계정의 연결 High 토큰을 내부 고정 실행기에만 사용한다. 일반 Host·relay는 상승하지 않는다. 연결 High 토큰이 없는 표준 계정, 재부팅·로그오프 후 복구, 서비스 업그레이드·제거, 중첩 Hyper-V 실험실은 미검증이다. 기존 서비스·세션을 보호하기 위해 전체 통합 설치기를 다시 실행하지 않았으며, wheel 설치와 실제 설치 프로필 `--check`를 별도로 검증했다.

## 실제 사용한 소스와 바이너리

모든 저장소에는 아래 HEAD 이후 작업 변경이 있다. HEAD만으로 실행 소스를 식별하지 않으며 증거의 `versions.json`은 실제 로드한 Python 파일 해시도 기록한다.

| 구성 | 실제 사용 정보 |
|---|---|
| Host HEAD | `9e11b8de0ad13085aa95b223342613435525b571` + 작업 변경 |
| Manager HEAD / 버전 | `de1cfde6b134c01b398eddfe2e0c9a8da72dcdbf` + 작업 변경 / `0.1.0` |
| Runner HEAD | `e692bd91fde58187693949639cb390fa3cd1f58d` + 기존 복구 변경 |
| micro_VM HEAD | `795b6729653b773181cf037a18eee5d3fa1cc844` + 서비스·기존 복구 변경 |
| B 실제 Manager | `C:\SCRPAppLab\management-deploy2-20261109\venv\Lib\site-packages\sandbox_manager\__init__.py` |
| B wheel SHA-256 | `1aff7c590dc96619b2bac4726ecec0f5c2e7ada7c3fecc1fb7c8eacb1e47a52f` |
| C 실제 Manager | `C:\SCRPAppLab\management-deploy-20261109\venv\Lib\site-packages\sandbox_manager\__init__.py` |
| C wheel SHA-256 | `b04c9570823f00b762a70b9ceb1cddb15db57aaf7a7f5ed4c4e11824f9a74dcd` |
| Runner SHA-256 | `e010e6f4d22f9b0470705bb51bbb0f290eb619eb4c0c6cd405e312b99ddbdd08` |
| relay SHA-256 | `08006d0def45796e8e0385d79c51ca8c0a61e7f7a878af317e081ad6ed62e1ab` |
| 설치·실행 서비스 SHA-256 | `13b7464b49c619025914933756aa8b1c70ad05c058dd7e640d44e602f2d1d2f7` |
| 설치된 dbictl SHA-256 | `f34ace242c4f11d3d59d0fa250592e8df28ab0e3e8cf87f01af7fda053285a69` |
| 설치된 DbiBoot SHA-256 | `d31f1a511e01627a54bb73d91a7add43193a24a57f79e5b683ec38a91bc04eaa` |

설치본 파일 목록·해시는 `C:\Program Files\MinoBox-Management\management-install.json`에 있다. 상주 supervisor는 LocalSystem이며, 관리 worker는 등록 계정의 High 토큰으로 실행된다. 실측 worker PID는 46032이고 생성 시각까지 기록했다. 서비스 health의 `vm_ready:false`와 SCRP READY는 별개다.

추가 clean build에서 나온 서비스 SHA-256은 `b86583c6a4877c9118dfdd322f6d710ed0e20a54e34c62ec5e5789c701419bf2`다. 새 묶음 `C:\minobox\tmp\dist\management-service-20261109`는 빌드·패키징 검증본이며 실행 중인 설치본을 덮어쓰지 않았다. **새 묶음 전체를 재설치해 실제 VM을 다시 검증한 결과로 계산하지 않는다.** MSVC 14.51.36231의 DbiBoot가 저장소의 14.44 고정값과 달라 `-NewLayer`를 명시했고 manifest에 고정 불일치를 남겼다.

## VM·세션과 실제 증거

| 세션 | SCRP 세션 | VM |
|---|---|---|
| 기존 WSB A | `SES-d49a03a2660b4a4ba95aa32e16093137` | `f2b8693b-41b1-45cf-98db-46e33dcf79fc` |
| 수정 wheel B | `SES-b8b61e30fcab4326a981e836039a18bb` | workspace `3823e797-524e-42ea-a572-13f2e23f02b2`, container `efb9e854-1b03-422f-a92a-6bc8370d7053` |
| 최초 wheel C | `SES-aca93f59e70c4551a2bf10064d8b0dd3` | workspace `cee6d6c6-d66e-483b-8a49-a38f22dae25b`, container `878e4be4-870a-4a42-895d-0cacd1f3ec20` |

B 증거는 `C:\SCRPAppLab\management-session2-20261109`, C는 `C:\SCRPAppLab\management-session-20261109`, 서비스·빌드·배포 증거는 `C:\SCRPAppLab\desktop-service-20261109`에 있다.

- B `008-b-korean-0.png`, C `012-c-korean-0.png`: 각 앱에 `일반 권한 B 한글 입력 검증`, `일반 권한 C 한글 입력 검증`이 표시된다. 입력 ACK만으로 판정하지 않았다. 오래된 화면으로 거부된 입력 2건은 `STALE_OBSERVATION`을 확인한 뒤 새 화면에서만 전달했다.
- B `018-b-receipt-final.result.json`, C `022-c-receipt-final.result.json`: 각 `RUN-0002`, `SUCCEEDED`, `GUEST_PROCESS_VERIFIED`, 종료 코드 0. 영수증과 결과 모두 실행 횟수 1이다. GUI 앱 `RUN-0001`은 열린 상태이므로 완료 작업으로 계산하지 않는다.
- B `019-b-export-final.result.json`, C `023-c-export-final.result.json`: 각 4개 파일이 `EXPORTED`, `defender-service` CLEAN. 동일 이름 `management-input.txt`·`management-router.json`을 각 세션의 `Downloads/SandboxOutput/<세션>/<ART-ID>`에 저장했고 실제 저장 파일 SHA-256이 후보와 일치했다.
- B 입력 해시 `8c8bbfe7d10f6253fd6f5ce2640cab31bcfb7ace48175e423c267dbde4b6de67`, C 입력 해시 `f424c1ef76116d87409b8081f0ff48791a4a66e4b172f87c458e146ed73845ad`. 반출된 Router JSON도 해당 세션·workspace·container·입력 해시를 담는다.
- A `hardening-20261109/110-management-a-observe-0.png`와 `111-management-final-state.result.json`: 실제 WSB 바탕화면과 READY. 기존 B·C도 `hardening-bc2-20261109/075-management-preserved-*.result.json`에서 연결을 유지한다. 새 B·C 최종 상태도 READY/connected다.

## 실제 발견·수정한 오류

처음 동시에 시작한 검증 B(`SES-863fd5969cb646d0a27db9b26dc41edc`, workspace `398a7447-5db3-4d40-af1e-bfdea617f51a`)는 VM 생성 후 상태 JSON 직접 읽기에서 `PermissionError`로 시작에 실패했다. 당시 시작 실패 처리에서 이 B만 종료됐고 `cleanup_confirmed:true`를 확인했다. C와 기존 세션은 유지됐다. 이 실패를 성공 결과에서 제외한다.

서비스 경로의 상태 조회를 capability·소유권 검사를 거치는 RPC로 바꿨다. 파일 ACL을 완화하지 않았다. 보호 파일 읽기를 모두 거부하는 테스트에서도 상태 조회가 되고, 다른 VM/container 응답은 거부되는 것을 확인했다. 새 wheel로 별도 B를 시작해 위 실제 기능을 재검증했다. C에는 실행 중인 구 wheel을 덮어쓰지 않았으므로 두 wheel의 차이를 명시했다.

기존 빌드 디렉터리의 증분 전체 링크에서는 이전 `serve_broker` 서명을 참조하는 WorkspaceSmoke 객체 때문에 실패했다. 별도 `tmp/build/management-final`에서 171개 단계를 처음부터 빌드해 통과했다. CTest launcher 1건은 PowerShell 7에서 물려받은 모듈 경로로 `Get-FileHash`를 찾지 못했다. CMake에서 PowerShell 5.1 테스트의 모듈 경로를 고정하고 관련 5개 시험을 재실행해 통과했다.

## 자동 검증

- Host: `host-service-final.log`, **886 passed, 23 skipped**.
- Manager: `manager-service-final.log`, **242 passed, 1 skipped, 8 subtests passed**.
- native: clean 전체 빌드 성공. 선택한 CTest 40개 중 최종 **39 통과·1 skip**(초기 launcher 실패와 수정 후 재실행 로그를 함께 보존). 실제 High 신원 시험과 `owned_workspace_and_real_ipc`는 이번 실행에서 제외했다. 전자는 Medium 환경, 후자는 기존 viewer/VM 보호 때문이다. 전체 CTest를 한 번에 모두 통과했다고 쓰지 않는다.
- `management_service_session_boundaries`: 소유권, capability, 중복 변경, 한도, Host 경로 거부 등 27개 검증. 실제 VM 대역 테스트다.
- `tests/test_management_contract.py`: 요청·파일 결과 규격과 실제 서비스 health 응답 검사. health는 VM READY 증거가 아니다.
- `deployment-profile.json` / `deployment-profile-check.log`: 실제 설치 서비스·설정·Runner·relay 고정, 일반 권한 `host/solution.py --config ... --check` 성공. 기존 Scanner 서비스·Defender·실행 금지 폴더를 확인했다. 새 VM 시작이나 전역 MCP 설정 변경은 하지 않았다.

## 전체 바탕화면 시험은 실패

별도 진단 VM workspace `fee644bf-3348-442b-8acb-da904eac4706`, container `02085c1e-345a-4458-8437-aa3300a9422b`에서 기존 `workspace desktop-logon`을 1회 실행했다. A와 기존 B·C는 유지했다. `desktop-logon-report.json`의 결과는 `console_logon_logon_timeout`, Win32 258, `logged_on:false`, `shell_running:false`, `logonui_ended:1`, `claim_kept:true`다. 이후 진단 VM의 Agent/Runner 연결이 끊겼고 원래 Runner 종료도 확인되지 않았다. VM과 claim을 임의 제거하거나 불확실한 입력을 재전송하지 않았다.

이는 현재 PC(Windows 26200.9711)에서 실제 전체 바탕화면이 성립하지 않았다는 증거다. **현재 PC의 정확한 거부 NTSTATUS가 `STATUS_REMOTE_SESSION_LIMIT`라고 확정한 증거는 아니다.** 다른 빌드의 저장소 기록과 구분한다. 실패 직후 Guest 이벤트 수집도 연결 상실로 완료되지 않아, 기본 Win+R 구현·검증을 완료했다고 할 수 없다.

이후 사용자의 명시적 종료 승인으로 이 실패 진단 VM만 종료했다. 전체 workspace·container·세션·소유자·claim을 확인한 `stop-failed-desktop-probe-20261109.ps1`을 1회 실행했다. 최초 응답은 비동기 `Stopping`이므로 즉시 확인 파일은 실패로 기록됐지만, 추가 종료 요청 없이 뒤이은 읽기 전용 확인에서 `Stopped`, `cleanup_confirmed:true`, `compute_absence_verified:true`를 확인했다. `failed-desktop-stop-confirmed.json`의 확인 시각은 2026-11-09T04:50:51Z다. A 및 기존 B·C는 `112-after-desktop-probe-stop.result.json`, `076-after-desktop-probe-stop-*.result.json`에서 READY/connected를 유지했다.

일반 권한 B에서 별도 Router `RUN-0003`으로 `SwitchDesktop` 진단을 실행했다. Guest 영수증은 SUCCEEDED이며 `desktop-switch-evidence.json`은 Defender 검사 후 ART-000005로 반출됐다(SHA-256 `13a0ed9ce6c0945651cc0419e65d20f892fb30b49dbf98715e3a4b7b1684bbff`). 입력 데스크톱은 실행 전과 실행 후 5회 모두 Winlogon이었다. 보고서의 Win32 203은 OpenDesktop/SwitchDesktop 실패를 구분하지 않고 이전 LastError가 남을 수 있는 진단 코드의 값이므로, 정확한 실패 원인으로 해석하지 않는다. 이 진단은 전체 데스크톱 전환 성공 증거가 아니다.

### 별도 native RDP 진단

새 진단 VM workspace `bd6f82cb-46d9-4d21-a25b-6fdc9b0192cc`, container `a30157b2-b042-4852-a0b6-092a636fabc0`, SCRP `SES-b416320a6d304bc98291a22cc3dff008`은 시작 후 실제 READY와 heartbeat를 확인했다. 이 진단 실행기는 High이며, 앞의 일반 권한 배포 결과에 포함하지 않는다. 증거 루트는 `C:\SCRPAppLab\desktop-rdp-20261109`다.

`workspace viewer --console --hidden --keep-session`을 사용했고 보호 검사 예외나 감사 허용 플래그를 추가하지 않았다. `rdp-report.json`은 301141ms 동안 120회 관찰한 뒤 `logon.ready:false`, `shell_running:false`, `hidden_logon_incomplete:true`, `console_attached:false`를 보고했다. 최상위 `ok:true`만으로 바탕화면 성공을 판정하지 않는다. 클라이언트 종료 코드 `0xC037010A`는 설치 SDK의 `ERROR_VMCOMPUTE_CONNECTION_CLOSED`이며, 그 자체로 최초 로그온 실패 원인은 아니다. 클라이언트는 종료됐고 viewer claim은 해제됐으며 진단 VM은 유지됐다.

이 VM의 Router `RUN-0001`~`RUN-0003`은 모두 SUCCEEDED/GUEST_PROCESS_VERIFIED/exit 0이다. Guest에서 수집하고 Defender 검사 후 반출한 이벤트는 다음 순서를 보였다(UTC).

| 시각 | 실제 이벤트 |
|---|---|
| 04:58:02.753879 | Security 4624, WDAGUtilityAccount, LogonType 10 |
| 04:58:02.758892 | Winlogon 2, Win32Status 0 |
| 04:58:02.765814 / .774497 | LocalSessionManager 41 / 42, 같은 ActivityID, SessionID 2 |
| 04:58:02.769792 | RdpCoreTS `SendLogonErrorInfoToClient(WinlogonStatus: 0x2, ClientError: 0xfffffffe)` |
| 04:58:33.926012 | LocalSessionManager 40, Session 2, Reason 12 |
| 04:58:34.106300 | RdpCoreTS 103, ReasonCode 12; 이어서 server initiated disconnect |
| 05:02:32 | 입력 데스크톱 Winlogon, 작업 표시줄 없음, Explorer 없음 |

`0xfffffffe`는 [Microsoft RDP 규격](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/845eb789-6edf-453a-8b0e-c976823d1f72)의 로그온 진행 알림이며, 함께 표시된 2를 독립적인 실패 NTSTATUS로 취급하지 않는다. RDP의 12는 [ExtendedDisconnectReasonCode](https://learn.microsoft.com/en-us/windows/win32/termserv/extendeddisconnectreasoncode)의 LogoffByUser 값이지만, 이를 실제 사용자가 로그오프 버튼을 눌렀다는 증거로 취급하지 않는다. 해당 시점에 진단 코드는 로그오프나 클라이언트 닫기를 요청하지 않았다. 인증 이후 세션 해제까지는 확인했으며, 해제를 일으킨 호출자와 최초 내부 실패 상태는 아직 확정하지 못했다. 같은 시각의 `0xc000015b`는 ContainerUser의 **서비스 로그온(type 5)** 실패로, 성공한 WDAGUtilityAccount 원격 인증과 구분한다.

반출 해시는 `logon-evidence.json` ART-000001 `316ecab4ac7cba62a85f4dbed3091dd25d08f3d3919b31e27b7633aeb56e5098`, `rdp-event-details.json` ART-000004 `6e33e3883b7879d4f8da0e8bd4cd38438b85890daf8d43ed3117e1083733afe9`, `rdp-post-auth.json` ART-000007 `86b280a2c4929b03ab5a8cdbc0a40235ce1cd62d355ad1c0bb1443000621b2a5`다. 시험 동안 A·일반 권한 B·C의 `rdp-hold-001`~`067` 관찰 결과를 남겼다.

### Guest 안에서 수집한 후속 ETW

동일 진단 VM의 Winlogon·LocalSessionManager 두 provider만 180초·4MiB 순환 ETW로 수집했다. Host 전체 추적은 실행하지 않았다. `rdp-trace3-finished.json`의 시작·종료 코드는 모두 0이며 05:14:01Z~05:17:01Z를 기록했다. 실제 ETL은 90112바이트이고, Guest에서 렌더링한 이벤트 68개와 함께 Defender 검사 후 반출했다. `rdp-trace3-events.json` ART-000020 SHA-256은 `f527f84ffbc794b011894f2dee13a005374a77153405ece19b23b247425a95a0`이다.

이 두 번째 RDP 시도는 `rdp4-report.json`에 기록했다. 세션 2가 `Created → CsrConnected → CsrInitialized → Connected`까지 진행했고, Winlogon의 인증 반환 상태는 0이었다. 05:14:10.879Z의 중재 종료 뒤 05:14:41.889Z에 **`Connected → Terminated`, `EvTerminatedWinlogon`**을 기록했다. 이후 Reason 12와 연결 해제·CSR 해제가 뒤따랐다. `logon.ready:false`, `shell_running:false`, `console_attached:false`였고 클라이언트는 종료됐으며 claim은 해제됐다. 최초 실패 NTSTATUS나 호출 스택은 이 기록에 없어 원인을 확정하지 않는다.

준비 실패도 별도로 보존했다. 첫 준비 실행기는 PowerShell 5.1에서 Get-Content 문자열의 확장 속성을 JSON으로 직렬화하다 정체되어, PID·생성 시각·실행 경로를 검증한 **자신의 실행기만** 종료했다. Guest 추적·RDP는 시작 전이었다. ReadAllText의 일반 문자열로 수정했다. 다음 준비는 logman의 복수 `-p` 사용 오류로 시작 코드 `0x80070057`을 반환했다(Router RUN-0004 FAILED). `-pf` provider 파일로 수정한 RUN-0005는 SUCCEEDED/GUEST_PROCESS_VERIFIED/exit 0이다. 기록 중 열린 ETL 때문에 Output 스냅샷이 한 번 OUTPUT_UNAVAILABLE로 거부됐으나, 추적 종료 후 같은 검사·반출 경로로 완료했다.

기존 Guest 이벤트 진단기는 UserData에 있는 Session/Reason을 누락하고, 상한 시각 없이 이전 이미지 이벤트까지 섞었다. `tools/guest-logon-evidence.ps1`에 시작·종료 시각과 UserData 추출, ActivityID/PID/TID, RdpCoreTS 조회를 추가했다. 실제 RUN-0006이 SUCCEEDED했고 ART-000015에서 원래 시도의 Session 2/Reason 12/같은 ActivityID를 확인했다. 이 수정은 진단 정확도 개선이며 바탕화면 기능 구현으로 계산하지 않는다.

### 로그온 화면 수집 준비 실패

사용자가 각각 1회씩 승인한 후속 화면 진단에서 새 Winlogon 세션 2는 발견했지만 수집 프로세스를 만들지 못해 PNG는 없었다. 최초 결과는 일반적인 매개 변수 오류뿐이었고, API별 기록을 추가한 결과 `DuplicateTokenEx`, Win32 87을 확인했다. 원인은 진단 코드가 `TokenPrimary`로 1 대신 0을 넘긴 오류다. Windows의 로그온 제한으로 해석하지 않는다. `rdp-screen2-parent.json`은 ART-000031로 검사·반출됐으며 SHA-256 `826b5984415ea245ad3493a8dddfb766c5c8c1e3e67741cf83f9b630128cf389`다. RUN-0008/0009의 SUCCEEDED는 진단 스크립트 완료이며, 내부 `ok:false`를 우선해 화면 수집 실패로 판정했다.

### TokenPrimary 수정본과 실행 문맥 확인

Guest 대조 RUN-0010에서 DuplicateTokenEx의 token type 0은 Win32 87, 올바른 TokenPrimary 1은 성공을 반환했다. 사용자가 추가 1회를 승인한 수정본 `test-desktop-rdp-guest-screen-primary-20261109.ps1`은 토큰 복제와 TokenSessionId 설정을 통과했지만, `CreateProcessAsUser(Winlogon desktop)`에서 Win32 5(접근 거부)를 반환했다. 대상은 세션 2, Winlogon PID 6088(생성 시각 2026-11-09T05:36:24.2503541Z)였다. 화면 수집 자식이 생성되지 않았으므로 PNG는 없다. ART-000038 `rdp-screen3-parent.json`은 Defender 검사 후 EXPORTED, SHA-256 `13be23ace64411cb23879888e9cd81e8acbe715a9b6aa797366a4c806c66d4c6`이다. RUN-0011의 SUCCEEDED는 진단 스크립트 완료만 나타낸다.

읽기 전용 후속 Router 진단에서 호출 프로세스가 세션 1의 Job에 속하고 조회한 Job의 LimitFlags가 0임을 확인했다. ART-000041 `screen-caller-job.json`은 Defender 검사 후 EXPORTED, SHA-256 `d7f407531dde0485264da485e012197f72fbb1bdefc8b7e58a0a452368fb5d2f`이다. Microsoft의 [Job 계약](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createjobobjecta)에 따르면 같은 Job의 프로세스는 같은 Windows 세션에 속해야 한다. 따라서 세션 1에서 세션 2로 자식을 만들며 Job을 상속하는 진단 설계가 접근 거부의 후보 원인이다. 이 대조는 별도 프로세스에서 수행했으며 실패 호출의 커널 분기를 기록하지 않았으므로 단일 원인으로 확정하지 않는다. 이 접근 거부는 원래 Winlogon 종료 원인과도 구분한다. Job 제한 해제, breakaway, ACL 변경은 실행하지 않았다.

`rdp7-report.json`은 301859ms/120회 관찰 후 logon.ready:false, shell_running:false, console_attached:false를 기록했다. 14:41:36 KST에 클라이언트 종료를 확인했고 viewer_session_claimed:false였다. 진단 VM은 `053-rdp7-final-state.result.json`에서 READY/connected/세대 1을 유지했다. A와 일반 권한 B·C도 각 증거 루트의 `rdp7-hold-063.result.json`에서 READY/connected/세대 1이었다. 이번 승인된 RDP 1회를 완료했으며 추가 RDP 로그온은 실행하지 않았다. 전체 바탕화면과 기본 Win+R은 여전히 미검증이며 최초 Winlogon 내부 실패 원인은 확정하지 못했다.

### 화면 수집을 제외한 로그온 종료 추적

2026-11-09 후속 요청으로 화면 진단을 중단하고 기존 이벤트·프로세스 종료·호출 스택을 조사했다. 동일 진단 workspace/container를 사용했으며 A, 일반 권한 B·C 및 기존 B·C는 각 `cause-final-state-*.result.json`에서 READY/connected/세대 1을 유지했다. `rdp9-finished.json`, `rdp10-finished.json`에서 진단 클라이언트 종료를 확인했고 두 보고서 모두 viewer_session_claimed:false였다. VM은 종료하지 않았다.

`logon-termination-existing-evidence.json`(ART-000044)의 FilterHashtable 시각 조회는 알려진 이벤트가 있는데도 결과가 없었다. 이것을 오류 이벤트 부재로 해석하지 않았다. UTC 문자열을 직접 넣은 XPath 대조 `logon-termination-xpath-evidence.json`(ART-000047)은 동일 구간의 Security·Winlogon·LSM 이벤트를 회수했다. 네 차례 인증 성공 후 약 31초 뒤 세션 종료가 반복됐으며 해당 조회에 4647/4689는 없었다. 감사 이벤트 부재만으로 사용자/프로세스의 종료 요청을 배제하지 않는다. AgentSessionMoved 기록도 없었지만 이것만으로 모든 micro_VM 개입이 배제되는 것은 아니다.

Guest 전용 Kernel-Process·Winlogon·LSM·RdpCoreTS 추적(`rdp9`)은 120초 동안 445개 이벤트를 수집했다(변환 상한 12000). ART-000061 `logon-cause2-events.json` SHA-256 `c72413b6575e5d4fce7ef2f1988d03c8044a9486cc9cf87bf8a66d2367628e0f`는 Defender 검사 후 반출됐다. 실제 순서는 다음과 같다(UTC).

| 시각 | 관찰 |
|---|---|
| 05:56:13.947496 | 세션 2 Winlogon PID 5424 생성 |
| 05:56:15.983830 | Winlogon 인증 반환 상태 0 |
| 05:56:46.993008 | Winlogon TID 2748이 Event=1 알림 시작 |
| 05:56:46.993178 | LSM이 EvTerminatedWinlogon으로 Connected → Terminated |
| 05:56:47.073110 | LogonUI 종료 코드 0 |
| 05:56:47.144627 | DWM 종료 코드 0xD00002FE |
| 05:56:47.155630 | fontdrvhost 종료 코드 0x00000102 |
| 05:56:47.159574 | Winlogon 종료 코드 0 |

이 구간에서 userinit.exe와 explorer.exe 생성 이벤트는 없었다. DWM 종료는 Winlogon의 종료 알림 뒤이므로 DWM 종료 코드를 최초 원인으로 단정하지 않는다. Winlogon 종료 코드 0도 로그온 성공이나 외부 종료 요청 부재의 증거로 취급하지 않는다. 준비용 첫 추적 RUN-0015는 열린 ETL의 Output 스냅샷 실패로 RDP 시작 전에 끝났다. 기록 중 ETL을 Guest RunnerLogs에 두고, 종료 뒤 닫힌 파일만 Output에 내는 방식으로 수정한 RUN-0016에서 실제 로그온을 기록했다. 준비 실패와 실제 시험을 구분한다.

후속 `rdp10`은 Guest 내장 WPR의 고유 인스턴스 `MinoLogonStack_b416320a_1`로 90초/설정 버퍼 12MiB의 Winlogon·LSM 이벤트 스택 및 ProcessThread/Loader 기록을 수집했다. Host ETW, 화면, 메모리 덤프, 서비스/ACL/보안 정책 변경은 없다. 시작·종료 코드 모두 0이며 기존 Guest 추적 세션은 중지하지 않았다. 총 67개의 이벤트 스택 중 Winlogon 스택은 55개다. Winlogon PID 6032의 실제 이미지 베이스는 `0x7FF7E8780000`, 크기는 `0xF7000`이다. 종료 알림 스택에는 `winlogon+0x34F89`, `+0x41C1F`, `+0x596F2`, `+0x31CEE`가 포함된다. 주소를 아직 함수 이름이나 최초 실패 분기로 해석하지 않았다.

ART-000069 `logon-stack1.etl`(4718592바이트, SHA-256 `74272bc05313bab34eff0595f8ddeb11c264600cd2d174b3dcbdb11e934d894c`)과 ART-000074 `logon-stack1-focus.json`, ART-000077 `logon-stack1-module-map.json`은 검사 후 반출됐다. 24772366바이트 XML 변환본은 OUTPUT_TOO_LARGE로 거부됐다. 원본과 해시가 일치하는 자체 진단 사본만 Guest RunnerLogs로 옮겼으며, XML을 분할하거나 다른 경로로 반출하지 않았다. 작은 스택 요약과 허용 크기인 ETL은 같은 공식 검사 경로를 사용했다. 최초 focus의 stack_node_count:0은 검색식이 실제 `<Stack>` 태그를 놓친 진단 요약 오류였고, module-map의 실제 XML 태그 집계에서 67/55를 확인했다.

Host 파일과 Guest 파일의 Winlogon SHA-256은 `2baa43fa3e9b1694fbe86b789854b24217a1cf4802a94d1bc28bc45290a89d63`으로 일치한다. CodeView가 요구하는 공개 심볼은 `winlogon.pdb/2BE8AB4088C5B923E6F852DBFEFD6F351/winlogon.pdb`다. 공식 SCRP inbox_download는 Host의 17444 바인딩 충돌로 RUNTIME_UNAVAILABLE을 반환했고 다운로드되지 않았다. 사용자 AGENTS의 연결 실패 후 다른 실행 경로 금지에 따라 우회하지 않았다. 해당 Microsoft 공개 PDB 1개만 Host에서 데이터로 다운로드하는 예외를 요청했으며, 준비한 `download-public-winlogon-symbol-20261109.ps1`은 아직 실행하지 않았다. 정확한 최초 거부 함수/상태는 미확정이다.

## 재현 순서

1. 검토한 micro_VM·Runner를 빌드하고 micro_VM 묶음을 만든다. 서비스 설치는 `management-service.md`의 동일 계정 최초 설치 절차를 따른다. 기존 서비스를 덮어쓰지 않는다.
2. Host `requirements-base.txt`와 수정 Manager wheel을 새 venv에 설치한다. `PYTHONPATH`에 Manager checkout을 넣지 않고 실제 `sandbox_manager.__file__`·파일 해시를 기록한다.
3. Host 설치 프로필에서 서비스 package/root/max_active, relay, Runner 해시를 확인하고 일반 권한 `--check`를 통과시킨다. 최초 전체 설치는 기존 세션이 없는 유지보수 시점에 수행한다.
4. A를 유지한 채 두 일반 권한 Host를 각각 시작한다. `task_submit` 후 READY·인증·실제 첫 화면·heartbeat와 서로 다른 전체 VM ID를 확인한다.
5. 각 VM에서 Router로 검증 앱을 열고, 최신 화면을 관찰한 뒤 한글 입력한다. 같은 이름의 Output을 저장하고 `artifact_export`/`artifact_list`의 Defender EXPORTED를 기다린다.
6. 별도 Router 작업의 `sandbox_run_status`에서 Guest 영수증·stdout 검사까지 완료해 `SUCCEEDED`를 확인한다. 반출 바이트 해시·세션·VM을 대조하고 A·기존 세션의 최종 연결을 확인한다. 세션은 사용자 요청 없이 종료하지 않는다.
