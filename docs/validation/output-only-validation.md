# Output 단일 반출 검증 기록 (#105)

검증일: 2026-11-03. 최신 Host/Runner의 실행 중 반출과 창 닫기 후 반출을 완료했다.

## 실제 Windows Sandbox에서 확인한 것

- 세 구성요소가 READY이고 `artifact.output.v1`을 협상했다.
- 생성된 WSB에는 RunnerPackage, RunnerBootstrap, Inbox의 읽기 전용 매핑만 있다.
  Shared 쓰기 매핑은 없다. Manager 소스 변경 없이 이 구성을 시작했다.
- Sandbox 바탕화면의 Output 바로가기가 실제 세션/세대 Output을 가리킨다.
  그 타깃에 저장한 테스트 결과가 HTTPS로 Host의 `Work/output/<session>/ART-*`에 수신됐다.
- 새 Runner의 `output_snapshot_test.exe`를 Guest Input 사본으로 실행했다.
  잠금, SHA-256, 중첩 파일, 추가 파일 감지, 파일/총량 제한, 재캡처, 하드링크 거부가
  `Output snapshot verification passed`, `NATIVE_EXIT=0`으로 끝났다.
- 실행 중 `output-regression.txt` 반출을 요청했으나 목록 확인 응답이 없어 HELD가 됐다.
  공개되지 않은 임시 사본을 유지했다. 안내창까지 기다리다 60초 MCP 제한을 넘는 문제를
  확인해 Output 도구의 제한을 늘렸다. 아래 최신 구성에서 실제 창 재검증을 완료했다.

## 최신 구성의 실제 최종 반출

- Host `c0f4047c7a6aa99bcbb8c8b046f7011a67488ea9`, Runner
  `0bbacd3fcf6ef63357e4e9bad0f1c17584cd4f9f`, Manager
  `66923d381e7090a880e4b9000beb4a0c946ba332`을 함께 실행했다.
- Runner 실행 파일 SHA-256:
  `2a9c0f156e74aa0371a34ba6f66515359846e4fab101a9168ee2e2e4e2205641`.
- 세션: `SES-b4062448bd9a45b8851b7eaf6a268292`, generation 1.
  Guest의 Output 바로가기 타깃에 무해한 고정 바이트를 저장했다.
- 실행 중 BIN과 ZIP을 `artifact_export`로 요청했다. 실제 사용자가 목록 확인과
  최종 보관 창을 처리했고, 두 파일 모두 `EXPORTED`, `engine=defender-service`가 됐다.
- 07:07:29 KST 사용자의 Sandbox 창 닫기를 감지했다. 전체 목록 CAPTURE/VERIFY 응답을
  받은 뒤 07:07:29.596 TERMINATE를 보냈다. 07:07:30.869 Manager 종료·정리를 확인한 뒤
  남은 TXT의 목록 확인·검사·최종 보관을 진행했다. 07:07:37.867 사용자의 keep을 기록했고,
  07:07:38.813 Host 서버 정리를 마쳤다. 이후 상태는 `TERMINATED`, `host_released=true`,
  `host_error=null`이다.

| 파일 | 반출 ID | 바이트 | SHA-256 | 시점 |
|---|---|---:|---|---|
| o-1103.bin | ART-000001 | 7 | a0fee516a1277bacc2f375afaf8f5a9ac05c5529dd5075ca616cbd9d0afe53a9 | 실행 중 |
| p-1103.zip | ART-000002 | 22 | 8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85 | 실행 중 |
| c-1103.txt | ART-000003 | 10 | e36ef977a4a50ab35a8d767bf6e82a53582c6690fa228b8a3bd637237662e5e3 | 창 닫기 후 |

최종 위치는 `Downloads/SandboxOutput/<위 세션>/<반출 ID>/<파일명>`이다.
세 파일 모두 예상 바이트와 SHA-256이 일치하며 `Zone.Identifier: ZoneId=3`이 있다.
각 파일은 정확히 한 사본씩 존재하고, 종료 시 이미 반출한 BIN/ZIP을 중복 공개하지 않았다.
Host 대기 영역에는 `output-state.json`만 남았고 `files=[]`, 확보 상태는 `CAPTURED`,
`complete=true`다. 검사 서비스는 Running이며 세 반출 모두 서비스의 CLEAN 응답을 요구하는
경로로 완료됐다. 서비스 전용 ProgramData의 로그·격리 폴더는 현재 사용자 ACL로 열 수 없으므로,
그 폴더의 물리적 삭제를 별도로 실측했다고 주장하지 않는다. 서비스 정리 요청 성공은
반출 경로의 필수 조건이다. 악성 판정·오류 처리는 아래 회귀 검사와 구분한다.

로컬 원본 증거: `SecureCUAState/solution/output-latest-evidence`의
`0024.json`(세 후보), `0029.json`(실행 중 두 반출), `0030.json`(종료 상태),
`0031.json`(세 반출 완료), `published-files.json`(바이트·해시·MOTW), 같은 상태 루트의
`host.log` 및 세션별 `audit/*.jsonl`. 개인 경로·세션 설정·토큰을 저장소에 복사하지 않는다.

## 자동 회귀

Python 3.13.7 embedded와 테스트 의존성을 Input에 반입하고 Guest의 input-check에서
전체 SHA-256 일치를 확인한 후 실행했다. Host에서 테스트 코드를 실행하지 않았다.

- v2: 47 통과, 1 실패. 변조 모사 테스트가 읽기 전용 파일의 쓰기 금지에서 막혔다.
  테스트 사본의 속성만 바꿔 변조를 모사하도록 수정했다.
- v3: 93 통과, 3 실패. 삭제된 CLI 안내 검사 2개는 대소문자 기대값 문제였고,
  stdio 설치 테스트 1개는 Guest의 관리자 실행을 제품이 정상 거부한 경우였다.
  실제 옵션 이름과 관리자 거부 동작을 검증하도록 테스트를 수정했다.
- v4: 위 수정과 후속 진입점 변경을 같은 Sandbox에서 재검증해 **89 통과,
  PYTEST_EXIT=0**을 확인했다(76.25초). Output/기존 Artifact 전송, 목록·최종 승인,
  종료 순서·확보 실패 시 VM 보존, Shared CLI 거부, 설치 PowerShell, 실행 진입점과
  검증기 검사를 포함한다. v3에서 통과한 별도 시작/복구 테스트는 재실행하지 않았다.
  반입 패키지 SHA-256: `d5b7409c2d57b00dcfa6df486c9932d72bfa5c6e1df454515884e526996b7783`.
- develop `6001349`의 저장소 규칙을 병합한 v5 전체 실행: 694 통과, 4 실패, 55 제외.
  새 `ARTIFACT_BLOCKED` 안내 누락과 제거된 Shared API를 전제로 한 테스트 3개를 확인했다.
  오류 안내를 추가하고 테스트를 Output 서비스 선택·종료 후 검사·정리 실패 차단으로 전환했다.
- v7: 빠른 점검 **18 통과**, 전체 `pytest -q tests` **700 통과, 55 제외**, 193.11초,
  `QUICK_EXIT=0`, `PYTEST_EXIT=0`. 일반 사용자/설치된 서비스/선택 실행 환경이 필요한
  제외 항목을 실제 검증한 것으로 계산하지 않는다. CAPTURE 응답 유실 시 동일 ID 해제,
  해제 응답 유실 시 상태 보류, VM 종료 후 검사·승인 완료까지 기다리는 검증기도 포함한다.
  반입 패키지 SHA-256: `c3cb8b07f80a3682c4a142af3dde6447f3ac470a7f1e703ea09ab41189613b35`.
- Runner v6: 실제 파일 잠금 검사에 비동기 작업자 요청·응답 상관관계, 다른 연결/세대 거부,
  중복 CAPTURE·잘못된 ID 해제 거부, 반복 RELEASE, 종료 후 잠금 정리를 추가해 Guest에서 통과했다.
  `Output snapshot and worker protocol verification passed`, `NATIVE_EXIT=0`.
  반입 패키지 SHA-256: `507f60d1625c1bea5172dee3c9da768da212cc3aa014f6ed68478f45b950f8c8`.
- v8: Runner 세대 교체 후 이전 잠금 ID가 새 확보를 막는 경우와 이전 CAPTURE/VERIFY
  응답이 늦게 도착하는 경우를 보완했다. 이전 수신본 유지와 새 세대 재확보를 검증했다.
  빠른 점검 **18 통과**, 전체 **703 통과, 55 제외**, 193.76초, `PYTEST_EXIT=0`.
  반입 패키지 SHA-256: `6ba259c1f400690d14f6e197b8fb53be44ecd89eba7866311895283fd9d2f873`.

회귀 테스트는 MCP/WSS/HTTPS 및 Windows 파일 잠금·Named Pipe 통신을 실제로 사용한다.
일부 테스트의 VM, 전체 목록, 검사 판정, 사용자 선택은 대역이다. 이것을 설치된 Defender나
사용자의 실제 승인 증거로 간주하지 않는다.

## 검증 범위와 제한

- 실제 서비스 검사와 두 승인 창, 실행 중 및 창 닫기 후 다운로드 반출을 확인했다.
- 프로토콜 실패/경쟁 및 설치 갱신 경로는 회귀 테스트로 검증했다. 다른 PC에서의
  신규 설치 실측과 이번 세션에서의 악성 파일 실험은 수행하지 않았다.
- 강제 VM 소멸이나 Host 장애 전에 전송되지 않은 파일까지 복구한다는 보장은 없다.
- 기존 Shared 임시 잔여물은 자동 삭제하거나 이관하지 않는다.

## 등록한 작업

- Host 이슈 [#105](https://github.com/b-hamo/host_control/issues/105), PR [#108](https://github.com/b-hamo/host_control/pull/108).
- Runner 이슈 [#35](https://github.com/b-hamo/sandbox_runner/issues/35), PR [#36](https://github.com/b-hamo/sandbox_runner/pull/36).
- Manager 소스는 변경하지 않았다. 두 PR은 develop 대상이며 함께 적용해야 한다.
