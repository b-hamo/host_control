# Output 단일 반출 검증 기록 (#105)

검증일: 2026-11-03. 작업은 진행 중이며 실제 최종 반출 완료 기록은 아직 없다.

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
  확인해 Output 도구의 제한을 늘렸다. 수정 후 실제 창 재검증은 필요하다.

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

회귀 테스트는 MCP/WSS/HTTPS 및 Windows 파일 잠금·Named Pipe 통신을 실제로 사용한다.
일부 테스트의 VM, 전체 목록, 검사 판정, 사용자 선택은 대역이다. 이것을 설치된 Defender나
사용자의 실제 승인 증거로 간주하지 않는다.

## 남은 확인

- 최신 Host/Runner 구성으로 재시작 후 실제 Defender 검사와 두 승인 창, 다운로드의
  파일 내용·SHA-256·MOTW·단일 사본을 확인해야 한다.
- 실행 중 반출에 이어 정상 종료/창 닫기에서 최종 Output 확보와 남은 파일 반출을 확인해야 한다.
- 최신 프로토콜의 실패/경쟁 및 설치 갱신 경로 검증을 마친 뒤 Draft를 해제한다.
- 기존 Shared 임시 잔여물은 자동 삭제하거나 이관하지 않는다.

## 등록한 작업

- Host 이슈 [#105](https://github.com/b-hamo/host_control/issues/105), Draft PR [#108](https://github.com/b-hamo/host_control/pull/108).
- Runner 이슈 [#35](https://github.com/b-hamo/sandbox_runner/issues/35), Draft PR [#36](https://github.com/b-hamo/sandbox_runner/pull/36).
- Manager 소스는 변경하지 않았다. 두 PR은 develop 대상이며 실제 최종 반출 검증 전까지 Draft다.
