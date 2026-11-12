# Shared와 Output 반출 통합

관련 이슈: #103. 기준 develop: Host `1d4ae95`, Manager `66923d3`, Runner `094785d`.

## 사용자 절차

통합 실행(`host/solution.py`)은 `--unified-export`를 기본 선택한다.
Codex는 `artifact_list`로 Shared 미러와 Runner Output 후보를 함께 조회하고,
사용자에게 파일명·출처·알려진 크기·현재 상태를 보여 준 뒤 선택한 후보 ID로
`artifact_export`를 호출한다. 임의 Host 경로를 반출 인자로 받지 않는다.

1. Host의 목록 확인 창에서 사용자가 검사할 파일을 확인한다. 취소/무응답은 보류한다.
2. Shared는 조회 시 크기·SHA-256과 실제 파일이 같은지 확인한다. Output은 기존
   일회용 HTTPS 권한으로 수신하고 Runner 결과와 수신 크기를 대조한다.
3. 두 출처 모두 동일한 SecureArtifactScanner Shared 프로필로 검사한다.
4. CLEAN 이후 별도의 보관 승인 창을 표시한다. 목록 확인은 최종 승인을 대신하지 않는다.
5. 승인한 동일 바이트만 다운로드 Known Folder의
   `SandboxShared/<세션>/<반출 ID>/`에 저장한다. MOTW(ZoneId=3)를 붙인다.
6. 최종 경로와 SHA-256이 있는 EXPORTED가 완료 증거다. ACCEPTED/업로드 성공은 완료가 아니다.

Sandbox 종료 시에도 자동 보관 절차를 유지한다. 종료/정리 확인 후 남아 있는 Shared 파일에
목록 확인 → 검사 → 최종 승인 절차를 적용하며, 묶음은 `remaining-<임의 ID>` 아래 저장한다.
동일 세션에서 이미 반출한 파일은 현재 Shared 내용과 최종 파일의 해시가 모두 일치할 때만
중복 반출을 생략한다. 실행 중 Shared 원본은 지우지 않는다.

Shared 미러는 비동기이므로 Guest에서 파일을 저장하고 닫은 뒤 목록에 나타날 때까지 기다린다.
목록은 Guest의 마지막 저장까지 완료됐다는 보증이 아니다. 목록 확인 뒤 변경된 파일은 다시
조회해야 하며, 검사·최종 승인·복사 동안 파일과 상위 폴더 핸들을 잠근다.

## 구성요소와 정책

- Host: 후보 합산, 목록 확인과 최종 승인, 수신, 공통 검사/보관, 중복 방지.
- Manager: 기존 Sandbox 수명주기와 Shared 미러/감시. 종료 확인 후 Host의 공통 처리를 호출한다.
- Runner: 기존 Output 후보 보고와 HTTPS 업로드. 기존 전송 계약을 재사용한다.
- 검사 서비스: 기존 Shared scan-only 프로필. 검사 오류·미확인·악성은 차단하며 대체 검사기를 쓰지 않는다.

통합 경로는 확장자 허용 목록을 두지 않는다. 통합 프로필의 파일당 상한은 50 MiB이고,
Shared 전체 상한은 기존 2 GiB/20,000개다. 링크·특수 파일·모호한 경로는 거부한다.
Runner 수신 파일은 실행 금지 ACL을 확인한 Work/shared 아래 전용 수신 영역에 보관한다.
검사 서비스 계정에 사용자 다운로드 폴더 쓰기 권한을 부여하지 않는다.

기존 수동 실행 설정은 `--unified-export`를 명시해야 한다. 이 옵션은 `--shared`,
`--artifact-export`, `--runner-exe`, `--artifact-scanner defender-service`가 필요하다.
기존 검사 서비스의 artifact ExportRoot는 상태 점검/호환용으로 유지되며 통합 사용자 반출은
`State/exports`에 공개하지 않는다.

## 검증 기록

2026-11-02 Windows Sandbox에서 116개 회귀 테스트가 통과했다(66.90초, 종료 코드 0).
검증 범위: 통합 반출, 기존 Shared/Artifact 반출, 설치 프로필, 창 종료, MCP 세션 교체,
Router/sandbox_run, 검증 클라이언트. Windows 파일 핸들/삭제·Named Pipe·HTTPS는 실제로
사용하며, 백신 판정과 사람의 클릭은 자동 테스트에서 대역을 사용한다.
실제 반출 검증기 자체의 경로·내용·해시·MOTW·종료 대기 검증 8개도 같은 Sandbox에서
추가 통과했다(0.09초). 합계 124개이며 전체를 한 번에 실행한 수치는 아니다.

초기 반입 묶음의 pytest 의존 모듈 `py.py` 누락을 보완했다. 다음 실행은 80개 통과/2개
실패였고, 실패는 Sandbox의 기본 pytest 임시 경로가 사용자 폴더 금지 정책에 걸린 것이었다.
별도 작업 경로를 `--basetemp`로 지정한 최종 실행에서 116개 모두 통과했다.

실제 검증 명령:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/verify_unified_export.ps1
```

이 명령은 무해한 Shared 바이너리/Output 바이너리/종료 보관 TXT를 Guest에서 만든다.
사용자가 두 수동 반출의 목록 확인과 최종 승인을 선택하고 Sandbox를 닫은 뒤 남은 파일의
목록 확인과 최종 승인을 선택한다. 실제 경로·바이트·SHA-256·MOTW·중복 여부를 확인하며
`State/unified-export-verification.json`에 단계별 결과를 기록한다. 에러가 나도 VM을 임의로
종료하거나 승인하지 않는다. 실제 검증 완료 전 해당 결과를 통과로 표시하지 않는다.

### 실제 서비스·승인 창을 통한 반출 확인 (2026-11-03 KST)

세션 `SES-c354a4dd5cd74512950cbea4436fe026`에서 설치된 SecureArtifactScanner와
실제 사용자 목록 확인/최종 보관 승인을 거쳐 아래 세 경로를 확인했다.
검증기는 `EXPORTED_ALL_THREE`, 종료 코드 0으로 완료했다.

| 경로 | 파일 | 크기 | 세션 다운로드 폴더 아래 위치 |
| --- | --- | ---: | --- |
| 실행 중 Shared 반출 | `unified-shared-22a0f64fa4.bin` | 26 B | `ART-000003/` |
| Runner Output HTTPS 수신 후 반출 | `unified-output-22a0f64fa4.bin` | 26 B | `ART-000001/` |
| Sandbox 종료 후 남은 Shared 자동 반출 | `unified-close-22a0f64fa4.txt` | 28 B | `remaining-af149a31dcc5/` |

저장 루트는 Windows 다운로드 폴더의 `SandboxShared/<세션>`이다. 세 파일 모두
예상 바이트·SHA-256·MOTW `ZoneId=3`이 일치하고, 종료 뒤 최종 파일이 각각 한 개만
남는 것을 확인했다. 기존 Shared 수동 반출 파일이 종료 처리에서 중복 저장되지 않았다.

서비스 감사 로그도 같은 세션·아래 해시에 대해 `scan_profile=shared`,
`defender_verdict=CLEAN`, `defender_exit_code=0`, `malware_detected=false`를 기록했다.
엔진은 `platform 4.18.26100.4-0 / engine 1.1.26100.4 / sig 1.463.93.0`이다.

```text
Shared: 6d20acfce788749b3e6f5b17c4eddd14952c87d5083ae3600aafa635e0678a26
Output: f789237172d68c3b3494903047e018dadc36e4e76997895c91024242c20e68f2
종료:   8ef6c230df34732a0e9e5fb003668b53229ac0f4961f0aa25f380352cb746763
```

이 scan-only 경로는 CLEAN 결과를 받은 뒤 서비스 측 임시 사본을 `abort`로 정리하고,
Host가 잠근 원본을 승인 후 공개한다. 따라서 서비스 작업의 종료 상태는
`CANCELLED/ABORTED` 후 `DISPOSED`로 남을 수 있다. 사용자 반출 취소를 뜻하는 값은
아니며, 서비스의 Defender 판정·해시와 Host의 `EXPORTED` 결과를 함께 대조해야 한다.

검증 중 긴 명령의 입력 시간 초과 및 Output 후보 누락이 발생했다. 검증기를 파일별
짧은 명령으로 변경하고 실행 창에 넣기 전 259자 상한을 확인한 뒤 세 경로가 통과했다.
이전 실패 세션의 입력을 재전송하지 않았으며 사용자가 닫은 뒤 새 검증 세션을 사용했다.
Guest 관찰 화면은 State의 `verification-<임의값>`에 보존한다. `--await-review`는
승인 창을 열기 전 목록 확인 준비를 기다리는 검증기 옵션이며 제품 승인 창을 대신
승인하지 않는다. 최종 반출 보고서는 `State/unified-export-verification.json`에 남는다.

이 실제 검증은 무해한 세 파일에 대한 정상 경로 확인이다. 악성·검사 오류·변조·취소 등
거부 경로는 위 자동 회귀 테스트 범위이며, 이번 실제 세션에서 악성 파일을 실행하거나
모든 실패 조건을 재현한 것은 아니다.
