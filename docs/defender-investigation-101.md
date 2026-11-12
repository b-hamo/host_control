# Defender 탐지 조사와 재검증 — #101 / PR #102

## 확인한 원인과 한계

2026-10-31 21:58:42 KST에 Defender 실시간 보호가 서비스 실행 파일을
`Trojan:Win32/Bearfoos.A!ml`로 분류하여 격리했다. EICAR 시험 파일 탐지와는 다른 이벤트다.
22:12에는 빌드 출력의 같은 EXE도 탐지됐다. 서비스 제거/시작 실패는 이 격리의 결과였다.

Defender 정의를 `1.463.47.0`에서 `1.463.56.0`으로 갱신한 후,
빌드 중간 폴더에 남아 있던 **동일 SHA-256의 EXE**에 MpCmdRun 사용자 지정 검사를 수행했다.
결과는 `found no threats`, 종료 코드 0, 파일 유지였고 해당 경로의 새 탐지 이벤트는 없었다.

- 비교한 SHA-256: `9642dc2243234171e9aa96275badcf0ca7f00fd5771dd1ec97a5ab00db3ba1f1`
- 엔진: `1.1.26100.4`, 플랫폼: `4.18.26100.4-0`
- 동일 바이트의 판정 변화이므로 소스 수정/파일명 변경/재패키징으로 탐지를 피한 결과가 아니다.
- 실시간 보호를 끄거나 Defender 예외/허용 목록을 추가하지 않았다. 격리 저장소에서도 복원하지 않았다.
- 이 증거는 당시 정의/판정 상태에서 발생한 오탐 가능성을 지지한다. 다만 Microsoft 내부 분류 규칙이나
  클라우드 판정 변경 내역은 공개 로그에 없으므로 **특정 코드 줄이 원인 또는 Microsoft가 오탐을 확정했다고
  주장하지 않는다**. 향후 모든 정의 버전에서 탐지되지 않음을 보장하지도 않는다.

Microsoft는 판정의 정확성을 조사한 뒤 필요하면 분석 포털로 파일을 제출하도록 안내한다.
이번에는 파일을 외부 분석 서비스에 업로드하지 않았다.
[공식 대응 절차](https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-false-positives-negatives).
PyInstaller가 사전 빌드 bootloader의 오탐 가능성을 문서화한 것은 일반적인 배경이며,
이번 탐지가 bootloader 때문이라는 직접 증거는 아니다.
[PyInstaller 문서](https://www.pyinstaller.org/en/stable/bootloader-building.html).

## 빌드 출처 확인

공식 PyPI JSON API의 배포 SHA-256으로 wheel 다운로드를 검증하고, 설치된 빌드 환경의
실제 패키지 파일을 wheel 내용과 대조했다. 메타데이터/설치 중 생성 파일은 비교에서 제외했다.
주요 세 패키지의 실행 코드·리소스 **1,877개 일치, 불일치/누락 0개**다. 이는 비교 대상의 출처
확인이며 전체 PC/모든 의존성에 대한 보안 감사나 서비스 무해성의 단독 증명이 아니다.

| 패키지 | 버전 | 일치 파일 | 공식 wheel SHA-256 |
|---|---|---:|---|
| PyInstaller | 6.22.3 | 566 | `500bd58c7bf7e584a8435adccbd763a0b918d5c12b08d74ff50fd79b2915458b` |
| pyinstaller-hooks-contrib | 2026.9 | 715 | `fb3e67dd64122561724c48ad0366ac9e8c16e638b63bf7d85de03bf3fdbf06c3` |
| pywin32 | 312 / cp313 win_amd64 | 596 | `c53e878d15a1c44788082bfe712a905433473aa38f86375b7cf8b45e3acbaaf9` |

서비스 진입점과 주요 실행 경로도 읽었다. 서비스 등록은 설치기의 SCM 설정이며,
서비스는 Named Pipe 요청을 받아 비공개 격리 저장소의 파일을 MpCmdRun으로 검사한다.
EICAR 자체 시험은 기존 정책대로 유지했다. 탐지 회피를 위한 문자열 인코딩·난독화·bootloader
교체·검사 생략은 하지 않았다.

## 수정

`installer/scanner_bundle_check.ps1`을 빌드와 설치에서 공통 호출한다.

1. Defender 정의를 갱신한다. 갱신 실패는 명령 실패로 전달한다.
2. 활성 Defender/실시간 보호 및 서명된 MpCmdRun을 확인한다. 실제 설치 경로는 Defender
   레지스트리의 InstallLocation을 사용한다. AMProductVersion에는 폴더의 `-0` 등이 빠질 수 있다.
3. EXE 실행 전 배포 묶음 전체를 검사한다. 기존 서비스를 중지/교체하기 전에도 다시 검사한다.
4. 종료 코드 외에 새 탐지 이벤트와 검사 전후 전체 파일 SHA-256/목록을 비교한다.
   종료 코드가 0이어도 탐지/격리/변경이 있으면 실패한다. 링크가 있는 묶음은 거부한다.
5. 빌드 기록에 검사 시각·정의·엔진·플랫폼·EXE 해시를 남긴다. 이후의 정상 파일/EICAR,
   계정/ACL/실제 반출 검증은 계속 필요하다.

검사는 그 시점의 판정이며 이후 비동기 탐지를 완전히 예방하지 않는다. 이후 탐지나 서비스
중단 시 통합 진입점과 반출 검사가 실패하여 공개를 차단하는 기존 동작을 유지한다.

## 검증

- 사용자 승인 범위의 Host 회귀 테스트 **39 passed**. 추가 5개는 AV/SCM 대역을 사용하여
  정상, 탐지, 검사 실패, 실시간 보호 꺼짐, 종료 코드 0 이후 파일 격리를 확인한다.
- 실제 전체 설치에서 새 환경에 로컬 Manager 설치 및 Runner 빌드 성공.
- 새 Scanner 78개 배포 파일의 Defender 검사 통과(정의 `1.463.56.0`).
- 새 EXE SHA-256: `97fd7ff842e0362e79891ba7813b13e7a3cd8593e818be8293563e6482cc1a3c`.
- 전용 서비스 계정·ACL·HEALTH_CHECK·정상 파일 CLEAN·EICAR MALWARE_DETECTED·격리 저장소
  정리 0개까지 실제 installer/verify.ps1 통과. 실제 연결/반출 결과는 아래와 같다.
- 설치의 실제 UAC 단계에서 Manager 방화벽 4개 규칙과 SYSTEM 재연결 작업을 적용했다.
  일반 사용자 preflight 및 `SOLUTION_INSTALLED`, Codex 백업/등록을 확인했다.
- 기존 세션 종료 뒤 새 Python 환경의 MCP 클라이언트로 Manager/Runner가 READY에 도달했다.
  검증 세션은 `SES-a452da97fdd543e4b6f3f115271f9f24`다.
- 검증 중 최소화된 창은 종료로 간주하지 않는 것을 확인했다. 최신 Windows 프로세스명
  `WindowsSandboxRemoteSession` 및 UI 연결이 끊긴 VM의 `vmmemWindowsSandbox`도 설치
  사전 점검에 추가했다. 해당 두 경우를 대역 회귀 테스트로 확인했다.
## 실제 보관 반출 결과

2026-10-31 22:33 KST, **최종 다운로드 반출 성공**.

- 세션: `SES-a452da97fdd543e4b6f3f115271f9f24`
- 22:33:10 Host가 사용자의 창 종료를 감지, 22:33:11 Manager가 `wsb list`로 VM 종료 확인 및 정리.
- 22:33:17 실제 승인 창의 `keep` 선택과 `SHARED ... at session end: EXPORTED` 기록.
- 파일: 다운로드 Known Folder의 `SandboxShared/SES-a452da97fdd543e4b6f3f115271f9f24/solution-verify-12a1bb10a301.txt`
- 크기: **69바이트**. Guest에서 생성한 내용 및 Host 미러에서 기록한 바이트와 일치.
- SHA-256: `3e78cb6131f72aaa7854be84ca18bfbb34657fe38590454d895b27f6245f7d2e`
- `Zone.Identifier`: `[ZoneTransfer]`, **ZoneId=3**.
- 검증 프로그램 종료 코드 0, `State/session-result.json`의 상태 **EXPORTED**.
- 반출 후에도 SecureArtifactScanner 서비스 Running, 이번 재설치 이후 Bearfoos 추가 탐지 없음.

사용자가 종료·보관을 선택했다. 자동 승인/직접 다운로드 파일 생성/Host 파일 복사로 대신하지 않았다.
검증 클라이언트가 새 MCP Host를 실행해 실제 세 구성요소를 검증한 것이며, 현재 대화의 기존
SCRP 도구 연결이 새 프로필로 교체됐음을 의미하지는 않는다. Codex 등록은 완료했고 기존
연결은 별도 재연결이 필요하다. 새 PC에서의 설치와 모든 Dev/Deploy 갱신 조합은 이번 PC의
실제 반출 성공과 구분하여 미검증 범위로 남긴다.
서비스 감사 기록도 파일 해시와 대조했다. Job `job-2b5c5a6e7996372ec0008a523a2847f1`의
`scan_profile=shared`, `defender_verdict=CLEAN`, `defender_exit_code=0`, 크기 69와 위 SHA-256이
일치하며 격리 사본은 DISPOSED다. 서비스의 `CANCELLED/ABORTED`는 scan-only Shared 검사 후
서비스 사본 정리이며, 최종 사용자 파일 공개는 Host의 EXPORTED 기록으로 확인한다.
검사 시각은 22:33:11.784–22:33:13.857 KST로 VM 종료 확인 이후, 22:33:17 보관·공개 이전이다.