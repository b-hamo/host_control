# SecureArtifactScanner — 반출 후보 파일 검사 Windows 서비스

Windows Sandbox에서 나온 반출 후보 파일을 Host에서 **받고 → 격리하고 → Microsoft Defender로 검사하고 → (승인 시) 공개하고 → 폐기**하는 독립 Windows 서비스.
`host_control`(Host)과는 **별도 프로세스**이고, Named Pipe로만 대화한다. Host 프로세스의 메모리나 전역 상태를 쓰지 않는다.

이번 단계의 범위: 서비스 단독 동작(설치·검사·격리·폐기·복구·패키징). `host/artifacts.py`·`host/upload_server.py`와의 연결은 후속 작업(§15 API 계약).

## 1. 구조

```
 Host (host_control, 사용자 계정)                   SecureArtifactScanner.exe (NT SERVICE\SecureArtifactScanner)
 ─────────────────────────────────                  ──────────────────────────────────────────────────────────────
  (후속) ArtifactBroker ──Named Pipe──▶ ipc_server.py      요청 검증(크기·필드·식별자) → 명령 분배
         \\.\pipe\SecureArtifactScanner                     │
                    (ACL: SYSTEM·Admins·서비스·Host 사용자)  ▼
                                                    scan_job_manager.py   Job 상태 전이, 중복·세대·만료, 취소
                                                     │        │        │
                                     quarantine_manager.py  defender_scanner.py  artifact_publisher.py
                                     작업별 격리 폴더·잠금  MpCmdRun.exe 실행·판정   승인 확인·Export Root 공개
                                                     │
                                     recovery_manager.py  시작 시 이전 실행의 잔여물 폐기(재개 없음)
                                     runtime.py / service.py  조립, pywin32 서비스, 명령줄
```

| 파일 | 하는 일 |
|---|---|
| `service.py` | pywin32 `ServiceFramework`. SCM 시작/중지/종료(Shutdown) 처리, 명령줄(`version`·`debug`·`client`) |
| `runtime.py` | 구성 요소 조립·시작·중지, 로깅, 자기 토큰 정보(`HEALTH_CHECK`) |
| `ipc_server.py` | Named Pipe 서버(overlapped I/O, 인스턴스 4개), 요청 검증·분배(`RequestHandler`) |
| `pipe_io.py` | 길이 접두 프레임(4바이트 LE + UTF-8 JSON), 시간 제한·중지 이벤트가 있는 읽기/쓰기 |
| `ipc_client.py` | 테스트용 클라이언트(후속 Host 연동에서도 같은 호출 사용) |
| `client_checks.py` | `SecureArtifactScanner.exe client health/roundtrip` (verify.ps1이 사용) |
| `scan_job_manager.py` | Job 상태 관리·규칙(§9) |
| `quarantine_manager.py` | 작업별 격리 폴더, 청크 쓰기, 크기·SHA-256, 잠금, 삭제·재시도 |
| `winfile.py` | pywin32 파일 핸들 도구(CREATE_NEW, 공유 모드, 파일 ID·최종 경로, reparse 검사) |
| `defender_scanner.py` | MpCmdRun 위치 검증, Defender 상태, 실행·타임아웃, 탐지 이벤트, EICAR 자체 시험, 판정 |
| `artifact_publisher.py` | 승인 확인, Export Root로 검증 후 공개 |
| `recovery_manager.py` | 시작 시 잔여 Job·부분 공개 파일 폐기, 비정상 종료 감지 |
| `models.py`, `config.py` | 상태·판정·식별자 규칙, 설정 파일(`config.json`) |

## 2. Python + pywin32를 쓴 이유

- Host가 Python 3.13이라 검증 로직·테스트 구조를 그대로 재사용할 수 있다. 형식 정책은 `host/artifact_scan.py`의 `check_format`(UTF-8 `.txt`)을 **그대로 import**한다(표준 라이브러리만 쓰는 함수라 서비스 번들에 Host 나머지는 들어가지 않는다).
- pywin32가 서비스(SCM), Named Pipe, ACL·토큰, 이벤트 로그, Job Object, 파일 핸들 API를 모두 제공해 `ctypes`가 필요 없었다(새 언어 추가 없음).
- 보안 경계는 언어가 아니라 **프로세스·계정**으로 나눈다: 서비스는 별도 프로세스, 별도 가상 계정.

## 3. 설치·실행 구조

| 위치 | 내용 | 권한(ACL, 상속 차단) |
|---|---|---|
| `C:\Program Files\SecureRuntime\ScannerService\` | `SecureArtifactScanner.exe` + `_internal\` (PyInstaller onedir) | SYSTEM·Administrators 모든 권한, 서비스·Users 읽기/실행만 |
| `C:\ProgramData\SecureRuntime\` | 데이터 루트 | SYSTEM·Administrators, 서비스는 이 폴더만 읽기 |
| `…\SecureRuntime\ScannerService\config.json` | 설정 | 관리자만 쓰기, 서비스 읽기 |
| `…\ScannerService\logs\` | `scanner.log`(5 MB × 5 순환) | SYSTEM·Administrators·서비스(수정). **Users 접근 없음** |
| `…\ScannerService\work\` | MpCmdRun TEMP, 실행 표시 파일 | SYSTEM·Administrators·서비스(수정) |
| `C:\ProgramData\SecureRuntime\Quarantine\` | 작업별 격리 폴더 | SYSTEM·Administrators·서비스(수정). Users 접근 없음, 색인 제외 |

SCM 등록(설치 스크립트가 함): 시작 유형 자동, 계정 `NT SERVICE\SecureArtifactScanner`(암호 없음), SID 유형 `unrestricted`, 필요 권한 `SeChangeNotifyPrivilege/SeImpersonatePrivilege`만(그 밖의 서비스 기본 권한은 토큰에서 제거), 실패 시 5초/30초/120초 후 재시작(`failureflag 1`).

서비스 상태 보고: `START_PENDING`(대기 힌트 60초) → 런타임 시작·파이프 대기 시작 → `RUNNING` → 중지 요청 시 `STOP_PENDING`. `SvcStop`은 신호만 보내고 즉시 반환, 실제 정리는 서비스 스레드가 한다(새 작업 거부 → 진행 중 검사 취소, 최대 20초 대기 → 파이프 닫기 → 실행 표시 "정상 중지"). 시작 실패는 로그와 Windows 이벤트 로그(Application, 원본 `SecureArtifactScanner`)에 남고 SCM에는 오류로 보고된다.

## 4. 가상 서비스 계정의 권한 모델

- `NT SERVICE\SecureArtifactScanner`는 서비스 등록 시 생기는 가상 계정(SID `S-1-5-80-…`)이다. 관리자 그룹이 아니고 LocalSystem도 아니다. 시작 때 자기 토큰을 읽어 관리자/LocalSystem이면 경고하고, `HEALTH_CHECK`가 토큰 정보(계정·SID·관리자 여부·무결성·권한 목록)를 돌려준다.
- 이 계정이 쓸 수 있는 곳: 격리 저장소, logs, work, (설정했다면) Export Root. 읽을 수 있는 곳: 설치 폴더, config.json, Defender 상태 레지스트리, Defender Operational 이벤트 로그(채널 ACL이 서비스 로그온(SU)에 읽기를 준다 — 실측).
- 실측(이 PC, 사용자 권한): MpCmdRun 위치·서명 버전 레지스트리 읽기 가능, **제외(Exclusions) 레지스트리는 거부** → 제외 여부는 EICAR 자체 시험으로 확인(§7).
- 서비스 SID 설정(`sidtype unrestricted`)과 가상 계정 설정(`obj= "NT SERVICE\…"`)은 다르다. 앞의 것은 토큰에 서비스 SID를 넣는 것이고, 뒤의 것이 실제 실행 계정이다. 그래서 검증은 `sc qc`의 `SERVICE_START_NAME`, `Win32_Service.StartName`, 실행 중 프로세스의 사용자(`Get-Process -IncludeUserName`), 서비스가 스스로 읽은 토큰 네 가지를 모두 본다(`verify.ps1`).

> **ACL과 가상 서비스 계정은 샌드박스가 아니다.** 접근 권한을 좁히는 수단일 뿐이다. 서비스 프로세스에서 코드 실행 취약점이 생기면 그 계정이 가진 권한(격리 저장소·Export Root 쓰기, 일반 사용자 수준 읽기 등)은 그대로 쓰인다. 그래서 검사 대상 파일은 **절대 실행·열기·미리보기 하지 않고**(이름은 항상 `payload.part`, 색인 제외), 서비스는 최소 권한으로만 실행한다.

## 5. 격리 저장소와 ACL

```
C:\ProgramData\SecureRuntime\Quarantine\
└── session-SES-001\                    검증된 session_id ([A-Za-z0-9][A-Za-z0-9_-]{0,63})
    ├── job-a8f3…(32 hex)\              서비스가 만든 랜덤 ID, 매번 새로 만들고 재사용하지 않음
    │   ├── payload.part                받은 바이트 (Guest의 파일 이름·경로는 Host 경로에 절대 안 씀)
    │   └── job.json                    상태 기록 (복구 로그용, 내용으로 무엇도 재개하지 않음)
    └── job-5c21…\
```

- 폴더: 루트·세션·작업 폴더마다 reparse point(정션·심볼릭 링크) 거부 + 핸들의 최종 경로가 예상 경로와 같은지 확인. 루트 자체가 링크를 거쳐 닿으면 서비스가 시작하지 않는다.
- 파일: `CREATE_NEW`(이미 있는 파일·링크는 열지 않음) + `FILE_FLAG_OPEN_REPARSE_POINT`, 업로드 중에는 공유 없음. 업로드 완료 후에는 **쓰기 공유 없는 읽기 잠금**(READ + DELETE 공유: Defender의 격리·삭제는 허용)을 Job이 끝날 때까지 유지 → 검사 중·검사 후 파일 교체·변경 불가. 파일 ID(볼륨 일련번호+파일 인덱스)·링크 수 1을 확인한다.
- 크기·해시: `BEGIN_UPLOAD`에 선언한 크기·SHA-256과 받은 바이트가 정확히 같아야 한다. 청크는 순서대로만(offset = 지금까지 받은 바이트), 선언 크기 초과 불가. 검사 전·검사 후·공개 직전에 잠금 핸들로 다시 해시한다.
- 한도(설정 가능): 파일 1 MiB(Host 데모 정책과 같음, 최대 50 MiB), 청크 256 KiB, 동시 Job 8개, 동시 검사 2개, 저장소 합계 200 MiB, 디스크 여유 512 MiB 미만이면 거부(`DISK_FULL`).
- 설치 스크립트의 ACL 적용: 폴더마다 **소유자 + 상속 차단 + 모든 허용 규칙을 한 번에** 쓴다(.NET `DirectorySecurity`, `Set-Acl` 1회). 부모 → 자식 순서. 예전 테스트의 "`icacls /inheritance:r` 먼저, 권한 부여 나중" 순서에서 생긴 접근 상실 문제를 원천적으로 없앴다. ProgramData는 일반 사용자도 폴더를 만들 수 있으므로, 설치 전에 이미 있는 폴더가 관리자/SYSTEM 소유가 아니거나 링크면 설치를 멈춘다.

## 6. Named Pipe 인터페이스 (`scanner-ipc-v1`)

`\\.\pipe\SecureArtifactScanner`, 바이트 모드, 프레임 = 4바이트 little-endian 길이 + UTF-8 JSON. 길이는 본문을 읽기 전에 검사한다(요청 512 KiB, 응답 64 KiB). 초과 요청은 `REQUEST_TOO_LARGE` 후 연결을 끊는다. 60초 동안 요청이 없으면 연결을 닫는다.

파이프 보안:
- DACL `D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;<서비스 SID>)(A;;0x12019b;;;<Host 사용자 SID>)`: 네트워크 로그온 거부, 원격 클라이언트 거부(`PIPE_REJECT_REMOTE_CLIENTS`). 클라이언트 권한 `0x12019b`는 읽기·쓰기에서 **`FILE_CREATE_PIPE_INSTANCE`를 뺀 것**: 파이프의 GENERIC_WRITE에는 이 권한이 들어 있어, 주면 클라이언트가 같은 이름으로 서버 인스턴스를 만들어 서비스를 사칭할 수 있다.
- 첫 인스턴스는 `FILE_FLAG_FIRST_PIPE_INSTANCE`: 누가 이름을 먼저 차지했으면 서비스가 시작을 거부한다.
- 첫 요청을 읽은 뒤 `ImpersonateNamedPipeClient`로 클라이언트 SID를 확인해 기록(신원 불명이면 거부). 클라이언트는 `SECURITY_IDENTIFICATION`으로 연결하므로 서비스가 클라이언트로 **행동**할 수는 없다. 테스트 클라이언트는 파이프 서버 PID가 SCM이 알려 준 서비스 PID인지 확인한다.

요청 형식:

```json
{"protocol_version": "scanner-ipc-v1", "request_id": "r-1", "command": "BEGIN_UPLOAD",
 "session_id": "SES-001", "runtime_id": "RT-SBX-001", "generation": 1, "artifact_id": "ART-000001",
 "job_id": "job-…", "payload": {}}
```
응답: `{"protocol_version", "request_id", "status": "OK", "result": {...}}` 또는 `{"status": "ERROR", "error": {"code", "message", "retryable"}}`. 모르는 필드는 최상위·payload 모두 거부.

| 명령 | 필요한 값 | payload | 결과 |
|---|---|---|---|
| `HEALTH_CHECK` | – | `{"selftest": true}`(선택: EICAR 자체 시험 즉시 실행) | 버전, PID, 토큰, Defender 상태, 공개 설정, Job 수, 복구 결과, 한도 |
| `BEGIN_UPLOAD` | 4개 식별자 (job_id 금지) | `file_name`(표시·형식 검사용), `size`, `sha256`(선택: 모르면 생략) | Job (job_id는 서비스가 발급) |
| `WRITE_CHUNK` | 식별자 + job_id | `offset`, `data`(base64, ≤256 KiB) | `received_bytes` |
| `COMPLETE_UPLOAD` | 식별자 + job_id | `sha256`(BEGIN에서 생략했으면 필수, 둘 다 주면 같아야 함) | Job (`RECEIVED`) |
| `SCAN` | 식별자 + job_id | – | Job (`SCANNING`, 백그라운드 검사. `GET_STATUS`로 확인) |
| `GET_STATUS` | 식별자 + job_id | – | Job |
| `PUBLISH` | 식별자 + job_id | `approval` (§12) | Job (`outcome: EXPORTED`, `export_path`) |
| `ABORT` | 식별자 + job_id, 또는 `session_id`만 | `scope: "job"\|"session"`, `reason` | Job, 또는 `{"cancelled_jobs": n}` |

**없는 기능**: 임의 경로 검사, 프로세스·명령 실행, 임의 경로 쓰기. 서비스는 자기가 만든 Job과 파일만 다룬다. Job의 4개 식별자(session·runtime·generation·artifact) 중 하나라도 다르면 Job이 없는 것처럼 `JOB_NOT_FOUND`.

## 7. Defender 검사 절차

검사 전:
1. **MpCmdRun 위치**: Defender 레지스트리 `InstallLocation`의 `MpCmdRun.exe`(없으면 `Program Files\Windows Defender\`). Defender 폴더 안이어야 하고, 링크가 아니어야 하며, 파일과 상위 폴더를 SYSTEM·Administrators·TrustedInstaller 말고는 쓸 수 없어야 한다. 요청에서 받은 경로는 절대 실행하지 않는다.
2. **Defender 상태**: WinDefend 서비스 실행 중(SCM), 수동(passive) 모드 아님, 정책으로 꺼지지 않음, 보안 인텔리전스 버전 확인.
3. **제외 여부**: 관리자가 아니면 제외 목록을 읽을 수 없다(실측: 레지스트리 접근 거부). 대신 첫 검사 전과 이후 6시간마다 격리 저장소 안(`_selftest-…\payload.part`, 실제 파일과 같은 이름)에 EICAR 시험 문자열을 쓰고 검사한다. Defender가 잡지 못하면 그 위치가 제외됐거나 Defender가 고장난 것으로 보고 **모든 검사를 `SCANNER_UNAVAILABLE`로 차단**(실패는 5분간 기억). 이 시험은 Windows 보안 알림(위협 발견)을 띄운다 — 정상이다.
4. 형식 정책(UTF-8 `.txt`)을 먼저 적용: 통과하지 못하면 Defender에 넘기지도 않고 `BLOCKED`.

실행: `MpCmdRun.exe -Scan -ScanType 3 -File <격리 파일>` — `shell=False`, 인수 목록, 전체 경로, 최소 환경 변수(TEMP = work), 창 없음. Job Object(`KILL_ON_JOB_CLOSE`)에 넣어 시간 초과(기본 120초)·취소 시 자식까지 종료. 출력·오류 수집(각 8 KiB까지), 실행 시간 측정. `-DisableRemediation`은 쓰지 않는다(탐지 시 Defender의 조치 유지).

## 8. 검사 결과 판정 기준

실측(이 PC, 플랫폼 4.18.26100.4, 사용자 권한):

| 대상 | 종료 코드 | 출력 | 파일 | 이벤트 |
|---|---|---|---|---|
| 정상 TXT | 0 | `… found no threats.` | 남음 | 없음 |
| EICAR | **0** | `… found 1 threats. Cleaning started… Cleaning finished.` | **삭제됨** | 1116 (`Virus:DOS/EICAR_Test_File`) |
| 없는 파일 | 2 | `[Failed][0x80070002] <한국어 메시지>` | – | – |
| 업로드 직후 EICAR | – | – | 실시간 보호가 열기 거부(winerror 225) | – |

**종료 코드 0은 "깨끗함"이 아니다.** 판정:

| 판정 | 조건 | Job |
|---|---|---|
| `DETECTED` | 탐지 이벤트(1006/1007/1008/1015/1116/1117/1118/1119 중 경로가 이 파일인 것) **또는** 출력의 위협 수 ≥ 1 **또는** 종료 0인데 파일이 사라짐 **또는** 업로드 직후 실시간 보호가 거부(225/226) | `BLOCKED` `MALWARE_DETECTED` |
| `ERROR` | 종료 코드 ≠ 0 (탐지 신호 없음), 실행 실패 | `BLOCKED` `SCAN_ERROR` |
| `TIMEOUT` | 시간 초과 (프로세스 트리 종료) | `BLOCKED` `SCAN_TIMEOUT` |
| `UNAVAILABLE` | Defender 꺼짐·수동 모드·정책 비활성, MpCmdRun 신뢰 불가, 자체 시험 실패 | `BLOCKED` `SCANNER_UNAVAILABLE` |
| `UNVERIFIABLE` | 실행은 됐지만 탐지 로그를 읽을 수 없음 | `BLOCKED` `SCAN_UNVERIFIABLE` |
| `CLEAN` | 종료 0, 출력에 위협 수 없음, 탐지 이벤트 없음(검사 후 2초 대기 뒤 조회), 파일이 그대로 있음 + 잠금 핸들로 재해시 일치 | `SCANNED` |

출력 문자열(영어·한국어)은 **탐지 신호로만** 쓰고, 문자열 하나로 "안전"을 정하지 않는다(현지화된 출력에 "found no threats"가 없어도 다른 조건이 모두 맞으면 CLEAN, 있어도 이벤트가 있으면 DETECTED). 확실히 판단할 수 없으면 반출하지 않는다.

## 9. 검사 작업의 상태 전이

```
CREATED → RECEIVING → RECEIVED → SCANNING → SCANNED → PUBLISHING → EXPORTED → DISPOSED
   └──────────┴───────────┴──────────┴──────────┴───────────┴─→ BLOCKED / FAILED / CANCELLED → DISPOSED
```
- `BLOCKED`: 판정이 반출을 막음(악성·검사 오류·시간 초과·검사 불가·형식·내용 변경). `FAILED`: 작업 자체가 깨짐(해시·크기 불일치, 공개 실패·충돌). `CANCELLED`: `ABORT`, 세션 종료, 새 세대, 만료, 서비스 중지.
- `DISPOSED`는 격리 파일 삭제 완료를 뜻하고, 어떻게 끝났는지는 `outcome`에 남는다(예: `state: DISPOSED, outcome: EXPORTED`).
- 규칙: 표에 없는 전이 거부(`INVALID_STATE`) · 같은 (session, runtime, generation, artifact)의 진행 중 Job은 하나(`DUPLICATE_JOB`) · `SCAN`·`PUBLISH`는 한 번씩(`ALREADY_PUBLISHED`) · 새 generation이 오면 이전 generation의 Job 취소(`RUNTIME_REPLACED`), 이전 generation 요청은 `STALE_GENERATION` · 검사·공개 중 취소는 그 스레드가 끝내며 실제 일어난 상태로 끝난다 · 업로드 120초 무활동 `UPLOAD_TIMEOUT`, Job 수명 15분 `JOB_EXPIRED`.
- 검사 서비스는 사용자 승인 여부를 스스로 판단하지 않는다. Job 상태와 Host Artifact Broker의 상태(`CANDIDATE → … → EXPORTED`)는 별개다.

## 10. 임시 저장소 폐기

Job이 끝나면(`EXPORTED`·`BLOCKED`·`FAILED`·`CANCELLED`) 잠금을 닫고 작업 폴더를 지운다. 지울 때 링크는 따라가지 않고 링크 자체만 지운다. 실패하면 `cleanup_error`로 기록하고 30초마다 도는 정리(sweep)가 다시 시도한다. 정리는 살아 있는 Job이 없는 작업 폴더(이전 실행 잔여물 포함)와 오래된 자체 시험 폴더도 지운다. 지우지 못한 폴더는 Users 접근이 없는 격리 저장소 안에 그대로 남아 공개되지 않는다. 끝난 Job 기록은 5분 뒤 메모리에서도 지운다.

## 11. 장애 복구

| 상황 | 처리 |
|---|---|
| 서비스 강제 종료·Windows 재부팅·충돌 | 다음 시작 때 실행 표시(`work\service-run.json`)로 비정상 종료 감지·기록. 남은 작업 폴더는 `job.json`으로 로그만 남기고 **전부 삭제**. 검사 통과·공개 상태로 재개하지 않음. SCM이 5초 뒤 재시작 |
| 공개 중 중단 | Export Root의 `.job-<id>.partial` 삭제 (최종 이름 파일은 검증 후 rename으로만 생기므로 반쯤 쓴 최종 파일은 없음) |
| Defender 오류·타임아웃 | `BLOCKED`, 프로세스 트리 종료 |
| IPC 연결 끊김·Host Control 종료 | Job은 연결과 무관하게 남고, 업로드 무활동·수명 만료로 취소·삭제. Host가 세션 종료 시 `ABORT scope=session` |
| 삭제 실패 | `cleanup_error` 기록, sweep마다 재시도, 그동안 격리 저장소 밖으로 나가지 않음 |
| 중복 Job | `DUPLICATE_JOB` |
| 디스크 공간 부족 | `DISK_FULL`·`STORAGE_FULL`(재시도 가능), 쓰기 오류는 `FAILED STORAGE_ERROR` |
| 서비스 중지 중 요청 | `SERVICE_STOPPING` |

## 12. 공개(Publish)와 승인

`<export_root>\<session_id>\<artifact_id>\<안전한 파일 이름>` (`host/artifacts.py`와 같은 이름 규칙: Guest 경로에서 파일 이름만, 금지 문자·예약 이름 처리).

조건: 업로드 완료·크기·SHA-256 일치 → Defender `CLEAN` → 형식 정책 통과 → Job `SCANNED`·미공개 → 격리 파일이 그대로 → **승인이 이 Job·artifact·session·SHA-256을 정확히 가리킴**. 잠금 핸들에서 숨김 `.job-<id>.partial`로 복사 → 그 파일을 다시 잠그고 해시 → 최종 이름으로 rename(덮어쓰기 없음, 있으면 `PUBLISH_CONFLICT`) → 핸들의 최종 경로가 Export Root 안인지 확인. 이 모든 단계 중 하나라도 실패하면 최종 이름에는 아무것도 생기지 않는다. 검사 전 파일을 Export Root에 미리 두는 일은 없다.

승인(이번 단계, 테스트용 인터페이스): `approval_mode: host_asserted` — Host가 "사용자가 이 바이트를 승인했다"고 알려 준다:
```json
{"approved": true, "approval_id": "APR-…", "approved_by": "<표시용>", "job_id": "job-…",
 "artifact_id": "ART-…", "session_id": "SES-…", "sha256": "<Job의 SHA-256>"}
```
파이프 ACL로 Host 사용자·관리자만 보낼 수 있고, 다른 Job이나 다른 바이트에는 쓸 수 없다. 실제 승인 권한(사용자 승인 창과의 연결, 위조 방지 서명 등)은 후속 Artifact Broker 연동에서 정한다. `export_root`가 없거나 `approval_mode: disabled`이면 `PUBLISH_DISABLED`.

## 13. 로깅과 감사

`logs\scanner.log` (UTC). Job이 끝날 때와 삭제될 때 `AUDIT {json}` 한 줄: job_id, artifact_id, session_id, runtime_id, generation, 크기, SHA-256, 검사 시작·끝 시각, Defender 판정·종료 코드·위협 이름·엔진/서명 버전, 악성 여부, 최종 상태, 오류 코드, 정리 결과. 남기지 않는 것: 파일 내용, 업로드 데이터(base64), 토큰·비밀(이 인터페이스엔 없음), 환경 변수, 사용자 경로(공개 경로는 Export Root 아래 상대 경로만).

## 14. 패키징·설치·제거

```powershell
# 빌드 (일반 권한). build\scanner\venv에 고정 버전(installer\requirements-build.txt)으로 PyInstaller --onedir
powershell -ExecutionPolicy Bypass -File installer\build.ps1
# → dist\SecureArtifactScanner\SecureArtifactScanner.exe (+ _internal\, Python 설치 불필요)

# 설치 (관리자 PowerShell). 반복 실행 가능. -ExportRoot를 주면 PUBLISH 활성화
powershell -ExecutionPolicy Bypass -File installer\install.ps1 -ExportRoot "$env:USERPROFILE\SecureExports"
#   관리자 계정이 Host 사용자와 다르면 -ClientUser "PC\host-user"

# 검증 (관리자). 보고서: build\verify-report.txt
powershell -ExecutionPolicy Bypass -File installer\verify.ps1 -Publish -Restart -CrashTest

# 제거 (관리자). Export Root의 결과물은 지우지 않음. -KeepLogs로 로그 보존
powershell -ExecutionPolicy Bypass -File installer\uninstall.ps1
```

- `--onefile`을 쓰지 않는 이유: 실행할 때마다 TEMP에 런타임을 풀어 거기서 코드를 읽는다. `--onedir`은 관리자만 쓸 수 있는 설치 폴더에서만 읽는다. frozen 실행 시 `sys.path`를 번들 폴더로 제한하고, `HEALTH_CHECK`가 `sys_path_ok`로 보고한다.
- 개발 중 콘솔 실행: `python scanner_service\service.py debug --data-root <임시 폴더> --pipe \\.\pipe\sas-dev` (현재 사용자에게 파이프 허용, 폴더 자동 생성).

의존성: 서비스 실행 `pywin32==312` (Windows 전용, `requirements.txt`에 플랫폼 표시), 빌드 `pyinstaller==6.22.3`·`pyinstaller-hooks-contrib==2026.9` (`installer/requirements-build.txt`). Host 공통 의존성(jsonschema·websockets·cryptography·sandbox_manager)은 서비스에 필요 없다.

## 15. Artifact Broker 연동 (`--artifact-scanner defender-service`)

구현: `host/scanner_client.py`(비동기 파이프 클라이언트), `host/artifacts.py`(수신·공개), `host/artifact_scan.py`(`DefenderServiceScanner`), `host/mcp_server.py`(옵션·상태 확인).

1. **상태 확인**: Host 시작 때와 15초마다 `HEALTH_CHECK`. 서비스 계정이 정확히 `NT SERVICE\SecureArtifactScanner`이고 관리자·LocalSystem이 아님, 중지 중 아님, Defender 사용 가능, 공개 가능, 서비스의 `export_root`가 Host의 `--export-dir`과 같아야 "사용 가능". 아니면 `artifact_export`가 **승인 창을 띄우기 전에** `SCANNER_UNAVAILABLE`(재시도 가능)로 거부된다. 시작 때 같은 session_id로 남은 이전 Job은 `ABORT scope=session`.
2. **수신**: 기존 HTTPS 검사(인증·token·기한·크기·Content-Type, 1회용 grant)는 그대로. 본문은 Host 파일(`.part`) 없이 64 KiB씩 한 파이프 연결로 `BEGIN_UPLOAD`(크기, `file_name` = 후보 `relative_path`) → `WRITE_CHUNK` → `COMPLETE_UPLOAD`(`sha256` = Host가 흘려보내며 계산한 해시. 서비스가 자기 계산과 비교). 응답의 크기·해시가 Host 값과 다르면 실패. 성공해야 기존과 같은 빈 201. grant에 `scanner_job_id`가 붙는다.
   - 서비스 없음·바쁨(`SCANNER_UNAVAILABLE`, `STORAGE_FULL` 등) → 503, `FILE_TOO_LARGE` → 413, 그 밖 → 500. 실패하면 Job은 `ABORT`.
   - 업로드 완료 순간 실시간 보호가 거부(`MALWARE_DETECTED`·`CONTENT_REMOVED`·`CONTENT_CHANGED`) → 수신은 201, 검사 결과가 그 코드로 `BLOCKED`(재시도 불가).
3. **결과 대조**: `ARTIFACT_RESULT`와 수신 기록 대조는 기존 그대로. 어긋나면 Job `ABORT`.
4. **검사**: `SCAN` → `GET_STATUS` 폴링(0.25초, Host 제한 300초 — 서비스의 MpCmdRun 120초 + 자체 시험). `SCANNED`이고 크기·SHA-256이 Host 기록과 같고 판정 `CLEAN`일 때만 통과. `BLOCKED`면 서비스의 `error.code` 그대로(`MALWARE_DETECTED`, `SCAN_ERROR`, `SCAN_TIMEOUT`, `SCANNER_UNAVAILABLE`, `SCAN_UNVERIFIABLE`, `FORMAT_NOT_ALLOWED`, `NOT_UTF8`, `CONTENT_CHANGED`), 그 밖(취소·실패·연결 끊김)은 `SCAN_ERROR`/`SCANNER_UNAVAILABLE`. Host 시간 초과면 `SCAN_TIMEOUT` + `ABORT`.
5. **공개**: 사용자 승인은 기존대로 grant 발급 전에 받았다. 그 뒤 `PUBLISH`(승인 객체 = job·artifact·session·SHA-256). 서비스가 `<export_dir>\<session>\<artifact>\<안전한 이름>`에 쓰면 Host가 다시 확인: 예상 경로와 같음, 링크 아님, 잠근 채 해시·크기가 받은 바이트와 같음 → 그때만 `EXPORTED`. 확인 실패나 공개 중 취소면 그 파일(같은 바이트일 때만)을 지우고 `FAILED PUBLISH_FAILED`. 같은 Job 재공개는 서비스가 `ALREADY_PUBLISHED`로 거부.
6. **취소**: 세션 종료·세대 변경·Telemetry 끊김·Control 끊김 → 기존 `cancel_identity` / `_end` → grant 취소 → Job `ABORT`(백그라운드, 실패해도 서비스의 만료가 정리).
7. 모든 파이프 호출은 `asyncio.to_thread`로 실행해 Host 이벤트 루프를 막지 않는다. 연결 대기는 2초(서비스 없음은 빨리 실패), 요청 I/O는 30초. 응답의 `request_id`와 job·session·runtime·generation·artifact를 모두 확인한다. 실제 서비스면 파이프 서버 PID가 SCM의 서비스 PID와 같아야 한다.
8. 기존 `none`·`amsi` 모드는 바뀌지 않았다(파일 경로·검사·공개 모두 기존 코드).

실행 예: 서비스를 Host의 export 폴더로 설치하고 같은 폴더를 준다.
```powershell
powershell -ExecutionPolicy Bypass -File installer\install.ps1 -ExportRoot C:\Users\<user>\...\host_control\host\.exports
python host\mcp_server.py ... --artifact-export --artifact-scanner defender-service
```

## 16. 보안상 한계와 미검증 사항

- ACL·가상 계정은 샌드박스가 아니다(§4). 서비스 프로세스가 공격당하면 그 계정 권한은 그대로 쓰인다.
- 승인은 Host 주장 방식(§12): 파이프에 접근할 수 있는 Host 사용자 권한의 프로그램이면 승인을 만들 수 있다. Broker 연동 후에도 승인 창은 Host 안에 있으므로 서비스가 따로 확인할 방법은 없다(같은 사용자 권한 경계).
- Export Root는 사용자 폴더이므로 같은 사용자가 공개된 파일을 나중에 바꿀 수 있다(공개 시점까지만 보장).
- MpCmdRun을 강제 종료해도 Defender 엔진(MsMpEng, SYSTEM)의 진행 중 검사는 멈추지 않을 수 있다(판정은 이미 `TIMEOUT`으로 차단).
- 탐지 이벤트는 "검사 시작 2초 전 이후 + 경로 일치"로 연결한다. 같은 경로를 동시에 다른 경로로 검사하는 일은 없지만(작업마다 랜덤 폴더), 이벤트 지연이 2초를 넘으면 그 이벤트는 못 볼 수 있다. 그 경우에도 Defender가 파일을 삭제·격리했다면 파일 사라짐으로 잡힌다.
- 자체 시험은 Defender의 위협 알림을 6시간마다(그리고 재시작 후 첫 검사 때) 만든다.
- 다른 백신이 주 백신이라 Defender가 수동 모드이면 모든 검사가 차단된다(의도된 동작).
- 미검증: Python이 없는 **별도 PC**에서의 설치·실행(개발 PC에서는 번들 안 경로만 쓰는 것을 확인), Defender가 꺼졌거나 다른 백신이 주 백신인 PC(단위 테스트로만), 실제 Windows 재부팅(프로세스 강제 종료로 대신 확인), 디스크가 실제로 가득 찬 상황(한도 설정으로만).

## 17. 실제 Windows 검증 결과 (2026-10-30, Windows 11 Pro 10.0.26200, Defender 4.18.26100.4 / sig 1.463.31.0)

`installer\install.ps1 -ExportRoot build\verify-exports` → `installer\verify.ps1 -Publish -Restart -CrashTest` (관리자):

- 계정: `sc qc` `SERVICE_START_NAME : NT SERVICE\SecureArtifactScanner`, `Win32_Service.StartName`·실행 프로세스 사용자 동일, SID 유형 `UNRESTRICTED`, 필요 권한 2개만
- 토큰(서비스가 스스로 읽음): `is_admin=False`, Administrators 그룹 없음, LocalSystem 아님, 무결성 0x3000(서비스 계정 기본값), 권한 `SeChangeNotifyPrivilege, SeImpersonatePrivilege`만
- ACL: 설치 폴더·실행 파일·config.json은 관리자만 쓰기, SecureRuntime·ScannerService·logs·work·Quarantine은 SYSTEM·Administrators·서비스만, 상속 차단
- 기능: frozen 실행(설치 폴더, `sys.path` 번들 안), 정상 TXT → CLEAN → SCANNED → DISPOSED, EICAR → `BLOCKED MALWARE_DETECTED (Virus:DOS/EICAR_Test_File)`, 공개 → `EXPORTED`, 검사 후 격리 저장소 0개
- `Restart-Service` 뒤 새 프로세스·정상 중지 기록, 프로세스 강제 종료 뒤 SCM 재시작·비정상 종료 감지
- 발견해 고친 것: 서비스 계정에서는 EICAR 파일이 Defender 삭제 대기 상태가 되어 파일 속성 조회가 `WinError 5`로 거부됨 → 처음엔 `SCAN_ERROR`(반출은 막혔지만 원인 오표시), 이제 탐지로 판정. SCM의 세 번째 실패 조치는 120초 뒤라서 `-CrashTest` 대기를 150초로 늘림

## 18. 보안 검증·통합 테스트 (작업 3, 2026-10-30, 같은 PC: Windows 11 Pro 26200, 12 논리 코어, Defender 4.18.26100.4 / sig 1.463.31.0)

### 테스트 구성

| 파일 | 무엇을 | 언제 실행 |
|---|---|---|
| `tests/test_scanner_service.py`, `test_quarantine_manager.py`, `test_scanner_recovery.py`, `test_defender_scanner.py` | 서비스 단위(상태 전이, 격리, 링크, 판정 규칙, 복구, IPC) | 항상 (Windows) |
| `tests/test_scanner_client.py` | Host 파이프 클라이언트 + 스크립트형 가짜 파이프 서버: 다른 요청의 응답, 다른 Job의 응답, 끊김, 무응답, 서비스 없음, 다른 프로세스의 파이프, 오류 코드, 이벤트 루프 비차단, 종료 전 ABORT 완료 | 항상 (Windows) |
| `tests/test_artifact_scanner_service.py` | Host ↔ 프로세스 안 서비스(가짜 Defender) 전 구간 | 항상 (Windows, 일반 사용자) |
| `tests/test_scanner_security.py` | 업로드 중단, 파이프 단절, 서비스 한도·용량, 승인 없음, 다른 세션·세대, 공개 중 취소(늦은 성공 응답), 공개 실패, 공개 파일 ACL·해시, 링크·정션, Host 종료 | 항상 (Windows, 일반 사용자; 심볼릭 링크 1건은 권한 필요) |
| `tests/test_scanner_integration.py` | 실제 MpCmdRun / 설치된 서비스(일반 사용자) / 서비스 중지·강제 종료·제거 후 재설치(관리자) | `SCANNER_DEFENDER_TESTS=1` / `SCANNER_SERVICE_TESTS=1` / `SCANNER_SERVICE_ADMIN_TESTS=1` |
| `tests/scanner_perf.py` | 성능 측정 도구 (테스트 아님, 관리자) | 수동 |

일반 CI(비 Windows)에서는 위 파일이 전부 건너뛰어진다(`sys.platform`, pywin32). 관리자 권한으로 pytest를 돌릴 때는 `--basetemp <별도 폴더>`를 준다: 관리자가 만든 `pytest-current` 링크는 다음 일반 사용자 실행을 접근 거부로 망친다(실제로 겪음, 정리함).

### 결과

| 항목 | 결과 | 근거 |
|---|---|---|
| 가상 계정·관리자 아님 | 통과 | `sc qc`, 프로세스 사용자, 서비스 자기 토큰(`is_admin=False`, Administrators 그룹 없음, 권한 2개) |
| ACL (일반 사용자 차단) | 통과 | 일반 사용자로 격리 저장소·logs 목록, config.json 읽기, 설치 폴더 쓰기, exe 덮어쓰기, 격리 폴더 생성 → 모두 `PermissionError` |
| 서비스 계정의 정상 접근 | 통과 | 업로드·검사·삭제 후 `cleanup_error` 없음 |
| PyInstaller onedir·pywin32 DLL | 통과 | frozen, `sys.path`와 `pywintypes313.dll`·`win32api/win32file/servicemanager.pyd` 모두 설치 폴더 안 |
| 설치·제거·재설치 | 통과 | 제거 후 서비스·설치 폴더·격리 저장소 없음, Export Root의 기존 파일 유지, 재설치 후 정상 |
| 서비스 중지 시 정리 | 통과 | 받은 Job이 있는 상태에서 중지 → 격리 저장소 비움, 실행 표시 `running=false`, 프로세스·파이프 사라짐 |
| 정상 TXT 검사·반출 | 통과 | 실제 서비스 + Host: 0 바이트·1 MiB TXT `EXPORTED`, 바이트·SHA-256 일치 |
| EICAR 탐지·반출 차단 | 통과 | 아래 판정 근거 |
| 검사 실패·시간 초과 차단 | 통과 | 실제 MpCmdRun 시간 초과 → `TIMEOUT`, 프로세스 종료 확인. 없는 파일 → exit 2 `ERROR` |
| 무결성(검사 전후 SHA-256) | 통과 | 서비스가 다른 해시를 보고·검사 후 내용 변경 → `CONTENT_CHANGED`, 공개 없음 |
| 다른 세션·런타임·세대 접근 | 통과 | `JOB_NOT_FOUND`, 새 세대가 옛 Job 취소, 옛 세대 요청 `STALE_GENERATION` |
| 승인 없는 반출 | 통과 | 승인 거부 → Runner 요청·업로드·서비스 Job 모두 없음 |
| 업로드 token 만료·재사용, `ARTIFACT_RESULT` 불일치 | 통과 | 410·409, `RESULT_MISMATCH` 후 Job 폐기 |
| 공개 실패·중복 공개·늦은 성공 응답 | 통과 | `PUBLISH_FAILED` 파일 없음, `ALREADY_PUBLISHED`, 공개 중 세션 종료(서비스가 rename 전·후) → 파일 남지 않음 |
| 공개 파일 ACL | 통과 | 모두 상속 ACE, Everyone·Users·인증된 사용자·익명 쓰기 없음 |
| 서비스 강제 종료(검사 중) | 통과 | 재시작 후 `previous_run_unclean`, 남은 Job 폐기, 옛 Job `JOB_NOT_FOUND`; Host가 기다리던 반출은 `BLOCKED`, 파일 없음 |
| 파이프 단절·HTTPS 업로드 중단·Host 종료·세션 종료·Telemetry 끊김·검사 중 취소 | 통과 | 매번 `EXPORTED` 아님, 격리 저장소 비움, Host 파일 없음 |
| `none`·`amsi`·`defender-service` 회귀 | 통과 | 전체 642 통과 / 23 건너뜀(선택 실행분, 위에서 따로 통과) |

### EICAR와 판정 근거 (실측)

| 대상 | MpCmdRun 종료 코드 | 출력 | 파일 | 탐지 이벤트 | 판정 |
|---|---|---|---|---|---|
| 정상 TXT | 0 | `found no threats` | 남음 | 0건 | CLEAN |
| EICAR (사용자 계정, 직접) | **0** | `found 1 threats`, `Cleaning finished` | **삭제됨** | 1116 `Virus:DOS/EICAR_Test_File`, 경로 = 검사 파일 | DETECTED |
| 없는 파일 | 2 | `hr = 0x80070002` | – | – | ERROR |
| EICAR (서비스 계정) | – | – | 삭제 대기 / 읽기 거부(실시간 보호) | 1116 | DETECTED → `BLOCKED MALWARE_DETECTED` |

같은 시간대에 다른 경로로 조회하면 탐지 이벤트는 0건이었다(이벤트는 경로로 정확히 연결됨). 종료 코드만 보면 정상과 EICAR를 구분할 수 없다는 것을 실측으로 확인했다.

### 성능 (`tests/scanner_perf.py`, 각 3회 중앙값, 관리자 실행)

| 지표 | 값 |
|---|---|
| 서비스 시작: SCM 시작 → RUNNING / → 첫 HEALTH_CHECK | 0.43 s / 0.44 s |
| HEALTH_CHECK | 4 ms |
| EICAR 자체 시험 (시작 후 첫 검사 때, 6시간마다) | 10.9 s |
| 파이프 업로드 1 KiB / 64 KiB / 256 KiB / 1 MiB | 14 / 14 / 18 / 42 ms |
| 검사 SCAN → SCANNED (크기 무관) | 2.09–2.11 s (MpCmdRun 자체 0.05 s + 탐지 이벤트 대기 2 s) |
| 임시 디렉터리 폐기 (ABORT → 폴더 없음) | 5–7 ms |
| Host 전 구간 1 MiB: HTTPS+파이프 전송 | 56 ms |
| Host 전 구간 1 MiB: `artifact_export` → `EXPORTED` | 2.61 s (최대 2.90 s) |
| 동시 4 × 1 MiB (동시 검사 2개 한도) | 전체 4.34 s, Job별 검사 2.09–4.22 s |
| 그동안 서비스 프로세스 | CPU 평균 0.8 % / 최대 3.7 % (머신 전체 대비), 메모리 35.7 MiB |
| 그동안 MsMpEng | CPU 평균 0.1 % / 최대 1.2 %, 메모리 225 MiB |

검사 시간의 대부분은 Defender가 탐지 이벤트를 쓰는 시간을 기다리는 `event_settle_s`(2초)다. 줄이면 빨라지지만 탐지 이벤트를 놓칠 위험이 커진다(그 경우에도 파일 삭제로 잡히지만, 근거가 하나 줄어든다).

### 발견한 결함과 수정

1. **Host 종료 시 ABORT 유실 가능**: 취소 요청을 데몬 스레드로 보내서, Host 프로세스가 바로 끝나면 서비스에 닿지 못할 수 있었다(서비스 만료로 15분 뒤에야 정리). → `ScannerServiceClient.drain()`, Host 종료 때 최대 5초 기다림. 테스트 `test_aborts_finish_before_the_host_exits`, `test_host_exit_during_a_scan_reaches_the_service`.
2. (배포) **서명 없는 실행 파일은 App Control이 켜진 PC에서 실행 불가**: Python 없는 환경 검증용 Windows Sandbox(사용자 모드 코드 무결성 강제)에서 `SecureArtifactScanner.exe`가 "An Application Control policy has blocked this file"로 차단됨(로컬 복사본도 동일). 코드 결함은 아니지만 배포 조건이다.
3. (테스트) 관리자 pytest가 남긴 `pytest-current` 링크 → `--basetemp` 안내.

### 미검증 (성공으로 표시하지 않음)

- **Python이 없는 PC에서의 설치·실행**: Windows Sandbox에서 Python이 없는 것은 확인했지만 App Control 정책이 서명 없는 exe 실행을 막아 설치 단계에 못 갔다. 우회하지 않았다. 서명 후 또는 App Control 없는 깨끗한 VM에서 다시 해야 한다.
- **Defender 비활성화 PC**: 보안 설정을 바꾸지 않았다. 비활성·수동 모드·정책 비활성은 가짜 상태로만 시험(`SCANNER_UNAVAILABLE`). Sandbox 안 Defender가 꺼져 있었지만 exe가 막혀 서비스로는 확인하지 못했다.
- **실제 Windows 재부팅**: 재부팅하지 않았다. 강제 종료 후 재시작으로 같은 복구 경로(실행 표시·잔여 Job 폐기)를 확인했다.
- 디스크가 실제로 가득 찬 상황(한도 설정으로만), 실제 sandbox_runner와의 연동(테스트 Runner로만).
