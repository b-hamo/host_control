# 작업별 행동 검사 없는 비교 모드 (#89)

`examples/no-task-checks/operator-config.example.json`의 `task_checks: false`로 실행한다.
이 설정은 Host 구성에서만 선택하며 MCP 인자로 바꿀 수 없다. 기존 기본값은 true다.
실행 중인 MCP와 발표 브랜치의 설정은 자동 변경하지 않는다.

```powershell
python -I scripts/launch_router_workflow.py --config C:/SCRP/no-task-checks.json
```

설정의 절대 경로를 환경에 맞게 바꾸고 directory는 새 경로로 지정한다.

생략되는 검사:
- 작업 위임 존재·만료, 허용 동작·위치와의 비교
- 위임의 reads/writes/network/capabilities 부분집합 검사
- 위임의 실행 지문 허용 목록과 작업별 승인 요구
- workflow의 task_file 로딩 및 사용자 작업별 URL 허용 목록

유지되는 검사/기능:
- Host 출처 등록, 현재 파일 해시 및 출처 계보 검증
- Local 데이터 루트/파일 형식 제한, Local 프로세스 실행 금지
- 실행 활성화 스위치와 Sandbox 전용 실행·입력 바인딩 계약
- HTTP(S) URL 형식, 자격 증명 포함 URL 거절, 현재 관찰 화면 확인
- 반출 artifact의 검사·해시·검증된 결과 계약 및 반출 승인 경로
- 실행 영수증 검증, 중복 방지, 의존성 완료 확인, 종료/결과 보존

위임의 location 비교를 생략해도 실행 위치는 Action 모델과 LocalTools의 고정
도구 구현에서 제한된다. 임의 Host 명령 실행 API를 추가한 변경은 아니다.
정적 프로필 드라이버는 여전히 바인딩된 명령만 실행한다. 그 제한은 전송/실행
계약이며 작업별 권한 검사와 별개다. 설치·다운로드 도구가 새로 생기지는 않는다.

외부 목적지의 작업별 제한도 없어지므로 이 모드는 정보 외부 전송을 작업 의도로
막는다고 주장하지 않는다. Sandbox/반출 검사는 이를 대신하지 않는다.
웹 탐색은 Router 소유 로컬 Edge에서 이루어진다. OS 전체의 도구 통제는 아니다.
