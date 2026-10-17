# 사용자 작업별 웹 접근 범위

## 발표 브랜치에서 실행

`examples/midterm/operator-config.example.json`과 `user-task.example.json`을
Host 설정 위치에 복사하고 절대 경로를 환경에 맞게 바꾼다. run directory는
새 연결마다 아직 존재하지 않는 경로를 사용한다. 저장소 requirements와
호환되는 sandbox_manager를 설치하거나 형제 checkout으로 둔다.

```powershell
python -I scripts/launch_router_workflow.py --config C:/SCRP/config/operator-config.json
```

MCP의 command/args에도 같은 Python과 런처·설정의 절대 경로를 지정한다.
예제 게임 서버 목록은 2026-10-17에 관찰한 의존 서버이며 제품 코드의 고정
허용 목록이 아니다. 다른 작업은 user-task 파일의 goal/urls를 변경한다.
게임 예제에서는 실행 및 자동 클립보드 분석을 비활성화한다.

## 작업폴더 통합 및 계약

프로젝트의 `scripts/launch_router_chat.py`는 `config/router-task.json`을 Host 작업 파일로 지정한다.
파일은 사용자 요청을 처리하는 Host 측에서 작성한다. 페이지 내용이나 MCP 호출 인자가
허용 출처를 늘리는 권한을 갖지는 않는다. 런처와 Router 코드에는 특정 테스트 사이트를 넣지 않는다.

작업 파일의 형식은 `{"goal": "사용자 작업", "urls": ["https://example.org/path"]}`이다.
Router는 URL에서 정규화한 origin을 추출해 새 workflow의 범위로 사용한다.
현재 작업의 범위는 고정된다. 다른 사용자 작업은 Host 작업 파일을 갱신하고
`router_stop` 후 새 request_id로 시작하면 같은 MCP 연결에서 새 범위를 읽는다.
기존 request_id는 기존 작업 조회에만 사용한다. 이는 자연어 권한 판정기를 추가한 것이 아니다.

`WEB_SCOPE_DENIED` 응답에는 요청 origin, 허용 origin, 수행하려던 동작, 다음 조치가 들어간다.
잘못된 URL은 `INVALID_WEB_URL`이다. URL의 자격 증명, 경로, 쿼리를 오류에 노출하지 않는다.
브라우저 하위 리소스 차단도 화면 결과의 `blocked_requests`에서 확인할 수 있다.
필요한 추가 서버는 사용자 작업과의 관련성을 확인한 뒤 Host 작업 파일에 명시한다.
페이지에서 발견했다는 이유만으로 자동 허용하지 않는다.

이 경로는 Router가 소유한 로컬 Edge의 HTTP(S) 탐색/요청을 제한한다.
OS 전체 네트워크 격리나 다른 도구의 강제 중계를 의미하지 않는다.
웹 탐색 권한은 프로그램 실행 권한과 별개다. 이번 게임 검증 설정은
`allow_execution=false`, `auto_analyze_clipboard=false`이며 일반 Sandbox 연결은 보존한다.

검증: 사용자 지정 게임 사이트에서 초급 게임 생성과 셀 열기를 Router MCP로 수행했다.
범위 밖 탐색 거부, 필요한 게임 서버의 명시적 추가, 종료 후 범위 재로딩,
외부 폰트 요청 차단, 브라우저 정리도 확인했다. 프로젝트 evidence의
`task-scope-minesweeper-20261017-02`에 요청/응답과 pytest 결과를 보관한다.
