# Router 후속 작업 수명주기

Router MCP 연결은 유지하면서 개별 plan과 Sandbox를 종료하고 새 작업을 시작한다.
기존 GUI MCP의 task_submit/computer_*를 Agent에게 노출하거나 fallback으로 사용하지 않는다.
Guest 실행 내부에서는 기존 SCRP Broker/driver를 재사용한다.

## 기존 설정으로 사용

`python -m host.router_mcp_server --config <Host 설정 파일>`을 그대로 사용한다.
기존 설정의 plan은 보존되며, 같은 파일이 `default` 프로필로 등록된다.

1. `router_list {}`로 프로필과 plan의 종료·정리 상태를 확인한다.
2. 기존 작업을 `router_stop {"plan_id":"기존 plan ID"}`로 종료하고 `stopped=true`를 확인한다.
3. `router_start {"profile":"default","request_id":"새 작업 시작 식별자"}`를 호출한다.
4. 반환된 `plan_id`와 `execution_action`으로 `router_plan`에 task/action을 등록한다.
5. `router_submit`, `router_status`, `router_result`에 새 `plan_id`를 명시해 작업을 수행한다.
6. 완료 후 해당 `plan_id`로 `router_stop`을 호출한다. 과거 plan은 계속 조회할 수 있다.

`--config`에서 plan_id를 생략한 submit/status/result/stop은 항상 **최초 설정의 plan**을 대상으로 한다.
새 plan을 만든 뒤에도 기본 대상은 바뀌지 않는다. 지연된 이전 호출이 새 Sandbox를 중단하는 것을 막는다.
router_plan은 기존처럼 plan_id가 필수다. 실행 요청 식별자는 plan별로 독립적이다.

## 여러 Host 프로필 사용

`python -m host.router_mcp_server --catalog <카탈로그 JSON>`:

```json
{
  "version": 1,
  "private_directory": "C:/RouterPrivate/connection",
  "profiles": {
    "build": "C:/RouterPrivate/build.json",
    "test": "C:/RouterPrivate/test.json"
  }
}
```

프로필 파일은 기존 provisioning JSON 형식이다. Agent 입력으로 파일 경로, 출처 등록,
권한 위임을 받지 않는다. 운영자가 카탈로그/설정/상태 디렉터리를 보호해야 한다.
카탈로그 모드는 초기화·목록 조회만으로 Host listener나 Sandbox를 시작하지 않는다.
모든 plan/submit/status/result/stop 호출에 plan_id가 필수다.

각 시작은 새 plan ID, session ID, runtime ID와 전용 인증서·감사·Sandbox·반출 저장 경로를 만든다.
프로필의 정확한 실행 명령과 출처는 유지하며, 기존 Guest 결과 디렉터리에 해당하는 쓰기 범위만
새 session/runtime의 결과 디렉터리로 바꾼다. 해당 원본 실행 지문을 허용했던 위임만 새 지문으로
결합한다. 반환된 execution_action을 사용해야 하며 예전 session의 action을 재사용하지 않는다.
권한 만료, 출처 변경, 승인 필요 조건은 기존 실행 검사에서 계속 적용된다.
새 작업은 등록된 프로필의 권한 범위 안에서만 가능하다. 임의 명령을 자동 승인하는 API가 아니다.

## 중복·종료·장애 계약

- 시작 request_id를 DB에 기록한 뒤 Runtime을 연다. 응답 유실/timeout 시 같은 profile과
  **같은 시작 request_id**로 router_start를 재호출하면 동일 plan을 반환한다.
- 진짜 새 사용자 작업에만 새 시작 request_id를 사용한다. 종료된 시작 ID를 재사용해도
  plan은 부활하지 않는다. 다른 profile로 같은 시작 ID를 쓰면 IDEMPOTENCY_CONFLICT다.
- 동시에 하나의 plan만 활성화한다. 이전 plan이 살아 있으면 PLAN_ACTIVE,
  종료 정리가 확인되지 않았으면 CLEANUP_UNCONFIRMED로 다음 시작을 막는다.
- router_stop 이후 기존 plan의 계획 등록/실행은 PLAN_STOPPED다. 상태와 검증된 결과는 유지한다.
- 정상 stdio 종료는 모든 plan을 정리한다. 정상 재접속 시 이전 결과를 조회하고 새 작업을 시작할 수 있다.
- 후속 plan 실행 중 MCP 프로세스 강제 종료 또는 시작 실패 후 정리 미확정은 자동 복구·재실행하지 않는다.
  보존된 예약은 조회 전용이며 새 작업도 차단한다. 운영자가 소유 Guest/Host 자원 정리를 확인해야 한다.
  불확실한 상태를 없애려고 DB를 삭제하거나 stopped/cleaned 값을 수정하지 않는다.
  강제 종료 후 고아 자원의 자동 회수는 이 변경의 범위 밖이다.
- 기존 --config 최초 plan의 재접속 계약은 유지한다. 보존된 실행 요청은 UNKNOWN으로 조정하며 자동 재생하지 않는다.
- 연결당 plan은 최대 1024개다. 결과 보존 정책이나 운영자 보관 절차 없이 자동 삭제하지 않는다.

## 검증

`tests/test_router_connection.py`는 실제 stdio MCP에서 A 종료 → B 시작/완료 → A 결과 조회,
재접속, 명시적 plan 라우팅, 직접 도구 거부를 확인한다. 이는 Local TXT 작업을 사용한다.
추가 모의 Guest 검사는 실행 권한·출처·명령 보존과 session별 출력 범위, 실행 횟수를 확인한다.
동시 시작, 중복 ID, 정리 실패, 시작 실패, 강제 종료의 재실행 방지도 검사한다.
실제 Windows Sandbox 시험 결과는 PR에 별도로 기록한다. 모의 검사를 실제 Guest 증거로 표현하지 않는다.
