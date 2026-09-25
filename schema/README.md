# SCRP Schema — Host ↔ Runner 메시지 규격

`Secure_CUA_Protocol_W1_v0.1` 5~8장의 표를 코드가 읽는 JSON Schema(draft 2020-12)로 옮긴 것이다.
Host는 `scrp/validate.py`로, Runner(C++)는 자체 검증기로 **같은 JSON 파일**을 읽어 검증한다.
문서(노션·PDF)와 이 파일이 다르면 **이 파일이 기준**이다.

```
envelope.schema.json        공통 Envelope (16개 필드 전부 필수, 값이 없으면 null)
payload/<TYPE>.schema.json  type별 payload 20종 (정의에 없는 필드는 거부)
```

검증 순서 (`scrp/validate.py`): 64 KiB 크기 → UTF-8 strict → JSON(중복 key·NaN 거부) →
중첩 깊이 16 → Envelope 스키마 → type별 payload 스키마.

## 노션 "기본 요청 8가지" 표와 다른 점

초기 표와 프로토콜 PDF v0.1이 다른 부분은 **PDF를 따른다** (2026-09-22 결정).

| 항목 | 초기 표 | 이 스키마 |
|---|---|---|
| CLICK · TYPE · KEYPRESS · SCROLL | 각각 독립 메시지 | `ACTION_REQUEST` 하나에 `operation`으로 구분 (`mouse.click`, `keyboard.type` 등) |
| OBSERVE 응답 | `image_ref`로 이미지 참조 | 이미지는 HTTPS PUT 별도 경로, `OBSERVE_RESULT`에는 크기·sha256·upload_id만 |
| HEARTBEAT | `probe_id` | `lease_expires_at` 요청 / `ALIVE`에 runtime_state·worker_alive·queue_depth |
| ARTIFACT_REQUEST | 목록 조회 (`op: "list"`) | 특정 파일 **전송 요청**. 목록 조회는 Host 쪽(Runner 메시지 아님) |
| UI_ACTION | 있음 | **유지** — `ACTION_REQUEST.operation = "ui.click_element"`. selector는 `{name, control_type(enum)}`만, 정확히 1개 매칭일 때만 실행, `ui.automation` Capability 필요 |

`ACTION_REQUEST.operation`은 이 7개뿐이다:
`mouse.move`, `mouse.click`, `mouse.scroll`, `keyboard.type`, `keyboard.press`, `keyboard.hotkey`, `ui.click_element`

## PDF가 "W2에 정한다"고 미뤄둔 세부 사항의 결정

- `task_id`·`action_id`가 필수인 메시지: OBSERVE, OBSERVE_RESULT, ACTION_REQUEST, ACK, ACTION_RESULT
- 응답 메시지(HELLO_ACK, *_RESULT, ACK, ALIVE, *_ACK)는 `correlation_id`·`status` 필수, 요청·이벤트는 셋 다 null
- `status` 값: ACK → `ACCEPTED`/`REJECTED`, ACTION_RESULT → `SUCCESS`/`PARTIAL_SUCCESS`/`FAILED`/`UNKNOWN`/`BLOCKED`, 그 외 응답 → `OK`/`ERROR`
- `error.code`: 명세서 B-10 목록 + `PROTOCOL_DENIED`, `UNSUPPORTED_TYPE`, `MESSAGE_TOO_LARGE`, `STALE_OBSERVATION`, `RATE_LIMITED`, `INTERNAL`
- HELLO·HELLO_ACK는 `sequence_number = 1`, HELLO의 `connection_id`는 null
- `nonce`는 128-bit base64url 22자, `timestamp`는 `Z`로 끝나는 RFC 3339만
- `keyboard.press` 키 이름은 소문자 102개 고정 (`enter`, `hangul`, `capslock`, `numpadenter` 등). 절전·전원·미디어 키는 제외

## 담당 및 확정 상태

| 범위 | 담당 | 상태 |
|---|---|---|
| Envelope, ACK·ERROR, OBSERVE*, ACTION_REQUEST·RESULT 구조, STATE*, HEARTBEAT·ALIVE, TERMINATE*, ARTIFACT_REQUEST·RESULT | 이준원 (2.2, 2.3) | 초안 |
| ACTION_REQUEST의 operation별 인자 한계값 (키 목록, 좌표 상한, text 길이 단위) | 정유진 (2.3) | **확정 필요** |
| HELLO, HELLO_ACK, CHANNEL_HELLO·ACK — Capability 어휘, limits, 자격 구조 | 정유진 (2.5) | 이준원 초안, **확정 필요** |
| SECURITY_EVENT(ARTIFACT_CANDIDATE) evidence | 곽재혁 (2.6) | 이준원 초안, **확정 필요** |

## 동결 (M2)

위 "확정 필요" 항목이 정해지면 `git tag scrp-schema-v1.0`을 붙인다. 이후 변경은 Envelope의
`version` 값을 올리는 경우에만 한다.
