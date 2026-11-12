# artifact-export-v1 (Runner 계약, Host 채택)

파일 반출 프로파일의 메시지 6종(CHANNEL_HELLO, CHANNEL_ACK, SECURITY_EVENT, EVENT_ACK,
ARTIFACT_REQUEST, ARTIFACT_RESULT) 규격이다. Runner 담당이 정의·구현한 계약을 Host가 그대로 채택했다.

| 파일 | 출처 |
|---|---|
| `messages.schema.json` | `b-hamo/sandbox_runner` `32700916f4e7074051a109aaf6b4728dbeba7df4` `docs/contracts/artifact-export-v1/messages.schema.json` (수정 없음) |
| `examples.json` | 같은 커밋 `docs/contracts/artifact-export-v1/examples.json` (수정 없음, 테스트 기준) |

- **이 프로파일을 선택한 세션에서만** 위 6종을 이 스키마로 검사한다 (`scrp/validate.py`의 `profile`).
  다른 세션은 `schema/envelope.schema.json` + `schema/payload/`의 기존 규칙을 그대로 쓴다. 기존 스키마는 덮어쓰지 않았다.
- 선택 방법: bootstrap의 `control_contract: "artifact-export-v1"` + `artifact_upload`, HELLO/HELLO_ACK의 `artifact.export.v1` capability.
- 스키마는 형태만 검사한다. 인증·세션 binding·상관관계·권한 상태·파일 경계는 Host 코드(`host/telemetry.py`, `host/artifacts.py`)가 검사한다.
- `$id` URL은 가져오지 않는다 (로컬 파일만 사용).
- 계약 문서: Runner 저장소 `docs/artifact-export-contract.md` (같은 커밋)
