# CLEAN 파일 자동 반출과 MCP 결과

통합 Output 반출은 Windows 목록 확인·최종 보관·결과 알림창을 띄우지 않는다.
명시적으로 요청한 파일과 정상 종료 시 최종 목록에 포함된 나머지 Output 파일을
SecureArtifactScanner로 검사하고 CLEAN인 파일만 다운로드에 저장한다.
악성·오류·미확인·검사 서비스 부재·파일 변경은 공개하지 않는다.

## MCP 응답

`artifact_export`에 반출 ID와 선택 사항인 `wait_ms`(0~30000, 기본 30000)를 전달한다.
대기 시간이 지나도 전송·검사를 취소하지 않는다. `completed=false`면
`artifact_list`에 `wait_ms`를 주어 완료를 기다릴 수 있다. 같은 ID 재요청은 중복 저장하지 않는다.
`completed=true`는 처리가 끝났다는 의미다. 성공은 `status=EXPORTED`와 `export_path`로
확인하며 차단은 `result.code`와 `result.detail`로 확인한다. 완료 결과는 종료 뒤에도 조회된다.

```json
{"status":"EXPORTED","completed":true,"notification":"mcp","automatic_export":true,"export_path":"C:\\Users\\user\\Downloads\\SandboxOutput\\SES-...\\ART-000001\\result.zip"}
```

Host는 MCP 결과를 반환하며, 에이전트가 채팅에서 저장 위치 또는 차단 사유를 설명한다.
호출이 없는 상태에서 MCP가 임의로 새 채팅 메시지를 생성하지는 않는다. 창을 직접 닫은 뒤에는
에이전트의 후속 결과 조회로 종료 반출 결과를 받는다.

## 파일과 종료 처리

Sandbox Output 원본 → 실행 금지 Host 임시 수신본 → 서비스 격리 검사 사본 순으로 처리한다.
CLEAN 후 잠긴 Host 수신본과 동일한 바이트를 다운로드에 복사하고 MOTW를 붙인다.
성공 후 임시 수신본은 정리하며, 실패 사본은 실행 금지 영역에 남겨 원인을 기록한다.
서비스 검사 사본 정리는 기존 scan-only 계약을 사용한다.

정상 종료는 전체 목록과 파일을 확보·대조한 다음 VM을 종료하고 각 파일을 검사한다.
한 파일의 악성·오류가 다른 CLEAN 파일의 처리를 중단시키지 않는다. 이미 저장한 동일 파일은
재저장하지 않는다. 최종 목록 확보 실패나 강제 VM 소멸에서는 이전 수신본을 최신 결과로
자동 공개하지 않는다. 아직 전송되지 않은 바이트는 복구를 보장하지 않는다.

변경은 Host에 적용되며 Runner와 Manager의 기존 계약을 재사용한다. 통합 Output 이외의
레거시 반출 정책과 Sandbox 종료 확인 등 반출 외 승인에는 영향을 주지 않는다.

session_stop의 output은 종료 후 확보·파일별 반출 결과다. 창 닫기 후에는 runtime_get_state의
output 또는 artifact_list로 조회한다. 같은 MCP 연결에서 다음 세션을 시작하기 전까지 보존한다.
강제 Host 프로세스 소멸 후의 복구 API는 포함하지 않는다.

## 검증 상태 (2026-11-03 KST)

추가 회귀 사례는 CLEAN/DETECTED/ERROR/UNVERIFIABLE, 파일별 혼합 판정, 서비스 부재,
수신본 변조, 예상치 못한 오류 후 다음 파일 처리, 명시 반출과 종료 반출 중복 방지,
대기 취소, 종료 후 MCP 결과 조회, 공개 후 상태 기록 실패다.
Windows Named Pipe 테스트 서비스와 가짜 백신을 사용하며 실제 Defender 검증과 구분한다.

이번 채팅의 실행 검증은 SCRP task_submit에서 RUNTIME_UNAVAILABLE로 중단됐다.
Host의 0.0.0.0:17444 바인딩이 WinError 10048(포트 사용 중)로 실패했고,
runtime_get_state도 START_FAILED를 반환했다. router_execute 및 pytest는 호출하지 않았으며
Host에서 대신 실행하지 않았다. 다른 채팅에서 준비한 검사 묶음도 이 최종 소스의 실행 증거로 취급하지 않는다.

git diff --check는 통과했다. 빠른 점검·전체 테스트·실제 서비스 자동 반출은 미검증이며,
연결 복구 후 다음 검증이 필요하다.

```text
python -m pytest -q tests/test_repo_rules.py tests/test_codex_skill.py
python -m pytest -q tests
```

docs/output-only-validation.md는 #105 승인 창 방식의 검증 기록이며 이번 변경의 통과 증거가 아니다.
