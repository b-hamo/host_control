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

최초 시도는 SCRP Host의 17444 포트 충돌로 시작하지 못했다. 사용자가 기존 Sandbox를 닫은 뒤
포트 해제를 확인했다. 다음 시작에서는 등록된 구형 Runner에 artifact.output.v1이 없어 종료됐다.
기존 실행 파일과 solution.json을 로컬 build/auto110-runner-backup에 백업하고, #105에서 검증한
Runner(SHA-256 2a9c0f156e74aa0371a34ba6f66515359846e4fab101a9168ee2e2e4e2205641)로
등록 경로의 실행 파일 및 프로필 해시를 갱신했다. Host에서 Runner나 테스트를 직접 실행하지 않았다.

커밋 98c63f3690d7c9635fe90384424085b8430baa5a를 새 묶음으로 반입해 다음 결과를 얻었다.

- Guest input-check에서 ZIP/실행 스크립트의 OK와 SHA-256 일치를 확인했다.
- 빠른 점검: **18 passed**, 0.50초.
- 전체 테스트: **717 passed, 55 skipped**, 191.93초. 실패 0개.
- SCRP RUN-0006: **SUCCEEDED / GUEST_PROCESS_VERIFIED / exit_code=0 / FULL_EXIT=0**.
- 세션: SES-7c90d6c123a147faa502a9c0dc0614ac. Python 3.13.7 embedded.
- 소스/의존성 ZIP SHA-256: 330696ff5b4c2aa5360ec7370e303017a581a3eff3f3b5eddcd56acd75b38a28.

검증 준비 중 Guest의 PowerShell Archive 모듈을 로드하지 못해 .NET ZIP API를 사용했고,
pytest의 py.py 및 pythoncom.py 누락과 pywin32 DLL 검색 경로를 보완했다. 준비 실패의 로그는
테스트 실패나 통과로 계산하지 않았다. 최종 실행은 같은 SCRP Sandbox 안에서 수행했다.

실제 서비스 정상 반출도 확인했다. 전체 로그 ART-000017은 936바이트이며 SHA-256은
ce5d5bd4d22ad9ab217db09833fab52439c1c48418be28bbc995fd9e20d85a95다.
artifact_export는 반출 확인창 없이 EXPORTED/completed=true/notification=mcp와 다운로드 경로를
반환했다. 실제 파일의 해시, MOTW ZoneId=3 및 동일 ID 재요청 후 사본 1개를 확인했다.
빠른 점검 로그 ART-000012도 동일 서비스 경로로 EXPORTED가 됐다.

55개 제외 항목은 통과로 계산하지 않는다. 악성·검사 오류·서비스 부재·종료 시 혼합 파일 처리와
종료 후 MCP 조회는 자동 회귀로 확인했으며 실제 악성 파일 실험이나 이번 새 세션의 창 닫기 후
전체 자동 저장을 재현한 것은 아니다. 현 MCP 프로세스의 일부 설명/진입점은 이전 로드 상태이므로,
새 MCP 프로세스에서 최신 설명·종료 응답 전체를 확인하는 실환경 검증도 남는다. 검증용 Sandbox는 유지했다.
git diff --check도 통과했다.

```text
python -m pytest -q tests/test_repo_rules.py tests/test_codex_skill.py
python -m pytest -q tests
```

docs/output-only-validation.md는 #105 승인 창 방식의 검증 기록이며 이번 변경의 통과 증거가 아니다.
