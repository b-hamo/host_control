# Host 재시작 후 MCP 재접속

`--shared-runtime --shared-state <절대 경로>`를 지정하면 stdio 클라이언트와
Host 소유 프로세스의 수명이 분리된다. 상태 경로는 inbox/shared 밖의 운영자 전용
디렉터리여야 한다. 이 디렉터리에는 로컬 접속 인증 토큰이 포함되므로 공유하거나
Sandbox에 매핑하지 않는다. 같은 설정과 상태 경로를 사용한 클라이언트는 같은
Host에 접속한다.

```text
python host/mcp_server.py --shared-runtime --shared-state C:\SecureCUA\host-state --agent-guard
```

실제 Sandbox 설정에는 기존 `--runner-exe`, inbox 등 필요한 옵션을 함께 사용한다.
기존 Router 배포 계층의 `run(args, ...)` 호출에서는 `router_state`도 지원한다.

Host 소켓이 닫혀도 Codex와 연결된 stdio 프로세스는 종료하지 않는다. 이후 요청이
도착하면 같은 설정으로 인증된 Host에 재접속하며, Host가 없으면 소유 프로세스
시작을 시도한다. 접속은 기본 20초 동안 시도하며 개별 소켓 접속/인증 대기는
최대 5초이므로 마지막 시도까지 포함하면 이보다 길어질 수 있다. 초기화가
완료됐던 클라이언트는 새 소켓에서 MCP 초기화와 initialized 알림만 다시 보낸다.

- 전송 전에 접속 실패: `MCP_HOST_UNAVAILABLE`, `outcome=NOT_SENT`.
- 전송 또는 응답 대기 중 연결 손실/잘못된 응답: `MCP_REQUEST_OUTCOME_UNKNOWN`,
  `outcome=UNKNOWN`. 인자의 `request_id`가 있으면 그대로 반환한다.
- 두 경우 모두 `replayed=false`이며, tool 요청에는 MCP `isError=true`를 반환한다.
  stdio는 다음 요청을 받을 수 있도록 유지한다.
- 불확실한 실행은 자동 재실행하지 않는다. Router가 있는 배포에서는 재접속 후
  원래 `request_id`로 `router_result`를 조회하고 확인된 결과에 따라 후속 작업을 정한다.
- 설정/인증 불일치는 접속 실패이며 다른 설정으로 우회하지 않는다.
- stdin EOF는 클라이언트만 종료한다. 응답 대기 중이어도 소켓을 닫아 대기를 해제한다.

재접속은 Sandbox 세션 인계 기능이 아니다. Host가 잃어버린 세션, Router의
`CLEANUP_UNCONFIRMED`, 결과가 불명확한 요청 기록을 삭제하거나 자동 해제하지 않는다.
또한 이미 종료된 stdio 프로세스를 Codex 안에서 되살리지는 못하므로 이 기능은
새로 시작하는 MCP 클라이언트부터 적용된다. Codex 자체가 자식 프로세스를 종료하는
경우까지 Host 생존을 보장하지 않는다.

## 검증

```text
python -m unittest discover -s tests -p test_mcp_reconnect.py -v
```

실제 로컬 소켓과 별도 Python 프로세스를 사용한다. 가짜 Host를 종료/교체한 뒤
동일한 stdio 클라이언트에서 후속 요청이 성공하는지, 실행 접수 뒤 응답을 잃어도
요청이 한 번만 기록되는지, 인증 거절·응답 ID 불일치·EOF가 올바르게 처리되는지
검증한다. 실제 Sandbox/사용자 프로그램은 시작하지 않는다.
