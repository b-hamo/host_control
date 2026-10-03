# host_control

Host에서 Agent 요청을 통제·전달하는 프로그램.
AI Agent(Codex)의 요청을 검사해서 격리된 Sandbox 안의 Runner(`b-hamo/sandbox_runner`)로 전달하고,
돌아온 결과를 검증한다.

```
Codex ──MCP──▶ [ MCP Server + Broker ] ──▶ [ Host 송신기 ] ──WSS──▶ [ Runner ]
                  W5 예정                   host/sender.py          sandbox_runner
                                           (현재 포함)              Sandbox 안
```

## 현재 포함된 것

| 경로 | 내용 | WBS |
|---|---|---|
| `host/sender.py` | Host 송신기. Runner 접속 수락, 제어 메시지 전송, 응답 검증 | 3.4 |
| `scrp/validate.py` | 메시지 검증기 (크기·인코딩·스키마) | 2.2 |
| `scrp/envelope.py` | 메시지 봉투 생성기 (ID·sequence·nonce·timestamp) | 2.2 |
| `schema/` | Host ↔ Runner 메시지 규격 — **Runner도 이 파일을 기준으로 구현** | 2.2, 2.3 |

규격의 결정 사항과 노션 초기 표와의 차이는 [schema/README.md](schema/README.md)에 있다.

## 실행

Python 3.11 이상.

```bash
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt
.venv/Scripts/python.exe host/sender.py
```

`listening on ws://0.0.0.0:17443/scrp/v1/control`이 뜨면 Runner의 접속을 기다리는 상태다.
Runner가 접속해 HELLO를 보내면 데모 순서(화면 관찰 → 클릭 → 입력 → 생존 확인 → 상태 조회 → 종료)를
실행하고 결과를 출력한다. `--no-demo`는 핸드셰이크만 하고 대기한다.

Windows Sandbox에서 접속받으려면 Host 방화벽에서 TCP 17443 인바운드를 허용해야 한다.

## 현재 한계

- 통신이 **평문(ws://)**이고 인증 토큰을 검증하지 않는다 → WBS 4.6
- Runner가 HELLO에 담아 보낸 session_id를 그대로 사용한다. Lifecycle Manager가 발급한 값과
  대조하는 것은 4.6에서 한다
- Heartbeat는 1회만 주고받는다. 주기 전송과 재연결은 4.4
- task_id·action_id를 송신기가 임시로 발급한다. W5에 Broker(명세서 B-4)로 옮긴다
