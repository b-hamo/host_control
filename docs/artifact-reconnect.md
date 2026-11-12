# 인증된 반출 채널 재연결

`artifact.reconnect.v1`은 Host GUI Runner가 이전 Control 연결의 파일 작업·업로더·Telemetry를
중단하고 join한 후 새 HELLO를 보낸다는 추가 capability다. Host와 Runner를 함께 갱신해야 한다.
기존 파일 메시지/업로드 토큰/검사 계약은 그대로다. HELLO/HELLO_ACK capability enum만 확장한다.

Host는 검증된 Control HELLO에서 연결 ID를 기록하고, 발급한 일회성 Telemetry 토큰에 그 ID를
내부적으로 결합한다. 새 채널은 이 연결의 토큰으로만 열 수 있다. 이전 채널의 이벤트와 늦은
종료 알림은 새 채널에 적용하지 않는다. 이전 업로드 권한·후보는 재활성화하지 않는다.
이미 수신·확인한 Host 사본은 보존하고 이후에도 기존 Scanner 검사와 공개 경로를 따른다.

재개는 Output 전송이 유휴 상태일 때만 허용한다. 진행 중인 수신·prefetch 또는 해제가 확인되지
않은 snapshot이 있으면 차단을 유지한다. 종료/보안 위반으로 폐기한 세대, 새 capability가 없는
Runner도 복구하지 않는다. 새 연결은 기존 snapshot 완료 표시를 무효화하고 새 manifest 검증을 요구한다.
따라서 일반 Telemetry 단독 재접속으로 기존 차단을 지울 수 없다.

`tests/test_output_export.py`는 이전 권한 폐기·늦은 종료·대기 snapshot·진행 중 전송·종료 상태와
Host 사본 보존을 검사한다. `test_artifact_export.py`는 실제 TLS 연결의 새 Control/Telemetry
자격 교환과 이전 토큰 거부를 검사한다. 이 시험의 Runner와 Scanner는 테스트 대역이다.
실제 VM 결과는 `mixed-vm-followup-20261108.md`에 따로 기록한다.
