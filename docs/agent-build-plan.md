# 에이전트가 결정하는 Host 빌드

`router_execute(form="build-plan")`은 에이전트가 전달한 빌드 명령을 **Host에서** 실행한다.
컴파일러·언어·옵션·소스 내용의 허용 목록 검사는 하지 않는다. 소스 보관 위치, 입력 해시,
요청 중복, 세션 신원, 결과 전달과 Guest 영수증은 기존 계약대로 처리한다.

빌드 명령은 `executable`과 `arguments` 배열이다. 문자열을 셸로 재해석하거나 옵션을 자동 추가하지 않는다.
셸이 필요하면 `cmd.exe /c ...` 또는 PowerShell을 명시한다. CMake·MSBuild·패키지 설치 등 전달한
빌드 단계도 Host에서 실행된다. 최종 `output.entry`는 Router가 Host에서 실행하지 않으며,
파일 또는 DLL·리소스를 포함한 출력 폴더를 ZIP으로 묶어 기존 Sandbox로 전달한다.

## 단일 소스

먼저 원문을 `router_capture`로 기록한다. 받은 source_id로 다음과 같이 요청한다.
이 예제의 옵션은 호출 인자일 뿐 Router 구현에 하드코딩하지 않는다.

```json
{
  "request_id": "build-001",
  "source_id": "CAP-0001-AGENT",
  "form": "build-plan",
  "build_plan": {
    "source_name": "b-hamo.c",
    "steps": [{
      "name": "compile",
      "executable": "gcc",
      "arguments": ["-std=gnu17", "-O2", "-static", "-municode", "b-hamo.c", "-o", "app.exe", "-lwinhttp", "-lshlwapi", "-lshell32"]
    }],
    "output": {"path": "app.exe"}
  }
}
```

Host의 PATH 또는 설치된 컴파일러 검색으로 실행 파일을 찾는다. 자동 검색이 없는 도구는 설치된
실행 파일의 절대 경로를 전달하면 된다. 도구 검색표는 편의 기능이며 실행 허용 목록이 아니다.
별도 소스/헤더는 `build_plan.inputs`에 `{ "source_id": "CAP-0002-AGENT", "path": "helper.h" }`로 추가한다.

## 프로젝트와 출력 폴더

inbox로 받은 ZIP은 최상위 `source_id` 대신 `file`에 받은 파일명을 넣는다. ZIP의 최상위 폴더를
자동 제거하지 않으므로 실제 구조에 맞춰 `working_directory`와 `output.path`를 정한다.

```json
{
  "request_id": "build-project-001",
  "file": "project.zip",
  "form": "build-plan",
  "build_plan": {
    "source_name": ".",
    "archive": true,
    "working_directory": "project-main",
    "steps": [
      {"name": "configure", "executable": "cmake", "arguments": ["-S", ".", "-B", "build"]},
      {"name": "build", "executable": "cmake", "arguments": ["--build", "build", "--config", "Release"]}
    ],
    "output": {"path": "project-main/build/Release", "entry": "app.exe"}
  }
}
```

각 단계의 작업 폴더는 새 임시 작업 공간 기준이다. `environment`는 Host 환경 변수에 덮어쓴다.
각 단계는 독립 프로세스이므로 이전 셸의 `cd`/환경 변수 변경은 다음 단계에 이어지지 않는다.
기본 제한은 단계당 900초이며 `timeout_seconds`로 지정한다. 첫 nonzero 종료에서 후속 단계를 멈춘다.
임시 작업 폴더는 빌드 완료/실패 후 정리한다. 결과 로그는 마지막 16,000자, 묶을 산출물은 50 MiB까지다.

Java는 `output.runtime="java"`, `output.arguments=["-jar", "{entry}"]`를 사용한다.
.NET은 `dotnet publish` 출력 폴더와 DLL entry, `runtime="dotnet"`, `arguments=["{entry}"]`를 전달한다.
`{root}`는 Guest의 압축 해제 폴더다. 실행 cwd는 entry의 부모 폴더다.
런타임은 기존 program_share가 준비하므로 해당 런타임 공유 지원과 Host 설치가 필요하다.

## 결과 및 재요청

요청은 빌드 전 `run_id`와 `ACCEPTED`를 반환한다. `sandbox_run_status`에서 다음을 구분한다.

- `build_status`: Host 빌드의 PENDING/RUNNING/SUCCEEDED/FAILED/UNKNOWN.
- `build_log`, `build_steps`: 빌드 로그와 단계별 종료 코드. 실패는 `build_error`, `build_error_code`, `build_exit_code`.
- `state`, `exit_code`, `stdout`: Sandbox 실행과 실제 Guest 영수증 결과.

빌드 성공은 Guest 실행 성공과 다르다. 같은 request_id/같은 인자는 빌드 중·실패 후에도 같은 작업을
반환한다. 다른 인자로 같은 ID를 쓰면 충돌이다. 확정된 컴파일 실패를 수정할 때만 새 ID를 사용한다.
시간 초과·연결 종료·UNKNOWN에서는 실행을 자동 재전송하지 않는다. 빌드 계획은 감사 로그에 원문 대신
해시로 기록하며 소스와 산출물의 해시도 유지한다.

## 적용 상태

소스 구현이며, 실제 Host/Sandbox 컴파일·실행은 미검증이다. 사용자 요청으로 테스트 실행을 생략했다.
실행 중인 MCP는 자동 교체하지 않는다. 이 버전을 배포하고 새 도구 목록에 build-plan이 나타나야 호출할 수 있다.
기존 c-source 등의 고정 경로와 sandbox_run의 프로젝트 레시피는 호환성을 위해 유지한다.
