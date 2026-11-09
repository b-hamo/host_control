# Windows Sandbox + micro_VM 동시 실행 — 다른 PC 재현 시험

#115에서 개발 PC(Windows 11 26200.9711) 한 대로 확인한 혼합 실행을 **다른 PC에서 다시** 확인한다.
micro_VM README의 검증 상태표에서 "다른 PC·다른 Windows 빌드"는 아직 미검증이다.

| 단계 | 확인하는 것 | 쓰는 것 |
|---|---|---|
| 1단계 | VM끼리 같이 켜지는가 (SCRP 없음) | micro_VM CLI(`minobox`), Windows Sandbox 앱 |
| 2단계 | SCRP Host 두 개가 각자 VM을 맡아 같이 동작하는가 | `tools/mixed_vm_smoke.py` |

모든 명령은 **관리자 Windows PowerShell 5.1**에서 실행한다. micro_VM broker가 관리자 권한을 요구한다.
`.ps1` 실행이 막히면, 그 창에서만 허용한다.

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

## 준비물

- Windows 11 Pro 또는 Enterprise x64
  - Windows Sandbox 기능(`Containers-DisposableClientVM`)과 하드웨어 가상화를 켠다.
  - `winver`로 빌드 번호를 적어 둔다.
- 메모리 16 GB 이상을 권장한다. micro_VM VM 하나가 4 GB를 쓰고, Sandbox도 같이 켜진다.
- Git, Python 3.13 (팀 공통 3.13.15)
- Visual Studio 2022 또는 Build Tools의 "C++를 사용한 데스크톱 개발". micro_VM 빌드에 쓴다.
- MSYS2 UCRT64의 gcc, cmake, ninja, jsoncpp. Runner 빌드에 쓴다.
- 노트북이면 충전기를 꽂는다. 배터리 절전 상태에서는 Sandbox 시작이 실패한 사례가 있다.

## 0. 받기와 빌드

```powershell
mkdir C:\scrp; cd C:\scrp
git clone -b develop https://github.com/b-hamo/host_control
git clone -b develop https://github.com/b-hamo/sandbox_manager
git clone -b develop https://github.com/b-hamo/sandbox_runner
git clone -b develop https://github.com/b-hamo/micro_VM
```

이 문서와 스크립트가 develop에 머지되기 전이면 host_control에서 시험 브랜치를 받는다.

```powershell
cd C:\scrp\host_control; git checkout test/119-mixed-vm-other-pc
```

**Host**

```powershell
cd C:\scrp\host_control
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

**Runner**: 결과물은 `build\solution\sandbox_runner.exe`다.

```powershell
cd C:\scrp\sandbox_runner
.\scripts\build.ps1 -UcrtRoot C:\msys64\ucrt64
```

**micro_VM**: 처음 쓰는 PC이므로 `-NewLayer`로 묶는다.

```powershell
cd C:\scrp\micro_VM
.\scripts\build-dbi.ps1
.\scripts\package-minobox.ps1 -NewLayer
```

- 빌드 폴더는 `tmp\build\windows-x64-debug`, 묶음 폴더는 `tmp\dist\minoBox-<시각>`이다.
- `ScrpRelay.exe`는 전체 빌드에 함께 생긴다. 없으면 다음 명령으로 찾는다.

  ```powershell
  Get-ChildItem tmp\build -Recurse -Filter ScrpRelay.exe
  ```

**방화벽 (한 번만)**: Sandbox 안 Runner가 Host 포트 17443/17444에 닿게 한다. 방화벽 규칙을 바꾸는 단계다.

```powershell
cd C:\scrp\sandbox_manager
powershell -ExecutionPolicy Bypass -File .\tools\install_firewall.ps1
```

## 1단계: VM끼리 같이 켜지는가

micro_VM 묶음 폴더(`C:\scrp\micro_VM\tmp\dist\minoBox-<시각>`)에서 실행한다.

| 순서 | 할 일 | 기대 결과 |
|---|---|---|
| 1-1 | Sandbox를 **닫은** 상태에서 `.\minobox run --name 첫VM --no-desktop -d`, 이어서 `.\minobox ps`, `.\minobox stop 첫VM` | 처음에는 PC 검증과 레이어 준비로 10분 넘게 걸릴 수 있다. 다음부터는 수십 초다 |
| 1-2 | 시작 메뉴에서 Windows Sandbox를 켜고 바탕화면까지 기다린다 | Sandbox 바탕화면이 뜬다 |
| 1-3 | `.\minobox run --name 시험B --program cmd.exe -d` | VM이 켜진다. "진짜 바탕화면은 건너뜁니다" 안내가 나와도 정상이다 |
| 1-4 | `.\minobox screenshot 시험B -o b.png`, 그리고 Sandbox 창에서 메모장 열기 | b.png에 명령 프롬프트가 보이고, Sandbox도 계속 정상이다 |
| 1-5 | `.\minobox stop 시험B`, Sandbox를 닫는다 | 둘 다 깨끗이 꺼진다 (`.\minobox ps`, `wsb list`가 비어 있다) |
| 1-6 (선택) | 바탕화면 VM(`.\minobox run --name 바탕`)을 켠 채 Sandbox를 켠다 | 문서상 Sandbox가 "원격 환경이 로그오프되고 있습니다"로 닫혀야 한다. 결과만 적는다 |

## 2단계: SCRP Host 두 개 (`tools/mixed_vm_smoke.py`)

스크립트가 하는 일:
- Host A(Windows Sandbox)와 Host B(micro_VM 앱 창)를 실제 MCP 서버로 띄운다.
- 슬롯마다 다음을 한 번씩 확인한다. 입력은 재시도하지 않는다.
  1. 켜기와 READY (걸린 시간 기록)
  2. 모두 켜진 상태의 화면
  3. Win+R 입력이 자기 화면에만 닿는가
  4. 나중에 켠 쪽을 끈 뒤 남은 쪽이 살아 있는가
- 결과는 `--work` 폴더의 `result.json`과 PNG로 남는다.
- 매 실행마다 **새 폴더**를 지정한다. 같은 폴더를 다시 쓰면 거부한다.

경로를 변수로 둔다. 묶음 폴더 이름은 실제 이름으로 바꾼다.

```powershell
cd C:\scrp\host_control
$py   = ".\.venv\Scripts\python.exe"
$pkg  = "C:\scrp\micro_VM\tmp\dist\minoBox-<시각>"
$common = @("--runner", "C:\scrp\sandbox_runner\build\solution\sandbox_runner.exe",
            "--manager", "C:\scrp\sandbox_manager",
            "--vm-package", $pkg, "--vm-root", "C:\scrp\vmroot",
            "--relay", "C:\scrp\micro_VM\tmp\build\windows-x64-debug\ScrpRelay.exe")
```

| 순서 | 명령 | 확인하는 것 |
|---|---|---|
| 2-0 | Sandbox를 닫고 `& $py tools\mixed_vm_smoke.py @common --slots B --work C:\scrp\evidence\2-0-B` | micro_VM 혼자 SCRP READY가 되는가 (새 `--vm-root`의 첫 준비 포함) |
| 2-1 | `& $py tools\mixed_vm_smoke.py @common --slots A,B --work C:\scrp\evidence\2-1-AB` | **Sandbox 사용 중에 micro_VM을 켜는** 경우. 우리가 정한 정책의 핵심이다 |
| 2-2 | `& $py tools\mixed_vm_smoke.py @common --slots B,A --work C:\scrp\evidence\2-2-BA` | 반대 순서: micro_VM을 쓰는 중에 Sandbox를 켜는 경우 |

- Sandbox가 시작 중에 멈추거나 화면이 검게 남으면 `--vgpu-off`를 붙여 다시 실행하고, 그 사실을 기록한다. AMD GPU PC에서 vGPU 때문에 Sandbox가 죽은 사례가 있다.
- Win+R을 누르면 Sandbox(A)에는 Windows 실행 창이, micro_VM(B)에는 Runner 전용 명령 입력 창이 뜬다. 스크립트가 Esc로 닫는다.

### 합격 기준

- 각 실행 마지막 줄이 `RESULT PASS`다.
- `2-together.png`에서 A와 B 둘 다 자기 화면이 보인다.
- `3-A-before-B-input.png`와 `3-A-after-B-input.png`를 비교해, B에 입력하는 동안 A 화면이 바뀌지 않았다. 반대도 같다.
- `result.json`의 `"A READY + screenshot"`, `"B READY + screenshot"` 값(초)을 적는다. 속도 비교에 쓴다.

## 실패했을 때 정리

- Host가 비정상으로 끝나도 micro_VM Manager는 VM을 보존한다(#115의 고정 VM 보존). 남은 것을 확인하고 끈다.

  ```powershell
  wsb list
  & "$pkg\dbictl.exe" workspace list --root C:\scrp\vmroot
  & "$pkg\dbictl.exe" workspace stop --root C:\scrp\vmroot --id <GUID> --confirm-stop
  ```

- 실패한 Sandbox의 오류 창이 열려 있으면 micro_VM이 계속 "Sandbox 실행 중"으로 본다. 그 창의 **닫기**를 누른다.

## 결과 공유

다음을 모아 공유한다.
- 1단계 표의 결과
- 2단계 각 `--work` 폴더의 `result.json`과 PNG
- Windows 빌드, CPU와 GPU, 메모리
- 각 저장소의 `git rev-parse HEAD`

`certs\` 폴더와 `audit\` 폴더는 공유하지 않는다. 인증서와 세션 기록이 들어 있다.

## 알려진 제한

- Host B는 micro_VM broker 때문에 관리자 권한으로 실행된다. 시험용 구성이다. 제품에서는 VM 관리를 별도 서비스로 분리해야 한다.
- 진짜 바탕화면은 PC당 하나다. micro_VM은 앱 창 모드로만 Sandbox와 같이 쓴다.
- 입력은 순차로 보낸다. 동시 입력 부하, 자원 부족, Runner 프로세스 소실은 이 시험의 범위가 아니다(#115 미완료 항목).
