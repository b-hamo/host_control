# 팀 공용 코덱스 Skill을 이 PC의 코덱스에 넣는다 (관리자 아님). git pull 로 Skill이 바뀌었을 때도 다시 돌린다.
#
#   powershell -ExecutionPolicy Bypass -File codex\install_skill.ps1
#
# 코덱스는 저장소가 아니라 %USERPROFILE%\.codex\skills 만 읽는다. 그래서 저장소의 Skill이 바뀌어도
# 이 스크립트로 다시 복사해야 코덱스에 적용된다. 복사한 뒤 코덱스를 완전히 껐다 켠다.
$ErrorActionPreference = 'Stop'
$src = Join-Path $PSScriptRoot 'skills\secure-sandbox-run'
$skills = Join-Path $env:USERPROFILE '.codex\skills'
$dst = Join-Path $skills 'secure-sandbox-run'
if (-not (Test-Path (Join-Path $src 'SKILL.md'))) { throw "Skill not found: $src" }
New-Item -ItemType Directory -Force $dst | Out-Null
$old = Join-Path $dst 'SKILL.md'
if (Test-Path $old) {
  $backup = Join-Path $env:USERPROFILE ('.codex\skill-backups\secure-sandbox-run.SKILL.' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.md')
  New-Item -ItemType Directory -Force (Split-Path $backup) | Out-Null
  Copy-Item $old $backup
  "이전 Skill 백업: $backup"
}
Copy-Item (Join-Path $src 'SKILL.md') $old -Force
"설치: $old"
# 같은 일을 하는 예전 Skill이 같이 켜져 있으면 코덱스가 서로 다른 지시를 받는다.
$other = Join-Path $skills 'scrp-sandbox-execution'
if (Test-Path $other) {
  "주의: $other 도 있습니다. 같은 일을 하는 예전 Skill이니 코덱스 Skill 화면에서 끄거나 지우세요."
}
"코덱스를 완전히 껐다 켠 뒤 새 대화에서 쓰세요."
