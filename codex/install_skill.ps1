# 팀 공용 Skill을 이 PC의 AI 에이전트에 넣는다 (관리자 아님). git pull 로 Skill이 바뀌었을 때도 다시 돌린다.
#
#   powershell -ExecutionPolicy Bypass -File codex\install_skill.ps1                 # Codex
#   powershell -ExecutionPolicy Bypass -File codex\install_skill.ps1 -Agent Claude   # Claude Code
#   powershell -ExecutionPolicy Bypass -File codex\install_skill.ps1 -Agent Both
#
# 에이전트는 저장소가 아니라 자기 폴더(%USERPROFILE%\.codex\skills, %USERPROFILE%\.claude\skills)만 읽는다.
# 그래서 저장소의 Skill이 바뀌어도 이 스크립트로 다시 복사해야 적용된다. 복사한 뒤 에이전트를 껐다 켠다.
param([ValidateSet('Codex','Claude','Both')][string]$Agent = 'Codex')
$ErrorActionPreference = 'Stop'
$src = Join-Path $PSScriptRoot 'skills\secure-sandbox-run'
if (-not (Test-Path (Join-Path $src 'SKILL.md'))) { throw "Skill not found: $src" }
$homes = @()
if ($Agent -in 'Codex','Both') { $homes += Join-Path $env:USERPROFILE '.codex' }
if ($Agent -in 'Claude','Both') { $homes += Join-Path $env:USERPROFILE '.claude' }
foreach ($agentHome in $homes) {
  $skills = Join-Path $agentHome 'skills'
  $dst = Join-Path $skills 'secure-sandbox-run'
  New-Item -ItemType Directory -Force $dst | Out-Null
  $old = Join-Path $dst 'SKILL.md'
  if (Test-Path $old) {
    $backup = Join-Path $agentHome ('skill-backups\secure-sandbox-run.SKILL.' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.md')
    New-Item -ItemType Directory -Force (Split-Path $backup) | Out-Null
    Copy-Item $old $backup
    "이전 Skill 백업: $backup"
  }
  Copy-Item (Join-Path $src 'SKILL.md') $old -Force
  "설치: $old"
  # 같은 일을 하는 예전 Skill이 같이 켜져 있으면 에이전트가 서로 다른 지시를 받는다.
  $other = Join-Path $skills 'scrp-sandbox-execution'
  if (Test-Path $other) {
    "주의: $other 도 있습니다. 같은 일을 하는 예전 Skill이니 끄거나 지우세요."
  }
}
"에이전트를 완전히 껐다 켠 뒤 새 대화에서 쓰세요."
