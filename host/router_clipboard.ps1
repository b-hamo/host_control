$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
if ($env:USERNAME -ne 'WDAGUtilityAccount') { throw 'Guest account required' }
Add-Type -TypeDefinition 'using System.Runtime.InteropServices; public static class RouterClipboard { [DllImport("user32.dll")] public static extern uint GetClipboardSequenceNumber(); }'
$before = [RouterClipboard]::GetClipboardSequenceNumber()
$text = [string](Get-Clipboard -Raw)
$after = [RouterClipboard]::GetClipboardSequenceNumber()
if ($before -ne $after) { throw 'Clipboard changed during capture' }
if ($text.Length -gt 65536) { throw 'Clipboard exceeds limit' }
@{ contract = 'router-clipboard-v1'; sequence = $after; text = $text; user = $env:USERNAME; computer = $env:COMPUTERNAME } | ConvertTo-Json -Compress
