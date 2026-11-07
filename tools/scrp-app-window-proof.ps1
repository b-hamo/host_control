param([Parameter(Mandatory=$true)][ValidateSet('B','C')][string]$Slot,
      [Parameter(Mandatory=$true)][ValidatePattern('^SES-[a-f0-9]{32}$')][string]$Session)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$output='C:\RunnerWorkspace\Sessions\session-'+$Session+'\runtime-RT-SBX-001\generation-1\output'
if(-not(Test-Path -LiteralPath $output)){throw 'This session Output directory does not exist'}
$form=New-Object Windows.Forms.Form
$form.Text='SCRP '+$Slot+' - '+$Session
$form.Size=New-Object Drawing.Size(780,320)
$form.StartPosition='Manual'
$form.Location=New-Object Drawing.Point(20,20)
$label=New-Object Windows.Forms.Label
$label.Text='Session '+$Slot+': enter Korean text, then save to this session Output.'
$label.Location=New-Object Drawing.Point(20,20)
$label.Size=New-Object Drawing.Size(720,40)
$text=New-Object Windows.Forms.TextBox
$text.Location=New-Object Drawing.Point(20,80)
$text.Size=New-Object Drawing.Size(720,45)
$text.Font=New-Object Drawing.Font('Malgun Gothic',18)
$button=New-Object Windows.Forms.Button
$button.Text='Save '+$Slot+' result'
$button.Location=New-Object Drawing.Point(20,150)
$button.Size=New-Object Drawing.Size(260,60)
$button.Add_Click({
 $value=$Slot+'|'+$Session+'|'+$text.Text
 [IO.File]::WriteAllText((Join-Path $output 'same-name.txt'),$value,(New-Object Text.UTF8Encoding($false)))
 $form.Close()
})
$form.Controls.AddRange(@($label,$text,$button))
$form.Add_Shown({$text.Focus()})
[void]$form.ShowDialog()
Write-Output ('completed='+$Slot+';session='+$Session)
