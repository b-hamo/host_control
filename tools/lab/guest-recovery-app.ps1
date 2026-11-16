param([Parameter(Mandatory=$true)][ValidatePattern('^SES-[a-f0-9]{32}$')][string]$Session)
$ErrorActionPreference='Stop'
$ctx=[IO.File]::ReadAllText('C:\RunnerPackage\guest-context.json')|ConvertFrom-Json
if($ctx.session_id -ne $Session){throw 'Wrong recovery app session'}
$output=$ctx.output_path
$marker='C:\RunnerLogs\recovery-app-start.json'
if(Test-Path -LiteralPath $marker){throw 'Recovery app already started; never replay'}
[IO.File]::WriteAllText($marker,(@{session=$Session;pid=$PID;execution_count=1;output=$output}|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
Add-Type -AssemblyName System.Windows.Forms,System.Drawing
$form=[Windows.Forms.Form]::new()
$form.Text='SCRP recovery '+$Session
$form.ClientSize=[Drawing.Size]::new(680,300)
$box=[Windows.Forms.TextBox]::new()
$box.Location=[Drawing.Point]::new(20,80)
$box.Size=[Drawing.Size]::new(630,50)
$box.Font=[Drawing.Font]::new('Malgun Gothic',20)
$button=[Windows.Forms.Button]::new()
$button.Text='Save preserved app Output'
$button.Location=[Drawing.Point]::new(20,160)
$button.Size=[Drawing.Size]::new(320,60)
$button.Add_Click({
 $path=Join-Path $output 'runner-recovery-app.txt'
 if(Test-Path -LiteralPath $path){$form.Text='Already saved; no overwrite';return}
 [IO.File]::WriteAllText($path,($Session+'|'+$PID+'|'+$box.Text),[Text.UTF8Encoding]::new($false))
 $form.Text='Saved same surviving app; PID '+$PID
})
$form.Controls.AddRange(@($box,$button))
[void]$form.ShowDialog()
