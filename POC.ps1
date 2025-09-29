$user = $env:USERNAME

For($i=0;$i -lt 200; $i++)
{
$meh ="_pwned.txt"
Write-Host "PWNED!!! $i" -ForegroundColor Cyan
$file = "C:\users\$user\Desktop\" + $i +$meh
echo "Pwned!" > $file
}
sleep -Seconds 60
exit 1
