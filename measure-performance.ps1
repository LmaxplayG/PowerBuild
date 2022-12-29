$TIMES = 10
$TOTAL = @()

for ($i = 0; $i -lt $TIMES; $i++) {
    $TOTAL += Measure-Command { .\pwc.ps1 clean }
    $TOTAL += Measure-Command { .\pwc.ps1 clean }
    Write-Host "Run $i of $TIMES"
}

$TOTAL | Measure-Object -Property TotalSeconds -Average -Sum -Maximum -Minimum -StandardDeviation