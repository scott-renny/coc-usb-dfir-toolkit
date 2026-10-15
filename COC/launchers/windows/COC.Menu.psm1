#Requires -Version 5.1
# Layout adapted from USB #1's published Version 9 console design.
$script:CocFrameWidth=70
function Get-CocConsoleWidth {
    try {$w=$Host.UI.RawUI.WindowSize.Width;if($w -gt 0){return [int]$w}}catch{}
    return 80
}
function Get-CocMenuLayout {
    param([int]$Columns=0,[int]$Rows=0,[int]$ContentHeight=30)
    if($Columns -le 0){$Columns=Get-CocConsoleWidth}
    if($Rows -le 0){try{$Rows=$Host.UI.RawUI.WindowSize.Height}catch{$Rows=0}}
    $left=[Math]::Min(200,[Math]::Max(0,[int][Math]::Floor(($Columns-70)/2)))
    $top=if($Rows -gt 0){[Math]::Min(100,[Math]::Max(0,[int][Math]::Floor(($Rows-$ContentHeight)/2)))}else{0}
    [pscustomobject]@{Left=$left;Top=$top;FrameWidth=70;Columns=$Columns;Rows=$Rows}
}
function Format-CocCentered {
    param([string]$Text,[int]$Width=80)
    if($Width -lt 1){throw 'Console width must be positive'}
    foreach($line in ($Text -split "`r?`n")){
        if($line.Length -eq 0){'';continue}
        $remaining=$line.Trim()
        while($remaining.Length -gt $Width){
            $cut=$remaining.LastIndexOf(' ',$Width-1)
            if($cut -lt 1){$cut=$Width}
            $part=$remaining.Substring(0,$cut).TrimEnd()
            (' '*[Math]::Max(0,[int][Math]::Floor(($Width-$part.Length)/2)))+$part
            $remaining=$remaining.Substring($cut).TrimStart()
        }
        (' '*[Math]::Max(0,[int][Math]::Floor(($Width-$remaining.Length)/2)))+$remaining
    }
}

function Write-CocFrameLine {
    param([string]$Text='',[ConsoleColor]$ForegroundColor=[ConsoleColor]::Cyan)
    $layout=Get-CocMenuLayout
    Microsoft.PowerShell.Utility\Write-Host ((' '*$layout.Left)+$Text) -ForegroundColor $ForegroundColor
}
function Write-CocCentered {
    param([Parameter(Position=0)][AllowEmptyString()][string]$Text='', [ConsoleColor]$ForegroundColor=[ConsoleColor]::Cyan)
    foreach($line in @(Format-CocCentered $Text 70)){Write-CocFrameLine $line -ForegroundColor $ForegroundColor}
}
function Get-CocLogoLines {
    return @('                         .-----------------.','                         \   o---.    o    /','                          \      \---/    /','                           \  o---+      /','                            \     o     /','                             \   COC   /','                              \_______/')
}
function Write-CocMenuHeader {
    param([string]$Title,[string]$Subtitle='USB 02 - FORENSICS / INCIDENT RESPONSE',[int]$ContentHeight=21)
    if($Title -eq 'MAIN MENU'){$ContentHeight=30}
    try{$Host.UI.RawUI.BackgroundColor=[ConsoleColor]::Black;$Host.UI.RawUI.ForegroundColor=[ConsoleColor]::Cyan}catch{}
    Clear-Host
    $layout=Get-CocMenuLayout -ContentHeight $ContentHeight
    for($i=0;$i -lt $layout.Top;$i++){Microsoft.PowerShell.Utility\Write-Host ''}
    Write-CocFrameLine ''
    foreach($line in @(Get-CocLogoLines)){Write-CocFrameLine $line}
    Write-CocFrameLine ''
    Write-CocFrameLine ('='*70)
    if($Title -eq 'MAIN MENU'){
        Write-CocCentered 'CYBERSECURITY OPERATIONS CENTER'
        Write-CocCentered 'COC TECHNICIAN CONTROL CENTER'
        Write-CocCentered $Subtitle
    }else{Write-CocCentered $Title}
    Write-CocFrameLine ('='*70)
    Write-CocFrameLine ''
}
function Write-CocMenuOptions {
    param([string[]]$Options)
    foreach($option in $Options){
        if($option -match '^0[. ]'){Write-CocFrameLine ''}
        $remaining=$option.Trim()
        while($remaining.Length -gt 68){
            $cut=$remaining.LastIndexOf(' ',67);if($cut -lt 1){$cut=68}
            Write-CocFrameLine ('  '+$remaining.Substring(0,$cut).TrimEnd())
            $remaining=$remaining.Substring($cut).TrimStart()
        }
        Write-CocFrameLine ('  '+$remaining)
    }
    Write-CocFrameLine ''
}
function Read-CocPrompt {
    param([string]$Prompt)
    $layout=Get-CocMenuLayout
    return (Read-Host ((' '*$layout.Left)+$Prompt))
}
Export-ModuleMember -Function Get-CocConsoleWidth,Get-CocMenuLayout,Get-CocLogoLines,Format-CocCentered,Write-CocCentered,Write-CocMenuHeader,Write-CocMenuOptions,Read-CocPrompt
