[CmdLetBinding()]
param(
    [Parameter(Mandatory = $True, HelpMessage = 'Installation path of ConfigMgr Client Health Console Extension.')]
    [String]$Path,
    
    [Parameter(Mandatory = $True, HelpMessage = 'Name of the scheduled task configured on the devices to start ConfigMgr Client Health')]
    [String]$ScheduledTaskName,
    
    [Parameter(Mandatory = $False, HelpMessage = 'Maximum number of threads running at the same time when running against a collection of devices. Default = 20')]
    [String]$MaxThreads = 20,
    
    [Parameter(Mandatory = $true, HelpMessage = 'Configuration Manager site code.')]
    [String]$SiteCode
)

# Trim the '\' from $Path if present
$Path = $Path.TrimEnd('\')


$ScriptPath = $MyInvocation.MyCommand.Source
$ScriptParentPath = Split-Path -Path $ScriptPath -Parent
$ScriptName = "$(Split-Path -Path $ScriptPath -Leaf)".Replace('.ps1', '')

Write-Host 'Installing the Configuration Manager Console Extension'
$ExtensionPath = "$($ENV:SMS_ADMIN_UI_PATH)\..\..\XmlStorage\Extensions"

$ActionDir = "$ScriptParentPath\Extensions\Actions"
$Extensions = Get-ChildItem -Path $ActionDir
$ResourceAssembly = "$Path\ConfigMgr Client Health.dll"
foreach ($extension in $Extensions) {
    try {
        $Filename = Get-ChildItem -Path "$ActionDir\$extension" -Filter '*.xml' | Select-Object -ExpandProperty Name
        foreach ($File in $FileName) {
            $XmlFile = "$ActionDir\$extension\$File"
            [XML]$XML = Get-Content -Path $XmlFile -Raw
            $XML.ActionDescription.ImagesDescription.ResourceAssembly.Assembly = $ResourceAssembly
            $ArgumentList = "-sta -executionpolicy bypass -Command `"&amp; {&amp; '$Path\Scripts\ConfigMgrClientHealthExtension.ps1' -ResourceId ##SUB:ResourceID##  -Name '##SUB:Name##' -Namespace '##SUB:__Namespace##'"
            switch -Wildcard ($File) {
                '*Device*' { $ArgumentList = "$ArgumentList -TaskName '$ScheduledTaskName' -Type 'Device'"; break }
                '*Collection*' { $ArgumentList = "$ArgumentList -TaskName '$ScheduledTaskName' -Type 'Collection' -MaxThreads $MaxThreads"; break }
            }
            $xml.ActionDescription.ActionGroups.ActionDescription | ForEach-Object {
                switch -Regex ($_.DisplayName) {
                    'Start' {
                        $ActionType = 'Start'
                    }
                    'Uninstall' {
                        $ActionType = 'Uninstall'
                    }
                }
                $_.Executable.Parameters = "$ArgumentList -$ActionType}`""
            }
            $XML.Save($XmlFile)
        }
    }
    catch {
        Write-Error 'Unable to update XML file with new script path'
    }
}

Copy-Item -Path $ActionDir -Destination $ExtensionPath -Recurse -Force

Write-Host 'Installing the script files for the Console Extension'
if (! (Test-Path -Path $Path)) {
    $null = New-Item -ItemType Directory -Path $Path -Force
    $null = New-Item -ItemType Directory -Path "$Path\Scripts" -Force
}

Copy-Item -Path "$ScriptParentPath\ConfigMgr Client Health.dll" -Destination $path -Force

$ScriptsDir = "$ScriptParentPath\Scripts"

Copy-Item -Path $ScriptsDir -Destination $Path -Recurse -Force

Get-ChildItem -Path $Path -Recurse | Unblock-File