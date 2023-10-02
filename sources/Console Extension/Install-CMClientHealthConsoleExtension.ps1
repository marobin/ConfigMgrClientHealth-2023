[CmdLetBinding()]
Param(
    [Parameter(Mandatory = $True, HelpMessage = 'Installation path of ConfigMgr Client Health Console Extension. Default=C:\Program Files (x86)\ConfigMgr Client Health')]
    [String]$Path,
    
    [Parameter(Mandatory = $True, HelpMessage = 'Name of the scheduled task configured on the devices to start ConfigMgr Client Health')]
    [String]$ScheduledTaskName,
    
    [Parameter(Mandatory = $False, HelpMessage = 'Maximum number of threads running at the same time when running against a collection of devices. Default = 20')]
    [String]$MaxThreads = 20,
    
    [Parameter(Mandatory = $true, HelpMessage = 'Configuration Manager site code.')]
    [String]$SiteCode
)

# Trim the '\' from $Path if present
$Path = $Path.TrimEnd("\")

$ScriptRoot = $PSScriptRoot
Write-Host 'Installing the Configuration Manager Console Extension'
$ExtensionPath = "$($ENV:SMS_ADMIN_UI_PATH)\..\..\XmlStorage\Extensions"

$ActionDir = "$ScriptRoot\Extensions\Actions"
$Extensions = Get-ChildItem -Path $ActionDir
$ResourceAssembly = "$Path\ConfigMgr Client Health.dll"
foreach ($extension in $Extensions) {
    try {
        $Filename = Get-ChildItem -Path "$ActionDir\$extension" -Filter '*.xml' | Select-Object -ExpandProperty Name
        foreach ($File in $FileName) {
            $XmlFile = "$ActionDir\$extension\$File"
            [XML]$XML = Get-Content -Path $XmlFile -Raw
            $XML.ActionDescription.ImagesDescription.ResourceAssembly.Assembly = $ResourceAssembly

            $ArgumentList = "-sta -executionpolicy bypass -file `"$Path\Scripts\ConfigMgrClientHealthExtension.ps1`" -ResourceId `"##SUB:ResourceID##`" -SiteCode `"##SUB:SiteCode##`""
            Switch -Wildcard ($File) {
                '*Device*' { $ArgumentList = "$ArgumentList -TaskName `"$ScheduledTaskName`" -Type `"Device`"" }
                '*Collection*' { $ArgumentList = "$ArgumentList -TaskName `"$ScheduledTaskName`" -Type `"Collection`" -MaxThreads $MaxThreads" }
            }
            $xml.ActionDescription.ActionGroups.ActionDescription | ForEach-Object {
                Switch -Regex ($_.DisplayName) {
                    'Start' {
                        $ActionType = 'Start'
                    }
                    'Uninstall' {
                        $ActionType = 'Uninstall'
                    }
                }
                $_.Executable.Parameters = "$ArgumentList -$ActionType"
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

Copy-Item -Path "$ScriptRoot\ConfigMgr Client Health.dll" -Destination $path -Force

$ScriptsDir = "$ScriptRoot\Scripts"

Copy-Item -Path $ScriptsDir -Destination $Path -Recurse -Force

Get-ChildItem -Path $Path -Recurse | Unblock-File