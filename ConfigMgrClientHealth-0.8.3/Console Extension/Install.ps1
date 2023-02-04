[CmdLetBinding()]
Param(
    [Parameter(Mandatory=$True, HelpMessage='Installation path of ConfigMgr Client Health Console Extension. Default=C:\Program Files (x86)\ConfigMgr Client Health')][String]$Path,
    [Parameter(Mandatory=$True, HelpMessage='Name of the scheduled task configured on the devices to start ConfigMgr Client Health')][String]$ScheduledTaskName,
    [Parameter(Mandatory=$False, HelpMessage='Maximum number of threads running at the same time when running against a collection of devices. Default = 20')][String]$MaxThreads = 20
)

# Trim the '\' from $Path if present
$i = $Path.Length -1
if ($Path.Substring($i) -eq '\') {
    $Path = $Path.Substring(0, $Path.Length -1)
}


#$scriptPath = "$path\Scripts"

Write-Host 'Installing the Configuration Manager Console Extension'
$ExtensionPath = "$($ENV:SMS_ADMIN_UI_PATH)\..\..\XmlStorage\Extensions"

$dir = "$psscriptroot\Extensions\Actions"
$Extensions = Get-ChildItem $dir
foreach ($extension in $Extensions) {
    try {
        $ResourceAssembly = "$Path\ConfigMgr Client Health.dll"
        
        
        $Filename = (Get-ChildItem "$dir\$extension").Name
        Switch -Wildcard ($Filename) {
            "*Device*" {$NewParameter = "-sta -executionpolicy bypass -file `"$Path\Scripts\Start-ConfigMgrClientHealth.ps1`" -Type `"Device`" -Name `"##SUB:Name##`" -ScheduledTask `"$ScheduledTaskName`""}
            "*Collection*" {$NewParameter = "-sta -executionpolicy bypass -file `"$Path\Scripts\Start-ConfigMgrClientHealth.ps1`" -Type `"Collection`" -Name `"##SUB:Name##`" -ScheduledTask `"$ScheduledTaskName`" -MaxThreads $MaxThreads"}
        }
        
        $XmlFile = "$dir\$extension\$Filename"
        [XML]$XML = Get-Content -Path $XmlFile
        $XML.ActionDescription.ImagesDescription.ResourceAssembly.Assembly = $ResourceAssembly
        $XML.ActionDescription.ActionGroups.ActionDescription.Executable.Parameters = $NewParameter
        $XML.Save($XmlFile)
    }
    catch {
        Write-Error "Unable to update XML file with new script path"
    }
}

Copy-Item -Path $dir -Destination $ExtensionPath -Recurse -Force

Write-Host 'Installing the script files for the Console Extension'
if ((Test-Path -Path $Path) -ne $True) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    New-Item -ItemType Directory -Path "$Path\Scripts" -Force | Out-Null
}

Copy-Item -Path "$psscriptroot\ConfigMgr Client Health.dll" -Destination $path -Force

#$dir = "E:\ClientHealth\Console Extension\Scripts"
$dir = "$psscriptroot\Scripts"
#$Scripts = Get-ChildItem $dir

Copy-Item -Path $dir -Destination $Path -Recurse -Force

Get-ChildItem $Path | Unblock-File
Get-ChildItem "$Path\Scripts" | Unblock-File