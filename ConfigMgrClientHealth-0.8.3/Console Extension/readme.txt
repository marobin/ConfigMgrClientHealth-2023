ConfigMgr console extension to start ConfigMgr Client Health remotely on devices.

This right click tool uses PowerShell to start the ConfigMgr Client Health scheduled task on the device.
Windows Remote Management (WinRM) is required to run on the devices for this to work.

PowerShell installer:
Install.ps1 -Path "C:\Program Files\ConfigMgr Client Health Console Extension" -ScheduledTaskName "ConfigMgr Client Health"

-Path
The path to where the console extension stores its assembly and scripts.

-ScheduledTaskName
The name of the scheduled task configured locally the devices that starts ConfigMgr Client Health.

-MaxThreads
Optional parameter. Configures the maximum number of simultaneous threads when running against a collection of devices. Default value is 20.


NOTE: This extension will not be able to start unless a scheduled task on the client exist to start ConfigMgr Client Health. This console extension simply starts that scheduled task, using PowerShell and WinRM to connect to the computer.