// Decompiled with JetBrains decompiler
// Type: ClientHealthWebservice.Models.Client
// Assembly: ClientHealthWebservice, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// MVID: 3BFC8FB3-876C-406B-9DDF-70D45BEA9D7D
// Assembly location: E:\_GITHUB\ConfigMgrClientHealth-bis\sources\ConfigMgr Client Health Webservice 2.0.1\bin\ClientHealthWebservice.dll

using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ClientHealthWebservice.Models
{
  [Table("Clients")]
  public class Client
  {
    [Key]
    public string Hostname { get; set; }

    public string OperatingSystem { get; set; }

    public string Architecture { get; set; }

    public string Build { get; set; }

    public string Manufacturer { get; set; }

    public string Model { get; set; }

    public DateTime? InstallDate { get; set; }

    public DateTime? OSUpdates { get; set; }

    public string LastLoggedOnUser { get; set; }

    public string ClientVersion { get; set; }

    public double PSVersion { get; set; }

    public int PSBuild { get; set; }

    public string Sitecode { get; set; }

    public string Domain { get; set; }

    public int MaxLogSize { get; set; }

    public int MaxLogHistory { get; set; }

    public int CacheSize { get; set; }

    public string ClientAuthCertificate { get; set; }

    public string SMSCertificate { get; set; }

    public string ProvisioningMode { get; set; }

    public string DNS { get; set; }

    public string Drivers { get; set; }

    public string Updates { get; set; }

    public string PendingReboot { get; set; }

    public DateTime? LastBootTime { get; set; }

    public double OSDiskFreeSpace { get; set; }

    public string Services { get; set; }

    public string AdminShare { get; set; }

    public string StateMessages { get; set; }

    public string WUAHandler { get; set; }

    public string WMI { get; set; }

    public DateTime? RefreshComplianceState { get; set; }

    public DateTime? ClientInstalled { get; set; }

    public string Version { get; set; }

    public DateTime? Timestamp { get; set; }

    public DateTime? HWInventory { get; set; }

    public string SWMetering { get; set; }

    public string BITS { get; set; }

    public int PatchLevel { get; set; }

    public string ClientInstalledReason { get; set; }

    public string Compliant { get; set; }
    }
}
