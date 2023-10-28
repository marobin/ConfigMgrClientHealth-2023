
-----
**Table des matières**

- [ConfigMgr Client Health](#configmgr-client-health)
- [Fonctionnement](#fonctionnement)
- [Déploiement](#déploiement)
	- [Intune](#intune)
	- [GPO](#gpo)
	- [Désinstallation du script via Configuration Manager](#désinstallation-du-script-via-configuration-manager)
- [Sources](#sources)
	- [ConfigMgrClientHealth.ps1](#configmgrclienthealthps1)
	- [Install.ps1](#installps1)
	- [Uninstall.ps1](#uninstallps1)
	- [Config-Client.xml](#config-clientxml)
	- [ConfigMgrClientHealth-Functions.ps1](#configmgrclienthealth-functionsps1)
- [Web Service](#web-service)
	- [Erreur 500](#erreur-500)
- [Rapport](#rapport)
	- [Colonnes affichées](#colonnes-affichées)
	- [Autres champs disponibles](#autres-champs-disponibles)

----
# ConfigMgr Client Health

Script de remédiation du client Configuration Manager.

**Script**  : ConfigMgrClientHealth.ps1  
**Version** : 1.1  

Les sources à jour se trouvent à cet emplacement : `\\SRV\CMClientHealth$`  

Ce script est basé sur le travail d'Anders Rodland : [ConfigMgr Client Health 0.8.3](https://github.com/AndersRodland/ConfigMgrClientHealth/raw/master/Download/ConfigMgrClientHealth-0.8.3.zip)    

La documentation officielle et complète se trouve [sur le site du développeur](https://www.andersrodland.com/configmgr-client-health/).  
  
:memo: La base de donnée 0.7.5 est requise pour les scripts en version 0.8.3 et supérieur.  
  

# Fonctionnement

Le script est lancé via une tâche planifiée "**ConfigMgr Client Health - Client**", elle-même déclenchée lors d'une connexion au réseau CORP.  
Ceci est possible en souscrivant à l'événement **ID 10000** du journal "**Microsoft-Windows-NetworkProfile/Operational**".  
  
Le script règle autant de problèmes connus que possible avant d'envoyer un rapport à un Web Service (https://SRV/ConfigMgrClientHealth).  
Le Web Service se charge ensuite d'enregistrer ces données dans une base de donnée sur le serveur **SQL...** nommée **ClientHealth** en utilisant le compte de service **SVC_CM_HEALTH**.   
  
Cette base de donnée sert ensuite à produire un rapport montrant le résultat des exécutions du script sur chaque machine (voir [Rapport](#rapport))  
  
Un log est créé sur chaque machine dans le dossier suivant : **C:\ProgramData\ConfigMgrClientHealth\Logs**.  
  
  
# Déploiement

## Intune
Le script a été déployé en tant que Windows app (Win32) via Intune avec le nom **Configuration Manager Client Health**.  
  
Cette application est déployée en obligatoire sur le groupe Azure AD **G-OS-CONFIGMGR-CLIENT-REMEDIATION**.  
Les membres de ce groupe sont synchronisés depuis un regroupement Configuration Manager nommé "**CH_ClientVersion-RemediationNeeded-CORP**" (_\Assets and Compliance\Overview\Device Collections\Operational\Client Health_).  

> :warning: Le workload de Co-management "**Client apps**" doit être attribué à Intune pour que cela fonctionne.  
> En revanche, les appareils ciblés n'ont pour la plupart aucun client Configuration Manager.  
> Ces appareils ne seront probablement pas en mesure d'installer l'application via Intune étant donné qu'ils ne peuvent pas récupérer l'attribution du workload.  


> :memo: Ligne de commande utilisée pour créer le fichier .intunewin : 
> **IntuneWinAppUtil.exe -c "`<Dossier source>`" -s "`<Dossier source>`\ConfigMgrClientHealth-1.1-Full.txt" -o "c:\temp\ClientHealth" -q**

## GPO
Le script est également déployé via la GPO `MCH-INSTALL-ConfigMgrClientHealth` sur l'OU "**OU=COMPUTERS,OU=INFRA,DC=domain,DC=com**".  
Les sources utilisées se trouvent à l'emplacement suivant : `\\domain.com\SysVol\domain.com\Policies\{D72277D4-280E-4527-83DD-478879DBECEC}\Machine\Scripts\ConfigMgrClientHealth`.  

  
Cette GPO utilise un filtre WMI afin de ne cibler que les machines Windows 10 et 11 : 
```sql
SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "10.%"
SELECT * FROM Win32_OperatingSystem WHERE NOT Caption LIKE "%Server%"
```

> :memo: En mettant les sources dans le Sysvol, on s'assure que le contenu sera répliqué sur les RODC.  
```powershell
$SysvolPath = 'SYSVOL\domain.com\Policies\{D72277D4-280E-4527-83DD-478879DBECEC}\Machine\Scripts\ConfigMgrClientHealth'

Get-ADForest | 
	Select-Object -ExpandProperty GlobalCatalogs | 
	Where-Object {
		(Test-Connection -ComputerName $_ -Count 1 -Quiet) `
		-and -not (Test-Path -Path "\\$_\$SysvolPath")
	}
```
  
Le groupe AD `G-SCCM-CLIENT-REMEDIATION-EXCLUDE` permet de refuser l'application de la GPO sur certaines machines.  
  
> :memo: L'installation du script peut être suivi pour les machines ayant accès au réseau CORP au moment de l'installation via ce log : 
> `\\domain.com\CMClientHealth$\Logs\GPODeployment.log`
  

## Désinstallation du script via Configuration Manager
Une fois le client réparé, il est préférable de supprimer la tâche planifiée sur les machines en utilisant le script Configuration Manager `Uninstall ConfigMgr Client Health Script`.  
  
  
# Sources
## ConfigMgrClientHealth.ps1

Ceci est le script principal lancé par la tâche planifiée créée sur chaque machine.  
  
Voir la [documentation officielle](https://www.andersrodland.com/configmgr-client-health/) pour avoir des détails à propos des paramètres du script.  
  
1. Vérifie que le client est requis sur la machine
   * Le client est déjà installé
   * Les flags de CoManagement Intune sont configurés
   * L'appareil est joint à Azure AD en mode hybride
    :warning: **La tâche planifiée est supprimée et le script se termine si aucune des conditions ci-dessus n'est respectée.**
2. Le script est-il exécuté avec une élévation de droits? Arrêt du script si c'est le cas.
3. Une séquence de tâches est-elle en cours? Arrêt du script si c'est le cas.
4. L'ordinateur a-t-il été redémarré depuis la dernière exécution? Arrêt du script dans le cas contraire.
5. Vérifie la taille des logs.
6. Création d'un objet qui permet de tracer l'évolution des différents tests. Cet objet sera envoyé au WebService.
7. Vérifie si la base de données SQL peut être contactée directement. (voir [Config-Client.xml](#config-clientxml)).
8. Vérifie la cohérence de la base WMI. Exécute une réparation si besoin.
9. Vérifie si le client est déjà installé. Lance l'installation si ce n'est pas le cas.
10. Vérifie la version du client. Réinstallation si cette version est inférieure à la version requise (voir [Config-Client.xml](#config-clientxml)).
11. Vérification de l'état des services Windows (voir [Config-Client.xml](#config-clientxml)).
12. Vérification du code site du client (voir [Config-Client.xml](#config-clientxml)).
13. Vérification de la taille du cache (voir [Config-Client.xml](#config-clientxml)).
14. Retire le client de mode de provision ([Provisioning Mode](https://learn.microsoft.com/en-us/mem/configmgr/osd/understand/provisioning-mode)) le cas échéant.
15. Vérifie qu'il n'y ait pas d'erreur de certificat dans le log `ClientIDManagerStartup.log` et y remédie si besoin.
16. Vérifie l'inventaire matériel.
17. Vérifie l'état du "Software Metering Driver" (mtrmgr.log).
18. Vérification et réparation des enregistrements DNS si besoin.
19. Vérification et remédiation du service BITS si besoin.
20. Vérification de la configuration de l'agent.
21. Vérification des composants de stratégie (registry.pol) et de mise à jour (WUAHandler.log).
22. Vérification de l'état du magasin de mise à jour.
23. Vérification de l'état des partages administratifs (Admin$ and C$)
24. Vérifie qu'il n'y ait pas de pilote manquant ou mal installé.
25. Met à jour l'appareil (wusa.exe) si paramétré dans [Config-Client.xml](#config-clientxml).
26. Vérification de l'espace disque (voir [Config-Client.xml](#config-clientxml)).
27. Envoi des messages d'état non envoyés ([state messages](https://learn.microsoft.com/en-us/troubleshoot/mem/configmgr/update-management/state-messaging-description)).
28. Redémarrage du service `ccmexec` si besoin.
29. Suppression des éléments orphelins dans le cache du client (ccmcache).
30. Réinstallation du client si besoin (WMI corrompu, mauvaise version).
31. Exécution de la tâche planifiée native "ClientHealth".
32. Mise à jour de la date d'exécution du script dans le registre.
33. Mise à jour de la base de donnée directement ou via le WebService.



## Install.ps1

1. Création du dossier **C:\ProgramData\ConfigMgrClientHealth** et du sous-dossier **Logs**.
2. Suppression des acls des utilisateurs standard sur le dossier (`Utilisateurs` et `Utilisateurs authentifiés`).
3. Copie des scripts, dossier CMClient (contenant les sources d'installation du client) et du fichier `Config-Client.xml` (Tâche planifiée).
4. Modification de `Config-Client.xml` pour paramétrer l'action de la tâche planifiée.
5. Création de la tâche planifiée

## Uninstall.ps1

1. Sauvegarde des logs **C:\ProgramData\ConfigMgrClientHealth\Logs** dans **C:\Windows\Temp**.
2. Suppression de la tâche planifiée.
3. Suppression du dossier d'installation **C:\ProgramData\ConfigMgrClientHealth**.

## Config-Client.xml

Fichier de configuration utilisé par le script.  
  
Il est composés de 7 parties : 
- **LocalFiles** : Chemin des sources locales
- **Client** : Paramètres du client à vérifier
- **ClientInstallationProperty** : Paramètres à passer à `ccmsetup.exe`
- **Log** : Paramétrage de la journalisation
- **Option** : Options diverses du script
- **Service** : Configuration des services Windows à vérifier/appliquer
- **Remediation** : Composants à vérifier/réparer

```xml
<?xml version="1.0" encoding="utf-8"?>
<Configuration>
	<LocalFiles>C:\ProgramData\ClientHealth</LocalFiles> <!-- Path locally on computer for temporary files and local clienthealth.log if LocalLogFile="True" -->
	<Client Name="Version">5.00.9078.1025</Client>
	<Client Name="SiteCode"></Client>
	<Client Name="Domain">domain.com</Client>
	<Client Name="AutoUpgrade">True</Client>
	<Client Name="Share"></Client>
	<Client Name="CacheSize" Value="10240" DeleteOrphanedData="True" Enable="True" />
	<Client Name="Log" MaxLogSize="4096" MaxLogHistory="2" Enable="True" />
	<ClientInstallProperty>/noservice</ClientInstallProperty>
	<ClientInstallProperty>SMSSITECODE=</ClientInstallProperty>
	<ClientInstallProperty>CCMHOSTNAME=DOMAIN.CLOUDAPP.NET/CCM_Proxy_MutualAuth/72057594037927974</ClientInstallProperty>
	<ClientInstallProperty>/mp=SRV.domain.com</ClientInstallProperty>
	<ClientInstallProperty>SMSMP=https://SRV.domain.com</ClientInstallProperty>
	<ClientInstallProperty>/Source:C:\ProgramData\ConfigMgrClientHealth\CMClient</ClientInstallProperty>
	<ClientInstallProperty>/NoCRLCheck</ClientInstallProperty>
	<ClientInstallProperty>/UsePKICert</ClientInstallProperty>
	<ClientInstallProperty>DNSSUFFIX=domain.com</ClientInstallProperty>
	<Log Name="File" Share="" Level="Full" MaxLogHistory="8" LocalLogFile="True" Enable="True" /> <!-- Level: Full = everything. ClientInstall = only if installation of sccm agent fails.  -->
	<Log Name="SQL" Server="SRV-SQL.domain.com" Enable="True" />
	<Log Name="Time" Format="ClientLocal" /> <!-- Valid formats: ClientLocal / UTC  -->
	<Option Name="CcmSQLCELog" Enable="False" /> <!-- Optional check on the ConfigMgr agent if local database is corrupt -->
	<Option Name="BITSCheck" Fix="True" Enable="True" />
	<Option Name="ClientSettingsCheck" Fix="True" Enable="True" />
	<Option Name="DNSCheck" Fix="True" Enable="True" />
	<Option Name="Drivers" Enable="True" />
	<Option Name="Updates" Share="" Fix="True" Enable="False" />
	<Option Name="PendingReboot" StartRebootApplication="False" Enable="True" />
	<Option Name="RebootApplication" Application="\\SRV.domain.com\ClientHealth$\RebootApp\shutdowntool.exe /t:7200 /m:1440" Enable="False" />
	<Option Name="MaxRebootDays" Days="7" Enable="True" />
	<Option Name="OSDiskFreeSpace">10</Option>
	<Option Name="HardwareInventory" Days="7" Fix="True" Enable="True" />
	<Option Name="SoftwareMetering" Fix="True" Enable="True" />
	<Option Name="WMI" Fix="True" Enable="True"/>
	<Option Name="RefreshComplianceState" Days="7" Enable="True"/>
	<Service Name="BITS" StartupType="Automatic (Delayed Start)" State="Running" Uptime=""/>
	<Service Name="winmgmt" StartupType="Automatic" State="Running" Uptime=""/>
	<Service Name="wuauserv" StartupType="Automatic (Delayed Start)" State="Running" Uptime=""/>
	<Service Name="lanmanserver" StartupType="Automatic" State="Running" Uptime=""/>
	<Service Name="RpcSs" StartupType="Automatic" State="Running" Uptime=""/>
	<Service Name="W32Time" StartupType="Automatic" State="Running" Uptime=""/>
	<Service Name="ccmexec" StartupType="Automatic (Delayed Start)" State="Running" Uptime="" />
	<Remediation Name="AdminShare" Fix="True" />
	<Remediation Name="ClientProvisioningMode" Fix="True" />
	<Remediation Name="ClientStateMessages" Fix="True" />
	<Remediation Name="ClientWUAHandler" Fix="True"  Days="30"/>
	<Remediation Name="SMSCertificate" Fix="True" />
</Configuration>

```

> :memo: Références concernant l'installation du client :
> - [How to deploy clients to Windows computers in Configuration Manager](https://learn.microsoft.com/en-us/mem/configmgr/core/clients/deploy/deploy-clients-to-windows-computers)
> - [About client installation parameters and properties in Configuration Manager](https://learn.microsoft.com/en-us/mem/configmgr/core/clients/deploy/about-client-installation-properties?source=recommendations)
> - [Install and assign Configuration Manager clients using Azure AD for authentication](https://learn.microsoft.com/en-us/mem/configmgr/core/clients/deploy/deploy-clients-cmg-azure)
> - [Intune MDM-managed Windows devices](https://learn.microsoft.com/en-us/mem/configmgr/core/clients/deploy/deploy-clients-to-windows-computers#bkmk_mdm)
> - [Microsoft Intune MDM installation](https://learn.microsoft.com/en-us/mem/configmgr/core/clients/deploy/plan/client-installation-methods#microsoft-intune-mdm-installation)
> - [Token-based authentication for cloud management gateway](https://learn.microsoft.com/en-us/mem/configmgr/core/clients/deploy/deploy-clients-cmg-token)



## ConfigMgrClientHealth-Functions.ps1

Ce script contient toutes les fonctions utilisées par le script principal.  

# Web Service
  
## Erreur 500 
  
Activer les erreurs détaillées dans le fichier web.config  
```xml
<configuration>
  <system.web>
	<customErrors mode="Off"/>
  </system.web>
</configuration>
```

> Erreur :  
> The current identity (`<Domain>\<UserName>`) does not have write access to 'C:\WINDOWS\Microsoft.NET\Framework\v4.0.30319\Temporary ASP.NET Files'  
>  
> Résolution :  
> **C:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_regiis.exe -ga `<Domain>\<UserName>`**  


# Rapport

Le rapport est disponible dans la console Configuration Manager dans le noeud "**Monitoring\Reports**" : "**\CM Client Health Detailed Report-2016".**  

Il est également disponible directement à partir de [ce lien](https://srv/Reports_SSRS/report/ConfigMgr_/CM%20Client%20Health%20Detailed%20Report-2016).  

## Colonnes affichées

|Colonne|SQL|Description|Valeurs possibles|
|-------|-----|-----------|-----------------|
|Hostname|`Hostname`| Nom de la machine ||
|Last Run|`Timestamp`| Dernière exécution du script||
|Operating System|`OperatingSystem` (`Architecture`)|Nom du système d'exploitation||
|Build|`Build`| Version de l'OS||
|Model|[`Manufacturer`] `Model`| Fabricant et modèle de la machine||
|Install Date|`InstallDate`|Date de masterisation du poste||
|Last Logged On User|`LastLoggedOnUser`|Dernier utilisateur connecté||
|Client Installed |`ClientInstalled`|Date d'installation du client par le script| |
|Client Version |`ClientVersion`|Version du client||
|ClientInstalledReason |`ClientInstalledReason`|Raison de l'installation du client par le script| - ConfigMgr Client database files missing (%WINDIR%\CCM\*.sdf).</br>- ConfigMgr Client database corrupt (CcmSQLCELog).</br>- Service not running, failed to start (ccmexec)</br>- Failed to connect to SMS_Client WMI class (root/ccm:SMS_Client).</br>- No agent found.</br>- Corrupt WMI.</br>- Below minimum verison.</br>- Upgrade failed.</br> |
|Pending Reboot |`PendingReboot`|Redémarrage en attente | Compliant</br>Pending Reboot|
|Last Boot Time |`LastBootTime`|Dernier redémarrage ||
|Sitecode |`Sitecode`|Code site actuel| |
|Domain|`Domain`|Domaine lié à la machine||
|WMI |`WMI`|Etat de la base WMI| Compliant</br>Repaired</br>Corrupt</br>PolicyPlatform Recompiled.|
|DNS |`DNS`|Etat des enregistrements DNS| Repaired</br>Skipped</br>Compliant|
|SMS Certificate |`SMSCertificate`|Etat des certificats SMS du client| Compliant</br>Missing</br>Server rejected registration |
|Provisioning Mode |`ProvisioningMode`|Mode de provisionnement| Compliant</br>Repaired|
|Drivers |`Drivers`|Etat des pilotes| Compliant</br><number> unknown or faulty driver(s)|
|OSDisk Free Space |`OSDiskFreeSpace`|Espace disque restant (GB)| -1 (WMI issue)</br>free disk space|
|Patch Level|`PatchLevel`|Numéro URB||
|WUAHandler |`WUAHandler`|Etat du composant de mise à jour| Compliant</br>Checking</br>Broken (WUAHandler Log)</br>Broken (File Age)</br>Broken (Event Log)</br>Repaired (WUAHandler Log)</br>Repaired (File Age)</br>Repaired (Event Log) |
|Admin Share |`AdminShare`|Etat des partages administratifs| Compliant</br>Repaired|
|Services |`Services`|Etat des services| Compliant</br>Started</br>Restarted|
|BITS |`BITS`|Etat du service BITS| Compliant</br>Remediated</br>Error</br>PS Module BitsTransfer missing|
|State Messages |`StateMessages`|Etat des messages d'état| Compliant</br>Repaired|
|Hardware Inventory |`HWInventory`|Date du dernier inventaire matériel||
|PS Version |`PSVersion`|Version PowerShell||
|Script Version |`Version`|Version du script| Script version|

## Autres champs disponibles

|Champ|Description|Valeurs possibles|
|-------|-----------|-----------------|
|`MaxLogSize` |Taille actuelle maximale des logs cm| |
|`MaxLogHistory` |Nombre actuel maximal de logs cm| |
|`CacheSize` |Taille du cache cm actuel| |
|`ClientSettings` |Stratégies de paramètres client (CCM_ClientAgentConfig) | Compliant</br>Remediated</br>Error|
|`RefreshComplianceState` |Date de rafraichissement de la conformité du client pour les mises à jour | date|
|`OSUpdates` |Date de la dernière mise à jour du système| |
|`Updates` |Etat des mises à jour| Compliant</br>Failed</br><Log Entry> (KB)|
|`RebootApp` |Date de redémarrage initié par le script (voir [Config-Client.xml](#config-clientxml))| |
|`SWMetering` |Date du dernier inventaire logiciel| Compliant</br>Remediated</br>Error|