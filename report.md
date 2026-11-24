# sigma2wazuh report (2026-11-24)

Converted 183 Sigma rules into 249 Wazuh rules; skipped 68.

## Converted

| Wazuh IDs | Level | ATT&CK | Sigma rule |
|---|---|---|---|
| 101000 | 8 | T1134.001 | Potential Access Token Abuse (`win_security_access_token_abuse.yml`) |
| 101001 | 5 | T1078.001 T1078.002 T1078.003 | Admin User Remote Logon (`win_security_admin_rdp_login.yml`) |
| 101002 | 13 |  | DiagTrackEoP Default Login Username (`win_security_diagtrack_eop_default_login_username.yml`) |
| 101003 | 5 | T1098 | A Member Was Added to a Security-Enabled Global Group (`win_security_member_added_security_enabled_global_group.yml`) |
| 101004 | 5 | T1098 | A Member Was Removed From a Security-Enabled Global Group (`win_security_member_removed_security_enabled_global_group.yml`) |
| 101005 | 11 | T1550.002 | Successful Overpass the Hash Attempt (`win_security_overpass_the_hash.yml`) |
| 101006-101007 | 8 | T1550.002 | Pass the Hash Activity 2 (`win_security_pass_the_hash_2.yml`) |
| 101008 | 11 | T1021.001 | RDP Login from Localhost (`win_security_rdp_localhost_login.yml`) |
| 101009 | 5 | T1098 | A Security-Enabled Global Group Was Deleted (`win_security_security_enabled_global_group_deleted.yml`) |
| 101010 | 8 | T1078 T1110 T1133 | External Remote RDP Logon from Public IP (`win_security_successful_external_remote_rdp_login.yml`) |
| 101011 | 11 | T1078 T1110 T1133 | External Remote SMB Logon from Public IP (`win_security_successful_external_remote_smb_login.yml`) |
| 101012 | 8 | T1078 T1133 T1190 | Failed Logon From Public IP (`win_security_susp_failed_logon_source.yml`) |
| 101013 | 5 | T1550 | Outgoing Logon with New Credentials (`win_security_susp_logon_newcredentials.yml`) |
| 101014 | 11 | T1548 | Potential Privilege Escalation via Local Kerberos Relay over LDAP (`win_security_susp_privesc_kerberos_relay_over_ldap.yml`) |
| 101015 | 11 | T1557.001 | RottenPotato Like Attack Pattern (`win_security_susp_rottenpotato.yml`) |
| 101016 | 5 | T1047 | Successful Account Login Via WMI (`win_security_susp_wmi_login.yml`) |
| 101017 | 11 | T1098 | Powerview Add-DomainObjectAcl DCSync AD Extend Right (`win_security_account_backdoor_dcsync_rights.yml`) |
| 101018-101019 | 11 | T1087.002 | AD Privileged Users or Groups Reconnaissance (`win_security_account_discovery.yml`) |
| 101020 | 13 | T1222.001 | AD Object WriteDAC Access (`win_security_ad_object_writedac_access.yml`) |
| 101021 | 8 | T1003.006 | Suspicious Machine Account Replication - DcSync Indicator (`win_security_ad_replication_machine_account.yml`) |
| 101022 | 8 | T1003.006 | Active Directory Replication from Non Machine Account - DcSync Indicator (`win_security_ad_replication_non_machine_account.yml`) |
| 101023 | 8 | T1087.002 | Potential AD User Enumeration From Non-Machine Account (`win_security_ad_user_enumeration.yml`) |
| 101024-101025 | 5 |  | ADCS Certificate Template Configuration Vulnerability (`win_security_adcs_certificate_template_configuration_vulnerability.yml`) |
| 101026-101027 | 11 |  | ADCS Certificate Template Configuration Vulnerability with Risky EKU (`win_security_adcs_certificate_template_configuration_vulnerability_eku.yml`) |
| 101028 | 5 | T1207 | Add or Remove Computer from DC (`win_security_add_remove_computer.yml`) |
| 101029 | 5 | T1021.002 | Access To ADMIN$ Network Share (`win_security_admin_share_access.yml`) |
| 101030 | 11 | T1098 | Enabled User Right in AD to Control User Objects (`win_security_alert_active_directory_user_control.yml`) |
| 101031-101034 | 11 | T1098 | Active Directory User Backdoors (`win_security_alert_ad_user_backdoors.yml`) |
| 101035-101037 | 11 | T1562 | Weak Encryption Enabled and Kerberoast (`win_security_alert_enable_weak_encryption.yml`) |
| 101038-101039 | 11 | T1059 T1087 T1114 T1550.002 | Hacktool Ruler (`win_security_alert_ruler.yml`) |
| 101040-101041 | 11 | T1070.001 | Security Eventlog Cleared (`win_security_audit_log_cleared.yml`) |
| 101042 | 8 | T1123 | Processes Accessing the Microphone and Webcam (`win_security_camera_microphone_access.yml`) |
| 101043-101046 | 11 | T1021.002 T1543.003 T1569.002 | CobaltStrike Service Installations - Security (`win_security_cobaltstrike_service_installs.yml`) |
| 101047 | 8 | T1484.001 | Windows Default Domain GPO Modification (`win_security_default_domain_gpo_modification.yml`) |
| 101048 | 8 | T1200 | Device Installation Blocked (`win_security_device_installation_blocked.yml`) |
| 101049 | 5 | T1562 | Windows Event Auditing Disabled (`win_security_disable_event_auditing.yml`) |
| 101050-101051 | 11 | T1562 | Important Windows Event Auditing Disabled (`win_security_disable_event_auditing_critical.yml`) |
| 101052-101053 | 11 | T1112 T1562 | ETW Logging Disabled In .NET Processes - Registry (`win_security_dot_net_etw_tamper.yml`) |
| 101054 | 11 | T1003.004 | DPAPI Domain Backup Key Extraction (`win_security_dpapi_domain_backupkey_extraction.yml`) |
| 101055 | 8 | T1003.004 | DPAPI Domain Master Key Backup Attempt (`win_security_dpapi_domain_masterkey_backup_attempt.yml`) |
| 101056-101057 | 5 | T1091 T1200 | External Disk Drive Or USB Storage Device Was Recognized By The System (`win_security_external_device.yml`) |
| 101058-101059 | 11 | T1053.005 | Persistence and Execution at Scale via GPO Scheduled Task (`win_security_gpo_scheduledtasks.yml`) |
| 101060 | 11 | T1136.001 | Hidden Local User Creation (`win_security_hidden_user_creation.yml`) |
| 101061-101062 | 11 | T1053.005 T1562 | HackTool - Defendnot Default Scheduled Task Activity (`win_security_hktl_defendnot_default_scheduled_task_activity.yml`) |
| 101063 | 11 | T1562 | HackTool - EDRSilencer Execution - Filter Added (`win_security_hktl_edr_silencer.yml`) |
| 101064-101065 | 11 | T1134 T1134.001 | HackTool - NoFilter Execution (`win_security_hktl_nofilter.yml`) |
| 101066 | 11 | T1554 | HybridConnectionManager Service Installation (`win_security_hybridconnectionmgr_svc_installation.yml`) |
| 101067 | 11 | T1027 T1059.001 | Invoke-Obfuscation CLIP+ Launcher - Security (`win_security_invoke_obfuscation_clip_services_security.yml`) |
| 101068 | 11 | T1027 | Invoke-Obfuscation Obfuscated IEX Invocation - Security (`win_security_invoke_obfuscation_obfuscated_iex_services_security.yml`) |
| 101069 | 11 | T1027 T1059.001 | Invoke-Obfuscation STDIN+ Launcher - Security (`win_security_invoke_obfuscation_stdin_services_security.yml`) |
| 101070 | 11 | T1027 T1059.001 | Invoke-Obfuscation VAR+ Launcher - Security (`win_security_invoke_obfuscation_var_services_security.yml`) |
| 101071 | 8 | T1027 T1059.001 | Invoke-Obfuscation COMPRESS OBFUSCATION - Security (`win_security_invoke_obfuscation_via_compress_services_security.yml`) |
| 101072 | 8 | T1027 T1059.001 | Invoke-Obfuscation RUNDLL LAUNCHER - Security (`win_security_invoke_obfuscation_via_rundll_services_security.yml`) |
| 101073 | 11 | T1027 T1059.001 | Invoke-Obfuscation Via Stdin - Security (`win_security_invoke_obfuscation_via_stdin_services_security.yml`) |
| 101074 | 11 | T1027 T1059.001 | Invoke-Obfuscation Via Use Clip - Security (`win_security_invoke_obfuscation_via_use_clip_services_security.yml`) |
| 101075 | 11 | T1027 T1059.001 | Invoke-Obfuscation Via Use MSHTA - Security (`win_security_invoke_obfuscation_via_use_mshta_services_security.yml`) |
| 101076 | 11 | T1027 T1059.001 | Invoke-Obfuscation Via Use Rundll32 - Security (`win_security_invoke_obfuscation_via_use_rundll32_services_security.yml`) |
| 101077 | 11 | T1027 T1059.001 | Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - Security (`win_security_invoke_obfuscation_via_var_services_security.yml`) |
| 101078 | 8 | T1558.003 | Kerberoasting Activity - Initial Query (`win_security_kerberoasting_activity.yml`) |
| 101079 | 8 | T1558.004 | Potential AS-REP Roasting via Kerberos TGT Requests (`win_security_kerberos_asrep_roasting.yml`) |
| 101080-101081 | 11 | T1557.003 | Potential Kerberos Coercion by Spoofing SPNs via DNS Manipulation (`win_security_kerberos_coercion_via_dns_object.yml`) |
| 101082 | 11 | T1003.001 T1003.002 T1003.004 T1003.005 T1003.006 T1569.002 | Credential Dumping Tools Service Execution - Security (`win_security_mal_creddumper.yml`) |
| 101083-101084 | 11 | T1021.002 | Metasploit SMB Authentication (`win_security_metasploit_authentication.yml`) |
| 101085 | 11 | T1021.002 T1569.002 T1570 | Metasploit Or Impacket Service Installation Via SMB PsExec (`win_security_metasploit_or_impacket_smb_psexec_service_install.yml`) |
| 101086-101088 | 11 | T1134.001 T1134.002 | Meterpreter or Cobalt Strike Getsystem Service Installation - Security (`win_security_meterpreter_or_cobaltstrike_getsystem_service_install.yml`) |
| 101089 | 11 | T1112 T1562 | NetNTLM Downgrade Attack (`win_security_net_ntlm_downgrade.yml`) |
| 101090-101093 | 8 | T1036 | New or Renamed User Account with '$' Character (`win_security_new_or_renamed_user_account_with_dollar_sign.yml`) |
| 101094 | 8 | T1021.001 | Denied Access To Remote Desktop (`win_security_not_allowed_rdp_access.yml`) |
| 101095 | 8 | T1201 | Password Policy Enumerated (`win_security_password_policy_enumerated.yml`) |
| 101096 | 8 | T1040 | Windows Pcap Drivers (`win_security_pcap_drivers.yml`) |
| 101097 | 11 | T1187 | PetitPotam Suspicious Kerberos TGT Request (`win_security_petitpotam_susp_tgt_request.yml`) |
| 101098-101099 | 8 | T1207 | Possible DC Shadow Attack (`win_security_possible_dc_shadow.yml`) |
| 101100 | 11 | T1569.002 | PowerShell Scripts Installed as Services - Security (`win_security_powershell_script_installed_as_service.yml`) |
| 101101 | 11 | T1558.003 | Register new Logon Process by Rubeus (`win_security_register_new_logon_process_by_rubeus.yml`) |
| 101102 | 11 | T1558 | Replay Attack Detected (`win_security_replay_attack_detected.yml`) |
| 101103-101104 | 8 | T1548 | SCM Database Privileged Operation (`win_security_scm_database_privileged_operation.yml`) |
| 101105 | 8 | T1543.003 T1569.002 | Remote Access Tool Services Have Been Installed - Security (`win_security_service_install_remote_access_software.yml`) |
| 101106-101107 | 11 | T1543 | Service Installed By Unusual Client - Security (`win_security_service_installation_by_unusal_client.yml`) |
| 101108 | 8 | T1098 | A New Trust Was Created To A Domain (`win_security_susp_add_domain_trust.yml`) |
| 101109-101110 | 8 | T1134.005 | Addition of SID History to Active Directory Object (`win_security_susp_add_sid_history.yml`) |
| 101111-101112 | 13 | T1078 | Win Susp Computer Name Containing Samtheadmin (`win_security_susp_computer_name.yml`) |
| 101113 | 11 | T1098 | Password Change on Directory Service Restore Mode (DSRM) Account (`win_security_susp_dsrm_password_change.yml`) |
| 101114-101115 | 8 | T1078 | Account Tampering - Suspicious Failed Logon Reasons (`win_security_susp_failed_logon_reasons.yml`) |
| 101116 | 8 | T1484.001 | Group Policy Abuse for Privilege Addition (`win_security_susp_group_policy_abuse_privilege_addition.yml`) |
| 101117-101118 | 8 | T1484.001 T1547 | Startup/Logon Script Added to Group Policy Object (`win_security_susp_group_policy_startup_script_added_to_gpo.yml`) |
| 101119 | 11 | T1212 | Kerberos Manipulation (`win_security_susp_kerberos_manipulation.yml`) |
| 101120 | 11 | T1001.003 | Suspicious LDAP-Attributes Used (`win_security_susp_ldap_dataexchange.yml`) |
| 101121 | 11 | T1136.001 T1136.002 | Suspicious Windows ANONYMOUS LOGON Local Account Created (`win_security_susp_local_anon_logon_created.yml`) |
| 101122-101123 | 8 | T1078 | Suspicious Remote Logon with Explicit Credentials (`win_security_susp_logon_explicit_credentials.yml`) |
| 101124 | 11 | T1069.002 T1087.002 | Reconnaissance Activity (`win_security_susp_net_recon_activity.yml`) |
| 101125 | 8 | T1027 | Password Protected ZIP File Opened (`win_security_susp_opened_encrypted_zip.yml`) |
| 101126 | 11 | T1027 T1036 T1105 | Password Protected ZIP File Opened (Suspicious Filenames) (`win_security_susp_opened_encrypted_zip_filename.yml`) |
| 101127 | 11 | T1027 T1566.001 | Password Protected ZIP File Opened (Email Attachment) (`win_security_susp_opened_encrypted_zip_outlook.yml`) |
| 101128 | 11 | T1556 | Possible Shadow Credentials Added (`win_security_susp_possible_shadow_credentials_added.yml`) |
| 101129 | 8 | T1558.003 | Suspicious Kerberos RC4 Ticket Encryption (`win_security_susp_rc4_kerberos.yml`) |
| 101130 | 11 | T1053.005 | Suspicious Scheduled Task Creation (`win_security_susp_scheduled_task_creation.yml`) |
| 101131-101133 | 11 | T1053.005 | Important Scheduled Task Deleted/Disabled (`win_security_susp_scheduled_task_delete_or_disable.yml`) |
| 101134 | 11 | T1053.005 | Suspicious Scheduled Task Update (`win_security_susp_scheduled_task_update.yml`) |
| 101135-101136 | 5 | T1070.006 | Unauthorized System Time Modification (`win_security_susp_time_modification.yml`) |
| 101137-101138 | 11 | T1112 | Sysmon Channel Reference Deletion (`win_security_sysmon_channel_reference_deletion.yml`) |
| 101139 | 5 | T1048 | Tap Driver Installation - Security (`win_security_tap_driver_installation.yml`) |
| 101140-101141 | 8 | T1078 T1098 | User Added to Local Administrator Group (`win_security_user_added_to_local_administrators.yml`) |
| 101142 | 11 | T1558.003 | User Couldn't Call a Privileged Service 'LsaRegisterLogonProcess' (`win_security_user_couldnt_call_priv_service_lsaregisterlogonprocess.yml`) |
| 101143 | 5 | T1136.001 | Local User Creation (`win_security_user_creation.yml`) |
| 101144-101145 | 8 | T1562 | Potential Privileged System Service Operation - SeLoadDriverPrivilege (`win_security_user_driver_loaded.yml`) |
| 101146 | 8 | T1562 | Windows Defender Exclusion List Modified (`win_security_windows_defender_exclusions_registry_modified.yml`) |
| 101147 | 8 | T1546.003 | WMI Persistence - Security (`win_security_wmi_persistence.yml`) |
| 101148 | 11 | T1562 | Sysmon Application Crashed (`win_system_application_sysmon_crash.yml`) |
| 101149 | 8 | T1550.002 | NTLMv1 Logon Between Client and Server (`win_system_lsasrv_ntlmv1.yml`) |
| 101150 | 5 | T1553.004 | Active Directory Certificate Services Denied Certificate Enrollment Request (`win_system_adcs_enrollment_request_denied.yml`) |
| 101151 | 11 | T1574.001 | DHCP Server Loaded the CallOut DLL (`win_system_susp_dhcp_config.yml`) |
| 101152 | 11 | T1574.001 | DHCP Server Error Failed Loading the CallOut DLL (`win_system_susp_dhcp_config_failed.yml`) |
| 101153 | 11 | T1557.001 | Local Privilege Escalation Indicator TabTip (`win_system_lpe_indicators_tabtip.yml`) |
| 101154 | 8 | T1070.001 | Eventlog Cleared (`win_system_eventlog_cleared.yml`) |
| 101155 | 11 | T1070.001 | Important Windows Eventlog Cleared (`win_system_susp_eventlog_cleared.yml`) |
| 101156 | 8 |  | Certificate Use With No Strong Mapping (`win_system_kdcsvc_cert_use_no_strong_mapping.yml`) |
| 101157 | 5 | T1558.003 | No Suitable Encryption Key Found For Generating Kerberos Ticket (`win_system_kdcsvc_tgs_no_suitable_encryption_key_found.yml`) |
| 101158 | 11 | T1003.002 | Critical Hive In Suspicious Location Access Bits Cleared (`win_system_susp_critical_hive_location_access_bits_cleared.yml`) |
| 101159 | 5 | T1003.002 | Volume Shadow Copy Mount (`win_system_volume_shadow_copy_mount.yml`) |
| 101160-101161 | 13 | T1210 | Zerologon Exploitation Using Well-known Tools (`win_system_possible_zerologon_exploitation_using_wellknown_tools.yml`) |
| 101162 | 11 | T1548 | Vulnerable Netlogon Secure Channel Connection Allowed (`win_system_vul_cve_2020_1472.yml`) |
| 101163 | 11 | T1499.001 | NTFS Vulnerability Exploitation (`win_system_ntfs_vuln_exploit.yml`) |
| 101164-101167 | 13 | T1021.002 T1543.003 T1569.002 | CobaltStrike Service Installations - System (`win_system_cobaltstrike_service_installs.yml`) |
| 101168 | 8 | T1562 | Windows Defender Threat Detection Service Disabled (`win_system_defender_disabled.yml`) |
| 101169-101170 | 11 | T1021.002 T1569.002 | smbexec.py Service Installation (`win_system_hack_smbexec.yml`) |
| 101171 | 11 | T1027 T1059.001 | Invoke-Obfuscation CLIP+ Launcher - System (`win_system_invoke_obfuscation_clip_services.yml`) |
| 101172 | 11 | T1027 | Invoke-Obfuscation Obfuscated IEX Invocation - System (`win_system_invoke_obfuscation_obfuscated_iex_services.yml`) |
| 101173-101174 | 11 | T1027 T1059.001 | Invoke-Obfuscation STDIN+ Launcher - System (`win_system_invoke_obfuscation_stdin_services.yml`) |
| 101175 | 11 | T1027 T1059.001 | Invoke-Obfuscation VAR+ Launcher - System (`win_system_invoke_obfuscation_var_services.yml`) |
| 101176 | 8 | T1027 T1059.001 | Invoke-Obfuscation COMPRESS OBFUSCATION - System (`win_system_invoke_obfuscation_via_compress_services.yml`) |
| 101177 | 8 | T1027 T1059.001 | Invoke-Obfuscation RUNDLL LAUNCHER - System (`win_system_invoke_obfuscation_via_rundll_services.yml`) |
| 101178 | 11 | T1027 T1059.001 | Invoke-Obfuscation Via Stdin - System (`win_system_invoke_obfuscation_via_stdin_services.yml`) |
| 101179 | 11 | T1027 T1059.001 | Invoke-Obfuscation Via Use Clip - System (`win_system_invoke_obfuscation_via_use_clip_services.yml`) |
| 101180 | 11 | T1027 T1059.001 | Invoke-Obfuscation Via Use MSHTA - System (`win_system_invoke_obfuscation_via_use_mshta_services.yml`) |
| 101181 | 11 | T1027 T1059.001 | Invoke-Obfuscation Via Use Rundll32 - System (`win_system_invoke_obfuscation_via_use_rundll32_services.yml`) |
| 101182 | 11 | T1027 T1059.001 | Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - System (`win_system_invoke_obfuscation_via_var_services.yml`) |
| 101183 | 11 | T1543 | KrbRelayUp Service Installation (`win_system_krbrelayup_service_installation.yml`) |
| 101184 | 11 | T1003.001 T1003.002 T1003.004 T1003.005 T1003.006 T1569.002 | Credential Dumping Tools Service Execution - System (`win_system_mal_creddumper.yml`) |
| 101185-101187 | 11 | T1134.001 T1134.002 | Meterpreter or Cobalt Strike Getsystem Service Installation - System (`win_system_meterpreter_or_cobaltstrike_getsystem_service_installation.yml`) |
| 101188 | 13 | T1543.003 | Moriya Rootkit - System (`win_system_moriya_rootkit.yml`) |
| 101189 | 11 | T1569.002 | PowerShell Scripts Installed as Services (`win_system_powershell_script_installed_as_service.yml`) |
| 101190-101191 | 8 |  | Anydesk Remote Access Software Service Installation (`win_system_service_install_anydesk.yml`) |
| 101192-101193 | 8 | T1569.002 | CSExec Service Installation (`win_system_service_install_csexecsvc.yml`) |
| 101194-101195 | 11 | T1569.002 | HackTool Service Registration or Execution (`win_system_service_install_hacktools.yml`) |
| 101196-101197 | 8 | T1219.002 | Mesh Agent Service Installation (`win_system_service_install_mesh_agent.yml`) |
| 101198-101199 | 8 |  | NetSupport Manager Service Install (`win_system_service_install_netsupport_manager.yml`) |
| 101200-101201 | 8 | T1569.002 | PAExec Service Installation (`win_system_service_install_paexec.yml`) |
| 101202-101203 | 8 | T1543.003 | New PDQDeploy Service - Server Side (`win_system_service_install_pdqdeploy.yml`) |
| 101204-101205 | 8 | T1543.003 | New PDQDeploy Service - Client Side (`win_system_service_install_pdqdeploy_runner.yml`) |
| 101206 | 11 | T1543.003 T1569.002 | ProcessHacker Privilege Elevation (`win_system_service_install_pua_proceshacker.yml`) |
| 101207-101208 | 8 | T1569.002 | RemCom Service Installation (`win_system_service_install_remcom.yml`) |
| 101209 | 8 | T1543.003 T1569.002 | Remote Access Tool Services Have Been Installed - System (`win_system_service_install_remote_access_software.yml`) |
| 101210-101211 | 8 |  | Remote Utilities Host Service Install (`win_system_service_install_remote_utilities.yml`) |
| 101212-101213 | 11 | T1543.003 T1569.002 | Sliver C2 Default Service Installation (`win_system_service_install_sliver.yml`) |
| 101214 | 11 | T1543 | Service Installed By Unusual Client - System (`win_system_service_install_sups_unusal_client.yml`) |
| 101215 | 11 | T1543.003 | Suspicious Service Installation (`win_system_service_install_susp.yml`) |
| 101216-101217 | 8 | T1569.002 | PsExec Service Installation (`win_system_service_install_sysinternals_psexec.yml`) |
| 101218-101219 | 8 | T1219.002 | TacticalRMM Service Installation (`win_system_service_install_tacticalrmm.yml`) |
| 101220 | 8 | T1048 | Tap Driver Installation (`win_system_service_install_tap_driver.yml`) |
| 101221-101222 | 8 | T1543.003 | Uncommon Service Installation Image Path (`win_system_service_install_uncommon.yml`) |
| 101223 | 5 |  | Windows Service Terminated With Error (`win_system_service_terminated_error_generic.yml`) |
| 101224-101225 | 11 |  | Important Windows Service Terminated With Error (`win_system_service_terminated_error_important.yml`) |
| 101226-101227 | 11 |  | Important Windows Service Terminated Unexpectedly (`win_system_service_terminated_unexpectedly.yml`) |
| 101228 | 11 |  | RTCore Suspicious Service Installation (`win_system_susp_rtcore64_service_install.yml`) |
| 101229-101230 | 8 | T1543.003 | Service Installation in Suspicious Folder (`win_system_susp_service_installation_folder.yml`) |
| 101231 | 11 | T1543.003 | Service Installation with Suspicious Folder Pattern (`win_system_susp_service_installation_folder_pattern.yml`) |
| 101232 | 11 | T1543.003 | Suspicious Service Installation Script (`win_system_susp_service_installation_script.yml`) |
| 101233 | 8 | T1190 | F5 BIG-IP iControl Rest API Command Execution - Webserver (`web_f5_tm_utility_bash_api_request.yml`) |
| 101234 | 8 | T1190 | Successful IIS Shortname Fuzzing Scan (`web_iis_tilt_shortname_scan.yml`) |
| 101235 | 8 | T1190 | Path Traversal Exploitation Attempts (`web_path_traversal_exploitation_attempt.yml`) |
| 101236 | 8 | T1083 | Source Code Enumeration Detection by Keyword (`web_source_code_enumeration.yml`) |
| 101237 | 8 | T1190 | Suspicious User-Agents Related To Recon Tools (`web_susp_useragents.yml`) |
| 101238 | 11 | T1505.003 | Suspicious Windows Strings In URI (`web_susp_windows_path_uri.yml`) |
| 101239 | 11 | T1071.001 | APT User Agent (`proxy_ua_apt.yml`) |
| 101240 | 8 | T1071.001 | Suspicious Base64 Encoded User-Agent (`proxy_ua_base64_encoded.yml`) |
| 101241 | 11 | T1071.001 | Crypto Miner User Agent (`proxy_ua_cryptominer.yml`) |
| 101242 | 8 | T1071.001 | HTTP Request With Empty User Agent (`proxy_ua_empty.yml`) |
| 101243 | 11 | T1071.001 | Exploit Framework User Agent (`proxy_ua_frameworks.yml`) |
| 101244 | 11 | T1110 T1190 | Hack Tool User Agent (`proxy_ua_hacktool.yml`) |
| 101245 | 11 | T1071.001 | Malware User Agent (`proxy_ua_malware.yml`) |
| 101246 | 8 | T1071.001 | Windows PowerShell User Agent (`proxy_ua_powershell.yml`) |
| 101247 | 8 | T1567.002 | Rclone Activity via Proxy (`proxy_ua_rclone.yml`) |
| 101248 | 8 | T1071.001 | Potential Base64 Encoded User-Agent (`proxy_ua_susp_base64.yml`) |

## Skipped

| Sigma rule | Why |
|---|---|
| `windows/builtin/security/object_access/win_security_wfp_endpoint_agent_blocked.yml` | event IDs [5157] are not collected |
| `windows/builtin/security/win_security_aadhealth_mon_agent_regkey_access.yml` | event IDs [4656, 4663] are not collected |
| `windows/builtin/security/win_security_aadhealth_svc_agent_regkey_access.yml` | event IDs [4656, 4663] are not collected |
| `windows/builtin/security/win_security_atsvc_task.yml` | event IDs [5145] are not collected |
| `windows/builtin/security/win_security_codeintegrity_check_failure.yml` | level informational |
| `windows/builtin/security/win_security_dce_rpc_smb_spoolss_named_pipe.yml` | event IDs [5145] are not collected |
| `windows/builtin/security/win_security_dcom_iertutil_dll_hijack.yml` | event IDs [5145] are not collected |
| `windows/builtin/security/win_security_explicit_credential_local_logon.yml` | status experimental |
| `windows/builtin/security/win_security_impacket_psexec.yml` | event IDs [5145] are not collected |
| `windows/builtin/security/win_security_impacket_secretdump.yml` | event IDs [5145] are not collected |
| `windows/builtin/security/win_security_iso_mount.yml` | event IDs [4663] are not collected |
| `windows/builtin/security/win_security_lm_namedpipe.yml` | event IDs [5145] are not collected |
| `windows/builtin/security/win_security_lsass_access_non_system_account.yml` | event IDs [4656, 4663] are not collected |
| `windows/builtin/security/win_security_mal_wceaux_dll.yml` | event IDs [4656, 4663] are not collected |
| `windows/builtin/security/win_security_net_share_obj_susp_desktop_ini.yml` | event IDs [5145] are not collected |
| `windows/builtin/security/win_security_petitpotam_network_share.yml` | event IDs [5145] are not collected |
| `windows/builtin/security/win_security_protected_storage_service_access.yml` | event IDs [5145] are not collected |
| `windows/builtin/security/win_security_rdp_reverse_tunnel.yml` | event IDs [5156] are not collected |
| `windows/builtin/security/win_security_registry_permissions_weakness_check.yml` | event IDs [4663] are not collected |
| `windows/builtin/security/win_security_remote_powershell_session.yml` | event IDs [5156] are not collected |
| `windows/builtin/security/win_security_sam_registry_hive_handle_request.yml` | event IDs [4656] are not collected |
| `windows/builtin/security/win_security_scm_database_handle_failure.yml` | event IDs [4656] are not collected |
| `windows/builtin/security/win_security_sdelete_potential_secure_deletion.yml` | event IDs [4656, 4658, 4663] are not collected |
| `windows/builtin/security/win_security_signal_sensitive_config_access.yml` | status experimental |
| `windows/builtin/security/win_security_smb_file_creation_admin_shares.yml` | event IDs [5145] are not collected |
| `windows/builtin/security/win_security_susp_lsass_dump.yml` | event IDs [4656] are not collected |
| `windows/builtin/security/win_security_susp_lsass_dump_generic.yml` | event IDs [4656, 4663] are not collected |
| `windows/builtin/security/win_security_susp_outbound_kerberos_connection.yml` | event IDs [5156] are not collected |
| `windows/builtin/security/win_security_susp_psexec.yml` | event IDs [5145] are not collected |
| `windows/builtin/security/win_security_susp_raccess_sensitive_fext.yml` | event IDs [5145] are not collected |
| `windows/builtin/security/win_security_svcctl_remote_service.yml` | event IDs [5145] are not collected |
| `windows/builtin/security/win_security_syskey_registry_access.yml` | event IDs [4656, 4663] are not collected |
| `windows/builtin/security/win_security_teams_suspicious_objectaccess.yml` | event IDs [4663] are not collected |
| `windows/builtin/security/win_security_transf_files_with_cred_data_via_network_shares.yml` | event IDs [5145] are not collected |
| `windows/builtin/security/win_security_user_logoff.yml` | level informational |
| `windows/builtin/security/win_security_vssaudit_secevent_source_registration.yml` | level informational |
| `windows/builtin/security/win_security_windows_defender_exclusions_write_access.yml` | event IDs [4656, 4663] are not collected |
| `windows/builtin/security/win_security_wmiprvse_wbemcomn_dll_hijack.yml` | event IDs [5145] are not collected |
| `windows/builtin/security/win_security_workstation_was_locked.yml` | level informational |
| `windows/builtin/system/microsoft_windows_Iphlpsvc/win_system_isatap_router_address_set.yml` | status experimental |
| `windows/builtin/system/microsoft_windows_wer_systemerrorreporting/win_system_crash_dump_created.yml` | status experimental |
| `windows/builtin/system/microsoft_windows_windows_update_client/win_system_susp_system_update_error.yml` | level informational |
| `web/webserver_generic/web_java_payload_in_access_logs.yml` | 10 alternatives (max 6) |
| `web/webserver_generic/web_jndi_exploit.yml` | 20 alternatives (max 6) |
| `web/webserver_generic/web_sql_injection_in_access_logs.yml` | 30 alternatives (max 6) |
| `web/webserver_generic/web_ssti_in_access_logs.yml` | 10 alternatives (max 6) |
| `web/webserver_generic/web_webshell_regeorg.yml` | field 'cs-referer' |
| `web/webserver_generic/web_win_webshells_in_access_logs.yml` | 36 alternatives (max 6) |
| `web/webserver_generic/web_xss_in_access_logs.yml` | 16 alternatives (max 6) |
| `web/proxy_generic/proxy_download_susp_dyndns.yml` | fields ['c-uri-extension', 'cs-host'] not in only_fields for this category |
| `web/proxy_generic/proxy_download_susp_tlds_blacklist.yml` | fields ['c-uri-extension', 'cs-host'] not in only_fields for this category |
| `web/proxy_generic/proxy_download_susp_tlds_whitelist.yml` | fields ['c-uri-extension', 'cs-host'] not in only_fields for this category |
| `web/proxy_generic/proxy_downloadcradle_webdav.yml` | fields ['cs-method'] not in only_fields for this category |
| `web/proxy_generic/proxy_f5_tm_utility_bash_api_request.yml` | fields ['c-uri', 'cs-method'] not in only_fields for this category |
| `web/proxy_generic/proxy_hello_world_user_agent.yml` | status experimental |
| `web/proxy_generic/proxy_hktl_baby_shark_default_agent_url.yml` | fields ['c-uri'] not in only_fields for this category |
| `web/proxy_generic/proxy_hktl_cobalt_strike_malleable_c2_requests.yml` | fields ['c-uri', 'cs-cookie', 'cs-host', 'cs-method'] not in only_fields for this category |
| `web/proxy_generic/proxy_hktl_empire_ua_uri_patterns.yml` | fields ['cs-method', 'cs-uri'] not in only_fields for this category |
| `web/proxy_generic/proxy_pua_advanced_ip_scanner_update_check.yml` | fields ['c-uri', 'c-uri-query'] not in only_fields for this category |
| `web/proxy_generic/proxy_pwndrop.yml` | fields ['c-uri'] not in only_fields for this category |
| `web/proxy_generic/proxy_raw_paste_service_access.yml` | fields ['c-uri'] not in only_fields for this category |
| `web/proxy_generic/proxy_susp_flash_download_loc.yml` | fields ['c-uri', 'cs-host'] not in only_fields for this category |
| `web/proxy_generic/proxy_susp_ipfs_cred_harvest.yml` | fields ['cs-uri'] not in only_fields for this category |
| `web/proxy_generic/proxy_telegram_api.yml` | fields ['cs-host'] not in only_fields for this category |
| `web/proxy_generic/proxy_ua_bitsadmin_susp_ip.yml` | fields ['cs-host'] not in only_fields for this category |
| `web/proxy_generic/proxy_ua_bitsadmin_susp_tld.yml` | fields ['cs-host'] not in only_fields for this category |
| `web/proxy_generic/proxy_ua_susp.yml` | fields ['cs-host'] not in only_fields for this category |
| `web/proxy_generic/proxy_webdav_external_execution.yml` | fields ['c-uri', 'cs-method', 'dst_ip'] not in only_fields for this category |
