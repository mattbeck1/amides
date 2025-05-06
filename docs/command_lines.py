
import os
import json
import pandas as pd
import re

# Base directory
BASE_DIR = "/home/amides/amides/amides/data/sigma/events/windows/process_creation"

# List of folders
folders_with_cmdline = [
    "sysmon_apt_muddywater_dnstunnel",
    "win_apt_apt29_thinktanks",
    "win_apt_babyshark",
    "win_apt_bear_activity_gtr19",
    "win_apt_elise",
    "win_apt_equationgroup_dll_u_load",
    "win_apt_hurricane_panda",
    "win_apt_ke3chang_regadd",
    "win_apt_taidoor",
    "win_apt_turla_comrat_may20",
    "win_apt_unc2452_cmds",
    "win_apt_unc2452_ps",
    "win_apt_wocao",
    "win_apt_zxshell",
    "win_bootconf_mod",
    "win_change_default_file_association",
    "win_cmdkey_recon",
    "win_commandline_path_traversal",
    "win_control_panel_item",
    "win_copying_sensitive_files_with_credential_data",
    "win_crime_maze_ransomware",
    "win_crime_snatch_ransomware",
    "win_data_compressed_with_rar",
    "win_dsquery_domain_trust_discovery",
    "win_etw_trace_evasion",
    "win_exploit_cve_2020_1048",
    "win_hack_koadic",
    "win_install_reg_debugger_backdoor",
    "win_interactive_at",
    "win_local_system_owner_account_discovery",
    "win_lsass_dump",
    "win_mal_adwind",
    "win_malware_emotet",
    "win_malware_ryuk",
    "win_malware_script_dropper",
    "win_malware_trickbot_recon_activity",
    "win_malware_wannacry",
    "win_net_enum",
    "win_net_user_add",
    "win_netsh_allow_port_rdp",
    "win_netsh_fw_add",
    "win_netsh_packet_capture",
    "win_netsh_port_fwd",
    "win_netsh_port_fwd_3389",
    "win_netsh_wifi_credential_harvesting",
    "win_network_sniffing",
    "win_new_service_creation",
    "win_possible_applocker_bypass",
    "win_powershell_amsi_bypass",
    "win_powershell_bitsjob",
    "win_powershell_downgrade_attack",
    "win_powershell_download",
    "win_powershell_frombase64string",
    "win_powershell_suspicious_parameter_variation",
    "win_powershell_xor_commandline",
    "win_powersploit_empire_schtasks",
    "win_process_creation_bitsadmin_download",
    "win_process_dump_rundll32_comsvcs",
    "win_query_registry",
    "win_redmimicry_winnti_proc",
    "win_remote_time_discovery",
    "win_run_powershell_script_from_ads",
    "win_service_execution",
    "win_shadow_copies_access_symlink",
    "win_spn_enum",
    "win_susp_adfind",
    "win_susp_bcdedit",
    "win_susp_bginfo",
    "win_susp_calc",
    "win_susp_cdb",
    "win_susp_certutil_command",
    "win_susp_certutil_encode",
    "win_susp_cli_escape",
    "win_susp_codepage_switch",
    "win_susp_copy_lateral_movement",
    "win_susp_copy_system32",
    "win_susp_crackmapexec_execution",
    "win_susp_crackmapexec_powershell_obfuscation",
    "win_susp_csc_folder",
    "win_susp_curl_download",
    "win_susp_curl_fileupload",
    "win_susp_curl_start_combo",
    "win_susp_desktopimgdownldr",
    "win_susp_direct_asep_reg_keys_modification",
    "win_susp_disable_ie_features",
    "win_susp_disable_raccine",
    "win_susp_eventlog_clear",
    "win_susp_explorer_break_proctree",
    "win_susp_findstr_lnk",
    "win_susp_firewall_disable",
    "win_susp_fsutil_usage",
    "win_susp_iss_module_install",
    "win_susp_msiexec_web_install",
    "win_susp_net_execution",
    "win_susp_netsh_dll_persistence",
    "win_susp_odbcconf",
    "win_susp_ping_hex_ip",
    "win_susp_powershell_empire_launch",
    "win_susp_powershell_empire_uac_bypass",
    "win_susp_powershell_enc_cmd",
    "win_susp_powershell_hidden_b64_cmd",
    "win_susp_procdump",
    "win_susp_ps_appdata",
    "win_susp_psr_capture_screenshots",
    "win_susp_rar_flags",
    "win_susp_recon_activity",
    "win_susp_regsvr32_anomalies",
    "win_susp_regsvr32_flags_anomaly",
    "win_susp_rundll32_activity",
    "win_susp_rundll32_by_ordinal",
    "win_susp_schtask_creation",
    "win_susp_script_execution",
    "win_susp_service_path_modification",
    "win_susp_squirrel_lolbin",
    "win_susp_svchost_no_cli",
    "win_susp_sysprep_appdata",
    "win_susp_sysvol_access",
    "win_susp_tscon_rdp_redirect",
    "win_susp_volsnap_disable",
    "win_susp_wmi_execution",
    "win_susp_wmic_proc_create_rundll32",
    "win_susp_wmic_security_product_uninstall",
    "win_sysmon_driver_unload",
    "win_task_folder_evasion",
    "win_trust_discovery",
    "win_using_sc_to_change_sevice_image_path_by_non_admin",
    "win_vul_java_remote_debugging",
    "win_webshell_detection",
    "win_webshell_recon_detection",
    "win_win10_sched_task_0day"
]   # Paste your full list here

# Storage for results
results = []

for folder in folders_with_cmdline:
    folder_path = os.path.join(BASE_DIR, folder)
    if not os.path.exists(folder_path):
        continue

    for filename in os.listdir(folder_path):
        if not re.match(r"Microsoft-Windows-Sysmon_1_(Evasion_Cmdline|Match)_\d+\.json", filename):
            continue

        file_path = os.path.join(folder_path, filename)
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            events = data if isinstance(data, list) else [data]

            for event in events:
                cmdline = None

                # First priority
                if 'process' in event and 'command_line' in event['process']:
                    cmdline = event['process']['command_line']
                # Fallback
                elif 'winlog' in event and 'event_data' in event['winlog']:
                    cmdline = event['winlog']['event_data'].get('CommandLine')

                if cmdline:
                    results.append({
                        'folder': folder,
                        'file': filename,
                        'command_line': cmdline
                    })

        except Exception as e:
            print(f"Failed to read {file_path}: {e}")

# Convert to DataFrame
df = pd.DataFrame(results)

# Save or display
df.to_csv('all_extracted_command_lines.csv', index=False)
print(df)
