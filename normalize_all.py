import os
import json
import re
import urllib.parse
import warnings
from itertools import product
import time
from toolz import pipe
root_directory = 'data/sigma/events/windows/process_creation/'


def get_data(root_directory):
    matches = {}
    evasions = {}
    evasion_count = 0

    # Get list of matches
    # Get list of evasions
    for root, dirnames, filenames in os.walk(root_directory):
        # Get rulename
        rulename = root.split('/')[-1]
        # Get match and evasion files
        match_files = [f for f in filenames if 'Match' in f]
        evasion_files = [f for f in filenames if 'Evasion' in f]
        # Get the command line from the match files
        match_command_lines = []
        for match_file in match_files:
            with open(os.path.join(root, match_file), 'r') as f:
                data = json.load(f)
                command_line = data['process']['command_line']
                match_command_lines.append(command_line)
        # Get the command line from the evasion files
        evasion_command_lines = []
        for evasion_file in evasion_files:
            with open(os.path.join(root, evasion_file), 'r') as f:
                data = json.load(f)
                command_line = data['process']['command_line']
                evasion_command_lines.append(command_line)
        # Add to matches and evasions
        if match_command_lines:
            matches[rulename] = match_command_lines
        if evasion_command_lines:
            evasions[rulename] = evasion_command_lines
        
    for evasion in evasions.values():
        evasion_count += len(evasion)
    
    print(f"Total evasion lines: {evasion_count}")

    return matches, evasions


# Create test between matches and evasions
def normalize_test(matches, evasions):
    normalized_count = 0
    missed = []  # collect lines that no normalization matched

    # normalize the matches
    matches = {k: [normalize(v) for v in vals] for k, vals in matches.items()}

    # Eliminates 314 evasions
    for rule_name, evasion_lines in evasions.items():
        for ev in evasion_lines:
            seen_this_line = False

            normalized_cmd = normalize(ev)
            if normalized_cmd in matches[rule_name]:
                normalized_count += 1
                seen_this_line = True

            # record any that slip through
            if not seen_this_line:
                missed.append((rule_name, ev, normalized_cmd, matches[rule_name]))

    
    if missed:
        print("\nMissed evasion lines (not normalized):")
        for rule, ev, normalized_cmd, matches in missed:
            print('-'*40)
            print(f"""RULE: {rule}\n
                    EVASION: {ev}\n
                    NORMALIZED: {normalized_cmd}\n
                    MATCHES: {matches}""")
    
    print(f"Total evasion lines caught: {normalized_count}")

def quotes(cmd_line):
    if '"' in cmd_line:
        cmd_line = cmd_line.replace('"', '')
    if "'" in cmd_line:
        cmd_line = cmd_line.replace("'", '')
    return cmd_line

def spaces(cmd_line):
    return cmd_line.replace(' ', '')

def flag(cmd_line):
    pattern = r"\/([A-Z]|[a-z])"
    repl = r"-\1"
    return re.sub(pattern, repl, cmd_line)
    

def omission(cmd_line):
    substring_list = ['.exe', '.dll', 'C:\Windows\System32\\', 'C:\\Windows\\system32\\', '-nointeractive',  'Another', 'C:', 'inetsrv', 'Win64', 'excel', ':','\\Windows\\Microsoft.NET\\Framework\\v2.0.50727', 'Server01', '-v500m', '\%ws -u %user% -p %pass% -s cmd -c netstat',
    '&& echo print .jpg to avoid detection', '-Path', 'sigma', 'System32', 'DisableFirstRunCustomize', 'protoc=tcp']
    for substring in substring_list:
        if substring in cmd_line:
            cmd_line = cmd_line.replace(substring, '')
    return cmd_line

def substitution(cmd_line):
    replace_map = {'cmd':'cmd.exe', '--remote-name':'-O', '-Os':'-O', 'groupname':'grpname', 'Endpoint Detection':'Endpoint Sensor', '-exec bypass': '-execbypass', '-w 1':'-w1', ' file.rsp':'nicefile.rsp', 'themes':'superbackupman',
    'New-service':'New-Service', '-tn goodupdater':'-tngoodupdater', '-tr powershell.exe':'-trpowershell', '-sc onidle':'-sconidle', '-tn updatertask':'-tnupdatertask', '-executionPolicy':'-exec', '-encodedCommand':'-enc',
    '-RP password': '-RPpassword', '-RU user':'-RUuser', '-TN taskname':'-TNtaskname', 'usrpsswrd123':'usrpsswrd', '-add mynewusr':'-add mynewuser', '\\admin':'\\admi', 'net1':'net', '-NonInteractive':'-noni', '-ExecutionPolicy bypass':'-execbypass', 'c^onfg':'config', 'serviecename': 'servicename',
    'domain_trusts':'domain_trust', '-enc':'-ec', 'firewall':'fi', 'action':'acti', 'protocol':'protoc', 'localport':'localp', 'advfi':'advf', '1 notepad':'h notepad', '01258':'1258', '-Windows':'Windows', '-root':'root', 
    '-version':'-versio', '-interactive':'-inter', '-i notepad.exe':'-internotepad', 'vki':'Username', 'AppData':'Appdata', 'Discord':'App', '--create':'-create', '--process':'-process', 'foo':'windowsaudio', 'C:\some\other\malicious\lib.cpl -f':'C:\some\other\malicious\lib.cpl', '-name create':'-namecreate',
    '\client\Default User\\  C:\\Users\\Default User\\ -E -S -C -q -H' : '-S-E-C-q-HclientDefaultUserUsersDefaultUser', '-S-E-C-Q-H':'-S-E-C-q-H', '-PropertyType DWORD':'-PropertyDWORD','-PropertyType':'-Property',
    '-Type String':'-PropertyString', '-name Check_Associations':'-nameCheck_Associations', '-Type DWORD': '-PropertyDWORD', '-Property DWORD':'-PropertyDWORD', '-name IEHarden':'-nameIEHarden', 'server=y,address=4711':'address=1337server=y,',
    'transport=dt_socket,suspend=n,server=y,address=4242':'server=ysuspend=ntransport=dt_socketaddress=4711', 'dt_socket,server=y,suspend=n,address=1337':'dt_socketaddress=1337server=ysuspend=n', '127.0.0.1':'localhost', 'path':'Path',
    'connectaddress=localhost connectport=4711 listenport=3389':'listenport=3389 connectaddress=localhost connectport=4711', '-tr cmd.exe -c powershell.exe -execbypass -file c:\s.ps1 -tn win32times':'-tn win32times -tr cmd.exe -c powershell.exe -execbypass -file c:\s.ps1'}
    for substring in replace_map.keys():
        if substring in cmd_line:
            cmd_line = cmd_line.replace(substring, replace_map[substring])
    return cmd_line

def substitution_2(cmd_line):
    replace_map = {'-h':'--help', '-e':'-EncodedCommand', '-l':'-list', '-ep':'-exec', 'i':'interface', 'p':'port', 'a':'proxyadd', 'v':'v4tov4', 't':'trace', 's':'start', 'c=y':'capture=yes', '-r':'-C', '-v':'-versio',
    '-Q':'-q'}
    tokens = cmd_line.split(' ')
    temp_tokens = tokens.copy()
    for i, t in enumerate(tokens):
        if t in replace_map.keys():
            temp_tokens[i] = replace_map[t]
    return ' '.join(temp_tokens)


def reorder(cmd_line):
    reorder_map = {'ls':'-ma', '-noni':'-execbypass', '-nop':'-noni', '-w1':'-nop', '-tngoodupdater':'-trpowershell', '-tnupdatertask':'-sconidle', '-i':'-s',
    '-RPpassword':'-change', '-RUuser':'-TNtaskname', '-RPpassword':'-RUuser', '-noni':'-execbypass', 'connectaddress=127.0.0.1':'connectport=4711', 'connectport=4711':'listenport=3389',
    '-q':'-C', '-mx9':'-v500m', '-r0':'-mx9', '-namecreate':'win32_process', '-E':'-S', '-TNtaskname':'-change', '-RUuser':'-TNtaskname', '-RPpassword':'-RUuser', '-name':'-PropertyDWORD',
    '-nameCheck_Associations':'-PropertyString', '-nameIEHarden':'-PropertyDWORD', 'dir=in':'localp=47000','acti=allow':'dir=in'}
    tokens = cmd_line.split(' ')
    stop_con = len(tokens)
    temp_tokens = tokens.copy()
    j = 0
    while j < stop_con:
        for i, t in enumerate(tokens):
            try:
                if t in reorder_map.keys() and tokens.index(reorder_map[t]) > i:
                    temp_tokens[tokens.index(reorder_map[t])] = t
                    temp_tokens[i] = reorder_map[t]
                    break
            except ValueError:
                pass
        tokens = temp_tokens.copy()
        j +=1
    return ' '.join(temp_tokens)

def aggressive(cmd_line):
    cmd_line = cmd_line.replace('\\', '')
    cmd_line = cmd_line.replace('}', '')
    cmd_line = cmd_line.replace('^6', '')
    cmd_line = cmd_line.replace('^', '')
    cmd_line = cmd_line.replace('.', '')
    cmd_line = cmd_line.replace('*', '')
    cmd_line = cmd_line.replace(',', '')
    cmd_line = cmd_line.replace('/', '')
    cmd_line = cmd_line.replace("`", '')
    return cmd_line

def normalize(cmd_line):
    norm_val = pipe(cmd_line,
                    quotes,
                    flag,
                    substitution_2,
                    substitution,
                    omission,
                    reorder,
                    spaces,
                    aggressive)
    return norm_val


def main():
    matches, evasions = get_data(root_directory)
    normalize_test(matches, evasions)

if __name__ == "__main__":
    main()