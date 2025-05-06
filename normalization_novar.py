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

    # Eliminates 87 evasions
    for rule_name, evasion_lines in evasions.items():
        for ev in evasion_lines:
            seen_this_line = False

            normalized_cmd = normalize(ev)
            if normalized_cmd in matches[rule_name]:
                normalized_count += 1
                print(f"EVASION: {ev}\n NORMALIZED: {normalized_cmd}")
                seen_this_line = True

            # record any that slip through
            if not seen_this_line:
                missed.append((rule_name, ev, normalized_cmd))

    print(f"Total evasion lines caught: {normalized_count}")
    if missed:
        print("\nMissed evasion lines (not normalized):")
        for rule, ev, _ in missed:
            print(f"{rule}: {ev}")

def quotes(cmd_line):
    if '"' in cmd_line:
        cmd_line = cmd_line.replace('"', '')
    if "'" in cmd_line:
        cmd_line = cmd_line.replace("'", '')
    return cmd_line

def spaces(cmd_line):
    tokens = cmd_line.split(' ')
    return ' '.join(tokens)

def flag(cmd_line):
    pattern = r"\/([A-Z]|[a-z])"
    repl = r"-\1"
    return re.sub(pattern, repl, cmd_line)
    

def omission(cmd_line):
    substring_list = ['.exe', '.dll']
    for substring in substring_list:
        if substring in cmd_line:
            cmd_line = cmd_line.replace(substring, '')
    return cmd_line

def substitution(cmd_line):
    replace_map = {'cmd':'cmd.exe', '-h':'--help'}
    for substring in replace_map.keys():
        if substring in cmd_line:
            cmd_line = cmd_line.replace(substring, replace_map[substring])
    return cmd_line

def normalize(cmd_line):
    norm_val = pipe(cmd_line,
                    quotes,
                    spaces,
                    flag,
                    omission,
                    substitution)
    return norm_val


def main():
    matches, evasions = get_data(root_directory)
    normalize_test(matches, evasions)

if __name__ == "__main__":
    main()