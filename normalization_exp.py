import os
import json
import re
import urllib.parse
import warnings
from itertools import product
import time
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

    # Eliminates 178 evasions
    for rule_name, evasion_lines in evasions.items():
        for ev in evasion_lines:
            seen_this_line = False

            # Remove quotes that are in the middle of a token
            tokens = ev.split()
            normalized_tokens = [remove_mid_quotes(token) for token in tokens]
            normalized_cmd = ' '.join(normalized_tokens)
            if normalized_cmd in matches[rule_name]:
                normalized_count += 1
                # print(f"EVASION: {ev}\n NORMALIZED: {normalized_cmd}")
                seen_this_line = True

            # record any that slip through
            if not seen_this_line:
                missed.append((rule_name, ev, normalized_cmd))

    temp_missed = missed.copy()
    missed = []

    # 213 Eliminated
    for rule_name, ev, cmd_line in temp_missed:
        seen_this_line = False

        variants = quote_variations(cmd_line)
        evasion_list = [' '.join(v) for v in variants]
        # Technique 1: insertion-only
        for x in evasion_list:
            if x in matches[rule_name]:
                normalized_count += 1
                seen_this_line = True
                break

        # record any that slip through
        if not seen_this_line:
            missed.append((rule_name, ev, variants))

    temp_missed = missed.copy()
    missed = []

    # 231 eliminated
    for rule_name, ev, varis in temp_missed:
        seen_this_line = False

        variants = omission_variations(varis)
        evasion_list = [' '.join(v) for v in variants]
        # Technique 1: insertion-only
        for x in evasion_list:
            if x in matches[rule_name]:
                normalized_count += 1
                seen_this_line = True
                break

        # record any that slip through
        if not seen_this_line:
            missed.append((rule_name, ev, variants))

    temp_missed = missed.copy()
    missed = []

    # 265 eliminated
    for rule_name, ev, varis in temp_missed:
        seen_this_line = False

        variants = flag_variations(varis)
        evasion_list = [' '.join(v) for v in variants]
        # Technique 1: insertion-only
        for x in evasion_list:
            if x in matches[rule_name]:
                normalized_count += 1
                seen_this_line = True
                break

        # record any that slip through
        if not seen_this_line:
            missed.append((rule_name, ev, variants))

    temp_missed = missed.copy()
    missed = []

    # # 265 eliminated
    # for rule_name, ev, varis in temp_missed:
    #     seen_this_line = False

    #     variants = substitution_variations(varis)
    #     evasion_list = [' '.join(v) for v in variants]
    #     # Technique 1: insertion-only
    #     for x in evasion_list:
    #         if x in matches[rule_name]:
    #             normalized_count += 1
    #             seen_this_line = True
    #             break

    #     # record any that slip through
    #     if not seen_this_line:
    #         missed.append((rule_name, ev, variants))
    
    # 265 eliminated
    for rule_name, ev, varis in temp_missed:
        seen_this_line = False

        variants = space_variations(varis)
        evasion_list = [' '.join(v) for v in variants]
        # Technique 1: insertion-only
        for x in evasion_list:
            if x in matches[rule_name]:
                normalized_count += 1
                seen_this_line = True
                break
            if x+' ' in matches[rule_name]:
                normalized_count += 1
                seen_this_line = True
                break

        # record any that slip through
        if not seen_this_line:
            missed.append((rule_name, ev, variants))
        


    print(f"Total evasion lines caught: {normalized_count}")
    if missed:
        print("\nMissed evasion lines (not normalized):")
        for rule, ev, _ in missed:
            print(f"{rule}: {ev}")

def remove_mid_quotes(token):
    # Remove the quotes from the middle of individual tokens
    start = token[0] if token[0] in ['"', "'"] else ''
    end = token[-1] if token[-1] in ['"', "'"] else ''
    middle = token
    if start and end:
        middle = token[1:-1]
        middle = middle.replace('"', '').replace("'", '')
        return start + middle + end
    else:
        return token.replace('"', '').replace("'", '')

def quote_variations(cmd_line):
    tokens = cmd_line.split()
    variants = [list(tokens)]
    for i, t in enumerate(tokens):
        temp_variants = variants.copy()
        if t[0] == '"' and t[-1] == '"':
            for v in variants:
                temp = v.copy()
                temp[i] = t.replace('"', '')
                temp_variants.append(temp)
            variants = temp_variants
    return variants

def flag_variations(prev_variants):
    tokens = prev_variants[0]
    variants = prev_variants
    for i, t in enumerate(tokens):
        temp_variants = variants.copy()
        if t[0] == '/':
            for v in variants:
                temp = v.copy()
                temp[i] = t.replace('/', '-')
                temp_variants.append(temp)
            variants = temp_variants
        if t[0] == '-':
            for v in variants:
                temp = v.copy()
                temp[i] = t.replace('-', '/')
                temp_variants.append(temp)
            variants = temp_variants
    return variants

def omission_variations(prev_variants):
    substring_list = ['.exe', '.dll']
    tokens = prev_variants[0]
    variants = prev_variants
    for i, t in enumerate(tokens):
        temp_variants = variants.copy()
        for substring in substring_list:
            if substring in t:
                for v in variants:
                    temp = v.copy()
                    temp[i] = t.replace(substring, '')
                    temp_variants.append(temp)
                variants = temp_variants
    return variants

def substitution_variations(prev_variants):
    replace_map = {'-h':'--help', 'cmd':'cmd.exe'}
    tokens = prev_variants[0]
    variants = prev_variants
    for i, t in enumerate(tokens):
        temp_variants = variants.copy()
        for substring in replace_map.keys():
            if substring == t:
                for v in variants:
                    temp = v.copy()
                    temp[i] = replace_map[substring]
                    temp_variants.append(temp)
                variants = temp_variants
    return variants

def space_variations(prev_variants):
    replace_map = {'cmd':'cmd.exe', '-h':'--help'}
    tokens = prev_variants[0]
    variants = prev_variants
    for i, t in enumerate(tokens):
        temp_variants = variants.copy()
        for substring in replace_map.keys():
            if substring in t:
                for v in variants:
                    temp = v.copy()
                    temp[i] = t.replace(substring, replace_map[substring])
                    temp_variants.append(temp)
                variants = temp_variants
    return variants

def normalize(cmd_line):
    # Remove quotes that are in the middle of a token
    tokens = cmd_line.split()
    normalized_tokens = [remove_mid_quotes(token) for token in tokens]
    # 178 evasions eliminated
    normalized_cmd_line = ' '.join(normalized_tokens)
    # 213 evasions eliminated
    variants = quote_variations(normalized_cmd_line)
    # 245 evasions aliminated
    variants = flag_variations(variants)
    return omission_variations(variants)


def main():
    matches, evasions = get_data(root_directory)
    normalize_test(matches, evasions)

if __name__ == "__main__":
    main()