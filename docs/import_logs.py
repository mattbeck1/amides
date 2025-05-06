import os
import json
import csv

def load_json(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

def compare_dicts(match_log, evasion_log):
    diffs = []
    for key in match_log:
        match_val = match_log.get(key)
        evasion_val = evasion_log.get(key)
        if match_val != evasion_val:
            diffs.append((key, match_val, evasion_val))
    return diffs

def find_log_pairs(base_dir):
    log_pairs = []

    for root, dirs, files in os.walk(base_dir):
        match_files = {}
        evasion_files = {}

        for filename in files:
            if filename.endswith('.json'):
                if 'Match' in filename:
                    key = filename.split('Match')[0]
                    match_files[key] = os.path.join(root, filename)
                elif 'Evasion' in filename:
                    key = filename.split('Evasion')[0]
                    evasion_files.setdefault(key, []).append(os.path.join(root, filename))

        for key in match_files:
            if key in evasion_files:
                match_path = match_files[key]
                for evasion_path in evasion_files[key]:
                    log_pairs.append((match_path, evasion_path))

    return log_pairs

def export_differences_to_csv(log_pairs, csv_filename='evasion_differences.csv'):
    with open(csv_filename, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Match File', 'Evasion File', 'Field', 'Match Value', 'Evasion Value'])

        for match_path, evasion_path in log_pairs:
            match_log = load_json(match_path)
            evasion_log = load_json(evasion_path)

            diffs = compare_dicts(match_log, evasion_log)
            for key, match_val, evasion_val in diffs:
                writer.writerow([
                    os.path.basename(match_path),
                    os.path.basename(evasion_path),
                    key,
                    str(match_val),
                    str(evasion_val)
                ])

def main():
    base_dir = "/home/amides/amides/amides/data/sigma/events/windows/process_creation/"
    log_pairs = find_log_pairs(base_dir)
    export_differences_to_csv(log_pairs)
    print(f"✅ Export complete: evasion_differences.csv with {len(log_pairs)} log pair(s) processed.")

if __name__ == "__main__":
    main()




