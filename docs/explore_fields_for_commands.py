import pandas as pd
import subprocess
import difflib

# Load data
df = pd.read_csv("evasion_differences.csv")
target_field = "CommandLine"  # or whatever field holds command lines
cmd_df = df[df['Field'] == target_field].dropna().reset_index(drop=True)

def is_runnable(cmd):
    return any(x in cmd.lower() for x in ['cmd', 'powershell', '.exe', '/c', '-enc'])

# Filter further
cmd_df = cmd_df[
    cmd_df['Match Value'].apply(is_runnable) & 
    cmd_df['Evasion Value'].apply(is_runnable)
].reset_index(drop=True)

def run_cmd(command):
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        return "", f"ERROR: {e}"

results = []

for i, row in cmd_df.iterrows():
    match_cmd = row['Match Value']
    evasion_cmd = row['Evasion Value']

    match_out, match_err = run_cmd(match_cmd)
    evasion_out, evasion_err = run_cmd(evasion_cmd)

    is_equivalent = match_out == evasion_out

    results.append({
        'Match Cmd': match_cmd,
        'Evasion Cmd': evasion_cmd,
        'Match Out': match_out,
        'Evasion Out': evasion_out,
        'Match Err': match_err,
        'Evasion Err': evasion_err,
        'Equivalent': is_equivalent
    })


import csv

with open("functional_equivalence_report.csv", "w", newline='', encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=results[0].keys())
    writer.writeheader()
    writer.writerows(results)

print("✅ Functional comparison report saved to functional_equivalence_report.csv")
