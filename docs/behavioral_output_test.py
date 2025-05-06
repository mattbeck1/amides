import pandas as pd
import re

df = pd.read_csv("evasion_differences.csv")

def extract_command(value):
    if not isinstance(value, str):
        return ''
    match = re.search(r'CommandLine:\s*(.*)', value)
    if match:
        return match.group(1).strip()
    return value.strip()

def normalize(cmd):
    if not isinstance(cmd, str):
        return ''
    cmd = cmd.lower().strip()
    cmd = re.sub(r'\s+', ' ', cmd)  # normalize whitespace
    cmd = cmd.replace('^', '')  # remove obfuscation
    return cmd

results = []

for i, row in df.iterrows():
    match_raw = extract_command(row['Match Value'])
    evasion_raw = extract_command(row['Evasion Value'])

    match_cmd = normalize(match_raw)
    evasion_cmd = normalize(evasion_raw)

    equivalent = match_cmd == evasion_cmd

    results.append({
        'Pair Index': i,
        'Match Cmd': match_cmd,
        'Evasion Cmd': evasion_cmd,
        'Equivalent': equivalent
    })

pd.DataFrame(results).to_csv("static_functional_equivalence.csv", index=False)
print("✅ Static comparison saved to static_functional_equivalence.csv")
