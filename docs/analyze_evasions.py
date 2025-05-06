import pandas as pd

# Load the CSV
df = pd.read_csv("evasion_differences.csv")

# 1. Field frequency
print("\n📌 Most commonly changed fields:")
print(df['Field'].value_counts())

# 2. CommandLine examples
# Try to sample from CommandLine (or whatever field exists)
target_field = 'CommandLine'  # Update this if needed

cmd_df = df[df['Field'] == target_field]

if not cmd_df.empty:
    print(f"\n🧪 Sample changes for field '{target_field}':")
    print(cmd_df[['Match Value', 'Evasion Value']].sample(min(5, len(cmd_df))))
else:
    print(f"\n⚠️ No rows found for field '{target_field}'.")


# 3. CommandLine patterns
print("\n🔎 Obfuscation indicators (base64, powershell, symbols):")
pattern_hits = cmd_df['Evasion Value'].str.contains("base64|b64|enc|powershell|\\+|\\|", case=False, na=False)
print(pattern_hits.value_counts())

# 4. Critical fields
critical_fields = ['Image', 'ParentImage', 'ParentCommandLine']
crit_df = df[df['Field'].isin(critical_fields)]
print("\n🚨 Critical fields changed:")
print(crit_df['Field'].value_counts())

# 5. Trivial changes (case/space only)
def is_trivial_change(row):
    mv, ev = str(row['Match Value']), str(row['Evasion Value'])
    return mv.lower().strip() == ev.lower().strip()

df['TrivialChange'] = df.apply(is_trivial_change, axis=1)
print(f"\n🧹 Trivial changes (same after case/space normalization): {df['TrivialChange'].sum()}")

# 6. Fields changed per evasion
change_counts = df.groupby('Evasion File')['Field'].nunique().reset_index(name='NumFieldsChanged')
print("\n📊 Most modified evasions (by number of fields):")
print(change_counts.sort_values(by='NumFieldsChanged', ascending=False).head())

# 7. List of fields changed per evasion
fields_per_evasion = df.groupby('Evasion File')['Field'].apply(list)
print("\n📋 Fields changed in each evasion:")
print(fields_per_evasion.head())

# Export Match Value and Evasion Value only
df[['Match Value', 'Evasion Value']].to_csv('match_vs_evasion.csv', index=False)
print("\n✅ Exported 'match_vs_evasion.csv' with Match and Evasion values only.")

with open('match_vs_evasion.txt', 'w', encoding='utf-8') as f:
    for idx, row in df.iterrows():
        f.write(f"\n🔹 Row {idx+1}\n")
        f.write(f"Field: {row['Field']}\n")
        f.write(f"Match Value:\n{row['Match Value']}\n")
        f.write(f"Evasion Value:\n{row['Evasion Value']}\n")
        f.write("-" * 60 + "\n")

df_short = df.copy()
df_short['Match Value'] = df_short['Match Value'].astype(str).str.slice(0, 80)
df_short['Evasion Value'] = df_short['Evasion Value'].astype(str).str.slice(0, 80)

df_short.to_csv('match_vs_evasion_truncated.csv', index=False)
print("📁 Exported to match_vs_evasion_truncated.csv (80-char previews).")


for field_name, group_df in df.groupby('Field'):
    filename = f"evasion_diffs_{field_name.replace('.', '_')}.csv"
    group_df.to_csv(filename, index=False)
    print(f"📁 Exported: {filename}")

df.to_excel('match_vs_evasion.xlsx', index=False)
print("📁 Exported to match_vs_evasion.xlsx")
