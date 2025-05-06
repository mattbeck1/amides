import pandas as pd

# Load the CSV
df = pd.read_csv("evasion_differences.csv")

# 1. Field frequency
print("\n📌 Most commonly changed fields:")
print(df['Field'].value_counts())

# 2. CommandLine examples
cmd_df = df[df['Field'] == 'CommandLine']
print("\n🧪 Sample CommandLine changes:")
print(cmd_df[['Match Value', 'Evasion Value']].sample(5))

# 3. CommandLine patterns
print("\n🔎 Obfuscation indicators (base64, powershell, symbols):")
pattern_hits = cmd_df['Evasion Value'].str.contains("base64|b64|enc|powershell|\\+|\\|", case=False, na=False)
print(pattern_hits.value_counts())

# 4. Critical fields
critical_fields = ['CommandLine']
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
