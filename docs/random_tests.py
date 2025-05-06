import pandas as pd
df = pd.read_csv("evasion_differences.csv")
print(df['Field'].unique())

# View a few sample entries where the field is 'process'
df[df['Field'] == 'process'][['Match Value', 'Evasion Value']].head(5)
