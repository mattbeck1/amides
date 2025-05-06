import pandas as pd
import subprocess

# Load your CSV
df = pd.read_csv("evasion_differences.csv")

# Set the field you want to compare
target_field = "process"  # Change this if your field name is different

# Filter rows that contain just that field
cmd_df = df[df['Field'] == target_field].reset_index(drop=True)

# Create a log file
with open("command_comparison_log.txt", "w") as log:
    for i, row in cmd_df.iterrows():
        match_cmd = str(row["Match Value"])
        evasion_cmd = str(row["Evasion Value"])

        log.write(f"\n==============================\n")
        log.write(f"🧪 Pair {i+1}\n")
        log.write(f"📜 Match Command:\n{match_cmd}\n")
        log.write(f"🕵️ Evasion Command:\n{evasion_cmd}\n")

        # Function to safely run a command and capture output
        def run_cmd(cmd):
            try:
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=10  # Prevent hanging
                )
                return result.stdout.strip(), result.stderr.strip()
            except Exception as e:
                return "", f"ERROR: {e}"

        # Run and log both
        match_out, match_err = run_cmd(match_cmd)
        evasion_out, evasion_err = run_cmd(evasion_cmd)

        log.write(f"\n✅ Match Output:\n{match_out}\n")
        if match_err:
            log.write(f"⚠️ Match Error:\n{match_err}\n")

        log.write(f"\n✅ Evasion Output:\n{evasion_out}\n")
        if evasion_err:
            log.write(f"⚠️ Evasion Error:\n{evasion_err}\n")

print("✅ Done. Results saved to 'command_comparison_log.txt'")
