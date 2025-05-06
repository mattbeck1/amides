import os
import yaml

def extract_edited_fields(base_dir):
    edited_fields_by_folder = {}

    for root, dirs, files in os.walk(base_dir):
        if 'properties.yml' in files:
            prop_path = os.path.join(root, 'properties.yml')
            try:
                with open(prop_path, 'r') as f:
                    yml = yaml.safe_load(f)
                folder_name = os.path.basename(root)
                edited_fields = yml.get('edited_fields', [])
                if edited_fields:
                    edited_fields_by_folder[folder_name] = edited_fields
            except Exception as e:
                print(f"Error reading {prop_path}: {e}")

    return edited_fields_by_folder

def save_results(results, output_path="edited_fields_summary.csv"):
    with open(output_path, "w") as f:
        f.write("Folder,Edited Fields\n")
        for folder, fields in sorted(results.items()):
            fields_str = "; ".join(fields)
            f.write(f"{folder},{fields_str}\n")
    print(f"Saved summary to {output_path}")

# Example usage
if __name__ == "__main__":
    base_dir = "/home/amides/amides/amides/data/sigma/events/windows/process_creation"  # Update this
    results = extract_edited_fields(base_dir)
    save_results(results)
