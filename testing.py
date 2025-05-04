import pandas as pd

# Define file paths
input_file = "merged_dataset.csv"  # Path to merged dataset
output_file = "sampled_dataset.csv"  # Path to save sampled dataset

# Number of samples to extract
num_samples = 100  # Change this value if needed

# Load the dataset
df = pd.read_csv(input_file)

# Randomly sample rows from the dataset
sampled_df = df.sample(n=num_samples, random_state=42)  # Random state ensures reproducibility

# Save the sampled dataset
sampled_df.to_csv(output_file, index=False)

print(f"✅ Sampled dataset with {num_samples} rows saved to {output_file}")
