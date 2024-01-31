import requests
import pandas as pd
import re
from io import StringIO
import subprocess

# Configuration variables
url = "http://95.217.228.46:41337/metagraph?netuid=18"
min_stake = 1000  # Minimum STAKE amount to filter
ipv4_regex = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # Regex pattern for matching IPv4 addresses


# Make the GET request to the URL
response = requests.get(url)
response_text = response.text

# Convert CSV data to DataFrame
df = pd.read_csv(StringIO(response_text))

# Clean up nonstandard characters in column names
df.columns = [re.sub(r'[^A-Za-z0-9]', '', col) for col in df.columns]

# Display the DataFrame
print(df)


# Filter DataFrame by STAKE amount
filtered_df = df[df['STAKE'] >= min_stake]

# Iterate over the filtered DataFrame
for index, row in filtered_df.iterrows():
    axon = row['AXON']
    if pd.notna(axon):  # Check if axon is not NaN
        match = re.search(ipv4_regex, axon)
        if match:
            print(row)
            ip_address = match.group(1)
            try:
                # Execute subprocess to add UFW rule
#                subprocess.run(["ufw", "allow", "from", ip_address, "to", "any", "port", "1000:65535"], check=True)
                print(f"Firewall rule added for IP: {ip_address}")
            except subprocess.CalledProcessError as e:
                print(f"Error adding firewall rule for IP: {ip_address}: {e}")
