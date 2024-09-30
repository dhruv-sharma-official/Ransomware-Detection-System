import os
import random

def simulate_ransomware(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            # Rename files with a ransomware-like extension
            new_name = file + random.choice(['.enc', '.crypt', '.locked'])
            os.rename(os.path.join(root, file), os.path.join(root, new_name))

simulate_ransomware(os.path.expanduser('C:\Users\dhruv\Downloads'))  # Change path as needed
