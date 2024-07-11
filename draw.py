import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime
import re

# Given log data
log_data = """
2024-07-11T03:02:27.028+10:00 INFO [07-10|17:02:27] [Liam] [commitNewWork] start Finalize elapsed=1.123s
2024-07-11T03:05:29.397+10:00 INFO [07-10|17:05:29] [Liam] [commitNewWork] start Finalize elapsed=1.269s
2024-07-11T03:08:29.496+10:00 INFO [07-10|17:08:29] [Liam] [commitNewWork] start Finalize elapsed=1.325s
2024-07-11T03:11:29.515+10:00 INFO [07-10|17:11:29] [Liam] [commitNewWork] start Finalize elapsed=1.357s
2024-07-11T03:14:30.804+10:00 INFO [07-10|17:14:30] [Liam] [commitNewWork] start Finalize elapsed=1.526s
"""

# Extract data from log
timestamps = []
elapsed_times = []

for line in log_data.strip().split('\n'):
    timestamp_match = re.search(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}\+\d{2}:\d{2})', line)
    elapsed_match = re.search(r'elapsed=(\d+\.\d+)s', line)
    
    if timestamp_match and elapsed_match:
        timestamps.append(datetime.fromisoformat(timestamp_match.group(1)))
        elapsed_times.append(float(elapsed_match.group(1)))

# Create a DataFrame
df = pd.DataFrame({
    'Time': timestamps,
    'Elapsed Time': elapsed_times
})

# Plot the data
plt.figure(figsize=(10, 5))
plt.plot(df['Time'], df['Elapsed Time'], marker='o')
plt.xlabel('Time')
plt.ylabel('Elapsed Time (s)')
plt.title('Elapsed Time Over Time')
plt.grid(True)
plt.show()
