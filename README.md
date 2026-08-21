# SSH-log-analyzer
Python tool designed to parse SSH authentication log files and detect suspicious login patterns. It combines time-series sliding window analysis with statistical anomaly detection to identify brute-force attacks.
## Features
- Interactive **Tkinter** interface with custom file selection.
- **Dual Detection Engine**:
    - **Sliding Window**: Flags rapid burst attacks.
    - **Statistical Anomaly Detection**: Uses NumPy to calculate the 95th percentile of failed login counts per day, surfacing high-volume attack vectors.
