# UnNatty Detector v1.4

UnNatty Detector is a tool designed to analyze the memory of processes and detect any anomalies, including hooks or altered `discord_voice.node` files. It provides insights into potential tampering and aids in identifying suspicious behavior.

## Features

### 1. Hook Detection
- Scans the memory of the loaded `discord_voice.node` process.
- Detects Address-Of-Byte (AOB) changes and abnormal Assembly (ASM) code.
- Alerts when hooks are found and logs them for further analysis.

### 2. Process History Inspection
- Tracks the process history to detect patterns of injection or suspicious activity.
- Analyzes process creation and termination behaviors for irregularities.

### 3. Byte Comparison
- Compares the file size of the loaded `discord_voice.node` with the latest official version.
- Identifies outdated or potentially tampered files.

### 4. Detailed Logging
- Generates a `logs.txt` file with:
  - Details on detected hooks.
  - Anomalies in memory.
  - Process history for manual inspection.
- Useful for advanced debugging and verification.

### 5. User-Friendly Alerts
- Displays warnings such as:
  ```
  Hook detected! Analyze `logs.txt` for more information.
  ```
- Provides a fallback message:
  ```
  No hooks detected, but this doesn't guarantee safety. Check `logs.txt` and review process history.
  ```

---

## How to Compile and Use

### Build from Source
If you don’t trust the provided executable, you can build the tool from source:
1. Ensure you have Visual Studio 2022 installed.
2. Clone the repository:
   ```bash
   git clone https://github.com/oracledsc/UnNatty-Detector.git
   cd UnNatty-Detector
   ```
3. Open the project in Visual Studio 2022 and build the solution in Release x64
4. For assistance, DM `oracledsc` on Discord.

### Download Precompiled Binary
You can directly download the precompiled binary from the [Releases Page](https://github.com/oracledsc/UnNatty-Detector/releases/download/release/UnNatty-Detector.exe).

### Usage
1. **Send the Tool**: Share the `UnNatty-Detector.exe` file with the target user.
2. **Make sure he doesn't restart Discord or leave the VC!**
3. **Run on Screenshare**: Instruct the user to run the tool while screensharing.
4. **Analyze Results**:
   - If a hook is detected, the tool will alert: `Hook detected! Analyze logs.txt for more information.`
   - If no hook is detected, the tool will say so but advise checking the `logs.txt` file manually.
   - The `logs.txt` file includes:
     - Process list: Helps identify suspicious processes like Abaddon or hooks.
     - Voice node details: Includes file size, offsets, etc., to verify against the latest Discord voice node.
     - More Infos if a hook has been detected.

### What to Do If Someone Bypasses It
If someone bypasses the tool or it fails to detect a hook:
- DM `oracledsc` on Discord for support and fixes.
- The tool is basic for now, but no one has been able to bypass it yet.
  
---

## Disclaimer
This tool is for educational purposes only. Use it responsibly and in accordance with all applicable laws and regulations.
