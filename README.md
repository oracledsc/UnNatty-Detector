# UnNatty Detector v2.0.0

UnNatty Detector is a comprehensive tool designed to analyze process memory and detect anomalies, with a focus on identifying potential hooks and tampering in Discord's voice communication module.

## Features

### 1. Advanced Hook Detection
- Comprehensive scan of process memory for various hook types:
  - Inline Hooks
  - Import Address Table (IAT) Hooks
  - Virtual Table (VTable) Hooks
  - Page Guard Hooks
- Detailed pattern matching for suspicious code modifications

### 2. Module and Node Integrity Verification
- Validates integrity of `discord_voice.node`
- Compares loaded modules against original file
- Checks for unauthorized modifications in executable sections

### 3. Audio Hook Specific Detection
- Specialized scanning for audio-related hooks
- Identifies suspicious signatures and hex patterns
- Focuses on Discord voice communication modules

### 4. ImGui and Extended Signature Detection
- Scans for potential injection indicators
- Detects ImGui-related signatures
- Identifies suspicious module names and string patterns

### 5. Comprehensive Logging
- Generates detailed `logs.txt` with:
  - Timestamp of detection
  - Specific module and hook information
  - Detected suspicious patterns
  - Memory region details

## Technical Capabilities

- Memory scanning across different protection levels
- Multi-module analysis for Discord variants (Discord, DiscordCanary, DiscordPTB)
- Advanced byte-level comparison techniques

## Compilation Requirements

- Visual Studio 2022
- Windows SDK
- C++17 Standard
- Dependencies:
  - Windows API
  - Toolhelp32 Library
  - ImageHlp Library
  - WinTrust Library

## Usage

1. Run the executable
2. Allow scanning of running Discord process
3. Review `logs.txt` for detailed findings

### Caution
- Tool is for educational and security research purposes
- Use responsibly and ethically
- No guarantee of 100% detection

## License

Copyright (c) 2024 UnNatty Detector

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Contact
For support or inquiries, contact oracledsc on discord
