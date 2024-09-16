# Windows Baseline Host Enumeration Script

## Overview

The `WindowsBaselineEnumeration.ps1` script is designed to perform a comprehensive baseline enumeration of a Windows host. This script collects various system information that can be useful for system administrators, security analysts, and IT professionals to understand the current state of a Windows machine.

| Windows OS Version | Baseline Script Applicable |
|--------------------|----------------------------|
| Windows 11         | **Yes** ✅                 |
| Windows 10         | **Yes** ✅                 |

## Features

- Collects system information such as OS version, installed software, and hardware details.
- Gathers network configuration and connection details.
- Retrieves security-related information including user accounts, group memberships, and security policies.
- Outputs the collected data in a structured format for easy analysis.

## Prerequisites

- Windows PowerShell 5.1 or later.
- Administrative privileges to run the script and access system information.

## Usage

1. **Download the Script**

   Download the `WindowsBaselineEnumeration.ps1` script to your local machine.

2. **Open PowerShell as Administrator**

   Right-click on the PowerShell icon and select "Run as Administrator" to open a PowerShell session with elevated privileges.

3. **Navigate to the Script Directory**

   Use the `cd` command to navigate to the directory where the script is located. For example:
   ```powershell
   cd C:\path\to\script
   ```

4. **Run the Script:** Excecute the script by typing the following command:
    ```powershell
    .\Windows11_10_BaseEnum.ps1
    ```

5. **Follow the Prompts Provided:** The script will prompt you to specify the **output directory** and **descriptive file name** for the collected data.

**NOTE:** it is recommended to use a descriptive file name that includes the hostname and date of the enumeration. For example: `hostname_yyyy-mm-dd_hh-mm-ss`. This will help with organizing and identifying the collected data for later analysis.

## Example Output

- **System Information**
OS Name: Microsoft Windows 10 Pro
OS Version: 10.0.19042 N/A Build 19042
System Manufacturer: Dell Inc.
System Model: XPS 15 9570

- **Installed Software**
Adobe Acrobat Reader DC
Google Chrome
Microsoft Office 365

- **Network Configuration**
IP Address: 192.168.1.100
Subnet Mask: 255.255.255.0
Default Gateway: 192.168.1.1

## Customization

You can customize the script to collect additional information or modify the output format. Open the script in a text editor and make the necessary changes. Ensure you test the modified script in a controlled environment before deploying it in a production setting.

## Troubleshooting

- **Permissions Issues:** Ensure you are running the script with administrative privileges.

- **PowerShell Exeuction Policy:** If you encounter an error related to the PowerShell execution policy, you can temporarily bypass by running: 

  ```powershell
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  ```

## Contributing

If you have suggestions for improvements or have identified bugs, please open an issue or submit a pull request on the repository.

## Next Steps...

- Exapand compatiblity with the following Windows OS Versions

| Windows OS Version       | Baseline Script Applicable  |
|--------------------------|-----------------------------|
| Windows 8.1              | **In Progress** 🟡          |
| Windows 8                | **In Progress** 🟡          |
| Windows 7                | **In Progress** 🟡          |
| Windows Server 2022      | **In Progress** 🟡          |
| Windows Server 2019      | **In Progress** 🟡          |
| Windows Server 2016      | **In Progress** 🟡          |
| Windows Server 2012 R2   | **In Progress** 🟡          |
| Windows Server 2012      | **In Progress** 🟡          |
