# RansomOps-Demo

The RansomOps-Demo project serves as a practical demonstration of how ransomware attacks operate, aiming to raise awareness about cybersecurity threats and the consequences of careless digital practices.

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Environment Setup](#environment-setup)
4. [Prerequisites](#prerequisites)
5. [Installation](#installation)
6. [Usage](#usage)
7. [Troubleshooting](#troubleshooting)
8. [Clean Up](#clean-up)
9. [Disclaimer](#disclaimer)
---

## Overview

In this educational simulation, we explore a real-world scenario where a victim unknowingly downloads malware disguised as legitimate software from a phishing website. Once installed, the malware encrypts the victim's files, rendering them inaccessible and leaving the victim at the mercy of attackers.

---
## Features

- **Phishing Simulation**: Demonstrates how attackers use phishing techniques to deliver malicious software.
- **Ransomware Execution**: Shows the encryption of victim files to simulate a ransomware attack.
- **Educational Focus**:  Highlights prevention strategies and raises awareness of cybersecurity risks.
- **Environment Isolation**: Runs in a controlled setup using virtual machines for safety.

---
## Environment Setup 

- **Attacker’s Setup**:  
  - Operating System: Kali Linux (used for launching attacks and monitoring the victim’s machine).  

- **Victim’s Setup**:  
  - Operating System: Windows running in VMware. 




## Prerequisites

Before starting, ensure you have:
- [VMware](https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion)
- [Kali Linux](https://www.kali.org/get-kali/#kali-platforms) 


---

## Installation

### **Step 1: Clone the Repository**
```bash
git clone <repository-url>
cd RansomOps-Demo
`````

### Step 2: Configure Virtual Machines
- Set up Kali Linux and Windows virtual machines in VMware.
- Assign network configurations (e.g., NAT or Bridged) to ensure connectivity between the attacker and victim machines.

### Step 3:  Set Up Phishing Website
On the Kali Linux machine:
1. Install Apache:
```bash
sudo apt update && sudo apt install apache2 -y
`````
2. Host the phishing webpage in `/var/www/html`.

### Step 4: Deploy Ransomware Payload
- Prepare the ransomware payload and ensure it is accessible through the phishing site.

### Step 5: Test the Setup
- Verify that the victim can access the phishing site and download the payload.

- Simulate the attack and observe the ransomware execution.


## Usage
### Running the Simulation
1. Launch both the attacker and victim virtual machines.
2. Access the phishing site from the victim’s browser.
3. Download and execute the ransomware payload on the victim machine.
4. Observe the file encryption and ransomware behavior.

### Post-Attack Analysis
- Review the attack logs on the Kali Linux machine.
- Discuss mitigation strategies and prevention methods.

## Troubleshooting
### Common Issues
- Phishing Site Not Accessible: Ensure Apache is running and network settings are configured correctly.
```bash
sudo systemctl start apache2
`````


- **VMware Network Issues**: Check that both virtual machines are on the same network type (NAT/Bridged).

- **Payload Not Executing**: Verify that the payload is compatible with the victim’s OS and that any required dependencies are present.


## Clean Up
To safely clean up the demo:
1. Shut down and delete the victim and attacker virtual machines.
2. Remove any residual files from the host system.
3. Reset network configurations if modified.


## Contributing
If you wish to contribute:

1. Fork the repository.
2. Create a feature branch:
```bash
git checkout -b feature-name
`````
3. Commit your changes:
```bash
git commit -m "Add feature"
`````
4. Push to the branch:
```bash
git push origin feature-name
`````
5. Create a pull request.

---
🚨## Disclaimer
**Disclaimer**: This project is for educational and awareness purposes only. Unauthorized use of the information provided here for malicious intent is strictly prohibited.