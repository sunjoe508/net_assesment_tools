# 🌐 **Wi-Fi Network Activity Monitor & Device Discovery**

## 📡 **Overview**

Welcome to **Wi-Fi Network Activity Monitor & Device Discovery**, your ultimate tool to monitor your Wi-Fi network, discover devices, and track real-time network activity! 🚀 Whether you're an IT pro, network administrator, or just curious about your home network, this tool gives you deep insights into connected devices and their activity.

### 🧑‍💻 **Key Features**
- **Wi-Fi Network Discovery**: Scan for available Wi-Fi networks and select one to monitor.
- **Device Discovery**: Automatically detect devices on your network and get their details (IP, MAC, Hostname, OS).
- **Real-Time Network Monitoring**: Capture and analyze network packets (TCP, UDP, HTTP).
- **Detailed Device Reports**: View a full list of all detected devices on the network with crucial info.
- **Security Insights**: Monitor suspicious activity and track potential threats in real-time.

---

## 🔧 **Requirements**

Before using the tool, you will need the following:

- **Python 3.x** installed
- **Libraries**:
    - `scapy` (for packet sniffing and network discovery)
    - `colorama` (to beautify terminal output)
    - `nmap` (to detect operating systems of devices)
    - `os` (for OS interaction)
    - `platform` (to detect system type and adjust commands)

To install the required libraries, simply run:

```bash
pip install scapy colorama

🚀 Installation Steps

    Clone the repository:

git clone https://github.com/your-username/wifi-network-activity-monitor.git

Navigate into the project folder:

cd wifi-network-activity-monitor

Run the tool:

    python wifi_activity_tracker.py

🛠️ How It Works
Step 1: Wi-Fi Network Discovery

    The tool starts by scanning all available Wi-Fi networks in your area.
    A list of networks will be displayed for you to choose from.

Step 2: Device Discovery

    After selecting a network, the tool uses ARP requests to identify devices connected to the network.
    For each device, it captures important information like:
        🖧 IP Address
        🏷️ MAC Address
        🏠 Hostname
        🖥️ Operating System

Step 3: Real-Time Network Activity Monitoring

    The tool listens for network traffic and logs packets in real time.
    It captures and displays the following details:
        📡 Protocol (TCP, UDP, HTTP)
        🏷️ Source & Destination IPs
        🌐 HTTP Requests (hostnames and paths)
        🛠️ Port Scanning Results (for security monitoring)

Step 4: Generate Device Report

    A summary report of all devices on the network is compiled.
    The report includes:
        Device Info (IP, MAC, Hostname, OS)
        Network Traffic Logs (packets captured)

📋 Sample Output
Wi-Fi Network Discovery:

[INFO] Scanning available Wi-Fi networks...

Available Wi-Fi Networks:
1. Network_A
2. Network_B
3. Network_C

Select a Wi-Fi network (enter the number): 2
[INFO] Selected Network: Network_B

Device Discovery:

[INFO] Discovering devices on network: 192.168.1.0/24

[INFO] Devices found on the network:
IP: 192.168.1.5 | MAC: 00:1A:2B:3C:4D:5E | Hostname: device1.local | OS: Linux
IP: 192.168.1.6 | MAC: 00:1B:3C:4D:5E:6F | Hostname: device2.local | OS: Windows

Real-Time Network Activity:

[INFO] Packet: 192.168.1.5 --> 192.168.1.6, Protocol: TCP
    Source Port: 80, Destination Port: 12345
    HTTP Request: Host: www.example.com, Path: /home

📜 Logging and Reports

The tool logs all captured data into a file named network_activity_log.txt. The log includes:

    Device details (IP, MAC, Hostname, OS)
    Network packets (TCP, UDP, HTTP)
    Date & Time of Activity: For historical tracking

You can review the file to analyze network activity over time.
📝 Usage Tips

    Run with Elevated Privileges: Some features (such as network discovery) require administrator or root privileges. Use sudo on Linux/macOS or run as Administrator on Windows.

    sudo python wifi_activity_tracker.py

    Selecting the Correct Interface: When monitoring traffic, ensure you're using the correct network interface (e.g., wlan0 for Wi-Fi).

    Stopping the Script: Press Ctrl+C to stop the real-time monitoring anytime.

🤝 Contributing

We encourage contributions! If you want to improve this tool or add new features, please feel free to fork the repo and submit a pull request.

Here’s how to contribute:

    Fork this repository.
    Clone your forked repo locally.
    Make changes or add features.
    Submit a pull request.

🛡️ License

This project is open-source and available under the MIT License. See the LICENSE file for more details.
⚠️ Disclaimer

Please use this tool responsibly. Unauthorized scanning or sniffing of network traffic may be illegal in some jurisdictions. Ensure you have explicit permission before running this tool on any network.
👀 Looking Forward

In future versions, we plan to integrate more advanced features like:

    Automated Threat Detection: Using machine learning to identify suspicious network behavior.
    Enhanced Visualization: Offering a graphical representation of the network traffic and devices.
    Cross-Platform Support: Making the tool more compatible across different OSes.

Stay tuned! ✨

---

### **Key Enhancements in this Version:**

- **Visual Appeal**: Added more emojis and sections to make it more visually engaging.
- **Code Blocks**: Clearer sections using code blocks for sample outputs, installation commands, and other technical details.
- **Structured Sections**: Organized each part of the tool with clear and descriptive headings.
- **Real-Time Updates**: Incorporated dynamic and interactive sections like monitoring network traffic in real-time.

This version should make your README much more visually appealing, while providing all the technical details needed for a smooth user experience.
best
