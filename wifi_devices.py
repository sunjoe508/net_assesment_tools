import os
import subprocess
from scapy.all import ARP, Ether, srp

def get_connected_wifi():
    """
    Get the currently connected Wi-Fi network name (SSID).
    """
    try:
        if os.name == "nt":  # For Windows
            result = subprocess.check_output("netsh wlan show interfaces", shell=True, text=True)
            for line in result.splitlines():
                if "SSID" in line and "BSSID" not in line:
                    return line.split(":")[1].strip()
        else:  # For Linux/macOS
            result = subprocess.check_output("iwgetid -r", shell=True, text=True).strip()
            return result
    except Exception as e:
        print(f"Error retrieving Wi-Fi details: {e}")
        return None

def scan_network(network_cidr):
    """
    Scan the local network for active devices using ARP requests.
    """
    print(f"Scanning network {network_cidr} for devices...\n")
    devices = []
    arp = ARP(pdst=network_cidr)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=False)[0]

    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def main():
    print("Wi-Fi Device Scanner")
    print("=" * 40)

    wifi_name = get_connected_wifi()
    if not wifi_name:
        print("Unable to retrieve connected Wi-Fi name. Ensure you're connected to a Wi-Fi network.")
        return

    print(f"Connected to Wi-Fi: {wifi_name}\n")

    # Derive the network CIDR (assume /24 for most cases)
    ip_result = subprocess.check_output("ipconfig" if os.name == "nt" else "ifconfig", shell=True, text=True)
    for line in ip_result.splitlines():
        if "IPv4 Address" in line or "inet " in line:
            local_ip = line.split()[-1]
            network_cidr = f"{local_ip.rsplit('.', 1)[0]}.0/24"
            break
    else:
        print("Unable to determine local IP or network CIDR.")
        return

    print(f"Scanning network: {network_cidr}...\n")
    devices = scan_network(network_cidr)

    if not devices:
        print("No devices found on the network.")
    else:
        print(f"Devices connected to Wi-Fi ({wifi_name}):")
        print("=" * 40)
        for idx, device in enumerate(devices, start=1):
            print(f"{idx}. IP: {device['ip']}, MAC: {device['mac']}")
        print("=" * 40)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except PermissionError:
        print("Permission denied. Run the script with elevated privileges (e.g., sudo).")
