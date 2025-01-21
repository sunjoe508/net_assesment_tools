import os
import platform
from scapy.all import sniff, ARP, Ether, srp
from scapy.layers.http import HTTPRequest  # Import HTTP layer for HTTP request analysis
from scapy.layers.inet import IP, TCP, UDP

def scan_networks():
    """
    Scans available Wi-Fi networks and returns a list of networks.
    """
    print("[INFO] Scanning available Wi-Fi networks...")
    networks = []

    if platform.system() == "Linux":
        # Use `nmcli` to list Wi-Fi networks on Linux
        result = os.popen("nmcli -t -f SSID dev wifi").read()
        networks = [line.strip() for line in result.split("\n") if line.strip()]
    elif platform.system() == "Windows":
        # Use `netsh` to list Wi-Fi networks on Windows
        result = os.popen("netsh wlan show networks").read()
        for line in result.split("\n"):
            if "SSID" in line:
                networks.append(line.split(":")[1].strip())
    else:
        print("[ERROR] Unsupported operating system.")
    
    return networks

def discover_devices(network_ip):
    """
    Uses ARP to discover devices on the given network.
    """
    print(f"[INFO] Discovering devices on network: {network_ip}")
    # Create an ARP request to get the MAC addresses in the given network range
    arp_request = ARP(pdst=network_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    # Send the request and receive the response
    result = srp(arp_request_broadcast, timeout=3, verbose=False)[0]

    devices = []
    for sent, received in result:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})

    return devices

def packet_callback(packet):
    """
    Callback function to process captured packets.
    """
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"[INFO] Packet: {src_ip} --> {dst_ip}")

        if packet.haslayer(TCP):
            print("    Protocol: TCP")
            print(f"    Source Port: {packet[TCP].sport}")
            print(f"    Destination Port: {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print("    Protocol: UDP")
            print(f"    Source Port: {packet[UDP].sport}")
            print(f"    Destination Port: {packet[UDP].dport}")

        if packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]
            print("    HTTP Request:")
            print(f"    Host: {http_layer.Host.decode()}")
            print(f"    Path: {http_layer.Path.decode()}")

def monitor_network(interface):
    """
    Capture packets on the given network interface.
    """
    print(f"[INFO] Monitoring network on interface: {interface}")
    print("Press Ctrl+C to stop.\n")
    try:
        sniff(iface=interface, prn=packet_callback, store=False)
    except PermissionError:
        print("[ERROR] Permission denied. Run the script with elevated privileges.")
    except KeyboardInterrupt:
        print("\n[INFO] Monitoring stopped.")

def main():
    print("Wi-Fi Network Activity Monitor and Device Discovery")
    print("=" * 50)

    # Step 1: Scan available Wi-Fi networks
    networks = scan_networks()

    if not networks:
        print("[ERROR] No Wi-Fi networks found. Ensure Wi-Fi is enabled.")
        return

    print("\nAvailable Wi-Fi Networks:")
    for idx, network in enumerate(networks, 1):
        print(f"{idx}. {network}")

    # Step 2: Select a Wi-Fi network
    choice = int(input("\nSelect a Wi-Fi network (enter the number): "))
    if choice < 1 or choice > len(networks):
        print("[ERROR] Invalid selection.")
        return

    selected_network = networks[choice - 1]
    print(f"[INFO] Selected Network: {selected_network}")

    # Step 3: Get the local network range (this can be adjusted)
    local_ip = input("Enter your local IP address (e.g., 192.168.1.101): ").strip()
    if not local_ip:
        print("[ERROR] Invalid IP address.")
        return

    # Calculate the network IP range for ARP discovery
    network_ip = ".".join(local_ip.split(".")[:-1]) + ".1/24"
    print(f"[INFO] Scanning devices on network: {network_ip}")

    # Step 4: Discover devices on the network
    devices = discover_devices(network_ip)

    if devices:
        print("\n[INFO] Devices found on the network:")
        for device in devices:
            print(f"IP: {device['ip']} | MAC: {device['mac']}")
    else:
        print("[INFO] No devices found on the network.")

    # Step 5: Specify the network interface
    interface = input("Enter the network interface to monitor (e.g., wlan0): ").strip()

    if not interface:
        print("[ERROR] Network interface not specified.")
        return

    # Step 6: Monitor the selected network
    monitor_network(interface)

if __name__ == "__main__":
    main()
