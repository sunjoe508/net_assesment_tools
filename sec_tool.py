import socket
import threading
from scapy.all import ARP, Ether, srp
import ipaddress

# scan for devices on the network
def discover_devices(network_cidr):
    print(f"Scanning the network for devices ({network_cidr})...")
    devices = []
    arp = ARP(pdst=network_cidr)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=False)[0]

    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

#  scan open ports on a given device
def scan_port(ip, port, open_ports):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
    except Exception:
        pass

def check_open_ports(ip, port_range):
    open_ports = []
    threads = []
    for port in port_range:
        thread = threading.Thread(target=scan_port, args=(ip, port, open_ports))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()
    return open_ports

#  security report
def generate_report(devices):
    print("\nGenerating Security Assessment Report...")
    print("=" * 50)
    print(f"Total Devices Found: {len(devices)}")
    print("Devices and Open Ports:")
    for device in devices:
        print(f"Device IP: {device['ip']}, MAC Address: {device['mac']}")
        if 'open_ports' in device:
            if device['open_ports']:
                print(f"  Open Ports: {', '.join(map(str, device['open_ports']))}")
                print("  Potential Threat: Unnecessary open ports detected.")
            else:
                print("  Open Ports: None detected. Device appears secure.")
        else:
            print("  Open Ports: Not scanned.")
    print("=" * 50)
    print("Threat Assessment Complete!")

# Main function
def main():
    print("Network Threat Assessment Tool")
    print("=" * 40)
    
    # Get network CIDR from user
    network = input("Enter the network (e.g., 192.168.1.0/24): ")
    try:
        # Validate network format
        ipaddress.ip_network(network)
        devices = discover_devices(network)

        if not devices:
            print("No devices found on the network.")
            return

        # Scan each device for open ports
        port_range = range(1, 1025)  # Common port range
        for device in devices:
            print(f"Scanning {device['ip']} for open ports...")
            device['open_ports'] = check_open_ports(device['ip'], port_range)

        # Generate and display the report
        generate_report(devices)

    except ValueError:
        print("Invalid network format. Please enter a valid CIDR (e.g., 192.168.1.0/24).")
    except PermissionError:
        print("Permission denied. Run the script with elevated privileges (e.g., sudo).")
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")

if __name__ == "__main__":
    main()

