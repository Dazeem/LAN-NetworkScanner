from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
import socket


def scan_network(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    print(f"Scanning network: {ip_range}...\n")
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        try:
            hostname = socket.gethostbyaddr(received.psrc)[0]
        except socket.herror:
            hostname = "Unknown"

        devices.append({
            "IP": received.psrc,
            "MAC": received.hwsrc,
            "Hostname": hostname
        })

    return devices


def display_devices(devices):
    print("Available devices in the network:")
    print("IP" + " " * 17 + "MAC Address" + " " * 7 + "Hostname")
    print("-" * 60)
    for device in devices:
        print(f"{device['IP']:20} {device['MAC']:20} {device['Hostname']}")


if __name__ == "__main__":
    target_range = "192.168.1.0/24"
    scanned_devices = scan_network(target_range)
    display_devices(scanned_devices)
