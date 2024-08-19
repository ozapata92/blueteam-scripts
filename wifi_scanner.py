import scapy.all as scapy
import argparse
import time
import signal
import sys
from mac_vendor_lookup import MacLookup
from colorama import init, Fore, Style

# Inicializar colorama
init()

def signal_handler(sig, frame):
    print(Fore.RED + "\n[!] Stopping the network scanner." + Style.RESET_ALL)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def get_arguments():
    parser = argparse.ArgumentParser(description="Scan network continuously for connected devices.")
    parser.add_argument("-r", "--network", dest="network", help="IP range to scan. Example: 192.168.0.0/24")
    parser.add_argument("-t", "--interval", dest="interval", type=int, default=1, help="Time interval between scans (in seconds). Default is 1 seconds.")
    args = parser.parse_args()

    if not args.network:
        print(Fore.YELLOW + "[*] No network provided. Using default network: 192.168.0.0/24" + Style.RESET_ALL)
        args.network = "192.168.0.0/24"
    
    return args

def create_arp_packet(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    return broadcast / arp_request

def scan_network(ip):
    packet = create_arp_packet(ip)
    answered_list = scapy.srp(packet, timeout=1, verbose=False)[0]
    
    devices = []
    mac_lookup = MacLookup()

    for element in answered_list:
        mac_address = element[1].hwsrc
        try:
            vendor = mac_lookup.lookup(mac_address)
        except Exception:
            vendor = "Unknown"

        devices.append({
            "ip": element[1].psrc,
            "mac": mac_address,
            "vendor": vendor
        })
    
    return devices

def display_header(interval):
    current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    next_update = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() + interval))
    print(Fore.CYAN + "\n[*] Network scan results")
    print(f"[*] Last updated: {current_time}")
    print(f"[*] Next update: {next_update}" + Style.RESET_ALL)
    print("----------------------------------------------------------------")

def display_results(devices):
    display_header(args.interval)
    if devices:
        print(Fore.GREEN + "IP\t\t\tMAC Address\t\t\tVendor" + Style.RESET_ALL)
        print("----------------------------------------------------------------")
        for device in devices:
            print(f"{Fore.BLUE}{device['ip']}\t{Fore.YELLOW}{device['mac']}\t{Fore.MAGENTA}{device['vendor']}{Style.RESET_ALL}")
    else:
        print(Fore.RED + "No devices found on the network." + Style.RESET_ALL)

def main():
    global args
    args = get_arguments()
    print(Fore.GREEN + f"[*] Starting network scanner on {args.network} every {args.interval} seconds. Press Ctrl+C to stop." + Style.RESET_ALL)

    while True:
        devices_found = scan_network(args.network)
        display_results(devices_found)
        time.sleep(args.interval)

if __name__ == "__main__":
    main()
