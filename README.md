# DHCPStarvation
Simple DHCP Starvation Attack With Scapy

This is a simple Python script designed to implementing DHCP Starvation attacks on the network. It is important to note this script is only useful for learning network socket programming with scapy in Python and for modeling and implementing it on a small network.

NOTE1: The script must be run with root access on Linux.

NOTE2: I think the scapy is not installed by default on your system and you need to install it using APT or PIP.

## Usage

```markdown

sudo python3 DHCPStarvation.py -i <interface> -c <packets count>
sudo python3 DHCPStarvation.py -i vboxnet0 -c 252
