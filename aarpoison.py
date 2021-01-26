from os import popen
from colors import Msg

# Designed to monitor for arp poisoning attacks
arp_table = ""
ips, macs = [], []

def reset():
    global arp_table
    arp_table = {
        "ip": [],
        "mac": []
    }
reset()

# def load_arp_table():
#     global ips, macs
#     reset()
#     for (mac,ip) in zip(ips, macs):
#         arp_table["ip"].append(ip)
#         arp_table["mac"].append(mac)
#     ips.clear()
#     macs.clear()

def parse_arp_table(line, index):
    l = line.split(" ")
    try:
        ips.append(l[1].lstrip("(").rstrip(")"))
        macs.append(l[3])
    except Exception:
        print(Msg.ferror("Failed to parse row: "+line))
    # Compare arp table to current arp table
    try:
        if arp_table["ip"][index] != l[1].lstrip("(").rstrip(")"):
            print(Msg.ferror("POSSIBLE ARP POISON: "+arp_table["ip"][index]+" DOES NOT MATCH "+l[1].lstrip("(").rstrip(")")))
            # Update arp_table
            arp_table["ip"][index] = l[1].lstrip("(").rstrip(")")
        if arp_table["mac"][index] != l[3]:
            print(Msg.ferror("POSSIBLE ARP POISON: "+arp_table["mac"][index]+" DOES NOT MATCH "+l[3]))
            # Update arp_table
            arp_table["mac"][index] = l[3]
    except IndexError:
        try:
            print(Msg.fnote("New Device Found")+" Adding device to checklist...")
            print(Msg.fcyan("\tIP") + l[1].lstrip("(").rstrip(")"))
            print(Msg.fwarn("\tMAC") + l[3])
            arp_table["ip"].append(l[1].lstrip("(").rstrip(")"))
            arp_table['mac'].append(l[3])
        except Exception:
            print(Msg.ferror("Failed to add device to checklist: ")+line)
    except:
        print(Msg.ferror("Failed to evaluate row: "+line+" to -> "+arp_table["ip"][index]))

print("This script will keep running until Ctrl + C is executed...")

while True:
    arp_table_lines = popen('arp -a')
    for (index,line) in enumerate(arp_table_lines):
        parse_arp_table(line, index)