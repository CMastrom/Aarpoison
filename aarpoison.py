from os import popen
from colors import Msg
from sys import argv
from sys import exit as sysexit

try:
    if argv[1] == "--defend":
        DEFEND = True
    elif argv[1] == "--help":
        print("""
            Anti-ARP Poisoning Software -- Version 1.0.0
            Options:
                [ --help ] displays the current message
                [ --defend ] enables defensive mode, which enables aarpoison, in the event of a discovered ARP Poisoning attack, to try and counter the attack
        """)
    else:
        print(Msg.ferror("INVALID PARAM")+ " Parameter  '"+argv[1]+"' unrecognized.")
        sysexit(1)

except Exception:
    DEFEND = False

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

def find_duplicate(mac_addr):
    global arp_table
    ip_found_at = []
    for (ip,mac) in zip(arp_table["ip"],arp_table["mac"]):
        if mac == mac_addr:
            ip_found_at.append(ip)
    return ip_found_at

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
            print("\t"+Msg.fwarn("POTENTIAL ATTACKER: ")+ "Potential attacker ip: "+l[1].lstrip("(").rstrip(")"))
            print("\t"+Msg.fcyan("SWITCHED")+ arp_table["ip"][index] + " switched to ip "+l[1].lstrip("(").rstrip(")")+" for MAC "+arp_table['mac'][index])
            # Update arp_table
            arp_table["ip"][index] = l[1].lstrip("(").rstrip(")")
        if arp_table["mac"][index] != l[3]:
            print(Msg.ferror("POSSIBLE ARP POISON: "+arp_table["mac"][index]+" DOES NOT MATCH "+l[3]))
            print("\t"+Msg.fwarn("POTENTIAL ATTACKER: ")+ "Potential attacker ip: "+l[1].lstrip("(").rstrip(")"))
            # Try to find attacker:
            pot_attacker_ip = find_duplicate(l[3])
            attacker_ip = "[Failed to find Attacker IP]"
            for aip in pot_attacker_ip:
                if aip != arp_table["ip"][index]:
                    attacker_ip = aip
                    break
            print("\t"+Msg.fcyan("SWITCHED")+ arp_table["ip"][index] + " switched to mac "+l[3]+" by IP "+attacker_ip)
            if DEFEND:
                # Try and reset the MAC to the correct one
                print("\t"+Msg.fnote("RESETTING")+ " Resetting ARP Poising device to correct mac address...")
                print("\t"+Msg.fnote("DUMPING RESPONSE:"))
                print(popen("arp -s "+arp_table["ip"][index]+" "+arp_table["mac"][index]+"; ping "+arp_table["ip"][index]))
                print("\t"+Msg.fcyan("SWITCHED (DEFEND)")+ arp_table["ip"][index] + " switched back to mac "+arp_table['mac'][index]+" by SELF")
                # Do not update arp_table because it was reset back
            else:
                #dc:ef:9:96:9b:68
                #bc:ec:23:ca:a6:b
                # Update arp_table
                arp_table["mac"][index] = l[3]
    except IndexError:
        try:
            print(Msg.fnote("New Device Found")+" Adding device to checklist...")
            print("\t"+Msg.fcyan("IP") + l[1].lstrip("(").rstrip(")"))
            print("\t"+Msg.fwarn("MAC") + l[3])
            arp_table["ip"].append(l[1].lstrip("(").rstrip(")"))
            arp_table['mac'].append(l[3])
        except Exception:
            print(Msg.ferror("Failed to add device to checklist: ")+line)
    except Exception as e:
        print(Msg.ferror("Failed to evaluate row: "+line+" to -> "+arp_table["ip"][index]))
        #raise e

print("This script will keep running until Ctrl + C is executed...")

while True:
    arp_table_lines = popen('arp -a')
    for (index,line) in enumerate(arp_table_lines):
        parse_arp_table(line, index)