from subprocess import check_output
from colors import Msg
from sys import argv
from sys import exit as sysexit
from time import sleep
from signal import signal, SIGINT
frozen_ips = []

def handler(signal_received, frame):
    # Handle any cleanup here
    print('Ctrl + C detected, unfreezing targeted ips...')
    try:
        for ip in frozen_ips:
            print(Msg.fnote("UNFREEZING CONNECTION")+ " Attempting to create a dynamic entry for "+ip+" in ARP table...")
            if if_dynamic(ip):
                print(Msg.ferror("ERROR")+" Cannot set entry to dynamic because it already is static.")
                sysexit(1)
            print(Msg.fnote("DELETE STATIC")+" Attempting to delete the old static entry...")
            print(popen("sudo arp -d "+ip))
            print(Msg.fnote("DYNAMIC ADD")+" Attempting to add dynamic entry:")
            print(popen("ping "+ip+" -c 5"))
            if if_dynamic(ip):
                print(Msg.fsucc("SUCCESS")+" Router entry in ARP table is dynamic (unfrozen)!")
            else:
                print(Msg.ferror("ERROR")+" Router entry failed to update to dynamic in ARP table")
    except Exception as e:
        print(e)
        sysexit(0)
    sysexit(0)
signal(SIGINT, handler)

def popen(command):
    process = check_output(command.split(" "))
    try:
        process = process.decode('utf-8').split("\n")
    except Exception as e:
        print(Msg.ferror("POPEN ERROR")+":")
        print(e)
    return process

def if_permanent(router):
    arp_table_lines = popen("arp -a")
    for line in arp_table_lines:
        l = line.split(" ")
        if l[1].lstrip("(").rstrip(")") == router:
            if l[6] == "permanent":
                return True
            return False
    return False

def if_dynamic(router):
    arp_table_lines = popen("arp -a")
    for line in arp_table_lines:
        l = line.split(" ")
        if l[1].lstrip("(").rstrip(")") == router:
            if l[6] == "ifscope":
                return True
            return False
    return False

try:
    if argv[1] == "--defend":
        DEFEND = True
    elif argv[1] == "--help":
        print("""
            Anti-ARP Poisoning Software -- Version 1.0.0
            Options:
                [ --help ] displays the current message
                [ --defend ] enables defensive mode, which enables aarpoison, in the event of a discovered ARP Poisoning attack, to try and counter the attack
                [ --frz-conn $router_ip ] sets arp table entry for the router (or any ip) to static (NOTE: if the router doesn't have this device as a static entry in its ARP table, then someone can still ARP poison the router! This only prevents ARP poisoning of your device!)
                [ --unfrz-conn $router_ip ] sets arp table entry for the router (or any ip) to dynamic
        """)
        sysexit(1)
    elif argv[1] == "--frz-conn":
        try:
            print(Msg.fnote("FREEZING CONNECTION")+ " Attempting to create a static entry for "+argv[2]+" in ARP table...")
            router = argv[2]
            arp_table_lines = popen("arp -a")
            for line in arp_table_lines:
                l = line.split(" ")
                if l[1].lstrip("(").rstrip(")") == router:
                    print(Msg.fnote("FOUND ROUTER")+" The following commands may require a password (they need to be run as sudo)...")
                    if if_permanent(router):
                        print(Msg.ferror("ERROR")+" Cannot set entry to static because it already is static.")
                        sysexit(1)
                    print(Msg.fnote("STATIC ADD")+" Attempting to add static entry:")
                    print(popen("sudo arp -s "+l[1].lstrip("(").rstrip(")")+" "+l[3]))
                    print(Msg.fnote("DELETE DYNAMIC")+" Attempting to delete the old dynamic entry...")
                    print(popen("sudo arp -d "+l[1].lstrip("(").rstrip(")")))
                    if if_permanent(router):
                        print(Msg.fsucc("SUCCESS")+" Router entry in ARP table is static (frozen)!")
                    else:
                        print(Msg.ferror("ERROR")+" Router entry failed to update to static in ARP table")
                    break
        except Exception as e:
            try: 
                router = argv[2]
                print(e)
            except Exception as error:
                print(Msg.ferror("FAILED")+" Must provide the router ip after specifying --freeze-connection")
                print(error)
            sysexit(1)
        sysexit(1)
    elif argv[1] == "--unfrz-conn":
        try:
            print(Msg.fnote("UNFREEZING CONNECTION")+ " Attempting to create a dynamic entry for "+argv[2]+" in ARP table...")
            router = argv[2]
            arp_table_lines = popen("arp -a")
            for line in arp_table_lines:
                l = line.split(" ")
                if l[1].lstrip("(").rstrip(")") == router:
                    print(Msg.fnote("FOUND ROUTER")+" The following commands may require a password (they need to be run as sudo)...")
                    if if_dynamic(router):
                        print(Msg.ferror("ERROR")+" Cannot set entry to dynamic because it already is static.")
                        sysexit(1)
                    print(Msg.fnote("DELETE STATIC")+" Attempting to delete the old static entry...")
                    print(popen("sudo arp -d "+l[1].lstrip("(").rstrip(")")))
                    print(Msg.fnote("DYNAMIC ADD")+" Attempting to add dynamic entry:")
                    print(popen("ping "+l[1].lstrip("(").rstrip(")")+" -c 5"))
                    if if_dynamic(router):
                        print(Msg.fsucc("SUCCESS")+" Router entry in ARP table is dynamic (unfrozen)!")
                    else:
                        print(Msg.ferror("ERROR")+" Router entry failed to update to dynamic in ARP table")
                    break
        except Exception as e:
            try: 
                router = argv[2]
                print(e)
            except Exception as error:
                print(Msg.ferror("FAILED")+" Must provide the router ip after specifying --unfreeze-connection")
                print(error)
            sysexit(1)
        sysexit(1)
    else:
        print(Msg.ferror("INVALID PARAM")+ " Parameter  '"+argv[1]+"' unrecognized.")
        sysexit(1)
except Exception:
    DEFEND = False

# Designed to monitor for arp poisoning attacks
arp_table = ""

def reset():
    global arp_table
    arp_table = {
        "ip": [],
        "mac": []
    }
reset()

def find_duplicate(mac_addr):
    global arp_table
    ip_found_at = []
    for (ip,mac) in zip(arp_table["ip"],arp_table["mac"]):
        if mac == mac_addr:
            ip_found_at.append(ip)
    return ip_found_at

def getmac(ip):
    global arp_table
    for (mac,_ip) in zip(arp_table['mac'], arp_table['ip']):
        if _ip == ip:
            return mac
    return False

def updatemac(ip, mac):
    global arp_table
    for (index,_ip) in enumerate(arp_table['ip']):
        if _ip == ip:
            arp_table['mac'][index] = mac
            return True
    return False

def parse_arp_table(line):
    global arp_table
    l = line.split(" ")
    if not l or l[0] is None or l[0] == "":
        return
    try:
        ip = l[1].lstrip("(").rstrip(")")
        mac = getmac(ip)
        if mac != False:
            if mac != l[3] and ip not in frozen_ips:
                print(Msg.ferror("POSSIBLE ARP POISON: "+mac+" DOES NOT MATCH "+l[3]))
                # Try to find attacker:
                pot_attacker_ip = find_duplicate(l[3])
                attacker_ip = "[Failed to find Attacker IP]"
                for aip in pot_attacker_ip:
                    if aip != ip:
                        attacker_ip = aip
                        break
                print("\t"+Msg.fwarn("POTENTIAL ATTACKER: ")+ "Potential attacker ip: "+attacker_ip)
                print("\t"+Msg.fcyan("SWITCHED")+ ip + " switched to mac "+l[3]+" by IP "+attacker_ip)
                if DEFEND:
                    if ip not in frozen_ips:
                        # Try and reset the MAC to the correct one
                        print("\t"+Msg.fnote("RESETTING")+ " Resetting ARP Poising device to correct mac address...")
                        print("\t"+Msg.fnote("DUMPING RESPONSE:"))
                        print(popen("sudo arp -s "+ip+" "+mac))
                        print(popen("sudo arp -d "+ip))
                        print("\t"+Msg.fcyan("SWITCHED (DEFEND)")+ ip + " switched back to mac "+mac+" by SELF")
                        print("\t"+Msg.fwarn("FROZE ATTACKED IP ENTRY")+" To prevent further attacks, "+ip+" entry has been frozen (set to permanent) to mac address "+mac)
                        frozen_ips.append(ip)
                        # Do not update arp_table because it was reset back
                else:
                    # Update arp_table
                    status = updatemac(ip, l[3])
                    if status == False:
                        print(Msg.ferror("UPDATE FAILED")+" Failed to update mac address to "+l[3]+" from "+mac+" for ip "+ip)
        else:
            try:
                print(Msg.fnote("New Device Found")+" Adding device to checklist...")
                print("\t"+Msg.fcyan("IP") + l[1].lstrip("(").rstrip(")"))
                print("\t"+Msg.fwarn("MAC") + l[3])
                arp_table["ip"].append(l[1].lstrip("(").rstrip(")"))
                arp_table['mac'].append(l[3])
            except Exception as e:
                print(Msg.ferror("Failed to add device to checklist: ")+line)
                print(e)
    except Exception as e:
        print(Msg.ferror("Failed to evaluate row: "+line))
        print(e)

print("This script will keep running until Ctrl + C is executed...")

while True:
    arp_table_lines = popen('arp -a')
    for line in arp_table_lines:
        parse_arp_table(line)
