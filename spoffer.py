from scapy.all import *
from scapy.layers.inet import ICMP
from scapy.layers.inet import UDP
from scapy.layers.inet import IP


# def send_raw_ip_packet(ip):
 #   send(ip, verbose = False)


def spoof_icmp_packet(src_ip, dst_ip):
    # Fill in the ICMP header
    icmp = ICMP()
    icmp.type = 8  # ICMP Type: 8 is request, 0 is reply.

    # Fill in the IP header
    ip = IP()
    ip.version = 4
    ip.ihl = 5
    ip.ttl = 20
    ip.src = src_ip
    ip.dst = dst_ip
    ip.proto = 1  # Protocol type for ICMP
    ip.len = len(ip) + len(icmp)  # IP Packet length (data + header)

    # Construct the packet
    packet = ip / icmp

    # Send the spoofed packet
    send(packet)


def spoof_udp_packet(src_ip, src_port, dst_ip, dst_port):
    # Fill in the UDP header
    udp = UDP()
    udp.sport = src_port
    udp.dport = dst_port

    # Fill in the IP header
    ip = IP()
    ip.version = 4
    ip.ihl = 5
    ip.ttl = 20
    ip.src = src_ip
    ip.dst = dst_ip
    ip.proto = 17  # Protocol type for UDP
    ip.len = len(ip) + len(udp)  # IP Packet length (data + header)

    # Construct the packet
    packet = ip / udp

    # Send the spoofed packet
    send(packet)


 # Spoof an ICMP packet
spoof_icmp_packet("172.17.0.1", "8.8.8.8")
 
# Spoof a UDP packet
spoof_udp_packet("192.168.1.10", 12345, "192.168.1.20", 80)

