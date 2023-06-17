from scapy.all import *
from scapy.layers.inet import IP, ICMP, UDP

def packet_sniff_A_spoof(packet):
    try:
        if ICMP in packet and packet[ICMP].type  ==  8:  # ICMP echo request
            # Creating an ICMP echo reply packet
            src_ip  =  packet[IP].dst
            dst_ip  =  packet[IP].src
            spoofed_packet  =  IP(src = dst_ip, dst = src_ip) / ICMP(type = 0, id = packet[ICMP].id, seq = packet[ICMP].seq) / packet[Raw].load

            # Print the original and spoofed packet details
            print("Original ICMP Packet:")
            print("Source IP:", packet[IP].src)
            print("Destination IP:", packet[IP].dst)
            print("ICMP Type:", packet[ICMP].type)
            print("ICMP ID:", packet[ICMP].id)
            print("ICMP Seq:", packet[ICMP].seq)
            print("Raw Data:", packet[Raw].load)
            print("*****************")

            # Print the details of the spoofed packet
            print("Spoofed ICMP packet:")
            print("Changed Source IP from:", packet[IP].src, "to:", spoofed_packet[IP].src)
            print("Changed Destination IP from:", packet[IP].dst, "to:", spoofed_packet[IP].dst)
            print("ICMP Type:", spoofed_packet[ICMP].type)
            print("ICMP ID:", spoofed_packet[ICMP].id)
            print("ICMP Seq:", spoofed_packet[ICMP].seq)
            print("Raw Data:", spoofed_packet[Raw].load)
            print("***************************************************")

            # Send the spoofed packet
            send(spoofed_packet, verbose = 0)

            # Print a message indicating successful spoofing
            print("Spoofed ICMP packet sent")

        # Uncomment the following code if you want to handle UDP echo requests as well
        # if UDP in packet and packet[UDP].dport == 7:  # UDP echo request (port number can be adjusted as per your requirements)
        #     # Creating a UDP echo reply packet
        #     spoofed_packet  =  IP(src = packet[IP].dst, dst = packet[IP].src) / UDP(dport = packet[UDP].sport,
        #                                                                       sport = packet[UDP].dport) / packet[Raw].load
        #     # Send the spoofed packet
        #     send(spoofed_packet)

    except Exception as e:
        print(f"Error: {str(e)}")


def main():
    try:
        ip_address = input("Enter the IP address to sniff and spoof: ")
# Replace with the Attacker IP address mentioned in the Appendix B
        print("Sniffing and spoofing ICMP packets from IP address:(Attacker IP address) {ip_address}") 

        # Start sniffing packets and then spoof
        sniff(iface = "eth0", prn = packet_sniff_A_spoof, filter = "icmp", store = 0)

    except KeyboardInterrupt:
        print("\nSniffing and spoofing stopped by user.")


if __name__  ==  "__main__":
    main()
