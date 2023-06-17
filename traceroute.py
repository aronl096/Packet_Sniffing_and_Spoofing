from scapy.all import *
from scapy.layers.inet import IP, ICMP

PACKET_TYPE = "echo-request"
TTL_EXCEED = 12
PACKET_VERBOSE = 0


def get_ip_from_packet(packet):
    
    # Extracts the source IP address from a packet.
    
    return packet[IP].src


def reach_host(response_packet):
    
    # Checks if the response packet indicates reaching the destination host.
    
    return response_packet[ICMP].type != TTL_EXCEED


def seconds_to_ms(seconds):
    
    # transform (convert) seconds to milliseconds.
    
    return seconds / 60 * 1000


def hop(address, ttl, timeout):
    
    # Sends an ICMP packet with the specified TTL to the destination address and waits for a response.
    
    my_packet = IP(dst = address, ttl = ttl) / ICMP(type = PACKET_TYPE)
    # sr1() function in Scapy is used to send a single packet and receive a response.
    return sr1(my_packet, timeout = timeout, verbose = PACKET_VERBOSE)


def print_status_message(success, ttl, response_time=None, ip=None):
    
    # Prints the status message for a particular hop, indicating if it was successful or timed out.
   
    if success:
        response_ms_time = seconds_to_ms(response_time)
        message = f"{ttl})  {response_ms_time} ms {ip}"
    else:
        message = f"{ttl}) Request Time Out."

    print(message)


def trace_R(host, max_hops = 30, timeout = 5, verbose = True):
    
    # Performs a traceroute by incrementing the TTL and collecting the intermediate IP addresses.
    
    ttl = 1
    pos = []

    while ttl <= max_hops:
        start_time = time.time()
        response_packet = hop(host, ttl, timeout)
        final_time = time.time() - start_time

        if response_packet:
            ip = get_ip_from_packet(response_packet)
            pos.append(ip)

            if verbose:
                print_status_message(True, ttl, final_time, ip)
            if reach_host(response_packet):
                break
        else:
            pos.append(None)

            if verbose:
                print_status_message(False, ttl)
        ttl += 1

    return pos


    
    # Main function for having traceroute to a given destination IP address.
    
dst_ip = input("Enter the destination IP address: ")
result = trace_R(dst_ip)
print("Intermediate IP addresses:")
for hop_num, ip_addr in enumerate(result, start=1):
 if ip_addr:
   print(f"Hop {hop_num}: {ip_addr}")
 else:
  print(f"Hop {hop_num}: Request Time Out.")

