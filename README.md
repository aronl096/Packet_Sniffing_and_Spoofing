# Packet_Sniffing_and_Spoofing

## Sniffer.py : 
I wrote a sniffer for capturing packets.  My sniffer should be able to sniff the following protocols:
-	TCP
-	UDP 
-	ICMP
-	IGMP
-	RAW (other - default)
   
Use your sniffer to sniff the TCP packets and write them out into a txt file named after your IDs. The format of each packet should be { source_ip: <input>, dest_ip: <input>, source_port: <input>, dest_port: <input>, timestamp: <input>, total_length: <input>, cache_flag: <input>, steps_flag: <input>, type_flag: <input>, status_code: <input>, cache_control: <input>, data: <input> }
The data output may be unreadable in ASCII form so write the output as hexadecimal.

## Spoffer.py : 
I wrote a spoofer for spoofing packets. My spoofer should be able to spoof packets  by using the following protocols:
-	ICMP
-	UDP

The spoofer should fake the sender’s IP and has a valid response. Your code should be able to spoof other protocols with small changes.

## Traceroute.py :
The objective of this code is to use Scapy to estimate the distance, in terms of number of routers, between your VM and a selected destination. This is basically what is implemented by the traceroute tool. In this task, we will write our own tool. The idea is quite straightforward: just send an packet (any type) to the destination, with its Time-To-Live (TTL) field set to 1 first. This packet will be dropped by the first router, which will send us an ICMP error message, telling us that the time-to-live has exceeded. That is how we get the IP address of the first router. We then increase our TTL field to 2, send out another packet, and get the IP address of the second router. We will repeat this procedure until our packet finally reach the destination. It should be noted that this experiment only gets an estimated result, because in theory, not all these packets take the same route (but in practice, they may within a short period of time).

## Snoffer.py :
In this code, you will combine the sniffing and spoofing techniques to implement the following sniff-and-then-spoof program. I installed two machines on the same LAN. From machine A, you ping an IP X. This will generate an ICMP echo request packet. If X is alive, the ping program will receive an echo reply, and print out the response. Your sniff-and-then-spoof program runs on the attacker machine, which monitors the LAN through packet sniffing. Whenever it sees an ICMP echo request, regardless of what the target IP address is, your program should immediately send out an echo reply using the packet spoofing technique. 

