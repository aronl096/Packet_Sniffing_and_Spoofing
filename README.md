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

