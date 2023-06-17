import struct
import socket
import binascii
import datetime


def main():
    con = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    k = 5
    with open("319311940_336389515.txt", "w") as file:
     while k > 0:
        k -= 1
        raw_data, address = con.recvfrom(65536)
        if len(raw_data) < 28:
            continue  # Skip processing if the data is not sufficient

        packet, data = p_frame(raw_data)
        packet["timestamp"] = p_time(packet)
        print("\n p_Frame:")
        # לפני ההגשה נמחק את החלק של הפרוטוקול כי אין צורך בו על פי הדרישות
        packet_info = "protocol: {}, Source: {}, Destination: {}, source_port: {}, dest_port: {}, timestamp: {}, total_length: {}, cache_flag: {}, steps_flag: {}, type_flag: {}, status_code: {}, cache_control: {}\n".format(
                packet["protocol"],
                packet["source_ip"],
                packet["dest_ip"],
                packet["source_port"],
                packet["dest_port"],
                packet["timestamp"],
                packet["total_length"],
                packet["cache_flag"],
                packet["steps_flag"],
                packet["type_flag"],
                packet["status_code"],
                packet["cache_control"],
            )
        
            # Print packet details
        print(packet_info)

            # Write packet details to file
        file.write(packet_info)


# Unpacking packet frame
def p_frame(data):
    # Ethernet Header: 14 bytes
    eth_header = struct.unpack("!6s6sH", data[:14])
    eth_protocol = socket.ntohs(eth_header[2])

    if eth_protocol == 8:  # IP packets
        ip_header = struct.unpack("!BBHHHBBH4s4s", data[14:34])
        protocol = ip_header[6]

        if protocol == 6:  # TCP
            tcp_header = struct.unpack("!HHLLBBHHH", data[34:54])
            src_port = tcp_header[0]
            dest_port = tcp_header[1]
        elif protocol == 17:  # UDP
            udp_header = struct.unpack("!HHHH", data[34:42])
            src_port = udp_header[0]
            dest_port = udp_header[1]
        elif protocol == 1:  # ICMP
            src_port = 0
            dest_port = 0
        elif protocol == 2:  # IGMP
            src_port = 0
            dest_port = 0
        else:  # Other IP packets
            src_port = 0
            dest_port = 0
    else:  # Other packets (non-IP)
        src_port = 0
        dest_port = 0

    # Define the format string for unpacking
    format_string = "! 4s 4s H H I H H H H H 16s"

    # Unpack the data using the format string if it has enough bytes
    if len(data) >= 42:
        (
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            timestamp,
            total_length,
            cache_flag,
            steps_flag,
            type_flag,
            status_code,
            cache_control,
        ) = struct.unpack(format_string, data[:42])

        # Convert the IP addresses to human-readable format
        src_ip = socket.inet_ntoa(ip_header[8])
        dst_ip = socket.inet_ntoa(ip_header[9])

        # Convert cache_control to a readable format
        cache_control_readable = binascii.hexlify(data[42:58]).decode("utf-8")

        # Return the unpacked values as a dictionary
        packet = {
            "protocol": get_protocol_name(protocol),
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "source_port": src_port,
            "dest_port": dst_port,
            # The timestamp typically represents the date and time when the packet was received or captured.
            "timestamp": timestamp,
            "total_length": len(data),
            "cache_flag": cache_flag,
            "steps_flag": steps_flag,
            "type_flag": type_flag,
            "status_code": status_code,
            "cache_control": cache_control_readable,
        }
        return packet, data[58:]
    else:
        # For non-IP packets, return None
        return None, None


def p_time(packet):
    # Convert the timestamp to a datetime object
    timestamp = datetime.datetime.fromtimestamp(packet["timestamp"])
    # Check if the timestamp is before the year 2023
    if timestamp.year < 2023:
        # Update the year to 2023
        timestamp = timestamp.replace(year=2023)
    if timestamp.month < 6:
        # Update the month to 6
        timestamp = timestamp.replace(month=6)

    # Format the timestamp into a readable string
    timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")

    return (
        timestamp_str  # return to update the timestamp field with the formatted string
    )


def get_protocol_name(protocol_num):
    # Mapping protocol number to protocol name
    protocol_map = {
        1: "ICMP",
        2: "IGMP",
        6: "TCP",
        17: "UDP",
    }
    return protocol_map.get(protocol_num, "RAW")


if __name__ == "__main__":
    main()
