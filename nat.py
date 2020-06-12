import select, socket, sys, queue
import struct

ETH_P_ALL = 0x0003
ETH_LENGTH = 14
ETH0_NETWORK = '10.0.0.'
ETH1_NETWORK = '10.0.1.'
ETH0_IP_ADDR = ETH0_NETWORK + '11'
ETH1_IP_ADDR = ETH1_NETWORK + '10'


def bytes_to_mac(bytesmac):
    return ':'.join('{:02x}'.format(x) for x in bytesmac)


def checksum(msg):
    s = 0
    msg = (msg + b'\x00') if len(msg)%2 else msg
    for i in range(0, len(msg), 2):
        w = msg[i] + (msg[i+1] << 8)
        s = s + w
        s = (s & 0xffff) + (s >> 16)
    s = ~s & 0xffff
    return socket.ntohs(s)


def create_socket(interface_name):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    s.bind((interface_name, 0))
    mac_addr = s.getsockname()[-1]
    print(interface_name + ' MAC address:' + bytes_to_mac(mac_addr))

    return (s, mac_addr)


def is_dest_ip_private(packet):
    iph = struct.unpack('!BBHHHBBH4s4s', packet[ETH_LENGTH:20+ETH_LENGTH])
    return socket.inet_ntoa(iph[-1]).startswith(ETH0_NETWORK)

def pack_ip_header(packet, s_ip_addr, d_ip_addr):
    iph = struct.unpack('!BBHHHBBH4s4s', packet[ETH_LENGTH:20+ETH_LENGTH])
    # Header IP
    ip_ver = 4
    ip_ihl = 5
    ip_tos = iph[1]
    ip_tot_len = iph[2]
    ip_id = iph[3]
    ip_frag_off = iph[4]
    ip_ttl = iph[5]
    ip_proto = iph[6]
    ip_check = 0
    ip_saddr = socket.inet_aton(s_ip_addr) if s_ip_addr is not None else iph[-2]
    ip_daddr = socket.inet_aton(d_ip_addr) if d_ip_addr is not None else iph[-1]

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl,
        ip_proto, ip_check, ip_saddr, ip_daddr)

    ip_check = checksum(ip_header)

    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl,
        ip_proto, ip_check, ip_saddr, ip_daddr)

    return (ip_header, ip_proto, ip_saddr, ip_daddr)


def udp(packet, ip_saddr, ip_daddr):
    udph = struct.unpack('!HHHH', packet[20+ETH_LENGTH:28+ETH_LENGTH])
    data = packet[28+ETH_LENGTH:]
    udp_sport = udph[0]
    udp_dport = udph[1]
    udp_len = udph[2]
    udp_check = 0

    udp_header = struct.pack('!HHHH', udp_sport, udp_dport, udp_len, udp_check)

    udp_pseudo_header = struct.pack('!4s4sBBH', ip_saddr, ip_daddr, udp_check, socket.IPPROTO_UDP, udp_len)

    udp_check = checksum(udp_pseudo_header + udp_header + data)

    udp_header = struct.pack('!HHHH', udp_sport, udp_dport, udp_len, udp_check)

    return udp_header + data


def tcp(packet, ip_saddr, ip_daddr):
    tcph = struct.unpack('!HHLLBBHHH', packet[20+ETH_LENGTH:40+ETH_LENGTH])
    data = packet[40+ETH_LENGTH:]
    tcp_sport = tcph[0]
    tcp_dport = tcph[1]
    tcp_seq = tcph[2]
    tcp_ack = tcph[3]
    tcp_hl_r = tcph[4]
    tcp_flags = tcph[5]
    tcp_wsize = tcph[6]
    tcp_check = 0
    tcp_urgptr = tcph[8]

    tcp_header = struct.pack("!HHLLBBHHH", tcp_sport, tcp_dport, tcp_seq, tcp_ack, tcp_hl_r, tcp_flags,
        tcp_wsize, tcp_check, tcp_urgptr)

    tcp_pseudo_header = struct.pack("!4s4sBBH", ip_saddr, ip_daddr, tcp_check, socket.IPPROTO_TCP, len(tcp_header))

    tcp_check = checksum(tcp_pseudo_header + tcp_header + data)

    tcp_header = struct.pack("!HHLLBBHHH", tcp_sport, tcp_dport, tcp_seq, tcp_ack, tcp_hl_r, tcp_flags,
        tcp_wsize, tcp_check, tcp_urgptr)

    return tcp_header + data


def process_packet(packet, ip_proto, ip_saddr, ip_daddr):
    if ip_proto == socket.IPPROTO_TCP:
        return tcp(packet, ip_saddr, ip_daddr)
    elif ip_proto == socket.IPPROTO_UDP:
        return udp(packet, ip_saddr, ip_daddr)

    return packet[20+ETH_LENGTH:]


try:
    (s0, eth0_mac_addr) = create_socket('eth0')
    (s1, eth1_mac_addr) = create_socket('eth1')
except OSError as msg:
    print('Error' + str(msg))
    sys.exit(1)

print('Sockets created!')

inputs = [s0, s1]
outputs = []
message_queues = {}

while inputs:
    readable, writable, exceptional = select.select(inputs, outputs, inputs)
    for s in readable:
        (packet, addr) = s.recvfrom(65536)

        eth_header = packet[:ETH_LENGTH]

        eth = struct.unpack('!6s6sH', eth_header)
        protocol = eth[2]

        interface = 'eth0' if s is s0 else 'eth1'
        print('Received from ' + interface)
        print('MAC Dst: ' + bytes_to_mac(eth[0]))
        print('MAC Src: ' + bytes_to_mac(eth[1]))
        print('Type: ' + hex(protocol))
        print('{0}'.format(protocol))

        nexthdr = packet[ETH_LENGTH:]

        if protocol == 2048: # IP
            if s is s0:
                dest_mac = b'\x00\x00\x00\xaa\x00\x03'
                source_mac = eth1_mac_addr

                eth_hdr = struct.pack('!6s6sH', dest_mac, source_mac, protocol)
                (ip_header, ip_proto, ip_saddr, ip_daddr) = pack_ip_header(packet, ETH1_IP_ADDR, None)
                s1.send(eth_hdr + ip_header + process_packet(packet, ip_proto, ip_saddr, ip_daddr))
            elif s is s1 and not is_dest_ip_private(packet):
                dest_mac = b'\x00\x00\x00\xaa\x00\x00'
                source_mac = eth0_mac_addr

                eth_hdr = struct.pack('!6s6sH', dest_mac, source_mac, protocol)
                (ip_header, ip_proto, ip_saddr, ip_daddr) = pack_ip_header(packet, None, ETH0_NETWORK + '10')
                s0.send(eth_hdr + ip_header + process_packet(packet, ip_proto, ip_saddr, ip_daddr))
