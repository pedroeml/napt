import select, socket, sys, queue
import struct

ETH_P_ALL = 0x0003

def bytes_to_mac(bytesmac):
    return ':'.join('{:02x}'.format(x) for x in bytesmac)

# Create 2 sockets, one for each interface eth0 and eth1
try:
    s0 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    s0.bind(('eth0', 0))
    s1 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    s1.bind(('eth1', 0))
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
        (packet,addr) = s.recvfrom(65536)

        eth_length = 14
        eth_header = packet[:14]

        eth = struct.unpack('!6s6sH', eth_header)

        interface = 'eth0' if s is s0 else 'eth1'
        print('Received from ' + interface)
        print('MAC Dst: ' + bytes_to_mac(eth[0]))
        print('MAC Src: ' + bytes_to_mac(eth[1]))
        print('Type: ' + hex(eth[2]))
        print('{0}'.format(eth[2]))

        nexthdr = packet[14:]

        if s is s0 : # eth0 - 00:00:00:aa:00:01
            if eth[2] == 2048 : # IP
                # Header Ethernet
                # MAC Destino - 6 bytes
                dest_mac = b'\x00\x00\x00\xaa\x00\x03'
                # MAC Origem - 6 bytes
                source_mac = b'\x00\x00\x00\xaa\x00\x02'
                protocol = eth[2]

                eth_hdr = struct.pack('!6s6sH', dest_mac, source_mac, protocol)

                packet = eth_hdr+nexthdr
                s1.send(packet)
        else :
            if eth[2] == 2048 : # IP
                # Header Ethernet
                # MAC Destino - 6 bytes
                dest_mac = b'\x00\x00\x00\xaa\x00\x00'
                # MAC Origem - 6 bytes
                source_mac = b'\x00\x00\x00\xaa\x00\x01'
                protocol = eth[2]

                eth_hdr = struct.pack('!6s6sH', dest_mac, source_mac, protocol)

                packet = eth_hdr+nexthdr
                s0.send(packet)
