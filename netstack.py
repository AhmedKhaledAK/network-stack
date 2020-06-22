from fcntl import ioctl
import os
import struct
import subprocess
import shlex
import binascii
import netifaces
import enum



class EthPacket(object):
    """
    Represents the data present in an Ethernet packet
    """

    def __init__(self, dmac, smac, ethertype, payload):
        self.dmac = dmac
        self.smac = smac
        self.ethertype = ethertype
        self.payload = payload

    """
    Returns EthPacket object as a byte array
    """
    def to_bytes(self):
        return (self.dmac + self.smac + self.ethertype + self.payload)


class IpPacket(object):
    """
    Represents the required data to be extracted from an IP packet
    """

    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload


class ArpPacket(object):
    """
    Represents the data present in an ARP packet
    """

    def __init__(self, hwtype, protype, hwsize, prosize, opcode, smac, sip, dmac, dip):
        self.hwtype = hwtype
        self.protype = protype
        self.hwsize = hwsize
        self.prosize = prosize
        self.opcode = opcode
        self.smac = smac
        self.sip = sip
        self.dmac = dmac
        self.dip = dip
    
    """
    Returns ArpPacket object as a byte array
    """
    def to_bytes(self):
        return (self.hwtype + self.protype + self.hwsize.to_bytes(1, 'big') 
                + self.prosize.to_bytes(1, 'big') + self.opcode + self.smac 
                + self.sip + self.dmac + self.dip)


class UdpPacket(object):
    """
    Represents the data present in a UDP packet
    """

    def __init__(self, sport, dport, length, checksum, data):
        self.sport = sport
        self.dport = dport
        self.length = length
        self.checksum = checksum
        self.data = data
    
    """
    Returns UdpPacket object as a byte array
    """
    def to_bytes(self):
        return (self.sport + self.dport + self.length + self.checksum + self.data)


class IcmpPacket(object):
    """
    Represents the data present in an ICMP packet
    """

    def __init__(self, icmp_type, code, checksum, identifier, seqnum, data):
        self.icmp_type = icmp_type
        self.code = code
        self.checksum = checksum
        self.identifier = identifier
        self.seqnum = seqnum
        self.data = data
    
    """
    Returns IcmpPacket object as a byte array
    """
    def to_bytes(self):
        return (self.icmp_type + self.code + self.checksum + self.identifier + self.seqnum + self.data)


class EthernetPacketType(enum.Enum):
    """
    Represents the Ethernet packet type
    """
    ARP = 1
    IP = 2
    DEFAULT = 0

    """
    Returns packet type of an Ethernet packet
    """
    def get_ethertype(eth_packet: EthPacket):
        if eth_packet.ethertype == bytearray.fromhex("0806"):
            return EthernetPacketType.ARP
        if eth_packet.ethertype == bytearray.fromhex("0800"):
            return EthernetPacketType.IP

        return EthernetPacketType.DEFAULT


class IpPacketType(enum.Enum):
    """
    Represents the IP packet type
    """
    ICMP = 1
    UDP = 2
    DEFAULT = 0

    """
    Returns protocol of an IP packet
    """
    def get_protocol(ip_packet: IpPacket):
        if ip_packet.protocol == 17:
            return IpPacketType.UDP
        if ip_packet.protocol == 1:
            return IpPacketType.ICMP

        return IpPacketType.DEFAULT



def parse_icmp_packet(icmp_packet: bytes) -> IcmpPacket:
    """
    Parses raw bytes of an ICMP packet and returns IcmpPacket
    """
    icmp_type = icmp_packet[0]
    code = icmp_packet[1]
    checksum = icmp_packet[2:4]
    identifier = icmp_packet[4:6]
    seqnum = icmp_packet[6:8]
    data = icmp_packet[8:]

    return IcmpPacket(icmp_type, code, checksum, identifier, seqnum, data)


def generate_icmp_packet(icmp_request: IcmpPacket) -> IcmpPacket:
    """
    Generates and returns an IcmpPacket response
    """
    header = b''

    icmp_type = 0
    icmp_type = icmp_type.to_bytes(1, 'big')
    
    code = icmp_request.code.to_bytes(1, 'big')
    
    checksum = 0
    checksum = checksum.to_bytes(2, 'big')
    
    identifier = icmp_request.identifier
    seqnum = icmp_request.seqnum
    data = icmp_request.data

    header += icmp_type + code + checksum + identifier + seqnum + data
    checksum = calculate_checksum(header)
    checksum = checksum.to_bytes(2, 'big')

    return IcmpPacket(icmp_type, code, checksum, identifier, seqnum, data)


def parse_arp_packet(arp_packet: bytes) -> ArpPacket:
    """
    Parses raw bytes of an ARP packet and returns an ArpPacket
    """
    hwtype = arp_packet[:2]
    protype = arp_packet[2:4]
    hwsize = arp_packet[4]
    prosize = arp_packet[5]
    opcode = arp_packet[6:8]
    smac = arp_packet[8:14]
    sip = arp_packet[14:18]
    dmac = arp_packet[18:24]
    dip = arp_packet[24:28]
    
    return ArpPacket(hwtype, protype, hwsize, prosize, opcode, smac, sip, dmac, dip)
    

def generate_arp_response(arp_request: ArpPacket) -> ArpPacket:
    """
    Generates and returns an ArpPacket response
    """
    hwtype = arp_request.hwtype
    protype = arp_request.protype
    hwsize = arp_request.hwsize
    prosize = arp_request.prosize

    opcode = int(2).to_bytes(2, 'big')
    smac = get_mac_addr()
    sip = arp_request.dip

    dmac = arp_request.smac
    dip = arp_request.sip

    return ArpPacket(hwtype, protype, hwsize, prosize, opcode, smac, sip, dmac, dip)


def parse_ip_packet(ip_packet: bytes) -> IpPacket:
    """
    Parses raw bytes of an IPv4 packet and returns IpPacket
    """
    ihl = ip_packet[0] & (0x0F)
    protocol = ip_packet[9]
    source_address = ip_packet[12:16]
    destination_address = ip_packet[16:20]

    payload = ip_packet[int(ihl) * 4 :]
    # identif = ip_packet[4:6]

    return IpPacket(protocol, ihl, source_address, destination_address, payload)


def generate_ip_packet(ip_req: IpPacket, payload) -> bytes:
    """
    Generates and returns an IP packet in the form of raw bytes
    """
    header = b''
    
    # IP version 4
    version = 0x4

    # header length = 5 x 32 bit words
    ihl = 0x5
    f_byte = ((version << 4) | ihl).to_bytes(1, 'big')

    service_type = 0x1C
    service_type = service_type.to_bytes(1, 'big')

    # total length = header length + udp packet length (in bytes)
    total_length = 5*4 + len(payload)
    total_length = total_length.to_bytes(2, 'big')
    
    identification = 0
    identification = identification.to_bytes(2, 'big')

    flags = 0b010
    frag_offset = 0b0000000000000
    flags = ((flags << 13) | frag_offset).to_bytes(2, 'big')

    time_to_live = 64
    time_to_live = time_to_live.to_bytes(1, 'big')

    protocol = ip_req.protocol
    protocol = protocol.to_bytes(1, 'big')

    checksum = 0
    checksum = checksum.to_bytes(2, 'big')

    target_address = ip_req.source_address
    src_address = ip_req.destination_address
    
    header = (f_byte + service_type + total_length + identification 
                    + flags + time_to_live + protocol + checksum + src_address 
                    + target_address)

    checksum = calculate_checksum(header)
    checksum = checksum.to_bytes(2, 'big')

    ip_response = (f_byte + service_type + total_length + identification 
                    + flags + time_to_live + protocol + checksum + src_address 
                    + target_address + payload)

    return ip_response


def parse_udp_packet(udp_packet: bytes) -> UdpPacket:
    """
    Parses raw bytes of a UDP packet and returns UdpPacket
    """
    sport = udp_packet[:2]
    dport = udp_packet[2:4]
    length = udp_packet[4:6]
    checksum = udp_packet[6:8]
    data = udp_packet[8:]

    return UdpPacket(sport, dport, length, checksum, data)


def generate_udp_packet(udp_packet: UdpPacket) -> UdpPacket:
    """
    Generates and returns UdpPacket response
    """
    udp_response = b''
    dest_port = udp_packet.sport
    src_port = udp_packet.dport
    data = udp_packet.data
    checksum = 0
    checksum = checksum.to_bytes(2, 'big')
    length = (8 + len(data)).to_bytes(2, 'big')
    udp_response = src_port + dest_port + length + checksum + data

    return UdpPacket(src_port, dest_port, length, checksum, data)


def parse_ethernet_packet(ethernet_packet: bytes) -> EthPacket:
    """
    Parses raw bytes of an Ethernet packet and returns EthPacket
    """
    dmac = ethernet_packet[:6]
    smac = ethernet_packet[6:12]
    ethertype = ethernet_packet[12:14]
    payload = ethernet_packet[14:]

    return EthPacket(dmac, smac, ethertype, payload)


def generate_ethernet_packet(eth_packet: EthPacket, payload: bytes):
    """
    Generates and returns EthPacket response
    """
    smac = get_mac_addr() 
    dmac = eth_packet.smac
    ethertype = eth_packet.ethertype

    return EthPacket(dmac, smac, ethertype, payload)


def generate_response_packet(raw_packet: bytes):
    """
    Generates a response packet
    """
    eth_response = None

    eth_packet = parse_ethernet_packet(raw_packet)
    eth_packet_type = EthernetPacketType.get_ethertype(eth_packet)

    if eth_packet_type == EthernetPacketType.ARP:
        arp_request = parse_arp_packet(eth_packet.payload)
        arp_response = generate_arp_response(arp_request)
        eth_response = generate_ethernet_packet(eth_packet, arp_response.to_bytes())
    
    elif eth_packet_type == EthernetPacketType.IP:
        ip_packet = parse_ip_packet(eth_packet.payload)
        ip_packet_type = IpPacketType.get_protocol(ip_packet)

        if ip_packet_type == IpPacketType.UDP:
            udp_packet = parse_udp_packet(ip_packet.payload)
            udp_response = generate_udp_packet(udp_packet)
            ip_response = generate_ip_packet(ip_packet, udp_response.to_bytes())
            eth_response = generate_ethernet_packet(eth_packet, ip_response)

        elif ip_packet_type == IpPacketType.ICMP:
            icmp_request = parse_icmp_packet(ip_packet.payload)
            icmp_response = generate_icmp_packet(icmp_request)
            ip_response = generate_ip_packet(ip_packet, icmp_response.to_bytes())
            eth_response = generate_ethernet_packet(eth_packet, ip_response)
    
    return eth_response


def calculate_checksum(header: bytes):
    """
    Given a header, it calculates and returns the checksum
    """
    sum = 0

    # add every 16-bits to sum
    for i in range(0, len(header), 2):
        val = struct.unpack('!H', header[i:i+2])[0]
        sum += val

    # discard overflow if present
    checksum = sum & 0x0FFFF

    # if there is an overflow, add it to checksum value
    if sum & 0xF0000 != 0:
        overflow = (int((sum&0xF0000) / (4096*16)))
        checksum += overflow

    # get 1's complement
    checksum = checksum ^ 0xFFFF

    return checksum


def get_mac_addr():
    """
    Returns MAC address of device in the form of raw bytes
    """
    addr = netifaces.ifaddresses('tap0')[netifaces.AF_LINK][0].get('addr')
    macbytes = binascii.unhexlify(addr.replace(':', ''))

    return macbytes


def create_tap_device():
    """
    Creates a TAP device and returns its descriptor
    """
    # if device with the name tap0 already exists, delete it
    subprocess.call(shlex.split("ip link delete tap0"))
    
    # create tap device called tap0
    subprocess.call(shlex.split("ip tuntap add mode tap tap0"))
    
    # assign the IP 10.0.0.1 to tap0
    subprocess.call(shlex.split("ip addr add 10.0.0.1/24 dev tap0"))
    subprocess.call(shlex.split("ip link set tap0 up"))

    TUNSETIFF = 0x400454CA
    IFF_TAP   = 0x0002
    IFF_NO_PI = 0x1000

    # get ftap descriptor
    ftap = os.open("/dev/net/tun", os.O_RDWR)
    ioctl(ftap, TUNSETIFF, struct.pack("16sH", b"tap0", IFF_TAP | IFF_NO_PI))

    return ftap


def receive_packet(ftap):
    """
    Receives a packet and returns it
    """
    return os.read(ftap, 4096)


def main():
    ftap = create_tap_device()
    while True:
        raw_packet = receive_packet(ftap)
        eth_response = generate_response_packet(raw_packet)
        if eth_response == None:
            continue
        os.write(ftap, eth_response.to_bytes())


if __name__ == "__main__":
  main()