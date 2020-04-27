import os
from fcntl import ioctl
import struct
import subprocess
import shlex
import binascii
import netifaces

class EthPacket(object):
    def __init__(self, dmac, smac, ethtype, payload):
        self.dmac = dmac
        self.smac = smac
        self.ethtype = ethtype
        self.payload = payload

class ArpPacket(object):
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

    def arp_to_bytes(self):
        return self.hwtype + self.protype + self.hwsize.to_bytes(1, 'big') + self.prosize.to_bytes(1, 'big') + self.opcode + self.smac + self.sip + self.dmac + self.dip

class IpPacket(object):
    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload

class UdpPacket(object):
    def __init__(self, sport, dport, length, checksum, data):
        self.sport = sport
        self.dport = sport
        self.length = length
        self.checksum = checksum
        self.data = data

class IcmpPacket(object):
    def __init__(self, icmp_type, code, checksum, identifier, seqnum):
        self.icmp_type = icmp_type
        self.code = code
        self.checksum = checksum
        self.identifier = identifier
        self.seqnum = seqnum

def parse_raw_mac_addr(raw_mac_addr: bytes) -> str:
    mac = ""
    i = 0
    while i < len(raw_mac_addr):
        if i == len(raw_mac_addr) - 1:
            mac += str(raw_mac_addr[i] & 0xFF)
        else:
            mac += str(raw_mac_addr[i] & 0xFF) + ":"
        i += 1
    return mac

def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:
    addr = ""
    i = 0
    while i < len(raw_ip_addr):
        if i == len(raw_ip_addr) - 1:
            addr+= str(raw_ip_addr[i] & 0xFF)
        else:
            addr+= str(raw_ip_addr[i] & 0xFF) + "."
        i+=1

    return addr

def getdata(offset, packet):
    start = int(offset*32/8)
    return packet[start:]

def getmacddr():
    return netifaces.ifaddresses('tap0')[netifaces.AF_LINK][0].get('addr')

def parse_link_layer_packet(eth_packet: bytes) -> EthPacket:

    dmac = eth_packet[:6]
    print("dmac:",binascii.hexlify(dmac))
    dmac_str = parse_raw_mac_addr(dmac)
    print("dmac_str:", dmac_str)

    smac = eth_packet[6:12]
    print("smac:", binascii.hexlify(smac))
    smac_str = parse_raw_mac_addr(smac)
    print("smac_str:", smac_str)

    ethtype = eth_packet[12:14]
    print("ethtype:", binascii.hexlify(ethtype))

    payload = eth_packet[14:]
    print("payload: ", binascii.hexlify(payload))

    return EthPacket(dmac, smac, ethtype, payload)

def generate_ethernet_packet(eth_packet: EthPacket):
    """
    returns bytes WITHOUT payload
    """
    smac_str = getmacddr()
    smac = binascii.unhexlify(smac_str.replace(':', '')) 
    dmac = ethpacket.smac
    ethtype = bytearray.fromhex("0806")

    return dmac + smac + ethtype

def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:
    print("IP IP")
    ihl = ip_packet[0] & 0x0F
    protocol = ip_packet[9]
    print("protocol:",protocol)
    srcaddr = parse_raw_ip_addr(ip_packet[12:16])
    destaddr  = parse_raw_ip_addr(ip_packet[16:20])

    data = getdata(ihl, ip_packet)

    return IpPacket(protocol, ihl, srcaddr, destaddr, data)

def parse_arp_packet(arp_packet: bytes) -> ArpPacket:
    print("ARP")
    hwtype = arp_packet[:2]
    print("hwtype:", hwtype)

    protype = arp_packet[2:4]
    print("protype:", protype)

    hwsize = arp_packet[4]
    print("hwsize:", hwsize)

    prosize = arp_packet[5]
    print("prosize:", prosize)

    opcode = arp_packet[6:8]
    print("opcode:", opcode)

    smac = arp_packet[8:14]
    print("smac:", binascii.hexlify(smac))

    sip = arp_packet[14:18]
    print("sip:", binascii.hexlify(sip))

    dmac = arp_packet[18:24]
    print("dmac:", binascii.hexlify(dmac))

    dip = arp_packet[24:28]
    print("dip:", binascii.hexlify(dip))

    return ArpPacket(hwtype, protype, hwsize, prosize, opcode, smac, sip, dmac, dip)

def generate_arp_response(arp_request: ArpPacket) -> ArpPacket:
    hwtype = arp_request.hwtype
    protype = arp_request.protype
    hwsize = arp_request.hwsize
    prosize = arp_request.prosize

    opcode = int(2).to_bytes(2, 'big')
    smac_str = getmacddr()
    smac = binascii.unhexlify(smac_str.replace(':', '')) 
    sip = arp_request.dip

    dmac = arp_request.smac
    dip = arp_request.sip


    print(binascii.hexlify(hwtype))
    print(binascii.hexlify(protype))
    print(hwsize)
    print(prosize)
    print(binascii.hexlify(opcode))
    print("smac" ,smac)
    print(binascii.hexlify(sip))
    print(binascii.hexlify(dmac))
    print(binascii.hexlify(dip))

    return ArpPacket(hwtype, protype, hwsize, prosize, opcode, smac, sip, dmac, dip)

def parse_udp_packet(udp_packet: bytes) -> UdpPacket:
    print("UDP")
    sport = udp_packet[:2]
    dport = udp_packet[2:4]
    length = udp_packet[4:6]
    checksum = udp_packet[6:8]
    data = udp_packet[8:]


    return UdpPacket(sport, dport, length, checksum, data)

def parse_icmp_packet(icmp_packet: bytes) -> IcmpPacket:
    icmp_type = icmp_packet[0]
    code = icmp_packet[1]
    checksum = icmp_packet[2:4]
    identifier = icmp_packet[4:6]
    seqnum = icmp_packet[6:8]

    return IcmpPacket(icmp_type, code, checksum, identifier, seqnum)


subprocess.call(shlex.split("ip link delete tap0"))
subprocess.call(shlex.split("ip tuntap add mode tap tap0"))
subprocess.call(shlex.split("ip addr add 10.0.0.1/24 dev tap0"))
subprocess.call(shlex.split("ip link set tap0 up"))

TUNSETIFF = 0x400454ca
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

ftun = os.open("/dev/net/tun", os.O_RDWR)
ioctl(ftun, TUNSETIFF, struct.pack("16sH", b"tap0", IFF_TAP | IFF_NO_PI))

while True:
    raw_packet = os.read(ftun, 65535) # we get ftun descriptor by opening /dev/net/tun
    ethpacket = parse_link_layer_packet(raw_packet)
    eth_response_bytes = generate_ethernet_packet(ethpacket)
    if ethpacket.ethtype == bytearray.fromhex("0806"):
        arp_request = parse_arp_packet(ethpacket.payload)
        arp_response = generate_arp_response(arp_request)
        os.write(ftun, eth_response_bytes + arp_response.arp_to_bytes())

    elif ethpacket.ethtype == bytearray.fromhex("0800"):
        ip_packet = parse_network_layer_packet(ethpacket.payload)
        if ip_packet.protocol == 17:
            udp_packet = parse_udp_packet(ip_packet.payload)
    print(binascii.hexlify(raw_packet))