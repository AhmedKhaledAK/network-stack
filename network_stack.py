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


class IpPacket(object):
    """
    Represents the *required* data to be extracted from an IP packet.
    """

    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload

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

def generate_arp_response(arp_request: ArpPacket):
    hwtype = arp_request.hwtype
    protype = arp_request.protype
    hwsize = arp_request.hwsize
    prosize = arp_request.prosize

    opcode = int(2).to_bytes(2, 'big')
    smac_str = getmacddr()
    print("SMAC:",smac_str)
    smac = binascii.unhexlify(smac_str.replace(':', '')) 
    print("SMMMAAAACCC:",binascii.hexlify(smac))
    sip = arp_request.dip
    dip = arp_request.sip
    dmac = arp_request.smac

    return hwtype + protype + hwsize.to_bytes(1, 'big') + prosize.to_bytes(1, 'big') + opcode + smac + sip + dmac+dip

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
    if ethpacket.ethtype == bytearray.fromhex("0806"):
        arp_request = parse_arp_packet(ethpacket.payload)
        arp_response_bytes = generate_arp_response(arp_request)
    print(binascii.hexlify(raw_packet))