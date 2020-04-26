import os
from fcntl import ioctl
import struct
import subprocess
import shlex
import binascii

class EthPacket(object):
    def __init__(self, dmac, smac, ethtype, payload):
        self.dmac = dmac
        self.smac = smac
        self.ethtype = ethtype
        self.payload = payload


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

def parse_link_layer_packet(eth_packet: bytes) -> EthPacket:

    dmac = eth_packet[:6]
    print("dmac:",binascii.hexlify(dmac));
    dmac_str = parse_raw_mac_addr(dmac)
    print("dmac_str:", dmac_str)

    smac = eth_packet[6:12]
    print("smac:", binascii.hexlify(smac))
    smac_str = parse_raw_mac_addr(smac)
    print("smac_str:", smac_str)

    ethtype = eth_packet[12:14]
    print("ethtype:", binascii.hexlify(ethtype))

    return EthPacket(None, None, None, None)

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
    print(binascii.hexlify(raw_packet))