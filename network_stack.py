import os
from fcntl import ioctl
import struct
import subprocess
import shlex

subprocess.call(shlex.split("ip link delete tun0"))
subprocess.call(shlex.split("ip tuntap add mode tun tun0"))
subprocess.call(shlex.split("ip addr add 10.0.0.1/24 dev tun0"))
subprocess.call(shlex.split("ip link set tun0 up"))

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

ftun = os.open("/dev/net/tun", os.O_RDWR)
ioctl(ftun, TUNSETIFF, struct.pack("16sH", b"tun0", IFF_TUN | IFF_NO_PI))

while True:
    raw_packet = os.read(ftun, 1500) # we get ftun descriptor by opening /dev/net/tun
    print(raw_packet)