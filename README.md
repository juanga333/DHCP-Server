# DHCP-Server

This is a DHCP rogue server developed for ethical purposes and pestesting.

## Starting

### Pre-requisites

```
sudo apt install python3
sudo apt install python3-pip
```

### Installation
```
git clone https://github.com/juanga333/DHCP-Server.git
cd DHCP-Server
pip3 install -r requirements.txt
```

### Usage
_This is the basic usage example_
```
sudo python3 dhcpserver.py -m <netmask>
```

_In order to specify dns and gateway ip_
```
sudo python3 dhcpserver.py -m <netmask> -d <dns_ip> -g <gateway_ip>
```

_Also You can specify the list of ips for the victims_
```
sudo python3 dhcpserver.py -m <netmask> -d <dns_ip> -g <gateway_ip> -x 192.168.0.101-120
```

_You can speficy you want to do a starvation attack before listening_
```
sudo python3 dhcpserver.py -m <netmask> -d <dns_ip> -g <gateway_ip> -x 192.168.0.101-120 -s <delay seconds> -i <number of iteration>
```
