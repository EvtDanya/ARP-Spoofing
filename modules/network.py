import ifaddr
from scapy.all import ARP, Ether, srp

def get_interfaces() -> list:
    '''
    Get list of interfaces
    '''
    available_interfaces = []
    interfaces = ifaddr.get_adapters()

    for adapter in interfaces:
        interface = {}
        interface['name'] = adapter.nice_name
        interface['ip'] = adapter.ips[1].ip
        available_interfaces.append(interface)

    return available_interfaces

def get_mac(target_ip):
    '''
    Get the MAC address of the target
    '''
    packet = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op='who-has', pdst=target_ip)
    resp, _= srp(packet, timeout=2, retry=10, verbose=False)
    for _, r in resp:
        return r[Ether].src
    return None