import ifaddr
from kamene.all import ARP, Ether, srp

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

def get_mac(target_ip) -> str:
    '''
    Get the MAC address of the target
    '''
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip), timeout=2, retry=10)
    
    for s,r in responses:
        return r[Ether].src
    return None