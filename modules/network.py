import ifaddr
from kamene.all import ARP, Ether, srp
import scapy.all as scapy

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
    responses, unanswered = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=target_ip), timeout=2, retry=10)
    try:    
        for s,r in responses:
            return r[Ether].src
    except:
        return r.src
    return None