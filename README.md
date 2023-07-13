# ARP spoofing

# How to start   
• clone repository: 
  ```
  git clone https://github.com/EvtDanya/ARP-Spoofing
  ``` 
• go to install folder and install requirements:  
  ```
  chmod +x install.sh
  sudo ./install.sh
  ``` 
# Abilities
To see what this tool can, run the following command:
  ```
  python3 ./arp-spoofing.py -h
  ```
![screen of result](https://github.com/EvtDanya/ARP-Spoofing/blob/main/github/print_help.png)  

# About  
You need to specify the ip address of the victim, the gateway and also specify the network interface to sniff on. After all intercepted packets will be saved in "dumps/" directory and victim's ARP table will be restored. By default, 100 packets are intercepted  

## Feedback  
If you have any questions or suggestions, please dm me https://t.me/d3f3nd3r