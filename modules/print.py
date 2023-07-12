from colorama import Fore, Style

def print_logo() -> None:
    print(Fore.GREEN +
          '    _    ____  ____                           __ _   \n'          
          '   / \  |  _ \|  _ \   ___ _ __   ___   ___  / _(_)_ __   __ _ \n'
          '  / _ \ | |_) | |_) | / __| \'_ \ / _ \ / _ \| |_| | \'_ \ / _` |\n'
          ' / ___ \|  _ <|  __/  \__ \ |_) | (_) | (_) |  _| | | | | (_| |\n'
          '/_/   \_\_| \_\_|     |___/ .__/ \___/ \___/|_| |_|_| |_|\__, |\n'
          '                          |_|                            |___/ \n'
          '\nDownload link: https://github.com/EvtDanya/ARP-Spoofing\n\n'
          + Style.RESET_ALL)

def print_color(text, color=None) -> None:
    '''
    Print color text
    '''
    if color:
        color_obj = getattr(Fore, color.upper(), None)
        if color_obj:
            print(color_obj + text + Style.RESET_ALL)
            return
    print(text)  
  