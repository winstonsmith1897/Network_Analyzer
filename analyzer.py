import scapy.layers.l2
import scapy.layers.inet

class NetworkAnalyzer:
    def __init__(self, network_interface):
        self.interface = network_interface
    
    def scan_network(self, network_range):
        """Scans the specified network range and returns a list of
        tuples containing the IP address and MAC address of each
        device found.
        """
        # invia un pacchetto ARP di richiesta
        arp_request = scapy.layers.l2.ARP(pdst=network_range)
        broadcast = scapy.layers.l2.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        answered_list = scapy.layers.srp(packet, iface=self.interface, verbose=False)[0]
        
        # estrae gli indirizzi IP e MAC dalle risposte
        devices = []
        for element in answered_list:
            ip = element[1].psrc
            mac = element[1].hwsrc
            devices.append((ip, mac))
        
        return devices
    
    def get_os(self, ip_address):
        """Sends an ICMP echo request to the specified IP address
        and attempts to determine the operating system of the
        device based on the response.
        """
        # invia un pacchetto ICMP di richiesta
        packet = scapy.layers.inet.IP(dst=ip_address) / scapy.layers.inet.ICMP()
        response = scapy.layers.sr1(packet, iface=self.interface, verbose=False)
        
        # analizza la risposta per determinare il sistema operativo
        if response:
            if response.haslayer(scapy.layers.inet.ICMP):
                # se il pacchetto contiene un layer ICMP, potrebbe essere un sistema operativo Linux
                return "Linux"
            elif response.haslayer(scapy.layers.inet.TCP):
                # se il pacchetto contiene un layer TCP, potrebbe essere un sistema operativo Windows
                return "Windows"
        else:
            # se non si riceve alcuna risposta, il dispositivo potrebbe essere un router o un firewall
            return "Router/Firewall"

# esempio di utilizzo
analyzer = NetworkAnalyzer("eth0")

# scansiona la rete 192.168.1.0/24
devices = analyzer.scan_network("192.168.1.0/24")
