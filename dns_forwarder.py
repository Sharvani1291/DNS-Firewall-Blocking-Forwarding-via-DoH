import argparse
import socket
import requests
from scapy.all import DNS, DNSQR
import logging
import base64

class DNSForwarder:
    def __init__(self, dst_ip, deny_list_file, log_file, use_doh, doh_server):
        self.dst_ip = dst_ip
        self.deny_list = self.load_deny_list(deny_list_file)
        self.use_doh = use_doh
        self.doh_server = doh_server
        self.doh_session = requests.Session()
        
        if log_file:
            logging.basicConfig(filename=log_file, level=logging.INFO, format='%(message)s')
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((socket.gethostname()+".cs.uga.edu", 53))
    
    def load_deny_list(self, file_name):
        with open(file_name, 'r') as f:
            return set(line.strip() for line in f)
    
    def send_doh_request(self, dns_msg, server):
        url = f"https://{server}/dns-query?dns={base64.urlsafe_b64encode(bytes(dns_msg)).decode().rstrip('=')}"
        response = self.doh_session.get(url, timeout=5)
        return response.content
    
    def handle_request(self, data, addr):
        dns_req = DNS(data)
        domain = dns_req.qd.qname.decode('utf-8')[:-1]
        
        if domain in self.deny_list:
            dns_req.qr = 1
            dns_req.ra = 1
            dns_req.rcode = 3
            self.socket.sendto(bytes(dns_req), addr)
            logging.info(f"{domain} {DNSQR().get_field('qtype').i2s[dns_req.qd.qtype]} DENY")
        else:
            if self.use_doh or self.doh_server:
                doh_server = self.doh_server or "8.8.8.8"
                try:
                    response_data = self.send_doh_request(data, doh_server)
                    self.socket.sendto(response_data, addr)
                except requests.exceptions.RequestException as e:
                    logging.error(f"DoH request failed: {e}")
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as resolver_socket:
                    resolver_socket.sendto(data, (self.dst_ip, 53))
                    resolver_socket.settimeout(10)
                    try:
                        response_data, _ = resolver_socket.recvfrom(1024)
                        self.socket.sendto(response_data, addr)
                    except socket.timeout:
                        logging.error("DNS request timed out")
            logging.info(f"{domain} {DNSQR().get_field('qtype').i2s[dns_req.qd.qtype]} ALLOW")
    
    def run(self):
        print("DNS forwarder has started...")
        while True:
            data, addr = self.socket.recvfrom(1024)
            self.handle_request(data, addr)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--dst_ip", help="Destination DNS server IP")
    parser.add_argument("-f", "--deny_list_file", required=True, help="File containing domains to block")
    parser.add_argument("-l", "--log_file", help="Append-only log file")
    parser.add_argument("--doh", action="store_true", help="Use default upstream DoH server")
    parser.add_argument("--doh_server", help="Use this upstream DoH server")
    args = parser.parse_args()
    
    dns_forwarder = DNSForwarder(args.dst_ip, args.deny_list_file, args.log_file, args.doh, args.doh_server)
    dns_forwarder.run()

if __name__ == "__main__":
    main()