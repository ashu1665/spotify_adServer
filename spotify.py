import pyshark
import socket
import subprocess
import os
import re

cap = pyshark.LiveCapture(interface='eth0')
cap.sniff(packet_count=10)


def findUnique(ip_addr):
 if ip_addr in open('search.txt').read():
    #print("word found")
    pass
 else:
    f=open('search.txt','a')
    if 'spotify' in ip_addr or  ip_addr in open('ad_server.txt').read() or 'doubleclick' in ip_addr:
     f.write(ip_addr+'\n')
     f.close()
     try:
      a=socket.gethostbyaddr(ip_addr)
      print(ip_addr+"----------"+a[0]+"---->"+str(os.system("host "+ip_addr)))
     #print(ip_addr2+"----------"+a[0]+"---->"+str(os.system("host "+ip_addr2)))
     except:
      print(ip_addr+"--->"+str(os.system("host "+ip_addr)))
     #print(ip_addr2+"--->"+str(os.system("host "+ip_addr2)))

def print_conversation_header(pkt):
    try:
         #abc=re.findAll("\A127.0.0",pkt.ip.dst)
         #if abc:
          x=''
          if pkt.dns.qry_name:
            print('DNS Request from %s: %s' % (pkt.ip.src, pkt.dns.qry_name))
            x=pkt.dns.qry_name
          elif pkt.dns.resp_name:
            print('DNS Response from %s: %s' % (pkt.ip.src, pkt.dns.resp_name))
            x=pkt.dns.resp_name
          protocol =  pkt.transport_layer
          src_addr = pkt.ip.src
          src_port = pkt[pkt.transport_layer].srcport
          dst_addr = pkt.ip.dst
          dst_port = pkt[pkt.transport_layer].dstport
          #print('%s  %s:%s --> %s:%s' % (protocol, src_addr, src_port, dst_addr, dst_port))
          findUnique(x)
    except AttributeError as e:
        #ignore packets that aren't TCP/UDP or IPv4
        pass
open("search.txt","w").close()
cap.apply_on_packets(print_conversation_header)
