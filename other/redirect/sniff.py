# -*- coding: utf-8 -*-

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import PcapReader
from scapy.config import conf
from scapy.error import warning
from scapy.packet import Raw
from scapy.sendrecv import sendp
from scapy.sendrecv import sniff as sniffing
import random
import copy
import logging
import time
import re
import subprocess
import redis

packet_prfix = '\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00'
file_path_prfix = "/tmp/ram/"

redirmsg = ["HTTP/1.1 302 Found",
            # "Location: %(url)s",
            "Location: http://www.163.com",
            "Cache-Control: private",
            "Content-Type: text/html; charset=UTF-8",
            "Server: o_o",
            "Content-Length: 0",
            "",
            ""]

# redirpkt = '\r\n'.join(redirmsg)

class MPcapReader(PcapReader):
    def __init__(self, handle):
        self.filename = "abc.pcap"
        self.f = handle
        self.endian = "<"
        self.linktype = 1
#         self.f.read(4)
#         hdr = self.f.read(20)
#         if len(hdr)<20:
#             raise Scapy_Exception("Invalid pcap file (too short)")
#         _, _, _, _, _, linktype = struct.unpack(self.endian+"HHIIII",hdr)
# 
#         self.linktype = linktype
#         
        try:
            self.LLcls = conf.l2types[self.linktype]
        except KeyError:
            warning("PcapReader: unknown LL type [%i]/[%#x]. Using Raw packets" % (self.linktype, self.linktype))
            self.LLcls = conf.raw_layer
            
def parseHeader(buff, t='response'):
    SEP = '\r\n\r\n'
    HeadersSEP = '\r*\n(?![\t\x20])'
    log = logging.getLogger('parseHeader')
    if SEP in buff:
        header, body = buff.split(SEP, 1)
    else:
        header = buff
        body = ''
    headerlines = re.split(HeadersSEP, header)
    
    if len(headerlines) > 1:
        r = dict()
        if t == 'response':
            _t = headerlines[0].split(' ', 2)
            if len(_t) == 3:
                httpversion, _code, _ = _t
            else:
                log.warn('Could not parse the first header line: %s' % '_t')
                return r
            try:
                r['code'] = int(_code)
            except ValueError:
                return r
        elif t == 'request':
            _t = headerlines[0].split(' ', 2)
            if len(_t) == 3:
                method, uri, httpversion = _t
                r['method'] = method
                r['uri'] = uri
                r['httpversion'] = httpversion
        else:
            log.warn('Could not parse the first header line: %s' % '_t')
            return r  
        r['headers'] = dict()
        for headerline in headerlines[1:]:
            SEP = ':'
            if SEP in headerline:
                tmpname, tmpval = headerline.split(SEP, 1)
                name = tmpname.lower().strip()
                val = map(lambda x: x.strip(), tmpval.split(','))
            else:
                name, val = headerline.lower(), None
            r['headers'][name] = val
        r['body'] = body
        return r

def getdsturl(tcpdata):
        log = logging.getLogger('getdsturl')
        p = parseHeader(tcpdata, t='request')
        if p is None:
                log.warn('parseHeader returned None')
                return
        if p.has_key('uri') and p.has_key('headers'):
            if p['headers'].has_key('host'):
                r = 'http://%s%s' % (p['headers']['host'][0], p['uri'])
                return r
            else:
                log.warn('seems like no host header was set')
        else:
                log.warn('parseHeader did not give us a nice return %s' % p)

def verify(url):
    global urls_cache
#     print "url:", url
    for cdn_host in cdn_hosts:
        if url.find(cdn_host) != -1:
            return False
    ext = url.split('.')[-1].split("?")[0].lower()
#     host = url.split('//')[1].split('/')[0]
    if ext not in exts:
    # if ext in exts:
        return False
    for black in black_list:
        if url.find(black) != -1:
            return False
    if url_request_times > 0:
        if url not in urls_cache:
            rs.lpush("urls", url)
            if url_request_times == 1:
                urls_cache[url] = url_request_times
            else:
                r = int(rs.get(url))
                if not r or r < url_request_times:
                    return False
                urls_cache[url] = url_request_times
    return True
    
def pkt_callback_wrap(pkt):
    try:
        pkt_callback(pkt)
    except Exception as e:
        print(e)
        return
    
def pkt_callback(pkt):
    # print("got Ethernet packet")
    # construct fake l2 for ethernet packet
    dst = mac_dst
    src = mac_src
#         dst = "00:19:e8:a4:bf:44" # 60.207.196.4
    # src = "c8:1f:66:c8:9b:0b" # 192.168.1.203
#         src = "c8:1f:66:c6:aa:91" # 60.207.196.4
    l2 = Ether(dst=dst, src=src)
#         l2 = scapy.Ether(dst = '80:e6:50:07:58:12', src = macl.src)


    ipl = pkt.getlayer(IP)
    l3 = IP(src=ipl.dst, dst=ipl.src)

    # print("we have TCP packet")
    # construct fake layer 4 for TCP
    tcpl = pkt.getlayer(TCP)
    l4 = TCP(dport=tcpl.sport, sport=tcpl.dport)

    if tcpl.flags == 2:  # syn
        # print "return 4"
        return
    elif tcpl.flags == 24 or tcpl.flags == 16:  # psh ack
        if pkt.haslayer(Raw):
#             print ipl.src
#             print ipl.dst
            # print("packet has some data")
            tcpdata = pkt.getlayer(Raw).load
#             print tcpdata
#             print getdsturl(tcpdata)
            if tcpdata.startswith("GET "):
#                 print("TCP data starts with GET")
                
                try:
                    dsturl = getdsturl(tcpdata)
                except Exception as e:
                    print(e)
                    return

                # print dsturl
                if dsturl is None:
                    # print "return 6", dsturl
                    return
                
                # if pkt.getlayer(scapy.IP).src == '219.239.205.142':
                #     print(dsturl)
                # else:
                #     print(dsturl)
                # global num
                # num += 1
                # perSec = int(num / (time.time() -  start_time))
                # print("url num per sec:", perSec)
                # logger.info(dsturl)
#                 print("IP: %s, DST URL: %s" % (pkt.getlayer(scapy.IP).src, dsturl))
#                 print(dsturl)
                if verify(dsturl) == False:
#                     print "inject success"
                    # print "return 7", dsturl
                    return
#                 print iface, dsturl

                # print(ipl.src, ipl.dst)
                # print(tcpl.sport, tcpl.dport)
                # print(time.time(), dsturl)

                # credirpkt = redirpkt % {'url': "http://0x0a.net/" }
                rd = random.randint(0, cdn_num - 1)
                this_redirmsg = copy.copy(redirmsg)
                try:
                    url_list = dsturl[7:].split('/') if dsturl[:7] == 'http://' else dsturl.split('/')
                    dst_host = url_list[0]
                    query_string = "/".join(url_list[1:])
                except Exception as e:
                    print(e)
                    return
                this_redirmsg[1] = "Location: http://%s.%s/%s" % (dst_host, cdn_hosts[rd], query_string)
                redirpkt = '\r\n'.join(this_redirmsg)
                credirpkt = redirpkt

                # construct reply packet
                pktreply = l2 / l3 / l4
                pktreply.getlayer(TCP).seq = tcpl.ack
                pktreply.getlayer(TCP).ack = tcpl.seq + len(tcpdata)
                pktreply.getlayer(TCP).flags = "PA"

                # construct fin packet
                finpktreply = pktreply.copy()
                finpktreply.getlayer(TCP).flags = "FA"
                finpktreply.getlayer(TCP).seq += len(credirpkt)

                # add redir payload to reply packet
                pktreply.getlayer(TCP).add_payload(credirpkt)

                packetbasket = [pktreply, finpktreply]

                # send reply packet
                sendp(packetbasket, verbose=0, iface=sendiface)
                # print("Reply sent")
        # print "return 8"
        return

        
def sniff(d):
    global cdn_hosts
    global cdn_num
    global exts
    global url_request_times
    global black_list
    global sendiface
    global logger
    global num
    global start_time
    global iface
    global mac_dst
    global mac_src
    global filter_hosts
    global urls_cache
    global rs
    num = 0
    start_time = time.time()
    cdn_hosts = d['cdn_hosts']
    cdn_num = d['cdn_num']
    exts = d['exts']
    url_request_times = d['url_request_times']
    black_list = d['black_list']
    sendiface = d['sendiface']
    logger = d['logger']
    filter_hosts = d['filter_hosts']
    iface = d['interface']
    mac_dst = d['mac_dst']
    mac_src = d['mac_src']
    file_path = "%s%s.pcap" % (file_path_prfix, iface, )
    if filter_hosts == 'localhost':
        filter_hosts = "tcp[(tcp[12]>>2):4] = 0x47455420"
    else:
        filter_hosts = "tcp[(tcp[12]>>2):4] = 0x47455420 and host (%s)" % (filter_hosts)
    urls_cache = {}
    rs = redis.Redis(host=d['redis_servere_host'], port=d['redis_servere_port']) 
#     print filter_hosts
#     filter_rules = "tcp dst port 80 and host (%s)" % (filter_hosts)
#     filter_rules = "tcp dst port 80"
    # filter_rules = "tcp dst port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0) and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420"
    # filter_rules = "tcp dst port 80 and dst net 140.206.160.0/24"
#     sniffing(iface=d['interface'], prn=pkt_callback_wrap, filter=filter_rules, store=0)
#    "tcp[(tcp[12]>>2):4] = 0x47455420"
#    tcp[(tcp[12]>>2):4] = 0x47455420 and host ilder.bild.de

# nohup tcpdump -i p1p1 -w p1p1.log 'tcp dst port 80 and host (bilder.bild.de)' > p1p1.log &
# nohup tcpdump -i p1p2 -w p1p2.log 'tcp dst port 80 and host (bilder.bild.de)' > p1p2.log &
# nohup tcpdump -i p1p3 -w p1p3.log 'tcp dst port 80 and host (bilder.bild.de)' > p1p3.log &
# nohup tcpdump -i p1p4 -w p1p4.log 'tcp dst port 80 and host (bilder.bild.de)' > p1p4.log &

# download.comsenz.com wtdisk.com www.ibiblio.org

    try:
        status = 0  # 0：初始状态；1：有效状态；2：无效状态，下面的不用判断了
        pcap_data = ""
        line_one = ""
#         if filter_hosts == "tcp[(tcp[12]>>2):4] = 0x47455420":
#             for row in p.stdout:
#                 stdout_loop(row, status, pcap_data, line_one, file_path)
#         else:
#             for row in iter(p.stdout.readline, b''):
#                 stdout_loop(row, status, pcap_data, line_one, file_path)
        if filter_hosts == "tcp[(tcp[12]>>2):4] = 0x47455420":
            p = subprocess.Popen(['tcpdump', '-U', '-s', '0', '-w', '-', '-i', iface, filter_hosts], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            for row in p.stdout:
                data = row
                num = len(data)
                if line_one == "":
                    line_one = data
            
                if num == 2:
                    if status == 1:
                        f = open(file_path, "wb")
                        f.write(packet_prfix + pcap_data)
                        f.close()
                        pkts = PcapReader(file_path)
                        for pkt in pkts:
                            pkt_callback_wrap(pkt)
                            continue
                    status = 0
                    pcap_data = ""
                    line_one = ""
                if status == 2:
                    continue
                if len(line_one) > 0 and status == 0:
                    res = re.findall('\.([0-9a-zA-z]*)\sHTTP/1\.1', line_one)
                    if len(res) > 0:
                        ext = res[0].split("?")[0].lower()
                        if ext in exts:
                            status = 1
                    if status != 1:
                        status = 2
                if data != "\r\n" and status == 1 and (pcap_data == "" or data[:4] == "Host"):
                    pcap_data += data
        else:
            sniffing(iface=d['interface'], prn=pkt_callback_wrap, filter=filter_hosts, store=0)
#             for row in iter(p.stdout.readline, b''):
#                 data = row
#                 num = len(data)
#                 if line_one == "":
#                     line_one = data
#             
#                 if num == 2:
#                     if status == 1:
#                         f = open(file_path, "wb")
#                         f.write(packet_prfix + pcap_data)
#                         f.close()
#                         pkts = PcapReader(file_path)
#                         for pkt in pkts:
#                             pkt_callback_wrap(pkt)
#                             continue
#                     status = 0
#                     pcap_data = ""
#                     line_one = ""
#                 if status == 2:
#                     continue
#                 if len(line_one) > 0 and status == 0:
#                     res = re.findall('\.([0-9a-zA-z]*)\sHTTP/1\.1', line_one)
#                     if len(res) > 0:
#                         ext = res[0]
#                         if ext in exts:
#                             status = 1
#                     if status != 1:
#                         status = 2
#                 if data != "\r\n" and status == 1 and (pcap_data == "" or data[:4] == "Host"):
#                     pcap_data += data
    except KeyboardInterrupt:
        p.terminate()  # zombie protection, if needed
        