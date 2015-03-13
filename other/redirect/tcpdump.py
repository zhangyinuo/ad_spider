# -*- coding: utf-8 -*-
import subprocess
from scapy.data import MTU
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.all import *
import cStringIO
import re

def parseHeader(buff, type='response'):
    import re
    SEP = '\r\n\r\n'
    HeadersSEP = '\r*\n(?![\t\x20])'
    import logging
    log = logging.getLogger('parseHeader')
    if SEP in buff:
        header, body = buff.split(SEP, 1)
    else:
        header = buff
        body = ''
    headerlines = re.split(HeadersSEP, header)
    
    if len(headerlines) > 1:
        r = dict()
        if type == 'response':
            _t = headerlines[0].split(' ', 2)
            if len(_t) == 3:
                httpversion, _code, description = _t
            else:
                log.warn('Could not parse the first header line: %s' % '_t')
                return r
            try:
                r['code'] = int(_code)
            except ValueError:
                return r
        elif type == 'request':
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
        p = parseHeader(tcpdata, type='request')
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
                
prfix = '\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00'
file_path = "/tmp/ram/data.pcap"
exts = ['txt', 'mp4', 'asf', 'asx', 'avi', 'mov', 'rm', 'rmvb', 'ram', 'wmv', 'flv', 'f4v', 'm4v', 'hlv', 'letv', 'mkv', 'm4a', 'ogg', 'pfv', 'ogm', 'mpg', 'mpeg', 'rpx', 'smi', 'smil']
# exts = ['txt']
d = {}
for ext in exts:
    d[ext] = True

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
            
# f = open("p1p1.log", "w")
# tcp[(tcp[12]>>2):4] = 0x47455420
p = subprocess.Popen(['tcpdump', '-U', '-s', '0', '-w', '-', 'tcp dst port 80', '-i', 'p1p1', '-c', '1000000000'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
try:
    status = 0  # 0：初始状态；1：有效状态；2：无效状态，下面的不用判断了
    pcap_data = ""
    ad = ""
    line_one = ""
    for row in p.stdout:
        data = row
        num = len(data)
        if line_one == "":
            line_one = data
#             print [line_one]
            
        if num == 2:
            if status == 1:
                f = open(file_path, "wb")
                f.write(prfix + pcap_data)
                f.close()
#                 f = cStringIO.StringIO(open("data.pcap",'rb').read())
#                 print("pcap_data", pcap_data)
#                 f.write(prfix+pcap_data)
#                 f.seek(0)
#                 print("f.read():", f.read())
#                 s = MPcapReader(f)
                pkts = PcapReader(file_path)
#                 pkt = s.recv(MTU)
                for pkt in pkts:
#                     print type(pkt)
#                     print dir(pkt)
                    if not pkt.haslayer(TCP) or not pkt.haslayer(Ether) or not pkt.haslayer(IP):
                        print type(pkt)
    #                         print dir(pkt)
                        break
                    try:
                        tcpdata = pkt.getlayer(Raw).load
                    except Exception as e:
                        continue
                    if tcpdata.startswith("GET "):
                        try:
                            dsturl = getdsturl(tcpdata)
                        except Exception as e:
                            print(e)
                            continue
                        if not dsturl:
                            continue
                        print dsturl
            status = 0
            pcap_data = ""
            line_one = ""
        if status == 2:
            continue
#         if num >= 5 and data[:5] == "Host:":
#             status = 1
#             print(data)
        if len(line_one) > 0 and status == 0:
            res = re.findall('\.([0-9a-zA-z]*)\sHTTP/1\.1', line_one)
            if len(res) > 0:
                ext = res[0]
                if ext in exts:
                    status = 1
            if status != 1:
                status = 2
        if data != "\r\n":
            pcap_data += data
#     print ad
except KeyboardInterrupt:
    p.terminate()  # zombie protection, if needed


