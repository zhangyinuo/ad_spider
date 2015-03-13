# -*- coding: utf-8 -*-
import gevent
import web
import sys
from libs import config
import cPickle
import logging.handlers
import copy
import os
import redis
# from scapy.layers.inet import TCP, IP
# from scapy.layers.l2 import Ether
# from scapy.packet import Raw
# from scapy.sendrecv import sendp
# from scapy.sendrecv import sniff

class main(object):
    def __init__(self):
        self._init_val()
        self._initDB()
        self._initRedis()
#         self._initLog()
        self.run()

    def _init_val(self):
        
        # 程序路径
        self.root = sys.path[0]
        
        # 干扰机的配置文件路径，不是web的
        self.config_path = "%s/config.ini" % (self.root)
        
        # 先把干扰机的配置文件读出来
        self.rcf = {}
        rcf = config.main()
        rcf.read(self.config_path)
        self.rcf['cdn_hosts'] = rcf.geteval('system', 'cdn_hosts')
        self.rcf['exts'] = rcf.geteval('system', 'exts')
        self.rcf['url_request_times'] = 0
        self.rcf['black_list'] = rcf.geteval('system', 'black_list')
        
        self.rcf['sendiface'] = rcf.get('system', 'sendiface')
        self.rcf['mac_dst'] = rcf.get('system', 'mac_dst')
        self.rcf['mac_src'] = rcf.get('system', 'mac_src')
        self.rcf['filter_hosts'] = rcf.get('system', 'filter_hosts')
        self.rcf['redis_servere_host'] = rcf.get('system', 'redis_servere_host')
        self.rcf['redis_servere_port'] = rcf.getint('system', 'redis_servere_port')
        
        # 配置文件 系统数据
        cf = config.main()
        cf.read("%s/config_web.ini" % (self.root))
        self.user_id = cf.getint('system', 'user_id')
        self.renew_time = cf.getint('system', 'renew_time')
        
        # redis
        self.redis_servere_host = cf.get('system', 'redis_servere_host')
        self.redis_servere_port = cf.getint('system', 'redis_servere_port')
        
        
        # 配置文件 数据库
        self.sql_host = cf.get('db', 'sql_host')
        self.sql_port = cf.getint('db', 'sql_port')
        self.sql_user = cf.get('db', 'sql_user')
        self.sql_password = cf.get('db', 'sql_password')
        self.sql_name = cf.get('db', 'sql_name')
        self.sql_charset = cf.get('db', 'sql_charset')
        self.sql_prefix = cf.get('db', 'sql_prefix')
        
        # 转向的报文
        self.redirmsg = ["HTTP/1.1 302 Found",
            # "Location: %(url)s",
            "Location: http://www.163.com",
            "Cache-Control: private",
            "Content-Type: text/html; charset=UTF-8",
            "Server: o_o",
            "Content-Length: 0",
            "",
            ""]
        
        self.exts = []
        self.filter_hosts = []
        self.filter = ""
        self.black_list = []
        self.urls_cache = {} # 已经请求的连接字典缓存，就不用每次验证次数是否达到时都去读redis了
        self.url_request_times = 0

    def _initRedis(self):
        self.redis = redis.Redis(host=self.redis_servere_host, port=self.redis_servere_port)  # 如果设置了密码，就加上password=密码

    def _initDB(self):
        self.db = web.database(dbn='mysql', db=self.sql_name, user=self.sql_user, pw=self.sql_password, host=self.sql_host, port=self.sql_port, charset=self.sql_charset)
        self.db.printing = False
        
        self._renew()
    
    def _initLog(self):
        LOG_FILE = '%s/logs/%s.log' % (self.root, self.interface,)
        handler = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=1024 * 1024, backupCount=5)  # 实例化handler   
        fmt = '%(asctime)s - %(filename)s:%(lineno)s - %(name)s - %(message)s'
        formatter = logging.Formatter(fmt)  # 实例化formatter  
        handler.setFormatter(formatter)  # 为handler添加formatter  
        logger = logging.getLogger(self.interface)  # 获取名为tst的logger  
        logger.addHandler(handler)  # 为logger添加handler  
        logger.setLevel(logging.DEBUG)
        
    def _renew(self):
        old_exts = copy.copy(self.exts)
        old_url_request_times = copy.copy(self.url_request_times)
        old_filter = copy.copy(self.filter)
        old_black_list = copy.copy(self.black_list)
        self.exts = ""
        self.rcf['exts'] = []
        res = self.db.select('app_base', {"user_id":self.user_id}, where="user_id = $user_id")
        if res:
            r = res[0]
            data = cPickle.loads(r.data)
            if 'exts' in data:
                self.exts = data['exts']
                self.rcf['exts'] = self.exts.split(",")
            if 'url_request_times' in data:
                self.url_request_times = self.rcf['url_request_times'] = int(data['url_request_times'])
            else:
                self.url_request_times = self.rcf['url_request_times'] = 0
        self.filter_hosts = []
        res = self.db.select('app_white_list', {"user_id":self.user_id}, where="user_id = $user_id")
        if res:
            r = res[0]
            self.filter_hosts = cPickle.loads(r.data)
        if len(self.filter_hosts) == 0:
            self.filter_hosts = ['localhost']

        self.black_list = []
        res = self.db.select('app_black_list', {"user_id":self.user_id}, where="user_id = $user_id")
        if res:
            r = res[0]
            self.black_list = cPickle.loads(r.data)
        self.filter = ""
        for host in self.filter_hosts:
            if self.filter == "":
                self.filter = host
            else :
                self.filter += " or %s" % (host)
        if self.filter == "":
            self.filter = "localhost"
#         print(time.time(), self.user_id, self.exts, self.filter_hosts, self.filter)
        if old_exts != self.exts or old_filter != self.filter or old_black_list != self.black_list or old_url_request_times != self.url_request_times:
            if old_url_request_times > self.url_request_times:
                self.urls_cache = {}
            print "reset"
            self._reset()

    def _reset(self):
        lines = os.popen('ps aux | grep \'python redirect_server.py\'').read().split("\n")
        for line in lines:
            line = ' '.join(line.split())
            data = line.split()
            if len(data) > 2:
                pid = data[1]
                print pid
                os.popen('kill -9 %s' % (pid))
        
        data = """[system]
cdn_hosts = %s

exts = %s

black_list = %s

sendiface = %s

mac_dst = %s

mac_src = %s

filter_hosts = %s

url_request_times = %s

redis_servere_host = %s

redis_servere_port = %s
        """
        data = data % (self.rcf['cdn_hosts'], self.rcf['exts'], self.black_list, self.rcf['sendiface'], self.rcf['mac_dst'], self.rcf['mac_src'], self.filter, self.rcf['url_request_times'], self.rcf['redis_servere_host'], self.rcf['redis_servere_port'])
        self.write_file(self.config_path, data)
        gevent.sleep(1)
        os.popen('bash start_debug.sh')
        print "reset over"
    
    def _update(self):
        self._renew()
        gevent.sleep(self.renew_time)
        gevent.spawn(self._update)

    # aaa
    def _queue(self):
        i = 0
        while self.url_request_times > 0:
            url = self.redis.rpop("urls")
            if url == None:
                break
            if url not in self.urls_cache:
                self.urls_cache[url] = 0
            if self.urls_cache[url] < (self.url_request_times - 1):
                self.urls_cache[url] += 1
            else:
                self.redis.set(url, self.url_request_times)
            i += 1
            if i > 10000:
                break
        gevent.sleep(0.1)
        gevent.spawn(self._queue)
              
    def run(self):
        gevent.spawn(self._update)
        gevent.spawn(self._queue)
        while True:
            gevent.sleep(1)
#         gevent.spawn(sniff(iface=self.interface, prn=self.pkt_callback_wrap, filter=self.filter, store=0))
#         sniff(iface=self.interface, prn=self.pkt_callback_wrap, filter=self.filter, store=0)
#         while True:
#             sniff(iface=self.interface, prn=self.pkt_callback_wrap, filter=self.filter, store=0)
            

    def write_file(self, file_path, data):
        f = open(file_path, 'wb')
        f.write(data)
        f.close()
        
#     def parseHeader(self, buff,t='response'):
#         SEP = '\r\n\r\n'
#         HeadersSEP = '\r*\n(?![\t\x20])'
#         log = logging.getLogger('parseHeader')
#         if SEP in buff:
#             header,body = buff.split(SEP,1)
#         else:
#             header = buff
#             body = ''
#         headerlines = re.split(HeadersSEP, header)
#         
#         if len(headerlines) > 1:
#             r = dict()
#             if t == 'response':
#                 _t = headerlines[0].split(' ',2)
#                 if len(_t) == 3:
#                     httpversion,_code,_ = _t
#                 else:
#                     log.warn('Could not parse the first header line: %s' % '_t')
#                     return r
#                 try:
#                     r['code'] = int(_code)
#                 except ValueError:
#                     return r
#             elif t == 'request':
#                 _t = headerlines[0].split(' ',2)
#                 if len(_t) == 3:
#                     method,uri,httpversion = _t
#                     r['method'] = method
#                     r['uri'] = uri
#                     r['httpversion'] = httpversion
#             else:
#                 log.warn('Could not parse the first header line: %s' % '_t')
#                 return r  
#             r['headers'] = dict()
#             for headerline in headerlines[1:]:
#                 SEP = ':'
#                 if SEP in headerline:
#                     tmpname,tmpval = headerline.split(SEP,1)
#                     name = tmpname.lower().strip()
#                     val =  map(lambda x: x.strip(),tmpval.split(','))
#                 else:
#                     name,val = headerline.lower(),None
#                 r['headers'][name] = val
#             r['body'] = body
#             return r
#     
#     def getdsturl(self, tcpdata):
#             log = logging.getLogger('getdsturl')
#             p = self.parseHeader(tcpdata,t='request')
#             if p is None:
#                     log.warn('parseHeader returned None')
#                     return
#             if p.has_key('uri') and p.has_key('headers'):
#                 if p['headers'].has_key('host'):
#                     r = 'http://%s%s' % (p['headers']['host'][0],p['uri'])
#                     return r
#                 else:
#                     log.warn('seems like no host header was set')
#             else:
#                     log.warn('parseHeader did not give us a nice return %s' % p)
#     
#     def verify(self, url):
#         for cdn_host in self.cdn_hosts:
#             if url.find(cdn_host) != -1:
#                 return False
#         for item in self.black_list:
#             if url.find(item) != -1:
#                 return False
#         ext = url.split('.')[-1]
#         host = url.split('//')[1].split('/')[0]
#         if ext in self.exts and host in self.filter_hosts:
#             return True
#         return False
#         
#     def pkt_callback_wrap(self, pkt):
#         try:
#             self.pkt_callback(pkt)
#         except Exception as e:
#             print(e)
#             return
#         
#     def pkt_callback(self, pkt):
#         if not pkt.haslayer(TCP):
#             return
#         
#         if pkt.haslayer(Ether):
# #             macl = pkt.getlayer(mscapy.Ether)
# #             dst = "00:19:e8:a4:bf:44"
#             # src = "c8:1f:66:c8:9b:0b" # 192.168.1.203
# #             src = "c8:1f:66:c6:aa:91" # 60.207.196.4
#             l2 = Ether(dst=self.mac_dst, src=self.mac_src)
#     #         l2 = mscapy.Ether(dst = '80:e6:50:07:58:12', src = macl.src)
#         else:
#             return
#     
#         if pkt.haslayer(IP):
#             # construct fake l3
#             ipl = pkt.getlayer(IP)
#             l3 = IP(src=ipl.dst, dst=ipl.src)
#         else:
#             return
#         
#         # construct fake layer 4 for TCP
#         tcpl = pkt.getlayer(TCP)
#         l4 = TCP(dport=tcpl.sport, sport=tcpl.dport)
#     
#         if tcpl.flags == 2:  # syn
#             # print "return 4"
#             return
#         elif tcpl.flags == 24 or tcpl.flags == 16:  # psh ack
#             if pkt.haslayer(Raw):
#                 tcpdata = pkt.getlayer(Raw).load
#                 if tcpdata.startswith("GET "):
#                     try:
#                         dsturl = self.getdsturl(tcpdata)
#                     except Exception as e:
#                         print(e)
#                         return
#     
#                     if dsturl is None:
#                         return
#                     
#                     if self.verify(dsturl) == False:
#                         return
#                     
#                     rd = random.randint(0, self.cdn_num - 1)
#                     this_redirmsg = copy.copy(self.redirmsg)
#                     try:
#                         url_list = dsturl[7:].split('/') if dsturl[:7] == 'http://' else dsturl.split('/')
#                         dst_host = url_list[0]
#                         query_string = "/".join(url_list[1:])
#                     except Exception as e:
#                         print(e)
#                         return
#                     this_redirmsg[1] = "Location: http://%s.%s/%s" % (dst_host, self.cdn_hosts[rd], query_string)
#                     redirpkt = '\r\n'.join(this_redirmsg)
#                     credirpkt = redirpkt
#     
#                     # construct reply packet
#                     pktreply = l2 / l3 / l4
#                     pktreply.getlayer(TCP).seq = tcpl.ack
#                     pktreply.getlayer(TCP).ack = tcpl.seq + len(tcpdata)
#                     pktreply.getlayer(TCP).flags = "PA"
#     
#                     # construct fin packet
#                     finpktreply = pktreply.copy()
#                     finpktreply.getlayer(TCP).flags = "FA"
#                     finpktreply.getlayer(TCP).seq += len(credirpkt)
#     
#                     # add redir payload to reply packet
#                     pktreply.getlayer(TCP).add_payload(credirpkt)
#     
#                     packetbasket = [pktreply, finpktreply]
#     
#                     # send reply packet
#                     sendp(packetbasket, verbose=0, iface=self.sendiface)
#             return
    
