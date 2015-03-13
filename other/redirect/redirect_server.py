# -*- coding: utf-8 -*-

import sys
import config
import logging.handlers
import sniff
# import redirect
        
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("example:\npython main.py em1")
        sys.exit()
    
    interface = sys.argv[1]
    root = sys.path[0]
    cf = config.main()
    cf.read("%s/config.ini" % (root))
    cdn_hosts = cf.geteval('system', 'cdn_hosts')
    cdn_num = len(cdn_hosts)
    exts = cf.geteval('system', 'exts')
    url_request_times = cf.getint('system', 'url_request_times')
    black_list = cf.geteval('system', 'black_list')
    sendiface = cf.get('system', 'sendiface')
    filter_hosts = cf.get('system', 'filter_hosts')
    mac_src = cf.get('system', 'mac_src')
    mac_dst = cf.get('system', 'mac_dst')
    
    redis_servere_host = cf.get('system', 'redis_servere_host')
    redis_servere_port = cf.getint('system', 'redis_servere_port')
    
    LOG_FILE = '%s/logs/%s.log' % (root, interface,)
    handler = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes = 1024*1024, backupCount = 5) # 实例化handler   
    fmt = '%(asctime)s - %(filename)s:%(lineno)s - %(name)s - %(message)s'
    formatter = logging.Formatter(fmt)   # 实例化formatter  
    handler.setFormatter(formatter)      # 为handler添加formatter  
    logger = logging.getLogger(interface)    # 获取名为tst的logger  
    logger.addHandler(handler)           # 为logger添加handler  
    logger.setLevel(logging.DEBUG)
    
    d = {'url_request_times':url_request_times, 'redis_servere_host':redis_servere_host, 'redis_servere_port':redis_servere_port, 'interface':interface, 'cdn_hosts':cdn_hosts, 'cdn_num':cdn_num, 'exts':exts, 'black_list':black_list, 'sendiface':sendiface, 'filter_hosts':filter_hosts, 'logger':logger, 'mac_src':mac_src, 'mac_dst':mac_dst}
    # redirect.sniff(d)
    while True:
        try:
            sniff.sniff(d)
        except Exception as e:
            print("error", e)
        
