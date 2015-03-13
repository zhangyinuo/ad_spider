# -*- coding: utf-8 -*-
"""
压力测试
"""

__author__ = '满智勇'


"""
python check.py -c 2 -u download.comsenz.com -f /license.txt
python check.py -c 2 -u download.comsenz.com -f /README.html.ori
('location',
"""

import time  
import httplib  
import threading
from time import sleep  
  
# 性能测试页面
host = "download.comsenz.com"
uri = "/DiscuzX/license.txt"

# 配置:压力测试   
# THREAD_NUM = 10            # 并发线程总数   
# ONE_WORKER_NUM = 500       # 每个线程的循环次数   
# LOOP_SLEEP = 0.01      # 每次请求时间间隔(秒)   
  
# 配置:模拟运行状态   
THREAD_NUM = 1  # 并发线程总数   
ONE_WORKER_NUM = 100  # 每个线程的循环次数   
LOOP_SLEEP = 0.5  # 每次请求时间间隔(秒)   
success = 0.0  # 正常干扰数
  
  
# 出错数   
ERROR_NUM = 0  
  
  
# 具体的处理函数，负责处理单个任务   
def doWork(index):
    global success
    threading.currentThread()  
    # print "["+t.name+" "+str(index)+"] "+PERF_TEST_URL   
  
    try:
        conn = httplib.HTTPConnection(host)
        conn.request("GET", uri)
        rsps = conn.getresponse()
        for item in rsps.getheaders():
            if item[0] == "location":
                success += 1
    except Exception as e:
        print e  
  
  
# 这个是工作进程，www.linuxidc.com负责不断从队列取数据并处理   
def working():  
    threading.currentThread()  
#     print "["+t.name+"] Sub Thread Begin"  
  
    i = 0  
    while i < ONE_WORKER_NUM:  
        i += 1  
        doWork(i)  
        sleep(LOOP_SLEEP)  
  
#     print "["+t.name+"] Sub Thread End"  
  
  
def main():
#     for i in xrange(2, 255):
#         print "140.206.161.%s" % i
#     return
#     ext = "a0"
#     for i in xrange(2, 255):
#         ext += ",a%s" % i
#     print ext
#     return
    # doWork(0)   
    # return   

    t1 = time.time()  
  
    Threads = []  
  
    # 创建线程   
    for i in range(THREAD_NUM):  
        t = threading.Thread(target=working, name="T" + str(i))  
        t.setDaemon(True)  
        Threads.append(t)  
  
    for t in Threads:  
        t.start()  
  
    for t in Threads:  
        t.join()  
  
    print "main thread end"  
  
    t2 = time.time()  
    print u"========================================"  
    print u"URL:http:%s%s" % (host, uri,)  
    print u"任务数量:", THREAD_NUM, "*", ONE_WORKER_NUM, "=", THREAD_NUM * ONE_WORKER_NUM  
    print u"总耗时(秒):", t2 - t1  
    print u"每次请求耗时(秒):", (t2 - t1) / (THREAD_NUM * ONE_WORKER_NUM)  
    print u"每秒承载请求数:", 1 / ((t2 - t1) / (THREAD_NUM * ONE_WORKER_NUM))  
    print u"错误数量:", ERROR_NUM
    print u"成功干扰数:", (success / (THREAD_NUM * ONE_WORKER_NUM)) * 100
  
  
if __name__ == "__main__": main()

