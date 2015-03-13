# -*- coding: utf-8 -*-
'''
Created on 2014年10月22日

@author: ManZhiYong
'''

import ConfigParser

class main(ConfigParser.SafeConfigParser):
    def geteval(self, section, option, raw=False, _vars=None):
        print self.get(section, option, raw, _vars)
        r = eval(self.get(section, option, raw, _vars))
        return r
