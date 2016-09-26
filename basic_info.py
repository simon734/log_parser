import re
import logging
from log_keys import *
from datetime import datetime

# basic info definition
class log_basic_info:
    def __init__(self):
        self.uin = None
        self.log_level = None
        self.relay_tid = None
        self.relay_tcp_inited = None
        self.relay_udp_inited = None

    def __str__(self):
        return ''''basic_info:uin={}, relay_thread_id={}, log_level={}'''.format(self.uin, self.relay_tid, self.log_level)

    def has_relay_init(self):
        return self.relay_tcp_inited and self.relay_udp_inited

    def get_relay_info(self, line):
        m = re.search(LKEY_TCP_RELAY_INIT, line.msg)
        if m:
            self.relay_tcp_inited = m.group(1)
            self.relay_tid = line.prefix.tid
            logging.debug('get_relay_info: tcp init is %s, tid=%s', self.relay_tcp_inited, self.relay_tid)
            return True
        m = re.search(LKEY_UDP_RELAY_INIT, line.msg)
        if m:
            self.relay_udp_inited = m.group(1)
            self.relay_tid = line.prefix.tid
            logging.debug('get_relay_info: udp init is %s, tid=%s', self.relay_udp_inited, self.relay_tid)
            return True

        return False

    def get_uin(self, line):
        p = re.compile(LKEY_BASIC_UIN)
        m = p.search(line.msg)
        if m:
            self.uin = m.group(1).decode('utf-8')

    def get_loglevel(self, line):
        p = re.compile(LKEY_BASIC_LOG_LEVEL)
        m = p.search(line.msg)
        if m:
            self.log_level = m.group(1).decode('utf-8')

# prefix
class log_prefix:
    def __init__(self, match, line_num):
        strtime = str(match.group(1), 'utf-8')
        threadid = str(match.group(2), 'utf-8')
        loglevel = str(match.group(3), 'utf-8')

        self.time = datetime.strptime(strtime, '%Y-%m-%d %H:%M:%S.%f')
        self.tid = threadid
        self.loglev = loglevel
        self.linenum = line_num
        #debug('log prefix:{0}, tid:{1}, loglevel:{2}, ', self.time, self.tid, self.loglev )
        #logging.debug('log prefix:%d', line_num)

# msg line definition
class msg_line:
    def __init__(self, prefix, msg):
        self.prefix = prefix
        self.msg = msg

    def __str__(self):
        return 'line:{0}, time:{1}, msg:{2}'.format(self.prefix.linenum, self.prefix.time, self.msg)
