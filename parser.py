import sys
import re
import logging
from datetime import datetime
from log_keys import *

# data members
logger = None
lsp_basic_info = []
lsp_sess_list = []

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
        logging.debug('log prefix:%d', line_num)

# basic info definition
class log_basic_info:
    def __init__(self):
        pass

    def get_uin(self, prefix, msg):
        p = re.compile(LKEY_BASIC_UIN)
        print('get_uin:', msg)
        m = p.match(msg)
        if m:
            print('uin:', m.group(1))

    def get_loglevel(self, prefix, msg):
        p = re.compile(LKEY_BASIC_LOG_LEVEL)
        print('get_loglevel:', msg)
        m = p.match(msg)
        if m:
            print('log level:', m.group(1))

    def get_netmode(self, prefix, msg):
        p = re.compile(LKEY_BASIC_NET_MODE)
        print('get_netmode:', msg)
        m = p.match(msg)
        if m:
            print('net_mode:', m.group(1))

# session definition

# parse line
def parse_line(line):
    pass

# init everything

# main entry
def main():
    print('argv=', sys.argv)
    if len(sys.argv) < 2:
        sys.exit(1)
    # get the log file full path
    file_path = sys.argv[1]
    print('File path=', file_path)
    basic_info = log_basic_info()

    with open(file_path, 'rb') as file:
        count = 0
        pattern = re.compile(LKEY_COMMON_PREFIX)
        for line in file:
            count += 1
            match = pattern.match(line)
            if match and count <= 3:
                prefix = log_prefix(match, count)
                msg = line[match.end():]
                if count == 1:
                    basic_info.get_uin(prefix, msg)
                elif count == 2:
                    basic_info.get_loglevel(prefix, msg)
                elif count == 3:
                    basic_info.get_netmode(prefix, msg)
                else :
                    pass

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    #logger = logging.getLogger()
    main()
