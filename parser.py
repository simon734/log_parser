import sys
import re
import logging
from collections import defaultdict
from log_keys import *
from basic_info import *

# data members
lsp_basic_info = []
lsp_sess_list = dict()  # token --> session object
lsp_sock_list = defaultdict(list) 
lsp_basic_info = log_basic_info()

ptn_prefix = re.compile(LKEY_COMMON_PREFIX)
ptn_socket = re.compile(LKEY_COMMON_SOCKET)
ptn_close_socket = re.compile(LKEY_SOCK_CLOSE_SOCK)
ptn_token  = re.compile(LKEY_COMMON_TOKEN)
ptn_sess_type = re.compile(LKEY_COMMON_SESS_TYPE)

ptn_tcp_recv = re.compile(LKEY_TCP_RECV)
ptn_tcp_send = re.compile(LKEY_TCP_SEND)
ptn_tcp_connect = re.compile(LKEY_TCP_CONNECT)

ptn_udp_recv = re.compile(LKEY_UDP_RECV)
ptn_udp_send = re.compile(LKEY_UDP_SEND)

# determine the type of socket
def get_sock_type(line):
    kind = 'Unknown'
    mt = ptn_sess_type.search(line.msg)
    if mt:
        kind = mt.group(1)
    return kind

def get_token_in_line(line):
    token = b'0'
    m = ptn_token.search(line.msg)
    if m:
        token = m.group(1)
    return m

# socket definition
class lsp_socket:
    def __init__(self, sid, line):
        self.sid = sid
        self.kind = get_sock_type(line)
        self.lines = []
        self.fake_token = get_token_in_line(line)
        self.real_token = None
        if lsp_basic_info.relay_tid != line.prefix.tid:
            self.real_token = self.fake_token
        else:
            m = re.search(LKEY_TCP_RELAY_ACCEPT, line.msg)
            if m:
                logging.info('lsp_socket, token=%s, log=%s', self.fake_token, line)
                self.real_token = self.fake_token
                self.kind = b'TCP'

        self.begin_time = None
        self.end_time = None
        self.recv_valid_packs = 0
        self.recv_bytes = 0
        self.send_valid_packs = 0
        self.send_bytes = 0

        self.recv_total_packs = 0
        self.send_total_packs = 0

        self.connect_initiate_time = None
        self.connect_dest = None

    def __str__(self):
        if self.kind == b'TCP':
            return '''socket={0.sid}, type=TCP, begin_time={0.begin_time}, end_time={0.end_time},
                    connect_dest={0.connect_dest}, connect_initiate_time={0.connect_initiate_time},
                    recv_btyes={0.recv_bytes}, send_bytes={0.send_bytes},
                    recv_packs={0.recv_valid_packs}/{0.recv_total_packs}, send_packs={0.send_valid_packs}/{0.send_total_packs}'''.format(self)
        elif self.kind == b'UDP':
            return '''socket={0.sid}, type=UDP, begin_time={0.begin_time}, end_time={0.end_time},
                    recv_btyes={0.recv_bytes}, send_bytes={0.send_bytes},
                    recv_packs={0.recv_valid_packs}/{0.recv_total_packs}, send_packs={0.send_valid_packs}/{0.send_total_packs}'''.format(self)
        else:
            return 'socket={}, type=Unknow'.format(self.sid)

    def add_line(self, line):
        #self.lines.append(line)
        if not self.begin_time:
            self.parse_begin(line)
            return

        has_consumed = self.parse_recv(line)
        if has_consumed:
            return

        has_consumed = self.parse_send(line)
        if has_consumed:
            return

        has_consumed = self.parse_connect(line)
        if has_consumed:
            return

        has_consumed = self.parse_end(line)
        if has_consumed:
            return

    def update_token(self, token):
        if token != self.fake_token:
            self.real_token = token

    def has_closed(self):
        if self.end_time:
            return True
        return False

    def parse_begin(self, line):
        if self.begin_time:
            logging.warning('parse_begin, socket has already begined, line:%s', line)
        self.begin_time = line.prefix.time

    def parse_end(self, line):
        m = ptn_close_socket.search(line.msg)
        if not m:
            return False

        if self.end_time:
            logging.warning('parse_end, socket has already closed, line:%s', line)
        self.end_time = line.prefix.time
        return True

    def parse_connect(self, line):
        m = ptn_tcp_connect.search(line.msg)
        if not m:
            return False

        ret = int(m.group(1))
        err = int(m.group(2))
        self.connect_dest = m.group(3)
        logging.debug('parse_connect, ret=%d, err=%d, dest=%s, socket=%s', ret, err, self.connect_dest, self.sid)
        if ret == 0:
            pass
        elif err == 10035 or err == 997:
            if not self.connect_initiate_time:
                self.connect_initiate_time = line.prefix.time
        else:
            logging.error('parse_connect, ret=%d, err=%d, dest=%s, socket=%s, log:%s', ret, err, self.connect_dest, self.sid, line)

    def parse_recv(self, line):
        #logging.info('parse_recv:%s', line)
        m = None
        if self.kind == b'TCP':
            m = ptn_tcp_recv.search(line.msg)
        elif self.kind == b'UDP':
            m = ptn_udp_recv.search(line.msg)
        else:
            return False
        if not m:
            return False

        self.recv_total_packs += 1
        ret = int(m.group(1))
        err = int(m.group(2))
        recv_bytes = int(m.group(3))
        logging.debug('parse_recv: ret=%d, err=%d, recv_bytes=%d', ret, err, recv_bytes)
        if ret == 0 and err == 0 and recv_bytes > 0:
            self.recv_valid_packs += 1
            self.recv_bytes += recv_bytes
        else:
            logging.error('parse_recv:ret=%d, err=%d, recv_bytes=%d, socket=%s, log=%s', ret, err, recv_bytes, self.sid, line)
        return True

    def parse_send(self, line):
        m = None
        if self.kind == b'TCP':
            m = ptn_tcp_send.search(line.msg)
        elif self.kind == b'UDP':
            m = ptn_udp_send.search(line.msg)
            if not m:
                m = ptn_tcp_send.search(line.msg)
        else:
            return False
        if not m:
            return False

        self.send_total_packs += 1
        ret = int(m.group(1))
        err = int(m.group(2))
        send_bytes = int(m.group(3))
        if self.sid == b'3648':
            logging.info('parse_send: ret=%s, err=%s, send_bytes=%s, log=%s', ret, err, send_bytes, line)
        if ret == 0 and err == 0 and send_bytes > 0:
            self.send_valid_packs += 1
            self.send_bytes += send_bytes
        else:
            logging.error('parse_send:ret=%d, err=%d, send_bytes=%d, socket=%s, log=%s', ret, err, send_bytes, self.sid, line)
        return True

# find a socket object if exists, or create a new one
def get_sock_object(sid, line):
    socks_list = lsp_sock_list[sid]
    for sock in socks_list:
        if sid == b'556':
            logging.info('get_sock_object, sid=%s, sock=%s', sid, sock)
        if not sock.has_closed():
            return sock

    logging.info('get_sock_object, create new socket object, socket=%s, log:%s', sid, line)
    sock = lsp_socket(sid, line)
    lsp_sock_list[sid].append(sock)
    return sock

# session definition
class lsp_session:
    def __init__(self, token, line):
        self.token = token
        self.socks = dict()
        self.kind = get_sock_type(line)

    def add_sock(self, sock):
        self.socks[sock.sid] = sock

    def get_sock(self, sid):
        if sid in self.socks:
            return self.socks[sid]
        return None

    def __str__(self):
        return 'token:' + str(self.token, 'utf-8') + ', kind:' + str(self.kind, 'utf-8')

# parse token line
def parse_token_line(token, line):
    if token not in lsp_sess_list:
        sess = lsp_session(token, line)
        lsp_sess_list[token] = sess

    m = ptn_socket.search(line.msg)
    if not m:
        #logging.warning('parse_token_line, socket key not found. line=%s', line.msg)
        return

    sess = lsp_sess_list[token]
    sid = m.group(1)
    sock = sess.get_sock(sid)
    if not sock:
        logging.info('parse_token_line, line=%d, token=%s, type=%s, socket=%s', line.prefix.linenum, token, sess.kind, sid)
        sock = get_sock_object(sid, line)
        sess.add_sock(sock)

    sock.add_line(line)
    sock.update_token(token)

# parse socket line
def parse_socket_line(line):
    m = ptn_socket.search(line.msg)
    if not m:
        return

    sid = m.group(1)
    sock = get_sock_object(sid, line)
    sock.add_line(line)

# parse line
def parse_line(line):
    if not lsp_basic_info.has_relay_init():
        is_ok = lsp_basic_info.get_relay_info(line)
        if is_ok:
            return

    m = ptn_token.search(line.msg)
    if m:
        parse_token_line(m.group(1), line)
        return 

    parse_socket_line(line)

# parse log file
def parse_log_file(file_path):
    with open(file_path, 'rb') as file:
        count = 0
        multi_mode = False
        for line in file:
            count += 1
            match = ptn_prefix.match(line)
            if match:
                if not multi_mode:
                    prefix = log_prefix(match, count)
                    msg = line[match.end():]
                    line = msg_line(prefix, msg)
                    if count > 2:
                        parse_line(line)
                    elif count == 1:
                        lsp_basic_info.get_uin(line)
                    elif count == 2:
                        lsp_basic_info.get_loglevel(line)
                else: # multiple line parsing
                    logging.debug('mutlple line:%s', msg)
                    line = msg_line(prefix, msg)
                    parse_line(line)
                    multi_mode = False
            else:
                logging.debug('Mutliple part:%s', count)
                msg += line
                multi_mode = True

# main entry
def main():
    print('argv=', sys.argv)
    if len(sys.argv) < 2:
        sys.exit(1)
    # get the log file full path
    file_path = sys.argv[1]
    print('File path=', file_path)
    parse_log_file(file_path)
    for k,v in sorted(lsp_sess_list.items()):
        logging.info('token %s:', k)
        for sock in v.socks.values():
            logging.info('socket details:%s', sock)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    #logger = logging.getLogger()
    main()
