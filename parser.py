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
ptn_new_socket = re.compile(LKEY_SOCK_NEW_SOCK)
ptn_close_socket = re.compile(LKEY_SOCK_CLOSE_SOCK)
ptn_negotiation = re.compile(LKEY_SOCK_NEGOTIATION)
ptn_token  = re.compile(LKEY_COMMON_TOKEN)
ptn_sess_type = re.compile(LKEY_COMMON_SESS_TYPE)

ptn_tcp_recv = re.compile(LKEY_TCP_RECV)
ptn_tcp_send = re.compile(LKEY_TCP_SEND)
ptn_tcp_connect = re.compile(LKEY_TCP_CONNECT)
ptn_tcp_relay_accept = re.compile(LKEY_TCP_RELAY_ACCEPT)
ptn_tcp_is_allow_relay = re.compile(LKEY_TCP_IS_ALLOW_RELAY)
ptn_tcp_is_allow_acc = re.compile(LKEY_TCP_IS_ALLOW_ACC)

ptn_udp_recv = re.compile(LKEY_UDP_RECV)
ptn_udp_send = re.compile(LKEY_UDP_SEND)
ptn_udp_is_allow_relay = re.compile(LKEY_UDP_IS_ALLOW_RELAY)
ptn_udp_is_allow_acc = re.compile(LKEY_UDP_IS_ALLOW_ACC)

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
    def __init__(self, sid, kind, ftoken, rtoken, line):
        self.sid = sid
        self.kind = kind
        self.key_logs = []
        self.fake_token = ftoken
        self.real_token = rtoken
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
        self.sock_class = None

    def __str__(self):
        if self.kind == b'TCP':
            return '''socket={0.sid}, type=TCP, class={0.sock_class}, real_token={0.real_token}, fake_token={0.fake_token},
                    begin_time={0.begin_time}, end_time={0.end_time},
                    connect_dest={0.connect_dest}, connect_initiate_time={0.connect_initiate_time},
                    recv_btyes={0.recv_bytes}, send_bytes={0.send_bytes},
                    recv_packs={0.recv_valid_packs}/{0.recv_total_packs}, send_packs={0.send_valid_packs}/{0.send_total_packs}'''.format(self)
        elif self.kind == b'UDP':
            return '''socket={0.sid}, type=UDP, class={0.sock_class}, real_token={0.real_token}, fake_token={0.fake_token},
                    begin_time={0.begin_time}, end_time={0.end_time},
                    recv_btyes={0.recv_bytes}, send_bytes={0.send_bytes},
                    recv_packs={0.recv_valid_packs}/{0.recv_total_packs}, send_packs={0.send_valid_packs}/{0.send_total_packs}'''.format(self)
        else:
            return 'socket={}, type=Unknow'.format(self.sid)

    def add_line(self, line):
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

    def update_sock_class(self, sock_class, rtoken):
        logging.debug('update_sock_class, rtoken=%s, real_token=%s, the socket %s, class %s', rtoken, self.real_token, self.sid, sock_class)

        if self.sock_class != None:
            logging.error('update_sock_class, token=%s, the socket %s already has its class %s, now updating again with class %s',
                    self.fake_token, self.sid, self.sock_class, sock_class)
            return
        self.sock_class = sock_class

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
            logging.warning('parse_connect, ret=%d, err=%d, dest=%s, socket=%s, log:%s', ret, err, self.connect_dest, self.sid, line)
            self.key_logs.append(line)

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
            logging.warning('parse_recv:ret=%d, err=%d, recv_bytes=%d, socket=%s, log=%s', ret, err, recv_bytes, self.sid, line)
            self.key_logs.append(line)
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
        if ret == 0 and err == 0 and send_bytes > 0:
            self.send_valid_packs += 1
            self.send_bytes += send_bytes
        else:
            logging.warning('parse_send:ret=%d, err=%d, send_bytes=%d, socket=%s, log=%s', ret, err, send_bytes, self.sid, line)
            self.key_logs.append(line)
        return True

# find a socket object if exists, or create a new one
def get_sock_object(sid, line):
    socks_list = lsp_sock_list[sid]
    for sock in socks_list:
        if not sock.has_closed():
            return sock

    m = ptn_new_socket.search(line.msg)
    is_accept_sock = False
    if not m:
        m = ptn_tcp_relay_accept.search(line.msg)
        is_accept_sock = True
    if not m:
        return None

    new_sid = m.group(1)
    ftoken = m.group(2)
    rtoken = None
    kind = get_sock_type(line)
    if lsp_basic_info.relay_tid != line.prefix.tid or is_accept_sock:
        rtoken = ftoken
    if is_accept_sock:
        kind = b'TCP'
    logging.debug('get_sock_object, create new socket object, kind=%s, request_socket=%s, new_socket=%s, ftoken=%s, rtoken=%s, log:%s',
            kind, sid, new_sid, ftoken, rtoken, line)
    sock = lsp_socket(new_sid, kind, ftoken, rtoken, line)
    lsp_sock_list[sid].append(sock)
    return sock

# session definition
class lsp_session:
    def __init__(self, token, line):
        self.token = token
        self.socks = []
        self.kind = get_sock_type(line)
        self.is_allow_relay = False
        self.is_allow_acc = False
        self.has_sock_class_updated = False
        self.key_logs = []

    def add_sock(self, sock):
        self.socks.append(sock)

    def update_sess_sock_class(self):
        if self.has_sock_class_updated:
            return

        count = len(self.socks)
        if count < 3:
            return
        elif count > 3:
            logging.error('add sock, two many sockets in token %s', self.token)

        self.has_sock_class_updated = True
        self.socks[0].update_sock_class('game socket', self.token)
        self.socks[1].update_sock_class('local socket', self.token)
        self.socks[2].update_sock_class('remote socket', self.token)

    def get_sock(self, sid):
        for sock in self.socks:
            if sock.sid == sid:
                return sock
        return None

    def parse_line(self, line):
        has_consumed = self.parse_is_allow_relay(line)
        if has_consumed:
            return True

        has_consumed = self.parse_is_allow_acc(line)
        if has_consumed:
            return True

        has_consumed = self.parse_negotiation(line)
        if has_consumed:
            return True

        return False

    def parse_is_allow_relay(self, line):
        m = ptn_tcp_is_allow_relay.search(line.msg)
        if not m:
            m = ptn_udp_is_allow_relay.search(line.msg)

        if not m:
            return False
        self.is_allow_relay = m.group(1)
        logging.debug('parse_is_allow_relay, token=%s, result=%s, log=%s', self.token, self.is_allow_relay, line)
        return True

    def parse_is_allow_acc(self, line):
        if self.is_allow_relay != b'true':
            return False

        m = ptn_tcp_is_allow_acc.search(line.msg)
        if not m:
            m = ptn_udp_is_allow_acc.search(line.msg)

        if not m:
            return False
        self.is_allow_acc = m.group(1)
        logging.debug('parse_is_allow_acc, token=%s, result=%s, log=%s', self.token, self.is_allow_acc, line)
        return True

    def parse_negotiation(self, line):
        if self.is_allow_acc != b'true':
            return False
        m = ptn_negotiation.search(line.msg)
        if not m:
            #logging.info('parse_negotiation, failed to match. token=%s', self.token)
            return False

        self.key_logs.append(line)
        logging.debug('parse_negotiation, token=%s, log=%s', self.token, line)
        return True

    def __str__(self):
        return 'token:{0.token}, type={0.kind}, is_allow_relay:{0.is_allow_relay}, is_allow_acc:{0.is_allow_acc}'.format(self)

# parse token line
def parse_token_line(token, line):
    if token not in lsp_sess_list:
        sess = lsp_session(token, line)
        lsp_sess_list[token] = sess

    m = ptn_socket.search(line.msg)
    if m:
        logging.debug('parse_token_line, token=%s, line=%s', token, line.msg)
        sess = lsp_sess_list[token]
        sid = m.group(1)
        sock = sess.get_sock(sid)
        if not sock:
            logging.debug('parse_token_line, line=%d, token=%s, type=%s, socket=%s', line.prefix.linenum, token, sess.kind, sid)
            sock = get_sock_object(sid, line)
            if not sock:
                return
            sess.add_sock(sock)

        sock.add_line(line)
        sock.update_token(token)

    # filter out important token messages
    sess = lsp_sess_list[token]
    sess.parse_line(line)
    sess.update_sess_sock_class()

# parse socket line
def parse_socket_line(line):
    m = ptn_socket.search(line.msg)
    if not m:
        return

    sid = m.group(1)
    sock = get_sock_object(sid, line)
    if sock:
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
    logging.debug('argv=', sys.argv)
    if len(sys.argv) < 2:
        sys.exit(1)
    # get the log file full path
    file_path = sys.argv[1]
    logging.debug('File path=', file_path)
    parse_log_file(file_path)
    for k,v in sorted(lsp_sess_list.items()):
        if v.is_allow_relay != b'true':
            continue
        logging.info('------begin--->>>>:')
        logging.info('token %s:', v)
        for log in v.key_logs:
            logging.info('%s', log)
        logging.info('\n')
        for sock in v.socks:
            logging.info('socket details-->%s', sock)
            for log in sock.key_logs:
                logging.info('%s', log)
            logging.info('\n')

        logging.info('<<<---end------\n\n')

if __name__ == "__main__":
    logging.basicConfig(format='%(message)s', level=logging.INFO)
    #logger = logging.getLogger()
    main()
