import sys
import re
import io
import os
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
ptn_comm_stat = re.compile(LKEY_SOCK_COMM_STAT)
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

# data statistics
class data_stat:
    def __init__(self):
        self.recv_valid_packs = 0
        self.recv_bytes = 0
        self.send_valid_packs = 0
        self.send_bytes = 0
        self.recv_total_packs = 0
        self.send_total_packs = 0


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
        self.sock_data = defaultdict(data_stat)   # dest  --  data_stat

        self.connect_initiate_time = None
        self.connect_dest = None
        self.sock_class = None

    def __str__(self):
        if self.kind != b'TCP' and self.kind != b'UDP':
            return 'socket={}, type=Unknow'.format(self.sid.decode('utf-8'))

        output = io.StringIO()
        output.write('''socket={1}, type={kind}, class={0.sock_class}, real_token={real_token}, fake_token={fake_token},
                    begin_time={0.begin_time}, end_time={0.end_time}\n'''.format(
                        self, self.sid.decode('utf-8'), kind=self.kind.decode('utf-8'), real_token=self.real_token.decode('utf-8'), fake_token=self.fake_token.decode('utf-8')))

        if self.kind == b'TCP' and self.connect_dest != None:
            output.write('''connect_dest={1}, connect_initiate_time={0.connect_initiate_time},\n'''.format(self, self.connect_dest.decode('utf-8')))

        for k,v in self.sock_data.items():
            output.write('''peer={0}, recv_btyes={1.recv_bytes}, send_bytes={1.send_bytes},
                            recv_packs={1.recv_valid_packs}/{1.recv_total_packs}, send_packs={1.send_valid_packs}/{1.send_total_packs}\n'''.format(k, v))
        contents = output.getvalue()
        output.close()
        return contents

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
            logging.debug('update_sock_class, token=%s, the socket %s already has its class %s, now updating again with class %s',
                    self.real_token, self.sid, self.sock_class, sock_class)
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
        is_udp_mode = False
        m = None
        if self.kind == b'TCP':
            m = ptn_tcp_recv.search(line.msg)
        elif self.kind == b'UDP':
            m = ptn_udp_recv.search(line.msg)
            is_udp_mode = True
            if not m:
                m = ptn_tcp_recv.search(line.msg)
                is_udp_mode = False
        else:
            return False
        if not m:
            return False

        ret = int(m.group(1))
        err = int(m.group(2))
        dest = self.connect_dest
        if is_udp_mode:
            dest = m.group(3)
        recv_bytes = int(m.group(4))
        logging.debug('parse_recv: ret=%d, err=%d, recv_bytes=%d', ret, err, recv_bytes)

        stat = self.sock_data[dest]
        stat.recv_total_packs += 1
        if ret == 0 and err == 0 and recv_bytes > 0:
            stat.recv_valid_packs += 1
            stat.recv_bytes += recv_bytes
        else:
            logging.warning('parse_recv:ret=%d, err=%d, recv_bytes=%d, socket=%s, log=%s', ret, err, recv_bytes, self.sid, line)
            self.key_logs.append(line)
        return True

    def parse_send(self, line):
        m = None
        is_udp_mode = False
        if self.kind == b'TCP':
            m = ptn_tcp_send.search(line.msg)
        elif self.kind == b'UDP':
            m = ptn_udp_send.search(line.msg)
            is_udp_mode = True
            if not m:
                m = ptn_tcp_send.search(line.msg)
                is_udp_mode = False
        else:
            return False
        if not m:
            return False

        ret = int(m.group(1))
        err = int(m.group(2))
        from_dst = self.connect_dest
        if is_udp_mode:
            from_dst = m.group(3)
        send_bytes = int(m.group(4))

        stat = self.sock_data[from_dst]
        stat.send_total_packs += 1
        if ret == 0 and err == 0 and send_bytes > 0:
            stat.send_valid_packs += 1
            stat.send_bytes += send_bytes
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

# commnication statistics
class comm_stat:
    def __init__(self):
        self.guid_str=None
        self.proxy_ip=None
        self.proxy_port=None
        self.proxy_idc=None
        self.game_ip=None
        self.game_port=None
        self.game_idc=None

    def __str__(self):
        return '''guid={0.guid_str},
                  proxy={0.proxy_ip}:{0.proxy_port}, proxy_idc={0.proxy_idc}
                  game_svr={0.game_ip}:{0.game_port}, game_idc={0.game_idc}'''.format(self)

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
        self.sock_comm_stat = comm_stat()

    def add_sock(self, sock):
        self.socks.append(sock)
        if self.has_sock_class_updated:
            self.has_sock_class_updated = False

    def update_sess_sock_class(self):
        if self.has_sock_class_updated:
            return

        count = len(self.socks)
        if count < 3:
            return

        self.has_sock_class_updated = True
        self.socks[0].update_sock_class('game socket', self.token)
        self.socks[1].update_sock_class('local socket', self.token)
        for index in range(2, count):
            self.socks[index].update_sock_class('remote socket', self.token)

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

        has_consumed = self.parse_comm_stat(line)
        if has_consumed:
            return True

        return False

    def parse_is_allow_relay(self, line):
        m = ptn_tcp_is_allow_relay.search(line.msg)
        if not m:
            m = ptn_udp_is_allow_relay.search(line.msg)

        if not m:
            return False
        if m.group(1) == b'true':
            self.is_allow_relay = True
        logging.debug('parse_is_allow_relay, token=%s, result=%s, log=%s', self.token, self.is_allow_relay, line)
        return True

    def parse_is_allow_acc(self, line):
        m = ptn_tcp_is_allow_acc.search(line.msg)
        if not m:
            m = ptn_udp_is_allow_acc.search(line.msg)

        if not m:
            return False
        if m.group(1) == b'true' or m.group(1) == b'acc':
            self.is_allow_relay = True
            self.is_allow_acc = True
        logging.debug('parse_is_allow_acc, token=%s, result=%s, log=%s', self.token, self.is_allow_acc, line)
        return True

    def parse_negotiation(self, line):
        if not self.is_allow_acc:
            return False
        m = ptn_negotiation.search(line.msg)
        if not m:
            #logging.info('parse_negotiation, failed to match. token=%s', self.token)
            return False

        self.key_logs.append(line)
        logging.debug('parse_negotiation, token=%s, log=%s', self.token, line)
        return True

    def parse_comm_stat(self, line):
        if not self.is_allow_acc:
            return False

        m = ptn_comm_stat.search(line.msg)
        if not m:
            return False

        # b'ReportCommunicationStatistic.*guid_str=([\w|-]+).*proxy_ip=([\d|.]+).*proxy_port=(\d+).*proxy_idc=(\d+).*game_ip=([\d|.]+).*game_port=(\d+).*game_idc=(\d+)'
        stat = self.sock_comm_stat
        stat.guid_str = m.group(1).decode('utf-8')
        stat.proxy_ip = m.group(2).decode('utf-8')
        stat.proxy_port = m.group(3).decode('utf-8')
        stat.proxy_idc = m.group(4).decode('utf-8')
        stat.game_ip = m.group(5).decode('utf-8')
        stat.game_port = m.group(6).decode('utf-8')
        stat.game_idc = m.group(7).decode('utf-8')
        return True

    def __str__(self):
        return 'token:{0.token}, type={0.kind}, is_allow_relay:{0.is_allow_relay}, is_allow_acc:{0.is_allow_acc},\n\n{0.sock_comm_stat}'.format(
                self )

# parse token line
def parse_token_line(token, line):
    if token not in lsp_sess_list:
        sess = lsp_session(token, line)
        lsp_sess_list[token] = sess

    m = ptn_socket.search(line.msg)
    if m:
        sess = lsp_sess_list[token]
        sid = m.group(1)
        sock = sess.get_sock(sid)
        logging.debug('parse_token_line, token=%s, socket=%s, line=%s', token, sid, line.msg)
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

# get file logger
def set_file_logger(file_path):
    logger = logging.getLogger()

    log_file_name = os.path.splitext(file_path)[0] + '_parsed_log.txt'
    fh = logging.FileHandler(log_file_name, 'w')
    fh.setLevel(logging.ERROR)
    formatter = logging.Formatter('%(message)s')
    fh.setFormatter(formatter)

    logger.addHandler(fh)

# main entry
def main():
    logging.debug('argv=', sys.argv)
    if len(sys.argv) < 2:
        sys.exit(1)
    # get the log file full path
    file_path = sys.argv[1]
    logging.debug('File path=', file_path)
    set_file_logger(file_path)
    parse_log_file(file_path)

    logging.error('\n%s\n', lsp_basic_info)

    for k,v in sorted(lsp_sess_list.items()):
        if not v.is_allow_relay:
            pass
            #continue
        logging.error('------begin--->>>>:')
        logging.error('%s:\n', v)
        for log in v.key_logs:
            logging.error('%s', log)
        logging.error('\n')
        for sock in v.socks:
            logging.error('socket details-->%s', sock)
            for log in sock.key_logs:
                logging.error('%s', log)
            logging.error('\n')

        logging.error('<<<---end------\n\n')

if __name__ == "__main__":
    logging.basicConfig(format='%(message)s', level=logging.INFO)
    #logger = logging.getLogger()
    main()
