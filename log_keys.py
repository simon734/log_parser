# keys for common info
LKEY_COMMON_PREFIX = b'\[(.*)\]\[(\d+)\]\[(\d)\]'
LKEY_COMMON_SOCKET = b'\Wsocket\s?=\s?(\d+)'
LKEY_COMMON_TOKEN = b'\Wtoken\s?=\s?(\d+)'
LKEY_COMMON_SESS_TYPE = b'type\s?=\s?(UDP|TCP)'

# keys for basic info
LKEY_BASIC_UIN = b'Basic info,uin=(\d+)'
LKEY_BASIC_LOG_LEVEL = b'log level:(\d+)'
LKEY_BASIC_NET_MODE = b'net_mode=(0x\d+),'

# keys for TCP/UDP
LKEY_SOCK_NEW_SOCK = b'WSPSocket.*\Wsocket=(\d+).*token=(\d+)'
LKEY_SOCK_CLOSE_SOCK = b'WSPCloseSocket.*ret=(-?\d+).*err=(-?\d+)'
LKEY_SOCK_NEGOTIATION = b'Negotiation'
LKEY_SOCK_COMM_STAT = b'ReportCommunicationStatistic.*guid_str=([\w|-]+).*proxy_ip=([\d|.]+).*proxy_port=(\d+).*proxy_idc=(\d+).*game_ip=([\d|.]+).*game_port=(\d+).*game_idc=(\d+)'
LKEY_SOCK_MAKE_DECISION = b'Ready to make decision.*socket=(\d+)'

# keys for TCP
LKEY_TCP_RELAY_INIT = b'RelayMgr::InternalInit, TCP init is (\w+)'
LKEY_TCP_CONNECT = b'[WSPConnect|WSPConnectEx].*ret=(-?\d+).*err=(-?\d+).*dest=(\d+\.\d+\.\d+\.\d+:\d+)'
LKEY_TCP_RELAY_ACCEPT = b'OnLocalServerAcceptable.*\Wsocket=(\d+).*token=(\d+)'
####LKEY_TCP_ACCEPT = b'WSPAccept.*err=(-?\d+).*recv_bytes=(\d+)'
LKEY_TCP_RECV = b'WSPRecv.*ret=(-?\d+).*err=(-?\d+)(.*)recv_bytes=(\d+)'
LKEY_TCP_SEND = b'WSPSend.*ret=(-?\d+).*err=(-?\d+)(.*)sent_bytes=(\d+)'
LKEY_TCP_IS_ALLOW_RELAY = b'IsAllowConnect.*result=(\w+)'
LKEY_TCP_IS_ALLOW_ACC = b'DecideRemoteAddr.*use_acc_=(\w+)'

# keys for UDP
LKEY_UDP_RELAY_INIT = b'RelayMgr::InternalInit, UDP init is (\w+)'
LKEY_UDP_RECV = b'WSPRecvFrom.*ret=(-?\d+).*err=(-?\d+).*from=(\d+\.\d+\.\d+\.\d+:\d+).*recv_bytes=(\d+)'
LKEY_UDP_SEND = b'WSPSendTo.*ret=(-?\d+).*err=(-?\d+).*dst=(\d+\.\d+\.\d+\.\d+:\d+).*sent_bytes=(\d+)'
LKEY_UDP_IS_ALLOW_RELAY = b'IsAllowUdpRelayed.*relay=(\w+)'
LKEY_UDP_IS_ALLOW_ACC = b'DecideAccl.*result=(\w+)'
