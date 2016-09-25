# keys for common info
LKEY_COMMON_PREFIX = b'\[(.*)\]\[(\d+)\]\[(\d)\]'
LKEY_COMMON_SOCKET = b'[, ]socket\s?=\s?(\d+)'
LKEY_COMMON_TOKEN = b'[, ]token\s?=\s?(\d+)'
LKEY_COMMON_SESS_TYPE = b'type\s?=\s?(UDP|TCP)'

# keys for basic info
LKEY_BASIC_UIN = b'Basic info,uin=(\d+)'
LKEY_BASIC_LOG_LEVEL = b'log level:(\d+)'
LKEY_BASIC_NET_MODE = b'net_mode=(0x\d+),'

# keys for TCP/UDP
LKEY_SOCK_CLOSE_SOCK = b'WSPCloseSocket.*ret=(-?\d+).*err=(-?\d+)'

# keys for TCP
LKEY_TCP_RELAY_INIT = b'RelayMgr::InternalInit, TCP init is (\w+)'
LKEY_TCP_CONNECT = b'[WSPConnect|WSPConnectEx].*ret=(-?\d+).*err=(-?\d+).*dest=(\d+\.\d+\.\d+\.\d+:\d+)'
LKEY_TCP_RELAY_ACCEPT = b'OnLocalServerAcceptable.*token=(\d+)'
#LKEY_TCP_ACCEPT = b'WSPAccept.*err=(-?\d+).*recv_bytes=(\d+)'
LKEY_TCP_RECV = b'WSPRecv.*ret=(-?\d+).*err=(-?\d+).*recv_bytes=(\d+)'
LKEY_TCP_SEND = b'WSPSend.*ret=(-?\d+).*err=(-?\d+).*sent_bytes=(\d+)'

# keys for UDP
LKEY_UDP_RELAY_INIT = b'RelayMgr::InternalInit, UDP init is (\w+)'
LKEY_UDP_RECV = b'WSPRecvFrom.*ret=(-?\d+).*err=(-?\d+).*recv_bytes=(\d+)'
LKEY_UDP_SEND = b'WSPSendTo.*ret=(-?\d+).*err=(-?\d+).*sent_bytes=(\d+)'
