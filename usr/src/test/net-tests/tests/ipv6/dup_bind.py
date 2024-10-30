#!@PYTHON@

#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2024 Bill Sommerfeld <sommerfeld@hamachi.org>
#

""" Set up multiple bound sockets and then send/connect to some of them.
Helps to test that link-local addresses are properly scoped """

import argparse
import fcntl
import struct
import socket
import sys
from threading import Thread
from typing import List, Optional, Tuple, Type, Union

SockAddr = Union[Tuple[str, int], Tuple[str, int, int, int]]

IP_BOUND_IF=0x41
IPV6_BOUND_IF=0x41

SIOCGLIFINDEX=0xc0786985
LIFREQSIZE=376
LIFNAMSIZ=32
LIFRU_OFFSET=40

def get_ifindex(arg: str) -> int:
    "Look up ifindex corresponding to a named interface"
    buf = bytearray(LIFREQSIZE)

    ifname = bytes(arg, encoding='ascii')
    if len(ifname) >= LIFNAMSIZ:
        raise ValueError('Interface name too long', arg)
    buf[0:len(ifname)] = ifname

    with socket.socket(family=socket.AF_INET6,
                       type=socket.SOCK_DGRAM,
                       proto=socket.IPPROTO_UDP) as s:
        fcntl.ioctl(s.fileno(), SIOCGLIFINDEX, buf)
        return struct.unpack_from('i', buffer=buf, offset=LIFRU_OFFSET)[0]

def fmt_addr(addr: SockAddr) -> str:
    "Produce a printable form of a socket address"
    (addrstr, portstr) = socket.getnameinfo(
        addr, socket.NI_NUMERICHOST|socket.NI_NUMERICSERV)
    return addrstr + ' port ' + portstr

class TestProto:
    """ Abstract(-ish) base class for test protocols """

    sockobj: socket.socket
    proto: int = -1
    type: int = -1
    thread: Thread
    ifindex: Optional[int]

    def __init__(self, name: str, family: int, addr: SockAddr) -> None:
        self.name = name
        self.family = family
        self.addr = addr
        self.ifindex = None

    def set_ifindex(self, ifindex: int) -> None:
        "Save an ifindex for later"
        self.ifindex = ifindex

    def bind_ifindex(self) -> None:
        "Apply saved ifindex (if any) to the socket"

        if self.ifindex is not None:
            print('bind to ifindex', self.ifindex)
            if self.family==socket.AF_INET6:
                self.sockobj.setsockopt(socket.IPPROTO_IPV6, IPV6_BOUND_IF, self.ifindex)
            else:
                self.sockobj.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, self.ifindex)

    def setup_listener(self) -> None:
        "Create a listening socket for the responder"
        self.sockobj = socket.socket(family=self.family, type=self.type, proto=self.proto)
        self.sockobj.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.bind_ifindex()
        self.sockobj.bind(self.addr)

    def start_responder(self) -> None:
        "Create socket and start a server thread"
        self.setup_listener()
        self.thread = Thread(target=self.server_thread, name=self.name, daemon=True)
        self.thread.start()

    def server_thread(self) -> None:
        "Placeholder server thread body"
        raise ValueError

    def run_initiator(self) -> None:
        "Placeholder test client"
        raise ValueError

class TestProtoTcp(TestProto):
    """ Simple test for TCP sockets """

    proto=socket.IPPROTO_TCP
    type=socket.SOCK_STREAM

    def setup_listener(self) -> None:
        super().setup_listener()
        self.sockobj.listen(5)

    def conn_thread(self, conn: socket.socket) -> None:
        "Secondary thread to handle an accepted connection"
        while True:
            buf = conn.recv(2048)
            if len(buf) == 0:
                conn.close()
                return
            conn.send(buf)

    def server_thread(self) -> None:
        while True:
            (conn, fromaddr) = self.sockobj.accept()
            print('accepted connection from', fmt_addr(fromaddr))

            t = Thread(target=self.conn_thread, name='connection', daemon=True, args=[conn])
            t.start()

    def run_initiator(self) -> None:

        self.sockobj = socket.socket(family=self.family, type=self.type, proto=self.proto)
        self.bind_ifindex()
        self.sockobj.settimeout(1.0)
        self.sockobj.connect(self.addr)


        msg=b'hello, world\n'
        self.sockobj.send(msg)
        buf = self.sockobj.recv(2048)
        if msg == buf:
            print (self.name, 'passed')
        else:
            raise ValueError('message mismatch', msg, buf)

class TestProtoUdp(TestProto):
    """ Simple test for UDP sockets """

    proto=socket.IPPROTO_UDP
    type=socket.SOCK_DGRAM

    def server_thread(self) -> None:
        while True:
            (buf, fromaddr) = self.sockobj.recvfrom(2048)
            print('server received', len(buf), 'bytes from',fmt_addr(fromaddr))
            self.sockobj.sendto(buf, fromaddr)

    def run_initiator(self) -> None:

        self.sockobj = socket.socket(family=self.family, type=self.type, proto=self.proto)
        self.bind_ifindex()
        self.sockobj.settimeout(0.1)
        self.sockobj.connect(self.addr)

        msg=b'hello, world from %s\n' % bytes(self.name, encoding='utf-8')
        self.sockobj.send(msg)
        (buf, fromaddr) = self.sockobj.recvfrom(2048)
        print('initiator received', len(buf), 'bytes from', fmt_addr(fromaddr))
        if msg == buf:
            print (self.name, 'passed')
        else:
            raise ValueError('message mismatch', msg, buf)

test_map = {
    'udp': TestProtoUdp,
    'tcp': TestProtoTcp,
}

family_map = {
    '4': socket.AF_INET,
    '6': socket.AF_INET6,
}

def get_addr(addr: str, port: int, family: int,
             proto: Type[TestProto]) -> Tuple[SockAddr, Optional[int]]:
    """Pull sockaddr,ifindex pair out of a command line argument;
    accept either 'addr' or 'ifname,addr' syntax."""
    ifindex = None

    if ',' in addr:
        (ifname, addr) = addr.split(',', maxsplit=1)
        ifindex = get_ifindex(ifname)

    sa = socket.getaddrinfo(addr, port, family=family, proto=proto.proto,
                            flags=socket.AI_NUMERICHOST|socket.AI_NUMERICSERV)

    return (sa[0][4], ifindex)

def main(argv: List[str]) -> int:
    "Multi-socket test.   Bind several sockets; connect to several specified addresses"

    parser = argparse.ArgumentParser(prog='dup-bind')

    parser.add_argument('--proto', choices=test_map.keys(), required=True)
    parser.add_argument('--family', choices=family_map.keys(), required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--addr', action='append')
    parser.add_argument('test', nargs='+')

    args = parser.parse_args(argv)

    endpoints = []

    family=family_map[args.family]
    test_proto=test_map[args.proto]

    try:
        for addrstr in args.addr:
            print('listen on', addrstr)
            (saddr, ifindex) = get_addr(addrstr, args.port, family, test_proto)

            test_addr = test_proto(name=addrstr, family=family, addr=saddr)
            if ifindex is not None:
                test_addr.set_ifindex(ifindex)
            test_addr.start_responder()
            endpoints.append(test_addr)

        for addr in args.test:
            print('test to', addr)
            (saddr, ifindex) = get_addr(addr, args.port, family, test_proto)

            test_addr = test_proto(name=addr, family=family, addr=saddr)
            if ifindex is not None:
                test_addr.set_ifindex(ifindex)
            test_addr.run_initiator()
    except ValueError as err:
        print('FAIL:', str(err))
        return 1
    except OSError as err:
        print('FAIL:', str(err))
        return 1
    except socket.timeout as err:
        print('FAIL:', str(err))
        return 1

    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
