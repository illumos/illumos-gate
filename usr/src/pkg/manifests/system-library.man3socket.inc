#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#

#
# Copyright 2011, Richard Lowe
# Copyright 2012 Nexenta Systems, Inc. All rights reserved.
# Copyright 2013, OmniTI Computer Consulting, Inc.
#

file path=usr/share/man/man3socket/accept.3socket
file path=usr/share/man/man3socket/bind.3socket
file path=usr/share/man/man3socket/byteorder.3socket
file path=usr/share/man/man3socket/connect.3socket
file path=usr/share/man/man3socket/ethers.3socket
file path=usr/share/man/man3socket/getaddrinfo.3socket
file path=usr/share/man/man3socket/getifaddrs.3socket
file path=usr/share/man/man3socket/getipnodebyname.3socket
file path=usr/share/man/man3socket/getnetbyname.3socket
file path=usr/share/man/man3socket/getpeername.3socket
file path=usr/share/man/man3socket/getprotobyname.3socket
file path=usr/share/man/man3socket/getservbyname.3socket
file path=usr/share/man/man3socket/getsockname.3socket
file path=usr/share/man/man3socket/getsockopt.3socket
file path=usr/share/man/man3socket/getsourcefilter.3socket
file path=usr/share/man/man3socket/icmp6_filter.3socket
file path=usr/share/man/man3socket/if_nametoindex.3socket
file path=usr/share/man/man3socket/inet.3socket
file path=usr/share/man/man3socket/inet6_opt.3socket
file path=usr/share/man/man3socket/inet6_rth.3socket
file path=usr/share/man/man3socket/listen.3socket
file path=usr/share/man/man3socket/rcmd.3socket
file path=usr/share/man/man3socket/recv.3socket
file path=usr/share/man/man3socket/rexec.3socket
file path=usr/share/man/man3socket/sctp_bindx.3socket
file path=usr/share/man/man3socket/sctp_getladdrs.3socket
file path=usr/share/man/man3socket/sctp_getpaddrs.3socket
file path=usr/share/man/man3socket/sctp_opt_info.3socket
file path=usr/share/man/man3socket/sctp_peeloff.3socket
file path=usr/share/man/man3socket/sctp_recvmsg.3socket
file path=usr/share/man/man3socket/sctp_send.3socket
file path=usr/share/man/man3socket/sctp_sendmsg.3socket
file path=usr/share/man/man3socket/send.3socket
file path=usr/share/man/man3socket/shutdown.3socket
file path=usr/share/man/man3socket/socket.3socket
file path=usr/share/man/man3socket/socketpair.3socket
file path=usr/share/man/man3socket/spray.3socket
link path=usr/share/man/man3socket/accept4.3socket target=accept.3socket
link path=usr/share/man/man3socket/endnetent.3socket \
    target=getnetbyname.3socket
link path=usr/share/man/man3socket/endprotoent.3socket \
    target=getprotobyname.3socket
link path=usr/share/man/man3socket/endservent.3socket \
    target=getservbyname.3socket
link path=usr/share/man/man3socket/ether_aton.3socket target=ethers.3socket
link path=usr/share/man/man3socket/ether_hostton.3socket target=ethers.3socket
link path=usr/share/man/man3socket/ether_line.3socket target=ethers.3socket
link path=usr/share/man/man3socket/ether_ntoa.3socket target=ethers.3socket
link path=usr/share/man/man3socket/ether_ntohost.3socket target=ethers.3socket
link path=usr/share/man/man3socket/freeaddrinfo.3socket \
    target=getaddrinfo.3socket
link path=usr/share/man/man3socket/freehostent.3socket \
    target=getipnodebyname.3socket
link path=usr/share/man/man3socket/freeifaddrs.3socket \
    target=getifaddrs.3socket
link path=usr/share/man/man3socket/gai_strerror.3socket \
    target=getaddrinfo.3socket
link path=usr/share/man/man3socket/getipnodebyaddr.3socket \
    target=getipnodebyname.3socket
link path=usr/share/man/man3socket/getipv4sourcefilter.3socket \
    target=getsourcefilter.3socket
link path=usr/share/man/man3socket/getnameinfo.3socket \
    target=getaddrinfo.3socket
link path=usr/share/man/man3socket/getnetbyaddr.3socket \
    target=getnetbyname.3socket
link path=usr/share/man/man3socket/getnetbyaddr_r.3socket \
    target=getnetbyname.3socket
link path=usr/share/man/man3socket/getnetbyname_r.3socket \
    target=getnetbyname.3socket
link path=usr/share/man/man3socket/getnetent.3socket \
    target=getnetbyname.3socket
link path=usr/share/man/man3socket/getnetent_r.3socket \
    target=getnetbyname.3socket
link path=usr/share/man/man3socket/getprotobyname_r.3socket \
    target=getprotobyname.3socket
link path=usr/share/man/man3socket/getprotobynumber.3socket \
    target=getprotobyname.3socket
link path=usr/share/man/man3socket/getprotobynumber_r.3socket \
    target=getprotobyname.3socket
link path=usr/share/man/man3socket/getprotoent.3socket \
    target=getprotobyname.3socket
link path=usr/share/man/man3socket/getprotoent_r.3socket \
    target=getprotobyname.3socket
link path=usr/share/man/man3socket/getservbyname_r.3socket \
    target=getservbyname.3socket
link path=usr/share/man/man3socket/getservbyport.3socket \
    target=getservbyname.3socket
link path=usr/share/man/man3socket/getservbyport_r.3socket \
    target=getservbyname.3socket
link path=usr/share/man/man3socket/getservent.3socket \
    target=getservbyname.3socket
link path=usr/share/man/man3socket/getservent_r.3socket \
    target=getservbyname.3socket
link path=usr/share/man/man3socket/htonl.3socket target=byteorder.3socket
link path=usr/share/man/man3socket/htonll.3socket target=byteorder.3socket
link path=usr/share/man/man3socket/htons.3socket target=byteorder.3socket
link path=usr/share/man/man3socket/if_freenameindex.3socket \
    target=if_nametoindex.3socket
link path=usr/share/man/man3socket/if_indextoname.3socket \
    target=if_nametoindex.3socket
link path=usr/share/man/man3socket/if_nameindex.3socket \
    target=if_nametoindex.3socket
link path=usr/share/man/man3socket/inet6.3socket target=inet.3socket
link path=usr/share/man/man3socket/inet6_opt_append.3socket \
    target=inet6_opt.3socket
link path=usr/share/man/man3socket/inet6_opt_find.3socket \
    target=inet6_opt.3socket
link path=usr/share/man/man3socket/inet6_opt_finish.3socket \
    target=inet6_opt.3socket
link path=usr/share/man/man3socket/inet6_opt_get_val.3socket \
    target=inet6_opt.3socket
link path=usr/share/man/man3socket/inet6_opt_init.3socket \
    target=inet6_opt.3socket
link path=usr/share/man/man3socket/inet6_opt_next.3socket \
    target=inet6_opt.3socket
link path=usr/share/man/man3socket/inet6_opt_set_val.3socket \
    target=inet6_opt.3socket
link path=usr/share/man/man3socket/inet6_rth_add.3socket \
    target=inet6_rth.3socket
link path=usr/share/man/man3socket/inet6_rth_getaddr.3socket \
    target=inet6_rth.3socket
link path=usr/share/man/man3socket/inet6_rth_init.3socket \
    target=inet6_rth.3socket
link path=usr/share/man/man3socket/inet6_rth_reverse.3socket \
    target=inet6_rth.3socket
link path=usr/share/man/man3socket/inet6_rth_segments.3socket \
    target=inet6_rth.3socket
link path=usr/share/man/man3socket/inet6_rth_space.3socket \
    target=inet6_rth.3socket
link path=usr/share/man/man3socket/inet_addr.3socket target=inet.3socket
link path=usr/share/man/man3socket/inet_aton.3socket target=inet.3socket
link path=usr/share/man/man3socket/inet_lnaof.3socket target=inet.3socket
link path=usr/share/man/man3socket/inet_makeaddr.3socket target=inet.3socket
link path=usr/share/man/man3socket/inet_netof.3socket target=inet.3socket
link path=usr/share/man/man3socket/inet_network.3socket target=inet.3socket
link path=usr/share/man/man3socket/inet_ntoa.3socket target=inet.3socket
link path=usr/share/man/man3socket/inet_ntop.3socket target=inet.3socket
link path=usr/share/man/man3socket/inet_pton.3socket target=inet.3socket
link path=usr/share/man/man3socket/ntohl.3socket target=byteorder.3socket
link path=usr/share/man/man3socket/ntohll.3socket target=byteorder.3socket
link path=usr/share/man/man3socket/ntohs.3socket target=byteorder.3socket
link path=usr/share/man/man3socket/rcmd_af.3socket target=rcmd.3socket
link path=usr/share/man/man3socket/recvfrom.3socket target=recv.3socket
link path=usr/share/man/man3socket/recvmsg.3socket target=recv.3socket
link path=usr/share/man/man3socket/rexec_af.3socket target=rexec.3socket
link path=usr/share/man/man3socket/rresvport.3socket target=rcmd.3socket
link path=usr/share/man/man3socket/rresvport_af.3socket target=rcmd.3socket
link path=usr/share/man/man3socket/ruserok.3socket target=rcmd.3socket
link path=usr/share/man/man3socket/sctp_freeladdrs.3socket \
    target=sctp_getladdrs.3socket
link path=usr/share/man/man3socket/sctp_freepaddrs.3socket \
    target=sctp_getpaddrs.3socket
link path=usr/share/man/man3socket/sendmsg.3socket target=send.3socket
link path=usr/share/man/man3socket/sendto.3socket target=send.3socket
link path=usr/share/man/man3socket/setipv4sourcefilter.3socket \
    target=getsourcefilter.3socket
link path=usr/share/man/man3socket/setnetent.3socket \
    target=getnetbyname.3socket
link path=usr/share/man/man3socket/setprotoent.3socket \
    target=getprotobyname.3socket
link path=usr/share/man/man3socket/setservent.3socket \
    target=getservbyname.3socket
link path=usr/share/man/man3socket/setsockopt.3socket \
    target=getsockopt.3socket
link path=usr/share/man/man3socket/setsourcefilter.3socket \
    target=getsourcefilter.3socket
