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
#

file path=usr/share/man/man3xnet/accept.3xnet
file path=usr/share/man/man3xnet/bind.3xnet
file path=usr/share/man/man3xnet/connect.3xnet
file path=usr/share/man/man3xnet/endhostent.3xnet
file path=usr/share/man/man3xnet/endnetent.3xnet
file path=usr/share/man/man3xnet/endprotoent.3xnet
file path=usr/share/man/man3xnet/endservent.3xnet
file path=usr/share/man/man3xnet/freeaddrinfo.3xnet
file path=usr/share/man/man3xnet/gai_strerror.3xnet
file path=usr/share/man/man3xnet/gethostname.3xnet
file path=usr/share/man/man3xnet/getnameinfo.3xnet
file path=usr/share/man/man3xnet/getpeername.3xnet
file path=usr/share/man/man3xnet/getsockname.3xnet
file path=usr/share/man/man3xnet/getsockopt.3xnet
file path=usr/share/man/man3xnet/htonl.3xnet
file path=usr/share/man/man3xnet/if_nametoindex.3xnet
file path=usr/share/man/man3xnet/inet_addr.3xnet
file path=usr/share/man/man3xnet/inet_ntop.3xnet
file path=usr/share/man/man3xnet/listen.3xnet
file path=usr/share/man/man3xnet/recv.3xnet
file path=usr/share/man/man3xnet/recvfrom.3xnet
file path=usr/share/man/man3xnet/recvmsg.3xnet
file path=usr/share/man/man3xnet/send.3xnet
file path=usr/share/man/man3xnet/sendmsg.3xnet
file path=usr/share/man/man3xnet/sendto.3xnet
file path=usr/share/man/man3xnet/setsockopt.3xnet
file path=usr/share/man/man3xnet/shutdown.3xnet
file path=usr/share/man/man3xnet/sockatmark.3xnet
file path=usr/share/man/man3xnet/socket.3xnet
file path=usr/share/man/man3xnet/socketpair.3xnet
link path=usr/share/man/man3xnet/getaddrinfo.3xnet target=freeaddrinfo.3xnet
link path=usr/share/man/man3xnet/gethostbyaddr.3xnet target=endhostent.3xnet
link path=usr/share/man/man3xnet/gethostbyname.3xnet target=endhostent.3xnet
link path=usr/share/man/man3xnet/gethostent.3xnet target=endhostent.3xnet
link path=usr/share/man/man3xnet/getnetbyaddr.3xnet target=endnetent.3xnet
link path=usr/share/man/man3xnet/getnetbyname.3xnet target=endnetent.3xnet
link path=usr/share/man/man3xnet/getnetent.3xnet target=endnetent.3xnet
link path=usr/share/man/man3xnet/getprotobyname.3xnet target=endprotoent.3xnet
link path=usr/share/man/man3xnet/getprotobynumber.3xnet \
    target=endprotoent.3xnet
link path=usr/share/man/man3xnet/getprotoent.3xnet target=endprotoent.3xnet
link path=usr/share/man/man3xnet/getservbyname.3xnet target=endservent.3xnet
link path=usr/share/man/man3xnet/getservbyport.3xnet target=endservent.3xnet
link path=usr/share/man/man3xnet/getservent.3xnet target=endservent.3xnet
link path=usr/share/man/man3xnet/htons.3xnet target=htonl.3xnet
link path=usr/share/man/man3xnet/if_freenameindex.3xnet \
    target=if_nametoindex.3xnet
link path=usr/share/man/man3xnet/if_indextoname.3xnet \
    target=if_nametoindex.3xnet
link path=usr/share/man/man3xnet/if_nameindex.3xnet \
    target=if_nametoindex.3xnet
link path=usr/share/man/man3xnet/inet_lnaof.3xnet target=inet_addr.3xnet
link path=usr/share/man/man3xnet/inet_makeaddr.3xnet target=inet_addr.3xnet
link path=usr/share/man/man3xnet/inet_netof.3xnet target=inet_addr.3xnet
link path=usr/share/man/man3xnet/inet_network.3xnet target=inet_addr.3xnet
link path=usr/share/man/man3xnet/inet_ntoa.3xnet target=inet_addr.3xnet
link path=usr/share/man/man3xnet/inet_pton.3xnet target=inet_ntop.3xnet
link path=usr/share/man/man3xnet/ntohl.3xnet target=htonl.3xnet
link path=usr/share/man/man3xnet/ntohs.3xnet target=htonl.3xnet
link path=usr/share/man/man3xnet/sethostent.3xnet target=endhostent.3xnet
link path=usr/share/man/man3xnet/setnetent.3xnet target=endnetent.3xnet
link path=usr/share/man/man3xnet/setprotoent.3xnet target=endprotoent.3xnet
link path=usr/share/man/man3xnet/setservent.3xnet target=endservent.3xnet
