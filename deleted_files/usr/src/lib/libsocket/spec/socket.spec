#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

# NOTE: Look at "versions" file for more details on why there may
# appear to be "gaps" in version number space.

function	endservent
include		<netdb.h>
declaration	int endservent(void)
version		SUNW_0.7
end

function	__xnet_bind
include		<sys/types.h>, <sys/socket.h>
declaration	int __xnet_bind(int socket, const struct sockaddr *address, \
			socklen_t address_len)
version		SUNW_1.1
errno		EACCES EADDRINUSE EADDRNOTAVAIL EBADF EINVAL ENOSR \
			ENOTSOCK EIO EISDIR ELOOP ENOENT ENOTDIR EROFS
exception	
end

function	__xnet_connect
include		<sys/types.h>, <sys/socket.h>
declaration	int __xnet_connect(int socket, const struct sockaddr *address, \
			socklen_t address_len)
version		SUNW_1.1
errno		EACCES EADDRINUSE EADDRNOTAVAIL EAFNOSUPPORT EALREADY EBADF \
			ECONNREFUSED EINPROGRESS EINTR EINVAL EIO EISCONN ELOOP \
			ENETUNREACH ENOENT ENOSR ENXIO ETIMEDOUT ENOTDIR \
			ENOTSOCK EPROTOTYPE
exception	$return == -1
end

function	__xnet_getsockopt
include		<sys/types.h>, <sys/socket.h>
declaration	int __xnet_getsockopt(int socket, int level, \
			int option_name, void *option_value, \
			Psocklen_t option_len)
version		SUNW_1.1
errno		EBADF ENOPROTOOPT ENOTSOCK EINVAL EOPNOTSUPP ENOBUFS ENOSR
exception	$return == -1
end

function	__xnet_listen
include		<sys/types.h>, <sys/socket.h>
declaration	int __xnet_listen(int socket, int backlog)
version		SUNW_1.1
errno		EBADF ENOTSOCK EOPNOTSUPP EINVAL EDESTADDRREQ ENOBUFS
exception	$return == -1
end

function	__xnet_sendto
include		<sys/types.h>, <sys/socket.h>
declaration	int __xnet_sendto(int socket, const void *message, \
			size_t length, int flags, \
			const struct sockaddr *dest_addr, size_t dest_len)
version		SUNW_1.1
errno		EAFNOSUPPORT EBADF ECONNRESET EINTR EMSGSIZE ENOTCONN \
			ENOTSOCK EOPNOTSUPP EPIPE EWOULDBLOCK EAGAIN EACCES \
			EIO ELOOP ENAMETOOLONG ENOENT ENOTDIR EDESTADDRREQ \
			EHOSTUNREACH EISCONN ENETDOWN ENETUNREACH ENOBUFS \
			ENOMEM ENOSR
exception	$return == -1
end

function	__xnet_socket
include		<sys/types.h>, <sys/socket.h>
declaration	int __xnet_socket(int domain, int type, int protocol)
version		SUNW_1.1
errno		EACCES EAFNOSUPPORT EMFILE ENFILE EPROTONOSUPPORT EPROTOTYPE \
			ENOBUFS ENOMEM ENOSR
exception	$return == -1
end

function	__xnet_socketpair
include		<sys/types.h>, <sys/socket.h>
declaration	int __xnet_socketpair(int domain, int type, int protocol, \
			int socket_vector[2])
version		SUNW_1.1
errno		EAFNOSUPPORT EMFILE ENFILE EOPNOTSUPP EPROTONOSUPPORT \
			EPROTOTYPE EACCES ENOMEM ENOBUFS ENOSR
exception	$return == -1
end

function	accept
include		<sys/types.h>, <sys/socket.h>
declaration	int accept(int s, struct sockaddr *addr, void *addrlen)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
errno		EBADF EINTR ENODEV ENOMEM ENOSR ENOTSOCK EOPNOTSUPP EPROTO \
			EWOULDBLOCK
exception	$return == -1
end

function	bind
include		<sys/types.h>, <sys/socket.h>
declaration	int bind(int s, const struct sockaddr *name, socklen_t namelen)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
errno		EACCES EADDRINUSE EADDRNOTAVAIL EBADF EINVAL ENOSR ENOTSOCK \
			EIO EISDIR ELOOP ENOENT ENOTDIR EROFS
exception	
end

function	bindresvport
version		SUNWprivate_1.1
end

function	connect
include		<sys/types.h>, <sys/socket.h>
declaration	int connect(int s, const struct sockaddr *name, \
			socklen_t namelen)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
errno		EACCES EADDRINUSE EADDRNOTAVAIL EAFNOSUPPORT EALREADY EBADF \
			ECONNREFUSED EINPROGRESS EINTR EINVAL EIO EISCONN \
			ELOOP ENETUNREACH ENOENT ENOSR ENXIO ETIMEDOUT \
			ENOTDIR ENOTSOCK EPROTOTYPE
exception	$return == -1
end

function	endnetent
include		<netdb.h>
declaration	int endnetent(void)
version		SUNW_0.7 
exception	$return == -1
end

function	endprotoent
include		<netdb.h>
declaration	int endprotoent(void)
version		SUNW_0.7
errno		ERANGE
end

function	ether_aton
include		<sys/types.h>
include		<sys/socket.h>
include		<net/if.h>
include		<netinet/in.h>
include		<netinet/if_ether.h>
declaration	struct ether_addr *ether_aton (const char *s)
version		SUNW_0.7
exception	
end

function	ether_hostton
include		<sys/types.h>
include		<sys/socket.h>
include		<net/if.h>
include		<netinet/in.h>
include		<netinet/if_ether.h>
declaration	int ether_hostton (const char *hostname, struct ether_addr *e)
version		SUNW_0.7
exception	
end

function	ether_line
include		<sys/types.h>
include		<sys/socket.h>
include		<net/if.h>
include		<netinet/in.h>
include		<netinet/if_ether.h>
declaration	int ether_line (const char *l, struct ether_addr *e, \
			char *hostname)
version		SUNW_0.7
exception	
end

function	ether_ntoa
include		<sys/types.h>
include		<sys/socket.h>
include		<net/if.h>
include		<netinet/in.h>
include		<netinet/if_ether.h>
declaration	char *ether_ntoa (const struct ether_addr *e)
version		SUNW_0.7
exception	
end

function	ether_ntohost
include		<sys/types.h>
include		<sys/socket.h>
include		<net/if.h>
include		<netinet/in.h>
include		<netinet/if_ether.h>
declaration	int ether_ntohost (char *hostname, const struct ether_addr *e)
version		SUNW_0.7
exception	
end

function	freeaddrinfo
include		<sys/socket.h>
include		<netdb.h>
declaration	void freeaddrinfo(struct addrinfo *ai)
version		SUNW_1.4
end

function	gai_strerror
include		<sys/socket.h>
include		<netdb.h>
declaration	const char *gai_strerror(int ecode)
version		SUNW_1.4
end

function	getaddrinfo
include		<sys/socket.h>
include		<netdb.h>
declaration	int getaddrinfo(const char *hostname, const char *servname, \
			const struct addrinfo *hints, struct addrinfo **res)
version		SUNW_1.4
exception	$return != 0
end

function	__xnet_getaddrinfo
include		<sys/socket.h>
include		<netdb.h>
declaration	int __xnet_getaddrinfo(const char *hostname, \
			const char *servname, const struct addrinfo *hints, \
			struct addrinfo **res)
version		SUNW_1.5
exception	$return != 0
end

function	getnameinfo
include		<sys/socket.h>
include		<netdb.h>
declaration	int getnameinfo(const struct sockaddr *sa, socklen_t salen, \
			char *host, socklen_t hostlen, char *serv, \
			socklen_t servlen, int flags)
version		SUNW_1.4
exception	$return != 0
end

function	getnetbyaddr
include		<netdb.h>
declaration	struct netent *getnetbyaddr(in_addr_t net, int type)
version		SUNW_0.7
exception	$return == 0
end

function	getnetbyaddr_r
include		<netdb.h>
declaration	struct netent *getnetbyaddr_r(long net, int type, \
			struct netent *result, char *buffer, int buflen)
version		SUNW_0.7
exception	$return == 0
end

function	getnetbyname
include		<netdb.h>
declaration	struct netent *getnetbyname(const char *name)
version		SUNW_0.7
exception	$return == 0
end

function	getnetbyname_r
include		<netdb.h>
declaration	struct netent *getnetbyname_r(const char *name, \
			struct netent *result, char *buffer, int buflen)
version		SUNW_0.7
exception	$return == 0
end

function	getnetent
include		<netdb.h>
declaration	struct netent *getnetent(void)
version		SUNW_0.7
exception	$return == 0
end

function	getnetent_r
include		<netdb.h>
declaration	struct netent *getnetent_r(struct netent *result, \
			char *buffer, int buflen)
version		SUNW_0.7
exception	$return == 0
end

function	getpeername
include		<sys/socket.h>
declaration	int getpeername(int s, struct sockaddr *name, \
			Psocklen_t namelen)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
errno		EBADF ENOMEM ENOSR ENOTCONN ENOTSOCK
exception	$return == -1
end

function	getprotobyname
include		<netdb.h>
declaration	struct protoent *getprotobyname(const char *name)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
errno		ERANGE
exception	$return == 0
end

function	getprotobyname_r
include		<netdb.h>
declaration	struct protoent *getprotobyname_r(const char *name, \
			struct protoent *result, char *buffer, int buflen)
version		SUNW_0.7
errno		ERANGE
exception	$return == 0
end

function	getprotobynumber
include		<netdb.h>
declaration	struct protoent *getprotobynumber(int proto)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
errno		ERANGE
exception	$return == 0
end

function	getprotobynumber_r
include		<netdb.h>
declaration	struct protoent *getprotobynumber_r(int proto, \
			struct protoent *result, char *buffer, int buflen)
version		SUNW_0.7
errno		ERANGE
exception	$return == 0
end

function	getprotoent
include		<netdb.h>
declaration	struct protoent *getprotoent(void)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
errno		ERANGE
exception	$return == 0
end

function	getprotoent_r
include		<netdb.h>
declaration	struct protoent *getprotoent_r(struct protoent *result, \
			char *buffer, int buflen)
version		SUNW_0.7
errno		ERANGE
exception	$return == 0
end

function	getservbyname
include		<netdb.h>
declaration	struct servent *getservbyname(const char *name, \
			const char *proto)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	getservbyname_r
include		<netdb.h>
declaration	struct servent *getservbyname_r(const char *name, \
			const char *proto, struct servent *result, \
			char *buffer, int buflen)
version		SUNW_0.7
exception	$return == 0
end

function	getservbyport
include		<netdb.h>
declaration	struct servent *getservbyport(int port, const char *proto)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	getservbyport_r
include		<netdb.h>
declaration	struct servent *getservbyport_r(int port, const char *proto, \
			struct servent *result, char *buffer, int buflen)
version		SUNW_0.7
exception	$return == 0
end

function	getservent
include		<netdb.h>
declaration	struct servent *getservent(void)
version		SUNW_0.7 
exception	$return == 0
end

function	getservent_r
include		<netdb.h>
declaration	struct servent *getservent_r(struct servent *result, \
			char *buffer, int buflen)
version		SUNW_0.7
exception	$return == 0
end

function	getsockname
include		<sys/types.h>
include		<sys/socket.h>
declaration	int getsockname(int s, struct sockaddr *name, void *namelen)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
errno		EBADF ENOMEM ENOSR ENOTSOCK
exception	$return == -1
end

function	getsockopt
include		<sys/types.h>
include		<sys/socket.h>
declaration	int getsockopt(int s, int level, int optname, void *optval, \
			void *optlen)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
errno		EBADF ENOMEM ENOPROTOOPT ENOSR ENOTSOCK
exception	$return == -1
end

function	getsourcefilter
include		<netinet/in.h>
declaration	int getsourcefilter(int s, uint32_t interface, \
			struct sockaddr *group, socklen_t grouplen, \
			uint32_t *fmode, uint_t *numsrc, \
			struct sockaddr_storage *slist)
version		SUNW_1.6
errno		EBADF ENOPROTOOPT ENOSR ENOTSOCK ENXIO EADDRNOTAVAIL
exception	$return == -1
end

function	getipv4sourcefilter
include		<netinet/in.h>
declaration	int getipv4sourcefilter(int s, struct in_addr interface, \
			struct in_addr group, uint32_t *fmode, \
			uint32_t *numsrc, struct in_addr *slist)
version		SUNW_1.6
errno		EBADF ENOPROTOOPT ENOSR ENOTSOCK ENXIO EADDRNOTAVAIL
exception	$return == -1
end

function	htonl
include		<sys/types.h>
include		<netinet/in.h>
include		<inttypes.h>
declaration	uint32_t htonl(uint32_t hostlong)
version		SUNW_0.7
end

function	htons
include		<sys/types.h>
include		<netinet/in.h>
include		<inttypes.h>
declaration	uint16_t htons(uint16_t hostshort)
version		SUNW_0.7
end

function	if_freenameindex
include		<net/if.h>
declaration	void if_freenameindex(struct if_nameindex *ptr)
version		SUNW_1.4
end

function	if_indextoname
include		<net/if.h>
declaration	char *if_indextoname(uint32_t ifindex, char *ifname)
version		SUNW_1.4
exception	$return == 0
end

function	if_nametoindex
include		<net/if.h>
declaration	uint32_t if_nametoindex(const char *ifname)
version		SUNW_1.4
exception	$return == 0
end

function	if_nameindex
include		<net/if.h>
declaration	struct if_nameindex *if_nameindex(void)
version		SUNW_1.4
exception	$return == 0
end

data		in6addr_any
declaration	const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT
version		SUNW_1.4	
end

data		in6addr_loopback
declaration	const struct in6_addr in6addr_loopback = IN6ADDR_LOOPBACK_INIT
version		SUNW_1.4
end

function	inet_lnaof
include		<sys/types.h>
include		<netinet/in.h>
declaration	in_addr_t inet_lnaof(struct in_addr in)
# see inet_lnaof	inet (3n)	- Internet address manipulation
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	inet_makeaddr
include		<sys/types.h>
include		<netinet/in.h>
declaration	struct in_addr inet_makeaddr(in_addr_t net, in_addr_t lna)
# see inet_makeaddr	inet (3n)	- Internet address manipulation
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	inet_network
include		<sys/types.h>
include		<netinet/in.h>
declaration	in_addr_t inet_network(const char *cp)
# see inet_network	inet (3n)	- Internet address manipulation
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	listen
include		<sys/types.h>
include		<sys/socket.h>
declaration	int listen(int socket, int backlog)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
errno		EBADF ENOTSOCK EOPNOTSUPP EINVAL EDESTADDRREQ ENOBUFS
exception	$return == -1
end

function	ntohl
include		<sys/types.h>
include		<netinet/in.h>
include		<inttypes.h>
declaration	uint32_t ntohl(uint32_t netlong)
version		SUNW_0.7
end

function	ntohs
include		<sys/types.h>
include		<netinet/in.h>
include		<inttypes.h>
declaration	uint16_t ntohs(uint16_t netshort)
version		SUNW_0.7
end

function	rcmd
include		<netdb.h>
declaration	int rcmd(char **ahost, unsigned short inport, \
			const char *luser, const char *ruser, const char *cmd, \
			int *fd2p)
version		SUNW_0.7
exception	$return == -1
end

function	rcmd_af
include		<netdb.h>
declaration	int rcmd_af(char **ahost, unsigned short inport, \
			const char *luser, const char *ruser, \
			const char *cmd, int *fd2p, int af)
version		SUNW_1.4
exception	$return == -1
end

function	recv
include		<sys/types.h>
include		<sys/socket.h>
include		<sys/uio.h>
declaration	ssize_t recv(int s, void *buf,	size_t len, int flags)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
errno		EBADF EINTR EIO ENOMEM ENOSR ENOTSOCK ESTALE EWOULDBLOCK
exception	$return == -1
end

function	recvfrom
include		<sys/types.h>
include		<sys/socket.h>
include		<sys/uio.h>
declaration	ssize_t recvfrom(int s, void *buf, size_t len, int flags, \
			struct sockaddr *from, void *fromlen)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
errno		EBADF EINTR EIO ENOMEM ENOSR ENOTSOCK ESTALE EWOULDBLOCK
exception	$return == -1
end

function	rexec
include		<netdb.h>
declaration	int rexec(char **ahost, unsigned short inport, \
			const char *user, const char *passwd, const char *cmd, \
			int *fd2p)
version		SUNW_0.7
exception	$return == -1
end

function	rexec_af
include		<netdb.h>
declaration	int rexec_af(char **ahost, unsigned short inport, \
			const char *user, const char *passwd, \
			const char *cmd, int *fd2p, int af)
version		SUNW_1.4
exception	$return == -1
end

function	rresvport
include		<netdb.h>
declaration	int rresvport(int *port)
version		SUNW_0.7
exception	$return == -1
end

function	rresvport_af
include		<netdb.h>
declaration	int rresvport_af(int *alport, int af)
version		SUNW_1.4
exception	$return == -1
end

function	rresvport_addr
include		<netdb.h>
declaration	int rresvport_addr(int *alport, struct sockaddr_storage *addr)
version		SUNWprivate_1.1
exception	$return == -1
end

function	ruserok
include		<netdb.h>
declaration	int ruserok(const char *rhost, int suser, const char *ruser, \
			const char *luser)
version		SUNW_0.7
exception	$return == -1
end

function	send
include		<sys/types.h>
include		<sys/socket.h>
declaration	ssize_t send(int s, const void *msg, size_t len, int flags)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
errno		EBADF EINTR EINVAL EMSGSIZE ENOMEM ENOSR ENOTSOCK EWOULDBLOCK
exception	$return == -1
end

function	sendto
include		<sys/types.h>
include		<sys/socket.h>
declaration	ssize_t sendto(int s, const void *msg, size_t len, int flags, \
			const struct sockaddr *to, socklen_t tolen)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
errno		EBADF EINTR EINVAL EMSGSIZE ENOMEM ENOSR ENOTSOCK EWOULDBLOCK
exception	$return == -1
end

function	setnetent
include		<netdb.h>
declaration	int setnetent(int stayopen)
version		SUNW_0.7
exception	$return == -1
end

function	setprotoent
include		<netdb.h>
declaration	int setprotoent(int stayopen)
version		SUNW_0.7
errno		ERANGE
end

function	setservent
include		<netdb.h>
declaration	int setservent(int stayopen)
version		SUNW_0.7
exception	$return == 0
end

function	setsockopt
include		<sys/types.h>
include		<sys/socket.h>
declaration	int setsockopt(int s, int level, int optname, \
			const void *optval, socklen_t optlen)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
errno		EBADF ENOMEM ENOPROTOOPT ENOSR ENOTSOCK
exception	$return == -1
end

function	setsourcefilter
include		<netinet/in.h>
declaration	int setsourcefilter(int s, uint32_t interface, \
			struct sockaddr *group, socklen_t grouplen, \
			uint32_t fmode, uint_t numsrc, \
			struct sockaddr_storage *slist)
version		SUNW_1.6
errno		EBADF ENOPROTOOPT ENOSR ENOTSOCK ENXIO ENOBUFS
exception	$return == -1
end

function	setipv4sourcefilter
include		<netinet/in.h>
declaration	int setipv4sourcefilter(int s, struct in_addr interface, \
			struct in_addr group, uint32_t fmode,
			uint32_t numsrc, struct in_addr *slist)
version		SUNW_1.6
errno		EBADF ENOPROTOOPT ENOSR ENOTSOCK ENXIO ENOBUFS
exception	$return == -1
end

function	shutdown
declaration	int shutdown(int s, int how)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
errno		EBADF ENOMEM ENOSR ENOTCONN ENOTSOCK
exception	$return == -1
end

function	sockatmark
declaration	int sockatmark(int socket)
version		SUNW_1.5
errno		EBADF ENOTTY
exception	$return == -1
end

function	socket
include		<sys/types.h>
include		<sys/socket.h>
declaration	int socket(int domain, int type, int protocol)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
errno		EACCES EMFILE ENOMEM ENOSR EPROTONOSUPPORT
exception	$return == -1
end

function	socketpair
include		<sys/types.h>
include		<sys/socket.h>
declaration	int socketpair(int domain, int type, int protocol, int sv[2])
version		SUNW_0.7
errno		EAFNOSUPPORT EMFILE ENOMEM ENOSR EOPNOTSUPP EPROTONOSUPPORT
exception	$return == -1
end

function	_link_ntoa
include		<net/if_dl.h>
declaration	char *_link_ntoa(const unsigned char *, char *, int, int)
version		SUNWprivate_1.3
exception	$return == 0
end

function	_link_aton
include		<net/if_dl.h>
declaration	unsigned char *_link_aton(const char *, int *)
version		SUNWprivate_1.3
exception	$return == 0
end

# IPv6 routing header manipulation
function	inet6_rth_add
include		<netinet/in.h>
declaration	int inet6_rth_add(void *bp, const struct in6_addr *addr)
version		SUNW_1.5
errno
exception	$return == -1
end

function	inet6_rth_init
include		<netinet/in.h>
declaration	void *inet6_rth_init(void *bp, socklen_t bp_len, int type, int segments)
version		SUNW_1.5
errno
exception	$return == 0
end

function	inet6_rth_getaddr
include		<netinet/in.h>
declaration	struct in6_addr *inet6_rth_getaddr(const void *bp, int index)
version		SUNW_1.5
errno
exception	$return == 0
end

function	inet6_rth_reverse
include		<netinet/in.h>
declaration	int inet6_rth_reverse(const void *in, void *out)
version		SUNW_1.5
errno
exception	$return == -1
end

function	inet6_rth_segments
include		<netinet/in.h>
declaration	int inet6_rth_segments(const void *bp)
version		SUNW_1.5
errno
exception	$return == -1
end

function	inet6_rth_space
include		<unistd.h>
declaration	socklen_t inet6_rth_space(int type, int segments)
version		SUNW_1.5
errno
exception	$return == 0
end

# IPv6 option header manipulation
function	inet6_opt_init
include		<netinet/in.h>, <sys/socket.h>
declaration	int inet6_opt_init(void *extbuf, socklen_t extlen)
version		SUNW_1.5
errno
exception	$return == -1
end

function	inet6_opt_append
include		<netinet/in.h>, <sys/socket.h>
declaration	int inet6_opt_append(void *extbuf, socklen_t extlen,\
			int offset, uint8_t type, socklen_t len, uint_t align,\
			void **databufp)
version		SUNW_1.5
errno
exception	$return == -1
end

function	inet6_opt_finish
include		<netinet/in.h>, <sys/socket.h>
declaration	int inet6_opt_finish(void *extbuf, socklen_t extlen,\
			int offset)
version		SUNW_1.5
errno
exception	$return == -1
end

function	inet6_opt_set_val
include		<netinet/in.h>, <sys/socket.h>
declaration	int inet6_opt_set_val(void *databuf, int offset, void *val,\
			socklen_t vallen)
version		SUNW_1.5
errno
exception	$return == -1
end

function	inet6_opt_next
include		<netinet/in.h>, <sys/socket.h>
declaration	int inet6_opt_next(void *extbuf, socklen_t extlen, int offset,\
			uint8_t *typep, socklen_t *lenp, void **databufp)
version		SUNW_1.5
errno
exception	$return == -1
end

function	inet6_opt_find
include		<netinet/in.h>, <sys/socket.h>
declaration	int inet6_opt_find(void *extbuf, socklen_t extlen, int offset,\
			uint8_t type, socklen_t *lenp, void **databufp)
version		SUNW_1.5
errno
exception	$return == -1
end

function	inet6_opt_get_val
include		<netinet/in.h>, <sys/socket.h>
declaration	int inet6_opt_get_val(void *databuf, int offset, void *val,\
			socklen_t vallen)
version		SUNW_1.5
errno
exception	$return == -1
end

# mh mailing system
function	_ruserpass
version		SUNWprivate_1.1
end

# BCP
function	_socket_bsd
version		SUNWprivate_1.1
end

# BCP
function	_socketpair_bsd
version		SUNWprivate_1.1
end

# rpc.bootparamd
function	bootparams_getbyname
version		SUNWprivate_1.1
end

# ifconfig
function	getnetmaskbyaddr
version		SUNWprivate_1.2
end

# in.dhcpd, dhcp admin
function	getnetmaskbynet
version		SUNWprivate_1.2
end
