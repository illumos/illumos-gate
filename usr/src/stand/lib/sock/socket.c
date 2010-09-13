/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * socket.c, Code implementing a simple socket interface.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include "socket_impl.h"
#include <sys/isa_defs.h>
#include <sys/sysmacros.h>
#include <sys/bootconf.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/uio.h>
#include <sys/salib.h>
#include "socket_inet.h"
#include "ipv4.h"
#include "ipv4_impl.h"
#include "udp_inet.h"
#include "tcp_inet.h"
#include "mac.h"
#include "mac_impl.h"
#include <sys/promif.h>

struct inetboot_socket	sockets[MAXSOCKET] = { 0 };

/* Default send and receive socket buffer size */
#define	SO_DEF_SNDBUF	48*1024
#define	SO_DEF_RCVBUF	48*1024

/* Default max socket buffer size */
#define	SO_MAX_BUF	4*1024*1024

static ssize_t dgram_sendto(int, const void *, size_t, int,
    const struct sockaddr *, int);
static ssize_t stream_sendto(int, const void *, size_t, int);
static int bind_check(int, const struct sockaddr *);
static int quickbind(int);

/* Check the validity of a fd and return the socket index of that fd. */
int
so_check_fd(int fd, int *errno)
{
	int i;

	i = FD_TO_SOCKET(fd);
	if (i < 0 || i >= MAXSOCKET) {
		*errno = ENOTSOCK;
		return (-1);
	}
	if (sockets[i].type == INETBOOT_UNUSED) {
		*errno = ENOTSOCK;
		return (-1);
	}
	return (i);
}

/*
 * Create an endpoint for network communication. Returns a descriptor.
 *
 * Notes:
 *	Only PF_INET communication domains are supported. Within
 * 	this domain, only SOCK_RAW, SOCK_DGRAM and SOCK_STREAM types are
 *	supported.
 */
int
socket(int domain, int type, int protocol)
{
	static int sock_initialized;
	int i;

	errno = 0;

	if (!sock_initialized) {
		for (i = 0; i < MAXSOCKET; i++)
			sockets[i].type = INETBOOT_UNUSED;
		sock_initialized = B_TRUE;
	}
	if (domain != AF_INET) {
		errno = EPROTONOSUPPORT;
		return (-1);
	}

	/* Find available socket */
	for (i = 0; i < MAXSOCKET; i++) {
		if (sockets[i].type == INETBOOT_UNUSED)
			break;
	}
	if (i >= MAXSOCKET) {
		errno = EMFILE;	/* No slots left. */
		return (-1);
	}

	/* Some socket initialization... */
	sockets[i].so_rcvbuf = SO_DEF_RCVBUF;
	sockets[i].so_sndbuf = SO_DEF_SNDBUF;

	/*
	 * Note that we ignore the protocol field for SOCK_DGRAM and
	 * SOCK_STREAM.  When we support different protocols in future,
	 * this needs to be changed.
	 */
	switch (type) {
	case SOCK_RAW:
		ipv4_raw_socket(&sockets[i], (uint8_t)protocol);
		break;
	case SOCK_DGRAM:
		udp_socket_init(&sockets[i]);
		break;
	case SOCK_STREAM:
		tcp_socket_init(&sockets[i]);
		break;
	default:
		errno = EPROTOTYPE;
		break;
	}

	if (errno != 0)
		return (-1);

	/* IPv4 generic initialization. */
	ipv4_socket_init(&sockets[i]);

	/* MAC generic initialization. */
	mac_socket_init(&sockets[i]);

	return (i + SOCKETTYPE);
}

int
getsockname(int s, struct sockaddr *name,  socklen_t *namelen)
{
	int i;

	errno = 0;
	if ((i = so_check_fd(s, &errno)) == -1)
		return (-1);

	if (*namelen < sizeof (struct sockaddr_in)) {
		errno = ENOMEM;
		return (-1);
	}

	/* Structure assignment... */
	*((struct sockaddr_in *)name) = sockets[i].bind;
	*namelen = sizeof (struct sockaddr_in);
	return (0);
}

/*
 * The socket options we support are:
 * SO_RCVTIMEO	-	Value is in msecs, and is of uint32_t.
 * SO_DONTROUTE	-	Value is an int, and is a boolean (nonzero if set).
 * SO_REUSEADDR -	Value is an int boolean.
 * SO_RCVBUF -		Value is an int.
 * SO_SNDBUF -		Value is an int.
 */
int
getsockopt(int s, int level, int option, void *optval, socklen_t *optlen)
{
	int i;

	errno = 0;
	if ((i = so_check_fd(s, &errno)) == -1)
		return (-1);

	switch (level) {
	case SOL_SOCKET: {
		switch (option) {
		case SO_RCVTIMEO:
			if (*optlen == sizeof (uint32_t)) {
				*(uint32_t *)optval = sockets[i].in_timeout;
			} else {
				*optlen = 0;
				errno = EINVAL;
			}
			break;
		case SO_DONTROUTE:
			if (*optlen == sizeof (int)) {
				*(int *)optval =
				    (sockets[i].out_flags & SO_DONTROUTE);
			} else {
				*optlen = 0;
				errno = EINVAL;
			}
			break;
		case SO_REUSEADDR:
			if (*optlen == sizeof (int)) {
				*(int *)optval =
				    (sockets[i].so_opt & SO_REUSEADDR);
			} else {
				*optlen = 0;
				errno = EINVAL;
			}
			break;
		case SO_RCVBUF:
			if (*optlen == sizeof (int)) {
				*(int *)optval = sockets[i].so_rcvbuf;
			} else {
				*optlen = 0;
				errno = EINVAL;
			}
			break;
		case SO_SNDBUF:
			if (*optlen == sizeof (int)) {
				*(int *)optval = sockets[i].so_sndbuf;
			} else {
				*optlen = 0;
				errno = EINVAL;
			}
			break;
		case SO_LINGER:
			if (*optlen == sizeof (struct linger)) {
				/* struct copy */
				*(struct linger *)optval = sockets[i].so_linger;
			} else {
				*optlen = 0;
				errno = EINVAL;
			}
		default:
			errno = ENOPROTOOPT;
			break;
		}
		break;
	} /* case SOL_SOCKET */
	case IPPROTO_TCP:
	case IPPROTO_IP: {
		switch (option) {
		default:
			*optlen = 0;
			errno = ENOPROTOOPT;
			break;
		}
		break;
	} /* case IPPROTO_IP or IPPROTO_TCP */
	default:
		errno = ENOPROTOOPT;
		break;
	} /* switch (level) */

	if (errno != 0)
		return (-1);
	else
		return (0);
}

/*
 * Generate a network-order source port from the privileged range if
 * "reserved" is true, dynamic/private range otherwise. We consider the
 * range of 512-1023 privileged ports as ports we can use. This mirrors
 * historical rpc client practice for privileged port selection.
 */
in_port_t
get_source_port(boolean_t reserved)
{
	static in_port_t	dynamic = IPPORT_DYNAMIC_START - 1,
	    rsvdport = (IPPORT_RESERVED / 2) - 1;
	in_port_t		p;

	if (reserved) {
		if (++rsvdport >= IPPORT_RESERVED)
			p = rsvdport = IPPORT_RESERVED / 2;
		else
			p = rsvdport;
	} else
		p = ++dynamic;

	return (htons(p));
}

/*
 * The socket options we support are:
 * SO_RECVTIMEO	-	Value is uint32_t msecs.
 * SO_DONTROUTE	-	Value is int boolean (nonzero == TRUE, zero == FALSE).
 * SO_REUSEADDR -	value is int boolean.
 * SO_RCVBUF -		Value is int.
 * SO_SNDBUF -		Value is int.
 */
int
setsockopt(int s, int level, int option, const void *optval, socklen_t optlen)
{
	int i;

	errno = 0;
	if ((i = so_check_fd(s, &errno)) == -1)
		return (-1);

	switch (level) {
	case SOL_SOCKET: {
		switch (option) {
		case SO_RCVTIMEO:
			if (optlen == sizeof (uint32_t))
				sockets[i].in_timeout = *(uint32_t *)optval;
			else {
				errno = EINVAL;
			}
			break;
		case SO_DONTROUTE:
			if (optlen == sizeof (int)) {
				if (*(int *)optval)
					sockets[i].out_flags |= SO_DONTROUTE;
				else
					sockets[i].out_flags &= ~SO_DONTROUTE;
			} else {
				errno = EINVAL;
			}
			break;
		case SO_REUSEADDR:
			if (optlen == sizeof (int)) {
				if (*(int *)optval)
					sockets[i].so_opt |= SO_REUSEADDR;
				else
					sockets[i].so_opt &= ~SO_REUSEADDR;
			} else {
				errno = EINVAL;
			}
			break;
		case SO_RCVBUF:
			if (optlen == sizeof (int)) {
				sockets[i].so_rcvbuf = *(int *)optval;
				if (sockets[i].so_rcvbuf > SO_MAX_BUF)
					sockets[i].so_rcvbuf = SO_MAX_BUF;
				(void) tcp_opt_set(sockets[i].pcb,
				    level, option, optval, optlen);
			} else {
				errno = EINVAL;
			}
			break;
		case SO_SNDBUF:
			if (optlen == sizeof (int)) {
				sockets[i].so_sndbuf = *(int *)optval;
				if (sockets[i].so_sndbuf > SO_MAX_BUF)
					sockets[i].so_sndbuf = SO_MAX_BUF;
				(void) tcp_opt_set(sockets[i].pcb,
				    level, option, optval, optlen);
			} else {
				errno = EINVAL;
			}
			break;
		case SO_LINGER:
			if (optlen == sizeof (struct linger)) {
				/* struct copy */
				sockets[i].so_linger = *(struct linger *)optval;
				(void) tcp_opt_set(sockets[i].pcb,
				    level, option, optval, optlen);
			} else {
				errno = EINVAL;
			}
			break;
		default:
			errno = ENOPROTOOPT;
			break;
		}
		break;
	} /* case SOL_SOCKET */
	case IPPROTO_TCP:
	case IPPROTO_IP: {
		switch (option) {
		default:
			errno = ENOPROTOOPT;
			break;
		}
		break;
	} /* case IPPROTO_IP  or IPPROTO_TCP */
	default:
		errno = ENOPROTOOPT;
		break;
	} /* switch (level) */

	if (errno != 0)
		return (-1);
	else
		return (0);
}

/*
 * Shut down part of a full-duplex connection.
 *
 * Only supported for TCP sockets
 */
int
shutdown(int s, int how)
{
	int sock_id;
	int i;

	errno = 0;
	if ((sock_id = so_check_fd(s, &errno)) == -1)
		return (-1);

	/* shutdown only supported for TCP sockets */
	if (sockets[sock_id].type != INETBOOT_STREAM) {
		errno = EOPNOTSUPP;
		return (-1);
	}

	if (!(sockets[sock_id].so_state & SS_ISCONNECTED)) {
		errno = ENOTCONN;
		return (-1);
	}

	switch (how) {
	case 0:
		sockets[sock_id].so_state |= SS_CANTRCVMORE;
		break;
	case 1:
		sockets[sock_id].so_state |= SS_CANTSENDMORE;
		break;
	case 2:
		sockets[sock_id].so_state |= (SS_CANTRCVMORE | SS_CANTSENDMORE);
		break;
	default:
		errno = EINVAL;
		return (-1);
	}

	switch (sockets[sock_id].so_state &
	    (SS_CANTRCVMORE | SS_CANTSENDMORE)) {
	case (SS_CANTRCVMORE | SS_CANTSENDMORE):
		/* Call lower level protocol close routine. */
		for (i = TRANSPORT_LVL; i >= MEDIA_LVL; i--) {
			if (sockets[sock_id].close[i] != NULL) {
				(void) sockets[sock_id].close[i](sock_id);
			}
		}
		nuke_grams(&sockets[sock_id].inq);
		break;
	case SS_CANTRCVMORE:
		nuke_grams(&sockets[sock_id].inq);
		break;
	case SS_CANTSENDMORE:
		/* Call lower level protocol close routine. */
		if (tcp_shutdown(sock_id) < 0)
			return (-1);
		break;
	default:
		errno = EINVAL;
		return (-1);
	}

	return (0);
}

/*
 * "close" a socket.
 */
int
socket_close(int s)
{
	int sock_id, i;

	errno = 0;
	if ((sock_id = so_check_fd(s, &errno)) == -1)
		return (-1);

	/* Call lower level protocol close routine. */
	for (i = TRANSPORT_LVL; i >= MEDIA_LVL; i--) {
		if (sockets[sock_id].close[i] != NULL) {
			/*
			 * Note that the close() routine of other
			 * layers can return an error.  But right
			 * now, the only mechanism to report that
			 * back is for the close() routine to set
			 * the errno and socket_close() will return
			 * an error.  But the close operation will
			 * not be stopped.
			 */
			(void) sockets[sock_id].close[i](sock_id);
		}
	}

	/*
	 * Clear the input queue.  This has to be done
	 * after the lower level protocol close routines have been
	 * called as they may want to do something about the queue.
	 */
	nuke_grams(&sockets[sock_id].inq);

	bzero((caddr_t)&sockets[sock_id], sizeof (struct inetboot_socket));
	sockets[sock_id].type = INETBOOT_UNUSED;

	return (0);
}

/*
 * Read up to `nbyte' of data from socket `s' into `buf'; if non-zero,
 * then give up after `read_timeout' seconds.  Returns the number of
 * bytes read, or -1 on failure.
 */
int
socket_read(int s, void *buf, size_t nbyte, int read_timeout)
{
	ssize_t	n;
	uint_t	start, diff;

	/*
	 * keep calling non-blocking recvfrom until something received
	 * or an error occurs
	 */
	start = prom_gettime();
	for (;;) {
		n = recvfrom(s, buf, nbyte, MSG_DONTWAIT, NULL, NULL);
		if (n == -1 && errno == EWOULDBLOCK) {
			diff = (uint_t)((prom_gettime() - start) + 500) / 1000;
			if (read_timeout != 0 && diff > read_timeout) {
				errno = EINTR;
				return (-1);
			}
		} else {
			return (n);
		}
	}
}

/*
 * Write up to `nbyte' bytes of data from `buf' to the address pointed to
 * `addr' using socket `s'.  Returns the number of bytes writte on success,
 * or -1 on failure.
 */
int
socket_write(int s, const void *buf, size_t nbyte, struct sockaddr_in *addr)
{
	return (sendto(s, buf, nbyte, 0, (struct sockaddr *)addr,
	    sizeof (*addr)));
}

static int
bind_check(int sock_id, const struct sockaddr *addr)
{
	int k;
	struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;

	/* Do not check for duplicate bind() if SO_REUSEADDR option is set. */
	if (! (sockets[sock_id].so_opt & SO_REUSEADDR)) {
		for (k = 0; k < MAXSOCKET; k++) {
			if (sockets[k].type != INETBOOT_UNUSED &&
			    sockets[k].proto == sockets[sock_id].proto &&
			    sockets[k].bound) {
				if ((sockets[k].bind.sin_addr.s_addr ==
				    in_addr->sin_addr.s_addr) &&
				    (sockets[k].bind.sin_port ==
				    in_addr->sin_port)) {
					errno = EADDRINUSE;
					return (-1);
				}
			}
		}
	}
	return (0);
}

/* Assign a name to an unnamed socket. */
int
bind(int s, const struct sockaddr *name, socklen_t namelen)
{
	int i;

	errno = 0;

	if ((i = so_check_fd(s, &errno)) == -1)
		return (-1);

	if (name == NULL) {
		/* unbind */
		if (sockets[i].bound) {
			bzero((caddr_t)&sockets[i].bind,
			    sizeof (struct sockaddr_in));
			sockets[i].bound = B_FALSE;
		}
		return (0);
	}
	if (namelen != sizeof (struct sockaddr_in) || name == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (name->sa_family != AF_INET) {
		errno = EAFNOSUPPORT;
		return (-1);
	}
	if (sockets[i].bound) {
		if (bcmp((caddr_t)&sockets[i].bind, (caddr_t)name,
		    namelen) == 0) {
			/* attempt to bind to same address ok... */
			return (0);
		}
		errno = EINVAL;	/* already bound */
		return (-1);
	}

	if (errno != 0) {
		return (-1);
	}

	/* Check for duplicate bind(). */
	if (bind_check(i, name) < 0)
		return (-1);

	bcopy((caddr_t)name, (caddr_t)&sockets[i].bind, namelen);
	if (sockets[i].type == INETBOOT_STREAM) {
		if (tcp_bind(i) < 0) {
			return (-1);
		}
	}
	sockets[i].bound = B_TRUE;

	return (0);
}

static int
quickbind(int sock_id)
{
	int i;
	struct sockaddr_in addr;

	/*
	 * XXX This needs more work.  Right now, if ipv4_setipaddr()
	 * have not been called, this will be wrong.  But we need
	 * something better.  Need to be revisited.
	 */
	ipv4_getipaddr(&addr.sin_addr);
	addr.sin_family = AF_INET;

	for (i = SMALLEST_ANON_PORT; i <= LARGEST_ANON_PORT; i++) {
		addr.sin_port = htons(i);
		if (bind_check(sock_id, (struct sockaddr *)&addr) == 0)
			break;
	}
	/* Need to clear errno as it is probably set by bind_check(). */
	errno = 0;

	if (i <= LARGEST_ANON_PORT) {
		bcopy((caddr_t)&addr, (caddr_t)&sockets[sock_id].bind,
		    sizeof (struct sockaddr_in));
		sockets[sock_id].bound = B_TRUE;
#ifdef DEBUG
		printf("quick bind done addr %s port %d\n",
		    inet_ntoa(sockets[sock_id].bind.sin_addr),
		    ntohs(sockets[sock_id].bind.sin_port));
#endif
		return (0);
	} else {
		return (-1);
	}
}

int
listen(int fd, int backlog)
{
	int sock_id;

	errno = 0;
	if ((sock_id = so_check_fd(fd, &errno)) == -1)
		return (-1);

	if (sockets[sock_id].type != INETBOOT_STREAM) {
		errno = EOPNOTSUPP;
		return (-1);
	}
	if (sockets[sock_id].so_error != 0) {
		errno = sockets[sock_id].so_error;
		return (-1);
	}
	return (tcp_listen(sock_id, backlog));
}

int
accept(int fd, struct sockaddr *addr,  socklen_t *addr_len)
{
	int sock_id;
	int new_sd;

	errno = 0;
	if ((sock_id = so_check_fd(fd, &errno)) == -1)
		return (-1);

	if (sockets[sock_id].type != INETBOOT_STREAM) {
		errno = EOPNOTSUPP;
		return (-1);
	}
	if (sockets[sock_id].so_error != 0) {
		errno = sockets[sock_id].so_error;
		return (-1);
	}
	if ((new_sd = tcp_accept(sock_id, addr, addr_len)) == -1)
		return (-1);
	sock_id = so_check_fd(new_sd, &errno);
	sockets[sock_id].so_state |= SS_ISCONNECTED;
	return (new_sd);
}

int
connect(int fd, const  struct sockaddr *addr, socklen_t addr_len)
{
	int sock_id;
	int so_type;

	errno = 0;
	if ((sock_id = so_check_fd(fd, &errno)) == -1)
		return (-1);

	so_type = sockets[sock_id].type;

	if (addr == NULL || addr_len == 0) {
		errno = EINVAL;
		return (-1);
	}
	/* Don't allow connect for raw socket. */
	if (so_type == INETBOOT_RAW) {
		errno = EPROTONOSUPPORT;
		return (-1);
	}

	if (sockets[sock_id].so_state & SS_ISCONNECTED) {
		errno = EINVAL;
		return (-1);
	}

	if (sockets[sock_id].so_error != 0) {
		errno = sockets[sock_id].so_error;
		return (-1);
	}

	/* If the socket is not bound, we need to do a quick bind. */
	if (!sockets[sock_id].bound) {
		/* For TCP socket, just call tcp_bind(). */
		if (so_type == INETBOOT_STREAM) {
			if (tcp_bind(sock_id) < 0)
				return (-1);
		} else {
			if (quickbind(sock_id) < 0) {
				errno = EADDRNOTAVAIL;
				return (-1);
			}
		}
	}
	/* Should do some sanity check for addr .... */
	bcopy((caddr_t)addr, &sockets[sock_id].remote,
	    sizeof (struct sockaddr_in));

	if (sockets[sock_id].type == INETBOOT_STREAM) {
		/* Call TCP connect routine. */
		if (tcp_connect(sock_id) == 0)
			sockets[sock_id].so_state |= SS_ISCONNECTED;
		else {
			if (sockets[sock_id].so_error != 0)
				errno = sockets[sock_id].so_error;
			return (-1);
		}
	} else {
		sockets[sock_id].so_state |= SS_ISCONNECTED;
	}
	return (0);
}

/* Just a wrapper around recvfrom(). */
ssize_t
recv(int s, void *buf, size_t len, int flags)
{
	return (recvfrom(s, buf, len, flags, NULL, NULL));
}

/*
 * Receive messages from a connectionless socket. Legal flags are 0 and
 * MSG_DONTWAIT. MSG_WAITALL is not currently supported.
 *
 * Returns length of message for success, -1 if error occurred.
 */
ssize_t
recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from,
    socklen_t *fromlen)
{
	int			sock_id, i;
	ssize_t			datalen, bytes = 0;
	struct inetgram		*icp;
	enum SockType		so_type;
	char			*tmp_buf;
	mblk_t			*mp;

	errno = 0;

	if ((sock_id = so_check_fd(s, &errno)) == -1) {
		errno = EINVAL;
		return (-1);
	}

	if (sockets[sock_id].type == INETBOOT_STREAM &&
	    !(sockets[sock_id].so_state & SS_ISCONNECTED)) {
		errno = ENOTCONN;
		return (-1);
	}

	if (buf == NULL || len == 0) {
		errno = EINVAL;
		return (-1);
	}
	/* Yup - MSG_WAITALL not implemented */
	if ((flags & ~MSG_DONTWAIT) != 0) {
		errno = EINVAL;
		return (-1);
	}

retry:
	if (sockets[sock_id].inq == NULL) {
		/* Go out and check the wire */
		for (i = MEDIA_LVL; i < APP_LVL; i++) {
			if (sockets[sock_id].input[i] != NULL) {
				if (sockets[sock_id].input[i](sock_id) < 0) {
					if (sockets[sock_id].so_error != 0) {
						errno =
						    sockets[sock_id].so_error;
					}
					return (-1);
				}
			}
		}
	}

	so_type = sockets[sock_id].type;

	/* Remove unknown inetgrams from the head of inq.  Can this happen? */
	while ((icp = sockets[sock_id].inq) != NULL) {
		if ((so_type == INETBOOT_DGRAM ||
		    so_type == INETBOOT_STREAM) &&
		    icp->igm_level != APP_LVL) {
#ifdef	DEBUG
			printf("recvfrom: unexpected level %d frame found\n",
			    icp->igm_level);
#endif	/* DEBUG */
			del_gram(&sockets[sock_id].inq, icp, B_TRUE);
			continue;
		} else {
			break;
		}
	}


	if (icp == NULL) {
		/*
		 * Checking for error should be done everytime a lower layer
		 * input routing is called.  For example, if TCP gets a RST,
		 * this should be reported asap.
		 */
		if (sockets[sock_id].so_state & SS_CANTRCVMORE) {
			if (sockets[sock_id].so_error != 0) {
				errno = sockets[sock_id].so_error;
				return (-1);
			} else {
				return (0);
			}
		}

		if ((flags & MSG_DONTWAIT) == 0)
			goto retry;	/* wait forever */

		/* no data */
		errno = EWOULDBLOCK;
		return (-1);
	}

	if (from != NULL && fromlen != NULL) {
		switch (so_type) {
		case INETBOOT_STREAM:
			/* Need to copy from the socket's remote address. */
			bcopy(&(sockets[sock_id].remote), from, MIN(*fromlen,
			    sizeof (struct sockaddr_in)));
			break;
		case INETBOOT_RAW:
		case INETBOOT_DGRAM:
		default:
			if (*fromlen > sizeof (icp->igm_saddr))
				*fromlen = sizeof (icp->igm_saddr);
			bcopy((caddr_t)&(icp->igm_saddr), (caddr_t)from,
			    MIN(*fromlen, sizeof (struct sockaddr_in)));
			break;
		}
	}

	mp = icp->igm_mp;
	switch (so_type) {
	case INETBOOT_STREAM:
		/*
		 * If the message has igm_id == TCP_CALLB_MAGIC_ID, we need
		 * to drain the data held by tcp and try again.
		 */
		if (icp->igm_id == TCP_CALLB_MAGIC_ID) {
			del_gram(&sockets[sock_id].inq, icp, B_TRUE);
			tcp_rcv_drain_sock(sock_id);
			goto retry;
		}

		/* TCP should put only user data in the inetgram. */
		tmp_buf = (char *)buf;
		while (len > 0 && icp != NULL) {
			datalen = mp->b_wptr - mp->b_rptr;
			if (len < datalen) {
				bcopy(mp->b_rptr, tmp_buf, len);
				bytes += len;
				mp->b_rptr += len;
				break;
			} else {
				bcopy(mp->b_rptr, tmp_buf, datalen);
				len -= datalen;
				bytes += datalen;
				tmp_buf += datalen;
				del_gram(&sockets[sock_id].inq, icp, B_TRUE);

				/*
				 * If we have any embedded magic messages just
				 * drop them.
				 */
				while ((icp = sockets[sock_id].inq) != NULL) {
					if (icp->igm_id != TCP_CALLB_MAGIC_ID)
						break;
					del_gram(&sockets[sock_id].inq, icp,
					    B_TRUE);
				}

				if (icp == NULL)
					break;
				mp = icp->igm_mp;
			}
		}
		sockets[sock_id].so_rcvbuf += (int32_t)bytes;
		break;
	case INETBOOT_DGRAM:
		datalen = mp->b_wptr - mp->b_rptr;
		if (len < datalen)
			bytes = len;
		else
			bytes = datalen;
		bcopy(mp->b_rptr, buf, bytes);
		del_gram(&sockets[sock_id].inq, icp, B_TRUE);
		break;
	case INETBOOT_RAW:
	default:
		datalen = mp->b_wptr - mp->b_rptr;
		if (len < datalen)
			bytes = len;
		else
			bytes = datalen;
		bcopy(mp->b_rptr, buf, bytes);
		del_gram(&sockets[sock_id].inq, icp, B_TRUE);
		break;
	}

#ifdef	DEBUG
	printf("recvfrom(%d): data: (0x%x,%d)\n", sock_id,
	    (icp != NULL) ? icp->igm_mp : 0, bytes);
#endif	/* DEBUG */
	return (bytes);
}


/* Just a wrapper around sendto(). */
ssize_t
send(int s, const void *msg, size_t len, int flags)
{
	return (sendto(s, msg, len, flags, NULL, 0));
}

/*
 * Transmit a message through a socket.
 *
 * Supported flags: MSG_DONTROUTE or 0.
 */
ssize_t
sendto(int s, const void *msg, size_t len, int flags, const struct sockaddr *to,
    socklen_t tolen)
{
	enum SockType so_type;
	int sock_id;
	ssize_t bytes;

	errno = 0;

	if ((sock_id = so_check_fd(s, &errno)) == -1) {
		return (-1);
	}
	if (msg == NULL) {
		errno = EINVAL;
		return (-1);
	}
	so_type = sockets[sock_id].type;
	if ((flags & ~MSG_DONTROUTE) != 0) {
		errno = EINVAL;
		return (-1);
	}
	if (sockets[sock_id].so_error != 0) {
		errno = sockets[sock_id].so_error;
		return (-1);
	}
	if (to != NULL && to->sa_family != AF_INET) {
		errno = EAFNOSUPPORT;
		return (-1);
	}

	switch (so_type) {
	case INETBOOT_RAW:
	case INETBOOT_DGRAM:
		if (!(sockets[sock_id].so_state & SS_ISCONNECTED) &&
		    (to == NULL || tolen != sizeof (struct sockaddr_in))) {
			errno = EINVAL;
			return (-1);
		}
		bytes = dgram_sendto(sock_id, msg, len, flags, to, tolen);
		break;
	case INETBOOT_STREAM:
		if (!((sockets[sock_id].so_state & SS_ISCONNECTED) ||
		    (sockets[sock_id].so_state & SS_ISCONNECTING))) {
			errno = EINVAL;
			return (-1);
		}
		if (sockets[sock_id].so_state & SS_CANTSENDMORE) {
			errno = EPIPE;
			return (-1);
		}
		bytes = stream_sendto(sock_id, msg, len, flags);
		break;
	default:
		/* Should not happen... */
		errno = EPROTOTYPE;
		return (-1);
	}
	return (bytes);
}

static ssize_t
dgram_sendto(int i, const void *msg, size_t len, int flags,
    const struct sockaddr *to, int tolen)
{
	struct inetgram		oc;
	int			l, offset;
	size_t			tlen;
	mblk_t			*mp;

#ifdef	DEBUG
	{
	struct sockaddr_in *sin = (struct sockaddr_in *)to;
	printf("sendto(%d): msg of length: %d sent to port %d and host: %s\n",
	    i, len, ntohs(sin->sin_port), inet_ntoa(sin->sin_addr));
	}
#endif	/* DEBUG */

	nuke_grams(&sockets[i].inq); /* flush the input queue */

	/* calculate offset for data */
	offset = sockets[i].headerlen[MEDIA_LVL](NULL) +
	    (sockets[i].headerlen[NETWORK_LVL])(NULL);

	bzero((caddr_t)&oc, sizeof (oc));
	if (sockets[i].type != INETBOOT_RAW) {
		offset += (sockets[i].headerlen[TRANSPORT_LVL])(NULL);
		oc.igm_level = TRANSPORT_LVL;
	} else
		oc.igm_level = NETWORK_LVL;
	oc.igm_oflags = flags;

	if (to != NULL) {
		bcopy((caddr_t)to, (caddr_t)&oc.igm_saddr, tolen);
	} else {
		bcopy((caddr_t)&sockets[i].remote, (caddr_t)&oc.igm_saddr,
		    sizeof (struct sockaddr_in));
	}

	/* Get a legal source port if the socket isn't bound. */
	if (sockets[i].bound == B_FALSE &&
	    ntohs(oc.igm_saddr.sin_port == 0)) {
		((struct sockaddr_in *)&oc.igm_saddr)->sin_port =
		    get_source_port(B_FALSE);
	}

	/* Round up to 16bit value for checksum purposes */
	if (sockets[i].type == INETBOOT_DGRAM) {
		tlen = ((len + sizeof (uint16_t) - 1) &
		    ~(sizeof (uint16_t) - 1));
	} else
		tlen = len;

	if ((oc.igm_mp = allocb(tlen + offset, 0)) == NULL) {
		errno = ENOMEM;
		return (-1);
	}
	mp = oc.igm_mp;
	mp->b_rptr = mp->b_wptr += offset;
	bcopy((caddr_t)msg, mp->b_wptr, len);
	mp->b_wptr += len;
	for (l = TRANSPORT_LVL; l >= MEDIA_LVL; l--) {
		if (sockets[i].output[l] != NULL) {
			if (sockets[i].output[l](i, &oc) < 0) {
				freeb(mp);
				if (errno == 0)
					errno = EIO;
				return (-1);
			}
		}
	}
	freeb(mp);
	return (len);
}

/* ARGSUSED */
static ssize_t
stream_sendto(int i, const void *msg, size_t len, int flags)
{
	int cnt;

	assert(sockets[i].pcb != NULL);

	/*
	 * Call directly TCP's send routine.  We do this because TCP
	 * needs to decide whether to send out the data.
	 *
	 * Note also that currently, TCP ignores all flags passed in for
	 * TCP socket.
	 */
	if ((cnt = tcp_send(i, sockets[i].pcb, msg, len)) < 0) {
		if (sockets[i].so_error != 0)
			errno = sockets[i].so_error;
		return (-1);
	} else {
		return (cnt);
	}
}

/*
 * Returns ptr to the last inetgram in the list, or null if list is null
 */
struct inetgram *
last_gram(struct inetgram *igp)
{
	struct inetgram	*wp;
	for (wp = igp; wp != NULL; wp = wp->igm_next) {
		if (wp->igm_next == NULL)
			return (wp);
	}
	return (NULL);
}

/*
 * Adds an inetgram or list of inetgrams to the end of the list.
 */
void
add_grams(struct inetgram **igpp, struct inetgram *newgp)
{
	struct inetgram	 *wp;

	if (newgp == NULL)
		return;

	if (*igpp == NULL)
		*igpp = newgp;
	else {
		wp = last_gram(*igpp);
		wp->igm_next = newgp;
	}
}

/*
 * Nuke a whole list of grams.
 */
void
nuke_grams(struct inetgram **lgpp)
{
	while (*lgpp != NULL)
		del_gram(lgpp, *lgpp, B_TRUE);
}

/*
 * Remove the referenced inetgram. List is altered accordingly. Destroy the
 * referenced inetgram if freeit is B_TRUE.
 */
void
del_gram(struct inetgram **lgpp, struct inetgram *igp, int freeit)
{
	struct inetgram	*wp, *pp = NULL;

	if (lgpp == NULL || igp == NULL)
		return;

	wp = *lgpp;
	while (wp != NULL) {
		if (wp == igp) {
			/* detach wp from the list */
			if (*lgpp == wp)
				*lgpp = (*lgpp)->igm_next;
			else
				pp->igm_next = wp->igm_next;
			igp->igm_next = NULL;

			if (freeit) {
				if (igp->igm_mp != NULL)
					freeb(igp->igm_mp);
				bkmem_free((caddr_t)igp,
				    sizeof (struct inetgram));
			}
			break;
		}
		pp = wp;
		wp = wp->igm_next;
	}
}

struct nct_t nct[] = {
	"bootp",	NCT_BOOTP_DHCP,
	"dhcp",		NCT_BOOTP_DHCP,
	"rarp",		NCT_RARP_BOOTPARAMS,
	"manual",	NCT_MANUAL
};
int	nct_entries = sizeof (nct) / sizeof (nct[0]);

/*
 * Figure out from the bootpath what kind of network configuration strategy
 * we should use. Returns the network config strategy.
 */
int
get_netconfig_strategy(void)
{
	int	i;
#define	ISSPACE(c) (c == ' ' || c == '\t' || c == '\n' || c == '\0')
	char	lbootpath[OBP_MAXPATHLEN];
	char	net_options[NCT_BUFSIZE];
	char	*op, *nop, *sp;
	pnode_t	cn;
	int	proplen;

	/* If the PROM DHCP cache exists, we're done */
	if (prom_cached_reply(B_TRUE))
		return (NCT_BOOTP_DHCP);

	/*
	 *	Newer (version 4) PROMs will put the name in the
	 *	"net-config-strategy" property.
	 */
	cn = prom_finddevice("/chosen");
	if ((proplen = prom_getproplen(cn, "net-config-strategy")) <
	    sizeof (net_options)) {
		(void) prom_getprop(cn, "net-config-strategy", net_options);
		net_options[proplen] = '\0';
	} else {

		/*
		 * We're reduced to sacanning bootpath for the prototol to use.
		 * Since there was no "net-config-strategy" property, this is
		 * an old PROM, so we need to excise any extraneous key/value
		 * initializations from bootpath[].
		 */
		for (op = prom_bootpath(), sp = lbootpath; op != NULL &&
		    !ISSPACE(*op); sp++, op++)
			*sp = *op;
		*sp = '\0';
		/* find the last '/' (in the device path) */
		if ((op = strrchr(lbootpath, '/')) == NULL)	/* last '/' */
			op = lbootpath;
		else
			op++;
		/* then look for the ':' separating it from the protocol */
		while (*op != ':' && *op != '\0')
			op++;

		if (*op == ':') {
			for (nop = net_options, op++;
			    *op != '\0' && *op != '/' && !ISSPACE(*op) &&
			    nop < &net_options[NCT_BUFSIZE]; nop++, op++)
				*nop = *op;
			*nop = '\0';
		} else
			net_options[0] = '\0';
	}

#undef	ISSPACE

	for (i = 0; i < nct_entries; i++)
		if (strcmp(net_options, nct[i].p_name) == 0)
			return (nct[i].p_id);

	return (NCT_DEFAULT);
}

/* Modified STREAM routines for ease of porting core TCP code. */

/*ARGSUSED*/
mblk_t *
allocb(size_t size, uint_t pri)
{
	unsigned char *base;
	mblk_t *mp;

	if ((mp = (mblk_t *)bkmem_zalloc(sizeof (mblk_t))) == NULL)
		return (NULL);
	if ((base = (unsigned char *)bkmem_zalloc(size)) == NULL)
		return (NULL);

	mp->b_next = mp->b_prev = mp->b_cont = NULL;
	mp->b_rptr = mp->b_wptr = mp->b_datap = (unsigned char *)base;
	mp->b_size = size;

	return (mp);
}

void
freeb(mblk_t *mp)
{
#ifdef DEBUG
	printf("freeb datap %x\n", mp->b_datap);
#endif
	bkmem_free((caddr_t)(mp->b_datap), mp->b_size);
#ifdef DEBUG
	printf("freeb mp %x\n", mp);
#endif
	bkmem_free((caddr_t)mp, sizeof (mblk_t));
}

void
freemsg(mblk_t *mp)
{
	while (mp) {
		mblk_t *mp_cont = mp->b_cont;

		freeb(mp);
		mp = mp_cont;
	}
}

mblk_t *
copyb(mblk_t *bp)
{
	mblk_t *nbp;
	unsigned char *ndp;

	assert((uintptr_t)(bp->b_wptr - bp->b_rptr) >= 0);

	if (!(nbp = allocb(bp->b_size, 0)))
		return (NULL);
	nbp->b_cont = NULL;
	ndp = nbp->b_datap;

	nbp->b_rptr = ndp + (bp->b_rptr - bp->b_datap);
	nbp->b_wptr = nbp->b_rptr + (bp->b_wptr - bp->b_rptr);
	bcopy(bp->b_datap, nbp->b_datap, bp->b_size);
	return (nbp);
}

/* To simplify things, dupb() is implemented as copyb(). */
mblk_t *
dupb(mblk_t *mp)
{
	return (copyb(mp));
}

/*
 * get number of data bytes in message
 */
size_t
msgdsize(mblk_t *bp)
{
	size_t count = 0;

	for (; bp != NULL; bp = bp->b_cont) {
		assert(bp->b_wptr >= bp->b_rptr);
		count += bp->b_wptr - bp->b_rptr;
	}
	return (count);
}
