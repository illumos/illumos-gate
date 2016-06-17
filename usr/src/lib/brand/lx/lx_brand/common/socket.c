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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2016 Joyent, Inc.
 */

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <libintl.h>
#include <strings.h>
#include <alloca.h>
#include <ucred.h>
#include <limits.h>

#include <sys/param.h>
#include <sys/brand.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/un.h>
#include <netinet/tcp.h>
#include <netinet/igmp.h>
#include <netinet/icmp6.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/lx_debug.h>
#include <sys/lx_syscall.h>
#include <sys/lx_socket.h>
#include <sys/lx_brand.h>
#include <sys/lx_misc.h>
#include <netpacket/packet.h>

#ifdef __i386

static int lx_listen32(ulong_t *);
static int lx_socketpair32(ulong_t *);
static int lx_shutdown32(ulong_t *);
static int lx_recvmmsg32(ulong_t *);
static int lx_sendmmsg32(ulong_t *);

typedef int (*sockfn_t)(ulong_t *);

static struct {
	sockfn_t s_fn;	/* Function implementing the subcommand */
	int s_nargs;	/* Number of arguments the function takes */
} sockfns[] = {
	NULL, 3,
	NULL, 3,
	NULL, 3,
	lx_listen32, 2,
	NULL, 3,
	NULL, 3,
	NULL, 3,
	lx_socketpair32, 4,
	NULL, 4,
	NULL, 4,
	NULL, 6,
	NULL, 6,
	lx_shutdown32, 2,
	NULL, 5,
	NULL, 5,
	NULL, 3,
	NULL, 3,
	NULL, 4,
	lx_recvmmsg32, 5,
	lx_sendmmsg32, 4
};
#endif /* __i386 */

/*
 * What follows are a series of tables we use to translate Linux constants
 * into equivalent Illumos constants and back again.  I wish this were
 * cleaner, more programmatic, and generally nicer.  Sadly, life is messy,
 * and Unix networking even more so.
 */
static const int ltos_family[LX_AF_MAX + 1] =  {
	AF_UNSPEC, AF_UNIX, AF_INET, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_INET6, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_LX_NETLINK,
	AF_PACKET, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED
};

#define	LTOS_FAMILY(d) ((d) <= LX_AF_MAX ? ltos_family[(d)] : AF_INVAL)

static const int ltos_socktype[LX_SOCK_PACKET + 1] = {
	SOCK_NOTSUPPORTED, SOCK_STREAM, SOCK_DGRAM, SOCK_RAW,
	SOCK_RDM, SOCK_SEQPACKET, SOCK_NOTSUPPORTED, SOCK_NOTSUPPORTED,
	SOCK_NOTSUPPORTED, SOCK_NOTSUPPORTED, SOCK_NOTSUPPORTED
};

#define	LTOS_SOCKTYPE(t)	\
	((t) <= LX_SOCK_PACKET ? ltos_socktype[(t)] : SOCK_INVAL)

typedef struct {
	sa_family_t	nl_family;
	unsigned short	nl_pad;
	uint32_t	nl_pid;
	uint32_t	nl_groups;
} lx_sockaddr_nl_t;

typedef struct {
	sa_family_t	sin6_family;
	in_port_t	sin6_port;
	uint32_t	sin6_flowinfo;
	struct in6_addr	sin6_addr;
	uint32_t	sin6_scope_id;  /* Depends on scope of sin6_addr */
	/* one 32-bit field shorter than illumos */
} lx_sockaddr_in6_t;

static int
convert_pkt_proto(int protocol)
{
	switch (ntohs(protocol)) {
	case LX_ETH_P_802_2:
		return (ETH_P_802_2);
	case LX_ETH_P_IP:
		return (ETH_P_IP);
	case LX_ETH_P_ARP:
		return (ETH_P_ARP);
	case LX_ETH_P_IPV6:
		return (ETH_P_IPV6);
	case LX_ETH_P_ALL:
	case LX_ETH_P_802_3:
		return (ETH_P_ALL);
	default:
		return (-1);
	}
}

static int
convert_sock_args(int in_dom, int in_type, int in_protocol, int *out_dom,
    int *out_type, int *out_options, int *out_protocol)
{
	int domain, type, options;

	if (in_dom < 0 || in_type < 0 || in_protocol < 0)
		return (-EINVAL);

	domain = LTOS_FAMILY(in_dom);
	if (domain == AF_NOTSUPPORTED || domain == AF_UNSPEC)
		return (-EAFNOSUPPORT);
	if (domain == AF_INVAL)
		return (-EINVAL);

	type = LTOS_SOCKTYPE(in_type & LX_SOCK_TYPE_MASK);
	if (type == SOCK_NOTSUPPORTED)
		return (-ESOCKTNOSUPPORT);
	if (type == SOCK_INVAL)
		return (-EINVAL);

	/*
	 * Linux does not allow the app to specify IP Protocol for raw
	 * sockets.  Illumos does, so bail out here.
	 */
	if (domain == AF_INET && type == SOCK_RAW && in_protocol == IPPROTO_IP)
		return (-ESOCKTNOSUPPORT);

	options = 0;
	if (in_type & LX_SOCK_NONBLOCK)
		options |= SOCK_NONBLOCK;
	if (in_type & LX_SOCK_CLOEXEC)
		options |= SOCK_CLOEXEC;

	/*
	 * The protocol definitions for PF_PACKET differ between Linux and
	 * illumos.
	 */
	if (domain == PF_PACKET &&
	    (in_protocol = convert_pkt_proto(in_protocol)) < 0)
		return (EINVAL);

	*out_dom = domain;
	*out_type = type;
	*out_options = options;
	*out_protocol = in_protocol;
	return (0);
}

long
lx_listen(int sockfd, int backlog)
{
	int r;

	lx_debug("\tlisten(%d, %d)", sockfd, backlog);
	r = listen(sockfd, backlog);

	return ((r < 0) ? -errno : r);
}

long
lx_socketpair(int domain, int type, int protocol, int *sv)
{
	int options;
	int fds[2];
	int r;

	r = convert_sock_args(domain, type, protocol, &domain, &type, &options,
	    &protocol);
	if (r != 0)
		return (r);

	lx_debug("\tsocketpair(%d, %d, %d, 0x%p)", domain, type, protocol, sv);

	r = socketpair(domain, type | options, protocol, fds);

	if (r == 0) {
		if (uucopy(fds, sv, sizeof (fds)) != 0) {
			r = errno;
			(void) close(fds[0]);
			(void) close(fds[1]);
			return (-r);
		}
		return (0);
	}

	if (errno == EPROTONOSUPPORT)
		return (-ESOCKTNOSUPPORT);

	return (-errno);
}

long
lx_shutdown(int sockfd, int how)
{
	int r;

	lx_debug("\tshutdown(%d, %d)", sockfd, how);
	r = shutdown(sockfd, how);

	return ((r < 0) ? -errno : r);
}

#ifdef __i386

static int
lx_listen32(ulong_t *args)
{
	return (lx_listen((int)args[0], (int)args[1]));
}

static int
lx_socketpair32(ulong_t *args)
{
	return (lx_socketpair((int)args[0], (int)args[1], (int)args[2],
	    (int *)args[3]));
}

static int
lx_shutdown32(ulong_t *args)
{
	return (lx_shutdown((int)args[0], (int)args[1]));
}

/* ARGSUSED */
static int
lx_recvmmsg32(ulong_t *args)
{
	lx_unsupported("Unsupported socketcall: recvmmsg\n.");
	return (-EINVAL);
}

/* ARGSUSED */
static int
lx_sendmmsg32(ulong_t *args)
{
	lx_unsupported("Unsupported socketcall: sendmmsg\n.");
	return (-EINVAL);
}

long
lx_socketcall(uintptr_t p1, uintptr_t p2)
{
	int subcmd = (int)p1 - 1; /* subcommands start at 1 - not 0 */
	ulong_t args[6];
	int r;

	if (subcmd < 0 || subcmd >= LX_SENDMMSG)
		return (-EINVAL);

	/* Bail out if we are trying to call an IKE function */
	if (sockfns[subcmd].s_fn == NULL) {
		lx_err_fatal("lx_socketcall: deprecated subcmd: %d", subcmd);
	}

	/*
	 * Copy the arguments to the subcommand in from the app's address
	 * space, returning EFAULT if we get a bogus pointer.
	 */
	if (uucopy((void *)p2, args,
	    sockfns[subcmd].s_nargs * sizeof (ulong_t)))
		return (-errno);

	r = (sockfns[subcmd].s_fn)(args);

	return (r);
}

#endif /* __i386 */
