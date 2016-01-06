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
 * Copyright 2015 Joyent, Inc. All rights reserved.
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

/*
 * This string is used to prefix all abstract namespace Unix sockets, ie all
 * abstract namespace sockets are converted to regular sockets in the /tmp
 * directory with .ABSK_ prefixed to their names.
 */
#define	ABST_PRFX "/tmp/.ABSK_"
#define	ABST_PRFX_LEN 11

typedef enum {
	lxa_none,
	lxa_abstract,
	lxa_devlog
} lx_addr_type_t;

#ifdef __i386

static int lx_listen32(ulong_t *);
static int lx_accept32(ulong_t *);
static int lx_getsockname32(ulong_t *);
static int lx_getpeername32(ulong_t *);
static int lx_socketpair32(ulong_t *);
static int lx_shutdown32(ulong_t *);
static int lx_accept4_32(ulong_t *);
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
	lx_accept32, 3,
	lx_getsockname32, 3,
	lx_getpeername32, 3,
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
	lx_accept4_32, 4,
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

#define	LX_AF_INET6	10
#define	LX_AF_NETLINK	16
#define	LX_AF_PACKET	17

static const int stol_family[LX_AF_MAX + 1] =  {
	AF_UNSPEC, AF_UNIX, AF_INET, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, LX_AF_INET6, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, LX_AF_PACKET,
	LX_AF_NETLINK
};

#define	LTOS_FAMILY(d) ((d) <= LX_AF_MAX ? ltos_family[(d)] : AF_INVAL)
#define	STOL_FAMILY(d) ((d) <= LX_AF_MAX ? stol_family[(d)] : AF_INVAL)

static const int ltos_socktype[LX_SOCK_PACKET + 1] = {
	SOCK_NOTSUPPORTED, SOCK_STREAM, SOCK_DGRAM, SOCK_RAW,
	SOCK_RDM, SOCK_SEQPACKET, SOCK_NOTSUPPORTED, SOCK_NOTSUPPORTED,
	SOCK_NOTSUPPORTED, SOCK_NOTSUPPORTED, SOCK_NOTSUPPORTED
};

#define	LTOS_SOCKTYPE(t)	\
	((t) <= LX_SOCK_PACKET ? ltos_socktype[(t)] : SOCK_INVAL)

static const int stol_socktype[SOCK_SEQPACKET + 1] = {
	SOCK_NOTSUPPORTED, LX_SOCK_DGRAM, LX_SOCK_STREAM, SOCK_NOTSUPPORTED,
	LX_SOCK_RAW, LX_SOCK_RDM, LX_SOCK_SEQPACKET
};

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
stol_sockaddr(struct sockaddr *addr, socklen_t *len,
    struct sockaddr *inaddr, socklen_t inlen, socklen_t orig)
{
	int size = inlen;

	switch (inaddr->sa_family) {
	case AF_INET:
		if (inlen > sizeof (struct sockaddr))
			return (EINVAL);
		break;

	case AF_INET6:
		if (inlen != sizeof (struct sockaddr_in6))
			return (EINVAL);
		/*
		 * The linux sockaddr_in6 is shorter than illumos.
		 * We just truncate the extra field on the way out
		 */
		size = (sizeof (lx_sockaddr_in6_t));
		inlen = (sizeof (lx_sockaddr_in6_t));
		break;

	case AF_UNIX:
		if (inlen > sizeof (struct sockaddr_un))
			return (EINVAL);
		break;

	case (sa_family_t)AF_NOTSUPPORTED:
		return (EPROTONOSUPPORT);

	case (sa_family_t)AF_INVAL:
		return (EAFNOSUPPORT);

	default:
		break;
	}

	inaddr->sa_family = STOL_FAMILY(inaddr->sa_family);

	/*
	 * If inlen is larger than orig, copy out the maximum amount of
	 * data possible and then update *len to indicate the actual
	 * size of all the data that it wanted to copy out.
	 */
	size = (orig > 0 && orig < size) ? orig : size;

	if (uucopy(inaddr, addr, size) < 0)
		return (errno);

	if (uucopy(&inlen, len, sizeof (socklen_t)) < 0)
		return (errno);

	return (0);
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
lx_accept(int sockfd, void *name, int *nlp)
{
	socklen_t namelen = 0, origlen;
	struct sockaddr *saddr;
	int r, err;
	int size;

	lx_debug("\taccept(%d, 0x%p, 0x%p", sockfd, (struct sockaddr *)name,
	    nlp);

	/*
	 * The Linux man page says that -1 is returned and errno is set to
	 * EFAULT if the "name" address is bad, but it is silent on what to
	 * set errno to if the "namelen" address is bad.  Experimentation
	 * shows that Linux (at least the 2.4.21 kernel in CentOS) actually
	 * sets errno to EINVAL in both cases.
	 *
	 * Note that we must first check the name pointer, as the Linux
	 * docs state nothing is copied out if the "name" pointer is NULL.
	 * If it is NULL, we don't care about the namelen pointer's value
	 * or about dereferencing it.
	 *
	 * Happily, illumos' accept(3SOCKET) treats NULL name pointers and
	 * zero namelens the same way.
	 */
	if ((name != NULL) &&
	    (uucopy((void *)nlp, &namelen, sizeof (socklen_t)) != 0))
		return ((errno == EFAULT) ? -EINVAL : -errno);
	origlen = namelen;

	if (name != NULL) {
		/*
		 * Use sizeof (struct sockaddr_in6) as the minimum temporary
		 * name allocation.  This will allow families such as AF_INET6
		 * to work properly when their namelen differs between LX and
		 * illumos.
		 */
		size = sizeof (struct sockaddr_in6);
		if (namelen > size)
			size = namelen;

		saddr = SAFE_ALLOCA(size);
		if (saddr == NULL)
			return (-EINVAL);
		bzero(saddr, size);
	} else {
		saddr = NULL;
	}

	lx_debug("\taccept namelen = %d", namelen);

	if ((r = accept(sockfd, saddr, &namelen)) < 0)
		return ((errno == EFAULT) ? -EINVAL : -errno);

	lx_debug("\taccept namelen returned %d bytes", namelen);

	/*
	 * In Linux, accept()ed sockets do not inherit anything set by
	 * fcntl(), so filter those out.
	 */
	if (fcntl(r, F_SETFL, 0) < 0)
		return (-errno);

	/*
	 * Once again, a bad "namelen" address sets errno to EINVAL, not
	 * EFAULT.  If namelen was zero, there's no need to copy a zero back
	 * out.
	 *
	 * Logic might dictate that we should check if we can write to
	 * the namelen pointer earlier so we don't accept a pending connection
	 * only to fail the call because we can't write the namelen value back
	 * out. However, testing shows Linux does indeed fail the call after
	 * accepting the connection so we must behave in a compatible manner.
	 */
	if ((name != NULL) && (namelen != 0)) {
		err = stol_sockaddr((struct sockaddr *)name, (socklen_t *)nlp,
		    saddr, namelen, origlen);
		if (err != 0) {
			close(r);
			return ((err == EFAULT) ? -EINVAL : -err);
		}
	}

	return (r);
}

long
lx_getsockname(int sockfd, void *np, int *nlp)
{
	struct sockaddr *name = NULL;
	socklen_t namelen, namelen_orig;
	struct stat sb;
	int err;

	if (uucopy((void *)nlp, &namelen, sizeof (socklen_t)) != 0)
		return (-errno);
	namelen_orig = namelen;

	lx_debug("\tgetsockname(%d, 0x%p, 0x%p (=%d))", sockfd,
	    (struct sockaddr *)np, nlp, namelen);

	if (fstat(sockfd, &sb) == 0 && !S_ISSOCK(sb.st_mode))
		return (-ENOTSOCK);

	/*
	 * Use sizeof (struct sockaddr_in6) as the minimum temporary
	 * name allocation.  This will allow families such as AF_INET6
	 * to work properly when their namelen differs between LX and
	 * illumos.
	 */
	if (namelen <= 0)
		return (-EBADF);
	else if (namelen < sizeof (struct sockaddr_in6))
		namelen = sizeof (struct sockaddr_in6);

	if ((name = SAFE_ALLOCA(namelen)) == NULL)
		return (-ENOMEM);
	bzero(name, namelen);

	if (getsockname(sockfd, name, &namelen) < 0)
		return (-errno);

	/*
	 * If the name that getsockname() wants to return is larger
	 * than namelen, getsockname() will copy out the maximum amount
	 * of data possible and then update namelen to indicate the
	 * actually size of all the data that it wanted to copy out.
	 */
	err = stol_sockaddr((struct sockaddr *)np, (socklen_t *)nlp, name,
	    namelen, namelen_orig);
	return ((err != 0) ? -err : 0);
}

long
lx_getpeername(int sockfd, void *np, int *nlp)
{
	struct sockaddr *name;
	socklen_t namelen, namelen_orig;
	int err;

	if (uucopy((void *)nlp, &namelen, sizeof (socklen_t)) != 0)
		return (-errno);
	namelen_orig = namelen;

	lx_debug("\tgetpeername(%d, 0x%p, 0x%p (=%d))", sockfd,
	    (struct sockaddr *)np, nlp, namelen);

	/* LTP can pass -1 but we'll limit the allocation to a page */
	if ((uint32_t)namelen > 4096)
		return (-EINVAL);

	/*
	 * Linux returns EFAULT in this case, even if the namelen parameter
	 * is 0 (some test cases use -1, so we check for that too).  This check
	 * will not catch other illegal addresses, but the benefit catching a
	 * non-null illegal address here is not worth the cost of another
	 * system call.
	 */
	if (np == NULL || np == (void *)-1)
		return (-EFAULT);

	/*
	 * Use sizeof (struct sockaddr_in6) as the minimum temporary
	 * name allocation.  This will allow families such as AF_INET6
	 * to work properly when their namelen differs between LX and
	 * illumos.
	 */
	if (namelen < sizeof (struct sockaddr_in6))
		namelen = sizeof (struct sockaddr_in6);

	name = SAFE_ALLOCA(namelen);
	if (name == NULL)
		return (-EINVAL);
	bzero(name, namelen);

	if ((getpeername(sockfd, name, &namelen)) < 0)
		return (-errno);

	err = stol_sockaddr((struct sockaddr *)np, (socklen_t *)nlp,
	    name, namelen, namelen_orig);
	if (err != 0)
		return (-err);

	return (0);
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

/*
 * Based on the lx_accept code with the addition of the flags handling.
 * See internal comments in that function for more explanation.
 */
long
lx_accept4(int sockfd, void *np, int *nlp, int lx_flags)
{
	socklen_t namelen, namelen_orig;
	struct sockaddr *name = NULL;
	int flags = 0;
	int r, err;

	lx_debug("\taccept4(%d, 0x%p, 0x%p 0x%x", sockfd, np, nlp, lx_flags);

	if ((np != NULL) &&
	    (uucopy((void *)nlp, &namelen, sizeof (socklen_t)) != 0))
		return ((errno == EFAULT) ? -EINVAL : -errno);

	namelen_orig = namelen;
	lx_debug("\taccept4 namelen = %d", namelen);

	if (np != NULL) {
		/*
		 * Use sizeof (struct sockaddr_in6) as the minimum temporary
		 * name allocation.  This will allow families such as AF_INET6
		 * to work properly when their namelen differs between LX and
		 * illumos.
		 */
		if (namelen < sizeof (struct sockaddr_in6))
			namelen = sizeof (struct sockaddr_in6);

		name = SAFE_ALLOCA(namelen);
		if (name == NULL)
			return (-EINVAL);
		bzero(name, namelen);
	}

	if (lx_flags & LX_SOCK_NONBLOCK)
		flags |= SOCK_NONBLOCK;

	if (lx_flags & LX_SOCK_CLOEXEC)
		flags |= SOCK_CLOEXEC;

	if ((r = accept4(sockfd, name, &namelen, flags)) < 0)
		return ((errno == EFAULT) ? -EINVAL : -errno);

	lx_debug("\taccept4 namelen returned %d bytes", namelen);

	if (np != NULL && namelen != 0) {
		err = stol_sockaddr((struct sockaddr *)np, (socklen_t *)nlp,
		    name, namelen, namelen_orig);
		if (err != 0) {
			close(r);
			return ((err == EFAULT) ? -EINVAL : -err);
		}
	}
	return (r);
}

#ifdef __i386

static int
lx_listen32(ulong_t *args)
{
	return (lx_listen((int)args[0], (int)args[1]));
}

static int
lx_accept32(ulong_t *args)
{
	return (lx_accept((int)args[0], (struct sockaddr *)args[1],
	    (int *)args[2]));
}

static int
lx_getsockname32(ulong_t *args)
{
	return (lx_getsockname((int)args[0], (struct sockaddr *)args[1],
	    (int *)args[2]));
}

static int
lx_getpeername32(ulong_t *args)
{
	return (lx_getpeername((int)args[0], (struct sockaddr *)args[1],
	    (int *)args[2]));
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

static int
lx_accept4_32(ulong_t *args)
{
	return (lx_accept4((int)args[0], (struct sockaddr *)args[1],
	    (int *)args[2], (int)args[3]));
}

static int
lx_recvmmsg32(ulong_t *args)
{
	lx_unsupported("Unsupported socketcall: recvmmsg\n.");
	return (-EINVAL);
}

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
