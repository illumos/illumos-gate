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

#include <sys/param.h>
#include <sys/brand.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/un.h>
#include <netinet/tcp.h>
#include <netinet/igmp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/lx_debug.h>
#include <sys/lx_syscall.h>
#include <sys/lx_socket.h>
#include <sys/lx_brand.h>
#include <sys/lx_misc.h>

/*
 * This string is used to prefix all abstract namespace unix sockets, ie all
 * abstract namespace sockets are converted to regular sockets in the /tmp
 * directory with .ABSK_ prefixed to their names.
 */
#define	ABST_PRFX "/tmp/.ABSK_"
#define	ABST_PRFX_LEN 11

static int lx_socket(ulong_t *);
static int lx_bind(ulong_t *);
static int lx_connect(ulong_t *);
static int lx_listen(ulong_t *);
static int lx_accept(ulong_t *);
static int lx_getsockname(ulong_t *);
static int lx_getpeername(ulong_t *);
static int lx_socketpair(ulong_t *);
static int lx_send(ulong_t *);
static int lx_recv(ulong_t *);
static int lx_sendto(ulong_t *);
static int lx_recvfrom(ulong_t *);
static int lx_shutdown(ulong_t *);
static int lx_setsockopt(ulong_t *);
static int lx_getsockopt(ulong_t *);
static int lx_sendmsg(ulong_t *);
static int lx_recvmsg(ulong_t *);

typedef int (*sockfn_t)(ulong_t *);

static struct {
	sockfn_t s_fn;	/* Function implementing the subcommand */
	int s_nargs;	/* Number of arguments the function takes */
} sockfns[] = {
	lx_socket, 3,
	lx_bind, 3,
	lx_connect, 3,
	lx_listen, 2,
	lx_accept, 3,
	lx_getsockname, 3,
	lx_getpeername, 3,
	lx_socketpair, 4,
	lx_send, 4,
	lx_recv, 4,
	lx_sendto, 6,
	lx_recvfrom, 6,
	lx_shutdown, 2,
	lx_setsockopt, 5,
	lx_getsockopt, 5,
	lx_sendmsg, 3,
	lx_recvmsg, 3
};

/*
 * What follows are a series of tables we use to translate Linux constants
 * into equivalent Solaris constants and back again.  I wish this were
 * cleaner, more programmatic, and generally nicer.  Sadly, life is messy,
 * and Unix networking even more so.
 */
static const int ltos_family[LX_AF_MAX + 1] =  {
	AF_UNSPEC, AF_UNIX, AF_INET, AF_CCITT, AF_IPX,
	AF_APPLETALK, AF_NOTSUPPORTED, AF_OSI, AF_NOTSUPPORTED,
	AF_X25, AF_INET6, AF_CCITT, AF_DECnet,
	AF_802, AF_POLICY, AF_KEY, AF_ROUTE,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_SNA, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED
};

#define	LTOS_FAMILY(d) ((d) <= LX_AF_MAX ? ltos_family[(d)] : AF_INVAL)

static const int ltos_socktype[LX_SOCK_PACKET + 1] = {
	SOCK_NOTSUPPORTED, SOCK_STREAM, SOCK_DGRAM, SOCK_RAW,
	SOCK_RDM, SOCK_SEQPACKET, SOCK_NOTSUPPORTED, SOCK_NOTSUPPORTED,
	SOCK_NOTSUPPORTED, SOCK_NOTSUPPORTED, SOCK_NOTSUPPORTED
};

#define	LTOS_SOCKTYPE(t)	\
	((t) <= LX_SOCK_PACKET ? ltos_socktype[(t)] : SOCK_INVAL)

/*
 * Linux socket option type definitions
 *
 * The protocol `levels` are well defined (see in.h) The option values are
 * not so well defined. Linux often uses different values to Solaris
 * although they mean the same thing. For example, IP_TOS in Linux is
 * defined as value 1 but in Solaris it is defined as value 3. This table
 * maps all the Protocol levels to their options and maps them between
 * Linux and Solaris and vice versa.  Hence the reason for the complexity.
 */

typedef struct lx_proto_opts {
	const int *proto;	/* Linux to Solaris mapping table */
	int maxentries;		/* max entries in this table */
} lx_proto_opts_t;

#define	OPTNOTSUP	-1	/* we don't support it */

static const int ltos_ip_sockopts[LX_IP_DROP_MEMBERSHIP + 1] = {
	OPTNOTSUP, IP_TOS, IP_TTL, IP_HDRINCL,
	IP_OPTIONS, OPTNOTSUP, IP_RECVOPTS, IP_RETOPTS,
	OPTNOTSUP, OPTNOTSUP, OPTNOTSUP, OPTNOTSUP,
	IP_RECVTTL, OPTNOTSUP, OPTNOTSUP, OPTNOTSUP,
	OPTNOTSUP, OPTNOTSUP, OPTNOTSUP, OPTNOTSUP,
	OPTNOTSUP, OPTNOTSUP, OPTNOTSUP, OPTNOTSUP,
	OPTNOTSUP, OPTNOTSUP, OPTNOTSUP, OPTNOTSUP,
	OPTNOTSUP, OPTNOTSUP, OPTNOTSUP, OPTNOTSUP,
	IP_MULTICAST_IF, IP_MULTICAST_TTL, IP_MULTICAST_LOOP,
	IP_ADD_MEMBERSHIP, IP_DROP_MEMBERSHIP
};

static const int ltos_tcp_sockopts[LX_TCP_QUICKACK + 1] = {
	OPTNOTSUP, TCP_NODELAY, TCP_MAXSEG, OPTNOTSUP,
	OPTNOTSUP, OPTNOTSUP, OPTNOTSUP, OPTNOTSUP,
	TCP_KEEPALIVE, OPTNOTSUP, OPTNOTSUP, OPTNOTSUP,
	OPTNOTSUP
};

static const int ltos_igmp_sockopts[IGMP_MTRACE + 1] = {
	OPTNOTSUP, OPTNOTSUP, OPTNOTSUP, OPTNOTSUP,
	OPTNOTSUP, OPTNOTSUP, OPTNOTSUP, OPTNOTSUP,
	IGMP_MINLEN, OPTNOTSUP, OPTNOTSUP, /* XXX: was IGMP_TIMER_SCALE */
	OPTNOTSUP, OPTNOTSUP, OPTNOTSUP, OPTNOTSUP,
	OPTNOTSUP, OPTNOTSUP, IGMP_MEMBERSHIP_QUERY,
	IGMP_V1_MEMBERSHIP_REPORT, IGMP_DVMRP,
	IGMP_PIM, OPTNOTSUP, IGMP_V2_MEMBERSHIP_REPORT,
	IGMP_V2_LEAVE_GROUP, OPTNOTSUP, OPTNOTSUP,
	OPTNOTSUP, OPTNOTSUP, OPTNOTSUP, OPTNOTSUP,
	IGMP_MTRACE_RESP, IGMP_MTRACE
};

static const int ltos_socket_sockopts[LX_SO_ACCEPTCONN + 1] = {
	OPTNOTSUP,	SO_DEBUG,	SO_REUSEADDR,	SO_TYPE,
	SO_ERROR,	SO_DONTROUTE,	SO_BROADCAST,	SO_SNDBUF,
	SO_RCVBUF,	SO_KEEPALIVE,	SO_OOBINLINE,	OPTNOTSUP,
	OPTNOTSUP,	SO_LINGER,	OPTNOTSUP,	OPTNOTSUP,
	OPTNOTSUP,	OPTNOTSUP,	SO_RCVLOWAT,	SO_SNDLOWAT,
	SO_RCVTIMEO,	SO_SNDTIMEO,	OPTNOTSUP,	OPTNOTSUP,
	OPTNOTSUP,	OPTNOTSUP,	OPTNOTSUP,	OPTNOTSUP,
	OPTNOTSUP,	OPTNOTSUP,	SO_ACCEPTCONN
};

#define	PROTO_SOCKOPTS(opts)    \
	{ (opts), sizeof ((opts)) / sizeof ((opts)[0]) }

/*
 * The main Linux to Solaris protocol to options mapping table
 * IPPROTO_TAB_SIZE can be set up to IPPROTO_MAX. All entries above
 * IPPROTO_TAB_SIZE are in effect not implemented,
 */

#define	IPPROTO_TAB_SIZE	8

static const lx_proto_opts_t ltos_proto_opts[IPPROTO_TAB_SIZE] = {
	/* IPPROTO_IP		0 */
	PROTO_SOCKOPTS(ltos_ip_sockopts),
	/* SOL_SOCKET		1 */
	PROTO_SOCKOPTS(ltos_socket_sockopts),
	/* IPPROTO_IGMP		2 */
	PROTO_SOCKOPTS(ltos_igmp_sockopts),
	/* NOT IMPLEMENTED	3 */
	{ NULL, 0 },
	/* NOT IMPLEMENTED	4 */
	{ NULL, 0 },
	/* NOT IMPLEMENTED	5 */
	{ NULL, 0 },
	/* IPPROTO_TCP		6 */
	PROTO_SOCKOPTS(ltos_tcp_sockopts),
	/* NOT IMPLEMENTED	7 */
	{ NULL, 0 }
};

/*
 * Lifted from socket.h, since these definitions are contained within
 * _KERNEL guards.
 */
#define	_CMSG_HDR_ALIGNMENT	4
#define	_CMSG_HDR_ALIGN(x)	(((uintptr_t)(x) + _CMSG_HDR_ALIGNMENT - 1) & \
				    ~(_CMSG_HDR_ALIGNMENT - 1))
#define	CMSG_FIRSTHDR(m)						\
	(((m)->msg_controllen < sizeof (struct cmsghdr)) ?		\
	    (struct cmsghdr *)0 : (struct cmsghdr *)((m)->msg_control))

#define	CMSG_NXTHDR(m, c)						\
	(((c) == 0) ? CMSG_FIRSTHDR(m) :			\
	((((uintptr_t)_CMSG_HDR_ALIGN((char *)(c) +			\
	((struct cmsghdr *)(c))->cmsg_len) + sizeof (struct cmsghdr)) >	\
	(((uintptr_t)((struct lx_msghdr *)(m))->msg_control) +		\
	((uintptr_t)((struct lx_msghdr *)(m))->msg_controllen))) ?	\
	((struct cmsghdr *)0) :						\
	((struct cmsghdr *)_CMSG_HDR_ALIGN((char *)(c) +		\
	    ((struct cmsghdr *)(c))->cmsg_len))))

#define	LX_TO_SOL	1
#define	SOL_TO_LX	2

static int
convert_cmsgs(int direction, struct lx_msghdr *msg, char *caller)
{
	struct cmsghdr *cmsg, *last;
	int err = 0;

	cmsg = CMSG_FIRSTHDR(msg);
	while (cmsg != NULL && err == 0) {
		if (direction == LX_TO_SOL) {
			if (cmsg->cmsg_level == LX_SOL_SOCKET) {
				cmsg->cmsg_level = SOL_SOCKET;
				if (cmsg->cmsg_type == LX_SCM_RIGHTS)
					cmsg->cmsg_type = SCM_RIGHTS;
				else if (cmsg->cmsg_type == LX_SCM_CRED)
					cmsg->cmsg_type = SCM_UCRED;
				else
					err = ENOTSUP;
			} else {
				err = ENOTSUP;
			}
		} else {
			if (cmsg->cmsg_level == SOL_SOCKET) {
				cmsg->cmsg_level = LX_SOL_SOCKET;
				if (cmsg->cmsg_type == SCM_RIGHTS)
					cmsg->cmsg_type = LX_SCM_RIGHTS;
				else if (cmsg->cmsg_type == SCM_UCRED)
					cmsg->cmsg_type = LX_SCM_CRED;
				else
					err = ENOTSUP;
			} else {
				err = ENOTSUP;
			}
		}

		last = cmsg;
		cmsg = CMSG_NXTHDR(msg, last);
	}
	if (err)
		lx_unsupported("Unsupported socket control message in %s\n.",
		    caller);

	return (err);
}

/*
 * If inaddr is an abstract namespace unix socket, this function expects addr
 * to have enough memory to hold the expanded socket name, ie it must be of
 * size *len + ABST_PRFX_LEN.
 */
static int
convert_sockaddr(struct sockaddr *addr, socklen_t *len,
	struct sockaddr *inaddr, socklen_t inlen)
{
	sa_family_t family;
	int lx_in6_len;
	int size;
	int i, orig_len;

	/*
	 * Note that if the buffer at inaddr is ever smaller than inlen bytes,
	 * we may erroneously return EFAULT rather than a possible EINVAL
	 * as the copy comes before the various checks as to whether inlen
	 * is of the proper length for the socket type.
	 *
	 * This isn't an issue at present because all callers to this routine
	 * do meet that constraint.
	 */
	if ((ssize_t)inlen < 0)
		return (-EINVAL);
	if (uucopy(inaddr, addr, inlen) != 0)
		return (-errno);

	family = LTOS_FAMILY(addr->sa_family);

	switch (family) {
		case (sa_family_t)AF_NOTSUPPORTED:
			return (-EPROTONOSUPPORT);
		case (sa_family_t)AF_INVAL:
			return (-EAFNOSUPPORT);
		case AF_INET:
			size = sizeof (struct sockaddr);

			if (inlen < size)
				return (-EINVAL);

			*len = size;
			break;

		case AF_INET6:
			/*
			 * The Solaris sockaddr_in6 has one more 32-bit
			 * field than the Linux version.
			 */
			size = sizeof (struct sockaddr_in6);
			lx_in6_len = size - sizeof (uint32_t);

			if (inlen != lx_in6_len)
				return (-EINVAL);

			*len = (sizeof (struct sockaddr_in6));
			bzero((char *)addr + lx_in6_len, sizeof	(uint32_t));
			break;

		case AF_UNIX:
			if (inlen > sizeof (struct sockaddr_un))
				return (-EINVAL);

			*len = inlen;

			/*
			 * Linux supports abstract unix sockets, which are
			 * simply sockets that do not exist on the file system.
			 * These sockets are denoted by beginning the path with
			 * a NULL character. To support these, we strip out the
			 * leading NULL character and change the path to point
			 * to a real place in /tmp directory, by prepending
			 * ABST_PRFX and replacing all illegal characters with
			 * '_'.
			 */
			if (addr->sa_data[0] == '\0') {

				/*
				 * inlen is the entire size of the sockaddr_un
				 * data structure, including the sun_family, so
				 * we need to subtract this out. We subtract
				 * 1 since we want to overwrite the leadin NULL
				 * character, and thus do not include it in the
				 * length.
				 */
				orig_len = inlen - sizeof (addr->sa_family) - 1;

				/*
				 * Since abstract paths can contain illegal
				 * filename characters, we simply replace these
				 * with '_'
				 */
				for (i = 1; i < orig_len + 1; i++) {
					if (addr->sa_data[i] == '\0' ||
					    addr->sa_data[i] == '/')
						addr->sa_data[i] = '_';
				}

				/*
				 * prepend ABST_PRFX to file name, minus the
				 * leading NULL character. This places the
				 * socket as a hidden file in the /tmp
				 * directory.
				 */
				(void) memmove(addr->sa_data + ABST_PRFX_LEN,
				    addr->sa_data + 1, orig_len);
				bcopy(ABST_PRFX, addr->sa_data, ABST_PRFX_LEN);

				/*
				 * Since abstract socket paths may not be NULL
				 * terminated, we must explicitly NULL terminate
				 * our string.
				 */
				addr->sa_data[orig_len + ABST_PRFX_LEN] = '\0';

				/*
				 * Make len reflect the new len of our string.
				 * Although we removed the NULL character at the
				 * beginning of the string, we added a NULL
				 * character to the end, so the net gain in
				 * length is simply ABST_PRFX_LEN.
				 */
				*len = inlen + ABST_PRFX_LEN;
			}
			break;

		default:
			*len = inlen;
	}

	addr->sa_family = family;
	return (0);
}

static int
convert_sock_args(int in_dom, int in_type, int in_protocol, int *out_dom,
    int *out_type)
{
	int domain, type;

	if (in_dom < 0 || in_type < 0 || in_protocol < 0)
		return (-EINVAL);

	domain = LTOS_FAMILY(in_dom);
	if (domain == AF_NOTSUPPORTED || domain == AF_UNSPEC)
		return (-EAFNOSUPPORT);
	if (domain == AF_INVAL)
		return (-EINVAL);

	type = LTOS_SOCKTYPE(in_type);
	if (type == SOCK_NOTSUPPORTED)
		return (-ESOCKTNOSUPPORT);
	if (type == SOCK_INVAL)
		return (-EINVAL);

	/*
	 * Linux does not allow the app to specify IP Protocol for raw
	 * sockets.  Solaris does, so bail out here.
	 */
	if (type == SOCK_RAW && in_protocol == IPPROTO_IP)
		return (-ESOCKTNOSUPPORT);

	*out_dom = domain;
	*out_type = type;
	return (0);
}

static int
convert_sockflags(int lx_flags)
{
	int solaris_flags = 0;

	if (lx_flags & LX_MSG_OOB)
		solaris_flags |= MSG_OOB;

	if (lx_flags & LX_MSG_PEEK)
		solaris_flags |= MSG_PEEK;

	if (lx_flags & LX_MSG_DONTROUTE)
		solaris_flags |= MSG_DONTROUTE;

	if (lx_flags & LX_MSG_CTRUNC)
		solaris_flags |= MSG_CTRUNC;

	if (lx_flags & LX_MSG_TRUNC)
		solaris_flags |= MSG_TRUNC;

	if (lx_flags & LX_MSG_WAITALL)
		solaris_flags |= MSG_WAITALL;

	if (lx_flags & LX_MSG_DONTWAIT)
		solaris_flags |= MSG_DONTWAIT;

	if (lx_flags & LX_MSG_EOR)
		solaris_flags |= MSG_EOR;

	if (lx_flags & LX_MSG_PROXY)
		lx_unsupported("socket operation with MSG_PROXY flag set");

	if (lx_flags & LX_MSG_FIN)
		lx_unsupported("socket operation with MSG_FIN flag set");

	if (lx_flags & LX_MSG_SYN)
		lx_unsupported("socket operation with MSG_SYN flag set");

	if (lx_flags & LX_MSG_CONFIRM)
		lx_unsupported("socket operation with MSG_CONFIRM set");

	if (lx_flags & LX_MSG_RST)
		lx_unsupported("socket operation with MSG_RST flag set");

	if (lx_flags & LX_MSG_MORE)
		lx_unsupported("socket operation with MSG_MORE flag set");

	return (solaris_flags);
}

static int
lx_socket(ulong_t *args)
{
	int domain;
	int type;
	int protocol = (int)args[2];
	int fd;
	int err;

	err = convert_sock_args((int)args[0], (int)args[1], protocol,
	    &domain, &type);
	if (err != 0)
		return (err);

	lx_debug("\tsocket(%d, %d, %d)", domain, type, protocol);

	/* Right now IPv6 sockets don't work */
	if (domain == AF_INET6)
		return (-EAFNOSUPPORT);

	/*
	 * Clients of the auditing subsystem used by CentOS 4 and 5 expect to
	 * be able to create AF_ROUTE SOCK_RAW sockets to communicate with the
	 * auditing daemons. Failure to create these sockets will cause login,
	 * ssh and useradd, amoung other programs to fail. To trick these
	 * programs into working, we convert the socket domain and type to
	 * something that we do support. Then when sendto is called on these
	 * sockets, we return an error code. See lx_sendto.
	 */
	if (domain == AF_ROUTE && type == SOCK_RAW) {
		domain = AF_INET;
		type = SOCK_STREAM;
		protocol = 0;
	}

	fd = socket(domain, type, protocol);
	if (fd >= 0)
		return (fd);

	if (errno == EPROTONOSUPPORT)
		return (-ESOCKTNOSUPPORT);

	return (-errno);
}

static int
lx_bind(ulong_t *args)
{
	int sockfd = (int)args[0];
	struct stat64 statbuf;
	struct sockaddr *name, oldname;
	socklen_t len;
	int r, r2, ret, tmperrno;
	int abst_sock;
	struct stat sb;

	if (uucopy((struct sockaddr *)args[1], &oldname,
	    sizeof (struct sockaddr)) != 0)
		return (-errno);

	/*
	 * Handle Linux abstract sockets, which are UNIX sockets whose path
	 * begins with a NULL character.
	 */
	abst_sock = (oldname.sa_family == AF_UNIX) &&
	    (oldname.sa_data[0] == '\0');

	/*
	 * convert_sockaddr will expand the socket path if it is abstract, so
	 * we need to allocate extra memory for it now.
	 */
	if ((name = SAFE_ALLOCA((socklen_t)args[2] +
	    abst_sock * ABST_PRFX_LEN)) == NULL)
		return (-EINVAL);

	if ((r = convert_sockaddr(name, &len, (struct sockaddr *)args[1],
	    (socklen_t)args[2])) < 0)
		return (r);

	/*
	 * Linux abstract namespace unix sockets are simply socket that do not
	 * exist on the filesystem. We emulate them by changing their paths
	 * in covert_sockaddr so that they point real files names on the
	 * filesystem. Because in Linux they do not exist on the filesystem
	 * applications do not have to worry about deleting files, however in
	 * our filesystem based emulation we do. To solve this problem, we first
	 * check to see if the socket already exists before we create one. If it
	 * does we attempt to connect to it to see if it is in use, or just
	 * left over from a previous lx_bind call. If we are unable to connect,
	 * we assume it is not in use and remove the file, then continue on
	 * as if the file never existed.
	 */
	if (abst_sock && stat(name->sa_data, &sb) == 0 &&
	    S_ISSOCK(sb.st_mode)) {
		if ((r2 = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
			return (-ENOSR);
		ret = connect(r2, name, len);
		tmperrno = errno;
		if (close(r2) < 0)
			return (-EINVAL);

		/*
		 * if we can't connect to the socket, assume no one is using it
		 * and remove it, otherwise assume it is in use and return
		 * EADDRINUSE.
		 */
		if ((ret < 0) && (tmperrno == ECONNREFUSED)) {
			if (unlink(name->sa_data) < 0) {
				return (-EADDRINUSE);
			}
		} else {
			return (-EADDRINUSE);
		}
	}

	lx_debug("\tbind(%d, 0x%p, %d)", sockfd, name, len);

	if (name->sa_family == AF_UNIX)
		lx_debug("\t\tAF_UNIX, path = %s", name->sa_data);

	r = bind(sockfd, name, len);

	/*
	 * Linux returns EADDRINUSE for attempts to bind to UNIX domain
	 * sockets that aren't sockets.
	 */
	if ((r < 0) && (errno == EINVAL) && (name->sa_family == AF_UNIX) &&
	    ((stat64(name->sa_data, &statbuf) == 0) &&
	    (!S_ISSOCK(statbuf.st_mode))))
		return (-EADDRINUSE);

	return ((r < 0) ? -errno : r);
}

static int
lx_connect(ulong_t *args)
{
	int sockfd = (int)args[0];
	struct sockaddr *name, oldname;
	socklen_t len;
	int r;
	int abst_sock;

	if (uucopy((struct sockaddr *)args[1], &oldname,
	    sizeof (struct sockaddr)) != 0)
		return (-errno);


	/* Handle Linux abstract sockets */
	abst_sock = (oldname.sa_family == AF_UNIX) &&
	    (oldname.sa_data[0] == '\0');

	/*
	 * convert_sockaddr will expand the socket path, if it is abstract, so
	 * we need to allocate extra memory for it now.
	 */
	if ((name = SAFE_ALLOCA((socklen_t)args[2] +
	    abst_sock * ABST_PRFX_LEN)) == NULL)
		return (-EINVAL);

	if ((r = convert_sockaddr(name, &len, (struct sockaddr *)args[1],
	    (socklen_t)args[2])) < 0)
		return (r);

	lx_debug("\tconnect(%d, 0x%p, %d)", sockfd, name, len);

	if (name->sa_family == AF_UNIX)
		lx_debug("\t\tAF_UNIX, path = %s", name->sa_data);

	r = connect(sockfd, name, len);

	return ((r < 0) ? -errno : r);
}

static int
lx_listen(ulong_t *args)
{
	int sockfd = (int)args[0];
	int backlog = (int)args[1];
	int r;

	lx_debug("\tlisten(%d, %d)", sockfd, backlog);
	r = listen(sockfd, backlog);

	return ((r < 0) ? -errno : r);
}

static int
lx_accept(ulong_t *args)
{
	int sockfd = (int)args[0];
	struct sockaddr *name = (struct sockaddr *)args[1];
	socklen_t namelen = 0;
	int r;

	lx_debug("\taccept(%d, 0x%p, 0x%p", sockfd, args[1], args[2]);

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
	 * Happily, Solaris' accept(3SOCKET) treats NULL name pointers and
	 * zero namelens the same way.
	 */
	if ((name != NULL) &&
	    (uucopy((void *)args[2], &namelen, sizeof (socklen_t)) != 0))
		return ((errno == EFAULT) ? -EINVAL : -errno);

	lx_debug("\taccept namelen = %d", namelen);

	if ((r = accept(sockfd, name, &namelen)) < 0)
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
	if ((name != NULL) && (namelen != 0) &&
	    (uucopy(&namelen, (void *)args[2], sizeof (socklen_t)) != 0))
		return ((errno == EFAULT) ? -EINVAL : -errno);

	return (r);
}

static int
lx_getsockname(ulong_t *args)
{
	int sockfd = (int)args[0];
	struct sockaddr *name = NULL;
	socklen_t namelen, namelen_orig;

	if (uucopy((void *)args[2], &namelen, sizeof (socklen_t)) != 0)
		return (-errno);
	namelen_orig = namelen;

	lx_debug("\tgetsockname(%d, 0x%p, 0x%p (=%d))",
	    sockfd, args[1], args[2], namelen);

	if (namelen > 0) {
		if ((name = SAFE_ALLOCA(namelen)) == NULL)
			return (-EINVAL);
		bzero(name, namelen);
	}

	if ((getsockname(sockfd, name, &namelen)) < 0)
		return (-errno);

	/*
	 * If the name that getsockname() want's to return is larger
	 * than namelen, getsockname() will copy out the maximum amount
	 * of data possible and then update namelen to indicate the
	 * actually size of all the data that it wanted to copy out.
	 */
	if (uucopy(name, (void *)args[1], namelen_orig) != 0)
		return (-errno);
	if (uucopy(&namelen, (void *)args[2], sizeof (socklen_t)) != 0)
		return (-errno);

	return (0);
}

static int
lx_getpeername(ulong_t *args)
{
	int sockfd = (int)args[0];
	struct sockaddr *name;
	socklen_t namelen;

	if (uucopy((void *)args[2], &namelen, sizeof (socklen_t)) != 0)
		return (-errno);

	lx_debug("\tgetpeername(%d, 0x%p, 0x%p (=%d))",
	    sockfd, args[1], args[2], namelen);

	/*
	 * Linux returns EFAULT in this case, even if the namelen parameter
	 * is 0.  This check will not catch other illegal addresses, but
	 * the benefit catching a non-null illegal address here is not
	 * worth the cost of another system call.
	 */
	if ((void *)args[1] == NULL)
		return (-EFAULT);

	if ((name = SAFE_ALLOCA(namelen)) == NULL)
		return (-EINVAL);
	if ((getpeername(sockfd, name, &namelen)) < 0)
		return (-errno);

	if (uucopy(name, (void *)args[1], namelen) != 0)
		return (-errno);

	if (uucopy(&namelen, (void *)args[2], sizeof (socklen_t)) != 0)
		return (-errno);

	return (0);
}

static int
lx_socketpair(ulong_t *args)
{
	int domain;
	int type;
	int protocol = (int)args[2];
	int *sv = (int *)args[3];
	int fds[2];
	int r;

	r = convert_sock_args((int)args[0], (int)args[1], protocol,
	    &domain, &type);
	if (r != 0)
		return (r);

	lx_debug("\tsocketpair(%d, %d, %d, 0x%p)", domain, type, protocol, sv);

	r = socketpair(domain, type, protocol, fds);

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

static ssize_t
lx_send(ulong_t *args)
{
	int sockfd = (int)args[0];
	void *buf = (void *)args[1];
	size_t len = (size_t)args[2];
	int flags = (int)args[3];
	ssize_t r;

	int nosigpipe = flags & LX_MSG_NOSIGNAL;
	struct sigaction newact, oact;

	lx_debug("\tsend(%d, 0x%p, 0x%d, 0x%x)", sockfd, buf, len, flags);

	flags = convert_sockflags(flags);

	/*
	 * If nosigpipe is set, we want to emulate the Linux action of
	 * not sending a SIGPIPE to the caller if the remote socket has
	 * already been closed.
	 *
	 * As SIGPIPE is a directed signal sent only to the thread that
	 * performed the action, we can emulate this behavior by momentarily
	 * resetting the action for SIGPIPE to SIG_IGN, performing the socket
	 * call, and resetting the action back to its previous value.
	 */
	if (nosigpipe) {
		newact.sa_handler = SIG_IGN;
		newact.sa_flags = 0;
		(void) sigemptyset(&newact.sa_mask);

		if (sigaction(SIGPIPE, &newact, &oact) < 0)
			lx_err_fatal(gettext(
			    "%s: could not ignore SIGPIPE to emulate "
			    "LX_MSG_NOSIGNAL"), "send()");
	}

	r = send(sockfd, buf, len, flags);

	if ((nosigpipe) && (sigaction(SIGPIPE, &oact, NULL) < 0))
		lx_err_fatal(
		    gettext("%s: could not reset SIGPIPE handler to "
		    "emulate LX_MSG_NOSIGNAL"), "send()");

	return ((r < 0) ? -errno : r);
}

static ssize_t
lx_recv(ulong_t *args)
{
	int sockfd = (int)args[0];
	void *buf = (void *)args[1];
	size_t len = (size_t)args[2];
	int flags = (int)args[3];
	ssize_t r;

	int nosigpipe = flags & LX_MSG_NOSIGNAL;
	struct sigaction newact, oact;

	lx_debug("\trecv(%d, 0x%p, 0x%d, 0x%x)", sockfd, buf, len, flags);

	flags = convert_sockflags(flags);

	/*
	 * If nosigpipe is set, we want to emulate the Linux action of
	 * not sending a SIGPIPE to the caller if the remote socket has
	 * already been closed.
	 *
	 * As SIGPIPE is a directed signal sent only to the thread that
	 * performed the action, we can emulate this behavior by momentarily
	 * resetting the action for SIGPIPE to SIG_IGN, performing the socket
	 * call, and resetting the action back to its previous value.
	 */
	if (nosigpipe) {
		newact.sa_handler = SIG_IGN;
		newact.sa_flags = 0;
		(void) sigemptyset(&newact.sa_mask);

		if (sigaction(SIGPIPE, &newact, &oact) < 0)
			lx_err_fatal(gettext(
			    "%s: could not ignore SIGPIPE to emulate "
			    "LX_MSG_NOSIGNAL"), "recv()");
	}

	r = recv(sockfd, buf, len, flags);

	if ((nosigpipe) && (sigaction(SIGPIPE, &oact, NULL) < 0))
		lx_err_fatal(
		    gettext("%s: could not reset SIGPIPE handler to "
		    "emulate LX_MSG_NOSIGNAL"), "recv()");

	return ((r < 0) ? -errno : r);
}

static ssize_t
lx_sendto(ulong_t *args)
{
	int sockfd = (int)args[0];
	void *buf = (void *)args[1];
	size_t len = (size_t)args[2];
	int flags = (int)args[3];
	struct sockaddr *to = NULL, oldto;
	socklen_t tolen = 0;
	ssize_t r;
	int abst_sock;

	int nosigpipe = flags & LX_MSG_NOSIGNAL;
	struct sigaction newact, oact;

	if ((args[4] != NULL) && (args[5] > 0)) {
		if (uucopy((struct sockaddr *)args[4], &oldto,
		    sizeof (struct sockaddr)) != 0)
			return (-errno);

		/* Handle Linux abstract sockets */
		abst_sock = (oldto.sa_family == AF_UNIX) &&
		    (oldto.sa_data[0] == '\0');

		/*
		 * convert_sockaddr will expand the socket path, if it is
		 * abstract, so we need to allocate extra memory for it now.
		 */
		if ((to = SAFE_ALLOCA(args[5] + abst_sock * ABST_PRFX_LEN))
		    == NULL)
			return (-EINVAL);

		if ((r = convert_sockaddr(to, &tolen,
		    (struct sockaddr *)args[4], (socklen_t)args[5])) < 0)
			return (r);
	}


	lx_debug("\tsendto(%d, 0x%p, 0x%d, 0x%x, 0x%x, %d)", sockfd, buf, len,
	    flags, to, tolen);

	flags = convert_sockflags(flags);

	/* return this error to make auditing subsystem happy */
	if (to && to->sa_family == AF_ROUTE) {
		return (-ECONNREFUSED);
	}

	/*
	 * If nosigpipe is set, we want to emulate the Linux action of
	 * not sending a SIGPIPE to the caller if the remote socket has
	 * already been closed.
	 *
	 * As SIGPIPE is a directed signal sent only to the thread that
	 * performed the action, we can emulate this behavior by momentarily
	 * resetting the action for SIGPIPE to SIG_IGN, performing the socket
	 * call, and resetting the action back to its previous value.
	 */
	if (nosigpipe) {
		newact.sa_handler = SIG_IGN;
		newact.sa_flags = 0;
		(void) sigemptyset(&newact.sa_mask);

		if (sigaction(SIGPIPE, &newact, &oact) < 0)
			lx_err_fatal(gettext(
			    "%s: could not ignore SIGPIPE to emulate "
			    "LX_MSG_NOSIGNAL"), "sendto()");
	}

	r = sendto(sockfd, buf, len, flags, to, tolen);

	if ((nosigpipe) && (sigaction(SIGPIPE, &oact, NULL) < 0))
		lx_err_fatal(
		    gettext("%s: could not reset SIGPIPE handler to "
		    "emulate LX_MSG_NOSIGNAL"), "sendto()");

	if (r < 0) {
		/*
		 * according to the man page and LTP, the expected error in
		 * this case is EPIPE.
		 */
		if (errno == ENOTCONN)
			return (-EPIPE);
		else
			return (-errno);
	}
	return (r);
}

static ssize_t
lx_recvfrom(ulong_t *args)
{
	int sockfd = (int)args[0];
	void *buf = (void *)args[1];
	size_t len = (size_t)args[2];
	int flags = (int)args[3];
	struct sockaddr *from = (struct sockaddr *)args[4];
	socklen_t *from_lenp = (socklen_t *)args[5];
	ssize_t r;

	int nosigpipe = flags & LX_MSG_NOSIGNAL;
	struct sigaction newact, oact;

	lx_debug("\trecvfrom(%d, 0x%p, 0x%d, 0x%x, 0x%x, 0x%p)", sockfd, buf,
	    len, flags, from, from_lenp);

	flags = convert_sockflags(flags);

	/*
	 * If nosigpipe is set, we want to emulate the Linux action of
	 * not sending a SIGPIPE to the caller if the remote socket has
	 * already been closed.
	 *
	 * As SIGPIPE is a directed signal sent only to the thread that
	 * performed the action, we can emulate this behavior by momentarily
	 * resetting the action for SIGPIPE to SIG_IGN, performing the socket
	 * call, and resetting the action back to its previous value.
	 */
	if (nosigpipe) {
		newact.sa_handler = SIG_IGN;
		newact.sa_flags = 0;
		(void) sigemptyset(&newact.sa_mask);

		if (sigaction(SIGPIPE, &newact, &oact) < 0)
			lx_err_fatal(gettext(
			    "%s: could not ignore SIGPIPE to emulate "
			    "LX_MSG_NOSIGNAL"), "recvfrom()");
	}

	r = recvfrom(sockfd, buf, len, flags, from, from_lenp);

	if ((nosigpipe) && (sigaction(SIGPIPE, &oact, NULL) < 0))
		lx_err_fatal(
		    gettext("%s: could not reset SIGPIPE handler to "
		    "emulate LX_MSG_NOSIGNAL"), "recvfrom()");

	return ((r < 0) ? -errno : r);
}

static int
lx_shutdown(ulong_t *args)
{
	int sockfd = (int)args[0];
	int how = (int)args[1];
	int r;

	lx_debug("\tshutdown(%d, %d)", sockfd, how);
	r = shutdown(sockfd, how);

	return ((r < 0) ? -errno : r);
}

static int
lx_setsockopt(ulong_t *args)
{
	int sockfd = (int)args[0];
	int level = (int)args[1];
	int optname = (int)args[2];
	void *optval = (void *)args[3];
	int optlen = (int)args[4];
	int internal_opt;
	int r;

	lx_debug("\tsetsockopt(%d, %d, %d, 0x%p, %d)", sockfd, level, optname,
	    optval, optlen);

	/*
	 * The kernel returns EFAULT for all invalid addresses except NULL,
	 * for which it returns EINVAL.  Linux wants EFAULT for NULL too.
	 */
	if (optval == NULL)
		return (-EFAULT);

	/*
	 * Do a table lookup of the Solaris equivalent of the given option
	 */
	if (level < IPPROTO_IP || level >= IPPROTO_TAB_SIZE)
		return (-ENOPROTOOPT);

	if (ltos_proto_opts[level].maxentries == 0 ||
	    optname <= 0 || optname >= (ltos_proto_opts[level].maxentries))
		return (-ENOPROTOOPT);

	/*
	 * Linux sets this option when it wants to send credentials over a
	 * socket. Currently we just ignore it to make Linux programs happy.
	 */
	if ((level == LX_SOL_SOCKET) && (optname == LX_SO_PASSCRED))
		return (0);


	if ((level == IPPROTO_TCP) && (optname == LX_TCP_CORK)) {
		/*
		 * TCP_CORK is a Linux-only option that instructs the TCP
		 * stack not to send out partial frames.  Solaris doesn't
		 * include this option but some apps require it.  So, we do
		 * our best to emulate the option by disabling TCP_NODELAY.
		 * If the app requests that we disable TCP_CORK, we just
		 * ignore it since enabling TCP_NODELAY may be
		 * overcompensating.
		 */
		optname = TCP_NODELAY;
		if (optlen != sizeof (int))
			return (-EINVAL);
		if (uucopy(optval, &internal_opt, sizeof (int)) != 0)
			return (-errno);
		if (internal_opt == 0)
			return (0);
		internal_opt = 1;
		optval = &internal_opt;
	} else {
		optname = ltos_proto_opts[level].proto[optname];

		if (optname == OPTNOTSUP)
			return (-ENOPROTOOPT);
	}

	if (level == LX_SOL_SOCKET)
		level = SOL_SOCKET;

	r = setsockopt(sockfd, level, optname, optval, optlen);

	return ((r < 0) ? -errno : r);
}

static int
lx_getsockopt(ulong_t *args)
{
	int sockfd = (int)args[0];
	int level = (int)args[1];
	int optname = (int)args[2];
	void *optval = (void *)args[3];
	int *optlenp = (int *)args[4];
	int r;

	lx_debug("\tgetsockopt(%d, %d, %d, 0x%p, 0x%p)", sockfd, level, optname,
	    optval, optlenp);

	/*
	 * According to the Linux man page, a NULL optval should indicate
	 * (as in Solaris) that no return value is expected.  Instead, it
	 * actually triggers an EFAULT error.
	 */
	if (optval == NULL)
		return (-EFAULT);

	/*
	 * Do a table lookup of the Solaris equivalent of the given option
	 */
	if (level < IPPROTO_IP || level >= IPPROTO_TAB_SIZE)
		return (-EOPNOTSUPP);

	if (ltos_proto_opts[level].maxentries == 0 ||
	    optname <= 0 || optname >= (ltos_proto_opts[level].maxentries))
		return (-ENOPROTOOPT);

	if ((level == LX_SOL_SOCKET) && (optname == LX_SO_PASSCRED) ||
	    (level == IPPROTO_TCP) && (optname == LX_TCP_CORK)) {
		/*
		 * Linux sets LX_SO_PASSCRED when it wants to send credentials
		 * over a socket. Since we do not support it, it is never set
		 * and we return 0.
		 *
		 * We don't support TCP_CORK but some apps rely on it.  So,
		 * rather than return an error we just return 0.  This
		 * isn't exactly a lie, since this option really isn't set,
		 * but it's not the whole truth either.  Fortunately, we
		 * aren't under oath.
		 */
		r = 0;
		if (uucopy(&r, optval, sizeof (int)) != 0)
			return (-errno);
		r = sizeof (int);
		if (uucopy(&r, optlenp, sizeof (int)) != 0)
			return (-errno);
		return (0);
	}
	if ((level == LX_SOL_SOCKET) && (optname == LX_SO_PEERCRED)) {
		struct lx_ucred	lx_ucred;
		ucred_t		*ucp;

		/*
		 * We don't support SO_PEERCRED, but we do have equivalent
		 * functionality in getpeerucred() so invoke that here.
		 */

		/* Verify there's going to be enough room for the results. */
		if (uucopy(optlenp, &r, sizeof (int)) != 0)
			return (-errno);
		if (r < sizeof (struct lx_ucred))
			return (-EOVERFLOW);

		/*
		 * We allocate a ucred_t ourselves rather than allow
		 * getpeerucred() to do it for us because getpeerucred()
		 * uses malloc(3C) and we'd rather use SAFE_ALLOCA().
		 */
		if ((ucp = (ucred_t *)SAFE_ALLOCA(ucred_size())) == NULL)
			return (-ENOMEM);

		/* Get the credential for the remote end of this socket. */
		if (getpeerucred(sockfd, &ucp) != 0)
			return (-errno);
		if (((lx_ucred.lxu_pid = ucred_getpid(ucp)) == -1) ||
		    ((lx_ucred.lxu_uid = ucred_geteuid(ucp)) == (uid_t)-1) ||
		    ((lx_ucred.lxu_gid = ucred_getegid(ucp)) == (gid_t)-1)) {
			return (-errno);
		}

		/* Copy out the results. */
		if ((uucopy(&lx_ucred, optval, sizeof (lx_ucred))) != 0)
			return (-errno);
		r = sizeof (lx_ucred);
		if ((uucopy(&r, optlenp, sizeof (int))) != 0)
			return (-errno);
		return (0);
	}

	optname = ltos_proto_opts[level].proto[optname];

	if (optname == OPTNOTSUP)
		return (-ENOPROTOOPT);

	if (level == LX_SOL_SOCKET)
		level = SOL_SOCKET;

	r = getsockopt(sockfd, level, optname, optval, optlenp);

	return ((r < 0) ? -errno : r);
}

/*
 * libc routines that issue these system calls.  We bypass the libsocket
 * wrappers since they explicitly turn off the MSG_XPG_2 flag we need for
 * Linux compatibility.
 */
extern int _so_sendmsg();
extern int _so_recvmsg();

static int
lx_sendmsg(ulong_t *args)
{
	int sockfd = (int)args[0];
	struct lx_msghdr msg;
	struct cmsghdr *cmsg;
	int flags = (int)args[2];
	int r;

	int nosigpipe = flags & LX_MSG_NOSIGNAL;
	struct sigaction newact, oact;

	lx_debug("\tsendmsg(%d, 0x%p, 0x%x)", sockfd, (void *)args[1], flags);

	flags = convert_sockflags(flags);

	if ((uucopy((void *)args[1], &msg, sizeof (msg))) != 0)
		return (-errno);

	/*
	 * If there are control messages bundled in this message, we need
	 * to convert them from Linux to Solaris.
	 */
	if (msg.msg_control != NULL) {
		if (msg.msg_controllen == 0) {
			cmsg = NULL;
		} else {
			cmsg = SAFE_ALLOCA(msg.msg_controllen);
			if (cmsg == NULL)
				return (-EINVAL);
		}
		if ((uucopy(msg.msg_control, cmsg, msg.msg_controllen)) != 0)
			return (-errno);
		msg.msg_control = cmsg;
		if ((r = convert_cmsgs(LX_TO_SOL, &msg, "sendmsg()")) != 0)
			return (-r);
	}

	/*
	 * If nosigpipe is set, we want to emulate the Linux action of
	 * not sending a SIGPIPE to the caller if the remote socket has
	 * already been closed.
	 *
	 * As SIGPIPE is a directed signal sent only to the thread that
	 * performed the action, we can emulate this behavior by momentarily
	 * resetting the action for SIGPIPE to SIG_IGN, performing the socket
	 * call, and resetting the action back to its previous value.
	 */
	if (nosigpipe) {
		newact.sa_handler = SIG_IGN;
		newact.sa_flags = 0;
		(void) sigemptyset(&newact.sa_mask);

		if (sigaction(SIGPIPE, &newact, &oact) < 0)
			lx_err_fatal(gettext(
			    "%s: could not ignore SIGPIPE to emulate "
			    "LX_MSG_NOSIGNAL"), "sendmsg()");
	}

	r = _so_sendmsg(sockfd, (struct msghdr *)&msg, flags | MSG_XPG4_2);

	if ((nosigpipe) && (sigaction(SIGPIPE, &oact, NULL) < 0))
		lx_err_fatal(
		    gettext("%s: could not reset SIGPIPE handler to "
		    "emulate LX_MSG_NOSIGNAL"), "sendmsg()");

	if (r < 0) {
		/*
		 * according to the man page and LTP, the expected error in
		 * this case is EPIPE.
		 */
		if (errno == ENOTCONN)
			return (-EPIPE);
		else
			return (-errno);
	}

	return (r);
}

static int
lx_recvmsg(ulong_t *args)
{
	int sockfd = (int)args[0];
	struct lx_msghdr msg;
	struct lx_msghdr *msgp = (struct lx_msghdr *)args[1];
	struct cmsghdr *cmsg;
	int flags = (int)args[2];
	int r, err;

	int nosigpipe = flags & LX_MSG_NOSIGNAL;
	struct sigaction newact, oact;

	lx_debug("\trecvmsg(%d, 0x%p, 0x%x)", sockfd, (void *)args[1], flags);

	flags = convert_sockflags(flags);

	if ((uucopy(msgp, &msg, sizeof (msg))) != 0)
		return (-errno);

	/*
	 * If we are expecting to have to convert any control messages,
	 * then we should receive them into our address space instead of
	 * the app's.
	 */
	if (msg.msg_control != NULL) {
		cmsg = msg.msg_control;
		if (msg.msg_controllen == 0) {
			msg.msg_control = NULL;
		} else {
			msg.msg_control = SAFE_ALLOCA(msg.msg_controllen);
			if (msg.msg_control == NULL)
				return (-EINVAL);
		}
	}

	/*
	 * If nosigpipe is set, we want to emulate the Linux action of
	 * not sending a SIGPIPE to the caller if the remote socket has
	 * already been closed.
	 *
	 * As SIGPIPE is a directed signal sent only to the thread that
	 * performed the action, we can emulate this behavior by momentarily
	 * resetting the action for SIGPIPE to SIG_IGN, performing the socket
	 * call, and resetting the action back to its previous value.
	 */
	if (nosigpipe) {
		newact.sa_handler = SIG_IGN;
		newact.sa_flags = 0;
		(void) sigemptyset(&newact.sa_mask);

		if (sigaction(SIGPIPE, &newact, &oact) < 0)
			lx_err_fatal(gettext(
			    "%s: could not ignore SIGPIPE to emulate "
			    "LX_MSG_NOSIGNAL"), "recvmsg()");
	}

	r = _so_recvmsg(sockfd, (struct msghdr *)&msg, flags | MSG_XPG4_2);

	if ((nosigpipe) && (sigaction(SIGPIPE, &oact, NULL) < 0))
		lx_err_fatal(
		    gettext("%s: could not reset SIGPIPE handler to "
		    "emulate LX_MSG_NOSIGNAL"), "recvmsg()");

	if (r >= 0 && msg.msg_control != NULL) {
		/*
		 * If there are control messages bundled in this message,
		 * we need to convert them from Linux to Solaris.
		 */
		if ((err = convert_cmsgs(SOL_TO_LX, &msg, "recvmsg()")) != 0)
			return (-err);

		if ((uucopy(msg.msg_control, cmsg, msg.msg_controllen)) != 0)
			return (-errno);
	}

	/*
	 * A handful of the values in the msghdr are set by the recvmsg()
	 * call, so copy their values back to the caller.  Rather than iterate,
	 * just copy the whole structure back.
	 */
	if (uucopy(&msg, msgp, sizeof (msg)) != 0)
		return (-errno);

	return ((r < 0) ? -errno : r);
}

int
lx_socketcall(uintptr_t p1, uintptr_t p2)
{
	int subcmd = (int)p1 - 1; /* subcommands start at 1 - not 0 */
	ulong_t args[6];
	int r;

	if (subcmd < 0 || subcmd >= LX_RECVMSG)
		return (-EINVAL);

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
