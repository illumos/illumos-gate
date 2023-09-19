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
 * Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2022 Joyent, Inc.
 */

#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/sockio.h>
#include <sys/thread.h>
#include <sys/stropts.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/kmem.h>
#include <sys/un.h>
#include <sys/sunddi.h>
#include <sys/cred.h>
#include <sys/ucred.h>
#include <sys/model.h>
#include <sys/brand.h>
#include <sys/vmsystm.h>
#include <sys/limits.h>
#include <sys/fcntl.h>
#include <sys/sysmacros.h>
#include <netpacket/packet.h>
#include <sockcommon.h>
#include <socktpi_impl.h>
#include <netinet/udp.h>
#include <sys/sdt.h>
#include <netinet/tcp.h>
#include <netinet/igmp.h>
#include <netinet/icmp6.h>
#include <inet/cc.h>
#include <inet/tcp_impl.h>
#include <lx_errno.h>

#include <sys/lx_brand.h>
#include <sys/lx_socket.h>
#include <sys/lx_types.h>
#include <sys/lx_impl.h>

/* From uts/common/fs/sockfs/socksyscalls.c */
extern int listen(int, int, int);
extern int shutdown(int, int, int);

typedef struct lx_ucred {
	pid_t		lxu_pid;
	lx_uid_t	lxu_uid;
	lx_gid_t	lxu_gid;
} lx_ucred_t;

typedef struct lx_socket_aux_data
{
	kmutex_t lxsad_lock;
	enum lxsad_status_t {
		LXSS_NONE = 0,
		LXSS_CONNECTING,
		LXSS_CONNECTED
	} lxsad_status;
	uint_t lxsad_flags;
} lx_socket_aux_data_t;

#define	LX_SS_MAXSIZE	128

typedef struct lx_sockaddr_storage {
	unsigned short	lxss_family;
	char		lxdata[LX_SS_MAXSIZE - sizeof (unsigned short)];
} lx_sockaddr_storage_t;

typedef struct lx_group_req {
	uint32_t	lxgr_interface;
#ifdef _LP64
	/* On 64-bit linux kernels, gr_interface is padded by 4 bytes. */
	uint32_t	_lxgr_pad;
#endif
	lx_sockaddr_storage_t	lxgr_group;
} lx_group_req_t;

#if defined(_SYSCALL32_IMPL)

typedef struct lx_group_req32 {
	uint32_t		lxgr_interface;
	lx_sockaddr_storage_t	lxgr_group;
} lx_group_req32_t;

#endif /* defined(_SYSCALL32_IMPL) */

/* lxsad_flags */
#define	LXSAD_FL_STRCRED	0x1
#define	LXSAD_FL_EMULSEQPKT	0x2
/* These two work together to implement Linux SO_REUSEADDR semantics. */
#define	LXSAD_FL_EMULRUADDR	0x4
#define	LXSAD_FL_EMULRUPORT	0x8

static lx_socket_aux_data_t *lx_sad_acquire(vnode_t *);

/* VSD key for lx-specific socket information */
static uint_t lx_socket_vsd = 0;

/* Convenience enum to enforce translation direction */
typedef enum lx_xlate_dir {
	SUNOS_TO_LX,
	LX_TO_SUNOS
} lx_xlate_dir_t;

/* enum for getpeername/getsockname handling */
typedef enum lx_getname_type {
	LX_GETPEERNAME,
	LX_GETSOCKNAME
} lx_getname_type_t;

/*
 * What follows are a series of tables we use to translate Linux constants
 * into equivalent Illumos constants and back again.  I wish this were
 * cleaner, more programmatic, and generally nicer.  Sadly, life is messy,
 * and Unix networking even more so.
 */
static const int ltos_family[LX_AF_MAX + 1] =  {
	AF_UNSPEC,		/* LX_AF_UNSPEC		*/
	AF_UNIX,		/* LX_AF_UNIX		*/
	AF_INET,		/* LX_AF_INET		*/
	AF_NOTSUPPORTED,	/* LX_AF_AX25		*/
	AF_NOTSUPPORTED,	/* LX_AF_IPX		*/
	AF_NOTSUPPORTED,	/* LX_AF_APPLETALK	*/
	AF_NOTSUPPORTED,	/* LX_AF_NETROM		*/
	AF_NOTSUPPORTED,	/* LX_AF_BRIDGE		*/
	AF_NOTSUPPORTED,	/* LX_AF_ATMPVC		*/
	AF_NOTSUPPORTED,	/* LX_AF_X25		*/
	AF_INET6,		/* LX_AF_INET6		*/
	AF_NOTSUPPORTED,	/* LX_AF_ROSE		*/
	AF_NOTSUPPORTED,	/* LX_AF_DECNET		*/
	AF_NOTSUPPORTED,	/* LX_AF_NETBEUI	*/
	AF_NOTSUPPORTED,	/* LX_AF_SECURITY	*/
	AF_NOTSUPPORTED,	/* LX_AF_KEY		*/
	AF_LX_NETLINK,		/* LX_AF_NETLINK	*/
	AF_PACKET,		/* LX_AF_PACKET		*/
	AF_NOTSUPPORTED,	/* LX_AF_ASH		*/
	AF_NOTSUPPORTED,	/* LX_AF_ECONET		*/
	AF_NOTSUPPORTED,	/* LX_AF_ATMSVC		*/
	AF_NOTSUPPORTED,	/* LX_AF_RDS		*/
	AF_NOTSUPPORTED,	/* LX_AF_SNA		*/
	AF_NOTSUPPORTED,	/* LX_AF_IRDA		*/
	AF_NOTSUPPORTED,	/* LX_AF_PPOX		*/
	AF_NOTSUPPORTED,	/* LX_AF_WANPIPE	*/
	AF_NOTSUPPORTED,	/* LX_AF_LLC		*/
	AF_NOTSUPPORTED,	/* NONE			*/
	AF_NOTSUPPORTED,	/* NONE			*/
	AF_NOTSUPPORTED,	/* LX_AF_CAN		*/
	AF_NOTSUPPORTED,	/* LX_AF_TIPC		*/
	AF_NOTSUPPORTED,	/* LX_AF_BLUETOOTH	*/
	AF_NOTSUPPORTED,	/* LX_AF_IUCV		*/
	AF_NOTSUPPORTED		/* LX_AF_RXRPC		*/
				/* LX_AF_ISDN		*/
				/* LX_AF_PHONET		*/
				/* LX_AF_IEEE802154	*/
				/* LX_AF_CAIF		*/
				/* LX_AF_ALG		*/
				/* LX_AF_NFC		*/
				/* LX_AF_VSOCK		*/
};

static const int stol_family[LX_AF_MAX + 1] =  {
	AF_UNSPEC,		/* AF_UNSPEC		*/
	AF_UNIX,		/* AF_UNIX		*/
	AF_INET,		/* AF_INET		*/
	AF_NOTSUPPORTED,	/* AF_IMPLINK		*/
	AF_NOTSUPPORTED,	/* AF_PUP		*/
	AF_NOTSUPPORTED,	/* AF_CHAOS		*/
	AF_NOTSUPPORTED,	/* AF_NS		*/
	AF_NOTSUPPORTED,	/* AF_NBS		*/
	AF_NOTSUPPORTED,	/* AF_ECMA		*/
	AF_NOTSUPPORTED,	/* AF_DATAKIT		*/
	AF_NOTSUPPORTED,	/* AF_CCITT		*/
	AF_NOTSUPPORTED,	/* AF_SNA		*/
	AF_NOTSUPPORTED,	/* AF_DECNET		*/
	AF_NOTSUPPORTED,	/* AF_DLI		*/
	AF_NOTSUPPORTED,	/* AF_LAT		*/
	AF_NOTSUPPORTED,	/* AF_HYLINK		*/
	AF_NOTSUPPORTED,	/* AF_APPLETALK		*/
	AF_NOTSUPPORTED,	/* AF_NIT		*/
	AF_NOTSUPPORTED,	/* AF_802		*/
	AF_NOTSUPPORTED,	/* AF_OSI		*/
	AF_NOTSUPPORTED,	/* AF_X25		*/
	AF_NOTSUPPORTED,	/* AF_OSINET		*/
	AF_NOTSUPPORTED,	/* AF_GOSIP		*/
	AF_NOTSUPPORTED,	/* AF_IPX		*/
	AF_NOTSUPPORTED,	/* AF_ROUTE		*/
	AF_NOTSUPPORTED,	/* AF_LINK		*/
	LX_AF_INET6,		/* AF_INET6		*/
	AF_NOTSUPPORTED,	/* AF_KEY		*/
	AF_NOTSUPPORTED,	/* AF_NCA		*/
	AF_NOTSUPPORTED,	/* AF_POLICY		*/
	AF_NOTSUPPORTED,	/* AF_INET_OFFLOAD	*/
	AF_NOTSUPPORTED,	/* AF_TRILL		*/
	LX_AF_PACKET,		/* AF_PACKET		*/
	LX_AF_NETLINK		/* AF_LX_NETLINK	*/
};

#define	LTOS_FAMILY(d) ((d) <= LX_AF_MAX ? ltos_family[(d)] : AF_INVAL)
#define	STOL_FAMILY(d) ((d) <= LX_AF_MAX ? stol_family[(d)] : AF_INVAL)


static const int ltos_socktype[LX_SOCK_PACKET + 1] = {
	SOCK_NOTSUPPORTED, SOCK_STREAM, SOCK_DGRAM, SOCK_RAW,
	SOCK_RDM, SOCK_SEQPACKET, SOCK_NOTSUPPORTED, SOCK_NOTSUPPORTED,
	SOCK_NOTSUPPORTED, SOCK_NOTSUPPORTED, SOCK_NOTSUPPORTED
};

static const int stol_socktype[SOCK_SEQPACKET + 1] = {
	SOCK_NOTSUPPORTED, LX_SOCK_DGRAM, LX_SOCK_STREAM, SOCK_NOTSUPPORTED,
	LX_SOCK_RAW, LX_SOCK_RDM, LX_SOCK_SEQPACKET
};

#define	LTOS_SOCKTYPE(t)	\
	((t) <= LX_SOCK_PACKET ? ltos_socktype[(t)] : SOCK_INVAL)
#define	STOL_SOCKTYPE(t)	\
	((t) <= SOCK_SEQPACKET ? stol_socktype[(t)] : SOCK_INVAL)


/*
 * This string is used to prefix all abstract namespace Unix sockets, ie all
 * abstract namespace sockets are converted to regular sockets in the /tmp
 * directory with .ABSK_ prefixed to their names.
 */
#define	ABST_PRFX "/tmp/.ABSK_"
#define	ABST_PRFX_LEN (sizeof (ABST_PRFX) - 1)

#define	DATAFILT	"datafilt"

typedef enum {
	lxa_none,
	lxa_abstract,
	lxa_devlog
} lx_addr_type_t;

static int
ltos_pkt_proto(int protocol)
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


typedef struct lx_flag_map {
	enum {
		LXFM_MAP,
		LXFM_IGNORE,
		LXFM_UNSUP
	} lxfm_action;
	int lxfm_sunos_flag;
	int lxfm_linux_flag;
	char *lxfm_name;
} lx_flag_map_t;

static lx_flag_map_t lx_flag_map_tbl[] = {
	{ LXFM_MAP,	MSG_OOB,		LX_MSG_OOB,		NULL },
	{ LXFM_MAP,	MSG_PEEK,		LX_MSG_PEEK,		NULL },
	{ LXFM_MAP,	MSG_DONTROUTE,		LX_MSG_DONTROUTE,	NULL },
	{ LXFM_MAP,	MSG_CTRUNC,		LX_MSG_CTRUNC,		NULL },
	{ LXFM_MAP,	MSG_TRUNC,		LX_MSG_TRUNC,		NULL },
	{ LXFM_MAP,	MSG_DONTWAIT,		LX_MSG_DONTWAIT,	NULL },
	{ LXFM_MAP,	MSG_EOR,		LX_MSG_EOR,		NULL },
	{ LXFM_MAP,	MSG_WAITALL,		LX_MSG_WAITALL,		NULL },
	/* MSG_CONFIRM is safe to ignore */
	{ LXFM_IGNORE,	0,			LX_MSG_CONFIRM,		NULL },
	/*
	 * The NOSIGNAL and CMSG_CLOEXEC flags are handled by the emulation
	 * outside of the flag-conversion routine.
	 */
	{ LXFM_IGNORE,	0,			LX_MSG_NOSIGNAL,	NULL },
	{ LXFM_IGNORE,	0,			LX_MSG_CMSG_CLOEXEC,	NULL },
	{ LXFM_UNSUP,	LX_MSG_PROXY,		0,	"MSG_PROXY" },
	{ LXFM_UNSUP,	LX_MSG_FIN,		0,	"MSG_FIN" },
	{ LXFM_UNSUP,	LX_MSG_SYN,		0,	"MSG_SYN" },
	{ LXFM_UNSUP,	LX_MSG_RST,		0,	"MSG_RST" },
	{ LXFM_UNSUP,	LX_MSG_ERRQUEUE,	0,	"MSG_ERRQUEUE" },
	{ LXFM_UNSUP,	LX_MSG_MORE,		0,	"MSG_MORE" },
	{ LXFM_UNSUP,	LX_MSG_WAITFORONE,	0,	"MSG_WAITFORONE" },
	{ LXFM_UNSUP,	LX_MSG_FASTOPEN,	0,	"MSG_FASTOPEN" },
};

#define	LX_FLAG_MAP_MAX	\
	(sizeof (lx_flag_map_tbl) / sizeof (lx_flag_map_tbl[0]))

#define	LX_UNSUP_BUFSZ	64

static int
lx_xlate_sock_flags(int inflags, lx_xlate_dir_t dir)
{
	int i, outflags = 0;
	char buf[LX_UNSUP_BUFSZ];

	VERIFY(dir == SUNOS_TO_LX || dir == LX_TO_SUNOS);

	for (i = 0; i < LX_FLAG_MAP_MAX; i++) {
		lx_flag_map_t *map = &lx_flag_map_tbl[i];
		int match, out;

		if (dir == SUNOS_TO_LX) {
			match = inflags & map->lxfm_sunos_flag;
			out = map->lxfm_linux_flag;
		} else {
			match = inflags & map->lxfm_linux_flag;
			out = map->lxfm_sunos_flag;
		}
		switch (map->lxfm_action) {
		case LXFM_MAP:
			if (match != 0) {
				inflags &= ~(match);
				outflags |= out;
			}
			break;
		case LXFM_IGNORE:
			if (match != 0) {
				inflags &= ~(match);
			}
			break;
		case LXFM_UNSUP:
			if (match != 0) {
				(void) snprintf(buf, LX_UNSUP_BUFSZ,
				    "unsupported sock flag %s", map->lxfm_name);
				lx_unsupported(buf);
			}
		}
	}
	if (inflags != 0) {
		(void) snprintf(buf, LX_UNSUP_BUFSZ,
		    "unsupported sock flags 0x%08x", inflags);
		lx_unsupported(buf);
	}

	return (outflags);
}

typedef enum lx_sun_type {
	LX_SUN_NORMAL,
	LX_SUN_ABSTRACT,
} lx_sun_type_t;

static void
ltos_sockaddr_ux(const struct sockaddr *inaddr, const socklen_t inlen,
    struct sockaddr **outaddr, socklen_t *outlen, lx_sun_type_t *sun_type)
{
	struct sockaddr_un buf;
	/* Calculate size of (sun_family + any padding) in sockaddr */
	int sizediff = (sizeof (buf) - sizeof (buf.sun_path));
	int len = inlen - sizediff;

	VERIFY(len > 0);
	VERIFY(len <= sizeof (buf.sun_path));
	bzero(&buf, sizeof (buf));

	if (inaddr->sa_data[0] == '\0') {
		/*
		 * Linux supports abstract Unix sockets, which are simply
		 * sockets that do not exist on the file system.  These sockets
		 * are denoted by beginning the path with a NULL character. To
		 * support these, we strip out the leading NULL character and
		 * change the path to point to a real place in /tmp directory,
		 * by prepending ABST_PRFX and replacing all illegal characters
		 * with * '_'.
		 *
		 * Since these sockets are supposed to exist outside the
		 * filesystem, they must be cleaned up after use.  This removal
		 * is performed during bind().
		 */
		int idx, odx;

		/* Add our abstract prefix */
		(void) strcpy(buf.sun_path, ABST_PRFX);
		for (idx = 1, odx = ABST_PRFX_LEN;
		    idx < len && odx < sizeof (buf.sun_path);
		    idx++, odx++) {
			char c = inaddr->sa_data[idx];
			if (c == '\0' || c == '/') {
				buf.sun_path[odx] = '_';
			} else {
				buf.sun_path[odx] = c;
			}
		}

		/*
		 * Since abstract socket addresses might not be NUL terminated,
		 * we must explicitly NUL terminate the translated path.
		 * Care is taken not to overflow the buffer.
		 */
		if (odx == sizeof (buf.sun_path)) {
			buf.sun_path[odx - 1] = '\0';
		} else {
			buf.sun_path[odx] = '\0';
		}

		if (sun_type != NULL) {
			*sun_type = LX_SUN_ABSTRACT;
		}
	} else {
		/* Copy the address directly, minding termination */
		(void) strncpy(buf.sun_path, inaddr->sa_data, len);
		len = strnlen(buf.sun_path, len);
		if (len == sizeof (buf.sun_path)) {
			buf.sun_path[len - 1] = '\0';
		} else {
			VERIFY(len < sizeof (buf.sun_path));
			buf.sun_path[len] = '\0';
		}

		if (sun_type != NULL) {
			*sun_type = LX_SUN_NORMAL;
		}
	}
	buf.sun_family = AF_UNIX;
	*outlen = strlen(buf.sun_path) + 1 + sizediff;
	VERIFY(*outlen <= sizeof (struct sockaddr_un));

	*outaddr = kmem_alloc(*outlen, KM_SLEEP);
	bcopy(&buf, *outaddr, *outlen);
}

/*
 * Copy in a Linux-native socket address from userspace and convert it into
 * illumos format.  When successful, it will allocate an appropriately sized
 * struct to be freed by the caller.
 */
static long
ltos_sockaddr_copyin(const struct sockaddr *inaddr, const socklen_t inlen,
    struct sockaddr **outaddr, socklen_t *outlen, lx_sun_type_t *sun_type)
{
	sa_family_t family;
	struct sockaddr *laddr;
	struct sockaddr_ll *sal;
	int proto, error = 0;

	VERIFY(inaddr != NULL);

	if (inlen < sizeof (sa_family_t) ||
	    inlen > sizeof (struct sockaddr_storage)) {
		return (EINVAL);
	}
	laddr = kmem_alloc(inlen, KM_SLEEP);
	if (copyin(inaddr, laddr, inlen) != 0) {
		kmem_free(laddr, inlen);
		return (EFAULT);
	}

	family = LTOS_FAMILY(laddr->sa_family);
	switch (family) {
		case (sa_family_t)AF_NOTSUPPORTED:
			error = EPROTONOSUPPORT;
			break;

		case (sa_family_t)AF_INVAL:
			error = EAFNOSUPPORT;
			break;

		case AF_UNIX:
			if (inlen < sizeof (sa_family_t) + 2 ||
			    inlen > sizeof (struct sockaddr_un)) {
				error = EINVAL;
				break;
			}
			ltos_sockaddr_ux(laddr, inlen, outaddr, outlen,
			    sun_type);

			/* AF_UNIX bypasses the standard copy logic */
			kmem_free(laddr, inlen);
			return (0);

		case AF_PACKET:
			if (inlen < sizeof (struct sockaddr_ll)) {
				error = EINVAL;
				break;
			}
			*outlen = sizeof (struct sockaddr_ll);

			/* sll_protocol must be translated */
			/* LINTED: alignment */
			sal = (struct sockaddr_ll *)laddr;
			proto = ltos_pkt_proto(sal->sll_protocol);
			if (proto < 0) {
				error = EINVAL;
			}
			sal->sll_protocol = proto;
			break;

		case AF_INET:
			if (inlen < sizeof (struct sockaddr)) {
				error = EINVAL;
				break;
			}
			*outlen = sizeof (struct sockaddr);
			break;

		case AF_INET6:
			/*
			 * The illumos sockaddr_in6 has one more 32-bit field
			 * than the Linux version.  We simply zero that field
			 * via kmem_zalloc.
			 */
			if (inlen < sizeof (lx_sockaddr_in6_t)) {
				error = EINVAL;
				break;
			}
			*outlen = sizeof (struct sockaddr_in6);
			*outaddr = (struct sockaddr *)kmem_zalloc(*outlen,
			    KM_SLEEP);
			bcopy(laddr, *outaddr, sizeof (lx_sockaddr_in6_t));
			(*outaddr)->sa_family = AF_INET6;
			/* AF_INET6 bypasses the standard copy logic */
			kmem_free(laddr, inlen);
			return (0);

		default:
			*outlen = inlen;
	}

	if (error == 0) {
		/*
		 * For most address families, just copying into a sockaddr of
		 * the correct size and updating sa_family is adequate.
		 */
		VERIFY(inlen >= *outlen);

		*outaddr = (struct sockaddr *)kmem_zalloc(*outlen, KM_SLEEP);
		bcopy(laddr, *outaddr, *outlen);
		(*outaddr)->sa_family = family;
	}
	kmem_free(laddr, inlen);
	return (error);
}

/*
 * Convert an illumos-native socket address into Linux format and copy it out
 * to userspace.
 */
static long
stol_sockaddr_copyout(struct sockaddr *inaddr, socklen_t inlen,
    struct sockaddr *outaddr, void *outlenp, socklen_t orig)
{
	socklen_t size = inlen;
	struct sockaddr_storage buf;
	struct sockaddr *bufaddr;

	/*
	 * Either we were passed a valid sockaddr (with length) or the length
	 * is set to 0.
	 */
	VERIFY(inaddr != NULL || inlen == 0);

	if (inlen == 0) {
		goto finish;
	}


	switch (inaddr->sa_family) {
	case AF_INET:
		if (inlen != sizeof (struct sockaddr)) {
			return (EINVAL);
		}
		break;

	case AF_INET6:
		if (inlen != sizeof (struct sockaddr_in6)) {
			return (EINVAL);
		}
		/*
		 * The linux sockaddr_in6 is shorter than illumos.
		 * Truncate the extra field on the way out.
		 */
		size = (sizeof (lx_sockaddr_in6_t));
		inlen = (sizeof (lx_sockaddr_in6_t));
		break;

	case AF_UNIX:
		if (inlen > sizeof (struct sockaddr_un)) {
			return (EINVAL);
		}

		/*
		 * On Linux an empty AF_UNIX address is returned as NULL, which
		 * means setting the returned length to only encompass the
		 * address family part of the buffer. However, some code also
		 * references the address portion of the buffer and uses it,
		 * even though the returned length has been shortened. Thus, we
		 * clear the buffer to ensure that the address portion is NULL.
		 */
		if (inaddr->sa_data[0] == '\0') {
			bzero(&buf, sizeof (buf));
			inlen = sizeof (inaddr->sa_family);
		}
		break;

	case (sa_family_t)AF_NOTSUPPORTED:
		return (EPROTONOSUPPORT);

	case (sa_family_t)AF_INVAL:
		return (EAFNOSUPPORT);

	default:
		break;
	}

	/*
	 * The input should be smaller than sockaddr_storage, the largest
	 * sockaddr we support.
	 */
	VERIFY(inlen <= sizeof (buf));

	bufaddr = (struct sockaddr *)&buf;
	bcopy(inaddr, bufaddr, inlen);
	bufaddr->sa_family = STOL_FAMILY(bufaddr->sa_family);

	/*
	 * It is possible that userspace passed us a smaller buffer than we
	 * hope to output.  When this is the case, we will truncate our output
	 * to the max size of their buffer but report the true size of the
	 * sockaddr when outputting the outlen value.
	 */
	size = (orig < size) ? orig : size;

	if (copyout(bufaddr, outaddr, size) != 0) {
		return (EFAULT);
	}

finish:
#if defined(_LP64)
	if (get_udatamodel() != DATAMODEL_NATIVE) {
		int32_t len32 = (int32_t)inlen;
		if (copyout(&len32, outlenp, sizeof (len32)) != 0) {
			return (EFAULT);
		}
	} else
#endif /* defined(_LP64) */
	{
		if (copyout(&inlen, outlenp, sizeof (inlen)) != 0) {
			return (EFAULT);
		}
	}

	return (0);
}

typedef struct lx_cmsg_xlate {
	int lcx_sunos_level;
	int lcx_sunos_type;
	int (*lcx_stol_conv)(struct cmsghdr *, struct cmsghdr *);
	int lcx_linux_level;
	int lcx_linux_type;
	int (*lcx_ltos_conv)(struct cmsghdr *, struct cmsghdr *);
} lx_cmsg_xlate_t;

static int cmsg_conv_generic(struct cmsghdr *, struct cmsghdr *);
static int stol_conv_ucred(struct cmsghdr *, struct cmsghdr *);
static int ltos_conv_ucred(struct cmsghdr *, struct cmsghdr *);
static int stol_conv_recvttl(struct cmsghdr *, struct cmsghdr *);

/*
 * Table describing SunOS <-> Linux cmsg translation mappings.
 * Certain types (IP_RECVTTL) are only converted in one direction and are
 * indicated by one of the translation functions being set to NULL.
 */
static lx_cmsg_xlate_t lx_cmsg_xlate_tbl[] = {
	{ SOL_SOCKET, SCM_RIGHTS, cmsg_conv_generic,
	    LX_SOL_SOCKET, LX_SCM_RIGHTS, cmsg_conv_generic },
	{ SOL_SOCKET, SCM_UCRED, stol_conv_ucred,
	    LX_SOL_SOCKET, LX_SCM_CRED, ltos_conv_ucred },
	{ SOL_SOCKET, SCM_TIMESTAMP, cmsg_conv_generic,
	    LX_SOL_SOCKET, LX_SCM_TIMESTAMP, cmsg_conv_generic },
	{ IPPROTO_IP, IP_PKTINFO, cmsg_conv_generic,
	    LX_IPPROTO_IP, LX_IP_PKTINFO, cmsg_conv_generic },
	{ IPPROTO_IP, IP_RECVTTL, stol_conv_recvttl,
	    LX_IPPROTO_IP, LX_IP_TTL, NULL },
	{ IPPROTO_IP, IP_RECVTOS, cmsg_conv_generic,
	    LX_IPPROTO_IP, LX_IP_TOS, cmsg_conv_generic },
	{ IPPROTO_IP, IP_TTL, cmsg_conv_generic,
	    LX_IPPROTO_IP, LX_IP_TTL, cmsg_conv_generic },
	{ IPPROTO_IPV6, IPV6_HOPLIMIT, cmsg_conv_generic,
	    LX_IPPROTO_IPV6, LX_IPV6_HOPLIMIT, cmsg_conv_generic },
	{ IPPROTO_IPV6, IPV6_PKTINFO, cmsg_conv_generic,
	    LX_IPPROTO_IPV6, LX_IPV6_PKTINFO, cmsg_conv_generic },
	{ IPPROTO_IPV6, IPV6_TCLASS, cmsg_conv_generic,
	    LX_IPPROTO_IPV6, LX_IPV6_TCLASS, cmsg_conv_generic }
};

#define	LX_MAX_CMSG_XLATE	\
	(sizeof (lx_cmsg_xlate_tbl) / sizeof (lx_cmsg_xlate_tbl[0]))

#if defined(_LP64)

typedef struct {
	int64_t	cmsg_len;
	int32_t	cmsg_level;
	int32_t	cmsg_type;
} lx_cmsghdr64_t;

/* The alignment/padding for 64bit Linux cmsghdr is not the same. */
#define	LX_CMSG64_ALIGNMENT	8
#define	ISALIGNED_LX_CMSG64(addr)					\
	(((uintptr_t)(addr) & (LX_CMSG64_ALIGNMENT - 1)) == 0)
#define	ROUNDUP_LX_CMSG64_LEN(len)					\
	(((len) + LX_CMSG64_ALIGNMENT - 1) & ~(LX_CMSG64_ALIGNMENT - 1))

#define	LX_CMSG64_IS_ALIGNED(m)			\
	(((uintptr_t)(m) & (_CMSG_DATA_ALIGNMENT - 1)) == 0)
#define	LX_CMSG64_DATA(c)	((unsigned char *)(((lx_cmsghdr64_t *)(c)) + 1))
/*
 * LX_CMSG64_VALID is closely derived from CMSG_VALID with one particularly
 * important addition.  Since cmsg_len is 64bit, (cmsg + cmsg_len) is checked
 * against the start address as well.  This prevents bogus inputs from wrapping
 * around the address space.
 */
#define	LX_CMSG64_VALID(cmsg, start, end)				\
	(ISALIGNED_LX_CMSG64(cmsg) &&					\
	((uintptr_t)(cmsg) >= (uintptr_t)(start)) &&			\
	((uintptr_t)(cmsg) < (uintptr_t)(end)) &&			\
	((cmsg)->cmsg_len >= sizeof (lx_cmsghdr64_t)) &&		\
	((uintptr_t)(cmsg) + (cmsg)->cmsg_len <= (uintptr_t)(end)) &&	\
	((uintptr_t)(cmsg) + (cmsg)->cmsg_len >= (uintptr_t)(start)))
#define	LX_CMSG64_NEXT(cmsg)				\
	(lx_cmsghdr64_t *)((uintptr_t)(cmsg) +		\
	    ROUNDUP_LX_CMSG64_LEN((cmsg)->cmsg_len))
#define	LX_CMSG64_DIFF	sizeof (uint32_t)

#endif /* defined(_LP64) */

/*
 * convert ucred_s to lx_ucred.
 */
static int
stol_conv_ucred(struct cmsghdr *inmsg, struct cmsghdr *omsg)
{
	/*
	 * Format the data correctly in the omsg buffer.
	 */
	if (omsg != NULL) {
		struct ucred_s *scred;
		prcred_t *cr;
		lx_ucred_t lcred;

		scred = (struct ucred_s *)CMSG_CONTENT(inmsg);
		lcred.lxu_pid = scred->uc_pid;
		/* LINTED: alignment */
		cr = UCCRED(scred);
		if (cr != NULL) {
			lcred.lxu_uid = cr->pr_euid;
			lcred.lxu_gid = cr->pr_egid;
		} else {
			lcred.lxu_uid = lcred.lxu_gid = 0;
		}

		bcopy(&lcred, CMSG_CONTENT(omsg), sizeof (lx_ucred_t));
	}

	return (sizeof (struct cmsghdr) + sizeof (lx_ucred_t));
}

static int
ltos_conv_ucred(struct cmsghdr *inmsg, struct cmsghdr *omsg)
{
	if (omsg != NULL) {
		struct ucred_s *uc;
		prcred_t *pc;
		lx_ucred_t *lcred;

		uc = (struct ucred_s *)CMSG_CONTENT(omsg);
		/* LINTED: alignment */
		pc = (prcred_t *)((char *)uc + sizeof (struct ucred_s));

		uc->uc_credoff = sizeof (struct ucred_s);

		lcred = (lx_ucred_t *)CMSG_CONTENT(inmsg);

		uc->uc_pid = lcred->lxu_pid;
		pc->pr_euid = lcred->lxu_uid;
		pc->pr_egid = lcred->lxu_gid;
	}

	return (sizeof (struct cmsghdr) + sizeof (struct ucred_s) +
	    sizeof (prcred_t));

}

static int
stol_conv_recvttl(struct cmsghdr *inmsg, struct cmsghdr *omsg)
{
	/*
	 * SunOS communicates the TTL of incoming packets via IP_RECVTTL using
	 * a uint8_t value instead of IP_TTL using an int. This conversion is
	 * only needed in the one direction since Linux does not handle
	 * IP_RECVTTL in the sendmsg path.
	 */
	if (omsg != NULL) {
		uint8_t *inttl = (uint8_t *)CMSG_CONTENT(inmsg);
		int *ottl = (int *)CMSG_CONTENT(omsg);

		*ottl = (int)*inttl;
	}

	return (sizeof (struct cmsghdr) + sizeof (int));
}

static int
cmsg_conv_generic(struct cmsghdr *inmsg, struct cmsghdr *omsg)
{
	if (omsg != NULL) {
		size_t data_len;

		data_len = inmsg->cmsg_len - sizeof (struct cmsghdr);
		bcopy(CMSG_CONTENT(inmsg), CMSG_CONTENT(omsg), data_len);
	}

	return (inmsg->cmsg_len);
}

static int
lx_xlate_cmsg(struct cmsghdr *inmsg, struct cmsghdr *omsg, lx_xlate_dir_t dir)
{
	int i;
	int len;

	VERIFY(dir == SUNOS_TO_LX || dir == LX_TO_SUNOS);

	for (i = 0; i < LX_MAX_CMSG_XLATE; i++) {
		lx_cmsg_xlate_t *xlate = &lx_cmsg_xlate_tbl[i];
		if (dir == LX_TO_SUNOS &&
		    inmsg->cmsg_level == xlate->lcx_linux_level &&
		    inmsg->cmsg_type == xlate->lcx_linux_type &&
		    xlate->lcx_ltos_conv != NULL) {
			len = xlate->lcx_ltos_conv(inmsg, omsg);
			if (omsg != NULL) {
				omsg->cmsg_len = len;
				omsg->cmsg_level = xlate->lcx_sunos_level;
				omsg->cmsg_type = xlate->lcx_sunos_type;
			}
			return (len);
		} else if (dir == SUNOS_TO_LX &&
		    inmsg->cmsg_level == xlate->lcx_sunos_level &&
		    inmsg->cmsg_type == xlate->lcx_sunos_type &&
		    xlate->lcx_stol_conv != NULL) {
			len = xlate->lcx_stol_conv(inmsg, omsg);
			if (omsg != NULL) {
				omsg->cmsg_len = len;
				omsg->cmsg_level = xlate->lcx_linux_level;
				omsg->cmsg_type = xlate->lcx_linux_type;
			}
			return (len);
		}
	}
	/*
	 * The Linux man page for sendmsg does not define a specific error for
	 * unsupported cmsgs.  While it is meant to indicated bad values for
	 * passed flags, EOPNOTSUPP appears to be the next closest choice.
	 */
	return (-EOPNOTSUPP);
}

static long
ltos_cmsgs_copyin(void *addr, socklen_t inlen, void **outmsg,
    socklen_t *outlenp)
{
	void *inbuf, *obuf;
	struct cmsghdr *inmsg, *omsg;
	int slen = 0;

	if (inlen < sizeof (struct cmsghdr) || inlen > SO_MAXARGSIZE) {
		return (EINVAL);
	}

#if defined(_LP64)
	if (get_udatamodel() == DATAMODEL_NATIVE &&
	    inlen < sizeof (lx_cmsghdr64_t)) {
		/* The size requirements are more strict for 64bit. */
		return (EINVAL);
	}
#endif /* defined(_LP64) */

	inbuf = kmem_alloc(inlen, KM_SLEEP);
	if (copyin(addr, inbuf, inlen) != 0) {
		kmem_free(inbuf, inlen);
		return (EFAULT);
	}

#if defined(_LP64)
	if (get_udatamodel() == DATAMODEL_NATIVE) {
		/*
		 * Linux cmsg headers are longer than illumos under x86_64.
		 * Convert to regular cmsgs first.
		 */
		lx_cmsghdr64_t *lmsg;
		struct cmsghdr *smsg;
		void *newbuf;
		int len = 0;

		/* Inventory the new cmsg size */
		for (lmsg = (lx_cmsghdr64_t *)inbuf;
		    LX_CMSG64_VALID(lmsg, inbuf, (uintptr_t)inbuf + inlen) != 0;
		    lmsg = LX_CMSG64_NEXT(lmsg)) {
			len += ROUNDUP_cmsglen(lmsg->cmsg_len - LX_CMSG64_DIFF);
		}

		VERIFY(len < inlen);
		if (len == 0) {
			/* Input was bogus, so we can give up early. */
			kmem_free(inbuf, inlen);
			*outmsg = NULL;
			*outlenp = 0;
			return (EINVAL);
		}

		newbuf = kmem_alloc(len, KM_SLEEP);

		for (lmsg = (lx_cmsghdr64_t *)inbuf,
		    smsg = (struct cmsghdr *)newbuf;
		    LX_CMSG64_VALID(lmsg, inbuf, (uintptr_t)inbuf + inlen) != 0;
		    lmsg = LX_CMSG64_NEXT(lmsg), smsg = CMSG_NEXT(smsg)) {
			smsg->cmsg_level = lmsg->cmsg_level;
			smsg->cmsg_type = lmsg->cmsg_type;
			smsg->cmsg_len = lmsg->cmsg_len - LX_CMSG64_DIFF;

			/* The above length measurement should ensure this */
			ASSERT(CMSG_VALID(smsg, newbuf,
			    (uintptr_t)newbuf + len));

			bcopy(LX_CMSG64_DATA(lmsg), CMSG_CONTENT(smsg),
			    smsg->cmsg_len - sizeof (*smsg));
		}

		kmem_free(inbuf, inlen);
		inbuf = newbuf;
		inlen = len;
	}
#endif /* defined(_LP64) */

	/*
	 * Now determine how much space we need for the conversion.
	 */
	for (inmsg = (struct cmsghdr *)inbuf;
	    CMSG_VALID(inmsg, inbuf, (uintptr_t)inbuf + inlen) != 0;
	    inmsg = CMSG_NEXT(inmsg)) {
		int sz;

		if ((sz = lx_xlate_cmsg(inmsg, NULL, LX_TO_SUNOS)) < 0) {
			/* unsupported msg */
			kmem_free(inbuf, inlen);
			return (-sz);
		}

		slen += ROUNDUP_cmsglen(sz);
	}

	obuf = kmem_zalloc(slen, KM_SLEEP);

	/*
	 * Now do the conversion.
	 */
	for (inmsg = (struct cmsghdr *)inbuf, omsg = (struct cmsghdr *)obuf;
	    CMSG_VALID(inmsg, inbuf, (uintptr_t)inbuf + inlen) != 0;
	    inmsg = CMSG_NEXT(inmsg), omsg = CMSG_NEXT(omsg)) {
		VERIFY(lx_xlate_cmsg(inmsg, omsg, LX_TO_SUNOS) >= 0);
	}

	kmem_free(inbuf, inlen);
	*outmsg = obuf;
	*outlenp = slen;
	return (0);
}

static long
stol_cmsgs_copyout(void *input, socklen_t inlen, void *addr,
    void *outlenp, socklen_t orig_outlen)
{
	void *obuf;
	struct cmsghdr *inmsg, *omsg;
	int error = 0;
	socklen_t lx_len = 0;
#if defined(_LP64)
	model_t model = get_udatamodel();
#endif

	if (inlen == 0) {
		/* Simply output the zero controllen */
		goto finish;
	}

	VERIFY(inlen >= sizeof (struct cmsghdr));

	/*
	 * First determine how much space we need for the conversion and
	 * make sure the caller has provided at least that much space to return
	 * results.
	 */
	for (inmsg = (struct cmsghdr *)input;
	    CMSG_VALID(inmsg, input, (uintptr_t)input + inlen) != 0;
	    inmsg = CMSG_NEXT(inmsg)) {
		int sz;

		if ((sz = lx_xlate_cmsg(inmsg, NULL, SUNOS_TO_LX)) < 0) {
			/* unsupported msg */
			return (-sz);
		}

#if defined(_LP64)
		if (model == DATAMODEL_NATIVE) {
			/*
			 * The converted 64-bit cmsgs require an additional 4
			 * bytes of header space and must be aligned to 8 bytes
			 * (instead of the typical 4 for x86)
			 */
			sz = ROUNDUP_LX_CMSG64_LEN(sz + LX_CMSG64_DIFF);
		} else
#endif /* defined(_LP64) */
		{
			/*
			 * The converted 32-bit cmsgs do not require additional
			 * header space or padding for Linux conversion.
			 */
			sz = ROUNDUP_cmsglen(sz);
		}

		/*
		 * Unlike SunOS, Linux requires that the last cmsg be
		 * adequately padded for alignment.
		 */
		lx_len += sz;
	}

	if (lx_len > orig_outlen || addr == NULL) {
		/* This will be interpreted by the caller */
		error = EMSGSIZE;
		lx_len = 0;
		goto finish;
	}

	/*
	 * Since cmsgs are often padded to an aligned size, kmem_zalloc is
	 * necessary to prevent leaking the contents of uninitialized memory.
	 */
	obuf = kmem_zalloc(lx_len, KM_SLEEP);

	/*
	 * Convert the msgs.
	 */
	for (inmsg = (struct cmsghdr *)input, omsg = (struct cmsghdr *)obuf;
	    CMSG_VALID(inmsg, input, (uintptr_t)input + inlen) != 0;
	    inmsg = CMSG_NEXT(inmsg), omsg = CMSG_NEXT(omsg)) {
		VERIFY(lx_xlate_cmsg(inmsg, omsg, SUNOS_TO_LX) >= 0);
	}

#if defined(_LP64)
	if (model == DATAMODEL_NATIVE) {
		/* Linux cmsg headers are longer than illumos under x86_64. */
		struct cmsghdr *smsg;
		lx_cmsghdr64_t *lmsg;
		void *newbuf;

		/*
		 * Once again, kmem_zalloc is needed to avoid leaking the
		 * contents of uninialized memory
		 */
		newbuf = kmem_zalloc(lx_len, KM_SLEEP);
		for (smsg = (struct cmsghdr *)obuf,
		    lmsg = (lx_cmsghdr64_t *)newbuf;
		    CMSG_VALID(smsg, obuf, (uintptr_t)obuf + inlen) != 0;
		    smsg = CMSG_NEXT(smsg), lmsg = LX_CMSG64_NEXT(lmsg)) {
			lmsg->cmsg_level = smsg->cmsg_level;
			lmsg->cmsg_type = smsg->cmsg_type;
			lmsg->cmsg_len = smsg->cmsg_len + LX_CMSG64_DIFF;

			ASSERT(LX_CMSG64_VALID(lmsg, newbuf,
			    (uintptr_t)newbuf + lx_len) != 0);

			bcopy(CMSG_CONTENT(smsg), LX_CMSG64_DATA(lmsg),
			    smsg->cmsg_len - sizeof (*smsg));
		}

		kmem_free(obuf, lx_len);
		obuf = newbuf;
	}
#endif /* defined(_LP64) */

	if (copyout(obuf, addr, lx_len) != 0) {
		kmem_free(obuf, lx_len);
		return (EFAULT);
	}
	kmem_free(obuf, lx_len);

finish:
	if (outlenp != NULL) {
#if defined(_LP64)
		if (model != DATAMODEL_NATIVE) {
			int32_t len32 = (int32_t)lx_len;
			if (copyout(&len32, outlenp, sizeof (len32)) != 0) {
				return (EFAULT);
			}
		} else
#endif /* defined(_LP64) */
		{
			if (copyout(&lx_len, outlenp, sizeof (lx_len)) != 0) {
				return (EFAULT);
			}
		}
	}
	return (error);
}

static void
lx_cmsg_set_cloexec(void *input, socklen_t inlen)
{
	struct cmsghdr *inmsg;

	if (inlen == 0) {
		return;
	}

	for (inmsg = (struct cmsghdr *)input;
	    CMSG_VALID(inmsg, input, (uintptr_t)input + inlen) != 0;
	    inmsg = CMSG_NEXT(inmsg)) {
		if (inmsg->cmsg_level == SOL_SOCKET &&
		    inmsg->cmsg_type == SCM_RIGHTS) {
			int *fds = (int *)CMSG_CONTENT(inmsg);
			int i, num = (int)CMSG_CONTENTLEN(inmsg) / sizeof (int);

			for (i = 0; i < num; i++) {
				char flags;
				file_t *fp;

				fp = getf(fds[i]);
				if (fp == NULL) {
					/*
					 * It is possible that a received fd
					 * will already have been closed if a
					 * thread in the local process is
					 * indiscriminately issuing close(2)
					 * calls while the message is being
					 * received.  If that is the case, no
					 * further processing of the fd is
					 * needed.  It will still be passed
					 * up in the cmsg even though the
					 * caller chose to close it already.
					 */
					continue;
				}

				flags = f_getfd(fds[i]);
				flags |= FD_CLOEXEC;
				f_setfd(fds[i], flags);
				releasef(fds[i]);
			}
		}
	}
}

static int
lx_cmsg_try_ucred(sonode_t *so, struct nmsghdr *msg, socklen_t origlen)
{
	lx_socket_aux_data_t *sad;
	struct cmsghdr *cmsg = NULL;
	int msgsize;
	cred_t *cred;

	if (origlen == 0) {
		return (0);
	}
	sad = lx_sad_acquire(SOTOV(so));
	if ((sad->lxsad_flags & LXSAD_FL_STRCRED) == 0) {
		mutex_exit(&sad->lxsad_lock);
		return (0);
	}
	mutex_exit(&sad->lxsad_lock);

	mutex_enter(&so->so_lock);
	if (so->so_peercred == NULL) {
		mutex_exit(&so->so_lock);
		return (0);
	}
	crhold(cred = so->so_peercred);
	mutex_exit(&so->so_lock);

	msgsize = ucredminsize(cred) + sizeof (struct cmsghdr);
	if (msg->msg_control == NULL) {
		msg->msg_controllen = msgsize;
		msg->msg_control = cmsg = kmem_zalloc(msgsize, KM_SLEEP);
	} else {
		/*
		 * The so_recvmsg operation may have allocated a msg_control
		 * buffer which precisely fits all returned cmsgs.  We must
		 * manually verify the length of that cmsg data and reallocate
		 * the buffer if it lacks the necessary space.
		 */
		uintptr_t start = (uintptr_t)msg->msg_control;
		uintptr_t end = start + msg->msg_controllen;

		ASSERT(msg->msg_controllen > 0);
		cmsg = (struct cmsghdr *)msg->msg_control;
		while (CMSG_VALID(cmsg, start, end) != 0) {
			if (cmsg->cmsg_level == SOL_SOCKET &&
			    cmsg->cmsg_type == SCM_UCRED) {
				/*
				 * If some later code change results in a ucred
				 * being attached anyways, there is no need for
				 * us to do it manually
				 */
				crfree(cred);
				return (0);
			}
			cmsg = CMSG_NEXT(cmsg);
		}
		if (((uintptr_t)cmsg + msgsize) > end) {
			socklen_t offset = (uintptr_t)cmsg - start;
			socklen_t newsize = offset + msgsize;
			void *newbuf;

			if (newsize < msg->msg_controllen) {
				/* size overflow, bail */
				crfree(cred);
				return (-1);
			}
			newbuf = kmem_alloc(newsize, KM_SLEEP);
			bcopy(msg->msg_control, newbuf, msg->msg_controllen);
			kmem_free(msg->msg_control, msg->msg_controllen);

			msg->msg_control = newbuf;
			msg->msg_controllen = newsize;
			cmsg = (struct cmsghdr *)((uintptr_t)newbuf + offset);
		}
	}

	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_UCRED;
	cmsg->cmsg_len = msgsize;
	(void) cred2ucred(cred, so->so_cpid, CMSG_CONTENT(cmsg), CRED());
	crfree(cred);
	return (0);
}

static lx_socket_aux_data_t *
lx_sad_acquire(vnode_t *vp)
{
	lx_socket_aux_data_t *cur, *created;

	mutex_enter(&vp->v_vsd_lock);
	cur = (lx_socket_aux_data_t *)vsd_get(vp, lx_socket_vsd);
	if (cur == NULL) {
		/* perform our allocation carefully */
		mutex_exit(&vp->v_vsd_lock);

		created = (lx_socket_aux_data_t *)kmem_zalloc(
		    sizeof (*created), KM_SLEEP);

		mutex_enter(&vp->v_vsd_lock);
		cur = (lx_socket_aux_data_t *)vsd_get(vp, lx_socket_vsd);
		if (cur == NULL) {
			mutex_init(&created->lxsad_lock, NULL, MUTEX_DEFAULT,
			    NULL);
			(void) vsd_set(vp, lx_socket_vsd, created);
			cur = created;
		} else {
			kmem_free(created, sizeof (*created));
		}
	}
	mutex_exit(&vp->v_vsd_lock);
	mutex_enter(&cur->lxsad_lock);
	return (cur);
}

static int
lx_convert_pkt_proto(int protocol)
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
lx_convert_sock_args(int in_dom, int in_type, int in_proto, int *out_dom,
    int *out_type, int *out_options, int *out_proto)
{
	int domain, type, options;

	if (in_dom < 0 || in_type < 0 || in_proto < 0)
		return (EINVAL);

	domain = LTOS_FAMILY(in_dom);
	if (domain == AF_NOTSUPPORTED || domain == AF_UNSPEC)
		return (EAFNOSUPPORT);
	if (domain == AF_INVAL)
		return (EINVAL);

	type = LTOS_SOCKTYPE(in_type & LX_SOCK_TYPE_MASK);
	if (type == SOCK_INVAL)
		return (EINVAL);
	/*
	 * Linux does not allow the app to specify IP Protocol for raw sockets.
	 * SunOS does, so bail out here.
	 */
	if (type == SOCK_NOTSUPPORTED ||
	    (domain == AF_INET && type == SOCK_RAW && in_proto == IPPROTO_IP)) {
		if (lx_kern_release_cmp(curzone, "2.6.15") < 0) {
			/*
			 * Use error appropriate for kernel version.
			 * See lx_socket_create for more detail.
			 */
			return (ESOCKTNOSUPPORT);
		}
		return (EPROTONOSUPPORT);
	}

	options = 0;
	in_type &= ~(LX_SOCK_TYPE_MASK);
	if (in_type & LX_SOCK_NONBLOCK) {
		in_type ^= LX_SOCK_NONBLOCK;
		options |= SOCK_NONBLOCK;
	}
	if (in_type & LX_SOCK_CLOEXEC) {
		in_type ^= LX_SOCK_CLOEXEC;
		options |= SOCK_CLOEXEC;
	}
	if (in_type != 0) {
		return (EINVAL);
	}

	/* Protocol definitions for PF_PACKET differ between Linux and SunOS */
	if (domain == PF_PACKET &&
	    (in_proto = lx_convert_pkt_proto(in_proto)) < 0)
		return (EINVAL);

	*out_dom = domain;
	*out_type = type;
	*out_options = options;
	*out_proto = in_proto;
	return (0);
}

/*
 * For restartable socket syscall handling, the relevant syscalls are only
 * restarted when a timeout is not set on the socket.
 */
static void
lx_sock_syscall_restart(sonode_t *so, boolean_t recv)
{
	if (recv) {
		if (so->so_rcvtimeo != 0)
			return;
	} else {
		if (so->so_sndtimeo != 0)
			return;
	}

	ttolxlwp(curthread)->br_syscall_restart = B_TRUE;
}

static int
lx_socket_create(int domain, int type, int protocol, int options, file_t **fpp,
    int *fdp)
{
	sonode_t *so;
	vnode_t *vp;
	file_t *fp;
	int err, fd;

	/*
	 * EACCES is returned in Linux when the user isn't allowed to use a
	 * "ping socket". EACCES is also used by the iputils-ping userland
	 * application to determine if fallback to SOCK_RAW is necessary.
	 *
	 * This can be removed if we ever implement SOCK_DGRAM + IPPROTO_ICMP.
	 */
	if ((domain == AF_INET && type == SOCK_DGRAM && protocol ==
	    IPPROTO_ICMP) || (domain == AF_INET6 && type == SOCK_DGRAM &&
	    protocol == IPPROTO_ICMPV6))
		return (EACCES);

	/* logic cloned from so_socket */
	so = socket_create(domain, type, protocol, NULL, NULL, SOCKET_SLEEP,
	    SOV_DEFAULT, CRED(), &err);

	if (so == NULL) {
		switch (err) {
		case EPROTOTYPE:
		case EPROTONOSUPPORT:
			if (lx_kern_release_cmp(curzone, "2.6.15") < 0) {
				/*
				 * Linux changed its socket error behavior in
				 * versions 2.6.15 and later.  See git commit
				 * 86c8f9d158f68538a971a47206a46a22c7479bac in
				 * the Linux repository.
				 *
				 * LTP presently checks for version 2.6.16.
				 */
				return (ESOCKTNOSUPPORT);
			}
			return (EPROTONOSUPPORT);
		default:
			return (err);
		}
	}

	/* Allocate a file descriptor for the socket */
	vp = SOTOV(so);
	if ((err = falloc(vp, FWRITE|FREAD, &fp, &fd)) != 0) {
		(void) socket_close(so, 0, CRED());
		socket_destroy(so);
		return (err);
	}

	/*
	 * Linux programs do not tolerate errors appearing from asynchronous
	 * events (such as ICMP messages arriving).  Setting SM_DEFERERR will
	 * prevent checking/delivery of such errors.
	 */
	so->so_mode |= SM_DEFERERR;

	/* Now fill in the entries that falloc reserved */
	if (options & SOCK_NONBLOCK) {
		so->so_state |= SS_NONBLOCK;
		fp->f_flag |= FNONBLOCK;
	}
	mutex_exit(&fp->f_tlock);
	*fpp = fp;
	*fdp = fd;
	return (0);
}

static void
lx_socket_destroy(file_t *fp, int fd)
{
	sonode_t *so = VTOSO(fp->f_vnode);

	setf(fd, NULL);

	mutex_enter(&fp->f_tlock);
	unfalloc(fp);

	(void) socket_close(so, 0, CRED());
	socket_destroy(so);
}

long
lx_socket(int domain, int type, int protocol)
{
	int error, options, fd = -1;
	file_t *fp = NULL;

	if ((error = lx_convert_sock_args(domain, type, protocol, &domain,
	    &type, &options, &protocol)) != 0) {
		return (set_errno(error));
	}

	error = lx_socket_create(domain, type, protocol, options, &fp, &fd);
	if (error != 0) {
		return (set_errno(error));
	}

	setf(fd, fp);
	if ((options & SOCK_CLOEXEC) != 0) {
		f_setfd(fd, FD_CLOEXEC);
	}
	return (fd);
}

long
lx_bind(long sock, uintptr_t name, socklen_t namelen)
{
	struct sonode *so;
	struct sockaddr *addr = NULL;
	socklen_t len = 0;
	file_t *fp;
	int error;
	lx_sun_type_t sun_type;
	boolean_t not_sock = B_FALSE;

	if ((so = getsonode(sock, &error, &fp)) == NULL) {
		return (set_errno(error));
	}

	if (namelen != 0) {
		error = ltos_sockaddr_copyin((struct sockaddr *)name, namelen,
		    &addr, &len, &sun_type);
		if (error != 0) {
			releasef(sock);
			return (set_errno(error));
		}
	}

	if (addr != NULL && addr->sa_family == AF_UNIX) {
		vnode_t *vp;

		error = so_ux_lookup(so, (struct sockaddr_un *)addr, B_TRUE,
		    &vp);
		if (error == 0) {
			/* A valid socket exists and is open at this address. */
			VN_RELE(vp);
		} else {
			/* Keep track of paths which are not valid sockets. */
			if (error == ENOTSOCK) {
				not_sock = B_TRUE;
			}

			/*
			 * When binding to an abstract namespace address or
			 * /dev/log, implicit clean-up must occur if there is
			 * not a valid socket at the specififed address.  See
			 * ltos_sockaddr_copyin for details about why these
			 * socket types act differently.
			 */
			if (sun_type == LX_SUN_ABSTRACT) {
				(void) vn_removeat(NULL, addr->sa_data,
				    UIO_SYSSPACE, RMFILE);
			}
		}
	}

	error = socket_bind(so, addr, len, _SOBIND_XPG4_2, CRED());

	/*
	 * Linux returns EADDRINUSE for attempts to bind to Unix domain
	 * sockets that aren't sockets.
	 */
	if (error == EINVAL && addr != NULL && addr->sa_family == AF_UNIX &&
	    not_sock == B_TRUE) {
		error = EADDRINUSE;
	}

	releasef(sock);

	if (addr != NULL) {
		kmem_free(addr, len);
	}

	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}

long
lx_connect(long sock, uintptr_t name, socklen_t namelen)
{
	struct sonode *so;
	struct sockaddr *addr = NULL;
	lx_socket_aux_data_t *sad = NULL;
	socklen_t len = 0;
	file_t *fp;
	int error;

	if ((so = getsonode(sock, &error, &fp)) == NULL) {
		return (set_errno(error));
	}

	/*
	 * Ensure the name is sized appropriately before we alloc memory and
	 * copy it in from userspace.  We need at least the address family to
	 * make later sizing decisions.
	 */
	if (namelen != 0) {
		error = ltos_sockaddr_copyin((struct sockaddr *)name, namelen,
		    &addr, &len, NULL);
		if (error != 0) {
			releasef(sock);
			return (set_errno(error));
		}
	}

	error = socket_connect(so, addr, len, fp->f_flag,
	    _SOCONNECT_XPG4_2, CRED());

	if (error == EINTR)
		lx_sock_syscall_restart(so, B_FALSE);

	/*
	 * Linux connect(2) behavior is rather strange when using the
	 * O_NONBLOCK flag.  The first call will return EINPROGRESS, as
	 * expected.  Provided that is successful, a second call to connect
	 * will return 0 instead of EISCONN.  Subsequent connect calls will
	 * return EISCONN.
	 */
	if ((fp->f_flag & FNONBLOCK) != 0 && error != 0) {
		sad = lx_sad_acquire(SOTOV(so));
		if (error == EISCONN &&
		    sad->lxsad_status == LXSS_CONNECTING) {
			/* Report the one success */
			sad->lxsad_status = LXSS_CONNECTED;
			error = 0;
		} else if (error == EINPROGRESS) {
			sad->lxsad_status = LXSS_CONNECTING;
		}
		mutex_exit(&sad->lxsad_lock);
	}

	/*
	 * When connecting to a UDP socket, configure it so that future
	 * sendto/sendmsg operations are allowed to specify a destination
	 * address. See the Posix spec. for sendto(2). Linux allows this while
	 * illumos would return EISCONN if the option is not set.
	 */
	if (error == 0 && so->so_protocol == IPPROTO_UDP &&
	    (so->so_family == AF_INET || so->so_family == AF_INET6)) {
		int val = 1;

		DTRACE_PROBE(lx__connect__udp);
		(void) socket_setsockopt(so, IPPROTO_UDP, UDP_SND_TO_CONNECTED,
		    &val, sizeof (val), CRED());
	}

	releasef(sock);

	if (addr != NULL) {
		kmem_free(addr, len);
	}

	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}

/*
 * Custom version of socket_recvmsg for error-handling overrides.
 */
static int
lx_socket_recvmsg(struct sonode *so, struct nmsghdr *msg, struct uio *uiop,
    cred_t *cr)
{
	int error;
	ssize_t orig_resid = uiop->uio_resid;

	/*
	 * Do not bypass the cache when reading data, as the application
	 * is likely to access the data shortly.
	 */
	uiop->uio_extflg |= UIO_COPY_CACHED;

	error = SOP_RECVMSG(so, msg, uiop, cr);

	switch (error) {
	case EINTR:
	/* EAGAIN is EWOULDBLOCK */
	case EWOULDBLOCK:
		/* We did a partial read */
		if (uiop->uio_resid != orig_resid)
			error = 0;
		break;
	case ENOTCONN:
		/*
		 * The rules are different for non-blocking sockets which are
		 * still in the process of making a connection
		 */
		if ((msg->msg_flags & MSG_DONTWAIT) != 0 ||
		    (uiop->uio_fmode & (FNONBLOCK|FNDELAY)) != 0) {
			error = EAGAIN;
		}
		break;
	default:
		break;
	}
	return (error);
}

static long
lx_recv_common(int sock, struct nmsghdr *msg, xuio_t *xuiop, int flags,
    void *namelenp, void *controllenp, void *flagsp)
{
	struct sonode *so;
	file_t *fp;
	void *name;
	socklen_t namelen;
	void *control;
	socklen_t controllen;
	ssize_t len;
	int error;
	boolean_t fd_cloexec;
	boolean_t is_peek_trunc;

	if ((so = getsonode(sock, &error, &fp)) == NULL) {
		return (set_errno(error));
	}

	fd_cloexec = ((flags & LX_MSG_CMSG_CLOEXEC) != 0);
	flags = lx_xlate_sock_flags(flags, LX_TO_SUNOS);
	is_peek_trunc = (flags & (MSG_PEEK|MSG_TRUNC)) == (MSG_PEEK|MSG_TRUNC);
	len = xuiop->xu_uio.uio_resid;
	xuiop->xu_uio.uio_fmode = fp->f_flag;
	xuiop->xu_uio.uio_extflg = UIO_COPY_CACHED;

	/*
	 * Linux accepts MSG_TRUNC as an input flag, unlike SunOS and many
	 * other UNIX distributions.  When combined with MSG_PEEK, it causes
	 * recvmsg to return the size of the waiting message, regardless of
	 * buffer size.  This behavior is commonly used with a 0-length buffer
	 * to interrogate the size of a queued message prior to allocating a
	 * buffer for it.
	 *
	 * In order to support this functionality, a custom XUIO type is used
	 * to communicate the total message size out from the depths of sockfs.
	 */
	if (is_peek_trunc) {
		xuiop->xu_uio.uio_extflg |= UIO_XUIO;
		xuiop->xu_type = UIOTYPE_PEEKSIZE;
		xuiop->xu_ext.xu_ps.xu_ps_set = B_FALSE;
		xuiop->xu_ext.xu_ps.xu_ps_size = 0;
	}

	name = msg->msg_name;
	namelen = msg->msg_namelen;
	control = msg->msg_control;
	controllen = msg->msg_controllen;

	/*
	 * socket_recvmsg will allocate these if needed.
	 * NULL them out to prevent any confusion.
	 */
	msg->msg_name = NULL;
	msg->msg_control = NULL;

	msg->msg_flags = flags & (MSG_OOB | MSG_PEEK | MSG_WAITALL |
	    MSG_DONTWAIT);
	/* Default to XPG4.2 operation */
	msg->msg_flags |= MSG_XPG4_2;

	error = lx_socket_recvmsg(so, msg, (struct uio *)xuiop, CRED());
	if (error) {
		if (error == EINTR)
			lx_sock_syscall_restart(so, B_TRUE);
		releasef(sock);
		return (set_errno(error));
	}
	lwp_stat_update(LWP_STAT_MSGRCV, 1);
	releasef(sock);

	if (namelen != 0) {
		error = stol_sockaddr_copyout(msg->msg_name, msg->msg_namelen,
		    name, namelenp, namelen);

		if (msg->msg_namelen != 0) {
			kmem_free(msg->msg_name, (size_t)msg->msg_namelen);
			msg->msg_namelen = 0;
		}

		/*
		 * Errors during copyout of the name are not a concern to Linux
		 * callers at this point in the syscall
		 */
		if (error != 0 && error != EFAULT) {
			goto err;
		}
	}

	if (controllen != 0) {
		if (fd_cloexec) {
			/*
			 * If CLOEXEC needs to set on file descriptors passed
			 * via SCM_RIGHTS, do so before formatting the cmsgs
			 * for Linux.
			 */
			lx_cmsg_set_cloexec(msg->msg_control,
			    msg->msg_controllen);
		}
		if (so->so_family == AF_UNIX &&
		    (so->so_mode & SM_CONNREQUIRED) != 0) {
			/*
			 * It may be necessary to append a SCM_UCRED cmsg to
			 * the controls if SO_PASSCRED is set on a
			 * connection-oriented AF_UNIX socket.
			 *
			 * See lx_setsockopt_socket for more details.
			 */
			if (lx_cmsg_try_ucred(so, msg, controllen) != 0) {
				msg->msg_flags |= MSG_CTRUNC;
			}
		}

		error = stol_cmsgs_copyout(msg->msg_control,
		    msg->msg_controllen, control, controllenp, controllen);

		if (error != 0) {
			/*
			 * If there was an error during cmsg translation or
			 * copyout, we need to clean up any FDs that are being
			 * passed back via SCM_RIGHTS.  This prevents us from
			 * leaking those open files.
			 */
			so_closefds(msg->msg_control, msg->msg_controllen, 0,
			    0);

			/*
			 * An error during cmsg_copyout means we had
			 * _something_ to process.
			 */
			VERIFY(msg->msg_controllen != 0);

			kmem_free(msg->msg_control,
			    (size_t)msg->msg_controllen);
			msg->msg_controllen = 0;

			if (error == EMSGSIZE) {
				/* Communicate that messages were truncated */
				msg->msg_flags |= MSG_CTRUNC;
				error = 0;
			} else {
				goto err;
			}
		} else if (msg->msg_controllen != 0) {
			kmem_free(msg->msg_control,
			    (size_t)msg->msg_controllen);
			msg->msg_controllen = 0;
		}
	}

	if (flagsp != NULL) {
		int flags;

		/* Clear internal flag. */
		flags = msg->msg_flags & ~MSG_XPG4_2;
		flags = lx_xlate_sock_flags(flags, SUNOS_TO_LX);

		if (copyout(&flags, flagsp, sizeof (flags) != 0)) {
			error = EFAULT;
			goto err;
		}
	}

	/*
	 * If both MSG_PEEK|MSG_TRUNC were set on the input flags and the
	 * socket layer was able to calculate the total message size for us,
	 * return that instead of the copied size.
	 */
	if (is_peek_trunc && xuiop->xu_ext.xu_ps.xu_ps_set == B_TRUE) {
		return (xuiop->xu_ext.xu_ps.xu_ps_size);
	}

	return (len - xuiop->xu_uio.uio_resid);

err:
	if (msg->msg_controllen != 0) {
		/* Prevent FD leakage (see above) */
		so_closefds(msg->msg_control, msg->msg_controllen, 0, 0);
		kmem_free(msg->msg_control, (size_t)msg->msg_controllen);
	}
	if (msg->msg_namelen != 0) {
		kmem_free(msg->msg_name, (size_t)msg->msg_namelen);
	}
	return (set_errno(error));
}

long
lx_recv(int sock, void *buffer, size_t len, int flags)
{
	struct nmsghdr smsg;
	xuio_t xuio;
	struct iovec uiov;

	if ((ssize_t)len < 0) {
		/*
		 * The input len is unsigned, so limit it to SSIZE_MAX since
		 * the return value is signed.
		 */
		return (set_errno(EINVAL));
	}

	uiov.iov_base = buffer;
	uiov.iov_len = len;
	xuio.xu_uio.uio_loffset = 0;
	xuio.xu_uio.uio_iov = &uiov;
	xuio.xu_uio.uio_iovcnt = 1;
	xuio.xu_uio.uio_resid = len;
	xuio.xu_uio.uio_segflg = UIO_USERSPACE;
	xuio.xu_uio.uio_limit = 0;

	smsg.msg_namelen = 0;
	smsg.msg_controllen = 0;
	smsg.msg_flags = 0;
	return (lx_recv_common(sock, &smsg, &xuio, flags, NULL, NULL, NULL));
}

long
lx_recvfrom(int sock, void *buffer, size_t len, int flags,
    struct sockaddr *srcaddr, socklen_t *addrlenp)
{
	struct nmsghdr smsg;
	xuio_t xuio;
	struct iovec uiov;

	if ((ssize_t)len < 0) {
		/* Keep len reasonably limited (see lx_recv) */
		return (set_errno(EINVAL));
	}

	uiov.iov_base = buffer;
	uiov.iov_len = len;
	xuio.xu_uio.uio_loffset = 0;
	xuio.xu_uio.uio_iov = &uiov;
	xuio.xu_uio.uio_iovcnt = 1;
	xuio.xu_uio.uio_resid = len;
	xuio.xu_uio.uio_segflg = UIO_USERSPACE;
	xuio.xu_uio.uio_limit = 0;

	smsg.msg_name = (char *)srcaddr;
	if (addrlenp != NULL && srcaddr != NULL) {
		/*
		 * Despite addrlenp being defined as a socklen_t *, Linux
		 * treats it internally as an int *.  Certain LTP tests depend
		 * upon this behavior, so we must emulate it as well.
		 */
		int namelen;

		if (copyin(addrlenp, &namelen, sizeof (namelen)) != 0) {
			return (set_errno(EFAULT));
		}
		if (namelen < 0) {
			return (set_errno(EINVAL));
		}
		smsg.msg_namelen = namelen;
	} else {
		smsg.msg_namelen = 0;
	}
	smsg.msg_controllen = 0;
	smsg.msg_flags = 0;

	return (lx_recv_common(sock, &smsg, &xuio, flags, addrlenp, NULL,
	    NULL));
}

long
lx_recvmsg(int sock, void *msg, int flags)
{
	struct nmsghdr smsg;
	xuio_t xuio;
	struct iovec luiov[IOV_MAX_STACK], *uiov;
	int i, iovcnt, iovsize;
	long res;
	ssize_t len = 0;
	void *namelenp, *controllenp, *flagsp;

#if defined(_LP64)
	if (get_udatamodel() != DATAMODEL_NATIVE) {
		lx_msghdr32_t lmsg32;
		if (copyin(msg, &lmsg32, sizeof (lmsg32)) != 0) {
			return (set_errno(EFAULT));
		}
		smsg.msg_name = (void *)(uintptr_t)lmsg32.msg_name;
		smsg.msg_namelen = lmsg32.msg_namelen;
		smsg.msg_iov = (struct iovec *)(uintptr_t)lmsg32.msg_iov;
		smsg.msg_iovlen = lmsg32.msg_iovlen;
		smsg.msg_control = (void *)(uintptr_t)lmsg32.msg_control;
		smsg.msg_controllen = lmsg32.msg_controllen;
		smsg.msg_flags = lmsg32.msg_flags;

		namelenp = &((lx_msghdr32_t *)msg)->msg_namelen;
		controllenp = &((lx_msghdr32_t *)msg)->msg_controllen;
		flagsp = &((lx_msghdr32_t *)msg)->msg_flags;
	} else
#endif /* defined(_LP64) */
	{
		lx_msghdr_t lmsg;
		if (copyin(msg, &lmsg, sizeof (lmsg)) != 0) {
			return (set_errno(EFAULT));
		}
		smsg.msg_name = lmsg.msg_name;
		smsg.msg_namelen = lmsg.msg_namelen;
		smsg.msg_iov = lmsg.msg_iov;
		smsg.msg_iovlen = lmsg.msg_iovlen;
		smsg.msg_control = lmsg.msg_control;
		smsg.msg_controllen = lmsg.msg_controllen;
		smsg.msg_flags = lmsg.msg_flags;

		namelenp = &((lx_msghdr_t *)msg)->msg_namelen;
		controllenp = &((lx_msghdr_t *)msg)->msg_controllen;
		flagsp = &((lx_msghdr_t *)msg)->msg_flags;
	}

	iovcnt = smsg.msg_iovlen;
	if (iovcnt < 0 || iovcnt > IOV_MAX) {
		return (set_errno(EMSGSIZE));
	}
	if (iovcnt > IOV_MAX_STACK) {
		iovsize = iovcnt * sizeof (struct iovec);
		uiov = kmem_alloc(iovsize, KM_SLEEP);
	} else if (iovcnt > 0) {
		iovsize = 0;
		uiov = luiov;
	} else {
		iovsize = 0;
		uiov = NULL;
		goto noiov;
	}

#if defined(_LP64)
	if (get_udatamodel() != DATAMODEL_NATIVE) {
		/* convert from 32bit iovec structs */
		struct iovec32 luiov32[IOV_MAX_STACK], *uiov32;
		ssize_t iov32size;
		ssize32_t count32;

		iov32size = iovcnt * sizeof (struct iovec32);
		if (iovsize != 0) {
			uiov32 = kmem_alloc(iov32size, KM_SLEEP);
		} else {
			uiov32 = luiov32;
		}

		if (copyin((struct iovec32 *)smsg.msg_iov, uiov32, iov32size)) {
			if (iovsize != 0) {
				kmem_free(uiov32, iov32size);
				kmem_free(uiov, iovsize);
			}

			return (set_errno(EFAULT));
		}

		count32 = 0;
		for (i = 0; i < iovcnt; i++) {
			ssize32_t iovlen32;

			iovlen32 = uiov32[i].iov_len;
			count32 += iovlen32;
			if (iovlen32 < 0 || count32 < 0) {
				if (iovsize != 0) {
					kmem_free(uiov32, iov32size);
					kmem_free(uiov, iovsize);
				}

				return (set_errno(EINVAL));
			}

			uiov[i].iov_len = iovlen32;
			uiov[i].iov_base =
			    (caddr_t)(uintptr_t)uiov32[i].iov_base;
		}
		len = count32;

		if (iovsize != 0) {
			kmem_free(uiov32, iov32size);
		}
	} else
#endif /* defined(_LP64) */
	{
		if (copyin(smsg.msg_iov, uiov,
		    iovcnt * sizeof (struct iovec)) != 0) {
			if (iovsize != 0) {
				kmem_free(uiov, iovsize);
			}
			return (set_errno(EFAULT));
		}

		len = 0;
		for (i = 0; i < iovcnt; i++) {
			ssize_t iovlen = uiov[i].iov_len;
			len += iovlen;
			if (iovlen < 0 || len < 0) {
				if (iovsize != 0) {
					kmem_free(uiov, iovsize);
				}
				return (set_errno(EINVAL));
			}
		}
	}

noiov:
	/* Since the iovec is passed via the uio, NULL it out in the msg */
	smsg.msg_iov = NULL;

	xuio.xu_uio.uio_loffset = 0;
	xuio.xu_uio.uio_iov = uiov;
	xuio.xu_uio.uio_iovcnt = iovcnt;
	xuio.xu_uio.uio_resid = len;
	xuio.xu_uio.uio_segflg = UIO_USERSPACE;
	xuio.xu_uio.uio_limit = 0;

	res = lx_recv_common(sock, &smsg, &xuio, flags, namelenp, controllenp,
	    flagsp);

	if (iovsize != 0) {
		kmem_free(uiov, iovsize);
	}

	return (res);
}

long
lx_recvmmsg(int sock, void *msg, uint_t vlen, int flags, timespec_t *timeoutp)
{
	hrtime_t deadline = 0;
	uint_t rcvd = 0;
	long ret = 0;
	boolean_t waitforone;

	waitforone = ((flags & LX_MSG_WAITFORONE) != 0);
	flags &= ~LX_MSG_WAITFORONE;

	/*
	 * We want to limit the work that a thread calling recvmmsg() can
	 * perform in the kernel so that it cannot accrue too high a priority.
	 * Artificially capping vlen means that the thread will return to
	 * userspace after processing at most IOV_MAX messages, giving the
	 * system a chance to reset the thread priority.
	 *
	 * Linux does not cap vlen here and recvmmsg() is expected to return
	 * once vlen messages have been received, a timeout occurs, or if an
	 * error is encountered; the artificial cap adds another case.
	 *
	 * It is possible that returning "early" in this emulation will
	 * cause problems with some applications however a properly written
	 * recvmmsg() consumer should consume only the received datagrams
	 * and try again if it wants more. This may need revisiting in the
	 * future.
	 */
	if (vlen > IOV_MAX)
		vlen = IOV_MAX;

	if (timeoutp != NULL) {
		timespec_t timeout;
		uhrtime_t utime = (uhrtime_t)gethrtime();

		if (get_udatamodel() == DATAMODEL_NATIVE) {
			if (copyin(timeoutp, &timeout, sizeof (timestruc_t)))
				return (set_errno(EFAULT));
		} else {
			timestruc32_t timeout32;
			if (copyin(timeoutp, &timeout32,
			    sizeof (timestruc32_t)))
				return (set_errno(EFAULT));
			timeout.tv_sec = (time_t)timeout32.tv_sec;
			timeout.tv_nsec = timeout32.tv_nsec;
		}

		if (itimerspecfix(&timeout))
			return (set_errno(EINVAL));

		/*
		 * Make sure that deadline will not overflow. itimerspecfix()
		 * has already checked for negative values and too big a value
		 * in tv_nsec
		 */
		if (timeout.tv_sec >= HRTIME_MAX / NANOSEC)
			return (set_errno(EINVAL));

		utime += timeout.tv_sec * NANOSEC;
		utime += timeout.tv_nsec;

		if (utime > HRTIME_MAX)
			return (set_errno(EINVAL));

		deadline = (hrtime_t)utime;
	}

	for (rcvd = 0; rcvd < vlen; rcvd++) {
		uint_t *ptr;

		if (get_udatamodel() == DATAMODEL_NATIVE) {
			lx_mmsghdr_t *hdr = (lx_mmsghdr_t *)msg;
			hdr += rcvd;
			ret = lx_recvmsg(sock, (lx_msghdr_t *)hdr, flags);
			ptr = &hdr->msg_len;
		} else {
			lx_mmsghdr32_t *hdr = (lx_mmsghdr32_t *)msg;
			hdr += rcvd;
			ret = lx_recvmsg(sock, (lx_msghdr32_t *)hdr, flags);
			ptr = &hdr->msg_len;
		}
		if (ttolwp(curthread)->lwp_errno != 0)
			break;
		copyout(&ret, ptr, sizeof (*ptr));
		/*
		 * If MSG_WAITFORONE is set, set MSG_DONTWAIT after the
		 * first packet has been received.
		 */
		if (waitforone) {
			flags |= LX_MSG_DONTWAIT;
			waitforone = B_FALSE;
		}
		/*
		 * The Linux man page documents the timeout option as
		 * only being checked after each datagram is received.
		 * The man page does not document ETIMEDOUT as a return
		 * code so we do not set an errno.
		 */
		if (deadline > 0 && gethrtime() >= deadline)
			break;
	}

	if (rcvd > 0) {
		/*
		 * Any error code is deliberately discarded if any message
		 * was successfully received.
		 */
		ttolwp(curthread)->lwp_errno = 0;
		return (rcvd);
	}

	return (ret);
}

/*
 * Custom version of socket_sendmsg for error-handling overrides.
 */
static int
lx_socket_sendmsg(struct sonode *so, struct nmsghdr *msg, struct uio *uiop,
    cred_t *cr, boolean_t nosig)
{
	int error = 0;
	ssize_t orig_resid = uiop->uio_resid;

	/*
	 * Do not bypass the cache if we are doing a local (AF_UNIX) write.
	 */
	if (so->so_family == AF_UNIX) {
		uiop->uio_extflg |= UIO_COPY_CACHED;
	} else {
		uiop->uio_extflg &= ~UIO_COPY_CACHED;
	}

	error = SOP_SENDMSG(so, msg, uiop, cr);

	switch (error) {
	case EINTR:
	case ENOMEM:
	/* EAGAIN is EWOULDBLOCK */
	case EWOULDBLOCK:
		/* We did a partial send */
		if (uiop->uio_resid != orig_resid) {
			error = 0;
		}
		break;

	case ENOTCONN:
		/*
		 * The rules are different for non-blocking sockets which are
		 * still in the process of making a connection
		 */
		if ((msg->msg_flags & MSG_DONTWAIT) != 0 ||
		    (uiop->uio_fmode & (FNONBLOCK|FNDELAY)) != 0) {
			error = EAGAIN;
			break;
		}

		/* Appease LTP and match behavior detailed in the man page */
		error = EPIPE;
		/* FALLTHROUGH */
	case EPIPE:
		if (nosig == B_FALSE) {
			tsignal(curthread, SIGPIPE);
		}
		break;

	default:
		break;
	}

	return (error);
}

static long
lx_send_common(int sock, struct nmsghdr *msg, struct uio *uiop, int flags)
{
	struct sonode *so;
	file_t *fp;
	struct sockaddr *name = NULL;
	socklen_t namelen;
	void *control = NULL;
	socklen_t controllen;
	ssize_t len = 0;
	int error;
	boolean_t nosig;

	if ((so = getsonode(sock, &error, &fp)) == NULL) {
		return (set_errno(error));
	}

	uiop->uio_fmode = fp->f_flag;

	/* Allocate and copyin name and control */
	if (msg->msg_name != NULL && msg->msg_namelen != 0) {
		ASSERT(MUTEX_NOT_HELD(&so->so_lock));

		error = ltos_sockaddr_copyin((struct sockaddr *)msg->msg_name,
		    msg->msg_namelen, &name, &namelen, NULL);
		if (error != 0) {
			goto done;
		}
		/* copyin_name null terminates addresses for AF_UNIX */
		msg->msg_namelen = namelen;
		msg->msg_name = name;
	} else {
		msg->msg_name = name = NULL;
		msg->msg_namelen = namelen = 0;
	}

	if (msg->msg_control != NULL && msg->msg_controllen != 0) {
		/*
		 * Verify that the length is not excessive to prevent
		 * an application from consuming all of kernel memory.
		 */
		if (msg->msg_controllen > SO_MAXARGSIZE) {
			error = EINVAL;
			goto done;
		}
		if ((error = ltos_cmsgs_copyin(msg->msg_control,
		    msg->msg_controllen, &control, &controllen)) != 0) {
			goto done;
		}
		msg->msg_control = control;
		msg->msg_controllen = controllen;
	} else {
		msg->msg_control = control = NULL;
		msg->msg_controllen = controllen = 0;
	}

	len = uiop->uio_resid;
	msg->msg_flags = lx_xlate_sock_flags(flags, LX_TO_SUNOS);
	/* Default to XPG4.2 operation */
	msg->msg_flags |= MSG_XPG4_2;
	nosig = ((flags & LX_MSG_NOSIGNAL) != 0);

	error = lx_socket_sendmsg(so, msg, uiop, CRED(), nosig);
	if (error == EINTR)
		lx_sock_syscall_restart(so, B_FALSE);
done:
	if (control != NULL) {
		kmem_free(control, controllen);
	}
	if (name != NULL) {
		kmem_free(name, namelen);
	}
	if (error != 0) {
		releasef(sock);
		return (set_errno(error));
	}
	lwp_stat_update(LWP_STAT_MSGSND, 1);
	releasef(sock);
	return (len - uiop->uio_resid);
}

/*
 * For both send and sendto Linux evaluates errors in a different order than
 * we do internally. Specifically it will check the buffer address before
 * checking if the socket is connected. This can lead to a different errno on
 * us vs. Linux (seen with LTP) but we don't bother to emulate this.
 */
long
lx_send(int sock, void *buffer, size_t len, int flags)
{
	struct nmsghdr smsg;
	struct uio auio;
	struct iovec aiov[1];

	if ((ssize_t)len < 0) {
		/* Keep len reasonably limited (see lx_recv) */
		return (set_errno(EINVAL));
	}

	aiov[0].iov_base = buffer;
	aiov[0].iov_len = len;
	auio.uio_loffset = 0;
	auio.uio_iov = aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = len;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_limit = 0;

	smsg.msg_name = NULL;
	smsg.msg_control = NULL;
	return (lx_send_common(sock, &smsg, &auio, flags));
}

long
lx_sendto(int sock, void *buffer, size_t len, int flags,
    struct sockaddr *dstaddr, socklen_t addrlen)
{
	struct nmsghdr smsg;
	struct uio auio;
	struct iovec aiov[1];

	if ((ssize_t)len < 0) {
		/* Keep len reasonably limited (see lx_recv) */
		return (set_errno(EINVAL));
	}

	aiov[0].iov_base = buffer;
	aiov[0].iov_len = len;
	auio.uio_loffset = 0;
	auio.uio_iov = aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = len;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_limit = 0;

	smsg.msg_name = (char *)dstaddr;
	smsg.msg_namelen = addrlen;
	smsg.msg_control = NULL;
	return (lx_send_common(sock, &smsg, &auio, flags));
}

long
lx_sendmsg(int sock, void *msg, int flags)
{
	struct nmsghdr smsg;
	struct uio auio;
	struct iovec buf[IOV_MAX_STACK], *aiov;
	int i, iovcnt, iovsize;
	long res;
	ssize_t len = 0;

#if defined(_LP64)
	if (get_udatamodel() != DATAMODEL_NATIVE) {
		lx_msghdr32_t lmsg32;
		if (copyin(msg, &lmsg32, sizeof (lmsg32)) != 0) {
			return (set_errno(EFAULT));
		}
		smsg.msg_name = (void *)(uintptr_t)lmsg32.msg_name;
		smsg.msg_namelen = lmsg32.msg_namelen;
		smsg.msg_iov = (struct iovec *)(uintptr_t)lmsg32.msg_iov;
		smsg.msg_iovlen = lmsg32.msg_iovlen;
		smsg.msg_control = (void *)(uintptr_t)lmsg32.msg_control;
		smsg.msg_controllen = lmsg32.msg_controllen;
		smsg.msg_flags = lmsg32.msg_flags;
	} else
#endif /* defined(_LP64) */
	{
		lx_msghdr_t lmsg;
		if (copyin(msg, &lmsg, sizeof (lmsg)) != 0) {
			return (set_errno(EFAULT));
		}
		smsg.msg_name = lmsg.msg_name;
		smsg.msg_namelen = lmsg.msg_namelen;
		smsg.msg_iov = lmsg.msg_iov;
		smsg.msg_iovlen = lmsg.msg_iovlen;
		smsg.msg_control = lmsg.msg_control;
		smsg.msg_controllen = lmsg.msg_controllen;
		smsg.msg_flags = lmsg.msg_flags;
	}

	iovcnt = smsg.msg_iovlen;
	if (iovcnt <= 0 || iovcnt > IOV_MAX) {
		return (set_errno(EMSGSIZE));
	}
	if (iovcnt > IOV_MAX_STACK) {
		iovsize = iovcnt * sizeof (struct iovec);
		aiov = kmem_alloc(iovsize, KM_SLEEP);
	} else {
		iovsize = 0;
		aiov = buf;
	}

#if defined(_LP64)
	if (get_udatamodel() != DATAMODEL_NATIVE) {
		/* convert from 32bit iovec structs */
		struct iovec32 buf32[IOV_MAX_STACK], *aiov32 = buf32;
		ssize_t iov32size;
		ssize32_t count32;

		iov32size = iovcnt * sizeof (struct iovec32);
		if (iovsize != 0) {
			aiov32 = kmem_alloc(iov32size, KM_SLEEP);
		}

		if (copyin((struct iovec32 *)smsg.msg_iov, aiov32, iov32size)) {
			if (iovsize != 0) {
				kmem_free(aiov32, iov32size);
				kmem_free(aiov, iovsize);
			}

			return (set_errno(EFAULT));
		}

		count32 = 0;
		for (i = 0; i < iovcnt; i++) {
			ssize32_t iovlen32;

			iovlen32 = aiov32[i].iov_len;
			count32 += iovlen32;
			if (iovlen32 < 0 || count32 < 0) {
				if (iovsize != 0) {
					kmem_free(aiov32, iov32size);
					kmem_free(aiov, iovsize);
				}

				return (set_errno(EINVAL));
			}

			aiov[i].iov_len = iovlen32;
			aiov[i].iov_base =
			    (caddr_t)(uintptr_t)aiov32[i].iov_base;
		}
		len = count32;

		if (iovsize != 0) {
			kmem_free(aiov32, iov32size);
		}
	} else
#endif /* defined(_LP64) */
	{
		if (copyin(smsg.msg_iov, aiov,
		    iovcnt * sizeof (struct iovec)) != 0) {
			if (iovsize != 0) {
				kmem_free(aiov, iovsize);
			}
			return (set_errno(EFAULT));
		}

		len = 0;
		for (i = 0; i < iovcnt; i++) {
			ssize_t iovlen = aiov[i].iov_len;

			len += iovlen;
			if (iovlen < 0 || len < 0) {
				if (iovsize != 0) {
					kmem_free(aiov, iovsize);
				}
				return (set_errno(EINVAL));
			}
		}
	}
	/* Since the iovec is passed via the uio, NULL it out in the msg */
	smsg.msg_iov = NULL;

	auio.uio_loffset = 0;
	auio.uio_iov = aiov;
	auio.uio_iovcnt = iovcnt;
	auio.uio_resid = len;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_limit = 0;

	res = lx_send_common(sock, &smsg, &auio, flags);

	if (iovsize != 0) {
		kmem_free(aiov, iovsize);
	}

	return (res);
}

long
lx_sendmmsg(int sock, void *msg, uint_t vlen, int flags)
{
	long ret = 0;
	uint_t sent = 0;

	/*
	 * Linux caps vlen to UIO_MAXIOV (1024).
	 */
	if (vlen > IOV_MAX)
		vlen = IOV_MAX;

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		lx_mmsghdr_t *hdr = msg;

		for (sent = 0; sent < vlen; sent++, hdr++) {
			ret = lx_sendmsg(sock, (lx_msghdr_t *)hdr, flags);
			if (ttolwp(curthread)->lwp_errno != 0)
				break;
			copyout(&ret, &hdr->msg_len, sizeof (hdr->msg_len));
		}
	} else {
		lx_mmsghdr32_t *hdr = msg;

		for (sent = 0; sent < vlen; sent++, hdr++) {
			ret = lx_sendmsg(sock, (lx_msghdr32_t *)hdr, flags);
			if (ttolwp(curthread)->lwp_errno != 0)
				break;
			copyout(&ret, &hdr->msg_len, sizeof (hdr->msg_len));
		}
	}

	if (sent > 0) {
		/*
		 * Any error code is deliberately discarded if any message
		 * was successfully sent.
		 */
		ttolwp(curthread)->lwp_errno = 0;
		return (sent);
	}

	return (ret);
}

/*
 * Linux socket option type definitions
 *
 * The protocol `levels` are well defined (see in.h) The option values are
 * not so well defined. Linux often uses different values vs. Illumos
 * although they mean the same thing. For example, IP_TOS in Linux is
 * defined as value 1 but in Illumos it is defined as value 3. This table
 * maps all the Protocol levels to their options and maps them between
 * Linux and Illumos and vice versa.  Hence the reason for the complexity.
 *
 * For a certain subset of sockopts, Linux will implicitly truncate optval
 * input, so long as optlen meets a minimum size.  Because illumos is strict
 * about optlen, we must cap optlen for those options.
 */

typedef struct lx_sockopt_map {
	const int lsm_opt;	/* Illumos-native equivalent */
	const int lsm_lcap;	/* Cap optlen to this size. (Ignored if 0) */
} lx_sockopt_map_t;

typedef struct lx_proto_opts {
	const lx_sockopt_map_t	*lpo_entries;	/* Linux->SunOS map entries */
	unsigned int		lpo_max;	/* max entries in table */
} lx_proto_opts_t;

#define	OPTNOTSUP	-1	/* we don't support it */

#define	PROTO_SOCKOPTS(opts)    \
	{ (opts), sizeof ((opts)) / sizeof ((opts)[0]) }

/* Shorten name so the columns can line up */
#define	IP_MREQ_SZ	sizeof (struct ip_mreq)

static const lx_sockopt_map_t ltos_ip_sockopts[LX_IP_UNICAST_IF + 1] = {
	{ OPTNOTSUP, 0 },
	{ IP_TOS, sizeof (int) },		/* IP_TOS		*/
	{ IP_TTL, sizeof (int) },		/* IP_TTL		*/
	{ IP_HDRINCL, sizeof (int) },		/* IP_HDRINCL		*/
	{ IP_OPTIONS, 0 },			/* IP_OPTIONS		*/
	{ OPTNOTSUP, 0 },			/* IP_ROUTER_ALERT	*/
	{ IP_RECVOPTS, sizeof (int) },		/* IP_RECVOPTS		*/
	{ IP_RETOPTS, sizeof (int) },		/* IP_RETOPTS		*/
	{ IP_PKTINFO, sizeof (int) },		/* IP_PKTINFO		*/
	{ OPTNOTSUP, 0 },			/* IP_PKTOPTIONS	*/
	{ OPTNOTSUP, 0 },			/* IP_MTUDISCOVER	*/
	{ OPTNOTSUP, 0 },			/* IP_RECVERR		*/
	{ IP_RECVTTL, sizeof (int) },		/* IP_RECVTTL		*/
	{ IP_RECVTOS, sizeof (int) },		/* IP_RECVTOS		*/
	{ OPTNOTSUP, 0 },			/* IP_MTU		*/
	{ OPTNOTSUP, 0 },			/* IP_FREEBIND		*/
	{ OPTNOTSUP, 0 },			/* IP_IPSEC_POLICY	*/
	{ OPTNOTSUP, 0 },			/* IP_XFRM_POLICY	*/
	{ OPTNOTSUP, 0 },			/* IP_PASSSEC		*/
	{ OPTNOTSUP, 0 },			/* IP_TRANSPARENT	*/
	{ OPTNOTSUP, 0 },			/* IP_ORIGDSTADDR	*/
	{ OPTNOTSUP, 0 },			/* IP_MINTTL		*/
	{ OPTNOTSUP, 0 },			/* IP_NODEFRAG		*/
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ IP_MULTICAST_IF, sizeof (int) },	/* IP_MULTICAST_IF	*/
	{ IP_MULTICAST_TTL, sizeof (int) },	/* IP_MULTICAST_TTL	*/
	{ IP_MULTICAST_LOOP, sizeof (int) },	/* IP_MULTICAST_LOOP	*/
	{ IP_ADD_MEMBERSHIP, IP_MREQ_SZ },	/* IP_ADD_MEMBERSHIP	*/
	{ IP_DROP_MEMBERSHIP, IP_MREQ_SZ },	/* IP_DROP_MEMBERSHIP	*/
	{ IP_UNBLOCK_SOURCE, 0 },		/* IP_UNBLOCK_SOURCE	*/
	{ IP_BLOCK_SOURCE, 0 },			/* IP_BLOCK_SOURCE	*/
	{ IP_ADD_SOURCE_MEMBERSHIP, 0 },	/* IP_ADD_SOURCE_MEMBERSHIP */
	{ OPTNOTSUP, 0 },			/* IP_DROP_SOURCE_MEMBERSHIP */
	{ OPTNOTSUP, 0 },			/* IP_MSFILTER		*/
	{ MCAST_JOIN_GROUP, 0 },		/* MCAST_JOIN_GROUP	*/
	{ OPTNOTSUP, 0 },			/* MCAST_BLOCK_SOURCE	*/
	{ OPTNOTSUP, 0 },			/* MCAST_UNBLOCK_SOURCE	*/
	{ MCAST_LEAVE_GROUP, 0 },		/* MCAST_LEAVE_GROUP	*/
	{ OPTNOTSUP, 0 },			/* MCAST_JOIN_SOURCE_GROUP */
	{ OPTNOTSUP, 0 },			/* MCAST_LEAVE_SOURCE_GROUP */
	{ OPTNOTSUP, 0 },			/* MCAST_MSFILTER	*/
	{ OPTNOTSUP, 0 },			/* IP_MULTICAST_ALL	*/
	{ OPTNOTSUP, 0 }			/* IP_UNICAST_IF	*/
};

/* Shorten name so the columns can line up */
#define	IP6_MREQ_SZ	sizeof (struct ipv6_mreq)

static const lx_sockopt_map_t ltos_ipv6_sockopts[LX_IPV6_TCLASS + 1] = {
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },			/* IPV6_ADDRFORM	*/
	{ OPTNOTSUP, 0 },			/* IPV6_2292PKTINFO	*/
	{ OPTNOTSUP, 0 },			/* IPV6_2292HOPOPTS	*/
	{ OPTNOTSUP, 0 },			/* IPV6_2292DSTOPTS	*/
	{ OPTNOTSUP, 0 },			/* IPV6_2292RTHDR	*/
	{ OPTNOTSUP, 0 },			/* IPV6_2292PKTOPTIONS	*/
	{ IPV6_CHECKSUM, sizeof (int) },	/* IPV6_CHECKSUM	*/
	{ OPTNOTSUP, 0 },			/* IPV6_2292HOPLIMIT	*/
	{ OPTNOTSUP, 0 },			/* IPV6_NEXTHOP		*/
	{ OPTNOTSUP, 0 },			/* IPV6_AUTHHDR		*/
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ IPV6_UNICAST_HOPS, sizeof (int) },	/* IPV6_UNICAST_HOPS	*/
	{ IPV6_MULTICAST_IF, sizeof (int) },	/* IPV6_MULTICAST_IF	*/
	{ IPV6_MULTICAST_HOPS, sizeof (int) },	/* IPV6_MULTICAST_HOPS	*/
	{ IPV6_MULTICAST_LOOP, sizeof (int) },	/* IPV6_MULTICAST_LOOP	*/
	{ IPV6_ADD_MEMBERSHIP, IP6_MREQ_SZ },	/* IPV6_JOIN_GROUP	*/
	{ IPV6_DROP_MEMBERSHIP, IP6_MREQ_SZ },	/* IPV6_LEAVE_GROUP	*/
	{ OPTNOTSUP, 0 },			/* IPV6_ROUTER_ALERT	*/
	{ OPTNOTSUP, 0 },			/* IPV6_MTU_DISCOVER	*/
	{ OPTNOTSUP, 0 },			/* IPV6_MTU		*/
	{ OPTNOTSUP, 0 },			/* IPV6_RECVERR		*/
	{ IPV6_V6ONLY, sizeof (int) },		/* IPV6_V6ONLY		*/
	{ OPTNOTSUP, 0 },			/* IPV6_JOIN_ANYCAST	*/
	{ OPTNOTSUP, 0 },			/* IPV6_LEAVE_ANYCAST	*/
	{ OPTNOTSUP, 0 },			/* IPV6_IPSEC_POLICY	*/
	{ OPTNOTSUP, 0 },			/* IPV6_XFRM_POLICY	*/
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ MCAST_JOIN_GROUP, 0 },		/* MCAST_JOIN_GROUP	*/
	{ OPTNOTSUP, 0 },			/* MCAST_BLOCK_SOURCE	*/
	{ OPTNOTSUP, 0 },			/* MCAST_UNBLOCK_SOURCE	*/
	{ MCAST_LEAVE_GROUP, 0 },		/* MCAST_LEAVE_GROUP	*/
	{ OPTNOTSUP, 0 },			/* MCAST_JOIN_SOURCE_GROUP */
	{ OPTNOTSUP, 0 },			/* MCAST_LEAVE_SOURCE_GROUP */
	{ OPTNOTSUP, 0 },			/* MCAST_MSFILTER	*/
	{ IPV6_RECVPKTINFO, sizeof (int) },	/* IPV6_RECVPKTINFO	*/
	{ IPV6_PKTINFO, 0 },			/* IPV6_PKTINFO		*/
	{ IPV6_RECVHOPLIMIT, sizeof (int) },	/* IPV6_RECVHOPLIMIT	*/
	{ IPV6_HOPLIMIT, 0 },			/* IPV6_HOPLIMIT	*/
	{ OPTNOTSUP, 0 },			/* IPV6_RECVHOPOPTS	*/
	{ OPTNOTSUP, 0 },			/* IPV6_HOPOPTS		*/
	{ OPTNOTSUP, 0 },			/* IPV6_RTHDRDSTOPTS	*/
	{ OPTNOTSUP, 0 },			/* IPV6_RECVRTHDR	*/
	{ OPTNOTSUP, 0 },			/* IPV6_RTHDR		*/
	{ OPTNOTSUP, 0 },			/* IPV6_RECVDSTOPTS	*/
	{ OPTNOTSUP, 0 },			/* IPV6_DSTOPTS		*/
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ IPV6_RECVTCLASS, sizeof (int) },	/* IPV6_RECVTCLASS	*/
	{ IPV6_TCLASS, sizeof (int) }		/* IPV6_TCLASS		*/
};

static const lx_sockopt_map_t ltos_icmpv6_sockopts[LX_ICMP6_FILTER + 1] = {
	{ OPTNOTSUP, 0 },
	{ ICMP6_FILTER, 0 }	/* ICMP6_FILTER	*/
};

/*
 * Options marked as "in code" in their comment are handled in the
 * lx_setsockopt_tcp() and lx_getsockopt_tcp() functions.
 *
 * For the Linux TCP_SYNCNT option (the number of SYN retransmits) we emulate
 * that by interpreting the two connection interval settings:
 *    TCP_CONN_NOTIFY_THRESHOLD
 *	tcp_first_ctimer_threshold = tcps->tcps_ip_notify_cinterval
 *    TCP_CONN_ABORT_THRESHOLD
 *	tcp_second_ctimer_threshold = tcps->tcps_ip_abort_cinterval
 * The system (re)transmits a SYN and performs a doubling backoff from the
 * first timer until it passes the second timer. We determine the SYN count
 * from these two values. Normally it will be 5. Also see the TCPS_SYN_SENT
 * case in tcp_timer(); a tcp_second_ctimer_threshold value of 0 means to
 * retransmit SYN indefinitely.
 *
 * For the Linux TCP_USER_TIMEOUT option we use our TCP_ABORT_THRESHOLD since
 * this seems to be the closest match. This value is the
 * tcp_second_timer_threshold, which gets initialized to the
 * tcp_ip_abort_interval value. The tunable guide describes this as:
 *     For a given TCP connection, if TCP has been retransmitting for
 *     tcp_ip_abort_interval period of time and it has not received any
 *     acknowledgment from the other endpoint during this period, TCP closes
 *     this connection.
 * The value is in milliseconds, which matches TCP_USER_TIMEOUT.
 */
static const lx_sockopt_map_t ltos_tcp_sockopts[LX_TCP_NOTSENT_LOWAT + 1] = {
	{ OPTNOTSUP, 0 },
	{ TCP_NODELAY, sizeof (int) },		/* TCP_NODELAY		*/
	{ TCP_MAXSEG, sizeof (int) },		/* TCP_MAXSEG - in code	*/
	{ TCP_CORK, sizeof (int) },		/* TCP_CORK		*/
	{ TCP_KEEPIDLE, sizeof (int) },		/* TCP_KEEPIDLE		*/
	{ TCP_KEEPINTVL, sizeof (int) },	/* TCP_KEEPINTVL	*/
	{ TCP_KEEPCNT, sizeof (int) },		/* TCP_KEEPCNT		*/
	{ OPTNOTSUP, 0 },			/* TCP_SYNCNT - in code	*/
	{ TCP_LINGER2, sizeof (int) },		/* TCP_LINGER2		*/
	{ OPTNOTSUP, 0 },			/* TCP_DEFER_ACCEPT - in code */
	{ OPTNOTSUP, 0 },			/* TCP_WINDOW_CLAMP - in code */
	{ OPTNOTSUP, 0 },			/* TCP_INFO		*/
	{ TCP_QUICKACK, sizeof (int) },		/* TCP_QUICKACK		*/
	{ TCP_CONGESTION, CC_ALGO_NAME_MAX },	/* TCP_CONGESTION	*/
	{ OPTNOTSUP, 0 },			/* TCP_MD5SIG		*/
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },			/* TCP_THIN_LINEAR_TIMEOUTS */
	{ OPTNOTSUP, 0 },			/* TCP_THIN_DUPACK	*/
	{ TCP_ABORT_THRESHOLD, sizeof (int) },	/* TCP_USER_TIMEOUT	*/
	{ OPTNOTSUP, 0 },			/* TCP_REPAIR		*/
	{ OPTNOTSUP, 0 },			/* TCP_REPAIR_QUEUE	*/
	{ OPTNOTSUP, 0 },			/* TCP_QUEUE_SEQ	*/
	{ OPTNOTSUP, 0 },			/* TCP_REPAIR_OPTIONS	*/
	{ OPTNOTSUP, 0 },			/* TCP_FASTOPEN		*/
	{ OPTNOTSUP, 0 },			/* TCP_TIMESTAMP	*/
	{ OPTNOTSUP, 0 }			/* TCP_NOTSENT_LOWAT	*/
};

static const lx_sockopt_map_t ltos_igmp_sockopts[IGMP_MTRACE + 1] = {
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ IGMP_MINLEN, 0 },		/* IGMP_MINLEN			*/
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ IGMP_MEMBERSHIP_QUERY, 0 },	/* IGMP_HOST_MEMBERSHIP_QUERY	*/
	{ IGMP_V1_MEMBERSHIP_REPORT, 0 }, /* IGMP_HOST_MEMBERSHIP_REPORT */
	{ IGMP_DVMRP, 0 },		/* IGMP_DVMRP			*/
	{ IGMP_PIM, 0 },		/* IGMP_PIM			*/
	{ OPTNOTSUP, 0 },		/* IGMP_TRACE			*/
	{ IGMP_V2_MEMBERSHIP_REPORT, 0 }, /* IGMPV2_HOST_MEMBERSHIP_REPORT */
	{ IGMP_V2_LEAVE_GROUP, 0 },	/* IGMP_HOST_LEAVE_MESSAGE	*/
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },
	{ IGMP_MTRACE_RESP, 0 },	/* IGMP_MTRACE_RESP		*/
	{ IGMP_MTRACE, 0 }		/* IGMP_MTRACE			*/
};

static const lx_sockopt_map_t ltos_socket_sockopts[LX_SO_BPF_EXTENSIONS + 1] = {
	{ OPTNOTSUP, 0 },
	{ SO_DEBUG, sizeof (int) },	/* SO_DEBUG			*/
	{ SO_REUSEADDR, sizeof (int) },	/* SO_REUSEADDR			*/
	{ SO_TYPE, 0 },			/* SO_TYPE			*/
	{ SO_ERROR, 0 },		/* SO_ERROR			*/
	{ SO_DONTROUTE, sizeof (int) },	/* SO_DONTROUTE			*/
	{ SO_BROADCAST, sizeof (int) },	/* SO_BROADCAST			*/
	{ SO_SNDBUF, sizeof (int) },	/* SO_SNDBUF			*/
	{ SO_RCVBUF, sizeof (int) },	/* SO_RCVBUF			*/
	{ SO_KEEPALIVE, sizeof (int) },	/* SO_KEEPALIVE			*/
	{ SO_OOBINLINE, sizeof (int) },	/* SO_OOBINLINE			*/
	{ OPTNOTSUP, 0 },		/* SO_NO_CHECK			*/
	{ OPTNOTSUP, 0 },		/* SO_PRIORITY			*/
	{ SO_LINGER, 0 },		/* SO_LINGER			*/
	{ OPTNOTSUP, 0 },		/* SO_BSDCOMPAT			*/
	{ SO_REUSEPORT, sizeof (int) },	/* SO_REUSEPORT			*/
	{ SO_RECVUCRED, sizeof (int) },	/* SO_PASSCRED			*/
	{ OPTNOTSUP, 0 },		/* SO_PEERCRED			*/
	{ SO_RCVLOWAT, sizeof (int) },	/* SO_RCVLOWAT			*/
	{ SO_SNDLOWAT, sizeof (int) },	/* SO_SNDLOWAT			*/
	{ SO_RCVTIMEO, 0 },		/* SO_RCVTIMEO			*/
	{ SO_SNDTIMEO, 0 },		/* SO_SNDTIMEO			*/
	{ OPTNOTSUP, 0 },		/* SO_SECURITY_AUTHENTICATION	*/
	{ OPTNOTSUP, 0 },		/* SO_SECURITY_ENCRYPTION_TRANSPORT */
	{ OPTNOTSUP, 0 },		/* SO_SECURITY_ENCRYPTION_NETWORK */
	{ OPTNOTSUP, 0 },		/* SO_BINDTODEVICE		*/
	{ SO_ATTACH_FILTER, 0 },	/* SO_ATTACH_FILTER		*/
	{ SO_DETACH_FILTER, 0 },	/* SO_DETACH_FILTER		*/
	{ OPTNOTSUP, 0 },		/* SO_PEERNAME			*/
	{ SO_TIMESTAMP, sizeof (int) },	/* SO_TIMESTAMP			*/
	{ SO_ACCEPTCONN, 0 },		/* SO_ACCEPTCONN		*/
	{ OPTNOTSUP, 0 },		/* SO_PEERSEC			*/
	{ SO_SNDBUF, sizeof (int) },	/* SO_SNDBUFFORCE		*/
	{ SO_RCVBUF, sizeof (int) },	/* SO_RCVBUFFORCE		*/
	{ OPTNOTSUP, 0 },		/* SO_PASSSEC			*/
	{ OPTNOTSUP, 0 },		/* SO_TIMESTAMPNS		*/
	{ OPTNOTSUP, 0 },		/* SO_MARK			*/
	{ OPTNOTSUP, 0 },		/* SO_TIMESTAMPING		*/
	{ SO_PROTOTYPE, 0 },		/* SO_PROTOCOL			*/
	{ SO_DOMAIN, 0 },		/* SO_DOMAIN			*/
	{ OPTNOTSUP, 0 },		/* SO_RXQ_OVFL			*/
	{ OPTNOTSUP, 0 },		/* SO_WIFI_STATUS		*/
	{ OPTNOTSUP, 0 },		/* SO_PEEK_OFF			*/
	{ OPTNOTSUP, 0 },		/* SO_NOFCS			*/
	{ OPTNOTSUP, 0 },		/* SO_LOCK_FILTER		*/
	{ OPTNOTSUP, 0 },		/* SO_SELECT_ERR_QUEUE		*/
	{ OPTNOTSUP, 0 },		/* SO_BUSY_POLL			*/
	{ OPTNOTSUP, 0 },		/* SO_MAX_PACING_RATE		*/
	{ OPTNOTSUP, 0 }		/* SO_BPF_EXTENSIONS		*/
};

static const lx_sockopt_map_t ltos_raw_sockopts[LX_ICMP_FILTER + 1] = {
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 }		/* ICMP_FILTER		*/
};

static const lx_sockopt_map_t ltos_packet_sockopts[LX_PACKET_STATISTICS + 1] = {
	{ OPTNOTSUP, 0 },
	{ PACKET_ADD_MEMBERSHIP, 0 },	/* PACKET_ADD_MEMBERSHIP	*/
	{ PACKET_DROP_MEMBERSHIP, 0 },	/* PACKET_DROP_MEMBERSHIP	*/
	{ OPTNOTSUP, 0 },		/* PACKET_RECV_OUTPUT		*/
	{ OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 },		/* PACKET_RX_RING		*/
	{ PACKET_STATISTICS, 0 }	/* PACKET_STATISTICS		*/
};

/* Needed for SO_ATTACH_FILTER */
struct lx_bpf_program {
    unsigned short bf_len;
    caddr_t bf_insns;
};

/* Invert filter fields as Linux expects */
#define	LX_ICMP6_FILTER_INVERT(filterp) ( \
	((filterp)->__icmp6_filt[0] ^= 0xFFFFFFFFU), \
	((filterp)->__icmp6_filt[1] ^= 0xFFFFFFFFU), \
	((filterp)->__icmp6_filt[2] ^= 0xFFFFFFFFU), \
	((filterp)->__icmp6_filt[3] ^= 0xFFFFFFFFU), \
	((filterp)->__icmp6_filt[4] ^= 0xFFFFFFFFU), \
	((filterp)->__icmp6_filt[5] ^= 0xFFFFFFFFU), \
	((filterp)->__icmp6_filt[6] ^= 0xFFFFFFFFU), \
	((filterp)->__icmp6_filt[7] ^= 0xFFFFFFFFU))

static boolean_t
lx_sockopt_lookup(lx_proto_opts_t tbl, int *optname, socklen_t *optlen)
{
	const lx_sockopt_map_t *entry;

	if (*optname > tbl.lpo_max) {
		return (B_FALSE);
	}
	entry = &tbl.lpo_entries[*optname];
	if (entry->lsm_opt == OPTNOTSUP) {
		return (B_FALSE);
	}
	*optname = entry->lsm_opt;
	/* Truncate the optlen if needed/allowed */
	if (entry->lsm_lcap != 0 && *optlen > entry->lsm_lcap) {
		*optlen = entry->lsm_lcap;
	}
	return (B_TRUE);
}

static int
lx_mcast_common(sonode_t *so, int level, int optname, void *optval,
    socklen_t optlen)
{
	int error;
	struct group_req gr;
	lx_sockaddr_storage_t *lxss;

	ASSERT(optname == LX_MCAST_JOIN_GROUP ||
	    optname == LX_MCAST_LEAVE_GROUP);

	/*
	 * For MCAST_JOIN_GROUP and MCAST_LEAVE_GROUP, Linux uses a
	 * gr_group that has a different size from the native gr_group.
	 * We need to translate to the native gr_group taking special
	 * care to do the right thing when dealing with a 32-bit program
	 * making a call into a 64-bit kernel.
	 */

	bzero(&gr, sizeof (gr));

#if defined(_SYSCALL32_IMPL)
	if (get_udatamodel() != DATAMODEL_NATIVE) {
		if (optlen != sizeof (lx_group_req32_t)) {
			return (EINVAL);
		}

		lx_group_req32_t *lxgr = optval;

		/* use the 32-bit type */
		gr.gr_interface = lxgr->lxgr_interface;
		lxss = &lxgr->lxgr_group;
	} else
#endif /* defined(_SYSCALL32_IMPL) */
	{
		if (optlen != sizeof (lx_group_req_t)) {
			return (EINVAL);
		}

		lx_group_req_t *lxgr = optval;

		gr.gr_interface = lxgr->lxgr_interface;
		lxss = &lxgr->lxgr_group;
	}

	bcopy(lxss, &gr.gr_group, sizeof (*lxss));
	gr.gr_group.ss_family = LTOS_FAMILY(lxss->lxss_family);

	optlen = sizeof (gr);
	optname = (optname == LX_MCAST_JOIN_GROUP) ?
	    MCAST_JOIN_GROUP : MCAST_LEAVE_GROUP;

	error = socket_setsockopt(so, level, optname, &gr,
	    optlen, CRED());
	return (error);
}


/*
 * NOTE: For now, the following mess applies to TCP (i.e. AF_INET{,6} +
 * SOCK_STREAM) only, until we enable SO_REUSEPORT for other socket/protocol
 * types as well.  The lx_so_needs_reusehandling() macro indicates what
 * socket(s) apply to the following mess.
 */
#define	lx_so_needs_reusehandling(so)	((so)->so_type == SOCK_STREAM && \
	((so)->so_family == AF_INET || (so)->so_family == AF_INET6))

/*
 * So in Linux, the SO_REUSEADDR includes, essentially, SO_REUSEPORT as part
 * of its functionality.  Experiments on CentOS 7 with a 3.10-ish kernel show
 * that querying on SO_REUSEPORT show it's "off" if SO_REUSEADDR gets set.
 * This means we can't count on directly querying the native socket state. We
 * munge things here in LX-land to essentially turn on both REUSEADDR and
 * REUSEPORT in native conn_t state for LX processes that set SO_REUSEADDR.
 *
 * We also keep track if the wily Linux app sends BOTH REUSEADDR and REUSEPORT
 * down. We can return that both are on, or if it uses just REUSEADDR, we
 * don't return yes for a check of REUSEPORT.  This means our conn_t state may
 * be different than what an LX process will see.  "REUSEPORT" for LX may be
 * off, but internally it will be on.
 *
 * BEGIN CSTYLED
 * State table for internal conn_reuse{addr,port}:
 *
 * LX ADDR,PORT  Int. ADDR,PORT  New ADDR  New LX    New Int.  LXchg?  Intchg?
 * ============  ==============  ========  ======    ========  ======  =======
 *
 * off,off       off,off         off       off,off   off,off   NO      NO
 *
 * off,off       off,off         on        on,off    on,on     YES     YES(2)
 *
 * off,on        off,on          off       off,on    off,on    NO      NO
 *
 * off,on        off,on          on        on,on     on,on     YES     YES
 *
 * on,off        on,on           off       off,off   off,off   YES     YES(2)
 *
 * on,off        on,on           on        on,off    on,on     NO      NO
 *
 * on,on         on,on           off       off,on    off,on    YES     YES
 *
 * on,on         on,on           on        on,on     on,on     NO      NO
 *
 *
 * LX ADDR,PORT  Int. ADDR,PORT  New PORT  New LX    New Int.  LXchg?  Intchg?
 * ============  ==============  ========  ======    ========  ======  =======
 *
 * off,off       off,off         off       off,off   off,off   NO      NO
 *
 * off,off       off,off         on        off,on    off,on    YES     YES
 *
 * off,on        off,on          off       off,off   off,off   YES     YES
 *
 * off,on        off,on          on        off,on    off,on    NO      NO
 *
 * on,off        on,on           off       on,off    on,on     NO      NO
 *
 * on,off        on,on           on        on,on     on,on     YES     NO
 *
 * on,on         on,on           off       on,off    on,on     YES     NO
 *
 * on,on         on,on           on        on,on     on,on     NO      NO
 *
 * END CSTYLED
 *
 * For setting these options, we need to obey the state table above.
 * For getting REUSEADDR, the native stack handles it already.
 * For getting REUSEPORT, we'll have to track the auxiliary data's flags.
 */
static int
lx_set_reuse_handler(sonode_t *so, int optname, void *optval, socklen_t optlen)
{
	lx_socket_aux_data_t *sad;
	boolean_t enable;
	int error;

	if (optlen != sizeof (int))
		return (EINVAL);
	enable = (*((int *)optval) != 0);

	ASSERT(optname == LX_SO_REUSEADDR || optname == LX_SO_REUSEPORT);
	sad = lx_sad_acquire(SOTOV(so));

	/*
	 * lx_sad_acquire() holds its mutex for us.  This protects us
	 * against racing option-setters on the same socket.
	 */
	if (optname == LX_SO_REUSEADDR) {
		/* Check if already set to what we want! */
		if (enable ==
		    ((sad->lxsad_flags & LXSAD_FL_EMULRUADDR) != 0)) {
			mutex_exit(&sad->lxsad_lock);
			return (0);
		}

		/*
		 * At this point, we know we need to change SO_REUSEADDR,
		 * Linux-style.  We know these are supported options too,
		 * so we don't bother with any lookup.
		 */
		error = socket_setsockopt(so, SOL_SOCKET, SO_REUSEADDR,
		    optval, optlen, CRED());
		if (error != 0) {
			mutex_exit(&sad->lxsad_lock);
			return (error);
		}
		if (enable)
			sad->lxsad_flags |= LXSAD_FL_EMULRUADDR;
		else
			sad->lxsad_flags &= ~LXSAD_FL_EMULRUADDR;

		/*
		 * At THIS point, we need to figure out if we ALSO need to
		 * toggle the native-side SO_REUSEPORT state because Linux's
		 * SO_REUSEADDR ALSO include the moral equivalent of
		 * SO_REUSEPORT.  There may be further subtleties, but for now
		 * assume a Linux app that uses SO_REUSEADDR wants that
		 * SO_REUSEPORT functionality thrown in for free.
		 *
		 * Check for SO_REUSEPORT already enabled first.
		 */
		if ((sad->lxsad_flags & LXSAD_FL_EMULRUPORT) != 0) {
			/* Someone turned on REUSEPORT first, we're good. */
			mutex_exit(&sad->lxsad_lock);
			return (0);
		}

		/*
		 * Fall through to REUSEPORT setting, it'll know it's a
		 * supplement based on (optname == SO_REUSEADDR).
		 */
	} else if (enable ==
	    ((sad->lxsad_flags & LXSAD_FL_EMULRUPORT) != 0)) {
		/*
		 * If we reach here, we're setting REUSEPORT to what it's
		 * already set.
		 */
		ASSERT3U(optname, ==, LX_SO_REUSEPORT);
		mutex_exit(&sad->lxsad_lock);
		return (0);
	}

	if (optname == LX_SO_REUSEPORT &&
	    ((sad->lxsad_flags & LXSAD_FL_EMULRUADDR) != 0)) {
		/*
		 * Corner case: REUSEPORT change *but* REUSEADDR is still
		 * enabled.  We must not alter conn_t/native state here, as
		 * REUSEADDR *needs* REUSEPORT enabled on conn_t/native state.
		 * If we want to enable REUSEPORT, the setsockopt would be a
		 * NOP.  If want to disable it, we MUST NOT turn off native
		 * REUSEPORT lest we break Linux-like behavior, and instead
		 * merely turn off the LXSAD_FL_EMULRUPORT flag.
		 */
		error = 0;
	} else {
		/*
		 * At this point, we need to change REUSEPORT.  We may be
		 * doing it for an actual REUSEPORT change, OR for Linux
		 * REUSEADDR semantics.  As earlier, we know the option map
		 * lookup is superfluous.
		 */
		error = socket_setsockopt(so, SOL_SOCKET, SO_REUSEPORT, optval,
		    optlen, CRED());
	}

	if (error != 0 && optname == LX_SO_REUSEADDR) {
		int addr_error, revert_to_optval;

		ASSERT0(sad->lxsad_flags & LXSAD_FL_EMULRUPORT);
		/*
		 * We need more cleanup if the REUSEPORT change fails during
		 * an actual REUSEADDR set.
		 */
		if (enable) {
			sad->lxsad_flags &= ~LXSAD_FL_EMULRUADDR;
			revert_to_optval = 0;
		} else {
			sad->lxsad_flags |= LXSAD_FL_EMULRUADDR;
			revert_to_optval = 1;
		}

		/* Just hardwire it, we're in trouble! */
		addr_error = socket_setsockopt(so, SOL_SOCKET, SO_REUSEADDR,
		    &revert_to_optval, optlen, CRED());
		if (addr_error != 0) {
			/*
			 * Well this sucks, we really shot ourselves in the
			 * foot.  We should somehow signal a catastrophic
			 * error. For now, just return the one we had earlier.
			 */
			DTRACE_PROBE1(lx__reuse__seconderr, int, addr_error);
			mutex_exit(&sad->lxsad_lock);
			return (error);
		}
		/*
		 * Else we managed successfully to clean up and can fall
		 * through the normal error path.
		 */
	} else if (error == 0 && optname == LX_SO_REUSEPORT) {
		/* We successfully changed REUSEPORT explicitly. */
		if (enable)
			sad->lxsad_flags |= LXSAD_FL_EMULRUPORT;
		else
			sad->lxsad_flags &= ~LXSAD_FL_EMULRUPORT;
	}
	/* Else it's an error for an explicit REUSEPORT, just return. */

	mutex_exit(&sad->lxsad_lock);
	return (error);
}

static int
lx_setsockopt_ip(sonode_t *so, int optname, void *optval, socklen_t optlen)
{
	int error;
	int *intval = (int *)optval;
	lx_proto_opts_t sockopts_tbl = PROTO_SOCKOPTS(ltos_ip_sockopts);

	switch (optname) {
	case LX_IP_RECVERR:
		/*
		 * Ping sets this option to receive errors on raw sockets.
		 * Currently we just ignore it to make ping happy. From the
		 * Linux ip.7 man page:
		 *
		 *   For raw sockets, IP_RECVERR enables passing of all
		 *   received ICMP errors to the application.
		 *
		 * Programs known to depend upon this:
		 * - ping
		 * - traceroute
		 * - mount.nfs
		 */
		return (0);

	case LX_IP_MTU_DISCOVER: {
		int val;

		/*
		 * We translate Linux's IP_MTU_DISCOVER into our IP_DONTFRAG,
		 * allowing this be a byte or an integer and observing the
		 * inverted sense of the two relative to one another (and
		 * translating accordingly).
		 */
		if (optlen < sizeof (int)) {
			val = *((uint8_t *)optval);
		} else {
			val = *((int *)optval);
		}

		switch (val) {
		case LX_IP_PMTUDISC_DONT:
			val = 1;
			break;

		case LX_IP_PMTUDISC_DO:
		case LX_IP_PMTUDISC_WANT:
			val = 0;
			break;

		default:
			return (EOPNOTSUPP);
		}

		error = socket_setsockopt(so, IPPROTO_IP, IP_DONTFRAG,
		    &val, sizeof (val), CRED());
		return (error);
	}

	case LX_IP_MULTICAST_TTL:
	case LX_IP_MULTICAST_LOOP:
		/*
		 * For IP_MULTICAST_TTL and IP_MULTICAST_LOOP, Linux defines
		 * the option value to be an integer while we define it to be
		 * an unsigned character.  To prevent the kernel from spitting
		 * back an error on an illegal length, verify that the option
		 * value is less than UCHAR_MAX before truncating optlen.
		 */
		if (optlen <= 0 || optlen > sizeof (int) ||
		    *intval > UINT8_MAX) {
			return (EINVAL);
		}
		optlen = sizeof (uchar_t);
		break;

	case LX_MCAST_JOIN_GROUP:
	case LX_MCAST_LEAVE_GROUP:
		error = lx_mcast_common(so, IPPROTO_IP, optname, optval,
		    optlen);
		return (error);
	default:
		break;
	}

	if (!lx_sockopt_lookup(sockopts_tbl, &optname, &optlen)) {
		return (ENOPROTOOPT);
	}

	error = socket_setsockopt(so, IPPROTO_IP, optname, optval, optlen,
	    CRED());
	return (error);
}

static int
lx_setsockopt_ipv6(sonode_t *so, int optname, void *optval, socklen_t optlen)
{
	int error;
	lx_proto_opts_t sockopts_tbl = PROTO_SOCKOPTS(ltos_ipv6_sockopts);

	switch (optname) {
	case LX_IPV6_RECVERR:
		/*
		 * Ping and glibc's resolver set this.  See lx_setsockopt_ip()'s
		 * handling of LX_IP_RECVERR for more.
		 */
		return (0);
	case LX_IPV6_MTU:
		/*
		 * There isn't a good translation for IPV6_MTU and certain apps
		 * such as bind9 will bail if it cannot be set.
		 * We just lie about the success for now.
		 */
		return (0);
	case LX_MCAST_JOIN_GROUP:
	case LX_MCAST_LEAVE_GROUP:
		error = lx_mcast_common(so, IPPROTO_IPV6, optname, optval,
		    optlen);
		return (error);
	default:
		break;
	}

	if (!lx_sockopt_lookup(sockopts_tbl, &optname, &optlen)) {
		return (ENOPROTOOPT);
	}
	error = socket_setsockopt(so, IPPROTO_IPV6, optname, optval, optlen,
	    CRED());
	return (error);
}

static int
lx_setsockopt_icmpv6(sonode_t *so, int optname, void *optval, socklen_t optlen)
{
	int error;
	lx_proto_opts_t sockopts_tbl = PROTO_SOCKOPTS(ltos_icmpv6_sockopts);

	if (optname == LX_ICMP6_FILTER && optval != NULL) {
		/*
		 * Surprise! The input to ICMP6_FILTER on Linux is inverted
		 * when compared to illumos.
		 */
		if (optlen != sizeof (icmp6_filter_t)) {
			return (EINVAL);
		}
		LX_ICMP6_FILTER_INVERT((icmp6_filter_t *)optval);
	}

	if (!lx_sockopt_lookup(sockopts_tbl, &optname, &optlen)) {
		return (ENOPROTOOPT);
	}
	error = socket_setsockopt(so, IPPROTO_ICMPV6, optname, optval, optlen,
	    CRED());
	return (error);
}

static int
lx_setsockopt_tcp(sonode_t *so, int optname, void *optval, socklen_t optlen)
{
	int error;
	lx_proto_opts_t sockopts_tbl = PROTO_SOCKOPTS(ltos_tcp_sockopts);
	cred_t *cr = CRED();
	uint32_t rto_max, abrt_thresh;
	boolean_t abrt_changed = B_FALSE, rto_max_changed = B_FALSE;

	if (optname == LX_TCP_WINDOW_CLAMP) {
		/* It appears safe to lie and say we did this. */
		return (0);
	}

	if (optname == LX_TCP_MAXSEG) {
		/*
		 * We can get, but not set, TCP_MAXSEG. However, it appears
		 * safe to lie and say we did this. A future extension might
		 * be to allow setting this before a connection is established.
		 */
		return (0);
	}

	if (optname == LX_TCP_SYNCNT) {
		int intval;
		uint64_t syn_last_backoff;
		uint_t syn_cnt, syn_backoff, len;

		/*
		 * See the comment above the ltos_tcp_sockopts table for an
		 * explanation of the TCP_SYNCNT emulation.
		 */
		if (optlen != sizeof (int)) {
			return (EINVAL);
		}
		intval = *(int *)optval;
		if (intval > 255) {
			return (EINVAL);
		}

		len = sizeof (syn_backoff);
		error = socket_getsockopt(so, IPPROTO_TCP,
		    TCP_CONN_NOTIFY_THRESHOLD, &syn_backoff, &len, 0, cr);
		if (error != 0)
			return (error);

		syn_last_backoff = syn_backoff;
		for (syn_cnt = 0; syn_cnt < intval; syn_cnt++) {
			syn_last_backoff *= 2;
			/*
			 * Since the tcps_ip_abort_cinterval is milliseconds and
			 * stored as a uint_t, it's basically impossible to get
			 * up to the Linux limit of 255 SYN retries due to the
			 * doubling on the backoff.
			 */
			if (syn_last_backoff > UINT_MAX) {
				return (EINVAL);
			}
		}

		syn_backoff = (uint_t)syn_last_backoff;
		error = socket_setsockopt(so, IPPROTO_TCP,
		    TCP_CONN_ABORT_THRESHOLD, &syn_backoff, len, cr);
		return (error);
	}

	if (optname == LX_TCP_DEFER_ACCEPT) {
		int *intval;
		char *dfp;

		/*
		 * Emulate TCP_DEFER_ACCEPT using the datafilt(7M) socket
		 * filter but we can't emulate the timeout aspect so treat any
		 * non-zero value as enabling and zero as disabling.
		 */
		if (optlen != sizeof (int)) {
			return (EINVAL);
		}
		intval = (int *)optval;

		/*
		 * socket_setsockopt asserts that the optval is aligned, so
		 * we use kmem_alloc to ensure this.
		 */
		dfp = (char *)kmem_alloc(sizeof (DATAFILT), KM_SLEEP);
		(void) strcpy(dfp, DATAFILT);

		if (*intval > 0) {
			error = socket_setsockopt(so, SOL_FILTER, FIL_ATTACH,
			    dfp, 9, cr);
			if (error == EEXIST) {
				error = 0;
			}
		} else {
			error = socket_setsockopt(so, SOL_FILTER, FIL_DETACH,
			    dfp, 9, cr);
			if (error == ENXIO) {
				error = 0;
			}
		}
		kmem_free(dfp, sizeof (DATAFILT));
		return (error);
	}

	if (!lx_sockopt_lookup(sockopts_tbl, &optname, &optlen)) {
		return (ENOPROTOOPT);
	}

	if (optname == TCP_KEEPINTVL) {
		/*
		 * When setting TCP_KEEPINTVL there is an unfortunate set of
		 * dependencies. TCP_KEEPINTVL must be <= TCP_RTO_MAX and
		 * TCP_RTO_MAX must be <= TCP_ABORT_THRESHOLD. Thus, we may
		 * have to increase one or both of these in order to increase
		 * TCP_KEEPINTVL. Note that TCP_KEEPINTVL is passed in seconds
		 * but TCP_RTO_MAX and TCP_ABORT_THRESHOLD are in milliseconds.
		 * Also note that we currently make no attempt to handle
		 * concurrent application threads simultaneously changing
		 * TCP_KEEPINTVL, since that is unlikely. We could revisit
		 * locking if it ever becomes an issue.
		 */
		uint32_t new_val = *(uint_t *)optval * 1000;
		uint32_t len;

		/*
		 * Linux limits this to 32k, so we do too. However, anything
		 * over 2 hours (7200000 ms) will fail anyway due to the
		 * system-wide default (see "_rexmit_interval_max" in
		 * tcp_tunables.c). Our 2 hour default seems reasonable as a
		 * practical limit for now.
		 */
		if (*(uint_t *)optval > SHRT_MAX)
			return (EINVAL);

		len = sizeof (rto_max);
		if ((error = socket_getsockopt(so, IPPROTO_TCP, TCP_RTO_MAX,
		    &rto_max, &len, 0, cr)) != 0)
			return (error);
		len = sizeof (abrt_thresh);
		if ((error = socket_getsockopt(so, IPPROTO_TCP,
		    TCP_ABORT_THRESHOLD, &abrt_thresh, &len, 0, cr)) != 0)
			return (error);

		if (new_val > abrt_thresh) {
			error = socket_setsockopt(so, IPPROTO_TCP,
			    TCP_ABORT_THRESHOLD, &new_val, sizeof (new_val),
			    cr);
			if (error != 0)
				goto fail;
			abrt_changed = B_TRUE;
		}
		if (new_val > rto_max) {
			error = socket_setsockopt(so, IPPROTO_TCP,
			    TCP_RTO_MAX, &new_val, sizeof (new_val), cr);
			if (error != 0)
				goto fail;
			rto_max_changed = B_TRUE;
		}
	}

	error = socket_setsockopt(so, IPPROTO_TCP, optname, optval, optlen, cr);

fail:
	if (error != 0 && optname == TCP_KEEPINTVL) {
		/*
		 * If changing TCP_KEEPINTVL failed then we may need to
		 * restore the previous values for TCP_ABORT_THRESHOLD and
		 * TCP_RTO_MAX.
		 */
		if (rto_max_changed) {
			(void) socket_setsockopt(so, IPPROTO_TCP,
			    TCP_RTO_MAX, &rto_max,
			    sizeof (rto_max), cr);
		}
		if (abrt_changed) {
			(void) socket_setsockopt(so, IPPROTO_TCP,
			    TCP_ABORT_THRESHOLD, &abrt_thresh,
			    sizeof (abrt_thresh), cr);
		}
	}

	return (error);
}

static int
lx_setsockopt_socket(sonode_t *so, int optname, void *optval, socklen_t optlen)
{
	int error;
	lx_proto_opts_t sockopts_tbl = PROTO_SOCKOPTS(ltos_socket_sockopts);
	struct lx_bpf_program *lbp;
	int *intval;
	struct bpf_program bp;

	switch (optname) {
	case LX_SO_BSDCOMPAT:
		/* Linux ignores this option. */
		return (0);

	case LX_SO_TIMESTAMP:
		/*
		 * SO_TIMESTAMP is not supported on AF_UNIX sockets but we have
		 * some of those which apps use for logging, etc., so pretend
		 * this worked.
		 */
		if (so->so_family == AF_UNIX) {
			return (0);
		}
		break;

	case LX_SO_ATTACH_FILTER:
		/*
		 * Convert bpf program struct
		 */
		if (optlen != sizeof (struct lx_bpf_program)) {
			return (EINVAL);
		}
		lbp = (struct lx_bpf_program *)optval;
		bp.bf_len = lbp->bf_len;
		/* LINTED: alignment */
		bp.bf_insns = (struct bpf_insn *)lbp->bf_insns;
		optval = &bp;
		break;

	case LX_SO_PASSSEC:
		/*
		 * SO_PASSSEC is very similar to SO_PASSCRED (emulated by
		 * SO_RECVUCRED) in that it requests that cmsgs containing
		 * identity information be attached to recieved messages.
		 * Instead of ucred information, security-module-specific
		 * information such as selinux label is expected
		 *
		 * Since LX does not at all support selinux today, the
		 * option is silently accepted.
		 */
		return (0);

	case LX_SO_REUSEADDR:
	case LX_SO_REUSEPORT:
		if (lx_so_needs_reusehandling(so)) {
			/*
			 * See lx_set_reuse_handler's comments for the oddness
			 * of REUSE* in some cases.
			 */
			return (lx_set_reuse_handler(so, optname, optval,
			    optlen));
		}
		break;

	case LX_SO_PASSCRED:
		/*
		 * In many cases, the Linux SO_PASSCRED is mapped to the SunOS
		 * SO_RECVUCRED to enable the passing of peer credential
		 * information via received cmsgs.  One exception is for
		 * connection-oriented AF_UNIX sockets which do not yet support
		 * that option.  Instead, we track the setting internally and,
		 * when there is appropriate cmsg space, emulate the credential
		 * passing by querying the STREAMS ioctl.
		 *
		 * Note: this approach is broken for the case when a process
		 * sets up a Unix-domain socket with SO_PASSCRED, then forks
		 * one or more children, and expects to use the cmsg cred to
		 * accurately know which child pid sent the message (currently
		 * a pid is recorded when the socket is connected, not for each
		 * msg sent). getpeerucred(3c) suffers from the same problem.
		 * We have a workaround in lx_socketpair (use DGRAM if
		 * SEQPACKET), but the general case requires enhancing our
		 * streams support to allow passing credential cmsgs on a
		 * connection-oriented Unix socket.
		 */
		if (so->so_family == AF_UNIX &&
		    (so->so_mode & SM_CONNREQUIRED) != 0) {
			lx_socket_aux_data_t *sad;

			if (optlen != sizeof (int)) {
				return (EINVAL);
			}
			intval = (int *)optval;
			sad = lx_sad_acquire(SOTOV(so));
			if (*intval == 0) {
				sad->lxsad_flags &= ~LXSAD_FL_STRCRED;
			} else {
				sad->lxsad_flags |= LXSAD_FL_STRCRED;
			}
			mutex_exit(&sad->lxsad_lock);
			return (0);
		}
		break;
	}

	if (!lx_sockopt_lookup(sockopts_tbl, &optname, &optlen)) {
		return (ENOPROTOOPT);
	}

	error = socket_setsockopt(so, SOL_SOCKET, optname, optval, optlen,
	    CRED());
	return (error);
}

static int
lx_setsockopt_raw(sonode_t *so, int optname, void *optval, socklen_t optlen)
{
	int error;
	lx_proto_opts_t sockopts_tbl = PROTO_SOCKOPTS(ltos_raw_sockopts);

	switch (optname) {
	case LX_ICMP_FILTER:
		/*
		 * This option is currently ignored to appease ping.
		 */
		return (0);

	case LX_IPV6_CHECKSUM:
		/*
		 * Ping6 tries to set the IPV6_CHECKSUM offset in a way that
		 * illumos won't allow.  Quietly ignore this to prevent it from
		 * complaining.
		 */
		return (0);

	default:
		break;
	}

	if (!lx_sockopt_lookup(sockopts_tbl, &optname, &optlen)) {
		return (ENOPROTOOPT);
	}

	error = socket_setsockopt(so, IPPROTO_TCP, optname, optval, optlen,
	    CRED());
	return (error);
}

static int
lx_setsockopt_packet(sonode_t *so, int optname, void *optval, socklen_t optlen)
{
	int error;
	lx_proto_opts_t sockopts_tbl = PROTO_SOCKOPTS(ltos_packet_sockopts);
	struct packet_mreq *mr;

	switch (optname) {
	case LX_PACKET_ADD_MEMBERSHIP:
	case LX_PACKET_DROP_MEMBERSHIP:
		/* Convert Linux mr_type to illumos */
		if (optlen != sizeof (struct packet_mreq)) {
			return (EINVAL);
		}
		mr = (struct packet_mreq *)optval;
		if (--mr->mr_type > PACKET_MR_ALLMULTI)
			return (EINVAL);
		optval = mr;
		break;

	default:
		break;
	}

	if (!lx_sockopt_lookup(sockopts_tbl, &optname, &optlen)) {
		return (ENOPROTOOPT);
	}

	error = socket_setsockopt(so, SOL_PACKET, optname, optval, optlen,
	    CRED());
	return (error);
}

static int
lx_setsockopt_igmp(sonode_t *so, int optname, void *optval, socklen_t optlen)
{
	int error;
	lx_proto_opts_t sockopts_tbl = PROTO_SOCKOPTS(ltos_igmp_sockopts);

	if (!lx_sockopt_lookup(sockopts_tbl, &optname, &optlen)) {
		return (ENOPROTOOPT);
	}

	error = socket_setsockopt(so, IPPROTO_IGMP, optname, optval, optlen,
	    CRED());
	return (error);
}

static int
lx_getsockopt_ip(sonode_t *so, int optname, void *optval, socklen_t *optlen)
{
	int error = 0;
	lx_proto_opts_t sockopts_tbl = PROTO_SOCKOPTS(ltos_ip_sockopts);

	if (!lx_sockopt_lookup(sockopts_tbl, &optname, optlen)) {
		return (ENOPROTOOPT);
	}

	error = socket_getsockopt(so, IPPROTO_IP, optname, optval, optlen, 0,
	    CRED());
	return (error);
}

static int
lx_getsockopt_ipv6(sonode_t *so, int optname, void *optval, socklen_t *optlen)
{
	int error = 0;
	lx_proto_opts_t sockopts_tbl = PROTO_SOCKOPTS(ltos_ipv6_sockopts);

	if (!lx_sockopt_lookup(sockopts_tbl, &optname, optlen)) {
		return (ENOPROTOOPT);
	}

	error = socket_getsockopt(so, IPPROTO_IPV6, optname, optval, optlen, 0,
	    CRED());
	return (error);
}

static int
lx_getsockopt_icmpv6(sonode_t *so, int optname, void *optval,
    socklen_t *optlen)
{
	int error = 0;
	lx_proto_opts_t sockopts_tbl = PROTO_SOCKOPTS(ltos_icmpv6_sockopts);

	if (optname == LX_ICMP6_FILTER) {
		error = socket_getsockopt(so, IPPROTO_ICMPV6, ICMP6_FILTER,
		    optval, optlen, 0, CRED());

		/*
		 * ICMP6_FILTER is inverted on Linux. Make it so before copying
		 * back to caller's buffer.
		 */
		if (error == 0) {
			LX_ICMP6_FILTER_INVERT((icmp6_filter_t *)optval);
		}
		return (error);
	}

	if (!lx_sockopt_lookup(sockopts_tbl, &optname, optlen)) {
		return (ENOPROTOOPT);
	}

	error = socket_getsockopt(so, IPPROTO_ICMPV6, optname, optval, optlen,
	    0, CRED());
	return (error);
}

/*
 * When attempting to get socket options on AF_UNIX sockets we need to be a bit
 * careful with the returned errno values. It turns out different OSes return
 * different errno values here:
 *     - illumos: ENOPROTOOPT
 *     - Linux: EOPNOTSUPP
 *     - FreeBSD: EINVAL
 * Therefore we remap ENOPROTOOPT to EOPNOTSUPP when a userland program attempts
 * to get one of the various TCP_XXX options under this condition.
 */
static int
lx_getsockopt_tcp(sonode_t *so, int optname, void *optval, socklen_t *optlen)
{
	int error = 0;
	cred_t *cr = CRED();
	int *intval = (int *)optval;
	lx_proto_opts_t sockopts_tbl = PROTO_SOCKOPTS(ltos_tcp_sockopts);

	switch (optname) {
	case LX_TCP_WINDOW_CLAMP:
		/*
		 * We do not support these options but some apps rely on them.
		 * Rather than return an error we just return 0.  This isn't
		 * exactly a lie, since the options really aren't set, but it's
		 * not the whole truth either. Fortunately, we aren't under
		 * oath.
		 */
		if (*optlen < sizeof (int)) {
			return (EINVAL);
		}
		if (so->so_family == AF_UNIX) {
			return (EOPNOTSUPP);
		} else {
			*intval = 0;
		}
		*optlen = sizeof (int);
		return (error);

	case LX_TCP_SYNCNT:
		/*
		 * See the comment above the ltos_tcp_sockopts table for an
		 * explanation of the TCP_SYNCNT emulation.
		 */
		if (*optlen < sizeof (int)) {
			error = EINVAL;
		} else {
			uint_t syn_cnt, syn_backoff, syn_abortconn, len;

			len = sizeof (syn_backoff);
			error = socket_getsockopt(so, IPPROTO_TCP,
			    TCP_CONN_NOTIFY_THRESHOLD, &syn_backoff, &len, 0,
			    cr);
			if (error != 0)
				goto out;
			error = socket_getsockopt(so, IPPROTO_TCP,
			    TCP_CONN_ABORT_THRESHOLD, &syn_abortconn, &len, 0,
			    cr);
			if (error != 0)
				goto out;

			syn_cnt = 0;
			while (syn_backoff < syn_abortconn) {
				syn_cnt++;
				syn_backoff *= 2;
			}
			if (syn_cnt > 255)	/* clamp to Linux limit */
				syn_cnt = 255;

			*intval = syn_cnt;
			*optlen = sizeof (int);
		}

		goto out;

	case LX_TCP_DEFER_ACCEPT:
		/*
		 * We do support TCP_DEFER_ACCEPT using the datafilt(7M) socket
		 * filter but we don't emulate the timeout aspect so treat the
		 * existence as 1 and absence as 0.
		 */
		if (*optlen < sizeof (int)) {
			error = EINVAL;
		} else {
			struct fil_info fi[10];
			int i;
			socklen_t len = sizeof (fi);

			if ((error = socket_getsockopt(so, SOL_FILTER,
			    FIL_LIST, fi, &len, 0, cr)) != 0) {
				*optlen = sizeof (int);
				goto out;
			}

			*intval = 0;
			len = len / sizeof (struct fil_info);
			for (i = 0; i < len; i++) {
				if (fi[i].fi_flags == FILF_PROG &&
				    strcmp(fi[i].fi_name, "datafilt") == 0) {
					*intval = 1;
					break;
				}
			}
		}
		*optlen = sizeof (int);
		goto out;
	default:
		break;
	}

	if (!lx_sockopt_lookup(sockopts_tbl, &optname, optlen)) {
		if (optname <= sockopts_tbl.lpo_max &&
		    so->so_family == AF_UNIX) {
			return (EOPNOTSUPP);
		}
		return (ENOPROTOOPT);
	}

	error = socket_getsockopt(so, IPPROTO_TCP, optname, optval, optlen, 0,
	    cr);

out:
	if (error == ENOPROTOOPT && so->so_family == AF_UNIX) {
		return (EOPNOTSUPP);
	}
	return (error);
}

static int
lx_getsockopt_socket(sonode_t *so, int optname, void *optval,
    socklen_t *optlen)
{
	int error = 0;
	int *intval = (int *)optval;
	lx_proto_opts_t sockopts_tbl = PROTO_SOCKOPTS(ltos_socket_sockopts);
	lx_socket_aux_data_t *sad;

	switch (optname) {
	case LX_SO_PROTOCOL:
		/*
		 * We need to special-case netlink and AF_UNIX too.
		 */
		if (so->so_family != AF_LX_NETLINK && so->so_family != AF_UNIX)
			break;	/* Common-case it. */
		if (*optlen < sizeof (int)) {
			error = EINVAL;
		} else {
			*intval = so->so_protocol;
		}
		*optlen = sizeof (int);
		return (error);

	case LX_SO_TYPE:
		/*
		 * Special handling for connectionless AF_UNIX sockets.
		 * See lx_socketpair for more details.
		 */
		if (so->so_family == AF_UNIX &&
		    (so->so_mode & SM_CONNREQUIRED) == 0) {
			if (*optlen < sizeof (int))
				return (EINVAL);
			sad = lx_sad_acquire(SOTOV(so));
			if ((sad->lxsad_flags & LXSAD_FL_EMULSEQPKT) != 0) {
				*intval = LX_SOCK_SEQPACKET;
				*optlen = sizeof (int);
				mutex_exit(&sad->lxsad_lock);
				return (0);
			}
			mutex_exit(&sad->lxsad_lock);
		}
		break;

	case LX_SO_PASSSEC:
		/*
		 * Communicate value of 0 since selinux-related functionality
		 * is not supported.
		 */
		if (*optlen < sizeof (int)) {
			error = EINVAL;
		} else {
			*intval = 0;
		}
		*optlen = sizeof (int);
		return (error);

	case LX_SO_PASSCRED:
		/*
		 * Special handling for connection-oriented AF_UNIX sockets.
		 * See lx_setsockopt_socket for more details.
		 */
		if (so->so_family == AF_UNIX &&
		    (so->so_mode & SM_CONNREQUIRED) != 0) {
			if (*optlen < sizeof (int)) {
				return (EINVAL);
			}
			sad = lx_sad_acquire(SOTOV(so));
			*intval = ((sad->lxsad_flags & LXSAD_FL_STRCRED) == 0 ?
			    0 : 1);
			*optlen = sizeof (int);
			mutex_exit(&sad->lxsad_lock);
			return (0);
		}
		break;

	case LX_SO_REUSEPORT:
		/*
		 * See lx_so_needs_reusehandling() and lx_set_reuse_handler()
		 * for the sordid details.
		 */
		if (!lx_so_needs_reusehandling(so))
			break;

		if (*optlen < sizeof (int))
			return (EINVAL);
		sad = lx_sad_acquire(SOTOV(so));
		*optlen = sizeof (int);
		*intval =
		    (sad->lxsad_flags & LXSAD_FL_EMULRUPORT) == 0 ? 0 : 1;
		mutex_exit(&sad->lxsad_lock);
		return (0);

	case LX_SO_PEERCRED:
		if (*optlen < sizeof (struct lx_ucred)) {
			error = EINVAL;
		} else {
			struct lx_ucred *lcred = (struct lx_ucred *)optval;

			mutex_enter(&so->so_lock);
			if ((so->so_mode & SM_CONNREQUIRED) == 0) {
				error = ENOTSUP;
			} else if (so->so_peercred == NULL) {
				error = EINVAL;
			} else {
				lcred->lxu_uid = crgetuid(so->so_peercred);
				lcred->lxu_gid = crgetgid(so->so_peercred);
				lcred->lxu_pid = so->so_cpid;
			}
			mutex_exit(&so->so_lock);
		}
		*optlen = sizeof (struct lx_ucred);
		return (error);

	default:
		break;
	}

	if (!lx_sockopt_lookup(sockopts_tbl, &optname, optlen)) {
		return (ENOPROTOOPT);
	}

	error = socket_getsockopt(so, SOL_SOCKET, optname, optval, optlen, 0,
	    CRED());

	if (error == 0) {
		switch (optname) {
		case SO_TYPE:
			/* translate our type back to Linux */
			*intval = STOL_SOCKTYPE(*intval);
			break;

		case SO_ERROR:
			*intval = lx_errno(*intval, EINVAL);
			break;
		default:
			break;
		}
	}
	return (error);
}

static int
lx_getsockopt_raw(sonode_t *so, int optname, void *optval, socklen_t *optlen)
{
	int error = 0;
	lx_proto_opts_t sockopts_tbl = PROTO_SOCKOPTS(ltos_raw_sockopts);

	if (!lx_sockopt_lookup(sockopts_tbl, &optname, optlen)) {
		return (ENOPROTOOPT);
	}

	error = socket_getsockopt(so, IPPROTO_RAW, optname, optval, optlen, 0,
	    CRED());
	return (error);
}

static int
lx_getsockopt_packet(sonode_t *so, int optname, void *optval,
    socklen_t *optlen)
{
	int error = 0;
	lx_proto_opts_t sockopts_tbl = PROTO_SOCKOPTS(ltos_packet_sockopts);

	if (!lx_sockopt_lookup(sockopts_tbl, &optname, optlen)) {
		return (ENOPROTOOPT);
	}

	error = socket_getsockopt(so, SOL_PACKET, optname, optval, optlen, 0,
	    CRED());
	return (error);
}

static int
lx_getsockopt_igmp(sonode_t *so, int optname, void *optval, socklen_t *optlen)
{
	int error = 0;
	lx_proto_opts_t sockopts_tbl = PROTO_SOCKOPTS(ltos_igmp_sockopts);

	if (!lx_sockopt_lookup(sockopts_tbl, &optname, optlen)) {
		return (ENOPROTOOPT);
	}

	error = socket_getsockopt(so, IPPROTO_IGMP, optname, optval, optlen, 0,
	    CRED());
	return (error);
}

long
lx_setsockopt(int sock, int level, int optname, void *optval, socklen_t optlen)
{
	struct sonode *so;
	file_t *fp;
	int buflen = 0;
	intptr_t stkbuf[2];
	void *optbuf = stkbuf;
	int error = 0;

	if (optlen != 0) {
		if (optlen > SO_MAXARGSIZE) {
			return (set_errno(EINVAL));
		}
		if (optlen > sizeof (stkbuf)) {
			buflen = optlen;
			optbuf = kmem_alloc(optlen, KM_SLEEP);
		} else {
			/*
			 * Zero the on-stack buffer to avoid poisoning smaller
			 * optvals with stack garbage.
			 */
			stkbuf[0] = 0;
			stkbuf[1] = 0;
		}
		if (copyin(optval, optbuf, optlen) != 0) {
			if (buflen != 0) {
				kmem_free(optbuf, buflen);
			}
			return (set_errno(EFAULT));
		}
	} else {
		optbuf = NULL;
	}
	if ((so = getsonode(sock, &error, &fp)) == NULL) {
		if (buflen != 0) {
			kmem_free(optbuf, buflen);
		}
		return (set_errno(error));
	}

	switch (level) {
	case LX_IPPROTO_IP:
		error = lx_setsockopt_ip(so, optname, optbuf, optlen);
		break;
	case LX_IPPROTO_IPV6:
		error = lx_setsockopt_ipv6(so, optname, optbuf, optlen);
		break;
	case LX_IPPROTO_ICMPV6:
		error = lx_setsockopt_icmpv6(so, optname, optbuf, optlen);
		break;
	case LX_IPPROTO_TCP:
		error = lx_setsockopt_tcp(so, optname, optbuf, optlen);
		break;
	case LX_SOL_SOCKET:
		error = lx_setsockopt_socket(so, optname, optbuf, optlen);
		break;
	case LX_IPPROTO_RAW:
		error = lx_setsockopt_raw(so, optname, optbuf, optlen);
		break;
	case LX_SOL_PACKET:
		error = lx_setsockopt_packet(so, optname, optbuf, optlen);
		break;
	case LX_IPPROTO_IGMP:
		error = lx_setsockopt_igmp(so, optname, optbuf, optlen);
		break;
	case LX_SOL_NETLINK:
		/*
		 * Since our netlink implmentation is modeled after Linux,
		 * sockopts can be passed directly through.
		 */
		error = socket_setsockopt(so, LX_SOL_NETLINK, optname, optval,
		    optlen, CRED());
		break;
	default:
		error = ENOPROTOOPT;
		break;
	}

	if (error == ENOPROTOOPT) {
		char buf[LX_UNSUP_BUFSZ];

		(void) snprintf(buf, LX_UNSUP_BUFSZ, "setsockopt(%d, %d)",
		    level, optname);
		lx_unsupported(buf);
	}
	if (buflen != 0) {
		kmem_free(optbuf, buflen);
	}
	releasef(sock);
	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}

long
lx_getsockopt(int sock, int level, int optname, void *optval,
    socklen_t *optlenp)
{
	struct sonode *so;
	file_t *fp;
	int error = 0, buflen = 0;
	socklen_t optlen;
	intptr_t stkbuf[2];
	void *optbuf = stkbuf;

	if (copyin(optlenp, &optlen, sizeof (optlen)) != 0) {
		return (set_errno(EFAULT));
	}
	if (optlen != 0) {
		if (optlen > SO_MAXARGSIZE) {
			return (set_errno(EINVAL));
		}
		if (optlen > sizeof (stkbuf)) {
			buflen = optlen;
			optbuf = kmem_zalloc(optlen, KM_SLEEP);
		} else {
			/* zero the on-stack buffer, just in case */
			stkbuf[0] = 0;
			stkbuf[1] = 0;
		}
	} else {
		optbuf = NULL;
	}
	if ((so = getsonode(sock, &error, &fp)) == NULL) {
		if (buflen != 0) {
			kmem_free(optbuf, buflen);
		}
		return (set_errno(error));
	}

	switch (level) {
	case LX_IPPROTO_IP:
		error = lx_getsockopt_ip(so, optname, optbuf, &optlen);
		break;
	case LX_IPPROTO_IPV6:
		error = lx_getsockopt_ipv6(so, optname, optbuf, &optlen);
		break;
	case LX_IPPROTO_ICMPV6:
		error = lx_getsockopt_icmpv6(so, optname, optbuf, &optlen);
		break;
	case LX_IPPROTO_TCP:
		error = lx_getsockopt_tcp(so, optname, optbuf, &optlen);
		break;
	case LX_SOL_SOCKET:
		error = lx_getsockopt_socket(so, optname, optbuf, &optlen);
		break;
	case LX_IPPROTO_RAW:
		error = lx_getsockopt_raw(so, optname, optbuf, &optlen);
		break;
	case LX_SOL_PACKET:
		error = lx_getsockopt_packet(so, optname, optbuf, &optlen);
		break;
	case LX_IPPROTO_IGMP:
		error = lx_getsockopt_igmp(so, optname, optbuf, &optlen);
		break;
	case LX_SOL_NETLINK:
		/*
		 * Since our netlink implmentation is modeled after Linux,
		 * sockopts can be passed directly through.
		 */
		error = socket_getsockopt(so, LX_SOL_NETLINK, optname, optval,
		    &optlen, 0, CRED());
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	if (error == ENOPROTOOPT) {
		char buf[LX_UNSUP_BUFSZ];

		(void) snprintf(buf, LX_UNSUP_BUFSZ, "getsockopt(%d, %d)",
		    level, optname);
		lx_unsupported(buf);
	}
	if (copyout(&optlen, optlenp, sizeof (optlen)) != 0) {
		error = EFAULT;
	}
	if (error == 0 && optlen > 0) {
		VERIFY(optlen <= sizeof (stkbuf) || optlen <= buflen);
		if (copyout(optbuf, optval, optlen) != 0) {
			error = EFAULT;
		}
	}
	if (buflen != 0) {
		kmem_free(optbuf, buflen);
	}
	releasef(sock);
	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}

long
lx_getname_common(lx_getname_type_t type, int sockfd, void *np, int *nlp)
{
	struct sockaddr_storage buf;
	struct sockaddr *name = (struct sockaddr *)&buf;
	socklen_t namelen, namelen_orig;
	int err, tmp;
	struct sonode *so;

	/* We need to validate the name address up front to pass LTP. */
	if (copyin(np, &tmp, sizeof (tmp)) != 0)
		return (set_errno(EFAULT));

	if (copyin(nlp, &namelen, sizeof (socklen_t)) != 0)
		return (set_errno(EFAULT));
	namelen_orig = namelen;

	/* LTP can pass -1 */
	if ((int)namelen < 0)
		return (set_errno(EINVAL));

	if ((so = getsonode(sockfd, &err, NULL)) == NULL)
		return (set_errno(err));

	bzero(&buf, sizeof (buf));
	namelen = sizeof (struct sockaddr_storage);
	if (type == LX_GETPEERNAME) {
		err = socket_getpeername(so, name, &namelen, B_FALSE, CRED());
	} else {
		err = socket_getsockname(so, name, &namelen, CRED());
	}

	if (err == 0) {
		ASSERT(namelen <= so->so_max_addr_len);
		err = stol_sockaddr_copyout(name, namelen,
		    (struct sockaddr *)np, (socklen_t *)nlp, namelen_orig);
	}

	releasef(sockfd);
	return (err != 0 ? set_errno(err) : 0);
}

long
lx_getpeername(int sockfd, void *np, int *nlp)
{
	return (lx_getname_common(LX_GETPEERNAME, sockfd, np, nlp));
}

long
lx_getsockname(int sockfd, void *np, int *nlp)
{
	return (lx_getname_common(LX_GETSOCKNAME, sockfd, np, nlp));
}

static int
lx_accept_common(int sock, struct sockaddr *name, socklen_t *nlp, int flags)
{
	struct sonode *so;
	file_t *fp;
	int error;
	socklen_t namelen;
	struct sonode *nso;
	struct vnode *nvp;
	struct file *nfp;
	int nfd;
	int arg;

	if (flags & ~(LX_SOCK_CLOEXEC | LX_SOCK_NONBLOCK)) {
		return (set_errno(EINVAL));
	}

	if ((so = getsonode(sock, &error, &fp)) == NULL)
		return (set_errno(error));

	if (name != NULL) {
		/*
		 * The Linux man page says that -1 is returned and errno is set
		 * to EFAULT if the "name" address is bad, but it is silent on
		 * what to set errno to if the "namelen" address is bad.
		 * LTP expects EINVAL.
		 *
		 * Note that we must first check the name pointer, as the Linux
		 * docs state nothing is copied out if the "name" pointer is
		 * NULL. If it is NULL, we don't care about the namelen
		 * pointer's value or about dereferencing it.
		 */
		if (copyin(nlp, &namelen, sizeof (namelen))) {
			releasef(sock);
			return (set_errno(EINVAL));
		}
		if (namelen == 0) {
			name = NULL;
		}
	} else {
		namelen = 0;
	}

	/*
	 * Allocate the user fd before socket_accept() in order to
	 * catch EMFILE errors before calling socket_accept().
	 */
	if ((error = falloc(NULL, FWRITE|FREAD, &nfp, &nfd)) != 0) {
		eprintsoline(so, EMFILE);
		releasef(sock);
		return (set_errno(error));
	}
	if ((error = socket_accept(so, fp->f_flag, CRED(), &nso)) != 0) {
		if (error == EINTR)
			lx_sock_syscall_restart(so, B_TRUE);
		setf(nfd, NULL);
		unfalloc(nfp);
		releasef(sock);
		return (set_errno(error));
	}

	nvp = SOTOV(nso);

	if (namelen != 0) {
		socklen_t addrlen = sizeof (struct sockaddr_storage);
		struct sockaddr_storage buf;
		struct sockaddr *addrp = (struct sockaddr *)&buf;

		if ((error = socket_getpeername(nso, addrp, &addrlen, B_TRUE,
		    CRED())) == 0) {
			error = stol_sockaddr_copyout(addrp, addrlen,
			    name, nlp, namelen);
			/*
			 * Logic might dictate that we should check if we can
			 * write to the namelen pointer earlier so we don't
			 * accept a pending connection only to fail the call
			 * because we can't write the namelen value back out.
			 * However, testing shows Linux does indeed fail the
			 * call after accepting the connection so we must
			 * behave in a compatible manner.
			 */
		} else {
			ASSERT(error == EINVAL || error == ENOTCONN);
			error = ECONNABORTED;
		}
	}

	if (error != 0) {
		setf(nfd, NULL);
		unfalloc(nfp);
		(void) socket_close(nso, 0, CRED());
		socket_destroy(nso);
		releasef(sock);
		return (set_errno(error));
	}

	/* Fill in the entries that falloc reserved */
	nfp->f_vnode = nvp;
	mutex_exit(&nfp->f_tlock);
	setf(nfd, nfp);

	/* Act on LX_SOCK_CLOEXEC from flags */
	if (flags & LX_SOCK_CLOEXEC) {
		f_setfd(nfd, FD_CLOEXEC);
	}

	/*
	 * In Linux, accept()ed sockets do not inherit anything set by fcntl(),
	 * so either explicitly set the flags or filter those out.
	 *
	 * The VOP_SETFL code is a simplification of the F_SETFL code in
	 * fcntl(). Ignore any errors from VOP_SETFL.
	 */
	arg = 0;
	if (flags & LX_SOCK_NONBLOCK)
		arg |= FNONBLOCK;

	error = VOP_SETFL(nvp, nfp->f_flag, arg, nfp->f_cred, NULL);
	if (error != 0) {
		eprintsoline(so, error);
		error = 0;
	} else {
		mutex_enter(&nfp->f_tlock);
		nfp->f_flag &= ~FMASK | (FREAD|FWRITE);
		nfp->f_flag |= arg;
		mutex_exit(&nfp->f_tlock);
	}

	releasef(sock);
	return (nfd);
}

long
lx_accept(int sockfd, void *np, int *nlp)
{
	return (lx_accept_common(sockfd, (struct sockaddr *)np,
	    (socklen_t *)nlp, 0));
}

long
lx_accept4(int sockfd, void *np, int *nlp, int flags)
{
	return (lx_accept_common(sockfd, (struct sockaddr *)np,
	    (socklen_t *)nlp, flags));
}

long
lx_listen(int sockfd, int backlog)
{
	return (listen(sockfd, backlog, 0));
}

long
lx_shutdown(int sockfd, int how)
{
	return (shutdown(sockfd, how, 0));
}

/*
 * Connect two sockets together for a socketpair.  This is derived from
 * so_socketpair, but forgoes the task of dealing with file descriptors.
 */
static int
lx_socketpair_connect(file_t *fp1, file_t *fp2)
{
	sonode_t *so1, *so2;
	sotpi_info_t *sti1, *sti2;
	struct sockaddr_ux name;
	int error;

	so1 = VTOSO(fp1->f_vnode);
	so2 = VTOSO(fp2->f_vnode);
	sti1 = SOTOTPI(so1);
	sti2 = SOTOTPI(so2);

	VERIFY(so1->so_ops == &sotpi_sonodeops &&
	    so2->so_ops == &sotpi_sonodeops);

	if (so1->so_type == SOCK_DGRAM) {
		/*
		 * Bind both sockets and connect them with each other.
		 */
		error = socket_bind(so1, NULL, 0, _SOBIND_UNSPEC, CRED());
		if (error) {
			return (error);
		}
		error = socket_bind(so2, NULL, 0, _SOBIND_UNSPEC, CRED());
		if (error) {
			return (error);
		}
		name.sou_family = AF_UNIX;
		name.sou_addr = sti2->sti_ux_laddr;
		error = socket_connect(so1, (struct sockaddr *)&name,
		    (socklen_t)sizeof (name), 0, _SOCONNECT_NOXLATE, CRED());
		if (error) {
			return (error);
		}
		name.sou_addr = sti1->sti_ux_laddr;
		error = socket_connect(so2, (struct sockaddr *)&name,
		    (socklen_t)sizeof (name), 0, _SOCONNECT_NOXLATE, CRED());
		return (error);
	} else {
		sonode_t *nso;

		/*
		 * Bind both sockets, with 'so1' being a listener.  Connect
		 * 'so2' to 'so1', doing so as nonblocking to avoid waiting for
		 * soaccept to complete.  Accept the connection on 'so1',
		 * replacing the socket/vnode in 'fp1' with the new connection.
		 *
		 * We could simply call socket_listen() here (which would do the
		 * binding automatically) if the code didn't rely on passing
		 * _SOBIND_NOXLATE to the TPI implementation of socket_bind().
		 */
		error = socket_bind(so1, NULL, 0, _SOBIND_UNSPEC|
		    _SOBIND_NOXLATE|_SOBIND_LISTEN|_SOBIND_SOCKETPAIR, CRED());
		if (error) {
			return (error);
		}
		error = socket_bind(so2, NULL, 0, _SOBIND_UNSPEC, CRED());
		if (error) {
			return (error);
		}

		name.sou_family = AF_UNIX;
		name.sou_addr = sti1->sti_ux_laddr;
		error = socket_connect(so2,
		    (struct sockaddr *)&name,
		    (socklen_t)sizeof (name),
		    FNONBLOCK, _SOCONNECT_NOXLATE, CRED());
		if (error != 0 && error != EINPROGRESS) {
			return (error);
		}

		error = socket_accept(so1, 0, CRED(), &nso);
		if (error) {
			return (error);
		}

		/* wait for so2 being SS_CONNECTED */
		mutex_enter(&so2->so_lock);
		error = sowaitconnected(so2, 0, 0);
		mutex_exit(&so2->so_lock);
		if (error != 0) {
			(void) socket_close(nso, 0, CRED());
			socket_destroy(nso);
			return (error);
		}

		(void) socket_close(so1, 0, CRED());
		socket_destroy(so1);
		fp1->f_vnode = SOTOV(nso);
	}
	return (0);
}

long
lx_socketpair(int domain, int type, int protocol, int *sv)
{
	int err, options, fds[2];
	file_t *fps[2];
	boolean_t emul_seqp = B_FALSE;

	/*
	 * For the special case of SOCK_SEQPACKET for AF_UNIX, we want to treat
	 * this as a SOCK_DGRAM. The semantics are similar, but our native code
	 * will not pass cmsg creds over a connection-oriented socket, unlike a
	 * connectionless one. Some Linux code depends on this for Unix-domain
	 * sockets. In particular, a sockopt of SO_PASSCRED, which we map into
	 * our native SO_RECVUCRED, must work across fork so that the correct
	 * pid of the sender is available in the cmsg. See the comment in
	 * lx_setsockopt_socket().
	 */
	if (domain == LX_AF_UNIX && type == LX_SOCK_SEQPACKET) {
		type = LX_SOCK_DGRAM;
		emul_seqp = B_TRUE;
	}

	if ((err = lx_convert_sock_args(domain, type, protocol, &domain, &type,
	    &options, &protocol)) != 0) {
		return (set_errno(err));
	}

	if ((err = lx_socket_create(domain, type, protocol, options, &fps[0],
	    &fds[0])) != 0) {
		return (set_errno(err));
	}

	/*
	 * While it seems silly to check the family after socket creation, this
	 * is done to appease LTP when it tries some outlandish combinations of
	 * domain/type/protocol.  The socket_create function is relied upon to
	 * emit the expected errors.
	 */
	if (VTOSO(fps[0]->f_vnode)->so_family != AF_UNIX) {
		lx_socket_destroy(fps[0], fds[0]);
		return (set_errno(EOPNOTSUPP));
	}

	if ((err = lx_socket_create(domain, type, protocol, options, &fps[1],
	    &fds[1])) != 0) {
		lx_socket_destroy(fps[0], fds[0]);
		return (set_errno(err));
	}

	err = lx_socketpair_connect(fps[0], fps[1]);
	if (err != 0) {
		lx_socket_destroy(fps[0], fds[0]);
		lx_socket_destroy(fps[1], fds[1]);
		return (set_errno(err));
	}

	if (emul_seqp) {
		int i;
		for (i = 0; i < 2; i++) {
			sonode_t *so = VTOSO(fps[i]->f_vnode);
			lx_socket_aux_data_t *sad = lx_sad_acquire(SOTOV(so));
			sad->lxsad_flags |= LXSAD_FL_EMULSEQPKT;
			mutex_exit(&sad->lxsad_lock);
		}
	}

	setf(fds[0], fps[0]);
	setf(fds[1], fps[1]);

	if ((options & SOCK_CLOEXEC) != 0) {
		f_setfd(fds[0], FD_CLOEXEC);
		f_setfd(fds[1], FD_CLOEXEC);
	}
	if (copyout(fds, sv, sizeof (fds)) != 0) {
		(void) closeandsetf(fds[0], NULL);
		(void) closeandsetf(fds[1], NULL);
		return (set_errno(EFAULT));
	}
	return (0);
}


#if defined(_SYSCALL32_IMPL)

#define	LX_SYS_SOCKETCALL		102
#define	LX_SOCKETCALL_MAX		20

typedef long (*lx_sockfn_t)();

static struct {
	lx_sockfn_t s_fn;	/* Function implementing the subcommand */
	int s_nargs;		/* Number of arguments the function takes */
} lx_socketcall_fns[] = {
	lx_socket,	3,	/* socket */
	lx_bind,	3,	/* bind */
	lx_connect,	3,	/* connect */
	lx_listen,	2,	/* listen */
	lx_accept,	3,	/* accept */
	lx_getsockname,	3,	/* getsockname */
	lx_getpeername,	3,	/* getpeername */
	lx_socketpair,	4,	/* socketpair */
	lx_send,	4,	/* send */
	lx_recv,	4,	/* recv */
	lx_sendto,	6,	/* sendto */
	lx_recvfrom,	6,	/* recvfrom */
	lx_shutdown,	2,	/* shutdown */
	lx_setsockopt,	5,	/* setsockopt */
	lx_getsockopt,	5,	/* getsockopt */
	lx_sendmsg,	3,	/* sendmsg */
	lx_recvmsg,	3,	/* recvmsg */
	lx_accept4,	4,	/* accept4 */
	lx_recvmmsg,	5,	/* recvmmsg */
	lx_sendmmsg,	4	/* sendmmsg */
};

long
lx_socketcall(long p1, uint32_t *p2)
{
	int subcmd, i;
	unsigned long args[6] = { 0, 0, 0, 0, 0, 0 };

	/* incoming subcmds are 1-indexed */
	subcmd = (int)p1 - 1;

	if (subcmd < 0 || subcmd >= LX_SOCKETCALL_MAX ||
	    lx_socketcall_fns[subcmd].s_fn == NULL) {
		return (set_errno(EINVAL));
	}

	/*
	 * Copy the arguments to the subcommand in from the app's address
	 * space, returning EFAULT if we get a bogus pointer.
	 */
	for (i = 0; i < lx_socketcall_fns[subcmd].s_nargs; i++) {
		uint32_t arg;

		if (copyin(&p2[i], &arg, sizeof (uint32_t)) != 0) {
			return (set_errno(EFAULT));
		}
		args[i] = (unsigned long)arg;
	}

	return ((lx_socketcall_fns[subcmd].s_fn)(args[0], args[1], args[2],
	    args[3], args[4], args[5]));
}

#endif /* defined(_SYSCALL32_IMPL) */

static void
lx_socket_vsd_free(void *data)
{
	lx_socket_aux_data_t *entry;

	entry = (lx_socket_aux_data_t *)data;
	mutex_destroy(&entry->lxsad_lock);
	kmem_free(entry, sizeof (*entry));
}

void
lx_socket_init()
{
	vsd_create(&lx_socket_vsd, lx_socket_vsd_free);
}

void
lx_socket_fini()
{
	vsd_destroy(&lx_socket_vsd);
}
