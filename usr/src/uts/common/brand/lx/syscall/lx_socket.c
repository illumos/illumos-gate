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
#include <netpacket/packet.h>
#include <sockcommon.h>

#include <sys/lx_brand.h>
#include <sys/lx_socket.h>
#include <sys/lx_types.h>
#include <sys/lx_impl.h>

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
} lx_socket_aux_data_t;

/* VSD key for lx-specific socket information */
static uint_t lx_socket_vsd = 0;

/* Convenience enum to enforce translation direction */
typedef enum lx_xlate_dir {
	SUNOS_TO_LX,
	LX_TO_SUNOS
} lx_xlate_dir_t;

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
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED
};

#define	LX_AF_INET6	10
#define	LX_AF_PACKET	17

static const int stol_family[LX_AF_MAX + 1] =  {
	AF_UNSPEC, AF_UNIX, AF_INET, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_LX_NETLINK,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, LX_AF_INET6, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, LX_AF_PACKET
};

#define	LTOS_FAMILY(d) ((d) <= LX_AF_MAX ? ltos_family[(d)] : AF_INVAL)
#define	STOL_FAMILY(d) ((d) <= LX_AF_MAX ? stol_family[(d)] : AF_INVAL)


/*
 * This string is used to prefix all abstract namespace Unix sockets, ie all
 * abstract namespace sockets are converted to regular sockets in the /tmp
 * directory with .ABSK_ prefixed to their names.
 */
#define	ABST_PRFX "/tmp/.ABSK_"
#define	ABST_PRFX_LEN 11

#define	LX_DEV_LOG			"/dev/log"
#define	LX_DEV_LOG_REDIRECT		"/var/run/.dev_log_redirect"

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

#define	LX_FLAG_BUFSZ	64

static int
lx_xlate_sock_flags(int inflags, lx_xlate_dir_t dir)
{
	int i, outflags = 0;
	char buf[LX_FLAG_BUFSZ];

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
				snprintf(buf, LX_FLAG_BUFSZ,
				    "unsupported sock flag %s", map->lxfm_name);
				lx_unsupported(buf);
			}
		}
	}
	if (inflags != 0) {
		snprintf(buf, LX_FLAG_BUFSZ, "unsupported sock flags 0x%08x",
		    inflags);
		lx_unsupported(buf);
	}

	return (outflags);
}

static void
convert_abst_path(const struct sockaddr *inaddr, socklen_t len,
    struct sockaddr *outaddr)
{
	int idx, odx;
	struct sockaddr_un buf;

	/*
	 * len is the entire size of the sockaddr data structure, including the
	 * sa_family, so we need to subtract this out.
	 */
	len -= sizeof (sa_family_t);

	/* Add our abstract prefix */
	(void) strcpy(buf.sun_path, ABST_PRFX);
	for (idx = 1, odx = ABST_PRFX_LEN;
	    idx < len && odx < sizeof (buf.sun_path); idx++, odx++) {
		char c = inaddr->sa_data[idx];
		if (c == '\0' || c == '/') {
			buf.sun_path[odx] = '_';
		} else {
			buf.sun_path[odx] = c;
		}
	}

	/*
	 * Since abstract socket paths may not be NULL terminated, we must
	 * explicitly NULL terminate our string. Don't overflow the buffer if
	 * the path is exactly that size.
	 */
	if (odx == sizeof (buf.sun_path)) {
		buf.sun_path[odx - 1] = '\0';
	} else {
		buf.sun_path[odx] = '\0';
	}

	(void) strcpy(outaddr->sa_data, buf.sun_path);
}

static long
ltos_sockaddr_copyin(const struct sockaddr *inaddr, const socklen_t inlen,
    struct sockaddr **outaddr, socklen_t *outlen)
{
	sa_family_t family;
	struct sockaddr *laddr;
	struct sockaddr_ll *sal;
	int proto, error = 0;

	VERIFY(inaddr != NULL);

	if (inlen < sizeof (sa_family_t) ||
	    inlen > sizeof (struct sockaddr_un)) {
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

			/*
			 * Since the address may expand during translation,
			 * allocate a full sockaddr_un structure for output.
			 * Use of kmem_zalloc prevents garbage from appearing
			 * in the output if the address is shorter than the
			 * maximum.
			 */
			*outlen = sizeof (struct sockaddr_un);
			*outaddr = kmem_zalloc(*outlen, KM_SLEEP);
			(*outaddr)->sa_family = AF_UNIX;

			if (strcmp(laddr->sa_data, LX_DEV_LOG) == 0) {
				/*
				 * In order to support /dev/log -- a Unix
				 * domain socket used for logging that has had
				 * its path hard-coded far and wide -- we need
				 * to relocate the socket into a writable
				 * filesystem.  This also necessitates some
				 * cleanup in bind(); see lx_bind() for
				 * details.
				 */
				(void) strcpy((*outaddr)->sa_data,
				    LX_DEV_LOG_REDIRECT);
			} else if (laddr->sa_data[0] == '\0') {
				/*
				 * Linux supports abstract Unix sockets, which
				 * are simply sockets that do not exist on the
				 * file system.  These sockets are denoted by
				 * beginning the path with a NULL character. To
				 * support these, we strip out the leading NULL
				 * character and change the path to point to a
				 * real place in /tmp directory, by prepending
				 * ABST_PRFX and replacing all illegal
				 * characters with * '_'.
				 */
				convert_abst_path(laddr, inlen, *outaddr);
			} else {
				bcopy(laddr->sa_data, (*outaddr)->sa_data,
				    inlen - sizeof (sa_family_t));
			}
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
			if (inlen != sizeof (lx_sockaddr_in6_t)) {
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

static long
stol_sockaddr_copyout(struct sockaddr *inaddr, socklen_t inlen,
    struct sockaddr *outaddr, socklen_t *outlen, socklen_t orig)
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
		/*
		 * Inform userspace that there is no sockaddr as the result of
		 * this operation by setting the output length to 0.
		 */
		if (copyout(&inlen, outlen, sizeof (inlen)) != 0) {
			return (EFAULT);
		}
		return (0);
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
	if (copyout(&inlen, outlen, sizeof (inlen)) != 0) {
		return (EFAULT);
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

static lx_cmsg_xlate_t lx_cmsg_xlate_tbl[] = {
	{ SOL_SOCKET, SCM_RIGHTS, cmsg_conv_generic,
	    LX_SOL_SOCKET, LX_SCM_RIGHTS, cmsg_conv_generic },
	{ SOL_SOCKET, SCM_UCRED, stol_conv_ucred,
	    LX_SOL_SOCKET, LX_SCM_CRED, ltos_conv_ucred },
	{ SOL_SOCKET, SCM_TIMESTAMP, cmsg_conv_generic,
	    LX_SOL_SOCKET, LX_SCM_TIMESTAMP, cmsg_conv_generic },
	{ IPPROTO_IPV6, IPV6_PKTINFO, cmsg_conv_generic,
	    LX_IPPROTO_IPV6, LX_IPV6_PKTINFO, cmsg_conv_generic }
};

#define	LX_MAX_CMSG_XLATE	\
	(sizeof (lx_cmsg_xlate_tbl) / sizeof (lx_cmsg_xlate_tbl[0]))

#if defined(_LP64)

typedef struct {
	int64_t	cmsg_len;
	int32_t	cmsg_level;
	int32_t	cmsg_type;
} lx_cmsghdr64_t;

/* The alignment/padding for 64bit Linux cmsghdr is the same. */
#define	ISALIGNED_LX_CMSG64(addr)	ISALIGNED_cmsghdr(addr)
#define	ROUNDUP_LX_CMSG64_LEN(len)	ROUNDUP_cmsglen(len)

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
	int len;

	len = sizeof (struct cmsghdr) + sizeof (lx_ucred_t);

	/*
	 * Format the data correctly in the omsg buffer.
	 */
	if (omsg != NULL) {
		struct ucred_s *scred = (struct ucred_s *)CMSG_CONTENT(inmsg);
		prcred_t *cr;
		lx_ucred_t lcred;

		lcred.lxu_pid = scred->uc_pid;
		cr = UCCRED(scred);
		if (cr != NULL) {
			lcred.lxu_uid = cr->pr_euid;
			lcred.lxu_gid = cr->pr_egid;
		} else {
			lcred.lxu_uid = lcred.lxu_gid = 0;
		}

		bcopy(&lcred, CMSG_CONTENT(omsg), sizeof (lx_ucred_t));
	}

	return (len);
}

static int
ltos_conv_ucred(struct cmsghdr *inmsg, struct cmsghdr *omsg)
{
	int len;
	size_t data_len;

	data_len = sizeof (struct ucred_s) + sizeof (prcred_t);

	len = sizeof (struct cmsghdr) + data_len;

	if (omsg != NULL) {
		struct ucred_s *uc;
		prcred_t *pc;
		lx_ucred_t *lcred;

		uc = (struct ucred_s *)CMSG_CONTENT(omsg);
		pc = (prcred_t *)((char *)uc + sizeof (struct ucred_s));

		uc->uc_credoff = sizeof (struct ucred_s);

		lcred = (lx_ucred_t *)CMSG_CONTENT(inmsg);

		uc->uc_pid = lcred->lxu_pid;
		pc->pr_euid = lcred->lxu_uid;
		pc->pr_egid = lcred->lxu_gid;
	}

	return (len);
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
		    inmsg->cmsg_type == xlate->lcx_linux_type) {
			ASSERT(xlate->lcx_ltos_conv != NULL);
			len = xlate->lcx_ltos_conv(inmsg, omsg);
			if (omsg != NULL) {
				omsg->cmsg_len = len;
				omsg->cmsg_level = xlate->lcx_sunos_level;
				omsg->cmsg_type = xlate->lcx_sunos_type;
			}
			return (len);
		} else if (dir == SUNOS_TO_LX &&
		    inmsg->cmsg_level == xlate->lcx_sunos_level &&
		    inmsg->cmsg_type == xlate->lcx_sunos_type) {
			ASSERT(xlate->lcx_stol_conv != NULL);
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
    socklen_t *outlenp, socklen_t orig_outlen)
{
	void *obuf;
	struct cmsghdr *inmsg, *omsg;
	int error = 0, count = 0;
	socklen_t lx_len = 0;

	if (inlen == 0) {
		/* Simply output the zero controllen */
		goto finish;
	}

	VERIFY(inlen > sizeof (struct cmsghdr));

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
		count++;
		lx_len += sz;
	}

#if defined(_LP64)
	if (get_udatamodel() == DATAMODEL_NATIVE) {
		/*
		 * Account for the extra header space needed here so we can
		 * fail out now if the orig_outlen is too short.
		 */

		lx_len += count * LX_CMSG64_DIFF;
	}
#endif /* defined(_LP64) */

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
	if (get_udatamodel() == DATAMODEL_NATIVE) {
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
	if (outlenp != NULL &&
	    copyout(&lx_len, outlenp, sizeof (lx_len)) != 0) {
		return (EFAULT);
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
				/* set CLOEXEC on the fd */
				fp = getf(fds[i]);
				VERIFY(fp != NULL);
				flags = f_getfd(fds[i]);
				flags |= FD_CLOEXEC;
				f_setfd(fds[i], flags);
				releasef(fds[i]);
			}
		}
	}
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

long
lx_connect(long sock, uintptr_t name, socklen_t namelen)
{
	struct sonode *so;
	struct sockaddr *addr = NULL;
	lx_socket_aux_data_t *sad = NULL;
	socklen_t len;
	file_t *fp;
	int error;

	if ((so = getsonode(sock, &error, &fp)) == NULL) {
		return (set_errno(error));
	}

	/*
	 * Ensure the name is size appropriately before we alloc memory and
	 * copy it in from userspace.  We need at least the address family to
	 * make later sizing decisions.
	 */
	if (namelen != 0) {
		error = ltos_sockaddr_copyin((struct sockaddr *)name, namelen,
		    &addr, &len);
		if (error != 0) {
			releasef(sock);
			return (set_errno(error));
		}
	}


	error = socket_connect(so, addr, len, fp->f_flag,
	    _SOCONNECT_XPG4_2, CRED());

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

	releasef(sock);

	if (addr != NULL) {
		kmem_free(addr, len);
	}

	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}

static long
lx_recv_common(int sock, struct nmsghdr *msg, struct uio *uiop, int flags,
    socklen_t *namelenp, socklen_t *controllenp, int *flagsp)
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

	if ((so = getsonode(sock, &error, &fp)) == NULL) {
		return (set_errno(error));
	}

	fd_cloexec = ((flags & LX_MSG_CMSG_CLOEXEC) != 0);
	flags = lx_xlate_sock_flags(flags, LX_TO_SUNOS);
	len = uiop->uio_resid;
	uiop->uio_fmode = fp->f_flag;
	uiop->uio_extflg = UIO_COPY_CACHED;

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

	error = socket_recvmsg(so, msg, uiop, CRED());
	if (error) {
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

	return (len - uiop->uio_resid);

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
	struct uio auio;
	struct iovec aiov[1];

	if ((ssize_t)len < 0) {
		/*
		 * The input len is unsigned, so limit it to SSIZE_MAX since
		 * the return value is signed.
		 */
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

	smsg.msg_namelen = 0;
	smsg.msg_controllen = 0;
	smsg.msg_flags = 0;
	return (lx_recv_common(sock, &smsg, &auio, flags, NULL, NULL, NULL));
}

long
lx_recvfrom(int sock, void *buffer, size_t len, int flags,
    struct sockaddr *srcaddr, socklen_t *addrlenp)
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

	return (lx_recv_common(sock, &smsg, &auio, flags, addrlenp, NULL,
	    NULL));
}

long
lx_recvmsg(int sock, void *msg, int flags)
{
	struct nmsghdr smsg;
	struct uio auio;
	struct iovec buf[IOV_MAX_STACK], *aiov;
	int i, iovcnt, iovsize;
	long res;
	ssize_t len = 0;
	socklen_t *namelenp;
	socklen_t *controllenp;
	int *flagsp;

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
		struct iovec32 buf32[IOV_MAX_STACK], *aiov32;
		ssize_t iov32size;
		ssize32_t count32;

		iov32size = iovcnt * sizeof (struct iovec32);
		if (iovsize != 0) {
			aiov32 = kmem_alloc(iov32size, KM_SLEEP);
		} else {
			aiov32 = buf32;
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

	res = lx_recv_common(sock, &smsg, &auio, flags, namelenp, controllenp,
	    flagsp);

	if (iovsize != 0) {
		kmem_free(aiov, iovsize);
	}

	return (res);
}

/*
 * Custom version of socket_sendmsg.
 * This facilitates support of LX_MSG_NOSIGNAL with a parameter to override
 * SIGPIPE behavior on EPIPE.
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
		    msg->msg_namelen, &name, &namelen);
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

#if defined(_SYSCALL32_IMPL)

#define	LX_SYS_SOCKETCALL		102
#define	LX_SOCKETCALL_MAX		20

typedef long (*lx_sockfn_t)();

static struct {
	lx_sockfn_t s_fn;	/* Function implementing the subcommand */
	int s_nargs;		/* Number of arguments the function takes */
} lx_socketcall_fns[] = {
	NULL,		3,	/* socket */
	NULL,		3,	/* bind */
	lx_connect,	3,	/* connect */
	NULL,		2,	/* listen */
	NULL,		3,	/* accept */
	NULL,		3,	/* getsockname */
	NULL,		3,	/* getpeername */
	NULL,		4,	/* socketpair */
	lx_send,	4,	/* send */
	lx_recv,	4,	/* recv */
	lx_sendto,	6,	/* sendto */
	lx_recvfrom,	6,	/* recvfrom */
	NULL,		2,	/* shutdown */
	NULL,		5,	/* getsockopt */
	NULL,		5,	/* getsockopt */
	lx_sendmsg,	3,	/* sendmsg */
	lx_recvmsg,	3,	/* recvmsg */
	NULL,		4,	/* accept4 */
	NULL,		5,	/* recvmmsg */
	NULL,		4	/* sendmmsg */
};

long
lx_socketcall(long p1, uint32_t *p2)
{
	int subcmd, i;
	unsigned long args[6] = { 0, 0, 0, 0, 0, 0 };
	lx_lwp_data_t *lwpd = ttolxlwp(curthread);

	/* incoming subcmds are 1-indexed */
	subcmd = (int)p1 - 1;

	if (subcmd < 0 || subcmd >= LX_SOCKETCALL_MAX) {
		return (-EINVAL);
	}

	/* Vector back out to userland emulation if we lack IKE */
	if (lx_socketcall_fns[subcmd].s_fn == NULL) {
		uintptr_t uargs[2] = {p1, (uintptr_t)p2};
		/* The userspace emulation will handle the syscall return */
		lwpd->br_eosys = JUSTRETURN;
		lx_emulate_user32(ttolwp(curthread), LX_SYS_SOCKETCALL, uargs);
		return (0);
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
