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
#include <sys/model.h>
#include <sys/brand.h>
#include <netpacket/packet.h>
#include <sockcommon.h>

#include <sys/lx_brand.h>
#include <sys/lx_socket.h>
#include <sys/lx_impl.h>



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
ltos_sockaddr(const struct sockaddr *inaddr, const socklen_t inlen,
    struct sockaddr **outaddr, socklen_t *outlen)
{
	sa_family_t family;
	struct sockaddr_ll *sal;
	int proto;

	VERIFY(inaddr != NULL);
	family = LTOS_FAMILY(inaddr->sa_family);

	switch (family) {
		case (sa_family_t)AF_NOTSUPPORTED:
			return (EPROTONOSUPPORT);

		case (sa_family_t)AF_INVAL:
			return (EAFNOSUPPORT);

		case AF_UNIX:
			if (inlen > sizeof (struct sockaddr_un)) {
				return (EINVAL);
			}

			*outlen = sizeof (struct sockaddr_un);
			*outaddr = kmem_zalloc(*outlen, KM_SLEEP);
			(*outaddr)->sa_family = AF_UNIX;

			if (strcmp(inaddr->sa_data, LX_DEV_LOG) == 0) {
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
			} else if (inaddr->sa_data[0] == '\0') {
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
				convert_abst_path(inaddr, inlen, *outaddr);
			} else {
				bcopy(inaddr->sa_data, (*outaddr)->sa_data,
				    inlen - sizeof (sa_family_t));
			}
			return (0);

		case AF_PACKET:
			sal = (struct sockaddr_ll *)inaddr;
			proto = ltos_pkt_proto(sal->sll_protocol);
			if (proto < 0) {
				return (EINVAL);
			}

			*outlen = inlen;
			*outaddr = (struct sockaddr *)kmem_zalloc(*outlen,
			    KM_SLEEP);
			bcopy(inaddr, *outaddr, inlen);

			sal = (struct sockaddr_ll *)*outaddr;
			sal->sll_family = family;
			sal->sll_protocol = proto;
			return (0);

		case AF_INET:
			if (inlen < sizeof (struct sockaddr)) {
				return (EINVAL);
			}
			*outlen = sizeof (struct sockaddr);
			break;

		case AF_INET6:
			/*
			 * The illumos sockaddr_in6 has one more 32-bit field
			 * than the Linux version.  We assume the caller has
			 * zeroed the sockaddr we're copying into.
			 */
			if (inlen != sizeof (lx_sockaddr_in6_t)) {
				return (EINVAL);
			}
			*outlen = sizeof (struct sockaddr_in6);
			break;

		default:
			*outlen = inlen;
	}

	/*
	 * For most address families, just copying into a sockaddr of the
	 * correct size and updating sa_family is adequate.
	 */
	*outaddr = (struct sockaddr *)kmem_zalloc(*outlen, KM_SLEEP);
	bcopy(inaddr, *outaddr, *outlen);
	(*outaddr)->sa_family = family;
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


long
lx_connect(long sock, uintptr_t name, socklen_t namelen)
{
	struct sonode *so;
	struct sockaddr *laddr = NULL, *saddr = NULL;
	lx_socket_aux_data_t *sad = NULL;
	socklen_t snamelen;
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
		if (namelen < sizeof (sa_family_t) ||
		    namelen > SO_MAXARGSIZE) {
			releasef(sock);
			return (set_errno(EINVAL));
		}
		laddr = kmem_zalloc(namelen, KM_SLEEP);
		if (copyin((void *)name, laddr, namelen) != 0) {
			kmem_free(laddr, namelen);
			releasef(sock);
			return (set_errno(EFAULT));
		}
		error = ltos_sockaddr(laddr, namelen, &saddr, &snamelen);
		if (error != 0) {
			kmem_free(laddr, namelen);
			releasef(sock);
			return (set_errno(error));
		}
	}


	error = socket_connect(so, saddr, snamelen, fp->f_flag,
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

	if (laddr != NULL) {
		kmem_free(laddr, namelen);
	}
	if (saddr != NULL) {
		kmem_free(saddr, snamelen);
	}

	if (error != 0) {
		return (set_errno(error));
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
	NULL, 3,			/* socket */
	NULL, 3,			/* bind */
	(lx_sockfn_t)lx_connect, 3,	/* connect */
	NULL, 2,			/* listen */
	NULL, 3,			/* accept */
	NULL, 3,			/* getsockname */
	NULL, 3,			/* getpeername */
	NULL, 4,			/* socketpair */
	NULL, 4,			/* send */
	NULL, 4,			/* recv */
	NULL, 6,			/* sendto */
	NULL, 6,			/* recvfrom */
	NULL, 2,			/* shutdown */
	NULL, 5,			/* getsockopt */
	NULL, 5,			/* getsockopt */
	NULL, 3,			/* sendmsg */
	NULL, 3,			/* recvmsg */
	NULL, 4,			/* accept4 */
	NULL, 5,			/* recvmmsg */
	NULL, 4				/* sendmmsg */
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

#endif



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
