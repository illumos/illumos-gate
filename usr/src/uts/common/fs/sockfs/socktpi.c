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
 * Copyright (c) 1995, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/kmem_impl.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/user.h>
#include <sys/termios.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/suntpi.h>
#include <sys/ddi.h>
#include <sys/esunddi.h>
#include <sys/flock.h>
#include <sys/modctl.h>
#include <sys/vtrace.h>
#include <sys/cmn_err.h>
#include <sys/pathname.h>

#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <sys/strsun.h>

#include <sys/tiuser.h>
#define	_SUN_TPI_VERSION	2
#include <sys/tihdr.h>
#include <sys/timod.h>		/* TI_GETMYNAME, TI_GETPEERNAME */

#include <c2/audit.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/tcp.h>
#include <inet/udp_impl.h>

#include <sys/zone.h>

#include <fs/sockfs/nl7c.h>
#include <fs/sockfs/nl7curi.h>

#include <fs/sockfs/sockcommon.h>
#include <fs/sockfs/socktpi.h>
#include <fs/sockfs/socktpi_impl.h>

/*
 * Possible failures when memory can't be allocated. The documented behavior:
 *
 * 		5.5:			4.X:		XNET:
 * accept:	ENOMEM/ENOSR/EINTR	- (EINTR)	ENOMEM/ENOBUFS/ENOSR/
 *							EINTR
 *	(4.X does not document EINTR but returns it)
 * bind:	ENOSR			-		ENOBUFS/ENOSR
 * connect: 	EINTR			EINTR		ENOBUFS/ENOSR/EINTR
 * getpeername:	ENOMEM/ENOSR		ENOBUFS (-)	ENOBUFS/ENOSR
 * getsockname:	ENOMEM/ENOSR		ENOBUFS (-)	ENOBUFS/ENOSR
 *	(4.X getpeername and getsockname do not fail in practice)
 * getsockopt:	ENOMEM/ENOSR		-		ENOBUFS/ENOSR
 * listen:	-			-		ENOBUFS
 * recv:	ENOMEM/ENOSR/EINTR	EINTR		ENOBUFS/ENOMEM/ENOSR/
 *							EINTR
 * send:	ENOMEM/ENOSR/EINTR	ENOBUFS/EINTR	ENOBUFS/ENOMEM/ENOSR/
 *							EINTR
 * setsockopt:	ENOMEM/ENOSR		-		ENOBUFS/ENOMEM/ENOSR
 * shutdown:	ENOMEM/ENOSR		-		ENOBUFS/ENOSR
 * socket:	ENOMEM/ENOSR		ENOBUFS		ENOBUFS/ENOMEM/ENOSR
 * socketpair:	ENOMEM/ENOSR		-		ENOBUFS/ENOMEM/ENOSR
 *
 * Resolution. When allocation fails:
 *	recv: return EINTR
 *	send: return EINTR
 *	connect, accept: EINTR
 *	bind, listen, shutdown (unbind, unix_close, disconnect): sleep
 *	socket, socketpair: ENOBUFS
 *	getpeername, getsockname: sleep
 *	getsockopt, setsockopt: sleep
 */

#ifdef SOCK_TEST
/*
 * Variables that make sockfs do something other than the standard TPI
 * for the AF_INET transports.
 *
 * solisten_tpi_tcp:
 *	TCP can handle a O_T_BIND_REQ with an increased backlog even though
 *	the transport is already bound. This is needed to avoid loosing the
 *	port number should listen() do a T_UNBIND_REQ followed by a
 *	O_T_BIND_REQ.
 *
 * soconnect_tpi_udp:
 *	UDP and ICMP can handle a T_CONN_REQ.
 *	This is needed to make the sequence of connect(), getsockname()
 *	return the local IP address used to send packets to the connected to
 *	destination.
 *
 * soconnect_tpi_tcp:
 *	TCP can handle a T_CONN_REQ without seeing a O_T_BIND_REQ.
 *	Set this to non-zero to send TPI conformant messages to TCP in this
 *	respect. This is a performance optimization.
 *
 * soaccept_tpi_tcp:
 *	TCP can handle a T_CONN_REQ without the acceptor being bound.
 *	This is a performance optimization that has been picked up in XTI.
 *
 * soaccept_tpi_multioptions:
 *	When inheriting SOL_SOCKET options from the listener to the accepting
 *	socket send them as a single message for AF_INET{,6}.
 */
int solisten_tpi_tcp = 0;
int soconnect_tpi_udp = 0;
int soconnect_tpi_tcp = 0;
int soaccept_tpi_tcp = 0;
int soaccept_tpi_multioptions = 1;
#else /* SOCK_TEST */
#define	soconnect_tpi_tcp	0
#define	soconnect_tpi_udp	0
#define	solisten_tpi_tcp	0
#define	soaccept_tpi_tcp	0
#define	soaccept_tpi_multioptions	1
#endif /* SOCK_TEST */

#ifdef SOCK_TEST
extern int do_useracc;
extern clock_t sock_test_timelimit;
#endif /* SOCK_TEST */

extern uint32_t ucredsize;

/*
 * Some X/Open added checks might have to be backed out to keep SunOS 4.X
 * applications working. Turn on this flag to disable these checks.
 */
int xnet_skip_checks = 0;
int xnet_check_print = 0;
int xnet_truncate_print = 0;

static void sotpi_destroy(struct sonode *);
static struct sonode *sotpi_create(struct sockparams *, int, int, int, int,
    int, int *, cred_t *cr);

static boolean_t	sotpi_info_create(struct sonode *, int);
static void		sotpi_info_init(struct sonode *);
static void 		sotpi_info_fini(struct sonode *);
static void 		sotpi_info_destroy(struct sonode *);

/*
 * Do direct function call to the transport layer below; this would
 * also allow the transport to utilize read-side synchronous stream
 * interface if necessary.  This is a /etc/system tunable that must
 * not be modified on a running system.  By default this is enabled
 * for performance reasons and may be disabled for debugging purposes.
 */
boolean_t socktpi_direct = B_TRUE;

static struct kmem_cache *socktpi_cache, *socktpi_unix_cache;

extern	void sigintr(k_sigset_t *, int);
extern	void sigunintr(k_sigset_t *);

static int	sotpi_unbind(struct sonode *, int);

/* TPI sockfs sonode operations */
int 		sotpi_init(struct sonode *, struct sonode *, struct cred *,
		    int);
static int	sotpi_accept(struct sonode *, int, struct cred *,
		    struct sonode **);
static int	sotpi_bind(struct sonode *, struct sockaddr *, socklen_t,
		    int, struct cred *);
static int	sotpi_listen(struct sonode *, int, struct cred *);
static int	sotpi_connect(struct sonode *, struct sockaddr *,
		    socklen_t, int, int, struct cred *);
extern int	sotpi_recvmsg(struct sonode *, struct nmsghdr *,
		    struct uio *, struct cred *);
static int	sotpi_sendmsg(struct sonode *, struct nmsghdr *,
		    struct uio *, struct cred *);
static int	sotpi_sendmblk(struct sonode *, struct nmsghdr *, int,
		    struct cred *, mblk_t **);
static int	sosend_dgramcmsg(struct sonode *, struct sockaddr *, socklen_t,
		    struct uio *, void *, t_uscalar_t, int);
static int	sodgram_direct(struct sonode *, struct sockaddr *,
		    socklen_t, struct uio *, int);
extern int	sotpi_getpeername(struct sonode *, struct sockaddr *,
		    socklen_t *, boolean_t, struct cred *);
static int	sotpi_getsockname(struct sonode *, struct sockaddr *,
		    socklen_t *, struct cred *);
static int	sotpi_shutdown(struct sonode *, int, struct cred *);
extern int	sotpi_getsockopt(struct sonode *, int, int, void *,
		    socklen_t *, int, struct cred *);
extern int	sotpi_setsockopt(struct sonode *, int, int, const void *,
		    socklen_t, struct cred *);
static int 	sotpi_ioctl(struct sonode *, int, intptr_t, int, struct cred *,
		    int32_t *);
static int 	socktpi_plumbioctl(struct vnode *, int, intptr_t, int,
		    struct cred *, int32_t *);
static int 	sotpi_poll(struct sonode *, short, int, short *,
		    struct pollhead **);
static int 	sotpi_close(struct sonode *, int, struct cred *);

static int	i_sotpi_info_constructor(sotpi_info_t *);
static void 	i_sotpi_info_destructor(sotpi_info_t *);

sonodeops_t sotpi_sonodeops = {
	sotpi_init,		/* sop_init		*/
	sotpi_accept,		/* sop_accept		*/
	sotpi_bind,		/* sop_bind		*/
	sotpi_listen,		/* sop_listen		*/
	sotpi_connect,		/* sop_connect		*/
	sotpi_recvmsg,		/* sop_recvmsg		*/
	sotpi_sendmsg,		/* sop_sendmsg		*/
	sotpi_sendmblk,		/* sop_sendmblk		*/
	sotpi_getpeername,	/* sop_getpeername	*/
	sotpi_getsockname,	/* sop_getsockname	*/
	sotpi_shutdown,		/* sop_shutdown		*/
	sotpi_getsockopt,	/* sop_getsockopt	*/
	sotpi_setsockopt,	/* sop_setsockopt	*/
	sotpi_ioctl,		/* sop_ioctl		*/
	sotpi_poll,		/* sop_poll		*/
	sotpi_close,		/* sop_close		*/
};

/*
 * Return a TPI socket vnode.
 *
 * Note that sockets assume that the driver will clone (either itself
 * or by using the clone driver) i.e. a socket() call will always
 * result in a new vnode being created.
 */

/*
 * Common create code for socket and accept. If tso is set the values
 * from that node is used instead of issuing a T_INFO_REQ.
 */

/* ARGSUSED */
static struct sonode *
sotpi_create(struct sockparams *sp, int family, int type, int protocol,
    int version, int sflags, int *errorp, cred_t *cr)
{
	struct sonode	*so;
	kmem_cache_t 	*cp;
	int		sfamily = family;

	ASSERT(sp->sp_sdev_info.sd_vnode != NULL);

	if (family == AF_NCA) {
		/*
		 * The request is for an NCA socket so for NL7C use the
		 * INET domain instead and mark NL7C_AF_NCA below.
		 */
		family = AF_INET;
		/*
		 * NL7C is not supported in the non-global zone,
		 * we enforce this restriction here.
		 */
		if (getzoneid() != GLOBAL_ZONEID) {
			*errorp = ENOTSUP;
			return (NULL);
		}
	}

	/*
	 * to be compatible with old tpi socket implementation ignore
	 * sleep flag (sflags) passed in
	 */
	cp = (family == AF_UNIX) ? socktpi_unix_cache : socktpi_cache;
	so = kmem_cache_alloc(cp, KM_SLEEP);
	if (so == NULL) {
		*errorp = ENOMEM;
		return (NULL);
	}

	sonode_init(so, sp, family, type, protocol, &sotpi_sonodeops);
	sotpi_info_init(so);

	if (sfamily == AF_NCA) {
		SOTOTPI(so)->sti_nl7c_flags = NL7C_AF_NCA;
	}

	if (version == SOV_DEFAULT)
		version = so_default_version;

	so->so_version = (short)version;
	*errorp = 0;

	return (so);
}

static void
sotpi_destroy(struct sonode *so)
{
	kmem_cache_t *cp;
	struct sockparams *origsp;

	/*
	 * If there is a new dealloc function (ie. smod_destroy_func),
	 * then it should check the correctness of the ops.
	 */

	ASSERT(so->so_ops == &sotpi_sonodeops);

	origsp = SOTOTPI(so)->sti_orig_sp;

	sotpi_info_fini(so);

	if (so->so_state & SS_FALLBACK_COMP) {
		/*
		 * A fallback happend, which means that a sotpi_info_t struct
		 * was allocated (as opposed to being allocated from the TPI
		 * sonode cache. Therefore we explicitly free the struct
		 * here.
		 */
		sotpi_info_destroy(so);
		ASSERT(origsp != NULL);

		origsp->sp_smod_info->smod_sock_destroy_func(so);
		SOCKPARAMS_DEC_REF(origsp);
	} else {
		sonode_fini(so);
		cp = (so->so_family == AF_UNIX) ? socktpi_unix_cache :
		    socktpi_cache;
		kmem_cache_free(cp, so);
	}
}

/* ARGSUSED1 */
int
sotpi_init(struct sonode *so, struct sonode *tso, struct cred *cr, int flags)
{
	major_t maj;
	dev_t newdev;
	struct vnode *vp;
	int error = 0;
	struct stdata *stp;

	sotpi_info_t *sti = SOTOTPI(so);

	dprint(1, ("sotpi_init()\n"));

	/*
	 * over write the sleep flag passed in but that is ok
	 * as tpi socket does not honor sleep flag.
	 */
	flags |= FREAD|FWRITE;

	/*
	 * Record in so_flag that it is a clone.
	 */
	if (getmajor(sti->sti_dev) == clone_major)
		so->so_flag |= SOCLONE;

	if ((so->so_type == SOCK_STREAM || so->so_type == SOCK_DGRAM) &&
	    (so->so_family == AF_INET || so->so_family == AF_INET6) &&
	    (so->so_protocol == IPPROTO_TCP || so->so_protocol == IPPROTO_UDP ||
	    so->so_protocol == IPPROTO_IP)) {
		/* Tell tcp or udp that it's talking to sockets */
		flags |= SO_SOCKSTR;

		/*
		 * Here we indicate to socktpi_open() our attempt to
		 * make direct calls between sockfs and transport.
		 * The final decision is left to socktpi_open().
		 */
		sti->sti_direct = 1;

		ASSERT(so->so_type != SOCK_DGRAM || tso == NULL);
		if (so->so_type == SOCK_STREAM && tso != NULL) {
			if (SOTOTPI(tso)->sti_direct) {
				/*
				 * Inherit sti_direct from listener and pass
				 * SO_ACCEPTOR open flag to tcp, indicating
				 * that this is an accept fast-path instance.
				 */
				flags |= SO_ACCEPTOR;
			} else {
				/*
				 * sti_direct is not set on listener, meaning
				 * that the listener has been converted from
				 * a socket to a stream.  Ensure that the
				 * acceptor inherits these settings.
				 */
				sti->sti_direct = 0;
				flags &= ~SO_SOCKSTR;
			}
		}
	}

	/*
	 * Tell local transport that it is talking to sockets.
	 */
	if (so->so_family == AF_UNIX) {
		flags |= SO_SOCKSTR;
	}

	vp = SOTOV(so);
	newdev = vp->v_rdev;
	maj = getmajor(newdev);
	ASSERT(STREAMSTAB(maj));

	error = stropen(vp, &newdev, flags, cr);

	stp = vp->v_stream;
	if (error == 0) {
		if (so->so_flag & SOCLONE)
			ASSERT(newdev != vp->v_rdev);
		mutex_enter(&so->so_lock);
		sti->sti_dev = newdev;
		vp->v_rdev = newdev;
		mutex_exit(&so->so_lock);

		if (stp->sd_flag & STRISTTY) {
			/*
			 * this is a post SVR4 tty driver - a socket can not
			 * be a controlling terminal. Fail the open.
			 */
			(void) sotpi_close(so, flags, cr);
			return (ENOTTY);	/* XXX */
		}

		ASSERT(stp->sd_wrq != NULL);
		sti->sti_provinfo = tpi_findprov(stp->sd_wrq);

		/*
		 * If caller is interested in doing direct function call
		 * interface to/from transport module, probe the module
		 * directly beneath the streamhead to see if it qualifies.
		 *
		 * We turn off the direct interface when qualifications fail.
		 * In the acceptor case, we simply turn off the sti_direct
		 * flag on the socket. We do the fallback after the accept
		 * has completed, before the new socket is returned to the
		 * application.
		 */
		if (sti->sti_direct) {
			queue_t *tq = stp->sd_wrq->q_next;

			/*
			 * sti_direct is currently supported and tested
			 * only for tcp/udp; this is the main reason to
			 * have the following assertions.
			 */
			ASSERT(so->so_family == AF_INET ||
			    so->so_family == AF_INET6);
			ASSERT(so->so_protocol == IPPROTO_UDP ||
			    so->so_protocol == IPPROTO_TCP ||
			    so->so_protocol == IPPROTO_IP);
			ASSERT(so->so_type == SOCK_DGRAM ||
			    so->so_type == SOCK_STREAM);

			/*
			 * Abort direct call interface if the module directly
			 * underneath the stream head is not defined with the
			 * _D_DIRECT flag.  This could happen in the tcp or
			 * udp case, when some other module is autopushed
			 * above it, or for some reasons the expected module
			 * isn't purely D_MP (which is the main requirement).
			 */
			if (!socktpi_direct || !(tq->q_flag & _QDIRECT) ||
			    !(_OTHERQ(tq)->q_flag & _QDIRECT)) {
				int rval;

				/* Continue on without direct calls */
				sti->sti_direct = 0;

				/*
				 * Cannot issue ioctl on fallback socket since
				 * there is no conn associated with the queue.
				 * The fallback downcall will notify the proto
				 * of the change.
				 */
				if (!(flags & SO_ACCEPTOR) &&
				    !(flags & SO_FALLBACK)) {
					if ((error = strioctl(vp,
					    _SIOCSOCKFALLBACK, 0, 0, K_TO_K,
					    cr, &rval)) != 0) {
						(void) sotpi_close(so, flags,
						    cr);
						return (error);
					}
				}
			}
		}

		if (flags & SO_FALLBACK) {
			/*
			 * The stream created does not have a conn.
			 * do stream set up after conn has been assigned
			 */
			return (error);
		}
		if (error = so_strinit(so, tso)) {
			(void) sotpi_close(so, flags, cr);
			return (error);
		}

		/* Wildcard */
		if (so->so_protocol != so->so_sockparams->sp_protocol) {
			int protocol = so->so_protocol;
			/*
			 * Issue SO_PROTOTYPE setsockopt.
			 */
			error = sotpi_setsockopt(so, SOL_SOCKET, SO_PROTOTYPE,
			    &protocol, (t_uscalar_t)sizeof (protocol), cr);
			if (error != 0) {
				(void) sotpi_close(so, flags, cr);
				/*
				 * Setsockopt often fails with ENOPROTOOPT but
				 * socket() should fail with
				 * EPROTONOSUPPORT/EPROTOTYPE.
				 */
				return (EPROTONOSUPPORT);
			}
		}

	} else {
		/*
		 * While the same socket can not be reopened (unlike specfs)
		 * the stream head sets STREOPENFAIL when the autopush fails.
		 */
		if ((stp != NULL) &&
		    (stp->sd_flag & STREOPENFAIL)) {
			/*
			 * Open failed part way through.
			 */
			mutex_enter(&stp->sd_lock);
			stp->sd_flag &= ~STREOPENFAIL;
			mutex_exit(&stp->sd_lock);
			(void) sotpi_close(so, flags, cr);
			return (error);
			/*NOTREACHED*/
		}
		ASSERT(stp == NULL);
	}
	TRACE_4(TR_FAC_SOCKFS, TR_SOCKFS_OPEN,
	    "sockfs open:maj %d vp %p so %p error %d",
	    maj, vp, so, error);
	return (error);
}

/*
 * Bind the socket to an unspecified address in sockfs only.
 * Used for TCP/UDP transports where we know that the O_T_BIND_REQ isn't
 * required in all cases.
 */
static void
so_automatic_bind(struct sonode *so)
{
	sotpi_info_t *sti = SOTOTPI(so);
	ASSERT(so->so_family == AF_INET || so->so_family == AF_INET6);

	ASSERT(MUTEX_HELD(&so->so_lock));
	ASSERT(!(so->so_state & SS_ISBOUND));
	ASSERT(sti->sti_unbind_mp);

	ASSERT(sti->sti_laddr_len <= sti->sti_laddr_maxlen);
	bzero(sti->sti_laddr_sa, sti->sti_laddr_len);
	sti->sti_laddr_sa->sa_family = so->so_family;
	so->so_state |= SS_ISBOUND;
}


/*
 * bind the socket.
 *
 * If the socket is already bound and none of _SOBIND_SOCKBSD or _SOBIND_XPG4_2
 * are passed in we allow rebinding. Note that for backwards compatibility
 * even "svr4" sockets pass in _SOBIND_SOCKBSD/SOV_SOCKBSD to sobind/bind.
 * Thus the rebinding code is currently not executed.
 *
 * The constraints for rebinding are:
 * - it is a SOCK_DGRAM, or
 * - it is a SOCK_STREAM/SOCK_SEQPACKET that has not been connected
 *   and no listen() has been done.
 * This rebinding code was added based on some language in the XNET book
 * about not returning EINVAL it the protocol allows rebinding. However,
 * this language is not present in the Posix socket draft. Thus maybe the
 * rebinding logic should be deleted from the source.
 *
 * A null "name" can be used to unbind the socket if:
 * - it is a SOCK_DGRAM, or
 * - it is a SOCK_STREAM/SOCK_SEQPACKET that has not been connected
 *   and no listen() has been done.
 */
/* ARGSUSED */
static int
sotpi_bindlisten(struct sonode *so, struct sockaddr *name,
    socklen_t namelen, int backlog, int flags, struct cred *cr)
{
	struct T_bind_req	bind_req;
	struct T_bind_ack	*bind_ack;
	int			error = 0;
	mblk_t			*mp;
	void			*addr;
	t_uscalar_t		addrlen;
	int			unbind_on_err = 1;
	boolean_t		clear_acceptconn_on_err = B_FALSE;
	boolean_t		restore_backlog_on_err = B_FALSE;
	int			save_so_backlog;
	t_scalar_t		PRIM_type = O_T_BIND_REQ;
	boolean_t		tcp_udp_xport;
	void			*nl7c = NULL;
	sotpi_info_t		*sti = SOTOTPI(so);

	dprintso(so, 1, ("sotpi_bindlisten(%p, %p, %d, %d, 0x%x) %s\n",
	    (void *)so, (void *)name, namelen, backlog, flags,
	    pr_state(so->so_state, so->so_mode)));

	tcp_udp_xport = so->so_type == SOCK_STREAM || so->so_type == SOCK_DGRAM;

	if (!(flags & _SOBIND_LOCK_HELD)) {
		mutex_enter(&so->so_lock);
		so_lock_single(so);	/* Set SOLOCKED */
	} else {
		ASSERT(MUTEX_HELD(&so->so_lock));
		ASSERT(so->so_flag & SOLOCKED);
	}

	/*
	 * Make sure that there is a preallocated unbind_req message
	 * before binding. This message allocated when the socket is
	 * created  but it might be have been consumed.
	 */
	if (sti->sti_unbind_mp == NULL) {
		dprintso(so, 1, ("sobind: allocating unbind_req\n"));
		/* NOTE: holding so_lock while sleeping */
		sti->sti_unbind_mp =
		    soallocproto(sizeof (struct T_unbind_req), _ALLOC_SLEEP,
		    cr);
	}

	if (flags & _SOBIND_REBIND) {
		/*
		 * Called from solisten after doing an sotpi_unbind() or
		 * potentially without the unbind (latter for AF_INET{,6}).
		 */
		ASSERT(name == NULL && namelen == 0);

		if (so->so_family == AF_UNIX) {
			ASSERT(sti->sti_ux_bound_vp);
			addr = &sti->sti_ux_laddr;
			addrlen = (t_uscalar_t)sizeof (sti->sti_ux_laddr);
			dprintso(so, 1, ("sobind rebind UNIX: addrlen %d, "
			    "addr 0x%p, vp %p\n",
			    addrlen,
			    (void *)((struct so_ux_addr *)addr)->soua_vp,
			    (void *)sti->sti_ux_bound_vp));
		} else {
			addr = sti->sti_laddr_sa;
			addrlen = (t_uscalar_t)sti->sti_laddr_len;
		}
	} else if (flags & _SOBIND_UNSPEC) {
		ASSERT(name == NULL && namelen == 0);

		/*
		 * The caller checked SS_ISBOUND but not necessarily
		 * under so_lock
		 */
		if (so->so_state & SS_ISBOUND) {
			/* No error */
			goto done;
		}

		/* Set an initial local address */
		switch (so->so_family) {
		case AF_UNIX:
			/*
			 * Use an address with same size as struct sockaddr
			 * just like BSD.
			 */
			sti->sti_laddr_len =
			    (socklen_t)sizeof (struct sockaddr);
			ASSERT(sti->sti_laddr_len <= sti->sti_laddr_maxlen);
			bzero(sti->sti_laddr_sa, sti->sti_laddr_len);
			sti->sti_laddr_sa->sa_family = so->so_family;

			/*
			 * Pass down an address with the implicit bind
			 * magic number and the rest all zeros.
			 * The transport will return a unique address.
			 */
			sti->sti_ux_laddr.soua_vp = NULL;
			sti->sti_ux_laddr.soua_magic = SOU_MAGIC_IMPLICIT;
			addr = &sti->sti_ux_laddr;
			addrlen = (t_uscalar_t)sizeof (sti->sti_ux_laddr);
			break;

		case AF_INET:
		case AF_INET6:
			/*
			 * An unspecified bind in TPI has a NULL address.
			 * Set the address in sockfs to have the sa_family.
			 */
			sti->sti_laddr_len = (so->so_family == AF_INET) ?
			    (socklen_t)sizeof (sin_t) :
			    (socklen_t)sizeof (sin6_t);
			ASSERT(sti->sti_laddr_len <= sti->sti_laddr_maxlen);
			bzero(sti->sti_laddr_sa, sti->sti_laddr_len);
			sti->sti_laddr_sa->sa_family = so->so_family;
			addr = NULL;
			addrlen = 0;
			break;

		default:
			/*
			 * An unspecified bind in TPI has a NULL address.
			 * Set the address in sockfs to be zero length.
			 *
			 * Can not assume there is a sa_family for all
			 * protocol families. For example, AF_X25 does not
			 * have a family field.
			 */
			bzero(sti->sti_laddr_sa, sti->sti_laddr_len);
			sti->sti_laddr_len = 0;	/* XXX correct? */
			addr = NULL;
			addrlen = 0;
			break;
		}

	} else {
		if (so->so_state & SS_ISBOUND) {
			/*
			 * If it is ok to rebind the socket, first unbind
			 * with the transport. A rebind to the NULL address
			 * is interpreted as an unbind.
			 * Note that a bind to NULL in BSD does unbind the
			 * socket but it fails with EINVAL.
			 * Note that regular sockets set SOV_SOCKBSD i.e.
			 * _SOBIND_SOCKBSD gets set here hence no type of
			 * socket does currently allow rebinding.
			 *
			 * If the name is NULL just do an unbind.
			 */
			if (flags & (_SOBIND_SOCKBSD|_SOBIND_XPG4_2) &&
			    name != NULL) {
				error = EINVAL;
				unbind_on_err = 0;
				eprintsoline(so, error);
				goto done;
			}
			if ((so->so_mode & SM_CONNREQUIRED) &&
			    (so->so_state & SS_CANTREBIND)) {
				error = EINVAL;
				unbind_on_err = 0;
				eprintsoline(so, error);
				goto done;
			}
			error = sotpi_unbind(so, 0);
			if (error) {
				eprintsoline(so, error);
				goto done;
			}
			ASSERT(!(so->so_state & SS_ISBOUND));
			if (name == NULL) {
				so->so_state &=
				    ~(SS_ISCONNECTED|SS_ISCONNECTING);
				goto done;
			}
		}

		/* X/Open requires this check */
		if ((so->so_state & SS_CANTSENDMORE) && !xnet_skip_checks) {
			if (xnet_check_print) {
				printf("sockfs: X/Open bind state check "
				    "caused EINVAL\n");
			}
			error = EINVAL;
			goto done;
		}

		switch (so->so_family) {
		case AF_UNIX:
			/*
			 * All AF_UNIX addresses are nul terminated
			 * when copied (copyin_name) in so the minimum
			 * length is 3 bytes.
			 */
			if (name == NULL ||
			    (ssize_t)namelen <= sizeof (short) + 1) {
				error = EISDIR;
				eprintsoline(so, error);
				goto done;
			}
			/*
			 * Verify so_family matches the bound family.
			 * BSD does not check this for AF_UNIX resulting
			 * in funny mknods.
			 */
			if (name->sa_family != so->so_family) {
				error = EAFNOSUPPORT;
				goto done;
			}
			break;
		case AF_INET:
			if (name == NULL) {
				error = EINVAL;
				eprintsoline(so, error);
				goto done;
			}
			if ((size_t)namelen != sizeof (sin_t)) {
				error = name->sa_family != so->so_family ?
				    EAFNOSUPPORT : EINVAL;
				eprintsoline(so, error);
				goto done;
			}
			if ((flags & _SOBIND_XPG4_2) &&
			    (name->sa_family != so->so_family)) {
				/*
				 * This check has to be made for X/Open
				 * sockets however application failures have
				 * been observed when it is applied to
				 * all sockets.
				 */
				error = EAFNOSUPPORT;
				eprintsoline(so, error);
				goto done;
			}
			/*
			 * Force a zero sa_family to match so_family.
			 *
			 * Some programs like inetd(1M) don't set the
			 * family field. Other programs leave
			 * sin_family set to garbage - SunOS 4.X does
			 * not check the family field on a bind.
			 * We use the family field that
			 * was passed in to the socket() call.
			 */
			name->sa_family = so->so_family;
			break;

		case AF_INET6: {
#ifdef DEBUG
			sin6_t *sin6 = (sin6_t *)name;
#endif /* DEBUG */

			if (name == NULL) {
				error = EINVAL;
				eprintsoline(so, error);
				goto done;
			}
			if ((size_t)namelen != sizeof (sin6_t)) {
				error = name->sa_family != so->so_family ?
				    EAFNOSUPPORT : EINVAL;
				eprintsoline(so, error);
				goto done;
			}
			if (name->sa_family != so->so_family) {
				/*
				 * With IPv6 we require the family to match
				 * unlike in IPv4.
				 */
				error = EAFNOSUPPORT;
				eprintsoline(so, error);
				goto done;
			}
#ifdef DEBUG
			/*
			 * Verify that apps don't forget to clear
			 * sin6_scope_id etc
			 */
			if (sin6->sin6_scope_id != 0 &&
			    !IN6_IS_ADDR_LINKSCOPE(&sin6->sin6_addr)) {
				zcmn_err(getzoneid(), CE_WARN,
				    "bind with uninitialized sin6_scope_id "
				    "(%d) on socket. Pid = %d\n",
				    (int)sin6->sin6_scope_id,
				    (int)curproc->p_pid);
			}
			if (sin6->__sin6_src_id != 0) {
				zcmn_err(getzoneid(), CE_WARN,
				    "bind with uninitialized __sin6_src_id "
				    "(%d) on socket. Pid = %d\n",
				    (int)sin6->__sin6_src_id,
				    (int)curproc->p_pid);
			}
#endif /* DEBUG */
			break;
		}
		default:
			/*
			 * Don't do any length or sa_family check to allow
			 * non-sockaddr style addresses.
			 */
			if (name == NULL) {
				error = EINVAL;
				eprintsoline(so, error);
				goto done;
			}
			break;
		}

		if (namelen > (t_uscalar_t)sti->sti_laddr_maxlen) {
			error = ENAMETOOLONG;
			eprintsoline(so, error);
			goto done;
		}
		/*
		 * Save local address.
		 */
		sti->sti_laddr_len = (socklen_t)namelen;
		ASSERT(sti->sti_laddr_len <= sti->sti_laddr_maxlen);
		bcopy(name, sti->sti_laddr_sa, namelen);

		addr = sti->sti_laddr_sa;
		addrlen = (t_uscalar_t)sti->sti_laddr_len;
		switch (so->so_family) {
		case AF_INET6:
		case AF_INET:
			break;
		case AF_UNIX: {
			struct sockaddr_un *soun =
			    (struct sockaddr_un *)sti->sti_laddr_sa;
			struct vnode *vp, *rvp;
			struct vattr vattr;

			ASSERT(sti->sti_ux_bound_vp == NULL);
			/*
			 * Create vnode for the specified path name.
			 * Keep vnode held with a reference in sti_ux_bound_vp.
			 * Use the vnode pointer as the address used in the
			 * bind with the transport.
			 *
			 * Use the same mode as in BSD. In particular this does
			 * not observe the umask.
			 */
			/* MAXPATHLEN + soun_family + nul termination */
			if (sti->sti_laddr_len >
			    (socklen_t)(MAXPATHLEN + sizeof (short) + 1)) {
				error = ENAMETOOLONG;
				eprintsoline(so, error);
				goto done;
			}
			vattr.va_type = VSOCK;
			vattr.va_mode = 0777 & ~PTOU(curproc)->u_cmask;
			vattr.va_mask = AT_TYPE|AT_MODE;
			/* NOTE: holding so_lock */
			error = vn_create(soun->sun_path, UIO_SYSSPACE, &vattr,
			    EXCL, 0, &vp, CRMKNOD, 0, 0);
			if (error) {
				if (error == EEXIST)
					error = EADDRINUSE;
				eprintsoline(so, error);
				goto done;
			}
			/*
			 * Establish pointer from the underlying filesystem
			 * vnode to the socket node.
			 * sti_ux_bound_vp and v_stream->sd_vnode form the
			 * cross-linkage between the underlying filesystem
			 * node and the socket node.
			 */

			if ((VOP_REALVP(vp, &rvp, NULL) == 0) && (vp != rvp)) {
				VN_HOLD(rvp);
				VN_RELE(vp);
				vp = rvp;
			}

			ASSERT(SOTOV(so)->v_stream);
			mutex_enter(&vp->v_lock);
			vp->v_stream = SOTOV(so)->v_stream;
			sti->sti_ux_bound_vp = vp;
			mutex_exit(&vp->v_lock);

			/*
			 * Use the vnode pointer value as a unique address
			 * (together with the magic number to avoid conflicts
			 * with implicit binds) in the transport provider.
			 */
			sti->sti_ux_laddr.soua_vp =
			    (void *)sti->sti_ux_bound_vp;
			sti->sti_ux_laddr.soua_magic = SOU_MAGIC_EXPLICIT;
			addr = &sti->sti_ux_laddr;
			addrlen = (t_uscalar_t)sizeof (sti->sti_ux_laddr);
			dprintso(so, 1, ("sobind UNIX: addrlen %d, addr %p\n",
			    addrlen,
			    (void *)((struct so_ux_addr *)addr)->soua_vp));
			break;
		}
		} /* end switch (so->so_family) */
	}

	/*
	 * set SS_ACCEPTCONN before sending down O_T_BIND_REQ since
	 * the transport can start passing up T_CONN_IND messages
	 * as soon as it receives the bind req and strsock_proto()
	 * insists that SS_ACCEPTCONN is set when processing T_CONN_INDs.
	 */
	if (flags & _SOBIND_LISTEN) {
		if ((so->so_state & SS_ACCEPTCONN) == 0)
			clear_acceptconn_on_err = B_TRUE;
		save_so_backlog = so->so_backlog;
		restore_backlog_on_err = B_TRUE;
		so->so_state |= SS_ACCEPTCONN;
		so->so_backlog = backlog;
	}

	/*
	 * If NL7C addr(s) have been configured check for addr/port match,
	 * or if an implicit NL7C socket via AF_NCA mark socket as NL7C.
	 *
	 * NL7C supports the TCP transport only so check AF_INET and AF_INET6
	 * family sockets only. If match mark as such.
	 */
	if (nl7c_enabled && ((addr != NULL &&
	    (so->so_family == AF_INET || so->so_family == AF_INET6) &&
	    (nl7c = nl7c_lookup_addr(addr, addrlen))) ||
	    sti->sti_nl7c_flags == NL7C_AF_NCA)) {
		/*
		 * NL7C is not supported in non-global zones,
		 * we enforce this restriction here.
		 */
		if (so->so_zoneid == GLOBAL_ZONEID) {
			/* An NL7C socket, mark it */
			sti->sti_nl7c_flags |= NL7C_ENABLED;
			if (nl7c == NULL) {
				/*
				 * Was an AF_NCA bind() so add it to the
				 * addr list for reporting purposes.
				 */
				nl7c = nl7c_add_addr(addr, addrlen);
			}
		} else
			nl7c = NULL;
	}

	/*
	 * We send a T_BIND_REQ for TCP/UDP since we know it supports it,
	 * for other transports we will send in a O_T_BIND_REQ.
	 */
	if (tcp_udp_xport &&
	    (so->so_family == AF_INET || so->so_family == AF_INET6))
		PRIM_type = T_BIND_REQ;

	bind_req.PRIM_type = PRIM_type;
	bind_req.ADDR_length = addrlen;
	bind_req.ADDR_offset = (t_scalar_t)sizeof (bind_req);
	bind_req.CONIND_number = backlog;
	/* NOTE: holding so_lock while sleeping */
	mp = soallocproto2(&bind_req, sizeof (bind_req),
	    addr, addrlen, 0, _ALLOC_SLEEP, cr);
	sti->sti_laddr_valid = 0;

	/* Done using sti_laddr_sa - can drop the lock */
	mutex_exit(&so->so_lock);

	error = kstrputmsg(SOTOV(so), mp, NULL, 0, 0,
	    MSG_BAND|MSG_HOLDSIG|MSG_IGNERROR, 0);
	if (error) {
		eprintsoline(so, error);
		mutex_enter(&so->so_lock);
		goto done;
	}

	mutex_enter(&so->so_lock);
	error = sowaitprim(so, PRIM_type, T_BIND_ACK,
	    (t_uscalar_t)sizeof (*bind_ack), &mp, 0);
	if (error) {
		eprintsoline(so, error);
		goto done;
	}
	ASSERT(mp);
	/*
	 * Even if some TPI message (e.g. T_DISCON_IND) was received in
	 * strsock_proto while the lock was dropped above, the bind
	 * is allowed to complete.
	 */

	/* Mark as bound. This will be undone if we detect errors below. */
	if (flags & _SOBIND_NOXLATE) {
		ASSERT(so->so_family == AF_UNIX);
		sti->sti_faddr_noxlate = 1;
	}
	ASSERT(!(so->so_state & SS_ISBOUND) || (flags & _SOBIND_REBIND));
	so->so_state |= SS_ISBOUND;
	ASSERT(sti->sti_unbind_mp);

	/* note that we've already set SS_ACCEPTCONN above */

	/*
	 * Recompute addrlen - an unspecied bind sent down an
	 * address of length zero but we expect the appropriate length
	 * in return.
	 */
	addrlen = (t_uscalar_t)(so->so_family == AF_UNIX ?
	    sizeof (sti->sti_ux_laddr) : sti->sti_laddr_len);

	bind_ack = (struct T_bind_ack *)mp->b_rptr;
	/*
	 * The alignment restriction is really too strict but
	 * we want enough alignment to inspect the fields of
	 * a sockaddr_in.
	 */
	addr = sogetoff(mp, bind_ack->ADDR_offset,
	    bind_ack->ADDR_length,
	    __TPI_ALIGN_SIZE);
	if (addr == NULL) {
		freemsg(mp);
		error = EPROTO;
		eprintsoline(so, error);
		goto done;
	}
	if (!(flags & _SOBIND_UNSPEC)) {
		/*
		 * Verify that the transport didn't return something we
		 * did not want e.g. an address other than what we asked for.
		 *
		 * NOTE: These checks would go away if/when we switch to
		 * using the new TPI (in which the transport would fail
		 * the request instead of assigning a different address).
		 *
		 * NOTE2: For protocols that we don't know (i.e. any
		 * other than AF_INET6, AF_INET and AF_UNIX), we
		 * cannot know if the transport should be expected to
		 * return the same address as that requested.
		 *
		 * NOTE3: For AF_INET and AF_INET6, TCP/UDP, we send
		 * down a T_BIND_REQ. We use O_T_BIND_REQ for others.
		 *
		 * For example, in the case of netatalk it may be
		 * inappropriate for the transport to return the
		 * requested address (as it may have allocated a local
		 * port number in behaviour similar to that of an
		 * AF_INET bind request with a port number of zero).
		 *
		 * Given the definition of O_T_BIND_REQ, where the
		 * transport may bind to an address other than the
		 * requested address, it's not possible to determine
		 * whether a returned address that differs from the
		 * requested address is a reason to fail (because the
		 * requested address was not available) or succeed
		 * (because the transport allocated an appropriate
		 * address and/or port).
		 *
		 * sockfs currently requires that the transport return
		 * the requested address in the T_BIND_ACK, unless
		 * there is code here to allow for any discrepancy.
		 * Such code exists for AF_INET and AF_INET6.
		 *
		 * Netatalk chooses to return the requested address
		 * rather than the (correct) allocated address.  This
		 * means that netatalk violates the TPI specification
		 * (and would not function correctly if used from a
		 * TLI application), but it does mean that it works
		 * with sockfs.
		 *
		 * As noted above, using the newer XTI bind primitive
		 * (T_BIND_REQ) in preference to O_T_BIND_REQ would
		 * allow sockfs to be more sure about whether or not
		 * the bind request had succeeded (as transports are
		 * not permitted to bind to a different address than
		 * that requested - they must return failure).
		 * Unfortunately, support for T_BIND_REQ may not be
		 * present in all transport implementations (netatalk,
		 * for example, doesn't have it), making the
		 * transition difficult.
		 */
		if (bind_ack->ADDR_length != addrlen) {
			/* Assumes that the requested address was in use */
			freemsg(mp);
			error = EADDRINUSE;
			eprintsoline(so, error);
			goto done;
		}

		switch (so->so_family) {
		case AF_INET6:
		case AF_INET: {
			sin_t *rname, *aname;

			rname = (sin_t *)addr;
			aname = (sin_t *)sti->sti_laddr_sa;

			/*
			 * Take advantage of the alignment
			 * of sin_port and sin6_port which fall
			 * in the same place in their data structures.
			 * Just use sin_port for either address family.
			 *
			 * This may become a problem if (heaven forbid)
			 * there's a separate ipv6port_reserved... :-P
			 *
			 * Binding to port 0 has the semantics of letting
			 * the transport bind to any port.
			 *
			 * If the transport is TCP or UDP since we had sent
			 * a T_BIND_REQ we would not get a port other than
			 * what we asked for.
			 */
			if (tcp_udp_xport) {
				/*
				 * Pick up the new port number if we bound to
				 * port 0.
				 */
				if (aname->sin_port == 0)
					aname->sin_port = rname->sin_port;
				sti->sti_laddr_valid = 1;
				break;
			}
			if (aname->sin_port != 0 &&
			    aname->sin_port != rname->sin_port) {
				freemsg(mp);
				error = EADDRINUSE;
				eprintsoline(so, error);
				goto done;
			}
			/*
			 * Pick up the new port number if we bound to port 0.
			 */
			aname->sin_port = rname->sin_port;

			/*
			 * Unfortunately, addresses aren't _quite_ the same.
			 */
			if (so->so_family == AF_INET) {
				if (aname->sin_addr.s_addr !=
				    rname->sin_addr.s_addr) {
					freemsg(mp);
					error = EADDRNOTAVAIL;
					eprintsoline(so, error);
					goto done;
				}
			} else {
				sin6_t *rname6 = (sin6_t *)rname;
				sin6_t *aname6 = (sin6_t *)aname;

				if (!IN6_ARE_ADDR_EQUAL(&aname6->sin6_addr,
				    &rname6->sin6_addr)) {
					freemsg(mp);
					error = EADDRNOTAVAIL;
					eprintsoline(so, error);
					goto done;
				}
			}
			break;
		}
		case AF_UNIX:
			if (bcmp(addr, &sti->sti_ux_laddr, addrlen) != 0) {
				freemsg(mp);
				error = EADDRINUSE;
				eprintsoline(so, error);
				eprintso(so,
				    ("addrlen %d, addr 0x%x, vp %p\n",
				    addrlen, *((int *)addr),
				    (void *)sti->sti_ux_bound_vp));
				goto done;
			}
			sti->sti_laddr_valid = 1;
			break;
		default:
			/*
			 * NOTE: This assumes that addresses can be
			 * byte-compared for equivalence.
			 */
			if (bcmp(addr, sti->sti_laddr_sa, addrlen) != 0) {
				freemsg(mp);
				error = EADDRINUSE;
				eprintsoline(so, error);
				goto done;
			}
			/*
			 * Don't mark sti_laddr_valid, as we cannot be
			 * sure that the returned address is the real
			 * bound address when talking to an unknown
			 * transport.
			 */
			break;
		}
	} else {
		/*
		 * Save for returned address for getsockname.
		 * Needed for unspecific bind unless transport supports
		 * the TI_GETMYNAME ioctl.
		 * Do this for AF_INET{,6} even though they do, as
		 * caching info here is much better performance than
		 * a TPI/STREAMS trip to the transport for getsockname.
		 * Any which can't for some reason _must_ _not_ set
		 * sti_laddr_valid here for the caching version of
		 * getsockname to not break;
		 */
		switch (so->so_family) {
		case AF_UNIX:
			/*
			 * Record the address bound with the transport
			 * for use by socketpair.
			 */
			bcopy(addr, &sti->sti_ux_laddr, addrlen);
			sti->sti_laddr_valid = 1;
			break;
		case AF_INET:
		case AF_INET6:
			ASSERT(sti->sti_laddr_len <= sti->sti_laddr_maxlen);
			bcopy(addr, sti->sti_laddr_sa, sti->sti_laddr_len);
			sti->sti_laddr_valid = 1;
			break;
		default:
			/*
			 * Don't mark sti_laddr_valid, as we cannot be
			 * sure that the returned address is the real
			 * bound address when talking to an unknown
			 * transport.
			 */
			break;
		}
	}

	if (nl7c != NULL) {
		/* Register listen()er sonode pointer with NL7C */
		nl7c_listener_addr(nl7c, so);
	}

	freemsg(mp);

done:
	if (error) {
		/* reset state & backlog to values held on entry */
		if (clear_acceptconn_on_err == B_TRUE)
			so->so_state &= ~SS_ACCEPTCONN;
		if (restore_backlog_on_err == B_TRUE)
			so->so_backlog = save_so_backlog;

		if (unbind_on_err && so->so_state & SS_ISBOUND) {
			int err;

			err = sotpi_unbind(so, 0);
			/* LINTED - statement has no consequent: if */
			if (err) {
				eprintsoline(so, error);
			} else {
				ASSERT(!(so->so_state & SS_ISBOUND));
			}
		}
	}
	if (!(flags & _SOBIND_LOCK_HELD)) {
		so_unlock_single(so, SOLOCKED);
		mutex_exit(&so->so_lock);
	} else {
		ASSERT(MUTEX_HELD(&so->so_lock));
		ASSERT(so->so_flag & SOLOCKED);
	}
	return (error);
}

/* bind the socket */
static int
sotpi_bind(struct sonode *so, struct sockaddr *name, socklen_t namelen,
    int flags, struct cred *cr)
{
	if ((flags & _SOBIND_SOCKETPAIR) == 0)
		return (sotpi_bindlisten(so, name, namelen, 0, flags, cr));

	flags &= ~_SOBIND_SOCKETPAIR;
	return (sotpi_bindlisten(so, name, namelen, 1, flags, cr));
}

/*
 * Unbind a socket - used when bind() fails, when bind() specifies a NULL
 * address, or when listen needs to unbind and bind.
 * If the _SOUNBIND_REBIND flag is specified the addresses are retained
 * so that a sobind can pick them up.
 */
static int
sotpi_unbind(struct sonode *so, int flags)
{
	struct T_unbind_req	unbind_req;
	int			error = 0;
	mblk_t			*mp;
	sotpi_info_t		*sti = SOTOTPI(so);

	dprintso(so, 1, ("sotpi_unbind(%p, 0x%x) %s\n",
	    (void *)so, flags, pr_state(so->so_state, so->so_mode)));

	ASSERT(MUTEX_HELD(&so->so_lock));
	ASSERT(so->so_flag & SOLOCKED);

	if (!(so->so_state & SS_ISBOUND)) {
		error = EINVAL;
		eprintsoline(so, error);
		goto done;
	}

	mutex_exit(&so->so_lock);

	/*
	 * Flush the read and write side (except stream head read queue)
	 * and send down T_UNBIND_REQ.
	 */
	(void) putnextctl1(strvp2wq(SOTOV(so)), M_FLUSH, FLUSHRW);

	unbind_req.PRIM_type = T_UNBIND_REQ;
	mp = soallocproto1(&unbind_req, sizeof (unbind_req),
	    0, _ALLOC_SLEEP, CRED());
	error = kstrputmsg(SOTOV(so), mp, NULL, 0, 0,
	    MSG_BAND|MSG_HOLDSIG|MSG_IGNERROR, 0);
	mutex_enter(&so->so_lock);
	if (error) {
		eprintsoline(so, error);
		goto done;
	}

	error = sowaitokack(so, T_UNBIND_REQ);
	if (error) {
		eprintsoline(so, error);
		goto done;
	}

	/*
	 * Even if some TPI message (e.g. T_DISCON_IND) was received in
	 * strsock_proto while the lock was dropped above, the unbind
	 * is allowed to complete.
	 */
	if (!(flags & _SOUNBIND_REBIND)) {
		/*
		 * Clear out bound address.
		 */
		vnode_t *vp;

		if ((vp = sti->sti_ux_bound_vp) != NULL) {
			sti->sti_ux_bound_vp = NULL;
			vn_rele_stream(vp);
		}
		/* Clear out address */
		sti->sti_laddr_len = 0;
	}
	so->so_state &= ~(SS_ISBOUND|SS_ACCEPTCONN);
	sti->sti_laddr_valid = 0;

done:

	/* If the caller held the lock don't release it here */
	ASSERT(MUTEX_HELD(&so->so_lock));
	ASSERT(so->so_flag & SOLOCKED);

	return (error);
}

/*
 * listen on the socket.
 * For TPI conforming transports this has to first unbind with the transport
 * and then bind again using the new backlog.
 */
/* ARGSUSED */
int
sotpi_listen(struct sonode *so, int backlog, struct cred *cr)
{
	int		error = 0;
	sotpi_info_t	*sti = SOTOTPI(so);

	dprintso(so, 1, ("sotpi_listen(%p, %d) %s\n",
	    (void *)so, backlog, pr_state(so->so_state, so->so_mode)));

	if (sti->sti_serv_type == T_CLTS)
		return (EOPNOTSUPP);

	/*
	 * If the socket is ready to accept connections already, then
	 * return without doing anything.  This avoids a problem where
	 * a second listen() call fails if a connection is pending and
	 * leaves the socket unbound. Only when we are not unbinding
	 * with the transport can we safely increase the backlog.
	 */
	if (so->so_state & SS_ACCEPTCONN &&
	    !((so->so_family == AF_INET || so->so_family == AF_INET6) &&
	    /*CONSTCOND*/
	    !solisten_tpi_tcp))
		return (0);

	if (so->so_state & SS_ISCONNECTED)
		return (EINVAL);

	mutex_enter(&so->so_lock);
	so_lock_single(so);	/* Set SOLOCKED */

	/*
	 * If the listen doesn't change the backlog we do nothing.
	 * This avoids an EPROTO error from the transport.
	 */
	if ((so->so_state & SS_ACCEPTCONN) &&
	    so->so_backlog == backlog)
		goto done;

	if (!(so->so_state & SS_ISBOUND)) {
		/*
		 * Must have been explicitly bound in the UNIX domain.
		 */
		if (so->so_family == AF_UNIX) {
			error = EINVAL;
			goto done;
		}
		error = sotpi_bindlisten(so, NULL, 0, backlog,
		    _SOBIND_UNSPEC|_SOBIND_LOCK_HELD|_SOBIND_LISTEN, cr);
	} else if (backlog > 0) {
		/*
		 * AF_INET{,6} hack to avoid losing the port.
		 * Assumes that all AF_INET{,6} transports can handle a
		 * O_T_BIND_REQ with a non-zero CONIND_number when the TPI
		 * has already bound thus it is possible to avoid the unbind.
		 */
		if (!((so->so_family == AF_INET || so->so_family == AF_INET6) &&
		    /*CONSTCOND*/
		    !solisten_tpi_tcp)) {
			error = sotpi_unbind(so, _SOUNBIND_REBIND);
			if (error)
				goto done;
		}
		error = sotpi_bindlisten(so, NULL, 0, backlog,
		    _SOBIND_REBIND|_SOBIND_LOCK_HELD|_SOBIND_LISTEN, cr);
	} else {
		so->so_state |= SS_ACCEPTCONN;
		so->so_backlog = backlog;
	}
	if (error)
		goto done;
	ASSERT(so->so_state & SS_ACCEPTCONN);
done:
	so_unlock_single(so, SOLOCKED);
	mutex_exit(&so->so_lock);
	return (error);
}

/*
 * Disconnect either a specified seqno or all (-1).
 * The former is used on listening sockets only.
 *
 * When seqno == -1 sodisconnect could call sotpi_unbind. However,
 * the current use of sodisconnect(seqno == -1) is only for shutdown
 * so there is no point (and potentially incorrect) to unbind.
 */
static int
sodisconnect(struct sonode *so, t_scalar_t seqno, int flags)
{
	struct T_discon_req	discon_req;
	int			error = 0;
	mblk_t			*mp;

	dprintso(so, 1, ("sodisconnect(%p, %d, 0x%x) %s\n",
	    (void *)so, seqno, flags, pr_state(so->so_state, so->so_mode)));

	if (!(flags & _SODISCONNECT_LOCK_HELD)) {
		mutex_enter(&so->so_lock);
		so_lock_single(so);	/* Set SOLOCKED */
	} else {
		ASSERT(MUTEX_HELD(&so->so_lock));
		ASSERT(so->so_flag & SOLOCKED);
	}

	if (!(so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING|SS_ACCEPTCONN))) {
		error = EINVAL;
		eprintsoline(so, error);
		goto done;
	}

	mutex_exit(&so->so_lock);
	/*
	 * Flush the write side (unless this is a listener)
	 * and then send down a T_DISCON_REQ.
	 * (Don't flush on listener since it could flush {O_}T_CONN_RES
	 * and other messages.)
	 */
	if (!(so->so_state & SS_ACCEPTCONN))
		(void) putnextctl1(strvp2wq(SOTOV(so)), M_FLUSH, FLUSHW);

	discon_req.PRIM_type = T_DISCON_REQ;
	discon_req.SEQ_number = seqno;
	mp = soallocproto1(&discon_req, sizeof (discon_req),
	    0, _ALLOC_SLEEP, CRED());
	error = kstrputmsg(SOTOV(so), mp, NULL, 0, 0,
	    MSG_BAND|MSG_HOLDSIG|MSG_IGNERROR, 0);
	mutex_enter(&so->so_lock);
	if (error) {
		eprintsoline(so, error);
		goto done;
	}

	error = sowaitokack(so, T_DISCON_REQ);
	if (error) {
		eprintsoline(so, error);
		goto done;
	}
	/*
	 * Even if some TPI message (e.g. T_DISCON_IND) was received in
	 * strsock_proto while the lock was dropped above, the disconnect
	 * is allowed to complete. However, it is not possible to
	 * assert that SS_ISCONNECTED|SS_ISCONNECTING are set.
	 */
	so->so_state &= ~(SS_ISCONNECTED|SS_ISCONNECTING);
	SOTOTPI(so)->sti_laddr_valid = 0;
	SOTOTPI(so)->sti_faddr_valid = 0;
done:
	if (!(flags & _SODISCONNECT_LOCK_HELD)) {
		so_unlock_single(so, SOLOCKED);
		mutex_exit(&so->so_lock);
	} else {
		/* If the caller held the lock don't release it here */
		ASSERT(MUTEX_HELD(&so->so_lock));
		ASSERT(so->so_flag & SOLOCKED);
	}
	return (error);
}

/* ARGSUSED */
int
sotpi_accept(struct sonode *so, int fflag, struct cred *cr,
    struct sonode **nsop)
{
	struct T_conn_ind	*conn_ind;
	struct T_conn_res	*conn_res;
	int			error = 0;
	mblk_t			*mp, *ack_mp;
	struct sonode		*nso;
	vnode_t			*nvp;
	void			*src;
	t_uscalar_t		srclen;
	void			*opt;
	t_uscalar_t		optlen;
	t_scalar_t		PRIM_type;
	t_scalar_t		SEQ_number;
	size_t			sinlen;
	sotpi_info_t		*sti = SOTOTPI(so);
	sotpi_info_t		*nsti;

	dprintso(so, 1, ("sotpi_accept(%p, 0x%x, %p) %s\n",
	    (void *)so, fflag, (void *)nsop,
	    pr_state(so->so_state, so->so_mode)));

	/*
	 * Defer single-threading the accepting socket until
	 * the T_CONN_IND has been received and parsed and the
	 * new sonode has been opened.
	 */

	/* Check that we are not already connected */
	if ((so->so_state & SS_ACCEPTCONN) == 0)
		goto conn_bad;
again:
	if ((error = sowaitconnind(so, fflag, &mp)) != 0)
		goto e_bad;

	ASSERT(mp != NULL);
	conn_ind = (struct T_conn_ind *)mp->b_rptr;

	/*
	 * Save SEQ_number for error paths.
	 */
	SEQ_number = conn_ind->SEQ_number;

	srclen = conn_ind->SRC_length;
	src = sogetoff(mp, conn_ind->SRC_offset, srclen, 1);
	if (src == NULL) {
		error = EPROTO;
		freemsg(mp);
		eprintsoline(so, error);
		goto disconnect_unlocked;
	}
	optlen = conn_ind->OPT_length;
	switch (so->so_family) {
	case AF_INET:
	case AF_INET6:
		if ((optlen == sizeof (intptr_t)) && (sti->sti_direct != 0)) {
			bcopy(mp->b_rptr + conn_ind->OPT_offset,
			    &opt, conn_ind->OPT_length);
		} else {
			/*
			 * The transport (in this case TCP) hasn't sent up
			 * a pointer to an instance for the accept fast-path.
			 * Disable fast-path completely because the call to
			 * sotpi_create() below would otherwise create an
			 * incomplete TCP instance, which would lead to
			 * problems when sockfs sends a normal T_CONN_RES
			 * message down the new stream.
			 */
			if (sti->sti_direct) {
				int rval;
				/*
				 * For consistency we inform tcp to disable
				 * direct interface on the listener, though
				 * we can certainly live without doing this
				 * because no data will ever travel upstream
				 * on the listening socket.
				 */
				sti->sti_direct = 0;
				(void) strioctl(SOTOV(so), _SIOCSOCKFALLBACK,
				    0, 0, K_TO_K, cr, &rval);
			}
			opt = NULL;
			optlen = 0;
		}
		break;
	case AF_UNIX:
	default:
		if (optlen != 0) {
			opt = sogetoff(mp, conn_ind->OPT_offset, optlen,
			    __TPI_ALIGN_SIZE);
			if (opt == NULL) {
				error = EPROTO;
				freemsg(mp);
				eprintsoline(so, error);
				goto disconnect_unlocked;
			}
		}
		if (so->so_family == AF_UNIX) {
			if (!sti->sti_faddr_noxlate) {
				src = NULL;
				srclen = 0;
			}
			/* Extract src address from options */
			if (optlen != 0)
				so_getopt_srcaddr(opt, optlen, &src, &srclen);
		}
		break;
	}

	/*
	 * Create the new socket.
	 */
	nso = socket_newconn(so, NULL, NULL, SOCKET_SLEEP, &error);
	if (nso == NULL) {
		ASSERT(error != 0);
		/*
		 * Accept can not fail with ENOBUFS. sotpi_create
		 * sleeps waiting for memory until a signal is caught
		 * so return EINTR.
		 */
		freemsg(mp);
		if (error == ENOBUFS)
			error = EINTR;
		goto e_disc_unl;
	}
	nvp = SOTOV(nso);
	nsti = SOTOTPI(nso);

#ifdef DEBUG
	/*
	 * SO_DEBUG is used to trigger the dprint* and eprint* macros thus
	 * it's inherited early to allow debugging of the accept code itself.
	 */
	nso->so_options |= so->so_options & SO_DEBUG;
#endif /* DEBUG */

	/*
	 * Save the SRC address from the T_CONN_IND
	 * for getpeername to work on AF_UNIX and on transports that do not
	 * support TI_GETPEERNAME.
	 *
	 * NOTE: AF_UNIX NUL termination is ensured by the sender's
	 * copyin_name().
	 */
	if (srclen > (t_uscalar_t)nsti->sti_faddr_maxlen) {
		error = EINVAL;
		freemsg(mp);
		eprintsoline(so, error);
		goto disconnect_vp_unlocked;
	}
	nsti->sti_faddr_len = (socklen_t)srclen;
	ASSERT(sti->sti_faddr_len <= sti->sti_faddr_maxlen);
	bcopy(src, nsti->sti_faddr_sa, srclen);
	nsti->sti_faddr_valid = 1;

	/*
	 * Record so_peercred and so_cpid from a cred in the T_CONN_IND.
	 */
	if ((DB_REF(mp) > 1) || MBLKSIZE(mp) <
	    (sizeof (struct T_conn_res) + sizeof (intptr_t))) {
		cred_t	*cr;
		pid_t	cpid;

		cr = msg_getcred(mp, &cpid);
		if (cr != NULL) {
			crhold(cr);
			nso->so_peercred = cr;
			nso->so_cpid = cpid;
		}
		freemsg(mp);

		mp = soallocproto1(NULL, sizeof (struct T_conn_res) +
		    sizeof (intptr_t), 0, _ALLOC_INTR, cr);
		if (mp == NULL) {
			/*
			 * Accept can not fail with ENOBUFS.
			 * A signal was caught so return EINTR.
			 */
			error = EINTR;
			eprintsoline(so, error);
			goto disconnect_vp_unlocked;
		}
		conn_res = (struct T_conn_res *)mp->b_rptr;
	} else {
		/*
		 * For efficency reasons we use msg_extractcred; no crhold
		 * needed since db_credp is cleared (i.e., we move the cred
		 * from the message to so_peercred.
		 */
		nso->so_peercred = msg_extractcred(mp, &nso->so_cpid);

		mp->b_rptr = DB_BASE(mp);
		conn_res = (struct T_conn_res *)mp->b_rptr;
		mp->b_wptr = mp->b_rptr + sizeof (struct T_conn_res);

		mblk_setcred(mp, cr, curproc->p_pid);
	}

	/*
	 * New socket must be bound at least in sockfs and, except for AF_INET,
	 * (or AF_INET6) it also has to be bound in the transport provider.
	 * We set the local address in the sonode from the T_OK_ACK of the
	 * T_CONN_RES. For this reason the address we bind to here isn't
	 * important.
	 */
	if ((nso->so_family == AF_INET || nso->so_family == AF_INET6) &&
	    /*CONSTCOND*/
	    nso->so_type == SOCK_STREAM && !soaccept_tpi_tcp) {
		/*
		 * Optimization for AF_INET{,6} transports
		 * that can handle a T_CONN_RES without being bound.
		 */
		mutex_enter(&nso->so_lock);
		so_automatic_bind(nso);
		mutex_exit(&nso->so_lock);
	} else {
		/* Perform NULL bind with the transport provider. */
		if ((error = sotpi_bind(nso, NULL, 0, _SOBIND_UNSPEC,
		    cr)) != 0) {
			ASSERT(error != ENOBUFS);
			freemsg(mp);
			eprintsoline(nso, error);
			goto disconnect_vp_unlocked;
		}
	}

	/*
	 * Inherit SIOCSPGRP, SS_ASYNC before we send the {O_}T_CONN_RES
	 * so that any data arriving on the new socket will cause the
	 * appropriate signals to be delivered for the new socket.
	 *
	 * No other thread (except strsock_proto and strsock_misc)
	 * can access the new socket thus we relax the locking.
	 */
	nso->so_pgrp = so->so_pgrp;
	nso->so_state |= so->so_state & SS_ASYNC;
	nsti->sti_faddr_noxlate = sti->sti_faddr_noxlate;

	if (nso->so_pgrp != 0) {
		if ((error = so_set_events(nso, nvp, cr)) != 0) {
			eprintsoline(nso, error);
			error = 0;
			nso->so_pgrp = 0;
		}
	}

	/*
	 * Make note of the socket level options. TCP and IP level options
	 * are already inherited. We could do all this after accept is
	 * successful but doing it here simplifies code and no harm done
	 * for error case.
	 */
	nso->so_options = so->so_options & (SO_DEBUG|SO_REUSEADDR|SO_KEEPALIVE|
	    SO_DONTROUTE|SO_BROADCAST|SO_USELOOPBACK|
	    SO_OOBINLINE|SO_DGRAM_ERRIND|SO_LINGER);
	nso->so_sndbuf = so->so_sndbuf;
	nso->so_rcvbuf = so->so_rcvbuf;
	if (nso->so_options & SO_LINGER)
		nso->so_linger = so->so_linger;

	/*
	 * Note that the following sti_direct code path should be
	 * removed once we are confident that the direct sockets
	 * do not result in any degradation.
	 */
	if (sti->sti_direct) {

		ASSERT(opt != NULL);

		conn_res->OPT_length = optlen;
		conn_res->OPT_offset = MBLKL(mp);
		bcopy(&opt, mp->b_wptr, optlen);
		mp->b_wptr += optlen;
		conn_res->PRIM_type = T_CONN_RES;
		conn_res->ACCEPTOR_id = 0;
		PRIM_type = T_CONN_RES;

		/* Send down the T_CONN_RES on acceptor STREAM */
		error = kstrputmsg(SOTOV(nso), mp, NULL,
		    0, 0, MSG_BAND|MSG_HOLDSIG|MSG_IGNERROR, 0);
		if (error) {
			mutex_enter(&so->so_lock);
			so_lock_single(so);
			eprintsoline(so, error);
			goto disconnect_vp;
		}
		mutex_enter(&nso->so_lock);
		error = sowaitprim(nso, T_CONN_RES, T_OK_ACK,
		    (t_uscalar_t)sizeof (struct T_ok_ack), &ack_mp, 0);
		if (error) {
			mutex_exit(&nso->so_lock);
			mutex_enter(&so->so_lock);
			so_lock_single(so);
			eprintsoline(so, error);
			goto disconnect_vp;
		}
		if (nso->so_family == AF_INET) {
			sin_t *sin;

			sin = (sin_t *)(ack_mp->b_rptr +
			    sizeof (struct T_ok_ack));
			bcopy(sin, nsti->sti_laddr_sa, sizeof (sin_t));
			nsti->sti_laddr_len = sizeof (sin_t);
		} else {
			sin6_t *sin6;

			sin6 = (sin6_t *)(ack_mp->b_rptr +
			    sizeof (struct T_ok_ack));
			bcopy(sin6, nsti->sti_laddr_sa, sizeof (sin6_t));
			nsti->sti_laddr_len = sizeof (sin6_t);
		}
		freemsg(ack_mp);

		nso->so_state |= SS_ISCONNECTED;
		nso->so_proto_handle = (sock_lower_handle_t)opt;
		nsti->sti_laddr_valid = 1;

		if (sti->sti_nl7c_flags & NL7C_ENABLED) {
			/*
			 * A NL7C marked listen()er so the new socket
			 * inherits the listen()er's NL7C state, except
			 * for NL7C_POLLIN.
			 *
			 * Only call NL7C to process the new socket if
			 * the listen socket allows blocking i/o.
			 */
			nsti->sti_nl7c_flags =
			    sti->sti_nl7c_flags & (~NL7C_POLLIN);
			if (so->so_state & (SS_NONBLOCK|SS_NDELAY)) {
				/*
				 * Nonblocking accept() just make it
				 * persist to defer processing to the
				 * read-side syscall (e.g. read).
				 */
				nsti->sti_nl7c_flags |= NL7C_SOPERSIST;
			} else if (nl7c_process(nso, B_FALSE)) {
				/*
				 * NL7C has completed processing on the
				 * socket, close the socket and back to
				 * the top to await the next T_CONN_IND.
				 */
				mutex_exit(&nso->so_lock);
				(void) VOP_CLOSE(nvp, 0, 1, (offset_t)0,
				    cr, NULL);
				VN_RELE(nvp);
				goto again;
			}
			/* Pass the new socket out */
		}

		mutex_exit(&nso->so_lock);

		/*
		 * It's possible, through the use of autopush for example,
		 * that the acceptor stream may not support sti_direct
		 * semantics. If the new socket does not support sti_direct
		 * we issue a _SIOCSOCKFALLBACK to inform the transport
		 * as we would in the I_PUSH case.
		 */
		if (nsti->sti_direct == 0) {
			int	rval;

			if ((error = strioctl(SOTOV(nso), _SIOCSOCKFALLBACK,
			    0, 0, K_TO_K, cr, &rval)) != 0) {
				mutex_enter(&so->so_lock);
				so_lock_single(so);
				eprintsoline(so, error);
				goto disconnect_vp;
			}
		}

		/*
		 * Pass out new socket.
		 */
		if (nsop != NULL)
			*nsop = nso;

		return (0);
	}

	/*
	 * This is the non-performance case for sockets (e.g. AF_UNIX sockets)
	 * which don't support the FireEngine accept fast-path. It is also
	 * used when the virtual "sockmod" has been I_POP'd and I_PUSH'd
	 * again. Neither sockfs nor TCP attempt to find out if some other
	 * random module has been inserted in between (in which case we
	 * should follow TLI accept behaviour). We blindly assume the worst
	 * case and revert back to old behaviour i.e. TCP will not send us
	 * any option (eager) and the accept should happen on the listener
	 * queue. Any queued T_conn_ind have already got their options removed
	 * by so_sock2_stream() when "sockmod" was I_POP'd.
	 */
	/*
	 * Fill in the {O_}T_CONN_RES before getting SOLOCKED.
	 */
	if ((nso->so_mode & SM_ACCEPTOR_ID) == 0) {
#ifdef	_ILP32
		queue_t	*q;

		/*
		 * Find read queue in driver
		 * Can safely do this since we "own" nso/nvp.
		 */
		q = strvp2wq(nvp)->q_next;
		while (SAMESTR(q))
			q = q->q_next;
		q = RD(q);
		conn_res->ACCEPTOR_id = (t_uscalar_t)q;
#else
		conn_res->ACCEPTOR_id = (t_uscalar_t)getminor(nvp->v_rdev);
#endif	/* _ILP32 */
		conn_res->PRIM_type = O_T_CONN_RES;
		PRIM_type = O_T_CONN_RES;
	} else {
		conn_res->ACCEPTOR_id = nsti->sti_acceptor_id;
		conn_res->PRIM_type = T_CONN_RES;
		PRIM_type = T_CONN_RES;
	}
	conn_res->SEQ_number = SEQ_number;
	conn_res->OPT_length = 0;
	conn_res->OPT_offset = 0;

	mutex_enter(&so->so_lock);
	so_lock_single(so);	/* Set SOLOCKED */
	mutex_exit(&so->so_lock);

	error = kstrputmsg(SOTOV(so), mp, NULL,
	    0, 0, MSG_BAND|MSG_HOLDSIG|MSG_IGNERROR, 0);
	mutex_enter(&so->so_lock);
	if (error) {
		eprintsoline(so, error);
		goto disconnect_vp;
	}
	error = sowaitprim(so, PRIM_type, T_OK_ACK,
	    (t_uscalar_t)sizeof (struct T_ok_ack), &ack_mp, 0);
	if (error) {
		eprintsoline(so, error);
		goto disconnect_vp;
	}
	mutex_exit(&so->so_lock);
	/*
	 * If there is a sin/sin6 appended onto the T_OK_ACK use
	 * that to set the local address. If this is not present
	 * then we zero out the address and don't set the
	 * sti_laddr_valid bit. For AF_UNIX endpoints we copy over
	 * the pathname from the listening socket.
	 * In the case where this is TCP or an AF_UNIX socket the
	 * client side may have queued data or a T_ORDREL in the
	 * transport. Having now sent the T_CONN_RES we may receive
	 * those queued messages at any time. Hold the acceptor
	 * so_lock until its state and laddr are finalized.
	 */
	mutex_enter(&nso->so_lock);
	sinlen = (nso->so_family == AF_INET) ? sizeof (sin_t) : sizeof (sin6_t);
	if ((nso->so_family == AF_INET) || (nso->so_family == AF_INET6) &&
	    MBLKL(ack_mp) == (sizeof (struct T_ok_ack) + sinlen)) {
		ack_mp->b_rptr += sizeof (struct T_ok_ack);
		bcopy(ack_mp->b_rptr, nsti->sti_laddr_sa, sinlen);
		nsti->sti_laddr_len = sinlen;
		nsti->sti_laddr_valid = 1;
	} else if (nso->so_family == AF_UNIX) {
		ASSERT(so->so_family == AF_UNIX);
		nsti->sti_laddr_len = sti->sti_laddr_len;
		ASSERT(nsti->sti_laddr_len <= nsti->sti_laddr_maxlen);
		bcopy(sti->sti_laddr_sa, nsti->sti_laddr_sa,
		    nsti->sti_laddr_len);
		nsti->sti_laddr_valid = 1;
	} else {
		nsti->sti_laddr_len = sti->sti_laddr_len;
		ASSERT(nsti->sti_laddr_len <= nsti->sti_laddr_maxlen);
		bzero(nsti->sti_laddr_sa, nsti->sti_addr_size);
		nsti->sti_laddr_sa->sa_family = nso->so_family;
	}
	nso->so_state |= SS_ISCONNECTED;
	mutex_exit(&nso->so_lock);

	freemsg(ack_mp);

	mutex_enter(&so->so_lock);
	so_unlock_single(so, SOLOCKED);
	mutex_exit(&so->so_lock);

	/*
	 * Pass out new socket.
	 */
	if (nsop != NULL)
		*nsop = nso;

	return (0);


eproto_disc_unl:
	error = EPROTO;
e_disc_unl:
	eprintsoline(so, error);
	goto disconnect_unlocked;

pr_disc_vp_unl:
	eprintsoline(so, error);
disconnect_vp_unlocked:
	(void) VOP_CLOSE(nvp, 0, 1, 0, cr, NULL);
	VN_RELE(nvp);
disconnect_unlocked:
	(void) sodisconnect(so, SEQ_number, 0);
	return (error);

pr_disc_vp:
	eprintsoline(so, error);
disconnect_vp:
	(void) sodisconnect(so, SEQ_number, _SODISCONNECT_LOCK_HELD);
	so_unlock_single(so, SOLOCKED);
	mutex_exit(&so->so_lock);
	(void) VOP_CLOSE(nvp, 0, 1, 0, cr, NULL);
	VN_RELE(nvp);
	return (error);

conn_bad:	/* Note: SunOS 4/BSD unconditionally returns EINVAL here */
	error = (so->so_type == SOCK_DGRAM || so->so_type == SOCK_RAW)
	    ? EOPNOTSUPP : EINVAL;
e_bad:
	eprintsoline(so, error);
	return (error);
}

/*
 * connect a socket.
 *
 * Allow SOCK_DGRAM sockets to reconnect (by specifying a new address) and to
 * unconnect (by specifying a null address).
 */
int
sotpi_connect(struct sonode *so,
	struct sockaddr *name,
	socklen_t namelen,
	int fflag,
	int flags,
	struct cred *cr)
{
	struct T_conn_req	conn_req;
	int			error = 0;
	mblk_t			*mp;
	void			*src;
	socklen_t		srclen;
	void			*addr;
	socklen_t		addrlen;
	boolean_t		need_unlock;
	sotpi_info_t		*sti = SOTOTPI(so);

	dprintso(so, 1, ("sotpi_connect(%p, %p, %d, 0x%x, 0x%x) %s\n",
	    (void *)so, (void *)name, namelen, fflag, flags,
	    pr_state(so->so_state, so->so_mode)));

	/*
	 * Preallocate the T_CONN_REQ mblk before grabbing SOLOCKED to
	 * avoid sleeping for memory with SOLOCKED held.
	 * We know that the T_CONN_REQ can't be larger than 2 * sti_faddr_maxlen
	 * + sizeof (struct T_opthdr).
	 * (the AF_UNIX so_ux_addr_xlate() does not make the address
	 * exceed sti_faddr_maxlen).
	 */
	mp = soallocproto(sizeof (struct T_conn_req) +
	    2 * sti->sti_faddr_maxlen + sizeof (struct T_opthdr), _ALLOC_INTR,
	    cr);
	if (mp == NULL) {
		/*
		 * Connect can not fail with ENOBUFS. A signal was
		 * caught so return EINTR.
		 */
		error = EINTR;
		eprintsoline(so, error);
		return (error);
	}

	mutex_enter(&so->so_lock);
	/*
	 * Make sure there is a preallocated T_unbind_req message
	 * before any binding. This message is allocated when the
	 * socket is created. Since another thread can consume
	 * so_unbind_mp by the time we return from so_lock_single(),
	 * we should check the availability of so_unbind_mp after
	 * we return from so_lock_single().
	 */

	so_lock_single(so);	/* Set SOLOCKED */
	need_unlock = B_TRUE;

	if (sti->sti_unbind_mp == NULL) {
		dprintso(so, 1, ("sotpi_connect: allocating unbind_req\n"));
		/* NOTE: holding so_lock while sleeping */
		sti->sti_unbind_mp =
		    soallocproto(sizeof (struct T_unbind_req), _ALLOC_INTR, cr);
		if (sti->sti_unbind_mp == NULL) {
			error = EINTR;
			goto done;
		}
	}

	/*
	 * Can't have done a listen before connecting.
	 */
	if (so->so_state & SS_ACCEPTCONN) {
		error = EOPNOTSUPP;
		goto done;
	}

	/*
	 * Must be bound with the transport
	 */
	if (!(so->so_state & SS_ISBOUND)) {
		if ((so->so_family == AF_INET || so->so_family == AF_INET6) &&
		    /*CONSTCOND*/
		    so->so_type == SOCK_STREAM && !soconnect_tpi_tcp) {
			/*
			 * Optimization for AF_INET{,6} transports
			 * that can handle a T_CONN_REQ without being bound.
			 */
			so_automatic_bind(so);
		} else {
			error = sotpi_bind(so, NULL, 0,
			    _SOBIND_UNSPEC|_SOBIND_LOCK_HELD, cr);
			if (error)
				goto done;
		}
		ASSERT(so->so_state & SS_ISBOUND);
		flags |= _SOCONNECT_DID_BIND;
	}

	/*
	 * Handle a connect to a name parameter of type AF_UNSPEC like a
	 * connect to a null address. This is the portable method to
	 * unconnect a socket.
	 */
	if ((namelen >= sizeof (sa_family_t)) &&
	    (name->sa_family == AF_UNSPEC)) {
		name = NULL;
		namelen = 0;
	}

	/*
	 * Check that we are not already connected.
	 * A connection-oriented socket cannot be reconnected.
	 * A connected connection-less socket can be
	 * - connected to a different address by a subsequent connect
	 * - "unconnected" by a connect to the NULL address
	 */
	if (so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING)) {
		ASSERT(!(flags & _SOCONNECT_DID_BIND));
		if (so->so_mode & SM_CONNREQUIRED) {
			/* Connection-oriented socket */
			error = so->so_state & SS_ISCONNECTED ?
			    EISCONN : EALREADY;
			goto done;
		}
		/* Connection-less socket */
		if (name == NULL) {
			/*
			 * Remove the connected state and clear SO_DGRAM_ERRIND
			 * since it was set when the socket was connected.
			 * If this is UDP also send down a T_DISCON_REQ.
			 */
			int val;

			if ((so->so_family == AF_INET ||
			    so->so_family == AF_INET6) &&
			    (so->so_type == SOCK_DGRAM ||
			    so->so_type == SOCK_RAW) &&
			    /*CONSTCOND*/
			    !soconnect_tpi_udp) {
				/* XXX What about implicitly unbinding here? */
				error = sodisconnect(so, -1,
				    _SODISCONNECT_LOCK_HELD);
			} else {
				so->so_state &=
				    ~(SS_ISCONNECTED | SS_ISCONNECTING);
				sti->sti_faddr_valid = 0;
				sti->sti_faddr_len = 0;
			}

			/* Remove SOLOCKED since setsockopt will grab it */
			so_unlock_single(so, SOLOCKED);
			mutex_exit(&so->so_lock);

			val = 0;
			(void) sotpi_setsockopt(so, SOL_SOCKET,
			    SO_DGRAM_ERRIND, &val, (t_uscalar_t)sizeof (val),
			    cr);

			mutex_enter(&so->so_lock);
			so_lock_single(so);	/* Set SOLOCKED */
			goto done;
		}
	}
	ASSERT(so->so_state & SS_ISBOUND);

	if (name == NULL || namelen == 0) {
		error = EINVAL;
		goto done;
	}
	/*
	 * Mark the socket if sti_faddr_sa represents the transport level
	 * address.
	 */
	if (flags & _SOCONNECT_NOXLATE) {
		struct sockaddr_ux	*soaddr_ux;

		ASSERT(so->so_family == AF_UNIX);
		if (namelen != sizeof (struct sockaddr_ux)) {
			error = EINVAL;
			goto done;
		}
		soaddr_ux = (struct sockaddr_ux *)name;
		name = (struct sockaddr *)&soaddr_ux->sou_addr;
		namelen = sizeof (soaddr_ux->sou_addr);
		sti->sti_faddr_noxlate = 1;
	}

	/*
	 * Length and family checks.
	 */
	error = so_addr_verify(so, name, namelen);
	if (error)
		goto bad;

	/*
	 * Save foreign address. Needed for AF_UNIX as well as
	 * transport providers that do not support TI_GETPEERNAME.
	 * Also used for cached foreign address for TCP and UDP.
	 */
	if (namelen > (t_uscalar_t)sti->sti_faddr_maxlen) {
		error = EINVAL;
		goto done;
	}
	sti->sti_faddr_len = (socklen_t)namelen;
	ASSERT(sti->sti_faddr_len <= sti->sti_faddr_maxlen);
	bcopy(name, sti->sti_faddr_sa, namelen);
	sti->sti_faddr_valid = 1;

	if (so->so_family == AF_UNIX) {
		if (sti->sti_faddr_noxlate) {
			/*
			 * Already have a transport internal address. Do not
			 * pass any (transport internal) source address.
			 */
			addr = sti->sti_faddr_sa;
			addrlen = (t_uscalar_t)sti->sti_faddr_len;
			src = NULL;
			srclen = 0;
		} else {
			/*
			 * Pass the sockaddr_un source address as an option
			 * and translate the remote address.
			 * Holding so_lock thus sti_laddr_sa can not change.
			 */
			src = sti->sti_laddr_sa;
			srclen = (t_uscalar_t)sti->sti_laddr_len;
			dprintso(so, 1,
			    ("sotpi_connect UNIX: srclen %d, src %p\n",
			    srclen, src));
			error = so_ux_addr_xlate(so,
			    sti->sti_faddr_sa, (socklen_t)sti->sti_faddr_len,
			    (flags & _SOCONNECT_XPG4_2),
			    &addr, &addrlen);
			if (error)
				goto bad;
		}
	} else {
		addr = sti->sti_faddr_sa;
		addrlen = (t_uscalar_t)sti->sti_faddr_len;
		src = NULL;
		srclen = 0;
	}
	/*
	 * When connecting a datagram socket we issue the SO_DGRAM_ERRIND
	 * option which asks the transport provider to send T_UDERR_IND
	 * messages. These T_UDERR_IND messages are used to return connected
	 * style errors (e.g. ECONNRESET) for connected datagram sockets.
	 *
	 * In addition, for UDP (and SOCK_RAW AF_INET{,6} sockets)
	 * we send down a T_CONN_REQ. This is needed to let the
	 * transport assign a local address that is consistent with
	 * the remote address. Applications depend on a getsockname()
	 * after a connect() to retrieve the "source" IP address for
	 * the connected socket.  Invalidate the cached local address
	 * to force getsockname() to enquire of the transport.
	 */
	if (!(so->so_mode & SM_CONNREQUIRED)) {
		/*
		 * Datagram socket.
		 */
		int32_t val;

		so_unlock_single(so, SOLOCKED);
		mutex_exit(&so->so_lock);

		val = 1;
		(void) sotpi_setsockopt(so, SOL_SOCKET, SO_DGRAM_ERRIND,
		    &val, (t_uscalar_t)sizeof (val), cr);

		mutex_enter(&so->so_lock);
		so_lock_single(so);	/* Set SOLOCKED */
		if ((so->so_family != AF_INET && so->so_family != AF_INET6) ||
		    (so->so_type != SOCK_DGRAM && so->so_type != SOCK_RAW) ||
		    soconnect_tpi_udp) {
			soisconnected(so);
			goto done;
		}
		/*
		 * Send down T_CONN_REQ etc.
		 * Clear fflag to avoid returning EWOULDBLOCK.
		 */
		fflag = 0;
		ASSERT(so->so_family != AF_UNIX);
		sti->sti_laddr_valid = 0;
	} else if (sti->sti_laddr_len != 0) {
		/*
		 * If the local address or port was "any" then it may be
		 * changed by the transport as a result of the
		 * connect.  Invalidate the cached version if we have one.
		 */
		switch (so->so_family) {
		case AF_INET:
			ASSERT(sti->sti_laddr_len == (socklen_t)sizeof (sin_t));
			if (((sin_t *)sti->sti_laddr_sa)->sin_addr.s_addr ==
			    INADDR_ANY ||
			    ((sin_t *)sti->sti_laddr_sa)->sin_port == 0)
				sti->sti_laddr_valid = 0;
			break;

		case AF_INET6:
			ASSERT(sti->sti_laddr_len ==
			    (socklen_t)sizeof (sin6_t));
			if (IN6_IS_ADDR_UNSPECIFIED(
			    &((sin6_t *)sti->sti_laddr_sa) ->sin6_addr) ||
			    IN6_IS_ADDR_V4MAPPED_ANY(
			    &((sin6_t *)sti->sti_laddr_sa)->sin6_addr) ||
			    ((sin6_t *)sti->sti_laddr_sa)->sin6_port == 0)
				sti->sti_laddr_valid = 0;
			break;

		default:
			break;
		}
	}

	/*
	 * Check for failure of an earlier call
	 */
	if (so->so_error != 0)
		goto so_bad;

	/*
	 * Send down T_CONN_REQ. Message was allocated above.
	 */
	conn_req.PRIM_type = T_CONN_REQ;
	conn_req.DEST_length = addrlen;
	conn_req.DEST_offset = (t_scalar_t)sizeof (conn_req);
	if (srclen == 0) {
		conn_req.OPT_length = 0;
		conn_req.OPT_offset = 0;
		soappendmsg(mp, &conn_req, sizeof (conn_req));
		soappendmsg(mp, addr, addrlen);
	} else {
		/*
		 * There is a AF_UNIX sockaddr_un to include as a source
		 * address option.
		 */
		struct T_opthdr toh;

		toh.level = SOL_SOCKET;
		toh.name = SO_SRCADDR;
		toh.len = (t_uscalar_t)(srclen + sizeof (struct T_opthdr));
		toh.status = 0;
		conn_req.OPT_length =
		    (t_scalar_t)(sizeof (toh) + _TPI_ALIGN_TOPT(srclen));
		conn_req.OPT_offset = (t_scalar_t)(sizeof (conn_req) +
		    _TPI_ALIGN_TOPT(addrlen));

		soappendmsg(mp, &conn_req, sizeof (conn_req));
		soappendmsg(mp, addr, addrlen);
		mp->b_wptr += _TPI_ALIGN_TOPT(addrlen) - addrlen;
		soappendmsg(mp, &toh, sizeof (toh));
		soappendmsg(mp, src, srclen);
		mp->b_wptr += _TPI_ALIGN_TOPT(srclen) - srclen;
		ASSERT(mp->b_wptr <= mp->b_datap->db_lim);
	}
	/*
	 * Set SS_ISCONNECTING before sending down the T_CONN_REQ
	 * in order to have the right state when the T_CONN_CON shows up.
	 */
	soisconnecting(so);
	mutex_exit(&so->so_lock);

	if (AU_AUDITING())
		audit_sock(T_CONN_REQ, strvp2wq(SOTOV(so)), mp, 0);

	error = kstrputmsg(SOTOV(so), mp, NULL, 0, 0,
	    MSG_BAND|MSG_HOLDSIG|MSG_IGNERROR, 0);
	mp = NULL;
	mutex_enter(&so->so_lock);
	if (error != 0)
		goto bad;

	if ((error = sowaitokack(so, T_CONN_REQ)) != 0)
		goto bad;

	/* Allow other threads to access the socket */
	so_unlock_single(so, SOLOCKED);
	need_unlock = B_FALSE;

	/*
	 * Wait until we get a T_CONN_CON or an error
	 */
	if ((error = sowaitconnected(so, fflag, 0)) != 0) {
		so_lock_single(so);	/* Set SOLOCKED */
		need_unlock = B_TRUE;
	}

done:
	freemsg(mp);
	switch (error) {
	case EINPROGRESS:
	case EALREADY:
	case EISCONN:
	case EINTR:
		/* Non-fatal errors */
		sti->sti_laddr_valid = 0;
		/* FALLTHRU */
	case 0:
		break;
	default:
		ASSERT(need_unlock);
		/*
		 * Fatal errors: clear SS_ISCONNECTING in case it was set,
		 * and invalidate local-address cache
		 */
		so->so_state &= ~SS_ISCONNECTING;
		sti->sti_laddr_valid = 0;
		/* A discon_ind might have already unbound us */
		if ((flags & _SOCONNECT_DID_BIND) &&
		    (so->so_state & SS_ISBOUND)) {
			int err;

			err = sotpi_unbind(so, 0);
			/* LINTED - statement has no conseq */
			if (err) {
				eprintsoline(so, err);
			}
		}
		break;
	}
	if (need_unlock)
		so_unlock_single(so, SOLOCKED);
	mutex_exit(&so->so_lock);
	return (error);

so_bad:	error = sogeterr(so, B_TRUE);
bad:	eprintsoline(so, error);
	goto done;
}

/* ARGSUSED */
int
sotpi_shutdown(struct sonode *so, int how, struct cred *cr)
{
	struct T_ordrel_req	ordrel_req;
	mblk_t			*mp;
	uint_t			old_state, state_change;
	int			error = 0;
	sotpi_info_t		*sti = SOTOTPI(so);

	dprintso(so, 1, ("sotpi_shutdown(%p, %d) %s\n",
	    (void *)so, how, pr_state(so->so_state, so->so_mode)));

	mutex_enter(&so->so_lock);
	so_lock_single(so);	/* Set SOLOCKED */

	/*
	 * SunOS 4.X has no check for datagram sockets.
	 * 5.X checks that it is connected (ENOTCONN)
	 * X/Open requires that we check the connected state.
	 */
	if (!(so->so_state & SS_ISCONNECTED)) {
		if (!xnet_skip_checks) {
			error = ENOTCONN;
			if (xnet_check_print) {
				printf("sockfs: X/Open shutdown check "
				    "caused ENOTCONN\n");
			}
		}
		goto done;
	}
	/*
	 * Record the current state and then perform any state changes.
	 * Then use the difference between the old and new states to
	 * determine which messages need to be sent.
	 * This prevents e.g. duplicate T_ORDREL_REQ when there are
	 * duplicate calls to shutdown().
	 */
	old_state = so->so_state;

	switch (how) {
	case 0:
		socantrcvmore(so);
		break;
	case 1:
		socantsendmore(so);
		break;
	case 2:
		socantsendmore(so);
		socantrcvmore(so);
		break;
	default:
		error = EINVAL;
		goto done;
	}

	/*
	 * Assumes that the SS_CANT* flags are never cleared in the above code.
	 */
	state_change = (so->so_state & (SS_CANTRCVMORE|SS_CANTSENDMORE)) -
	    (old_state & (SS_CANTRCVMORE|SS_CANTSENDMORE));
	ASSERT((state_change & ~(SS_CANTRCVMORE|SS_CANTSENDMORE)) == 0);

	switch (state_change) {
	case 0:
		dprintso(so, 1,
		    ("sotpi_shutdown: nothing to send in state 0x%x\n",
		    so->so_state));
		goto done;

	case SS_CANTRCVMORE:
		mutex_exit(&so->so_lock);
		strseteof(SOTOV(so), 1);
		/*
		 * strseteof takes care of read side wakeups,
		 * pollwakeups, and signals.
		 */
		/*
		 * Get the read lock before flushing data to avoid problems
		 * with the T_EXDATA_IND MSG_PEEK code in sotpi_recvmsg.
		 */
		mutex_enter(&so->so_lock);
		(void) so_lock_read(so, 0);	/* Set SOREADLOCKED */
		mutex_exit(&so->so_lock);

		/* Flush read side queue */
		strflushrq(SOTOV(so), FLUSHALL);

		mutex_enter(&so->so_lock);
		so_unlock_read(so);		/* Clear SOREADLOCKED */
		break;

	case SS_CANTSENDMORE:
		mutex_exit(&so->so_lock);
		strsetwerror(SOTOV(so), 0, 0, sogetwrerr);
		mutex_enter(&so->so_lock);
		break;

	case SS_CANTSENDMORE|SS_CANTRCVMORE:
		mutex_exit(&so->so_lock);
		strsetwerror(SOTOV(so), 0, 0, sogetwrerr);
		strseteof(SOTOV(so), 1);
		/*
		 * strseteof takes care of read side wakeups,
		 * pollwakeups, and signals.
		 */
		/*
		 * Get the read lock before flushing data to avoid problems
		 * with the T_EXDATA_IND MSG_PEEK code in sotpi_recvmsg.
		 */
		mutex_enter(&so->so_lock);
		(void) so_lock_read(so, 0);	/* Set SOREADLOCKED */
		mutex_exit(&so->so_lock);

		/* Flush read side queue */
		strflushrq(SOTOV(so), FLUSHALL);

		mutex_enter(&so->so_lock);
		so_unlock_read(so);		/* Clear SOREADLOCKED */
		break;
	}

	ASSERT(MUTEX_HELD(&so->so_lock));

	/*
	 * If either SS_CANTSENDMORE or SS_CANTRCVMORE or both of them
	 * was set due to this call and the new state has both of them set:
	 *	Send the AF_UNIX close indication
	 *	For T_COTS send a discon_ind
	 *
	 * If cantsend was set due to this call:
	 *	For T_COTSORD send an ordrel_ind
	 *
	 * Note that for T_CLTS there is no message sent here.
	 */
	if ((so->so_state & (SS_CANTRCVMORE|SS_CANTSENDMORE)) ==
	    (SS_CANTRCVMORE|SS_CANTSENDMORE)) {
		/*
		 * For SunOS 4.X compatibility we tell the other end
		 * that we are unable to receive at this point.
		 */
		if (so->so_family == AF_UNIX && sti->sti_serv_type != T_CLTS)
			so_unix_close(so);

		if (sti->sti_serv_type == T_COTS)
			error = sodisconnect(so, -1, _SODISCONNECT_LOCK_HELD);
	}
	if ((state_change & SS_CANTSENDMORE) &&
	    (sti->sti_serv_type == T_COTS_ORD)) {
		/* Send an orderly release */
		ordrel_req.PRIM_type = T_ORDREL_REQ;

		mutex_exit(&so->so_lock);
		mp = soallocproto1(&ordrel_req, sizeof (ordrel_req),
		    0, _ALLOC_SLEEP, cr);
		/*
		 * Send down the T_ORDREL_REQ even if there is flow control.
		 * This prevents shutdown from blocking.
		 * Note that there is no T_OK_ACK for ordrel_req.
		 */
		error = kstrputmsg(SOTOV(so), mp, NULL, 0, 0,
		    MSG_BAND|MSG_HOLDSIG|MSG_IGNERROR|MSG_IGNFLOW, 0);
		mutex_enter(&so->so_lock);
		if (error) {
			eprintsoline(so, error);
			goto done;
		}
	}

done:
	so_unlock_single(so, SOLOCKED);
	mutex_exit(&so->so_lock);
	return (error);
}

/*
 * For any connected SOCK_STREAM/SOCK_SEQPACKET AF_UNIX socket we send
 * a zero-length T_OPTDATA_REQ with the SO_UNIX_CLOSE option to inform the peer
 * that we have closed.
 * Also, for connected AF_UNIX SOCK_DGRAM sockets we send a zero-length
 * T_UNITDATA_REQ containing the same option.
 *
 * For SOCK_DGRAM half-connections (somebody connected to this end
 * but this end is not connect) we don't know where to send any
 * SO_UNIX_CLOSE.
 *
 * We have to ignore stream head errors just in case there has been
 * a shutdown(output).
 * Ignore any flow control to try to get the message more quickly to the peer.
 * While locally ignoring flow control solves the problem when there
 * is only the loopback transport on the stream it would not provide
 * the correct AF_UNIX socket semantics when one or more modules have
 * been pushed.
 */
void
so_unix_close(struct sonode *so)
{
	int		error;
	struct T_opthdr	toh;
	mblk_t		*mp;
	sotpi_info_t	*sti = SOTOTPI(so);

	ASSERT(MUTEX_HELD(&so->so_lock));

	ASSERT(so->so_family == AF_UNIX);

	if ((so->so_state & (SS_ISCONNECTED|SS_ISBOUND)) !=
	    (SS_ISCONNECTED|SS_ISBOUND))
		return;

	dprintso(so, 1, ("so_unix_close(%p) %s\n",
	    (void *)so, pr_state(so->so_state, so->so_mode)));

	toh.level = SOL_SOCKET;
	toh.name = SO_UNIX_CLOSE;

	/* zero length + header */
	toh.len = (t_uscalar_t)sizeof (struct T_opthdr);
	toh.status = 0;

	if (so->so_type == SOCK_STREAM || so->so_type == SOCK_SEQPACKET) {
		struct T_optdata_req tdr;

		tdr.PRIM_type = T_OPTDATA_REQ;
		tdr.DATA_flag = 0;

		tdr.OPT_length = (t_scalar_t)sizeof (toh);
		tdr.OPT_offset = (t_scalar_t)sizeof (tdr);

		/* NOTE: holding so_lock while sleeping */
		mp = soallocproto2(&tdr, sizeof (tdr),
		    &toh, sizeof (toh), 0, _ALLOC_SLEEP, CRED());
	} else {
		struct T_unitdata_req	tudr;
		void			*addr;
		socklen_t		addrlen;
		void			*src;
		socklen_t		srclen;
		struct T_opthdr		toh2;
		t_scalar_t		size;

		/* Connecteded DGRAM socket */

		/*
		 * For AF_UNIX the destination address is translated to
		 * an internal name and the source address is passed as
		 * an option.
		 */
		/*
		 * Length and family checks.
		 */
		error = so_addr_verify(so, sti->sti_faddr_sa,
		    (t_uscalar_t)sti->sti_faddr_len);
		if (error) {
			eprintsoline(so, error);
			return;
		}
		if (sti->sti_faddr_noxlate) {
			/*
			 * Already have a transport internal address. Do not
			 * pass any (transport internal) source address.
			 */
			addr = sti->sti_faddr_sa;
			addrlen = (t_uscalar_t)sti->sti_faddr_len;
			src = NULL;
			srclen = 0;
		} else {
			/*
			 * Pass the sockaddr_un source address as an option
			 * and translate the remote address.
			 * Holding so_lock thus sti_laddr_sa can not change.
			 */
			src = sti->sti_laddr_sa;
			srclen = (socklen_t)sti->sti_laddr_len;
			dprintso(so, 1,
			    ("so_ux_close: srclen %d, src %p\n",
			    srclen, src));
			error = so_ux_addr_xlate(so,
			    sti->sti_faddr_sa,
			    (socklen_t)sti->sti_faddr_len, 0,
			    &addr, &addrlen);
			if (error) {
				eprintsoline(so, error);
				return;
			}
		}
		tudr.PRIM_type = T_UNITDATA_REQ;
		tudr.DEST_length = addrlen;
		tudr.DEST_offset = (t_scalar_t)sizeof (tudr);
		if (srclen == 0) {
			tudr.OPT_length = (t_scalar_t)sizeof (toh);
			tudr.OPT_offset = (t_scalar_t)(sizeof (tudr) +
			    _TPI_ALIGN_TOPT(addrlen));

			size = tudr.OPT_offset + tudr.OPT_length;
			/* NOTE: holding so_lock while sleeping */
			mp = soallocproto2(&tudr, sizeof (tudr),
			    addr, addrlen, size, _ALLOC_SLEEP, CRED());
			mp->b_wptr += (_TPI_ALIGN_TOPT(addrlen) - addrlen);
			soappendmsg(mp, &toh, sizeof (toh));
		} else {
			/*
			 * There is a AF_UNIX sockaddr_un to include as a
			 * source address option.
			 */
			tudr.OPT_length = (t_scalar_t)(2 * sizeof (toh) +
			    _TPI_ALIGN_TOPT(srclen));
			tudr.OPT_offset = (t_scalar_t)(sizeof (tudr) +
			    _TPI_ALIGN_TOPT(addrlen));

			toh2.level = SOL_SOCKET;
			toh2.name = SO_SRCADDR;
			toh2.len = (t_uscalar_t)(srclen +
			    sizeof (struct T_opthdr));
			toh2.status = 0;

			size = tudr.OPT_offset + tudr.OPT_length;

			/* NOTE: holding so_lock while sleeping */
			mp = soallocproto2(&tudr, sizeof (tudr),
			    addr, addrlen, size, _ALLOC_SLEEP, CRED());
			mp->b_wptr += _TPI_ALIGN_TOPT(addrlen) - addrlen;
			soappendmsg(mp, &toh, sizeof (toh));
			soappendmsg(mp, &toh2, sizeof (toh2));
			soappendmsg(mp, src, srclen);
			mp->b_wptr += _TPI_ALIGN_TOPT(srclen) - srclen;
		}
		ASSERT(mp->b_wptr <= mp->b_datap->db_lim);
	}
	mutex_exit(&so->so_lock);
	error = kstrputmsg(SOTOV(so), mp, NULL, 0, 0,
	    MSG_BAND|MSG_HOLDSIG|MSG_IGNERROR|MSG_IGNFLOW, 0);
	mutex_enter(&so->so_lock);
}

/*
 * Called by sotpi_recvmsg when reading a non-zero amount of data.
 * In addition, the caller typically verifies that there is some
 * potential state to clear by checking
 *	if (so->so_state & (SS_OOBPEND|SS_HAVEOOBDATA|SS_RCVATMARK))
 * before calling this routine.
 * Note that such a check can be made without holding so_lock since
 * sotpi_recvmsg is single-threaded (using SOREADLOCKED) and only sotpi_recvmsg
 * decrements sti_oobsigcnt.
 *
 * When data is read *after* the point that all pending
 * oob data has been consumed the oob indication is cleared.
 *
 * This logic keeps select/poll returning POLLRDBAND and
 * SIOCATMARK returning true until we have read past
 * the mark.
 */
static void
sorecv_update_oobstate(struct sonode *so)
{
	sotpi_info_t *sti = SOTOTPI(so);

	mutex_enter(&so->so_lock);
	ASSERT(so_verify_oobstate(so));
	dprintso(so, 1,
	    ("sorecv_update_oobstate: counts %d/%d state %s\n",
	    sti->sti_oobsigcnt,
	    sti->sti_oobcnt, pr_state(so->so_state, so->so_mode)));
	if (sti->sti_oobsigcnt == 0) {
		/* No more pending oob indications */
		so->so_state &= ~(SS_OOBPEND|SS_HAVEOOBDATA|SS_RCVATMARK);
		freemsg(so->so_oobmsg);
		so->so_oobmsg = NULL;
	}
	ASSERT(so_verify_oobstate(so));
	mutex_exit(&so->so_lock);
}

/*
 * Handle recv* calls for an so which has NL7C saved recv mblk_t(s).
 */
static int
nl7c_sorecv(struct sonode *so, mblk_t **rmp, uio_t *uiop, rval_t *rp)
{
	sotpi_info_t *sti = SOTOTPI(so);
	int	error = 0;
	mblk_t *tmp = NULL;
	mblk_t *pmp = NULL;
	mblk_t *nmp = sti->sti_nl7c_rcv_mp;

	ASSERT(nmp != NULL);

	while (nmp != NULL && uiop->uio_resid > 0) {
		ssize_t n;

		if (DB_TYPE(nmp) == M_DATA) {
			/*
			 * We have some data, uiomove up to resid bytes.
			 */
			n = MIN(MBLKL(nmp), uiop->uio_resid);
			if (n > 0)
				error = uiomove(nmp->b_rptr, n, UIO_READ, uiop);
			nmp->b_rptr += n;
			if (nmp->b_rptr == nmp->b_wptr) {
				pmp = nmp;
				nmp = nmp->b_cont;
			}
			if (error)
				break;
		} else {
			/*
			 * We only handle data, save for caller to handle.
			 */
			if (pmp != NULL) {
				pmp->b_cont = nmp->b_cont;
			}
			nmp->b_cont = NULL;
			if (*rmp == NULL) {
				*rmp = nmp;
			} else {
				tmp->b_cont = nmp;
			}
			nmp = nmp->b_cont;
			tmp = nmp;
		}
	}
	if (pmp != NULL) {
		/* Free any mblk_t(s) which we have consumed */
		pmp->b_cont = NULL;
		freemsg(sti->sti_nl7c_rcv_mp);
	}
	if ((sti->sti_nl7c_rcv_mp = nmp) == NULL) {
		/* Last mblk_t so return the saved kstrgetmsg() rval/error */
		if (error == 0) {
			rval_t	*p = (rval_t *)&sti->sti_nl7c_rcv_rval;

			error = p->r_v.r_v2;
			p->r_v.r_v2 = 0;
		}
		rp->r_vals = sti->sti_nl7c_rcv_rval;
		sti->sti_nl7c_rcv_rval = 0;
	} else {
		/* More mblk_t(s) to process so no rval to return */
		rp->r_vals = 0;
	}
	return (error);
}
/*
 * Receive the next message on the queue.
 * If msg_controllen is non-zero when called the caller is interested in
 * any received control info (options).
 * If msg_namelen is non-zero when called the caller is interested in
 * any received source address.
 * The routine returns with msg_control and msg_name pointing to
 * kmem_alloc'ed memory which the caller has to free.
 */
/* ARGSUSED */
int
sotpi_recvmsg(struct sonode *so, struct nmsghdr *msg, struct uio *uiop,
    struct cred *cr)
{
	union T_primitives	*tpr;
	mblk_t			*mp;
	uchar_t			pri;
	int			pflag, opflag;
	void			*control;
	t_uscalar_t		controllen;
	t_uscalar_t		namelen;
	int			so_state = so->so_state; /* Snapshot */
	ssize_t			saved_resid;
	rval_t			rval;
	int			flags;
	clock_t			timout;
	int			error = 0;
	sotpi_info_t		*sti = SOTOTPI(so);

	flags = msg->msg_flags;
	msg->msg_flags = 0;

	dprintso(so, 1, ("sotpi_recvmsg(%p, %p, 0x%x) state %s err %d\n",
	    (void *)so, (void *)msg, flags,
	    pr_state(so->so_state, so->so_mode), so->so_error));

	if (so->so_version == SOV_STREAM) {
		so_update_attrs(so, SOACC);
		/* The imaginary "sockmod" has been popped - act as a stream */
		return (strread(SOTOV(so), uiop, cr));
	}

	/*
	 * If we are not connected because we have never been connected
	 * we return ENOTCONN. If we have been connected (but are no longer
	 * connected) then SS_CANTRCVMORE is set and we let kstrgetmsg return
	 * the EOF.
	 *
	 * An alternative would be to post an ENOTCONN error in stream head
	 * (read+write) and clear it when we're connected. However, that error
	 * would cause incorrect poll/select behavior!
	 */
	if ((so_state & (SS_ISCONNECTED|SS_CANTRCVMORE)) == 0 &&
	    (so->so_mode & SM_CONNREQUIRED)) {
		return (ENOTCONN);
	}

	/*
	 * Note: SunOS 4.X checks uio_resid == 0 before going to sleep (but
	 * after checking that the read queue is empty) and returns zero.
	 * This implementation will sleep (in kstrgetmsg) even if uio_resid
	 * is zero.
	 */

	if (flags & MSG_OOB) {
		/* Check that the transport supports OOB */
		if (!(so->so_mode & SM_EXDATA))
			return (EOPNOTSUPP);
		so_update_attrs(so, SOACC);
		return (sorecvoob(so, msg, uiop, flags,
		    (so->so_options & SO_OOBINLINE)));
	}

	so_update_attrs(so, SOACC);

	/*
	 * Set msg_controllen and msg_namelen to zero here to make it
	 * simpler in the cases that no control or name is returned.
	 */
	controllen = msg->msg_controllen;
	namelen = msg->msg_namelen;
	msg->msg_controllen = 0;
	msg->msg_namelen = 0;

	dprintso(so, 1, ("sotpi_recvmsg: namelen %d controllen %d\n",
	    namelen, controllen));

	mutex_enter(&so->so_lock);
	/*
	 * If an NL7C enabled socket and not waiting for write data.
	 */
	if ((sti->sti_nl7c_flags & (NL7C_ENABLED | NL7C_WAITWRITE)) ==
	    NL7C_ENABLED) {
		if (sti->sti_nl7c_uri) {
			/* Close uri processing for a previous request */
			nl7c_close(so);
		}
		if ((so_state & SS_CANTRCVMORE) &&
		    sti->sti_nl7c_rcv_mp == NULL) {
			/* Nothing to process, EOF */
			mutex_exit(&so->so_lock);
			return (0);
		} else if (sti->sti_nl7c_flags & NL7C_SOPERSIST) {
			/* Persistent NL7C socket, try to process request */
			boolean_t ret;

			ret = nl7c_process(so,
			    (so->so_state & (SS_NONBLOCK|SS_NDELAY)));
			rval.r_vals = sti->sti_nl7c_rcv_rval;
			error = rval.r_v.r_v2;
			if (error) {
				/* Error of some sort, return it */
				mutex_exit(&so->so_lock);
				return (error);
			}
			if (sti->sti_nl7c_flags &&
			    ! (sti->sti_nl7c_flags & NL7C_WAITWRITE)) {
				/*
				 * Still an NL7C socket and no data
				 * to pass up to the caller.
				 */
				mutex_exit(&so->so_lock);
				if (ret) {
					/* EOF */
					return (0);
				} else {
					/* Need more data */
					return (EAGAIN);
				}
			}
		} else {
			/*
			 * Not persistent so no further NL7C processing.
			 */
			sti->sti_nl7c_flags = 0;
		}
	}
	/*
	 * Only one reader is allowed at any given time. This is needed
	 * for T_EXDATA handling and, in the future, MSG_WAITALL.
	 *
	 * This is slightly different that BSD behavior in that it fails with
	 * EWOULDBLOCK when using nonblocking io. In BSD the read queue access
	 * is single-threaded using sblock(), which is dropped while waiting
	 * for data to appear. The difference shows up e.g. if one
	 * file descriptor does not have O_NONBLOCK but a dup'ed file descriptor
	 * does use nonblocking io and different threads are reading each
	 * file descriptor. In BSD there would never be an EWOULDBLOCK error
	 * in this case as long as the read queue doesn't get empty.
	 * In this implementation the thread using nonblocking io can
	 * get an EWOULDBLOCK error due to the blocking thread executing
	 * e.g. in the uiomove in kstrgetmsg.
	 * This difference is not believed to be significant.
	 */
	/* Set SOREADLOCKED */
	error = so_lock_read_intr(so,
	    uiop->uio_fmode | ((flags & MSG_DONTWAIT) ? FNONBLOCK : 0));
	mutex_exit(&so->so_lock);
	if (error)
		return (error);

	/*
	 * Tell kstrgetmsg to not inspect the stream head errors until all
	 * queued data has been consumed.
	 * Use a timeout=-1 to wait forever unless MSG_DONTWAIT is set.
	 * Also, If uio_fmode indicates nonblocking kstrgetmsg will not block.
	 *
	 * MSG_WAITALL only applies to M_DATA and T_DATA_IND messages and
	 * to T_OPTDATA_IND that do not contain any user-visible control msg.
	 * Note that MSG_WAITALL set with MSG_PEEK is a noop.
	 */
	pflag = MSG_ANY | MSG_DELAYERROR;
	if (flags & MSG_PEEK) {
		pflag |= MSG_IPEEK;
		flags &= ~MSG_WAITALL;
	}
	if (so->so_mode & SM_ATOMIC)
		pflag |= MSG_DISCARDTAIL;

	if (flags & MSG_DONTWAIT)
		timout = 0;
	else if (so->so_rcvtimeo != 0)
		timout = TICK_TO_MSEC(so->so_rcvtimeo);
	else
		timout = -1;
	opflag = pflag;
retry:
	saved_resid = uiop->uio_resid;
	pri = 0;
	mp = NULL;
	if (sti->sti_nl7c_rcv_mp != NULL) {
		/* Already kstrgetmsg()ed saved mblk(s) from NL7C */
		error = nl7c_sorecv(so, &mp, uiop, &rval);
	} else {
		error = kstrgetmsg(SOTOV(so), &mp, uiop, &pri, &pflag,
		    timout, &rval);
	}
	if (error != 0) {
		/* kstrgetmsg returns ETIME when timeout expires */
		if (error == ETIME)
			error = EWOULDBLOCK;
		goto out;
	}
	/*
	 * For datagrams the MOREDATA flag is used to set MSG_TRUNC.
	 * For non-datagrams MOREDATA is used to set MSG_EOR.
	 */
	ASSERT(!(rval.r_val1 & MORECTL));
	if ((rval.r_val1 & MOREDATA) && (so->so_mode & SM_ATOMIC))
		msg->msg_flags |= MSG_TRUNC;

	if (mp == NULL) {
		dprintso(so, 1, ("sotpi_recvmsg: got M_DATA\n"));
		/*
		 * 4.3BSD and 4.4BSD clears the mark when peeking across it.
		 * The draft Posix socket spec states that the mark should
		 * not be cleared when peeking. We follow the latter.
		 */
		if ((so->so_state &
		    (SS_OOBPEND|SS_HAVEOOBDATA|SS_RCVATMARK)) &&
		    (uiop->uio_resid != saved_resid) &&
		    !(flags & MSG_PEEK)) {
			sorecv_update_oobstate(so);
		}

		mutex_enter(&so->so_lock);
		/* Set MSG_EOR based on MOREDATA */
		if (!(rval.r_val1 & MOREDATA)) {
			if (so->so_state & SS_SAVEDEOR) {
				msg->msg_flags |= MSG_EOR;
				so->so_state &= ~SS_SAVEDEOR;
			}
		}
		/*
		 * If some data was received (i.e. not EOF) and the
		 * read/recv* has not been satisfied wait for some more.
		 */
		if ((flags & MSG_WAITALL) && !(msg->msg_flags & MSG_EOR) &&
		    uiop->uio_resid != saved_resid && uiop->uio_resid > 0) {
			mutex_exit(&so->so_lock);
			pflag = opflag | MSG_NOMARK;
			goto retry;
		}
		goto out_locked;
	}

	/* strsock_proto has already verified length and alignment */
	tpr = (union T_primitives *)mp->b_rptr;
	dprintso(so, 1, ("sotpi_recvmsg: type %d\n", tpr->type));

	switch (tpr->type) {
	case T_DATA_IND: {
		if ((so->so_state &
		    (SS_OOBPEND|SS_HAVEOOBDATA|SS_RCVATMARK)) &&
		    (uiop->uio_resid != saved_resid) &&
		    !(flags & MSG_PEEK)) {
			sorecv_update_oobstate(so);
		}

		/*
		 * Set msg_flags to MSG_EOR based on
		 * MORE_flag and MOREDATA.
		 */
		mutex_enter(&so->so_lock);
		so->so_state &= ~SS_SAVEDEOR;
		if (!(tpr->data_ind.MORE_flag & 1)) {
			if (!(rval.r_val1 & MOREDATA))
				msg->msg_flags |= MSG_EOR;
			else
				so->so_state |= SS_SAVEDEOR;
		}
		freemsg(mp);
		/*
		 * If some data was received (i.e. not EOF) and the
		 * read/recv* has not been satisfied wait for some more.
		 */
		if ((flags & MSG_WAITALL) && !(msg->msg_flags & MSG_EOR) &&
		    uiop->uio_resid != saved_resid && uiop->uio_resid > 0) {
			mutex_exit(&so->so_lock);
			pflag = opflag | MSG_NOMARK;
			goto retry;
		}
		goto out_locked;
	}
	case T_UNITDATA_IND: {
		void *addr;
		t_uscalar_t addrlen;
		void *abuf;
		t_uscalar_t optlen;
		void *opt;

		if ((so->so_state &
		    (SS_OOBPEND|SS_HAVEOOBDATA|SS_RCVATMARK)) &&
		    (uiop->uio_resid != saved_resid) &&
		    !(flags & MSG_PEEK)) {
			sorecv_update_oobstate(so);
		}

		if (namelen != 0) {
			/* Caller wants source address */
			addrlen = tpr->unitdata_ind.SRC_length;
			addr = sogetoff(mp,
			    tpr->unitdata_ind.SRC_offset,
			    addrlen, 1);
			if (addr == NULL) {
				freemsg(mp);
				error = EPROTO;
				eprintsoline(so, error);
				goto out;
			}
			if (so->so_family == AF_UNIX) {
				/*
				 * Can not use the transport level address.
				 * If there is a SO_SRCADDR option carrying
				 * the socket level address it will be
				 * extracted below.
				 */
				addr = NULL;
				addrlen = 0;
			}
		}
		optlen = tpr->unitdata_ind.OPT_length;
		if (optlen != 0) {
			t_uscalar_t ncontrollen;

			/*
			 * Extract any source address option.
			 * Determine how large cmsg buffer is needed.
			 */
			opt = sogetoff(mp,
			    tpr->unitdata_ind.OPT_offset,
			    optlen, __TPI_ALIGN_SIZE);

			if (opt == NULL) {
				freemsg(mp);
				error = EPROTO;
				eprintsoline(so, error);
				goto out;
			}
			if (so->so_family == AF_UNIX)
				so_getopt_srcaddr(opt, optlen, &addr, &addrlen);
			ncontrollen = so_cmsglen(mp, opt, optlen,
			    !(flags & MSG_XPG4_2));
			if (controllen != 0)
				controllen = ncontrollen;
			else if (ncontrollen != 0)
				msg->msg_flags |= MSG_CTRUNC;
		} else {
			controllen = 0;
		}

		if (namelen != 0) {
			/*
			 * Return address to caller.
			 * Caller handles truncation if length
			 * exceeds msg_namelen.
			 * NOTE: AF_UNIX NUL termination is ensured by
			 * the sender's copyin_name().
			 */
			abuf = kmem_alloc(addrlen, KM_SLEEP);

			bcopy(addr, abuf, addrlen);
			msg->msg_name = abuf;
			msg->msg_namelen = addrlen;
		}

		if (controllen != 0) {
			/*
			 * Return control msg to caller.
			 * Caller handles truncation if length
			 * exceeds msg_controllen.
			 */
			control = kmem_zalloc(controllen, KM_SLEEP);

			error = so_opt2cmsg(mp, opt, optlen,
			    !(flags & MSG_XPG4_2),
			    control, controllen);
			if (error) {
				freemsg(mp);
				if (msg->msg_namelen != 0)
					kmem_free(msg->msg_name,
					    msg->msg_namelen);
				kmem_free(control, controllen);
				eprintsoline(so, error);
				goto out;
			}
			msg->msg_control = control;
			msg->msg_controllen = controllen;
		}

		freemsg(mp);
		goto out;
	}
	case T_OPTDATA_IND: {
		struct T_optdata_req *tdr;
		void *opt;
		t_uscalar_t optlen;

		if ((so->so_state &
		    (SS_OOBPEND|SS_HAVEOOBDATA|SS_RCVATMARK)) &&
		    (uiop->uio_resid != saved_resid) &&
		    !(flags & MSG_PEEK)) {
			sorecv_update_oobstate(so);
		}

		tdr = (struct T_optdata_req *)mp->b_rptr;
		optlen = tdr->OPT_length;
		if (optlen != 0) {
			t_uscalar_t ncontrollen;
			/*
			 * Determine how large cmsg buffer is needed.
			 */
			opt = sogetoff(mp,
			    tpr->optdata_ind.OPT_offset,
			    optlen, __TPI_ALIGN_SIZE);

			if (opt == NULL) {
				freemsg(mp);
				error = EPROTO;
				eprintsoline(so, error);
				goto out;
			}

			ncontrollen = so_cmsglen(mp, opt, optlen,
			    !(flags & MSG_XPG4_2));
			if (controllen != 0)
				controllen = ncontrollen;
			else if (ncontrollen != 0)
				msg->msg_flags |= MSG_CTRUNC;
		} else {
			controllen = 0;
		}

		if (controllen != 0) {
			/*
			 * Return control msg to caller.
			 * Caller handles truncation if length
			 * exceeds msg_controllen.
			 */
			control = kmem_zalloc(controllen, KM_SLEEP);

			error = so_opt2cmsg(mp, opt, optlen,
			    !(flags & MSG_XPG4_2),
			    control, controllen);
			if (error) {
				freemsg(mp);
				kmem_free(control, controllen);
				eprintsoline(so, error);
				goto out;
			}
			msg->msg_control = control;
			msg->msg_controllen = controllen;
		}

		/*
		 * Set msg_flags to MSG_EOR based on
		 * DATA_flag and MOREDATA.
		 */
		mutex_enter(&so->so_lock);
		so->so_state &= ~SS_SAVEDEOR;
		if (!(tpr->data_ind.MORE_flag & 1)) {
			if (!(rval.r_val1 & MOREDATA))
				msg->msg_flags |= MSG_EOR;
			else
				so->so_state |= SS_SAVEDEOR;
		}
		freemsg(mp);
		/*
		 * If some data was received (i.e. not EOF) and the
		 * read/recv* has not been satisfied wait for some more.
		 * Not possible to wait if control info was received.
		 */
		if ((flags & MSG_WAITALL) && !(msg->msg_flags & MSG_EOR) &&
		    controllen == 0 &&
		    uiop->uio_resid != saved_resid && uiop->uio_resid > 0) {
			mutex_exit(&so->so_lock);
			pflag = opflag | MSG_NOMARK;
			goto retry;
		}
		goto out_locked;
	}
	case T_EXDATA_IND: {
		dprintso(so, 1,
		    ("sotpi_recvmsg: EXDATA_IND counts %d/%d consumed %ld "
		    "state %s\n",
		    sti->sti_oobsigcnt, sti->sti_oobcnt,
		    saved_resid - uiop->uio_resid,
		    pr_state(so->so_state, so->so_mode)));
		/*
		 * kstrgetmsg handles MSGMARK so there is nothing to
		 * inspect in the T_EXDATA_IND.
		 * strsock_proto makes the stream head queue the T_EXDATA_IND
		 * as a separate message with no M_DATA component. Furthermore,
		 * the stream head does not consolidate M_DATA messages onto
		 * an MSGMARK'ed message ensuring that the T_EXDATA_IND
		 * remains a message by itself. This is needed since MSGMARK
		 * marks both the whole message as well as the last byte
		 * of the message.
		 */
		freemsg(mp);
		ASSERT(uiop->uio_resid == saved_resid);	/* No data */
		if (flags & MSG_PEEK) {
			/*
			 * Even though we are peeking we consume the
			 * T_EXDATA_IND thereby moving the mark information
			 * to SS_RCVATMARK. Then the oob code below will
			 * retry the peeking kstrgetmsg.
			 * Note that the stream head read queue is
			 * never flushed without holding SOREADLOCKED
			 * thus the T_EXDATA_IND can not disappear
			 * underneath us.
			 */
			dprintso(so, 1,
			    ("sotpi_recvmsg: consume EXDATA_IND "
			    "counts %d/%d state %s\n",
			    sti->sti_oobsigcnt,
			    sti->sti_oobcnt,
			    pr_state(so->so_state, so->so_mode)));

			pflag = MSG_ANY | MSG_DELAYERROR;
			if (so->so_mode & SM_ATOMIC)
				pflag |= MSG_DISCARDTAIL;

			pri = 0;
			mp = NULL;

			error = kstrgetmsg(SOTOV(so), &mp, uiop,
			    &pri, &pflag, (clock_t)-1, &rval);
			ASSERT(uiop->uio_resid == saved_resid);

			if (error) {
#ifdef SOCK_DEBUG
				if (error != EWOULDBLOCK && error != EINTR) {
					eprintsoline(so, error);
				}
#endif /* SOCK_DEBUG */
				goto out;
			}
			ASSERT(mp);
			tpr = (union T_primitives *)mp->b_rptr;
			ASSERT(tpr->type == T_EXDATA_IND);
			freemsg(mp);
		} /* end "if (flags & MSG_PEEK)" */

		/*
		 * Decrement the number of queued and pending oob.
		 *
		 * SS_RCVATMARK is cleared when we read past a mark.
		 * SS_HAVEOOBDATA is cleared when we've read past the
		 * last mark.
		 * SS_OOBPEND is cleared if we've read past the last
		 * mark and no (new) SIGURG has been posted.
		 */
		mutex_enter(&so->so_lock);
		ASSERT(so_verify_oobstate(so));
		ASSERT(sti->sti_oobsigcnt >= sti->sti_oobcnt);
		ASSERT(sti->sti_oobsigcnt > 0);
		sti->sti_oobsigcnt--;
		ASSERT(sti->sti_oobcnt > 0);
		sti->sti_oobcnt--;
		/*
		 * Since the T_EXDATA_IND has been removed from the stream
		 * head, but we have not read data past the mark,
		 * sockfs needs to track that the socket is still at the mark.
		 *
		 * Since no data was received call kstrgetmsg again to wait
		 * for data.
		 */
		so->so_state |= SS_RCVATMARK;
		mutex_exit(&so->so_lock);
		dprintso(so, 1,
		    ("sotpi_recvmsg: retry EXDATA_IND counts %d/%d state %s\n",
		    sti->sti_oobsigcnt, sti->sti_oobcnt,
		    pr_state(so->so_state, so->so_mode)));
		pflag = opflag;
		goto retry;
	}
	default:
		cmn_err(CE_CONT, "sotpi_recvmsg: so %p prim %d mp %p\n",
		    (void *)so, tpr->type, (void *)mp);
		ASSERT(0);
		freemsg(mp);
		error = EPROTO;
		eprintsoline(so, error);
		goto out;
	}
	/* NOTREACHED */
out:
	mutex_enter(&so->so_lock);
out_locked:
	so_unlock_read(so);	/* Clear SOREADLOCKED */
	mutex_exit(&so->so_lock);
	return (error);
}

/*
 * Sending data with options on a datagram socket.
 * Assumes caller has verified that SS_ISBOUND etc. are set.
 */
static int
sosend_dgramcmsg(struct sonode *so, struct sockaddr *name, socklen_t namelen,
    struct uio *uiop, void *control, t_uscalar_t controllen, int flags)
{
	struct T_unitdata_req	tudr;
	mblk_t			*mp;
	int			error;
	void			*addr;
	socklen_t		addrlen;
	void			*src;
	socklen_t		srclen;
	ssize_t			len;
	int			size;
	struct T_opthdr		toh;
	struct fdbuf		*fdbuf;
	t_uscalar_t		optlen;
	void			*fds;
	int			fdlen;
	sotpi_info_t		*sti = SOTOTPI(so);

	ASSERT(name && namelen);
	ASSERT(control && controllen);

	len = uiop->uio_resid;
	if (len > (ssize_t)sti->sti_tidu_size) {
		return (EMSGSIZE);
	}

	/*
	 * For AF_UNIX the destination address is translated to an internal
	 * name and the source address is passed as an option.
	 * Also, file descriptors are passed as file pointers in an
	 * option.
	 */

	/*
	 * Length and family checks.
	 */
	error = so_addr_verify(so, name, namelen);
	if (error) {
		eprintsoline(so, error);
		return (error);
	}
	if (so->so_family == AF_UNIX) {
		if (sti->sti_faddr_noxlate) {
			/*
			 * Already have a transport internal address. Do not
			 * pass any (transport internal) source address.
			 */
			addr = name;
			addrlen = namelen;
			src = NULL;
			srclen = 0;
		} else {
			/*
			 * Pass the sockaddr_un source address as an option
			 * and translate the remote address.
			 *
			 * Note that this code does not prevent sti_laddr_sa
			 * from changing while it is being used. Thus
			 * if an unbind+bind occurs concurrently with this
			 * send the peer might see a partially new and a
			 * partially old "from" address.
			 */
			src = sti->sti_laddr_sa;
			srclen = (t_uscalar_t)sti->sti_laddr_len;
			dprintso(so, 1,
			    ("sosend_dgramcmsg UNIX: srclen %d, src %p\n",
			    srclen, src));
			error = so_ux_addr_xlate(so, name, namelen,
			    (flags & MSG_XPG4_2),
			    &addr, &addrlen);
			if (error) {
				eprintsoline(so, error);
				return (error);
			}
		}
	} else {
		addr = name;
		addrlen = namelen;
		src = NULL;
		srclen = 0;
	}
	optlen = so_optlen(control, controllen,
	    !(flags & MSG_XPG4_2));
	tudr.PRIM_type = T_UNITDATA_REQ;
	tudr.DEST_length = addrlen;
	tudr.DEST_offset = (t_scalar_t)sizeof (tudr);
	if (srclen != 0)
		tudr.OPT_length = (t_scalar_t)(optlen + sizeof (toh) +
		    _TPI_ALIGN_TOPT(srclen));
	else
		tudr.OPT_length = optlen;
	tudr.OPT_offset = (t_scalar_t)(sizeof (tudr) +
	    _TPI_ALIGN_TOPT(addrlen));

	size = tudr.OPT_offset + tudr.OPT_length;

	/*
	 * File descriptors only when SM_FDPASSING set.
	 */
	error = so_getfdopt(control, controllen,
	    !(flags & MSG_XPG4_2), &fds, &fdlen);
	if (error)
		return (error);
	if (fdlen != -1) {
		if (!(so->so_mode & SM_FDPASSING))
			return (EOPNOTSUPP);

		error = fdbuf_create(fds, fdlen, &fdbuf);
		if (error)
			return (error);

		/*
		 * Pre-allocate enough additional space for lower level modules
		 * to append an option (e.g. see tl_unitdata). The following
		 * is enough extra space for the largest option we might append.
		 */
		size += sizeof (struct T_opthdr) + ucredsize;
		mp = fdbuf_allocmsg(size, fdbuf);
	} else {
		mp = soallocproto(size, _ALLOC_INTR, CRED());
		if (mp == NULL) {
			/*
			 * Caught a signal waiting for memory.
			 * Let send* return EINTR.
			 */
			return (EINTR);
		}
	}
	soappendmsg(mp, &tudr, sizeof (tudr));
	soappendmsg(mp, addr, addrlen);
	mp->b_wptr += _TPI_ALIGN_TOPT(addrlen) - addrlen;

	if (fdlen != -1) {
		ASSERT(fdbuf != NULL);
		toh.level = SOL_SOCKET;
		toh.name = SO_FILEP;
		toh.len = fdbuf->fd_size +
		    (t_uscalar_t)sizeof (struct T_opthdr);
		toh.status = 0;
		soappendmsg(mp, &toh, sizeof (toh));
		soappendmsg(mp, fdbuf, fdbuf->fd_size);
		ASSERT(__TPI_TOPT_ISALIGNED(mp->b_wptr));
	}
	if (srclen != 0) {
		/*
		 * There is a AF_UNIX sockaddr_un to include as a source
		 * address option.
		 */
		toh.level = SOL_SOCKET;
		toh.name = SO_SRCADDR;
		toh.len = (t_uscalar_t)(srclen + sizeof (struct T_opthdr));
		toh.status = 0;
		soappendmsg(mp, &toh, sizeof (toh));
		soappendmsg(mp, src, srclen);
		mp->b_wptr += _TPI_ALIGN_TOPT(srclen) - srclen;
		ASSERT(__TPI_TOPT_ISALIGNED(mp->b_wptr));
	}
	ASSERT(mp->b_wptr <= mp->b_datap->db_lim);
	so_cmsg2opt(control, controllen, !(flags & MSG_XPG4_2), mp);
	/*
	 * Normally at most 3 bytes left in the message, but we might have
	 * allowed for extra space if we're passing fd's through.
	 */
	ASSERT(MBLKL(mp) <= (ssize_t)size);

	ASSERT(mp->b_wptr <= mp->b_datap->db_lim);
	if (AU_AUDITING())
		audit_sock(T_UNITDATA_REQ, strvp2wq(SOTOV(so)), mp, 0);

	error = kstrputmsg(SOTOV(so), mp, uiop, len, 0, MSG_BAND, 0);
#ifdef SOCK_DEBUG
	if (error) {
		eprintsoline(so, error);
	}
#endif /* SOCK_DEBUG */
	return (error);
}

/*
 * Sending data with options on a connected stream socket.
 * Assumes caller has verified that SS_ISCONNECTED is set.
 */
static int
sosend_svccmsg(struct sonode *so, struct uio *uiop, int more, void *control,
    t_uscalar_t controllen, int flags)
{
	struct T_optdata_req	tdr;
	mblk_t			*mp;
	int			error;
	ssize_t			iosize;
	int			size;
	struct fdbuf		*fdbuf;
	t_uscalar_t		optlen;
	void			*fds;
	int			fdlen;
	struct T_opthdr		toh;
	sotpi_info_t		*sti = SOTOTPI(so);

	dprintso(so, 1,
	    ("sosend_svccmsg: resid %ld bytes\n", uiop->uio_resid));

	/*
	 * Has to be bound and connected. However, since no locks are
	 * held the state could have changed after sotpi_sendmsg checked it
	 * thus it is not possible to ASSERT on the state.
	 */

	/* Options on connection-oriented only when SM_OPTDATA set. */
	if (!(so->so_mode & SM_OPTDATA))
		return (EOPNOTSUPP);

	do {
		/*
		 * Set the MORE flag if uio_resid does not fit in this
		 * message or if the caller passed in "more".
		 * Error for transports with zero tidu_size.
		 */
		tdr.PRIM_type = T_OPTDATA_REQ;
		iosize = sti->sti_tidu_size;
		if (iosize <= 0)
			return (EMSGSIZE);
		if (uiop->uio_resid > iosize) {
			tdr.DATA_flag = 1;
		} else {
			if (more)
				tdr.DATA_flag = 1;
			else
				tdr.DATA_flag = 0;
			iosize = uiop->uio_resid;
		}
		dprintso(so, 1, ("sosend_svccmsg: sending %d, %ld bytes\n",
		    tdr.DATA_flag, iosize));

		optlen = so_optlen(control, controllen, !(flags & MSG_XPG4_2));
		tdr.OPT_length = optlen;
		tdr.OPT_offset = (t_scalar_t)sizeof (tdr);

		size = (int)sizeof (tdr) + optlen;
		/*
		 * File descriptors only when SM_FDPASSING set.
		 */
		error = so_getfdopt(control, controllen,
		    !(flags & MSG_XPG4_2), &fds, &fdlen);
		if (error)
			return (error);
		if (fdlen != -1) {
			if (!(so->so_mode & SM_FDPASSING))
				return (EOPNOTSUPP);

			error = fdbuf_create(fds, fdlen, &fdbuf);
			if (error)
				return (error);

			/*
			 * Pre-allocate enough additional space for lower level
			 * modules to append an option (e.g. see tl_unitdata).
			 * The following is enough extra space for the largest
			 * option we might append.
			 */
			size += sizeof (struct T_opthdr) + ucredsize;
			mp = fdbuf_allocmsg(size, fdbuf);
		} else {
			mp = soallocproto(size, _ALLOC_INTR, CRED());
			if (mp == NULL) {
				/*
				 * Caught a signal waiting for memory.
				 * Let send* return EINTR.
				 */
				return (EINTR);
			}
		}
		soappendmsg(mp, &tdr, sizeof (tdr));

		if (fdlen != -1) {
			ASSERT(fdbuf != NULL);
			toh.level = SOL_SOCKET;
			toh.name = SO_FILEP;
			toh.len = fdbuf->fd_size +
			    (t_uscalar_t)sizeof (struct T_opthdr);
			toh.status = 0;
			soappendmsg(mp, &toh, sizeof (toh));
			soappendmsg(mp, fdbuf, fdbuf->fd_size);
			ASSERT(__TPI_TOPT_ISALIGNED(mp->b_wptr));
		}
		so_cmsg2opt(control, controllen, !(flags & MSG_XPG4_2), mp);
		/*
		 * Normally at most 3 bytes left in the message, but we might
		 * have allowed for extra space if we're passing fd's through.
		 */
		ASSERT(MBLKL(mp) <= (ssize_t)size);

		ASSERT(mp->b_wptr <= mp->b_datap->db_lim);

		error = kstrputmsg(SOTOV(so), mp, uiop, iosize,
		    0, MSG_BAND, 0);
		if (error) {
			eprintsoline(so, error);
			return (error);
		}
		control = NULL;
		if (uiop->uio_resid > 0) {
			/*
			 * Recheck for fatal errors. Fail write even though
			 * some data have been written. This is consistent
			 * with strwrite semantics and BSD sockets semantics.
			 */
			if (so->so_state & SS_CANTSENDMORE) {
				eprintsoline(so, error);
				return (EPIPE);
			}
			if (so->so_error != 0) {
				mutex_enter(&so->so_lock);
				error = sogeterr(so, B_TRUE);
				mutex_exit(&so->so_lock);
				if (error != 0) {
					eprintsoline(so, error);
					return (error);
				}
			}
		}
	} while (uiop->uio_resid > 0);
	return (0);
}

/*
 * Sending data on a datagram socket.
 * Assumes caller has verified that SS_ISBOUND etc. are set.
 *
 * For AF_UNIX the destination address is translated to an internal
 * name and the source address is passed as an option.
 */
int
sosend_dgram(struct sonode *so, struct sockaddr	*name, socklen_t namelen,
    struct uio *uiop, int flags)
{
	struct T_unitdata_req	tudr;
	mblk_t			*mp;
	int			error;
	void			*addr;
	socklen_t		addrlen;
	void			*src;
	socklen_t		srclen;
	ssize_t			len;
	sotpi_info_t		*sti = SOTOTPI(so);

	ASSERT(name != NULL && namelen != 0);

	len = uiop->uio_resid;
	if (len > sti->sti_tidu_size) {
		error = EMSGSIZE;
		goto done;
	}

	/* Length and family checks */
	error = so_addr_verify(so, name, namelen);
	if (error != 0)
		goto done;

	if (sti->sti_direct)
		return (sodgram_direct(so, name, namelen, uiop, flags));

	if (so->so_family == AF_UNIX) {
		if (sti->sti_faddr_noxlate) {
			/*
			 * Already have a transport internal address. Do not
			 * pass any (transport internal) source address.
			 */
			addr = name;
			addrlen = namelen;
			src = NULL;
			srclen = 0;
		} else {
			/*
			 * Pass the sockaddr_un source address as an option
			 * and translate the remote address.
			 *
			 * Note that this code does not prevent sti_laddr_sa
			 * from changing while it is being used. Thus
			 * if an unbind+bind occurs concurrently with this
			 * send the peer might see a partially new and a
			 * partially old "from" address.
			 */
			src = sti->sti_laddr_sa;
			srclen = (socklen_t)sti->sti_laddr_len;
			dprintso(so, 1,
			    ("sosend_dgram UNIX: srclen %d, src %p\n",
			    srclen, src));
			error = so_ux_addr_xlate(so, name, namelen,
			    (flags & MSG_XPG4_2),
			    &addr, &addrlen);
			if (error) {
				eprintsoline(so, error);
				goto done;
			}
		}
	} else {
		addr = name;
		addrlen = namelen;
		src = NULL;
		srclen = 0;
	}
	tudr.PRIM_type = T_UNITDATA_REQ;
	tudr.DEST_length = addrlen;
	tudr.DEST_offset = (t_scalar_t)sizeof (tudr);
	if (srclen == 0) {
		tudr.OPT_length = 0;
		tudr.OPT_offset = 0;

		mp = soallocproto2(&tudr, sizeof (tudr),
		    addr, addrlen, 0, _ALLOC_INTR, CRED());
		if (mp == NULL) {
			/*
			 * Caught a signal waiting for memory.
			 * Let send* return EINTR.
			 */
			error = EINTR;
			goto done;
		}
	} else {
		/*
		 * There is a AF_UNIX sockaddr_un to include as a source
		 * address option.
		 */
		struct T_opthdr toh;
		ssize_t size;

		tudr.OPT_length = (t_scalar_t)(sizeof (toh) +
		    _TPI_ALIGN_TOPT(srclen));
		tudr.OPT_offset = (t_scalar_t)(sizeof (tudr) +
		    _TPI_ALIGN_TOPT(addrlen));

		toh.level = SOL_SOCKET;
		toh.name = SO_SRCADDR;
		toh.len = (t_uscalar_t)(srclen + sizeof (struct T_opthdr));
		toh.status = 0;

		size = tudr.OPT_offset + tudr.OPT_length;
		mp = soallocproto2(&tudr, sizeof (tudr),
		    addr, addrlen, size, _ALLOC_INTR, CRED());
		if (mp == NULL) {
			/*
			 * Caught a signal waiting for memory.
			 * Let send* return EINTR.
			 */
			error = EINTR;
			goto done;
		}
		mp->b_wptr += _TPI_ALIGN_TOPT(addrlen) - addrlen;
		soappendmsg(mp, &toh, sizeof (toh));
		soappendmsg(mp, src, srclen);
		mp->b_wptr += _TPI_ALIGN_TOPT(srclen) - srclen;
		ASSERT(mp->b_wptr <= mp->b_datap->db_lim);
	}

	if (AU_AUDITING())
		audit_sock(T_UNITDATA_REQ, strvp2wq(SOTOV(so)), mp, 0);

	error = kstrputmsg(SOTOV(so), mp, uiop, len, 0, MSG_BAND, 0);
done:
#ifdef SOCK_DEBUG
	if (error) {
		eprintsoline(so, error);
	}
#endif /* SOCK_DEBUG */
	return (error);
}

/*
 * Sending data on a connected stream socket.
 * Assumes caller has verified that SS_ISCONNECTED is set.
 */
int
sosend_svc(struct sonode *so, struct uio *uiop, t_scalar_t prim, int more,
    int sflag)
{
	struct T_data_req	tdr;
	mblk_t			*mp;
	int			error;
	ssize_t			iosize;
	sotpi_info_t		*sti = SOTOTPI(so);

	dprintso(so, 1,
	    ("sosend_svc: %p, resid %ld bytes, prim %d, sflag 0x%x\n",
	    (void *)so, uiop->uio_resid, prim, sflag));

	/*
	 * Has to be bound and connected. However, since no locks are
	 * held the state could have changed after sotpi_sendmsg checked it
	 * thus it is not possible to ASSERT on the state.
	 */

	do {
		/*
		 * Set the MORE flag if uio_resid does not fit in this
		 * message or if the caller passed in "more".
		 * Error for transports with zero tidu_size.
		 */
		tdr.PRIM_type = prim;
		iosize = sti->sti_tidu_size;
		if (iosize <= 0)
			return (EMSGSIZE);
		if (uiop->uio_resid > iosize) {
			tdr.MORE_flag = 1;
		} else {
			if (more)
				tdr.MORE_flag = 1;
			else
				tdr.MORE_flag = 0;
			iosize = uiop->uio_resid;
		}
		dprintso(so, 1, ("sosend_svc: sending 0x%x %d, %ld bytes\n",
		    prim, tdr.MORE_flag, iosize));
		mp = soallocproto1(&tdr, sizeof (tdr), 0, _ALLOC_INTR, CRED());
		if (mp == NULL) {
			/*
			 * Caught a signal waiting for memory.
			 * Let send* return EINTR.
			 */
			return (EINTR);
		}

		error = kstrputmsg(SOTOV(so), mp, uiop, iosize,
		    0, sflag | MSG_BAND, 0);
		if (error) {
			eprintsoline(so, error);
			return (error);
		}
		if (uiop->uio_resid > 0) {
			/*
			 * Recheck for fatal errors. Fail write even though
			 * some data have been written. This is consistent
			 * with strwrite semantics and BSD sockets semantics.
			 */
			if (so->so_state & SS_CANTSENDMORE) {
				eprintsoline(so, error);
				return (EPIPE);
			}
			if (so->so_error != 0) {
				mutex_enter(&so->so_lock);
				error = sogeterr(so, B_TRUE);
				mutex_exit(&so->so_lock);
				if (error != 0) {
					eprintsoline(so, error);
					return (error);
				}
			}
		}
	} while (uiop->uio_resid > 0);
	return (0);
}

/*
 * Check the state for errors and call the appropriate send function.
 *
 * If MSG_DONTROUTE is set (and SO_DONTROUTE isn't already set)
 * this function issues a setsockopt to toggle SO_DONTROUTE before and
 * after sending the message.
 */
static int
sotpi_sendmsg(struct sonode *so, struct nmsghdr *msg, struct uio *uiop,
    struct cred *cr)
{
	int		so_state;
	int		so_mode;
	int		error;
	struct sockaddr *name;
	t_uscalar_t	namelen;
	int		dontroute;
	int		flags;
	sotpi_info_t	*sti = SOTOTPI(so);

	dprintso(so, 1, ("sotpi_sendmsg(%p, %p, 0x%x) state %s, error %d\n",
	    (void *)so, (void *)msg, msg->msg_flags,
	    pr_state(so->so_state, so->so_mode), so->so_error));

	if (so->so_version == SOV_STREAM) {
		/* The imaginary "sockmod" has been popped - act as a stream */
		so_update_attrs(so, SOMOD);
		return (strwrite(SOTOV(so), uiop, cr));
	}

	mutex_enter(&so->so_lock);
	so_state = so->so_state;

	if (so_state & SS_CANTSENDMORE) {
		mutex_exit(&so->so_lock);
		return (EPIPE);
	}

	if (so->so_error != 0) {
		error = sogeterr(so, B_TRUE);
		if (error != 0) {
			mutex_exit(&so->so_lock);
			return (error);
		}
	}

	name = (struct sockaddr *)msg->msg_name;
	namelen = msg->msg_namelen;

	so_mode = so->so_mode;

	if (name == NULL) {
		if (!(so_state & SS_ISCONNECTED)) {
			mutex_exit(&so->so_lock);
			if (so_mode & SM_CONNREQUIRED)
				return (ENOTCONN);
			else
				return (EDESTADDRREQ);
		}
		if (so_mode & SM_CONNREQUIRED) {
			name = NULL;
			namelen = 0;
		} else {
			/*
			 * Note that this code does not prevent sti_faddr_sa
			 * from changing while it is being used. Thus
			 * if an "unconnect"+connect occurs concurrently with
			 * this send the datagram might be delivered to a
			 * garbaled address.
			 */
			ASSERT(sti->sti_faddr_sa);
			name = sti->sti_faddr_sa;
			namelen = (t_uscalar_t)sti->sti_faddr_len;
		}
	} else {
		if (!(so_state & SS_ISCONNECTED) &&
		    (so_mode & SM_CONNREQUIRED)) {
			/* Required but not connected */
			mutex_exit(&so->so_lock);
			return (ENOTCONN);
		}
		/*
		 * Ignore the address on connection-oriented sockets.
		 * Just like BSD this code does not generate an error for
		 * TCP (a CONNREQUIRED socket) when sending to an address
		 * passed in with sendto/sendmsg. Instead the data is
		 * delivered on the connection as if no address had been
		 * supplied.
		 */
		if ((so_state & SS_ISCONNECTED) &&
		    !(so_mode & SM_CONNREQUIRED)) {
			mutex_exit(&so->so_lock);
			return (EISCONN);
		}
		if (!(so_state & SS_ISBOUND)) {
			so_lock_single(so);	/* Set SOLOCKED */
			error = sotpi_bind(so, NULL, 0,
			    _SOBIND_UNSPEC|_SOBIND_LOCK_HELD, cr);
			so_unlock_single(so, SOLOCKED);
			if (error) {
				mutex_exit(&so->so_lock);
				eprintsoline(so, error);
				return (error);
			}
		}
		/*
		 * Handle delayed datagram errors. These are only queued
		 * when the application sets SO_DGRAM_ERRIND.
		 * Return the error if we are sending to the address
		 * that was returned in the last T_UDERROR_IND.
		 * If sending to some other address discard the delayed
		 * error indication.
		 */
		if (sti->sti_delayed_error) {
			struct T_uderror_ind	*tudi;
			void			*addr;
			t_uscalar_t		addrlen;
			boolean_t		match = B_FALSE;

			ASSERT(sti->sti_eaddr_mp);
			error = sti->sti_delayed_error;
			sti->sti_delayed_error = 0;
			tudi =
			    (struct T_uderror_ind *)sti->sti_eaddr_mp->b_rptr;
			addrlen = tudi->DEST_length;
			addr = sogetoff(sti->sti_eaddr_mp,
			    tudi->DEST_offset, addrlen, 1);
			ASSERT(addr);	/* Checked by strsock_proto */
			switch (so->so_family) {
			case AF_INET: {
				/* Compare just IP address and port */
				sin_t *sin1 = (sin_t *)name;
				sin_t *sin2 = (sin_t *)addr;

				if (addrlen == sizeof (sin_t) &&
				    namelen == addrlen &&
				    sin1->sin_port == sin2->sin_port &&
				    sin1->sin_addr.s_addr ==
				    sin2->sin_addr.s_addr)
					match = B_TRUE;
				break;
			}
			case AF_INET6: {
				/* Compare just IP address and port. Not flow */
				sin6_t *sin1 = (sin6_t *)name;
				sin6_t *sin2 = (sin6_t *)addr;

				if (addrlen == sizeof (sin6_t) &&
				    namelen == addrlen &&
				    sin1->sin6_port == sin2->sin6_port &&
				    IN6_ARE_ADDR_EQUAL(&sin1->sin6_addr,
				    &sin2->sin6_addr))
					match = B_TRUE;
				break;
			}
			case AF_UNIX:
			default:
				if (namelen == addrlen &&
				    bcmp(name, addr, namelen) == 0)
					match = B_TRUE;
			}
			if (match) {
				freemsg(sti->sti_eaddr_mp);
				sti->sti_eaddr_mp = NULL;
				mutex_exit(&so->so_lock);
#ifdef DEBUG
				dprintso(so, 0,
				    ("sockfs delayed error %d for %s\n",
				    error,
				    pr_addr(so->so_family, name, namelen)));
#endif /* DEBUG */
				return (error);
			}
			freemsg(sti->sti_eaddr_mp);
			sti->sti_eaddr_mp = NULL;
		}
	}
	mutex_exit(&so->so_lock);

	flags = msg->msg_flags;
	dontroute = 0;
	if ((flags & MSG_DONTROUTE) && !(so->so_options & SO_DONTROUTE)) {
		uint32_t	val;

		val = 1;
		error = sotpi_setsockopt(so, SOL_SOCKET, SO_DONTROUTE,
		    &val, (t_uscalar_t)sizeof (val), cr);
		if (error)
			return (error);
		dontroute = 1;
	}

	if ((flags & MSG_OOB) && !(so_mode & SM_EXDATA)) {
		error = EOPNOTSUPP;
		goto done;
	}
	if (msg->msg_controllen != 0) {
		if (!(so_mode & SM_CONNREQUIRED)) {
			so_update_attrs(so, SOMOD);
			error = sosend_dgramcmsg(so, name, namelen, uiop,
			    msg->msg_control, msg->msg_controllen, flags);
		} else {
			if (flags & MSG_OOB) {
				/* Can't generate T_EXDATA_REQ with options */
				error = EOPNOTSUPP;
				goto done;
			}
			so_update_attrs(so, SOMOD);
			error = sosend_svccmsg(so, uiop,
			    !(flags & MSG_EOR),
			    msg->msg_control, msg->msg_controllen,
			    flags);
		}
		goto done;
	}

	so_update_attrs(so, SOMOD);
	if (!(so_mode & SM_CONNREQUIRED)) {
		/*
		 * If there is no SO_DONTROUTE to turn off return immediately
		 * from send_dgram. This can allow tail-call optimizations.
		 */
		if (!dontroute) {
			return (sosend_dgram(so, name, namelen, uiop, flags));
		}
		error = sosend_dgram(so, name, namelen, uiop, flags);
	} else {
		t_scalar_t prim;
		int sflag;

		/* Ignore msg_name in the connected state */
		if (flags & MSG_OOB) {
			prim = T_EXDATA_REQ;
			/*
			 * Send down T_EXDATA_REQ even if there is flow
			 * control for data.
			 */
			sflag = MSG_IGNFLOW;
		} else {
			if (so_mode & SM_BYTESTREAM) {
				/* Byte stream transport - use write */
				dprintso(so, 1, ("sotpi_sendmsg: write\n"));

				/* Send M_DATA messages */
				if ((sti->sti_nl7c_flags & NL7C_ENABLED) &&
				    (error = nl7c_data(so, uiop)) >= 0) {
					/* NL7C consumed the data */
					return (error);
				}
				/*
				 * If there is no SO_DONTROUTE to turn off,
				 * sti_direct is on, and there is no flow
				 * control, we can take the fast path.
				 */
				if (!dontroute && sti->sti_direct != 0 &&
				    canputnext(SOTOV(so)->v_stream->sd_wrq)) {
					return (sostream_direct(so, uiop,
					    NULL, cr));
				}
				error = strwrite(SOTOV(so), uiop, cr);
				goto done;
			}
			prim = T_DATA_REQ;
			sflag = 0;
		}
		/*
		 * If there is no SO_DONTROUTE to turn off return immediately
		 * from sosend_svc. This can allow tail-call optimizations.
		 */
		if (!dontroute)
			return (sosend_svc(so, uiop, prim,
			    !(flags & MSG_EOR), sflag));
		error = sosend_svc(so, uiop, prim,
		    !(flags & MSG_EOR), sflag);
	}
	ASSERT(dontroute);
done:
	if (dontroute) {
		uint32_t	val;

		val = 0;
		(void) sotpi_setsockopt(so, SOL_SOCKET, SO_DONTROUTE,
		    &val, (t_uscalar_t)sizeof (val), cr);
	}
	return (error);
}

/*
 * kstrwritemp() has very similar semantics as that of strwrite().
 * The main difference is it obtains mblks from the caller and also
 * does not do any copy as done in strwrite() from user buffers to
 * kernel buffers.
 *
 * Currently, this routine is used by sendfile to send data allocated
 * within the kernel without any copying. This interface does not use the
 * synchronous stream interface as synch. stream interface implies
 * copying.
 */
int
kstrwritemp(struct vnode *vp, mblk_t *mp, ushort_t fmode)
{
	struct stdata *stp;
	struct queue *wqp;
	mblk_t *newmp;
	char waitflag;
	int tempmode;
	int error = 0;
	int done = 0;
	struct sonode *so;
	boolean_t direct;

	ASSERT(vp->v_stream);
	stp = vp->v_stream;

	so = VTOSO(vp);
	direct = _SOTOTPI(so)->sti_direct;

	/*
	 * This is the sockfs direct fast path. canputnext() need
	 * not be accurate so we don't grab the sd_lock here. If
	 * we get flow-controlled, we grab sd_lock just before the
	 * do..while loop below to emulate what strwrite() does.
	 */
	wqp = stp->sd_wrq;
	if (canputnext(wqp) && direct &&
	    !(stp->sd_flag & (STWRERR|STRHUP|STPLEX))) {
		return (sostream_direct(so, NULL, mp, CRED()));
	} else if (stp->sd_flag & (STWRERR|STRHUP|STPLEX)) {
		/* Fast check of flags before acquiring the lock */
		mutex_enter(&stp->sd_lock);
		error = strgeterr(stp, STWRERR|STRHUP|STPLEX, 0);
		mutex_exit(&stp->sd_lock);
		if (error != 0) {
			if (!(stp->sd_flag & STPLEX) &&
			    (stp->sd_wput_opt & SW_SIGPIPE)) {
				error = EPIPE;
			}
			return (error);
		}
	}

	waitflag = WRITEWAIT;
	if (stp->sd_flag & OLDNDELAY)
		tempmode = fmode & ~FNDELAY;
	else
		tempmode = fmode;

	mutex_enter(&stp->sd_lock);
	do {
		if (canputnext(wqp)) {
			mutex_exit(&stp->sd_lock);
			if (stp->sd_wputdatafunc != NULL) {
				newmp = (stp->sd_wputdatafunc)(vp, mp, NULL,
				    NULL, NULL, NULL);
				if (newmp == NULL) {
					/* The caller will free mp */
					return (ECOMM);
				}
				mp = newmp;
			}
			putnext(wqp, mp);
			return (0);
		}
		error = strwaitq(stp, waitflag, (ssize_t)0, tempmode, -1,
		    &done);
	} while (error == 0 && !done);

	mutex_exit(&stp->sd_lock);
	/*
	 * EAGAIN tells the application to try again. ENOMEM
	 * is returned only if the memory allocation size
	 * exceeds the physical limits of the system. ENOMEM
	 * can't be true here.
	 */
	if (error == ENOMEM)
		error = EAGAIN;
	return (error);
}

/* ARGSUSED */
static int
sotpi_sendmblk(struct sonode *so, struct nmsghdr *msg, int fflag,
    struct cred *cr, mblk_t **mpp)
{
	int error;

	if (so->so_family != AF_INET && so->so_family != AF_INET6)
		return (EAFNOSUPPORT);

	if (so->so_state & SS_CANTSENDMORE)
		return (EPIPE);

	if (so->so_type != SOCK_STREAM)
		return (EOPNOTSUPP);

	if ((so->so_state & SS_ISCONNECTED) == 0)
		return (ENOTCONN);

	error = kstrwritemp(so->so_vnode, *mpp, fflag);
	if (error == 0)
		*mpp = NULL;
	return (error);
}

/*
 * Sending data on a datagram socket.
 * Assumes caller has verified that SS_ISBOUND etc. are set.
 */
/* ARGSUSED */
static int
sodgram_direct(struct sonode *so, struct sockaddr *name,
    socklen_t namelen, struct uio *uiop, int flags)
{
	struct T_unitdata_req	tudr;
	mblk_t			*mp = NULL;
	int			error = 0;
	void			*addr;
	socklen_t		addrlen;
	ssize_t			len;
	struct stdata		*stp = SOTOV(so)->v_stream;
	int			so_state;
	queue_t			*udp_wq;
	boolean_t		connected;
	mblk_t			*mpdata = NULL;
	sotpi_info_t		*sti = SOTOTPI(so);
	uint32_t		auditing = AU_AUDITING();

	ASSERT(name != NULL && namelen != 0);
	ASSERT(!(so->so_mode & SM_CONNREQUIRED));
	ASSERT(!(so->so_mode & SM_EXDATA));
	ASSERT(so->so_family == AF_INET || so->so_family == AF_INET6);
	ASSERT(SOTOV(so)->v_type == VSOCK);

	/* Caller checked for proper length */
	len = uiop->uio_resid;
	ASSERT(len <= sti->sti_tidu_size);

	/* Length and family checks have been done by caller */
	ASSERT(name->sa_family == so->so_family);
	ASSERT(so->so_family == AF_INET ||
	    (namelen == (socklen_t)sizeof (struct sockaddr_in6)));
	ASSERT(so->so_family == AF_INET6 ||
	    (namelen == (socklen_t)sizeof (struct sockaddr_in)));

	addr = name;
	addrlen = namelen;

	if (stp->sd_sidp != NULL &&
	    (error = straccess(stp, JCWRITE)) != 0)
		goto done;

	so_state = so->so_state;

	connected = so_state & SS_ISCONNECTED;
	if (!connected) {
		tudr.PRIM_type = T_UNITDATA_REQ;
		tudr.DEST_length = addrlen;
		tudr.DEST_offset = (t_scalar_t)sizeof (tudr);
		tudr.OPT_length = 0;
		tudr.OPT_offset = 0;

		mp = soallocproto2(&tudr, sizeof (tudr), addr, addrlen, 0,
		    _ALLOC_INTR, CRED());
		if (mp == NULL) {
			/*
			 * Caught a signal waiting for memory.
			 * Let send* return EINTR.
			 */
			error = EINTR;
			goto done;
		}
	}

	/*
	 * For UDP we don't break up the copyin into smaller pieces
	 * as in the TCP case.  That means if ENOMEM is returned by
	 * mcopyinuio() then the uio vector has not been modified at
	 * all and we fallback to either strwrite() or kstrputmsg()
	 * below.  Note also that we never generate priority messages
	 * from here.
	 */
	udp_wq = stp->sd_wrq->q_next;
	if (canput(udp_wq) &&
	    (mpdata = mcopyinuio(stp, uiop, -1, -1, &error)) != NULL) {
		ASSERT(DB_TYPE(mpdata) == M_DATA);
		ASSERT(uiop->uio_resid == 0);
		if (!connected)
			linkb(mp, mpdata);
		else
			mp = mpdata;
		if (auditing)
			audit_sock(T_UNITDATA_REQ, strvp2wq(SOTOV(so)), mp, 0);

		udp_wput(udp_wq, mp);
		return (0);
	}

	ASSERT(mpdata == NULL);
	if (error != 0 && error != ENOMEM) {
		freemsg(mp);
		return (error);
	}

	/*
	 * For connected, let strwrite() handle the blocking case.
	 * Otherwise we fall thru and use kstrputmsg().
	 */
	if (connected)
		return (strwrite(SOTOV(so), uiop, CRED()));

	if (auditing)
		audit_sock(T_UNITDATA_REQ, strvp2wq(SOTOV(so)), mp, 0);

	error = kstrputmsg(SOTOV(so), mp, uiop, len, 0, MSG_BAND, 0);
done:
#ifdef SOCK_DEBUG
	if (error != 0) {
		eprintsoline(so, error);
	}
#endif /* SOCK_DEBUG */
	return (error);
}

int
sostream_direct(struct sonode *so, struct uio *uiop, mblk_t *mp, cred_t *cr)
{
	struct stdata *stp = SOTOV(so)->v_stream;
	ssize_t iosize, rmax, maxblk;
	queue_t *tcp_wq = stp->sd_wrq->q_next;
	mblk_t *newmp;
	int error = 0, wflag = 0;

	ASSERT(so->so_mode & SM_BYTESTREAM);
	ASSERT(SOTOV(so)->v_type == VSOCK);

	if (stp->sd_sidp != NULL &&
	    (error = straccess(stp, JCWRITE)) != 0)
		return (error);

	if (uiop == NULL) {
		/*
		 * kstrwritemp() should have checked sd_flag and
		 * flow-control before coming here.  If we end up
		 * here it means that we can simply pass down the
		 * data to tcp.
		 */
		ASSERT(mp != NULL);
		if (stp->sd_wputdatafunc != NULL) {
			newmp = (stp->sd_wputdatafunc)(SOTOV(so), mp, NULL,
			    NULL, NULL, NULL);
			if (newmp == NULL) {
				/* The caller will free mp */
				return (ECOMM);
			}
			mp = newmp;
		}
		tcp_wput(tcp_wq, mp);
		return (0);
	}

	/* Fallback to strwrite() to do proper error handling */
	if (stp->sd_flag & (STWRERR|STRHUP|STPLEX|STRDELIM|OLDNDELAY))
		return (strwrite(SOTOV(so), uiop, cr));

	rmax = stp->sd_qn_maxpsz;
	ASSERT(rmax >= 0 || rmax == INFPSZ);
	if (rmax == 0 || uiop->uio_resid <= 0)
		return (0);

	if (rmax == INFPSZ)
		rmax = uiop->uio_resid;

	maxblk = stp->sd_maxblk;

	for (;;) {
		iosize = MIN(uiop->uio_resid, rmax);

		mp = mcopyinuio(stp, uiop, iosize, maxblk, &error);
		if (mp == NULL) {
			/*
			 * Fallback to strwrite() for ENOMEM; if this
			 * is our first time in this routine and the uio
			 * vector has not been modified, we will end up
			 * calling strwrite() without any flag set.
			 */
			if (error == ENOMEM)
				goto slow_send;
			else
				return (error);
		}
		ASSERT(uiop->uio_resid >= 0);
		/*
		 * If mp is non-NULL and ENOMEM is set, it means that
		 * mcopyinuio() was able to break down some of the user
		 * data into one or more mblks.  Send the partial data
		 * to tcp and let the rest be handled in strwrite().
		 */
		ASSERT(error == 0 || error == ENOMEM);
		if (stp->sd_wputdatafunc != NULL) {
			newmp = (stp->sd_wputdatafunc)(SOTOV(so), mp, NULL,
			    NULL, NULL, NULL);
			if (newmp == NULL) {
				/* The caller will free mp */
				return (ECOMM);
			}
			mp = newmp;
		}
		tcp_wput(tcp_wq, mp);

		wflag |= NOINTR;

		if (uiop->uio_resid == 0) {	/* No more data; we're done */
			ASSERT(error == 0);
			break;
		} else if (error == ENOMEM || !canput(tcp_wq) || (stp->sd_flag &
		    (STWRERR|STRHUP|STPLEX|STRDELIM|OLDNDELAY))) {
slow_send:
			/*
			 * We were able to send down partial data using
			 * the direct call interface, but are now relying
			 * on strwrite() to handle the non-fastpath cases.
			 * If the socket is blocking we will sleep in
			 * strwaitq() until write is permitted, otherwise,
			 * we will need to return the amount of bytes
			 * written so far back to the app.  This is the
			 * reason why we pass NOINTR flag to strwrite()
			 * for non-blocking socket, because we don't want
			 * to return EAGAIN when portion of the user data
			 * has actually been sent down.
			 */
			return (strwrite_common(SOTOV(so), uiop, cr, wflag));
		}
	}
	return (0);
}

/*
 * Update sti_faddr by asking the transport (unless AF_UNIX).
 */
/* ARGSUSED */
int
sotpi_getpeername(struct sonode *so, struct sockaddr *name, socklen_t *namelen,
    boolean_t accept, struct cred *cr)
{
	struct strbuf	strbuf;
	int		error = 0, res;
	void		*addr;
	t_uscalar_t	addrlen;
	k_sigset_t	smask;
	sotpi_info_t	*sti = SOTOTPI(so);

	dprintso(so, 1, ("sotpi_getpeername(%p) %s\n",
	    (void *)so, pr_state(so->so_state, so->so_mode)));

	ASSERT(*namelen > 0);
	mutex_enter(&so->so_lock);
	so_lock_single(so);	/* Set SOLOCKED */

	if (accept) {
		bcopy(sti->sti_faddr_sa, name,
		    MIN(*namelen, sti->sti_faddr_len));
		*namelen = sti->sti_faddr_noxlate ? 0: sti->sti_faddr_len;
		goto done;
	}

	if (!(so->so_state & SS_ISCONNECTED)) {
		error = ENOTCONN;
		goto done;
	}
	/* Added this check for X/Open */
	if ((so->so_state & SS_CANTSENDMORE) && !xnet_skip_checks) {
		error = EINVAL;
		if (xnet_check_print) {
			printf("sockfs: X/Open getpeername check => EINVAL\n");
		}
		goto done;
	}

	if (sti->sti_faddr_valid) {
		bcopy(sti->sti_faddr_sa, name,
		    MIN(*namelen, sti->sti_faddr_len));
		*namelen = sti->sti_faddr_noxlate ? 0: sti->sti_faddr_len;
		goto done;
	}

#ifdef DEBUG
	dprintso(so, 1, ("sotpi_getpeername (local): %s\n",
	    pr_addr(so->so_family, sti->sti_faddr_sa,
	    (t_uscalar_t)sti->sti_faddr_len)));
#endif /* DEBUG */

	if (so->so_family == AF_UNIX) {
		/* Transport has different name space - return local info */
		if (sti->sti_faddr_noxlate)
			*namelen = 0;
		error = 0;
		goto done;
	}

	ASSERT(so->so_family != AF_UNIX && sti->sti_faddr_noxlate == 0);

	ASSERT(sti->sti_faddr_sa);
	/* Allocate local buffer to use with ioctl */
	addrlen = (t_uscalar_t)sti->sti_faddr_maxlen;
	mutex_exit(&so->so_lock);
	addr = kmem_alloc(addrlen, KM_SLEEP);

	/*
	 * Issue TI_GETPEERNAME with signals masked.
	 * Put the result in sti_faddr_sa so that getpeername works after
	 * a shutdown(output).
	 * If the ioctl fails (e.g. due to a ECONNRESET) the error is reposted
	 * back to the socket.
	 */
	strbuf.buf = addr;
	strbuf.maxlen = addrlen;
	strbuf.len = 0;

	sigintr(&smask, 0);
	res = 0;
	ASSERT(cr);
	error = strioctl(SOTOV(so), TI_GETPEERNAME, (intptr_t)&strbuf,
	    0, K_TO_K, cr, &res);
	sigunintr(&smask);

	mutex_enter(&so->so_lock);
	/*
	 * If there is an error record the error in so_error put don't fail
	 * the getpeername. Instead fallback on the recorded
	 * sti->sti_faddr_sa.
	 */
	if (error) {
		/*
		 * Various stream head errors can be returned to the ioctl.
		 * However, it is impossible to determine which ones of
		 * these are really socket level errors that were incorrectly
		 * consumed by the ioctl. Thus this code silently ignores the
		 * error - to code explicitly does not reinstate the error
		 * using soseterror().
		 * Experiments have shows that at least this set of
		 * errors are reported and should not be reinstated on the
		 * socket:
		 *	EINVAL	E.g. if an I_LINK was in effect when
		 *		getpeername was called.
		 *	EPIPE	The ioctl error semantics prefer the write
		 *		side error over the read side error.
		 *	ENOTCONN The transport just got disconnected but
		 *		sockfs had not yet seen the T_DISCON_IND
		 *		when issuing the ioctl.
		 */
		error = 0;
	} else if (res == 0 && strbuf.len > 0 &&
	    (so->so_state & SS_ISCONNECTED)) {
		ASSERT(strbuf.len <= (int)sti->sti_faddr_maxlen);
		sti->sti_faddr_len = (socklen_t)strbuf.len;
		bcopy(addr, sti->sti_faddr_sa, sti->sti_faddr_len);
		sti->sti_faddr_valid = 1;

		bcopy(addr, name, MIN(*namelen, sti->sti_faddr_len));
		*namelen = sti->sti_faddr_len;
	}
	kmem_free(addr, addrlen);
#ifdef DEBUG
	dprintso(so, 1, ("sotpi_getpeername (tp): %s\n",
	    pr_addr(so->so_family, sti->sti_faddr_sa,
	    (t_uscalar_t)sti->sti_faddr_len)));
#endif /* DEBUG */
done:
	so_unlock_single(so, SOLOCKED);
	mutex_exit(&so->so_lock);
	return (error);
}

/*
 * Update sti_laddr by asking the transport (unless AF_UNIX).
 */
int
sotpi_getsockname(struct sonode *so, struct sockaddr *name, socklen_t *namelen,
    struct cred *cr)
{
	struct strbuf	strbuf;
	int		error = 0, res;
	void		*addr;
	t_uscalar_t	addrlen;
	k_sigset_t	smask;
	sotpi_info_t	*sti = SOTOTPI(so);

	dprintso(so, 1, ("sotpi_getsockname(%p) %s\n",
	    (void *)so, pr_state(so->so_state, so->so_mode)));

	ASSERT(*namelen > 0);
	mutex_enter(&so->so_lock);
	so_lock_single(so);	/* Set SOLOCKED */

#ifdef DEBUG

	dprintso(so, 1, ("sotpi_getsockname (local): %s\n",
	    pr_addr(so->so_family, sti->sti_laddr_sa,
	    (t_uscalar_t)sti->sti_laddr_len)));
#endif /* DEBUG */
	if (sti->sti_laddr_valid) {
		bcopy(sti->sti_laddr_sa, name,
		    MIN(*namelen, sti->sti_laddr_len));
		*namelen = sti->sti_laddr_len;
		goto done;
	}

	if (so->so_family == AF_UNIX) {
		/*
		 * Transport has different name space - return local info. If we
		 * have enough space, let consumers know the family.
		 */
		if (*namelen >= sizeof (sa_family_t)) {
			name->sa_family = AF_UNIX;
			*namelen = sizeof (sa_family_t);
		} else {
			*namelen = 0;
		}
		error = 0;
		goto done;
	}
	if (!(so->so_state & SS_ISBOUND)) {
		/* If not bound, then nothing to return. */
		error = 0;
		goto done;
	}

	/* Allocate local buffer to use with ioctl */
	addrlen = (t_uscalar_t)sti->sti_laddr_maxlen;
	mutex_exit(&so->so_lock);
	addr = kmem_alloc(addrlen, KM_SLEEP);

	/*
	 * Issue TI_GETMYNAME with signals masked.
	 * Put the result in sti_laddr_sa so that getsockname works after
	 * a shutdown(output).
	 * If the ioctl fails (e.g. due to a ECONNRESET) the error is reposted
	 * back to the socket.
	 */
	strbuf.buf = addr;
	strbuf.maxlen = addrlen;
	strbuf.len = 0;

	sigintr(&smask, 0);
	res = 0;
	ASSERT(cr);
	error = strioctl(SOTOV(so), TI_GETMYNAME, (intptr_t)&strbuf,
	    0, K_TO_K, cr, &res);
	sigunintr(&smask);

	mutex_enter(&so->so_lock);
	/*
	 * If there is an error record the error in so_error put don't fail
	 * the getsockname. Instead fallback on the recorded
	 * sti->sti_laddr_sa.
	 */
	if (error) {
		/*
		 * Various stream head errors can be returned to the ioctl.
		 * However, it is impossible to determine which ones of
		 * these are really socket level errors that were incorrectly
		 * consumed by the ioctl. Thus this code silently ignores the
		 * error - to code explicitly does not reinstate the error
		 * using soseterror().
		 * Experiments have shows that at least this set of
		 * errors are reported and should not be reinstated on the
		 * socket:
		 *	EINVAL	E.g. if an I_LINK was in effect when
		 *		getsockname was called.
		 *	EPIPE	The ioctl error semantics prefer the write
		 *		side error over the read side error.
		 */
		error = 0;
	} else if (res == 0 && strbuf.len > 0 &&
	    (so->so_state & SS_ISBOUND)) {
		ASSERT(strbuf.len <= (int)sti->sti_laddr_maxlen);
		sti->sti_laddr_len = (socklen_t)strbuf.len;
		bcopy(addr, sti->sti_laddr_sa, sti->sti_laddr_len);
		sti->sti_laddr_valid = 1;

		bcopy(addr, name, MIN(sti->sti_laddr_len, *namelen));
		*namelen = sti->sti_laddr_len;
	}
	kmem_free(addr, addrlen);
#ifdef DEBUG
	dprintso(so, 1, ("sotpi_getsockname (tp): %s\n",
	    pr_addr(so->so_family, sti->sti_laddr_sa,
	    (t_uscalar_t)sti->sti_laddr_len)));
#endif /* DEBUG */
done:
	so_unlock_single(so, SOLOCKED);
	mutex_exit(&so->so_lock);
	return (error);
}

/*
 * Get socket options. For SOL_SOCKET options some options are handled
 * by the sockfs while others use the value recorded in the sonode as a
 * fallback should the T_SVR4_OPTMGMT_REQ fail.
 *
 * On the return most *optlenp bytes are copied to optval.
 */
/* ARGSUSED */
int
sotpi_getsockopt(struct sonode *so, int level, int option_name,
		void *optval, socklen_t *optlenp, int flags, struct cred *cr)
{
	struct T_optmgmt_req	optmgmt_req;
	struct T_optmgmt_ack	*optmgmt_ack;
	struct opthdr		oh;
	struct opthdr		*opt_res;
	mblk_t			*mp = NULL;
	int			error = 0;
	void			*option = NULL;	/* Set if fallback value */
	t_uscalar_t		maxlen = *optlenp;
	t_uscalar_t		len;
	uint32_t		value;
	struct timeval		tmo_val; /* used for SO_RCVTIMEO, SO_SNDTIMEO */
	struct timeval32	tmo_val32;
	struct so_snd_bufinfo	snd_bufinfo;	/* used for zero copy */

	dprintso(so, 1, ("sotpi_getsockopt(%p, 0x%x, 0x%x, %p, %p) %s\n",
	    (void *)so, level, option_name, optval, (void *)optlenp,
	    pr_state(so->so_state, so->so_mode)));

	mutex_enter(&so->so_lock);
	so_lock_single(so);	/* Set SOLOCKED */

	/*
	 * Check for SOL_SOCKET options.
	 * Certain SOL_SOCKET options are returned directly whereas
	 * others only provide a default (fallback) value should
	 * the T_SVR4_OPTMGMT_REQ fail.
	 */
	if (level == SOL_SOCKET) {
		/* Check parameters */
		switch (option_name) {
		case SO_TYPE:
		case SO_ERROR:
		case SO_DEBUG:
		case SO_ACCEPTCONN:
		case SO_REUSEADDR:
		case SO_KEEPALIVE:
		case SO_DONTROUTE:
		case SO_BROADCAST:
		case SO_USELOOPBACK:
		case SO_OOBINLINE:
		case SO_SNDBUF:
		case SO_RCVBUF:
#ifdef notyet
		case SO_SNDLOWAT:
		case SO_RCVLOWAT:
#endif /* notyet */
		case SO_DOMAIN:
		case SO_DGRAM_ERRIND:
			if (maxlen < (t_uscalar_t)sizeof (int32_t)) {
				error = EINVAL;
				eprintsoline(so, error);
				goto done2;
			}
			break;
		case SO_RCVTIMEO:
		case SO_SNDTIMEO:
			if (get_udatamodel() == DATAMODEL_NONE ||
			    get_udatamodel() == DATAMODEL_NATIVE) {
				if (maxlen < sizeof (struct timeval)) {
					error = EINVAL;
					eprintsoline(so, error);
					goto done2;
				}
			} else {
				if (maxlen < sizeof (struct timeval32)) {
					error = EINVAL;
					eprintsoline(so, error);
					goto done2;
				}

			}
			break;
		case SO_LINGER:
			if (maxlen < (t_uscalar_t)sizeof (struct linger)) {
				error = EINVAL;
				eprintsoline(so, error);
				goto done2;
			}
			break;
		case SO_SND_BUFINFO:
			if (maxlen < (t_uscalar_t)
			    sizeof (struct so_snd_bufinfo)) {
				error = EINVAL;
				eprintsoline(so, error);
				goto done2;
			}
			break;
		}

		len = (t_uscalar_t)sizeof (uint32_t);	/* Default */

		switch (option_name) {
		case SO_TYPE:
			value = so->so_type;
			option = &value;
			goto copyout; /* No need to issue T_SVR4_OPTMGMT_REQ */

		case SO_ERROR:
			value = sogeterr(so, B_TRUE);
			option = &value;
			goto copyout; /* No need to issue T_SVR4_OPTMGMT_REQ */

		case SO_ACCEPTCONN:
			if (so->so_state & SS_ACCEPTCONN)
				value = SO_ACCEPTCONN;
			else
				value = 0;
#ifdef DEBUG
			if (value) {
				dprintso(so, 1,
				    ("sotpi_getsockopt: 0x%x is set\n",
				    option_name));
			} else {
				dprintso(so, 1,
				    ("sotpi_getsockopt: 0x%x not set\n",
				    option_name));
			}
#endif /* DEBUG */
			option = &value;
			goto copyout; /* No need to issue T_SVR4_OPTMGMT_REQ */

		case SO_DEBUG:
		case SO_REUSEADDR:
		case SO_KEEPALIVE:
		case SO_DONTROUTE:
		case SO_BROADCAST:
		case SO_USELOOPBACK:
		case SO_OOBINLINE:
		case SO_DGRAM_ERRIND:
			value = (so->so_options & option_name);
#ifdef DEBUG
			if (value) {
				dprintso(so, 1,
				    ("sotpi_getsockopt: 0x%x is set\n",
				    option_name));
			} else {
				dprintso(so, 1,
				    ("sotpi_getsockopt: 0x%x not set\n",
				    option_name));
			}
#endif /* DEBUG */
			option = &value;
			goto copyout; /* No need to issue T_SVR4_OPTMGMT_REQ */

		/*
		 * The following options are only returned by sockfs when the
		 * T_SVR4_OPTMGMT_REQ fails.
		 */
		case SO_LINGER:
			option = &so->so_linger;
			len = (t_uscalar_t)sizeof (struct linger);
			break;
		case SO_SNDBUF: {
			ssize_t lvalue;

			/*
			 * If the option has not been set then get a default
			 * value from the read queue. This value is
			 * returned if the transport fails
			 * the T_SVR4_OPTMGMT_REQ.
			 */
			lvalue = so->so_sndbuf;
			if (lvalue == 0) {
				mutex_exit(&so->so_lock);
				(void) strqget(strvp2wq(SOTOV(so))->q_next,
				    QHIWAT, 0, &lvalue);
				mutex_enter(&so->so_lock);
				dprintso(so, 1,
				    ("got SO_SNDBUF %ld from q\n", lvalue));
			}
			value = (int)lvalue;
			option = &value;
			len = (t_uscalar_t)sizeof (so->so_sndbuf);
			break;
		}
		case SO_RCVBUF: {
			ssize_t lvalue;

			/*
			 * If the option has not been set then get a default
			 * value from the read queue. This value is
			 * returned if the transport fails
			 * the T_SVR4_OPTMGMT_REQ.
			 *
			 * XXX If SO_RCVBUF has been set and this is an
			 * XPG 4.2 application then do not ask the transport
			 * since the transport might adjust the value and not
			 * return exactly what was set by the application.
			 * For non-XPG 4.2 application we return the value
			 * that the transport is actually using.
			 */
			lvalue = so->so_rcvbuf;
			if (lvalue == 0) {
				mutex_exit(&so->so_lock);
				(void) strqget(RD(strvp2wq(SOTOV(so))),
				    QHIWAT, 0, &lvalue);
				mutex_enter(&so->so_lock);
				dprintso(so, 1,
				    ("got SO_RCVBUF %ld from q\n", lvalue));
			} else if (flags & _SOGETSOCKOPT_XPG4_2) {
				value = (int)lvalue;
				option = &value;
				goto copyout;	/* skip asking transport */
			}
			value = (int)lvalue;
			option = &value;
			len = (t_uscalar_t)sizeof (so->so_rcvbuf);
			break;
		}
		case SO_DOMAIN:
			value = so->so_family;
			option = &value;
			goto copyout; /* No need to issue T_SVR4_OPTMGMT_REQ */

#ifdef notyet
		/*
		 * We do not implement the semantics of these options
		 * thus we shouldn't implement the options either.
		 */
		case SO_SNDLOWAT:
			value = so->so_sndlowat;
			option = &value;
			break;
		case SO_RCVLOWAT:
			value = so->so_rcvlowat;
			option = &value;
			break;
#endif /* notyet */
		case SO_SNDTIMEO:
		case SO_RCVTIMEO: {
			clock_t val;

			if (option_name == SO_RCVTIMEO)
				val = drv_hztousec(so->so_rcvtimeo);
			else
				val = drv_hztousec(so->so_sndtimeo);
			tmo_val.tv_sec = val / (1000 * 1000);
			tmo_val.tv_usec = val % (1000 * 1000);
			if (get_udatamodel() == DATAMODEL_NONE ||
			    get_udatamodel() == DATAMODEL_NATIVE) {
				option = &tmo_val;
				len = sizeof (struct timeval);
			} else {
				TIMEVAL_TO_TIMEVAL32(&tmo_val32, &tmo_val);
				option = &tmo_val32;
				len = sizeof (struct timeval32);
			}
			break;
		}
		case SO_SND_BUFINFO: {
			snd_bufinfo.sbi_wroff =
			    (so->so_proto_props).sopp_wroff;
			snd_bufinfo.sbi_maxblk =
			    (so->so_proto_props).sopp_maxblk;
			snd_bufinfo.sbi_maxpsz =
			    (so->so_proto_props).sopp_maxpsz;
			snd_bufinfo.sbi_tail =
			    (so->so_proto_props).sopp_tail;
			option = &snd_bufinfo;
			len = (t_uscalar_t)sizeof (struct so_snd_bufinfo);
			break;
		}
		}
	}

	mutex_exit(&so->so_lock);

	/* Send request */
	optmgmt_req.PRIM_type = T_SVR4_OPTMGMT_REQ;
	optmgmt_req.MGMT_flags = T_CHECK;
	optmgmt_req.OPT_length = (t_scalar_t)(sizeof (oh) + maxlen);
	optmgmt_req.OPT_offset = (t_scalar_t)sizeof (optmgmt_req);

	oh.level = level;
	oh.name = option_name;
	oh.len = maxlen;

	mp = soallocproto3(&optmgmt_req, sizeof (optmgmt_req),
	    &oh, sizeof (oh), NULL, maxlen, 0, _ALLOC_SLEEP, cr);
	/* Let option management work in the presence of data flow control */
	error = kstrputmsg(SOTOV(so), mp, NULL, 0, 0,
	    MSG_BAND|MSG_HOLDSIG|MSG_IGNERROR|MSG_IGNFLOW, 0);
	mp = NULL;
	mutex_enter(&so->so_lock);
	if (error) {
		eprintsoline(so, error);
		goto done2;
	}
	error = sowaitprim(so, T_SVR4_OPTMGMT_REQ, T_OPTMGMT_ACK,
	    (t_uscalar_t)(sizeof (*optmgmt_ack) + sizeof (*opt_res)), &mp, 0);
	if (error) {
		if (option != NULL) {
			/* We have a fallback value */
			error = 0;
			goto copyout;
		}
		eprintsoline(so, error);
		goto done2;
	}
	ASSERT(mp);
	optmgmt_ack = (struct T_optmgmt_ack *)mp->b_rptr;
	opt_res = (struct opthdr *)sogetoff(mp, optmgmt_ack->OPT_offset,
	    optmgmt_ack->OPT_length, __TPI_ALIGN_SIZE);
	if (opt_res == NULL) {
		if (option != NULL) {
			/* We have a fallback value */
			error = 0;
			goto copyout;
		}
		error = EPROTO;
		eprintsoline(so, error);
		goto done;
	}
	option = &opt_res[1];

	/* check to ensure that the option is within bounds */
	if (((uintptr_t)option + opt_res->len < (uintptr_t)option) ||
	    (uintptr_t)option + opt_res->len > (uintptr_t)mp->b_wptr) {
		if (option != NULL) {
			/* We have a fallback value */
			error = 0;
			goto copyout;
		}
		error = EPROTO;
		eprintsoline(so, error);
		goto done;
	}

	len = opt_res->len;

copyout: {
		t_uscalar_t size = MIN(len, maxlen);
		bcopy(option, optval, size);
		bcopy(&size, optlenp, sizeof (size));
	}
done:
	freemsg(mp);
done2:
	so_unlock_single(so, SOLOCKED);
	mutex_exit(&so->so_lock);

	return (error);
}

/*
 * Set socket options. All options are passed down in a T_SVR4_OPTMGMT_REQ.
 * SOL_SOCKET options are also recorded in the sonode. A setsockopt for
 * SOL_SOCKET options will not fail just because the T_SVR4_OPTMGMT_REQ fails -
 * setsockopt has to work even if the transport does not support the option.
 */
/* ARGSUSED */
int
sotpi_setsockopt(struct sonode *so, int level, int option_name,
	const void *optval, t_uscalar_t optlen, struct cred *cr)
{
	struct T_optmgmt_req	optmgmt_req;
	struct opthdr		oh;
	mblk_t			*mp;
	int			error = 0;
	boolean_t		handled = B_FALSE;

	dprintso(so, 1, ("sotpi_setsockopt(%p, 0x%x, 0x%x, %p, %d) %s\n",
	    (void *)so, level, option_name, optval, optlen,
	    pr_state(so->so_state, so->so_mode)));

	/* X/Open requires this check */
	if ((so->so_state & SS_CANTSENDMORE) && !xnet_skip_checks) {
		if (xnet_check_print)
			printf("sockfs: X/Open setsockopt check => EINVAL\n");
		return (EINVAL);
	}

	mutex_enter(&so->so_lock);
	so_lock_single(so);	/* Set SOLOCKED */
	mutex_exit(&so->so_lock);

	optmgmt_req.PRIM_type = T_SVR4_OPTMGMT_REQ;
	optmgmt_req.MGMT_flags = T_NEGOTIATE;
	optmgmt_req.OPT_length = (t_scalar_t)sizeof (oh) + optlen;
	optmgmt_req.OPT_offset = (t_scalar_t)sizeof (optmgmt_req);

	oh.level = level;
	oh.name = option_name;
	oh.len = optlen;

	mp = soallocproto3(&optmgmt_req, sizeof (optmgmt_req),
	    &oh, sizeof (oh), optval, optlen, 0, _ALLOC_SLEEP, cr);
	/* Let option management work in the presence of data flow control */
	error = kstrputmsg(SOTOV(so), mp, NULL, 0, 0,
	    MSG_BAND|MSG_HOLDSIG|MSG_IGNERROR|MSG_IGNFLOW, 0);
	mp = NULL;
	mutex_enter(&so->so_lock);
	if (error) {
		eprintsoline(so, error);
		goto done2;
	}
	error = sowaitprim(so, T_SVR4_OPTMGMT_REQ, T_OPTMGMT_ACK,
	    (t_uscalar_t)sizeof (struct T_optmgmt_ack), &mp, 0);
	if (error) {
		eprintsoline(so, error);
		goto done;
	}
	ASSERT(mp);
	/* No need to verify T_optmgmt_ack */
	freemsg(mp);
done:
	/*
	 * Check for SOL_SOCKET options and record their values.
	 * If we know about a SOL_SOCKET parameter and the transport
	 * failed it with TBADOPT or TOUTSTATE (i.e. ENOPROTOOPT or
	 * EPROTO) we let the setsockopt succeed.
	 */
	if (level == SOL_SOCKET) {
		/* Check parameters */
		switch (option_name) {
		case SO_DEBUG:
		case SO_REUSEADDR:
		case SO_KEEPALIVE:
		case SO_DONTROUTE:
		case SO_BROADCAST:
		case SO_USELOOPBACK:
		case SO_OOBINLINE:
		case SO_SNDBUF:
		case SO_RCVBUF:
#ifdef notyet
		case SO_SNDLOWAT:
		case SO_RCVLOWAT:
#endif /* notyet */
		case SO_DGRAM_ERRIND:
			if (optlen != (t_uscalar_t)sizeof (int32_t)) {
				error = EINVAL;
				eprintsoline(so, error);
				goto done2;
			}
			ASSERT(optval);
			handled = B_TRUE;
			break;
		case SO_SNDTIMEO:
		case SO_RCVTIMEO:
			if (get_udatamodel() == DATAMODEL_NONE ||
			    get_udatamodel() == DATAMODEL_NATIVE) {
				if (optlen != sizeof (struct timeval)) {
					error = EINVAL;
					eprintsoline(so, error);
					goto done2;
				}
			} else {
				if (optlen != sizeof (struct timeval32)) {
					error = EINVAL;
					eprintsoline(so, error);
					goto done2;
				}
			}
			ASSERT(optval);
			handled = B_TRUE;
			break;
		case SO_LINGER:
			if (optlen != (t_uscalar_t)sizeof (struct linger)) {
				error = EINVAL;
				eprintsoline(so, error);
				goto done2;
			}
			ASSERT(optval);
			handled = B_TRUE;
			break;
		}

#define	intvalue	(*(int32_t *)optval)

		switch (option_name) {
		case SO_TYPE:
		case SO_ERROR:
		case SO_ACCEPTCONN:
			/* Can't be set */
			error = ENOPROTOOPT;
			goto done2;
		case SO_LINGER: {
			struct linger *l = (struct linger *)optval;

			so->so_linger.l_linger = l->l_linger;
			if (l->l_onoff) {
				so->so_linger.l_onoff = SO_LINGER;
				so->so_options |= SO_LINGER;
			} else {
				so->so_linger.l_onoff = 0;
				so->so_options &= ~SO_LINGER;
			}
			break;
		}

		case SO_DEBUG:
#ifdef SOCK_TEST
			if (intvalue & 2)
				sock_test_timelimit = 10 * hz;
			else
				sock_test_timelimit = 0;

			if (intvalue & 4)
				do_useracc = 0;
			else
				do_useracc = 1;
#endif /* SOCK_TEST */
			/* FALLTHRU */
		case SO_REUSEADDR:
		case SO_KEEPALIVE:
		case SO_DONTROUTE:
		case SO_BROADCAST:
		case SO_USELOOPBACK:
		case SO_OOBINLINE:
		case SO_DGRAM_ERRIND:
			if (intvalue != 0) {
				dprintso(so, 1,
				    ("socket_setsockopt: setting 0x%x\n",
				    option_name));
				so->so_options |= option_name;
			} else {
				dprintso(so, 1,
				    ("socket_setsockopt: clearing 0x%x\n",
				    option_name));
				so->so_options &= ~option_name;
			}
			break;
		/*
		 * The following options are only returned by us when the
		 * transport layer fails.
		 * XXX XPG 4.2 applications retrieve SO_RCVBUF from sockfs
		 * since the transport might adjust the value and not
		 * return exactly what was set by the application.
		 */
		case SO_SNDBUF:
			so->so_sndbuf = intvalue;
			break;
		case SO_RCVBUF:
			so->so_rcvbuf = intvalue;
			break;
		case SO_RCVPSH:
			so->so_rcv_timer_interval = intvalue;
			break;
#ifdef notyet
		/*
		 * We do not implement the semantics of these options
		 * thus we shouldn't implement the options either.
		 */
		case SO_SNDLOWAT:
			so->so_sndlowat = intvalue;
			break;
		case SO_RCVLOWAT:
			so->so_rcvlowat = intvalue;
			break;
#endif /* notyet */
		case SO_SNDTIMEO:
		case SO_RCVTIMEO: {
			struct timeval tl;
			clock_t val;

			if (get_udatamodel() == DATAMODEL_NONE ||
			    get_udatamodel() == DATAMODEL_NATIVE)
				bcopy(&tl, (struct timeval *)optval,
				    sizeof (struct timeval));
			else
				TIMEVAL32_TO_TIMEVAL(&tl,
				    (struct timeval32 *)optval);
			val = tl.tv_sec * 1000 * 1000 + tl.tv_usec;
			if (option_name == SO_RCVTIMEO)
				so->so_rcvtimeo = drv_usectohz(val);
			else
				so->so_sndtimeo = drv_usectohz(val);
			break;
		}
		}
#undef	intvalue

		if (error) {
			if ((error == ENOPROTOOPT || error == EPROTO ||
			    error == EINVAL) && handled) {
				dprintso(so, 1,
				    ("setsockopt: ignoring error %d for 0x%x\n",
				    error, option_name));
				error = 0;
			}
		}
	}
done2:
	so_unlock_single(so, SOLOCKED);
	mutex_exit(&so->so_lock);
	return (error);
}

/*
 * sotpi_close() is called when the last open reference goes away.
 */
/* ARGSUSED */
int
sotpi_close(struct sonode *so, int flag, struct cred *cr)
{
	struct vnode *vp = SOTOV(so);
	dev_t dev;
	int error = 0;
	sotpi_info_t *sti = SOTOTPI(so);

	dprintso(so, 1, ("sotpi_close(%p, %x) %s\n",
	    (void *)vp, flag, pr_state(so->so_state, so->so_mode)));

	dev = sti->sti_dev;

	ASSERT(STREAMSTAB(getmajor(dev)));

	mutex_enter(&so->so_lock);
	so_lock_single(so);	/* Set SOLOCKED */

	ASSERT(so_verify_oobstate(so));

	if (sti->sti_nl7c_flags & NL7C_ENABLED) {
		sti->sti_nl7c_flags = 0;
		nl7c_close(so);
	}

	if (vp->v_stream != NULL) {
		vnode_t *ux_vp;

		if (so->so_family == AF_UNIX) {
			/* Could avoid this when CANTSENDMORE for !dgram */
			so_unix_close(so);
		}

		mutex_exit(&so->so_lock);
		/*
		 * Disassemble the linkage from the AF_UNIX underlying file
		 * system vnode to this socket (by atomically clearing
		 * v_stream in vn_rele_stream) before strclose clears sd_vnode
		 * and frees the stream head.
		 */
		if ((ux_vp = sti->sti_ux_bound_vp) != NULL) {
			ASSERT(ux_vp->v_stream);
			sti->sti_ux_bound_vp = NULL;
			vn_rele_stream(ux_vp);
		}
		error = strclose(vp, flag, cr);
		vp->v_stream = NULL;
		mutex_enter(&so->so_lock);
	}

	/*
	 * Flush the T_DISCON_IND on sti_discon_ind_mp.
	 */
	so_flush_discon_ind(so);

	so_unlock_single(so, SOLOCKED);
	mutex_exit(&so->so_lock);

	/*
	 * Needed for STREAMs.
	 * Decrement the device driver's reference count for streams
	 * opened via the clone dip. The driver was held in clone_open().
	 * The absence of clone_close() forces this asymmetry.
	 */
	if (so->so_flag & SOCLONE)
		ddi_rele_driver(getmajor(dev));

	return (error);
}

static int
sotpi_ioctl(struct sonode *so, int cmd, intptr_t arg, int mode,
    struct cred *cr, int32_t *rvalp)
{
	struct vnode *vp = SOTOV(so);
	sotpi_info_t *sti = SOTOTPI(so);
	int error = 0;

	dprintso(so, 0, ("sotpi_ioctl: cmd 0x%x, arg 0x%lx, state %s\n",
	    cmd, arg, pr_state(so->so_state, so->so_mode)));

	switch (cmd) {
	case SIOCSQPTR:
		/*
		 * SIOCSQPTR is valid only when helper stream is created
		 * by the protocol.
		 */
	case _I_INSERT:
	case _I_REMOVE:
		/*
		 * Since there's no compelling reason to support these ioctls
		 * on sockets, and doing so would increase the complexity
		 * markedly, prevent it.
		 */
		return (EOPNOTSUPP);

	case I_FIND:
	case I_LIST:
	case I_LOOK:
	case I_POP:
	case I_PUSH:
		/*
		 * To prevent races and inconsistencies between the actual
		 * state of the stream and the state according to the sonode,
		 * we serialize all operations which modify or operate on the
		 * list of modules on the socket's stream.
		 */
		mutex_enter(&sti->sti_plumb_lock);
		error = socktpi_plumbioctl(vp, cmd, arg, mode, cr, rvalp);
		mutex_exit(&sti->sti_plumb_lock);
		return (error);

	default:
		if (so->so_version != SOV_STREAM)
			break;

		/*
		 * The imaginary "sockmod" has been popped; act as a stream.
		 */
		return (strioctl(vp, cmd, arg, mode, U_TO_K, cr, rvalp));
	}

	ASSERT(so->so_version != SOV_STREAM);

	/*
	 * Process socket-specific ioctls.
	 */
	switch (cmd) {
	case FIONBIO: {
		int32_t value;

		if (so_copyin((void *)arg, &value, sizeof (int32_t),
		    (mode & (int)FKIOCTL)))
			return (EFAULT);

		mutex_enter(&so->so_lock);
		if (value) {
			so->so_state |= SS_NDELAY;
		} else {
			so->so_state &= ~SS_NDELAY;
		}
		mutex_exit(&so->so_lock);
		return (0);
	}

	case FIOASYNC: {
		int32_t value;

		if (so_copyin((void *)arg, &value, sizeof (int32_t),
		    (mode & (int)FKIOCTL)))
			return (EFAULT);

		mutex_enter(&so->so_lock);
		/*
		 * SS_ASYNC flag not already set correctly?
		 * (!value != !(so->so_state & SS_ASYNC))
		 * but some engineers find that too hard to read.
		 */
		if (value == 0 && (so->so_state & SS_ASYNC) != 0 ||
		    value != 0 && (so->so_state & SS_ASYNC) == 0)
			error = so_flip_async(so, vp, mode, cr);
		mutex_exit(&so->so_lock);
		return (error);
	}

	case SIOCSPGRP:
	case FIOSETOWN: {
		pid_t pgrp;

		if (so_copyin((void *)arg, &pgrp, sizeof (pid_t),
		    (mode & (int)FKIOCTL)))
			return (EFAULT);

		mutex_enter(&so->so_lock);
		dprintso(so, 1, ("setown: new %d old %d\n", pgrp, so->so_pgrp));
		/* Any change? */
		if (pgrp != so->so_pgrp)
			error = so_set_siggrp(so, vp, pgrp, mode, cr);
		mutex_exit(&so->so_lock);
		return (error);
	}
	case SIOCGPGRP:
	case FIOGETOWN:
		if (so_copyout(&so->so_pgrp, (void *)arg,
		    sizeof (pid_t), (mode & (int)FKIOCTL)))
			return (EFAULT);
		return (0);

	case SIOCATMARK: {
		int retval;
		uint_t so_state;

		/*
		 * strwaitmark has a finite timeout after which it
		 * returns -1 if the mark state is undetermined.
		 * In order to avoid any race between the mark state
		 * in sockfs and the mark state in the stream head this
		 * routine loops until the mark state can be determined
		 * (or the urgent data indication has been removed by some
		 * other thread).
		 */
		do {
			mutex_enter(&so->so_lock);
			so_state = so->so_state;
			mutex_exit(&so->so_lock);
			if (so_state & SS_RCVATMARK) {
				retval = 1;
			} else if (!(so_state & SS_OOBPEND)) {
				/*
				 * No SIGURG has been generated -- there is no
				 * pending or present urgent data. Thus can't
				 * possibly be at the mark.
				 */
				retval = 0;
			} else {
				/*
				 * Have the stream head wait until there is
				 * either some messages on the read queue, or
				 * STRATMARK or STRNOTATMARK gets set. The
				 * STRNOTATMARK flag is used so that the
				 * transport can send up a MSGNOTMARKNEXT
				 * M_DATA to indicate that it is not
				 * at the mark and additional data is not about
				 * to be send upstream.
				 *
				 * If the mark state is undetermined this will
				 * return -1 and we will loop rechecking the
				 * socket state.
				 */
				retval = strwaitmark(vp);
			}
		} while (retval == -1);

		if (so_copyout(&retval, (void *)arg, sizeof (int),
		    (mode & (int)FKIOCTL)))
			return (EFAULT);
		return (0);
	}

	case I_FDINSERT:
	case I_SENDFD:
	case I_RECVFD:
	case I_ATMARK:
	case _SIOCSOCKFALLBACK:
		/*
		 * These ioctls do not apply to sockets. I_FDINSERT can be
		 * used to send M_PROTO messages without modifying the socket
		 * state. I_SENDFD/RECVFD should not be used for socket file
		 * descriptor passing since they assume a twisted stream.
		 * SIOCATMARK must be used instead of I_ATMARK.
		 *
		 * _SIOCSOCKFALLBACK from an application should never be
		 * processed.  It is only generated by socktpi_open() or
		 * in response to I_POP or I_PUSH.
		 */
#ifdef DEBUG
		zcmn_err(getzoneid(), CE_WARN,
		    "Unsupported STREAMS ioctl 0x%x on socket. "
		    "Pid = %d\n", cmd, curproc->p_pid);
#endif /* DEBUG */
		return (EOPNOTSUPP);

	case _I_GETPEERCRED:
		if ((mode & FKIOCTL) == 0)
			return (EINVAL);

		mutex_enter(&so->so_lock);
		if ((so->so_mode & SM_CONNREQUIRED) == 0) {
			error = ENOTSUP;
		} else if ((so->so_state & SS_ISCONNECTED) == 0) {
			error = ENOTCONN;
		} else if (so->so_peercred != NULL) {
			k_peercred_t *kp = (k_peercred_t *)arg;
			kp->pc_cr = so->so_peercred;
			kp->pc_cpid = so->so_cpid;
			crhold(so->so_peercred);
		} else {
			error = EINVAL;
		}
		mutex_exit(&so->so_lock);
		return (error);

	default:
		/*
		 * Do the higher-order bits of the ioctl cmd indicate
		 * that it is an I_* streams ioctl?
		 */
		if ((cmd & 0xffffff00U) == STR &&
		    so->so_version == SOV_SOCKBSD) {
#ifdef DEBUG
			zcmn_err(getzoneid(), CE_WARN,
			    "Unsupported STREAMS ioctl 0x%x on socket. "
			    "Pid = %d\n", cmd, 	curproc->p_pid);
#endif /* DEBUG */
			return (EOPNOTSUPP);
		}
		return (strioctl(vp, cmd, arg, mode, U_TO_K, cr, rvalp));
	}
}

/*
 * Handle plumbing-related ioctls.
 */
static int
socktpi_plumbioctl(struct vnode *vp, int cmd, intptr_t arg, int mode,
    struct cred *cr, int32_t *rvalp)
{
	static const char sockmod_name[] = "sockmod";
	struct sonode	*so = VTOSO(vp);
	char		mname[FMNAMESZ + 1];
	int		error;
	sotpi_info_t	*sti = SOTOTPI(so);

	ASSERT(MUTEX_HELD(&sti->sti_plumb_lock));

	if (so->so_version == SOV_SOCKBSD)
		return (EOPNOTSUPP);

	if (so->so_version == SOV_STREAM) {
		/*
		 * The imaginary "sockmod" has been popped - act as a stream.
		 * If this is a push of sockmod then change back to a socket.
		 */
		if (cmd == I_PUSH) {
			error = ((mode & FKIOCTL) ? copystr : copyinstr)(
			    (void *)arg, mname, sizeof (mname), NULL);

			if (error == 0 && strcmp(mname, sockmod_name) == 0) {
				dprintso(so, 0, ("socktpi_ioctl: going to "
				    "socket version\n"));
				so_stream2sock(so);
				return (0);
			}
		}
		return (strioctl(vp, cmd, arg, mode, U_TO_K, cr, rvalp));
	}

	switch (cmd) {
	case I_PUSH:
		if (sti->sti_direct) {
			mutex_enter(&so->so_lock);
			so_lock_single(so);
			mutex_exit(&so->so_lock);

			error = strioctl(vp, _SIOCSOCKFALLBACK, 0, 0, K_TO_K,
			    cr, rvalp);

			mutex_enter(&so->so_lock);
			if (error == 0)
				sti->sti_direct = 0;
			so_unlock_single(so, SOLOCKED);
			mutex_exit(&so->so_lock);

			if (error != 0)
				return (error);
		}

		error = strioctl(vp, cmd, arg, mode, U_TO_K, cr, rvalp);
		if (error == 0)
			sti->sti_pushcnt++;
		return (error);

	case I_POP:
		if (sti->sti_pushcnt == 0) {
			/* Emulate sockmod being popped */
			dprintso(so, 0,
			    ("socktpi_ioctl: going to STREAMS version\n"));
			return (so_sock2stream(so));
		}

		error = strioctl(vp, cmd, arg, mode, U_TO_K, cr, rvalp);
		if (error == 0)
			sti->sti_pushcnt--;
		return (error);

	case I_LIST: {
		struct str_mlist *kmlistp, *umlistp;
		struct str_list	kstrlist;
		ssize_t		kstrlistsize;
		int		i, nmods;

		STRUCT_DECL(str_list, ustrlist);
		STRUCT_INIT(ustrlist, mode);

		if (arg == NULL) {
			error = strioctl(vp, cmd, arg, mode, U_TO_K, cr, rvalp);
			if (error == 0)
				(*rvalp)++;	/* Add one for sockmod */
			return (error);
		}

		error = so_copyin((void *)arg, STRUCT_BUF(ustrlist),
		    STRUCT_SIZE(ustrlist), mode & FKIOCTL);
		if (error != 0)
			return (error);

		nmods = STRUCT_FGET(ustrlist, sl_nmods);
		if (nmods <= 0)
			return (EINVAL);
		/*
		 * Ceiling nmods at nstrpush to prevent someone from
		 * maliciously consuming lots of kernel memory.
		 */
		nmods = MIN(nmods, nstrpush);

		kstrlistsize = (nmods + 1) * sizeof (struct str_mlist);
		kstrlist.sl_nmods = nmods;
		kstrlist.sl_modlist = kmem_zalloc(kstrlistsize, KM_SLEEP);

		error = strioctl(vp, cmd, (intptr_t)&kstrlist, mode, K_TO_K,
		    cr, rvalp);
		if (error != 0)
			goto done;

		/*
		 * Considering the module list as a 0-based array of sl_nmods
		 * modules, sockmod should conceptually exist at slot
		 * sti_pushcnt.  Insert sockmod at this location by sliding all
		 * of the module names after so_pushcnt over by one.  We know
		 * that there will be room to do this since we allocated
		 * sl_modlist with an additional slot.
		 */
		for (i = kstrlist.sl_nmods; i > sti->sti_pushcnt; i--)
			kstrlist.sl_modlist[i] = kstrlist.sl_modlist[i - 1];

		(void) strcpy(kstrlist.sl_modlist[i].l_name, sockmod_name);
		kstrlist.sl_nmods++;

		/*
		 * Copy all of the entries out to ustrlist.
		 */
		kmlistp = kstrlist.sl_modlist;
		umlistp = STRUCT_FGETP(ustrlist, sl_modlist);
		for (i = 0; i < nmods && i < kstrlist.sl_nmods; i++) {
			error = so_copyout(kmlistp++, umlistp++,
			    sizeof (struct str_mlist), mode & FKIOCTL);
			if (error != 0)
				goto done;
		}

		error = so_copyout(&i, (void *)arg, sizeof (int32_t),
		    mode & FKIOCTL);
		if (error == 0)
			*rvalp = 0;
	done:
		kmem_free(kstrlist.sl_modlist, kstrlistsize);
		return (error);
	}
	case I_LOOK:
		if (sti->sti_pushcnt == 0) {
			return (so_copyout(sockmod_name, (void *)arg,
			    sizeof (sockmod_name), mode & FKIOCTL));
		}
		return (strioctl(vp, cmd, arg, mode, U_TO_K, cr, rvalp));

	case I_FIND:
		error = strioctl(vp, cmd, arg, mode, U_TO_K, cr, rvalp);
		if (error && error != EINVAL)
			return (error);

		/* if not found and string was sockmod return 1 */
		if (*rvalp == 0 || error == EINVAL) {
			error = ((mode & FKIOCTL) ? copystr : copyinstr)(
			    (void *)arg, mname, sizeof (mname), NULL);
			if (error == ENAMETOOLONG)
				error = EINVAL;

			if (error == 0 && strcmp(mname, sockmod_name) == 0)
				*rvalp = 1;
		}
		return (error);

	default:
		panic("socktpi_plumbioctl: unknown ioctl %d", cmd);
		break;
	}

	return (0);
}

/*
 * Wrapper around the streams poll routine that implements socket poll
 * semantics.
 * The sockfs never calls pollwakeup itself - the stream head take care
 * of all pollwakeups. Since sockfs never holds so_lock when calling the
 * stream head there can never be a deadlock due to holding so_lock across
 * pollwakeup and acquiring so_lock in this routine.
 *
 * However, since the performance of VOP_POLL is critical we avoid
 * acquiring so_lock here. This is based on two assumptions:
 *  - The poll implementation holds locks to serialize the VOP_POLL call
 *    and a pollwakeup for the same pollhead. This ensures that should
 *    e.g. so_state change during a socktpi_poll call the pollwakeup
 *    (which strsock_* and strrput conspire to issue) is issued after
 *    the state change. Thus the pollwakeup will block until VOP_POLL has
 *    returned and then wake up poll and have it call VOP_POLL again.
 *  - The reading of so_state without holding so_lock does not result in
 *    stale data that is older than the latest state change that has dropped
 *    so_lock. This is ensured by the mutex_exit issuing the appropriate
 *    memory barrier to force the data into the coherency domain.
 */
static int
sotpi_poll(
	struct sonode	*so,
	short		events,
	int		anyyet,
	short		*reventsp,
	struct pollhead **phpp)
{
	short origevents = events;
	struct vnode *vp = SOTOV(so);
	int error;
	int so_state = so->so_state;	/* snapshot */
	sotpi_info_t *sti = SOTOTPI(so);

	dprintso(so, 0, ("socktpi_poll(%p): state %s err %d\n",
	    (void *)vp, pr_state(so_state, so->so_mode), so->so_error));

	ASSERT(vp->v_type == VSOCK);
	ASSERT(vp->v_stream != NULL);

	if (so->so_version == SOV_STREAM) {
		/* The imaginary "sockmod" has been popped - act as a stream */
		return (strpoll(vp->v_stream, events, anyyet,
		    reventsp, phpp));
	}

	if (!(so_state & SS_ISCONNECTED) &&
	    (so->so_mode & SM_CONNREQUIRED)) {
		/* Not connected yet - turn off write side events */
		events &= ~(POLLOUT|POLLWRBAND);
	}
	/*
	 * Check for errors without calling strpoll if the caller wants them.
	 * In sockets the errors are represented as input/output events
	 * and there is no need to ask the stream head for this information.
	 */
	if (so->so_error != 0 &&
	    ((POLLIN|POLLRDNORM|POLLOUT) & origevents)  != 0) {
		*reventsp = (POLLIN|POLLRDNORM|POLLOUT) & origevents;
		return (0);
	}
	/*
	 * Ignore M_PROTO only messages such as the T_EXDATA_IND messages.
	 * These message with only an M_PROTO/M_PCPROTO part and no M_DATA
	 * will not trigger a POLLIN event with POLLRDDATA set.
	 * The handling of urgent data (causing POLLRDBAND) is done by
	 * inspecting SS_OOBPEND below.
	 */
	events |= POLLRDDATA;

	/*
	 * After shutdown(output) a stream head write error is set.
	 * However, we should not return output events.
	 */
	events |= POLLNOERR;
	error = strpoll(vp->v_stream, events, anyyet,
	    reventsp, phpp);
	if (error)
		return (error);

	ASSERT(!(*reventsp & POLLERR));

	/*
	 * Notes on T_CONN_IND handling for sockets.
	 *
	 * If strpoll() returned without events, SR_POLLIN is guaranteed
	 * to be set, ensuring any subsequent strrput() runs pollwakeup().
	 *
	 * Since the so_lock is not held, soqueueconnind() may have run
	 * and a T_CONN_IND may be waiting. We now check for any queued
	 * T_CONN_IND msgs on sti_conn_ind_head and set appropriate events
	 * to ensure poll returns.
	 *
	 * However:
	 * If the T_CONN_IND hasn't arrived by the time strpoll() returns,
	 * when strrput() does run for an arriving M_PROTO with T_CONN_IND
	 * the following actions will occur; taken together they ensure the
	 * syscall will return.
	 *
	 * 1. If a socket, soqueueconnind() will queue the T_CONN_IND but if
	 *    the accept() was run on a non-blocking socket sowaitconnind()
	 *    may have already returned EWOULDBLOCK, so not be waiting to
	 *    process the message. Additionally socktpi_poll() has probably
	 *    proceeded past the sti_conn_ind_head check below.
	 * 2. strrput() runs pollwakeup()->pollnotify()->cv_signal() to wake
	 *    this thread,  however that could occur before poll_common()
	 *    has entered cv_wait.
	 * 3. pollnotify() sets T_POLLWAKE, while holding the pc_lock.
	 *
	 * Before proceeding to cv_wait() in poll_common() for an event,
	 * poll_common() atomically checks for T_POLLWAKE under the pc_lock,
	 * and if set, re-calls strpoll() to ensure the late arriving
	 * T_CONN_IND is recognized, and pollsys() returns.
	 */

	if (sti->sti_conn_ind_head != NULL)
		*reventsp |= (POLLIN|POLLRDNORM) & events;

	if (so->so_state & SS_CANTRCVMORE) {
		*reventsp |= POLLRDHUP & events;

		if (so->so_state & SS_CANTSENDMORE)
			*reventsp |= POLLHUP;
	}

	if (so->so_state & SS_OOBPEND)
		*reventsp |= POLLRDBAND & events;

	if (sti->sti_nl7c_rcv_mp != NULL) {
		*reventsp |= (POLLIN|POLLRDNORM) & events;
	}
	if ((sti->sti_nl7c_flags & NL7C_ENABLED) &&
	    ((POLLIN|POLLRDNORM) & *reventsp)) {
		sti->sti_nl7c_flags |= NL7C_POLLIN;
	}

	return (0);
}

/*ARGSUSED*/
static int
socktpi_constructor(void *buf, void *cdrarg, int kmflags)
{
	sotpi_sonode_t *st = (sotpi_sonode_t *)buf;
	int error = 0;

	error = sonode_constructor(buf, cdrarg, kmflags);
	if (error != 0)
		return (error);

	error = i_sotpi_info_constructor(&st->st_info);
	if (error != 0)
		sonode_destructor(buf, cdrarg);

	st->st_sonode.so_priv = &st->st_info;

	return (error);
}

/*ARGSUSED1*/
static void
socktpi_destructor(void *buf, void *cdrarg)
{
	sotpi_sonode_t *st = (sotpi_sonode_t *)buf;

	ASSERT(st->st_sonode.so_priv == &st->st_info);
	st->st_sonode.so_priv = NULL;

	i_sotpi_info_destructor(&st->st_info);
	sonode_destructor(buf, cdrarg);
}

static int
socktpi_unix_constructor(void *buf, void *cdrarg, int kmflags)
{
	int retval;

	if ((retval = socktpi_constructor(buf, cdrarg, kmflags)) == 0) {
		struct sonode *so = (struct sonode *)buf;
		sotpi_info_t *sti = SOTOTPI(so);

		mutex_enter(&socklist.sl_lock);

		sti->sti_next_so = socklist.sl_list;
		sti->sti_prev_so = NULL;
		if (sti->sti_next_so != NULL)
			SOTOTPI(sti->sti_next_so)->sti_prev_so = so;
		socklist.sl_list = so;

		mutex_exit(&socklist.sl_lock);

	}
	return (retval);
}

static void
socktpi_unix_destructor(void *buf, void *cdrarg)
{
	struct sonode	*so = (struct sonode *)buf;
	sotpi_info_t	*sti = SOTOTPI(so);

	mutex_enter(&socklist.sl_lock);

	if (sti->sti_next_so != NULL)
		SOTOTPI(sti->sti_next_so)->sti_prev_so = sti->sti_prev_so;
	if (sti->sti_prev_so != NULL)
		SOTOTPI(sti->sti_prev_so)->sti_next_so = sti->sti_next_so;
	else
		socklist.sl_list = sti->sti_next_so;

	mutex_exit(&socklist.sl_lock);

	socktpi_destructor(buf, cdrarg);
}

int
socktpi_init(void)
{
	/*
	 * Create sonode caches.  We create a special one for AF_UNIX so
	 * that we can track them for netstat(1m).
	 */
	socktpi_cache = kmem_cache_create("socktpi_cache",
	    sizeof (struct sotpi_sonode), 0, socktpi_constructor,
	    socktpi_destructor, NULL, NULL, NULL, 0);

	socktpi_unix_cache = kmem_cache_create("socktpi_unix_cache",
	    sizeof (struct sotpi_sonode), 0, socktpi_unix_constructor,
	    socktpi_unix_destructor, NULL, NULL, NULL, 0);

	return (0);
}

/*
 * Given a non-TPI sonode, allocate and prep it to be ready for TPI.
 *
 * Caller must still update state and mode using sotpi_update_state().
 */
int
sotpi_convert_sonode(struct sonode *so, struct sockparams *newsp,
    boolean_t *direct, queue_t **qp, struct cred *cr)
{
	sotpi_info_t *sti;
	struct sockparams *origsp = so->so_sockparams;
	sock_lower_handle_t handle = so->so_proto_handle;
	struct stdata *stp;
	struct vnode *vp;
	queue_t *q;
	int error = 0;

	ASSERT((so->so_state & (SS_FALLBACK_PENDING|SS_FALLBACK_COMP)) ==
	    SS_FALLBACK_PENDING);
	ASSERT(SOCK_IS_NONSTR(so));

	*qp = NULL;
	*direct = B_FALSE;
	so->so_sockparams = newsp;
	/*
	 * Allocate and initalize fields required by TPI.
	 */
	(void) sotpi_info_create(so, KM_SLEEP);
	sotpi_info_init(so);

	if ((error = sotpi_init(so, NULL, cr, SO_FALLBACK)) != 0) {
		sotpi_info_fini(so);
		sotpi_info_destroy(so);
		return (error);
	}
	ASSERT(handle == so->so_proto_handle);
	sti = SOTOTPI(so);
	if (sti->sti_direct != 0)
		*direct = B_TRUE;

	/*
	 * Keep the original sp around so we can properly dispose of the
	 * sonode when the socket is being closed.
	 */
	sti->sti_orig_sp = origsp;

	so_basic_strinit(so);	/* skips the T_CAPABILITY_REQ */
	so_alloc_addr(so, so->so_max_addr_len);

	/*
	 * If the application has done a SIOCSPGRP, make sure the
	 * STREAM head is aware. This needs to take place before
	 * the protocol start sending up messages. Otherwise we
	 * might miss to generate SIGPOLL.
	 *
	 * It is possible that the application will receive duplicate
	 * signals if some were already generated for either data or
	 * connection indications.
	 */
	if (so->so_pgrp != 0) {
		if (so_set_events(so, so->so_vnode, cr) != 0)
			so->so_pgrp = 0;
	}

	/*
	 * Determine which queue to use.
	 */
	vp = SOTOV(so);
	stp = vp->v_stream;
	ASSERT(stp != NULL);
	q = stp->sd_wrq->q_next;

	/*
	 * Skip any modules that may have been auto pushed when the device
	 * was opened
	 */
	while (q->q_next != NULL)
		q = q->q_next;
	*qp = _RD(q);

	/* This is now a STREAMS sockets */
	so->so_not_str = B_FALSE;

	return (error);
}

/*
 * Revert a TPI sonode. It is only allowed to revert the sonode during
 * the fallback process.
 */
void
sotpi_revert_sonode(struct sonode *so, struct cred *cr)
{
	vnode_t *vp = SOTOV(so);

	ASSERT((so->so_state & (SS_FALLBACK_PENDING|SS_FALLBACK_COMP)) ==
	    SS_FALLBACK_PENDING);
	ASSERT(!SOCK_IS_NONSTR(so));
	ASSERT(vp->v_stream != NULL);

	strclean(vp);
	(void) strclose(vp, FREAD|FWRITE|SO_FALLBACK, cr);

	/*
	 * Restore the original sockparams. The caller is responsible for
	 * dropping the ref to the new sp.
	 */
	so->so_sockparams = SOTOTPI(so)->sti_orig_sp;

	sotpi_info_fini(so);
	sotpi_info_destroy(so);

	/* This is no longer a STREAMS sockets */
	so->so_not_str = B_TRUE;
}

void
sotpi_update_state(struct sonode *so, struct T_capability_ack *tcap,
    struct sockaddr *laddr, socklen_t laddrlen, struct sockaddr *faddr,
    socklen_t faddrlen, short opts)
{
	sotpi_info_t *sti = SOTOTPI(so);

	so_proc_tcapability_ack(so, tcap);

	so->so_options |= opts;

	/*
	 * Determine whether the foreign and local address are valid
	 */
	if (laddrlen != 0) {
		ASSERT(laddrlen <= sti->sti_laddr_maxlen);
		sti->sti_laddr_len = laddrlen;
		bcopy(laddr, sti->sti_laddr_sa, laddrlen);
		sti->sti_laddr_valid = (so->so_state & SS_ISBOUND);
	}

	if (faddrlen != 0) {
		ASSERT(faddrlen <= sti->sti_faddr_maxlen);
		sti->sti_faddr_len = faddrlen;
		bcopy(faddr, sti->sti_faddr_sa, faddrlen);
		sti->sti_faddr_valid = (so->so_state & SS_ISCONNECTED);
	}

}

/*
 * Allocate enough space to cache the local and foreign addresses.
 */
void
so_alloc_addr(struct sonode *so, t_uscalar_t maxlen)
{
	sotpi_info_t *sti = SOTOTPI(so);

	ASSERT(sti->sti_laddr_sa == NULL && sti->sti_faddr_sa == NULL);
	ASSERT(sti->sti_laddr_len == 0 && sti->sti_faddr_len == 0);
	sti->sti_laddr_maxlen = sti->sti_faddr_maxlen =
	    P2ROUNDUP(maxlen, KMEM_ALIGN);
	so->so_max_addr_len = sti->sti_laddr_maxlen;
	sti->sti_laddr_sa = kmem_alloc(sti->sti_laddr_maxlen * 2, KM_SLEEP);
	sti->sti_faddr_sa = (struct sockaddr *)((caddr_t)sti->sti_laddr_sa
	    + sti->sti_laddr_maxlen);

	if (so->so_family == AF_UNIX) {
		/*
		 * Initialize AF_UNIX related fields.
		 */
		bzero(&sti->sti_ux_laddr, sizeof (sti->sti_ux_laddr));
		bzero(&sti->sti_ux_faddr, sizeof (sti->sti_ux_faddr));
	}
}


sotpi_info_t *
sotpi_sototpi(struct sonode *so)
{
	sotpi_info_t *sti;

	ASSERT(so != NULL);

	sti = (sotpi_info_t *)so->so_priv;

	ASSERT(sti != NULL);
	ASSERT(sti->sti_magic == SOTPI_INFO_MAGIC);

	return (sti);
}

static int
i_sotpi_info_constructor(sotpi_info_t *sti)
{
	sti->sti_magic		= SOTPI_INFO_MAGIC;
	sti->sti_ack_mp		= NULL;
	sti->sti_discon_ind_mp	= NULL;
	sti->sti_ux_bound_vp	= NULL;
	sti->sti_unbind_mp	= NULL;

	sti->sti_conn_ind_head	= NULL;
	sti->sti_conn_ind_tail	= NULL;

	sti->sti_laddr_sa	= NULL;
	sti->sti_faddr_sa	= NULL;

	sti->sti_nl7c_flags	= 0;
	sti->sti_nl7c_uri	= NULL;
	sti->sti_nl7c_rcv_mp	= NULL;

	mutex_init(&sti->sti_plumb_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&sti->sti_ack_cv, NULL, CV_DEFAULT, NULL);

	return (0);
}

static void
i_sotpi_info_destructor(sotpi_info_t *sti)
{
	ASSERT(sti->sti_magic == SOTPI_INFO_MAGIC);
	ASSERT(sti->sti_ack_mp == NULL);
	ASSERT(sti->sti_discon_ind_mp == NULL);
	ASSERT(sti->sti_ux_bound_vp == NULL);
	ASSERT(sti->sti_unbind_mp == NULL);

	ASSERT(sti->sti_conn_ind_head == NULL);
	ASSERT(sti->sti_conn_ind_tail == NULL);

	ASSERT(sti->sti_laddr_sa == NULL);
	ASSERT(sti->sti_faddr_sa == NULL);

	ASSERT(sti->sti_nl7c_flags == 0);
	ASSERT(sti->sti_nl7c_uri == NULL);
	ASSERT(sti->sti_nl7c_rcv_mp == NULL);

	mutex_destroy(&sti->sti_plumb_lock);
	cv_destroy(&sti->sti_ack_cv);
}

/*
 * Creates and attaches TPI information to the given sonode
 */
static boolean_t
sotpi_info_create(struct sonode *so, int kmflags)
{
	sotpi_info_t *sti;

	ASSERT(so->so_priv == NULL);

	if ((sti = kmem_zalloc(sizeof (*sti), kmflags)) == NULL)
		return (B_FALSE);

	if (i_sotpi_info_constructor(sti) != 0) {
		kmem_free(sti, sizeof (*sti));
		return (B_FALSE);
	}

	so->so_priv = (void *)sti;
	return (B_TRUE);
}

/*
 * Initializes the TPI information.
 */
static void
sotpi_info_init(struct sonode *so)
{
	struct vnode *vp = SOTOV(so);
	sotpi_info_t *sti = SOTOTPI(so);
	time_t now;

	sti->sti_dev 	= so->so_sockparams->sp_sdev_info.sd_vnode->v_rdev;
	vp->v_rdev	= sti->sti_dev;

	sti->sti_orig_sp = NULL;

	sti->sti_pushcnt = 0;

	now = gethrestime_sec();
	sti->sti_atime	= now;
	sti->sti_mtime	= now;
	sti->sti_ctime	= now;

	sti->sti_eaddr_mp = NULL;
	sti->sti_delayed_error = 0;

	sti->sti_provinfo = NULL;

	sti->sti_oobcnt = 0;
	sti->sti_oobsigcnt = 0;

	ASSERT(sti->sti_laddr_sa == NULL && sti->sti_faddr_sa == NULL);

	sti->sti_laddr_sa	= 0;
	sti->sti_faddr_sa	= 0;
	sti->sti_laddr_maxlen = sti->sti_faddr_maxlen = 0;
	sti->sti_laddr_len = sti->sti_faddr_len = 0;

	sti->sti_laddr_valid = 0;
	sti->sti_faddr_valid = 0;
	sti->sti_faddr_noxlate = 0;

	sti->sti_direct = 0;

	ASSERT(sti->sti_ack_mp == NULL);
	ASSERT(sti->sti_ux_bound_vp == NULL);
	ASSERT(sti->sti_unbind_mp == NULL);

	ASSERT(sti->sti_conn_ind_head == NULL);
	ASSERT(sti->sti_conn_ind_tail == NULL);
}

/*
 * Given a sonode, grab the TPI info and free any data.
 */
static void
sotpi_info_fini(struct sonode *so)
{
	sotpi_info_t *sti = SOTOTPI(so);
	mblk_t *mp;

	ASSERT(sti->sti_discon_ind_mp == NULL);

	if ((mp = sti->sti_conn_ind_head) != NULL) {
		mblk_t *mp1;

		while (mp) {
			mp1 = mp->b_next;
			mp->b_next = NULL;
			freemsg(mp);
			mp = mp1;
		}
		sti->sti_conn_ind_head = sti->sti_conn_ind_tail = NULL;
	}

	/*
	 * Protect so->so_[lf]addr_sa so that sockfs_snapshot() can safely
	 * indirect them.  It also uses so_count as a validity test.
	 */
	mutex_enter(&so->so_lock);

	if (sti->sti_laddr_sa) {
		ASSERT((caddr_t)sti->sti_faddr_sa ==
		    (caddr_t)sti->sti_laddr_sa + sti->sti_laddr_maxlen);
		ASSERT(sti->sti_faddr_maxlen == sti->sti_laddr_maxlen);
		sti->sti_laddr_valid = 0;
		sti->sti_faddr_valid = 0;
		kmem_free(sti->sti_laddr_sa, sti->sti_laddr_maxlen * 2);
		sti->sti_laddr_sa = NULL;
		sti->sti_laddr_len = sti->sti_laddr_maxlen = 0;
		sti->sti_faddr_sa = NULL;
		sti->sti_faddr_len = sti->sti_faddr_maxlen = 0;
	}

	mutex_exit(&so->so_lock);

	if ((mp = sti->sti_eaddr_mp) != NULL) {
		freemsg(mp);
		sti->sti_eaddr_mp = NULL;
		sti->sti_delayed_error = 0;
	}

	if ((mp = sti->sti_ack_mp) != NULL) {
		freemsg(mp);
		sti->sti_ack_mp = NULL;
	}

	if ((mp = sti->sti_nl7c_rcv_mp) != NULL) {
		sti->sti_nl7c_rcv_mp = NULL;
		freemsg(mp);
	}
	sti->sti_nl7c_rcv_rval = 0;
	if (sti->sti_nl7c_uri != NULL) {
		nl7c_urifree(so);
		/* urifree() cleared nl7c_uri */
	}
	if (sti->sti_nl7c_flags) {
		sti->sti_nl7c_flags = 0;
	}

	ASSERT(sti->sti_ux_bound_vp == NULL);
	if ((mp = sti->sti_unbind_mp) != NULL) {
		freemsg(mp);
		sti->sti_unbind_mp = NULL;
	}
}

/*
 * Destroys the TPI information attached to a sonode.
 */
static void
sotpi_info_destroy(struct sonode *so)
{
	sotpi_info_t *sti = SOTOTPI(so);

	i_sotpi_info_destructor(sti);
	kmem_free(sti, sizeof (*sti));

	so->so_priv = NULL;
}

/*
 * Create the global sotpi socket module entry. It will never be freed.
 */
smod_info_t *
sotpi_smod_create(void)
{
	smod_info_t *smodp;

	smodp = kmem_zalloc(sizeof (*smodp), KM_SLEEP);
	smodp->smod_name = kmem_alloc(sizeof (SOTPI_SMOD_NAME), KM_SLEEP);
	(void) strcpy(smodp->smod_name, SOTPI_SMOD_NAME);
	/*
	 * Initialize the smod_refcnt to 1 so it will never be freed.
	 */
	smodp->smod_refcnt = 1;
	smodp->smod_uc_version = SOCK_UC_VERSION;
	smodp->smod_dc_version = SOCK_DC_VERSION;
	smodp->smod_sock_create_func = &sotpi_create;
	smodp->smod_sock_destroy_func = &sotpi_destroy;
	return (smodp);
}
