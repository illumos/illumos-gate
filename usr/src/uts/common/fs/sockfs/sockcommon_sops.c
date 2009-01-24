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

#pragma ident	"@(#)sockcommon_sops.c	1.1	07/06/14 SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>

#include <sys/stropts.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#define	_SUN_TPI_VERSION	2
#include <sys/tihdr.h>
#include <sys/sockio.h>
#include <sys/sodirect.h>
#include <sys/kmem_impl.h>

#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/ddi.h>
#include <netinet/in.h>
#include <inet/ip.h>

#include <fs/sockfs/sockcommon.h>

#include <sys/socket_proto.h>

#include <fs/sockfs/socktpi_impl.h>
#include <sys/tihdr.h>
#include <fs/sockfs/nl7c.h>
#include <inet/kssl/ksslapi.h>


extern int xnet_skip_checks;
extern int xnet_check_print;

static void so_queue_oob(sock_upper_handle_t, mblk_t *, size_t);


/*ARGSUSED*/
int
so_accept_notsupp(struct sonode *lso, int fflag,
    struct cred *cr, struct sonode **nsop)
{
	return (EOPNOTSUPP);
}

/*ARGSUSED*/
int
so_listen_notsupp(struct sonode *so, int backlog, struct cred *cr)
{
	return (EOPNOTSUPP);
}

/*ARGSUSED*/
int
so_getsockname_notsupp(struct sonode *so, struct sockaddr *sa,
    socklen_t *len, struct cred *cr)
{
	return (EOPNOTSUPP);
}

/*ARGSUSED*/
int
so_getpeername_notsupp(struct sonode *so, struct sockaddr *addr,
    socklen_t *addrlen, boolean_t accept, struct cred *cr)
{
	return (EOPNOTSUPP);
}

/*ARGSUSED*/
int
so_shutdown_notsupp(struct sonode *so, int how, struct cred *cr)
{
	return (EOPNOTSUPP);
}

/*ARGSUSED*/
int
so_sendmblk_notsupp(struct sonode *so, struct msghdr *msg, int fflag,
    struct cred *cr, mblk_t **mpp)
{
	return (EOPNOTSUPP);
}

/*
 * Generic Socket Ops
 */

/* ARGSUSED */
int
so_init(struct sonode *so, struct sonode *pso, struct cred *cr, int flags)
{
	return (socket_init_common(so, pso, flags, cr));
}

int
so_bind(struct sonode *so, struct sockaddr *name, socklen_t namelen,
    int flags, struct cred *cr)
{
	int error;

	SO_BLOCK_FALLBACK(so, SOP_BIND(so, name, namelen, flags, cr));

	ASSERT(flags == _SOBIND_XPG4_2 || flags == _SOBIND_SOCKBSD);

	/* X/Open requires this check */
	if ((so->so_state & SS_CANTSENDMORE) && !xnet_skip_checks) {
		if (xnet_check_print) {
			printf("sockfs: X/Open bind state check "
			    "caused EINVAL\n");
		}
		error = EINVAL;
		goto done;
	}

	/*
	 * a bind to a NULL address is interpreted as unbind. So just
	 * do the downcall.
	 */
	if (name == NULL)
		goto dobind;

	switch (so->so_family) {
	case AF_INET:
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
#endif
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
		/* Just pass the request to the protocol */
		goto dobind;
	}

	/*
	 * First we check if either NCA or KSSL has been enabled for
	 * the requested address, and if so, we fall back to TPI.
	 * If neither of those two services are enabled, then we just
	 * pass the request to the protocol.
	 *
	 * Note that KSSL can only be enabled on a socket if NCA is NOT
	 * enabled for that socket, hence the else-statement below.
	 */
	if (nl7c_enabled && ((so->so_family == AF_INET ||
	    so->so_family == AF_INET6) &&
	    nl7c_lookup_addr(name, namelen) != NULL)) {
		/*
		 * NL7C is not supported in non-global zones,
		 * we enforce this restriction here.
		 */
		if (so->so_zoneid == GLOBAL_ZONEID) {
			/* NCA should be used, so fall back to TPI */
			error = so_tpi_fallback(so, cr);
			SO_UNBLOCK_FALLBACK(so);
			if (error)
				return (error);
			else
				return (SOP_BIND(so, name, namelen, flags, cr));
		}
	} else if (so->so_type == SOCK_STREAM) {
		/* Check if KSSL has been configured for this address */
		kssl_ent_t ent;
		kssl_endpt_type_t type;
		struct T_bind_req bind_req;
		mblk_t *mp;

		/*
		 * TODO: Check with KSSL team if we could add a function call
		 * that only queries whether KSSL is enabled for the given
		 * address.
		 */
		bind_req.PRIM_type = T_BIND_REQ;
		bind_req.ADDR_length = namelen;
		bind_req.ADDR_offset = (t_scalar_t)sizeof (bind_req);
		mp = soallocproto2(&bind_req, sizeof (bind_req),
		    name, namelen, 0, _ALLOC_SLEEP);

		type = kssl_check_proxy(mp, so, &ent);
		freemsg(mp);

		if (type != KSSL_NO_PROXY) {
			/*
			 * KSSL has been configured for this address, so
			 * we must fall back to TPI.
			 */
			kssl_release_ent(ent, so, type);
			error = so_tpi_fallback(so, cr);
			SO_UNBLOCK_FALLBACK(so);
			if (error)
				return (error);
			else
				return (SOP_BIND(so, name, namelen, flags, cr));
		}
	}

dobind:
	error = (*so->so_downcalls->sd_bind)
	    (so->so_proto_handle, name, namelen, cr);
done:
	SO_UNBLOCK_FALLBACK(so);

	return (error);
}

int
so_listen(struct sonode *so, int backlog, struct cred *cr)
{
	int	error = 0;

	ASSERT(MUTEX_NOT_HELD(&so->so_lock));
	SO_BLOCK_FALLBACK(so, SOP_LISTEN(so, backlog, cr));

	error = (*so->so_downcalls->sd_listen)(so->so_proto_handle, backlog,
	    cr);

	SO_UNBLOCK_FALLBACK(so);

	return (error);
}


int
so_connect(struct sonode *so, const struct sockaddr *name,
    socklen_t namelen, int fflag, int flags, struct cred *cr)
{
	int error = 0;
	sock_connid_t id;

	ASSERT(MUTEX_NOT_HELD(&so->so_lock));
	SO_BLOCK_FALLBACK(so, SOP_CONNECT(so, name, namelen, fflag, flags, cr));

	/*
	 * If there is a pending error, return error
	 * This can happen if a non blocking operation caused an error.
	 */

	if (so->so_error != 0) {
		mutex_enter(&so->so_lock);
		error = sogeterr(so, B_TRUE);
		mutex_exit(&so->so_lock);
		if (error != 0)
			goto done;
	}

	error = (*so->so_downcalls->sd_connect)(so->so_proto_handle,
	    name, namelen, &id, cr);

	if (error == EINPROGRESS)
		error = so_wait_connected(so, fflag & (FNONBLOCK|FNDELAY), id);

done:
	SO_UNBLOCK_FALLBACK(so);
	return (error);
}

/*ARGSUSED*/
int
so_accept(struct sonode *so, int fflag, struct cred *cr, struct sonode **nsop)
{
	int error = 0;
	struct sonode *nso;

	*nsop = NULL;

	SO_BLOCK_FALLBACK(so, SOP_ACCEPT(so, fflag, cr, nsop));
	if ((so->so_state & SS_ACCEPTCONN) == 0) {
		SO_UNBLOCK_FALLBACK(so);
		return ((so->so_type == SOCK_DGRAM || so->so_type == SOCK_RAW) ?
		    EOPNOTSUPP : EINVAL);
	}

	if ((error = so_acceptq_dequeue(so, (fflag & (FNONBLOCK|FNDELAY)),
	    &nso)) == 0) {
		ASSERT(nso != NULL);

		/* finish the accept */
		error = (*so->so_downcalls->sd_accept)(so->so_proto_handle,
		    nso->so_proto_handle, (sock_upper_handle_t)nso, cr);
		if (error != 0) {
			(void) socket_close(nso, 0, cr);
			socket_destroy(nso);
		} else {
			*nsop = nso;
		}
	}

	SO_UNBLOCK_FALLBACK(so);
	return (error);
}

int
so_sendmsg(struct sonode *so, struct nmsghdr *msg, struct uio *uiop,
    struct cred *cr)
{
	int error, flags;
	boolean_t dontblock;
	ssize_t orig_resid;
	mblk_t  *mp;

	SO_BLOCK_FALLBACK(so, SOP_SENDMSG(so, msg, uiop, cr));

	flags = msg->msg_flags;
	error = 0;
	dontblock = (flags & MSG_DONTWAIT) ||
	    (uiop->uio_fmode & (FNONBLOCK|FNDELAY));

	if (!(flags & MSG_XPG4_2) && msg->msg_controllen != 0) {
		/*
		 * Old way of passing fd's is not supported
		 */
		SO_UNBLOCK_FALLBACK(so);
		return (EOPNOTSUPP);
	}

	if ((so->so_mode & SM_ATOMIC) &&
	    uiop->uio_resid > so->so_proto_props.sopp_maxpsz &&
	    so->so_proto_props.sopp_maxpsz != -1) {
		SO_UNBLOCK_FALLBACK(so);
		return (EMSGSIZE);
	}

	/*
	 * For atomic sends we will only do one iteration.
	 */
	do {
		if (so->so_state & SS_CANTSENDMORE) {
			error = EPIPE;
			break;
		}

		if (so->so_error != 0) {
			mutex_enter(&so->so_lock);
			error = sogeterr(so, B_TRUE);
			mutex_exit(&so->so_lock);
			if (error != 0)
				break;
		}

		/*
		 * Send down OOB messages even if the send path is being
		 * flow controlled (assuming the protocol supports OOB data).
		 */
		if (flags & MSG_OOB) {
			if ((so->so_mode & SM_EXDATA) == 0) {
				error = EOPNOTSUPP;
				break;
			}
		} else if (so->so_snd_qfull) {
			/*
			 * Need to wait until the protocol is ready to receive
			 * more data for transmission.
			 */
			if ((error = so_snd_wait_qnotfull(so, dontblock)) != 0)
				break;
		}

		/*
		 * Time to send data to the protocol. We either copy the
		 * data into mblks or pass the uio directly to the protocol.
		 * We decide what to do based on the available down calls.
		 */
		if (so->so_downcalls->sd_send_uio != NULL) {
			error = (*so->so_downcalls->sd_send_uio)
			    (so->so_proto_handle, uiop, msg, cr);
			if (error != 0)
				break;
		} else {
			/* save the resid in case of failure */
			orig_resid = uiop->uio_resid;

			if ((mp = socopyinuio(uiop,
			    so->so_proto_props.sopp_maxpsz,
			    so->so_proto_props.sopp_wroff,
			    so->so_proto_props.sopp_maxblk,
			    so->so_proto_props.sopp_tail, &error)) == NULL) {
				break;
			}
			ASSERT(uiop->uio_resid >= 0);

			error = (*so->so_downcalls->sd_send)
			    (so->so_proto_handle, mp, msg, cr);
			if (error != 0) {
				/*
				 * The send failed. We do not have to free the
				 * mblks, because that is the protocol's
				 * responsibility. However, uio_resid must
				 * remain accurate, so adjust that here.
				 */
				uiop->uio_resid = orig_resid;
					break;
			}
		}
	} while (uiop->uio_resid > 0);

	SO_UNBLOCK_FALLBACK(so);

	return (error);
}

int
so_sendmblk(struct sonode *so, struct nmsghdr *msg, int fflag,
    struct cred *cr, mblk_t **mpp)
{
	int error;
	boolean_t dontblock;
	size_t size;
	mblk_t *mp = *mpp;

	SO_BLOCK_FALLBACK(so, SOP_SENDMBLK(so, msg, fflag, cr, mpp));

	error = 0;
	dontblock = (msg->msg_flags & MSG_DONTWAIT) ||
	    (fflag & (FNONBLOCK|FNDELAY));
	size = msgdsize(mp);

	if ((so->so_mode & SM_SENDFILESUPP) == 0 ||
	    so->so_downcalls->sd_send == NULL) {
		SO_UNBLOCK_FALLBACK(so);
		return (EOPNOTSUPP);
	}

	if ((so->so_mode & SM_ATOMIC) &&
	    size > so->so_proto_props.sopp_maxpsz &&
	    so->so_proto_props.sopp_maxpsz != -1) {
		SO_UNBLOCK_FALLBACK(so);
		return (EMSGSIZE);
	}

	while (mp != NULL) {
		mblk_t *nmp, *last_mblk;
		size_t mlen;

		if (so->so_state & SS_CANTSENDMORE) {
			error = EPIPE;
			break;
		}
		if (so->so_error != 0) {
			mutex_enter(&so->so_lock);
			error = sogeterr(so, B_TRUE);
			mutex_exit(&so->so_lock);
			if (error != 0)
				break;
		}
		if (so->so_snd_qfull) {
			/*
			 * Need to wait until the protocol is ready to receive
			 * more data for transmission.
			 */
			if ((error = so_snd_wait_qnotfull(so, dontblock)) != 0)
				break;
		}

		/*
		 * We only allow so_maxpsz of data to be sent down to
		 * the protocol at time.
		 */
		mlen = MBLKL(mp);
		nmp = mp->b_cont;
		last_mblk = mp;
		while (nmp != NULL) {
			mlen += MBLKL(nmp);
			if (mlen > so->so_proto_props.sopp_maxpsz) {
				last_mblk->b_cont = NULL;
				break;
			}
			last_mblk = nmp;
			nmp = nmp->b_cont;
		}

		error = (*so->so_downcalls->sd_send)
		    (so->so_proto_handle, mp, msg, cr);
		if (error != 0) {
			/*
			 * The send failed. The protocol will free the mblks
			 * that were sent down. Let the caller deal with the
			 * rest.
			 */
			*mpp = nmp;
			break;
		}

		*mpp = mp = nmp;
	}

	SO_UNBLOCK_FALLBACK(so);

	return (error);
}

int
so_shutdown(struct sonode *so, int how, struct cred *cr)
{
	int error;

	SO_BLOCK_FALLBACK(so, SOP_SHUTDOWN(so, how, cr));

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

	error = ((*so->so_downcalls->sd_shutdown)(so->so_proto_handle,
	    how, cr));

	/*
	 * Protocol agreed to shutdown. We need to flush the
	 * receive buffer if the receive side is being shutdown.
	 */
	if (error == 0 && how != SHUT_WR) {
		mutex_enter(&so->so_lock);
		/* wait for active reader to finish */
		(void) so_lock_read(so, 0);

		so_rcv_flush(so);

		so_unlock_read(so);
		mutex_exit(&so->so_lock);
	}

done:
	SO_UNBLOCK_FALLBACK(so);
	return (error);
}

int
so_getsockname(struct sonode *so, struct sockaddr *addr,
    socklen_t *addrlen, struct cred *cr)
{
	int error;

	SO_BLOCK_FALLBACK(so, SOP_GETSOCKNAME(so, addr, addrlen, cr));

	error = (*so->so_downcalls->sd_getsockname)
	    (so->so_proto_handle, addr, addrlen, cr);

	SO_UNBLOCK_FALLBACK(so);
	return (error);
}

int
so_getpeername(struct sonode *so, struct sockaddr *addr,
    socklen_t *addrlen, boolean_t accept, struct cred *cr)
{
	int error;

	SO_BLOCK_FALLBACK(so, SOP_GETPEERNAME(so, addr, addrlen, accept, cr));

	if (accept) {
		error = (*so->so_downcalls->sd_getpeername)
		    (so->so_proto_handle, addr, addrlen, cr);
	} else if (!(so->so_state & SS_ISCONNECTED)) {
		error = ENOTCONN;
	} else if ((so->so_state & SS_CANTSENDMORE) && !xnet_skip_checks) {
		/* Added this check for X/Open */
		error = EINVAL;
		if (xnet_check_print) {
			printf("sockfs: X/Open getpeername check => EINVAL\n");
		}
	} else {
		error = (*so->so_downcalls->sd_getpeername)
		    (so->so_proto_handle, addr, addrlen, cr);
	}

	SO_UNBLOCK_FALLBACK(so);
	return (error);
}

int
so_getsockopt(struct sonode *so, int level, int option_name,
    void *optval, socklen_t *optlenp, int flags, struct cred *cr)
{
	int error = 0;

	ASSERT(MUTEX_NOT_HELD(&so->so_lock));
	SO_BLOCK_FALLBACK(so,
	    SOP_GETSOCKOPT(so, level, option_name, optval, optlenp, flags, cr));

	error = socket_getopt_common(so, level, option_name, optval, optlenp,
	    flags);
	if (error < 0) {
		error = (*so->so_downcalls->sd_getsockopt)
		    (so->so_proto_handle, level, option_name, optval, optlenp,
		    cr);
		if (error ==  ENOPROTOOPT) {
			if (level == SOL_SOCKET) {
				/*
				 * If a protocol does not support a particular
				 * socket option, set can fail (not allowed)
				 * but get can not fail. This is the previous
				 * sockfs bahvior.
				 */
				switch (option_name) {
				case SO_LINGER:
					if (*optlenp < (t_uscalar_t)
					    sizeof (struct linger)) {
						error = EINVAL;
						break;
					}
					error = 0;
					bzero(optval, sizeof (struct linger));
					*optlenp = sizeof (struct linger);
					break;
				case SO_RCVTIMEO:
				case SO_SNDTIMEO:
					if (*optlenp < (t_uscalar_t)
					    sizeof (struct timeval)) {
						error = EINVAL;
						break;
					}
					error = 0;
					bzero(optval, sizeof (struct timeval));
					*optlenp = sizeof (struct timeval);
					break;
				case SO_SND_BUFINFO:
					if (*optlenp < (t_uscalar_t)
					    sizeof (struct so_snd_bufinfo)) {
						error = EINVAL;
						break;
					}
					error = 0;
					bzero(optval,
					    sizeof (struct so_snd_bufinfo));
					*optlenp =
					    sizeof (struct so_snd_bufinfo);
					break;
				case SO_DEBUG:
				case SO_REUSEADDR:
				case SO_KEEPALIVE:
				case SO_DONTROUTE:
				case SO_BROADCAST:
				case SO_USELOOPBACK:
				case SO_OOBINLINE:
				case SO_DGRAM_ERRIND:
				case SO_SNDBUF:
				case SO_RCVBUF:
					error = 0;
					*((int32_t *)optval) = 0;
					*optlenp = sizeof (int32_t);
					break;
				default:
					break;
				}
			}
		}
	}

	SO_UNBLOCK_FALLBACK(so);
	return (error);
}

int
so_setsockopt(struct sonode *so, int level, int option_name,
    const void *optval, socklen_t optlen, struct cred *cr)
{
	int error = 0;
	struct timeval tl;
	const void *opt = optval;

	SO_BLOCK_FALLBACK(so,
	    SOP_SETSOCKOPT(so, level, option_name, optval, optlen, cr));

	/* X/Open requires this check */
	if (so->so_state & SS_CANTSENDMORE && !xnet_skip_checks) {
		SO_UNBLOCK_FALLBACK(so);
		if (xnet_check_print)
			printf("sockfs: X/Open setsockopt check => EINVAL\n");
		return (EINVAL);
	}

	if (level == SOL_SOCKET) {
		switch (option_name) {
		case SO_RCVTIMEO:
		case SO_SNDTIMEO: {
			/*
			 * We pass down these two options to protocol in order
			 * to support some third part protocols which need to
			 * know them. For those protocols which don't care
			 * these two options, simply return 0.
			 */
			clock_t t_usec;

			if (get_udatamodel() == DATAMODEL_NONE ||
			    get_udatamodel() == DATAMODEL_NATIVE) {
				if (optlen != sizeof (struct timeval)) {
					error = EINVAL;
					goto done;
				}
				bcopy((struct timeval *)optval, &tl,
				    sizeof (struct timeval));
			} else {
				if (optlen != sizeof (struct timeval32)) {
					error = EINVAL;
					goto done;
				}
				TIMEVAL32_TO_TIMEVAL(&tl,
				    (struct timeval32 *)optval);
			}
			opt = &tl;
			optlen = sizeof (tl);
			t_usec = tl.tv_sec * 1000 * 1000 + tl.tv_usec;
			mutex_enter(&so->so_lock);
			if (option_name == SO_RCVTIMEO)
				so->so_rcvtimeo = drv_usectohz(t_usec);
			else
				so->so_sndtimeo = drv_usectohz(t_usec);
			mutex_exit(&so->so_lock);
			break;
		}
		case SO_RCVBUF:
			/*
			 * XXX XPG 4.2 applications retrieve SO_RCVBUF from
			 * sockfs since the transport might adjust the value
			 * and not return exactly what was set by the
			 * application.
			 */
			so->so_xpg_rcvbuf = *(int32_t *)optval;
			break;
		}
	}
	error = (*so->so_downcalls->sd_setsockopt)
	    (so->so_proto_handle, level, option_name, opt, optlen, cr);
done:
	SO_UNBLOCK_FALLBACK(so);
	return (error);
}

int
so_ioctl(struct sonode *so, int cmd, intptr_t arg, int mode,
    struct cred *cr, int32_t *rvalp)
{
	int error = 0;

	SO_BLOCK_FALLBACK(so, SOP_IOCTL(so, cmd, arg, mode, cr, rvalp));

	/*
	 * If there is a pending error, return error
	 * This can happen if a non blocking operation caused an error.
	 */
	if (so->so_error != 0) {
		mutex_enter(&so->so_lock);
		error = sogeterr(so, B_TRUE);
		mutex_exit(&so->so_lock);
		if (error != 0)
			goto done;
	}

	/*
	 * calling strioc can result in the socket falling back to TPI,
	 * if that is supported.
	 */
	if ((error = socket_ioctl_common(so, cmd, arg, mode, cr, rvalp)) < 0 &&
	    (error = socket_strioc_common(so, cmd, arg, mode, cr, rvalp)) < 0) {
		error = (*so->so_downcalls->sd_ioctl)(so->so_proto_handle,
		    cmd, arg, mode, rvalp, cr);
	}

done:
	SO_UNBLOCK_FALLBACK(so);

	return (error);
}

int
so_poll(struct sonode *so, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	int state = so->so_state;
	*reventsp = 0;

	if (so->so_error != 0 &&
	    ((POLLIN|POLLRDNORM|POLLOUT) & events)  != 0) {
		*reventsp = (POLLIN|POLLRDNORM|POLLOUT) & events;
		return (0);
	}

	/*
	 * As long as there is buffer to send data, and the socket is
	 * in a state where it can send data (i.e., connected for
	 * connection oriented protocols), then turn on POLLOUT events
	 */
	if (!so->so_snd_qfull && ((so->so_mode & SM_CONNREQUIRED) == 0 ||
	    state & SS_ISCONNECTED)) {
		*reventsp |= POLLOUT & events;
	}

	/*
	 * Turn on POLLIN whenever there is data on the receive queue,
	 * or the socket is in a state where no more data will be received.
	 * Also, if the socket is accepting connections, flip the bit if
	 * there is something on the queue.
	 *
	 * We do an initial check for events without holding locks. However,
	 * if there are no event available, then we redo the check for POLLIN
	 * events under the lock.
	 */

	/* Pending connections */
	if (so->so_acceptq_len > 0)
		*reventsp |= (POLLIN|POLLRDNORM) & events;

	/* Data */
	/* so_downcalls is null for sctp */
	if (so->so_downcalls != NULL && so->so_downcalls->sd_poll != NULL) {
		*reventsp |= (*so->so_downcalls->sd_poll)
		    (so->so_proto_handle, events & SO_PROTO_POLLEV, anyyet,
		    CRED()) & events;
		ASSERT((*reventsp & ~events) == 0);
		/* do not recheck events */
		events &= ~SO_PROTO_POLLEV;
	} else {
		if (SO_HAVE_DATA(so))
			*reventsp |= (POLLIN|POLLRDNORM) & events;

		/* Urgent data */
		if ((state & SS_OOBPEND) != 0)
			*reventsp |= (POLLRDBAND) & events;
	}

	if (!*reventsp && !anyyet) {
		/* Check for read events again, but this time under lock */
		if (events & (POLLIN|POLLRDNORM)) {
			mutex_enter(&so->so_lock);
			if (SO_HAVE_DATA(so) || so->so_acceptq_len > 0) {
				mutex_exit(&so->so_lock);
				*reventsp |= (POLLIN|POLLRDNORM) & events;
				return (0);
			} else {
				so->so_pollev |= SO_POLLEV_IN;
				mutex_exit(&so->so_lock);
			}
		}
		*phpp = &so->so_poll_list;
	}
	return (0);
}

/*
 * Generic Upcalls
 */
void
so_connected(sock_upper_handle_t sock_handle, sock_connid_t id,
    cred_t *peer_cred, pid_t peer_cpid)
{
	struct sonode *so = (struct sonode *)sock_handle;

	mutex_enter(&so->so_lock);
	ASSERT(so->so_proto_handle != NULL);

	if (peer_cred != NULL) {
		if (so->so_peercred != NULL)
			crfree(so->so_peercred);
		crhold(peer_cred);
		so->so_peercred = peer_cred;
		so->so_cpid = peer_cpid;
	}

	so->so_proto_connid = id;
	soisconnected(so);
	/*
	 * Wake ones who're waiting for conn to become established.
	 */
	so_notify_connected(so);
}

int
so_disconnected(sock_upper_handle_t sock_handle, sock_connid_t id, int error)
{
	struct sonode *so = (struct sonode *)sock_handle;

	mutex_enter(&so->so_lock);

	so->so_proto_connid = id;
	soisdisconnected(so, error);
	so_notify_disconnected(so, error);

	return (0);
}

void
so_opctl(sock_upper_handle_t sock_handle, sock_opctl_action_t action,
    uintptr_t arg)
{
	struct sonode *so = (struct sonode *)sock_handle;

	switch (action) {
	case SOCK_OPCTL_SHUT_SEND:
		mutex_enter(&so->so_lock);
		socantsendmore(so);
		so_notify_disconnecting(so);
		break;
	case SOCK_OPCTL_SHUT_RECV: {
		mutex_enter(&so->so_lock);
		socantrcvmore(so);
		so_notify_eof(so);
		break;
	}
	case SOCK_OPCTL_ENAB_ACCEPT:
		mutex_enter(&so->so_lock);
		so->so_state |= SS_ACCEPTCONN;
		so->so_backlog = (unsigned int)arg;
		mutex_exit(&so->so_lock);
		break;
	default:
		ASSERT(0);
		break;
	}
}

void
so_txq_full(sock_upper_handle_t sock_handle, boolean_t qfull)
{
	struct sonode *so = (struct sonode *)sock_handle;

	if (qfull) {
		so_snd_qfull(so);
	} else {
		so_snd_qnotfull(so);
		mutex_enter(&so->so_lock);
		so_notify_writable(so);
	}
}

sock_upper_handle_t
so_newconn(sock_upper_handle_t parenthandle,
    sock_lower_handle_t proto_handle, sock_downcalls_t *sock_downcalls,
    struct cred *peer_cred, pid_t peer_cpid, sock_upcalls_t **sock_upcallsp)
{
	struct sonode	*so = (struct sonode *)parenthandle;
	struct sonode	*nso;
	int error;

	ASSERT(proto_handle != NULL);

	if ((so->so_state & SS_ACCEPTCONN) == 0 ||
	    so->so_acceptq_len >= so->so_backlog)
		return (NULL);

	nso = socket_newconn(so, proto_handle, sock_downcalls, SOCKET_NOSLEEP,
	    &error);
	if (nso == NULL)
		return (NULL);

	if (peer_cred != NULL) {
		crhold(peer_cred);
		nso->so_peercred = peer_cred;
		nso->so_cpid = peer_cpid;
	}

	(void) so_acceptq_enqueue(so, nso);
	mutex_enter(&so->so_lock);
	so_notify_newconn(so);

	*sock_upcallsp = &so_upcalls;

	return ((sock_upper_handle_t)nso);
}

void
so_set_prop(sock_upper_handle_t sock_handle, struct sock_proto_props *soppp)
{
	struct sonode *so;

	so = (struct sonode *)sock_handle;

	mutex_enter(&so->so_lock);

	if (soppp->sopp_flags & SOCKOPT_MAXBLK)
		so->so_proto_props.sopp_maxblk = soppp->sopp_maxblk;
	if (soppp->sopp_flags & SOCKOPT_WROFF)
		so->so_proto_props.sopp_wroff = soppp->sopp_wroff;
	if (soppp->sopp_flags & SOCKOPT_TAIL)
		so->so_proto_props.sopp_tail = soppp->sopp_tail;
	if (soppp->sopp_flags & SOCKOPT_RCVHIWAT)
		so->so_proto_props.sopp_rxhiwat = soppp->sopp_rxhiwat;
	if (soppp->sopp_flags & SOCKOPT_RCVLOWAT)
		so->so_proto_props.sopp_rxlowat = soppp->sopp_rxlowat;
	if (soppp->sopp_flags & SOCKOPT_MAXPSZ)
		so->so_proto_props.sopp_maxpsz = soppp->sopp_maxpsz;
	if (soppp->sopp_flags & SOCKOPT_MINPSZ)
		so->so_proto_props.sopp_minpsz = soppp->sopp_minpsz;
	if (soppp->sopp_flags & SOCKOPT_ZCOPY) {
		if (soppp->sopp_zcopyflag & ZCVMSAFE) {
			so->so_proto_props.sopp_zcopyflag |= STZCVMSAFE;
			so->so_proto_props.sopp_zcopyflag &= ~STZCVMUNSAFE;
		} else if (soppp->sopp_zcopyflag & ZCVMUNSAFE) {
			so->so_proto_props.sopp_zcopyflag |= STZCVMUNSAFE;
			so->so_proto_props.sopp_zcopyflag &= ~STZCVMSAFE;
		}

		if (soppp->sopp_zcopyflag & COPYCACHED) {
			so->so_proto_props.sopp_zcopyflag |= STRCOPYCACHED;
		}
	}
	if (soppp->sopp_flags & SOCKOPT_OOBINLINE)
		so->so_proto_props.sopp_oobinline = soppp->sopp_oobinline;
	if (soppp->sopp_flags & SOCKOPT_RCVTIMER)
		so->so_proto_props.sopp_rcvtimer = soppp->sopp_rcvtimer;
	if (soppp->sopp_flags & SOCKOPT_RCVTHRESH)
		so->so_proto_props.sopp_rcvthresh = soppp->sopp_rcvthresh;
	if (soppp->sopp_flags & SOCKOPT_MAXADDRLEN)
		so->so_proto_props.sopp_maxaddrlen = soppp->sopp_maxaddrlen;

	mutex_exit(&so->so_lock);

#ifdef DEBUG
	soppp->sopp_flags &= ~(SOCKOPT_MAXBLK | SOCKOPT_WROFF | SOCKOPT_TAIL |
	    SOCKOPT_RCVHIWAT | SOCKOPT_RCVLOWAT | SOCKOPT_MAXPSZ |
	    SOCKOPT_ZCOPY | SOCKOPT_OOBINLINE | SOCKOPT_RCVTIMER |
	    SOCKOPT_RCVTHRESH | SOCKOPT_MAXADDRLEN | SOCKOPT_MINPSZ);
	ASSERT(soppp->sopp_flags == 0);
#endif
}

/* ARGSUSED */
ssize_t
so_queue_msg(sock_upper_handle_t sock_handle, mblk_t *mp,
    size_t msg_size, int flags, int *errorp,  boolean_t *force_pushp)
{
	struct sonode *so = (struct sonode *)sock_handle;
	boolean_t force_push = B_TRUE;
	int space_left;
	sodirect_t *sodp = so->so_direct;

	ASSERT(errorp != NULL);
	*errorp = 0;
	if (mp == NULL) {
		if (msg_size > 0) {
			ASSERT(so->so_downcalls->sd_recv_uio != NULL);
			mutex_enter(&so->so_lock);
			/* the notify functions will drop the lock */
			if (flags & MSG_OOB)
				so_notify_oobdata(so, IS_SO_OOB_INLINE(so));
			else
				so_notify_data(so, msg_size);
			return (0);
		}
		/*
		 * recv space check
		 */
		mutex_enter(&so->so_lock);
		space_left = so->so_rcvbuf - so->so_rcv_queued;
		if (space_left <= 0) {
			so->so_flowctrld = B_TRUE;
			*errorp = ENOSPC;
			space_left = -1;
		}
		goto done_unlock;
	}

	ASSERT(mp->b_next == NULL);
	ASSERT(DB_TYPE(mp) == M_DATA || DB_TYPE(mp) == M_PROTO);
	ASSERT(msg_size == msgdsize(mp));

	if (flags & MSG_OOB) {
		so_queue_oob(sock_handle, mp, msg_size);
		return (0);
	}

	if (force_pushp != NULL)
		force_push = *force_pushp;

	if (DB_TYPE(mp) == M_PROTO && !__TPI_PRIM_ISALIGNED(mp->b_rptr)) {
		/* The read pointer is not aligned correctly for TPI */
		zcmn_err(getzoneid(), CE_WARN,
		    "sockfs: Unaligned TPI message received. rptr = %p\n",
		    (void *)mp->b_rptr);
		freemsg(mp);
		mutex_enter(sodp->sod_lockp);
		SOD_UIOAFINI(sodp);
		mutex_exit(sodp->sod_lockp);

		return (so->so_rcvbuf - so->so_rcv_queued);
	}

	mutex_enter(&so->so_lock);
	if (so->so_state & (SS_FALLBACK_PENDING | SS_FALLBACK_COMP)) {
		SOD_DISABLE(sodp);
		mutex_exit(&so->so_lock);
		*errorp = EOPNOTSUPP;
		return (-1);
	}
	if (so->so_state & SS_CANTRCVMORE) {
		freemsg(mp);
		SOD_DISABLE(sodp);
		mutex_exit(&so->so_lock);
		return (0);
	}

	/* process the mblk via I/OAT if capable */
	if (sodp != NULL && (sodp->sod_state & SOD_ENABLED)) {
		if (DB_TYPE(mp) == M_DATA) {
			(void) sod_uioa_mblk_init(sodp, mp, msg_size);
		} else {
			SOD_UIOAFINI(sodp);
		}
	}

	if (mp->b_next == NULL) {
		so_enqueue_msg(so, mp, msg_size);
	} else {
		do {
			mblk_t *nmp;

			if ((nmp = mp->b_next) != NULL) {
				mp->b_next = NULL;
			}
			so_enqueue_msg(so, mp, msgdsize(mp));
			mp = nmp;
		} while (mp != NULL);
	}

	space_left = so->so_rcvbuf - so->so_rcv_queued;
	if (space_left <= 0) {
		so->so_flowctrld = B_TRUE;
		*errorp = ENOSPC;
		space_left = -1;
	}

	if (force_push || so->so_rcv_queued >= so->so_rcv_thresh ||
	    so->so_rcv_queued >= so->so_rcv_wanted ||
	    (sodp != NULL && so->so_rcv_queued >= sodp->sod_want)) {
		SOCKET_TIMER_CANCEL(so);
		/*
		 * so_notify_data will release the lock
		 */
		so_notify_data(so, so->so_rcv_queued);

		if (force_pushp != NULL)
			*force_pushp = B_TRUE;
		goto done;
	} else if (so->so_rcv_timer_tid == 0) {
		/* Make sure the recv push timer is running */
		SOCKET_TIMER_START(so);
	}

done_unlock:
	mutex_exit(&so->so_lock);
done:
	return (space_left);
}

/*
 * Set the offset of where the oob data is relative to the bytes in
 * queued. Also generate SIGURG
 */
void
so_signal_oob(sock_upper_handle_t sock_handle, ssize_t offset)
{
	struct sonode *so;

	ASSERT(offset >= 0);
	so = (struct sonode *)sock_handle;
	mutex_enter(&so->so_lock);
	SOD_UIOAFINI(so->so_direct);

	/*
	 * New urgent data on the way so forget about any old
	 * urgent data.
	 */
	so->so_state &= ~(SS_HAVEOOBDATA|SS_HADOOBDATA);

	/*
	 * Record that urgent data is pending.
	 */
	so->so_state |= SS_OOBPEND;

	if (so->so_oobmsg != NULL) {
		dprintso(so, 1, ("sock: discarding old oob\n"));
		freemsg(so->so_oobmsg);
		so->so_oobmsg = NULL;
	}

	/*
	 * set the offset where the urgent byte is
	 */
	so->so_oobmark = so->so_rcv_queued + offset;
	if (so->so_oobmark == 0)
		so->so_state |= SS_RCVATMARK;
	else
		so->so_state &= ~SS_RCVATMARK;

	so_notify_oobsig(so);
}

/*
 * Queue the OOB byte
 */
static void
so_queue_oob(sock_upper_handle_t sock_handle, mblk_t *mp, size_t len)
{
	struct sonode *so;

	so = (struct sonode *)sock_handle;
	mutex_enter(&so->so_lock);
	SOD_UIOAFINI(so->so_direct);

	ASSERT(mp != NULL);
	if (!IS_SO_OOB_INLINE(so)) {
		so->so_oobmsg = mp;
		so->so_state |= SS_HAVEOOBDATA;
	} else {
		so_enqueue_msg(so, mp, len);
	}

	so_notify_oobdata(so, IS_SO_OOB_INLINE(so));
}

int
so_close(struct sonode *so, int flag, struct cred *cr)
{
	int error;

	error = (*so->so_downcalls->sd_close)(so->so_proto_handle, flag, cr);

	/*
	 * At this point there will be no more upcalls from the protocol
	 */
	mutex_enter(&so->so_lock);

	ASSERT(so_verify_oobstate(so));

	so_rcv_flush(so);
	mutex_exit(&so->so_lock);

	return (error);
}

void
so_zcopy_notify(sock_upper_handle_t sock_handle)
{
	struct sonode *so = (struct sonode *)sock_handle;

	mutex_enter(&so->so_lock);
	so->so_copyflag |= STZCNOTIFY;
	cv_broadcast(&so->so_copy_cv);
	mutex_exit(&so->so_lock);
}

void
so_set_error(sock_upper_handle_t sock_handle, int error)
{
	struct sonode *so = (struct sonode *)sock_handle;

	mutex_enter(&so->so_lock);

	soseterror(so, error);

	so_notify_error(so);
}

/*
 * so_recvmsg - read data from the socket
 *
 * There are two ways of obtaining data; either we ask the protocol to
 * copy directly into the supplied buffer, or we copy data from the
 * sonode's receive queue. The decision which one to use depends on
 * whether the protocol has a sd_recv_uio down call.
 */
int
so_recvmsg(struct sonode *so, struct nmsghdr *msg, struct uio *uiop,
    struct cred *cr)
{
	rval_t 		rval;
	int 		flags = 0;
	t_uscalar_t	controllen, namelen;
	int 		error = 0;
	int ret;
	mblk_t		*mctlp = NULL;
	union T_primitives *tpr;
	void		*control;
	ssize_t		saved_resid;
	struct uio	*suiop;

	SO_BLOCK_FALLBACK(so, SOP_RECVMSG(so, msg, uiop, cr));

	if ((so->so_state & (SS_ISCONNECTED|SS_CANTRCVMORE)) == 0 &&
	    (so->so_mode & SM_CONNREQUIRED)) {
		SO_UNBLOCK_FALLBACK(so);
		return (ENOTCONN);
	}

	if (msg->msg_flags & MSG_PEEK)
		msg->msg_flags &= ~MSG_WAITALL;

	if (so->so_mode & SM_ATOMIC)
		msg->msg_flags |= MSG_TRUNC;

	if (msg->msg_flags & MSG_OOB) {
		if ((so->so_mode & SM_EXDATA) == 0) {
			error = EOPNOTSUPP;
		} else if (so->so_downcalls->sd_recv_uio != NULL) {
			error = (*so->so_downcalls->sd_recv_uio)
			    (so->so_proto_handle, uiop, msg, cr);
		} else {
			error = sorecvoob(so, msg, uiop, msg->msg_flags,
			    IS_SO_OOB_INLINE(so));
		}
		SO_UNBLOCK_FALLBACK(so);
		return (error);
	}

	/*
	 * If the protocol has the recv down call, then pass the request
	 * down.
	 */
	if (so->so_downcalls->sd_recv_uio != NULL) {
		error = (*so->so_downcalls->sd_recv_uio)
		    (so->so_proto_handle, uiop, msg, cr);
		SO_UNBLOCK_FALLBACK(so);
		return (error);
	}

	/*
	 * Reading data from the socket buffer
	 */
	flags = msg->msg_flags;
	msg->msg_flags = 0;

	/*
	 * Set msg_controllen and msg_namelen to zero here to make it
	 * simpler in the cases that no control or name is returned.
	 */
	controllen = msg->msg_controllen;
	namelen = msg->msg_namelen;
	msg->msg_controllen = 0;
	msg->msg_namelen = 0;

	mutex_enter(&so->so_lock);
	/* Set SOREADLOCKED */
	error = so_lock_read_intr(so,
	    uiop->uio_fmode | ((flags & MSG_DONTWAIT) ? FNONBLOCK : 0));
	mutex_exit(&so->so_lock);
	if (error) {
		SO_UNBLOCK_FALLBACK(so);
		return (error);
	}

	suiop = sod_rcv_init(so, flags, &uiop);
retry:
	saved_resid = uiop->uio_resid;
	error = so_dequeue_msg(so, &mctlp, uiop, &rval, flags);
	if (error != 0) {
		goto out;
	}
	/*
	 * For datagrams the MOREDATA flag is used to set MSG_TRUNC.
	 * For non-datagrams MOREDATA is used to set MSG_EOR.
	 */
	ASSERT(!(rval.r_val1 & MORECTL));
	if ((rval.r_val1 & MOREDATA) && (so->so_mode & SM_ATOMIC))
		msg->msg_flags |= MSG_TRUNC;
	if (mctlp == NULL) {
		dprintso(so, 1, ("so_recvmsg: got M_DATA\n"));

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
			goto retry;
		}

		goto out_locked;
	}
	/* strsock_proto has already verified length and alignment */
	tpr = (union T_primitives *)mctlp->b_rptr;
	dprintso(so, 1, ("so_recvmsg: type %d\n", tpr->type));
	switch (tpr->type) {
	case T_DATA_IND: {
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
		freemsg(mctlp);
		/*
		 * If some data was received (i.e. not EOF) and the
		 * read/recv* has not been satisfied wait for some more.
		 */
		if ((flags & MSG_WAITALL) && !(msg->msg_flags & MSG_EOR) &&
		    uiop->uio_resid != saved_resid && uiop->uio_resid > 0) {
			mutex_exit(&so->so_lock);
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

		if (namelen != 0) {
			/* Caller wants source address */
			addrlen = tpr->unitdata_ind.SRC_length;
			addr = sogetoff(mctlp, tpr->unitdata_ind.SRC_offset,
			    addrlen, 1);
			if (addr == NULL) {
				freemsg(mctlp);
				error = EPROTO;
				eprintsoline(so, error);
				goto out;
			}
			ASSERT(so->so_family != AF_UNIX);
		}
		optlen = tpr->unitdata_ind.OPT_length;
		if (optlen != 0) {
			t_uscalar_t ncontrollen;

			/*
			 * Extract any source address option.
			 * Determine how large cmsg buffer is needed.
			 */
			opt = sogetoff(mctlp, tpr->unitdata_ind.OPT_offset,
			    optlen, __TPI_ALIGN_SIZE);

			if (opt == NULL) {
				freemsg(mctlp);
				error = EPROTO;
				eprintsoline(so, error);
				goto out;
			}
			if (so->so_family == AF_UNIX)
				so_getopt_srcaddr(opt, optlen, &addr, &addrlen);
			ncontrollen = so_cmsglen(mctlp, opt, optlen,
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

			error = so_opt2cmsg(mctlp, opt, optlen,
			    !(flags & MSG_XPG4_2), control, controllen);
			if (error) {
				freemsg(mctlp);
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

		freemsg(mctlp);
		goto out;
	}
	case T_OPTDATA_IND: {
		struct T_optdata_req *tdr;
		void *opt;
		t_uscalar_t optlen;

		tdr = (struct T_optdata_req *)mctlp->b_rptr;
		optlen = tdr->OPT_length;
		if (optlen != 0) {
			t_uscalar_t ncontrollen;
			/*
			 * Determine how large cmsg buffer is needed.
			 */
			opt = sogetoff(mctlp,
			    tpr->optdata_ind.OPT_offset, optlen,
			    __TPI_ALIGN_SIZE);

			if (opt == NULL) {
				freemsg(mctlp);
				error = EPROTO;
				eprintsoline(so, error);
				goto out;
			}

			ncontrollen = so_cmsglen(mctlp, opt, optlen,
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

			error = so_opt2cmsg(mctlp, opt, optlen,
			    !(flags & MSG_XPG4_2), control, controllen);
			if (error) {
				freemsg(mctlp);
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
		freemsg(mctlp);
		/*
		 * If some data was received (i.e. not EOF) and the
		 * read/recv* has not been satisfied wait for some more.
		 * Not possible to wait if control info was received.
		 */
		if ((flags & MSG_WAITALL) && !(msg->msg_flags & MSG_EOR) &&
		    controllen == 0 &&
		    uiop->uio_resid != saved_resid && uiop->uio_resid > 0) {
			mutex_exit(&so->so_lock);
			goto retry;
		}
		goto out_locked;
	}
	default:
		cmn_err(CE_CONT, "so_recvmsg bad type %x \n",
		    tpr->type);
		freemsg(mctlp);
		error = EPROTO;
		ASSERT(0);
	}
out:
	mutex_enter(&so->so_lock);
out_locked:
	/* The sod_lockp pointers to the sonode so_lock */
	ret = sod_rcv_done(so, suiop, uiop);
	if (ret != 0 && error == 0)
		error = ret;

	so_unlock_read(so);	/* Clear SOREADLOCKED */
	mutex_exit(&so->so_lock);

	SO_UNBLOCK_FALLBACK(so);

	return (error);
}

sonodeops_t so_sonodeops = {
	so_init,		/* sop_init	*/
	so_accept,		/* sop_accept   */
	so_bind,		/* sop_bind	*/
	so_listen,		/* sop_listen   */
	so_connect,		/* sop_connect  */
	so_recvmsg,		/* sop_recvmsg  */
	so_sendmsg,		/* sop_sendmsg  */
	so_sendmblk,		/* sop_sendmblk */
	so_getpeername,		/* sop_getpeername */
	so_getsockname,		/* sop_getsockname */
	so_shutdown,		/* sop_shutdown */
	so_getsockopt,		/* sop_getsockopt */
	so_setsockopt,		/* sop_setsockopt */
	so_ioctl,		/* sop_ioctl    */
	so_poll,		/* sop_poll	*/
	so_close,		/* sop_close */
};

sock_upcalls_t so_upcalls = {
	so_newconn,
	so_connected,
	so_disconnected,
	so_opctl,
	so_queue_msg,
	so_set_prop,
	so_txq_full,
	so_signal_oob,
	so_zcopy_notify,
	so_set_error
};
