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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/inttypes.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/user.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/esunddi.h>
#include <sys/flock.h>
#include <sys/modctl.h>
#include <sys/vtrace.h>
#include <sys/strsun.h>
#include <sys/cmn_err.h>
#include <sys/proc.h>
#include <sys/ddi.h>
#include <sys/kmem_impl.h>

#include <sys/suntpi.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/socketvar.h>
#include <netinet/in.h>

#include <sys/tiuser.h>
#define	_SUN_TPI_VERSION	2
#include <sys/tihdr.h>

#include <inet/kssl/ksslapi.h>

#include <c2/audit.h>

#include <sys/dcopy.h>

int so_default_version = SOV_SOCKSTREAM;

#ifdef DEBUG
/* Set sockdebug to print debug messages when SO_DEBUG is set */
int sockdebug = 0;

/* Set sockprinterr to print error messages when SO_DEBUG is set */
int sockprinterr = 0;

/*
 * Set so_default_options to SO_DEBUG is all sockets should be created
 * with SO_DEBUG set. This is needed to get debug printouts from the
 * socket() call itself.
 */
int so_default_options = 0;
#endif /* DEBUG */

#ifdef SOCK_TEST
/*
 * Set to number of ticks to limit cv_waits for code coverage testing.
 * Set to 1000 when SO_DEBUG is set to 2.
 */
clock_t sock_test_timelimit = 0;
#endif /* SOCK_TEST */

/*
 * For concurrency testing of e.g. opening /dev/ip which does not
 * handle T_INFO_REQ messages.
 */
int so_no_tinfo = 0;

/*
 * Timeout for getting a T_CAPABILITY_ACK - it is possible for a provider
 * to simply ignore the T_CAPABILITY_REQ.
 */
clock_t	sock_capability_timeout	= 2;	/* seconds */

static int	do_tcapability(struct sonode *so, t_uscalar_t cap_bits1);
static void	so_removehooks(struct sonode *so);

static mblk_t *strsock_proto(vnode_t *vp, mblk_t *mp,
		strwakeup_t *wakeups, strsigset_t *firstmsgsigs,
		strsigset_t *allmsgsigs, strpollset_t *pollwakeups);
static mblk_t *strsock_misc(vnode_t *vp, mblk_t *mp,
		strwakeup_t *wakeups, strsigset_t *firstmsgsigs,
		strsigset_t *allmsgsigs, strpollset_t *pollwakeups);

static int tlitosyserr(int terr);

/*
 * Sodirect kmem_cache and put/wakeup functions.
 */
struct kmem_cache *socktpi_sod_cache;
static int sodput(sodirect_t *, mblk_t *);
static void sodwakeup(sodirect_t *);

/*
 * Called by sockinit() when sockfs is loaded.
 */
int
sostr_init()
{
	/* Allocate sodirect_t kmem_cache */
	socktpi_sod_cache = kmem_cache_create("socktpi_sod_cache",
	    sizeof (sodirect_t), 0, NULL, NULL, NULL, NULL, NULL, 0);

	return (0);
}

/*
 * Convert a socket to a stream. Invoked when the illusory sockmod
 * is popped from the stream.
 * Change the stream head back to default operation without losing
 * any messages (T_conn_ind's are moved to the stream head queue).
 */
int
so_sock2stream(struct sonode *so)
{
	struct vnode		*vp = SOTOV(so);
	queue_t			*rq;
	mblk_t			*mp;
	int			error = 0;

	ASSERT(MUTEX_HELD(&so->so_plumb_lock));

	mutex_enter(&so->so_lock);
	so_lock_single(so);

	ASSERT(so->so_version != SOV_STREAM);

	if (so->so_state & SS_DIRECT) {
		mblk_t **mpp;
		int rval;

		/*
		 * Tell the transport below that sockmod is being popped
		 */
		mutex_exit(&so->so_lock);
		error = strioctl(vp, _SIOCSOCKFALLBACK, 0, 0, K_TO_K, CRED(),
		    &rval);
		mutex_enter(&so->so_lock);
		if (error != 0) {
			dprintso(so, 0, ("so_sock2stream(%p): "
			    "_SIOCSOCKFALLBACK failed\n", so));
			goto exit;
		}
		so->so_state &= ~SS_DIRECT;

		for (mpp = &so->so_conn_ind_head; (mp = *mpp) != NULL;
		    mpp = &mp->b_next) {
			struct T_conn_ind	*conn_ind;

			/*
			 * strsock_proto() has already verified the length of
			 * this message block.
			 */
			ASSERT(MBLKL(mp) >= sizeof (struct T_conn_ind));

			conn_ind = (struct T_conn_ind *)mp->b_rptr;
			if (conn_ind->OPT_length == 0 &&
			    conn_ind->OPT_offset == 0)
				continue;

			if (DB_REF(mp) > 1) {
				mblk_t	*newmp;
				size_t	length;
				cred_t	*cr;

				/*
				 * Copy the message block because it is used
				 * elsewhere, too.
				 */
				length = MBLKL(mp);
				newmp = soallocproto(length, _ALLOC_INTR);
				if (newmp == NULL) {
					error = EINTR;
					goto exit;
				}
				bcopy(mp->b_rptr, newmp->b_wptr, length);
				newmp->b_wptr += length;
				newmp->b_next = mp->b_next;
				cr = DB_CRED(mp);
				if (cr != NULL)
					mblk_setcred(newmp, cr);
				DB_CPID(newmp) = DB_CPID(mp);

				/*
				 * Link the new message block into the queue
				 * and free the old one.
				 */
				*mpp = newmp;
				mp->b_next = NULL;
				freemsg(mp);

				mp = newmp;
				conn_ind = (struct T_conn_ind *)mp->b_rptr;
			}

			/*
			 * Remove options added by TCP for accept fast-path.
			 */
			conn_ind->OPT_length = 0;
			conn_ind->OPT_offset = 0;
		}
	}

	so->so_version = SOV_STREAM;
	so->so_priv = NULL;

	/*
	 * Remove the hooks in the stream head to avoid queuing more
	 * packets in sockfs.
	 */
	mutex_exit(&so->so_lock);
	so_removehooks(so);
	mutex_enter(&so->so_lock);

	/*
	 * Clear any state related to urgent data. Leave any T_EXDATA_IND
	 * on the queue - the behavior of urgent data after a switch is
	 * left undefined.
	 */
	so->so_error = so->so_delayed_error = 0;
	freemsg(so->so_oobmsg);
	so->so_oobmsg = NULL;
	so->so_oobsigcnt = so->so_oobcnt = 0;

	so->so_state &= ~(SS_RCVATMARK|SS_OOBPEND|SS_HAVEOOBDATA|SS_HADOOBDATA|
	    SS_HASCONNIND|SS_SAVEDEOR);
	ASSERT(so_verify_oobstate(so));

	freemsg(so->so_ack_mp);
	so->so_ack_mp = NULL;

	/*
	 * Flush the T_DISCON_IND on so_discon_ind_mp.
	 */
	so_flush_discon_ind(so);

	/*
	 * Move any queued T_CONN_IND messages to stream head queue.
	 */
	rq = RD(strvp2wq(vp));
	while ((mp = so->so_conn_ind_head) != NULL) {
		so->so_conn_ind_head = mp->b_next;
		mp->b_next = NULL;
		if (so->so_conn_ind_head == NULL) {
			ASSERT(so->so_conn_ind_tail == mp);
			so->so_conn_ind_tail = NULL;
		}
		dprintso(so, 0,
		    ("so_sock2stream(%p): moving T_CONN_IND\n",
		    so));

		/* Drop lock across put() */
		mutex_exit(&so->so_lock);
		put(rq, mp);
		mutex_enter(&so->so_lock);
	}

exit:
	ASSERT(MUTEX_HELD(&so->so_lock));
	so_unlock_single(so, SOLOCKED);
	mutex_exit(&so->so_lock);
	return (error);
}

/*
 * Covert a stream back to a socket. This is invoked when the illusory
 * sockmod is pushed on a stream (where the stream was "created" by
 * popping the illusory sockmod).
 * This routine can not recreate the socket state (certain aspects of
 * it like urgent data state and the bound/connected addresses for AF_UNIX
 * sockets can not be recreated by asking the transport for information).
 * Thus this routine implicitly assumes that the socket is in an initial
 * state (as if it was just created). It flushes any messages queued on the
 * read queue to avoid dealing with e.g. TPI acks or T_exdata_ind messages.
 */
void
so_stream2sock(struct sonode *so)
{
	struct vnode *vp = SOTOV(so);

	ASSERT(MUTEX_HELD(&so->so_plumb_lock));

	mutex_enter(&so->so_lock);
	so_lock_single(so);
	ASSERT(so->so_version == SOV_STREAM);
	so->so_version = SOV_SOCKSTREAM;
	so->so_pushcnt = 0;
	mutex_exit(&so->so_lock);

	/*
	 * Set a permenent error to force any thread in sorecvmsg to
	 * return (and drop SOREADLOCKED). Clear the error once
	 * we have SOREADLOCKED.
	 * This makes a read sleeping during the I_PUSH of sockmod return
	 * EIO.
	 */
	strsetrerror(SOTOV(so), EIO, 1, NULL);

	/*
	 * Get the read lock before flushing data to avoid
	 * problems with the T_EXDATA_IND MSG_PEEK code in sorecvmsg.
	 */
	mutex_enter(&so->so_lock);
	(void) so_lock_read(so, 0);	/* Set SOREADLOCKED */
	mutex_exit(&so->so_lock);

	strsetrerror(SOTOV(so), 0, 0, NULL);
	so_installhooks(so);

	/*
	 * Flush everything on the read queue.
	 * This ensures that no T_CONN_IND remain and that no T_EXDATA_IND
	 * remain; those types of messages would confuse sockfs.
	 */
	strflushrq(vp, FLUSHALL);
	mutex_enter(&so->so_lock);

	/*
	 * Flush the T_DISCON_IND on so_discon_ind_mp.
	 */
	so_flush_discon_ind(so);
	so_unlock_read(so);	/* Clear SOREADLOCKED */

	so_unlock_single(so, SOLOCKED);
	mutex_exit(&so->so_lock);
}

/*
 * Install the hooks in the stream head.
 */
void
so_installhooks(struct sonode *so)
{
	struct vnode *vp = SOTOV(so);

	strsetrputhooks(vp, SH_SIGALLDATA | SH_IGN_ZEROLEN | SH_CONSOL_DATA,
	    strsock_proto, strsock_misc);
	strsetwputhooks(vp, SH_SIGPIPE | SH_RECHECK_ERR, 0);
}

/*
 * Remove the hooks in the stream head.
 */
static void
so_removehooks(struct sonode *so)
{
	struct vnode *vp = SOTOV(so);

	strsetrputhooks(vp, 0, NULL, NULL);
	strsetwputhooks(vp, 0, STRTIMOUT);
	/*
	 * Leave read behavior as it would have been for a normal
	 * stream i.e. a read of an M_PROTO will fail.
	 */
}

/*
 * Initialize the streams side of a socket including
 * T_info_req/ack processing. If tso is not NULL its values are used thereby
 * avoiding the T_INFO_REQ.
 */
int
so_strinit(struct sonode *so, struct sonode *tso)
{
	struct vnode *vp = SOTOV(so);
	struct stdata *stp;
	mblk_t *mp;
	int error;

	dprintso(so, 1, ("so_strinit(%p)\n", so));

	/* Preallocate an unbind_req message */
	mp = soallocproto(sizeof (struct T_unbind_req), _ALLOC_SLEEP);
	mutex_enter(&so->so_lock);
	so->so_unbind_mp = mp;
#ifdef DEBUG
	so->so_options = so_default_options;
#endif /* DEBUG */
	mutex_exit(&so->so_lock);

	so_installhooks(so);

	/*
	 * The T_CAPABILITY_REQ should be the first message sent down because
	 * at least TCP has a fast-path for this which avoids timeouts while
	 * waiting for the T_CAPABILITY_ACK under high system load.
	 */
	if (tso == NULL) {
		error = do_tcapability(so, TC1_ACCEPTOR_ID | TC1_INFO);
		if (error)
			return (error);
	} else {
		mutex_enter(&so->so_lock);
		so->so_tsdu_size = tso->so_tsdu_size;
		so->so_etsdu_size = tso->so_etsdu_size;
		so->so_addr_size = tso->so_addr_size;
		so->so_opt_size = tso->so_opt_size;
		so->so_tidu_size = tso->so_tidu_size;
		so->so_serv_type = tso->so_serv_type;
		so->so_mode = tso->so_mode & ~SM_ACCEPTOR_ID;
		mutex_exit(&so->so_lock);

		/* the following do_tcapability may update so->so_mode */
		if ((tso->so_serv_type != T_CLTS) &&
		    !(tso->so_state & SS_DIRECT)) {
			error = do_tcapability(so, TC1_ACCEPTOR_ID);
			if (error)
				return (error);
		}
	}
	/*
	 * If the addr_size is 0 we treat it as already bound
	 * and connected. This is used by the routing socket.
	 * We set the addr_size to something to allocate a the address
	 * structures.
	 */
	if (so->so_addr_size == 0) {
		so->so_state |= SS_ISBOUND | SS_ISCONNECTED;
		/* Address size can vary with address families. */
		if (so->so_family == AF_INET6)
			so->so_addr_size =
			    (t_scalar_t)sizeof (struct sockaddr_in6);
		else
			so->so_addr_size =
			    (t_scalar_t)sizeof (struct sockaddr_in);
		ASSERT(so->so_unbind_mp);
	}
	/*
	 * Allocate the addresses.
	 */
	ASSERT(so->so_laddr_sa == NULL && so->so_faddr_sa == NULL);
	ASSERT(so->so_laddr_len == 0 && so->so_faddr_len == 0);
	so->so_laddr_maxlen = so->so_faddr_maxlen =
	    P2ROUNDUP(so->so_addr_size, KMEM_ALIGN);
	so->so_laddr_sa = kmem_alloc(so->so_laddr_maxlen * 2, KM_SLEEP);
	so->so_faddr_sa = (struct sockaddr *)((caddr_t)so->so_laddr_sa
	    + so->so_laddr_maxlen);

	if (so->so_family == AF_UNIX) {
		/*
		 * Initialize AF_UNIX related fields.
		 */
		bzero(&so->so_ux_laddr, sizeof (so->so_ux_laddr));
		bzero(&so->so_ux_faddr, sizeof (so->so_ux_faddr));
	}

	stp = vp->v_stream;
	/*
	 * Have to keep minpsz at zero in order to allow write/send of zero
	 * bytes.
	 */
	mutex_enter(&stp->sd_lock);
	if (stp->sd_qn_minpsz == 1)
		stp->sd_qn_minpsz = 0;
	mutex_exit(&stp->sd_lock);

	/*
	 * If sodirect capable allocate and initialize sodirect_t.
	 * Note, SS_SODIRECT is set in socktpi_open().
	 */
	if (so->so_state & SS_SODIRECT) {
		sodirect_t	*sodp;

		ASSERT(so->so_direct == NULL);

		sodp = kmem_cache_alloc(socktpi_sod_cache, KM_SLEEP);
		sodp->sod_state = SOD_ENABLED | SOD_WAKE_NOT;
		sodp->sod_want = 0;
		sodp->sod_q = RD(stp->sd_wrq);
		sodp->sod_enqueue = sodput;
		sodp->sod_wakeup = sodwakeup;
		sodp->sod_uioafh = NULL;
		sodp->sod_uioaft = NULL;
		sodp->sod_lock = &stp->sd_lock;
		/*
		 * Remainder of the sod_uioa members are left uninitialized
		 * but will be initialized later by uioainit() before uioa
		 * is enabled.
		 */
		sodp->sod_uioa.uioa_state = UIOA_ALLOC;
		so->so_direct = sodp;
		stp->sd_sodirect = sodp;
	}

	return (0);
}

static void
copy_tinfo(struct sonode *so, struct T_info_ack *tia)
{
	so->so_tsdu_size = tia->TSDU_size;
	so->so_etsdu_size = tia->ETSDU_size;
	so->so_addr_size = tia->ADDR_size;
	so->so_opt_size = tia->OPT_size;
	so->so_tidu_size = tia->TIDU_size;
	so->so_serv_type = tia->SERV_type;
	switch (tia->CURRENT_state) {
	case TS_UNBND:
		break;
	case TS_IDLE:
		so->so_state |= SS_ISBOUND;
		so->so_laddr_len = 0;
		so->so_state &= ~SS_LADDR_VALID;
		break;
	case TS_DATA_XFER:
		so->so_state |= SS_ISBOUND|SS_ISCONNECTED;
		so->so_laddr_len = 0;
		so->so_faddr_len = 0;
		so->so_state &= ~(SS_LADDR_VALID | SS_FADDR_VALID);
		break;
	}

	/*
	 * Heuristics for determining the socket mode flags
	 * (SM_ATOMIC, SM_CONNREQUIRED, SM_ADDR, SM_FDPASSING,
	 * and SM_EXDATA, SM_OPTDATA, and SM_BYTESTREAM)
	 * from the info ack.
	 */
	if (so->so_serv_type == T_CLTS) {
		so->so_mode |= SM_ATOMIC | SM_ADDR;
	} else {
		so->so_mode |= SM_CONNREQUIRED;
		if (so->so_etsdu_size != 0 && so->so_etsdu_size != -2)
			so->so_mode |= SM_EXDATA;
	}
	if (so->so_type == SOCK_SEQPACKET || so->so_type == SOCK_RAW) {
		/* Semantics are to discard tail end of messages */
		so->so_mode |= SM_ATOMIC;
	}
	if (so->so_family == AF_UNIX) {
		so->so_mode |= SM_FDPASSING | SM_OPTDATA;
		if (so->so_addr_size == -1) {
			/* MAXPATHLEN + soun_family + nul termination */
			so->so_addr_size = (t_scalar_t)(MAXPATHLEN +
			    sizeof (short) + 1);
		}
		if (so->so_type == SOCK_STREAM) {
			/*
			 * Make it into a byte-stream transport.
			 * SOCK_SEQPACKET sockets are unchanged.
			 */
			so->so_tsdu_size = 0;
		}
	} else if (so->so_addr_size == -1) {
		/*
		 * Logic extracted from sockmod - have to pick some max address
		 * length in order to preallocate the addresses.
		 */
		so->so_addr_size = SOA_DEFSIZE;
	}
	if (so->so_tsdu_size == 0)
		so->so_mode |= SM_BYTESTREAM;
}

static int
check_tinfo(struct sonode *so)
{
	/* Consistency checks */
	if (so->so_type == SOCK_DGRAM && so->so_serv_type != T_CLTS) {
		eprintso(so, ("service type and socket type mismatch\n"));
		eprintsoline(so, EPROTO);
		return (EPROTO);
	}
	if (so->so_type == SOCK_STREAM && so->so_serv_type == T_CLTS) {
		eprintso(so, ("service type and socket type mismatch\n"));
		eprintsoline(so, EPROTO);
		return (EPROTO);
	}
	if (so->so_type == SOCK_SEQPACKET && so->so_serv_type == T_CLTS) {
		eprintso(so, ("service type and socket type mismatch\n"));
		eprintsoline(so, EPROTO);
		return (EPROTO);
	}
	if (so->so_family == AF_INET &&
	    so->so_addr_size != (t_scalar_t)sizeof (struct sockaddr_in)) {
		eprintso(so,
		    ("AF_INET must have sockaddr_in address length. Got %d\n",
		    so->so_addr_size));
		eprintsoline(so, EMSGSIZE);
		return (EMSGSIZE);
	}
	if (so->so_family == AF_INET6 &&
	    so->so_addr_size != (t_scalar_t)sizeof (struct sockaddr_in6)) {
		eprintso(so,
		    ("AF_INET6 must have sockaddr_in6 address length. Got %d\n",
		    so->so_addr_size));
		eprintsoline(so, EMSGSIZE);
		return (EMSGSIZE);
	}

	dprintso(so, 1, (
	    "tinfo: serv %d tsdu %d, etsdu %d, addr %d, opt %d, tidu %d\n",
	    so->so_serv_type, so->so_tsdu_size, so->so_etsdu_size,
	    so->so_addr_size, so->so_opt_size,
	    so->so_tidu_size));
	dprintso(so, 1, ("tinfo: so_state %s\n",
	    pr_state(so->so_state, so->so_mode)));
	return (0);
}

/*
 * Send down T_info_req and wait for the ack.
 * Record interesting T_info_ack values in the sonode.
 */
static int
do_tinfo(struct sonode *so)
{
	struct T_info_req tir;
	mblk_t *mp;
	int error;

	ASSERT(MUTEX_NOT_HELD(&so->so_lock));

	if (so_no_tinfo) {
		so->so_addr_size = 0;
		return (0);
	}

	dprintso(so, 1, ("do_tinfo(%p)\n", so));

	/* Send T_INFO_REQ */
	tir.PRIM_type = T_INFO_REQ;
	mp = soallocproto1(&tir, sizeof (tir),
	    sizeof (struct T_info_req) + sizeof (struct T_info_ack),
	    _ALLOC_INTR);
	if (mp == NULL) {
		eprintsoline(so, ENOBUFS);
		return (ENOBUFS);
	}
	/* T_INFO_REQ has to be M_PCPROTO */
	DB_TYPE(mp) = M_PCPROTO;

	error = kstrputmsg(SOTOV(so), mp, NULL, 0, 0,
	    MSG_BAND|MSG_HOLDSIG|MSG_IGNERROR, 0);
	if (error) {
		eprintsoline(so, error);
		return (error);
	}
	mutex_enter(&so->so_lock);
	/* Wait for T_INFO_ACK */
	if ((error = sowaitprim(so, T_INFO_REQ, T_INFO_ACK,
	    (t_uscalar_t)sizeof (struct T_info_ack), &mp, 0))) {
		mutex_exit(&so->so_lock);
		eprintsoline(so, error);
		return (error);
	}

	ASSERT(mp);
	copy_tinfo(so, (struct T_info_ack *)mp->b_rptr);
	mutex_exit(&so->so_lock);
	freemsg(mp);
	return (check_tinfo(so));
}

/*
 * Send down T_capability_req and wait for the ack.
 * Record interesting T_capability_ack values in the sonode.
 */
static int
do_tcapability(struct sonode *so, t_uscalar_t cap_bits1)
{
	struct T_capability_req tcr;
	struct T_capability_ack *tca;
	mblk_t *mp;
	int error;

	ASSERT(cap_bits1 != 0);
	ASSERT((cap_bits1 & ~(TC1_ACCEPTOR_ID | TC1_INFO)) == 0);
	ASSERT(MUTEX_NOT_HELD(&so->so_lock));

	if (so->so_provinfo->tpi_capability == PI_NO)
		return (do_tinfo(so));

	if (so_no_tinfo) {
		so->so_addr_size = 0;
		if ((cap_bits1 &= ~TC1_INFO) == 0)
			return (0);
	}

	dprintso(so, 1, ("do_tcapability(%p)\n", so));

	/* Send T_CAPABILITY_REQ */
	tcr.PRIM_type = T_CAPABILITY_REQ;
	tcr.CAP_bits1 = cap_bits1;
	mp = soallocproto1(&tcr, sizeof (tcr),
	    sizeof (struct T_capability_req) + sizeof (struct T_capability_ack),
	    _ALLOC_INTR);
	if (mp == NULL) {
		eprintsoline(so, ENOBUFS);
		return (ENOBUFS);
	}
	/* T_CAPABILITY_REQ should be M_PCPROTO here */
	DB_TYPE(mp) = M_PCPROTO;

	error = kstrputmsg(SOTOV(so), mp, NULL, 0, 0,
	    MSG_BAND|MSG_HOLDSIG|MSG_IGNERROR, 0);
	if (error) {
		eprintsoline(so, error);
		return (error);
	}
	mutex_enter(&so->so_lock);
	/* Wait for T_CAPABILITY_ACK */
	if ((error = sowaitprim(so, T_CAPABILITY_REQ, T_CAPABILITY_ACK,
	    (t_uscalar_t)sizeof (*tca), &mp, sock_capability_timeout * hz))) {
		mutex_exit(&so->so_lock);
		PI_PROVLOCK(so->so_provinfo);
		if (so->so_provinfo->tpi_capability == PI_DONTKNOW)
			so->so_provinfo->tpi_capability = PI_NO;
		PI_PROVUNLOCK(so->so_provinfo);
		ASSERT((so->so_mode & SM_ACCEPTOR_ID) == 0);
		if (cap_bits1 & TC1_INFO) {
			/*
			 * If the T_CAPABILITY_REQ timed out and then a
			 * T_INFO_REQ gets a protocol error, most likely
			 * the capability was slow (vs. unsupported). Return
			 * ENOSR for this case as a best guess.
			 */
			if (error == ETIME) {
				return ((error = do_tinfo(so)) == EPROTO ?
				    ENOSR : error);
			}
			return (do_tinfo(so));
		}
		return (0);
	}

	if (so->so_provinfo->tpi_capability == PI_DONTKNOW) {
		PI_PROVLOCK(so->so_provinfo);
		so->so_provinfo->tpi_capability = PI_YES;
		PI_PROVUNLOCK(so->so_provinfo);
	}

	ASSERT(mp);
	tca = (struct T_capability_ack *)mp->b_rptr;

	ASSERT((cap_bits1 & TC1_INFO) == (tca->CAP_bits1 & TC1_INFO));

	cap_bits1 = tca->CAP_bits1;

	if (cap_bits1 & TC1_ACCEPTOR_ID) {
		so->so_acceptor_id = tca->ACCEPTOR_id;
		so->so_mode |= SM_ACCEPTOR_ID;
	}

	if (cap_bits1 & TC1_INFO)
		copy_tinfo(so, &tca->INFO_ack);

	mutex_exit(&so->so_lock);
	freemsg(mp);

	if (cap_bits1 & TC1_INFO)
		return (check_tinfo(so));

	return (0);
}

/*
 * Retrieve and clear the socket error.
 */
int
sogeterr(struct sonode *so)
{
	int error;

	ASSERT(MUTEX_HELD(&so->so_lock));

	error = so->so_error;
	so->so_error = 0;

	return (error);
}

/*
 * This routine is registered with the stream head to retrieve read
 * side errors.
 * It does not clear the socket error for a peeking read side operation.
 * It the error is to be cleared it sets *clearerr.
 */
int
sogetrderr(vnode_t *vp, int ispeek, int *clearerr)
{
	struct sonode *so = VTOSO(vp);
	int error;

	mutex_enter(&so->so_lock);
	if (ispeek) {
		error = so->so_error;
		*clearerr = 0;
	} else {
		error = so->so_error;
		so->so_error = 0;
		*clearerr = 1;
	}
	mutex_exit(&so->so_lock);
	return (error);
}

/*
 * This routine is registered with the stream head to retrieve write
 * side errors.
 * It does not clear the socket error for a peeking read side operation.
 * It the error is to be cleared it sets *clearerr.
 */
int
sogetwrerr(vnode_t *vp, int ispeek, int *clearerr)
{
	struct sonode *so = VTOSO(vp);
	int error;

	mutex_enter(&so->so_lock);
	if (so->so_state & SS_CANTSENDMORE) {
		error = EPIPE;
		*clearerr = 0;
	} else {
		error = so->so_error;
		if (ispeek) {
			*clearerr = 0;
		} else {
			so->so_error = 0;
			*clearerr = 1;
		}
	}
	mutex_exit(&so->so_lock);
	return (error);
}

/*
 * Set a nonpersistent read and write error on the socket.
 * Used when there is a T_uderror_ind for a connected socket.
 * The caller also needs to call strsetrerror and strsetwerror
 * after dropping the lock.
 */
void
soseterror(struct sonode *so, int error)
{
	ASSERT(error != 0);

	ASSERT(MUTEX_HELD(&so->so_lock));
	so->so_error = (ushort_t)error;
}

void
soisconnecting(struct sonode *so)
{
	ASSERT(MUTEX_HELD(&so->so_lock));
	so->so_state &= ~(SS_ISCONNECTED|SS_ISDISCONNECTING);
	so->so_state |= SS_ISCONNECTING;
	cv_broadcast(&so->so_state_cv);
}

void
soisconnected(struct sonode *so)
{
	ASSERT(MUTEX_HELD(&so->so_lock));
	so->so_state &= ~(SS_ISCONNECTING|SS_ISDISCONNECTING);
	so->so_state |= SS_ISCONNECTED;
	cv_broadcast(&so->so_state_cv);
}

/*
 * The caller also needs to call strsetrerror, strsetwerror and strseteof.
 */
void
soisdisconnected(struct sonode *so, int error)
{
	ASSERT(MUTEX_HELD(&so->so_lock));
	so->so_state &= ~(SS_ISCONNECTING|SS_ISCONNECTED|SS_ISDISCONNECTING|
	    SS_LADDR_VALID|SS_FADDR_VALID);
	so->so_state |= (SS_CANTRCVMORE|SS_CANTSENDMORE);
	so->so_error = (ushort_t)error;
	if (so->so_peercred != NULL) {
		crfree(so->so_peercred);
		so->so_peercred = NULL;
	}
	cv_broadcast(&so->so_state_cv);
}

/*
 * For connected AF_UNIX SOCK_DGRAM sockets when the peer closes.
 * Does not affect write side.
 * The caller also has to call strsetrerror.
 */
static void
sobreakconn(struct sonode *so, int error)
{
	ASSERT(MUTEX_HELD(&so->so_lock));
	so->so_state &= ~(SS_ISCONNECTING|SS_ISCONNECTED|SS_ISDISCONNECTING);
	so->so_error = (ushort_t)error;
	cv_broadcast(&so->so_state_cv);
}

/*
 * Can no longer send.
 * Caller must also call strsetwerror.
 *
 * We mark the peer address as no longer valid for getpeername, but
 * leave it around for so_unix_close to notify the peer (that
 * transport has no addressing held at that layer).
 */
void
socantsendmore(struct sonode *so)
{
	ASSERT(MUTEX_HELD(&so->so_lock));
	so->so_state = so->so_state & ~SS_FADDR_VALID | SS_CANTSENDMORE;
	cv_broadcast(&so->so_state_cv);
}

/*
 * The caller must call strseteof(,1) as well as this routine
 * to change the socket state.
 */
void
socantrcvmore(struct sonode *so)
{
	ASSERT(MUTEX_HELD(&so->so_lock));
	so->so_state |= SS_CANTRCVMORE;
	cv_broadcast(&so->so_state_cv);
}

/*
 * The caller has sent down a "request_prim" primitive and wants to wait for
 * an ack ("ack_prim") or an T_ERROR_ACK for it.
 * The specified "ack_prim" can be a T_OK_ACK.
 *
 * Assumes that all the TPI acks are M_PCPROTO messages.
 *
 * Note that the socket is single-threaded (using so_lock_single)
 * for all operations that generate TPI ack messages. Since
 * only TPI ack messages are M_PCPROTO we should never receive
 * anything except either the ack we are expecting or a T_ERROR_ACK
 * for the same primitive.
 */
int
sowaitprim(struct sonode *so, t_scalar_t request_prim, t_scalar_t ack_prim,
	    t_uscalar_t min_size, mblk_t **mpp, clock_t wait)
{
	mblk_t *mp;
	union T_primitives *tpr;
	int error;

	dprintso(so, 1, ("sowaitprim(%p, %d, %d, %d, %p, %lu)\n",
	    so, request_prim, ack_prim, min_size, mpp, wait));

	ASSERT(MUTEX_HELD(&so->so_lock));

	error = sowaitack(so, &mp, wait);
	if (error)
		return (error);

	dprintso(so, 1, ("got msg %p\n", mp));
	if (DB_TYPE(mp) != M_PCPROTO ||
	    MBLKL(mp) < sizeof (tpr->type)) {
		freemsg(mp);
		eprintsoline(so, EPROTO);
		return (EPROTO);
	}
	tpr = (union T_primitives *)mp->b_rptr;
	/*
	 * Did we get the primitive that we were asking for?
	 * For T_OK_ACK we also check that it matches the request primitive.
	 */
	if (tpr->type == ack_prim &&
	    (ack_prim != T_OK_ACK ||
	    tpr->ok_ack.CORRECT_prim == request_prim)) {
		if (MBLKL(mp) >= (ssize_t)min_size) {
			/* Found what we are looking for */
			*mpp = mp;
			return (0);
		}
		/* Too short */
		freemsg(mp);
		eprintsoline(so, EPROTO);
		return (EPROTO);
	}

	if (tpr->type == T_ERROR_ACK &&
	    tpr->error_ack.ERROR_prim == request_prim) {
		/* Error to the primitive we were looking for */
		if (tpr->error_ack.TLI_error == TSYSERR) {
			error = tpr->error_ack.UNIX_error;
		} else {
			error = tlitosyserr(tpr->error_ack.TLI_error);
		}
		dprintso(so, 0, ("error_ack for %d: %d/%d ->%d\n",
		    tpr->error_ack.ERROR_prim,
		    tpr->error_ack.TLI_error,
		    tpr->error_ack.UNIX_error,
		    error));
		freemsg(mp);
		return (error);
	}
	/*
	 * Wrong primitive or T_ERROR_ACK for the wrong primitive
	 */
#ifdef DEBUG
	if (tpr->type == T_ERROR_ACK) {
		dprintso(so, 0, ("error_ack for %d: %d/%d\n",
		    tpr->error_ack.ERROR_prim,
		    tpr->error_ack.TLI_error,
		    tpr->error_ack.UNIX_error));
	} else if (tpr->type == T_OK_ACK) {
		dprintso(so, 0, ("ok_ack for %d, expected %d for %d\n",
		    tpr->ok_ack.CORRECT_prim,
		    ack_prim, request_prim));
	} else {
		dprintso(so, 0,
		    ("unexpected primitive %d, expected %d for %d\n",
		    tpr->type, ack_prim, request_prim));
	}
#endif /* DEBUG */

	freemsg(mp);
	eprintsoline(so, EPROTO);
	return (EPROTO);
}

/*
 * Wait for a T_OK_ACK for the specified primitive.
 */
int
sowaitokack(struct sonode *so, t_scalar_t request_prim)
{
	mblk_t *mp;
	int error;

	error = sowaitprim(so, request_prim, T_OK_ACK,
	    (t_uscalar_t)sizeof (struct T_ok_ack), &mp, 0);
	if (error)
		return (error);
	freemsg(mp);
	return (0);
}

/*
 * Queue a received TPI ack message on so_ack_mp.
 */
void
soqueueack(struct sonode *so, mblk_t *mp)
{
	if (DB_TYPE(mp) != M_PCPROTO) {
		zcmn_err(getzoneid(), CE_WARN,
		    "sockfs: received unexpected M_PROTO TPI ack. Prim %d\n",
		    *(t_scalar_t *)mp->b_rptr);
		freemsg(mp);
		return;
	}

	mutex_enter(&so->so_lock);
	if (so->so_ack_mp != NULL) {
		dprintso(so, 1, ("so_ack_mp already set\n"));
		freemsg(so->so_ack_mp);
		so->so_ack_mp = NULL;
	}
	so->so_ack_mp = mp;
	cv_broadcast(&so->so_ack_cv);
	mutex_exit(&so->so_lock);
}

/*
 * Wait for a TPI ack ignoring signals and errors.
 */
int
sowaitack(struct sonode *so, mblk_t **mpp, clock_t wait)
{
	ASSERT(MUTEX_HELD(&so->so_lock));

	while (so->so_ack_mp == NULL) {
#ifdef SOCK_TEST
		if (wait == 0 && sock_test_timelimit != 0)
			wait = sock_test_timelimit;
#endif
		if (wait != 0) {
			/*
			 * Only wait for the time limit.
			 */
			clock_t now;

			time_to_wait(&now, wait);
			if (cv_timedwait(&so->so_ack_cv, &so->so_lock,
			    now) == -1) {
				eprintsoline(so, ETIME);
				return (ETIME);
			}
		}
		else
			cv_wait(&so->so_ack_cv, &so->so_lock);
	}
	*mpp = so->so_ack_mp;
#ifdef DEBUG
	{
		union T_primitives *tpr;
		mblk_t *mp = *mpp;

		tpr = (union T_primitives *)mp->b_rptr;
		ASSERT(DB_TYPE(mp) == M_PCPROTO);
		ASSERT(tpr->type == T_OK_ACK ||
		    tpr->type == T_ERROR_ACK ||
		    tpr->type == T_BIND_ACK ||
		    tpr->type == T_CAPABILITY_ACK ||
		    tpr->type == T_INFO_ACK ||
		    tpr->type == T_OPTMGMT_ACK);
	}
#endif /* DEBUG */
	so->so_ack_mp = NULL;
	return (0);
}

/*
 * Queue a received T_CONN_IND message on so_conn_ind_head/tail.
 */
void
soqueueconnind(struct sonode *so, mblk_t *mp)
{
	if (DB_TYPE(mp) != M_PROTO) {
		zcmn_err(getzoneid(), CE_WARN,
		    "sockfs: received unexpected M_PCPROTO T_CONN_IND\n");
		freemsg(mp);
		return;
	}

	mutex_enter(&so->so_lock);
	ASSERT(mp->b_next == NULL);
	if (so->so_conn_ind_head == NULL) {
		so->so_conn_ind_head = mp;
		so->so_state |= SS_HASCONNIND;
	} else {
		ASSERT(so->so_state & SS_HASCONNIND);
		ASSERT(so->so_conn_ind_tail->b_next == NULL);
		so->so_conn_ind_tail->b_next = mp;
	}
	so->so_conn_ind_tail = mp;
	/* Wakeup a single consumer of the T_CONN_IND */
	cv_signal(&so->so_connind_cv);
	mutex_exit(&so->so_lock);
}

/*
 * Wait for a T_CONN_IND.
 * Don't wait if nonblocking.
 * Accept signals and socket errors.
 */
int
sowaitconnind(struct sonode *so, int fmode, mblk_t **mpp)
{
	mblk_t *mp;
	int error = 0;

	ASSERT(MUTEX_NOT_HELD(&so->so_lock));
	mutex_enter(&so->so_lock);
check_error:
	if (so->so_error) {
		error = sogeterr(so);
		if (error) {
			mutex_exit(&so->so_lock);
			return (error);
		}
	}

	if (so->so_conn_ind_head == NULL) {
		if (fmode & (FNDELAY|FNONBLOCK)) {
			error = EWOULDBLOCK;
			goto done;
		}
		if (!cv_wait_sig_swap(&so->so_connind_cv, &so->so_lock)) {
			error = EINTR;
			goto done;
		}
		goto check_error;
	}
	mp = so->so_conn_ind_head;
	so->so_conn_ind_head = mp->b_next;
	mp->b_next = NULL;
	if (so->so_conn_ind_head == NULL) {
		ASSERT(so->so_conn_ind_tail == mp);
		so->so_conn_ind_tail = NULL;
		so->so_state &= ~SS_HASCONNIND;
	}
	*mpp = mp;
done:
	mutex_exit(&so->so_lock);
	return (error);
}

/*
 * Flush a T_CONN_IND matching the sequence number from the list.
 * Return zero if found; non-zero otherwise.
 * This is called very infrequently thus it is ok to do a linear search.
 */
int
soflushconnind(struct sonode *so, t_scalar_t seqno)
{
	mblk_t *prevmp, *mp;
	struct T_conn_ind *tci;

	mutex_enter(&so->so_lock);
	for (prevmp = NULL, mp = so->so_conn_ind_head; mp != NULL;
	    prevmp = mp, mp = mp->b_next) {
		tci = (struct T_conn_ind *)mp->b_rptr;
		if (tci->SEQ_number == seqno) {
			dprintso(so, 1,
			    ("t_discon_ind: found T_CONN_IND %d\n", seqno));
			/* Deleting last? */
			if (so->so_conn_ind_tail == mp) {
				so->so_conn_ind_tail = prevmp;
			}
			if (prevmp == NULL) {
				/* Deleting first */
				so->so_conn_ind_head = mp->b_next;
			} else {
				prevmp->b_next = mp->b_next;
			}
			mp->b_next = NULL;
			if (so->so_conn_ind_head == NULL) {
				ASSERT(so->so_conn_ind_tail == NULL);
				so->so_state &= ~SS_HASCONNIND;
			} else {
				ASSERT(so->so_conn_ind_tail != NULL);
			}
			so->so_error = ECONNABORTED;
			mutex_exit(&so->so_lock);

			/*
			 * T_KSSL_PROXY_CONN_IND may carry a handle for
			 * an SSL context, and needs to be released.
			 */
			if ((tci->PRIM_type == T_SSL_PROXY_CONN_IND) &&
			    (mp->b_cont != NULL)) {
				kssl_ctx_t kssl_ctx;

				ASSERT(MBLKL(mp->b_cont) ==
				    sizeof (kssl_ctx_t));
				kssl_ctx = *((kssl_ctx_t *)mp->b_cont->b_rptr);
				kssl_release_ctx(kssl_ctx);
			}
			freemsg(mp);
			return (0);
		}
	}
	mutex_exit(&so->so_lock);
	dprintso(so, 1,	("t_discon_ind: NOT found T_CONN_IND %d\n", seqno));
	return (-1);
}

/*
 * Wait until the socket is connected or there is an error.
 * fmode should contain any nonblocking flags. nosig should be
 * set if the caller does not want the wait to be interrupted by a signal.
 */
int
sowaitconnected(struct sonode *so, int fmode, int nosig)
{
	int error;

	ASSERT(MUTEX_HELD(&so->so_lock));

	while ((so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING)) ==
	    SS_ISCONNECTING && so->so_error == 0) {

		dprintso(so, 1, ("waiting for SS_ISCONNECTED on %p\n", so));
		if (fmode & (FNDELAY|FNONBLOCK))
			return (EINPROGRESS);

		if (nosig)
			cv_wait(&so->so_state_cv, &so->so_lock);
		else if (!cv_wait_sig_swap(&so->so_state_cv, &so->so_lock)) {
			/*
			 * Return EINTR and let the application use
			 * nonblocking techniques for detecting when
			 * the connection has been established.
			 */
			return (EINTR);
		}
		dprintso(so, 1, ("awoken on %p\n", so));
	}

	if (so->so_error != 0) {
		error = sogeterr(so);
		ASSERT(error != 0);
		dprintso(so, 1, ("sowaitconnected: error %d\n", error));
		return (error);
	}
	if (!(so->so_state & SS_ISCONNECTED)) {
		/*
		 * Could have received a T_ORDREL_IND or a T_DISCON_IND with
		 * zero errno. Or another thread could have consumed so_error
		 * e.g. by calling read.
		 */
		error = ECONNREFUSED;
		dprintso(so, 1, ("sowaitconnected: error %d\n", error));
		return (error);
	}
	return (0);
}


/*
 * Handle the signal generation aspect of urgent data.
 */
static void
so_oob_sig(struct sonode *so, int extrasig,
    strsigset_t *signals, strpollset_t *pollwakeups)
{
	ASSERT(MUTEX_HELD(&so->so_lock));

	ASSERT(so_verify_oobstate(so));
	ASSERT(so->so_oobsigcnt >= so->so_oobcnt);
	if (so->so_oobsigcnt > so->so_oobcnt) {
		/*
		 * Signal has already been generated once for this
		 * urgent "event". However, since TCP can receive updated
		 * urgent pointers we still generate a signal.
		 */
		ASSERT(so->so_state & SS_OOBPEND);
		if (extrasig) {
			*signals |= S_RDBAND;
			*pollwakeups |= POLLRDBAND;
		}
		return;
	}

	so->so_oobsigcnt++;
	ASSERT(so->so_oobsigcnt > 0);	/* Wraparound */
	ASSERT(so->so_oobsigcnt > so->so_oobcnt);

	/*
	 * Record (for select/poll) that urgent data is pending.
	 */
	so->so_state |= SS_OOBPEND;
	/*
	 * New urgent data on the way so forget about any old
	 * urgent data.
	 */
	so->so_state &= ~(SS_HAVEOOBDATA|SS_HADOOBDATA);
	if (so->so_oobmsg != NULL) {
		dprintso(so, 1, ("sock: discarding old oob\n"));
		freemsg(so->so_oobmsg);
		so->so_oobmsg = NULL;
	}
	*signals |= S_RDBAND;
	*pollwakeups |= POLLRDBAND;
	ASSERT(so_verify_oobstate(so));
}

/*
 * Handle the processing of the T_EXDATA_IND with urgent data.
 * Returns the T_EXDATA_IND if it should be queued on the read queue.
 */
/* ARGSUSED2 */
static mblk_t *
so_oob_exdata(struct sonode *so, mblk_t *mp,
	strsigset_t *signals, strpollset_t *pollwakeups)
{
	ASSERT(MUTEX_HELD(&so->so_lock));

	ASSERT(so_verify_oobstate(so));

	ASSERT(so->so_oobsigcnt > so->so_oobcnt);

	so->so_oobcnt++;
	ASSERT(so->so_oobcnt > 0);	/* wraparound? */
	ASSERT(so->so_oobsigcnt >= so->so_oobcnt);

	/*
	 * Set MSGMARK for SIOCATMARK.
	 */
	mp->b_flag |= MSGMARK;

	ASSERT(so_verify_oobstate(so));
	return (mp);
}

/*
 * Handle the processing of the actual urgent data.
 * Returns the data mblk if it should be queued on the read queue.
 */
static mblk_t *
so_oob_data(struct sonode *so, mblk_t *mp,
	strsigset_t *signals, strpollset_t *pollwakeups)
{
	ASSERT(MUTEX_HELD(&so->so_lock));

	ASSERT(so_verify_oobstate(so));

	ASSERT(so->so_oobsigcnt >= so->so_oobcnt);
	ASSERT(mp != NULL);
	/*
	 * For OOBINLINE we keep the data in the T_EXDATA_IND.
	 * Otherwise we store it in so_oobmsg.
	 */
	ASSERT(so->so_oobmsg == NULL);
	if (so->so_options & SO_OOBINLINE) {
		*pollwakeups |= POLLIN | POLLRDNORM | POLLRDBAND;
		*signals |= S_INPUT | S_RDNORM;
	} else {
		*pollwakeups |= POLLRDBAND;
		so->so_state |= SS_HAVEOOBDATA;
		so->so_oobmsg = mp;
		mp = NULL;
	}
	ASSERT(so_verify_oobstate(so));
	return (mp);
}

/*
 * Caller must hold the mutex.
 * For delayed processing, save the T_DISCON_IND received
 * from below on so_discon_ind_mp.
 * When the message is processed the framework will call:
 *      (*func)(so, mp);
 */
static void
so_save_discon_ind(struct sonode *so,
	mblk_t *mp,
	void (*func)(struct sonode *so, mblk_t *))
{
	ASSERT(MUTEX_HELD(&so->so_lock));

	/*
	 * Discard new T_DISCON_IND if we have already received another.
	 * Currently the earlier message can either be on so_discon_ind_mp
	 * or being processed.
	 */
	if (so->so_discon_ind_mp != NULL || (so->so_flag & SOASYNC_UNBIND)) {
		zcmn_err(getzoneid(), CE_WARN,
		    "sockfs: received unexpected additional T_DISCON_IND\n");
		freemsg(mp);
		return;
	}
	mp->b_prev = (mblk_t *)func;
	mp->b_next = NULL;
	so->so_discon_ind_mp = mp;
}

/*
 * Caller must hold the mutex and make sure that either SOLOCKED
 * or SOASYNC_UNBIND is set. Called from so_unlock_single().
 * Perform delayed processing of T_DISCON_IND message on so_discon_ind_mp.
 * Need to ensure that strsock_proto() will not end up sleeping for
 * SOASYNC_UNBIND, while executing this function.
 */
void
so_drain_discon_ind(struct sonode *so)
{
	mblk_t	*bp;
	void (*func)(struct sonode *so, mblk_t *);

	ASSERT(MUTEX_HELD(&so->so_lock));
	ASSERT(so->so_flag & (SOLOCKED|SOASYNC_UNBIND));

	/* Process T_DISCON_IND on so_discon_ind_mp */
	if ((bp = so->so_discon_ind_mp) != NULL) {
		so->so_discon_ind_mp = NULL;
		func = (void (*)())bp->b_prev;
		bp->b_prev = NULL;

		/*
		 * This (*func) is supposed to generate a message downstream
		 * and we need to have a flag set until the corresponding
		 * upstream message reaches stream head.
		 * When processing T_DISCON_IND in strsock_discon_ind
		 * we hold SOASYN_UNBIND when sending T_UNBIND_REQ down and
		 * drop the flag after we get the ACK in strsock_proto.
		 */
		(void) (*func)(so, bp);
	}
}

/*
 * Caller must hold the mutex.
 * Remove the T_DISCON_IND on so_discon_ind_mp.
 */
void
so_flush_discon_ind(struct sonode *so)
{
	mblk_t	*bp;

	ASSERT(MUTEX_HELD(&so->so_lock));

	/*
	 * Remove T_DISCON_IND mblk at so_discon_ind_mp.
	 */
	if ((bp = so->so_discon_ind_mp) != NULL) {
		so->so_discon_ind_mp = NULL;
		bp->b_prev = NULL;
		freemsg(bp);
	}
}

/*
 * Caller must hold the mutex.
 *
 * This function is used to process the T_DISCON_IND message. It does
 * immediate processing when called from strsock_proto and delayed
 * processing of discon_ind saved on so_discon_ind_mp when called from
 * so_drain_discon_ind. When a T_DISCON_IND message is saved in
 * so_discon_ind_mp for delayed processing, this function is registered
 * as the callback function to process the message.
 *
 * SOASYNC_UNBIND should be held in this function, during the non-blocking
 * unbind operation, and should be released only after we receive the ACK
 * in strsock_proto, for the T_UNBIND_REQ sent here. Since SOLOCKED is not set,
 * no TPI messages would be sent down at this time. This is to prevent M_FLUSH
 * sent from either this function or tcp_unbind(), flushing away any TPI
 * message that is being sent down and stays in a lower module's queue.
 *
 * This function drops so_lock and grabs it again.
 */
static void
strsock_discon_ind(struct sonode *so, mblk_t *discon_mp)
{
	struct vnode *vp;
	struct stdata *stp;
	union T_primitives *tpr;
	struct T_unbind_req *ubr;
	mblk_t *mp;
	int error;

	ASSERT(MUTEX_HELD(&so->so_lock));
	ASSERT(discon_mp);
	ASSERT(discon_mp->b_rptr);

	tpr = (union T_primitives *)discon_mp->b_rptr;
	ASSERT(tpr->type == T_DISCON_IND);

	vp = SOTOV(so);
	stp = vp->v_stream;
	ASSERT(stp);

	/*
	 * Not a listener
	 */
	ASSERT((so->so_state & SS_ACCEPTCONN) == 0);

	/*
	 * This assumes that the name space for DISCON_reason
	 * is the errno name space.
	 */
	soisdisconnected(so, tpr->discon_ind.DISCON_reason);

	/*
	 * Unbind with the transport without blocking.
	 * If we've already received a T_DISCON_IND do not unbind.
	 *
	 * If there is no preallocated unbind message, we have already
	 * unbound with the transport
	 *
	 * If the socket is not bound, no need to unbind.
	 */
	mp = so->so_unbind_mp;
	if (mp == NULL) {
		ASSERT(!(so->so_state & SS_ISBOUND));
		mutex_exit(&so->so_lock);
	} else if (!(so->so_state & SS_ISBOUND))  {
		mutex_exit(&so->so_lock);
	} else {
		so->so_unbind_mp = NULL;

		/*
		 * Is another T_DISCON_IND being processed.
		 */
		ASSERT((so->so_flag & SOASYNC_UNBIND) == 0);

		/*
		 * Make strsock_proto ignore T_OK_ACK and T_ERROR_ACK for
		 * this unbind. Set SOASYNC_UNBIND. This should be cleared
		 * only after we receive the ACK in strsock_proto.
		 */
		so->so_flag |= SOASYNC_UNBIND;
		ASSERT(!(so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING)));
		so->so_state &= ~(SS_ISBOUND|SS_ACCEPTCONN|SS_LADDR_VALID);
		mutex_exit(&so->so_lock);

		/*
		 * Send down T_UNBIND_REQ ignoring flow control.
		 * XXX Assumes that MSG_IGNFLOW implies that this thread
		 * does not run service procedures.
		 */
		ASSERT(DB_TYPE(mp) == M_PROTO);
		ubr = (struct T_unbind_req *)mp->b_rptr;
		mp->b_wptr += sizeof (*ubr);
		ubr->PRIM_type = T_UNBIND_REQ;

		/*
		 * Flush the read and write side (except stream head read queue)
		 * and send down T_UNBIND_REQ.
		 */
		(void) putnextctl1(strvp2wq(SOTOV(so)), M_FLUSH, FLUSHRW);
		error = kstrputmsg(SOTOV(so), mp, NULL, 0, 0,
		    MSG_BAND|MSG_HOLDSIG|MSG_IGNERROR|MSG_IGNFLOW, 0);
		/* LINTED - warning: statement has no consequent: if */
		if (error) {
			eprintsoline(so, error);
		}
	}

	if (tpr->discon_ind.DISCON_reason != 0)
		strsetrerror(SOTOV(so), 0, 0, sogetrderr);
	strsetwerror(SOTOV(so), 0, 0, sogetwrerr);
	strseteof(SOTOV(so), 1);
	/*
	 * strseteof takes care of read side wakeups,
	 * pollwakeups, and signals.
	 */
	dprintso(so, 1, ("T_DISCON_IND: error %d\n", so->so_error));
	freemsg(discon_mp);


	pollwakeup(&stp->sd_pollist, POLLOUT);
	mutex_enter(&stp->sd_lock);

	/*
	 * Wake sleeping write
	 */
	if (stp->sd_flag & WSLEEP) {
		stp->sd_flag &= ~WSLEEP;
		cv_broadcast(&stp->sd_wrq->q_wait);
	}

	/*
	 * strsendsig can handle multiple signals with a
	 * single call.  Send SIGPOLL for S_OUTPUT event.
	 */
	if (stp->sd_sigflags & S_OUTPUT)
		strsendsig(stp->sd_siglist, S_OUTPUT, 0, 0);

	mutex_exit(&stp->sd_lock);
	mutex_enter(&so->so_lock);
}

/*
 * This routine is registered with the stream head to receive M_PROTO
 * and M_PCPROTO messages.
 *
 * Returns NULL if the message was consumed.
 * Returns an mblk to make that mblk be processed (and queued) by the stream
 * head.
 *
 * Sets the return parameters (*wakeups, *firstmsgsigs, *allmsgsigs, and
 * *pollwakeups) for the stream head to take action on. Note that since
 * sockets always deliver SIGIO for every new piece of data this routine
 * never sets *firstmsgsigs; any signals are returned in *allmsgsigs.
 *
 * This routine handles all data related TPI messages independent of
 * the type of the socket i.e. it doesn't care if T_UNITDATA_IND message
 * arrive on a SOCK_STREAM.
 */
static mblk_t *
strsock_proto(vnode_t *vp, mblk_t *mp,
		strwakeup_t *wakeups, strsigset_t *firstmsgsigs,
		strsigset_t *allmsgsigs, strpollset_t *pollwakeups)
{
	union T_primitives *tpr;
	struct sonode *so;

	so = VTOSO(vp);

	dprintso(so, 1, ("strsock_proto(%p, %p)\n", vp, mp));

	/* Set default return values */
	*firstmsgsigs = *wakeups = *allmsgsigs = *pollwakeups = 0;

	ASSERT(DB_TYPE(mp) == M_PROTO ||
	    DB_TYPE(mp) == M_PCPROTO);

	if (MBLKL(mp) < sizeof (tpr->type)) {
		/* The message is too short to even contain the primitive */
		zcmn_err(getzoneid(), CE_WARN,
		    "sockfs: Too short TPI message received. Len = %ld\n",
		    (ptrdiff_t)(MBLKL(mp)));
		freemsg(mp);
		return (NULL);
	}
	if (!__TPI_PRIM_ISALIGNED(mp->b_rptr)) {
		/* The read pointer is not aligned correctly for TPI */
		zcmn_err(getzoneid(), CE_WARN,
		    "sockfs: Unaligned TPI message received. rptr = %p\n",
		    (void *)mp->b_rptr);
		freemsg(mp);
		return (NULL);
	}
	tpr = (union T_primitives *)mp->b_rptr;
	dprintso(so, 1, ("strsock_proto: primitive %d\n", tpr->type));

	switch (tpr->type) {

	case T_DATA_IND:
		if (MBLKL(mp) < sizeof (struct T_data_ind)) {
			zcmn_err(getzoneid(), CE_WARN,
			    "sockfs: Too short T_DATA_IND. Len = %ld\n",
			    (ptrdiff_t)(MBLKL(mp)));
			freemsg(mp);
			return (NULL);
		}
		/*
		 * Ignore zero-length T_DATA_IND messages. These might be
		 * generated by some transports.
		 * This is needed to prevent read (which skips the M_PROTO
		 * part) to unexpectedly return 0 (or return EWOULDBLOCK
		 * on a non-blocking socket after select/poll has indicated
		 * that data is available).
		 */
		if (msgdsize(mp->b_cont) == 0) {
			dprintso(so, 0,
			    ("strsock_proto: zero length T_DATA_IND\n"));
			freemsg(mp);
			return (NULL);
		}
		*allmsgsigs = S_INPUT | S_RDNORM;
		*pollwakeups = POLLIN | POLLRDNORM;
		*wakeups = RSLEEP;
		return (mp);

	case T_UNITDATA_IND: {
		struct T_unitdata_ind	*tudi = &tpr->unitdata_ind;
		void			*addr;
		t_uscalar_t		addrlen;

		if (MBLKL(mp) < sizeof (struct T_unitdata_ind)) {
			zcmn_err(getzoneid(), CE_WARN,
			    "sockfs: Too short T_UNITDATA_IND. Len = %ld\n",
			    (ptrdiff_t)(MBLKL(mp)));
			freemsg(mp);
			return (NULL);
		}

		/* Is this is not a connected datagram socket? */
		if ((so->so_mode & SM_CONNREQUIRED) ||
		    !(so->so_state & SS_ISCONNECTED)) {
			/*
			 * Not a connected datagram socket. Look for
			 * the SO_UNIX_CLOSE option. If such an option is found
			 * discard the message (since it has no meaning
			 * unless connected).
			 */
			if (so->so_family == AF_UNIX && msgdsize(mp) == 0 &&
			    tudi->OPT_length != 0) {
				void *opt;
				t_uscalar_t optlen = tudi->OPT_length;

				opt = sogetoff(mp, tudi->OPT_offset,
				    optlen, __TPI_ALIGN_SIZE);
				if (opt == NULL) {
					/* The len/off falls outside mp */
					freemsg(mp);
					mutex_enter(&so->so_lock);
					soseterror(so, EPROTO);
					mutex_exit(&so->so_lock);
					zcmn_err(getzoneid(), CE_WARN,
					    "sockfs: T_unidata_ind with "
					    "invalid optlen/offset %u/%d\n",
					    optlen, tudi->OPT_offset);
					return (NULL);
				}
				if (so_getopt_unix_close(opt, optlen)) {
					freemsg(mp);
					return (NULL);
				}
			}
			*allmsgsigs = S_INPUT | S_RDNORM;
			*pollwakeups = POLLIN | POLLRDNORM;
			*wakeups = RSLEEP;
			if (audit_active)
				audit_sock(T_UNITDATA_IND, strvp2wq(vp),
				    mp, 0);
			return (mp);
		}

		/*
		 * A connect datagram socket. For AF_INET{,6} we verify that
		 * the source address matches the "connected to" address.
		 * The semantics of AF_UNIX sockets is to not verify
		 * the source address.
		 * Note that this source address verification is transport
		 * specific. Thus the real fix would be to extent TPI
		 * to allow T_CONN_REQ messages to be send to connectionless
		 * transport providers and always let the transport provider
		 * do whatever filtering is needed.
		 *
		 * The verification/filtering semantics for transports
		 * other than AF_INET and AF_UNIX are unknown. The choice
		 * would be to either filter using bcmp or let all messages
		 * get through. This code does not filter other address
		 * families since this at least allows the application to
		 * work around any missing filtering.
		 *
		 * XXX Should we move filtering to UDP/ICMP???
		 * That would require passing e.g. a T_DISCON_REQ to UDP
		 * when the socket becomes unconnected.
		 */
		addrlen = tudi->SRC_length;
		/*
		 * The alignment restriction is really to strict but
		 * we want enough alignment to inspect the fields of
		 * a sockaddr_in.
		 */
		addr = sogetoff(mp, tudi->SRC_offset, addrlen,
		    __TPI_ALIGN_SIZE);
		if (addr == NULL) {
			freemsg(mp);
			mutex_enter(&so->so_lock);
			soseterror(so, EPROTO);
			mutex_exit(&so->so_lock);
			zcmn_err(getzoneid(), CE_WARN,
			    "sockfs: T_unidata_ind with invalid "
			    "addrlen/offset %u/%d\n",
			    addrlen, tudi->SRC_offset);
			return (NULL);
		}

		if (so->so_family == AF_INET) {
			/*
			 * For AF_INET we allow wildcarding both sin_addr
			 * and sin_port.
			 */
			struct sockaddr_in *faddr, *sin;

			/* Prevent so_faddr_sa from changing while accessed */
			mutex_enter(&so->so_lock);
			ASSERT(so->so_faddr_len ==
			    (socklen_t)sizeof (struct sockaddr_in));
			faddr = (struct sockaddr_in *)so->so_faddr_sa;
			sin = (struct sockaddr_in *)addr;
			if (addrlen !=
			    (t_uscalar_t)sizeof (struct sockaddr_in) ||
			    (sin->sin_addr.s_addr != faddr->sin_addr.s_addr &&
			    faddr->sin_addr.s_addr != INADDR_ANY) ||
			    (so->so_type != SOCK_RAW &&
			    sin->sin_port != faddr->sin_port &&
			    faddr->sin_port != 0)) {
#ifdef DEBUG
				dprintso(so, 0,
				    ("sockfs: T_UNITDATA_IND mismatch: %s",
				    pr_addr(so->so_family,
				    (struct sockaddr *)addr,
				    addrlen)));
				dprintso(so, 0, (" - %s\n",
				    pr_addr(so->so_family, so->so_faddr_sa,
				    (t_uscalar_t)so->so_faddr_len)));
#endif /* DEBUG */
				mutex_exit(&so->so_lock);
				freemsg(mp);
				return (NULL);
			}
			mutex_exit(&so->so_lock);
		} else if (so->so_family == AF_INET6) {
			/*
			 * For AF_INET6 we allow wildcarding both sin6_addr
			 * and sin6_port.
			 */
			struct sockaddr_in6 *faddr6, *sin6;
			static struct in6_addr zeroes; /* inits to all zeros */

			/* Prevent so_faddr_sa from changing while accessed */
			mutex_enter(&so->so_lock);
			ASSERT(so->so_faddr_len ==
			    (socklen_t)sizeof (struct sockaddr_in6));
			faddr6 = (struct sockaddr_in6 *)so->so_faddr_sa;
			sin6 = (struct sockaddr_in6 *)addr;
			/* XXX could we get a mapped address ::ffff:0.0.0.0 ? */
			if (addrlen !=
			    (t_uscalar_t)sizeof (struct sockaddr_in6) ||
			    (!IN6_ARE_ADDR_EQUAL(&sin6->sin6_addr,
			    &faddr6->sin6_addr) &&
			    !IN6_ARE_ADDR_EQUAL(&faddr6->sin6_addr, &zeroes)) ||
			    (so->so_type != SOCK_RAW &&
			    sin6->sin6_port != faddr6->sin6_port &&
			    faddr6->sin6_port != 0)) {
#ifdef DEBUG
				dprintso(so, 0,
				    ("sockfs: T_UNITDATA_IND mismatch: %s",
				    pr_addr(so->so_family,
				    (struct sockaddr *)addr,
				    addrlen)));
				dprintso(so, 0, (" - %s\n",
				    pr_addr(so->so_family, so->so_faddr_sa,
				    (t_uscalar_t)so->so_faddr_len)));
#endif /* DEBUG */
				mutex_exit(&so->so_lock);
				freemsg(mp);
				return (NULL);
			}
			mutex_exit(&so->so_lock);
		} else if (so->so_family == AF_UNIX &&
		    msgdsize(mp->b_cont) == 0 &&
		    tudi->OPT_length != 0) {
			/*
			 * Attempt to extract AF_UNIX
			 * SO_UNIX_CLOSE indication from options.
			 */
			void *opt;
			t_uscalar_t optlen = tudi->OPT_length;

			opt = sogetoff(mp, tudi->OPT_offset,
			    optlen, __TPI_ALIGN_SIZE);
			if (opt == NULL) {
				/* The len/off falls outside mp */
				freemsg(mp);
				mutex_enter(&so->so_lock);
				soseterror(so, EPROTO);
				mutex_exit(&so->so_lock);
				zcmn_err(getzoneid(), CE_WARN,
				    "sockfs: T_unidata_ind with invalid "
				    "optlen/offset %u/%d\n",
				    optlen, tudi->OPT_offset);
				return (NULL);
			}
			/*
			 * If we received a unix close indication mark the
			 * socket and discard this message.
			 */
			if (so_getopt_unix_close(opt, optlen)) {
				mutex_enter(&so->so_lock);
				sobreakconn(so, ECONNRESET);
				mutex_exit(&so->so_lock);
				strsetrerror(SOTOV(so), 0, 0, sogetrderr);
				freemsg(mp);
				*pollwakeups = POLLIN | POLLRDNORM;
				*allmsgsigs = S_INPUT | S_RDNORM;
				*wakeups = RSLEEP;
				return (NULL);
			}
		}
		*allmsgsigs = S_INPUT | S_RDNORM;
		*pollwakeups = POLLIN | POLLRDNORM;
		*wakeups = RSLEEP;
		return (mp);
	}

	case T_OPTDATA_IND: {
		struct T_optdata_ind	*tdi = &tpr->optdata_ind;

		if (MBLKL(mp) < sizeof (struct T_optdata_ind)) {
			zcmn_err(getzoneid(), CE_WARN,
			    "sockfs: Too short T_OPTDATA_IND. Len = %ld\n",
			    (ptrdiff_t)(MBLKL(mp)));
			freemsg(mp);
			return (NULL);
		}
		/*
		 * Allow zero-length messages carrying options.
		 * This is used when carrying the SO_UNIX_CLOSE option.
		 */
		if (so->so_family == AF_UNIX && msgdsize(mp->b_cont) == 0 &&
		    tdi->OPT_length != 0) {
			/*
			 * Attempt to extract AF_UNIX close indication
			 * from the options. Ignore any other options -
			 * those are handled once the message is removed
			 * from the queue.
			 * The close indication message should not carry data.
			 */
			void *opt;
			t_uscalar_t optlen = tdi->OPT_length;

			opt = sogetoff(mp, tdi->OPT_offset,
			    optlen, __TPI_ALIGN_SIZE);
			if (opt == NULL) {
				/* The len/off falls outside mp */
				freemsg(mp);
				mutex_enter(&so->so_lock);
				soseterror(so, EPROTO);
				mutex_exit(&so->so_lock);
				zcmn_err(getzoneid(), CE_WARN,
				    "sockfs: T_optdata_ind with invalid "
				    "optlen/offset %u/%d\n",
				    optlen, tdi->OPT_offset);
				return (NULL);
			}
			/*
			 * If we received a close indication mark the
			 * socket and discard this message.
			 */
			if (so_getopt_unix_close(opt, optlen)) {
				mutex_enter(&so->so_lock);
				socantsendmore(so);
				mutex_exit(&so->so_lock);
				strsetwerror(SOTOV(so), 0, 0, sogetwrerr);
				freemsg(mp);
				return (NULL);
			}
		}
		*allmsgsigs = S_INPUT | S_RDNORM;
		*pollwakeups = POLLIN | POLLRDNORM;
		*wakeups = RSLEEP;
		return (mp);
	}

	case T_EXDATA_IND: {
		mblk_t		*mctl, *mdata;
		mblk_t *lbp;
		union T_primitives *tprp;
		struct stdata   *stp;
		queue_t *qp;

		if (MBLKL(mp) < sizeof (struct T_exdata_ind)) {
			zcmn_err(getzoneid(), CE_WARN,
			    "sockfs: Too short T_EXDATA_IND. Len = %ld\n",
			    (ptrdiff_t)(MBLKL(mp)));
			freemsg(mp);
			return (NULL);
		}
		/*
		 * Ignore zero-length T_EXDATA_IND messages. These might be
		 * generated by some transports.
		 *
		 * This is needed to prevent read (which skips the M_PROTO
		 * part) to unexpectedly return 0 (or return EWOULDBLOCK
		 * on a non-blocking socket after select/poll has indicated
		 * that data is available).
		 */
		dprintso(so, 1,
		    ("T_EXDATA_IND(%p): counts %d/%d state %s\n",
		    vp, so->so_oobsigcnt, so->so_oobcnt,
		    pr_state(so->so_state, so->so_mode)));

		if (msgdsize(mp->b_cont) == 0) {
			dprintso(so, 0,
			    ("strsock_proto: zero length T_EXDATA_IND\n"));
			freemsg(mp);
			return (NULL);
		}

		/*
		 * Split into the T_EXDATA_IND and the M_DATA part.
		 * We process these three pieces separately:
		 *	signal generation
		 *	handling T_EXDATA_IND
		 *	handling M_DATA component
		 */
		mctl = mp;
		mdata = mctl->b_cont;
		mctl->b_cont = NULL;
		mutex_enter(&so->so_lock);
		so_oob_sig(so, 0, allmsgsigs, pollwakeups);
		mctl = so_oob_exdata(so, mctl, allmsgsigs, pollwakeups);
		mdata = so_oob_data(so, mdata, allmsgsigs, pollwakeups);

		stp = vp->v_stream;
		ASSERT(stp != NULL);
		qp = _RD(stp->sd_wrq);

		mutex_enter(QLOCK(qp));
		lbp = qp->q_last;

		/*
		 * We want to avoid queueing up a string of T_EXDATA_IND
		 * messages with no intervening data messages at the stream
		 * head. These messages contribute to the total message
		 * count. Eventually this can lead to STREAMS flow contol
		 * and also cause TCP to advertise a zero window condition
		 * to the peer. This can happen in the degenerate case where
		 * the sender and receiver exchange only OOB data. The sender
		 * only sends messages with MSG_OOB flag and the receiver
		 * receives only MSG_OOB messages and does not use SO_OOBINLINE.
		 * An example of this scenario has been reported in applications
		 * that use OOB data to exchange heart beats. Flow control
		 * relief will never happen if the application only reads OOB
		 * data which is done directly by sorecvoob() and the
		 * T_EXDATA_IND messages at the streamhead won't be consumed.
		 * Note that there is no correctness issue in compressing the
		 * string of T_EXDATA_IND messages into a single T_EXDATA_IND
		 * message. A single read that does not specify MSG_OOB will
		 * read across all the marks in a loop in sotpi_recvmsg().
		 * Each mark is individually distinguishable only if the
		 * T_EXDATA_IND messages are separated by data messages.
		 */
		if ((qp->q_first != NULL) && (DB_TYPE(lbp) == M_PROTO)) {
			tprp = (union T_primitives *)lbp->b_rptr;
			if ((tprp->type == T_EXDATA_IND) &&
			    !(so->so_options & SO_OOBINLINE)) {

				/*
				 * free the new M_PROTO message
				 */
				freemsg(mctl);

				/*
				 * adjust the OOB count and OOB	signal count
				 * just incremented for the new OOB data.
				 */
				so->so_oobcnt--;
				so->so_oobsigcnt--;
				mutex_exit(QLOCK(qp));
				mutex_exit(&so->so_lock);
				return (NULL);
			}
		}
		mutex_exit(QLOCK(qp));

		/*
		 * Pass the T_EXDATA_IND and the M_DATA back separately
		 * by using b_next linkage. (The stream head will queue any
		 * b_next linked messages separately.) This is needed
		 * since MSGMARK applies to the last by of the message
		 * hence we can not have any M_DATA component attached
		 * to the marked T_EXDATA_IND. Note that the stream head
		 * will not consolidate M_DATA messages onto an MSGMARK'ed
		 * message in order to preserve the constraint that
		 * the T_EXDATA_IND always is a separate message.
		 */
		ASSERT(mctl != NULL);
		mctl->b_next = mdata;
		mp = mctl;
#ifdef DEBUG
		if (mdata == NULL) {
			dprintso(so, 1,
			    ("after outofline T_EXDATA_IND(%p): "
			    "counts %d/%d  poll 0x%x sig 0x%x state %s\n",
			    vp, so->so_oobsigcnt,
			    so->so_oobcnt, *pollwakeups, *allmsgsigs,
			    pr_state(so->so_state, so->so_mode)));
		} else {
			dprintso(so, 1,
			    ("after inline T_EXDATA_IND(%p): "
			    "counts %d/%d  poll 0x%x sig 0x%x state %s\n",
			    vp, so->so_oobsigcnt,
			    so->so_oobcnt, *pollwakeups, *allmsgsigs,
			    pr_state(so->so_state, so->so_mode)));
		}
#endif /* DEBUG */
		mutex_exit(&so->so_lock);
		*wakeups = RSLEEP;
		return (mp);
	}

	case T_CONN_CON: {
		struct T_conn_con	*conn_con;
		void			*addr;
		t_uscalar_t		addrlen;

		/*
		 * Verify the state, update the state to ISCONNECTED,
		 * record the potentially new address in the message,
		 * and drop the message.
		 */
		if (MBLKL(mp) < sizeof (struct T_conn_con)) {
			zcmn_err(getzoneid(), CE_WARN,
			    "sockfs: Too short T_CONN_CON. Len = %ld\n",
			    (ptrdiff_t)(MBLKL(mp)));
			freemsg(mp);
			return (NULL);
		}

		mutex_enter(&so->so_lock);
		if ((so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING)) !=
		    SS_ISCONNECTING) {
			mutex_exit(&so->so_lock);
			dprintso(so, 1,
			    ("T_CONN_CON: state %x\n", so->so_state));
			freemsg(mp);
			return (NULL);
		}

		conn_con = &tpr->conn_con;
		addrlen = conn_con->RES_length;
		/*
		 * Allow the address to be of different size than sent down
		 * in the T_CONN_REQ as long as it doesn't exceed the maxlen.
		 * For AF_UNIX require the identical length.
		 */
		if (so->so_family == AF_UNIX ?
		    addrlen != (t_uscalar_t)sizeof (so->so_ux_laddr) :
		    addrlen > (t_uscalar_t)so->so_faddr_maxlen) {
			zcmn_err(getzoneid(), CE_WARN,
			    "sockfs: T_conn_con with different "
			    "length %u/%d\n",
			    addrlen, conn_con->RES_length);
			soisdisconnected(so, EPROTO);
			mutex_exit(&so->so_lock);
			strsetrerror(SOTOV(so), 0, 0, sogetrderr);
			strsetwerror(SOTOV(so), 0, 0, sogetwrerr);
			strseteof(SOTOV(so), 1);
			freemsg(mp);
			/*
			 * strseteof takes care of read side wakeups,
			 * pollwakeups, and signals.
			 */
			*wakeups = WSLEEP;
			*allmsgsigs = S_OUTPUT;
			*pollwakeups = POLLOUT;
			return (NULL);
		}
		addr = sogetoff(mp, conn_con->RES_offset, addrlen, 1);
		if (addr == NULL) {
			zcmn_err(getzoneid(), CE_WARN,
			    "sockfs: T_conn_con with invalid "
			    "addrlen/offset %u/%d\n",
			    addrlen, conn_con->RES_offset);
			mutex_exit(&so->so_lock);
			strsetrerror(SOTOV(so), 0, 0, sogetrderr);
			strsetwerror(SOTOV(so), 0, 0, sogetwrerr);
			strseteof(SOTOV(so), 1);
			freemsg(mp);
			/*
			 * strseteof takes care of read side wakeups,
			 * pollwakeups, and signals.
			 */
			*wakeups = WSLEEP;
			*allmsgsigs = S_OUTPUT;
			*pollwakeups = POLLOUT;
			return (NULL);
		}

		/*
		 * Save for getpeername.
		 */
		if (so->so_family != AF_UNIX) {
			so->so_faddr_len = (socklen_t)addrlen;
			ASSERT(so->so_faddr_len <= so->so_faddr_maxlen);
			bcopy(addr, so->so_faddr_sa, addrlen);
			so->so_state |= SS_FADDR_VALID;
		}

		if (so->so_peercred != NULL)
			crfree(so->so_peercred);
		so->so_peercred = DB_CRED(mp);
		so->so_cpid = DB_CPID(mp);
		if (so->so_peercred != NULL)
			crhold(so->so_peercred);

		/* Wakeup anybody sleeping in sowaitconnected */
		soisconnected(so);
		mutex_exit(&so->so_lock);

		/*
		 * The socket is now available for sending data.
		 */
		*wakeups = WSLEEP;
		*allmsgsigs = S_OUTPUT;
		*pollwakeups = POLLOUT;
		freemsg(mp);
		return (NULL);
	}

	/*
	 * Extra processing in case of an SSL proxy, before queuing or
	 * forwarding to the fallback endpoint
	 */
	case T_SSL_PROXY_CONN_IND:
	case T_CONN_IND:
		/*
		 * Verify the min size and queue the message on
		 * the so_conn_ind_head/tail list.
		 */
		if (MBLKL(mp) < sizeof (struct T_conn_ind)) {
			zcmn_err(getzoneid(), CE_WARN,
			    "sockfs: Too short T_CONN_IND. Len = %ld\n",
			    (ptrdiff_t)(MBLKL(mp)));
			freemsg(mp);
			return (NULL);
		}

		if (audit_active)
			audit_sock(T_CONN_IND, strvp2wq(vp), mp, 0);
		if (!(so->so_state & SS_ACCEPTCONN)) {
			zcmn_err(getzoneid(), CE_WARN,
			    "sockfs: T_conn_ind on non-listening socket\n");
			freemsg(mp);
			return (NULL);
		}

		if (tpr->type == T_SSL_PROXY_CONN_IND && mp->b_cont == NULL) {
			/* No context: need to fall back */
			struct sonode *fbso;
			stdata_t *fbstp;

			tpr->type = T_CONN_IND;

			fbso = kssl_find_fallback(so->so_kssl_ent);

			/*
			 * No fallback: the remote will timeout and
			 * disconnect.
			 */
			if (fbso == NULL) {
				freemsg(mp);
				return (NULL);
			}
			fbstp = SOTOV(fbso)->v_stream;
			qreply(fbstp->sd_wrq->q_next, mp);
			return (NULL);
		}
		soqueueconnind(so, mp);
		*allmsgsigs = S_INPUT | S_RDNORM;
		*pollwakeups = POLLIN | POLLRDNORM;
		*wakeups = RSLEEP;
		return (NULL);

	case T_ORDREL_IND:
		if (MBLKL(mp) < sizeof (struct T_ordrel_ind)) {
			zcmn_err(getzoneid(), CE_WARN,
			    "sockfs: Too short T_ORDREL_IND. Len = %ld\n",
			    (ptrdiff_t)(MBLKL(mp)));
			freemsg(mp);
			return (NULL);
		}

		/*
		 * Some providers send this when not fully connected.
		 * SunLink X.25 needs to retrieve disconnect reason after
		 * disconnect for compatibility. It uses T_ORDREL_IND
		 * instead of T_DISCON_IND so that it may use the
		 * endpoint after a connect failure to retrieve the
		 * reason using an ioctl. Thus we explicitly clear
		 * SS_ISCONNECTING here for SunLink X.25.
		 * This is a needed TPI violation.
		 */
		mutex_enter(&so->so_lock);
		so->so_state &= ~SS_ISCONNECTING;
		socantrcvmore(so);
		mutex_exit(&so->so_lock);
		strseteof(SOTOV(so), 1);
		/*
		 * strseteof takes care of read side wakeups,
		 * pollwakeups, and signals.
		 */
		freemsg(mp);
		return (NULL);

	case T_DISCON_IND:
		if (MBLKL(mp) < sizeof (struct T_discon_ind)) {
			zcmn_err(getzoneid(), CE_WARN,
			    "sockfs: Too short T_DISCON_IND. Len = %ld\n",
			    (ptrdiff_t)(MBLKL(mp)));
			freemsg(mp);
			return (NULL);
		}
		if (so->so_state & SS_ACCEPTCONN) {
			/*
			 * This is a listener. Look for a queued T_CONN_IND
			 * with a matching sequence number and remove it
			 * from the list.
			 * It is normal to not find the sequence number since
			 * the soaccept might have already dequeued it
			 * (in which case the T_CONN_RES will fail with
			 * TBADSEQ).
			 */
			(void) soflushconnind(so, tpr->discon_ind.SEQ_number);
			freemsg(mp);
			return (0);
		}

		/*
		 * Not a listener
		 *
		 * If SS_CANTRCVMORE for AF_UNIX ignore the discon_reason.
		 * Such a discon_ind appears when the peer has first done
		 * a shutdown() followed by a close() in which case we just
		 * want to record socantsendmore.
		 * In this case sockfs first receives a T_ORDREL_IND followed
		 * by a T_DISCON_IND.
		 * Note that for other transports (e.g. TCP) we need to handle
		 * the discon_ind in this case since it signals an error.
		 */
		mutex_enter(&so->so_lock);
		if ((so->so_state & SS_CANTRCVMORE) &&
		    (so->so_family == AF_UNIX)) {
			socantsendmore(so);
			mutex_exit(&so->so_lock);
			strsetwerror(SOTOV(so), 0, 0, sogetwrerr);
			dprintso(so, 1,
			    ("T_DISCON_IND: error %d\n", so->so_error));
			freemsg(mp);
			/*
			 * Set these variables for caller to process them.
			 * For the else part where T_DISCON_IND is processed,
			 * this will be done in the function being called
			 * (strsock_discon_ind())
			 */
			*wakeups = WSLEEP;
			*allmsgsigs = S_OUTPUT;
			*pollwakeups = POLLOUT;
		} else if (so->so_flag & (SOASYNC_UNBIND | SOLOCKED)) {
			/*
			 * Deferred processing of T_DISCON_IND
			 */
			so_save_discon_ind(so, mp, strsock_discon_ind);
			mutex_exit(&so->so_lock);
		} else {
			/*
			 * Process T_DISCON_IND now
			 */
			(void) strsock_discon_ind(so, mp);
			mutex_exit(&so->so_lock);
		}
		return (NULL);

	case T_UDERROR_IND: {
		struct T_uderror_ind	*tudi = &tpr->uderror_ind;
		void			*addr;
		t_uscalar_t		addrlen;
		int			error;

		dprintso(so, 0,
		    ("T_UDERROR_IND: error %d\n", tudi->ERROR_type));

		if (MBLKL(mp) < sizeof (struct T_uderror_ind)) {
			zcmn_err(getzoneid(), CE_WARN,
			    "sockfs: Too short T_UDERROR_IND. Len = %ld\n",
			    (ptrdiff_t)(MBLKL(mp)));
			freemsg(mp);
			return (NULL);
		}
		/* Ignore on connection-oriented transports */
		if (so->so_mode & SM_CONNREQUIRED) {
			freemsg(mp);
			eprintsoline(so, 0);
			zcmn_err(getzoneid(), CE_WARN,
			    "sockfs: T_uderror_ind on connection-oriented "
			    "transport\n");
			return (NULL);
		}
		addrlen = tudi->DEST_length;
		addr = sogetoff(mp, tudi->DEST_offset, addrlen, 1);
		if (addr == NULL) {
			zcmn_err(getzoneid(), CE_WARN,
			    "sockfs: T_uderror_ind with invalid "
			    "addrlen/offset %u/%d\n",
			    addrlen, tudi->DEST_offset);
			freemsg(mp);
			return (NULL);
		}

		/* Verify source address for connected socket. */
		mutex_enter(&so->so_lock);
		if (so->so_state & SS_ISCONNECTED) {
			void *faddr;
			t_uscalar_t faddr_len;
			boolean_t match = B_FALSE;

			switch (so->so_family) {
			case AF_INET: {
				/* Compare just IP address and port */
				struct sockaddr_in *sin1, *sin2;

				sin1 = (struct sockaddr_in *)so->so_faddr_sa;
				sin2 = (struct sockaddr_in *)addr;
				if (addrlen == sizeof (struct sockaddr_in) &&
				    sin1->sin_port == sin2->sin_port &&
				    sin1->sin_addr.s_addr ==
				    sin2->sin_addr.s_addr)
					match = B_TRUE;
				break;
			}
			case AF_INET6: {
				/* Compare just IP address and port. Not flow */
				struct sockaddr_in6 *sin1, *sin2;

				sin1 = (struct sockaddr_in6 *)so->so_faddr_sa;
				sin2 = (struct sockaddr_in6 *)addr;
				if (addrlen == sizeof (struct sockaddr_in6) &&
				    sin1->sin6_port == sin2->sin6_port &&
				    IN6_ARE_ADDR_EQUAL(&sin1->sin6_addr,
				    &sin2->sin6_addr))
					match = B_TRUE;
				break;
			}
			case AF_UNIX:
				faddr = &so->so_ux_faddr;
				faddr_len =
				    (t_uscalar_t)sizeof (so->so_ux_faddr);
				if (faddr_len == addrlen &&
				    bcmp(addr, faddr, addrlen) == 0)
					match = B_TRUE;
				break;
			default:
				faddr = so->so_faddr_sa;
				faddr_len = (t_uscalar_t)so->so_faddr_len;
				if (faddr_len == addrlen &&
				    bcmp(addr, faddr, addrlen) == 0)
					match = B_TRUE;
				break;
			}

			if (!match) {
#ifdef DEBUG
				dprintso(so, 0,
				    ("sockfs: T_UDERR_IND mismatch: %s - ",
				    pr_addr(so->so_family,
				    (struct sockaddr *)addr,
				    addrlen)));
				dprintso(so, 0, ("%s\n",
				    pr_addr(so->so_family, so->so_faddr_sa,
				    so->so_faddr_len)));
#endif /* DEBUG */
				mutex_exit(&so->so_lock);
				freemsg(mp);
				return (NULL);
			}
			/*
			 * Make the write error nonpersistent. If the error
			 * is zero we use ECONNRESET.
			 * This assumes that the name space for ERROR_type
			 * is the errno name space.
			 */
			if (tudi->ERROR_type != 0)
				error = tudi->ERROR_type;
			else
				error = ECONNRESET;

			soseterror(so, error);
			mutex_exit(&so->so_lock);
			strsetrerror(SOTOV(so), 0, 0, sogetrderr);
			strsetwerror(SOTOV(so), 0, 0, sogetwrerr);
			*wakeups = RSLEEP | WSLEEP;
			*allmsgsigs = S_INPUT | S_RDNORM | S_OUTPUT;
			*pollwakeups = POLLIN | POLLRDNORM | POLLOUT;
			freemsg(mp);
			return (NULL);
		}
		/*
		 * If the application asked for delayed errors
		 * record the T_UDERROR_IND so_eaddr_mp and the reason in
		 * so_delayed_error for delayed error posting. If the reason
		 * is zero use ECONNRESET.
		 * Note that delayed error indications do not make sense for
		 * AF_UNIX sockets since sendto checks that the destination
		 * address is valid at the time of the sendto.
		 */
		if (!(so->so_options & SO_DGRAM_ERRIND)) {
			mutex_exit(&so->so_lock);
			freemsg(mp);
			return (NULL);
		}
		if (so->so_eaddr_mp != NULL)
			freemsg(so->so_eaddr_mp);

		so->so_eaddr_mp = mp;
		if (tudi->ERROR_type != 0)
			error = tudi->ERROR_type;
		else
			error = ECONNRESET;
		so->so_delayed_error = (ushort_t)error;
		mutex_exit(&so->so_lock);
		return (NULL);
	}

	case T_ERROR_ACK:
		dprintso(so, 0,
		    ("strsock_proto: T_ERROR_ACK for %d, error %d/%d\n",
		    tpr->error_ack.ERROR_prim,
		    tpr->error_ack.TLI_error,
		    tpr->error_ack.UNIX_error));

		if (MBLKL(mp) < sizeof (struct T_error_ack)) {
			zcmn_err(getzoneid(), CE_WARN,
			    "sockfs: Too short T_ERROR_ACK. Len = %ld\n",
			    (ptrdiff_t)(MBLKL(mp)));
			freemsg(mp);
			return (NULL);
		}
		/*
		 * Check if we were waiting for the async message
		 */
		mutex_enter(&so->so_lock);
		if ((so->so_flag & SOASYNC_UNBIND) &&
		    tpr->error_ack.ERROR_prim == T_UNBIND_REQ) {
			so_unlock_single(so, SOASYNC_UNBIND);
			mutex_exit(&so->so_lock);
			freemsg(mp);
			return (NULL);
		}
		mutex_exit(&so->so_lock);
		soqueueack(so, mp);
		return (NULL);

	case T_OK_ACK:
		if (MBLKL(mp) < sizeof (struct T_ok_ack)) {
			zcmn_err(getzoneid(), CE_WARN,
			    "sockfs: Too short T_OK_ACK. Len = %ld\n",
			    (ptrdiff_t)(MBLKL(mp)));
			freemsg(mp);
			return (NULL);
		}
		/*
		 * Check if we were waiting for the async message
		 */
		mutex_enter(&so->so_lock);
		if ((so->so_flag & SOASYNC_UNBIND) &&
		    tpr->ok_ack.CORRECT_prim == T_UNBIND_REQ) {
			dprintso(so, 1,
			    ("strsock_proto: T_OK_ACK async unbind\n"));
			so_unlock_single(so, SOASYNC_UNBIND);
			mutex_exit(&so->so_lock);
			freemsg(mp);
			return (NULL);
		}
		mutex_exit(&so->so_lock);
		soqueueack(so, mp);
		return (NULL);

	case T_INFO_ACK:
		if (MBLKL(mp) < sizeof (struct T_info_ack)) {
			zcmn_err(getzoneid(), CE_WARN,
			    "sockfs: Too short T_INFO_ACK. Len = %ld\n",
			    (ptrdiff_t)(MBLKL(mp)));
			freemsg(mp);
			return (NULL);
		}
		soqueueack(so, mp);
		return (NULL);

	case T_CAPABILITY_ACK:
		/*
		 * A T_capability_ack need only be large enough to hold
		 * the PRIM_type and CAP_bits1 fields; checking for anything
		 * larger might reject a correct response from an older
		 * provider.
		 */
		if (MBLKL(mp) < 2 * sizeof (t_uscalar_t)) {
			zcmn_err(getzoneid(), CE_WARN,
			    "sockfs: Too short T_CAPABILITY_ACK. Len = %ld\n",
			    (ptrdiff_t)(MBLKL(mp)));
			freemsg(mp);
			return (NULL);
		}
		soqueueack(so, mp);
		return (NULL);

	case T_BIND_ACK:
		if (MBLKL(mp) < sizeof (struct T_bind_ack)) {
			zcmn_err(getzoneid(), CE_WARN,
			    "sockfs: Too short T_BIND_ACK. Len = %ld\n",
			    (ptrdiff_t)(MBLKL(mp)));
			freemsg(mp);
			return (NULL);
		}
		soqueueack(so, mp);
		return (NULL);

	case T_OPTMGMT_ACK:
		if (MBLKL(mp) < sizeof (struct T_optmgmt_ack)) {
			zcmn_err(getzoneid(), CE_WARN,
			    "sockfs: Too short T_OPTMGMT_ACK. Len = %ld\n",
			    (ptrdiff_t)(MBLKL(mp)));
			freemsg(mp);
			return (NULL);
		}
		soqueueack(so, mp);
		return (NULL);
	default:
#ifdef DEBUG
		zcmn_err(getzoneid(), CE_WARN,
		    "sockfs: unknown TPI primitive %d received\n",
		    tpr->type);
#endif /* DEBUG */
		freemsg(mp);
		return (NULL);
	}
}

/*
 * This routine is registered with the stream head to receive other
 * (non-data, and non-proto) messages.
 *
 * Returns NULL if the message was consumed.
 * Returns an mblk to make that mblk be processed by the stream head.
 *
 * Sets the return parameters (*wakeups, *firstmsgsigs, *allmsgsigs, and
 * *pollwakeups) for the stream head to take action on.
 */
static mblk_t *
strsock_misc(vnode_t *vp, mblk_t *mp,
		strwakeup_t *wakeups, strsigset_t *firstmsgsigs,
		strsigset_t *allmsgsigs, strpollset_t *pollwakeups)
{
	struct sonode *so;

	so = VTOSO(vp);

	dprintso(so, 1, ("strsock_misc(%p, %p, 0x%x)\n",
	    vp, mp, DB_TYPE(mp)));

	/* Set default return values */
	*wakeups = *allmsgsigs = *firstmsgsigs = *pollwakeups = 0;

	switch (DB_TYPE(mp)) {
	case M_PCSIG:
		/*
		 * This assumes that an M_PCSIG for the urgent data arrives
		 * before the corresponding T_EXDATA_IND.
		 *
		 * Note: Just like in SunOS 4.X and 4.4BSD a poll will be
		 * awoken before the urgent data shows up.
		 * For OOBINLINE this can result in select returning
		 * only exceptions as opposed to except|read.
		 */
		if (*mp->b_rptr == SIGURG) {
			mutex_enter(&so->so_lock);
			dprintso(so, 1,
			    ("SIGURG(%p): counts %d/%d state %s\n",
			    vp, so->so_oobsigcnt,
			    so->so_oobcnt,
			    pr_state(so->so_state, so->so_mode)));
			so_oob_sig(so, 1, allmsgsigs, pollwakeups);
			dprintso(so, 1,
			    ("after SIGURG(%p): counts %d/%d "
			    " poll 0x%x sig 0x%x state %s\n",
			    vp, so->so_oobsigcnt,
			    so->so_oobcnt, *pollwakeups, *allmsgsigs,
			    pr_state(so->so_state, so->so_mode)));
			mutex_exit(&so->so_lock);
		}
		freemsg(mp);
		return (NULL);

	case M_SIG:
	case M_HANGUP:
	case M_UNHANGUP:
	case M_ERROR:
		/* M_ERRORs etc are ignored */
		freemsg(mp);
		return (NULL);

	case M_FLUSH:
		/*
		 * Do not flush read queue. If the M_FLUSH
		 * arrives because of an impending T_discon_ind
		 * we still have to keep any queued data - this is part of
		 * socket semantics.
		 */
		if (*mp->b_rptr & FLUSHW) {
			*mp->b_rptr &= ~FLUSHR;
			return (mp);
		}
		freemsg(mp);
		return (NULL);

	default:
		return (mp);
	}
}


/* Register to receive signals for certain events */
int
so_set_asyncsigs(vnode_t *vp, pid_t pgrp, int events, int mode, cred_t *cr)
{
	struct strsigset ss;
	int32_t rval;

	/*
	 * Note that SOLOCKED will be set except for the call from soaccept().
	 */
	ASSERT(!mutex_owned(&VTOSO(vp)->so_lock));
	ss.ss_pid = pgrp;
	ss.ss_events = events;
	return (strioctl(vp, I_ESETSIG, (intptr_t)&ss, mode, K_TO_K, cr,
	    &rval));
}


/* Register for events matching the SS_ASYNC flag */
int
so_set_events(struct sonode *so, vnode_t *vp, cred_t *cr)
{
	int events = so->so_state & SS_ASYNC ?
	    S_RDBAND | S_BANDURG | S_RDNORM | S_OUTPUT :
	    S_RDBAND | S_BANDURG;

	return (so_set_asyncsigs(vp, so->so_pgrp, events, 0, cr));
}


/* Change the SS_ASYNC flag, and update signal delivery if needed */
int
so_flip_async(struct sonode *so, vnode_t *vp, int mode, cred_t *cr)
{
	ASSERT(mutex_owned(&so->so_lock));
	if (so->so_pgrp != 0) {
		int error;
		int events = so->so_state & SS_ASYNC ?		/* Old flag */
		    S_RDBAND | S_BANDURG :			/* New sigs */
		    S_RDBAND | S_BANDURG | S_RDNORM | S_OUTPUT;

		so_lock_single(so);
		mutex_exit(&so->so_lock);

		error = so_set_asyncsigs(vp, so->so_pgrp, events, mode, cr);

		mutex_enter(&so->so_lock);
		so_unlock_single(so, SOLOCKED);
		if (error)
			return (error);
	}
	so->so_state ^= SS_ASYNC;
	return (0);
}

/*
 * Set new pid/pgrp for SIGPOLL (or SIGIO for FIOASYNC mode), replacing
 * any existing one.  If passed zero, just clear the existing one.
 */
int
so_set_siggrp(struct sonode *so, vnode_t *vp, pid_t pgrp, int mode, cred_t *cr)
{
	int events = so->so_state & SS_ASYNC ?
	    S_RDBAND | S_BANDURG | S_RDNORM | S_OUTPUT :
	    S_RDBAND | S_BANDURG;
	int error;

	ASSERT(mutex_owned(&so->so_lock));

	/*
	 * Change socket process (group).
	 *
	 * strioctl (via so_set_asyncsigs) will perform permission check and
	 * also keep a PID_HOLD to prevent the pid from being reused.
	 */
	so_lock_single(so);
	mutex_exit(&so->so_lock);

	if (pgrp != 0) {
		dprintso(so, 1, ("setown: adding pgrp %d ev 0x%x\n",
		    pgrp, events));
		error = so_set_asyncsigs(vp, pgrp, events, mode, cr);
		if (error != 0) {
			eprintsoline(so, error);
			goto bad;
		}
	}
	/* Remove the previously registered process/group */
	if (so->so_pgrp != 0) {
		dprintso(so, 1, ("setown: removing pgrp %d\n", so->so_pgrp));
		error = so_set_asyncsigs(vp, so->so_pgrp, 0, mode, cr);
		if (error != 0) {
			eprintsoline(so, error);
			error = 0;
		}
	}
	mutex_enter(&so->so_lock);
	so_unlock_single(so, SOLOCKED);
	so->so_pgrp = pgrp;
	return (0);
bad:
	mutex_enter(&so->so_lock);
	so_unlock_single(so, SOLOCKED);
	return (error);
}



/*
 * Translate a TLI(/XTI) error into a system error as best we can.
 */
static const int tli_errs[] = {
		0,		/* no error	*/
		EADDRNOTAVAIL,  /* TBADADDR	*/
		ENOPROTOOPT,	/* TBADOPT	*/
		EACCES,		/* TACCES	*/
		EBADF,		/* TBADF	*/
		EADDRNOTAVAIL,	/* TNOADDR	*/
		EPROTO,		/* TOUTSTATE	*/
		ECONNABORTED,	/* TBADSEQ	*/
		0,		/* TSYSERR - will never get	*/
		EPROTO,		/* TLOOK - should never be sent by transport */
		EMSGSIZE,	/* TBADDATA	*/
		EMSGSIZE,	/* TBUFOVFLW	*/
		EPROTO,		/* TFLOW	*/
		EWOULDBLOCK,	/* TNODATA	*/
		EPROTO,		/* TNODIS	*/
		EPROTO,		/* TNOUDERR	*/
		EINVAL,		/* TBADFLAG	*/
		EPROTO,		/* TNOREL	*/
		EOPNOTSUPP,	/* TNOTSUPPORT	*/
		EPROTO,		/* TSTATECHNG	*/
		/* following represent error namespace expansion with XTI */
		EPROTO,		/* TNOSTRUCTYPE - never sent by transport */
		EPROTO,		/* TBADNAME - never sent by transport */
		EPROTO,		/* TBADQLEN - never sent by transport */
		EADDRINUSE,	/* TADDRBUSY	*/
		EBADF,		/* TINDOUT	*/
		EBADF,		/* TPROVMISMATCH */
		EBADF,		/* TRESQLEN	*/
		EBADF,		/* TRESADDR	*/
		EPROTO,		/* TQFULL - never sent by transport */
		EPROTO,		/* TPROTO	*/
};

static int
tlitosyserr(int terr)
{
	ASSERT(terr != TSYSERR);
	if (terr >= (sizeof (tli_errs) / sizeof (tli_errs[0])))
		return (EPROTO);
	else
		return (tli_errs[terr]);
}

/*
 * Sockfs sodirect STREAMS read put procedure. Called from sodirect enable
 * transport driver/module with an mblk_t chain.
 *
 * Note, we in-line putq() for the fast-path cases of q is empty, q_last and
 * bp are of type M_DATA. All other cases we call putq().
 *
 * On success a zero will be return, else an errno will be returned.
 */
int
sodput(sodirect_t *sodp, mblk_t *bp)
{
	queue_t		*q = sodp->sod_q;
	struct stdata	*stp = (struct stdata *)q->q_ptr;
	mblk_t		*nbp;
	int		ret;
	mblk_t		*last = q->q_last;
	int		bytecnt = 0;
	int		mblkcnt = 0;


	ASSERT(MUTEX_HELD(sodp->sod_lock));

	if (stp->sd_flag == STREOF) {
		ret = 0;
		goto error;
	}

	if (q->q_first == NULL) {
		/* Q empty, really fast fast-path */
		bp->b_prev = NULL;
		bp->b_next = NULL;
		q->q_first = bp;
		q->q_last = bp;

	} else if (last->b_datap->db_type == M_DATA &&
	    bp->b_datap->db_type == M_DATA) {
		/*
		 * Last mblk_t chain and bp are both type M_DATA so
		 * in-line putq() here, if the DBLK_UIOA state match
		 * add bp to the end of the current last chain, else
		 * start a new last chain with bp.
		 */
		if ((last->b_datap->db_flags & DBLK_UIOA) ==
		    (bp->b_datap->db_flags & DBLK_UIOA)) {
			/* Added to end */
			while ((nbp = last->b_cont) != NULL)
				last = nbp;
			last->b_cont = bp;
		} else {
			/* New last */
			last->b_next = bp;
			bp->b_next = NULL;
			bp->b_prev = last;
			q->q_last = bp;
		}
	} else {
		/*
		 * Can't use q_last so just call putq().
		 */
		(void) putq(q, bp);
		return (0);
	}

	/* Count bytes and mblk_t's */
	do {
		bytecnt += MBLKL(bp);
		mblkcnt++;
	} while ((bp = bp->b_cont) != NULL);
	q->q_count += bytecnt;
	q->q_mblkcnt += mblkcnt;

	/* Check for QFULL */
	if (q->q_count >= q->q_hiwat + sodp->sod_want ||
	    q->q_mblkcnt >= q->q_hiwat) {
		q->q_flag |= QFULL;
	}

	return (0);

error:
	do {
		if ((nbp = bp->b_next) != NULL)
			bp->b_next = NULL;
		freemsg(bp);
	} while ((bp = nbp) != NULL);

	return (ret);
}

/*
 * Sockfs sodirect read wakeup. Called from a sodirect enabled transport
 * driver/module to indicate that read-side data is available.
 *
 * On return the sodirect_t.lock mutex will be exited so this must be the
 * last sodirect_t call to guarantee atomic access of *sodp.
 */
void
sodwakeup(sodirect_t *sodp)
{
	queue_t		*q = sodp->sod_q;
	struct stdata	*stp = (struct stdata *)q->q_ptr;

	ASSERT(MUTEX_HELD(sodp->sod_lock));

	if (stp->sd_flag & RSLEEP) {
		stp->sd_flag &= ~RSLEEP;
		cv_broadcast(&q->q_wait);
	}

	if (stp->sd_rput_opt & SR_POLLIN) {
		stp->sd_rput_opt &= ~SR_POLLIN;
		mutex_exit(sodp->sod_lock);
		pollwakeup(&stp->sd_pollist, POLLIN | POLLRDNORM);
	} else
		mutex_exit(sodp->sod_lock);
}
