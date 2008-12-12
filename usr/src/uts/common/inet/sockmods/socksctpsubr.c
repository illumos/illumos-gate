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

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/strsubr.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>

#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/strsun.h>
#include <sys/signal.h>

#include <netinet/sctp.h>
#include <inet/sctp_itf.h>
#include <fs/sockfs/sockcommon.h>
#include "socksctp.h"

extern kmem_cache_t *sosctp_assoccache;
/*
 * Find a free association id. See os/fio.c file descriptor allocator
 * for description of the algorithm.
 */
sctp_assoc_t
sosctp_aid_get(struct sctp_sonode *ss)
{
	sctp_assoc_t id, size, ralloc;
	struct sctp_sa_id *assocs = ss->ss_assocs;

	ASSERT((ss->ss_maxassoc & (ss->ss_maxassoc + 1)) == 0);

	for (id = 1; (uint32_t)id < ss->ss_maxassoc; id |= id + 1) {
		size = id + 1;
		if (assocs[id].ssi_alloc == size)
			continue;
		for (ralloc = 0, size >>= 1; size != 0; size >>= 1) {
			ralloc += assocs[id + size].ssi_alloc;
			if (assocs[id].ssi_alloc == ralloc + size) {
				id += size;
				ralloc = 0;
			}
		}
		return (id);
	}
	return (-1);
}

/*
 * Allocate or free ID, depending on whether incr is 1 or -1
 */
void
sosctp_aid_reserve(struct sctp_sonode *ss, sctp_assoc_t id, int incr)
{
	struct sctp_sa_id *assocs = ss->ss_assocs;
	sctp_assoc_t pid;

	ASSERT((assocs[id].ssi_assoc == NULL && incr == 1) ||
	    (assocs[id].ssi_assoc != NULL && incr == -1));

	for (pid = id; pid >= 0; pid = (pid & (pid + 1)) - 1) {
		assocs[pid].ssi_alloc += incr;
	}
}

/*
 * Increase size of the ss_assocs array to accommodate at least maxid.
 * We keep the size of the form 2^n - 1 for benefit of sosctp_aid_get().
 */
int
sosctp_aid_grow(struct sctp_sonode *ss, sctp_assoc_t maxid, int kmflags)
{
	sctp_assoc_t newcnt, oldcnt;
	struct sctp_sa_id *newlist, *oldlist;

	ASSERT(MUTEX_HELD(&ss->ss_so.so_lock));
	for (newcnt = 1; newcnt <= maxid; newcnt = (newcnt << 1) | 1) {
		continue;
	}

	mutex_exit(&ss->ss_so.so_lock);
	newlist = kmem_alloc(newcnt * sizeof (struct sctp_sa_id), kmflags);
	mutex_enter(&ss->ss_so.so_lock);
	if (newlist == NULL) {
		return (-1);
	}
	oldcnt = ss->ss_maxassoc;
	if (newcnt <= oldcnt) {
		kmem_free(newlist, newcnt * sizeof (struct sctp_sa_id));
		return (0);
	}
	ASSERT((newcnt & (newcnt + 1)) == 0);
	oldlist = ss->ss_assocs;
	ss->ss_assocs = newlist;
	ss->ss_maxassoc = newcnt;

	bcopy(oldlist, newlist, oldcnt * sizeof (struct sctp_sa_id));
	bzero(newlist + oldcnt,
	    (newcnt - oldcnt) * sizeof (struct sctp_sa_id));
	if (oldlist != NULL) {
		kmem_free(oldlist, oldcnt * sizeof (struct sctp_sa_id));
	}
	return (0);
}

/*
 * Convert a id into a pointer to sctp_sockassoc structure.
 * Increments refcnt.
 */
int
sosctp_assoc(struct sctp_sonode *ss, sctp_assoc_t id, struct sctp_soassoc **ssa)
{
	ASSERT(ssa != NULL);
	ASSERT(MUTEX_HELD(&ss->ss_so.so_lock));
	if ((uint32_t)id >= ss->ss_maxassoc) {
		*ssa = NULL;
		return (EINVAL);
	}

	if ((*ssa = ss->ss_assocs[id].ssi_assoc) == NULL) {
		return (EINVAL);
	}
	if (((*ssa)->ssa_state & (SS_CANTSENDMORE|SS_CANTRCVMORE)) ==
	    (SS_CANTSENDMORE|SS_CANTRCVMORE)) {
		/*
		 * Disconnected connection, shouldn't be found anymore
		 */
		*ssa = NULL;
		return (ESHUTDOWN);
	}
	SSA_REFHOLD(*ssa)

	return (0);
}

/*
 * Can be called from upcall, or through system call.
 */
struct sctp_soassoc *
sosctp_assoc_create(struct sctp_sonode *ss, int kmflag)
{
	struct sctp_soassoc *ssa;

	ssa = kmem_cache_alloc(sosctp_assoccache, kmflag);
	if (ssa != NULL) {
		ssa->ssa_type = SOSCTP_ASSOC;
		ssa->ssa_refcnt = 1;
		ssa->ssa_sonode = ss;
		ssa->ssa_state = 0;
		ssa->ssa_error = 0;
#if 0
		ssa->ssa_txqueued = 0;
#endif
		ssa->ssa_snd_qfull = 0;
	}
	dprint(2, ("sosctp_assoc_create %p %p\n", (void *)ss, (void *)ssa));
	return (ssa);
}

void
sosctp_assoc_free(struct sctp_sonode *ss, struct sctp_soassoc *ssa)
{
	struct sonode *so = &ss->ss_so;

	dprint(2, ("sosctp_assoc_free %p %p (%d)\n", (void *)ss, (void *)ssa,
	    ssa->ssa_id));
	ASSERT(MUTEX_HELD(&so->so_lock));
	if (ssa->ssa_conn != NULL) {
		mutex_exit(&so->so_lock);

		sctp_recvd(ssa->ssa_conn, so->so_rcvbuf);
		(void) sctp_disconnect(ssa->ssa_conn);
		sctp_close(ssa->ssa_conn);

		mutex_enter(&so->so_lock);
		ssa->ssa_conn = NULL;
	}
	sosctp_aid_reserve(ss, ssa->ssa_id, -1);
	ss->ss_assocs[ssa->ssa_id].ssi_assoc = NULL;
	--ss->ss_assoccnt;
	kmem_cache_free(sosctp_assoccache, ssa);
}

/*
 * Pack the ancillary stuff taking care of alignment issues.
 * sctp_input_add_ancillary() packs the information as:
 * struct cmsghdr -> ancillary data + struct cmsghdr -> ancillary data + ...
 * In the next version of SCTP, sctp_input_add_ancillary() should
 * pack the information taking alignment into account, then we would
 * not need this routine.
 */
void
sosctp_pack_cmsg(const uchar_t *opt, struct nmsghdr *msg, int len)
{
	struct cmsghdr	*ocmsg;
	struct cmsghdr	*cmsg;
	int		optlen = 0;
	char		*cend;
	boolean_t	isaligned = B_TRUE;

	ocmsg = (struct cmsghdr *)opt;
	cend = (char *)opt + len;
	/* Figure out the length incl. alignment et. al. */
	for (;;) {
		if ((char *)(ocmsg + 1) > cend ||
		    ((char *)ocmsg + ocmsg->cmsg_len) > cend) {
			break;
		}
		if (isaligned && !ISALIGNED_cmsghdr(ocmsg))
			isaligned = B_FALSE;
		optlen += ROUNDUP_cmsglen(ocmsg->cmsg_len);
		if (ocmsg->cmsg_len > 0) {
			ocmsg = (struct cmsghdr *)
			    ((uchar_t *)ocmsg + ocmsg->cmsg_len);
		} else {
			break;
		}
	}
	/* Now allocate and copy */
	msg->msg_control = kmem_zalloc(optlen, KM_SLEEP);
	msg->msg_controllen = optlen;
	if (isaligned) {
		ASSERT(optlen == len);
		bcopy(opt, msg->msg_control, len);
		return;
	}
	cmsg = (struct cmsghdr *)msg->msg_control;
	ASSERT(ISALIGNED_cmsghdr(cmsg));
	ocmsg = (struct cmsghdr *)opt;
	cend = (char *)opt + len;
	for (;;) {
		if ((char *)(ocmsg + 1) > cend ||
		    ((char *)ocmsg + ocmsg->cmsg_len) > cend) {
			break;
		}
		bcopy(ocmsg, cmsg, ocmsg->cmsg_len);
		if (ocmsg->cmsg_len > 0) {
			cmsg = (struct cmsghdr *)((uchar_t *)cmsg +
			    ROUNDUP_cmsglen(ocmsg->cmsg_len));
			ASSERT(ISALIGNED_cmsghdr(cmsg));
			ocmsg = (struct cmsghdr *)
			    ((uchar_t *)ocmsg + ocmsg->cmsg_len);
		} else {
			break;
		}
	}
}

/*
 * Find cmsghdr of specified type
 */
struct cmsghdr *
sosctp_find_cmsg(const uchar_t *control, socklen_t clen, int type)
{
	struct cmsghdr *cmsg;
	char *cend;

	cmsg = (struct cmsghdr *)control;
	cend = (char *)control + clen;

	for (;;) {
		if ((char *)(cmsg + 1) > cend ||
		    ((char *)cmsg + cmsg->cmsg_len) > cend) {
			break;
		}
		if ((cmsg->cmsg_level == IPPROTO_SCTP) &&
		    (cmsg->cmsg_type == type)) {
			return (cmsg);
		}
		if (cmsg->cmsg_len > 0) {
			cmsg = CMSG_NEXT(cmsg);
		} else {
			break;
		}
	}
	return (NULL);
}

/*
 * Wait until the association is connected or there is an error.
 * fmode should contain any nonblocking flags.
 */
static int
sosctp_assoc_waitconnected(struct sctp_soassoc *ssa, int fmode)
{
	struct sonode *so = &ssa->ssa_sonode->ss_so;
	int error = 0;

	ASSERT((ssa->ssa_state & (SS_ISCONNECTED|SS_ISCONNECTING)) ||
	    ssa->ssa_error != 0);

	while ((ssa->ssa_state & (SS_ISCONNECTED|SS_ISCONNECTING)) ==
	    SS_ISCONNECTING && ssa->ssa_error == 0) {

		dprint(3, ("waiting for SS_ISCONNECTED on %p\n", (void *)so));
		if (fmode & (FNDELAY|FNONBLOCK))
			return (EINPROGRESS);

		if (so->so_state & SS_CLOSING)
			return (EINTR);
		if (!cv_wait_sig_swap(&so->so_state_cv, &so->so_lock)) {
			/*
			 * Return EINTR and let the application use
			 * nonblocking techniques for detecting when
			 * the connection has been established.
			 */
			return (EINTR);
		}
		dprint(3, ("awoken on %p\n", (void *)so));
	}
	if (ssa->ssa_error != 0) {
		error = ssa->ssa_error;
		ssa->ssa_error = 0;
		dprint(3, ("sosctp_assoc_waitconnected: error %d\n", error));
		return (error);
	}

	if (!(ssa->ssa_state & SS_ISCONNECTED)) {
		/*
		 * Another thread could have consumed so_error
		 * e.g. by calling read. - take from sowaitconnected()
		 */
		error = ECONNREFUSED;
		dprint(3, ("sosctp_waitconnected: error %d\n", error));
		return (error);
	}
	return (0);
}

/*
 * Called from connect(), sendmsg() when we need to create a new association.
 */
int
sosctp_assoc_createconn(struct sctp_sonode *ss, const struct sockaddr *name,
    socklen_t namelen, const uchar_t *control, socklen_t controllen, int fflag,
    struct cred *cr, struct sctp_soassoc **ssap)
{
	struct sonode *so = &ss->ss_so;
	struct sctp_soassoc *ssa;
	struct sockaddr_storage laddr;
	sctp_sockbuf_limits_t sbl;
	sctp_assoc_t id;
	int error;
	struct cmsghdr *cmsg;

	ASSERT(MUTEX_HELD(&so->so_lock));

	/*
	 * System needs to pick local endpoint
	 */
	if (!(so->so_state & SS_ISBOUND)) {
		bzero(&laddr, sizeof (laddr));
		laddr.ss_family = so->so_family;

		error = SOP_BIND(so, (struct sockaddr *)&laddr,
		    sizeof (laddr), _SOBIND_LOCK_HELD, cr);
		if (error) {
			*ssap = NULL;
			return (error);
		}
	}

	/*
	 * Create a new association, and call connect on that.
	 */
	for (;;) {
		id = sosctp_aid_get(ss);
		if (id != -1) {
			break;
		}
		/*
		 * Array not large enough; increase size.
		 */
		(void) sosctp_aid_grow(ss, ss->ss_maxassoc, KM_SLEEP);
	}
	++ss->ss_assoccnt;
	sosctp_aid_reserve(ss, id, 1);

	mutex_exit(&so->so_lock);

	ssa = sosctp_assoc_create(ss, KM_SLEEP);
	ssa->ssa_wroff = ss->ss_wroff;
	ssa->ssa_wrsize = ss->ss_wrsize;
	ssa->ssa_conn = sctp_create(ssa, (struct sctp_s *)so->so_proto_handle,
	    so->so_family, SCTP_CAN_BLOCK, &sosctp_assoc_upcalls, &sbl, cr);

	mutex_enter(&so->so_lock);
	ss->ss_assocs[id].ssi_assoc = ssa;
	ssa->ssa_id = id;
	if (ssa->ssa_conn == NULL) {
		ASSERT(ssa->ssa_refcnt == 1);
		sosctp_assoc_free(ss, ssa);
		*ssap = NULL;
		return (ENOMEM);
	}
	ssa->ssa_state |= SS_ISBOUND;

	sosctp_assoc_isconnecting(ssa);
	SSA_REFHOLD(ssa);
	mutex_exit(&so->so_lock);

	/*
	 * Can specify special init params
	 */
	cmsg = sosctp_find_cmsg(control, controllen, SCTP_INIT);
	if (cmsg != NULL) {
		error = sctp_set_opt(ssa->ssa_conn, IPPROTO_SCTP, SCTP_INITMSG,
		    cmsg + 1, cmsg->cmsg_len - sizeof (*cmsg));
		if (error != 0)
			goto ret_err;
	}

	if ((error = sctp_connect(ssa->ssa_conn, name, namelen)) != 0)
		goto ret_err;

	mutex_enter(&so->so_lock);
	/*
	 * Allow other threads to access the socket
	 */
	error = sosctp_assoc_waitconnected(ssa, fflag);

	switch (error) {
	case 0:
	case EINPROGRESS:
	case EALREADY:
	case EINTR:
		/* Non-fatal errors */
		break;
	default:
		/*
		 * Fatal errors.  It means that sctp_assoc_disconnected()
		 * must have been called.  So we only need to do a
		 * SSA_REFRELE() here to release our hold done above.
		 */
		ASSERT(ssa->ssa_state & (SS_CANTSENDMORE | SS_CANTRCVMORE));
		SSA_REFRELE(ss, ssa);
		ssa = NULL;
		break;
	}

	*ssap = ssa;
	return (error);

ret_err:
	mutex_enter(&so->so_lock);
	/*
	 * There should not be any upcall done by SCTP.  So normally the
	 * ssa_refcnt should be 2.  And we can call sosctp_assoc_free()
	 * directly.  But since the ssa is inserted to the ss_soassocs
	 * array above, some thread can actually put a hold on it.  In
	 * this special case, we "manually" decrease the ssa_refcnt by 2.
	 */
	if (ssa->ssa_refcnt > 2)
		ssa->ssa_refcnt -= 2;
	else
		sosctp_assoc_free(ss, ssa);
	*ssap = NULL;
	return (error);
}

/*
 * Inherit socket properties
 */
void
sosctp_so_inherit(struct sctp_sonode *lss, struct sctp_sonode *nss)
{
	struct sonode *nso = &nss->ss_so;
	struct sonode *lso = &lss->ss_so;

	nso->so_options = lso->so_options & (SO_DEBUG|SO_REUSEADDR|
	    SO_KEEPALIVE|SO_DONTROUTE|SO_BROADCAST|SO_USELOOPBACK|
	    SO_OOBINLINE|SO_DGRAM_ERRIND|SO_LINGER);
	nso->so_sndbuf = lso->so_sndbuf;
	nso->so_rcvbuf = lso->so_rcvbuf;
	nso->so_pgrp = lso->so_pgrp;

	nso->so_rcvlowat = lso->so_rcvlowat;
	nso->so_sndlowat = lso->so_sndlowat;
}

/*
 * Branching association to it's own socket. Inherit properties from
 * the parent, and move data from RX queue to TX.
 */
void
sosctp_assoc_move(struct sctp_sonode *ss, struct sctp_sonode *nss,
    struct sctp_soassoc *ssa)
{
	mblk_t *mp, **nmp, *last_mp;
	struct sctp_soassoc *tmp;

	sosctp_so_inherit(ss, nss);

	nss->ss_so.so_state |= (ss->ss_so.so_state & (SS_NDELAY|SS_NONBLOCK));
	nss->ss_so.so_state |=
	    (ssa->ssa_state & (SS_ISCONNECTED|SS_ISCONNECTING|
	    SS_ISDISCONNECTING|SS_CANTSENDMORE|SS_CANTRCVMORE|SS_ISBOUND));
	nss->ss_so.so_error = ssa->ssa_error;
#if 0
	nss->ss_so.so_txqueued = ssa->ssa_txqueued;
#endif
	nss->ss_so.so_snd_qfull = ssa->ssa_snd_qfull;
	nss->ss_wroff = ssa->ssa_wroff;
	nss->ss_wrsize = ssa->ssa_wrsize;
	nss->ss_so.so_rcv_queued = ssa->ssa_rcv_queued;
	nss->ss_so.so_proto_handle = (sock_lower_handle_t)ssa->ssa_conn;

	if (nss->ss_so.so_rcv_queued > 0) {
		nmp = &ss->ss_so.so_rcv_q_head;
		last_mp = NULL;
		while ((mp = *nmp) != NULL) {
			tmp = *(struct sctp_soassoc **)DB_BASE(mp);
			if (tmp == ssa) {
				*nmp = mp->b_next;
				ASSERT(DB_TYPE(mp) != M_DATA);
				if (nss->ss_so.so_rcv_q_last_head == NULL) {
					nss->ss_so.so_rcv_q_head = mp;
				} else {
					nss->ss_so.so_rcv_q_last_head->b_next =
					    mp;
				}
				nss->ss_so.so_rcv_q_last_head = mp;
				nss->ss_so.so_rcv_q_last_head->b_prev = last_mp;
				mp->b_next = NULL;
			} else {
				nmp = &mp->b_next;
				last_mp = mp;
			}
		}
		ss->ss_so.so_rcv_q_last_head = last_mp;
		ss->ss_so.so_rcv_q_last_head->b_prev = last_mp;
	}
}

void
sosctp_assoc_isconnecting(struct sctp_soassoc *ssa)
{
	struct sonode *so = &ssa->ssa_sonode->ss_so;

	ASSERT(MUTEX_HELD(&so->so_lock));

	ssa->ssa_state &= ~(SS_ISCONNECTED|SS_ISDISCONNECTING);
	ssa->ssa_state |= SS_ISCONNECTING;
	cv_broadcast(&so->so_state_cv);
}

void
sosctp_assoc_isconnected(struct sctp_soassoc *ssa)
{
	struct sonode *so = &ssa->ssa_sonode->ss_so;

	ASSERT(MUTEX_HELD(&so->so_lock));

	ssa->ssa_state &= ~(SS_ISCONNECTING|SS_ISDISCONNECTING);
	ssa->ssa_state |= SS_ISCONNECTED;
	cv_broadcast(&so->so_state_cv);
}

void
sosctp_assoc_isdisconnecting(struct sctp_soassoc *ssa)
{
	struct sonode *so = &ssa->ssa_sonode->ss_so;

	ASSERT(MUTEX_HELD(&so->so_lock));

	ssa->ssa_state &= ~SS_ISCONNECTING;
	ssa->ssa_state |= SS_CANTSENDMORE;
	cv_broadcast(&so->so_state_cv);
}

void
sosctp_assoc_isdisconnected(struct sctp_soassoc *ssa, int error)
{
	struct sonode *so = &ssa->ssa_sonode->ss_so;

	ASSERT(MUTEX_HELD(&so->so_lock));

	ssa->ssa_state &= ~(SS_ISCONNECTING|SS_ISCONNECTED|SS_ISDISCONNECTING);
	ssa->ssa_state |= (SS_CANTRCVMORE|SS_CANTSENDMORE);
	if (error != 0)
		ssa->ssa_error = (ushort_t)error;
	cv_broadcast(&so->so_state_cv);
}
