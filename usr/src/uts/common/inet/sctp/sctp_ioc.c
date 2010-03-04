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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/kmem.h>
#include <sys/random.h>
#include <sys/policy.h>

#include <netinet/in.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/nd.h>
#include <inet/ipclassifier.h>
#include <inet/optcom.h>
#include <inet/sctp_ip.h>
#include "sctp_impl.h"

/*
 * sctp_wput_ioctl is called by sctp_wput to handle all
 * M_IOCTL messages.
 */
void
sctp_wput_ioctl(queue_t *q, mblk_t *mp)
{
	conn_t	*connp = (conn_t *)q->q_ptr;
	struct iocblk	*iocp;

	if (connp == NULL) {
		ip0dbg(("sctp_wput_ioctl: null conn\n"));
		return;
	}

	iocp = (struct iocblk *)mp->b_rptr;
	switch (iocp->ioc_cmd) {
	case ND_SET:
		/* sctp_nd_getset() -> nd_getset() does the checking. */
	case ND_GET:
		if (!sctp_nd_getset(q, mp)) {
			break;
		}
		qreply(q, mp);
		return;
	default:
		iocp->ioc_error = EOPNOTSUPP;
		break;
	}
err_ret:
	iocp->ioc_count = 0;
	mp->b_datap->db_type = M_IOCNAK;
	qreply(q, mp);
}

/*
 * A SCTP streams driver which is there just to handle ioctls on /dev/sctp.
 */
static int sctp_str_close(queue_t *);
static int sctp_str_open(queue_t *, dev_t *, int, int, cred_t *);

static struct module_info sctp_mod_info =  {
	5711, "sctp", 1, INFPSZ, 512, 128
};

static struct qinit sctprinit = {
	NULL, NULL, sctp_str_open, sctp_str_close, NULL, &sctp_mod_info
};

static struct qinit sctpwinit = {
	(pfi_t)sctp_wput, NULL, NULL, NULL, NULL, &sctp_mod_info
};

struct streamtab sctpinfo = {
	&sctprinit, &sctpwinit
};

static int
sctp_str_close(queue_t *q)
{
	conn_t	*connp = Q_TO_CONN(q);

	qprocsoff(connp->conn_rq);

	ASSERT(connp->conn_ref == 1);

	inet_minor_free(connp->conn_minor_arena, connp->conn_dev);

	q->q_ptr = WR(q)->q_ptr = NULL;
	CONN_DEC_REF(connp);

	return (0);
}

/*ARGSUSED2*/
static int
sctp_str_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	conn_t 		*connp;
	major_t		maj;
	netstack_t	*ns;
	zoneid_t	zoneid;

	/* If the stream is already open, return immediately. */
	if (q->q_ptr != NULL)
		return (0);

	/* If this is not a driver open, fail. */
	if (sflag == MODOPEN)
		return (EINVAL);

	ns = netstack_find_by_cred(credp);
	ASSERT(ns != NULL);

	/*
	 * For exclusive stacks we set the zoneid to zero
	 * to make IP operate as if in the global zone.
	 */
	if (ns->netstack_stackid != GLOBAL_NETSTACKID)
		zoneid = GLOBAL_ZONEID;
	else
		zoneid = crgetzoneid(credp);

	/*
	 * We are opening as a device. This is an IP client stream, and we
	 * allocate an conn_t as the instance data.
	 */
	connp = ipcl_conn_create(IPCL_IPCCONN, KM_SLEEP, ns);

	/*
	 * ipcl_conn_create did a netstack_hold. Undo the hold that was
	 * done by netstack_find_by_cred()
	 */
	netstack_rele(ns);

	connp->conn_zoneid = zoneid;
	connp->conn_ixa->ixa_flags |= IXAF_SET_ULP_CKSUM;
	/* conn_allzones can not be set this early, hence no IPCL_ZONEID */
	connp->conn_ixa->ixa_zoneid = zoneid;

	connp->conn_rq = q;
	connp->conn_wq = WR(q);
	q->q_ptr = WR(q)->q_ptr = connp;

	if ((ip_minor_arena_la != NULL) &&
	    (connp->conn_dev = inet_minor_alloc(ip_minor_arena_la)) != 0) {
		connp->conn_minor_arena = ip_minor_arena_la;
	} else {
		/*
		 * Minor numbers in the large arena are exhausted.
		 * Try to allocate from the small arena.
		 */
		if ((connp->conn_dev = inet_minor_alloc(ip_minor_arena_sa))
		    == 0) {
			/* CONN_DEC_REF takes care of netstack_rele() */
			q->q_ptr = WR(q)->q_ptr = NULL;
			CONN_DEC_REF(connp);
			return (EBUSY);
		}
		connp->conn_minor_arena = ip_minor_arena_sa;
	}

	maj = getemajor(*devp);
	*devp = makedevice(maj, (minor_t)connp->conn_dev);

	/*
	 * connp->conn_cred is crfree()ed in ipcl_conn_destroy()
	 */
	ASSERT(connp->conn_cred == NULL);
	connp->conn_cred = credp;
	crhold(connp->conn_cred);
	connp->conn_cpid = curproc->p_pid;
	/* Cache things in ixa without an extra refhold */
	ASSERT(!(connp->conn_ixa->ixa_free_flags & IXA_FREE_CRED));
	connp->conn_ixa->ixa_cred = connp->conn_cred;
	connp->conn_ixa->ixa_cpid = connp->conn_cpid;
	if (is_system_labeled())
		connp->conn_ixa->ixa_tsl = crgetlabel(connp->conn_cred);

	/*
	 * Make the conn globally visible to walkers
	 */
	mutex_enter(&connp->conn_lock);
	connp->conn_state_flags &= ~CONN_INCIPIENT;
	mutex_exit(&connp->conn_lock);
	ASSERT(connp->conn_ref == 1);

	qprocson(q);

	return (0);
}


/*
 * The SCTP write put procedure which is used only to handle ioctls.
 */
void
sctp_wput(queue_t *q, mblk_t *mp)
{
	uchar_t		*rptr;
	t_scalar_t	type;

	switch (mp->b_datap->db_type) {
	case M_IOCTL:
		sctp_wput_ioctl(q, mp);
		break;
	case M_DATA:
		/* Should be handled in sctp_output() */
		ASSERT(0);
		freemsg(mp);
		break;
	case M_PROTO:
	case M_PCPROTO:
		rptr = mp->b_rptr;
		if ((mp->b_wptr - rptr) >= sizeof (t_scalar_t)) {
			type = ((union T_primitives *)rptr)->type;
			/*
			 * There is no "standard" way on how to respond
			 * to T_CAPABILITY_REQ if a module does not
			 * understand it.  And the current TI mod
			 * has problems handling an error ack.  So we
			 * catch the request here and reply with a response
			 * which the TI mod knows how to respond to.
			 */
			switch (type) {
			case T_CAPABILITY_REQ:
				(void) putnextctl1(RD(q), M_ERROR, EPROTO);
				break;
			default:
				if ((mp = mi_tpi_err_ack_alloc(mp,
				    TNOTSUPPORT, 0)) != NULL) {
					qreply(q, mp);
					return;
				}
			}
		}
		/* FALLTHRU */
	default:
		freemsg(mp);
		return;
	}
}
