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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
 * We need a stream q for sending packets to IP.  This q should
 * be set in strplumb() time.  Once it is set, it will never
 * be removed.  Since it is done in strplumb() time, there is
 * no need to have a lock on the default q.
 */
static void
sctp_def_q_set(queue_t *q, mblk_t *mp)
{
	conn_t		*connp = (conn_t *)q->q_ptr;
	struct iocblk	*iocp = (struct iocblk *)mp->b_rptr;
	mblk_t		*mp1;
	hrtime_t	t;
	sctp_stack_t	*sctps = connp->conn_netstack->
	    netstack_sctp;

	ASSERT(connp != NULL && connp->conn_ulp == IPPROTO_SCTP &&
	    connp->conn_rq == NULL);

	if ((mp1 = mp->b_cont) == NULL) {
		iocp->ioc_error = EINVAL;
		ip0dbg(("sctp_def_q_set: no file descriptor\n"));
		goto done;
	}

	mutex_enter(&sctps->sctps_g_q_lock);
	if (sctps->sctps_g_q != NULL) {
		mutex_exit(&sctps->sctps_g_q_lock);
		ip0dbg(("sctp_def_q_set: already set\n"));
		iocp->ioc_error = EALREADY;
		goto done;
	}

	sctps->sctps_g_q = q;
	mutex_exit(&sctps->sctps_g_q_lock);
	sctps->sctps_gsctp = (sctp_t *)sctp_create(NULL, NULL, AF_INET6,
	    SCTP_CAN_BLOCK, NULL, NULL, connp->conn_cred);
	mutex_enter(&sctps->sctps_g_q_lock);
	if (sctps->sctps_gsctp == NULL) {
		sctps->sctps_g_q = NULL;
		mutex_exit(&sctps->sctps_g_q_lock);
		iocp->ioc_error = ENOMEM;
		goto done;
	}
	mutex_exit(&sctps->sctps_g_q_lock);
	ASSERT(sctps->sctps_g_q_ref >= 1);
	ASSERT(list_head(&sctps->sctps_g_list) == sctps->sctps_gsctp);

	/*
	 * As a good citizen of using /dev/urandom, add some entropy
	 * to the random number pool.
	 */
	t = gethrtime();
	(void) random_add_entropy((uint8_t *)&t, sizeof (t), 0);
done:
	if (mp1 != NULL) {
		freemsg(mp1);
		mp->b_cont = NULL;
	}
	iocp->ioc_count = 0;
	mp->b_datap->db_type = M_IOCACK;
	qreply(q, mp);
}


/*
 * sctp_wput_ioctl is called by sctp_wput_slow to handle all
 * M_IOCTL messages.
 */
void
sctp_wput_ioctl(queue_t *q, mblk_t *mp)
{
	conn_t	*connp = (conn_t *)q->q_ptr;
	struct iocblk	*iocp;
	cred_t *cr;

	if (connp == NULL) {
		ip0dbg(("sctp_wput_ioctl: null conn\n"));
		return;
	}

	iocp = (struct iocblk *)mp->b_rptr;
	cr = DB_CREDDEF(mp, iocp->ioc_cr);
	switch (iocp->ioc_cmd) {
	case SCTP_IOC_DEFAULT_Q:
		/* Wants to be the default wq. */
		if (cr != NULL && secpolicy_ip_config(cr, B_FALSE) != 0) {
			iocp->ioc_error = EPERM;
			goto err_ret;
		}
		sctp_def_q_set(q, mp);
		return;

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
