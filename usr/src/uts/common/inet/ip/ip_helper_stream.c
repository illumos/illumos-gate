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

#include <sys/types.h>
#include <inet/ip.h>
#include <inet/ip_impl.h>
#include <inet/ipclassifier.h>
#include <inet/proto_set.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/cmn_err.h>
#include <sys/t_kuser.h>
#include <sys/tihdr.h>
#include <sys/pathname.h>
#include <sys/sockio.h>
#include <sys/vmem.h>
#include <sys/disp.h>

void ip_helper_wput(queue_t *q, mblk_t *mp);

static int ip_helper_stream_close(queue_t *, int);

static struct module_info ip_helper_stream_info =  {
	0, "iphelper", IP_MOD_MINPSZ, IP_MOD_MAXPSZ, IP_MOD_HIWAT, IP_MOD_LOWAT
};

static struct qinit ip_helper_stream_rinit = {
	NULL, NULL, NULL, ip_helper_stream_close, NULL,
	&ip_helper_stream_info, NULL
};

static struct qinit ip_helper_stream_winit = {
	(pfi_t)ip_helper_wput, (pfi_t)ip_wsrv, NULL, NULL, NULL,
	&ip_helper_stream_info, NULL, NULL, NULL, STRUIOT_NONE
};

/*
 * set the q_ptr of the 'q' to the conn_t pointer passed in
 */
static void
ip_helper_share_conn(queue_t *q, mblk_t *mp, cred_t *crp)
{
	conn_t *connp = *((conn_t **)mp->b_cont->b_rptr);

	/*
	 * This operation is allowed only on helper streams with kcred
	 */

	if (kcred != crp || msgdsize(mp->b_cont) != sizeof (void *)) {
		miocnak(q, mp, 0, EINVAL);
		return;
	}

	connp->conn_helper_info->iphs_minfo = q->q_ptr;
	connp->conn_helper_info->iphs_rq = RD(q);
	connp->conn_helper_info->iphs_wq = WR(q);
	WR(q)->q_ptr = RD(q)->q_ptr = (void *)connp;
	connp->conn_rq = RD(q);
	connp->conn_wq = WR(q);
	miocack(q, mp, 0, 0);
}

void
ip_helper_wput(queue_t *q, mblk_t *mp)
{
	struct iocblk *iocp = (struct iocblk *)mp->b_rptr;
	if (DB_TYPE(mp) == M_IOCTL &&
	    iocp->ioc_cmd == SIOCSQPTR) {
		ip_helper_share_conn(q, mp, iocp->ioc_cr);
	} else {
		/* We only handle ioctl related messages here */
		ASSERT(DB_TYPE(mp) != M_DATA);
		ip_wput_nondata(q, mp);
	}
}

/* ARGSUSED3 */
int
ip_helper_stream_setup(queue_t *q, dev_t *devp, int flag, int sflag,
    cred_t *credp, boolean_t isv6)
{
	major_t			maj;
	ip_helper_minfo_t	*ip_minfop;

	ASSERT((flag & ~(FKLYR)) == IP_HELPER_STR);

	ASSERT(RD(q) == q);

	ip_minfop = kmem_alloc(sizeof (ip_helper_minfo_t), KM_SLEEP);
	ASSERT(ip_minfop != NULL);

	ip_minfop->ip_minfo_dev = 0;
	ip_minfop->ip_minfo_arena = NULL;

	/*
	 * Clone the device, allocate minor device number
	 */
	if (ip_minor_arena_la != NULL)
		ip_minfop->ip_minfo_dev = inet_minor_alloc(ip_minor_arena_la);

	if (ip_minfop->ip_minfo_dev == 0) {
		/*
		 * numbers in the large arena are exhausted
		 * Try small arena.
		 * Or this is a 32 bit system, 32 bit systems do not have
		 * ip_minor_arena_la
		 */
		ip_minfop->ip_minfo_dev = inet_minor_alloc(ip_minor_arena_sa);
		if (ip_minfop->ip_minfo_dev == 0) {
			return (EBUSY);
		}
		ip_minfop->ip_minfo_arena = ip_minor_arena_sa;
	} else {
		ip_minfop->ip_minfo_arena = ip_minor_arena_la;
	}


	ASSERT(ip_minfop->ip_minfo_dev != 0);
	ASSERT(ip_minfop->ip_minfo_arena != NULL);

	RD(q)->q_ptr = WR(q)->q_ptr = ip_minfop;

	maj = getemajor(*devp);
	*devp = makedevice(maj, (ulong_t)(ip_minfop->ip_minfo_dev));

	q->q_qinfo = &ip_helper_stream_rinit;
	WR(q)->q_qinfo = &ip_helper_stream_winit;
	qprocson(q);
	return (0);
}

/* ARGSUSED1 */
static int
ip_helper_stream_close(queue_t *q, int flag)
{
	ip_helper_minfo_t *ip_minfop;

	qprocsoff(q);
	ip_minfop = (q)->q_ptr;
	inet_minor_free(ip_minfop->ip_minfo_arena,
	    ip_minfop->ip_minfo_dev);
	kmem_free(ip_minfop, sizeof (ip_helper_minfo_t));
	RD(q)->q_ptr = NULL;
	WR(q)->q_ptr = NULL;
	return (0);
}

/*
 * Public interface for creating an IP stream with shared conn_t
 * Handles multiple callers in parallel by using conn_lock.
 * Note that we allocate the helper stream without any locks, which means
 * we might need to free it if we had two threads doing this concurrently
 * for the conn_t.
 */
int
ip_create_helper_stream(conn_t *connp, ldi_ident_t li)
{
	ip_helper_stream_info_t *helper;
	int	error;
	int	ret;

	ASSERT(!servicing_interrupt());

	if (connp->conn_helper_info != NULL) {
		/* Already allocated */
		return (0);
	}

	error = 0;
	helper = kmem_alloc(sizeof (ip_helper_stream_info_t), KM_SLEEP);

	/*
	 * open ip device via the layered interface.
	 * pass in kcred as some threads do not have the
	 * priviledge to open /dev/ip and the check in
	 * secpolicy_spec_open() will fail the open
	 */
	error = ldi_open_by_name((connp->conn_family == AF_INET6 ? DEV_IP6 :
	    DEV_IP), IP_HELPER_STR, kcred, &helper->iphs_handle, li);

	if (error != 0) {
		kmem_free(helper, sizeof (ip_helper_stream_info_t));
		return (error);
	}
	/* Make sure we are the only one */
	mutex_enter(&connp->conn_lock);
	if (connp->conn_helper_info != NULL) {
		/* Some other thread won - discard this stream */
		mutex_exit(&connp->conn_lock);
		(void) ldi_close(helper->iphs_handle, 0, kcred);
		kmem_free(helper, sizeof (ip_helper_stream_info_t));
		return (0);
	}
	connp->conn_helper_info = helper;
	/*
	 * Share connp with the helper stream. We hold conn_lock across this
	 * operation.
	 */
	error = ldi_ioctl(helper->iphs_handle, SIOCSQPTR, (intptr_t)connp,
	    FKIOCTL, kcred, &ret);

	if (error != 0) {
		/*
		 * Passing in a zero flag indicates that an error
		 * occured and stream was not shared
		 */
		(void) ldi_close(helper->iphs_handle, 0, kcred);
		kmem_free(helper, sizeof (ip_helper_stream_info_t));
		connp->conn_helper_info = NULL;
	}
	mutex_exit(&connp->conn_lock);
	return (error);
}

/*
 * Public interface for freeing IP helper stream
 * Caller must ensure no concurrent use of the conn_t, which is normally
 * done by calling this from the close routine when the conn_t is quiesced.
 */
void
ip_free_helper_stream(conn_t *connp)
{
	ASSERT(!servicing_interrupt());

	if (connp->conn_helper_info == NULL)
		return;

	ASSERT(connp->conn_helper_info->iphs_handle != NULL);

	connp->conn_helper_info->iphs_rq->q_ptr =
	    connp->conn_helper_info->iphs_wq->q_ptr =
	    connp->conn_helper_info->iphs_minfo;
	(void) ldi_close(connp->conn_helper_info->iphs_handle,
	    IP_HELPER_STR, kcred);
	kmem_free(connp->conn_helper_info, sizeof (ip_helper_stream_info_t));
	connp->conn_helper_info = NULL;
}
