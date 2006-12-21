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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <inet/common.h>
#include <net/if_arp.h>
#include <sys/file.h>
#include <sys/sockio.h>
#include <sys/pathname.h>
#include <inet/arp.h>
#include <sys/modctl.h>
#include <sys/ib/ib_types.h>
#include <sys/ib/clients/rds/rdsib_arp.h>
#include <sys/ib/clients/rds/rdsib_debug.h>

extern int rds_pr_lookup(rds_streams_t *rdss, rds_ipx_addr_t *dst_addr,
    rds_ipx_addr_t *src_addr, uint8_t localroute, uint32_t bound_dev_if,
    rds_pr_comp_func_t func);
extern void rds_pr_arp_ack(mblk_t *mp);
extern void rds_pr_ip6_ack(mblk_t *mp);
extern void rds_pr_proto(queue_t *, mblk_t *);
extern void rds_pr_ip_ack(mblk_t *mp);
extern int rds_rts_announce(rds_streams_t *rdss);
extern void rds_prwqn_delete(rds_prwqn_t *wqnp);

#if 0
extern dev_info_t *rdsdip;
#endif

extern ddi_taskq_t	*rds_taskq;

/*
 * rds_get_ibaddr_complete
 */
static int
rds_get_ibaddr_complete(void *arg, int status)
{
	rds_prwqn_t	*wqnp = (rds_prwqn_t *)arg;
	rds_streams_t	*rdss = (rds_streams_t *)wqnp->arg;

	RDS_DPRINTF4("rds_get_ibaddr_complete", "Enter: rdss: 0x%p wqnp: 0x%p",
	    rdss, wqnp);

	mutex_enter(&rdss->lock);
	rdss->status = status;

	RDS_DPRINTF2(LABEL, "sgid: %llx:%llx dgid: %llx:%llx",
	    wqnp->sgid.gid_prefix, wqnp->sgid.gid_guid, wqnp->dgid.gid_prefix,
	    wqnp->dgid.gid_guid);

	/*
	 * lock is held by the caller and is released after
	 * this function returns
	 */
	cv_signal(&rdss->cv);
	mutex_exit(&rdss->lock);

	RDS_DPRINTF4("rds_get_ibaddr_complete", "Return");

	return (0);
}

/*
 * Lower read service procedure (messages coming back from arp/ip).
 * Process messages based on queue type.
 */
static int
rds_lrsrv(queue_t *q)
{
	mblk_t *mp;
	rds_streams_t *rdss = q->q_ptr;

	RDS_DPRINTF4("rds_lrsrv", "Enter: 0x%p 0x%p", q, rdss);

	if (WR(q) == rdss->ipqueue) {
		while (mp = getq(q)) {
			rds_pr_ip_ack(mp);
		}
	} else if (WR(q) == rdss->arpqueue) {
		while (mp = getq(q)) {
			rds_pr_arp_ack(mp);
		}
	} else if (WR(q) == rdss->ip6queue) {
		while (mp = getq(q)) {
			rds_pr_ip6_ack(mp);
		}
	} else {
		freemsg(mp);
	}

	RDS_DPRINTF4("rds_lrsrv", "Return: 0x%p", q);

	return (0);
}

/*
 * Lower write service procedure.
 * Used when lower streams are flow controlled.
 */
static int
rds_lwsrv(queue_t *q)
{
	mblk_t *mp;

	RDS_DPRINTF4("rds_lwsrv", "Enter: 0x%p", q);

	while (mp = getq(q)) {
		if (canputnext(q)) {
			putnext(q, mp);
		} else {
			(void) putbq(q, mp);
			qenable(q);
			break;
		}
	}

	RDS_DPRINTF4("rds_lwsrv", "Return: 0x%p", q);
	return (0);
}

/*
 * Lower read put procedure. Arp/ip messages come here.
 */
static int
rds_lrput(queue_t *q, mblk_t *mp)
{
	RDS_DPRINTF4("rds_lrput", "Enter: 0x%p, db_type: %d", q, DB_TYPE(mp));

	switch (DB_TYPE(mp)) {
		case M_FLUSH:
			/*
			 * Turn around
			 */
			if (*mp->b_rptr & FLUSHW) {
				*mp->b_rptr &= ~FLUSHR;
				qreply(q, mp);
				return (0);
			}
			freemsg(mp);
			break;
		case M_IOCACK:
		case M_IOCNAK:
		case M_DATA:
			/*
			 * This could be in interrupt context.
			 * Some of the ibt calls cannot be called in
			 * interrupt context, so
			 * put it in the queue and the message will be
			 * processed by service proccedure
			 */
			(void) putq(q, mp);
			qenable(q);
			break;
		case M_PROTO:
		case M_PCPROTO:
			rds_pr_proto(q, mp);
			break;
		default:
			RDS_DPRINTF1(LABEL, "lrput: got unknown msg <0x%x>\n",
			mp->b_datap->db_type);
			ASSERT(0);
			break;
	}

	RDS_DPRINTF4("rds_lrput", "Return: 0x%p", q);

	return (0);
}

/*
 * Streams write queue module info
 */
static struct module_info rds_winfo = {
	99,		/* module ID number */
	"rds",		/* module name */
	0,		/* min packet size */
	INFPSZ,
	49152,		/* STREAM queue high water mark -- 49152 */
	12		/* STREAM queue low water mark -- 12 */
};

/*
 * Streams lower write queue, for rds/ip requests.
 */
static struct qinit rds_lwinit = {
	NULL,		/* qi_putp */
	rds_lwsrv,	/* qi_srvp */
	NULL,		/* qi_qopen */
	NULL,		/* qi_qclose */
	NULL,		/* qi_qadmin */
	&rds_winfo,	/* module info */
	NULL,		/* module statistics struct */
	NULL,
	NULL,
	STRUIOT_NONE	/* stream uio type is standard uiomove() */
};

/*
 * Streams lower read queue: read reply messages from rds/ip.
 */
static struct qinit rds_lrinit = {
	rds_lrput,	/* qi_putp */
	rds_lrsrv,	/* qi_srvp */
	NULL,		/* qi_qopen */
	NULL,		/* qi_qclose */
	NULL,		/* qi_qadmin */
	&rds_winfo,	/* module info */
	NULL,		/* module statistics struct */
	NULL,
	NULL,
	STRUIOT_NONE /* stream uio type is standard uiomove() */
};


int
rds_link_driver(rds_streams_t *rdss, char *path, queue_t **q, vnode_t **dev_vp)
{
	struct stdata *dev_stp;
#if 0
	cdevsw_impl_t *dp;
#endif
	vnode_t *vp;
	int error;
	queue_t *rq;

	RDS_DPRINTF4("rds_link_driver", "Enter: %s", path);

	/* open the driver from inside the kernel */
	error = vn_open(path, UIO_SYSSPACE, FREAD|FWRITE, 0, &vp,
	    0, NULL);
	if (error) {
		RDS_DPRINTF1(LABEL, "rds_link_driver: vn_open('%s') failed\n",
		    path);
		return (error);
	}
	*dev_vp = vp;

	dev_stp = vp->v_stream;
	*q = dev_stp->sd_wrq;

	mutex_enter(&vp->v_lock);
	vp->v_count++;
	mutex_exit(&vp->v_lock);

	rq = RD(dev_stp->sd_wrq);
	RD(rq)->q_ptr = WR(rq)->q_ptr = rdss;
#if 0
	dp = &devimpl[rdss->major];
	setq(rq, &rds_lrinit, &rds_lwinit, dp->d_dmp, dp->d_qflag,
	    dp->d_sqtype, B_TRUE);
#else
	setq(rq, &rds_lrinit, &rds_lwinit, NULL, QMTSAFE,
	    SQ_CI|SQ_CO, B_FALSE);
#endif

	RDS_DPRINTF4("rds_link_driver", "Return: %s", path);

	return (0);
}

extern struct qinit strdata;
extern struct qinit stwdata;

/*
 * Unlink ip, rds, icmp6 drivers
 */
/* ARGSUSED */
int
rds_unlink_driver(queue_t **q, vnode_t **dev_vp)
{
	vnode_t *vp = *dev_vp;
	struct stdata *dev_stp = vp->v_stream;
	queue_t *wrq, *rq;
	int	rc;

	RDS_DPRINTF4("rds_unlink_driver", "Enter: 0x%p", q);

	wrq = dev_stp->sd_wrq;
	rq = RD(wrq);

	disable_svc(rq);
	wait_svc(rq);
	flushq(rq, FLUSHALL);
	flushq(WR(rq), FLUSHALL);

	rq->q_ptr = wrq->q_ptr = dev_stp;

	setq(rq, &strdata, &stwdata, NULL, QMTSAFE, SQ_CI|SQ_CO, B_TRUE);

	if ((rc = VOP_CLOSE(vp, FREAD, 1, (offset_t)0, 0)) != 0) {
		RDS_DPRINTF1(LABEL, "VOP_CLOSE failed %d\n", rc);
	}
	vn_rele(vp);

	RDS_DPRINTF4("rds_unlink_driver", "Return: 0x%p", q);

	return (0);
}

int
rds_unlink_drivers(rds_streams_t *rdss)
{
	RDS_DPRINTF4("rds_unlink_drivers", "Enter");

	if (rdss->ipqueue) {
		(void) rds_unlink_driver(&rdss->ipqueue, &rdss->ip_vp);
	}

	if (rdss->arpqueue) {
		(void) rds_unlink_driver(&rdss->arpqueue, &rdss->arp_vp);
	}

	RDS_DPRINTF4("rds_unlink_drivers", "Return");

	return (0);
}

/*
 * Link ip, rds drivers below rds
 */
int
rds_link_drivers(rds_streams_t *rdss)
{
	int	rc;

	RDS_DPRINTF4("rds_link_drivers", "Enter");

	if ((rc = rds_link_driver(rdss, "/dev/ip", &rdss->ipqueue,
	    &rdss->ip_vp)) != 0) {
		RDS_DPRINTF1(LABEL, "rds_link_drivers: ip failed\n");
		return (rc);
	}

	if ((rc = rds_link_driver(rdss, "/dev/arp", &rdss->arpqueue,
	    &rdss->arp_vp)) != 0) {
		(void) rds_unlink_driver(&rdss->ipqueue,
		    &rdss->ip_vp);
		RDS_DPRINTF1(LABEL, "rds_link_drivers: rds failed\n");
		return (rc);
	}

	/*
	 * let IP know this is a routing socket
	 */
	if ((rc = rds_rts_announce(rdss))) {
		RDS_DPRINTF1(LABEL, "link_drivers: rts_announce failed\n");
		(void) rds_unlink_drivers(rdss);
		return (rc);
	}

	RDS_DPRINTF4("rds_link_drivers", "Return");

	return (0);
}

#define	AF_RDS	30

typedef struct rds_get_ibaddr_args_s {
	int		ret;
	ipaddr_t	srcip;
	ipaddr_t	destip;
	ib_gid_t	sgid;
	ib_gid_t	dgid;
	kmutex_t	lock;
	kcondvar_t	cv;
} rds_get_ibaddr_args_t;

void
rds_get_ibaddr_impl(void *arg)
{
	rds_get_ibaddr_args_t	*argsp = (rds_get_ibaddr_args_t *)arg;
	rds_streams_t		*rdss;
	rds_ipx_addr_t		srcaddr, destaddr;
	int			ret;

	RDS_DPRINTF4("rds_get_ibaddr", "Enter: src: 0x%x dest: 0x%x",
	    argsp->srcip, argsp->destip);

	rdss = (rds_streams_t *)kmem_zalloc(sizeof (rds_streams_t), KM_SLEEP);

	mutex_init(&rdss->lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&rdss->cv, NULL, CV_DRIVER, NULL);
#if 0
	rdss->major = ddi_driver_major(rdsdip);
#endif

	ret = rds_link_drivers(rdss);
	if (ret != 0) {
		RDS_DPRINTF2(LABEL, "rds_link_drivers failed %d", ret);
		argsp->ret = ret;
		mutex_enter(&argsp->lock);
		cv_signal(&argsp->cv);
		mutex_exit(&argsp->lock);
		return;
	}

	destaddr.family = AF_INET;
	destaddr.un.ip4addr = htonl(argsp->destip);
	srcaddr.family = AF_INET;
	srcaddr.un.ip4addr = htonl(argsp->srcip);

	(void) rds_pr_lookup(rdss, &destaddr, &srcaddr, 0, NULL,
	    rds_get_ibaddr_complete);

	mutex_enter(&rdss->lock);
	cv_wait(&rdss->cv, &rdss->lock);
	mutex_exit(&rdss->lock);

	(void) rds_unlink_drivers(rdss);

	argsp->ret = rdss->status;
	if (argsp->ret == 0) {
		argsp->sgid = rdss->wqnp->sgid;
		argsp->dgid = rdss->wqnp->dgid;
	}

	rds_prwqn_delete(rdss->wqnp);
	mutex_destroy(&rdss->lock);
	cv_destroy(&rdss->cv);
	kmem_free(rdss, sizeof (rds_streams_t));

	mutex_enter(&argsp->lock);
	cv_signal(&argsp->cv);
	mutex_exit(&argsp->lock);

	RDS_DPRINTF4("rds_get_ibaddr", "Return");
}

int
rds_get_ibaddr(ipaddr_t srcip, ipaddr_t destip, ib_gid_t *sgid, ib_gid_t *dgid)
{
	rds_get_ibaddr_args_t *argsp;
	int		ret;

	RDS_DPRINTF4("rds_get_ibaddr", "Enter: src: 0x%x dest: 0x%x", srcip,
	    destip);

	argsp = (rds_get_ibaddr_args_t *)kmem_zalloc(
	    sizeof (rds_get_ibaddr_args_t), KM_SLEEP);
	argsp->srcip = srcip;
	argsp->destip = destip;
	mutex_init(&argsp->lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&argsp->cv, NULL, CV_DRIVER, NULL);

	ret = ddi_taskq_dispatch(rds_taskq, rds_get_ibaddr_impl,
	    (void *)argsp, DDI_NOSLEEP);
	if (ret != DDI_SUCCESS) {
		RDS_DPRINTF1(LABEL, "Taskq dispatch failed");
		return (ret);
	}

	mutex_enter(&argsp->lock);
	cv_wait(&argsp->cv, &argsp->lock);
	mutex_exit(&argsp->lock);

	ret = argsp->ret;
	*sgid = argsp->sgid;
	*dgid = argsp->dgid;

	cv_destroy(&argsp->cv);
	mutex_destroy(&argsp->lock);
	kmem_free(argsp, sizeof (rds_get_ibaddr_args_t));

	return (ret);
}
