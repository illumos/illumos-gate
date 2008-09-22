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


/*
 * Zone Console Driver.
 *
 * This driver, derived from the pts/ptm drivers, is the pseudo console driver
 * for system zones.  Its implementation is straightforward.  Each instance
 * of the driver represents a global-zone/local-zone pair (this maps in a
 * straightforward way to the commonly used terminal notion of "master side"
 * and "slave side", and we use that terminology throughout).
 *
 * Instances of zcons are onlined as children of /pseudo/zconsnex@1/
 * by zoneadmd in userland, using the devctl framework; thus the driver
 * does not need to maintain any sort of "admin" node.
 *
 * The driver shuttles I/O from master side to slave side and back.  In a break
 * from the pts/ptm semantics, if one side is not open, I/O directed towards
 * it will simply be discarded.  This is so that if zoneadmd is not holding
 * the master side console open (i.e. it has died somehow), processes in
 * the zone do not experience any errors and I/O to the console does not
 * hang.
 *
 * TODO: we may want to revisit the other direction; i.e. we may want
 * zoneadmd to be able to detect whether no zone processes are holding the
 * console open, an unusual situation.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/cred.h>
#include <sys/ddi.h>
#include <sys/debug.h>
#include <sys/devops.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/modctl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/zcons.h>

static int zc_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int zc_attach(dev_info_t *, ddi_attach_cmd_t);
static int zc_detach(dev_info_t *, ddi_detach_cmd_t);

static int zc_open(queue_t *, dev_t *, int, int, cred_t *);
static int zc_close(queue_t *, int, cred_t *);
static void zc_wput(queue_t *, mblk_t *);
static void zc_rsrv(queue_t *);
static void zc_wsrv(queue_t *);

/*
 * The instance number is encoded in the dev_t in the minor number; the lowest
 * bit of the minor number is used to track the master vs. slave side of the
 * virtual console.  The rest of the bits in the minor number are the instance.
 */
#define	ZC_MASTER_MINOR	0
#define	ZC_SLAVE_MINOR	1

#define	ZC_INSTANCE(x)	(getminor((x)) >> 1)
#define	ZC_NODE(x)	(getminor((x)) & 0x01)

int zcons_debug = 0;
#define	DBG(a)   if (zcons_debug) cmn_err(CE_NOTE, a)
#define	DBG1(a, b)   if (zcons_debug) cmn_err(CE_NOTE, a, b)


/*
 * Zone Console Pseudo Terminal Module: stream data structure definitions
 */
static struct module_info zc_info = {
	31337,	/* c0z we r hAx0rs */
	"zcons",
	0,
	INFPSZ,
	2048,
	128
};

static struct qinit zc_rinit = {
	NULL,
	(int (*)()) zc_rsrv,
	zc_open,
	zc_close,
	NULL,
	&zc_info,
	NULL
};

static struct qinit zc_winit = {
	(int (*)()) zc_wput,
	(int (*)()) zc_wsrv,
	NULL,
	NULL,
	NULL,
	&zc_info,
	NULL
};

static struct streamtab zc_tab_info = {
	&zc_rinit,
	&zc_winit,
	NULL,
	NULL
};

#define	ZC_CONF_FLAG	(D_MP | D_MTQPAIR | D_MTOUTPERIM | D_MTOCEXCL)

/*
 * this will define (struct cb_ops cb_zc_ops) and (struct dev_ops zc_ops)
 */
DDI_DEFINE_STREAM_OPS(zc_ops, nulldev, nulldev,	zc_attach, zc_detach, nodev, \
	zc_getinfo, ZC_CONF_FLAG, &zc_tab_info, ddi_quiesce_not_needed);

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, 	/* Type of module (this is a pseudo driver) */
	"Zone console driver",	/* description of module */
	&zc_ops			/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

typedef struct zc_state {
	dev_info_t *zc_devinfo;
	queue_t *zc_master_rdq;
	queue_t *zc_slave_rdq;
	int zc_state;
} zc_state_t;

#define	ZC_STATE_MOPEN	0x01
#define	ZC_STATE_SOPEN	0x02

static void *zc_soft_state;

int
_init(void)
{
	int err;

	if ((err = ddi_soft_state_init(&zc_soft_state,
	    sizeof (zc_state_t), 0)) != 0) {
		return (err);
	}

	if ((err = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(zc_soft_state);

	return (err);
}


int
_fini(void)
{
	int err;

	if ((err = mod_remove(&modlinkage)) != 0) {
		return (err);
	}

	ddi_soft_state_fini(&zc_soft_state);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
zc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	zc_state_t *zcs;
	int instance;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	instance = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(zc_soft_state, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if ((ddi_create_minor_node(dip, ZCONS_SLAVE_NAME, S_IFCHR,
	    instance << 1 | ZC_SLAVE_MINOR, DDI_PSEUDO, 0) == DDI_FAILURE) ||
	    (ddi_create_minor_node(dip, ZCONS_MASTER_NAME, S_IFCHR,
	    instance << 1 | ZC_MASTER_MINOR, DDI_PSEUDO, 0) == DDI_FAILURE)) {
		ddi_remove_minor_node(dip, NULL);
		ddi_soft_state_free(zc_soft_state, instance);
		return (DDI_FAILURE);
	}

	if ((zcs = ddi_get_soft_state(zc_soft_state, instance)) == NULL) {
		ddi_remove_minor_node(dip, NULL);
		ddi_soft_state_free(zc_soft_state, instance);
		return (DDI_FAILURE);
	}
	zcs->zc_devinfo = dip;

	return (DDI_SUCCESS);
}

static int
zc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	zc_state_t *zcs;
	int instance;

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	instance = ddi_get_instance(dip);
	if ((zcs = ddi_get_soft_state(zc_soft_state, instance)) == NULL)
		return (DDI_FAILURE);

	if ((zcs->zc_state & ZC_STATE_MOPEN) ||
	    (zcs->zc_state & ZC_STATE_SOPEN)) {
		DBG1("zc_detach: device (dip=%p) still open\n", (void *)dip);
		return (DDI_FAILURE);
	}

	ddi_remove_minor_node(dip, NULL);
	ddi_soft_state_free(zc_soft_state, instance);

	return (DDI_SUCCESS);
}

/*
 * zc_getinfo()
 *	getinfo(9e) entrypoint.
 */
/*ARGSUSED*/
static int
zc_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	zc_state_t *zcs;
	int instance = ZC_INSTANCE((dev_t)arg);

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((zcs = ddi_get_soft_state(zc_soft_state, instance)) == NULL)
			return (DDI_FAILURE);
		*result = zcs->zc_devinfo;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

/*
 * Return the equivalent queue from the other side of the relationship.
 * e.g.: given the slave's write queue, return the master's write queue.
 */
static queue_t *
zc_switch(queue_t *qp)
{
	zc_state_t *zcs = qp->q_ptr;
	ASSERT(zcs != NULL);

	if (qp == zcs->zc_master_rdq)
		return (zcs->zc_slave_rdq);
	else if (OTHERQ(qp) == zcs->zc_master_rdq && zcs->zc_slave_rdq != NULL)
		return (OTHERQ(zcs->zc_slave_rdq));
	else if (qp == zcs->zc_slave_rdq)
		return (zcs->zc_master_rdq);
	else if (OTHERQ(qp) == zcs->zc_slave_rdq && zcs->zc_master_rdq != NULL)
		return (OTHERQ(zcs->zc_master_rdq));
	else
		return (NULL);
}

/*
 * For debugging and outputting messages.  Returns the name of the side of
 * the relationship associated with this queue.
 */
static const char *
zc_side(queue_t *qp)
{
	zc_state_t *zcs = qp->q_ptr;
	ASSERT(zcs != NULL);

	if (qp == zcs->zc_master_rdq ||
	    OTHERQ(qp) == zcs->zc_master_rdq) {
		return ("master");
	}
	ASSERT(qp == zcs->zc_slave_rdq || OTHERQ(qp) == zcs->zc_slave_rdq);
	return ("slave");
}

/*ARGSUSED*/
static int
zc_master_open(zc_state_t *zcs,
    queue_t	*rqp,	/* pointer to the read side queue */
    dev_t	*devp,	/* pointer to stream tail's dev */
    int		oflag,	/* the user open(2) supplied flags */
    int		sflag,	/* open state flag */
    cred_t	*credp)	/* credentials */
{
	mblk_t *mop;
	struct stroptions *sop;

	/*
	 * Enforce exclusivity on the master side; the only consumer should
	 * be the zoneadmd for the zone.
	 */
	if ((zcs->zc_state & ZC_STATE_MOPEN) != 0)
		return (EBUSY);

	if ((mop = allocb(sizeof (struct stroptions), BPRI_MED)) == NULL) {
		DBG("zc_master_open(): mop allocation failed\n");
		return (ENOMEM);
	}

	zcs->zc_state |= ZC_STATE_MOPEN;

	/*
	 * q_ptr stores driver private data; stash the soft state data on both
	 * read and write sides of the queue.
	 */
	WR(rqp)->q_ptr = rqp->q_ptr = zcs;
	qprocson(rqp);

	/*
	 * Following qprocson(), the master side is fully plumbed into the
	 * STREAM and may send/receive messages.  Setting zcs->zc_master_rdq
	 * will allow the slave to send messages to us (the master).
	 * This cannot occur before qprocson() because the master is not
	 * ready to process them until that point.
	 */
	zcs->zc_master_rdq = rqp;

	/*
	 * set up hi/lo water marks on stream head read queue and add
	 * controlling tty as needed.
	 */
	mop->b_datap->db_type = M_SETOPTS;
	mop->b_wptr += sizeof (struct stroptions);
	sop = (struct stroptions *)(void *)mop->b_rptr;
	if (oflag & FNOCTTY)
		sop->so_flags = SO_HIWAT | SO_LOWAT;
	else
		sop->so_flags = SO_HIWAT | SO_LOWAT | SO_ISTTY;
	sop->so_hiwat = 512;
	sop->so_lowat = 256;
	putnext(rqp, mop);

	return (0);
}

/*ARGSUSED*/
static int
zc_slave_open(zc_state_t *zcs,
    queue_t	*rqp,	/* pointer to the read side queue */
    dev_t	*devp,	/* pointer to stream tail's dev */
    int		oflag,	/* the user open(2) supplied flags */
    int		sflag,	/* open state flag */
    cred_t	*credp)	/* credentials */
{
	mblk_t *mop;
	struct stroptions *sop;

	/*
	 * The slave side can be opened as many times as needed.
	 */
	if ((zcs->zc_state & ZC_STATE_SOPEN) != 0) {
		ASSERT((rqp != NULL) && (WR(rqp)->q_ptr == zcs));
		return (0);
	}

	if ((mop = allocb(sizeof (struct stroptions), BPRI_MED)) == NULL) {
		DBG("zc_slave_open(): mop allocation failed\n");
		return (ENOMEM);
	}

	zcs->zc_state |= ZC_STATE_SOPEN;

	/*
	 * q_ptr stores driver private data; stash the soft state data on both
	 * read and write sides of the queue.
	 */
	WR(rqp)->q_ptr = rqp->q_ptr = zcs;

	qprocson(rqp);

	/*
	 * Must follow qprocson(), since we aren't ready to process until then.
	 */
	zcs->zc_slave_rdq = rqp;

	/*
	 * set up hi/lo water marks on stream head read queue and add
	 * controlling tty as needed.
	 */
	mop->b_datap->db_type = M_SETOPTS;
	mop->b_wptr += sizeof (struct stroptions);
	sop = (struct stroptions *)(void *)mop->b_rptr;
	sop->so_flags = SO_HIWAT | SO_LOWAT | SO_ISTTY;
	sop->so_hiwat = 512;
	sop->so_lowat = 256;
	putnext(rqp, mop);

	return (0);
}

/*
 * open(9e) entrypoint; checks sflag, and rejects anything unordinary.
 */
static int
zc_open(queue_t *rqp,		/* pointer to the read side queue */
	dev_t   *devp,		/* pointer to stream tail's dev */
	int	oflag,		/* the user open(2) supplied flags */
	int	sflag,		/* open state flag */
	cred_t  *credp)		/* credentials */
{
	int instance = ZC_INSTANCE(*devp);
	int ret;
	zc_state_t *zcs;

	if (sflag != 0)
		return (EINVAL);

	if ((zcs = ddi_get_soft_state(zc_soft_state, instance)) == NULL)
		return (ENXIO);

	switch (ZC_NODE(*devp)) {
	case ZC_MASTER_MINOR:
		ret = zc_master_open(zcs, rqp, devp, oflag, sflag, credp);
		break;
	case ZC_SLAVE_MINOR:
		ret = zc_slave_open(zcs, rqp, devp, oflag, sflag, credp);
		break;
	default:
		ret = ENXIO;
		break;
	}

	return (ret);
}

/*
 * close(9e) entrypoint.
 */
/*ARGSUSED1*/
static int
zc_close(queue_t *rqp, int flag, cred_t *credp)
{
	queue_t *wqp;
	mblk_t	*bp;
	zc_state_t *zcs;

	zcs = (zc_state_t *)rqp->q_ptr;

	if (rqp == zcs->zc_master_rdq) {
		DBG("Closing master side");

		zcs->zc_master_rdq = NULL;
		zcs->zc_state &= ~ZC_STATE_MOPEN;

		/*
		 * qenable slave side write queue so that it can flush
		 * its messages as master's read queue is going away
		 */
		if (zcs->zc_slave_rdq != NULL) {
			qenable(WR(zcs->zc_slave_rdq));
		}

		qprocsoff(rqp);
		WR(rqp)->q_ptr = rqp->q_ptr = NULL;

	} else if (rqp == zcs->zc_slave_rdq) {

		DBG("Closing slave side");
		zcs->zc_state &= ~ZC_STATE_SOPEN;
		zcs->zc_slave_rdq = NULL;

		wqp = WR(rqp);
		while ((bp = getq(wqp)) != NULL) {
			if (zcs->zc_master_rdq != NULL)
				putnext(zcs->zc_master_rdq, bp);
			else if (bp->b_datap->db_type == M_IOCTL)
				miocnak(wqp, bp, 0, 0);
			else
				freemsg(bp);
		}

		/*
		 * Qenable master side write queue so that it can flush its
		 * messages as slaves's read queue is going away.
		 */
		if (zcs->zc_master_rdq != NULL)
			qenable(WR(zcs->zc_master_rdq));

		qprocsoff(rqp);
		WR(rqp)->q_ptr = rqp->q_ptr = NULL;
	}

	return (0);
}

static void
handle_mflush(queue_t *qp, mblk_t *mp)
{
	mblk_t *nmp;
	DBG1("M_FLUSH on %s side", zc_side(qp));

	if (*mp->b_rptr & FLUSHW) {
		DBG1("M_FLUSH, FLUSHW, %s side", zc_side(qp));
		flushq(qp, FLUSHDATA);
		*mp->b_rptr &= ~FLUSHW;
		if ((*mp->b_rptr & FLUSHR) == 0) {
			/*
			 * FLUSHW only. Change to FLUSHR and putnext other side,
			 * then we are done.
			 */
			*mp->b_rptr |= FLUSHR;
			if (zc_switch(RD(qp)) != NULL) {
				putnext(zc_switch(RD(qp)), mp);
				return;
			}
		} else if ((zc_switch(RD(qp)) != NULL) &&
		    (nmp = copyb(mp)) != NULL) {
			/*
			 * It is a FLUSHRW; we copy the mblk and send
			 * it to the other side, since we still need to use
			 * the mblk in FLUSHR processing, below.
			 */
			putnext(zc_switch(RD(qp)), nmp);
		}
	}

	if (*mp->b_rptr & FLUSHR) {
		DBG("qreply(qp) turning FLUSHR around\n");
		qreply(qp, mp);
		return;
	}
	freemsg(mp);
}

/*
 * wput(9E) is symmetric for master and slave sides, so this handles both
 * without splitting the codepath.
 *
 * zc_wput() looks at the other side; if there is no process holding that
 * side open, it frees the message.  This prevents processes from hanging
 * if no one is holding open the console.  Otherwise, it putnext's high
 * priority messages, putnext's normal messages if possible, and otherwise
 * enqueues the messages; in the case that something is enqueued, wsrv(9E)
 * will take care of eventually shuttling I/O to the other side.
 */
static void
zc_wput(queue_t *qp, mblk_t *mp)
{
	unsigned char type = mp->b_datap->db_type;

	ASSERT(qp->q_ptr);

	DBG1("entering zc_wput, %s side", zc_side(qp));

	if (zc_switch(RD(qp)) == NULL) {
		DBG1("wput to %s side (no one listening)", zc_side(qp));
		switch (type) {
		case M_FLUSH:
			handle_mflush(qp, mp);
			break;
		case M_IOCTL:
			miocnak(qp, mp, 0, 0);
			break;
		default:
			freemsg(mp);
			break;
		}
		return;
	}

	if (type >= QPCTL) {
		DBG1("(hipri) wput, %s side", zc_side(qp));
		switch (type) {
		case M_READ:		/* supposedly from ldterm? */
			DBG("zc_wput: tossing M_READ\n");
			freemsg(mp);
			break;
		case M_FLUSH:
			handle_mflush(qp, mp);
			break;
		default:
			/*
			 * Put this to the other side.
			 */
			ASSERT(zc_switch(RD(qp)) != NULL);
			putnext(zc_switch(RD(qp)), mp);
			break;
		}
		DBG1("done (hipri) wput, %s side", zc_side(qp));
		return;
	}

	/*
	 * Only putnext if there isn't already something in the queue.
	 * otherwise things would wind up out of order.
	 */
	if (qp->q_first == NULL && bcanputnext(RD(zc_switch(qp)), mp->b_band)) {
		DBG("wput: putting message to other side\n");
		putnext(RD(zc_switch(qp)), mp);
	} else {
		DBG("wput: putting msg onto queue\n");
		(void) putq(qp, mp);
	}
	DBG1("done wput, %s side", zc_side(qp));
}

/*
 * rsrv(9E) is symmetric for master and slave, so zc_rsrv() handles both
 * without splitting up the codepath.
 *
 * Enable the write side of the partner.  This triggers the partner to send
 * messages queued on its write side to this queue's read side.
 */
static void
zc_rsrv(queue_t *qp)
{
	zc_state_t *zcs;
	zcs = (zc_state_t *)qp->q_ptr;

	/*
	 * Care must be taken here, as either of the master or slave side
	 * qptr could be NULL.
	 */
	ASSERT(qp == zcs->zc_master_rdq || qp == zcs->zc_slave_rdq);
	if (zc_switch(qp) == NULL) {
		DBG("zc_rsrv: other side isn't listening\n");
		return;
	}
	qenable(WR(zc_switch(qp)));
}

/*
 * This routine is symmetric for master and slave, so it handles both without
 * splitting up the codepath.
 *
 * If there are messages on this queue that can be sent to the other, send
 * them via putnext(). Else, if queued messages cannot be sent, leave them
 * on this queue.
 */
static void
zc_wsrv(queue_t *qp)
{
	mblk_t *mp;

	DBG1("zc_wsrv master (%s) side", zc_side(qp));

	/*
	 * Partner has no read queue, so take the data, and throw it away.
	 */
	if (zc_switch(RD(qp)) == NULL) {
		DBG("zc_wsrv: other side isn't listening");
		while ((mp = getq(qp)) != NULL) {
			if (mp->b_datap->db_type == M_IOCTL)
				miocnak(qp, mp, 0, 0);
			else
				freemsg(mp);
		}
		flushq(qp, FLUSHALL);
		return;
	}

	/*
	 * while there are messages on this write queue...
	 */
	while ((mp = getq(qp)) != NULL) {
		/*
		 * Due to the way zc_wput is implemented, we should never
		 * see a control message here.
		 */
		ASSERT(mp->b_datap->db_type < QPCTL);

		if (bcanputnext(RD(zc_switch(qp)), mp->b_band)) {
			DBG("wsrv: send message to other side\n");
			putnext(RD(zc_switch(qp)), mp);
		} else {
			DBG("wsrv: putting msg back on queue\n");
			(void) putbq(qp, mp);
			break;
		}
	}
}
