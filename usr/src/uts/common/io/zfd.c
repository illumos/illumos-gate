/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

/*
 * Zone File Descriptor Driver.
 *
 * This driver is derived from the zcons driver which is in turn derived from
 * the pts/ptm drivers. The purpose is to expose file descriptors within the
 * zone which are connected to zoneadmd and used for logging or an interactive
 * connection to a process within the zone.
 *
 * Its implementation is straightforward. Each instance of the driver
 * represents a global-zone/local-zone pair. Unlike the zcons device, zoneadmd
 * uses these devices unidirectionally to provide stdin, stdout and stderr to
 * the process within the zone.
 *
 * Instances of zfd are onlined as children of /pseudo/zfdnex@2/ by zoneadmd,
 * using the devctl framework; thus the driver does not need to maintain any
 * sort of "admin" node.
 *
 * The driver shuttles I/O from master side to slave side and back.  In a break
 * from the pts/ptm semantics, if one side is not open, I/O directed towards
 * it will simply be discarded. This is so that if zoneadmd is not holding the
 * master side fd open (i.e. it has died somehow), processes in the zone do not
 * experience any errors and I/O to the fd does not cause the process to hang.
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
#include <sys/kstr.h>
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
#include <sys/zfd.h>
#include <sys/vnode.h>
#include <sys/fs/snode.h>
#include <sys/zone.h>

static int zfd_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int zfd_attach(dev_info_t *, ddi_attach_cmd_t);
static int zfd_detach(dev_info_t *, ddi_detach_cmd_t);

static int zfd_open(queue_t *, dev_t *, int, int, cred_t *);
static int zfd_close(queue_t *, int, cred_t *);
static void zfd_wput(queue_t *, mblk_t *);
static void zfd_rsrv(queue_t *);
static void zfd_wsrv(queue_t *);

/*
 * The instance number is encoded in the dev_t in the minor number; the lowest
 * bit of the minor number is used to track the master vs. slave side of the
 * fd. The rest of the bits in the minor number are the instance.
 */
#define	ZFD_MASTER_MINOR		0
#define	ZFD_SLAVE_MINOR		1

#define	ZFD_INSTANCE(x)		(getminor((x)) >> 1)
#define	ZFD_NODE(x)		(getminor((x)) & 0x01)

/*
 * This macro converts a zfd_state_t pointer to the associated slave minor
 * node's dev_t.
 */
#define	ZFD_STATE_TO_SLAVEDEV(x)	\
	(makedevice(ddi_driver_major((x)->zfd_devinfo), \
	(minor_t)(ddi_get_instance((x)->zfd_devinfo) << 1 | ZFD_SLAVE_MINOR)))

int zfd_debug = 0;
#define	DBG(a)		if (zfd_debug) cmn_err(CE_NOTE, a)
#define	DBG1(a, b)	if (zfd_debug) cmn_err(CE_NOTE, a, b)

/*
 * ZFD Pseudo Terminal Module: stream data structure definitions,
 * based on zcons.
 */
static struct module_info zfd_info = {
	0x20FD,	/* ZOFD - 8445 */
	"zfd",
	0,		/* min packet size */
	INFPSZ,		/* max packet size - infinity */
	2048,		/* high water */
	128		/* low water */
};

static struct qinit zfd_rinit = {
	NULL,
	(int (*)()) zfd_rsrv,
	zfd_open,
	zfd_close,
	NULL,
	&zfd_info,
	NULL
};

static struct qinit zfd_winit = {
	(int (*)()) zfd_wput,
	(int (*)()) zfd_wsrv,
	NULL,
	NULL,
	NULL,
	&zfd_info,
	NULL
};

static struct streamtab zfd_tab_info = {
	&zfd_rinit,
	&zfd_winit,
	NULL,
	NULL
};

#define	ZFD_CONF_FLAG	(D_MP | D_MTQPAIR | D_MTOUTPERIM | D_MTOCEXCL)

/*
 * this will define (struct cb_ops cb_zfd_ops) and (struct dev_ops zfd_ops)
 */
DDI_DEFINE_STREAM_OPS(zfd_ops, nulldev, nulldev, zfd_attach, zfd_detach, \
	nodev, zfd_getinfo, ZFD_CONF_FLAG, &zfd_tab_info, \
	ddi_quiesce_not_needed);

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, 	/* Type of module (this is a pseudo driver) */
	"Zone FD driver",	/* description of module */
	&zfd_ops		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

typedef struct zfd_state {
	dev_info_t *zfd_devinfo;
	queue_t *zfd_master_rdq;
	queue_t *zfd_slave_rdq;
	vnode_t *zfd_slave_vnode;
	int zfd_state;
	int zfd_tty;
} zfd_state_t;

#define	ZFD_STATE_MOPEN	0x01
#define	ZFD_STATE_SOPEN	0x02

static void *zfd_soft_state;

/*
 * List of STREAMS modules that is pushed onto a slave instance after the
 * ZFD_MAKETTY ioctl has been received.
 */
static char *zfd_mods[] = {
	"ptem",
	"ldterm",
	"ttcompat",
	NULL
};

int
_init(void)
{
	int err;

	if ((err = ddi_soft_state_init(&zfd_soft_state, sizeof (zfd_state_t),
	    0)) != 0) {
		return (err);
	}

	if ((err = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(zfd_soft_state);

	return (err);
}


int
_fini(void)
{
	int err;

	if ((err = mod_remove(&modlinkage)) != 0) {
		return (err);
	}

	ddi_soft_state_fini(&zfd_soft_state);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
zfd_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	zfd_state_t *zfds;
	int instance;
	char masternm[ZFD_NAME_LEN], slavenm[ZFD_NAME_LEN];

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	instance = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(zfd_soft_state, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);

	(void) snprintf(masternm, sizeof (masternm), "%s%d", ZFD_MASTER_NAME,
	    instance);
	(void) snprintf(slavenm, sizeof (slavenm), "%s%d", ZFD_SLAVE_NAME,
	    instance);

	/*
	 * Create the master and slave minor nodes.
	 */
	if ((ddi_create_minor_node(dip, slavenm, S_IFCHR,
	    instance << 1 | ZFD_SLAVE_MINOR, DDI_PSEUDO, 0) == DDI_FAILURE) ||
	    (ddi_create_minor_node(dip, masternm, S_IFCHR,
	    instance << 1 | ZFD_MASTER_MINOR, DDI_PSEUDO, 0) == DDI_FAILURE)) {
		ddi_remove_minor_node(dip, NULL);
		ddi_soft_state_free(zfd_soft_state, instance);
		return (DDI_FAILURE);
	}

	VERIFY((zfds = ddi_get_soft_state(zfd_soft_state, instance)) != NULL);
	zfds->zfd_devinfo = dip;
	zfds->zfd_tty = 0;
	return (DDI_SUCCESS);
}

static int
zfd_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	zfd_state_t *zfds;
	int instance;

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	instance = ddi_get_instance(dip);
	if ((zfds = ddi_get_soft_state(zfd_soft_state, instance)) == NULL)
		return (DDI_FAILURE);

	if ((zfds->zfd_state & ZFD_STATE_MOPEN) ||
	    (zfds->zfd_state & ZFD_STATE_SOPEN)) {
		DBG1("zfd_detach: device (dip=%p) still open\n", (void *)dip);
		return (DDI_FAILURE);
	}

	ddi_remove_minor_node(dip, NULL);
	ddi_soft_state_free(zfd_soft_state, instance);

	return (DDI_SUCCESS);
}

/*
 * zfd_getinfo()
 *	getinfo(9e) entrypoint.
 */
/*ARGSUSED*/
static int
zfd_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	zfd_state_t *zfds;
	int instance = ZFD_INSTANCE((dev_t)arg);

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((zfds = ddi_get_soft_state(zfd_soft_state,
		    instance)) == NULL)
			return (DDI_FAILURE);
		*result = zfds->zfd_devinfo;
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
zfd_switch(queue_t *qp)
{
	zfd_state_t *zfds = qp->q_ptr;
	ASSERT(zfds != NULL);

	if (qp == zfds->zfd_master_rdq)
		return (zfds->zfd_slave_rdq);
	else if (OTHERQ(qp) == zfds->zfd_master_rdq && zfds->zfd_slave_rdq
	    != NULL)
		return (OTHERQ(zfds->zfd_slave_rdq));
	else if (qp == zfds->zfd_slave_rdq)
		return (zfds->zfd_master_rdq);
	else if (OTHERQ(qp) == zfds->zfd_slave_rdq && zfds->zfd_master_rdq
	    != NULL)
		return (OTHERQ(zfds->zfd_master_rdq));
	else
		return (NULL);
}

/*
 * For debugging and outputting messages.  Returns the name of the side of
 * the relationship associated with this queue.
 */
static const char *
zfd_side(queue_t *qp)
{
	zfd_state_t *zfds = qp->q_ptr;
	ASSERT(zfds != NULL);

	if (qp == zfds->zfd_master_rdq ||
	    OTHERQ(qp) == zfds->zfd_master_rdq) {
		return ("master");
	}
	ASSERT(qp == zfds->zfd_slave_rdq || OTHERQ(qp) == zfds->zfd_slave_rdq);
	return ("slave");
}

/*ARGSUSED*/
static int
zfd_master_open(zfd_state_t *zfds,
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
	if ((zfds->zfd_state & ZFD_STATE_MOPEN) != 0)
		return (EBUSY);

	if ((mop = allocb(sizeof (struct stroptions), BPRI_MED)) == NULL) {
		DBG("zfd_master_open(): mop allocation failed\n");
		return (ENOMEM);
	}

	zfds->zfd_state |= ZFD_STATE_MOPEN;

	/*
	 * q_ptr stores driver private data; stash the soft state data on both
	 * read and write sides of the queue.
	 */
	WR(rqp)->q_ptr = rqp->q_ptr = zfds;
	qprocson(rqp);

	/*
	 * Following qprocson(), the master side is fully plumbed into the
	 * STREAM and may send/receive messages.  Setting zfds->zfd_master_rdq
	 * will allow the slave to send messages to us (the master).
	 * This cannot occur before qprocson() because the master is not
	 * ready to process them until that point.
	 */
	zfds->zfd_master_rdq = rqp;

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
zfd_slave_open(zfd_state_t *zfds,
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
	if ((zfds->zfd_state & ZFD_STATE_SOPEN) != 0) {
		ASSERT((rqp != NULL) && (WR(rqp)->q_ptr == zfds));
		return (0);
	}

	if (zfds->zfd_tty == 1) {
		major_t major;
		minor_t minor;
		minor_t lastminor;
		uint_t anchorindex;

		/*
		 * Set up sad(7D) so that the necessary STREAMS modules will
		 * be in place.  A wrinkle is that 'ptem' must be anchored
		 * in place (see streamio(7i)) because we always want the
		 * fd to have terminal semantics.
		 */
		minor =
		    ddi_get_instance(zfds->zfd_devinfo) << 1 | ZFD_SLAVE_MINOR;
		major = ddi_driver_major(zfds->zfd_devinfo);
		lastminor = 0;
		anchorindex = 1;
		if (kstr_autopush(SET_AUTOPUSH, &major, &minor, &lastminor,
		    &anchorindex, zfd_mods) != 0) {
			DBG("zfd_slave_open(): kstr_autopush() failed\n");
			return (EIO);
		}
	}

	if ((mop = allocb(sizeof (struct stroptions), BPRI_MED)) == NULL) {
		DBG("zfd_slave_open(): mop allocation failed\n");
		return (ENOMEM);
	}

	zfds->zfd_state |= ZFD_STATE_SOPEN;

	/*
	 * q_ptr stores driver private data; stash the soft state data on both
	 * read and write sides of the queue.
	 */
	WR(rqp)->q_ptr = rqp->q_ptr = zfds;

	qprocson(rqp);

	/*
	 * Must follow qprocson(), since we aren't ready to process until then.
	 */
	zfds->zfd_slave_rdq = rqp;

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
zfd_open(queue_t *rqp,		/* pointer to the read side queue */
	dev_t   *devp,		/* pointer to stream tail's dev */
	int	oflag,		/* the user open(2) supplied flags */
	int	sflag,		/* open state flag */
	cred_t  *credp)		/* credentials */
{
	int instance = ZFD_INSTANCE(*devp);
	int ret;
	zfd_state_t *zfds;

	if (sflag != 0)
		return (EINVAL);

	if ((zfds = ddi_get_soft_state(zfd_soft_state, instance)) == NULL)
		return (ENXIO);

	switch (ZFD_NODE(*devp)) {
	case ZFD_MASTER_MINOR:
		ret = zfd_master_open(zfds, rqp, devp, oflag, sflag, credp);
		break;
	case ZFD_SLAVE_MINOR:
		ret = zfd_slave_open(zfds, rqp, devp, oflag, sflag, credp);
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
zfd_close(queue_t *rqp, int flag, cred_t *credp)
{
	queue_t *wqp;
	mblk_t	*bp;
	zfd_state_t *zfds;
	major_t major;
	minor_t minor;

	zfds = (zfd_state_t *)rqp->q_ptr;

	if (rqp == zfds->zfd_master_rdq) {
		DBG("Closing master side");

		zfds->zfd_master_rdq = NULL;
		zfds->zfd_state &= ~ZFD_STATE_MOPEN;

		/*
		 * qenable slave side write queue so that it can flush
		 * its messages as master's read queue is going away
		 */
		if (zfds->zfd_slave_rdq != NULL) {
			qenable(WR(zfds->zfd_slave_rdq));
		}

		qprocsoff(rqp);
		WR(rqp)->q_ptr = rqp->q_ptr = NULL;

	} else if (rqp == zfds->zfd_slave_rdq) {

		DBG("Closing slave side");
		zfds->zfd_state &= ~ZFD_STATE_SOPEN;
		zfds->zfd_slave_rdq = NULL;

		wqp = WR(rqp);
		while ((bp = getq(wqp)) != NULL) {
			if (zfds->zfd_master_rdq != NULL)
				putnext(zfds->zfd_master_rdq, bp);
			else if (bp->b_datap->db_type == M_IOCTL)
				miocnak(wqp, bp, 0, 0);
			else
				freemsg(bp);
		}

		/*
		 * Qenable master side write queue so that it can flush its
		 * messages as slaves's read queue is going away.
		 */
		if (zfds->zfd_master_rdq != NULL)
			qenable(WR(zfds->zfd_master_rdq));

		qprocsoff(rqp);
		WR(rqp)->q_ptr = rqp->q_ptr = NULL;

		if (zfds->zfd_tty == 1) {
			/*
			 * Clear the sad configuration so that reopening
			 * doesn't fail to set up sad configuration.
			 */
			major = ddi_driver_major(zfds->zfd_devinfo);
			minor = ddi_get_instance(zfds->zfd_devinfo) << 1 |
			    ZFD_SLAVE_MINOR;
			(void) kstr_autopush(CLR_AUTOPUSH, &major, &minor,
			    NULL, NULL, NULL);
		}
	}

	return (0);
}

static void
handle_mflush(queue_t *qp, mblk_t *mp)
{
	mblk_t *nmp;
	DBG1("M_FLUSH on %s side", zfd_side(qp));

	if (*mp->b_rptr & FLUSHW) {
		DBG1("M_FLUSH, FLUSHW, %s side", zfd_side(qp));
		flushq(qp, FLUSHDATA);
		*mp->b_rptr &= ~FLUSHW;
		if ((*mp->b_rptr & FLUSHR) == 0) {
			/*
			 * FLUSHW only. Change to FLUSHR and putnext other side,
			 * then we are done.
			 */
			*mp->b_rptr |= FLUSHR;
			if (zfd_switch(RD(qp)) != NULL) {
				putnext(zfd_switch(RD(qp)), mp);
				return;
			}
		} else if ((zfd_switch(RD(qp)) != NULL) &&
		    (nmp = copyb(mp)) != NULL) {
			/*
			 * It is a FLUSHRW; we copy the mblk and send
			 * it to the other side, since we still need to use
			 * the mblk in FLUSHR processing, below.
			 */
			putnext(zfd_switch(RD(qp)), nmp);
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
 * without splitting the codepath.  (The only exception to this is the
 * processing of zfd ioctls, which is restricted to the master side.)
 *
 * zfd_wput() looks at the other side; if there is no process holding that
 * side open, it frees the message.  This prevents processes from hanging
 * if no one is holding open the fd.  Otherwise, it putnext's high
 * priority messages, putnext's normal messages if possible, and otherwise
 * enqueues the messages; in the case that something is enqueued, wsrv(9E)
 * will take care of eventually shuttling I/O to the other side.
 */
static void
zfd_wput(queue_t *qp, mblk_t *mp)
{
	unsigned char type = mp->b_datap->db_type;
	zfd_state_t *zfds;
	struct iocblk *iocbp;

	ASSERT(qp->q_ptr);

	DBG1("entering zfd_wput, %s side", zfd_side(qp));

	/*
	 * Process zfd ioctl messages if qp is the master side's write queue.
	 */
	zfds = (zfd_state_t *)qp->q_ptr;
	if (zfds->zfd_master_rdq != NULL && qp == WR(zfds->zfd_master_rdq) &&
	    type == M_IOCTL) {
		iocbp = (struct iocblk *)(void *)mp->b_rptr;
		switch (iocbp->ioc_cmd) {
		case ZFD_MAKETTY:
			/*
			 * The process that passed the ioctl must be running in
			 * the global zone.
			 */
			if (crgetzoneid(iocbp->ioc_cr) != GLOBAL_ZONEID) {
				miocack(qp, mp, 0, EINVAL);
				return;
			}
			zfds->zfd_tty = 1;
			miocack(qp, mp, 0, 0);
			return;
		default:
			break;
		}
	}

	if (zfd_switch(RD(qp)) == NULL) {
		DBG1("wput to %s side (no one listening)", zfd_side(qp));
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
		DBG1("(hipri) wput, %s side", zfd_side(qp));
		switch (type) {
		case M_READ:		/* supposedly from ldterm? */
			DBG("zfd_wput: tossing M_READ\n");
			freemsg(mp);
			break;
		case M_FLUSH:
			handle_mflush(qp, mp);
			break;
		default:
			/*
			 * Put this to the other side.
			 */
			ASSERT(zfd_switch(RD(qp)) != NULL);
			putnext(zfd_switch(RD(qp)), mp);
			break;
		}
		DBG1("done (hipri) wput, %s side", zfd_side(qp));
		return;
	}

	/*
	 * Only putnext if there isn't already something in the queue.
	 * otherwise things would wind up out of order.
	 */
	if (qp->q_first == NULL &&
	    bcanputnext(RD(zfd_switch(qp)), mp->b_band)) {
		DBG("wput: putting message to other side\n");
		putnext(RD(zfd_switch(qp)), mp);
	} else {
		DBG("wput: putting msg onto queue\n");
		(void) putq(qp, mp);
	}
	DBG1("done wput, %s side", zfd_side(qp));
}

/*
 * rsrv(9E) is symmetric for master and slave, so zfd_rsrv() handles both
 * without splitting up the codepath.
 *
 * Enable the write side of the partner.  This triggers the partner to send
 * messages queued on its write side to this queue's read side.
 */
static void
zfd_rsrv(queue_t *qp)
{
	zfd_state_t *zfds;
	zfds = (zfd_state_t *)qp->q_ptr;

	/*
	 * Care must be taken here, as either of the master or slave side
	 * qptr could be NULL.
	 */
	ASSERT(qp == zfds->zfd_master_rdq || qp == zfds->zfd_slave_rdq);
	if (zfd_switch(qp) == NULL) {
		DBG("zfd_rsrv: other side isn't listening\n");
		return;
	}
	qenable(WR(zfd_switch(qp)));
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
zfd_wsrv(queue_t *qp)
{
	mblk_t *mp;

	DBG1("zfd_wsrv master (%s) side", zfd_side(qp));

	/*
	 * Partner has no read queue, so take the data, and throw it away.
	 */
	if (zfd_switch(RD(qp)) == NULL) {
		DBG("zfd_wsrv: other side isn't listening");
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
		 * Due to the way zfd_wput is implemented, we should never
		 * see a control message here.
		 */
		ASSERT(mp->b_datap->db_type < QPCTL);

		if (bcanputnext(RD(zfd_switch(qp)), mp->b_band)) {
			DBG("wsrv: send message to other side\n");
			putnext(RD(zfd_switch(qp)), mp);
		} else {
			DBG("wsrv: putting msg back on queue\n");
			(void) putbq(qp, mp);
			break;
		}
	}
}
