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
 *
 *
 *
 * MASTER SIDE IOCTLS
 *
 * The ZC_HOLDSLAVE and ZC_RELEASESLAVE ioctls instruct the master side of the
 * console to hold and release a reference to the slave side's vnode.  They are
 * meant to be issued by zoneadmd after the console device node is created and
 * before it is destroyed so that the slave's STREAMS anchor, ptem, is
 * preserved when ttymon starts popping STREAMS modules from within the
 * associated zone.  This guarantees that the zone console will always have
 * terminal semantics while the zone is running.
 *
 * Here is the issue: the ptem module is anchored in the zone console
 * (slave side) so that processes within the associated non-global zone will
 * fail to pop it off, thus ensuring that the slave will retain terminal
 * semantics.  When a process attempts to pop the anchor off of a stream, the
 * STREAMS subsystem checks whether the calling process' zone is the same as
 * that of the process that pushed the anchor onto the stream and cancels the
 * pop if they differ.  zoneadmd used to hold an open file descriptor for the
 * slave while the associated non-global zone ran, thus ensuring that the
 * slave's STREAMS anchor would never be popped from within the non-global zone
 * (because zoneadmd runs in the global zone).  However, this file descriptor
 * was removed to make zone console management more robust.  sad(7D) is now
 * used to automatically set up the slave's STREAMS modules when the zone
 * console is freshly opened within the associated non-global zone.  However,
 * when a process within the non-global zone freshly opens the zone console, the
 * anchor is pushed from within the non-global zone, making it possible for
 * processes within the non-global zone (e.g., ttymon) to pop the anchor and
 * destroy the zone console's terminal semantics.
 *
 * One solution is to make the zcons device hold the slave open while the
 * associated non-global zone runs so that the STREAMS anchor will always be
 * associated with the global zone.  Unfortunately, the slave cannot be opened
 * from within the zcons driver because the driver is not reentrant: it has
 * an outer STREAMS perimeter.  Therefore, the next best option is for zcons to
 * provide an ioctl interface to zoneadmd to manage holding and releasing
 * the slave side of the console.  It is sufficient to hold the slave side's
 * vnode and bump the associated snode's reference count to preserve the slave's
 * STREAMS configuration while the associated zone runs, so that's what the
 * ioctls do.
 *
 *
 * ZC_HOLDSLAVE
 *
 * This ioctl takes a file descriptor as an argument.  It effectively gets a
 * reference to the slave side's minor node's vnode and bumps the associated
 * snode's reference count.  The vnode reference is stored in the zcons device
 * node's soft state.  This ioctl succeeds if the given file descriptor refers
 * to the slave side's minor node or if there is already a reference to the
 * slave side's minor node's vnode in the device's soft state.
 *
 *
 * ZC_RELEASESLAVE
 *
 * This ioctl takes a file descriptor as an argument.  It effectively releases
 * the vnode reference stored in the zcons device node's soft state (which was
 * previously acquired via ZC_HOLDSLAVE) and decrements the reference count of
 * the snode associated with the vnode.  This ioctl succeeds if the given file
 * descriptor refers to the slave side's minor node or if no reference to the
 * slave side's minor node's vnode is stored in the device's soft state.
 *
 *
 * Note that the file descriptor arguments for both ioctls must be cast to
 * integers of pointer width.
 *
 * Here's how the dance between zcons and zoneadmd works:
 *
 *     Zone boot:
 *     1.  While booting the zone, zoneadmd creates an instance of zcons.
 *     2.  zoneadmd opens the master and slave sides of the new zone console
 *         and issues the ZC_HOLDSLAVE ioctl on the master side, passing its
 *         file descriptor for the slave side as the ioctl argument.
 *     3.  zcons holds the slave side's vnode, bumps the snode's reference
 *         count, and stores a pointer to the vnode in the device's soft
 *         state.
 *     4.  zoneadmd closes the master and slave sides and continues to boot
 *         the zone.
 *
 *     Zone halt:
 *     1.  While halting the zone, zoneadmd opens the master and slave sides
 *         of the zone's console and issues the ZC_RELEASESLAVE ioctl on the
 *         master side, passing its file descriptor for the slave side as the
 *         ioctl argument.
 *     2.  zcons decrements the slave side's snode's reference count, releases
 *         the slave's vnode, and eliminates its reference to the vnode in the
 *         device's soft state.
 *     3.  zoneadmd closes the master and slave sides.
 *     4.  zoneadmd destroys the zcons device and continues to halt the zone.
 *
 * It is necessary for zoneadmd to hold the slave open while issuing
 * ZC_RELEASESLAVE because zcons might otherwise release the last reference to
 * the slave's vnode.  If it does, then specfs will panic because it will expect
 * that the STREAMS configuration for the vnode was destroyed, which VN_RELE
 * doesn't do.  Forcing zoneadmd to hold the slave open guarantees that zcons
 * won't release the vnode's last reference.  zoneadmd will properly destroy the
 * vnode and the snode when it closes the file descriptor.
 *
 * Technically, any process that can access the master side can issue these
 * ioctls, but they should be treated as private interfaces for zoneadmd.
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
#include <sys/zcons.h>
#include <sys/vnode.h>
#include <sys/fs/snode.h>
#include <sys/zone.h>

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
#define	ZC_MASTER_MINOR		0
#define	ZC_SLAVE_MINOR		1

#define	ZC_INSTANCE(x)		(getminor((x)) >> 1)
#define	ZC_NODE(x)		(getminor((x)) & 0x01)

/*
 * This macro converts a zc_state_t pointer to the associated slave minor node's
 * dev_t.
 */
#define	ZC_STATE_TO_SLAVEDEV(x)	(makedevice(ddi_driver_major((x)->zc_devinfo), \
	(minor_t)(ddi_get_instance((x)->zc_devinfo) << 1 | ZC_SLAVE_MINOR)))

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
	_TTY_BUFSIZ,
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
	vnode_t *zc_slave_vnode;
	int zc_state;
} zc_state_t;

#define	ZC_STATE_MOPEN	0x01
#define	ZC_STATE_SOPEN	0x02

static void *zc_soft_state;

/*
 * List of STREAMS modules that should be pushed onto every slave instance.
 */
static char *zcons_mods[] = {
	"ptem",
	"ldterm",
	"ttcompat",
	NULL
};

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

	/*
	 * Create the master and slave minor nodes.
	 */
	if ((ddi_create_minor_node(dip, ZCONS_SLAVE_NAME, S_IFCHR,
	    instance << 1 | ZC_SLAVE_MINOR, DDI_PSEUDO, 0) == DDI_FAILURE) ||
	    (ddi_create_minor_node(dip, ZCONS_MASTER_NAME, S_IFCHR,
	    instance << 1 | ZC_MASTER_MINOR, DDI_PSEUDO, 0) == DDI_FAILURE)) {
		ddi_remove_minor_node(dip, NULL);
		ddi_soft_state_free(zc_soft_state, instance);
		return (DDI_FAILURE);
	}

	VERIFY((zcs = ddi_get_soft_state(zc_soft_state, instance)) != NULL);
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
	sop->so_hiwat = _TTY_BUFSIZ;
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
	major_t major;
	minor_t minor;
	minor_t lastminor;
	uint_t anchorindex;

	/*
	 * The slave side can be opened as many times as needed.
	 */
	if ((zcs->zc_state & ZC_STATE_SOPEN) != 0) {
		ASSERT((rqp != NULL) && (WR(rqp)->q_ptr == zcs));
		return (0);
	}

	/*
	 * Set up sad(7D) so that the necessary STREAMS modules will be in
	 * place.  A wrinkle is that 'ptem' must be anchored
	 * in place (see streamio(7i)) because we always want the console to
	 * have terminal semantics.
	 */
	minor = ddi_get_instance(zcs->zc_devinfo) << 1 | ZC_SLAVE_MINOR;
	major = ddi_driver_major(zcs->zc_devinfo);
	lastminor = 0;
	anchorindex = 1;
	if (kstr_autopush(SET_AUTOPUSH, &major, &minor, &lastminor,
	    &anchorindex, zcons_mods) != 0) {
		DBG("zc_slave_open(): kstr_autopush() failed\n");
		return (EIO);
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
	sop->so_hiwat = _TTY_BUFSIZ;
	sop->so_lowat = 256;
	putnext(rqp, mop);

	return (0);
}

/*
 * open(9e) entrypoint; checks sflag, and rejects anything unordinary.
 */
static int
zc_open(queue_t *rqp,	/* pointer to the read side queue */
    dev_t   *devp,	/* pointer to stream tail's dev */
    int	oflag,		/* the user open(2) supplied flags */
    int	sflag,		/* open state flag */
    cred_t  *credp)	/* credentials */
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
	major_t major;
	minor_t minor;

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

		/*
		 * Clear the sad configuration so that reopening doesn't fail
		 * to set up sad configuration.
		 */
		major = ddi_driver_major(zcs->zc_devinfo);
		minor = ddi_get_instance(zcs->zc_devinfo) << 1 | ZC_SLAVE_MINOR;
		(void) kstr_autopush(CLR_AUTOPUSH, &major, &minor, NULL, NULL,
		    NULL);
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
 * without splitting the codepath.  (The only exception to this is the
 * processing of zcons ioctls, which is restricted to the master side.)
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
	zc_state_t *zcs;
	struct iocblk *iocbp;
	file_t *slave_filep;
	struct snode *slave_snodep;
	int slave_fd;

	ASSERT(qp->q_ptr);

	DBG1("entering zc_wput, %s side", zc_side(qp));

	/*
	 * Process zcons ioctl messages if qp is the master console's write
	 * queue.
	 */
	zcs = (zc_state_t *)qp->q_ptr;
	if (zcs->zc_master_rdq != NULL && qp == WR(zcs->zc_master_rdq) &&
	    type == M_IOCTL) {
		iocbp = (struct iocblk *)(void *)mp->b_rptr;
		switch (iocbp->ioc_cmd) {
		case ZC_HOLDSLAVE:
			/*
			 * Hold the slave's vnode and increment the refcount
			 * of the snode.  If the vnode is already held, then
			 * indicate success.
			 */
			if (iocbp->ioc_count != TRANSPARENT) {
				miocack(qp, mp, 0, EINVAL);
				return;
			}
			if (zcs->zc_slave_vnode != NULL) {
				miocack(qp, mp, 0, 0);
				return;
			}

			/*
			 * The process that passed the ioctl must be running in
			 * the global zone.
			 */
			if (curzone != global_zone) {
				miocack(qp, mp, 0, EINVAL);
				return;
			}

			/*
			 * The calling process must pass a file descriptor for
			 * the slave device.
			 */
			slave_fd =
			    (int)(intptr_t)*(caddr_t *)(void *)mp->b_cont->
			    b_rptr;
			slave_filep = getf(slave_fd);
			if (slave_filep == NULL) {
				miocack(qp, mp, 0, EINVAL);
				return;
			}
			if (ZC_STATE_TO_SLAVEDEV(zcs) !=
			    slave_filep->f_vnode->v_rdev) {
				releasef(slave_fd);
				miocack(qp, mp, 0, EINVAL);
				return;
			}

			/*
			 * Get a reference to the slave's vnode.  Also bump the
			 * reference count on the associated snode.
			 */
			ASSERT(vn_matchops(slave_filep->f_vnode,
			    spec_getvnodeops()));
			zcs->zc_slave_vnode = slave_filep->f_vnode;
			VN_HOLD(zcs->zc_slave_vnode);
			slave_snodep = VTOCS(zcs->zc_slave_vnode);
			mutex_enter(&slave_snodep->s_lock);
			++slave_snodep->s_count;
			mutex_exit(&slave_snodep->s_lock);
			releasef(slave_fd);
			miocack(qp, mp, 0, 0);
			return;
		case ZC_RELEASESLAVE:
			/*
			 * Release the master's handle on the slave's vnode.
			 * If there isn't a handle for the vnode, then indicate
			 * success.
			 */
			if (iocbp->ioc_count != TRANSPARENT) {
				miocack(qp, mp, 0, EINVAL);
				return;
			}
			if (zcs->zc_slave_vnode == NULL) {
				miocack(qp, mp, 0, 0);
				return;
			}

			/*
			 * The process that passed the ioctl must be running in
			 * the global zone.
			 */
			if (curzone != global_zone) {
				miocack(qp, mp, 0, EINVAL);
				return;
			}

			/*
			 * The process that passed the ioctl must have provided
			 * a file descriptor for the slave device.  Make sure
			 * this is correct.
			 */
			slave_fd =
			    (int)(intptr_t)*(caddr_t *)(void *)mp->b_cont->
			    b_rptr;
			slave_filep = getf(slave_fd);
			if (slave_filep == NULL) {
				miocack(qp, mp, 0, EINVAL);
				return;
			}
			if (zcs->zc_slave_vnode->v_rdev !=
			    slave_filep->f_vnode->v_rdev) {
				releasef(slave_fd);
				miocack(qp, mp, 0, EINVAL);
				return;
			}

			/*
			 * Decrement the snode's reference count and release the
			 * vnode.
			 */
			ASSERT(vn_matchops(slave_filep->f_vnode,
			    spec_getvnodeops()));
			slave_snodep = VTOCS(zcs->zc_slave_vnode);
			mutex_enter(&slave_snodep->s_lock);
			--slave_snodep->s_count;
			mutex_exit(&slave_snodep->s_lock);
			VN_RELE(zcs->zc_slave_vnode);
			zcs->zc_slave_vnode = NULL;
			releasef(slave_fd);
			miocack(qp, mp, 0, 0);
			return;
		default:
			break;
		}
	}

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
