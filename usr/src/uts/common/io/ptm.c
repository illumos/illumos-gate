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
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/



/*
 * Pseudo Terminal Master Driver.
 *
 * The pseudo-tty subsystem simulates a terminal connection, where the master
 * side represents the terminal and the slave represents the user process's
 * special device end point. The master device is set up as a cloned device
 * where its major device number is the major for the clone device and its minor
 * device number is the major for the ptm driver. There are no nodes in the file
 * system for master devices. The master pseudo driver is opened using the
 * open(2) system call with /dev/ptmx as the device parameter.  The clone open
 * finds the next available minor device for the ptm major device.
 *
 * A master device is available only if it and its corresponding slave device
 * are not already open. When the master device is opened, the corresponding
 * slave device is automatically locked out. Only one open is allowed on a
 * master device.  Multiple opens are allowed on the slave device.  After both
 * the master and slave have been opened, the user has two file descriptors
 * which are the end points of a full duplex connection composed of two streams
 * which are automatically connected at the master and slave drivers. The user
 * may then push modules onto either side of the stream pair.
 *
 * The master and slave drivers pass all messages to their adjacent queues.
 * Only the M_FLUSH needs some processing.  Because the read queue of one side
 * is connected to the write queue of the other, the FLUSHR flag is changed to
 * the FLUSHW flag and vice versa. When the master device is closed an M_HANGUP
 * message is sent to the slave device which will render the device
 * unusable. The process on the slave side gets the EIO when attempting to write
 * on that stream but it will be able to read any data remaining on the stream
 * head read queue.  When all the data has been read, read() returns 0
 * indicating that the stream can no longer be used.  On the last close of the
 * slave device, a 0-length message is sent to the master device. When the
 * application on the master side issues a read() or getmsg() and 0 is returned,
 * the user of the master device decides whether to issue a close() that
 * dismantles the pseudo-terminal subsystem. If the master device is not closed,
 * the pseudo-tty subsystem will be available to another user to open the slave
 * device.
 *
 * If O_NONBLOCK or O_NDELAY is set, read on the master side returns -1 with
 * errno set to EAGAIN if no data is available, and write returns -1 with errno
 * set to EAGAIN if there is internal flow control.
 *
 * IOCTLS:
 *
 *  ISPTM: determines whether the file descriptor is that of an open master
 *	   device. Return code of zero indicates that the file descriptor
 *	   represents master device.
 *
 *  UNLKPT: unlocks the master and slave devices.  It returns 0 on success. On
 *	    failure, the errno is set to EINVAL indicating that the master
 *	    device is not open.
 *
 *  ZONEPT: sets the zone membership of the associated pts device.
 *
 *  GRPPT:  sets the group owner of the associated pts device.
 *
 * Synchronization:
 *
 *   All global data synchronization between ptm/pts is done via global
 *   ptms_lock mutex which is initialized at system boot time from
 *   ptms_initspace (called from space.c).
 *
 *   Individual fields of pt_ttys structure (except ptm_rdq, pts_rdq and
 *   pt_nullmsg) are protected by pt_ttys.pt_lock mutex.
 *
 *   PT_ENTER_READ/PT_ENTER_WRITE are reference counter based read-write locks
 *   which allow reader locks to be reacquired by the same thread (usual
 *   reader/writer locks can't be used for that purpose since it is illegal for
 *   a thread to acquire a lock it already holds, even as a reader). The sole
 *   purpose of these macros is to guarantee that the peer queue will not
 *   disappear (due to closing peer) while it is used. It is safe to use
 *   PT_ENTER_READ/PT_EXIT_READ brackets across calls like putq/putnext (since
 *   they are not real locks but reference counts).
 *
 *   PT_ENTER_WRITE/PT_EXIT_WRITE brackets are used ONLY in master/slave
 *   open/close paths to modify ptm_rdq and pts_rdq fields. These fields should
 *   be set to appropriate queues *after* qprocson() is called during open (to
 *   prevent peer from accessing the queue with incomplete plumbing) and set to
 *   NULL before qprocsoff() is called during close.
 *
 *   The pt_nullmsg field is only used in open/close routines and it is also
 *   protected by PT_ENTER_WRITE/PT_EXIT_WRITE brackets to avoid extra mutex
 *   holds.
 *
 * Lock Ordering:
 *
 *   If both ptms_lock and per-pty lock should be held, ptms_lock should always
 *   be entered first, followed by per-pty lock.
 *
 * See ptms.h, pts.c and ptms_conf.c for more information.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/file.h>
#include <sys/sysmacros.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/proc.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/ptms.h>
#include <sys/stat.h>
#include <sys/strsun.h>
#include <sys/systm.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/zone.h>

#ifdef DEBUG
int ptm_debug = 0;
#define	DBG(a)	 if (ptm_debug) cmn_err(CE_NOTE, a)
#else
#define	DBG(a)
#endif

static int ptmopen(queue_t *, dev_t *, int, int, cred_t *);
static int ptmclose(queue_t *, int, cred_t *);
static void ptmwput(queue_t *, mblk_t *);
static void ptmrsrv(queue_t *);
static void ptmwsrv(queue_t *);

/*
 * Master Stream Pseudo Terminal Module: stream data structure definitions
 */

static struct module_info ptm_info = {
	0xdead,
	"ptm",
	0,
	512,
	512,
	128
};

static struct qinit ptmrint = {
	NULL,
	(int (*)()) ptmrsrv,
	ptmopen,
	ptmclose,
	NULL,
	&ptm_info,
	NULL
};

static struct qinit ptmwint = {
	(int (*)()) ptmwput,
	(int (*)()) ptmwsrv,
	NULL,
	NULL,
	NULL,
	&ptm_info,
	NULL
};

static struct streamtab ptminfo = {
	&ptmrint,
	&ptmwint,
	NULL,
	NULL
};

static int ptm_attach(dev_info_t *, ddi_attach_cmd_t);
static int ptm_detach(dev_info_t *, ddi_detach_cmd_t);
static int ptm_devinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);

static dev_info_t	*ptm_dip;		/* private devinfo pointer */

/*
 * this will define (struct cb_ops cb_ptm_ops) and (struct dev_ops ptm_ops)
 */
DDI_DEFINE_STREAM_OPS(ptm_ops, nulldev, nulldev, ptm_attach, ptm_detach,
    nodev, ptm_devinfo, D_MP, &ptminfo, ddi_quiesce_not_supported);

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This one is a pseudo driver */
	"Master streams driver 'ptm'",
	&ptm_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	int rc;

	if ((rc = mod_install(&modlinkage)) == 0)
		ptms_init();
	return (rc);
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
ptm_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(devi, "ptmajor", S_IFCHR,
	    0, DDI_PSEUDO, NULL) == DDI_FAILURE) {
		ddi_remove_minor_node(devi, NULL);
		return (DDI_FAILURE);
	}
	if (ddi_create_minor_node(devi, "ptmx", S_IFCHR,
	    0, DDI_PSEUDO, CLONE_DEV) == DDI_FAILURE) {
		ddi_remove_minor_node(devi, NULL);
		return (DDI_FAILURE);
	}
	ptm_dip = devi;

	return (DDI_SUCCESS);
}

static int
ptm_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	ddi_remove_minor_node(devi, NULL);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
ptm_devinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (ptm_dip == NULL) {
			error = DDI_FAILURE;
		} else {
			*result = (void *)ptm_dip;
			error = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}


/* ARGSUSED */
/*
 * Open a minor of the master device. Store the write queue pointer and set the
 * pt_state field to (PTMOPEN | PTLOCK).
 * This code will work properly with both clone opens and direct opens of the
 * master device.
 */
static int
ptmopen(
	queue_t *rqp,		/* pointer to the read side queue */
	dev_t   *devp,		/* pointer to stream tail's dev */
	int	oflag,		/* the user open(2) supplied flags */
	int	sflag,		/* open state flag */
	cred_t  *credp)		/* credentials */
{
	struct pt_ttys	*ptmp;
	mblk_t		*mop;		/* ptr to a setopts message block */
	struct stroptions *sop;
	minor_t		dminor = getminor(*devp);

	/* Allow reopen */
	if (rqp->q_ptr != NULL)
		return (0);

	if (sflag & MODOPEN)
		return (ENXIO);

	if (!(sflag & CLONEOPEN) && dminor != 0) {
		/*
		 * This is a direct open to specific master device through an
		 * artificially created entry with specific minor in
		 * /dev/directory. Such behavior is not supported.
		 */
		return (ENXIO);
	}

	/*
	 * The master open requires that the slave be attached
	 * before it returns so that attempts to open the slave will
	 * succeeed
	 */
	if (ptms_attach_slave() != 0) {
		return (ENXIO);
	}

	mop = allocb(sizeof (struct stroptions), BPRI_MED);
	if (mop == NULL) {
		DDBG("ptmopen(): mop allocation failed\n", 0);
		return (ENOMEM);
	}

	if ((ptmp = pt_ttys_alloc()) == NULL) {
		DDBG("ptmopen(): pty allocation failed\n", 0);
		freemsg(mop);
		return (ENOMEM);
	}

	dminor = ptmp->pt_minor;

	DDBGP("ptmopen(): allocated ptmp %p\n", (uintptr_t)ptmp);
	DDBG("ptmopen(): allocated minor %d\n", dminor);

	WR(rqp)->q_ptr = rqp->q_ptr = ptmp;

	qprocson(rqp);

	/* Allow slave to send messages to master */
	PT_ENTER_WRITE(ptmp);
	ptmp->ptm_rdq = rqp;
	PT_EXIT_WRITE(ptmp);

	/*
	 * set up hi/lo water marks on stream head read queue
	 * and add controlling tty if not set
	 */
	mop->b_datap->db_type = M_SETOPTS;
	mop->b_wptr += sizeof (struct stroptions);
	sop = (struct stroptions *)mop->b_rptr;
	if (oflag & FNOCTTY)
		sop->so_flags = SO_HIWAT | SO_LOWAT;
	else
		sop->so_flags = SO_HIWAT | SO_LOWAT | SO_ISTTY;
	sop->so_hiwat = _TTY_BUFSIZ;
	sop->so_lowat = 256;
	putnext(rqp, mop);

	/*
	 * The input, devp, is a major device number, the output is put
	 * into the same parm as a major,minor pair.
	 */
	*devp = makedevice(getmajor(*devp), dminor);

	return (0);
}


/*
 * Find the address to private data identifying the slave's write queue.
 * Send a hang-up message up the slave's read queue to designate the
 * master/slave pair is tearing down. Uattach the master and slave by
 * nulling out the write queue fields in the private data structure.
 * Finally, unlock the master/slave pair and mark the master as closed.
 */
/*ARGSUSED1*/
static int
ptmclose(queue_t *rqp, int flag, cred_t *credp)
{
	struct pt_ttys	*ptmp;
	queue_t *pts_rdq;

	ASSERT(rqp->q_ptr);

	ptmp = (struct pt_ttys *)rqp->q_ptr;
	PT_ENTER_READ(ptmp);
	if (ptmp->pts_rdq) {
		pts_rdq = ptmp->pts_rdq;
		if (pts_rdq->q_next) {
			DBG(("send hangup message to slave\n"));
			(void) putnextctl(pts_rdq, M_HANGUP);
		}
	}
	PT_EXIT_READ(ptmp);
	/*
	 * ptm_rdq should be cleared before call to qprocsoff() to prevent pts
	 * write procedure to attempt using ptm_rdq after qprocsoff.
	 */
	PT_ENTER_WRITE(ptmp);
	ptmp->ptm_rdq = NULL;
	freemsg(ptmp->pt_nullmsg);
	ptmp->pt_nullmsg = NULL;
	/*
	 * qenable slave side write queue so that it can flush
	 * its messages as master's read queue is going away
	 */
	if (ptmp->pts_rdq)
		qenable(WR(ptmp->pts_rdq));
	PT_EXIT_WRITE(ptmp);

	qprocsoff(rqp);

	/* Finish the close */
	rqp->q_ptr = NULL;
	WR(rqp)->q_ptr = NULL;

	ptms_close(ptmp, PTMOPEN | PTLOCK);

	return (0);
}

/*
 * The wput procedure will only handle ioctl and flush messages.
 */
static void
ptmwput(queue_t *qp, mblk_t *mp)
{
	struct pt_ttys	*ptmp;
	struct iocblk	*iocp;

	DBG(("entering ptmwput\n"));
	ASSERT(qp->q_ptr);

	ptmp = (struct pt_ttys *)qp->q_ptr;
	PT_ENTER_READ(ptmp);

	switch (mp->b_datap->db_type) {
	/*
	 * if write queue request, flush master's write
	 * queue and send FLUSHR up slave side. If read
	 * queue request, convert to FLUSHW and putnext().
	 */
	case M_FLUSH:
		{
			unsigned char flush_flg = 0;

			DBG(("ptm got flush request\n"));
			if (*mp->b_rptr & FLUSHW) {
				DBG(("got FLUSHW, flush ptm write Q\n"));
				if (*mp->b_rptr & FLUSHBAND)
					/*
					 * if it is a FLUSHBAND, do flushband.
					 */
					flushband(qp, *(mp->b_rptr + 1),
					    FLUSHDATA);
				else
					flushq(qp, FLUSHDATA);
				flush_flg = (*mp->b_rptr & ~FLUSHW) | FLUSHR;
			}
			if (*mp->b_rptr & FLUSHR) {
				DBG(("got FLUSHR, set FLUSHW\n"));
				flush_flg |= (*mp->b_rptr & ~FLUSHR) | FLUSHW;
			}
			if (flush_flg != 0 && ptmp->pts_rdq &&
			    !(ptmp->pt_state & PTLOCK)) {
				DBG(("putnext to pts\n"));
				*mp->b_rptr = flush_flg;
				putnext(ptmp->pts_rdq, mp);
			} else
				freemsg(mp);
			break;
		}

	case M_IOCTL:
		iocp = (struct iocblk *)mp->b_rptr;
		switch (iocp->ioc_cmd) {
		default:
			if ((ptmp->pt_state & PTLOCK) ||
			    (ptmp->pts_rdq == NULL)) {
				DBG(("got M_IOCTL but no slave\n"));
				miocnak(qp, mp, 0, EINVAL);
				PT_EXIT_READ(ptmp);
				return;
			}
			(void) putq(qp, mp);
			break;
		case UNLKPT:
			mutex_enter(&ptmp->pt_lock);
			ptmp->pt_state &= ~PTLOCK;
			mutex_exit(&ptmp->pt_lock);
			/*FALLTHROUGH*/
		case ISPTM:
			DBG(("ack the UNLKPT/ISPTM\n"));
			miocack(qp, mp, 0, 0);
			break;
		case ZONEPT:
		{
			zoneid_t z;
			int error;

			if ((error = drv_priv(iocp->ioc_cr)) != 0) {
				miocnak(qp, mp, 0, error);
				break;
			}
			if ((error = miocpullup(mp, sizeof (zoneid_t))) != 0) {
				miocnak(qp, mp, 0, error);
				break;
			}
			z = *((zoneid_t *)mp->b_cont->b_rptr);
			if (z < MIN_ZONEID || z > MAX_ZONEID) {
				miocnak(qp, mp, 0, EINVAL);
				break;
			}

			mutex_enter(&ptmp->pt_lock);
			ptmp->pt_zoneid = z;
			mutex_exit(&ptmp->pt_lock);
			miocack(qp, mp, 0, 0);
			break;
		}
		case OWNERPT:
		{
			pt_own_t *ptop;
			int error;
			zone_t *zone;

			if ((error = miocpullup(mp, sizeof (pt_own_t))) != 0) {
				miocnak(qp, mp, 0, error);
				break;
			}

			zone = zone_find_by_id(ptmp->pt_zoneid);
			ptop = (pt_own_t *)mp->b_cont->b_rptr;

			if (!VALID_UID(ptop->pto_ruid, zone) ||
			    !VALID_GID(ptop->pto_rgid, zone)) {
				zone_rele(zone);
				miocnak(qp, mp, 0, EINVAL);
				break;
			}
			zone_rele(zone);
			mutex_enter(&ptmp->pt_lock);
			ptmp->pt_ruid = ptop->pto_ruid;
			ptmp->pt_rgid = ptop->pto_rgid;
			mutex_exit(&ptmp->pt_lock);
			miocack(qp, mp, 0, 0);
			break;
		}
		}
		break;

	case M_READ:
		/* Caused by ldterm - can not pass to slave */
		freemsg(mp);
		break;

	/*
	 * send other messages to slave
	 */
	default:
		if ((ptmp->pt_state  & PTLOCK) || (ptmp->pts_rdq == NULL)) {
			DBG(("got msg. but no slave\n"));
			mp = mexchange(NULL, mp, 2, M_ERROR, -1);
			if (mp != NULL) {
				mp->b_rptr[0] = NOERROR;
				mp->b_rptr[1] = EINVAL;
				qreply(qp, mp);
			}
			PT_EXIT_READ(ptmp);
			return;
		}
		DBG(("put msg on master's write queue\n"));
		(void) putq(qp, mp);
		break;
	}
	DBG(("return from ptmwput()\n"));
	PT_EXIT_READ(ptmp);
}


/*
 * enable the write side of the slave. This triggers the
 * slave to send any messages queued on its write side to
 * the read side of this master.
 */
static void
ptmrsrv(queue_t *qp)
{
	struct pt_ttys	*ptmp;

	DBG(("entering ptmrsrv\n"));
	ASSERT(qp->q_ptr);

	ptmp = (struct pt_ttys *)qp->q_ptr;
	PT_ENTER_READ(ptmp);
	if (ptmp->pts_rdq) {
		qenable(WR(ptmp->pts_rdq));
	}
	PT_EXIT_READ(ptmp);
	DBG(("leaving ptmrsrv\n"));
}


/*
 * If there are messages on this queue that can be sent to
 * slave, send them via putnext(). Else, if queued messages
 * cannot be sent, leave them on this queue. If priority
 * messages on this queue, send them to slave no matter what.
 */
static void
ptmwsrv(queue_t *qp)
{
	struct pt_ttys	*ptmp;
	mblk_t 		*mp;

	DBG(("entering ptmwsrv\n"));
	ASSERT(qp->q_ptr);

	ptmp = (struct pt_ttys *)qp->q_ptr;

	if ((mp = getq(qp)) == NULL) {
		/* If there are no messages there's nothing to do. */
		DBG(("leaving ptmwsrv (no messages)\n"));
		return;
	}

	PT_ENTER_READ(ptmp);
	if ((ptmp->pt_state  & PTLOCK) || (ptmp->pts_rdq == NULL)) {
		DBG(("in master write srv proc but no slave\n"));
		/*
		 * Free messages on the write queue and send
		 * NAK for any M_IOCTL type messages to wakeup
		 * the user process waiting for ACK/NAK from
		 * the ioctl invocation
		 */
		do {
			if (mp->b_datap->db_type == M_IOCTL)
				miocnak(qp, mp, 0, EINVAL);
			else
				freemsg(mp);
		} while ((mp = getq(qp)) != NULL);
		flushq(qp, FLUSHALL);

		mp = mexchange(NULL, NULL, 2, M_ERROR, -1);
		if (mp != NULL) {
			mp->b_rptr[0] = NOERROR;
			mp->b_rptr[1] = EINVAL;
			qreply(qp, mp);
		}
		PT_EXIT_READ(ptmp);
		return;
	}
	/*
	 * while there are messages on this write queue...
	 */
	do {
		/*
		 * if don't have control message and cannot put
		 * msg. on slave's read queue, put it back on
		 * this queue.
		 */
		if (mp->b_datap->db_type <= QPCTL &&
		    !bcanputnext(ptmp->pts_rdq, mp->b_band)) {
			DBG(("put msg. back on queue\n"));
			(void) putbq(qp, mp);
			break;
		}
		/*
		 * else send the message up slave's stream
		 */
		DBG(("send message to slave\n"));
		putnext(ptmp->pts_rdq, mp);
	} while ((mp = getq(qp)) != NULL);
	DBG(("leaving ptmwsrv\n"));
	PT_EXIT_READ(ptmp);
}
