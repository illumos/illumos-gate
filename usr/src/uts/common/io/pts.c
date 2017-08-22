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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/



/*
 * Pseudo Terminal Slave Driver.
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
 * See ptms.h, ptm.c and ptms_conf.c fore more information.
 *
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/ptms.h>
#include <sys/systm.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cred.h>
#include <sys/zone.h>

#ifdef DEBUG
int pts_debug = 0;
#define	DBG(a)	 if (pts_debug) cmn_err(CE_NOTE, a)
#else
#define	DBG(a)
#endif

static int ptsopen(queue_t *, dev_t *, int, int, cred_t *);
static int ptsclose(queue_t *, int, cred_t *);
static void ptswput(queue_t *, mblk_t *);
static void ptsrsrv(queue_t *);
static void ptswsrv(queue_t *);

/*
 * Slave Stream Pseudo Terminal Module: stream data structure definitions
 */
static struct module_info pts_info = {
	0xface,
	"pts",
	0,
	_TTY_BUFSIZ,
	_TTY_BUFSIZ,
	128
};

static struct qinit ptsrint = {
	NULL,
	(int (*)()) ptsrsrv,
	ptsopen,
	ptsclose,
	NULL,
	&pts_info,
	NULL
};

static struct qinit ptswint = {
	(int (*)()) ptswput,
	(int (*)()) ptswsrv,
	NULL,
	NULL,
	NULL,
	&pts_info,
	NULL
};

static struct streamtab ptsinfo = {
	&ptsrint,
	&ptswint,
	NULL,
	NULL
};

static int pts_devinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int pts_attach(dev_info_t *, ddi_attach_cmd_t);
static int pts_detach(dev_info_t *, ddi_detach_cmd_t);

#define	PTS_CONF_FLAG	(D_NEW | D_MP)

/*
 * this will define (struct cb_ops cb_pts_ops) and (struct dev_ops pts_ops)
 */
DDI_DEFINE_STREAM_OPS(pts_ops, nulldev, nulldev,	\
    pts_attach, pts_detach, nodev,			\
    pts_devinfo, PTS_CONF_FLAG, &ptsinfo, ddi_quiesce_not_supported);

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This one is a pseudo driver */
	"Slave Stream Pseudo Terminal driver 'pts'",
	&pts_ops,	/* driver ops */
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
pts_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	mutex_enter(&ptms_lock);
	pts_dip = devi;
	mutex_exit(&ptms_lock);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
pts_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	/*
	 * For now, pts cannot be detached.
	 */
	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
pts_devinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (pts_dip == NULL) {
			error = DDI_FAILURE;
		} else {
			*result = (void *)pts_dip;
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
 * Open the slave device. Reject a clone open and do not allow the
 * driver to be pushed. If the slave/master pair is locked or if
 * the master is not open, return EACCESS.
 * Upon success, store the write queue pointer in private data and
 * set the PTSOPEN bit in the pt_state field.
 */
static int
ptsopen(
	queue_t *rqp,		/* pointer to the read side queue */
	dev_t   *devp,		/* pointer to stream tail's dev */
	int	oflag,		/* the user open(2) supplied flags */
	int	sflag,		/* open state flag */
	cred_t  *credp)		/* credentials */
{
	struct pt_ttys	*ptsp;
	mblk_t		*mp;
	mblk_t		*mop;	/* ptr to a setopts message block */
	minor_t		dminor = getminor(*devp);
	struct stroptions *sop;

	DDBG("entering ptsopen(%d)", dminor);

	if (sflag != 0) {
		return (EINVAL);
	}

	mutex_enter(&ptms_lock);
	ptsp = ptms_minor2ptty(dminor);

	if (ptsp == NULL) {
		mutex_exit(&ptms_lock);
		return (ENXIO);
	}
	mutex_enter(&ptsp->pt_lock);

	/*
	 * Prevent opens from zones other than the one blessed by ptm.  We
	 * can't even allow the global zone to open all pts's, as it would
	 * otherwise inproperly be able to claim pts's already opened by zones.
	 */
	if (ptsp->pt_zoneid != getzoneid()) {
		mutex_exit(&ptsp->pt_lock);
		mutex_exit(&ptms_lock);
		return (EPERM);
	}

	/*
	 * Allow reopen of this device.
	 */
	if (rqp->q_ptr != NULL) {
		ASSERT(rqp->q_ptr == ptsp);
		ASSERT(ptsp->pts_rdq == rqp);
		mutex_exit(&ptsp->pt_lock);
		mutex_exit(&ptms_lock);
		return (0);
	}

	DDBGP("ptsopen: p = %p\n", (uintptr_t)ptsp);
	DDBG("ptsopen: state = %x\n", ptsp->pt_state);


	ASSERT(ptsp->pt_minor == dminor);

	if ((ptsp->pt_state & PTLOCK) || !(ptsp->pt_state & PTMOPEN)) {
		mutex_exit(&ptsp->pt_lock);
		mutex_exit(&ptms_lock);
		return (EAGAIN);
	}

	/*
	 * if already, open simply return...
	 */
	if (ptsp->pt_state & PTSOPEN) {
		ASSERT(rqp->q_ptr == ptsp);
		ASSERT(ptsp->pts_rdq == rqp);
		mutex_exit(&ptsp->pt_lock);
		mutex_exit(&ptms_lock);
		return (0);
	}

	/*
	 * Allocate message block for setting stream head options.
	 */
	if ((mop = allocb(sizeof (struct stroptions), BPRI_MED)) == NULL) {
		mutex_exit(&ptsp->pt_lock);
		mutex_exit(&ptms_lock);
		return (ENOMEM);
	}

	/*
	 * Slave should send zero-length message to a master when it is
	 * closing. If memory is low at that time, master will not detect slave
	 * closes, this pty will not be deallocated. So, preallocate this
	 * zero-length message block early.
	 */
	if ((mp = allocb(0, BPRI_MED)) == NULL) {
		mutex_exit(&ptsp->pt_lock);
		mutex_exit(&ptms_lock);
		freemsg(mop);
		return (ENOMEM);
	}

	ptsp->pt_state |= PTSOPEN;

	WR(rqp)->q_ptr = rqp->q_ptr = ptsp;

	mutex_exit(&ptsp->pt_lock);
	mutex_exit(&ptms_lock);

	qprocson(rqp);

	/*
	 * After qprocson pts driver is fully plumbed into the stream and can
	 * send/receive messages. Setting pts_rdq will allow master side to send
	 * messages to the slave. This setting can't occur before qprocson() is
	 * finished because slave is not ready to process them.
	 */
	PT_ENTER_WRITE(ptsp);
	ptsp->pts_rdq = rqp;
	ASSERT(ptsp->pt_nullmsg == NULL);
	ptsp->pt_nullmsg = mp;
	PT_EXIT_WRITE(ptsp);

	/*
	 * set up hi/lo water marks on stream head read queue
	 * and add controlling tty if not set
	 */

	mop->b_datap->db_type = M_SETOPTS;
	mop->b_wptr += sizeof (struct stroptions);
	sop = (struct stroptions *)mop->b_rptr;
	sop->so_flags = SO_HIWAT | SO_LOWAT | SO_ISTTY;
	sop->so_hiwat = _TTY_BUFSIZ;
	sop->so_lowat = 256;
	putnext(rqp, mop);

	return (0);
}



/*
 * Find the address to private data identifying the slave's write
 * queue. Send a 0-length msg up the slave's read queue to designate
 * the master is closing. Uattach the master from the slave by nulling
 * out master's write queue field in private data.
 */
/*ARGSUSED1*/
static int
ptsclose(queue_t *rqp, int flag, cred_t *credp)
{
	struct pt_ttys	*ptsp;
	queue_t *wqp;
	mblk_t	*mp;
	mblk_t	*bp;

	/*
	 * q_ptr should never be NULL in the close routine and it is checked in
	 * DEBUG kernel by ASSERT. For non-DEBUG kernel the attempt is made to
	 * behave gracefully.
	 */
	ASSERT(rqp->q_ptr != NULL);
	if (rqp->q_ptr == NULL) {
		qprocsoff(rqp);
		return (0);
	}

	ptsp = (struct pt_ttys *)rqp->q_ptr;

	/*
	 * Slave is going to close and doesn't want any new  messages coming
	 * from the master side, so set pts_rdq to NULL. This should be done
	 * before call to qprocsoff() since slave can't process additional
	 * messages from the master after qprocsoff is called.
	 */
	PT_ENTER_WRITE(ptsp);
	mp = ptsp->pt_nullmsg;
	ptsp->pt_nullmsg = NULL;
	ptsp->pts_rdq = NULL;
	PT_EXIT_WRITE(ptsp);

	/*
	 * Drain the ouput
	 */
	wqp = WR(rqp);
	PT_ENTER_READ(ptsp);
	while ((bp = getq(wqp)) != NULL) {
		if (ptsp->ptm_rdq) {
			putnext(ptsp->ptm_rdq, bp);
		} else if (bp->b_datap->db_type == M_IOCTL) {
			bp->b_datap->db_type = M_IOCNAK;
			freemsg(bp->b_cont);
			bp->b_cont = NULL;
			qreply(wqp, bp);
		} else {
			freemsg(bp);
		}
	}
	/*
	 * qenable master side write queue so that it can flush
	 * its messages as slaves's read queue is going away
	 */
	if (ptsp->ptm_rdq) {
		if (mp)
			putnext(ptsp->ptm_rdq, mp);
		else
			qenable(WR(ptsp->ptm_rdq));
	} else
		freemsg(mp);
	PT_EXIT_READ(ptsp);

	qprocsoff(rqp);

	rqp->q_ptr = NULL;
	WR(rqp)->q_ptr = NULL;

	ptms_close(ptsp, PTSOPEN | PTSTTY);

	return (0);
}


/*
 * The wput procedure will only handle flush messages.
 * All other messages are queued and the write side
 * service procedure sends them off to the master side.
 */
static void
ptswput(queue_t *qp, mblk_t *mp)
{
	struct pt_ttys *ptsp;
	struct iocblk  *iocp;
	unsigned char type = mp->b_datap->db_type;

	DBG(("entering ptswput\n"));
	ASSERT(qp->q_ptr);

	ptsp = (struct pt_ttys *)qp->q_ptr;
	PT_ENTER_READ(ptsp);
	if (ptsp->ptm_rdq == NULL) {
		DBG(("in write put proc but no master\n"));
		/*
		 * NAK ioctl as slave side read queue is gone.
		 * Or else free the message.
		 */
		if (mp->b_datap->db_type == M_IOCTL) {
			mp->b_datap->db_type = M_IOCNAK;
			freemsg(mp->b_cont);
			mp->b_cont = NULL;
			qreply(qp, mp);
		} else
			freemsg(mp);
		PT_EXIT_READ(ptsp);
		return;
	}

	if (type >= QPCTL) {
		switch (type) {

		/*
		 * if write queue request, flush slave's write
		 * queue and send FLUSHR to ptm. If read queue
		 * request, send FLUSHR to ptm.
		 */
		case M_FLUSH:
		DBG(("pts got flush request\n"));
		if (*mp->b_rptr & FLUSHW) {

			DBG(("got FLUSHW, flush pts write Q\n"));
			if (*mp->b_rptr & FLUSHBAND)
				/*
				 * if it is a FLUSHBAND, do flushband.
				 */
				flushband(qp, *(mp->b_rptr + 1), FLUSHDATA);
			else
				flushq(qp, FLUSHDATA);

			*mp->b_rptr &= ~FLUSHW;
			if ((*mp->b_rptr & FLUSHR) == 0) {
				/*
				 * FLUSHW only. Change to FLUSHR and putnext
				 * to ptm, then we are done.
				 */
				*mp->b_rptr |= FLUSHR;
				if (ptsp->ptm_rdq)
					putnext(ptsp->ptm_rdq, mp);
				break;
			} else {
				mblk_t *nmp;

				/* It is a FLUSHRW. Duplicate the mblk */
				nmp = copyb(mp);
				if (nmp) {
					/*
					 * Change FLUSHW to FLUSHR before
					 * putnext to ptm.
					 */
					DBG(("putnext nmp(FLUSHR) to ptm\n"));
					*nmp->b_rptr |= FLUSHR;
					if (ptsp->ptm_rdq)
						putnext(ptsp->ptm_rdq, nmp);
				}
			}
		}
		/*
		 * Since the packet module will toss any
		 * M_FLUSHES sent to the master's stream head
		 * read queue, we simply turn it around here.
		 */
		if (*mp->b_rptr & FLUSHR) {
			ASSERT(RD(qp)->q_first == NULL);
			DBG(("qreply(qp) turning FLUSHR around\n"));
			qreply(qp, mp);
		} else {
			freemsg(mp);
		}
		break;

		case M_READ:
		/* Caused by ldterm - can not pass to master */
		freemsg(mp);
		break;

		default:
		if (ptsp->ptm_rdq)
			putnext(ptsp->ptm_rdq, mp);
		break;
		}
		PT_EXIT_READ(ptsp);
		return;
	}

	switch (type) {

	case M_IOCTL:
		/*
		 * For case PTSSTTY set the flag PTSTTY and ACK
		 * the ioctl so that the user program can push
		 * the associated modules to get tty semantics.
		 * See bugid 4025044
		 */
		iocp = (struct iocblk *)mp->b_rptr;
		switch (iocp->ioc_cmd) {
		default:
			break;

		case PTSSTTY:
			if (ptsp->pt_state & PTSTTY) {
				mp->b_datap->db_type = M_IOCNAK;
				iocp->ioc_error = EEXIST;
			} else {
				mp->b_datap->db_type = M_IOCACK;
				mutex_enter(&ptsp->pt_lock);
				ptsp->pt_state |= PTSTTY;
				mutex_exit(&ptsp->pt_lock);
				iocp->ioc_error = 0;
			}
			iocp->ioc_count = 0;
			qreply(qp, mp);
			PT_EXIT_READ(ptsp);
			return;
		}

	default:
		/*
		 * send other messages to the master
		 */
		DBG(("put msg on slave's write queue\n"));
		(void) putq(qp, mp);
		break;
	}

	PT_EXIT_READ(ptsp);
	DBG(("return from ptswput()\n"));
}


/*
 * enable the write side of the master. This triggers the
 * master to send any messages queued on its write side to
 * the read side of this slave.
 */
static void
ptsrsrv(queue_t *qp)
{
	struct pt_ttys *ptsp;

	DBG(("entering ptsrsrv\n"));
	ASSERT(qp->q_ptr);

	ptsp = (struct pt_ttys *)qp->q_ptr;
	PT_ENTER_READ(ptsp);
	if (ptsp->ptm_rdq == NULL) {
		DBG(("in read srv proc but no master\n"));
		PT_EXIT_READ(ptsp);
		return;
	}
	qenable(WR(ptsp->ptm_rdq));
	PT_EXIT_READ(ptsp);
	DBG(("leaving ptsrsrv\n"));
}

/*
 * If there are messages on this queue that can be sent to
 * master, send them via putnext(). Else, if queued messages
 * cannot be sent, leave them on this queue. If priority
 * messages on this queue, send them to master no matter what.
 */
static void
ptswsrv(queue_t *qp)
{
	struct pt_ttys *ptsp;
	queue_t *ptm_rdq;
	mblk_t *mp;

	DBG(("entering ptswsrv\n"));
	ASSERT(qp->q_ptr);

	ptsp = (struct pt_ttys *)qp->q_ptr;
	PT_ENTER_READ(ptsp);
	if (ptsp->ptm_rdq == NULL) {
		DBG(("in write srv proc but no master\n"));
		/*
		 * Free messages on the write queue and send
		 * NAK for any M_IOCTL type messages to wakeup
		 * the user process waiting for ACK/NAK from
		 * the ioctl invocation
		 */
		while ((mp = getq(qp)) != NULL) {
			if (mp->b_datap->db_type == M_IOCTL) {
				mp->b_datap->db_type = M_IOCNAK;
				freemsg(mp->b_cont);
				mp->b_cont = NULL;
				qreply(qp, mp);
			} else
				freemsg(mp);
		}
		PT_EXIT_READ(ptsp);
		return;
	} else {
		ptm_rdq = ptsp->ptm_rdq;
	}

	/*
	 * while there are messages on this write queue...
	 */
	while ((mp = getq(qp)) != NULL) {
		/*
		 * if don't have control message and cannot put
		 * msg. on master's read queue, put it back on
		 * this queue.
		 */
		if (mp->b_datap->db_type <= QPCTL &&
		    !bcanputnext(ptm_rdq, mp->b_band)) {
			DBG(("put msg. back on Q\n"));
			(void) putbq(qp, mp);
			break;
		}
		/*
		 * else send the message up master's stream
		 */
		DBG(("send message to master\n"));
		putnext(ptm_rdq, mp);
	}
	DBG(("leaving ptswsrv\n"));
	PT_EXIT_READ(ptsp);
}
