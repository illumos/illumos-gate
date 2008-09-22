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
 * Description: logindmux.c
 *
 * The logindmux driver is used with login modules (like telmod/rlmod).
 * This is a 1x1 cloning mux and two of these muxes are used. The lower link
 * of one of the muxes receives input from net and the lower link of the
 * other mux receives input from pseudo terminal subsystem.
 *
 * The logdmux_qexch_lock mutex manages the race between LOGDMX_IOC_QEXCHANGE,
 * logdmuxunlink() and logdmuxclose(), so that the instance selected as a peer
 * in LOGDMX_IOC_QEXCHANGE cannot be unlinked or closed until the qexchange
 * is complete; see the inline comments in the code for details.
 *
 * The logdmux_peerq_lock mutex manages the race between logdmuxlwsrv() and
 * logdmuxlrput() (when null'ing tmxp->peerq during LOGDMUX_UNLINK_REQ
 * processing).
 *
 * The logdmux_minor_lock mutex serializes the growth of logdmux_minor_arena
 * (the arena is grown gradually rather than allocated all at once so that
 * minor numbers are recycled sooner; for simplicity it is never shrunk).
 *
 * The unlink operation is implemented using protocol messages that flow
 * between the two logindmux peer instances. The instance processing the
 * I_UNLINK ioctl will send a LOGDMUX_UNLINK_REQ protocol message to its
 * peer to indicate that it wishes to unlink; the peer will process this
 * message in its lrput, null its tmxp->peerq and then send a
 * LOGDMUX_UNLINK_RESP protocol message in reply to indicate that the
 * unlink can proceed; having received the reply in its lrput, the
 * instance processing the I_UNLINK can then continue. To ensure that only
 * one of the peer instances will be actively processing an I_UNLINK at
 * any one time, a single structure (an unlinkinfo_t containing a mutex,
 * state variable and pointer to an M_CTL mblk) is allocated during
 * the processing of the LOGDMX_IOC_QEXCHANGE ioctl. The two instances, if
 * trying to unlink simultaneously, will race to get control of this
 * structure which contains the resources necessary to process the
 * I_UNLINK. The instance that wins this race will be able to continue
 * with the unlink whilst the other instance will be obliged to wait.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/logindmux.h>
#include <sys/logindmux_impl.h>
#include <sys/stat.h>
#include <sys/kmem.h>
#include <sys/vmem.h>
#include <sys/strsun.h>
#include <sys/sysmacros.h>
#include <sys/mkdev.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/termios.h>
#include <sys/cmn_err.h>

static int logdmuxopen(queue_t *, dev_t *, int, int, cred_t *);
static int logdmuxclose(queue_t *, int, cred_t *);
static int logdmuxursrv(queue_t *);
static int logdmuxuwput(queue_t *, mblk_t *);
static int logdmuxlrput(queue_t *, mblk_t *);
static int logdmuxlrsrv(queue_t *);
static int logdmuxlwsrv(queue_t *);
static int logdmuxuwsrv(queue_t *);
static int logdmux_alloc_unlinkinfo(struct tmx *, struct tmx *);

static void logdmuxlink(queue_t *, mblk_t *);
static void logdmuxunlink(queue_t *, mblk_t *);
static void logdmux_finish_unlink(queue_t *, mblk_t *);
static void logdmux_unlink_timer(void *arg);
static void recover(queue_t *, mblk_t *, size_t);
static void flushq_dataonly(queue_t *);

static kmutex_t logdmux_qexch_lock;
static kmutex_t logdmux_peerq_lock;
static kmutex_t logdmux_minor_lock;
static minor_t	logdmux_maxminor = 256;	/* grown as necessary */
static vmem_t	*logdmux_minor_arena;
static void	*logdmux_statep;

static struct module_info logdmuxm_info = {
	LOGDMX_ID,
	"logindmux",
	0,
	256,
	512,
	256
};

static struct qinit logdmuxurinit = {
	NULL,
	logdmuxursrv,
	logdmuxopen,
	logdmuxclose,
	NULL,
	&logdmuxm_info
};

static struct qinit logdmuxuwinit = {
	logdmuxuwput,
	logdmuxuwsrv,
	NULL,
	NULL,
	NULL,
	&logdmuxm_info
};

static struct qinit logdmuxlrinit = {
	logdmuxlrput,
	logdmuxlrsrv,
	NULL,
	NULL,
	NULL,
	&logdmuxm_info
};

static struct qinit logdmuxlwinit = {
	NULL,
	logdmuxlwsrv,
	NULL,
	NULL,
	NULL,
	&logdmuxm_info
};

struct streamtab logdmuxinfo = {
	&logdmuxurinit,
	&logdmuxuwinit,
	&logdmuxlrinit,
	&logdmuxlwinit
};

static int logdmux_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int logdmux_attach(dev_info_t *, ddi_attach_cmd_t);
static int logdmux_detach(dev_info_t *, ddi_detach_cmd_t);
static dev_info_t *logdmux_dip;

DDI_DEFINE_STREAM_OPS(logdmux_ops, nulldev, nulldev, logdmux_attach,
    logdmux_detach, nulldev, logdmux_info, D_MP | D_MTPERQ, &logdmuxinfo,
    ddi_quiesce_not_needed);

static struct modldrv modldrv = {
	&mod_driverops,
	"logindmux driver",
	&logdmux_ops
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

int
_init(void)
{
	int	ret;

	mutex_init(&logdmux_peerq_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&logdmux_qexch_lock, NULL, MUTEX_DRIVER, NULL);

	if ((ret = mod_install(&modlinkage)) != 0) {
		mutex_destroy(&logdmux_peerq_lock);
		mutex_destroy(&logdmux_qexch_lock);
		return (ret);
	}

	logdmux_minor_arena = vmem_create("logdmux_minor", (void *)1,
	    logdmux_maxminor, 1, NULL, NULL, NULL, 0,
	    VM_SLEEP | VMC_IDENTIFIER);
	(void) ddi_soft_state_init(&logdmux_statep, sizeof (struct tmx), 1);

	return (0);
}

int
_fini(void)
{
	int	ret;

	if ((ret = mod_remove(&modlinkage)) == 0) {
		mutex_destroy(&logdmux_peerq_lock);
		mutex_destroy(&logdmux_qexch_lock);
		ddi_soft_state_fini(&logdmux_statep);
		vmem_destroy(logdmux_minor_arena);
		logdmux_minor_arena = NULL;
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
logdmux_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(devi, "logindmux", S_IFCHR, 0, DDI_PSEUDO,
	    CLONE_DEV) == DDI_FAILURE)
		return (DDI_FAILURE);

	logdmux_dip = devi;
	return (DDI_SUCCESS);
}

static int
logdmux_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	ddi_remove_minor_node(devi, NULL);
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
logdmux_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (logdmux_dip == NULL) {
			error = DDI_FAILURE;
		} else {
			*result = logdmux_dip;
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

/*
 * Logindmux open routine
 */
/*ARGSUSED*/
static int
logdmuxopen(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *crp)
{
	struct	tmx *tmxp;
	minor_t	minor, omaxminor;

	if (sflag != CLONEOPEN)
		return (EINVAL);

	mutex_enter(&logdmux_minor_lock);
	if (vmem_size(logdmux_minor_arena, VMEM_FREE) == 0) {
		/*
		 * The arena has been exhausted; grow by powers of two
		 * up to MAXMIN; bail if we've run out of minors.
		 */
		if (logdmux_maxminor == MAXMIN) {
			mutex_exit(&logdmux_minor_lock);
			return (ENOMEM);
		}

		omaxminor = logdmux_maxminor;
		logdmux_maxminor = MIN(logdmux_maxminor << 1, MAXMIN);

		(void) vmem_add(logdmux_minor_arena,
		    (void *)(uintptr_t)(omaxminor + 1),
		    logdmux_maxminor - omaxminor, VM_SLEEP);
	}
	minor = (minor_t)(uintptr_t)
	    vmem_alloc(logdmux_minor_arena, 1, VM_SLEEP);
	mutex_exit(&logdmux_minor_lock);

	if (ddi_soft_state_zalloc(logdmux_statep, minor) == DDI_FAILURE) {
		vmem_free(logdmux_minor_arena, (void *)(uintptr_t)minor, 1);
		return (ENOMEM);
	}

	tmxp = ddi_get_soft_state(logdmux_statep, minor);
	tmxp->rdq = q;
	tmxp->muxq = NULL;
	tmxp->peerq = NULL;
	tmxp->unlinkinfop = NULL;
	tmxp->dev0 = minor;

	*devp = makedevice(getmajor(*devp), tmxp->dev0);
	q->q_ptr = tmxp;
	WR(q)->q_ptr = tmxp;

	qprocson(q);
	return (0);
}

/*
 * Logindmux close routine gets called when telnet connection is closed
 */
/*ARGSUSED*/
static int
logdmuxclose(queue_t *q, int flag, cred_t *crp)
{
	struct tmx	*tmxp = q->q_ptr;
	minor_t		minor = tmxp->dev0;

	ASSERT(tmxp->muxq == NULL);
	ASSERT(tmxp->peerq == NULL);

	qprocsoff(q);
	if (tmxp->wbufcid != 0) {
		qunbufcall(q, tmxp->wbufcid);
		tmxp->wbufcid = 0;
	}
	if (tmxp->rbufcid != 0) {
		qunbufcall(q, tmxp->rbufcid);
		tmxp->rbufcid = 0;
	}
	if (tmxp->rtimoutid != 0) {
		(void) quntimeout(q, tmxp->rtimoutid);
		tmxp->rtimoutid = 0;
	}
	if (tmxp->wtimoutid != 0) {
		(void) quntimeout(q, tmxp->wtimoutid);
		tmxp->wtimoutid = 0;
	}
	if (tmxp->utimoutid != 0) {
		(void) quntimeout(q, tmxp->utimoutid);
		tmxp->utimoutid = 0;
	}

	/*
	 * Hold logdmux_qexch_lock to prevent another thread that might be
	 * in LOGDMX_IOC_QEXCHANGE from looking up our state while we're
	 * disposing of it.
	 */
	mutex_enter(&logdmux_qexch_lock);
	ddi_soft_state_free(logdmux_statep, minor);
	vmem_free(logdmux_minor_arena, (void *)(uintptr_t)minor, 1);
	mutex_exit(&logdmux_qexch_lock);

	q->q_ptr = NULL;
	WR(q)->q_ptr = NULL;

	return (0);
}

/*
 * Upper read service routine
 */
static int
logdmuxursrv(queue_t *q)
{
	struct tmx *tmxp = q->q_ptr;

	if (tmxp->muxq != NULL)
		qenable(RD(tmxp->muxq));
	return (0);
}

/*
 * This routine gets called when telnet daemon sends data or ioctl messages
 * to upper mux queue.
 */
static int
logdmuxuwput(queue_t *q, mblk_t *mp)
{
	queue_t		*qp;
	mblk_t		*newmp;
	struct iocblk	*ioc;
	minor_t		minor;
	STRUCT_HANDLE(protocol_arg, protoh);
	struct tmx	*tmxp, *tmxpeerp;
	int		error;

	tmxp = q->q_ptr;

	switch (mp->b_datap->db_type) {

	case M_IOCTL:
		ASSERT(MBLKL(mp) == sizeof (struct iocblk));

		ioc = (struct iocblk *)mp->b_rptr;
		switch (ioc->ioc_cmd) {
		/*
		 * This is a special ioctl which exchanges q info
		 * of the two peers, connected to netf and ptmx.
		 */
		case LOGDMX_IOC_QEXCHANGE:
			error = miocpullup(mp,
			    SIZEOF_STRUCT(protocol_arg, ioc->ioc_flag));
			if (error != 0) {
				miocnak(q, mp, 0, error);
				break;
			}
			STRUCT_SET_HANDLE(protoh, ioc->ioc_flag,
			    (struct protocol_arg *)mp->b_cont->b_rptr);
#ifdef _SYSCALL32_IMPL
			if ((ioc->ioc_flag & DATAMODEL_MASK) ==
			    DATAMODEL_ILP32) {
				minor = getminor(expldev(
				    STRUCT_FGET(protoh, dev)));
			} else
#endif
			{
				minor = getminor(STRUCT_FGET(protoh, dev));
			}

			/*
			 * The second argument to ddi_get_soft_state() is
			 * interpreted as an `int', so prohibit negative
			 * values.
			 */
			if ((int)minor < 0) {
				miocnak(q, mp, 0, EINVAL);
				break;
			}

			/*
			 * We must hold logdmux_qexch_lock while looking up
			 * the proposed peer to prevent another thread from
			 * simultaneously I_UNLINKing or closing it.
			 */
			mutex_enter(&logdmux_qexch_lock);

			/*
			 * For LOGDMX_IOC_QEXCHANGE to succeed, our peer must
			 * exist (and not be us), and both we and our peer
			 * must be I_LINKed (i.e., muxq must not be NULL) and
			 * not already have a peer.
			 */
			tmxpeerp = ddi_get_soft_state(logdmux_statep, minor);
			if (tmxpeerp == NULL || tmxpeerp == tmxp ||
			    tmxpeerp->muxq == NULL || tmxpeerp->peerq != NULL ||
			    tmxp->muxq == NULL || tmxp->peerq != NULL) {
				mutex_exit(&logdmux_qexch_lock);
				miocnak(q, mp, 0, EINVAL);
				break;
			}

			/*
			 * If `flag' is set then exchange queues and assume
			 * tmxp refers to the ptmx stream.
			 */
			if (STRUCT_FGET(protoh, flag)) {
				/*
				 * Allocate and populate the structure we
				 * need when processing an I_UNLINK ioctl.
				 * Give both logindmux instances a pointer
				 * to it from their tmx structure.
				 */
				if ((error = logdmux_alloc_unlinkinfo(
				    tmxp, tmxpeerp)) != 0) {
					mutex_exit(&logdmux_qexch_lock);
					miocnak(q, mp, 0, error);
					break;
				}
				tmxp->peerq = tmxpeerp->muxq;
				tmxpeerp->peerq = tmxp->muxq;
				tmxp->isptm = B_TRUE;
			}
			mutex_exit(&logdmux_qexch_lock);
			miocack(q, mp, 0, 0);
			break;

		case I_LINK:
			ASSERT(MBLKL(mp->b_cont) == sizeof (struct linkblk));
			logdmuxlink(q, mp);
			break;

		case I_UNLINK:
			ASSERT(MBLKL(mp->b_cont) == sizeof (struct linkblk));
			logdmuxunlink(q, mp);
			break;

		default:
			if (tmxp->muxq == NULL) {
				miocnak(q, mp, 0, EINVAL);
				return (0);
			}
			putnext(tmxp->muxq, mp);
			break;
		}

		break;

	case M_DATA:
		if (!tmxp->isptm) {
			if ((newmp = allocb(sizeof (char), BPRI_MED)) == NULL) {
				recover(q, mp, sizeof (char));
				return (0);
			}
			newmp->b_datap->db_type = M_CTL;
			*newmp->b_wptr++ = M_CTL_MAGIC_NUMBER;
			newmp->b_cont = mp;
			mp = newmp;
		}
		/* FALLTHRU */

	case M_PROTO:
	case M_PCPROTO:
		qp = tmxp->muxq;
		if (qp == NULL) {
			merror(q, mp, EINVAL);
			return (0);
		}

		if (queclass(mp) < QPCTL) {
			if (q->q_first != NULL || !canputnext(qp)) {
				(void) putq(q, mp);
				return (0);
			}
		}
		putnext(qp, mp);
		break;

	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW)
			flushq(q, FLUSHALL);

		if (tmxp->muxq != NULL) {
			putnext(tmxp->muxq, mp);
			return (0);
		}

		*mp->b_rptr &= ~FLUSHW;
		if (*mp->b_rptr & FLUSHR)
			qreply(q, mp);
		else
			freemsg(mp);
		break;

	default:
		cmn_err(CE_NOTE, "logdmuxuwput: received unexpected message"
		    " of type 0x%x", mp->b_datap->db_type);
		freemsg(mp);
	}
	return (0);
}

/*
 * Upper write service routine
 */
static int
logdmuxuwsrv(queue_t *q)
{
	mblk_t		*mp, *newmp;
	queue_t		*qp;
	struct tmx	*tmxp = q->q_ptr;

	while ((mp = getq(q)) != NULL) {
		switch (mp->b_datap->db_type) {
		case M_DATA:
			if (!tmxp->isptm) {
				if ((newmp = allocb(sizeof (char), BPRI_MED)) ==
				    NULL) {
					recover(q, mp, sizeof (char));
					return (0);
				}
				newmp->b_datap->db_type = M_CTL;
				*newmp->b_wptr++ = M_CTL_MAGIC_NUMBER;
				newmp->b_cont = mp;
				mp = newmp;
			}
			/* FALLTHRU */

		case M_CTL:
		case M_PROTO:
			if (tmxp->muxq == NULL) {
				merror(q, mp, EIO);
				break;
			}
			qp = tmxp->muxq;
			if (!canputnext(qp)) {
				(void) putbq(q, mp);
				return (0);
			}
			putnext(qp, mp);
			break;


		default:
			cmn_err(CE_NOTE, "logdmuxuwsrv: received unexpected"
			    " message of type 0x%x", mp->b_datap->db_type);
			freemsg(mp);
		}
	}
	return (0);
}

/*
 * Logindmux lower put routine detects from which of the two lower queues
 * the data needs to be read from and writes it out to its peer queue.
 * For protocol, it detects M_CTL and sends its data to the daemon. Also,
 * for ioctl and other types of messages, it lets the daemon handle it.
 */
static int
logdmuxlrput(queue_t *q, mblk_t *mp)
{
	mblk_t		*savemp;
	queue_t 	*qp;
	struct iocblk	*ioc;
	struct tmx	*tmxp = q->q_ptr;
	uchar_t		flush;
	uint_t		*messagep;
	unlinkinfo_t	*unlinkinfop = tmxp->unlinkinfop;

	if (tmxp->muxq == NULL || tmxp->peerq == NULL) {
		freemsg(mp);
		return (0);
	}

	/*
	 * If there's already a message on our queue and the incoming
	 * message is not of a high-priority, enqueue the message --
	 * but not if it's a logindmux protocol message.
	 */
	if ((q->q_first != NULL) && (queclass(mp) < QPCTL) &&
	    (!LOGDMUX_PROTO_MBLK(mp))) {
		(void) putq(q, mp);
		return (0);
	}

	switch (mp->b_datap->db_type) {

	case M_IOCTL:
		ioc = (struct iocblk *)mp->b_rptr;
		switch (ioc->ioc_cmd) {

		case TIOCSWINSZ:
		case TCSETAF:
		case TCSETSF:
		case TCSETA:
		case TCSETAW:
		case TCSETS:
		case TCSETSW:
		case TCSBRK:
		case TIOCSTI:
			qp = tmxp->peerq;
			break;

		default:
			cmn_err(CE_NOTE, "logdmuxlrput: received unexpected"
			    " request for ioctl 0x%x", ioc->ioc_cmd);

			/* NAK unrecognized ioctl's. */
			miocnak(q, mp, 0, 0);
			return (0);
		}
		break;

	case M_DATA:
	case M_HANGUP:
		qp = tmxp->peerq;
		break;

	case M_CTL:
		/*
		 * The protocol messages that flow between the peers
		 * to implement the unlink functionality are M_CTLs
		 * which have the M_IOCTL/I_UNLINK mblk of the ioctl
		 * attached via b_cont.  LOGDMUX_PROTO_MBLK() uses
		 * this to determine whether a particular M_CTL is a
		 * peer protocol message.
		 */
		if (LOGDMUX_PROTO_MBLK(mp)) {
			messagep = (uint_t *)mp->b_rptr;

			switch (*messagep) {

			case LOGDMUX_UNLINK_REQ:
				/*
				 * We've received a message from our
				 * peer indicating that it wants to
				 * unlink.
				 */
				*messagep = LOGDMUX_UNLINK_RESP;
				qp = tmxp->peerq;

				mutex_enter(&logdmux_peerq_lock);
				tmxp->peerq = NULL;
				mutex_exit(&logdmux_peerq_lock);

				put(RD(qp), mp);
				return (0);

			case LOGDMUX_UNLINK_RESP:
				/*
				 * We've received a positive response
				 * from our peer to an earlier
				 * LOGDMUX_UNLINK_REQ that we sent.
				 * We can now carry on with the unlink.
				 */
				qp = tmxp->rdq;
				mutex_enter(&unlinkinfop->state_lock);
				ASSERT(unlinkinfop->state ==
				    LOGDMUX_UNLINK_PENDING);
				unlinkinfop->state = LOGDMUX_UNLINKED;
				mutex_exit(&unlinkinfop->state_lock);
				logdmux_finish_unlink(WR(qp), mp->b_cont);
				return (0);
			}
		}

		qp = tmxp->rdq;
		if (q->q_first != NULL || !canputnext(qp)) {
			(void) putq(q, mp);
			return (0);
		}
		if ((MBLKL(mp) == 1) && (*mp->b_rptr == M_CTL_MAGIC_NUMBER)) {
			savemp = mp->b_cont;
			freeb(mp);
			mp = savemp;
		}
		putnext(qp, mp);
		return (0);

	case M_IOCACK:
	case M_IOCNAK:
	case M_PROTO:
	case M_PCPROTO:
	case M_PCSIG:
	case M_SETOPTS:
		qp = tmxp->rdq;
		break;

	case M_ERROR:
		if (tmxp->isptm) {
			/*
			 * This error is from ptm.  We could tell TCP to
			 * shutdown the connection, but it's easier to just
			 * wait for the daemon to get SIGCHLD and close from
			 * above.
			 */
			freemsg(mp);
			return (0);
		}
		/*
		 * This is from TCP.  Don't really know why we'd
		 * get this, but we have a pretty good idea what
		 * to do:  Send M_HANGUP to the pty.
		 */
		mp->b_datap->db_type = M_HANGUP;
		mp->b_wptr = mp->b_rptr;
		qp = tmxp->peerq;
		break;

	case M_FLUSH:
		if (*mp->b_rptr & FLUSHR)
			flushq_dataonly(q);

		if (mp->b_flag & MSGMARK) {
			/*
			 * This M_FLUSH has been marked by the module
			 * below as intended for the upper queue,
			 * not the peer queue.
			 */
			qp = tmxp->rdq;
			mp->b_flag &= ~MSGMARK;
		} else {
			/*
			 * Wrap this M_FLUSH through the mux.
			 * The FLUSHR and FLUSHW bits must be
			 * reversed.
			 */
			qp = tmxp->peerq;
			flush = *mp->b_rptr;
			*mp->b_rptr &= ~(FLUSHR | FLUSHW);
			if (flush & FLUSHW)
				*mp->b_rptr |= FLUSHR;
			if (flush & FLUSHR)
				*mp->b_rptr |= FLUSHW;
		}
		break;

	case M_START:
	case M_STOP:
	case M_STARTI:
	case M_STOPI:
		freemsg(mp);
		return (0);

	default:
		cmn_err(CE_NOTE, "logdmuxlrput: received unexpected "
		    "message of type 0x%x", mp->b_datap->db_type);
		freemsg(mp);
		return (0);
	}
	if (queclass(mp) < QPCTL) {
		if (q->q_first != NULL || !canputnext(qp)) {
			(void) putq(q, mp);
			return (0);
		}
	}
	putnext(qp, mp);
	return (0);
}

/*
 * Lower read service routine
 */
static int
logdmuxlrsrv(queue_t *q)
{
	mblk_t		*mp, *savemp;
	queue_t 	*qp;
	struct iocblk	*ioc;
	struct tmx	*tmxp = q->q_ptr;

	while ((mp = getq(q)) != NULL) {
		if (tmxp->muxq == NULL || tmxp->peerq == NULL) {
			freemsg(mp);
			continue;
		}

		switch (mp->b_datap->db_type) {

		case M_IOCTL:
			ioc = (struct iocblk *)mp->b_rptr;

			switch (ioc->ioc_cmd) {

			case TIOCSWINSZ:
			case TCSETAF:
			case TCSETSF:
			case TCSETA:
			case TCSETAW:
			case TCSETS:
			case TCSETSW:
			case TCSBRK:
			case TIOCSTI:
				qp = tmxp->peerq;
				break;

			default:
				cmn_err(CE_NOTE, "logdmuxlrsrv: received "
				    "unexpected request for ioctl 0x%x",
				    ioc->ioc_cmd);

				/* NAK unrecognized ioctl's. */
				miocnak(q, mp, 0, 0);
				continue;
			}
			break;

		case M_DATA:
		case M_HANGUP:
			qp = tmxp->peerq;
			break;

		case M_CTL:
			qp = tmxp->rdq;
			if (!canputnext(qp)) {
				(void) putbq(q, mp);
				return (0);
			}
			if (MBLKL(mp) == 1 &&
			    (*mp->b_rptr == M_CTL_MAGIC_NUMBER)) {
				savemp = mp->b_cont;
				freeb(mp);
				mp = savemp;
			}
			putnext(qp, mp);
			continue;

		case M_PROTO:
		case M_SETOPTS:
			qp = tmxp->rdq;
			break;

		default:
			cmn_err(CE_NOTE, "logdmuxlrsrv: received unexpected "
			    "message of type 0x%x", mp->b_datap->db_type);
			freemsg(mp);
			continue;
		}
		ASSERT(queclass(mp) < QPCTL);
		if (!canputnext(qp)) {
			(void) putbq(q, mp);
			return (0);
		}
		putnext(qp, mp);
	}
	return (0);
}

/*
 * Lower side write service procedure.  No messages are ever placed on
 * the write queue here, this just back-enables all of the upper side
 * write service procedures.
 */
static int
logdmuxlwsrv(queue_t *q)
{
	struct tmx *tmxp = q->q_ptr;

	/*
	 * Qenable upper write queue and find out which lower
	 * queue needs to be restarted with flow control.
	 * Qenable the peer queue so canputnext will
	 * succeed on next call to logdmuxlrput.
	 */
	qenable(WR(tmxp->rdq));

	mutex_enter(&logdmux_peerq_lock);
	if (tmxp->peerq != NULL)
		qenable(RD(tmxp->peerq));
	mutex_exit(&logdmux_peerq_lock);

	return (0);
}

/*
 * This routine does I_LINK operation.
 */
static void
logdmuxlink(queue_t *q, mblk_t *mp)
{
	struct tmx	*tmxp = q->q_ptr;
	struct linkblk	*lp = (struct linkblk *)mp->b_cont->b_rptr;

	/*
	 * Fail if we're already linked.
	 */
	if (tmxp->muxq != NULL) {
		miocnak(q, mp, 0, EINVAL);
		return;
	}

	tmxp->muxq = lp->l_qbot;
	tmxp->muxq->q_ptr = tmxp;
	RD(tmxp->muxq)->q_ptr = tmxp;

	miocack(q, mp, 0, 0);
}

/*
 * logdmuxunlink() is called from logdmuxuwput() and is the first of two
 * functions which process an I_UNLINK ioctl. logdmuxunlink() will determine
 * the state of logindmux peer linkage and, based on this, control when the
 * second function, logdmux_finish_unlink(), is called.  It's
 * logdmux_finish_unlink() that's sending the M_IOCACK upstream and
 * resetting the link state.
 */
static void
logdmuxunlink(queue_t *q, mblk_t *mp)
{
	struct tmx	*tmxp = q->q_ptr;
	unlinkinfo_t	*unlinkinfop;

	/*
	 * If we don't have a peer, just unlink.  Note that this check needs
	 * to be done under logdmux_qexch_lock to prevent racing with
	 * LOGDMX_IOC_QEXCHANGE, and we *must* set muxq to NULL prior to
	 * releasing the lock so that LOGDMX_IOC_QEXCHANGE will not consider
	 * us as a possible peer anymore (if it already considers us to be a
	 * peer, then unlinkinfop will not be NULL) -- NULLing muxq precludes
	 * use of logdmux_finish_unlink() here.
	 */
	mutex_enter(&logdmux_qexch_lock);
	unlinkinfop = tmxp->unlinkinfop;
	if (unlinkinfop == NULL) {
		ASSERT(tmxp->peerq == NULL);
		tmxp->muxq = NULL;
		mutex_exit(&logdmux_qexch_lock);
		miocack(q, mp, 0, 0);
		return;
	}
	mutex_exit(&logdmux_qexch_lock);

	mutex_enter(&unlinkinfop->state_lock);

	switch (unlinkinfop->state) {

	case LOGDMUX_LINKED:
		/*
		 * We're the first instance to process an I_UNLINK --
		 * ie, the peer instance is still there. We'll change
		 * the state so that only one instance is executing an
		 * I_UNLINK at any one time.
		 */
		unlinkinfop->state = LOGDMUX_UNLINK_PENDING;
		mutex_exit(&unlinkinfop->state_lock);
		/*
		 * Attach the original M_IOCTL message to a
		 * LOGDMUX_UNLINK_REQ message and send it to our peer to
		 * tell it to unlink from us. When it has completed the
		 * task, it will send us a LOGDMUX_UNLINK_RESP message
		 * with the original M_IOCTL still attached, which will be
		 * processed in our logdmuxlrput(). At that point, we will
		 * call logdmux_finish_unlink() to complete the unlink
		 * operation using the attached M_IOCTL.
		 */
		unlinkinfop->prot_mp->b_cont = mp;
		/*
		 * Put the M_CTL directly to the peer's lower RQ.
		 */
		put(RD(tmxp->peerq), unlinkinfop->prot_mp);
		break;

	case LOGDMUX_UNLINK_PENDING:
		mutex_exit(&unlinkinfop->state_lock);
		/*
		 * Our peer is actively processing an I_UNLINK itself.
		 * We have to wait for the peer to complete and we use
		 * qtimeout as a way to poll for its completion.
		 * We save a reference to our mblk so that we can send
		 * it upstream once our peer is done.
		 */
		tmxp->unlink_mp = mp;
		tmxp->utimoutid = qtimeout(q, logdmux_unlink_timer, q,
		    drv_usectohz(LOGDMUX_POLL_WAIT));
		break;

	case LOGDMUX_UNLINKED:
		/*
		 * Our peer is no longer linked so we can proceed.
		 */
		mutex_exit(&unlinkinfop->state_lock);
		mutex_destroy(&unlinkinfop->state_lock);
		freeb(unlinkinfop->prot_mp);
		kmem_free(unlinkinfop, sizeof (unlinkinfo_t));
		logdmux_finish_unlink(q, mp);
		break;

	default:
		mutex_exit(&unlinkinfop->state_lock);
		cmn_err(CE_PANIC,
		    "logdmuxunlink: peer linkage is in an unrecognized state");
		break;
	}
}

/*
 * Finish the unlink operation.  Note that no locks should be held since
 * this routine calls into other queues.
 */
static void
logdmux_finish_unlink(queue_t *q, mblk_t *unlink_mp)
{
	struct tmx *tmxp = q->q_ptr;
	mblk_t *mp;

	/*
	 * Flush any write side data downstream.
	 */
	while ((mp = getq(WR(q))) != NULL)
		putnext(tmxp->muxq, mp);

	/*
	 * Note that we do not NULL out q_ptr since another thread (e.g., a
	 * STREAMS service thread) might call logdmuxlrput() between the time
	 * we exit the logindmux perimeter and the time the STREAMS framework
	 * resets q_ptr to stdata (since muxq is set to NULL, any messages
	 * will just be discarded).
	 */
	tmxp->muxq = NULL;
	tmxp->unlinkinfop = NULL;
	tmxp->peerq = NULL;
	miocack(q, unlink_mp, 0, 0);
}

/*
 * logdmux_unlink_timer() is executed by qtimeout(). This function will
 * check unlinkinfop->state to determine whether the peer has completed
 * its I_UNLINK. If it hasn't, we use qtimeout() to initiate another poll.
 */
static void
logdmux_unlink_timer(void *arg)
{
	queue_t		*q = arg;
	struct	tmx	*tmxp = q->q_ptr;
	unlinkinfo_t	*unlinkinfop = tmxp->unlinkinfop;

	tmxp->utimoutid = 0;

	mutex_enter(&unlinkinfop->state_lock);

	if (unlinkinfop->state != LOGDMUX_UNLINKED) {
		ASSERT(unlinkinfop->state == LOGDMUX_UNLINK_PENDING);
		mutex_exit(&unlinkinfop->state_lock);
		/*
		 * We need to wait longer for our peer to complete.
		 */
		tmxp->utimoutid = qtimeout(q, logdmux_unlink_timer, q,
		    drv_usectohz(LOGDMUX_POLL_WAIT));
	} else {
		/*
		 * Our peer is no longer linked so we can proceed with
		 * the cleanup.
		 */
		mutex_exit(&unlinkinfop->state_lock);
		mutex_destroy(&unlinkinfop->state_lock);
		freeb(unlinkinfop->prot_mp);
		kmem_free(unlinkinfop, sizeof (unlinkinfo_t));
		logdmux_finish_unlink(q, tmxp->unlink_mp);
	}
}

static void
logdmux_timer(void *arg)
{
	queue_t		*q = arg;
	struct tmx	*tmxp = q->q_ptr;

	ASSERT(tmxp != NULL);

	if (q->q_flag & QREADR) {
		ASSERT(tmxp->rtimoutid != 0);
		tmxp->rtimoutid = 0;
	} else {
		ASSERT(tmxp->wtimoutid != 0);
		tmxp->wtimoutid = 0;
	}
	enableok(q);
	qenable(q);
}

static void
logdmux_buffer(void *arg)
{
	queue_t		*q = arg;
	struct tmx	*tmxp = q->q_ptr;

	ASSERT(tmxp != NULL);

	if (q->q_flag & QREADR) {
		ASSERT(tmxp->rbufcid != 0);
		tmxp->rbufcid = 0;
	} else {
		ASSERT(tmxp->wbufcid != 0);
		tmxp->wbufcid = 0;
	}
	enableok(q);
	qenable(q);
}

static void
recover(queue_t *q, mblk_t *mp, size_t size)
{
	timeout_id_t	tid;
	bufcall_id_t	bid;
	struct	tmx	*tmxp = q->q_ptr;

	/*
	 * Avoid re-enabling the queue.
	 */
	ASSERT(queclass(mp) < QPCTL);
	ASSERT(WR(q)->q_next == NULL); /* Called from upper queue only */
	noenable(q);
	(void) putbq(q, mp);

	/*
	 * Make sure there is at most one outstanding request per queue.
	 */
	if (q->q_flag & QREADR) {
		if (tmxp->rtimoutid != 0 || tmxp->rbufcid != 0)
			return;
	} else {
		if (tmxp->wtimoutid != 0 || tmxp->wbufcid != 0)
			return;
	}
	if (!(bid = qbufcall(RD(q), size, BPRI_MED, logdmux_buffer, q))) {
		tid = qtimeout(RD(q), logdmux_timer, q, drv_usectohz(SIMWAIT));
		if (q->q_flag & QREADR)
			tmxp->rtimoutid = tid;
		else
			tmxp->wtimoutid = tid;
	} else	{
		if (q->q_flag & QREADR)
			tmxp->rbufcid = bid;
		else
			tmxp->wbufcid = bid;
	}
}

static void
flushq_dataonly(queue_t *q)
{
	mblk_t *mp, *nmp;

	/*
	 * Since we are already in the perimeter, and we are not a put-shared
	 * perimeter, we don't need to freeze the stream or anything to
	 * be ensured of exclusivity.
	 */
	mp = q->q_first;
	while (mp != NULL) {
		if (mp->b_datap->db_type == M_DATA) {
			nmp = mp->b_next;
			rmvq(q, mp);
			freemsg(mp);
			mp = nmp;
		} else {
			mp = mp->b_next;
		}
	}
}

/*
 * logdmux_alloc_unlinkinfo() is called from logdmuxuwput() during the
 * processing of a LOGDMX_IOC_QEXCHANGE ioctl() to allocate the
 * unlinkinfo_t which is needed during the processing of an I_UNLINK.
 */
static int
logdmux_alloc_unlinkinfo(struct tmx *t0, struct tmx *t1)
{
	unlinkinfo_t	*p;
	uint_t		*messagep;

	if ((p = kmem_zalloc(sizeof (unlinkinfo_t), KM_NOSLEEP)) == NULL)
		return (ENOSR);

	if ((p->prot_mp = allocb(sizeof (uint_t), BPRI_MED)) == NULL) {
		kmem_free(p, sizeof (unlinkinfo_t));
		return (ENOSR);
	}

	DB_TYPE(p->prot_mp) = M_CTL;
	messagep = (uint_t *)p->prot_mp->b_wptr;
	*messagep = LOGDMUX_UNLINK_REQ;
	p->prot_mp->b_wptr += sizeof (*messagep);
	p->state = LOGDMUX_LINKED;
	mutex_init(&p->state_lock, NULL, MUTEX_DRIVER, NULL);

	t0->unlinkinfop = t1->unlinkinfop = p;

	return (0);
}
