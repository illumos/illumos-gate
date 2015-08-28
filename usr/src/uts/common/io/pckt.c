/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Description: The pckt module packetizes messages on
 *		its read queue by pre-fixing an M_PROTO
 *		message type to certain incoming messages.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/debug.h>

/*
 * This is the loadable module wrapper.
 */
#include <sys/conf.h>
#include <sys/modctl.h>

static struct streamtab pcktinfo;

/*
 * Per queue instances are single-threaded since the q_ptr
 * field of queues need to be shared among threads.
 */
static struct fmodsw fsw = {
	"pckt",
	&pcktinfo,
	D_NEW | D_MTPERQ | D_MP
};

/*
 * Module linkage information for the kernel.
 */

static struct modlstrmod modlstrmod = {
	&mod_strmodops,
	"pckt module",
	&fsw
};

static struct modlinkage modlinkage = {
	MODREV_1, &modlstrmod, NULL
};


int
_init(void)
{
	return (mod_install(&modlinkage));
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

static int	pcktopen(queue_t *, dev_t *, int, int, cred_t *);
static int	pcktclose(queue_t *, int, cred_t *);
static void	pcktrput(queue_t *, mblk_t *);
static void	pcktrsrv(queue_t *);
static void	pcktwput(queue_t *, mblk_t *);
static mblk_t	*add_ctl_info(queue_t *, mblk_t *);
static void	add_ctl_wkup(void *);


/*
 * Stream module data structure definitions.
 * Sits over the ptm module generally.
 *
 * Read side flow control strategy: Since we may be putting messages on
 * the read q due to allocb failures, these failures must get
 * reflected fairly quickly to the module below us.
 * No sense in piling on messages in times of memory shortage.
 * Further, for the case of upper level flow control, there is no
 * compelling reason to have more buffering in this module.
 * Thus use a hi-water mark of one.
 * This module imposes no max packet size, there is no inherent reason
 * in the code to do so.
 */
static struct module_info pcktiinfo = {
	0x9898,					/* module id number */
	"pckt",					/* module name */
	0,					/* minimum packet size */
	INFPSZ,					/* maximum packet size */
	1,					/* hi-water mark */
	0					/* lo-water mark */
};

/*
 * Write side flow control strategy: There is no write service procedure.
 * The write put function is pass thru, thus there is no reason to have any
 * limits on the maximum packet size.
 */
static struct module_info pcktoinfo = {
	0x9898,					/* module id number */
	"pckt",					/* module name */
	0,					/* minimum packet size */
	INFPSZ,					/* maximum packet size */
	0,					/* hi-water mark */
	0					/* lo-water mark */
};

static struct qinit pcktrinit = {
	(int (*)())pcktrput,
	(int (*)())pcktrsrv,
	pcktopen,
	pcktclose,
	NULL,
	&pcktiinfo,
	NULL
};

static struct qinit pcktwinit = {
	(int (*)())pcktwput,
	NULL,
	NULL,
	NULL,
	NULL,
	&pcktoinfo,
	NULL
};

static struct streamtab pcktinfo = {
	&pcktrinit,
	&pcktwinit,
	NULL,
	NULL
};


/*
 * Per-instance state struct for the pckt module.
 */
struct pckt_info {
	queue_t		*pi_qptr;		/* back pointer to q */
	bufcall_id_t	pi_bufcall_id;
#ifdef _MULTI_DATAMODEL
	model_t		model;
#endif /* _MULTI_DATAMODEL */
};

/*
 * Dummy qbufcall callback routine used by open and close.
 * The framework will wake up qwait_sig when we return from
 * this routine (as part of leaving the perimeters.)
 * (The framework enters the perimeters before calling the qbufcall() callback
 * and leaves the perimeters after the callback routine has executed. The
 * framework performs an implicit wakeup of any thread in qwait/qwait_sig
 * when it leaves the perimeter. See qwait(9E).)
 */
/* ARGSUSED */
static void
dummy_callback(void *arg)
{}

/*
 * pcktopen - open routine gets called when the
 *	    module gets pushed onto the stream.
 */
/*ARGSUSED*/
static int
pcktopen(
	queue_t *q,		/* pointer to the read side queue */
	dev_t   *devp,		/* pointer to stream tail's dev */
	int	oflag,		/* the user open(2) supplied flags */
	int	sflag,		/* open state flag */
	cred_t  *credp)		/* credentials */
{
	struct pckt_info	*pip;
	mblk_t			*mop; /* ptr to a setopts msg block */
	struct stroptions	*sop;

	if (sflag != MODOPEN)
		return (EINVAL);

	if (q->q_ptr != NULL) {
		/* It's already attached. */
		return (0);
	}

	/*
	 * Allocate state structure.
	 */
	pip = kmem_zalloc(sizeof (*pip), KM_SLEEP);

#ifdef _MULTI_DATAMODEL
	pip->model = ddi_model_convert_from(get_udatamodel());
#endif /* _MULTI_DATAMODEL */

	/*
	 * Cross-link.
	 */
	pip->pi_qptr = q;
	q->q_ptr = pip;
	WR(q)->q_ptr = pip;

	qprocson(q);

	/*
	 * Initialize an M_SETOPTS message to set up hi/lo water marks on
	 * stream head read queue.
	 */

	while ((mop = allocb(sizeof (struct stroptions), BPRI_MED)) == NULL) {
		bufcall_id_t id = qbufcall(q, sizeof (struct stroptions),
		    BPRI_MED, dummy_callback, NULL);
		if (!qwait_sig(q)) {
			qunbufcall(q, id);
			kmem_free(pip, sizeof (*pip));
			qprocsoff(q);
			return (EINTR);
		}
		qunbufcall(q, id);
	}


	/*
	 * XXX: Should this module really control the hi/low water marks?
	 * Is there any reason in this code to do so?
	 */
	mop->b_datap->db_type = M_SETOPTS;
	mop->b_wptr += sizeof (struct stroptions);
	sop = (struct stroptions *)mop->b_rptr;
	sop->so_flags = SO_HIWAT | SO_LOWAT;
	sop->so_hiwat = 512;
	sop->so_lowat = 256;

	/*
	 * Commit to the open and send the M_SETOPTS off to the stream head.
	 */
	putnext(q, mop);

	return (0);
}


/*
 * pcktclose - This routine gets called when the module
 *	gets popped off of the stream.
 */

/*ARGSUSED*/
static int
pcktclose(
	queue_t *q,	/* Pointer to the read queue */
	int	flag,
	cred_t  *credp)
{
	struct pckt_info	*pip = (struct pckt_info *)q->q_ptr;

	qprocsoff(q);
	/*
	 * Cancel outstanding qbufcall
	 */
	if (pip->pi_bufcall_id) {
		qunbufcall(q, pip->pi_bufcall_id);
		pip->pi_bufcall_id = 0;
	}
	/*
	 * Do not worry about msgs queued on the q, the framework
	 * will free them up.
	 */
	kmem_free(q->q_ptr, sizeof (struct pckt_info));
	q->q_ptr = WR(q)->q_ptr = NULL;
	return (0);
}

/*
 * pcktrput - Module read queue put procedure.
 *	This is called from the module or
 *	driver downstream.
 */
static void
pcktrput(
	queue_t *q,	/* Pointer to the read queue */
	mblk_t *mp)	/* Pointer to the current message block */
{
	mblk_t		*pckt_msgp;


	switch (mp->b_datap->db_type) {
	case M_FLUSH:
		/*
		 * The PTS driver swaps the FLUSHR and FLUSHW flags
		 * we need to swap them back to reflect the actual
		 * slave side FLUSH mode.
		 */
		if ((*mp->b_rptr & FLUSHRW) != FLUSHRW)
			if ((*mp->b_rptr & FLUSHRW) == FLUSHR)
				*mp->b_rptr = FLUSHW;
			else if ((*mp->b_rptr & FLUSHRW) == FLUSHW)
				*mp->b_rptr = FLUSHR;

		pckt_msgp = copymsg(mp);
		if (*mp->b_rptr & FLUSHW) {
			/*
			 * In the packet model we are not allowing
			 * flushes of the master's stream head read
			 * side queue. This is because all packet
			 * state information is stored there and
			 * a flush could destroy this data before
			 * it is read.
			 */
			*mp->b_rptr = FLUSHW;
			putnext(q, mp);
		} else {
			/*
			 * Free messages that only flush the
			 * master's read queue.
			 */
			freemsg(mp);
		}

		if (pckt_msgp == NULL)
			break;

		mp = pckt_msgp;
		/*
		 * Prefix M_PROTO and putnext.
		 */
		goto prefix_head;

	case M_DATA:
	case M_IOCTL:
	case M_PROTO:
		/*
		 * For non-priority messages, follow flow-control rules.
		 * Also, if there are messages on the q already, keep
		 * queueing them since they need to be processed in order.
		 */
		if (!canputnext(q) || (qsize(q) > 0)) {
			(void) putq(q, mp);
			break;
		}
		/* FALLTHROUGH */

	/*
	 * For high priority messages, skip flow control checks.
	 */
	case M_PCPROTO:
	case M_READ:
	case M_STOP:
	case M_START:
	case M_STARTI:
	case M_STOPI:
prefix_head:
		/*
		 * Prefix an M_PROTO header to message and pass upstream.
		 */
		if ((mp = add_ctl_info(q, mp)) != NULL)
			putnext(q, mp);
		break;

	default:
		/*
		 * For data messages, queue them back on the queue if
		 * there are messages on the queue already. This is
		 * done to preserve the order of messages.
		 * For high priority messages or for no messages on the
		 * q, simply putnext() and pass it on.
		 */
		if ((datamsg(mp->b_datap->db_type)) && (qsize(q) > 0))
			(void) putq(q, mp);
		else
			putnext(q, mp);
		break;
	}
}

/*
 * pcktrsrv - module read service procedure
 * This function deals with messages left in the queue due to
 *	(a) not enough memory to allocate the header M_PROTO message
 *	(b) flow control reasons
 * The function will attempt to get the messages off the queue and
 * process them.
 */
static void
pcktrsrv(queue_t *q)
{
	mblk_t *mp;

	while ((mp = getq(q)) != NULL) {
		if (!canputnext(q)) {
			/*
			 * For high priority messages, make sure there is no
			 * infinite loop. Disable the queue for this case.
			 * High priority messages get here only for buffer
			 * allocation failures. Thus the bufcall callout
			 * will reenable the q.
			 * XXX bug alert - nooenable will *not* prevent
			 * putbq of a hipri messages frm enabling the queue.
			 */
			if (!datamsg(mp->b_datap->db_type))
				noenable(q);
			(void) putbq(q, mp);
			return;
		}

		/*
		 * M_FLUSH msgs may also be here if there was a memory
		 * failure.
		 */
		switch (mp->b_datap->db_type) {
		case M_FLUSH:
		case M_PROTO:
		case M_PCPROTO:
		case M_STOP:
		case M_START:
		case M_IOCTL:
		case M_DATA:
		case M_READ:
		case M_STARTI:
		case M_STOPI:
			/*
			 * Prefix an M_PROTO header to msg and pass upstream.
			 */
			if ((mp = add_ctl_info(q, mp)) == NULL) {
				/*
				 * Running into memory or flow ctl problems.
				 */
				return;
			}
			/* FALL THROUGH */

		default:
			putnext(q, mp);
			break;
		}
	}
}

/*
 * pcktwput - Module write queue put procedure.
 *	All messages are send downstream unchanged
 */

static void
pcktwput(
	queue_t *q,	/* Pointer to the read queue */
	mblk_t *mp)	/* Pointer to current message block */
{
	putnext(q, mp);
}

#ifdef _MULTI_DATAMODEL
/*
 * reallocb - copy the data block from the given message block into a new block.
 * This function is used in case data block had another message block
 * pointing to it (and hence we just copy this one data block).
 *
 * Returns new message block if successful. On failure it returns NULL.
 * It also tries to do a qbufcall and if that also fails,
 * it frees the message block.
 */
static mblk_t *
pckt_reallocb(
	queue_t *q,	/* Pointer to the read queue */
	mblk_t *mp	/* Pointer to the message block to be changed */
)
{
	mblk_t	*nmp;

	ASSERT(mp->b_datap->db_ref >= 1);

	/*
	 * No reallocation is needed if there is only one reference
	 * to this data block.
	 */
	if (mp->b_datap->db_ref == 1)
		return (mp);

	if ((nmp = copyb(mp)) == NULL) {
		struct pckt_info	*pip = (struct pckt_info *)q->q_ptr;

		noenable(q);
		if (pip->pi_bufcall_id = qbufcall(q, mp->b_wptr - mp->b_rptr,
		    BPRI_MED, add_ctl_wkup, q)) {
			/*
			 * Put the message back onto the q.
			 */
			(void) putq(q, mp);
		} else {
			/*
			 * Things are pretty bad and serious if bufcall fails!
			 * Drop the message in this case.
			 */
			freemsg(mp);
		}
		return ((mblk_t *)0);
	}

	nmp->b_cont = mp->b_cont;
	freeb(mp);
	return (nmp);
}
#endif /* _MULTI_DATAMODEL */

/*
 * add_ctl_info: add message control information to in coming
 * 	message.
 */
static mblk_t *
add_ctl_info(
	queue_t *q,		/* pointer to the read queue */
	mblk_t	*mp)		/* pointer to the raw data input message */
{
	struct pckt_info	*pip = (struct pckt_info *)q->q_ptr;
	mblk_t	*bp;		/* pointer to the unmodified message block */

	/*
	 * Waiting on space for previous message?
	 */
	if (pip->pi_bufcall_id) {
		/*
		 * Chain this message on to q for later processing.
		 */
		(void) putq(q, mp);
		return (NULL);
	}

	/*
	 * Need to add the message block header as
	 * an M_PROTO type message.
	 */
	if ((bp = allocb(sizeof (char), BPRI_MED)) == (mblk_t *)NULL) {

		/*
		 * There are two reasons to disable the q:
		 * (1) Flow control reasons should not wake up the q.
		 * (2) High priority messages will wakeup the q
		 *	immediately. Disallow this.
		 */
		noenable(q);
		if (pip->pi_bufcall_id = qbufcall(q, sizeof (char), BPRI_MED,
		    add_ctl_wkup, q)) {
			/*
			 * Add the message to the q.
			 */
			(void) putq(q, mp);
		} else {
			/*
			 * Things are pretty bad and serious if bufcall fails!
			 * Drop the message in this case.
			 */
			freemsg(mp);
		}

		return (NULL);
	}

	/*
	 * Copy the message type information to this message.
	 */
	bp->b_datap->db_type = M_PROTO;
	*(unsigned char *)bp->b_rptr = mp->b_datap->db_type;
	bp->b_wptr++;

#ifdef _MULTI_DATAMODEL
	/*
	 * Check the datamodel and if the calling program is
	 * an ILP32 application then we covert the M_IOCTLs and M_READs
	 * into the native ILP32 format before passing them upstream
	 * to user mode.
	 */
	switch (pip->model) {
	case DDI_MODEL_ILP32:
		switch (mp->b_datap->db_type) {
			/*
			 * This structure must have the same shape as
			 * the * ILP32 compilation of `struct iocblk'
			 * from <sys/stream.h>.
			 */
			struct iocblk32 {
				int32_t   	ioc_cmd;
				caddr32_t	ioc_cr;
				uint32_t	ioc_id;
				int32_t   	ioc_count;
				int32_t   	ioc_error;
				int32_t   	ioc_rval;
				int32_t   	ioc_fill1;
				uint32_t	ioc_flag;
				int32_t   	ioc_filler[2];
			} niocblk_32;
			struct iocblk		*iocblk_64;

		case M_IOCTL:
			if ((mp = pckt_reallocb(q, mp)) == (mblk_t *)0)
				return ((mblk_t *)0);

			bzero(&niocblk_32, sizeof (niocblk_32));
			iocblk_64 = (struct iocblk *)mp->b_rptr;

			/* Leave the pointer to cred_t structure as it is. */
			niocblk_32.ioc_cmd = iocblk_64->ioc_cmd;
			niocblk_32.ioc_cr = (caddr32_t)(uintptr_t)
			    iocblk_64->ioc_cr;
			niocblk_32.ioc_id = iocblk_64->ioc_id;
			niocblk_32.ioc_count = iocblk_64->ioc_count;
			niocblk_32.ioc_error = iocblk_64->ioc_error;
			niocblk_32.ioc_rval = iocblk_64->ioc_rval;
			niocblk_32.ioc_flag = iocblk_64->ioc_flag;

			/* Copy the iocblk structure for ILP32 back */
			*(struct iocblk32 *)mp->b_rptr = niocblk_32;
			mp->b_wptr = mp->b_rptr + sizeof (struct iocblk32);
			break;

		case M_READ:
			if ((mp = pckt_reallocb(q, mp)) == (mblk_t *)0)
				return ((mblk_t *)0);

			/* change the size_t to size32_t for ILP32 */
			*(size32_t *)mp->b_rptr = *(size_t *)mp->b_rptr;
			mp->b_wptr = mp->b_rptr + sizeof (size32_t);
			break;
		}
		break;

	case DATAMODEL_NONE:
		break;
	}
#endif /* _MULTI_DATAMODEL */

	/*
	 * Now change the orginal message type to M_DATA and tie them up.
	 */
	mp->b_datap->db_type = M_DATA;
	bp->b_cont = mp;

	return (bp);
}

static void
add_ctl_wkup(void *arg)
{
	queue_t *q = arg;	/* ptr to the read queue */
	struct pckt_info *pip = (struct pckt_info *)q->q_ptr;

	pip->pi_bufcall_id = 0;
	/*
	 * Allow enabling of the q to allow the service
	 * function to do its job.
	 *
	 * Also, qenable() to schedule the q immediately.
	 * This is to ensure timely processing of high priority
	 * messages if they are on the q.
	 */
	enableok(q);
	qenable(q);
}
