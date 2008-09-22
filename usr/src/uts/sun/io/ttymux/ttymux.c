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
 * DESCRIPTION
 *
 * ttymux - Multiplexer driver for multiplexing termio compliant streams onto
 * a single upper stream.
 *
 * ADD2FRONT macro can be used to specify the order in which a console
 * device is put in the queue of multiplexed physical serial devices,
 * during the association and disassociation of a console interface.
 * When this macro is defined, the device is placed in front of the queue,
 * otherwise by default it is placed at the end.
 * Console I/O happens to each of the physical devices in the order of
 * their position in this queue.
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strlog.h>
#include <sys/strsun.h>
#include <sys/modctl.h>
#include <sys/debug.h>
#include <sys/kbio.h>
#include <sys/devops.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/consdev.h>
#include <sys/tty.h>
#include <sys/ptyvar.h>
#include <sys/termio.h>
#include <sys/fcntl.h>
#include <sys/mkdev.h>
#include <sys/ser_sync.h>
#include <sys/esunddi.h>
#include <sys/policy.h>

#include <sys/ttymux.h>
#include "ttymux_impl.h"

/*
 * Extern declarations
 */
extern mblk_t *mkiocb(uint_t);
extern int nulldev();
extern uintptr_t space_fetch(char *key);

extern int sm_ioctl_cmd(sm_uqi_t *, mblk_t *);
extern int ttymux_abort_ioctl(mblk_t *);
extern int ttymux_device_fini(sm_lqi_t *);
extern int ttymux_device_init(sm_lqi_t *);

/*
 * Exported interfaces
 */
int sm_disassociate(int, sm_lqi_t *, ulong_t);
int sm_associate(int, sm_lqi_t *, ulong_t, uint_t, char *);

/*
 * Variables defined here and visible only internally
 */
sm_ss_t		*sm_ssp = 0;
static int	sm_instance = 0;
static int	smctlunit;

static uint_t	sm_default_trflag = 0;
uint_t		sm_max_units = 6;
uint_t		sm_minor_cnt = 0;
static uint_t	sm_refuse_opens = 0;

/*
 * Local definitions.
 */

/* force these flags to be unset on console devices */
static ulong_t	sm_cmask = (ulong_t)(CRTSXOFF|CRTSCTS);

/*
 * SECTION
 * Implementation Section:
 */
void
sm_debug(char *msg, ...)
{
	va_list	args;
	char	buf[256];
	int	sz;

	va_start(args, msg);
	sz = vsnprintf(buf, sizeof (buf), msg, args);
	va_end(args);

	if (sz < 0)
		(void) strlog(ddi_driver_major(sm_ssp->sm_dip), sm_instance, 1,
		    SL_TRACE, "vsnprintf parse error\n");
	else if (sz > sizeof (buf)) {
		char *b;
		size_t	len = sz + 1;

		b = kmem_alloc(len, KM_SLEEP);
		va_start(args, msg);
		sz = vsnprintf(b, len, msg, args);
		va_end(args);
		if (sz > 0)
			(void) strlog(ddi_driver_major(sm_ssp->sm_dip),
			    sm_instance, 1, SL_TRACE, b);
		kmem_free(b, len);
	} else {

		(void) strlog(ddi_driver_major(sm_ssp->sm_dip), sm_instance,
		    1, SL_TRACE, buf);
	}
}

void
sm_log(char *msg, ...)
{
	va_list	args;
	char	buf[128];
	int	sz;

	va_start(args, msg);
	sz = vsnprintf(buf, sizeof (buf), msg, args);
	va_end(args);

	if (sz < 0)
		(void) strlog(ddi_driver_major(sm_ssp->sm_dip), sm_instance, 1,
		    SL_TRACE, "vsnprintf parse error\n");
	else if (sz > sizeof (buf)) {
		char *b;
		size_t	len = sz + 1;

		b = kmem_alloc(len, KM_SLEEP);
		va_start(args, msg);
		sz = vsnprintf(b, len, msg, args);
		va_end(args);
		if (sz > 0)
			(void) strlog(ddi_driver_major(sm_ssp->sm_dip),
			    sm_instance, 1, SL_NOTE, b);
		kmem_free(b, len);
	} else {

		(void) strlog(ddi_driver_major(sm_ssp->sm_dip), sm_instance,
		    1, SL_NOTE, buf);
	}
}

/*
 * Should only be called if the caller can guarantee that the vnode
 * and/or the stream won't disappear while finding the dip.
 * This routine is only called during an I_PLINK request so it's safe.
 * The routine obtains the dev_t for a linked se stream.
 */
static void
sm_setdip(queue_t *q, sm_lqi_t *lqi)
{
	lqi->sm_dev = q && STREAM(q) ? STREAM(q)->sd_vnode->v_rdev : NODEV;
}

/*
 * Called from driver close, state change reports and I_PUNLINK ioctl.
 * A lower stream has been unlinked - clean up the state associated with it.
 */
void
sm_lqifree(sm_lqi_t *lqi)
{
	int mu_owned;
	sm_lqi_t **pplqi;

	ASSERT(mutex_owned(lqi->sm_umutex));
	ASSERT(SM_RQ(lqi) != 0);

	/*
	 * Clear all state associated with this lower queue except
	 * the identity of the queues themselves and the link id which
	 * can only be cleared by issuing a streams I_PUNLINK ioctl.
	 *
	 * The association of a lower queue is a two step process:
	 * 1. initialise the lower q data structure on I_PLINK
	 * 2. associate an upper q with the lower q on SM_CMD_ASSOCIATE.
	 *
	 * If step 2 has ocurred then
	 * remove this lower queue info from the logical unit.
	 */
	if (lqi->sm_uqi) {
		sm_dbg('Y', ("lqifree unit %d, ", lqi->sm_uqi->sm_lunit));
		if ((mu_owned = mutex_owned(lqi->sm_uqi->sm_umutex)) == 0)
			LOCK_UNIT(lqi->sm_uqi);

		pplqi = &lqi->sm_uqi->sm_lqs;
		while (*pplqi != lqi) {
			ASSERT(*pplqi);
			pplqi = &((*pplqi)->sm_nlqi);
		}
		*pplqi = lqi->sm_nlqi;
		lqi->sm_uqi->sm_nlqs--;

		if (mu_owned == 0)
			UNLOCK_UNIT(lqi->sm_uqi);

		lqi->sm_uqi = 0;
	}
}

/*
 * Given a q return the associated lower queue data structure or NULL.
 * Return the data locked.
 */
static sm_lqi_t *
get_lqi_byq(queue_t *q)
{
	int i;
	sm_lqi_t *lqi, *flqi = 0;

	for (i = 0; i < MAX_LQS; i++) {
		lqi = &sm_ssp->sm_lqs[i];
		LOCK_UNIT(lqi);
		if (flqi == 0 && lqi->sm_linkid == 0) /* assumes muxids != 0 */
			flqi = lqi;
		else if (SM_RQ(lqi) == q || SM_WQ(lqi) == q) {
			if (flqi)
				UNLOCK_UNIT(flqi);
			return (lqi);
		}
		else
			UNLOCK_UNIT(lqi);
	}
	return (flqi);
}

/*
 * Given a streams link identifier return the associated lower queue data
 * structure or NULL.
 */
sm_lqi_t *
get_lqi_byid(int linkid)
{
	int i;
	sm_lqi_t *lqi;

	if (linkid == 0)
		return (NULL);
	for (i = 0; i < MAX_LQS; i++) {
		lqi = &sm_ssp->sm_lqs[i];
		if (lqi->sm_linkid == linkid)
			return (lqi);
	}
	return (NULL);
}

/*
 * Given a dev_t for a lower stream return the associated lower queue data
 * structure or NULL.
 */
sm_lqi_t *
get_lqi_bydevt(dev_t dev)
{
	int i;
	sm_lqi_t *lqi;

	if (dev == NODEV)
		return (NULL);

	for (i = 0; i < MAX_LQS; i++) {
		lqi = &sm_ssp->sm_lqs[i];
		if (lqi->sm_dev == dev)
			return (lqi);
	}
	return (NULL);
}

/*
 * Determine whether the input flag is set on at least
 * howmany queues.
 */
static int
sm_is_flag_set(sm_uqi_t *uqi, uint_t flag, uint_t howmany)
{
	sm_lqi_t *lqi;

	if (howmany == 0)
		return (0);

	for (lqi = uqi->sm_lqs; lqi; lqi = lqi->sm_nlqi) {
		if (lqi->sm_flags & flag)
			if (--howmany == 0)
				return (1);
	}
	return (0);
}

/*
 * How many usable queues are associated with a given upper stream
 */
static int
sm_uwq_error(sm_uqi_t *uqi)
{
	return (sm_is_flag_set(uqi, (WERROR_MODE|HANGUP_MODE), uqi->sm_nlqs));
}

/*
 * How many of the queues associated with a given upper stream
 * - do not - have the given flags set.
 */
static int
sm_q_count(sm_uqi_t *uqi, uint_t flag)
{
	sm_lqi_t *lqi;
	int count = 0;

	for (lqi = uqi->sm_lqs; lqi; lqi = lqi->sm_nlqi) {
		if ((lqi->sm_flags & flag) == 0)
			count++;
	}
	return (count);
}

/*
 * How many of the queues associated with a given upper stream
 * - do not - have the given flags set.
 */
static int
sm_qs_without(sm_uqi_t *uqi, uint_t flag, uint_t ioflag)
{
	sm_lqi_t *lqi;
	int count = 0;

	for (lqi = uqi->sm_lqs; lqi; lqi = lqi->sm_nlqi) {
		if ((lqi->sm_flags & flag) == 0 &&
		    (lqi->sm_ioflag & ioflag) == 0)
			count++;
	}
	return (count);
}

/*
 * How many usable queues are associated with a given upper stream
 */
static int
sm_good_qs(sm_uqi_t *uqi)
{
	return (sm_q_count(uqi, (WERROR_MODE|HANGUP_MODE)));
}

static int
sm_cnt_oqs(sm_uqi_t *uqi)
{
	return (sm_qs_without(uqi, (WERROR_MODE|HANGUP_MODE),
	    (uint_t)FOROUTPUT));
}

/*
 * Send an ioctl downstream and remember that it was sent so that
 * its response can be caught on the way back up.
 */
static void
sm_issue_ioctl(void *arg)
{
	sm_lqi_t *lqi = arg;
	uint_t cmdflag = 0;
	queue_t *q = SM_WQ(lqi);
	int iocmd, size;

	LOCK_UNIT(lqi);

	lqi->sm_bid = 0;
	if ((lqi->sm_flags & (WERROR_MODE|HANGUP_MODE)) == 0 &&
	    (lqi->sm_flags & (WANT_CDSTAT|WANT_TCSET))) {
		mblk_t *pioc;

		if (lqi->sm_flags & WANT_TCSET) {
			lqi->sm_flags &= ~WANT_TCSET;
			iocmd = TCSETS;
			cmdflag = WANT_TCSET;
		} else if (lqi->sm_flags & WANT_SC) {
			lqi->sm_flags &= ~WANT_SC;
			iocmd = TIOCGSOFTCAR;
			cmdflag = WANT_SC;
		} else if (lqi->sm_flags & WANT_CD) {
			lqi->sm_flags &= ~WANT_CD;
			iocmd = TIOCMGET;
		} else if (lqi->sm_flags & WANT_CL) {
			lqi->sm_flags &= ~WANT_CL;
			iocmd = TCGETS;
			cmdflag = WANT_CL;
		} else {
			UNLOCK_UNIT(lqi);
			return;
		}

		if (pioc = mkiocb(iocmd)) {
			if (cmdflag == WANT_TCSET) {
				pioc->b_cont =
				    sm_allocb(sizeof (struct termios),
				    BPRI_MED);
				if (pioc->b_cont == 0) {
					freemsg(pioc);
					pioc = 0;
				} else {
					struct termios *tc = (struct termios *)
					    pioc->b_cont->b_wptr;

					bzero((caddr_t)tc,
					    sizeof (struct termios));
					tc->c_cflag = lqi->sm_ttycommon->
					    t_cflag;
					pioc->b_cont->b_rptr =
					    pioc->b_cont->b_wptr;
					pioc->b_cont->b_wptr +=
					    sizeof (struct termios);
				}
				size = sizeof (struct iocblk) +
				    sizeof (struct termios);
			}
			else
				size = sizeof (struct iocblk);
		}
		else
			size = sizeof (struct iocblk);

		if (pioc != 0) {

			lqi->sm_piocid = ((struct iocblk *)pioc->b_rptr)->
			    ioc_id;
			lqi->sm_flags |= SM_IOCPENDING;

			/* lqi->sm_flags |= cmdflag; */
			UNLOCK_UNIT(lqi);
			(void) putq(q, pioc);
		} else {
			UNLOCK_UNIT(lqi);
			lqi->sm_bid = qbufcall(WR(q), size, BPRI_MED,
			    sm_issue_ioctl, lqi);
		}
	}
	else
		UNLOCK_UNIT(lqi);
}

/*
 * Associate one of the drivers minor nodes with a serial device.
 */
int
sm_associate(int unit, sm_lqi_t *plqi, ulong_t tag, uint_t ioflag, char *dp)
{
	sm_uqi_t *uqi;
	int rval = 0;

	sm_dbg('Y', ("sm_associate(%d, %d, %d): ",
	    (plqi) ? plqi->sm_linkid : 0, unit, ioflag));
	/*
	 * Check the data is valid.
	 * Associate a lower queue with a logical unit.
	 */

	if (unit < 0 || unit >= NLUNITS || plqi == 0 ||
	    (uqi = get_uqi(sm_ssp, unit)) == 0) {
		sm_dbg('@', (" invalid: lqi=0x%p lui=0x%p:", plqi, uqi));
		rval = EINVAL;
	} else {
		if ((ioflag & FORIO) == 0)
			ioflag = FORIO;

		LOCK_UNIT(plqi);

		if (plqi->sm_uqi) {
			if (plqi->sm_uqi->sm_lunit == unit) {
				if ((ioflag & (uint_t)FORIO) != 0)
					plqi->sm_ioflag =
					    (ioflag & (uint_t)FORIO);
				rval = 0;
			} else {
				sm_dbg('@', ("already associated with unit %d:",
				    plqi->sm_uqi->sm_lunit));
				rval = EINVAL;
			}
		} else {

			LOCK_UNIT(uqi);

			if ((ioflag & (uint_t)FORIO) != 0)
				plqi->sm_ioflag = (ioflag & (uint_t)FORIO);

			plqi->sm_ttycommon->t_cflag = uqi->sm_ttycommon->
			    t_cflag;
			plqi->sm_ttycommon->t_flags = uqi->sm_ttycommon->
			    t_flags;
			plqi->sm_uqi = uqi;
			plqi->sm_mbits = 0;
			plqi->sm_tag = tag;

			if (*dp == '/')
				(void) strncpy(plqi->sm_path, dp, MAXPATHLEN);
			else
				*(plqi->sm_path) = '\0';

			plqi->sm_flags |= WANT_TCSET;
#ifdef ADD2FRONT
			plqi->sm_nlqi = uqi->sm_lqs;
			uqi->sm_lqs = plqi;
#else
			plqi->sm_nlqi = 0;
			if (uqi->sm_lqs) {
				sm_lqi_t *lq;
				for (lq = uqi->sm_lqs; lq->sm_nlqi;
				    lq = lq->sm_nlqi) {
				}
				lq->sm_nlqi = plqi;
			} else
				uqi->sm_lqs = plqi;
#endif
			uqi->sm_nlqs++;

			(void) ttymux_device_init(plqi);

			UNLOCK_UNIT(uqi);
			rval = 0;
			/*
			 * Everything looks good so it's now ok to enable lower
			 * queue processing.
			 * Note the lower queue should be enabled as soon as
			 * I_PLINK returns (used in sm_get_ttymodes etc).
			 * Schedule ioctls to obtain the terminal settings.
			 */

			if ((uqi->sm_flags & FULLY_OPEN) || uqi->sm_waitq)
				plqi->sm_uqflags |= SM_UQVALID;

			qenable(SM_RQ(plqi));
			if (plqi->sm_flags & (WANT_CDSTAT|WANT_TCSET)) {
				/*
				 * Bypass the lower half of the driver (hence
				 * no qwriter) and apply the current termio
				 * settings on the lower stream.
				 */
				UNLOCK_UNIT(plqi);
				if (plqi->sm_bid) {
					qunbufcall(SM_WQ(plqi), plqi->sm_bid);
					plqi->sm_bid = 0;
				}
				/*
				 * Only set cflags on the lower q if we know
				 * the settings on any other lower queue.
				 */
				sm_issue_ioctl(plqi);
				LOCK_UNIT(plqi);

			}
		}

		UNLOCK_UNIT(plqi);
	}
	sm_dbg('Y', ("sm_associate: rval=%d.\n", rval));
	return (rval);
}

/*
 * Break an association between one of the driver's minor nodes and
 * a serial device.
 */
int
sm_disassociate(int unit, sm_lqi_t *plqi, ulong_t tag)
{
	sm_uqi_t *uqi;
	int rval = 0;

	sm_dbg('Y', ("sm_disassociate: link %d, unit %d: ",
	    (plqi) ? plqi->sm_linkid : 0, unit));
	/*
	 * Check the data is valid.
	 * Disassociate a lower queue with a logical unit.
	 */
	if (unit < 0 || unit >= NLUNITS || plqi == 0 ||
	    (uqi = get_uqi(sm_ssp, unit)) == 0) {
		sm_dbg('@', ("invalid: lqi=0x%p lui=0x%p", plqi, uqi));
		rval = EINVAL;
	} else {
		LOCK_UNIT(plqi);

		if (plqi->sm_uqi == NULL) {
			sm_dbg('@', ("unit not associated"));
			rval = EINVAL;
		} else if (plqi->sm_uqi->sm_lunit != unit) {
			sm_dbg('@', ("unit and linkid not related",
			    plqi->sm_uqi->sm_lunit));
			rval = EINVAL;
		} else if (plqi->sm_tag != tag) {
			sm_dbg('@',
			    ("Invalid tag for TTYMUX_DISASSOC ioctl\n"));
			rval = EPERM;
		} else {
			sm_dbg('Y', ("disassociating "));

			(void) ttymux_device_fini(plqi);

			/*
			 * Indicate that carrier status is no
			 * longer required and that the upper
			 * queue should not be used by plqi
			 */
			plqi->sm_flags &= ~(WANT_CDSTAT|WANT_TCSET);
			plqi->sm_uqflags &= ~(SM_UQVALID|SM_OBPCNDEV);
			plqi->sm_ioflag = 0u;

			sm_lqifree(plqi);
			rval = 0;
		}
		UNLOCK_UNIT(plqi);
	}
	sm_dbg('Y', (" rval=%d.\n", rval));
	return (rval);

}

/*
 * Streams helper routines;
 */

/*
 * Schedule a qbufcall for an upper queue.
 * Must be called within the perimiter of the parameter q.
 * fn must reenable the q.
 * Called:
 *	 whenever a message must be placed on multiple queues and allocb fails;
 */
static void
sm_sched_uqcb(queue_t *q, int memreq, int pri, void (*fn)())
{
	sm_uqi_t	*uqi = q->q_ptr;

	if (uqi->sm_ttybid != 0)
		qunbufcall(q, uqi->sm_ttybid);

	noenable(q);

	uqi->sm_ttybid = qbufcall(q, memreq, pri, fn, uqi);
}

/*
 * qbufcall routine to restart the queues when memory is available.
 */
static void
sm_reenable_q(sm_uqi_t *uqi)
{
	queue_t *wq = SM_WQ(uqi);

	if ((uqi->sm_flags & SM_STOPPED) == 0) {
		enableok(wq);
		qenable(wq);
	}
}

/*
 * Place a message on the write queue of each stream associated with
 * the given upper stream.
 */
static void
sm_senddown(sm_uqi_t *uqi)
{
	sm_lqi_t *lqi;

	for (lqi = uqi->sm_lqs; lqi != 0; lqi = lqi->sm_nlqi) {
		if (lqi->sm_mp != 0) {
			putnext(SM_WQ(lqi), lqi->sm_mp);
			lqi->sm_mp = 0;
		}
	}
}

/*
 * For each lower device that should receive a write message duplicate
 * the message block.
 */
static int
sm_dupmsg(sm_uqi_t *uqi, mblk_t *mp)
{
	sm_lqi_t	*lqi;
	mblk_t	*origmp = mp;

	for (lqi = uqi->sm_lqs; lqi != 0; lqi = lqi->sm_nlqi) {
		lqi->sm_mp = 0;
		if (lqi->sm_flags & WERROR_MODE) {
			continue;
		}
		if ((lqi->sm_ioflag & (uint_t)FOROUTPUT) == 0) {
			if (DB_TYPE(mp) == M_DATA)
				continue;
		}
		if (lqi->sm_nlqi == 0) {
			lqi->sm_mp = mp;
			origmp = NULL;
		} else if ((lqi->sm_mp = sm_copymsg(mp)) == 0) {
			sm_lqi_t *flqi;

			for (flqi = uqi->sm_lqs; flqi != lqi;
			    flqi = flqi->sm_nlqi) {
				if (lqi->sm_mp) {
				/* must have been sm_copymsg */
					sm_freemsg(lqi->sm_mp);
					lqi->sm_mp = 0;
				}
			}
			return (sm_cnt_oqs(uqi) * msgdsize(mp));
		}
	}
	if (origmp != NULL)
		freemsg(origmp);
	return (0);
}

/*
 * Return 1 if all associated lower devices have room for another message
 * otherwise return 0.
 */
static int
sm_cansenddown(sm_uqi_t *uqi)
{

	register sm_lqi_t	*lqi;

	if (uqi->sm_lqs == 0)
		return (0);

	for (lqi = uqi->sm_lqs; lqi != 0; lqi = lqi->sm_nlqi) {
		if ((lqi->sm_flags & WERROR_MODE) == 0 &&
		    canputnext(SM_WQ(lqi)) == 0)
			return (0);
	}
	return (1);
}

/*
 * Put a message down all associated lower queues.
 * Return 1 if the q function was called.
 */
static int
sm_putqs(queue_t *q, mblk_t *mp, int (*qfn)())
{
	register sm_uqi_t *uqi = (sm_uqi_t *)q->q_ptr;
	register int memreq;
	int pri = (DB_TYPE(mp) < QPCTL) ? BPRI_MED : BPRI_HI;
	int rval = 0;

	if (uqi->sm_lqs == 0 || (uqi->sm_flags & WERROR_MODE)) {

		sm_dbg('Q', ("sm_putqs: freeing (0x%p 0x%p).\n", uqi->sm_lqs,
		    uqi->sm_flags));
		freemsg(mp);
	} else if (pri != BPRI_HI && sm_cansenddown(uqi) == 0) {
		/* a lower q is flow controlled */
		(void) qfn(q, mp);
		rval = 1;
	} else if ((memreq = sm_dupmsg(uqi, mp)) == 0) {

		sm_senddown(uqi);

	} else {
		sm_log("sm_putqs: msg 0x%x - can't alloc %d bytes (pri %d).\n",
		    DB_TYPE(mp), memreq, pri);
		sm_sched_uqcb(q, memreq, pri, sm_reenable_q);

		(void) qfn(q, mp);
		rval = 1;

	}

	return (rval);
}

/*
 * Service a streams link and unlink requests.
 */
static void
sm_link_req(queue_t *wq, mblk_t *mp)
{
	struct linkblk *linkp;
	int rval;
	int cmd;
	sm_lqi_t *plqi;

	ASSERT(DB_TYPE(mp) == M_IOCTL);

	cmd = ((struct iocblk *)mp->b_rptr)->ioc_cmd;
	switch (cmd) {

	case I_LINK:
	case I_PLINK:
		sm_dbg('G', ("sm_link_req: M_IOCTL %x (I_PLINK).\n", cmd));

		linkp = (struct linkblk *)mp->b_cont->b_rptr;

		/*
		 * 1.	Sanity check the link block.
		 * 2.	Validate that the queue is not already linked
		 *		(and resources available).
		 * 3.	Validate that the lower queue is not associated with
		 *		a logical unit.
		 * 4.	Remember that this lower queue is linked to the driver.
		 */
		if ((linkp == NULL) || (MBLKL(mp) < sizeof (*linkp)) ||
		    linkp->l_qbot == NULL) {
			sm_dbg('I', ("sm_link_req: invalid link block.\n"));
			rval = EINVAL;
		} else if ((plqi = get_lqi_byq(linkp->l_qbot)) == 0) {
			sm_dbg('I', ("sm_link_req: out of resources.\n"));
			rval = EBUSY; /* out of resources */
		} else if (plqi->sm_uqi) {
			UNLOCK_UNIT(plqi); /* was aquired by get_lqi_byq */
			sm_dbg('I', ("sm_link_req: already associated.\n"));
			rval = EBUSY; /* already linked */
		} else {
			SM_WQ(plqi) = linkp->l_qbot;
			SM_RQ(plqi)	= OTHERQ(linkp->l_qbot);

			linkp->l_qbot->q_ptr =
			    OTHERQ(linkp->l_qbot)->q_ptr = plqi;
			plqi->sm_linkid = linkp->l_index;
			UNLOCK_UNIT(plqi); /* was aquired by get_lqi_byq */

			sm_dbg('H', ("sm_link_req: linkid = %d.\n",
			    linkp->l_index));

			sm_setdip(linkp->l_qbot, plqi);
			plqi->sm_ttycommon->t_flags = 0;
			plqi->sm_ttycommon->t_cflag = 0;
			plqi->sm_mbits = 0;
			(void) ttymux_device_init(plqi);
			rval = 0;
		}

		break;

	case I_UNLINK:
	case I_PUNLINK:
		sm_dbg('G', ("sm_link_req: M_IOCTL (I_PUNLINK).\n"));

		linkp = (struct linkblk *)mp->b_cont->b_rptr;

		if ((linkp == NULL) ||
		    (MBLKL(mp) < sizeof (*linkp)) ||
		    linkp->l_qbot == NULL) {
			rval = EINVAL;
		} else if ((plqi = get_lqi_byid(linkp->l_index)) == 0) {
			rval = EINVAL;
		} else {
			sm_uqi_t *uqi;
			int werrmode;

			/*
			 * Mark the lower q as invalid.
			 */
			sm_dbg('G', ("I_PUNLINK: freeing link %d\n",
			    linkp->l_index));

			if (plqi->sm_bid) {
				qunbufcall(SM_RQ(plqi), plqi->sm_bid);
				plqi->sm_bid = 0;
			}
			if (plqi->sm_ttybid) {
				qunbufcall(SM_RQ(plqi), plqi->sm_ttybid);
				plqi->sm_ttybid = 0;
			}

			uqi = plqi->sm_uqi;


			(void) ttymux_device_fini(plqi);

			if (uqi)
				(void) sm_disassociate(uqi->sm_lunit,
				    plqi, plqi->sm_tag);

			LOCK_UNIT(plqi);

			plqi->sm_piocid = 0;

			werrmode = (plqi->sm_flags & (WERROR_MODE|HANGUP_MODE))
			    ? 1 : 0;

			plqi->sm_mbits = 0;
			plqi->sm_flags = 0;

			ttycommon_close(plqi->sm_ttycommon);
			/* SM_RQ(plqi) = SM_WQ(plqi) = 0; */
			plqi->sm_ttycommon->t_flags = 0;
			plqi->sm_ttycommon->t_cflag = 0;
			plqi->sm_ttycommon->t_iflag = 0;
			plqi->sm_linkid = 0;
			plqi->sm_dev = NODEV;
			plqi->sm_hadkadbchar = 0;
			plqi->sm_nachar = sm_ssp->sm_abs;

			UNLOCK_UNIT(plqi);
			if (uqi &&
			    werrmode &&
			    (uqi->sm_flags & FULLY_OPEN) &&
			    sm_uwq_error(uqi) &&
			    putnextctl(SM_RQ(uqi), M_HANGUP) == 0) {
				sm_log("sm_link_req: putnextctl(M_HANGUP)"
				    " failed.\n");
			}

			rval = 0;
		}

		break;
	default:
		rval = EINVAL;
	}
	if (rval != 0)
		miocnak(wq, mp, 0, rval);
	else
		miocack(wq, mp, 0, 0);
}

static int
sm_getiocinfo(mblk_t *mp, struct sm_iocinfo *info)
{
	switch (DB_TYPE(mp)) {
	case M_COPYOUT:
		info->sm_id = ((struct copyreq *)mp->b_rptr)->cq_id;
		info->sm_cmd = ((struct copyreq *)mp->b_rptr)->cq_cmd;
		info->sm_data = (((struct copyreq *)mp->b_rptr)->cq_size &&
		    mp->b_cont) ? (void *)mp->b_cont->b_rptr : 0;
		break;
	case M_COPYIN:
		info->sm_id = ((struct copyresp *)mp->b_rptr)->cp_id;
		info->sm_cmd = ((struct copyresp *)mp->b_rptr)->cp_cmd;
		info->sm_data = 0;
		break;
	case M_IOCACK:
		info->sm_id = ((struct iocblk *)mp->b_rptr)->ioc_id;
		info->sm_cmd = ((struct iocblk *)mp->b_rptr)->ioc_cmd;
		/* the se driver has bug so we cannot use ioc_count */
		info->sm_data = (((struct iocblk *)mp->b_rptr)->
		    ioc_error == 0 && mp->b_cont) ?
		    (void *)mp->b_cont->b_rptr : 0;
		break;
	case M_IOCNAK:
		info->sm_id = ((struct iocblk *)mp->b_rptr)->ioc_id;
		info->sm_cmd = ((struct iocblk *)mp->b_rptr)->ioc_cmd;
		info->sm_data = 0;
		break;
	case M_IOCDATA:
		info->sm_id = ((struct copyresp *)mp->b_rptr)->cp_id;
		info->sm_cmd = ((struct copyresp *)mp->b_rptr)->cp_cmd;
		info->sm_data = (((struct copyresp *)mp->b_rptr)->
		    cp_rval == 0 && mp->b_cont) ?
		    (void *)mp->b_cont->b_rptr : 0;
		break;
	case M_IOCTL:
		info->sm_id = ((struct iocblk *)mp->b_rptr)->ioc_id;
		info->sm_cmd = ((struct iocblk *)mp->b_rptr)->ioc_cmd;
		info->sm_data = 0;
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

/*
 * Record the termio settings that have been set on the upper stream
 */
static int
sm_update_ttyinfo(mblk_t *mp, sm_uqi_t *uqi)
{
	int err;
	struct sm_iocinfo info;

	if ((err = sm_getiocinfo(mp, &info)) != 0)
		return (err);

	switch (info.sm_cmd) {
	case TIOCSPPS:
	case TIOCGPPS:
	case TIOCGPPSEV:
		return (ENOTSUP);
	case TIOCGWINSZ:
	case TIOCSWINSZ:
		break;
	case TCSBRK:
	case TIOCSBRK:
	case TIOCCBRK:
		break;
	case TCSETSF:
		uqi->sm_flags |= FLUSHR_PEND;
		sm_dbg('I', ("TCSETSF: FLUSH is pending\n"));
		/*FALLTHROUGH*/
	case TCSETSW:
	case TCSETS:
	case TCGETS:
		if (info.sm_data != 0) {
			((struct termios *)info.sm_data)->c_cflag &=
			    (tcflag_t)(~uqi->sm_cmask);
			uqi->sm_ttycommon->t_cflag =
			    ((struct termios *)info.sm_data)->c_cflag;
		}
		break;
	case TCSETAF:
		sm_dbg('I', ("TCSETAF: FLUSH is pending\n"));
		uqi->sm_flags |= FLUSHR_PEND;
		/*FALLTHROUGH*/
	case TCSETAW:
	case TCSETA:
	case TCGETA:
		if (info.sm_data != 0) {
			((struct termio *)info.sm_data)->c_cflag &=
			    (tcflag_t)(~uqi->sm_cmask);
			uqi->sm_ttycommon->t_cflag =
			    (tcflag_t)((struct termio *)info.sm_data)->c_cflag;
		}
		break;
	case TIOCSSOFTCAR:
	case TIOCGSOFTCAR:
		if (info.sm_data != 0) {
			if (*(int *)info.sm_data == 1)
				uqi->sm_ttycommon->t_flags |= TS_SOFTCAR;
			else
				uqi->sm_ttycommon->t_flags &= ~TS_SOFTCAR;
		}
		break;
	case TIOCMSET:
	case TIOCMGET:
		if (info.sm_data != 0)
			uqi->sm_mbits = *(int *)info.sm_data;
		break;
	case TIOCMBIS:
		if (info.sm_data != 0)
			uqi->sm_mbits |= *(int *)info.sm_data;
		break;
	case TIOCMBIC:
		if (info.sm_data != 0)
			uqi->sm_mbits &= ~(*(int *)info.sm_data);
		break;
	default:
		return (EINVAL);
		/* NOTREACHED */
	} /* end switch cmd */

	if ((uqi->sm_mbits & TIOCM_CD) ||
	    (uqi->sm_ttycommon->t_flags & TS_SOFTCAR) ||
	    (uqi->sm_ttycommon->t_cflag & CLOCAL))
		uqi->sm_flags |= SM_CARON;
	else
		uqi->sm_flags &= ~SM_CARON;

	return (0);
}

/*
 * SECTION
 * STREAM's interface to the OS.
 * Routines directly callable from the OS.
 */

/*
 * Processes high priority messages comming from modules above the
 * multiplexor.
 * Return 1 if the queue was disabled.
 */
static int
sm_hp_uwput(queue_t *wq, mblk_t *mp)
{
	sm_uqi_t	*uqi = (sm_uqi_t *)(wq->q_ptr);
	int	rval = 0;
	sm_lqi_t	*plqi;
	int	msgtype = DB_TYPE(mp);

	switch (msgtype) {

	case M_FLUSH:
		/*
		 * How to flush the bottom half:
		 * putctl1(SM_WQ(plqi), *mp->b_rptr)
		 * will work on the bottom half but if FLUSHR is set
		 * when is the right time to flush the upper read queue.
		 *
		 * Could set uqi->sm_flags & WANT_FLUSH but then what happens
		 * if FLUSHR is set and the driver sends up a FLUSHR
		 * before it handles the current FLUSHR request
		 * (if only there was an id for the message that could
		 * be matched when it returns back from the drivers.
		 *
		 * Thus I'm going by the book - the bottom half acts like
		 * a stream head and turns around FLUSHW back down to
		 * the driver (see lrput). The upper half acts like a
		 * driver and turns around FLUSHR:
		 */

		sm_dbg('I', ("sm_hp_uwput: FLUSH request 0x%x\n", *mp->b_rptr));
		/* flush the upper write queue */
		if (*mp->b_rptr & FLUSHW)
			flushq(wq, FLUSHDATA);

		/*
		 * flush each associated lower write queue
		 * and pass down the driver (ignore the FLUSHR and deal with
		 * it when it comes back up the read side.
		 */
		for (plqi = uqi->sm_lqs; plqi != 0; plqi = plqi->sm_nlqi) {
			if ((plqi->sm_flags & WERROR_MODE) == 0 &&
			    SM_WQ(plqi)) {
				sm_dbg('I', ("flush lq 0x%p\n", SM_WQ(plqi)));
				if (*mp->b_rptr & FLUSHW)
					flushq(SM_WQ(plqi), FLUSHDATA);
				(void) putnextctl1(SM_WQ(plqi), M_FLUSH,
				    *mp->b_rptr);
			}
		}
		break;

	case M_STARTI:
		for (plqi = uqi->sm_lqs; plqi != 0; plqi = plqi->sm_nlqi) {
			plqi->sm_flags &= ~SM_ISTOPPED;
			if ((plqi->sm_flags & WERROR_MODE) == 0)
				(void) putnextctl(SM_WQ(plqi), msgtype);
		}
		break;

	case M_STOPI:
		for (plqi = uqi->sm_lqs; plqi != 0; plqi = plqi->sm_nlqi) {
			plqi->sm_flags |= SM_ISTOPPED;
			if ((plqi->sm_flags & WERROR_MODE) == 0)
				(void) putnextctl(SM_WQ(plqi), msgtype);
		}
		break;

	case M_STOP:	/* must never be queued */
		uqi->sm_flags |= SM_STOPPED;
		noenable(wq);
		for (plqi = uqi->sm_lqs; plqi != 0; plqi = plqi->sm_nlqi)
			if ((plqi->sm_flags & WERROR_MODE) == 0)
				(void) putnextctl(SM_WQ(plqi), msgtype);

		rval = 1;
		break;

	case M_START:	/* never be queued */
		uqi->sm_flags &= ~SM_STOPPED;
		enableok(wq);
		qenable(wq);
		for (plqi = uqi->sm_lqs; plqi != 0; plqi = plqi->sm_nlqi)
			if ((plqi->sm_flags & WERROR_MODE) == 0)
				(void) putnextctl(SM_WQ(plqi), msgtype);

		break;

	case M_PCSIG:
	case M_COPYOUT:
	case M_COPYIN:
	case M_IOCACK:
	case M_IOCNAK:
		/* Wrong direction for message */
		break;
	case M_READ:
		break;
	case M_PCPROTO:
	case M_PCRSE:
	default:
		sm_dbg('I', ("sm_hp_uwput: default case %d.\n", msgtype));
		break;
	} /* end switch on high pri message type */

	freemsg(mp);
	return (rval);
}

static int
sm_default_uwioctl(queue_t *wq, mblk_t *mp, int (*qfn)())
{
	int	err;
	struct iocblk	*iobp;
	sm_uqi_t	*uqi;

	uqi = (sm_uqi_t *)(wq->q_ptr);
	iobp = (struct iocblk *)mp->b_rptr;

	switch (iobp->ioc_cmd) {
	case TIOCEXCL:
	case TIOCNXCL:
	case TIOCSTI:
		/*
		 * The three ioctl types we support do not require any
		 * additional allocation and should not return a pending
		 * ioctl state. For this reason it is safe for us to ignore
		 * the return value from ttycommon_ioctl().
		 * Additionally, we translate any error response from
		 * ttycommon_ioctl() into EINVAL.
		 */
		(void) ttycommon_ioctl(uqi->sm_ttycommon, wq, mp, &err);
		if (err < 0)
			miocnak(wq, mp, 0, EINVAL);
		else
			miocack(wq, mp, 0, 0);
		return (0);
	default:
		break;
	}
	if ((err = sm_update_ttyinfo(mp, uqi)) != 0) {
		miocnak(wq, mp, 0, err);
		return (0);
	}

	/*
	 * If uqi->sm_siocdata.sm_iocid just overwrite it since the stream
	 * head will have timed it out
	 */
	uqi->sm_siocdata.sm_iocid = iobp->ioc_id;
	uqi->sm_siocdata.sm_acked = 0;
	uqi->sm_siocdata.sm_nacks = sm_good_qs(uqi);
	uqi->sm_siocdata.sm_acnt = 0;
	uqi->sm_siocdata.sm_policy = uqi->sm_policy;
	uqi->sm_siocdata.sm_flags = 0;
	sm_dbg('Z', (" want %d acks for id %d.\n",
	    uqi->sm_siocdata.sm_nacks, iobp->ioc_id));

	return (sm_putqs(wq, mp, qfn));
}

/*
 *
 * sm_uwput - put function for an upper STREAM write.
 */
static int
sm_uwput(queue_t *wq, mblk_t *mp)
{
	sm_uqi_t		*uqi;
	uchar_t		msgtype;
	int		cmd;
	struct iocblk	*iobp;

	uqi = (sm_uqi_t *)(wq->q_ptr);
	msgtype = DB_TYPE(mp);

	ASSERT(uqi != 0 && sm_ssp != 0);

	if (msgtype >= QPCTL && msgtype != M_IOCDATA) {
		(void) sm_hp_uwput(wq, mp);
		return (0);
	}

	switch (DB_TYPE(mp)) {
	case M_DATA:
	case M_DELAY:
	case M_BREAK:
	default:
		(void) sm_putqs(wq, mp, putq);
		break;

	case M_CTL:
		if (((struct iocblk *)mp->b_rptr)->ioc_cmd == MC_CANONQUERY) {
			(void) putnextctl1(OTHERQ(wq), M_CTL, MC_NOCANON);
		}
		freemsg(mp);
		break;
	case M_IOCDATA: /* not handled as high pri because may need to putbq */
		sm_dbg('M', ("sm_uwput(M_IOCDATA)\n"));
		/*FALLTHROUGH*/
	case M_IOCTL:
		cmd = (msgtype == M_IOCDATA) ?
		    ((struct copyresp *)mp->b_rptr)->cp_cmd :
		    ((struct iocblk *)mp->b_rptr)->ioc_cmd;

		iobp = (struct iocblk *)mp->b_rptr;
		iobp->ioc_rval = 0;

		sm_dbg('M', ("sm_uwput(M_IOCTL:%d)\n", cmd));

		switch (cmd) {

		case CONSGETABORTENABLE:
			iobp->ioc_error = ttymux_abort_ioctl(mp);
			DB_TYPE(mp) = iobp->ioc_error ? M_IOCNAK : M_IOCACK;
			qreply(wq, mp);
			break;
		case CONSSETABORTENABLE:
			iobp->ioc_error =
			    secpolicy_sys_config(iobp->ioc_cr, B_FALSE) != 0 ?
			    EPERM : ttymux_abort_ioctl(mp);
			DB_TYPE(mp) = iobp->ioc_error ? M_IOCNAK : M_IOCACK;
			qreply(wq, mp);
			break;
		case TTYMUX_SETABORT:
			if (secpolicy_sys_config(iobp->ioc_cr, B_FALSE) != 0) {
				iobp->ioc_error = EPERM;
				DB_TYPE(mp) = M_IOCNAK;
				qreply(wq, mp);
				break;
			}
			/*FALLTHROUGH*/
		case TTYMUX_GETABORT:
		case TTYMUX_GETABORTSTR:
		case TTYMUX_ASSOC:
		case TTYMUX_DISASSOC:
		case TTYMUX_SETCTL:
		case TTYMUX_GETLINK:
		case TTYMUX_CONSDEV:
		case TTYMUX_GETCTL:
		case TTYMUX_LIST:
			(void) sm_ioctl_cmd(uqi, mp);
			qreply(wq, mp);
			break;
		case I_LINK:
		case I_PLINK:
		case I_UNLINK:
		case I_PUNLINK:
			qwriter(wq, mp, sm_link_req, PERIM_OUTER);
			break;
		case TCSETSW:
		case TCSETSF:
		case TCSETAW:
		case TCSETAF:
		case TCSBRK:
			if (wq->q_first) {
				sm_dbg('A', ("sm_uwput: TCSET-> on srv q.\n"));
				/* keep message order intact */
				(void) putq(wq, mp);
				break;
			}
			/*FALLTHROUGH*/
		default:
			(void) sm_default_uwioctl(wq, mp, putq);
			break;
		}

		break; /* M_IOCTL */

	} /* end switch on message type */

	return (0);
}

/*
 * sm_uwsrv - service function for an upper STREAM write.
 * 'sm_uwsrv' takes a q parameter.	The q parameter specifies the queue
 * which is to be serviced.	This function reads the messages which are on
 * this service queue and passes them to the appropriate lower driver queue.
 */
static int
sm_uwsrv(queue_t *q)
{
	mblk_t	*mp;
	sm_uqi_t	*uqi = (sm_uqi_t *)(q->q_ptr);
	int		msgtype;

	ASSERT(q == SM_WQ(uqi));

	/*
	 * Empty the queue unless explicitly stopped.
	 */
	while (mp = getq(q)) {
		msgtype = DB_TYPE(mp);

		if (msgtype >= QPCTL && msgtype != M_IOCDATA)
			if (sm_hp_uwput(q, mp)) {
				sm_dbg('T', ("sm_uwsrv: flowcontrolled.\n"));
				break; /* indicates that the is disabled */
			}
			else
				continue;

		if (uqi->sm_flags & SM_STOPPED) {
			(void) putbq(q, mp);
			sm_dbg('T', ("sm_uwsrv: SM_STOPPED.\n"));
			break;
		}

		/*
		 * Read any ttycommon data that may
		 * change (TS_SOFTCAR, CREAD, etc.).
		 */
		switch (DB_TYPE(mp)) {
		case M_IOCTL:
		case M_IOCDATA:
			if (sm_default_uwioctl(q, mp, putbq))
				return (0);
			break;

		default:
			if (sm_putqs(q, mp, putbq))
				return (0);
		}
	}
	return (0);
}

/*
 * Lower write side service routine used for backenabling upstream
 * flow control.
 */
static int
sm_lwsrv(queue_t *q)
{
	sm_lqi_t *lqi = (sm_lqi_t *)q->q_ptr;
	queue_t *uwq;

	LOCK_UNIT(lqi);
	if (lqi->sm_uqflags & SM_UQVALID) {
		/*
		 * It's safe to lock uqi since lwsrv runs asynchronously
		 * with the upper write routines so this cannot be an
		 * upper half thread. While holding the lqi lock and
		 * if SM_UQVALID is set we are guaranteed that
		 * lqi->sm_uqi will be valid.
		 */
		sm_dbg('I', ("sm_lwsrv: re-enabling upper queue.\n"));

		uwq = SM_WQ(lqi->sm_uqi);
		UNLOCK_UNIT(lqi);
		qenable(uwq);
	} else  {
		UNLOCK_UNIT(lqi);
	}
	return (0);
}

/*
 * Upper read queue ioctl response handler for messages
 * passed from the lower half of the driver.
 */
static int
sm_uriocack(queue_t *rq, mblk_t *mp)
{
	sm_uqi_t		*uqi = (sm_uqi_t *)rq->q_ptr;
	int		err, flag;
	sm_iocdata_t	*iodp;
	struct sm_iocinfo	info;

	if ((err = sm_getiocinfo(mp, &info)) != 0) {
		sm_dbg('I', ("Unknown ioctl response\n"));
		return (err);
	}

	if (info.sm_id == uqi->sm_piocdata.sm_iocid) {
		iodp = &uqi->sm_piocdata;
	} else if (info.sm_id == uqi->sm_siocdata.sm_iocid) {
		iodp = &uqi->sm_siocdata;
	} else {
		sm_log("Unexpected ioctl response\n");
		sm_dbg('I', ("Unexpected ioctl response (id %d)\n",
		    info.sm_id));

		/*
		 * If the response is sent up it will result in
		 * duplicate ioctl responses. The ioctl has probably been
		 * timed out by the stream head so dispose of the response
		 * (since it has arrived too late.
		 */
		goto out;
	}

	flag = SM_COPYIN;

	switch (DB_TYPE(mp)) {
	case M_COPYOUT:
		flag = SM_COPYOUT;
		/*FALLTHRU*/
	case M_COPYIN:
		if (iodp->sm_flags & flag)
			goto out;
		iodp->sm_flags |= flag;

		break;
	case M_IOCACK:
		iodp->sm_ackcnt += 1;
		iodp->sm_acnt += 1;
		if (iodp->sm_policy == FIRSTACK) {
			if (iodp->sm_acnt == iodp->sm_nacks)
				iodp->sm_iocid = 0;
			if (iodp->sm_acnt == 1)
				iodp->sm_acked = 1;
			else
				goto out;
		} else {
			if (iodp->sm_acnt == iodp->sm_nacks) {
				iodp->sm_iocid = 0;
				iodp->sm_acked = 1;
			} else
				goto out;
		}
		break;
	case M_IOCNAK:
		iodp->sm_nakcnt += 1;
		iodp->sm_acnt += 1;
		if (iodp->sm_acnt == iodp->sm_nacks) {
			iodp->sm_iocid = 0;
			if (iodp->sm_acked == 0) {
				iodp->sm_acked = 1;
				break;
			}
		}
		goto out;
	default:
		goto out;
	}

	/*
	 * Merge the tty settings each of the associated lower streams.
	 */
	if (info.sm_data)
		(void) sm_update_ttyinfo(mp, uqi);

	if (iodp == &uqi->sm_piocdata) {
		if (iodp->sm_iocid == 0) {
			uqi->sm_flags &= ~SM_IOCPENDING;
		}
	} else {
		sm_dbg('I', ("sm_uriocack: forwarding response for %d.\n",
		    info.sm_id));
		putnext(rq, mp);
		return (0);
	}
out:
	sm_dbg('I', ("sm_uriocack: freeing response for %d.\n", info.sm_id));
	freemsg(mp);
	return (0);
}

/*
 * Transfer a message from the lower read side of the multiplexer onto
 * the associated upper stream.
 */
static int
sm_ursendup(queue_t *q, mblk_t *mp)
{
	sm_uqi_t	*uqi = (sm_uqi_t *)q->q_ptr;

	if (!canputnext(q) && DB_TYPE(mp) < QPCTL) {
		sm_dbg('I', ("sm_ursendup: flow controlled.\n"));
		return (1);
	}

	switch (DB_TYPE(mp)) {
	case M_COPYIN:
	case M_COPYOUT:
	case M_IOCACK:
	case M_IOCNAK:
		(void) sm_uriocack(q, mp);
		break;
	case M_HANGUP:
		if (sm_uwq_error(uqi)) {
			/* there are no usable lower q's */
			uqi->sm_flags &= ~SM_CARON;
			putnext(q, mp);
		} else {
			/* there are still usable q's - don't send up */
			freemsg(mp);
		}
		break;
	case M_ERROR:
		if (sm_uwq_error(uqi)) {
			/* there are no usable lower q's */
			uqi->sm_flags &= ~SM_CARON;
			putnext(q, mp);
		} else if (*mp->b_rptr == NOERROR) {
			/* the error has cleared */
			uqi->sm_flags &= ~ERROR_MODE;
			putnext(q, mp);
		} else {
			/* there are still usable q's - don't send up */
			freemsg(mp);
		}
		break;
	case M_FLUSH:
		flushq(q, FLUSHDATA);
		putnext(q, mp);	/* time to use FLUSHR_PEND flag */
		break;
	case M_CTL:
		/* wrong direction - must have come from sm_close */
		uqi->sm_flags |= SM_CLOSE;
		sm_dbg('I', ("sm_ursrv: had SM_CLOSE.\n"));
		freemsg(mp);
		break;
	case M_UNHANGUP:
		/* just pass them all up - they're harmless */
		uqi->sm_flags |= SM_CARON;
		/* FALLTHROUGH */
	default:
		putnext(q, mp);
		break;
	}

	return (0);
}

/*
 * sm_urput - put function for a lower STREAM read.
 */
static int
sm_urput(queue_t *q, mblk_t *mp)
{
	if (sm_ursendup(q, mp) != 0)
		(void) putq(q, mp);

	return (0);
}

/*
 * Upper read side service routine.
 * Read side needs to be fast so only check for duplicate M_IOCTL acks.
 */
static int
sm_ursrv(queue_t *q)
{
	sm_uqi_t	*uqi = (sm_uqi_t *)q->q_ptr;
	mblk_t	*mp;
	int	flags = uqi->sm_flags;

	while ((mp = getq(q))) {
		if (sm_ursendup(q, mp) != 0) {
			sm_dbg('I', ("sm_ursrv: flow controlled.\n"));
			(void) putbq(q, mp);
			uqi->sm_flags |= WANT_RENB;
			break;
		}
	}

	/*
	 * If the q service was called because it was no longer
	 * flow controled then enable each of the driver queues.
	 */
	if ((flags & WANT_RENB) && !(uqi->sm_flags & WANT_RENB)) {
		sm_lqi_t *lqi;
		queue_t *drq; /* read q of linked driver */

		uqi->sm_flags &= ~WANT_RENB;
		for (lqi = uqi->sm_lqs; lqi != 0; lqi = lqi->sm_nlqi) {
			drq = SM_RQ(lqi)->q_next;
			if (drq && drq->q_first != 0)
				qenable(drq);
		}
	}

	return (0);
}

/*
 * Check a message sent from a linked device for abort requests and
 * for flow control.
 */
static int
sm_lrmsg_check(queue_t *q, mblk_t *mp)
{
	sm_lqi_t	*lqi	= (sm_lqi_t *)q->q_ptr;

	switch (DB_TYPE(mp)) {
	case M_DATA:
		LOCK_UNIT(lqi);
		/*
		 * check for abort - only allow abort on I/O consoles
		 * known to OBP -
		 * fix it when we do polled io
		 */
		if ((lqi->sm_ioflag & (uint_t)FORINPUT) == 0) {
			freemsg(mp);
			UNLOCK_UNIT(lqi);
			return (1);
		}
		if ((lqi->sm_uqflags & SM_OBPCNDEV) &&
		    lqi->sm_ctrla_abort_on &&
		    abort_enable == KIOCABORTALTERNATE) {

			uchar_t		*rxc;
			boolean_t	aborted = B_FALSE;

			for (rxc = mp->b_rptr;
			    rxc != mp->b_wptr;
			    rxc++)

				if (*rxc == *lqi->sm_nachar) {
					lqi->sm_nachar++;
					if (*lqi->sm_nachar == '\0') {
						abort_sequence_enter(
						    (char *)NULL);
						lqi->sm_nachar = sm_ssp->sm_abs;
						aborted = B_TRUE;
					}
				} else
					lqi->sm_nachar = (*rxc == *sm_ssp->
					    sm_abs) ?
					    sm_ssp->
					    sm_abs + 1 :
					    sm_ssp->sm_abs;

			if (aborted) {
				freemsg(mp);
				UNLOCK_UNIT(lqi);
				return (1);
			}
		}
		UNLOCK_UNIT(lqi);
		break;
	case M_BREAK:	/* we'll eventually see this as a flush */
		LOCK_UNIT(lqi);
		/*
		 * Only allow abort on OBP devices. When polled I/O is
		 * supported allow abort on any console device.
		 * Parity errors are reported upstream as breaks so
		 * ensure that there is no data in the message before
		 * deciding whether to abort.
		 */
		if ((lqi->sm_uqflags & SM_OBPCNDEV) && /* console stream */
		    (mp->b_wptr - mp->b_rptr == 0 &&
		    msgdsize(mp) == 0)) {	/* not due to parity */

			if (lqi->sm_break_abort_on &&
			    abort_enable != KIOCABORTALTERNATE)
				abort_sequence_enter((char *)NULL);

			freemsg(mp);
			UNLOCK_UNIT(lqi);
			return (1);
		} else {
			UNLOCK_UNIT(lqi);
		}
		break;
	default:
		break;
	}

	if (DB_TYPE(mp) >= QPCTL)
		return (0);

	LOCK_UNIT(lqi); /* lock out the upper half */
	if ((lqi->sm_uqflags & SM_UQVALID) && SM_RQ(lqi->sm_uqi)) {
		UNLOCK_UNIT(lqi);
		if (!canput(SM_RQ(lqi->sm_uqi))) {
			sm_dbg('I', ("sm_lrmsg_check: flow controlled.\n"));
			(void) putq(q, mp);
			return (1);
		}
	} else {
		UNLOCK_UNIT(lqi);
	}

	return (0);
}

/*
 * sm_sendup - deliver a message to the upper read side of the multiplexer
 */
static int
sm_sendup(queue_t *q, mblk_t *mp)
{
	sm_lqi_t	*lqi	= (sm_lqi_t *)q->q_ptr;

	if (sm_ssp == NULL) {
		freemsg(mp);
		return (0);
	}

	/*
	 * Check for CD status change messages from driver.
	 * (Remark: this is an se driver thread running at soft interupt
	 * priority and the waiters are in user context).
	 */
	switch (DB_TYPE(mp)) {
	case M_DATA:
	case M_BREAK:	/* we'll eventually see this as a flush */
		break;

	/* high priority messages */
	case M_IOCACK:
	case M_IOCNAK:
		if ((lqi->sm_flags & SM_IOCPENDING) && lqi->sm_piocid ==
		    ((struct iocblk *)mp->b_rptr)->ioc_id) {
			freemsg(mp);
			lqi->sm_flags &= ~SM_IOCPENDING;
			sm_issue_ioctl(lqi);
			return (0);
		}
		break;
	case M_UNHANGUP:
		/*
		 * If the driver can send an M_UNHANGUP it must be able to
		 * accept messages from above (ie clear WERROR_MODE if set).
		 */
		sm_dbg('E', ("lrput: M_UNHANGUP\n"));
		lqi->sm_mbits |= TIOCM_CD;
		lqi->sm_flags &= ~(WERROR_MODE|HANGUP_MODE);

		break;

	case M_HANGUP:
		sm_dbg('E', ("lrput: MHANGUP\n"));
		lqi->sm_mbits &= ~TIOCM_CD;
		lqi->sm_flags |= (WERROR_MODE|HANGUP_MODE);
		break;

	case M_ERROR:

		sm_dbg('E', ("lrput: MERROR\n"));
		/*
		 * Tell the driver to flush rd/wr queue if its read/write error.
		 * if its a read/write error flush rq/wq (type in first bytes).
		 */
		if ((mp->b_wptr - mp->b_rptr) == 2) {
			uchar_t	rw = 0;

			if (*mp->b_rptr == NOERROR) {
				/* not in error anymore */
				lqi->sm_flags &= ~ERROR_MODE;
				lqi->sm_flags |= WANT_CD;
			} else {
				if (*mp->b_rptr != 0) {
					/* read error */
					rw |= FLUSHR;
					lqi->sm_flags |= RERROR_MODE;
				}
				mp->b_rptr++;
				if (*mp->b_rptr != 0) {
					/* write error */
					rw |= FLUSHW;
					lqi->sm_flags |= WERROR_MODE;
				}

				mp->b_rptr--;
				/* has next driver done qprocsoff */
				if (rw && OTHERQ(q)->q_next != NULL) {
					(void) putnextctl1(OTHERQ(q), M_FLUSH,
					    rw);
				}
			}
		} else if (*mp->b_rptr != 0 && OTHERQ(q)->q_next != NULL) {
			sm_dbg('E', ("lrput: old style MERROR (?)\n"));

			lqi->sm_flags |= (RERROR_MODE | WERROR_MODE);
			(void) putnextctl1(OTHERQ(q), M_FLUSH, FLUSHRW);
		}
		break;

	case M_PCSIG:
	case M_SIG:
		break;
	case M_COPYOUT:
	case M_COPYIN:
		break;
	case M_FLUSH:
		/* flush the read queue and pass on up */
		flushq(q, FLUSHDATA);
		break;
	default:
		break;
	}

	LOCK_UNIT(lqi); /* lock out the upper half */
	if (lqi->sm_uqflags & SM_UQVALID && SM_RQ(lqi->sm_uqi)) {
		UNLOCK_UNIT(lqi);
		(void) putq(SM_RQ(lqi->sm_uqi), mp);
		return (0);
	} else {
		sm_dbg('I', ("sm_sendup: uq not valid\n"));
		freemsg(mp);
	}
	UNLOCK_UNIT(lqi);

	return (0);
}

/*
 * sm_lrput - put function for a lower STREAM read.
 */
static int
sm_lrput(queue_t *q, mblk_t *mp)
{
	if (sm_lrmsg_check(q, mp) == 0)
		(void) sm_sendup(q, mp);
	return (0);
}

/*
 * sm_lrsrv - service function for the lower read STREAM.
 */
static int
sm_lrsrv(queue_t *q)
{
	mblk_t	*mp;

	sm_dbg('I', ("sm_lrsrv: not controlled.\n"));
	while (mp = getq(q))
		(void) sm_sendup(q, mp);

	return (0);
}

/*
 * Check whether a thread is allowed to open the requested device.
 */
static int
sm_ok_to_open(sm_uqi_t *uqi, int protocol, cred_t *credp, int *abort_waiters)
{
	int rval = 0;
	int proto;

	*abort_waiters = 0;

	switch (protocol) {
		case ASYNC_DEVICE: /* Standard async protocol */
		if ((uqi->sm_protocol == NULL_PROTOCOL) ||
		    (uqi->sm_protocol == ASYN_PROTOCOL)) {
			/*
			 * Lock out other incompatible protocol requests.
			 */
			proto = ASYN_PROTOCOL;
			rval = 0;
		} else
			rval = EBUSY;
		break;

		case OUTLINE:	/* Outdial protocol */
		if ((uqi->sm_protocol == NULL_PROTOCOL) ||
		    (uqi->sm_protocol == OUTD_PROTOCOL)) {
			proto = OUTD_PROTOCOL;
			rval = 0;
		} else if (uqi->sm_protocol == ASYN_PROTOCOL) {
			/*
			 * check for dialout request on a line that is already
			 * open for dial in:
			 * kick off any thread that is waiting to fully open
			 */
			if (uqi->sm_flags & FULLY_OPEN)
				rval = EBUSY;
			else {
				proto = OUTD_PROTOCOL;
				*abort_waiters = 1;
			}
		} else
			rval = EBUSY;
		break;
		default:
			rval = ENOTSUP;
	}

	if (rval == 0 &&
	    (uqi->sm_ttycommon->t_flags & TS_XCLUDE) &&
	    secpolicy_excl_open(credp) != 0) {

		if (uqi->sm_flags & FULLY_OPEN) {
			rval = EBUSY; /* exclusive device already open */
		} else {
			/* NB TS_XCLUDE cant be set during open so NOTREACHED */
			/* force any waiters to yield TS_XCLUDE */
			*abort_waiters = 1;
		}
	}

	if (rval == 0)
		uqi->sm_protocol = proto;

	sm_dbg('A', ("ok_to_open (0x%p, %d) proto=%d rval %d (wabort=%d)",
	    uqi, protocol, uqi->sm_protocol, rval, *abort_waiters));

	return (rval);
}

/* wait for memory to become available whilst performing a qwait */
/*ARGSUSED*/
static void dummy_callback(void *arg)
{}

/* ARGSUSED */
static int
sm_dump_msg(queue_t *q, mblk_t *mp)
{
	freemsg(mp);
	return (0);
}

/*
 * Wait for a message to arrive - must be called with exclusive
 * access at the outer perimiter.
 */
static int
sm_qwait_sig(sm_uqi_t *uqi, queue_t *q)
{
	int err;

	sm_dbg('C', ("sm_qwait_sig: waiting.\n"));

	uqi->sm_waitq = q;
	uqi->sm_nwaiters++;	/* required by the close routine */
	err = qwait_sig(q);
	if (--uqi->sm_nwaiters == 0)
		uqi->sm_waitq = 0;

	if (err == 0)
		err = EINTR;
	else if (q->q_ptr == 0) /* can happen if there are multiple waiters */
		err = -1;
	else if (uqi->sm_flags & SM_CLOSE) {
		uqi->sm_flags &= ~SM_CLOSE;
		err = 1;	/* a different protocol has closed its stream */
	}
	else
		err = 0;	/* was worth waiting for */

	sm_dbg('C', ("sm_qwait_sig: rval %d\n", err));
	return (err);
}

/*
 * Defer the opening of one the drivers devices until the state of each
 * associated lower stream is known.
 */
static int
sm_defer_open(sm_uqi_t *uqi, queue_t *q)
{
	uint_t cmdflags = WANT_CDSTAT;
	int err, nqs;

	while ((nqs = sm_good_qs(uqi)) == 0) {
		sm_dbg('C', ("sm_defer_open: no good qs\n"));
		if (err = sm_qwait_sig(uqi, q))
			return (err);
	}

	while ((uqi->sm_flags & SM_CARON) == 0) {
		int iocmd;
		mblk_t *pioc;

		sm_dbg('C', ("sm_defer_open: flags 0x%x cmdflags 0x%x\n",
		    uqi->sm_flags, cmdflags));
		if (cmdflags == 0) {
			if (err = sm_qwait_sig(uqi, q))
				return (err);
			continue;	/* waiting for an M_UNHANGUP */
		} else if (cmdflags & WANT_SC) {
			cmdflags &= ~WANT_SC;
			iocmd = TIOCGSOFTCAR;
		} else if (cmdflags & WANT_CD) {
			cmdflags &= ~WANT_CD;
			iocmd = TIOCMGET;
		} else if (cmdflags & WANT_CL) {
			cmdflags &= ~WANT_CL;
			iocmd = TCGETS;
		}

		if (uqi->sm_piocdata.sm_iocid == 0) {
			while ((pioc = mkiocb(iocmd)) == 0) {
				bufcall_id_t id =
				    qbufcall(q, sizeof (struct iocblk),
				    BPRI_MED, dummy_callback, 0);
				if (err = sm_qwait_sig(uqi, q)) {
					/* wait for the bufcall */
					qunbufcall(q, id);
					return (err);
				}
				qunbufcall(q, id);
			}

			uqi->sm_flags |= SM_IOCPENDING;

			uqi->sm_piocdata.sm_iocid =
			    ((struct iocblk *)pioc->b_rptr)->ioc_id;
			uqi->sm_piocdata.sm_acked = 0;
			uqi->sm_piocdata.sm_nacks = nqs;
			uqi->sm_piocdata.sm_acnt = 0;
			uqi->sm_piocdata.sm_ackcnt = uqi->
			    sm_piocdata.sm_nakcnt = 0;
			uqi->sm_piocdata.sm_policy = uqi->sm_policy;
			uqi->sm_piocdata.sm_flags = SM_INTERNALIOC;
			if (sm_putqs(WR(q), pioc, sm_dump_msg) != 0) {
				uqi->sm_piocdata.sm_iocid = 0;
				sm_log("sm_defer_open: bad putqs\n");
				return (-1);
			}
		}

		sm_dbg('C', ("sm_defer_open: flags 0x%x\n", uqi->sm_flags));
		while ((uqi->sm_flags & SM_CARON) == 0 &&
		    (uqi->sm_flags & SM_IOCPENDING) != 0)
			if (err = sm_qwait_sig(uqi, q))
				return (err);

		sm_dbg('C', ("defer_open: uq flags 0x%x.\n", uqi->sm_flags));
	}
	sm_dbg('C', ("defer_open: return 0.\n"));
	return (0);
}

static int
sm_open(queue_t *rq, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	int		ftstat;
	int		unit;
	int		protocol;
	sm_uqi_t		*uqi;
	int		abort_waiters;

	if (sm_ssp == NULL)
		return (ENXIO);
	/*
	 * sflag = 0 => streams device.
	 */
	if (sflag != 0 || DEV_TO_UNIT(*devp) >= NLUNITS) {
		sm_dbg('C', ("open: sflag=%d or bad dev_t.\n", sflag));
		return (ENXIO);
	}

	unit = DEV_TO_UNIT(*devp);
	protocol = DEV_TO_PROTOBITS(*devp);

	uqi = get_uqi(sm_ssp, unit);

	sm_dbg('C', ("open(0x%p, %d, 0x%x) :- unit=%d, proto=%d, uqi=0x%p\n",
	    rq, *devp, flag, unit, protocol, uqi));

	if (uqi == 0)
		return (ENXIO);

	if (sm_refuse_opens && unit > smctlunit && uqi->sm_nlqs == 0)
		return (ENXIO);

	if (uqi->sm_flags & EXCL_OPEN && (flag & FEXCL)) {
		return (EBUSY); /* device in use */
	}

	if ((flag & FEXCL)) {
		if (secpolicy_excl_open(credp) != 0)
			return (EPERM);

		if ((uqi->sm_flags & FULLY_OPEN) || uqi->sm_nwaiters > 0)
			return (EBUSY); /* device in use */

		uqi->sm_flags |= EXCL_OPEN;
	}

	if (uqi->sm_protocol == NULL_PROTOCOL) {
		struct termios *termiosp;
		int len;

		if (ddi_getlongprop(DDI_DEV_T_ANY, ddi_root_node(),
		    DDI_PROP_NOTPROM, "ttymodes", (caddr_t)&termiosp, &len)
		    == DDI_PROP_SUCCESS &&
		    (len == sizeof (struct termios))) {

			sm_dbg('C', ("open: c_cflag=0x%x\n",
				termiosp->c_cflag));

			uqi->sm_ttycommon->t_iflag = termiosp->c_iflag;
			uqi->sm_ttycommon->t_cflag = termiosp->c_cflag;
			uqi->sm_ttycommon->t_stopc = termiosp->c_cc[VSTOP];
			uqi->sm_ttycommon->t_startc = termiosp->c_cc[VSTART];

			/*
			 * IGNBRK,BRKINT,INPCK,IXON,IXANY,IXOFF - drivers
			 * PARMRK,IGNPAR,ISTRIP - how to report parity
			 * INLCR,IGNCR,ICRNL,IUCLC - ldterm (sophisticated I/O)
			 * IXON, IXANY, IXOFF - flow control input
			 * CBAUD,CSIZE,CS5-8,CSTOPB,PARENB,PARODD,HUPCL,
			 * RCV1EN,XMT1EN,LOBLK,XCLUDE,CRTSXOFF,CRTSCTS,
			 * CIBAUD,PAREXT,CBAUDEXT,CIBAUDEXT,CREAD,CLOCAL
			 */

			kmem_free(termiosp, len);
		}
		else
			bzero((caddr_t)uqi->sm_ttycommon,
			    sizeof (uqi->sm_ttycommon));

		if (*devp == rconsdev) {
			uqi->sm_cmask = sm_cmask;
			uqi->sm_ttycommon->t_flags |= TS_SOFTCAR;
		} else {
			uqi->sm_ttycommon->t_flags &= ~TS_SOFTCAR;
		}

		/*
		 * Clear the default CLOCAL and TS_SOFTCAR flags since
		 * they must correspond to the settings on the real devices.
		 */

		uqi->sm_ttycommon->t_cflag &= ~(uqi->sm_cmask|CLOCAL);
		uqi->sm_mbits = 0;
		uqi->sm_policy = FIRSTACK;
		if (unit == 0 && sm_ssp->sm_ms == 0)
			sm_ssp->sm_ms = (sm_mux_state_t *)
			    space_fetch(TTYMUXPTR);
		if (sm_ssp->sm_ms) {
			if (sm_ssp->sm_ms->sm_cons_stdin.sm_dev == *devp ||
			    sm_ssp->sm_ms->sm_cons_stdout.sm_dev == *devp)
				sm_ssp->sm_lconsole = uqi;
		}
	}

	/*
	 * Does this thread need to wait?
	 */

	sm_dbg('C', ("sm_open: %d %d 0x%p 0x%x\n",
	    !(flag & (FNDELAY|FNONBLOCK)), !(protocol == OUTLINE), uqi->sm_lqs,
	    uqi->sm_flags));

tryopen:

	abort_waiters = 0;
	if (ftstat = sm_ok_to_open(uqi, protocol, credp, &abort_waiters)) {
		sm_dbg('C', ("open failed stat=%d.\n", ftstat));

		if ((uqi->sm_flags & FULLY_OPEN) == 0 && uqi->sm_nwaiters == 0)
			uqi->sm_protocol = NULL_PROTOCOL;
		if (flag & FEXCL)
			uqi->sm_flags &= ~EXCL_OPEN;
		return (ftstat);
	}

	if (abort_waiters) {
		uqi->sm_dev = *devp;
		/* different device wants to use the unit */
		SM_RQ(uqi) = rq;
		SM_WQ(uqi) = WR(rq);
	}
	if (rq->q_ptr == 0) {
		sm_lqi_t *lqi;

		uqi->sm_dev = *devp;
		rq->q_ptr = WR(rq)->q_ptr = uqi;
		SM_RQ(uqi) = rq;
		SM_WQ(uqi) = WR(rq);
		qprocson(rq);
		for (lqi = uqi->sm_lqs; lqi != 0; lqi = lqi->sm_nlqi) {
			LOCK_UNIT(lqi);
			lqi->sm_uqflags |= SM_UQVALID;
			UNLOCK_UNIT(lqi);
		}

		sm_dbg('C', ("sm_open: SM_UQVALID set on lqs.\n"));
	}

	if (*devp != rconsdev && BLOCKING(uqi, protocol, flag)) {

		uqi->sm_flags |= WANT_CDSTAT;

		do {
			/*
			 * Wait for notifications of changes in the CLOCAL
			 * and TS_SOFTCAR flags and a TIOCM_CD flag of a
			 * TIOCMGET request (come in on the write side queue).
			 */

			if ((ftstat = sm_defer_open(uqi, rq)) != EINTR) {
				if (ftstat) {
					goto tryopen;
				} else {
					continue;
				}
			}

			if (uqi->sm_nwaiters == 0) {	/* clean up */
				/*
				 * only opens on an asynchronous
				 * protocols reach here so checking
				 * nwaiters == 0 is sufficient to
				 * ensure that no other thread
				 * is waiting on this logical unit
				 */
				if ((uqi->sm_flags & FULLY_OPEN) == 0) {

					sm_lqi_t *lqi;

					uqi->sm_dev = NODEV;
					sm_dbg('C', ("sm_open FULLY_OPEN=0\n"));
					for (lqi = uqi->sm_lqs; lqi != 0;
					    lqi = lqi->sm_nlqi) {
						LOCK_UNIT(lqi);
						lqi->sm_uqflags &= ~SM_UQVALID;
						UNLOCK_UNIT(lqi);
					}

					qprocsoff(rq);
					rq->q_ptr = WR(rq)->q_ptr = 0;
					SM_RQ(uqi) = 0;
					SM_WQ(uqi) = 0;
				}
			}
			if ((uqi->sm_flags & FULLY_OPEN) == 0 &&
			    uqi->sm_nwaiters == 0)
				uqi->sm_protocol = NULL_PROTOCOL;
			if (flag & FEXCL)
				uqi->sm_flags &= ~EXCL_OPEN;
			sm_dbg('C', ("sm_open: done (ret %d).\n", ftstat));
			return (ftstat);
		} while (BLOCKING(uqi, protocol, flag));
	}

	uqi->sm_flags |= FULLY_OPEN;

	sm_dbg('C', ("sm_open done (ret %d).\n", ftstat));
	return (ftstat);
}

/*
 * Multiplexer device close routine.
 */
/*ARGSUSED*/
static int
sm_close(queue_t *rq, int flag, cred_t *credp)
{
	sm_uqi_t *uqi = (sm_uqi_t *)rq->q_ptr;
	sm_lqi_t *lqi;

	if (sm_ssp == NULL)
		return (ENXIO);

	if (uqi == NULL) {
		sm_dbg('C', ("close: WARN:- q 0x%p already closed.\n", rq));
		return (ENXIO);
	}

	sm_dbg('C', ("close: uqi=0x%p unit=%d q=0x%p)\n", uqi, uqi->sm_lunit,
	    rq));

	if (SM_RQ(uqi) != rq)
		sm_dbg('C', ("sm_close: rq != current uqi queue\n"));

	if (uqi->sm_ttybid) {
		qunbufcall(SM_RQ(uqi), uqi->sm_ttybid);
		uqi->sm_ttybid = 0;
	}

	/*
	 * Tell all the linked queues that the upper queue has gone
	 * Note close will never get called on a stream while there is a
	 * thread blocked trying to open the same stream.
	 * If there is a blocked open on a different stream but on
	 * the same logical unit it will reset the lower queue flags.
	 */
	for (lqi = uqi->sm_lqs; lqi != 0; lqi = lqi->sm_nlqi) {
		LOCK_UNIT(lqi);
		lqi->sm_uqflags &= ~SM_UQVALID;
		UNLOCK_UNIT(lqi);
	}

	/*
	 * Turn off the STREAMs queue processing for this queue.
	 */
	qprocsoff(rq);

	/*
	 * Similarly we will never get here if there is thread trying to
	 * open ths stream.
	 */
	LOCK_UNIT(uqi);
	if (uqi->sm_waitq == 0)
		uqi->sm_flags = (uqi->sm_flags & SM_OBPCNDEV) ? SM_OBPCNDEV :
		    0U;

	uqi->sm_dev = NODEV;
	uqi->sm_protocol = NULL_PROTOCOL;
	ttycommon_close(uqi->sm_ttycommon);
	/* it just frees any pending ioctl */

	uqi->sm_ttycommon->t_cflag = 0;
	uqi->sm_ttycommon->t_flags = 0;

	/*
	 * Reset the queue pointers to NULL.
	 * If a thread is qwaiting in the open routine it will recheck
	 * the q_ptr.
	 */
	rq->q_ptr = NULL;
	WR(rq)->q_ptr = NULL;
	UNLOCK_UNIT(uqi);

	if (sm_ssp->sm_lconsole == uqi) {
		/* this will never be the outdial device closing */
		sm_ssp->sm_lconsole = 0;
	}
	/*
	 * If there is another thread waiting for this close then unblock
	 * the thread by putting a message on its read queue.
	 */
	if (uqi->sm_waitq) {
		sm_dbg('C', ("close(0x%p): doing putctl on 0x%p\n",
		    rq, uqi->sm_waitq));
		if (rq == uqi->sm_waitq)
			sm_log("close: waitq and closeq are same q\n");
		(void) putctl(uqi->sm_waitq, M_CTL);
	}

	uqi->sm_flags &= ~(EXCL_OPEN | FULLY_OPEN);
	sm_dbg('C', ("close: returning ok.\n"));
	return (0);
}

/*
 * Initialise the software abort sequence for use when one of the
 * driver's nodes provides the system console.
 */
static void
sm_set_abort()
{
	char ds[3] = { '\r', '~', CNTRL('b') };
	char as[SM_MAX_ABSLEN];
	int len = SM_MAX_ABSLEN;

	if (ddi_prop_op(DDI_DEV_T_ANY, sm_ssp->sm_dip, PROP_LEN_AND_VAL_BUF, 0,
	    "abort-str", as, &len) != DDI_PROP_SUCCESS ||
	    (len = strlen(as)) < SM_MIN_ABSLEN) {
		(void) strcpy(as, ds);
		len = strlen(as);
	} else {
		char *s;
		int i;

		for (s = as, i = 0; i < len-1; i++, s++) {
			if (as[i] == '^' && as[i+1] >= 'a' && as[i+1] <= 'z') {
				*s = as[i+1] - 'a' + 1;
				i++;
			} else {
				*s = as[i];
			}
		}
		*s++ = as[i];
		*s = '\0';
		len = strlen(as);
	}

	if (len < SM_MIN_ABSLEN)
		(void) strcpy(sm_ssp->sm_abs, ds);
	else
		(void) strcpy(sm_ssp->sm_abs, as);
}

/*
 *
 * sm_attach - initialisation routine per driver instance.
 */
static int
sm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int unit;
	char name[32];
	sm_uqi_t *uqi;
	sm_lqi_t *lqip;

	/*
	 * Is this an attach?
	 */
	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	/*
	 * Validate the instance number (sm is a single instance driver).
	 */
	if (sm_ssp) {	/* only one instance allowed */
		return (DDI_FAILURE);
	}

	sm_instance = ddi_get_instance(dip);

	/*
	 * Create the default minor node which will become the console.
	 * (create it with three different names).:
	 *	con which appears in the /dev filesystem;
	 *	input which matches the prom /multiplexer:input node;
	 *	output which matches the prom /multiplexer:input node
	 * Create a minor node for control operations.
	 */
	if (ddi_create_minor_node(dip, "con", S_IFCHR, 0,
	    DDI_PSEUDO, 0) != DDI_SUCCESS ||
	    ddi_create_minor_node(dip, "input", S_IFCHR, 0,
	    DDI_PSEUDO, 0) != DDI_SUCCESS ||
	    ddi_create_minor_node(dip, "output", S_IFCHR, 0,
	    DDI_PSEUDO, 0) != DDI_SUCCESS ||
	    ddi_create_minor_node(dip, "ctl", S_IFCHR, 1,
	    DDI_PSEUDO, 0) != DDI_SUCCESS) {

		cmn_err(CE_WARN, "sm_attach: create minors failed.\n");
		ddi_remove_minor_node(dip, NULL);
		return (DDI_FAILURE);
	}

	smctlunit = 1;

	/*
	 * Allocate private state for this instance.
	 */
	sm_ssp = (sm_ss_t *)kmem_zalloc(sizeof (sm_ss_t), KM_SLEEP);

	/*
	 * Initialise per instance data.
	 */
	sm_ssp->sm_dip = dip;

	/*
	 * Get required debug level.
	 */
	sm_ssp->sm_trflag = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "sm-trlv", sm_default_trflag);

	sm_max_units = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "sm-max-units", sm_max_units);
	sm_minor_cnt = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "sm-minor-cnt", 0);

	sm_refuse_opens = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "sm-refuse-opens", sm_refuse_opens);

	sm_ssp->sm_ctrla_abort_on = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "sm-ctrla-abort-on", 1);
	sm_ssp->sm_break_abort_on = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "sm-break-abort-on", 0);

	sm_set_abort();

	sm_ssp->sm_lqs = (sm_lqi_t *)kmem_zalloc(sizeof (sm_lqi_t) * MAX_LQS,
	    KM_SLEEP);
	sm_ssp->sm_uqs = (sm_uqi_t *)kmem_zalloc(sizeof (sm_uqi_t) * NLUNITS,
	    KM_SLEEP);

	for (unit = 2; unit < NLUNITS && unit < sm_minor_cnt + 2; unit++) {

		if (snprintf(name, sizeof (name), "sm%c", 'a' + unit-2) >
		    sizeof (name)) {
			cmn_err(CE_WARN,
			    "sm_attach: create device for unit %d failed.\n",
			    unit);
		} else if (ddi_create_minor_node(dip, name, S_IFCHR,
		    unit, DDI_NT_SERIAL, NULL) != DDI_SUCCESS) {
			ddi_remove_minor_node(dip, NULL);
			return (DDI_FAILURE);
		}

		if (snprintf(name, sizeof (name), "sm%c,cu", 'a' + unit-2) >
		    sizeof (name)) {
			cmn_err(CE_WARN,
			    "sm_attach: create cu device for unit %d failed.\n",
			    unit);
			continue;
		} else if (ddi_create_minor_node(dip, name, S_IFCHR,
		    unit|OUTLINE, DDI_NT_SERIAL_DO, NULL) != DDI_SUCCESS) {
			ddi_remove_minor_node(dip, NULL);
			return (DDI_FAILURE);
		}
	}

	for (unit = 0; unit < NLUNITS; unit++) {

		uqi = get_uqi(sm_ssp, unit);
		uqi->sm_lqs = 0;
		uqi->sm_dev = NODEV;
		uqi->sm_nlqs = 0;
		uqi->sm_lunit = unit;
		uqi->sm_protocol = NULL_PROTOCOL;
		mutex_init(uqi->sm_umutex, NULL, MUTEX_DRIVER, NULL);
		cv_init(uqi->sm_ucv, NULL, CV_DRIVER, NULL);
		mutex_init(&uqi->sm_ttycommon->t_excl, NULL,
		    MUTEX_DRIVER, NULL);
	}

	for (unit = 0; unit < MAX_LQS; unit++) {
		lqip = get_lqi(sm_ssp, unit);
		lqip->sm_unit = unit;
		lqip->sm_hadkadbchar = 0;
		lqip->sm_nachar = sm_ssp->sm_abs;
		lqip->sm_ioflag = FORIO;
		lqip->sm_ctrla_abort_on = sm_ssp->sm_ctrla_abort_on;
		lqip->sm_break_abort_on = sm_ssp->sm_break_abort_on;
		mutex_init(lqip->sm_umutex, NULL, MUTEX_DRIVER, NULL);
		cv_init(lqip->sm_ucv, NULL, CV_DRIVER, NULL);
		mutex_init(&lqip->sm_ttycommon->t_excl, NULL,
		    MUTEX_DRIVER, NULL);
	}

	return (DDI_SUCCESS);
}

/*
 *
 * sm_detach - detach routine per driver instance.
 */
static int
sm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	sm_uqi_t		*lu;
	sm_lqi_t		*pu;
	int		unit;

	/*
	 * Is this a detach request for instance 0 (single instance driver).
	 */
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	if (sm_ssp == NULL)
		return (DDI_FAILURE);

	sm_dbg('V', ("detach ..."));


	/*
	 * Check that all the upper and lower queues are closed.
	 */

	for (unit = 0; unit < NLUNITS; unit++) {
		lu = &sm_ssp->sm_uqs[unit];
		if (lu && lu->sm_protocol != NULL_PROTOCOL) {
			sm_dbg('V', ("detach: upper unit still open.\n"));
			return (DDI_FAILURE);
		}
	}
	for (unit = 0; unit < MAX_LQS; unit++) {
		pu = &sm_ssp->sm_lqs[unit];
		if (pu && pu->sm_linkid != 0) {
			sm_dbg('V', ("detach: lower unit still linked (%d)\n",
			    pu->sm_linkid));
			return (DDI_FAILURE);
		}
	}

	for (unit = 0; unit < NLUNITS; unit++) {
		lu = &sm_ssp->sm_uqs[unit];
		mutex_destroy(lu->sm_umutex);
		cv_destroy(lu->sm_ucv);
		mutex_destroy(&lu->sm_ttycommon->t_excl);
	}
	for (unit = 0; unit < MAX_LQS; unit++) {
		pu = &sm_ssp->sm_lqs[unit];
		mutex_destroy(pu->sm_umutex);
		cv_destroy(pu->sm_ucv);
		mutex_destroy(&pu->sm_ttycommon->t_excl);
	}

	/*
	 * Tidy up per instance state.
	 */
	kmem_free(sm_ssp->sm_lqs, sizeof (sm_lqi_t) * MAX_LQS);
	kmem_free(sm_ssp->sm_uqs, sizeof (sm_uqi_t) * NLUNITS);
	kmem_free(sm_ssp, sizeof (sm_ss_t));

	sm_ssp = 0;

	/*
	 * Remove all of the devices created in attach.
	 */
	ddi_remove_minor_node(dip, NULL);

	return (DDI_SUCCESS);
}

/*
 * SECTION
 * Driver interface to the OS.
 */

/*
 * The driver is responsible for managing the mapping between the file system
 * device types (major/minor pairs) and the corresponding instance of the driver
 * or device information pointer (dip).
 * sm_info - return the instance or dip corresponding to the dev_t.
 */
/*ARGSUSED*/
static int
sm_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int res = DDI_SUCCESS;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (sm_ssp == NULL)
			res = DDI_FAILURE;
		else
			*result = (void *)sm_ssp->sm_dip;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void*)0;	/* single instance driver */
		break;

	default:
		res = DDI_FAILURE;
		break;
	}

	return (res);
}

/*
 * End of driver implementation
 */

/*
 * Loadable module interface to the kernel
 */

/*
 * Firstly the Streams specific interface
 */

/*
 * Solaris driver/STREAM initialisation structures.
 */
static struct module_info uinfo =
{
	SM_MOD_ID,
	TTYMUX_DRVNAME,
	0,		/* min packet size */
	INFPSZ,		/* max packet size */
	2048,		/* high water mark */
	256,		/* low water mark */
};

/*
 * Use zero water marks becuase the lower queues are used only for flow control.
 */
static struct module_info linfo =
{
	SM_MOD_ID,
	TTYMUX_DRVNAME,
	0,		/* min packet size */
	INFPSZ,		/* max packet size */
	0,		/* high water mark */
	0		/* low water mark	*/
};


/*
 * Solaris upper read STREAM initialisation structure.
 */
static struct qinit urinit =
{
	sm_urput,	/* put */
	sm_ursrv,	/* service */
	sm_open,	/* open */
	sm_close,	/* close */
	NULL,		/* admin */
	&uinfo,		/* module info */
	NULL		/* stats */
};

/*
 * Solaris upper write STREAM initialisation structure.
 */
static struct qinit uwinit =
{
	sm_uwput,
	sm_uwsrv,
	NULL,
	NULL,
	NULL,
	&uinfo,
	NULL
};

/*
 * Solaris lower read STREAM initialisation structure.
 */
static struct qinit lrinit =
{
	sm_lrput,
	sm_lrsrv,
	NULL,
	NULL, NULL,
	&linfo,
	NULL
};

/*
 * Solaris lower write STREAM initialisation structure.
 */
static struct qinit lwinit =
{
	putq,
	sm_lwsrv,
	NULL,
	NULL,
	NULL,
	&linfo,
	NULL
};

/*
 * Multiplexing STREAM structure.
 */
struct streamtab sm_streamtab =
{
	&urinit,
	&uwinit,
	&lrinit,
	&lwinit
};

/*
 * Driver operations structure (struct cb_ops) and
 * driver dynamic loading functions (struct dev_ops).
 */

/*
 * Fold the Stream interface to the kernel into the driver interface
 * to the OS.
 */

DDI_DEFINE_STREAM_OPS(sm_ops, \
	nulldev, nulldev, \
	sm_attach, sm_detach, nodev, \
	sm_info, (D_NEW | D_MTQPAIR|D_MTOUTPERIM|D_MTOCEXCL | D_MP),
	&sm_streamtab, ddi_quiesce_not_supported);

/*
 * Driver module information.
 */
extern struct mod_ops mod_driverops;
static struct modldrv modldrv =
{
	&mod_driverops,
	"serial mux driver",
	&sm_ops
};

static struct modlinkage modlinkage =
{
	MODREV_1,
	&modldrv,
	NULL
};

/*
 * Define the body of our interface to the OS.
 */

/*
 * '_init' is called by Solaris to initialise any driver
 * specific state and to install the driver.
 */
int
_init(void)
{
	return (mod_install(&modlinkage));
}

/*
 * _info - return this drivers interface to the kernel.
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * _fini - the OS is finished with the services provided by the driver.
 * remove ourself and then remove any footprint that remains.
 */
int
_fini(void)
{
	return (mod_remove(&modlinkage));
}
