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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * UNIX Device Driver Interface functions
 *
 * This file contains functions that are to be added to the kernel
 * to put the interface presented to drivers in conformance with
 * the DDI standard. Of the functions added to the kernel, 17 are
 * function equivalents of existing macros in sysmacros.h,
 * stream.h, and param.h
 *
 * 17 additional functions -- drv_getparm(), drv_setparm(),
 * getrbuf(), freerbuf(),
 * getemajor(), geteminor(), etoimajor(), itoemajor(), drv_usectohz(),
 * drv_hztousec(), drv_usecwait(), drv_priv(), and kvtoppid() --
 * are specified by DDI to exist in the kernel and are implemented here.
 *
 * Note that putnext() and put() are not in this file. The C version of
 * these routines are in uts/common/os/putnext.c and assembly versions
 * might exist for some architectures.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/t_lock.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/cpuvar.h>
#include <sys/signal.h>
#include <sys/pcb.h>
#include <sys/user.h>
#include <sys/errno.h>
#include <sys/buf.h>
#include <sys/proc.h>
#include <sys/cmn_err.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/uio.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/cred.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/poll.h>
#include <sys/session.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>
#include <sys/mkdev.h>
#include <sys/debug.h>
#include <sys/vtrace.h>

/*
 * return internal major number corresponding to device
 * number (new format) argument
 */
major_t
getmajor(dev_t dev)
{
#ifdef _LP64
	return ((major_t)((dev >> NBITSMINOR64) & MAXMAJ64));
#else
	return ((major_t)((dev >> NBITSMINOR) & MAXMAJ));
#endif
}

/*
 * return external major number corresponding to device
 * number (new format) argument
 */
major_t
getemajor(dev_t dev)
{
#ifdef _LP64
	return ((major_t)((dev >> NBITSMINOR64) & MAXMAJ64));
#else
	return ((major_t)((dev >> NBITSMINOR) & MAXMAJ));
#endif
}

/*
 * return internal minor number corresponding to device
 * number (new format) argument
 */
minor_t
getminor(dev_t dev)
{
#ifdef _LP64
	return ((minor_t)(dev & MAXMIN64));
#else
	return ((minor_t)(dev & MAXMIN));
#endif
}

/*
 * return external minor number corresponding to device
 * number (new format) argument
 */
minor_t
geteminor(dev_t dev)
{
#ifdef _LP64
	return ((minor_t)(dev & MAXMIN64));
#else
	return ((minor_t)(dev & MAXMIN));
#endif
}

/*
 * return internal major number corresponding to external
 * major number.
 */
int
etoimajor(major_t emajnum)
{
#ifdef _LP64
	if (emajnum >= devcnt)
		return (-1); /* invalid external major */
#else
	if (emajnum > MAXMAJ || emajnum >= devcnt)
		return (-1); /* invalid external major */
#endif
	return ((int)emajnum);
}

/*
 * return external major number corresponding to internal
 * major number argument or -1 if no external major number
 * can be found after lastemaj that maps to the internal
 * major number. Pass a lastemaj val of -1 to start
 * the search initially. (Typical use of this function is
 * of the form:
 *
 *	lastemaj = -1;
 *	while ((lastemaj = itoemajor(imag, lastemaj)) != -1)
 *		{ process major number }
 */
int
itoemajor(major_t imajnum, int lastemaj)
{
	if (imajnum >= devcnt)
		return (-1);

	/*
	 * if lastemaj == -1 then start from beginning of
	 * the (imaginary) MAJOR table
	 */
	if (lastemaj < -1)
		return (-1);

	/*
	 * given that there's a 1-1 mapping of internal to external
	 * major numbers, searching is somewhat pointless ... let's
	 * just go there directly.
	 */
	if (++lastemaj < devcnt && imajnum < devcnt)
		return (imajnum);
	return (-1);
}

/*
 * encode external major and minor number arguments into a
 * new format device number
 */
dev_t
makedevice(major_t maj, minor_t minor)
{
#ifdef _LP64
	return (((dev_t)maj << NBITSMINOR64) | (minor & MAXMIN64));
#else
	return (((dev_t)maj << NBITSMINOR) | (minor & MAXMIN));
#endif
}

/*
 * cmpdev - compress new device format to old device format
 */
o_dev_t
cmpdev(dev_t dev)
{
	major_t major_d;
	minor_t minor_d;

#ifdef _LP64
	major_d = dev >> NBITSMINOR64;
	minor_d = dev & MAXMIN64;
#else
	major_d = dev >> NBITSMINOR;
	minor_d = dev & MAXMIN;
#endif
	if (major_d > OMAXMAJ || minor_d > OMAXMIN)
		return ((o_dev_t)NODEV);
	return ((o_dev_t)((major_d << ONBITSMINOR) | minor_d));
}

dev_t
expdev(dev_t dev)
{
	major_t major_d;
	minor_t minor_d;

	major_d = ((dev >> ONBITSMINOR) & OMAXMAJ);
	minor_d = (dev & OMAXMIN);
#ifdef _LP64
	return ((((dev_t)major_d << NBITSMINOR64) | minor_d));
#else
	return ((((dev_t)major_d << NBITSMINOR) | minor_d));
#endif
}

/*
 * return true (1) if the message type input is a data
 * message type, 0 otherwise
 */
#undef datamsg
int
datamsg(unsigned char db_type)
{
	return (db_type == M_DATA || db_type == M_PROTO ||
	    db_type == M_PCPROTO || db_type == M_DELAY);
}

/*
 * return a pointer to the other queue in the queue pair of qp
 */
queue_t *
OTHERQ(queue_t *q)
{
	return (_OTHERQ(q));
}

/*
 * return a pointer to the read queue in the queue pair of qp.
 */
queue_t *
RD(queue_t *q)
{
		return (_RD(q));

}

/*
 * return a pointer to the write queue in the queue pair of qp.
 */
int
SAMESTR(queue_t *q)
{
	return (_SAMESTR(q));
}

/*
 * return a pointer to the write queue in the queue pair of qp.
 */
queue_t *
WR(queue_t *q)
{
	return (_WR(q));
}

/*
 * store value of kernel parameter associated with parm
 */
int
drv_getparm(unsigned int parm, void *valuep)
{
	proc_t	*p = curproc;
	time_t	now;

	switch (parm) {
	case UPROCP:
		*(proc_t **)valuep = p;
		break;
	case PPGRP:
		mutex_enter(&p->p_lock);
		*(pid_t *)valuep = p->p_pgrp;
		mutex_exit(&p->p_lock);
		break;
	case LBOLT:
		*(clock_t *)valuep = ddi_get_lbolt();
		break;
	case TIME:
		if ((now = gethrestime_sec()) == 0) {
			timestruc_t ts;
			mutex_enter(&tod_lock);
			ts = tod_get();
			mutex_exit(&tod_lock);
			*(time_t *)valuep = ts.tv_sec;
		} else {
			*(time_t *)valuep = now;
		}
		break;
	case PPID:
		*(pid_t *)valuep = p->p_pid;
		break;
	case PSID:
		mutex_enter(&p->p_splock);
		*(pid_t *)valuep = p->p_sessp->s_sid;
		mutex_exit(&p->p_splock);
		break;
	case UCRED:
		*(cred_t **)valuep = CRED();
		break;
	default:
		return (-1);
	}

	return (0);
}

/*
 * set value of kernel parameter associated with parm
 */
int
drv_setparm(unsigned int parm, unsigned long value)
{
	switch (parm) {
	case SYSRINT:
		CPU_STATS_ADDQ(CPU, sys, rcvint, value);
		break;
	case SYSXINT:
		CPU_STATS_ADDQ(CPU, sys, xmtint, value);
		break;
	case SYSMINT:
		CPU_STATS_ADDQ(CPU, sys, mdmint, value);
		break;
	case SYSRAWC:
		CPU_STATS_ADDQ(CPU, sys, rawch, value);
		break;
	case SYSCANC:
		CPU_STATS_ADDQ(CPU, sys, canch, value);
		break;
	case SYSOUTC:
		CPU_STATS_ADDQ(CPU, sys, outch, value);
		break;
	default:
		return (-1);
	}

	return (0);
}

/*
 * allocate space for buffer header and return pointer to it.
 * preferred means of obtaining space for a local buf header.
 * returns pointer to buf upon success, NULL for failure
 */
struct buf *
getrbuf(int sleep)
{
	struct buf *bp;

	bp = kmem_alloc(sizeof (struct buf), sleep);
	if (bp == NULL)
		return (NULL);
	bioinit(bp);

	return (bp);
}

/*
 * free up space allocated by getrbuf()
 */
void
freerbuf(struct buf *bp)
{
	biofini(bp);
	kmem_free(bp, sizeof (struct buf));
}

/*
 * convert byte count input to logical page units
 * (byte counts that are not a page-size multiple
 * are rounded down)
 */
pgcnt_t
btop(size_t numbytes)
{
	return (numbytes >> PAGESHIFT);
}

/*
 * convert byte count input to logical page units
 * (byte counts that are not a page-size multiple
 * are rounded up)
 */
pgcnt_t
btopr(size_t numbytes)
{
	return ((numbytes + PAGEOFFSET) >> PAGESHIFT);
}

/*
 * convert size in pages to bytes.
 */
size_t
ptob(pgcnt_t numpages)
{
	return (numpages << PAGESHIFT);
}

#define	MAXCLOCK_T LONG_MAX

/*
 * Convert from system time units (hz) to microseconds.
 *
 * If ticks <= 0, return 0.
 * If converting ticks to usecs would overflow, return MAXCLOCK_T.
 * Otherwise, convert ticks to microseconds.
 */
clock_t
drv_hztousec(clock_t ticks)
{
	if (ticks <= 0)
		return (0);

	if (ticks > MAXCLOCK_T / usec_per_tick)
		return (MAXCLOCK_T);

	return (TICK_TO_USEC(ticks));
}


/*
 * Convert from microseconds to system time units (hz), rounded up.
 *
 * If ticks <= 0, return 0.
 * Otherwise, convert microseconds to ticks, rounding up.
 */
clock_t
drv_usectohz(clock_t microsecs)
{
	if (microsecs <= 0)
		return (0);

	return (USEC_TO_TICK_ROUNDUP(microsecs));
}

#ifdef	sun
/*
 * drv_usecwait implemented in each architecture's machine
 * specific code somewhere. For sparc, it is the alternate entry
 * to usec_delay (eventually usec_delay goes away). See
 * sparc/os/ml/sparc_subr.s
 */
#endif

/*
 * bcanputnext, canputnext assume called from timeout, bufcall,
 * or esballoc free routines.  since these are driven by
 * clock interrupts, instead of system calls the appropriate plumbing
 * locks have not been acquired.
 */
int
bcanputnext(queue_t *q, unsigned char band)
{
	int	ret;

	claimstr(q);
	ret = bcanput(q->q_next, band);
	releasestr(q);
	return (ret);
}

int
canputnext(queue_t *q)
{
	queue_t	*qofsq = q;
	struct stdata *stp = STREAM(q);
	kmutex_t *sdlock;

	TRACE_1(TR_FAC_STREAMS_FR, TR_CANPUTNEXT_IN,
	    "canputnext?:%p\n", q);

	if (stp->sd_ciputctrl != NULL) {
		int ix = CPU->cpu_seqid & stp->sd_nciputctrl;
		sdlock = &stp->sd_ciputctrl[ix].ciputctrl_lock;
		mutex_enter(sdlock);
	} else
		mutex_enter(sdlock = &stp->sd_reflock);

	/* get next module forward with a service queue */
	q = q->q_next->q_nfsrv;
	ASSERT(q != NULL);

	/* this is for loopback transports, they should not do a canputnext */
	ASSERT(STRMATED(q->q_stream) || STREAM(q) == STREAM(qofsq));

	if (!(q->q_flag & QFULL)) {
		mutex_exit(sdlock);
		TRACE_2(TR_FAC_STREAMS_FR, TR_CANPUTNEXT_OUT,
		    "canputnext:%p %d", q, 1);
		return (1);
	}

	if (sdlock != &stp->sd_reflock) {
		mutex_exit(sdlock);
		mutex_enter(&stp->sd_reflock);
	}

	/* the above is the most frequently used path */
	stp->sd_refcnt++;
	ASSERT(stp->sd_refcnt != 0);	/* Wraparound */
	mutex_exit(&stp->sd_reflock);

	mutex_enter(QLOCK(q));
	if (q->q_flag & QFULL) {
		q->q_flag |= QWANTW;
		mutex_exit(QLOCK(q));
		TRACE_2(TR_FAC_STREAMS_FR, TR_CANPUTNEXT_OUT,
		    "canputnext:%p %d", q, 0);
		releasestr(qofsq);

		return (0);
	}
	mutex_exit(QLOCK(q));
	TRACE_2(TR_FAC_STREAMS_FR, TR_CANPUTNEXT_OUT, "canputnext:%p %d", q, 1);
	releasestr(qofsq);

	return (1);
}


/*
 * Open has progressed to the point where it is safe to send/receive messages.
 *
 * "qprocson enables the put and service routines of the driver
 * or module... Prior to the call to qprocson, the put and service
 * routines of a newly pushed module or newly opened driver are
 * disabled.  For the module, messages flow around it as if it
 * were not present in the stream... qprocson must be called by
 * the first open of a module or driver after allocation and
 * initialization of any resource on which the put and service
 * routines depend."
 *
 * Note that before calling qprocson a module/driver could itself cause its
 * put or service procedures to be run by using put() or qenable().
 */
void
qprocson(queue_t *q)
{
	ASSERT(q->q_flag & QREADR);
	/*
	 * Do not call insertq() if it is a re-open.  But if _QINSERTING
	 * is set, q_next will not be NULL and we need to call insertq().
	 */
	if ((q->q_next == NULL && WR(q)->q_next == NULL) ||
	    (q->q_flag & _QINSERTING))
		insertq(STREAM(q), q);
}

/*
 * Close has reached a point where it can no longer allow put/service
 * into the queue.
 *
 * "qprocsoff disables the put and service routines of the driver
 * or module... When the routines are disabled in a module, messages
 * flow around the module as if it were not present in the stream.
 * qprocsoff must be called by the close routine of a driver or module
 * before deallocating any resources on which the driver/module's
 * put and service routines depend.  qprocsoff will remove the
 * queue's service routines from the list of service routines to be
 * run and waits until any concurrent put or service routines are
 * finished."
 *
 * Note that after calling qprocsoff a module/driver could itself cause its
 * put procedures to be run by using put().
 */
void
qprocsoff(queue_t *q)
{
	ASSERT(q->q_flag & QREADR);
	if (q->q_flag & QWCLOSE) {
		/* Called more than once */
		return;
	}
	disable_svc(q);
	removeq(q);
}

/*
 * "freezestr() freezes the state of the entire STREAM  containing
 *  the  queue  pair  q.  A frozen STREAM blocks any thread
 *  attempting to enter any open, close, put or service  routine
 *  belonging  to  any  queue instance in the STREAM, and blocks
 *  any thread currently within the STREAM if it attempts to put
 *  messages  onto  or take messages off of any queue within the
 *  STREAM (with the sole exception  of  the  caller).   Threads
 *  blocked  by  this  mechanism  remain  so until the STREAM is
 *  thawed by a call to unfreezestr().
 *
 * Use strblock to set SQ_FROZEN in all syncqs in the stream (prevents
 * further entry into put, service, open, and close procedures) and
 * grab (and hold) all the QLOCKs in the stream (to block putq, getq etc.)
 *
 * Note: this has to be the only code that acquires one QLOCK while holding
 * another QLOCK (otherwise we would have locking hirarchy/ordering violations.)
 */
void
freezestr(queue_t *q)
{
	struct stdata *stp = STREAM(q);

	/*
	 * Increment refcnt to prevent q_next from changing during the strblock
	 * as well as while the stream is frozen.
	 */
	claimstr(RD(q));

	strblock(q);
	ASSERT(stp->sd_freezer == NULL);
	stp->sd_freezer = curthread;
	for (q = stp->sd_wrq; q != NULL; q = SAMESTR(q) ? q->q_next : NULL) {
		mutex_enter(QLOCK(q));
		mutex_enter(QLOCK(RD(q)));
	}
}

/*
 * Undo what freezestr did.
 * Have to drop the QLOCKs before the strunblock since strunblock will
 * potentially call other put procedures.
 */
void
unfreezestr(queue_t *q)
{
	struct stdata *stp = STREAM(q);
	queue_t	*q1;

	for (q1 = stp->sd_wrq; q1 != NULL;
	    q1 = SAMESTR(q1) ? q1->q_next : NULL) {
		mutex_exit(QLOCK(q1));
		mutex_exit(QLOCK(RD(q1)));
	}
	ASSERT(stp->sd_freezer == curthread);
	stp->sd_freezer = NULL;
	strunblock(q);
	releasestr(RD(q));
}

/*
 * Used by open and close procedures to "sleep" waiting for messages to
 * arrive. Note: can only be used in open and close procedures.
 *
 * Lower the gate and let in either messages on the syncq (if there are
 * any) or put/service procedures.
 *
 * If the queue has an outer perimeter this will not prevent entry into this
 * syncq (since outer_enter does not set SQ_WRITER on the syncq that gets the
 * exclusive access to the outer perimeter.)
 *
 * Return 0 is the cv_wait_sig was interrupted; otherwise 1.
 *
 * It only makes sense to grab sq_putlocks for !SQ_CIOC sync queues because
 * otherwise put entry points were not blocked in the first place. if this is
 * SQ_CIOC then qwait is used to wait for service procedure to run since syncq
 * is always SQ_CIPUT if it is SQ_CIOC.
 *
 * Note that SQ_EXCL is dropped and SQ_WANTEXITWAKEUP set in sq_flags
 * atomically under sq_putlocks to make sure putnext will not miss a pending
 * wakeup.
 */
int
qwait_sig(queue_t *q)
{
	syncq_t		*sq, *outer;
	uint_t		flags;
	int		ret = 1;
	int		is_sq_cioc;

	/*
	 * Perform the same operations as a leavesq(sq, SQ_OPENCLOSE)
	 * while detecting all cases where the perimeter is entered
	 * so that qwait_sig can return to the caller.
	 *
	 * Drain the syncq if possible. Otherwise reset SQ_EXCL and
	 * wait for a thread to leave the syncq.
	 */
	sq = q->q_syncq;
	ASSERT(sq);
	is_sq_cioc = (sq->sq_type & SQ_CIOC) ? 1 : 0;
	ASSERT(sq->sq_outer == NULL || sq->sq_outer->sq_flags & SQ_WRITER);
	outer = sq->sq_outer;
	/*
	 * XXX this does not work if there is only an outer perimeter.
	 * The semantics of qwait/qwait_sig are undefined in this case.
	 */
	if (outer)
		outer_exit(outer);

	mutex_enter(SQLOCK(sq));
	if (is_sq_cioc == 0) {
		SQ_PUTLOCKS_ENTER(sq);
	}
	flags = sq->sq_flags;
	/*
	 * Drop SQ_EXCL and sq_count but hold the SQLOCK
	 * to prevent any undetected entry and exit into the perimeter.
	 */
	ASSERT(sq->sq_count > 0);
	sq->sq_count--;

	if (is_sq_cioc == 0) {
		ASSERT(flags & SQ_EXCL);
		flags &= ~SQ_EXCL;
	}
	/*
	 * Unblock any thread blocked in an entersq or outer_enter.
	 * Note: we do not unblock a thread waiting in qwait/qwait_sig,
	 * since that could lead to livelock with two threads in
	 * qwait for the same (per module) inner perimeter.
	 */
	if (flags & SQ_WANTWAKEUP) {
		cv_broadcast(&sq->sq_wait);
		flags &= ~SQ_WANTWAKEUP;
	}
	sq->sq_flags = flags;
	if ((flags & SQ_QUEUED) && !(flags & SQ_STAYAWAY)) {
		if (is_sq_cioc == 0) {
			SQ_PUTLOCKS_EXIT(sq);
		}
		/* drain_syncq() drops SQLOCK */
		drain_syncq(sq);
		ASSERT(MUTEX_NOT_HELD(SQLOCK(sq)));
		entersq(sq, SQ_OPENCLOSE);
		return (1);
	}
	/*
	 * Sleep on sq_exitwait to only be woken up when threads leave the
	 * put or service procedures. We can not sleep on sq_wait since an
	 * outer_exit in a qwait running in the same outer perimeter would
	 * cause a livelock "ping-pong" between two or more qwait'ers.
	 */
	do {
		sq->sq_flags |= SQ_WANTEXWAKEUP;
		if (is_sq_cioc == 0) {
			SQ_PUTLOCKS_EXIT(sq);
		}
		ret = cv_wait_sig(&sq->sq_exitwait, SQLOCK(sq));
		if (is_sq_cioc == 0) {
			SQ_PUTLOCKS_ENTER(sq);
		}
	} while (ret && (sq->sq_flags & SQ_WANTEXWAKEUP));
	if (is_sq_cioc == 0) {
		SQ_PUTLOCKS_EXIT(sq);
	}
	mutex_exit(SQLOCK(sq));

	/*
	 * Re-enter the perimeters again
	 */
	entersq(sq, SQ_OPENCLOSE);
	return (ret);
}

/*
 * Used by open and close procedures to "sleep" waiting for messages to
 * arrive. Note: can only be used in open and close procedures.
 *
 * Lower the gate and let in either messages on the syncq (if there are
 * any) or put/service procedures.
 *
 * If the queue has an outer perimeter this will not prevent entry into this
 * syncq (since outer_enter does not set SQ_WRITER on the syncq that gets the
 * exclusive access to the outer perimeter.)
 *
 * It only makes sense to grab sq_putlocks for !SQ_CIOC sync queues because
 * otherwise put entry points were not blocked in the first place. if this is
 * SQ_CIOC then qwait is used to wait for service procedure to run since syncq
 * is always SQ_CIPUT if it is SQ_CIOC.
 *
 * Note that SQ_EXCL is dropped and SQ_WANTEXITWAKEUP set in sq_flags
 * atomically under sq_putlocks to make sure putnext will not miss a pending
 * wakeup.
 */
void
qwait(queue_t *q)
{
	syncq_t		*sq, *outer;
	uint_t		flags;
	int		is_sq_cioc;

	/*
	 * Perform the same operations as a leavesq(sq, SQ_OPENCLOSE)
	 * while detecting all cases where the perimeter is entered
	 * so that qwait can return to the caller.
	 *
	 * Drain the syncq if possible. Otherwise reset SQ_EXCL and
	 * wait for a thread to leave the syncq.
	 */
	sq = q->q_syncq;
	ASSERT(sq);
	is_sq_cioc = (sq->sq_type & SQ_CIOC) ? 1 : 0;
	ASSERT(sq->sq_outer == NULL || sq->sq_outer->sq_flags & SQ_WRITER);
	outer = sq->sq_outer;
	/*
	 * XXX this does not work if there is only an outer perimeter.
	 * The semantics of qwait/qwait_sig are undefined in this case.
	 */
	if (outer)
		outer_exit(outer);

	mutex_enter(SQLOCK(sq));
	if (is_sq_cioc == 0) {
		SQ_PUTLOCKS_ENTER(sq);
	}
	flags = sq->sq_flags;
	/*
	 * Drop SQ_EXCL and sq_count but hold the SQLOCK
	 * to prevent any undetected entry and exit into the perimeter.
	 */
	ASSERT(sq->sq_count > 0);
	sq->sq_count--;

	if (is_sq_cioc == 0) {
		ASSERT(flags & SQ_EXCL);
		flags &= ~SQ_EXCL;
	}
	/*
	 * Unblock any thread blocked in an entersq or outer_enter.
	 * Note: we do not unblock a thread waiting in qwait/qwait_sig,
	 * since that could lead to livelock with two threads in
	 * qwait for the same (per module) inner perimeter.
	 */
	if (flags & SQ_WANTWAKEUP) {
		cv_broadcast(&sq->sq_wait);
		flags &= ~SQ_WANTWAKEUP;
	}
	sq->sq_flags = flags;
	if ((flags & SQ_QUEUED) && !(flags & SQ_STAYAWAY)) {
		if (is_sq_cioc == 0) {
			SQ_PUTLOCKS_EXIT(sq);
		}
		/* drain_syncq() drops SQLOCK */
		drain_syncq(sq);
		ASSERT(MUTEX_NOT_HELD(SQLOCK(sq)));
		entersq(sq, SQ_OPENCLOSE);
		return;
	}
	/*
	 * Sleep on sq_exitwait to only be woken up when threads leave the
	 * put or service procedures. We can not sleep on sq_wait since an
	 * outer_exit in a qwait running in the same outer perimeter would
	 * cause a livelock "ping-pong" between two or more qwait'ers.
	 */
	do {
		sq->sq_flags |= SQ_WANTEXWAKEUP;
		if (is_sq_cioc == 0) {
			SQ_PUTLOCKS_EXIT(sq);
		}
		cv_wait(&sq->sq_exitwait, SQLOCK(sq));
		if (is_sq_cioc == 0) {
			SQ_PUTLOCKS_ENTER(sq);
		}
	} while (sq->sq_flags & SQ_WANTEXWAKEUP);
	if (is_sq_cioc == 0) {
		SQ_PUTLOCKS_EXIT(sq);
	}
	mutex_exit(SQLOCK(sq));

	/*
	 * Re-enter the perimeters again
	 */
	entersq(sq, SQ_OPENCLOSE);
}

/*
 * Used for the synchronous streams entrypoints when sleeping outside
 * the perimeters. Must never be called from regular put entrypoint.
 *
 * There's no need to grab sq_putlocks here (which only exist for CIPUT sync
 * queues). If it is CIPUT sync queue put entry points were not blocked in the
 * first place by rwnext/infonext which are treated as put entrypoints for
 * permiter syncronization purposes.
 *
 * Consolidation private.
 */
boolean_t
qwait_rw(queue_t *q)
{
	syncq_t		*sq;
	ulong_t		flags;
	boolean_t	gotsignal = B_FALSE;

	/*
	 * Perform the same operations as a leavesq(sq, SQ_PUT)
	 * while detecting all cases where the perimeter is entered
	 * so that qwait_rw can return to the caller.
	 *
	 * Drain the syncq if possible. Otherwise reset SQ_EXCL and
	 * wait for a thread to leave the syncq.
	 */
	sq = q->q_syncq;
	ASSERT(sq);

	mutex_enter(SQLOCK(sq));
	flags = sq->sq_flags;
	/*
	 * Drop SQ_EXCL and sq_count but hold the SQLOCK until to prevent any
	 * undetected entry and exit into the perimeter.
	 */
	ASSERT(sq->sq_count > 0);
	sq->sq_count--;
	if (!(sq->sq_type & SQ_CIPUT)) {
		ASSERT(flags & SQ_EXCL);
		flags &= ~SQ_EXCL;
	}
	/*
	 * Unblock any thread blocked in an entersq or outer_enter.
	 * Note: we do not unblock a thread waiting in qwait/qwait_sig,
	 * since that could lead to livelock with two threads in
	 * qwait for the same (per module) inner perimeter.
	 */
	if (flags & SQ_WANTWAKEUP) {
		cv_broadcast(&sq->sq_wait);
		flags &= ~SQ_WANTWAKEUP;
	}
	sq->sq_flags = flags;
	if ((flags & SQ_QUEUED) && !(flags & SQ_STAYAWAY)) {
		/* drain_syncq() drops SQLOCK */
		drain_syncq(sq);
		ASSERT(MUTEX_NOT_HELD(SQLOCK(sq)));
		entersq(sq, SQ_PUT);
		return (B_FALSE);
	}
	/*
	 * Sleep on sq_exitwait to only be woken up when threads leave the
	 * put or service procedures. We can not sleep on sq_wait since an
	 * outer_exit in a qwait running in the same outer perimeter would
	 * cause a livelock "ping-pong" between two or more qwait'ers.
	 */
	do {
		sq->sq_flags |= SQ_WANTEXWAKEUP;
		if (cv_wait_sig(&sq->sq_exitwait, SQLOCK(sq)) <= 0) {
			sq->sq_flags &= ~SQ_WANTEXWAKEUP;
			gotsignal = B_TRUE;
			break;
		}
	} while (sq->sq_flags & SQ_WANTEXWAKEUP);
	mutex_exit(SQLOCK(sq));

	/*
	 * Re-enter the perimeters again
	 */
	entersq(sq, SQ_PUT);
	return (gotsignal);
}

/*
 * Asynchronously upgrade to exclusive access at either the inner or
 * outer perimeter.
 */
void
qwriter(queue_t *q, mblk_t *mp, void (*func)(), int perim)
{
	if (perim == PERIM_INNER)
		qwriter_inner(q, mp, func);
	else if (perim == PERIM_OUTER)
		qwriter_outer(q, mp, func);
	else
		panic("qwriter: wrong \"perimeter\" parameter");
}

/*
 * Schedule a synchronous streams timeout
 */
timeout_id_t
qtimeout(queue_t *q, void (*func)(void *), void *arg, clock_t tim)
{
	syncq_t		*sq;
	callbparams_t	*cbp;
	timeout_id_t	tid;

	sq = q->q_syncq;
	/*
	 * you don't want the timeout firing before its params are set up
	 * callbparams_alloc() acquires SQLOCK(sq)
	 * qtimeout() can't fail and can't sleep, so panic if memory is not
	 * available.
	 */
	cbp = callbparams_alloc(sq, func, arg, KM_NOSLEEP | KM_PANIC);
	/*
	 * the callbflags in the sq use the same flags. They get anded
	 * in the callbwrapper to determine if a qun* of this callback type
	 * is required. This is not a request to cancel.
	 */
	cbp->cbp_flags = SQ_CANCEL_TOUT;
	/* check new timeout version return codes */
	tid = timeout(qcallbwrapper, cbp, tim);
	cbp->cbp_id = (callbparams_id_t)tid;
	mutex_exit(SQLOCK(sq));
	/* use local id because the cbp memory could be free by now */
	return (tid);
}

bufcall_id_t
qbufcall(queue_t *q, size_t size, uint_t pri, void (*func)(void *), void *arg)
{
	syncq_t		*sq;
	callbparams_t	*cbp;
	bufcall_id_t	bid;

	sq = q->q_syncq;
	/*
	 * you don't want the timeout firing before its params are set up
	 * callbparams_alloc() acquires SQLOCK(sq) if successful.
	 */
	cbp = callbparams_alloc(sq, func, arg, KM_NOSLEEP);
	if (cbp == NULL)
		return ((bufcall_id_t)0);

	/*
	 * the callbflags in the sq use the same flags. They get anded
	 * in the callbwrapper to determine if a qun* of this callback type
	 * is required. This is not a request to cancel.
	 */
	cbp->cbp_flags = SQ_CANCEL_BUFCALL;
	/* check new timeout version return codes */
	bid = bufcall(size, pri, qcallbwrapper, cbp);
	cbp->cbp_id = (callbparams_id_t)bid;
	if (bid == 0) {
		callbparams_free(sq, cbp);
	}
	mutex_exit(SQLOCK(sq));
	/* use local id because the params memory could be free by now */
	return (bid);
}

/*
 * cancel a timeout callback which enters the inner perimeter.
 * cancelling of all callback types on a given syncq is serialized.
 * the SQ_CALLB_BYPASSED flag indicates that the callback fn did
 * not execute. The quntimeout return value needs to reflect this.
 * As with out existing callback programming model - callbacks must
 * be cancelled before a close completes - so ensuring that the sq
 * is valid when the callback wrapper is executed.
 */
clock_t
quntimeout(queue_t *q, timeout_id_t id)
{
	syncq_t *sq = q->q_syncq;
	clock_t ret;

	mutex_enter(SQLOCK(sq));
	/* callbacks are processed serially on each syncq */
	while (sq->sq_callbflags & SQ_CALLB_CANCEL_MASK) {
		sq->sq_flags |= SQ_WANTWAKEUP;
		cv_wait(&sq->sq_wait, SQLOCK(sq));
	}
	sq->sq_cancelid = (callbparams_id_t)id;
	sq->sq_callbflags = SQ_CANCEL_TOUT;
	if (sq->sq_flags & SQ_WANTWAKEUP) {
		cv_broadcast(&sq->sq_wait);
		sq->sq_flags &= ~SQ_WANTWAKEUP;
	}
	mutex_exit(SQLOCK(sq));
	ret = untimeout(id);
	mutex_enter(SQLOCK(sq));
	if (ret != -1) {
		/* The wrapper was never called - need to free based on id */
		callbparams_free_id(sq, (callbparams_id_t)id, SQ_CANCEL_TOUT);
	}
	if (sq->sq_callbflags & SQ_CALLB_BYPASSED) {
		ret = 0;	/* this was how much time left */
	}
	sq->sq_callbflags = 0;
	if (sq->sq_flags & SQ_WANTWAKEUP) {
		cv_broadcast(&sq->sq_wait);
		sq->sq_flags &= ~SQ_WANTWAKEUP;
	}
	mutex_exit(SQLOCK(sq));
	return (ret);
}


void
qunbufcall(queue_t *q, bufcall_id_t id)
{
	syncq_t *sq = q->q_syncq;

	mutex_enter(SQLOCK(sq));
	/* callbacks are processed serially on each syncq */
	while (sq->sq_callbflags & SQ_CALLB_CANCEL_MASK) {
		sq->sq_flags |= SQ_WANTWAKEUP;
		cv_wait(&sq->sq_wait, SQLOCK(sq));
	}
	sq->sq_cancelid = (callbparams_id_t)id;
	sq->sq_callbflags = SQ_CANCEL_BUFCALL;
	if (sq->sq_flags & SQ_WANTWAKEUP) {
		cv_broadcast(&sq->sq_wait);
		sq->sq_flags &= ~SQ_WANTWAKEUP;
	}
	mutex_exit(SQLOCK(sq));
	unbufcall(id);
	mutex_enter(SQLOCK(sq));
	/*
	 * No indication from unbufcall if the callback has already run.
	 * Always attempt to free it.
	 */
	callbparams_free_id(sq, (callbparams_id_t)id, SQ_CANCEL_BUFCALL);
	sq->sq_callbflags = 0;
	if (sq->sq_flags & SQ_WANTWAKEUP) {
		cv_broadcast(&sq->sq_wait);
		sq->sq_flags &= ~SQ_WANTWAKEUP;
	}
	mutex_exit(SQLOCK(sq));
}

/*
 * Associate the stream with an instance of the bottom driver.  This
 * function is called by APIs that establish or modify the hardware
 * association (ppa) of an open stream.  Two examples of such
 * post-open(9E) APIs are the dlpi(4P) DL_ATTACH_REQ message, and the
 * ndd(8) "instance=" ioctl(2).  This interface may be called from a
 * stream driver's wput procedure and from within syncq perimeters,
 * so it can't block.
 *
 * The qassociate() "model" is that it should drive attach(9E), yet it
 * can't really do that because driving attach(9E) is a blocking
 * operation.  Instead, the qassociate() implementation has complex
 * dependencies on the implementation behavior of other parts of the
 * kernel to ensure all appropriate instances (ones that have not been
 * made inaccessible by DR) are attached at stream open() time, and
 * that they will not autodetach.  The code relies on the fact that an
 * open() of a stream that ends up using qassociate() always occurs on
 * a minor node created with CLONE_DEV.  The open() comes through
 * clnopen() and since clnopen() calls ddi_hold_installed_driver() we
 * attach all instances and mark them DN_NO_AUTODETACH (given
 * DN_DRIVER_HELD is maintained correctly).
 *
 * Since qassociate() can't really drive attach(9E), there are corner
 * cases where the compromise described above leads to qassociate()
 * returning failure.  This can happen when administrative functions
 * that cause detach(9E), such as "update_drv" or "modunload -i", are
 * performed on the driver between the time the stream was opened and
 * the time its hardware association was established.  Although this can
 * theoretically be an arbitrary amount of time, in practice the window
 * is usually quite small, since applications almost always issue their
 * hardware association request immediately after opening the stream,
 * and do not typically switch association while open.  When these
 * corner cases occur, and qassociate() finds the requested instance
 * detached, it will return failure.  This failure should be propagated
 * to the requesting administrative application using the appropriate
 * post-open(9E) API error mechanism.
 *
 * All qassociate() callers are expected to check for and gracefully handle
 * failure return, propagating errors back to the requesting administrative
 * application.
 */
int
qassociate(queue_t *q, int instance)
{
	vnode_t *vp;
	major_t major;
	dev_info_t *dip;

	if (instance == -1) {
		ddi_assoc_queue_with_devi(q, NULL);
		return (0);
	}

	vp = STREAM(q)->sd_vnode;
	major = getmajor(vp->v_rdev);
	dip = ddi_hold_devi_by_instance(major, instance,
	    E_DDI_HOLD_DEVI_NOATTACH);
	if (dip == NULL)
		return (-1);

	ddi_assoc_queue_with_devi(q, dip);
	ddi_release_devi(dip);
	return (0);
}

/*
 * This routine is the SVR4MP 'replacement' for
 * hat_getkpfnum.  The only major difference is
 * the return value for illegal addresses - since
 * sunm_getkpfnum() and srmmu_getkpfnum() both
 * return '-1' for bogus mappings, we can (more or
 * less) return the value directly.
 */
ppid_t
kvtoppid(caddr_t addr)
{
	return ((ppid_t)hat_getpfnum(kas.a_hat, addr));
}

/*
 * This is used to set the timeout value for cv_timed_wait() or
 * cv_timedwait_sig().
 */
void
time_to_wait(clock_t *now, clock_t time)
{
	*now = ddi_get_lbolt() + time;
}
