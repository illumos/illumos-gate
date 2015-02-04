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
 * Copyright (c) 2013 Gary Mills
 * Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2015, Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/varargs.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/log.h>
#include <sys/spl.h>
#include <sys/syslog.h>
#include <sys/console.h>
#include <sys/debug.h>
#include <sys/utsname.h>
#include <sys/id_space.h>
#include <sys/zone.h>

log_zone_t log_global;
queue_t *log_consq;
queue_t *log_backlogq;
queue_t *log_intrq;

#define	LOG_PRISIZE	8	/* max priority size: 7 characters + null */
#define	LOG_FACSIZE	9	/* max priority size: 8 characters + null */

static krwlock_t log_rwlock;
static int log_rwlock_depth;
static int log_seq_no[SL_CONSOLE + 1];
static stdata_t log_fakestr;
static id_space_t *log_minorspace;
static log_t log_backlog;
static struct kmem_cache *log_cons_cache;	/* log_t cache */

static queue_t *log_recentq;
static queue_t *log_freeq;

static zone_key_t log_zone_key;

static char log_overflow_msg[] = "message overflow on /dev/log minor #%d%s\n";

static char log_pri[LOG_PRIMASK + 1][LOG_PRISIZE] = {
	"emerg",	"alert",	"crit",		"error",
	"warning",	"notice",	"info",		"debug"
};

static char log_fac[LOG_NFACILITIES + 1][LOG_FACSIZE] = {
	"kern",		"user",		"mail",		"daemon",
	"auth",		"syslog",	"lpr",		"news",
	"uucp",		"altcron",	"authpriv",	"ftp",
	"ntp",		"audit",	"console",	"cron",
	"local0",	"local1",	"local2",	"local3",
	"local4",	"local5",	"local6",	"local7",
	"unknown"
};
static int log_cons_constructor(void *, void *, int);
static void log_cons_destructor(void *, void *);

/*
 * Get exclusive access to the logging system; this includes all minor
 * devices.  We use an rwlock rather than a mutex because hold times
 * are potentially long, so we don't want to waste cycles in adaptive mutex
 * spin (rwlocks always block when contended).  Note that we explicitly
 * support recursive calls (e.g. printf() calls foo() calls printf()).
 *
 * Clients may use log_enter() / log_exit() to guarantee that a group
 * of messages is treated atomically (i.e. they appear in order and are
 * not interspersed with any other messages), e.g. for multiline printf().
 *
 * This could probably be changed to a per-zone lock if contention becomes
 * an issue.
 */
void
log_enter(void)
{
	if (rw_owner(&log_rwlock) != curthread)
		rw_enter(&log_rwlock, RW_WRITER);
	log_rwlock_depth++;
}

void
log_exit(void)
{
	if (--log_rwlock_depth == 0)
		rw_exit(&log_rwlock);
}

void
log_flushq(queue_t *q)
{
	mblk_t *mp;
	log_t *lp = (log_t *)q->q_ptr;

	/* lp will be NULL if the queue was created via log_makeq */
	while ((mp = getq_noenab(q, 0)) != NULL)
		log_sendmsg(mp, lp == NULL ? GLOBAL_ZONEID : lp->log_zoneid);
}

/*
 * Create a minimal queue with just enough fields filled in to support
 * canput(9F), putq(9F), and getq_noenab(9F).  We set QNOENB to ensure
 * that the queue will never be enabled.
 */
static queue_t *
log_makeq(size_t lowat, size_t hiwat, void *ibc)
{
	queue_t *q;

	q = kmem_zalloc(sizeof (queue_t), KM_SLEEP);
	q->q_stream = &log_fakestr;
	q->q_flag = QISDRV | QMTSAFE | QNOENB | QREADR | QUSE;
	q->q_nfsrv = q;
	q->q_lowat = lowat;
	q->q_hiwat = hiwat;
	mutex_init(QLOCK(q), NULL, MUTEX_DRIVER, ibc);

	return (q);
}

/*
 * Initialize the log structure for a new zone.
 */
static void *
log_zoneinit(zoneid_t zoneid)
{
	int i;
	log_zone_t *lzp;

	if (zoneid == GLOBAL_ZONEID)
		lzp = &log_global;	/* use statically allocated struct */
	else
		lzp = kmem_zalloc(sizeof (log_zone_t), KM_SLEEP);

	for (i = 0; i < LOG_NUMCLONES; i++) {
		lzp->lz_clones[i].log_minor =
		    (minor_t)id_alloc(log_minorspace);
		lzp->lz_clones[i].log_zoneid = zoneid;
	}
	return (lzp);
}

/*ARGSUSED*/
static void
log_zonefree(zoneid_t zoneid, void *arg)
{
	log_zone_t *lzp = arg;
	int i;

	ASSERT(lzp != &log_global && zoneid != GLOBAL_ZONEID);
	if (lzp == NULL)
		return;
	for (i = 0; i < LOG_NUMCLONES; i++)
		id_free(log_minorspace, lzp->lz_clones[i].log_minor);
	kmem_free(lzp, sizeof (log_zone_t));
}

void
log_init(void)
{
	int log_maxzones;

	/*
	 * Create a backlog queue to consume console messages during periods
	 * when there is no console reader (e.g. before syslogd(1M) starts).
	 */
	log_backlogq = log_consq = log_makeq(0, LOG_HIWAT, NULL);

	/*
	 * Create a queue to hold free message of size <= LOG_MSGSIZE.
	 * Calls from high-level interrupt handlers will do a getq_noenab()
	 * from this queue, so its q_lock must be a maximum SPL spin lock.
	 */
	log_freeq = log_makeq(LOG_MINFREE, LOG_MAXFREE, (void *)ipltospl(SPL8));

	/*
	 * Create a queue for messages from high-level interrupt context.
	 * These messages are drained via softcall, or explicitly by panic().
	 */
	log_intrq = log_makeq(0, LOG_HIWAT, (void *)ipltospl(SPL8));

	/*
	 * Create a queue to hold the most recent 8K of console messages.
	 * Useful for debugging.  Required by the "$<msgbuf" adb macro.
	 */
	log_recentq = log_makeq(0, LOG_RECENTSIZE, NULL);

	/*
	 * Create an id space for clone devices opened via /dev/log.
	 * Need to limit the number of zones to avoid exceeding the
	 * available minor number space.
	 */
	log_maxzones = (L_MAXMIN32 - LOG_LOGMIN) / LOG_NUMCLONES - 1;
	if (log_maxzones < maxzones)
		maxzones = log_maxzones;
	log_minorspace = id_space_create("logminor_space", LOG_LOGMIN + 1,
	    L_MAXMIN32);
	/*
	 * Put ourselves on the ZSD list.  Note that zones have not been
	 * initialized yet, but our constructor will be called on the global
	 * zone when they are.
	 */
	zone_key_create(&log_zone_key, log_zoneinit, NULL, log_zonefree);

	/*
	 * Initialize backlog structure.
	 */
	log_backlog.log_zoneid = GLOBAL_ZONEID;
	log_backlog.log_minor = LOG_BACKLOG;

	/* Allocate kmem cache for conslog's log structures */
	log_cons_cache = kmem_cache_create("log_cons_cache",
	    sizeof (struct log), 0, log_cons_constructor, log_cons_destructor,
	    NULL, NULL, NULL, 0);

	/*
	 * Let the logging begin.
	 */
	log_update(&log_backlog, log_backlogq, SL_CONSOLE, log_console);

	/*
	 * Now that logging is enabled, emit the SunOS banner.
	 */
	printf("\rSunOS Release %s Version %s %u-bit\n",
	    utsname.release, utsname.version, NBBY * (uint_t)sizeof (void *));
	printf("Copyright (c) 2010-2015, Joyent Inc. All rights reserved.\n");
#ifdef DEBUG
	printf("DEBUG enabled\n");
#endif
}

/*
 * Allocate a log device corresponding to supplied device type.
 * Both devices are clonable. /dev/log devices are allocated per zone.
 * /dev/conslog devices are allocated from kmem cache.
 */
log_t *
log_alloc(minor_t type)
{
	zone_t *zptr = curproc->p_zone;
	log_zone_t *lzp;
	log_t *lp;
	int i;
	minor_t minor;

	if (type == LOG_CONSMIN) {

		/*
		 * Return a write-only /dev/conslog device.
		 * No point allocating log_t until there's a free minor number.
		 */
		minor = (minor_t)id_alloc(log_minorspace);
		lp = kmem_cache_alloc(log_cons_cache, KM_SLEEP);
		lp->log_minor = minor;
		return (lp);
	} else {
		ASSERT(type == LOG_LOGMIN);

		lzp = zone_getspecific(log_zone_key, zptr);
		ASSERT(lzp != NULL);

		/* search for an available /dev/log device for the zone */
		for (i = LOG_LOGMINIDX; i <= LOG_LOGMAXIDX; i++) {
			lp = &lzp->lz_clones[i];
			if (lp->log_inuse == 0)
				break;
		}
		if (i > LOG_LOGMAXIDX)
			lp = NULL;
		else
			/* Indicate which device type */
			lp->log_major = LOG_LOGMIN;
		return (lp);
	}
}

void
log_free(log_t *lp)
{
	id_free(log_minorspace, lp->log_minor);
	kmem_cache_free(log_cons_cache, lp);
}

/*
 * Move console messages from src to dst.  The time of day isn't known
 * early in boot, so fix up the message timestamps if necessary.
 */
static void
log_conswitch(log_t *src, log_t *dst)
{
	mblk_t *mp;
	mblk_t *hmp = NULL;
	mblk_t *tmp = NULL;
	log_ctl_t *hlc;

	while ((mp = getq_noenab(src->log_q, 0)) != NULL) {
		log_ctl_t *lc = (log_ctl_t *)mp->b_rptr;
		lc->flags |= SL_LOGONLY;

		/*
		 * The ttime is written with 0 in log_sensmsg() only when
		 * good gethrestime_sec() data is not available to store in
		 * the log_ctl_t in the early boot phase.
		 */
		if (lc->ttime == 0) {
			/*
			 * Look ahead to first early boot message with time.
			 */
			if (hmp) {
				tmp->b_next = mp;
				tmp = mp;
			} else
				hmp = tmp = mp;
			continue;
		}

		while (hmp) {
			tmp = hmp->b_next;
			hmp->b_next = NULL;
			hlc = (log_ctl_t *)hmp->b_rptr;
			/*
			 * Calculate hrestime for an early log message with
			 * an invalid time stamp. We know:
			 *  - the lbolt of the invalid time stamp.
			 *  - the hrestime and lbolt of the first valid
			 *    time stamp.
			 */
			hlc->ttime = lc->ttime - (lc->ltime - hlc->ltime) / hz;
			(void) putq(dst->log_q, hmp);
			hmp = tmp;
		}
		(void) putq(dst->log_q, mp);
	}
	while (hmp) {
		tmp = hmp->b_next;
		hmp->b_next = NULL;
		hlc = (log_ctl_t *)hmp->b_rptr;
		hlc->ttime = gethrestime_sec() -
		    (ddi_get_lbolt() - hlc->ltime) / hz;
		(void) putq(dst->log_q, hmp);
		hmp = tmp;
	}
	dst->log_overflow = src->log_overflow;
	src->log_flags = 0;
	dst->log_flags = SL_CONSOLE;
	log_consq = dst->log_q;
}

/*
 * Set the fields in the 'target' clone to the specified values.
 * Then, look at all clones to determine which message types are
 * currently active and which clone is the primary console queue.
 * If the primary console queue changes to or from the backlog
 * queue, copy all messages from backlog to primary or vice versa.
 */
void
log_update(log_t *target, queue_t *q, short flags, log_filter_t *filter)
{
	log_t *lp;
	short active = SL_CONSOLE;
	zone_t *zptr = NULL;
	log_zone_t *lzp;
	zoneid_t zoneid = target->log_zoneid;
	int i;

	log_enter();

	if (q != NULL)
		target->log_q = q;
	target->log_wanted = filter;
	target->log_flags = flags;
	target->log_overflow = 0;

	/*
	 * Need to special case the global zone here since this may be
	 * called before zone_init.
	 */
	if (zoneid == GLOBAL_ZONEID) {
		lzp = &log_global;
	} else if ((zptr = zone_find_by_id(zoneid)) == NULL) {
		log_exit();
		return;		/* zone is being destroyed, ignore update */
	} else {
		lzp = zone_getspecific(log_zone_key, zptr);
	}
	ASSERT(lzp != NULL);
	for (i = LOG_LOGMAXIDX; i >= LOG_LOGMINIDX; i--) {
		lp = &lzp->lz_clones[i];
		if (zoneid == GLOBAL_ZONEID && (lp->log_flags & SL_CONSOLE))
			log_consq = lp->log_q;
		active |= lp->log_flags;
	}
	lzp->lz_active = active;

	if (zptr)
		zone_rele(zptr);

	if (log_consq == target->log_q) {
		if (flags & SL_CONSOLE)
			log_conswitch(&log_backlog, target);
		else
			log_conswitch(target, &log_backlog);
	}
	target->log_q = q;

	log_exit();
}

/*ARGSUSED*/
int
log_error(log_t *lp, log_ctl_t *lc)
{
	if ((lc->pri & LOG_FACMASK) == LOG_KERN)
		lc->pri = LOG_KERN | LOG_ERR;
	return (1);
}

int
log_trace(log_t *lp, log_ctl_t *lc)
{
	trace_ids_t *tid = (trace_ids_t *)lp->log_data->b_rptr;
	trace_ids_t *tidend = (trace_ids_t *)lp->log_data->b_wptr;

	/*
	 * We use `tid + 1 <= tidend' here rather than the more traditional
	 * `tid < tidend', since the former ensures that there's at least
	 * `sizeof (trace_ids_t)' bytes available before executing the
	 * loop, whereas the latter only ensures that there's a single byte.
	 */
	for (; tid + 1 <= tidend; tid++) {
		if (tid->ti_level < lc->level && tid->ti_level >= 0)
			continue;
		if (tid->ti_mid != lc->mid && tid->ti_mid >= 0)
			continue;
		if (tid->ti_sid != lc->sid && tid->ti_sid >= 0)
			continue;
		if ((lc->pri & LOG_FACMASK) == LOG_KERN)
			lc->pri = LOG_KERN | LOG_DEBUG;
		return (1);
	}
	return (0);
}

/*ARGSUSED*/
int
log_console(log_t *lp, log_ctl_t *lc)
{
	if ((lc->pri & LOG_FACMASK) == LOG_KERN) {
		if (lc->flags & SL_FATAL)
			lc->pri = LOG_KERN | LOG_CRIT;
		else if (lc->flags & SL_ERROR)
			lc->pri = LOG_KERN | LOG_ERR;
		else if (lc->flags & SL_WARN)
			lc->pri = LOG_KERN | LOG_WARNING;
		else if (lc->flags & SL_NOTE)
			lc->pri = LOG_KERN | LOG_NOTICE;
		else if (lc->flags & SL_TRACE)
			lc->pri = LOG_KERN | LOG_DEBUG;
		else
			lc->pri = LOG_KERN | LOG_INFO;
	}
	return (1);
}

mblk_t *
log_makemsg(int mid, int sid, int level, int sl, int pri, void *msg,
	size_t size, int on_intr)
{
	mblk_t *mp = NULL;
	mblk_t *mp2;
	log_ctl_t *lc;

	if (size <= LOG_MSGSIZE &&
	    (on_intr || log_freeq->q_count > log_freeq->q_lowat))
		mp = getq_noenab(log_freeq, 0);

	if (mp == NULL) {
		if (on_intr ||
		    (mp = allocb(sizeof (log_ctl_t), BPRI_HI)) == NULL ||
		    (mp2 = allocb(MAX(size, LOG_MSGSIZE), BPRI_HI)) == NULL) {
			freemsg(mp);
			return (NULL);
		}
		DB_TYPE(mp) = M_PROTO;
		mp->b_wptr += sizeof (log_ctl_t);
		mp->b_cont = mp2;
	} else {
		mp2 = mp->b_cont;
		mp2->b_wptr = mp2->b_rptr;
	}

	lc = (log_ctl_t *)mp->b_rptr;
	lc->mid = mid;
	lc->sid = sid;
	lc->level = level;
	lc->flags = sl;
	lc->pri = pri;

	bcopy(msg, mp2->b_wptr, size - 1);
	mp2->b_wptr[size - 1] = '\0';
	mp2->b_wptr += strlen((char *)mp2->b_wptr) + 1;

	return (mp);
}

void
log_freemsg(mblk_t *mp)
{
	mblk_t *mp2 = mp->b_cont;

	ASSERT(MBLKL(mp) == sizeof (log_ctl_t));
	ASSERT(mp2->b_rptr == mp2->b_datap->db_base);

	if ((log_freeq->q_flag & QFULL) == 0 &&
	    MBLKL(mp2) <= LOG_MSGSIZE && MBLKSIZE(mp2) >= LOG_MSGSIZE)
		(void) putq(log_freeq, mp);
	else
		freemsg(mp);
}

void
log_sendmsg(mblk_t *mp, zoneid_t zoneid)
{
	log_t *lp;
	char *src, *dst;
	mblk_t *mp2 = mp->b_cont;
	log_ctl_t *lc = (log_ctl_t *)mp->b_rptr;
	int flags, fac;
	off_t facility = 0;
	off_t body = 0;
	zone_t *zptr = NULL;
	log_zone_t *lzp;
	int i;
	int backlog;

	/*
	 * Need to special case the global zone here since this may be
	 * called before zone_init.
	 */
	if (zoneid == GLOBAL_ZONEID) {
		lzp = &log_global;
	} else if ((zptr = zone_find_by_id(zoneid)) == NULL) {
		/* specified zone doesn't exist, free message and return */
		log_freemsg(mp);
		return;
	} else {
		lzp = zone_getspecific(log_zone_key, zptr);
	}
	ASSERT(lzp != NULL);

	if ((lc->flags & lzp->lz_active) == 0) {
		if (zptr)
			zone_rele(zptr);
		log_freemsg(mp);
		return;
	}

	if (panicstr) {
		/*
		 * Raise the console queue's q_hiwat to ensure that we
		 * capture all panic messages.
		 */
		log_consq->q_hiwat = 2 * LOG_HIWAT;
		log_consq->q_flag &= ~QFULL;

		/* Message was created while panicking. */
		lc->flags |= SL_PANICMSG;
	}

	src = (char *)mp2->b_rptr;
	dst = strstr(src, "FACILITY_AND_PRIORITY] ");
	if (dst != NULL) {
		facility = dst - src;
		body = facility + 23; /* strlen("FACILITY_AND_PRIORITY] ") */
	}

	log_enter();

	/*
	 * In the early boot phase hrestime is invalid, then timechanged is 0.
	 * If hrestime is not valid, the ttime is set to 0 here and the correct
	 * ttime is calculated in log_conswitch() later. The log_conswitch()
	 * calculation to determine the correct ttime does not use ttime data
	 * from these log_ctl_t structures; it only uses ttime from log_ctl_t's
	 * that contain good data.
	 *
	 */
	lc->ltime = ddi_get_lbolt();
	if (timechanged) {
		lc->ttime = gethrestime_sec();
	} else {
		lc->ttime = 0;
	}

	flags = lc->flags & lzp->lz_active;
	log_seq_no[flags & SL_ERROR]++;
	log_seq_no[flags & SL_TRACE]++;
	log_seq_no[flags & SL_CONSOLE]++;

	/*
	 * If this is in the global zone, start with the backlog, then
	 * walk through the clone logs.  If not, just do the clone logs.
	 */
	backlog = (zoneid == GLOBAL_ZONEID);
	i = LOG_LOGMINIDX;
	while (i <= LOG_LOGMAXIDX) {
		if (backlog) {
			/*
			 * Do the backlog this time, then start on the
			 * others.
			 */
			backlog = 0;
			lp = &log_backlog;
		} else {
			lp = &lzp->lz_clones[i++];
		}

		if ((lp->log_flags & flags) && lp->log_wanted(lp, lc)) {
			if (canput(lp->log_q)) {
				lp->log_overflow = 0;
				lc->seq_no = log_seq_no[lp->log_flags];
				if ((mp2 = copymsg(mp)) == NULL)
					break;
				if (facility != 0) {
					src = (char *)mp2->b_cont->b_rptr;
					dst = src + facility;
					fac = (lc->pri & LOG_FACMASK) >> 3;
					dst += snprintf(dst,
					    LOG_FACSIZE + LOG_PRISIZE, "%s.%s",
					    log_fac[MIN(fac, LOG_NFACILITIES)],
					    log_pri[lc->pri & LOG_PRIMASK]);
					src += body - 2; /* copy "] " too */
					while (*src != '\0')
						*dst++ = *src++;
					*dst++ = '\0';
					mp2->b_cont->b_wptr = (uchar_t *)dst;
				}
				(void) putq(lp->log_q, mp2);
			} else if (++lp->log_overflow == 1) {
				if (lp->log_q == log_consq) {
					console_printf(log_overflow_msg,
					    lp->log_minor,
					    " -- is syslogd(1M) running?");
				} else {
					printf(log_overflow_msg,
					    lp->log_minor, "");
				}
			}
		}
	}

	if (zptr)
		zone_rele(zptr);

	if ((flags & SL_CONSOLE) && (lc->pri & LOG_FACMASK) == LOG_KERN) {
		if ((mp2 == NULL || log_consq == log_backlogq || panicstr) &&
		    (lc->flags & SL_LOGONLY) == 0)
			console_printf("%s", (char *)mp->b_cont->b_rptr + body);
		if ((lc->flags & SL_CONSONLY) == 0 &&
		    (mp2 = copymsg(mp)) != NULL) {
			mp2->b_cont->b_rptr += body;
			if (log_recentq->q_flag & QFULL)
				freemsg(getq_noenab(log_recentq, 0));
			(void) putq(log_recentq, mp2);
		}
	}

	log_freemsg(mp);

	log_exit();
}

/*
 * Print queued messages to console.
 */
void
log_printq(queue_t *qfirst)
{
	mblk_t *mp;
	queue_t *q, *qlast;
	char *cp, *msgp;
	log_ctl_t *lc;

	/*
	 * Look ahead to first queued message in the stream.
	 */
	qlast = NULL;
	do {
		for (q = qfirst; q->q_next != qlast; q = q->q_next)
			continue;
		for (mp = q->q_first; mp != NULL; mp = mp->b_next) {
			lc = (log_ctl_t *)mp->b_rptr;
			/*
			 * Check if message is already displayed at
			 * /dev/console.
			 */
			if (lc->flags & SL_PANICMSG)
				continue;

			cp = (char *)mp->b_cont->b_rptr;

			/* Strip off the message ID. */
			if ((msgp = strstr(cp, "[ID ")) != NULL &&
			    (msgp = strstr(msgp,  "] ")) != NULL) {
				cp = msgp + 2;
			}

			/*
			 * Using console_printf instead of printf to avoid
			 * queueing messages to log_consq.
			 */
			console_printf("%s", cp);
		}
	} while ((qlast = q) != qfirst);
}

/* ARGSUSED */
static int
log_cons_constructor(void *buf, void *cdrarg, int kmflags)
{
	struct log *lp = buf;

	lp->log_zoneid = GLOBAL_ZONEID;
	lp->log_major = LOG_CONSMIN;	/* Indicate which device type */
	lp->log_data = NULL;
	return (0);
}

/* ARGSUSED */
static void
log_cons_destructor(void *buf, void *cdrarg)
{
	struct log *lp = buf;

	ASSERT(lp->log_zoneid == GLOBAL_ZONEID);
	ASSERT(lp->log_major == LOG_CONSMIN);
	ASSERT(lp->log_data == NULL);
}
