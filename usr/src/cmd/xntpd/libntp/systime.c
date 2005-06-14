/*
 * Copyright 1996, 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * systime -- routines to fiddle a UNIX clock.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif
#ifdef HAVE_UTMP_H
# include <utmp.h>
#endif /* HAVE_UTMP_H */
#ifdef HAVE_UTMPX_H
# include <utmpx.h>
#endif /* HAVE_UTMPX_H */

#include "ntp_fp.h"
#include "ntp_syslog.h"
#include "ntp_unixtime.h"
#include "ntp_stdlib.h"

#if defined(GDT_SURVEYING)
l_fp gdt_rsadj;		/* running sum of adjustments to time */
#endif

#ifdef SLEWALWAYS
int slewalways = 1;
#else
int slewalways = 0;
#endif

extern int debug;
int allow_set_backward;

/*
 * These routines (init_systime, get_systime, step_systime, adj_systime)
 * implement an interface between the (more or less) system independent
 * bits of NTP and the peculiarities of dealing with the Unix system
 * clock.  These routines will run with good precision fairly independently
 * of your kernel's value of tickadj.  I couldn't tell the difference
 * between tickadj==40 and tickadj==5 on a microvax, though I prefer
 * to set tickadj == 500/hz when in doubt.  At your option you
 * may compile this so that your system's clock is always slewed to the
 * correct time even for large corrections.  Of course, all of this takes
 * a lot of code which wouldn't be needed with a reasonable tickadj and
 * a willingness to let the clock be stepped occasionally.  Oh well.
 */

/*
 * Clock variables.  We round calls to adjtime() to adj_precision
 * microseconds, and limit the adjustment to tvu_maxslew microseconds
 * (tsf_maxslew fractional sec) in one adjustment interval.  As we are
 * thus limited in the speed and precision with which we can adjust the
 * clock, we compensate by keeping the known "error" in the system time
 * in sys_clock_offset.  This is added to timestamps returned by get_systime().
 * We also remember the clock precision we computed from the kernel in
 * case someone asks us.
 */

long sys_clock;

long adj_precision;		/* adj precision in usec (tickadj) */
long tvu_maxslew;		/* maximum adjust doable in 1 second */

u_long tsf_maxslew;		/* same as above, as long format */

l_fp sys_clock_offset;		/* correction for current system time */

#ifdef SYS_WINNT
/*
 * number of 100 nanosecond units added to the clock at each tick
 * determined by GetSystemTimeAdjustment() in clock_parms()
 */
long units_per_tick;
#endif /* SYS_WINNT */

/*
 * get_systime - return the system time in timestamp format
 * As a side effect, update sys_clock.
 */
void
get_systime(now)
	l_fp *now;
{
	struct timeval tv;
#ifdef HAVE_GETCLOCK
        struct timespec ts;
#endif

	/*
	 * Get the time of day, convert to time stamp format
	 * and add in the current time offset.  Then round
	 * appropriately.
	 */

#ifdef HAVE_GETCLOCK
        (void) getclock(TIMEOFDAY, &ts);
        tv.tv_sec = ts.tv_sec;
        tv.tv_usec = ts.tv_nsec / 1000;
#else /*  not HAVE_GETCLOCK */
	(void) GETTIMEOFDAY(&tv, (struct timezone *)0);
#endif /* not HAVE_GETCLOCK */

	TVTOTS(&tv, now);
	L_ADD(now, &sys_clock_offset);
	if (now->l_uf & TS_ROUNDBIT)
		L_ADDUF(now, TS_ROUNDBIT);

	now->l_ui += JAN_1970;
	now->l_uf &= TS_MASK;

	sys_clock = now->l_ui;
}

/*
 * step_systime - do a step adjustment in the system time (at least from
 *		  NTP's point of view.
 */
int
step_systime(now)
	l_fp *now;
{
	register u_long tmp_ui;
	register u_long tmp_uf;
	int isneg;
#ifdef STEP_SLEW
	int n;
#endif

	/*
	 * Take the absolute value of the offset
	 */
	tmp_ui = now->l_ui;
	tmp_uf = now->l_uf;
	if (M_ISNEG(tmp_ui, tmp_uf)) {
		M_NEG(tmp_ui, tmp_uf);
		isneg = 1;
	} else
		isneg = 0;

#ifdef STEP_SLEW
	if (tmp_ui >= 3) {		/* Step it and slew we  might win */
	     n = step_systime_real(now);
	     if (!n) return n;
	     if (isneg) 
		now->l_ui = ~0;
	     else
		now->l_ui = ~0;
	}
	/*
	 * Just add adjustment into the current offset.  The update
	 * routine will take care of bringing the system clock into
	 * line.
	 */
	L_ADD(&sys_clock_offset, now);
#if defined(GDT_SURVEYING)
	L_ADD(&gdt_rsadj, now);
#endif
	return 1;
#else /* STEP_SLEW */

	if (slewalways) {
		/*
		 * Just add adjustment into the current offset.  The update
		 * routine will take care of bringing the system clock into
		 * line.
		 */
		L_ADD(&sys_clock_offset, now);
#if defined(GDT_SURVEYING)
		L_ADD(&gdt_rsadj, now);
#endif
		return 1;
	} else {
#ifdef DEBUG
		if (debug > 2)
		   printf ("allow_set_backward=%d\n",allow_set_backward);
#endif
		if (isneg && !allow_set_backward) {
		   L_ADD(&sys_clock_offset, now);
		   return 1;
		}
		else {
#ifdef DEBUG
		   if (debug > 2)
		      printf ("calling step_systime_real from not slewalways\n");
#endif
                   return step_systime_real(now);
		}
	}
#endif  /* STEP_SLEW  */
}

int	max_no_complete	= 20;

/*
 * adj_systime - called once every second to make system time adjustments.
 */
int
adj_systime(now)
	l_fp *now;
{
	register u_long offset_i, offset_f;
	register long temp;
	register u_long residual;
	register int isneg = 0;
	struct timeval adjtv;
#ifndef SYS_WINNT
	struct timeval oadjtv;
	l_fp oadjts;
#endif
	long adj = now->l_f;
	int rval;

#ifdef SYS_WINNT
	DWORD dwTimeAdjustment;
#endif /* SYS_WINNT */

#if defined(GDT_SURVEYING)
	/* add to record of increments */
	M_ADDF(gdt_rsadj.l_ui, gdt_rsadj.l_uf, adj);
#endif

#ifdef DEBUG
	if (debug > 4)
		printf("systime: offset %s\n", lfptoa(now, 6));
#endif 
	/*
	 * Move the current offset into the registers
	 */
	offset_i = sys_clock_offset.l_ui;
	offset_f = sys_clock_offset.l_uf;

	/*
	 * Add the new adjustment into the system offset.  Adjust the
	 * system clock to minimize this.
	 */
	M_ADDF(offset_i, offset_f, adj);
	if (M_ISNEG(offset_i, offset_f)) {
		isneg = 1;
		M_NEG(offset_i, offset_f);
	}
	adjtv.tv_sec = 0;
	if (offset_i > 0 || offset_f >= tsf_maxslew) {
		/*
		 * Slew is bigger than we can complete in
		 * the adjustment interval.  Make a maximum
		 * sized slew and reduce sys_clock_offset by this
		 * much.
		 */
		M_SUBUF(offset_i, offset_f, tsf_maxslew);
		if (!isneg) {
#ifndef SYS_WINNT
			adjtv.tv_usec = tvu_maxslew;
#else
			dwTimeAdjustment = units_per_tick + tvu_maxslew / adj_precision;
#endif /* SYS_WINNT */
		} else {
#ifndef SYS_WINNT
			adjtv.tv_usec = -tvu_maxslew;
#else
			dwTimeAdjustment = units_per_tick - tvu_maxslew / adj_precision;
#endif /* SYS_WINNT */
			M_NEG(offset_i, offset_f);
		}

#ifdef DEBUG
		if (debug > 4)
			printf("systime: maximum slew: %s%s, remainder = %s\n",
			    isneg?"-":"", umfptoa(0, tsf_maxslew, 9),
			    mfptoa(offset_i, offset_f, 9));
#endif
	} else {
		/*
		 * We can do this slew in the time period.  Do our
		 * best approximation (rounded), save residual for
		 * next adjustment.
		 *
		 * Note that offset_i is guaranteed to be 0 here.
		 */
		TSFTOTVU(offset_f, temp);
#ifndef ADJTIME_IS_ACCURATE
		/*
		 * Round value to be an even multiple of adj_precision
		 */
		residual = temp % adj_precision;
		temp -= residual;
		if ( (long) (residual << 1) >= adj_precision)
			temp += adj_precision;
#endif /* ADJTIME_IS_ACCURATE */
		TVUTOTSF(temp, residual);
		M_SUBUF(offset_i, offset_f, residual);

		if (isneg) {
#ifndef SYS_WINNT
			adjtv.tv_usec = -temp;
#else
			dwTimeAdjustment = units_per_tick - temp / adj_precision;
#endif /* SYS_WINNT */
			M_NEG(offset_i, offset_f);
		} else {
#ifndef SYS_WINNT
			adjtv.tv_usec = temp;
#else
			dwTimeAdjustment = units_per_tick + temp / adj_precision;
#endif /* SYS_WINNT */
		}
#ifdef DEBUG
		if (debug > 4) {
#ifndef SYS_WINNT
			printf(
		"systime: adjtv = %s sec, adjts = %s sec, sys_clock_offset = %s sec\n",
			    tvtoa(&adjtv), umfptoa(0, residual, 6),
			    mfptoa(offset_i, offset_f, 6));
#else
			printf(
		"systime: dwTimeAdjustment = %d, sys_clock_offset = %s sec\n",
				dwTimeAdjustment, mfptoa(offset_i, offset_f, 6));
#endif /* SYS_WINNT */
			printf("sys_adjtime: zeroing offset_i and offset_f\n");
		}
#endif /* DEBUG */

		offset_i = offset_f = 0;
	}

	/*
	 * Here we do the actual adjustment. If for some reason the adjtime()
	 * call fails, like it is not implemented or something like that,
	 * we honk to the log. If the previous adjustment did not complete,
	 * we correct the residual offset and honk to the log, but only for
	 * a little while.
	 */
	if (
#ifndef SYS_WINNT
        /* casey - we need a posix type thang here */
	    (adjtime(&adjtv, &oadjtv) < 0)
#else
	    (!SetSystemTimeAdjustment(dwTimeAdjustment, FALSE))
#endif /* SYS_WINNT */
	    ) {
		msyslog(LOG_ERR, "Can't adjust time: %m");
		rval = 0;
	} else {
		sys_clock_offset.l_ui = offset_i;
		sys_clock_offset.l_uf = offset_f;
		rval = 1;
#ifndef SYS_WINNT 
		if (oadjtv.tv_sec != 0 || oadjtv.tv_usec != 0) {
			sTVTOTS(&oadjtv, &oadjts);
			L_ADD(&sys_clock_offset, &oadjts);
#if defined(GDT_SURVEYING)
			L_ADD(&gdt_rsadj, &oadjts);
#endif
			if (max_no_complete > 0) {
				max_no_complete--;
				NLOG(NLOG_SYSSTATUS|NLOG_SYNCSTATUS)
                                    msyslog(LOG_WARNING,
		"Previous time adjustment incomplete; residual %s sec\n",
				    lfptoa(&oadjts, 6));
			}
		}
#endif /* SYS_WINNT */
	}
	return(rval);
}


/*
 * This is used by ntpdate even when xntpd does not use it! WLJ
 */
int
step_systime_real(now)
	l_fp *now;
{
	struct timeval timetv, adjtv, oldtimetv;
	int isneg = 0;
#if defined(HAVE_GETCLOCK) || defined(HAVE_CLOCK_SETTIME)
        struct timespec ts;
#endif

#if DEBUG
	if (debug)
		printf("step_systime: offset %s sys_offset %s\n",
			lfptoa(now, 6), lfptoa(&sys_clock_offset, 6));
#endif

	/*
	 * We can afford to be sloppy here since if this is called
	 * the time is really screwed and everything is being reset.
	 */
	L_ADD(&sys_clock_offset, now);
#if defined(GDT_SURVEYING)
	L_ADD(&gdt_rsadj, now);
#endif

	if (L_ISNEG(&sys_clock_offset)) {
		isneg = 1;
		L_NEG(&sys_clock_offset);
	}
	TSTOTV(&sys_clock_offset, &adjtv);

#ifdef HAVE_GETCLOCK
        (void) getclock(TIMEOFDAY, &ts);
        timetv.tv_sec = ts.tv_sec;
        timetv.tv_usec = ts.tv_nsec / 1000;
#else /*  not HAVE_GETCLOCK */
	(void) GETTIMEOFDAY(&timetv, (struct timezone *)0);
#endif /* not HAVE_GETCLOCK */

	oldtimetv = timetv;

#ifdef DEBUG
	if (debug)
		printf("step: %s sec, sys_clock_offset = %s sec, adjtv = %s sec, timetv = %s sec\n",
		    lfptoa(now, 6), lfptoa(&sys_clock_offset, 6), tvtoa(&adjtv),
		    utvtoa(&timetv));
#endif
	if (isneg) {
		timetv.tv_sec -= adjtv.tv_sec;
		timetv.tv_usec -= adjtv.tv_usec;
		if (timetv.tv_usec < 0) {
			timetv.tv_sec--;
			timetv.tv_usec += 1000000;
		}
	} else {
		timetv.tv_sec += adjtv.tv_sec;
		timetv.tv_usec += adjtv.tv_usec;
		if (timetv.tv_usec >= 1000000) {
			timetv.tv_sec++;
			timetv.tv_usec -= 1000000;
		}
	}
#ifdef DEBUG
	if (debug)
		printf("step: old timetv = %s sec\n", utvtoa(&timetv));
#endif
#if HAVE_CLOCK_SETTIME
	ts.tv_sec = timetv.tv_sec;
	ts.tv_nsec = timetv.tv_usec * 1000;
#endif /* HAVE_CLOCK_SETTIME */
	if (
#if HAVE_CLOCK_SETTIME
	    (clock_settime(CLOCK_REALTIME, &ts) != 0)
#else /* HAVE_CLOCK_SETTIME */
	    (SETTIMEOFDAY(&timetv, (struct timezone *)0) != 0)
#endif /* HAVE_CLOCK_SETTIME */
	    ) {
		msyslog(LOG_ERR, "Can't set time of day: %m");
		return (0);
	}
#if DEBUG
	if (debug) {
#ifdef HAVE_GETCLOCK
        (void) getclock(TIMEOFDAY, &ts);
        timetv.tv_sec = ts.tv_sec;
        timetv.tv_usec = ts.tv_nsec / 1000;
#else /*  not HAVE_GETCLOCK */
	(void) GETTIMEOFDAY(&timetv, (struct timezone *)0);
#endif /* not HAVE_GETCLOCK */
		printf("step: new timetv = %s sec\n", utvtoa(&timetv));
	}
#endif
	L_CLR(&sys_clock_offset);

#ifdef NEED_HPUX_ADJTIME
	/*
	 * CHECKME: is this correct when called by ntpdate?????
	 */
	_clear_adjtime();
#endif

	/*
	 * FreeBSD, for example, has:
	 * struct utmp {
	 *     char    ut_line[UT_LINESIZE];
	 *     char    ut_name[UT_NAMESIZE];
	 *     char    ut_host[UT_HOSTSIZE];
	 *     long    ut_time;
	 * };
	 * and appends line="|", name="date", host="", time for the OLD
	 * and appends line="{", name="date", host="", time for the NEW
	 * to _PATH_WTMP .
	 *
	 * Some OSes have utmp, some have utmpx.
	 */

	/*
	 * Write old and new time entries in utmp and wtmp if step adjustment
	 * is greater than one second.
	 *
	 * This might become even Uglier...
	 */

	if (oldtimetv.tv_sec != timetv.tv_sec)
	  {
#ifdef HAVE_UTMP_H
	    struct utmp ut;
#endif
#ifdef HAVE_UTMPX_H
	    struct utmpx utx;
#endif

#ifdef HAVE_UTMP_H
	    memset((char *)&ut, 0, sizeof(ut));
#endif
#ifdef HAVE_UTMPX_H
	    memset((char *)&utx, 0, sizeof(utx));
#endif

	    /* UTMP */

#ifdef UPDATE_UTMP
# ifdef HAVE_PUTUTLINE
	    ut.ut_type = OLD_TIME;
	    (void)strcpy(ut.ut_line, OTIME_MSG);
	    ut.ut_time = oldtimetv.tv_sec;
	    pututline(&ut);
	    setutent();
	    ut.ut_type = NEW_TIME;
	    (void)strcpy(ut.ut_line, NTIME_MSG);
	    ut.ut_time = timetv.tv_sec;
	    pututline(&ut);
	    endutent();
# else /* not HAVE_PUTUTLINE */
# endif /* not HAVE_PUTUTLINE */
#endif /* UPDATE_UTMP */

	    /* UTMPX */

#ifdef UPDATE_UTMPX
# ifdef HAVE_PUTUTXLINE
	    utx.ut_type = OLD_TIME;
	    (void)strcpy(utx.ut_line, OTIME_MSG);
	    utx.ut_tv = oldtimetv;
	    pututxline(&utx);
	    setutxent();
	    utx.ut_type = NEW_TIME;
	    (void)strcpy(utx.ut_line, NTIME_MSG);
	    utx.ut_tv = timetv;
	    pututxline(&utx);
	    endutxent();
# else /* not HAVE_PUTUTXLINE */
# endif /* not HAVE_PUTUTXLINE */
#endif /* UPDATE_UTMPX */

	    /* WTMP */

#ifdef UPDATE_WTMP
# ifdef HAVE_PUTUTLINE
	    utmpname(WTMP_FILE);
	    ut.ut_type = OLD_TIME;
	    (void)strcpy(ut.ut_line, OTIME_MSG);
	    ut.ut_time = oldtimetv.tv_sec;
	    pututline(&ut);
	    ut.ut_type = NEW_TIME;
	    (void)strcpy(ut.ut_line, NTIME_MSG);
	    ut.ut_time = timetv.tv_sec;
	    pututline(&ut);
	    endutent();
# else /* not HAVE_PUTUTLINE */
# endif /* not HAVE_PUTUTLINE */
#endif /* UPDATE_WTMP */

	    /* WTMPX */

#ifdef UPDATE_WTMPX
# ifdef HAVE_PUTUTXLINE
	    utx.ut_type = OLD_TIME;
	    utx.ut_tv = oldtimetv;
	    (void)strcpy(utx.ut_line, OTIME_MSG);
#  ifdef HAVE_UPDWTMPX
	    updwtmpx(WTMPX_FILE, &utx);
#  else /* not HAVE_UPDWTMPX */
#  endif /* not HAVE_UPDWTMPX */
# else /* not HAVE_PUTUTXLINE */
# endif /* not HAVE_PUTUTXLINE */
# ifdef HAVE_PUTUTXLINE
	    utx.ut_type = NEW_TIME;
	    utx.ut_tv = timetv;
	    (void)strcpy(utx.ut_line, NTIME_MSG);
#  ifdef HAVE_UPDWTMPX
	    updwtmpx(WTMPX_FILE, &utx);
#  else /* not HAVE_UPDWTMPX */
#  endif /* not HAVE_UPDWTMPX */
# else /* not HAVE_PUTUTXLINE */
# endif /* not HAVE_PUTUTXLINE */
#endif /* UPDATE_WTMPX */

	  }
	return (1);
}
