/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1982, 1986, 1993 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SYS_TIME_H
#define	_SYS_TIME_H

#include <sys/feature_tests.h>

/*
 * Structure returned by gettimeofday(2) system call,
 * and used in other calls.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(__XOPEN_OR_POSIX) || defined(_XPG4_2) || \
	defined(__EXTENSIONS__)
#ifndef	_ASM

#if !defined(_TIME_T) || __cplusplus >= 199711L
#define	_TIME_T
typedef	long	time_t;		/* time of day in seconds */
#endif	/* _TIME_T */

#ifndef	_SUSECONDS_T
#define	_SUSECONDS_T
typedef	long	suseconds_t;	/* signed # of microseconds */
#endif	/* _SUSECONDS_T */

struct timeval {
	time_t		tv_sec;		/* seconds */
	suseconds_t	tv_usec;	/* and microseconds */
};

#if defined(_SYSCALL32)

#include <sys/types32.h>

#define	TIMEVAL32_TO_TIMEVAL(tv, tv32)	{	\
	(tv)->tv_sec = (time_t)(tv32)->tv_sec;	\
	(tv)->tv_usec = (tv32)->tv_usec;	\
}

#define	TIMEVAL_TO_TIMEVAL32(tv32, tv)	{		\
	(tv32)->tv_sec = (time32_t)(tv)->tv_sec;	\
	(tv32)->tv_usec = (int32_t)(tv)->tv_usec;	\
}

#define	TIME32_MAX	INT32_MAX
#define	TIME32_MIN	INT32_MIN

#define	TIMEVAL_OVERFLOW(tv)	\
	((tv)->tv_sec < TIME32_MIN || (tv)->tv_sec > TIME32_MAX)

#endif	/* _SYSCALL32 */

#endif	/* _ASM */
#endif	/* !defined(__XOPEN_OR_POSIX) || defined(_XPG4_2) ... */

#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
#ifndef	_ASM
struct timezone {
	int	tz_minuteswest;	/* minutes west of Greenwich */
	int	tz_dsttime;	/* type of dst correction */
};

#endif	/* _ASM */
#endif /* !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) */

#ifdef	__cplusplus
}
#endif

/*
 * Needed for longlong_t type.  Placement of this due to <sys/types.h>
 * including <sys/select.h> which relies on the presense of the itimerval
 * structure.
 */
#ifndef	_ASM
#include <sys/types.h>
#endif	/* _ASM */

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)

#define	DST_NONE	0	/* not on dst */
#define	DST_USA		1	/* USA style dst */
#define	DST_AUST	2	/* Australian style dst */
#define	DST_WET		3	/* Western European dst */
#define	DST_MET		4	/* Middle European dst */
#define	DST_EET		5	/* Eastern European dst */
#define	DST_CAN		6	/* Canada */
#define	DST_GB		7	/* Great Britain and Eire */
#define	DST_RUM		8	/* Rumania */
#define	DST_TUR		9	/* Turkey */
#define	DST_AUSTALT	10	/* Australian style with shift in 1986 */

/*
 * Operations on timevals.
 */
#define	timerisset(tvp)		((tvp)->tv_sec || (tvp)->tv_usec)
#define	timercmp(tvp, uvp, cmp) \
	(((tvp)->tv_sec == (uvp)->tv_sec) ? \
	    /* CSTYLED */ \
	    ((tvp)->tv_usec cmp (uvp)->tv_usec) : \
	    /* CSTYLED */ \
	    ((tvp)->tv_sec cmp (uvp)->tv_sec))

#define	timerclear(tvp)		(tvp)->tv_sec = (tvp)->tv_usec = 0

#ifdef __lint
/*
 * Make innocuous, lint-happy versions until do {} while (0) is acknowleged as
 * lint-safe.  If the compiler could know that we always make tv_usec < 1000000
 * we wouldn't need a special linted version.
 */
#define	timeradd(tvp, uvp, vvp)					\
	do								\
	{								\
		(vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;	\
		if ((vvp)->tv_usec >= 1000000)				\
		{							\
			(vvp)->tv_sec++;				\
			(vvp)->tv_usec -= 1000000;			\
		}							\
	} while ((vvp)->tv_usec >= 1000000)
#define	timersub(tvp, uvp, vvp)					\
	do								\
	{								\
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;	\
		if ((vvp)->tv_usec < 0)					\
		{							\
			(vvp)->tv_sec--;				\
			(vvp)->tv_usec += 1000000;			\
		}							\
	} while ((vvp)->tv_usec >= 1000000)
#else
#define	timeradd(tvp, uvp, vvp)					\
	do								\
	{								\
		(vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;	\
		if ((vvp)->tv_usec >= 1000000)				\
		{							\
			(vvp)->tv_sec++;				\
			(vvp)->tv_usec -= 1000000;			\
		}							\
	} while (0)

#define	timersub(tvp, uvp, vvp)					\
	do								\
	{								\
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;	\
		if ((vvp)->tv_usec < 0)					\
		{							\
			(vvp)->tv_sec--;				\
			(vvp)->tv_usec += 1000000;			\
		}							\
	} while (0)
#endif /* __lint */

#endif /* !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) */

#if !defined(__XOPEN_OR_POSIX) || defined(_XPG4_2) || defined(__EXTENSIONS__)
/*
 * Names of the interval timers, and structure
 * defining a timer setting.
 */
#define	ITIMER_REAL	0	/* Decrements in real time */
#define	ITIMER_VIRTUAL	1	/* Decrements in process virtual time */
#define	ITIMER_PROF	2	/* Decrements both in process virtual */
				/* time and when system is running on */
				/* behalf of the process. */
#define	ITIMER_REALPROF	3	/* Decrements in real time for real- */
				/* time profiling of multithreaded */
				/* programs. */

#ifndef	_ASM
struct	itimerval {
	struct	timeval it_interval;	/* timer interval */
	struct	timeval it_value;	/* current value */
};

#if defined(_SYSCALL32)

struct itimerval32 {
	struct	timeval32 it_interval;
	struct	timeval32 it_value;
};

#define	ITIMERVAL32_TO_ITIMERVAL(itv, itv32)	{	\
	TIMEVAL32_TO_TIMEVAL(&(itv)->it_interval, &(itv32)->it_interval); \
	TIMEVAL32_TO_TIMEVAL(&(itv)->it_value, &(itv32)->it_value);	\
}

#define	ITIMERVAL_TO_ITIMERVAL32(itv32, itv)	{	\
	TIMEVAL_TO_TIMEVAL32(&(itv32)->it_interval, &(itv)->it_interval); \
	TIMEVAL_TO_TIMEVAL32(&(itv32)->it_value, &(itv)->it_value);	\
}

#define	ITIMERVAL_OVERFLOW(itv)				\
	(TIMEVAL_OVERFLOW(&(itv)->it_interval) ||	\
	TIMEVAL_OVERFLOW(&(itv)->it_value))

#endif	/* _SYSCALL32 */
#endif	/* _ASM */
#endif /* !defined(__XOPEN_OR_POSIX) || defined(_XPG4_2) ... */


#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
/*
 *	Definitions for commonly used resolutions.
 */
#define	SEC		1
#define	MILLISEC	1000
#define	MICROSEC	1000000
#define	NANOSEC		1000000000LL

#define	MSEC2NSEC(m)	((hrtime_t)(m) * (NANOSEC / MILLISEC))
#define	NSEC2MSEC(n)	((n) / (NANOSEC / MILLISEC))

#endif /* !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) */

#ifndef	_ASM

/*
 * Time expressed as a 64-bit nanosecond counter.
 */
typedef	longlong_t	hrtime_t;

#if defined(_KERNEL) || defined(_FAKE_KERNEL)

#include <sys/time_impl.h>
#include <sys/mutex.h>

extern int tick_per_msec;	/* clock ticks per millisecond (may be zero) */
extern int msec_per_tick;	/* milliseconds per clock tick (may be zero) */
extern int usec_per_tick;	/* microseconds per clock tick */
extern int nsec_per_tick;	/* nanoseconds per clock tick */

/*
 * Macros to convert from common units of time (sec, msec, usec, nsec,
 * timeval, timestruc) to clock ticks and vice versa.
 */
#define	TICK_TO_SEC(tick)	((tick) / hz)
#define	SEC_TO_TICK(sec)	((sec) * hz)

#define	TICK_TO_MSEC(tick)	\
	(msec_per_tick ? (tick) * msec_per_tick : (tick) / tick_per_msec)
#define	MSEC_TO_TICK(msec)	\
	(msec_per_tick ? (msec) / msec_per_tick : (msec) * tick_per_msec)
#define	MSEC_TO_TICK_ROUNDUP(msec)	\
	(msec_per_tick ? \
	((msec) == 0 ? 0 : ((msec) - 1) / msec_per_tick + 1) : \
	(msec) * tick_per_msec)

#define	TICK_TO_USEC(tick)		((tick) * usec_per_tick)
#define	USEC_TO_TICK(usec)		((usec) / usec_per_tick)
#define	USEC_TO_TICK_ROUNDUP(usec)	\
	((usec) == 0 ? 0 : USEC_TO_TICK((usec) - 1) + 1)

#define	TICK_TO_NSEC(tick)		((hrtime_t)(tick) * nsec_per_tick)
#define	NSEC_TO_TICK(nsec)		((nsec) / nsec_per_tick)
#define	NSEC_TO_TICK_ROUNDUP(nsec)	\
	((nsec) == 0 ? 0 : NSEC_TO_TICK((nsec) - 1) + 1)

#define	TICK_TO_TIMEVAL(tick, tvp) {	\
	clock_t __tmptck = (tick);	\
	(tvp)->tv_sec = TICK_TO_SEC(__tmptck);	\
	(tvp)->tv_usec = TICK_TO_USEC(__tmptck - SEC_TO_TICK((tvp)->tv_sec)); \
}

#define	TICK_TO_TIMEVAL32(tick, tvp) {	\
	clock_t __tmptck = (tick);	\
	time_t __tmptm = TICK_TO_SEC(__tmptck);	\
	(tvp)->tv_sec = (time32_t)__tmptm;	\
	(tvp)->tv_usec = TICK_TO_USEC(__tmptck - SEC_TO_TICK(__tmptm)); \
}

#define	TICK_TO_TIMESTRUC(tick, tsp) {	\
	clock_t __tmptck = (tick);	\
	(tsp)->tv_sec = TICK_TO_SEC(__tmptck);	\
	(tsp)->tv_nsec = TICK_TO_NSEC(__tmptck - SEC_TO_TICK((tsp)->tv_sec)); \
}

#define	TICK_TO_TIMESTRUC32(tick, tsp) {	\
	clock_t __tmptck = (tick);			\
	time_t __tmptm = TICK_TO_SEC(__tmptck);		\
	(tsp)->tv_sec = (time32_t)__tmptm;		\
	(tsp)->tv_nsec = TICK_TO_NSEC(__tmptck - SEC_TO_TICK(__tmptm));	\
}

#define	TIMEVAL_TO_TICK(tvp)	\
	(SEC_TO_TICK((tvp)->tv_sec) + USEC_TO_TICK((tvp)->tv_usec))

#define	TIMESTRUC_TO_TICK(tsp)	\
	(SEC_TO_TICK((tsp)->tv_sec) + NSEC_TO_TICK((tsp)->tv_nsec))

typedef struct todinfo {
	int	tod_sec;	/* seconds 0-59 */
	int	tod_min;	/* minutes 0-59 */
	int	tod_hour;	/* hours 0-23 */
	int	tod_dow;	/* day of week 1-7 */
	int	tod_day;	/* day of month 1-31 */
	int	tod_month;	/* month 1-12 */
	int	tod_year;	/* year 70+ */
} todinfo_t;

extern	int64_t		timedelta;
extern	int		timechanged;
extern	int		tod_needsync;
extern	kmutex_t	tod_lock;
extern	volatile timestruc_t	hrestime;
extern	hrtime_t	hres_last_tick;
extern	int64_t		hrestime_adj;
extern	uint_t		adj_shift;

extern	timestruc_t	tod_get(void);
extern	void		tod_set(timestruc_t);
extern	void		set_hrestime(timestruc_t *);
extern	todinfo_t	utc_to_tod(time_t);
extern	time_t		tod_to_utc(todinfo_t);
extern	int		hr_clock_lock(void);
extern	void		hr_clock_unlock(int);
extern	hrtime_t 	gethrtime(void);
extern	hrtime_t 	gethrtime_unscaled(void);
extern	hrtime_t	gethrtime_max(void);
extern	hrtime_t	gethrtime_waitfree(void);
extern	void		scalehrtime(hrtime_t *);
extern	uint64_t	unscalehrtime(hrtime_t);
extern	void 		gethrestime(timespec_t *);
extern	time_t 		gethrestime_sec(void);
extern	void		gethrestime_lasttick(timespec_t *);
extern	void		hrt2ts(hrtime_t, timestruc_t *);
extern	hrtime_t	ts2hrt(const timestruc_t *);
extern	void		hrt2tv(hrtime_t, struct timeval *);
extern	hrtime_t	tv2hrt(struct timeval *);
extern	int		itimerfix(struct timeval *, int);
extern	int		itimerdecr(struct itimerval *, int);
extern	void		timevaladd(struct timeval *, struct timeval *);
extern	void		timevalsub(struct timeval *, struct timeval *);
extern	void		timevalfix(struct timeval *);
extern	void		dtrace_hres_tick(void);

extern clock_t		ddi_get_lbolt(void);
extern int64_t		ddi_get_lbolt64(void);

#if defined(_SYSCALL32)
extern	void		hrt2ts32(hrtime_t, timestruc32_t *);
#endif

#endif /* _KERNEL */

#if !defined(_KERNEL) && !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
int adjtime(struct timeval *, struct timeval *);
#endif /* !defined(_KERNEL) && !defined(__XOPEN_OR_POSIX) ... */

#if !defined(_KERNEL) && !defined(__XOPEN_OR_POSIX) || \
	defined(_ATFILE_SOURCE) || defined(__EXTENSIONS__)
int futimesat(int, const char *, const struct timeval *);
#endif /* defined(__ATFILE_SOURCE) */

#if !defined(_KERNEL) && !defined(__XOPEN_OR_POSIX) || defined(_XPG4_2) || \
	defined(__EXTENSIONS__)

int getitimer(int, struct itimerval *);
int utimes(const char *, const struct timeval *);
#if defined(_XPG4_2)
int setitimer(int, const struct itimerval *_RESTRICT_KYWD,
	struct itimerval *_RESTRICT_KYWD);
#else
int setitimer(int, struct itimerval *_RESTRICT_KYWD,
	struct itimerval *_RESTRICT_KYWD);
#endif /* defined(_XPG2_2) */

#endif /* !defined(_KERNEL) ... defined(_XPG4_2) */

/*
 * gettimeofday() and settimeofday() were included in SVr4 due to their
 * common use in BSD based applications.  They were to be included exactly
 * as in BSD, with two parameters.  However, AT&T/USL noted that the second
 * parameter was unused and deleted it, thereby making a routine included
 * for compatibility, incompatible.
 *
 * XSH4.2 (spec 1170) defines gettimeofday and settimeofday to have two
 * parameters.
 *
 * This has caused general disagreement in the application community as to
 * the syntax of these routines.  Solaris defaults to the XSH4.2 definition.
 * The flag _SVID_GETTOD may be used to force the SVID version.
 */
#if !defined(_KERNEL) && !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)

#if defined(_SVID_GETTOD)
int settimeofday(struct timeval *);
#else
int settimeofday(struct timeval *, void *);
#endif
hrtime_t	gethrtime(void);
hrtime_t	gethrvtime(void);

#endif /* !(defined _KERNEL) && !defined(__XOPEN_OR_POSIX) ... */

#if !defined(_KERNEL) && !defined(__XOPEN_OR_POSIX) || defined(_XPG4_2) || \
	defined(__EXTENSIONS__)

#if defined(_SVID_GETTOD)
int gettimeofday(struct timeval *);
#else
int gettimeofday(struct timeval *_RESTRICT_KYWD, void *_RESTRICT_KYWD);
#endif

#endif /* !defined(_KERNEL) && !defined(__XOPEN_OR_POSIX) ... */

/*
 * The inclusion of <time.h> is historical and was added for
 * backward compatibility in delta 1.2 when a number of definitions
 * were moved out of <sys/time.h>.  More recently, the timespec and
 * itimerspec structure definitions, along with the _CLOCK_*, CLOCK_*,
 * _TIMER_*, and TIMER_* symbols were moved to <sys/time_impl.h>,
 * which is now included by <time.h>.  This change was due to POSIX
 * 1003.1b-1993 and X/Open UNIX 98 requirements.  For non-POSIX and
 * non-X/Open applications, including this header will still make
 * visible these definitions.
 */
#if !defined(_BOOT) && !defined(_KERNEL) && !defined(_FAKE_KERNEL) && \
	!defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
#include <time.h>
#endif

/*
 * The inclusion of <sys/select.h> is needed for the FD_CLR,
 * FD_ISSET, FD_SET, and FD_SETSIZE macros as well as the
 * select() prototype defined in the XOpen specifications
 * beginning with XSH4v2.  Placement required after definition
 * for itimerval.
 */
#if !defined(_KERNEL) && !defined(_FAKE_KERNEL) && \
	!defined(__XOPEN_OR_POSIX) || \
	defined(_XPG4_2) || defined(__EXTENSIONS__)
#include <sys/select.h>
#endif

#endif	/* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TIME_H */
