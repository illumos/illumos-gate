/*
 * Copyright (c) David L. Mills 1993, 1994
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted, provided
 * that the above copyright notice appears in all copies and that both the
 * copyright notice and this permission notice appear in supporting
 * documentation, and that the name University of Delaware not be used in
 * advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission.	The University of Delaware
 * makes no representations about the suitability this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 */

/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 1996-1997, 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_TIMEX_H
#define	_SYS_TIMEX_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/inttypes.h>

/*
 * The following defines establish the engineering parameters of the
 * phase-lock loop (PLL) model used in the kernel implementation. These
 * parameters have been carefully chosen by analysis for good stability
 * and wide dynamic range.
 *
 * The hz variable is defined in the kernel build environment. It
 * establishes the timer interrupt frequency.
 *
 * SCALE_KG and SCALE_KF establish the damping of the PLL and are chosen
 * for a slightly underdamped convergence characteristic. SCALE_KH
 * establishes the damping of the FLL and is chosen by wisdom and black
 * art.
 *
 * MAXTC establishes the maximum time constant of the PLL. With the
 * SCALE_KG and SCALE_KF values given and a time constant range from
 * zero to MAXTC, the PLL will converge in 15 minutes to 16 hours,
 * respectively.
 */
#define	SCALE_KG	(1<<6)	/* phase factor (multiplier) */
#define	SCALE_KF	(1<<16)	/* PLL frequency factor (multiplier) */
#define	SCALE_KH	(1<<2)	/* FLL frequency factor (multiplier) */
#define	MAXTC		(1<<6)	/* maximum time constant */


/*
 * The following defines establish the scaling of the various variables
 * used by the PLL. They are chosen to allow the greatest precision
 * possible without overflow of a 32-bit word.
 *
 * SCALE_PHASE defines the scaling (multiplier) of the time_phase variable,
 * which serves as a an extension to the low-order bits of the system
 * clock variable time.tv_usec.
 *
 * SCALE_UPDATE defines the scaling (multiplier) of the time_offset variable,
 * which represents the current time offset with respect to standard
 * time.
 *
 * SCALE_USEC defines the scaling (multiplier) of the time_freq and
 * time_tolerance variables, which represent the current frequency
 * offset and maximum frequency tolerance.
 *
 * FINEUSEC is 1 us in SCALE_UPDATE units of the time_phase variable.
 */
#define	SCALE_PHASE	(1<<22)	/* phase scale */
#define	SCALE_USEC	(1<<16)
#define	SCALE_UPDATE	(SCALE_KG * MAXTC) /*  */
#define	FINEUSEC	(1<<22)	/* 1 us in phase units */

/*
 * The following defines establish the performance envelope of the PLL.
 * They insure it operates within predefined limits, in order to satisfy
 * correctness assertions. An excursion which exceeds these bounds is
 * clamped to the bound and operation proceeds accordingly. In practice,
 * this can occur only if something has failed or is operating out of
 * tolerance, but otherwise the PLL continues to operate in a stable
 * mode.
 *
 * MAXPHASE must be set greater than or equal to CLOCK.MAX (128 ms), as
 * defined in the NTP specification. CLOCK.MAX establishes the maximum
 * time offset allowed before the system time is reset, rather than
 * incrementally adjusted. Here, the maximum offset is clamped to
 * MAXPHASE only in order to prevent overflow errors due to defective
 * protocol implementations.
 *
 * MAXFREQ is the maximum frequency tolerance of the CPU clock
 * oscillator plus the maximum slew rate allowed by the protocol. It
 * should be set to at least the frequency tolerance of the oscillator
 * plus 100 ppm for vernier frequency adjustments. The oscillator time and
 * frequency are disciplined to an external source, presumably with
 * negligible time and frequency error relative to UTC, and MAXFREQ can
 * be reduced.
 *
 * MAXTIME is the maximum jitter tolerance of the PPS signal.
 *
 * MINSEC and MAXSEC define the lower and upper bounds on the interval
 * between protocol updates.
 */
#define	MAXPHASE 512000		/* max phase error (us) */
#define	MAXFREQ (512 * SCALE_USEC) /* max freq error (100 ppm) */
#define	MAXTIME (200 << PPS_AVG) /* max PPS error (jitter) (200 us) */
#define	MINSEC 16		/* min interval between updates (s) */
#define	MAXSEC 1200		/* max interval between updates (s) */

/*
 * The following defines are used only if a pulse-per-second (PPS)
 * signal is available and connected via a modem control lead, such as
 * produced by the optional ppsclock feature incorporated in the Sun
 * asynch driver. They establish the design parameters of the frequency-
 * lock loop used to discipline the CPU clock oscillator to the PPS
 * signal.
 *
 * PPS_AVG is the averaging factor for the frequency loop, as well as
 * the time and frequency dispersion.
 *
 * PPS_SHIFT and PPS_SHIFTMAX specify the minimum and maximum
 * calibration intervals, respectively, in seconds as a power of two.
 *
 * PPS_VALID is the maximum interval before the PPS signal is considered
 * invalid and protocol updates used directly instead.
 *
 * MAXGLITCH is the maximum interval before a time offset of more than
 * MAXTIME is believed.
 */
#define	PPS_AVG 2		/* pps averaging constant (shift) */
#define	PPS_SHIFT 2		/* min interval duration (s) (shift) */
#define	PPS_SHIFTMAX 8		/* max interval duration (s) (shift) */
#define	PPS_VALID 120		/* pps signal watchdog max (s) */
#define	MAXGLITCH 30		/* pps signal glitch max (s) */

/*
 * The following defines and structures define the user interface for
 * the ntp_gettime() and ntp_adjtime() system calls.
 *
 * Control mode codes (timex.modes)
 */
#define	MOD_OFFSET	0x0001	/* set time offset */
#define	MOD_FREQUENCY	0x0002	/* set frequency offset */
#define	MOD_MAXERROR	0x0004	/* set maximum time error */
#define	MOD_ESTERROR	0x0008	/* set estimated time error */
#define	MOD_STATUS	0x0010	/* set clock status bits */
#define	MOD_TIMECONST	0x0020	/* set pll time constant */
#define	MOD_CLKB	0x4000	/* set clock B */
#define	MOD_CLKA	0x8000	/* set clock A */

/*
 * Status codes (timex.status)
 */
#define	STA_PLL		0x0001	/* enable PLL updates (rw) */
#define	STA_PPSFREQ	0x0002	/* enable PPS freq discipline (rw) */
#define	STA_PPSTIME	0x0004	/* enable PPS time discipline (rw) */
#define	STA_FLL		0x0008	/* select frequency-lock mode (rw) */

#define	STA_INS		0x0010	/* insert leap (rw) */
#define	STA_DEL		0x0020	/* delete leap (rw) */
#define	STA_UNSYNC	0x0040	/* clock unsynchronized (rw) */
#define	STA_FREQHOLD	0x0080	/* hold frequency (rw) */

#define	STA_PPSSIGNAL	0x0100	/* PPS signal present (ro) */
#define	STA_PPSJITTER	0x0200	/* PPS signal jitter exceeded (ro) */
#define	STA_PPSWANDER	0x0400	/* PPS signal wander exceeded (ro) */
#define	STA_PPSERROR	0x0800	/* PPS signal calibration error (ro) */

#define	STA_CLOCKERR	0x1000	/* clock hardware fault (ro) */

#define	STA_RONLY (STA_PPSSIGNAL | STA_PPSJITTER | STA_PPSWANDER | \
    STA_PPSERROR | STA_CLOCKERR) /* read-only bits */

/*
 * Clock states (time_state)
 */
#define	TIME_OK		0	/* no leap second warning */
#define	TIME_INS	1	/* insert leap second warning */
#define	TIME_DEL	2	/* delete leap second warning */
#define	TIME_OOP	3	/* leap second in progress */
#define	TIME_WAIT	4	/* leap second has occured */
#define	TIME_ERROR	5	/* clock not synchronized */

/*
 * NTP user interface (ntp_gettime()) - used to read kernel clock values
 *
 * Note: maximum error = NTP synch distance = dispersion + delay / 2;
 * estimated error = NTP dispersion.
 */
struct ntptimeval {
	struct timeval time;	/* current time (ro) */
	int32_t maxerror;	/* maximum error (us) (ro) */
	int32_t esterror;	/* estimated error (us) (ro) */
};

#if defined(_SYSCALL32)

/* Kernel's view of _ILP32 application's ntptimeval struct */

struct ntptimeval32 {
	struct timeval32 time;
	int32_t	maxerror;
	int32_t esterror;
};

#endif	/* _SYSCALL32 */

/*
 * NTP daemon interface - (ntp_adjtime()) used to discipline CPU clock
 * oscillator
 */
struct timex {
	uint32_t modes;		/* clock mode bits (wo) */
	int32_t offset;		/* time offset (us) (rw) */
	int32_t freq;		/* frequency offset (scaled ppm) (rw) */
	int32_t maxerror;	/* maximum error (us) (rw) */
	int32_t esterror;	/* estimated error (us) (rw) */
	int32_t status;		/* clock status bits (rw) */
	int32_t constant;	/* pll time constant (rw) */
	int32_t precision;	/* clock precision (us) (ro) */
	int32_t tolerance;	/* clock freq tolerance (scaled ppm) (ro) */
	int32_t ppsfreq;	/* pps frequency (scaled ppm) (ro) */
	int32_t jitter;		/* pps jitter (us) (ro) */
	int32_t shift;		/* interval duration (s) (shift) (ro) */
	int32_t stabil;		/* pps stability (scaled ppm) (ro) */
	int32_t jitcnt;		/* jitter limit exceeded (ro) */
	int32_t calcnt;		/* calibration intervals (ro) */
	int32_t errcnt;		/* calibration errors (ro) */
	int32_t stbcnt;		/* stability limit exceeded (ro) */
};

/*
 * NTP syscalls
 */
int ntp_gettime(struct ntptimeval *);
int ntp_adjtime(struct timex *);

#ifdef _KERNEL

extern int32_t time_state;	/* clock state */
extern int32_t time_status;	/* clock status bits */
extern int32_t time_offset;	/* time adjustment (us) */
extern int32_t time_freq;	/* frequency offset (scaled ppm) */
extern int32_t time_maxerror;	/* maximum error (us) */
extern int32_t time_esterror;	/* estimated error (us) */
extern int32_t time_constant;	/* pll time constant */
extern int32_t time_precision;	/* clock precision (us) */
extern int32_t time_tolerance;	/* frequency tolerance (scaled ppm) */
extern int32_t pps_shift;	/* interval duration (s) (shift) */
extern int32_t pps_freq;	/* pps frequency offset (scaled ppm) */
extern int32_t pps_jitter;	/* pps jitter (us) */
extern int32_t pps_stabil;	/* pps stability (scaled ppm) */
extern int32_t pps_jitcnt;	/* jitter limit exceeded */
extern int32_t pps_calcnt;	/* calibration intervals */
extern int32_t pps_errcnt;	/* calibration errors */
extern int32_t pps_stbcnt;	/* stability limit exceeded */

extern void clock_update(int);
extern void ddi_hardpps(struct timeval *, int);

#endif /* _KERNEL */


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TIMEX_H */
