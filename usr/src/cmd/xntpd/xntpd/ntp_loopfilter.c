/*
 * Copyright 1996, 1999-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ntp_loopfilter.c - implements the NTP loop filter algorithm
 *
 */
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <ctype.h>
#include <sys/time.h>


#include <signal.h>
#include <errno.h>
#include <setjmp.h>
#include "ntpd.h"
#include "ntp_io.h"
#include "ntp_unixtime.h"
#include "ntp_stdlib.h"

#if defined(VMS) && defined(VMS_LOCALUNIT)	/*wjm*/
#include "ntp_refclock.h"
#endif /* VMS */
#ifdef KERNEL_PLL
#include <sys/timex.h>
#ifdef NTP_SYSCALLS_STD
#define ntp_gettime(t)  syscall(SYS_ntp_gettime, (t))
#define ntp_adjtime(t)  syscall(SYS_ntp_adjtime, (t))
#else /* NOT NTP_SYSCALLS_STD */
#ifdef HAVE___NTP_GETTIME
#define ntp_gettime(t)  __ntp_gettime((t))
#endif /* HAVE___NTP_GETTIME */
#ifdef HAVE___ADJTIMEX
#define ntp_adjtime(t)  __adjtimex((t))
#endif
#endif /* NOT NTP_SYSCALLS_STD */

#endif /* KERNEL_PLL */

/*
 * The loop filter is implemented in slavish adherence to the
 * specification (Section 5), except that for consistency we
 * mostly carry the quantities in the same units as appendix G.
 *
 * Kernel PLL/PPS state machine
 *
 * The following state machine is used when the kernel PLL modifications
 * described in the README.kernel file are present.
 *
 * Each update to a prefer peer sets pps_update true if it survives the
 * intersection algorithm and its time is within range. The PPS time
 * discipline is enabled (STA_PPSTIME bit set in the status word) when
 * pps_update is true and the PPS frequency discipline is enabled. If
 * the PPS time discipline is enabled and the kernel reports a PPS
 * signal is present, the pps_control variable is set to the current
 * time. If the current time is later than pps_control by PPS_MAXAGE
 * (120 s), this variable is set to zero.
 *
 * The pll_enable switch can be set both at configuration time and at
 * run time using xntpdc. If true, the kernel modifications are active
 * as described above; if false, the kernel is bypassed entirely (except
 * for the PPS frequency update, if enabled) and the daemon PLL used
 * instead. 
 */
#define RSH_DRIFT_TO_ADJ (CLOCK_DSCALE - 16)
#define RSH_FRAC_TO_FREQ (CLOCK_FREQ - RSH_DRIFT_TO_ADJ)
#define PPS_MAXAGE 120		/* kernel pps signal timeout (s) */

/*
 * Program variables
 */
l_fp last_offset;		/* last clock offset */
u_long last_time;		/* time of last clock update (s) */
u_fp clock_stability;		/* clock stability (ppm) */
s_fp clock_frequency;		/* clock frequency error (ppm) */
s_fp drift_comp;		/* pll frequency (ppm) */
static long clock_adjust;	/* clock adjust (fraction only) */
static int time_constant;	/* pll time constant */
static s_fp max_comp;		/* max frequency offset (ppm) */
int tc_counter;			/* poll-adjust counter */
int pll_status;			/* status bits for kernel pll */
volatile int pll_control;	/* true if working kernel pll */
int pll_enable;			/* true if pll enabled */
u_long pps_control;		/* last pps sample time */
int pps_update;			/* pps update valid */
int fdpps = -1;			/* pps file descriptor */
int pps_enable;			/* pps disabled by default */
char cutout;			/* override for max capture range */
extern	l_fp sys_clock_offset;	/* correction for current system time */

/*
 * Imported from the ntp_proto module
 */
extern s_fp sys_rootdelay;	/* root delay */
extern u_fp sys_rootdispersion;	/* root dispersion */
extern struct peer *sys_peer;	/* system peer pointer */
extern u_char sys_poll;		/* log2 of system poll interval */
extern u_char sys_leap;		/* system leap bits */
extern l_fp sys_refskew;	/* accumulated skew since last update */
extern u_fp sys_maxd[];		/* total dispersion history */

/*
 * Imported from ntp_io.c
 */
extern struct interface *loopback_interface;

/*
 * Imported from ntpd module
 */
extern int debug;		/* global debug flag */
extern int correct_any;

/*
 * Imported from timer module
 */
extern u_long current_time;	/* like it says, in seconds */

/*
 * Imported from leap module
 */
extern u_char leapbits;		/* sanitized leap bits */

extern int slewalways;

#if defined(KERNEL_PLL)
#define MOD_BITS (MOD_OFFSET | MOD_MAXERROR | MOD_ESTERROR | \
   MOD_STATUS | MOD_TIMECONST)
#ifdef NTP_SYSCALLS_STD
#ifdef DECL_SYSCALL
	extern int syscall	P((int, void *, ...));
#endif /* DECL_SYSCALL */
#endif /* NTP_SYSCALLS_STD */
void pll_trap		P((int));
#ifdef SIGSYS
static struct sigaction sigsys;	/* current sigaction status */
static struct sigaction newsigsys; /* new sigaction status */
static sigjmp_buf env;		/* environment var. for pll_trap() */
#endif /* SIGSYS */
#endif /* KERNEL_PLL */
#if defined(GDT_SURVEYING)
extern long sys_clock;		/* imported from ntp_proto */
extern l_fp gdt_rsadj;		/* running sum of adjustments to time */
#endif /* GDT_SURVEYING */

/*
 * init_loopfilter - initialize loop filter data
 */
void
init_loopfilter()
{
extern u_long tsf_maxslew;
u_long tsf_limit;

	/*
	 * Limit for drift_comp, minimum of two values. The first is to
	 * avoid signed overflow, the second to keep within 75% of the
	 * maximum adjustment possible in adj_systime().
	 */
	max_comp = 0x7fff0000;
#if defined(SCO3_TICKADJ) || defined(SCO5_TICKADJ)
	tsf_limit = tsf_maxslew;
#else
	tsf_limit = ((tsf_maxslew >> 1) + (tsf_maxslew >> 2));
#endif /* not SCO[35]_TICKADJ */
	if ((max_comp >> RSH_DRIFT_TO_ADJ) > (s_fp) tsf_limit)
		max_comp = tsf_limit << RSH_DRIFT_TO_ADJ;

	/*
	 * Reset clockworks
	 */
	drift_comp = 0;
	clock_adjust = 0;
	tc_counter = 0;
	sys_poll = NTP_MINPOLL;

	last_time = 0;
	clock_frequency = 0;
	clock_stability = 0;
	pps_update = pps_control = 0;
}

/*
 * local_clock - the NTP logical clock loop filter.  Returns 1 if the
 *	clock was stepped, 0 if it was slewed and -1 if it is hopeless.
 */
int
local_clock(fp_offset, peer, fastset)
	l_fp *fp_offset;	/* best offset estimate */
	struct peer *peer;	/* synch source peer structure */
	int fastset;		/* from ntp_proto - just left unsynch
				   state */
{
	long offset;
	long tmp;
	l_fp ftmp;
	s_fp stmp;
	long interval;
#if defined(KERNEL_PLL)
	struct timex ntv;
#endif /* KERNEL_PLL */

	if (last_time == 0)
		last_time = current_time;
	interval = current_time - last_time;
	 if (interval < 1)
		interval = 1;
	time_constant = min(peer->ppoll, sys_poll) - 4;
	clock_adjust = 0;
	offset = fp_offset->l_f;

#ifdef DEBUG
	if (debug > 1)
		printf(
		    "local_clock: offset %s peer %s interval %ld cutout %d)\n",
		    lfptoa(fp_offset, 6), ntoa(&peer->srcadr), interval,
		    cutout);
#endif

	/*
	 * If the clock is way off, don't tempt fate by correcting it.
	 */
	ftmp = *fp_offset;
	if (L_ISNEG(&ftmp))
		L_NEG(&ftmp);
	if (ftmp.l_ui >= CLOCK_WAYTOOBIG && !correct_any) {
		msyslog(LOG_ERR,
 		    "time error %s is way too large (set clock manually)",
		     lfptoa(fp_offset, 6));
		return (-1);

	/*
	 * If the magnitude of the offset is greater than CLOCK_MAX (128
	 * ms), reset the poll interval and wait for further
	 * instructions. Note that the cutout switch is set when the
	 * time is stepped, possibly because the frequency error is off
	 * planet. In that case all sanity checks are disabled and the
	 * discipine loop is on its own. Presumably, the loop will
	 * eventually capture the wayward oscillator (if less than 500
	 * ppm off planet) and converge, which will then reset the
	 * cutout switch.
	 */
	} else if (ftmp.l_ui > CLOCK_MAX_I || ftmp.l_f < 0
		   || (ftmp.l_ui == CLOCK_MAX_I && ftmp.l_uf >= CLOCK_MAX_F
		       && !cutout)) {
		tc_counter = 0;
		sys_poll = peer->minpoll;

		/*
		 * Either we are not in synchronization, or we have gone
		 * CLOCK_MINSTEP (900 s) since the last acceptable
		 * update. We step the clock and leave the frequency
		 * alone. Since the clock filter has been reset, the
		 * dispersions will be high upon recovery. The cutout
		 * switch will prevent the usual sanity checks in the
		 * interest of snatching a possibly wayward oscillator.
		 * Chez nous silicon.
		 */
		if (fastset || interval > CLOCK_MINSTEP) {
			step_systime(fp_offset);
			NLOG(NLOG_SYNCEVENT|NLOG_SYSEVENT)
			    msyslog(LOG_NOTICE, "time reset (%s) %s s",
			    slewalways ? "slew" : "step",
			    lfptoa(fp_offset, 6));
			cutout = 1;
			L_CLR(&last_offset);
			last_time = current_time;
			return (1);

		/*
		 * The local clock is out of range, but we haven't
		 * allowed enough time for the peer (usually a radio
		 * clock) to recover after a leap second. Pretend we wuz
		 * never here.
		 */
		} else {
			return (0);
		}

	/*
	 * This code segment works when the clock-adjustment code is
	 * implemented in the kernel, which at present is only in the
	 * (modified) HP 9, SunOS 4, Ultrix 4 and OSF/1 kernels. In the
	 * case of the DECstation 5000/240 and Alpha AXP, additional
	 * kernel modifications provide a true microsecond clock. We
	 * know the scaling of the frequency variable (s_fp) is the same
	 * as the kernel variable (1 << SHIFT_USEC = 16).
	 */
#if defined(KERNEL_PLL)
	} else if (pll_control && pll_enable) {
		l_fp pps_offset;
		u_fp pps_dispersion;

		/*
		 * We initialize the structure for the ntp_adjtime()
		 * system call. We have to convert everything to
		 * microseconds first. Afterwards, remember the
		 * frequency offset for the drift file.
		 */
		memset((char *)&ntv,  0, sizeof ntv);
		ntv.modes = MOD_BITS;
		if (offset >= 0) {
			TSFTOTVU(offset, ntv.offset);
		} else {
			TSFTOTVU(-offset, ntv.offset);
			ntv.offset = -ntv.offset;
		}
		ntv.esterror = sys_rootdispersion << 4;
		ntv.maxerror = ntv.esterror + (sys_rootdelay << 2);
		ntv.constant = min(peer->ppoll, sys_poll) - 4;
		ntv.status = STA_PLL;
		if (pps_enable)
			ntv.status |= STA_PPSFREQ;
		if (pps_update && pps_enable)
			ntv.status |= STA_PPSTIME;

		/*
		 * Set the leap bits in the status word.
		 */
		if (sys_leap & LEAP_ADDSECOND && sys_leap & LEAP_DELSECOND)
			ntv.status |= STA_UNSYNC;
		else if (sys_leap & LEAP_ADDSECOND)
			ntv.status |= STA_INS;
		else if (sys_leap & LEAP_DELSECOND)
			ntv.status |= STA_DEL;

		/*
		 * This astonishingly intricate wonder juggles the
		 * status bits so that the kernel loop behaves as the
		 * daemon loop; viz., selects the FLL when necessary,
		 * etc. See the comments following the #endif for
		 * explanation.
		 */
		if (sys_maxd[0] > CLOCK_MAX_FP && !cutout)
			ntv.status |= STA_FLL | STA_FREQHOLD;
		else if (sys_maxd[0] > sys_maxd[1] + sys_maxd[2] &&
		     !cutout)
			return (0);
		else if (interval >= CLOCK_MAXSEC && peer->maxpoll > 10)
			ntv.status |= STA_FLL;
		if (ntp_adjtime(&ntv) == TIME_ERROR)
			if (ntv.status != pll_status)
				msyslog(LOG_ERR,
				    "kernel pll status change %x",
				    ntv.status);
		drift_comp = ntv.freq;
		pll_status = ntv.status;

		/*
		 * If the kernel pps discipline is working, monitor its
		 * performance.
		 */
		if (pll_status & STA_PPSTIME && pll_status &
		    STA_PPSSIGNAL && ntv.shift)	{
			if (ntv.offset >= 0)
				TVUTOTSF(ntv.offset, offset);
			else {
				TVUTOTSF(-ntv.offset, offset);
				offset = -offset;
			}
		L_CLR(&pps_offset);
		L_ADDF(&pps_offset, offset);
		TVUTOTSF(ntv.jitter, tmp);
		pps_dispersion = (tmp >> 16) & 0xffff;
		if (!pps_control)
			NLOG(NLOG_SYSEVENT) /* conditional syslog */
			    msyslog(LOG_INFO, "pps sync enabled");
		pps_control = current_time;
		record_peer_stats(&loopback_interface->sin,
		    ctlsysstatus(), fp_offset, 0, pps_dispersion);
	}
#endif /* KERNEL_PLL */

	/*
	 * If the noise exceeds CLOCK_MAX_FP (128 ms), just set the
	 * clock and leave the frequency alone.
	 */
	} else if (sys_maxd[0] > CLOCK_MAX_FP && !cutout) {
#if DEBUG
		if (debug)
			printf("local_clock: dispersion exceeded %s\n",
			    ufptoa(sys_maxd[0], 5));
#endif /* DEBUG */

	/*
	 * If the noise has increased substantially over previous
	 * values, consider it a spike and ignore it. The factor of two
	 * is hard-coded.
	 */
	} else if (sys_maxd[0] > sys_maxd[1] + sys_maxd[2] && !cutout) {
#if DEBUG
		if (debug)
			printf("local_clock: spike ignored %s\n",
			    ufptoa(sys_maxd[0], 5));
#endif /* DEBUG */
		return (0);

	/*
	 * If this is the local-clock reference driver, we don't want to
	 * fidget the frequency, just fall out of the conditional and
	 * set the time.
	 */
	} else if (peer->refclktype == REFCLK_LOCALCLOCK) {

	/*
	 * If the interval between corrections is less than the Allan
	 * variance intercept point, we use a phase-lock loop to compute
	 * new values of time and frequency. The bandwidth is controlled
	 * by the time constant, which is adjusted in response to the
	 * phase error and dispersion.
	 */ 
	} else if (interval < CLOCK_MAXSEC
		   || peer->maxpoll <= NTP_MAXDPOLL) {
		long ltmp = interval;

		tmp = NTP_MAXDPOLL;
		while (ltmp < (1 << NTP_MAXDPOLL)) {
			tmp--;
			ltmp <<= 1;
		}
		tmp = RSH_FRAC_TO_FREQ - tmp + time_constant + time_constant;
		if (offset < 0)
			drift_comp -= -offset >> tmp;
		else
			drift_comp += offset >> tmp;

	/*
	 * If the interval between corrections is greater than the Allan
	 * variance intercept point, we use a hybrid frequency-lock loop
	 * to compute new values of phase and frequency. The following
	 * code is based on ideas suggested by Judah Levine of NIST and
	 * used in his "lockclock" implementation of ACTS. The magic
	 * factor of 4 in the left shift is to convert from s_fp to ppm.
	 */
	} else {
		time_constant = 2;
		stmp = (offset / interval) << 4;
		if (stmp < 0)
			drift_comp -= -stmp >> CLOCK_G;
		else
			drift_comp += stmp >> CLOCK_G;
	}
	clock_adjust = offset;

	/*
	 * As a sanity check, we clamp the frequency not to exceed the
	 * slew rate of the stock Unix adjtime() system call. Kick off
	 * the cutout switch if the dispersion falls below CLOCK_MAX_FP
	 * (128 ms).
	 */
	if (drift_comp > max_comp)
		drift_comp = max_comp;
	else if (drift_comp < -max_comp)
		drift_comp = -max_comp;
	stmp = LFPTOFP(fp_offset);
	if (stmp < 0)
		stmp = -stmp;
	if (stmp < CLOCK_MAX_FP)
		cutout = 0;
	if (interval > (1 << (peer->minpoll - 1))) {

		/*
		 * Determine when to adjust the poll interval. We do
		 * this regardless of what source controls the loop,
		 * since we might flap back and forth between sources.
		 */
		if (stmp > (s_fp)sys_maxd[0]) {
			tc_counter -= (int)sys_poll << 1;
			if (tc_counter < -CLOCK_LIMIT) {
				tc_counter = -CLOCK_LIMIT;
				if (sys_poll > peer->minpoll) {
					sys_poll--;
					tc_counter = 0;
				}
			}
		} else {
			tc_counter += (int)sys_poll;
			if (tc_counter > CLOCK_LIMIT) {
				tc_counter = CLOCK_LIMIT;
				if (sys_poll < peer->maxpoll) {
					sys_poll++;
					tc_counter = 0;
			}
		}
	}

	/*
	 * Calculate the frequency offset and frequency
	 * stability. These are useful for performance
	 * monitoring, but do not affect the loop variables. The
	 * results are scaled as a s_fp in ppm, because we know
	 * more than we should.
	 */
	ftmp = *fp_offset;
	L_SUB(&ftmp, &last_offset);
	clock_frequency = (LFPTOFP(&ftmp) / interval) << 20;
	if (clock_frequency < -max_comp)
		clock_frequency = -max_comp;
	else if (clock_frequency > max_comp)
		clock_frequency = max_comp;
	stmp = clock_frequency;
	if (stmp < 0)
		stmp = -stmp;
	stmp -= clock_stability;
	if (stmp < 0)
		clock_stability -= -stmp >> NTP_MAXD;
	else
		clock_stability += stmp >> NTP_MAXD;
	}
	last_offset = *fp_offset;
	last_time = current_time;
#ifdef DEBUG
	if (debug > 1)
		printf(
		    "local_clock: phase %s freq %s disp %s poll %d count %d\n",
		    mfptoa((clock_adjust < 0 ? -1 : 0), clock_adjust, 6),
		    fptoa(drift_comp, 3), fptoa(sys_maxd[0], 5),
		    sys_poll, tc_counter);
#endif /* DEBUG */

	(void) record_loop_stats(fp_offset, drift_comp, (unsigned)sys_poll);
	
	/*
	 * Whew. I've had enough.
	 */
	return (0);
}


/*
 * adj_host_clock - Called once every second to update the local clock.
 */
void
adj_host_clock()
{
	register long adjustment;
	l_fp offset;

	/*
	 * Update the dispersion since the last update. Don't allow
	 * frequency measurements over periods longer than NTP_MAXAGE
	 * (86400 s = one day).
	 */
	if (current_time - last_time > NTP_MAXAGE)
		last_time = 0;
	L_ADDUF(&sys_refskew, NTP_SKEWINC);

	/*
	 * Declare PPS kernel unsync if the pps signal has not been
	 * heard for a few minutes.
	 */
	if (pps_control && current_time - pps_control > PPS_MAXAGE) {
		if (pps_control)
		    NLOG(NLOG_SYSEVENT) /* conditional if clause */
		    msyslog(LOG_INFO, "pps sync disabled");
		pps_control = 0;
	}

 	/*
 	 * If the phase-lock loop is not implemented in the kernel, we
	 * do it the hard way using incremental adjustments and the
	 * adjtime() system call.
	 */
	if (pll_control && pll_enable) {
		if (L_ISZERO(&sys_clock_offset)) {
			return;
		}
	}
	adjustment = clock_adjust;
	if (adjustment < 0)
		adjustment = -(-adjustment >> (CLOCK_PHASE + time_constant));
	else
		adjustment >>= CLOCK_PHASE + time_constant;
	clock_adjust -= adjustment;
	if (drift_comp < 0)
		adjustment -= -drift_comp >> RSH_DRIFT_TO_ADJ;
	else
		adjustment += drift_comp >> RSH_DRIFT_TO_ADJ;

	/*
	 * Intricate wrinkle. If the local clock driver is in use and
	 * selected for synchronization, somebody else may be tinker the
	 * adjtime() syscall. In this case we have to avoid calling
	 * adjtime(), since that may truncate the other guy's requests.
	 * That means the local clock fudge time and frequency
	 * adjustments don't work in that case. Caveat empty.
	 */
	if (sys_peer) {
		if (sys_peer->refclktype == REFCLK_LOCALCLOCK &&
		    sys_peer->flags & FLAG_PREFER) {
                       /* I think that sys_clock_offset might be jammed
                        * to exactly zero now.  It might have had a
                        * small residual before things switched to the
                        * local refclock prefer at lower stratum, or a
                        * glitch might have happened during interrupts
                        * when the external control jumped the time */
	                L_CLR(&sys_clock_offset);
			return;
		}
 	}
	L_CLR(&offset);
	L_ADDF(&offset, adjustment);
	adj_systime(&offset);
}


/*
 * adj_frequency - adjust local clock frequency
 */
void
adj_frequency(freq)
     s_fp freq;			/* frequency (ppm) */
{
#if defined(KERNEL_PLL)
	struct timex ntv;
#endif /* KERNEL_PLL */

	/*
	 * This routine adjusts the frequency offset. It is used by the
	 * local clock driver to adjust frequency when no external
	 * discipline source is available and by the acts driver when
	 * the interval between updates is greater than 1 << NTP_MAXPOLL.
	 * Note that the maximum offset is limited by max_comp when
	 * the daemon pll is used, but the maximum may be different
	 * when the kernel pll is used.
	 */
	drift_comp += freq;
	if (drift_comp > max_comp)
		drift_comp = max_comp;
	else if (drift_comp < -max_comp)
		drift_comp = -max_comp;
#if defined(KERNEL_PLL)
	/*
	 * If the phase-lock code is implemented in the kernel, set the
	 * kernel frequency as well, but be sure to set drift_comp to
	 * the actual frequency.
	 */
	if (!(pll_control && pll_enable))
		return;
	memset((char *)&ntv, 0, sizeof ntv);
	ntv.modes = MOD_FREQUENCY;
	ntv.freq = freq + drift_comp;
	if (ntp_adjtime(&ntv) < 0)
		msyslog(LOG_ERR,
		    "adj_frequency: ntp_adjtime failed: %m");
	drift_comp = ntv.freq;
#endif /* KERNEL_PLL */
}


/*
 * loop_config - configure the loop filter
 */
void
loop_config(item, lfp_value)
	int item;
	l_fp *lfp_value;
{
#if defined(KERNEL_PLL)
	struct timex ntv;
#endif /* KERNEL_PLL */

#ifdef DEBUG
	if (debug)
		printf("loop_config %d %s\n",
		    item, lfptoa(lfp_value, 3));
#endif
	switch (item) {

	case LOOP_DRIFTCOMP:
		drift_comp = LFPTOFP(lfp_value);
		if (drift_comp > max_comp)
			drift_comp = max_comp;
		if (drift_comp < -max_comp)
			drift_comp = -max_comp;

#if defined(KERNEL_PLL)
		/*
		 * If the phase-lock code is implemented in the kernel,
		 * give the time_constant and saved frequency offset to
		 * the kernel. If not, no harm is done. We do this
		 * whether or not the use of the kernel mods is
		 * requested, in order to clear out the trash from
		 * possible prior customers.
		 */
		memset((char *)&ntv, 0, sizeof ntv);
		pll_control = 1;
		ntv.modes = MOD_BITS | MOD_FREQUENCY;
		ntv.freq = drift_comp;
		ntv.maxerror = NTP_MAXDISPERSE;
		ntv.esterror = NTP_MAXDISPERSE;
		ntv.status = STA_PLL | STA_UNSYNC;
		ntv.constant = sys_poll - 4;
#ifdef SIGSYS
		newsigsys.sa_handler = pll_trap;
		newsigsys.sa_flags = 0;
		if ((sigaction(SIGSYS, &newsigsys, &sigsys)))
		msyslog(LOG_ERR,
		    "sigaction() fails to save SIGSYS trap: %m");

		/*
		 * Note ntp_adjtime() normally fails on the first call,
		 * since we deliberately set the clock unsynchronized.
		 * Use sigsetjmp() to save state and then call
		 * ntp_adjtime(); if it fails, then siglongjmp() is used
		 * to return control
		 */
		if (sigsetjmp(env, 1) == 0) {
#endif /* SIGSYS */
			if (ntp_adjtime(&ntv) < 0) {
				msyslog(LOG_ERR,
				    "loop_config: ntp_adjtime() failed: %m");
			}
#ifdef SIGSYS
		}
		if ((sigaction(SIGSYS, &sigsys, (struct sigaction
		    *)NULL)))
			msyslog(LOG_ERR,
			    "sigaction() fails to restore SIGSYS trap: %m");
#endif /* SIGSYS */
		if (pll_control)
			msyslog(LOG_NOTICE,
			    "using kernel phase-lock loop %04x,"
			    " drift correction %s",
			    ntv.status, fptoa(NTOHS_FP(ntv.freq), 5));
		else
			msyslog(LOG_NOTICE,
			    "using xntpd phase-lock loop");
#endif /* KERNEL_PLL */
		break;

	default:
		/* sigh */
		break;
	}
}


#if defined(KERNEL_PLL) && defined(SIGSYS)
/*
 * _trap - trap processor for undefined syscalls
 *
 * This nugget is called by the kernel when the SYS_ntp_adjtime()
 * syscall bombs because the silly thing has not been implemented in
 * the kernel. In this case the phase-lock loop is emulated by
 * the stock adjtime() syscall and a lot of indelicate abuse.
 */
RETSIGTYPE
pll_trap(arg)
	int arg;
{
	pll_control = 0;
	siglongjmp(env, 1);
}
#endif /* KERNEL_PLL && SIGSYS */
