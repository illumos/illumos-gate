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
 * tod driver module for Serengeti
 * This module implements a soft tod since
 * Serengeti has no tod part.
 */

#include <sys/modctl.h>
#include <sys/systm.h>
#include <sys/cpuvar.h>
#include <sys/promif.h>
#include <sys/sgsbbc_iosram.h>
#include <sys/todsg.h>
#include <sys/cmn_err.h>
#include <sys/time.h>
#include <sys/sysmacros.h>
#include <sys/clock.h>

#if defined(DEBUG) || defined(lint)
static int todsg_debug = 0;
#define	DCMNERR if (todsg_debug) cmn_err
#else
#define	DCMNERR
#endif /* DEBUG */

#define	OFFSET(base, field)	((char *)&base.field - (char *)&base)
#define	SC_DOWN_COUNT_THRESHOLD	2
#define	SC_TOD_MIN_REV		2

static timestruc_t	todsg_get(void);
static void		todsg_set(timestruc_t);
static uint32_t		todsg_set_watchdog_timer(uint_t);
static uint32_t		todsg_clear_watchdog_timer(void);
static void		todsg_set_power_alarm(timestruc_t);
static void		todsg_clear_power_alarm(void);
static uint64_t		todsg_get_cpufrequency(void);
static int 		update_heartbeat(void);
static int		verify_sc_tod_version(void);
static int 		update_tod_skew(time_t skew);

static uint32_t i_am_alive = 0;
static uint32_t sc_tod_version = 0;
static time_t 	skew_adjust = 0;
static int 	is_sc_down = 0;
static int	adjust_sc_down = 0;

/*
 * Module linkage information for the kernel.
 */
static struct modlmisc modlmisc = {
	&mod_miscops, "Serengeti tod module"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

int
_init(void)
{

	DCMNERR(CE_NOTE, "todsg:_init(): begins");

	if (strcmp(tod_module_name, "todsg") == 0) {
		time_t ssc_time = (time_t)0;
		char obp_string[80];

		/*
		 * To obtain the initial start of day time, we use an
		 * OBP callback; this is because the iosram is not yet
		 * accessible from the OS at this early stage of startup.
		 */

		/*
		 * Set the string to pass to OBP
		 */
		(void) sprintf(obp_string,
			"h# %p \" unix-get-tod\" $find if execute else "
			"3drop then",
			(void *)&ssc_time);

		prom_interpret(obp_string, 0, 0, 0, 0, 0);

		if (ssc_time == (time_t)0) {
			cmn_err(CE_WARN, "Initial date is invalid. "
				"This can be caused by older firmware.");
			cmn_err(CE_CONT, "Please flashupdate the System "
				"Controller firmware to the latest version.\n");
			cmn_err(CE_CONT, "Attempting to set the date and time "
				"based on the last shutdown.\n");
			cmn_err(CE_CONT, "Please inspect the date and time and "
				"correct if necessary.\n");
		}

		hrestime.tv_sec = ssc_time;

		DCMNERR(CE_NOTE, "todsg: _init(): time from OBP 0x%lX",
				ssc_time);
		/*
		 * Verify whether the received date/clock has overflowed
		 * an integer(32bit), so that we capture any corrupted
		 * date from SC, thereby preventing boot failure.
		 */
		if (TIMESPEC_OVERFLOW(&hrestime)) {
			cmn_err(CE_WARN, "Date overflow detected.");
			cmn_err(CE_CONT, "Attempting to set the date and time "
				"based on the last shutdown.\n");
			cmn_err(CE_CONT, "Please inspect the date and time and "
				"correct if necessary.\n");

			/*
			 * By setting hrestime.tv_sec to zero
			 * we force the vfs_mountroot() to set
			 * the date from the last shutdown.
			 */
			hrestime.tv_sec = (time_t)0;
			/*
			 * Save the skew so that we can update
			 * IOSRAM when it becomes accessible.
			 */
			skew_adjust = -ssc_time;
		}

		DCMNERR(CE_NOTE, "todsg:_init(): set tod_ops");

		tod_ops.tod_get = todsg_get;
		tod_ops.tod_set = todsg_set;
		tod_ops.tod_set_watchdog_timer = todsg_set_watchdog_timer;
		tod_ops.tod_clear_watchdog_timer = todsg_clear_watchdog_timer;
		tod_ops.tod_set_power_alarm = todsg_set_power_alarm;
		tod_ops.tod_clear_power_alarm = todsg_clear_power_alarm;
		tod_ops.tod_get_cpufrequency = todsg_get_cpufrequency;
	}

	return (mod_install(&modlinkage));

}

int
_fini(void)
{
	if (strcmp(tod_module_name, "todsg") == 0)
		return (EBUSY);
	else
		return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
update_heartbeat(void)
{
	tod_iosram_t tod_buf;
	int complained = 0;

	/* Update the heartbeat */
	if (i_am_alive == UINT32_MAX)
		i_am_alive = 0;
	else
		i_am_alive++;
	if (iosram_write(SBBC_TOD_KEY, OFFSET(tod_buf, tod_i_am_alive),
			(char *)&i_am_alive, sizeof (uint32_t))) {
		complained++;
		cmn_err(CE_WARN, "update_heartbeat(): write heartbeat failed");
	}
	return (complained);
}

static int
verify_sc_tod_version(void)
{
	uint32_t magic;
	tod_iosram_t tod_buf;

	if (!todsg_use_sc)
		return (FALSE);
	/*
	 * read tod_version only when the first time and
	 * when there has been a previous sc down time
	 */
	if (!sc_tod_version || is_sc_down >= SC_DOWN_COUNT_THRESHOLD) {
		if (iosram_read(SBBC_TOD_KEY, OFFSET(tod_buf, tod_magic),
			(char *)&magic, sizeof (uint32_t)) ||
				magic != TODSG_MAGIC) {
			cmn_err(CE_WARN, "get_sc_tod_version(): "
						"TOD SRAM magic error");
			return (FALSE);
		}
		if (iosram_read(SBBC_TOD_KEY, OFFSET(tod_buf, tod_version),
			(char *)&sc_tod_version, sizeof (uint32_t))) {
			cmn_err(CE_WARN, "get_sc_tod_version(): "
				"read tod version failed");
			sc_tod_version = 0;
			return (FALSE);
		}
	}
	if (sc_tod_version >= SC_TOD_MIN_REV) {
		return (TRUE);
	} else {
		todsg_use_sc = 0;
		cmn_err(CE_WARN,
			"todsg_get(): incorrect firmware version, "
			"(%d): expected version >= %d.",
			sc_tod_version, SC_TOD_MIN_REV);
	}
	return (FALSE);
}

static int
update_tod_skew(time_t skew)
{
	time_t domain_skew;
	tod_iosram_t tod_buf;
	int complained = 0;

	DCMNERR(CE_NOTE, "update_tod_skew(): skew  0x%lX", skew);

	if (iosram_read(SBBC_TOD_KEY, OFFSET(tod_buf, tod_domain_skew),
			(char *)&domain_skew, sizeof (time_t))) {
		complained++;
		cmn_err(CE_WARN, "update_tod_skew(): "
				"read tod domain skew failed");
	}
	domain_skew += skew;
	/* we shall update the skew_adjust too now */
	domain_skew += skew_adjust;
	if (!complained && iosram_write(SBBC_TOD_KEY,
			OFFSET(tod_buf, tod_domain_skew),
				(char *)&domain_skew, sizeof (time_t))) {
		complained++;
		cmn_err(CE_WARN, "update_tod_skew(): "
				"write domain skew failed");
	}
	if (!complained)
		skew_adjust = 0;
	return (complained);
}


/*
 * Return time value read from IOSRAM.
 * Must be called with tod_lock held.
 */
static timestruc_t
todsg_get(void)
{
	tod_iosram_t tod_buf;
	time_t seconds;
	time_t domain_skew;
	int complained = 0;
	static time_t pre_seconds = (time_t)0;

	ASSERT(MUTEX_HELD(&tod_lock));

	if (!verify_sc_tod_version()) {
		/* if we can't use SC */
		goto return_hrestime;
	}
	if (watchdog_activated != 0 || watchdog_enable != 0)
		complained = update_heartbeat();
	if (!complained && (iosram_read(SBBC_TOD_KEY,
			OFFSET(tod_buf, tod_get_value),
			(char *)&seconds, sizeof (time_t)))) {
		complained++;
		cmn_err(CE_WARN, "todsg_get(): read 64-bit tod value failed");
	}
	if (!complained && skew_adjust)  {
		/*
		 * This is our first chance to update IOSRAM
		 * with local copy of the skew,  so update it.
		 */
		complained = update_tod_skew(0);
	}
	if (!complained && iosram_read(SBBC_TOD_KEY,
			OFFSET(tod_buf, tod_domain_skew),
			(char *)&domain_skew, sizeof (time_t))) {
		complained++;
		cmn_err(CE_WARN, "todsg_get(): read tod domain skew failed");
	}

	if (complained) {
		cmn_err(CE_WARN, "todsg_get(): turned off using tod");
		todsg_use_sc = 0;
		goto return_hrestime;
	}

	/*
	 * If the SC gets rebooted, and we are using NTP, then we need
	 * to sync the IOSRAM to hrestime when the SC comes back.  We
	 * can determine that either NTP slew (or date -a) was called if
	 * the global timedelta was non-zero at any point while the SC
	 * was away.  If timedelta remains zero throughout, then the
	 * default action will be to sync hrestime to IOSRAM
	 */
	if (seconds != pre_seconds) {	/* SC still alive */
		pre_seconds = seconds;
		if (is_sc_down >= SC_DOWN_COUNT_THRESHOLD && adjust_sc_down) {
			skew_adjust = hrestime.tv_sec - (seconds + domain_skew);
			complained = update_tod_skew(0);
			if (!complained && (iosram_read(SBBC_TOD_KEY,
				OFFSET(tod_buf, tod_domain_skew),
				(char *)&domain_skew, sizeof (time_t)))) {
				complained++;
				cmn_err(CE_WARN, "todsg_get(): "
					"read tod domain skew failed");
			}
		}
		is_sc_down = 0;
		adjust_sc_down = 0;

		/*
		 * If complained then domain_skew is invalid.
		 * Hand back hrestime instead.
		 */
		if (!complained) {
			timestruc_t ts = {0, 0};
			ts.tv_sec = seconds + domain_skew;
			return (ts);
		} else {
			goto return_hrestime;
		}
	}

	/* SC/TOD is down */
	is_sc_down++;
	if (timedelta != 0) {
		adjust_sc_down = 1;
	}

return_hrestime:
	/*
	 * We need to inform the tod_validate code to stop checking till
	 * SC come back up again. Note that we will return hrestime below
	 * which can be different that the previous TOD value we returned
	 */
	tod_fault_reset();
	return (hrestime);
}

static void
todsg_set(timestruc_t ts)
{
	int complained = 0;
	tod_iosram_t tod_buf;
	time_t domain_skew;
	time_t seconds;
	time_t hwtod;

	ASSERT(MUTEX_HELD(&tod_lock));

	if (!verify_sc_tod_version()) {
		/* if we can't use SC */
		return;
	}
	/*
	 * If the SC is down just note the fact that we should
	 * have adjusted the hardware skew which caters for calls
	 * to stime(). (eg NTP step, as opposed to NTP skew)
	 */
	if (is_sc_down) {
		adjust_sc_down = 1;
		return;
	}
	/*
	 * reason to update i_am_alive here:
	 * To work around a generic Solaris bug that can
	 * cause tod_get() to be starved by too frequent
	 * calls to the stime() system call.
	 */
	if (watchdog_activated != 0 || watchdog_enable != 0)
		complained = update_heartbeat();

	/*
	 * We are passed hrestime from clock.c so we need to read the
	 * IOSRAM for the hardware's idea of the time to see if we need
	 * to update the skew.
	 */
	if (!complained && (iosram_read(SBBC_TOD_KEY,
			OFFSET(tod_buf, tod_get_value),
			(char *)&seconds, sizeof (time_t)))) {
		complained++;
		cmn_err(CE_WARN, "todsg_set(): read 64-bit tod value failed");
	}

	if (!complained && iosram_read(SBBC_TOD_KEY,
			OFFSET(tod_buf, tod_domain_skew),
			(char *)&domain_skew, sizeof (time_t))) {
		complained++;
		cmn_err(CE_WARN, "todsg_set(): read tod domain skew failed");
	}

	/*
	 * Only update the skew if the time passed differs from
	 * what the hardware thinks & no errors talking to SC
	 */
	if (!complained && (ts.tv_sec != (seconds + domain_skew))) {
		hwtod = seconds + domain_skew;
		complained = update_tod_skew(ts.tv_sec - hwtod);

		DCMNERR(CE_NOTE, "todsg_set(): set time %lX (%lX)%s",
			ts.tv_sec, hwtod, complained ? " failed" : "");

	}

	if (complained) {
		cmn_err(CE_WARN, "todsg_set(): turned off using tod");
		todsg_use_sc = 0;
	}
}

static uint32_t
todsg_set_watchdog_timer(uint32_t timeoutval)
{
	tod_iosram_t tod_buf;

	ASSERT(MUTEX_HELD(&tod_lock));

	if (!verify_sc_tod_version()) {
		DCMNERR(CE_NOTE, "todsg_set_watchdog_timer(): "
			"verify_sc_tod_version failed");
		return (0);
	}
	DCMNERR(CE_NOTE, "todsg_set_watchdog_timer(): "
		"set watchdog timer value = %d", timeoutval);

	if (iosram_write(SBBC_TOD_KEY, OFFSET(tod_buf, tod_timeout_period),
			(char *)&timeoutval, sizeof (uint32_t))) {
		DCMNERR(CE_NOTE, "todsg_set_watchdog_timer(): "
			"write new timeout value failed");
		return (0);
	}
	watchdog_activated = 1;
	return (timeoutval);
}

static uint32_t
todsg_clear_watchdog_timer(void)
{
	tod_iosram_t tod_buf;
	uint32_t r_timeout_period;
	uint32_t w_timeout_period;

	ASSERT(MUTEX_HELD(&tod_lock));

	if ((watchdog_activated == 0) || !verify_sc_tod_version()) {
		DCMNERR(CE_NOTE, "todsg_set_watchdog_timer(): "
			"either watchdog not activated or "
			"verify_sc_tod_version failed");
		return (0);
	}
	if (iosram_read(SBBC_TOD_KEY, OFFSET(tod_buf, tod_timeout_period),
			(char *)&r_timeout_period, sizeof (uint32_t))) {
		DCMNERR(CE_NOTE, "todsg_clear_watchdog_timer(): "
			"read timeout value failed");
		return (0);
	}
	DCMNERR(CE_NOTE, "todsg_clear_watchdog_timer(): "
		"clear watchdog timer (old value=%d)", r_timeout_period);
	w_timeout_period = 0;
	if (iosram_write(SBBC_TOD_KEY, OFFSET(tod_buf, tod_timeout_period),
			(char *)&w_timeout_period, sizeof (uint32_t))) {
		DCMNERR(CE_NOTE, "todsg_clear_watchdog_timer(): "
			"write zero timeout value failed");
		return (0);
	}
	watchdog_activated = 0;
	return (r_timeout_period);
}

/*
 * Null function.
 */
/* ARGSUSED */
static void
todsg_set_power_alarm(timestruc_t ts)
{
	ASSERT(MUTEX_HELD(&tod_lock));
}

/*
 * Null function
 */
static void
todsg_clear_power_alarm()
{
	ASSERT(MUTEX_HELD(&tod_lock));
}

/*
 * Get clock freq from the cpunode
 */
uint64_t
todsg_get_cpufrequency(void)
{

	DCMNERR(CE_NOTE, "todsg_get_cpufrequency(): frequency=%ldMHz",
		cpunodes[CPU->cpu_id].clock_freq/1000000);

	return (cpunodes[CPU->cpu_id].clock_freq);
}
