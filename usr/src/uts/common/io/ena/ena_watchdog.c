/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2024 Oxide Computer Company
 */

#include "ena_hw.h"
#include "ena.h"

bool ena_force_reset = false;

static void
ena_watchdog(void *arg)
{
	ena_t *ena = arg;
	uint32_t statusreg;
	enum {
		RESET_NONE = 0,
		RESET_FORCED,
		RESET_ERROR,
		RESET_FATAL,
		RESET_KEEPALIVE,
		RESET_TX_STALL,
	} reset = RESET_NONE;

	if (ena_force_reset) {
		ena_force_reset = false;
		reset = RESET_FORCED;
		goto out;
	}

	if (ena->ena_state & ENA_STATE_ERROR) {
		atomic_and_32(&ena->ena_state, ~ENA_STATE_ERROR);
		reset = RESET_ERROR;
		goto out;
	}

	statusreg = ena_hw_bar_read32(ena, ENAHW_REG_DEV_STS);
	if ((statusreg & ENAHW_DEV_STS_FATAL_ERROR_MASK) >>
	    ENAHW_DEV_STS_FATAL_ERROR_SHIFT != 0) {
		reset = RESET_FATAL;
		goto out;
	}

	if (ena->ena_watchdog_last_keepalive > 0 &&
	    gethrtime() - ena->ena_watchdog_last_keepalive >
	    ENA_DEVICE_KEEPALIVE_TIMEOUT_NS) {
		reset = RESET_KEEPALIVE;
		goto out;
	}

	bool stalled = false;
	uint_t stalledq = 0;
	for (uint_t i = 0; i < ena->ena_num_txqs; i++) {
		ena_txq_t *txq = &ena->ena_txqs[i];
		uint32_t s;

		mutex_enter(&txq->et_lock);
		if (txq->et_blocked)
			s = ++txq->et_stall_watchdog;
		else
			s = txq->et_stall_watchdog = 0;
		mutex_exit(&txq->et_lock);

		if (s > ENA_TX_STALL_TIMEOUT) {
			stalled = true;
			stalledq = i;
			break;
		}
	}
	if (stalled) {
		reset = RESET_TX_STALL;
		goto out;
	}

out:
	if (reset != RESET_NONE) {
		enahw_reset_reason_t reason;

		mutex_enter(&ena->ena_lock);
		switch (reset) {
		case RESET_FORCED:
			ena->ena_device_stat.eds_reset_forced.value.ui64++;
			ena_err(ena, "forced reset");
			reason = ENAHW_RESET_USER_TRIGGER;
			break;
		case RESET_ERROR:
			/*
			 * Whoever set the error bit will have also set the
			 * reset reason for us.
			 */
			ena->ena_device_stat.eds_reset_error.value.ui64++;
			ena_err(ena, "error state detected");
			reason = ena->ena_reset_reason;
			break;
		case RESET_FATAL:
			ena->ena_device_stat.eds_reset_fatal.value.ui64++;
			ena_err(ena, "device reports fatal error (status 0x%x)"
			    ", resetting", statusreg);
			reason = ENAHW_RESET_GENERIC;
			break;
		case RESET_KEEPALIVE:
			ena->ena_device_stat.eds_reset_keepalive.value.ui64++;
			ena_err(ena, "device keepalive timeout");
			reason = ENAHW_RESET_KEEP_ALIVE_TO;
			break;
		case RESET_TX_STALL:
			ena->ena_device_stat.eds_reset_txstall.value.ui64++;
			ena_err(ena, "TX ring 0x%x appears stalled, resetting",
			    stalledq);
			reason = ENAHW_RESET_MISS_TX_CMPL;
			break;
		default:
			ena_panic(ena, "unhandled case in reset switch");
		}
		ena->ena_reset_reason = reason;
		mutex_exit(&ena->ena_lock);

		if (!ena_reset(ena, reason))
			ena_panic(ena, "failed to reset device");
	}
}

void
ena_enable_watchdog(ena_t *ena)
{
	mutex_enter(&ena->ena_watchdog_lock);
	if (ena->ena_watchdog_periodic == NULL) {
		ena->ena_watchdog_periodic = ddi_periodic_add(ena_watchdog,
		    (void *)ena, ENA_WATCHDOG_INTERVAL_NS, DDI_IPL_0);
	}
	mutex_exit(&ena->ena_watchdog_lock);
}

void
ena_disable_watchdog(ena_t *ena)
{
	mutex_enter(&ena->ena_watchdog_lock);
	if (ena->ena_watchdog_periodic != NULL) {
		ddi_periodic_delete(ena->ena_watchdog_periodic);
		ena->ena_watchdog_periodic = NULL;
	}
	mutex_exit(&ena->ena_watchdog_lock);
}
