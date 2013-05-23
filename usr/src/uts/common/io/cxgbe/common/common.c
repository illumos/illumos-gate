/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * This file is part of the Chelsio T4 Ethernet driver.
 *
 * Copyright (C) 2005-2013 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include "common.h"

int
is_offload(const struct adapter *adap)
{
	return (adap->params.offload);
}

unsigned int
core_ticks_per_usec(const struct adapter *adap)
{
	return (adap->params.vpd.cclk / 1000);
}

int
t4_wr_mbox(struct adapter *adap, int mbox, const void *cmd, int size, void *rpl)
{
	return (t4_wr_mbox_meat(adap, mbox, cmd, size, rpl, true));
}

unsigned int
us_to_core_ticks(const struct adapter *adap, unsigned int us)
{
	return ((us * adap->params.vpd.cclk) / 1000);
}

unsigned int
core_ticks_to_us(const struct adapter *adapter, unsigned int ticks)
{
	/* add Core Clock / 2 to round ticks to nearest uS */
	return ((ticks * 1000 + adapter->params.vpd.cclk/2) /
	    adapter->params.vpd.cclk);
}

unsigned int
dack_ticks_to_usec(const struct adapter *adap, unsigned int ticks)
{
	return ((ticks << adap->params.tp.dack_re) / core_ticks_per_usec(adap));
}

int
is_bypass(const adapter_t *adap)
{
	return (adap->params.bypass);
}

int
is_bypass_device(int device)
{
	/* TODO - this should be set based upon device capabilities */
	switch (device) {
#ifdef CONFIG_CHELSIO_BYPASS
	case 0x440b:
	case 0x440c:
		return (1);
#endif

	default:
		return (0);
	}
}

int
t4_wait_op_done(struct adapter *adapter, int reg, u32 mask, int polarity,
    int attempts, int delay)
{
	return (t4_wait_op_done_val(adapter, reg, mask, polarity, attempts,
	    delay, NULL));
}

int
t4_wr_mbox_ns(struct adapter *adap, int mbox, const void *cmd, int size,
    void *rpl)
{
	return (t4_wr_mbox_meat(adap, mbox, cmd, size, rpl, false));
}
