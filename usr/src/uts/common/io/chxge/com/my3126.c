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
 * Copyright (C) 2003-2005 Chelsio Communications.  All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* my3126.c */

#include "cphy.h"
#include "elmer0.h"
#include "suni1x10gexp_regs.h"

/* Port Reset */
/* ARGSUSED */
static int my3126_reset(struct cphy *cphy, int wait)
{
	/*
	 * This can be done through registers.  It is not required since
	 * a full chip reset is used.
	 */
	return (0);
}

/* ARGSUSED */
static int my3126_interrupt_enable(struct cphy *cphy)
{
	/* T1 Elmer does not support link/act LED. */
	if (!is_T2(cphy->adapter))
		return (0);
	ch_start_cyclic(&cphy->phy_update_cyclic, 30);
	(void) t1_tpi_read(cphy->adapter, A_ELMER0_GPO, &cphy->elmer_gpo);
	return (0);
}

/* ARGSUSED */
static int my3126_interrupt_disable(struct cphy *cphy)
{
	/* T1 Elmer does not support link/act LED. */
	if (is_T2(cphy->adapter))
		ch_stop_cyclic(&cphy->phy_update_cyclic);
	return (0);
}

/* ARGSUSED */
static int my3126_interrupt_clear(struct cphy *cphy)
{
	return (0);
}

#define OFFSET(REG_ADDR)    (REG_ADDR << 2)

static int my3126_interrupt_handler(struct cphy *cphy)
{
	u32 val;
	u16 val16;
	u16 status;
	u32 act_count;
	adapter_t *adapter;

	/* T1 Elmer does not support link/act LED. */
	if (!is_T2(cphy->adapter))
		return (cphy_cause_link_change);

	adapter = cphy->adapter;
	if (cphy->count == 50) {
		(void) mdio_read(cphy, 0x1, 0x1, &val);
		val16 = (u16) val;
		status = cphy->bmsr ^ val16;
	
		if (status & BMSR_LSTATUS) {
			link_changed(adapter, 0);
		}
		cphy->bmsr = val16;

		/* We have only enabled link change interrupts so it
		   must be that
		 */
		cphy->count = 0;
	}
	(void) t1_tpi_write(adapter, OFFSET(SUNI1x10GEXP_REG_MSTAT_CONTROL),
                SUNI1x10GEXP_BITMSK_MSTAT_SNAP);
	(void) t1_tpi_read(adapter,
		OFFSET(SUNI1x10GEXP_REG_MSTAT_COUNTER_1_LOW), &act_count);
	(void) t1_tpi_read(adapter,
		OFFSET(SUNI1x10GEXP_REG_MSTAT_COUNTER_33_LOW), &val);
	act_count += val;
	val = cphy->elmer_gpo;
	if ((val & (1 << 8)) ||
		(cphy->act_count == act_count) || (cphy->act_on)) {
		val |= (1 << 9);
		(void) t1_tpi_write(adapter, A_ELMER0_GPO, val);
		cphy->act_on = 0;
	} else {
		val &= ~(1 << 9);
                (void) t1_tpi_write(adapter, A_ELMER0_GPO, val);
		cphy->act_on = 1;
	}
	cphy->elmer_gpo = val;
	cphy->act_count = act_count;
	cphy->count++;

	return (cphy_cause_link_change);
}

/* ARGSUSED */
static int my3126_set_loopback(struct cphy *cphy, int on)
{
	return (0);
}

/* To check the activity LED */
static int my3126_get_link_status(struct cphy *cphy,
			int *link_ok, int *speed, int *duplex, int *fc)
{
	u32 val;
	u16 val16;
	adapter_t *adapter;

	/* T1 Elmer does not support link/act LED. */
	if (!is_T2(cphy->adapter))
		return (0);

	adapter = cphy->adapter;
	(void) mdio_read(cphy, 0x1, 0x1, &val);
	val16 = (u16) val;
	val = cphy->elmer_gpo;
	*link_ok = (val16 & BMSR_LSTATUS);
	if (*link_ok) {
		// Light the LED.
		 val &= ~(1 << 8);
	} else {
		// Turn off the LED.
		 val |= (1 << 8);
	}
	(void) t1_tpi_write(adapter, A_ELMER0_GPO, val);
	cphy->elmer_gpo = val;
	*speed = SPEED_10000;
	*duplex = DUPLEX_FULL;
	/* need to add flow control */
	if (fc)
		*fc = PAUSE_RX | PAUSE_TX;

	return (0);
}

static void my3126_destroy(struct cphy *cphy)
{
	t1_os_free((void *) cphy, sizeof(*cphy));
}

#ifdef C99_NOT_SUPPORTED
static struct cphy_ops my3126_ops = {
	my3126_destroy,
	my3126_reset,
	my3126_interrupt_enable,
	my3126_interrupt_disable,
	my3126_interrupt_clear,
	my3126_interrupt_handler,
	NULL,
	NULL,
	NULL,
	NULL,
	my3126_set_loopback,
	NULL,
	my3126_get_link_status,
};
#else
static struct cphy_ops my3126_ops = {
	.destroy           = my3126_destroy,
	.reset             = my3126_reset,
	.interrupt_enable  = my3126_interrupt_enable,
	.interrupt_disable = my3126_interrupt_disable,
	.interrupt_clear   = my3126_interrupt_clear,
	.interrupt_handler = my3126_interrupt_handler,
	.get_link_status   = my3126_get_link_status,
	.set_loopback      = my3126_set_loopback,
};
#endif

static struct cphy *my3126_phy_create(adapter_t *adapter, int phy_addr,
				      struct mdio_ops *mdio_ops)
{
	struct cphy *cphy = t1_os_malloc_wait_zero(sizeof(*cphy));

	if (cphy)
		cphy_init(cphy, adapter, phy_addr, &my3126_ops, mdio_ops);

	if (is_T2(adapter)) {
        	ch_init_cyclic(adapter, &cphy->phy_update_cyclic,
				(void (*)(void *))my3126_interrupt_handler,
				cphy);
		cphy->bmsr = 0;
	}

	return (cphy);
}

/* Chip Reset */
static int my3126_phy_reset(adapter_t * adapter)
{
	u32 val;

	(void) t1_tpi_read(adapter, A_ELMER0_GPO, &val);
	val &= ~4;
	(void) t1_tpi_write(adapter, A_ELMER0_GPO, val);
	DELAY_MS(100);

	(void) t1_tpi_write(adapter, A_ELMER0_GPO, val | 4);
	DELAY_MS(1000);

	/* Now lets enable the Laser. Delay 100us */
	(void) t1_tpi_read(adapter, A_ELMER0_GPO, &val);
	val |= 0x8000;
	(void) t1_tpi_write(adapter, A_ELMER0_GPO, val);
	DELAY_US(100);
	return (0);
}

struct gphy t1_my3126_ops = {
	my3126_phy_create,
	my3126_phy_reset
};
