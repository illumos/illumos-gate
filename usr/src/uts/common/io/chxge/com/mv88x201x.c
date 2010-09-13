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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* mv88x201x.c */

#include "cphy.h"
#include "elmer0.h"

/*
 * The 88x2010 Rev C. requires some link status registers * to be read
 * twice in order to get the right values. Future * revisions will fix
 * this problem and then this macro * can disappear.
 */
#define MV88x2010_LINK_STATUS_BUGS    1

static int led_init(struct cphy *cphy)
{
	/* Setup the LED registers so we can turn on/off.
	 * Writing these bits maps control to another
	 * register. mmd(0x1) addr(0x7)
	 */
	(void) mdio_write(cphy, 0x3, 0x8304, 0xdddd);
	return 0;
}

static int led_link(struct cphy *cphy, u32 do_enable)
{
	u32 led = 0;
#define LINK_ENABLE_BIT 0x1

	(void) mdio_read(cphy, 0x1, 0x7, &led);

	if (do_enable & LINK_ENABLE_BIT) {
		led |= LINK_ENABLE_BIT;
		(void) mdio_write(cphy, 0x1, 0x7, led);
	} else {
		led &= ~LINK_ENABLE_BIT;
		(void) mdio_write(cphy, 0x1, 0x7, led);
	}
	return 0;
}

/* Port Reset */
/* ARGSUSED */
static int mv88x201x_reset(struct cphy *cphy, int wait)
{
	/* This can be done through registers.  It is not required since
	 * a full chip reset is used.
	 */
	return 0;
}

static int mv88x201x_interrupt_enable(struct cphy *cphy)
{
	/* Enable PHY LASI interrupts. */
	(void) mdio_write(cphy, 0x1, 0x9002, 0x1);

	/* Enable Marvell interrupts through Elmer0. */
	if (t1_is_asic(cphy->adapter)) {
		u32 elmer;

		(void) t1_tpi_read(cphy->adapter, A_ELMER0_INT_ENABLE, &elmer);
		elmer |= ELMER0_GP_BIT6;
		(void) t1_tpi_write(cphy->adapter, A_ELMER0_INT_ENABLE, elmer);
	}
	return 0;
}

static int mv88x201x_interrupt_disable(struct cphy *cphy)
{
	/* Disable PHY LASI interrupts. */
	(void) mdio_write(cphy, 0x1, 0x9002, 0x0);

	/* Disable Marvell interrupts through Elmer0. */
	if (t1_is_asic(cphy->adapter)) {
		u32 elmer;

		(void) t1_tpi_read(cphy->adapter, A_ELMER0_INT_ENABLE, &elmer);
		elmer &= ~ELMER0_GP_BIT6;
		(void) t1_tpi_write(cphy->adapter, A_ELMER0_INT_ENABLE, elmer);
	}
	return 0;
}

static int mv88x201x_interrupt_clear(struct cphy *cphy)
{
	u32 elmer;
	u32 val;

#ifdef MV88x2010_LINK_STATUS_BUGS
	/* Required to read twice before clear takes affect. */
	(void) mdio_read(cphy, 0x1, 0x9003, &val);
	(void) mdio_read(cphy, 0x1, 0x9004, &val);
	(void) mdio_read(cphy, 0x1, 0x9005, &val);

	/* Read this register after the others above it else
	 * the register doesn't clear correctly. 
	 */
	(void) mdio_read(cphy, 0x1, 0x1, &val);
#endif

	/* Clear link status. */
	(void) mdio_read(cphy, 0x1, 0x1, &val);
	/* Clear PHY LASI interrupts. */
	(void) mdio_read(cphy, 0x1, 0x9005, &val);

#ifdef MV88x2010_LINK_STATUS_BUGS
	/* Do it again. */
	(void) mdio_read(cphy, 0x1, 0x9003, &val);
	(void) mdio_read(cphy, 0x1, 0x9004, &val);
#endif

	/* Clear Marvell interrupts through Elmer0. */
	if (t1_is_asic(cphy->adapter)) {
		(void) t1_tpi_read(cphy->adapter, A_ELMER0_INT_CAUSE, &elmer);
		elmer |= ELMER0_GP_BIT6;
		(void) t1_tpi_write(cphy->adapter, A_ELMER0_INT_CAUSE, elmer);
	}
	return 0;
}

static int mv88x201x_interrupt_handler(struct cphy *cphy)
{
	/* Clear interrupts */
	(void) mv88x201x_interrupt_clear(cphy);

	/* We have only enabled link change interrupts and so
	 * cphy_cause must be a link change interrupt.
	 */
	return cphy_cause_link_change;
}

/* ARGSUSED */
static int mv88x201x_set_loopback(struct cphy *cphy, int on)
{
	return 0;
}

static int mv88x201x_get_link_status(struct cphy *cphy, int *link_ok,
				     int *speed, int *duplex, int *fc)
{
	u32 val = 0;
#define LINK_STATUS_BIT 0x4

	if (link_ok) {
		/* Read link status. */
		(void) mdio_read(cphy, 0x1, 0x1, &val);
		val &= LINK_STATUS_BIT;
		*link_ok = (val == LINK_STATUS_BIT);
		/* Turn on/off Link LED */
		(void) led_link(cphy, *link_ok);
	}
	if (speed)
		*speed = SPEED_10000;
	if (duplex)
		*duplex = DUPLEX_FULL;
	if (fc)
		*fc = PAUSE_RX | PAUSE_TX;
	return 0;
}

static void mv88x201x_destroy(struct cphy *cphy)
{
	t1_os_free((void *) cphy, sizeof(*cphy));
}

#ifdef C99_NOT_SUPPORTED
static struct cphy_ops mv88x201x_ops = {
	mv88x201x_destroy,
	mv88x201x_reset,
	mv88x201x_interrupt_enable,
	mv88x201x_interrupt_disable,
	mv88x201x_interrupt_clear,
	mv88x201x_interrupt_handler,
	NULL,
	NULL,
	NULL,
	NULL,
	mv88x201x_set_loopback,
	NULL,
	mv88x201x_get_link_status,
};
#else
static struct cphy_ops mv88x201x_ops = {
	.destroy           = mv88x201x_destroy,
	.reset             = mv88x201x_reset,
	.interrupt_enable  = mv88x201x_interrupt_enable,
	.interrupt_disable = mv88x201x_interrupt_disable,
	.interrupt_clear   = mv88x201x_interrupt_clear,
	.interrupt_handler = mv88x201x_interrupt_handler,
	.get_link_status   = mv88x201x_get_link_status,
	.set_loopback      = mv88x201x_set_loopback,
};
#endif

static struct cphy *mv88x201x_phy_create(adapter_t *adapter, int phy_addr,
					 struct mdio_ops *mdio_ops)
{
	u32 val;
	struct cphy *cphy = t1_os_malloc_wait_zero(sizeof(*cphy));

	if (!cphy)
		return NULL;

	cphy_init(cphy, adapter, phy_addr, &mv88x201x_ops, mdio_ops);

	/* Commands the PHY to enable XFP's clock. */
	(void) mdio_read(cphy, 0x3, 0x8300, &val);
	(void) mdio_write(cphy, 0x3, 0x8300, val | 1);

	/* Clear link status. Required because of a bug in the PHY.  */
	(void) mdio_read(cphy, 0x1, 0x8, &val);
	(void) mdio_read(cphy, 0x3, 0x8, &val);

	/* Allows for Link,Ack LED turn on/off */
	(void) led_init(cphy);
	return cphy;
}

/* Chip Reset */
static int mv88x201x_phy_reset(adapter_t *adapter)
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
	return 0;
}

struct gphy t1_mv88x201x_ops = {
	mv88x201x_phy_create,
	mv88x201x_phy_reset
};
