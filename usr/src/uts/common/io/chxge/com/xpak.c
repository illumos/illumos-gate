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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* xpak.c */

#include "cphy.h"
#include "elmer0.h"

/* ARGSUSED */
static int xpak_reset(struct cphy *cphy, int wait)
{
	return 0;
}

/* ARGSUSED */
static int xpak_interrupt_enable(struct cphy *cphy)
{
	return 0;
}

/* ARGSUSED */
static int xpak_interrupt_disable(struct cphy *cphy)
{
	return 0;
}

/* ARGSUSED */
static int xpak_interrupt_clear(struct cphy *cphy)
{
	return 0;
}

/* ARGSUSED */
static int xpak_set_loopback(struct cphy *cphy, int on)
{
	return 0;
}

/* ARGSUSED */
static int xpak_get_link_status(struct cphy *cphy, int *link_ok, int *speed,
				int *duplex, int *fc)
{
	if (link_ok)
		*link_ok = 1;
	if (speed)
		*speed = SPEED_10000;
	if (duplex)
		*duplex = DUPLEX_FULL;
	if (fc)
		*fc = PAUSE_RX | PAUSE_TX;
	return 0;
}

static void xpak_destroy(struct cphy *cphy)
{
	t1_os_free((void *)cphy, sizeof(*cphy));
}

#ifdef C99_NOT_SUPPORTED
static struct cphy_ops xpak_ops = {
	 xpak_destroy,
         xpak_reset,
         xpak_interrupt_enable,
         xpak_interrupt_disable,
         xpak_interrupt_clear,
         NULL,
         NULL,
         NULL,
         NULL,
         NULL,
	 xpak_set_loopback,
         NULL,
         xpak_get_link_status,
};
#else
static struct cphy_ops xpak_ops = {
	.destroy           = xpak_destroy,
	.reset             = xpak_reset,
	.interrupt_enable  = xpak_interrupt_enable,
	.interrupt_disable = xpak_interrupt_disable,
	.interrupt_clear   = xpak_interrupt_clear,
	.get_link_status   = xpak_get_link_status,
	.set_loopback      = xpak_set_loopback,
};
#endif

/* ARGSUSED */
static struct cphy *xpak_phy_create(adapter_t * adapter, int phy_addr,
				    struct mdio_ops *mdio_ops)
{
	struct cphy *cphy = t1_os_malloc_wait_zero(sizeof(*cphy));

	if (!cphy)
		return NULL;

	cphy->ops        = &xpak_ops;
	cphy->adapter    = adapter;
	cphy->mdio_read  = mdio_ops->read;
	cphy->mdio_write = mdio_ops->write;
	return cphy;
}

static int xpak_phy_reset(adapter_t *adapter)
{
	u32 val;

	(void) t1_tpi_read(adapter, A_ELMER0_GPO, &val);
	val &= ~4;
	(void) t1_tpi_write(adapter, A_ELMER0_GPO, val);
	DELAY_MS(100);

	/*
	 * Errata #26 states to wait 5 seconds after reset before transceiver
	 * becomes operational.
	 */
	(void) t1_tpi_write(adapter, A_ELMER0_GPO, val | 4);
	DELAY_MS(5000);

	/* Now lets enable the Laser. Delay 100us
	 * as defined in XPAK errata.
	 */
	(void) t1_tpi_read(adapter, A_ELMER0_GPO, &val);
	val |= 0x8000;
	(void) t1_tpi_write(adapter, A_ELMER0_GPO, val);
	DELAY_US(100);
	return 0;
}

struct gphy t1_xpak_ops = {
	xpak_phy_create,
	xpak_phy_reset
};
 
