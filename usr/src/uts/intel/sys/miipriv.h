/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * miipriv.h
 * MII/PHY Support for MAC drivers. private definitions for mii module
 */

#ifndef _MIIPRIV_H
#define	_MIIPRIV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* Vendor Specific functions */
typedef void (*phy_genfunc)(mii_handle_t, int phy);
typedef int (*phy_getspeedfunc)(mii_handle_t, int phy, int *speed, int *fd);

/* per-PHY information. */
struct phydata
{
	ulong_t id;			/* ID from MII registers 2,3 */
	char *description;		/* Text description from ID */
	phy_genfunc phy_dump;		/* how to dump registers this make */
	phy_genfunc phy_postreset;	/* What to do after a reset (or init) */
	phy_getspeedfunc phy_getspeed;	/* how to find current speed */
	unsigned short control;		/* Bits that need to be written ...  */
					/* ...to control register */
	enum mii_phy_state state;	/* Current state of link at this PHY */
	int fix_speed;			/* Speed fixed in conf file */
	int fix_duplex;
	/*
	 * ^^NEEDSWORK: We can only fix speed for the driver, never mind a
	 * particular PHY on a particular instance, but this is where this
	 * belongs.
	 */
};

typedef struct mii_info
{
	mii_readfunc_t mii_read;	/* How to read an MII register */
	mii_writefunc_t mii_write;	/* How to write an MII register */
	mii_linkfunc_t mii_linknotify;	/* What to do when link state changes */
	dev_info_t *mii_dip;		/* MAC's devinfo */
	timeout_id_t portmon_timer;	/* ID of timer for the port monitor */
	kmutex_t *lock;			/* Lock to serialise mii calls */
	struct phydata *phys[32];	/* PHY Information indexed by address */
} mii_info_t;

#ifdef	__cplusplus
}
#endif

#endif /* _MIIPRIV_H */
