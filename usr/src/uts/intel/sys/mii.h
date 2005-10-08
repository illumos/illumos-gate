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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * mii.h
 * Generic MII/PHY Support for MAC drivers.
 *
 * Copyrighted as an unpublished work. (c) Copyright 1997 Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _MII_H
#define	_MII_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * NOTES
 * All calls to MII functions are assumed to be serialized by the user.
 * In the case of the port monitor, which causes asynchronous callbacks,
 * you must pass the address of a mutex. MII aquires this before calling
 * the user callback, and releases it after the callback returns.
 *
 * All calls requiring a PHY address must be done AFTER calling
 * mii_init_phy() for that PHY, with the exception of mii_phyexists()
 *
 * mii_rsan() will not accept mii_wait_interrupt as a wait type. Its futile to
 * expect autonegotiation to happen fast enough. (You're better off using the
 * port monitor to tell you, asynchronously that the link has been
 * re-established than waiting at all.)
 */

/*
 * MII programming Interface types
 */

enum mii_phy_state {phy_state_unknown, phy_state_linkup, phy_state_linkdown};
enum mii_wait_type {mii_wait_none, mii_wait_user, mii_wait_interrupt};
typedef ushort_t (*mii_readfunc_t)(dev_info_t *, int phy, int reg);
typedef void (*mii_writefunc_t)(dev_info_t *, int phy, int reg, int value);
typedef void (*mii_linkfunc_t)(dev_info_t *, int phy, enum mii_phy_state state);

struct mii_info;	/* Private to MII! */
typedef struct mii_info *mii_handle_t;

/*
 * Entrypoints
 */

int mii_create(dev_info_t *, mii_writefunc_t, mii_readfunc_t, mii_handle_t *);
			/* Initialise the PHY interface */

int mii_init_phy(mii_handle_t, int phy);
			/* Initialise a PHY */

int mii_getspeed(mii_handle_t, int phy, int *speed, int *full_duplex);
			/* Check operating speed of PHY */

int mii_probe_phy(mii_handle_t, int phy);
			/* Check if PHY exists at an address */

int mii_rsan(mii_handle_t mac, int phy, enum mii_wait_type wait_type);
					/* Restart autonegotiation */

int mii_fixspeed(mii_handle_t, int phy, int speed, int fullduplex);
			/* Fix speed and duplex mode of PHY (disable autoneg) */

int mii_autoneg_enab(mii_handle_t mac, int phy);
			/* (re-)enable autonegotiation */

int mii_reset_phy(mii_handle_t, int phy, enum mii_wait_type wait_type);
			/* Force PHY to reset itself */

int mii_disable_fullduplex(mii_handle_t, int phy);
			/* Stop the PHY advertising full duplex capability */

int mii_linkup(mii_handle_t, int phy);
			/* Check link status on a phy */

int mii_sync(mii_handle_t, int phy);
			/* Sync API if something may have affected the PHY */

int mii_isolate(mii_handle_t, int phy);
			/* Electrically isolate a PHY */

int mii_unisolate(mii_handle_t, int phy);
			/* Unisolate */

int mii_dump_phy(mii_handle_t, int phy);
			/* Dump register contents */

int mii_start_portmon(mii_handle_t mac, mii_linkfunc_t func, kmutex_t *lock);
			/* Monitor initialised PHYs for link state changes */

int mii_stop_portmon(mii_handle_t mac);
			/* Stop port monitor */

void mii_destroy(mii_handle_t mac);
			/* Cleanup MII interface */

/*
 * Errorcodes
 */
#define	MII_SUCCESS 0
#define	MII_PHYPRESENT 1	/* PHY already exists at specified address */
#define	MII_NOMEM 2		/* Not enough memory */
#define	MII_PARAM 3		/* parameters passed are incorrect */
#define	MII_NOTSUPPORTED 4	/* operation not supported by hardware. */
#define	MII_STATE 5		/* The request is not valid at this time. */
#define	MII_HARDFAIL 6		/* The hardware is not functioning correctly */
#define	MII_TIMEOUT 7		/* Timeout waiting for operation to complete */
#define	MII_PHYNOTPRESENT 8	/* There is no PHY at the specified address */

#ifdef	__cplusplus
}
#endif

#endif /* _MII_H */
