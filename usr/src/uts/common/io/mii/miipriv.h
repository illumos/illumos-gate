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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * miipriv.h
 *
 * Private MII header file.
 */

#ifndef _MIIPRIV_H
#define	_MIIPRIV_H

#define	PHY_SET(phy, reg, bit)		\
	phy_write(phy, reg, phy_read(phy, reg) | (bit))
#define	PHY_CLR(phy, reg, bit)		\
	phy_write(phy, reg, phy_read(phy, reg) & ~(bit))

typedef struct phy_ops phy_ops_t;
typedef struct phy_handle phy_handle_t;

struct phy_handle {
	/*
	 * Read only fields for PHY implementations, used internally by
	 * the framework.
	 */
	mii_handle_t	phy_mii;
	boolean_t	phy_present;
	uint8_t		phy_addr;
	uint8_t		phy_type;
	uint32_t	phy_id;

	/*
	 * Scratch storage available for PHY implementations.  While
	 * perhaps not as "clean" as other solutions with dynamic memory,
	 * this avoids having to deal with potential concerns regarding the
	 * lifetime of the storage.  It will be zeroed each time the MII
	 * bus is reprobed.
	 */
	uintptr_t	phy_scratch[8];

	/*
	 * These fields are intended to be overridden by PHY
	 * implementations.  If left NULL, then default
	 * implementations will be supplied.
	 */
	const char	*phy_vendor;
	const char	*phy_model;
	int		(*phy_reset)(phy_handle_t *);
	int		(*phy_start)(phy_handle_t *);
	int		(*phy_stop)(phy_handle_t *);
	int		(*phy_check)(phy_handle_t *);
	int		(*phy_loop)(phy_handle_t *);

	/*
	 * Physical capabilities.  PHY implementations may override
	 * the defaults if necessary.
	 */
	boolean_t	phy_cap_aneg;
	boolean_t	phy_cap_10_hdx;
	boolean_t	phy_cap_10_fdx;
	boolean_t	phy_cap_100_t4;
	boolean_t	phy_cap_100_hdx;
	boolean_t	phy_cap_100_fdx;
	boolean_t	phy_cap_1000_hdx;
	boolean_t	phy_cap_1000_fdx;
	boolean_t	phy_cap_pause;
	boolean_t	phy_cap_asmpause;

	/*
	 * Local configured settings.  PHY implementations should
	 * these as read only.  The MII common layer will limit
	 * settings to only those that are sensible per the actual
	 * capabilities of the device.  These represent administrator
	 * preferences.
	 */
	boolean_t	phy_en_aneg;
	boolean_t	phy_en_10_hdx;
	boolean_t	phy_en_10_fdx;
	boolean_t	phy_en_100_t4;
	boolean_t	phy_en_100_hdx;
	boolean_t	phy_en_100_fdx;
	boolean_t	phy_en_1000_hdx;
	boolean_t	phy_en_1000_fdx;
	boolean_t	phy_en_pause;
	boolean_t	phy_en_asmpause;
	link_flowctrl_t	phy_en_flowctrl;

	/*
	 * Settings exposed on the hardware.  MII common layer will
	 * limit settings to only those that are sensible per the
	 * actual capabilities of the device.
	 */
	boolean_t	phy_adv_aneg;
	boolean_t	phy_adv_10_hdx;
	boolean_t	phy_adv_10_fdx;
	boolean_t	phy_adv_100_t4;
	boolean_t	phy_adv_100_hdx;
	boolean_t	phy_adv_100_fdx;
	boolean_t	phy_adv_1000_hdx;
	boolean_t	phy_adv_1000_fdx;
	boolean_t	phy_adv_pause;
	boolean_t	phy_adv_asmpause;

	/*
	 * Link partner settings.  PHY implementations should
	 * fill these in during phy_check.
	 */
	boolean_t	phy_lp_aneg;
	boolean_t	phy_lp_10_hdx;
	boolean_t	phy_lp_10_fdx;
	boolean_t	phy_lp_100_t4;
	boolean_t	phy_lp_100_hdx;
	boolean_t	phy_lp_100_fdx;
	boolean_t	phy_lp_1000_hdx;
	boolean_t	phy_lp_1000_fdx;
	boolean_t	phy_lp_pause;
	boolean_t	phy_lp_asmpause;

	/*
	 * Loopback state.  Loopback state overrides any other settings.
	 */
	int		phy_loopback;
#define	PHY_LB_NONE	0
#define	PHY_LB_INT_PHY	1
#define	PHY_LB_EXT_10	2
#define	PHY_LB_EXT_100	3
#define	PHY_LB_EXT_1000	4

	/*
	 * Resolved link status.  PHY implementations should
	 * fill these during phy_check.
	 */
	link_state_t	phy_link;
	uint32_t	phy_speed;
	link_duplex_t	phy_duplex;
	link_flowctrl_t	phy_flowctrl;
};

/*
 * Routines intended to be accessed by PHY specific implementation code.
 * All of these routines assume that any relevant locks are held by the
 * famework (which would be true for all of the PHY functions.
 */

uint16_t phy_read(phy_handle_t *, uint8_t);
void phy_write(phy_handle_t *, uint8_t, uint16_t);
int phy_get_prop(phy_handle_t *, char *, int);
const char *phy_get_name(phy_handle_t *);
const char *phy_get_driver(phy_handle_t *);
void phy_warn(phy_handle_t *, const char *, ...);

/*
 * phy_reset is called when the PHY needs to be reset.  The default
 * implementation just resets the PHY by toggling the BMCR bit, but it
 * also unisolates and powers up the PHY.
 */
int phy_reset(phy_handle_t *);

/*
 * phy_start is used to start services on the PHY.  Typically this is
 * called when autonegotiation should be started.  phy_reset will
 * already have been called.
 */
int phy_start(phy_handle_t *);

/*
 * phy_stop is used when the phy services should be stopped.  This can
 * be done, for example, when a different PHY will be used.  The default
 * implementation isolates the PHY, puts it into loopback, and then powers
 * it down.
 */
int phy_stop(phy_handle_t *);

/*
 * phy_check is called to check the current state of the link.  It
 * can be used from the implementations phy_check entry point.
 */
int phy_check(phy_handle_t *);

/*
 * phy_ isoop called to establish loopback mode.  The PHY must
 * examine the value of phy_loopback.
 */
int phy_loop(phy_handle_t *);

/*
 * The following probes are PHY specific, and located here so that
 * the common PHY layer can find them.
 */
boolean_t phy_intel_probe(phy_handle_t *);
boolean_t phy_natsemi_probe(phy_handle_t *);
boolean_t phy_qualsemi_probe(phy_handle_t *);
boolean_t phy_cicada_probe(phy_handle_t *);
boolean_t phy_marvell_probe(phy_handle_t *);
boolean_t phy_realtek_probe(phy_handle_t *);
boolean_t phy_other_probe(phy_handle_t *);

#endif /* _MIIPRIV_H */
