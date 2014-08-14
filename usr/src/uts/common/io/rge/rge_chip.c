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

#include "rge.h"

#define	REG32(rgep, reg)	((uint32_t *)(rgep->io_regs+(reg)))
#define	REG16(rgep, reg)	((uint16_t *)(rgep->io_regs+(reg)))
#define	REG8(rgep, reg)		((uint8_t *)(rgep->io_regs+(reg)))
#define	PIO_ADDR(rgep, offset)	((void *)(rgep->io_regs+(offset)))

/*
 * Patchable globals:
 *
 *	rge_autorecover
 *		Enables/disables automatic recovery after fault detection
 */
static uint32_t rge_autorecover = 1;

/*
 * globals:
 */
#define	RGE_DBG		RGE_DBG_REGS	/* debug flag for this code	*/
static uint32_t rge_watchdog_count	= 1 << 5;
static uint32_t rge_rx_watchdog_count	= 1 << 3;

/*
 * Operating register get/set access routines
 */

static uint32_t rge_reg_get32(rge_t *rgep, uintptr_t regno);
#pragma	inline(rge_reg_get32)

static uint32_t
rge_reg_get32(rge_t *rgep, uintptr_t regno)
{
	RGE_TRACE(("rge_reg_get32($%p, 0x%lx)",
	    (void *)rgep, regno));

	return (ddi_get32(rgep->io_handle, REG32(rgep, regno)));
}

static void rge_reg_put32(rge_t *rgep, uintptr_t regno, uint32_t data);
#pragma	inline(rge_reg_put32)

static void
rge_reg_put32(rge_t *rgep, uintptr_t regno, uint32_t data)
{
	RGE_TRACE(("rge_reg_put32($%p, 0x%lx, 0x%x)",
	    (void *)rgep, regno, data));

	ddi_put32(rgep->io_handle, REG32(rgep, regno), data);
}

static void rge_reg_set32(rge_t *rgep, uintptr_t regno, uint32_t bits);
#pragma	inline(rge_reg_set32)

static void
rge_reg_set32(rge_t *rgep, uintptr_t regno, uint32_t bits)
{
	uint32_t regval;

	RGE_TRACE(("rge_reg_set32($%p, 0x%lx, 0x%x)",
	    (void *)rgep, regno, bits));

	regval = rge_reg_get32(rgep, regno);
	regval |= bits;
	rge_reg_put32(rgep, regno, regval);
}

static void rge_reg_clr32(rge_t *rgep, uintptr_t regno, uint32_t bits);
#pragma	inline(rge_reg_clr32)

static void
rge_reg_clr32(rge_t *rgep, uintptr_t regno, uint32_t bits)
{
	uint32_t regval;

	RGE_TRACE(("rge_reg_clr32($%p, 0x%lx, 0x%x)",
	    (void *)rgep, regno, bits));

	regval = rge_reg_get32(rgep, regno);
	regval &= ~bits;
	rge_reg_put32(rgep, regno, regval);
}

static uint16_t rge_reg_get16(rge_t *rgep, uintptr_t regno);
#pragma	inline(rge_reg_get16)

static uint16_t
rge_reg_get16(rge_t *rgep, uintptr_t regno)
{
	RGE_TRACE(("rge_reg_get16($%p, 0x%lx)",
	    (void *)rgep, regno));

	return (ddi_get16(rgep->io_handle, REG16(rgep, regno)));
}

static void rge_reg_put16(rge_t *rgep, uintptr_t regno, uint16_t data);
#pragma	inline(rge_reg_put16)

static void
rge_reg_put16(rge_t *rgep, uintptr_t regno, uint16_t data)
{
	RGE_TRACE(("rge_reg_put16($%p, 0x%lx, 0x%x)",
	    (void *)rgep, regno, data));

	ddi_put16(rgep->io_handle, REG16(rgep, regno), data);
}

static uint8_t rge_reg_get8(rge_t *rgep, uintptr_t regno);
#pragma	inline(rge_reg_get8)

static uint8_t
rge_reg_get8(rge_t *rgep, uintptr_t regno)
{
	RGE_TRACE(("rge_reg_get8($%p, 0x%lx)",
	    (void *)rgep, regno));

	return (ddi_get8(rgep->io_handle, REG8(rgep, regno)));
}

static void rge_reg_put8(rge_t *rgep, uintptr_t regno, uint8_t data);
#pragma	inline(rge_reg_put8)

static void
rge_reg_put8(rge_t *rgep, uintptr_t regno, uint8_t data)
{
	RGE_TRACE(("rge_reg_put8($%p, 0x%lx, 0x%x)",
	    (void *)rgep, regno, data));

	ddi_put8(rgep->io_handle, REG8(rgep, regno), data);
}

static void rge_reg_set8(rge_t *rgep, uintptr_t regno, uint8_t bits);
#pragma	inline(rge_reg_set8)

static void
rge_reg_set8(rge_t *rgep, uintptr_t regno, uint8_t bits)
{
	uint8_t regval;

	RGE_TRACE(("rge_reg_set8($%p, 0x%lx, 0x%x)",
	    (void *)rgep, regno, bits));

	regval = rge_reg_get8(rgep, regno);
	regval |= bits;
	rge_reg_put8(rgep, regno, regval);
}

static void rge_reg_clr8(rge_t *rgep, uintptr_t regno, uint8_t bits);
#pragma	inline(rge_reg_clr8)

static void
rge_reg_clr8(rge_t *rgep, uintptr_t regno, uint8_t bits)
{
	uint8_t regval;

	RGE_TRACE(("rge_reg_clr8($%p, 0x%lx, 0x%x)",
	    (void *)rgep, regno, bits));

	regval = rge_reg_get8(rgep, regno);
	regval &= ~bits;
	rge_reg_put8(rgep, regno, regval);
}

uint16_t rge_mii_get16(rge_t *rgep, uintptr_t mii);
#pragma	no_inline(rge_mii_get16)

uint16_t
rge_mii_get16(rge_t *rgep, uintptr_t mii)
{
	uint32_t regval;
	uint32_t val32;
	uint32_t i;

	regval = (mii & PHY_REG_MASK) << PHY_REG_SHIFT;
	rge_reg_put32(rgep, PHY_ACCESS_REG, regval);

	/*
	 * Waiting for PHY reading OK
	 */
	for (i = 0; i < PHY_RESET_LOOP; i++) {
		drv_usecwait(1000);
		val32 = rge_reg_get32(rgep, PHY_ACCESS_REG);
		if (val32 & PHY_ACCESS_WR_FLAG)
			return ((uint16_t)(val32 & 0xffff));
	}

	RGE_REPORT((rgep, "rge_mii_get16(0x%x) fail, val = %x", mii, val32));
	return ((uint16_t)~0u);
}

void rge_mii_put16(rge_t *rgep, uintptr_t mii, uint16_t data);
#pragma	no_inline(rge_mii_put16)

void
rge_mii_put16(rge_t *rgep, uintptr_t mii, uint16_t data)
{
	uint32_t regval;
	uint32_t val32;
	uint32_t i;

	regval = (mii & PHY_REG_MASK) << PHY_REG_SHIFT;
	regval |= data & PHY_DATA_MASK;
	regval |= PHY_ACCESS_WR_FLAG;
	rge_reg_put32(rgep, PHY_ACCESS_REG, regval);

	/*
	 * Waiting for PHY writing OK
	 */
	for (i = 0; i < PHY_RESET_LOOP; i++) {
		drv_usecwait(1000);
		val32 = rge_reg_get32(rgep, PHY_ACCESS_REG);
		if (!(val32 & PHY_ACCESS_WR_FLAG))
			return;
	}
	RGE_REPORT((rgep, "rge_mii_put16(0x%lx, 0x%x) fail",
	    mii, data));
}

void rge_ephy_put16(rge_t *rgep, uintptr_t emii, uint16_t data);
#pragma	no_inline(rge_ephy_put16)

void
rge_ephy_put16(rge_t *rgep, uintptr_t emii, uint16_t data)
{
	uint32_t regval;
	uint32_t val32;
	uint32_t i;

	regval = (emii & EPHY_REG_MASK) << EPHY_REG_SHIFT;
	regval |= data & EPHY_DATA_MASK;
	regval |= EPHY_ACCESS_WR_FLAG;
	rge_reg_put32(rgep, EPHY_ACCESS_REG, regval);

	/*
	 * Waiting for PHY writing OK
	 */
	for (i = 0; i < PHY_RESET_LOOP; i++) {
		drv_usecwait(1000);
		val32 = rge_reg_get32(rgep, EPHY_ACCESS_REG);
		if (!(val32 & EPHY_ACCESS_WR_FLAG))
			return;
	}
	RGE_REPORT((rgep, "rge_ephy_put16(0x%lx, 0x%x) fail",
	    emii, data));
}

/*
 * Atomically shift a 32-bit word left, returning
 * the value it had *before* the shift was applied
 */
static uint32_t rge_atomic_shl32(uint32_t *sp, uint_t count);
#pragma	inline(rge_mii_put16)

static uint32_t
rge_atomic_shl32(uint32_t *sp, uint_t count)
{
	uint32_t oldval;
	uint32_t newval;

	/* ATOMICALLY */
	do {
		oldval = *sp;
		newval = oldval << count;
	} while (atomic_cas_32(sp, oldval, newval) != oldval);

	return (oldval);
}

/*
 * PHY operation routines
 */
#if	RGE_DEBUGGING

void
rge_phydump(rge_t *rgep)
{
	uint16_t regs[32];
	int i;

	ASSERT(mutex_owned(rgep->genlock));

	for (i = 0; i < 32; ++i) {
		regs[i] = rge_mii_get16(rgep, i);
	}

	for (i = 0; i < 32; i += 8)
		RGE_DEBUG(("rge_phydump: "
		    "0x%04x %04x %04x %04x %04x %04x %04x %04x",
		    regs[i+0], regs[i+1], regs[i+2], regs[i+3],
		    regs[i+4], regs[i+5], regs[i+6], regs[i+7]));
}

#endif	/* RGE_DEBUGGING */

static void
rge_phy_check(rge_t *rgep)
{
	uint16_t gig_ctl;

	if (rgep->param_link_up  == LINK_STATE_DOWN) {
		/*
		 * RTL8169S/8110S PHY has the "PCS bug".  Need reset PHY
		 * every 15 seconds whin link down & advertise is 1000.
		 */
		if (rgep->chipid.phy_ver == PHY_VER_S) {
			gig_ctl = rge_mii_get16(rgep, MII_1000BASE_T_CONTROL);
			if (gig_ctl & MII_1000BT_CTL_ADV_FDX) {
				rgep->link_down_count++;
				if (rgep->link_down_count > 15) {
					(void) rge_phy_reset(rgep);
					rgep->stats.phy_reset++;
					rgep->link_down_count = 0;
				}
			}
		}
	} else {
		rgep->link_down_count = 0;
	}
}

/*
 * Basic low-level function to reset the PHY.
 * Doesn't incorporate any special-case workarounds.
 *
 * Returns TRUE on success, FALSE if the RESET bit doesn't clear
 */
boolean_t
rge_phy_reset(rge_t *rgep)
{
	uint16_t control;
	uint_t count;

	/*
	 * Set the PHY RESET bit, then wait up to 5 ms for it to self-clear
	 */
	control = rge_mii_get16(rgep, MII_CONTROL);
	rge_mii_put16(rgep, MII_CONTROL, control | MII_CONTROL_RESET);
	for (count = 0; count < 5; count++) {
		drv_usecwait(100);
		control = rge_mii_get16(rgep, MII_CONTROL);
		if (BIC(control, MII_CONTROL_RESET))
			return (B_TRUE);
	}

	RGE_REPORT((rgep, "rge_phy_reset: FAILED, control now 0x%x", control));
	return (B_FALSE);
}

/*
 * Synchronise the PHY's speed/duplex/autonegotiation capabilities
 * and advertisements with the required settings as specified by the various
 * param_* variables that can be poked via the NDD interface.
 *
 * We always reset the PHY and reprogram *all* the relevant registers,
 * not just those changed.  This should cause the link to go down, and then
 * back up again once the link is stable and autonegotiation (if enabled)
 * is complete.  We should get a link state change interrupt somewhere along
 * the way ...
 *
 * NOTE: <genlock> must already be held by the caller
 */
void
rge_phy_update(rge_t *rgep)
{
	boolean_t adv_autoneg;
	boolean_t adv_pause;
	boolean_t adv_asym_pause;
	boolean_t adv_1000fdx;
	boolean_t adv_1000hdx;
	boolean_t adv_100fdx;
	boolean_t adv_100hdx;
	boolean_t adv_10fdx;
	boolean_t adv_10hdx;

	uint16_t control;
	uint16_t gigctrl;
	uint16_t anar;

	ASSERT(mutex_owned(rgep->genlock));

	RGE_DEBUG(("rge_phy_update: autoneg %d "
	    "pause %d asym_pause %d "
	    "1000fdx %d 1000hdx %d "
	    "100fdx %d 100hdx %d "
	    "10fdx %d 10hdx %d ",
	    rgep->param_adv_autoneg,
	    rgep->param_adv_pause, rgep->param_adv_asym_pause,
	    rgep->param_adv_1000fdx, rgep->param_adv_1000hdx,
	    rgep->param_adv_100fdx, rgep->param_adv_100hdx,
	    rgep->param_adv_10fdx, rgep->param_adv_10hdx));

	control = gigctrl = anar = 0;

	/*
	 * PHY settings are normally based on the param_* variables,
	 * but if any loopback mode is in effect, that takes precedence.
	 *
	 * RGE supports MAC-internal loopback, PHY-internal loopback,
	 * and External loopback at a variety of speeds (with a special
	 * cable).  In all cases, autoneg is turned OFF, full-duplex
	 * is turned ON, and the speed/mastership is forced.
	 */
	switch (rgep->param_loop_mode) {
	case RGE_LOOP_NONE:
	default:
		adv_autoneg = rgep->param_adv_autoneg;
		adv_pause = rgep->param_adv_pause;
		adv_asym_pause = rgep->param_adv_asym_pause;
		adv_1000fdx = rgep->param_adv_1000fdx;
		adv_1000hdx = rgep->param_adv_1000hdx;
		adv_100fdx = rgep->param_adv_100fdx;
		adv_100hdx = rgep->param_adv_100hdx;
		adv_10fdx = rgep->param_adv_10fdx;
		adv_10hdx = rgep->param_adv_10hdx;
		break;

	case RGE_LOOP_INTERNAL_PHY:
	case RGE_LOOP_INTERNAL_MAC:
		adv_autoneg = adv_pause = adv_asym_pause = B_FALSE;
		adv_1000fdx = adv_100fdx = adv_10fdx = B_FALSE;
		adv_1000hdx = adv_100hdx = adv_10hdx = B_FALSE;
		rgep->param_link_duplex = LINK_DUPLEX_FULL;

		switch (rgep->param_loop_mode) {
		case RGE_LOOP_INTERNAL_PHY:
			if (rgep->chipid.mac_ver != MAC_VER_8101E) {
				rgep->param_link_speed = 1000;
				adv_1000fdx = B_TRUE;
			} else {
				rgep->param_link_speed = 100;
				adv_100fdx = B_TRUE;
			}
			control = MII_CONTROL_LOOPBACK;
			break;

		case RGE_LOOP_INTERNAL_MAC:
			if (rgep->chipid.mac_ver != MAC_VER_8101E) {
				rgep->param_link_speed = 1000;
				adv_1000fdx = B_TRUE;
			} else {
				rgep->param_link_speed = 100;
				adv_100fdx = B_TRUE;
			break;
		}
	}

	RGE_DEBUG(("rge_phy_update: autoneg %d "
	    "pause %d asym_pause %d "
	    "1000fdx %d 1000hdx %d "
	    "100fdx %d 100hdx %d "
	    "10fdx %d 10hdx %d ",
	    adv_autoneg,
	    adv_pause, adv_asym_pause,
	    adv_1000fdx, adv_1000hdx,
	    adv_100fdx, adv_100hdx,
	    adv_10fdx, adv_10hdx));

	/*
	 * We should have at least one technology capability set;
	 * if not, we select a default of 1000Mb/s full-duplex
	 */
	if (!adv_1000fdx && !adv_100fdx && !adv_10fdx &&
	    !adv_1000hdx && !adv_100hdx && !adv_10hdx) {
		if (rgep->chipid.mac_ver != MAC_VER_8101E)
			adv_1000fdx = B_TRUE;
		} else {
			adv_1000fdx = B_FALSE;
			adv_100fdx = B_TRUE;
		}
	}

	/*
	 * Now transform the adv_* variables into the proper settings
	 * of the PHY registers ...
	 *
	 * If autonegotiation is (now) enabled, we want to trigger
	 * a new autonegotiation cycle once the PHY has been
	 * programmed with the capabilities to be advertised.
	 *
	 * RTL8169/8110 doesn't support 1000Mb/s half-duplex.
	 */
	if (adv_autoneg)
		control |= MII_CONTROL_ANE|MII_CONTROL_RSAN;

	if (adv_1000fdx)
		control |= MII_CONTROL_1GB|MII_CONTROL_FDUPLEX;
	else if (adv_1000hdx)
		control |= MII_CONTROL_1GB;
	else if (adv_100fdx)
		control |= MII_CONTROL_100MB|MII_CONTROL_FDUPLEX;
	else if (adv_100hdx)
		control |= MII_CONTROL_100MB;
	else if (adv_10fdx)
		control |= MII_CONTROL_FDUPLEX;
	else if (adv_10hdx)
		control |= 0;
	else
		{ _NOTE(EMPTY); }	/* Can't get here anyway ...	*/

	if (adv_1000fdx) {
		gigctrl |= MII_1000BT_CTL_ADV_FDX;
		/*
		 * Chipset limitation: need set other capabilities to true
		 */
		if (rgep->chipid.is_pcie)
			adv_1000hdx = B_TRUE;
		adv_100fdx = B_TRUE;
		adv_100hdx  = B_TRUE;
		adv_10fdx = B_TRUE;
		adv_10hdx = B_TRUE;
	}

	if (adv_1000hdx)
		gigctrl |= MII_1000BT_CTL_ADV_HDX;

	if (adv_100fdx)
		anar |= MII_ABILITY_100BASE_TX_FD;
	if (adv_100hdx)
		anar |= MII_ABILITY_100BASE_TX;
	if (adv_10fdx)
		anar |= MII_ABILITY_10BASE_T_FD;
	if (adv_10hdx)
		anar |= MII_ABILITY_10BASE_T;

	if (adv_pause)
		anar |= MII_ABILITY_PAUSE;
	if (adv_asym_pause)
		anar |= MII_ABILITY_ASMPAUSE;

	/*
	 * Munge in any other fixed bits we require ...
	 */
	anar |= MII_AN_SELECTOR_8023;

	/*
	 * Restart the PHY and write the new values.  Note the
	 * time, so that we can say whether subsequent link state
	 * changes can be attributed to our reprogramming the PHY
	 */
	rge_phy_init(rgep);
	if (rgep->chipid.mac_ver == MAC_VER_8168B_B ||
	    rgep->chipid.mac_ver == MAC_VER_8168B_C) {
		/* power up PHY for RTL8168B chipset */
		rge_mii_put16(rgep, PHY_1F_REG, 0x0000);
		rge_mii_put16(rgep, PHY_0E_REG, 0x0000);
		rge_mii_put16(rgep, PHY_1F_REG, 0x0000);
	}
	rge_mii_put16(rgep, MII_AN_ADVERT, anar);
	rge_mii_put16(rgep, MII_1000BASE_T_CONTROL, gigctrl);
	rge_mii_put16(rgep, MII_CONTROL, control);

	RGE_DEBUG(("rge_phy_update: anar <- 0x%x", anar));
	RGE_DEBUG(("rge_phy_update: control <- 0x%x", control));
	RGE_DEBUG(("rge_phy_update: gigctrl <- 0x%x", gigctrl));
}

void rge_phy_init(rge_t *rgep);
#pragma	no_inline(rge_phy_init)

void
rge_phy_init(rge_t *rgep)
{
	rgep->phy_mii_addr = 1;

	/*
	 * Below phy config steps are copied from the Programming Guide
	 * (there's no detail comments for these steps.)
	 */
	switch (rgep->chipid.mac_ver) {
	case MAC_VER_8169S_D:
	case MAC_VER_8169S_E :
		rge_mii_put16(rgep, PHY_1F_REG, 0x0001);
		rge_mii_put16(rgep, PHY_15_REG, 0x1000);
		rge_mii_put16(rgep, PHY_18_REG, 0x65c7);
		rge_mii_put16(rgep, PHY_ANAR_REG, 0x0000);
		rge_mii_put16(rgep, PHY_ID_REG_2, 0x00a1);
		rge_mii_put16(rgep, PHY_ID_REG_1, 0x0008);
		rge_mii_put16(rgep, PHY_BMSR_REG, 0x1020);
		rge_mii_put16(rgep, PHY_BMCR_REG, 0x1000);
		rge_mii_put16(rgep, PHY_ANAR_REG, 0x0800);
		rge_mii_put16(rgep, PHY_ANAR_REG, 0x0000);
		rge_mii_put16(rgep, PHY_ANAR_REG, 0x7000);
		rge_mii_put16(rgep, PHY_ID_REG_2, 0xff41);
		rge_mii_put16(rgep, PHY_ID_REG_1, 0xde60);
		rge_mii_put16(rgep, PHY_BMSR_REG, 0x0140);
		rge_mii_put16(rgep, PHY_BMCR_REG, 0x0077);
		rge_mii_put16(rgep, PHY_ANAR_REG, 0x7800);
		rge_mii_put16(rgep, PHY_ANAR_REG, 0x7000);
		rge_mii_put16(rgep, PHY_ANAR_REG, 0xa000);
		rge_mii_put16(rgep, PHY_ID_REG_2, 0xdf01);
		rge_mii_put16(rgep, PHY_ID_REG_1, 0xdf20);
		rge_mii_put16(rgep, PHY_BMSR_REG, 0xff95);
		rge_mii_put16(rgep, PHY_BMCR_REG, 0xfa00);
		rge_mii_put16(rgep, PHY_ANAR_REG, 0xa800);
		rge_mii_put16(rgep, PHY_ANAR_REG, 0xa000);
		rge_mii_put16(rgep, PHY_ANAR_REG, 0xb000);
		rge_mii_put16(rgep, PHY_ID_REG_2, 0xff41);
		rge_mii_put16(rgep, PHY_ID_REG_1, 0xde20);
		rge_mii_put16(rgep, PHY_BMSR_REG, 0x0140);
		rge_mii_put16(rgep, PHY_BMCR_REG, 0x00bb);
		rge_mii_put16(rgep, PHY_ANAR_REG, 0xb800);
		rge_mii_put16(rgep, PHY_ANAR_REG, 0xb000);
		rge_mii_put16(rgep, PHY_ANAR_REG, 0xf000);
		rge_mii_put16(rgep, PHY_ID_REG_2, 0xdf01);
		rge_mii_put16(rgep, PHY_ID_REG_1, 0xdf20);
		rge_mii_put16(rgep, PHY_BMSR_REG, 0xff95);
		rge_mii_put16(rgep, PHY_BMCR_REG, 0xbf00);
		rge_mii_put16(rgep, PHY_ANAR_REG, 0xf800);
		rge_mii_put16(rgep, PHY_ANAR_REG, 0xf000);
		rge_mii_put16(rgep, PHY_ANAR_REG, 0x0000);
		rge_mii_put16(rgep, PHY_1F_REG, 0x0000);
		rge_mii_put16(rgep, PHY_0B_REG, 0x0000);
		break;

	case MAC_VER_8169SB:
		rge_mii_put16(rgep, PHY_1F_REG, 0x0001);
		rge_mii_put16(rgep, PHY_1B_REG, 0xD41E);
		rge_mii_put16(rgep, PHY_0E_REG, 0x7bff);
		rge_mii_put16(rgep, PHY_GBCR_REG, GBCR_DEFAULT);
		rge_mii_put16(rgep, PHY_1F_REG, 0x0002);
		rge_mii_put16(rgep, PHY_BMSR_REG, 0x90D0);
		rge_mii_put16(rgep, PHY_1F_REG, 0x0000);
		break;

	case MAC_VER_8169SC:
		rge_mii_put16(rgep, PHY_1F_REG, 0x0001);
		rge_mii_put16(rgep, PHY_ANER_REG, 0x0078);
		rge_mii_put16(rgep, PHY_ANNPRR_REG, 0x05dc);
		rge_mii_put16(rgep, PHY_GBCR_REG, 0x2672);
		rge_mii_put16(rgep, PHY_GBSR_REG, 0x6a14);
		rge_mii_put16(rgep, PHY_0B_REG, 0x7cb0);
		rge_mii_put16(rgep, PHY_0C_REG, 0xdb80);
		rge_mii_put16(rgep, PHY_1B_REG, 0xc414);
		rge_mii_put16(rgep, PHY_1C_REG, 0xef03);
		rge_mii_put16(rgep, PHY_1D_REG, 0x3dc8);
		rge_mii_put16(rgep, PHY_1F_REG, 0x0003);
		rge_mii_put16(rgep, PHY_13_REG, 0x0600);
		rge_mii_put16(rgep, PHY_1F_REG, 0x0000);
		break;

	case MAC_VER_8168:
		rge_mii_put16(rgep, PHY_1F_REG, 0x0001);
		rge_mii_put16(rgep, PHY_ANER_REG, 0x00aa);
		rge_mii_put16(rgep, PHY_ANNPTR_REG, 0x3173);
		rge_mii_put16(rgep, PHY_ANNPRR_REG, 0x08fc);
		rge_mii_put16(rgep, PHY_GBCR_REG, 0xe2d0);
		rge_mii_put16(rgep, PHY_0B_REG, 0x941a);
		rge_mii_put16(rgep, PHY_18_REG, 0x65fe);
		rge_mii_put16(rgep, PHY_1C_REG, 0x1e02);
		rge_mii_put16(rgep, PHY_1F_REG, 0x0002);
		rge_mii_put16(rgep, PHY_ANNPTR_REG, 0x103e);
		rge_mii_put16(rgep, PHY_1F_REG, 0x0000);
		break;

	case MAC_VER_8168B_B:
	case MAC_VER_8168B_C:
		rge_mii_put16(rgep, PHY_1F_REG, 0x0001);
		rge_mii_put16(rgep, PHY_0B_REG, 0x94b0);
		rge_mii_put16(rgep, PHY_1B_REG, 0xc416);
		rge_mii_put16(rgep, PHY_1F_REG, 0x0003);
		rge_mii_put16(rgep, PHY_12_REG, 0x6096);
		rge_mii_put16(rgep, PHY_1F_REG, 0x0000);
		break;
	}
}

void rge_chip_ident(rge_t *rgep);
#pragma	no_inline(rge_chip_ident)

void
rge_chip_ident(rge_t *rgep)
{
	chip_id_t *chip = &rgep->chipid;
	uint32_t val32;
	uint16_t val16;

	/*
	 * Read and record MAC version
	 */
	val32 = rge_reg_get32(rgep, TX_CONFIG_REG);
	val32 &= HW_VERSION_ID_0 | HW_VERSION_ID_1;
	chip->mac_ver = val32;
	chip->is_pcie = pci_lcap_locate(rgep->cfg_handle,
	    PCI_CAP_ID_PCI_E, &val16) == DDI_SUCCESS;

	/*
	 * Workaround for 8101E_C
	 */
	chip->enable_mac_first = !chip->is_pcie;
	if (chip->mac_ver == MAC_VER_8101E_C) {
		chip->is_pcie = B_FALSE;
	}

	/*
	 * Read and record PHY version
	 */
	val16 = rge_mii_get16(rgep, PHY_ID_REG_2);
	val16 &= PHY_VER_MASK;
	chip->phy_ver = val16;

	/* set pci latency timer */
	if (chip->mac_ver == MAC_VER_8169 ||
	    chip->mac_ver == MAC_VER_8169S_D ||
	    chip->mac_ver == MAC_VER_8169S_E ||
	    chip->mac_ver == MAC_VER_8169SC)
		pci_config_put8(rgep->cfg_handle, PCI_CONF_LATENCY_TIMER, 0x40);

	if (chip->mac_ver == MAC_VER_8169SC) {
		val16 = rge_reg_get16(rgep, RT_CONFIG_1_REG);
		val16 &= 0x0300;
		if (val16 == 0x1)	/* 66Mhz PCI */
			rge_reg_put32(rgep, 0x7c, 0x000700ff);
		else if (val16 == 0x0) /* 33Mhz PCI */
			rge_reg_put32(rgep, 0x7c, 0x0007ff00);
	}

	/*
	 * PCIE chipset require the Rx buffer start address must be
	 * 8-byte alignment and the Rx buffer size must be multiple of 8.
	 * We'll just use bcopy in receive procedure for the PCIE chipset.
	 */
	if (chip->is_pcie) {
		rgep->chip_flags |= CHIP_FLAG_FORCE_BCOPY;
		if (rgep->default_mtu > ETHERMTU) {
			rge_notice(rgep, "Jumbo packets not supported "
			    "for this PCIE chipset");
			rgep->default_mtu = ETHERMTU;
		}
	}
	if (rgep->chip_flags & CHIP_FLAG_FORCE_BCOPY)
		rgep->head_room = 0;
	else
		rgep->head_room = RGE_HEADROOM;

	/*
	 * Initialize other variables.
	 */
	if (rgep->default_mtu < ETHERMTU || rgep->default_mtu > RGE_JUMBO_MTU)
		rgep->default_mtu = ETHERMTU;
	if (rgep->default_mtu > ETHERMTU) {
		rgep->rxbuf_size = RGE_BUFF_SIZE_JUMBO;
		rgep->txbuf_size = RGE_BUFF_SIZE_JUMBO;
		rgep->ethmax_size = RGE_JUMBO_SIZE;
	} else {
		rgep->rxbuf_size = RGE_BUFF_SIZE_STD;
		rgep->txbuf_size = RGE_BUFF_SIZE_STD;
		rgep->ethmax_size = ETHERMAX;
	}
	chip->rxconfig = RX_CONFIG_DEFAULT;
	chip->txconfig = TX_CONFIG_DEFAULT;

	/* interval to update statistics for polling mode */
	rgep->tick_delta = drv_usectohz(1000*1000/CLK_TICK);

	/* ensure we are not in polling mode */
	rgep->curr_tick = ddi_get_lbolt() - 2*rgep->tick_delta;
	RGE_TRACE(("%s: MAC version = %x, PHY version = %x",
	    rgep->ifname, chip->mac_ver, chip->phy_ver));
}

/*
 * Perform first-stage chip (re-)initialisation, using only config-space
 * accesses:
 *
 * + Read the vendor/device/revision/subsystem/cache-line-size registers,
 *   returning the data in the structure pointed to by <idp>.
 * + Enable Memory Space accesses.
 * + Enable Bus Mastering according.
 */
void rge_chip_cfg_init(rge_t *rgep, chip_id_t *cidp);
#pragma	no_inline(rge_chip_cfg_init)

void
rge_chip_cfg_init(rge_t *rgep, chip_id_t *cidp)
{
	ddi_acc_handle_t handle;
	uint16_t commd;

	handle = rgep->cfg_handle;

	/*
	 * Save PCI cache line size and subsystem vendor ID
	 */
	cidp->command = pci_config_get16(handle, PCI_CONF_COMM);
	cidp->vendor = pci_config_get16(handle, PCI_CONF_VENID);
	cidp->device = pci_config_get16(handle, PCI_CONF_DEVID);
	cidp->subven = pci_config_get16(handle, PCI_CONF_SUBVENID);
	cidp->subdev = pci_config_get16(handle, PCI_CONF_SUBSYSID);
	cidp->revision = pci_config_get8(handle, PCI_CONF_REVID);
	cidp->clsize = pci_config_get8(handle, PCI_CONF_CACHE_LINESZ);
	cidp->latency = pci_config_get8(handle, PCI_CONF_LATENCY_TIMER);

	/*
	 * Turn on Master Enable (DMA) and IO Enable bits.
	 * Enable PCI Memory Space accesses
	 */
	commd = cidp->command;
	commd |= PCI_COMM_ME | PCI_COMM_MAE | PCI_COMM_IO;
	pci_config_put16(handle, PCI_CONF_COMM, commd);

	RGE_DEBUG(("rge_chip_cfg_init: vendor 0x%x device 0x%x revision 0x%x",
	    cidp->vendor, cidp->device, cidp->revision));
	RGE_DEBUG(("rge_chip_cfg_init: subven 0x%x subdev 0x%x",
	    cidp->subven, cidp->subdev));
	RGE_DEBUG(("rge_chip_cfg_init: clsize %d latency %d command 0x%x",
	    cidp->clsize, cidp->latency, cidp->command));
}

int rge_chip_reset(rge_t *rgep);
#pragma	no_inline(rge_chip_reset)

int
rge_chip_reset(rge_t *rgep)
{
	int i;
	uint8_t val8;

	/*
	 * Chip should be in STOP state
	 */
	rge_reg_clr8(rgep, RT_COMMAND_REG,
	    RT_COMMAND_RX_ENABLE | RT_COMMAND_TX_ENABLE);

	/*
	 * Disable interrupt
	 */
	rgep->int_mask = INT_MASK_NONE;
	rge_reg_put16(rgep, INT_MASK_REG, rgep->int_mask);

	/*
	 * Clear pended interrupt
	 */
	rge_reg_put16(rgep, INT_STATUS_REG, INT_MASK_ALL);

	/*
	 * Reset chip
	 */
	rge_reg_set8(rgep, RT_COMMAND_REG, RT_COMMAND_RESET);

	/*
	 * Wait for reset success
	 */
	for (i = 0; i < CHIP_RESET_LOOP; i++) {
		drv_usecwait(10);
		val8 = rge_reg_get8(rgep, RT_COMMAND_REG);
		if (!(val8 & RT_COMMAND_RESET)) {
			rgep->rge_chip_state = RGE_CHIP_RESET;
			return (0);
		}
	}
	RGE_REPORT((rgep, "rge_chip_reset fail."));
	return (-1);
}

void rge_chip_init(rge_t *rgep);
#pragma	no_inline(rge_chip_init)

void
rge_chip_init(rge_t *rgep)
{
	uint32_t val32;
	uint32_t val16;
	uint32_t *hashp;
	chip_id_t *chip = &rgep->chipid;

	/*
	 * Increase the threshold voltage of RX sensitivity
	 */
	if (chip->mac_ver == MAC_VER_8168B_B ||
	    chip->mac_ver == MAC_VER_8168B_C ||
	    chip->mac_ver == MAC_VER_8101E) {
		rge_ephy_put16(rgep, 0x01, 0x1bd3);
	}

	if (chip->mac_ver == MAC_VER_8168 ||
	    chip->mac_ver == MAC_VER_8168B_B) {
		val16 = rge_reg_get8(rgep, PHY_STATUS_REG);
		val16 = 0x12<<8 | val16;
		rge_reg_put16(rgep, PHY_STATUS_REG, val16);
		rge_reg_put32(rgep, RT_CSI_DATA_REG, 0x00021c01);
		rge_reg_put32(rgep, RT_CSI_ACCESS_REG, 0x8000f088);
		rge_reg_put32(rgep, RT_CSI_DATA_REG, 0x00004000);
		rge_reg_put32(rgep, RT_CSI_ACCESS_REG, 0x8000f0b0);
		rge_reg_put32(rgep, RT_CSI_ACCESS_REG, 0x0000f068);
		val32 = rge_reg_get32(rgep, RT_CSI_DATA_REG);
		val32 |= 0x7000;
		val32 &= 0xffff5fff;
		rge_reg_put32(rgep, RT_CSI_DATA_REG, val32);
		rge_reg_put32(rgep, RT_CSI_ACCESS_REG, 0x8000f068);
	}

	/*
	 * Config MII register
	 */
	rgep->param_link_up = LINK_STATE_DOWN;
	rge_phy_update(rgep);

	/*
	 * Enable Rx checksum offload.
	 *  Then for vlan support, we must enable receive vlan de-tagging.
	 *  Otherwise, there'll be checksum error.
	 */
	val16 = rge_reg_get16(rgep, CPLUS_COMMAND_REG);
	val16 |= RX_CKSM_OFFLOAD | RX_VLAN_DETAG;
	if (chip->mac_ver == MAC_VER_8169S_D) {
		val16 |= CPLUS_BIT14 | MUL_PCI_RW_ENABLE;
		rge_reg_put8(rgep, RESV_82_REG, 0x01);
	}
	if (chip->mac_ver == MAC_VER_8169S_E ||
	    chip->mac_ver == MAC_VER_8169SC) {
		val16 |= MUL_PCI_RW_ENABLE;
	}
	rge_reg_put16(rgep, CPLUS_COMMAND_REG, val16 & (~0x03));

	/*
	 * Start transmit/receive before set tx/rx configuration register
	 */
	if (chip->enable_mac_first)
		rge_reg_set8(rgep, RT_COMMAND_REG,
		    RT_COMMAND_RX_ENABLE | RT_COMMAND_TX_ENABLE);

	/*
	 * Set dump tally counter register
	 */
	val32 = rgep->dma_area_stats.cookie.dmac_laddress >> 32;
	rge_reg_put32(rgep, DUMP_COUNTER_REG_1, val32);
	val32 = rge_reg_get32(rgep, DUMP_COUNTER_REG_0);
	val32 &= DUMP_COUNTER_REG_RESV;
	val32 |= rgep->dma_area_stats.cookie.dmac_laddress;
	rge_reg_put32(rgep, DUMP_COUNTER_REG_0, val32);

	/*
	 * Change to config register write enable mode
	 */
	rge_reg_set8(rgep, RT_93c46_COMMOND_REG, RT_93c46_MODE_CONFIG);

	/*
	 * Set Tx/Rx maximum packet size
	 */
	if (rgep->default_mtu > ETHERMTU) {
		rge_reg_put8(rgep, TX_MAX_PKTSIZE_REG, TX_PKTSIZE_JUMBO);
		rge_reg_put16(rgep, RX_MAX_PKTSIZE_REG, RX_PKTSIZE_JUMBO);
	} else if (rgep->chipid.mac_ver != MAC_VER_8101E) {
		rge_reg_put8(rgep, TX_MAX_PKTSIZE_REG, TX_PKTSIZE_STD);
		rge_reg_put16(rgep, RX_MAX_PKTSIZE_REG, RX_PKTSIZE_STD);
	} else {
		rge_reg_put8(rgep, TX_MAX_PKTSIZE_REG, TX_PKTSIZE_STD_8101E);
		rge_reg_put16(rgep, RX_MAX_PKTSIZE_REG, RX_PKTSIZE_STD_8101E);
	}

	/*
	 * Set receive configuration register
	 */
	val32 = rge_reg_get32(rgep, RX_CONFIG_REG);
	val32 &= RX_CONFIG_REG_RESV;
	if (rgep->promisc)
		val32 |= RX_ACCEPT_ALL_PKT;
	rge_reg_put32(rgep, RX_CONFIG_REG, val32 | chip->rxconfig);

	/*
	 * Set transmit configuration register
	 */
	val32 = rge_reg_get32(rgep, TX_CONFIG_REG);
	val32 &= TX_CONFIG_REG_RESV;
	rge_reg_put32(rgep, TX_CONFIG_REG, val32 | chip->txconfig);

	/*
	 * Set Tx/Rx descriptor register
	 */
	val32 = rgep->tx_desc.cookie.dmac_laddress;
	rge_reg_put32(rgep, NORMAL_TX_RING_ADDR_LO_REG, val32);
	val32 = rgep->tx_desc.cookie.dmac_laddress >> 32;
	rge_reg_put32(rgep, NORMAL_TX_RING_ADDR_HI_REG, val32);
	rge_reg_put32(rgep, HIGH_TX_RING_ADDR_LO_REG, 0);
	rge_reg_put32(rgep, HIGH_TX_RING_ADDR_HI_REG, 0);
	val32 = rgep->rx_desc.cookie.dmac_laddress;
	rge_reg_put32(rgep, RX_RING_ADDR_LO_REG, val32);
	val32 = rgep->rx_desc.cookie.dmac_laddress >> 32;
	rge_reg_put32(rgep, RX_RING_ADDR_HI_REG, val32);

	/*
	 * Suggested setting from Realtek
	 */
	if (rgep->chipid.mac_ver != MAC_VER_8101E)
		rge_reg_put16(rgep, RESV_E2_REG, 0x282a);
	else
		rge_reg_put16(rgep, RESV_E2_REG, 0x0000);

	/*
	 * Set multicast register
	 */
	hashp = (uint32_t *)rgep->mcast_hash;
	if (rgep->promisc) {
		rge_reg_put32(rgep, MULTICAST_0_REG, ~0U);
		rge_reg_put32(rgep, MULTICAST_4_REG, ~0U);
	} else {
		rge_reg_put32(rgep, MULTICAST_0_REG, RGE_BSWAP_32(hashp[0]));
		rge_reg_put32(rgep, MULTICAST_4_REG, RGE_BSWAP_32(hashp[1]));
	}

	/*
	 * Msic register setting:
	 *   -- Missed packet counter: clear it
	 *   -- TimerInt Register
	 *   -- Timer count register
	 */
	rge_reg_put32(rgep, RX_PKT_MISS_COUNT_REG, 0);
	rge_reg_put32(rgep, TIMER_INT_REG, TIMER_INT_NONE);
	rge_reg_put32(rgep, TIMER_COUNT_REG, 0);

	/*
	 * disable the Unicast Wakeup Frame capability
	 */
	rge_reg_clr8(rgep, RT_CONFIG_5_REG, RT_UNI_WAKE_FRAME);

	/*
	 * Return to normal network/host communication mode
	 */
	rge_reg_clr8(rgep, RT_93c46_COMMOND_REG, RT_93c46_MODE_CONFIG);
	drv_usecwait(20);
}

/*
 * rge_chip_start() -- start the chip transmitting and/or receiving,
 * including enabling interrupts
 */
void rge_chip_start(rge_t *rgep);
#pragma	no_inline(rge_chip_start)

void
rge_chip_start(rge_t *rgep)
{
	/*
	 * Clear statistics
	 */
	bzero(&rgep->stats, sizeof (rge_stats_t));
	DMA_ZERO(rgep->dma_area_stats);

	/*
	 * Start transmit/receive
	 */
	rge_reg_set8(rgep, RT_COMMAND_REG,
	    RT_COMMAND_RX_ENABLE | RT_COMMAND_TX_ENABLE);

	/*
	 * Enable interrupt
	 */
	rgep->int_mask = RGE_INT_MASK;
	if (rgep->chipid.is_pcie) {
		rgep->int_mask |= NO_TXDESC_INT;
	}
	rgep->rx_fifo_ovf = 0;
	rgep->int_mask |= RX_FIFO_OVERFLOW_INT;
	rge_reg_put16(rgep, INT_MASK_REG, rgep->int_mask);

	/*
	 * All done!
	 */
	rgep->rge_chip_state = RGE_CHIP_RUNNING;
}

/*
 * rge_chip_stop() -- stop board receiving
 *
 * Since this function is also invoked by rge_quiesce(), it
 * must not block; also, no tracing or logging takes place
 * when invoked by rge_quiesce().
 */
void rge_chip_stop(rge_t *rgep, boolean_t fault);
#pragma	no_inline(rge_chip_stop)

void
rge_chip_stop(rge_t *rgep, boolean_t fault)
{
	/*
	 * Disable interrupt
	 */
	rgep->int_mask = INT_MASK_NONE;
	rge_reg_put16(rgep, INT_MASK_REG, rgep->int_mask);

	/*
	 * Clear pended interrupt
	 */
	if (!rgep->suspended) {
		rge_reg_put16(rgep, INT_STATUS_REG, INT_MASK_ALL);
	}

	/*
	 * Stop the board and disable transmit/receive
	 */
	rge_reg_clr8(rgep, RT_COMMAND_REG,
	    RT_COMMAND_RX_ENABLE | RT_COMMAND_TX_ENABLE);

	if (fault)
		rgep->rge_chip_state = RGE_CHIP_FAULT;
	else
		rgep->rge_chip_state = RGE_CHIP_STOPPED;
}

/*
 * rge_get_mac_addr() -- get the MAC address on NIC
 */
static void rge_get_mac_addr(rge_t *rgep);
#pragma	inline(rge_get_mac_addr)

static void
rge_get_mac_addr(rge_t *rgep)
{
	uint8_t *macaddr = rgep->netaddr;
	uint32_t val32;

	/*
	 * Read first 4-byte of mac address
	 */
	val32 = rge_reg_get32(rgep, ID_0_REG);
	macaddr[0] = val32 & 0xff;
	val32 = val32 >> 8;
	macaddr[1] = val32 & 0xff;
	val32 = val32 >> 8;
	macaddr[2] = val32 & 0xff;
	val32 = val32 >> 8;
	macaddr[3] = val32 & 0xff;

	/*
	 * Read last 2-byte of mac address
	 */
	val32 = rge_reg_get32(rgep, ID_4_REG);
	macaddr[4] = val32 & 0xff;
	val32 = val32 >> 8;
	macaddr[5] = val32 & 0xff;
}

static void rge_set_mac_addr(rge_t *rgep);
#pragma	inline(rge_set_mac_addr)

static void
rge_set_mac_addr(rge_t *rgep)
{
	uint8_t *p = rgep->netaddr;
	uint32_t val32;

	/*
	 * Change to config register write enable mode
	 */
	rge_reg_set8(rgep, RT_93c46_COMMOND_REG, RT_93c46_MODE_CONFIG);

	/*
	 * Get first 4 bytes of mac address
	 */
	val32 = p[3];
	val32 = val32 << 8;
	val32 |= p[2];
	val32 = val32 << 8;
	val32 |= p[1];
	val32 = val32 << 8;
	val32 |= p[0];

	/*
	 * Set first 4 bytes of mac address
	 */
	rge_reg_put32(rgep, ID_0_REG, val32);

	/*
	 * Get last 2 bytes of mac address
	 */
	val32 = p[5];
	val32 = val32 << 8;
	val32 |= p[4];

	/*
	 * Set last 2 bytes of mac address
	 */
	val32 |= rge_reg_get32(rgep, ID_4_REG) & ~0xffff;
	rge_reg_put32(rgep, ID_4_REG, val32);

	/*
	 * Return to normal network/host communication mode
	 */
	rge_reg_clr8(rgep, RT_93c46_COMMOND_REG, RT_93c46_MODE_CONFIG);
}

static void rge_set_multi_addr(rge_t *rgep);
#pragma	inline(rge_set_multi_addr)

static void
rge_set_multi_addr(rge_t *rgep)
{
	uint32_t *hashp;

	hashp = (uint32_t *)rgep->mcast_hash;

	/*
	 * Change to config register write enable mode
	 */
	if (rgep->chipid.mac_ver == MAC_VER_8169SC) {
		rge_reg_set8(rgep, RT_93c46_COMMOND_REG, RT_93c46_MODE_CONFIG);
	}
	if (rgep->promisc) {
		rge_reg_put32(rgep, MULTICAST_0_REG, ~0U);
		rge_reg_put32(rgep, MULTICAST_4_REG, ~0U);
	} else {
		rge_reg_put32(rgep, MULTICAST_0_REG, RGE_BSWAP_32(hashp[0]));
		rge_reg_put32(rgep, MULTICAST_4_REG, RGE_BSWAP_32(hashp[1]));
	}

	/*
	 * Return to normal network/host communication mode
	 */
	if (rgep->chipid.mac_ver == MAC_VER_8169SC) {
		rge_reg_clr8(rgep, RT_93c46_COMMOND_REG, RT_93c46_MODE_CONFIG);
	}
}

static void rge_set_promisc(rge_t *rgep);
#pragma	inline(rge_set_promisc)

static void
rge_set_promisc(rge_t *rgep)
{
	if (rgep->promisc)
		rge_reg_set32(rgep, RX_CONFIG_REG, RX_ACCEPT_ALL_PKT);
	else
		rge_reg_clr32(rgep, RX_CONFIG_REG, RX_ACCEPT_ALL_PKT);
}

/*
 * rge_chip_sync() -- program the chip with the unicast MAC address,
 * the multicast hash table, the required level of promiscuity, and
 * the current loopback mode ...
 */
void rge_chip_sync(rge_t *rgep, enum rge_sync_op todo);
#pragma	no_inline(rge_chip_sync)

void
rge_chip_sync(rge_t *rgep, enum rge_sync_op todo)
{
	switch (todo) {
	case RGE_GET_MAC:
		rge_get_mac_addr(rgep);
		break;
	case RGE_SET_MAC:
		/* Reprogram the unicast MAC address(es) ... */
		rge_set_mac_addr(rgep);
		break;
	case RGE_SET_MUL:
		/* Reprogram the hashed multicast address table ... */
		rge_set_multi_addr(rgep);
		break;
	case RGE_SET_PROMISC:
		/* Set or clear the PROMISCUOUS mode bit */
		rge_set_multi_addr(rgep);
		rge_set_promisc(rgep);
		break;
	default:
		break;
	}
}

void rge_chip_blank(void *arg, time_t ticks, uint_t count, int flag);
#pragma	no_inline(rge_chip_blank)

/* ARGSUSED */
void
rge_chip_blank(void *arg, time_t ticks, uint_t count, int flag)
{
	_NOTE(ARGUNUSED(arg, ticks, count));
}

void rge_tx_trigger(rge_t *rgep);
#pragma	no_inline(rge_tx_trigger)

void
rge_tx_trigger(rge_t *rgep)
{
	rge_reg_put8(rgep, TX_RINGS_POLL_REG, NORMAL_TX_RING_POLL);
}

void rge_hw_stats_dump(rge_t *rgep);
#pragma	no_inline(rge_tx_trigger)

void
rge_hw_stats_dump(rge_t *rgep)
{
	int i = 0;
	uint32_t regval = 0;

	if (rgep->rge_mac_state == RGE_MAC_STOPPED)
		return;

	regval = rge_reg_get32(rgep, DUMP_COUNTER_REG_0);
	while (regval & DUMP_START) {
		drv_usecwait(100);
		if (++i > STATS_DUMP_LOOP) {
			RGE_DEBUG(("rge h/w statistics dump fail!"));
			rgep->rge_chip_state = RGE_CHIP_ERROR;
			return;
		}
		regval = rge_reg_get32(rgep, DUMP_COUNTER_REG_0);
	}
	DMA_SYNC(rgep->dma_area_stats, DDI_DMA_SYNC_FORKERNEL);

	/*
	 * Start H/W statistics dump for RTL8169 chip
	 */
	rge_reg_set32(rgep, DUMP_COUNTER_REG_0, DUMP_START);
}

/*
 * ========== Hardware interrupt handler ==========
 */

#undef	RGE_DBG
#define	RGE_DBG		RGE_DBG_INT	/* debug flag for this code	*/

static void rge_wake_factotum(rge_t *rgep);
#pragma	inline(rge_wake_factotum)

static void
rge_wake_factotum(rge_t *rgep)
{
	if (rgep->factotum_flag == 0) {
		rgep->factotum_flag = 1;
		(void) ddi_intr_trigger_softint(rgep->factotum_hdl, NULL);
	}
}

/*
 *	rge_intr() -- handle chip interrupts
 */
uint_t rge_intr(caddr_t arg1, caddr_t arg2);
#pragma	no_inline(rge_intr)

uint_t
rge_intr(caddr_t arg1, caddr_t arg2)
{
	rge_t *rgep = (rge_t *)arg1;
	uint16_t int_status;
	clock_t	now;
	uint32_t tx_pkts;
	uint32_t rx_pkts;
	uint32_t poll_rate;
	uint32_t opt_pkts;
	uint32_t opt_intrs;
	boolean_t update_int_mask = B_FALSE;
	uint32_t itimer;

	_NOTE(ARGUNUSED(arg2))

	mutex_enter(rgep->genlock);

	if (rgep->suspended) {
		mutex_exit(rgep->genlock);
		return (DDI_INTR_UNCLAIMED);
	}

	/*
	 * Was this interrupt caused by our device...
	 */
	int_status = rge_reg_get16(rgep, INT_STATUS_REG);
	if (!(int_status & rgep->int_mask)) {
		mutex_exit(rgep->genlock);
		return (DDI_INTR_UNCLAIMED);
				/* indicate it wasn't our interrupt */
	}
	rgep->stats.intr++;

	/*
	 * Clear interrupt
	 *	For PCIE chipset, we need disable interrupt first.
	 */
	if (rgep->chipid.is_pcie) {
		rge_reg_put16(rgep, INT_MASK_REG, INT_MASK_NONE);
		update_int_mask = B_TRUE;
	}
	rge_reg_put16(rgep, INT_STATUS_REG, int_status);

	/*
	 * Calculate optimal polling interval
	 */
	now = ddi_get_lbolt();
	if (now - rgep->curr_tick >= rgep->tick_delta &&
	    (rgep->param_link_speed == RGE_SPEED_1000M ||
	    rgep->param_link_speed == RGE_SPEED_100M)) {
		/* number of rx and tx packets in the last tick */
		tx_pkts = rgep->stats.opackets - rgep->last_opackets;
		rx_pkts = rgep->stats.rpackets - rgep->last_rpackets;

		rgep->last_opackets = rgep->stats.opackets;
		rgep->last_rpackets = rgep->stats.rpackets;

		/* restore interrupt mask */
		rgep->int_mask |= TX_OK_INT | RX_OK_INT;
		if (rgep->chipid.is_pcie) {
			rgep->int_mask |= NO_TXDESC_INT;
		}

		/* optimal number of packets in a tick */
		if (rgep->param_link_speed == RGE_SPEED_1000M) {
			opt_pkts = (1000*1000*1000/8)/ETHERMTU/CLK_TICK;
		} else {
			opt_pkts = (100*1000*1000/8)/ETHERMTU/CLK_TICK;
		}

		/*
		 * calculate polling interval based on rx and tx packets
		 * in the last tick
		 */
		poll_rate = 0;
		if (now - rgep->curr_tick < 2*rgep->tick_delta) {
			opt_intrs = opt_pkts/TX_COALESC;
			if (tx_pkts > opt_intrs) {
				poll_rate = max(tx_pkts/TX_COALESC, opt_intrs);
				rgep->int_mask &= ~(TX_OK_INT | NO_TXDESC_INT);
			}

			opt_intrs = opt_pkts/RX_COALESC;
			if (rx_pkts > opt_intrs) {
				opt_intrs = max(rx_pkts/RX_COALESC, opt_intrs);
				poll_rate = max(opt_intrs, poll_rate);
				rgep->int_mask &= ~RX_OK_INT;
			}
			/* ensure poll_rate reasonable */
			poll_rate = min(poll_rate, opt_pkts*4);
		}

		if (poll_rate) {
			/* move to polling mode */
			if (rgep->chipid.is_pcie) {
				itimer = (TIMER_CLK_PCIE/CLK_TICK)/poll_rate;
			} else {
				itimer = (TIMER_CLK_PCI/CLK_TICK)/poll_rate;
			}
		} else {
			/* move to normal mode */
			itimer = 0;
		}
		RGE_DEBUG(("%s: poll: itimer:%d int_mask:0x%x",
		    __func__, itimer, rgep->int_mask));
		rge_reg_put32(rgep, TIMER_INT_REG, itimer);

		/* update timestamp for statistics */
		rgep->curr_tick = now;

		/* reset timer */
		int_status |= TIME_OUT_INT;

		update_int_mask = B_TRUE;
	}

	if (int_status & TIME_OUT_INT) {
		rge_reg_put32(rgep, TIMER_COUNT_REG, 0);
	}

	/* flush post writes */
	(void) rge_reg_get16(rgep, INT_STATUS_REG);

	/*
	 * Cable link change interrupt
	 */
	if (int_status & LINK_CHANGE_INT) {
		rge_chip_cyclic(rgep);
	}

	if (int_status & RX_FIFO_OVERFLOW_INT) {
		/* start rx watchdog timeout detection */
		rgep->rx_fifo_ovf = 1;
		if (rgep->int_mask & RX_FIFO_OVERFLOW_INT) {
			rgep->int_mask &= ~RX_FIFO_OVERFLOW_INT;
			update_int_mask = B_TRUE;
		}
	} else if (int_status & RGE_RX_INT) {
		/* stop rx watchdog timeout detection */
		rgep->rx_fifo_ovf = 0;
		if ((rgep->int_mask & RX_FIFO_OVERFLOW_INT) == 0) {
			rgep->int_mask |= RX_FIFO_OVERFLOW_INT;
			update_int_mask = B_TRUE;
		}
	}

	mutex_exit(rgep->genlock);

	/*
	 * Receive interrupt
	 */
	if (int_status & RGE_RX_INT)
		rge_receive(rgep);

	/*
	 * Transmit interrupt
	 */
	if (int_status & TX_ERR_INT) {
		RGE_REPORT((rgep, "tx error happened, resetting the chip "));
		mutex_enter(rgep->genlock);
		rgep->rge_chip_state = RGE_CHIP_ERROR;
		mutex_exit(rgep->genlock);
	} else if ((rgep->chipid.is_pcie && (int_status & NO_TXDESC_INT)) ||
	    ((int_status & TX_OK_INT) && rgep->tx_free < RGE_SEND_SLOTS/8)) {
		(void) ddi_intr_trigger_softint(rgep->resched_hdl, NULL);
	}

	/*
	 * System error interrupt
	 */
	if (int_status & SYS_ERR_INT) {
		RGE_REPORT((rgep, "sys error happened, resetting the chip "));
		mutex_enter(rgep->genlock);
		rgep->rge_chip_state = RGE_CHIP_ERROR;
		mutex_exit(rgep->genlock);
	}

	/*
	 * Re-enable interrupt for PCIE chipset or install new int_mask
	 */
	if (update_int_mask)
		rge_reg_put16(rgep, INT_MASK_REG, rgep->int_mask);

	return (DDI_INTR_CLAIMED);	/* indicate it was our interrupt */
}

/*
 * ========== Factotum, implemented as a softint handler ==========
 */

#undef	RGE_DBG
#define	RGE_DBG		RGE_DBG_FACT	/* debug flag for this code	*/

static boolean_t rge_factotum_link_check(rge_t *rgep);
#pragma	no_inline(rge_factotum_link_check)

static boolean_t
rge_factotum_link_check(rge_t *rgep)
{
	uint8_t media_status;
	int32_t link;

	media_status = rge_reg_get8(rgep, PHY_STATUS_REG);
	link = (media_status & PHY_STATUS_LINK_UP) ?
	    LINK_STATE_UP : LINK_STATE_DOWN;
	if (rgep->param_link_up != link) {
		/*
		 * Link change.
		 */
		rgep->param_link_up = link;

		if (link == LINK_STATE_UP) {
			if (media_status & PHY_STATUS_1000MF) {
				rgep->param_link_speed = RGE_SPEED_1000M;
				rgep->param_link_duplex = LINK_DUPLEX_FULL;
			} else {
				rgep->param_link_speed =
				    (media_status & PHY_STATUS_100M) ?
				    RGE_SPEED_100M : RGE_SPEED_10M;
				rgep->param_link_duplex =
				    (media_status & PHY_STATUS_DUPLEX_FULL) ?
				    LINK_DUPLEX_FULL : LINK_DUPLEX_HALF;
			}
		}
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Factotum routine to check for Tx stall, using the 'watchdog' counter
 */
static boolean_t rge_factotum_stall_check(rge_t *rgep);
#pragma	no_inline(rge_factotum_stall_check)

static boolean_t
rge_factotum_stall_check(rge_t *rgep)
{
	uint32_t dogval;

	ASSERT(mutex_owned(rgep->genlock));

	/*
	 * Specific check for RX stall ...
	 */
	rgep->rx_fifo_ovf <<= 1;
	if (rgep->rx_fifo_ovf > rge_rx_watchdog_count) {
		RGE_REPORT((rgep, "rx_hang detected"));
		return (B_TRUE);
	}

	/*
	 * Specific check for Tx stall ...
	 *
	 * The 'watchdog' counter is incremented whenever a packet
	 * is queued, reset to 1 when some (but not all) buffers
	 * are reclaimed, reset to 0 (disabled) when all buffers
	 * are reclaimed, and shifted left here.  If it exceeds the
	 * threshold value, the chip is assumed to have stalled and
	 * is put into the ERROR state.  The factotum will then reset
	 * it on the next pass.
	 *
	 * All of which should ensure that we don't get into a state
	 * where packets are left pending indefinitely!
	 */
	if (rgep->resched_needed)
		(void) ddi_intr_trigger_softint(rgep->resched_hdl, NULL);
	dogval = rge_atomic_shl32(&rgep->watchdog, 1);
	if (dogval < rge_watchdog_count)
		return (B_FALSE);

	RGE_REPORT((rgep, "Tx stall detected, watchdog code 0x%x", dogval));
	return (B_TRUE);

}

/*
 * The factotum is woken up when there's something to do that we'd rather
 * not do from inside a hardware interrupt handler or high-level cyclic.
 * Its two main tasks are:
 *	reset & restart the chip after an error
 *	check the link status whenever necessary
 */
uint_t rge_chip_factotum(caddr_t arg1, caddr_t arg2);
#pragma	no_inline(rge_chip_factotum)

uint_t
rge_chip_factotum(caddr_t arg1, caddr_t arg2)
{
	rge_t *rgep;
	uint_t result;
	boolean_t error;
	boolean_t linkchg;

	rgep = (rge_t *)arg1;
	_NOTE(ARGUNUSED(arg2))

	if (rgep->factotum_flag == 0)
		return (DDI_INTR_UNCLAIMED);

	rgep->factotum_flag = 0;
	result = DDI_INTR_CLAIMED;
	error = B_FALSE;
	linkchg = B_FALSE;

	mutex_enter(rgep->genlock);
	switch (rgep->rge_chip_state) {
	default:
		break;

	case RGE_CHIP_RUNNING:
		linkchg = rge_factotum_link_check(rgep);
		error = rge_factotum_stall_check(rgep);
		break;

	case RGE_CHIP_ERROR:
		error = B_TRUE;
		break;

	case RGE_CHIP_FAULT:
		/*
		 * Fault detected, time to reset ...
		 */
		if (rge_autorecover) {
			RGE_REPORT((rgep, "automatic recovery activated"));
			rge_restart(rgep);
		}
		break;
	}

	/*
	 * If an error is detected, stop the chip now, marking it as
	 * faulty, so that it will be reset next time through ...
	 */
	if (error)
		rge_chip_stop(rgep, B_TRUE);
	mutex_exit(rgep->genlock);

	/*
	 * If the link state changed, tell the world about it.
	 * Note: can't do this while still holding the mutex.
	 */
	if (linkchg)
		mac_link_update(rgep->mh, rgep->param_link_up);

	return (result);
}

/*
 * High-level cyclic handler
 *
 * This routine schedules a (low-level) softint callback to the
 * factotum, and prods the chip to update the status block (which
 * will cause a hardware interrupt when complete).
 */
void rge_chip_cyclic(void *arg);
#pragma	no_inline(rge_chip_cyclic)

void
rge_chip_cyclic(void *arg)
{
	rge_t *rgep;

	rgep = arg;

	switch (rgep->rge_chip_state) {
	default:
		return;

	case RGE_CHIP_RUNNING:
		rge_phy_check(rgep);
		if (rgep->tx_free < RGE_SEND_SLOTS)
			rge_send_recycle(rgep);
		break;

	case RGE_CHIP_FAULT:
	case RGE_CHIP_ERROR:
		break;
	}

	rge_wake_factotum(rgep);
}


/*
 * ========== Ioctl subfunctions ==========
 */

#undef	RGE_DBG
#define	RGE_DBG		RGE_DBG_PPIO	/* debug flag for this code	*/

#if	RGE_DEBUGGING || RGE_DO_PPIO

static void rge_chip_peek_cfg(rge_t *rgep, rge_peekpoke_t *ppd);
#pragma	no_inline(rge_chip_peek_cfg)

static void
rge_chip_peek_cfg(rge_t *rgep, rge_peekpoke_t *ppd)
{
	uint64_t regval;
	uint64_t regno;

	RGE_TRACE(("rge_chip_peek_cfg($%p, $%p)",
	    (void *)rgep, (void *)ppd));

	regno = ppd->pp_acc_offset;

	switch (ppd->pp_acc_size) {
	case 1:
		regval = pci_config_get8(rgep->cfg_handle, regno);
		break;

	case 2:
		regval = pci_config_get16(rgep->cfg_handle, regno);
		break;

	case 4:
		regval = pci_config_get32(rgep->cfg_handle, regno);
		break;

	case 8:
		regval = pci_config_get64(rgep->cfg_handle, regno);
		break;
	}

	ppd->pp_acc_data = regval;
}

static void rge_chip_poke_cfg(rge_t *rgep, rge_peekpoke_t *ppd);
#pragma	no_inline(rge_chip_poke_cfg)

static void
rge_chip_poke_cfg(rge_t *rgep, rge_peekpoke_t *ppd)
{
	uint64_t regval;
	uint64_t regno;

	RGE_TRACE(("rge_chip_poke_cfg($%p, $%p)",
	    (void *)rgep, (void *)ppd));

	regno = ppd->pp_acc_offset;
	regval = ppd->pp_acc_data;

	switch (ppd->pp_acc_size) {
	case 1:
		pci_config_put8(rgep->cfg_handle, regno, regval);
		break;

	case 2:
		pci_config_put16(rgep->cfg_handle, regno, regval);
		break;

	case 4:
		pci_config_put32(rgep->cfg_handle, regno, regval);
		break;

	case 8:
		pci_config_put64(rgep->cfg_handle, regno, regval);
		break;
	}
}

static void rge_chip_peek_reg(rge_t *rgep, rge_peekpoke_t *ppd);
#pragma	no_inline(rge_chip_peek_reg)

static void
rge_chip_peek_reg(rge_t *rgep, rge_peekpoke_t *ppd)
{
	uint64_t regval;
	void *regaddr;

	RGE_TRACE(("rge_chip_peek_reg($%p, $%p)",
	    (void *)rgep, (void *)ppd));

	regaddr = PIO_ADDR(rgep, ppd->pp_acc_offset);

	switch (ppd->pp_acc_size) {
	case 1:
		regval = ddi_get8(rgep->io_handle, regaddr);
		break;

	case 2:
		regval = ddi_get16(rgep->io_handle, regaddr);
		break;

	case 4:
		regval = ddi_get32(rgep->io_handle, regaddr);
		break;

	case 8:
		regval = ddi_get64(rgep->io_handle, regaddr);
		break;
	}

	ppd->pp_acc_data = regval;
}

static void rge_chip_poke_reg(rge_t *rgep, rge_peekpoke_t *ppd);
#pragma	no_inline(rge_chip_peek_reg)

static void
rge_chip_poke_reg(rge_t *rgep, rge_peekpoke_t *ppd)
{
	uint64_t regval;
	void *regaddr;

	RGE_TRACE(("rge_chip_poke_reg($%p, $%p)",
	    (void *)rgep, (void *)ppd));

	regaddr = PIO_ADDR(rgep, ppd->pp_acc_offset);
	regval = ppd->pp_acc_data;

	switch (ppd->pp_acc_size) {
	case 1:
		ddi_put8(rgep->io_handle, regaddr, regval);
		break;

	case 2:
		ddi_put16(rgep->io_handle, regaddr, regval);
		break;

	case 4:
		ddi_put32(rgep->io_handle, regaddr, regval);
		break;

	case 8:
		ddi_put64(rgep->io_handle, regaddr, regval);
		break;
	}
}

static void rge_chip_peek_mii(rge_t *rgep, rge_peekpoke_t *ppd);
#pragma	no_inline(rge_chip_peek_mii)

static void
rge_chip_peek_mii(rge_t *rgep, rge_peekpoke_t *ppd)
{
	RGE_TRACE(("rge_chip_peek_mii($%p, $%p)",
	    (void *)rgep, (void *)ppd));

	ppd->pp_acc_data = rge_mii_get16(rgep, ppd->pp_acc_offset/2);
}

static void rge_chip_poke_mii(rge_t *rgep, rge_peekpoke_t *ppd);
#pragma	no_inline(rge_chip_poke_mii)

static void
rge_chip_poke_mii(rge_t *rgep, rge_peekpoke_t *ppd)
{
	RGE_TRACE(("rge_chip_poke_mii($%p, $%p)",
	    (void *)rgep, (void *)ppd));

	rge_mii_put16(rgep, ppd->pp_acc_offset/2, ppd->pp_acc_data);
}

static void rge_chip_peek_mem(rge_t *rgep, rge_peekpoke_t *ppd);
#pragma	no_inline(rge_chip_peek_mem)

static void
rge_chip_peek_mem(rge_t *rgep, rge_peekpoke_t *ppd)
{
	uint64_t regval;
	void *vaddr;

	RGE_TRACE(("rge_chip_peek_rge($%p, $%p)",
	    (void *)rgep, (void *)ppd));

	vaddr = (void *)(uintptr_t)ppd->pp_acc_offset;

	switch (ppd->pp_acc_size) {
	case 1:
		regval = *(uint8_t *)vaddr;
		break;

	case 2:
		regval = *(uint16_t *)vaddr;
		break;

	case 4:
		regval = *(uint32_t *)vaddr;
		break;

	case 8:
		regval = *(uint64_t *)vaddr;
		break;
	}

	RGE_DEBUG(("rge_chip_peek_mem($%p, $%p) peeked 0x%llx from $%p",
	    (void *)rgep, (void *)ppd, regval, vaddr));

	ppd->pp_acc_data = regval;
}

static void rge_chip_poke_mem(rge_t *rgep, rge_peekpoke_t *ppd);
#pragma	no_inline(rge_chip_poke_mem)

static void
rge_chip_poke_mem(rge_t *rgep, rge_peekpoke_t *ppd)
{
	uint64_t regval;
	void *vaddr;

	RGE_TRACE(("rge_chip_poke_mem($%p, $%p)",
	    (void *)rgep, (void *)ppd));

	vaddr = (void *)(uintptr_t)ppd->pp_acc_offset;
	regval = ppd->pp_acc_data;

	RGE_DEBUG(("rge_chip_poke_mem($%p, $%p) poking 0x%llx at $%p",
	    (void *)rgep, (void *)ppd, regval, vaddr));

	switch (ppd->pp_acc_size) {
	case 1:
		*(uint8_t *)vaddr = (uint8_t)regval;
		break;

	case 2:
		*(uint16_t *)vaddr = (uint16_t)regval;
		break;

	case 4:
		*(uint32_t *)vaddr = (uint32_t)regval;
		break;

	case 8:
		*(uint64_t *)vaddr = (uint64_t)regval;
		break;
	}
}

static enum ioc_reply rge_pp_ioctl(rge_t *rgep, int cmd, mblk_t *mp,
					struct iocblk *iocp);
#pragma	no_inline(rge_pp_ioctl)

static enum ioc_reply
rge_pp_ioctl(rge_t *rgep, int cmd, mblk_t *mp, struct iocblk *iocp)
{
	void (*ppfn)(rge_t *rgep, rge_peekpoke_t *ppd);
	rge_peekpoke_t *ppd;
	dma_area_t *areap;
	uint64_t sizemask;
	uint64_t mem_va;
	uint64_t maxoff;
	boolean_t peek;

	switch (cmd) {
	default:
		/* NOTREACHED */
		rge_error(rgep, "rge_pp_ioctl: invalid cmd 0x%x", cmd);
		return (IOC_INVAL);

	case RGE_PEEK:
		peek = B_TRUE;
		break;

	case RGE_POKE:
		peek = B_FALSE;
		break;
	}

	/*
	 * Validate format of ioctl
	 */
	if (iocp->ioc_count != sizeof (rge_peekpoke_t))
		return (IOC_INVAL);
	if (mp->b_cont == NULL)
		return (IOC_INVAL);
	ppd = (rge_peekpoke_t *)mp->b_cont->b_rptr;

	/*
	 * Validate request parameters
	 */
	switch (ppd->pp_acc_space) {
	default:
		return (IOC_INVAL);

	case RGE_PP_SPACE_CFG:
		/*
		 * Config space
		 */
		sizemask = 8|4|2|1;
		mem_va = 0;
		maxoff = PCI_CONF_HDR_SIZE;
		ppfn = peek ? rge_chip_peek_cfg : rge_chip_poke_cfg;
		break;

	case RGE_PP_SPACE_REG:
		/*
		 * Memory-mapped I/O space
		 */
		sizemask = 8|4|2|1;
		mem_va = 0;
		maxoff = RGE_REGISTER_MAX;
		ppfn = peek ? rge_chip_peek_reg : rge_chip_poke_reg;
		break;

	case RGE_PP_SPACE_MII:
		/*
		 * PHY's MII registers
		 * NB: all PHY registers are two bytes, but the
		 * addresses increment in ones (word addressing).
		 * So we scale the address here, then undo the
		 * transformation inside the peek/poke functions.
		 */
		ppd->pp_acc_offset *= 2;
		sizemask = 2;
		mem_va = 0;
		maxoff = (MII_MAXREG+1)*2;
		ppfn = peek ? rge_chip_peek_mii : rge_chip_poke_mii;
		break;

	case RGE_PP_SPACE_RGE:
		/*
		 * RGE data structure!
		 */
		sizemask = 8|4|2|1;
		mem_va = (uintptr_t)rgep;
		maxoff = sizeof (*rgep);
		ppfn = peek ? rge_chip_peek_mem : rge_chip_poke_mem;
		break;

	case RGE_PP_SPACE_STATISTICS:
	case RGE_PP_SPACE_TXDESC:
	case RGE_PP_SPACE_TXBUFF:
	case RGE_PP_SPACE_RXDESC:
	case RGE_PP_SPACE_RXBUFF:
		/*
		 * Various DMA_AREAs
		 */
		switch (ppd->pp_acc_space) {
		case RGE_PP_SPACE_TXDESC:
			areap = &rgep->dma_area_txdesc;
			break;
		case RGE_PP_SPACE_RXDESC:
			areap = &rgep->dma_area_rxdesc;
			break;
		case RGE_PP_SPACE_STATISTICS:
			areap = &rgep->dma_area_stats;
			break;
		}

		sizemask = 8|4|2|1;
		mem_va = (uintptr_t)areap->mem_va;
		maxoff = areap->alength;
		ppfn = peek ? rge_chip_peek_mem : rge_chip_poke_mem;
		break;
	}

	switch (ppd->pp_acc_size) {
	default:
		return (IOC_INVAL);

	case 8:
	case 4:
	case 2:
	case 1:
		if ((ppd->pp_acc_size & sizemask) == 0)
			return (IOC_INVAL);
		break;
	}

	if ((ppd->pp_acc_offset % ppd->pp_acc_size) != 0)
		return (IOC_INVAL);

	if (ppd->pp_acc_offset >= maxoff)
		return (IOC_INVAL);

	if (ppd->pp_acc_offset+ppd->pp_acc_size > maxoff)
		return (IOC_INVAL);

	/*
	 * All OK - go do it!
	 */
	ppd->pp_acc_offset += mem_va;
	(*ppfn)(rgep, ppd);
	return (peek ? IOC_REPLY : IOC_ACK);
}

static enum ioc_reply rge_diag_ioctl(rge_t *rgep, int cmd, mblk_t *mp,
					struct iocblk *iocp);
#pragma	no_inline(rge_diag_ioctl)

static enum ioc_reply
rge_diag_ioctl(rge_t *rgep, int cmd, mblk_t *mp, struct iocblk *iocp)
{
	ASSERT(mutex_owned(rgep->genlock));

	switch (cmd) {
	default:
		/* NOTREACHED */
		rge_error(rgep, "rge_diag_ioctl: invalid cmd 0x%x", cmd);
		return (IOC_INVAL);

	case RGE_DIAG:
		/*
		 * Currently a no-op
		 */
		return (IOC_ACK);

	case RGE_PEEK:
	case RGE_POKE:
		return (rge_pp_ioctl(rgep, cmd, mp, iocp));

	case RGE_PHY_RESET:
		return (IOC_RESTART_ACK);

	case RGE_SOFT_RESET:
	case RGE_HARD_RESET:
		/*
		 * Reset and reinitialise the 570x hardware
		 */
		rge_restart(rgep);
		return (IOC_ACK);
	}

	/* NOTREACHED */
}

#endif	/* RGE_DEBUGGING || RGE_DO_PPIO */

static enum ioc_reply rge_mii_ioctl(rge_t *rgep, int cmd, mblk_t *mp,
				    struct iocblk *iocp);
#pragma	no_inline(rge_mii_ioctl)

static enum ioc_reply
rge_mii_ioctl(rge_t *rgep, int cmd, mblk_t *mp, struct iocblk *iocp)
{
	struct rge_mii_rw *miirwp;

	/*
	 * Validate format of ioctl
	 */
	if (iocp->ioc_count != sizeof (struct rge_mii_rw))
		return (IOC_INVAL);
	if (mp->b_cont == NULL)
		return (IOC_INVAL);
	miirwp = (struct rge_mii_rw *)mp->b_cont->b_rptr;

	/*
	 * Validate request parameters ...
	 */
	if (miirwp->mii_reg > MII_MAXREG)
		return (IOC_INVAL);

	switch (cmd) {
	default:
		/* NOTREACHED */
		rge_error(rgep, "rge_mii_ioctl: invalid cmd 0x%x", cmd);
		return (IOC_INVAL);

	case RGE_MII_READ:
		miirwp->mii_data = rge_mii_get16(rgep, miirwp->mii_reg);
		return (IOC_REPLY);

	case RGE_MII_WRITE:
		rge_mii_put16(rgep, miirwp->mii_reg, miirwp->mii_data);
		return (IOC_ACK);
	}

	/* NOTREACHED */
}

enum ioc_reply rge_chip_ioctl(rge_t *rgep, queue_t *wq, mblk_t *mp,
				struct iocblk *iocp);
#pragma	no_inline(rge_chip_ioctl)

enum ioc_reply
rge_chip_ioctl(rge_t *rgep, queue_t *wq, mblk_t *mp, struct iocblk *iocp)
{
	int cmd;

	RGE_TRACE(("rge_chip_ioctl($%p, $%p, $%p, $%p)",
	    (void *)rgep, (void *)wq, (void *)mp, (void *)iocp));

	ASSERT(mutex_owned(rgep->genlock));

	cmd = iocp->ioc_cmd;
	switch (cmd) {
	default:
		/* NOTREACHED */
		rge_error(rgep, "rge_chip_ioctl: invalid cmd 0x%x", cmd);
		return (IOC_INVAL);

	case RGE_DIAG:
	case RGE_PEEK:
	case RGE_POKE:
	case RGE_PHY_RESET:
	case RGE_SOFT_RESET:
	case RGE_HARD_RESET:
#if	RGE_DEBUGGING || RGE_DO_PPIO
		return (rge_diag_ioctl(rgep, cmd, mp, iocp));
#else
		return (IOC_INVAL);
#endif	/* RGE_DEBUGGING || RGE_DO_PPIO */

	case RGE_MII_READ:
	case RGE_MII_WRITE:
		return (rge_mii_ioctl(rgep, cmd, mp, iocp));

	}

	/* NOTREACHED */
}
