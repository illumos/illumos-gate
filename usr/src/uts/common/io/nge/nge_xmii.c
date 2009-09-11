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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "nge.h"

#undef	NGE_DBG
#define	NGE_DBG		NGE_DBG_MII	/* debug flag for this code	*/

/*
 * The arrays below can be indexed by the MODE bits from the mac2phy
 * register to determine the current speed/duplex settings.
 */
static const int16_t nge_copper_link_speed[] = {
	0,				/* MII_AUX_STATUS_MODE_NONE	*/
	10,				/* MII_AUX_STAT0,US_MODE_10	*/
	100,				/* MII_AUX_STAT0,US_MODE_100	*/
	1000,				/* MII_AUX_STAT0,US_MODE_1000	*/
};

static const int8_t nge_copper_link_duplex[] = {
	LINK_DUPLEX_UNKNOWN,		/* MII_DUPLEX_NONE	*/
	LINK_DUPLEX_HALF,		/* MII_DUPLEX_HALF	*/
	LINK_DUPLEX_FULL,		/* MII_DUPLEX_FULL	*/
};


static uint16_t nge_mii_access(nge_t *ngep, nge_regno_t regno,
    uint16_t data, uint32_t cmd);
#pragma	inline(nge_mii_access)

static uint16_t
nge_mii_access(nge_t *ngep, nge_regno_t regno, uint16_t data, uint32_t cmd)
{
	uint16_t tries;
	uint16_t mdio_data;
	nge_mdio_adr mdio_adr;
	nge_mintr_src intr_src;

	NGE_TRACE(("nge_mii_access($%p, 0x%lx, 0x%x, 0x%x)",
	    (void *)ngep, regno, data, cmd));

	/*
	 * Clear the privous interrupt event
	 */
	intr_src.src_val = nge_reg_get8(ngep, NGE_MINTR_SRC);
	nge_reg_put8(ngep, NGE_MINTR_SRC, intr_src.src_val);

	/*
	 * Check whether the current operation has been finished
	 */
	mdio_adr.adr_val = nge_reg_get16(ngep, NGE_MDIO_ADR);
	for (tries = 0; tries < 30; tries ++) {
		if (mdio_adr.adr_bits.mdio_clc == NGE_CLEAR)
			break;
		drv_usecwait(10);
		mdio_adr.adr_val = nge_reg_get16(ngep, NGE_MDIO_ADR);
	}

	/*
	 * The current operation can not be finished successfully
	 *  The driver should halt the current operation
	 */
	if (tries == 30) {
		mdio_adr.adr_bits.mdio_clc = NGE_SET;
		nge_reg_put16(ngep, NGE_MDIO_ADR, mdio_adr.adr_val);
		drv_usecwait(100);
	}

	/*
	 * Assemble the operation cmd
	 */
	mdio_adr.adr_bits.phy_reg = (uint16_t)regno;
	mdio_adr.adr_bits.phy_adr = ngep->phy_xmii_addr;
	mdio_adr.adr_bits.mdio_rw = (cmd == NGE_MDIO_WRITE) ? 1 : 0;


	if (cmd == NGE_MDIO_WRITE)
		nge_reg_put16(ngep, NGE_MDIO_DATA, data);

	nge_reg_put16(ngep, NGE_MDIO_ADR, mdio_adr.adr_val);

	/*
	 * To check whether the read/write operation is finished
	 */
	for (tries = 0; tries < 300; tries ++) {
		drv_usecwait(10);
		mdio_adr.adr_val = nge_reg_get16(ngep, NGE_MDIO_ADR);
		if (mdio_adr.adr_bits.mdio_clc == NGE_CLEAR)
			break;
	}
	if (tries == 300)
		return ((uint16_t)~0);

	/*
	 * Read the data from MDIO data register
	 */
	if (cmd == NGE_MDIO_READ)
		mdio_data = nge_reg_get16(ngep, NGE_MDIO_DATA);

	/*
	 * To check whether the read/write operation is valid
	 */
	intr_src.src_val = nge_reg_get8(ngep, NGE_MINTR_SRC);
	nge_reg_put8(ngep, NGE_MINTR_SRC, intr_src.src_val);
	if (intr_src.src_bits.mrei == NGE_SET)
		return ((uint16_t)~0);

	return (mdio_data);
}

uint16_t nge_mii_get16(nge_t *ngep, nge_regno_t regno);
#pragma	inline(nge_mii_get16)

uint16_t
nge_mii_get16(nge_t *ngep, nge_regno_t regno)
{

	return (nge_mii_access(ngep, regno, 0, NGE_MDIO_READ));
}

void nge_mii_put16(nge_t *ngep, nge_regno_t regno, uint16_t data);
#pragma	inline(nge_mii_put16)

void
nge_mii_put16(nge_t *ngep, nge_regno_t regno, uint16_t data)
{

	(void) nge_mii_access(ngep, regno, data, NGE_MDIO_WRITE);
}

/*
 * Basic low-level function to probe for a PHY
 *
 * Returns TRUE if the PHY responds with valid data, FALSE otherwise
 */
static boolean_t
nge_phy_probe(nge_t *ngep)
{
	int i;
	uint16_t phy_status;
	uint16_t phyidh;
	uint16_t phyidl;

	NGE_TRACE(("nge_phy_probe($%p)", (void *)ngep));

	/*
	 * Scan the phys to find the right address
	 * of the phy
	 *
	 * Probe maximum for 32 phy addresses
	 */
	for (i = 0; i < NGE_PHY_NUMBER; i++) {
		ngep->phy_xmii_addr = i;
		/*
		 * Read the MII_STATUS register twice, in
		 * order to clear any sticky bits (but they should
		 * have been cleared by the RESET, I think).
		 */
		phy_status = nge_mii_get16(ngep, MII_STATUS);
		phy_status = nge_mii_get16(ngep, MII_STATUS);
		if (phy_status != 0xffff) {
			phyidh = nge_mii_get16(ngep, MII_PHYIDH);
			phyidl = nge_mii_get16(ngep, MII_PHYIDL);
			ngep->phy_id =
			    (((uint32_t)phyidh << 16) |(phyidl & MII_IDL_MASK));
			NGE_DEBUG(("nge_phy_probe: status 0x%x, phy id 0x%x",
			    phy_status, ngep->phy_id));

			return (B_TRUE);
		}
	}

	return (B_FALSE);
}


/*
 * Basic low-level function to powerup the phy and remove the isolation
 */

static boolean_t
nge_phy_recover(nge_t *ngep)
{
	uint16_t control;
	uint16_t count;

	NGE_TRACE(("nge_phy_recover($%p)", (void *)ngep));
	control = nge_mii_get16(ngep, MII_CONTROL);
	control &= ~(MII_CONTROL_PWRDN | MII_CONTROL_ISOLATE);
	nge_mii_put16(ngep, MII_CONTROL, control);
	for (count = 0; ++count < 10; ) {
		drv_usecwait(5);
		control = nge_mii_get16(ngep, MII_CONTROL);
		if (BIC(control, MII_CONTROL_PWRDN))
			return (B_TRUE);
	}

	return (B_FALSE);
}
/*
 * Basic low-level function to reset the PHY.
 * Doesn't incorporate any special-case workarounds.
 *
 * Returns TRUE on success, FALSE if the RESET bit doesn't clear
 */
boolean_t
nge_phy_reset(nge_t *ngep)
{
	uint16_t control;
	uint_t count;

	NGE_TRACE(("nge_phy_reset($%p)", (void *)ngep));

	ASSERT(mutex_owned(ngep->genlock));

	/*
	 * Set the PHY RESET bit, then wait up to 5 ms for it to self-clear
	 */
	control = nge_mii_get16(ngep, MII_CONTROL);
	control |= MII_CONTROL_RESET;
	nge_mii_put16(ngep, MII_CONTROL, control);
	/* We should wait for 500ms. It's defined in the manual */
	delay(drv_usectohz(500000));
	for (count = 0; ++count < 10; ) {
		drv_usecwait(5);
		control = nge_mii_get16(ngep, MII_CONTROL);
		if (BIC(control, MII_CONTROL_RESET))
			return (B_TRUE);
	}
	NGE_DEBUG(("nge_phy_reset: FAILED, control now 0x%x", control));

	return (B_FALSE);
}

static boolean_t
nge_phy_restart(nge_t *ngep)
{
	uint16_t mii_reg;

	if (!nge_phy_recover(ngep))
		return (B_FALSE);
	if (!nge_phy_reset(ngep))
		return (B_FALSE);

	if (MII_PHY_MFG(ngep->phy_id) == MII_ID_CICADA) {
		if (ngep->phy_mode == RGMII_IN) {
			mii_reg = nge_mii_get16(ngep,
			    MII_CICADA_EXT_CONTROL);
			mii_reg &= ~(MII_CICADA_MODE_SELECT_BITS
			    | MII_CICADA_POWER_SUPPLY_BITS);
			mii_reg |= (MII_CICADA_MODE_SELECT_RGMII
			    | MII_CICADA_POWER_SUPPLY_2_5V);
			nge_mii_put16(ngep, MII_CICADA_EXT_CONTROL, mii_reg);

			mii_reg = nge_mii_get16(ngep,
			    MII_CICADA_AUXCTRL_STATUS);
			mii_reg |= MII_CICADA_PIN_PRORITY_SETTING;
			nge_mii_put16(ngep, MII_CICADA_AUXCTRL_STATUS,
			    mii_reg);
		} else {
			mii_reg = nge_mii_get16(ngep,
			    MII_CICADA_10BASET_CONTROL);
			mii_reg |= MII_CICADA_DISABLE_ECHO_MODE;
			nge_mii_put16(ngep,
			    MII_CICADA_10BASET_CONTROL, mii_reg);

			mii_reg = nge_mii_get16(ngep,
			    MII_CICADA_BYPASS_CONTROL);
			mii_reg &= (~CICADA_125MHZ_CLOCK_ENABLE);
			nge_mii_put16(ngep, MII_CICADA_BYPASS_CONTROL, mii_reg);
		}
	}

	return (B_TRUE);
}

/*
 * Synchronise the (copper) PHY's speed/duplex/autonegotiation capabilities
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
static void
nge_update_copper(nge_t *ngep)
{
	uint16_t control;
	uint16_t gigctrl;
	uint16_t anar;
	boolean_t adv_autoneg;
	boolean_t adv_pause;
	boolean_t adv_asym_pause;
	boolean_t adv_1000fdx;
	boolean_t adv_100fdx;
	boolean_t adv_100hdx;
	boolean_t adv_10fdx;
	boolean_t adv_10hdx;

	NGE_TRACE(("nge_update_copper($%p)", (void *)ngep));

	ASSERT(mutex_owned(ngep->genlock));

	NGE_DEBUG(("nge_update_copper: autoneg %d "
	    "pause %d asym_pause %d "
	    "1000fdx %d "
	    "100fdx %d 100hdx %d "
	    "10fdx %d 10hdx %d ",
	    ngep->param_adv_autoneg,
	    ngep->param_adv_pause, ngep->param_adv_asym_pause,
	    ngep->param_adv_1000fdx,
	    ngep->param_adv_100fdx, ngep->param_adv_100hdx,
	    ngep->param_adv_10fdx, ngep->param_adv_10hdx));

	control = anar = gigctrl = 0;

	/*
	 * PHY settings are normally based on the param_* variables,
	 * but if any loopback mode is in effect, that takes precedence.
	 *
	 * NGE supports MAC-internal loopback, PHY-internal loopback,
	 * and External loopback at a variety of speeds (with a special
	 * cable).  In all cases, autoneg is turned OFF, full-duplex
	 * is turned ON, and the speed/mastership is forced.
	 */
	switch (ngep->param_loop_mode) {
	case NGE_LOOP_NONE:
	default:
		adv_pause = ngep->param_adv_pause;
		adv_autoneg = ngep->param_adv_autoneg;
		adv_asym_pause = ngep->param_adv_asym_pause;
		if (ngep->phy_mode == MII_IN) {
			adv_1000fdx = ngep->param_adv_1000fdx = B_FALSE;
		}
		adv_1000fdx = ngep->param_adv_1000fdx;
		adv_100fdx = ngep->param_adv_100fdx;
		adv_100hdx = ngep->param_adv_100hdx;
		adv_10fdx = ngep->param_adv_10fdx;
		adv_10hdx = ngep->param_adv_10hdx;

		break;

	case NGE_LOOP_EXTERNAL_100:
	case NGE_LOOP_EXTERNAL_10:
	case NGE_LOOP_INTERNAL_PHY:
		adv_autoneg = adv_pause = adv_asym_pause = B_FALSE;
		adv_1000fdx = adv_100fdx = adv_10fdx = B_FALSE;
		adv_100hdx = adv_10hdx = B_FALSE;
		ngep->param_link_duplex = LINK_DUPLEX_FULL;

		switch (ngep->param_loop_mode) {
		case NGE_LOOP_EXTERNAL_100:
			ngep->param_link_speed = 100;
			adv_100fdx = B_TRUE;
			break;

		case NGE_LOOP_EXTERNAL_10:
			ngep->param_link_speed = 10;
			adv_10fdx = B_TRUE;
			break;

		case NGE_LOOP_INTERNAL_PHY:
			ngep->param_link_speed = 1000;
			adv_1000fdx = B_TRUE;
			break;

		}
	}
	NGE_DEBUG(("nge_update_copper: autoneg %d "
	    "pause %d asym_pause %d "
	    "1000fdx %d "
	    "100fdx %d 100hdx %d "
	    "10fdx %d 10hdx %d ",
	    adv_autoneg,
	    adv_pause, adv_asym_pause,
	    adv_1000fdx,
	    adv_100fdx, adv_100hdx,
	    adv_10fdx, adv_10hdx));

	/*
	 * We should have at least one technology capability set;
	 * if not, we select a default of 10Mb/s half-duplex
	 */
	if (!adv_1000fdx && !adv_100fdx && !adv_10fdx &&
	    !adv_100hdx && !adv_10hdx)
		adv_10hdx = B_TRUE;

	/*
	 * Now transform the adv_* variables into the proper settings
	 * of the PHY registers ...
	 *
	 * If autonegotiation is (now) enabled, we want to trigger
	 * a new autonegotiation cycle once the PHY has been
	 * programmed with the capabilities to be advertised.
	 */
	if (adv_autoneg)
		control |= MII_CONTROL_ANE|MII_CONTROL_RSAN;

	if (adv_1000fdx)
		control |= MII_CONTROL_1000MB|MII_CONTROL_FDUPLEX;
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

	if (adv_1000fdx)
		gigctrl |= MII_1000BT_CTL_ADV_FDX;
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
	 * Restart the PHY and write the new values.
	 */
	nge_mii_put16(ngep, MII_AN_ADVERT, anar);
	nge_mii_put16(ngep, MII_CONTROL, control);
	nge_mii_put16(ngep, MII_1000BASE_T_CONTROL, gigctrl);
	if (!nge_phy_restart(ngep))
		nge_error(ngep, "nge_update_copper: failed to restart phy");
	/*
	 * Loopback bit in control register is not reset sticky
	 * write it after PHY restart.
	 */
	if (ngep->param_loop_mode == NGE_LOOP_INTERNAL_PHY) {
		control = nge_mii_get16(ngep, MII_CONTROL);
		control |= MII_CONTROL_LOOPBACK;
		nge_mii_put16(ngep, MII_CONTROL, control);
	}
}

static boolean_t
nge_check_copper(nge_t *ngep)
{
	uint16_t mii_status;
	uint16_t mii_exstatus;
	uint16_t mii_excontrol;
	uint16_t anar;
	uint16_t lpan;
	uint_t speed;
	uint_t duplex;
	boolean_t linkup;
	nge_mii_cs mii_cs;
	nge_mintr_src mintr_src;

	speed = UNKOWN_SPEED;
	duplex = UNKOWN_DUPLEX;
	/*
	 * Read the status from the PHY (which is self-clearing
	 * on read!); also read & clear the main (Ethernet) MAC status
	 * (the relevant bits of this are write-one-to-clear).
	 */
	mii_status = nge_mii_get16(ngep, MII_STATUS);
	mii_cs.cs_val = nge_reg_get32(ngep, NGE_MII_CS);
	mintr_src.src_val = nge_reg_get32(ngep, NGE_MINTR_SRC);
	nge_reg_put32(ngep, NGE_MINTR_SRC, mintr_src.src_val);

	NGE_DEBUG(("nge_check_copper: link %d/%s, MII status 0x%x "
	    "(was 0x%x)", ngep->link_state,
	    UPORDOWN(ngep->param_link_up), mii_status,
	    ngep->phy_gen_status));

	do {
		/*
		 * If the PHY status changed, record the time
		 */
		switch (ngep->phy_mode) {
		default:
		case RGMII_IN:

			/*
			 * Judge the giga speed by reading control
			 * and status register
			 */
			mii_excontrol = nge_mii_get16(ngep,
			    MII_1000BASE_T_CONTROL);
			mii_exstatus = nge_mii_get16(ngep,
			    MII_1000BASE_T_STATUS);
			if ((mii_excontrol & MII_1000BT_CTL_ADV_FDX) &&
			    (mii_exstatus & MII_1000BT_STAT_LP_FDX_CAP)) {
				speed  = NGE_1000M;
				duplex = NGE_FD;
			} else {
				anar = nge_mii_get16(ngep, MII_AN_ADVERT);
				lpan = nge_mii_get16(ngep, MII_AN_LPABLE);
				if (lpan != 0)
					anar = (anar & lpan);
				if (anar & MII_100BASET_FD) {
					speed = NGE_100M;
					duplex = NGE_FD;
				} else if (anar & MII_100BASET_HD) {
					speed = NGE_100M;
					duplex = NGE_HD;
				} else if (anar & MII_10BASET_FD) {
					speed = NGE_10M;
					duplex = NGE_FD;
				} else if (anar & MII_10BASET_HD) {
					speed = NGE_10M;
					duplex = NGE_HD;
				}
			}
			break;
		case MII_IN:
			anar = nge_mii_get16(ngep, MII_AN_ADVERT);
			lpan = nge_mii_get16(ngep, MII_AN_LPABLE);
			if (lpan != 0)
				anar = (anar & lpan);

			if (anar & MII_100BASET_FD) {
				speed = NGE_100M;
				duplex = NGE_FD;
			} else if (anar & MII_100BASET_HD) {
				speed = NGE_100M;
				duplex = NGE_HD;
			} else if (anar & MII_10BASET_FD) {
				speed = NGE_10M;
				duplex = NGE_FD;
			} else if (anar & MII_10BASET_HD) {
				speed = NGE_10M;
				duplex = NGE_HD;
			}
			break;
		}


		/*
		 * We will only consider the link UP if all the readings
		 * are consistent and give meaningful results ...
		 */
		linkup = nge_copper_link_speed[speed] > 0;
		linkup &= nge_copper_link_duplex[duplex] != LINK_DUPLEX_UNKNOWN;
		linkup &= BIS(mii_status, MII_STATUS_LINKUP);
		linkup &= BIS(mii_cs.cs_val, MII_STATUS_LINKUP);

		/*
		 * Record current register values, then reread status
		 * register & loop until it stabilises ...
		 */
		ngep->phy_gen_status = mii_status;
		mii_status = nge_mii_get16(ngep, MII_STATUS);
	} while (mii_status != ngep->phy_gen_status);

	/* Get the Link Partner Ability */
	mii_exstatus = nge_mii_get16(ngep, MII_1000BASE_T_STATUS);
	lpan = nge_mii_get16(ngep, MII_AN_LPABLE);
	if (mii_exstatus & MII_1000BT_STAT_LP_FDX_CAP) {
		ngep->param_lp_autoneg = B_TRUE;
		ngep->param_link_autoneg = B_TRUE;
		ngep->param_lp_1000fdx = B_TRUE;
	}
	if (mii_exstatus & MII_1000BT_STAT_LP_HDX_CAP) {
		ngep->param_lp_autoneg = B_TRUE;
		ngep->param_link_autoneg = B_TRUE;
		ngep->param_lp_1000hdx = B_TRUE;
	}
	if (lpan & MII_100BASET_FD)
		ngep->param_lp_100fdx = B_TRUE;
	if (lpan & MII_100BASET_HD)
		ngep->param_lp_100hdx = B_TRUE;
	if (lpan & MII_10BASET_FD)
		ngep->param_lp_10fdx = B_TRUE;
	if (lpan & MII_10BASET_HD)
		ngep->param_lp_10hdx = B_TRUE;
	if (lpan & MII_LP_ASYM_PAUSE)
		ngep->param_lp_asym_pause = B_TRUE;
	if (lpan & MII_LP_PAUSE)
		ngep->param_lp_pause = B_TRUE;
	if (linkup) {
		ngep->param_link_up = linkup;
		ngep->param_link_speed = nge_copper_link_speed[speed];
		ngep->param_link_duplex = nge_copper_link_duplex[duplex];
	} else {
		ngep->param_link_up = B_FALSE;
		ngep->param_link_speed = 0;
		ngep->param_link_duplex = LINK_DUPLEX_UNKNOWN;
	}
	NGE_DEBUG(("nge_check_copper: link now %s speed %d duplex %d",
	    UPORDOWN(ngep->param_link_up),
	    ngep->param_link_speed,
	    ngep->param_link_duplex));

	return (B_FALSE);
}

/*
 * Because the network chipset embedded in Ck8-04 bridge is only a mac chipset,
 * the different vendor can use different media(serdes and copper).
 * To make it easier to extend the driver to support more platforms with ck8-04,
 * For example, one platform with serdes support,
 * wrapper phy operation functions.
 * But now, only supply copper phy operations.
 */
static const phys_ops_t copper_ops = {
	nge_phy_restart,
	nge_update_copper,
	nge_check_copper
};

/*
 * Here we have to determine which media we're using (copper or serdes).
 * Once that's done, we can initialise the physical layer appropriately.
 */
void
nge_phys_init(nge_t *ngep)
{
	nge_mac2phy m2p;
	NGE_TRACE(("nge_phys_init($%p)", (void *)ngep));

	/* Get the phy type from MAC2PHY register */
	m2p.m2p_val = nge_reg_get32(ngep, NGE_MAC2PHY);
	ngep->phy_mode = m2p.m2p_bits.in_type;
	if ((ngep->phy_mode != RGMII_IN) && (ngep->phy_mode != MII_IN)) {
		ngep->phy_mode = RGMII_IN;
		m2p.m2p_bits.in_type = RGMII_IN;
		nge_reg_put32(ngep, NGE_MAC2PHY, m2p.m2p_val);
	}

	/*
	 * Probe for the type of the  PHY.
	 */
	ngep->phy_xmii_addr = 1;
	(void) nge_phy_probe(ngep);
	ngep->chipinfo.flags |= CHIP_FLAG_COPPER;
	ngep->physops = &copper_ops;
	(*(ngep->physops->phys_restart))(ngep);
}
