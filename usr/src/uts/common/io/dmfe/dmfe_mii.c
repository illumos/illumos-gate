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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "dmfe_impl.h"

/*
 * The bit-twiddling required by the MII interface makes the functions
 * in this file relatively slow, so they should probably only be called
 * from base/low-pri code.  However, there's nothing here that really
 * won't work at hi-pri, AFAIK; and 'relatively slow' only means that
 * they have microsecond busy-waits all over the place.
 *
 * dmfe_recheck_link(), on the other hand, uses delay() and loops for
 * up to dmfe_restart_time_us microseconds (currently 12 seconds), so
 * it should only be called from user (ioctl) or factotum context.
 *
 * Time parameters:
 *
 *	RESTART_TIME is the time in microseconds to allow for the link
 *	to go down and recover after changing the PHY parameters.
 *
 *	RESTART_POLL is the interval between checks on the link state
 *	while waiting for up to RESTART_TIME in total.
 *
 *	SETTLE_TIME is the time to allow for the PHY to stabilise
 *	after a change from LINK DOWN to LINK UP; multiple changes
 *	within this time are coalesced into one (in case the link
 *	goes UP-DOWN-UP as negotiation tries different speeds, etc).
 *
 * Patchable globals:
 *	dmfe_restart_time_us:	RESTART_TIME
 *	dmfe_restart_poll_us:	RESTART_POLL
 *	dmfe_mii_settle_time:	SETTLE_TIME
 */

#define	RESTART_POLL		600000		/* microseconds		*/
#define	RESTART_TIME		12000000	/* microseconds		*/
#define	SETTLE_TIME		3000000		/* microseconds		*/

#define	MII_AN_SELECTOR_8023	1
#define	MII_STATUS_INVAL	0xffffU

static clock_t dmfe_restart_poll_us = RESTART_POLL;
static clock_t dmfe_restart_time_us = RESTART_TIME;
static clock_t dmfe_mii_settle_time = SETTLE_TIME;
static const int mii_reg_size = 16;			/* bits		*/

#define	DMFE_DBG	DMFE_DBG_MII	/* debug flag for this code	*/

/*
 * Type of transceiver currently in use.  The IEEE 802.3 std aPhyType
 * enumerates the following set
 */
enum xcvr_type {
	XCVR_TYPE_UNDEFINED	= 0,	/* undefined, or not yet known	*/
	XCVR_TYPE_10BASE_T	= 7,	/* 10 Mbps copper		*/
	XCVR_TYPE_100BASE_X	= 24	/* 100 Mbps copper		*/
};

/*
 * ======== Low-level SROM access ========
 */

/*
 * EEPROM access is here because it shares register functionality with MII.
 * NB: <romaddr> is a byte address but must be 16-bit aligned.
 *     <cnt> is a byte count, and must be a multiple of 2.
 */
void
dmfe_read_eeprom(dmfe_t *dmfep, uint16_t raddr, uint8_t *ptr, int cnt)
{
	uint16_t value;
	uint16_t bit;

	/* only a whole number of words for now */
	ASSERT((cnt % 2) == 0);
	ASSERT((raddr % 2) == 0);
	ASSERT(cnt > 0);
	ASSERT(((raddr + cnt) / 2) < (HIGH_ADDRESS_BIT << 1));

	raddr /= 2;	/* make it a word address */

	/* loop over multiple words... rom access in 16-bit increments */
	while (cnt > 0) {

		/* select the eeprom */
		dmfe_chip_put32(dmfep, ETHER_ROM_REG, READ_EEPROM);
		drv_usecwait(1);
		dmfe_chip_put32(dmfep, ETHER_ROM_REG, READ_EEPROM_CS);
		drv_usecwait(1);
		dmfe_chip_put32(dmfep, ETHER_ROM_REG, READ_EEPROM_CS | SEL_CLK);
		drv_usecwait(1);
		dmfe_chip_put32(dmfep, ETHER_ROM_REG, READ_EEPROM_CS);
		drv_usecwait(1);

		/* send 3 bit read command */
		for (bit = HIGH_CMD_BIT; bit != 0; bit >>= 1) {

			value = (bit & EEPROM_READ_CMD) ? DATA_IN : 0;

			/* strobe the bit in */
			dmfe_chip_put32(dmfep, ETHER_ROM_REG,
			    READ_EEPROM_CS | value);
			drv_usecwait(1);
			dmfe_chip_put32(dmfep, ETHER_ROM_REG,
			    READ_EEPROM_CS | SEL_CLK | value);
			drv_usecwait(1);
			dmfe_chip_put32(dmfep, ETHER_ROM_REG,
			    READ_EEPROM_CS | value);
			drv_usecwait(1);
		}

		/* send 6 bit address */
		for (bit = HIGH_ADDRESS_BIT; bit != 0; bit >>= 1) {
			value = (bit & raddr) ? DATA_IN : 0;

			/* strobe the bit in */
			dmfe_chip_put32(dmfep, ETHER_ROM_REG,
			    READ_EEPROM_CS | value);
			drv_usecwait(1);
			dmfe_chip_put32(dmfep, ETHER_ROM_REG,
			    READ_EEPROM_CS | SEL_CLK | value);
			drv_usecwait(1);
			dmfe_chip_put32(dmfep, ETHER_ROM_REG,
			    READ_EEPROM_CS | value);
			drv_usecwait(1);
		}

		/* shift out data */
		value = 0;
		for (bit = HIGH_DATA_BIT; bit != 0; bit >>= 1) {

			dmfe_chip_put32(dmfep, ETHER_ROM_REG,
			    READ_EEPROM_CS | SEL_CLK);
			drv_usecwait(1);

			if (dmfe_chip_get32(dmfep, ETHER_ROM_REG) & DATA_OUT)
				value |= bit;
			drv_usecwait(1);

			dmfe_chip_put32(dmfep, ETHER_ROM_REG, READ_EEPROM_CS);
			drv_usecwait(1);
		}

		/* turn off EEPROM access */
		dmfe_chip_put32(dmfep, ETHER_ROM_REG, READ_EEPROM);
		drv_usecwait(1);

		/* this makes it endian neutral */
		*ptr++ = value & 0xff;
		*ptr++ = (value >> 8);

		cnt -= 2;
		raddr++;
	}
}

/*
 * ======== Lowest-level bit-twiddling to drive MII interface ========
 */

/*
 * Poke <nbits> (up to 32) bits from <mii_data> along the MII control lines.
 * Note: the data is taken starting with the MSB of <mii_data> and working
 * down through progressively less significant bits.
 */
static void
dmfe_poke_mii(dmfe_t *dmfep, uint32_t mii_data, uint_t nbits)
{
	uint32_t dbit;

	ASSERT(mutex_owned(dmfep->milock));

	for (; nbits > 0; mii_data <<= 1, --nbits) {
		/*
		 * Extract the MSB of <mii_data> and shift it to the
		 * proper bit position in the MII-poking register
		 */
		dbit = mii_data >> 31;
		dbit <<= MII_DATA_OUT_SHIFT;
		ASSERT((dbit & ~MII_DATA_OUT) == 0);

		/*
		 * Drive the bit across the wire ...
		 */
		dmfe_chip_put32(dmfep, ETHER_ROM_REG,
		    MII_WRITE | dbit);			/* Clock Low	*/
		drv_usecwait(MII_DELAY);
		dmfe_chip_put32(dmfep, ETHER_ROM_REG,
		    MII_WRITE | MII_CLOCK | dbit);	/* Clock High	*/
		drv_usecwait(MII_DELAY);
	}

	dmfe_chip_put32(dmfep, ETHER_ROM_REG,
	    MII_WRITE | dbit);				/* Clock Low	*/
	drv_usecwait(MII_DELAY);
}

/*
 * Put the MDIO port in tri-state for the turn around bits
 * in MII read and at end of MII management sequence.
 */
static void
dmfe_tristate_mii(dmfe_t *dmfep)
{
	ASSERT(mutex_owned(dmfep->milock));

	dmfe_chip_put32(dmfep, ETHER_ROM_REG, MII_TRISTATE);
	drv_usecwait(MII_DELAY);
	dmfe_chip_put32(dmfep, ETHER_ROM_REG, MII_TRISTATE | MII_CLOCK);
	drv_usecwait(MII_DELAY);
}


/*
 * ======== Next level: issue an MII access command/get a response ========
 */

static void
dmfe_mii_command(dmfe_t *dmfep, uint32_t command_word, int nbits)
{
	ASSERT(mutex_owned(dmfep->milock));

	/* Write Preamble & Command & return to tristate */
	dmfe_poke_mii(dmfep, MII_PREAMBLE, 2*mii_reg_size);
	dmfe_poke_mii(dmfep, command_word, nbits);
	dmfe_tristate_mii(dmfep);
}

static uint16_t
dmfe_mii_response(dmfe_t *dmfep)
{
	boolean_t ack;
	uint16_t data;
	uint32_t tmp;
	int i;

	/* Check that the PHY generated a zero bit on the 2nd clock */
	tmp = dmfe_chip_get32(dmfep, ETHER_ROM_REG);
	ack = (tmp & MII_DATA_IN) == 0;

	/* read data WORD */
	for (data = 0, i = 0; i < mii_reg_size; ++i) {
		dmfe_chip_put32(dmfep, ETHER_ROM_REG, MII_READ);
		drv_usecwait(MII_DELAY);
		dmfe_chip_put32(dmfep, ETHER_ROM_REG, MII_READ | MII_CLOCK);
		drv_usecwait(MII_DELAY);
		tmp = dmfe_chip_get32(dmfep, ETHER_ROM_REG);
		data <<= 1;
		data |= (tmp >> MII_DATA_IN_SHIFT) & 1;
	}

	/* leave the interface tristated */
	dmfe_tristate_mii(dmfep);

	return (ack ? data : ~0);
}

/*
 * ======== Next level: 16-bit PHY register access routines ========
 */

static void
dmfe_phy_write(dmfe_t *dmfep, uint_t reg_num, uint_t reg_dat)
{
	uint32_t command_word;

	/* Issue MII command */
	command_word = MII_WRITE_FRAME;
	command_word |= dmfep->phy_addr << MII_PHY_ADDR_SHIFT;
	command_word |= reg_num << MII_REG_ADDR_SHIFT;
	command_word |= reg_dat;
	dmfe_mii_command(dmfep, command_word, 2*mii_reg_size);
}

static uint16_t
dmfe_phy_read(dmfe_t *dmfep, uint_t reg_num)
{
	uint32_t command_word;

	/* Issue MII command */
	command_word = MII_READ_FRAME;
	command_word |= dmfep->phy_addr << MII_PHY_ADDR_SHIFT;
	command_word |= reg_num << MII_REG_ADDR_SHIFT;
	dmfe_mii_command(dmfep, command_word, mii_reg_size-2);

	return (dmfe_mii_response(dmfep));
}

/*
 * ======== Next level: PHY control operations ========
 */

/*
 * Reset the PHYceiver, using a wierd sequence of accesses to CR12
 *
 * This could be done using MII accesses; but this should be quicker ....
 */
static void
dmfe_phy_reset(dmfe_t *dmfep)
{
	DMFE_TRACE(("dmfe_phy_reset($%p)", (void *)dmfep));

	ASSERT(mutex_owned(dmfep->milock));

	dmfe_chip_put32(dmfep, PHY_STATUS_REG, GPS_WRITE_ENABLE|GPS_PHY_RESET);
	drv_usecwait(10);
	dmfe_chip_put32(dmfep, PHY_STATUS_REG, GPS_PHY_RESET);
	drv_usecwait(10);
	dmfe_chip_put32(dmfep, PHY_STATUS_REG, 0);
	drv_usecwait(10);
}

/*
 * Read the MII_STATUS register (BMSR)
 */
static uint16_t
dmfe_mii_status(dmfe_t *dmfep)
{
	uint16_t bmsr;

	bmsr = dmfe_phy_read(dmfep, MII_STATUS);

	DMFE_DEBUG(("dmfe_mii_status: bmsr 0x%x", bmsr));

	return (bmsr);
}

/*
 * Returns true if PHY at address <phy_addr> is present and accessible.
 * We determine whether the PHY is there by looking for at least one
 * set bit, and at least one clear bit, in the value returned from its
 * status register (i.e. BMSR is not all zeroes or all ones).
 */
static boolean_t
dmfe_probe_phy(dmfe_t *dmfep)
{
	uint16_t bmsr;

	ASSERT(mutex_owned(dmfep->milock));

	/* Clear any latched bits by reading twice */
	bmsr = dmfe_mii_status(dmfep);
	bmsr = dmfe_mii_status(dmfep);

	DMFE_DEBUG(("dmfe_probe_phy($%p, %d) BMSR 0x%x",
	    (void *)dmfep, dmfep->phy_addr, bmsr));

	/*
	 * At least one bit in BMSR should be set (for the device
	 * capabilities) and at least one clear (one of the error
	 * bits).  Unconnected devices tend to show 0xffff, but
	 * 0x0000 has also been seen.
	 */
	return (bmsr != 0 && bmsr != MII_STATUS_INVAL);
}

static boolean_t
dmfe_find_phy(dmfe_t *dmfep)
{
	int mii_addr;

	ASSERT(mutex_owned(dmfep->milock));

	/*
	 * Verify that the PHY responds to MII accesses.  It *should*
	 * be at MII address 1, but the Davicom internal PHY can be
	 * reprogrammed to appear at a different address, so we'll
	 * check all 32 possible addresses if necessary (in the order
	 * 1, 2, 3..31, 0)
	 */
	for (mii_addr = 1; ; ) {
		dmfep->phy_addr = mii_addr % 32;
		if (dmfe_probe_phy(dmfep))
			break;
		if (++mii_addr > 32) {
			DMFE_DEBUG(("No PHY found"));
			return (B_FALSE);
		}
	}

	dmfep->phy_id = dmfe_phy_read(dmfep, MII_PHYIDH) << 16;
	dmfep->phy_id |= dmfe_phy_read(dmfep, MII_PHYIDL);

	DMFE_DEBUG(("PHY at address %d, id 0x%x", mii_addr, dmfep->phy_id));

	switch (PHY_MANUFACTURER(dmfep->phy_id)) {
	case OUI_DAVICOM:
		return (B_TRUE);

	default:
		dmfe_warning(dmfep, "unsupported (non-Davicom) PHY found!");
		return (B_FALSE);
	}
}

#undef	DMFE_DBG

#define	DMFE_DBG	DMFE_DBG_LINK	/* debug flag for this code	*/

/*
 * ======== Top-level PHY management routines ========
 */

/*
 * (Re)initalise the PHY's speed/duplex/autonegotiation registers, basing
 * the required settings on the various param_* variables that can be poked
 * via the NDD interface.
 *
 * NOTE: the Tx/Rx processes should be STOPPED when this routine is called
 */
void
dmfe_update_phy(dmfe_t *dmfep)
{
	uint16_t control;
	uint16_t anar;

	DMFE_DEBUG(("dmfe_update_phy: autoneg %d 100fdx %d 100hdx %d "
	    "10fdx %d 10hdx %d", dmfep->param_autoneg,
	    dmfep->param_anar_100fdx, dmfep->param_anar_100hdx,
	    dmfep->param_anar_10fdx, dmfep->param_anar_10hdx));

	ASSERT(mutex_owned(dmfep->milock));

	/*
	 * NDD initialisation will have already set up the param_*
	 * variables based on the values of the various properties.
	 * Here we have to transform these into the proper settings
	 * of the PHY registers ...
	 */
	anar = control = 0;

	if (dmfep->param_anar_100fdx)
		control |= MII_CONTROL_100MB|MII_CONTROL_FDUPLEX;
	else if (dmfep->param_anar_100hdx)
		control |= MII_CONTROL_100MB;
	else if (dmfep->param_anar_10fdx)
		control |= MII_CONTROL_FDUPLEX;

	if (dmfep->param_anar_100fdx)
		anar |= MII_ABILITY_100BASE_TX_FD;
	if (dmfep->param_anar_100hdx)
		anar |= MII_ABILITY_100BASE_TX;
	if (dmfep->param_anar_10fdx)
		anar |= MII_ABILITY_10BASE_T_FD;
	if (dmfep->param_anar_10hdx)
		anar |= MII_ABILITY_10BASE_T;

	if (anar == 0) {
		/*
		 * A stupid combination of settings has left us with no
		 * options - so select the default (100Mb/s half-duplex)
		 * for now and re-enable ALL autonegotiation options.
		 */
		control |= MII_CONTROL_100MB;
		anar |= MII_ABILITY_100BASE_TX_FD;
		anar |= MII_ABILITY_100BASE_TX;
		anar |= MII_ABILITY_10BASE_T_FD;
		anar |= MII_ABILITY_10BASE_T;
	}

	if ((dmfep->opmode & LOOPBACK_MODE_MASK) != LOOPBACK_OFF) {
		/*
		 * If loopback is selected at the MAC level, we have
		 * to make sure that the settings are consistent at
		 * the PHY, and also keep autonegotiation switched OFF,
		 * otherwise we can get all sorts of strange effects
		 * including continuous link change interrupts :-(
		 */
		control |= MII_CONTROL_LOOPBACK;
	} else if (dmfep->param_autoneg) {
		/*
		 * Autonegotiation is only possible if loopback is OFF
		 */
		control |= MII_CONTROL_ANE;
	}

	DMFE_DEBUG(("dmfe_update_phy: anar 0x%x control 0x%x", anar, control));

	anar |= MII_AN_SELECTOR_8023;
	if ((anar != dmfep->phy_anar_w) || (control != dmfep->phy_control) ||
	    (dmfep->update_phy)) {
		/*
		 * Something's changed; reset the PHY and write the new
		 * values to the PHY CONTROL and ANAR registers.  This
		 * will probably cause the link to go down, and then back
		 * up again once the link is stable and autonegotiation
		 * (if enabled) is complete.  We should get a link state
		 * change at the end; but in any case the ticker will keep
		 * an eye on what's going on ...
		 */
		dmfe_phy_reset(dmfep);
		dmfe_phy_write(dmfep, MII_CONTROL, control);
		dmfe_phy_write(dmfep, MII_AN_ADVERT, anar);
	}

	/*
	 * If autonegotiation is (now) enabled, we want to trigger
	 * a new autonegotiation cycle now that the PHY has been
	 * programmed with the capabilities to be advertised.
	 */
	if (control & MII_CONTROL_ANE)
		dmfe_phy_write(dmfep, MII_CONTROL, control | MII_CONTROL_RSAN);

	/*
	 * Save the values written in the shadow copies of the CONTROL
	 * and ANAR registers, and clear the shadow BMSR 'cos it's no
	 * longer valid.
	 */
	dmfep->phy_control = control;
	dmfep->phy_anar_w = anar;
	dmfep->phy_bmsr = 0;
}


/*
 * PHY initialisation, called only once
 *
 * Discover the MII address of the PHY (should be 1).
 * Initialise according to preset NDD parameters.
 * Return status
 */
boolean_t
dmfe_init_phy(dmfe_t *dmfep)
{
	boolean_t ok;

	mutex_enter(dmfep->milock);
	ok = dmfe_find_phy(dmfep);
	if (ok)
		dmfe_update_phy(dmfep);
	mutex_exit(dmfep->milock);

	return (ok);
}

/*
 *	========== Active Media Determination Routines ==========
 */


/*
 * Check whether the BMSR has changed.  If it hasn't, this routine
 * just returns B_FALSE (no further action required).  Otherwise,
 * it records the time when the change was seen and returns B_TRUE.
 *
 * This routine needs only the <milock>, although <oplock> may
 * also be held.  This is why full processing of the link change
 * is left to dmfe_recheck_link() below.
 */
static boolean_t
dmfe_check_bmsr(dmfe_t *dmfep)
{
	uint16_t new_bmsr;

	DMFE_TRACE(("dmfe_check_bmsr($%p)", (void *)dmfep));

	ASSERT(mutex_owned(dmfep->milock));

	/*
	 * Read the BMSR and check it against the previous value
	 */
	new_bmsr = dmfe_mii_status(dmfep);
	DMFE_DEBUG(("dmfe_check_bmsr: bmsr 0x%x -> 0x%x",
	    dmfep->phy_bmsr, new_bmsr));

	/*
	 * Record new value and timestamp if it's changed
	 */
	if (new_bmsr != dmfep->phy_bmsr) {
		dmfep->phy_bmsr = new_bmsr;
		dmfep->phy_bmsr_lbolt = ddi_get_lbolt();
		return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * 'Quick' link check routine
 *
 * Call whenever the link state may have changed, or periodically to
 * poll for link up/down events.  Returns B_FALSE if nothing interesting
 * has happened.  Otherwise, it returns B_TRUE, telling the caller to
 * call dmfe_recheck_link() (below).  If the link state is UNKNOWN, we
 * return B_TRUE anyway, even if the BMSR hasn't changed - but only after
 * going through the motions, 'cos the read of the BMSR has side-effects -
 * some of the BMSR bits are latching-until-read, and dmfe_check_bmsr()
 * also records the time of any change to the BMSR!
 */
boolean_t
dmfe_check_link(dmfe_t *dmfep)
{
	if (dmfe_check_bmsr(dmfep))
		return (B_TRUE);
	return (dmfep->link_state == LINK_STATE_UNKNOWN);
}


/*
 * Update all parameters and statistics after a link state change.
 */
static void
dmfe_media_update(dmfe_t *dmfep, link_state_t newstate, int speed, int duplex)
{
	int ks_id;

	ASSERT(mutex_owned(dmfep->milock));
	ASSERT(mutex_owned(dmfep->oplock));
	ASSERT(newstate != dmfep->link_state);

	switch (newstate) {
	case LINK_STATE_UP:
		dmfep->param_linkup = 1;
		break;

	default:
		dmfep->param_linkup = 0;
		break;
	}

	switch (speed) {
	case 100:
		dmfep->op_stats_speed = 100000000;
		dmfep->param_speed = speed;
		dmfep->phy_inuse = XCVR_100X;
		break;

	case 10:
		dmfep->op_stats_speed = 10000000;
		dmfep->param_speed = speed;
		dmfep->phy_inuse = XCVR_10;
		break;

	default:
		dmfep->op_stats_speed = 0;
		dmfep->phy_inuse = XCVR_UNDEFINED;
		break;
	}

	dmfep->op_stats_duplex = dmfep->param_duplex = duplex;

	if (newstate == LINK_STATE_UP)
		ks_id = KS_LINK_UP_CNT;
	else
		ks_id = KS_LINK_DROP_CNT;
	DRV_KS_INC(dmfep, ks_id);
}

/*
 * Verify and report a change in the state of the link ...
 */
static void
dmfe_link_change(dmfe_t *dmfep, link_state_t newstate)
{
	boolean_t report;
	uint32_t gpsr;
	int speed;
	int duplex;

	ASSERT(mutex_owned(dmfep->milock));
	ASSERT(mutex_owned(dmfep->oplock));
	ASSERT(newstate != dmfep->link_state);

	switch (newstate) {
	case LINK_STATE_UP:
		gpsr = dmfe_chip_get32(dmfep, PHY_STATUS_REG);
		speed = gpsr & GPS_LINK_100 ? 100 : 10;
		duplex = (gpsr & GPS_FULL_DUPLEX) ?
		    LINK_DUPLEX_FULL: LINK_DUPLEX_HALF;
		report = B_TRUE;
		break;

	default:
		speed = 0;
		duplex = LINK_DUPLEX_UNKNOWN;
		switch (dmfep->link_state) {
		case LINK_STATE_DOWN:		/* DOWN->UNKNOWN	*/
		case LINK_STATE_UNKNOWN:	/* UNKNOWN->DOWN	*/
			report = B_FALSE;
			break;

		case LINK_STATE_UP:		/* UP->DOWN/UNKNOWN	*/
			report = B_TRUE;
			break;
		}
		break;
	}

	/*
	 * Update status & report new link state if required ...
	 */
	if (report)
		dmfe_media_update(dmfep, newstate, speed, duplex);
}

/*
 * Examine the value most recently read from the BMSR and derive
 * the (new) link state.
 *
 * This routine also incorporates heuristics determining when to
 * accept a new state as valid and report it, based on the new
 * (apparent) state, the old state, and the time elapsed since
 * the last time we saw a (potential) state change.  For example,
 * we want to accept UP->DOWN immediately, but UNKNOWN->UP only
 * once autonegotiation is completed and the results are stable.
 */
static link_state_t
dmfe_process_bmsr(dmfe_t *dmfep, clock_t time)
{
	link_state_t newstate;
	uint32_t gpsr;
	uint16_t bmsr;
	uint16_t anlpar;
	uint16_t anar;

	ASSERT(mutex_owned(dmfep->milock));
	ASSERT(mutex_owned(dmfep->oplock));

	/*
	 * Read PHY registers & publish through driver-specific kstats
	 * Decode abilities & publish through ndd & standard MII kstats
	 */
	dmfep->phy_anar_r = dmfe_phy_read(dmfep, MII_AN_ADVERT);
	dmfep->phy_aner   = dmfe_phy_read(dmfep, MII_AN_EXPANSION);
	dmfep->phy_anlpar = dmfe_phy_read(dmfep, MII_AN_LPABLE);
	dmfep->phy_dscsr  = dmfe_phy_read(dmfep, DM_SCSR);

	DRV_KS_SET(dmfep, KS_MIIREG_BMSR, dmfep->phy_bmsr);
	DRV_KS_SET(dmfep, KS_MIIREG_ANAR, dmfep->phy_anar_r);
	DRV_KS_SET(dmfep, KS_MIIREG_ANER, dmfep->phy_aner);
	DRV_KS_SET(dmfep, KS_MIIREG_ANLPAR, dmfep->phy_anlpar);
	DRV_KS_SET(dmfep, KS_MIIREG_DSCSR, dmfep->phy_dscsr);

	DMFE_DEBUG(("dmfe_process_bmsr: ANAR 0x%x->0x%x ANLPAR 0x%x SCSR 0x%x",
	    dmfep->phy_anar_w, dmfep->phy_anar_r,
	    dmfep->phy_anlpar, dmfep->phy_dscsr));

	/*
	 * Capabilities of DM9102A
	 */
	bmsr = dmfep->phy_bmsr;

	dmfep->param_bmsr_100T4    = BIS(bmsr, MII_STATUS_100_BASE_T4);
	dmfep->param_bmsr_100fdx   = BIS(bmsr, MII_STATUS_100_BASEX_FD);
	dmfep->param_bmsr_100hdx   = BIS(bmsr, MII_STATUS_100_BASEX);
	dmfep->param_bmsr_10fdx    = BIS(bmsr, MII_STATUS_10_FD);
	dmfep->param_bmsr_10hdx    = BIS(bmsr, MII_STATUS_10);
	dmfep->param_bmsr_remfault = 1;
	dmfep->param_bmsr_autoneg  = BIS(bmsr, MII_STATUS_CANAUTONEG);

	/*
	 * Advertised abilities of DM9102A
	 */
	anar = dmfep->phy_anar_r;
	dmfep->param_anar_remfault = BIS(anar, MII_AN_ADVERT_REMFAULT);

	/*
	 * Link Partners advertised abilities
	 */
	if ((dmfep->phy_aner & MII_AN_EXP_LPCANAN) == 0) {
		anlpar = 0;
		dmfep->param_lp_autoneg = 0;
	} else {
		anlpar = dmfep->phy_anlpar;
		dmfep->param_lp_autoneg = 1;
	}

	dmfep->param_lp_100T4    = BIS(anlpar, MII_ABILITY_100BASE_T4);
	dmfep->param_lp_100fdx   = BIS(anlpar, MII_ABILITY_100BASE_TX_FD);
	dmfep->param_lp_100hdx   = BIS(anlpar, MII_ABILITY_100BASE_TX);
	dmfep->param_lp_10fdx    = BIS(anlpar, MII_ABILITY_10BASE_T_FD);
	dmfep->param_lp_10hdx    = BIS(anlpar, MII_ABILITY_10BASE_T);
	dmfep->param_lp_remfault = BIS(anlpar, MII_AN_ADVERT_REMFAULT);

	/*
	 * Derive new state & time since last change
	 */
	newstate = (dmfep->phy_bmsr & MII_STATUS_LINKUP) ?
	    LINK_STATE_UP : LINK_STATE_DOWN;
	time -= dmfep->phy_bmsr_lbolt;

	/*
	 * Hah! That would be just too easy ... we have to check
	 * for all sorts of special cases before we decide :(
	 */
	if (dmfep->phy_bmsr == MII_STATUS_INVAL)
		newstate = LINK_STATE_DOWN;
	else if ((dmfep->link_state == LINK_STATE_UP) &&
	    (newstate == LINK_STATE_DOWN))
		/*EMPTY*/;
	else if (time < drv_usectohz(dmfe_mii_settle_time))
		newstate = LINK_STATE_UNKNOWN;
	else if (dmfep->phy_bmsr & MII_STATUS_ANDONE)
		/*EMPTY*/;
	else if (dmfep->phy_control & MII_CONTROL_ANE)
		newstate = LINK_STATE_DOWN;

	if (newstate == LINK_STATE_UP) {
		/*
		 * Link apparently UP - but get the PHY status register
		 * (GPSR) and make sure it also shows a consistent value.
		 * In particular, both the link status bits should be 1,
		 * and the speed bits should show one set and one clear.
		 * Any other combination indicates that we haven't really
		 * got a stable link yet ...
		 */
		gpsr = dmfe_chip_get32(dmfep, PHY_STATUS_REG);
		DMFE_DEBUG(("dmfe_process_bmsr: GPSR 0x%x", gpsr));

		switch (gpsr & (GPS_LINK_STATUS|GPS_UTP_SIG)) {
		case GPS_LINK_STATUS|GPS_UTP_SIG:
			break;
		default:
			newstate = LINK_STATE_UNKNOWN;
			break;
		}

		switch (gpsr & (GPS_LINK_10|GPS_LINK_100)) {
		case GPS_LINK_100:
		case GPS_LINK_10:
			break;
		default:
			newstate = LINK_STATE_UNKNOWN;
			break;
		}
	}

	DMFE_DEBUG(("dmfe_process_bmsr: BMSR 0x%x state %d -> %d @ %d",
	    dmfep->phy_bmsr, dmfep->link_state, newstate, time));

	return (newstate);
}

/*
 * 'Full' link check routine
 *
 * Call whenever dmfe_check_link() above indicates that the link
 * state may have changed.  Handles all changes to the link state
 * (up/down, speed/duplex changes), including multiple changes
 * occuring within the <timeout>.  <timeout> will be zero if called
 * from the factotum (for an unexpected change) or the number of
 * ticks for which to wait for stability after an ioctl that changes
 * the link parameters.  Even when <timeout> is zero, we loop while
 * the BMSR keeps changing ...
 *
 * Needs both <milock> and <oplock>, and the Tx/Rx processes
 * should already be stopped so we're not liable to confuse them
 * by changing the PHY/MAC parameters under them ...
 *
 */
void
dmfe_recheck_link(dmfe_t *dmfep, boolean_t ioctl)
{
	link_state_t newstate;
	boolean_t again;
	clock_t deadline;
	clock_t now;

	DMFE_TRACE(("dmfe_recheck_link($%p, %d)", (void *)dmfep, ioctl));

	ASSERT(mutex_owned(dmfep->milock));
	ASSERT(mutex_owned(dmfep->oplock));

	now = deadline = ddi_get_lbolt();
	if (ioctl)
		deadline += drv_usectohz(dmfe_restart_time_us);

	for (; ; now = ddi_get_lbolt()) {
		newstate = dmfe_process_bmsr(dmfep, now);
		again = dmfe_check_bmsr(dmfep);
		if (newstate != dmfep->link_state) {
			dmfe_link_change(dmfep, newstate);
			dmfep->link_state = newstate;
			again = B_TRUE;
		}
		ASSERT(dmfep->link_state == newstate);
		if (again)
			continue;
		if (newstate == LINK_STATE_UP) {
			dmfep->update_phy = B_TRUE;
			break;
		}
		if (now >= deadline)
			break;
		delay(drv_usectohz(dmfe_restart_poll_us));
	}
}

#undef	DMFE_DBG
