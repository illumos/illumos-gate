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

#include "dmfe_impl.h"

/*
 * The bit-twiddling required by the MII interface makes the functions
 * in this file relatively slow, so they should probably only be called
 * from base/low-pri code.  However, there's nothing here that really
 * won't work at hi-pri, AFAIK; and 'relatively slow' only means that
 * they have microsecond busy-waits all over the place.
 */

static const int mii_reg_size = 16;			/* bits		*/

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
dmfe_mii_write(void *arg, uint8_t phy_num, uint8_t reg_num, uint16_t reg_dat)
{
	dmfe_t *dmfep = arg;
	uint32_t command_word;

	/* Issue MII command */
	mutex_enter(dmfep->milock);
	command_word = MII_WRITE_FRAME;
	command_word |= phy_num << MII_PHY_ADDR_SHIFT;
	command_word |= reg_num << MII_REG_ADDR_SHIFT;
	command_word |= reg_dat;
	dmfe_mii_command(dmfep, command_word, 2*mii_reg_size);
	mutex_exit(dmfep->milock);
}

static uint16_t
dmfe_mii_read(void *arg, uint8_t phy_num, uint8_t reg_num)
{
	dmfe_t *dmfep = arg;
	uint32_t command_word;
	uint16_t rv;

	/* Issue MII command */
	command_word = MII_READ_FRAME;
	command_word |= phy_num << MII_PHY_ADDR_SHIFT;
	command_word |= reg_num << MII_REG_ADDR_SHIFT;

	mutex_enter(dmfep->milock);
	dmfe_mii_command(dmfep, command_word, mii_reg_size-2);

	rv = dmfe_mii_response(dmfep);
	mutex_exit(dmfep->milock);
	return (rv);
}

static void
dmfe_mii_notify(void *arg, link_state_t link)
{
	dmfe_t *dmfep = arg;

	if (link == LINK_STATE_UP) {
		mutex_enter(dmfep->oplock);
		/*
		 * Configure DUPLEX setting on MAC.
		 */
		if (mii_get_duplex(dmfep->mii) == LINK_DUPLEX_FULL) {
			dmfep->opmode |= FULL_DUPLEX;
		} else {
			dmfep->opmode &= ~FULL_DUPLEX;
		}
		dmfe_chip_put32(dmfep, OPN_MODE_REG, dmfep->opmode);
		mutex_exit(dmfep->oplock);
	}
	mac_link_update(dmfep->mh, link);
}


/*
 * PHY initialisation, called only once
 */

static mii_ops_t dmfe_mii_ops = {
	MII_OPS_VERSION,
	dmfe_mii_read,
	dmfe_mii_write,
	dmfe_mii_notify,
	NULL,			/* mii_reset */
};

boolean_t
dmfe_init_phy(dmfe_t *dmfep)
{
	dmfep->mii = mii_alloc(dmfep, dmfep->devinfo, &dmfe_mii_ops);
	if (dmfep->mii == NULL) {
		return (B_FALSE);
	}
	return (B_TRUE);
}
