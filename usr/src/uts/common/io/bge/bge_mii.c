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
 * Copyright (c) 2010-2013, by Broadcom, Inc.
 * All Rights Reserved.
 */

/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates.
 * All rights reserved.
 */

#include "bge_impl.h"

/*
 * Bit test macros, returning boolean_t values
 */
#define	BIS(w, b)	(((w) & (b)) ? B_TRUE : B_FALSE)
#define	BIC(w, b)	(((w) & (b)) ? B_FALSE : B_TRUE)
#define	UPORDOWN(x)	((x) ? "up" : "down")

/*
 * ========== Copper (PHY) support ==========
 */

#define	BGE_DBG		BGE_DBG_PHY	/* debug flag for this code	*/

/*
 * #defines:
 *	BGE_COPPER_WIRESPEED controls whether the Broadcom WireSpeed(tm)
 *	feature is enabled.  We need to recheck whether this can be
 *	enabled; at one time it seemed to interact unpleasantly with the
 *	loopback modes.
 *
 *	BGE_COPPER_IDLEOFF controls whether the (copper) PHY power is
 *	turned off when the PHY is idled i.e. during driver suspend().
 *	For now this is disabled because the chip doesn't seem to
 *	resume cleanly if the PHY power is turned off.
 */
#define	BGE_COPPER_WIRESPEED	B_TRUE
#define	BGE_COPPER_IDLEOFF	B_FALSE

/*
 * The arrays below can be indexed by the MODE bits from the Auxiliary
 * Status register to determine the current speed/duplex settings.
 */
static const int16_t bge_copper_link_speed[] = {
	0,				/* MII_AUX_STATUS_MODE_NONE	*/
	10,				/* MII_AUX_STATUS_MODE_10_H	*/
	10,				/* MII_AUX_STATUS_MODE_10_F	*/
	100,				/* MII_AUX_STATUS_MODE_100_H	*/
	0,				/* MII_AUX_STATUS_MODE_100_4	*/
	100,				/* MII_AUX_STATUS_MODE_100_F	*/
	1000,				/* MII_AUX_STATUS_MODE_1000_H	*/
	1000				/* MII_AUX_STATUS_MODE_1000_F	*/
};

static const int8_t bge_copper_link_duplex[] = {
	LINK_DUPLEX_UNKNOWN,		/* MII_AUX_STATUS_MODE_NONE	*/
	LINK_DUPLEX_HALF,		/* MII_AUX_STATUS_MODE_10_H	*/
	LINK_DUPLEX_FULL,		/* MII_AUX_STATUS_MODE_10_F	*/
	LINK_DUPLEX_HALF,		/* MII_AUX_STATUS_MODE_100_H	*/
	LINK_DUPLEX_UNKNOWN,		/* MII_AUX_STATUS_MODE_100_4	*/
	LINK_DUPLEX_FULL,		/* MII_AUX_STATUS_MODE_100_F	*/
	LINK_DUPLEX_HALF,		/* MII_AUX_STATUS_MODE_1000_H	*/
	LINK_DUPLEX_FULL		/* MII_AUX_STATUS_MODE_1000_F	*/
};

static const int16_t bge_copper_link_speed_5906[] = {
	0,				/* MII_AUX_STATUS_MODE_NONE	*/
	10,				/* MII_AUX_STATUS_MODE_10_H	*/
	10,				/* MII_AUX_STATUS_MODE_10_F	*/
	100,				/* MII_AUX_STATUS_MODE_100_H	*/
	0,				/* MII_AUX_STATUS_MODE_100_4	*/
	100,				/* MII_AUX_STATUS_MODE_100_F	*/
	0,				/* MII_AUX_STATUS_MODE_1000_H	*/
	0				/* MII_AUX_STATUS_MODE_1000_F	*/
};

static const int8_t bge_copper_link_duplex_5906[] = {
	LINK_DUPLEX_UNKNOWN,		/* MII_AUX_STATUS_MODE_NONE	*/
	LINK_DUPLEX_HALF,		/* MII_AUX_STATUS_MODE_10_H	*/
	LINK_DUPLEX_FULL,		/* MII_AUX_STATUS_MODE_10_F	*/
	LINK_DUPLEX_HALF,		/* MII_AUX_STATUS_MODE_100_H	*/
	LINK_DUPLEX_UNKNOWN,		/* MII_AUX_STATUS_MODE_100_4	*/
	LINK_DUPLEX_FULL,		/* MII_AUX_STATUS_MODE_100_F	*/
	LINK_DUPLEX_UNKNOWN,		/* MII_AUX_STATUS_MODE_1000_H	*/
	LINK_DUPLEX_UNKNOWN		/* MII_AUX_STATUS_MODE_1000_F	*/
};

#if	BGE_DEBUGGING

static void
bge_phydump(bge_t *bgep, uint16_t mii_status, uint16_t aux)
{
	uint16_t regs[32];
	int i;

	ASSERT(mutex_owned(bgep->genlock));

	for (i = 0; i < 32; ++i)
		switch (i) {
		default:
			regs[i] = bge_mii_get16(bgep, i);
			break;

		case MII_STATUS:
			regs[i] = mii_status;
			break;

		case MII_AUX_STATUS:
			regs[i] = aux;
			break;

		case 0x0b: case 0x0c: case 0x0d: case 0x0e:
		case 0x15: case 0x16: case 0x17:
		case 0x1c:
		case 0x1f:
			/* reserved registers -- don't read these */
			regs[i] = 0;
			break;
		}

	for (i = 0; i < 32; i += 8)
		BGE_DEBUG(("bge_phydump: "
		    "0x%04x %04x %04x %04x %04x %04x %04x %04x",
		    regs[i+0], regs[i+1], regs[i+2], regs[i+3],
		    regs[i+4], regs[i+5], regs[i+6], regs[i+7]));
}

#endif	/* BGE_DEBUGGING */

static void
bge_phy_toggle_auxctl_smdsp(bge_t *bgep,
                            boolean_t enable)
{
	uint16_t val;

	val = bge_mii_get16(bgep, MII_AUX_CONTROL);

	if (enable) {
		val |= MII_AUX_CTRL_SMDSP_ENA;
	} else {
		val &= ~MII_AUX_CTRL_SMDSP_ENA;
	}

	bge_mii_put16(bgep, MII_AUX_CONTROL, (val | MII_AUX_CTRL_TX_6DB));
}

/*
 * Basic low-level function to probe for a PHY
 *
 * Returns TRUE if the PHY responds with valid data, FALSE otherwise
 */
static boolean_t
bge_phy_probe(bge_t *bgep)
{
	uint16_t miicfg;
	uint32_t nicsig, niccfg;
	int i;

	BGE_TRACE(("bge_phy_probe($%p)", (void *)bgep));

	ASSERT(mutex_owned(bgep->genlock));

	nicsig = bge_nic_read32(bgep, BGE_NIC_DATA_SIG_ADDR);
	if (nicsig == BGE_NIC_DATA_SIG) {
		niccfg = bge_nic_read32(bgep, BGE_NIC_DATA_NIC_CFG_ADDR);
		switch (niccfg & BGE_NIC_CFG_PHY_TYPE_MASK) {
		default:
		case BGE_NIC_CFG_PHY_TYPE_COPPER:
			return (B_TRUE);
		case BGE_NIC_CFG_PHY_TYPE_FIBER:
			return (B_FALSE);
		}
	} else {
		/*
		 * Read the MII_STATUS register twice, in
		 * order to clear any sticky bits (but they should
		 * have been cleared by the RESET, I think).
		 */
		for (i = 0; i < 100; i++) {
			drv_usecwait(40);
			miicfg = bge_mii_get16(bgep, MII_STATUS);
		}
		BGE_DEBUG(("bge_phy_probe: status 0x%x", miicfg));

		/*
		 * Now check the value read; it should have at least one bit set
		 * (for the device capabilities) and at least one clear (one of
		 * the error bits). So if we see all 0s or all 1s, there's a
		 * problem.  In particular, bge_mii_get16() returns all 1s if
		 * communications fails ...
		 */
		switch (miicfg) {
		case 0x0000:
		case 0xffff:
			return (B_FALSE);

		default:
			return (B_TRUE);
		}
	}
}

/*
 * Basic low-level function to reset the PHY.
 * Doesn't incorporate any special-case workarounds.
 *
 * Returns TRUE on success, FALSE if the RESET bit doesn't clear
 */
static boolean_t
bge_phy_reset(bge_t *bgep)
{
	uint16_t control;
	uint_t count;

	BGE_TRACE(("bge_phy_reset($%p)", (void *)bgep));

	ASSERT(mutex_owned(bgep->genlock));

	if (DEVICE_5906_SERIES_CHIPSETS(bgep)) {
		drv_usecwait(40);
		/* put PHY into ready state */
		bge_reg_clr32(bgep, MISC_CONFIG_REG, MISC_CONFIG_EPHY_IDDQ);
		(void) bge_reg_get32(bgep, MISC_CONFIG_REG); /* flush */
		drv_usecwait(40);
	}

	/*
	 * Set the PHY RESET bit, then wait up to 5 ms for it to self-clear
	 */
	bge_mii_put16(bgep, MII_CONTROL, MII_CONTROL_RESET);
	for (count = 0; ++count < 1000; ) {
		drv_usecwait(5);
		control = bge_mii_get16(bgep, MII_CONTROL);
		if (BIC(control, MII_CONTROL_RESET))
			return (B_TRUE);
	}

	if (DEVICE_5906_SERIES_CHIPSETS(bgep))
		(void) bge_adj_volt_5906(bgep);

	BGE_DEBUG(("bge_phy_reset: FAILED, control now 0x%x", control));

	return (B_FALSE);
}

/*
 * Basic low-level function to powerdown the PHY, if supported
 * If powerdown support is compiled out, this function does nothing.
 */
static void
bge_phy_powerdown(bge_t *bgep)
{
	BGE_TRACE(("bge_phy_powerdown"));
#if	BGE_COPPER_IDLEOFF
	bge_mii_put16(bgep, MII_CONTROL, MII_CONTROL_PWRDN);
#endif	/* BGE_COPPER_IDLEOFF */
}

/*
 * The following functions are based on sample code provided by
 * Broadcom (20-June-2003), and implement workarounds said to be
 * required on the early revisions of the BCM5703/4C.
 *
 * The registers and values used are mostly UNDOCUMENTED, and
 * therefore don't have symbolic names ;-(
 *
 * Many of the comments are straight out of the Broadcom code:
 * even where the code has been restructured, the original
 * comments have been preserved in order to explain what these
 * undocumented registers & values are all about ...
 */

static void
bge_phy_macro_wait(bge_t *bgep)
{
	uint_t count;

	for (count = 100; --count; )
		if ((bge_mii_get16(bgep, 0x16) & 0x1000) == 0)
			break;
}

/*
 * PHY test data pattern:
 *
 * For 5703/04, each DFE TAP has 21-bits (low word 15, hi word 6)
 * For 5705,    each DFE TAP has 19-bits (low word 15, hi word 4)
 * For simplicity, we check only 19-bits, so we don't have to
 * distinguish which chip it is.
 * the LO word contains 15 bits, make sure pattern data is < 0x7fff
 * the HI word contains  6 bits, make sure pattern data is < 0x003f
 */
#define	N_CHANNELS	4
#define	N_TAPS		3

static struct {
	uint16_t	lo;
	uint16_t	hi;
} tap_data[N_CHANNELS][N_TAPS] = {
	{
		{ 0x5555, 0x0005 },	/* ch0, TAP 0, LO/HI pattern */
		{ 0x2aaa, 0x000a },	/* ch0, TAP 1, LO/HI pattern */
		{ 0x3456, 0x0003 }	/* ch0, TAP 2, LO/HI pattern */
	},
	{
		{ 0x2aaa, 0x000a },	/* ch1, TAP 0, LO/HI pattern */
		{ 0x3333, 0x0003 },	/* ch1, TAP 1, LO/HI pattern */
		{ 0x789a, 0x0005 }	/* ch1, TAP 2, LO/HI pattern */
	},
	{
		{ 0x5a5a, 0x0005 },	/* ch2, TAP 0, LO/HI pattern */
		{ 0x2a6a, 0x000a },	/* ch2, TAP 1, LO/HI pattern */
		{ 0x1bcd, 0x0003 }	/* ch2, TAP 2, LO/HI pattern */
	},
	{
		{ 0x2a5a, 0x000a },	/* ch3, TAP 0, LO/HI pattern */
		{ 0x33c3, 0x0003 },	/* ch3, TAP 1, LO/HI pattern */
		{ 0x2ef1, 0x0005 }	/* ch3, TAP 2, LO/HI pattern */
	}
};

/*
 * Check whether the PHY has locked up after a RESET.
 *
 * Returns TRUE if it did, FALSE is it's OK ;-)
 */
static boolean_t
bge_phy_locked_up(bge_t *bgep)
{
	uint16_t dataLo;
	uint16_t dataHi;
	uint_t chan;
	uint_t tap;

	/*
	 * Check TAPs for all 4 channels, as soon as we see a lockup
	 * we'll stop checking.
	 */
	for (chan = 0; chan < N_CHANNELS; ++chan) {
		/* Select channel and set TAP index to 0 */
		bge_mii_put16(bgep, 0x17, (chan << 13) | 0x0200);
		/* Freeze filter again just to be safe */
		bge_mii_put16(bgep, 0x16, 0x0002);

		/*
		 * Write fixed pattern to the RAM, 3 TAPs for
		 * each channel, each TAP have 2 WORDs (LO/HI)
		 */
		for (tap = 0; tap < N_TAPS; ++tap) {
			bge_mii_put16(bgep, 0x15, tap_data[chan][tap].lo);
			bge_mii_put16(bgep, 0x15, tap_data[chan][tap].hi);
		}

		/*
		 * Active PHY's Macro operation to write DFE
		 * TAP from RAM, and wait for Macro to complete.
		 */
		bge_mii_put16(bgep, 0x16, 0x0202);
		bge_phy_macro_wait(bgep);

		/*
		 * Done with write phase, now begin read phase.
		 */

		/* Select channel and set TAP index to 0 */
		bge_mii_put16(bgep, 0x17, (chan << 13) | 0x0200);

		/*
		 * Active PHY's Macro operation to load DFE
		 * TAP to RAM, and wait for Macro to complete
		 */
		bge_mii_put16(bgep, 0x16, 0x0082);
		bge_phy_macro_wait(bgep);

		/* Enable "pre-fetch" */
		bge_mii_put16(bgep, 0x16, 0x0802);
		bge_phy_macro_wait(bgep);

		/*
		 * Read back the TAP values.  3 TAPs for each
		 * channel, each TAP have 2 WORDs (LO/HI)
		 */
		for (tap = 0; tap < N_TAPS; ++tap) {
			/*
			 * Read Lo/Hi then wait for 'done' is faster.
			 * For DFE TAP, the HI word contains 6 bits,
			 * LO word contains 15 bits
			 */
			dataLo = bge_mii_get16(bgep, 0x15) & 0x7fff;
			dataHi = bge_mii_get16(bgep, 0x15) & 0x003f;
			bge_phy_macro_wait(bgep);

			/*
			 * Check if what we wrote is what we read back.
			 * If failed, then the PHY is locked up, we need
			 * to do PHY reset again
			 */
			if (dataLo != tap_data[chan][tap].lo)
				return (B_TRUE);	/* wedged!	*/

			if (dataHi != tap_data[chan][tap].hi)
				return (B_TRUE);	/* wedged!	*/
		}
	}

	/*
	 * The PHY isn't locked up ;-)
	 */
	return (B_FALSE);
}

/*
 * Special-case code to reset the PHY on the 5702/5703/5704C/5705/5782.
 * Tries up to 5 times to recover from failure to reset or PHY lockup.
 *
 * Returns TRUE on success, FALSE if there's an unrecoverable problem
 */
static boolean_t
bge_phy_reset_and_check(bge_t *bgep)
{
	boolean_t reset_success;
	boolean_t phy_locked;
	uint16_t extctrl;
	uint16_t gigctrl;
	uint_t retries;

	for (retries = 0; retries < 5; ++retries) {
		/* Issue a phy reset, and wait for reset to complete */
		/* Assuming reset is successful first */
		reset_success = bge_phy_reset(bgep);

		/*
		 * Now go check the DFE TAPs to see if locked up, but
		 * first, we need to set up PHY so we can read DFE
		 * TAPs.
		 */

		/*
		 * Disable Transmitter and Interrupt, while we play
		 * with the PHY registers, so the link partner won't
		 * see any strange data and the Driver won't see any
		 * interrupts.
		 */
		extctrl = bge_mii_get16(bgep, 0x10);
		bge_mii_put16(bgep, 0x10, extctrl | 0x3000);

		/* Setup Full-Duplex, 1000 mbps */
		bge_mii_put16(bgep, 0x0, 0x0140);

		/* Set to Master mode */
		gigctrl = bge_mii_get16(bgep, 0x9);
		bge_mii_put16(bgep, 0x9, 0x1800);

		/* Enable SM_DSP_CLOCK & 6dB */
		bge_mii_put16(bgep, 0x18, 0x0c00);	/* "the ADC fix" */

		/* Work-arounds */
		bge_mii_put16(bgep, 0x17, 0x201f);
		bge_mii_put16(bgep, 0x15, 0x2aaa);

		/* More workarounds */
		bge_mii_put16(bgep, 0x17, 0x000a);
		bge_mii_put16(bgep, 0x15, 0x0323);	/* "the Gamma fix" */

		/* Blocks the PHY control access */
		bge_mii_put16(bgep, 0x17, 0x8005);
		bge_mii_put16(bgep, 0x15, 0x0800);

		/* Test whether PHY locked up ;-( */
		phy_locked = bge_phy_locked_up(bgep);
		if (reset_success && !phy_locked)
			break;

		/*
		 * Some problem here ... log it & retry
		 */
		if (!reset_success)
			BGE_REPORT((bgep, "PHY didn't reset!"));
		if (phy_locked)
			BGE_REPORT((bgep, "PHY locked up!"));
	}

	/* Remove block phy control */
	bge_mii_put16(bgep, 0x17, 0x8005);
	bge_mii_put16(bgep, 0x15, 0x0000);

	/* Unfreeze DFE TAP filter for all channels */
	bge_mii_put16(bgep, 0x17, 0x8200);
	bge_mii_put16(bgep, 0x16, 0x0000);

	/* Restore PHY back to operating state */
	bge_mii_put16(bgep, 0x18, 0x0400);

	/* Restore 1000BASE-T Control Register */
	bge_mii_put16(bgep, 0x9, gigctrl);

	/* Enable transmitter and interrupt */
	extctrl = bge_mii_get16(bgep, 0x10);
	bge_mii_put16(bgep, 0x10, extctrl & ~0x3000);

	if (DEVICE_5906_SERIES_CHIPSETS(bgep))
		(void) bge_adj_volt_5906(bgep);

	if (!reset_success)
		bge_fm_ereport(bgep, DDI_FM_DEVICE_NO_RESPONSE);
	else if (phy_locked)
		bge_fm_ereport(bgep, DDI_FM_DEVICE_INVAL_STATE);
	return (reset_success && !phy_locked);
}

static void
bge_phy_tweak_gmii(bge_t *bgep)
{
	/* Tweak GMII timing */
	bge_mii_put16(bgep, 0x1c, 0x8d68);
	bge_mii_put16(bgep, 0x1c, 0x8d68);
}

/* Bit Error Rate reduction fix */
static void
bge_phy_bit_err_fix(bge_t *bgep)
{
	bge_mii_put16(bgep, 0x18, 0x0c00);
	bge_mii_put16(bgep, 0x17, 0x000a);
	bge_mii_put16(bgep, 0x15, 0x310b);
	bge_mii_put16(bgep, 0x17, 0x201f);
	bge_mii_put16(bgep, 0x15, 0x9506);
	bge_mii_put16(bgep, 0x17, 0x401f);
	bge_mii_put16(bgep, 0x15, 0x14e2);
	bge_mii_put16(bgep, 0x18, 0x0400);
}

/*
 * End of Broadcom-derived workaround code
 */

static int
bge_restart_copper(bge_t *bgep, boolean_t powerdown)
{
	uint16_t phy_status;
	boolean_t reset_ok;
	uint16_t extctrl, auxctrl;
	int i;

	BGE_TRACE(("bge_restart_copper($%p, %d)", (void *)bgep, powerdown));

	ASSERT(mutex_owned(bgep->genlock));

	switch (MHCR_CHIP_ASIC_REV(bgep)) {
	default:
		/*
		 * Shouldn't happen; it means we don't recognise this chip.
		 * It's probably a new one, so we'll try our best anyway ...
		 */
	case MHCR_CHIP_ASIC_REV_5703:
	case MHCR_CHIP_ASIC_REV_5704:
	case MHCR_CHIP_ASIC_REV_5705:
	case MHCR_CHIP_ASIC_REV_5752:
	case MHCR_CHIP_ASIC_REV_5714:
	case MHCR_CHIP_ASIC_REV_5715:
		reset_ok = bge_phy_reset_and_check(bgep);
		break;

	case MHCR_CHIP_ASIC_REV_5906:
	case MHCR_CHIP_ASIC_REV_5700:
	case MHCR_CHIP_ASIC_REV_5701:
	case MHCR_CHIP_ASIC_REV_5723: /* 5717 and 5725 series as well */
	case MHCR_CHIP_ASIC_REV_5721_5751:
		/*
		 * Just a plain reset; the "check" code breaks these chips
		 */
		reset_ok = bge_phy_reset(bgep);
		if (!reset_ok)
			bge_fm_ereport(bgep, DDI_FM_DEVICE_NO_RESPONSE);
		break;
	}
	if (!reset_ok) {
		BGE_REPORT((bgep, "PHY failed to reset correctly"));
		return (DDI_FAILURE);
	}

	/*
	 * Step 5: disable WOL (not required after RESET)
	 *
	 * Step 6: refer to errata
	 */
	switch (bgep->chipid.asic_rev) {
	default:
		break;

	case MHCR_CHIP_REV_5704_A0:
		bge_phy_tweak_gmii(bgep);
		break;
	}

	switch (MHCR_CHIP_ASIC_REV(bgep)) {
	case MHCR_CHIP_ASIC_REV_5705:
	case MHCR_CHIP_ASIC_REV_5721_5751:
		bge_phy_bit_err_fix(bgep);
		break;
	}

	if (!(bgep->chipid.flags & CHIP_FLAG_NO_JUMBO) &&
	    (bgep->chipid.default_mtu > BGE_DEFAULT_MTU)) {
		/* Set the GMII Fifo Elasticity to high latency */
		extctrl = bge_mii_get16(bgep, 0x10);
		bge_mii_put16(bgep, 0x10, extctrl | 0x1);

		/* Allow reception of extended length packets */
		bge_mii_put16(bgep, MII_AUX_CONTROL, 0x0007);
		auxctrl = bge_mii_get16(bgep, MII_AUX_CONTROL);
		auxctrl |= 0x4000;
		bge_mii_put16(bgep, MII_AUX_CONTROL, auxctrl);
	}

	/*
	 * Step 7: read the MII_INTR_STATUS register twice,
	 * in order to clear any sticky bits (but they should
	 * have been cleared by the RESET, I think), and we're
	 * not using PHY interrupts anyway.
	 *
	 * Step 8: enable the PHY to interrupt on link status
	 * change (not required)
	 *
	 * Step 9: configure PHY LED Mode - not applicable?
	 *
	 * Step 10: read the MII_STATUS register twice, in
	 * order to clear any sticky bits (but they should
	 * have been cleared by the RESET, I think).
	 */
	for (i = 0; i < 100; i++) {
		drv_usecwait(40);
		phy_status = bge_mii_get16(bgep, MII_STATUS);
	}
	BGE_DEBUG(("bge_restart_copper: status 0x%x", phy_status));

	/*
	 * Finally, shut down the PHY, if required
	 */
	if (powerdown)
		bge_phy_powerdown(bgep);
	return (DDI_SUCCESS);
}

boolean_t
bge_eee_cap(bge_t * bgep)
{
	if (!(DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep))) {
		/* EEE is not supported on this chip */
		BGE_DEBUG(("bge_eee: eee not supported (device 0x%x)",
		    bgep->chipid.device));
		return (B_FALSE);
	}

	switch (CHIP_ASIC_REV_PROD_ID(bgep)) {
	case CHIP_ASIC_REV_5717_B0: /* = CHIP_ASIC_REV_5718_B0 */
	case CHIP_ASIC_REV_5717_C0:
	/* case CHIP_ASIC_REV_5718_B0: */
	case CHIP_ASIC_REV_5719_A0:
	case CHIP_ASIC_REV_5719_A1:
	case CHIP_ASIC_REV_5720_A0:
	case CHIP_ASIC_REV_5725_A0:
	case CHIP_ASIC_REV_5727_B0:
		return (B_TRUE);

	default:
		/* EEE is not supported on this asic rev */
		BGE_DEBUG(("bge_eee: eee not supported (asic rev 0x%08x)",
		    bgep->chipid.asic_rev));
		return (B_FALSE);
	}
}

void
bge_eee_init(bge_t * bgep)
{
	uint32_t val;

	BGE_TRACE(("bge_eee_init($%p)", (void *)bgep));

	ASSERT(mutex_owned(bgep->genlock));

	if (!bge_eee_cap(bgep)) {
		return;
	}

	/* Enable MAC control of LPI */

	val = (EEE_LINK_IDLE_PCIE_NL0 | EEE_LINK_IDLE_UART_IDL);
	if (DEVICE_5725_SERIES_CHIPSETS(bgep))
		val |= EEE_LINK_IDLE_APE_TX_MT;
	bge_reg_put32(bgep, EEE_LINK_IDLE_CONTROL_REG, val);

	bge_reg_put32(bgep, EEE_CONTROL_REG, EEE_CONTROL_EXIT_20_1_US);

	val = EEE_MODE_ERLY_L1_XIT_DET | EEE_MODE_LPI_IN_TX |
	    EEE_MODE_LPI_IN_RX | EEE_MODE_EEE_ENABLE;

	if (bgep->chipid.device != DEVICE_ID_5717)
		val |= EEE_MODE_SND_IDX_DET_EN;

	//val |= EEE_MODE_APE_TX_DET_EN;

	if (!bgep->chipid.eee) {
		val = 0;
	}

	bge_reg_put32(bgep, EEE_MODE_REG, val);

	/* Set EEE timer debounce values */

	bge_reg_put32(bgep, EEE_DEBOUNCE_T1_CONTROL_REG,
	    EEE_DEBOUNCE_T1_PCIEXIT_2047US | EEE_DEBOUNCE_T1_LNKIDLE_2047US);

	bge_reg_put32(bgep, EEE_DEBOUNCE_T2_CONTROL_REG,
	    EEE_DEBOUNCE_T2_APE_TX_2047US | EEE_DEBOUNCE_T2_TXIDXEQ_2047US);
}

void
bge_eee_autoneg(bge_t * bgep, boolean_t adv_100fdx, boolean_t adv_1000fdx)
{
	uint32_t val;
	uint16_t mii_val;

	BGE_TRACE(("bge_eee_autoneg($%p)", (void *)bgep));

	ASSERT(mutex_owned(bgep->genlock));

	if (!bge_eee_cap(bgep)) {
		return;
	}

	/* Disable LPI Requests */
	val = bge_reg_get32(bgep, EEE_MODE_REG);
	val &= ~EEE_MODE_LPI_ENABLE;
	bge_reg_put32(bgep, EEE_MODE_REG, val);

	bge_phy_toggle_auxctl_smdsp(bgep, B_TRUE);

	mii_val = 0;

	if (bgep->chipid.eee) {
		if (adv_100fdx) {
			mii_val |= EEE_CL45_D7_RESULT_STAT_LP_100TX;
		}
		if (adv_1000fdx) {
			mii_val |= EEE_CL45_D7_RESULT_STAT_LP_1000T;
		}
	}

	/* Enable EEE advertisement for the specified mode(s)... */
	bge_mii_put16(bgep, MII_MMD_CTRL, MDIO_MMD_AN);
	bge_mii_put16(bgep, MII_MMD_ADDRESS_DATA, MDIO_AN_EEE_ADV);
	bge_mii_put16(bgep, MII_MMD_CTRL,
	    MII_MMD_CTRL_DATA_NOINC | MDIO_MMD_AN);
	bge_mii_put16(bgep, MII_MMD_ADDRESS_DATA, mii_val);

	/* Setup PHY DSP for EEE */
	switch (bgep->chipid.device) {
	case DEVICE_ID_5717:
	case DEVICE_ID_5718:
	case DEVICE_ID_5719:
		/* If we advertised any EEE advertisements above... */
		if (mii_val) {
			mii_val = (MII_DSP_TAP26_ALNOKO |
			    MII_DSP_TAP26_RMRXSTO |
			    MII_DSP_TAP26_OPCSINPT);
		}
		bge_phydsp_write(bgep, MII_DSP_TAP26, mii_val);
		/* fall through */
	case DEVICE_ID_5720:
	case DEVICE_ID_5725:
	case DEVICE_ID_5727:
		mii_val = bge_phydsp_read(bgep, MII_DSP_CH34TP2);
		bge_phydsp_write(bgep, MII_DSP_CH34TP2,
		    (mii_val | MII_DSP_CH34TP2_HIBW01));
	}

	bge_phy_toggle_auxctl_smdsp(bgep, B_FALSE);
}

void
bge_eee_adjust(bge_t * bgep)
{
	uint32_t val;
	uint16_t mii_val;

	BGE_TRACE(("bge_eee_adjust($%p, %d)", (void *)bgep));

	ASSERT(mutex_owned(bgep->genlock));

	if (!bge_eee_cap(bgep)) {
		return;
	}

	bgep->eee_lpi_wait = 0;

	/* Check for PHY link status */
	if (bgep->param_link_up) {
		BGE_DEBUG(("bge_eee_adjust: link status up"));

		/*
		 * XXX if duplex full and speed is 1000 or 100 then do the
		 * following...
		 */

		if (bgep->param_link_speed == 1000) {
			BGE_DEBUG(("bge_eee_adjust: eee timing for 1000Mb"));
			bge_reg_put32(bgep, EEE_CONTROL_REG,
			    EEE_CONTROL_EXIT_16_5_US);
		} else if (bgep->param_link_speed == 100) {
			BGE_DEBUG(("bge_eee_adjust: eee timing for 100Mb"));
			bge_reg_put32(bgep, EEE_CONTROL_REG,
			    EEE_CONTROL_EXIT_36_US);
		}

		/* Read PHY's EEE negotiation status */
		bge_mii_put16(bgep, MII_MMD_CTRL, MDIO_MMD_AN);
		bge_mii_put16(bgep, MII_MMD_ADDRESS_DATA,
		    EEE_CL45_D7_RESULT_STAT);
		bge_mii_put16(bgep, MII_MMD_CTRL,
		    MII_MMD_CTRL_DATA_NOINC | MDIO_MMD_AN);
		mii_val = bge_mii_get16(bgep, MII_MMD_ADDRESS_DATA);

		/* Enable EEE LPI request if EEE negotiated */
		if ((mii_val == EEE_CL45_D7_RESULT_STAT_LP_1000T) ||
		    (mii_val == EEE_CL45_D7_RESULT_STAT_LP_100TX)) {
			BGE_DEBUG(("bge_eee_adjust: eee negotiaton success, lpi scheduled"));
			bgep->eee_lpi_wait = 2;
		} else {
			BGE_DEBUG(("bge_eee_adjust: eee negotiation failed"));
		}
	} else {
		BGE_DEBUG(("bge_eee_adjust: link status down"));
	}

	if (!bgep->eee_lpi_wait) {
		if (bgep->param_link_up) {
			bge_phy_toggle_auxctl_smdsp(bgep, B_TRUE);
			bge_phydsp_write(bgep, MII_DSP_TAP26, 0);
			bge_phy_toggle_auxctl_smdsp(bgep, B_FALSE);
		}

		/* Disable LPI requests */
		val = bge_reg_get32(bgep, EEE_MODE_REG);
		val &= ~EEE_MODE_LPI_ENABLE;
		bge_reg_put32(bgep, EEE_MODE_REG, val);
	}
}

void
bge_eee_enable(bge_t * bgep)
{
	uint32_t val;

	/* XXX check for EEE for 5717 family... */

	if (bgep->param_link_speed == 1000) {
		bge_phy_toggle_auxctl_smdsp(bgep, B_TRUE);
		bge_phydsp_write(bgep, MII_DSP_TAP26,
		    MII_DSP_TAP26_ALNOKO | MII_DSP_TAP26_RMRXSTO);
		bge_phy_toggle_auxctl_smdsp(bgep, B_FALSE);
	}

	val = bge_reg_get32(bgep, EEE_MODE_REG);
	val |= EEE_MODE_LPI_ENABLE;
	bge_reg_put32(bgep, EEE_MODE_REG, val);
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
static int
bge_update_copper(bge_t *bgep)
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
	uint16_t auxctrl;
	uint16_t anar;

	BGE_TRACE(("bge_update_copper($%p)", (void *)bgep));

	ASSERT(mutex_owned(bgep->genlock));

	BGE_DEBUG(("bge_update_copper: autoneg %d "
	    "pause %d asym_pause %d "
	    "1000fdx %d 1000hdx %d "
	    "100fdx %d 100hdx %d "
	    "10fdx %d 10hdx %d ",
	    bgep->param_adv_autoneg,
	    bgep->param_adv_pause, bgep->param_adv_asym_pause,
	    bgep->param_adv_1000fdx, bgep->param_adv_1000hdx,
	    bgep->param_adv_100fdx, bgep->param_adv_100hdx,
	    bgep->param_adv_10fdx, bgep->param_adv_10hdx));

	control = gigctrl = auxctrl = anar = 0;

	/*
	 * PHY settings are normally based on the param_* variables,
	 * but if any loopback mode is in effect, that takes precedence.
	 *
	 * BGE supports MAC-internal loopback, PHY-internal loopback,
	 * and External loopback at a variety of speeds (with a special
	 * cable).  In all cases, autoneg is turned OFF, full-duplex
	 * is turned ON, and the speed/mastership is forced.
	 */
	switch (bgep->param_loop_mode) {
	case BGE_LOOP_NONE:
	default:
		adv_autoneg = bgep->param_adv_autoneg;
		adv_pause = bgep->param_adv_pause;
		adv_asym_pause = bgep->param_adv_asym_pause;
		adv_1000fdx = bgep->param_adv_1000fdx;
		adv_1000hdx = bgep->param_adv_1000hdx;
		adv_100fdx = bgep->param_adv_100fdx;
		adv_100hdx = bgep->param_adv_100hdx;
		adv_10fdx = bgep->param_adv_10fdx;
		adv_10hdx = bgep->param_adv_10hdx;
		break;

	case BGE_LOOP_EXTERNAL_1000:
	case BGE_LOOP_EXTERNAL_100:
	case BGE_LOOP_EXTERNAL_10:
	case BGE_LOOP_INTERNAL_PHY:
	case BGE_LOOP_INTERNAL_MAC:
		adv_autoneg = adv_pause = adv_asym_pause = B_FALSE;
		adv_1000fdx = adv_100fdx = adv_10fdx = B_FALSE;
		adv_1000hdx = adv_100hdx = adv_10hdx = B_FALSE;
		bgep->param_link_duplex = LINK_DUPLEX_FULL;

		switch (bgep->param_loop_mode) {
		case BGE_LOOP_EXTERNAL_1000:
			bgep->param_link_speed = 1000;
			adv_1000fdx = B_TRUE;
			auxctrl = MII_AUX_CTRL_NORM_EXT_LOOPBACK;
			gigctrl |= MII_MSCONTROL_MANUAL;
			gigctrl |= MII_MSCONTROL_MASTER;
			break;

		case BGE_LOOP_EXTERNAL_100:
			bgep->param_link_speed = 100;
			adv_100fdx = B_TRUE;
			auxctrl = MII_AUX_CTRL_NORM_EXT_LOOPBACK;
			break;

		case BGE_LOOP_EXTERNAL_10:
			bgep->param_link_speed = 10;
			adv_10fdx = B_TRUE;
			auxctrl = MII_AUX_CTRL_NORM_EXT_LOOPBACK;
			break;

		case BGE_LOOP_INTERNAL_PHY:
			bgep->param_link_speed = 1000;
			adv_1000fdx = B_TRUE;
			control = MII_CONTROL_LOOPBACK;
			break;

		case BGE_LOOP_INTERNAL_MAC:
			bgep->param_link_speed = 1000;
			adv_1000fdx = B_TRUE;
			break;
		}
	}

	BGE_DEBUG(("bge_update_copper: autoneg %d "
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
	    !adv_1000hdx && !adv_100hdx && !adv_10hdx)
		adv_1000fdx = B_TRUE;

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

	if (adv_1000fdx)
		gigctrl |= MII_MSCONTROL_1000T_FD;
	if (adv_1000hdx)
		gigctrl |= MII_MSCONTROL_1000T;

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
	auxctrl |= MII_AUX_CTRL_NORM_TX_MODE;
	auxctrl |= MII_AUX_CTRL_NORMAL;

	/*
	 * Restart the PHY and write the new values.  Note the
	 * time, so that we can say whether subsequent link state
	 * changes can be attributed to our reprogramming the PHY
	 */
	if ((*bgep->physops->phys_restart)(bgep, B_FALSE) == DDI_FAILURE)
		return (DDI_FAILURE);
	bge_mii_put16(bgep, MII_AN_ADVERT, anar);
	if (auxctrl & MII_AUX_CTRL_NORM_EXT_LOOPBACK)
		bge_mii_put16(bgep, MII_AUX_CONTROL, auxctrl);
	bge_mii_put16(bgep, MII_MSCONTROL, gigctrl);
	bge_mii_put16(bgep, MII_CONTROL, control);

	BGE_DEBUG(("bge_update_copper: anar <- 0x%x", anar));
	BGE_DEBUG(("bge_update_copper: auxctrl <- 0x%x", auxctrl));
	BGE_DEBUG(("bge_update_copper: gigctrl <- 0x%x", gigctrl));
	BGE_DEBUG(("bge_update_copper: control <- 0x%x", control));

#if	BGE_COPPER_WIRESPEED
	/*
	 * Enable the 'wire-speed' feature, if the chip supports it
	 * and we haven't got (any) loopback mode selected.
	 */
	switch (bgep->chipid.device) {
	case DEVICE_ID_5700:
	case DEVICE_ID_5700x:
	case DEVICE_ID_5705C:
	case DEVICE_ID_5782:
		/*
		 * These chips are known or assumed not to support it
		 */
		break;

	default:
		/*
		 * All other Broadcom chips are expected to support it.
		 */
		if (bgep->param_loop_mode == BGE_LOOP_NONE)
			bge_mii_put16(bgep, MII_AUX_CONTROL,
			    MII_AUX_CTRL_MISC_WRITE_ENABLE |
			    MII_AUX_CTRL_MISC_WIRE_SPEED |
			    MII_AUX_CTRL_MISC);
		break;
	}
#endif	/* BGE_COPPER_WIRESPEED */

	/* enable EEE on those chips that support it */
	bge_eee_autoneg(bgep, adv_100fdx, adv_1000fdx);

	return (DDI_SUCCESS);
}

static boolean_t
bge_check_copper(bge_t *bgep, boolean_t recheck)
{
	uint32_t emac_status;
	uint16_t mii_status;
	uint16_t aux;
	uint_t mode;
	boolean_t linkup;
	int i;

	/*
	 * Step 10: read the status from the PHY (which is self-clearing
	 * on read!); also read & clear the main (Ethernet) MAC status
	 * (the relevant bits of this are write-one-to-clear).
	 */
	for (i = 0; i < 100; i++) {
		drv_usecwait(40);
		mii_status = bge_mii_get16(bgep, MII_STATUS);
	}
	emac_status = bge_reg_get32(bgep, ETHERNET_MAC_STATUS_REG);
	bge_reg_put32(bgep, ETHERNET_MAC_STATUS_REG, emac_status);

	BGE_DEBUG(("bge_check_copper: link %d/%s, MII status 0x%x "
	    "(was 0x%x), Ethernet MAC status 0x%x",
	    bgep->link_state, UPORDOWN(bgep->param_link_up), mii_status,
	    bgep->phy_gen_status, emac_status));

	/*
	 * If the PHY status hasn't changed since last we looked, and
	 * we not forcing a recheck (i.e. the link state was already
	 * known), there's nothing to do.
	 */
	if (mii_status == bgep->phy_gen_status && !recheck) {
		BGE_DEBUG(("bge_check_copper: no link change"));
		return (B_FALSE);
	}

	do {
		/*
		 * Step 11: read AUX STATUS register to find speed/duplex
		 */
		for (i = 0; i < 2000; i++) {
			drv_usecwait(10);
			aux = bge_mii_get16(bgep, MII_AUX_STATUS);
		}
		BGE_CDB(bge_phydump, (bgep, mii_status, aux));

		/*
		 * We will only consider the link UP if all the readings
		 * are consistent and give meaningful results ...
		 */
		mode = aux & MII_AUX_STATUS_MODE_MASK;
		mode >>= MII_AUX_STATUS_MODE_SHIFT;
		if (DEVICE_5906_SERIES_CHIPSETS(bgep)) {
			linkup = BIS(aux, MII_AUX_STATUS_LINKUP);
			linkup &= BIS(mii_status, MII_STATUS_LINKUP);
		} else {
			linkup = bge_copper_link_speed[mode] > 0;
			linkup &= bge_copper_link_duplex[mode] !=
			    LINK_DUPLEX_UNKNOWN;
			linkup &= BIS(aux, MII_AUX_STATUS_LINKUP);
			linkup &= BIS(mii_status, MII_STATUS_LINKUP);
		}

		BGE_DEBUG(("bge_check_copper: MII status 0x%x aux 0x%x "
		    "=> mode %d (%s)",
		    mii_status, aux,
		    mode, UPORDOWN(linkup)));

		/*
		 * Record current register values, then reread status
		 * register & loop until it stabilises ...
		 */
		bgep->phy_aux_status = aux;
		bgep->phy_gen_status = mii_status;

		for (i = 0; i < 100; i++)
		{
			drv_usecwait(40);
			mii_status = bge_mii_get16(bgep, MII_STATUS);
		}
	} while (mii_status != bgep->phy_gen_status);

	/*
	 * Assume very little ...
	 */
	bgep->param_lp_autoneg = B_FALSE;
	bgep->param_lp_1000fdx = B_FALSE;
	bgep->param_lp_1000hdx = B_FALSE;
	bgep->param_lp_100fdx = B_FALSE;
	bgep->param_lp_100hdx = B_FALSE;
	bgep->param_lp_10fdx = B_FALSE;
	bgep->param_lp_10hdx = B_FALSE;
	bgep->param_lp_pause = B_FALSE;
	bgep->param_lp_asym_pause = B_FALSE;
	bgep->param_link_autoneg = B_FALSE;
	bgep->param_link_tx_pause = B_FALSE;
	if (bgep->param_adv_autoneg)
		bgep->param_link_rx_pause = B_FALSE;
	else
		bgep->param_link_rx_pause = bgep->param_adv_pause;

	/*
	 * Discover all the link partner's abilities.
	 * These are scattered through various registers ...
	 */
	if (BIS(aux, MII_AUX_STATUS_LP_ANEG_ABLE)) {
		bgep->param_lp_autoneg = B_TRUE;
		bgep->param_link_autoneg = B_TRUE;
		bgep->param_link_tx_pause = BIS(aux, MII_AUX_STATUS_TX_PAUSE);
		bgep->param_link_rx_pause = BIS(aux, MII_AUX_STATUS_RX_PAUSE);

		aux = bge_mii_get16(bgep, MII_MSSTATUS);
		bgep->param_lp_1000fdx = BIS(aux, MII_MSSTATUS_LP1000T_FD);
		bgep->param_lp_1000hdx = BIS(aux, MII_MSSTATUS_LP1000T);

		aux = bge_mii_get16(bgep, MII_AN_LPABLE);
		bgep->param_lp_100fdx = BIS(aux, MII_ABILITY_100BASE_TX_FD);
		bgep->param_lp_100hdx = BIS(aux, MII_ABILITY_100BASE_TX);
		bgep->param_lp_10fdx = BIS(aux, MII_ABILITY_10BASE_T_FD);
		bgep->param_lp_10hdx = BIS(aux, MII_ABILITY_10BASE_T);
		bgep->param_lp_pause = BIS(aux, MII_ABILITY_PAUSE);
		bgep->param_lp_asym_pause = BIS(aux, MII_ABILITY_ASMPAUSE);
	}

	/*
	 * Step 12: update ndd-visible state parameters, BUT!
	 * we don't transfer the new state to <link_state> just yet;
	 * instead we mark the <link_state> as UNKNOWN, and our caller
	 * will resolve it once the status has stopped changing and
	 * been stable for several seconds.
	 */
	BGE_DEBUG(("bge_check_copper: link was %s speed %d duplex %d",
	    UPORDOWN(bgep->param_link_up),
	    bgep->param_link_speed,
	    bgep->param_link_duplex));

	if (!linkup)
		mode = MII_AUX_STATUS_MODE_NONE;
	bgep->param_link_up = linkup;
	bgep->link_state = LINK_STATE_UNKNOWN;
	if (DEVICE_5906_SERIES_CHIPSETS(bgep)) {
		if (bgep->phy_aux_status & MII_AUX_STATUS_NEG_ENABLED_5906) {
			bgep->param_link_speed =
			    bge_copper_link_speed_5906[mode];
			bgep->param_link_duplex =
			    bge_copper_link_duplex_5906[mode];
		} else {
			bgep->param_link_speed = (bgep->phy_aux_status &
			    MII_AUX_STATUS_SPEED_IND_5906) ?  100 : 10;
			bgep->param_link_duplex = (bgep->phy_aux_status &
			    MII_AUX_STATUS_DUPLEX_IND_5906) ? LINK_DUPLEX_FULL :
			    LINK_DUPLEX_HALF;
		}
	} else {
		bgep->param_link_speed = bge_copper_link_speed[mode];
		bgep->param_link_duplex = bge_copper_link_duplex[mode];
	}

	bge_eee_adjust(bgep);

	bge_log(bgep, "bge_check_copper: link now %s speed %d duplex %d",
	        UPORDOWN(bgep->param_link_up),
	        bgep->param_link_speed,
	        bgep->param_link_duplex);

	return (B_TRUE);
}

static const phys_ops_t copper_ops = {
	bge_restart_copper,
	bge_update_copper,
	bge_check_copper
};


/*
 * ========== SerDes support ==========
 */

#undef	BGE_DBG
#define	BGE_DBG		BGE_DBG_SERDES	/* debug flag for this code	*/

/*
 * Reinitialise the SerDes interface.  Note that it normally powers
 * up in the disabled state, so we need to explicitly activate it.
 */
static int
bge_restart_serdes(bge_t *bgep, boolean_t powerdown)
{
	uint32_t macmode;

	BGE_TRACE(("bge_restart_serdes($%p, %d)", (void *)bgep, powerdown));

	ASSERT(mutex_owned(bgep->genlock));

	/*
	 * Ensure that the main Ethernet MAC mode register is programmed
	 * appropriately for the SerDes interface ...
	 */
	macmode = bge_reg_get32(bgep, ETHERNET_MAC_MODE_REG);
	macmode &= ~ETHERNET_MODE_LINK_POLARITY;
	macmode &= ~ETHERNET_MODE_PORTMODE_MASK;
	if (DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5714_SERIES_CHIPSETS(bgep)) {
		macmode |= ETHERNET_MODE_PORTMODE_GMII;
	} else {
		macmode |= ETHERNET_MODE_PORTMODE_TBI;
	}
	bge_reg_put32(bgep, ETHERNET_MAC_MODE_REG, macmode);

	/*
	 * Ensure that loopback is OFF and comma detection is enabled.  Then
	 * disable the SerDes output (the first time through, it may/will
	 * already be disabled).  If we're shutting down, leave it disabled.
	 */
	bge_reg_clr32(bgep, SERDES_CONTROL_REG, SERDES_CONTROL_TBI_LOOPBACK);
	bge_reg_set32(bgep, SERDES_CONTROL_REG, SERDES_CONTROL_COMMA_DETECT);
	bge_reg_set32(bgep, SERDES_CONTROL_REG, SERDES_CONTROL_TX_DISABLE);
	if (powerdown)
		return (DDI_SUCCESS);

	/*
	 * Otherwise, pause, (re-)enable the SerDes output, and send
	 * all-zero config words in order to force autoneg restart.
	 * Invalidate the saved "link partners received configs", as
	 * we're starting over ...
	 */
	drv_usecwait(10000);
	bge_reg_clr32(bgep, SERDES_CONTROL_REG, SERDES_CONTROL_TX_DISABLE);
	bge_reg_put32(bgep, TX_1000BASEX_AUTONEG_REG, 0);
	bge_reg_set32(bgep, ETHERNET_MAC_MODE_REG, ETHERNET_MODE_SEND_CFGS);
	drv_usecwait(10);
	bge_reg_clr32(bgep, ETHERNET_MAC_MODE_REG, ETHERNET_MODE_SEND_CFGS);
	bgep->serdes_lpadv = AUTONEG_CODE_FAULT_ANEG_ERR;
	bgep->serdes_status = ~0U;
	return (DDI_SUCCESS);
}

/*
 * Synchronise the SerDes speed/duplex/autonegotiation capabilities and
 * advertisements with the required settings as specified by the various
 * param_* variables that can be poked via the NDD interface.
 *
 * We always reinitalise the SerDes; this should cause the link to go down,
 * and then back up again once the link is stable and autonegotiation
 * (if enabled) is complete.  We should get a link state change interrupt
 * somewhere along the way ...
 *
 * NOTE: SerDes only supports 1000FDX/HDX (with or without pause) so the
 * param_* variables relating to lower speeds are ignored.
 *
 * NOTE: <genlock> must already be held by the caller
 */
static int
bge_update_serdes(bge_t *bgep)
{
	boolean_t adv_autoneg;
	boolean_t adv_pause;
	boolean_t adv_asym_pause;
	boolean_t adv_1000fdx;
	boolean_t adv_1000hdx;

	uint32_t serdes;
	uint32_t advert;

	BGE_TRACE(("bge_update_serdes($%p)", (void *)bgep));

	ASSERT(mutex_owned(bgep->genlock));

	BGE_DEBUG(("bge_update_serdes: autoneg %d "
	    "pause %d asym_pause %d "
	    "1000fdx %d 1000hdx %d "
	    "100fdx %d 100hdx %d "
	    "10fdx %d 10hdx %d ",
	    bgep->param_adv_autoneg,
	    bgep->param_adv_pause, bgep->param_adv_asym_pause,
	    bgep->param_adv_1000fdx, bgep->param_adv_1000hdx,
	    bgep->param_adv_100fdx, bgep->param_adv_100hdx,
	    bgep->param_adv_10fdx, bgep->param_adv_10hdx));

	serdes = advert = 0;

	/*
	 * SerDes settings are normally based on the param_* variables,
	 * but if any loopback mode is in effect, that takes precedence.
	 *
	 * BGE supports MAC-internal loopback, PHY-internal loopback,
	 * and External loopback at a variety of speeds (with a special
	 * cable).  In all cases, autoneg is turned OFF, full-duplex
	 * is turned ON, and the speed/mastership is forced.
	 *
	 * Note: for the SerDes interface, "PHY" internal loopback is
	 * interpreted as SerDes internal loopback, and all external
	 * loopback modes are treated equivalently, as 1Gb/external.
	 */
	switch (bgep->param_loop_mode) {
	case BGE_LOOP_NONE:
	default:
		adv_autoneg = bgep->param_adv_autoneg;
		adv_pause = bgep->param_adv_pause;
		adv_asym_pause = bgep->param_adv_asym_pause;
		adv_1000fdx = bgep->param_adv_1000fdx;
		adv_1000hdx = bgep->param_adv_1000hdx;
		break;

	case BGE_LOOP_INTERNAL_PHY:
		serdes |= SERDES_CONTROL_TBI_LOOPBACK;
		/* FALLTHRU */
	case BGE_LOOP_INTERNAL_MAC:
	case BGE_LOOP_EXTERNAL_1000:
	case BGE_LOOP_EXTERNAL_100:
	case BGE_LOOP_EXTERNAL_10:
		adv_autoneg = adv_pause = adv_asym_pause = B_FALSE;
		adv_1000fdx = B_TRUE;
		adv_1000hdx = B_FALSE;
		break;
	}

	BGE_DEBUG(("bge_update_serdes: autoneg %d "
	    "pause %d asym_pause %d "
	    "1000fdx %d 1000hdx %d ",
	    adv_autoneg,
	    adv_pause, adv_asym_pause,
	    adv_1000fdx, adv_1000hdx));

	/*
	 * We should have at least one gigabit technology capability
	 * set; if not, we select a default of 1000Mb/s full-duplex
	 */
	if (!adv_1000fdx && !adv_1000hdx)
		adv_1000fdx = B_TRUE;

	/*
	 * Now transform the adv_* variables into the proper settings
	 * of the SerDes registers ...
	 *
	 * If autonegotiation is (now) not enabled, pretend it's been
	 * done and failed ...
	 */
	if (!adv_autoneg)
		advert |= AUTONEG_CODE_FAULT_ANEG_ERR;

	if (adv_1000fdx) {
		advert |= AUTONEG_CODE_FULL_DUPLEX;
		bgep->param_adv_1000fdx = adv_1000fdx;
		bgep->param_link_duplex = LINK_DUPLEX_FULL;
		bgep->param_link_speed = 1000;
	}
	if (adv_1000hdx) {
		advert |= AUTONEG_CODE_HALF_DUPLEX;
		bgep->param_adv_1000hdx = adv_1000hdx;
		bgep->param_link_duplex = LINK_DUPLEX_HALF;
		bgep->param_link_speed = 1000;
	}

	if (adv_pause)
		advert |= AUTONEG_CODE_PAUSE;
	if (adv_asym_pause)
		advert |= AUTONEG_CODE_ASYM_PAUSE;

	/*
	 * Restart the SerDes and write the new values.  Note the
	 * time, so that we can say whether subsequent link state
	 * changes can be attributed to our reprogramming the SerDes
	 */
	bgep->serdes_advert = advert;
	(void) bge_restart_serdes(bgep, B_FALSE);
	bge_reg_set32(bgep, SERDES_CONTROL_REG, serdes);

	BGE_DEBUG(("bge_update_serdes: serdes |= 0x%x, advert 0x%x",
	    serdes, advert));
	return (DDI_SUCCESS);
}

/*
 * Bare-minimum autoneg protocol
 *
 * This code is only called when the link is up and we're receiving config
 * words, which implies that the link partner wants to autonegotiate
 * (otherwise, we wouldn't see configs and wouldn't reach this code).
 */
static void
bge_autoneg_serdes(bge_t *bgep)
{
	boolean_t ack;

	bgep->serdes_lpadv = bge_reg_get32(bgep, RX_1000BASEX_AUTONEG_REG);
	ack = BIS(bgep->serdes_lpadv, AUTONEG_CODE_ACKNOWLEDGE);

	if (!ack) {
		/*
		 * Phase 1: after SerDes reset, we send a few zero configs
		 * but then stop.  Here the partner is sending configs, but
		 * not ACKing ours; we assume that's 'cos we're not sending
		 * any.  So here we send ours, with ACK already set.
		 */
		bge_reg_put32(bgep, TX_1000BASEX_AUTONEG_REG,
		    bgep->serdes_advert | AUTONEG_CODE_ACKNOWLEDGE);
		bge_reg_set32(bgep, ETHERNET_MAC_MODE_REG,
		    ETHERNET_MODE_SEND_CFGS);
	} else {
		/*
		 * Phase 2: partner has ACKed our configs, so now we can
		 * stop sending; once our partner also stops sending, we
		 * can resolve the Tx/Rx configs.
		 */
		bge_reg_clr32(bgep, ETHERNET_MAC_MODE_REG,
		    ETHERNET_MODE_SEND_CFGS);
	}

	BGE_DEBUG(("bge_autoneg_serdes: Rx 0x%x %s Tx 0x%x",
	    bgep->serdes_lpadv,
	    ack ? "stop" : "send",
	    bgep->serdes_advert));
}

static boolean_t
bge_check_serdes(bge_t *bgep, boolean_t recheck)
{
	uint32_t emac_status;
	uint32_t tx_status;
	uint32_t lpadv;
	boolean_t linkup;
	boolean_t linkup_old = bgep->param_link_up;

	for (;;) {
		/*
		 * Step 10: BCM5714S, BCM5715S only
		 * Don't call function bge_autoneg_serdes() as
		 * RX_1000BASEX_AUTONEG_REG (0x0448) is not applicable
		 * to BCM5705, BCM5788, BCM5721, BCM5751, BCM5752,
		 * BCM5714, and BCM5715 devices.
		 */
		if (DEVICE_5717_SERIES_CHIPSETS(bgep) ||
		    DEVICE_5725_SERIES_CHIPSETS(bgep) ||
		    DEVICE_5714_SERIES_CHIPSETS(bgep)) {
			tx_status = bge_reg_get32(bgep,
			    TRANSMIT_MAC_STATUS_REG);
			linkup = BIS(tx_status, TRANSMIT_STATUS_LINK_UP);
			emac_status = bge_reg_get32(bgep,
			    ETHERNET_MAC_STATUS_REG);
			bgep->serdes_status = emac_status;
			/* clear write-one-to-clear bits in MAC status */
			if ((emac_status & ETHERNET_STATUS_MI_COMPLETE) &&
			    (DEVICE_5717_SERIES_CHIPSETS(bgep) ||
			     DEVICE_5725_SERIES_CHIPSETS(bgep))) {
				emac_status |= ETHERNET_STATUS_SYNC_CHANGED |
				    ETHERNET_STATUS_CFG_CHANGED;
			}
			bge_reg_put32(bgep,
			    ETHERNET_MAC_STATUS_REG, emac_status);
			/*
			 * If the link status has not changed then then
			 * break. If it has loop around and recheck again.
			 * Keep looping until the link status has not
			 * changed.
			 */
			if ((linkup && linkup_old) ||
			    (!linkup && !linkup_old)) {
				break;
			}
			if (linkup)
				linkup_old = B_TRUE;
			else
				linkup_old = B_FALSE;
			recheck = B_TRUE;
		} else {
			/*
			 * Step 10: others
			 * read & clear the main (Ethernet) MAC status
			 * (the relevant bits of this are write-one-to-clear).
			 */
			emac_status = bge_reg_get32(bgep,
			    ETHERNET_MAC_STATUS_REG);
			bge_reg_put32(bgep,
			    ETHERNET_MAC_STATUS_REG, emac_status);

			BGE_DEBUG(("bge_check_serdes: link %d/%s, "
			    "MAC status 0x%x (was 0x%x)",
			    bgep->link_state, UPORDOWN(bgep->param_link_up),
			    emac_status, bgep->serdes_status));

			/*
			 * We will only consider the link UP if all the readings
			 * are consistent and give meaningful results ...
			 */
			bgep->serdes_status = emac_status;
			linkup = BIS(emac_status,
			    ETHERNET_STATUS_SIGNAL_DETECT);
			linkup &= BIS(emac_status, ETHERNET_STATUS_PCS_SYNCHED);

			/*
			 * Now some fiddling with the interpretation:
			 *	if there's been an error at the PCS level, treat
			 *	it as a link change (the h/w doesn't do this)
			 *
			 *	if there's been a change, but it's only a PCS
			 *	sync change (not a config change), AND the link
			 *	already was & is still UP, then ignore the
			 *	change
			 */
			if (BIS(emac_status, ETHERNET_STATUS_PCS_ERROR))
				emac_status |= ETHERNET_STATUS_LINK_CHANGED;
			else if (BIC(emac_status, ETHERNET_STATUS_CFG_CHANGED))
				if (bgep->param_link_up && linkup)
					emac_status &=
					    ~ETHERNET_STATUS_LINK_CHANGED;

			BGE_DEBUG(("bge_check_serdes: status 0x%x => 0x%x %s",
			    bgep->serdes_status, emac_status,
			    UPORDOWN(linkup)));

			/*
			 * If we're receiving configs, run the autoneg protocol
			 */
			if (linkup && BIS(emac_status,
			    ETHERNET_STATUS_RECEIVING_CFG))
				bge_autoneg_serdes(bgep);

			/*
			 * If the SerDes status hasn't changed, we're done ...
			 */
			if (BIC(emac_status, ETHERNET_STATUS_LINK_CHANGED))
				break;

			/*
			 * Go round again until we no longer see a change ...
			 */
			recheck = B_TRUE;
		}
	}

	/*
	 * If we're not forcing a recheck (i.e. the link state was already
	 * known), and we didn't see the hardware flag a change, there's
	 * no more to do (and we tell the caller nothing happened).
	 */
	if (!recheck)
		return (B_FALSE);

	/*
	 * Don't resolve autoneg until we're no longer receiving configs
	 */
	if (linkup && BIS(emac_status, ETHERNET_STATUS_RECEIVING_CFG))
		return (B_FALSE);

	/*
	 * Assume very little ...
	 */
	bgep->param_lp_autoneg = B_FALSE;
	bgep->param_lp_1000fdx = B_FALSE;
	bgep->param_lp_1000hdx = B_FALSE;
	bgep->param_lp_100fdx = B_FALSE;
	bgep->param_lp_100hdx = B_FALSE;
	bgep->param_lp_10fdx = B_FALSE;
	bgep->param_lp_10hdx = B_FALSE;
	bgep->param_lp_pause = B_FALSE;
	bgep->param_lp_asym_pause = B_FALSE;
	bgep->param_link_autoneg = B_FALSE;
	bgep->param_link_tx_pause = B_FALSE;
	if (bgep->param_adv_autoneg)
		bgep->param_link_rx_pause = B_FALSE;
	else
		bgep->param_link_rx_pause = bgep->param_adv_pause;

	/*
	 * Discover all the link partner's abilities.
	 */
	lpadv = bgep->serdes_lpadv;
	if (lpadv != 0 && BIC(lpadv, AUTONEG_CODE_FAULT_MASK)) {
		/*
		 * No fault, so derive partner's capabilities
		 */
		bgep->param_lp_autoneg = B_TRUE;
		bgep->param_lp_1000fdx = BIS(lpadv, AUTONEG_CODE_FULL_DUPLEX);
		bgep->param_lp_1000hdx = BIS(lpadv, AUTONEG_CODE_HALF_DUPLEX);
		bgep->param_lp_pause = BIS(lpadv, AUTONEG_CODE_PAUSE);
		bgep->param_lp_asym_pause = BIS(lpadv, AUTONEG_CODE_ASYM_PAUSE);

		/*
		 * Pause direction resolution
		 */
		bgep->param_link_autoneg = B_TRUE;
		if (bgep->param_adv_pause &&
		    bgep->param_lp_pause) {
			bgep->param_link_tx_pause = B_TRUE;
			bgep->param_link_rx_pause = B_TRUE;
		}
		if (bgep->param_adv_asym_pause &&
		    bgep->param_lp_asym_pause) {
			if (bgep->param_adv_pause)
				bgep->param_link_rx_pause = B_TRUE;
			if (bgep->param_lp_pause)
				bgep->param_link_tx_pause = B_TRUE;
		}
	}

	/*
	 * Step 12: update ndd-visible state parameters, BUT!
	 * we don't transfer the new state to <link_state> just yet;
	 * instead we mark the <link_state> as UNKNOWN, and our caller
	 * will resolve it once the status has stopped changing and
	 * been stable for several seconds.
	 */
	BGE_DEBUG(("bge_check_serdes: link was %s speed %d duplex %d",
	    UPORDOWN(bgep->param_link_up),
	    bgep->param_link_speed,
	    bgep->param_link_duplex));

	if (linkup) {
		bgep->param_link_up = B_TRUE;
		bgep->param_link_speed = 1000;
		if (bgep->param_adv_1000fdx)
			bgep->param_link_duplex = LINK_DUPLEX_FULL;
		else
			bgep->param_link_duplex = LINK_DUPLEX_HALF;
		if (bgep->param_lp_autoneg && !bgep->param_lp_1000fdx)
			bgep->param_link_duplex = LINK_DUPLEX_HALF;
	} else {
		bgep->param_link_up = B_FALSE;
		bgep->param_link_speed = 0;
		bgep->param_link_duplex = LINK_DUPLEX_UNKNOWN;
	}
	bgep->link_state = LINK_STATE_UNKNOWN;

	bge_log(bgep, "bge_check_serdes: link now %s speed %d duplex %d",
	        UPORDOWN(bgep->param_link_up),
	        bgep->param_link_speed,
	        bgep->param_link_duplex);

	return (B_TRUE);
}

static const phys_ops_t serdes_ops = {
	bge_restart_serdes,
	bge_update_serdes,
	bge_check_serdes
};

/*
 * ========== Exported physical layer control routines ==========
 */

#undef	BGE_DBG
#define	BGE_DBG		BGE_DBG_PHYS	/* debug flag for this code	*/

/*
 * Here we have to determine which media we're using (copper or serdes).
 * Once that's done, we can initialise the physical layer appropriately.
 */
int
bge_phys_init(bge_t *bgep)
{
	uint32_t regval;

	BGE_TRACE(("bge_phys_init($%p)", (void *)bgep));

	mutex_enter(bgep->genlock);

	/*
	 * Probe for the (internal) PHY.  If it's not there, we'll assume
	 * that this is a 5703/4S, with a SerDes interface rather than
	 * a PHY. BCM5714S/BCM5715S are not supported.It are based on
	 * BCM800x PHY.
	 */
	bgep->phy_mii_addr = 1;

	if (DEVICE_5717_SERIES_CHIPSETS(bgep)) {
		bgep->phy_mii_addr = (bgep->pci_func + 1);
		regval = bge_reg_get32(bgep, SGMII_STATUS_REG);
		if (regval & MEDIA_SELECTION_MODE)
			bgep->phy_mii_addr += 7; /* sgmii */
	}

	if (bge_phy_probe(bgep)) {
		bgep->chipid.flags &= ~CHIP_FLAG_SERDES;
		bgep->physops = &copper_ops;
	} else {
		bgep->chipid.flags |= CHIP_FLAG_SERDES;
		bgep->physops = &serdes_ops;
	}

	if ((*bgep->physops->phys_restart)(bgep, B_FALSE) != DDI_SUCCESS) {
		mutex_exit(bgep->genlock);
		return (EIO);
	}
	if (bge_check_acc_handle(bgep, bgep->io_handle) != DDI_FM_OK) {
		mutex_exit(bgep->genlock);
		return (EIO);
	}
	mutex_exit(bgep->genlock);
	return (0);
}

/*
 * Reset the physical layer
 */
void
bge_phys_reset(bge_t *bgep)
{
	BGE_TRACE(("bge_phys_reset($%p)", (void *)bgep));

	mutex_enter(bgep->genlock);
	if ((*bgep->physops->phys_restart)(bgep, B_FALSE) != DDI_SUCCESS)
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_UNAFFECTED);
	if (bge_check_acc_handle(bgep, bgep->io_handle) != DDI_FM_OK)
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_UNAFFECTED);
	mutex_exit(bgep->genlock);
}

/*
 * Reset and power off the physical layer.
 *
 * Another RESET should get it back to working, but it may take a few
 * seconds it may take a few moments to return to normal operation ...
 */
int
bge_phys_idle(bge_t *bgep)
{
	BGE_TRACE(("bge_phys_idle($%p)", (void *)bgep));

	ASSERT(mutex_owned(bgep->genlock));
	return ((*bgep->physops->phys_restart)(bgep, B_TRUE));
}

/*
 * Synchronise the PHYSICAL layer's speed/duplex/autonegotiation capabilities
 * and advertisements with the required settings as specified by the various
 * param_* variables that can be poked via the NDD interface.
 *
 * We always reset the PHYSICAL layer and reprogram *all* relevant registers.
 * This is expected to cause the link to go down, and then back up again once
 * the link is stable and autonegotiation (if enabled) is complete.  We should
 * get a link state change interrupt somewhere along the way ...
 *
 * NOTE: <genlock> must already be held by the caller
 */
int
bge_phys_update(bge_t *bgep)
{
	BGE_TRACE(("bge_phys_update($%p)", (void *)bgep));

	ASSERT(mutex_owned(bgep->genlock));
	return ((*bgep->physops->phys_update)(bgep));
}

#undef	BGE_DBG
#define	BGE_DBG		BGE_DBG_LINK	/* debug flag for this code	*/

/*
 * Read the link status and determine whether anything's changed ...
 *
 * This routine should be called whenever the chip flags a change
 * in the hardware link state.
 *
 * This routine returns B_FALSE if the link state has not changed,
 * returns B_TRUE when the change to the new state should be accepted.
 * In such a case, the param_* variables give the new hardware state,
 * which the caller should use to update link_state etc.
 *
 * The caller must already hold <genlock>
 */
boolean_t
bge_phys_check(bge_t *bgep)
{
	BGE_TRACE(("bge_phys_check($%p)", (void *)bgep));

	ASSERT(mutex_owned(bgep->genlock));

	/*
	 * Force a link recheck if current state is unknown.
	 * phys_check() returns TRUE if the link status changed,
	 * FALSE otherwise.
	 */
	return ((*bgep->physops->phys_check)(bgep,
	    (bgep->link_state == LINK_STATE_UNKNOWN)));
}
