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
 * Copyright (c) 2012 Gary Mills
 *
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2008, Pyun YongHyeon <yongari@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/mii.h>
#include <sys/miiregs.h>

#include "atge.h"
#include "atge_cmn_reg.h"
#include "atge_l1c_reg.h"
#include "atge_l1e_reg.h"
#include "atge_l1_reg.h"

uint16_t
atge_mii_read(void *arg, uint8_t phy, uint8_t reg)
{
	atge_t	*atgep = arg;
	uint32_t v;
	int i;

	mutex_enter(&atgep->atge_mii_lock);

	OUTL(atgep, ATGE_MDIO, MDIO_OP_EXECUTE | MDIO_OP_READ |
	    MDIO_SUP_PREAMBLE | MDIO_CLK_25_4 | MDIO_REG_ADDR(reg));

	for (i = PHY_TIMEOUT; i > 0; i--) {
		drv_usecwait(5);
		v = INL(atgep, ATGE_MDIO);
		if ((v & (MDIO_OP_EXECUTE | MDIO_OP_BUSY)) == 0)
			break;
	}

	mutex_exit(&atgep->atge_mii_lock);

	if (i == 0) {
		atge_error(atgep->atge_dip, "PHY (%d) read timeout : %d",
		    phy, reg);

		return (0xffff);
	}

	/*
	 * Some fast ethernet chips may not be able to auto-nego with
	 * switches even though they have 1000T based PHY. Hence we mask
	 * 1000T based capabilities.
	 */
	if (atgep->atge_flags & ATGE_FLAG_FASTETHER) {
		if (reg == MII_STATUS)
			v &= ~MII_STATUS_EXTSTAT;
		else if (reg == MII_EXTSTATUS)
			v = 0;
	}

	return ((v & MDIO_DATA_MASK) >> MDIO_DATA_SHIFT);
}

void
atge_mii_write(void *arg, uint8_t phy, uint8_t reg, uint16_t val)
{
	atge_t	*atgep = arg;
	uint32_t v;
	int i;

	mutex_enter(&atgep->atge_mii_lock);

	OUTL(atgep, ATGE_MDIO, MDIO_OP_EXECUTE | MDIO_OP_WRITE |
	    (val & MDIO_DATA_MASK) << MDIO_DATA_SHIFT |
	    MDIO_SUP_PREAMBLE | MDIO_CLK_25_4 | MDIO_REG_ADDR(reg));

	for (i = PHY_TIMEOUT; i > 0; i--) {
		drv_usecwait(5);
		v = INL(atgep, ATGE_MDIO);
		if ((v & (MDIO_OP_EXECUTE | MDIO_OP_BUSY)) == 0)
			break;
	}

	mutex_exit(&atgep->atge_mii_lock);

	if (i == 0) {
		atge_error(atgep->atge_dip, "PHY (%d) write timeout:reg %d,"
		    "  val :%d", phy, reg, val);
	}
}

void
atge_l1e_mii_reset(void *arg)
{
	atge_t *atgep = arg;
	int phyaddr;

	phyaddr = mii_get_addr(atgep->atge_mii);

	OUTW(atgep, ATGE_GPHY_CTRL,
	    GPHY_CTRL_HIB_EN | GPHY_CTRL_HIB_PULSE | GPHY_CTRL_SEL_ANA_RESET |
	    GPHY_CTRL_PHY_PLL_ON);
	drv_usecwait(1000);

	OUTW(atgep, ATGE_GPHY_CTRL,
	    GPHY_CTRL_EXT_RESET | GPHY_CTRL_HIB_EN | GPHY_CTRL_HIB_PULSE |
	    GPHY_CTRL_SEL_ANA_RESET | GPHY_CTRL_PHY_PLL_ON);
	drv_usecwait(1000);

	/*
	 * Some fast ethernet chips may not be able to auto-nego with
	 * switches even though they have 1000T based PHY. Hence we need
	 * to write 0 to MII_MSCONTROL control register.
	 */
	if (atgep->atge_flags & ATGE_FLAG_FASTETHER)
		atge_mii_write(atgep, phyaddr, MII_MSCONTROL, 0x0);

	/* Enable hibernation mode. */
	atge_mii_write(atgep, phyaddr, ATPHY_DBG_ADDR, 0x0B);
	atge_mii_write(atgep, phyaddr, ATPHY_DBG_DATA, 0xBC00);

	/* Set Class A/B for all modes. */
	atge_mii_write(atgep, phyaddr, ATPHY_DBG_ADDR, 0x00);
	atge_mii_write(atgep, phyaddr, ATPHY_DBG_DATA, 0x02EF);

	/* Enable 10BT power saving. */
	atge_mii_write(atgep, phyaddr, ATPHY_DBG_ADDR, 0x12);
	atge_mii_write(atgep, phyaddr, ATPHY_DBG_DATA, 0x4C04);

	/* Adjust 1000T power. */
	atge_mii_write(atgep, phyaddr, ATPHY_DBG_ADDR, 0x04);
	atge_mii_write(atgep, phyaddr, ATPHY_DBG_DATA, 0x8BBB);

	/* 10BT center tap voltage. */
	atge_mii_write(atgep, phyaddr, ATPHY_DBG_ADDR, 0x05);
	atge_mii_write(atgep, phyaddr, ATPHY_DBG_DATA, 0x2C46);
	drv_usecwait(1000);
}

void
atge_l1_mii_reset(void *arg)
{
	atge_t *atgep = arg;
	int linkup, i;
	uint16_t reg, pn;
	int phyaddr;

	phyaddr = mii_get_addr(atgep->atge_mii);

	OUTL(atgep, ATGE_GPHY_CTRL, GPHY_CTRL_RST);
	drv_usecwait(1000);

	OUTL(atgep, ATGE_GPHY_CTRL, GPHY_CTRL_CLR);
	drv_usecwait(1000);

	atge_mii_write(atgep, phyaddr, MII_CONTROL, MII_CONTROL_RESET);

	for (linkup = 0, pn = 0; pn < 4; pn++) {
		atge_mii_write(atgep, phyaddr, ATPHY_CDTC,
		    (pn << PHY_CDTC_POFF) | PHY_CDTC_ENB);

		for (i = 200; i > 0; i--) {
			drv_usecwait(1000);

			reg = atge_mii_read(atgep, phyaddr, ATPHY_CDTC);

			if ((reg & PHY_CDTC_ENB) == 0)
				break;
		}

		drv_usecwait(1000);

		reg = atge_mii_read(atgep, phyaddr, ATPHY_CDTS);

		if ((reg & PHY_CDTS_STAT_MASK) != PHY_CDTS_STAT_OPEN) {
			linkup++;
			break;
		}
	}

	atge_mii_write(atgep, phyaddr, MII_CONTROL,
	    MII_CONTROL_RESET |  MII_CONTROL_ANE | MII_CONTROL_RSAN);

	if (linkup == 0) {
		atge_mii_write(atgep, phyaddr, ATPHY_DBG_ADDR, 0);
		atge_mii_write(atgep, phyaddr, ATPHY_DBG_DATA, 0x124E);

		atge_mii_write(atgep, phyaddr, ATPHY_DBG_ADDR, 1);
		reg = atge_mii_read(atgep, phyaddr, ATPHY_DBG_DATA);
		atge_mii_write(atgep, phyaddr, ATPHY_DBG_DATA, reg | 0x03);

		drv_usecwait(1500 * 1000);

		atge_mii_write(atgep, phyaddr, ATPHY_DBG_ADDR, 0);
		atge_mii_write(atgep, phyaddr, ATPHY_DBG_DATA, 0x024E);
	}
}

void
atge_l1c_mii_reset(void *arg)
{
	atge_t *atgep = arg;
	uint16_t data;
	int phyaddr;

	phyaddr = mii_get_addr(atgep->atge_mii);

	/* Reset magic from Linux, via Freebsd */
	OUTW(atgep, ATGE_GPHY_CTRL, GPHY_CTRL_SEL_ANA_RESET);
	(void) INW(atgep, ATGE_GPHY_CTRL);
	drv_usecwait(10 * 1000);

	OUTW(atgep, ATGE_GPHY_CTRL,
	    GPHY_CTRL_EXT_RESET | GPHY_CTRL_SEL_ANA_RESET);
	(void) INW(atgep, ATGE_GPHY_CTRL);
	drv_usecwait(10 * 1000);

	/*
	 * Some fast ethernet chips may not be able to auto-nego with
	 * switches even though they have 1000T based PHY. Hence we need
	 * to write 0 to MII_MSCONTROL control register.
	 */
	if (atgep->atge_flags & ATGE_FLAG_FASTETHER)
		atge_mii_write(atgep, phyaddr, MII_MSCONTROL, 0x0);

	/* DSP fixup, Vendor magic. */
	switch (ATGE_DID(atgep)) {
		uint16_t reg;

	case ATGE_CHIP_AR8152V1_DEV_ID:
		atge_mii_write(atgep, phyaddr, ATPHY_DBG_ADDR, 0x000A);
		reg = atge_mii_read(atgep, phyaddr, ATPHY_DBG_DATA);
		atge_mii_write(atgep, phyaddr, ATPHY_DBG_DATA, reg & 0xDFFF);
		/* FALLTHROUGH */
	case ATGE_CHIP_AR8151V2_DEV_ID:
	case ATGE_CHIP_AR8151V1_DEV_ID:
	case ATGE_CHIP_AR8152V2_DEV_ID:
		atge_mii_write(atgep, phyaddr, ATPHY_DBG_ADDR, 0x003B);
		reg = atge_mii_read(atgep, phyaddr, ATPHY_DBG_DATA);
		atge_mii_write(atgep, phyaddr, ATPHY_DBG_DATA, reg & 0xFFF7);
		drv_usecwait(20 * 1000);
		break;
	}

	switch (ATGE_DID(atgep)) {
	case ATGE_CHIP_AR8151V1_DEV_ID:
		atge_mii_write(atgep, phyaddr, ATPHY_DBG_ADDR, 0x0029);
		atge_mii_write(atgep, phyaddr, ATPHY_DBG_DATA, 0x929D);
		break;
	case ATGE_CHIP_AR8151V2_DEV_ID:
	case ATGE_CHIP_AR8152V2_DEV_ID:
	case ATGE_CHIP_L1CG_DEV_ID:
	case ATGE_CHIP_L1CF_DEV_ID:
		atge_mii_write(atgep, phyaddr, ATPHY_DBG_ADDR, 0x0029);
		atge_mii_write(atgep, phyaddr, ATPHY_DBG_DATA, 0xB6DD);
		break;
	}

	/* Load DSP codes, vendor magic. */
	data = ANA_LOOP_SEL_10BT | ANA_EN_MASK_TB | ANA_EN_10BT_IDLE |
	    ((1 << ANA_INTERVAL_SEL_TIMER_SHIFT) &
	    ANA_INTERVAL_SEL_TIMER_MASK);
	atge_mii_write(atgep, phyaddr,
	    ATPHY_DBG_ADDR, MII_ANA_CFG18);
	atge_mii_write(atgep, phyaddr,
	    ATPHY_DBG_DATA, data);

	data = ((2 << ANA_SERDES_CDR_BW_SHIFT) & ANA_SERDES_CDR_BW_MASK) |
	    ANA_MS_PAD_DBG | ANA_SERDES_EN_DEEM | ANA_SERDES_SEL_HSP |
	    ANA_SERDES_EN_PLL | ANA_SERDES_EN_LCKDT;
	atge_mii_write(atgep, phyaddr,
	    ATPHY_DBG_ADDR, MII_ANA_CFG5);
	atge_mii_write(atgep, phyaddr,
	    ATPHY_DBG_DATA, data);

	data = ((44 << ANA_LONG_CABLE_TH_100_SHIFT) &
	    ANA_LONG_CABLE_TH_100_MASK) |
	    ((33 << ANA_SHORT_CABLE_TH_100_SHIFT) &
	    ANA_SHORT_CABLE_TH_100_SHIFT) |
	    ANA_BP_BAD_LINK_ACCUM | ANA_BP_SMALL_BW;
	atge_mii_write(atgep, phyaddr,
	    ATPHY_DBG_ADDR, MII_ANA_CFG54);
	atge_mii_write(atgep, phyaddr,
	    ATPHY_DBG_DATA, data);

	data = ((11 << ANA_IECHO_ADJ_3_SHIFT) & ANA_IECHO_ADJ_3_MASK) |
	    ((11 << ANA_IECHO_ADJ_2_SHIFT) & ANA_IECHO_ADJ_2_MASK) |
	    ((8 << ANA_IECHO_ADJ_1_SHIFT) & ANA_IECHO_ADJ_1_MASK) |
	    ((8 << ANA_IECHO_ADJ_0_SHIFT) & ANA_IECHO_ADJ_0_MASK);
	atge_mii_write(atgep, phyaddr,
	    ATPHY_DBG_ADDR, MII_ANA_CFG4);
	atge_mii_write(atgep, phyaddr,
	    ATPHY_DBG_DATA, data);

	data = ((7 & ANA_MANUL_SWICH_ON_SHIFT) & ANA_MANUL_SWICH_ON_MASK) |
	    ANA_RESTART_CAL | ANA_MAN_ENABLE | ANA_SEL_HSP | ANA_EN_HB |
	    ANA_OEN_125M;
	atge_mii_write(atgep, phyaddr,
	    ATPHY_DBG_ADDR, MII_ANA_CFG0);
	atge_mii_write(atgep, phyaddr,
	    ATPHY_DBG_DATA, data);
	drv_usecwait(1000);
}

uint16_t
atge_l1c_mii_read(void *arg, uint8_t phy, uint8_t reg)
{

	if (phy != 0) {
		/* avoid PHY address alias */
		return (0xffffU);
	}

	return (atge_mii_read(arg, phy, reg));
}

void
atge_l1c_mii_write(void *arg, uint8_t phy, uint8_t reg, uint16_t val)
{

	if (phy != 0) {
		/* avoid PHY address alias */
		return;
	}

	if (reg == MII_CONTROL) {
		/*
		 * Don't issue a reset if MII_CONTROL_RESET is set.
		 * Otherwise it occasionally
		 * advertises incorrect capability.
		 */
		if ((val & MII_CONTROL_RESET) == 0) {
			/* RESET bit is required to set mode */
			atge_mii_write(arg, phy, reg, val | MII_CONTROL_RESET);
		}
	} else {
		atge_mii_write(arg, phy, reg, val);
	}
}
