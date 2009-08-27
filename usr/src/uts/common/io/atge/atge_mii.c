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
#include "atge_l1e_reg.h"

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
		drv_usecwait(1);
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

	OUTW(atgep, L1E_GPHY_CTRL,
	    GPHY_CTRL_HIB_EN | GPHY_CTRL_HIB_PULSE | GPHY_CTRL_SEL_ANA_RESET |
	    GPHY_CTRL_PHY_PLL_ON);
	drv_usecwait(1000);

	OUTW(atgep, L1E_GPHY_CTRL,
	    GPHY_CTRL_EXT_RESET | GPHY_CTRL_HIB_EN | GPHY_CTRL_HIB_PULSE |
	    GPHY_CTRL_SEL_ANA_RESET | GPHY_CTRL_PHY_PLL_ON);
	drv_usecwait(1000);

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
