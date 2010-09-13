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

/*
 * MII overrides for Marvell PHYs.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/mii.h>
#include <sys/miiregs.h>
#include "miipriv.h"

#define	MVPHY_PSC	MII_VENDOR(0)	/* PHY specific control */

#define	MV_PSC_TXFIFO_DEPTH	0xc000
#define	MV_PSC_RXFIFO_DEPTH	0x3000
#define	MV_PSC_ASSERT_CRS_TX	0x0800	/* older PHYs */
#define	MV_PSC_DOWNSHIFT_EN	0x0800	/* newer PHYs */
#define	MV_PSC_FORCE_GOOD_LINK	0x0400
#define	MV_PSC_DIS_SCRAMBLER	0x0200
#define	MV_PSC_MII_5BIT_EN	0x0100
#define	MV_PSC_EN_DETECT_MASK	0x0300
#define	MV_PSC_EN_EXT_DISTANCE	0x0080
#define	MV_PSC_AUTO_X_MODE	0x0060
#define	MV_PSC_AUTO_X_1000T	0x0040
#define	MV_PSC_MDIX_MANUAL	0x0010
#define	MV_PSC_MDI_MANUAL	0x0000
#define	MV_PSC_RGMII_POWER_UP	0x0008	/* 88E1116, 88E1149 page 2 */
#define	MV_PSC_POWER_DOWN	0x0004	/* 88E1116 page 0 */

#define	MV_PSC_MODE_MASK	0x0380	/* 88E1112 page 2 */
#define	MV_PSC_MODE_AUTO	0x0180
#define	MV_PSC_MODE_COPPER	0x0280
#define	MV_PSC_MODE_1000BASEX	0x0380

#define	MV_PSC_DIS_125CLK	0x0010
#define	MV_PSC_MAC_PDOWN	0x0008
#define	MV_PSC_SQE_TEST		0x0004
#define	MV_PSC_POL_REVERSE	0x0002
#define	MV_PSC_JABBER_DIS	0x0001

/* 88E3016 */
#define	MV_PSC_AUTO_MDIX	0x0030
#define	MV_PSC_SIGDET_POLARITY	0x0040
#define	MV_PSC_EXT_DIST		0x0080
#define	MV_PSC_FEFI_DIS		0x0100
#define	MV_PSC_NLP_GEN_DIS	0x0800
#define	MV_PSC_LPNP		0x1000
#define	MV_PSC_NLP_CHK_DIS	0x2000
#define	MV_PSC_EN_DETECT	0x4000

/* LED control page 3, 88E1116, 88E1149 */
#define	MV_PSC_LED_LOS_MASK	0xf000
#define	MV_PSC_LED_INIT_MASK	0x0f00
#define	MV_PSC_LED_STA1_MASK	0x00f0
#define	MV_PSC_LED_STA0_MASK	0x000f

#define	MV_PSC_LED_LOS_CTRL(x)	(((x) << 12) & MV_PSC_LED_LOS_MASK)
#define	MV_PSC_LED_INIT_CTRL(x)	(((x) << 8) & MV_PSC_LED_INIT_MASK)
#define	MV_PSC_LED_STA1_CTRL(x)	(((x) << 4) & MV_PSC_LED_STA1_MASK)
#define	MV_PSC_LED_STA0_CTRL(x)	(((x)) & MV_PSC_LED_STA0_MASK)


#define	MVPHY_INTEN	MII_VENDOR(2)	/* Interrupt enable */

#define	MV_INTEN_PULSE_MASK	0x7000
#define	MV_INTEN_PULSE_NOSTR	0x0000
#define	MV_INTEN_PULSE_21MS	0x1000
#define	MV_INTEN_PULSE_42MS	0x2000
#define	MV_INTEN_PULSE_84MS	0x3000
#define	MV_INTEN_PULSE_170MS	0x4000
#define	MV_INTEN_PULSE_340MS	0x5000
#define	MV_INTEN_PULSE_670MS	0x6000
#define	MV_INTEN_PULSE_1300MS	0x7000

#define	MV_INTEN_BLINK_MASK	0x0700
#define	MV_INTEN_BLINK_42MS	0x0000
#define	MV_INTEN_BLINK_84MS	0x0100
#define	MV_INTEN_BLINK_170MS	0x0200
#define	MV_INTEN_BLINK_340MS	0x0300
#define	MV_INTEN_BLINK_670MS	0x0400

#define	MVPHY_INTST	MII_VENDOR(3)	/* Interrupt status */

#define	MVPHY_EPSC	MII_VENDOR(4)	/* Ext. phy specific control */
#define	MV_EPSC_DOWN_NO_IDLE	0x8000
#define	MV_EPSC_FIBER_LOOPBACK	0x4000
#define	MV_EPSC_TX_CLK_2_5	0x0060
#define	MV_EPSC_TX_CLK_25	0x0070
#define	MV_EPSC_TX_CLK_0	0x0000

#define	MVPHY_EADR	MII_VENDOR(6)	/* Extended address */

#define	MVPHY_LED_PSEL	MII_VENDOR(6)	/* 88E3016 */
#define	MV_LED_PSEL_COLX	0x00
#define	MV_LED_PSEL_ERROR	0x01
#define	MV_LED_PSEL_DUPLEX	0x02
#define	MV_LED_PSEL_DP_COL	0x03
#define	MV_LED_PSEL_SPEED	0x04
#define	MV_LED_PSEL_LINK	0x05
#define	MV_LED_PSEL_TX		0x06
#define	MV_LED_PSEL_RX		0x07
#define	MV_LED_PSEL_ACT		0x08
#define	MV_LED_PSEL_LNK_RX	0x09
#define	MV_LED_PSEL_LNK_ACT	0x0a
#define	MV_LED_PSEL_ACT_BL	0x0b
#define	MV_LED_PSEL_TX_BL	0x0c
#define	MV_LED_PSEL_RX_BL	0x0d
#define	MV_LED_PSEL_COLX_BL	0x0e
#define	MV_LED_PSEL_INACT	0x0f
#define	MV_LED_PSEL_LED2(x)	(x << 8)
#define	MV_LED_PSEL_LED1(x)	(x << 4)
#define	MV_LED_PSEL_LED0(x)	(x << 0)

#define	MVPHY_PAGE_ADDR	MII_VENDOR(13)
#define	MVPHY_PAGE_DATA	MII_VENDOR(14)


#define	MVPHY_EPSS	MII_VENDOR(11)	/* Ext. phy specific status */

#define	MV_EPSS_FCAUTOSEL	0x8000		/* fiber/copper autosel */
#define	MV_EPSS_FCRESOL		0x1000		/* fiber/copper resol */

static int
mvphy_reset_88e3016(phy_handle_t *ph)
{
	uint16_t	reg;
	int		rv;

	rv = phy_reset(ph);

	reg = phy_read(ph, MVPHY_PSC);

	reg |= MV_PSC_AUTO_MDIX;
	reg &= ~(MV_PSC_EN_DETECT | MV_PSC_DIS_SCRAMBLER);
	reg |= MV_PSC_LPNP;

	/* enable class A driver for Yukon FE+ A0. */
	PHY_SET(ph, MII_VENDOR(12), 0x0001);

	phy_write(ph, MVPHY_PSC, reg);

	/* LED2 = ACT blink, LED1 = LINK), LED0 = SPEED */
	phy_write(ph, MVPHY_LED_PSEL,
	    MV_LED_PSEL_LED2(MV_LED_PSEL_ACT_BL) |
	    MV_LED_PSEL_LED1(MV_LED_PSEL_LINK) |
	    MV_LED_PSEL_LED0(MV_LED_PSEL_SPEED));

	/* calibration, values not documented */
	phy_write(ph, MVPHY_PAGE_ADDR, 17);
	phy_write(ph, MVPHY_PAGE_DATA, 0x3f60);

	/* Normal BMCR reset now */
	return (rv);
}

static int
mvphy_loop_88e3016(phy_handle_t *ph)
{
	uint16_t	reg;
	int		rv;

	rv = phy_loop(ph);

	/*
	 * The PHY apparently needs a soft reset, but supposedly
	 * retains most of the other critical state.
	 */
	reg = phy_read(ph, MII_CONTROL);
	reg |= MII_CONTROL_RESET;
	phy_write(ph, MII_CONTROL, reg);

	reg = phy_read(ph, MVPHY_PSC);
	reg &= ~(MV_PSC_AUTO_MDIX);
	reg &= ~(MV_PSC_EN_DETECT | MV_PSC_DIS_SCRAMBLER);
	reg |= MV_PSC_LPNP;

	phy_write(ph, MVPHY_PSC, reg);

	return (rv);
}

static int
mvphy_reset_88e3082(phy_handle_t *ph)
{
	uint16_t reg;
	int	rv;

	rv = phy_reset(ph);

	reg = phy_read(ph, MVPHY_PSC);
	reg |= (MV_PSC_AUTO_X_MODE >> 1);
	reg |= MV_PSC_ASSERT_CRS_TX;
	reg &= ~MV_PSC_POL_REVERSE;
	phy_write(ph, MVPHY_PSC, reg);

	return (rv);
}

static int
mvphy_reset_88e1149(phy_handle_t *ph)
{
	uint16_t reg;
	int rv;

	/* make sure that this PHY uses page 0 (copper) */
	phy_write(ph, MVPHY_EADR, 0);

	reg = phy_read(ph, MVPHY_PSC);
	/* Disable energy detect mode */
	reg &= ~MV_PSC_EN_DETECT_MASK;
	reg |= MV_PSC_AUTO_X_MODE;
	reg |= MV_PSC_DOWNSHIFT_EN;
	reg &= ~MV_PSC_POL_REVERSE;
	phy_write(ph, MVPHY_PSC, reg);

	rv = phy_reset(ph);

	phy_write(ph, MVPHY_EADR, 2);
	PHY_SET(ph, MVPHY_PSC, MV_PSC_RGMII_POWER_UP);

	/*
	 * Fix for signal amplitude in 10BASE-T, undocumented.
	 * This is from the Marvell reference source code.
	 */
	phy_write(ph, MVPHY_EADR, 255);
	phy_write(ph, 0x18, 0xaa99);
	phy_write(ph, 0x17, 0x2011);

	if (MII_PHY_REV(ph->phy_id) == 0) {
		/*
		 * EC_U: IEEE A/B 1000BASE-T symmetry failure
		 *
		 * EC_U is rev 0, Ultra 2 is rev 1 (at least the
		 * unit I have), so we trigger on revid.
		 */
		phy_write(ph, 0x18, 0xa204);
		phy_write(ph, 0x17, 0x2002);
	}

	/* page 3 is led control */
	phy_write(ph, MVPHY_EADR, 3);
	phy_write(ph, MVPHY_PSC,
	    MV_PSC_LED_LOS_CTRL(1) |		/* link/act */
	    MV_PSC_LED_INIT_CTRL(8) |		/* 10 Mbps */
	    MV_PSC_LED_STA1_CTRL(7) |		/* 100 Mbps */
	    MV_PSC_LED_STA0_CTRL(7));		/* 1000 Mbps */
	phy_write(ph, MVPHY_INTEN, 0);

	phy_write(ph, MVPHY_EADR, 0);

	/*
	 * Weird... undocumented logic in the Intel e1000g driver.
	 * I'm not sure what these values really do.
	 */
	phy_write(ph, MVPHY_PAGE_ADDR, 3);
	phy_write(ph, MVPHY_PAGE_DATA, 0);

	return (rv);
}

static int
mvphy_reset_88e1116(phy_handle_t *ph)
{
	uint16_t reg;

	/* make sure that this PHY uses page 0 (copper) */
	phy_write(ph, MVPHY_EADR, 0);

	reg = phy_read(ph, MVPHY_PSC);

	reg &= ~MV_PSC_POWER_DOWN;
	/* Disable energy detect mode */
	reg &= ~MV_PSC_EN_DETECT_MASK;
	reg |= MV_PSC_AUTO_X_MODE;
	reg |= MV_PSC_ASSERT_CRS_TX;
	reg &= ~MV_PSC_POL_REVERSE;
	phy_write(ph, MVPHY_PSC, reg);

	phy_write(ph, MVPHY_EADR, 2);
	PHY_SET(ph, MVPHY_PSC, MV_PSC_RGMII_POWER_UP);

	/* page 3 is led control */
	phy_write(ph, MVPHY_EADR, 3);
	phy_write(ph, MVPHY_PSC,
	    MV_PSC_LED_LOS_CTRL(1) |		/* link/act */
	    MV_PSC_LED_INIT_CTRL(8) |		/* 10 Mbps */
	    MV_PSC_LED_STA1_CTRL(7) |		/* 100 Mbps */
	    MV_PSC_LED_STA0_CTRL(7));		/* 1000 Mbps */
	phy_write(ph, MVPHY_INTEN, 0);

	phy_write(ph, MVPHY_EADR, 0);

	return (phy_reset(ph));
}

static int
mvphy_reset_88e1118(phy_handle_t *ph)
{
	uint16_t reg;
	reg = phy_read(ph, MVPHY_PSC);

	/* Disable energy detect mode */
	reg &= ~MV_PSC_EN_DETECT_MASK;
	reg |= MV_PSC_AUTO_X_MODE;
	reg |= MV_PSC_ASSERT_CRS_TX;
	reg &= ~MV_PSC_POL_REVERSE;
	phy_write(ph, MVPHY_PSC, reg);

	return (phy_reset(ph));
}

static int
mvphy_reset_88e1111(phy_handle_t *ph)
{
	uint16_t reg;

	reg = phy_read(ph, MVPHY_PSC);

	/* Disable energy detect mode */
	reg &= ~MV_PSC_EN_DETECT_MASK;
	reg |= MV_PSC_AUTO_X_MODE;
	reg |= MV_PSC_ASSERT_CRS_TX;
	reg &= ~MV_PSC_POL_REVERSE;

	phy_write(ph, MVPHY_PSC, reg);

	/* force TX CLOCK to 25 MHz */
	PHY_SET(ph, MVPHY_EPSC, MV_EPSC_TX_CLK_25);

	return (phy_reset(ph));

}

static int
mvphy_reset_88e1112(phy_handle_t *ph)
{
	uint16_t	reg, page;

	if (phy_read(ph, MVPHY_EPSS) & MV_EPSS_FCRESOL) {

		/* interface indicates fiber */
		PHY_CLR(ph, MVPHY_PSC, MV_PSC_AUTO_X_MODE);

		page = phy_read(ph, MVPHY_EADR);

		/* Go into locked 1000BASE-X mode */
		page = phy_read(ph, MVPHY_EADR);
		phy_write(ph, MVPHY_EADR, 2);
		reg = phy_read(ph, MVPHY_PSC);
		reg &= ~MV_PSC_MODE_MASK;
		reg |= MV_PSC_MODE_1000BASEX;
		phy_write(ph, MVPHY_PSC, reg);
		phy_write(ph, MVPHY_EADR, page);

	} else {
		reg = phy_read(ph, MVPHY_PSC);

		/* Disable energy detect mode */
		reg &= ~MV_PSC_EN_DETECT_MASK;
		reg |= MV_PSC_AUTO_X_MODE;
		reg |= MV_PSC_ASSERT_CRS_TX;
		reg &= ~MV_PSC_POL_REVERSE;
		phy_write(ph, MVPHY_PSC, reg);
	}

	return (phy_reset(ph));
}

static int
mvphy_reset_88e1011(phy_handle_t *ph)
{
	uint16_t reg;

	if (phy_read(ph, MVPHY_EPSS) & MV_EPSS_FCRESOL) {

		/* interface indicates fiber */
		PHY_CLR(ph, MVPHY_PSC, MV_PSC_AUTO_X_MODE);

	} else {
		reg = phy_read(ph, MVPHY_PSC);
		reg &= ~MV_PSC_AUTO_X_MODE;
		reg |= MV_PSC_ASSERT_CRS_TX;
		reg &= ~MV_PSC_POL_REVERSE;
		phy_write(ph, MVPHY_PSC, reg);
	}
	/* force TX CLOCK to 25 MHz */
	PHY_SET(ph, MVPHY_EPSC, MV_EPSC_TX_CLK_25);

	return (phy_reset(ph));
}

static int
mvphy_reset(phy_handle_t *ph)
{
	uint16_t reg;

	reg = phy_read(ph, MVPHY_PSC);

	reg &= ~MV_PSC_AUTO_X_MODE;
	reg |= MV_PSC_ASSERT_CRS_TX;
	reg &= ~MV_PSC_POL_REVERSE;
	phy_write(ph, MVPHY_PSC, reg);

	PHY_SET(ph, MVPHY_EPSC, MV_EPSC_TX_CLK_25);

	/* Normal BMCR reset now */
	return (phy_reset(ph));
}

static int
mvphy_start(phy_handle_t *ph)
{
	int rv;

	rv = phy_start(ph);
	/*
	 * If not autonegotiating, then we need to reset the PHY according to
	 * Marvell.  I don't think this is according to the spec.  Apparently
	 * the register states are not lost during this.
	 */
	if ((rv == 0) && (!ph->phy_adv_aneg)) {
		rv = ph->phy_reset(ph);
	}
	return (rv);
}

boolean_t
phy_marvell_probe(phy_handle_t *ph)
{
	switch (MII_PHY_MFG(ph->phy_id)) {
	case MII_OUI_MARVELL:
		ph->phy_vendor = "Marvell";
		switch (MII_PHY_MODEL(ph->phy_id)) {
		case MII_MODEL_MARVELL_88E1000:
		case MII_MODEL_MARVELL_88E1000_2:
		case MII_MODEL_MARVELL_88E1000_3:
			ph->phy_model = "88E1000";
			ph->phy_reset = mvphy_reset;
			break;
		case MII_MODEL_MARVELL_88E1011:
			ph->phy_model = "88E1011";
			ph->phy_reset = mvphy_reset_88e1011;
			break;
		case MII_MODEL_MARVELL_88E1111:
			ph->phy_model = "88E1111";
			ph->phy_reset = mvphy_reset_88e1111;
			break;
		case MII_MODEL_MARVELL_88E1112:
			ph->phy_model = "88E1112";
			ph->phy_reset = mvphy_reset_88e1112;
			break;
		case MII_MODEL_MARVELL_88E1116:
			ph->phy_model = "88E1116";
			ph->phy_reset = mvphy_reset_88e1116;
			break;
		case MII_MODEL_MARVELL_88E1116R:
			ph->phy_model = "88E1116R";
			ph->phy_reset = mvphy_reset;
			break;
		case MII_MODEL_MARVELL_88E1118:
			ph->phy_model = "88E1118";
			ph->phy_reset = mvphy_reset_88e1118;
			break;
		case MII_MODEL_MARVELL_88E1149:
			ph->phy_model = "88E1149";
			ph->phy_reset = mvphy_reset;
			ph->phy_reset = mvphy_reset_88e1149;
			break;
		case MII_MODEL_MARVELL_88E3016:
			ph->phy_model = "88E3016";
			ph->phy_reset = mvphy_reset_88e3016;
			ph->phy_loop = mvphy_loop_88e3016;
			break;
		case MII_MODEL_MARVELL_88E3082:
			ph->phy_model = "88E3082";
			ph->phy_reset = mvphy_reset_88e3082;
			break;
		default:
			/* Unknown PHY model */
			return (B_FALSE);
		}
		break;

	default:
		return (B_FALSE);
	}

	ph->phy_start = mvphy_start;

	return (B_TRUE);
}
