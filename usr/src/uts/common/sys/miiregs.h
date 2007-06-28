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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Definitions for MII registers from 802.3u and vendor documentation
 */

#ifndef _MIIREGS_H
#define	_MIIREGS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/* Register addresses: Section 22.2.4 */
#define	MII_CONTROL		0
#define	MII_STATUS		1
#define	MII_PHYIDH		2
#define	MII_PHYIDL		3
#define	MII_AN_ADVERT		4	/* Auto negotiation advertisement. */
#define	MII_AN_LPABLE		5	/* Auto neg. Link Partner Ability  */
#define	MII_AN_EXPANSION	6	/* Auto neg. Expansion.		   */
#define	MII_AN_NXTPGXMIT	7	/* Auto neg. Next Page Transmit	   */
#define	MII_RESERVED		8	/* Reserved up to 16		   */
#define	MII_VENDOR(x)		(16+(x)) /* Vendor specific		   */

/* Control register: 22.2.4.1 */
#define	MII_CONTROL_RESET	(1<<15)
#define	MII_CONTROL_LOOPBACK	(1<<14)
#define	MII_CONTROL_100MB	(1<<13)
#define	MII_CONTROL_ANE		(1<<12)
#define	MII_CONTROL_PWRDN	(1<<11)
#define	MII_CONTROL_ISOLATE	(1<<10)
#define	MII_CONTROL_RSAN	(1<<9)
#define	MII_CONTROL_FDUPLEX	(1<<8)
#define	MII_CONTROL_COLTST	(1<<7)
#define	MII_CONTROL_RESERVED	0x7f

/* Status register: 22.2.4.2 */
#define	MII_STATUS_100_BASE_T4	(1<<15)
#define	MII_STATUS_100_BASEX_FD	(1<<14)
#define	MII_STATUS_100_BASEX	(1<<13)
#define	MII_STATUS_10_FD	(1<<12)
#define	MII_STATUS_10		(1<<11)
#define	MII_STATUS_RESERVED	(0xf<<7)
#define	MII_STATUS_MFPRMBLSUPR	(1<<6)
#define	MII_STATUS_ANDONE	(1<<5)
#define	MII_STATUS_REMFAULT	(1<<4)
#define	MII_STATUS_CANAUTONEG	(1<<3)
#define	MII_STATUS_LINKUP	(1<<2)
#define	MII_STATUS_JABBERING	(1<<1)
#define	MII_STATUS_EXTENDED	(1<<0)

/* Advertisement/Partner ability registers: 28.2.4.1.3/4 */

#define	MII_AN_ADVERT_NP	(1<<15)
#define	MII_AN_ADVERT_ACK	(1<<14)
#define	MII_AN_ADVERT_REMFAULT	(1<<13)
#define	MII_AN_ADVERT_RESERVED	(3<<11)
#define	MII_AN_ADVERT_FCS	(1<<10)
#define	MII_AN_ADVERT_TECHABLE	(0xff<<5)
#define	MII_AN_ADVERT_SELECTOR	(0x1f)

/* Technology field bits (above). From Annex 28B */
#define	MII_ABILITY_10BASE_T	(1<<5)
#define	MII_ABILITY_10BASE_T_FD	(1<<6)
#define	MII_ABILITY_100BASE_TX	(1<<7)
#define	MII_ABILITY_100BASE_TX_FD (1<<8)
#define	MII_ABILITY_100BASE_T4	(1<<9)

/* Expansion register 28.2.4.1.5 */
#define	MII_AN_EXP_PARFAULT	(1<<4)	/* fault detected		  */
#define	MII_AN_EXP_LPCANNXTP	(1<<3)	/* Link partner is Next Page able */
#define	MII_AN_EXP_CANNXTPP	(1<<2)	/* Local is next page able	  */
#define	MII_AN_EXP_PAGERCVD	(1<<1)	/* A new page has been recvd.	  */
#define	MII_AN_EXP_LPCANAN	(1<<0)	/* LP can auto-negotiate	  */

/*
 * Truncated OUIs as found in the PHY Identifier ( 22.2.4.3.1 ),
 * and known models (and their registers) from those manufacturers
 */

#define	PHY_MANUFACTURER(x)	(((x) >> 10) & 0x3fffff) /* 22 bits, 10-31 */
#define	PHY_MODEL(x)		(((x) >> 4) & 0x3f)	 /* 6 bits,4-9	   */
#define	PHY_REVISION(x)		((x) & 0xf)		 /* 4 bits, 0-3	   */

#define	OUI_NATIONAL_SEMICONDUCTOR 0x80017
#define	NS_DP83840		0x00
#define	MII_83840_ADDR		25
#define	NS83840_ADDR_SPEED10	(1<<6)
#define	NS83840_ADDR_CONSTAT	(1<<5)
#define	NS83840_ADDR_ADDR	(0x1f<<0)

#define	OUI_INTEL		0x0aa00
#define	INTEL_82553_CSTEP	0x35	/* A and B steps are non-standard */
#define	MII_82553_EX0		16
#define	I82553_EX0_FDUPLEX	(1<<0)
#define	I82553_EX0_100MB	(1<<1)
#define	I82553_EX0_WAKE		(1<<2)
#define	I82553_EX0_SQUELCH	(3<<3) /* 3:4 */
#define	I82553_EX0_REVCNTR	(7<<5) /* 5:7 */
#define	I82553_EX0_FRCFAIL	(1<<8)
#define	I82553_EX0_TEST		(0x1f<<9) /* 13:9 */
#define	I82553_EX0_LINKDIS	(1<<14)
#define	I82553_EX0_JABDIS	(1<<15)

#define	MII_82553_EX1
#define	I82553_EX1_RESERVE	(0x1ff<<0) /* 0:8 */
#define	I82553_EX1_CH2EOF	(1<<9)
#define	I82553_EX1_MNCHSTR	(1<<10)
#define	I82553_EX1_EOP		(1<<11)
#define	I82553_EX1_BADCODE	(1<<12)
#define	I82553_EX1_INVALCODE	(1<<13)
#define	I82553_EX1_DCBALANCE	(1<<14)
#define	I82553_EX1_PAIRSKEW	(1<<15)

#define	INTEL_82555		0x15
#define	INTEL_82562_EH		0x33
#define	INTEL_82562_ET		0x32
#define	INTEL_82562_EM		0x31

#define	OUI_ICS			0x57d
#define	ICS_1890		2
#define	ICS_1889		1
#define	ICS_EXCTRL		16
#define	ICS_EXCTRL_CMDOVRD	(1<<15)
#define	ICS_EXCTRL_PHYADDR	(0x1f<<6)
#define	ICS_EXCTRL_SCSTEST	(1<<5)
#define	ICS_EXCTRL_INVECTEST	(1<<2)
#define	ICS_EXCTRL_SCDISABLE	(1<<0)

#define	ICS_QUICKPOLL		17
#define	ICS_QUICKPOLL_100MB	(1<<15)
#define	ICS_QUICKPOLL_FDUPLEX	(1<<14)
#define	ICS_QUICKPOLL_ANPROG	(7<<11)
#define	ICS_QUICKPOLL_RSE	(1<<10)
#define	ICS_QUICKPOLL_PLLLOCK	(1<<9)
#define	ICS_QUICKPOLL_FALSECD	(1<<8)
#define	ICS_QUICKPOLL_SYMINVAL	(1<<7)
#define	ICS_QUICKPOLL_SYMHALT	(1<<6)
#define	ICS_QUICKPOLL_PREMEND	(1<<5)
#define	ICS_QUICKPOLL_ANDONE	(1<<4)
#define	ICS_QUICKPOLL_RESERVED	(1<<3)
#define	ICS_QUICKPOLL_JABBER	(1<<2)
#define	ICS_QUICKPOLL_REMFAULT	(1<<1)
#define	ICS_QUICKPOLL_LINKSTAT	(1<<0)

#define	ICS_10BASET		18
#define	ICS_10BASET_REMJABBER	(1<<15)
#define	ICS_10BASET_REVPOLARITY (1<<14)
#define	ICS_10BASET_RESERVED	(0xff<<6)
#define	ICS_10BASET_NOJABBER	(1<<5)
#define	ICS_10BASET_NORMLOOP	(1<<4)
#define	ICS_10BASET_NOAUTOPOLL	(1<<3)
#define	ICS_10BASET_NOSQE	(1<<2)
#define	ICS_10BASET_NOLINKLOSS	(1<<1)
#define	ICS_10BASET_NOSQUELCH	(1<<0)

#define	ICS_EXCTRL2		19
#define	ICS_EXCTRL2_ISREPEATER	(1<<15)
#define	ICS_EXCTRL2_SOFTPRI	(1<<14)
#define	ICS_EXCTRL2_LPCANREMF	(1<<13)
#define	ICS_EXCTRL2_RMFSXMITED	(1<<10)
#define	ICS_EXCTRL2_ANPWRREMF	(1<<4)
#define	ICS_EXCTRL2_10BASETQUAL (1<<2)
#define	ICS_EXCTRL2_AUTOPWRDN	(1<<0)

#define	OUI_DAVICOM		0x0606e

#define	DM_SCR			16
#define	DM_SCR_F_TX		(1<<10)
#define	DM_SCR_UTP		(1<<9)
#define	DM_SCR_F_LINK_100	(1<<7)
#define	DM_SCR_LED_CTL		(1<<5)
#define	DM_SCR_SMRST		(1<<3)
#define	DM_SCR_MFPSC		(1<<2)
#define	DM_SCR_SLEEP		(1<<1)
#define	DM_SCR_RLOUT		(1<<0)

#define	DM_SCSR			17
#define	DM_SCSR_100FDX		(1<<15)
#define	DM_SCSR_100HDX		(1<<14)
#define	DM_SCSR_10FDX		(1<<13)
#define	DM_SCSR_10HDX		(1<<12)
#define	DM_SCSR_PHYAD		(0x1f<<4)
#define	DM_SCSR_ANMB		(0x0f)

#define	DM_10BT			18
#define	DM_10BT_LB_EN		(1<<14)
#define	DM_10BT_HBE		(1<<13)
#define	DM_10BT_JABEN		(1<<11)

#ifdef __cplusplus
}
#endif

#endif /* _MIIREGS_H */
