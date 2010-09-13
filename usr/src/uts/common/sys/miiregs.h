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
 * Definitions for MII registers from 802.3u and vendor documentation
 */

#ifndef _SYS_MIIREGS_H
#define	_SYS_MIIREGS_H

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
#define	MII_AN_NXTPGLP		8	/* Link Part. Augo neg. Next Page  */
#define	MII_MSCONTROL		9	/* 100Base-T2 and 1000 BaseT Ctrl. */
#define	MII_MSSTATUS		10	/* 100Base-T2 and 1000 BaseT Stat. */
#define	MII_EXTSTATUS		15	/* Extended status registers	   */
#define	MII_VENDOR(x)		(16+(x)) /* Vendor specific		   */

/* Control register: 22.2.4.1, 28.2.4.1.1 */
#define	MII_CONTROL_RESET	(1<<15)
#define	MII_CONTROL_LOOPBACK	(1<<14)
#define	MII_CONTROL_100MB	(1<<13)
#define	MII_CONTROL_ANE		(1<<12)
#define	MII_CONTROL_PWRDN	(1<<11)
#define	MII_CONTROL_ISOLATE	(1<<10)
#define	MII_CONTROL_RSAN	(1<<9)
#define	MII_CONTROL_FDUPLEX	(1<<8)
#define	MII_CONTROL_COLTST	(1<<7)
#define	MII_CONTROL_1GB		(1<<6)
#define	MII_CONTROL_UNIDIR	(1<<5)

/* Status register: 22.2.4.2, 28.2.4.1.2 */
#define	MII_STATUS_100_BASE_T4	(1<<15)
#define	MII_STATUS_100_BASEX_FD	(1<<14)
#define	MII_STATUS_100_BASEX	(1<<13)
#define	MII_STATUS_10_FD	(1<<12)
#define	MII_STATUS_10		(1<<11)
#define	MII_STATUS_100T2_FD	(1<<10)
#define	MII_STATUS_100T2	(1<<9)
#define	MII_STATUS_EXTSTAT	(1<<8)
#define	MII_STATUS_UNIDIR	(1<<7)
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
#define	MII_AN_ADVERT_EXTNP	(1<<12)
#define	MII_AN_ADVERT_TECHABLE	(0x7f<<5)
#define	MII_AN_ADVERT_SELECTOR	(0x1f)
#define	MII_AN_SELECTOR_8023	0x0001

/* Technology field bits (above). From Annex 28B */
#define	MII_ABILITY_10BASE_T	(1<<5)
#define	MII_ABILITY_10BASE_T_FD	(1<<6)
#define	MII_ABILITY_100BASE_TX	(1<<7)
#define	MII_ABILITY_100BASE_TX_FD (1<<8)
#define	MII_ABILITY_100BASE_T4	(1<<9)
#define	MII_ABILITY_PAUSE	(1<<10)
#define	MII_ABILITY_ASMPAUSE	(1<<11)
/* Override fields for 1000 Base-X: 37.2.5.1.3 */
#define	MII_ABILITY_X_FD	(1<<5)
#define	MII_ABILITY_X_HD	(1<<6)
#define	MII_ABILITY_X_PAUSE	(1<<7)
#define	MII_ABILITY_X_ASMPAUSE	(1<<8)
/* Override fields for 100 Base T2: 32.5.4.2 */
#define	MII_ABILITY_T2_FD	(1<<11)
#define	MII_ABILITY_T2_HD	(1<<10)

/* Expansion register 28.2.4.1.5 */
#define	MII_AN_EXP_PARFAULT	(1<<4)	/* fault detected		  */
#define	MII_AN_EXP_LPCANNXTP	(1<<3)	/* Link partner is Next Page able */
#define	MII_AN_EXP_CANNXTPP	(1<<2)	/* Local is next page able	  */
#define	MII_AN_EXP_PAGERCVD	(1<<1)	/* A new page has been recvd.	  */
#define	MII_AN_EXP_LPCANAN	(1<<0)	/* LP can auto-negotiate	  */

/* Master/Slave control: 40.5.1.1 */
#define	MII_MSCONTROL_TEST_MASK	(3<<13)
#define	MII_MSCONTROL_MANUAL	(1<<12)	/* manual master/slave control */
#define	MII_MSCONTROL_MASTER	(1<<11)
#define	MII_MSCONTROL_MULTIPORT	(1<<10)	/* DCE, default 0 for NICs */
#define	MII_MSCONTROL_1000T_FD	(1<<9)
#define	MII_MSCONTROL_1000T	(1<<8)

/* Master/Slave status: 40.5.1.1 */
#define	MII_MSSTATUS_FAULT	(1<<15)	/* Master/slave config fault */
#define	MII_MSSTATUS_MASTER	(1<<14)	/* Master/slave config result */
#define	MII_MSSTATUS_RXSTAT	(1<<13)
#define	MII_MSSTATUS_REMRXSTAT	(1<<12)
#define	MII_MSSTATUS_LP1000T_FD	(1<<11)
#define	MII_MSSTATUS_LP1000T	(1<<10)
#define	MII_MSSTATUS_IDLE_ERR	(0xff)

/* Extended status: 22.2.4.4 */
#define	MII_EXTSTATUS_1000X_FD	(1<<15)
#define	MII_EXTSTATUS_1000X	(1<<14)
#define	MII_EXTSTATUS_1000T_FD	(1<<13)
#define	MII_EXTSTATUS_1000T	(1<<12)

/*
 * Truncated OUIs as found in the PHY Identifier ( 22.2.4.3.1 ),
 * and known models (and their registers) from those manufacturers
 */

#define	MII_PHY_MFG(x)		(((x) >> 10) & 0x3fffff) /* 22 bits, 10-31 */
#define	MII_PHY_MODEL(x)	(((x) >> 4) & 0x3f)	 /* 6 bits,4-9	   */
#define	MII_PHY_REV(x)		((x) & 0xf)		 /* 4 bits, 0-3	   */

/*
 * PHY manufacturer OUIs
 */
#define	MII_OUI_ALTIMA			0x000895
#define	MII_OUI_AMD			0x00001a
#define	MII_OUI_AMD_2			0x000058
#define	MII_OUI_ATTANSIC		0x001374
#define	MII_OUI_BROADCOM		0x001018
#define	MII_OUI_BROADCOM_2		0x000818
#define	MII_OUI_CICADA			0x0003f1
#define	MII_OUI_CICADA_2		0x00c08f
#define	MII_OUI_DAVICOM			0x00606e
#define	MII_OUI_DAVICOM_2		0x000676
#define	MII_OUI_ICS			0x00057d
#define	MII_OUI_ICPLUS			0x0090c3
#define	MII_OUI_INTEL			0x00aa00
#define	MII_OUI_INTEL_2			0x001f00
#define	MII_OUI_LUCENT			0x00601d
#define	MII_OUI_MARVELL			0x005043
#define	MII_OUI_NATIONAL_SEMI		0x080017
#define	MII_OUI_NATIONAL_SEMI_2		0x1000e8
#define	MII_OUI_QUALITY_SEMI		0x006051
#define	MII_OUI_QUALITY_SEMI_2		0x00608a

/*
 * PHY models
 */
#define	MII_MODEL_ALTIMA_AC101			0x21	/* also Am79C874 */
#define	MII_MODEL_ALTIMA_AC101L			0x12
#define	MII_MODEL_ALTIMA_AM79C875		0x14

#define	MII_MODEL_AMD_AM79C901			0x37
#define	MII_MODEL_AMD_AM79C972			0x01
#define	MII_MODEL_AMD_AM79C973			0x36

#define	MII_MODEL_CICADA_CS8201			0x01
#define	MII_MODEL_CICADA_CS8201A		0x20
#define	MII_MODEL_CICADA_CS8201B		0x21

#define	MII_MODEL_DAVICOM_DM9101		0x00
#define	MII_MODEL_DAVICOM_DM9102		0x04
#define	MII_MODEL_DAVICOM_DM9161		0x08

#define	MII_MODEL_ICPLUS_IP101			0x05

#define	MII_MODEL_ICS_ICS1889			0x01
#define	MII_MODEL_ICS_ICS1890			0x02
#define	MII_MODEL_ICS_ICS1892			0x03
#define	MII_MODEL_ICS_ICS1893			0x04

#define	MII_MODEL_INTEL_82553_CSTEP		0x35
#define	MII_MODEL_INTEL_82555			0x15
#define	MII_MODEL_INTEL_82562_EH		0x33
#define	MII_MODEL_INTEL_82562_EM		0x31
#define	MII_MODEL_INTEL_82562_ET		0x32

#define	MII_MODEL_LUCENT_LU6612			0x0c

#define	MII_MODEL_MARVELL_88E1000		0x00
#define	MII_MODEL_MARVELL_88E1011		0x02
#define	MII_MODEL_MARVELL_88E1000_2		0x03
#define	MII_MODEL_MARVELL_88E1000S		0x04
#define	MII_MODEL_MARVELL_88E1000_3		0x05
#define	MII_MODEL_MARVELL_88E3082		0x08	/* 10/100 */
#define	MII_MODEL_MARVELL_88E1112		0x09
#define	MII_MODEL_MARVELL_88E1149		0x0b
#define	MII_MODEL_MARVELL_88E1111		0x0c
#define	MII_MODEL_MARVELL_88E1116		0x21
#define	MII_MODEL_MARVELL_88E1118		0x22
#define	MII_MODEL_MARVELL_88E1116R		0x24
#define	MII_MODEL_MARVELL_88E3016		0x26	/* 10/100 */

#define	MII_MODEL_NATIONAL_SEMI_DP83840		0x00
#define	MII_MODEL_NATIONAL_SEMI_DP83843		0x01
#define	MII_MODEL_NATIONAL_SEMI_DP83815		0x02
#define	MII_MODEL_NATIONAL_SEMI_DP83847		0x03
#define	MII_MODEL_NATIONAL_SEMI_DP83891		0x05
#define	MII_MODEL_NATIONAL_SEMI_DP83861		0x06

#define	MII_MODEL_QUALITY_SEMI_QS6612		0x00

#ifdef __cplusplus
}
#endif

#endif /* _SYS_MIIREGS_H */
