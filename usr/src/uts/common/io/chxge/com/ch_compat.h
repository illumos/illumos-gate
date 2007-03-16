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
 * Copyright (C) 2003-2005 Chelsio Communications.  All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* ch_compat.h */

#ifndef CHELSIO_T1_COMPAT_H
#define	CHELSIO_T1_COMPAT_H

#ifndef ETH_ALEN
#define	ETH_ALEN 6
#endif

/* MAC and PHY link speeds */
enum { SPEED_10, SPEED_100, SPEED_1000, SPEED_10000 };

/* MAC and PHY link duplex */
enum { DUPLEX_HALF, DUPLEX_FULL };

/* Autonegotiation settings */
enum { AUTONEG_DISABLE, AUTONEG_ENABLE };

#ifndef MII_BMCR

/* Generic MII registers and register fields. */
#define	MII_BMCR	0x00	/* Basic mode control register	*/
#define	MII_BMSR	0x01	/* Basic mode status register	*/
#define	MII_PHYSID1	0x02	/* PHYS ID 1			*/
#define	MII_PHYSID2	0x03	/* PHYS ID 2			*/
#define	MII_ADVERTISE	0x04	/* Advertisement control reg	*/
#define	MII_LPA		0x05	/* Link partner ability reg	*/

/* Basic mode control register. */
#define	BMCR_RESV	0x007f	/* Unused...			*/
#define	BMCR_CTST	0x0080	/* Collision test		*/
#define	BMCR_FULLDPLX	0x0100	/* Full duplex			*/
#define	BMCR_ANRESTART	0x0200	/* Auto negotiation restart	*/
#define	BMCR_ISOLATE	0x0400	/* Disconnect DP83840 from MII	*/
#define	BMCR_PDOWN	0x0800	/* Powerdown the DP83840	*/
#define	BMCR_ANENABLE	0x1000	/* Enable auto negotiation	*/
#define	BMCR_SPEED100	0x2000	/* Select 100Mbps		*/
#define	BMCR_LOOPBACK	0x4000	/* TXD loopback bits		*/
#define	BMCR_RESET	0x8000	/* Reset the DP83840		*/

/* Basic mode status register. */
#define	BMSR_ERCAP		0x0001	/* Ext-reg capability		*/
#define	BMSR_JCD		0x0002	/* Jabber detected		*/
#define	BMSR_LSTATUS		0x0004	/* Link status			*/
#define	BMSR_ANEGCAPABLE	0x0008	/* Able to do auto-negotiation	*/
#define	BMSR_RFAULT		0x0010	/* Remote fault detected	*/
#define	BMSR_ANEGCOMPLETE	0x0020	/* Auto-negotiation complete	*/
#define	BMSR_RESV		0x07c0	/* Unused...			*/
#define	BMSR_10HALF		0x0800	/* Can do 10mbps, half-duplex	*/
#define	BMSR_10FULL		0x1000	/* Can do 10mbps, full-duplex	*/
#define	BMSR_100HALF		0x2000	/* Can do 100mbps, half-duplex	*/
#define	BMSR_100FULL		0x4000	/* Can do 100mbps, full-duplex	*/
#define	BMSR_100BASE4		0x8000	/* Can do 100mbps, 4k packets	*/

/* Advertisement control register. */
#define	ADVERTISE_SLCT		0x001f	/* Selector bits		*/
#define	ADVERTISE_CSMA		0x0001	/* Only selector supported	*/
#define	ADVERTISE_10HALF	0x0020	/* Try for 10mbps half-duplex	*/
#define	ADVERTISE_10FULL	0x0040	/* Try for 10mbps full-duplex	*/
#define	ADVERTISE_100HALF	0x0080	/* Try for 100mbps half-duplex	*/
#define	ADVERTISE_100FULL	0x0100	/* Try for 100mbps full-duplex	*/
#define	ADVERTISE_100BASE4	0x0200	/* Try for 100mbps 4k packets	*/
#define	ADVERTISE_RESV		0x1c00	/* Unused...			*/
#define	ADVERTISE_RFAULT	0x2000	/* Say we can detect faults	*/
#define	ADVERTISE_LPACK		0x4000	/* Ack link partners response	*/
#define	ADVERTISE_NPAGE		0x8000	/* Next page bit		*/
#endif

/* MAC and PHY supported features */
#define	SUPPORTED_10baseT_Half		(1 << 0)
#define	SUPPORTED_10baseT_Full		(1 << 1)
#define	SUPPORTED_100baseT_Half		(1 << 2)
#define	SUPPORTED_100baseT_Full		(1 << 3)
#define	SUPPORTED_1000baseT_Half	(1 << 4)
#define	SUPPORTED_1000baseT_Full	(1 << 5)
#define	SUPPORTED_10000baseT_Full	(1 << 6)
#define	SUPPORTED_Autoneg		(1 << 7)
#define	SUPPORTED_TP			(1 << 8)
#define	SUPPORTED_FIBRE			(1 << 9)
#define	SUPPORTED_PAUSE			(1 << 10)
#define	SUPPORTED_LOOPBACK		(1 << 11)

/* Features advertised by PHY */
#define	ADVERTISED_10baseT_Half		(1 << 0)
#define	ADVERTISED_10baseT_Full		(1 << 1)
#define	ADVERTISED_100baseT_Half	(1 << 2)
#define	ADVERTISED_100baseT_Full	(1 << 3)
#define	ADVERTISED_1000baseT_Half	(1 << 4)
#define	ADVERTISED_1000baseT_Full	(1 << 5)
#define	ADVERTISED_10000baseT_Full	(1 << 6)
#define	ADVERTISED_Autoneg		(1 << 7)
#define	ADVERTISED_PAUSE		(1 << 10)
#define	ADVERTISED_ASYM_PAUSE		(1 << 12)

/* diagnostic message categories */
enum { LINK = 1, INTR = 2, HW = 4 };

/* diagnostic message levels */
/* enum { INFO, DEBUG }; */

#ifndef __devinit
#define	__devinit
#endif

#ifndef CH_DEVICE
struct pci_device_id {
	unsigned short devid;
	unsigned short ssid;
	unsigned short board_info_index;
};

#define	CH_DEVICE_COMMON(devid, ssid, idx) { devid, ssid, idx }
#define	CH_DEVICE(devid, ssid, idx) CH_DEVICE_COMMON(devid, ssid, idx)
#endif

#endif
