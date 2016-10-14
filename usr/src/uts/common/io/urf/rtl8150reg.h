/*
 * @(#)rtl8150reg.h	1.1 04/09/16
 * Macro definitions for Realtek 8150 USB to fast ethernet controller
 * based on Realtek RTL8150 data sheet
 * This file is public domain. Coded by M.Murayama (KHF04453@nifty.com)
 */

#ifndef __RTL8150REG_H__
#define	__RTL8150REG_H__

/*
 * Register offset
 */
#define	IDR	0x0120	/* Base of ID registers */
#define	MAR	0x0126	/* Base of multicast registers */
#define	CR	0x012e	/* Command register */
#define	TCR	0x012f	/* Transmit Configuration register */
#define	RCR	0x0130	/* Receive Configuration register */
#define	TSR	0x0132	/* Transmit Status register */
#define	RSR	0x0133	/* Receive Status register */
#define	CON0	0x0135	/* Configuration register 0 */
#define	CON1	0x0136	/* Configuration register 1 */
#define	MSR	0x0137	/* Media Status register */
#define	PHYADD	0x0138	/* PHY address register */
#define	PHYDAT	0x0139	/* PHY data register */
#define	PHYCNT	0x013b	/* PHY control register */
#define	GPPC	0x013d	/* General purpose pin control */
#define	WAKECNT	0x013e	/* Wake up event control */
#define	BMCR	0x0140	/* Basic Mode Control register */
#define	BMSR	0x0142	/* Basic Mode Status register */
#define	ANAR	0x0144	/* Auto Negotiation Advertisement register */
#define	ANLP	0x0146	/* Auto Negotiation Link Partner register */
#define	ANER	0x0148	/* Auto Negotiation Expansion register */
#define	NWAYT	0x014a	/* Nway test register */
#define	CSCR	0x014c	/* CS configuration register */
#define	CRC0	0x014e	/* Power management register for wakeup frame0 */
#define	CRC1	0x0150	/* Power management register for wakeup frame1 */
#define	CRC2	0x0152	/* Power management register for wakeup frame2 */
#define	CRC3	0x0154	/* Power management register for wakeup frame3 */
#define	CRC4	0x0156	/* Power management register for wakeup frame4 */
#define	BYTEMASK0 0x0158	/* Power management wakeup frame0 bytemask */
#define	BYTEMASK1 0x0160	/* Power management wakeup frame1 bytemask */
#define	BYTEMASK2 0x0168	/* Power management wakeup frame2 bytemask */
#define	BYTEMASK3 0x0170	/* Power management wakeup frame3 bytemask */
#define	BYTEMASK4 0x0178	/* Power management wakeup frame4 bytemask */
#define	PHY1	0x0180	/* PHY parameter 1 */
#define	PHY2	0x0184	/* PHY parameter 2 */
#define	TW1	0x0186	/* Twister parameter 1 */

/*
 * Bit field definitions
 */
/* CR : Command register (uint8_t) */
#define	CR_WEPROM	0x20	/* EEPROM write enable */
#define	CR_SOFT_RST	0x10	/* Reset */
#define	CR_RE		0x08	/* Ethernet receive enable */
#define	CR_TE		0x04	/* Ethernet transmit enable */
#define	CR_EP3CLREN	0x02	/* clear performance counter after EP3 */
#define	CR_AUTOLOAD	0x01	/* autoload contents of 93c46 */

#define	CR_BITS	"\020\006WEPROM\005SOFT_RST\004RE\003TE\002EP3CLREN\001AUTOLOAD"

/* TCR: Transmit Configuration register */
#define	TCR_TXRR	0xc0	/* Tx retry count */
#define	TCR_TXRR_SHIFT		6
#define	TCR_IFG		0x18	/* Interframe Gap */
#define	TCR_IFG_SHIFT		3
#define	TCR_IFG_802_3		(3 << TCR_IFG_SHIFT)	/* 802.3 standard */
#define	TCR_NOCRC	0x01	/* Inhibit Appending CRC */

#define	TCR_BITS	"\020\001NOCRC"

/* Receive Configuration register */
#define	RCR_TAIL	0x0080	/* Rx header forward to host in CRC field */
#define	RCR_AER		0x0040	/* Accept Error packet */
#define	RCR_AR		0x0020	/* Accept runt */
#define	RCR_AM		0x0010	/* Accept multicast */
#define	RCR_AB		0x0008	/* Accept broadcast */
#define	RCR_AD		0x0004	/* Accept physical match */
#define	RCR_AAM		0x0002	/* Accept all Multicast */
#define	RCR_AAP		0x0001	/* Accept all physical */

#define	RCR_ACCEPT_MODE		\
	(RCR_AER | RCR_AR | RCR_AM | RCR_AB | RCR_AD | RCR_AAM | RCR_AAP)

#define	RCR_BITS	\
	"\020\010TAIL\007AER\006AR\005AM\004AB\003AD\002AAM\001AAP"

/* Transmit Status register */

#define	TSR_ECOL	0x20	/* excessive collision indication */
#define	TSR_LCOL	0x10	/* late collision indication */
#define	TSR_LOSS_CRS	0x08	/* lost of carrier indication */
#define	TSR_JBR		0x04	/* jabber time out indication */
#define	TSR_BUF_EMPTY	0x02	/* Tx buffer is empty */
#define	TSR_BUF_FULL	0x01	/* Tx buffer is full */

#define	TSR_BITS	\
	"\020"		\
	"\006ECOL"	\
	"\005LCOL"	\
	"\004LOSS_CRS"	\
	"\003JBR"	\
	"\002BUF_EMPTY"	\
	"\001BUF_FULL"

/* Receive status register in Rx packet field */
#define	RSR_WEVENT	0x80	/* Wakeup event indication */
#define	RSR_RX_BUF_FULL	0x40	/* Receive buffer full indication */
#define	RSR_LKCHG	0x20	/* Link change indication */
#define	RSR_RUNT	0x10	/* short packet indication */
#define	RSR_LONG	0x08	/* Long packet indication */
#define	RSR_CRC		0x04	/* CRC error indication */
#define	RSR_FAE		0x02	/* Frame alignment error */
#define	RSR_ROK		0x01	/* Receive OK indication */

#define	RSR_ERRS	(RSR_RUNT | RSR_LONG | RSR_CRC | RSR_FAE)
#define	RSR_BITS	\
	"\020"		\
	"\010WEVENT"	\
	"\007RX_BUF_FULL"	\
	"\006LKCHG"	\
	"\005RUNT"	\
	"\004LONG"	\
	"\003CRC"	\
	"\002FAE"	\
	"\001ROK"

/* Config 0 */

#define	CON0_SUSLED	0x80
#define	CON0_PARM_EN	0x40	/* parameter enable */
#define	CON0_LDPS	0x08
#define	CON0_MSEL	0x04	/* media select 1:MII, 0:auto */
#define	CON0_LEDS	0x03	/* LED pattern */

/* Config 1 */
#define	CON0_BWF	0x40	/* Broadcast wakeup function 1:on 0:off */
#define	CON0_MWF	0x20	/* Multicast wakeup function 1:on 0:off */
#define	CON0_UWF	0x10	/* Unicast wakeup function 1:on 0:off */
#define	CON0_LONGWF1	0x02	/* */
#define	CON0_LONGWF0	0x01	/* */


/* MSR : Media Status register */
#define	MSR_TXFCE	0x80	/* Tx Flow control enable */
#define	MSR_RXFCE	0x40	/* Rx Flow control enable */
#define	MSR_DUPLEX	0x10	/* full duplex */
#define	MSR_SPEED_100	0x08	/* 100Mbps mode */
#define	MSR_LINK	0x04	/* link status */
#define	MSR_TXPF	0x02	/* 8150 sends pause packet */
#define	MSR_RXPF	0x01	/* 8150 is in backoff state */

#define	MSR_BITS	\
	"\020"		\
	"\010TXFCE"	\
	"\007RXFCE"	\
	"\005DUPLEX"	\
	"\004SPEED_100"	\
	"\003LINK"	\
	"\002TXPF"	\
	"\001RXPF"

/* MII PHY Address */
#define	PHYADD_MASK	0x1f

/* MII PHY Data */
#define	PHYCNT_OWN	0x40	/* 8150 owns:1 not owns:0 */
#define	PHYCNT_RWCR	0x20	/* write:1 read:0 */
#define	PHYCNT_PHYOFF	0x1f

/* BMCR (almost same with MII_CONTROL register) */
#define	BMCR_RESET	0x8000	/* PHY reset */
#define	BMCR_Spd_Set	0x2000	/* 100Mbps */
#define	BMCR_ANE	0x1000	/* auto negotiation enable */
#define	BMCR_RSA	0x0200	/* restart auto negotiation */
#define	BMCR_duplex	0x0100	/* 100Mbps */

/* Basic mode status register */
/* Auto-negotiation Advertisement register */
/* Auto-negotiation Link Partner Ability register */
/* Auto-negotiation Expansion register */

/* Nway test register */
#define	NWAYT_NWLPBK	0x0080
#define	NWAYT_ENNWLE	0x0008
#define	NWAYT_FLAGABD	0x0004
#define	NWAYT_FLAGPDF	0x0002
#define	NWAYT_FLAGLSC	0x0001

/* CS configuration register */
#define	CS_TESTFUN	0x8000	/* */
#define	CS_LD		0x0200	/* */
#define	CS_HEARTBEAT	0x0100	/* */
#define	CS_JBEN		0x0080	/* */
#define	CS_F_LINK100	0x0040	/* */
#define	CS_F_CONNECT	0x0020	/* */
#define	CS_CON_STATUS	0x0008	/* */
#define	CS_CON_STATUS_EN 0x0004	/* */
#define	CS_PASS_SCR	0x0001	/* bypass scramble function */

/*
 * header format of rx packet
 */
#define	RXHD_MULT	0x8000	/* multicast packet */
#define	RXHD_PHYS	0x4000	/* physical match packet */
#define	RXHD_RUNT	0x2000	/* too short */
#define	RXHD_VALID	0x1000	/* packet is ok */
#define	RXHD_BYTECNT	0x0fff	/* rx byte count */

#define	RXHD_BITS	\
	"\020"		\
	"\020MULT"	\
	"\017PHYS"	\
	"\016RUNT"	\
	"\015VALID"
/*
 * Offset to EPROM contents
 */
#define	URF_EEPROM_BASE		0x1200
#define	EPROM_EthernetID	0x0002

#endif /* __RTL8150REG_H__ */
