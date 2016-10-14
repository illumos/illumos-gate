/*
 * @(#)adm8511reg.h	1.1 09/06/20
 * Register dehinitsions of ADMtek ADM8511 Fast Ethernet to USB controller.
 * Codeded by Masayuki Murayama(KHF04453@nifty.ne.jp)
 * This file is public domain.
 */

#ifndef __ADM8511_H__
#define	__ADM8511_H__

#define	EC0		0x00	/* B */
#define	EC1		0x01	/* B */
#define	EC2		0x02	/* B */
#define	MA		0x08	/* 8byte array */
#define	EID		0x10	/* B */
#define	PAUSETIMER	0x18	/* B pause timer */
#define	RPNBFC		0x1a	/* B */
#define	ORFBFC		0x1b	/* B */
#define	EP1C		0x1c	/* B */
#define	RXFC		0x1d	/* B */
#define	BIST		0x1e	/* B */
#define	EEOFFSET	0x20	/* B */
#define	EEDATA		0x21	/* W */
#define	EECTRL		0x23	/* B */
#define	PHYA		0x25	/* B */
#define	PHYD		0x26 	/* W */
#define	PHYAC		0x28	/* B */
#define	USBSTAT		0x2a	/* B */
#define	ETHTXSTAT	0x2b	/* W */
#define	ETHRXSTAT	0x2d	/* B */
#define	LOSTCNT		0x2e	/* W */
#define	WF0MASK		0x30	/* 16byte array */
#define	WF0OFFSET	0x40	/* W */
#define	WF0CRC		0x41	/* W */
#define	WF1MASK		0x48	/* 16byte array */
#define	WF1OFFSET	0x58	/* W */
#define	WF1CRC		0x59	/* W */
#define	WF2MASK		0x60	/* 16byte array */
#define	WF2OFFSET	0x70	/* W */
#define	WF2CRC		0x71	/* W */
#define	WCTRL		0x78	/* B */
#define	WSTAT		0x7a	/* B */
#define	IPHYC		0x7b	/* B */
#define	GPIO54		0x7c	/* B */
#define	GPIO10		0x7e	/* B */
#define	GPIO32		0x7f	/* B */
#define	TEST		0x80	/* B */
#define	TM		0x81	/* B */
#define	RPN		0x82	/* B */

/* Ethernet control register 0: offset 0 */
#define	EC0_TXE		0x80U
#define	EC0_RXE		0x40U
#define	EC0_RXFCE	0x20U
#define	EC0_WOE		0x10U
#define	EC0_RXSA	0x08U
#define	EC0_SBO		0x04U
#define	EC0_RXMA	0x02U
#define	EC0_RXCS	0x01U

#define	EC0_BITS	\
	"\020"	\
	"\010TXE"	\
	"\007RXE"	\
	"\006RXFCE"	\
	"\005WOE"	\
	"\004RXSA"	\
	"\003SBO"	\
	"\002RXMA"	\
	"\001RXCS"

/* Ethernet control register 1: offset 1 */
#define	EC1_FD		0x20U
#define	EC1_100M	0x10U	/* 0:10Mbps 1:100Mbps */
#define	EC1_RM		0x08U	/* reset mac */

#define	EC1_BITS	\
	"\020"	\
	"\006FD"	\
	"\005100M"	\
	"\004RM"

/* Ethernet control register 2: offset 2 */
#define	EC2_MEPL	0x80U	/* 8515: MTU 0:1528, 1:1638 */
#define	EC2_RPNC	0x40U
#define	EC2_LEEPRS	0x20U
#define	EC2_EEPRW	0x10U
#define	EC2_LB		0x08U
#define	EC2_PROM	0x04U
#define	EC2_RXBP	0x02U
#define	EC2_EP3RC	0x01U

#define	EC2_BITS	\
	"\020"	\
	"\010MEPS"	\
	"\007RPNC"	\
	"\006LEEPRS"	\
	"\005EEPRW"	\
	"\004LB"	\
	"\003PROM"	\
	"\002RXBP"	\
	"\001EP3RC"

/* Recieve Packet number based Flow Control register: offset 0x1a */
#define	RPNBFC_PN	0x7eU	/* */
#define		RPNBFC_PN_SHIFT	1
#define	RPNBFC_FCP	0x01U	/* enable rx flow control */

/* Occupied Recieve FIFO based Flow Control register: offset 0x1b */
#define	ORFBFC_RXS	0x7eU	/* */
#define		ORFBFC_RXS_SHIFT	1
#define		ORFBFC_RXS_UNIT	1024U
#define	ORFBFC_FCRXS	0x01U	/* enable rx flow control */

/* EP1 control register: offset 0x1c */
#define	EP1C_EP1S0E	0x80U	/* send 0 enable */
#define	EP1C_ITMA	0x60U	/* internal test mode A */
#define	EP1C_ITMB	0x1fU	/* internal test mode B */

#define	EP1C_BITS	\
	"\020"	\
	"\010EP1S0E"

/* Rx FIFO Control register: offset 0x1d */
#define	RXFC_EXT_SRAM	0x02	/* enable external 32k sram */
#define	RXFC_RX32PKT	0x01	/* max 32 packet */

/* EEPROM offset register: offset 0x20 */
#define	EEOFFSET_MASK	0x3f	/* eeprom offset address in word */

/* EEPROM access control register: offset 0x23 */
#define	EECTRL_DONE	0x04
#define	EECTRL_RD	0x02
#define	EECTRL_WR	0x01

#define	EECTRL_BITS	\
	"\020"	\
	"\003DONE"	\
	"\002RD"	\
	"\001WR"

/* PHY control register: offset 28 */
#define	PHYAC_DO	0x80U	/* Done */
#define	PHYAC_RDPHY	0x40U	/* read phy */
#define	PHYAC_WRPHY	0x20U	/* write phy */
#define	PHYAC_PHYRA	0x1fU	/* PHY register address */

#define	PHYCTRL_BITS	\
	"\020"	\
	"\010DO"	\
	"\007RDPHY"	\
	"\006WRPHY"

/* Internal PHY control register: offset 7b */
#define	IPHYC_EPHY	0x02
#define	IPHYC_PHYR	0x01

#define	IPHYC_BITS	\
	"\020"	\
	"\002EPHY"	\
	"\001PHYR"

/* GPIO45 register: offset 7c */
#define	GPIO54_5OE	0x20
#define	GPIO54_5O	0x10
#define	GPIO54_5I	0x08
#define	GPIO54_4OE	0x04
#define	GPIO54_4O	0x02
#define	GPIO54_4I	0x01

/* GPIO01 register: offset 7e */
#define	GPIO10_1OE	0x20
#define	GPIO10_1O	0x10
#define	GPIO10_1I	0x08
#define	GPIO10_0OE	0x04
#define	GPIO10_0O	0x02
#define	GPIO10_0I	0x01

/* GPIO23 register: offset 7f */
#define	GPIO32_3OE	0x20
#define	GPIO32_3O	0x10
#define	GPIO32_3I	0x08
#define	GPIO32_2OE	0x04
#define	GPIO32_2O	0x02
#define	GPIO32_2I	0x01

/* rx status at the end of received packets */
/* byte 0 and 1 is packet length in little endian */
/* byte 2 is receive status */
#define	RSR_DRIBBLE	0x10
#define	RSR_CRC		0x08
#define	RSR_RUNT	0x04
#define	RSR_LONG	0x02
#define	RSR_MULTI	0x01

#define	RSR_ERRORS	\
	(RSR_DRIBBLE | RSR_CRC | RSR_RUNT | RSR_LONG | RSR_MULTI)

#define	RSR_BITS	\
	"\020"	\
	"\005DRIBBLE"	\
	"\004CRC"	\
	"\003RUNT"	\
	"\002LONG"	\
	"\001MULTI"
/* byte 3 is reserved */

/* TEST register: offset 80 */

#endif /* __ADM8511_H__ */
