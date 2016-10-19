/*
 * Macro definitions for Davicom DM9601 USB to fast ethernet controler
 * based on Davicom DM9601E data sheet
 * This file is public domain. Coded by M.Murayama (KHF04453@nifty.com)
 */

#ifndef __DM9601_H__
#define	__DM9601_H__

/*
 * offset of registers
 */
#define	NCR	0x00U	/* network control register */
#define	NSR	0x01U	/* network status register */
#define	TCR	0x02U	/* tx control register */
#define	TSR1	0x03U	/* tx status register 1 */
#define	TSR2	0x04U	/* tx status register 2 */
#define	RCR	0x05U	/* rx control register */
#define	RSR	0x06U	/* rx status register */
#define	ROCR	0x07U	/* rx overflow counter register */
#define	BPTR	0x08U	/* back pressure threshold regster */
#define	FCTR	0x09U	/* flow control threshold regster */
#define	FCR	0x0aU	/* flow control threshold regster */
#define	EPCR	0x0bU	/* eeprom & phy control register */
#define	EPAR	0x0cU	/* eeprom & phy address register */
#define	EPDR	0x0dU	/* eeprom & phy data register (2byte) */
#define	WCR	0x0fU	/* wake up control register */
#define	PAR	0x10U	/* physical address register (6byte) */
#define	MAR	0x16U	/* multicast address register (8byte) */
#define	GPCR	0x1eU	/* general purpose control register */
#define	GPR	0x1fU	/* general purpose register */
#define	VID	0x28U	/* vendor ID (2byte) */
#define	PID	0x2aU	/* product ID (2byte) */
#define	CHIPR	0x2cU	/* chip revision */
#define	USBDA	0xf0U	/* usb device address register */
#define	RXC	0xf1U	/* received packet counter register */
#define	TUSC	0xf2U	/* tx packet counter/usb status register */
#define	USBC	0xf4U	/* usb control register */

/*
 * register definitions
 */
/* network control register */
#define	NCR_EXT_PHY	0x80U	/* 1: select external phy */
#define	NCR_WAKEEN	0x40U	/* 1: wake up event enable */
#define	NCR_FCOL	0x10U	/* force collision mode for test */
#define	NCR_FDX		0x08U	/* 1: full duplex mode (for external phy) */
#define	NCR_LBK		0x06U
#define		NCR_LBK_SHIFT		1
#define		NCR_LBK_NORMAL	(0U << NCR_LBK_SHIFT)
#define		NCR_LBK_MAC	(1U << NCR_LBK_SHIFT)
#define		NCR_LBK_PHY_D	(2U << NCR_LBK_SHIFT)
#define		NCR_LBK_PHY_A	(3U << NCR_LBK_SHIFT)
#define	NCR_RST		0x01U	/* 1: reset, auto clear */

#define	NCR_BITS	\
	"\020"	\
	"\010EXT_PHY"	\
	"\007WAKEEN"	\
	"\005FCOL"	\
	"\004FDX"	\
	"\001RST"

/* network status register */
#define	NSR_SPEED	0x80U	/* 1:10M 0:100M */
#define	NSR_LINKST	0x40U	/* 1:ok 0:fail */
#define	NSR_WAKEST	0x20U	/* 1:enabled */
#define	NSR_TXFULL	0x10U	/* 1:tx fifo full */
#define	NSR_TX2END	0x08U	/* tx packet2 complete status */
#define	NSR_TX1END	0x04U	/* tx packet1 complete status */
#define	NSR_RXOV	0x02U	/* rx fifo overflow */
#define	NSR_RXRDY	0x01U	/* rx packet ready */

#define	NSR_BITS	\
	"\020"	\
	"\010SPEED_10"	\
	"\007LINKST_UP"	\
	"\006WAKEST"	\
	"\005TXFULL"	\
	"\004TX2END"	\
	"\003TX1END"	\
	"\002RXOV"	\
	"\001RXRDY"

/* tx control register */
#define	TCR_TJDIS	0x40U	/* tx jitter control */
#define	TCR_EXCEDM	0x20U	/* excessive collision mode */
#define	TCR_PAD_DIS2	0x10U	/* PAD appends disable for pkt2 */
#define	TCR_CRC_DIS2	0x08U	/* CRC appends disable for pkt2 */
#define	TCR_PAD_DIS1	0x04U	/* PAD appends disable for pkt1 */
#define	TCR_CRC_DIS1	0x02U	/* CRC appends disable for pkt1 */

#define	TCR_BITS	\
	"\020"	\
	"\007TJDIS"	\
	"\006EXCEDM"	\
	"\005PAD_DIS2"	\
	"\004CRC_DIS2"	\
	"\003PAD_DIS1"	\
	"\002CRC_DIS1"

/* tx status register (ro) */
#define	TSR_TJTO	0x80U	/* tx jabber time out */
#define	TSR_LC		0x40U	/* loss of carrier */
#define	TSR_NC		0x20U	/* no carrier */
#define	TSR_LATEC	0x10U	/* late collision */
#define	TSR_COL		0x08U	/* late collision */
#define	TSR_EL		0x04U	/* excessive collision */

#define	TSR_BITS	\
	"\020"		\
	"\010TJTO"	\
	"\007LC"	\
	"\006NC"	\
	"\005LATEC"	\
	"\004COL"	\
	"\003EL"

/* rx control register */
#define	RCR_WTDIS	0x40U	/* watch dog timer disable */
#define	RCR_DIS_LONG	0x20U	/* discard longer packets than 1522 */
#define	RCR_DIS_CRC	0x10U	/* discard crc error packets */
#define	RCR_ALL		0x08U	/* pass all multicast */
#define	RCR_RUNT	0x04U	/* pass runt packets */
#define	RCR_PRMSC	0x02U	/* promiscuous mode */
#define	RCR_RXEN	0x01U	/* rx enable */

#define	RCR_BITS	\
	"\020"		\
	"\007WTDIS"	\
	"\006DIS_LONG"	\
	"\005DIS_CRC"	\
	"\004ALL"	\
	"\003RUNT"	\
	"\002PRMSC"	\
	"\001RXEN"

/* rx status register */
#define	RSR_RF		0x80U	/* runt frame */
#define	RSR_MF		0x40U	/* multicast frame */
#define	RSR_LCS		0x20U	/* late collision seen */
#define	RSR_RWTO	0x10U	/* receive watchdog timeout */
#define	RSR_PLE		0x08U	/* physical layer error */
#define	RSR_AE		0x04U	/* alignment error */
#define	RSR_CE		0x02U	/* crc error */
#define	RSR_FOE		0x01U	/* fifo overflow error */

#define	RSR_BITS	\
	"\020"		\
	"\010RF"	\
	"\007MF"	\
	"\006LCS"	\
	"\005RWTO"	\
	"\004PLE"	\
	"\003AE"	\
	"\002CE"	\
	"\001FOE"

/* receive overflow counter register */
#define	ROCR_RXFU	0x80U	/* receive overflow counter overflow */
#define	ROCR_ROC	0x7fU	/* receive overflow counter */

#define	ROCR_BITS	\
	"\020"		\
	"\010RXFU"

/* back pressure threshold register */
#define	BPTR_BPHW	0xf0U	/* high water overflow threshold */
#define		BPTR_BPHW_SHIFT	4
#define		BPTR_BPHW_UNIT	1024U
#define		BPTR_BPHW_DEFAULT	(3 << BPTR_BPHW_SHIFT)	/* 3k */
#define	BPTR_JPT	0x0fU	/* jam pattern time */
#define		BPTR_JPT_SHIFT	0
#define		BPTR_JPT_5us	(0U << BPTR_JPT_SHIFT)
#define		BPTR_JPT_10us	(1U << BPTR_JPT_SHIFT)
#define		BPTR_JPT_15us	(2U << BPTR_JPT_SHIFT)
#define		BPTR_JPT_25us	(3U << BPTR_JPT_SHIFT)
#define		BPTR_JPT_50us	(4U << BPTR_JPT_SHIFT)
#define		BPTR_JPT_100us	(5U << BPTR_JPT_SHIFT)
#define		BPTR_JPT_150us	(6U << BPTR_JPT_SHIFT)
#define		BPTR_JPT_200us	(7U << BPTR_JPT_SHIFT)
#define		BPTR_JPT_250us	(8U << BPTR_JPT_SHIFT)
#define		BPTR_JPT_300us	(9U << BPTR_JPT_SHIFT)
#define		BPTR_JPT_350us	(10U << BPTR_JPT_SHIFT)
#define		BPTR_JPT_400us	(11U << BPTR_JPT_SHIFT)
#define		BPTR_JPT_450us	(12U << BPTR_JPT_SHIFT)
#define		BPTR_JPT_500us	(13U << BPTR_JPT_SHIFT)
#define		BPTR_JPT_550us	(14U << BPTR_JPT_SHIFT)
#define		BPTR_JPT_600us	(15U << BPTR_JPT_SHIFT)

/* flow control threshold register */
#define	FCTR_HWOT	0xf0U	/* rx fifo high water overflow threshold */
#define		FCTR_HWOT_SHIFT	4
#define		FCTR_HWOT_UNIT	1024U
#define	FCTR_LWOT	0x0fU	/* rx fifo low water overflow threshold */
#define		FCTR_LWOT_SHIFT	0
#define		FCTR_LWOT_UNIT	1024U

/* rx/tx flow control register */
#define	FCR_TXPO	0x80U	/* tx pause packet */
#define	FCR_TXPF	0x40U	/* tx pause packet */
#define	FCR_TXPEN	0x20U	/* tx pause packet */
#define	FCR_BKPA	0x10U	/* back pressure mode */
#define	FCR_BKPM	0x08U	/* back pressure mode */
#define	FCR_BKPS	0x04U	/* rx pause packet current status (r/c) */
#define	FCR_RXPCS	0x02U	/* rx pause packet current status (ro) */
#define	FCR_FLCE	0x01U	/* flow control enbale */

#define	FCR_BITS	\
	"\020"		\
	"\000TXPO"	\
	"\000TXPF"	\
	"\000TXPEN"	\
	"\000BKPA"	\
	"\000BKPM"	\
	"\000BKPS"	\
	"\000RXPCS"	\
	"\000FLCE"

/* EEPROM & PHY control register (0x0b) */
#define	EPCR_REEP	0x20U	/* reload eeprom */
#define	EPCR_WEP	0x10U	/* write eeprom enable */
#define	EPCR_EPOS	0x08U	/* select device, 0:eeprom, 1:phy */
#define	EPCR_ERPRR	0x04U	/* read command */
#define	EPCR_ERPRW	0x02U	/* write command */
#define	EPCR_ERRE	0x01U	/* eeprom/phy access in progress (ro) */

#define	EPCR_BITS	\
	"\020"		\
	"\005REEP"	\
	"\004WEP"	\
	"\003EPOS"	\
	"\002ERPRR"	\
	"\001ERPRW"	\
	"\000ERRE"

/* EEPROM & PHY access register (0x0c) */
#define	EPAR_PHYADR	0xc0U	/* phy address, internal phy(1) or external */
#define		EPAR_PHYADR_SHIFT	6
#define	EPAR_EROA	0x3fU	/* eeprom word addr or phy register addr */
#define		EPAR_EROA_SHIFT	0

/* EEPROM & PHY data register (0x0d(low)-0x0e(hi)) */

/* wake up control register (0x0f) */
#define	WCR_LINKEN	0x20U	/* enable link status event */
#define	WCR_SAMPLEEN	0x10U	/* enable sample frame event */
#define	WCR_MAGICEN	0x08U	/* enable magic pkt event */
#define	WCR_LINKST	0x04U	/* link status change occur ro */
#define	WCR_SAMPLEST	0x02U	/* sample frame rx occur ro */
#define	WCR_MAGICST	0x01U	/* magic pkt rx occur ro */

#define	WCR_BITS	\
	"\020"		\
	"\000LINKEN"	\
	"\000SAMPLEEN"	\
	"\000MAGICEN"	\
	"\000LINKST"	\
	"\000SAMPLEST"	\
	"\000MAGICST"

/* physical address register (0x10-0x15) */
/* multicast address register (0x16-0x1c) */
/* general purpose control register (0x1e) */
#define	GPCR_GEPCTRL	0x7f
#define		GPCR_OUT(n)	(1U << (n))

#define	GPCR_BITS	\
	"\020"		\
	"\006OUT5"	\
	"\005OUT4"	\
	"\004OUT3"	\
	"\003OUT2"	\
	"\002OUT1"	\
	"\001OUT0"

/* general purpose register (0x1f) */
#define	GPR_GEPIO5	0x20U
#define	GPR_GEPIO4	0x10U
#define	GPR_GEPIO3	0x08U
#define	GPR_GEPIO2	0x04U
#define	GPR_GEPIO1	0x02U
#define	GPR_GEPIO0	0x01U

#define	GPR_BITS	\
	"\020"		\
	"\006GEPIO5"	\
	"\005GEPIO4"	\
	"\004GEPIO3"	\
	"\003GEPIO2"	\
	"\002GEPIO1"	\
	"\001GEPIO0"

/* vendor id register (0x28-0x29) */
/* product id register (0x2a-0x2b) */
/* chip revision register (0x2c) */

/* usb device address register (0xf0) */
#define	USBDA_USBFA	0x3fU	/* usb device address */
#define		USBDA_USBFA_SHIFT	0

/* receive packet counter register (0xf1) */

/* transmitpacket counter/usb status register (0xf2) */
#define	TUSR_RXFAULT	0x80U	/* indicate rx has unexpected condition */
#define	TUSR_SUSFLAG	0x40U	/* indicate device has suspended condition */
#define	TUSR_EP1RDY	0x20U	/* ready for read from ep1 pipe */
#define	TUSR_SRAM	0x18U	/* sram size 0:32K, 1:48K, 2:16K, 3:64K */
#define		TUSR_SRAM_SHIFT	3
#define		TUSR_SRAM_32K	(0U << TUSR_SRAM_SHIFT)
#define		TUSR_SRAM_48K	(1U << TUSR_SRAM_SHIFT)
#define		TUSR_SRAM_16K	(2U << TUSR_SRAM_SHIFT)
#define		TUSR_SRAM_64K	(3U << TUSR_SRAM_SHIFT)
#define	TUSR_TXC2	0x04U	/* two or more packets in tx buffer */
#define	TUSR_TXC1	0x02U	/* one packet in tx buffer */
#define	TUSR_TXC0	0x01U	/* no packet in tx buffer */

#define	TUSR_BITS	\
	"\020"		\
	"\010RXFAULT"	\
	"\007SUSFLAG"	\
	"\006EP1RDY"	\
	"\003TXC2"	\
	"\002TXC1"	\
	"\001TXC0"

/* usb control register (0xf4) */
#define	USBC_EP3ACK	0x20U	/* ep3 will alway return 8byte data if NAK=0 */
#define	USBC_EP3NACK	0x10U	/* ep3 will alway return NAK */
#define	USBC_MEMTST	0x01U

/* bulk message format */
#define	TX_HEADER_SIZE	2
#define	RX_HEADER_SIZE	3

/* interrupt msg format */
struct intr_msg {
	uint8_t	im_nsr;
	uint8_t	im_tsr1;
	uint8_t	im_tsr2;
	uint8_t	im_rsr;
	uint8_t	im_rocr;
	uint8_t	im_rxc;
	uint8_t	im_txc;
	uint8_t	im_gpr;
};
#endif /* __DM9601_H__ */
