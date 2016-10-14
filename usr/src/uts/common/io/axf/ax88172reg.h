/*
 * @(#)ax88172reg.h	1.1 09/06/15
 * Macro definitions for ASIX AX88172 USB to fast ethernet controler
 * based on ASIX AX88172/88772 data sheet
 * This file is public domain. Coded by M.Murayama (KHF04453@nifty.com)
 */

#ifndef __AX88172_H__
#define	__AX88172_H__

/*
 * Vendor command definitions
 */
#define	VCMD_READ_SRAM			0x02
#define	VCMD_WRITE_RXSRAM		0x03
#define	VCMD_WRITE_TXSRAM		0x04
#define	VCMD_SOFTWARE_MII_OP		0x06
#define	VCMD_READ_MII_REG		0x07
#define	VCMD_WRITE_MII_REG		0x08
#define	VCMD_READ_MII_OPMODE		0x09
#define	VCMD_HARDWARE_MII_OP		0x0a
#define	VCMD_READ_SROM			0x0b
#define	VCMD_WRITE_SROM			0x0c
#define	VCMD_WRITE_SROM_ENABLE		0x0d
#define	VCMD_WRITE_SROM_DISABLE		0x0e
#define	VCMD_READ_RXCTRL		0x0f
#define	VCMD_WRITE_RXCTRL		0x10
#define	VCMD_READ_IPGS			0x11
#define	VCMD_WRITE_IPG			0x12
#define	VCMD_WRITE_IPG1			0x13
#define	VCMD_WRITE_IPG2			0x14
#define	VCMD_READ_MCAST_FILTER		0x15
#define	VCMD_WRITE_MCAST_FILTER		0x16
#define	VCMD_READ_NODE_ID		0x17
#define	VCMD_READ_PHY_IDS		0x19
#define	VCMD_READ_MEDIUM_STATUS		0x1a
#define	VCMD_WRITE_MEDIUM_STATUS	0x1b
#define	VCMD_SET_MONITOR_MODE		0x1c
#define	VCMD_GET_MONITOR_MODE		0x1d
#define	VCMD_READ_GPIO			0x1e
#define	VCMD_WRITE_GPIO			0x1f

/* ax88772 only,  currently not supported */
#define	VCMD_WRITE_IPGS_88772		0x12
#define	VCMD_READ_NODE_ID_88772		0x13
#define	VCMD_WRITE_NODE_ID_88772	0x14
#define	VCMD_WRITE_TEST_REG_88772	0x17
#define	VCMD_SOFTWARE_RESET_88772	0x20
#define	VCMD_READ_PHY_SELECT_88772	0x21
#define	VCMD_WRITE_PHY_SELECT_88772	0x22


/*
 * Register definitions
 */

/* Rx control register */
#define	RCR_SO		0x80	/* Start Operation */
#define	RCR_AP_88772	0x20	/* accept physical address from mcast filter */
#define	RCR_AM		0x10	/* accept multicast address */
#define	RCR_AB		0x08	/* accept broadcast address */
#define	RCR_SEP		0x04	/* save error packet */
#define	RCR_AMALL	0x02	/* accept all multicast address */
#define	RCR_PRO		0x01	/* promiscious, all frames received */

#define	RCR_MFB	0x0300
#define		RCR_MFB_SHIFT	8
#define		RCR_MFB_2K	(0U << RCR_MFB_SHIFT)
#define		RCR_MFB_4K	(1U << RCR_MFB_SHIFT)
#define		RCR_MFB_8K	(2U << RCR_MFB_SHIFT)
#define		RCR_MFB_16K	(3U << RCR_MFB_SHIFT)

#define	RCR_BITS	\
	"\020"	\
	"\010SO"	\
	"\006AP"	\
	"\005AM"	\
	"\004AB"	\
	"\003SEP"	\
	"\002AMALL"	\
	"\001PRO"

/* Medium status register */
#define	MSR_SM		0x1000	/* super mac support */
#define	MSR_SBP		0x0800	/* stop backpressure */
#define	MSR_PS		0x0200	/* port speed in mii mode */
#define	MSR_RE		0x0100	/* rx enable */
#define	MSR_PF		0x0080	/* check only length/type for pause frame */
#define	MSR_JFE		0x0040	/* jumbo frame enable */
#define	MSR_TFC		0x0020	/* tx flow control enable */
#define	MSR_RFC		0x0010	/* rx flow control enable (178) */
#define	MSR_FCEN	0x0010	/* flow control enable (172/772) */
#define	MSR_ENCK	0x0008	/* Enable GTX_CLK and TXC clock output (178) */
#define	MSR_TXABT	0x0004	/* Tx abort allow, always set */
#define	MSR_FDPX	0x0002	/* full duplex */
#define	MSR_GM		0x0001	/* Gigabit mode (178) */

#define	MSR_BITS	\
	"\020"	\
	"\015SM"	\
	"\014SBP"	\
	"\012PS"	\
	"\011RE"	\
	"\005FCEN"	\
	"\004ENCK"	\
	"\003TXABT"	\
	"\002FDPX"	\
	"\001GM"

/* monitor mode register */
#define	MMR_RWMP	0x04	/* remote wakeup by magic pkt */
#define	MMR_RWLU	0x02	/* remote wakeup by linkup */
#define	MMR_MOM		0x01	/* monitor mode 1:en, 0:dis */

#define	MMR_BITS	\
	"\020"	\
	"\003RWMP"	\
	"\002RWLU"	\
	"\001MOM"

/* GPIO register */
#define	GPIO_RSE	0x80	/* reload serial eeprom (88772) */
#define	GPIO_DATA2	0x20
#define	GPIO_EN2	0x10
#define	GPIO_DATA1	0x08
#define	GPIO_EN1	0x04
#define	GPIO_DATA0	0x02
#define	GPIO_EN0	0x01

#define	GPIO_BITS	\
	"\020"		\
	"\010RSE"	\
	"\006DATA2"	\
	"\005EN2"	\
	"\004DATA1"	\
	"\003EN1"	\
	"\002DATA0"	\
	"\001EN0"

/* Software reset register */
#define	SWRST_IPPD	0x40	/* internal phy power down control */
#define	SWRST_IPRL	0x20	/* internal phy reset control */
#define	SWRST_BZ	0x10	/* force Bulk In to return zero-length pkt */
#define	SWRST_PRL	0x08	/* external phy reset pin level */
#define	SWRST_PRTE	0x04	/* external phy tri-state enable */
#define	SWRST_RT	0x02	/* clear frame length error for Bulk-Out */
#define	SWRST_RR	0x01	/* clear frame length error for Bulk-In */

#define	SWRST_BITS	\
	"\020"		\
	"\007IPPD"	\
	"\006IPRL"	\
	"\005BZ"	\
	"\004PRL"	\
	"\003PRTE"	\
	"\002RT"	\
	"\001RR"

/* Software PHY Select Status register */
#define	SPSS_ASEL	0x02	/* 1:auto select 0:manual select */
#define	SPSS_PSEL	0x01	/* 1:intenal phy, 0:external (when ASEL=0) */

#endif /* __AX88172_H__ */
