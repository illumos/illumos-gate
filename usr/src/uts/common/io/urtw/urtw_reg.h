/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2008 Weongyo Jeong
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    similar to the "NO WARRANTY" disclaimer below ("Disclaimer") and any
 *    redistribution must be conditioned upon including a substantially
 *    similar Disclaimer requirement for further binary redistribution.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF NONINFRINGEMENT, MERCHANTIBILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGES.
 */

#ifndef _URTW_REG_H
#define	_URTW_REG_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Known hardware revisions.
 */
#define	URTW_HWREV_8187			0x01
#define	URTW_HWREV_8187_B		0x02
#define	URTW_HWREV_8187_D		0x04
#define	URTW_HWREV_8187B		0x08
#define	URTW_HWREV_8187B_B		0x10
#define	URTW_HWREV_8187B_D		0x20
#define	URTW_HWREV_8187B_E		0x40

/* for 8187  */
#define	URTW_MAC0			0x0000		/* 1 byte  */
#define	URTW_MAC1			0x0001		/* 1 byte  */
#define	URTW_MAC2			0x0002		/* 1 byte  */
#define	URTW_MAC3			0x0003		/* 1 byte  */
#define	URTW_MAC4			0x0004		/* 1 byte  */
#define	URTW_MAC5			0x0005		/* 1 byte  */
#define	URTW_BRSR			0x002c		/* 2 byte  */
#define	URTW_BRSR_MBR_8185		(0x0fff)
#define	URTW_8187B_EIFS			0x002d		/* 1 byte */
#define	URTW_BSSID			0x002e		/* 6 byte  */
#define	URTW_RESP_RATE			0x0034		/* 1 byte  */
#define	URTW_8187B_BRSR			0x0034		/* 2 byte */
#define	URTW_RESP_MAX_RATE_SHIFT	(4)
#define	URTW_RESP_MIN_RATE_SHIFT	(0)
#define	URTW_EIFS			0x0035		/* 1 byte  */
#define	URTW_INTR_MASK			0x003c		/* 2 byte  */
#define	URTW_CMD			0x0037		/* 1 byte  */
#define	URTW_CMD_TX_ENABLE		(0x4)
#define	URTW_CMD_RX_ENABLE		(0x8)
#define	URTW_CMD_RST			(0x10)
#define	URTW_TX_CONF			0x0040		/* 4 byte  */

#define	URTW_TX_HWREV_MASK		(7 << 25)
#define	URTW_TX_HWREV_8187_D	(5 << 25)
#define	URTW_TX_HWREV_8187B_D	(6 << 25)
#define	URTW_TX_DURPROCMODE		(1 << 30)
#define	URTW_TX_DISREQQSIZE		(1 << 28)
#define	URTW_TX_SHORTRETRY		(7 << 8)
#define	URTW_TX_LONGRETRY		(7 << 0)

#define	URTW_TX_LOOPBACK_SHIFT		(17)
#define	URTW_TX_LOOPBACK_NONE		(0 << URTW_TX_LOOPBACK_SHIFT)
#define	URTW_TX_LOOPBACK_MAC		(1 << URTW_TX_LOOPBACK_SHIFT)
#define	URTW_TX_LOOPBACK_BASEBAND	(2 << URTW_TX_LOOPBACK_SHIFT)
#define	URTW_TX_LOOPBACK_CONTINUE	(3 << URTW_TX_LOOPBACK_SHIFT)
#define	URTW_TX_LOOPBACK_MASK		(0x60000)
#define	URTW_TX_DPRETRY_MASK		(0xff00)
#define	URTW_TX_RTSRETRY_MASK		(0xff)
#define	URTW_TX_DPRETRY_SHIFT		(0)
#define	URTW_TX_RTSRETRY_SHIFT		(8)
#define	URTW_TX_NOCRC			(0x10000)
#define	URTW_TX_MXDMA_MASK		(0xe00000)
#define	URTW_TX_MXDMA_1024		(6 << URTW_TX_MXDMA_SHIFT)
#define	URTW_TX_MXDMA_2048		(7 << URTW_TX_MXDMA_SHIFT)
#define	URTW_TX_MXDMA_SHIFT		(21)
#define	URTW_TX_CWMIN			(0x80000000)
#define	URTW_TX_DISCW			(1 << 20)
#define	URTW_TX_SWPLCPLEN		(1 << 24)
#define	URTW_TX_NOICV			(0x80000)
#define	URTW_RX				0x0044		/* 4 byte  */
#define	URTW_RX_9356SEL			(1 << 6)
#define	URTW_RX_FILTER_MASK			\
	(URTW_RX_FILTER_ALLMAC | URTW_RX_FILTER_NICMAC |\
	URTW_RX_FILTER_MCAST | \
	URTW_RX_FILTER_BCAST | URTW_RX_FILTER_CRCERR |\
	URTW_RX_FILTER_ICVERR | \
	URTW_RX_FILTER_DATA | URTW_RX_FILTER_CTL |\
	URTW_RX_FILTER_MNG |	\
	(1 << 21) |\
	URTW_RX_FILTER_PWR | URTW_RX_CHECK_BSSID)
#define	URTW_RX_FILTER_ALLMAC		(0x00000001)
#define	URTW_RX_FILTER_NICMAC		(0x00000002)
#define	URTW_RX_FILTER_MCAST		(0x00000004)
#define	URTW_RX_FILTER_BCAST		(0x00000008)
#define	URTW_RX_FILTER_CRCERR		(0x00000020)
#define	URTW_RX_FILTER_ICVERR		(0x00001000)
#define	URTW_RX_FILTER_DATA		(0x00040000)
#define	URTW_RX_FILTER_CTL		(0x00080000)
#define	URTW_RX_FILTER_MNG		(0x00100000)
#define	URTW_RX_FILTER_PWR		(0x00400000)
#define	URTW_RX_CHECK_BSSID		(0x00800000)
#define	URTW_RX_FIFO_THRESHOLD_MASK	((1 << 13) | (1 << 14) | (1 << 15))
#define	URTW_RX_FIFO_THRESHOLD_SHIFT	(13)
#define	URTW_RX_FIFO_THRESHOLD_128	(3)
#define	URTW_RX_FIFO_THRESHOLD_256	(4)
#define	URTW_RX_FIFO_THRESHOLD_512	(5)
#define	URTW_RX_FIFO_THRESHOLD_1024	(6)
#define	URTW_RX_FIFO_THRESHOLD_NONE	(7 << URTW_RX_FIFO_THRESHOLD_SHIFT)
#define	URTW_RX_AUTORESETPHY		(1 << URTW_RX_AUTORESETPHY_SHIFT)
#define	URTW_RX_AUTORESETPHY_SHIFT	(28)
#define	URTW_MAX_RX_DMA_MASK		((1<<8) | (1<<9) | (1<<10))
#define	URTW_MAX_RX_DMA_2048		(0x1c00)
#define	URTW_MAX_RX_DMA_1024		(6)
#define	URTW_MAX_RX_DMA_SHIFT		(10)
#define	URTW_RCR_ONLYERLPKT		(0x80000000)
#define	URTW_INT_TIMEOUT		0x0048		/* 4 byte  */
#define	URTW_EPROM_CMD			0x0050		/* 1 byte  */
#define	URTW_EPROM_CMD_NORMAL		(0x0)
#define	URTW_EPROM_CMD_NORMAL_MODE				\
	(URTW_EPROM_CMD_NORMAL << URTW_EPROM_CMD_SHIFT)
#define	URTW_EPROM_CMD_LOAD		(0x1)
#define	URTW_EPROM_CMD_PROGRAM		(0x2)
#define	URTW_EPROM_CMD_PROGRAM_MODE				\
	(URTW_EPROM_CMD_PROGRAM << URTW_EPROM_CMD_SHIFT)
#define	URTW_EPROM_CMD_CONFIG		(0x3)
#define	URTW_EPROM_CMD_SHIFT		(6)
#define	URTW_EPROM_CMD_MASK		((1 << 7) | (1 << 6))
#define	URTW_EPROM_READBIT		(0x1)
#define	URTW_EPROM_WRITEBIT		(0x2)
#define	URTW_EPROM_CK			(0x4)
#define	URTW_EPROM_CS			(0x8)

#define	URTW_CONFIG1			0x0052		/* 1 byte */
#define	URTW_CONFIG2			0x0053		/* 1 byte */

#define	URTW_ANAPARAM			0x0054		/* 4 byte  */
#define	URTW_8187_8225_ANAPARAM_ON	(0xa0000a59)
#define	URTW_8187B_8225_ANAPARAM_ON	(0x45090658)

#define	URTW_MSR			0x0058		/* 1 byte  */
#define	URTW_MSR_LINK_MASK		((1 << 2) | (1 << 3))
#define	URTW_MSR_LINK_SHIFT		(2)
#define	URTW_MSR_LINK_NONE		(0 << URTW_MSR_LINK_SHIFT)
#define	URTW_MSR_LINK_ADHOC		(1 << URTW_MSR_LINK_SHIFT)
#define	URTW_MSR_LINK_STA		(2 << URTW_MSR_LINK_SHIFT)
#define	URTW_MSR_LINK_HOSTAP	(3 << URTW_MSR_LINK_SHIFT)
#define	URTW_MSR_LINK_ENEDCA		(4 << URTW_MSR_LINK_SHIFT)


#define	URTW_CONFIG3			0x0059		/* 1 byte  */
#define	URTW_CONFIG3_ANAPARAM_WRITE	(0x40)
#define	URTW_CONFIG3_ANAPARAM_W_SHIFT	(6)
#define	URTW_CONFIG3_GNT_SELECT		(0x80)

#define	URTW_PSR			0x005e		/* 1 byte  */
#define	URTW_ANAPARAM2			0x0060		/* 4 byte  */
#define	URTW_8187_8225_ANAPARAM2_ON	(0x860c7312)
#define	URTW_8187B_8225_ANAPARAM2_ON	(0x727f3f52)

#define	URTW_BEACON_INTERVAL		0x0070		/* 2 byte  */
#define	URTW_ATIM_WND			0x0072		/* 2 byte  */
#define	URTW_BEACON_INTERVAL_TIME	0x0074		/* 2 byte  */
#define	URTW_ATIM_TR_ITV		0x0076		/* 2 byte  */
#define	URTW_RF_PINS_OUTPUT		0x0080		/* 2 byte  */
#define	URTW_BB_HOST_BANG_CLK		(1 << 1)
#define	URTW_BB_HOST_BANG_EN		(1 << 2)
#define	URTW_BB_HOST_BANG_RW		(1 << 3)
#define	URTW_RF_PINS_ENABLE		0x0082		/* 2 byte  */
#define	URTW_RF_PINS_SELECT		0x0084		/* 2 byte  */
#define	URTW_RF_PINS_INPUT		0x0086		/* 2 byte  */
#define	URTW_RF_PARA			0x0088		/* 4 byte  */
#define	URTW_RF_TIMING			0x008c		/* 4 byte  */
#define	URTW_GP_ENABLE			0x0090		/* 1 byte  */
#define	URTW_GPIO			0x0091		/* 1 byte  */
#define	URTW_HSSI_PARA			0x0094

#define	URTW_TX_AGC_CTL			0x009c		/* 1 byte  */
#define	URTW_TX_AGC_CTL_PERPACKET_GAIN	(0x1)
#define	URTW_TX_AGC_CTL_PERPACKET_ANTSEL	(0x2)
#define	URTW_TX_AGC_CTL_FEEDBACK_ANT	(0x4)
#define	URTW_TX_GAIN_CCK		0x009d		/* 1 byte  */
#define	URTW_TX_GAIN_OFDM		0x009e		/* 1 byte  */
#define	URTW_TX_ANTENNA			0x009f		/* 1 byte  */
#define	URTW_WPA_CONFIG			0x00b0		/* 1 byte  */
#define	URTW_SIFS			0x00b4		/* 1 byte  */
#define	URTW_DIFS			0x00b5		/* 1 byte  */
#define	URTW_SLOT			0x00b6		/* 1 byte  */
#define	URTW_CW_CONF			0x00bc		/* 1 byte  */
#define	URTW_CW_CONF_PERPACKET_RETRY	(0x2)
#define	URTW_CW_CONF_PERPACKET_CW	(0x1)
#define	URTW_CW_VAL			0x00bd		/* 1 byte  */
#define	URTW_RATE_FALLBACK		0x00be		/* 1 byte  */

#define	URTW_RATE_FALLBACK_ENABLE	(0x80)
#define	URTW_ACM_CONTROL		0x00bf		/* 1 byte */
#define	URTW_8187B_HWREV		0x00e1		/* 1 byte */
#define	URTW_8187B_HWREV_8187B_B	(0x0)
#define	URTW_8187B_HWREV_8187B_D	(0x1)
#define	URTW_8187B_HWREV_8187B_E	(0x2)
#define	URTW_INT_MIG			0x00e2		/* 2 byte */
#define	URTW_TID_AC_MAP			0x00e8		/* 2 byte */
#define	URTW_ANAPARAM3			0x00ee		/* 4 byte */
#define	URTW_8187B_8225_ANAPARAM3_ON	(0x0)
#define	URTW_TALLY_SEL			0x00fc		/* 1 byte */
#define	URTW_AC_VO			0x00f0		/* 1 byte */
#define	URTW_AC_VI			0x00f4		/* 1 byte */
#define	URTW_AC_BE			0x00f8		/* 1 byte */
#define	URTW_AC_BK			0x00fc		/* 1 byte */
#define	URTW_FEMR			0x01d4		/* 2 byte */
#define	URTW_ARFR			0x01e0		/* 2 byte */
#define	URTW_RFSW_CTRL			0x0272		/* 2 byte */

/* for EEPROM  */
#define	URTW_EPROM_TXPW_BASE		0x05
#define	URTW_EPROM_RFCHIPID		0x06
#define	URTW_EPROM_RFCHIPID_RTL8225U	(5)
#define	URTW_EPROM_MACADDR		0x07
#define	URTW_EPROM_TXPW0		0x16
#define	URTW_EPROM_TXPW2		0x1b
#define	URTW_EPROM_TXPW1		0x3d
#define	URTW_EPROM_SWREV		0x3f
#define	URTW_EPROM_CID_MASK		(0xff)
#define	URTW_EPROM_CID_RSVD0		(0x00)
#define	URTW_EPROM_CID_RSVD1		(0xff)
#define	URTW_EPROM_CID_ALPHA0		(0x01)
#define	URTW_EPROM_CID_SERCOMM_PS	(0x02)
#define	URTW_EPROM_CID_HW_LED		(0x03)

/* LED  */
#define	URTW_CID_DEFAULT		0
#define	URTW_CID_8187_ALPHA0		1
#define	URTW_CID_8187_SERCOMM_PS	2
#define	URTW_CID_8187_HW_LED		3
#define	URTW_SW_LED_MODE0		0
#define	URTW_SW_LED_MODE1		1
#define	URTW_SW_LED_MODE2		2
#define	URTW_SW_LED_MODE3		3
#define	URTW_HW_LED			4
#define	URTW_LED_CTL_POWER_ON		0
#define	URTW_LED_CTL_LINK		2
#define	URTW_LED_CTL_TX			4
#define	URTW_LED_PIN_GPIO0		0
#define	URTW_LED_PIN_LED0		1
#define	URTW_LED_PIN_LED1		2
#define	URTW_LED_UNKNOWN		0
#define	URTW_LED_ON			1
#define	URTW_LED_OFF			2
#define	URTW_LED_BLINK_NORMAL		3
#define	URTW_LED_BLINK_SLOWLY		4
#define	URTW_LED_POWER_ON_BLINK		5
#define	URTW_LED_SCAN_BLINK		6
#define	URTW_LED_NO_LINK_BLINK		7
#define	URTW_LED_BLINK_CM3		8

/* for extra area  */
#define	URTW_EPROM_DISABLE		0
#define	URTW_EPROM_ENABLE		1
#define	URTW_EPROM_DELAY		10
#define	URTW_8187_GETREGS_REQ		5
#define	URTW_8187_SETREGS_REQ		5
#define	URTW_8225_RF_MAX_SENS		6
#define	URTW_8225_RF_DEF_SENS		4
#define	URTW_DEFAULT_RTS_RETRY		7
#define	URTW_DEFAULT_TX_RETRY		7
#define	URTW_DEFAULT_RTS_THRESHOLD	2342U

#ifdef __cplusplus
}
#endif

#endif /* _URTW_REG_H */
