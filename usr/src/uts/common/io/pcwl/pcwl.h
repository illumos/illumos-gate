/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1997, 1998, 1999
 *      Bill Paul <wpaul@ctr.columbia.edu>.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Bill Paul.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Bill Paul AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Bill Paul OR THE VOICES IN HIS HEAD
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Hardware specific driver declarations for Lucent and PrismII
 * chipsets.
 */

#ifndef _SYS_PCWL_H
#define	_SYS_PCWL_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/list.h>

/*
 * Encryption controls. We can enable or disable encryption as
 * well as specify up to 4 encryption keys. We can also specify
 * which of the four keys will be used for transmit encryption.
 */
#define	WL_RID_ENCRYPTION	0xFC20
#define	WL_RID_ENCRYPTION_P2	0xFC28
#define	WL_RID_DEFLT_CRYPT_KEYS 0xFCB0
#define	WL_RID_CRYPT_KEY0_P2	0xFC24
#define	WL_RID_TX_CRYPT_KEY	0xFCB1
#define	WL_RID_TX_CRYPT_KEY_P2	0xFC23
#define	WL_RID_COMP_IDENT	0xFD20	/* version */
#define	WL_RID_WEP_AVAIL	0xFD4F

#define	WL_RID_AUTHTYPE_P2	0xFC2A	/* PRISM-II */
#define	WL_RID_AUTHTYPE_L	0xFC21	/* 0xFC21 on Lucent */
#define	WL_AUTHTYPE_SYS_P2	0x1
#define	WL_AUTHTYPE_KEY_P2	0x2
#define	WL_AUTHTYPE_ALL_P2	(WL_AUTHTYPE_SYS_P2 | WL_AUTHTYPE_KEY_P2)

#define	WL_SPEED_1Mbps_P2	0x1
#define	WL_SPEED_2Mbps_P2	0x2
#define	WL_SPEED_55Mbps_P2	0x4
#define	WL_SPEED_11Mbps_P2	0x8

/*
 * PrismII Tx rate
 */
#define	WL_P_TX_RATE_FIX_1M	WL_SPEED_1Mbps_P2
#define	WL_P_TX_RATE_FIX_2M	WL_SPEED_2Mbps_P2
#define	WL_P_TX_RATE_FIX_5M	WL_SPEED_55Mbps_P2
#define	WL_P_TX_RATE_FIX_11M	WL_SPEED_11Mbps_P2
#define	WL_P_TX_RATE_AUTO_H	\
	(WL_SPEED_11Mbps_P2 | WL_SPEED_55Mbps_P2 | \
	WL_SPEED_2Mbps_P2 | WL_SPEED_1Mbps_P2)
#define	WL_P_TX_RATE_AUTO_M	\
	(WL_SPEED_55Mbps_P2 | WL_SPEED_2Mbps_P2 | \
	WL_SPEED_1Mbps_P2)
#define	WL_P_TX_RATE_AUTO_L	\
	(WL_SPEED_2Mbps_P2 | WL_SPEED_1Mbps_P2)


#define	WL_TIMEOUT	500000

/*
 * Default port: 0 (only 0 exists on stations)
 */
#define	WL_DEFAULT_PORT		0

/*
 * Lucent TX rate: Default 11Mbps
 */
#define	WL_L_TX_RATE_FIX_1M	1
#define	WL_L_TX_RATE_FIX_2M	2
#define	WL_L_TX_RATE_AUTO_H	3
#define	WL_L_TX_RATE_FIX_5M	4 /* 5.5M */
#define	WL_L_TX_RATE_FIX_11M	5
#define	WL_L_TX_RATE_AUTO_L	6
#define	WL_L_TX_RATE_AUTO_M	7

#define	WL_TX_RATE_FIX_1M(p) \
	(p->pcwl_chip_type == PCWL_CHIP_PRISMII ? \
	WL_P_TX_RATE_FIX_1M : WL_L_TX_RATE_FIX_1M)
#define	WL_TX_RATE_FIX_2M(p) \
	(p->pcwl_chip_type == PCWL_CHIP_PRISMII ? \
	WL_P_TX_RATE_FIX_2M : WL_L_TX_RATE_FIX_2M)
#define	WL_TX_RATE_AUTO_H(p) \
	(p->pcwl_chip_type == PCWL_CHIP_PRISMII ? \
	WL_P_TX_RATE_AUTO_H : WL_L_TX_RATE_AUTO_H)
#define	WL_TX_RATE_FIX_5M(p) \
	(p->pcwl_chip_type == PCWL_CHIP_PRISMII ? \
	WL_P_TX_RATE_FIX_5M : WL_L_TX_RATE_FIX_5M)
#define	WL_TX_RATE_FIX_11M(p) \
	(p->pcwl_chip_type == PCWL_CHIP_PRISMII ? \
	WL_P_TX_RATE_FIX_11M : WL_L_TX_RATE_FIX_11M)
#define	WL_TX_RATE_AUTO_L(p) \
	(p->pcwl_chip_type == PCWL_CHIP_PRISMII ? \
	WL_P_TX_RATE_AUTO_L : WL_L_TX_RATE_AUTO_L)
#define	WL_TX_RATE_AUTO_M(p) \
	(p->pcwl_chip_type == PCWL_CHIP_PRISMII ? \
	WL_P_TX_RATE_AUTO_M : WL_L_TX_RATE_AUTO_M)

/*
 * Default network name: empty string implies any
 */
#define	WL_DEFAULT_NETNAME	("")
#define	WL_DEFAULT_NODENAME	("solaris node")
#define	WL_DEFAULT_AP_DENSITY	1
#define	WL_DEFAULT_RTS_THRESH	2347
#define	WL_DEFAULT_DATALEN	2304
#define	WL_DEFAULT_CREATE_IBSS	0
#define	WL_DEFAULT_PM_ENABLED	0
#define	WL_DEFAULT_MAX_SLEEP	100
#define	WL_DEFAULT_CHAN		3
#define	WL_DEFAULT_TX_CRYPT_KEY	0

/*
 * Size of Hermes I/O space.
 */
#define	WL_IOSIZ	0x40

/*
 * Hermes command/status registers.
 */
#define	WL_COMMAND	0x00
#define	WL_PARAM0	0x02
#define	WL_PARAM1	0x04
#define	WL_PARAM2	0x06
#define	WL_STATUS	0x08
#define	WL_RESP0	0x0A
#define	WL_RESP1	0x0C
#define	WL_RESP2	0x0E

/*
 * Command register values.
 */
#define	WL_CMD_BUSY		0x8000 /* busy bit */
#define	WL_CMD_INI		0x0000 /* initialize */
#define	WL_CMD_ENABLE		0x0001 /* enable */
#define	WL_CMD_DISABLE		0x0002 /* disable */
#define	WL_CMD_DIAG		0x0003
#define	WL_CMD_ALLOC_MEM	0x000A /* allocate NIC memory */
#define	WL_CMD_TX		0x000B /* transmit */
#define	WL_CMD_NOTIFY		0x0010
#define	WL_CMD_INQUIRE		0x0011
#define	WL_CMD_ACCESS		0x0021
#define	WL_CMD_PROGRAM		0x0022

#define	WL_CMD_CODE_MASK	0x003F

/*
 * Reclaim qualifier bit, applicable to the
 * TX and INQUIRE commands.
 */
#define	WL_RECLAIM		0x0100 /* reclaim NIC memory */

/*
 * ACCESS command qualifier bits.
 */
#define	WL_ACCESS_READ		0x0000
#define	WL_ACCESS_WRITE		0x0100

/*
 * PROGRAM command qualifier bits.
 */
#define	WL_PROGRAM_DISABLE	0x0000
#define	WL_PROGRAM_ENABLE_RAM	0x0100
#define	WL_PROGRAM_ENABLE_NVRAM	0x0200
#define	WL_PROGRAM_NVRAM	0x0300

/*
 * Status register values
 */
#define	WL_STAT_CMD_CODE	0x003F
#define	WL_STAT_DIAG_ERR	0x0100
#define	WL_STAT_INQ_ERR		0x0500
#define	WL_STAT_CMD_RESULT	0x7F00

/*
 * memory handle management registers
 */
#define	WL_INFO_FID		0x10
#define	WL_RX_FID		0x20
#define	WL_ALLOC_FID		0x22
#define	WL_TX_CMP_FID		0x24

#define	WL_INVALID_FID		0xffff

/*
 * Buffer Access Path (BAP) registers.
 * These are I/O channels.  you can use each one for
 * any desired purpose independently of the other. In general
 * though, we use BAP1 for reading and writing LTV records and
 * reading received data frames, and BAP0 for writing transmit
 * frames. This is a convention though, not a rule.
 * For PrismII chip, frequently overlap between BAP0 and BAP1
 * may hang the hardware. this is a known bug, so just use BAP1
 * for PrismII.
 */
#define	WL_SEL0			0x18
#define	WL_SEL1			0x1A
#define	WL_OFF0			0x1C
#define	WL_OFF1			0x1E
#define	WL_DATA0		0x36
#define	WL_DATA1		0x38
#define	WL_BAP0			WL_DATA0
#define	WL_BAP1			WL_DATA1

#define	WL_OFF_BUSY		0x8000
#define	WL_OFF_ERR		0x4000
#define	WL_OFF_DATAOFF		0x0FFF

/*
 * Event registers
 */
#define	WL_EVENT_STAT		0x30	/* Event status */
#define	WL_INT_EN		0x32	/* Interrupt enable/disable */
#define	WL_EVENT_ACK		0x34	/* Ack event */

/*
 * Events
 */
#define	WL_EV_TICK		0x8000	/* aux timer tick */
#define	WL_EV_RES		0x4000	/* controller h/w error (time out) */
#define	WL_EV_INFO_DROP		0x2000	/* no RAM to build unsolicited frame */
#define	WL_EV_NO_CARD		0x0800	/* card removed (hunh?) */
#define	WL_EV_DUIF_RX		0x0400	/* wavelan management packet received */
#define	WL_EV_INFO		0x0080	/* async info frame */
#define	WL_EV_CMD		0x0010	/* command completed */
#define	WL_EV_ALLOC		0x0008	/* async alloc/reclaim completed */
#define	WL_EV_TX_EXC		0x0004	/* async xmit completed with failure */
#define	WL_EV_TX		0x0002	/* async xmit completed succesfully */
#define	WL_EV_RX		0x0001	/* async rx completed */

#define	WL_EV_ALL		0xffff	/* all events */
#define	WL_INTRS	\
	(WL_EV_RX|WL_EV_TX|WL_EV_TX_EXC|WL_EV_ALLOC|WL_EV_INFO|WL_EV_INFO_DROP)

/*
 * Host software registers
 */
#define	WL_SW0			0x28
#define	WL_SW1			0x2A
#define	WL_SW2			0x2C
#define	WL_SW3			0x2E

#define	WL_CNTL			0x14

#define	WL_CNTL_AUX_ENA		0xC000
#define	WL_CNTL_AUX_ENA_STAT	0xC000
#define	WL_CNTL_AUX_DIS_STAT	0x0000
#define	WL_CNTL_AUX_ENA_CNTL	0x8000
#define	WL_CNTL_AUX_DIS_CNTL	0x4000

#define	WL_AUX_PAGE		0x3A
#define	WL_AUX_OFFSET		0x3C
#define	WL_AUX_DATA		0x3E

#define	WL_RID_DNLD_BUF		0xFD01

/*
 * Mem sizes (0xFD02).
 */
#define	WL_RID_MEMSZ		0xFD02
#define	WL_RID_FWIDENT_P2	0xFD02

/*
 * NIC Identification (0xFD0B).
 */
#define	WL_RID_CARD_ID	0xFD0B

typedef struct pcwl_ltv_ver {
	uint16_t	wl_compid;
	uint16_t	wl_variant;
	uint16_t	wl_major;
	uint16_t	wl_minor;
} pcwl_ltv_ver_t;

#define	WL_RID_FWVER	0xFFFF
typedef struct pcwl_ltv_fwver {
	uint16_t	pri[7];
	uint16_t	st[7];
} pcwl_ltv_fwver_t;

#define	WI_NIC_EVB2	0x8000
#define	WI_NIC_HWB3763	0x8001
#define	WI_NIC_HWB3163	0x8002
#define	WI_NIC_HWB3163B	0x8003
#define	WI_NIC_EVB3	0x8004
#define	WI_NIC_HWB1153	0x8007
#define	WI_NIC_P2_SST	0x8008	/* Prism2 with SST flush */
#define	WI_NIC_PRISM2_5	0x800C
#define	WI_NIC_3874A	0x8013	/* Prism2.5 Mini-PCI */

/*
 * List of intended regulatory domains (0xFD11).
 */
#define	WL_RID_DOMAINS		0xFD11
/*
 * CIS struct (0xFD13).
 */
#define	WL_RID_CIS		0xFD13

/*
 * Current MAC port connection status
 */
#define	WL_RID_PORTSTATUS	0xFD40
#define	WL_PORT_DISABLED	1
#define	WL_PORT_INITIAL		2
#define	WL_PORT_TO_IBSS		3
#define	WL_PORT_TO_BSS		4
#define	WL_PORT_OOR		5
#define	WL_PORT_RADIO_OFF	7 /* only for miniPci */

/*
 * Current Service Set the station is connected to
 */
#define	WL_RID_SSID		0xFD41

/*
 * MAC address used as identifier of the BSS the station
 * is connected to
 */
#define	WL_RID_BSSID		0xFD42

/*
 * Communications quality (0xFD43).
 */
#define	WL_RID_COMMQUAL		0xFD43

/*
 * Actual system scale thresholds (0xFD46).
 */
#define	WL_RID_SYSTEM_SCALE	0xFC06

/*
 * Actual current transmission rate
 */
#define	WL_RID_CUR_TX_RATE	0xFD44

/*
 * Connection control characteristics.
 * 1 == Basic Service Set (BSS), a.k.a IEEE 802.11 Infrastructure
 * 2 == Wireless Distribudion System (WDS), Access Point only
 * 3 == Pseudo IBSS / Ad Hoc
 */
#define	WL_RID_PORTTYPE		0xFC00
#define	WL_PORTTYPE_BSS		0x1
#define	WL_PORTTYPE_WDS		0x2
#define	WL_PORTTYPE_ADHOC	0x3

/*
 * Mac addresses.
 */
#define	WL_RID_MAC_NODE		0xFC01
#define	WL_RID_MAC_WDS		0xFC08

/*
 * Station set identification (SSID).
 */
#define	WL_RID_DESIRED_SSID	0xFC02
#define	WL_RID_OWN_SSID		0xFC04

/*
 * Set communications channel (radio frequency).
 */
#define	WL_RID_OWN_CHNL		0xFC03
#define	WL_RID_CURRENT_CHNL	0xFDC1

/*
 * Frame data size.
 */
#define	WL_RID_MAX_DATALEN	0xFC07

/*
 * ESS power management enable
 */
#define	WL_RID_PM_ENABLED	0xFC09

/*
 * ESS max PM sleep internal
 */
#define	WL_RID_MAX_SLEEP	0xFC0C

/*
 * Set our station name.
 */
#define	WL_RID_NODENAME		0xFC0E

/*
 * Multicast addresses to be put in filter. We're
 * allowed up to 16 addresses in the filter.
 */
#define	WL_RID_MCAST		0xFC80

/*
 * Create IBSS.
 */
#define	WL_RID_CREATE_IBSS	0xFC81

#define	WL_RID_FRAG_THRESH	0xFC82
#define	WL_RID_RTS_THRESH	0xFC83

/*
 * TX rate control
 * 0 == Fixed 1mbps
 * 1 == Fixed 2mbps
 * 2 == auto fallback
 */
#define	WL_RID_TX_RATE		0xFC84

/*
 * promiscuous mode.
 */
#define	WL_RID_PROMISC		0xFC85

/*
 * scan ssid
 */
#define	WL_RID_SCAN_SSID	0xFCB2

/*
 * Auxiliary Timer tick interval
 */
#define	WL_RID_TICK_TIME	0xFCE0

/*
 * PrismII scan
 */
#define	WL_RID_SCAN_REQUEST	0xFCE1
#define	WL_RID_HSCAN_REQUEST	0xFCE5

/*
 * Information frame types.
 */
#define	WL_INFO_NOTIFY		0xF000	/* Handover address */
#define	WL_INFO_COUNTERS	0xF100	/* Statistics counters */
#define	WL_INFO_SCAN_RESULTS	0xF101	/* Scan results */
#define	WL_INFO_HSCAN_RESULTS	0xF103	/* HostScan results */
#define	WL_INFO_LINK_STAT	0xF200	/* Link status */
#define	WL_INFO_ASSOC_STAT	0xF201	/* Association status */

/*
 * Link status
 */
#define	WL_LINK_CONNECT		1
#define	WL_LINK_DISCONNECT	2
#define	WL_LINK_AP_CR		3 /* AP change */
#define	WL_LINK_AP_OOR		4 /* AP out of range */
#define	WL_LINK_AP_IR		5 /* AP in range */

typedef struct wl_scan_result {
	uint16_t		wl_srt_chid;  /* bss channel id */
	uint16_t		wl_srt_anl;   /* noise level */
	uint16_t		wl_srt_sl;    /* signal level */
	uint8_t			wl_srt_bssid[6];  /* mac address of the bss */
	uint16_t		wl_srt_bcnint; /* bss beacon interval */
	uint16_t		wl_srt_cap;    /* bss capability */

	uint16_t		wl_srt_ssidlen;  /* ssid name length */
	char			wl_srt_ssid[32]; /* ssid */

	uint16_t		wl_srt_suprates[5]; /* supported rates */
	uint16_t		wl_srt_rate; /* actual data rate of the probe */
	uint16_t		wl_srt_atim;
} wl_scan_result_t;

#define	WL_SRT_MAX_NUM		32 /* max number of scan result stored */
#define	WL_SCAN_TIMEOUT_MAX	30 /* seconds after which the scan item ages */
#define	WL_SCAN_AGAIN_THRESHOLD	5 /* threshold below which card scan again */
#define	WL_MAX_SCAN_TIMES	2 /* max scan times per scan command */

typedef struct wl_scan_list {
	wl_scan_result_t	wl_val;
	uint32_t		wl_timeout;
	list_node_t		wl_scan_node;
} wl_scan_list_t;

#define	WL_FTYPE_MGMT		0x0000
#define	WL_FTYPE_CTL		0x0004
#define	WL_FTYPE_DATA		0x0008

/*
 * SNAP (sub-network access protocol) constants for transmission
 * of IP datagrams over IEEE 802 networks, taken from RFC1042.
 * We need these for the LLC/SNAP header fields in the TX/RX frame
 * structure.
 */
#define	WL_SNAP_K1		0xaa	/* assigned global SAP for SNAP */
#define	WL_SNAP_K2		0x00
#define	WL_SNAP_CONTROL		0x03	/* unnumbered information format */
#define	WL_SNAP_WORD0		(WL_SNAP_K1 | (WL_SNAP_K1 << 8))
#define	WL_SNAP_WORD1		(WL_SNAP_K2 | (WL_SNAP_CONTROL << 8))
#define	WL_SNAPHDR_LEN		0x6

/*
 * Hermes transmit/receive frame structure
 */
typedef struct wl_frame {
	uint16_t		wl_status;	/* 0x00 */
	uint16_t		wl_rsvd0;	/* 0x02 */
	uint16_t		wl_rsvd1;	/* 0x04 */
	uint16_t		wl_q_info;	/* 0x06 */
	uint16_t		wl_rsvd2;	/* 0x08 */
	uint16_t		wl_rsvd3;	/* 0x0A */
	uint16_t		wl_tx_ctl;	/* 0x0C */
	uint16_t		wl_frame_ctl;	/* 0x0E */
	uint16_t		wl_id;		/* 0x10 */
	uint8_t			wl_addr1[6];	/* 0x12 */
	uint8_t			wl_addr2[6];	/* 0x18 */
	uint8_t			wl_addr3[6];	/* 0x1E */
	uint16_t		wl_seq_ctl;	/* 0x24 */
	uint8_t			wl_addr4[6];	/* 0x26 */
	uint16_t		wl_dat_len;	/* 0x2C */

	uint8_t			wl_dst_addr[6];	/* 0x2E */
	uint8_t			wl_src_addr[6];	/* 0x34 */
	uint16_t		wl_len;		/* 0x3A */
	uint16_t		wl_dat[3];	/* 0x3C */ /* SNAP header */
	uint16_t		wl_type;	/* 0x42 */
} wl_frame_t;

static wl_frame_t wl_frame_default = {
	0,			/* wl_status	   0x00 */
	0,			/* wl_rsvd0	   0x02 */
	0,			/* wl_rsvd1	   0x04 */
	0,			/* wl_q_info	   0x06 */
	0,			/* wl_rsvd2	   0x08 */
	0,			/* wl_rsvd3	   0x0A */
	0,			/* wl_tx_ctl	   0x0C */
	WL_FTYPE_DATA,		/* wl_frame_ctl	   0x0E */
	0,			/* wl_id	   0x10 */
	{ 0, 0, 0, 0, 0, 0 },	/* wl_addr1[6]	   0x12 */
	{ 0, 0, 0, 0, 0, 0 },	/* wl_addr2[6]	   0x18 */
	{ 0, 0, 0, 0, 0, 0 },	/* wl_addr3[6]	   0x1E */
	0,			/* wl_seq_ctl	   0x24 */
	{ 0, 0, 0, 0, 0, 0 },	/* wl_addr4[6]	   0x26 */
	(uint16_t)-WL_SNAPHDR_LEN, /* wl_dat_len	   0x2C */

	{ 0, 0, 0, 0, 0, 0 },	/* wl_dst_addr[6]  0x2E */
	{ 0, 0, 0, 0, 0, 0 },	/* wl_src_addr[6]  0x34 */
	(uint16_t)-WL_SNAPHDR_LEN, /* wl_len	   0x3A */
	{ WL_SNAP_WORD0,
	WL_SNAP_WORD1, 0 },	/* wl_dat[3]	   0x3C */ /* SNAP header */
	0			/* wl_type	   0x42 */
};

#define	MLEN(mp)		((mp)->b_wptr - (mp)->b_rptr)
#define	ETH_HDRLEN		(sizeof (struct ether_header))
#define	WL_802_3_HDRLEN		0x2E
#define	WL_802_11_HDRLEN	0x44
#define	WL_802_11_RAW_HDRLEN	0x3C

#define	WL_STAT_BADCRC		0x0001
#define	WL_STAT_UNDECRYPTABLE	0x0002
#define	WL_STAT_ERRSTAT		0x0003
#define	WL_STAT_MAC_PORT	0x0700
#define	WL_STAT_1042		0x2000	/* RFC1042 encoded */
#define	WL_STAT_TUNNEL		0x4000	/* Bridge-tunnel encoded */
#define	WL_STAT_WMP_MSG		0x6000	/* WaveLAN-II management protocol */
#define	WL_RXSTAT_MSG_TYPE	0xE000

#define	WL_ENC_TX_802_3		0x00
#define	WL_ENC_TX_802_11	0x11
#define	WL_ENC_TX_E_II		0x0E

#define	WL_ENC_TX_1042		0x00
#define	WL_ENC_TX_TUNNEL	0xF8

#define	WL_TXCNTL_MACPORT	0x00FF
#define	WL_TXCNTL_STRUCTTYPE	0xFF00
#define	WL_TXCNTL_TXOK		0x2
#define	WL_TXCNTL_TXEX		0x4
#define	WL_TXCNTL_SET	(WL_TXCNTL_TXOK | WL_TXCNTL_TXEX)

typedef struct rf_ckey {
	uint16_t	ckey_len;
	uint8_t		ckey_dat[14];
} rf_ckey_t;

/*
 * Configurable parameters of the RF interface
 * All the info here is passed to the card through PIO.
 */
typedef struct pcwl_rf {
	uint16_t	rf_max_datalen;
	uint16_t	rf_create_ibss;
	uint16_t	rf_porttype;
	uint16_t	rf_rts_thresh;
	uint16_t	rf_tx_rate;
	uint16_t	rf_system_scale;
	uint16_t	rf_pm_enabled;
	uint16_t	rf_max_sleep;
	uint16_t	rf_own_chnl;
	uint16_t	rf_port_no;
	char		rf_own_ssid[34];
	char		rf_desired_ssid[34];
	char		rf_nodename[34];
	uint16_t	rf_promiscuous;
	uint16_t	rf_encryption;		/* use encryption? */
	uint16_t	rf_authtype;		/* prism2 only */
	uint16_t	rf_tx_crypt_key;
	rf_ckey_t	rf_ckeys[4];
} pcwl_rf_t;

#define	PCWL_MCAST_ENTSHIFT	4
#define	PCWL_MCAST_ENTRIES	(1 << PCWL_MCAST_ENTSHIFT)
#define	PCWL_MCBUF_LEN		(ETHERADDRL << PCWL_MCAST_ENTSHIFT)
#define	PCWL_MCBUF_WORDS	(PCWL_MCBUF_LEN >> 1)

typedef enum {
	WLC_TX_UNICAST_FRAMES,		/*  0+ */
	WLC_TX_MULTICAST_FRAMES,	/*  1+ */
	WLC_TX_FRAGMENTS,		/*  2+ */
	WLC_TX_UNICAST_OCTETS,		/*  3+ */
	WLC_TX_MULTICAST_OCTETS,	/*  4  */
	WLC_TX_DEFERRED_XMITS,		/*  5+ */
	WLC_TX_SINGLE_RETRIES,		/*  6+ */
	WLC_TX_MULTI_RETRIES,		/*  7+ */
	WLC_TX_RETRY_LIMIT,		/*  8+ */
	WLC_TX_DISCARDS,		/*  9+ */
	WLC_RX_UNICAST_FRAMES,		/* 10+ */
	WLC_RX_MULTICAST_FRAMES,	/* 11+ */
	WLC_RX_FRAGMENTS,		/* 12+ */
	WLC_RX_UNICAST_OCTETS,		/* 13+ */
	WLC_RX_MULTICAST_OCTETS,	/* 14  */
	WLC_RX_FCS_ERRORS,		/* 15+ */
	WLC_RX_DISCARDS_NOBUF,		/* 16+ */
	WLC_TX_DISCARDS_WRONG_SA,	/* 17+ */
	WLC_RX_WEP_CANT_DECRYPT,	/* 18+ */
	WLC_RX_MSG_IN_MSG_FRAGS,	/* 19+ */
	WLC_RX_MSG_IN_BAD_MSG_FRAGS,	/* 20+ */
	WLC_STAT_CNT			/* 21 - keep it as the last entry */
} pcwl_cntr_offset;

#define	WL_XMT_BUF_NUM	8
typedef struct	wl_tx_ring_data {
	uint16_t		wl_tx_fids[WL_XMT_BUF_NUM];
	uint16_t		wl_tx_ring[WL_XMT_BUF_NUM];
	int			wl_tx_prod;
	int			wl_tx_cons;
	kmutex_t		wl_tx_lock;	/* for send only */
} pcwl_txring_t;

#define	PCWL_DEVICE_PCI		0
#define	PCWL_DEVICE_PCCARD	1

/*
 * The macinfo is really used as the softstate structure.
 *
 * pcwl_mh	 - mac_handle_t structure
 * pcwl_cslock	 - lock for card services request. Used with pcwl_cscv
 * pcwl_cscv	 - condition variable to wait for card events
 * pcwl_chdl	 - client handle, an uint32_t bit mask encoding for socket,
 *			function, and client info.
 *			See cs_priv.h MAKE_CLIENT_HANDLE.
 * pcwl_log_sock - holds the logical to physical translation for this card.
 *			Specifically has physical adapter and socket #.
 *			Socket # is the same as part of the pcwl_chdl encoding.
 *			Physical adapter # is from card service socket impl.
 */
typedef struct pcwl_macinfo {
	mac_handle_t		pcwl_mh;
	dev_info_t		*pcwl_dip;
	int			pcwl_device_type; /* pci or pcmcia card */
	kmutex_t		pcwl_cslock;	/* for card services */
	kcondvar_t		pcwl_cscv;	/* for card services */
	client_handle_t		pcwl_chdl;	/* s,f,c encoding, cs_priv.h */
	map_log_socket_t	pcwl_log_sock;	/* logical/phys socket map */

	int			pcwl_socket;    /* socket number */
	int			pcwl_config_hi;	/* cfttbl index */
	int			pcwl_config;	/* default config index */
	int			pcwl_vcc;	/* vcc level */
	int			pcwl_iodecode;	/* # of address lines */
	int			pcwl_chip_type;	/* Lucent or Prism-II */

	uint8_t 		pcwl_mac_addr[ETHERADDRL];
	uint8_t 		pcwl_bssid[ETHERADDRL];
	uint16_t		pcwl_has_wep;	/* has encryption capability */
	uint32_t		pcwl_flag;
	uint32_t		pcwl_reschedule_need;
	pcwl_rf_t		pcwl_rf;	/* RF interface parameters */

	uint16_t		pcwl_dmem_id;	/* nic mem id for tx buffer */
	uint16_t		pcwl_mgmt_id;	/* nic mem id for mgmt buffer */
	pcwl_txring_t		pcwl_txring;

	uint16_t		pcwl_mcast[PCWL_MCBUF_WORDS]; /* MC filters */

	kmutex_t		pcwl_scanlist_lock;	/* scanlist lock */
	kmutex_t		pcwl_glock;	/* generic lock */

	caddr_t			pcwl_bar;	/* for pci device only */
	ddi_acc_handle_t	pcwl_handle;
	caddr_t			pcwl_cfg_base;
	ddi_acc_handle_t	pcwl_cfg_handle;

	ddi_acc_handle_t	pcwl_port;	/* for pcmcia device only */

	ddi_iblock_cookie_t	pcwl_ib_cookie;
	ddi_softintr_t		pcwl_softint_id; /* pcwl_intr soft intr id */

	uint16_t		pcwl_cntrs_t[WLC_STAT_CNT];
	uint64_t		pcwl_cntrs_s[WLC_STAT_CNT];
	uint64_t		pcwl_noxmtbuf;
	timeout_id_t		pcwl_scanlist_timeout_id;
	list_t			pcwl_scan_list;
	uint16_t		pcwl_scan_num;
	uint16_t		pcwl_rssi;
	timeout_id_t		pcwl_connect_timeout_id;
} pcwl_maci_t;

#define	PCWL_IDENT_STRING	modldrv.drv_linkinfo
#define	PCWL_CHIP_LUCENT	0
#define	PCWL_CHIP_PRISMII	1
#define	HDL(pcwl_p)		((pcwl_p)->pcwl_port)
#define	GLD3(pcwl_p)		((pcwl_p)->pcwl_mh)
#define	DIP(pcwl_p)		((pcwl_p)->pcwl_dip)
#define	RF(pcwl_p)		(&(pcwl_p)->pcwl_rf)

#define	PCWL_CARD_INTREN	0x1
#define	PCWL_SOFTINTR		0x2	/* high level and soft intr enabled */
#define	PCWL_CARD_LINKUP	0x4	/* link status of the STA */
#define	PCWL_CARD_GSTAT		0x8
#define	PCWL_ATTACHED		0x10
#define	PCWL_CS_REGISTERED	0x20
#define	PCWL_ENABLED		0x40
#define	PCWL_CARD_READY		0x80
#define	PCWL_CARD_FAILED	0x100
#define	PCWL_CARD_INTR		0x200
#define	PCWL_CARD_PLUMBED	0x400
#define	PCWL_CARD_SUSPEND	0x800

#define	PCWL_STATE_IDLE		0x1

#define	PCWL_NICMEM_SZ		(2048) /* 80211MTU set as 1500, so 2k here */

static int	pcwl_probe(dev_info_t *dip);
static int	pcwl_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int	pcwl_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

static int	pcwl_register_cs(dev_info_t *dip, pcwl_maci_t *pcwl_p);
static void	pcwl_unregister_cs(pcwl_maci_t *pcwl_p);
static void	pcwl_destroy_locks(pcwl_maci_t *pcwl_p);
static int	pcwl_reset_backend(pcwl_maci_t *pcwl_p);
static int	pcwl_get_cap(pcwl_maci_t *pcwl_p);
static int	pcwl_card_insert(pcwl_maci_t *pcwl_p);
static int	pcwl_ev_hdlr(event_t ev, int pri, event_callback_args_t *arg);
static void	pcwl_card_remove(pcwl_maci_t *pcwl_p);
static int	pcwl_init_nicmem(pcwl_maci_t *pcwl_p);

/*
 * high level device access primitives, glock must held before calling
 */
static uint16_t	pcwl_set_cmd(pcwl_maci_t *pcwl_p, uint16_t mode, uint16_t type);
static uint16_t pcwl_set_ch(pcwl_maci_t *, uint16_t, uint16_t, uint16_t);
static uint16_t	pcwl_get_ltv(pcwl_maci_t *pcwl_p, uint16_t len, uint16_t type,
			uint16_t *val_p);
static uint16_t	pcwl_put_ltv(pcwl_maci_t *pcwl_p, uint16_t len, uint16_t type,
			uint16_t *val_p);
static uint16_t	pcwl_fil_ltv(pcwl_maci_t *pcwl_p, uint16_t len, uint16_t type,
			uint16_t val);
static uint16_t	pcwl_put_str(pcwl_maci_t *pcwl_p, uint16_t type, char *str_p);
static uint16_t pcwl_rdch0(pcwl_maci_t *pcwl_p, uint16_t type, uint16_t off,
			uint16_t *buf_p, int len, int order);
static uint16_t pcwl_wrch1(pcwl_maci_t *pcwl_p, uint16_t type, uint16_t off,
			uint16_t *buf_p, int len, int order);
static int	pcwl_config_rf(pcwl_maci_t *pcwl_p);
static int	pcwl_loaddef_rf(pcwl_maci_t *pcwl_p);
static void	pcwl_start_locked(pcwl_maci_t *pcwl_p);
static void	pcwl_stop_locked(pcwl_maci_t *pcwl_p);
static int	pcwl_saddr_locked(pcwl_maci_t *pcwl_p);
static uint16_t	pcwl_alloc_nicmem(pcwl_maci_t *pcwl_p, uint16_t len,
			uint16_t *id_p);
static void	pcwl_chip_type(pcwl_maci_t *pcwl_p);

/*
 * Required driver entry points for mac
 */
static int	pcwl_start(void *);
static void	pcwl_stop(void *);
static int	pcwl_saddr(void *, const uint8_t *);
static mblk_t	*pcwl_tx(void *, mblk_t *);
static int	pcwl_send(pcwl_maci_t *, mblk_t *);
static int	pcwl_prom(void *, boolean_t);
static int	pcwl_gstat(void *, uint_t, uint64_t *);
static int	pcwl_sdmulti(void *, boolean_t, const uint8_t *);
static void 	pcwl_ioctl(void *, queue_t *, mblk_t *);

static uint_t	pcwl_intr(caddr_t arg);
static uint_t	pcwl_intr_hi(caddr_t arg);
static void	pcwl_rcv(pcwl_maci_t *pcwl_p);
static uint32_t pcwl_txdone(pcwl_maci_t *pcwl_p);
static void pcwl_infodone(pcwl_maci_t *pcwl_p);
static void 	pcwl_ssid_scan(pcwl_maci_t *, uint16_t, uint16_t, uint16_t);

/*
 * prototypes of the function for wifi ioctl
 */
static int	pcwl_cfg_essid(mblk_t *, pcwl_maci_t *, uint32_t);
static int	pcwl_cfg_bssid(mblk_t *, pcwl_maci_t *, uint32_t);
static int	pcwl_cfg_scan(mblk_t *, pcwl_maci_t *, uint32_t);
static int	pcwl_cfg_linkstatus(mblk_t *, pcwl_maci_t *, uint32_t);
static int	pcwl_cfg_bsstype(mblk_t *, pcwl_maci_t *, uint32_t);
static int	pcwl_cfg_phy(mblk_t *, pcwl_maci_t *, uint32_t);
static int	pcwl_cfg_desiredrates(mblk_t *, pcwl_maci_t *, uint32_t);
static int	pcwl_cfg_supportrates(mblk_t *, pcwl_maci_t *, uint32_t);
static int	pcwl_cfg_powermode(mblk_t *, pcwl_maci_t *, uint32_t);
static int	pcwl_cfg_authmode(mblk_t *, pcwl_maci_t *, uint32_t);
static int	pcwl_cfg_encryption(mblk_t *, pcwl_maci_t *, uint32_t);
static int	pcwl_cfg_wepkeyid(mblk_t *, pcwl_maci_t *, uint32_t);
static int	pcwl_cfg_createibss(mblk_t *, pcwl_maci_t *, uint32_t);
static int	pcwl_cfg_rssi(mblk_t *, pcwl_maci_t *, uint32_t);
static int	pcwl_cfg_radio(mblk_t *, pcwl_maci_t *, uint32_t);
static int	pcwl_cfg_wepkey(mblk_t *, pcwl_maci_t *, uint32_t);
static void	pcwl_wlan_ioctl(pcwl_maci_t *, queue_t *, mblk_t *, uint32_t);
static int	pcwl_getset(mblk_t *, pcwl_maci_t *, uint32_t);

static void	pcwl_scanlist_timeout(void *);
static void	pcwl_delete_scan_item(pcwl_maci_t *, wl_scan_list_t *);
static int	pcwl_add_scan_item(pcwl_maci_t *, wl_scan_result_t);
static void	pcwl_get_rssi(pcwl_maci_t *);
static void 	pcwl_connect_timeout(void *arg);

#define	RDCH0(h, t, o, b_p, l)	pcwl_rdch0(h, t, o, b_p, l, 1)
#define	WRCH1(h, t, o, b_p, l)	pcwl_wrch1(h, t, o, b_p, l, 1)
#define	RDPKT(h, t, o, b_p, l)	pcwl_rdch0(h, t, o, b_p, l, 0)
#define	WRPKT(h, t, o, b_p, l)	pcwl_wrch1(h, t, o, b_p, l, 0)

#define	FIL_LTV(pcwl_p, len, type, val)	 \
	(void) pcwl_fil_ltv(pcwl_p, len, type, val)
#define	PUT_LTV(pcwl_p, len, type, v_p)	 \
	(void) pcwl_put_ltv(pcwl_p, len, type, v_p)
#define	PUT_STR(pcwl_p, type, str_p)	\
	(void) pcwl_put_str(pcwl_p, type, str_p)

#define	PCWL_READ(p, o, v)	{ \
	if (p->pcwl_device_type == PCWL_DEVICE_PCI) { \
		uint16_t t = ddi_get16(p->pcwl_handle, \
		    (uint16_t *)(p->pcwl_bar + 2*(o))); \
		v = LE_16(t); \
	} else { \
		uint16_t t = csx_Get16(HDL(p), o); \
		v = LE_16(t); \
	}\
}
#define	PCWL_WRITE(p, o, v)	{ \
	if (p->pcwl_device_type == PCWL_DEVICE_PCI) { \
		ddi_put16(p->pcwl_handle, \
		    (uint16_t *)(p->pcwl_bar + 2*(o)), LE_16(v)); \
	} else { \
		csx_Put16(HDL(p), o, LE_16(v)); \
	}\
}
#define	PCWL_READ_P(p, o, v, h)	{ \
	if (p->pcwl_device_type == PCWL_DEVICE_PCI) { \
		uint16_t t = ddi_get16(p->pcwl_handle, \
		    (uint16_t *)(p->pcwl_bar + 2*(o))); \
		*(v) = h ? LE_16(t) : t; \
	} else { \
		uint16_t t = csx_Get16(HDL(p), o); \
		*(v) = h ? LE_16(t) : t; \
	}\
}
#define	PCWL_WRITE_P(p, o, v, h)	{ \
	if (p->pcwl_device_type == PCWL_DEVICE_PCI) { \
		ddi_put16(p->pcwl_handle, (uint16_t *)(p->pcwl_bar + 2*(o)), \
		    h ? LE_16(*(v)) : (*(v))); \
	} else {\
		csx_Put16(HDL(p), o, h ? LE_16(*(v)) : (*(v))); \
	}\
}

#ifdef _BIG_ENDIAN
#define	PCWL_SWAP16(buf_p, len) { \
	int pcwl_swap_len = len; \
	for (pcwl_swap_len = (pcwl_swap_len + 1) >> 1; pcwl_swap_len; ) { \
		uint16_t val; \
		pcwl_swap_len--; \
		val = *((uint16_t *)(buf_p) + pcwl_swap_len); \
		*((uint16_t *)(buf_p) + pcwl_swap_len) = LE_16(val); \
	} \
}
#else /* _BIG_ENDIAN */
#define	PCWL_SWAP16(buf_p, len)
#endif /* _BIG_ENDIAN */

#define	PCWL_ENABLE_INTR(pcwl_p)	{\
	PCWL_WRITE(pcwl_p, WL_INT_EN, WL_INTRS);\
}
#define	PCWL_DISABLE_INTR(pcwl_p)	{ \
	PCWL_WRITE(pcwl_p, WL_INT_EN, 0); \
	PCWL_WRITE(pcwl_p, WL_EVENT_ACK, 0xffff);\
}

/*
 * 16-bit driver private status code
 */
#define	PCWL_SUCCESS		0x0
#define	PCWL_FAIL		0x1
#define	PCWL_TIMEDOUT_CMD	0x10
#define	PCWL_TIMEDOUT_ACCESS	0x11
#define	PCWL_TIMEDOUT_TARGET	0x12
#define	PCWL_BADLEN		0x13
#define	PCWL_BADTYPE		0x14
#define	PCWL_TIMEDOUT_ALLOC	0x15
#define	PCWL_FAILURE_CMD	0x16

#define	PCWL_STATUS_MAX		0xffff
#define	N_PCWL			2

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCWL_H */
