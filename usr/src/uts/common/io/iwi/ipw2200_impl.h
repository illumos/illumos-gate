/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2004, 2005
 *      Damien Bergamini <damien.bergamini@free.fr>. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _SYS_IPW2200_IMPL_H
#define	_SYS_IPW2200_IMPL_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Intel Wireless PRO/2200 mini-pci adapter driver
 * ipw2200_impl.h includes:
 * 	. implementation of ipw2200
 * 	. hardware operations and interface definations for ipw2200
 * 	. firmware operations and interface definations for ipw2200
 */
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/mac.h>
#include <sys/mac_wifi.h>
#include <sys/net80211.h>

/*
 * Implementation of ipw2200
 */
#define	IPW2200_PCI_CFG_RNUM 	(0) /* pci config space */
#define	IPW2200_PCI_CSR_RNUM 	(1) /* device CSR space */
#define	IPW2200_PCI_INTR_NUM	(0) /* interrupt number */

#define	IPW2200_TX_RING_SIZE 	(64)
#define	IPW2200_CMD_RING_SIZE	(16)
#define	IPW2200_RX_RING_SIZE 	(32)

struct dma_region {
	ddi_dma_handle_t	dr_hnd;
	ddi_acc_handle_t	dr_acc;
	ddi_dma_cookie_t	dr_cookie;
	uint_t			dr_ccnt;
	uint32_t		dr_pbase;
	caddr_t			dr_base;
	size_t			dr_size;
	const char		*dr_name;
};

struct ipw2200_firmware {
	uint8_t			*boot_base; /* boot code */
	size_t			boot_size;
	uint8_t			*uc_base; /* u-controller code */
	size_t			uc_size;
	uint8_t			*fw_base; /* firmware code */
	size_t			fw_size;
};

/*
 * besides the statistic counted by net80211, driver can also record
 * statistic data while process
 */
struct ipw2200_stats {
	uint32_t		sc_rx_len_err;
	uint32_t		sc_tx_discard;
	uint32_t		sc_tx_alloc_fail;
	uint32_t		sc_tx_encap_fail;
	uint32_t		sc_tx_crypto_fail;
};

/*
 * per-instance soft-state structure
 */
struct ipw2200_softc {
	struct ieee80211com	sc_ic;
	dev_info_t		*sc_dip;
	int	(*sc_newstate)(struct ieee80211com *,
	    enum ieee80211_state, int);
	void    (*sc_node_free)(struct ieee80211com *);
	int			sc_authmode;

	/* CSR */
	ddi_acc_handle_t	sc_ioh;
	caddr_t			sc_regs;
	/* mutex to protect interrupt handler */
	kmutex_t		sc_ilock;
	/* interrupt iblock cookie */
	ddi_iblock_cookie_t 	sc_iblk;
	/* soft interrupt */
	ddi_softintr_t		sc_link_softint;
	/* link status */
	int32_t			sc_linkstate;
	/* flags */
	uint32_t		sc_flags;
#define	IPW2200_FLAG_FW_CACHED		(1 << 0)
#define	IPW2200_FLAG_FW_INITED		(1 << 1)
#define	IPW2200_FLAG_RUNNING		(1 << 2)
#define	IPW2200_FLAG_LINK_CHANGE	(1 << 3)
#define	IPW2200_FLAG_TX_SCHED		(1 << 4)
#define	IPW2200_FLAG_SCANNING		(1 << 5)
#define	IPW2200_FLAG_HW_ERR_RECOVER	(1 << 6)
#define	IPW2200_FLAG_ASSOCIATED		(1 << 7)
#define	IPW2200_FLAG_SUSPEND		(1 << 8)
#define	IPW2200_FLAG_QUIESCED		(1 << 9)
#define	IPW2200_FLAG_HAS_RADIO_SWITCH	(1 << 16)
	/* firmware download */
	int			sc_fw_ok;
	kcondvar_t		sc_fw_cond;

	/* command desc ring */
	kmutex_t		sc_cmd_lock;
	kcondvar_t		sc_cmd_cond;
	uint32_t		sc_cmd_cur;
	uint32_t		sc_cmd_free;
	struct ipw2200_cmd_desc	*sc_cmdsc;

	/* command status */
	int			sc_done[IPW2200_CMD_RING_SIZE];
	kcondvar_t		sc_cmd_status_cond;

	/* tx ring, bd->hdr&buf */
	kmutex_t		sc_tx_lock;
	uint32_t		sc_tx_cur;
	uint32_t		sc_tx_free;
	struct ipw2200_tx_desc	*sc_txdsc;
	uint8_t			*sc_txbufs[IPW2200_TX_RING_SIZE];

	/* rx ring */
	uint32_t		sc_rx_cur;
	uint32_t		sc_rx_free;
	uint8_t			*sc_rxbufs[IPW2200_RX_RING_SIZE];

	/* tx-desc & tx-buffer array */
	struct dma_region	sc_dma_txdsc;
	struct dma_region	sc_dma_txbufs[IPW2200_TX_RING_SIZE];
	struct dma_region	sc_dma_cmdsc;
	/* rx-buffer array */
	struct dma_region	sc_dma_rxbufs[IPW2200_RX_RING_SIZE];

	/* hw configuration values */
	uint8_t			sc_macaddr[IEEE80211_ADDR_LEN];
	/* MAC address string */
	char			sc_macstr[32];

	/* firmware */
	struct ipw2200_firmware	sc_fw;

	/* reschedule lock */
	kmutex_t		sc_resched_lock;

	/* pci information */
	uint16_t		sc_vendor, sc_device, sc_subven, sc_subdev;

	/* statistic counting by driver */
	struct ipw2200_stats	sc_stats;

	/* mfthread related, mfthread is used to handle asynchronous task */
	kthread_t		*sc_mf_thread;
	kmutex_t		sc_mflock;
	int			sc_mfthread_switch;
	kcondvar_t		sc_mfthread_req;
	kcondvar_t		sc_mfthread_cv;

};

/*
 * RING_BACKWARD - move 'x' backward 's' steps in a 'b'- sized ring
 * RING_FORWARD	 - move 'x' forward 's' steps in a 'b'- sized ring
 *
 * note that there must be 0 <= 'x' < 'b' && 0 <= 's' < 'b'
 */
#define	RING_FLEN(x, y, b)	((((x) > (y)) ? ((b)+(y)-(x)) : ((y)-(x))))
#define	RING_FORWARD(x, s, b)	(((x)+(s))%(b))
#define	RING_BACKWARD(x, s, b)	RING_FORWARD((x), (b)-(s), (b))

extern int ipw2200_init(struct ipw2200_softc *sc);
extern void ipw2200_wifi_ioctl(struct ipw2200_softc *, queue_t *,
    mblk_t *, uint32_t);
extern int ipw2200_dma_region_alloc(struct ipw2200_softc *sc,
    struct dma_region *dr, size_t size, uint_t dir, uint_t flags);
extern void ipw2200_dma_region_free(struct dma_region *dr);
extern int ipw2200_disable(struct ipw2200_softc *sc);
extern int ipw2200_start_scan(struct ipw2200_softc *sc);

/*
 * get radio off/on status
 */
extern int ipw2200_radio_status(struct ipw2200_softc *sc);

/*
 * Below structure and functions will be used for statistic, which will be
 * displayed when the wificonfig running...
 */
struct statistic {
	int		index;
	const char	*desc;
};
extern void ipw2200_get_statistics(struct ipw2200_softc *sc);

/*
 * Hardware related definations and interfaces.
 */
#define	IPW2200_CSR_INTR		(0x0008)
#define	IPW2200_CSR_INTR_MASK		(0x000c)
#define	IPW2200_CSR_INDIRECT_ADDR	(0x0010)
#define	IPW2200_CSR_INDIRECT_DATA	(0x0014)
#define	IPW2200_CSR_AUTOINC_ADDR	(0x0018)
#define	IPW2200_CSR_AUTOINC_DATA	(0x001c)
#define	IPW2200_CSR_RST			(0x0020)
#define	IPW2200_CSR_CTL			(0x0024)
#define	IPW2200_CSR_IO			(0x0030)
#define	IPW2200_CSR_CMD_BASE		(0x0200)
#define	IPW2200_CSR_CMD_SIZE		(0x0204)
#define	IPW2200_CSR_TX1_BASE		(0x0208)
#define	IPW2200_CSR_TX1_SIZE		(0x020c)
#define	IPW2200_CSR_TX2_BASE		(0x0210)
#define	IPW2200_CSR_TX2_SIZE		(0x0214)
#define	IPW2200_CSR_TX3_BASE		(0x0218)
#define	IPW2200_CSR_TX3_SIZE		(0x021c)
#define	IPW2200_CSR_TX4_BASE		(0x0220)
#define	IPW2200_CSR_TX4_SIZE		(0x0224)
#define	IPW2200_CSR_CMD_READ_INDEX	(0x0280)
#define	IPW2200_CSR_TX1_READ_INDEX	(0x0284)
#define	IPW2200_CSR_TX2_READ_INDEX	(0x0288)
#define	IPW2200_CSR_TX3_READ_INDEX	(0x028c)
#define	IPW2200_CSR_TX4_READ_INDEX	(0x0290)
#define	IPW2200_CSR_RX_READ_INDEX	(0x02a0)
#define	IPW2200_CSR_RX_BASE		(0x0500)
#define	IPW2200_CSR_TABLE0_SIZE		(0x0700)
#define	IPW2200_CSR_TABLE0_BASE		(0x0704)
#define	IPW2200_CSR_NODE_BASE		(0x0c0c)
#define	IPW2200_CSR_CMD_WRITE_INDEX	(0x0f80)
#define	IPW2200_CSR_TX1_WRITE_INDEX	(0x0f84)
#define	IPW2200_CSR_TX2_WRITE_INDEX	(0x0f88)
#define	IPW2200_CSR_TX3_WRITE_INDEX	(0x0f8c)
#define	IPW2200_CSR_TX4_WRITE_INDEX	(0x0f90)
#define	IPW2200_CSR_RX_WRITE_INDEX	(0x0fa0)
#define	IPW2200_CSR_READ_INT		(0x0ff4)

#define	IPW2200_CSR_CURRENTT_TX_RATE	IPW2200_CSR_TABLE0_BASE

/*
 * CSR flags: IPW2200_CSR_INTR
 */
#define	IPW2200_INTR_RX_TRANSFER	(0x00000002)
#define	IPW2200_INTR_CMD_TRANSFER	(0x00000800)
#define	IPW2200_INTR_TX1_TRANSFER	(0x00001000)
#define	IPW2200_INTR_TX2_TRANSFER	(0x00002000)
#define	IPW2200_INTR_TX3_TRANSFER	(0x00004000)
#define	IPW2200_INTR_TX4_TRANSFER	(0x00008000)
#define	IPW2200_INTR_FW_INITED		(0x01000000)
#define	IPW2200_INTR_RADIO_OFF		(0x04000000)
#define	IPW2200_INTR_FATAL_ERROR	(0x40000000)
#define	IPW2200_INTR_PARITY_ERROR	(0x80000000)

#define	IPW2200_INTR_MASK_ALL	(IPW2200_INTR_RX_TRANSFER	| \
	IPW2200_INTR_CMD_TRANSFER	| \
	IPW2200_INTR_TX1_TRANSFER	| \
	IPW2200_INTR_TX2_TRANSFER	| \
	IPW2200_INTR_TX3_TRANSFER	| \
	IPW2200_INTR_TX4_TRANSFER	| \
	IPW2200_INTR_FW_INITED		| \
	IPW2200_INTR_RADIO_OFF		| \
	IPW2200_INTR_FATAL_ERROR	| \
	IPW2200_INTR_PARITY_ERROR)

#define	IPW2200_INTR_MASK_ERR	(IPW2200_INTR_FATAL_ERROR	| \
	IPW2200_INTR_PARITY_ERROR)

/*
 * CSR flags for register: IPW2200_CSR_RST, which is used to reset h/w
 */
#define	IPW2200_RST_PRINCETON_RESET	(0x00000001)
#define	IPW2200_RST_STANDBY		(0x00000004)
#define	IPW2200_RST_LED_ACTIVITY	(0x00000010)
#define	IPW2200_RST_LED_ASSOCIATED	(0x00000020)
#define	IPW2200_RST_LED_OFDM		(0x00000040)
#define	IPW2200_RST_SW_RESET		(0x00000080)
#define	IPW2200_RST_MASTER_DISABLED	(0x00000100)
#define	IPW2200_RST_STOP_MASTER		(0x00000200)
#define	IPW2200_RST_GATE_ODMA		(0x02000000)
#define	IPW2200_RST_GATE_IDMA		(0x04000000)
#define	IPW2200_RST_GATE_ADMA		(0x20000000)

/*
 * CSR flags for register: IPW2200_CSR_CTL
 */
#define	IPW2200_CTL_CLOCK_READY		(0x00000001)
#define	IPW2200_CTL_ALLOW_STANDBY	(0x00000002)
#define	IPW2200_CTL_INIT		(0x00000004)

/*
 * CSR flags for register: IPW2200_CSR_IO
 */
#define	IPW2200_IO_RADIO_ENABLED	(0x00010000)

/*
 * CSR flags for register: IPW2200_CSR_READ_INT
 */
#define	IPW2200_READ_INT_INIT_HOST	(0x20000000)

/* table2 offsets */
#define	IPW2200_INFO_ADAPTER_MAC	(40)

/* constants for command blocks */
#define	IPW2200_CB_DEFAULT_CTL		(0x8cea0000)
#define	IPW2200_CB_MAXDATALEN		(8191)

/* supported rates */
#define	IPW2200_RATE_DS1		(10)
#define	IPW2200_RATE_DS2		(20)
#define	IPW2200_RATE_DS5		(55)
#define	IPW2200_RATE_DS11		(110)
#define	IPW2200_RATE_OFDM6		(13)
#define	IPW2200_RATE_OFDM9		(15)
#define	IPW2200_RATE_OFDM12		(5)
#define	IPW2200_RATE_OFDM18		(7)
#define	IPW2200_RATE_OFDM24		(9)
#define	IPW2200_RATE_OFDM36		(11)
#define	IPW2200_RATE_OFDM48		(1)
#define	IPW2200_RATE_OFDM54		(3)

#pragma pack(1)
/* HW structures, packed */

struct ipw2200_hdr {
	uint8_t		type;
#define	IPW2200_HDR_TYPE_DATA		(0)
#define	IPW2200_HDR_TYPE_COMMAND	(1)
#define	IPW2200_HDR_TYPE_NOTIF		(3)
#define	IPW2200_HDR_TYPE_FRAME		(9)
	uint8_t		seq;
	uint8_t		flags;
#define	IPW2200_HDR_FLAG_IRQ		(0x04)
	uint8_t		reserved;
};

struct ipw2200_notif {
	uint32_t	reserved[2];
	uint8_t		type;
#define	IPW2200_NOTIF_TYPE_SUCCESS		(0)
#define	IPW2200_NOTIF_TYPE_UNSPECIFIED		(1)
#define	IPW2200_NOTIF_TYPE_ASSOCIATION		(10)
#define	IPW2200_NOTIF_TYPE_AUTHENTICATION	(11)
#define	IPW2200_NOTIF_TYPE_SCAN_CHANNEL		(12)
#define	IPW2200_NOTIF_TYPE_SCAN_COMPLETE	(13)
#define	IPW2200_NOTIF_TYPE_FRAG_LENGTH		(14)
#define	IPW2200_NOTIF_TYPE_LINK_QUALITY		(15)
#define	IPW2200_NOTIF_TYPE_BEACON		(17)
#define	IPW2200_NOTIF_TYPE_TGI_TX_KEY		(18)
#define	IPW2200_NOTIF_TYPE_CALIBRATION		(20)
#define	IPW2200_NOTIF_TYPE_NOISE		(25)
	uint8_t		flags;
	uint16_t	len;
};

/*
 * structure for notification IPW2200_NOTIF_TYPE_AUTHENTICATION
 */
struct ipw2200_notif_authentication {
	uint8_t		state;
#define	IPW2200_AUTH_FAIL	(0)
#define	IPW2200_AUTH_SENT_1	(1)
#define	IPW2200_AUTH_RECV_2	(2)
#define	IPW2200_AUTH_SEQ1_PASS	(3)
#define	IPW2200_AUTH_SEQ1_FAIL	(4)
#define	IPW2200_AUTH_SUCCESS	(9)
};

/*
 * structure for notification IPW2200_NOTIF_TYPE_ASSOCIATION
 */
struct ipw2200_notif_association {
	uint8_t		state;
#define	IPW2200_ASSOC_FAIL	(0)
#define	IPW2200_ASSOC_SUCCESS	(12)
	struct ieee80211_frame	frame;
	uint16_t	capinfo;
	uint16_t	status;
	uint16_t	associd;
};

/*
 * structure for notification BACAON
 */
struct ipw2200_notif_beacon_state {
	uint32_t	state;
#define	IPW2200_BEACON_MISS	(1)
	uint32_t	number;
};

/*
 * structure for notification IPW2200_NOTIF_TYPE_SCAN_CHANNEL
 */
struct ipw2200_notif_scan_channel {
	uint8_t		nchan;
	uint8_t		reserved[47];
};

/*
 * structure for notification IPW2200_NOTIF_TYPE_SCAN_COMPLETE
 */
struct ipw2200_notif_scan_complete {
	uint8_t		type;
	uint8_t		nchan;
	uint8_t		status;
	uint8_t		reserved;
};

/*
 * received frame header
 */
struct ipw2200_frame {
	uint32_t	reserved1[2];
	uint8_t		chan;
	uint8_t		status;
	uint8_t		rate;
	uint8_t		rssi; /* receiver signal strength indicator */
	uint8_t		agc; /* automatic gain control */
	uint8_t		rssi_dbm;
	uint16_t	signal;
	uint16_t	noise;
	uint8_t		antenna;
	uint8_t		control;
	uint8_t		reserved3[2];
	uint16_t	len;
};

/*
 * header for transmission
 */
struct ipw2200_tx_desc {
	struct ipw2200_hdr	hdr;
	uint32_t	reserved1;
	uint8_t		station;
	uint8_t		reserved2[3];
	uint8_t		cmd;
#define	IPW2200_DATA_CMD_TX		(0x0b)
	uint8_t		seq;
	uint16_t	len;
	uint8_t		priority;
	uint8_t		flags;
#define	IPW2200_DATA_FLAG_SHPREAMBLE	(0x04)
#define	IPW2200_DATA_FLAG_NO_WEP	(0x20)
#define	IPW2200_DATA_FLAG_NEED_ACK	(0x80)
	uint8_t		xflags;
#define	IPW2200_DATA_XFLAG_QOS		(0x10)
	uint8_t		wep_txkey;
	uint8_t		wepkey[IEEE80211_KEYBUF_SIZE];
	uint8_t		rate;
	uint8_t		antenna;
	uint8_t		reserved3[10];

	struct ieee80211_frame_addr4 wh;
	uint8_t		reserved4[2];
	uint32_t	iv;
	uint32_t	eiv;

	uint32_t	nseg;
#define	IPW2200_MAX_NSEG		(6)
	uint32_t	seg_addr[IPW2200_MAX_NSEG];
	uint16_t	seg_len[IPW2200_MAX_NSEG];
};

/*
 * command
 */
struct ipw2200_cmd_desc {
	struct ipw2200_hdr	hdr;
	uint8_t			type;
#define	IPW2200_CMD_ENABLE		(2)
#define	IPW2200_CMD_SET_CONFIG		(6)
#define	IPW2200_CMD_SET_ESSID		(8)
#define	IPW2200_CMD_SET_MAC_ADDRESS	(11)
#define	IPW2200_CMD_SET_RTS_THRESHOLD	(15)
#define	IPW2200_CMD_SET_FRAG_THRESHOLD	(16)
#define	IPW2200_CMD_SET_POWER_MODE	(17)
#define	IPW2200_CMD_SET_WEP_KEY		(18)
#define	IPW2200_CMD_SCAN		(20)
#define	IPW2200_CMD_ASSOCIATE		(21)
#define	IPW2200_CMD_SET_RATES		(22)
#define	IPW2200_CMD_ABORT_SCAN		(23)
#define	IPW2200_CMD_SET_WME_PARAMS	(25)
#define	IPW2200_CMD_SCAN_EXT		(26)
#define	IPW2200_CMD_SET_OPTIE		(31)
#define	IPW2200_CMD_DISABLE		(33)
#define	IPW2200_CMD_SET_IV		(34)
#define	IPW2200_CMD_SET_TX_POWER	(35)
#define	IPW2200_CMD_SET_SENSITIVITY	(42)
#define	IPW2200_CMD_SET_WMEIE		(84)
	uint8_t			len;
	uint16_t		reserved;
	uint8_t			data[120];
};

/*
 * node information (IBSS)
 */
struct ipw2200_ibssnode {
	uint8_t		bssid[IEEE80211_ADDR_LEN];
	uint8_t		reserved[2];
};

/*
 * constants for 'mode' fields
 */
#define	IPW2200_MODE_11A	(0)
#define	IPW2200_MODE_11B	(1)
#define	IPW2200_MODE_11G	(2)

/*
 * macro for command IPW2200_CMD_SET_SENSITIVITY
 */
#define	IPW2200_RSSIDBM2RAW(rssi)((rssi) - 112)

/*
 * possible values for command IPW2200_CMD_SET_POWER_MODE
 */
#define	IPW2200_POWER_MODE_CAM		(0)
#define	IPW2200_POWER_MODE_PSP		(3)
#define	IPW2200_POWER_MODE_MAX		(5)

/*
 * structure for command IPW2200_CMD_SET_RATES
 */
struct ipw2200_rateset {
	uint8_t		mode;
	uint8_t		nrates;
	uint8_t		type;
#define	IPW2200_RATESET_TYPE_NEGOCIATED	(0)
#define	IPW2200_RATESET_TYPE_SUPPORTED	(1)
	uint8_t		reserved;
	uint8_t		rates[12];
};

/*
 * structure for command IPW2200_CMD_SET_TX_POWER
 */
struct ipw2200_txpower {
	uint8_t		nchan;
	uint8_t		mode;
	struct {
		uint8_t	chan;
		uint8_t power;
#define	IPW2200_TXPOWER_MAX	(20)
#define	IPW2200_TXPOWER_RATIO	(IEEE80211_TXPOWER_MAX / IPW2200_TXPOWER_MAX)
	} chan[37];
};

/*
 * structure for command IPW2200_CMD_ASSOCIATE
 */
struct ipw2200_associate {
	uint8_t		chan;
	uint8_t		auth;
#define	IPW2200_AUTH_OPEN	(0)
#define	IPW2200_AUTH_SHARED	(1)
#define	IPW2200_AUTH_NONE	(3)
	uint8_t		type;
#define	IPW2200_HC_ASSOC	(0)
#define	IPW2200_HC_REASSOC	(1)
#define	IPW2200_HC_DISASSOC	(2)
#define	IPW2200_HC_IBSS_START	(3)
#define	IPW2200_HC_IBSS_RECONF	(4)
#define	IPW2200_HC_DISASSOC_QUIET (5)
	uint8_t		reserved1;
	uint16_t	policy;
#define	IPW2200_POLICY_WME	(1)
#define	IPW2200_POLICY_WPA	(2)
	uint8_t		plen;
	uint8_t		mode;
	uint8_t		bssid[IEEE80211_ADDR_LEN];
	uint8_t		tstamp[8];

	uint16_t	capinfo;
	uint16_t	lintval;
	uint16_t	intval;
	uint8_t		dst[IEEE80211_ADDR_LEN];
	uint32_t	reserved3;
	uint16_t	reserved4;
};

#define	IPW2200_SCAN_CHANNELS	(54)

/*
 * structure for command IPW2200_CMD_SCAN
 */
struct ipw2200_scan {
	uint8_t		type;
#define	IPW2200_SCAN_TYPE_PASSIVE_STOP	(0) /* passive, stop on first beacon */
#define	IPW2200_SCAN_TYPE_PASSIVE	(1) /* passive, full dwell on channel */
#define	IPW2200_SCAN_TYPE_DIRECTED	(2) /* active, directed probe seq */
#define	IPW2200_SCAN_TYPE_BROADCAST	(3) /* active, bcast probe seq */
#define	IPW2200_SCAN_TYPE_BDIRECTED	(4) /* active, directed+bcast probe */
#define	IPW2200_SCAN_TYPES		(5)
	uint16_t	dwelltime;
	uint8_t		channels[IPW2200_SCAN_CHANNELS];
#define	IPW2200_CHAN_5GHZ	(0 << 6)
#define	IPW2200_CHAN_2GHZ	(1 << 6)
	uint8_t		reserved[3];
};

/*
 * structure for command IPW2200_CMD_SCAN_EXT
 */
struct ipw2200_scan_ext {
	uint32_t	full_scan_index;
	uint8_t		channels[IPW2200_SCAN_CHANNELS];
	uint8_t		scan_type[IPW2200_SCAN_CHANNELS/2];
	uint8_t		reserved;
	uint16_t	dwell_time[IPW2200_SCAN_TYPES];
};

/*
 * structure for command IPW2200_CMD_SET_CONFIGURATION
 */
struct ipw2200_configuration {
	uint8_t		bluetooth_coexistence;
	uint8_t		reserved1;
	uint8_t		answer_pbreq;
	uint8_t		allow_invalid_frames;
	uint8_t		multicast_enabled;
	uint8_t		drop_unicast_unencrypted;
	uint8_t		disable_unicast_decryption;
	uint8_t		drop_multicast_unencrypted;
	uint8_t		disable_multicast_decryption;
	uint8_t		antenna;
#define	IPW2200_ANTENNA_AUTO	(0)	/* firmware selects best antenna */
#define	IPW2200_ANTENNA_A	(1)	/* use antenna A only */
#define	IPW2200_ANTENNA_B	(3)	/* use antenna B only */
#define	IPW2200_ANTENNA_SLOWDIV	(2)	/* slow diversity algorithm */
	uint8_t		include_crc;
	uint8_t		use_protection;
	uint8_t		protection_ctsonly;
	uint8_t		enable_multicast_filtering;
	uint8_t		bluetooth_threshold;
	uint8_t		reserved4;
	uint8_t		allow_beacon_and_probe_resp;
	uint8_t		allow_mgt;
	uint8_t		noise_reported;
	uint8_t		reserved5;
};

/*
 * structure for command IPW2200_CMD_SET_WEP_KEY
 */
struct ipw2200_wep_key {
	uint8_t		cmd;
#define	IPW2200_WEP_KEY_CMD_SETKEY	(0x08)
	uint8_t		seq;
	uint8_t		idx;
	uint8_t		len;
	uint8_t		key[IEEE80211_KEYBUF_SIZE];
};

/*
 * the following two structures are for future WME support
 */
struct ipw2200_wme_params {
	uint16_t	cwmin[WME_NUM_AC];
	uint16_t	cwmax[WME_NUM_AC];
	uint8_t		aifsn[WME_NUM_AC];
	uint8_t		acm[WME_NUM_AC];
	uint16_t	burst[WME_NUM_AC];
};

struct ipw2200_sensitivity {
	uint16_t	rssi;
#define	IPW2200_RSSI_TO_DBM	(112)
	uint16_t	reserved;
};

#pragma pack()

/*
 * ROM entries
 */
#define	IPW2200_EEPROM_MAC	(0x21)
#define	IPW2200_EEPROM_NIC	(0x25)	/* nic type (lsb) */
#define	IPW2200_EEPROM_SKU	(0x25)	/* nic type (msb) */

/*
 * EVENT controls
 */
#define	IPW2200_IMEM_EVENT_CTL	(0x00300004)
/*
 * EEPROM controls
 */
#define	IPW2200_IMEM_EEPROM_CTL	(0x00300040)

#define	IPW2200_EEPROM_DELAY	(1) /* minimum hold time(microsecond) */

/*
 * possible flags for register IWI_MEM_EVENT
 */
#define	IPW2200_LED_ASSOC	(1 << 5)
#define	IPW2200_LED_MASK	(0xd9fffffb)

/*
 * control and status registers access macros
 */
extern uint8_t ipw2200_csr_get8(struct ipw2200_softc *sc, uint32_t off);
extern uint16_t ipw2200_csr_get16(struct ipw2200_softc *sc, uint32_t off);
extern uint32_t ipw2200_csr_get32(struct ipw2200_softc *sc, uint32_t off);
extern void ipw2200_csr_getbuf32(struct ipw2200_softc *sc, uint32_t off,
    uint32_t *buf, size_t cnt);
extern void ipw2200_csr_put8(struct ipw2200_softc *sc, uint32_t off,
    uint8_t val);
extern void ipw2200_csr_put16(struct ipw2200_softc *sc, uint32_t off,
    uint16_t val);
extern void ipw2200_csr_put32(struct ipw2200_softc *sc, uint32_t off,
    uint32_t val);
/*
 * indirect memory space access macros
 */
extern uint8_t ipw2200_imem_get8(struct ipw2200_softc *sc, uint32_t addr);
extern uint16_t ipw2200_imem_get16(struct ipw2200_softc *sc,
    uint32_t addr);
extern uint32_t ipw2200_imem_get32(struct ipw2200_softc *sc,
    uint32_t addr);
extern void ipw2200_imem_put8(struct ipw2200_softc *sc, uint32_t addr,
    uint8_t val);
extern void ipw2200_imem_put16(struct ipw2200_softc *sc, uint32_t addr,
    uint16_t val);
extern void ipw2200_imem_put32(struct ipw2200_softc *sc, uint32_t addr,
    uint32_t val);
/*
 * EEPROM access macro
 */
extern void ipw2200_rom_control(struct ipw2200_softc *sc, uint32_t val);
extern uint16_t ipw2200_rom_get16(struct ipw2200_softc *sc, uint8_t addr);

/*
 * Firmware related definations and interfaces.
 */
extern int ipw2200_cache_firmware(struct ipw2200_softc *sc);
extern int ipw2200_free_firmware(struct ipw2200_softc *sc);
extern int ipw2200_load_uc(struct ipw2200_softc *sc, uint8_t *buf, size_t size);
extern int ipw2200_load_fw(struct ipw2200_softc *sc, uint8_t *buf, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IPW2200_IMPL_H */
