/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright(c) 2004
 *	Damien Bergamini <damien.bergamini@free.fr>. All rights reserved.
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
 * DAMAGES(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _SYS_IPW2100_IMPL_H
#define	_SYS_IPW2100_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Intel Wireless PRO/2100 mini-PCI adapter driver
 * ipw2100_impl.h includes:
 * 	. implementation of ipw2100
 * 	. hardware operation and interface define for ipw2100
 * 	. firmware operation and interface define for ipw2100
 */
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/mac.h>
#include <sys/net80211.h>

/*
 * Implementation of ipw2100
 */
#define	IPW2100_NODENAME	"ipw"

#define	IPW2100_PCI_CFG_RNUM	(0) /* pci config space */
#define	IPW2100_PCI_CSR_RNUM	(1) /* device CSR space */

#define	IPW2100_NUM_TXBD    (128)
#define	IPW2100_TXBD_SIZE   (IPW2100_NUM_TXBD * sizeof (struct ipw2100_bd))
#define	IPW2100_NUM_TXBUF   (IPW2100_NUM_TXBD/2)  /* ipw2100_txb number */
#define	IPW2100_TXBUF_SIZE  (sizeof (struct ipw2100_txb))

#define	IPW2100_NUM_RXBD    (128)
#define	IPW2100_STATUS_SIZE (IPW2100_NUM_RXBD * sizeof (struct ipw2100_status))
#define	IPW2100_RXBD_SIZE   (IPW2100_NUM_RXBD * sizeof (struct ipw2100_bd))
#define	IPW2100_NUM_RXBUF   (IPW2100_NUM_RXBD)
#define	IPW2100_RXBUF_SIZE  (sizeof (struct ipw2100_rxb))

#define	IPW2100_CMD_SIZE    (sizeof (struct ipw2100_cmd))

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

struct ipw2100_firmware {
	uint8_t			*bin_base; /* image */
	size_t			bin_size;
	uint8_t			*fw_base; /* firmware code */
	size_t			fw_size;
	uint8_t			*uc_base; /* u-controller code */
	size_t			uc_size;
};

/*
 * per-instance soft-state structure
 */
struct ipw2100_softc {
	struct ieee80211com	sc_ic;
	dev_info_t		*sc_dip;
	int	(*sc_newstate)(struct ieee80211com *,
	    enum ieee80211_state, int);
	int			sc_authmode;
	/* CSR */
	ddi_acc_handle_t	sc_ioh;
	caddr_t			sc_regs;
	/* interrupt */
	ddi_iblock_cookie_t	sc_iblk;
	/* soft interrupt */
	ddi_softintr_t		sc_link_softint;
	/* link state */
	int32_t			sc_linkstate;
	/* mutex to protect interrupt handler */
	kmutex_t		sc_ilock;
	kcondvar_t		sc_fw_cond;
	/* flags */
	uint_t			sc_flags;
#define	IPW2100_FLAG_FW_CACHED		(1 << 0)
#define	IPW2100_FLAG_FW_INITED		(1 << 1)
#define	IPW2100_FLAG_RUNNING		(1 << 2)
#define	IPW2100_FLAG_LINK_CHANGE	(1 << 3)
#define	IPW2100_FLAG_TX_SCHED		(1 << 4)
#define	IPW2100_FLAG_CMD_WAIT		(1 << 5)
#define	IPW2100_FLAG_SCAN_COMPLETE	(1 << 6)
#define	IPW2100_FLAG_HW_ERR_RECOVER	(1 << 7)
#define	IPW2100_FLAG_HAS_RADIO_SWITCH	(1 << 16)
	/* command */
	struct ipw2100_cmd	*sc_cmd;
	int			sc_done; /* command is done */
	kcondvar_t		sc_cmd_cond;
	/* reschedule lock */
	kmutex_t		sc_resched_lock;
	/* tx ring, bd->hdr&buf */
	kmutex_t		sc_tx_lock;
	kcondvar_t		sc_tx_cond;
	uint32_t		sc_tx_cur;
	uint32_t		sc_tx_free;
	struct ipw2100_bd	*sc_txbd;
	struct ipw2100_txb	*sc_txbufs[IPW2100_NUM_TXBUF];
	/* rx ring, status, bd->buf */
	uint32_t		sc_rx_cur;
	uint32_t		sc_rx_free;
	struct ipw2100_status	*sc_status;
	struct ipw2100_bd	*sc_rxbd;
	struct ipw2100_rxb	*sc_rxbufs[IPW2100_NUM_RXBUF];
	/* DMA resources */
	struct dma_region	sc_dma_txbd; /* tx buffer descriptor */
	struct dma_region	sc_dma_txbufs[IPW2100_NUM_TXBUF];
	struct dma_region	sc_dma_rxbd; /* rx buffer descriptor */
	struct dma_region	sc_dma_rxbufs[IPW2100_NUM_RXBUF];
	struct dma_region	sc_dma_status;
	struct dma_region	sc_dma_cmd; /* command */
	/* hw configuration values */
	uint8_t			sc_macaddr[IEEE80211_ADDR_LEN];
	uint16_t		sc_chmask;
	/* MAC address string */
	char			sc_macstr[32];
	/* tables */
	uint32_t		sc_table1_base;
	uint32_t		sc_table2_base;
	/* firmware */
	struct			ipw2100_firmware sc_fw;
	/* mfthread related */
	kmutex_t		sc_mflock;
	kcondvar_t		sc_mfthread_cv;
	kcondvar_t		sc_scan_cv; /* used for active scan */
	kthread_t		*sc_mf_thread;
	uint32_t		sc_mfthread_switch; /* 0/1 indicate off/on */
	int			if_flags;
};

/*
 * RING_BACKWARD  - move 'x' backward 's' steps in a 'b'-sized ring
 * RING_FORWARD   - move 'x' forward 's' steps in a 'b'-sized ring
 *
 * note that there must be 0 <= 'x' < 'b' && 0 <= 's' < 'b'
 */
#define	RING_FLEN(x, y, b)	((((x) > (y)) ? ((b)+(y)-(x)) : ((y)-(x))))
#define	RING_FORWARD(x, s, b)	(((x)+(s))%(b))
#define	RING_BACKWARD(x, s, b)	RING_FORWARD((x), (b)-(s), (b))

/*
 * field_offset
 */
#define	OFFSETOF(s, m)		((size_t)(&(((s *)0)->m)))

extern int ipw2100_init(struct ipw2100_softc *sc);
extern int ipw2100_disable(struct ipw2100_softc *sc);

/*
 * Below structure and functions will be used for statistic
 */
struct statistic {
	int		index;
	const char	*desc;
	int		unit;
#define	INT		1
#define	HEX		2
#define	MASK		HEX
#define	PERCENTAGE	3
#define	BOOL		4
};
extern void ipw2100_get_statistics(struct ipw2100_softc *sc);

/*
 * Hardware related definations and interfaces.
 */
#define	IPW2100_CSR_INTR		(0x0008)
#define	IPW2100_CSR_INTR_MASK		(0x000c)
#define	IPW2100_CSR_INDIRECT_ADDR	(0x0010)
#define	IPW2100_CSR_INDIRECT_DATA	(0x0014)
#define	IPW2100_CSR_AUTOINC_ADDR	(0x0018)
#define	IPW2100_CSR_AUTOINC_DATA	(0x001c)
#define	IPW2100_CSR_RST			(0x0020)
#define	IPW2100_CSR_CTL			(0x0024)
#define	IPW2100_CSR_IO			(0x0030)
#define	IPW2100_CSR_DEBUG_AREA		(0x0090)

#define	IPW2100_CSR_TX_BD_BASE		(0x0200)
#define	IPW2100_CSR_TX_BD_SIZE		(0x0204)
#define	IPW2100_CSR_RX_BD_BASE		(0x0240)
#define	IPW2100_CSR_RX_STATUS_BASE	(0x0244)
#define	IPW2100_CSR_RX_BD_SIZE		(0x0248)
#define	IPW2100_CSR_TABLE1_BASE		(0x0380)
#define	IPW2100_CSR_TABLE2_BASE		(0x0384)
/*
 * tx-rd-index  the entry to be processed by HW, i.e. empty tx buffer
 * tx-wr-index  the entry just being filled by SW with new data to transmit
 */
#define	IPW2100_CSR_TX_READ_INDEX	(0x0280)
#define	IPW2100_CSR_TX_WRITE_INDEX	(0x0f80)
/*
 * rx-rd-index  the entry just being processed by HW, i.e. new received data
 * rx-wr-index  the entry just being set by SW to empty buffer to receive
 */
#define	IPW2100_CSR_RX_READ_INDEX	(0x02a0)
#define	IPW2100_CSR_RX_WRITE_INDEX	(0x0fa0)

/*
 * CSR flags: IPW2100_CSR_INTR
 * The interrupt register is used to indicate the h/w status
 */
#define	IPW2100_INTR_TX_TRANSFER	(0x00000001)
#define	IPW2100_INTR_RX_TRANSFER	(0x00000002)
#define	IPW2100_INTR_STATUS_CHANGE	(0x00000010)
#define	IPW2100_INTR_COMMAND_DONE	(0x00010000)
#define	IPW2100_INTR_FW_INIT_DONE	(0x01000000)
#define	IPW2100_INTR_FATAL_ERROR	(0x40000000)
#define	IPW2100_INTR_PARITY_ERROR	(0x80000000)
#define	IPW2100_INTR_MASK_ALL	(IPW2100_INTR_TX_TRANSFER | \
				IPW2100_INTR_RX_TRANSFER | \
				IPW2100_INTR_STATUS_CHANGE | \
				IPW2100_INTR_COMMAND_DONE | \
				IPW2100_INTR_FW_INIT_DONE | \
				IPW2100_INTR_FATAL_ERROR | \
				IPW2100_INTR_PARITY_ERROR)
#define	IPW2100_INTR_MASK_ERR	(IPW2100_INTR_FATAL_ERROR | \
				IPW2100_INTR_PARITY_ERROR)

/*
 * CSR flags: IPW2100_CSR_RST
 * The reset register is used to reset hardware
 */
#define	IPW2100_RST_PRINCETON_RESET	(0x00000001)
#define	IPW2100_RST_SW_RESET		(0x00000080)
#define	IPW2100_RST_MASTER_DISABLED	(0x00000100)
#define	IPW2100_RST_STOP_MASTER		(0x00000200)

/*
 * CSR flags: IPW2100_CSR_CTL
 */
#define	IPW2100_CTL_CLOCK_READY		(0x00000001)
#define	IPW2100_CTL_ALLOW_STANDBY	(0x00000002)
#define	IPW2100_CTL_INIT		(0x00000004)

/*
 * CSR flags: IPW2100_CSR_IO
 */
#define	IPW2100_IO_GPIO1_ENABLE		(0x00000008)
#define	IPW2100_IO_GPIO1_MASK		(0x0000000c)
#define	IPW2100_IO_GPIO3_MASK		(0x000000c0)
#define	IPW2100_IO_LED_OFF		(0x00002000)
#define	IPW2100_IO_RADIO_DISABLED	(0x00010000)

/*
 * States code
 */
#define	IPW2100_STATE_ASSOCIATED	(0x0004)
#define	IPW2100_STATE_ASSOCIATION_LOST	(0x0008)
#define	IPW2100_STATE_SCAN_COMPLETE	(0x0020)
#define	IPW2100_STATE_RADIO_DISABLED	(0x0100)
#define	IPW2100_STATE_DISABLED		(0x0200)
#define	IPW2100_STATE_SCANNING		(0x0800)

/*
 * table1 offsets
 */
#define	IPW2100_INFO_LOCK		(480)
#define	IPW2100_INFO_APS_CNT		(604)
#define	IPW2100_INFO_APS_BASE		(608)
#define	IPW2100_INFO_CARD_DISABLED	(628)
#define	IPW2100_INFO_CURRENT_CHANNEL	(756)
#define	IPW2100_INFO_CURRENT_TX_RATE	(768)

/*
 * table2 offsets
 */
#define	IPW2100_INFO_CURRENT_SSID	(48)
#define	IPW2100_INFO_CURRENT_BSSID	(112)

/*
 * supported rates
 */
#define	IPW2100_RATE_DS1		(1)
#define	IPW2100_RATE_DS2		(2)
#define	IPW2100_RATE_DS5		(4)
#define	IPW2100_RATE_DS11		(8)

/* hw structures, packed */
#pragma pack(1)
/*
 * firmware binary image header
 */
struct ipw2100_firmware_hdr {
	uint32_t	version;
	uint32_t	fw_size;
	uint32_t	uc_size;
};

/*
 * buffer descriptor
 */
struct ipw2100_bd {
	uint32_t	phyaddr;
	uint32_t	len;
	uint8_t		flags;
/* flags */
#define	IPW2100_BD_FLAG_TX_LAST_FRAGMENT	(0x08)
#define	IPW2100_BD_FLAG_TX_NOT_LAST_FRAGMENT	(0x01)
/* data content */
#define	IPW2100_BD_FLAG_TX_FRAME_802_3		(0x00)
#define	IPW2100_BD_FLAG_TX_FRAME_COMMAND	(0x02)
#define	IPW2100_BD_FLAG_TX_FRAME_802_11		(0x04)
	/* number of fragments, only 1st BD is needed */
	uint8_t		nfrag;
	uint8_t		reserved[6];
};

/*
 * status descriptor
 */
struct ipw2100_status {
	uint32_t	len;
	uint16_t	code;
#define	IPW2100_STATUS_CODE_COMMAND		(0)
#define	IPW2100_STATUS_CODE_NEWSTATE		(1)
#define	IPW2100_STATUS_CODE_DATA_802_11		(2)
#define	IPW2100_STATUS_CODE_DATA_802_3		(3)
#define	IPW2100_STATUS_CODE_NOTIFICATION	(4)
	uint8_t		flags;
#define	IPW2100_STATUS_FLAG_DECRYPTED		(0x01)
#define	IPW2100_STATUS_FLAG_WEP_ENCRYPTED	(0x02)
#define	IPW2100_STATUS_FLAG_CRC_ERROR		(0x04)
	/* received signal strength indicator */
	uint8_t		rssi;
};

/*
 * data header
 */
struct ipw2100_hdr {
	uint32_t	type;
	uint32_t	subtype;
	uint8_t		encrypted;
	uint8_t		encrypt;
	uint8_t		keyidx;
	uint8_t		keysz;
	uint8_t		key[IEEE80211_KEYBUF_SIZE];
	uint8_t		reserved[10];
	uint8_t		saddr[IEEE80211_ADDR_LEN];
	uint8_t		daddr[IEEE80211_ADDR_LEN];
	uint16_t	fragsz;
};

/*
 * command
 */
struct ipw2100_cmd {
	uint32_t	type;
#define	IPW2100_CMD_ENABLE			(2)
#define	IPW2100_CMD_SET_CONFIGURATION		(6)
#define	IPW2100_CMD_SET_ESSID			(8)
#define	IPW2100_CMD_SET_MANDATORY_BSSID		(9)
#define	IPW2100_CMD_SET_AUTH_TYPE		(10)
#define	IPW2100_CMD_SET_MAC_ADDRESS		(11)
#define	IPW2100_CMD_SET_MODE			(12)
#define	IPW2100_CMD_SET_I18N_MODE		(13)
#define	IPW2100_CMD_SET_CHANNEL			(14)
#define	IPW2100_CMD_SET_RTS_THRESHOLD		(15)
#define	IPW2100_CMD_SET_FRAG_THRESHOLD		(16)
#define	IPW2100_CMD_SET_POWER_MODE		(17)
#define	IPW2100_CMD_SET_TX_RATES		(18)
#define	IPW2100_CMD_SET_BASIC_TX_RATES		(19)
#define	IPW2100_CMD_SET_WEP_KEY			(20)
#define	IPW2100_CMD_SET_WEP_KEY_INDEX		(25)
#define	IPW2100_CMD_SET_WEP_FLAGS		(26)
#define	IPW2100_CMD_ADD_MULTICAST		(27)
#define	IPW2100_CMD_CLR_MULTICAST		(28)
#define	IPW2100_CMD_SET_BEACON_INTERVAL		(29)
#define	IPW2100_CMD_CLR_STATISTICS		(31)
#define	IPW2100_CMD_SEND			(33)
#define	IPW2100_CMD_SET_TX_POWER_INDEX		(36)
#define	IPW2100_CMD_BROADCAST_SCAN		(43)
#define	IPW2100_CMD_DISABLE			(44)
#define	IPW2100_CMD_SET_DESIRED_BSSID		(45)
#define	IPW2100_CMD_SET_SCAN_OPTIONS		(46)
#define	IPW2100_CMD_PREPARE_POWER_DOWN		(58)
#define	IPW2100_CMD_DISABLE_PHY			(61)
#define	IPW2100_CMD_SET_SECURITY_INFORMATION	(67)
#define	IPW2100_CMD_SET_WPA_IE			(69)
	uint32_t	subtype;
	uint32_t	seq;
	uint32_t	len;
	uint8_t		data[400];
	uint32_t	status;
	uint8_t		reserved[68];
};

/*
 * IPW2100_CMD_SET_POWER_MODE
 */
#define	IPW2100_POWER_MODE_CAM	(0)
#define	IPW2100_POWER_AUTOMATIC	(6)

/*
 * IPW2100_CMD_SET_MODE
 */
#define	IPW2100_MODE_BSS	(0)
#define	IPW2100_MODE_IBSS	(1)
#define	IPW2100_MODE_MONITOR	(2)

/*
 * structure for IPW2100_CMD_SET_WEP_KEY
 */
struct ipw2100_wep_key {
	uint8_t		idx;
	uint8_t		len;
	uint8_t		key[13];
};

/*
 * structure for IPW2100_CMD_SET_SECURITY_INFORMATION
 */
struct ipw2100_security {
	uint32_t	ciphers;
#define	IPW2100_CIPHER_NONE	(0x00000001)
#define	IPW2100_CIPHER_WEP40	(0x00000002)
#define	IPW2100_CIPHER_WEP104	(0x00000020)
	uint16_t	version;
	uint8_t		authmode;
#define	IPW2100_AUTH_OPEN	(0)
#define	IPW2100_AUTH_SHARED	(1)
	uint8_t		replay_counters_number;
	uint8_t		unicast_using_group;
};

/*
 * structure for IPW2100_CMD_SET_SCAN_OPTIONS
 */
struct ipw2100_scan_options {
	uint32_t	flags;
#define	IPW2100_SCAN_DO_NOT_ASSOCIATE	(0x00000001)
#define	IPW2100_SCAN_PASSIVE		(0x00000008)
	uint32_t	channels;
};

/*
 * structure for IPW2100_CMD_SET_CONFIGURATION
 */
struct ipw2100_configuration {
	uint32_t	flags;
#define	IPW2100_CFG_PROMISCUOUS		(0x00000004)
#define	IPW2100_CFG_PREAMBLE_AUTO	(0x00000010)
#define	IPW2100_CFG_IBSS_AUTO_START	(0x00000020)
#define	IPW2100_CFG_802_1x_ENABLE	(0x00004000)
#define	IPW2100_CFG_BSS_MASK		(0x00008000)
#define	IPW2100_CFG_IBSS_MASK		(0x00010000)
	uint32_t	bss_chan;
	uint32_t	ibss_chan;
};

/*
 * element in AP table
 */
struct ipw2100_node {
	uint32_t	reserved_1[2];
	uint8_t		bssid[IEEE80211_ADDR_LEN];
	uint8_t		chan;
	uint8_t		rates;
	uint16_t	reserved_2;
	uint16_t	capinfo;
	uint16_t	reserved_3;
	uint16_t	intval;
	uint8_t		reserved_4[28];
	uint8_t		essid[IEEE80211_NWID_LEN];
	uint16_t	reserved_5;
	uint8_t		esslen;
	uint8_t		reserved_6[7];
	uint8_t		rssi;
};
#pragma pack()

/*
 * transmit buffer block
 */
struct ipw2100_txb {
	struct ipw2100_hdr	txb_hdr; /* header */
	uint8_t			txb_dat[IEEE80211_MAX_LEN]; /* payload */
};

/*
 * maximum frame header lenght: 4 MAC addresses + 1 fc + 1 id + 1 seqctl
 */
#define	IEEE80211_MAX_FHLEN	(4*6+2+2+2)

/*
 * receive buffer block
 */
struct ipw2100_rxb {
	uint8_t		rxb_dat[IEEE80211_MAX_FHLEN   /* frame */
				+ IEEE80211_MAX_LEN   /* payload */
				+ IEEE80211_CRC_LEN]; /* FCS */
};

/*
 * ROM entries
 */
#define	IPW2100_ROM_RADIO		(0x11)
#define	IPW2100_ROM_MAC			(0x21)
#define	IPW2100_ROM_CHANNEL_LIST	(0x37)

/*
 * EEPROM controls
 */
#define	IPW2100_IMEM_EEPROM_CTL		(0x00300040)
#define	IPW2100_EEPROM_DELAY		(1)

/*
 * CSR access routines
 */
extern uint8_t ipw2100_csr_get8(struct ipw2100_softc *sc, uint32_t off);
extern uint16_t ipw2100_csr_get16(struct ipw2100_softc *sc, uint32_t off);
extern uint32_t ipw2100_csr_get32(struct ipw2100_softc *sc, uint32_t off);
extern void ipw2100_csr_rep_get16(struct ipw2100_softc *sc, uint32_t off,
    uint16_t *buf, size_t cnt);
extern void ipw2100_csr_put8(struct ipw2100_softc *sc, uint32_t off,
    uint8_t val);
extern void ipw2100_csr_put16(struct ipw2100_softc *sc,
    uint32_t off, uint16_t val);
extern void ipw2100_csr_put32(struct ipw2100_softc *sc,
    uint32_t off, uint32_t val);
extern void ipw2100_csr_rep_put8(struct ipw2100_softc *sc,
    uint32_t off, uint8_t *buf, size_t cnt);
extern uint8_t ipw2100_imem_get8(struct ipw2100_softc *sc, int32_t addr);
extern uint16_t ipw2100_imem_get16(struct ipw2100_softc *sc,
    uint32_t addr);
extern uint32_t ipw2100_imem_get32(struct ipw2100_softc *sc,
    uint32_t addr);
extern void ipw2100_imem_rep_get16(struct ipw2100_softc *sc,
    uint32_t addr, uint16_t *buf, size_t cnt);
extern void ipw2100_imem_put8(struct ipw2100_softc *sc,
    uint32_t addr, uint8_t val);
extern void ipw2100_imem_put16(struct ipw2100_softc *sc,
    uint32_t addr, uint16_t val);
extern void ipw2100_imem_put32(struct ipw2100_softc *sc,
    uint32_t addr, uint32_t val);
extern void ipw2100_imem_rep_put8(struct ipw2100_softc *sc,
    uint32_t addr, uint8_t *buf, size_t cnt);
extern void ipw2100_imem_getbuf(struct ipw2100_softc *sc,
    uint32_t addr, uint8_t *buf, size_t cnt);
extern void ipw2100_imem_putbuf(struct ipw2100_softc *sc,
    uint32_t addr, uint8_t *buf, size_t cnt);
extern void ipw2100_rom_control(struct ipw2100_softc *sc, uint32_t val);
extern uint8_t ipw2100_table1_get8(struct ipw2100_softc *sc, uint32_t off);
extern uint32_t ipw2100_table1_get32(struct ipw2100_softc *sc,
    uint32_t off);
extern void ipw2100_table1_put32(struct ipw2100_softc *sc,
    uint32_t off, uint32_t val);
extern int ipw2100_table2_getbuf(struct ipw2100_softc *sc,
    uint32_t off, uint8_t *buf, uint32_t *len);

extern uint16_t ipw2100_rom_get16(struct ipw2100_softc *sc, uint8_t addr);

/*
 * Firmware related definations and interfaces.
 */
extern int ipw2100_cache_firmware(struct ipw2100_softc *sc);
extern int ipw2100_free_firmware(struct ipw2100_softc *sc);
extern int ipw2100_load_uc(struct ipw2100_softc *sc);
extern int ipw2100_load_fw(struct ipw2100_softc *sc);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IPW2100_IMPL_H */
