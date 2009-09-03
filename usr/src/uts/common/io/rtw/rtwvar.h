/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2004, 2005 David Young.  All rights reserved.
 *
 * Driver for the Realtek RTL8180 802.11 MAC/BBP by David Young.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of David Young may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY David Young ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL David
 * Young BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */
#ifndef _RTWVAR_H_
#define	_RTWVAR_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/list.h>
#include <sys/net80211.h>

#ifndef __func__
#define	__func__ ""
#endif

extern void rtw_dbg(uint32_t dbg_flags, const int8_t *fmt, ...);

#define	RTW_DEBUG_TUNE		0x000001
#define	RTW_DEBUG_PKTFILT	0x000002
#define	RTW_DEBUG_XMIT		0x000004
#define	RTW_DEBUG_DMA		0x000008
#define	RTW_DEBUG_NODE		0x000010
#define	RTW_DEBUG_PWR		0x000020
#define	RTW_DEBUG_ATTACH	0x000040
#define	RTW_DEBUG_REGDUMP	0x000080
#define	RTW_DEBUG_ACCESS	0x000100
#define	RTW_DEBUG_RESET		0x000200
#define	RTW_DEBUG_INIT		0x000400
#define	RTW_DEBUG_PKTDUMP	0x000800
#define	RTW_DEBUG_RECV		0x001000
#define	RTW_DEBUG_RECV_DESC	0x002000
#define	RTW_DEBUG_IOSTATE	0x004000
#define	RTW_DEBUG_INTR		0x008000
#define	RTW_DEBUG_PHY		0x010000
#define	RTW_DEBUG_PHYIO		0x020000
#define	RTW_DEBUG_PHYBITIO	0x040000
#define	RTW_DEBUG_TIMEOUT	0x080000
#define	RTW_DEBUG_BUGS		0x100000
#define	RTW_DEBUG_BEACON	0x200000
#define	RTW_DEBUG_WIFICFG	0x400000
#define	RTW_DEBUG_80211		0x800000
#define	RTW_DEBUG_MAX		0xffffff

#ifdef DEBUG
#define	RTW_DPRINTF \
	rtw_dbg
#else /* DEBUG */
#define	RTW_DPRINTF
#endif /* DEBUG */

enum rtw_locale {
	RTW_LOCALE_USA = 0,
	RTW_LOCALE_EUROPE,
	RTW_LOCALE_JAPAN,
	RTW_LOCALE_UNKNOWN
};

enum rtw_rfchipid {
	RTW_RFCHIPID_RESERVED = 0,
	RTW_RFCHIPID_INTERSIL = 1,
	RTW_RFCHIPID_RFMD = 2,
	RTW_RFCHIPID_PHILIPS = 3,
	RTW_RFCHIPID_MAXIM = 4,
	RTW_RFCHIPID_GCT = 5
};

/*
 * sc_flags
 */
#define	RTW_F_ENABLED		0x00000001	/* chip is enabled */
#define	RTW_F_DIGPHY		0x00000002	/* digital PHY */
#define	RTW_F_DFLANTB		0x00000004	/* B antenna is default */
#define	RTW_F_ANTDIV		0x00000010	/* h/w antenna diversity */
#define	RTW_F_9356SROM		0x00000020	/* 93c56 SROM */
#define	RTW_F_SLEEP		0x00000040	/* chip is asleep */
#define	RTW_F_INVALID		0x00000080	/* chip is absent */
#define	RTW_F_SUSPEND		0x00000100	/* driver is suspended */
#define	RTW_F_PLUMBED		0x00000200	/* driver is plumbed */
#define	RTW_F_ATTACHED		0x01000000	/* driver is attached */
/*
 * all PHY flags
 */
#define	RTW_F_ALLPHY		(RTW_F_DIGPHY|RTW_F_DFLANTB|RTW_F_ANTDIV)

enum rtw_access {RTW_ACCESS_NONE = 0,
		RTW_ACCESS_CONFIG = 1,
		RTW_ACCESS_ANAPARM = 2};

struct rtw_regs {
	ddi_acc_handle_t	r_handle;
	caddr_t			r_base;
	enum rtw_access		r_access;
};

#define	RTW_SR_GET(sr, ofs) \
	(((sr)->sr_content[(ofs)/2] >> (((ofs) % 2 == 0) ? 0 : 8)) & 0xff)

#define	RTW_SR_GET16(sr, ofs) \
	(RTW_SR_GET((sr), (ofs)) | (RTW_SR_GET((sr), (ofs) + 1) << 8))

struct rtw_srom {
	uint16_t		*sr_content;
	uint16_t		sr_size;
};


#define	RTW_NTXPRI	4	/* number of Tx priorities */
#define	RTW_TXPRILO	0
#define	RTW_TXPRIMD	1
#define	RTW_TXPRIHI	2
#define	RTW_TXPRIBCN	3	/* beacon priority */

#define	RTW_MAXPKTSEGS		64	/* Max 64 segments per Tx packet */

/*
 * Note well: the descriptor rings must begin on RTW_DESC_ALIGNMENT
 * boundaries.  I allocate them consecutively from one buffer, so
 * just round up.
 */
#define	RTW_TXQLENLO	64	/* low-priority queue length */
#define	RTW_TXQLENMD	64	/* medium-priority */
#define	RTW_TXQLENHI	64	/* high-priority */
#define	RTW_TXQLENBCN	2	/* beacon */

#define	RTW_NTXDESCLO	RTW_TXQLENLO
#define	RTW_NTXDESCMD	RTW_TXQLENMD
#define	RTW_NTXDESCHI	RTW_TXQLENHI
#define	RTW_NTXDESCBCN	RTW_TXQLENBCN

#define	RTW_NTXDESCTOTAL	(RTW_NTXDESCLO + RTW_NTXDESCMD + \
				RTW_NTXDESCHI + RTW_NTXDESCBCN)

#define	RTW_RXQLEN	64
#define	RTW_DMA_SYNC(area, flag) ((void) ddi_dma_sync((area).dma_hdl,\
	(area).offset, (area).alength, (flag)))

#define	RTW_DMA_SYNC_DESC(area, offset, len, flag) \
	((void) ddi_dma_sync((area).dma_hdl, offset, len, (flag)))

#define	RTW_MINC(x, y) (x) = ((x + 1) % y)
#define	list_empty(a) ((a)->list_head.list_next == &(a)->list_head)

typedef struct dma_area {
	ddi_acc_handle_t	acc_hdl;	/* handle for memory */
	caddr_t			mem_va;		/* CPU VA of memory */
	uint32_t		nslots;		/* number of slots */
	uint32_t		size;		/* size per slot */
	size_t			alength;	/* allocated size */
						/* >= product of above */

	ddi_dma_handle_t	dma_hdl;	/* DMA handle */
	offset_t		offset;		/* relative to handle */
	ddi_dma_cookie_t	cookie;		/* associated cookie */
	uint32_t		ncookies;	/* must be 1 */
	uint32_t		token;		/* arbitrary identifier */
} dma_area_t;						/* 0x50 (80) bytes */

struct rtw_txbuf {
	struct rtw_txdesc	*txdesc;	/* virtual addr of desc */
	uint32_t		bf_daddr;	/* physical addr of desc */
	uint32_t		next_bf_daddr;	/* physical addr of next desc */
	dma_area_t		bf_dma;		/* dma area for buf */
	struct ieee80211_node	*bf_in;		/* pointer to the node */
	list_node_t		bf_node;
	uint32_t		order;
};

struct rtw_rxbuf {
	struct rtw_rxdesc	*rxdesc;	/* virtual addr of desc */
	uint32_t		bf_daddr;	/* physical addr of desc */
	dma_area_t		bf_dma;		/* dma area for buf */
};

struct rtw_txq {
	struct	rtw_txdesc	*txdesc_h;
	struct	rtw_txbuf	*txbuf_h;
	uint32_t		tx_prod;
	uint32_t		tx_cons;
	uint32_t		tx_nfree;
	kmutex_t		txbuf_lock;
	list_t			tx_free_list;
	list_t			tx_dirty_list;
};

struct rtw_descs {
	struct rtw_txdesc	hd_txlo[RTW_NTXDESCLO];
	struct rtw_txdesc	hd_txmd[RTW_NTXDESCMD];
	struct rtw_txdesc	hd_txhi[RTW_NTXDESCHI];
	struct rtw_rxdesc	hd_rx[RTW_RXQLEN];
	struct rtw_txdesc	hd_bcn[RTW_NTXDESCBCN];
};
#define	RTW_DESC_OFFSET(ring, i)	offsetof(struct rtw_descs, ring[i])
#define	RTW_RING_OFFSET(ring)		RTW_DESC_OFFSET(ring, 0)
#define	RTW_RING_BASE(baseaddr0, ring) \
	(baseaddr0 + RTW_RING_OFFSET(ring))

/*
 * One Time Unit (TU) is 1Kus = 1024 microseconds.
 */
#define	IEEE80211_DUR_TU		1024

/*
 * IEEE 802.11b durations for DSSS PHY in microseconds
 */
#define	IEEE80211_DUR_DS_LONG_PREAMBLE	144
#define	IEEE80211_DUR_DS_SHORT_PREAMBLE	72

#define	IEEE80211_DUR_DS_SLOW_PLCPHDR	48
#define	IEEE80211_DUR_DS_FAST_PLCPHDR	24
#define	IEEE80211_DUR_DS_SLOW_ACK	112
#define	IEEE80211_DUR_DS_FAST_ACK	56
#define	IEEE80211_DUR_DS_SLOW_CTS	112
#define	IEEE80211_DUR_DS_FAST_CTS	56

#define	IEEE80211_DUR_DS_SLOT		20
#define	IEEE80211_DUR_DS_SIFS		10
#define	IEEE80211_DUR_DS_PIFS	(IEEE80211_DUR_DS_SIFS + IEEE80211_DUR_DS_SLOT)
#define	IEEE80211_DUR_DS_DIFS	(IEEE80211_DUR_DS_SIFS + \
				2 * IEEE80211_DUR_DS_SLOT)
#define	IEEE80211_DUR_DS_EIFS	(IEEE80211_DUR_DS_SIFS + \
				IEEE80211_DUR_DS_SLOW_ACK + \
				IEEE80211_DUR_DS_LONG_PREAMBLE + \
				IEEE80211_DUR_DS_SLOW_PLCPHDR + \
				IEEE80211_DUR_DIFS)

/*
 * 802.11 frame duration definitions.
 */
struct rtw_ieee80211_duration {
	uint16_t	d_rts_dur;
	uint16_t	d_data_dur;
	uint16_t	d_plcp_len;
	uint8_t		d_residue;	/* unused octets in time slot */
	uint8_t		resv;
};


#ifdef RTW_RADIOTAP
/*
 * Radio capture format for RTL8180.
 */

#define	RTW_RX_RADIOTAP_PRESENT					\
	((1 << IEEE80211_RADIOTAP_TSFT)			|	\
	(1 << IEEE80211_RADIOTAP_FLAGS)		|	\
	(1 << IEEE80211_RADIOTAP_RATE)			|	\
	(1 << IEEE80211_RADIOTAP_CHANNEL)		|	\
	(1 << IEEE80211_RADIOTAP_LOCK_QUALITY)		|	\
	(1 << IEEE80211_RADIOTAP_DB_ANTSIGNAL)		|	\
	0)

struct rtw_rx_radiotap_header {
	struct ieee80211_radiotap_header	rr_ihdr;
	uint64_t				rr_tsft;
	uint8_t				rr_flags;
	uint8_t				rr_rate;
	uint16_t				rr_chan_freq;
	uint16_t				rr_chan_flags;
	uint16_t				rr_barker_lock;
	uint8_t				rr_antsignal;
} __attribute__((__packed__));

#define	RTW_TX_RADIOTAP_PRESENT				\
	((1 << IEEE80211_RADIOTAP_FLAGS)	|	\
	(1 << IEEE80211_RADIOTAP_RATE)		|	\
	(1 << IEEE80211_RADIOTAP_CHANNEL)	|	\
	0)

struct rtw_tx_radiotap_header {
	struct ieee80211_radiotap_header	rt_ihdr;
	uint8_t				rt_flags;
	uint8_t				rt_rate;
	uint16_t				rt_chan_freq;
	uint16_t				rt_chan_flags;
} __attribute__((__packed__));
#endif

enum rtw_attach_state {FINISHED, FINISH_DESCMAP_LOAD, FINISH_DESCMAP_CREATE,
	FINISH_DESC_MAP, FINISH_DESC_ALLOC, FINISH_RXMAPS_CREATE,
	FINISH_TXMAPS_CREATE, FINISH_RESET, FINISH_READ_SROM, FINISH_PARSE_SROM,
	FINISH_RF_ATTACH, FINISH_ID_STA, FINISH_TXDESCBLK_SETUP,
	FINISH_TXCTLBLK_SETUP, DETACHED};

struct rtw_hooks {
	void			*rh_shutdown;	/* shutdown hook */
	void			*rh_power;	/* power management hook */
};

enum rtw_pwrstate { RTW_OFF = 0, RTW_SLEEP, RTW_ON };

typedef void (*rtw_continuous_tx_cb_t)(void *arg, int);

struct rtw_phy {
	struct rtw_rf	*p_rf;
	struct rtw_regs	*p_regs;
};

struct rtw_bbpset {
	uint_t	bb_antatten;
	uint_t	bb_chestlim;
	uint_t	bb_chsqlim;
	uint_t	bb_ifagcdet;
	uint_t	bb_ifagcini;
	uint_t	bb_ifagclimit;
	uint_t	bb_lnadet;
	uint_t	bb_sys1;
	uint_t	bb_sys2;
	uint_t	bb_sys3;
	uint_t	bb_trl;
	uint_t	bb_txagc;
};

struct rtw_rf {
	void	(*rf_destroy)(struct rtw_rf *);
	/*
	 * args: frequency, txpower, power state
	 */
	int	(*rf_init)(struct rtw_rf *, uint_t, uint8_t, enum rtw_pwrstate);
	/*
	 * arg: power state
	 */
	int	(*rf_pwrstate)(struct rtw_rf *, enum rtw_pwrstate);
	/*
	 * arg: frequency
	 */
	int	(*rf_tune)(struct rtw_rf *, uint_t);
	/*
	 * arg: txpower
	 */
	int	(*rf_txpower)(struct rtw_rf *, uint8_t);
	rtw_continuous_tx_cb_t	rf_continuous_tx_cb;
	void			*rf_continuous_tx_arg;
	struct rtw_bbpset	rf_bbpset;
};

typedef int (*rtw_rf_write_t)(struct rtw_regs *, enum rtw_rfchipid, uint_t,
    uint32_t);

struct rtw_rfbus {
	struct rtw_regs		*b_regs;
	rtw_rf_write_t		b_write;
};

struct rtw_max2820 {
	struct rtw_rf		mx_rf;
	struct rtw_rfbus	mx_bus;
	int			mx_is_a;	/* 1: MAX2820A/MAX2821A */
};

struct rtw_sa2400 {
	struct rtw_rf		sa_rf;
	struct rtw_rfbus	sa_bus;
	int			sa_digphy;	/* 1: digital PHY */
};

typedef void (*rtw_pwrstate_t)(struct rtw_regs *, enum rtw_pwrstate, int, int);

union rtw_keys {
	uint8_t		rk_keys[4][16];
	uint32_t	rk_words[16];
};

#define	RTW_LED_SLOW_TICKS	MAX(1, hz/2)
#define	RTW_LED_FAST_TICKS	MAX(1, hz/10)

struct rtw_led_state {
#define	RTW_LED0	0x1
#define	RTW_LED1	0x2
	uint8_t		ls_slowblink:2;
	uint8_t		ls_actblink:2;
	uint8_t		ls_default:2;
	uint8_t		ls_state;
	uint8_t		ls_event;
#define	RTW_LED_S_RX	0x1
#define	RTW_LED_S_TX	0x2
#define	RTW_LED_S_SLOW	0x4
};

typedef struct rtw_softc {
	ieee80211com_t		sc_ic;	/* IEEE 802.11 common */
	dev_info_t		*sc_dev; /* back pointer to dev_info_t */
	kmutex_t		sc_genlock;
	struct rtw_regs		sc_regs;
	ddi_acc_handle_t	sc_cfg_handle;
	caddr_t			sc_cfg_base;
	enum ieee80211_phymode	sc_curmode;
	uint32_t		sc_flags;
	uint32_t		sc_invalid;
	ddi_iblock_cookie_t	sc_iblock;
	uint32_t		sc_need_reschedule;
	uint16_t		sc_cachelsz;	/* cache line size */
	uchar_t			sc_macaddr[6];

	enum rtw_rfchipid	sc_rfchipid;
	enum rtw_locale		sc_locale;
	uint8_t			sc_phydelay;

	uint32_t		sc_dmabuf_size;
	dma_area_t		sc_desc_dma;

	struct rtw_txq		sc_txq[RTW_NTXPRI];

	struct	rtw_rxdesc	*rxdesc_h;
	struct  rtw_rxbuf	*rxbuf_h;
	uint32_t		rx_next;
	kmutex_t		rxbuf_lock;
	kmutex_t		sc_txlock;

	struct rtw_srom		sc_srom;
	enum rtw_pwrstate	sc_pwrstate;
	rtw_pwrstate_t		sc_pwrstate_cb;
	struct rtw_rf		*sc_rf;

	uint16_t		sc_inten;

	void (*sc_intr_ack)(struct rtw_regs *);

	int			(*sc_enable)(struct rtw_softc *);
	void			(*sc_disable)(struct rtw_softc *);
	void			(*sc_power)(struct rtw_softc *, int);
	struct rtw_hooks	sc_hooks;

	uint_t			sc_cur_chan;

	uint32_t		sc_tsfth;	/* most significant TSFT bits */
	uint32_t		sc_rcr;		/* RTW_RCR */
	uint8_t			sc_csthr;	/* carrier-sense threshold */

	uint8_t			sc_rev;		/* PCI/Cardbus revision */

	uint32_t		sc_anaparm;	/* register RTW_ANAPARM */
#ifdef RTW_RADIOTAP
	union {
		struct rtw_rx_radiotap_header	tap;
		uint8_t			pad[64];
	} sc_rxtapu;
	union {
		struct rtw_tx_radiotap_header	tap;
		uint8_t			pad[64];
	} sc_txtapu;
#endif
	union rtw_keys		sc_keys;
	int			sc_txkey;
	struct rtw_led_state	sc_led_state;
	int			sc_hwverid;

	int			(*sc_newstate)(ieee80211com_t *,
					enum ieee80211_state, int);

	timeout_id_t		sc_scan_id;
	timeout_id_t		sc_ratectl_id;
	uint32_t		sc_tx_ok;
	uint32_t		sc_tx_err;
	uint32_t		sc_tx_retr;
	uint32_t		sc_xmtretry;
	uint32_t		sc_noxmtbuf;
	uint32_t		sc_norcvbuf;
	uint32_t		sc_bytexmt64;
	uint32_t		sc_bytercv64;
	uint32_t		sc_pktxmt64;
	uint32_t		sc_pktrcv64;
	uint32_t		sc_intr;
	uint32_t		sc_ioerror;
	uint32_t		hw_start;
	uint32_t		hw_go;
} rtw_softc_t;

#define	RTW_SC(ic) ((rtw_softc_t *)ic)
#ifdef __cplusplus
}
#endif

#endif /* _RTWVAR_H_ */
