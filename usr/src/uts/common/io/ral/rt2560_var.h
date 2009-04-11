/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2005, 2006
 *	Damien Bergamini <damien.bergamini@free.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifndef	_RT2560_VAR_H
#define	_RT2560_VAR_H

#ifdef __cplusplus
extern "C" {
#endif

#define	RAL_FLAG_RUNNING	(1<<0)
#define	RAL_FLAG_SUSPENDING	(1<<1)

#define	RAL_RCR_PROMISC		(1<<0)
#define	RAL_RCR_MULTI		(2<<0)

#ifndef	DDI_NT_NET_WIFI
#define	DDI_NT_NET_WIFI		"ddi_network:wifi"
#endif

/*
 * Bit flags in the ral_dbg_flags
 */
#define	RAL_DBG_MSG		0x000001
#define	RAL_DBG_HW		0x000002
#define	RAL_DBG_DMA		0x000004
#define	RAL_DBG_INTR		0x000008
#define	RAL_DBG_TX		0x000010
#define	RAL_DBG_RX		0x000020
#define	RAL_DBG_CHAN		0x000040
#define	RAL_DBG_IOCTL		0x000080
#define	RAL_DBG_MGMT		0x000100
#define	RAL_DBG_STAT		0x000200
#define	RAL_DBG_GLD		0x000400
#define	RAL_DBG_80211		0x000800
#define	RAL_DBG_STATE		0x001000
#define	RAL_DBG_RXPACKET	0x002000
#define	RAL_DBG_TXPACKET	0x004000
#define	RAL_DBG_SUSPEND		0x008000
#define	RAL_DBG_ALL		0x00ffff

#define	RT2560_RX_RADIOTAP_PRESENT					\
	((1 << IEEE80211_RADIOTAP_TSFT) |				\
	(1 << IEEE80211_RADIOTAP_FLAGS) |				\
	(1 << IEEE80211_RADIOTAP_RATE) |				\
	(1 << IEEE80211_RADIOTAP_CHANNEL) |				\
	(1 << IEEE80211_RADIOTAP_ANTENNA) |				\
	(1 << IEEE80211_RADIOTAP_DB_ANTSIGNAL))

#define	RT2560_TX_RADIOTAP_PRESENT					\
	((1 << IEEE80211_RADIOTAP_FLAGS) |				\
	(1 << IEEE80211_RADIOTAP_RATE) |				\
	(1 << IEEE80211_RADIOTAP_CHANNEL) |				\
	(1 << IEEE80211_RADIOTAP_ANTENNA))

struct dma_region {
	ddi_dma_handle_t	dr_hnd;
	ddi_acc_handle_t	dr_acc;
	ddi_dma_cookie_t	dr_cookie;
	uint_t			dr_ccnt;
	uint32_t		dr_pbase;
	caddr_t			dr_base;
	size_t			dr_size;
};

struct rt2560_tx_data {
	caddr_t			buf;
	struct ieee80211_node	*ni;
	struct ral_rssdesc	id;
};

/*
 * physaddr = dr_desc.dr_pbase
 * desc = dr_desc.dr_base, desc[i].physaddr = dr_txbuf[i].dr_pbase
 * data[i]->buf = dr_txbuf[i].dr_bas
 */
struct rt2560_tx_ring {
	uint32_t		physaddr;
	struct rt2560_tx_desc	*desc;
	struct rt2560_tx_data	*data;

	struct dma_region	dr_desc;
	struct dma_region	*dr_txbuf;

	int			count;
	int			queued;
	int			cur;
	int			next;
	int			cur_encrypt;
	int			next_encrypt;
	kmutex_t		tx_lock;
};

struct rt2560_rx_data {
	caddr_t			buf;
	int			drop;
};

struct rt2560_rx_ring {
	uint32_t		physaddr;
	struct rt2560_rx_desc	*desc;
	struct rt2560_rx_data	*data;

	struct dma_region	dr_desc;
	struct dma_region	*dr_rxbuf;

	int			count;
	int			cur;
	int			next;
	int			cur_decrypt;
	kmutex_t		rx_lock;
};

struct rt2560_node {
	struct ieee80211_node	ni;
	struct ral_rssadapt	rssadapt;
};

struct rt2560_softc {
	struct ieee80211com	sc_ic;
	dev_info_t		*sc_dev;

	/* ddi i/o handler */
	ddi_acc_handle_t	sc_ioh;
	caddr_t			sc_rbase;

	/* interrupt */
	ddi_iblock_cookie_t	sc_iblock;

	kmutex_t		sc_genlock;

	timeout_id_t		sc_scan_id;
	timeout_id_t		sc_rssadapt_id;

	enum ieee80211_state	sc_ostate;
	timeout_id_t		sc_state_id;

	int			sc_tx_timer;

	uint32_t		asic_rev;
	uint32_t		eeprom_rev;
	uint8_t			rf_rev;

	struct rt2560_tx_ring	txq;
	struct rt2560_tx_ring	prioq;
	struct rt2560_rx_ring	rxq;

	uint32_t		sc_need_sched;
	uint32_t		sc_flags;
	uint32_t		sc_rcr;		/* RAL RCR */

	uint16_t		sc_cachelsz;
	ddi_softintr_t		sc_softint_id;

	uint32_t		sc_rx_pend;

	uint32_t		rf_regs[4];
	uint8_t			txpow[14];

	struct {
		uint8_t	reg;
		uint8_t	val;
	}			bbp_prom[16];

	int			led_mode;
	int			hw_radio;
	int			rx_ant;
	int			tx_ant;
	int			nb_ant;

	int			dwelltime;

	/* kstats */
	uint32_t		sc_tx_nobuf;
	uint32_t		sc_rx_nobuf;
	uint32_t		sc_tx_err;
	uint32_t		sc_rx_err;
	uint32_t		sc_tx_retries;

	int			(*sc_newstate)(struct ieee80211com *,
				    enum ieee80211_state, int);
};

#define	RAL_IS_RUNNING(_sc)	(((_sc)->sc_flags & RAL_FLAG_RUNNING) && \
	!((_sc)->sc_flags & RAL_FLAG_SUSPENDING))
#define	RAL_IS_INITED(_sc)	((_sc)->sc_flags & RAL_FLAG_RUNNING)
#define	RAL_LOCK(sc)		mutex_enter(&(sc)->sc_genlock)
#define	RAL_UNLOCK(sc)		mutex_exit(&(sc)->sc_genlock)

#define	MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define	MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

#ifdef __cplusplus
}
#endif

#endif /* _RT2560_VAR_H */
