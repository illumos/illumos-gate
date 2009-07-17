/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2007, 2008
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

#ifndef	_RT2860_VAR_H
#define	_RT2860_VAR_H

#include <sys/queue.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * EDCA Access Categories.
 */
enum ieee80211_edca_ac {
	EDCA_AC_BK  = 1,	/* Background */
	EDCA_AC_BE  = 0,	/* Best Effort */
	EDCA_AC_VI  = 2,	/* Video */
	EDCA_AC_VO  = 3		/* Voice */
};
#define	EDCA_NUM_AC	4

#define	RT2860_SUCCESS		0

#define	RT2860_TX_RING_COUNT	64
#define	RT2860_RX_RING_COUNT	128
#define	RT2860_TX_POOL_COUNT	(RT2860_TX_RING_COUNT * 2)

#define	RT2860_MAX_SCATTER	((RT2860_TX_RING_COUNT * 2) - 1)

#define	RT2860_RSSI_OFFSET	92

/* HW supports up to 255 STAs */
#define	RT2860_WCID_MAX		254
#define	RT2860_AID2WCID(aid)	((aid) & 0xff)

struct dma_area {
	ddi_acc_handle_t	acc_hdl;	/* handle for memory */
	caddr_t			mem_va;		/* CPU VA of memory */
	uint32_t		nslots;		/* number of slots */
	uint32_t		size;		/* size per slot */
	size_t			alength;	/* allocated size */

	ddi_dma_handle_t	dma_hdl;	/* DMA handle */
	offset_t		offset;		/* relative to handle */
	ddi_dma_cookie_t	cookie;		/* associated cookie */
	uint32_t		ncookies;	/* must be 1 */
	uint32_t		token;		/* arbitrary identifier */
};

struct rt2860_txd;

struct rt2860_tx_data {
	struct dma_area			txbuf_dma;
	struct rt2860_txwi		*txwi;
	uint32_t			paddr;
	struct ieee80211_node		*ni;
	SLIST_ENTRY(rt2860_tx_data)	next;
};

struct rt2860_tx_ring {
	struct dma_area		txdesc_dma;
	struct rt2860_txd	*txd;
	uint32_t		paddr;
	struct rt2860_tx_data	*data[RT2860_TX_RING_COUNT];
	int			cur;
	int			next;
	int			queued;
};

struct rt2860_rx_data {
	struct dma_area		rxbuf_dma;
};

struct rt2860_rx_ring {
	struct dma_area		rxdesc_dma;
	struct rt2860_rxd	*rxd;
	uint32_t		paddr;
	unsigned int		cur;	/* must be unsigned */
	struct rt2860_rx_data	data[RT2860_RX_RING_COUNT];
};

struct rt2860_amrr {
	uint_t	amrr_min_success_threshold;
	uint_t	amrr_max_success_threshold;
};

struct rt2860_amrr_node {
	int	amn_success;
	int	amn_recovery;
	int	amn_success_threshold;
	int	amn_txcnt;
	int	amn_retrycnt;
};

#define	RT2860_DMA_SYNC(area, flag) ((void) ddi_dma_sync((area).dma_hdl,\
	(area).offset, (area).alength, (flag)))
#define	RT2860_IS_RUNNING(_sc)		(((_sc)->sc_flags & RT2860_F_RUNNING))
#define	RT2860_IS_INITED(_sc)		((_sc)->sc_flags & RT2860_F_RUNNING)
#define	RT2860_IS_SUSPEND(_sc)		((_sc)->sc_flags & RT2860_F_SUSPEND)
#define	RT2860_GLOCK(_sc)		mutex_enter(&(_sc)->sc_genlock)
#define	RT2860_GUNLOCK(_sc)		mutex_exit(&(_sc)->sc_genlock)


struct rt2860_softc {
	struct ieee80211com	sc_ic;
	dev_info_t		*sc_dev;

	/* ddi reg handler */
	ddi_acc_handle_t	sc_cfg_handle;
	caddr_t			sc_cfg_base;
	/* ddi i/o handler */
	ddi_acc_handle_t	sc_io_handle;
	caddr_t			sc_io_base;
	/* interrupt */
	ddi_iblock_cookie_t	sc_iblock;
	kmutex_t		sc_genlock;
	kmutex_t		sc_txlock;
	kmutex_t		sc_rxlock;
	timeout_id_t		sc_scan_id;
	timeout_id_t		sc_rssadapt_id;
	timeout_id_t		sc_state_id;
	struct rt2860_amrr	amrr;
	enum ieee80211_state	sc_ostate;

#define	RT2860_ENABLED		(1 << 0)
#define	RT2860_FWLOADED		(1 << 1)
#define	RT2860_UPD_BEACON	(1 << 2)
#define	RT2860_ADVANCED_PS	(1 << 3)
#define	RT2860_F_RUNNING	(1 << 4)
#define	RT2860_F_SUSPEND	(1 << 5)
#define	RT2860_F_QUIESCE	(1 << 6)

	uint32_t			sc_ic_flags;
	uint32_t			sc_dmabuf_size;
	struct rt2860_tx_ring		txq[6];
	struct rt2860_rx_ring		rxq;

	struct dma_area			txpool_dma;
	struct rt2860_txwi		*txwi;
	struct rt2860_tx_data		data[RT2860_TX_POOL_COUNT];
	SLIST_HEAD(, rt2860_tx_data)	data_pool;

	int			sc_tx_timer;
	int			mgtqid;
	int			sifs;

	/* firmware related info */
	uint32_t		mac_rev;
	uint8_t			rf_rev;
	uint8_t			freq;
	uint8_t			ntxchains;
	uint8_t			nrxchains;
	uint8_t			pslevel;
	int8_t			txpow1[50];
	int8_t			txpow2[50];
	int8_t			rssi_2ghz[3];
	int8_t			rssi_5ghz[3];
	uint8_t			lna[4];
	uint8_t			calib_2ghz;
	uint8_t			calib_5ghz;
	uint8_t			tssi_2ghz[9];
	uint8_t			tssi_5ghz[9];
	uint8_t			step_2ghz;
	uint8_t			step_5ghz;

	uint32_t		sc_need_sched;
	uint32_t		sc_flags;
	/* RT2860 RCR */
	uint32_t		sc_rcr;

	uint16_t		sc_cachelsz;
	ddi_softintr_t		sc_softintr_hdl;

	uint32_t		sc_rx_pend;

	uint32_t		rf_regs[4];
	uint8_t			txpow[14];

	struct {
		uint8_t	reg;
		uint8_t	val;
	}			bbp[8];
	uint8_t			leds;
	uint16_t		led[3];
	uint32_t		txpow20mhz[5];
	uint32_t		txpow40mhz_2ghz[5];
	uint32_t		txpow40mhz_5ghz[5];

	struct rt2860_amrr_node	amn[RT2860_WCID_MAX + 1];

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

#ifdef __cplusplus
}
#endif

#endif /* _RT2860_VAR_H */
