/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2006
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
#ifndef _WPIVAR_H
#define	_WPIVAR_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WPI_BPF
typedef struct wpi_rx_radiotap_header {
	struct ieee80211_radiotap_header wr_ihdr;
	uint64_t	wr_tsft;
	uint8_t		wr_flags;
	uint8_t		wr_rate;
	uint16_t	wr_chan_freq;
	uint16_t	wr_chan_flags;
	int8_t		wr_dbm_antsignal;
	int8_t		wr_dbm_antnoise;
	uint8_t		wr_antenna;
} wpi_rx_radiotap_header_t;

#define	WPI_RX_RADIOTAP_PRESENT						\
	((1 << IEEE80211_RADIOTAP_TSFT) |				\
	(1 << IEEE80211_RADIOTAP_FLAGS) |				\
	(1 << IEEE80211_RADIOTAP_RATE) |				\
	(1 << IEEE80211_RADIOTAP_CHANNEL) |				\
	(1 << IEEE80211_RADIOTAP_DBM_ANTSIGNAL) |			\
	(1 << IEEE80211_RADIOTAP_DBM_ANTNOISE) |			\
	(1 << IEEE80211_RADIOTAP_ANTENNA))

typedef struct wpi_tx_radiotap_header {
	struct ieee80211_radiotap_header wt_ihdr;
	uint8_t		wt_flags;
	uint8_t		wt_rate;
	uint16_t	wt_chan_freq;
	uint16_t	wt_chan_flags;
} wpi_tx_radiotap_header_t;

#define	WPI_TX_RADIOTAP_PRESENT						\
	((1 << IEEE80211_RADIOTAP_FLAGS) |				\
	(1 << IEEE80211_RADIOTAP_RATE) |				\
	(1 << IEEE80211_RADIOTAP_CHANNEL))
#endif

#define	WPI_DMA_SYNC(area, flag) \
	(void) ddi_dma_sync((area).dma_hdl, (area).offset, \
	(area).alength, (flag))

#define	WPI_CHK_FAST_RECOVER(sc) \
	(sc->sc_ic.ic_state == IEEE80211_S_RUN && \
	sc->sc_ic.ic_opmode == IEEE80211_M_STA)

typedef struct wpi_dma_area {
	ddi_acc_handle_t	acc_hdl; /* handle for memory */
	caddr_t			mem_va; /* CPU VA of memory */
	uint32_t		nslots; /* number of slots */
	uint32_t		size;   /* size per slot */
	size_t			alength; /* allocated size */
					/* >= product of above */
	ddi_dma_handle_t	dma_hdl; /* DMA handle */
	offset_t		offset;  /* relative to handle */
	ddi_dma_cookie_t	cookie; /* associated cookie */
	uint32_t		ncookies;
	uint32_t		token; /* arbitrary identifier */
} wpi_dma_t;

typedef struct wpi_tx_data {
	wpi_dma_t		dma_data;
	wpi_tx_desc_t		*desc;
	uint32_t		paddr_desc;
	wpi_tx_cmd_t		*cmd;
	uint32_t		paddr_cmd;
} wpi_tx_data_t;

typedef struct wpi_tx_ring {
	wpi_dma_t		dma_desc;
	wpi_dma_t		dma_cmd;
	wpi_tx_data_t		*data;
	int			qid;
	int			count;
	int			queued;
	int			cur;
} wpi_tx_ring_t;

typedef struct wpi_rx_data {
	wpi_dma_t		dma_data;
} wpi_rx_data_t;

typedef struct wpi_rx_ring {
	wpi_dma_t		dma_desc;
	uint32_t 		*desc;
	wpi_rx_data_t		data[WPI_RX_RING_COUNT];
	int			cur;
} wpi_rx_ring_t;

typedef struct wpi_amrr {
	ieee80211_node_t in;	/* must be the first */
	int	txcnt;
	int	retrycnt;
	int	success;
	int	success_threshold;
	int	recovery;
} wpi_amrr_t;

typedef struct wpi_softc {
	struct ieee80211com	sc_ic;
	dev_info_t		*sc_dip;
	int			(*sc_newstate)(struct ieee80211com *,
				    enum ieee80211_state, int);
	enum ieee80211_state	sc_ostate;
	kmutex_t		sc_glock;
	kmutex_t		sc_mt_lock;
	kmutex_t		sc_tx_lock;
	kcondvar_t		sc_mt_cv;
	kcondvar_t		sc_tx_cv;
	kcondvar_t		sc_cmd_cv;
	kcondvar_t		sc_fw_cv;

	kthread_t		*sc_mf_thread;
	uint32_t		sc_mf_thread_switch;

	uint32_t		sc_flags;
	uint32_t		sc_dmabuf_sz;
	uint16_t		sc_clsz;
	uint8_t			sc_rev;
	uint8_t			sc_resv;

	/* shared area */
	wpi_dma_t		sc_dma_sh;
	wpi_shared_t		*sc_shared;

	wpi_tx_ring_t		sc_txq[4];
	wpi_tx_ring_t		sc_cmdq;
	wpi_tx_ring_t		sc_svcq;
	wpi_rx_ring_t		sc_rxq;

	/* dma */
	const wpi_firmware_hdr_t *sc_hdr;
	const char		*sc_boot;
	const char		*sc_text;
	const char		*sc_data;
	wpi_dma_t		sc_dma_fw_text;
	ddi_dma_cookie_t	sc_fw_text_cookie[4];
	wpi_dma_t		sc_dma_fw_data;
	ddi_dma_cookie_t	sc_fw_data_cookie[4];

	ddi_acc_handle_t	sc_handle;
	caddr_t			sc_base;
	ddi_iblock_cookie_t	sc_iblk;

	wpi_config_t		sc_config;
	wpi_config_t		sc_config_save;

	uint16_t		sc_pwr1[14];
	uint16_t		sc_pwr2[14];

	uint32_t		sc_tx_timer;
	uint32_t		sc_scan_next;
	uint32_t		sc_scan_pending;
	uint8_t			*sc_fw_bin;

	ddi_softintr_t		sc_notif_softint_id;
	uint32_t		sc_notif_softint_pending;
	uint32_t		sc_need_reschedule;

	clock_t			sc_clk;

	/* kstats */
	uint32_t		sc_tx_nobuf;
	uint32_t		sc_rx_nobuf;
	uint32_t		sc_tx_err;
	uint32_t		sc_rx_err;
	uint32_t		sc_tx_retries;

#ifdef WPI_BPF
	struct bpf_if		*sc_drvbpf;

	union {
		struct wpi_rx_radiotap_header th;
		uint8_t	pad[64];
	} sc_rxtapu;
#define	sc_rxtap	sc_rxtapu.th
	int			sc_rxtap_len;

	union {
		struct wpi_tx_radiotap_header th;
		uint8_t	pad[64];
	} sc_txtapu;
#define	sc_txtap	sc_txtapu.th
	int			sc_txtap_len;
#endif
} wpi_sc_t;

#define	WPI_F_ATTACHED		(1 << 0)
#define	WPI_F_CMD_DONE		(1 << 1)
#define	WPI_F_FW_INIT		(1 << 2)
#define	WPI_F_HW_ERR_RECOVER	(1 << 3)
#define	WPI_F_RATE_AUTO_CTL	(1 << 4)
#define	WPI_F_RUNNING		(1 << 5)
#define	WPI_F_SUSPEND		(1 << 6)
#define	WPI_F_RADIO_OFF		(1 << 7)
#define	WPI_F_SCANNING		(1 << 8)
#define	WPI_F_QUIESCED		(1 << 9)
#define	WPI_F_LAZY_RESUME	(1 << 10)

#define	WPI_SUCCESS		0
#define	WPI_FAIL		(EIO)
#ifdef __cplusplus
}
#endif

#endif /* _WPIVAR_H */
