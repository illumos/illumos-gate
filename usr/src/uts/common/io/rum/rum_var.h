/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2005, 2006 Damien Bergamini <damien.bergamini@free.fr>
 * Copyright (c) 2006 Niall O'Higgins <niallo@openbsd.org>
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
#ifndef	_RUM_VAR_H
#define	_RUM_VAR_H

#ifdef __cplusplus
extern "C" {
#endif

#define	RAL_FLAG_RUNNING	(1<<0)

#define	RAL_RCR_PROMISC		(1<<0)
#define	RAL_RCR_MULTI		(2<<0)

#ifndef	DDI_NT_NET_WIFI
#define	DDI_NT_NET_WIFI		"ddi_network:wifi"
#endif

/*
 * Bit flags in the ral_dbg_flags
 */
#define	RAL_DBG_MSG		0x000001
#define	RAL_DBG_ERR		0x000002
#define	RAL_DBG_USB		0x000004
#define	RAL_DBG_TX		0x000008
#define	RAL_DBG_RX		0x000010
#define	RAL_DBG_IOCTL		0x000020
#define	RAL_DBG_HW		0x000040
#define	RAL_DBG_ALL		0x000fff

#define	RAL_RX_LIST_COUNT	8
#define	RAL_TX_LIST_COUNT	8

struct rum_amrr {
	int	txcnt;
	int	retrycnt;
	int	success;
	int	success_threshold;
	int	recovery;
};

struct rum_softc {
	struct ieee80211com	sc_ic;
	dev_info_t		*sc_dev;

	usb_client_dev_data_t	*sc_udev;	/* usb dev */

	int			sc_rx_no;
	int			sc_tx_no;

	uint8_t			rf_rev;
	uint8_t			rffreq;

	kmutex_t		sc_genlock;

	usb_pipe_handle_t	sc_rx_pipeh;
	usb_pipe_handle_t	sc_tx_pipeh;

	enum ieee80211_state	sc_state;
	struct rum_amrr		amrr;

	kmutex_t		tx_lock;
	kmutex_t		rx_lock;

	int			tx_queued;
	int			rx_queued;

	int			sc_tx_timer;

	timeout_id_t		sc_scan_id;
	timeout_id_t		sc_amrr_id;

	uint32_t		sc_need_sched;
	uint32_t		sc_flags;
	uint32_t		sc_rcr;		/* RAL RCR */

	int			dwelltime;

	uint32_t		sta[6];
	uint32_t		rf_regs[4];
	uint8_t			txpow[44];

#pragma pack(1)
	struct {
		uint8_t	val;
		uint8_t	reg;
	}			bbp_prom[16];
#pragma pack()

	int			hw_radio;
	int			rx_ant;
	int			tx_ant;
	int			nb_ant;
	int			ext_2ghz_lna;
	int			ext_5ghz_lna;
	int			rssi_2ghz_corr;
	int			rssi_5ghz_corr;
	int			sifs;
	uint8_t			bbp17;

	/* kstats */
	uint32_t		sc_tx_nobuf;
	uint32_t		sc_rx_nobuf;
	uint32_t		sc_tx_err;
	uint32_t		sc_rx_err;
	uint32_t		sc_tx_retries;

	int			(*sc_newstate)(struct ieee80211com *,
				    enum ieee80211_state, int);
};

#define	RAL_IS_RUNNING(_sc)	((_sc)->sc_flags & RAL_FLAG_RUNNING)
#define	RAL_LOCK(sc)		mutex_enter(&(sc)->sc_genlock)
#define	RAL_UNLOCK(sc)		mutex_exit(&(sc)->sc_genlock)

#define	MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define	MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

#ifdef __cplusplus
}
#endif

#endif /* _RUM_VAR_H */
