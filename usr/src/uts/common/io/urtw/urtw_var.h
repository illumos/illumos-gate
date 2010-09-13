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
#ifndef	_URTW_VAR_H
#define	_URTW_VAR_H

#ifdef __cplusplus
extern "C" {
#endif

#define	URTW_RX_DATA_LIST_COUNT	(2)
#define	URTW_TX_DATA_LIST_COUNT	(16)
#define	URTW_RX_MAXSIZE	(0x9c4)
#define	URTW_TX_MAXSIZE	URTW_RX_MAXSIZE

#define	UT_READ_VENDOR_DEVICE (USB_DEV_REQ_TYPE_VENDOR |\
	USB_DEV_REQ_DEV_TO_HOST)

#define	UT_WRITE_VENDOR_DEVICE (USB_DEV_REQ_TYPE_VENDOR |\
	USB_DEV_REQ_HOST_TO_DEV)

#define	USBD_INVAL (-1)
#define	URTW_TX_TIMEOUT	(5)

typedef int usbd_status;

#define	URTW_MAX_CHANNELS (15)
#define	LOW_PRIORITY_PIPE (0)
#define	NORMAL_PRIORITY_PIPE (1)
#define	URTW_LED_LINKOFF_BLINK	(1000*1000)
#define	URTW_LED_LINKON_BLINK	(300*1000)

struct urtw_rf {
	/* RF methods */
	usbd_status			(*init)(struct urtw_rf *);
	usbd_status			(*set_chan)(struct urtw_rf *, int);
	usbd_status			(*set_sens)(struct urtw_rf *);

	/* RF attributes */
	struct urtw_softc		*rf_sc;
	uint32_t			max_sens;
	int32_t				sens;
};

struct urtw_softc {
	struct ieee80211com	sc_ic;
	dev_info_t		*sc_dev;
	kmutex_t		sc_genlock;
	kmutex_t		tx_lock;
	kmutex_t		rx_lock;
	usb_client_dev_data_t	*sc_udev;
	usb_pipe_handle_t	sc_rxpipe;
	usb_pipe_handle_t	sc_txpipe_low;
	usb_pipe_handle_t	sc_txpipe_normal;

	int			sc_tx_low_queued;
	int 			sc_tx_normal_queued;
	int			rx_queued;
	timeout_id_t		sc_scan_id;
	uint32_t		sc_need_sched;
	int			dwelltime;
	/* kstats */
	uint32_t		sc_tx_nobuf;
	uint32_t		sc_rx_nobuf;
	uint32_t		sc_rx_err;

	int			sc_flags;
	int			sc_arg;
	int			(*sc_newstate)(struct ieee80211com *,
				    enum ieee80211_state, int);

	int				sc_epromtype;
#define	URTW_EEPROM_93C46		0
#define	URTW_EEPROM_93C56		1
	uint8_t				sc_crcmon;
	uint8_t				sc_bssid[IEEE80211_ADDR_LEN];

	struct urtw_rf			sc_rf;

	/* for LED  */
	kmutex_t			sc_ledlock;
	timeout_id_t			sc_led_ch;
	uint8_t				sc_psr;
	uint8_t				sc_strategy;
	uint8_t				sc_led_freq;
#define	URTW_LED_GPIO			1
	uint8_t				sc_gpio_ledon;
	uint8_t				sc_gpio_ledinprogress;
	uint8_t				sc_gpio_ledstate;
	uint8_t				sc_gpio_ledpin;
	uint8_t				sc_gpio_blinktime;
	uint8_t				sc_gpio_blinkstate;
	uint8_t				sc_rts_retry;
	uint8_t				sc_tx_retry;
	uint8_t				sc_preamble_mode;
	int				sc_currate;
	/* TX power  */
	uint8_t				sc_txpwr_cck[URTW_MAX_CHANNELS];
	uint8_t				sc_txpwr_cck_base;
	uint8_t				sc_txpwr_ofdm[URTW_MAX_CHANNELS];
	uint8_t				sc_txpwr_ofdm_base;

	uint8_t				sc_hwrev;
	int				(*urtw_init)(void *);
};
#define	URTW_FLAG_RUNNING	(1 << 0)
#define	URTW_FLAG_SUSPEND	(1 << 1)
#define	URTW_FLAG_PLUGIN_ONLINE	(1 << 2)
#define	URTW_FLAG_HP		(1 << 3)

#define	URTW_IS_PLUGIN_ONLINE(_sc) \
	((_sc)->sc_flags & URTW_FLAG_PLUGIN_ONLINE)
#define	URTW_IS_RUNNING(_sc) \
	((_sc)->sc_flags & URTW_FLAG_RUNNING)
#define	URTW_IS_NOT_RUNNING(_sc) \
	(((_sc)->sc_flags & URTW_FLAG_RUNNING) == 0)
#define	URTW_IS_SUSPENDING(_sc)	((_sc)->sc_flags & URTW_FLAG_SUSPEND)

#define	URTW_LOCK(sc)		mutex_enter(&(sc)->sc_genlock)
#define	URTW_UNLOCK(sc)		mutex_exit(&(sc)->sc_genlock)
#define	URTW_LEDLOCK(sc)	mutex_enter(&(sc)->sc_ledlock)
#define	URTW_LEDUNLOCK(sc)	mutex_exit(&(sc)->sc_ledlock)

#ifdef __cplusplus
}
#endif

#endif /* _URTW_VAR_H */
