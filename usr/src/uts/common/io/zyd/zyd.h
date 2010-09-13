/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2008 by  Ben Taylor <bentaylor.solx86@gmail.com>
 * Copyright (c) 2007 by  Lukas Turek <turek@ksvi.mff.cuni.cz>
 * Copyright (c) 2007 by  Jiri Svoboda <jirik.svoboda@seznam.cz>
 * Copyright (c) 2007 by  Martin Krulis <martin.krulis@matfyz.cz>
 * Copyright (c) 2006 by Damien Bergamini <damien.bergamini@free.fr>
 * Copyright (c) 2006 by Florian Stoehr <ich@florian-stoehr.de>
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
 *
 */

#ifndef _ZYD_H
#define	_ZYD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/sysmacros.h>
#include <sys/net80211.h>

#define	USBDRV_MAJOR_VER 2
#define	USBDRV_MINOR_VER 0
#include <sys/usb/usba.h>
#include <sys/usb/usba/usba_types.h>

#define	ZYD_DRV_NAME  "zyd"
#define	ZYD_DRV_DESC  "Zydas ZD1211(B)"
#define	ZYD_DRV_REV   "V1.1"

/* Return the number of fields of an array */
#define	ZYD_ARRAY_LENGTH(arr) (sizeof (arr) / sizeof ((arr)[0]))

/*
 * Result type: all functions beginning with zyd_
 * should use this to indicate success or failure.
 * (except for public funcions, of course)
 *
 * Detecting error: always use (value != ZYD_SUCCESS)
 * Indicating error: return ZYD_FAILURE
 */
typedef enum {
	ZYD_SUCCESS,
	ZYD_FAILURE
} zyd_res;

/*
 * Chip revision ID
 */
typedef enum {
	ZYD_UNKNOWN,
	ZYD_ZD1211,
	ZYD_ZD1211B
} zyd_mac_rev_t;

/*
 * USB-safe mutual exclusion object.
 */
typedef struct {
	boolean_t initialized;	/* B_TRUE if properly initialized */
	boolean_t held;		/* B_TRUE if the object is held */
	kmutex_t lock;		/* serialize access */
	kcondvar_t wait;	/* for waiting on release */
} zyd_serial_t;

/*
 * Holds an ioread request status.
 */
struct zyd_ioread {
	volatile boolean_t pending;	/* ioread is in progress */
	volatile boolean_t done;	/* response has been received */
	volatile boolean_t exc;		/* an exception has occured */

	void *buffer;			/* response buffer */
	int buf_len;			/* buffer size (bytes) */
};

/*
 * USB state.
 */
struct zyd_usb {
	/* Copy of sc->dip */
	dev_info_t 		*dip;

	/* Device configuration information */
	usb_client_dev_data_t	*cdata;

	boolean_t		connected;

	/* Communication pipe handles */
	usb_pipe_handle_t	pipe_data_in;
	usb_pipe_handle_t	pipe_data_out;
	usb_pipe_handle_t	pipe_cmd_in;
	usb_pipe_handle_t	pipe_cmd_out;

	/* Communication endpoint data (copied from descriptor tree) */
	usb_ep_data_t		ep_data_in;
	usb_ep_data_t		ep_data_out;
	usb_ep_data_t		ep_cmd_in;
	usb_ep_data_t		ep_cmd_out;

	/* Current ioread request (if any) */
	struct zyd_ioread	io_read;
};

struct zyd_softc;	/* forward declaration */

struct zyd_rf {
	/* RF methods */
	zyd_res		(*init)(struct zyd_rf *);
	zyd_res		(*switch_radio)(struct zyd_rf *, boolean_t);
	zyd_res		(*set_channel)(struct zyd_rf *, uint8_t);

	/* RF attributes */
	struct		zyd_softc *rf_sc;	/* back-pointer */
	int		width;
};

/*
 * per-instance soft-state structure
 */
struct zyd_softc {
	/* Serialize access to the soft_state/device */
	zyd_serial_t		serial;
	struct zyd_rf		sc_rf;

	dev_info_t		*dip;

	/* timeout for scanning */
	timeout_id_t		timeout_id;

	/* USB-specific data */
	struct zyd_usb		usb;

	/* Chip revision ZYD1211/ZYD1211B */
	zyd_mac_rev_t		mac_rev;

	/* MAC address */
	uint8_t			macaddr[IEEE80211_ADDR_LEN];

	/* net80211 data */
	struct ieee80211com 	ic;

	boolean_t		running;
	boolean_t		suspended;
	boolean_t		resched;
	uint8_t			tx_queued;

	/* Data from EEPROM */
	uint16_t		fwbase;
	uint8_t			regdomain;
	uint16_t		fw_rev;
	uint8_t			rf_rev;
	uint8_t			pa_rev;
	uint8_t			fix_cr47;
	uint8_t			fix_cr157;
	uint8_t			pwr_cal[14];
	uint8_t			pwr_int[14];
	uint8_t			ofdm36_cal[14];
	uint8_t			ofdm48_cal[14];
	uint8_t			ofdm54_cal[14];

	/* kstats */
	uint32_t		tx_nobuf;
	uint32_t		rx_nobuf;
	uint32_t		tx_err;
	uint32_t		rx_err;

	/* net80211 original state change handler */
	int			(*newstate)(ieee80211com_t *,
					enum ieee80211_state, int);
};

/* RF-config request */
struct zyd_rfwrite {
	uint16_t	code;
	uint16_t	width;
	uint16_t	bit[32];
};

/* 16-bit I/O register write request */
struct zyd_iowrite16 {
	uint16_t	reg;
	uint16_t	value;
};

#pragma pack(1)

/* Generic usb command to the ZD chip */
struct zyd_cmd {
	uint16_t 	cmd_code;
	uint8_t		data[64];
};

/* ZD prepends this header to an incoming frame. */
struct zyd_plcphdr {
	uint8_t		signal;
	uint8_t		reserved[2];
	uint16_t	service;	/* unaligned! */
};

/* ZD appends this footer to an incoming frame. */
struct zyd_rx_stat {
	uint8_t rssi;
	uint8_t	signal_cck;
	uint8_t	signal_ofdm;
	uint8_t	cipher;
	uint8_t	flags;
};

/* this structure may be unaligned */
struct zyd_rx_desc {
#define	ZYD_MAX_RXFRAMECNT 3
	uint16_t   len[ZYD_MAX_RXFRAMECNT];
	uint16_t   tag;
#define	ZYD_TAG_MULTIFRAME 0x697e
};

/*
 * Prepended to the 802.11 frame when sending to data_out.
 */
struct zyd_tx_header {
	uint8_t rate_mod_flags;
	uint16_t frame_size;
	uint8_t type_flags;
	uint16_t packet_size;
	uint16_t frame_duration;
	uint8_t service;
	uint16_t next_frame_duration;
};

#pragma pack()

/*
 * Map USB id to 1211/1211B chip
 */
typedef struct zyd_usb_info {
	uint16_t	vendor_id;
	uint16_t	product_id;
	zyd_mac_rev_t	mac_rev;
} zyd_usb_info_t;

/*
 * Simple lock for callback-waiting. This lock should be used in situations when
 * one needs to wait for a callback function. It sipmply encapsulates one mutex
 * and one conditional variable.
 */
struct zyd_cb_lock {
	boolean_t done;
	kmutex_t mutex;
	kcondvar_t cv;
};

/* Bits for rate_mod_flags */
#define	ZYD_TX_RMF_RATE(rmf)	((rmf) & 0x0f)
#define	ZYD_TX_RMF_OFDM		0x10
#define	ZYD_TX_RMF_SH_PREAMBLE	0x20	/* CCK */
#define	ZYD_TX_RMF_5GHZ		0x40	/* OFDM */

/* Bits for type_flags */
#define	ZYD_TX_FLAG_BACKOFF	0x01
#define	ZYD_TX_FLAG_MULTICAST	0x02
#define	ZYD_TX_FLAG_TYPE(t)	(((t) & 0x3) << 2)
#define	ZYD_TX_TYPE_DATA	0
#define	ZYD_TX_TYPE_PS_POLL	1
#define	ZYD_TX_TYPE_MGMT	2
#define	ZYD_TX_TYPE_CTL		3

#define	ZYD_TX_FLAG_WAKEUP	0x10
#define	ZYD_TX_FLAG_RTS		0x20
#define	ZYD_TX_FLAG_ENCRYPT	0x40
#define	ZYD_TX_FLAG_CTS_TO_SELF	0x80

#define	ZYD_TX_SERVICE_LENGTH_EXTENSION		0x80

#define	ZYD_TX_LIST_COUNT	0x8
#define	ZYD_RX_LIST_COUNT	0x8
#define	ZYD_USB_REQ_COUNT	0x8

/*
 * Time in miliseconds to stay on one channel during scan.
 */
#define	ZYD_DWELL_TIME 200000

#define	ZYD_SER_SIG	B_TRUE
#define	ZYD_NO_SIG	B_FALSE

/* Location in the endpoint descriptor tree used by the device */
#define	ZYD_USB_CONFIG_NUMBER  1
#define	ZYD_USB_IFACE_INDEX    0
#define	ZYD_USB_ALT_IF_INDEX   0

#define	ZYD_DBG_HW	(1<<0)
#define	ZYD_DBG_FW	(1<<1)
#define	ZYD_DBG_USB	(1<<2)
#define	ZYD_DBG_TX	(1<<3)
#define	ZYD_DBG_RX	(1<<4)
#define	ZYD_DBG_SCAN	(1<<5)
#define	ZYD_DBG_GLD	(1<<6)
#define	ZYD_DBG_80211	(1<<7)
#define	ZYD_DBG_RESUME	(1<<8)

#define	ZYD_RX_BUF_SIZE (sizeof (struct zyd_rx_desc) + \
	((IEEE80211_MAX_LEN + 3) & ~3) * ZYD_MAX_RXFRAMECNT)

/* quickly determine if a given rate is CCK or OFDM */
#define	ZYD_RATE_IS_OFDM(rate)	((rate) >= 12 && (rate) != 22)

/*
 * Calculate the byte offset of a struct member
 */
#define	ZYD_IC_TO_SOFTC(ic)\
(\
	(struct zyd_softc *)(\
		(uintptr_t)(ic) - offsetof(struct zyd_softc, ic)\
)\
)

/*
 * The 'struct zyd_usb usb' is stored inside 'struct zyd_softc'.
 * Using the knowledge of the usb member position,
 * convert a pointer to 'usb' to a pointer to the zyd_softc.
 */
#define	ZYD_USB_TO_SOFTC(usbp)\
(\
	(struct zyd_softc *)(\
		(uintptr_t)(usbp) - offsetof(struct zyd_softc, usb)\
)\
)

/* Debugging macros */
#ifdef DEBUG
#define	ZYD_DEBUG(x)	zyd_dbg x
#else
#define	ZYD_DEBUG(x)
#endif
#define	ZYD_WARN	zyd_warn

extern void *zyd_ssp;

#ifdef DEBUG
extern uint32_t zyd_dbg_flags;
void	zyd_dbg(uint32_t dbg_mask, const char *fmt, ...);
#endif
void	zyd_warn(const char *fmt, ...);
/*
 * Functions needed for initializing radios and switching channels
 */
extern zyd_res	zyd_read32(struct zyd_softc *, uint16_t, uint32_t *);
extern zyd_res	zyd_write32(struct zyd_softc *, uint16_t, uint32_t);
extern zyd_res	zyd_read16(struct zyd_softc *, uint16_t, uint16_t *);
extern zyd_res	zyd_write16a(struct zyd_softc *, const struct zyd_iowrite16 *,
    int);
extern zyd_res	zyd_write16(struct zyd_softc *, uint16_t, uint16_t);
/*
 * Zydas's own USB-safe synchronization primitive. There are many USB API
 * functions which forbids that caller holds a mutex. So we're avoiding that
 * by using out own primitive (it consist of )
 */
void	zyd_serial_init(struct zyd_softc *sc);
zyd_res	zyd_serial_enter(struct zyd_softc *sc, boolean_t wait_sig);
void	zyd_serial_exit(struct zyd_softc *sc);
void	zyd_serial_deinit(struct zyd_softc *sc);

void	zyd_cb_lock_init(struct zyd_cb_lock *lock);
void	zyd_cb_lock_destroy(struct zyd_cb_lock *lock);
zyd_res	zyd_cb_lock_wait(struct zyd_cb_lock *lock, clock_t timeout);
void	zyd_cb_lock_signal(struct zyd_cb_lock *lock);

/* chipset specific routines */
void		zyd_hw_set_channel(struct zyd_softc *sc, uint8_t chan);
zyd_res		zyd_hw_init(struct zyd_softc *sc);
void		zyd_hw_deinit(struct zyd_softc *sc);
zyd_res		zyd_hw_start(struct zyd_softc *sc);
void		zyd_hw_stop(struct zyd_softc *sc);

/* USB specific routines */
zyd_res		zyd_usb_init(struct zyd_softc *sc);
void		zyd_usb_deinit(struct zyd_softc *sc);
zyd_res		zyd_usb_open_pipes(struct zyd_usb *uc);
void		zyd_usb_close_pipes(struct zyd_usb *uc);
zyd_res		zyd_usb_cmd_in_start_polling(struct zyd_usb *uc);
void		zyd_usb_cmd_in_stop_polling(struct zyd_usb *uc);
zyd_res		zyd_usb_data_in_enable(struct zyd_usb *uc);
void		zyd_usb_data_in_disable(struct zyd_usb *uc);
zyd_res		zyd_usb_cmd_send(struct zyd_usb *uc, uint16_t code,
			const void *data, size_t len);
zyd_res		zyd_usb_ioread_req(struct zyd_usb *uc, const void *in_data,
			size_t in_len, void *out_data, size_t out_len);
zyd_res		zyd_usb_send_packet(struct zyd_usb *uc, mblk_t *mp);
zyd_mac_rev_t	zyd_usb_mac_rev(uint16_t vendor, uint16_t product);
zyd_res		zyd_usb_loadfirmware(struct zyd_usb *uc, uint8_t *fw,
			size_t size);

void	zyd_receive(struct zyd_softc *sc, const uint8_t *buf, uint16_t len);
int	zyd_resume(struct zyd_softc *sc);
int	zyd_suspend(struct zyd_softc *sc);

extern uint8_t	zd1211_firmware[];
extern size_t	zd1211_firmware_size;
extern uint8_t	zd1211b_firmware[];
extern size_t	zd1211b_firmware_size;

#ifdef __cplusplus
}
#endif

#endif /* _ZYD_H */
