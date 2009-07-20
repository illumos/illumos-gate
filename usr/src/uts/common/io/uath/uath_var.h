/*
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2006
 *	Damien Bergamini <damien.bergamini@free.fr>
 * Copyright (c) 2006 Sam Leffler, Errno Consulting
 * Copyright (c) 2008-2009 Weongyo Jeong <weongyo@freebsd.org>
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


#ifndef	_UATH_VAR_H
#define	_UATH_VAR_H

#include <sys/queue.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	UATH_ID_BSS		2	/* Connection ID  */

#define	UATH_RX_DATA_LIST_COUNT	1	/* 128 */
#define	UATH_TX_DATA_LIST_COUNT	8	/* 16 */
#define	UATH_CMD_LIST_COUNT	8	/* 60 */

#define	UATH_DATA_TIMEOUT	10000
#define	UATH_CMD_TIMEOUT	1000

/*
 * Useful combinations of channel characteristics from net80211.
 */
#define	UATH_CHAN_A	\
	(IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM)
#define	UATH_CHAN_B	\
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_CCK)
#define	UATH_CHAN_PUREG	\
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_OFDM)
#define	UATH_CHAN_G	\
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_DYN)

#define	UATH_IS_CHAN_A(_c)		\
	(((_c)->ich_flags & UATH_CHAN_A) == UATH_CHAN_A)
#define	UATH_IS_CHAN_B(_c)		\
	(((_c)->ich_flags & UATH_CHAN_B) == UATH_CHAN_B)
#define	UATH_IS_CHAN_PUREG(_c)	\
	(((_c)->ich_flags & UATH_CHAN_PUREG) == UATH_CHAN_PUREG)
#define	UATH_IS_CHAN_G(_c)		\
	(((_c)->ich_flags & UATH_CHAN_G) == UATH_CHAN_G)
#define	UATH_IS_CHAN_ANYG(_c)	\
	(UATH_IS_CHAN_PUREG(_c) || UATH_IS_CHAN_G(_c))

#define	UATH_IS_CHAN_OFDM(_c)	\
	((_c)->ich_flags & IEEE80211_CHAN_OFDM)
#define	UATH_IS_CHAN_CCK(_c)	\
	((_c)->ich_flags & IEEE80211_CHAN_CCK)

#define	UATH_NODE_QOS	0x0002		/* QoS enabled */


/* flags for sending firmware commands */
#define	UATH_CMD_FLAG_ASYNC	(1 << 0)
#define	UATH_CMD_FLAG_READ	(1 << 1)
#define	UATH_CMD_FLAG_MAGIC	(1 << 2)

struct uath_cmd {
	struct uath_softc	*sc;
	uint32_t		flags;
	uint32_t		msgid;
	uint8_t			*buf;
	uint16_t		buflen;
	void			*odata;		/* NB: tx only */
	int			olen;		/* space in odata */
	STAILQ_ENTRY(uath_cmd)	next;
};
typedef STAILQ_HEAD(, uath_cmd) uath_cmdhead;

struct uath_data {
	struct uath_softc	*sc;
	uint8_t			*buf;
	uint16_t		buflen;
	struct ieee80211_node	*ni;		/* NB: tx only */
	STAILQ_ENTRY(uath_data)	next;
};
typedef STAILQ_HEAD(, uath_data) uath_datahead;

struct uath_cmd_lock {
	boolean_t	done;
	kmutex_t	mutex;
	kcondvar_t	cv;
};

struct uath_wme_settings {
	uint8_t				aifsn;
	uint8_t				logcwmin;
	uint8_t				logcwmax;
	uint16_t			txop;
#define	UATH_TXOP_TO_US(txop)		((txop) << 5)
	uint8_t				acm;
};

struct uath_devcap {
	uint32_t			targetVersion;
	uint32_t			targetRevision;
	uint32_t			macVersion;
	uint32_t			macRevision;
	uint32_t			phyRevision;
	uint32_t			analog5GhzRevision;
	uint32_t			analog2GhzRevision;
	uint32_t			regDomain;
	uint32_t			regCapBits;
	uint32_t			countryCode;
	uint32_t			keyCacheSize;
	uint32_t			numTxQueues;
	uint32_t			connectionIdMax;
	uint32_t			wirelessModes;
#define	UATH_WIRELESS_MODE_11A		0x01
#define	UATH_WIRELESS_MODE_TURBO	0x02
#define	UATH_WIRELESS_MODE_11B		0x04
#define	UATH_WIRELESS_MODE_11G		0x08
#define	UATH_WIRELESS_MODE_108G		0x10
	uint32_t			chanSpreadSupport;
	uint32_t			compressSupport;
	uint32_t			burstSupport;
	uint32_t			fastFramesSupport;
	uint32_t			chapTuningSupport;
	uint32_t			turboGSupport;
	uint32_t			turboPrimeSupport;
	uint32_t			deviceType;
	uint32_t			wmeSupport;
	uint32_t			low2GhzChan;
	uint32_t			high2GhzChan;
	uint32_t			low5GhzChan;
	uint32_t			high5GhzChan;
	uint32_t			supportCipherWEP;
	uint32_t			supportCipherAES_CCM;
	uint32_t			supportCipherTKIP;
	uint32_t			supportCipherMicAES_CCM;
	uint32_t			supportMicTKIP;
	uint32_t			twiceAntennaGain5G;
	uint32_t			twiceAntennaGain2G;
};

struct uath_stat {
	uint32_t			st_badchunkseqnum;
	uint32_t			st_invalidlen;
	uint32_t			st_multichunk;
	uint32_t			st_toobigrxpkt;
	uint32_t			st_stopinprogress;
	uint32_t			st_crcerr;
	uint32_t			st_phyerr;
	uint32_t			st_decrypt_crcerr;
	uint32_t			st_decrypt_micerr;
	uint32_t			st_decomperr;
	uint32_t			st_keyerr;
	uint32_t			st_err;
	/* not use CMD/RX/TX queues, so ignore some structure */
};
#define	UATH_STAT_INC(sc, var)		(sc)->sc_stat.var++
#define	UATH_STAT_DEC(sc, var)		(sc)->sc_stat.var--

struct uath_softc {
	struct ieee80211com	sc_ic;
	dev_info_t		*sc_dev;

	usb_client_dev_data_t	*sc_udev;	/* usb dev */
	int			dev_flags;
	uint32_t		sc_flags;

	usb_pipe_handle_t	rx_cmd_pipe;
	usb_pipe_handle_t	rx_data_pipe;
	usb_pipe_handle_t	tx_cmd_pipe;
	usb_pipe_handle_t	tx_data_pipe;

	kmutex_t		sc_genlock;
	kmutex_t		sc_rxlock_cmd;
	kmutex_t		sc_rxlock_data;
	kmutex_t		sc_txlock_cmd;
	kmutex_t		sc_txlock_data;

	struct uath_cmd		sc_cmd[UATH_CMD_LIST_COUNT];
	struct uath_data	sc_rx[UATH_RX_DATA_LIST_COUNT];
	struct uath_data	sc_tx[UATH_TX_DATA_LIST_COUNT];

	int			tx_cmd_queued;
	int			rx_cmd_queued;
	int			tx_data_queued;
	int			rx_data_queued;

	int			sc_cmdid;

	struct uath_stat	sc_stat;

	struct uath_cmd_lock 	rlock;
	struct uath_cmd_lock 	wlock;

	struct uath_devcap	sc_devcap;
	uint8_t			sc_serial[16];

	uint32_t		sc_msgid;
	uint32_t		sc_seqnum;

	uint8_t			sc_intrx_nextnum;
	uint32_t		sc_intrx_len;
#define	UATH_MAX_INTRX_SIZE		3616

	timeout_id_t		sc_scan_id;
	timeout_id_t		sc_stat_id;

	uint32_t		sc_need_sched;

	/* kstats */
	uint32_t		sc_tx_nobuf;
	uint32_t		sc_rx_nobuf;
	uint32_t		sc_tx_err;
	uint32_t		sc_rx_err;
	uint32_t		sc_tx_retries;

	int			(*sc_newstate)(struct ieee80211com *,
				    enum ieee80211_state, int);
};

#define	UATH_SUCCESS		0
#define	UATH_FAILURE		-1

#define	UATH_FLAG_RUNNING	(1 << 0)
#define	UATH_FLAG_SUSPEND	(1 << 1)
#define	UATH_FLAG_RECONNECT	(1 << 2)
#define	UATH_FLAG_DISCONNECT	(1 << 3)

#define	UATH_LOCK(sc)		mutex_enter(&(sc)->sc_genlock)
#define	UATH_UNLOCK(sc)		mutex_exit(&(sc)->sc_genlock)
#define	UATH_IS_RUNNING(_sc)	((_sc)->sc_flags & UATH_FLAG_RUNNING)
#define	UATH_IS_SUSPEND(_sc)	((_sc)->sc_flags & UATH_FLAG_SUSPEND)
#define	UATH_IS_DISCONNECT(_sc)	((_sc)->sc_flags & UATH_FLAG_DISCONNECT)
#define	UATH_IS_RECONNECT(_sc)	((_sc)->sc_flags & UATH_FLAG_RECONNECT)

#define	UATH_RESET_INTRX(sc) do {		\
	(sc)->sc_intrx_nextnum = 0;		\
	(sc)->sc_intrx_len = 0;			\
	_NOTE(CONSTCOND)						\
} while (0)


#ifdef __cplusplus
}
#endif

#endif /* _UATH_VAR_H */
