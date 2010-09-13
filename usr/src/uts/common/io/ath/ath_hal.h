/*
 * Copyright (c) 2002-2008 Sam Leffler, Errno Consulting, Atheros
 * Communications, Inc.  All rights reserved.
 *
 * Use is subject to license terms.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the following conditions are met:
 * 1. The materials contained herein are unmodified and are used
 * unmodified.
 * 2. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following NO
 * ''WARRANTY'' disclaimer below (''Disclaimer''), without
 * modification.
 * 3. Redistributions in binary form must reproduce at minimum a
 * disclaimer similar to the Disclaimer below and any redistribution
 * must be conditioned upon including a substantially similar
 * Disclaimer requirement for further binary redistribution.
 * 4. Neither the names of the above-listed copyright holders nor the
 * names of any contributors may be used to endorse or promote
 * product derived from this software without specific prior written
 * permission.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ''AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF NONINFRINGEMENT,
 * MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE
 * FOR SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGES.
 *
 */

#ifndef _ATH_HAL_H
#define	_ATH_HAL_H

/*
 * ath_hal.h is released by Atheros and used to describe the Atheros
 * Hardware Access Layer(HAL) interface. All kinds of data structures,
 * constant definition, APIs declaration are defined here.Clients of
 * the HAL call ath_hal_attach() to obtain a reference to an ath_hal
 * structure for use with the device. Hardware-related operations that
 * follow must call back into the HAL through interface, supplying the
 * reference as the first parameter.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* HAL version of this release */
#define	HAL_ABI_VERSION	0x08052700	/* YYMMDDnn */

/* HAL data type definition */
typedef void *		HAL_SOFTC;	/* pointer to driver/OS state */
typedef void *		HAL_BUS_TAG;	/* opaque bus i/o id tag */
typedef void *		HAL_BUS_HANDLE;	/* opaque bus i/o handle */
typedef uint32_t 	HAL_BUS_ADDR;
typedef uint16_t 	HAL_CTRY_CODE;	/* country code */
typedef uint16_t 	HAL_REG_DOMAIN;	/* regulatory domain code */

#define	HAL_NUM_TX_QUEUES	10		/* max number of tx queues */

#define	HAL_BEACON_PERIOD	0x0000ffff	/* beacon interval period */
#define	HAL_BEACON_ENA		0x00800000	/* beacon xmit enable */
#define	HAL_BEACON_RESET_TSF	0x01000000	/* clear TSF */

#define	CHANNEL_RAD_INT	0x00001	/* Radar interference detected on channel */
#define	CHANNEL_CW_INT	0x00002	/* CW interference detected on channel */
#define	CHANNEL_BUSY	0x00004	/* Busy, occupied or overlap with adjoin chan */
#define	CHANNEL_TURBO	0x00010	/* Turbo Channel */
#define	CHANNEL_CCK	0x00020	/* CCK channel */
#define	CHANNEL_OFDM	0x00040	/* OFDM channel */
#define	CHANNEL_2GHZ	0x00080	/* 2 GHz spectrum channel. */
#define	CHANNEL_5GHZ	0x00100	/* 5 GHz spectrum channel */
#define	CHANNEL_PASSIVE	0x00200	/* Only passive scan allowed in the channel */
#define	CHANNEL_DYN	0x00400	/* dynamic CCK-OFDM channel */
#define	CHANNEL_XR	0x00800	/* XR channel */
#define	CHANNEL_STURBO	0x02000	/* Static turbo, no 11a-only usage */
#define	CHANNEL_HALF	0x04000 /* Half rate channel */
#define	CHANNEL_QUARTER	0x08000 /* Quarter rate channel */
#define	CHANNEL_HT20	0x10000	/* 11n 20MHZ channel */
#define	CHANNEL_HT40PLUS	0x20000	/* 11n 40MHZ chan w/ ext chan above */
#define	CHANNEL_HT40MINUS	0x40000	/* 11n 40MHZ chan w/ ext chan below */

#define	CHANNEL_A	(CHANNEL_5GHZ|CHANNEL_OFDM)
#define	CHANNEL_B	(CHANNEL_2GHZ|CHANNEL_CCK)
#define	CHANNEL_PUREG	(CHANNEL_2GHZ|CHANNEL_OFDM)
#define	CHANNEL_G	(CHANNEL_2GHZ|CHANNEL_OFDM)
#define	CHANNEL_T	(CHANNEL_5GHZ|CHANNEL_OFDM|CHANNEL_TURBO)
#define	CHANNEL_ST	(CHANNEL_T|CHANNEL_STURBO)
#define	CHANNEL_108G	(CHANNEL_2GHZ|CHANNEL_OFDM|CHANNEL_TURBO)
#define	CHANNEL_108A	CHANNEL_T
#define	CHANNEL_X	(CHANNEL_5GHZ|CHANNEL_OFDM|CHANNEL_XR)
#define	CHANNEL_G_HT20	(CHANNEL_G|CHANNEL_HT20)
#define	CHANNEL_A_HT20	(CHANNEL_A|CHANNEL_HT20)
#define	CHANNEL_G_HT40PLUS	(CHANNEL_G_HT20|CHANNEL_HT40PLUS)
#define	CHANNEL_A_HT40PLUS	(CHANNEL_A_HT20|CHANNEL_HT40PLUS)
#define	CHANNEL_A_HT40MINUS	(CHANNEL_A_HT20|CHANNEL_HT40MINUS)
#define	CHANNEL_ALL \
	(CHANNEL_OFDM|CHANNEL_CCK|CHANNEL_5GHZ|CHANNEL_2GHZ| \
	CHANNEL_TURBO|CHANNEL_HT20|CHANNEL_HT40PLUS|CHANNEL_HT40MINUS)
#define	CHANNEL_ALL_NOTURBO 	(CHANNEL_ALL &~ CHANNEL_TURBO)

#define	CHANNEL_COMPAT	(CHANNEL_ALL_NOTURBO | CHANNEL_PASSIVE)

/* privFlags */
/*
 * Software use: channel interference used for AR as well as RADAR
 * interference detection
 */
#define	CHANNEL_INTERFERENCE	0x01
#define	CHANNEL_DFS		0x02	/* DFS required on channel */
#define	CHANNEL_4MS_LIMIT	0x04	/* 4msec packet limit on this channel */
#define	CHANNEL_DFS_CLEAR	0x08	/* if channel has been checked DFS */

#define	HAL_RSSI_EP_MULTIPLIER	(1<<7)	/* pow2 to optimize out * and / */

/* flags passed to tx descriptor setup methods */
#define	HAL_TXDESC_CLRDMASK	0x0001	/* clear destination filter mask */
#define	HAL_TXDESC_NOACK	0x0002	/* don't wait for ACK */
#define	HAL_TXDESC_RTSENA	0x0004	/* enable RTS */
#define	HAL_TXDESC_CTSENA	0x0008	/* enable CTS */
#define	HAL_TXDESC_INTREQ	0x0010	/* enable per-descriptor interrupt */
#define	HAL_TXDESC_VEOL		0x0020	/* mark virtual EOL */
/* NB: this only affects frame, not any RTS/CTS */
#define	HAL_TXDESC_DURENA	0x0040	/* enable h/w write of duration field */
#define	HAL_TXDESC_EXT_ONLY	0x0080	/* send on ext channel only (11n) */
#define	HAL_TXDESC_EXT_AND_CTL	0x0100	/* send on ext + ctl channels (11n) */
#define	HAL_TXDESC_VMF		0x0200	/* virtual more frag */

/* flags passed to rx descriptor setup methods */
#define	HAL_RXDESC_INTREQ	0x0020	/* enable per-descriptor interrupt */

/* tx error flags */
#define	HAL_TXERR_XRETRY	0x01	/* excessive retries */
#define	HAL_TXERR_FILT		0x02	/* blocked by tx filtering */
#define	HAL_TXERR_FIFO		0x04	/* fifo underrun */
#define	HAL_TXERR_XTXOP		0x08	/* txop exceeded */
#define	HAL_TXERR_DESC_CFG_ERR	0x10	/* Error in 20/40 desc config */
#define	HAL_TXERR_DATA_UNDERRUN	0x20	/* Tx buffer underrun */
#define	HAL_TXERR_DELIM_UNDERRUN 0x40	/* Tx delimiter underrun */
#define	HAL_TXSTAT_ALTRATE	0x80	/* alternate xmit rate used */

/* bits found in ts_flags */
#define	HAL_TX_BA		0x01	/* Block Ack seen */
#define	HAL_TX_AGGR		0x02	/* Aggregate */

/* rx error flags */
#define	HAL_RXERR_CRC		0x01	/* CRC error on frame */
#define	HAL_RXERR_PHY		0x02	/* PHY error, rs_phyerr is valid */
#define	HAL_RXERR_FIFO		0x04	/* fifo overrun */
#define	HAL_RXERR_DECRYPT	0x08	/* non-Michael decrypt error */
#define	HAL_RXERR_MIC		0x10	/* Michael MIC decrypt error */

/* bits found in rs_flags */
#define	HAL_RX_MORE		0x01	/* more descriptors follow */
#define	HAL_RX_MORE_AGGR	0x02	/* more frames in aggr */
#define	HAL_RX_GI		0x04	/* full gi */
#define	HAL_RX_2040		0x08	/* 40 Mhz */
#define	HAL_RX_DELIM_CRC_PRE	0x10	/* crc error in delimiter pre */
#define	HAL_RX_DELIM_CRC_POST	0x20	/* crc error in delim after */
#define	HAL_RX_DECRYPT_BUSY	0x40	/* decrypt was too slow */
#define	HAL_RX_DUP_FRAME	0x80	/* Dup frame rx'd on control channel */

/* value found in rs_keyix to mark invalid entries */
#define	HAL_RXKEYIX_INVALID	((uint8_t)-1)

/* value used to specify no encryption key for xmit */
#define	HAL_TXKEYIX_INVALID	((uint32_t)-1)

/* compression definitions */
#define	HAL_COMP_BUF_MAX_SIZE	9216	/* 9k */
#define	HAL_COMP_BUF_ALIGN_SIZE	512

#define	HAL_ANTENNA_MIN_MODE	0
#define	HAL_ANTENNA_FIXED_A	1
#define	HAL_ANTENNA_FIXED_B	2
#define	HAL_ANTENNA_MAX_MODE	3

/*
 * Status codes that may be returned by the HAL.  Note that
 * interfaces that return a status code set it only when an
 * error occurs--i.e. you cannot check it for success.
 */
typedef enum {
	HAL_OK		= 0,	/* No error */
	HAL_ENXIO	= 1,	/* No hardware present */
	HAL_ENOMEM	= 2,	/* Memory allocation failed */
	HAL_EIO		= 3,	/* Hardware didn't respond as expected */
	HAL_EEMAGIC	= 4,	/* EEPROM magic number invalid */
	HAL_EEVERSION	= 5,	/* EEPROM version invalid */
	HAL_EELOCKED	= 6,	/* EEPROM unreadable */
	HAL_EEBADSUM	= 7,	/* EEPROM checksum invalid */
	HAL_EEREAD	= 8,	/* EEPROM read problem */
	HAL_EEBADMAC	= 9,	/* EEPROM mac address invalid */
	HAL_EESIZE	= 10,	/* EEPROM size not supported */
	HAL_EEWRITE	= 11,	/* Attempt to change write-locked EEPROM */
	HAL_EINVAL	= 12,	/* Invalid parameter to function */
	HAL_ENOTSUPP	= 13,	/* Hardware revision not supported */
	HAL_ESELFTEST	= 14,	/* Hardware self-test failed */
	HAL_EINPROGRESS	= 15	/* Operation incomplete */
} HAL_STATUS;

typedef enum {
	AH_FALSE = 0,		/* NB: lots of code assumes false is zero */
	AH_TRUE  = 1
} HAL_BOOL;

typedef enum {
	HAL_CAP_REG_DMN		= 0,	/* current regulatory domain */
	HAL_CAP_CIPHER		= 1,	/* hardware supports cipher */
	HAL_CAP_TKIP_MIC	= 2,	/* handle TKIP MIC in hardware */
	HAL_CAP_TKIP_SPLIT	= 3,	/* hardware TKIP uses split keys */
	HAL_CAP_PHYCOUNTERS	= 4,	/* hardware PHY error counters */
	HAL_CAP_DIVERSITY	= 5,	/* hardware supports fast diversity */
	HAL_CAP_KEYCACHE_SIZE	= 6,	/* number of entries in key cache */
	HAL_CAP_NUM_TXQUEUES	= 7,	/* number of hardware xmit queues */
	HAL_CAP_VEOL		= 9,	/* hardware supports virtual EOL */
	HAL_CAP_PSPOLL		= 10,	/* hardware has working PS-Poll */
					/* support */
	HAL_CAP_DIAG		= 11,	/* hardware diagnostic support */
	HAL_CAP_COMPRESSION	= 12,	/* hardware supports compression */
	HAL_CAP_BURST		= 13,	/* hardware supports packet bursting */
	HAL_CAP_FASTFRAME	= 14,	/* hardware supoprts fast frames */
	HAL_CAP_TXPOW		= 15,	/* global tx power limit  */
	HAL_CAP_TPC		= 16,	/* per-packet tx power control  */
	HAL_CAP_PHYDIAG		= 17,	/* hardware phy error diagnostic */
	HAL_CAP_BSSIDMASK	= 18,	/* hardware supports bssid mask */
	HAL_CAP_MCAST_KEYSRCH	= 19,	/* hardware has multicast key search */
	HAL_CAP_TSF_ADJUST	= 20,	/* hardware has beacon tsf adjust */
	HAL_CAP_XR		= 21,	/* hardware has XR support  */
	/* hardware can support TKIP MIC when WMM is turned on */
	HAL_CAP_WME_TKIPMIC	= 22,
	/* hardware can support half rate channels */
	HAL_CAP_CHAN_HALFRATE	= 23,
	/* hardware can support quarter rate channels */
	HAL_CAP_CHAN_QUARTERRATE = 24,
	HAL_CAP_RFSILENT	= 25,	/* hardware has rfsilent support  */
	HAL_CAP_TPC_ACK		= 26,	/* ack txpower with per-packet tpc */
	HAL_CAP_TPC_CTS		= 27,	/* cts txpower with per-packet tpc */
	HAL_CAP_11D		= 28,	/* 11d beacon support for changing cc */
	HAL_CAP_INTMIT		= 29,	/* interference mitigation */
	HAL_CAP_RXORN_FATAL	= 30,	/* HAL_INT_RXORN treated as fatal */
	HAL_CAP_HT		= 31,	/* hardware can support HT */
	HAL_CAP_NUMTXCHAIN	= 32,	/* TX chains supported */
	HAL_CAP_NUMRXCHAIN	= 33,	/* RX chains supported */
	HAL_CAP_RXTSTAMP_PREC	= 34	/* rx desc tstamp precision (bits) */
} HAL_CAPABILITY_TYPE;

/*
 * "States" for setting the LED.  These correspond to
 * the possible 802.11 operational states and there may
 * be a many-to-one mapping between these states and the
 * actual hardware states for the LED's (i.e. the hardware
 * may have fewer states).
 */
typedef enum {
	HAL_LED_INIT	= 0,
	HAL_LED_SCAN	= 1,
	HAL_LED_AUTH	= 2,
	HAL_LED_ASSOC	= 3,
	HAL_LED_RUN	= 4
} HAL_LED_STATE;

/*
 * Transmit queue types/numbers.  These are used to tag
 * each transmit queue in the hardware and to identify a set
 * of transmit queues for operations such as start/stop dma.
 */
typedef enum {
	HAL_TX_QUEUE_INACTIVE	= 0,	/* queue is inactive/unused */
	HAL_TX_QUEUE_DATA	= 1,	/* data xmit q's */
	HAL_TX_QUEUE_BEACON	= 2,	/* beacon xmit q */
	HAL_TX_QUEUE_CAB	= 3,	/* "crap after beacon" xmit q */
	HAL_TX_QUEUE_UAPSD	= 4	/* u-apsd power save xmit q */
} HAL_TX_QUEUE;


/*
 * Transmit queue subtype.  These map directly to
 * WME Access Categories (except for UPSD).  Refer
 * to Table 5 of the WME spec.
 */
typedef enum {
	HAL_WME_AC_BK	= 0,		/* background access category */
	HAL_WME_AC_BE	= 1, 		/* best effort access category */
	HAL_WME_AC_VI	= 2,		/* video access category */
	HAL_WME_AC_VO	= 3,		/* voice access category */
	HAL_WME_UPSD	= 4,		/* uplink power save */
	HAL_XR_DATA	= 5		/* entended range data */
} HAL_TX_QUEUE_SUBTYPE;

/*
 * Transmit queue flags that control various
 * operational parameters.
 */
typedef enum {
	/*
	 * Per queue interrupt enables.  When set the associated
	 * interrupt may be delivered for packets sent through
	 * the queue.  Without these enabled no interrupts will
	 * be delivered for transmits through the queue.
	 *
	 * When 0x0001 is set, both TXQ_TXOKINT and TXQ_TXERRINT
	 * will be enabled.
	 */
	HAL_TXQ_TXOKINT_ENABLE	   = 0x0001,	/* enable TXOK interrupt */
	HAL_TXQ_TXERRINT_ENABLE    = 0x0001,	/* enable TXERR interrupt */
	HAL_TXQ_TXDESCINT_ENABLE   = 0x0002,	/* enable TXDESC interrupt */
	HAL_TXQ_TXEOLINT_ENABLE    = 0x0004,	/* enable TXEOL interrupt */
	HAL_TXQ_TXURNINT_ENABLE    = 0x0008,	/* enable TXURN interrupt */
	/*
	 * Enable hardware compression for packets sent through
	 * the queue.  The compression buffer must be setup and
	 * packets must have a key entry marked in the tx descriptor.
	 */
	HAL_TXQ_COMPRESSION_ENABLE = 0x0010,	/* enable h/w compression */
	/*
	 * Disable queue when veol is hit or ready time expires.
	 * By default the queue is disabled only on reaching the
	 * physical end of queue (i.e. a null link ptr in the
	 * descriptor chain).
	 */
	HAL_TXQ_RDYTIME_EXP_POLICY_ENABLE = 0x0020,
	/*
	 * Schedule frames on delivery of a DBA (DMA Beacon Alert)
	 * event.  Frames will be transmitted only when this timer
	 * fires, e.g to transmit a beacon in ap or adhoc modes.
	 */
	HAL_TXQ_DBA_GATED	   = 0x0040,	/* schedule based on DBA */
	/*
	 * Each transmit queue has a counter that is incremented
	 * each time the queue is enabled and decremented when
	 * the list of frames to transmit is traversed (or when
	 * the ready time for the queue expires).  This counter
	 * must be non-zero for frames to be scheduled for
	 * transmission.  The following controls disable bumping
	 * this counter under certain conditions.  Typically this
	 * is used to gate frames based on the contents of another
	 * queue (e.g. CAB traffic may only follow a beacon frame).
	 * These are meaningful only when frames are scheduled
	 * with a non-ASAP policy (e.g. DBA-gated).
	 */
	HAL_TXQ_CBR_DIS_QEMPTY	   = 0x0080,	/* disable on this q empty */
	HAL_TXQ_CBR_DIS_BEMPTY	   = 0x0100,	/* disable on beacon q empty */

	/*
	 * Fragment burst backoff policy.   Normally no backoff
	 * is done after a successful transmission, the next fragment
	 * is sent at SIFS.  If this flag is set backoff is done
	 * after each fragment, regardless whether it was ack'd or
	 * not, after the backoff count reaches zero a normal channel
	 * access procedure is done before the next transmit (i.e.
	 * wait AIFS instead of SIFS).
	 */
	HAL_TXQ_FRAG_BURST_BACKOFF_ENABLE = 0x00800000,
	/*
	 * Disable post-tx backoff following each frame.
	 */
	HAL_TXQ_BACKOFF_DISABLE    =  0x00010000, /* disable post backoff  */
	/*
	 * DCU arbiter lockout control.  This controls how
	 * lower priority tx queues are handled with respect
	 * to a specific queue when multiple queues have frames
	 * to send.  No lockout means lower priority queues arbitrate
	 * concurrently with this queue.  Intra-frame lockout
	 * means lower priority queues are locked out until the
	 * current frame transmits (e.g. including backoffs and bursting).
	 * Global lockout means nothing lower can arbitrary so
	 * long as there is traffic activity on this queue (frames,
	 * backoff, etc).
	 */
	HAL_TXQ_ARB_LOCKOUT_INTRA  = 0x00020000, /* intra-frame lockout */
	HAL_TXQ_ARB_LOCKOUT_GLOBAL = 0x00040000, /* full lockout s */

	HAL_TXQ_IGNORE_VIRTCOL	   = 0x00080000, /* ignore virt collisions */
	HAL_TXQ_SEQNUM_INC_DIS	   = 0x00100000  /* disable seqnum increment */
} HAL_TX_QUEUE_FLAGS;

typedef struct {
	uint32_t	tqi_ver;		/* hal TXQ version */
	HAL_TX_QUEUE_SUBTYPE tqi_subtype;	/* subtype if applicable */
	HAL_TX_QUEUE_FLAGS tqi_qflags;		/* flags (see above) */
	uint32_t	tqi_priority;		/* (not used) */
	uint32_t	tqi_aifs;		/* AIFS shift */
	int32_t		tqi_cwmin;		/* cwMin shift */
	int32_t		tqi_cwmax;		/* cwMax shift */
	uint16_t	tqi_shretry;		/* rts retry limit */
	uint16_t	tqi_lgretry;		/* long retry limit(not used) */
	uint32_t	tqi_cbrPeriod;
	uint32_t	tqi_cbrOverflowLimit;
	uint32_t	tqi_burstTime;
	uint32_t	tqi_readyTime;
	uint32_t	tqi_compBuf;		/* compress buffer phys addr */
} HAL_TXQ_INFO;

#define	HAL_TQI_NONVAL		0xffff

/* token to use for aifs, cwmin, cwmax */
#define	HAL_TXQ_USEDEFAULT	((uint32_t)-1)

/*
 * Transmit packet types.  This belongs in ah_desc.h, but
 * is here so we can give a proper type to various parameters
 * (and not require everyone include the file).
 *
 * NB: These values are intentionally assigned for
 *     direct use when setting up h/w descriptors.
 */
typedef enum {
	HAL_PKT_TYPE_NORMAL	= 0,
	HAL_PKT_TYPE_ATIM	= 1,
	HAL_PKT_TYPE_PSPOLL	= 2,
	HAL_PKT_TYPE_BEACON	= 3,
	HAL_PKT_TYPE_PROBE_RESP	= 4,
	HAL_PKT_TYPE_CHIRP	= 5,
	HAL_PKT_TYPE_GRP_POLL	= 6,
	HAL_PKT_TYPE_AMPDU	= 7
} HAL_PKT_TYPE;

/* Rx Filter Frame Types */
typedef enum {
	HAL_RX_FILTER_UCAST	= 0x00000001,	/* Allow unicast frames */
	HAL_RX_FILTER_MCAST	= 0x00000002,	/* Allow multicast frames */
	HAL_RX_FILTER_BCAST	= 0x00000004,	/* Allow broadcast frames */
	HAL_RX_FILTER_CONTROL	= 0x00000008,	/* Allow control frames */
	HAL_RX_FILTER_BEACON	= 0x00000010,	/* Allow beacon frames */
	HAL_RX_FILTER_PROM	= 0x00000020,	/* Promiscuous mode */
	HAL_RX_FILTER_XRPOLL	= 0x00000040,	/* Allow XR poll frmae */
	HAL_RX_FILTER_PROBEREQ	= 0x00000080,	/* Allow probe request frames */
	HAL_RX_FILTER_PHYERR	= 0x00000100,	/* Allow phy errors */
	HAL_RX_FILTER_PHYRADAR	= 0x00000200	/* Allow phy radar errors */
} HAL_RX_FILTER;

typedef enum {
	HAL_PM_AWAKE		= 0,
	HAL_PM_FULL_SLEEP	= 1,
	HAL_PM_NETWORK_SLEEP	= 2,
	HAL_PM_UNDEFINED	= 3
} HAL_POWER_MODE;

/*
 * NOTE WELL:
 * These are mapped to take advantage of the common locations for many of
 * the bits on all of the currently supported MAC chips. This is to make
 * the ISR as efficient as possible, while still abstracting HW differences.
 * When new hardware breaks this commonality this enumerated type, as well
 * as the HAL functions using it, must be modified. All values are directly
 * mapped unless commented otherwise.
 */
typedef enum {
	HAL_INT_RX	= 0x00000001,	/* Non-common mapping */
	HAL_INT_RXDESC	= 0x00000002,
	HAL_INT_RXNOFRM	= 0x00000008,
	HAL_INT_RXEOL	= 0x00000010,
	HAL_INT_RXORN	= 0x00000020,
	HAL_INT_TX	= 0x00000040,	/* Non-common mapping */
	HAL_INT_TXDESC	= 0x00000080,
	HAL_INT_TXURN	= 0x00000800,
	HAL_INT_MIB	= 0x00001000,
	HAL_INT_RXPHY	= 0x00004000,
	HAL_INT_RXKCM	= 0x00008000,
	HAL_INT_SWBA	= 0x00010000,
	HAL_INT_BMISS	= 0x00040000,
	HAL_INT_BNR	= 0x00100000,	/* Non-common mapping */
	HAL_INT_TIM	= 0x00200000,	/* Non-common mapping */
	HAL_INT_DTIM	= 0x00400000,	/* Non-common mapping */
	HAL_INT_DTIMSYNC = 0x00800000,	/* Non-common mapping */
	HAL_INT_GPIO	= 0x01000000,
	HAL_INT_CABEND	= 0x02000000,	/* Non-common mapping */
	HAL_INT_CST	= 0x10000000,	/* Non-common mapping */
	HAL_INT_GTT	= 0x20000000,	/* Non-common mapping */
	HAL_INT_FATAL	= 0x40000000,	/* Non-common mapping */
	HAL_INT_GLOBAL	= INT_MIN,	/* Set/clear IER */
	HAL_INT_BMISC	= HAL_INT_TIM
			| HAL_INT_DTIM
			| HAL_INT_DTIMSYNC
			| HAL_INT_CABEND,

	/* Interrupt bits that map directly to ISR/IMR bits */
	HAL_INT_COMMON  = HAL_INT_RXNOFRM
			| HAL_INT_RXDESC
			| HAL_INT_RXEOL
			| HAL_INT_RXORN
			| HAL_INT_TXURN
			| HAL_INT_TXDESC
			| HAL_INT_MIB
			| HAL_INT_RXPHY
			| HAL_INT_RXKCM
			| HAL_INT_SWBA
			| HAL_INT_BMISS
			| HAL_INT_GPIO,
} HAL_INT;

typedef enum {
	HAL_RFGAIN_INACTIVE		= 0,
	HAL_RFGAIN_READ_REQUESTED	= 1,
	HAL_RFGAIN_NEED_CHANGE		= 2
} HAL_RFGAIN;

typedef enum {
	HAL_PHYERR_UNDERRUN		= 0,	/* Transmit underrun */
	HAL_PHYERR_TIMING		= 1,	/* Timing error */
	HAL_PHYERR_PARITY		= 2,	/* Illegal parity */
	HAL_PHYERR_RATE			= 3,	/* Illegal rate */
	HAL_PHYERR_LENGTH		= 4,	/* Illegal length */
	HAL_PHYERR_RADAR		= 5,	/* Radar detect */
	HAL_PHYERR_SERVICE		= 6,	/* Illegal service */
	HAL_PHYERR_TOR			= 7,	/* Transmit override receive */
	/* NB: these are specific to the 5212 */
	HAL_PHYERR_OFDM_TIMING		= 17,	/* */
	HAL_PHYERR_OFDM_SIGNAL_PARITY	= 18,	/* */
	HAL_PHYERR_OFDM_RATE_ILLEGAL	= 19,	/* */
	HAL_PHYERR_OFDM_LENGTH_ILLEGAL	= 20,	/* */
	HAL_PHYERR_OFDM_POWER_DROP	= 21,	/* */
	HAL_PHYERR_OFDM_SERVICE		= 22,	/* */
	HAL_PHYERR_OFDM_RESTART		= 23,	/* */
	HAL_PHYERR_CCK_TIMING		= 25,	/* */
	HAL_PHYERR_CCK_HEADER_CRC	= 26,	/* */
	HAL_PHYERR_CCK_RATE_ILLEGAL	= 27,	/* */
	HAL_PHYERR_CCK_SERVICE		= 30,	/* */
	HAL_PHYERR_CCK_RESTART		= 31	/* */
}HAL_PHYERR;

/*
 * Channels are specified by frequency.
 */
typedef struct {
	uint32_t	channelFlags;
	uint16_t	channel;	/* setting in Mhz */
	uint8_t		privFlags;
	int8_t		maxRegTxPower;	/* max regulatory tx power in dBm */
	int8_t		maxTxPower;	/* max true tx power in 0.5 dBm */
	int8_t		minTxPower;	/* min true tx power in 0.5 dBm */
} HAL_CHANNEL;


typedef struct {
	uint32_t	ackrcv_bad;
	uint32_t	rts_bad;
	uint32_t	rts_good;
	uint32_t	fcs_bad;
	uint32_t	beacons;
} HAL_MIB_STATS;


enum {
	CTRY_DEBUG	= 0x1ff,		/* debug country code */
	CTRY_DEFAULT	= 0			/* default country code */
};

enum {
	HAL_MODE_11A	= 0x001,	/* 11a channels */
	HAL_MODE_TURBO	= 0x002,	/* 11a turbo-only channels */
	HAL_MODE_11B	= 0x004,	/* 11b channels */
	HAL_MODE_PUREG	= 0x008,	/* 11g channels (OFDM only) */
	HAL_MODE_11G	= 0x008,	/* XXX historical */
	HAL_MODE_108G	= 0x020,	/* 11g+Turbo channels */
	HAL_MODE_108A	= 0x040,	/* 11a+Turbo channels */
	HAL_MODE_XR	= 0x100,	/* XR channels */
	HAL_MODE_11A_HALF_RATE = 0x200,	/* 11A half rate channels */
	HAL_MODE_11A_QUARTER_RATE = 0x400,	/* 11A quarter rate channels */
	HAL_MODE_11NG_HT20	= 0x8000,
	HAL_MODE_11NA_HT20	= 0x10000,
	HAL_MODE_11NG_HT40PLUS	= 0x20000,
	HAL_MODE_11NG_HT40MINUS	= 0x40000,
	HAL_MODE_11NA_HT40PLUS	= 0x80000,
	HAL_MODE_11NA_HT40MINUS	= 0x100000,
	HAL_MODE_ALL	= 0xffffff
};

typedef struct {
	int		rateCount;		/* NB: for proper padding */
	uint8_t	rateCodeToIndex[144];	/* back mapping */
	struct {
		uint8_t	valid;		/* valid for rate control use */
		uint8_t	phy;		/* CCK/OFDM/XR */
		uint32_t rateKbps;	/* transfer rate in kbs */
		uint8_t	rateCode;	/* rate for h/w descriptors */
		/* mask for enabling short preamble in CCK rate code */
		uint8_t	shortPreamble;
		/* value for supported rates info element of MLME */
		uint8_t	dot11Rate;
		/* index of next lower basic rate; used for dur. calcs */
		uint8_t	controlRate;
		uint16_t lpAckDuration;	/* long preamble ACK duration */
		uint16_t spAckDuration;	/* short preamble ACK duration */
	} info[32];
} HAL_RATE_TABLE;

typedef struct {
	uint32_t	rs_count;	/* number of valid entries */
	uint8_t	rs_rates[32];		/* rates */
} HAL_RATE_SET;

/*
 * 802.11n specific structures and enums
 */
typedef enum {
	HAL_CHAINTYPE_TX	= 1,	/* Tx chain type */
	HAL_CHAINTYPE_RX	= 2,	/* RX chain type */
} HAL_CHAIN_TYPE;

typedef struct {
	uint_t	Tries;
	uint_t	Rate;
	uint_t	PktDuration;
	uint_t	ChSel;
	uint_t	RateFlags;
#define	HAL_RATESERIES_RTS_CTS	0x0001	/* use rts/cts w/this series */
#define	HAL_RATESERIES_2040	0x0002	/* use ext channel for series */
#define	HAL_RATESERIES_HALFGI	0x0004	/* use half-gi for series */
} HAL_11N_RATE_SERIES;

typedef enum {
	HAL_HT_MACMODE_20	= 0,	/* 20 MHz operation */
	HAL_HT_MACMODE_2040	= 1	/* 20/40 MHz operation */
} HAL_HT_MACMODE;

typedef enum {
	HAL_HT_PHYMODE_20	= 0,	/* 20 MHz operation */
	HAL_HT_PHYMODE_2040	= 1	/* 20/40 MHz operation */
} HAL_HT_PHYMODE;

typedef enum {
	HAL_HT_EXTPROTSPACING_20 = 0,	/* 20 MHz spacing */
	HAL_HT_EXTPROTSPACING_25 = 1	/* 25 MHz spacing */
} HAL_HT_EXTPROTSPACING;

typedef enum {
	HAL_RX_CLEAR_CTL_LOW	= 1,	/* force control chan to appear busy */
	HAL_RX_CLEAR_EXT_LOW	= 2	/* force ext chan to appear busy */
} HAL_HT_RXCLEAR;

/*
 * Antenna switch control.  By default antenna selection
 * enables multiple (2) antenna use.  To force use of the
 * A or B antenna only specify a fixed setting.  Fixing
 * the antenna will also disable any diversity support.
 */
typedef enum {
	HAL_ANT_VARIABLE = 0,		/* variable by programming */
	HAL_ANT_FIXED_A	 = 1,		/* fixed antenna A */
	HAL_ANT_FIXED_B	 = 2		/* fixed antenna B */
} HAL_ANT_SETTING;

typedef enum {
	HAL_M_STA	= 1,		/* infrastructure station */
	HAL_M_IBSS	= 0,		/* IBSS (adhoc) station */
	HAL_M_HOSTAP	= 6,		/* Software Access Point */
	HAL_M_MONITOR	= 8		/* Monitor mode */
} HAL_OPMODE;

typedef struct {
	uint8_t	kv_type;		/* one of HAL_CIPHER */
	uint8_t	kv_pad;
	uint16_t	kv_len;		/* length in bits */
	uint8_t	kv_val[16];		/* enough for 128-bit keys */
	uint8_t	kv_mic[8];		/* TKIP MIC key */
	uint8_t	kv_txmic[8];		/* TKIP TX MIC key (optional) */
} HAL_KEYVAL;

typedef enum {
	HAL_CIPHER_WEP		= 0,
	HAL_CIPHER_AES_OCB	= 1,
	HAL_CIPHER_AES_CCM	= 2,
	HAL_CIPHER_CKIP		= 3,
	HAL_CIPHER_TKIP		= 4,
	HAL_CIPHER_CLR		= 5,	/* no encryption */

	HAL_CIPHER_MIC		= 127	/* TKIP-MIC, not a cipher */
} HAL_CIPHER;

enum {
	HAL_SLOT_TIME_6  = 6,		/* NB: for turbo mode */
	HAL_SLOT_TIME_9	 = 9,
	HAL_SLOT_TIME_20 = 20
};

/*
 * Per-station beacon timer state.  Note that the specified
 * beacon interval (given in TU's) can also include flags
 * to force a TSF reset and to enable the beacon xmit logic.
 * If bs_cfpmaxduration is non-zero the hardware is setup to
 * coexist with a PCF-capable AP.
 */
typedef struct {
	uint32_t	bs_nexttbtt;		/* next beacon in TU */
	uint32_t	bs_nextdtim;		/* next DTIM in TU */
	uint32_t	bs_intval;		/* beacon interval+flags */
	uint32_t	bs_dtimperiod;
	uint16_t	bs_cfpperiod;		/* CFP period in TU */
	uint16_t	bs_cfpmaxduration;	/* max CFP duration in TU */
	uint32_t	bs_cfpnext;		/* next CFP in TU */
	uint16_t	bs_timoffset;		/* byte offset to TIM bitmap */
	uint16_t	bs_bmissthreshold;	/* beacon miss threshold */
	uint32_t	bs_sleepduration;	/* max sleep duration */
} HAL_BEACON_STATE;

/*
 * Like HAL_BEACON_STATE but for non-station mode setup.
 * NB: see above flag definitions
 */
typedef struct {
	uint32_t	bt_intval;		/* beacon interval+flags */
	uint32_t	bt_nexttbtt;		/* next beacon in TU */
	uint32_t	bt_nextatim;		/* next ATIM in TU */
	uint32_t	bt_nextdba;		/* next DBA in 1/8th TU */
	uint32_t	bt_nextswba;		/* next SWBA in 1/8th TU */
	uint32_t	bt_flags;		/* timer enables */
#define	HAL_BEACON_TBTT_EN	0x00000001
#define	HAL_BEACON_DBA_EN	0x00000002
#define	HAL_BEACON_SWBA_EN	0x00000004
} HAL_BEACON_TIMERS;

/*
 * Per-node statistics maintained by the driver for use in
 * optimizing signal quality and other operational aspects.
 */
typedef struct {
	uint32_t	ns_avgbrssi;	/* average beacon rssi */
	uint32_t	ns_avgrssi;	/* average data rssi */
	uint32_t	ns_avgtxrssi;	/* average tx rssi */
} HAL_NODE_STATS;

/*
 * Transmit descriptor status.  This structure is filled
 * in only after the tx descriptor process method finds a
 * ``done'' descriptor; at which point it returns something
 * other than HAL_EINPROGRESS.
 *
 * Note that ts_antenna may not be valid for all h/w.  It
 * should be used only if non-zero.
 */
struct ath_tx_status {
	uint16_t	ts_seqnum;	/* h/w assigned sequence number */
	uint16_t	ts_tstamp;	/* h/w assigned timestamp */
	uint8_t		ts_status;	/* frame status, 0 => xmit ok */
	uint8_t		ts_rate;	/* h/w transmit rate index */
	int8_t		ts_rssi;	/* tx ack RSSI */
	uint8_t		ts_shortretry;	/* # short retries */
	uint8_t		ts_longretry;	/* # long retries */
	uint8_t		ts_virtcol;	/* virtual collision count */
	uint8_t		ts_antenna;	/* antenna information */
	uint8_t		ts_finaltsi;	/* final transmit series index */
	/* AH_SUPPORT_AR5416 */		/* 802.11n status */
	uint8_t		ts_flags;	/* misc flags */
	int8_t		ts_rssi_ctl[3];	/* tx ack RSSI [ctl, chain 0-2] */
	int8_t		ts_rssi_ext[3];	/* tx ack RSSI [ext, chain 0-2] */
	uint32_t	ts_ba_low;	/* blockack bitmap low */
	uint32_t	ts_ba_high;	/* blockack bitmap high */
	uint32_t	ts_evm0;	/* evm bytes */
	uint32_t	ts_evm1;
	uint32_t	ts_evm2;
};


/*
 * Receive descriptor status.  This structure is filled
 * in only after the rx descriptor process method finds a
 * ``done'' descriptor; at which point it returns something
 * other than HAL_EINPROGRESS.
 *
 * If rx_status is zero, then the frame was received ok;
 * otherwise the error information is indicated and rs_phyerr
 * contains a phy error code if HAL_RXERR_PHY is set.  In general
 * the frame contents is undefined when an error occurred thought
 * for some errors (e.g. a decryption error), it may be meaningful.
 *
 * Note that the receive timestamp is expanded using the TSF to
 * at least 15 bits (regardless of what the h/w provides directly).
 * Newer hardware supports a full 32-bits; use HAL_CAP_32TSTAMP to
 * find out if the hardware is capable.
 *
 * rx_rssi is in units of dbm above the noise floor.  This value
 * is measured during the preamble and PLCP; i.e. with the initial
 * 4us of detection.  The noise floor is typically a consistent
 * -96dBm absolute power in a 20MHz channel.
 */
struct ath_rx_status {
	uint16_t	rs_datalen;	/* rx frame length */
	uint8_t		rs_status;	/* rx status, 0 => recv ok */
	uint8_t		rs_phyerr;	/* phy error code */
	int8_t		rs_rssi;	/* rx frame RSSI (xombined for 11n) */
	uint8_t		rs_keyix;	/* key cache index */
	uint8_t		rs_rate;	/* h/w receive rate index */
	uint8_t		rs_more;	/* see HAL_RXERR_XXX definition */
	uint32_t	rs_tstamp;	/* h/w assigned timestamp */
	uint32_t	rs_antenna;	/* antenna information */
	/* AH_SUPPORT_AR5416 */		/* 802.11n status */
	int8_t		rs_rssi_ctl[3];	/* rx frame RSSI [ctl, chain 0-2] */
	int8_t		rs_rssi_ext[3];	/* rx frame RSSI [ext, chain 0-2] */
	uint8_t		rs_isaggr;	/* is part of the aggregate */
	uint8_t		rs_moreaggr;	/* more frames in aggr to follow */
	uint8_t		rs_num_delims;	/* number of delims in aggr */
	uint8_t		rs_flags;	/* misc flags */
	uint32_t	rs_evm0;	/* evm bytes */
	uint32_t	rs_evm1;
	uint32_t	rs_evm2;
};

/*
 * Definitions for the software frame/packet descriptors used by
 * the Atheros HAL.  This definition obscures hardware-specific
 * details from the driver.  Drivers are expected to fillin the
 * portions of a descriptor that are not opaque then use HAL calls
 * to complete the work.  Status for completed frames is returned
 * in a device-independent format.
 */
/* AH_SUPPORT_AR5416 */
#define	HAL_DESC_HW_SIZE	20

#pragma pack(1)
struct ath_desc {
	/*
	 * The following definitions are passed directly
	 * the hardware and managed by the HAL.  Drivers
	 * should not touch those elements marked opaque.
	 */
	uint32_t	ds_link;	/* phys address of next descriptor */
	uint32_t	ds_data;	/* phys address of data buffer */
	uint32_t	ds_ctl0;	/* opaque DMA control 0 */
	uint32_t	ds_ctl1;	/* opaque DMA control 1 */
	uint32_t	ds_hw[HAL_DESC_HW_SIZE]; /* opaque h/w region */
};

struct ath_desc_status {
	union {
		struct ath_tx_status tx; /* xmit status */
		struct ath_rx_status rx; /* recv status */
	} ds_us;
};
#pragma pack()

#define	ds_txstat	ds_us.tx
#define	ds_rxstat	ds_us.rx

/*
 * Hardware Access Layer (HAL) API.
 *
 * Clients of the HAL call ath_hal_attach to obtain a reference to an
 * ath_hal structure for use with the device.  Hardware-related operations
 * that follow must call back into the HAL through interface, supplying
 * the reference as the first parameter.  Note that before using the
 * reference returned by ath_hal_attach the caller should verify the
 * ABI version number.
 */
struct ath_hal {
	uint32_t	ah_magic;	/* consistency check magic number */
	uint32_t	ah_abi;		/* HAL ABI version */
	uint16_t	ah_devid;	/* PCI device ID */
	uint16_t	ah_subvendorid;	/* PCI subvendor ID */
	HAL_SOFTC	ah_sc;		/* back pointer to driver/os state */
	HAL_BUS_TAG	ah_st;		/* params for register r+w */
	HAL_BUS_HANDLE	ah_sh;
	HAL_CTRY_CODE	ah_countryCode;

	uint32_t	ah_macVersion;	/* MAC version id */
	uint16_t	ah_macRev;	/* MAC revision */
	uint16_t	ah_phyRev;	/* PHY revision */
	/* NB: when only one radio is present the rev is in 5Ghz */
	uint16_t	ah_analog5GhzRev; /* 5GHz radio revision */
	uint16_t	ah_analog2GhzRev; /* 2GHz radio revision */

	const HAL_RATE_TABLE *(*ah_getRateTable)(struct ath_hal *,
				uint32_t mode);
	void	  (*ah_detach) (struct ath_hal *);

	/* Reset functions */
	HAL_BOOL  (*ah_reset) (struct ath_hal *, HAL_OPMODE,
				HAL_CHANNEL *, HAL_BOOL bChannelChange,
				HAL_STATUS *status);
	HAL_BOOL  (*ah_phyDisable) (struct ath_hal *);
	HAL_BOOL  (*ah_disable) (struct ath_hal *);
	void	  (*ah_setPCUConfig) (struct ath_hal *);
	HAL_BOOL  (*ah_perCalibration) (struct ath_hal *, HAL_CHANNEL *,
				HAL_BOOL *);
	HAL_BOOL  (*ah_setTxPowerLimit)(struct ath_hal *, uint32_t);

	/* DFS support */
	HAL_BOOL  (*ah_radarWait)(struct ath_hal *, HAL_CHANNEL *);

	/* Transmit functions */
	HAL_BOOL  (*ah_updateTxTrigLevel) (struct ath_hal *,
				HAL_BOOL incTrigLevel);
	int	  (*ah_setupTxQueue) (struct ath_hal *, HAL_TX_QUEUE,
				const HAL_TXQ_INFO *qInfo);
	HAL_BOOL  (*ah_setTxQueueProps) (struct ath_hal *, int q,
				const HAL_TXQ_INFO *qInfo);
	HAL_BOOL  (*ah_getTxQueueProps)(struct ath_hal *, int q,
				HAL_TXQ_INFO *qInfo);
	HAL_BOOL  (*ah_releaseTxQueue) (struct ath_hal *ah, uint32_t q);
	HAL_BOOL  (*ah_resetTxQueue) (struct ath_hal *ah, uint32_t q);
	uint32_t (*ah_getTxDP) (struct ath_hal *, uint32_t);
	HAL_BOOL  (*ah_setTxDP) (struct ath_hal *, uint32_t, uint32_t txdp);
	uint32_t (*ah_numTxPending)(struct ath_hal *, uint32_t q);
	HAL_BOOL  (*ah_startTxDma) (struct ath_hal *, uint32_t);
	HAL_BOOL  (*ah_stopTxDma) (struct ath_hal *, uint32_t);
	HAL_BOOL  (*ah_setupTxDesc) (struct ath_hal *, struct ath_desc *,
				uint32_t pktLen, uint32_t hdrLen,
				HAL_PKT_TYPE type, uint32_t txPower,
				uint32_t txRate0, uint32_t txTries0,
				uint32_t keyIx, uint32_t antMode,
				uint32_t flags, uint32_t rtsctsRate,
				uint32_t rtsctsDuration,
				uint32_t compicvLen, uint32_t compivLen,
				uint32_t comp);
	HAL_BOOL  (*ah_setupXTxDesc) (struct ath_hal *, struct ath_desc *,
				uint32_t txRate1, uint32_t txTries1,
				uint32_t txRate2, uint32_t txTries2,
				uint32_t txRate3, uint32_t txTries3);
	HAL_BOOL  (*ah_fillTxDesc) (struct ath_hal *, struct ath_desc *,
				uint32_t segLen, HAL_BOOL firstSeg,
				HAL_BOOL lastSeg, const struct ath_desc *);
	HAL_STATUS (*ah_procTxDesc)(struct ath_hal *, struct ath_desc *,
				struct ath_tx_status *);
	void	   (*ah_getTxIntrQueue)(struct ath_hal *, uint32_t *);
	void	   (*ah_reqTxIntrDesc)(struct ath_hal *, struct ath_desc *);

	/* Receive Functions */
	uint32_t (*ah_getRxDP) (struct ath_hal *);
	void	  (*ah_setRxDP) (struct ath_hal *, uint32_t rxdp);
	void	  (*ah_enableReceive) (struct ath_hal *);
	HAL_BOOL  (*ah_stopDmaReceive) (struct ath_hal *);
	void	  (*ah_startPcuReceive) (struct ath_hal *);
	void	  (*ah_stopPcuReceive) (struct ath_hal *);
	void	  (*ah_setMulticastFilter) (struct ath_hal *,
				uint32_t filter0, uint32_t filter1);
	HAL_BOOL  (*ah_setMulticastFilterIndex) (struct ath_hal *,
				uint32_t index);
	HAL_BOOL  (*ah_clrMulticastFilterIndex) (struct ath_hal *,
				uint32_t index);
	uint32_t (*ah_getRxFilter) (struct ath_hal *);
	void	  (*ah_setRxFilter) (struct ath_hal *, uint32_t);
	HAL_BOOL  (*ah_setupRxDesc) (struct ath_hal *, struct ath_desc *,
				uint32_t size, uint32_t flags);
	HAL_STATUS (*ah_procRxDesc) (struct ath_hal *, struct ath_desc *,
				uint32_t phyAddr, struct ath_desc *next,
				uint64_t tsf, struct ath_rx_status *);
	void	  (*ah_rxMonitor) (struct ath_hal *,
				const HAL_NODE_STATS *, HAL_CHANNEL *);
	void	  (*ah_procMibEvent) (struct ath_hal *,
				const HAL_NODE_STATS *);

	/* Misc Functions */
	HAL_STATUS  (*ah_getCapability) (struct ath_hal *,
				HAL_CAPABILITY_TYPE, uint32_t capability,
				uint32_t *result);
	HAL_BOOL    (*ah_setCapability) (struct ath_hal *,
				HAL_CAPABILITY_TYPE, uint32_t capability,
				uint32_t setting, HAL_STATUS *);
	HAL_BOOL    (*ah_getDiagState) (struct ath_hal *, int request,
				const void *args, uint32_t argsize,
				void **result, uint32_t *resultsize);
	void	  (*ah_getMacAddress) (struct ath_hal *, uint8_t *);
	HAL_BOOL  (*ah_setMacAddress) (struct ath_hal *, const uint8_t *);
	void	  (*ah_getBssIdMask)(struct ath_hal *, uint8_t *);
	HAL_BOOL  (*ah_setBssIdMask)(struct ath_hal *, const uint8_t *);
	HAL_BOOL  (*ah_setRegulatoryDomain) (struct ath_hal *,
				uint16_t, HAL_STATUS *);
	void	  (*ah_setLedState) (struct ath_hal *, HAL_LED_STATE);
	void	  (*ah_writeAssocid) (struct ath_hal *,
				const uint8_t *bssid, uint16_t assocId);
	HAL_BOOL  (*ah_gpioCfgOutput) (struct ath_hal *, uint32_t gpio);
	HAL_BOOL  (*ah_gpioCfgInput) (struct ath_hal *, uint32_t gpio);
	uint32_t (*ah_gpioGet) (struct ath_hal *, uint32_t gpio);
	HAL_BOOL  (*ah_gpioSet) (struct ath_hal *,
				uint32_t gpio, uint32_t val);
	void	  (*ah_gpioSetIntr) (struct ath_hal *, uint32_t, uint32_t);
	uint32_t (*ah_getTsf32) (struct ath_hal *);
	uint64_t (*ah_getTsf64) (struct ath_hal *);
	void	  (*ah_resetTsf) (struct ath_hal *);
	HAL_BOOL  (*ah_detectCardPresent) (struct ath_hal *);
	void	  (*ah_updateMibCounters) (struct ath_hal *, HAL_MIB_STATS *);
	HAL_RFGAIN (*ah_getRfGain) (struct ath_hal *);
	uint32_t  (*ah_getDefAntenna) (struct ath_hal *);
	void	  (*ah_setDefAntenna) (struct ath_hal *, uint32_t);
	HAL_ANT_SETTING (*ah_getAntennaSwitch) (struct ath_hal *);
	HAL_BOOL  (*ah_setAntennaSwitch) (struct ath_hal *, HAL_ANT_SETTING);
	HAL_BOOL  (*ah_setSifsTime) (struct ath_hal *, uint32_t);
	uint32_t  (*ah_getSifsTime) (struct ath_hal *);
	HAL_BOOL  (*ah_setSlotTime) (struct ath_hal *, uint32_t);
	uint32_t  (*ah_getSlotTime) (struct ath_hal *);
	HAL_BOOL  (*ah_setAckTimeout) (struct ath_hal *, uint32_t);
	uint32_t  (*ah_getAckTimeout) (struct ath_hal *);
	HAL_BOOL  (*ah_setAckCTSRate) (struct ath_hal *, uint32_t);
	uint32_t  (*ah_getAckCTSRate) (struct ath_hal *);
	HAL_BOOL  (*ah_setCTSTimeout) (struct ath_hal *, uint32_t);
	uint32_t  (*ah_getCTSTimeout) (struct ath_hal *);
	HAL_BOOL  (*ah_setDecompMask)(struct ath_hal *, uint16_t, int);
	void	  (*ah_setCoverageClass)(struct ath_hal *, uint8_t, int);
	/* Key Cache Functions */
	uint32_t (*ah_getKeyCacheSize) (struct ath_hal *);
	HAL_BOOL  (*ah_resetKeyCacheEntry) (struct ath_hal *, uint16_t);
	HAL_BOOL  (*ah_isKeyCacheEntryValid) (struct ath_hal *, uint16_t);
	HAL_BOOL  (*ah_setKeyCacheEntry) (struct ath_hal *,
				uint16_t, const HAL_KEYVAL *,
				const uint8_t *, int);
	HAL_BOOL  (*ah_setKeyCacheEntryMac) (struct ath_hal *,
				uint16_t, const uint8_t *);

	/* Power Management Functions */
	HAL_BOOL  (*ah_setPowerMode) (struct ath_hal *,
				HAL_POWER_MODE mode, int setChip);
	HAL_POWER_MODE (*ah_getPowerMode) (struct ath_hal *);
	int16_t   (*ah_getChanNoise)(struct ath_hal *, HAL_CHANNEL *);

	/* Beacon Management Functions */
	void	  (*ah_setBeaconTimers) (struct ath_hal *,
				const HAL_BEACON_TIMERS *);
	/* NB: deprecated, use ah_setBeaconTimers instead */
	void	  (*ah_beaconInit) (struct ath_hal *,
				uint32_t nexttbtt, uint32_t intval);
	void	  (*ah_setStationBeaconTimers) (struct ath_hal *,
				const HAL_BEACON_STATE *);
	void	  (*ah_resetStationBeaconTimers) (struct ath_hal *);

	/* Interrupt functions */
	HAL_BOOL  (*ah_isInterruptPending) (struct ath_hal *);
	HAL_BOOL  (*ah_getPendingInterrupts) (struct ath_hal *, HAL_INT *);
	HAL_INT	  (*ah_getInterrupts) (struct ath_hal *);
	HAL_INT	  (*ah_setInterrupts) (struct ath_hal *, HAL_INT);
};

/*
 * Check the PCI vendor ID and device ID against Atheros' values
 * and return a printable description for any Atheros hardware.
 * AH_NULL is returned if the ID's do not describe Atheros hardware.
 */
extern	const char *ath_hal_probe(uint16_t vendorid, uint16_t devid);

/*
 * Attach the HAL for use with the specified device.  The device is
 * defined by the PCI device ID.  The caller provides an opaque pointer
 * to an upper-layer data structure (HAL_SOFTC) that is stored in the
 * HAL state block for later use.  Hardware register accesses are done
 * using the specified bus tag and handle.  On successful return a
 * reference to a state block is returned that must be supplied in all
 * subsequent HAL calls.  Storage associated with this reference is
 * dynamically allocated and must be freed by calling the ah_detach
 * method when the client is done.  If the attach operation fails a
 * null (AH_NULL) reference will be returned and a status code will
 * be returned if the status parameter is non-zero.
 */
extern	struct ath_hal *ath_hal_attach(uint16_t devid, HAL_SOFTC,
		HAL_BUS_TAG, HAL_BUS_HANDLE, HAL_STATUS *status);

/*
 * Set the Vendor ID for Vendor SKU's which can modify the
 * channel properties returned by ath_hal_init_channels.
 * Return AH_TRUE if set succeeds
 */
extern  HAL_BOOL ath_hal_setvendor(struct ath_hal *, uint32_t);

/*
 * Return a list of channels available for use with the hardware.
 * The list is based on what the hardware is capable of, the specified
 * country code, the modeSelect mask, and whether or not outdoor
 * channels are to be permitted.
 *
 * The channel list is returned in the supplied array.  maxchans
 * defines the maximum size of this array.  nchans contains the actual
 * number of channels returned.  If a problem occurred or there were
 * no channels that met the criteria then AH_FALSE is returned.
 */
extern	HAL_BOOL  ath_hal_init_channels(struct ath_hal *,
		HAL_CHANNEL *chans, uint32_t maxchans, uint32_t *nchans,
		uint8_t *regclassids, uint32_t maxregids, uint32_t *nregids,
		HAL_CTRY_CODE cc, uint_t modeSelect,
		HAL_BOOL enableOutdoor, HAL_BOOL enableExtendedChannels);

/*
 * Calibrate noise floor data following a channel scan or similar.
 *  This must be called prior retrieving noise floor data.
 */
extern void ath_hal_process_noisefloor(struct ath_hal *ah);

/*
 * Return bit mask of wireless modes supported by the hardware.
 */
extern	uint32_t  ath_hal_getwirelessmodes(struct ath_hal *, HAL_CTRY_CODE);

/*
 * Calculate the transmit duration of a frame.
 */
extern uint16_t  ath_hal_computetxtime(struct ath_hal *,
		const HAL_RATE_TABLE *rates, uint32_t frameLen,
		uint16_t rateix, HAL_BOOL shortPreamble);

/*
 * Return if device is public safety.
 */
extern HAL_BOOL ath_hal_ispublicsafetysku(struct ath_hal *);

/*
 * Return if device is operating in 900 MHz band.
 */
extern HAL_BOOL ath_hal_isgsmsku(struct ath_hal *);

/*
 * Convert between IEEE channel number and channel frequency
 * using the specified channel flags; e.g. CHANNEL_2GHZ.
 */
extern	int  ath_hal_mhz2ieee(struct ath_hal *, uint32_t mhz, uint32_t flags);

/*
 * Return a version string for the HAL release.
 */
extern	char ath_hal_version[];

/*
 * Return a NULL-terminated array of build/configuration options.
 */
extern	const char *ath_hal_buildopts[];

/*
 * Macros to encapsulated HAL functions.
 */
#define	ATH_HAL_RESET(_ah, _opmode, _chan, _outdoor, _pstatus) \
	((*(_ah)->ah_reset)((_ah), (_opmode), (_chan), (_outdoor), (_pstatus)))
#define	ATH_HAL_PHYDISABLE(_ah)	\
	((*(_ah)->ah_phyDisable)((_ah)))
#define	ATH_HAL_GETCAPABILITY(_ah, _cap, _param, _result) \
	((*(_ah)->ah_getCapability)((_ah), (_cap), (_param), (_result)))
#define	ATH_HAL_SETCAPABILITY(_ah, _type, _cap, _param, _status) \
	((*(_ah)->ah_setCapability)((_ah), (_type), (_cap), (_param), \
	(_status)))
#define	ATH_HAL_GETREGDOMAIN(_ah, _prd) \
	ATH_HAL_GETCAPABILITY(_ah, HAL_CAP_REG_DMN, 0, (_prd))
#define	ATH_HAL_GETCOUNTRYCODE(_ah, _pcc) \
	(*(_pcc) = (_ah)->ah_countryCode)
#define	ATH_HAL_GETRATETABLE(_ah, _mode) \
	((*(_ah)->ah_getRateTable)((_ah), (_mode)))
#define	ATH_HAL_GETMAC(_ah, _mac) \
	((*(_ah)->ah_getMacAddress)((_ah), (_mac)))
#define	ATH_HAL_SETMAC(_ah, _mac) \
	((*(_ah)->ah_setMacAddress)((_ah), (_mac)))
#define	ATH_HAL_INTRSET(_ah, _mask) \
	((*(_ah)->ah_setInterrupts)((_ah), (_mask)))
#define	ATH_HAL_INTRGET(_ah) \
	((*(_ah)->ah_getInterrupts)((_ah)))
#define	ATH_HAL_INTRPEND(_ah) \
	((*(_ah)->ah_isInterruptPending)((_ah)))
#define	ATH_HAL_GETISR(_ah, _pmask) \
	((*(_ah)->ah_getPendingInterrupts)((_ah), (_pmask)))
#define	ATH_HAL_UPDATETXTRIGLEVEL(_ah, _inc) \
	((*(_ah)->ah_updateTxTrigLevel)((_ah), (_inc)))
#define	ATH_HAL_SETPOWER(_ah, _mode) \
	((*(_ah)->ah_setPowerMode)((_ah), (_mode), AH_TRUE))
#define	ATH_HAL_KEYRESET(_ah, _ix) \
	((*(_ah)->ah_resetKeyCacheEntry)((_ah), (_ix)))
#define	ATH_HAL_KEYSET(_ah, _ix, _pk, _mac) \
	((*(_ah)->ah_setKeyCacheEntry)((_ah), (_ix), (_pk), (_mac), AH_FALSE))
#define	ATH_HAL_KEYISVALID(_ah, _ix) \
	(((*(_ah)->ah_isKeyCacheEntryValid)((_ah), (_ix))))
#define	ATH_HAL_KEYSETMAC(_ah, _ix, _mac) \
	((*(_ah)->ah_setKeyCacheEntryMac)((_ah), (_ix), (_mac)))
#define	ATH_HAL_KEYCACHESIZE(_ah) \
	((*(_ah)->ah_getKeyCacheSize)((_ah)))
#define	ATH_HAL_GETRXFILTER(_ah) \
	((*(_ah)->ah_getRxFilter)((_ah)))
#define	ATH_HAL_SETRXFILTER(_ah, _filter) \
	((*(_ah)->ah_setRxFilter)((_ah), (_filter)))
#define	ATH_HAL_SETMCASTFILTER(_ah, _mfilt0, _mfilt1) \
	((*(_ah)->ah_setMulticastFilter)((_ah), (_mfilt0), (_mfilt1)))
#define	ATH_HAL_WAITFORBEACON(_ah, _bf) \
	((*(_ah)->ah_waitForBeaconDone)((_ah), (_bf)->bf_daddr))
#define	ATH_HAL_PUTRXBUF(_ah, _bufaddr) \
	((*(_ah)->ah_setRxDP)((_ah), (_bufaddr)))
#define	ATH_HAL_GETTSF32(_ah) \
	((*(_ah)->ah_getTsf32)((_ah)))
#define	ATH_HAL_GETTSF64(_ah) \
	((*(_ah)->ah_getTsf64)((_ah)))
#define	ATH_HAL_RESETTSF(_ah) \
	((*(_ah)->ah_resetTsf)((_ah)))
#define	ATH_HAL_RXENA(_ah) \
	((*(_ah)->ah_enableReceive)((_ah)))
#define	ATH_HAL_PUTTXBUF(_ah, _q, _bufaddr) \
	((*(_ah)->ah_setTxDP)((_ah), (_q), (_bufaddr)))
#define	ATH_HAL_GETTXBUF(_ah, _q) \
	((*(_ah)->ah_getTxDP)((_ah), (_q)))
#define	ATH_HAL_GETRXBUF(_ah) \
	((*(_ah)->ah_getRxDP)((_ah)))
#define	ATH_HAL_TXSTART(_ah, _q) \
	((*(_ah)->ah_startTxDma)((_ah), (_q)))
#define	ATH_HAL_SETCHANNEL(_ah, _chan) \
	((*(_ah)->ah_setChannel)((_ah), (_chan)))
#define	ATH_HAL_CALIBRATE(_ah, _chan, _iqcal) \
	((*(_ah)->ah_perCalibration)((_ah), (_chan), (_iqcal)))
#define	ATH_HAL_SETLEDSTATE(_ah, _state) \
	((*(_ah)->ah_setLedState)((_ah), (_state)))
#define	ATH_HAL_BEACONINIT(_ah, _nextb, _bperiod) \
	((*(_ah)->ah_beaconInit)((_ah), (_nextb), (_bperiod)))
#define	ATH_HAL_BEACONRESET(_ah) \
	((*(_ah)->ah_resetStationBeaconTimers)((_ah)))
#define	ATH_HAL_BEACONTIMERS(_ah, _beacon_state) \
	((*(_ah)->ah_setStationBeaconTimers)((_ah), (_beacon_state)))
#define	ATH_HAL_SETASSOCID(_ah, _bss, _associd) \
	((*(_ah)->ah_writeAssocid)((_ah), (_bss), (_associd)))
#define	ATH_HAL_SETOPMODE(_ah) \
	((*(_ah)->ah_setPCUConfig)((_ah)))
#define	ATH_HAL_STOPTXDMA(_ah, _qnum) \
	((*(_ah)->ah_stopTxDma)((_ah), (_qnum)))
#define	ATH_HAL_STOPPCURECV(_ah) \
	((*(_ah)->ah_stopPcuReceive)((_ah)))
#define	ATH_HAL_STARTPCURECV(_ah) \
	((*(_ah)->ah_startPcuReceive)((_ah)))
#define	ATH_HAL_STOPDMARECV(_ah) \
	((*(_ah)->ah_stopDmaReceive)((_ah)))
#define	ATH_HAL_DUMPSTATE(_ah) \
	((*(_ah)->ah_dumpState)((_ah)))
#define	ATH_HAL_DUMPEEPROM(_ah) \
	((*(_ah)->ah_dumpEeprom)((_ah)))
#define	ATH_HAL_DUMPRFGAIN(_ah) \
	((*(_ah)->ah_dumpRfGain)((_ah)))
#define	ATH_HAL_DUMPANI(_ah) \
	((*(_ah)->ah_dumpAni)((_ah)))
#define	ATH_HAL_SETUPTXQUEUE(_ah, _type, _irq) \
	((*(_ah)->ah_setupTxQueue)((_ah), (_type), (_irq)))
#define	ATH_HAL_RESETTXQUEUE(_ah, _q) \
	((*(_ah)->ah_resetTxQueue)((_ah), (_q)))
#define	ATH_HAL_RELEASETXQUEUE(_ah, _q) \
	((*(_ah)->ah_releaseTxQueue)((_ah), (_q)))
#define	ATH_HAL_GETTXQUEUEPROPS(_ah, _q, _qi) \
	((*(_ah)->ah_getTxQueueProps)((_ah), (_q), (_qi)))
#define	ATH_HAL_SETTXQUEUEPROPS(_ah, _q, _qi) \
	((*(_ah)->ah_setTxQueueProps)((_ah), (_q), (_qi)))
#define	ATH_HAL_HASVEOL(_ah) \
	(ATH_HAL_GETCAPABILITY(_ah, HAL_CAP_VEOL, 0, NULL) == HAL_OK)
#define	ATH_HAL_GETRFGAIN(_ah) \
	((*(_ah)->ah_getRfGain)((_ah)))
#define	ATH_HAL_RXMONITOR(_ah, _arg, _chan) \
	((*(_ah)->ah_rxMonitor)((_ah), (_arg), (_chan)))
#define	ATH_HAL_SETSLOTTIME(_ah, _us) \
	((*(_ah)->ah_setSlotTime)((_ah), (_us)))
#define	ATH_HAL_SETUPBEACONDESC(_ah, _ds, _opmode, _flen, _hlen, \
		_rate, _antmode) \
	((*(_ah)->ah_setupBeaconDesc)((_ah), (_ds), (_opmode), \
		(_flen), (_hlen), (_rate), (_antmode)))
#define	ATH_HAL_SETUPRXDESC(_ah, _ds, _size, _intreq) \
	((*(_ah)->ah_setupRxDesc)((_ah), (_ds), (_size), (_intreq)))
#define	ATH_HAL_RXPROCDESC(_ah, _ds, _dspa, _dsnext, _rs) \
	((*(_ah)->ah_procRxDesc)((_ah), (_ds), (_dspa), (_dsnext), 0, (_rs)))
#define	ATH_HAL_SETUPTXDESC(_ah, _ds, _plen, _hlen, _atype, _txpow, \
		_txr0, _txtr0, _keyix, _ant, _flags, \
		_rtsrate, _rtsdura) \
	((*(_ah)->ah_setupTxDesc)((_ah), (_ds), (_plen), (_hlen), (_atype), \
		(_txpow), (_txr0), (_txtr0), (_keyix), (_ant), \
		(_flags), (_rtsrate), (_rtsdura), 0, 0, 0))
#define	ATH_HAL_SETUPXTXDESC(_ah, _ds, \
		_txr1, _txtr1, _txr2, _txtr2, _txr3, _txtr3) \
	((*(_ah)->ah_setupXTxDesc)((_ah), (_ds), \
		(_txr1), (_txtr1), (_txr2), (_txtr2), (_txr3), (_txtr3)))
#define	ATH_HAL_FILLTXDESC(_ah, _ds, _l, _first, _last, _ath_desc) \
	((*(_ah)->ah_fillTxDesc)((_ah), (_ds), (_l), (_first), (_last), \
	(_ath_desc)))
#define	ATH_HAL_TXPROCDESC(_ah, _ds, _ts) \
	((*(_ah)->ah_procTxDesc)((_ah), (_ds), (_ts)))
#define	ATH_HAL_CIPHERSUPPORTED(_ah, _cipher) \
	(ATH_HAL_GETCAPABILITY(_ah, HAL_CAP_CIPHER, _cipher, NULL) == HAL_OK)
#define	ATH_HAL_HASTKIPSPLIT(_ah) \
	(ATH_HAL_GETCAPABILITY(_ah, HAL_CAP_TKIP_SPLIT, 0, NULL) == HAL_OK)
#define	ATH_HAL_GETTKIPSPLIT(_ah) \
	(ATH_HAL_GETCAPABILITY(_ah, HAL_CAP_TKIP_SPLIT, 1, NULL) == HAL_OK)
#define	ATH_HAL_SETTKIPSPLIT(_ah, _v) \
	(ATH_HAL_SETCAPABILITY(_ah, HAL_CAP_TKIP_SPLIT, 1, _v, NULL))
#define	ATH_HAL_HASRFSILENT(ah) \
	(ATH_HAL_GETCAPABILITY(_ah, HAL_CAP_RFSILENT, 0, NULL) == HAL_OK)
#define	ATH_HAL_GETRFKILL(_ah) \
	(ATH_HAL_GETCAPABILITY(_ah, HAL_CAP_RFSILENT, 1, NULL) == HAL_OK)
#define	ATH_HAL_SETRFKILL(_ah, _onoff) \
	(ATH_HAL_SETCAPABILITY(_ah, HAL_CAP_RFSILENT, 1, _onoff, NULL))
#define	ATH_HAL_GETRFSILENT(_ah, _prfsilent) \
	(ATH_HAL_GETCAPABILITY(_ah, HAL_CAP_RFSILENT, 2, _prfsilent) == HAL_OK)
#define	ATH_HAL_SETRFSILENT(_ah, _rfsilent) \
	(ATH_HAL_SETCAPABILITY(_ah, HAL_CAP_RFSILENT, 2, _rfsilent, NULL))

#if HAL_ABI_VERSION < 0x05120700
#define	ATH_HAL_PROCESS_NOISEFLOOR(_ah)
#define	ATH_HAL_GETCHANNOISE(_ah, _c)	(-96)
#define	HAL_CAP_TPC_ACK	100
#define	HAL_CAP_TPC_CTS	101
#else
#define	ATH_HAL_GETCHANNOISE(_ah, _c)	\
	((*(_ah)->ah_getChanNoise)((_ah), (_c)))
#endif

#if HAL_ABI_VERSION < 0x05122200
#define	HAL_TXQ_TXOKINT_ENABLE	TXQ_FLAG_TXOKINT_ENABLE
#define	HAL_TXQ_TXERRINT_ENABLE	TXQ_FLAG_TXERRINT_ENABLE
#define	HAL_TXQ_TXDESCINT_ENABLE	TXQ_FLAG_TXDESCINT_ENABLE
#define	HAL_TXQ_TXEOLINT_ENABLE	TXQ_FLAG_TXEOLINT_ENABLE
#define	HAL_TXQ_TXURNINT_ENABLE	TXQ_FLAG_TXURNINT_ENABLE
#endif

#ifdef __cplusplus
}
#endif

#endif /* _ATH_HAL_H */
