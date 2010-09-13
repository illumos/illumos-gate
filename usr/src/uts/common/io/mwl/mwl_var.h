/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2007-2009 Sam Leffler, Errno Consulting
 * Copyright (c) 2007-2009 Marvell Semiconductor, Inc.
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

/*
 * Definitions for the Marvell 88W8363 Wireless LAN controller.
 */

#ifndef	_MWL_VAR_H
#define	_MWL_VAR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/note.h>
#include "mwl_reg.h"

#define	MWL_CMDBUF_SIZE		0x4000	/* size of f/w command buffer */
#define	MWL_RX_RING_COUNT	256
#define	MWL_TX_RING_COUNT	256

#ifndef MWL_AGGR_SIZE
#define	MWL_AGGR_SIZE		3839	/* max tx agregation size */
#endif
#define	MWL_AGEINTERVAL		1	/* poke f/w every sec to age q's */

/*
 * Define total number of TX queues in the shared memory.
 * This count includes the EDCA queues, Block Ack queues, and HCCA queues
 * In addition to this, there could be a management packet queue some
 * time in the future
 */
#define	MWL_NUM_EDCA_QUEUES	4
#define	MWL_NUM_HCCA_QUEUES	0
#define	MWL_NUM_BA_QUEUES	0
#define	MWL_NUM_MGMT_QUEUES	0
#define	MWL_NUM_ACK_QUEUES	0
#define	MWL_NUM_TX_QUEUES \
	(MWL_NUM_EDCA_QUEUES + MWL_NUM_HCCA_QUEUES + MWL_NUM_BA_QUEUES + \
	MWL_NUM_MGMT_QUEUES + MWL_NUM_ACK_QUEUES)
#define	MWL_MAX_RXWCB_QUEUES	1

#define	MWL_MAX_SUPPORTED_RATES	12
#define	MWL_MAX_SUPPORTED_MCS	32

#define	PWTAGETRATETABLE20M	14 * 4
#define	PWTAGETRATETABLE40M	9 * 4
#define	PWTAGETRATETABLE20M_5G	35 * 4
#define	PWTAGETRATETABLE40M_5G	16 * 4

#define	MHF_CALDATA	0x0001		/* cal data retrieved */
#define	MHF_FWHANG	0x0002		/* fw appears hung */
#define	MHF_MBSS	0x0004		/* mbss enabled */

#define	IEEE80211_CHAN_STURBO	0x00002000 /* 11a static turbo channel only */
#define	IEEE80211_CHAN_HALF	0x00004000 /* Half rate channel */
#define	IEEE80211_CHAN_QUARTER	0x00008000 /* Quarter rate channel */

#define	IEEE80211_CHAN_HT20	0x00010000 /* HT 20 channel */
#define	IEEE80211_CHAN_HT40U	0x00020000 /* HT 40 channel w/ ext above */
#define	IEEE80211_CHAN_HT40D	0x00040000 /* HT 40 channel w/ ext below */

#define	IEEE80211_CHAN_FHSS \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_GFSK)
#define	IEEE80211_CHAN_A	\
	(IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM)
#define	IEEE80211_CHAN_B	\
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_CCK)
#define	IEEE80211_CHAN_PUREG \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_OFDM)
#define	IEEE80211_CHAN_G	\
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_DYN)
#define	IEEE80211_CHAN_HT40	\
	(IEEE80211_CHAN_HT40U | IEEE80211_CHAN_HT40D)
#define	IEEE80211_CHAN_HT	\
	(IEEE80211_CHAN_HT20 | IEEE80211_CHAN_HT40)

#define	IEEE80211_CHAN_108A \
	(IEEE80211_CHAN_A | IEEE80211_CHAN_TURBO)
#define	IEEE80211_CHAN_108G \
	(IEEE80211_CHAN_PUREG | IEEE80211_CHAN_TURBO)
#define	IEEE80211_CHAN_ST \
	(IEEE80211_CHAN_108A | IEEE80211_CHAN_STURBO)

#define	IEEE80211_MODE_STURBO_A	7
#define	IEEE80211_MODE_11NA	8	/* 5GHz, w/ HT */
#define	IEEE80211_MODE_11NG	9	/* 2GHz, w/ HT */
#define	IEEE80211_MODE_HALF	10	/* OFDM, 1/2x clock */
#define	IEEE80211_MODE_QUARTER	11	/* OFDM, 1/4x clock */


#define	IEEE80211_IS_CHAN_2GHZ_F(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_2GHZ) != 0)
#define	IEEE80211_IS_CHAN_5GHZ_F(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_5GHZ) != 0)

#define	IEEE80211_IS_CHAN_FHSS(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_FHSS) == IEEE80211_CHAN_FHSS)
#define	IEEE80211_IS_CHAN_A(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_A) == IEEE80211_CHAN_A)
#define	IEEE80211_IS_CHAN_B(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_B) == IEEE80211_CHAN_B)
#define	IEEE80211_IS_CHAN_PUREG(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_PUREG) == IEEE80211_CHAN_PUREG)
#define	IEEE80211_IS_CHAN_G(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_G) == IEEE80211_CHAN_G)
#define	IEEE80211_IS_CHAN_ANYG(_c) \
	(IEEE80211_IS_CHAN_PUREG(_c) || IEEE80211_IS_CHAN_G(_c))
#define	IEEE80211_IS_CHAN_ST(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_ST) == IEEE80211_CHAN_ST)
#define	IEEE80211_IS_CHAN_108A(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_108A) == IEEE80211_CHAN_108A)
#define	IEEE80211_IS_CHAN_108G(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_108G) == IEEE80211_CHAN_108G)

#define	IEEE80211_IS_CHAN_HTA(_c) \
	(IEEE80211_IS_CHAN_5GHZ_F(_c) && \
	((_c)->ic_flags & IEEE80211_CHAN_HT) != 0)

#define	IEEE80211_IS_CHAN_HTG(_c) \
	(IEEE80211_IS_CHAN_2GHZ_F(_c) && \
	((_c)->ic_flags & IEEE80211_CHAN_HT) != 0)

#define	IEEE80211_IS_CHAN_TURBO(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_TURBO) != 0)

#define	IEEE80211_IS_CHAN_HALF(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_HALF) != 0)

#define	IEEE80211_IS_CHAN_QUARTER(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_QUARTER) != 0)

/* WME stream classes */
#define	WME_AC_BE	0		/* best effort */
#define	WME_AC_BK	1		/* background */
#define	WME_AC_VI	2		/* video */
#define	WME_AC_VO	3		/* voice */

/*
 * Transmit queue assignment.
 */
enum {
	MWL_WME_AC_BK	= 0,		/* background access category */
	MWL_WME_AC_BE	= 1, 		/* best effort access category */
	MWL_WME_AC_VI	= 2,		/* video access category */
	MWL_WME_AC_VO	= 3,		/* voice access category */
};

const char *mwl_wme_acnames[] = {
	"WME_AC_BE",
	"WME_AC_BK",
	"WME_AC_VI",
	"WME_AC_VO",
	"WME_UPSD",
};

/*
 * Set Antenna Configuration (legacy operation).
 *
 * The RX antenna can be selected using the the bitmask
 * ant (bit 0 = antenna 1, bit 1 = antenna 2, etc.)
 * (diversity?XXX)
 */
typedef enum {
	WL_ANTENNATYPE_RX = 1,
	WL_ANTENNATYPE_TX = 2,
} MWL_HAL_ANTENNA;

/*
 * Set Radio Configuration.
 *
 * onoff != 0 turns radio on; otherwise off.
 * if radio is enabled, the preamble is set too.
 */
typedef enum {
	WL_LONG_PREAMBLE = 1,
	WL_SHORT_PREAMBLE = 3,
	WL_AUTO_PREAMBLE = 5,
} MWL_HAL_PREAMBLE;

/*
 * Transmit rate control.  Rate codes with bit 0x80 set are
 * interpreted as MCS codes (this limits us to 0-127).  The
 * transmit rate can be set to a single fixed rate or can
 * be configured to start at an initial rate and drop based
 * on retry counts.
 */
typedef enum {
	RATE_AUTO	= 0,	/* rate selected by firmware */
	RATE_FIXED	= 2,	/* rate fixed */
	RATE_FIXED_DROP	= 1,	/* rate starts fixed but may drop */
} MWL_HAL_TXRATE_HANDLING;

typedef enum {
	CSMODE_CONSERVATIVE = 0,
	CSMODE_AGGRESSIVE = 1,
	CSMODE_AUTO_ENA = 2,
	CSMODE_AUTO_DIS = 3,
} MWL_HAL_CSMODE;

#pragma pack(1)

/*
 * Device revision information.
 */
typedef struct {
	uint16_t	mh_devid;		/* PCI device ID */
	uint16_t	mh_subvendorid;		/* PCI subvendor ID */
	uint16_t	mh_macRev;		/* MAC revision */
	uint16_t	mh_phyRev;		/* PHY revision */
} MWL_DIAG_REVS;

typedef struct {
	uint16_t freqLow;
	uint16_t freqHigh;
	int nchannels;
	struct mwl_hal_channel {
		uint16_t freq;		/* channel center */
		uint8_t ieee;		/* channel number */
		int8_t maxTxPow;	/* max tx power (dBm) */
		uint8_t targetPowers[4]; /* target powers (dBm) */
#define	MWL_HAL_MAXCHAN	40
	} channels[MWL_HAL_MAXCHAN];
} MWL_HAL_CHANNELINFO;

typedef struct {
    uint32_t	FreqBand : 6,
#define	MWL_FREQ_BAND_2DOT4GHZ	0x1
#define	MWL_FREQ_BAND_5GHZ	0x4
		ChnlWidth: 5,
#define	MWL_CH_10_MHz_WIDTH  	0x1
#define	MWL_CH_20_MHz_WIDTH  	0x2
#define	MWL_CH_40_MHz_WIDTH  	0x4
		ExtChnlOffset: 2,
#define	MWL_EXT_CH_NONE		0x0
#define	MWL_EXT_CH_ABOVE_CTRL_CH 0x1
#define	MWL_EXT_CH_BELOW_CTRL_CH 0x3
		    : 19;		/* reserved */
} MWL_HAL_CHANNEL_FLAGS;

typedef struct {
    uint32_t	channel;
    MWL_HAL_CHANNEL_FLAGS channelFlags;
} MWL_HAL_CHANNEL;

/*
 * Channels are specified by frequency and attributes.
 */
struct mwl_channel {
	uint32_t	ic_flags;	/* see below */
	uint16_t	ic_freq;	/* setting in Mhz */
	uint8_t		ic_ieee;	/* IEEE channel number */
	int8_t		ic_maxregpower;	/* maximum regulatory tx power in dBm */
	int8_t		ic_maxpower;	/* maximum tx power in .5 dBm */
	int8_t		ic_minpower;	/* minimum tx power in .5 dBm */
	uint8_t		ic_state;	/* dynamic state */
	uint8_t		ic_extieee;	/* HT40 extension channel number */
	int8_t		ic_maxantgain;	/* maximum antenna gain in .5 dBm */
	uint8_t		ic_pad;
	uint16_t	ic_devdata;	/* opaque device/driver data */
};

/*
 * Regulatory Information.
 */
struct mwl_regdomain {
	uint16_t	regdomain;	/* SKU */
	uint16_t	country;	/* ISO country code */
	uint8_t		location;	/* I (indoor), O (outdoor), other */
	uint8_t		ecm;		/* Extended Channel Mode */
	char		isocc[2];	/* country code string */
	short		pad[2];
};

/*
 * Get Hardware/Firmware capabilities.
 */
struct mwl_hal_hwspec {
	uint8_t		hwVersion;	/* version of the HW */
	uint8_t		hostInterface;	/* host interface */
	uint16_t	maxNumWCB;	/* max # of WCB FW handles */
	uint16_t	maxNumMCAddr;	/* max # of mcast addresse FW handles */
	uint16_t	maxNumTxWcb;	/* max # of tx descs per WCB */
	uint8_t		macAddr[6];	/* MAC address programmed in HW */
	uint16_t	regionCode;	/* EEPROM region code */
	uint16_t	numAntennas;	/* Number of antenna used */
	uint32_t	fwReleaseNumber; /* firmware release number */
	uint32_t	wcbBase0;
	uint32_t	rxDescRead;
	uint32_t	rxDescWrite;
	uint32_t	ulFwAwakeCookie;
	uint32_t	wcbBase[MWL_NUM_TX_QUEUES - MWL_NUM_ACK_QUEUES];
};

/*
 * Crypto Configuration.
 */
typedef struct {
	uint16_t	pad;
	uint16_t	keyTypeId;
#define	KEY_TYPE_ID_WEP		0
#define	KEY_TYPE_ID_TKIP	1
#define	KEY_TYPE_ID_AES		2	/* AES-CCMP */
	uint32_t	keyFlags;
#define	KEY_FLAG_INUSE		0x00000001	/* indicate key is in use */
#define	KEY_FLAG_RXGROUPKEY	0x00000002	/* Group key for RX only */
#define	KEY_FLAG_TXGROUPKEY	0x00000004	/* Group key for TX */
#define	KEY_FLAG_PAIRWISE	0x00000008	/* pairwise */
#define	KEY_FLAG_RXONLY		0x00000010	/* only used for RX */
#define	KEY_FLAG_AUTHENTICATOR	0x00000020	/* Key is for Authenticator */
#define	KEY_FLAG_TSC_VALID	0x00000040	/* Sequence counters valid */
#define	KEY_FLAG_WEP_TXKEY	0x01000000	/* Tx key for WEP */
#define	KEY_FLAG_MICKEY_VALID	0x02000000	/* Tx/Rx MIC keys are valid */
	uint32_t	keyIndex; 	/* for WEP only; actual key index */
	uint16_t	keyLen;		/* key size in bytes */
	union {			/* key material, keyLen gives size */
		uint8_t	wep[16];	/* enough for 128 bits */
		uint8_t	aes[16];
		struct	{
		    /* NB: group or pairwise key is determined by keyFlags */
		    uint8_t	keyMaterial[16];
		    uint8_t	txMic[8];
		    uint8_t	rxMic[8];
		    struct {
			uint16_t	low;
			uint32_t	high;
		    } rsc;
		struct	{
			uint16_t	low;
			uint32_t	high;
		    } tsc;
		} tkip;
	} key;
} MWL_HAL_KEYVAL;

/*
 * Supply tx/rx dma-related settings to the firmware.
 */
struct mwl_hal_txrxdma {
	uint32_t   maxNumWCB;		/* max # of WCB FW handles */
	uint32_t   maxNumTxWcb;		/* max # of tx descs per WCB */
	uint32_t   rxDescRead;
	uint32_t   rxDescWrite;
	uint32_t   wcbBase[MWL_NUM_TX_QUEUES - MWL_NUM_ACK_QUEUES];
};

/*
 * Inform the firmware of a new association station.
 * The address is the MAC address of the peer station.
 * The AID is supplied sans the 0xc000 bits.  The station
 * ID is defined by the caller.  The peer information must
 * be supplied.
 *
 * NB: All values are in host byte order; any byte swapping
 *     is handled by the hal.
 */
typedef struct {
	uint32_t LegacyRateBitMap;
	uint32_t HTRateBitMap;
	uint16_t CapInfo;
	uint16_t HTCapabilitiesInfo;
	uint8_t	MacHTParamInfo;
	uint8_t	Rev;
	struct {
	    uint8_t ControlChan;
	    uint8_t AddChan;
	    uint8_t OpMode;
	    uint8_t stbc;
	} AddHtInfo;
} MWL_HAL_PEERINFO;

typedef struct {
	uint8_t	McastRate;	/* rate for multicast frames */
#define	RATE_MCS	0x80	/* rate is an MCS index */
	uint8_t	MgtRate;	/* rate for management frames */
	struct {
	    uint8_t TryCount;	/* try this many times */
	    uint8_t Rate;	/* use this tx rate */
	} RateSeries[4];	/* rate series */
} MWL_HAL_TXRATE;

#pragma pack()

/* driver-specific node state */
struct mwl_node {
	struct ieee80211_node	mn_node;	/* base class */
	struct mwl_ant_info	mn_ai;		/* antenna info */
	uint32_t	mn_avgrssi;	/* average rssi over all rx frames */
	uint16_t	mn_staid;	/* firmware station id */
};
#define	MWL_NODE(ni)		((struct mwl_node *)(ni))
#define	MWL_NODE_CONST(ni)	((const struct mwl_node *)(ni))

/*
 * DMA state for tx/rx.
 */

/*
 * Software backed version of tx/rx descriptors.  We keep
 * the software state out of the h/w descriptor structure
 * so that may be allocated in uncached memory w/o paying
 * performance hit.
 */
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

struct mwl_rxbuf {
	struct dma_area		rxbuf_dma;	/* dma area for buf */
	uint32_t		bf_baddr;
	uint8_t			*bf_mem;
	void			*bf_desc;
	uint32_t		bf_daddr;
};

struct mwl_rx_ring {
	struct dma_area		rxdesc_dma;
	uint32_t		physaddr;
	struct mwl_rxdesc	*desc;
	struct mwl_rxbuf	*buf;
	int			count;
	int			cur;
	int			next;
};

struct mwl_txbuf {
	struct dma_area		txbuf_dma;
	uint32_t		bf_baddr;	/* physical addr of buf */
	uint8_t			*bf_mem;
	uint32_t		bf_daddr;	/* physical addr of desc */
	void 			*bf_desc;	/* h/w descriptor */
	int			bf_nseg;
	struct ieee80211_node	*bf_node;
	struct mwl_txq		*bf_txq;	/* backpointer to tx q/ring */
};

struct mwl_tx_ring {
	struct dma_area		txdesc_dma;
	uint32_t		physaddr;
	struct mwl_txdesc	*desc;
	struct mwl_txbuf	*buf;
	int			qnum;	/* f/w q number */
	int			txpri;	/* f/w tx priority */
	int			count;
	int			queued;
	int			cur;
	int			next;
	int			stat;
};

struct mwl_softc {
	ieee80211com_t		sc_ic;
	dev_info_t		*sc_dev;

	/* ddi reg handler */
	ddi_acc_handle_t	sc_cfg_handle;
	caddr_t			sc_cfg_base;

	/* bar0 handler */
	ddi_acc_handle_t	sc_mem_handle;
	caddr_t			sc_mem_base;

	/* bar1 handler */
	ddi_acc_handle_t	sc_io_handle;
	caddr_t			sc_io_base;

	uint16_t		sc_cachelsz;
	uint32_t		sc_dmabuf_size;
	uchar_t			sc_macaddr[6];

	struct dma_area		sc_cmd_dma;
	uint16_t		*sc_cmd_mem;	/* f/w cmd buffer */
	uint32_t		sc_cmd_dmaaddr;	/* physaddr of cmd buffer */

	int			sc_hw_flags;
	uint32_t		sc_flags;

	/* SDRAM addr in the chipset */
	int			sc_SDRAMSIZE_Addr;

	MWL_HAL_CHANNELINFO	sc_20M;
	MWL_HAL_CHANNELINFO	sc_40M;
	MWL_HAL_CHANNELINFO	sc_20M_5G;
	MWL_HAL_CHANNELINFO	sc_40M_5G;

	struct mwl_hal_hwspec	sc_hwspecs;	/* h/w capabilities */
	MWL_DIAG_REVS		sc_revs;

	int			sc_nchans;	/* # entries in ic_channels */
	struct mwl_channel 	sc_channels[IEEE80211_CHAN_MAX];
	struct mwl_channel 	*sc_cur_chan;
	MWL_HAL_CHANNEL		sc_curchan;
	struct mwl_regdomain 	sc_regdomain; /* regulatory data */

	struct mwl_rx_ring	sc_rxring;
	struct mwl_tx_ring	sc_txring[MWL_NUM_TX_QUEUES];
	struct mwl_tx_ring	*sc_ac2q[5];	/* WME AC -> h/w q map */

	struct mwl_hal_txrxdma	sc_hwdma;	/* h/w dma setup */

	/* interrupt */
	ddi_iblock_cookie_t	sc_iblock;
	ddi_softint_handle_t	sc_softintr_hdl;
	ddi_intr_handle_t	*sc_intr_htable;
	uint_t			sc_intr_pri;
	uint32_t		sc_imask;	/* interrupt mask */
	uint32_t		sc_hal_imask;	/* interrupt mask copy */
	uint32_t		sc_rx_pend;

	/* mutex lock */
	kmutex_t		sc_glock;
	kmutex_t		sc_rxlock;
	kmutex_t		sc_txlock;

	uint16_t		sc_rxantenna;	/* rx antenna */
	uint16_t		sc_txantenna;	/* tx antenna */

	timeout_id_t		sc_scan_id;

	/* kstats */
	uint32_t		sc_tx_nobuf;
	uint32_t		sc_rx_nobuf;
	uint32_t		sc_tx_err;
	uint32_t		sc_rx_err;
	uint32_t		sc_tx_retries;

	uint32_t		sc_need_sched;
	uint32_t		sc_rcr;

	int			(*sc_newstate)(struct ieee80211com *,
				    enum ieee80211_state, int);
};

#define	mwl_mem_write4(sc, off, x) \
	ddi_put32((sc)->sc_mem_handle, \
	(uint32_t *)((sc)->sc_mem_base + (off)), x)

#define	mwl_mem_read4(sc, off) \
	ddi_get32((sc)->sc_mem_handle, \
	(uint32_t *)((sc)->sc_mem_base + (off)))

#define	mwl_ctl_write4(sc, off, x) \
	ddi_put32((sc)->sc_io_handle, \
	(uint32_t *)((sc)->sc_io_base + (off)), x)

#define	mwl_ctl_read4(sc, off) \
	ddi_get32((sc)->sc_io_handle, \
	(uint32_t *)((sc)->sc_io_base + (off)))

#define	mwl_ctl_read1(sc, off) \
	ddi_get8((sc)->sc_io_handle, \
	(uint8_t *)((sc)->sc_io_base + (off)))

#define	_CMD_SETUP(pCmd, type, cmd) do {				\
	pCmd = (type *)&sc->sc_cmd_mem[0];				\
	(void) memset(pCmd, 0, sizeof (type));				\
	pCmd->CmdHdr.Cmd = LE_16(cmd);					\
	pCmd->CmdHdr.Length = LE_16(sizeof (type));			\
	_NOTE(CONSTCOND)						\
} while (0)

#define	_VCMD_SETUP(pCmd, type, cmd) do {				\
	_CMD_SETUP(pCmd, type, cmd);					\
	pCmd->CmdHdr.MacId = 8;						\
	_NOTE(CONSTCOND)						\
} while (0)

#define	MWL_GLOCK(_sc)		mutex_enter(&(_sc)->sc_glock)
#define	MWL_GUNLOCK(_sc)	mutex_exit(&(_sc)->sc_glock)

#define	MWL_RXLOCK(_sc)		mutex_enter(&(_sc)->sc_rxlock)
#define	MWL_RXUNLOCK(_sc)	mutex_exit(&(_sc)->sc_rxlock)

#define	MWL_TXLOCK(_sc)		mutex_enter(&(_sc)->sc_txlock)
#define	MWL_TXUNLOCK(_sc)	mutex_exit(&(_sc)->sc_txlock)

#define	MWL_F_RUNNING		(1 << 0)
#define	MWL_F_SUSPEND		(1 << 1)
#define	MWL_F_QUIESCE		(1 << 2)

#define	MWL_RCR_PROMISC		(1 << 0)
#define	MWL_RCR_MULTI		(1 << 1)

#define	MWL_IS_RUNNING(_sc)	(((_sc)->sc_flags & MWL_F_RUNNING))
#define	MWL_IS_SUSPEND(_sc)	(((_sc)->sc_flags & MWL_F_SUSPEND))
#define	MWL_IS_QUIESCE(_sc)	(((_sc)->sc_flags & MWL_F_QUIESCE))

/*
 * 802.11 regulatory domain definitions.
 */
enum ISOCountryCode {
	CTRY_AFGHANISTAN	= 4,
	CTRY_ALBANIA		= 8,	/* Albania */
	CTRY_ALGERIA		= 12,	/* Algeria */
	CTRY_AMERICAN_SAMOA	= 16,
	CTRY_ANDORRA		= 20,
	CTRY_ANGOLA		= 24,
	CTRY_ANGUILLA		= 660,
	CTRY_ANTARTICA		= 10,
	CTRY_ANTIGUA		= 28,	/* Antigua and Barbuda */
	CTRY_ARGENTINA		= 32,	/* Argentina */
	CTRY_ARMENIA		= 51,	/* Armenia */
	CTRY_ARUBA		= 533,	/* Aruba */
	CTRY_AUSTRALIA		= 36,	/* Australia */
	CTRY_AUSTRIA		= 40,	/* Austria */
	CTRY_AZERBAIJAN		= 31,	/* Azerbaijan */
	CTRY_BAHAMAS		= 44,	/* Bahamas */
	CTRY_BAHRAIN		= 48,	/* Bahrain */
	CTRY_BANGLADESH		= 50,	/* Bangladesh */
	CTRY_BARBADOS		= 52,
	CTRY_BELARUS		= 112,	/* Belarus */
	CTRY_BELGIUM		= 56,	/* Belgium */
	CTRY_BELIZE		= 84,
	CTRY_BENIN		= 204,
	CTRY_BERMUDA		= 60,
	CTRY_BHUTAN		= 64,
	CTRY_BOLIVIA		= 68,	/* Bolivia */
	CTRY_BOSNIA_AND_HERZEGOWINA = 70,
	CTRY_BOTSWANA		= 72,
	CTRY_BOUVET_ISLAND	= 74,
	CTRY_BRAZIL		= 76,	/* Brazil */
	CTRY_BRITISH_INDIAN_OCEAN_TERRITORY = 86,
	CTRY_BRUNEI_DARUSSALAM	= 96,	/* Brunei Darussalam */
	CTRY_BULGARIA		= 100,	/* Bulgaria */
	CTRY_BURKINA_FASO	= 854,
	CTRY_BURUNDI		= 108,
	CTRY_CAMBODIA		= 116,
	CTRY_CAMEROON		= 120,
	CTRY_CANADA		= 124,	/* Canada */
	CTRY_CAPE_VERDE		= 132,
	CTRY_CAYMAN_ISLANDS	= 136,
	CTRY_CENTRAL_AFRICAN_REPUBLIC = 140,
	CTRY_CHAD		= 148,
	CTRY_CHILE		= 152,	/* Chile */
	CTRY_CHINA		= 156,	/* People's Republic of China */
	CTRY_CHRISTMAS_ISLAND	= 162,
	CTRY_COCOS_ISLANDS	= 166,
	CTRY_COLOMBIA		= 170,	/* Colombia */
	CTRY_COMOROS		= 174,
	CTRY_CONGO		= 178,
	CTRY_COOK_ISLANDS	= 184,
	CTRY_COSTA_RICA		= 188,	/* Costa Rica */
	CTRY_COTE_DIVOIRE	= 384,
	CTRY_CROATIA		= 191,	/* Croatia (local name: Hrvatska) */
	CTRY_CYPRUS		= 196,	/* Cyprus */
	CTRY_CZECH		= 203,	/* Czech Republic */
	CTRY_DENMARK		= 208,	/* Denmark */
	CTRY_DJIBOUTI		= 262,
	CTRY_DOMINICA		= 212,
	CTRY_DOMINICAN_REPUBLIC	= 214,	/* Dominican Republic */
	CTRY_EAST_TIMOR		= 626,
	CTRY_ECUADOR		= 218,	/* Ecuador */
	CTRY_EGYPT		= 818,	/* Egypt */
	CTRY_EL_SALVADOR	= 222,	/* El Salvador */
	CTRY_EQUATORIAL_GUINEA	= 226,
	CTRY_ERITREA		= 232,
	CTRY_ESTONIA		= 233,	/* Estonia */
	CTRY_ETHIOPIA		= 210,
	CTRY_FALKLAND_ISLANDS	= 238,	/* (Malvinas) */
	CTRY_FAEROE_ISLANDS	= 234,	/* Faeroe Islands */
	CTRY_FIJI		= 242,
	CTRY_FINLAND		= 246,	/* Finland */
	CTRY_FRANCE		= 250,	/* France */
	CTRY_FRANCE2		= 255,	/* France (Metropolitan) */
	CTRY_FRENCH_GUIANA	= 254,
	CTRY_FRENCH_POLYNESIA	= 258,
	CTRY_FRENCH_SOUTHERN_TERRITORIES	= 260,
	CTRY_GABON		= 266,
	CTRY_GAMBIA		= 270,
	CTRY_GEORGIA		= 268,	/* Georgia */
	CTRY_GERMANY		= 276,	/* Germany */
	CTRY_GHANA		= 288,
	CTRY_GIBRALTAR		= 292,
	CTRY_GREECE		= 300,	/* Greece */
	CTRY_GREENLAND		= 304,
	CTRY_GRENADA		= 308,
	CTRY_GUADELOUPE		= 312,
	CTRY_GUAM		= 316,
	CTRY_GUATEMALA		= 320,	/* Guatemala */
	CTRY_GUINEA		= 324,
	CTRY_GUINEA_BISSAU	= 624,
	CTRY_GUYANA		= 328,
	/* XXX correct remainder */
	CTRY_HAITI		= 332,
	CTRY_HONDURAS		= 340,	/* Honduras */
	CTRY_HONG_KONG		= 344,	/* Hong Kong S.A.R., P.R.C. */
	CTRY_HUNGARY		= 348,	/* Hungary */
	CTRY_ICELAND		= 352,	/* Iceland */
	CTRY_INDIA		= 356,	/* India */
	CTRY_INDONESIA		= 360,	/* Indonesia */
	CTRY_IRAN		= 364,	/* Iran */
	CTRY_IRAQ		= 368,	/* Iraq */
	CTRY_IRELAND		= 372,	/* Ireland */
	CTRY_ISRAEL		= 376,	/* Israel */
	CTRY_ITALY		= 380,	/* Italy */
	CTRY_JAMAICA		= 388,	/* Jamaica */
	CTRY_JAPAN		= 392,	/* Japan */
	CTRY_JORDAN		= 400,	/* Jordan */
	CTRY_KAZAKHSTAN		= 398,	/* Kazakhstan */
	CTRY_KENYA		= 404,	/* Kenya */
	CTRY_KOREA_NORTH	= 408,	/* North Korea */
	CTRY_KOREA_ROC		= 410,	/* South Korea */
	CTRY_KOREA_ROC2		= 411,	/* South Korea */
	CTRY_KUWAIT		= 414,	/* Kuwait */
	CTRY_LATVIA		= 428,	/* Latvia */
	CTRY_LEBANON		= 422,	/* Lebanon */
	CTRY_LIBYA		= 434,	/* Libya */
	CTRY_LIECHTENSTEIN	= 438,	/* Liechtenstein */
	CTRY_LITHUANIA		= 440,	/* Lithuania */
	CTRY_LUXEMBOURG		= 442,	/* Luxembourg */
	CTRY_MACAU		= 446,	/* Macau */
	CTRY_MACEDONIA		= 807,	/* Macedonia */
	CTRY_MALAYSIA		= 458,	/* Malaysia */
	CTRY_MALTA		= 470,	/* Malta */
	CTRY_MEXICO		= 484,	/* Mexico */
	CTRY_MONACO		= 492,	/* Principality of Monaco */
	CTRY_MOROCCO		= 504,	/* Morocco */
	CTRY_NEPAL		= 524,	/* Nepal */
	CTRY_NETHERLANDS	= 528,	/* Netherlands */
	CTRY_NEW_ZEALAND	= 554,	/* New Zealand */
	CTRY_NICARAGUA		= 558,	/* Nicaragua */
	CTRY_NORWAY		= 578,	/* Norway */
	CTRY_OMAN		= 512,	/* Oman */
	CTRY_PAKISTAN		= 586,	/* Islamic Republic of Pakistan */
	CTRY_PANAMA		= 591,	/* Panama */
	CTRY_PARAGUAY		= 600,	/* Paraguay */
	CTRY_PERU		= 604,	/* Peru */
	CTRY_PHILIPPINES	= 608,	/* Republic of the Philippines */
	CTRY_POLAND		= 616,	/* Poland */
	CTRY_PORTUGAL		= 620,	/* Portugal */
	CTRY_PUERTO_RICO	= 630,	/* Puerto Rico */
	CTRY_QATAR		= 634,	/* Qatar */
	CTRY_ROMANIA		= 642,	/* Romania */
	CTRY_RUSSIA		= 643,	/* Russia */
	CTRY_SAUDI_ARABIA	= 682,	/* Saudi Arabia */
	CTRY_SINGAPORE		= 702,	/* Singapore */
	CTRY_SLOVAKIA		= 703,	/* Slovak Republic */
	CTRY_SLOVENIA		= 705,	/* Slovenia */
	CTRY_SOUTH_AFRICA	= 710,	/* South Africa */
	CTRY_SPAIN		= 724,	/* Spain */
	CTRY_SRILANKA		= 144,	/* Sri Lanka */
	CTRY_SWEDEN		= 752,	/* Sweden */
	CTRY_SWITZERLAND	= 756,	/* Switzerland */
	CTRY_SYRIA		= 760,	/* Syria */
	CTRY_TAIWAN		= 158,	/* Taiwan */
	CTRY_THAILAND		= 764,	/* Thailand */
	CTRY_TRINIDAD_Y_TOBAGO	= 780,	/* Trinidad y Tobago */
	CTRY_TUNISIA		= 788,	/* Tunisia */
	CTRY_TURKEY		= 792,	/* Turkey */
	CTRY_UAE		= 784,	/* U.A.E. */
	CTRY_UKRAINE		= 804,	/* Ukraine */
	CTRY_UNITED_KINGDOM	= 826,	/* United Kingdom */
	CTRY_UNITED_STATES	= 840,	/* United States */
	CTRY_URUGUAY		= 858,	/* Uruguay */
	CTRY_UZBEKISTAN		= 860,	/* Uzbekistan */
	CTRY_VENEZUELA		= 862,	/* Venezuela */
	CTRY_VIET_NAM		= 704,	/* Viet Nam */
	CTRY_YEMEN		= 887,	/* Yemen */
	CTRY_ZIMBABWE		= 716,	/* Zimbabwe */

	/* NB: from here down not listed in 3166; they come from Atheros */
	CTRY_DEBUG		= 0x1ff, /* debug */
	CTRY_DEFAULT		= 0,	 /* default */

	CTRY_UNITED_STATES_FCC49 = 842,	/* United States (Public Safety) */
	CTRY_KOREA_ROC3		= 412,	/* South Korea */

	CTRY_JAPAN1		= 393,	/* Japan (JP1) */
	CTRY_JAPAN2		= 394,	/* Japan (JP0) */
	CTRY_JAPAN3		= 395,	/* Japan (JP1-1) */
	CTRY_JAPAN4		= 396,	/* Japan (JE1) */
	CTRY_JAPAN5		= 397,	/* Japan (JE2) */
	CTRY_JAPAN6		= 399,	/* Japan (JP6) */
	CTRY_JAPAN7		= 4007,	/* Japan (J7) */
	CTRY_JAPAN8		= 4008,	/* Japan (J8) */
	CTRY_JAPAN9		= 4009,	/* Japan (J9) */
	CTRY_JAPAN10		= 4010,	/* Japan (J10) */
	CTRY_JAPAN11		= 4011,	/* Japan (J11) */
	CTRY_JAPAN12		= 4012,	/* Japan (J12) */
	CTRY_JAPAN13		= 4013,	/* Japan (J13) */
	CTRY_JAPAN14		= 4014,	/* Japan (J14) */
	CTRY_JAPAN15		= 4015,	/* Japan (J15) */
	CTRY_JAPAN16		= 4016,	/* Japan (J16) */
	CTRY_JAPAN17		= 4017,	/* Japan (J17) */
	CTRY_JAPAN18		= 4018,	/* Japan (J18) */
	CTRY_JAPAN19		= 4019,	/* Japan (J19) */
	CTRY_JAPAN20		= 4020,	/* Japan (J20) */
	CTRY_JAPAN21		= 4021,	/* Japan (J21) */
	CTRY_JAPAN22		= 4022,	/* Japan (J22) */
	CTRY_JAPAN23		= 4023,	/* Japan (J23) */
	CTRY_JAPAN24		= 4024,	/* Japan (J24) */
};

enum RegdomainCode {
	SKU_FCC			= 0x10,	/* FCC, aka United States */
	SKU_CA			= 0x20,	/* North America, aka Canada */
	SKU_ETSI		= 0x30,	/* Europe */
	SKU_ETSI2		= 0x32,	/* Europe w/o HT40 in 5GHz */
	SKU_ETSI3		= 0x33,	/* Europe - channel 36 */
	SKU_FCC3		= 0x3a,	/* FCC w/5470 band, 11h, DFS */
	SKU_JAPAN		= 0x40,
	SKU_KOREA		= 0x45,
	SKU_APAC		= 0x50,	/* Asia Pacific */
	SKU_APAC2		= 0x51,	/* Asia Pacific w/ DFS on mid-band */
	SKU_APAC3		= 0x5d,	/* Asia Pacific w/o ISM band */
	SKU_ROW			= 0x81,	/* China/Taiwan/Rest of World */
	SKU_NONE		= 0xf0,	/* "Region Free" */
	SKU_DEBUG		= 0x1ff,

	/* NB: from here down private */
	SKU_SR9			= 0x0298, /* Ubiquiti SR9 (900MHz/GSM) */
	SKU_XR9			= 0x0299, /* Ubiquiti XR9 (900MHz/GSM) */
	SKU_GZ901		= 0x029a, /* Zcomax GZ-901 (900MHz/GSM) */
};

/*
 * Set regdomain code (IEEE SKU).
 */
enum {
	DOMAIN_CODE_FCC		= 0x10,	/* USA */
	DOMAIN_CODE_IC		= 0x20,	/* Canda */
	DOMAIN_CODE_ETSI	= 0x30,	/* Europe */
	DOMAIN_CODE_SPAIN	= 0x31,	/* Spain */
	DOMAIN_CODE_FRANCE	= 0x32,	/* France */
	DOMAIN_CODE_ETSI_131	= 0x130, /* ETSI w/ 1.3.1 radar type */
	DOMAIN_CODE_MKK		= 0x40,	/* Japan */
	DOMAIN_CODE_MKK2	= 0x41,	/* Japan w/ 10MHz chan spacing */
	DOMAIN_CODE_DGT		= 0x80,	/* Taiwan */
	DOMAIN_CODE_AUS		= 0x81,	/* Australia */
};


#ifdef __cplusplus
}
#endif

#endif /* _MWL_VAR_H */
