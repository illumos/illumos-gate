/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2008 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
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

#ifndef _ARN_CORE_H
#define	_ARN_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/note.h>
#include <sys/list.h>
#include <sys/net80211.h>

#include "arn_ath9k.h"
#include "arn_rc.h"

struct ath_node;

/*
 * Node type of wifi device
 */
#ifndef DDI_NT_NET_WIFI
#define	DDI_NT_NET_WIFI	"ddi_network:wifi"
#endif
#define	ARN_NODENAME	"arn"

#define	ARN_LOCK(_sc)		mutex_enter(&(_sc)->sc_genlock)
#define	ARN_UNLOCK(_sc)	mutex_exit(&(_sc)->sc_genlock)
#define	ARN_LOCK_ASSERT(_sc)	ASSERT(mutex_owned(&(_sc)->sc_genlock))

#define	ARRAY_SIZE(x)	(sizeof (x) / sizeof (x[0]))

#define	DIV_ROUND_UP(n, d)	(((n) + (d) - 1) / (d))

#define	ARN_MIN(a, b)	((a) < (b) ? (a) : (b))
#define	ARN_MAX(a, b)	((a) > (b) ? (a) : (b))

#define	abs(x)		((x) >= 0 ? (x) : -(x))

enum ath9k_key_len {
	ATH9K_LEN_WEP40 = 5,
	ATH9K_LEN_WEP104 = 13,
};

/*
 * Sync a DMA area described by a dma_area_t
 */
#define	ARN_DMA_SYNC(area, flag)    ((void) ddi_dma_sync((area).dma_hdl,    \
				(area).offset, (area).alength, (flag)))

#define	list_empty(a) ((a)->list_head.list_next == &(a)->list_head)
#define	list_d2l(a, obj) ((list_node_t *)(((char *)obj) + (a)->list_offset))
#define	list_object(a, node) ((void *)(((char *)node) - (a)->list_offset))
#define	list_entry(ptr, type, member)	\
	((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))
#define	list_is_last(node, list)	\
	((node)->list_next == &(list)->list_head)

#define	list_for_each_entry_safe(object, temp, list_t)	\
	for (object = list_head(list_t),	\
	temp = list_object((list_t), ((list_d2l(list_t, object))->list_next));\
	((list_d2l(list_t, temp))->list_next) != &((list_t)->list_head);\
	object = temp,	\
	temp = list_object((list_t), (list_d2l(list_t, temp))->list_next))

/*
 *  Insert src list after dst list. reinitialize src list thereafter.
 */
static __inline__ void
/* LINTED E_STATIC_UNUSED */
list_splice_tail_init(list_t *dst, list_t *src)
{
	list_node_t *dstnode = &dst->list_head;
	list_node_t *srcnode = &src->list_head;

	ASSERT(dst->list_size == src->list_size);
	ASSERT(dst->list_offset == src->list_offset);

	if (list_empty(src))
		return;

	dstnode->list_prev->list_next = srcnode->list_next;
	srcnode->list_next->list_prev = dstnode->list_prev;
	dstnode->list_prev = srcnode->list_prev;
	srcnode->list_prev->list_next = dstnode;

	/* reinitialize src list */
	srcnode->list_next = srcnode->list_prev = srcnode;
}

#define	ARN_LE_READ_16(p)						\
	((uint16_t)							\
	((((uint8_t *)(p))[0]) | (((uint8_t *)(p))[1] <<  8)))

#define	ARN_LE_READ_32(p)						\
	((uint32_t)							\
	((((uint8_t *)(p))[0]) | (((uint8_t *)(p))[1] <<  8) |		\
	(((uint8_t *)(p))[2] << 16) | (((uint8_t *)(p))[3] << 24)))

#define	swab16(value)  \
	((((value) & 0xff) << 8) | ((value) >> 8))

#define	swab32(value)	\
	(((uint32_t)swab16((uint16_t)((value) & 0xffff)) << 16) | \
	(uint32_t)swab16((uint16_t)((value) >> 16)))

#define	swab64(value)	\
	(((uint64_t)swab32((uint32_t)((value) & 0xffffffff)) \
	    << 32) | \
	(uint64_t)swab32((uint32_t)((value) >> 32)))

/* Bit map related macros. */
#define	set_bit(i, a)		((a)[(i)/NBBY] |= (1 << ((i)%NBBY)))
#define	clr_bit(i, a)		((a)[(i)/NBBY] &= ~(1 << ((i)%NBBY)))
#define	is_set(i, a)		((a)[(i)/NBBY] & (1 << ((i)%NBBY)))
#define	is_clr(i, a)		(!((a)[(i)/NBBY] & (1 << ((i)%NBBY))))

/* Macro to expand scalars to 64-bit objects */

#define	ito64(x) (sizeof (x) == 8) ?			\
	(((unsigned long long int)(x)) & (0xff)) :	\
	(sizeof (x) == 16) ?				\
	(((unsigned long long int)(x)) & 0xffff) :	\
	((sizeof (x) == 32) ?				\
	(((unsigned long long int)(x)) & 0xffffffff) :	\
	(unsigned long long int)(x))

/* increment with wrap-around */
#define	INCR(_l, _sz)	do {			\
		(_l)++;				\
		(_l) &= ((_sz) - 1);		\
	} while (0)

/* decrement with wrap-around */
#define	DECR(_l, _sz)  do {			\
		(_l)--;				\
		(_l) &= ((_sz) - 1);		\
	} while (0)

#define	A_MAX(a, b)	((a) > (b) ? (a) : (b))

#define	TSF_TO_TU(_h, _l)	\
	((((uint32_t)(_h)) << 22) | (((uint32_t)(_l)) >> 10))

#define	ARN_TXQ_SETUP(sc, i)	((sc)->sc_txqsetup & (1<<i))

#define	IEEE80211_IS_CHAN_HTA(_c) \
	(IEEE80211_IS_CHAN_5GHZ(_c) && \
	((_c)->ich_flags & IEEE80211_CHAN_HT))

#define	IEEE80211_IS_CHAN_HTG(_c) \
	(IEEE80211_IS_CHAN_2GHZ(_c) && \
	((_c)->ich_flags & IEEE80211_CHAN_HT))

#define	IEEE80211_IS_DATA(_wh) \
	(((_wh)->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == \
	IEEE80211_FC0_TYPE_DATA)

#define	IEEE80211_IS_DATA_QOS(_wh) \
	(((_wh)->i_fc[0] & (IEEE80211_FC0_TYPE_MASK | \
	IEEE80211_FC0_SUBTYPE_QOS)) == \
	(IEEE80211_FC0_TYPE_DATA | IEEE80211_FC0_SUBTYPE_QOS))

#define	IEEE80211_IS_MGMT(_wh) \
	(((_wh)->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == \
	IEEE80211_FC0_TYPE_MGT)

#define	IEEE80211_IS_CTL(_wh) \
	(((_wh)->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == \
	IEEE80211_FC0_TYPE_CTL)

#define	IEEE80211_IS_PSPOLL(_wh) \
	(((_wh)->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == \
	IEEE80211_FC0_SUBTYPE_PS_POLL)

#define	IEEE80211_IS_BACK_REQ(_wh) \
	(((_wh)->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) == \
	IEEE80211_FC0_SUBTYPE_BAR)

#define	IEEE80211_HAS_MOREFRAGS(_wh) \
	(((_wh)->i_fc[1] & IEEE80211_FC1_MORE_FRAG) == \
	IEEE80211_FC1_MORE_FRAG)

/* Debugging */
enum ARN_DEBUG {
	ARN_DBG_HW		= 0x00000001,
	ARN_DBG_REG_IO		= 0x00000002,
	ARN_DBG_QUEUE		= 0x00000004,
	ARN_DBG_EEPROM		= 0x00000008,
	ARN_DBG_XMIT		= 0x00000010,
	ARN_DBG_RECV		= 0x00000020,
	ARN_DBG_CALIBRATE	= 0x00000040,
	ARN_DBG_CHANNEL		= 0x00000080,
	ARN_DBG_INTERRUPT	= 0x00000100,
	ARN_DBG_REGULATORY	= 0x00000200,
	ARN_DBG_ANI		= 0x00000400,
	ARN_DBG_POWER_MGMT	= 0x00000800,
	ARN_DBG_KEYCACHE	= 0x00001000,
	ARN_DBG_BEACON		= 0x00002000,
	ARN_DBG_RATE		= 0x00004000,
	ARN_DBG_INIT		= 0x00008000,
	ARN_DBG_ATTACH		= 0x00010000,
	ARN_DBG_DEATCH		= 0x00020000,
	ARN_DBG_AGGR		= 0x00040000,
	ARN_DBG_RESET		= 0x00080000,
	ARN_DBG_FATAL		= 0x00100000,
	ARN_DBG_ANY		= 0x00200000,
	ARN_DBG_ALL		= 0x00FFFFFF,
};

/* Debug and log functions */
void arn_dbg(uint32_t dbg_flags, const int8_t *fmt, ...); /* debug function */
void arn_log(const int8_t *fmt, ...); /* event log function */
void arn_problem(const int8_t *fmt, ...); /* run-time problem function */

#ifdef DEBUG
#define	ARN_DDB(command)	do {				\
					{ command; }		\
					_NOTE(CONSTANTCONDITION)\
				} while (0)
#else
#define	ARN_DDB(command)
#endif /* DEBUG */

#define	ARN_DBG(args)		ARN_DDB(arn_dbg args)

struct ath_stats {
	uint32_t	ast_hardware;	/* fatal hardware error interrupts */
	uint32_t	ast_rxorn;	/* rx overrun interrupts */
	uint32_t	ast_rxeol;	/* rx eol interrupts */
	uint32_t	ast_txurn;	/* tx underrun interrupts */
	uint32_t	ast_tx_mgmt;	/* management frames transmitted */
	uint32_t	ast_tx_discard;	/* frames discarded prior to assoc */
	uint32_t	ast_tx_invalid; /* frames discarded 'cuz device gone */
	uint32_t	ast_tx_qstop;	/* tx queue stopped 'cuz full */
	uint32_t	ast_tx_nobuf;	/* tx failed 'cuz no tx buffer (data) */
	uint32_t	ast_tx_nobufmgt; /* tx failed 'cuz no tx buffer(mgmt) */
	uint32_t	ast_tx_xretries; /* tx failed 'cuz too many retries */
	uint32_t	ast_tx_fifoerr;	/* tx failed 'cuz FIFO underrun */
	uint32_t	ast_tx_filtered; /* tx failed 'cuz xmit filtered */
	uint32_t	ast_tx_shortretry; /* tx on-chip retries (short) */
	uint32_t	ast_tx_longretry; /* tx on-chip retries (long) */
	uint32_t	ast_tx_noack;	/* tx frames with no ack marked */
	uint32_t	ast_tx_rts;	/* tx frames with rts enabled */
	uint32_t	ast_tx_shortpre; /* tx frames with short preamble */
	uint32_t	ast_tx_altrate;	/* tx frames with alternate rate */
	uint32_t	ast_tx_protect;	/* tx frames with protection */
	int16_t		ast_tx_rssi;	/* tx rssi of last ack */
	int16_t		ast_tx_rssidelta; /* tx rssi delta */
	uint32_t	ast_rx_crcerr;	/* rx failed 'cuz of bad CRC */
	uint32_t	ast_rx_fifoerr;	/* rx failed 'cuz of FIFO overrun */
	uint32_t	ast_rx_badcrypt; /* rx failed 'cuz decryption */
	uint32_t	ast_rx_phyerr;	/* rx PHY error summary count */
	uint32_t	ast_rx_phy[32];	/* rx PHY error per-code counts */
	uint32_t	ast_rx_tooshort; /* rx discarded 'cuz frame too short */
	uint32_t	ast_per_cal;	/* periodic calibration calls */
	uint32_t	ast_per_calfail; /* periodic calibration failed */
	uint32_t	ast_per_rfgain;	/* periodic calibration rfgain reset */
	uint32_t	ast_rate_calls;	/* rate control checks */
	uint32_t	ast_rate_raise;	/* rate control raised xmit rate */
	uint32_t	ast_rate_drop;	/* rate control dropped xmit rate */
};

struct dma_area {
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
};
typedef struct dma_area dma_area_t;

/* Load-time Configuration */

/*
 * Per-instance load-time (note: NOT run-time)
 * configurations for Atheros Device
 */
struct ath_config {
	uint32_t ath_aggr_prot;
	uint16_t txpowlimit;
	uint16_t txpowlimit_override;
	uint8_t cabqReadytime; /* Cabq Readytime % */
	uint8_t swBeaconProcess; /* Process received beacons in SW (vs HW) */
};

/* Descriptor Management */

#define	ATH_TXBUF_RESET(_bf) do {		\
		(_bf)->bf_status = 0;		\
		(_bf)->bf_lastbf = NULL;	\
		(_bf)->bf_lastfrm = NULL;	\
		(_bf)->bf_next = NULL;		\
		(void) memset(&((_bf)->bf_state), 0,	\
		sizeof (struct ath_buf_state));	\
		(void) memset(&((_bf)->tx_info_priv), 0,	\
		sizeof (struct ath_tx_info_priv));	\
		_NOTE(CONSTCOND) \
	} while (0)

enum buffer_type {
	BUF_DATA		= BIT(0),
	BUF_AGGR		= BIT(1),
	BUF_AMPDU		= BIT(2),
	BUF_HT			= BIT(3),
	BUF_RETRY		= BIT(4),
	BUF_XRETRY		= BIT(5),
	BUF_SHORT_PREAMBLE	= BIT(6),
	BUF_BAR			= BIT(7),
	BUF_PSPOLL		= BIT(8),
	BUF_AGGR_BURST		= BIT(9),
	BUF_CALC_AIRTIME	= BIT(10),
};

struct ath_buf_state {
	int bfs_nframes;	/* # frames in aggregate */
	uint16_t bfs_al;	/* length of aggregate */
	uint16_t bfs_frmlen;	/* length of frame */
	int bfs_seqno;		/* sequence number */
	int bfs_tidno;		/* tid of this frame */
	int bfs_retries;	/* current retries */
	uint32_t bf_type;	/* BUF_* (enum buffer_type) */
	/* key type used to encrypt this frame */
	uint32_t bfs_keyix;
	enum ath9k_key_type bfs_keytype;
};

#define	bf_nframes		bf_state.bfs_nframes
#define	bf_al			bf_state.bfs_al
#define	bf_frmlen		bf_state.bfs_frmlen
#define	bf_retries		bf_state.bfs_retries
#define	bf_seqno		bf_state.bfs_seqno
#define	bf_tidno		bf_state.bfs_tidno
#define	bf_rcs			bf_state.bfs_rcs
#define	bf_keyix		bf_state.bfs_keyix
#define	bf_keytype		bf_state.bfs_keytype
#define	bf_isdata(bf)		(bf->bf_state.bf_type & BUF_DATA)
#define	bf_isaggr(bf)		(bf->bf_state.bf_type & BUF_AGGR)
#define	bf_isampdu(bf)		(bf->bf_state.bf_type & BUF_AMPDU)
#define	bf_isht(bf)		(bf->bf_state.bf_type & BUF_HT)
#define	bf_isretried(bf)	(bf->bf_state.bf_type & BUF_RETRY)
#define	bf_isxretried(bf)	(bf->bf_state.bf_type & BUF_XRETRY)
#define	bf_isshpreamble(bf)	(bf->bf_state.bf_type & BUF_SHORT_PREAMBLE)
#define	bf_isbar(bf)		(bf->bf_state.bf_type & BUF_BAR)
#define	bf_ispspoll(bf)		(bf->bf_state.bf_type & BUF_PSPOLL)
#define	bf_isaggrburst(bf)	(bf->bf_state.bf_type & BUF_AGGR_BURST)

/*
 * Abstraction of a contiguous buffer to transmit/receive.
 * There is only a single hw descriptor encapsulated here.
 */
struct ath_buf {
	/* last buf of this unit (a frame or an aggregate) */
	struct ath_buf *bf_lastbf;
	struct ath_buf *bf_lastfrm;	/* last buf of this frame */
	struct ath_buf *bf_next;	/* next subframe in the aggregate */
	mblk_t *bf_m;
	struct ath_desc	*bf_desc;	/* virtual addr of desc */
	uint32_t bf_daddr;		/* physical addr of desc */
	dma_area_t bf_dma;		/* dma area for buf */
	struct ieee80211_node *bf_in;	/* pointer to the node */
	uint32_t bf_status;
	uint16_t bf_flags;		/* tx descriptor flags */
	struct ath_buf_state bf_state;	/* buffer state */

	/* Temp workground for rc */
	struct ath9k_tx_rate rates[4];
	struct ath_tx_info_priv tx_info_priv;

	/* we're in list of sc->sc_txbuf_list or sc->sc_rxbuf_list */
	list_node_t bf_node;
};

/*
 * reset the rx buffer.
 * any new fields added to the athbuf and require
 * reset need to be added to this macro.
 * currently bf_status is the only one requires that
 * requires reset.
 */
#define	ATH_RXBUF_RESET(_bf)	((_bf)->bf_status = 0)

/* hw processing complete, desc processed by hal */
#define	ATH_BUFSTATUS_DONE	0x00000001
/* hw processing complete, desc hold for hw */
#define	ATH_BUFSTATUS_STALE	0x00000002
/* Rx-only: OS is done with this packet and it's ok to queued it to hw */
#define	ATH_BUFSTATUS_FREE	0x00000004

/* RX / TX */

#define	ATH_MAX_ANTENNA	3
#define	ATH_RXBUF	512
#define	WME_NUM_TID	16

void arn_rx_buf_link(struct arn_softc *sc, struct ath_buf *bf);
int arn_startrecv(struct arn_softc *sc);
boolean_t arn_stoprecv(struct arn_softc *sc);
void arn_flushrecv(struct arn_softc *sc);
uint32_t arn_calcrxfilter(struct arn_softc *sc);
int arn_rx_init(struct arn_softc *sc, int nbufs);
void arn_rx_cleanup(struct arn_softc *sc);
uint_t arn_softint_handler(caddr_t data);
void arn_setdefantenna(struct arn_softc *sc, uint32_t antenna);

#define	ATH_TXBUF	512
/* max number of transmit attempts (tries) */
#define	ATH_TXMAXTRY	13
/* max number of 11n transmit attempts (tries) */
#define	ATH_11N_TXMAXTRY	10
/* max number of tries for management and control frames */
#define	ATH_MGT_TXMAXTRY	4
#define	WME_BA_BMP_SIZE		64
#define	WME_MAX_BA		WME_BA_BMP_SIZE
#define	ATH_TID_MAX_BUFS	(2 * WME_MAX_BA)

/* Wireless Multimedia Extension Defines */
#define	WME_AC_BE	0 /* best effort */
#define	WME_AC_BK	1 /* background */
#define	WME_AC_VI	2 /* video */
#define	WME_AC_VO	3 /* voice */
#define	WME_NUM_AC	4

/*
 * Data transmit queue state.  One of these exists for each
 * hardware transmit queue.  Packets sent to us from above
 * are assigned to queues based on their priority.  Not all
 * devices support a complete set of hardware transmit queues.
 * For those devices the array sc_ac2q will map multiple
 * priorities to fewer hardware queues (typically all to one
 * hardware queue).
 */

struct ath_txq {
	uint32_t	axq_qnum; /* hardware q number */
	uint32_t	*axq_link; /* link ptr in last TX desc */
	list_t		axq_list; /* transmit queue */
	kmutex_t	axq_lock; /* lock on q and link */
	unsigned long	axq_lockflags; /* intr state when must cli */
	uint32_t		axq_depth; /* queue depth (stat only) */
	uint8_t 	axq_aggr_depth; /* aggregates queued */
	uint32_t 	axq_totalqueued; /* total ever queued */
	boolean_t	stopped;
	struct ath_buf	*axq_linkbuf; /* virtual addr of last buffer */
	/* first desc of the last descriptor that contains CTS */
	struct ath_desc *axq_lastdsWithCTS;

	/*
	 * final desc of the gating desc that determines whether
	 * lastdsWithCTS has been DMA'ed or not
	 */
	struct ath_desc *axq_gatingds;

	list_t axq_acq;

	uint32_t	axq_intrcnt; /* interrupt count */
};


#define	AGGR_CLEANUP		BIT(1)
#define	AGGR_ADDBA_COMPLETE	BIT(2)
#define	AGGR_ADDBA_PROGRESS	BIT(3)

/* per TID aggregate tx state for a destination */
struct ath_atx_tid {
	list_node_t list;
	list_t buf_q;
	struct ath_node *an;
	struct ath_atx_ac *ac;
	struct ath_buf *tx_buf[ATH_TID_MAX_BUFS]; /* active tx frames */
	uint16_t seq_start;
	uint16_t seq_next;
	uint16_t baw_size;
	int tidno;
	int baw_head; /* first un-acked tx buffer */
	int baw_tail; /* next unused tx buffer slot */
	int sched;
	int paused;
	uint8_t state;
	int addba_exchangeattempts;
};

/* per access-category aggregate tx state for a destination */
struct ath_atx_ac {
	int sched; /* dest-ac is scheduled */
	int qnum; /* H/W queue number associated with this AC */
	list_node_t		list;
	list_t		tid_q;
};

/* per dest tx state */
struct ath_atx {
	struct ath_atx_tid tid[WME_NUM_TID];
	struct ath_atx_ac ac[WME_NUM_AC];
};

/* per-frame tx control block */
struct ath_tx_control {
	struct ath_txq *txq;
	int if_id;
};

/* per frame tx status block */
struct ath_xmit_status {
	/* number of retries to successufully transmit this frame */
	int retries;
	int flags; /* status of transmit */
#define	ATH_TX_ERROR	0x01
#define	ATH_TX_XRETRY	0x02
#define	ATH_TX_BAR	0x04
};

struct ath_tx_stat {
	int rssi; /* RSSI (noise floor ajusted) */
	int rssictl[ATH_MAX_ANTENNA]; /* RSSI (noise floor ajusted) */
	int rssiextn[ATH_MAX_ANTENNA]; /* RSSI (noise floor ajusted) */
	int rateieee; /* data rate xmitted (IEEE rate code) */
	int rateKbps; /* data rate xmitted (Kbps) */
	int ratecode; /* phy rate code */
	int flags; /* validity flags */
/* if any of ctl,extn chain rssis are valid */
#define	ATH_TX_CHAIN_RSSI_VALID	0x01
/* if extn chain rssis are valid */
#define	ATH_TX_RSSI_EXTN_VALID	0x02
	uint32_t airtime; /* time on air per final tx rate */
};

void arn_tx_node_init(struct arn_softc *sc, struct ath_node *an);
void arn_tx_node_cleanup(struct arn_softc *sc, struct ieee80211_node *in);
struct ath_txq *arn_txq_setup(struct arn_softc *sc, int qtype, int subtype);
void arn_tx_cleanupq(struct arn_softc *sc, struct ath_txq *txq);
int arn_tx_setup(struct arn_softc *sc, int haltype);
void arn_draintxq(struct arn_softc *sc, boolean_t retry_tx);
void arn_tx_draintxq(struct arn_softc *sc, struct ath_txq *txq);
void arn_txq_schedule(struct arn_softc *sc, struct ath_txq *txq);
int arn_tx(ieee80211com_t *ic, mblk_t *mp, uint8_t type);
int arn_txq_update(struct arn_softc *sc, int qnum,
    struct ath9k_tx_queue_info *qinfo);
void arn_tx_int_proc(void *arg);

/* Node / Aggregation */

#define	ADDBA_EXCHANGE_ATTEMPTS	10
#define	ATH_AGGR_DELIM_SZ	4 /* delimiter size   */
#define	ATH_AGGR_MINPLEN	256 /* in bytes, minimum packet length */
/* number of delimiters for encryption padding */
#define	ATH_AGGR_ENCRYPTDELIM	10
/* minimum h/w qdepth to be sustained to maximize aggregation */
#define	ATH_AGGR_MIN_QDEPTH			2
#define	ATH_AMPDU_SUBFRAME_DEFAULT		32
#define	IEEE80211_SEQ_SEQ_SHIFT			4
#define	IEEE80211_SEQ_MAX			4096
#define	IEEE80211_MIN_AMPDU_BUF			0x8
#define	IEEE80211_HTCAP_MAXRXAMPDU_FACTOR	13

/*
 * return whether a bit at index _n in bitmap _bm is set
 * _sz is the size of the bitmap
 */
#define	ATH_BA_ISSET(_bm, _n)	(((_n) < (WME_BA_BMP_SIZE)) &&	\
	((_bm)[(_n) >> 5] & (1 << ((_n) & 31))))

/* return block-ack bitmap index given sequence and starting sequence */
#define	ATH_BA_INDEX(_st, _seq)	(((_seq) - (_st)) & (IEEE80211_SEQ_MAX - 1))

/* returns delimiter padding required given the packet length */
#define	ATH_AGGR_GET_NDELIM(_len)	\
	(((((_len) + ATH_AGGR_DELIM_SZ) < ATH_AGGR_MINPLEN) ?	\
	(ATH_AGGR_MINPLEN - (_len) - ATH_AGGR_DELIM_SZ) : 0) >> 2)

#define	BAW_WITHIN(_start, _bawsz, _seqno)	\
	((((_seqno) - (_start)) & 4095) < (_bawsz))

#define	ATH_DS_BA_SEQ(_ds)		((_ds)->ds_us.tx.ts_seqnum)
#define	ATH_DS_BA_BITMAP(_ds)		(&(_ds)->ds_us.tx.ba_low)
#define	ATH_DS_TX_BA(_ds)		((_ds)->ds_us.tx.ts_flags & ATH9K_TX_BA)
#define	ATH_AN_2_TID(_an, _tidno)	(&(_an)->tid[(_tidno)])

#define	ATH_TX_ERROR	0x01
#define	ATH_TX_XRETRY	0x02
#define	ATH_TX_BAR	0x04

enum ATH_AGGR_STATUS {
	ATH_AGGR_DONE,
	ATH_AGGR_BAW_CLOSED,
	ATH_AGGR_LIMITED,
};

struct aggr_rifs_param {
	int param_max_frames;
	int param_max_len;
	int param_rl;
	int param_al;
	struct ath_rc_series *param_rcs;
};

/* RSSI correction */
void ath9k_init_nfcal_hist_buffer(struct ath_hal *ah);

#define	AR_PHY_CCA_MAX_AR5416_GOOD_VALUE	-85
#define	AR_PHY_CCA_MAX_AR9280_GOOD_VALUE	-112
#define	AR_PHY_CCA_MAX_AR9285_GOOD_VALUE	-118

#define	ATH_RSSI_LPF_LEN		10
#define	RSSI_LPF_THRESHOLD		-20
#define	ATH9K_RSSI_BAD			-128
#define	ATH_RSSI_EP_MULTIPLIER		(1<<7)
#define	ATH_EP_MUL(x, mul)		((x) * (mul))
#define	ATH_RSSI_IN(x)		(ATH_EP_MUL((x), ATH_RSSI_EP_MULTIPLIER))
#define	ATH_LPF_RSSI(x, y, len)	\
	((x != ATH_RSSI_DUMMY_MARKER) ? \
	(((x) * ((len) - 1) + (y)) / (len)) : (y))
#define	ATH_RSSI_LPF(x, y)	do { \
    if ((y) >= RSSI_LPF_THRESHOLD)   \
	x = ATH_LPF_RSSI((x), ATH_RSSI_IN((y)), ATH_RSSI_LPF_LEN);  \
} while (0)
#define	ATH_EP_RND(x, mul)	\
	((((x)%(mul)) >= ((mul)/2)) ? ((x) + ((mul) - 1)) / (mul) : (x)/(mul))

/* driver-specific node state */
struct ath_node {
	struct ieee80211_node an_node;	/* base class */
	uint32_t	an_tx_times;	/* rate ctl times on one rate */
	uint32_t	an_tx_ok;	/* tx ok pkt */
	uint32_t	an_tx_err;	/* tx !ok pkt */
	uint32_t	an_tx_retr;	/* tx retry count */
	int32_t		an_tx_upper;	/* tx upper rate req cnt */
	uint32_t	an_tx_antenna;	/* antenna for last good frame */
	uint8_t		an_tx_rix0;	/* series 0 rate index */
	uint8_t		an_tx_try0;	/* series 0 try count */
	uint8_t		an_tx_mgtrate;	/* h/w rate for management/ctl frames */
	uint8_t		an_tx_mgtratesp; /* short preamble h/w rate for " " */
	uint8_t		an_tx_rate0;	/* series 0 h/w rate */
	uint8_t		an_tx_rate1;	/* series 1 h/w rate */
	uint8_t		an_tx_rate2;	/* series 2 h/w rate */
	uint8_t		an_tx_rate3;	/* series 3 h/w rate */
	uint8_t		an_tx_rate0sp;	/* series 0 short preamble h/w rate */
	uint8_t		an_tx_rate1sp;	/* series 1 short preamble h/w rate */
	uint8_t		an_tx_rate2sp;	/* series 2 short preamble h/w rate */
	uint8_t		an_tx_rate3sp;	/* series 3 short preamble h/w rate */
	struct ath_rate_priv rate_priv;
	struct ath_atx_tid tid[WME_NUM_TID];
	struct ath_atx_ac ac[WME_NUM_AC];
	uint16_t maxampdu;
	uint8_t mpdudensity;
	int	last_rssi;
};
#define	ATH_NODE(_n)	((struct ath_node *)(_n))

/*
 * Define the scheme that we select MAC address for multiple
 * BSS on the same radio. The very first VAP will just use the MAC
 * address from the EEPROM. For the next 3 VAPs, we set the
 * U/L bit (bit 1) in MAC address, and use the next two bits as the
 * index of the VAP.
 */

#define	ATH_SET_VAP_BSSID_MASK(bssid_mask) \
	((bssid_mask)[0] &= ~(((ATH_BCBUF-1)<<2)|0x02))


/* driver-specific vap state */
struct ath_vap {
	int av_bslot; /* beacon slot index */
	enum ath9k_opmode av_opmode; /* VAP operational mode */
	struct ath_buf *av_bcbuf; /* beacon buffer */
	struct ath_tx_control av_btxctl; /* txctl information for beacon */
};

/* Beacon Handling */

/*
 * Regardless of the number of beacons we stagger, (i.e. regardless of the
 * number of BSSIDs) if a given beacon does not go out even after waiting this
 * number of beacon intervals, the game's up.
 */
#define	BSTUCK_THRESH		(9 * ATH_BCBUF)
#define	ATH_BCBUF		4 /* number of beacon buffers */
#define	ATH_DEFAULT_BINTVAL	100 /* default beacon interval in TU */
#define	ATH_DEFAULT_BMISS_LIMIT	10
#define	IEEE80211_MS_TO_TU(x)	(((x) * 1000) / 1024)

/* beacon configuration */
struct ath_beacon_config {
	uint16_t beacon_interval;
	uint16_t listen_interval;
	uint16_t dtim_period;
	uint16_t bmiss_timeout;
	uint8_t dtim_count;
	uint8_t tim_offset;
	union {
		uint64_t last_tsf;
		uint8_t last_tstamp[8];
	} u; /* last received beacon/probe response timestamp of this BSS. */
};

uint32_t arn_beaconq_setup(struct ath_hal *ah);
int arn_beacon_alloc(struct arn_softc *sc, struct ieee80211_node *in);
void arn_beacon_config(struct arn_softc *sc);
void arn_beacon_return(struct arn_softc *sc);
void arn_beacon_sync(struct arn_softc *sc);
void arn_bmiss_proc(void *arg);

void arn_recv_mgmt(struct ieee80211com *ic, mblk_t *mp,
	struct ieee80211_node *in, int subtype, int rssi, uint32_t rstamp);

/* ANI */

/*
 * ANI values for STA only.
 * FIXME: Add appropriate values for AP later
 */

#define	ATH_ANI_POLLINTERVAL	100	/* 100 milliseconds between ANI poll */
#define	ATH_SHORT_CALINTERVAL	1000	/* 1 second between calibrations */
#define	ATH_LONG_CALINTERVAL	30000	/* 30 seconds between calibrations */
#define	ATH_RESTART_CALINTERVAL	1200000	/* 20 minutes between calibrations */

struct ath_ani {
	boolean_t sc_caldone;
	int16_t sc_noise_floor;
	unsigned int sc_longcal_timer;
	unsigned int sc_shortcal_timer;
	unsigned int sc_resetcal_timer;
	unsigned int sc_checkani_timer;
};

/* LED Control */
#define	ATH_LED_PIN	1

enum ath_led_type {
	ATH_LED_RADIO,
	ATH_LED_ASSOC,
	ATH_LED_TX,
	ATH_LED_RX
};

struct ath_led {
	struct arn_softc *sc;
	enum ath_led_type led_type;
	char name[32];
	boolean_t registered;
};

/* Rfkill */
#define	ATH_RFKILL_POLL_INTERVAL	2000 /* msecs */

/* Main driver core */
/*
 * Default cache line size, in bytes.
 * Used when PCI device not fully initialized by bootrom/BIOS
 */
#define	DEFAULT_CACHELINE	32
#define	ATH_DEFAULT_NOISE_FLOOR	-95
#define	ATH_REGCLASSIDS_MAX	10
#define	ATH_CABQ_READY_TIME	80 /* % of beacon interval */
#define	ATH_MAX_SW_RETRIES	10
#define	ATH_CHAN_MAX		255
#define	IEEE80211_WEP_NKID	4 /* number of key ids */
#define	IEEE80211_RATE_VAL	0x7f
/*
 * The key cache is used for h/w cipher state and also for
 * tracking station state such as the current tx antenna.
 * We also setup a mapping table between key cache slot indices
 * and station state to short-circuit node lookups on rx.
 * Different parts have different size key caches.  We handle
 * up to ATH_KEYMAX entries (could dynamically allocate state).
 */
#define	ATH_KEYMAX		128 /* max key cache size we handle */

#define	ATH_IF_ID_ANY		0xff
#define	ATH_TXPOWER_MAX		100 /* .5 dBm units */
#define	ATH_RSSI_DUMMY_MARKER	0x127
#define	ATH_RATE_DUMMY_MARKER	0

enum PROT_MODE {
	PROT_M_NONE = 0,
	PROT_M_RTSCTS,
	PROT_M_CTSONLY
};

#define	SC_OP_INVALID		BIT(0)
#define	SC_OP_BEACONS		BIT(1)
#define	SC_OP_RXAGGR		BIT(2)
#define	SC_OP_TXAGGR		BIT(3)
#define	SC_OP_CHAINMASK_UPDATE	BIT(4)
#define	SC_OP_FULL_RESET	BIT(5)
#define	SC_OP_NO_RESET		BIT(6)
#define	SC_OP_PREAMBLE_SHORT	BIT(7)
#define	SC_OP_PROTECT_ENABLE	BIT(8)
#define	SC_OP_RXFLUSH		BIT(9)
#define	SC_OP_LED_ASSOCIATED	BIT(10)
#define	SC_OP_RFKILL_REGISTERED	BIT(11)
#define	SC_OP_RFKILL_SW_BLOCKED	BIT(12)
#define	SC_OP_RFKILL_HW_BLOCKED	BIT(13)

/* HT  */
typedef	struct ht_conf {
	boolean_t		ht_supported;
	uint16_t		cap;
	uint8_t			ampdu_factor;
	uint8_t			ampdu_density;
	uint8_t			rx_mcs_mask[10];
} arn_ht_conf;

uint8_t parse_mpdudensity(uint8_t mpdudensity);

void arn_ampdu_recv_action(struct ieee80211_node *in,
    const uint8_t *frm, const uint8_t *efrm);
int arn_ampdu_send_action(struct ieee80211_node *in,
    int category, int action, uint16_t args[4]);
void arn_dump_line(unsigned char *p, uint32_t len, boolean_t isaddress,
    uint32_t group);
void arn_dump_pkg(unsigned char *p, uint32_t len, boolean_t isaddress,
    uint32_t group);

struct arn_softc {
	ieee80211com_t sc_isc;	/* IEEE 802.11 common */
	dev_info_t *sc_dev;    /* back pointer to dev_info_t */
	ddi_taskq_t *sc_tq;    /* private task queue */
	struct ath_hal *sc_ah;
	struct ath_config sc_config;
	caddr_t mem;

	uint8_t sc_isrunning; /* device is operational */
	uint8_t sc_mrretry;   /* multi-rate retry support */
	uint8_t sc_have11g;   /* have 11g support */
	uint8_t sc_bsync;	/* beacon sync */

	ddi_acc_handle_t	sc_cfg_handle;    /* DDI I/O handle */
	ddi_acc_handle_t	sc_io_handle;	   /* DDI I/O handle */
	ddi_acc_handle_t	sc_EEPROM_handle; /* DDI I/O handle */
	ddi_iblock_cookie_t	sc_iblock;
	ddi_softintr_t		sc_softint_id;

	/* 802.11n/HT capabilities */
	arn_ht_conf		sc_ht_conf;
	void			(*sc_recv_action)(ieee80211_node_t *,
				    const uint8_t *, const uint8_t *);
	int			(*sc_send_action)(ieee80211_node_t *,
				    int, int, uint16_t[4]);

	/* TX/RX descriptors */
	struct ath_desc *sc_desc;
	/* descriptor structure */
	dma_area_t sc_desc_dma;
	/* pointer to the first "struct ath_buf" */
	struct ath_buf *sc_vbufptr;
	/* length of all allocated "struct ath_buf" */
	uint32_t sc_vbuflen;
	/* size of one DMA TX/RX buffer based on 802.11 MTU */
	uint32_t tx_dmabuf_size;
	uint32_t rx_dmabuf_size;

	uint8_t sc_curbssid[6];
	uint8_t sc_myaddr[6];
	uint8_t sc_bssidmask[6];

	int sc_debug;
	uint32_t sc_intrstatus;
	uint32_t sc_flags; /* SC_OP_* */
	unsigned int rx_filter;
	uint16_t sc_curtxpow;
	uint16_t sc_curaid;
	uint16_t sc_cachelsz;
	int sc_slotupdate; /* slot to next advance fsm */
	int sc_slottime;
	int sc_bslot[ATH_BCBUF];
	uint8_t sc_tx_chainmask;
	uint8_t sc_rx_chainmask;
	enum ath9k_int sc_imask;
	enum PROT_MODE sc_protmode;

	uint8_t sc_nbcnvaps; /* # of vaps sending beacons */
	uint16_t sc_nvaps; /* # of active virtual ap's */

	uint8_t sc_mcastantenna;
	uint8_t sc_defant; /* current default antenna */
	uint8_t sc_rxotherant; /* rx's on non-default antenna */

	struct ath9k_node_stats sc_halstats; /* station-mode rssi stats */
	enum ath9k_ht_extprotspacing sc_ht_extprotspacing;
	enum ath9k_ht_macmode tx_chan_width;

	enum {
		OK, /* no change needed */
		UPDATE, /* update pending */
		COMMIT /* beacon sent, commit change */
	} sc_updateslot; /* slot time update fsm */

	/* Crypto */
	uint32_t	sc_keymax; /* size of key cache */
	uint8_t		sc_keymap[16]; /* bit map of key cache use */
	uint8_t		sc_splitmic; /* split TKIP MIC keys */

	/* RX */
	list_t		sc_rxbuf_list;
	int		sc_rxbufsize; /* rx size based on mtu */
	uint32_t 	*sc_rxlink; /* link ptr in last RX desc */
	uint32_t	sc_rx_pend;
	uint64_t	sc_lastrx; /* tsf at last rx'd frame */

	/* TX */
	list_t sc_txbuf_list;
	struct ath_txq 	sc_txq[ATH9K_NUM_TX_QUEUES];
	uint32_t sc_txqsetup;
	int sc_haltype2q[ATH9K_WME_AC_VO+1]; /* HAL WME AC -> h/w qnum */
	uint16_t seq_no; /* TX sequence number */

	/* Beacon */
	struct ath9k_tx_queue_info sc_beacon_qi;
	struct ath_txq *sc_cabq;
	list_t sc_bcbuf_list;	/* beacon buffer */
	uint32_t sc_beaconq;
	uint32_t sc_bmisscount;
	uint32_t ast_be_xmit;	/* beacons transmitted */
	uint64_t bc_tstamp;
	struct ieee80211_beacon_offsets asc_boff; /* dynamic update state */

	/* Rate */
	struct ath_rate_table *hw_rate_table[ATH9K_MODE_MAX];
	struct ath_rate_table *sc_currates; /* current rate table */
	uint8_t	asc_rixmap[256]; /* IEEE to h/w rate table ix */
	uint8_t sc_protrix;		/* protection rate index */

	/* mode */
	enum wireless_mode	sc_curmode; /* current phy mode */

	/* Channel, Band */
	struct ath9k_channel sc_curchan;

	/* Locks */
	kmutex_t	sc_genlock;
	kmutex_t	sc_serial_rw;
	kmutex_t	sc_rxbuflock;	/* recv lock  */
	kmutex_t	sc_txbuflock;	/* txbuf lock */
	kmutex_t	sc_rxflushlock;
	kmutex_t	sc_resetlock;
	kmutex_t	sc_bcbuflock;	/* beacon buffer lock */
	kmutex_t	sc_resched_lock;
	boolean_t	sc_resched_needed;

	/* LEDs */
	struct ath_led 	radio_led;
	struct ath_led 	assoc_led;
	struct ath_led 	tx_led;
	struct ath_led 	rx_led;

	uint8_t		sc_mcast_refs[64]; /* refer count */
	uint32_t	sc_mcast_hash[2]; /* multicast hash table */

	/* Rfkill */

	/* ANI */
	struct ath_ani sc_ani;

	/* interface statistics */
	struct ath_stats sc_stats;

	boolean_t sc_promisc; /* Promiscuous mode enabled */

	timeout_id_t sc_scan_timer;
	timeout_id_t sc_cal_timer;

	int (*sc_newstate)(ieee80211com_t *, enum ieee80211_state, int);
	void (*sc_recv_mgmt)(ieee80211com_t *, mblk_t *, ieee80211_node_t *,
	    int, int, uint32_t);
};

int arn_reset(ieee80211com_t *ic);

int arn_get_hal_qnum(uint16_t queue, struct arn_softc *sc);

int ath_cabq_update(struct arn_softc *);

void arn_update_chainmask(struct arn_softc *sc);

/*
 * Read and write, they both share the same lock. We do this to serialize
 * reads and writes on Atheros 802.11n PCI devices only. This is required
 * as the FIFO on these devices can only accept sanely 2 requests. After
 * that the device goes bananas. Serializing the reads/writes prevents this
 * from happening.
 */
void
arn_iowrite32(struct ath_hal *ah, uint32_t reg_offset, uint32_t val);
unsigned int
arn_ioread32(struct ath_hal *ah, uint32_t reg_offset);

#ifdef __cplusplus
}
#endif

#endif /* _ARN_CORE_H */
