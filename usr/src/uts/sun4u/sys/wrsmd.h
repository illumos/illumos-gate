/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * DLPI driver for RSM over Wildcat
 */

#ifndef	_SYS_WRSMD_H_
#define	_SYS_WRSMD_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/ethernet.h>
#include <sys/rsm/rsmpi.h>

/*
 * This driver is only supported on sparc systems, so there is no
 * need to worry about byte ordering issues.
 * However, need to update this version number whenever there is a
 * change in the layout of wrsmd remote shared memory that could
 * lead to incompatibilities between systems.
 */

#define	WRSMD_VERSION	(2)

/*
 * static limits
 */

#define	WRSMD_DUMP_IOCTL (5618)
#define	WRSMD_DUMP_DEST  (5619)

#define	RSM_MAX_DESTADDR 256	/* Wildcat maximum -- (must be power of 2) */

#define	RSM_DLPI_QPRI	8	/* XXX what is the priority range?? */
#define	RSM_DLPI_QDEPTH	100
#define	RSM_DLPI_QFLAGS	(RSM_INTR_SEND_Q_NO_FENCE)

#ifdef	_KERNEL

#define	WRSMD_CACHELINE_SIZE	(0x40)
#define	WRSMD_CACHELINE_SHIFT	6
#define	WRSMD_CACHELINE_OFFSET	(WRSMD_CACHELINE_SIZE - 1)
#define	WRSMD_CACHELINE_MASK	(~WRSMD_CACHELINE_OFFSET)
#define	WRSMD_CACHELINE_ROUNDUP(b) \
	(((uint64_t)(b) + WRSMD_CACHELINE_OFFSET) & WRSMD_CACHELINE_MASK)



/*
 * Use the same format address as ethernet when interacting with higher
 * level modules.
 */
typedef struct dl_rsm_addr {
	union {
		rsm_addr_t rsm;		/* real RSM HW address */
		struct {
			unsigned char zeroes[7];
			unsigned char addr;
		} wrsm;
		struct {		/* address in ethernet format */
			ushort_t zero;
			struct ether_addr addr;
		} ether;
	} m;
} dl_rsm_addr_t;



/*
 * Declarations specific to the medium
 */

#define	MEDIUM_MTU	(64*1024-1)	/* max frame w/o header */
#define	MEDIUM_MIN	(1)		/* min frame w/header w/o fcs */

#define	MEDIUMSAP_MAX	(0xffff)	/* max valid medium sap */


/*
 * Definitions for module_info.
 */

#define	WRSMDIDNUM	(726)		/* module ID number */
#define	WRSMDNAME	"wrsmd"		/* module name */
#define	WRSMDMINPSZ	(0)		/* min packet size */
#define	WRSMDMAXPSZ	(65536)		/* max packet size */
#define	WRSMDHIWAT	(65536)		/* hi-water mark */
#define	WRSMDLOWAT	(1)		/* lo-water mark */

/*
 * Driver parameters, from .conf file
 */

struct wrsmd_param {
	/* Size of packet buffers (must be multiple of 64 bytes) */
	uint_t wrsmd_buffer_size;

	/* Mask of base ID bits in IP address */
	uint_t wrsmd_netmask;

	/* Number of packet buffers exported to each communicating peer */
	ushort_t wrsmd_buffers;

	/* Size of communications queues (must be at least wrsmd_buffers) */
	ushort_t wrsmd_queue_size;

	/* Number of buffers which won't be loaned upstream */
	ushort_t wrsmd_buffers_retained;

	/* Time to reclaim idle connection after (in seconds) UNIMPLEMENTED */
	uint_t wrsmd_idle_reclaim_time;

	/* Number of retries after a read or write error */
	ushort_t wrsmd_err_retries;

	/* Maximum # of queue packets per destination */
	ushort_t wrsmd_max_queued_pkts;

	/* Initial FQE timeout interval */
	int wrsmd_nobuf_init_tmo;

	/* Maximum FQE timeout interval */
	int wrsmd_nobuf_max_tmo;

	/* Time after which we drop packets instead of doing FQE timeout */
	uint_t wrsmd_nobuf_drop_tmo;

	/* Initial message timeout interval */
	int wrsmd_msg_init_tmo;

	/* Maximum message timeout interval */
	int wrsmd_msg_max_tmo;

	/* Time after which we drop connection instead of doing msg timeout */
	uint_t wrsmd_msg_drop_tmo;

	/* Acknowledgment timeout interval */
	int wrsmd_ack_tmo;

	/* Queue element sync timeout interval */
	uint_t wrsmd_sync_tmo;

	/*
	 * timeout interval to wait before tearing down connection
	 * after last attach to device is removed.
	 */
	uint_t wrsmd_teardown_tmo;

	/* Number of packets to try and batch up in one transmission. */
	ushort_t wrsmd_train_size;

	/* Number of free buffers to try and batch up in one transmission. */
	ushort_t wrsmd_fqe_sync_size;
};

/*
 * Defaults and limits for parameters
 * Timeout parameter values now given in milliseconds,
 * rather than ticks.  Any values modified in wrsmd.conf
 * must now be in milliseconds.  Values get rounded up to
 * the next tick value, with granularity 10 ms for the default
 * 100 hz.
 */

#define	WRSMD_BUFFERS_DFLT		32
#define	WRSMD_BUFFER_SIZE_DFLT		16384
#define	WRSMD_QUEUE_SIZE_DFLT		64
#define	WRSMD_BUFFERS_RETAINED_DFLT	32
#define	WRSMD_IDLE_RECLAIM_TIME_DFLT	36000
#define	WRSMD_ERR_RETRIES_DFLT		1
#define	WRSMD_MAX_QUEUED_PKTS_DFLT	100
#define	WRSMD_NOBUF_INIT_TMO_DFLT	10
#define	WRSMD_NOBUF_MAX_TMO_DFLT	2560
#define	WRSMD_NOBUF_DROP_TMO_DFLT	5000
#define	WRSMD_MSG_INIT_TMO_DFLT		10
#define	WRSMD_MSG_MAX_TMO_DFLT		1280
#define	WRSMD_MSG_DROP_TMO_DFLT		30000
#define	WRSMD_ACK_TMO_DFLT		1000
#define	WRSMD_SYNC_TMO_DFLT		10
/*
 * We set this to two clock ticks to allow free destination timeouts
 * (<= 1 tick) to complete first, before next teardown timeout,
 * allowing fewer iterations of the latter.
 */
#define	WRSMD_TEARDOWN_TMO_DFLT		20

#define	WRSMD_TRAIN_SIZE_DFLT		8
#define	WRSMD_FQE_SYNC_SIZE_DFLT	16

/*
 * Macro to convert millisecond timeout parameters to clock ticks.
 */
#define	WRSMD_TICKS(x)	(drv_usectohz(1000 * (x)))

/* Definition of each possible event type */
#define	WRSMD_EVT_FREEDEST	0
#define	WRSMD_EVT_SYNC		1
#define	WRSMD_EVT_SYNC_DQE	2

/*
 * Per-Stream instance state information.
 *
 * Each instance is dynamically allocated at open() and freed at
 * close(). Each per-stream instance points to at most one per-device
 * structure using the ss_wrsmdp field. All instances are threaded
 * together into one list of active instances ordered on minor device
 * number.
 */

typedef struct wrsmdstr {
	struct wrsmdstr *ss_nextp;	/* next in list */
	queue_t *ss_rq;			/* ptr to our read queue */
	struct wrsmd *ss_wrsmdp;		/* attached device, if any */
	ushort_t ss_state;		/* current state */
	ushort_t ss_flags;		/* misc flags */
	t_uscalar_t ss_sap;		/* bound sap (from dl_bind_req_t) */
	minor_t ss_minor;		/* minor device number */
	kmutex_t ss_lock;		/* protect this struct */
} wrsmdstr_t;

_NOTE(READ_ONLY_DATA(wrsmdstr::ss_rq))
_NOTE(MUTEX_PROTECTS_DATA(wrsmdstr::ss_lock, wrsmdstr::ss_wrsmdp))
_NOTE(MUTEX_PROTECTS_DATA(wrsmdstr::ss_lock, wrsmdstr::ss_state))
_NOTE(MUTEX_PROTECTS_DATA(wrsmdstr::ss_lock, wrsmdstr::ss_sap))
_NOTE(MUTEX_PROTECTS_DATA(wrsmdstr::ss_lock, wrsmdstr::ss_flags))
_NOTE(READ_ONLY_DATA(wrsmdstr::ss_minor))

/*
 * For performance reasons, we read the following things in wrsmdsendup()
 * without getting ss_lock.  As long as accesses to these variables are atomic,
 * we believe nothing bad will happen.
 */
_NOTE(DATA_READABLE_WITHOUT_LOCK(wrsmdstr::ss_wrsmdp))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wrsmdstr::ss_sap))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wrsmdstr::ss_flags))

/* Per-stream flags */

#define	WRSMD_SLRAW	0x02	/* M_DATA plain raw mode */
#define	WRSMD_SLALLPHYS	0x04	/* "promiscuous mode" */
#define	WRSMD_SLALLSAP	0x08	/* enable all ether type values */
#define	WRSMD_SLFAST	0x10	/* "fast mode" */

typedef struct wrsmd_event {
	struct wrsmd_event *next;
	int type;
	void *arg;
} wrsmd_event_t;


/*
 * Per-Device instance state information.
 *
 * Each instance is dynamically allocated on first attach.
 */
typedef struct wrsmd {
	struct wrsmd	*wrsmd_nextp; 	/* next in linked list */
	queue_t		*wrsmd_wq;	/* ptr to one of our wq's, doesn't */
					/*  matter which one, to run wsrv */
	queue_t		*wrsmd_ipq;	/* IP queue, iff there's only one */
	krwlock_t	wrsmd_ipq_rwlock; /* protects wrsmd_ipq */

	dev_info_t	*wrsmd_dip;	/* dev info */
	ushort_t	wrsmd_flags;	/* misc. flags */
	ushort_t	wrsmd_promisc;	/* # of WRSMD_SLALLPHYS streams */
	ushort_t	wrsmd_attached_streams;	/* streams attached to device */
	kmutex_t	wrsmd_lock;	/* protect this struct */
	kmutex_t	wrsmd_dest_lock; /* protect dest table (below) */

	/* Counters to keep stats for netstat support */
	uint64_t wrsmd_ipackets;	/* # packets received */
	uint32_t wrsmd_ierrors;		/* # total input errors */
	uint64_t wrsmd_opackets;	/* # packets sent */
	uint32_t wrsmd_oerrors;		/* # total output errors */
	uint32_t wrsmd_collisions;	/* # collisions (FQE waits) */

	uint32_t wrsmd_in_bytes;	/* # bytes input (32 bit) */
	uint32_t wrsmd_in_bytes64;	/* # bytes input (64 bit) */
	uint64_t wrsmd_out_bytes;	/* # bytes output (32 bit) */
	uint64_t wrsmd_out_bytes64;	/* # bytes output (64 bit) */

	/* Other counters, for internal use */
	uint32_t wrsmd_xfers;		/* # calls to wrsmd_xmit */
	uint32_t wrsmd_xfer_pkts;	/* # pkts sent out by xmit */
	uint32_t wrsmd_syncdqes;	/* # syncdqe-ints sent out by  xmit */
	uint32_t wrsmd_lbufs;		/* # times we loaned bufs */
	uint32_t wrsmd_nlbufs;		/* # times we had to alloc buf */
	uint32_t wrsmd_pullup;		/* # times we had to coalesce pkts */
	uint32_t wrsmd_pullup_fail;	/* # times we couldn't pullup */
	uint32_t wrsmd_starts;		/* # calls to wrsmdstart */
	uint32_t wrsmd_start_xfers;	/* # calls to wrsmdxfer from start */
	uint32_t wrsmd_fqetmo_hint;	/* # times fqe tmo ended by hint */
	uint32_t wrsmd_fqetmo_drops;	/* # pkts dropped by fqetmo */
	uint32_t wrsmd_maxq_drops;	/* # pkts dropped 'cause q too long */
	uint32_t wrsmd_errs;		/* # errors on transfers */

	struct wrsmd_param 	wrsmd_param;	/* parameters */
	struct kstat		*wrsmd_ksp;	/* our kstats */
	dl_rsm_addr_t		wrsmd_rsm_addr; /* our RSM hardware address */
	uint_t			wrsmd_ctlr_id; /* our RSM controller id  */
	rsm_controller_object_t wrsmd_ctlr;
	rsm_controller_attr_t	*wrsmd_ctlr_attr;
	int	wrsmd_numdest;	/* Number of valid entries in desttbl */

	struct wrsmd_dest		/* table for destination structures */
		*wrsmd_desttbl[RSM_MAX_DESTADDR];

	struct wrsmd_dest 	*wrsmd_runq;	/* service routine run queue */
	kmutex_t wrsmd_runq_lock; /* protects wrsmd_runq, among others */

	timeout_id_t		wrsmd_teardown_tmo_id;	/* teardown device */

	/* Event thread for making RSM calles from non callback context */
	kmutex_t		event_lock;
	kthread_t 		*event_thread;
	kcondvar_t		event_cv;
	boolean_t		stop_events;
	kcondvar_t		event_thread_exit_cv;
	wrsmd_event_t		*events;

} wrsmd_t;


_NOTE(READ_ONLY_DATA(wrsmd::wrsmd_dip))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd::wrsmd_lock, wrsmd::wrsmd_flags))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd::wrsmd_lock, wrsmd::wrsmd_promisc))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wrsmd::wrsmd_promisc))

_NOTE(READ_ONLY_DATA(wrsmd::wrsmd_param))
_NOTE(READ_ONLY_DATA(wrsmd_param))

_NOTE(MUTEX_PROTECTS_DATA(wrsmd::wrsmd_lock, wrsmd::wrsmd_ksp))
_NOTE(READ_ONLY_DATA(wrsmd::wrsmd_ctlr_id))

_NOTE(MUTEX_PROTECTS_DATA(wrsmd::wrsmd_runq_lock, wrsmd::wrsmd_runq))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd::wrsmd_runq_lock, wrsmd::wrsmd_wq))

_NOTE(DATA_READABLE_WITHOUT_LOCK(wrsmd::wrsmd_dip))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wrsmd::wrsmd_ipackets))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wrsmd::wrsmd_ierrors))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wrsmd::wrsmd_opackets))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wrsmd::wrsmd_oerrors))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wrsmd::wrsmd_collisions))

/* RSMPI progress flags */
#define	WRSMDREGHANDLER	0x01
#define	WRSMDGOTCTLR	0x02

/* Attach progress bitmask */
#define	WRSMD_ATT_MUTEX		0x01
#define	WRSMD_ATT_LINKED		0x02
#define	WRSMD_ATT_MINOR		0x04
#define	WRSMD_ATT_KSTAT		0x08
#define	WRSMD_ATT_EVT_THREAD	0x10

#define	WRSMD_ATT_ALL	\
	(WRSMD_ATT_MUTEX | WRSMD_ATT_LINKED | WRSMD_ATT_MINOR \
	| WRSMD_ATT_KSTAT | WRSMD_ATT_EVT_THREAD)


/*
 * Number of bytes to add to buffer size to leave room for
 * headers from other streams modules:
 *
 * TCP Header is 14 bytes
 * IP Header is 20 bytes
 */
#define	WRSMDHEADROOM	34

/*
 * Full dlsap address format
 */

typedef struct wrsmddladdr {
	struct ether_addr	dl_addr;	/* RSM hardware addr */
	ushort_t		dl_sap;		/* SAP */
} wrsmddladdr_t;


/*
 * Full DLSAP address length
 */
#define	WRSMD_DEVICE_ADDRL (sizeof (ushort_t) + sizeof (struct ether_addr))
#define	WRSMD_IP_SAP	0x800	/* IP's sap */

#define	WRSMD_BCAST_ADDRL (sizeof (struct ether_addr))

#define	DLADDRL	(80)

/*
 * Export some of the error counters via the kstats mechanism.
 */
typedef struct wrsmd_stat {
	struct kstat_named rsm_ipackets;
	struct kstat_named rsm_ipackets64;
	struct kstat_named rsm_ierrors;
	struct kstat_named rsm_opackets;
	struct kstat_named rsm_opackets64;
	struct kstat_named rsm_oerrors;
	struct kstat_named rsm_collisions;
	struct kstat_named rsm_xfers;
	struct kstat_named rsm_xfer_pkts;
	struct kstat_named rsm_syncdqes;
	struct kstat_named rsm_lbufs;
	struct kstat_named rsm_nlbufs;
	struct kstat_named rsm_pullup;
	struct kstat_named rsm_pullup_fail;
	struct kstat_named rsm_starts;
	struct kstat_named rsm_start_xfers;
	struct kstat_named rsm_fqetmo_hint;
	struct kstat_named rsm_fqetmo_drops;
	struct kstat_named rsm_maxq_drops;
	struct kstat_named rsm_errs;
	struct kstat_named rsm_in_bytes;
	struct kstat_named rsm_in_bytes64;
	struct kstat_named rsm_out_bytes;
	struct kstat_named rsm_out_bytes64;
} wrsmd_stat_t;

_NOTE(SCHEME_PROTECTS_DATA("inconsistency OK", wrsmd_stat::rsm_ipackets))
_NOTE(SCHEME_PROTECTS_DATA("inconsistency OK", wrsmd_stat::rsm_ierrors))
_NOTE(SCHEME_PROTECTS_DATA("inconsistency OK", wrsmd_stat::rsm_opackets))
_NOTE(SCHEME_PROTECTS_DATA("inconsistency OK", wrsmd_stat::rsm_oerrors))
_NOTE(SCHEME_PROTECTS_DATA("inconsistency OK", wrsmd_stat::rsm_collisions))
_NOTE(SCHEME_PROTECTS_DATA("inconsistency OK", wrsmd_stat::rsm_xfers))
_NOTE(SCHEME_PROTECTS_DATA("inconsistency OK", wrsmd_stat::rsm_xfer_pkts))
_NOTE(SCHEME_PROTECTS_DATA("inconsistency OK", wrsmd_stat::rsm_lbufs))
_NOTE(SCHEME_PROTECTS_DATA("inconsistency OK", wrsmd_stat::rsm_nlbufs))
_NOTE(SCHEME_PROTECTS_DATA("inconsistency OK", wrsmd_stat::rsm_pullup))
_NOTE(SCHEME_PROTECTS_DATA("inconsistency OK", wrsmd_stat::rsm_pullup_fail))
_NOTE(SCHEME_PROTECTS_DATA("inconsistency OK", wrsmd_stat::rsm_starts))
_NOTE(SCHEME_PROTECTS_DATA("inconsistency OK", wrsmd_stat::rsm_start_xfers))
_NOTE(SCHEME_PROTECTS_DATA("inconsistency OK", wrsmd_stat::rsm_fqetmo_hint))
_NOTE(SCHEME_PROTECTS_DATA("inconsistency OK", wrsmd_stat::rsm_fqetmo_drops))
_NOTE(SCHEME_PROTECTS_DATA("inconsistency OK", wrsmd_stat::rsm_maxq_drops))
_NOTE(SCHEME_PROTECTS_DATA("inconsistency OK", wrsmd_stat::rsm_errs))
_NOTE(SCHEME_PROTECTS_DATA("inconsistency OK", wrsmd_stat::rsm_in_bytes))
_NOTE(SCHEME_PROTECTS_DATA("inconsistency OK", wrsmd_stat::rsm_out_bytes))

/* Some streams defines */

#define	DB_BASE(mp)		((mp)->b_datap->db_base)
#define	DB_LIM(mp)		((mp)->b_datap->db_lim)
#define	DB_REF(mp)		((mp)->b_datap->db_ref)
#define	DB_TYPE(mp)		((mp)->b_datap->db_type)

#define	MBLKL(mp)		((mp)->b_wptr - (mp)->b_rptr)
#define	MBLKSIZE(mp)	((mp)->b_datap->db_lim - (mp)->b_datap->db_base)
#define	MBLKHEAD(mp)	((mp)->b_rptr - (mp)->b_datap->db_base)
#define	MBLKTAIL(mp)	((mp)->b_datap->db_lim - (mp)->b_wptr)

/*
 * On Wildcat, if there is a data delivery problem with one of the 32 byte
 * halves of a 64 byte write to the remote node, the remote side writes all
 * 0's to that 32 byte region of memory.  We guarantee that the 4 byte fqe
 * entries and 8 byte byte dqe entries (described below) are aligned in a
 * way that guarantees that each fits within a single 32 byte region, so
 * checking for any non-zero value within the entry is sufficient to
 * guarantee that the write was successful.
 *
 * We use the seqnum as the write validity check, which means it must never
 * be 0.  A non-0 value ensures that the remote write was successful.
 *
 * Each fqe and dqe is 64 bytes in size.  This guarantees that
 * we can write one entry at a time atomically, without disturbing any other
 * entries.  This also quarantees alignment to wildcat hardware.  It does,
 * however, waste some space.
 *
 */

struct align_64byte {			/* Align to 64 bytes */
	uint64_t pad[8];
};

/*
 * Delivery Queue Entry, used to denote buffers containing new packets.
 */
#define	WRSMD_DQE_SEQ_MASK	0xFF	/* All 1's sequence */
typedef union wrsmd_dqe {
	struct align_64byte align;	/* Align to 64 bytes */
	struct wrsmd_dqe_s {	/* actual structure */
		ushort_t dq_length;	/* True length of packet */
		ushort_t dq_sap;	/* Packet's SAP */
		uchar_t	dq_seqnum;	/* Sequence number - validity check */
		uchar_t	dq_offset;	/* Packet offset within buffer */
		ushort_t dq_bufnum;	/* Buffer number */
	} s;
} wrsmd_dqe_t;

/*
 * Free Queue Entry, used to denote buffers which are available to be filled.
 */
#define	WRSMD_FQE_SEQ_MASK	0xFF	/* All 1's sequence */
typedef union wrsmd_fqe {
	struct align_64byte align;	/* Align to 64 bytes */
	struct wrsmd_fqe_s {
		uchar_t	fq_seqnum;	/* Sequence number - validity check */
		uchar_t	fq_filler;	/* Unused */
		ushort_t fq_bufnum;	/* Buffer number */
	} s;
} wrsmd_fqe_t;

/*
 * Segment data formats
 */

/*
 * The major version should be bumped whenever the contents of the
 * xfer segments are changed in a non-upward-compatible way, to prevent
 * confused attempts at communication with machines running older protocol
 * versions.
 */
#define	WRSMD_VERS_MAJOR		1
#define	WRSMD_VERS_MINOR		0

/*
 * Header for the data transfer segment.
 */
typedef struct wrsmd_xfer_hdr {
	size_t		rx_segsize;	/* size of segment */
	uint32_t	rx_cookie;	/* magic cookie */
	uint32_t	rx_bufsize;	/* size of buffers */
	ushort_t	rx_numbufs;	/* number of buffers */
	ushort_t	rx_numfqes;	/* number of elements in free queue */
	ushort_t	rx_numdqes;	/* num of elements in delivery queue */
	uint32_t	rx_buf_offset;	/* offset to start of buffers */
	uint32_t	rx_fq_offset;	/* offset to start of free queue */
	uint32_t	rx_dq_offset;	/* offset to start of delivery queue */
} wrsmd_xfer_hdr_t;

#define	WRSMD_XFER_COOKIE	0x58664572	/* 'XfEr' */

/*
 * Structure describing a loaned-up buffer
 */

typedef struct wrsmdbuf {
	frtn_t	rb_frtn;		/* Pointer to our free routine */
	int	rb_bufnum;		/* Number of loaned buffer */
	struct wrsmd_dest *rb_rd;	/* Destination buffer belongs to */
} wrsmdbuf_t;

_NOTE(READ_ONLY_DATA(wrsmdbuf::rb_frtn))
_NOTE(READ_ONLY_DATA(wrsmdbuf::rb_bufnum))
_NOTE(READ_ONLY_DATA(wrsmdbuf::rb_rd))

/*
 * Structure describing a packet which is currently being sent
 */

typedef struct wrsmd_pkt {
	mblk_t *rd_pkt_ptr;	/* packet pointer */
	ushort_t rd_pkt_offset;	/* packet offset within buffer */
	uint_t rd_pkt_len;	/* real length of packet */
	ushort_t rd_pkt_sap;	/* packet SAP */
} wrsmd_pkt_t;


/*
 * WRSMD message types
 */

#define	WRSMD_MSG_REQ_CONNECT		1
#define	WRSMD_MSG_CON_ACCEPT		2
#define	WRSMD_MSG_CON_ACK		3
#define	WRSMD_MSG_SYNC_DQE		4

#define	WRSMD_REXMIT			127



/*
 *
 *          R S M D   C O N N E C T I O N   P R O T O C O L
 *
 *
 * The connection protocol for the RSM DLPI driver is a follows:
 *
 * INITIATOR                              RESPONDER
 *
 * 1  Send RSDM_REQ_CONNECT
 *         Includes xfer segment ID
 *
 * 2                                      Send WRSMD_CON_ACCEPT
 *                                        Includes xfer segment ID
 *
 * 3  Send WRSMD_CON_ACK
 *
 * If an WRSMD_REQ_CONNECT message is received while an
 * WRSMD_REQ_CONNECT is outstanding to the same node ID:  if the
 * node receiving the duplicate WRSMD_REQ_CONNECT has a higher
 * numbered ID, it will accept the connection.  The lower numbered
 * node will reject the duplicate.
 *
 * The special message type WRSMD_REXMIT causes us to retransmit the
 * last message we sent (unsuccessfully or successfully), without
 * incrementing the sequence number on the message.  This is used when
 * we get a timeout waiting for a response to an WRSMDM_REQ_CONNECT
 * request and want to resend it.
 *
 */

typedef struct wrsmd_msg_header {
	uint8_t wrsmd_version;	/* Increment when incompatible change made */
	uint8_t reqtype;	/* One of the above */
	uint16_t seqno;		/* Sequence number */
} wrsmd_msg_header_t;

typedef struct wrsmd_con_request {
	rsm_memseg_id_t send_segid; /* Segment you should use to talk to me */
} wrsmd_con_request_t;

typedef struct wrsmd_con_accept {
	rsm_memseg_id_t send_segid; /* Segment you should use to talk to me */
	rsm_memseg_id_t rcv_segid; /* Segment I use to talk to you */
} wrsmd_con_accept_t;

typedef struct wrsmd_con_ack {
	rsm_memseg_id_t send_segid; /* Segment you should use to talk to me */
	rsm_memseg_id_t rcv_segid; /* Segment I use to talk to you */
} wrsmd_con_ack_t;

typedef struct wrsmd_syncdqe {
	rsm_memseg_id_t rcv_segid; /* Segment I use to talk to you */
} wrsmd_syncdqe_t;



typedef union wrsmd_msg {
	uint64_t align;
	struct {
		wrsmd_msg_header_t hdr;
		union {
			wrsmd_con_request_t	con_request;
			wrsmd_con_accept_t	con_accept;
			wrsmd_con_ack_t		con_ack;
			wrsmd_syncdqe_t		syncdqe;
		} m;
	} p;
} wrsmd_msg_t;

/*
 * Structure describing someone else communicating with us (a destination)
 */

typedef struct wrsmd_dest {

	/* Basics */
	wrsmd_t		*rd_wrsmdp;	/* Pointer to our device structure */
	rsm_addr_t 	rd_rsm_addr;	/* Address of destination */

	/* Interrupt queue */
	rsm_send_q_handle_t rsm_sendq;
	wrsmd_msg_t 	rsm_previous_msg;
	int 		rsm_previous_msg_valid;

	/* Packet queue */
	mblk_t	*rd_queue_h,	/* queue of packets waiting to go out */
		*rd_queue_t;
	ushort_t rd_queue_len;	/* number of packets on above queue */


	/* Local transfer segment */
	caddr_t 			rd_rawmem_base_addr;
	size_t 				rd_rawmem_base_size;
	rsm_memory_local_t 		rd_memory;
	rsm_memseg_id_t 		rd_lxfersegid;
	rsm_memseg_export_handle_t 	rd_lxferhand;


	/* Remote transfer segment */
	wrsmd_xfer_hdr_t			rd_rxferhdr;
	int 				rd_rxferhdr_valid;
	off_t 				rd_rbufoff;
	boolean_t 			rd_segid_valid;
	rsm_memseg_id_t 		rd_rxfersegid;
	rsm_memseg_import_handle_t 	rd_rxferhand;
	uint16_t 			rd_lastconnmsg_seq;


	/*
	 * Free queue we're writing to (describing buffers on our node
	 * available to partner; lives on partner)
	 */
	off_t	rd_fqw_f_off;	/* First usable element in queue */
	ushort_t rd_fqw_seq;	/* Sequence number we will write next */
	ushort_t rd_num_fqws;	/* Number of usable elements in queue */


	/*
	 * Delivery queue that we're writing to (describing buffers on
	 * partner that we've filled with data; lives on partner)
	 */
	off_t	rd_dqw_f_off;	/* First usable element in queue */
	ushort_t rd_dqw_seq;	/* Sequence number we will write next */
	ushort_t rd_num_dqws;	/* Number of usable elements in queue */


	/* Buffers (on partner) that we're writing to */
	uint_t	rd_rbuflen;	/* Length of remote buffers */
	ushort_t rd_numrbuf;	/* Number of remote buffers */


	/*
	 * Free queue we're reading from (describing buffers on partner
	 * available to us; lives on our node)
	 */
	volatile wrsmd_fqe_t	/* Pointers to ... */
		*rd_fqr_f,	/* First usable element in queue */
		*rd_fqr_l,	/* Last usable element in queue */
		*rd_fqr_n;	/* Element we'll read next */
	ushort_t rd_fqr_seq;	/* Sequence number we expect to read next */
	ushort_t rd_num_fqrs;	/* Number of usable elements in queue */


	/*
	 * Delivery queue we're reading from (describing buffers on our
	 * node that the partner has filled with data; lives on our node)
	 */
	volatile wrsmd_dqe_t	/* Pointers to ... */
		*rd_dqr_f,	/* First usable element in queue */
		*rd_dqr_l,	/* Last usable element in queue */
		*rd_dqr_n;	/* Element we'll read next */
	ushort_t rd_dqr_seq;	/* Sequence number we expect to read next */
	ushort_t rd_num_dqrs;	/* Number of usable elements in queue */


	/* (Local) buffers we're reading from */
	volatile void *rd_lbuf;	/* Start of first local buffer */
	uint_t	rd_lbuflen;	/* Length of each local buffer */
	ushort_t rd_numlbufs;	/* Number of local buffers */
	wrsmdbuf_t *rd_bufbase;	/* Local buffer description structures, */
				/*  for use in loaning buffers upward */


	/* Information on cached FQE's */
	ushort_t rd_cached_fqr_cnt;	/* number of cached fqe's */
	ushort_t *rd_cached_fqr;	/* buffer numbers from cached fqe's */


	/*
	 * Shadow free queue - local copy of free queue that lives on
	 * partner
	 */
	wrsmd_fqe_t		/* Pointers to ... */
		*rd_shdwfqw_f_addr,	/* Start of alloc'd memory for queue */
		*rd_shdwfqw_f,	/* First usable element */
		*rd_shdwfqw_l,	/* Last usable element */
		*rd_shdwfqw_i,	/* Next element added to queue goes here */
		*rd_shdwfqw_o;	/* Next element transmitted comes from here */

	/*
	 * Shadow delivery queue - local copy of delivery queue that lives
	 * on partner
	 */
	wrsmd_dqe_t		/* Pointers to ... */
		*rd_shdwdqw_f_addr,	/* Start of alloc'd memory for queue */
		*rd_shdwdqw_f,	/* First usable element */
		*rd_shdwdqw_l,	/* Last usable element */
		*rd_shdwdqw_i,	/* Next element added to queue goes here */
		*rd_shdwdqw_o;	/* Next element transmitted comes from here */

	ushort_t rd_shdwfqw_errflag;	/* If nonzero, we had an error last */
					/*  time we tried to write an FQE */
	ushort_t rd_shdwdqw_errflag;	/* If nonzero, we had an error last */
					/*  time we tried to write a DQE */
	ushort_t rd_stopq;		/* If nonzero, we shouldn't try to */
					/*  sync queues, the network is down */


	/* State information */
	ushort_t rd_state;	/* State (WRSMD_STATE_xxx, see below) */
	ushort_t rd_estate;	/* Event State */
	ushort_t rd_sstate;	/* Segment state (bitmask of WRSMD_RSMS_xxx) */
	ushort_t rd_dstate;	/* Delete state (0-2), != 0 means deleting */
	short	rd_refcnt;	/* Destination reference count */


	/* Command/sequence information */
	ushort_t rd_nseq;	/* Seq # we'll put on next message */
	uchar_t	rd_recvdack;	/* Nonzero if we've gotten a valid ACK */
	uchar_t	rd_sentconn;	/* Nonzero if we've sent a CONN */


	/* Last message transmitted, for rexmits if needed */
	wrsmd_msg_t rd_lastobmsg;	/* Last outbound message */



	/* Timeout information */

	timeout_id_t rd_fqe_tmo_id;	/* timeout ID for free queue retry. */
	timeout_id_t rd_tmo_id;	/* timeout ID for empty queue retry, etc. */
	int	rd_tmo_int;	/* backoff interval for timeout */
	int	rd_tmo_tot;	/* ticks we've waited so far this timeout */

	ushort_t rd_nlb;	/* number of outstanding loaned buffers */
	ushort_t rd_nlb_del;	/* if nonzero, we're being deleted, and are */
				/*  waiting for rd_nlb to go to 0 */


	kmutex_t rd_nlb_lock;	/* mutex to protect rd_nlb/rd_nlb_del */
	kmutex_t rd_lock;	/* mutex to protect this data structure */
	kmutex_t rd_net_lock;	/* mutex to protect segment data/pointers */
	kmutex_t rd_xmit_lock; 	/* mutex to protect xmit stuff */


	struct wrsmd_dest *rd_next;	/* ptrs for svc routine run queue */
} wrsmd_dest_t;

_NOTE(READ_ONLY_DATA(wrsmd_dest::rd_wrsmdp))
_NOTE(READ_ONLY_DATA(wrsmd_dest::rd_rsm_addr))

_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_xmit_lock, wrsmd_dest::rd_queue_h))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_xmit_lock, wrsmd_dest::rd_queue_t))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_xmit_lock, wrsmd_dest::rd_queue_len))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_lock, wrsmd_dest::rd_lxferhand))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_lock, wrsmd_dest::rd_rbuflen))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wrsmd_dest::rd_rbuflen))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_lock, wrsmd_dest::rd_numrbuf))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wrsmd_dest::rd_numrbuf))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_lock, wrsmd_dest::rd_lbuf))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wrsmd_dest::rd_lbuf))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_lock, wrsmd_dest::rd_lbuflen))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wrsmd_dest::rd_lbuflen))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_lock, wrsmd_dest::rd_numlbufs))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wrsmd_dest::rd_numlbufs))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_lock, wrsmd_dest::rd_bufbase))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wrsmd_dest::rd_bufbase))

_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_net_lock, wrsmd_dest::rd_shdwfqw_f))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_net_lock, wrsmd_dest::rd_shdwfqw_l))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_net_lock, wrsmd_dest::rd_shdwfqw_i))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_net_lock, wrsmd_dest::rd_shdwfqw_o))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_net_lock, wrsmd_dest::rd_fqw_seq))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_net_lock, wrsmd_dest::rd_shdwdqw_f))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_net_lock, wrsmd_dest::rd_shdwdqw_l))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_net_lock, wrsmd_dest::rd_shdwdqw_i))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_net_lock, wrsmd_dest::rd_shdwdqw_o))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_net_lock, wrsmd_dest::rd_dqw_seq))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_net_lock, wrsmd_dest::rd_fqr_f))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_net_lock, wrsmd_dest::rd_fqr_l))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_net_lock, wrsmd_dest::rd_fqr_n))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_net_lock, wrsmd_dest::rd_fqr_seq))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_net_lock, wrsmd_dest::rd_dqr_f))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_net_lock, wrsmd_dest::rd_dqr_l))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_net_lock, wrsmd_dest::rd_dqr_n))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_net_lock, wrsmd_dest::rd_dqr_seq))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_net_lock,
    wrsmd_dest::rd_cached_fqr_cnt))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_net_lock, wrsmd_dest::rd_cached_fqr))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_net_lock,
    wrsmd_dest::rd_shdwfqw_errflag))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_net_lock,
    wrsmd_dest::rd_shdwdqw_errflag))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_net_lock, wrsmd_dest::rd_stopq))

_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_xmit_lock, wrsmd_dest::rd_tmo_id))
_NOTE(DATA_READABLE_WITHOUT_LOCK(wrsmd_dest::rd_tmo_id))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_xmit_lock, wrsmd_dest::rd_tmo_int))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_xmit_lock, wrsmd_dest::rd_tmo_tot))

_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_nlb_lock, wrsmd_dest::rd_nlb))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd_dest::rd_nlb_lock, wrsmd_dest::rd_nlb_del))

_NOTE(MUTEX_PROTECTS_DATA(wrsmd::wrsmd_runq_lock, wrsmd_dest::rd_state))
_NOTE(SCHEME_PROTECTS_DATA("see comment below", wrsmd_dest::rd_next))

_NOTE(MUTEX_PROTECTS_DATA(wrsmd::wrsmd_dest_lock, wrsmd_dest::rd_dstate))
_NOTE(MUTEX_PROTECTS_DATA(wrsmd::wrsmd_dest_lock, wrsmd_dest::rd_refcnt))


/*
 * Run queue:
 *
 * Certain operations on destinations are performed by the driver's write
 * service routine (wrsmd_wsrv).  In order to arrange for this, there is a
 * queue of destinations waiting to be processed by the service routine.
 * Each device's wrsmd_runq points to the head of this queue of destinations,
 * which are linked together via rd_next.  Whenever the service routine
 * runs, after it has served its usual purpose of processing messages from
 * the stream's service queue, it traverses its list of destinations and
 * performs appropriate operations on them, depending on their state.
 *
 * The rd_next pointer is protected by the runq_lock everywhere but in the
 * middle of the service routine.  Essentially, the service routine takes a
 * whole chain of destination entries off of the run queue at once (inside
 * the runq_lock), and then traverses the list (outside the runq_lock).  Since
 * a scheduled destination should never be given a new state except by the
 * service routine, there should be no conflicting updates to rd_next.
 *
 * Destination states:
 *
 * A scheduled state means the destination is on the run queue; an unscheduled
 * state means the destination is not.  State transitions are always from
 * scheduled to unscheduled or vice versa.
 *
 * A state with a name of the form WRSMD_STATE_S_xxx is a scheduled state where
 * the service routine is going to do xxx next.  These states have odd numbers.
 *
 * A state with a name of the form WRSMD_STATE_W_xxx is an unscheduled state
 * where we are waiting for xxx to happen.  These states have even numbers.
 */

#define	WRSMD_STATE_NEW			0	/* Newly created */
#define	WRSMD_STATE_INPROGRESS		1000	/* Being processed */
#define	WRSMD_STATE_DELETING		2000	/* Being deleted */

#define	WRSMD_STATE_W_SCONNTMO		2	/* Waiting for conn rxmit tmo */
#define	WRSMD_STATE_W_ACCEPT		4	/* Waiting for accept msg */
#define	WRSMD_STATE_W_ACK		6	/* Waiting for ack msg */
#define	WRSMD_STATE_W_READY		8	/* Connected, wait for pkt */
#define	WRSMD_STATE_W_FQE		10	/* Waiting for fqe to xmit */

#define	WRSMD_STATE_S_REQ_CONNECT	1	/* Srv: send conn request */
#define	WRSMD_STATE_S_NEWCONN		3	/* Srv: setup/accept new conn */
#define	WRSMD_STATE_S_CONNXFER_ACCEPT	5	/* Srv: connxfer, then accept */
#define	WRSMD_STATE_S_CONNXFER_ACK	7	/* Srv: connxfer, then ack */
#define	WRSMD_STATE_S_XFER		9	/* Srv: xfer data */
#define	WRSMD_STATE_S_DELETE		11	/* Srv: delete this dest */
#define	WRSMD_STATE_S_SCONN		13	/* Srv: resend last conn */

#define	WRSMD_SCHED_STATE(s)	((s) & 1)

#define	WRSMD_STATE_STR(x) (						\
	(x == WRSMD_STATE_NEW) ? "WRSMD_STATE_NEW" :			\
	(x == WRSMD_STATE_INPROGRESS) ? "WRSMD_STATE_INPROGRESS" :	\
	(x == WRSMD_STATE_DELETING) ? "WRSMD_STATE_DELETING" :		\
	(x == WRSMD_STATE_W_SCONNTMO) ? "WRSMD_STATE_W_SCONNTMO" :	\
	(x == WRSMD_STATE_W_ACCEPT) ? "WRSMD_STATE_W_ACCEPT" :		\
	(x == WRSMD_STATE_W_ACK) ? "WRSMD_STATE_W_ACK" :		\
	(x == WRSMD_STATE_W_READY) ? "WRSMD_STATE_W_READY" :		\
	(x == WRSMD_STATE_W_FQE) ? "WRSMD_STATE_W_FQE" :		\
	(x == WRSMD_STATE_S_REQ_CONNECT) ? "WRSMD_STATE_S_REQ_CONNECT" :\
	(x == WRSMD_STATE_S_NEWCONN) ? "WRSMD_STATE_S_NEWCONN" :	\
	(x == WRSMD_STATE_S_CONNXFER_ACCEPT) ? \
	    "WRSMD_STATE_S_CONNXFER_ACCEPT" : \
	(x == WRSMD_STATE_S_CONNXFER_ACK) ? "WRSMD_STATE_S_CONNXFER_ACK" : \
	(x == WRSMD_STATE_S_XFER) ? "WRSMD_STATE_S_XFER" :		\
	(x == WRSMD_STATE_S_DELETE) ? "WRSMD_STATE_S_DELETE" :		\
	(x == WRSMD_STATE_S_SCONN) ? "WRSMD_STATE_S_SCONN" :		\
	"unknown")


/*
 * RSM driver state - basically, what segments we've created/connected.  We
 * keep a bitmask of the ones we've done, so that when we delete a
 * destination we don't try and undo something we never did.  Also, we
 * sometimes check to make sure rd_sstate is WRSMD_RSMS_ALL before trying to
 * perform an operation on a destination, to ensure we don't get ahead of
 * our initialization.
 */

#define	WRSMD_RSMS_LXFER_C	0x01	/* Create local xfer segment */
#define	WRSMD_RSMS_LXFER_P	0x02	/* Publish local xfer segment */
#define	WRSMD_RSMS_RXFER_S	0x04	/* Create send queue to remote node */
#define	WRSMD_RSMS_RXFER_C	0x10	/* Connect to remote xfer */

#define	WRSMD_RSMS_ALL	\
	(WRSMD_RSMS_LXFER_C | WRSMD_RSMS_LXFER_P | WRSMD_RSMS_RXFER_S | \
	WRSMD_RSMS_RXFER_C)

#endif	/* _KERNEL */


#ifdef __cplusplus
}
#endif


#endif	/* _SYS_WRSMD_H_ */
