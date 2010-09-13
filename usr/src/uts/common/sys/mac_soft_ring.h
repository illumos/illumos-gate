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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_MAC_SOFT_RING_H
#define	_SYS_MAC_SOFT_RING_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/cpuvar.h>
#include <sys/cpupart.h>
#include <sys/processor.h>
#include <sys/stream.h>
#include <sys/squeue.h>
#include <sys/dlpi.h>
#include <sys/mac_impl.h>
#include <sys/mac_stat.h>

#define	S_RING_NAMELEN 64

#define	MAX_SR_FANOUT	24

extern boolean_t mac_soft_ring_enable;
extern boolean_t mac_latency_optimize;

typedef struct mac_soft_ring_s mac_soft_ring_t;
typedef struct mac_soft_ring_set_s mac_soft_ring_set_t;

typedef void (*mac_soft_ring_drain_func_t)(mac_soft_ring_t *);
typedef mac_tx_cookie_t (*mac_tx_func_t)(mac_soft_ring_set_t *, mblk_t *,
    uintptr_t, uint16_t, mblk_t **);


/* Tx notify callback */
typedef struct mac_tx_notify_cb_s {
	mac_cb_t		mtnf_link;	/* Linked list of callbacks */
	mac_tx_notify_t		mtnf_fn;	/* The callback function */
	void			*mtnf_arg;	/* Callback function argument */
} mac_tx_notify_cb_t;

struct mac_soft_ring_s {
	/* Keep the most used members 64bytes cache aligned */
	kmutex_t	s_ring_lock;	/* lock before using any member */
	uint16_t	s_ring_type;	/* processing model of the sq */
	uint16_t	s_ring_state;	/* state flags and message count */
	int		s_ring_count;	/* # of mblocks in mac_soft_ring */
	size_t		s_ring_size;	/* Size of data queued */
	mblk_t		*s_ring_first;	/* first mblk chain or NULL */
	mblk_t		*s_ring_last;	/* last mblk chain or NULL */

	mac_direct_rx_t	s_ring_rx_func;
	void		*s_ring_rx_arg1;
	mac_resource_handle_t  s_ring_rx_arg2;

	/*
	 * Threshold after which packets get dropped.
	 * Is always greater than s_ring_tx_hiwat
	 */
	int		s_ring_tx_max_q_cnt;
	/* # of mblocks after which to apply flow control */
	int		s_ring_tx_hiwat;
	/* # of mblocks after which to relieve flow control */
	int		s_ring_tx_lowat;
	boolean_t	s_ring_tx_woken_up;
	uint32_t	s_ring_hiwat_cnt;	/* times blocked for Tx descs */

	void		*s_ring_tx_arg1;
	void		*s_ring_tx_arg2;

	/* Tx notify callback */
	mac_cb_info_t	s_ring_notify_cb_info;		/* cb list info */
	mac_cb_t	*s_ring_notify_cb_list;		/* The cb list */

	clock_t		s_ring_awaken;	/* time async thread was awakened */

	kthread_t	*s_ring_run;	/* Current thread processing sq */
	processorid_t	s_ring_cpuid;	/* processor to bind to */
	processorid_t	s_ring_cpuid_save;	/* saved cpuid during offline */
	kcondvar_t	s_ring_async;	/* async thread blocks on */
	clock_t		s_ring_wait;	/* lbolts to wait after a fill() */
	timeout_id_t	s_ring_tid;	/* timer id of pending timeout() */
	kthread_t	*s_ring_worker;	/* kernel thread id */
	char		s_ring_name[S_RING_NAMELEN + 1];
	uint32_t	s_ring_total_inpkt;
	uint32_t	s_ring_total_rbytes;
	uint32_t	s_ring_drops;
	struct mac_client_impl_s *s_ring_mcip;
	kstat_t		*s_ring_ksp;

	/* Teardown, poll disable control ops */
	kcondvar_t	s_ring_client_cv; /* Client wait for control op */

	mac_soft_ring_set_t *s_ring_set;   /* The SRS this ring belongs to */
	mac_soft_ring_t	*s_ring_next;
	mac_soft_ring_t	*s_ring_prev;
	mac_soft_ring_drain_func_t s_ring_drain_func;

	mac_tx_stats_t	s_st_stat;
};

typedef void (*mac_srs_drain_proc_t)(mac_soft_ring_set_t *, uint_t);

/* Transmit side Soft Ring Set */
typedef struct mac_srs_tx_s {
	/* Members for Tx size processing */
	uint32_t	st_mode;
	mac_tx_func_t	st_func;
	void		*st_arg1;
	void		*st_arg2;
	mac_group_t	*st_group;	/* TX group for share */
	boolean_t	st_woken_up;

	/*
	 * st_max_q_cnt is the queue depth threshold to limit
	 * outstanding packets on the Tx SRS. Once the limit
	 * is reached, Tx SRS will drop packets until the
	 * limit goes below the threshold.
	 */
	uint32_t	st_max_q_cnt;	/* max. outstanding packets */
	/*
	 * st_hiwat is used Tx serializer and bandwidth mode.
	 * This is the queue depth threshold upto which
	 * packets will get buffered with no flow-control
	 * back pressure applied to the caller. Once this
	 * threshold is reached, back pressure will be
	 * applied to the caller of mac_tx() (mac_tx() starts
	 * returning a cookie to indicate a blocked SRS).
	 * st_hiwat should always be lesser than or equal to
	 * st_max_q_cnt.
	 */
	uint32_t	st_hiwat;	/* mblk cnt to apply flow control */
	uint32_t	st_lowat;	/* mblk cnt to relieve flow control */
	uint32_t	st_hiwat_cnt; /* times blocked for Tx descs */
	mac_tx_stats_t	st_stat;
	mac_capab_aggr_t	st_capab_aggr;
	/*
	 * st_soft_rings is used as an array to store aggr Tx soft
	 * rings. When aggr_find_tx_ring() returns a pseudo ring,
	 * the associated soft ring has to be found. st_soft_rings
	 * array stores the soft ring associated with a pseudo Tx
	 * ring and it can be accessed using the pseudo ring
	 * index (mr_index). Note that the ring index is unique
	 * for each ring in a group.
	 */
	mac_soft_ring_t **st_soft_rings;
} mac_srs_tx_t;

/* Receive side Soft Ring Set */
typedef struct mac_srs_rx_s {
	/*
	 * Upcall Function for fanout, Rx processing etc. Perhaps
	 * the same 3 members below can be used for Tx
	 * processing, but looking around, mac_rx_func_t has
	 * proliferated too much into various files at different
	 * places. I am leaving the consolidation battle for
	 * another day.
	 */
	mac_direct_rx_t		sr_func;	/* srs_lock */
	void			*sr_arg1;	/* srs_lock */
	mac_resource_handle_t 	sr_arg2;	/* srs_lock */
	mac_rx_func_t		sr_lower_proc;	/* Atomically changed */
	uint32_t		sr_poll_pkt_cnt;
	uint32_t		sr_poll_thres;

	/* mblk cnt to apply flow control */
	uint32_t		sr_hiwat;
	/* mblk cnt to relieve flow control */
	uint32_t		sr_lowat;
	mac_rx_stats_t		sr_stat;

	/* Times polling was enabled */
	uint32_t		sr_poll_on;
	/* Times polling was enabled by worker thread */
	uint32_t		sr_worker_poll_on;
	/* Times polling was disabled */
	uint32_t		sr_poll_off;
	/* Poll thread signalled count */
	uint32_t		sr_poll_thr_sig;
	/* Poll thread busy */
	uint32_t		sr_poll_thr_busy;
	/* SRS drains, stays in poll mode but doesn't poll */
	uint32_t		sr_poll_drain_no_poll;
	/*
	 * SRS has nothing to do and no packets in H/W but
	 * there is a backlog in softrings. SRS stays in
	 * poll mode but doesn't do polling.
	 */
	uint32_t		sr_poll_no_poll;
	/* Active polling restarted */
	uint32_t		sr_below_hiwat;
	/* Found packets in last poll so try and poll again */
	uint32_t		sr_poll_again;
	/*
	 * Packets in queue but poll thread not allowed to process so
	 * signal the worker thread.
	 */
	uint32_t		sr_poll_sig_worker;
	/*
	 * Poll thread has nothing to do and H/W has nothing so
	 * reenable the interrupts.
	 */
	uint32_t		sr_poll_intr_enable;
	/*
	 * Poll thread has nothing to do and worker thread was already
	 * running so it can decide to reenable interrupt or poll again.
	 */
	uint32_t		sr_poll_goto_sleep;
	/* Worker thread goes back to draining the queue */
	uint32_t		sr_drain_again;
	/* More Packets in queue so signal the poll thread to drain */
	uint32_t		sr_drain_poll_sig;
	/* More Packets in queue so signal the worker thread to drain */
	uint32_t		sr_drain_worker_sig;
	/* Poll thread is already running so worker has nothing to do */
	uint32_t		sr_drain_poll_running;
	/* We have packets already queued so keep polling */
	uint32_t		sr_drain_keep_polling;
	/* Drain is done and interrupts are reenabled */
	uint32_t		sr_drain_finish_intr;
	/* Polling thread needs to schedule worker wakeup */
	uint32_t		sr_poll_worker_wakeup;
} mac_srs_rx_t;

/*
 * mac_soft_ring_set_s:
 * This is used both for Tx and Rx side. The srs_type identifies Rx or
 * Tx type.
 *
 * Note that the structure is carefully crafted, with Rx elements coming
 * first followed by Tx specific members. Future additions to this
 * structure should follow the same guidelines.
 *
 * Rx-side notes:
 * mac_rx_classify_flow_add() always creates a mac_soft_ring_set_t and fn_flow
 * points to info from it (func = srs_lower_proc, arg = soft_ring_set). On
 * interrupt path, srs_lower_proc does B/W adjustment and switch to polling mode
 * (if poll capable) and feeds the packets to soft_ring_list via choosen
 * fanout type (specified by srs_type). In poll mode, the poll thread which is
 * also a pointer can pick up the packets and feed them to various
 * soft_ring_list.
 *
 * The srs_type can either be protocol based or fanout based where fanout itelf
 * can be various types
 *
 * The polling works by turning off interrupts as soon as a packets
 * are queued on the soft ring set. Once the backlog is clear and poll
 * thread return empty handed i.e. Rx ring doesn't have anything, the
 * interrupt is turned back on. For this purpose we keep a separate
 * srs_poll_pkt_cnt counter which tracks the packets queued between SRS
 * and the soft rings as well. The counter is incremented when packets
 * are queued and decremented when SRS processes them (in case it has
 * no soft rings) or the soft ring process them. Its important that
 * in case SRS has softrings, the decrement doesn't happen till the
 * packet is processed by the soft rings since it takes very little time
 * for SRS to queue packet from SRS to soft rings and it will keep
 * bringing more packets in the system faster than soft rings can
 * process them.
 *
 * Tx side notes:
 * The srs structure acts as a serializer with a worker thread. The
 * default behavior of srs though is to act as a pass-thru. The queues
 * (srs_first, srs_last, srs_count) get used when Tx ring runs out of Tx
 * descriptors or to enforce bandwidth limits.
 *
 * When multiple Tx rings are present, the SRS state will be set to
 * SRS_FANOUT_OTH. Outgoing packets coming into mac_tx_srs_process()
 * function will be fanned out to one of the Tx side soft rings based on
 * a hint passed in mac_tx_srs_process(). Each soft ring, in turn, will
 * be associated with a distinct h/w Tx ring.
 */

struct mac_soft_ring_set_s {
	/*
	 * Common elements, common to both Rx and Tx SRS type.
	 * The following block of fields are protected by srs_lock
	 */
	kmutex_t	srs_lock;
	uint32_t	srs_type;
	uint32_t	srs_state;	/* state flags */
	uint32_t	srs_count;
	mblk_t		*srs_first;	/* first mblk chain or NULL */
	mblk_t		*srs_last;	/* last mblk chain or NULL */
	kcondvar_t	srs_async;	/* cv for worker thread */
	kcondvar_t	srs_cv;		/* cv for poll thread */
	kcondvar_t	srs_quiesce_done_cv;	/* cv for removal */
	timeout_id_t	srs_tid;	/* timeout id for pending timeout */

	/*
	 * List of soft rings & processing function.
	 * The following block is protected by Rx quiescence.
	 * i.e. they can be changed only after quiescing the SRS
	 * Protected by srs_lock.
	 */
	mac_soft_ring_t	*srs_soft_ring_head;
	mac_soft_ring_t	*srs_soft_ring_tail;
	int		srs_soft_ring_count;
	int		srs_soft_ring_quiesced_count;
	int		srs_soft_ring_condemned_count;
	mac_soft_ring_t	**srs_tcp_soft_rings;
	int		srs_tcp_ring_count;
	mac_soft_ring_t	**srs_udp_soft_rings;
	int		srs_udp_ring_count;
	mac_soft_ring_t	**srs_oth_soft_rings;
	int		srs_oth_ring_count;
	/*
	 * srs_tx_soft_rings is used by tx_srs in
	 * when operating in multi tx ring mode.
	 */
	mac_soft_ring_t	**srs_tx_soft_rings;
	int		srs_tx_ring_count;

	/*
	 * Bandwidth control related members.
	 * They are common to both Rx- and Tx-side.
	 * Following protected by srs_lock
	 */
	mac_bw_ctl_t	*srs_bw;
	size_t		srs_size;	/* Size of packets queued in bytes */
	pri_t		srs_pri;

	mac_soft_ring_set_t	*srs_next;	/* mac_srs_g_lock */
	mac_soft_ring_set_t	*srs_prev;	/* mac_srs_g_lock */

	/* Attribute specific drain func (BW ctl vs non-BW ctl)	*/
	mac_srs_drain_proc_t	srs_drain_func;	/* Write once (WO) */

	/*
	 * If the associated ring is exclusively used by a mac client, e.g.,
	 * an aggregation, this fields is used to keep a reference to the
	 * MAC client's pseudo ring.
	 */
	mac_resource_handle_t	srs_mrh;
	/*
	 * The following blocks are write once (WO) and valid for the life
	 * of the SRS
	 */
	struct mac_client_impl_s *srs_mcip;	/* back ptr to mac client */
	void			*srs_flent;	/* back ptr to flent */
	mac_ring_t		*srs_ring;	/*  Ring Descriptor */

	/* Teardown, disable control ops */
	kcondvar_t	srs_client_cv;	/* Client wait for the control op */

	kthread_t	*srs_worker;	/* WO, worker thread */
	kthread_t	*srs_poll_thr;	/* WO, poll thread */

	uint_t		srs_ind;	/* Round Robin indx for picking up SR */
	processorid_t	srs_worker_cpuid;	/* processor to bind to */
	processorid_t	srs_worker_cpuid_save;	/* saved cpuid during offline */
	processorid_t	srs_poll_cpuid;		/* processor to bind to */
	processorid_t	srs_poll_cpuid_save;	/* saved cpuid during offline */
	uint_t		srs_fanout_state;
	mac_cpus_t	srs_cpu;

	mac_srs_rx_t	srs_rx;
	mac_srs_tx_t	srs_tx;
	kstat_t		*srs_ksp;
};

/*
 * type flags - combination allowed to process and drain the queue
 */
#define	ST_RING_WORKER_ONLY  	0x0001	/* Worker thread only */
#define	ST_RING_ANY		0x0002	/* Any thread can process the queue */
#define	ST_RING_TCP		0x0004
#define	ST_RING_UDP		0x0008
#define	ST_RING_OTH		0x0010

#define	ST_RING_BW_CTL		0x0020
#define	ST_RING_TX		0x0040

/*
 * State flags.
 */
#define	S_RING_PROC		0x0001	/* being processed */
#define	S_RING_BOUND		0x0002	/* Worker thread is bound to a cpu */
#define	S_RING_BLOCK		0x0004	/* No Tx descs */
#define	S_RING_TX_HIWAT		0x0008	/* Tx high watermark reached */

#define	S_RING_WAKEUP_CLIENT	0x0010	/* flow ctrl, client wakeup needed */
#define	S_RING_BLANK		0x0020	/* Has been put into polling mode */
#define	S_RING_CLIENT_WAIT	0x0040	/* Client waiting for control op */

#define	S_RING_CONDEMNED	0x0100	/* Being torn down */
#define	S_RING_CONDEMNED_DONE	0x0200	/* Being torn down */
#define	S_RING_QUIESCE		0x0400	/* No traffic flow, transient flag */
#define	S_RING_QUIESCE_DONE	0x0800	/* No traffic flow, transient flag */

#define	S_RING_RESTART		0x1000	/* Go back to normal traffic flow */
#define	S_RING_ENQUEUED		0x2000	/* Pkts enqueued in Tx soft ring */

/*
 * arguments for processors to bind to
 */
#define	S_RING_BIND_NONE	-1

/*
 * defines for srs_type - identifies a link or a sub-flow
 * and other static characteristics of a SRS like a tx
 * srs, tcp only srs, etc.
 */
#define	SRST_LINK		0x00000001
#define	SRST_FLOW		0x00000002
#define	SRST_NO_SOFT_RINGS	0x00000004
#define	SRST_TCP_ONLY		0x00000008

#define	SRST_FANOUT_PROTO	0x00000010
#define	SRST_FANOUT_SRC_IP	0x00000020
#define	SRST_FANOUT_OTH		0x00000040
#define	SRST_DEFAULT_GRP	0x00000080

#define	SRST_TX			0x00000100
#define	SRST_BW_CONTROL		0x00000200
#define	SRST_DIRECT_POLL	0x00000400

#define	SRST_DLS_BYPASS		0x00001000
#define	SRST_CLIENT_POLL_ENABLED 0x00002000

/*
 * soft ring set flags. These bits are dynamic in nature and get
 * applied to srs_state. They reflect the state of SRS at any
 * point of time
 */
#define	SRS_BLANK		0x00000001
#define	SRS_WORKER_BOUND	0x00000002
#define	SRS_POLL_BOUND		0x00000004
#define	SRS_POLLING_CAPAB	0x00000008

#define	SRS_PROC		0x00000010
#define	SRS_GET_PKTS		0x00000020
#define	SRS_POLLING		0x00000040
#define	SRS_BW_ENFORCED		0x00000080

#define	SRS_WORKER		0x00000100
#define	SRS_ENQUEUED		0x00000200
#define	SRS_ANY_PROCESS		0x00000400
#define	SRS_PROC_FAST		0x00000800

#define	SRS_POLL_PROC		0x00001000
#define	SRS_TX_BLOCKED		0x00002000	/* out of Tx descs */
#define	SRS_TX_HIWAT		0x00004000	/* Tx count exceeds hiwat */
#define	SRS_TX_WAKEUP_CLIENT	0x00008000	/* Flow-ctl: wakeup client */

#define	SRS_CLIENT_PROC		0x00010000
#define	SRS_CLIENT_WAIT		0x00020000
#define	SRS_QUIESCE		0x00040000
#define	SRS_QUIESCE_DONE	0x00080000

#define	SRS_CONDEMNED		0x00100000
#define	SRS_CONDEMNED_DONE	0x00200000
#define	SRS_POLL_THR_QUIESCED	0x00400000
#define	SRS_RESTART		0x00800000

#define	SRS_RESTART_DONE	0x01000000
#define	SRS_POLL_THR_RESTART	0x02000000
#define	SRS_IN_GLIST		0x04000000
#define	SRS_POLL_THR_EXITED	0x08000000

#define	SRS_QUIESCE_PERM	0x10000000
#define	SRS_LATENCY_OPT		0x20000000
#define	SRS_SOFTRING_QUEUE	0x40000000

#define	SRS_QUIESCED(srs)	(srs->srs_state & SRS_QUIESCE_DONE)

/*
 * If the SRS_QUIESCE_PERM flag is set, the SRS worker thread will not be
 * able to be restarted.
 */
#define	SRS_QUIESCED_PERMANENT(srs)	(srs->srs_state & SRS_QUIESCE_PERM)

/*
 * soft ring set (SRS) Tx modes
 */
typedef enum {
	SRS_TX_DEFAULT = 0,
	SRS_TX_SERIALIZE,
	SRS_TX_FANOUT,
	SRS_TX_BW,
	SRS_TX_BW_FANOUT,
	SRS_TX_AGGR,
	SRS_TX_BW_AGGR
} mac_tx_srs_mode_t;

/*
 * SRS fanout states
 */
typedef enum {
	SRS_FANOUT_UNINIT = 0,
	SRS_FANOUT_INIT,
	SRS_FANOUT_REINIT
} mac_srs_fanout_state_t;

/*
 * Structure for dls statistics
 */
struct dls_kstats {
	kstat_named_t	dlss_soft_ring_pkt_drop;
};

extern struct dls_kstats dls_kstat;

#define	DLS_BUMP_STAT(x, y)	(dls_kstat.x.value.ui32 += y)

/* Turn dynamic polling off */
#define	MAC_SRS_POLLING_OFF(mac_srs) {					\
	ASSERT(MUTEX_HELD(&(mac_srs)->srs_lock));			\
	if (((mac_srs)->srs_state & (SRS_POLLING_CAPAB|SRS_POLLING)) == \
	    (SRS_POLLING_CAPAB|SRS_POLLING)) {				\
		(mac_srs)->srs_state &= ~SRS_POLLING;			\
		(void) mac_hwring_enable_intr((mac_ring_handle_t)	\
		    (mac_srs)->srs_ring);				\
		(mac_srs)->srs_rx.sr_poll_off++;			\
	}								\
}

#define	MAC_COUNT_CHAIN(mac_srs, head, tail, cnt, sz)	{	\
	mblk_t 		*tmp;		       			\
	boolean_t	bw_ctl = B_FALSE;			\
								\
	ASSERT((head) != NULL);					\
	cnt = 0;						\
	sz = 0;							\
	if ((mac_srs)->srs_type & SRST_BW_CONTROL)		\
		bw_ctl = B_TRUE;				\
	tmp = tail = (head);					\
	if ((head)->b_next == NULL) {				\
		cnt = 1;					\
		if (bw_ctl)					\
			sz += msgdsize(head);			\
	} else {						\
		while (tmp != NULL) {				\
			tail = tmp;				\
			cnt++;					\
			if (bw_ctl)				\
				sz += msgdsize(tmp);		\
			tmp = tmp->b_next;			\
		}						\
	}							\
}

/*
 * Decrement the cumulative packet count in SRS and its
 * soft rings. If the srs_poll_pkt_cnt goes below lowat, then check
 * if if the interface was left in a polling mode and no one
 * is really processing the queue (to get the interface out
 * of poll mode). If no one is processing the queue, then
 * acquire the PROC and signal the poll thread to check the
 * interface for packets and get the interface back to interrupt
 * mode if nothing is found.
 */
#define	MAC_UPDATE_SRS_COUNT_LOCKED(mac_srs, cnt) {		        \
	mac_srs_rx_t	*srs_rx = &(mac_srs)->srs_rx;			\
	ASSERT(MUTEX_HELD(&(mac_srs)->srs_lock));			\
									\
	srs_rx->sr_poll_pkt_cnt -= cnt;					\
	if ((srs_rx->sr_poll_pkt_cnt <= srs_rx->sr_poll_thres) && 	\
		(((mac_srs)->srs_state &				\
		(SRS_POLLING|SRS_PROC|SRS_GET_PKTS)) == SRS_POLLING))	\
	{								\
		(mac_srs)->srs_state |= (SRS_PROC|SRS_GET_PKTS);	\
		cv_signal(&(mac_srs)->srs_cv); 				\
		srs_rx->sr_below_hiwat++;				\
	}								\
}

/*
 * The following two macros are used to update the inbound packet and byte.
 * count. The packet and byte count reflect the packets and bytes that are
 * taken out of the SRS's queue, i.e. indicating they are being delivered.
 * The srs_count and srs_size are updated in different locations as the
 * srs_size is also used to take into account any bandwidth limits. The
 * srs_size is updated only when a soft ring, if any, sends a packet up,
 * as opposed to updating it when the SRS sends a packet to the SR, i.e.
 * the srs_size reflects the packets in the SRS and SRs. These
 * macros decrement the srs_size and srs_count and also increment the
 * ipackets and ibytes stats resp.
 *
 * xxx-venu These are done under srs_lock, for now we still update
 * mci_stat_ibytes/mci_stat_ipackets atomically, need to check if
 * just updating them would be accurate enough.
 *
 * If we are updating these for a sub-flow SRS, then we need to also
 * updated it's MAC client bandwidth info, if the MAC client is also
 * bandwidth regulated.
 */
#define	MAC_UPDATE_SRS_SIZE_LOCKED(srs, sz) {				\
	if ((srs)->srs_type & SRST_BW_CONTROL) {			\
		mutex_enter(&(srs)->srs_bw->mac_bw_lock);		\
		(srs)->srs_bw->mac_bw_sz -= (sz);			\
		(srs)->srs_bw->mac_bw_used += (sz);			\
		mutex_exit(&(srs)->srs_bw->mac_bw_lock);		\
	}								\
}

#define	MAC_TX_UPDATE_BW_INFO(srs, sz) {				\
	(srs)->srs_bw->mac_bw_sz -= (sz);				\
	(srs)->srs_bw->mac_bw_used += (sz);				\
}

#define	MAC_TX_SOFT_RINGS(mac_srs) ((mac_srs)->srs_tx_ring_count >= 1)

/* Soft ring flags for teardown */
#define	SRS_POLL_THR_OWNER	(SRS_PROC | SRS_POLLING | SRS_GET_PKTS)
#define	SRS_PAUSE		(SRS_CONDEMNED | SRS_QUIESCE)
#define	S_RING_PAUSE		(S_RING_CONDEMNED | S_RING_QUIESCE)

/* Soft rings */
extern void mac_soft_ring_init(void);
extern void mac_soft_ring_finish(void);
extern void mac_fanout_setup(mac_client_impl_t *, flow_entry_t *,
    mac_resource_props_t *, mac_direct_rx_t, void *, mac_resource_handle_t,
    cpupart_t *);

extern void mac_soft_ring_worker_wakeup(mac_soft_ring_t *);
extern void mac_soft_ring_blank(void *, time_t, uint_t, int);
extern mblk_t *mac_soft_ring_poll(mac_soft_ring_t *, int);
extern void mac_soft_ring_destroy(mac_soft_ring_t *);
extern void mac_soft_ring_dls_bypass(void *, mac_direct_rx_t, void *);

/* Rx SRS */
extern mac_soft_ring_set_t *mac_srs_create(struct mac_client_impl_s *,
    flow_entry_t *, uint32_t, mac_direct_rx_t, void *, mac_resource_handle_t,
    mac_ring_t *);
extern void mac_srs_free(mac_soft_ring_set_t *);
extern void mac_srs_signal(mac_soft_ring_set_t *, uint_t);
extern cpu_t *mac_srs_bind(mac_soft_ring_set_t *, processorid_t);
extern void mac_rx_srs_retarget_intr(mac_soft_ring_set_t *, processorid_t);
extern void mac_tx_srs_retarget_intr(mac_soft_ring_set_t *);

extern void mac_srs_change_upcall(void *, mac_direct_rx_t, void *);
extern void mac_srs_quiesce_initiate(mac_soft_ring_set_t *);
extern void mac_srs_client_poll_enable(struct mac_client_impl_s *,
    mac_soft_ring_set_t *);
extern void mac_srs_client_poll_disable(struct mac_client_impl_s *,
    mac_soft_ring_set_t *);
extern void mac_srs_client_poll_quiesce(struct mac_client_impl_s *,
    mac_soft_ring_set_t *);
extern void mac_srs_client_poll_restart(struct mac_client_impl_s *,
    mac_soft_ring_set_t *);
extern void mac_rx_srs_quiesce(mac_soft_ring_set_t *, uint_t);
extern void mac_rx_srs_restart(mac_soft_ring_set_t *);
extern void mac_rx_srs_subflow_process(void *, mac_resource_handle_t, mblk_t *,
    boolean_t);
extern void mac_tx_srs_quiesce(mac_soft_ring_set_t *, uint_t);

/* Tx SRS, Tx softring */
extern void mac_tx_srs_wakeup(mac_soft_ring_set_t *, mac_ring_handle_t);
extern void mac_tx_srs_setup(struct mac_client_impl_s *, flow_entry_t *);
extern mac_tx_func_t mac_tx_get_func(uint32_t);
extern mblk_t *mac_tx_send(mac_client_handle_t, mac_ring_handle_t, mblk_t *,
    mac_tx_stats_t *);
extern boolean_t mac_tx_srs_ring_present(mac_soft_ring_set_t *, mac_ring_t *);
extern mac_soft_ring_t *mac_tx_srs_get_soft_ring(mac_soft_ring_set_t *,
    mac_ring_t *);
extern void mac_tx_srs_add_ring(mac_soft_ring_set_t *, mac_ring_t *);
extern void mac_tx_srs_del_ring(mac_soft_ring_set_t *, mac_ring_t *);
extern mac_tx_cookie_t mac_tx_srs_no_desc(mac_soft_ring_set_t *, mblk_t *,
    uint16_t, mblk_t **);

/* Subflow specific stuff */
extern int mac_srs_flow_create(struct mac_client_impl_s *, flow_entry_t *,
    mac_resource_props_t *, int, int, mac_direct_rx_t);
extern void mac_srs_update_bwlimit(flow_entry_t *, mac_resource_props_t *);
extern void mac_srs_adjust_subflow_bwlimit(struct mac_client_impl_s *);
extern void mac_srs_update_drv(struct mac_client_impl_s *);
extern void mac_update_srs_priority(mac_soft_ring_set_t *, pri_t);
extern void mac_client_update_classifier(mac_client_impl_t *, boolean_t);

extern void mac_soft_ring_intr_enable(void *);
extern boolean_t mac_soft_ring_intr_disable(void *);
extern mac_soft_ring_t *mac_soft_ring_create(int, clock_t, uint16_t,
    pri_t, mac_client_impl_t *, mac_soft_ring_set_t *,
    processorid_t, mac_direct_rx_t, void *, mac_resource_handle_t);
extern cpu_t *mac_soft_ring_bind(mac_soft_ring_t *, processorid_t);
	extern void mac_soft_ring_unbind(mac_soft_ring_t *);
extern void mac_soft_ring_free(mac_soft_ring_t *);
extern void mac_soft_ring_signal(mac_soft_ring_t *, uint_t);
extern void mac_rx_soft_ring_process(mac_client_impl_t *, mac_soft_ring_t *,
    mblk_t *, mblk_t *, int, size_t);
extern mac_tx_cookie_t mac_tx_soft_ring_process(mac_soft_ring_t *,
    mblk_t *, uint16_t, mblk_t **);
extern void mac_srs_worker_quiesce(mac_soft_ring_set_t *);
extern void mac_srs_worker_restart(mac_soft_ring_set_t *);
extern void mac_rx_attach_flow_srs(mac_impl_t *, flow_entry_t *,
    mac_soft_ring_set_t *, mac_ring_t *, mac_classify_type_t);

extern void mac_rx_srs_drain_bw(mac_soft_ring_set_t *, uint_t);
extern void mac_rx_srs_drain(mac_soft_ring_set_t *, uint_t);
extern void mac_rx_srs_process(void *, mac_resource_handle_t, mblk_t *,
    boolean_t);
extern void mac_srs_worker(mac_soft_ring_set_t *);
extern void mac_rx_srs_poll_ring(mac_soft_ring_set_t *);
extern void mac_tx_srs_drain(mac_soft_ring_set_t *, uint_t);

extern void mac_tx_srs_restart(mac_soft_ring_set_t *);
extern void mac_rx_srs_remove(mac_soft_ring_set_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MAC_SOFT_RING_H */
