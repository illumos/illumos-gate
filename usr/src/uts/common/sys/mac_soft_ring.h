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
 * Copyright 2017 Joyent, Inc.
 * Copyright 2026 Oxide Computer Company
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

/*
 * Flagset of immutable and datapath-altered aspects of a softring.
 *
 * Flags prefixed by `ST_` identify static characteristics of how a ring should
 * process packets, whereas those prefixed `S_RING` reflect the current state
 * of datapath processing.
 *
 * Gaps in flag allocation correspond to former flag definitions (such that
 * existing flags mapped to their historic values). New flags can be placed in
 * these gaps without issue. See issue 17920.
 */
typedef enum {
	/*
	 * Packets may only be drained from this softring by its own worker
	 * thread, and cannot be handled inline by the SRS or its caller..
	 *
	 * Immutable.
	 */
	ST_RING_WORKER_ONLY	= 1 << 0,
	/*
	 * This softring is dedicated to handling TCP/IPv4 traffic when DLS
	 * bypass is configured.
	 *
	 * Immutable.
	 */
	ST_RING_TCP		= 1 << 2,
	/*
	 * This softring is dedicated to handling UDP/IPv4 traffic when DLS
	 * bypass is configured.
	 *
	 * Immutable.
	 */
	ST_RING_UDP		= 1 << 3,
	/*
	 * This softring handles all traffic which is ineligible for DLS bypass.
	 *
	 * Immutable.
	 */
	ST_RING_OTH		= 1 << 4,
	/*
	 * If set, this is a transmit softring. Packets will be directed via
	 * `mac_tx_send` to an underlying provider's ring.
	 *
	 * If absent, this is a receive softring. Packets will be delivered to a
	 * client via `s_ring_rx_func`.
	 *
	 * Immutable.
	 */
	ST_RING_TX		= 1 << 6,
	/*
	 * This softring is dedicated to handling TCP/IPv6 traffic when DLS
	 * bypass is configured.
	 *
	 * Immutable.
	 */
	ST_RING_TCP6		= 1 << 7,
	/*
	 * This softring is dedicated to handling UDP/IPv6 traffic when DLS
	 * bypass is configured.
	 *
	 * Immutable.
	 */
	ST_RING_UDP6		= 1 << 8,
	/*
	 * A thread is currently processing packets from this softring, and has
	 * relinquished its hold on `s_ring_lock` to allow more packets to be
	 * enqueued while it does so.
	 *
	 * Rx/Tx process methods will always enqueue packets if set, with the
	 * expectation that whoever is draining the thread will continue to
	 * do so.
	 */
	S_RING_PROC		= 1 << 16,
	/*
	 * The worker thread of this softring has been bound to a specific CPU.
	 */
	S_RING_BOUND		= 1 << 17,
	/*
	 * This softring is a TX softring and has run out of descriptors on the
	 * underlying ring/NIC.
	 *
	 * Any outbound packets will be queued until the underlying provider
	 * marks more descriptors as available via `mac_tx_ring_update`.
	 */
	S_RING_BLOCK		= 1 << 18,
	/*
	 * This softring is a TX softring and is flow controlled: more than
	 * `s_ring_tx_hiwat` packets are currently enqueued.
	 *
	 * Any outbound packets will be enqueued, and drained by the softring
	 * worker. Senders will receive a cookie -- they will be informed when
	 * any cookie is no longer flow controlled if they have registered a
	 * callback via `mac_client_tx_notify`.
	 */
	S_RING_TX_HIWAT		= 1 << 19,
	/*
	 * This softring is a TX softring and has returned a cookie to at least
	 * one sender who has set `MAC_TX_NO_ENQUEUE` regardless of watermark
	 * state.
	 *
	 * When the softring is drained, notify the client via its
	 * `mac_client_tx_notify` callback that it may send.
	 */
	S_RING_WAKEUP_CLIENT	= 1 << 20,
	/*
	 * This RX softring is client pollable and its client has called
	 * `mac_soft_ring_intr_disble` to stop MAC from delivering frames via
	 * `s_ring_rx_func`.
	 *
	 * Packets may _only_ be delivered by client polling. The client may
	 * undo this using `mac_soft_ring_intr_enable`.
	 */
	S_RING_BLANK		= 1 << 21,
	/*
	 * Request the thread processing packets to notify a waiting client when
	 * it is safe to alter the `s_ring_rx_func` callback and its arguments.
	 */
	S_RING_CLIENT_WAIT	= 1 << 22,
	/*
	 * This softring is marked for deletion.
	 *
	 * No further packets can be admitted into the softring, and enqueued
	 * packets must not be processed.
	 */
	S_RING_CONDEMNED	= 1 << 24,
	/*
	 * The softring worker has completed any teardown in response to
	 * `S_RING_CONDEMNED`.
	 *
	 * Requires `S_RING_QUIESCE_DONE`.
	 */
	S_RING_CONDEMNED_DONE	= 1 << 25,
	/*
	 * This softring has been signalled to stop processing any packets.
	 *
	 * The presence of this flag implies that the parent SRS has
	 * *also* been asked to quiesce. It will not enqueue any packets here.
	 */
	S_RING_QUIESCE		= 1 << 26,
	/*
	 * The softring has ceased processing any enqueued/arriving packets, and
	 * is awaiting a signal of either `S_RING_CONDEMNED` or `S_RING_RESTART`
	 * to wake up.
	 */
	S_RING_QUIESCE_DONE	= 1 << 27,
	/*
	 * The softring has been signalled to resume processing traffic.
	 *
	 * The worker thread should unset this and any `QUIESCE` flags and
	 * resume processing packets.
	 */
	S_RING_RESTART		= 1 << 28,
	/*
	 * This TX softring has packets enqueued, which the worker thread is
	 * responsible for draining.
	 */
	S_RING_ENQUEUED		= 1 << 29,
} mac_soft_ring_state_t;

/*
 * Used to verify whether a given value is allowed to be used as the
 * `type` of a softring during creation.
 */
#define	SR_STATE	0xffff0000

struct mac_soft_ring_s {
	/* Keep the most used members 64bytes cache aligned */
	kmutex_t	s_ring_lock;	/* lock before using any member */
	mac_soft_ring_state_t	s_ring_state;	/* processing model and state */
	uint32_t	s_ring_count;	/* # of mblocks in mac_soft_ring */
	size_t		s_ring_size;	/* Size of data queued */
	mblk_t		*s_ring_first;	/* first mblk chain or NULL */
	mblk_t		*s_ring_last;	/* last mblk chain or NULL */

	/* Protected by s_ring_lock + !S_RING_PROC */
	mac_direct_rx_t		s_ring_rx_func;
	void			*s_ring_rx_arg1;
	mac_resource_handle_t	s_ring_rx_arg2;

	/*
	 * Threshold after which packets get dropped.
	 * Is always greater than s_ring_tx_hiwat
	 */
	uint32_t	s_ring_tx_max_q_cnt;
	/* # of mblocks after which to apply flow control */
	uint32_t	s_ring_tx_hiwat;
	/* # of mblocks after which to relieve flow control */
	uint32_t	s_ring_tx_lowat;
	boolean_t	s_ring_tx_woken_up;
	uint32_t	s_ring_hiwat_cnt;	/* times blocked for Tx descs */

	/* Arguments for `mac_tx_send`, called by `mac_tx_soft_ring_drain` */
	mac_client_impl_t	*s_ring_tx_arg1;
	mac_ring_t		*s_ring_tx_arg2;

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
	uint64_t	s_ring_total_inpkt;
	uint64_t	s_ring_total_rbytes;
	uint64_t	s_ring_drops;
	mac_client_impl_t *s_ring_mcip;
	kstat_t		*s_ring_ksp;

	/* Teardown, poll disable control ops */
	kcondvar_t	s_ring_client_cv; /* Client wait for control op */

	mac_soft_ring_set_t *s_ring_set;   /* The SRS this ring belongs to */
	mac_soft_ring_t	*s_ring_next;
	mac_soft_ring_t	*s_ring_prev;
	mac_soft_ring_drain_func_t s_ring_drain_func;

	mac_tx_stats_t	s_st_stat;
};

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

/* Transmit side Soft Ring Set */
typedef struct mac_srs_tx_s {
	/* Members for Tx-side processing */
	mac_tx_srs_mode_t		st_mode;
	mac_tx_func_t			st_func;

	/* Arguments for `mac_tx_send` when called within `st_func` */
	mac_client_impl_t	*st_arg1;
	mac_ring_t		*st_arg2;

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
	 * Upcall function for Rx processing when `SRST_NO_SOFT_RINGS` is set.
	 * Rx softring callbacks for non-bypass traffic should use the same
	 * function and initial argument.
	 * Argument 2 of `sr_func` would be a client-provided handle, but is
	 * always `NULL` in this context as SRSes themselves cannot be used as
	 * part of client polling.
	 *
	 * Protected by srs_lock + !SRS_PROC.
	 */
	mac_direct_rx_t		sr_func;
	void			*sr_arg1;

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
 * Flagset of immutable and slowly-varying aspects of a softring set (SRS).
 *
 * These identify mainly static characteristics (Tx/Rx, whether the SRS
 * corresponds to the entrypoint on a MAC client) as well as state on an
 * administrative timescale (fanout behaviour, bandwidth control).
 *
 * See the commentary on `mac_soft_ring_state_t` for commentary on gaps in the
 * numbering of flags for this type.
 */
enum mac_soft_ring_set_type {
	/*
	 * The flow entry underpinning this SRS belongs to a MAC client for
	 * a link.
	 *
	 * Immutable.
	 */
	SRST_LINK			= 1 << 0,
	/*
	 * The flow entry underpinning this SRS belongs to a flow classifier
	 * attached to a given MAC client.
	 *
	 * Immutable.
	 */
	SRST_FLOW			= 1 << 1,
	/*
	 * This SRS does not have any softrings assigned.
	 *
	 * A Tx SRS has no rings and will send packets directly to the NIC,
	 * and an Rx SRS will handle packets inline via `sr_func`.
	 *
	 * Mutable for Tx SRSes.
	 */
	SRST_NO_SOFT_RINGS		= 1 << 2,
	/*
	 * Set on all Rx SRSes when the tunable `mac_latency_optimize` is
	 * `true`.
	 *
	 * If set, packets may be processed inline by any caller who arrives
	 * with more packets to enqueue if there is no existing backlog.
	 * The worker thread will share a CPU binding with the poll thread.
	 * Wakeups sent to worker threads will be instantaneous (loopback,
	 * teardown, and bandwidth-controlled cases).
	 *
	 * If unset on an Rx SRS, packets may only be moved to softrings by the
	 * worker thread. `SRST_ENQUEUE` will also be set in this case.
	 *
	 * Immutable. Requires !`SRST_TX`.
	 */
	SRST_LATENCY_OPT		= 1 << 3,
	/*
	 * This Rx SRS has softrings assigned, and has at least one per traffic
	 * class. Traffic must move to a softring for processing, but may still
	 * drain inline if the SRS is quiet.
	 *
	 * Immutable. Requires !`SRST_TX`. Mutually exclusive with
	 * `SRST_NO_SOFT_RINGS`.
	 */
	SRST_FANOUT_PROTO		= 1 << 4,
	/*
	 * This receive SRS has more than one softring for each traffic class,
	 * and must hash/round-robin received packets amongst a class's rings.
	 *
	 * Mutable. Requires !`SRST_TX`.
	 */
	SRST_FANOUT_SRC_IP		= 1 << 5,
	/*
	 * All softrings will be initialised with `ST_RING_WORKER_ONLY`.
	 *
	 * Set when `SRST_LATENCY_OPT` is disabled, or when the underlying ring
	 * requires `MAC_RING_RX_ENQUEUE` (sun4v).
	 *
	 * Immutable. Requires !`SRST_TX`.
	 */
	SRST_ENQUEUE			= 1 << 6,
	/*
	 * The SRS's client is placed on the default group (either due to
	 * oversubscription, or the device admits only one group).
	 *
	 * A hardware classified ring of this type will receive additional
	 * traffic when moved into full or all-multicast promiscuous mode.
	 *
	 * Mutable. Requires !`SRST_TX`.
	 */
	SRST_DEFAULT_GRP		= 1 << 7,
	/*
	 * If present, this is a transmit SRS. Otherwise it is a receive SRS.
	 *
	 * Transmit SRSes use softrings as mappings to underlying Tx rings
	 * from the hardware.
	 *
	 * The validity of `srs_tx`/`srs_rx` are gated on this flag, as are the
	 * choice of drain functions, enqueue behaviours, etc.
	 *
	 * Immutable.
	 */
	SRST_TX				= 1 << 8,
	/*
	 * `srs_bw` is enabled, and the queue size and egress rate of this SRS
	 * are limited accordingly.
	 *
	 * Mutable.
	 */
	SRST_BW_CONTROL			= 1 << 9,
	/*
	 * The SRS's MAC client has had a callback plumbed from IP to allow
	 * matching IPv4 packets to bypass DLS.
	 *
	 * When set, `ST_RING_TCP` and `ST_RING_UDP` must make use of this
	 * callback. The Rx path will send eligible traffic to these softrings
	 * in this case.
	 *
	 * Mutable under quiescence. Requires !`SRST_TX`.
	 */
	SRST_DLS_BYPASS_V4		= 1 << 12,
	/*
	 * The SRS's MAC client has had a callback plumbed from IP to allow
	 * matching IPv6 packets to bypass DLS.
	 *
	 * When set, `ST_RING_TCP6` and `ST_RING_UDP6` must make use of this
	 * callback. The Rx path will send eligible traffic to these softrings
	 * in this case.
	 *
	 * Mutable under quiescence. Requires !`SRST_TX`.
	 */
	SRST_DLS_BYPASS_V6		= 1 << 13,
	/*
	 * The underlying MAC client has had a `mac_resource_cb_t` plumbed down
	 * from IP for TCP/IPv4 classified traffic. MAC must inform IP of the
	 * addition, removal, and other state changes to any `ST_RING_TCP`
	 * softrings.
	 *
	 * Mutable under quiescence. Requires !`SRST_TX`.
	 */
	SRST_CLIENT_POLL_V4		= 1 << 14,
	/*
	 * The underlying MAC client has had a `mac_resource_cb_t` plumbed down
	 * from IP for TCP/IPv6 classified traffic. MAC must inform IP of the
	 * addition, removal, and other state changes to any `ST_RING_TCP6`
	 * softrings.
	 *
	 * Mutable under quiescence. Requires !`SRST_TX`.
	 */
	SRST_CLIENT_POLL_V6		= 1 << 15,
};

/*
 * Flagset reflecting the current state of datapath processing for a given SRS.
 *
 * See the commentary on `mac_soft_ring_state_t` for commentary on gaps in the
 * numbering of flags for this type.
 */
typedef enum {
	/*
	 * This SRS's worker thread is explicitly bound to a single CPU.
	 */
	SRS_WORKER_BOUND	= 1 << 1,
	/*
	 * This Rx SRS's poll thread is explicitly bound to a single CPU.
	 */
	SRS_POLL_BOUND		= 1 << 2,
	/*
	 * This Rx SRS is created on top of (and has exclusive
	 * use of) a dedicated ring. When under sufficient load, MAC will
	 * disable interrupts and pull packets into the SRS by polling the
	 * NIC/ring, and will set `SRS_POLLING` when this is the case.
	 *
	 * This flag may be added/removed as SRSes move between
	 * hardware/software classification (e.g., if groups must be shared).
	 */
	SRS_POLLING_CAPAB	= 1 << 3,
	/*
	 * A thread is currently processing packets from this SRS, and
	 * has relinquished its hold on `srs_lock` to allow more packets to be
	 * enqueued while it does so.
	 *
	 * SRS processing will always enqueue packets if set, with the
	 * expectation that whoever is draining the thread will continue to
	 * do so.
	 *
	 * Requires qualification of what thread is doing the processing: either
	 * `SRS_WORKER`, `SRS_PROC_FAST`, or `SRS_POLL_PROC`.
	 */
	SRS_PROC		= 1 << 4,
	/*
	 * The Rx poll thread should request more packets from the underlying
	 * device.
	 *
	 * Requires `SRS_POLLING`.
	 */
	SRS_GET_PKTS		= 1 << 5,
	/*
	 * This Rx SRS has been moved into poll mode. Interrupts from
	 * the underlying device are disabled, and the poll thread is
	 * exclusively responsible for moving packets into the SRS.
	 *
	 * Requires `SRS_POLLING_CAPAB`.
	 */
	SRS_POLLING		= 1 << 6,
	/*
	 * The SRS worker thread currently holds `SRS_PROC`.
	 *
	 * Requires `SRS_PROC`.
	 */
	SRS_WORKER		= 1 << 8,
	/*
	 * Packets have been enqueued on this TX SRS due to either flow control
	 * or a lack of Tx descriptors on the NIC.
	 */
	SRS_ENQUEUED		= 1 << 9,
	/*
	 * `SRS_PROC` is held by the caller of `mac_rx_srs_process` (typically
	 * the interrupt context) and packets are being processed inline.
	 *
	 * Requires `SRS_PROC`.
	 */
	SRS_PROC_FAST		= 1 << 11,
	/*
	 * The Rx SRS poll thread currently holds `SRS_PROC`.
	 *
	 * Requires `SRS_PROC`.
	 */
	SRS_POLL_PROC		= 1 << 12,
	/*
	 * This Tx SRS has run out of descriptors on the underlying NIC.
	 *
	 * Any outbound packets will be queued until the underlying provider
	 * marks more descriptors as available via `mac_tx_ring_update`.
	 */
	SRS_TX_BLOCKED		= 1 << 13,
	/*
	 * This Tx SRS is flow controlled: more than `st_hiwat` packets are
	 * currently enqueued.
	 *
	 * Any outbound packets will be enqueued, and drained by the SRS
	 * worker. Senders will receive a cookie -- they will be informed when
	 * any cookie is no longer flow controlled if they have registered a
	 * callback via `mac_client_tx_notify`.
	 */
	SRS_TX_HIWAT		= 1 << 14,
	/*
	 * This Tx SRS has returned a cookie to at least one sender who has set
	 * `MAC_TX_NO_ENQUEUE` regardless of watermark state.
	 *
	 * When the SRS is drained, notify the client via its
	 * `mac_client_tx_notify` callback that it may send.
	 */
	SRS_TX_WAKEUP_CLIENT	= 1 << 15,
	/*
	 * `SRS_PROC` is held by the SRS drain function, which is handling
	 * packets inline because it is of type `SRST_NO_SOFT_RINGS`.
	 *
	 * Requires `SRS_PROC`.
	 */
	SRS_CLIENT_PROC		= 1 << 16,
	/*
	 * This SRS has been signalled to stop processing any packets.
	 *
	 * Downstack entrypoints (rings, flows) which can call into this SRS
	 * should be quiesced such that no more packets will be enqueued while
	 * this is set.
	 *
	 * The SRS worker thread will propagate the request to any softrings.
	 */
	SRS_QUIESCE		= 1 << 18,
	/*
	 * The SRS has ceased processing any enqueued packets, the worker thread
	 * has finished quiescing any softrings and is awaiting a signal
	 * of either `SRS_CONDEMNED` or `SRS_RESTART` to wake up.
	 */
	SRS_QUIESCE_DONE	= 1 << 19,
	/*
	 * This SRS is marked for deletion.
	 *
	 * Downstack entrypoints (rings, flows) which can call into this SRS
	 * should be quiesced such that no more packets will be enqueued while
	 * this is set.
	 *
	 * The SRS worker thread will propagate the request to any softrings.
	 */
	SRS_CONDEMNED		= 1 << 20,
	/*
	 * The SRS worker has completed any teardown in response to
	 * `SRS_CONDEMNED`.
	 *
	 * Requires `SRS_CONDEMNED_DONE`.
	 */
	SRS_CONDEMNED_DONE	= 1 << 21,
	/*
	 * This Rx SRS's poll thread has quiesced in response to `SRS_QUIESCE`.
	 */
	SRS_POLL_THR_QUIESCED	= 1 << 22,
	/*
	 * The SRS has been signalled to resume processing traffic.
	 *
	 * The worker thread should unset this and any `QUIESCE` flags,
	 * propagate the request to softrings and the poll thread, and
	 * resume processing packets.
	 */
	SRS_RESTART		= 1 << 23,
	/*
	 * The SRS has successfully restarted all of its softrings and poll
	 * thread, if present.
	 */
	SRS_RESTART_DONE	= 1 << 24,
	/*
	 * This Rx SRS's worker thread has signalled the poll thread to resume
	 * in response to `SRS_RESTART`.
	 */
	SRS_POLL_THR_RESTART	= 1 << 25,
	/*
	 * This SRS is part of the global list `mac_srs_g_list`. Its siblings
	 * are accessed via `srs_next` and `srs_prev`.
	 */
	SRS_IN_GLIST		= 1 << 26,
	/*
	 * This Rx SRS's poll thread has terminated in response to
	 * `SRS_CONDEMN`.
	 */
	SRS_POLL_THR_EXITED	= 1 << 27,
	/*
	 * This SRS is semi-permanently quiesced, and should not accept
	 * `SRS_RESTART` requests.
	 */
	SRS_QUIESCE_PERM	= 1 << 28,
} mac_soft_ring_set_state_t;

/*
 * SRS fanout states.
 *
 * These are set during SRS initialisation and by the flow CPU init methods to
 * indicate whether any work is needing done to adjust the softrings.
 */
typedef enum {
	/*
	 * This is a new SRS. Softrings have not yet been created.
	 */
	SRS_FANOUT_UNINIT = 0,
	/*
	 * The SRS's bindings and fanout count match the underlying CPU spec.
	 */
	SRS_FANOUT_INIT,
	/*
	 * CPU count and/or bindings have changed and the SRS needs to be
	 * modified accordingly.
	 */
	SRS_FANOUT_REINIT
} mac_srs_fanout_state_t;

typedef void (*mac_srs_drain_proc_t)(mac_soft_ring_set_t *,
    const mac_soft_ring_set_state_t);

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
	mac_soft_ring_set_type_t	srs_type;
	mac_soft_ring_set_state_t	srs_state;

	/*
	 * The SRS's packet queue.
	 */
	mblk_t		*srs_first;	/* first mblk chain or NULL */
	mblk_t		*srs_last;	/* last mblk chain or NULL */
	size_t		srs_size;	/* Size of packets queued in bytes */
	uint32_t	srs_count;

	kcondvar_t	srs_async;	/* cv for worker thread */
	kcondvar_t	srs_cv;		/* cv for poll thread */
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

	kcondvar_t	srs_quiesce_done_cv;	/* cv for removal */

	mac_soft_ring_t	**srs_tcp_soft_rings;
	mac_soft_ring_t	**srs_udp_soft_rings;
	mac_soft_ring_t	**srs_tcp6_soft_rings;
	mac_soft_ring_t	**srs_udp6_soft_rings;
	mac_soft_ring_t	**srs_oth_soft_rings;
	/*
	 * srs_tx_soft_rings is used by tx_srs in
	 * when operating in multi tx ring mode.
	 */
	mac_soft_ring_t	**srs_tx_soft_rings;
	int		srs_tcp_ring_count;
	int		srs_udp_ring_count;
	int		srs_tcp6_ring_count;
	int		srs_udp6_ring_count;
	int		srs_oth_ring_count;
	int		srs_tx_ring_count;

	/*
	 * Bandwidth control related members.
	 * They are common to both Rx- and Tx-side.
	 * Following protected by srs_lock
	 */
	mac_bw_ctl_t	*srs_bw;
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
	mac_client_impl_t *srs_mcip;	/* back ptr to mac client */
	flow_entry_t	*srs_flent;	/* back ptr to flent */
	mac_ring_t	*srs_ring;	/*  Ring Descriptor */

	kthread_t	*srs_worker;	/* WO, worker thread */
	kthread_t	*srs_poll_thr;	/* WO, poll thread */

	uint_t		srs_ind;	/* Round Robin indx for picking up SR */
	processorid_t	srs_worker_cpuid;	/* processor to bind to */
	processorid_t	srs_worker_cpuid_save;	/* saved cpuid during offline */
	processorid_t	srs_poll_cpuid;		/* processor to bind to */
	processorid_t	srs_poll_cpuid_save;	/* saved cpuid during offline */
	mac_srs_fanout_state_t	srs_fanout_state;
	mac_cpus_t	srs_cpu;

	mac_srs_rx_t	srs_rx;
	mac_srs_tx_t	srs_tx;
	kstat_t		*srs_ksp;
};

/*
 * The total number of softring protocol lanes: TCP, TCP6, UDP, UDP6, OTH.
 */
#define	ST_RING_NUM_PROTO	5

/*
 * arguments for processors to bind to
 */
#define	S_RING_BIND_NONE	-1

/*
 * soft ring set flags. These bits are dynamic in nature and get
 * applied to srs_state. They reflect the state of SRS at any
 * point of time
 */

/*
 * This flag pertains to `mac_bw_ctl_t` (mac_flow_impl.h), and should not live
 * here.
 *
 * See illumos#17917.
 */
#define	SRS_BW_ENFORCED		1

#define	SRS_QUIESCED(srs)	(srs->srs_state & SRS_QUIESCE_DONE)

/*
 * If the SRS_QUIESCE_PERM flag is set, the SRS worker thread will not be
 * able to be restarted.
 */
#define	SRS_QUIESCED_PERMANENT(srs)	(srs->srs_state & SRS_QUIESCE_PERM)

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
	mblk_t		*tmp;					\
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
	if ((srs_rx->sr_poll_pkt_cnt <= srs_rx->sr_poll_thres) &&	\
	    (((mac_srs)->srs_state &					\
	    (SRS_POLLING|SRS_PROC|SRS_GET_PKTS)) == SRS_POLLING))	\
	{								\
		(mac_srs)->srs_state |= (SRS_PROC|SRS_GET_PKTS);	\
		cv_signal(&(mac_srs)->srs_cv);				\
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
    mac_resource_props_t *, mac_direct_rx_t, void *, cpupart_t *);

extern void mac_soft_ring_worker_wakeup(mac_soft_ring_t *);
extern mblk_t *mac_soft_ring_poll(mac_soft_ring_t *, size_t);
extern void mac_soft_ring_dls_bypass_enable(mac_soft_ring_t *, mac_direct_rx_t,
    void *);
extern void mac_soft_ring_dls_bypass_disable(mac_soft_ring_t *,
    mac_client_impl_t *);
extern void mac_soft_ring_poll_enable(mac_soft_ring_t *, mac_direct_rx_t,
    void *, mac_resource_cb_t *, uint32_t);
extern void mac_soft_ring_poll_disable(mac_soft_ring_t *, mac_resource_cb_t *,
    mac_client_impl_t *);

/* SRS */
extern void mac_srs_free(mac_soft_ring_set_t *);
extern void mac_srs_signal(mac_soft_ring_set_t *,
    const mac_soft_ring_set_state_t);

extern void mac_rx_srs_retarget_intr(mac_soft_ring_set_t *, processorid_t);
extern void mac_tx_srs_retarget_intr(mac_soft_ring_set_t *);

extern void mac_srs_client_poll_enable(mac_client_impl_t *,
    mac_soft_ring_set_t *, boolean_t);
extern void mac_srs_client_poll_disable(mac_client_impl_t *,
    mac_soft_ring_set_t *, boolean_t);
extern void mac_srs_client_poll_quiesce(mac_client_impl_t *,
    mac_soft_ring_set_t *);
extern void mac_srs_client_poll_restart(mac_client_impl_t *,
    mac_soft_ring_set_t *);
extern void mac_rx_srs_quiesce(mac_soft_ring_set_t *,
    const mac_soft_ring_set_state_t);
extern void mac_rx_srs_restart(mac_soft_ring_set_t *);
extern void mac_tx_srs_quiesce(mac_soft_ring_set_t *,
    const mac_soft_ring_set_state_t);

/* Tx SRS, Tx softring */
extern void mac_tx_srs_wakeup(mac_soft_ring_set_t *, mac_ring_handle_t);
extern void mac_tx_srs_setup(mac_client_impl_t *, flow_entry_t *);
extern mac_tx_func_t mac_tx_get_func(uint32_t);
extern mblk_t *mac_tx_send(mac_client_impl_t *, mac_ring_t *, mblk_t *,
    mac_tx_stats_t *);
extern boolean_t mac_tx_srs_ring_present(mac_soft_ring_set_t *, mac_ring_t *);
extern mac_soft_ring_t *mac_tx_srs_get_soft_ring(mac_soft_ring_set_t *,
    mac_ring_t *);
extern void mac_tx_srs_add_ring(mac_soft_ring_set_t *, mac_ring_t *);
extern void mac_tx_srs_del_ring(mac_soft_ring_set_t *, mac_ring_t *);
extern mac_tx_cookie_t mac_tx_srs_no_desc(mac_soft_ring_set_t *, mblk_t *,
    uint16_t, mblk_t **);

/* Subflow specific stuff */
extern void mac_srs_update_bwlimit(flow_entry_t *, mac_resource_props_t *);
extern void mac_update_srs_priority(mac_soft_ring_set_t *, pri_t);
extern void mac_client_update_classifier(mac_client_impl_t *, boolean_t);
extern void mac_rx_srs_subflow_process(void *, mac_resource_handle_t, mblk_t *,
    boolean_t);

/* Resource callbacks for clients */
extern int mac_soft_ring_intr_enable(void *);
extern boolean_t mac_soft_ring_intr_disable(void *);
extern cpu_t *mac_soft_ring_bind(mac_soft_ring_t *, processorid_t);
extern void mac_soft_ring_unbind(mac_soft_ring_t *);

extern mac_soft_ring_t *mac_soft_ring_create_rx(int, clock_t,
    const mac_soft_ring_state_t, pri_t, mac_client_impl_t *,
    mac_soft_ring_set_t *, processorid_t, mac_direct_rx_t, void *);
extern mac_soft_ring_t *mac_soft_ring_create_tx(int, clock_t,
    const mac_soft_ring_state_t, pri_t, mac_client_impl_t *,
    mac_soft_ring_set_t *, processorid_t, mac_ring_t *);
extern void mac_soft_ring_free(mac_soft_ring_t *);
extern void mac_soft_ring_signal(mac_soft_ring_t *,
    const mac_soft_ring_state_t);
extern void mac_rx_soft_ring_process(mac_client_impl_t *, mac_soft_ring_t *,
    mblk_t *, mblk_t *, int, size_t);
extern mac_tx_cookie_t mac_tx_soft_ring_process(mac_soft_ring_t *,
    mblk_t *, uint16_t, mblk_t **);
extern void mac_srs_worker_quiesce(mac_soft_ring_set_t *);
extern void mac_srs_worker_restart(mac_soft_ring_set_t *);

extern void mac_rx_srs_drain_bw(mac_soft_ring_set_t *,
    const mac_soft_ring_set_state_t);
extern void mac_rx_srs_drain(mac_soft_ring_set_t *,
    const mac_soft_ring_set_state_t);
extern void mac_rx_srs_process(void *, mac_resource_handle_t, mblk_t *,
    boolean_t);
extern void mac_srs_worker(mac_soft_ring_set_t *);
extern void mac_rx_srs_poll_ring(mac_soft_ring_set_t *);
extern void mac_tx_srs_drain(mac_soft_ring_set_t *,
    const mac_soft_ring_set_state_t);

extern void mac_tx_srs_restart(mac_soft_ring_set_t *);
extern void mac_rx_srs_remove(mac_soft_ring_set_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MAC_SOFT_RING_H */
