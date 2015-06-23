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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_INET_NCA_H
#define	_INET_NCA_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/thread.h>
#include <sys/door.h>
#include <sys/disp.h>
#include <sys/systm.h>
#include <sys/processor.h>
#include <sys/socket.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/tcp.h>
#include <inet/nca/ncadoorhdr.h>

/*
 * The NCA debugging facilities provided via ADB and MDB depend on a
 * number of NCA implementation details.  In particular, note that:
 *
 *	* ADB macros *must* be revised whenever members are added or
 *	  removed from the following structures:
 *
 *		nca_conn_t connf_t nca_cpu_t dcb_t hcb_t nca_if_t nca_io2_t
 *		node_t nodef_t sqfan_t nca_squeue_t tb_t te_t ti_t tw_t
 *
 *	* ADB macros should be added when new core data structures are
 *	  added to NCA.  Generally, if you had to put it in here, you
 *	  need to write a macro for it.
 *
 *	* MDB has many dependencies on the way core data structures
 *	  are connected.  In general, if you break these dependencies,
 *	  the MDB NCA module will fail to build.  However, breakage
 *	  may go undetected (for instance, changing a linked list
 *	  into a circularly linked list).  If you have any doubts,
 *	  inspect the NCA module source before committing your changes.
 *
 *	* MDB depends on the following variables (and their current
 *	  semantics) in order to function correctly:
 *
 *		nca_conn_fanout nca_conn_fanout_size nca_gv nca_lru
 *		urihash filehash
 *
 *	  If you change the names or *semantics* of these variables,
 *	  you must modify the MDB module accordingly.
 *
 *	  In addition, you should consider whether the changes you've
 *	  made should be reflected in the MDB dcmds themselves.
 */

/* The queue to make upcall on for NCAfs */
extern queue_t *ncaupcallq;
extern kmutex_t ncaupcallq_lock;

extern int nca_logging_on;
extern int nca_conn_fanout_size;
extern boolean_t nca_deferred_oq_if;
extern boolean_t nca_fanout_iq_if;

/* Checksum pointer for no checksum */

#define	NO_CKSUM (void *)-1

/* undef any tcp.h:tcp_t members overloaded by the Solaris 8 tcp.h */

#undef	tcp_last_rcv_lbolt
#undef	tcp_state
#undef	tcp_rto
#undef	tcp_snd_ts_ok
#undef	tcp_snd_ws_ok
#undef	tcp_snxt
#undef	tcp_swnd
#undef	tcp_mss
#undef	tcp_iss
#undef	tcp_rnxt
#undef	tcp_rwnd
#undef	tcp_lport
#undef	tcp_fport
#undef	tcp_ports

/* the iph_t is no longer defined in ip.h for Solaris 8 ? */

/* Unaligned IP header */
typedef struct iph_s {
	uchar_t	iph_version_and_hdr_length;
	uchar_t	iph_type_of_service;
	uchar_t	iph_length[2];
	uchar_t	iph_ident[2];
	uchar_t	iph_fragment_offset_and_flags[2];
	uchar_t	iph_ttl;
	uchar_t	iph_protocol;
	uchar_t	iph_hdr_checksum[2];
	uchar_t	iph_src[4];
	uchar_t	iph_dst[4];
} iph_t;


#define	true	B_TRUE			/* used with type boolean_t */
#define	false	B_FALSE			/* used with type boolean_t */

/*
 * Power of 2^N Primes useful for hashing for N of 0-28,
 * these primes are the nearest prime <= 2^N - 2^(N-2).
 */

#define	P2Ps() {0, 0, 0, 5, 11, 23, 47, 89, 191, 383, 761, 1531, 3067,	\
		6143, 12281, 24571, 49139, 98299, 196597, 393209,	\
		786431, 1572853, 3145721, 6291449, 12582893, 25165813,	\
		50331599, 100663291, 201326557, 0}

/*
 * Serialization queue type (move to strsubr.h (stream.h?) as a general
 * purpose lightweight mechanism for mblk_t serialization ?).
 */
typedef struct nca_squeue_s {
	uint16_t	sq_state;	/* state flags */
	uint16_t	sq_count;	/* message count */
	uint32_t	sq_type;	/* type flags */
	processorid_t	sq_bind;	/* processor to bind to */
	ddi_softintr_t	sq_softid;	/* softintr() id */
	void		(*sq_init)();	/* initialize function */
	void		*sq_init_arg;	/* initialize argument */
	void		(*sq_proc)();	/* process function */
	mblk_t		*sq_first;	/* first mblk chain or NULL */
	mblk_t		*sq_last;	/* last mblk chain or NULL */
	clock_t		sq_wait;	/* lbolts to wait after a fill() */
	clock_t		sq_iwait;	/* lbolt after nointr() */
	clock_t		sq_pwait;	/* lbolt after pause() */
	int		sq_isintr;	/* is being or was serviced by */
	timeout_id_t	sq_tid;		/* timer id of pending timeout() */
	kcondvar_t	sq_async;	/* async thread blocks on */
	kmutex_t	sq_lock;	/* lock before using any member */
	clock_t		sq_awaken;	/* time async thread was awakened */
	void		*sq_priv;	/* user defined private */
	kt_did_t	sq_ktid;	/* kernel thread id */
} nca_squeue_t;

/*
 * State flags and message count (i.e. properties that change)
 * Note: The MDB NCA module depends on the values of these flags.
 */

#define	SQS_CNT_TOOMANY	0x8000	/* message count toomany */

/* nca_squeue_t state flags now only 16 bits */

#define	SQS_PROC	0x0001	/* being processed */
#define	SQS_WORKER	0x0002	/* worker thread */
#define	SQS_ENTER	0x0004	/* enter thread */
#define	SQS_FAST	0x0008	/* enter-fast thread */
#define	SQS_PROXY	0x0010	/* proxy thread */
#define	SQS_SOFTINTR	0x0020	/* softint thread */
				/* 0x00C0 bits not used */

#define	SQS_NOINTR	0x0100	/* no interrupt processing */
#define	SQS_PAUSE	0x0200	/* paused */
#define	SQS_INTRWAIT	0x0400	/* interrupt waiting */
#define	SQS_NOPROC	0x0800	/* no processing */
				/* 0x7000 bits not used */
#define	SQS_EXIT	0x8000	/* worker(s) exit */

/*
 * Type flags (i.e. properties that don't change).
 * Note: The MDB NCA module depends on the values of these flags.
 */

#define	SQT_BIND_MASK	0xFF000000	/* bind flags mask */

#define	SQT_KMEM	0x00000001	/* was kmem_alloc()ed */
#define	SQT_DEFERRED	0x00000002	/* deferred processing */
#define	SQT_SOFTINTR	0x00000004	/* use softintr() */

#define	SQT_BIND_ANY	0x01000000	/* bind worker thread to any CPU */
#define	SQT_BIND_TO	0x02000000	/* bind worker thread to speced CPU */

#define	SQ_STATE_IS(sqp, flags) ((sqp)->sq_state & (flags))
#define	SQ_TYPE_IS(sqp, flags) ((sqp)->sq_type & (flags))


typedef struct sqfan_s {
	uint32_t	flg;		/* flags only */
	uint32_t	cnt;		/* vector count */
	uint32_t	ix;		/* next sqv[] to process */
	uint32_t	drain;		/* max mblk(s) draind per */
	nca_squeue_t	**sqv;	/* pointer to nca_squeue_t pointer vector */
} sqfan_t;

#define	SQF_DIST_CNT	0x0001	/* sqfan_t dist by queue count */
#define	SQF_DIST_IPv4	0x0002	/* sqfan_t dist by IPv4 src addr */

/*
 * A multiphase timer is implemented using the te_t, tb_t, and ti_t structs.
 *
 * The multiple phases of timer entry execution are:
 *
 * 1) resource, execution is done from resource reclaim when the timer event
 *    is the freeing of the timed resource.
 *
 * 2) process, execution is done from process thread yield (idle/return).
 *
 * 3) time, execution is done from a timeout callback thread.
 *
 * Each of the phases have a seperate timer fire time represented by the
 * the ti_t members lbolt1, lbolt2, and lbolt3. Each lbolt is an absolute
 * lbolt value with lbolt1 <= lbolt2 <= lbolt3.
 */

/*
 * te_t - timer entry.
 */

typedef struct te_s {
	struct te_s *prev;	/* prev te_t */
	struct te_s *next;	/* next te_t */
	struct tb_s *tbp;	/* pointer to timer bucket */
	void	*ep;		/* pointer to encapsulating struct */
} te_t;

/*
 * tb_t - timer bucket.
 */

typedef struct tb_s {
	struct tb_s *next;	/* next tb_t in ascending time order */
	clock_t	exec;		/* te_t lbolt exec value for bucket */
	te_t	*head;		/* head of te_t list (first timer) */
	te_t	*tail;		/* tail of te_t list (last timer) */
} tb_t;

/*
 * ti_t - timer state.
 */

typedef struct ti_s {
	clock_t	exec;		/* next te_t exec value (0 = NONE) */
	clock_t	lbolt1;		/* phase1 lbolt1 (0 = NONE) */
	clock_t	lbolt2;		/* phase2 lbolt2 (0 = NONE) */
	clock_t	lbolt3;		/* phase3 lbolt3 (0 = NONE) */
	tb_t	*head;		/* head of tb_t list (first timer bucket) */
	tb_t	*tail;		/* tail of tb_t list (last timer bucket) */
	timeout_id_t tid;	/* timer id of pending timeout() (0 = NONE) */
	void	*ep;		/* pointer to encapsulating struct */
} ti_t;

#define	NCA_TI_INPROC	-1	/* Processing going on */
#define	NCA_TI_NONE	0	/* no lbolt */

/*
 * TIME_WAIT grounded doubly linked list of nca_conn_t's awaiting TIME_WAIT
 * expiration for. This list is used for reclaim, reap, and timer based
 * processing.
 *
 * A multiphase timer is used:
 *
 * phase 1) reclaim of connections during connection allocation
 *
 * phase 2) reaping of connections during nca_squeue_t inq thread unwind
 *
 * phase 3) timeout of connections as a result of a timeout().
 *
 * Each of the phases have a seperate timer fire lbolt represented by the
 * the members lbolt1, lbolt2, and lbolt3, each is an absolute lbolt value
 * with lbolt1 <= lbolt2 <= lbolt3.
 */

typedef struct tw_s {
	clock_t	lbolt1;		/* phase1 lbolt value (0 = NONE) */
	clock_t	lbolt2;		/* phase2 lbolt value  */
	clock_t	lbolt3;		/* phase3 lbolt value  */
	struct nca_conn_s *head;	/* Head of nca_conn_t list */
	struct nca_conn_s *tail;	/* Tail of nca_conn_t list */
	timeout_id_t tid;	/* Timer id of pending timeout() (0 = NONE) */
	void	*ep;		/* pointer to encapsulating struct */
} tw_t;

#define	NCA_TW_NONE	0	/* no lbolt */

#define	NCA_TW_MS	1000

#define	NCA_TW_LBOLT MSEC_TO_TICK(NCA_TW_MS)

#define	NCA_TW_LBOLTS(twp, future) {					\
	clock_t	_lbolt = (future);					\
	clock_t	_mod = _lbolt % NCA_TW_LBOLT;				\
									\
	if (_mod) {							\
		/* Roundup to next TIME_WAIT bucket */			\
		_lbolt += NCA_TW_LBOLT - _mod;				\
	}								\
	if ((twp)->lbolt1 != _lbolt) {					\
		(twp)->lbolt1 = _lbolt;					\
		_lbolt += NCA_TW_LBOLT;					\
		(twp)->lbolt2 = _lbolt;					\
		_lbolt += NCA_TW_LBOLT;					\
		(twp)->lbolt3 = _lbolt;					\
		if ((twp)->tid != 0) {					\
			(void) untimeout((twp)->tid);			\
			(twp)->tid = 0;					\
		}							\
		if ((_lbolt) != NCA_TW_NONE) {				\
			(twp)->tid = timeout((pfv_t)nca_tw_fire, (twp),	\
			    (twp)->lbolt3 - ddi_get_lbolt());		\
		}							\
	}								\
}

/*
 * The Node Fanout structure.
 *
 * The hash tables and their linkage (hashnext) are protected by the
 * per-bucket lock. Each node_t inserted in the list points back at
 * the nodef_t that heads the bucket (hashfanout).
 */

typedef struct nodef_s {
	struct node_s	*head;
	kmutex_t	lock;
} nodef_t;

/*
 * A node_t is used to represent a cached byte-stream object. A node_t is
 * in one of four active states:
 *
 * 1) path != NULL, member of a node_t hash list with an object description
 *    (hashnext, size, path, pathsz members valid).
 *
 * 2) pp != NULL, 1) + phys pages allocated (pp, plrupn, plrunn members valid).
 *
 * 3) data != NULL, 2) + virt mapping allocated (data, datasz, vlrupn, vlrunn
 *    members valid).
 *
 * 4) cksum != NULL 3) + checksum mapping allocated
 */

typedef struct node_s {
	uint32_t 	ref;		/* ref (see below) state */
	uint32_t 	cnt;		/* ref count */
	int32_t		size;		/* object size (-1 = UNKNOWN) */
	uint32_t	mss;		/* mblk(s) in size mss */
	uint64_t	ctag;		/* usr defined cache tag, 0 => no tag */
	ipaddr_t	laddr;		/* local IP, for virtual hosting */
	uint16_t	lport;		/* local port, for virtual hosting */

	struct node_s	*plrunn;	/* Phys LRU list next node_t */
	struct node_s	*plrupn;	/* Phys LRU list previous node_t */
	struct node_s	*vlrunn;	/* Virt LRU list next node_t */
	struct node_s	*vlrupn;	/* Virt LRU list previous node_t */

	nodef_t	*hashfanout;		/* hash bucket we're part of */
	nodef_t	*ctaghashfanout;	/* ctaghash bucket we're part off */
	struct node_s *hashnext;	/* hash list next node_t */
	struct node_s *ctaghashnext;	/* ctaghash list next node_t */
	struct nca_conn_s *connhead;	/* head of list of conn(s) in miss */
	struct nca_conn_s *conntail;	/* tail of list of conn(s) in miss */
	struct node_s *next;		/* needed if data is in chunks */
	struct node_s *back;		/* needed if data is in chunks */

	clock_t	expire;		/* lbolt node_t expires (0 = NOW, -1 = NEVER) */
	time_t	lastmod;	/* HTTP "Last-Modified:" value */

	mblk_t	*req;		/* whole HTTP request (including headers) */
	int	reqsz;		/* size of above */
	int	reqcontl;	/* HTTP "Content-Length:" value */
	uint32_t rcv_cnt;	/* rcv_list byte count */
	mblk_t	*rcv_head;	/* rcv_list head */
	mblk_t	*rcv_tail;	/* rcv_list tail */
	mblk_t	*rcv_ptr;	/* rcv_list pointer */

	nca_squeue_t *sqp;	/* squeue node_t is being processed from */
	char	*path;		/* URI path component */
	int	pathsz;		/* size of above */
	uint_t	method;		/* HTTP request method */
	uint_t	version;	/* HTTP request version */
	char	*reqhdr;	/* HTTP request header(s) */
	int	reqhdrsz;	/* size of above */
	char	*reqhost;	/* HTTP "Host:" string */
	int	reqhostsz;	/* size of above */
	char	*reqaccept;	/* HTTP "Accept:" string */
	int	reqacceptsz;	/* size of above */
	char	*reqacceptl;	/* HTTP "Accept-Language:" string */
	int	reqacceptlsz;	/* size of above */

	page_t	**pp;		/* page pointer vector for data */
	char	*data;		/* data buffer */
	int	datasz;		/* size of above */
	uint16_t *cksum;	/* cksum() vector for data by mss */
	size_t	cksumlen;	/* length of memory block for above vector */
	uint_t	resbody;	/* HTTP response body at &data[resbody] */

	int	hlen;		/* data buffer split header len */
	int	fileoff;	/* file include offset */
	int	filelen;	/* length of file */
	struct node_s *fileback; /* head node_t of a file list (-1 for death) */
	struct node_s *filenext; /* next node_t of a file list */
	struct node_s *ctagback; /* head node_t of a ctag list */
	struct node_s *ctagnext; /* next node_t of a ctag list */
	vnode_t	*filevp;	/* vnode for the file */

	kmutex_t lock;		/* serializes access to node_t */
	frtn_t	frtn;		/* STREAMS free routine; always node_freeb() */
	boolean_t headchunk;	/* true if this node is the head chunk */

	/*
	 * The following 4 fields are used to record node states when
	 * upcalls are preempted. When preempted upcalls are not relevant,
	 * these fields should have default value 0.
	 */
	uint8_t advise;		/* an interpreted advise from http */
	boolean_t last_advisory; /* preempted upcall state -- advisory bit */
	boolean_t advisory;	/* need advisory from httpd before use */
	boolean_t first_upcall;	/* node in first upcall, a internal state */

	kcondvar_t cv;		/* sync upcall/downcall process on a node */
	int	onqueue;	/* == 1 if on miss_queue, debug aid */
} node_t;

/* Note: The MDB NCA module depends on the values of these flags. */

#define	REF_URI		0x80000000 /* & ref = node_t URI hashed */
#define	REF_PHYS	0x40000000 /* & ref = phys mapping in-use */
#define	REF_VIRT	0x20000000 /* & ref = virt mapping in-use */
#define	REF_CKSUM	0x10000000 /* & ref = checksum mapping in-use */
#define	REF_KMEM	0x08000000 /* & ref = kmem mapped (PHYS|VIRT) */
#define	REF_DONE	0x04000000 /* & ref = node_t fill is done */
#define	REF_SAFED	0x02000000 /* & ref = node_t not safe for use */
#define	REF_FILE	0x01000000 /* & ref = node_t filename hashed */
#define	REF_RESP	0x00800000 /* & ref = node_t response header parsed */
#define	REF_NOLRU	0x00400000 /* & ref = node_t not safe for lru reclaim */
#define	REF_MISS	0x00200000 /* & ref = node_t is/will missed() proc */
#define	REF_ONPLRU	0x00100000 /* & ref = node_t is on Phys LRU */
#define	REF_ONVLRU	0x00080000 /* & ref = node_t is on Virt LRU */
#define	REF_PREEMPT	0x00040000 /* & ref = node_t processing preempted */
#define	REF_CTAG	0x00020000 /* & ref = node_t CTAG hashed */
#define	REF_UPCALL	0x00010000 /* & ref = node_t upcall not yet complete */
#define	REF_OWNED	0x00008000 /* & ref = node_t owned (won't be freed) */
#define	REF_ERROR	0x00004000 /* & ref = node_t errored */
#define	REF_VNODE	0x00002000 /* & ref = node_t vnode hashed */
#define	REF_NCAFS	0x00001000 /* & ref = node_t is NCAfs required */
#define	REF_SEGMAP	0x00000800 /* & ref = segmapped (PHYS|VIRT) */
#define	REF_UNUSED	0x000007FF /* & ref = UNUSED */
/*
 * Mappings where no seperate PHYS and VIRT, i.e. single mapping with a
 * virtual address e.g. REF_KMEM and REF_SEGMAP.
 */
#define	REF_NOVIRT	(REF_KMEM | REF_SEGMAP)

/* Is this node safe for reclaim ? */
#define	REF_RECLAIM	(REF_SAFED | REF_NOLRU | REF_MISS)

/*
 * NCA node_t reference counting is more complicated than nca_conn_t reference
 * counting because we pass parts of node_t's (masquerading as dblk
 * buffers) into the STREAMS subsystem which eventually get freed by
 * network drivers just like regular dblk buffers.  Also, unlike nca_conn_t's,
 * we may wish to keep a node_t around even after there are no outstanding
 * references, since it's possible that it will be requested again.
 *
 * Thus, the node_t reference count reflects the number of active codepaths
 * in Solaris making use of a given node_t -- each codepath that requires
 * that the node_t stick around once it drops the node_t lock must acquire
 * a reference via NODE_REFHOLD and drop that reference via NODE_REFRELE
 * when done.  Note that following a NODE_REFRELE the node that was
 * released may no longer exist and thus it should not be referenced unless
 * the codepath has another outstanding reference.  When a node_t is passed
 * into the STREAMS subsystem via desballoc() and related interfaces, a
 * NODE_REFHOLD should be placed on the node_t and the free routine should
 * be set to node_freeb(), which will in turn call NODE_REFRELE.
 *
 * The concept of node ownership allows NCA to express that it would like
 * this node to hang around, even if there are no "explicit" references to
 * it (the ownership counts as an implicit reference).  All "headchunk"
 * hashed nodes are owned when they are created.  If they subsequently
 * become disowned (currently via nca_node_del() or nca_reclaim_vlru()),
 * they may have some or all their resources freed (via node_fr()) as soon
 * as the last reference to them is removed.  Note that it's possible that
 * a disowned node may become of interest again before some or all of its
 * resources were reclaimed -- in this case, it must be reowned via
 * NODE_OWN.  Note that an unhashed node should never be owned, though it
 * of course may be held and released; this is because there is no sense
 * in owning a node which is merely temporary (i.e., not hashed somewhere).
 * Note that the corollary of this statement is not true -- that is, just
 * because a node is hashed does not mean it is owned (it may have been
 * disowned via nca_reclaim_vlru()) -- this is why code must always reown
 * hashed nodes if it's desirable to have them stick around.
 *
 * All four macros *must* be called with the node lock held.  However,
 * NODE_DISOWN and NODE_REFRELE return with the lock unlocked (if there is
 * still a lock at all), because the operation may have just removed the
 * final reference to a node and it may no longer exist.
 *
 * A version of NODE_REFRELE is provided which doesn't unlock the lock but
 * can only be used when the caller can gaurantee that it's not the last ref
 * (e.g. the caller has another outstanding reference) as if it's the last
 * ref the node_t may no longer exist. The new macro is NODE_REFRELE_LOCKED.
 */

#define	NODE_DISOWN(np) {						\
									\
	NODE_T_TRACE((np), NODE_T_TRACE_DISOWN);			\
	ASSERT(mutex_owned(&(np)->lock));				\
									\
	if ((np)->ref & REF_OWNED) {					\
		if ((np)->cnt == 0)	{				\
			panic("nca NODE_DISOWN: %p has no references",	\
			    (void *)(np));				\
		}							\
		(np)->ref &= ~REF_OWNED;				\
		NODE_REFRELE(np);					\
	} else {							\
		mutex_exit(&(np)->lock);				\
	}								\
}

#define	NODE_OWN(np) {							\
									\
	NODE_T_TRACE((np), NODE_T_TRACE_OWN);				\
	ASSERT(mutex_owned(&(np)->lock));				\
									\
	if (!((np)->ref & REF_OWNED)) {					\
		if ((np)->cnt == UINT_MAX)				\
			panic(						\
			    "nca NODE_OWN: %p has too many references",	\
			    (void *)(np));				\
		(np)->ref |= REF_OWNED;					\
		(np)->cnt++;						\
	}								\
}

#define	NODE_REFHOLD(np) {						\
									\
	NODE_T_TRACE((np), NODE_T_TRACE_REFHOLD | ((np)->cnt + 1));	\
	ASSERT(mutex_owned(&(np)->lock));				\
									\
	if ((np)->cnt == UINT_MAX)					\
		panic("nca NODE_REFHOLD: %p has too many references",	\
		    (void *)(np));					\
	(np)->cnt++;							\
}

#define	NODE_REFRELE(np) {						\
									\
	NODE_T_TRACE((np), NODE_T_TRACE_REFRELE | ((np)->cnt - 1));	\
	ASSERT(mutex_owned(&(np)->lock));				\
									\
	if (((np)->ref & REF_OWNED) && (np)->cnt == 1)			\
		panic(							\
		    "nca NODE_REFRELE: %p has only OWNED reference",	\
		    (void *)(np));					\
	if ((np)->cnt == 0)						\
		panic("nca NODE_REFRELE: %p has no references",		\
		    (void *)(np));					\
	(np)->cnt--;							\
	if ((np)->cnt == 0) {						\
		ASSERT(((np)->ref & REF_OWNED) == 0);			\
		node_fr(np);		/* node_fr unlocks the lock */	\
	} else {							\
		mutex_exit(&(np)->lock);				\
	}								\
}

#define	NODE_REFRELE_LOCKED(np) {					\
	uint_t	_cnt = (np)->cnt;					\
									\
	NODE_T_TRACE((np), NODE_T_TRACE_REFRELE | (_cnt - 1));		\
	ASSERT(mutex_owned(&(np)->lock));				\
									\
	if ((np)->ref & REF_OWNED)					\
		_cnt--;							\
	if (((np)->ref & REF_OWNED) && _cnt == 0)			\
		panic("nca NODE_REFRELE_LOCKED: "			\
		    "%p has only OWNED reference", (void *)(np));	\
	if (_cnt == 0)							\
		panic("nca NODE_REFRELEL_LOCKED: "			\
		    "%p has no references", (void *)(np));		\
	if (_cnt == 1)							\
		panic("nca NODE_REFRELEL_LOCKED: "			\
		    "%p has only one reference", (void *)(np));		\
	(np)->cnt--;							\
}


/*
 * NODE_T_TRACE - trace node_t events.
 *
 * adb:
 * 32 bit
 *	*node_tp,0t8192-(((*node_tp)-node_tv)%0t48)/PXXDDnPnPnPnPnPnPnPnn
 *	node_tv,((*node_tp)-node_tv)%0t48/PXXDDnPnPnPnPnPnPnPnn
 *
 * 64 bit
 *	*node_tp,0t8192-(((*node_tp)-node_tv)%0t56)/PXXDDnXnXnXnXnXnXnXnn
 *	node_tv,((*node_tp)-node_tv)%0t56/PXXDDnXnXnXnXnXnXnXnn
 *
 * For incremental node tracing, note the value of node_tp (node_tp/X) after
 * a run, then replace that in the 2nd line for node_tv.
 */

#define	NODE_T_STK_DEPTH	6

struct node_ts {
	node_t	*node;
	unsigned action;
	unsigned ref;
	unsigned cnt;
	int	cpu;
	pc_t	stk[NODE_T_STK_DEPTH + 1];
};

#undef	NODE_T_TRACE_ON

#ifdef	NODE_T_TRACE_ON

#define	NODE_T_TRACE_ALLOC	0xFF000000	/* kmem_alloc() of */
#define	NODE_T_TRACE_ADD	0xFE000000	/* node_add() */

#define	NODE_T_TRACE_OWN	0xEF000000	/* node has been owned */
#define	NODE_T_TRACE_DISOWN	0xEE000000	/* node has been disowned */
#define	NODE_T_TRACE_DESBALLOC	0xED000000	/* desballoc() */
#define	NODE_T_TRACE_REFRELE	0xEC000000	/* refrele */
#define	NODE_T_TRACE_REFHOLD	0xEB000000	/* refhold */
#define	NODE_T_TRACE_NODE_FR	0xEA000000	/* node_fr() */

#define	NODE_T_TRACE_TEMPNODE	0xDF000000	/* node_temp() */
#define	NODE_T_TRACE_REPLACE	0xDE000000	/* node_replace() */
#define	NODE_T_TRACE_FLUSH	0xDD000000	/* node_flush() */
#define	NODE_T_TRACE_DOWNCALL	0xDC000000	/* downcall_service() */
#define	NODE_T_TRACE_DOWNCALL_2	0xDB000000	/* dcall_service->httpd_data */

#define	NODE_T_TRACE_DATA	0xCF000000	/* httpd_data() */

#define	NODE_T_TRACE_LRU	0xAF000000	/* nca_lru insert */
#define	NODE_T_TRACE_HTTPD	0xAE000000	/* call nca_httpd() */
#define	NODE_T_TRACE_MISS	0xAD000000	/* http_miss() */
#define	NODE_T_TRACE_TEMP	0xAC000000	/* np != *npp */
#define	NODE_T_TRACE_XMIT	0xAB000000	/* tcp_xmit() */
#define	NODE_T_TRACE_MISSED	0xAA000000	/* nca_missed() */

#define	NODE_T_TRACE_DEL	0x00000000	/* node_del() */

#if defined(__i386) || defined(__amd64)
#define	NODE_T_TRACE_STK() {						\
	_ix = getpcstack(&_p->stk[0], NODE_T_STK_DEPTH + 1);		\
	if (_ix < NODE_T_STK_DEPTH + 1) {				\
		_p->stk[_ix + 1] = 0;					\
	}								\
}
#else
#define	NODE_T_TRACE_STK() {						\
	_p->stk[0] = (pc_t)callee();					\
	_ix = getpcstack(&_p->stk[1], NODE_T_STK_DEPTH);		\
	if (_ix < NODE_T_STK_DEPTH) {					\
		_p->stk[_ix + 1] = 0;					\
	}								\
}
#endif

#define	NODE_TV_SZ 8192

extern struct node_ts node_tv[NODE_TV_SZ];
extern struct node_ts *node_tp;

#define	NODE_T_TRACE(p, a) {						\
	struct node_ts *_p;						\
	struct node_ts *_np;						\
	int    _ix;							\
									\
	do {								\
		_p = node_tp;						\
		if ((_np = _p + 1) == &node_tv[NODE_TV_SZ])		\
			_np = node_tv;					\
	} while (atomic_cas_ptr(&node_tp, _p, _np) != _p);		\
	_p->node = (p);							\
	_p->action = (a);						\
	_p->ref = (p) ? (p)->ref : 0;					\
	_p->cnt = (p) ? (p)->cnt : 0;					\
	_p->cpu = CPU->cpu_seqid;					\
	NODE_T_TRACE_STK();						\
}

#else	/* NODE_T_TRACE_ON */

#define	NODE_T_TRACE(p, a)

#endif	/* NODE_T_TRACE_ON */

/*
 * DOOR_TRACE - trace door node_t events.
 *
 * adb:
 * 32 bit
 *	*door_tp,0t8192-(((*door_tp)-door_tv)%0t112)/5XnPnPnPnPnPnPnPn64cnn
 *	door_tv,((*door_tp)-door_tv)%0t112/5XnPnPnPnPnPnPnPn64cnn
 * 64 bit
 *	*door_tp,0t8192-(((*door_tp)-door_tv)%0t128)/PXPXXnXnXnXnXnXnXnXn64cnn
 *	door_tv,((*door_tp)-door_tv)%0t128/PXPXXnXnXnXnXnXnXnXn64cnn
 */

#define	DOOR_STK_DEPTH	6

struct door_ts {
	struct nca_conn_s *cp;
	unsigned action;
	node_t	*np;
	int	ref;
	unsigned state;
	pc_t	stk[DOOR_STK_DEPTH + 1];
	char	data[64];
};

#undef	DOOR_TRACE_ON

#ifdef	DOOR_TRACE_ON

#define	DOOR_TRACE_UPCALL	0xF0000000	/* upcall() */
#define	DOOR_TRACE_UPCALL_RAW	0xF1000000	/* upcall() RAW ? */
#define	DOOR_TRACE_UPCALL_RET	0xFF000000	/* upcall() return */

#define	DOOR_TRACE_DOWNCALL	0xE0000000	/* downcall() */
#define	DOOR_TRACE_CONNECT	0xE1000000	/* connect() */
#define	DOOR_TRACE_CONNECT_DATA	0xE2000000	/* connect() */
#define	DOOR_TRACE_DIRECTFROM	0xE3000000	/* tee_splice() from */
#define	DOOR_TRACE_DIRECTTO	0xE4000000	/* tee_splice() to */
#define	DOOR_TRACE_DOWNCALL_RET	0xEF000000	/* downcall() return */

#define	DOOR_TRACE_INIT		0x80000000	/* doorcall_init() */
#define	DOOR_TRACE_INIT_RET	0x88000000	/* doorcall_init() return */

#if defined(__i386) || defined(__amd64)
#define	DOOR_TRACE_STK() {						\
	_ix = getpcstack(&_p->stk[0], DOOR_STK_DEPTH + 1);		\
	if (_ix < DOOR_STK_DEPTH + 1) {					\
		_p->stk[_ix] = 0;					\
	}								\
}
#else
#define	DOOR_TRACE_STK() {						\
	_p->stk[0] = (pc_t)callee();					\
	_ix = getpcstack(&_p->stk[1], DOOR_STK_DEPTH);			\
	if (_ix < DOOR_STK_DEPTH) {					\
		_p->stk[_ix + 1] = 0;					\
	}								\
}
#endif

#define	DOOR_TV_SZ 8192

extern struct door_ts door_tv[DOOR_TV_SZ];
extern struct door_ts *door_tp;

#define	DOOR_TRACE(io, d, d_sz, a) {				\
	nca_conn_t *_cp = (io) ? (nca_conn_t *)(io)->cid : (nca_conn_t *)NULL; \
	node_t *_req_np = _cp ? _cp->req_np : (node_t *)NULL;		\
	struct door_ts *_p;						\
	struct door_ts *_np;						\
	int    _ix;							\
									\
	do {								\
		_p = door_tp;						\
		if ((_np = _p + 1) == &door_tv[DOOR_TV_SZ])		\
			_np = door_tv;					\
	} while (atomic_cas_ptr(&door_tp, _p, _np) != _p);		\
	_p->cp = _cp;							\
	_p->np = _req_np;						\
	_p->action = (a);						\
	_p->ref = _req_np ? _req_np->ref : 0;				\
	if ((io)) {							\
		_p->state = ((io)->op == http_op ? 0x80000000 : 0) |	\
			    ((io)->more ? 0x40000000 : 0) |		\
			    ((io)->first ? 0x20000000 : 0) |		\
			    ((io)->advisory ? 0x10000000 : 0) |		\
			    ((io)->nocache ? 0x08000000 : 0) |		\
			    ((io)->preempt ? 0x04000000 : 0) |		\
			    ((io)->peer_len ? 0x02000000 : 0) |		\
			    ((io)->local_len ? 0x01000000 : 0) |	\
			    ((io)->data_len ? 0x00800000 : 0) |		\
			    (((io)->direct_type << 20) & 0x00700000) |	\
			    ((io)->direct_len ? 0x00080000 : 0) |	\
			    ((io)->trailer_len ? 0x00040000 : 0) |	\
			    (((io)->peer_len + (io)->local_len +	\
			    (io)->data_len + (io)->direct_len +		\
			    (io)->trailer_len) & 0x3FFFF);		\
	} else {							\
		_p->state = 0;						\
	}								\
	if ((d_sz)) {							\
		int _n = MIN((d_sz), 63);				\
									\
		bcopy((d), _p->data, _n);				\
		bzero(&_p->data[_n], 64 - _n);				\
	} else {							\
		bzero(_p->data, 64);					\
	}								\
	DOOR_TRACE_STK();						\
}

#else	/* DOOR_TRACE_ON */

#define	DOOR_TRACE(io, d, d_sz, a)

#endif	/* DOOR_TRACE_ON */

/*
 * NCA node LRU cache.  Defined here so that the NCA mdb module can use it.
 */
typedef struct lru_s {
	node_t		*phead;	/* Phys LRU list head (MRU) */
	node_t		*ptail;	/* Phys LRU list tail (LRU) */
	node_t		*vhead;	/* Virt LRU list head (MRU) */
	node_t 		*vtail;	/* Virt LRU list tail (LRU) */

	uint32_t	pcount;	/* Phys count of node_t members */
	uint32_t	vcount;	/* Virt count of node_t members */

	kmutex_t	lock;	/* Guarantee atomic access of above */
} lru_t;

/*
 * Per CPU instance structure.
 *
 * 32-bit adb: XXXnnDnnXXnnXXnnXDnnXXnn228+na
 * 64-bit adb: PPPnnD4+nnPPnnPPnnJDnnJ180+na
 */

typedef struct nca_cpu_s {

	node_t *persist_hdr_none;
	node_t *persist_hdr_close;
	node_t *persist_hdr_ka;

	uint32_t dcb_readers;	/* count of dcb_list readers for this CPU */

	nca_squeue_t *if_inq;	/* if_t input nca_squeue_t */
	nca_squeue_t *if_ouq;	/* if_t output nca_squeue_t */

	ti_t	*tcp_ti;	/* TCP TIMER list */
	tw_t	*tcp_tw;	/* TCP TIME_WAIT list */

	ddi_softintr_t soft_id;	/* soft interrupt id for if_inq worker */
	int	if_inq_cnt;	/* count of if_t.inq references */

	char	pad[256 - sizeof (node_t *) - sizeof (node_t *) -
		    sizeof (node_t *) - sizeof (uint32_t) -
		    sizeof (nca_squeue_t *) - sizeof (nca_squeue_t *) -
		    sizeof (ti_t *) - sizeof (tw_t *) -
		    sizeof (ddi_softintr_t) - sizeof (int)];
} nca_cpu_t;

extern nca_cpu_t *nca_gv;	/* global per CPU state indexed by cpu_seqid */

/*
 * hcb_t - host control block.
 *
 * Used early on in packet switching to select packets to be serviced by NCA
 * and optionally later on by the HTTP protocol layer to further select HTTP
 * request to be serviced.
 *
 * dcb_t - door control block.
 *
 * Used to associate one or more hcb_t(s) with a given httpd door instance.
 *
 * dcb_list - dcb_t global list, a singly linked grounded list of dcb_t's.
 *
 * Used to search for a hcb_t match, currently a singly linked grounded list
 * of dcb_t's with a linear walk of the list. While this is adequate for the
 * current httpd support (i.e. a single door) a move to either a hash or tree
 * will be required for multiple httpd instance support (i.e. multiple doors).
 *
 * The dcb_list is protected by a custom reader/writer lock, the motivation
 * for using a custom lock instead of a krwlock_t is that this lock is the
 * single hot spot in NCA (i.e. all in-bound packets must acquire this lock)
 * and a nonlocking atomic readers count scheme is used in the common case
 * (i.e. reader lock) with a fall-back to a conventional kmutex_t for writer
 * (i.e. ndd list add/delete).
 */

typedef struct hcb_s {
	struct hcb_s	*next;		/* Next hcb_t (none: NULL) */
	ipaddr_t	addr;		/* IP address (any: INADDR_ANY or 0) */
	uint16_t	port;		/* TCP port number */
	char		*host;		/* Host: name (any: NULL) */
	ssize_t		hostsz;		/* Size of above */
	char		*root;		/* Document root ("/": NULL) */
	ssize_t		rootsz;		/* Size of above */
} hcb_t;

typedef struct dcb_s {
	struct dcb_s	*next;		/* Next dcb_t (none: NULL) */
	char		*door;		/* Door file (default: NULL) */
	ssize_t		doorsz;		/* Size of above */
	door_handle_t	hand;		/* Door handle (default: NULL) */
	hcb_t		list;		/* Head of a hcb_t list (any: NULL) */
} dcb_t;

extern dcb_t dcb_list;
extern kmutex_t nca_dcb_lock;
extern kcondvar_t nca_dcb_wait;
extern kmutex_t nca_dcb_readers;

#define	NOHANDLE ((door_handle_t)-1)

#define	DCB_COUNT_USELOCK	0x80000000
#define	DCB_COUNT_MASK		0x3FFFFFFF

#define	DCB_RD_ENTER(cpu) {						\
	uint32_t *rp;							\
									\
	cpu = CPU->cpu_seqid;						\
	rp = &nca_gv[cpu].dcb_readers;					\
	while (atomic_add_32_nv(rp, 1) & DCB_COUNT_USELOCK) {		\
		/* Need to use the lock, so do the dance */		\
		mutex_enter(&nca_dcb_lock);				\
		if (atomic_add_32_nv(rp, -1) == DCB_COUNT_USELOCK &&	\
		    CV_HAS_WAITERS(&nca_dcb_wait)) {			\
			/* May be the last reader for this CPU */	\
			cv_signal(&nca_dcb_wait);			\
		}							\
		mutex_exit(&nca_dcb_lock);				\
		mutex_enter(&nca_dcb_readers);				\
		/*							\
		 * We block above waiting for the writer to exit the	\
		 * readers lock, if we didn't block then while we were	\
		 * away in the nca_dcb_lock enter the writer exited,	\
		 * we could optimize for this case by checking USELOCK	\
		 * after the decrement, but as this is an exceptional	\
		 * case not in the fast-path we'll just take the hit	\
		 * of a needless readers enter/exit.			\
		 */							\
		mutex_exit(&nca_dcb_readers);				\
	}								\
}

#define	DCB_RD_EXIT(cpu) {						\
	uint32_t *rp = &nca_gv[cpu].dcb_readers;			\
									\
	if (atomic_dec_32_nv(rp) == DCB_COUNT_USELOCK) {		\
		mutex_enter(&nca_dcb_lock);				\
		if (CV_HAS_WAITERS(&nca_dcb_wait)) {			\
			/* May be the last reader for this CPU */	\
			cv_signal(&nca_dcb_wait);			\
		}							\
		mutex_exit(&nca_dcb_lock);				\
	}								\
}

#define	DCB_WR_ENTER() {						\
	int cpu;							\
	int readers;							\
									\
	mutex_enter(&nca_dcb_readers);					\
	mutex_enter(&nca_dcb_lock);					\
	for (;;) {							\
		readers = 0;						\
		for (cpu = 0; cpu < max_ncpus; cpu++) {			\
			int new;					\
			uint32_t *rp = &nca_gv[cpu].dcb_readers;	\
			int old = *rp;					\
									\
			if (old & DCB_COUNT_USELOCK) {			\
				readers += old & DCB_COUNT_MASK;	\
				continue;				\
			}						\
			new = old | DCB_COUNT_USELOCK;			\
			while (atomic_cas_32(rp, old, new) != old) {	\
				old = *rp;				\
				new = old | DCB_COUNT_USELOCK;		\
			}						\
			readers += (new & DCB_COUNT_MASK);		\
		}							\
		if (readers == 0)					\
			break;						\
		cv_wait(&nca_dcb_wait, &nca_dcb_lock);			\
	}								\
	mutex_exit(&nca_dcb_lock);					\
}

#define	DCB_WR_EXIT() {							\
	int cpu;							\
									\
	mutex_enter(&nca_dcb_lock);					\
	for (cpu = 0; cpu < max_ncpus; cpu++) {				\
		int new;						\
		uint32_t *rp = &nca_gv[cpu].dcb_readers;		\
		int old = *rp;						\
									\
		new = old & ~DCB_COUNT_USELOCK;				\
		while (atomic_cas_32(rp, old, new) != old) {		\
			old = *rp;					\
			new = old & ~DCB_COUNT_USELOCK;			\
		}							\
	}								\
	mutex_exit(&nca_dcb_lock);					\
	mutex_exit(&nca_dcb_readers);					\
}

typedef struct nca_door_s {
	door_handle_t	handle;		/* The door handle */
	char		*name;		/* The door name */
	kmutex_t	lock;		/* The door lock */
	kcondvar_t	cv_writer;	/* condvar for thread waiting */
					/* to do door_init */
	kcondvar_t	cv_reader;	/* condvar for thread waiting */
					/* for a door_init to finish */
	uint32_t	upcalls;	/* Number of upcalls in progress */
	boolean_t	init_waiting;	/* door_init thread wanting to */
					/* be exclusive */
} nca_door_t;

/*
 * if_t - interface per instance data.
 */

typedef struct if_s {

	boolean_t dev;		/* is a device instance */

	queue_t	*rqp;		/* our read-side STREAMS queue */
	queue_t	*wqp;		/* our write-side STREAMS queue */

	/* DLPI M_DATA IP fastpath template */
	size_t	mac_length;
	mblk_t	*mac_mp;
	int32_t	mac_mtu;
	int32_t	mac_addr_len;

	uint32_t ip_ident;	/* our IP ident value */

	boolean_t hwcksum;	/* underlying NIC supports checksum offload */

	nca_squeue_t *inq;		/* in-bound nca_squeue_t */
	nca_squeue_t *ouq;		/* out-bound nca_squeue_t */

	/*
	 * All if_t are associated with a CPU and have a default
	 * router on link are chained in a circular linked list.
	 */
	struct if_s *next_if;
	struct if_s *prev_if;
	ipaddr_t local_addr;	/* This interface's IP address. */
	uchar_t router_ether_addr[6];

	uint_t	hdr_ioc_id;	/* id of DL_IOC_HDR_INFO M_IOCTL sent down */
	boolean_t info_req_pending;

	int32_t	capab_state;	/* Capability probe state */

	/* Bound local address of a NCAfs instance. */
	struct sockaddr_in	bound_addr;
} if_t;

/*
 * connf_t - connection fanout data.
 *
 * The hash tables and their linkage (hashnextp, hashprevp) are protected
 * by the per-bucket lock. Each nca_conn_t inserted in the list points back at
 * the connf_t that heads the bucket.
 */

typedef struct connf_s {
	uint32_t	max;
	struct nca_conn_s	*head;
	kmutex_t	lock;
} connf_t;

#ifdef	CONNP_T_TRACE_ON

#define	CONNP_TV_SZ 32

/*
 * Per nca_conn_t packet tracing.
 */
typedef struct connp_s {
	clock_t		lbolt;
	clock_t		tcp_ti;
	int32_t		len : 16,
			dir : 1,
			state : 4,
			flags : 6,
			xmit_np : 1,
			xmit_head : 1,
			unsent : 1,
			tail_unsent : 1,
			direct : 1;
	uint32_t	state1;
	uint32_t	state2;
	uint32_t	seq;
	uint32_t	ack;
	uint32_t	snxt;
	uint32_t	swnd;
} connp_t;

#endif	/* CONNP_T_TRACE_ON */

/*
 * nca_conn_t - connection per instance data.
 *
 * Note: hashlock is used to provide atomic access to all nca_conn_t members
 * above it. All other members are protected by the per CPU inq nca_squeue_t
 * which is used to serialize access to all nca_conn_t's per interface.
 *
 * Note: the nca_conn_t can have up to 3 NODE_REFHOLDs:
 *
 *	1) if req_np != NULL then a NODE_REFHOLD(req_np) was done:
 *
 *	    1.1) if http_refed then a NODE_REFHOLD(req_np) was done
 *
 *	    1.2) if http_frefed then a NODE_REFHOLD(req_np->fileback) was done
 *
 *
 * TODO: reorder elements in fast-path code access order.
 *
 * Dnn4XnXXDnnDnnXXXnnXXXnnUXnnXXXnnXXnnDDXXXDXDXDXnnDnnXXDDnXXXDDnnXXXDDnn
 * XXXDDnnXXXDDnnXXXDDnnXXnnDXXnn
 * b+++DDnAnDDDDDnnDnnUnnUUDXDUnnDnn20xnnXnnddnnUUUnnXXUnXXnnUUUnn
 * DDDDDDnnUUnnXXUXUnn4UD4Unn4UnUUnn
 * 64-bit: Xnn4+4pnnppEnEnn3pnn3pnnEJnnXXnnuunn4+ppnnXX3pD4+pD4+pD4+pnnEnnppnnD
 */

#define	TCP_XMIT_MAX_IX	5		/* Max xmit descriptors */

typedef struct nca_conn_s {

	int32_t ref;			/* Reference counter */

	te_t	tcp_ti;			/* TCP TIMER timer entry */

	struct nca_conn_s	*twnext;	/* TIME_WAIT next */
	struct nca_conn_s	*twprev;	/* TIME_WAIT prev */
	clock_t	twlbolt;		/* TIME_WAIT lbolt */

	clock_t create;			/* Create lbolt time */

	connf_t	*hashfanout;		/* Hash bucket we're part of */
	struct nca_conn_s	*hashnext;	/* Hash chain next */
	struct nca_conn_s	*hashprev;	/* Hash chain prev */

	struct nca_conn_s	*bindnext;	/* Next conn_s in bind list. */
	struct nca_conn_s	*bindprev;	/* Prev conn_s in bind list. */
	void		*tbf;		/* Pointer to bind hash list struct. */
	/*
	 * Note: atomic access of memebers above is guaranteed by the
	 * hashfanout->lock of the hash bucket that the nca_conn_t is in.
	 */

	size_t	mac_length;		/* MAC prepend length */
	mblk_t	*mac_mp;		/* MAC prepend data */

	ipaddr_t	laddr;		/* Local address */
	ipaddr_t	faddr;		/* Remote address. 0 => not connected */

	union {
		struct {
			uint16_t u_fport; /* Remote port */
			uint16_t u_lport; /* Local port */
		} u_ports1;
		uint32_t u_ports2;	/* Rem port, local port */
					/* Used for TCP_MATCH performance */
	} u_port;
#define	conn_lport	u_port.u_ports1.u_lport
#define	conn_fport	u_port.u_ports1.u_fport
#define	conn_ports	u_port.u_ports2

	if_t	*ifp;			/* Interface for this connection */
	nca_squeue_t *inq;		/* Per CPU inq for this connection */

	uint32_t req_tag;		/* nca_io_t request tag (0 == NONE) */
	int	req_parse;		/* HTTP request parse state */
	node_t	*req_np;		/* HTTP request node_t */
	mblk_t	*req_mp;		/* HTTP request mblk_t */
	char	*reqpath;		/* HTTP request URI path component */
	int	reqpathsz;		/* size of above */
	char	*reqrefer;		/* HTTP "Referer:" string */
	int	reqrefersz;		/* size of above */
	char	*requagent;		/* HTTP "User-Agent:" string */
	int	requagentsz;		/* size of above */
	struct nca_conn_s *nodenext;	/* Node_t nca_conn_t list */

	clock_t	http_count;		/* HTTP Keep-Alive request count */

	/*
	 * req_np xmit state used accross calls to tcp_xmit(). A reference
	 * to the req_np and to any inderect node_t (i.e. file/ctag) ...
	 */
	node_t	*xmit_refed;		/* have a ref to the uri node_t */
	node_t	*xmit_cur;		/* current node to transmit */

	int	xmit_ix;		/* current xmit[] index */
	int	xmit_pix;		/* past end xmit[] index */

	struct {
		node_t	*np;		/* node_t pointer for ref */
		char	*dp;		/* data pointer */
		uint16_t *cp;		/* cksum array */
		int	sz;		/* remaining data to xmit */
		int	iso;		/* initial segment offset (if any) */
		node_t	*refed;		/* have a ref to the node_t */
		int	dsz;		/* remaining data for current segment */
		caddr_t	*dvp;		/* data segment virtual pointer */
	} xmit[TCP_XMIT_MAX_IX];

	/*
	 * Connection NCA_IO_DIRECT_SPLICE & NCA_IO_DIRECT_TEE reference,
	 * see direct_splice and direct_tee below for type of send too.
	 */
	struct nca_conn_s	*direct; /* nca_conn_t to send recv data too */
	mblk_t		*direct_mp;	 /* mblk_t to use for tcp_close() */

	/*
	 * nca_conn_t state.
	 */

	int32_t	tcp_state;

	uint32_t
		tcp_urp_last_valid : 1,	/* Is tcp_urp_last valid? */
		tcp_hard_binding : 1,	/* If we've started a full bind */
		tcp_hard_bound : 1,	/* If we've done a full bind with IP */
		tcp_fin_acked : 1,	/* Has our FIN been acked? */

		tcp_fin_rcvd : 1,	/* Have we seen a FIN? */
		tcp_fin_sent : 1,	/* Have we sent our FIN yet? */
		tcp_ordrel_done : 1,	/* Have we sent the ord_rel upstream? */
		tcp_flow_stopped : 1,	/* Have we flow controlled xmitter? */

		tcp_debug : 1,		/* SO_DEBUG "socket" option. */
		tcp_dontroute : 1,	/* SO_DONTROUTE "socket" option. */
		tcp_broadcast : 1,	/* SO_BROADCAST "socket" option. */
		tcp_useloopback : 1,	/* SO_USELOOPBACK "socket" option. */

		tcp_oobinline : 1,	/* SO_OOBINLINE "socket" option. */
		tcp_dgram_errind : 1,	/* SO_DGRAM_ERRIND option */
		tcp_detached : 1,	/* If we're detached from a stream */
		tcp_bind_pending : 1,	/* Client is waiting for bind ack */

		tcp_unbind_pending : 1, /* Client sent T_UNBIND_REQ */
		tcp_deferred_clean_death : 1,
					/* defer tcp endpoint cleanup etc. */
		tcp_co_wakeq_done : 1,	/* A strwakeq() has been done */
		tcp_co_wakeq_force : 1,	/* A strwakeq() must be done */

		tcp_co_norm : 1,	/* In normal mode, putnext() done */
		tcp_co_wakeq_need : 1,	/* A strwakeq() needs to be done */
		tcp_snd_ws_ok : 1,	/* Received WSCALE from peer */
		tcp_snd_ts_ok : 1,	/* Received TSTAMP from peer */

		tcp_linger : 1,		/* SO_LINGER turned on */
		tcp_zero_win_probe: 1,	/* Zero win probing is in progress */
		tcp_loopback: 1,	/* src and dst are the same machine */
		tcp_localnet: 1,	/* src and dst are on the same subnet */

		tcp_syn_defense: 1,	/* For defense against SYN attack */
#define	tcp_dontdrop	tcp_syn_defense
		tcp_set_timer : 1,
		tcp_1_junk_fill_thru_bit_31 : 2;

	uint32_t
		tcp_active_open: 1,	/* This is a active open */
		tcp_timeout : 1,	/* qbufcall failed, qtimeout pending */
		tcp_rexmit : 1,		/* TCP is retransmitting */
		tcp_snd_sack_ok : 1,	/* Can use SACK for this connection */

		tcp_bind_proxy_addr : 1,	/* proxy addr is being used */
		tcp_recvdstaddr : 1,	/* return T_EXTCONN_IND with dst addr */
		tcp_refed : 1,		/* nca_conn_t refed by TCP */
		tcp_time_wait_comp : 1, /* TIME_WAIT compressed nca_conn_t */

		tcp_close : 1,		/* nca_conn_t close */
		http_persist : 3,	/* HTTP persistent connection state */

		deferred_xmit_end : 1,	/* xmit_end() deferred to xmit() */
		http_direct_splice : 1,	/* have a connection to splice too */
		http_direct_tee : 1,	/* have a connection to tee too */

		tcp_2_junk_fill_thru_bit_31 : 17;
/*
 * Note: all nca_conn_t members to be accessed by a tcp_time_wait_comp
 * nca_conn_t must be above this point !!!
 */

	uchar_t	tcp_timer_backoff;	/* Backoff shift count. */
	clock_t tcp_last_recv_time;	/* Last time we receive a segment. */
	clock_t	tcp_dack_set_time;	/* When delayed ACK timer is set. */

	int	tcp_ip_hdr_len;		/* Byte len of our current IP header */
	clock_t	tcp_first_timer_threshold;  /* When to prod IP */
	clock_t	tcp_second_timer_threshold; /* When to give up completely */
	clock_t	tcp_first_ctimer_threshold; /* 1st threshold while connecting */
	clock_t tcp_second_ctimer_threshold; /* 2nd ... while connecting */

	clock_t	tcp_last_rcv_lbolt; /* lbolt on last packet, used for PAWS */


	uint32_t tcp_obsegs;		/* Outbound segments on this stream */

	uint32_t tcp_mss;		/* Max segment size */
	uint32_t tcp_naglim;		/* Tunable nagle limit */
	int32_t	tcp_hdr_len;		/* Byte len of combined TCP/IP hdr */
	tcph_t	*tcp_tcph;		/* tcp header within combined hdr */
	int32_t	tcp_tcp_hdr_len;	/* tcp header len within combined */
	uint32_t	tcp_valid_bits;
#define	TCP_ISS_VALID	0x1	/* Is the tcp_iss seq num active? */
#define	TCP_FSS_VALID	0x2	/* Is the tcp_fss seq num active? */
#define	TCP_URG_VALID	0x4	/* If the tcp_urg seq num active? */

	int32_t	tcp_xmit_hiwater;	/* Send buffer high water mark. */

	union {				/* template ip header */
		ipha_t	tcp_u_ipha;
		char	tcp_u_buf[IP_SIMPLE_HDR_LENGTH+TCP_MIN_HEADER_LENGTH];
		double	tcp_u_aligner;
	} tcp_u;
#define	tcp_ipha	tcp_u.tcp_u_ipha
#define	tcp_iphc	tcp_u.tcp_u_buf

	uint32_t tcp_sum;		/* checksum to compensate for source */
					/* routed packets. Host byte order */

	uint16_t tcp_last_sent_len;	/* Record length for nagle */
	uint16_t tcp_dupack_cnt;	/* # of consequtive duplicate acks */

	uint32_t tcp_rnxt;		/* Seq we expect to recv next */
	uint32_t tcp_rwnd;		/* Current receive window */
	uint32_t tcp_rwnd_max;		/* Maximum receive window */

	mblk_t	*tcp_rcv_head;		/* Queued until push, urgent data or */
	mblk_t	*tcp_rcv_tail;		/* the count exceeds */
	uint32_t tcp_rcv_cnt;		/* tcp_rcv_push_wait. */

	mblk_t	*tcp_reass_head;	/* Out of order reassembly list head */
	mblk_t	*tcp_reass_tail;	/* Out of order reassembly list tail */

	uint32_t tcp_cwnd_ssthresh;	/* Congestion window */
	uint32_t tcp_cwnd_max;
	uint32_t tcp_csuna;		/* Clear (no rexmits in window) suna */

	int	tcp_rttv_updates;
	clock_t	tcp_rto;		/* Round trip timeout */
	clock_t	tcp_rtt_sa;		/* Round trip smoothed average */
	clock_t	tcp_rtt_sd;		/* Round trip smoothed deviation */
	clock_t	tcp_rtt_update;		/* Round trip update(s) */
	clock_t tcp_ms_we_have_waited;	/* Total retrans time */

	uint32_t tcp_swl1;		/* These help us avoid using stale */
	uint32_t tcp_swl2;		/*  packets to update state */

	mblk_t	*tcp_xmit_head;		/* Head of rexmit list */
	mblk_t	*tcp_xmit_last;		/* last valid data seen by tcp_wput */
	uint32_t tcp_unsent;		/* # of bytes in hand that are unsent */
	mblk_t	*tcp_xmit_tail;		/* Last rexmit data sent */
	uint32_t tcp_xmit_tail_unsent;	/* # of unsent bytes in xmit_tail */

	uint32_t tcp_snxt;		/* Senders next seq num */
	uint32_t tcp_suna;		/* Sender unacknowledged */
	uint32_t tcp_rexmit_nxt;	/* Next rexmit seq num */
	uint32_t tcp_rexmit_max;	/* Max retran seq num */
	int32_t	tcp_snd_burst;		/* Send burst factor */
	uint32_t tcp_swnd;		/* Senders window (relative to suna) */
	uint32_t tcp_cwnd;		/* Congestion window */
	int32_t tcp_cwnd_cnt;		/* cwnd cnt in congestion avoidance */
	uint32_t tcp_ackonly;		/* Senders last ack seq num */

	uint32_t tcp_irs;		/* Initial recv seq num */
	uint32_t tcp_iss;		/* Initial send seq num */
	uint32_t tcp_fss;		/* Final/fin send seq num */
	uint32_t tcp_urg;		/* Urgent data seq num */

	uint32_t tcp_rack;		/* Seq # we have acked */
	uint32_t tcp_rack_cnt;		/* # of bytes we have deferred ack */

	uint32_t tcp_max_swnd;		/* Maximum swnd we have seen */
	int64_t	tcp_rexmit_fire_time;
	int64_t	tcp_dack_fire_time;
	int64_t tcp_ka_fire_time;
	int64_t	tcp_http_ka_fire_time;

	int32_t	tcp_keepalive_intrvl;	/* Zero means don't bother */
	int32_t	tcp_ka_probe_sent;
	int32_t tcp_ka_last_intrvl;

#define	TCP_DACK_TIMER		0x1
#define	TCP_REXMIT_TIMER	0x2
#define	TCP_KA_TIMER		0x4
#define	TCP_HTTP_KA_TIMER	0x8
	int16_t		tcp_running_timer;
	int16_t		tcp_pending_timer;

#ifdef	CONNP_T_TRACE_ON
	connp_t *pkt_tp;		/* Packet tracing pointer */
	connp_t	pkt_tv[CONNP_TV_SZ];	/* Packet tracing vector */
#endif	/* CONNP_T_TRACE_ON */

} nca_conn_t;

/*
 * Active stack support parameters to control what ports NCA can use.
 * They are declared in ncaproto.c
 */
extern struct nca_tbf_s *nca_tcp_port;
extern in_port_t tcp_lo_port;
extern in_port_t tcp_hi_port;

/*
 * nca_conn_t.http_persist values and corresponding HTTP header strings are
 * used to determine the connection persistent state of a connection and
 * any HTTP header which needs to be sent.
 */

#define	PERSIST_NONE		0	/* Not persistent */

#define	PERSIST_CLOSE		1	/* Was persistent, send close header */
#define	PERSIST_TRUE		2	/* Connection is HTTP persistent */
#define	PERSIST_KA		3	/* Persistent, send Keep-Alive header */
#define	PERSIST_UPCALL		4	/* Insert "Connection: close" on */
					/* upcall and clear flag */

#define	PERSIST_HDR_NONE	"\r\n"
#define	PERSIST_HDR_CLOSE	"Connection: close\r\n\r\n"
#define	PERSIST_HDR_KA		"Connection: Keep-Alive\r\n\r\n"

/*
 * nca_conn_t nca_squeue_ctl() flag values:
 */

#define	CONN_MISS_DONE		0x0001	/* The conn miss processing is done */
#define	IF_TIME_WAIT		0x0002	/* A TIME_WAIT has fired */
#define	IF_TCP_TIMER		0x0003	/* A TCP TIMER has fired */
#define	NCA_CONN_TCP_TIMER	0x0004	/* A TCP TIMER needs to be execed */
#define	IF_TCP_CONNECT		0x0005	/* TCP connection request */
#define	IF_TCP_SEND		0x0006	/* A new send request. */

#define	IF_TCP_DIRECT_TO	0x0010	/* A TCP direct i/o, step 1 */
#define	IF_TCP_DIRECT_FROM	0x0012	/* A TCP direct i/o, step 2 */
#define	IF_TCP_DIRECT_TEE	0x0001	/* If a tee else a splice */
#define	IF_TCP_DIRECT_CLOSE	0x001F	/* A TCP direct i/o close */

#define	NCA_CONN_T_STK_DEPTH	7	/* max stack backtrace depth */

struct conn_ts {
	nca_conn_t	*conn;
	unsigned action;
	int	ref;
	int	cpu;
	pc_t	stk[NCA_CONN_T_STK_DEPTH + 1];
};

#undef	NCA_CONN_T_TRACE_ON

#ifdef	NCA_CONN_T_TRACE_ON

/*
 * adb:
 * 32 bit
 *	*conn_tp,0t4096-(((*conn_tp)-con_tv)%0t48)/PXDDnPnPnPnPnPnPnPnPnn
 *	con_tv,((*conn_tp)-con_tv)%0t48/PXDDnPnPnPnPnPnPnPnPnn
 * 64 bit
 *	*conn_tp,0t4096-(((*conn_tp)-con_tv)%0t56)/PXDDnXnXnXnXnXnXnXnXnn
 *	con_tv,((*conn_tp)-con_tv)%0t56/PXDDnXnXnXnXnXnXnXnXnn
 */

#define	NCA_CONN_T_REFINIT	0x10000000	/* CONN_REF init() |ref value */
#define	NCA_CONN_T_REFINIT1	0x11000000	/* CONN_REF init() |ref value */
#define	NCA_CONN_T_REFINIT2	0x12000000	/* CONN_REF init() |ref value */
#define	NCA_CONN_T_REFNOTCP	0x13000000 /* CONN_REF no longer tcp_refed */
#define	NCA_CONN_T_REFHOLD	0x1A000000	/* CONN_REFHOLD() | ref value */
#define	NCA_CONN_T_REFRELE	0x1F000000	/* CONN_REFRELE() | ref value */

#define	NCA_CONN_T_HTTPCALL	0x20000000	/* call http() | rbytes */
#define	NCA_CONN_T_HTTPRET1	0x21000000	/* return http() */
#define	NCA_CONN_T_HTTPRET2	0x22000000	/* return ! http() */

#define	NCA_CONN_T_MISSDONE	0x30000000	/* CONN_MISS_DONE */
#define	NCA_CONN_T_TCPTIMER	0x31000000	/* NCA_CONN_TCP_TIMER */
#define	NCA_CONN_T_XMIT_END	0x32000000	/* xmit_end() | tcp_unsent */
#define	NCA_CONN_T_XMIT_BAD	0x33000000 /* xmit_end() bad state |tcp_state */
#define	NCA_CONN_T_XMIT_DEF	0x34000000	/* xmit_end() deferred */
#define	NCA_CONN_T_TIME_WAIT 0x35000000	/* done: tcp_state == TCPS_TIME_WAIT */
#define	NCA_CONN_T_PKT_IN	0x36000000	/* tcp_input() | flags */
#define	NCA_CONN_T_PKT_OUT	0x37000000	/* tcp_input() | flags */

#define	NCA_CONN_T_DIRECT	0x40000000	/* tcp_direct() from conn_t */
#define	NCA_CONN_T_DIRECT1	0x41000000	/* tcp_direct() to conn_t */
#define	NCA_CONN_T_DIRECT2	0x42000000	/* IF_TCP_DIRECT_TO | TEE */
#define	NCA_CONN_T_DIRECT3	0x43000000	/* IF_TCP_DIRECT_FROM | TEE */
#define	NCA_CONN_T_DIRECT4	0x44000000	/* tcp_close() */
#define	NCA_CONN_T_DIRECT5	0x45000000	/* IF_TCP_DIRECT_CLOSE */
						/* from|tcp_state */
#define	NCA_CONN_T_DIRECT6	0x46000000	/* IF_TCP_DIRECT_CLOSE to */

#if defined(__i386) || defined(__amd64)
#define	NCA_CONN_T_TRACE_STK() {					\
	_ix = getpcstack(&_p->stk[0], NCA_CONN_T_STK_DEPTH + 1);	\
	if (_ix < NCA_CONN_T_STK_DEPTH + 1) {				\
		_p->stk[_ix + 1] = 0;					\
	}								\
}
#else
#define	NCA_CONN_T_TRACE_STK() {					\
	_p->stk[0] = (pc_t)callee();					\
	_ix = getpcstack(&_p->stk[1], NCA_CONN_T_STK_DEPTH);		\
	if (_ix < NCA_CONN_T_STK_DEPTH) {				\
		_p->stk[_ix + 1] = 0;					\
	}								\
}
#endif

#define	CON_TV_SZ 4096

extern struct conn_ts con_tv[CON_TV_SZ];
extern struct conn_ts *conn_tp;

#define	NCA_CONN_T_TRACE(p, a) {					\
	struct conn_ts *_p;						\
	struct conn_ts *_np;						\
	int    _ix;							\
									\
	do {								\
		_p = conn_tp;					\
		if ((_np = _p + 1) == &con_tv[CON_TV_SZ])	\
			_np = con_tv;				\
	} while (atomic_cas_ptr(&conn_tp, _p, _np) != _p);		\
	_p->conn = (p);							\
	_p->action = (a);						\
	_p->ref = (p)->ref;						\
	_p->cpu = CPU->cpu_seqid;					\
	NCA_CONN_T_TRACE_STK();						\
}

#else	/* NCA_CONN_T_TRACE_ON */

#define	NCA_CONN_T_TRACE(p, a)

#endif	/* NCA_CONN_T_TRACE_ON */


#define	CONN_REFHOLD(connp) {						\
									\
	NCA_CONN_T_TRACE((connp), NCA_CONN_T_REFHOLD | ((connp)->ref + 1)); \
									\
	if ((connp)->ref <= 0)						\
		panic("nca CONN_REFHOLD: %p has no references",		\
		    (void *)(connp));					\
	(connp)->ref++;							\
}

#define	CONN_REFRELE(connp) {						\
									\
	NCA_CONN_T_TRACE((connp), NCA_CONN_T_REFRELE | ((connp)->ref - 1)); \
									\
	if ((connp)->tcp_refed) {					\
		if ((connp)->ref == 1)					\
			panic("nca CONN_REFRELE: %p "			\
			    "has only tcp_refed reference",		\
			    (void *)(connp));				\
		if ((connp)->ref < 1)					\
			panic("nca CONN_REFRELE: %p has no references",	\
			    (void *)(connp));				\
	} else {							\
		if ((connp)->ref <= 0)					\
			panic("nca CONN_REFRELE: %p has no references",	\
			    (void *)(connp));				\
	}								\
	(connp)->ref--;							\
	if ((connp)->ref == 0) {					\
		/* Last ref of a nca_conn_t, so free it */		\
		kmutex_t *lock = &(connp)->hashfanout->lock;		\
		mutex_enter(lock);					\
		nca_conn_free(connp);					\
		/* Note: nca_conn_free exits lock */			\
	}								\
}

/*
 * The nca_io2_shadow_t is used by the kernel to contian a copy of a user-
 * land nca_io2_t and the the user-land nca_io2_t address and size.
 */

typedef struct nca_io2_shadow_s {
	nca_io2_t	io;		/* copy of user-land nca_io2_t */
	void		*data_ptr;	/* copy of door_arg_t.data_ptr */
	size_t		data_size;	/* copy of door_arg_t.data_size */
} nca_io2_shadow_t;

#define	SHADOW_NONE	0x00		/* nca_io2_t.shadow NONE */
#define	SHADOW_DOORSRV	0x01		/* nca_io2_t.shadow door_srv() */
#define	SHADOW_NCAFS	0x02		/* nca_io2_t.shadow NCAfs */


/*
 * Given a ptr to a nca_io2_t, a field and the field_length, write data
 * into buffer (Note: word aligned offsets).
 */
#define	NCA_IO_WDATA(val, vsize, p, n_used, len, off)		\
	/*CONSTCOND*/						\
	if ((val) == NULL) {					\
		(p)->len = vsize;				\
		(p)->off = 0;					\
	} else {						\
		(p)->len = (vsize);				\
		(p)->off = ((n_used) + sizeof (uint32_t) - 1) &	\
				(~(sizeof (uint32_t) - 1));	\
		bcopy((char *)(val),				\
		    ((char *)(p) + (p)->off), (vsize));		\
		(n_used) = (p)->off + (p)->len;			\
	}

/*
 * Given a ptr to an nca_io2_t, a field length member name, append data to
 * it in the buffer. Note: must be the last field a WDATA() was done for.
 *
 * Note: a NULL NCA_IO_WDATA() can be followed by a NCA_IO_ADATA() only if
 *		vsize was == -1.
 *
 */
#define	NCA_IO_ADATA(val, vsize, p, n_used, len, off)		\
	if ((p)->len == -1) {					\
		(p)->len = 0;					\
		(p)->off = ((n_used) + sizeof (uint32_t) - 1) &	\
		(~(sizeof (uint32_t) - 1));			\
	}							\
	bcopy((char *)(val), ((char *)(p) + \
	    (p)->off + (p)->len), (vsize));			\
	(p)->len += (vsize);					\
	(n_used) += (vsize);

/*
 * Given a ptr to a nca_io2_t and a field construct a pointer.
 */
#define	NCA_IO_PDATA(p, off) ((char *)(p) + (p)->off)


#ifndef	isdigit
#define	isdigit(c) ((c) >= '0' && (c) <= '9')
#endif

#ifndef	tolower
#define	tolower(c) ((c) >= 'A' && (c) <= 'Z' ? (c) | 0x20 : (c))
#endif

#ifndef	isalpha
#define	isalpha(c) (((c) >= 'A' && (c) <= 'Z') || ((c) >= 'a' && (c) <= 'z'))
#endif

#ifndef	isspace
#define	isspace(c) ((c) == ' ' || (c) == '\t' || (c) == '\n' || \
		    (c) == '\r' || (c) == '\f' || (c) == '\013')
#endif

extern char *strnchr(const char *, int, size_t);
extern char *strnstr(const char *, const char *, size_t);
extern char *strncasestr(const char *, const char *, size_t);
extern char *strrncasestr(const char *, const char *, size_t);
extern int atoin(const char *, size_t);
extern int digits(int);

extern void nca_conn_free(nca_conn_t *);
extern void nca_logit_off(void);
extern void node_fr(node_t *);

extern nca_squeue_t *nca_squeue_init(nca_squeue_t *, uint32_t,
    processorid_t, void (*)(), void *, void (*)(), clock_t, pri_t);
extern void nca_squeue_fini(nca_squeue_t *);
extern void nca_squeue_enter(nca_squeue_t *, mblk_t *, void *);
extern void nca_squeue_fill(nca_squeue_t *, mblk_t *, void *);
extern mblk_t *nca_squeue_remove(nca_squeue_t *);
extern void nca_squeue_worker(nca_squeue_t *);
extern mblk_t *nca_squeue_ctl(mblk_t *, void *, unsigned short);
extern void nca_squeue_signal(nca_squeue_t *);
extern void nca_squeue_exit(nca_squeue_t *);
extern void sqfan_init(sqfan_t *, uint32_t, uint32_t, uint32_t);
extern nca_squeue_t *sqfan_ixinit(sqfan_t *, uint32_t, nca_squeue_t *, uint32_t,
    processorid_t, void (*)(), void *, void (*)(), clock_t, pri_t);
extern void sqfan_fini(sqfan_t *);
extern void sqfan_fill(sqfan_t *, mblk_t *, void *);
extern mblk_t *sqfan_remove(sqfan_t *);
extern void nca_squeue_nointr(nca_squeue_t *, mblk_t *, void *, int);
extern void nca_squeue_pause(nca_squeue_t *, mblk_t *, void *, int, boolean_t);
extern void nca_squeue_willproxy(nca_squeue_t *);
extern void nca_squeue_proxy(nca_squeue_t *, nca_squeue_t *);
extern void nca_squeue_bind(nca_squeue_t *, uint32_t, processorid_t);

extern int nca_tcp_clean_death(nca_conn_t *, int);
extern nca_conn_t *nca_tcp_connect(ipaddr_t, in_port_t, boolean_t);
extern void nca_tcp_send(nca_conn_t *, mblk_t *);
extern void nca_tcp_direct(nca_conn_t *, nca_conn_t *, uint32_t);

/* Functions prototypes from ncadoorsrv.c */
extern node_t *nca_node_flush(node_t *);
extern void nca_downcall_service(void *, door_arg_t *, void (**)(void *,
    void *), void **, int *);
extern node_t *ctag_lookup(uint64_t, unsigned *);
extern node_t *node_replace(node_t *, nca_conn_t *);
extern node_t *node_temp(node_t *, nca_conn_t *);
extern void find_ctags(node_t *, nca_io2_t *, int *);
extern void nca_ncafs_srv(nca_io2_t *, struct uio *, queue_t *);
extern boolean_t nca_reclaim_vlru(void);
extern boolean_t nca_reclaim_plru(boolean_t, boolean_t);

/*
 * NCA_COUNTER() is used to add a signed long value to a unsigned long
 * counter, in general these counters are used to maintain NCA state.
 *
 * NCA_DEBUG_COUNTER() is used like NCA_COUNTER() but for counters used
 * to maintain additional debug state, by default these counters aren't
 * updated unless the global value nca_debug_counter is set to a value
 * other then zero.
 *
 * Also, if NCA_COUNTER_TRACE is defined a time ordered wrapping trace
 * buffer is maintained with hrtime_t stamps, counter address, value to
 * add, and new value entries for all NCA_COUNTER() and NCA_DEBUG_COUNTER()
 * use.
 */

#undef	NCA_COUNTER_TRACE

#ifdef	NCA_COUNTER_TRACE

#define	NCA_COUNTER_TRACE_SZ	1024

typedef struct nca_counter_s {
	hrtime_t	t;
	unsigned long	*p;
	unsigned long	v;
	unsigned long	nv;
} nca_counter_t;

extern nca_counter_t nca_counter_tv[];
extern nca_counter_t *nca_counter_tp;

#define	NCA_COUNTER(_p, _v) {						\
	unsigned long	*p = _p;					\
	long		v = _v;						\
	unsigned long	_nv;						\
	nca_counter_t	*_otp;						\
	nca_counter_t	*_ntp;						\
									\
	_nv = atomic_add_long_nv(p, v);					\
	do {								\
		_otp = nca_counter_tp;					\
		_ntp = _otp + 1;					\
		if (_ntp == &nca_counter_tv[NCA_COUNTER_TRACE_SZ])	\
			_ntp = nca_counter_tv;				\
	} while (atomic_cas_ptr((void *)&nca_counter_tp, (void *)_otp,	\
	    (void *)_ntp) != (void *)_otp);				\
	_ntp->t = gethrtime();						\
	_ntp->p = p;							\
	_ntp->v = v;							\
	_ntp->nv = _nv;							\
}

#else	/* NCA_COUNTER_TRACE */

#define	NCA_COUNTER(p, v) atomic_add_long((p), (v))

#endif	/* NCA_COUNTER_TRACE */


/*
 * This is the buf used in upcall to httpd.
 */
typedef struct {
	uintptr_t	tid;
	char		*buf;
} http_buf_table_t;

/*
 * URI and filename hash, a simple static hash bucket array of singly
 * linked grounded lists is used with a hashing algorithm which has
 * proven to have good distribution properities for strings of ...
 *
 * Note: NCA_HASH_SZ must be a prime number.
 */

#define	NCA_HASH_SZ	8053
#define	NCA_HASH_MASK	0xFFFFFF
#define	HASH_IX(s, l, hix, hsz) { \
	char *cp = (s); \
	int len = (l); \
			\
	(hix) = 0; \
	while (len-- > 0) { \
		(hix) = (hix) * 33 + *cp++; \
		(hix) &= NCA_HASH_MASK; \
	} \
	(hix) %= (hsz); \
}

/*
 * CTAG hash.
 */
#define	NCA_CTAGHASH_SZ	4096
#define	CTAGHASH_IX(t, ix) ((ix) = (t) % NCA_CTAGHASH_SZ)

/*
 * VNODE hash.
 *
 * Note: NCA_VNODEHASH_SZ must be a P2Ps() value.
 */
#define	NCA_VNODEHASH_SZ 12281
#define	VNODEHASH_IX(p, ix) ((ix) = (((uintptr_t)p >> 27) ^ \
	((uintptr_t)p >> 17) ^ ((uintptr_t)p >> 11) ^ (uintptr_t)p) % \
	ncavnodehash_sz)

extern pgcnt_t nca_ppmax;
extern pgcnt_t nca_vpmax;
extern pgcnt_t nca_pplim;
extern pgcnt_t nca_vplim;
extern pgcnt_t nca_ppmem;
extern pgcnt_t nca_vpmem;
extern ssize_t nca_kbmem;
extern ssize_t nca_spmem;
extern ssize_t nca_ckmem;
extern ssize_t nca_mbmem;
extern ssize_t nca_cbmem;
extern ssize_t nca_lbmem;
extern size_t  nca_maxkmem;
extern uint32_t nca_use_segmap;

extern ulong_t nca_hits;
extern ulong_t nca_file;
extern ulong_t nca_ctag;
extern ulong_t nca_miss;

extern ulong_t nca_hit304;
extern ulong_t nca_hitnoV;
extern ulong_t nca_hitnoVfast;
extern ulong_t nca_hitnoVtemp;

extern ulong_t nca_filehits;
extern ulong_t nca_filenoV;
extern ulong_t nca_filenoVfast;
extern ulong_t nca_filemiss;

extern ulong_t nca_missURI;
extern ulong_t nca_missQ;
extern ulong_t nca_missSAFE;
extern ulong_t nca_missnoV;
extern ulong_t nca_missnotcp;
extern ulong_t nca_missfail;
extern ulong_t nca_misstemp;
extern ulong_t nca_missnohash;
extern ulong_t nca_missclean;
extern ulong_t nca_missadvisory;
extern ulong_t nca_missadvNoA;
extern ulong_t nca_missERROR;

extern ulong_t nca_ERROR;
extern ulong_t nca_flushnode;
extern ulong_t nca_replacenode;
extern ulong_t nca_tempnode;

extern ulong_t nca_fail304;

extern ulong_t nca_nocache1;
extern ulong_t nca_nocache2;
extern ulong_t nca_nocache3;
extern ulong_t nca_nocache4;
extern ulong_t nca_nocache5;
extern ulong_t nca_nocache6;
extern ulong_t nca_nocache6nomp;
extern ulong_t nca_nocache7;
extern ulong_t nca_nocache8;
extern ulong_t nca_nocache9;
extern ulong_t nca_nocache10;
extern ulong_t nca_nocache11;
extern ulong_t nca_nocache12;
extern ulong_t nca_nocache13;
extern ulong_t nca_nocache14;
extern ulong_t nca_nocache15;
extern ulong_t nca_nodes;
extern ulong_t nca_desballoc;

extern ulong_t nca_plrucnt;
extern ulong_t nca_vlrucnt;
extern ulong_t nca_rpcall;
extern ulong_t nca_rvcall;
extern ulong_t nca_rpbusy;
extern ulong_t nca_rvbusy;
extern ulong_t nca_rpfail;
extern ulong_t nca_rpempty;
extern ulong_t nca_rvempty;
extern ulong_t nca_rpdone;
extern ulong_t nca_rvdone;
extern ulong_t nca_rmdone;
extern ulong_t nca_rkdone;
extern ulong_t nca_rsdone;
extern ulong_t nca_rndone;
extern ulong_t nca_rpnone;
extern ulong_t nca_rvnone;
extern ulong_t nca_rmnone;
extern ulong_t nca_rknone;
extern ulong_t nca_rsnone;
extern ulong_t nca_rnh;
extern ulong_t nca_ref[];
extern ulong_t nca_vmap_rpcall;

extern ulong_t nca_node_kmem_fail1;
extern ulong_t nca_node_kmem_fail2;

extern ulong_t doorsrv_nopreempt;
extern ulong_t doorsrv_badconnect;
extern ulong_t doorsrv_invaladvise;
extern ulong_t doorsrv_notupcall;
extern ulong_t doorsrv_badadvise;
extern ulong_t doorsrv_cksum;
extern ulong_t doorsrv_error;
extern ulong_t doorsrv_op;
extern ulong_t doorsrv_badtee;
extern ulong_t doorsrv_badio;
extern ulong_t doorsrv_sz;

extern ulong_t nca_allocfail;
extern ulong_t nca_mapinfail;
extern ulong_t nca_mapinfail1;
extern ulong_t nca_mapinfail2;
extern ulong_t nca_mapinfail3;

extern ulong_t nca_httpd_http;
extern ulong_t nca_httpd_badsz;
extern ulong_t nca_httpd_nosz;
extern ulong_t nca_httpd_filename;
extern ulong_t nca_httpd_filename1;
extern ulong_t nca_httpd_filename2;
extern ulong_t nca_httpd_trailer;
extern ulong_t nca_httpd_preempt;
extern ulong_t nca_httpd_downcall;
extern ulong_t nca_early_downcall;
extern ulong_t nca_httpd_more;

ulong_t nca_logit_noupcall;

ulong_t nca_logit;
ulong_t nca_logit_nomp;
ulong_t nca_logit_no;
ulong_t nca_logit_NULL;
ulong_t nca_logit_fail;

ulong_t nca_logit_flush_NULL1;
ulong_t nca_logit_flush_NULL2;

ulong_t nca_logger_NULL1;
ulong_t nca_logger_NULL2;

ulong_t nca_log_buf_alloc_NULL;
ulong_t nca_log_buf_alloc_fail;
ulong_t nca_log_buf_alloc_part;

ulong_t nca_log_buf_dup;

extern ulong_t nca_upcalls;
extern ulong_t nca_ncafs_upcalls;

extern ulong_t nca_conn_count;
extern ulong_t nca_conn_kmem;
extern ulong_t nca_conn_kmem_fail;
extern ulong_t nca_conn_allocb_fail;
extern ulong_t nca_conn_tw;
extern ulong_t nca_conn_tw1;
extern ulong_t nca_conn_tw2;
extern ulong_t nca_conn_reinit_cnt;
extern ulong_t nca_conn_NULL1;
extern ulong_t nca_conn_Q0;
extern ulong_t nca_conn_FLAGS;

extern ulong_t tcpwronginq;
extern ulong_t ipsendup;
extern ulong_t ipwrongcpu;
extern ulong_t iponcpu;

extern ulong_t nca_tcp_xmit_null;
extern ulong_t nca_tcp_xmit_null1;

extern ulong_t tw_on;
extern ulong_t tw_fire;
extern ulong_t tw_fire1;
extern ulong_t tw_fire2;
extern ulong_t tw_fire3;
extern ulong_t tw_add;
extern ulong_t tw_add1;
extern ulong_t tw_delete;
extern ulong_t tw_reclaim;
extern ulong_t tw_reap;
extern ulong_t tw_reap1;
extern ulong_t tw_reap2;
extern ulong_t tw_reap3;
extern ulong_t tw_reap4;
extern ulong_t tw_reap5;
extern ulong_t tw_timer;
extern ulong_t tw_timer1;
extern ulong_t tw_timer2;
extern ulong_t tw_timer3;
extern ulong_t tw_timer4;
extern ulong_t tw_timer5;

extern ulong_t ti_on;
extern ulong_t ti_fire;
extern ulong_t ti_fire1;
extern ulong_t ti_fire2;
extern ulong_t ti_fire3;
extern ulong_t ti_fire4;
extern ulong_t ti_add;
extern ulong_t ti_add1;
extern ulong_t ti_add2;
extern ulong_t ti_add3;
extern ulong_t ti_add4;
extern ulong_t ti_add5;
extern ulong_t ti_add_reuse;
extern ulong_t ti_delete;
extern ulong_t ti_delete1;
extern ulong_t ti_delete2;
extern ulong_t ti_reap;
extern ulong_t ti_reap1;
extern ulong_t ti_reap2;
extern ulong_t ti_reap3;
extern ulong_t ti_reap4;
extern ulong_t ti_reap5;
extern ulong_t ti_timer;
extern ulong_t ti_timer1;
extern ulong_t ti_timer2;
extern ulong_t ti_timer3;
extern ulong_t ti_timer4;
extern ulong_t ti_timer5;
extern ulong_t ti_timer6;

extern uint32_t nca_conn_q;
extern uint32_t nca_conn_q0;
extern uint32_t nca_conn_req_max_q;
extern uint32_t nca_conn_req_max_q0;

extern char nca_resp_500[];
extern ssize_t nca_resp_500_sz;

extern uint32_t ncaurihash_sz;
extern uint32_t ncafilehash_sz;
extern uint32_t ncactaghash_sz;
extern uint32_t ncavnodehash_sz;
extern nodef_t *ncaurihash;
extern nodef_t *ncafilehash;
extern nodef_t *ncavnodehash;
extern nodef_t *ncactaghash;
extern char nca_httpd_door_path[];
extern char nca_httpd_downdoor_path[];
extern door_handle_t nca_downcall_door_hand;
extern uint32_t n_http_buf_size;
extern door_handle_t nca_httpd_door_hand;
extern sqfan_t nca_miss_fanout1;
extern sqfan_t nca_miss_fanout2;
extern nca_door_t nca_httpd_door;
extern int nca_downdoor_created;
extern int n_http_buf_table;
extern http_buf_table_t *g_http_buf_table;
extern struct kmem_cache *node_cache;
#ifdef DEBUG
extern node_t *nca_http_response(nca_conn_t *, const char *, int, char *, int,
		    uint_t, const char *);
extern node_t *nca_http_response_node(nca_conn_t *, const char *, int, node_t *,
		    const char *);
#else
extern node_t *nca_http_response(nca_conn_t *, const char *, int, char *, int,
		    uint_t);
extern node_t *nca_http_response_node(nca_conn_t *, const char *, int,
    node_t *);
#endif
extern void nca_node_del(node_t *);
extern void nca_node_uncache(node_t *);
extern node_t *nca_node_add(char *, int, nodef_t *, int);
extern node_t *node_create(int, boolean_t, char *, int);
extern void nca_reclaim_phys(node_t *, boolean_t, boolean_t);
extern boolean_t nca_http_pmap(node_t *);
extern boolean_t nca_http_vmap(node_t *, int);
extern time_t nca_http_date(char *);
extern node_t *nca_httpd_data(node_t *, nca_conn_t *, nca_io2_t *, int);
extern void nca_missed(node_t *, mblk_t *, nca_squeue_t *);
extern void nca_miss_conn_mv(node_t *, nca_conn_t *);
extern void nca_miss_conn_fr(node_t *, nca_conn_t *);
extern void nca_http_logit(nca_conn_t *);
extern void nca_http_error(nca_conn_t *);
extern void nca_node_xmit(node_t *, nca_conn_t *);

/*
 * It contains data for forwarding data to application programs.
 * For door case, doorhandle is the upcall door handle and listenerq
 * is NULL; for ncafs, listenerq is the upcall listener queue and
 * doorhandle is NULL. listenning is always B_TRUE for door and it is
 * B_TRUE for ncafs only after the listen system call has been issued.
 */
typedef struct nca_listener_s {
	boolean_t	listenning;	/* is ready for accepting connection */
	door_handle_t	doorhandle;	/* door handle or NULL for ncafs */
	queue_t		*listenerq;	/* upcall queue or NULL for door */
} nca_listener_t;

/*
 * Returned values of nca_isnca_data.
 * NOT_NCA_DATA:	not NCA data.
 * NCA_DATA_ANY_ADDR:	NCA data, matches INADDR_ANY.
 * NCA_DATA_ADDR:	NCA data, match an IP address.
 */
#define	NOT_NCA_DATA		0
#define	NCA_DATA_ANY_ADDR	1
#define	NCA_DATA_ADDR		2

extern uint32_t ipportrehashcount1;
extern uint32_t ipportrehashcount2;
extern uint32_t ipportbucketcnt;
extern uint32_t ipporttablesize;
extern uint32_t ncafscount;
extern uint32_t doorcount;
extern int	ip_virtual_hosting;

extern nca_listener_t *nca_listener_find(ipaddr_t, uint16_t);
extern nca_listener_t *nca_listener_find2(ipaddr_t, uint16_t);
extern int		nca_isnca_data(ipaddr_t, uint16_t);
extern int		nca_listener_add(ipaddr_t, uint16_t, void *, boolean_t);
extern int		nca_listener_del(ipaddr_t, uint16_t);
extern void		nca_listener_report(mblk_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_NCA_H */
