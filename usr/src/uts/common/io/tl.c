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
/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2012 by Delphix. All rights reserved.
 */

/*
 * Multithreaded STREAMS Local Transport Provider.
 *
 * OVERVIEW
 * ========
 *
 * This driver provides TLI as well as socket semantics.  It provides
 * connectionless, connection oriented, and connection oriented with orderly
 * release transports for TLI and sockets. Each transport type has separate name
 * spaces (i.e. it is not possible to connect from a socket to a TLI endpoint) -
 * this removes any name space conflicts when binding to socket style transport
 * addresses.
 *
 * NOTE: There is one exception: Socket ticots and ticotsord transports share
 * the same namespace. In fact, sockets always use ticotsord type transport.
 *
 * The driver mode is specified during open() by the minor number used for
 * open.
 *
 *  The sockets in addition have the following semantic differences:
 *  No support for passing up credentials (TL_SET[U]CRED).
 *
 *	Options are passed through transparently on T_CONN_REQ to T_CONN_IND,
 *	from T_UNITDATA_REQ to T_UNIDATA_IND, and from T_OPTDATA_REQ to
 *	T_OPTDATA_IND.
 *
 *	The T_CONN_CON is generated when processing the T_CONN_REQ i.e. before
 *	a T_CONN_RES is received from the acceptor. This means that a socket
 *	connect will complete before the peer has called accept.
 *
 *
 * MULTITHREADING
 * ==============
 *
 * The driver does not use STREAMS protection mechanisms. Instead it uses a
 * generic "serializer" abstraction. Most of the operations are executed behind
 * the serializer and are, essentially single-threaded. All functions executed
 * behind the same serializer are strictly serialized. So if one thread calls
 * serializer_enter(serializer, foo, mp1, arg1); and another thread calls
 * serializer_enter(serializer, bar, mp2, arg1); then (depending on which one
 * was called) the actual sequence will be foo(mp1, arg1); bar(mp1, arg2) or
 * bar(mp1, arg2); foo(mp1, arg1); But foo() and bar() will never run at the
 * same time.
 *
 * Connectionless transport use a single serializer per transport type (one for
 * TLI and one for sockets. Connection-oriented transports use finer-grained
 * serializers.
 *
 * All COTS-type endpoints start their life with private serializers. During
 * connection request processing the endpoint serializer is switched to the
 * listener's serializer and the rest of T_CONN_REQ processing is done on the
 * listener serializer. During T_CONN_RES processing the eager serializer is
 * switched from listener to acceptor serializer and after that point all
 * processing for eager and acceptor happens on this serializer. To avoid races
 * with endpoint closes while its serializer may be changing closes are blocked
 * while serializers are manipulated.
 *
 * References accounting
 * ---------------------
 *
 * Endpoints are reference counted and freed when the last reference is
 * dropped. Functions within the serializer may access an endpoint state even
 * after an endpoint closed. The te_closing being set on the endpoint indicates
 * that the endpoint entered its close routine.
 *
 * One reference is held for each opened endpoint instance. The reference
 * counter is incremented when the endpoint is linked to another endpoint and
 * decremented when the link disappears. It is also incremented when the
 * endpoint is found by the hash table lookup. This increment is atomic with the
 * lookup itself and happens while the hash table read lock is held.
 *
 * Close synchronization
 * ---------------------
 *
 * During close the endpoint as marked as closing using te_closing flag. It is
 * usually enough to check for te_closing flag since all other state changes
 * happen after this flag is set and the close entered serializer. Immediately
 * after setting te_closing flag tl_close() enters serializer and waits until
 * the callback finishes. This allows all functions called within serializer to
 * simply check te_closing without any locks.
 *
 * Serializer management.
 * ---------------------
 *
 * For COTS transports serializers are created when the endpoint is constructed
 * and destroyed when the endpoint is destructed. CLTS transports use global
 * serializers - one for sockets and one for TLI.
 *
 * COTS serializers have separate reference counts to deal with several
 * endpoints sharing the same serializer. There is a subtle problem related to
 * the serializer destruction. The serializer should never be destroyed by any
 * function executed inside serializer. This means that close has to wait till
 * all serializer activity for this endpoint is finished before it can drop the
 * last reference on the endpoint (which may as well free the serializer).  This
 * is only relevant for COTS transports which manage serializers
 * dynamically. For CLTS transports close may complete without waiting for all
 * serializer activity to finish since serializer is only destroyed at driver
 * detach time.
 *
 * COTS endpoints keep track of the number of outstanding requests on the
 * serializer for the endpoint. The code handling accept() avoids changing
 * client serializer if it has any pending messages on the serializer and
 * instead moves acceptor to listener's serializer.
 *
 *
 * Use of hash tables
 * ------------------
 *
 * The driver uses modhash hash table implementation. Each transport uses two
 * hash tables - one for finding endpoints by acceptor ID and another one for
 * finding endpoints by address. For sockets TICOTS and TICOTSORD share the same
 * pair of hash tables since sockets only use TICOTSORD.
 *
 * All hash tables lookups increment a reference count for returned endpoints,
 * so we may safely check the endpoint state even when the endpoint is removed
 * from the hash by another thread immediately after it is found.
 *
 *
 * CLOSE processing
 * ================
 *
 * The driver enters serializer twice on close(). The close sequence is the
 * following:
 *
 * 1) Wait until closing is safe (te_closewait becomes zero)
 *	This step is needed to prevent close during serializer switches. In most
 *	cases (close happening after connection establishment) te_closewait is
 *	zero.
 * 1) Set te_closing.
 * 2) Call tl_close_ser() within serializer and wait for it to complete.
 *
 *      te_close_ser simply marks endpoint and wakes up waiting tl_close().
 *	It also needs to clear write-side q_next pointers - this should be done
 *	before qprocsoff().
 *
 *    This synchronous serializer entry during close is needed to ensure that
 *    the queue is valid everywhere inside the serializer.
 *
 *    Note that in many cases close will execute tl_close_ser() synchronously,
 *    so it will not wait at all.
 *
 * 3) Calls qprocsoff().
 * 4) Calls tl_close_finish_ser() within the serializer and waits for it to
 *	complete (for COTS transports). For CLTS transport there is no wait.
 *
 *	tl_close_finish_ser() Finishes the close process and wakes up waiting
 *	close if there is any.
 *
 *    Note that in most cases close will enter te_close_ser_finish()
 *    synchronously and will not wait at all.
 *
 *
 * Flow Control
 * ============
 *
 * The driver implements both read and write side service routines. No one calls
 * putq() on the read queue. The read side service routine tl_rsrv() is called
 * when the read side stream is back-enabled. It enters serializer synchronously
 * (waits till serializer processing is complete). Within serializer it
 * back-enables all endpoints blocked by the queue for connection-less
 * transports and enables write side service processing for the peer for
 * connection-oriented transports.
 *
 * Read and write side service routines use special mblk_sized space in the
 * endpoint structure to enter perimeter.
 *
 * Write-side flow control
 * -----------------------
 *
 * Write side flow control is a bit tricky. The driver needs to deal with two
 * message queues - the explicit STREAMS message queue maintained by
 * putq()/getq()/putbq() and the implicit queue within the serializer. These two
 * queues should be synchronized to preserve message ordering and should
 * maintain a single order determined by the order in which messages enter
 * tl_wput(). In order to maintain the ordering between these two queues the
 * STREAMS queue is only manipulated within the serializer, so the ordering is
 * provided by the serializer.
 *
 * Functions called from the tl_wsrv() sometimes may call putbq(). To
 * immediately stop any further processing of the STREAMS message queues the
 * code calling putbq() also sets the te_nowsrv flag in the endpoint. The write
 * side service processing stops when the flag is set.
 *
 * The tl_wsrv() function enters serializer synchronously and waits for it to
 * complete. The serializer call-back tl_wsrv_ser() either drains all messages
 * on the STREAMS queue or terminates when it notices the te_nowsrv flag
 * set. Note that the maximum amount of messages processed by tl_wput_ser() is
 * always bounded by the amount of messages on the STREAMS queue at the time
 * tl_wsrv_ser() is entered. Any new messages may only appear on the STREAMS
 * queue from another serialized entry which can't happen in parallel. This
 * guarantees that tl_wput_ser() is complete in bounded time (there is no risk
 * of it draining forever while writer places new messages on the STREAMS
 * queue).
 *
 * Note that a closing endpoint never sets te_nowsrv and never calls putbq().
 *
 *
 * Unix Domain Sockets
 * ===================
 *
 * The driver knows the structure of Unix Domain sockets addresses and treats
 * them differently from generic TLI addresses. For sockets implicit binds are
 * requested by setting SOU_MAGIC_IMPLICIT in the soua_magic part of the address
 * instead of using address length of zero. Explicit binds specify
 * SOU_MAGIC_EXPLICIT as magic.
 *
 * For implicit binds we always use minor number as soua_vp part of the address
 * and avoid any hash table lookups. This saves two hash tables lookups per
 * anonymous bind.
 *
 * For explicit address we hash the vnode pointer instead of hashing the
 * full-scale address+zone+length. Hashing by pointer is more efficient then
 * hashing by the full address.
 *
 * For unix domain sockets the te_ap is always pointing to te_uxaddr part of the
 * tep structure, so it should be never freed.
 *
 * Also for sockets the driver always uses minor number as acceptor id.
 *
 * TPI VIOLATIONS
 * --------------
 *
 * This driver violates TPI in several respects for Unix Domain Sockets:
 *
 * 1) It treats O_T_BIND_REQ as T_BIND_REQ and refuses bind if an explicit bind
 *	is requested and the endpoint is already in use. There is no point in
 *	generating an unused address since this address will be rejected by
 *	sockfs anyway. For implicit binds it always generates a new address
 *	(sets soua_vp to its minor number).
 *
 * 2) It always uses minor number as acceptor ID and never uses queue
 *	pointer. It is ok since sockets get acceptor ID from T_CAPABILITY_REQ
 *	message and they do not use the queue pointer.
 *
 * 3) For Listener sockets the usual sequence is to issue bind() zero backlog
 *	followed by listen(). The listen() should be issued with non-zero
 *	backlog, so sotpi_listen() issues unbind request followed by bind
 *	request to the same address but with a non-zero qlen value. Both
 *	tl_bind() and tl_unbind() require write lock on the hash table to
 *	insert/remove the address. The driver does not remove the address from
 *	the hash for endpoints that are bound to the explicit address and have
 *	backlog of zero. During T_BIND_REQ processing if the address requested
 *	is equal to the address the endpoint already has it updates the backlog
 *	without reinserting the address in the hash table. This optimization
 *	avoids two hash table updates for each listener created. It always
 *	avoids the problem of a "stolen" address when another listener may use
 *	the same address between the unbind and bind and suddenly listen() fails
 *	because address is in use even though the bind() succeeded.
 *
 *
 * CONNECTIONLESS TRANSPORTS
 * =========================
 *
 * Connectionless transports all share the same serializer (one for TLI and one
 * for Sockets). Functions executing behind serializer can check or modify state
 * of any endpoint.
 *
 * When endpoint X talks to another endpoint Y it caches the pointer to Y in the
 * te_lastep field. The next time X talks to some address A it checks whether A
 * is the same as Y's address and if it is there is no need to lookup Y. If the
 * address is different or the state of Y is not appropriate (e.g. closed or not
 * idle) X does a lookup using tl_find_peer() and caches the new address.
 * NOTE: tl_find_peer() never returns closing endpoint and it places a refhold
 * on the endpoint found.
 *
 * During close of endpoint Y it doesn't try to remove itself from other
 * endpoints caches. They will detect that Y is gone and will search the peer
 * endpoint again.
 *
 * Flow Control Handling.
 * ----------------------
 *
 * Each connectionless endpoint keeps a list of endpoints which are
 * flow-controlled by its queue. It also keeps a pointer to the queue which
 * flow-controls itself.  Whenever flow control releases for endpoint X it
 * enables all queues from the list. During close it also back-enables everyone
 * in the list. If X is flow-controlled when it is closing it removes it from
 * the peers list.
 *
 * DATA STRUCTURES
 * ===============
 *
 * Each endpoint is represented by the tl_endpt_t structure which keeps all the
 * endpoint state. For connection-oriented transports it has a keeps a list
 * of pending connections (tl_icon_t). For connectionless transports it keeps a
 * list of endpoints flow controlled by this one.
 *
 * Each transport type is represented by a per-transport data structure
 * tl_transport_state_t. It contains a pointer to an acceptor ID hash and the
 * endpoint address hash tables for each transport. It also contains pointer to
 * transport serializer for connectionless transports.
 *
 * Each endpoint keeps a link to its transport structure, so the code can find
 * all per-transport information quickly.
 */

#include	<sys/types.h>
#include	<sys/inttypes.h>
#include	<sys/stream.h>
#include	<sys/stropts.h>
#define	_SUN_TPI_VERSION 2
#include	<sys/tihdr.h>
#include	<sys/strlog.h>
#include	<sys/debug.h>
#include	<sys/cred.h>
#include	<sys/errno.h>
#include	<sys/kmem.h>
#include	<sys/id_space.h>
#include	<sys/modhash.h>
#include	<sys/mkdev.h>
#include	<sys/tl.h>
#include	<sys/stat.h>
#include	<sys/conf.h>
#include	<sys/modctl.h>
#include	<sys/strsun.h>
#include	<sys/socket.h>
#include	<sys/socketvar.h>
#include	<sys/sysmacros.h>
#include	<sys/xti_xtiopt.h>
#include	<sys/ddi.h>
#include	<sys/sunddi.h>
#include	<sys/zone.h>
#include	<inet/common.h>	/* typedef int (*pfi_t)() for inet/optcom.h */
#include	<inet/optcom.h>
#include	<sys/strsubr.h>
#include	<sys/ucred.h>
#include	<sys/suntpi.h>
#include	<sys/list.h>
#include	<sys/serializer.h>

/*
 * TBD List
 * 14 Eliminate state changes through table
 * 16. AF_UNIX socket options
 * 17. connect() for ticlts
 * 18. support for "netstat" to show AF_UNIX plus TLI local
 *	transport connections
 * 21. sanity check to flushing on sending M_ERROR
 */

/*
 * CONSTANT DECLARATIONS
 * --------------------
 */

/*
 * Local declarations
 */
#define	NEXTSTATE(EV, ST)	ti_statetbl[EV][ST]

#define	BADSEQNUM	(-1)	/* initial seq number used by T_DISCON_IND */
#define	TL_BUFWAIT	(10000)	/* usecs to wait for allocb buffer timeout */
#define	TL_TIDUSZ (64*1024)	/* tidu size when "strmsgz" is unlimited (0) */
/*
 * Hash tables size.
 */
#define	TL_HASH_SIZE 311

/*
 * Definitions for module_info
 */
#define		TL_ID		(104)		/* module ID number */
#define		TL_NAME		"tl"		/* module name */
#define		TL_MINPSZ	(0)		/* min packet size */
#define		TL_MAXPSZ	INFPSZ 		/* max packet size ZZZ */
#define		TL_HIWAT	(16*1024)	/* hi water mark */
#define		TL_LOWAT	(256)		/* lo water mark */
/*
 * Definition of minor numbers/modes for new transport provider modes.
 * We view the socket use as a separate mode to get a separate name space.
 */
#define		TL_TICOTS	0	/* connection oriented transport */
#define		TL_TICOTSORD 	1	/* COTS w/ orderly release */
#define		TL_TICLTS 	2	/* connectionless transport */
#define		TL_UNUSED	3
#define		TL_SOCKET	4	/* Socket */
#define		TL_SOCK_COTS	(TL_SOCKET|TL_TICOTS)
#define		TL_SOCK_COTSORD	(TL_SOCKET|TL_TICOTSORD)
#define		TL_SOCK_CLTS	(TL_SOCKET|TL_TICLTS)

#define		TL_MINOR_MASK	0x7
#define		TL_MINOR_START	(TL_TICLTS + 1)

/*
 * LOCAL MACROS
 */
#define	T_ALIGN(p)	P2ROUNDUP((p), sizeof (t_scalar_t))

/*
 * EXTERNAL VARIABLE DECLARATIONS
 * -----------------------------
 */
/*
 * state table defined in the OS space.c
 */
extern	char	ti_statetbl[TE_NOEVENTS][TS_NOSTATES];

/*
 * STREAMS DRIVER ENTRY POINTS PROTOTYPES
 */
static int tl_open(queue_t *, dev_t *, int, int, cred_t *);
static int tl_close(queue_t *, int, cred_t *);
static void tl_wput(queue_t *, mblk_t *);
static void tl_wsrv(queue_t *);
static void tl_rsrv(queue_t *);

static int tl_attach(dev_info_t *, ddi_attach_cmd_t);
static int tl_detach(dev_info_t *, ddi_detach_cmd_t);
static int tl_info(dev_info_t *, ddi_info_cmd_t, void *, void **);


/*
 * GLOBAL DATA STRUCTURES AND VARIABLES
 * -----------------------------------
 */

/*
 * Table representing database of all options managed by T_SVR4_OPTMGMT_REQ
 * For now, we only manage the SO_RECVUCRED option but we also have
 * harmless dummy options to make things work with some common code we access.
 */
opdes_t	tl_opt_arr[] = {
	/* The SO_TYPE is needed for the hack below */
	{
		SO_TYPE,
		SOL_SOCKET,
		OA_R,
		OA_R,
		OP_NP,
		0,
		sizeof (t_scalar_t),
		0
	},
	{
		SO_RECVUCRED,
		SOL_SOCKET,
		OA_RW,
		OA_RW,
		OP_NP,
		0,
		sizeof (int),
		0
	}
};

/*
 * Table of all supported levels
 * Note: Some levels (e.g. XTI_GENERIC) may be valid but may not have
 * any supported options so we need this info separately.
 *
 * This is needed only for topmost tpi providers.
 */
optlevel_t	tl_valid_levels_arr[] = {
	XTI_GENERIC,
	SOL_SOCKET,
	TL_PROT_LEVEL
};

#define	TL_VALID_LEVELS_CNT	A_CNT(tl_valid_levels_arr)
/*
 * Current upper bound on the amount of space needed to return all options.
 * Additional options with data size of sizeof(long) are handled automatically.
 * Others need hand job.
 */
#define	TL_MAX_OPT_BUF_LEN						\
		((A_CNT(tl_opt_arr) << 2) +				\
		(A_CNT(tl_opt_arr) * sizeof (struct opthdr)) +		\
		+ 64 + sizeof (struct T_optmgmt_ack))

#define	TL_OPT_ARR_CNT	A_CNT(tl_opt_arr)

/*
 *	transport addr structure
 */
typedef struct tl_addr {
	zoneid_t	ta_zoneid;		/* Zone scope of address */
	t_scalar_t	ta_alen;		/* length of abuf */
	void		*ta_abuf;		/* the addr itself */
} tl_addr_t;

/*
 * Refcounted version of serializer.
 */
typedef struct tl_serializer {
	uint_t		ts_refcnt;
	serializer_t	*ts_serializer;
} tl_serializer_t;

/*
 * Each transport type has a separate state.
 * Per-transport state.
 */
typedef struct tl_transport_state {
	char		*tr_name;
	minor_t		tr_minor;
	uint32_t	tr_defaddr;
	mod_hash_t	*tr_ai_hash;
	mod_hash_t	*tr_addr_hash;
	tl_serializer_t	*tr_serializer;
} tl_transport_state_t;

#define	TL_DFADDR 0x1000

static tl_transport_state_t tl_transports[] = {
	{ "ticots", TL_TICOTS, TL_DFADDR, NULL, NULL, NULL },
	{ "ticotsord", TL_TICOTSORD, TL_DFADDR, NULL, NULL, NULL },
	{ "ticlts", TL_TICLTS, TL_DFADDR, NULL, NULL, NULL },
	{ "undefined", TL_UNUSED, TL_DFADDR, NULL, NULL, NULL },
	{ "sticots", TL_SOCK_COTS, TL_DFADDR, NULL, NULL, NULL },
	{ "sticotsord", TL_SOCK_COTSORD, TL_DFADDR, NULL, NULL },
	{ "sticlts", TL_SOCK_CLTS, TL_DFADDR, NULL, NULL, NULL }
};

#define	TL_MAXTRANSPORT A_CNT(tl_transports)

struct tl_endpt;
typedef struct tl_endpt tl_endpt_t;

typedef void (tlproc_t)(mblk_t *, tl_endpt_t *);

/*
 * Data structure used to represent pending connects.
 * Records enough information so that the connecting peer can close
 * before the connection gets accepted.
 */
typedef struct tl_icon {
	list_node_t	ti_node;
	struct tl_endpt *ti_tep;	/* NULL if peer has already closed */
	mblk_t		*ti_mp;		/* b_next list of data + ordrel_ind */
	t_scalar_t	ti_seqno;	/* Sequence number */
} tl_icon_t;

typedef struct so_ux_addr soux_addr_t;
#define	TL_SOUX_ADDRLEN sizeof (soux_addr_t)

/*
 * Maximum number of unaccepted connection indications allowed per listener.
 */
#define	TL_MAXQLEN	4096
int tl_maxqlen = TL_MAXQLEN;

/*
 *	transport endpoint structure
 */
struct tl_endpt {
	queue_t		*te_rq;		/* stream read queue */
	queue_t		*te_wq;		/* stream write queue */
	uint32_t	te_refcnt;
	int32_t 	te_state;	/* TPI state of endpoint */
	minor_t		te_minor;	/* minor number */
#define	te_seqno	te_minor
	uint_t		te_flag;	/* flag field */
	boolean_t	te_nowsrv;
	tl_serializer_t	*te_ser;	/* Serializer to use */
#define	te_serializer	te_ser->ts_serializer

	soux_addr_t	te_uxaddr;	/* Socket address */
#define	te_magic	te_uxaddr.soua_magic
#define	te_vp		te_uxaddr.soua_vp
	tl_addr_t	te_ap;		/* addr bound to this endpt */
#define	te_zoneid te_ap.ta_zoneid
#define	te_alen	te_ap.ta_alen
#define	te_abuf	te_ap.ta_abuf

	tl_transport_state_t *te_transport;
#define	te_addrhash	te_transport->tr_addr_hash
#define	te_aihash	te_transport->tr_ai_hash
#define	te_defaddr	te_transport->tr_defaddr
	cred_t		*te_credp;	/* endpoint user credentials */
	mod_hash_hndl_t	te_hash_hndl;	/* Handle for address hash */

	/*
	 * State specific for connection-oriented and connectionless transports.
	 */
	union {
		/* Connection-oriented state. */
		struct {
			t_uscalar_t _te_nicon;	/* count of conn requests */
			t_uscalar_t _te_qlen;	/* max conn requests */
			tl_endpt_t  *_te_oconp;	/* conn request pending */
			tl_endpt_t  *_te_conp;	/* connected endpt */
#ifndef _ILP32
			void	    *_te_pad;
#endif
			list_t	_te_iconp;	/* list of conn ind. pending */
		} _te_cots_state;
		/* Connection-less state. */
		struct {
			tl_endpt_t *_te_lastep;	/* last dest. endpoint */
			tl_endpt_t *_te_flowq;	/* flow controlled on whom */
			list_node_t _te_flows;	/* lists of connections */
			list_t  _te_flowlist;	/* Who flowcontrols on me */
		} _te_clts_state;
	} _te_transport_state;
#define	te_nicon	_te_transport_state._te_cots_state._te_nicon
#define	te_qlen		_te_transport_state._te_cots_state._te_qlen
#define	te_oconp	_te_transport_state._te_cots_state._te_oconp
#define	te_conp		_te_transport_state._te_cots_state._te_conp
#define	te_iconp	_te_transport_state._te_cots_state._te_iconp
#define	te_lastep	_te_transport_state._te_clts_state._te_lastep
#define	te_flowq	_te_transport_state._te_clts_state._te_flowq
#define	te_flowlist	_te_transport_state._te_clts_state._te_flowlist
#define	te_flows	_te_transport_state._te_clts_state._te_flows

	bufcall_id_t	te_bufcid;	/* outstanding bufcall id */
	timeout_id_t	te_timoutid;	/* outstanding timeout id */
	pid_t		te_cpid;	/* cached pid of endpoint */
	t_uscalar_t	te_acceptor_id;	/* acceptor id for T_CONN_RES */
	/*
	 * Pieces of the endpoint state needed for closing.
	 */
	kmutex_t	te_closelock;
	kcondvar_t	te_closecv;
	uint8_t		te_closing;	/* The endpoint started closing */
	uint8_t		te_closewait;	/* Wait in close until zero */
	mblk_t		te_closemp;	/* for entering serializer on close */
	mblk_t		te_rsrvmp;	/* for entering serializer on rsrv */
	mblk_t		te_wsrvmp;	/* for entering serializer on wsrv */
	kmutex_t	te_srv_lock;
	kcondvar_t	te_srv_cv;
	uint8_t		te_rsrv_active;	/* Running in tl_rsrv()	*/
	uint8_t		te_wsrv_active;	/* Running in tl_wsrv()	*/
	/*
	 * Pieces of the endpoint state needed for serializer transitions.
	 */
	kmutex_t	te_ser_lock;	/* Protects the count below */
	uint_t		te_ser_count;	/* Number of messages on serializer */
};

/*
 * Flag values. Lower 4 bits specify that transport used.
 * TL_LISTENER, TL_ACCEPTOR, TL_ACCEPTED and TL_EAGER are for debugging only,
 * they allow to identify the endpoint more easily.
 */
#define	TL_LISTENER	0x00010	/* the listener endpoint */
#define	TL_ACCEPTOR	0x00020	/* the accepting endpoint */
#define	TL_EAGER	0x00040	/* connecting endpoint */
#define	TL_ACCEPTED	0x00080	/* accepted connection */
#define	TL_SETCRED	0x00100	/* flag to indicate sending of credentials */
#define	TL_SETUCRED	0x00200	/* flag to indicate sending of ucred */
#define	TL_SOCKUCRED	0x00400	/* flag to indicate sending of SCM_UCRED */
#define	TL_ADDRHASHED	0x01000	/* Endpoint address is stored in te_addrhash */
#define	TL_CLOSE_SER	0x10000	/* Endpoint close has entered the serializer */
/*
 * Boolean checks for the endpoint type.
 */
#define		IS_CLTS(x)	(((x)->te_flag & TL_TICLTS) != 0)
#define		IS_COTS(x)	(((x)->te_flag & TL_TICLTS) == 0)
#define		IS_COTSORD(x)	(((x)->te_flag & TL_TICOTSORD) != 0)
#define		IS_SOCKET(x)	(((x)->te_flag & TL_SOCKET) != 0)

/*
 * Certain operations are always used together. These macros reduce the chance
 * of missing a part of a combination.
 */
#define	TL_UNCONNECT(x) { tl_refrele(x); x = NULL; }
#define	TL_REMOVE_PEER(x) { if ((x) != NULL) TL_UNCONNECT(x) }

#define	TL_PUTBQ(x, mp) {		\
	ASSERT(!((x)->te_flag & TL_CLOSE_SER));	\
	(x)->te_nowsrv = B_TRUE;	\
	(void) putbq((x)->te_wq, mp);	\
}

#define	TL_QENABLE(x) { (x)->te_nowsrv = B_FALSE; qenable((x)->te_wq); }
#define	TL_PUTQ(x, mp) { (x)->te_nowsrv = B_FALSE; (void)putq((x)->te_wq, mp); }

/*
 * STREAMS driver glue data structures.
 */
static	struct	module_info	tl_minfo = {
	TL_ID,			/* mi_idnum */
	TL_NAME,		/* mi_idname */
	TL_MINPSZ,		/* mi_minpsz */
	TL_MAXPSZ,		/* mi_maxpsz */
	TL_HIWAT,		/* mi_hiwat */
	TL_LOWAT		/* mi_lowat */
};

static	struct	qinit	tl_rinit = {
	NULL,			/* qi_putp */
	(int (*)())tl_rsrv,	/* qi_srvp */
	tl_open,		/* qi_qopen */
	tl_close,		/* qi_qclose */
	NULL,			/* qi_qadmin */
	&tl_minfo,		/* qi_minfo */
	NULL			/* qi_mstat */
};

static	struct	qinit	tl_winit = {
	(int (*)())tl_wput,	/* qi_putp */
	(int (*)())tl_wsrv,	/* qi_srvp */
	NULL,			/* qi_qopen */
	NULL,			/* qi_qclose */
	NULL,			/* qi_qadmin */
	&tl_minfo,		/* qi_minfo */
	NULL			/* qi_mstat */
};

static	struct streamtab	tlinfo = {
	&tl_rinit,		/* st_rdinit */
	&tl_winit,		/* st_wrinit */
	NULL,			/* st_muxrinit */
	NULL			/* st_muxwrinit */
};

DDI_DEFINE_STREAM_OPS(tl_devops, nulldev, nulldev, tl_attach, tl_detach,
    nulldev, tl_info, D_MP, &tlinfo, ddi_quiesce_not_supported);

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module -- pseudo driver here */
	"TPI Local Transport (tl)",
	&tl_devops,		/* driver ops */
};

/*
 * Module linkage information for the kernel.
 */
static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

/*
 * Templates for response to info request
 * Check sanity of unlimited connect data etc.
 */

#define		TL_CLTS_PROVIDER_FLAG	(XPG4_1|SENDZERO)
#define		TL_COTS_PROVIDER_FLAG	(XPG4_1|SENDZERO)

static struct T_info_ack tl_cots_info_ack =
	{
		T_INFO_ACK,	/* PRIM_type -always T_INFO_ACK */
		T_INFINITE,	/* TSDU size */
		T_INFINITE,	/* ETSDU size */
		T_INFINITE,	/* CDATA_size */
		T_INFINITE,	/* DDATA_size */
		T_INFINITE,	/* ADDR_size  */
		T_INFINITE,	/* OPT_size */
		0,		/* TIDU_size - fill at run time */
		T_COTS,		/* SERV_type */
		-1,		/* CURRENT_state */
		TL_COTS_PROVIDER_FLAG	/* PROVIDER_flag */
	};

static struct T_info_ack tl_clts_info_ack =
	{
		T_INFO_ACK,	/* PRIM_type - always T_INFO_ACK */
		0,		/* TSDU_size - fill at run time */
		-2,		/* ETSDU_size -2 => not supported */
		-2,		/* CDATA_size -2 => not supported */
		-2,		/* DDATA_size  -2 => not supported */
		-1,		/* ADDR_size -1 => infinite */
		-1,		/* OPT_size */
		0,		/* TIDU_size - fill at run time */
		T_CLTS,		/* SERV_type */
		-1,		/* CURRENT_state */
		TL_CLTS_PROVIDER_FLAG /* PROVIDER_flag */
	};

/*
 * private copy of devinfo pointer used in tl_info
 */
static dev_info_t *tl_dip;

/*
 * Endpoints cache.
 */
static kmem_cache_t *tl_cache;
/*
 * Minor number space.
 */
static id_space_t *tl_minors;

/*
 * Default Data Unit size.
 */
static t_scalar_t tl_tidusz;

/*
 * Size of hash tables.
 */
static size_t tl_hash_size = TL_HASH_SIZE;

/*
 * Debug and test variable ONLY. Turn off T_CONN_IND queueing
 * for sockets.
 */
static int tl_disable_early_connect = 0;
static int tl_client_closing_when_accepting;

static int tl_serializer_noswitch;

/*
 * LOCAL FUNCTION PROTOTYPES
 * -------------------------
 */
static boolean_t tl_eqaddr(tl_addr_t *, tl_addr_t *);
static void tl_do_proto(mblk_t *, tl_endpt_t *);
static void tl_do_ioctl(mblk_t *, tl_endpt_t *);
static void tl_do_ioctl_ser(mblk_t *, tl_endpt_t *);
static void tl_error_ack(queue_t *, mblk_t *, t_scalar_t, t_scalar_t,
	t_scalar_t);
static void tl_bind(mblk_t *, tl_endpt_t *);
static void tl_bind_ser(mblk_t *, tl_endpt_t *);
static void tl_ok_ack(queue_t *, mblk_t  *mp, t_scalar_t);
static void tl_unbind(mblk_t *, tl_endpt_t *);
static void tl_optmgmt(queue_t *, mblk_t *);
static void tl_conn_req(queue_t *, mblk_t *);
static void tl_conn_req_ser(mblk_t *, tl_endpt_t *);
static void tl_conn_res(mblk_t *, tl_endpt_t *);
static void tl_discon_req(mblk_t *, tl_endpt_t *);
static void tl_capability_req(mblk_t *, tl_endpt_t *);
static void tl_info_req_ser(mblk_t *, tl_endpt_t *);
static void tl_addr_req_ser(mblk_t *, tl_endpt_t *);
static void tl_info_req(mblk_t *, tl_endpt_t *);
static void tl_addr_req(mblk_t *, tl_endpt_t *);
static void tl_connected_cots_addr_req(mblk_t *, tl_endpt_t *);
static void tl_data(mblk_t  *, tl_endpt_t *);
static void tl_exdata(mblk_t *, tl_endpt_t *);
static void tl_ordrel(mblk_t *, tl_endpt_t *);
static void tl_unitdata(mblk_t *, tl_endpt_t *);
static void tl_unitdata_ser(mblk_t *, tl_endpt_t *);
static void tl_uderr(queue_t *, mblk_t *, t_scalar_t);
static tl_endpt_t *tl_find_peer(tl_endpt_t *, tl_addr_t *);
static tl_endpt_t *tl_sock_find_peer(tl_endpt_t *, struct so_ux_addr *);
static boolean_t tl_get_any_addr(tl_endpt_t *, tl_addr_t *);
static void tl_cl_backenable(tl_endpt_t *);
static void tl_co_unconnect(tl_endpt_t *);
static mblk_t *tl_resizemp(mblk_t *, ssize_t);
static void tl_discon_ind(tl_endpt_t *, uint32_t);
static mblk_t *tl_discon_ind_alloc(uint32_t, t_scalar_t);
static mblk_t *tl_ordrel_ind_alloc(void);
static tl_icon_t *tl_icon_find(tl_endpt_t *, t_scalar_t);
static void tl_icon_queuemsg(tl_endpt_t *, t_scalar_t, mblk_t *);
static boolean_t tl_icon_hasprim(tl_endpt_t *, t_scalar_t, t_scalar_t);
static void tl_icon_sendmsgs(tl_endpt_t *, mblk_t **);
static void tl_icon_freemsgs(mblk_t **);
static void tl_merror(queue_t *, mblk_t *, int);
static void tl_fill_option(uchar_t *, cred_t *, pid_t, int, cred_t *);
static int tl_default_opt(queue_t *, int, int, uchar_t *);
static int tl_get_opt(queue_t *, int, int, uchar_t *);
static int tl_set_opt(queue_t *, uint_t, int, int, uint_t, uchar_t *, uint_t *,
    uchar_t *, void *, cred_t *);
static void tl_memrecover(queue_t *, mblk_t *, size_t);
static void tl_freetip(tl_endpt_t *, tl_icon_t *);
static void tl_free(tl_endpt_t *);
static int  tl_constructor(void *, void *, int);
static void tl_destructor(void *, void *);
static void tl_find_callback(mod_hash_key_t, mod_hash_val_t);
static tl_serializer_t *tl_serializer_alloc(int);
static void tl_serializer_refhold(tl_serializer_t *);
static void tl_serializer_refrele(tl_serializer_t *);
static void tl_serializer_enter(tl_endpt_t *, tlproc_t, mblk_t *);
static void tl_serializer_exit(tl_endpt_t *);
static boolean_t tl_noclose(tl_endpt_t *);
static void tl_closeok(tl_endpt_t *);
static void tl_refhold(tl_endpt_t *);
static void tl_refrele(tl_endpt_t *);
static int tl_hash_cmp_addr(mod_hash_key_t, mod_hash_key_t);
static uint_t tl_hash_by_addr(void *, mod_hash_key_t);
static void tl_close_ser(mblk_t *, tl_endpt_t *);
static void tl_close_finish_ser(mblk_t *, tl_endpt_t *);
static void tl_wput_data_ser(mblk_t *, tl_endpt_t *);
static void tl_proto_ser(mblk_t *, tl_endpt_t *);
static void tl_putq_ser(mblk_t *, tl_endpt_t *);
static void tl_wput_common_ser(mblk_t *, tl_endpt_t *);
static void tl_wput_ser(mblk_t *, tl_endpt_t *);
static void tl_wsrv_ser(mblk_t *, tl_endpt_t *);
static void tl_rsrv_ser(mblk_t *, tl_endpt_t *);
static void tl_addr_unbind(tl_endpt_t *);

/*
 * Intialize option database object for TL
 */

optdb_obj_t tl_opt_obj = {
	tl_default_opt,		/* TL default value function pointer */
	tl_get_opt,		/* TL get function pointer */
	tl_set_opt,		/* TL set function pointer */
	TL_OPT_ARR_CNT,		/* TL option database count of entries */
	tl_opt_arr,		/* TL option database */
	TL_VALID_LEVELS_CNT,	/* TL valid level count of entries */
	tl_valid_levels_arr	/* TL valid level array */
};

/*
 * LOCAL FUNCTIONS AND DRIVER ENTRY POINTS
 * ---------------------------------------
 */

/*
 * Loadable module routines
 */
int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Driver Entry Points and Other routines
 */
static int
tl_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int i;
	char name[32];

	/*
	 * Resume from a checkpoint state.
	 */
	if (cmd == DDI_RESUME)
		return (DDI_SUCCESS);

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	/*
	 * Deduce TIDU size to use.  Note: "strmsgsz" being 0 has semantics that
	 * streams message sizes can be unlimited. We use a defined constant
	 * instead.
	 */
	tl_tidusz = strmsgsz != 0 ? (t_scalar_t)strmsgsz : TL_TIDUSZ;

	/*
	 * Create subdevices for each transport.
	 */
	for (i = 0; i < TL_UNUSED; i++) {
		if (ddi_create_minor_node(devi,
		    tl_transports[i].tr_name,
		    S_IFCHR, tl_transports[i].tr_minor,
		    DDI_PSEUDO, NULL) == DDI_FAILURE) {
			ddi_remove_minor_node(devi, NULL);
			return (DDI_FAILURE);
		}
	}

	tl_cache = kmem_cache_create("tl_cache", sizeof (tl_endpt_t),
	    0, tl_constructor, tl_destructor, NULL, NULL, NULL, 0);

	if (tl_cache == NULL) {
		ddi_remove_minor_node(devi, NULL);
		return (DDI_FAILURE);
	}

	tl_minors = id_space_create("tl_minor_space",
	    TL_MINOR_START, MAXMIN32 - TL_MINOR_START + 1);

	/*
	 * Create ID space for minor numbers
	 */
	for (i = 0; i < TL_MAXTRANSPORT; i++) {
		tl_transport_state_t *t = &tl_transports[i];

		if (i == TL_UNUSED)
			continue;

		/* Socket COTSORD shares namespace with COTS */
		if (i == TL_SOCK_COTSORD) {
			t->tr_ai_hash =
			    tl_transports[TL_SOCK_COTS].tr_ai_hash;
			ASSERT(t->tr_ai_hash != NULL);
			t->tr_addr_hash =
			    tl_transports[TL_SOCK_COTS].tr_addr_hash;
			ASSERT(t->tr_addr_hash != NULL);
			continue;
		}

		/*
		 * Create hash tables.
		 */
		(void) snprintf(name, sizeof (name), "%s_ai_hash",
		    t->tr_name);
#ifdef _ILP32
		if (i & TL_SOCKET)
			t->tr_ai_hash =
			    mod_hash_create_idhash(name, tl_hash_size - 1,
			    mod_hash_null_valdtor);
		else
			t->tr_ai_hash =
			    mod_hash_create_ptrhash(name, tl_hash_size,
			    mod_hash_null_valdtor, sizeof (queue_t));
#else
		t->tr_ai_hash =
		    mod_hash_create_idhash(name, tl_hash_size - 1,
		    mod_hash_null_valdtor);
#endif /* _ILP32 */

		if (i & TL_SOCKET) {
			(void) snprintf(name, sizeof (name), "%s_sockaddr_hash",
			    t->tr_name);
			t->tr_addr_hash = mod_hash_create_ptrhash(name,
			    tl_hash_size, mod_hash_null_valdtor,
			    sizeof (uintptr_t));
		} else {
			(void) snprintf(name, sizeof (name), "%s_addr_hash",
			    t->tr_name);
			t->tr_addr_hash = mod_hash_create_extended(name,
			    tl_hash_size, mod_hash_null_keydtor,
			    mod_hash_null_valdtor,
			    tl_hash_by_addr, NULL, tl_hash_cmp_addr, KM_SLEEP);
		}

		/* Create serializer for connectionless transports. */
		if (i & TL_TICLTS)
			t->tr_serializer = tl_serializer_alloc(KM_SLEEP);
	}

	tl_dip = devi;

	return (DDI_SUCCESS);
}

static int
tl_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int i;

	if (cmd == DDI_SUSPEND)
		return (DDI_SUCCESS);

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	/*
	 * Destroy arenas and hash tables.
	 */
	for (i = 0; i < TL_MAXTRANSPORT; i++) {
		tl_transport_state_t *t = &tl_transports[i];

		if ((i == TL_UNUSED) || (i == TL_SOCK_COTSORD))
			continue;

		EQUIV(i & TL_TICLTS, t->tr_serializer != NULL);
		if (t->tr_serializer != NULL) {
			tl_serializer_refrele(t->tr_serializer);
			t->tr_serializer = NULL;
		}

#ifdef _ILP32
		if (i & TL_SOCKET)
			mod_hash_destroy_idhash(t->tr_ai_hash);
		else
			mod_hash_destroy_ptrhash(t->tr_ai_hash);
#else
		mod_hash_destroy_idhash(t->tr_ai_hash);
#endif /* _ILP32 */
		t->tr_ai_hash = NULL;
		if (i & TL_SOCKET)
			mod_hash_destroy_ptrhash(t->tr_addr_hash);
		else
			mod_hash_destroy_hash(t->tr_addr_hash);
		t->tr_addr_hash = NULL;
	}

	kmem_cache_destroy(tl_cache);
	tl_cache = NULL;
	id_space_destroy(tl_minors);
	tl_minors = NULL;
	ddi_remove_minor_node(devi, NULL);
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
tl_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{

	int retcode = DDI_FAILURE;

	switch (infocmd) {

	case DDI_INFO_DEVT2DEVINFO:
		if (tl_dip != NULL) {
			*result = (void *)tl_dip;
			retcode = DDI_SUCCESS;
		}
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		retcode = DDI_SUCCESS;
		break;

	default:
		break;
	}
	return (retcode);
}

/*
 * Endpoint reference management.
 */
static void
tl_refhold(tl_endpt_t *tep)
{
	atomic_inc_32(&tep->te_refcnt);
}

static void
tl_refrele(tl_endpt_t *tep)
{
	ASSERT(tep->te_refcnt != 0);

	if (atomic_dec_32_nv(&tep->te_refcnt) == 0)
		tl_free(tep);
}

/*ARGSUSED*/
static int
tl_constructor(void *buf, void *cdrarg, int kmflags)
{
	tl_endpt_t *tep = buf;

	bzero(tep, sizeof (tl_endpt_t));
	mutex_init(&tep->te_closelock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&tep->te_closecv, NULL, CV_DEFAULT, NULL);
	mutex_init(&tep->te_srv_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&tep->te_srv_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&tep->te_ser_lock, NULL, MUTEX_DEFAULT, NULL);

	return (0);
}

/*ARGSUSED*/
static void
tl_destructor(void *buf, void *cdrarg)
{
	tl_endpt_t *tep = buf;

	mutex_destroy(&tep->te_closelock);
	cv_destroy(&tep->te_closecv);
	mutex_destroy(&tep->te_srv_lock);
	cv_destroy(&tep->te_srv_cv);
	mutex_destroy(&tep->te_ser_lock);
}

static void
tl_free(tl_endpt_t *tep)
{
	ASSERT(tep->te_refcnt == 0);
	ASSERT(tep->te_transport != NULL);
	ASSERT(tep->te_rq == NULL);
	ASSERT(tep->te_wq == NULL);
	ASSERT(tep->te_ser != NULL);
	ASSERT(tep->te_ser_count == 0);
	ASSERT(! (tep->te_flag & TL_ADDRHASHED));

	if (IS_SOCKET(tep)) {
		ASSERT(tep->te_alen == TL_SOUX_ADDRLEN);
		ASSERT(tep->te_abuf == &tep->te_uxaddr);
		ASSERT(tep->te_vp == (void *)(uintptr_t)tep->te_minor);
		ASSERT(tep->te_magic == SOU_MAGIC_IMPLICIT);
	} else if (tep->te_abuf != NULL) {
		kmem_free(tep->te_abuf, tep->te_alen);
		tep->te_alen = -1; /* uninitialized */
		tep->te_abuf = NULL;
	} else {
		ASSERT(tep->te_alen == -1);
	}

	id_free(tl_minors, tep->te_minor);
	ASSERT(tep->te_credp == NULL);

	if (tep->te_hash_hndl != NULL)
		mod_hash_cancel(tep->te_addrhash, &tep->te_hash_hndl);

	if (IS_COTS(tep)) {
		TL_REMOVE_PEER(tep->te_conp);
		TL_REMOVE_PEER(tep->te_oconp);
		tl_serializer_refrele(tep->te_ser);
		tep->te_ser = NULL;
		ASSERT(tep->te_nicon == 0);
		ASSERT(list_head(&tep->te_iconp) == NULL);
	} else {
		ASSERT(tep->te_lastep == NULL);
		ASSERT(list_head(&tep->te_flowlist) == NULL);
		ASSERT(tep->te_flowq == NULL);
	}

	ASSERT(tep->te_bufcid == 0);
	ASSERT(tep->te_timoutid == 0);
	bzero(&tep->te_ap, sizeof (tep->te_ap));
	tep->te_acceptor_id = 0;

	ASSERT(tep->te_closewait == 0);
	ASSERT(!tep->te_rsrv_active);
	ASSERT(!tep->te_wsrv_active);
	tep->te_closing = 0;
	tep->te_nowsrv = B_FALSE;
	tep->te_flag = 0;

	kmem_cache_free(tl_cache, tep);
}

/*
 * Allocate/free reference-counted wrappers for serializers.
 */
static tl_serializer_t *
tl_serializer_alloc(int flags)
{
	tl_serializer_t *s = kmem_alloc(sizeof (tl_serializer_t), flags);
	serializer_t *ser;

	if (s == NULL)
		return (NULL);

	ser = serializer_create(flags);

	if (ser == NULL) {
		kmem_free(s, sizeof (tl_serializer_t));
		return (NULL);
	}

	s->ts_refcnt = 1;
	s->ts_serializer = ser;
	return (s);
}

static void
tl_serializer_refhold(tl_serializer_t *s)
{
	atomic_inc_32(&s->ts_refcnt);
}

static void
tl_serializer_refrele(tl_serializer_t *s)
{
	if (atomic_dec_32_nv(&s->ts_refcnt) == 0) {
		serializer_destroy(s->ts_serializer);
		kmem_free(s, sizeof (tl_serializer_t));
	}
}

/*
 * Post a request on the endpoint serializer. For COTS transports keep track of
 * the number of pending requests.
 */
static void
tl_serializer_enter(tl_endpt_t *tep, tlproc_t tlproc, mblk_t *mp)
{
	if (IS_COTS(tep)) {
		mutex_enter(&tep->te_ser_lock);
		tep->te_ser_count++;
		mutex_exit(&tep->te_ser_lock);
	}
	serializer_enter(tep->te_serializer, (srproc_t *)tlproc, mp, tep);
}

/*
 * Complete processing the request on the serializer. Decrement the counter for
 * pending requests for COTS transports.
 */
static void
tl_serializer_exit(tl_endpt_t *tep)
{
	if (IS_COTS(tep)) {
		mutex_enter(&tep->te_ser_lock);
		ASSERT(tep->te_ser_count != 0);
		tep->te_ser_count--;
		mutex_exit(&tep->te_ser_lock);
	}
}

/*
 * Hash management functions.
 */

/*
 * Return TRUE if two addresses are equal, false otherwise.
 */
static boolean_t
tl_eqaddr(tl_addr_t *ap1, tl_addr_t *ap2)
{
	return ((ap1->ta_alen > 0) &&
	    (ap1->ta_alen == ap2->ta_alen) &&
	    (ap1->ta_zoneid == ap2->ta_zoneid) &&
	    (bcmp(ap1->ta_abuf, ap2->ta_abuf, ap1->ta_alen) == 0));
}

/*
 * This function is called whenever an endpoint is found in the hash table.
 */
/* ARGSUSED0 */
static void
tl_find_callback(mod_hash_key_t key, mod_hash_val_t val)
{
	tl_refhold((tl_endpt_t *)val);
}

/*
 * Address hash function.
 */
/* ARGSUSED */
static uint_t
tl_hash_by_addr(void *hash_data, mod_hash_key_t key)
{
	tl_addr_t *ap = (tl_addr_t *)key;
	size_t	len = ap->ta_alen;
	uchar_t *p = ap->ta_abuf;
	uint_t i, g;

	ASSERT((len > 0) && (p != NULL));

	for (i = ap->ta_zoneid; len -- != 0; p++) {
		i = (i << 4) + (*p);
		if ((g = (i & 0xf0000000U)) != 0) {
			i ^= (g >> 24);
			i ^= g;
		}
	}
	return (i);
}

/*
 * This function is used by hash lookups. It compares two generic addresses.
 */
static int
tl_hash_cmp_addr(mod_hash_key_t key1, mod_hash_key_t key2)
{
#ifdef 	DEBUG
	tl_addr_t *ap1 = (tl_addr_t *)key1;
	tl_addr_t *ap2 = (tl_addr_t *)key2;

	ASSERT(key1 != NULL);
	ASSERT(key2 != NULL);

	ASSERT(ap1->ta_abuf != NULL);
	ASSERT(ap2->ta_abuf != NULL);
	ASSERT(ap1->ta_alen > 0);
	ASSERT(ap2->ta_alen > 0);
#endif

	return (! tl_eqaddr((tl_addr_t *)key1, (tl_addr_t *)key2));
}

/*
 * Prevent endpoint from closing if possible.
 * Return B_TRUE on success, B_FALSE on failure.
 */
static boolean_t
tl_noclose(tl_endpt_t *tep)
{
	boolean_t rc = B_FALSE;

	mutex_enter(&tep->te_closelock);
	if (! tep->te_closing) {
		ASSERT(tep->te_closewait == 0);
		tep->te_closewait++;
		rc = B_TRUE;
	}
	mutex_exit(&tep->te_closelock);
	return (rc);
}

/*
 * Allow endpoint to close if needed.
 */
static void
tl_closeok(tl_endpt_t *tep)
{
	ASSERT(tep->te_closewait > 0);
	mutex_enter(&tep->te_closelock);
	ASSERT(tep->te_closewait == 1);
	tep->te_closewait--;
	cv_signal(&tep->te_closecv);
	mutex_exit(&tep->te_closelock);
}

/*
 * STREAMS open entry point.
 */
/* ARGSUSED */
static int
tl_open(queue_t	*rq, dev_t *devp, int oflag, int sflag,	cred_t	*credp)
{
	tl_endpt_t *tep;
	minor_t	    minor = getminor(*devp);

	/*
	 * Driver is called directly. Both CLONEOPEN and MODOPEN
	 * are illegal
	 */
	if ((sflag == CLONEOPEN) || (sflag == MODOPEN))
		return (ENXIO);

	if (rq->q_ptr != NULL)
		return (0);

	/* Minor number should specify the mode used for the driver. */
	if ((minor >= TL_UNUSED))
		return (ENXIO);

	if (oflag & SO_SOCKSTR) {
		minor |= TL_SOCKET;
	}

	tep = kmem_cache_alloc(tl_cache, KM_SLEEP);
	tep->te_refcnt = 1;
	tep->te_cpid = curproc->p_pid;
	rq->q_ptr = WR(rq)->q_ptr = tep;
	tep->te_state = TS_UNBND;
	tep->te_credp = credp;
	crhold(credp);
	tep->te_zoneid = getzoneid();

	tep->te_flag = minor & TL_MINOR_MASK;
	tep->te_transport = &tl_transports[minor];

	/* Allocate a unique minor number for this instance. */
	tep->te_minor = (minor_t)id_alloc(tl_minors);

	/* Reserve hash handle for bind(). */
	(void) mod_hash_reserve(tep->te_addrhash, &tep->te_hash_hndl);

	/* Transport-specific initialization */
	if (IS_COTS(tep)) {
		/* Use private serializer */
		tep->te_ser = tl_serializer_alloc(KM_SLEEP);

		/* Create list for pending connections */
		list_create(&tep->te_iconp, sizeof (tl_icon_t),
		    offsetof(tl_icon_t, ti_node));
		tep->te_qlen = 0;
		tep->te_nicon = 0;
		tep->te_oconp = NULL;
		tep->te_conp = NULL;
	} else {
		/* Use shared serializer */
		tep->te_ser = tep->te_transport->tr_serializer;
		bzero(&tep->te_flows, sizeof (list_node_t));
		/* Create list for flow control */
		list_create(&tep->te_flowlist, sizeof (tl_endpt_t),
		    offsetof(tl_endpt_t, te_flows));
		tep->te_flowq = NULL;
		tep->te_lastep = NULL;

	}

	/* Initialize endpoint address */
	if (IS_SOCKET(tep)) {
		/* Socket-specific address handling. */
		tep->te_alen = TL_SOUX_ADDRLEN;
		tep->te_abuf = &tep->te_uxaddr;
		tep->te_vp = (void *)(uintptr_t)tep->te_minor;
		tep->te_magic = SOU_MAGIC_IMPLICIT;
	} else {
		tep->te_alen = -1;
		tep->te_abuf = NULL;
	}

	/* clone the driver */
	*devp = makedevice(getmajor(*devp), tep->te_minor);

	tep->te_rq = rq;
	tep->te_wq = WR(rq);

#ifdef	_ILP32
	if (IS_SOCKET(tep))
		tep->te_acceptor_id = tep->te_minor;
	else
		tep->te_acceptor_id = (t_uscalar_t)rq;
#else
	tep->te_acceptor_id = tep->te_minor;
#endif	/* _ILP32 */


	qprocson(rq);

	/*
	 * Insert acceptor ID in the hash. The AI hash always sleeps on
	 * insertion so insertion can't fail.
	 */
	(void) mod_hash_insert(tep->te_transport->tr_ai_hash,
	    (mod_hash_key_t)(uintptr_t)tep->te_acceptor_id,
	    (mod_hash_val_t)tep);

	return (0);
}

/* ARGSUSED1 */
static int
tl_close(queue_t *rq, int flag,	cred_t *credp)
{
	tl_endpt_t *tep = (tl_endpt_t *)rq->q_ptr;
	tl_endpt_t *elp = NULL;
	queue_t *wq = tep->te_wq;
	int rc;

	ASSERT(wq == WR(rq));

	/*
	 * Remove the endpoint from acceptor hash.
	 */
	rc = mod_hash_remove(tep->te_transport->tr_ai_hash,
	    (mod_hash_key_t)(uintptr_t)tep->te_acceptor_id,
	    (mod_hash_val_t *)&elp);
	ASSERT(rc == 0 && tep == elp);
	if ((rc != 0) || (tep != elp)) {
		(void) (STRLOG(TL_ID, tep->te_minor, 1,
		    SL_TRACE|SL_ERROR,
		    "tl_close:inconsistency in AI hash"));
	}

	/*
	 * Wait till close is safe, then mark endpoint as closing.
	 */
	mutex_enter(&tep->te_closelock);
	while (tep->te_closewait)
		cv_wait(&tep->te_closecv, &tep->te_closelock);
	tep->te_closing = B_TRUE;
	/*
	 * Will wait for the serializer part of the close to finish, so set
	 * te_closewait now.
	 */
	tep->te_closewait = 1;
	tep->te_nowsrv = B_FALSE;
	mutex_exit(&tep->te_closelock);

	/*
	 * tl_close_ser doesn't drop reference, so no need to tl_refhold.
	 * It is safe because close will wait for tl_close_ser to finish.
	 */
	tl_serializer_enter(tep, tl_close_ser, &tep->te_closemp);

	/*
	 * Wait for the first phase of close to complete before qprocsoff().
	 */
	mutex_enter(&tep->te_closelock);
	while (tep->te_closewait)
		cv_wait(&tep->te_closecv, &tep->te_closelock);
	mutex_exit(&tep->te_closelock);

	qprocsoff(rq);

	if (tep->te_bufcid) {
		qunbufcall(rq, tep->te_bufcid);
		tep->te_bufcid = 0;
	}
	if (tep->te_timoutid) {
		(void) quntimeout(rq, tep->te_timoutid);
		tep->te_timoutid = 0;
	}

	/*
	 * Finish close behind serializer.
	 *
	 * For a CLTS endpoint increase a refcount and continue close processing
	 * with serializer protection. This processing may happen asynchronously
	 * with the completion of tl_close().
	 *
	 * Fot a COTS endpoint wait before destroying tep since the serializer
	 * may go away together with tep and we need to destroy serializer
	 * outside of serializer context.
	 */
	ASSERT(tep->te_closewait == 0);
	if (IS_COTS(tep))
		tep->te_closewait = 1;
	else
		tl_refhold(tep);

	tl_serializer_enter(tep, tl_close_finish_ser, &tep->te_closemp);

	/*
	 * For connection-oriented transports wait for all serializer activity
	 * to settle down.
	 */
	if (IS_COTS(tep)) {
		mutex_enter(&tep->te_closelock);
		while (tep->te_closewait)
			cv_wait(&tep->te_closecv, &tep->te_closelock);
		mutex_exit(&tep->te_closelock);
	}

	crfree(tep->te_credp);
	tep->te_credp = NULL;
	tep->te_wq = NULL;
	tl_refrele(tep);
	/*
	 * tep is likely to be destroyed now, so can't reference it any more.
	 */

	rq->q_ptr = wq->q_ptr = NULL;
	return (0);
}

/*
 * First phase of close processing done behind the serializer.
 *
 * Do not drop the reference in the end - tl_close() wants this reference to
 * stay.
 */
/* ARGSUSED0 */
static void
tl_close_ser(mblk_t *mp, tl_endpt_t *tep)
{
	ASSERT(tep->te_closing);
	ASSERT(tep->te_closewait == 1);
	ASSERT(!(tep->te_flag & TL_CLOSE_SER));

	tep->te_flag |= TL_CLOSE_SER;

	/*
	 * Drain out all messages on queue except for TL_TICOTS where the
	 * abortive release semantics permit discarding of data on close
	 */
	if (tep->te_wq->q_first && (IS_CLTS(tep) || IS_COTSORD(tep))) {
		tl_wsrv_ser(NULL, tep);
	}

	/* Remove address from hash table. */
	tl_addr_unbind(tep);
	/*
	 * qprocsoff() gets confused when q->q_next is not NULL on the write
	 * queue of the driver, so clear these before qprocsoff() is called.
	 * Also clear q_next for the peer since this queue is going away.
	 */
	if (IS_COTS(tep) && !IS_SOCKET(tep)) {
		tl_endpt_t *peer_tep = tep->te_conp;

		tep->te_wq->q_next = NULL;
		if ((peer_tep != NULL) && !peer_tep->te_closing)
			peer_tep->te_wq->q_next = NULL;
	}

	tep->te_rq = NULL;

	/* wake up tl_close() */
	tl_closeok(tep);
	tl_serializer_exit(tep);
}

/*
 * Second phase of tl_close(). Should wakeup tl_close() for COTS mode and drop
 * the reference for CLTS.
 *
 * Called from serializer. Should drop reference count for CLTS only.
 */
/* ARGSUSED0 */
static void
tl_close_finish_ser(mblk_t *mp, tl_endpt_t *tep)
{
	ASSERT(tep->te_closing);
	IMPLY(IS_CLTS(tep), tep->te_closewait == 0);
	IMPLY(IS_COTS(tep), tep->te_closewait == 1);

	tep->te_state = -1;	/* Uninitialized */
	if (IS_COTS(tep)) {
		tl_co_unconnect(tep);
	} else {
		/* Connectionless specific cleanup */
		TL_REMOVE_PEER(tep->te_lastep);
		/*
		 * Backenable anybody that is flow controlled waiting for
		 * this endpoint.
		 */
		tl_cl_backenable(tep);
		if (tep->te_flowq != NULL) {
			list_remove(&(tep->te_flowq->te_flowlist), tep);
			tep->te_flowq = NULL;
		}
	}

	tl_serializer_exit(tep);
	if (IS_COTS(tep))
		tl_closeok(tep);
	else
		tl_refrele(tep);
}

/*
 * STREAMS write-side put procedure.
 * Enter serializer for most of the processing.
 *
 * The T_CONN_REQ is processed outside of serializer.
 */
static void
tl_wput(queue_t *wq, mblk_t *mp)
{
	tl_endpt_t		*tep = (tl_endpt_t *)wq->q_ptr;
	ssize_t			msz = MBLKL(mp);
	union T_primitives	*prim = (union T_primitives *)mp->b_rptr;
	tlproc_t		*tl_proc = NULL;

	switch (DB_TYPE(mp)) {
	case M_DATA:
		/* Only valid for connection-oriented transports */
		if (IS_CLTS(tep)) {
			(void) (STRLOG(TL_ID, tep->te_minor, 1,
			    SL_TRACE|SL_ERROR,
			    "tl_wput:M_DATA invalid for ticlts driver"));
			tl_merror(wq, mp, EPROTO);
			return;
		}
		tl_proc = tl_wput_data_ser;
		break;

	case M_IOCTL:
		switch (((struct iocblk *)mp->b_rptr)->ioc_cmd) {
		case TL_IOC_CREDOPT:
			/* FALLTHROUGH */
		case TL_IOC_UCREDOPT:
			/*
			 * Serialize endpoint state change.
			 */
			tl_proc = tl_do_ioctl_ser;
			break;

		default:
			miocnak(wq, mp, 0, EINVAL);
			return;
		}
		break;

	case M_FLUSH:
		/*
		 * do canonical M_FLUSH processing
		 */
		if (*mp->b_rptr & FLUSHW) {
			flushq(wq, FLUSHALL);
			*mp->b_rptr &= ~FLUSHW;
		}
		if (*mp->b_rptr & FLUSHR) {
			flushq(RD(wq), FLUSHALL);
			qreply(wq, mp);
		} else {
			freemsg(mp);
		}
		return;

	case M_PROTO:
		if (msz < sizeof (prim->type)) {
			(void) (STRLOG(TL_ID, tep->te_minor, 1,
			    SL_TRACE|SL_ERROR,
			    "tl_wput:M_PROTO data too short"));
			tl_merror(wq, mp, EPROTO);
			return;
		}
		switch (prim->type) {
		case T_OPTMGMT_REQ:
		case T_SVR4_OPTMGMT_REQ:
			/*
			 * Process TPI option management requests immediately
			 * in put procedure regardless of in-order processing
			 * of already queued messages.
			 * (Note: This driver supports AF_UNIX socket
			 * implementation.  Unless we implement this processing,
			 * setsockopt() on socket endpoint will block on flow
			 * controlled endpoints which it should not. That is
			 * required for successful execution of VSU socket tests
			 * and is consistent with BSD socket behavior).
			 */
			tl_optmgmt(wq, mp);
			return;
		case O_T_BIND_REQ:
		case T_BIND_REQ:
			tl_proc = tl_bind_ser;
			break;
		case T_CONN_REQ:
			if (IS_CLTS(tep)) {
				tl_merror(wq, mp, EPROTO);
				return;
			}
			tl_conn_req(wq, mp);
			return;
		case T_DATA_REQ:
		case T_OPTDATA_REQ:
		case T_EXDATA_REQ:
		case T_ORDREL_REQ:
			tl_proc = tl_putq_ser;
			break;
		case T_UNITDATA_REQ:
			if (IS_COTS(tep) ||
			    (msz < sizeof (struct T_unitdata_req))) {
				tl_merror(wq, mp, EPROTO);
				return;
			}
			if ((tep->te_state == TS_IDLE) && !wq->q_first) {
				tl_proc = tl_unitdata_ser;
			} else {
				tl_proc = tl_putq_ser;
			}
			break;
		default:
			/*
			 * process in service procedure if message already
			 * queued (maintain in-order processing)
			 */
			if (wq->q_first != NULL) {
				tl_proc = tl_putq_ser;
			} else {
				tl_proc = tl_wput_ser;
			}
			break;
		}
		break;

	case M_PCPROTO:
		/*
		 * Check that the message has enough data to figure out TPI
		 * primitive.
		 */
		if (msz < sizeof (prim->type)) {
			(void) (STRLOG(TL_ID, tep->te_minor, 1,
			    SL_TRACE|SL_ERROR,
			    "tl_wput:M_PCROTO data too short"));
			tl_merror(wq, mp, EPROTO);
			return;
		}
		switch (prim->type) {
		case T_CAPABILITY_REQ:
			tl_capability_req(mp, tep);
			return;
		case T_INFO_REQ:
			tl_proc = tl_info_req_ser;
			break;
		case T_ADDR_REQ:
			tl_proc = tl_addr_req_ser;
			break;

		default:
			(void) (STRLOG(TL_ID, tep->te_minor, 1,
			    SL_TRACE|SL_ERROR,
			    "tl_wput:unknown TPI msg primitive"));
			tl_merror(wq, mp, EPROTO);
			return;
		}
		break;
	default:
		(void) (STRLOG(TL_ID, tep->te_minor, 1, SL_TRACE|SL_ERROR,
		    "tl_wput:default:unexpected Streams message"));
		freemsg(mp);
		return;
	}

	/*
	 * Continue processing via serializer.
	 */
	ASSERT(tl_proc != NULL);
	tl_refhold(tep);
	tl_serializer_enter(tep, tl_proc, mp);
}

/*
 * Place message on the queue while preserving order.
 */
static void
tl_putq_ser(mblk_t *mp, tl_endpt_t *tep)
{
	if (tep->te_closing) {
		tl_wput_ser(mp, tep);
	} else {
		TL_PUTQ(tep, mp);
		tl_serializer_exit(tep);
		tl_refrele(tep);
	}

}

static void
tl_wput_common_ser(mblk_t *mp, tl_endpt_t *tep)
{
	ASSERT((DB_TYPE(mp) == M_DATA) || (DB_TYPE(mp) == M_PROTO));

	switch (DB_TYPE(mp)) {
	case M_DATA:
		tl_data(mp, tep);
		break;
	case M_PROTO:
		tl_do_proto(mp, tep);
		break;
	default:
		freemsg(mp);
		break;
	}
}

/*
 * Write side put procedure called from serializer.
 */
static void
tl_wput_ser(mblk_t *mp, tl_endpt_t *tep)
{
	tl_wput_common_ser(mp, tep);
	tl_serializer_exit(tep);
	tl_refrele(tep);
}

/*
 * M_DATA processing. Called from serializer.
 */
static void
tl_wput_data_ser(mblk_t *mp, tl_endpt_t *tep)
{
	tl_endpt_t	*peer_tep = tep->te_conp;
	queue_t		*peer_rq;

	ASSERT(DB_TYPE(mp) == M_DATA);
	ASSERT(IS_COTS(tep));

	IMPLY(peer_tep, tep->te_serializer == peer_tep->te_serializer);

	/*
	 * fastpath for data. Ignore flow control if tep is closing.
	 */
	if ((peer_tep != NULL) &&
	    !peer_tep->te_closing &&
	    ((tep->te_state == TS_DATA_XFER) ||
	    (tep->te_state == TS_WREQ_ORDREL)) &&
	    (tep->te_wq != NULL) &&
	    (tep->te_wq->q_first == NULL) &&
	    ((peer_tep->te_state == TS_DATA_XFER) ||
	    (peer_tep->te_state == TS_WREQ_ORDREL))	&&
	    ((peer_rq = peer_tep->te_rq) != NULL) &&
	    (canputnext(peer_rq) || tep->te_closing)) {
		putnext(peer_rq, mp);
	} else if (tep->te_closing) {
		/*
		 * It is possible that by the time we got here tep started to
		 * close. If the write queue is not empty, and the state is
		 * TS_DATA_XFER the data should be delivered in order, so we
		 * call putq() instead of freeing the data.
		 */
		if ((tep->te_wq != NULL) &&
		    ((tep->te_state == TS_DATA_XFER) ||
		    (tep->te_state == TS_WREQ_ORDREL))) {
			TL_PUTQ(tep, mp);
		} else {
			freemsg(mp);
		}
	} else {
		TL_PUTQ(tep, mp);
	}

	tl_serializer_exit(tep);
	tl_refrele(tep);
}

/*
 * Write side service routine.
 *
 * All actual processing happens within serializer which is entered
 * synchronously. It is possible that by the time tl_wsrv() wakes up, some new
 * messages that need processing may have arrived, so tl_wsrv repeats until
 * queue is empty or te_nowsrv is set.
 */
static void
tl_wsrv(queue_t *wq)
{
	tl_endpt_t *tep = (tl_endpt_t *)wq->q_ptr;

	while ((wq->q_first != NULL) && !tep->te_nowsrv) {
		mutex_enter(&tep->te_srv_lock);
		ASSERT(tep->te_wsrv_active == B_FALSE);
		tep->te_wsrv_active = B_TRUE;
		mutex_exit(&tep->te_srv_lock);

		tl_serializer_enter(tep, tl_wsrv_ser, &tep->te_wsrvmp);

		/*
		 * Wait for serializer job to complete.
		 */
		mutex_enter(&tep->te_srv_lock);
		while (tep->te_wsrv_active) {
			cv_wait(&tep->te_srv_cv, &tep->te_srv_lock);
		}
		cv_signal(&tep->te_srv_cv);
		mutex_exit(&tep->te_srv_lock);
	}
}

/*
 * Serialized write side processing of the STREAMS queue.
 * May be called either from tl_wsrv() or from tl_close() in which case ser_mp
 * is NULL.
 */
static void
tl_wsrv_ser(mblk_t *ser_mp, tl_endpt_t *tep)
{
	mblk_t *mp;
	queue_t *wq = tep->te_wq;

	ASSERT(wq != NULL);
	while (!tep->te_nowsrv && (mp = getq(wq)) != NULL) {
		tl_wput_common_ser(mp, tep);
	}

	/*
	 * Wakeup service routine unless called from close.
	 * If ser_mp is specified, the caller is tl_wsrv().
	 * Otherwise, the caller is tl_close_ser(). Since tl_close_ser() doesn't
	 * call tl_serializer_enter() before calling tl_wsrv_ser(), there should
	 * be no matching tl_serializer_exit() in this case.
	 * Also, there is no need to wakeup anyone since tl_close_ser() is not
	 * waiting on te_srv_cv.
	 */
	if (ser_mp != NULL) {
		/*
		 * We are called from tl_wsrv.
		 */
		mutex_enter(&tep->te_srv_lock);
		ASSERT(tep->te_wsrv_active);
		tep->te_wsrv_active = B_FALSE;
		cv_signal(&tep->te_srv_cv);
		mutex_exit(&tep->te_srv_lock);
		tl_serializer_exit(tep);
	}
}

/*
 * Called when the stream is backenabled. Enter serializer and qenable everyone
 * flow controlled by tep.
 *
 * NOTE: The service routine should enter serializer synchronously. Otherwise it
 * is possible that two instances of tl_rsrv will be running reusing the same
 * rsrv mblk.
 */
static void
tl_rsrv(queue_t *rq)
{
	tl_endpt_t *tep = (tl_endpt_t *)rq->q_ptr;

	ASSERT(rq->q_first == NULL);
	ASSERT(tep->te_rsrv_active == 0);

	tep->te_rsrv_active = B_TRUE;
	tl_serializer_enter(tep, tl_rsrv_ser, &tep->te_rsrvmp);
	/*
	 * Wait for serializer job to complete.
	 */
	mutex_enter(&tep->te_srv_lock);
	while (tep->te_rsrv_active) {
		cv_wait(&tep->te_srv_cv, &tep->te_srv_lock);
	}
	cv_signal(&tep->te_srv_cv);
	mutex_exit(&tep->te_srv_lock);
}

/* ARGSUSED */
static void
tl_rsrv_ser(mblk_t *mp, tl_endpt_t *tep)
{
	tl_endpt_t *peer_tep;

	if (IS_CLTS(tep) && tep->te_state == TS_IDLE) {
		tl_cl_backenable(tep);
	} else if (
	    IS_COTS(tep) &&
	    ((peer_tep = tep->te_conp) != NULL) &&
	    !peer_tep->te_closing &&
	    ((tep->te_state == TS_DATA_XFER) ||
	    (tep->te_state == TS_WIND_ORDREL)||
	    (tep->te_state == TS_WREQ_ORDREL))) {
		TL_QENABLE(peer_tep);
	}

	/*
	 * Wakeup read side service routine.
	 */
	mutex_enter(&tep->te_srv_lock);
	ASSERT(tep->te_rsrv_active);
	tep->te_rsrv_active = B_FALSE;
	cv_signal(&tep->te_srv_cv);
	mutex_exit(&tep->te_srv_lock);
	tl_serializer_exit(tep);
}

/*
 * process M_PROTO messages. Always called from serializer.
 */
static void
tl_do_proto(mblk_t *mp, tl_endpt_t *tep)
{
	ssize_t			msz = MBLKL(mp);
	union T_primitives	*prim = (union T_primitives *)mp->b_rptr;

	/* Message size was validated by tl_wput(). */
	ASSERT(msz >= sizeof (prim->type));

	switch (prim->type) {
	case T_UNBIND_REQ:
		tl_unbind(mp, tep);
		break;

	case T_ADDR_REQ:
		tl_addr_req(mp, tep);
		break;

	case O_T_CONN_RES:
	case T_CONN_RES:
		if (IS_CLTS(tep)) {
			tl_merror(tep->te_wq, mp, EPROTO);
			break;
		}
		tl_conn_res(mp, tep);
		break;

	case T_DISCON_REQ:
		if (IS_CLTS(tep)) {
			tl_merror(tep->te_wq, mp, EPROTO);
			break;
		}
		tl_discon_req(mp, tep);
		break;

	case T_DATA_REQ:
		if (IS_CLTS(tep)) {
			tl_merror(tep->te_wq, mp, EPROTO);
			break;
		}
		tl_data(mp, tep);
		break;

	case T_OPTDATA_REQ:
		if (IS_CLTS(tep)) {
			tl_merror(tep->te_wq, mp, EPROTO);
			break;
		}
		tl_data(mp, tep);
		break;

	case T_EXDATA_REQ:
		if (IS_CLTS(tep)) {
			tl_merror(tep->te_wq, mp, EPROTO);
			break;
		}
		tl_exdata(mp, tep);
		break;

	case T_ORDREL_REQ:
		if (! IS_COTSORD(tep)) {
			tl_merror(tep->te_wq, mp, EPROTO);
			break;
		}
		tl_ordrel(mp, tep);
		break;

	case T_UNITDATA_REQ:
		if (IS_COTS(tep)) {
			tl_merror(tep->te_wq, mp, EPROTO);
			break;
		}
		tl_unitdata(mp, tep);
		break;

	default:
		tl_merror(tep->te_wq, mp, EPROTO);
		break;
	}
}

/*
 * Process ioctl from serializer.
 * This is a wrapper around tl_do_ioctl().
 */
static void
tl_do_ioctl_ser(mblk_t *mp, tl_endpt_t *tep)
{
	if (! tep->te_closing)
		tl_do_ioctl(mp, tep);
	else
		freemsg(mp);

	tl_serializer_exit(tep);
	tl_refrele(tep);
}

static void
tl_do_ioctl(mblk_t *mp, tl_endpt_t *tep)
{
	struct iocblk *iocbp = (struct iocblk *)mp->b_rptr;
	int cmd = iocbp->ioc_cmd;
	queue_t *wq = tep->te_wq;
	int error;
	int thisopt, otheropt;

	ASSERT((cmd == TL_IOC_CREDOPT) || (cmd == TL_IOC_UCREDOPT));

	switch (cmd) {
	case TL_IOC_CREDOPT:
		if (cmd == TL_IOC_CREDOPT) {
			thisopt = TL_SETCRED;
			otheropt = TL_SETUCRED;
		} else {
			/* FALLTHROUGH */
	case TL_IOC_UCREDOPT:
			thisopt = TL_SETUCRED;
			otheropt = TL_SETCRED;
		}
		/*
		 * The credentials passing does not apply to sockets.
		 * Only one of the cred options can be set at a given time.
		 */
		if (IS_SOCKET(tep) || (tep->te_flag & otheropt)) {
			miocnak(wq, mp, 0, EINVAL);
			return;
		}

		/*
		 * Turn on generation of credential options for
		 * T_conn_req, T_conn_con, T_unidata_ind.
		 */
		error = miocpullup(mp, sizeof (uint32_t));
		if (error != 0) {
			miocnak(wq, mp, 0, error);
			return;
		}
		if (!IS_P2ALIGNED(mp->b_cont->b_rptr, sizeof (uint32_t))) {
			miocnak(wq, mp, 0, EINVAL);
			return;
		}

		if (*(uint32_t *)mp->b_cont->b_rptr)
			tep->te_flag |= thisopt;
		else
			tep->te_flag &= ~thisopt;

		miocack(wq, mp, 0, 0);
		break;

	default:
		/* Should not be here */
		miocnak(wq, mp, 0, EINVAL);
		break;
	}
}


/*
 * send T_ERROR_ACK
 * Note: assumes enough memory or caller passed big enough mp
 *	- no recovery from allocb failures
 */

static void
tl_error_ack(queue_t *wq, mblk_t *mp, t_scalar_t tli_err,
    t_scalar_t unix_err, t_scalar_t type)
{
	struct T_error_ack *err_ack;
	mblk_t *ackmp = tpi_ack_alloc(mp, sizeof (struct T_error_ack),
	    M_PCPROTO, T_ERROR_ACK);

	if (ackmp == NULL) {
		(void) (STRLOG(TL_ID, 0, 1, SL_TRACE|SL_ERROR,
		    "tl_error_ack:out of mblk memory"));
		tl_merror(wq, NULL, ENOSR);
		return;
	}
	err_ack = (struct T_error_ack *)ackmp->b_rptr;
	err_ack->ERROR_prim = type;
	err_ack->TLI_error = tli_err;
	err_ack->UNIX_error = unix_err;

	/*
	 * send error ack message
	 */
	qreply(wq, ackmp);
}



/*
 * send T_OK_ACK
 * Note: assumes enough memory or caller passed big enough mp
 *	- no recovery from allocb failures
 */
static void
tl_ok_ack(queue_t *wq, mblk_t *mp, t_scalar_t type)
{
	struct T_ok_ack *ok_ack;
	mblk_t *ackmp = tpi_ack_alloc(mp, sizeof (struct T_ok_ack),
	    M_PCPROTO, T_OK_ACK);

	if (ackmp == NULL) {
		tl_merror(wq, NULL, ENOMEM);
		return;
	}

	ok_ack = (struct T_ok_ack *)ackmp->b_rptr;
	ok_ack->CORRECT_prim = type;

	(void) qreply(wq, ackmp);
}

/*
 * Process T_BIND_REQ and O_T_BIND_REQ from serializer.
 * This is a wrapper around tl_bind().
 */
static void
tl_bind_ser(mblk_t *mp, tl_endpt_t *tep)
{
	if (! tep->te_closing)
		tl_bind(mp, tep);
	else
		freemsg(mp);

	tl_serializer_exit(tep);
	tl_refrele(tep);
}

/*
 * Process T_BIND_REQ and O_T_BIND_REQ TPI requests.
 * Assumes that the endpoint is in the unbound.
 */
static void
tl_bind(mblk_t *mp, tl_endpt_t *tep)
{
	queue_t			*wq = tep->te_wq;
	struct T_bind_ack	*b_ack;
	struct T_bind_req	*bind = (struct T_bind_req *)mp->b_rptr;
	mblk_t			*ackmp, *bamp;
	soux_addr_t		ux_addr;
	t_uscalar_t		qlen = 0;
	t_scalar_t		alen, aoff;
	tl_addr_t		addr_req;
	void			*addr_startp;
	ssize_t			msz = MBLKL(mp), basize;
	t_scalar_t		tli_err = 0, unix_err = 0;
	t_scalar_t		save_prim_type = bind->PRIM_type;
	t_scalar_t		save_state = tep->te_state;

	if (tep->te_state != TS_UNBND) {
		(void) (STRLOG(TL_ID, tep->te_minor, 1,
		    SL_TRACE|SL_ERROR,
		    "tl_wput:bind_request:out of state, state=%d",
		    tep->te_state));
		tli_err = TOUTSTATE;
		goto error;
	}

	if (msz < sizeof (struct T_bind_req)) {
		tli_err = TSYSERR; unix_err = EINVAL;
		goto error;
	}

	tep->te_state = NEXTSTATE(TE_BIND_REQ, tep->te_state);

	ASSERT((bind->PRIM_type == O_T_BIND_REQ) ||
	    (bind->PRIM_type == T_BIND_REQ));

	alen = bind->ADDR_length;
	aoff = bind->ADDR_offset;

	/* negotiate max conn req pending */
	if (IS_COTS(tep)) {
		qlen = bind->CONIND_number;
		if (qlen > tl_maxqlen)
			qlen = tl_maxqlen;
	}

	/*
	 * Reserve hash handle. It can only be NULL if the endpoint is unbound
	 * and bound again.
	 */
	if ((tep->te_hash_hndl == NULL) &&
	    ((tep->te_flag & TL_ADDRHASHED) == 0) &&
	    mod_hash_reserve_nosleep(tep->te_addrhash,
	    &tep->te_hash_hndl) != 0) {
		tli_err = TSYSERR; unix_err = ENOSR;
		goto error;
	}

	/*
	 * Verify address correctness.
	 */
	if (IS_SOCKET(tep)) {
		ASSERT(bind->PRIM_type == O_T_BIND_REQ);

		if ((alen != TL_SOUX_ADDRLEN) ||
		    (aoff < 0) ||
		    (aoff + alen > msz)) {
			(void) (STRLOG(TL_ID, tep->te_minor,
			    1, SL_TRACE|SL_ERROR,
			    "tl_bind: invalid socket addr"));
			tep->te_state = NEXTSTATE(TE_ERROR_ACK, tep->te_state);
			tli_err = TSYSERR; unix_err = EINVAL;
			goto error;
		}
		/* Copy address from message to local buffer. */
		bcopy(mp->b_rptr + aoff, &ux_addr, sizeof (ux_addr));
		/*
		 * Check that we got correct address from sockets
		 */
		if ((ux_addr.soua_magic != SOU_MAGIC_EXPLICIT) &&
		    (ux_addr.soua_magic != SOU_MAGIC_IMPLICIT)) {
			(void) (STRLOG(TL_ID, tep->te_minor,
			    1, SL_TRACE|SL_ERROR,
			    "tl_bind: invalid socket magic"));
			tep->te_state = NEXTSTATE(TE_ERROR_ACK, tep->te_state);
			tli_err = TSYSERR; unix_err = EINVAL;
			goto error;
		}
		if ((ux_addr.soua_magic == SOU_MAGIC_IMPLICIT) &&
		    (ux_addr.soua_vp != NULL)) {
			(void) (STRLOG(TL_ID, tep->te_minor,
			    1, SL_TRACE|SL_ERROR,
			    "tl_bind: implicit addr non-empty"));
			tep->te_state = NEXTSTATE(TE_ERROR_ACK, tep->te_state);
			tli_err = TSYSERR; unix_err = EINVAL;
			goto error;
		}
		if ((ux_addr.soua_magic == SOU_MAGIC_EXPLICIT) &&
		    (ux_addr.soua_vp == NULL)) {
			(void) (STRLOG(TL_ID, tep->te_minor,
			    1, SL_TRACE|SL_ERROR,
			    "tl_bind: explicit addr empty"));
			tep->te_state = NEXTSTATE(TE_ERROR_ACK, tep->te_state);
			tli_err = TSYSERR; unix_err = EINVAL;
			goto error;
		}
	} else {
		if ((alen > 0) && ((aoff < 0) ||
		    ((ssize_t)(aoff + alen) > msz) ||
		    ((aoff + alen) < 0))) {
			(void) (STRLOG(TL_ID, tep->te_minor,
			    1, SL_TRACE|SL_ERROR,
			    "tl_bind: invalid message"));
			tep->te_state = NEXTSTATE(TE_ERROR_ACK, tep->te_state);
			tli_err = TSYSERR; unix_err = EINVAL;
			goto error;
		}
		if ((alen < 0) || (alen > (msz - sizeof (struct T_bind_req)))) {
			(void) (STRLOG(TL_ID, tep->te_minor,
			    1, SL_TRACE|SL_ERROR,
			    "tl_bind: bad addr in  message"));
			tep->te_state = NEXTSTATE(TE_ERROR_ACK, tep->te_state);
			tli_err = TBADADDR;
			goto error;
		}
#ifdef DEBUG
		/*
		 * Mild form of ASSERT()ion to detect broken TPI apps.
		 * if (! assertion)
		 *	log warning;
		 */
		if (! ((alen == 0 && aoff == 0) ||
			(aoff >= (t_scalar_t)(sizeof (struct T_bind_req))))) {
			(void) (STRLOG(TL_ID, tep->te_minor,
				    3, SL_TRACE|SL_ERROR,
				    "tl_bind: addr overlaps TPI message"));
		}
#endif
	}

	/*
	 * Bind the address provided or allocate one if requested.
	 * Allow rebinds with a new qlen value.
	 */
	if (IS_SOCKET(tep)) {
		/*
		 * For anonymous requests the te_ap is already set up properly
		 * so use minor number as an address.
		 * For explicit requests need to check whether the address is
		 * already in use.
		 */
		if (ux_addr.soua_magic == SOU_MAGIC_EXPLICIT) {
			int rc;

			if (tep->te_flag & TL_ADDRHASHED) {
				ASSERT(IS_COTS(tep) && tep->te_qlen == 0);
				if (tep->te_vp == ux_addr.soua_vp)
					goto skip_addr_bind;
				else /* Rebind to a new address. */
					tl_addr_unbind(tep);
			}
			/*
			 * Insert address in the hash if it is not already
			 * there.  Since we use preallocated handle, the insert
			 * can fail only if the key is already present.
			 */
			rc = mod_hash_insert_reserve(tep->te_addrhash,
			    (mod_hash_key_t)ux_addr.soua_vp,
			    (mod_hash_val_t)tep, tep->te_hash_hndl);

			if (rc != 0) {
				ASSERT(rc == MH_ERR_DUPLICATE);
				/*
				 * Violate O_T_BIND_REQ semantics and fail with
				 * TADDRBUSY - sockets will not use any address
				 * other than supplied one for explicit binds.
				 */
				(void) (STRLOG(TL_ID, tep->te_minor, 1,
				    SL_TRACE|SL_ERROR,
				    "tl_bind:requested addr %p is busy",
				    ux_addr.soua_vp));
				tli_err = TADDRBUSY; unix_err = 0;
				goto error;
			}
			tep->te_uxaddr = ux_addr;
			tep->te_flag |= TL_ADDRHASHED;
			tep->te_hash_hndl = NULL;
		}
	} else if (alen == 0) {
		/*
		 * assign any free address
		 */
		if (! tl_get_any_addr(tep, NULL)) {
			(void) (STRLOG(TL_ID, tep->te_minor,
			    1, SL_TRACE|SL_ERROR,
			    "tl_bind:failed to get buffer for any "
			    "address"));
			tli_err = TSYSERR; unix_err = ENOSR;
			goto error;
		}
	} else {
		addr_req.ta_alen = alen;
		addr_req.ta_abuf = (mp->b_rptr + aoff);
		addr_req.ta_zoneid = tep->te_zoneid;

		tep->te_abuf = kmem_zalloc((size_t)alen, KM_NOSLEEP);
		if (tep->te_abuf == NULL) {
			tli_err = TSYSERR; unix_err = ENOSR;
			goto error;
		}
		bcopy(addr_req.ta_abuf, tep->te_abuf, addr_req.ta_alen);
		tep->te_alen = alen;

		if (mod_hash_insert_reserve(tep->te_addrhash,
		    (mod_hash_key_t)&tep->te_ap, (mod_hash_val_t)tep,
		    tep->te_hash_hndl) != 0) {
			if (save_prim_type == T_BIND_REQ) {
				/*
				 * The bind semantics for this primitive
				 * require a failure if the exact address
				 * requested is busy
				 */
				(void) (STRLOG(TL_ID, tep->te_minor, 1,
				    SL_TRACE|SL_ERROR,
				    "tl_bind:requested addr is busy"));
				tli_err = TADDRBUSY; unix_err = 0;
				goto error;
			}

			/*
			 * O_T_BIND_REQ semantics say if address if requested
			 * address is busy, bind to any available free address
			 */
			if (! tl_get_any_addr(tep, &addr_req)) {
				(void) (STRLOG(TL_ID, tep->te_minor, 1,
				    SL_TRACE|SL_ERROR,
				    "tl_bind:unable to get any addr buf"));
				tli_err = TSYSERR; unix_err = ENOMEM;
				goto error;
			}
		} else {
			tep->te_flag |= TL_ADDRHASHED;
			tep->te_hash_hndl = NULL;
		}
	}

	ASSERT(tep->te_alen >= 0);

skip_addr_bind:
	/*
	 * prepare T_BIND_ACK TPI message
	 */
	basize = sizeof (struct T_bind_ack) + tep->te_alen;
	bamp = reallocb(mp, basize, 0);
	if (bamp == NULL) {
		(void) (STRLOG(TL_ID, tep->te_minor, 1, SL_TRACE|SL_ERROR,
		    "tl_wput:tl_bind: allocb failed"));
		/*
		 * roll back state changes
		 */
		tl_addr_unbind(tep);
		tep->te_state = TS_UNBND;
		tl_memrecover(wq, mp, basize);
		return;
	}

	DB_TYPE(bamp) = M_PCPROTO;
	bamp->b_wptr = bamp->b_rptr + basize;
	b_ack = (struct T_bind_ack *)bamp->b_rptr;
	b_ack->PRIM_type = T_BIND_ACK;
	b_ack->CONIND_number = qlen;
	b_ack->ADDR_length = tep->te_alen;
	b_ack->ADDR_offset = (t_scalar_t)sizeof (struct T_bind_ack);
	addr_startp = bamp->b_rptr + b_ack->ADDR_offset;
	bcopy(tep->te_abuf, addr_startp, tep->te_alen);

	if (IS_COTS(tep)) {
		tep->te_qlen = qlen;
		if (qlen > 0)
			tep->te_flag |= TL_LISTENER;
	}

	tep->te_state = NEXTSTATE(TE_BIND_ACK, tep->te_state);
	/*
	 * send T_BIND_ACK message
	 */
	(void) qreply(wq, bamp);
	return;

error:
	ackmp = reallocb(mp, sizeof (struct T_error_ack), 0);
	if (ackmp == NULL) {
		/*
		 * roll back state changes
		 */
		tep->te_state = save_state;
		tl_memrecover(wq, mp, sizeof (struct T_error_ack));
		return;
	}
	tep->te_state = NEXTSTATE(TE_ERROR_ACK, tep->te_state);
	tl_error_ack(wq, ackmp, tli_err, unix_err, save_prim_type);
}

/*
 * Process T_UNBIND_REQ.
 * Called from serializer.
 */
static void
tl_unbind(mblk_t *mp, tl_endpt_t *tep)
{
	queue_t *wq;
	mblk_t *ackmp;

	if (tep->te_closing) {
		freemsg(mp);
		return;
	}

	wq = tep->te_wq;

	/*
	 * preallocate memory for max of T_OK_ACK and T_ERROR_ACK
	 * ==> allocate for T_ERROR_ACK (known max)
	 */
	if ((ackmp = reallocb(mp, sizeof (struct T_error_ack), 0)) == NULL) {
		tl_memrecover(wq, mp, sizeof (struct T_error_ack));
		return;
	}
	/*
	 * memory resources committed
	 * Note: no message validation. T_UNBIND_REQ message is
	 * same size as PRIM_type field so already verified earlier.
	 */

	/*
	 * validate state
	 */
	if (tep->te_state != TS_IDLE) {
		(void) (STRLOG(TL_ID, tep->te_minor, 1,
		    SL_TRACE|SL_ERROR,
		    "tl_wput:T_UNBIND_REQ:out of state, state=%d",
		    tep->te_state));
		tl_error_ack(wq, ackmp, TOUTSTATE, 0, T_UNBIND_REQ);
		return;
	}
	tep->te_state = NEXTSTATE(TE_UNBIND_REQ, tep->te_state);

	/*
	 * TPI says on T_UNBIND_REQ:
	 *    send up a M_FLUSH to flush both
	 *    read and write queues
	 */
	(void) putnextctl1(RD(wq), M_FLUSH, FLUSHRW);

	if (! IS_SOCKET(tep) || !IS_CLTS(tep) || tep->te_qlen != 0 ||
	    tep->te_magic != SOU_MAGIC_EXPLICIT) {

		/*
		 * Sockets use bind with qlen==0 followed by bind() to
		 * the same address with qlen > 0 for listeners.
		 * We allow rebind with a new qlen value.
		 */
		tl_addr_unbind(tep);
	}

	tep->te_state = NEXTSTATE(TE_OK_ACK1, tep->te_state);
	/*
	 * send  T_OK_ACK
	 */
	tl_ok_ack(wq, ackmp, T_UNBIND_REQ);
}


/*
 * Option management code from drv/ip is used here
 * Note: TL_PROT_LEVEL/TL_IOC_CREDOPT option is not part of tl_opt_arr
 *	database of options. So optcom_req() will fail T_SVR4_OPTMGMT_REQ.
 *	However, that is what we want as that option is 'unorthodox'
 *	and only valid in T_CONN_IND, T_CONN_CON  and T_UNITDATA_IND
 *	and not in T_SVR4_OPTMGMT_REQ/ACK
 * Note2: use of optcom_req means this routine is an exception to
 *	 recovery from allocb() failures.
 */

static void
tl_optmgmt(queue_t *wq, mblk_t *mp)
{
	tl_endpt_t *tep;
	mblk_t *ackmp;
	union T_primitives *prim;
	cred_t *cr;

	tep = (tl_endpt_t *)wq->q_ptr;
	prim = (union T_primitives *)mp->b_rptr;

	/*
	 * All Solaris components should pass a db_credp
	 * for this TPI message, hence we ASSERT.
	 * But in case there is some other M_PROTO that looks
	 * like a TPI message sent by some other kernel
	 * component, we check and return an error.
	 */
	cr = msg_getcred(mp, NULL);
	ASSERT(cr != NULL);
	if (cr == NULL) {
		tl_error_ack(wq, mp, TSYSERR, EINVAL, prim->type);
		return;
	}

	/*  all states OK for AF_UNIX options ? */
	if (!IS_SOCKET(tep) && tep->te_state != TS_IDLE &&
	    prim->type == T_SVR4_OPTMGMT_REQ) {
		/*
		 * Broken TLI semantics that options can only be managed
		 * in TS_IDLE state. Needed for Sparc ABI test suite that
		 * tests this TLI (mis)feature using this device driver.
		 */
		(void) (STRLOG(TL_ID, tep->te_minor, 1,
		    SL_TRACE|SL_ERROR,
		    "tl_wput:T_SVR4_OPTMGMT_REQ:out of state, state=%d",
		    tep->te_state));
		/*
		 * preallocate memory for T_ERROR_ACK
		 */
		ackmp = allocb(sizeof (struct T_error_ack), BPRI_MED);
		if (! ackmp) {
			tl_memrecover(wq, mp, sizeof (struct T_error_ack));
			return;
		}

		tl_error_ack(wq, ackmp, TOUTSTATE, 0, T_SVR4_OPTMGMT_REQ);
		freemsg(mp);
		return;
	}

	/*
	 * call common option management routine from drv/ip
	 */
	if (prim->type == T_SVR4_OPTMGMT_REQ) {
		svr4_optcom_req(wq, mp, cr, &tl_opt_obj);
	} else {
		ASSERT(prim->type == T_OPTMGMT_REQ);
		tpi_optcom_req(wq, mp, cr, &tl_opt_obj);
	}
}

/*
 * Handle T_conn_req - the driver part of accept().
 * If TL_SET[U]CRED generate the credentials options.
 * If this is a socket pass through options unmodified.
 * For sockets generate the T_CONN_CON here instead of
 * waiting for the T_CONN_RES.
 */
static void
tl_conn_req(queue_t *wq, mblk_t *mp)
{
	tl_endpt_t		*tep = (tl_endpt_t *)wq->q_ptr;
	struct T_conn_req	*creq = (struct T_conn_req *)mp->b_rptr;
	ssize_t			msz = MBLKL(mp);
	t_scalar_t		alen, aoff, olen, ooff,	err = 0;
	tl_endpt_t		*peer_tep = NULL;
	mblk_t			*ackmp;
	mblk_t			*dimp;
	struct T_discon_ind	*di;
	soux_addr_t		ux_addr;
	tl_addr_t		dst;

	ASSERT(IS_COTS(tep));

	if (tep->te_closing) {
		freemsg(mp);
		return;
	}

	/*
	 * preallocate memory for:
	 * 1. max of T_ERROR_ACK and T_OK_ACK
	 *	==> known max T_ERROR_ACK
	 * 2. max of T_DISCON_IND and T_CONN_IND
	 */
	ackmp = allocb(sizeof (struct T_error_ack), BPRI_MED);
	if (! ackmp) {
		tl_memrecover(wq, mp, sizeof (struct T_error_ack));
		return;
	}
	/*
	 * memory committed for T_OK_ACK/T_ERROR_ACK now
	 * will be committed for T_DISCON_IND/T_CONN_IND later
	 */

	if (tep->te_state != TS_IDLE) {
		(void) (STRLOG(TL_ID, tep->te_minor, 1,
		    SL_TRACE|SL_ERROR,
		    "tl_wput:T_CONN_REQ:out of state, state=%d",
		    tep->te_state));
		tl_error_ack(wq, ackmp, TOUTSTATE, 0, T_CONN_REQ);
		freemsg(mp);
		return;
	}

	/*
	 * validate the message
	 * Note: dereference fields in struct inside message only
	 * after validating the message length.
	 */
	if (msz < sizeof (struct T_conn_req)) {
		(void) (STRLOG(TL_ID, tep->te_minor, 1, SL_TRACE|SL_ERROR,
		    "tl_conn_req:invalid message length"));
		tl_error_ack(wq, ackmp, TSYSERR, EINVAL, T_CONN_REQ);
		freemsg(mp);
		return;
	}
	alen = creq->DEST_length;
	aoff = creq->DEST_offset;
	olen = creq->OPT_length;
	ooff = creq->OPT_offset;
	if (olen == 0)
		ooff = 0;

	if (IS_SOCKET(tep)) {
		if ((alen != TL_SOUX_ADDRLEN) ||
		    (aoff < 0) ||
		    (aoff + alen > msz) ||
		    (alen > msz - sizeof (struct T_conn_req))) {
			(void) (STRLOG(TL_ID, tep->te_minor,
				    1, SL_TRACE|SL_ERROR,
				    "tl_conn_req: invalid socket addr"));
			tl_error_ack(wq, ackmp, TSYSERR, EINVAL, T_CONN_REQ);
			freemsg(mp);
			return;
		}
		bcopy(mp->b_rptr + aoff, &ux_addr, TL_SOUX_ADDRLEN);
		if ((ux_addr.soua_magic != SOU_MAGIC_IMPLICIT) &&
		    (ux_addr.soua_magic != SOU_MAGIC_EXPLICIT)) {
			(void) (STRLOG(TL_ID, tep->te_minor,
			    1, SL_TRACE|SL_ERROR,
			    "tl_conn_req: invalid socket magic"));
			tl_error_ack(wq, ackmp, TSYSERR, EINVAL, T_CONN_REQ);
			freemsg(mp);
			return;
		}
	} else {
		if ((alen > 0 && ((aoff + alen) > msz || aoff + alen < 0)) ||
		    (olen > 0 && ((ssize_t)(ooff + olen) > msz ||
		    ooff + olen < 0)) ||
		    olen < 0 || ooff < 0) {
			(void) (STRLOG(TL_ID, tep->te_minor, 1,
			    SL_TRACE|SL_ERROR,
			    "tl_conn_req:invalid message"));
			tl_error_ack(wq, ackmp, TSYSERR, EINVAL, T_CONN_REQ);
			freemsg(mp);
			return;
		}

		if (alen <= 0 || aoff < 0 ||
		    (ssize_t)alen > msz - sizeof (struct T_conn_req)) {
			(void) (STRLOG(TL_ID, tep->te_minor, 1,
				    SL_TRACE|SL_ERROR,
				    "tl_conn_req:bad addr in message, "
				    "alen=%d, msz=%ld",
				    alen, msz));
			tl_error_ack(wq, ackmp, TBADADDR, 0, T_CONN_REQ);
			freemsg(mp);
			return;
		}
#ifdef DEBUG
		/*
		 * Mild form of ASSERT()ion to detect broken TPI apps.
		 * if (! assertion)
		 *	log warning;
		 */
		if (! (aoff >= (t_scalar_t)sizeof (struct T_conn_req))) {
			(void) (STRLOG(TL_ID, tep->te_minor, 3,
			    SL_TRACE|SL_ERROR,
			    "tl_conn_req: addr overlaps TPI message"));
		}
#endif
		if (olen) {
			/*
			 * no opts in connect req
			 * supported in this provider except for sockets.
			 */
			(void) (STRLOG(TL_ID, tep->te_minor, 1,
			    SL_TRACE|SL_ERROR,
			    "tl_conn_req:options not supported "
			    "in message"));
			tl_error_ack(wq, ackmp, TBADOPT, 0, T_CONN_REQ);
			freemsg(mp);
			return;
		}
	}

	/*
	 * Prevent tep from closing on us.
	 */
	if (! tl_noclose(tep)) {
		(void) (STRLOG(TL_ID, tep->te_minor, 1, SL_TRACE|SL_ERROR,
		    "tl_conn_req:endpoint is closing"));
		tl_error_ack(wq, ackmp, TOUTSTATE, 0, T_CONN_REQ);
		freemsg(mp);
		return;
	}

	tep->te_state = NEXTSTATE(TE_CONN_REQ, tep->te_state);
	/*
	 * get endpoint to connect to
	 * check that peer with DEST addr is bound to addr
	 * and has CONIND_number > 0
	 */
	dst.ta_alen = alen;
	dst.ta_abuf = mp->b_rptr + aoff;
	dst.ta_zoneid = tep->te_zoneid;

	/*
	 * Verify if remote addr is in use
	 */
	peer_tep = (IS_SOCKET(tep) ?
	    tl_sock_find_peer(tep, &ux_addr) :
	    tl_find_peer(tep, &dst));

	if (peer_tep == NULL) {
		(void) (STRLOG(TL_ID, tep->te_minor, 1, SL_TRACE|SL_ERROR,
		    "tl_conn_req:no one at connect address"));
		err = ECONNREFUSED;
	} else if (peer_tep->te_nicon >= peer_tep->te_qlen)  {
		/*
		 * validate that number of incoming connection is
		 * not to capacity on destination endpoint
		 */
		(void) (STRLOG(TL_ID, tep->te_minor, 2, SL_TRACE,
		    "tl_conn_req: qlen overflow connection refused"));
			err = ECONNREFUSED;
	}

	/*
	 * Send T_DISCON_IND in case of error
	 */
	if (err != 0) {
		if (peer_tep != NULL)
			tl_refrele(peer_tep);
		/* We are still expected to send T_OK_ACK */
		tep->te_state = NEXTSTATE(TE_OK_ACK1, tep->te_state);
		tl_ok_ack(tep->te_wq, ackmp, T_CONN_REQ);
		tl_closeok(tep);
		dimp = tpi_ack_alloc(mp, sizeof (struct T_discon_ind),
		    M_PROTO, T_DISCON_IND);
		if (dimp == NULL) {
			tl_merror(wq, NULL, ENOSR);
			return;
		}
		di = (struct T_discon_ind *)dimp->b_rptr;
		di->DISCON_reason = err;
		di->SEQ_number = BADSEQNUM;

		tep->te_state = TS_IDLE;
		/*
		 * send T_DISCON_IND message
		 */
		putnext(tep->te_rq, dimp);
		return;
	}

	ASSERT(IS_COTS(peer_tep));

	/*
	 * Found the listener. At this point processing will continue on
	 * listener serializer. Close of the endpoint should be blocked while we
	 * switch serializers.
	 */
	tl_serializer_refhold(peer_tep->te_ser);
	tl_serializer_refrele(tep->te_ser);
	tep->te_ser = peer_tep->te_ser;
	ASSERT(tep->te_oconp == NULL);
	tep->te_oconp = peer_tep;

	/*
	 * It is safe to close now. Close may continue on listener serializer.
	 */
	tl_closeok(tep);

	/*
	 * Pass ackmp to tl_conn_req_ser. Note that mp->b_cont may contain user
	 * data, so we link mp to ackmp.
	 */
	ackmp->b_cont = mp;
	mp = ackmp;

	tl_refhold(tep);
	tl_serializer_enter(tep, tl_conn_req_ser, mp);
}

/*
 * Finish T_CONN_REQ processing on listener serializer.
 */
static void
tl_conn_req_ser(mblk_t *mp, tl_endpt_t *tep)
{
	queue_t		*wq;
	tl_endpt_t	*peer_tep = tep->te_oconp;
	mblk_t		*confmp, *cimp, *indmp;
	void		*opts = NULL;
	mblk_t		*ackmp = mp;
	struct T_conn_req	*creq = (struct T_conn_req *)mp->b_cont->b_rptr;
	struct T_conn_ind	*ci;
	tl_icon_t	*tip;
	void		*addr_startp;
	t_scalar_t	olen = creq->OPT_length;
	t_scalar_t	ooff = creq->OPT_offset;
	size_t 		ci_msz;
	size_t		size;
	cred_t		*cr = NULL;
	pid_t		cpid;

	if (tep->te_closing) {
		TL_UNCONNECT(tep->te_oconp);
		tl_serializer_exit(tep);
		tl_refrele(tep);
		freemsg(mp);
		return;
	}

	wq = tep->te_wq;
	tep->te_flag |= TL_EAGER;

	/*
	 * Extract preallocated ackmp from mp.
	 */
	mp = mp->b_cont;
	ackmp->b_cont = NULL;

	if (olen == 0)
		ooff = 0;

	if (peer_tep->te_closing ||
	    !((peer_tep->te_state == TS_IDLE) ||
	    (peer_tep->te_state == TS_WRES_CIND))) {
		(void) (STRLOG(TL_ID, tep->te_minor, 2, SL_TRACE | SL_ERROR,
		    "tl_conn_req:peer in bad state (%d)",
		    peer_tep->te_state));
		TL_UNCONNECT(tep->te_oconp);
		tl_error_ack(wq, mp, TSYSERR, ECONNREFUSED, T_CONN_REQ);
		freemsg(ackmp);
		tl_serializer_exit(tep);
		tl_refrele(tep);
		return;
	}

	/*
	 * preallocate now for T_DISCON_IND or T_CONN_IND
	 */
	/*
	 * calculate length of T_CONN_IND message
	 */
	if (peer_tep->te_flag & (TL_SETCRED|TL_SETUCRED)) {
		cr = msg_getcred(mp, &cpid);
		ASSERT(cr != NULL);
		if (peer_tep->te_flag & TL_SETCRED) {
			ooff = 0;
			olen = (t_scalar_t) sizeof (struct opthdr) +
			    OPTLEN(sizeof (tl_credopt_t));
			/* 1 option only */
		} else {
			ooff = 0;
			olen = (t_scalar_t)sizeof (struct opthdr) +
			    OPTLEN(ucredminsize(cr));
			/* 1 option only */
		}
	}
	ci_msz = sizeof (struct T_conn_ind) + tep->te_alen;
	ci_msz = T_ALIGN(ci_msz) + olen;
	size = max(ci_msz, sizeof (struct T_discon_ind));

	/*
	 * Save options from mp - we'll need them for T_CONN_IND.
	 */
	if (ooff != 0) {
		opts = kmem_alloc(olen, KM_NOSLEEP);
		if (opts == NULL) {
			/*
			 * roll back state changes
			 */
			tep->te_state = TS_IDLE;
			tl_memrecover(wq, mp, size);
			freemsg(ackmp);
			TL_UNCONNECT(tep->te_oconp);
			tl_serializer_exit(tep);
			tl_refrele(tep);
			return;
		}
		/* Copy options to a temp buffer */
		bcopy(mp->b_rptr + ooff, opts, olen);
	}

	if (IS_SOCKET(tep) && !tl_disable_early_connect) {
		/*
		 * Generate a T_CONN_CON that has the identical address
		 * (and options) as the T_CONN_REQ.
		 * NOTE: assumes that the T_conn_req and T_conn_con structures
		 * are isomorphic.
		 */
		confmp = copyb(mp);
		if (! confmp) {
			/*
			 * roll back state changes
			 */
			tep->te_state = TS_IDLE;
			tl_memrecover(wq, mp, mp->b_wptr - mp->b_rptr);
			freemsg(ackmp);
			if (opts != NULL)
				kmem_free(opts, olen);
			TL_UNCONNECT(tep->te_oconp);
			tl_serializer_exit(tep);
			tl_refrele(tep);
			return;
		}
		((struct T_conn_con *)(confmp->b_rptr))->PRIM_type =
		    T_CONN_CON;
	} else {
		confmp = NULL;
	}
	if ((indmp = reallocb(mp, size, 0)) == NULL) {
		/*
		 * roll back state changes
		 */
		tep->te_state = TS_IDLE;
		tl_memrecover(wq, mp, size);
		freemsg(ackmp);
		if (opts != NULL)
			kmem_free(opts, olen);
		freemsg(confmp);
		TL_UNCONNECT(tep->te_oconp);
		tl_serializer_exit(tep);
		tl_refrele(tep);
		return;
	}

	tip = kmem_zalloc(sizeof (*tip), KM_NOSLEEP);
	if (tip == NULL) {
		/*
		 * roll back state changes
		 */
		tep->te_state = TS_IDLE;
		tl_memrecover(wq, indmp, sizeof (*tip));
		freemsg(ackmp);
		if (opts != NULL)
			kmem_free(opts, olen);
		freemsg(confmp);
		TL_UNCONNECT(tep->te_oconp);
		tl_serializer_exit(tep);
		tl_refrele(tep);
		return;
	}
	tip->ti_mp = NULL;

	/*
	 * memory is now committed for T_DISCON_IND/T_CONN_IND/T_CONN_CON
	 * and tl_icon_t cell.
	 */

	/*
	 * ack validity of request and send the peer credential in the ACK.
	 */
	tep->te_state = NEXTSTATE(TE_OK_ACK1, tep->te_state);

	if (peer_tep != NULL && peer_tep->te_credp != NULL &&
	    confmp != NULL) {
		mblk_setcred(confmp, peer_tep->te_credp, peer_tep->te_cpid);
	}

	tl_ok_ack(wq, ackmp, T_CONN_REQ);

	/*
	 * prepare message to send T_CONN_IND
	 */
	/*
	 * allocate the message - original data blocks retained
	 * in the returned mblk
	 */
	cimp = tl_resizemp(indmp, size);
	if (! cimp) {
		(void) (STRLOG(TL_ID, tep->te_minor, 3, SL_TRACE|SL_ERROR,
		    "tl_conn_req:con_ind:allocb failure"));
		tl_merror(wq, indmp, ENOMEM);
		TL_UNCONNECT(tep->te_oconp);
		tl_serializer_exit(tep);
		tl_refrele(tep);
		if (opts != NULL)
			kmem_free(opts, olen);
		freemsg(confmp);
		ASSERT(tip->ti_mp == NULL);
		kmem_free(tip, sizeof (*tip));
		return;
	}

	DB_TYPE(cimp) = M_PROTO;
	ci = (struct T_conn_ind *)cimp->b_rptr;
	ci->PRIM_type  = T_CONN_IND;
	ci->SRC_offset = (t_scalar_t)sizeof (struct T_conn_ind);
	ci->SRC_length = tep->te_alen;
	ci->SEQ_number = tep->te_seqno;

	addr_startp = cimp->b_rptr + ci->SRC_offset;
	bcopy(tep->te_abuf, addr_startp, tep->te_alen);
	if (peer_tep->te_flag & (TL_SETCRED|TL_SETUCRED)) {

		ci->OPT_offset = (t_scalar_t)T_ALIGN(ci->SRC_offset +
		    ci->SRC_length);
		ci->OPT_length = olen; /* because only 1 option */
		tl_fill_option(cimp->b_rptr + ci->OPT_offset,
		    cr, cpid,
		    peer_tep->te_flag, peer_tep->te_credp);
	} else if (ooff != 0) {
		/* Copy option from T_CONN_REQ */
		ci->OPT_offset = (t_scalar_t)T_ALIGN(ci->SRC_offset +
		    ci->SRC_length);
		ci->OPT_length = olen;
		ASSERT(opts != NULL);
		bcopy(opts, (void *)((uintptr_t)ci + ci->OPT_offset), olen);
	} else {
		ci->OPT_offset = 0;
		ci->OPT_length = 0;
	}
	if (opts != NULL)
		kmem_free(opts, olen);

	/*
	 * register connection request with server peer
	 * append to list of incoming connections
	 * increment references for both peer_tep and tep: peer_tep is placed on
	 * te_oconp and tep is placed on listeners queue.
	 */
	tip->ti_tep = tep;
	tip->ti_seqno = tep->te_seqno;
	list_insert_tail(&peer_tep->te_iconp, tip);
	peer_tep->te_nicon++;

	peer_tep->te_state = NEXTSTATE(TE_CONN_IND, peer_tep->te_state);
	/*
	 * send the T_CONN_IND message
	 */
	putnext(peer_tep->te_rq, cimp);

	/*
	 * Send a T_CONN_CON message for sockets.
	 * Disable the queues until we have reached the correct state!
	 */
	if (confmp != NULL) {
		tep->te_state = NEXTSTATE(TE_CONN_CON, tep->te_state);
		noenable(wq);
		putnext(tep->te_rq, confmp);
	}
	/*
	 * Now we need to increment tep reference because tep is referenced by
	 * server list of pending connections. We also need to decrement
	 * reference before exiting serializer. Two operations void each other
	 * so we don't modify reference at all.
	 */
	ASSERT(tep->te_refcnt >= 2);
	ASSERT(peer_tep->te_refcnt >= 2);
	tl_serializer_exit(tep);
}



/*
 * Handle T_conn_res on listener stream. Called on listener serializer.
 * tl_conn_req has already generated the T_CONN_CON.
 * tl_conn_res is called on listener serializer.
 * No one accesses acceptor at this point, so it is safe to modify acceptor.
 * Switch eager serializer to acceptor's.
 *
 * If TL_SET[U]CRED generate the credentials options.
 * For sockets tl_conn_req has already generated the T_CONN_CON.
 */
static void
tl_conn_res(mblk_t *mp, tl_endpt_t *tep)
{
	queue_t			*wq;
	struct T_conn_res	*cres = (struct T_conn_res *)mp->b_rptr;
	ssize_t			msz = MBLKL(mp);
	t_scalar_t		olen, ooff, err = 0;
	t_scalar_t		prim = cres->PRIM_type;
	uchar_t			*addr_startp;
	tl_endpt_t 		*acc_ep = NULL, *cl_ep = NULL;
	tl_icon_t		*tip;
	size_t			size;
	mblk_t			*ackmp, *respmp;
	mblk_t			*dimp, *ccmp = NULL;
	struct T_discon_ind	*di;
	struct T_conn_con	*cc;
	boolean_t		client_noclose_set = B_FALSE;
	boolean_t		switch_client_serializer = B_TRUE;

	ASSERT(IS_COTS(tep));

	if (tep->te_closing) {
		freemsg(mp);
		return;
	}

	wq = tep->te_wq;

	/*
	 * preallocate memory for:
	 * 1. max of T_ERROR_ACK and T_OK_ACK
	 *	==> known max T_ERROR_ACK
	 * 2. max of T_DISCON_IND and T_CONN_CON
	 */
	ackmp = allocb(sizeof (struct T_error_ack), BPRI_MED);
	if (! ackmp) {
		tl_memrecover(wq, mp, sizeof (struct T_error_ack));
		return;
	}
	/*
	 * memory committed for T_OK_ACK/T_ERROR_ACK now
	 * will be committed for T_DISCON_IND/T_CONN_CON later
	 */


	ASSERT(prim == T_CONN_RES || prim == O_T_CONN_RES);

	/*
	 * validate state
	 */
	if (tep->te_state != TS_WRES_CIND) {
		(void) (STRLOG(TL_ID, tep->te_minor, 1,
		    SL_TRACE|SL_ERROR,
		    "tl_wput:T_CONN_RES:out of state, state=%d",
		    tep->te_state));
		tl_error_ack(wq, ackmp, TOUTSTATE, 0, prim);
		freemsg(mp);
		return;
	}

	/*
	 * validate the message
	 * Note: dereference fields in struct inside message only
	 * after validating the message length.
	 */
	if (msz < sizeof (struct T_conn_res)) {
		(void) (STRLOG(TL_ID, tep->te_minor, 1, SL_TRACE|SL_ERROR,
		    "tl_conn_res:invalid message length"));
		tl_error_ack(wq, ackmp, TSYSERR, EINVAL, prim);
		freemsg(mp);
		return;
	}
	olen = cres->OPT_length;
	ooff = cres->OPT_offset;
	if (((olen > 0) && ((ooff + olen) > msz))) {
		(void) (STRLOG(TL_ID, tep->te_minor, 1, SL_TRACE|SL_ERROR,
		    "tl_conn_res:invalid message"));
		tl_error_ack(wq, ackmp, TSYSERR, EINVAL, prim);
		freemsg(mp);
		return;
	}
	if (olen) {
		/*
		 * no opts in connect res
		 * supported in this provider
		 */
		(void) (STRLOG(TL_ID, tep->te_minor, 1, SL_TRACE|SL_ERROR,
		    "tl_conn_res:options not supported in message"));
		tl_error_ack(wq, ackmp, TBADOPT, 0, prim);
		freemsg(mp);
		return;
	}

	tep->te_state = NEXTSTATE(TE_CONN_RES, tep->te_state);
	ASSERT(tep->te_state == TS_WACK_CRES);

	if (cres->SEQ_number < TL_MINOR_START &&
	    cres->SEQ_number >= BADSEQNUM) {
		(void) (STRLOG(TL_ID, tep->te_minor, 2, SL_TRACE|SL_ERROR,
		    "tl_conn_res:remote endpoint sequence number bad"));
		tep->te_state = NEXTSTATE(TE_ERROR_ACK, tep->te_state);
		tl_error_ack(wq, ackmp, TBADSEQ, 0, prim);
		freemsg(mp);
		return;
	}

	/*
	 * find accepting endpoint. Will have extra reference if found.
	 */
	if (mod_hash_find_cb(tep->te_transport->tr_ai_hash,
	    (mod_hash_key_t)(uintptr_t)cres->ACCEPTOR_id,
	    (mod_hash_val_t *)&acc_ep, tl_find_callback) != 0) {
		(void) (STRLOG(TL_ID, tep->te_minor, 2, SL_TRACE|SL_ERROR,
		    "tl_conn_res:bad accepting endpoint"));
		tep->te_state = NEXTSTATE(TE_ERROR_ACK, tep->te_state);
		tl_error_ack(wq, ackmp, TBADF, 0, prim);
		freemsg(mp);
		return;
	}

	/*
	 * Prevent acceptor from closing.
	 */
	if (! tl_noclose(acc_ep)) {
		(void) (STRLOG(TL_ID, tep->te_minor, 2, SL_TRACE|SL_ERROR,
		    "tl_conn_res:bad accepting endpoint"));
		tep->te_state = NEXTSTATE(TE_ERROR_ACK, tep->te_state);
		tl_error_ack(wq, ackmp, TBADF, 0, prim);
		tl_refrele(acc_ep);
		freemsg(mp);
		return;
	}

	acc_ep->te_flag |= TL_ACCEPTOR;

	/*
	 * validate that accepting endpoint, if different from listening
	 * has address bound => state is TS_IDLE
	 * TROUBLE in XPG4 !!?
	 */
	if ((tep != acc_ep) && (acc_ep->te_state != TS_IDLE)) {
		(void) (STRLOG(TL_ID, tep->te_minor, 2, SL_TRACE|SL_ERROR,
		    "tl_conn_res:accepting endpoint has no address bound,"
		    "state=%d", acc_ep->te_state));
		tep->te_state = NEXTSTATE(TE_ERROR_ACK, tep->te_state);
		tl_error_ack(wq, ackmp, TOUTSTATE, 0, prim);
		freemsg(mp);
		tl_closeok(acc_ep);
		tl_refrele(acc_ep);
		return;
	}

	/*
	 * validate if accepting endpt same as listening, then
	 * no other incoming connection should be on the queue
	 */

	if ((tep == acc_ep) && (tep->te_nicon > 1)) {
		(void) (STRLOG(TL_ID, tep->te_minor, 3, SL_TRACE|SL_ERROR,
		    "tl_conn_res: > 1 conn_ind on listener-acceptor"));
		tep->te_state = NEXTSTATE(TE_ERROR_ACK, tep->te_state);
		tl_error_ack(wq, ackmp, TBADF, 0, prim);
		freemsg(mp);
		tl_closeok(acc_ep);
		tl_refrele(acc_ep);
		return;
	}

	/*
	 * Mark for deletion, the entry corresponding to client
	 * on list of pending connections made by the listener
	 *  search list to see if client is one of the
	 * recorded as a listener.
	 */
	tip = tl_icon_find(tep, cres->SEQ_number);
	if (tip == NULL) {
		(void) (STRLOG(TL_ID, tep->te_minor, 2, SL_TRACE|SL_ERROR,
		    "tl_conn_res:no client in listener list"));
		tep->te_state = NEXTSTATE(TE_ERROR_ACK, tep->te_state);
		tl_error_ack(wq, ackmp, TBADSEQ, 0, prim);
		freemsg(mp);
		tl_closeok(acc_ep);
		tl_refrele(acc_ep);
		return;
	}

	/*
	 * If ti_tep is NULL the client has already closed. In this case
	 * the code below will avoid any action on the client side
	 * but complete the server and acceptor state transitions.
	 */
	ASSERT(tip->ti_tep == NULL ||
	    tip->ti_tep->te_seqno == cres->SEQ_number);
	cl_ep = tip->ti_tep;

	/*
	 * If the client is present it is switched from listener's to acceptor's
	 * serializer. We should block client closes while serializers are
	 * being switched.
	 *
	 * It is possible that the client is present but is currently being
	 * closed. There are two possible cases:
	 *
	 * 1) The client has already entered tl_close_finish_ser() and sent
	 *    T_ORDREL_IND. In this case we can just ignore the client (but we
	 *    still need to send all messages from tip->ti_mp to the acceptor).
	 *
	 * 2) The client started the close but has not entered
	 *    tl_close_finish_ser() yet. In this case, the client is already
	 *    proceeding asynchronously on the listener's serializer, so we're
	 *    forced to change the acceptor to use the listener's serializer to
	 *    ensure that any operations on the acceptor are serialized with
	 *    respect to the close that's in-progress.
	 */
	if (cl_ep != NULL) {
		if (tl_noclose(cl_ep)) {
			client_noclose_set = B_TRUE;
		} else {
			/*
			 * Client is closing. If it it has sent the
			 * T_ORDREL_IND, we can simply ignore it - otherwise,
			 * we have to let let the client continue until it is
			 * sent.
			 *
			 * If we do continue using the client, acceptor will
			 * switch to client's serializer which is used by client
			 * for its close.
			 */
			tl_client_closing_when_accepting++;
			switch_client_serializer = B_FALSE;
			if (!IS_SOCKET(cl_ep) || tl_disable_early_connect ||
			    cl_ep->te_state == -1)
				cl_ep = NULL;
		}
	}

	if (cl_ep != NULL) {
		/*
		 * validate client state to be TS_WCON_CREQ or TS_DATA_XFER
		 * (latter for sockets only)
		 */
		if (cl_ep->te_state != TS_WCON_CREQ &&
		    (cl_ep->te_state != TS_DATA_XFER &&
		    IS_SOCKET(cl_ep))) {
			err = ECONNREFUSED;
			/*
			 * T_DISCON_IND sent later after committing memory
			 * and acking validity of request
			 */
			(void) (STRLOG(TL_ID, tep->te_minor, 2, SL_TRACE,
			    "tl_conn_res:peer in bad state"));
		}

		/*
		 * preallocate now for T_DISCON_IND or T_CONN_CONN
		 * ack validity of request (T_OK_ACK) after memory committed
		 */

		if (err)
			size = sizeof (struct T_discon_ind);
		else {
			/*
			 * calculate length of T_CONN_CON message
			 */
			olen = 0;
			if (cl_ep->te_flag & TL_SETCRED) {
				olen = (t_scalar_t)sizeof (struct opthdr) +
				    OPTLEN(sizeof (tl_credopt_t));
			} else if (cl_ep->te_flag & TL_SETUCRED) {
				olen = (t_scalar_t)sizeof (struct opthdr) +
				    OPTLEN(ucredminsize(acc_ep->te_credp));
			}
			size = T_ALIGN(sizeof (struct T_conn_con) +
			    acc_ep->te_alen) + olen;
		}
		if ((respmp = reallocb(mp, size, 0)) == NULL) {
			/*
			 * roll back state changes
			 */
			tep->te_state = TS_WRES_CIND;
			tl_memrecover(wq, mp, size);
			freemsg(ackmp);
			if (client_noclose_set)
				tl_closeok(cl_ep);
			tl_closeok(acc_ep);
			tl_refrele(acc_ep);
			return;
		}
		mp = NULL;
	}

	/*
	 * Now ack validity of request
	 */
	if (tep->te_nicon == 1) {
		if (tep == acc_ep)
			tep->te_state = NEXTSTATE(TE_OK_ACK2, tep->te_state);
		else
			tep->te_state = NEXTSTATE(TE_OK_ACK3, tep->te_state);
	} else
		tep->te_state = NEXTSTATE(TE_OK_ACK4, tep->te_state);

	/*
	 * send T_DISCON_IND now if client state validation failed earlier
	 */
	if (err) {
		tl_ok_ack(wq, ackmp, prim);
		/*
		 * flush the queues - why always ?
		 */
		(void) putnextctl1(acc_ep->te_rq, M_FLUSH, FLUSHR);

		dimp = tl_resizemp(respmp, size);
		if (! dimp) {
			(void) (STRLOG(TL_ID, tep->te_minor, 3,
			    SL_TRACE|SL_ERROR,
			    "tl_conn_res:con_ind:allocb failure"));
			tl_merror(wq, respmp, ENOMEM);
			tl_closeok(acc_ep);
			if (client_noclose_set)
				tl_closeok(cl_ep);
			tl_refrele(acc_ep);
			return;
		}
		if (dimp->b_cont) {
			/* no user data in provider generated discon ind */
			freemsg(dimp->b_cont);
			dimp->b_cont = NULL;
		}

		DB_TYPE(dimp) = M_PROTO;
		di = (struct T_discon_ind *)dimp->b_rptr;
		di->PRIM_type  = T_DISCON_IND;
		di->DISCON_reason = err;
		di->SEQ_number = BADSEQNUM;

		tep->te_state = TS_IDLE;
		/*
		 * send T_DISCON_IND message
		 */
		putnext(acc_ep->te_rq, dimp);
		if (client_noclose_set)
			tl_closeok(cl_ep);
		tl_closeok(acc_ep);
		tl_refrele(acc_ep);
		return;
	}

	/*
	 * now start connecting the accepting endpoint
	 */
	if (tep != acc_ep)
		acc_ep->te_state = NEXTSTATE(TE_PASS_CONN, acc_ep->te_state);

	if (cl_ep == NULL) {
		/*
		 * The client has already closed. Send up any queued messages
		 * and change the state accordingly.
		 */
		tl_ok_ack(wq, ackmp, prim);
		tl_icon_sendmsgs(acc_ep, &tip->ti_mp);

		/*
		 * remove endpoint from incoming connection
		 * delete client from list of incoming connections
		 */
		tl_freetip(tep, tip);
		freemsg(mp);
		tl_closeok(acc_ep);
		tl_refrele(acc_ep);
		return;
	} else if (tip->ti_mp != NULL) {
		/*
		 * The client could have queued a T_DISCON_IND which needs
		 * to be sent up.
		 * Note that t_discon_req can not operate the same as
		 * t_data_req since it is not possible for it to putbq
		 * the message and return -1 due to the use of qwriter.
		 */
		tl_icon_sendmsgs(acc_ep, &tip->ti_mp);
	}

	/*
	 * prepare connect confirm T_CONN_CON message
	 */

	/*
	 * allocate the message - original data blocks
	 * retained in the returned mblk
	 */
	if (! IS_SOCKET(cl_ep) || tl_disable_early_connect) {
		ccmp = tl_resizemp(respmp, size);
		if (ccmp == NULL) {
			tl_ok_ack(wq, ackmp, prim);
			(void) (STRLOG(TL_ID, tep->te_minor, 3,
			    SL_TRACE|SL_ERROR,
			    "tl_conn_res:conn_con:allocb failure"));
			tl_merror(wq, respmp, ENOMEM);
			tl_closeok(acc_ep);
			if (client_noclose_set)
				tl_closeok(cl_ep);
			tl_refrele(acc_ep);
			return;
		}

		DB_TYPE(ccmp) = M_PROTO;
		cc = (struct T_conn_con *)ccmp->b_rptr;
		cc->PRIM_type  = T_CONN_CON;
		cc->RES_offset = (t_scalar_t)sizeof (struct T_conn_con);
		cc->RES_length = acc_ep->te_alen;
		addr_startp = ccmp->b_rptr + cc->RES_offset;
		bcopy(acc_ep->te_abuf, addr_startp, acc_ep->te_alen);
		if (cl_ep->te_flag & (TL_SETCRED|TL_SETUCRED)) {
			cc->OPT_offset = (t_scalar_t)T_ALIGN(cc->RES_offset +
			    cc->RES_length);
			cc->OPT_length = olen;
			tl_fill_option(ccmp->b_rptr + cc->OPT_offset,
			    acc_ep->te_credp, acc_ep->te_cpid, cl_ep->te_flag,
			    cl_ep->te_credp);
		} else {
			cc->OPT_offset = 0;
			cc->OPT_length = 0;
		}
		/*
		 * Forward the credential in the packet so it can be picked up
		 * at the higher layers for more complete credential processing
		 */
		mblk_setcred(ccmp, acc_ep->te_credp, acc_ep->te_cpid);
	} else {
		freemsg(respmp);
		respmp = NULL;
	}

	/*
	 * make connection linking
	 * accepting and client endpoints
	 * No need to increment references:
	 *	on client: it should already have one from tip->ti_tep linkage.
	 *	on acceptor is should already have one from the table lookup.
	 *
	 * At this point both client and acceptor can't close. Set client
	 * serializer to acceptor's.
	 */
	ASSERT(cl_ep->te_refcnt >= 2);
	ASSERT(acc_ep->te_refcnt >= 2);
	ASSERT(cl_ep->te_conp == NULL);
	ASSERT(acc_ep->te_conp == NULL);
	cl_ep->te_conp = acc_ep;
	acc_ep->te_conp = cl_ep;
	ASSERT(cl_ep->te_ser == tep->te_ser);
	if (switch_client_serializer) {
		mutex_enter(&cl_ep->te_ser_lock);
		if (cl_ep->te_ser_count > 0) {
			switch_client_serializer = B_FALSE;
			tl_serializer_noswitch++;
		} else {
			/*
			 * Move client to the acceptor's serializer.
			 */
			tl_serializer_refhold(acc_ep->te_ser);
			tl_serializer_refrele(cl_ep->te_ser);
			cl_ep->te_ser = acc_ep->te_ser;
		}
		mutex_exit(&cl_ep->te_ser_lock);
	}
	if (!switch_client_serializer) {
		/*
		 * It is not possible to switch client to use acceptor's.
		 * Move acceptor to client's serializer (which is the same as
		 * listener's).
		 */
		tl_serializer_refhold(cl_ep->te_ser);
		tl_serializer_refrele(acc_ep->te_ser);
		acc_ep->te_ser = cl_ep->te_ser;
	}

	TL_REMOVE_PEER(cl_ep->te_oconp);
	TL_REMOVE_PEER(acc_ep->te_oconp);

	/*
	 * remove endpoint from incoming connection
	 * delete client from list of incoming connections
	 */
	tip->ti_tep = NULL;
	tl_freetip(tep, tip);
	tl_ok_ack(wq, ackmp, prim);

	/*
	 * data blocks already linked in reallocb()
	 */

	/*
	 * link queues so that I_SENDFD will work
	 */
	if (! IS_SOCKET(tep)) {
		acc_ep->te_wq->q_next = cl_ep->te_rq;
		cl_ep->te_wq->q_next = acc_ep->te_rq;
	}

	/*
	 * send T_CONN_CON up on client side unless it was already
	 * done (for a socket). In cases any data or ordrel req has been
	 * queued make sure that the service procedure runs.
	 */
	if (IS_SOCKET(cl_ep) && !tl_disable_early_connect) {
		enableok(cl_ep->te_wq);
		TL_QENABLE(cl_ep);
		if (ccmp != NULL)
			freemsg(ccmp);
	} else {
		/*
		 * change client state on TE_CONN_CON event
		 */
		cl_ep->te_state = NEXTSTATE(TE_CONN_CON, cl_ep->te_state);
		putnext(cl_ep->te_rq, ccmp);
	}

	/* Mark the both endpoints as accepted */
	cl_ep->te_flag |= TL_ACCEPTED;
	acc_ep->te_flag |= TL_ACCEPTED;

	/*
	 * Allow client and acceptor to close.
	 */
	tl_closeok(acc_ep);
	if (client_noclose_set)
		tl_closeok(cl_ep);
}




static void
tl_discon_req(mblk_t *mp, tl_endpt_t *tep)
{
	queue_t			*wq;
	struct T_discon_req	*dr;
	ssize_t			msz;
	tl_endpt_t		*peer_tep = tep->te_conp;
	tl_endpt_t		*srv_tep = tep->te_oconp;
	tl_icon_t		*tip;
	size_t			size;
	mblk_t			*ackmp, *dimp, *respmp;
	struct T_discon_ind	*di;
	t_scalar_t		save_state, new_state;

	if (tep->te_closing) {
		freemsg(mp);
		return;
	}

	if ((peer_tep != NULL) && peer_tep->te_closing) {
		TL_UNCONNECT(tep->te_conp);
		peer_tep = NULL;
	}
	if ((srv_tep != NULL) && srv_tep->te_closing) {
		TL_UNCONNECT(tep->te_oconp);
		srv_tep = NULL;
	}

	wq = tep->te_wq;

	/*
	 * preallocate memory for:
	 * 1. max of T_ERROR_ACK and T_OK_ACK
	 *	==> known max T_ERROR_ACK
	 * 2. for  T_DISCON_IND
	 */
	ackmp = allocb(sizeof (struct T_error_ack), BPRI_MED);
	if (! ackmp) {
		tl_memrecover(wq, mp, sizeof (struct T_error_ack));
		return;
	}
	/*
	 * memory committed for T_OK_ACK/T_ERROR_ACK now
	 * will be committed for T_DISCON_IND  later
	 */

	dr = (struct T_discon_req *)mp->b_rptr;
	msz = MBLKL(mp);

	/*
	 * validate the state
	 */
	save_state = new_state = tep->te_state;
	if (! (save_state >= TS_WCON_CREQ && save_state <= TS_WRES_CIND) &&
	    ! (save_state >= TS_DATA_XFER && save_state <= TS_WREQ_ORDREL)) {
		(void) (STRLOG(TL_ID, tep->te_minor, 1,
		    SL_TRACE|SL_ERROR,
		    "tl_wput:T_DISCON_REQ:out of state, state=%d",
		    tep->te_state));
		tl_error_ack(wq, ackmp, TOUTSTATE, 0, T_DISCON_REQ);
		freemsg(mp);
		return;
	}
	/*
	 * Defer committing the state change until it is determined if
	 * the message will be queued with the tl_icon or not.
	 */
	new_state  = NEXTSTATE(TE_DISCON_REQ, tep->te_state);

	/* validate the message */
	if (msz < sizeof (struct T_discon_req)) {
		(void) (STRLOG(TL_ID, tep->te_minor, 1, SL_TRACE|SL_ERROR,
		    "tl_discon_req:invalid message"));
		tep->te_state = NEXTSTATE(TE_ERROR_ACK, new_state);
		tl_error_ack(wq, ackmp, TSYSERR, EINVAL, T_DISCON_REQ);
		freemsg(mp);
		return;
	}

	/*
	 * if server, then validate that client exists
	 * by connection sequence number etc.
	 */
	if (tep->te_nicon > 0) { /* server */

		/*
		 * search server list for disconnect client
		 */
		tip = tl_icon_find(tep, dr->SEQ_number);
		if (tip == NULL) {
			(void) (STRLOG(TL_ID, tep->te_minor, 2,
			    SL_TRACE|SL_ERROR,
			    "tl_discon_req:no disconnect endpoint"));
			tep->te_state = NEXTSTATE(TE_ERROR_ACK, new_state);
			tl_error_ack(wq, ackmp, TBADSEQ, 0, T_DISCON_REQ);
			freemsg(mp);
			return;
		}
		/*
		 * If ti_tep is NULL the client has already closed. In this case
		 * the code below will avoid any action on the client side.
		 */

		IMPLY(tip->ti_tep != NULL,
		    tip->ti_tep->te_seqno == dr->SEQ_number);
		peer_tep = tip->ti_tep;
	}

	/*
	 * preallocate now for T_DISCON_IND
	 * ack validity of request (T_OK_ACK) after memory committed
	 */
	size = sizeof (struct T_discon_ind);
	if ((respmp = reallocb(mp, size, 0)) == NULL) {
		tl_memrecover(wq, mp, size);
		freemsg(ackmp);
		return;
	}

	/*
	 * prepare message to ack validity of request
	 */
	if (tep->te_nicon == 0)
		new_state = NEXTSTATE(TE_OK_ACK1, new_state);
	else
		if (tep->te_nicon == 1)
			new_state = NEXTSTATE(TE_OK_ACK2, new_state);
		else
			new_state = NEXTSTATE(TE_OK_ACK4, new_state);

	/*
	 * Flushing queues according to TPI. Using the old state.
	 */
	if ((tep->te_nicon <= 1) &&
	    ((save_state == TS_DATA_XFER) ||
	    (save_state == TS_WIND_ORDREL) ||
	    (save_state == TS_WREQ_ORDREL)))
		(void) putnextctl1(RD(wq), M_FLUSH, FLUSHRW);

	/* send T_OK_ACK up  */
	tl_ok_ack(wq, ackmp, T_DISCON_REQ);

	/*
	 * now do disconnect business
	 */
	if (tep->te_nicon > 0) { /* listener */
		if (peer_tep != NULL && !peer_tep->te_closing) {
			/*
			 * disconnect incoming connect request pending to tep
			 */
			if ((dimp = tl_resizemp(respmp, size)) == NULL) {
				(void) (STRLOG(TL_ID, tep->te_minor, 2,
				    SL_TRACE|SL_ERROR,
				    "tl_discon_req: reallocb failed"));
				tep->te_state = new_state;
				tl_merror(wq, respmp, ENOMEM);
				return;
			}
			di = (struct T_discon_ind *)dimp->b_rptr;
			di->SEQ_number = BADSEQNUM;
			save_state = peer_tep->te_state;
			peer_tep->te_state = TS_IDLE;

			TL_REMOVE_PEER(peer_tep->te_oconp);
			enableok(peer_tep->te_wq);
			TL_QENABLE(peer_tep);
		} else {
			freemsg(respmp);
			dimp = NULL;
		}

		/*
		 * remove endpoint from incoming connection list
		 * - remove disconnect client from list on server
		 */
		tl_freetip(tep, tip);
	} else if ((peer_tep = tep->te_oconp) != NULL) { /* client */
		/*
		 * disconnect an outgoing request pending from tep
		 */

		if ((dimp = tl_resizemp(respmp, size)) == NULL) {
			(void) (STRLOG(TL_ID, tep->te_minor, 2,
			    SL_TRACE|SL_ERROR,
			    "tl_discon_req: reallocb failed"));
			tep->te_state = new_state;
			tl_merror(wq, respmp, ENOMEM);
			return;
		}
		di = (struct T_discon_ind *)dimp->b_rptr;
		DB_TYPE(dimp) = M_PROTO;
		di->PRIM_type  = T_DISCON_IND;
		di->DISCON_reason = ECONNRESET;
		di->SEQ_number = tep->te_seqno;

		/*
		 * If this is a socket the T_DISCON_IND is queued with
		 * the T_CONN_IND. Otherwise the T_CONN_IND is removed
		 * from the list of pending connections.
		 * Note that when te_oconp is set the peer better have
		 * a t_connind_t for the client.
		 */
		if (IS_SOCKET(tep) && !tl_disable_early_connect) {
			/*
			 * No need to check that
			 * ti_tep == NULL since the T_DISCON_IND
			 * takes precedence over other queued
			 * messages.
			 */
			tl_icon_queuemsg(peer_tep, tep->te_seqno, dimp);
			peer_tep = NULL;
			dimp = NULL;
			/*
			 * Can't clear te_oconp since tl_co_unconnect needs
			 * it as a hint not to free the tep.
			 * Keep the state unchanged since tl_conn_res inspects
			 * it.
			 */
			new_state = tep->te_state;
		} else {
			/* Found - delete it */
			tip = tl_icon_find(peer_tep, tep->te_seqno);
			if (tip != NULL) {
				ASSERT(tep == tip->ti_tep);
				save_state = peer_tep->te_state;
				if (peer_tep->te_nicon == 1)
					peer_tep->te_state =
					    NEXTSTATE(TE_DISCON_IND2,
					    peer_tep->te_state);
				else
					peer_tep->te_state =
					    NEXTSTATE(TE_DISCON_IND3,
					    peer_tep->te_state);
				tl_freetip(peer_tep, tip);
			}
			ASSERT(tep->te_oconp != NULL);
			TL_UNCONNECT(tep->te_oconp);
		}
	} else if ((peer_tep = tep->te_conp) != NULL) { /* connected! */
		if ((dimp = tl_resizemp(respmp, size)) == NULL) {
			(void) (STRLOG(TL_ID, tep->te_minor, 2,
			    SL_TRACE|SL_ERROR,
			    "tl_discon_req: reallocb failed"));
			tep->te_state = new_state;
			tl_merror(wq, respmp, ENOMEM);
			return;
		}
		di = (struct T_discon_ind *)dimp->b_rptr;
		di->SEQ_number = BADSEQNUM;

		save_state = peer_tep->te_state;
		peer_tep->te_state = TS_IDLE;
	} else {
		/* Not connected */
		tep->te_state = new_state;
		freemsg(respmp);
		return;
	}

	/* Commit state changes */
	tep->te_state = new_state;

	if (peer_tep == NULL) {
		ASSERT(dimp == NULL);
		goto done;
	}
	/*
	 * Flush queues on peer before sending up
	 * T_DISCON_IND according to TPI
	 */

	if ((save_state == TS_DATA_XFER) ||
	    (save_state == TS_WIND_ORDREL) ||
	    (save_state == TS_WREQ_ORDREL))
		(void) putnextctl1(peer_tep->te_rq, M_FLUSH, FLUSHRW);

	DB_TYPE(dimp) = M_PROTO;
	di->PRIM_type  = T_DISCON_IND;
	di->DISCON_reason = ECONNRESET;

	/*
	 * data blocks already linked into dimp by reallocb()
	 */
	/*
	 * send indication message to peer user module
	 */
	ASSERT(dimp != NULL);
	putnext(peer_tep->te_rq, dimp);
done:
	if (tep->te_conp) {	/* disconnect pointers if connected */
		ASSERT(! peer_tep->te_closing);

		/*
		 * Messages may be queued on peer's write queue
		 * waiting to be processed by its write service
		 * procedure. Before the pointer to the peer transport
		 * structure is set to NULL, qenable the peer's write
		 * queue so that the queued up messages are processed.
		 */
		if ((save_state == TS_DATA_XFER) ||
		    (save_state == TS_WIND_ORDREL) ||
		    (save_state == TS_WREQ_ORDREL))
			TL_QENABLE(peer_tep);
		ASSERT(peer_tep != NULL && peer_tep->te_conp != NULL);
		TL_UNCONNECT(peer_tep->te_conp);
		if (! IS_SOCKET(tep)) {
			/*
			 * unlink the streams
			 */
			tep->te_wq->q_next = NULL;
			peer_tep->te_wq->q_next = NULL;
		}
		TL_UNCONNECT(tep->te_conp);
	}
}

static void
tl_addr_req_ser(mblk_t *mp, tl_endpt_t *tep)
{
	if (!tep->te_closing)
		tl_addr_req(mp, tep);
	else
		freemsg(mp);

	tl_serializer_exit(tep);
	tl_refrele(tep);
}

static void
tl_addr_req(mblk_t *mp, tl_endpt_t *tep)
{
	queue_t			*wq;
	size_t			ack_sz;
	mblk_t			*ackmp;
	struct T_addr_ack	*taa;

	if (tep->te_closing) {
		freemsg(mp);
		return;
	}

	wq = tep->te_wq;

	/*
	 * Note: T_ADDR_REQ message has only PRIM_type field
	 * so it is already validated earlier.
	 */

	if (IS_CLTS(tep) ||
	    (tep->te_state > TS_WREQ_ORDREL) ||
	    (tep->te_state < TS_DATA_XFER)) {
		/*
		 * Either connectionless or connection oriented but not
		 * in connected data transfer state or half-closed states.
		 */
		ack_sz = sizeof (struct T_addr_ack);
		if (tep->te_state >= TS_IDLE)
			/* is bound */
			ack_sz += tep->te_alen;
		ackmp = reallocb(mp, ack_sz, 0);
		if (ackmp == NULL) {
			(void) (STRLOG(TL_ID, tep->te_minor, 1,
			    SL_TRACE|SL_ERROR,
			    "tl_addr_req: reallocb failed"));
			tl_memrecover(wq, mp, ack_sz);
			return;
		}

		taa = (struct T_addr_ack *)ackmp->b_rptr;

		bzero(taa, sizeof (struct T_addr_ack));

		taa->PRIM_type = T_ADDR_ACK;
		ackmp->b_datap->db_type = M_PCPROTO;
		ackmp->b_wptr = (uchar_t *)&taa[1];

		if (tep->te_state >= TS_IDLE) {
			/* endpoint is bound */
			taa->LOCADDR_length = tep->te_alen;
			taa->LOCADDR_offset = (t_scalar_t)sizeof (*taa);

			bcopy(tep->te_abuf, ackmp->b_wptr,
			    tep->te_alen);
			ackmp->b_wptr += tep->te_alen;
			ASSERT(ackmp->b_wptr <= ackmp->b_datap->db_lim);
		}

		(void) qreply(wq, ackmp);
	} else {
		ASSERT(tep->te_state == TS_DATA_XFER ||
		    tep->te_state == TS_WIND_ORDREL ||
		    tep->te_state == TS_WREQ_ORDREL);
		/* connection oriented in data transfer */
		tl_connected_cots_addr_req(mp, tep);
	}
}


static void
tl_connected_cots_addr_req(mblk_t *mp, tl_endpt_t *tep)
{
	tl_endpt_t		*peer_tep = tep->te_conp;
	size_t			ack_sz;
	mblk_t			*ackmp;
	struct T_addr_ack	*taa;
	uchar_t			*addr_startp;

	if (tep->te_closing) {
		freemsg(mp);
		return;
	}

	if (peer_tep == NULL || peer_tep->te_closing) {
		tl_error_ack(tep->te_wq, mp, TSYSERR, ECONNRESET, T_ADDR_REQ);
		return;
	}

	ASSERT(tep->te_state >= TS_IDLE);

	ack_sz = sizeof (struct T_addr_ack);
	ack_sz += T_ALIGN(tep->te_alen);
	ack_sz += peer_tep->te_alen;

	ackmp = tpi_ack_alloc(mp, ack_sz, M_PCPROTO, T_ADDR_ACK);
	if (ackmp == NULL) {
		(void) (STRLOG(TL_ID, tep->te_minor, 1, SL_TRACE|SL_ERROR,
		    "tl_connected_cots_addr_req: reallocb failed"));
		tl_memrecover(tep->te_wq, mp, ack_sz);
		return;
	}

	taa = (struct T_addr_ack *)ackmp->b_rptr;

	/* endpoint is bound */
	taa->LOCADDR_length = tep->te_alen;
	taa->LOCADDR_offset = (t_scalar_t)sizeof (*taa);

	addr_startp = (uchar_t *)&taa[1];

	bcopy(tep->te_abuf, addr_startp,
	    tep->te_alen);

	taa->REMADDR_length = peer_tep->te_alen;
	taa->REMADDR_offset = (t_scalar_t)T_ALIGN(taa->LOCADDR_offset +
	    taa->LOCADDR_length);
	addr_startp = ackmp->b_rptr + taa->REMADDR_offset;
	bcopy(peer_tep->te_abuf, addr_startp,
	    peer_tep->te_alen);
	ackmp->b_wptr = (uchar_t *)ackmp->b_rptr +
	    taa->REMADDR_offset + peer_tep->te_alen;
	ASSERT(ackmp->b_wptr <= ackmp->b_datap->db_lim);

	putnext(tep->te_rq, ackmp);
}

static void
tl_copy_info(struct T_info_ack *ia, tl_endpt_t *tep)
{
	if (IS_CLTS(tep)) {
		*ia = tl_clts_info_ack;
		ia->TSDU_size = tl_tidusz; /* TSDU and TIDU size are same */
	} else {
		*ia = tl_cots_info_ack;
		if (IS_COTSORD(tep))
			ia->SERV_type = T_COTS_ORD;
	}
	ia->TIDU_size = tl_tidusz;
	ia->CURRENT_state = tep->te_state;
}

/*
 * This routine responds to T_CAPABILITY_REQ messages.  It is called by
 * tl_wput.
 */
static void
tl_capability_req(mblk_t *mp, tl_endpt_t *tep)
{
	mblk_t			*ackmp;
	t_uscalar_t		cap_bits1;
	struct T_capability_ack	*tcap;

	if (tep->te_closing) {
		freemsg(mp);
		return;
	}

	cap_bits1 = ((struct T_capability_req *)mp->b_rptr)->CAP_bits1;

	ackmp = tpi_ack_alloc(mp, sizeof (struct T_capability_ack),
	    M_PCPROTO, T_CAPABILITY_ACK);
	if (ackmp == NULL) {
		(void) (STRLOG(TL_ID, tep->te_minor, 1, SL_TRACE|SL_ERROR,
		    "tl_capability_req: reallocb failed"));
		tl_memrecover(tep->te_wq, mp,
		    sizeof (struct T_capability_ack));
		return;
	}

	tcap = (struct T_capability_ack *)ackmp->b_rptr;
	tcap->CAP_bits1 = 0;

	if (cap_bits1 & TC1_INFO) {
		tl_copy_info(&tcap->INFO_ack, tep);
		tcap->CAP_bits1 |= TC1_INFO;
	}

	if (cap_bits1 & TC1_ACCEPTOR_ID) {
		tcap->ACCEPTOR_id = tep->te_acceptor_id;
		tcap->CAP_bits1 |= TC1_ACCEPTOR_ID;
	}

	putnext(tep->te_rq, ackmp);
}

static void
tl_info_req_ser(mblk_t *mp, tl_endpt_t *tep)
{
	if (! tep->te_closing)
		tl_info_req(mp, tep);
	else
		freemsg(mp);

	tl_serializer_exit(tep);
	tl_refrele(tep);
}

static void
tl_info_req(mblk_t *mp, tl_endpt_t *tep)
{
	mblk_t *ackmp;

	ackmp = tpi_ack_alloc(mp, sizeof (struct T_info_ack),
	    M_PCPROTO, T_INFO_ACK);
	if (ackmp == NULL) {
		(void) (STRLOG(TL_ID, tep->te_minor, 1, SL_TRACE|SL_ERROR,
		    "tl_info_req: reallocb failed"));
		tl_memrecover(tep->te_wq, mp, sizeof (struct T_info_ack));
		return;
	}

	/*
	 * fill in T_INFO_ACK contents
	 */
	tl_copy_info((struct T_info_ack *)ackmp->b_rptr, tep);

	/*
	 * send ack message
	 */
	putnext(tep->te_rq, ackmp);
}

/*
 * Handle M_DATA, T_data_req and T_optdata_req.
 * If this is a socket pass through T_optdata_req options unmodified.
 */
static void
tl_data(mblk_t *mp, tl_endpt_t *tep)
{
	queue_t			*wq = tep->te_wq;
	union T_primitives	*prim = (union T_primitives *)mp->b_rptr;
	ssize_t			msz = MBLKL(mp);
	tl_endpt_t		*peer_tep;
	queue_t			*peer_rq;
	boolean_t		closing = tep->te_closing;

	if (IS_CLTS(tep)) {
		(void) (STRLOG(TL_ID, tep->te_minor, 2,
		    SL_TRACE|SL_ERROR,
		    "tl_wput:clts:unattached M_DATA"));
		if (!closing) {
			tl_merror(wq, mp, EPROTO);
		} else {
			freemsg(mp);
		}
		return;
	}

	/*
	 * If the endpoint is closing it should still forward any data to the
	 * peer (if it has one). If it is not allowed to forward it can just
	 * free the message.
	 */
	if (closing &&
	    (tep->te_state != TS_DATA_XFER) &&
	    (tep->te_state != TS_WREQ_ORDREL)) {
		freemsg(mp);
		return;
	}

	if (DB_TYPE(mp) == M_PROTO) {
		if (prim->type == T_DATA_REQ &&
		    msz < sizeof (struct T_data_req)) {
			(void) (STRLOG(TL_ID, tep->te_minor, 1,
				SL_TRACE|SL_ERROR,
				"tl_data:T_DATA_REQ:invalid message"));
			if (!closing) {
				tl_merror(wq, mp, EPROTO);
			} else {
				freemsg(mp);
			}
			return;
		} else if (prim->type == T_OPTDATA_REQ &&
		    (msz < sizeof (struct T_optdata_req) || !IS_SOCKET(tep))) {
			(void) (STRLOG(TL_ID, tep->te_minor, 1,
			    SL_TRACE|SL_ERROR,
			    "tl_data:T_OPTDATA_REQ:invalid message"));
			if (!closing) {
				tl_merror(wq, mp, EPROTO);
			} else {
				freemsg(mp);
			}
			return;
		}
	}

	/*
	 * connection oriented provider
	 */
	switch (tep->te_state) {
	case TS_IDLE:
		/*
		 * Other end not here - do nothing.
		 */
		freemsg(mp);
		(void) (STRLOG(TL_ID, tep->te_minor, 3, SL_TRACE|SL_ERROR,
		    "tl_data:cots with endpoint idle"));
		return;

	case TS_DATA_XFER:
		/* valid states */
		if (tep->te_conp != NULL)
			break;

		if (tep->te_oconp == NULL) {
			if (!closing) {
				tl_merror(wq, mp, EPROTO);
			} else {
				freemsg(mp);
			}
			return;
		}
		/*
		 * For a socket the T_CONN_CON is sent early thus
		 * the peer might not yet have accepted the connection.
		 * If we are closing queue the packet with the T_CONN_IND.
		 * Otherwise defer processing the packet until the peer
		 * accepts the connection.
		 * Note that the queue is noenabled when we go into this
		 * state.
		 */
		if (!closing) {
			(void) (STRLOG(TL_ID, tep->te_minor, 1,
			    SL_TRACE|SL_ERROR,
			    "tl_data: ocon"));
			TL_PUTBQ(tep, mp);
			return;
		}
		if (DB_TYPE(mp) == M_PROTO) {
			if (msz < sizeof (t_scalar_t)) {
				freemsg(mp);
				return;
			}
			/* reuse message block - just change REQ to IND */
			if (prim->type == T_DATA_REQ)
				prim->type = T_DATA_IND;
			else
				prim->type = T_OPTDATA_IND;
		}
		tl_icon_queuemsg(tep->te_oconp, tep->te_seqno, mp);
		return;

	case TS_WREQ_ORDREL:
		if (tep->te_conp == NULL) {
			/*
			 * Other end closed - generate discon_ind
			 * with reason 0 to cause an EPIPE but no
			 * read side error on AF_UNIX sockets.
			 */
			freemsg(mp);
			(void) (STRLOG(TL_ID, tep->te_minor, 3,
			    SL_TRACE|SL_ERROR,
			    "tl_data: WREQ_ORDREL and no peer"));
			tl_discon_ind(tep, 0);
			return;
		}
		break;

	default:
		/* invalid state for event TE_DATA_REQ */
		(void) (STRLOG(TL_ID, tep->te_minor, 1, SL_TRACE|SL_ERROR,
		    "tl_data:cots:out of state"));
		tl_merror(wq, mp, EPROTO);
		return;
	}
	/*
	 * tep->te_state = NEXTSTATE(TE_DATA_REQ, tep->te_state);
	 * (State stays same on this event)
	 */

	/*
	 * get connected endpoint
	 */
	if (((peer_tep = tep->te_conp) == NULL) || peer_tep->te_closing) {
		freemsg(mp);
		/* Peer closed */
		(void) (STRLOG(TL_ID, tep->te_minor, 3, SL_TRACE,
		    "tl_data: peer gone"));
		return;
	}

	ASSERT(tep->te_serializer == peer_tep->te_serializer);
	peer_rq = peer_tep->te_rq;

	/*
	 * Put it back if flow controlled
	 * Note: Messages already on queue when we are closing is bounded
	 * so we can ignore flow control.
	 */
	if (!canputnext(peer_rq) && !closing) {
		TL_PUTBQ(tep, mp);
		return;
	}

	/*
	 * validate peer state
	 */
	switch (peer_tep->te_state) {
	case TS_DATA_XFER:
	case TS_WIND_ORDREL:
		/* valid states */
		break;
	default:
		(void) (STRLOG(TL_ID, tep->te_minor, 1, SL_TRACE|SL_ERROR,
		    "tl_data:rx side:invalid state"));
		tl_merror(peer_tep->te_wq, mp, EPROTO);
		return;
	}
	if (DB_TYPE(mp) == M_PROTO) {
		/* reuse message block - just change REQ to IND */
		if (prim->type == T_DATA_REQ)
			prim->type = T_DATA_IND;
		else
			prim->type = T_OPTDATA_IND;
	}
	/*
	 * peer_tep->te_state = NEXTSTATE(TE_DATA_IND, peer_tep->te_state);
	 * (peer state stays same on this event)
	 */
	/*
	 * send data to connected peer
	 */
	putnext(peer_rq, mp);
}



static void
tl_exdata(mblk_t *mp, tl_endpt_t *tep)
{
	queue_t			*wq = tep->te_wq;
	union T_primitives	*prim = (union T_primitives *)mp->b_rptr;
	ssize_t			msz = MBLKL(mp);
	tl_endpt_t		*peer_tep;
	queue_t			*peer_rq;
	boolean_t		closing = tep->te_closing;

	if (msz < sizeof (struct T_exdata_req)) {
		(void) (STRLOG(TL_ID, tep->te_minor, 1, SL_TRACE|SL_ERROR,
		    "tl_exdata:invalid message"));
		if (!closing) {
			tl_merror(wq, mp, EPROTO);
		} else {
			freemsg(mp);
		}
		return;
	}

	/*
	 * If the endpoint is closing it should still forward any data to the
	 * peer (if it has one). If it is not allowed to forward it can just
	 * free the message.
	 */
	if (closing &&
	    (tep->te_state != TS_DATA_XFER) &&
	    (tep->te_state != TS_WREQ_ORDREL)) {
		freemsg(mp);
		return;
	}

	/*
	 * validate state
	 */
	switch (tep->te_state) {
	case TS_IDLE:
		/*
		 * Other end not here - do nothing.
		 */
		freemsg(mp);
		(void) (STRLOG(TL_ID, tep->te_minor, 3, SL_TRACE|SL_ERROR,
		    "tl_exdata:cots with endpoint idle"));
		return;

	case TS_DATA_XFER:
		/* valid states */
		if (tep->te_conp != NULL)
			break;

		if (tep->te_oconp == NULL) {
			if (!closing) {
				tl_merror(wq, mp, EPROTO);
			} else {
				freemsg(mp);
			}
			return;
		}
		/*
		 * For a socket the T_CONN_CON is sent early thus
		 * the peer might not yet have accepted the connection.
		 * If we are closing queue the packet with the T_CONN_IND.
		 * Otherwise defer processing the packet until the peer
		 * accepts the connection.
		 * Note that the queue is noenabled when we go into this
		 * state.
		 */
		if (!closing) {
			(void) (STRLOG(TL_ID, tep->te_minor, 1,
			    SL_TRACE|SL_ERROR,
			    "tl_exdata: ocon"));
			TL_PUTBQ(tep, mp);
			return;
		}
		(void) (STRLOG(TL_ID, tep->te_minor, 1, SL_TRACE|SL_ERROR,
		    "tl_exdata: closing socket ocon"));
		prim->type = T_EXDATA_IND;
		tl_icon_queuemsg(tep->te_oconp, tep->te_seqno, mp);
		return;

	case TS_WREQ_ORDREL:
		if (tep->te_conp == NULL) {
			/*
			 * Other end closed - generate discon_ind
			 * with reason 0 to cause an EPIPE but no
			 * read side error on AF_UNIX sockets.
			 */
			freemsg(mp);
			(void) (STRLOG(TL_ID, tep->te_minor, 3,
			    SL_TRACE|SL_ERROR,
			    "tl_exdata: WREQ_ORDREL and no peer"));
			tl_discon_ind(tep, 0);
			return;
		}
		break;

	default:
		(void) (STRLOG(TL_ID, tep->te_minor, 1,
		    SL_TRACE|SL_ERROR,
		    "tl_wput:T_EXDATA_REQ:out of state, state=%d",
		    tep->te_state));
		tl_merror(wq, mp, EPROTO);
		return;
	}
	/*
	 * tep->te_state = NEXTSTATE(TE_EXDATA_REQ, tep->te_state);
	 * (state stays same on this event)
	 */

	/*
	 * get connected endpoint
	 */
	if (((peer_tep = tep->te_conp) == NULL) || peer_tep->te_closing) {
		freemsg(mp);
		/* Peer closed */
		(void) (STRLOG(TL_ID, tep->te_minor, 3, SL_TRACE,
		    "tl_exdata: peer gone"));
		return;
	}

	peer_rq = peer_tep->te_rq;

	/*
	 * Put it back if flow controlled
	 * Note: Messages already on queue when we are closing is bounded
	 * so we can ignore flow control.
	 */
	if (!canputnext(peer_rq) && !closing) {
		TL_PUTBQ(tep, mp);
		return;
	}

	/*
	 * validate state on peer
	 */
	switch (peer_tep->te_state) {
	case TS_DATA_XFER:
	case TS_WIND_ORDREL:
		/* valid states */
		break;
	default:
		(void) (STRLOG(TL_ID, tep->te_minor, 1, SL_TRACE|SL_ERROR,
		    "tl_exdata:rx side:invalid state"));
		tl_merror(peer_tep->te_wq, mp, EPROTO);
		return;
	}
	/*
	 * peer_tep->te_state = NEXTSTATE(TE_DATA_IND, peer_tep->te_state);
	 * (peer state stays same on this event)
	 */
	/*
	 * reuse message block
	 */
	prim->type = T_EXDATA_IND;

	/*
	 * send data to connected peer
	 */
	putnext(peer_rq, mp);
}



static void
tl_ordrel(mblk_t *mp, tl_endpt_t *tep)
{
	queue_t			*wq =  tep->te_wq;
	union T_primitives	*prim = (union T_primitives *)mp->b_rptr;
	ssize_t			msz = MBLKL(mp);
	tl_endpt_t		*peer_tep;
	queue_t			*peer_rq;
	boolean_t		closing = tep->te_closing;

	if (msz < sizeof (struct T_ordrel_req)) {
		(void) (STRLOG(TL_ID, tep->te_minor, 1, SL_TRACE|SL_ERROR,
		    "tl_ordrel:invalid message"));
		if (!closing) {
			tl_merror(wq, mp, EPROTO);
		} else {
			freemsg(mp);
		}
		return;
	}

	/*
	 * validate state
	 */
	switch (tep->te_state) {
	case TS_DATA_XFER:
	case TS_WREQ_ORDREL:
		/* valid states */
		if (tep->te_conp != NULL)
			break;

		if (tep->te_oconp == NULL)
			break;

		/*
		 * For a socket the T_CONN_CON is sent early thus
		 * the peer might not yet have accepted the connection.
		 * If we are closing queue the packet with the T_CONN_IND.
		 * Otherwise defer processing the packet until the peer
		 * accepts the connection.
		 * Note that the queue is noenabled when we go into this
		 * state.
		 */
		if (!closing) {
			(void) (STRLOG(TL_ID, tep->te_minor, 1,
			    SL_TRACE|SL_ERROR,
			    "tl_ordlrel: ocon"));
			TL_PUTBQ(tep, mp);
			return;
		}
		(void) (STRLOG(TL_ID, tep->te_minor, 1, SL_TRACE|SL_ERROR,
		    "tl_ordlrel: closing socket ocon"));
		prim->type = T_ORDREL_IND;
		(void) tl_icon_queuemsg(tep->te_oconp, tep->te_seqno, mp);
		return;

	default:
		(void) (STRLOG(TL_ID, tep->te_minor, 1,
		    SL_TRACE|SL_ERROR,
		    "tl_wput:T_ORDREL_REQ:out of state, state=%d",
		    tep->te_state));
		if (!closing) {
			tl_merror(wq, mp, EPROTO);
		} else {
			freemsg(mp);
		}
		return;
	}
	tep->te_state = NEXTSTATE(TE_ORDREL_REQ, tep->te_state);

	/*
	 * get connected endpoint
	 */
	if (((peer_tep = tep->te_conp) == NULL) || peer_tep->te_closing) {
		/* Peer closed */
		(void) (STRLOG(TL_ID, tep->te_minor, 3, SL_TRACE,
		    "tl_ordrel: peer gone"));
		freemsg(mp);
		return;
	}

	peer_rq = peer_tep->te_rq;

	/*
	 * Put it back if flow controlled except when we are closing.
	 * Note: Messages already on queue when we are closing is bounded
	 * so we can ignore flow control.
	 */
	if (! canputnext(peer_rq) && !closing) {
		TL_PUTBQ(tep, mp);
		return;
	}

	/*
	 * validate state on peer
	 */
	switch (peer_tep->te_state) {
	case TS_DATA_XFER:
	case TS_WIND_ORDREL:
		/* valid states */
		break;
	default:
		(void) (STRLOG(TL_ID, tep->te_minor, 1, SL_TRACE|SL_ERROR,
		    "tl_ordrel:rx side:invalid state"));
		tl_merror(peer_tep->te_wq, mp, EPROTO);
		return;
	}
	peer_tep->te_state = NEXTSTATE(TE_ORDREL_IND, peer_tep->te_state);

	/*
	 * reuse message block
	 */
	prim->type = T_ORDREL_IND;
	(void) (STRLOG(TL_ID, tep->te_minor, 3, SL_TRACE,
	    "tl_ordrel: send ordrel_ind"));

	/*
	 * send data to connected peer
	 */
	putnext(peer_rq, mp);
}


/*
 * Send T_UDERROR_IND. The error should be from the <sys/errno.h> space.
 */
static void
tl_uderr(queue_t *wq, mblk_t *mp, t_scalar_t err)
{
	size_t			err_sz;
	tl_endpt_t		*tep;
	struct T_unitdata_req	*udreq;
	mblk_t			*err_mp;
	t_scalar_t		alen;
	t_scalar_t		olen;
	struct T_uderror_ind	*uderr;
	uchar_t			*addr_startp;

	err_sz = sizeof (struct T_uderror_ind);
	tep = (tl_endpt_t *)wq->q_ptr;
	udreq = (struct T_unitdata_req *)mp->b_rptr;
	alen = udreq->DEST_length;
	olen = udreq->OPT_length;

	if (alen > 0)
		err_sz = T_ALIGN(err_sz + alen);
	if (olen > 0)
		err_sz += olen;

	err_mp = allocb(err_sz, BPRI_MED);
	if (! err_mp) {
		(void) (STRLOG(TL_ID, tep->te_minor, 3, SL_TRACE|SL_ERROR,
		    "tl_uderr:allocb failure"));
		/*
		 * Note: no rollback of state needed as it does
		 * not change in connectionless transport
		 */
		tl_memrecover(wq, mp, err_sz);
		return;
	}

	DB_TYPE(err_mp) = M_PROTO;
	err_mp->b_wptr = err_mp->b_rptr + err_sz;
	uderr = (struct T_uderror_ind *)err_mp->b_rptr;
	uderr->PRIM_type = T_UDERROR_IND;
	uderr->ERROR_type = err;
	uderr->DEST_length = alen;
	uderr->OPT_length = olen;
	if (alen <= 0) {
		uderr->DEST_offset = 0;
	} else {
		uderr->DEST_offset =
		    (t_scalar_t)sizeof (struct T_uderror_ind);
		addr_startp  = mp->b_rptr + udreq->DEST_offset;
		bcopy(addr_startp, err_mp->b_rptr + uderr->DEST_offset,
		    (size_t)alen);
	}
	if (olen <= 0) {
		uderr->OPT_offset = 0;
	} else {
		uderr->OPT_offset =
		    (t_scalar_t)T_ALIGN(sizeof (struct T_uderror_ind) +
		    uderr->DEST_length);
		addr_startp  = mp->b_rptr + udreq->OPT_offset;
		bcopy(addr_startp, err_mp->b_rptr+uderr->OPT_offset,
		    (size_t)olen);
	}
	freemsg(mp);

	/*
	 * send indication message
	 */
	tep->te_state = NEXTSTATE(TE_UDERROR_IND, tep->te_state);

	qreply(wq, err_mp);
}

static void
tl_unitdata_ser(mblk_t *mp, tl_endpt_t *tep)
{
	queue_t *wq = tep->te_wq;

	if (!tep->te_closing && (wq->q_first != NULL)) {
		TL_PUTQ(tep, mp);
	} else if (tep->te_rq != NULL)
		tl_unitdata(mp, tep);
	else
		freemsg(mp);

	tl_serializer_exit(tep);
	tl_refrele(tep);
}

/*
 * Handle T_unitdata_req.
 * If TL_SET[U]CRED or TL_SOCKUCRED generate the credentials options.
 * If this is a socket pass through options unmodified.
 */
static void
tl_unitdata(mblk_t *mp, tl_endpt_t *tep)
{
	queue_t			*wq = tep->te_wq;
	soux_addr_t		ux_addr;
	tl_addr_t		destaddr;
	uchar_t			*addr_startp;
	tl_endpt_t		*peer_tep;
	struct T_unitdata_ind	*udind;
	struct T_unitdata_req	*udreq;
	ssize_t			msz, ui_sz;
	t_scalar_t		alen, aoff, olen, ooff;
	t_scalar_t		oldolen = 0;
	cred_t			*cr = NULL;
	pid_t			cpid;

	udreq = (struct T_unitdata_req *)mp->b_rptr;
	msz = MBLKL(mp);

	/*
	 * validate the state
	 */
	if (tep->te_state != TS_IDLE) {
		(void) (STRLOG(TL_ID, tep->te_minor, 1,
		    SL_TRACE|SL_ERROR,
		    "tl_wput:T_CONN_REQ:out of state"));
		tl_merror(wq, mp, EPROTO);
		return;
	}
	/*
	 * tep->te_state = NEXTSTATE(TE_UNITDATA_REQ, tep->te_state);
	 * (state does not change on this event)
	 */

	/*
	 * validate the message
	 * Note: dereference fields in struct inside message only
	 * after validating the message length.
	 */
	if (msz < sizeof (struct T_unitdata_req)) {
		(void) (STRLOG(TL_ID, tep->te_minor, 1, SL_TRACE|SL_ERROR,
		    "tl_unitdata:invalid message length"));
		tl_merror(wq, mp, EINVAL);
		return;
	}
	alen = udreq->DEST_length;
	aoff = udreq->DEST_offset;
	oldolen = olen = udreq->OPT_length;
	ooff = udreq->OPT_offset;
	if (olen == 0)
		ooff = 0;

	if (IS_SOCKET(tep)) {
		if ((alen != TL_SOUX_ADDRLEN) ||
		    (aoff < 0) ||
		    (aoff + alen > msz) ||
		    (olen < 0) || (ooff < 0) ||
		    ((olen > 0) && ((ooff + olen) > msz))) {
			(void) (STRLOG(TL_ID, tep->te_minor,
			    1, SL_TRACE|SL_ERROR,
			    "tl_unitdata_req: invalid socket addr "
			    "(msz=%d, al=%d, ao=%d, ol=%d, oo = %d)",
			    (int)msz, alen, aoff, olen, ooff));
			tl_error_ack(wq, mp, TSYSERR, EINVAL, T_UNITDATA_REQ);
			return;
		}
		bcopy(mp->b_rptr + aoff, &ux_addr, TL_SOUX_ADDRLEN);

		if ((ux_addr.soua_magic != SOU_MAGIC_IMPLICIT) &&
		    (ux_addr.soua_magic != SOU_MAGIC_EXPLICIT)) {
			(void) (STRLOG(TL_ID, tep->te_minor,
			    1, SL_TRACE|SL_ERROR,
			    "tl_conn_req: invalid socket magic"));
			tl_error_ack(wq, mp, TSYSERR, EINVAL, T_UNITDATA_REQ);
			return;
		}
	} else {
		if ((alen < 0) ||
		    (aoff < 0) ||
		    ((alen > 0) && ((aoff + alen) > msz)) ||
		    ((ssize_t)alen > (msz - sizeof (struct T_unitdata_req))) ||
		    ((aoff + alen) < 0) ||
		    ((olen > 0) && ((ooff + olen) > msz)) ||
		    (olen < 0) ||
		    (ooff < 0) ||
		    ((ssize_t)olen > (msz - sizeof (struct T_unitdata_req)))) {
			(void) (STRLOG(TL_ID, tep->te_minor, 1,
				    SL_TRACE|SL_ERROR,
				    "tl_unitdata:invalid unit data message"));
			tl_merror(wq, mp, EINVAL);
			return;
		}
	}

	/* Options not supported unless it's a socket */
	if (alen == 0 || (olen != 0 && !IS_SOCKET(tep))) {
		(void) (STRLOG(TL_ID, tep->te_minor, 3, SL_TRACE|SL_ERROR,
		    "tl_unitdata:option use(unsupported) or zero len addr"));
		tl_uderr(wq, mp, EPROTO);
		return;
	}
#ifdef DEBUG
	/*
	 * Mild form of ASSERT()ion to detect broken TPI apps.
	 * if (! assertion)
	 *	log warning;
	 */
	if (! (aoff >= (t_scalar_t)sizeof (struct T_unitdata_req))) {
		(void) (STRLOG(TL_ID, tep->te_minor, 3, SL_TRACE|SL_ERROR,
		    "tl_unitdata:addr overlaps TPI message"));
	}
#endif
	/*
	 * get destination endpoint
	 */
	destaddr.ta_alen = alen;
	destaddr.ta_abuf = mp->b_rptr + aoff;
	destaddr.ta_zoneid = tep->te_zoneid;

	/*
	 * Check whether the destination is the same that was used previously
	 * and the destination endpoint is in the right state. If something is
	 * wrong, find destination again and cache it.
	 */
	peer_tep = tep->te_lastep;

	if ((peer_tep == NULL) || peer_tep->te_closing ||
	    (peer_tep->te_state != TS_IDLE) ||
	    !tl_eqaddr(&destaddr, &peer_tep->te_ap)) {
		/*
		 * Not the same as cached destination , need to find the right
		 * destination.
		 */
		peer_tep = (IS_SOCKET(tep) ?
		    tl_sock_find_peer(tep, &ux_addr) :
		    tl_find_peer(tep, &destaddr));

		if (peer_tep == NULL) {
			(void) (STRLOG(TL_ID, tep->te_minor, 3,
			    SL_TRACE|SL_ERROR,
			    "tl_unitdata:no one at destination address"));
			tl_uderr(wq, mp, ECONNRESET);
			return;
		}

		/*
		 * Cache the new peer.
		 */
		if (tep->te_lastep != NULL)
			tl_refrele(tep->te_lastep);

		tep->te_lastep = peer_tep;
	}

	if (peer_tep->te_state != TS_IDLE) {
		(void) (STRLOG(TL_ID, tep->te_minor, 1, SL_TRACE|SL_ERROR,
		    "tl_unitdata:provider in invalid state"));
		tl_uderr(wq, mp, EPROTO);
		return;
	}

	ASSERT(peer_tep->te_rq != NULL);

	/*
	 * Put it back if flow controlled except when we are closing.
	 * Note: Messages already on queue when we are closing is bounded
	 * so we can ignore flow control.
	 */
	if (!canputnext(peer_tep->te_rq) && !(tep->te_closing)) {
		/* record what we are flow controlled on */
		if (tep->te_flowq != NULL) {
			list_remove(&tep->te_flowq->te_flowlist, tep);
		}
		list_insert_head(&peer_tep->te_flowlist, tep);
		tep->te_flowq = peer_tep;
		TL_PUTBQ(tep, mp);
		return;
	}
	/*
	 * prepare indication message
	 */

	/*
	 * calculate length of message
	 */
	if (peer_tep->te_flag & (TL_SETCRED|TL_SETUCRED|TL_SOCKUCRED)) {
		cr = msg_getcred(mp, &cpid);
		ASSERT(cr != NULL);

		if (peer_tep->te_flag & TL_SETCRED) {
			ASSERT(olen == 0);
			olen = (t_scalar_t)sizeof (struct opthdr) +
			    OPTLEN(sizeof (tl_credopt_t));
						/* 1 option only */
		} else if (peer_tep->te_flag & TL_SETUCRED) {
			ASSERT(olen == 0);
			olen = (t_scalar_t)sizeof (struct opthdr) +
			    OPTLEN(ucredminsize(cr));
						/* 1 option only */
		} else {
			/* Possibly more than one option */
			olen += (t_scalar_t)sizeof (struct T_opthdr) +
			    OPTLEN(ucredminsize(cr));
		}
	}

	ui_sz = T_ALIGN(sizeof (struct T_unitdata_ind) + tep->te_alen) +
	    olen;
	/*
	 * If the unitdata_ind fits and we are not adding options
	 * reuse the udreq mblk.
	 */
	if (msz >= ui_sz && alen >= tep->te_alen &&
	    !(peer_tep->te_flag & (TL_SETCRED|TL_SETUCRED|TL_SOCKUCRED))) {
		/*
		 * Reuse the original mblk. Leave options in place.
		 */
		udind =  (struct T_unitdata_ind *)mp->b_rptr;
		udind->PRIM_type = T_UNITDATA_IND;
		udind->SRC_length = tep->te_alen;
		addr_startp = mp->b_rptr + udind->SRC_offset;
		bcopy(tep->te_abuf, addr_startp, tep->te_alen);
	} else {
		/* Allocate a new T_unidata_ind message */
		mblk_t *ui_mp;

		ui_mp = allocb(ui_sz, BPRI_MED);
		if (! ui_mp) {
			(void) (STRLOG(TL_ID, tep->te_minor, 4, SL_TRACE,
			    "tl_unitdata:allocb failure:message queued"));
			tl_memrecover(wq, mp, ui_sz);
			return;
		}

		/*
		 * fill in T_UNITDATA_IND contents
		 */
		DB_TYPE(ui_mp) = M_PROTO;
		ui_mp->b_wptr = ui_mp->b_rptr + ui_sz;
		udind =  (struct T_unitdata_ind *)ui_mp->b_rptr;
		udind->PRIM_type = T_UNITDATA_IND;
		udind->SRC_offset = (t_scalar_t)sizeof (struct T_unitdata_ind);
		udind->SRC_length = tep->te_alen;
		addr_startp = ui_mp->b_rptr + udind->SRC_offset;
		bcopy(tep->te_abuf, addr_startp, tep->te_alen);
		udind->OPT_offset =
		    (t_scalar_t)T_ALIGN(udind->SRC_offset + udind->SRC_length);
		udind->OPT_length = olen;
		if (peer_tep->te_flag & (TL_SETCRED|TL_SETUCRED|TL_SOCKUCRED)) {

			if (oldolen != 0) {
				bcopy((void *)((uintptr_t)udreq + ooff),
				    (void *)((uintptr_t)udind +
				    udind->OPT_offset),
				    oldolen);
			}
			ASSERT(cr != NULL);

			tl_fill_option(ui_mp->b_rptr + udind->OPT_offset +
			    oldolen, cr, cpid,
			    peer_tep->te_flag, peer_tep->te_credp);
		} else {
			bcopy((void *)((uintptr_t)udreq + ooff),
			    (void *)((uintptr_t)udind + udind->OPT_offset),
			    olen);
		}

		/*
		 * relink data blocks from mp to ui_mp
		 */
		ui_mp->b_cont = mp->b_cont;
		freeb(mp);
		mp = ui_mp;
	}
	/*
	 * send indication message
	 */
	peer_tep->te_state = NEXTSTATE(TE_UNITDATA_IND, peer_tep->te_state);
	putnext(peer_tep->te_rq, mp);
}



/*
 * Check if a given addr is in use.
 * Endpoint ptr returned or NULL if not found.
 * The name space is separate for each mode. This implies that
 * sockets get their own name space.
 */
static tl_endpt_t *
tl_find_peer(tl_endpt_t *tep, tl_addr_t *ap)
{
	tl_endpt_t *peer_tep = NULL;
	int rc = mod_hash_find_cb(tep->te_addrhash, (mod_hash_key_t)ap,
	    (mod_hash_val_t *)&peer_tep, tl_find_callback);

	ASSERT(! IS_SOCKET(tep));

	ASSERT(ap != NULL && ap->ta_alen > 0);
	ASSERT(ap->ta_zoneid == tep->te_zoneid);
	ASSERT(ap->ta_abuf != NULL);
	EQUIV(rc == 0, peer_tep != NULL);
	IMPLY(rc == 0,
	    (tep->te_zoneid == peer_tep->te_zoneid) &&
	    (tep->te_transport == peer_tep->te_transport));

	if ((rc == 0) && (peer_tep->te_closing)) {
		tl_refrele(peer_tep);
		peer_tep = NULL;
	}

	return (peer_tep);
}

/*
 * Find peer for a socket based on unix domain address.
 * For implicit addresses our peer can be found by minor number in ai hash. For
 * explicit binds we look vnode address at addr_hash.
 */
static tl_endpt_t *
tl_sock_find_peer(tl_endpt_t *tep, soux_addr_t *ux_addr)
{
	tl_endpt_t *peer_tep = NULL;
	mod_hash_t *hash = ux_addr->soua_magic == SOU_MAGIC_IMPLICIT ?
	    tep->te_aihash : tep->te_addrhash;
	int rc = mod_hash_find_cb(hash, (mod_hash_key_t)ux_addr->soua_vp,
	    (mod_hash_val_t *)&peer_tep, tl_find_callback);

	ASSERT(IS_SOCKET(tep));
	EQUIV(rc == 0, peer_tep != NULL);
	IMPLY(rc == 0, (tep->te_transport == peer_tep->te_transport));

	if (peer_tep != NULL) {
		/* Don't attempt to use closing peer. */
		if (peer_tep->te_closing)
			goto errout;

		/*
		 * Cross-zone unix sockets are permitted, but for Trusted
		 * Extensions only, the "server" for these must be in the
		 * global zone.
		 */
		if ((peer_tep->te_zoneid != tep->te_zoneid) &&
		    is_system_labeled() &&
		    (peer_tep->te_zoneid != GLOBAL_ZONEID))
			goto errout;
	}

	return (peer_tep);

errout:
	tl_refrele(peer_tep);
	return (NULL);
}

/*
 * Generate a free addr and return it in struct pointed by ap
 * but allocating space for address buffer.
 * The generated address will be at least 4 bytes long and, if req->ta_alen
 * exceeds 4 bytes, be req->ta_alen bytes long.
 *
 * If address is found it will be inserted in the hash.
 *
 * If req->ta_alen is larger than the default alen (4 bytes) the last
 * alen-4 bytes will always be the same as in req.
 *
 * Return 0 for failure.
 * Return non-zero for success.
 */
static boolean_t
tl_get_any_addr(tl_endpt_t *tep, tl_addr_t *req)
{
	t_scalar_t	alen;
	uint32_t	loopcnt;	/* Limit loop to 2^32 */

	ASSERT(tep->te_hash_hndl != NULL);
	ASSERT(! IS_SOCKET(tep));

	if (tep->te_hash_hndl == NULL)
		return (B_FALSE);

	/*
	 * check if default addr is in use
	 * if it is - bump it and try again
	 */
	if (req == NULL) {
		alen = sizeof (uint32_t);
	} else {
		alen = max(req->ta_alen, sizeof (uint32_t));
		ASSERT(tep->te_zoneid == req->ta_zoneid);
	}

	if (tep->te_alen < alen) {
		void *abuf = kmem_zalloc((size_t)alen, KM_NOSLEEP);

		/*
		 * Not enough space in tep->ta_ap to hold the address,
		 * allocate a bigger space.
		 */
		if (abuf == NULL)
			return (B_FALSE);

		if (tep->te_alen > 0)
			kmem_free(tep->te_abuf, tep->te_alen);

		tep->te_alen = alen;
		tep->te_abuf = abuf;
	}

	/* Copy in the address in req */
	if (req != NULL) {
		ASSERT(alen >= req->ta_alen);
		bcopy(req->ta_abuf, tep->te_abuf, (size_t)req->ta_alen);
	}

	/*
	 * First try minor number then try default addresses.
	 */
	bcopy(&tep->te_minor, tep->te_abuf, sizeof (uint32_t));

	for (loopcnt = 0; loopcnt < UINT32_MAX; loopcnt++) {
		if (mod_hash_insert_reserve(tep->te_addrhash,
		    (mod_hash_key_t)&tep->te_ap, (mod_hash_val_t)tep,
		    tep->te_hash_hndl) == 0) {
			/*
			 * found free address
			 */
			tep->te_flag |= TL_ADDRHASHED;
			tep->te_hash_hndl = NULL;

			return (B_TRUE); /* successful return */
		}
		/*
		 * Use default address.
		 */
		bcopy(&tep->te_defaddr, tep->te_abuf, sizeof (uint32_t));
		atomic_inc_32(&tep->te_defaddr);
	}

	/*
	 * Failed to find anything.
	 */
	(void) (STRLOG(TL_ID, -1, 1, SL_ERROR,
	    "tl_get_any_addr:looped 2^32 times"));
	return (B_FALSE);
}

/*
 * reallocb + set r/w ptrs to reflect size.
 */
static mblk_t *
tl_resizemp(mblk_t *mp, ssize_t new_size)
{
	if ((mp = reallocb(mp, new_size, 0)) == NULL)
		return (NULL);

	mp->b_rptr = DB_BASE(mp);
	mp->b_wptr = mp->b_rptr + new_size;
	return (mp);
}

static void
tl_cl_backenable(tl_endpt_t *tep)
{
	list_t *l = &tep->te_flowlist;
	tl_endpt_t *elp;

	ASSERT(IS_CLTS(tep));

	for (elp = list_head(l); elp != NULL; elp = list_head(l)) {
		ASSERT(tep->te_ser == elp->te_ser);
		ASSERT(elp->te_flowq == tep);
		if (! elp->te_closing)
			TL_QENABLE(elp);
		elp->te_flowq = NULL;
		list_remove(l, elp);
	}
}

/*
 * Unconnect endpoints.
 */
static void
tl_co_unconnect(tl_endpt_t *tep)
{
	tl_endpt_t	*peer_tep = tep->te_conp;
	tl_endpt_t	*srv_tep = tep->te_oconp;
	list_t		*l;
	tl_icon_t  	*tip;
	tl_endpt_t	*cl_tep;
	mblk_t		*d_mp;

	ASSERT(IS_COTS(tep));
	/*
	 * If our peer is closing, don't use it.
	 */
	if ((peer_tep != NULL) && peer_tep->te_closing) {
		TL_UNCONNECT(tep->te_conp);
		peer_tep = NULL;
	}
	if ((srv_tep != NULL) && srv_tep->te_closing) {
		TL_UNCONNECT(tep->te_oconp);
		srv_tep = NULL;
	}

	if (tep->te_nicon > 0) {
		l = &tep->te_iconp;
		/*
		 * If incoming requests pending, change state
		 * of clients on disconnect ind event and send
		 * discon_ind pdu to modules above them
		 * for server: all clients get disconnect
		 */

		while (tep->te_nicon > 0) {
			tip    = list_head(l);
			cl_tep = tip->ti_tep;

			if (cl_tep == NULL) {
				tl_freetip(tep, tip);
				continue;
			}

			if (cl_tep->te_oconp != NULL) {
				ASSERT(cl_tep != cl_tep->te_oconp);
				TL_UNCONNECT(cl_tep->te_oconp);
			}

			if (cl_tep->te_closing) {
				tl_freetip(tep, tip);
				continue;
			}

			enableok(cl_tep->te_wq);
			TL_QENABLE(cl_tep);
			d_mp = tl_discon_ind_alloc(ECONNREFUSED, BADSEQNUM);
			if (d_mp != NULL) {
				cl_tep->te_state = TS_IDLE;
				putnext(cl_tep->te_rq, d_mp);
			} else {
				(void) (STRLOG(TL_ID, tep->te_minor, 3,
				    SL_TRACE|SL_ERROR,
				    "tl_co_unconnect:icmng: "
				    "allocb failure"));
			}
			tl_freetip(tep, tip);
		}
	} else if (srv_tep != NULL) {
		/*
		 * If outgoing request pending, change state
		 * of server on discon ind event
		 */

		if (IS_SOCKET(tep) && !tl_disable_early_connect &&
		    IS_COTSORD(srv_tep) &&
		    !tl_icon_hasprim(srv_tep, tep->te_seqno, T_ORDREL_IND)) {
			/*
			 * Queue ordrel_ind for server to be picked up
			 * when the connection is accepted.
			 */
			d_mp = tl_ordrel_ind_alloc();
		} else {
			/*
			 * send discon_ind to server
			 */
			d_mp = tl_discon_ind_alloc(ECONNRESET, tep->te_seqno);
		}
		if (d_mp == NULL) {
			(void) (STRLOG(TL_ID, tep->te_minor, 3,
			    SL_TRACE|SL_ERROR,
			    "tl_co_unconnect:outgoing:allocb failure"));
			TL_UNCONNECT(tep->te_oconp);
			goto discon_peer;
		}

		/*
		 * If this is a socket the T_DISCON_IND is queued with
		 * the T_CONN_IND. Otherwise the T_CONN_IND is removed
		 * from the list of pending connections.
		 * Note that when te_oconp is set the peer better have
		 * a t_connind_t for the client.
		 */
		if (IS_SOCKET(tep) && !tl_disable_early_connect) {
			/*
			 * Queue the disconnection message.
			 */
			tl_icon_queuemsg(srv_tep, tep->te_seqno, d_mp);
		} else {
			tip = tl_icon_find(srv_tep, tep->te_seqno);
			if (tip == NULL) {
				freemsg(d_mp);
			} else {
				ASSERT(tep == tip->ti_tep);
				ASSERT(tep->te_ser == srv_tep->te_ser);
				/*
				 * Delete tip from the server list.
				 */
				if (srv_tep->te_nicon == 1) {
					srv_tep->te_state =
					    NEXTSTATE(TE_DISCON_IND2,
					    srv_tep->te_state);
				} else {
					srv_tep->te_state =
					    NEXTSTATE(TE_DISCON_IND3,
					    srv_tep->te_state);
				}
				ASSERT(*(uint32_t *)(d_mp->b_rptr) ==
				    T_DISCON_IND);
				putnext(srv_tep->te_rq, d_mp);
				tl_freetip(srv_tep, tip);
			}
			TL_UNCONNECT(tep->te_oconp);
			srv_tep = NULL;
		}
	} else if (peer_tep != NULL) {
		/*
		 * unconnect existing connection
		 * If connected, change state of peer on
		 * discon ind event and send discon ind pdu
		 * to module above it
		 */

		ASSERT(tep->te_ser == peer_tep->te_ser);
		if (IS_COTSORD(peer_tep) &&
		    (peer_tep->te_state == TS_WIND_ORDREL ||
		    peer_tep->te_state == TS_DATA_XFER)) {
			/*
			 * send ordrel ind
			 */
			(void) (STRLOG(TL_ID, tep->te_minor, 3, SL_TRACE,
			"tl_co_unconnect:connected: ordrel_ind state %d->%d",
			    peer_tep->te_state,
			    NEXTSTATE(TE_ORDREL_IND, peer_tep->te_state)));
			d_mp = tl_ordrel_ind_alloc();
			if (! d_mp) {
				(void) (STRLOG(TL_ID, tep->te_minor, 3,
				    SL_TRACE|SL_ERROR,
				    "tl_co_unconnect:connected:"
				    "allocb failure"));
				/*
				 * Continue with cleaning up peer as
				 * this side may go away with the close
				 */
				TL_QENABLE(peer_tep);
				goto discon_peer;
			}
			peer_tep->te_state =
			    NEXTSTATE(TE_ORDREL_IND, peer_tep->te_state);

			putnext(peer_tep->te_rq, d_mp);
			/*
			 * Handle flow control case.  This will generate
			 * a t_discon_ind message with reason 0 if there
			 * is data queued on the write side.
			 */
			TL_QENABLE(peer_tep);
		} else if (IS_COTSORD(peer_tep) &&
		    peer_tep->te_state == TS_WREQ_ORDREL) {
			/*
			 * Sent an ordrel_ind. We send a discon with
			 * with error 0 to inform that the peer is gone.
			 */
			(void) (STRLOG(TL_ID, tep->te_minor, 3,
			    SL_TRACE|SL_ERROR,
			    "tl_co_unconnect: discon in state %d",
			    tep->te_state));
			tl_discon_ind(peer_tep, 0);
		} else {
			(void) (STRLOG(TL_ID, tep->te_minor, 3,
			    SL_TRACE|SL_ERROR,
			    "tl_co_unconnect: state %d", tep->te_state));
			tl_discon_ind(peer_tep, ECONNRESET);
		}

discon_peer:
		/*
		 * Disconnect cross-pointers only for close
		 */
		if (tep->te_closing) {
			peer_tep = tep->te_conp;
			TL_REMOVE_PEER(peer_tep->te_conp);
			TL_REMOVE_PEER(tep->te_conp);
		}
	}
}

/*
 * Note: The following routine does not recover from allocb()
 * failures
 * The reason should be from the <sys/errno.h> space.
 */
static void
tl_discon_ind(tl_endpt_t *tep, uint32_t reason)
{
	mblk_t *d_mp;

	if (tep->te_closing)
		return;

	/*
	 * flush the queues.
	 */
	flushq(tep->te_rq, FLUSHDATA);
	(void) putnextctl1(tep->te_rq, M_FLUSH, FLUSHRW);

	/*
	 * send discon ind
	 */
	d_mp = tl_discon_ind_alloc(reason, tep->te_seqno);
	if (! d_mp) {
		(void) (STRLOG(TL_ID, tep->te_minor, 3, SL_TRACE|SL_ERROR,
		    "tl_discon_ind:allocb failure"));
		return;
	}
	tep->te_state = TS_IDLE;
	putnext(tep->te_rq, d_mp);
}

/*
 * Note: The following routine does not recover from allocb()
 * failures
 * The reason should be from the <sys/errno.h> space.
 */
static mblk_t *
tl_discon_ind_alloc(uint32_t reason, t_scalar_t seqnum)
{
	mblk_t *mp;
	struct T_discon_ind *tdi;

	if (mp = allocb(sizeof (struct T_discon_ind), BPRI_MED)) {
		DB_TYPE(mp) = M_PROTO;
		mp->b_wptr = mp->b_rptr + sizeof (struct T_discon_ind);
		tdi = (struct T_discon_ind *)mp->b_rptr;
		tdi->PRIM_type = T_DISCON_IND;
		tdi->DISCON_reason = reason;
		tdi->SEQ_number = seqnum;
	}
	return (mp);
}


/*
 * Note: The following routine does not recover from allocb()
 * failures
 */
static mblk_t *
tl_ordrel_ind_alloc(void)
{
	mblk_t *mp;
	struct T_ordrel_ind *toi;

	if (mp = allocb(sizeof (struct T_ordrel_ind), BPRI_MED)) {
		DB_TYPE(mp) = M_PROTO;
		mp->b_wptr = mp->b_rptr + sizeof (struct T_ordrel_ind);
		toi = (struct T_ordrel_ind *)mp->b_rptr;
		toi->PRIM_type = T_ORDREL_IND;
	}
	return (mp);
}


/*
 * Lookup the seqno in the list of queued connections.
 */
static tl_icon_t *
tl_icon_find(tl_endpt_t *tep, t_scalar_t seqno)
{
	list_t *l = &tep->te_iconp;
	tl_icon_t *tip = list_head(l);

	ASSERT(seqno != 0);

	for (; tip != NULL && (tip->ti_seqno != seqno); tip = list_next(l, tip))
		;

	return (tip);
}

/*
 * Queue data for a given T_CONN_IND while verifying that redundant
 * messages, such as a T_ORDREL_IND after a T_DISCON_IND, are not queued.
 * Used when the originator of the connection closes.
 */
static void
tl_icon_queuemsg(tl_endpt_t *tep, t_scalar_t seqno, mblk_t *nmp)
{
	tl_icon_t		*tip;
	mblk_t			**mpp, *mp;
	int			prim, nprim;

	if (nmp->b_datap->db_type == M_PROTO)
		nprim = ((union T_primitives *)nmp->b_rptr)->type;
	else
		nprim = -1;	/* M_DATA */

	tip = tl_icon_find(tep, seqno);
	if (tip == NULL) {
		freemsg(nmp);
		return;
	}

	ASSERT(tip->ti_seqno != 0);
	mpp = &tip->ti_mp;
	while (*mpp != NULL) {
		mp = *mpp;

		if (mp->b_datap->db_type == M_PROTO)
			prim = ((union T_primitives *)mp->b_rptr)->type;
		else
			prim = -1;	/* M_DATA */

		/*
		 * Allow nothing after a T_DISCON_IND
		 */
		if (prim == T_DISCON_IND) {
			freemsg(nmp);
			return;
		}
		/*
		 * Only allow a T_DISCON_IND after an T_ORDREL_IND
		 */
		if (prim == T_ORDREL_IND && nprim != T_DISCON_IND) {
			freemsg(nmp);
			return;
		}
		mpp = &(mp->b_next);
	}
	*mpp = nmp;
}

/*
 * Verify if a certain TPI primitive exists on the connind queue.
 * Use prim -1 for M_DATA.
 * Return non-zero if found.
 */
static boolean_t
tl_icon_hasprim(tl_endpt_t *tep, t_scalar_t seqno, t_scalar_t prim)
{
	tl_icon_t *tip = tl_icon_find(tep, seqno);
	boolean_t found = B_FALSE;

	if (tip != NULL) {
		mblk_t *mp;
		for (mp = tip->ti_mp; !found && mp != NULL; mp = mp->b_next) {
			found = (DB_TYPE(mp) == M_PROTO &&
			    ((union T_primitives *)mp->b_rptr)->type == prim);
		}
	}
	return (found);
}

/*
 * Send the b_next mblk chain that has accumulated before the connection
 * was accepted. Perform the necessary state transitions.
 */
static void
tl_icon_sendmsgs(tl_endpt_t *tep, mblk_t **mpp)
{
	mblk_t			*mp;
	union T_primitives	*primp;

	if (tep->te_closing) {
		tl_icon_freemsgs(mpp);
		return;
	}

	ASSERT(tep->te_state == TS_DATA_XFER);
	ASSERT(tep->te_rq->q_first == NULL);

	while ((mp = *mpp) != NULL) {
		*mpp = mp->b_next;
		mp->b_next = NULL;

		ASSERT((DB_TYPE(mp) == M_DATA) || (DB_TYPE(mp) == M_PROTO));
		switch (DB_TYPE(mp)) {
		default:
			freemsg(mp);
			break;
		case M_DATA:
			putnext(tep->te_rq, mp);
			break;
		case M_PROTO:
			primp = (union T_primitives *)mp->b_rptr;
			switch (primp->type) {
			case T_UNITDATA_IND:
			case T_DATA_IND:
			case T_OPTDATA_IND:
			case T_EXDATA_IND:
				putnext(tep->te_rq, mp);
				break;
			case T_ORDREL_IND:
				tep->te_state = NEXTSTATE(TE_ORDREL_IND,
				    tep->te_state);
				putnext(tep->te_rq, mp);
				break;
			case T_DISCON_IND:
				tep->te_state = TS_IDLE;
				putnext(tep->te_rq, mp);
				break;
			default:
#ifdef DEBUG
				cmn_err(CE_PANIC,
				    "tl_icon_sendmsgs: unknown primitive");
#endif /* DEBUG */
				freemsg(mp);
				break;
			}
			break;
		}
	}
}

/*
 * Free the b_next mblk chain that has accumulated before the connection
 * was accepted.
 */
static void
tl_icon_freemsgs(mblk_t **mpp)
{
	mblk_t *mp;

	while ((mp = *mpp) != NULL) {
		*mpp = mp->b_next;
		mp->b_next = NULL;
		freemsg(mp);
	}
}

/*
 * Send M_ERROR
 * Note: assumes caller ensured enough space in mp or enough
 *	memory available. Does not attempt recovery from allocb()
 *	failures
 */

static void
tl_merror(queue_t *wq, mblk_t *mp, int error)
{
	tl_endpt_t *tep = (tl_endpt_t *)wq->q_ptr;

	if (tep->te_closing) {
		freemsg(mp);
		return;
	}

	(void) (STRLOG(TL_ID, tep->te_minor, 1,
	    SL_TRACE|SL_ERROR,
	    "tl_merror: tep=%p, err=%d", (void *)tep, error));

	/*
	 * flush all messages on queue. we are shutting
	 * the stream down on fatal error
	 */
	flushq(wq, FLUSHALL);
	if (IS_COTS(tep)) {
		/* connection oriented - unconnect endpoints */
		tl_co_unconnect(tep);
	}
	if (mp->b_cont) {
		freemsg(mp->b_cont);
		mp->b_cont = NULL;
	}

	if ((MBLKSIZE(mp) < 1) || (DB_REF(mp) > 1)) {
		freemsg(mp);
		mp = allocb(1, BPRI_HI);
		if (!mp) {
			(void) (STRLOG(TL_ID, tep->te_minor, 1,
			    SL_TRACE|SL_ERROR,
			    "tl_merror:M_PROTO: out of memory"));
			return;
		}
	}
	if (mp) {
		DB_TYPE(mp) = M_ERROR;
		mp->b_rptr = DB_BASE(mp);
		*mp->b_rptr = (char)error;
		mp->b_wptr = mp->b_rptr + sizeof (char);
		qreply(wq, mp);
	} else {
		(void) putnextctl1(tep->te_rq, M_ERROR, error);
	}
}

static void
tl_fill_option(uchar_t *buf, cred_t *cr, pid_t cpid, int flag, cred_t *pcr)
{
	ASSERT(cr != NULL);

	if (flag & TL_SETCRED) {
		struct opthdr *opt = (struct opthdr *)buf;
		tl_credopt_t *tlcred;

		opt->level = TL_PROT_LEVEL;
		opt->name = TL_OPT_PEER_CRED;
		opt->len = (t_uscalar_t)OPTLEN(sizeof (tl_credopt_t));

		tlcred = (tl_credopt_t *)(opt + 1);
		tlcred->tc_uid = crgetuid(cr);
		tlcred->tc_gid = crgetgid(cr);
		tlcred->tc_ruid = crgetruid(cr);
		tlcred->tc_rgid = crgetrgid(cr);
		tlcred->tc_suid = crgetsuid(cr);
		tlcred->tc_sgid = crgetsgid(cr);
		tlcred->tc_ngroups = crgetngroups(cr);
	} else if (flag & TL_SETUCRED) {
		struct opthdr *opt = (struct opthdr *)buf;

		opt->level = TL_PROT_LEVEL;
		opt->name = TL_OPT_PEER_UCRED;
		opt->len = (t_uscalar_t)OPTLEN(ucredminsize(cr));

		(void) cred2ucred(cr, cpid, (void *)(opt + 1), pcr);
	} else {
		struct T_opthdr *topt = (struct T_opthdr *)buf;
		ASSERT(flag & TL_SOCKUCRED);

		topt->level = SOL_SOCKET;
		topt->name = SCM_UCRED;
		topt->len = ucredminsize(cr) + sizeof (*topt);
		topt->status = 0;
		(void) cred2ucred(cr, cpid, (void *)(topt + 1), pcr);
	}
}

/* ARGSUSED */
static int
tl_default_opt(queue_t *wq, int level, int name, uchar_t *ptr)
{
	/* no default value processed in protocol specific code currently */
	return (-1);
}

/* ARGSUSED */
static int
tl_get_opt(queue_t *wq, int level, int name, uchar_t *ptr)
{
	int len;
	tl_endpt_t *tep;
	int *valp;

	tep = (tl_endpt_t *)wq->q_ptr;

	len = 0;

	/*
	 * Assumes: option level and name sanity check done elsewhere
	 */

	switch (level) {
	case SOL_SOCKET:
		if (! IS_SOCKET(tep))
			break;
		switch (name) {
		case SO_RECVUCRED:
			len = sizeof (int);
			valp = (int *)ptr;
			*valp = (tep->te_flag & TL_SOCKUCRED) != 0;
			break;
		default:
			break;
		}
		break;
	case TL_PROT_LEVEL:
		switch (name) {
		case TL_OPT_PEER_CRED:
		case TL_OPT_PEER_UCRED:
			/*
			 * option not supposed to retrieved directly
			 * Only sent in T_CON_{IND,CON}, T_UNITDATA_IND
			 * when some internal flags set by other options
			 * Direct retrieval always designed to fail(ignored)
			 * for this option.
			 */
			break;
		}
	}
	return (len);
}

/* ARGSUSED */
static int
tl_set_opt(
	queue_t		*wq,
	uint_t		mgmt_flags,
	int		level,
	int		name,
	uint_t		inlen,
	uchar_t		*invalp,
	uint_t		*outlenp,
	uchar_t		*outvalp,
	void		*thisdg_attrs,
	cred_t		*cr)
{
	int error;
	tl_endpt_t *tep;

	tep = (tl_endpt_t *)wq->q_ptr;

	error = 0;		/* NOERROR */

	/*
	 * Assumes: option level and name sanity checks done elsewhere
	 */

	switch (level) {
	case SOL_SOCKET:
		if (! IS_SOCKET(tep)) {
			error = EINVAL;
			break;
		}
		/*
		 * TBD: fill in other AF_UNIX socket options and then stop
		 * returning error.
		 */
		switch (name) {
		case SO_RECVUCRED:
			/*
			 * We only support this for datagram sockets;
			 * getpeerucred handles the connection oriented
			 * transports.
			 */
			if (! IS_CLTS(tep)) {
				error = EINVAL;
				break;
			}
			if (*(int *)invalp == 0)
				tep->te_flag &= ~TL_SOCKUCRED;
			else
				tep->te_flag |= TL_SOCKUCRED;
			break;
		default:
			error = EINVAL;
			break;
		}
		break;
	case TL_PROT_LEVEL:
		switch (name) {
		case TL_OPT_PEER_CRED:
		case TL_OPT_PEER_UCRED:
			/*
			 * option not supposed to be set directly
			 * Its value in initialized for each endpoint at
			 * driver open time.
			 * Direct setting always designed to fail for this
			 * option.
			 */
			(void) (STRLOG(TL_ID, tep->te_minor, 1,
			    SL_TRACE|SL_ERROR,
			    "tl_set_opt: option is not supported"));
			error = EPROTO;
			break;
		}
	}
	return (error);
}


static void
tl_timer(void *arg)
{
	queue_t *wq = arg;
	tl_endpt_t *tep = (tl_endpt_t *)wq->q_ptr;

	ASSERT(tep);

	tep->te_timoutid = 0;

	enableok(wq);
	/*
	 * Note: can call wsrv directly here and save context switch
	 * Consider change when qtimeout (not timeout) is active
	 */
	qenable(wq);
}

static void
tl_buffer(void *arg)
{
	queue_t *wq = arg;
	tl_endpt_t *tep = (tl_endpt_t *)wq->q_ptr;

	ASSERT(tep);

	tep->te_bufcid = 0;
	tep->te_nowsrv = B_FALSE;

	enableok(wq);
	/*
	 *  Note: can call wsrv directly here and save context switch
	 * Consider change when qbufcall (not bufcall) is active
	 */
	qenable(wq);
}

static void
tl_memrecover(queue_t *wq, mblk_t *mp, size_t size)
{
	tl_endpt_t *tep;

	tep = (tl_endpt_t *)wq->q_ptr;

	if (tep->te_closing) {
		freemsg(mp);
		return;
	}
	noenable(wq);

	(void) insq(wq, wq->q_first, mp);

	if (tep->te_bufcid || tep->te_timoutid) {
		(void) (STRLOG(TL_ID, tep->te_minor, 1, SL_TRACE|SL_ERROR,
		    "tl_memrecover:recover %p pending", (void *)wq));
		return;
	}

	if (!(tep->te_bufcid = qbufcall(wq, size, BPRI_MED, tl_buffer, wq))) {
		tep->te_timoutid = qtimeout(wq, tl_timer, wq,
		    drv_usectohz(TL_BUFWAIT));
	}
}

static void
tl_freetip(tl_endpt_t *tep, tl_icon_t *tip)
{
	ASSERT(tip->ti_seqno != 0);

	if (tip->ti_mp != NULL) {
		tl_icon_freemsgs(&tip->ti_mp);
		tip->ti_mp = NULL;
	}
	if (tip->ti_tep != NULL) {
		tl_refrele(tip->ti_tep);
		tip->ti_tep = NULL;
	}
	list_remove(&tep->te_iconp, tip);
	kmem_free(tip, sizeof (tl_icon_t));
	tep->te_nicon--;
}

/*
 * Remove address from address hash.
 */
static void
tl_addr_unbind(tl_endpt_t *tep)
{
	tl_endpt_t *elp;

	if (tep->te_flag & TL_ADDRHASHED) {
		if (IS_SOCKET(tep)) {
			(void) mod_hash_remove(tep->te_addrhash,
			    (mod_hash_key_t)tep->te_vp,
			    (mod_hash_val_t *)&elp);
			tep->te_vp = (void *)(uintptr_t)tep->te_minor;
			tep->te_magic = SOU_MAGIC_IMPLICIT;
		} else {
			(void) mod_hash_remove(tep->te_addrhash,
			    (mod_hash_key_t)&tep->te_ap,
			    (mod_hash_val_t *)&elp);
			(void) kmem_free(tep->te_abuf, tep->te_alen);
			tep->te_alen = -1;
			tep->te_abuf = NULL;
		}
		tep->te_flag &= ~TL_ADDRHASHED;
	}
}
