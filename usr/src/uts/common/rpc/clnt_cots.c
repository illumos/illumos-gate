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
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T
 *		All Rights Reserved
 */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */


/*
 * Implements a kernel based, client side RPC over Connection Oriented
 * Transports (COTS).
 */

/*
 * Much of this file has been re-written to let NFS work better over slow
 * transports. A description follows.
 *
 * One of the annoying things about kRPC/COTS is that it will temporarily
 * create more than one connection between a client and server. This
 * happens because when a connection is made, the end-points entry in the
 * linked list of connections (headed by cm_hd), is removed so that other
 * threads don't mess with it. Went ahead and bit the bullet by keeping
 * the endpoint on the connection list and introducing state bits,
 * condition variables etc. to the connection entry data structure (struct
 * cm_xprt).
 *
 * Here is a summary of the changes to cm-xprt:
 *
 *	x_ctime is the timestamp of when the endpoint was last
 *	connected or disconnected. If an end-point is ever disconnected
 *	or re-connected, then any outstanding RPC request is presumed
 *	lost, telling clnt_cots_kcallit that it needs to re-send the
 *	request, not just wait for the original request's reply to
 *	arrive.
 *
 *	x_thread flag which tells us if a thread is doing a connection attempt.
 *
 *	x_waitdis flag which tells us we are waiting a disconnect ACK.
 *
 *	x_needdis flag which tells us we need to send a T_DISCONN_REQ
 *	to kill the connection.
 *
 *	x_needrel flag which tells us we need to send a T_ORDREL_REQ to
 *	gracefully close the connection.
 *
 *	#defined bitmasks for the all the b_* bits so that more
 *	efficient (and at times less clumsy) masks can be used to
 *	manipulated state in cases where multiple bits have to
 *	set/cleared/checked in the same critical section.
 *
 *	x_conn_cv and x_dis-_cv are new condition variables to let
 *	threads knows when the connection attempt is done, and to let
 *	the connecting thread know when the disconnect handshake is
 *	done.
 *
 * Added the CONN_HOLD() macro so that all reference holds have the same
 * look and feel.
 *
 * In the private (cku_private) portion of the client handle,
 *
 *	cku_flags replaces the cku_sent a boolean. cku_flags keeps
 *	track of whether a request as been sent, and whether the
 *	client's handles call record is on the dispatch list (so that
 *	the reply can be matched by XID to the right client handle).
 *	The idea of CKU_ONQUEUE is that we can exit clnt_cots_kcallit()
 *	and still have the response find the right client handle so
 *	that the retry of CLNT_CALL() gets the result. Testing, found
 *	situations where if the timeout was increased, performance
 *	degraded. This was due to us hitting a window where the thread
 *	was back in rfscall() (probably printing server not responding)
 *	while the response came back but no place to put it.
 *
 *	cku_ctime is just a cache of x_ctime. If they match,
 *	clnt_cots_kcallit() won't to send a retry (unless the maximum
 *	receive count limit as been reached). If the don't match, then
 *	we assume the request has been lost, and a retry of the request
 *	is needed.
 *
 *	cku_recv_attempts counts the number of receive count attempts
 *	after one try is sent on the wire.
 *
 * Added the clnt_delay() routine so that interruptible and
 * noninterruptible delays are possible.
 *
 * CLNT_MIN_TIMEOUT has been bumped to 10 seconds from 3. This is used to
 * control how long the client delays before returned after getting
 * ECONNREFUSED. At 3 seconds, 8 client threads per mount really does bash
 * a server that may be booting and not yet started nfsd.
 *
 * CLNT_MAXRECV_WITHOUT_RETRY is a new macro (value of 3) (with a tunable)
 * Why don't we just wait forever (receive an infinite # of times)?
 * Because the server may have rebooted. More insidious is that some
 * servers (ours) will drop NFS/TCP requests in some cases. This is bad,
 * but it is a reality.
 *
 * The case of a server doing orderly release really messes up the
 * client's recovery, especially if the server's TCP implementation is
 * buggy.  It was found was that the kRPC/COTS client was breaking some
 * TPI rules, such as not waiting for the acknowledgement of a
 * T_DISCON_REQ (hence the added case statements T_ERROR_ACK, T_OK_ACK and
 * T_DISCON_REQ in clnt_dispatch_notifyall()).
 *
 * One of things that we've seen is that a kRPC TCP endpoint goes into
 * TIMEWAIT and a thus a reconnect takes a long time to satisfy because
 * that the TIMEWAIT state takes a while to finish.  If a server sends a
 * T_ORDREL_IND, there is little point in an RPC client doing a
 * T_ORDREL_REQ, because the RPC request isn't going to make it (the
 * server is saying that it won't accept any more data). So kRPC was
 * changed to send a T_DISCON_REQ when we get a T_ORDREL_IND. So now the
 * connection skips the TIMEWAIT state and goes straight to a bound state
 * that kRPC can quickly switch to connected.
 *
 * Code that issues TPI request must use waitforack() to wait for the
 * corresponding ack (assuming there is one) in any future modifications.
 * This works around problems that may be introduced by breaking TPI rules
 * (by submitting new calls before earlier requests have been acked) in the
 * case of a signal or other early return.  waitforack() depends on
 * clnt_dispatch_notifyconn() to issue the wakeup when the ack
 * arrives, so adding new TPI calls may require corresponding changes
 * to clnt_dispatch_notifyconn(). Presently, the timeout period is based on
 * CLNT_MIN_TIMEOUT which is 10 seconds. If you modify this value, be sure
 * not to set it too low or TPI ACKS will be lost.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/timod.h>
#include <sys/tiuser.h>
#include <sys/tihdr.h>
#include <sys/t_kuser.h>
#include <sys/fcntl.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/systm.h>
#include <sys/kstat.h>
#include <sys/t_lock.h>
#include <sys/ddi.h>
#include <sys/cmn_err.h>
#include <sys/time.h>
#include <sys/isa_defs.h>
#include <sys/callb.h>
#include <sys/sunddi.h>
#include <sys/atomic.h>
#include <sys/sdt.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <rpc/rpc_msg.h>

#define	COTS_DEFAULT_ALLOCSIZE	2048

#define	WIRE_HDR_SIZE	20	/* serialized call header, sans proc number */
#define	MSG_OFFSET	128	/* offset of call into the mblk */

const char *kinet_ntop6(uchar_t *, char *, size_t);

static int	clnt_cots_ksettimers(CLIENT *, struct rpc_timers *,
    struct rpc_timers *, int, void(*)(int, int, caddr_t), caddr_t, uint32_t);
static enum clnt_stat	clnt_cots_kcallit(CLIENT *, rpcproc_t, xdrproc_t,
    caddr_t, xdrproc_t, caddr_t, struct timeval);
static void	clnt_cots_kabort(CLIENT *);
static void	clnt_cots_kerror(CLIENT *, struct rpc_err *);
static bool_t	clnt_cots_kfreeres(CLIENT *, xdrproc_t, caddr_t);
static void	clnt_cots_kdestroy(CLIENT *);
static bool_t	clnt_cots_kcontrol(CLIENT *, int, char *);


/* List of transports managed by the connection manager. */
struct cm_xprt {
	TIUSER		*x_tiptr;	/* transport handle */
	queue_t		*x_wq;		/* send queue */
	clock_t		x_time;		/* last time we handed this xprt out */
	clock_t		x_ctime;	/* time we went to CONNECTED */
	int		x_tidu_size;    /* TIDU size of this transport */
	union {
	    struct {
		unsigned int
#ifdef	_BIT_FIELDS_HTOL
		b_closing:	1,	/* we've sent a ord rel on this conn */
		b_dead:		1,	/* transport is closed or disconn */
		b_doomed:	1,	/* too many conns, let this go idle */
		b_connected:	1,	/* this connection is connected */

		b_ordrel:	1,	/* do an orderly release? */
		b_thread:	1,	/* thread doing connect */
		b_waitdis:	1,	/* waiting for disconnect ACK */
		b_needdis:	1,	/* need T_DISCON_REQ */

		b_needrel:	1,	/* need T_ORDREL_REQ */
		b_early_disc:	1,	/* got a T_ORDREL_IND or T_DISCON_IND */
					/* disconnect during connect */

		b_pad:		22;

#endif

#ifdef	_BIT_FIELDS_LTOH
		b_pad:		22,

		b_early_disc:	1,	/* got a T_ORDREL_IND or T_DISCON_IND */
					/* disconnect during connect */
		b_needrel:	1,	/* need T_ORDREL_REQ */

		b_needdis:	1,	/* need T_DISCON_REQ */
		b_waitdis:	1,	/* waiting for disconnect ACK */
		b_thread:	1,	/* thread doing connect */
		b_ordrel:	1,	/* do an orderly release? */

		b_connected:	1,	/* this connection is connected */
		b_doomed:	1,	/* too many conns, let this go idle */
		b_dead:		1,	/* transport is closed or disconn */
		b_closing:	1;	/* we've sent a ord rel on this conn */
#endif
	    } bit;	    unsigned int word;

#define	x_closing	x_state.bit.b_closing
#define	x_dead		x_state.bit.b_dead
#define	x_doomed	x_state.bit.b_doomed
#define	x_connected	x_state.bit.b_connected

#define	x_ordrel	x_state.bit.b_ordrel
#define	x_thread	x_state.bit.b_thread
#define	x_waitdis	x_state.bit.b_waitdis
#define	x_needdis	x_state.bit.b_needdis

#define	x_needrel	x_state.bit.b_needrel
#define	x_early_disc    x_state.bit.b_early_disc

#define	x_state_flags	x_state.word

#define	X_CLOSING	0x80000000
#define	X_DEAD		0x40000000
#define	X_DOOMED	0x20000000
#define	X_CONNECTED	0x10000000

#define	X_ORDREL	0x08000000
#define	X_THREAD	0x04000000
#define	X_WAITDIS	0x02000000
#define	X_NEEDDIS	0x01000000

#define	X_NEEDREL	0x00800000
#define	X_EARLYDISC	0x00400000

#define	X_BADSTATES	(X_CLOSING | X_DEAD | X_DOOMED)

	}		x_state;
	int		x_ref;		/* number of users of this xprt */
	int		x_family;	/* address family of transport */
	dev_t		x_rdev;		/* device number of transport */
	struct cm_xprt	*x_next;

	struct netbuf	x_server;	/* destination address */
	struct netbuf	x_src;		/* src address (for retries) */
	kmutex_t	x_lock;		/* lock on this entry */
	kcondvar_t	x_cv;		/* to signal when can be closed */
	kcondvar_t	x_conn_cv;	/* to signal when connection attempt */
					/* is complete */
	kstat_t		*x_ksp;

	kcondvar_t	x_dis_cv;	/* to signal when disconnect attempt */
					/* is complete */
	zoneid_t	x_zoneid;	/* zone this xprt belongs to */
};

typedef struct cm_kstat_xprt {
	kstat_named_t	x_wq;
	kstat_named_t	x_server;
	kstat_named_t	x_family;
	kstat_named_t	x_rdev;
	kstat_named_t	x_time;
	kstat_named_t	x_state;
	kstat_named_t	x_ref;
	kstat_named_t	x_port;
} cm_kstat_xprt_t;

static cm_kstat_xprt_t cm_kstat_template = {
	{ "write_queue", KSTAT_DATA_UINT32 },
	{ "server",	KSTAT_DATA_STRING },
	{ "addr_family", KSTAT_DATA_UINT32 },
	{ "device",	KSTAT_DATA_UINT32 },
	{ "time_stamp",	KSTAT_DATA_UINT32 },
	{ "status",	KSTAT_DATA_UINT32 },
	{ "ref_count",	KSTAT_DATA_INT32 },
	{ "port",	KSTAT_DATA_UINT32 },
};

/*
 * The inverse of this is connmgr_release().
 */
#define	CONN_HOLD(Cm_entry)	{\
	mutex_enter(&(Cm_entry)->x_lock);	\
	(Cm_entry)->x_ref++;	\
	mutex_exit(&(Cm_entry)->x_lock);	\
}


/*
 * Private data per rpc handle.  This structure is allocated by
 * clnt_cots_kcreate, and freed by clnt_cots_kdestroy.
 */
typedef struct cku_private_s {
	CLIENT			cku_client;	/* client handle */
	calllist_t		cku_call;	/* for dispatching calls */
	struct rpc_err		cku_err;	/* error status */

	struct netbuf		cku_srcaddr;	/* source address for retries */
	int			cku_addrfmly;  /* for binding port */
	struct netbuf		cku_addr;	/* remote address */
	dev_t			cku_device;	/* device to use */
	uint_t			cku_flags;
#define	CKU_ONQUEUE		0x1
#define	CKU_SENT		0x2

	bool_t			cku_progress;	/* for CLSET_PROGRESS */
	uint32_t		cku_xid;	/* current XID */
	clock_t			cku_ctime;	/* time stamp of when */
						/* connection was created */
	uint_t			cku_recv_attempts;
	XDR			cku_outxdr;	/* xdr routine for output */
	XDR			cku_inxdr;	/* xdr routine for input */
	char			cku_rpchdr[WIRE_HDR_SIZE + 4];
						/* pre-serialized rpc header */

	uint_t			cku_outbuflen;	/* default output mblk length */
	struct cred		*cku_cred;	/* credentials */
	bool_t			cku_nodelayonerr;
						/* for CLSET_NODELAYONERR */
	int			cku_useresvport; /* Use reserved port */
	struct rpc_cots_client	*cku_stats;	/* stats for zone */
} cku_private_t;

static struct cm_xprt *connmgr_wrapconnect(struct cm_xprt *,
	const struct timeval *, struct netbuf *, int, struct netbuf *,
	struct rpc_err *, bool_t, bool_t, cred_t *);

static bool_t	connmgr_connect(struct cm_xprt *, queue_t *, struct netbuf *,
				int, calllist_t *, int *, bool_t reconnect,
				const struct timeval *, bool_t, cred_t *);

static void	*connmgr_opt_getoff(mblk_t *mp, t_uscalar_t offset,
				t_uscalar_t length, uint_t align_size);
static bool_t	connmgr_setbufsz(calllist_t *e, queue_t *wq, cred_t *cr);
static bool_t	connmgr_getopt_int(queue_t *wq, int level, int name, int *val,
				calllist_t *e, cred_t *cr);
static bool_t	connmgr_setopt_int(queue_t *wq, int level, int name, int val,
				calllist_t *e, cred_t *cr);
static bool_t	connmgr_setopt(queue_t *, int, int, calllist_t *, cred_t *cr);
static void	connmgr_sndrel(struct cm_xprt *);
static void	connmgr_snddis(struct cm_xprt *);
static void	connmgr_close(struct cm_xprt *);
static void	connmgr_release(struct cm_xprt *);
static struct cm_xprt *connmgr_wrapget(struct netbuf *, const struct timeval *,
	cku_private_t *);

static struct cm_xprt *connmgr_get(struct netbuf *, const struct timeval *,
	struct netbuf *, int, struct netbuf *, struct rpc_err *, dev_t,
	bool_t, int, cred_t *);

static void connmgr_cancelconn(struct cm_xprt *);
static enum clnt_stat connmgr_cwait(struct cm_xprt *, const struct timeval *,
	bool_t);
static void connmgr_dis_and_wait(struct cm_xprt *);

static int	clnt_dispatch_send(queue_t *, mblk_t *, calllist_t *, uint_t,
					uint_t);

static int clnt_delay(clock_t, bool_t);

static int waitforack(calllist_t *, t_scalar_t, const struct timeval *, bool_t);

/*
 * Operations vector for TCP/IP based RPC
 */
static struct clnt_ops tcp_ops = {
	clnt_cots_kcallit,	/* do rpc call */
	clnt_cots_kabort,	/* abort call */
	clnt_cots_kerror,	/* return error status */
	clnt_cots_kfreeres,	/* free results */
	clnt_cots_kdestroy,	/* destroy rpc handle */
	clnt_cots_kcontrol,	/* the ioctl() of rpc */
	clnt_cots_ksettimers,	/* set retry timers */
};

static int rpc_kstat_instance = 0;  /* keeps the current instance */
				/* number for the next kstat_create */

static struct cm_xprt *cm_hd = NULL;
static kmutex_t connmgr_lock;	/* for connection mngr's list of transports */

extern kmutex_t clnt_max_msg_lock;

static calllist_t *clnt_pending = NULL;
extern kmutex_t clnt_pending_lock;

static int clnt_cots_hash_size = DEFAULT_HASH_SIZE;

static call_table_t *cots_call_ht;

static const struct rpc_cots_client {
	kstat_named_t	rccalls;
	kstat_named_t	rcbadcalls;
	kstat_named_t	rcbadxids;
	kstat_named_t	rctimeouts;
	kstat_named_t	rcnewcreds;
	kstat_named_t	rcbadverfs;
	kstat_named_t	rctimers;
	kstat_named_t	rccantconn;
	kstat_named_t	rcnomem;
	kstat_named_t	rcintrs;
} cots_rcstat_tmpl = {
	{ "calls",	KSTAT_DATA_UINT64 },
	{ "badcalls",	KSTAT_DATA_UINT64 },
	{ "badxids",	KSTAT_DATA_UINT64 },
	{ "timeouts",	KSTAT_DATA_UINT64 },
	{ "newcreds",	KSTAT_DATA_UINT64 },
	{ "badverfs",	KSTAT_DATA_UINT64 },
	{ "timers",	KSTAT_DATA_UINT64 },
	{ "cantconn",	KSTAT_DATA_UINT64 },
	{ "nomem",	KSTAT_DATA_UINT64 },
	{ "interrupts", KSTAT_DATA_UINT64 }
};

#define	COTSRCSTAT_INCR(p, x)	\
	atomic_inc_64(&(p)->x.value.ui64)

#define	CLNT_MAX_CONNS	1	/* concurrent connections between clnt/srvr */
int clnt_max_conns = CLNT_MAX_CONNS;

#define	CLNT_MIN_TIMEOUT	10	/* seconds to wait after we get a */
					/* connection reset */
#define	CLNT_MIN_CONNTIMEOUT	5	/* seconds to wait for a connection */


int clnt_cots_min_tout = CLNT_MIN_TIMEOUT;
int clnt_cots_min_conntout = CLNT_MIN_CONNTIMEOUT;

/*
 * Limit the number of times we will attempt to receive a reply without
 * re-sending a response.
 */
#define	CLNT_MAXRECV_WITHOUT_RETRY	3
uint_t clnt_cots_maxrecv	= CLNT_MAXRECV_WITHOUT_RETRY;

uint_t *clnt_max_msg_sizep;
void (*clnt_stop_idle)(queue_t *wq);

#define	ptoh(p)		(&((p)->cku_client))
#define	htop(h)		((cku_private_t *)((h)->cl_private))

/*
 * Times to retry
 */
#define	REFRESHES	2	/* authentication refreshes */

/*
 * The following is used to determine the global default behavior for
 * COTS when binding to a local port.
 *
 * If the value is set to 1 the default will be to select a reserved
 * (aka privileged) port, if the value is zero the default will be to
 * use non-reserved ports.  Users of kRPC may override this by using
 * CLNT_CONTROL() and CLSET_BINDRESVPORT.
 */
int clnt_cots_do_bindresvport = 1;

static zone_key_t zone_cots_key;

/*
 * Defaults TCP send and receive buffer size for RPC connections.
 * These values can be tuned by /etc/system.
 */
int rpc_send_bufsz = 1024*1024;
int rpc_recv_bufsz = 1024*1024;
/*
 * To use system-wide default for TCP send and receive buffer size,
 * use /etc/system to set rpc_default_tcp_bufsz to 1:
 *
 * set rpcmod:rpc_default_tcp_bufsz=1
 */
int rpc_default_tcp_bufsz = 0;

/*
 * We need to do this after all kernel threads in the zone have exited.
 */
/* ARGSUSED */
static void
clnt_zone_destroy(zoneid_t zoneid, void *unused)
{
	struct cm_xprt **cmp;
	struct cm_xprt *cm_entry;
	struct cm_xprt *freelist = NULL;

	mutex_enter(&connmgr_lock);
	cmp = &cm_hd;
	while ((cm_entry = *cmp) != NULL) {
		if (cm_entry->x_zoneid == zoneid) {
			*cmp = cm_entry->x_next;
			cm_entry->x_next = freelist;
			freelist = cm_entry;
		} else {
			cmp = &cm_entry->x_next;
		}
	}
	mutex_exit(&connmgr_lock);
	while ((cm_entry = freelist) != NULL) {
		freelist = cm_entry->x_next;
		connmgr_close(cm_entry);
	}
}

int
clnt_cots_kcreate(dev_t dev, struct netbuf *addr, int family, rpcprog_t prog,
    rpcvers_t vers, uint_t max_msgsize, cred_t *cred, CLIENT **ncl)
{
	CLIENT *h;
	cku_private_t *p;
	struct rpc_msg call_msg;
	struct rpcstat *rpcstat;

	RPCLOG(8, "clnt_cots_kcreate: prog %u\n", prog);

	rpcstat = zone_getspecific(rpcstat_zone_key, rpc_zone());
	ASSERT(rpcstat != NULL);

	/* Allocate and intialize the client handle. */
	p = kmem_zalloc(sizeof (*p), KM_SLEEP);

	h = ptoh(p);

	h->cl_private = (caddr_t)p;
	h->cl_auth = authkern_create();
	h->cl_ops = &tcp_ops;

	cv_init(&p->cku_call.call_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&p->cku_call.call_lock, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * If the current sanity check size in rpcmod is smaller
	 * than the size needed, then increase the sanity check.
	 */
	if (max_msgsize != 0 && clnt_max_msg_sizep != NULL &&
	    max_msgsize > *clnt_max_msg_sizep) {
		mutex_enter(&clnt_max_msg_lock);
		if (max_msgsize > *clnt_max_msg_sizep)
			*clnt_max_msg_sizep = max_msgsize;
		mutex_exit(&clnt_max_msg_lock);
	}

	p->cku_outbuflen = COTS_DEFAULT_ALLOCSIZE;

	/* Preserialize the call message header */

	call_msg.rm_xid = 0;
	call_msg.rm_direction = CALL;
	call_msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
	call_msg.rm_call.cb_prog = prog;
	call_msg.rm_call.cb_vers = vers;

	xdrmem_create(&p->cku_outxdr, p->cku_rpchdr, WIRE_HDR_SIZE, XDR_ENCODE);

	if (!xdr_callhdr(&p->cku_outxdr, &call_msg)) {
		XDR_DESTROY(&p->cku_outxdr);
		RPCLOG0(1, "clnt_cots_kcreate - Fatal header serialization "
		    "error\n");
		auth_destroy(h->cl_auth);
		kmem_free(p, sizeof (cku_private_t));
		RPCLOG0(1, "clnt_cots_kcreate: create failed error EINVAL\n");
		return (EINVAL);		/* XXX */
	}
	XDR_DESTROY(&p->cku_outxdr);

	/*
	 * The zalloc initialized the fields below.
	 * p->cku_xid = 0;
	 * p->cku_flags = 0;
	 * p->cku_srcaddr.len = 0;
	 * p->cku_srcaddr.maxlen = 0;
	 */

	p->cku_cred = cred;
	p->cku_device = dev;
	p->cku_addrfmly = family;
	p->cku_addr.buf = kmem_zalloc(addr->maxlen, KM_SLEEP);
	p->cku_addr.maxlen = addr->maxlen;
	p->cku_addr.len = addr->len;
	bcopy(addr->buf, p->cku_addr.buf, addr->len);
	p->cku_stats = rpcstat->rpc_cots_client;
	p->cku_useresvport = -1; /* value is has not been set */

	*ncl = h;
	return (0);
}

/*ARGSUSED*/
static void
clnt_cots_kabort(CLIENT *h)
{
}

/*
 * Return error info on this handle.
 */
static void
clnt_cots_kerror(CLIENT *h, struct rpc_err *err)
{
	/* LINTED pointer alignment */
	cku_private_t *p = htop(h);

	*err = p->cku_err;
}

/*ARGSUSED*/
static bool_t
clnt_cots_kfreeres(CLIENT *h, xdrproc_t xdr_res, caddr_t res_ptr)
{
	xdr_free(xdr_res, res_ptr);

	return (TRUE);
}

static bool_t
clnt_cots_kcontrol(CLIENT *h, int cmd, char *arg)
{
	cku_private_t *p = htop(h);

	switch (cmd) {
	case CLSET_PROGRESS:
		p->cku_progress = TRUE;
		return (TRUE);

	case CLSET_XID:
		if (arg == NULL)
			return (FALSE);

		p->cku_xid = *((uint32_t *)arg);
		return (TRUE);

	case CLGET_XID:
		if (arg == NULL)
			return (FALSE);

		*((uint32_t *)arg) = p->cku_xid;
		return (TRUE);

	case CLSET_NODELAYONERR:
		if (arg == NULL)
			return (FALSE);

		if (*((bool_t *)arg) == TRUE) {
			p->cku_nodelayonerr = TRUE;
			return (TRUE);
		}
		if (*((bool_t *)arg) == FALSE) {
			p->cku_nodelayonerr = FALSE;
			return (TRUE);
		}
		return (FALSE);

	case CLGET_NODELAYONERR:
		if (arg == NULL)
			return (FALSE);

		*((bool_t *)arg) = p->cku_nodelayonerr;
		return (TRUE);

	case CLSET_BINDRESVPORT:
		if (arg == NULL)
			return (FALSE);

		if (*(int *)arg != 1 && *(int *)arg != 0)
			return (FALSE);

		p->cku_useresvport = *(int *)arg;

		return (TRUE);

	case CLGET_BINDRESVPORT:
		if (arg == NULL)
			return (FALSE);

		*(int *)arg = p->cku_useresvport;

		return (TRUE);

	default:
		return (FALSE);
	}
}

/*
 * Destroy rpc handle.  Frees the space used for output buffer,
 * private data, and handle structure.
 */
static void
clnt_cots_kdestroy(CLIENT *h)
{
	/* LINTED pointer alignment */
	cku_private_t *p = htop(h);
	calllist_t *call = &p->cku_call;

	RPCLOG(8, "clnt_cots_kdestroy h: %p\n", (void *)h);
	RPCLOG(8, "clnt_cots_kdestroy h: xid=0x%x\n", p->cku_xid);

	if (p->cku_flags & CKU_ONQUEUE) {
		RPCLOG(64, "clnt_cots_kdestroy h: removing call for xid 0x%x "
		    "from dispatch list\n", p->cku_xid);
		call_table_remove(call);
	}

	if (call->call_reply)
		freemsg(call->call_reply);
	cv_destroy(&call->call_cv);
	mutex_destroy(&call->call_lock);

	kmem_free(p->cku_srcaddr.buf, p->cku_srcaddr.maxlen);
	kmem_free(p->cku_addr.buf, p->cku_addr.maxlen);
	kmem_free(p, sizeof (*p));
}

static int clnt_cots_pulls;
#define	RM_HDR_SIZE	4	/* record mark header size */

/*
 * Call remote procedure.
 */
static enum clnt_stat
clnt_cots_kcallit(CLIENT *h, rpcproc_t procnum, xdrproc_t xdr_args,
    caddr_t argsp, xdrproc_t xdr_results, caddr_t resultsp, struct timeval wait)
{
	/* LINTED pointer alignment */
	cku_private_t *p = htop(h);
	calllist_t *call = &p->cku_call;
	XDR *xdrs;
	struct rpc_msg reply_msg;
	mblk_t *mp;
#ifdef	RPCDEBUG
	clock_t time_sent;
#endif
	struct netbuf *retryaddr;
	struct cm_xprt *cm_entry = NULL;
	queue_t *wq;
	int len, waitsecs, max_waitsecs;
	int mpsize;
	int refreshes = REFRESHES;
	int interrupted;
	int tidu_size;
	enum clnt_stat status;
	struct timeval cwait;
	bool_t delay_first = FALSE;
	clock_t ticks, now;

	RPCLOG(2, "clnt_cots_kcallit, procnum %u\n", procnum);
	COTSRCSTAT_INCR(p->cku_stats, rccalls);

	RPCLOG(2, "clnt_cots_kcallit: wait.tv_sec: %ld\n", wait.tv_sec);
	RPCLOG(2, "clnt_cots_kcallit: wait.tv_usec: %ld\n", wait.tv_usec);
	/*
	 * Bug ID 1240234:
	 * Look out for zero length timeouts. We don't want to
	 * wait zero seconds for a connection to be established.
	 */
	if (wait.tv_sec < clnt_cots_min_conntout) {
		cwait.tv_sec = clnt_cots_min_conntout;
		cwait.tv_usec = 0;
		RPCLOG(8, "clnt_cots_kcallit: wait.tv_sec (%ld) too low,",
		    wait.tv_sec);
		RPCLOG(8, " setting to: %d\n", clnt_cots_min_conntout);
	} else {
		cwait = wait;
	}

call_again:
	if (cm_entry) {
		connmgr_release(cm_entry);
		cm_entry = NULL;
	}

	mp = NULL;

	/*
	 * If the call is not a retry, allocate a new xid and cache it
	 * for future retries.
	 * Bug ID 1246045:
	 * Treat call as a retry for purposes of binding the source
	 * port only if we actually attempted to send anything on
	 * the previous call.
	 */
	if (p->cku_xid == 0) {
		p->cku_xid = alloc_xid();
		call->call_zoneid = rpc_zoneid();

		/*
		 * We need to ASSERT here that our xid != 0 because this
		 * determines whether or not our call record gets placed on
		 * the hash table or the linked list.  By design, we mandate
		 * that RPC calls over cots must have xid's != 0, so we can
		 * ensure proper management of the hash table.
		 */
		ASSERT(p->cku_xid != 0);

		retryaddr = NULL;
		p->cku_flags &= ~CKU_SENT;

		if (p->cku_flags & CKU_ONQUEUE) {
			RPCLOG(8, "clnt_cots_kcallit: new call, dequeuing old"
			    " one (%p)\n", (void *)call);
			call_table_remove(call);
			p->cku_flags &= ~CKU_ONQUEUE;
			RPCLOG(64, "clnt_cots_kcallit: removing call from "
			    "dispatch list because xid was zero (now 0x%x)\n",
			    p->cku_xid);
		}

		if (call->call_reply != NULL) {
			freemsg(call->call_reply);
			call->call_reply = NULL;
		}
	} else if (p->cku_srcaddr.buf == NULL || p->cku_srcaddr.len == 0) {
		retryaddr = NULL;

	} else if (p->cku_flags & CKU_SENT) {
		retryaddr = &p->cku_srcaddr;

	} else {
		/*
		 * Bug ID 1246045: Nothing was sent, so set retryaddr to
		 * NULL and let connmgr_get() bind to any source port it
		 * can get.
		 */
		retryaddr = NULL;
	}

	RPCLOG(64, "clnt_cots_kcallit: xid = 0x%x", p->cku_xid);
	RPCLOG(64, " flags = 0x%x\n", p->cku_flags);

	p->cku_err.re_status = RPC_TIMEDOUT;
	p->cku_err.re_errno = p->cku_err.re_terrno = 0;

	cm_entry = connmgr_wrapget(retryaddr, &cwait, p);

	if (cm_entry == NULL) {
		RPCLOG(1, "clnt_cots_kcallit: can't connect status %s\n",
		    clnt_sperrno(p->cku_err.re_status));

		/*
		 * The reasons why we fail to create a connection are
		 * varied. In most cases we don't want the caller to
		 * immediately retry. This could have one or more
		 * bad effects. This includes flooding the net with
		 * connect requests to ports with no listener; a hard
		 * kernel loop due to all the "reserved" TCP ports being
		 * in use.
		 */
		delay_first = TRUE;

		/*
		 * Even if we end up returning EINTR, we still count a
		 * a "can't connect", because the connection manager
		 * might have been committed to waiting for or timing out on
		 * a connection.
		 */
		COTSRCSTAT_INCR(p->cku_stats, rccantconn);
		switch (p->cku_err.re_status) {
		case RPC_INTR:
			p->cku_err.re_errno = EINTR;

			/*
			 * No need to delay because a UNIX signal(2)
			 * interrupted us. The caller likely won't
			 * retry the CLNT_CALL() and even if it does,
			 * we assume the caller knows what it is doing.
			 */
			delay_first = FALSE;
			break;

		case RPC_TIMEDOUT:
			p->cku_err.re_errno = ETIMEDOUT;

			/*
			 * No need to delay because timed out already
			 * on the connection request and assume that the
			 * transport time out is longer than our minimum
			 * timeout, or least not too much smaller.
			 */
			delay_first = FALSE;
			break;

		case RPC_SYSTEMERROR:
		case RPC_TLIERROR:
			/*
			 * We want to delay here because a transient
			 * system error has a better chance of going away
			 * if we delay a bit. If it's not transient, then
			 * we don't want end up in a hard kernel loop
			 * due to retries.
			 */
			ASSERT(p->cku_err.re_errno != 0);
			break;


		case RPC_CANTCONNECT:
			/*
			 * RPC_CANTCONNECT is set on T_ERROR_ACK which
			 * implies some error down in the TCP layer or
			 * below. If cku_nodelayonerror is set then we
			 * assume the caller knows not to try too hard.
			 */
			RPCLOG0(8, "clnt_cots_kcallit: connection failed,");
			RPCLOG0(8, " re_status=RPC_CANTCONNECT,");
			RPCLOG(8, " re_errno=%d,", p->cku_err.re_errno);
			RPCLOG(8, " cku_nodelayonerr=%d", p->cku_nodelayonerr);
			if (p->cku_nodelayonerr == TRUE)
				delay_first = FALSE;

			p->cku_err.re_errno = EIO;

			break;

		case RPC_XPRTFAILED:
			/*
			 * We want to delay here because we likely
			 * got a refused connection.
			 */
			if (p->cku_err.re_errno == 0)
				p->cku_err.re_errno = EIO;

			RPCLOG(1, "clnt_cots_kcallit: transport failed: %d\n",
			    p->cku_err.re_errno);

			break;

		default:
			/*
			 * We delay here because it is better to err
			 * on the side of caution. If we got here then
			 * status could have been RPC_SUCCESS, but we
			 * know that we did not get a connection, so
			 * force the rpc status to RPC_CANTCONNECT.
			 */
			p->cku_err.re_status = RPC_CANTCONNECT;
			p->cku_err.re_errno = EIO;
			break;
		}
		if (delay_first == TRUE)
			ticks = clnt_cots_min_tout * drv_usectohz(1000000);
		goto cots_done;
	}

	/*
	 * If we've never sent any request on this connection (send count
	 * is zero, or the connection has been reset), cache the
	 * the connection's create time and send a request (possibly a retry)
	 */
	if ((p->cku_flags & CKU_SENT) == 0 ||
	    p->cku_ctime != cm_entry->x_ctime) {
		p->cku_ctime = cm_entry->x_ctime;

	} else if ((p->cku_flags & CKU_SENT) && (p->cku_flags & CKU_ONQUEUE) &&
	    (call->call_reply != NULL ||
	    p->cku_recv_attempts < clnt_cots_maxrecv)) {

		/*
		 * If we've sent a request and our call is on the dispatch
		 * queue and we haven't made too many receive attempts, then
		 * don't re-send, just receive.
		 */
		p->cku_recv_attempts++;
		goto read_again;
	}

	/*
	 * Now we create the RPC request in a STREAMS message.  We have to do
	 * this after the call to connmgr_get so that we have the correct
	 * TIDU size for the transport.
	 */
	tidu_size = cm_entry->x_tidu_size;
	len = MSG_OFFSET + MAX(tidu_size, RM_HDR_SIZE + WIRE_HDR_SIZE);

	while ((mp = allocb(len, BPRI_MED)) == NULL) {
		if (strwaitbuf(len, BPRI_MED)) {
			p->cku_err.re_status = RPC_SYSTEMERROR;
			p->cku_err.re_errno = ENOSR;
			COTSRCSTAT_INCR(p->cku_stats, rcnomem);
			goto cots_done;
		}
	}
	xdrs = &p->cku_outxdr;
	xdrmblk_init(xdrs, mp, XDR_ENCODE, tidu_size);
	mpsize = MBLKSIZE(mp);
	ASSERT(mpsize >= len);
	ASSERT(mp->b_rptr == mp->b_datap->db_base);

	/*
	 * If the size of mblk is not appreciably larger than what we
	 * asked, then resize the mblk to exactly len bytes. The reason for
	 * this: suppose len is 1600 bytes, the tidu is 1460 bytes
	 * (from TCP over ethernet), and the arguments to the RPC require
	 * 2800 bytes. Ideally we want the protocol to render two
	 * ~1400 byte segments over the wire. However if allocb() gives us a 2k
	 * mblk, and we allocate a second mblk for the remainder, the protocol
	 * module may generate 3 segments over the wire:
	 * 1460 bytes for the first, 448 (2048 - 1600) for the second, and
	 * 892 for the third. If we "waste" 448 bytes in the first mblk,
	 * the XDR encoding will generate two ~1400 byte mblks, and the
	 * protocol module is more likely to produce properly sized segments.
	 */
	if ((mpsize >> 1) <= len)
		mp->b_rptr += (mpsize - len);

	/*
	 * Adjust b_rptr to reserve space for the non-data protocol headers
	 * any downstream modules might like to add, and for the
	 * record marking header.
	 */
	mp->b_rptr += (MSG_OFFSET + RM_HDR_SIZE);

	if (h->cl_auth->ah_cred.oa_flavor != RPCSEC_GSS) {
		/* Copy in the preserialized RPC header information. */
		bcopy(p->cku_rpchdr, mp->b_rptr, WIRE_HDR_SIZE);

		/* Use XDR_SETPOS() to set the b_wptr to past the RPC header. */
		XDR_SETPOS(xdrs, (uint_t)(mp->b_rptr - mp->b_datap->db_base +
		    WIRE_HDR_SIZE));

		ASSERT((mp->b_wptr - mp->b_rptr) == WIRE_HDR_SIZE);

		/* Serialize the procedure number and the arguments. */
		if ((!XDR_PUTINT32(xdrs, (int32_t *)&procnum)) ||
		    (!AUTH_MARSHALL(h->cl_auth, xdrs, p->cku_cred)) ||
		    (!(*xdr_args)(xdrs, argsp))) {
			XDR_DESTROY(xdrs);
			p->cku_err.re_status = RPC_CANTENCODEARGS;
			p->cku_err.re_errno = EIO;
			goto cots_done;
		}

		(*(uint32_t *)(mp->b_rptr)) = p->cku_xid;
	} else {
		uint32_t *uproc = (uint32_t *)&p->cku_rpchdr[WIRE_HDR_SIZE];
		IXDR_PUT_U_INT32(uproc, procnum);

		(*(uint32_t *)(&p->cku_rpchdr[0])) = p->cku_xid;

		/* Use XDR_SETPOS() to set the b_wptr. */
		XDR_SETPOS(xdrs, (uint_t)(mp->b_rptr - mp->b_datap->db_base));

		/* Serialize the procedure number and the arguments. */
		if (!AUTH_WRAP(h->cl_auth, p->cku_rpchdr, WIRE_HDR_SIZE+4,
		    xdrs, xdr_args, argsp)) {
			XDR_DESTROY(xdrs);
			p->cku_err.re_status = RPC_CANTENCODEARGS;
			p->cku_err.re_errno = EIO;
			goto cots_done;
		}
	}

	XDR_DESTROY(xdrs);

	RPCLOG(2, "clnt_cots_kcallit: connected, sending call, tidu_size %d\n",
	    tidu_size);

	wq = cm_entry->x_wq;
	waitsecs = 0;

dispatch_again:
	status = clnt_dispatch_send(wq, mp, call, p->cku_xid,
	    (p->cku_flags & CKU_ONQUEUE));

	if ((status == RPC_CANTSEND) && (call->call_reason == ENOBUFS)) {
		/*
		 * QFULL condition, allow some time for queue to drain
		 * and try again. Give up after waiting for all timeout
		 * specified for the call, or zone is going away.
		 */
		max_waitsecs = wait.tv_sec ? wait.tv_sec : clnt_cots_min_tout;
		if ((waitsecs++ < max_waitsecs) &&
		    !(zone_status_get(curproc->p_zone) >=
		    ZONE_IS_SHUTTING_DOWN)) {

			/* wait 1 sec for queue to drain */
			if (clnt_delay(drv_usectohz(1000000),
			    h->cl_nosignal) == EINTR) {
				p->cku_err.re_errno = EINTR;
				p->cku_err.re_status = RPC_INTR;

				goto cots_done;
			}

			/* and try again */
			goto dispatch_again;
		}
		p->cku_err.re_status = status;
		p->cku_err.re_errno = call->call_reason;
		DTRACE_PROBE(krpc__e__clntcots__kcallit__cantsend);

		goto cots_done;
	}

	if (waitsecs) {
		/* adjust timeout to account for time wait to send */
		wait.tv_sec -= waitsecs;
		if (wait.tv_sec < 0) {
			/* pick up reply on next retry */
			wait.tv_sec = 0;
		}
		DTRACE_PROBE2(clnt_cots__sendwait, CLIENT *, h,
		    int, waitsecs);
	}

	RPCLOG(64, "clnt_cots_kcallit: sent call for xid 0x%x\n",
	    (uint_t)p->cku_xid);
	p->cku_flags = (CKU_ONQUEUE|CKU_SENT);
	p->cku_recv_attempts = 1;

#ifdef	RPCDEBUG
	time_sent = ddi_get_lbolt();
#endif

	/*
	 * Wait for a reply or a timeout.  If there is no error or timeout,
	 * (both indicated by call_status), call->call_reply will contain
	 * the RPC reply message.
	 */
read_again:
	mutex_enter(&call->call_lock);
	interrupted = 0;
	if (call->call_status == RPC_TIMEDOUT) {
		/*
		 * Indicate that the lwp is not to be stopped while waiting
		 * for this network traffic.  This is to avoid deadlock while
		 * debugging a process via /proc and also to avoid recursive
		 * mutex_enter()s due to NFS page faults while stopping
		 * (NFS holds locks when it calls here).
		 */
		clock_t cv_wait_ret;
		clock_t timout;
		clock_t oldlbolt;

		klwp_t *lwp = ttolwp(curthread);

		if (lwp != NULL)
			lwp->lwp_nostop++;

		oldlbolt = ddi_get_lbolt();
		timout = wait.tv_sec * drv_usectohz(1000000) +
		    drv_usectohz(wait.tv_usec) + oldlbolt;
		/*
		 * Iterate until the call_status is changed to something
		 * other that RPC_TIMEDOUT, or if cv_timedwait_sig() returns
		 * something <=0 zero. The latter means that we timed
		 * out.
		 */
		if (h->cl_nosignal)
			while ((cv_wait_ret = cv_timedwait(&call->call_cv,
			    &call->call_lock, timout)) > 0 &&
			    call->call_status == RPC_TIMEDOUT)
				;
		else
			while ((cv_wait_ret = cv_timedwait_sig(
			    &call->call_cv,
			    &call->call_lock, timout)) > 0 &&
			    call->call_status == RPC_TIMEDOUT)
				;

		switch (cv_wait_ret) {
		case 0:
			/*
			 * If we got out of the above loop with
			 * cv_timedwait_sig() returning 0, then we were
			 * interrupted regardless what call_status is.
			 */
			interrupted = 1;
			break;
		case -1:
			/* cv_timedwait_sig() timed out */
			break;
		default:

			/*
			 * We were cv_signaled(). If we didn't
			 * get a successful call_status and returned
			 * before time expired, delay up to clnt_cots_min_tout
			 * seconds so that the caller doesn't immediately
			 * try to call us again and thus force the
			 * same condition that got us here (such
			 * as a RPC_XPRTFAILED due to the server not
			 * listening on the end-point.
			 */
			if (call->call_status != RPC_SUCCESS) {
				clock_t curlbolt;
				clock_t diff;

				curlbolt = ddi_get_lbolt();
				ticks = clnt_cots_min_tout *
				    drv_usectohz(1000000);
				diff = curlbolt - oldlbolt;
				if (diff < ticks) {
					delay_first = TRUE;
					if (diff > 0)
						ticks -= diff;
				}
			}
			break;
		}

		if (lwp != NULL)
			lwp->lwp_nostop--;
	}
	/*
	 * Get the reply message, if any.  This will be freed at the end
	 * whether or not an error occurred.
	 */
	mp = call->call_reply;
	call->call_reply = NULL;

	/*
	 * call_err is the error info when the call is on dispatch queue.
	 * cku_err is the error info returned to the caller.
	 * Sync cku_err with call_err for local message processing.
	 */

	status = call->call_status;
	p->cku_err = call->call_err;
	mutex_exit(&call->call_lock);

	if (status != RPC_SUCCESS) {
		switch (status) {
		case RPC_TIMEDOUT:
			now = ddi_get_lbolt();
			if (interrupted) {
				COTSRCSTAT_INCR(p->cku_stats, rcintrs);
				p->cku_err.re_status = RPC_INTR;
				p->cku_err.re_errno = EINTR;
				RPCLOG(1, "clnt_cots_kcallit: xid 0x%x",
				    p->cku_xid);
				RPCLOG(1, "signal interrupted at %ld", now);
				RPCLOG(1, ", was sent at %ld\n", time_sent);
			} else {
				COTSRCSTAT_INCR(p->cku_stats, rctimeouts);
				p->cku_err.re_errno = ETIMEDOUT;
				RPCLOG(1, "clnt_cots_kcallit: timed out at %ld",
				    now);
				RPCLOG(1, ", was sent at %ld\n", time_sent);
			}
			break;

		case RPC_XPRTFAILED:
			if (p->cku_err.re_errno == 0)
				p->cku_err.re_errno = EIO;

			RPCLOG(1, "clnt_cots_kcallit: transport failed: %d\n",
			    p->cku_err.re_errno);
			break;

		case RPC_SYSTEMERROR:
			ASSERT(p->cku_err.re_errno);
			RPCLOG(1, "clnt_cots_kcallit: system error: %d\n",
			    p->cku_err.re_errno);
			break;

		default:
			p->cku_err.re_status = RPC_SYSTEMERROR;
			p->cku_err.re_errno = EIO;
			RPCLOG(1, "clnt_cots_kcallit: error: %s\n",
			    clnt_sperrno(status));
			break;
		}
		if (p->cku_err.re_status != RPC_TIMEDOUT) {

			if (p->cku_flags & CKU_ONQUEUE) {
				call_table_remove(call);
				p->cku_flags &= ~CKU_ONQUEUE;
			}

			RPCLOG(64, "clnt_cots_kcallit: non TIMEOUT so xid 0x%x "
			    "taken off dispatch list\n", p->cku_xid);
			if (call->call_reply) {
				freemsg(call->call_reply);
				call->call_reply = NULL;
			}
		} else if (wait.tv_sec != 0) {
			/*
			 * We've sent the request over TCP and so we have
			 * every reason to believe it will get
			 * delivered. In which case returning a timeout is not
			 * appropriate.
			 */
			if (p->cku_progress == TRUE &&
			    p->cku_recv_attempts < clnt_cots_maxrecv) {
				p->cku_err.re_status = RPC_INPROGRESS;
			}
		}
		goto cots_done;
	}

	xdrs = &p->cku_inxdr;
	xdrmblk_init(xdrs, mp, XDR_DECODE, 0);

	reply_msg.rm_direction = REPLY;
	reply_msg.rm_reply.rp_stat = MSG_ACCEPTED;
	reply_msg.acpted_rply.ar_stat = SUCCESS;

	reply_msg.acpted_rply.ar_verf = _null_auth;
	/*
	 *  xdr_results will be done in AUTH_UNWRAP.
	 */
	reply_msg.acpted_rply.ar_results.where = NULL;
	reply_msg.acpted_rply.ar_results.proc = xdr_void;

	if (xdr_replymsg(xdrs, &reply_msg)) {
		enum clnt_stat re_status;

		_seterr_reply(&reply_msg, &p->cku_err);

		re_status = p->cku_err.re_status;
		if (re_status == RPC_SUCCESS) {
			/*
			 * Reply is good, check auth.
			 */
			if (!AUTH_VALIDATE(h->cl_auth,
			    &reply_msg.acpted_rply.ar_verf)) {
				COTSRCSTAT_INCR(p->cku_stats, rcbadverfs);
				RPCLOG0(1, "clnt_cots_kcallit: validation "
				    "failure\n");
				freemsg(mp);
				(void) xdr_rpc_free_verifier(xdrs, &reply_msg);
				XDR_DESTROY(xdrs);
				mutex_enter(&call->call_lock);
				if (call->call_reply == NULL)
					call->call_status = RPC_TIMEDOUT;
				mutex_exit(&call->call_lock);
				goto read_again;
			} else if (!AUTH_UNWRAP(h->cl_auth, xdrs,
			    xdr_results, resultsp)) {
				RPCLOG0(1, "clnt_cots_kcallit: validation "
				    "failure (unwrap)\n");
				p->cku_err.re_status = RPC_CANTDECODERES;
				p->cku_err.re_errno = EIO;
			}
		} else {
			/* set errno in case we can't recover */
			if (re_status != RPC_VERSMISMATCH &&
			    re_status != RPC_AUTHERROR &&
			    re_status != RPC_PROGVERSMISMATCH)
				p->cku_err.re_errno = EIO;

			if (re_status == RPC_AUTHERROR) {
				/*
				 * Maybe our credential need to be refreshed
				 */
				if (cm_entry) {
					/*
					 * There is the potential that the
					 * cm_entry has/will be marked dead,
					 * so drop the connection altogether,
					 * force REFRESH to establish new
					 * connection.
					 */
					connmgr_cancelconn(cm_entry);
					cm_entry = NULL;
				}

				(void) xdr_rpc_free_verifier(xdrs,
				    &reply_msg);
				XDR_DESTROY(xdrs);

				if (p->cku_flags & CKU_ONQUEUE) {
					call_table_remove(call);
					p->cku_flags &= ~CKU_ONQUEUE;
				}
				RPCLOG(64,
				    "clnt_cots_kcallit: AUTH_ERROR, xid"
				    " 0x%x removed off dispatch list\n",
				    p->cku_xid);
				if (call->call_reply) {
					freemsg(call->call_reply);
					call->call_reply = NULL;
				}

				if ((refreshes > 0) &&
				    AUTH_REFRESH(h->cl_auth, &reply_msg,
				    p->cku_cred)) {
					refreshes--;
					freemsg(mp);
					mp = NULL;

					COTSRCSTAT_INCR(p->cku_stats,
					    rcbadcalls);
					COTSRCSTAT_INCR(p->cku_stats,
					    rcnewcreds);
					goto call_again;
				}

				/*
				 * We have used the client handle to
				 * do an AUTH_REFRESH and the RPC status may
				 * be set to RPC_SUCCESS; Let's make sure to
				 * set it to RPC_AUTHERROR.
				 */
				p->cku_err.re_status = RPC_AUTHERROR;

				/*
				 * Map recoverable and unrecoverable
				 * authentication errors to appropriate errno
				 */
				switch (p->cku_err.re_why) {
				case AUTH_TOOWEAK:
					/*
					 * This could be a failure where the
					 * server requires use of a reserved
					 * port,  check and optionally set the
					 * client handle useresvport trying
					 * one more time. Next go round we
					 * fall out with the tooweak error.
					 */
					if (p->cku_useresvport != 1) {
						p->cku_useresvport = 1;
						p->cku_xid = 0;
						freemsg(mp);
						mp = NULL;
						goto call_again;
					}
					/* FALLTHRU */
				case AUTH_BADCRED:
				case AUTH_BADVERF:
				case AUTH_INVALIDRESP:
				case AUTH_FAILED:
				case RPCSEC_GSS_NOCRED:
				case RPCSEC_GSS_FAILED:
						p->cku_err.re_errno = EACCES;
						break;
				case AUTH_REJECTEDCRED:
				case AUTH_REJECTEDVERF:
				default:	p->cku_err.re_errno = EIO;
						break;
				}
				RPCLOG(1, "clnt_cots_kcallit : authentication"
				    " failed with RPC_AUTHERROR of type %d\n",
				    (int)p->cku_err.re_why);
				goto cots_done;
			}
		}
	} else {
		/* reply didn't decode properly. */
		p->cku_err.re_status = RPC_CANTDECODERES;
		p->cku_err.re_errno = EIO;
		RPCLOG0(1, "clnt_cots_kcallit: decode failure\n");
	}

	(void) xdr_rpc_free_verifier(xdrs, &reply_msg);
	XDR_DESTROY(xdrs);

	if (p->cku_flags & CKU_ONQUEUE) {
		call_table_remove(call);
		p->cku_flags &= ~CKU_ONQUEUE;
	}

	RPCLOG(64, "clnt_cots_kcallit: xid 0x%x taken off dispatch list",
	    p->cku_xid);
	RPCLOG(64, " status is %s\n", clnt_sperrno(p->cku_err.re_status));
cots_done:
	if (cm_entry)
		connmgr_release(cm_entry);

	if (mp != NULL)
		freemsg(mp);
	if ((p->cku_flags & CKU_ONQUEUE) == 0 && call->call_reply) {
		freemsg(call->call_reply);
		call->call_reply = NULL;
	}
	if (p->cku_err.re_status != RPC_SUCCESS) {
		RPCLOG0(1, "clnt_cots_kcallit: tail-end failure\n");
		COTSRCSTAT_INCR(p->cku_stats, rcbadcalls);
	}

	/*
	 * No point in delaying if the zone is going away.
	 */
	if (delay_first == TRUE &&
	    !(zone_status_get(curproc->p_zone) >= ZONE_IS_SHUTTING_DOWN)) {
		if (clnt_delay(ticks, h->cl_nosignal) == EINTR) {
			p->cku_err.re_errno = EINTR;
			p->cku_err.re_status = RPC_INTR;
		}
	}
	return (p->cku_err.re_status);
}

/*
 * Kinit routine for cots.  This sets up the correct operations in
 * the client handle, as the handle may have previously been a clts
 * handle, and clears the xid field so there is no way a new call
 * could be mistaken for a retry.  It also sets in the handle the
 * information that is passed at create/kinit time but needed at
 * call time, as cots creates the transport at call time - device,
 * address of the server, protocol family.
 */
void
clnt_cots_kinit(CLIENT *h, dev_t dev, int family, struct netbuf *addr,
    int max_msgsize, cred_t *cred)
{
	/* LINTED pointer alignment */
	cku_private_t *p = htop(h);
	calllist_t *call = &p->cku_call;

	h->cl_ops = &tcp_ops;
	if (p->cku_flags & CKU_ONQUEUE) {
		call_table_remove(call);
		p->cku_flags &= ~CKU_ONQUEUE;
		RPCLOG(64, "clnt_cots_kinit: removing call for xid 0x%x from"
		    " dispatch list\n", p->cku_xid);
	}

	if (call->call_reply != NULL) {
		freemsg(call->call_reply);
		call->call_reply = NULL;
	}

	call->call_bucket = NULL;
	call->call_hash = 0;

	/*
	 * We don't clear cku_flags here, because clnt_cots_kcallit()
	 * takes care of handling the cku_flags reset.
	 */
	p->cku_xid = 0;
	p->cku_device = dev;
	p->cku_addrfmly = family;
	p->cku_cred = cred;

	if (p->cku_addr.maxlen < addr->len) {
		if (p->cku_addr.maxlen != 0 && p->cku_addr.buf != NULL)
			kmem_free(p->cku_addr.buf, p->cku_addr.maxlen);
		p->cku_addr.buf = kmem_zalloc(addr->maxlen, KM_SLEEP);
		p->cku_addr.maxlen = addr->maxlen;
	}

	p->cku_addr.len = addr->len;
	bcopy(addr->buf, p->cku_addr.buf, addr->len);

	/*
	 * If the current sanity check size in rpcmod is smaller
	 * than the size needed, then increase the sanity check.
	 */
	if (max_msgsize != 0 && clnt_max_msg_sizep != NULL &&
	    max_msgsize > *clnt_max_msg_sizep) {
		mutex_enter(&clnt_max_msg_lock);
		if (max_msgsize > *clnt_max_msg_sizep)
			*clnt_max_msg_sizep = max_msgsize;
		mutex_exit(&clnt_max_msg_lock);
	}
}

/*
 * ksettimers is a no-op for cots, with the exception of setting the xid.
 */
/* ARGSUSED */
static int
clnt_cots_ksettimers(CLIENT *h, struct rpc_timers *t, struct rpc_timers *all,
    int minimum, void (*feedback)(int, int, caddr_t), caddr_t arg, uint32_t xid)
{
	/* LINTED pointer alignment */
	cku_private_t *p = htop(h);

	if (xid)
		p->cku_xid = xid;
	COTSRCSTAT_INCR(p->cku_stats, rctimers);
	return (0);
}

extern void rpc_poptimod(struct vnode *);
extern int kstr_push(struct vnode *, char *);

int
conn_kstat_update(kstat_t *ksp, int rw)
{
	struct cm_xprt *cm_entry;
	struct cm_kstat_xprt *cm_ksp_data;
	uchar_t *b;
	char *fbuf;

	if (rw == KSTAT_WRITE)
		return (EACCES);
	if (ksp == NULL || ksp->ks_private == NULL)
		return (EIO);
	cm_entry  = (struct cm_xprt *)ksp->ks_private;
	cm_ksp_data = (struct cm_kstat_xprt *)ksp->ks_data;

	cm_ksp_data->x_wq.value.ui32 = (uint32_t)(uintptr_t)cm_entry->x_wq;
	cm_ksp_data->x_family.value.ui32 = cm_entry->x_family;
	cm_ksp_data->x_rdev.value.ui32 = (uint32_t)cm_entry->x_rdev;
	cm_ksp_data->x_time.value.ui32 = cm_entry->x_time;
	cm_ksp_data->x_ref.value.ui32 = cm_entry->x_ref;
	cm_ksp_data->x_state.value.ui32 = cm_entry->x_state_flags;

	if (cm_entry->x_server.buf) {
		fbuf = cm_ksp_data->x_server.value.str.addr.ptr;
		if (cm_entry->x_family == AF_INET &&
		    cm_entry->x_server.len ==
		    sizeof (struct sockaddr_in)) {
			struct sockaddr_in  *sa;
			sa = (struct sockaddr_in *)
				cm_entry->x_server.buf;
			b = (uchar_t *)&sa->sin_addr;
			(void) sprintf(fbuf,
			    "%d.%d.%d.%d", b[0] & 0xFF, b[1] & 0xFF,
			    b[2] & 0xFF, b[3] & 0xFF);
			cm_ksp_data->x_port.value.ui32 = ntohs(sa->sin_port);
		} else if (cm_entry->x_family == AF_INET6 &&
				cm_entry->x_server.len >=
				sizeof (struct sockaddr_in6)) {
			/* extract server IP address & port */
			struct sockaddr_in6 *sin6;
			sin6 = (struct sockaddr_in6 *)cm_entry->x_server.buf;
			(void) kinet_ntop6((uchar_t *)&sin6->sin6_addr, fbuf,
				INET6_ADDRSTRLEN);
			cm_ksp_data->x_port.value.ui32 = ntohs(sin6->sin6_port);
		} else {
			struct sockaddr_in  *sa;

			sa = (struct sockaddr_in *)cm_entry->x_server.buf;
			b = (uchar_t *)&sa->sin_addr;
			(void) sprintf(fbuf,
			    "%d.%d.%d.%d", b[0] & 0xFF, b[1] & 0xFF,
			    b[2] & 0xFF, b[3] & 0xFF);
		}
		KSTAT_NAMED_STR_BUFLEN(&cm_ksp_data->x_server) =
		    strlen(fbuf) + 1;
	}

	return (0);
}


/*
 * We want a version of delay which is interruptible by a UNIX signal
 * Return EINTR if an interrupt occured.
 */
static int
clnt_delay(clock_t ticks, bool_t nosignal)
{
	if (nosignal == TRUE) {
		delay(ticks);
		return (0);
	}
	return (delay_sig(ticks));
}

/*
 * Wait for a connection until a timeout, or until we are
 * signalled that there has been a connection state change.
 */
static enum clnt_stat
connmgr_cwait(struct cm_xprt *cm_entry, const struct timeval *waitp,
    bool_t nosignal)
{
	bool_t interrupted;
	clock_t timout, cv_stat;
	enum clnt_stat clstat;
	unsigned int old_state;

	ASSERT(MUTEX_HELD(&connmgr_lock));
	/*
	 * We wait for the transport connection to be made, or an
	 * indication that it could not be made.
	 */
	clstat = RPC_TIMEDOUT;
	interrupted = FALSE;

	old_state = cm_entry->x_state_flags;
	/*
	 * Now loop until cv_timedwait{_sig} returns because of
	 * a signal(0) or timeout(-1) or cv_signal(>0). But it may be
	 * cv_signalled for various other reasons too. So loop
	 * until there is a state change on the connection.
	 */

	timout = waitp->tv_sec * drv_usectohz(1000000) +
	    drv_usectohz(waitp->tv_usec) + ddi_get_lbolt();

	if (nosignal) {
		while ((cv_stat = cv_timedwait(&cm_entry->x_conn_cv,
		    &connmgr_lock, timout)) > 0 &&
		    cm_entry->x_state_flags == old_state)
			;
	} else {
		while ((cv_stat = cv_timedwait_sig(&cm_entry->x_conn_cv,
		    &connmgr_lock, timout)) > 0 &&
		    cm_entry->x_state_flags == old_state)
			;

		if (cv_stat == 0) /* got intr signal? */
			interrupted = TRUE;
	}

	if ((cm_entry->x_state_flags & (X_BADSTATES|X_CONNECTED)) ==
	    X_CONNECTED) {
		clstat = RPC_SUCCESS;
	} else {
		if (interrupted == TRUE)
			clstat = RPC_INTR;
		RPCLOG(1, "connmgr_cwait: can't connect, error: %s\n",
		    clnt_sperrno(clstat));
	}

	return (clstat);
}

/*
 * Primary interface for how RPC grabs a connection.
 */
static struct cm_xprt *
connmgr_wrapget(
	struct netbuf *retryaddr,
	const struct timeval *waitp,
	cku_private_t *p)
{
	struct cm_xprt *cm_entry;

	cm_entry = connmgr_get(retryaddr, waitp, &p->cku_addr, p->cku_addrfmly,
	    &p->cku_srcaddr, &p->cku_err, p->cku_device,
	    p->cku_client.cl_nosignal, p->cku_useresvport, p->cku_cred);

	if (cm_entry == NULL) {
		/*
		 * Re-map the call status to RPC_INTR if the err code is
		 * EINTR. This can happen if calls status is RPC_TLIERROR.
		 * However, don't re-map if signalling has been turned off.
		 * XXX Really need to create a separate thread whenever
		 * there isn't an existing connection.
		 */
		if (p->cku_err.re_errno == EINTR) {
			if (p->cku_client.cl_nosignal == TRUE)
				p->cku_err.re_errno = EIO;
			else
				p->cku_err.re_status = RPC_INTR;
		}
	}

	return (cm_entry);
}

/*
 * Obtains a transport to the server specified in addr.  If a suitable transport
 * does not already exist in the list of cached transports, a new connection
 * is created, connected, and added to the list. The connection is for sending
 * only - the reply message may come back on another transport connection.
 *
 * To implement round-robin load balancing with multiple client connections,
 * the last entry on the list is always selected. Once the entry is selected
 * it's re-inserted to the head of the list.
 */
static struct cm_xprt *
connmgr_get(
	struct netbuf	*retryaddr,
	const struct timeval	*waitp,	/* changed to a ptr to converse stack */
	struct netbuf	*destaddr,
	int		addrfmly,
	struct netbuf	*srcaddr,
	struct rpc_err	*rpcerr,
	dev_t		device,
	bool_t		nosignal,
	int		useresvport,
	cred_t		*cr)
{
	struct cm_xprt *cm_entry;
	struct cm_xprt *lru_entry;
	struct cm_xprt **cmp, **prev;
	queue_t *wq;
	TIUSER *tiptr;
	int i;
	int retval;
	int tidu_size;
	bool_t	connected;
	zoneid_t zoneid = rpc_zoneid();

	/*
	 * If the call is not a retry, look for a transport entry that
	 * goes to the server of interest.
	 */
	mutex_enter(&connmgr_lock);

	if (retryaddr == NULL) {
use_new_conn:
		i = 0;
		cm_entry = lru_entry = NULL;

		prev = cmp = &cm_hd;
		while ((cm_entry = *cmp) != NULL) {
			ASSERT(cm_entry != cm_entry->x_next);
			/*
			 * Garbage collect conections that are marked
			 * for needs disconnect.
			 */
			if (cm_entry->x_needdis) {
				CONN_HOLD(cm_entry);
				connmgr_dis_and_wait(cm_entry);
				connmgr_release(cm_entry);
				/*
				 * connmgr_lock could have been
				 * dropped for the disconnect
				 * processing so start over.
				 */
				goto use_new_conn;
			}

			/*
			 * Garbage collect the dead connections that have
			 * no threads working on them.
			 */
			if ((cm_entry->x_state_flags & (X_DEAD|X_THREAD)) ==
			    X_DEAD) {
				mutex_enter(&cm_entry->x_lock);
				if (cm_entry->x_ref != 0) {
					/*
					 * Currently in use.
					 * Cleanup later.
					 */
					cmp = &cm_entry->x_next;
					mutex_exit(&cm_entry->x_lock);
					continue;
				}
				mutex_exit(&cm_entry->x_lock);
				*cmp = cm_entry->x_next;
				mutex_exit(&connmgr_lock);
				connmgr_close(cm_entry);
				mutex_enter(&connmgr_lock);
				goto use_new_conn;
			}


			if ((cm_entry->x_state_flags & X_BADSTATES) == 0 &&
			    cm_entry->x_zoneid == zoneid &&
			    cm_entry->x_rdev == device &&
			    destaddr->len == cm_entry->x_server.len &&
			    bcmp(destaddr->buf, cm_entry->x_server.buf,
			    destaddr->len) == 0) {
				/*
				 * If the matching entry isn't connected,
				 * attempt to reconnect it.
				 */
				if (cm_entry->x_connected == FALSE) {
					/*
					 * We don't go through trying
					 * to find the least recently
					 * used connected because
					 * connmgr_reconnect() briefly
					 * dropped the connmgr_lock,
					 * allowing a window for our
					 * accounting to be messed up.
					 * In any case, a re-connected
					 * connection is as good as
					 * a LRU connection.
					 */
					return (connmgr_wrapconnect(cm_entry,
					    waitp, destaddr, addrfmly, srcaddr,
					    rpcerr, TRUE, nosignal, cr));
				}
				i++;

				/* keep track of the last entry */
				lru_entry = cm_entry;
				prev = cmp;
			}
			cmp = &cm_entry->x_next;
		}

		if (i > clnt_max_conns) {
			RPCLOG(8, "connmgr_get: too many conns, dooming entry"
			    " %p\n", (void *)lru_entry->x_tiptr);
			lru_entry->x_doomed = TRUE;
			goto use_new_conn;
		}

		/*
		 * If we are at the maximum number of connections to
		 * the server, hand back the least recently used one.
		 */
		if (i == clnt_max_conns) {
			/*
			 * Copy into the handle the source address of
			 * the connection, which we will use in case of
			 * a later retry.
			 */
			if (srcaddr->len != lru_entry->x_src.len) {
				if (srcaddr->len > 0)
					kmem_free(srcaddr->buf,
					    srcaddr->maxlen);
				srcaddr->buf = kmem_zalloc(
				    lru_entry->x_src.len, KM_SLEEP);
				srcaddr->maxlen = srcaddr->len =
				    lru_entry->x_src.len;
			}
			bcopy(lru_entry->x_src.buf, srcaddr->buf, srcaddr->len);
			RPCLOG(2, "connmgr_get: call going out on %p\n",
			    (void *)lru_entry);
			lru_entry->x_time = ddi_get_lbolt();
			CONN_HOLD(lru_entry);

			if ((i > 1) && (prev != &cm_hd)) {
				/*
				 * remove and re-insert entry at head of list.
				 */
				*prev = lru_entry->x_next;
				lru_entry->x_next = cm_hd;
				cm_hd = lru_entry;
			}

			mutex_exit(&connmgr_lock);
			return (lru_entry);
		}

	} else {
		/*
		 * This is the retry case (retryaddr != NULL).  Retries must
		 * be sent on the same source port as the original call.
		 */

		/*
		 * Walk the list looking for a connection with a source address
		 * that matches the retry address.
		 */
start_retry_loop:
		cmp = &cm_hd;
		while ((cm_entry = *cmp) != NULL) {
			ASSERT(cm_entry != cm_entry->x_next);

			/*
			 * determine if this connection matches the passed
			 * in retry address.  If it does not match, advance
			 * to the next element on the list.
			 */
			if (zoneid != cm_entry->x_zoneid ||
			    device != cm_entry->x_rdev ||
			    retryaddr->len != cm_entry->x_src.len ||
			    bcmp(retryaddr->buf, cm_entry->x_src.buf,
			    retryaddr->len) != 0) {
				cmp = &cm_entry->x_next;
				continue;
			}
			/*
			 * Garbage collect conections that are marked
			 * for needs disconnect.
			 */
			if (cm_entry->x_needdis) {
				CONN_HOLD(cm_entry);
				connmgr_dis_and_wait(cm_entry);
				connmgr_release(cm_entry);
				/*
				 * connmgr_lock could have been
				 * dropped for the disconnect
				 * processing so start over.
				 */
				goto start_retry_loop;
			}
			/*
			 * Garbage collect the dead connections that have
			 * no threads working on them.
			 */
			if ((cm_entry->x_state_flags & (X_DEAD|X_THREAD)) ==
			    X_DEAD) {
				mutex_enter(&cm_entry->x_lock);
				if (cm_entry->x_ref != 0) {
					/*
					 * Currently in use.
					 * Cleanup later.
					 */
					cmp = &cm_entry->x_next;
					mutex_exit(&cm_entry->x_lock);
					continue;
				}
				mutex_exit(&cm_entry->x_lock);
				*cmp = cm_entry->x_next;
				mutex_exit(&connmgr_lock);
				connmgr_close(cm_entry);
				mutex_enter(&connmgr_lock);
				goto start_retry_loop;
			}

			/*
			 * Sanity check: if the connection with our source
			 * port is going to some other server, something went
			 * wrong, as we never delete connections (i.e. release
			 * ports) unless they have been idle.  In this case,
			 * it is probably better to send the call out using
			 * a new source address than to fail it altogether,
			 * since that port may never be released.
			 */
			if (destaddr->len != cm_entry->x_server.len ||
			    bcmp(destaddr->buf, cm_entry->x_server.buf,
			    destaddr->len) != 0) {
				RPCLOG(1, "connmgr_get: tiptr %p"
				    " is going to a different server"
				    " with the port that belongs"
				    " to us!\n", (void *)cm_entry->x_tiptr);
				retryaddr = NULL;
				goto use_new_conn;
			}

			/*
			 * If the connection of interest is not connected and we
			 * can't reconnect it, then the server is probably
			 * still down.  Return NULL to the caller and let it
			 * retry later if it wants to.  We have a delay so the
			 * machine doesn't go into a tight retry loop.  If the
			 * entry was already connected, or the reconnected was
			 * successful, return this entry.
			 */
			if (cm_entry->x_connected == FALSE) {
				return (connmgr_wrapconnect(cm_entry,
				    waitp, destaddr, addrfmly, NULL,
				    rpcerr, TRUE, nosignal, cr));
			} else {
				CONN_HOLD(cm_entry);

				cm_entry->x_time = ddi_get_lbolt();
				mutex_exit(&connmgr_lock);
				RPCLOG(2, "connmgr_get: found old "
				    "transport %p for retry\n",
				    (void *)cm_entry);
				return (cm_entry);
			}
		}

		/*
		 * We cannot find an entry in the list for this retry.
		 * Either the entry has been removed temporarily to be
		 * reconnected by another thread, or the original call
		 * got a port but never got connected,
		 * and hence the transport never got put in the
		 * list.  Fall through to the "create new connection" code -
		 * the former case will fail there trying to rebind the port,
		 * and the later case (and any other pathological cases) will
		 * rebind and reconnect and not hang the client machine.
		 */
		RPCLOG0(8, "connmgr_get: no entry in list for retry\n");
	}
	/*
	 * Set up a transport entry in the connection manager's list.
	 */
	cm_entry = (struct cm_xprt *)
	    kmem_zalloc(sizeof (struct cm_xprt), KM_SLEEP);

	cm_entry->x_server.buf = kmem_zalloc(destaddr->len, KM_SLEEP);
	bcopy(destaddr->buf, cm_entry->x_server.buf, destaddr->len);
	cm_entry->x_server.len = cm_entry->x_server.maxlen = destaddr->len;

	cm_entry->x_state_flags = X_THREAD;
	cm_entry->x_ref = 1;
	cm_entry->x_family = addrfmly;
	cm_entry->x_rdev = device;
	cm_entry->x_zoneid = zoneid;
	mutex_init(&cm_entry->x_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&cm_entry->x_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&cm_entry->x_conn_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&cm_entry->x_dis_cv, NULL, CV_DEFAULT, NULL);

	/*
	 * Note that we add this partially initialized entry to the
	 * connection list. This is so that we don't have connections to
	 * the same server.
	 *
	 * Note that x_src is not initialized at this point. This is because
	 * retryaddr might be NULL in which case x_src is whatever
	 * t_kbind/bindresvport gives us. If another thread wants a
	 * connection to the same server, seemingly we have an issue, but we
	 * don't. If the other thread comes in with retryaddr == NULL, then it
	 * will never look at x_src, and it will end up waiting in
	 * connmgr_cwait() for the first thread to finish the connection
	 * attempt. If the other thread comes in with retryaddr != NULL, then
	 * that means there was a request sent on a connection, in which case
	 * the the connection should already exist. Thus the first thread
	 * never gets here ... it finds the connection it its server in the
	 * connection list.
	 *
	 * But even if theory is wrong, in the retryaddr != NULL case, the 2nd
	 * thread will skip us because x_src.len == 0.
	 */
	cm_entry->x_next = cm_hd;
	cm_hd = cm_entry;
	mutex_exit(&connmgr_lock);

	/*
	 * Either we didn't find an entry to the server of interest, or we
	 * don't have the maximum number of connections to that server -
	 * create a new connection.
	 */
	RPCLOG0(8, "connmgr_get: creating new connection\n");
	rpcerr->re_status = RPC_TLIERROR;

	i = t_kopen(NULL, device, FREAD|FWRITE|FNDELAY, &tiptr, zone_kcred());
	if (i) {
		RPCLOG(1, "connmgr_get: can't open cots device, error %d\n", i);
		rpcerr->re_errno = i;
		connmgr_cancelconn(cm_entry);
		return (NULL);
	}
	rpc_poptimod(tiptr->fp->f_vnode);

	if (i = strioctl(tiptr->fp->f_vnode, I_PUSH, (intptr_t)"rpcmod", 0,
	    K_TO_K, kcred, &retval)) {
		RPCLOG(1, "connmgr_get: can't push cots module, %d\n", i);
		(void) t_kclose(tiptr, 1);
		rpcerr->re_errno = i;
		connmgr_cancelconn(cm_entry);
		return (NULL);
	}

	if (i = strioctl(tiptr->fp->f_vnode, RPC_CLIENT, 0, 0, K_TO_K,
	    kcred, &retval)) {
		RPCLOG(1, "connmgr_get: can't set client status with cots "
		    "module, %d\n", i);
		(void) t_kclose(tiptr, 1);
		rpcerr->re_errno = i;
		connmgr_cancelconn(cm_entry);
		return (NULL);
	}

	mutex_enter(&connmgr_lock);

	wq = tiptr->fp->f_vnode->v_stream->sd_wrq->q_next;
	cm_entry->x_wq = wq;

	mutex_exit(&connmgr_lock);

	if (i = strioctl(tiptr->fp->f_vnode, I_PUSH, (intptr_t)"timod", 0,
	    K_TO_K, kcred, &retval)) {
		RPCLOG(1, "connmgr_get: can't push timod, %d\n", i);
		(void) t_kclose(tiptr, 1);
		rpcerr->re_errno = i;
		connmgr_cancelconn(cm_entry);
		return (NULL);
	}

	/*
	 * If the caller has not specified reserved port usage then
	 * take the system default.
	 */
	if (useresvport == -1)
		useresvport = clnt_cots_do_bindresvport;

	if ((useresvport || retryaddr != NULL) &&
	    (addrfmly == AF_INET || addrfmly == AF_INET6)) {
		bool_t alloc_src = FALSE;

		if (srcaddr->len != destaddr->len) {
			kmem_free(srcaddr->buf, srcaddr->maxlen);
			srcaddr->buf = kmem_zalloc(destaddr->len, KM_SLEEP);
			srcaddr->maxlen = destaddr->len;
			srcaddr->len = destaddr->len;
			alloc_src = TRUE;
		}

		if ((i = bindresvport(tiptr, retryaddr, srcaddr, TRUE)) != 0) {
			(void) t_kclose(tiptr, 1);
			RPCLOG(1, "connmgr_get: couldn't bind, retryaddr: "
			    "%p\n", (void *)retryaddr);

			/*
			 * 1225408: If we allocated a source address, then it
			 * is either garbage or all zeroes. In that case
			 * we need to clear srcaddr.
			 */
			if (alloc_src == TRUE) {
				kmem_free(srcaddr->buf, srcaddr->maxlen);
				srcaddr->maxlen = srcaddr->len = 0;
				srcaddr->buf = NULL;
			}
			rpcerr->re_errno = i;
			connmgr_cancelconn(cm_entry);
			return (NULL);
		}
	} else {
		if ((i = t_kbind(tiptr, NULL, NULL)) != 0) {
			RPCLOG(1, "clnt_cots_kcreate: t_kbind: %d\n", i);
			(void) t_kclose(tiptr, 1);
			rpcerr->re_errno = i;
			connmgr_cancelconn(cm_entry);
			return (NULL);
		}
	}

	{
		/*
		 * Keep the kernel stack lean. Don't move this call
		 * declaration to the top of this function because a
		 * call is declared in connmgr_wrapconnect()
		 */
		calllist_t call;

		bzero(&call, sizeof (call));
		cv_init(&call.call_cv, NULL, CV_DEFAULT, NULL);

		/*
		 * This is a bound end-point so don't close it's stream.
		 */
		connected = connmgr_connect(cm_entry, wq, destaddr, addrfmly,
		    &call, &tidu_size, FALSE, waitp, nosignal, cr);
		*rpcerr = call.call_err;
		cv_destroy(&call.call_cv);

	}

	mutex_enter(&connmgr_lock);

	/*
	 * Set up a transport entry in the connection manager's list.
	 */
	cm_entry->x_src.buf = kmem_zalloc(srcaddr->len, KM_SLEEP);
	bcopy(srcaddr->buf, cm_entry->x_src.buf, srcaddr->len);
	cm_entry->x_src.len = cm_entry->x_src.maxlen = srcaddr->len;

	cm_entry->x_tiptr = tiptr;
	cm_entry->x_time = ddi_get_lbolt();

	if (tiptr->tp_info.servtype == T_COTS_ORD)
		cm_entry->x_ordrel = TRUE;
	else
		cm_entry->x_ordrel = FALSE;

	cm_entry->x_tidu_size = tidu_size;

	if (cm_entry->x_early_disc) {
		/*
		 * We need to check if a disconnect request has come
		 * while we are connected, if so, then we need to
		 * set rpcerr->re_status appropriately before returning
		 * NULL to caller.
		 */
		if (rpcerr->re_status == RPC_SUCCESS)
			rpcerr->re_status = RPC_XPRTFAILED;
		cm_entry->x_connected = FALSE;
	} else
		cm_entry->x_connected = connected;

	/*
	 * There could be a discrepancy here such that
	 * x_early_disc is TRUE yet connected is TRUE as well
	 * and the connection is actually connected. In that case
	 * lets be conservative and declare the connection as not
	 * connected.
	 */
	cm_entry->x_early_disc = FALSE;
	cm_entry->x_needdis = (cm_entry->x_connected == FALSE);
	cm_entry->x_ctime = ddi_get_lbolt();

	/*
	 * Notify any threads waiting that the connection attempt is done.
	 */
	cm_entry->x_thread = FALSE;
	cv_broadcast(&cm_entry->x_conn_cv);

	if (cm_entry->x_connected == FALSE) {
		mutex_exit(&connmgr_lock);
		connmgr_release(cm_entry);
		return (NULL);
	}

	mutex_exit(&connmgr_lock);

	return (cm_entry);
}

/*
 * Keep the cm_xprt entry on the connecton list when making a connection. This
 * is to prevent multiple connections to a slow server from appearing.
 * We use the bit field x_thread to tell if a thread is doing a connection
 * which keeps other interested threads from messing with connection.
 * Those other threads just wait if x_thread is set.
 *
 * If x_thread is not set, then we do the actual work of connecting via
 * connmgr_connect().
 *
 * mutex convention: called with connmgr_lock held, returns with it released.
 */
static struct cm_xprt *
connmgr_wrapconnect(
	struct cm_xprt	*cm_entry,
	const struct timeval	*waitp,
	struct netbuf	*destaddr,
	int		addrfmly,
	struct netbuf	*srcaddr,
	struct rpc_err	*rpcerr,
	bool_t		reconnect,
	bool_t		nosignal,
	cred_t		*cr)
{
	ASSERT(MUTEX_HELD(&connmgr_lock));
	/*
	 * Hold this entry as we are about to drop connmgr_lock.
	 */
	CONN_HOLD(cm_entry);

	/*
	 * If there is a thread already making a connection for us, then
	 * wait for it to complete the connection.
	 */
	if (cm_entry->x_thread == TRUE) {
		rpcerr->re_status = connmgr_cwait(cm_entry, waitp, nosignal);

		if (rpcerr->re_status != RPC_SUCCESS) {
			mutex_exit(&connmgr_lock);
			connmgr_release(cm_entry);
			return (NULL);
		}
	} else {
		bool_t connected;
		calllist_t call;

		cm_entry->x_thread = TRUE;

		while (cm_entry->x_needrel == TRUE) {
			cm_entry->x_needrel = FALSE;

			connmgr_sndrel(cm_entry);
			delay(drv_usectohz(1000000));

			mutex_enter(&connmgr_lock);
		}

		/*
		 * If we need to send a T_DISCON_REQ, send one.
		 */
		connmgr_dis_and_wait(cm_entry);

		mutex_exit(&connmgr_lock);

		bzero(&call, sizeof (call));
		cv_init(&call.call_cv, NULL, CV_DEFAULT, NULL);

		connected = connmgr_connect(cm_entry, cm_entry->x_wq,
		    destaddr, addrfmly, &call, &cm_entry->x_tidu_size,
		    reconnect, waitp, nosignal, cr);

		*rpcerr = call.call_err;
		cv_destroy(&call.call_cv);

		mutex_enter(&connmgr_lock);


		if (cm_entry->x_early_disc) {
			/*
			 * We need to check if a disconnect request has come
			 * while we are connected, if so, then we need to
			 * set rpcerr->re_status appropriately before returning
			 * NULL to caller.
			 */
			if (rpcerr->re_status == RPC_SUCCESS)
				rpcerr->re_status = RPC_XPRTFAILED;
			cm_entry->x_connected = FALSE;
		} else
			cm_entry->x_connected = connected;

		/*
		 * There could be a discrepancy here such that
		 * x_early_disc is TRUE yet connected is TRUE as well
		 * and the connection is actually connected. In that case
		 * lets be conservative and declare the connection as not
		 * connected.
		 */

		cm_entry->x_early_disc = FALSE;
		cm_entry->x_needdis = (cm_entry->x_connected == FALSE);


		/*
		 * connmgr_connect() may have given up before the connection
		 * actually timed out. So ensure that before the next
		 * connection attempt we do a disconnect.
		 */
		cm_entry->x_ctime = ddi_get_lbolt();
		cm_entry->x_thread = FALSE;

		cv_broadcast(&cm_entry->x_conn_cv);

		if (cm_entry->x_connected == FALSE) {
			mutex_exit(&connmgr_lock);
			connmgr_release(cm_entry);
			return (NULL);
		}
	}

	if (srcaddr != NULL) {
		/*
		 * Copy into the handle the
		 * source address of the
		 * connection, which we will use
		 * in case of a later retry.
		 */
		if (srcaddr->len != cm_entry->x_src.len) {
			if (srcaddr->maxlen > 0)
				kmem_free(srcaddr->buf, srcaddr->maxlen);
			srcaddr->buf = kmem_zalloc(cm_entry->x_src.len,
			    KM_SLEEP);
			srcaddr->maxlen = srcaddr->len =
			    cm_entry->x_src.len;
		}
		bcopy(cm_entry->x_src.buf, srcaddr->buf, srcaddr->len);
	}
	cm_entry->x_time = ddi_get_lbolt();
	mutex_exit(&connmgr_lock);
	return (cm_entry);
}

/*
 * If we need to send a T_DISCON_REQ, send one.
 */
static void
connmgr_dis_and_wait(struct cm_xprt *cm_entry)
{
	ASSERT(MUTEX_HELD(&connmgr_lock));
	for (;;) {
		while (cm_entry->x_needdis == TRUE) {
			RPCLOG(8, "connmgr_dis_and_wait: need "
			    "T_DISCON_REQ for connection 0x%p\n",
			    (void *)cm_entry);
			cm_entry->x_needdis = FALSE;
			cm_entry->x_waitdis = TRUE;

			connmgr_snddis(cm_entry);

			mutex_enter(&connmgr_lock);
		}

		if (cm_entry->x_waitdis == TRUE) {
			clock_t timout;

			RPCLOG(8, "connmgr_dis_and_wait waiting for "
			    "T_DISCON_REQ's ACK for connection %p\n",
			    (void *)cm_entry);

			timout = clnt_cots_min_conntout * drv_usectohz(1000000);

			/*
			 * The TPI spec says that the T_DISCON_REQ
			 * will get acknowledged, but in practice
			 * the ACK may never get sent. So don't
			 * block forever.
			 */
			(void) cv_reltimedwait(&cm_entry->x_dis_cv,
			    &connmgr_lock, timout, TR_CLOCK_TICK);
		}
		/*
		 * If we got the ACK, break. If we didn't,
		 * then send another T_DISCON_REQ.
		 */
		if (cm_entry->x_waitdis == FALSE) {
			break;
		} else {
			RPCLOG(8, "connmgr_dis_and_wait: did"
			    "not get T_DISCON_REQ's ACK for "
			    "connection  %p\n", (void *)cm_entry);
			cm_entry->x_needdis = TRUE;
		}
	}
}

static void
connmgr_cancelconn(struct cm_xprt *cm_entry)
{
	/*
	 * Mark the connection table entry as dead; the next thread that
	 * goes through connmgr_release() will notice this and deal with it.
	 */
	mutex_enter(&connmgr_lock);
	cm_entry->x_dead = TRUE;

	/*
	 * Notify any threads waiting for the connection that it isn't
	 * going to happen.
	 */
	cm_entry->x_thread = FALSE;
	cv_broadcast(&cm_entry->x_conn_cv);
	mutex_exit(&connmgr_lock);

	connmgr_release(cm_entry);
}

static void
connmgr_close(struct cm_xprt *cm_entry)
{
	mutex_enter(&cm_entry->x_lock);
	while (cm_entry->x_ref != 0) {
		/*
		 * Must be a noninterruptible wait.
		 */
		cv_wait(&cm_entry->x_cv, &cm_entry->x_lock);
	}

	if (cm_entry->x_tiptr != NULL)
		(void) t_kclose(cm_entry->x_tiptr, 1);

	mutex_exit(&cm_entry->x_lock);
	if (cm_entry->x_ksp != NULL) {
		mutex_enter(&connmgr_lock);
		cm_entry->x_ksp->ks_private = NULL;
		mutex_exit(&connmgr_lock);

		/*
		 * Must free the buffer we allocated for the
		 * server address in the update function
		 */
		if (((struct cm_kstat_xprt *)(cm_entry->x_ksp->ks_data))->
		    x_server.value.str.addr.ptr != NULL)
			kmem_free(((struct cm_kstat_xprt *)(cm_entry->x_ksp->
			    ks_data))->x_server.value.str.addr.ptr,
			    INET6_ADDRSTRLEN);
		kmem_free(cm_entry->x_ksp->ks_data,
		    cm_entry->x_ksp->ks_data_size);
		kstat_delete(cm_entry->x_ksp);
	}

	mutex_destroy(&cm_entry->x_lock);
	cv_destroy(&cm_entry->x_cv);
	cv_destroy(&cm_entry->x_conn_cv);
	cv_destroy(&cm_entry->x_dis_cv);

	if (cm_entry->x_server.buf != NULL)
		kmem_free(cm_entry->x_server.buf, cm_entry->x_server.maxlen);
	if (cm_entry->x_src.buf != NULL)
		kmem_free(cm_entry->x_src.buf, cm_entry->x_src.maxlen);
	kmem_free(cm_entry, sizeof (struct cm_xprt));
}

/*
 * Called by KRPC after sending the call message to release the connection
 * it was using.
 */
static void
connmgr_release(struct cm_xprt *cm_entry)
{
	mutex_enter(&cm_entry->x_lock);
	cm_entry->x_ref--;
	if (cm_entry->x_ref == 0)
		cv_signal(&cm_entry->x_cv);
	mutex_exit(&cm_entry->x_lock);
}

/*
 * Set TCP receive and xmit buffer size for RPC connections.
 */
static bool_t
connmgr_setbufsz(calllist_t *e, queue_t *wq, cred_t *cr)
{
	int ok = FALSE;
	int val;

	if (rpc_default_tcp_bufsz)
		return (FALSE);

	/*
	 * Only set new buffer size if it's larger than the system
	 * default buffer size. If smaller buffer size is needed
	 * then use /etc/system to set rpc_default_tcp_bufsz to 1.
	 */
	ok = connmgr_getopt_int(wq, SOL_SOCKET, SO_RCVBUF, &val, e, cr);
	if ((ok == TRUE) && (val < rpc_send_bufsz)) {
		ok = connmgr_setopt_int(wq, SOL_SOCKET, SO_RCVBUF,
		    rpc_send_bufsz, e, cr);
		DTRACE_PROBE2(krpc__i__connmgr_rcvbufsz,
		    int, ok, calllist_t *, e);
	}

	ok = connmgr_getopt_int(wq, SOL_SOCKET, SO_SNDBUF, &val, e, cr);
	if ((ok == TRUE) && (val < rpc_recv_bufsz)) {
		ok = connmgr_setopt_int(wq, SOL_SOCKET, SO_SNDBUF,
		    rpc_recv_bufsz, e, cr);
		DTRACE_PROBE2(krpc__i__connmgr_sndbufsz,
		    int, ok, calllist_t *, e);
	}
	return (TRUE);
}

/*
 * Given an open stream, connect to the remote.  Returns true if connected,
 * false otherwise.
 */
static bool_t
connmgr_connect(
	struct cm_xprt		*cm_entry,
	queue_t			*wq,
	struct netbuf		*addr,
	int			addrfmly,
	calllist_t 		*e,
	int 			*tidu_ptr,
	bool_t 			reconnect,
	const struct timeval 	*waitp,
	bool_t 			nosignal,
	cred_t			*cr)
{
	mblk_t *mp;
	struct T_conn_req *tcr;
	struct T_info_ack *tinfo;
	int interrupted, error;
	int tidu_size, kstat_instance;

	/* if it's a reconnect, flush any lingering data messages */
	if (reconnect)
		(void) putctl1(wq, M_FLUSH, FLUSHRW);

	/*
	 * Note: if the receiver uses SCM_UCRED/getpeerucred the pid will
	 * appear as -1.
	 */
	mp = allocb_cred(sizeof (*tcr) + addr->len, cr, NOPID);
	if (mp == NULL) {
		/*
		 * This is unfortunate, but we need to look up the stats for
		 * this zone to increment the "memory allocation failed"
		 * counter.  curproc->p_zone is safe since we're initiating a
		 * connection and not in some strange streams context.
		 */
		struct rpcstat *rpcstat;

		rpcstat = zone_getspecific(rpcstat_zone_key, rpc_zone());
		ASSERT(rpcstat != NULL);

		RPCLOG0(1, "connmgr_connect: cannot alloc mp for "
		    "sending conn request\n");
		COTSRCSTAT_INCR(rpcstat->rpc_cots_client, rcnomem);
		e->call_status = RPC_SYSTEMERROR;
		e->call_reason = ENOSR;
		return (FALSE);
	}

	/* Set TCP buffer size for RPC connections if needed */
	if (addrfmly == AF_INET || addrfmly == AF_INET6)
		(void) connmgr_setbufsz(e, wq, cr);

	mp->b_datap->db_type = M_PROTO;
	tcr = (struct T_conn_req *)mp->b_rptr;
	bzero(tcr, sizeof (*tcr));
	tcr->PRIM_type = T_CONN_REQ;
	tcr->DEST_length = addr->len;
	tcr->DEST_offset = sizeof (struct T_conn_req);
	mp->b_wptr = mp->b_rptr + sizeof (*tcr);

	bcopy(addr->buf, mp->b_wptr, tcr->DEST_length);
	mp->b_wptr += tcr->DEST_length;

	RPCLOG(8, "connmgr_connect: sending conn request on queue "
	    "%p", (void *)wq);
	RPCLOG(8, " call %p\n", (void *)wq);
	/*
	 * We use the entry in the handle that is normally used for
	 * waiting for RPC replies to wait for the connection accept.
	 */
	if (clnt_dispatch_send(wq, mp, e, 0, 0) != RPC_SUCCESS) {
		DTRACE_PROBE(krpc__e__connmgr__connect__cantsend);
		freemsg(mp);
		return (FALSE);
	}

	mutex_enter(&clnt_pending_lock);

	/*
	 * We wait for the transport connection to be made, or an
	 * indication that it could not be made.
	 */
	interrupted = 0;

	/*
	 * waitforack should have been called with T_OK_ACK, but the
	 * present implementation needs to be passed T_INFO_ACK to
	 * work correctly.
	 */
	error = waitforack(e, T_INFO_ACK, waitp, nosignal);
	if (error == EINTR)
		interrupted = 1;
	if (zone_status_get(curproc->p_zone) >= ZONE_IS_EMPTY) {
		/*
		 * No time to lose; we essentially have been signaled to
		 * quit.
		 */
		interrupted = 1;
	}
#ifdef RPCDEBUG
	if (error == ETIME)
		RPCLOG0(8, "connmgr_connect: giving up "
		    "on connection attempt; "
		    "clnt_dispatch notifyconn "
		    "diagnostic 'no one waiting for "
		    "connection' should not be "
		    "unexpected\n");
#endif
	if (e->call_prev)
		e->call_prev->call_next = e->call_next;
	else
		clnt_pending = e->call_next;
	if (e->call_next)
		e->call_next->call_prev = e->call_prev;
	mutex_exit(&clnt_pending_lock);

	if (e->call_status != RPC_SUCCESS || error != 0) {
		if (interrupted)
			e->call_status = RPC_INTR;
		else if (error == ETIME)
			e->call_status = RPC_TIMEDOUT;
		else if (error == EPROTO) {
			e->call_status = RPC_SYSTEMERROR;
			e->call_reason = EPROTO;
		}

		RPCLOG(8, "connmgr_connect: can't connect, status: "
		    "%s\n", clnt_sperrno(e->call_status));

		if (e->call_reply) {
			freemsg(e->call_reply);
			e->call_reply = NULL;
		}

		return (FALSE);
	}
	/*
	 * The result of the "connection accept" is a T_info_ack
	 * in the call_reply field.
	 */
	ASSERT(e->call_reply != NULL);
	mp = e->call_reply;
	e->call_reply = NULL;
	tinfo = (struct T_info_ack *)mp->b_rptr;

	tidu_size = tinfo->TIDU_size;
	tidu_size -= (tidu_size % BYTES_PER_XDR_UNIT);
	if (tidu_size > COTS_DEFAULT_ALLOCSIZE || (tidu_size <= 0))
		tidu_size = COTS_DEFAULT_ALLOCSIZE;
	*tidu_ptr = tidu_size;

	freemsg(mp);

	/*
	 * Set up the pertinent options.  NODELAY is so the transport doesn't
	 * buffer up RPC messages on either end.  This may not be valid for
	 * all transports.  Failure to set this option is not cause to
	 * bail out so we return success anyway.  Note that lack of NODELAY
	 * or some other way to flush the message on both ends will cause
	 * lots of retries and terrible performance.
	 */
	if (addrfmly == AF_INET || addrfmly == AF_INET6) {
		(void) connmgr_setopt(wq, IPPROTO_TCP, TCP_NODELAY, e, cr);
		if (e->call_status == RPC_XPRTFAILED)
			return (FALSE);
	}

	/*
	 * Since we have a connection, we now need to figure out if
	 * we need to create a kstat. If x_ksp is not NULL then we
	 * are reusing a connection and so we do not need to create
	 * another kstat -- lets just return.
	 */
	if (cm_entry->x_ksp != NULL)
		return (TRUE);

	/*
	 * We need to increment rpc_kstat_instance atomically to prevent
	 * two kstats being created with the same instance.
	 */
	kstat_instance = atomic_inc_32_nv((uint32_t *)&rpc_kstat_instance);

	if ((cm_entry->x_ksp = kstat_create_zone("unix", kstat_instance,
	    "rpc_cots_connections", "rpc", KSTAT_TYPE_NAMED,
	    (uint_t)(sizeof (cm_kstat_xprt_t) / sizeof (kstat_named_t)),
	    KSTAT_FLAG_VIRTUAL, cm_entry->x_zoneid)) == NULL) {
		return (TRUE);
	}

	cm_entry->x_ksp->ks_lock = &connmgr_lock;
	cm_entry->x_ksp->ks_private = cm_entry;
	cm_entry->x_ksp->ks_data_size = ((INET6_ADDRSTRLEN * sizeof (char))
	    + sizeof (cm_kstat_template));
	cm_entry->x_ksp->ks_data = kmem_alloc(cm_entry->x_ksp->ks_data_size,
	    KM_SLEEP);
	bcopy(&cm_kstat_template, cm_entry->x_ksp->ks_data,
	    cm_entry->x_ksp->ks_data_size);
	((struct cm_kstat_xprt *)(cm_entry->x_ksp->ks_data))->
	    x_server.value.str.addr.ptr =
	    kmem_alloc(INET6_ADDRSTRLEN, KM_SLEEP);

	cm_entry->x_ksp->ks_update = conn_kstat_update;
	kstat_install(cm_entry->x_ksp);
	return (TRUE);
}

/*
 * Verify that the specified offset falls within the mblk and
 * that the resulting pointer is aligned.
 * Returns NULL if not.
 *
 * code from fs/sockfs/socksubr.c
 */
static void *
connmgr_opt_getoff(mblk_t *mp, t_uscalar_t offset,
    t_uscalar_t length, uint_t align_size)
{
	uintptr_t ptr1, ptr2;

	ASSERT(mp && mp->b_wptr >= mp->b_rptr);
	ptr1 = (uintptr_t)mp->b_rptr + offset;
	ptr2 = (uintptr_t)ptr1 + length;
	if (ptr1 < (uintptr_t)mp->b_rptr || ptr2 > (uintptr_t)mp->b_wptr) {
		return (NULL);
	}
	if ((ptr1 & (align_size - 1)) != 0) {
		return (NULL);
	}
	return ((void *)ptr1);
}

static bool_t
connmgr_getopt_int(queue_t *wq, int level, int name, int *val,
    calllist_t *e, cred_t *cr)
{
	mblk_t *mp;
	struct opthdr *opt, *opt_res;
	struct T_optmgmt_req *tor;
	struct T_optmgmt_ack *opt_ack;
	struct timeval waitp;
	int error;

	mp = allocb_cred(sizeof (struct T_optmgmt_req) +
	    sizeof (struct opthdr) + sizeof (int), cr, NOPID);
	if (mp == NULL)
		return (FALSE);

	mp->b_datap->db_type = M_PROTO;
	tor = (struct T_optmgmt_req *)(mp->b_rptr);
	tor->PRIM_type = T_SVR4_OPTMGMT_REQ;
	tor->MGMT_flags = T_CURRENT;
	tor->OPT_length = sizeof (struct opthdr) + sizeof (int);
	tor->OPT_offset = sizeof (struct T_optmgmt_req);

	opt = (struct opthdr *)(mp->b_rptr + sizeof (struct T_optmgmt_req));
	opt->level = level;
	opt->name = name;
	opt->len = sizeof (int);
	mp->b_wptr += sizeof (struct T_optmgmt_req) + sizeof (struct opthdr) +
	    sizeof (int);

	/*
	 * We will use this connection regardless
	 * of whether or not the option is readable.
	 */
	if (clnt_dispatch_send(wq, mp, e, 0, 0) != RPC_SUCCESS) {
		DTRACE_PROBE(krpc__e__connmgr__getopt__cantsend);
		freemsg(mp);
		return (FALSE);
	}

	mutex_enter(&clnt_pending_lock);

	waitp.tv_sec = clnt_cots_min_conntout;
	waitp.tv_usec = 0;
	error = waitforack(e, T_OPTMGMT_ACK, &waitp, 1);

	if (e->call_prev)
		e->call_prev->call_next = e->call_next;
	else
		clnt_pending = e->call_next;
	if (e->call_next)
		e->call_next->call_prev = e->call_prev;
	mutex_exit(&clnt_pending_lock);

	/* get reply message */
	mp = e->call_reply;
	e->call_reply = NULL;

	if ((!mp) || (e->call_status != RPC_SUCCESS) || (error != 0)) {

		DTRACE_PROBE4(krpc__e__connmgr_getopt, int, name,
		    int, e->call_status, int, error, mblk_t *, mp);

		if (mp)
			freemsg(mp);
		return (FALSE);
	}

	opt_ack = (struct T_optmgmt_ack *)mp->b_rptr;
	opt_res = (struct opthdr *)connmgr_opt_getoff(mp, opt_ack->OPT_offset,
	    opt_ack->OPT_length, __TPI_ALIGN_SIZE);

	if (!opt_res) {
		DTRACE_PROBE4(krpc__e__connmgr_optres, mblk_t *, mp, int, name,
		    int, opt_ack->OPT_offset, int, opt_ack->OPT_length);
		freemsg(mp);
		return (FALSE);
	}
	*val = *(int *)&opt_res[1];

	DTRACE_PROBE2(connmgr_getopt__ok, int, name, int, *val);

	freemsg(mp);
	return (TRUE);
}

/*
 * Called by connmgr_connect to set an option on the new stream.
 */
static bool_t
connmgr_setopt_int(queue_t *wq, int level, int name, int val,
    calllist_t *e, cred_t *cr)
{
	mblk_t *mp;
	struct opthdr *opt;
	struct T_optmgmt_req *tor;
	struct timeval waitp;
	int error;

	mp = allocb_cred(sizeof (struct T_optmgmt_req) +
	    sizeof (struct opthdr) + sizeof (int), cr, NOPID);
	if (mp == NULL) {
		RPCLOG0(1, "connmgr_setopt: cannot alloc mp for option "
		    "request\n");
		return (FALSE);
	}

	mp->b_datap->db_type = M_PROTO;
	tor = (struct T_optmgmt_req *)(mp->b_rptr);
	tor->PRIM_type = T_SVR4_OPTMGMT_REQ;
	tor->MGMT_flags = T_NEGOTIATE;
	tor->OPT_length = sizeof (struct opthdr) + sizeof (int);
	tor->OPT_offset = sizeof (struct T_optmgmt_req);

	opt = (struct opthdr *)(mp->b_rptr + sizeof (struct T_optmgmt_req));
	opt->level = level;
	opt->name = name;
	opt->len = sizeof (int);
	*(int *)((char *)opt + sizeof (*opt)) = val;
	mp->b_wptr += sizeof (struct T_optmgmt_req) + sizeof (struct opthdr) +
	    sizeof (int);

	/*
	 * We will use this connection regardless
	 * of whether or not the option is settable.
	 */
	if (clnt_dispatch_send(wq, mp, e, 0, 0) != RPC_SUCCESS) {
		DTRACE_PROBE(krpc__e__connmgr__setopt__cantsend);
		freemsg(mp);
		return (FALSE);
	}

	mutex_enter(&clnt_pending_lock);

	waitp.tv_sec = clnt_cots_min_conntout;
	waitp.tv_usec = 0;
	error = waitforack(e, T_OPTMGMT_ACK, &waitp, 1);

	if (e->call_prev)
		e->call_prev->call_next = e->call_next;
	else
		clnt_pending = e->call_next;
	if (e->call_next)
		e->call_next->call_prev = e->call_prev;
	mutex_exit(&clnt_pending_lock);

	if (e->call_reply != NULL) {
		freemsg(e->call_reply);
		e->call_reply = NULL;
	}

	if (e->call_status != RPC_SUCCESS || error != 0) {
		RPCLOG(1, "connmgr_setopt: can't set option: %d\n", name);
		return (FALSE);
	}
	RPCLOG(8, "connmgr_setopt: successfully set option: %d\n", name);
	return (TRUE);
}

static bool_t
connmgr_setopt(queue_t *wq, int level, int name, calllist_t *e, cred_t *cr)
{
	return (connmgr_setopt_int(wq, level, name, 1, e, cr));
}

#ifdef	DEBUG

/*
 * This is a knob to let us force code coverage in allocation failure
 * case.
 */
static int	connmgr_failsnd;
#define	CONN_SND_ALLOC(Size, Pri)	\
	((connmgr_failsnd-- > 0) ? NULL : allocb(Size, Pri))

#else

#define	CONN_SND_ALLOC(Size, Pri)	allocb(Size, Pri)

#endif

/*
 * Sends an orderly release on the specified queue.
 * Entered with connmgr_lock. Exited without connmgr_lock
 */
static void
connmgr_sndrel(struct cm_xprt *cm_entry)
{
	struct T_ordrel_req *torr;
	mblk_t *mp;
	queue_t *q = cm_entry->x_wq;
	ASSERT(MUTEX_HELD(&connmgr_lock));
	mp = CONN_SND_ALLOC(sizeof (struct T_ordrel_req), BPRI_LO);
	if (mp == NULL) {
		cm_entry->x_needrel = TRUE;
		mutex_exit(&connmgr_lock);
		RPCLOG(1, "connmgr_sndrel: cannot alloc mp for sending ordrel "
		    "to queue %p\n", (void *)q);
		return;
	}
	mutex_exit(&connmgr_lock);

	mp->b_datap->db_type = M_PROTO;
	torr = (struct T_ordrel_req *)(mp->b_rptr);
	torr->PRIM_type = T_ORDREL_REQ;
	mp->b_wptr = mp->b_rptr + sizeof (struct T_ordrel_req);

	RPCLOG(8, "connmgr_sndrel: sending ordrel to queue %p\n", (void *)q);
	put(q, mp);
}

/*
 * Sends an disconnect on the specified queue.
 * Entered with connmgr_lock. Exited without connmgr_lock
 */
static void
connmgr_snddis(struct cm_xprt *cm_entry)
{
	struct T_discon_req *tdis;
	mblk_t *mp;
	queue_t *q = cm_entry->x_wq;

	ASSERT(MUTEX_HELD(&connmgr_lock));
	mp = CONN_SND_ALLOC(sizeof (*tdis), BPRI_LO);
	if (mp == NULL) {
		cm_entry->x_needdis = TRUE;
		mutex_exit(&connmgr_lock);
		RPCLOG(1, "connmgr_snddis: cannot alloc mp for sending discon "
		    "to queue %p\n", (void *)q);
		return;
	}
	mutex_exit(&connmgr_lock);

	mp->b_datap->db_type = M_PROTO;
	tdis = (struct T_discon_req *)mp->b_rptr;
	tdis->PRIM_type = T_DISCON_REQ;
	mp->b_wptr = mp->b_rptr + sizeof (*tdis);

	RPCLOG(8, "connmgr_snddis: sending discon to queue %p\n", (void *)q);
	put(q, mp);
}

/*
 * Sets up the entry for receiving replies, and calls rpcmod's write put proc
 * (through put) to send the call.
 */
static int
clnt_dispatch_send(queue_t *q, mblk_t *mp, calllist_t *e, uint_t xid,
    uint_t queue_flag)
{
	ASSERT(e != NULL);

	e->call_status = RPC_TIMEDOUT;	/* optimistic, eh? */
	e->call_reason = 0;
	e->call_wq = q;
	e->call_xid = xid;
	e->call_notified = FALSE;

	if (!canput(q)) {
		e->call_status = RPC_CANTSEND;
		e->call_reason = ENOBUFS;
		return (RPC_CANTSEND);
	}

	/*
	 * If queue_flag is set then the calllist_t is already on the hash
	 * queue.  In this case just send the message and return.
	 */
	if (queue_flag) {
		put(q, mp);
		return (RPC_SUCCESS);

	}

	/*
	 * Set up calls for RPC requests (with XID != 0) on the hash
	 * queue for fast lookups and place other calls (i.e.
	 * connection management) on the linked list.
	 */
	if (xid != 0) {
		RPCLOG(64, "clnt_dispatch_send: putting xid 0x%x on "
		    "dispatch list\n", xid);
		e->call_hash = call_hash(xid, clnt_cots_hash_size);
		e->call_bucket = &cots_call_ht[e->call_hash];
		call_table_enter(e);
	} else {
		mutex_enter(&clnt_pending_lock);
		if (clnt_pending)
			clnt_pending->call_prev = e;
		e->call_next = clnt_pending;
		e->call_prev = NULL;
		clnt_pending = e;
		mutex_exit(&clnt_pending_lock);
	}

	put(q, mp);
	return (RPC_SUCCESS);
}

/*
 * Called by rpcmod to notify a client with a clnt_pending call that its reply
 * has arrived.  If we can't find a client waiting for this reply, we log
 * the error and return.
 */
bool_t
clnt_dispatch_notify(mblk_t *mp, zoneid_t zoneid)
{
	calllist_t *e = NULL;
	call_table_t *chtp;
	uint32_t xid;
	uint_t hash;

	if ((IS_P2ALIGNED(mp->b_rptr, sizeof (uint32_t))) &&
	    (mp->b_wptr - mp->b_rptr) >= sizeof (xid))
		xid = *((uint32_t *)mp->b_rptr);
	else {
		int i = 0;
		unsigned char *p = (unsigned char *)&xid;
		unsigned char *rptr;
		mblk_t *tmp = mp;

		/*
		 * Copy the xid, byte-by-byte into xid.
		 */
		while (tmp) {
			rptr = tmp->b_rptr;
			while (rptr < tmp->b_wptr) {
				*p++ = *rptr++;
				if (++i >= sizeof (xid))
					goto done_xid_copy;
			}
			tmp = tmp->b_cont;
		}

		/*
		 * If we got here, we ran out of mblk space before the
		 * xid could be copied.
		 */
		ASSERT(tmp == NULL && i < sizeof (xid));

		RPCLOG0(1,
		    "clnt_dispatch_notify: message less than size of xid\n");
		return (FALSE);

	}
done_xid_copy:

	hash = call_hash(xid, clnt_cots_hash_size);
	chtp = &cots_call_ht[hash];
	/* call_table_find returns with the hash bucket locked */
	call_table_find(chtp, xid, e);

	if (e != NULL) {
		/*
		 * Found thread waiting for this reply
		 */
		mutex_enter(&e->call_lock);

		/*
		 * verify that the reply is coming in on
		 * the same zone that it was sent from.
		 */
		if (e->call_zoneid != zoneid) {
			mutex_exit(&e->call_lock);
			mutex_exit(&chtp->ct_lock);
			RPCLOG0(1, "clnt_dispatch_notify: incorrect zoneid\n");
			return (FALSE);
		}

		if (e->call_reply)
			/*
			 * This can happen under the following scenario:
			 * clnt_cots_kcallit() times out on the response,
			 * rfscall() repeats the CLNT_CALL() with
			 * the same xid, clnt_cots_kcallit() sends the retry,
			 * thereby putting the clnt handle on the pending list,
			 * the first response arrives, signalling the thread
			 * in clnt_cots_kcallit(). Before that thread is
			 * dispatched, the second response arrives as well,
			 * and clnt_dispatch_notify still finds the handle on
			 * the pending list, with call_reply set. So free the
			 * old reply now.
			 *
			 * It is also possible for a response intended for
			 * an RPC call with a different xid to reside here.
			 * This can happen if the thread that owned this
			 * client handle prior to the current owner bailed
			 * out and left its call record on the dispatch
			 * queue.  A window exists where the response can
			 * arrive before the current owner dispatches its
			 * RPC call.
			 *
			 * In any case, this is the very last point where we
			 * can safely check the call_reply field before
			 * placing the new response there.
			 */
			freemsg(e->call_reply);
		e->call_reply = mp;
		e->call_status = RPC_SUCCESS;
		e->call_notified = TRUE;
		cv_signal(&e->call_cv);
		mutex_exit(&e->call_lock);
		mutex_exit(&chtp->ct_lock);
		return (TRUE);
	} else {
		zone_t *zone;
		struct rpcstat *rpcstat;

		mutex_exit(&chtp->ct_lock);
		RPCLOG(65, "clnt_dispatch_notify: no caller for reply 0x%x\n",
		    xid);
		/*
		 * This is unfortunate, but we need to lookup the zone so we
		 * can increment its "rcbadxids" counter.
		 */
		zone = zone_find_by_id(zoneid);
		if (zone == NULL) {
			/*
			 * The zone went away...
			 */
			return (FALSE);
		}
		rpcstat = zone_getspecific(rpcstat_zone_key, zone);
		if (zone_status_get(zone) >= ZONE_IS_SHUTTING_DOWN) {
			/*
			 * Not interested
			 */
			zone_rele(zone);
			return (FALSE);
		}
		COTSRCSTAT_INCR(rpcstat->rpc_cots_client, rcbadxids);
		zone_rele(zone);
	}
	return (FALSE);
}

/*
 * Called by rpcmod when a non-data indication arrives.  The ones in which we
 * are interested are connection indications and options acks.  We dispatch
 * based on the queue the indication came in on.  If we are not interested in
 * what came in, we return false to rpcmod, who will then pass it upstream.
 */
bool_t
clnt_dispatch_notifyconn(queue_t *q, mblk_t *mp)
{
	calllist_t *e;
	int type;

	ASSERT((q->q_flag & QREADR) == 0);

	type = ((union T_primitives *)mp->b_rptr)->type;
	RPCLOG(8, "clnt_dispatch_notifyconn: prim type: [%s]\n",
	    rpc_tpiprim2name(type));
	mutex_enter(&clnt_pending_lock);
	for (e = clnt_pending; /* NO CONDITION */; e = e->call_next) {
		if (e == NULL) {
			mutex_exit(&clnt_pending_lock);
			RPCLOG(1, "clnt_dispatch_notifyconn: no one waiting "
			    "for connection on queue 0x%p\n", (void *)q);
			return (FALSE);
		}
		if (e->call_wq == q)
			break;
	}

	switch (type) {
	case T_CONN_CON:
		/*
		 * The transport is now connected, send a T_INFO_REQ to get
		 * the tidu size.
		 */
		mutex_exit(&clnt_pending_lock);
		ASSERT(mp->b_datap->db_lim - mp->b_datap->db_base >=
		    sizeof (struct T_info_req));
		mp->b_rptr = mp->b_datap->db_base;
		((union T_primitives *)mp->b_rptr)->type = T_INFO_REQ;
		mp->b_wptr = mp->b_rptr + sizeof (struct T_info_req);
		mp->b_datap->db_type = M_PCPROTO;
		put(q, mp);
		return (TRUE);
	case T_INFO_ACK:
	case T_OPTMGMT_ACK:
		e->call_status = RPC_SUCCESS;
		e->call_reply = mp;
		e->call_notified = TRUE;
		cv_signal(&e->call_cv);
		break;
	case T_ERROR_ACK:
		e->call_status = RPC_CANTCONNECT;
		e->call_reply = mp;
		e->call_notified = TRUE;
		cv_signal(&e->call_cv);
		break;
	case T_OK_ACK:
		/*
		 * Great, but we are really waiting for a T_CONN_CON
		 */
		freemsg(mp);
		break;
	default:
		mutex_exit(&clnt_pending_lock);
		RPCLOG(1, "clnt_dispatch_notifyconn: bad type %d\n", type);
		return (FALSE);
	}

	mutex_exit(&clnt_pending_lock);
	return (TRUE);
}

/*
 * Called by rpcmod when the transport is (or should be) going away.  Informs
 * all callers waiting for replies and marks the entry in the connection
 * manager's list as unconnected, and either closing (close handshake in
 * progress) or dead.
 */
void
clnt_dispatch_notifyall(queue_t *q, int32_t msg_type, int32_t reason)
{
	calllist_t *e;
	call_table_t *ctp;
	struct cm_xprt *cm_entry;
	int have_connmgr_lock;
	int i;

	ASSERT((q->q_flag & QREADR) == 0);

	RPCLOG(1, "clnt_dispatch_notifyall on queue %p", (void *)q);
	RPCLOG(1, " received a notifcation prim type [%s]",
	    rpc_tpiprim2name(msg_type));
	RPCLOG(1, " and reason %d\n", reason);

	/*
	 * Find the transport entry in the connection manager's list, close
	 * the transport and delete the entry.  In the case where rpcmod's
	 * idle timer goes off, it sends us a T_ORDREL_REQ, indicating we
	 * should gracefully close the connection.
	 */
	have_connmgr_lock = 1;
	mutex_enter(&connmgr_lock);
	for (cm_entry = cm_hd; cm_entry; cm_entry = cm_entry->x_next) {
		ASSERT(cm_entry != cm_entry->x_next);
		if (cm_entry->x_wq == q) {
			ASSERT(MUTEX_HELD(&connmgr_lock));
			ASSERT(have_connmgr_lock == 1);
			switch (msg_type) {
			case T_ORDREL_REQ:

				if (cm_entry->x_dead) {
					RPCLOG(1, "idle timeout on dead "
					    "connection: %p\n",
					    (void *)cm_entry);
					if (clnt_stop_idle != NULL)
						(*clnt_stop_idle)(q);
					break;
				}

				/*
				 * Only mark the connection as dead if it is
				 * connected and idle.
				 * An unconnected connection has probably
				 * gone idle because the server is down,
				 * and when it comes back up there will be
				 * retries that need to use that connection.
				 */
				if (cm_entry->x_connected ||
				    cm_entry->x_doomed) {
					if (cm_entry->x_ordrel) {
						if (cm_entry->x_closing ==
						    TRUE) {
							/*
							 * The connection is
							 * obviously wedged due
							 * to a bug or problem
							 * with the transport.
							 * Mark it as dead.
							 * Otherwise we can
							 * leak connections.
							 */
							cm_entry->x_dead = TRUE;
							mutex_exit(
							    &connmgr_lock);
							have_connmgr_lock = 0;
							if (clnt_stop_idle !=
							    NULL)
							(*clnt_stop_idle)(q);
							break;
						}
						cm_entry->x_closing = TRUE;
						connmgr_sndrel(cm_entry);
						have_connmgr_lock = 0;
					} else {
						cm_entry->x_dead = TRUE;
						mutex_exit(&connmgr_lock);
						have_connmgr_lock = 0;
						if (clnt_stop_idle != NULL)
							(*clnt_stop_idle)(q);
					}
				} else {
					/*
					 * We don't mark the connection
					 * as dead, but we turn off the
					 * idle timer.
					 */
					mutex_exit(&connmgr_lock);
					have_connmgr_lock = 0;
					if (clnt_stop_idle != NULL)
						(*clnt_stop_idle)(q);
					RPCLOG(1, "clnt_dispatch_notifyall:"
					    " ignoring timeout from rpcmod"
					    " (q %p) because we are not "
					    " connected\n", (void *)q);
				}
				break;
			case T_ORDREL_IND:
				/*
				 * If this entry is marked closing, then we are
				 * completing a close handshake, and the
				 * connection is dead.  Otherwise, the server is
				 * trying to close. Since the server will not
				 * be sending any more RPC replies, we abort
				 * the connection, including flushing
				 * any RPC requests that are in-transit.
				 * In either case, mark the entry as dead so
				 * that it can be closed by the connection
				 * manager's garbage collector.
				 */
				cm_entry->x_dead = TRUE;
				if (cm_entry->x_closing) {
					mutex_exit(&connmgr_lock);
					have_connmgr_lock = 0;
					if (clnt_stop_idle != NULL)
						(*clnt_stop_idle)(q);
				} else {
					/*
					 * if we're getting a disconnect
					 * before we've finished our
					 * connect attempt, mark it for
					 * later processing
					 */
					if (cm_entry->x_thread)
						cm_entry->x_early_disc = TRUE;
					else
						cm_entry->x_connected = FALSE;
					cm_entry->x_waitdis = TRUE;
					connmgr_snddis(cm_entry);
					have_connmgr_lock = 0;
				}
				break;

			case T_ERROR_ACK:
			case T_OK_ACK:
				cm_entry->x_waitdis = FALSE;
				cv_signal(&cm_entry->x_dis_cv);
				mutex_exit(&connmgr_lock);
				return;

			case T_DISCON_REQ:
				if (cm_entry->x_thread)
					cm_entry->x_early_disc = TRUE;
				else
					cm_entry->x_connected = FALSE;
				cm_entry->x_waitdis = TRUE;

				connmgr_snddis(cm_entry);
				have_connmgr_lock = 0;
				break;

			case T_DISCON_IND:
			default:
				/*
				 * if we're getting a disconnect before
				 * we've finished our connect attempt,
				 * mark it for later processing
				 */
				if (cm_entry->x_closing) {
					cm_entry->x_dead = TRUE;
					mutex_exit(&connmgr_lock);
					have_connmgr_lock = 0;
					if (clnt_stop_idle != NULL)
						(*clnt_stop_idle)(q);
				} else {
					if (cm_entry->x_thread) {
						cm_entry->x_early_disc = TRUE;
					} else {
						cm_entry->x_dead = TRUE;
						cm_entry->x_connected = FALSE;
					}
				}
				break;
			}
			break;
		}
	}

	if (have_connmgr_lock)
		mutex_exit(&connmgr_lock);

	if (msg_type == T_ERROR_ACK || msg_type == T_OK_ACK) {
		RPCLOG(1, "clnt_dispatch_notifyall: (wq %p) could not find "
		    "connmgr entry for discon ack\n", (void *)q);
		return;
	}

	/*
	 * Then kick all the clnt_pending calls out of their wait.  There
	 * should be no clnt_pending calls in the case of rpcmod's idle
	 * timer firing.
	 */
	for (i = 0; i < clnt_cots_hash_size; i++) {
		ctp = &cots_call_ht[i];
		mutex_enter(&ctp->ct_lock);
		for (e = ctp->ct_call_next;
		    e != (calllist_t *)ctp;
		    e = e->call_next) {
			if (e->call_wq == q && e->call_notified == FALSE) {
				RPCLOG(1,
				    "clnt_dispatch_notifyall for queue %p ",
				    (void *)q);
				RPCLOG(1, "aborting clnt_pending call %p\n",
				    (void *)e);

				if (msg_type == T_DISCON_IND)
					e->call_reason = reason;
				e->call_notified = TRUE;
				e->call_status = RPC_XPRTFAILED;
				cv_signal(&e->call_cv);
			}
		}
		mutex_exit(&ctp->ct_lock);
	}

	mutex_enter(&clnt_pending_lock);
	for (e = clnt_pending; e; e = e->call_next) {
		/*
		 * Only signal those RPC handles that haven't been
		 * signalled yet. Otherwise we can get a bogus call_reason.
		 * This can happen if thread A is making a call over a
		 * connection. If the server is killed, it will cause
		 * reset, and reason will default to EIO as a result of
		 * a T_ORDREL_IND. Thread B then attempts to recreate
		 * the connection but gets a T_DISCON_IND. If we set the
		 * call_reason code for all threads, then if thread A
		 * hasn't been dispatched yet, it will get the wrong
		 * reason. The bogus call_reason can make it harder to
		 * discriminate between calls that fail because the
		 * connection attempt failed versus those where the call
		 * may have been executed on the server.
		 */
		if (e->call_wq == q && e->call_notified == FALSE) {
			RPCLOG(1, "clnt_dispatch_notifyall for queue %p ",
			    (void *)q);
			RPCLOG(1, " aborting clnt_pending call %p\n",
			    (void *)e);

			if (msg_type == T_DISCON_IND)
				e->call_reason = reason;
			e->call_notified = TRUE;
			/*
			 * Let the caller timeout, else it will retry
			 * immediately.
			 */
			e->call_status = RPC_XPRTFAILED;

			/*
			 * We used to just signal those threads
			 * waiting for a connection, (call_xid = 0).
			 * That meant that threads waiting for a response
			 * waited till their timeout expired. This
			 * could be a long time if they've specified a
			 * maximum timeout. (2^31 - 1). So we
			 * Signal all threads now.
			 */
			cv_signal(&e->call_cv);
		}
	}
	mutex_exit(&clnt_pending_lock);
}


/*ARGSUSED*/
/*
 * after resuming a system that's been suspended for longer than the
 * NFS server's idle timeout (svc_idle_timeout for Solaris 2), rfscall()
 * generates "NFS server X not responding" and "NFS server X ok" messages;
 * here we reset inet connections to cause a re-connect and avoid those
 * NFS messages.  see 4045054
 */
boolean_t
connmgr_cpr_reset(void *arg, int code)
{
	struct cm_xprt *cxp;

	if (code == CB_CODE_CPR_CHKPT)
		return (B_TRUE);

	if (mutex_tryenter(&connmgr_lock) == 0)
		return (B_FALSE);
	for (cxp = cm_hd; cxp; cxp = cxp->x_next) {
		if ((cxp->x_family == AF_INET || cxp->x_family == AF_INET6) &&
		    cxp->x_connected == TRUE) {
			if (cxp->x_thread)
				cxp->x_early_disc = TRUE;
			else
				cxp->x_connected = FALSE;
			cxp->x_needdis = TRUE;
		}
	}
	mutex_exit(&connmgr_lock);
	return (B_TRUE);
}

void
clnt_cots_stats_init(zoneid_t zoneid, struct rpc_cots_client **statsp)
{

	*statsp = (struct rpc_cots_client *)rpcstat_zone_init_common(zoneid,
	    "unix", "rpc_cots_client", (const kstat_named_t *)&cots_rcstat_tmpl,
	    sizeof (cots_rcstat_tmpl));
}

void
clnt_cots_stats_fini(zoneid_t zoneid, struct rpc_cots_client **statsp)
{
	rpcstat_zone_fini_common(zoneid, "unix", "rpc_cots_client");
	kmem_free(*statsp, sizeof (cots_rcstat_tmpl));
}

void
clnt_cots_init(void)
{
	mutex_init(&connmgr_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&clnt_pending_lock, NULL, MUTEX_DEFAULT, NULL);

	if (clnt_cots_hash_size < DEFAULT_MIN_HASH_SIZE)
		clnt_cots_hash_size = DEFAULT_MIN_HASH_SIZE;

	cots_call_ht = call_table_init(clnt_cots_hash_size);
	zone_key_create(&zone_cots_key, NULL, NULL, clnt_zone_destroy);
}

void
clnt_cots_fini(void)
{
	(void) zone_key_delete(zone_cots_key);
}

/*
 * Wait for TPI ack, returns success only if expected ack is received
 * within timeout period.
 */

static int
waitforack(calllist_t *e, t_scalar_t ack_prim, const struct timeval *waitp,
    bool_t nosignal)
{
	union T_primitives *tpr;
	clock_t timout;
	int cv_stat = 1;

	ASSERT(MUTEX_HELD(&clnt_pending_lock));
	while (e->call_reply == NULL) {
		if (waitp != NULL) {
			timout = waitp->tv_sec * drv_usectohz(MICROSEC) +
			    drv_usectohz(waitp->tv_usec);
			if (nosignal)
				cv_stat = cv_reltimedwait(&e->call_cv,
				    &clnt_pending_lock, timout, TR_CLOCK_TICK);
			else
				cv_stat = cv_reltimedwait_sig(&e->call_cv,
				    &clnt_pending_lock, timout, TR_CLOCK_TICK);
		} else {
			if (nosignal)
				cv_wait(&e->call_cv, &clnt_pending_lock);
			else
				cv_stat = cv_wait_sig(&e->call_cv,
				    &clnt_pending_lock);
		}
		if (cv_stat == -1)
			return (ETIME);
		if (cv_stat == 0)
			return (EINTR);
		/*
		 * if we received an error from the server and we know a reply
		 * is not going to be sent, do not wait for the full timeout,
		 * return now.
		 */
		if (e->call_status == RPC_XPRTFAILED)
			return (e->call_reason);
	}
	tpr = (union T_primitives *)e->call_reply->b_rptr;
	if (tpr->type == ack_prim)
		return (0); /* Success */

	if (tpr->type == T_ERROR_ACK) {
		if (tpr->error_ack.TLI_error == TSYSERR)
			return (tpr->error_ack.UNIX_error);
		else
			return (t_tlitosyserr(tpr->error_ack.TLI_error));
	}

	return (EPROTO); /* unknown or unexpected primitive */
}
