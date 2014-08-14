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

/*
 * Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T
 * All Rights Reserved
 */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */


/*
 * Implements a kernel based, client side RPC.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/ddi.h>
#include <sys/tiuser.h>
#include <sys/tihdr.h>
#include <sys/t_kuser.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/kstat.h>
#include <sys/t_lock.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/disp.h>
#include <sys/taskq.h>
#include <sys/list.h>
#include <sys/atomic.h>
#include <sys/zone.h>
#include <netinet/in.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <rpc/rpc_msg.h>

#include <sys/sdt.h>

static enum clnt_stat clnt_clts_kcallit(CLIENT *, rpcproc_t, xdrproc_t,
		    caddr_t, xdrproc_t, caddr_t, struct timeval);
static void	clnt_clts_kabort(CLIENT *);
static void	clnt_clts_kerror(CLIENT *, struct rpc_err *);
static bool_t	clnt_clts_kfreeres(CLIENT *, xdrproc_t, caddr_t);
static bool_t	clnt_clts_kcontrol(CLIENT *, int, char *);
static void	clnt_clts_kdestroy(CLIENT *);
static int	clnt_clts_ksettimers(CLIENT *, struct rpc_timers *,
		    struct rpc_timers *, int, void (*)(), caddr_t, uint32_t);

/*
 * Operations vector for CLTS based RPC
 */
static struct clnt_ops clts_ops = {
	clnt_clts_kcallit,	/* do rpc call */
	clnt_clts_kabort,	/* abort call */
	clnt_clts_kerror,	/* return error status */
	clnt_clts_kfreeres,	/* free results */
	clnt_clts_kdestroy,	/* destroy rpc handle */
	clnt_clts_kcontrol,	/* the ioctl() of rpc */
	clnt_clts_ksettimers	/* set retry timers */
};

/*
 * Endpoint for CLTS (INET, INET6, loopback, etc.)
 */
typedef struct endpnt_type {
	struct endpnt_type *e_next;	/* pointer to next endpoint type */
	list_t		e_pool;		/* list of available endpoints */
	list_t		e_ilist;	/* list of idle endpoints */
	struct endpnt	*e_pcurr;	/* pointer to current endpoint */
	char		e_protofmly[KNC_STRSIZE];	/* protocol family */
	dev_t		e_rdev;		/* device */
	kmutex_t	e_plock;	/* pool lock */
	kmutex_t	e_ilock;	/* idle list lock */
	timeout_id_t	e_itimer;	/* timer to dispatch the taskq */
	uint_t		e_cnt;		/* number of endpoints in the pool */
	zoneid_t	e_zoneid;	/* zoneid of endpoint type */
	kcondvar_t	e_async_cv;	/* cv for asynchronous reap threads */
	uint_t		e_async_count;	/* count of asynchronous reap threads */
} endpnt_type_t;

typedef struct endpnt {
	list_node_t	e_node;		/* link to the pool */
	list_node_t	e_idle;		/* link to the idle list */
	endpnt_type_t	*e_type;	/* back pointer to endpoint type */
	TIUSER		*e_tiptr;	/* pointer to transport endpoint */
	queue_t		*e_wq;		/* write queue */
	uint_t		e_flags;	/* endpoint flags */
	uint_t		e_ref;		/* ref count on endpoint */
	kcondvar_t	e_cv;		/* condition variable */
	kmutex_t	e_lock;		/* protects cv and flags */
	time_t		e_itime;	/* time when rele'd */
} endpnt_t;

#define	ENDPNT_ESTABLISHED	0x1	/* endpoint is established */
#define	ENDPNT_WAITING		0x2	/* thread waiting for endpoint */
#define	ENDPNT_BOUND		0x4	/* endpoint is bound */
#define	ENDPNT_STALE		0x8	/* endpoint is dead */
#define	ENDPNT_ONIDLE		0x10	/* endpoint is on the idle list */

static krwlock_t	endpnt_type_lock; /* protects endpnt_type_list */
static endpnt_type_t	*endpnt_type_list = NULL; /* list of CLTS endpoints */
static struct kmem_cache	*endpnt_cache; /* cache of endpnt_t's */
static taskq_t			*endpnt_taskq; /* endpnt_t reaper thread */
static bool_t			taskq_created; /* flag for endpnt_taskq */
static kmutex_t			endpnt_taskq_lock; /* taskq lock */
static zone_key_t		endpnt_destructor_key;

#define	DEFAULT_ENDPOINT_REAP_INTERVAL 60 /* 1 minute */
#define	DEFAULT_INTERVAL_SHIFT 30 /* 30 seconds */

/*
 * Endpoint tunables
 */
static int	clnt_clts_max_endpoints = -1;
static int	clnt_clts_hash_size = DEFAULT_HASH_SIZE;
static time_t	clnt_clts_endpoint_reap_interval = -1;
static clock_t	clnt_clts_taskq_dispatch_interval;

/*
 * Response completion hash queue
 */
static call_table_t *clts_call_ht;

/*
 * Routines for the endpoint manager
 */
static struct endpnt_type *endpnt_type_create(struct knetconfig *);
static void endpnt_type_free(struct endpnt_type *);
static int check_endpnt(struct endpnt *, struct endpnt **);
static struct endpnt *endpnt_get(struct knetconfig *, int);
static void endpnt_rele(struct endpnt *);
static void endpnt_reap_settimer(endpnt_type_t *);
static void endpnt_reap(endpnt_type_t *);
static void endpnt_reap_dispatch(void *);
static void endpnt_reclaim(zoneid_t);


/*
 * Request dipatching function.
 */
static int clnt_clts_dispatch_send(queue_t *q, mblk_t *, struct netbuf *addr,
					calllist_t *, uint_t, cred_t *);

/*
 * The size of the preserialized RPC header information.
 */
#define	CKU_HDRSIZE	20
/*
 * The initial allocation size.  It is small to reduce space requirements.
 */
#define	CKU_INITSIZE	2048
/*
 * The size of additional allocations, if required.  It is larger to
 * reduce the number of actual allocations.
 */
#define	CKU_ALLOCSIZE	8192

/*
 * Private data per rpc handle.  This structure is allocated by
 * clnt_clts_kcreate, and freed by clnt_clts_kdestroy.
 */
struct cku_private {
	CLIENT			 cku_client;	/* client handle */
	int			 cku_retrys;	/* request retrys */
	calllist_t		 cku_call;
	struct endpnt		*cku_endpnt;	/* open end point */
	struct knetconfig	 cku_config;
	struct netbuf		 cku_addr;	/* remote address */
	struct rpc_err		 cku_err;	/* error status */
	XDR			 cku_outxdr;	/* xdr stream for output */
	XDR			 cku_inxdr;	/* xdr stream for input */
	char			 cku_rpchdr[CKU_HDRSIZE + 4]; /* rpc header */
	struct cred		*cku_cred;	/* credentials */
	struct rpc_timers	*cku_timers;	/* for estimating RTT */
	struct rpc_timers	*cku_timeall;	/* for estimating RTT */
	void			 (*cku_feedback)(int, int, caddr_t);
						/* ptr to feedback rtn */
	caddr_t			 cku_feedarg;	/* argument for feedback func */
	uint32_t		 cku_xid;	/* current XID */
	bool_t			 cku_bcast;	/* RPC broadcast hint */
	int			cku_useresvport; /* Use reserved port */
	struct rpc_clts_client	*cku_stats;	/* counters for the zone */
};

static const struct rpc_clts_client {
	kstat_named_t	rccalls;
	kstat_named_t	rcbadcalls;
	kstat_named_t	rcretrans;
	kstat_named_t	rcbadxids;
	kstat_named_t	rctimeouts;
	kstat_named_t	rcnewcreds;
	kstat_named_t	rcbadverfs;
	kstat_named_t	rctimers;
	kstat_named_t	rcnomem;
	kstat_named_t	rccantsend;
} clts_rcstat_tmpl = {
	{ "calls",	KSTAT_DATA_UINT64 },
	{ "badcalls",	KSTAT_DATA_UINT64 },
	{ "retrans",	KSTAT_DATA_UINT64 },
	{ "badxids",	KSTAT_DATA_UINT64 },
	{ "timeouts",	KSTAT_DATA_UINT64 },
	{ "newcreds",	KSTAT_DATA_UINT64 },
	{ "badverfs",	KSTAT_DATA_UINT64 },
	{ "timers",	KSTAT_DATA_UINT64 },
	{ "nomem",	KSTAT_DATA_UINT64 },
	{ "cantsend",	KSTAT_DATA_UINT64 },
};

static uint_t clts_rcstat_ndata =
	sizeof (clts_rcstat_tmpl) / sizeof (kstat_named_t);

#define	RCSTAT_INCR(s, x)			\
	atomic_inc_64(&(s)->x.value.ui64)

#define	ptoh(p)		(&((p)->cku_client))
#define	htop(h)		((struct cku_private *)((h)->cl_private))

/*
 * Times to retry
 */
#define	SNDTRIES	4
#define	REFRESHES	2	/* authentication refreshes */

/*
 * The following is used to determine the global default behavior for
 * CLTS when binding to a local port.
 *
 * If the value is set to 1 the default will be to select a reserved
 * (aka privileged) port, if the value is zero the default will be to
 * use non-reserved ports.  Users of kRPC may override this by using
 * CLNT_CONTROL() and CLSET_BINDRESVPORT.
 */
static int clnt_clts_do_bindresvport = 1;

#define	BINDRESVPORT_RETRIES 5

void
clnt_clts_stats_init(zoneid_t zoneid, struct rpc_clts_client **statsp)
{
	kstat_t *ksp;
	kstat_named_t *knp;

	knp = rpcstat_zone_init_common(zoneid, "unix", "rpc_clts_client",
	    (const kstat_named_t *)&clts_rcstat_tmpl,
	    sizeof (clts_rcstat_tmpl));
	/*
	 * Backwards compatibility for old kstat clients
	 */
	ksp = kstat_create_zone("unix", 0, "rpc_client", "rpc",
	    KSTAT_TYPE_NAMED, clts_rcstat_ndata,
	    KSTAT_FLAG_VIRTUAL | KSTAT_FLAG_WRITABLE, zoneid);
	if (ksp) {
		ksp->ks_data = knp;
		kstat_install(ksp);
	}
	*statsp = (struct rpc_clts_client *)knp;
}

void
clnt_clts_stats_fini(zoneid_t zoneid, struct rpc_clts_client **statsp)
{
	rpcstat_zone_fini_common(zoneid, "unix", "rpc_clts_client");
	kstat_delete_byname_zone("unix", 0, "rpc_client", zoneid);
	kmem_free(*statsp, sizeof (clts_rcstat_tmpl));
}

/*
 * Create an rpc handle for a clts rpc connection.
 * Allocates space for the handle structure and the private data.
 */
/* ARGSUSED */
int
clnt_clts_kcreate(struct knetconfig *config, struct netbuf *addr,
	rpcprog_t pgm, rpcvers_t vers, int retrys, struct cred *cred,
	CLIENT **cl)
{
	CLIENT *h;
	struct cku_private *p;
	struct rpc_msg call_msg;
	int error;
	int plen;

	if (cl == NULL)
		return (EINVAL);

	*cl = NULL;
	error = 0;

	p = kmem_zalloc(sizeof (*p), KM_SLEEP);

	h = ptoh(p);

	/* handle */
	h->cl_ops = &clts_ops;
	h->cl_private = (caddr_t)p;
	h->cl_auth = authkern_create();

	/* call message, just used to pre-serialize below */
	call_msg.rm_xid = 0;
	call_msg.rm_direction = CALL;
	call_msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
	call_msg.rm_call.cb_prog = pgm;
	call_msg.rm_call.cb_vers = vers;

	/* private */
	clnt_clts_kinit(h, addr, retrys, cred);

	xdrmem_create(&p->cku_outxdr, p->cku_rpchdr, CKU_HDRSIZE, XDR_ENCODE);

	/* pre-serialize call message header */
	if (!xdr_callhdr(&p->cku_outxdr, &call_msg)) {
		error = EINVAL;		/* XXX */
		goto bad;
	}

	p->cku_config.knc_rdev = config->knc_rdev;
	p->cku_config.knc_semantics = config->knc_semantics;
	plen = strlen(config->knc_protofmly) + 1;
	p->cku_config.knc_protofmly = kmem_alloc(plen, KM_SLEEP);
	bcopy(config->knc_protofmly, p->cku_config.knc_protofmly, plen);
	p->cku_useresvport = -1; /* value is has not been set */

	cv_init(&p->cku_call.call_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&p->cku_call.call_lock, NULL, MUTEX_DEFAULT, NULL);

	*cl = h;
	return (0);

bad:
	auth_destroy(h->cl_auth);
	kmem_free(p->cku_addr.buf, addr->maxlen);
	kmem_free(p, sizeof (struct cku_private));

	return (error);
}

void
clnt_clts_kinit(CLIENT *h, struct netbuf *addr, int retrys, cred_t *cred)
{
	/* LINTED pointer alignment */
	struct cku_private *p = htop(h);
	struct rpcstat *rsp;

	rsp = zone_getspecific(rpcstat_zone_key, rpc_zone());
	ASSERT(rsp != NULL);

	p->cku_retrys = retrys;

	if (p->cku_addr.maxlen < addr->len) {
		if (p->cku_addr.maxlen != 0 && p->cku_addr.buf != NULL)
			kmem_free(p->cku_addr.buf, p->cku_addr.maxlen);

		p->cku_addr.buf = kmem_zalloc(addr->maxlen, KM_SLEEP);
		p->cku_addr.maxlen = addr->maxlen;
	}

	p->cku_addr.len = addr->len;
	bcopy(addr->buf, p->cku_addr.buf, addr->len);

	p->cku_cred = cred;
	p->cku_xid = 0;
	p->cku_timers = NULL;
	p->cku_timeall = NULL;
	p->cku_feedback = NULL;
	p->cku_bcast = FALSE;
	p->cku_call.call_xid = 0;
	p->cku_call.call_hash = 0;
	p->cku_call.call_notified = FALSE;
	p->cku_call.call_next = NULL;
	p->cku_call.call_prev = NULL;
	p->cku_call.call_reply = NULL;
	p->cku_call.call_wq = NULL;
	p->cku_stats = rsp->rpc_clts_client;
}

/*
 * set the timers.  Return current retransmission timeout.
 */
static int
clnt_clts_ksettimers(CLIENT *h, struct rpc_timers *t, struct rpc_timers *all,
	int minimum, void (*feedback)(int, int, caddr_t), caddr_t arg,
	uint32_t xid)
{
	/* LINTED pointer alignment */
	struct cku_private *p = htop(h);
	int value;

	p->cku_feedback = feedback;
	p->cku_feedarg = arg;
	p->cku_timers = t;
	p->cku_timeall = all;
	if (xid)
		p->cku_xid = xid;
	value = all->rt_rtxcur;
	value += t->rt_rtxcur;
	if (value < minimum)
		return (minimum);
	RCSTAT_INCR(p->cku_stats, rctimers);
	return (value);
}

/*
 * Time out back off function. tim is in HZ
 */
#define	MAXTIMO	(20 * hz)
#define	backoff(tim)	(((tim) < MAXTIMO) ? dobackoff(tim) : (tim))
#define	dobackoff(tim)	((((tim) << 1) > MAXTIMO) ? MAXTIMO : ((tim) << 1))

#define	RETRY_POLL_TIMO	30

/*
 * Call remote procedure.
 * Most of the work of rpc is done here.  We serialize what is left
 * of the header (some was pre-serialized in the handle), serialize
 * the arguments, and send it off.  We wait for a reply or a time out.
 * Timeout causes an immediate return, other packet problems may cause
 * a retry on the receive.  When a good packet is received we deserialize
 * it, and check verification.  A bad reply code will cause one retry
 * with full (longhand) credentials.
 */
enum clnt_stat
clnt_clts_kcallit_addr(CLIENT *h, rpcproc_t procnum, xdrproc_t xdr_args,
	caddr_t argsp, xdrproc_t xdr_results, caddr_t resultsp,
	struct timeval wait, struct netbuf *sin)
{
	/* LINTED pointer alignment */
	struct cku_private *p = htop(h);
	XDR *xdrs;
	int stries = p->cku_retrys;
	int refreshes = REFRESHES;	/* number of times to refresh cred */
	int round_trip;			/* time the RPC */
	int error;
	mblk_t *mp;
	mblk_t *mpdup;
	mblk_t *resp = NULL;
	mblk_t *tmp;
	calllist_t *call = &p->cku_call;
	clock_t ori_timout, timout;
	bool_t interrupted;
	enum clnt_stat status;
	struct rpc_msg reply_msg;
	enum clnt_stat re_status;
	endpnt_t *endpt;

	RCSTAT_INCR(p->cku_stats, rccalls);

	RPCLOG(2, "clnt_clts_kcallit_addr: wait.tv_sec: %ld\n", wait.tv_sec);
	RPCLOG(2, "clnt_clts_kcallit_addr: wait.tv_usec: %ld\n", wait.tv_usec);

	timout = TIMEVAL_TO_TICK(&wait);
	ori_timout = timout;

	if (p->cku_xid == 0) {
		p->cku_xid = alloc_xid();
		if (p->cku_endpnt != NULL)
			endpnt_rele(p->cku_endpnt);
		p->cku_endpnt = NULL;
	}
	call->call_zoneid = rpc_zoneid();

	mpdup = NULL;
call_again:

	if (mpdup == NULL) {

		while ((mp = allocb(CKU_INITSIZE, BPRI_LO)) == NULL) {
			if (strwaitbuf(CKU_INITSIZE, BPRI_LO)) {
				p->cku_err.re_status = RPC_SYSTEMERROR;
				p->cku_err.re_errno = ENOSR;
				goto done;
			}
		}

		xdrs = &p->cku_outxdr;
		xdrmblk_init(xdrs, mp, XDR_ENCODE, CKU_ALLOCSIZE);

		if (h->cl_auth->ah_cred.oa_flavor != RPCSEC_GSS) {
			/*
			 * Copy in the preserialized RPC header
			 * information.
			 */
			bcopy(p->cku_rpchdr, mp->b_rptr, CKU_HDRSIZE);

			/*
			 * transaction id is the 1st thing in the output
			 * buffer.
			 */
			/* LINTED pointer alignment */
			(*(uint32_t *)(mp->b_rptr)) = p->cku_xid;

			/* Skip the preserialized stuff. */
			XDR_SETPOS(xdrs, CKU_HDRSIZE);

			/* Serialize dynamic stuff into the output buffer. */
			if ((!XDR_PUTINT32(xdrs, (int32_t *)&procnum)) ||
			    (!AUTH_MARSHALL(h->cl_auth, xdrs, p->cku_cred)) ||
			    (!(*xdr_args)(xdrs, argsp))) {
				freemsg(mp);
				p->cku_err.re_status = RPC_CANTENCODEARGS;
				p->cku_err.re_errno = EIO;
				goto done;
			}
		} else {
			uint32_t *uproc = (uint32_t *)
			    &p->cku_rpchdr[CKU_HDRSIZE];
			IXDR_PUT_U_INT32(uproc, procnum);

			(*(uint32_t *)(&p->cku_rpchdr[0])) = p->cku_xid;
			XDR_SETPOS(xdrs, 0);

			/* Serialize the procedure number and the arguments. */
			if (!AUTH_WRAP(h->cl_auth, (caddr_t)p->cku_rpchdr,
			    CKU_HDRSIZE+4, xdrs, xdr_args, argsp)) {
				freemsg(mp);
				p->cku_err.re_status = RPC_CANTENCODEARGS;
				p->cku_err.re_errno = EIO;
				goto done;
			}
		}
	} else
		mp = mpdup;

	mpdup = dupmsg(mp);
	if (mpdup == NULL) {
		freemsg(mp);
		p->cku_err.re_status = RPC_SYSTEMERROR;
		p->cku_err.re_errno = ENOSR;
		goto done;
	}

	/*
	 * Grab an endpnt only if the endpoint is NULL.  We could be retrying
	 * the request and in this case we want to go through the same
	 * source port, so that the duplicate request cache may detect a
	 * retry.
	 */

	if (p->cku_endpnt == NULL)
		p->cku_endpnt = endpnt_get(&p->cku_config, p->cku_useresvport);

	if (p->cku_endpnt == NULL) {
		freemsg(mp);
		p->cku_err.re_status = RPC_SYSTEMERROR;
		p->cku_err.re_errno = ENOSR;
		goto done;
	}

	round_trip = ddi_get_lbolt();

	error = clnt_clts_dispatch_send(p->cku_endpnt->e_wq, mp,
	    &p->cku_addr, call, p->cku_xid, p->cku_cred);

	if (error != 0) {
		freemsg(mp);
		p->cku_err.re_status = RPC_CANTSEND;
		p->cku_err.re_errno = error;
		RCSTAT_INCR(p->cku_stats, rccantsend);
		goto done1;
	}

	RPCLOG(64, "clnt_clts_kcallit_addr: sent call for xid 0x%x\n",
	    p->cku_xid);

	/*
	 * There are two reasons for which we go back to to tryread.
	 *
	 * a) In case the status is RPC_PROCUNAVAIL and we sent out a
	 *    broadcast we should not get any invalid messages with the
	 *    RPC_PROCUNAVAIL error back. Some broken RPC implementations
	 *    send them and for this we have to ignore them ( as we would
	 *    have never received them ) and look for another message
	 *    which might contain the valid response because we don't know
	 *    how many broken implementations are in the network. So we are
	 *    going to loop until
	 *    - we received a valid response
	 *    - we have processed all invalid responses and
	 *	got a time out when we try to receive again a
	 *	message.
	 *
	 * b) We will jump back to tryread also in case we failed
	 *    within the AUTH_VALIDATE. In this case we should move
	 *    on and loop until we received a valid response or we
	 *    have processed all responses with broken authentication
	 *    and we got a time out when we try to receive a message.
	 */
tryread:
	mutex_enter(&call->call_lock);
	interrupted = FALSE;
	if (call->call_notified == FALSE) {
		klwp_t *lwp = ttolwp(curthread);
		clock_t cv_wait_ret = 1; /* init to > 0 */
		clock_t cv_timout = timout;

		if (lwp != NULL)
			lwp->lwp_nostop++;

		cv_timout += ddi_get_lbolt();

		if (h->cl_nosignal)
			while ((cv_wait_ret =
			    cv_timedwait(&call->call_cv,
			    &call->call_lock, cv_timout)) > 0 &&
			    call->call_notified == FALSE)
				;
		else
			while ((cv_wait_ret =
			    cv_timedwait_sig(&call->call_cv,
			    &call->call_lock, cv_timout)) > 0 &&
			    call->call_notified == FALSE)
				;

		if (cv_wait_ret == 0)
			interrupted = TRUE;

		if (lwp != NULL)
			lwp->lwp_nostop--;
	}
	resp = call->call_reply;
	call->call_reply = NULL;
	status = call->call_status;
	/*
	 * We have to reset the call_notified here. In case we have
	 * to do a retry ( e.g. in case we got a RPC_PROCUNAVAIL
	 * error ) we need to set this to false to ensure that
	 * we will wait for the next message. When the next message
	 * is going to arrive the function clnt_clts_dispatch_notify
	 * will set this to true again.
	 */
	call->call_notified = FALSE;
	call->call_status = RPC_TIMEDOUT;
	mutex_exit(&call->call_lock);

	if (status == RPC_TIMEDOUT) {
		if (interrupted) {
			/*
			 * We got interrupted, bail out
			 */
			p->cku_err.re_status = RPC_INTR;
			p->cku_err.re_errno = EINTR;
			goto done1;
		} else {
			RPCLOG(8, "clnt_clts_kcallit_addr: "
			    "request w/xid 0x%x timedout "
			    "waiting for reply\n", p->cku_xid);
#if 0 /* XXX not yet */
			/*
			 * Timeout may be due to a dead gateway. Send
			 * an ioctl downstream advising deletion of
			 * route when we reach the half-way point to
			 * timing out.
			 */
			if (stries == p->cku_retrys/2) {
				t_kadvise(p->cku_endpnt->e_tiptr,
				    (uchar_t *)p->cku_addr.buf,
				    p->cku_addr.len);
			}
#endif /* not yet */
			p->cku_err.re_status = RPC_TIMEDOUT;
			p->cku_err.re_errno = ETIMEDOUT;
			RCSTAT_INCR(p->cku_stats, rctimeouts);
			goto done1;
		}
	}

	ASSERT(resp != NULL);

	/*
	 * Prepare the message for further processing.  We need to remove
	 * the datagram header and copy the source address if necessary.  No
	 * need to verify the header since rpcmod took care of that.
	 */
	/*
	 * Copy the source address if the caller has supplied a netbuf.
	 */
	if (sin != NULL) {
		union T_primitives *pptr;

		pptr = (union T_primitives *)resp->b_rptr;
		bcopy(resp->b_rptr + pptr->unitdata_ind.SRC_offset, sin->buf,
		    pptr->unitdata_ind.SRC_length);
		sin->len = pptr->unitdata_ind.SRC_length;
	}

	/*
	 * Pop off the datagram header.
	 * It was retained in rpcmodrput().
	 */
	tmp = resp;
	resp = resp->b_cont;
	tmp->b_cont = NULL;
	freeb(tmp);

	round_trip = ddi_get_lbolt() - round_trip;
	/*
	 * Van Jacobson timer algorithm here, only if NOT a retransmission.
	 */
	if (p->cku_timers != NULL && stries == p->cku_retrys) {
		int rt;

		rt = round_trip;
		rt -= (p->cku_timers->rt_srtt >> 3);
		p->cku_timers->rt_srtt += rt;
		if (rt < 0)
			rt = - rt;
		rt -= (p->cku_timers->rt_deviate >> 2);
		p->cku_timers->rt_deviate += rt;
		p->cku_timers->rt_rtxcur =
		    (clock_t)((p->cku_timers->rt_srtt >> 2) +
		    p->cku_timers->rt_deviate) >> 1;

		rt = round_trip;
		rt -= (p->cku_timeall->rt_srtt >> 3);
		p->cku_timeall->rt_srtt += rt;
		if (rt < 0)
			rt = - rt;
		rt -= (p->cku_timeall->rt_deviate >> 2);
		p->cku_timeall->rt_deviate += rt;
		p->cku_timeall->rt_rtxcur =
		    (clock_t)((p->cku_timeall->rt_srtt >> 2) +
		    p->cku_timeall->rt_deviate) >> 1;
		if (p->cku_feedback != NULL) {
			(*p->cku_feedback)(FEEDBACK_OK, procnum,
			    p->cku_feedarg);
		}
	}

	/*
	 * Process reply
	 */
	xdrs = &(p->cku_inxdr);
	xdrmblk_init(xdrs, resp, XDR_DECODE, 0);

	reply_msg.rm_direction = REPLY;
	reply_msg.rm_reply.rp_stat = MSG_ACCEPTED;
	reply_msg.acpted_rply.ar_stat = SUCCESS;
	reply_msg.acpted_rply.ar_verf = _null_auth;
	/*
	 *  xdr_results will be done in AUTH_UNWRAP.
	 */
	reply_msg.acpted_rply.ar_results.where = NULL;
	reply_msg.acpted_rply.ar_results.proc = xdr_void;

	/*
	 * Decode and validate the response.
	 */
	if (!xdr_replymsg(xdrs, &reply_msg)) {
		p->cku_err.re_status = RPC_CANTDECODERES;
		p->cku_err.re_errno = EIO;
		(void) xdr_rpc_free_verifier(xdrs, &reply_msg);
		goto done1;
	}

	_seterr_reply(&reply_msg, &(p->cku_err));

	re_status = p->cku_err.re_status;
	if (re_status == RPC_SUCCESS) {
		/*
		 * Reply is good, check auth.
		 */
		if (!AUTH_VALIDATE(h->cl_auth,
		    &reply_msg.acpted_rply.ar_verf)) {
			p->cku_err.re_status = RPC_AUTHERROR;
			p->cku_err.re_why = AUTH_INVALIDRESP;
			RCSTAT_INCR(p->cku_stats, rcbadverfs);
			(void) xdr_rpc_free_verifier(xdrs, &reply_msg);
			goto tryread;
		}
		if (!AUTH_UNWRAP(h->cl_auth, xdrs, xdr_results, resultsp)) {
			p->cku_err.re_status = RPC_CANTDECODERES;
			p->cku_err.re_errno = EIO;
		}
		(void) xdr_rpc_free_verifier(xdrs, &reply_msg);
		goto done1;
	}
	/* set errno in case we can't recover */
	if (re_status != RPC_VERSMISMATCH &&
	    re_status != RPC_AUTHERROR && re_status != RPC_PROGVERSMISMATCH)
		p->cku_err.re_errno = EIO;
	/*
	 * Determine whether or not we're doing an RPC
	 * broadcast. Some server implementations don't
	 * follow RFC 1050, section 7.4.2 in that they
	 * don't remain silent when they see a proc
	 * they don't support. Therefore we keep trying
	 * to receive on RPC_PROCUNAVAIL, hoping to get
	 * a valid response from a compliant server.
	 */
	if (re_status == RPC_PROCUNAVAIL && p->cku_bcast) {
		(void) xdr_rpc_free_verifier(xdrs, &reply_msg);
		goto tryread;
	}
	if (re_status == RPC_AUTHERROR) {

		(void) xdr_rpc_free_verifier(xdrs, &reply_msg);
		call_table_remove(call);
		if (call->call_reply != NULL) {
			freemsg(call->call_reply);
			call->call_reply = NULL;
		}

		/*
		 * Maybe our credential need to be refreshed
		 */
		if (refreshes > 0 &&
		    AUTH_REFRESH(h->cl_auth, &reply_msg, p->cku_cred)) {
			/*
			 * The credential is refreshed. Try the request again.
			 * Even if stries == 0, we still retry as long as
			 * refreshes > 0. This prevents a soft authentication
			 * error turning into a hard one at an upper level.
			 */
			refreshes--;
			RCSTAT_INCR(p->cku_stats, rcbadcalls);
			RCSTAT_INCR(p->cku_stats, rcnewcreds);

			freemsg(mpdup);
			mpdup = NULL;
			freemsg(resp);
			resp = NULL;
			goto call_again;
		}
		/*
		 * We have used the client handle to do an AUTH_REFRESH
		 * and the RPC status may be set to RPC_SUCCESS;
		 * Let's make sure to set it to RPC_AUTHERROR.
		 */
		p->cku_err.re_status = RPC_CANTDECODERES;

		/*
		 * Map recoverable and unrecoverable
		 * authentication errors to appropriate errno
		 */
		switch (p->cku_err.re_why) {
		case AUTH_TOOWEAK:
			/*
			 * Could be an nfsportmon failure, set
			 * useresvport and try again.
			 */
			if (p->cku_useresvport != 1) {
				p->cku_useresvport = 1;

				freemsg(mpdup);
				mpdup = NULL;
				freemsg(resp);
				resp = NULL;

				endpt = p->cku_endpnt;
				if (endpt->e_tiptr != NULL) {
					mutex_enter(&endpt->e_lock);
					endpt->e_flags &= ~ENDPNT_BOUND;
					(void) t_kclose(endpt->e_tiptr, 1);
					endpt->e_tiptr = NULL;
					mutex_exit(&endpt->e_lock);

				}

				p->cku_xid = alloc_xid();
				endpnt_rele(p->cku_endpnt);
				p->cku_endpnt = NULL;
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
		default:
			p->cku_err.re_errno = EIO;
			break;
		}
		RPCLOG(1, "clnt_clts_kcallit : authentication failed "
		    "with RPC_AUTHERROR of type %d\n",
		    p->cku_err.re_why);
		goto done;
	}

	(void) xdr_rpc_free_verifier(xdrs, &reply_msg);

done1:
	call_table_remove(call);
	if (call->call_reply != NULL) {
		freemsg(call->call_reply);
		call->call_reply = NULL;
	}
	RPCLOG(64, "clnt_clts_kcallit_addr: xid 0x%x taken off dispatch list",
	    p->cku_xid);

done:
	if (resp != NULL) {
		freemsg(resp);
		resp = NULL;
	}

	if ((p->cku_err.re_status != RPC_SUCCESS) &&
	    (p->cku_err.re_status != RPC_INTR) &&
	    (p->cku_err.re_status != RPC_UDERROR) &&
	    !IS_UNRECOVERABLE_RPC(p->cku_err.re_status)) {
		if (p->cku_feedback != NULL && stries == p->cku_retrys) {
			(*p->cku_feedback)(FEEDBACK_REXMIT1, procnum,
			    p->cku_feedarg);
		}

		timout = backoff(timout);
		if (p->cku_timeall != (struct rpc_timers *)0)
			p->cku_timeall->rt_rtxcur = timout;

		if (p->cku_err.re_status == RPC_SYSTEMERROR ||
		    p->cku_err.re_status == RPC_CANTSEND) {
			/*
			 * Errors due to lack of resources, wait a bit
			 * and try again.
			 */
			(void) delay(hz/10);
		}
		if (stries-- > 0) {
			RCSTAT_INCR(p->cku_stats, rcretrans);
			goto call_again;
		}
	}

	if (mpdup != NULL)
		freemsg(mpdup);

	if (p->cku_err.re_status != RPC_SUCCESS) {
		RCSTAT_INCR(p->cku_stats, rcbadcalls);
	}

	/*
	 * Allow the endpoint to be held by the client handle in case this
	 * RPC was not successful.  A retry may occur at a higher level and
	 * in this case we may want to send the request over the same
	 * source port.
	 * Endpoint is also released for one-way RPC: no reply, nor retransmit
	 * is expected.
	 */
	if ((p->cku_err.re_status == RPC_SUCCESS ||
	    (p->cku_err.re_status == RPC_TIMEDOUT && ori_timout == 0)) &&
	    p->cku_endpnt != NULL) {
		endpnt_rele(p->cku_endpnt);
		p->cku_endpnt = NULL;
	} else {
		DTRACE_PROBE2(clnt_clts_kcallit_done, int, p->cku_err.re_status,
		    struct endpnt *, p->cku_endpnt);
	}

	return (p->cku_err.re_status);
}

static enum clnt_stat
clnt_clts_kcallit(CLIENT *h, rpcproc_t procnum, xdrproc_t xdr_args,
	caddr_t argsp, xdrproc_t xdr_results, caddr_t resultsp,
	struct timeval wait)
{
	return (clnt_clts_kcallit_addr(h, procnum, xdr_args, argsp,
	    xdr_results, resultsp, wait, NULL));
}

/*
 * Return error info on this handle.
 */
static void
clnt_clts_kerror(CLIENT *h, struct rpc_err *err)
{
	/* LINTED pointer alignment */
	struct cku_private *p = htop(h);

	*err = p->cku_err;
}

static bool_t
clnt_clts_kfreeres(CLIENT *h, xdrproc_t xdr_res, caddr_t res_ptr)
{
	/* LINTED pointer alignment */
	struct cku_private *p = htop(h);
	XDR *xdrs;

	xdrs = &(p->cku_outxdr);
	xdrs->x_op = XDR_FREE;
	return ((*xdr_res)(xdrs, res_ptr));
}

/*ARGSUSED*/
static void
clnt_clts_kabort(CLIENT *h)
{
}

static bool_t
clnt_clts_kcontrol(CLIENT *h, int cmd, char *arg)
{
	/* LINTED pointer alignment */
	struct cku_private *p = htop(h);

	switch (cmd) {
	case CLSET_XID:
		p->cku_xid = *((uint32_t *)arg);
		return (TRUE);

	case CLGET_XID:
		*((uint32_t *)arg) = p->cku_xid;
		return (TRUE);

	case CLSET_BCAST:
		p->cku_bcast = *((uint32_t *)arg);
		return (TRUE);

	case CLGET_BCAST:
		*((uint32_t *)arg) = p->cku_bcast;
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
 * Destroy rpc handle.
 * Frees the space used for output buffer, private data, and handle
 * structure, and the file pointer/TLI data on last reference.
 */
static void
clnt_clts_kdestroy(CLIENT *h)
{
	/* LINTED pointer alignment */
	struct cku_private *p = htop(h);
	calllist_t *call = &p->cku_call;

	int plen;

	RPCLOG(8, "clnt_clts_kdestroy h: %p\n", (void *)h);
	RPCLOG(8, "clnt_clts_kdestroy h: xid=0x%x\n", p->cku_xid);

	if (p->cku_endpnt != NULL)
		endpnt_rele(p->cku_endpnt);

	cv_destroy(&call->call_cv);
	mutex_destroy(&call->call_lock);

	plen = strlen(p->cku_config.knc_protofmly) + 1;
	kmem_free(p->cku_config.knc_protofmly, plen);
	kmem_free(p->cku_addr.buf, p->cku_addr.maxlen);
	kmem_free(p, sizeof (*p));
}

/*
 * The connectionless (CLTS) kRPC endpoint management subsystem.
 *
 * Because endpoints are potentially shared among threads making RPC calls,
 * they are managed in a pool according to type (endpnt_type_t).  Each
 * endpnt_type_t points to a list of usable endpoints through the e_pool
 * field, which is of type list_t.  list_t is a doubly-linked list.
 * The number of endpoints in the pool is stored in the e_cnt field of
 * endpnt_type_t and the endpoints are reference counted using the e_ref field
 * in the endpnt_t structure.
 *
 * As an optimization, endpoints that have no references are also linked
 * to an idle list via e_ilist which is also of type list_t.  When a thread
 * calls endpnt_get() to obtain a transport endpoint, the idle list is first
 * consulted and if such an endpoint exists, it is removed from the idle list
 * and returned to the caller.
 *
 * If the idle list is empty, then a check is made to see if more endpoints
 * can be created.  If so, we proceed and create a new endpoint which is added
 * to the pool and returned to the caller.  If we have reached the limit and
 * cannot make a new endpoint then one is returned to the caller via round-
 * robin policy.
 *
 * When an endpoint is placed on the idle list by a thread calling
 * endpnt_rele(), it is timestamped and then a reaper taskq is scheduled to
 * be dispatched if one hasn't already been.  When the timer fires, the
 * taskq traverses the idle list and checks to see which endpoints are
 * eligible to be closed.  It determines this by checking if the timestamp
 * when the endpoint was released has exceeded the the threshold for how long
 * it should stay alive.
 *
 * endpnt_t structures remain persistent until the memory reclaim callback,
 * endpnt_reclaim(), is invoked.
 *
 * Here is an example of how the data structures would be laid out by the
 * subsystem:
 *
 *       endpnt_type_t
 *
 *	 loopback		                  inet
 *	 _______________	                  ______________
 *	| e_next        |----------------------->| e_next       |---->>
 *	| e_pool        |<---+                   | e_pool       |<----+
 *	| e_ilist       |<---+--+                | e_ilist      |<----+--+
 *   +->| e_pcurr       |----+--+--+	      +->| e_pcurr      |-----+--+--+
 *   |	| ...           |    |  |  |	      |	 | ...	        |     |  |  |
 *   |	| e_itimer (90) |    |  |  |	      |	 | e_itimer (0) |     |  |  |
 *   |	| e_cnt (1)     |    |  |  |	      |	 | e_cnt (3)    |     |  |  |
 *   |	+---------------+    |  |  |	      |	 +--------------+     |  |  |
 *   |			     |  |  |	      |			      |  |  |
 *   |   endpnt_t            |  |  |          |	                      |  |  |
 *   |	 ____________        |  |  |	      |	  ____________        |  |  |
 *   |	| e_node     |<------+  |  |	      |	 | e_node     |<------+  |  |
 *   |	| e_idle     |<---------+  |	      |	 | e_idle     |       |  |  |
 *   +--| e_type     |<------------+	      +--| e_type     |       |  |  |
 *	| e_tiptr    |                        |  | e_tiptr    |       |  |  |
 *      | ...	     |		              |	 | ...	      |       |  |  |
 *	| e_lock     |		              |	 | e_lock     |       |  |  |
 *	| ...        |		              |	 | ...	      |       |  |  |
 *      | e_ref (0)  |		              |	 | e_ref (2)  |       |  |  |
 *	| e_itime    |	                      |	 | e_itime    |       |  |  |
 *	+------------+		              |	 +------------+       |  |  |
 *					      |			      |  |  |
 *					      |			      |  |  |
 *					      |	  ____________        |  |  |
 *					      |	 | e_node     |<------+  |  |
 *					      |	 | e_idle     |<------+--+  |
 *					      +--| e_type     |       |     |
 *					      |	 | e_tiptr    |       |     |
 *					      |	 | ...	      |       |     |
 *					      |	 | e_lock     |       |     |
 *					      |	 | ...	      |       |     |
 *					      |	 | e_ref (0)  |       |     |
 *					      |	 | e_itime    |       |     |
 *					      |	 +------------+       |     |
 *					      |			      |     |
 *					      |			      |     |
 *					      |	  ____________        |     |
 *					      |	 | e_node     |<------+     |
 *					      |	 | e_idle     |             |
 *					      +--| e_type     |<------------+
 *						 | e_tiptr    |
 *						 | ...	      |
 *						 | e_lock     |
 *						 | ...	      |
 *						 | e_ref (1)  |
 *						 | e_itime    |
 *						 +------------+
 *
 * Endpoint locking strategy:
 *
 * The following functions manipulate lists which hold the endpoint and the
 * endpoints themselves:
 *
 * endpnt_get()/check_endpnt()/endpnt_rele()/endpnt_reap()/do_endpnt_reclaim()
 *
 * Lock description follows:
 *
 * endpnt_type_lock: Global reader/writer lock which protects accesses to the
 *		     endpnt_type_list.
 *
 * e_plock: Lock defined in the endpnt_type_t.  It is intended to
 *	    protect accesses to the pool of endopints (e_pool) for a given
 *	    endpnt_type_t.
 *
 * e_ilock: Lock defined in endpnt_type_t.  It is intended to protect accesses
 *	    to the idle list (e_ilist) of available endpoints for a given
 *	    endpnt_type_t.  It also protects access to the e_itimer, e_async_cv,
 *	    and e_async_count fields in endpnt_type_t.
 *
 * e_lock: Lock defined in the endpnt structure.  It is intended to protect
 *	   flags, cv, and ref count.
 *
 * The order goes as follows so as not to induce deadlock.
 *
 * endpnt_type_lock -> e_plock -> e_ilock -> e_lock
 *
 * Interaction with Zones and shutting down:
 *
 * endpnt_type_ts are uniquely identified by the (e_zoneid, e_rdev, e_protofmly)
 * tuple, which means that a zone may not reuse another zone's idle endpoints
 * without first doing a t_kclose().
 *
 * A zone's endpnt_type_ts are destroyed when a zone is shut down; e_async_cv
 * and e_async_count are used to keep track of the threads in endpnt_taskq
 * trying to reap endpnt_ts in the endpnt_type_t.
 */

/*
 * Allocate and initialize an endpnt_type_t
 */
static struct endpnt_type *
endpnt_type_create(struct knetconfig *config)
{
	struct endpnt_type	*etype;

	/*
	 * Allocate a new endpoint type to hang a list of
	 * endpoints off of it.
	 */
	etype = kmem_alloc(sizeof (struct endpnt_type), KM_SLEEP);
	etype->e_next = NULL;
	etype->e_pcurr = NULL;
	etype->e_itimer = 0;
	etype->e_cnt = 0;

	(void) strncpy(etype->e_protofmly, config->knc_protofmly, KNC_STRSIZE);
	mutex_init(&etype->e_plock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&etype->e_ilock, NULL, MUTEX_DEFAULT, NULL);
	etype->e_rdev = config->knc_rdev;
	etype->e_zoneid = rpc_zoneid();
	etype->e_async_count = 0;
	cv_init(&etype->e_async_cv, NULL, CV_DEFAULT, NULL);

	list_create(&etype->e_pool, sizeof (endpnt_t),
	    offsetof(endpnt_t, e_node));
	list_create(&etype->e_ilist, sizeof (endpnt_t),
	    offsetof(endpnt_t, e_idle));

	/*
	 * Check to see if we need to create a taskq for endpoint
	 * reaping
	 */
	mutex_enter(&endpnt_taskq_lock);
	if (taskq_created == FALSE) {
		taskq_created = TRUE;
		mutex_exit(&endpnt_taskq_lock);
		ASSERT(endpnt_taskq == NULL);
		endpnt_taskq = taskq_create("clts_endpnt_taskq", 1,
		    minclsyspri, 200, INT_MAX, 0);
	} else
		mutex_exit(&endpnt_taskq_lock);

	return (etype);
}

/*
 * Free an endpnt_type_t
 */
static void
endpnt_type_free(struct endpnt_type *etype)
{
	mutex_destroy(&etype->e_plock);
	mutex_destroy(&etype->e_ilock);
	list_destroy(&etype->e_pool);
	list_destroy(&etype->e_ilist);
	kmem_free(etype, sizeof (endpnt_type_t));
}

/*
 * Check the endpoint to ensure that it is suitable for use.
 *
 * Possible return values:
 *
 * return (1) - Endpoint is established, but needs to be re-opened.
 * return (0) && *newp == NULL - Endpoint is established, but unusable.
 * return (0) && *newp != NULL - Endpoint is established and usable.
 */
static int
check_endpnt(struct endpnt *endp, struct endpnt **newp)
{
	*newp = endp;

	mutex_enter(&endp->e_lock);
	ASSERT(endp->e_ref >= 1);

	/*
	 * The first condition we check for is if the endpoint has been
	 * allocated, but is unusable either because it has been closed or
	 * has been marked stale.  Only *one* thread will be allowed to
	 * execute the then clause.  This is enforced because the first thread
	 * to check this condition will clear the flags, so that subsequent
	 * thread(s) checking this endpoint will move on.
	 */
	if ((endp->e_flags & ENDPNT_ESTABLISHED) &&
	    (!(endp->e_flags & ENDPNT_BOUND) ||
	    (endp->e_flags & ENDPNT_STALE))) {
		/*
		 * Clear the flags here since they will be
		 * set again by this thread.  They need to be
		 * individually cleared because we want to maintain
		 * the state for ENDPNT_ONIDLE.
		 */
		endp->e_flags &= ~(ENDPNT_ESTABLISHED |
		    ENDPNT_WAITING | ENDPNT_BOUND | ENDPNT_STALE);
		mutex_exit(&endp->e_lock);
		return (1);
	}

	/*
	 * The second condition is meant for any thread that is waiting for
	 * an endpoint to become established.  It will cv_wait() until
	 * the condition for the endpoint has been changed to ENDPNT_BOUND or
	 * ENDPNT_STALE.
	 */
	while (!(endp->e_flags & ENDPNT_BOUND) &&
	    !(endp->e_flags & ENDPNT_STALE)) {
		endp->e_flags |= ENDPNT_WAITING;
		cv_wait(&endp->e_cv, &endp->e_lock);
	}

	ASSERT(endp->e_flags & ENDPNT_ESTABLISHED);

	/*
	 * The last case we check for is if the endpoint has been marked stale.
	 * If this is the case then set *newp to NULL and return, so that the
	 * caller is notified of the error and can take appropriate action.
	 */
	if (endp->e_flags & ENDPNT_STALE) {
		endp->e_ref--;
		*newp = NULL;
	}
	mutex_exit(&endp->e_lock);
	return (0);
}

#ifdef DEBUG
/*
 * Provide a fault injection setting to test error conditions.
 */
static int endpnt_get_return_null = 0;
#endif

/*
 * Returns a handle (struct endpnt *) to an open and bound endpoint
 * specified by the knetconfig passed in.  Returns NULL if no valid endpoint
 * can be obtained.
 */
static struct endpnt *
endpnt_get(struct knetconfig *config, int useresvport)
{
	struct endpnt_type	*n_etype = NULL;
	struct endpnt_type	*np = NULL;
	struct endpnt		*new = NULL;
	struct endpnt		*endp = NULL;
	struct endpnt		*next = NULL;
	TIUSER			*tiptr = NULL;
	int			rtries = BINDRESVPORT_RETRIES;
	int			i = 0;
	int			error;
	int			retval;
	zoneid_t		zoneid = rpc_zoneid();
	cred_t			*cr;

	RPCLOG(1, "endpnt_get: protofmly %s, ", config->knc_protofmly);
	RPCLOG(1, "rdev %ld\n", config->knc_rdev);

#ifdef DEBUG
	/*
	 * Inject fault if desired.  Pretend we have a stale endpoint
	 * and return NULL.
	 */
	if (endpnt_get_return_null > 0) {
		endpnt_get_return_null--;
		return (NULL);
	}
#endif
	rw_enter(&endpnt_type_lock, RW_READER);

top:
	for (np = endpnt_type_list; np != NULL; np = np->e_next)
		if ((np->e_zoneid == zoneid) &&
		    (np->e_rdev == config->knc_rdev) &&
		    (strcmp(np->e_protofmly,
		    config->knc_protofmly) == 0))
			break;

	if (np == NULL && n_etype != NULL) {
		ASSERT(rw_write_held(&endpnt_type_lock));

		/*
		 * Link the endpoint type onto the list
		 */
		n_etype->e_next = endpnt_type_list;
		endpnt_type_list = n_etype;
		np = n_etype;
		n_etype = NULL;
	}

	if (np == NULL) {
		/*
		 * The logic here is that we were unable to find an
		 * endpnt_type_t that matched our criteria, so we allocate a
		 * new one.  Because kmem_alloc() needs to be called with
		 * KM_SLEEP, we drop our locks so that we don't induce
		 * deadlock.  After allocating and initializing the
		 * endpnt_type_t, we reaquire the lock and go back to check
		 * if this entry needs to be added to the list.  Since we do
		 * some operations without any locking other threads may
		 * have been looking for the same endpnt_type_t and gone
		 * through this code path.  We check for this case and allow
		 * one thread to link its endpnt_type_t to the list and the
		 * other threads will simply free theirs.
		 */
		rw_exit(&endpnt_type_lock);
		n_etype = endpnt_type_create(config);

		/*
		 * We need to reaquire the lock with RW_WRITER here so that
		 * we can safely link the new endpoint type onto the list.
		 */
		rw_enter(&endpnt_type_lock, RW_WRITER);
		goto top;
	}

	rw_exit(&endpnt_type_lock);
	/*
	 * If n_etype is not NULL, then another thread was able to
	 * insert an endpnt_type_t of this type  onto the list before
	 * we did.  Go ahead and free ours.
	 */
	if (n_etype != NULL)
		endpnt_type_free(n_etype);

	mutex_enter(&np->e_ilock);
	/*
	 * The algorithm to hand out endpoints is to first
	 * give out those that are idle if such endpoints
	 * exist.  Otherwise, create a new one if we haven't
	 * reached the max threshold.  Finally, we give out
	 * endpoints in a pseudo LRU fashion (round-robin).
	 *
	 * Note:  The idle list is merely a hint of those endpoints
	 * that should be idle.  There exists a window after the
	 * endpoint is released and before it is linked back onto the
	 * idle list where a thread could get a reference to it and
	 * use it.  This is okay, since the reference counts will
	 * still be consistent.
	 */
	if ((endp = (endpnt_t *)list_head(&np->e_ilist)) != NULL) {
		timeout_id_t t_id = 0;

		mutex_enter(&endp->e_lock);
		endp->e_ref++;
		endp->e_itime = 0;
		endp->e_flags &= ~ENDPNT_ONIDLE;
		mutex_exit(&endp->e_lock);

		/*
		 * Pop the endpoint off the idle list and hand it off
		 */
		list_remove(&np->e_ilist, endp);

		if (np->e_itimer != 0) {
			t_id = np->e_itimer;
			np->e_itimer = 0;
		}
		mutex_exit(&np->e_ilock);
		/*
		 * Reset the idle timer if it has been set
		 */
		if (t_id != (timeout_id_t)0)
			(void) untimeout(t_id);

		if (check_endpnt(endp, &new) == 0)
			return (new);
	} else if (np->e_cnt >= clnt_clts_max_endpoints) {
		/*
		 * There are no idle endpoints currently, so
		 * create a new one if we have not reached the maximum or
		 * hand one out in round-robin.
		 */
		mutex_exit(&np->e_ilock);
		mutex_enter(&np->e_plock);
		endp = np->e_pcurr;
		mutex_enter(&endp->e_lock);
		endp->e_ref++;
		mutex_exit(&endp->e_lock);

		ASSERT(endp != NULL);
		/*
		 * Advance the pointer to the next eligible endpoint, if
		 * necessary.
		 */
		if (np->e_cnt > 1) {
			next = (endpnt_t *)list_next(&np->e_pool, np->e_pcurr);
			if (next == NULL)
				next = (endpnt_t *)list_head(&np->e_pool);
			np->e_pcurr = next;
		}

		mutex_exit(&np->e_plock);

		/*
		 * We need to check to see if this endpoint is bound or
		 * not.  If it is in progress then just wait until
		 * the set up is complete
		 */
		if (check_endpnt(endp, &new) == 0)
			return (new);
	} else {
		mutex_exit(&np->e_ilock);
		mutex_enter(&np->e_plock);

		/*
		 * Allocate a new endpoint to use.  If we can't allocate any
		 * more memory then use one that is already established if any
		 * such endpoints exist.
		 */
		new = kmem_cache_alloc(endpnt_cache, KM_NOSLEEP);
		if (new == NULL) {
			RPCLOG0(1, "endpnt_get: kmem_cache_alloc failed\n");
			/*
			 * Try to recover by using an existing endpoint.
			 */
			if (np->e_cnt <= 0) {
				mutex_exit(&np->e_plock);
				return (NULL);
			}
			endp = np->e_pcurr;
			if ((next = list_next(&np->e_pool, np->e_pcurr)) !=
			    NULL)
				np->e_pcurr = next;
			ASSERT(endp != NULL);
			mutex_enter(&endp->e_lock);
			endp->e_ref++;
			mutex_exit(&endp->e_lock);
			mutex_exit(&np->e_plock);

			if (check_endpnt(endp, &new) == 0)
				return (new);
		} else {
			/*
			 * Partially init an endpoint structure and put
			 * it on the list, so that other interested threads
			 * know that one is being created
			 */
			bzero(new, sizeof (struct endpnt));

			cv_init(&new->e_cv, NULL, CV_DEFAULT, NULL);
			mutex_init(&new->e_lock, NULL, MUTEX_DEFAULT, NULL);
			new->e_ref = 1;
			new->e_type = np;

			/*
			 * Link the endpoint into the pool.
			 */
			list_insert_head(&np->e_pool, new);
			np->e_cnt++;
			if (np->e_pcurr == NULL)
				np->e_pcurr = new;
			mutex_exit(&np->e_plock);
		}
	}

	/*
	 * The transport should be opened with sufficient privs
	 */
	cr = zone_kcred();
	error = t_kopen(NULL, config->knc_rdev, FREAD|FWRITE|FNDELAY, &tiptr,
	    cr);
	if (error) {
		RPCLOG(1, "endpnt_get: t_kopen: %d\n", error);
		goto bad;
	}

	new->e_tiptr = tiptr;
	rpc_poptimod(tiptr->fp->f_vnode);

	/*
	 * Allow the kernel to push the module on behalf of the user.
	 */
	error = strioctl(tiptr->fp->f_vnode, I_PUSH, (intptr_t)"rpcmod", 0,
	    K_TO_K, cr, &retval);
	if (error) {
		RPCLOG(1, "endpnt_get: kstr_push on rpcmod failed %d\n", error);
		goto bad;
	}

	error = strioctl(tiptr->fp->f_vnode, RPC_CLIENT, 0, 0, K_TO_K,
	    cr, &retval);
	if (error) {
		RPCLOG(1, "endpnt_get: strioctl failed %d\n", error);
		goto bad;
	}

	/*
	 * Connectionless data flow should bypass the stream head.
	 */
	new->e_wq = tiptr->fp->f_vnode->v_stream->sd_wrq->q_next;

	error = strioctl(tiptr->fp->f_vnode, I_PUSH, (intptr_t)"timod", 0,
	    K_TO_K, cr, &retval);
	if (error) {
		RPCLOG(1, "endpnt_get: kstr_push on timod failed %d\n", error);
		goto bad;
	}

	/*
	 * Attempt to bind the endpoint.  If we fail then propogate
	 * error back to calling subsystem, so that it can be handled
	 * appropriately.
	 * If the caller has not specified reserved port usage then
	 * take the system default.
	 */
	if (useresvport == -1)
		useresvport = clnt_clts_do_bindresvport;

	if (useresvport &&
	    (strcmp(config->knc_protofmly, NC_INET) == 0 ||
	    strcmp(config->knc_protofmly, NC_INET6) == 0)) {

		while ((error =
		    bindresvport(new->e_tiptr, NULL, NULL, FALSE)) != 0) {
			RPCLOG(1,
			    "endpnt_get: bindresvport error %d\n", error);
			if (error != EPROTO) {
				if (rtries-- <= 0)
					goto bad;

				delay(hz << i++);
				continue;
			}

			(void) t_kclose(new->e_tiptr, 1);
			/*
			 * reopen with all privileges
			 */
			error = t_kopen(NULL, config->knc_rdev,
			    FREAD|FWRITE|FNDELAY,
			    &new->e_tiptr, cr);
			if (error) {
				RPCLOG(1, "endpnt_get: t_kopen: %d\n", error);
					new->e_tiptr = NULL;
					goto bad;
			}
		}
	} else if ((error = t_kbind(new->e_tiptr, NULL, NULL)) != 0) {
		RPCLOG(1, "endpnt_get: t_kbind failed: %d\n", error);
		goto bad;
	}

	/*
	 * Set the flags and notify and waiters that we have an established
	 * endpoint.
	 */
	mutex_enter(&new->e_lock);
	new->e_flags |= ENDPNT_ESTABLISHED;
	new->e_flags |= ENDPNT_BOUND;
	if (new->e_flags & ENDPNT_WAITING) {
		cv_broadcast(&new->e_cv);
		new->e_flags &= ~ENDPNT_WAITING;
	}
	mutex_exit(&new->e_lock);

	return (new);

bad:
	ASSERT(new != NULL);
	/*
	 * mark this endpoint as stale and notify any threads waiting
	 * on this endpoint that it will be going away.
	 */
	mutex_enter(&new->e_lock);
	if (new->e_ref > 0) {
		new->e_flags |= ENDPNT_ESTABLISHED;
		new->e_flags |= ENDPNT_STALE;
		if (new->e_flags & ENDPNT_WAITING) {
			cv_broadcast(&new->e_cv);
			new->e_flags &= ~ENDPNT_WAITING;
		}
	}
	new->e_ref--;
	new->e_tiptr = NULL;
	mutex_exit(&new->e_lock);

	/*
	 * If there was a transport endopoint opened, then close it.
	 */
	if (tiptr != NULL)
		(void) t_kclose(tiptr, 1);

	return (NULL);
}

/*
 * Release a referece to the endpoint
 */
static void
endpnt_rele(struct endpnt *sp)
{
	mutex_enter(&sp->e_lock);
	ASSERT(sp->e_ref > 0);
	sp->e_ref--;
	/*
	 * If the ref count is zero, then start the idle timer and link
	 * the endpoint onto the idle list.
	 */
	if (sp->e_ref == 0) {
		sp->e_itime = gethrestime_sec();

		/*
		 * Check to see if the endpoint is already linked to the idle
		 * list, so that we don't try to reinsert it.
		 */
		if (sp->e_flags & ENDPNT_ONIDLE) {
			mutex_exit(&sp->e_lock);
			mutex_enter(&sp->e_type->e_ilock);
			endpnt_reap_settimer(sp->e_type);
			mutex_exit(&sp->e_type->e_ilock);
			return;
		}

		sp->e_flags |= ENDPNT_ONIDLE;
		mutex_exit(&sp->e_lock);
		mutex_enter(&sp->e_type->e_ilock);
		list_insert_tail(&sp->e_type->e_ilist, sp);
		endpnt_reap_settimer(sp->e_type);
		mutex_exit(&sp->e_type->e_ilock);
	} else
		mutex_exit(&sp->e_lock);
}

static void
endpnt_reap_settimer(endpnt_type_t *etp)
{
	if (etp->e_itimer == (timeout_id_t)0)
		etp->e_itimer = timeout(endpnt_reap_dispatch, (void *)etp,
		    clnt_clts_taskq_dispatch_interval);
}

static void
endpnt_reap_dispatch(void *a)
{
	endpnt_type_t *etp = a;

	/*
	 * The idle timer has fired, so dispatch the taskq to close the
	 * endpoint.
	 */
	if (taskq_dispatch(endpnt_taskq, (task_func_t *)endpnt_reap, etp,
	    TQ_NOSLEEP) == NULL)
		return;
	mutex_enter(&etp->e_ilock);
	etp->e_async_count++;
	mutex_exit(&etp->e_ilock);
}

/*
 * Traverse the idle list and close those endpoints that have reached their
 * timeout interval.
 */
static void
endpnt_reap(endpnt_type_t *etp)
{
	struct endpnt *e;
	struct endpnt *next_node = NULL;

	mutex_enter(&etp->e_ilock);
	e = list_head(&etp->e_ilist);
	while (e != NULL) {
		next_node = list_next(&etp->e_ilist, e);

		mutex_enter(&e->e_lock);
		if (e->e_ref > 0) {
			mutex_exit(&e->e_lock);
			e = next_node;
			continue;
		}

		ASSERT(e->e_ref == 0);
		if (e->e_itime > 0 &&
		    (e->e_itime + clnt_clts_endpoint_reap_interval) <
		    gethrestime_sec()) {
			e->e_flags &= ~ENDPNT_BOUND;
			(void) t_kclose(e->e_tiptr, 1);
			e->e_tiptr = NULL;
			e->e_itime = 0;
		}
		mutex_exit(&e->e_lock);
		e = next_node;
	}
	etp->e_itimer = 0;
	if (--etp->e_async_count == 0)
		cv_signal(&etp->e_async_cv);
	mutex_exit(&etp->e_ilock);
}

static void
endpnt_reclaim(zoneid_t zoneid)
{
	struct endpnt_type *np;
	struct endpnt *e;
	struct endpnt *next_node = NULL;
	list_t free_list;
	int rcnt = 0;

	list_create(&free_list, sizeof (endpnt_t), offsetof(endpnt_t, e_node));

	RPCLOG0(1, "endpnt_reclaim: reclaim callback started\n");
	rw_enter(&endpnt_type_lock, RW_READER);
	for (np = endpnt_type_list; np != NULL; np = np->e_next) {
		if (zoneid != ALL_ZONES && zoneid != np->e_zoneid)
			continue;

		mutex_enter(&np->e_plock);
		RPCLOG(1, "endpnt_reclaim: protofmly %s, ",
		    np->e_protofmly);
		RPCLOG(1, "rdev %ld\n", np->e_rdev);
		RPCLOG(1, "endpnt_reclaim: found %d endpoint(s)\n",
		    np->e_cnt);

		if (np->e_cnt == 0) {
			mutex_exit(&np->e_plock);
			continue;
		}

		/*
		 * The nice thing about maintaining an idle list is that if
		 * there are any endpoints to reclaim, they are going to be
		 * on this list.  Just go through and reap the one's that
		 * have ref counts of zero.
		 */
		mutex_enter(&np->e_ilock);
		e = list_head(&np->e_ilist);
		while (e != NULL) {
			next_node = list_next(&np->e_ilist, e);
			mutex_enter(&e->e_lock);
			if (e->e_ref > 0) {
				mutex_exit(&e->e_lock);
				e = next_node;
				continue;
			}
			ASSERT(e->e_ref == 0);
			mutex_exit(&e->e_lock);

			list_remove(&np->e_ilist, e);
			list_remove(&np->e_pool, e);
			list_insert_head(&free_list, e);

			rcnt++;
			np->e_cnt--;
			e = next_node;
		}
		mutex_exit(&np->e_ilock);
		/*
		 * Reset the current pointer to be safe
		 */
		if ((e = (struct endpnt *)list_head(&np->e_pool)) != NULL)
			np->e_pcurr = e;
		else {
			ASSERT(np->e_cnt == 0);
			np->e_pcurr = NULL;
		}

		mutex_exit(&np->e_plock);
	}
	rw_exit(&endpnt_type_lock);

	while ((e = list_head(&free_list)) != NULL) {
		list_remove(&free_list, e);
		if (e->e_tiptr != NULL)
			(void) t_kclose(e->e_tiptr, 1);

		cv_destroy(&e->e_cv);
		mutex_destroy(&e->e_lock);
		kmem_cache_free(endpnt_cache, e);
	}
	list_destroy(&free_list);
	RPCLOG(1, "endpnt_reclaim: reclaimed %d endpoint(s)\n", rcnt);
}

/*
 * Endpoint reclaim zones destructor callback routine.
 *
 * After reclaiming any cached entries, we basically go through the endpnt_type
 * list, canceling outstanding timeouts and free'ing data structures.
 */
/* ARGSUSED */
static void
endpnt_destructor(zoneid_t zoneid, void *a)
{
	struct endpnt_type **npp;
	struct endpnt_type *np;
	struct endpnt_type *free_list = NULL;
	timeout_id_t t_id = 0;
	extern void clcleanup_zone(zoneid_t);
	extern void clcleanup4_zone(zoneid_t);

	/* Make sure NFS client handles are released. */
	clcleanup_zone(zoneid);
	clcleanup4_zone(zoneid);

	endpnt_reclaim(zoneid);
	/*
	 * We don't need to be holding on to any locks across the call to
	 * endpnt_reclaim() and the code below; we know that no-one can
	 * be holding open connections for this zone (all processes and kernel
	 * threads are gone), so nothing could be adding anything to the list.
	 */
	rw_enter(&endpnt_type_lock, RW_WRITER);
	npp = &endpnt_type_list;
	while ((np = *npp) != NULL) {
		if (np->e_zoneid != zoneid) {
			npp = &np->e_next;
			continue;
		}
		mutex_enter(&np->e_plock);
		mutex_enter(&np->e_ilock);
		if (np->e_itimer != 0) {
			t_id = np->e_itimer;
			np->e_itimer = 0;
		}
		ASSERT(np->e_cnt == 0);
		ASSERT(list_head(&np->e_pool) == NULL);
		ASSERT(list_head(&np->e_ilist) == NULL);

		mutex_exit(&np->e_ilock);
		mutex_exit(&np->e_plock);

		/*
		 * untimeout() any outstanding timers that have not yet fired.
		 */
		if (t_id != (timeout_id_t)0)
			(void) untimeout(t_id);
		*npp = np->e_next;
		np->e_next = free_list;
		free_list = np;
	}
	rw_exit(&endpnt_type_lock);

	while (free_list != NULL) {
		np = free_list;
		free_list = free_list->e_next;
		/*
		 * Wait for threads in endpnt_taskq trying to reap endpnt_ts in
		 * the endpnt_type_t.
		 */
		mutex_enter(&np->e_ilock);
		while (np->e_async_count > 0)
			cv_wait(&np->e_async_cv, &np->e_ilock);
		cv_destroy(&np->e_async_cv);
		mutex_destroy(&np->e_plock);
		mutex_destroy(&np->e_ilock);
		list_destroy(&np->e_pool);
		list_destroy(&np->e_ilist);
		kmem_free(np, sizeof (endpnt_type_t));
	}
}

/*
 * Endpoint reclaim kmem callback routine.
 */
/* ARGSUSED */
static void
endpnt_repossess(void *a)
{
	/*
	 * Reclaim idle endpnt's from all zones.
	 */
	if (endpnt_taskq != NULL)
		(void) taskq_dispatch(endpnt_taskq,
		    (task_func_t *)endpnt_reclaim, (void *)ALL_ZONES,
		    TQ_NOSLEEP);
}

/*
 * RPC request dispatch routine.  Constructs a datagram message and wraps it
 * around the RPC request to pass downstream.
 */
static int
clnt_clts_dispatch_send(queue_t *q, mblk_t *mp, struct netbuf *addr,
    calllist_t *cp, uint_t xid, cred_t *cr)
{
	mblk_t *bp;
	int msgsz;
	struct T_unitdata_req *udreq;

	/*
	 * Set up the call record.
	 */
	cp->call_wq = q;
	cp->call_xid = xid;
	cp->call_status = RPC_TIMEDOUT;
	cp->call_notified = FALSE;
	RPCLOG(64,
	    "clnt_clts_dispatch_send: putting xid 0x%x on "
	    "dispatch list\n", xid);
	cp->call_hash = call_hash(xid, clnt_clts_hash_size);
	cp->call_bucket = &clts_call_ht[cp->call_hash];
	call_table_enter(cp);

	/*
	 * Construct the datagram
	 */
	msgsz = (int)TUNITDATAREQSZ;
	/*
	 * Note: if the receiver uses SCM_UCRED/getpeerucred the pid will
	 * appear as -1.
	 */
	while (!(bp = allocb_cred(msgsz + addr->len, cr, NOPID))) {
		if (strwaitbuf(msgsz + addr->len, BPRI_LO))
			return (ENOSR);
	}

	udreq = (struct T_unitdata_req *)bp->b_wptr;
	udreq->PRIM_type = T_UNITDATA_REQ;
	udreq->DEST_length = addr->len;

	if (addr->len) {
		bcopy(addr->buf, bp->b_wptr + msgsz, addr->len);
		udreq->DEST_offset = (t_scalar_t)msgsz;
		msgsz += addr->len;
	} else
		udreq->DEST_offset = 0;
	udreq->OPT_length = 0;
	udreq->OPT_offset = 0;

	bp->b_datap->db_type = M_PROTO;
	bp->b_wptr += msgsz;

	/*
	 * Link the datagram header with the actual data
	 */
	linkb(bp, mp);

	/*
	 * Send downstream.
	 */
	if (canput(cp->call_wq)) {
		put(cp->call_wq, bp);
		return (0);
	}

	return (EIO);
}

/*
 * RPC response delivery routine.  Deliver the response to the waiting
 * thread by matching the xid.
 */
void
clnt_clts_dispatch_notify(mblk_t *mp, int resp_off, zoneid_t zoneid)
{
	calllist_t *e = NULL;
	call_table_t *chtp;
	uint32_t xid;
	uint_t hash;
	unsigned char *hdr_offset;
	mblk_t *resp;

	/*
	 * If the RPC response is not contained in the same mblk as the
	 * datagram header, then move to the next mblk.
	 */
	hdr_offset = mp->b_rptr;
	resp = mp;
	if ((mp->b_wptr - (mp->b_rptr + resp_off)) == 0)
		resp = mp->b_cont;
	else
		resp->b_rptr += resp_off;

	ASSERT(resp != NULL);

	if ((IS_P2ALIGNED(resp->b_rptr, sizeof (uint32_t))) &&
	    (resp->b_wptr - resp->b_rptr) >= sizeof (xid))
		xid = *((uint32_t *)resp->b_rptr);
	else {
		int i = 0;
		unsigned char *p = (unsigned char *)&xid;
		unsigned char *rptr;
		mblk_t *tmp = resp;

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
		    "clnt_dispatch_notify(clts): message less than "
		    "size of xid\n");

		freemsg(mp);
		return;
	}

done_xid_copy:

	/*
	 * Reset the read pointer back to the beginning of the protocol
	 * header if we moved it.
	 */
	if (mp->b_rptr != hdr_offset)
		mp->b_rptr = hdr_offset;

	hash = call_hash(xid, clnt_clts_hash_size);
	chtp = &clts_call_ht[hash];
	/* call_table_find returns with the hash bucket locked */
	call_table_find(chtp, xid, e);

	if (e != NULL) {
		mutex_enter(&e->call_lock);

		/*
		 * verify that the reply is coming in on
		 * the same zone that it was sent from.
		 */
		if (e->call_zoneid != zoneid) {
			mutex_exit(&e->call_lock);
			mutex_exit(&chtp->ct_lock);
			RPCLOG0(8, "clnt_dispatch_notify (clts): incorrect "
			    "zoneid\n");
			freemsg(mp);
			return;
		}

		/*
		 * found thread waiting for this reply.
		 */
		if (e->call_reply) {
			RPCLOG(8,
			    "clnt_dispatch_notify (clts): discarding old "
			    "reply for xid 0x%x\n",
			    xid);
			freemsg(e->call_reply);
		}
		e->call_notified = TRUE;
		e->call_reply = mp;
		e->call_status = RPC_SUCCESS;
		cv_signal(&e->call_cv);
		mutex_exit(&e->call_lock);
		mutex_exit(&chtp->ct_lock);
	} else {
		zone_t *zone;
		struct rpcstat *rpcstat;

		mutex_exit(&chtp->ct_lock);
		RPCLOG(8, "clnt_dispatch_notify (clts): no caller for reply "
		    "0x%x\n", xid);
		freemsg(mp);
		/*
		 * This is unfortunate, but we need to lookup the zone so we
		 * can increment its "rcbadxids" counter.
		 */
		zone = zone_find_by_id(zoneid);
		if (zone == NULL) {
			/*
			 * The zone went away...
			 */
			return;
		}
		rpcstat = zone_getspecific(rpcstat_zone_key, zone);
		if (zone_status_get(zone) >= ZONE_IS_SHUTTING_DOWN) {
			/*
			 * Not interested
			 */
			zone_rele(zone);
			return;
		}
		RCSTAT_INCR(rpcstat->rpc_clts_client, rcbadxids);
		zone_rele(zone);
	}
}

/*
 * Init routine.  Called when rpcmod is loaded.
 */
void
clnt_clts_init(void)
{
	endpnt_cache = kmem_cache_create("clnt_clts_endpnt_cache",
	    sizeof (struct endpnt), 0, NULL, NULL, endpnt_repossess, NULL,
	    NULL, 0);

	rw_init(&endpnt_type_lock, NULL, RW_DEFAULT, NULL);

	/*
	 * Perform simple bounds checking to make sure that the setting is
	 * reasonable
	 */
	if (clnt_clts_max_endpoints <= 0) {
		if (clnt_clts_do_bindresvport)
			clnt_clts_max_endpoints = RESERVED_PORTSPACE;
		else
			clnt_clts_max_endpoints = NONRESERVED_PORTSPACE;
	}

	if (clnt_clts_do_bindresvport &&
	    clnt_clts_max_endpoints > RESERVED_PORTSPACE)
		clnt_clts_max_endpoints = RESERVED_PORTSPACE;
	else if (clnt_clts_max_endpoints > NONRESERVED_PORTSPACE)
		clnt_clts_max_endpoints = NONRESERVED_PORTSPACE;

	if (clnt_clts_hash_size < DEFAULT_MIN_HASH_SIZE)
		clnt_clts_hash_size = DEFAULT_MIN_HASH_SIZE;

	/*
	 * Defer creating the taskq until rpcmod gets pushed.  If we are
	 * in diskless boot mode, rpcmod will get loaded early even before
	 * thread_create() is available.
	 */
	endpnt_taskq = NULL;
	taskq_created = FALSE;
	mutex_init(&endpnt_taskq_lock, NULL, MUTEX_DEFAULT, NULL);

	if (clnt_clts_endpoint_reap_interval < DEFAULT_ENDPOINT_REAP_INTERVAL)
		clnt_clts_endpoint_reap_interval =
		    DEFAULT_ENDPOINT_REAP_INTERVAL;

	/*
	 * Dispatch the taskq at an interval which is offset from the
	 * interval that the endpoints should be reaped.
	 */
	clnt_clts_taskq_dispatch_interval =
	    (clnt_clts_endpoint_reap_interval + DEFAULT_INTERVAL_SHIFT) * hz;

	/*
	 * Initialize the completion queue
	 */
	clts_call_ht = call_table_init(clnt_clts_hash_size);
	/*
	 * Initialize the zone destructor callback.
	 */
	zone_key_create(&endpnt_destructor_key, NULL, NULL, endpnt_destructor);
}

void
clnt_clts_fini(void)
{
	(void) zone_key_delete(endpnt_destructor_key);
}
