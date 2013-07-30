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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Transport Interface Library cooperating module - issue 2
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <sys/suntpi.h>
#include <sys/debug.h>
#include <sys/strlog.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsun.h>
#include <c2/audit.h>

/*
 * This is the loadable module wrapper.
 */
#include <sys/conf.h>
#include <sys/modctl.h>

static struct streamtab timinfo;

static struct fmodsw fsw = {
	"timod",
	&timinfo,
	D_MTQPAIR | D_MP,
};

/*
 * Module linkage information for the kernel.
 */

static struct modlstrmod modlstrmod = {
	&mod_strmodops, "transport interface str mod", &fsw
};

static struct modlinkage modlinkage = {
	MODREV_1, &modlstrmod, NULL
};

static krwlock_t	tim_list_rwlock;

/*
 * This module keeps track of capabilities of underlying transport. Information
 * is persistent through module invocations (open/close). Currently it remembers
 * whether underlying transport supports TI_GET{MY,PEER}NAME ioctls and
 * T_CAPABILITY_REQ message. This module either passes ioctl/messages to the
 * transport or emulates it when transport doesn't understand these
 * ioctl/messages.
 *
 * It is assumed that transport supports T_CAPABILITY_REQ when timod receives
 * T_CAPABILITY_ACK from the transport. There is no current standard describing
 * transport behaviour when it receives unknown message type, so following
 * reactions are expected and handled:
 *
 * 1) Transport drops unknown T_CAPABILITY_REQ message type. In this case timod
 *    will wait for tcap_wait time and assume that transport doesn't provide
 *    this message type. T_CAPABILITY_REQ should never travel over the wire, so
 *    timeout value should only take into consideration internal processing time
 *    for the message. From user standpoint it may mean that an application will
 *    hang for TCAP_WAIT time in the kernel the first time this message is used
 *    with some particular transport (e.g. TCP/IP) during system uptime.
 *
 * 2) Transport responds with T_ERROR_ACK specifying T_CAPABILITY_REQ as
 *    original message type. In this case it is assumed that transport doesn't
 *    support it (which may not always be true - some transports return
 *    T_ERROR_ACK in other cases like lack of system memory).
 *
 * 3) Transport responds with M_ERROR, effectively shutting down the
 *    stream. Unfortunately there is no standard way to pass the reason of
 *    M_ERROR message back to the caller, so it is assumed that if M_ERROR was
 *    sent in response to T_CAPABILITY_REQ message, transport doesn't support
 *    it.
 *
 * It is possible under certain circumstances that timod will incorrectly assume
 * that underlying transport doesn't provide T_CAPABILITY_REQ message type. In
 * this "worst-case" scenario timod will emulate its functionality by itself and
 * will provide only TC1_INFO capability. All other bits in CAP_bits1 field are
 * cleaned. TC1_INFO is emulated by sending T_INFO_REQ down to transport
 * provider.
 */

/*
 * Notes about locking:
 *
 * tim_list_rwlock protects the list of tim_tim structures itself.  When this
 * lock is held, the list itself is stable, but the contents of the entries
 * themselves might not be.
 *
 * The rest of the members are generally protected by D_MTQPAIR, which
 * specifies a default exclusive inner perimeter.  If you're looking at
 * q->q_ptr, then it's stable.
 *
 * There's one exception to this rule: tim_peer{maxlen,len,name}.  These members
 * are touched without entering the associated STREAMS perimeter because we
 * get the pointer via tim_findlink() rather than q_ptr.  These are protected
 * by tim_mutex instead.  If you don't hold that lock, don't look at them.
 *
 * (It would be possible to separate out the 'set by T_CONN_RES' cases from the
 * others, but there appears to be no reason to do so.)
 */
struct tim_tim {
	uint32_t	tim_flags;
	t_uscalar_t	tim_backlog;
	mblk_t		*tim_iocsave;
	t_scalar_t	tim_mymaxlen;
	t_scalar_t	tim_mylen;
	caddr_t		tim_myname;
	t_scalar_t	tim_peermaxlen;
	t_scalar_t	tim_peerlen;
	caddr_t		tim_peername;
	cred_t		*tim_peercred;
	mblk_t		*tim_consave;
	bufcall_id_t	tim_wbufcid;
	bufcall_id_t	tim_rbufcid;
	timeout_id_t	tim_wtimoutid;
	timeout_id_t	tim_rtimoutid;
	/* Protected by the global tim_list_rwlock for all instances */
	struct tim_tim	*tim_next;
	struct tim_tim	**tim_ptpn;
	t_uscalar_t	tim_acceptor;
	t_scalar_t	tim_saved_prim;		/* Primitive from message */
						/*  part of ioctl. */
	timeout_id_t	tim_tcap_timoutid;	/* For T_CAP_REQ timeout */
	tpi_provinfo_t	*tim_provinfo;		/* Transport description */
	kmutex_t	tim_mutex;		/* protect tim_peer* */
	pid_t		tim_cpid;
};


/*
 * Local flags used with tim_flags field in instance structure of
 * type 'struct _ti_user' declared above.
 * Historical note:
 * This namespace constants were previously declared in a
 * a very messed up namespace in timod.h
 *
 * There may be 3 states for transport:
 *
 * 1) It provides T_CAPABILITY_REQ
 * 2) It does not provide T_CAPABILITY_REQ
 * 3) It is not known yet whether transport provides T_CAPABILITY_REQ or not.
 *
 * It is assumed that the underlying transport either provides
 * T_CAPABILITY_REQ or not and this does not changes during the
 * system lifetime.
 *
 */
#define	PEEK_RDQ_EXPIND 0x0001	/* look for expinds on stream rd queues */
#define	WAITIOCACK	0x0002	/* waiting for info for ioctl act	*/
#define	CLTS		0x0004	/* connectionless transport		*/
#define	COTS		0x0008	/* connection-oriented transport	*/
#define	CONNWAIT	0x0010	/* waiting for connect confirmation	*/
#define	LOCORDREL	0x0020	/* local end has orderly released	*/
#define	REMORDREL	0x0040	/* remote end had orderly released	*/
#define	NAMEPROC	0x0080	/* processing a NAME ioctl		*/
#define	DO_MYNAME	0x0100	/* timod handles TI_GETMYNAME		*/
#define	DO_PEERNAME	0x0200	/* timod handles TI_GETPEERNAME		*/
#define	TI_CAP_RECVD	0x0400	/* TI_CAPABILITY received		*/
#define	CAP_WANTS_INFO	0x0800	/* TI_CAPABILITY has TC1_INFO set	*/
#define	WAIT_IOCINFOACK	0x1000	/* T_INFO_REQ generated from ioctl	*/
#define	WAIT_CONNRESACK	0x2000	/* waiting for T_OK_ACK to T_CONN_RES	*/


/* Debugging facilities */
/*
 * Logging needed for debugging timod should only appear in DEBUG kernel.
 */
#ifdef DEBUG
#define	TILOG(msg, arg)		tilog((msg), (arg))
#define	TILOGP(msg, arg)	tilogp((msg), (arg))
#else
#define	TILOG(msg, arg)
#define	TILOGP(msg, arg)
#endif


/*
 * Sleep timeout for T_CAPABILITY_REQ. This message never travels across
 * network, so timeout value should be enough to cover all internal processing
 * time.
 */
clock_t tim_tcap_wait = 2;

/* Sleep timeout in tim_recover() */
#define	TIMWAIT	(1*hz)
/* Sleep timeout in tim_ioctl_retry() 0.2 seconds */
#define	TIMIOCWAIT	(200*hz/1000)

/*
 * Return values for ti_doname().
 */
#define	DONAME_FAIL	0	/* failing ioctl (done) */
#define	DONAME_DONE	1	/* done processing */
#define	DONAME_CONT	2	/* continue proceesing (not done yet) */

/*
 * Function prototypes
 */
static int ti_doname(queue_t *, mblk_t *);
static int ti_expind_on_rdqueues(queue_t *);
static void tim_ioctl_send_reply(queue_t *, mblk_t *, mblk_t *);
static void tim_send_ioc_error_ack(queue_t *, struct tim_tim *, mblk_t *);
static void tim_tcap_timer(void *);
static void tim_tcap_genreply(queue_t *, struct tim_tim *);
static void tim_send_reply(queue_t *, mblk_t *, struct tim_tim *, t_scalar_t);
static void tim_answer_ti_sync(queue_t *, mblk_t *, struct tim_tim *,
    mblk_t *, uint32_t);
static void tim_send_ioctl_tpi_msg(queue_t *, mblk_t *, struct tim_tim *,
	struct iocblk *);
static void tim_clear_peer(struct tim_tim *);

int
_init(void)
{
	int	error;

	rw_init(&tim_list_rwlock, NULL, RW_DRIVER, NULL);
	error = mod_install(&modlinkage);
	if (error != 0) {
		rw_destroy(&tim_list_rwlock);
		return (error);
	}

	return (0);
}

int
_fini(void)
{
	int	error;

	error = mod_remove(&modlinkage);
	if (error != 0)
		return (error);
	rw_destroy(&tim_list_rwlock);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * Hash list for all instances. Used to find tim_tim structure based on
 * ACCEPTOR_id in T_CONN_RES. Protected by tim_list_rwlock.
 */
#define	TIM_HASH_SIZE	256
#ifdef	_ILP32
#define	TIM_HASH(id) (((uintptr_t)(id) >> 8) % TIM_HASH_SIZE)
#else
#define	TIM_HASH(id) ((uintptr_t)(id) % TIM_HASH_SIZE)
#endif	/* _ILP32 */
static struct tim_tim	*tim_hash[TIM_HASH_SIZE];
int		tim_cnt = 0;

static void tilog(char *, t_scalar_t);
static void tilogp(char *, uintptr_t);
static mblk_t *tim_filladdr(queue_t *, mblk_t *, boolean_t);
static void tim_addlink(struct tim_tim	*);
static void tim_dellink(struct tim_tim	*);
static struct tim_tim *tim_findlink(t_uscalar_t);
static void tim_recover(queue_t *, mblk_t *, t_scalar_t);
static void tim_ioctl_retry(queue_t *);

int dotilog = 0;

#define	TIMOD_ID	3

static int timodopen(queue_t *, dev_t *, int, int, cred_t *);
static int timodclose(queue_t *, int, cred_t *);
static void timodwput(queue_t *, mblk_t *);
static void timodrput(queue_t *, mblk_t *);
static void timodrsrv(queue_t *);
static void timodwsrv(queue_t *);
static int timodrproc(queue_t *, mblk_t *);
static int timodwproc(queue_t *, mblk_t *);

/* stream data structure definitions */

static struct module_info timod_info =
	{TIMOD_ID, "timod", 0, INFPSZ, 512, 128};
static struct qinit timodrinit = {
	(int (*)())timodrput,
	(int (*)())timodrsrv,
	timodopen,
	timodclose,
	nulldev,
	&timod_info,
	NULL
};
static struct qinit timodwinit = {
	(int (*)())timodwput,
	(int (*)())timodwsrv,
	timodopen,
	timodclose,
	nulldev,
	&timod_info,
	NULL
};
static struct streamtab timinfo = { &timodrinit, &timodwinit, NULL, NULL };

/*
 * timodopen -	open routine gets called when the module gets pushed
 *		onto the stream.
 */
/*ARGSUSED*/
static int
timodopen(
	queue_t *q,
	dev_t *devp,
	int flag,
	int sflag,
	cred_t *crp)
{
	struct tim_tim *tp;
	struct stroptions *sop;
	mblk_t *bp;

	ASSERT(q != NULL);

	if (q->q_ptr) {
		return (0);
	}

	if ((bp = allocb(sizeof (struct stroptions), BPRI_MED)) == 0)
		return (ENOMEM);

	tp = kmem_zalloc(sizeof (struct tim_tim), KM_SLEEP);

	tp->tim_cpid = -1;
	tp->tim_saved_prim = -1;

	mutex_init(&tp->tim_mutex, NULL, MUTEX_DEFAULT, NULL);

	q->q_ptr = (caddr_t)tp;
	WR(q)->q_ptr = (caddr_t)tp;

	tilogp("timodopen: Allocated for tp %lx\n", (uintptr_t)tp);
	tilogp("timodopen: Allocated for q %lx\n", (uintptr_t)q);

	/* Must be done before tpi_findprov and _ILP32 q_next walk below */
	qprocson(q);

	tp->tim_provinfo = tpi_findprov(q);

	/*
	 * Defer allocation of the buffers for the local address and
	 * the peer's address until we need them.
	 * Assume that timod has to handle getname until we here
	 * an iocack from the transport provider or we know that
	 * transport provider doesn't understand it.
	 */
	if (tp->tim_provinfo->tpi_myname != PI_YES) {
		TILOG("timodopen: setting DO_MYNAME\n", 0);
		tp->tim_flags |= DO_MYNAME;
	}

	if (tp->tim_provinfo->tpi_peername != PI_YES) {
		TILOG("timodopen: setting DO_PEERNAME\n", 0);
		tp->tim_flags |= DO_PEERNAME;
	}

#ifdef	_ILP32
	{
		queue_t *driverq;

		/*
		 * Find my driver's read queue (for T_CONN_RES handling)
		 */
		driverq = WR(q);
		while (SAMESTR(driverq))
			driverq = driverq->q_next;

		tp->tim_acceptor = (t_uscalar_t)RD(driverq);
	}
#else
	tp->tim_acceptor = (t_uscalar_t)getminor(*devp);
#endif	/* _ILP32 */

	/*
	 * Add this one to the list.
	 */
	tim_addlink(tp);

	/*
	 * Send M_SETOPTS to stream head to make sure M_PCPROTO messages
	 * are not flushed. This prevents application deadlocks.
	 */
	bp->b_datap->db_type = M_SETOPTS;
	bp->b_wptr += sizeof (struct stroptions);
	sop = (struct stroptions *)bp->b_rptr;
	sop->so_flags = SO_READOPT;
	sop->so_readopt = RFLUSHPCPROT;

	putnext(q, bp);

	return (0);
}

static void
tim_timer(void *arg)
{
	queue_t *q = arg;
	struct tim_tim *tp = (struct tim_tim *)q->q_ptr;

	ASSERT(tp);

	if (q->q_flag & QREADR) {
		ASSERT(tp->tim_rtimoutid);
		tp->tim_rtimoutid = 0;
	} else {
		ASSERT(tp->tim_wtimoutid);
		tp->tim_wtimoutid = 0;
	}
	enableok(q);
	qenable(q);
}

static void
tim_buffer(void *arg)
{
	queue_t *q = arg;
	struct tim_tim *tp = (struct tim_tim *)q->q_ptr;

	ASSERT(tp);

	if (q->q_flag & QREADR) {
		ASSERT(tp->tim_rbufcid);
		tp->tim_rbufcid = 0;
	} else {
		ASSERT(tp->tim_wbufcid);
		tp->tim_wbufcid = 0;
	}
	enableok(q);
	qenable(q);
}

/*
 * timodclose - This routine gets called when the module gets popped
 * off of the stream.
 */
/*ARGSUSED*/
static int
timodclose(
	queue_t *q,
	int flag,
	cred_t *crp)
{
	struct tim_tim *tp;
	mblk_t *mp;
	mblk_t *nmp;

	ASSERT(q != NULL);

	tp = (struct tim_tim *)q->q_ptr;
	q->q_ptr = NULL;

	ASSERT(tp != NULL);

	tilogp("timodclose: Entered for tp %lx\n", (uintptr_t)tp);
	tilogp("timodclose: Entered for q %lx\n", (uintptr_t)q);

	qprocsoff(q);
	tim_dellink(tp);

	/*
	 * Cancel any outstanding bufcall
	 * or timeout requests.
	 */
	if (tp->tim_wbufcid) {
		qunbufcall(q, tp->tim_wbufcid);
		tp->tim_wbufcid = 0;
	}
	if (tp->tim_rbufcid) {
		qunbufcall(q, tp->tim_rbufcid);
		tp->tim_rbufcid = 0;
	}
	if (tp->tim_wtimoutid) {
		(void) quntimeout(q, tp->tim_wtimoutid);
		tp->tim_wtimoutid = 0;
	}
	if (tp->tim_rtimoutid) {
		(void) quntimeout(q, tp->tim_rtimoutid);
		tp->tim_rtimoutid = 0;
	}

	if (tp->tim_tcap_timoutid != 0) {
		(void) quntimeout(q, tp->tim_tcap_timoutid);
		tp->tim_tcap_timoutid = 0;
	}

	if (tp->tim_iocsave != NULL)
		freemsg(tp->tim_iocsave);
	mp = tp->tim_consave;
	while (mp) {
		nmp = mp->b_next;
		mp->b_next = NULL;
		freemsg(mp);
		mp = nmp;
	}
	ASSERT(tp->tim_mymaxlen >= 0);
	if (tp->tim_mymaxlen != 0)
		kmem_free(tp->tim_myname, (size_t)tp->tim_mymaxlen);
	ASSERT(tp->tim_peermaxlen >= 0);
	if (tp->tim_peermaxlen != 0)
		kmem_free(tp->tim_peername, (size_t)tp->tim_peermaxlen);

	q->q_ptr = WR(q)->q_ptr = NULL;

	mutex_destroy(&tp->tim_mutex);

	if (tp->tim_peercred != NULL)
		crfree(tp->tim_peercred);

	kmem_free(tp, sizeof (struct tim_tim));

	return (0);
}

/*
 * timodrput -	Module read put procedure.  This is called from
 *		the module, driver, or stream head upstream/downstream.
 *		Handles M_FLUSH, M_DATA and some M_PROTO (T_DATA_IND,
 *		and T_UNITDATA_IND) messages. All others are queued to
 *		be handled by the service procedures.
 */
static void
timodrput(queue_t *q, mblk_t *mp)
{
	union T_primitives *pptr;

	/*
	 * During flow control and other instances when messages
	 * are on queue, queue up a non high priority message
	 */
	if (q->q_first != 0 && mp->b_datap->db_type < QPCTL) {
		(void) putq(q, mp);
		return;
	}

	/*
	 * Inline processing of data (to avoid additional procedure call).
	 * Rest is handled in timodrproc.
	 */

	switch (mp->b_datap->db_type) {
	case M_DATA:
		if (bcanputnext(q, mp->b_band))
			putnext(q, mp);
		else
			(void) putq(q, mp);
		break;
	case M_PROTO:
	case M_PCPROTO:
		if (MBLKL(mp) < sizeof (t_scalar_t)) {
			if (mp->b_datap->db_type == M_PCPROTO ||
			    bcanputnext(q, mp->b_band)) {
				putnext(q, mp);
			} else {
				(void) putq(q, mp);
			}
			break;
		}
		pptr = (union T_primitives *)mp->b_rptr;
		switch (pptr->type) {
		case T_EXDATA_IND:
		case T_DATA_IND:
		case T_UNITDATA_IND:
			if (bcanputnext(q, mp->b_band))
				putnext(q, mp);
			else
				(void) putq(q, mp);
			break;
		default:
			(void) timodrproc(q, mp);
			break;
		}
		break;
	default:
		(void) timodrproc(q, mp);
		break;
	}
}

/*
 * timodrsrv -	Module read queue service procedure.  This is called when
 *		messages are placed on an empty queue, when high priority
 *		messages are placed on the queue, and when flow control
 *		restrictions subside.  This code used to be included in a
 *		put procedure, but it was moved to a service procedure
 *		because several points were added where memory allocation
 *		could fail, and there is no reasonable recovery mechanism
 *		from the put procedure.
 */
/*ARGSUSED*/
static void
timodrsrv(queue_t *q)
{
	mblk_t *mp;
	struct tim_tim *tp;

	ASSERT(q != NULL);

	tp = (struct tim_tim *)q->q_ptr;
	if (!tp)
		return;

	while ((mp = getq(q)) != NULL) {
		if (timodrproc(q, mp)) {
			/*
			 * timodrproc did a putbq - stop processing
			 * messages.
			 */
			return;
		}
	}
}

/*
 * Perform common processing when a T_CAPABILITY_ACK or T_INFO_ACK
 * arrive.  Set the queue properties and adjust the tim_flags according
 * to the service type.
 */
static void
timodprocessinfo(queue_t *q, struct tim_tim *tp, struct T_info_ack *tia)
{
	TILOG("timodprocessinfo: strqset(%d)\n", tia->TIDU_size);
	(void) strqset(q, QMAXPSZ, 0, tia->TIDU_size);
	(void) strqset(OTHERQ(q), QMAXPSZ, 0, tia->TIDU_size);

	if ((tia->SERV_type == T_COTS) || (tia->SERV_type == T_COTS_ORD))
		tp->tim_flags = (tp->tim_flags & ~CLTS) | COTS;
	else if (tia->SERV_type == T_CLTS)
		tp->tim_flags = (tp->tim_flags & ~COTS) | CLTS;
}

static int
timodrproc(queue_t *q, mblk_t *mp)
{
	uint32_t auditing = AU_AUDITING();
	union T_primitives *pptr;
	struct tim_tim *tp;
	struct iocblk *iocbp;
	mblk_t *nbp;
	size_t blen;

	tp = (struct tim_tim *)q->q_ptr;

	switch (mp->b_datap->db_type) {
	default:
		putnext(q, mp);
		break;

	case M_ERROR:
		TILOG("timodrproc: Got M_ERROR, flags = %x\n", tp->tim_flags);
		/*
		 * There is no specified standard response for driver when it
		 * receives unknown message type and M_ERROR is one
		 * possibility. If we send T_CAPABILITY_REQ down and transport
		 * provider responds with M_ERROR we assume that it doesn't
		 * understand this message type. This assumption may be
		 * sometimes incorrect (transport may reply with M_ERROR for
		 * some other reason) but there is no way for us to distinguish
		 * between different cases. In the worst case timod and everyone
		 * else sharing global transport description with it may end up
		 * emulating T_CAPABILITY_REQ.
		 */

		/*
		 * Check that we are waiting for T_CAPABILITY_ACK and
		 * T_CAPABILITY_REQ is not implemented by transport or emulated
		 * by timod.
		 */
		if ((tp->tim_provinfo->tpi_capability == PI_DONTKNOW) &&
		    ((tp->tim_flags & TI_CAP_RECVD) != 0)) {
			/*
			 * Good chances that this transport doesn't provide
			 * T_CAPABILITY_REQ. Mark this information  permanently
			 * for the module + transport combination.
			 */
			PI_PROVLOCK(tp->tim_provinfo);
			if (tp->tim_provinfo->tpi_capability == PI_DONTKNOW)
				tp->tim_provinfo->tpi_capability = PI_NO;
			PI_PROVUNLOCK(tp->tim_provinfo);
			if (tp->tim_tcap_timoutid != 0) {
				(void) quntimeout(q, tp->tim_tcap_timoutid);
				tp->tim_tcap_timoutid = 0;
			}
		}
		putnext(q, mp);
		break;
	case M_DATA:
		if (!bcanputnext(q, mp->b_band)) {
			(void) putbq(q, mp);
			return (1);
		}
		putnext(q, mp);
		break;

	case M_PROTO:
	case M_PCPROTO:
		blen = MBLKL(mp);
		if (blen < sizeof (t_scalar_t)) {
			/*
			 * Note: it's not actually possible to get
			 * here with db_type M_PCPROTO, because
			 * timodrput has already checked MBLKL, and
			 * thus the assertion below.  If the length
			 * was too short, then the message would have
			 * already been putnext'd, and would thus
			 * never appear here.  Just the same, the code
			 * below handles the impossible case since
			 * it's easy to do and saves future
			 * maintainers from unfortunate accidents.
			 */
			ASSERT(mp->b_datap->db_type == M_PROTO);
			if (mp->b_datap->db_type == M_PROTO &&
			    !bcanputnext(q, mp->b_band)) {
				(void) putbq(q, mp);
				return (1);
			}
			putnext(q, mp);
			break;
		}

		pptr = (union T_primitives *)mp->b_rptr;
		switch (pptr->type) {
		default:

			if (auditing)
				audit_sock(T_UNITDATA_IND, q, mp, TIMOD_ID);
			putnext(q, mp);
			break;

		case T_ERROR_ACK:
			/* Restore db_type - recover() might have changed it */
			mp->b_datap->db_type = M_PCPROTO;
			if (blen < sizeof (struct T_error_ack)) {
				putnext(q, mp);
				break;
			}

			tilog("timodrproc: Got T_ERROR_ACK, flags = %x\n",
			    tp->tim_flags);

			if ((tp->tim_flags & WAIT_CONNRESACK) &&
			    tp->tim_saved_prim == pptr->error_ack.ERROR_prim) {
				tp->tim_flags &=
				    ~(WAIT_CONNRESACK | WAITIOCACK);
				freemsg(tp->tim_iocsave);
				tp->tim_iocsave = NULL;
				tp->tim_saved_prim = -1;
				putnext(q, mp);
			} else if (tp->tim_flags & WAITIOCACK) {
				tim_send_ioc_error_ack(q, tp, mp);
			} else {
				putnext(q, mp);
			}
			break;

		case T_OK_ACK:
			if (blen < sizeof (pptr->ok_ack)) {
				mp->b_datap->db_type = M_PCPROTO;
				putnext(q, mp);
				break;
			}

			tilog("timodrproc: Got T_OK_ACK\n", 0);

			if (pptr->ok_ack.CORRECT_prim == T_UNBIND_REQ)
				tp->tim_mylen = 0;

			if ((tp->tim_flags & WAIT_CONNRESACK) &&
			    tp->tim_saved_prim == pptr->ok_ack.CORRECT_prim) {
				struct T_conn_res *resp;
				struct T_conn_ind *indp;
				struct tim_tim *ntp;
				caddr_t ptr;

				rw_enter(&tim_list_rwlock, RW_READER);
				resp = (struct T_conn_res *)
				    tp->tim_iocsave->b_rptr;
				ntp = tim_findlink(resp->ACCEPTOR_id);
				if (ntp == NULL)
					goto cresackout;

				mutex_enter(&ntp->tim_mutex);
				if (ntp->tim_peercred != NULL)
					crfree(ntp->tim_peercred);
				ntp->tim_peercred =
				    msg_getcred(tp->tim_iocsave->b_cont,
				    &ntp->tim_cpid);
				if (ntp->tim_peercred != NULL)
					crhold(ntp->tim_peercred);

				if (!(ntp->tim_flags & DO_PEERNAME)) {
					mutex_exit(&ntp->tim_mutex);
					goto cresackout;
				}

				indp = (struct T_conn_ind *)
				    tp->tim_iocsave->b_cont->b_rptr;
				/* true as message is put on list */
				ASSERT(indp->SRC_length >= 0);

				if (indp->SRC_length > ntp->tim_peermaxlen) {
					ptr = kmem_alloc(indp->SRC_length,
					    KM_NOSLEEP);
					if (ptr == NULL) {
						mutex_exit(&ntp->tim_mutex);
						rw_exit(&tim_list_rwlock);
						tilog("timodwproc: kmem_alloc "
						    "failed, attempting "
						    "recovery\n", 0);
						tim_recover(q, mp,
						    indp->SRC_length);
						return (1);
					}
					if (ntp->tim_peermaxlen > 0)
						kmem_free(ntp->tim_peername,
						    ntp->tim_peermaxlen);
					ntp->tim_peername = ptr;
					ntp->tim_peermaxlen = indp->SRC_length;
				}
				ntp->tim_peerlen = indp->SRC_length;
				ptr = (caddr_t)indp + indp->SRC_offset;
				bcopy(ptr, ntp->tim_peername, ntp->tim_peerlen);

				mutex_exit(&ntp->tim_mutex);

			cresackout:
				rw_exit(&tim_list_rwlock);
				tp->tim_flags &=
				    ~(WAIT_CONNRESACK | WAITIOCACK);
				freemsg(tp->tim_iocsave);
				tp->tim_iocsave = NULL;
				tp->tim_saved_prim = -1;
			}

			tim_send_reply(q, mp, tp, pptr->ok_ack.CORRECT_prim);
			break;

		case T_BIND_ACK: {
			struct T_bind_ack *ackp =
			    (struct T_bind_ack *)mp->b_rptr;

			/* Restore db_type - recover() might have changed it */
			mp->b_datap->db_type = M_PCPROTO;
			if (blen < sizeof (*ackp)) {
				putnext(q, mp);
				break;
			}

			/* save negotiated backlog */
			tp->tim_backlog = ackp->CONIND_number;

			if (((tp->tim_flags & WAITIOCACK) == 0) ||
			    ((tp->tim_saved_prim != O_T_BIND_REQ) &&
			    (tp->tim_saved_prim != T_BIND_REQ))) {
				putnext(q, mp);
				break;
			}
			ASSERT(tp->tim_iocsave != NULL);

			if (tp->tim_flags & DO_MYNAME) {
				caddr_t p;

				if (ackp->ADDR_length < 0 ||
				    mp->b_rptr + ackp->ADDR_offset +
				    ackp->ADDR_length > mp->b_wptr) {
					putnext(q, mp);
					break;
				}
				if (ackp->ADDR_length > tp->tim_mymaxlen) {
					p = kmem_alloc(ackp->ADDR_length,
					    KM_NOSLEEP);
					if (p == NULL) {
						tilog("timodrproc: kmem_alloc "
						    "failed attempt recovery",
						    0);

						tim_recover(q, mp,
						    ackp->ADDR_length);
						return (1);
					}
					ASSERT(tp->tim_mymaxlen >= 0);
					if (tp->tim_mymaxlen != NULL) {
						kmem_free(tp->tim_myname,
						    tp->tim_mymaxlen);
					}
					tp->tim_myname = p;
					tp->tim_mymaxlen = ackp->ADDR_length;
				}
				tp->tim_mylen = ackp->ADDR_length;
				bcopy(mp->b_rptr + ackp->ADDR_offset,
				    tp->tim_myname, tp->tim_mylen);
			}
			tim_ioctl_send_reply(q, tp->tim_iocsave, mp);
			tp->tim_iocsave = NULL;
			tp->tim_saved_prim = -1;
			tp->tim_flags &= ~(WAITIOCACK | WAIT_IOCINFOACK |
			    TI_CAP_RECVD | CAP_WANTS_INFO);
			break;
		}

		case T_OPTMGMT_ACK:

			tilog("timodrproc: Got T_OPTMGMT_ACK\n", 0);

			/* Restore db_type - recover() might have change it */
			mp->b_datap->db_type = M_PCPROTO;

			if (((tp->tim_flags & WAITIOCACK) == 0) ||
			    ((tp->tim_saved_prim != T_SVR4_OPTMGMT_REQ) &&
			    (tp->tim_saved_prim != T_OPTMGMT_REQ))) {
				putnext(q, mp);
			} else {
				ASSERT(tp->tim_iocsave != NULL);
				tim_ioctl_send_reply(q, tp->tim_iocsave, mp);
				tp->tim_iocsave = NULL;
				tp->tim_saved_prim = -1;
				tp->tim_flags &= ~(WAITIOCACK |
				    WAIT_IOCINFOACK | TI_CAP_RECVD |
				    CAP_WANTS_INFO);
			}
		break;

		case T_INFO_ACK: {
		struct T_info_ack *tia = (struct T_info_ack *)pptr;

		/* Restore db_type - recover() might have changed it */
		mp->b_datap->db_type = M_PCPROTO;

		if (blen < sizeof (*tia)) {
			putnext(q, mp);
			break;
		}

		tilog("timodrproc: Got T_INFO_ACK, flags = %x\n",
		    tp->tim_flags);

		timodprocessinfo(q, tp, tia);

		TILOG("timodrproc: flags = %x\n", tp->tim_flags);
		if ((tp->tim_flags & WAITIOCACK) != 0) {
			size_t	expected_ack_size;
			ssize_t	deficit;
			int	ioc_cmd;
			struct T_capability_ack *tcap;

			/*
			 * The only case when T_INFO_ACK may be received back
			 * when we are waiting for ioctl to complete is when
			 * this ioctl sent T_INFO_REQ down.
			 */
			if (!(tp->tim_flags & WAIT_IOCINFOACK)) {
				putnext(q, mp);
				break;
			}
			ASSERT(tp->tim_iocsave != NULL);

			iocbp = (struct iocblk *)tp->tim_iocsave->b_rptr;
			ioc_cmd = iocbp->ioc_cmd;

			/*
			 * Was it sent from TI_CAPABILITY emulation?
			 */
			if (ioc_cmd == TI_CAPABILITY) {
				struct T_info_ack	saved_info;

				/*
				 * Perform sanity checks. The only case when we
				 * send T_INFO_REQ from TI_CAPABILITY is when
				 * timod emulates T_CAPABILITY_REQ and CAP_bits1
				 * has TC1_INFO set.
				 */
				if ((tp->tim_flags &
				    (TI_CAP_RECVD | CAP_WANTS_INFO)) !=
				    (TI_CAP_RECVD | CAP_WANTS_INFO)) {
					putnext(q, mp);
					break;
				}

				TILOG("timodrproc: emulating TI_CAPABILITY/"
				    "info\n", 0);

				/* Save info & reuse mp for T_CAPABILITY_ACK */
				saved_info = *tia;

				mp = tpi_ack_alloc(mp,
				    sizeof (struct T_capability_ack),
				    M_PCPROTO, T_CAPABILITY_ACK);

				if (mp == NULL) {
					tilog("timodrproc: realloc failed, "
					    "no recovery attempted\n", 0);
					return (1);
				}

				/*
				 * Copy T_INFO information into T_CAPABILITY_ACK
				 */
				tcap = (struct T_capability_ack *)mp->b_rptr;
				tcap->CAP_bits1 = TC1_INFO;
				tcap->INFO_ack = saved_info;
				tp->tim_flags &= ~(WAITIOCACK |
				    WAIT_IOCINFOACK | TI_CAP_RECVD |
				    CAP_WANTS_INFO);
				tim_ioctl_send_reply(q, tp->tim_iocsave, mp);
				tp->tim_iocsave = NULL;
				tp->tim_saved_prim = -1;
				break;
			}

			/*
			 * The code for TI_SYNC/TI_GETINFO is left here only for
			 * backward compatibility with staticaly linked old
			 * applications. New TLI/XTI code should use
			 * TI_CAPABILITY for getting transport info and should
			 * not use TI_GETINFO/TI_SYNC for this purpose.
			 */

			/*
			 * make sure the message sent back is the size of
			 * the "expected ack"
			 * For TI_GETINFO, expected ack size is
			 *	sizeof (T_info_ack)
			 * For TI_SYNC, expected ack size is
			 *	sizeof (struct ti_sync_ack);
			 */
			if (ioc_cmd != TI_GETINFO && ioc_cmd != TI_SYNC) {
				putnext(q, mp);
				break;
			}

			expected_ack_size =
			    sizeof (struct T_info_ack); /* TI_GETINFO */
			if (iocbp->ioc_cmd == TI_SYNC) {
				expected_ack_size = 2 * sizeof (uint32_t) +
				    sizeof (struct ti_sync_ack);
			}
			deficit = expected_ack_size - blen;

			if (deficit != 0) {
				if (mp->b_datap->db_lim - mp->b_wptr <
				    deficit) {
					mblk_t *tmp = allocb(expected_ack_size,
					    BPRI_HI);
					if (tmp == NULL) {
						ASSERT(MBLKSIZE(mp) >=
						    sizeof (struct T_error_ack));

						tilog("timodrproc: allocb failed no "
						    "recovery attempt\n", 0);

						mp->b_rptr = mp->b_datap->db_base;
						pptr = (union T_primitives *)
						    mp->b_rptr;
						pptr->error_ack.ERROR_prim = T_INFO_REQ;
						pptr->error_ack.TLI_error = TSYSERR;
						pptr->error_ack.UNIX_error = EAGAIN;
						pptr->error_ack.PRIM_type = T_ERROR_ACK;
						mp->b_datap->db_type = M_PCPROTO;
						tim_send_ioc_error_ack(q, tp, mp);
						break;
					} else {
						bcopy(mp->b_rptr, tmp->b_rptr, blen);
						tmp->b_wptr += blen;
						pptr = (union T_primitives *)
						    tmp->b_rptr;
						freemsg(mp);
						mp = tmp;
					}
				}
			}
			/*
			 * We now have "mp" which has enough space for an
			 * appropriate ack and contains struct T_info_ack
			 * that the transport provider returned. We now
			 * stuff it with more stuff to fullfill
			 * TI_SYNC ioctl needs, as necessary
			 */
			if (iocbp->ioc_cmd == TI_SYNC) {
				/*
				 * Assumes struct T_info_ack is first embedded
				 * type in struct ti_sync_ack so it is
				 * automatically there.
				 */
				struct ti_sync_ack *tsap =
				    (struct ti_sync_ack *)mp->b_rptr;

				/*
				 * tsap->tsa_qlen needs to be set only if
				 * TSRF_QLEN_REQ flag is set, but for
				 * compatibility with statically linked
				 * applications it is set here regardless of the
				 * flag since old XTI library expected it to be
				 * set.
				 */
				tsap->tsa_qlen = tp->tim_backlog;
				tsap->tsa_flags = 0x0; /* intialize clear */
				if (tp->tim_flags & PEEK_RDQ_EXPIND) {
					/*
					 * Request to peek for EXPIND in
					 * rcvbuf.
					 */
					if (ti_expind_on_rdqueues(q)) {
						/*
						 * Expedited data is
						 * queued on the stream
						 * read side
						 */
						tsap->tsa_flags |=
						    TSAF_EXP_QUEUED;
					}
					tp->tim_flags &=
					    ~PEEK_RDQ_EXPIND;
				}
				mp->b_wptr += 2*sizeof (uint32_t);
			}
			tim_ioctl_send_reply(q, tp->tim_iocsave, mp);
			tp->tim_iocsave = NULL;
			tp->tim_saved_prim = -1;
			tp->tim_flags &= ~(WAITIOCACK | WAIT_IOCINFOACK |
			    TI_CAP_RECVD | CAP_WANTS_INFO);
			break;
		}
	    }

	    putnext(q, mp);
	    break;

	    case T_ADDR_ACK:
		tilog("timodrproc: Got T_ADDR_ACK\n", 0);
		tim_send_reply(q, mp, tp, T_ADDR_REQ);
		break;

		case T_CONN_IND: {
			struct T_conn_ind *tcip =
			    (struct T_conn_ind *)mp->b_rptr;

			tilog("timodrproc: Got T_CONN_IND\n", 0);

			if (blen >= sizeof (*tcip) &&
			    MBLKIN(mp, tcip->SRC_offset, tcip->SRC_length)) {
				if (((nbp = dupmsg(mp)) != NULL) ||
				    ((nbp = copymsg(mp)) != NULL)) {
					nbp->b_next = tp->tim_consave;
					tp->tim_consave = nbp;
				} else {
					tim_recover(q, mp,
					    (t_scalar_t)sizeof (mblk_t));
					return (1);
				}
			}
			if (auditing)
				audit_sock(T_CONN_IND, q, mp, TIMOD_ID);
			putnext(q, mp);
			break;
		}

	    case T_CONN_CON:
		mutex_enter(&tp->tim_mutex);
		if (tp->tim_peercred != NULL)
			crfree(tp->tim_peercred);
		tp->tim_peercred = msg_getcred(mp, &tp->tim_cpid);
		if (tp->tim_peercred != NULL)
			crhold(tp->tim_peercred);
		mutex_exit(&tp->tim_mutex);

		tilog("timodrproc: Got T_CONN_CON\n", 0);

		tp->tim_flags &= ~CONNWAIT;
		putnext(q, mp);
		break;

	    case T_DISCON_IND: {
		struct T_discon_ind *disp;
		struct T_conn_ind *conp;
		mblk_t *pbp = NULL;

		if (q->q_first != 0)
			tilog("timodrput: T_DISCON_IND - flow control\n", 0);

		if (blen < sizeof (*disp)) {
			putnext(q, mp);
			break;
		}

		disp = (struct T_discon_ind *)mp->b_rptr;

		tilog("timodrproc: Got T_DISCON_IND Reason: %d\n",
		    disp->DISCON_reason);

		tp->tim_flags &= ~(CONNWAIT|LOCORDREL|REMORDREL);
		tim_clear_peer(tp);
		for (nbp = tp->tim_consave; nbp; nbp = nbp->b_next) {
			conp = (struct T_conn_ind *)nbp->b_rptr;
			if (conp->SEQ_number == disp->SEQ_number)
				break;
			pbp = nbp;
		}
		if (nbp) {
			if (pbp)
				pbp->b_next = nbp->b_next;
			else
				tp->tim_consave = nbp->b_next;
			nbp->b_next = NULL;
			freemsg(nbp);
		}
		putnext(q, mp);
		break;
	    }

	    case T_ORDREL_IND:

		    tilog("timodrproc: Got T_ORDREL_IND\n", 0);

		    if (tp->tim_flags & LOCORDREL) {
			    tp->tim_flags &= ~(LOCORDREL|REMORDREL);
			    tim_clear_peer(tp);
		    } else {
			    tp->tim_flags |= REMORDREL;
		    }
		    putnext(q, mp);
		    break;

	    case T_EXDATA_IND:
	    case T_DATA_IND:
	    case T_UNITDATA_IND:
		if (pptr->type == T_EXDATA_IND)
			tilog("timodrproc: Got T_EXDATA_IND\n", 0);

		if (!bcanputnext(q, mp->b_band)) {
			(void) putbq(q, mp);
			return (1);
		}
		putnext(q, mp);
		break;

	    case T_CAPABILITY_ACK: {
			struct T_capability_ack	*tca;

			if (blen < sizeof (*tca)) {
				putnext(q, mp);
				break;
			}

			/* This transport supports T_CAPABILITY_REQ */
			tilog("timodrproc: Got T_CAPABILITY_ACK\n", 0);

			PI_PROVLOCK(tp->tim_provinfo);
			if (tp->tim_provinfo->tpi_capability != PI_YES)
				tp->tim_provinfo->tpi_capability = PI_YES;
			PI_PROVUNLOCK(tp->tim_provinfo);

			/* Reset possible pending timeout */
			if (tp->tim_tcap_timoutid != 0) {
				(void) quntimeout(q, tp->tim_tcap_timoutid);
				tp->tim_tcap_timoutid = 0;
			}

			tca = (struct T_capability_ack *)mp->b_rptr;

			if (tca->CAP_bits1 & TC1_INFO)
				timodprocessinfo(q, tp, &tca->INFO_ack);

			tim_send_reply(q, mp, tp, T_CAPABILITY_REQ);
		}
		break;
	    }
	    break;

	case M_FLUSH:

		tilog("timodrproc: Got M_FLUSH\n", 0);

		if (*mp->b_rptr & FLUSHR) {
			if (*mp->b_rptr & FLUSHBAND)
				flushband(q, *(mp->b_rptr + 1), FLUSHDATA);
			else
				flushq(q, FLUSHDATA);
		}
		putnext(q, mp);
		break;

	case M_IOCACK:
	    iocbp = (struct iocblk *)mp->b_rptr;

	    tilog("timodrproc: Got M_IOCACK\n", 0);

	    if (iocbp->ioc_cmd == TI_GETMYNAME) {

		/*
		 * Transport provider supports this ioctl,
		 * so I don't have to.
		 */
		if ((tp->tim_flags & DO_MYNAME) != 0) {
			tp->tim_flags &= ~DO_MYNAME;
			PI_PROVLOCK(tp->tim_provinfo);
			tp->tim_provinfo->tpi_myname = PI_YES;
			PI_PROVUNLOCK(tp->tim_provinfo);
		}

		ASSERT(tp->tim_mymaxlen >= 0);
		if (tp->tim_mymaxlen != 0) {
			kmem_free(tp->tim_myname, (size_t)tp->tim_mymaxlen);
			tp->tim_myname = NULL;
			tp->tim_mymaxlen = 0;
		}
		/* tim_iocsave may already be overwritten. */
		if (tp->tim_saved_prim == -1) {
			freemsg(tp->tim_iocsave);
			tp->tim_iocsave = NULL;
		}
	    } else if (iocbp->ioc_cmd == TI_GETPEERNAME) {
		boolean_t clearit;

		/*
		 * Transport provider supports this ioctl,
		 * so I don't have to.
		 */
		if ((tp->tim_flags & DO_PEERNAME) != 0) {
			tp->tim_flags &= ~DO_PEERNAME;
			PI_PROVLOCK(tp->tim_provinfo);
			tp->tim_provinfo->tpi_peername = PI_YES;
			PI_PROVUNLOCK(tp->tim_provinfo);
		}

		mutex_enter(&tp->tim_mutex);
		ASSERT(tp->tim_peermaxlen >= 0);
		clearit = tp->tim_peermaxlen != 0;
		if (clearit) {
			kmem_free(tp->tim_peername, tp->tim_peermaxlen);
			tp->tim_peername = NULL;
			tp->tim_peermaxlen = 0;
			tp->tim_peerlen = 0;
		}
		mutex_exit(&tp->tim_mutex);
		if (clearit) {
			mblk_t *bp;

			bp = tp->tim_consave;
			while (bp != NULL) {
				nbp = bp->b_next;
				bp->b_next = NULL;
				freemsg(bp);
				bp = nbp;
			}
			tp->tim_consave = NULL;
		}
		/* tim_iocsave may already be overwritten. */
		if (tp->tim_saved_prim == -1) {
			freemsg(tp->tim_iocsave);
			tp->tim_iocsave = NULL;
		}
	    }
	    putnext(q, mp);
	    break;

	case M_IOCNAK:

		tilog("timodrproc: Got M_IOCNAK\n", 0);

		iocbp = (struct iocblk *)mp->b_rptr;
		if (((iocbp->ioc_cmd == TI_GETMYNAME) ||
		    (iocbp->ioc_cmd == TI_GETPEERNAME)) &&
		    ((iocbp->ioc_error == EINVAL) || (iocbp->ioc_error == 0))) {
			PI_PROVLOCK(tp->tim_provinfo);
			if (iocbp->ioc_cmd == TI_GETMYNAME) {
				if (tp->tim_provinfo->tpi_myname == PI_DONTKNOW)
					tp->tim_provinfo->tpi_myname = PI_NO;
			} else if (iocbp->ioc_cmd == TI_GETPEERNAME) {
				if (tp->tim_provinfo->tpi_peername == PI_DONTKNOW)
					tp->tim_provinfo->tpi_peername = PI_NO;
			}
			PI_PROVUNLOCK(tp->tim_provinfo);
			/* tim_iocsave may already be overwritten. */
			if ((tp->tim_iocsave != NULL) &&
			    (tp->tim_saved_prim == -1)) {
				freemsg(mp);
				mp = tp->tim_iocsave;
				tp->tim_iocsave = NULL;
				tp->tim_flags |= NAMEPROC;
				if (ti_doname(WR(q), mp) != DONAME_CONT) {
					tp->tim_flags &= ~NAMEPROC;
				}
				break;
			}
		}
		putnext(q, mp);
		break;
	}

	return (0);
}

/*
 * timodwput -	Module write put procedure.  This is called from
 *		the module, driver, or stream head upstream/downstream.
 *		Handles M_FLUSH, M_DATA and some M_PROTO (T_DATA_REQ,
 *		and T_UNITDATA_REQ) messages. All others are queued to
 *		be handled by the service procedures.
 */

static void
timodwput(queue_t *q, mblk_t *mp)
{
	union T_primitives *pptr;
	struct tim_tim *tp;
	struct iocblk *iocbp;

	/*
	 * Enqueue normal-priority messages if our queue already
	 * holds some messages for deferred processing but don't
	 * enqueue those M_IOCTLs which will result in an
	 * M_PCPROTO (ie, high priority) message being created.
	 */
	if (q->q_first != 0 && mp->b_datap->db_type < QPCTL) {
		if (mp->b_datap->db_type == M_IOCTL) {
			iocbp = (struct iocblk *)mp->b_rptr;
			switch (iocbp->ioc_cmd) {
			default:
				(void) putq(q, mp);
				return;

			case TI_GETINFO:
			case TI_SYNC:
			case TI_CAPABILITY:
				break;
			}
		} else {
			(void) putq(q, mp);
			return;
		}
	}
	/*
	 * Inline processing of data (to avoid additional procedure call).
	 * Rest is handled in timodwproc.
	 */

	switch (mp->b_datap->db_type) {
	case M_DATA:
		tp = (struct tim_tim *)q->q_ptr;
		ASSERT(tp);
		if (tp->tim_flags & CLTS) {
			mblk_t	*tmp;

			if ((tmp = tim_filladdr(q, mp, B_FALSE)) == NULL) {
				(void) putq(q, mp);
				break;
			} else {
				mp = tmp;
			}
		}
		if (bcanputnext(q, mp->b_band))
			putnext(q, mp);
		else
			(void) putq(q, mp);
		break;
	case M_PROTO:
	case M_PCPROTO:
		pptr = (union T_primitives *)mp->b_rptr;
		switch (pptr->type) {
		case T_UNITDATA_REQ:
			tp = (struct tim_tim *)q->q_ptr;
			ASSERT(tp);
			if (tp->tim_flags & CLTS) {
				mblk_t	*tmp;

				tmp = tim_filladdr(q, mp, B_FALSE);
				if (tmp == NULL) {
					(void) putq(q, mp);
					break;
				} else {
					mp = tmp;
				}
			}
			if (bcanputnext(q, mp->b_band))
				putnext(q, mp);
			else
				(void) putq(q, mp);
			break;

		case T_DATA_REQ:
		case T_EXDATA_REQ:
			if (bcanputnext(q, mp->b_band))
				putnext(q, mp);
			else
				(void) putq(q, mp);
			break;
		default:
			(void) timodwproc(q, mp);
			break;
		}
		break;
	default:
		(void) timodwproc(q, mp);
		break;
	}
}
/*
 * timodwsrv -	Module write queue service procedure.
 *		This is called when messages are placed on an empty queue,
 *		when high priority messages are placed on the queue, and
 *		when flow control restrictions subside.  This code used to
 *		be included in a put procedure, but it was moved to a
 *		service procedure because several points were added where
 *		memory allocation could fail, and there is no reasonable
 *		recovery mechanism from the put procedure.
 */
static void
timodwsrv(queue_t *q)
{
	mblk_t *mp;

	ASSERT(q != NULL);
	if (q->q_ptr == NULL)
		return;

	while ((mp = getq(q)) != NULL) {
		if (timodwproc(q, mp)) {
			/*
			 * timodwproc did a putbq - stop processing
			 * messages.
			 */
			return;
		}
	}
}

/*
 * Common routine to process write side messages
 */

static int
timodwproc(queue_t *q, mblk_t *mp)
{
	union T_primitives *pptr;
	struct tim_tim *tp;
	uint32_t auditing = AU_AUDITING();
	mblk_t *tmp;
	struct iocblk *iocbp;
	int error;

	tp = (struct tim_tim *)q->q_ptr;

	switch (mp->b_datap->db_type) {
	default:
		putnext(q, mp);
		break;

	case M_DATA:
		if (tp->tim_flags & CLTS) {
			if ((tmp = tim_filladdr(q, mp, B_TRUE)) == NULL) {
				return (1);
			} else {
				mp = tmp;
			}
		}
		if (!bcanputnext(q, mp->b_band)) {
			(void) putbq(q, mp);
			return (1);
		}
		putnext(q, mp);
		break;

	case M_IOCTL:

		iocbp = (struct iocblk *)mp->b_rptr;
		TILOG("timodwproc: Got M_IOCTL(%d)\n", iocbp->ioc_cmd);

		ASSERT(MBLKL(mp) == sizeof (struct iocblk));

		/*
		 * TPI requires we await response to a previously sent message
		 * before handling another, put it back on the head of queue.
		 * Since putbq() may see QWANTR unset when called from the
		 * service procedure, the queue must be explicitly scheduled
		 * for service, as no backenable will occur for this case.
		 * tim_ioctl_retry() sets a timer to handle the qenable.
		 */
		if (tp->tim_flags & WAITIOCACK) {
			TILOG("timodwproc: putbq M_IOCTL(%d)\n",
			    iocbp->ioc_cmd);
			(void) putbq(q, mp);
			/* Called from timodwsrv() and messages on queue */
			if (!(q->q_flag & QWANTR))
				tim_ioctl_retry(q);
			return (1);
		}

		switch (iocbp->ioc_cmd) {
		default:
			putnext(q, mp);
			break;

		case _I_GETPEERCRED:
			if ((tp->tim_flags & COTS) == 0) {
				miocnak(q, mp, 0, ENOTSUP);
			} else {
				mblk_t *cmp = mp->b_cont;
				k_peercred_t *kp = NULL;

				mutex_enter(&tp->tim_mutex);
				if (cmp != NULL &&
				    iocbp->ioc_flag == IOC_NATIVE &&
				    (tp->tim_flags &
				    (CONNWAIT|LOCORDREL|REMORDREL)) == 0 &&
				    tp->tim_peercred != NULL &&
				    DB_TYPE(cmp) == M_DATA &&
				    MBLKL(cmp) == sizeof (k_peercred_t)) {
					kp = (k_peercred_t *)cmp->b_rptr;
					crhold(kp->pc_cr = tp->tim_peercred);
					kp->pc_cpid = tp->tim_cpid;
				}
				mutex_exit(&tp->tim_mutex);
				if (kp != NULL)
					miocack(q, mp, sizeof (*kp), 0);
				else
					miocnak(q, mp, 0, ENOTCONN);
			}
			break;
		case TI_BIND:
		case TI_UNBIND:
		case TI_OPTMGMT:
		case TI_GETADDRS:
			TILOG("timodwproc: TI_{BIND|UNBIND|OPTMGMT|GETADDRS}"
			    "\n", 0);

			/*
			 * We know that tim_send_ioctl_tpi_msg() is only
			 * going to examine the `type' field, so we only
			 * check that we can access that much data.
			 */
			error = miocpullup(mp, sizeof (t_scalar_t));
			if (error != 0) {
				miocnak(q, mp, 0, error);
				break;
			}
			tim_send_ioctl_tpi_msg(q, mp, tp, iocbp);
			break;

		case TI_GETINFO:
			TILOG("timodwproc: TI_GETINFO\n", 0);
			error = miocpullup(mp, sizeof (struct T_info_req));
			if (error != 0) {
				miocnak(q, mp, 0, error);
				break;
			}
			tp->tim_flags |= WAIT_IOCINFOACK;
			tim_send_ioctl_tpi_msg(q, mp, tp, iocbp);
			break;

		case TI_SYNC: {
			mblk_t *tsr_mp;
			struct ti_sync_req *tsr;
			uint32_t tsr_flags;

			error = miocpullup(mp, sizeof (struct ti_sync_req));
			if (error != 0) {
				miocnak(q, mp, 0, error);
				break;
			}

			tsr_mp = mp->b_cont;
			tsr = (struct ti_sync_req *)tsr_mp->b_rptr;
			TILOG("timodwproc: TI_SYNC(%x)\n", tsr->tsr_flags);

			/*
			 * Save out the value of tsr_flags, in case we
			 * reallocb() tsr_mp (below).
			 */
			tsr_flags = tsr->tsr_flags;
			if ((tsr_flags & TSRF_INFO_REQ) == 0) {
				mblk_t *ack_mp = reallocb(tsr_mp,
				    sizeof (struct ti_sync_ack), 0);

				/* Can reply immediately. */
				mp->b_cont = NULL;
				if (ack_mp == NULL) {
					tilog("timodwproc: allocb failed no "
					    "recovery attempt\n", 0);
					freemsg(tsr_mp);
					miocnak(q, mp, 0, ENOMEM);
				} else {
					tim_answer_ti_sync(q, mp, tp,
					    ack_mp, tsr_flags);
				}
				break;
			}

			/*
			 * This code is retained for compatibility with
			 * old statically linked applications. New code
			 * should use TI_CAPABILITY for all TPI
			 * information and should not use TSRF_INFO_REQ
			 * flag.
			 *
			 * defer processsing necessary to rput procedure
			 * as we need to get information from transport
			 * driver. Set flags that will tell the read
			 * side the work needed on this request.
			 */

			if (tsr_flags & TSRF_IS_EXP_IN_RCVBUF)
				tp->tim_flags |= PEEK_RDQ_EXPIND;

			/*
			 * Convert message to a T_INFO_REQ message; relies
			 * on sizeof (struct ti_sync_req) >= sizeof (struct
			 * T_info_req)).
			 */
			ASSERT(MBLKL(tsr_mp) >= sizeof (struct T_info_req));

			((struct T_info_req *)tsr_mp->b_rptr)->PRIM_type =
			    T_INFO_REQ;
			tsr_mp->b_wptr = tsr_mp->b_rptr +
			    sizeof (struct T_info_req);
			tp->tim_flags |= WAIT_IOCINFOACK;
			tim_send_ioctl_tpi_msg(q, mp, tp, iocbp);
		}
		break;

		case TI_CAPABILITY: {
			mblk_t *tcsr_mp;
			struct T_capability_req *tcr;

			error = miocpullup(mp, sizeof (*tcr));
			if (error != 0) {
				miocnak(q, mp, 0, error);
				break;
			}

			tcsr_mp = mp->b_cont;
			tcr = (struct T_capability_req *)tcsr_mp->b_rptr;
			TILOG("timodwproc: TI_CAPABILITY(CAP_bits1 = %x)\n",
			    tcr->CAP_bits1);

			if (tcr->PRIM_type != T_CAPABILITY_REQ) {
				TILOG("timodwproc: invalid msg type %d\n",
				    tcr->PRIM_type);
				miocnak(q, mp, 0, EPROTO);
				break;
			}

			switch (tp->tim_provinfo->tpi_capability) {
			case PI_YES:
				/* Just send T_CAPABILITY_REQ down */
				tim_send_ioctl_tpi_msg(q, mp, tp, iocbp);
				break;

			case PI_DONTKNOW:
				/*
				 * It is unknown yet whether transport provides
				 * T_CAPABILITY_REQ or not. Send message down
				 * and wait for reply.
				 */

				ASSERT(tp->tim_tcap_timoutid == 0);
				if ((tcr->CAP_bits1 & TC1_INFO) == 0) {
					tp->tim_flags |= TI_CAP_RECVD;
				} else {
					tp->tim_flags |= (TI_CAP_RECVD |
					    CAP_WANTS_INFO);
				}

				tp->tim_tcap_timoutid = qtimeout(q,
				    tim_tcap_timer, q, tim_tcap_wait * hz);
				tim_send_ioctl_tpi_msg(q, mp, tp, iocbp);
				break;

			case PI_NO:
				/*
				 * Transport doesn't support T_CAPABILITY_REQ.
				 * Either reply immediately or send T_INFO_REQ
				 * if needed.
				 */
				if ((tcr->CAP_bits1 & TC1_INFO) != 0) {
					tp->tim_flags |= (TI_CAP_RECVD |
					    CAP_WANTS_INFO | WAIT_IOCINFOACK);
					TILOG("timodwproc: sending down "
					    "T_INFO_REQ, flags = %x\n",
					    tp->tim_flags);

				/*
				 * Generate T_INFO_REQ message and send
				 * it down
				 */
					((struct T_info_req *)tcsr_mp->b_rptr)->
					    PRIM_type = T_INFO_REQ;
					tcsr_mp->b_wptr = tcsr_mp->b_rptr +
					    sizeof (struct T_info_req);
					tim_send_ioctl_tpi_msg(q, mp, tp,
					    iocbp);
					break;
				}


				/*
				 * Can reply immediately. Just send back
				 * T_CAPABILITY_ACK with CAP_bits1 set to 0.
				 */
				mp->b_cont = tcsr_mp = tpi_ack_alloc(mp->b_cont,
				    sizeof (struct T_capability_ack), M_PCPROTO,
				    T_CAPABILITY_ACK);

				if (tcsr_mp == NULL) {
					tilog("timodwproc: allocb failed no "
					    "recovery attempt\n", 0);
					miocnak(q, mp, 0, ENOMEM);
					break;
				}

				tp->tim_flags &= ~(WAITIOCACK | TI_CAP_RECVD |
				    WAIT_IOCINFOACK | CAP_WANTS_INFO);
				((struct T_capability_ack *)
				    tcsr_mp->b_rptr)->CAP_bits1 = 0;
				tim_ioctl_send_reply(q, mp, tcsr_mp);

				/*
				 * It could happen when timod is awaiting ack
				 * for TI_GETPEERNAME/TI_GETMYNAME.
				 */
				if (tp->tim_iocsave != NULL) {
					freemsg(tp->tim_iocsave);
					tp->tim_iocsave = NULL;
					tp->tim_saved_prim = -1;
				}
				break;

			default:
				cmn_err(CE_PANIC,
				    "timodwproc: unknown tpi_capability value "
				    "%d\n", tp->tim_provinfo->tpi_capability);
				break;
			}
		}
		break;

		case TI_GETMYNAME:

			tilog("timodwproc: Got TI_GETMYNAME\n", 0);

			if (tp->tim_provinfo->tpi_myname == PI_YES) {
				putnext(q, mp);
				break;
			}
			goto getname;

		case TI_GETPEERNAME:

			tilog("timodwproc: Got TI_GETPEERNAME\n", 0);

			if (tp->tim_provinfo->tpi_peername == PI_YES) {
				putnext(q, mp);
				break;
			}
getname:
			if ((tmp = copymsg(mp)) == NULL) {
				tim_recover(q, mp, msgsize(mp));
				return (1);
			}
			/*
			 * tim_iocsave may be non-NULL when timod is awaiting
			 * ack for another TI_GETPEERNAME/TI_GETMYNAME.
			 */
			freemsg(tp->tim_iocsave);
			tp->tim_iocsave = mp;
			tp->tim_saved_prim = -1;
			putnext(q, tmp);
			break;
			}
		break;

	case M_IOCDATA:

		if (tp->tim_flags & NAMEPROC) {
			if (ti_doname(q, mp) != DONAME_CONT) {
				tp->tim_flags &= ~NAMEPROC;
			}
		} else
			putnext(q, mp);
		break;

	case M_PROTO:
	case M_PCPROTO:
		if (MBLKL(mp) < sizeof (t_scalar_t)) {
			merror(q, mp, EPROTO);
			return (1);
		}

		pptr = (union T_primitives *)mp->b_rptr;
		switch (pptr->type) {
		default:
			putnext(q, mp);
			break;

		case T_EXDATA_REQ:
		case T_DATA_REQ:
			if (pptr->type == T_EXDATA_REQ)
				tilog("timodwproc: Got T_EXDATA_REQ\n", 0);

		if (!bcanputnext(q, mp->b_band)) {
			(void) putbq(q, mp);
			return (1);
		}
		putnext(q, mp);
		break;

		case T_UNITDATA_REQ:
			if (tp->tim_flags & CLTS) {
				tmp = tim_filladdr(q, mp, B_TRUE);
				if (tmp == NULL) {
					return (1);
				} else {
					mp = tmp;
				}
			}
			if (auditing)
				audit_sock(T_UNITDATA_REQ, q, mp, TIMOD_ID);
		if (!bcanputnext(q, mp->b_band)) {
				(void) putbq(q, mp);
				return (1);
			}
			putnext(q, mp);
			break;

		case T_CONN_REQ: {
			struct T_conn_req *reqp = (struct T_conn_req *)
			    mp->b_rptr;
			void *p;

			tilog("timodwproc: Got T_CONN_REQ\n", 0);

			if (MBLKL(mp) < sizeof (struct T_conn_req)) {
				merror(q, mp, EPROTO);
				return (1);
			}

			if (tp->tim_flags & DO_PEERNAME) {
				if (!MBLKIN(mp, reqp->DEST_offset,
				    reqp->DEST_length)) {
					merror(q, mp, EPROTO);
					return (1);
				}
				ASSERT(reqp->DEST_length >= 0);
				mutex_enter(&tp->tim_mutex);
				if (reqp->DEST_length > tp->tim_peermaxlen) {
					p = kmem_alloc(reqp->DEST_length,
					    KM_NOSLEEP);
					if (p == NULL) {
						mutex_exit(&tp->tim_mutex);
						tilog("timodwproc: kmem_alloc "
						    "failed, attempting "
						    "recovery\n", 0);
						tim_recover(q, mp,
						    reqp->DEST_length);
						return (1);
					}
					if (tp->tim_peermaxlen)
						kmem_free(tp->tim_peername,
						    tp->tim_peermaxlen);
					tp->tim_peername = p;
					tp->tim_peermaxlen = reqp->DEST_length;
				}
				tp->tim_peerlen = reqp->DEST_length;
				p = mp->b_rptr + reqp->DEST_offset;
				bcopy(p, tp->tim_peername, tp->tim_peerlen);
				mutex_exit(&tp->tim_mutex);
			}
			if (tp->tim_flags & COTS)
				tp->tim_flags |= CONNWAIT;
			if (auditing)
				audit_sock(T_CONN_REQ, q, mp, TIMOD_ID);
		putnext(q, mp);
		break;
		}

		case O_T_CONN_RES:
		case T_CONN_RES: {
			struct T_conn_res *resp;
			struct T_conn_ind *indp;
			mblk_t *pmp = NULL;
			mblk_t *nbp;

			if (MBLKL(mp) < sizeof (struct T_conn_res) ||
			    (tp->tim_flags & WAITIOCACK)) {
				merror(q, mp, EPROTO);
				return (1);
			}

			resp = (struct T_conn_res *)mp->b_rptr;
			for (tmp = tp->tim_consave; tmp != NULL;
			    tmp = tmp->b_next) {
				indp = (struct T_conn_ind *)tmp->b_rptr;
				if (indp->SEQ_number == resp->SEQ_number)
					break;
				pmp = tmp;
			}
			if (tmp == NULL)
				goto cresout;

			if ((nbp = dupb(mp)) == NULL &&
			    (nbp = copyb(mp)) == NULL) {
				tim_recover(q, mp, msgsize(mp));
				return (1);
			}

			if (pmp != NULL)
				pmp->b_next = tmp->b_next;
			else
				tp->tim_consave = tmp->b_next;
			tmp->b_next = NULL;

			/*
			 * Construct a list with:
			 *	nbp - copy of user's original request
			 *	tmp - the extracted T_conn_ind
			 */
			nbp->b_cont = tmp;
			/*
			 * tim_iocsave may be non-NULL when timod is awaiting
			 * ack for TI_GETPEERNAME/TI_GETMYNAME.
			 */
			freemsg(tp->tim_iocsave);
			tp->tim_iocsave = nbp;
			tp->tim_saved_prim = pptr->type;
			tp->tim_flags |= WAIT_CONNRESACK | WAITIOCACK;

		cresout:
			putnext(q, mp);
			break;
		}

		case T_DISCON_REQ: {
			struct T_discon_req *disp;
			struct T_conn_ind *conp;
			mblk_t *pmp = NULL;

			if (MBLKL(mp) < sizeof (struct T_discon_req)) {
				merror(q, mp, EPROTO);
				return (1);
			}

			disp = (struct T_discon_req *)mp->b_rptr;
			tp->tim_flags &= ~(CONNWAIT|LOCORDREL|REMORDREL);
			tim_clear_peer(tp);

			/*
			 * If we are already connected, there won't
			 * be any messages on tim_consave.
			 */
			for (tmp = tp->tim_consave; tmp; tmp = tmp->b_next) {
				conp = (struct T_conn_ind *)tmp->b_rptr;
				if (conp->SEQ_number == disp->SEQ_number)
					break;
				pmp = tmp;
			}
			if (tmp) {
				if (pmp)
					pmp->b_next = tmp->b_next;
				else
					tp->tim_consave = tmp->b_next;
				tmp->b_next = NULL;
				freemsg(tmp);
			}
			putnext(q, mp);
			break;
		}

		case T_ORDREL_REQ:
			if (tp->tim_flags & REMORDREL) {
				tp->tim_flags &= ~(LOCORDREL|REMORDREL);
				tim_clear_peer(tp);
			} else {
				tp->tim_flags |= LOCORDREL;
			}
			putnext(q, mp);
			break;

		case T_CAPABILITY_REQ:
			tilog("timodwproc: Got T_CAPABILITY_REQ\n", 0);
			/*
			 * XXX: We may know at this point whether transport
			 * provides T_CAPABILITY_REQ or not and we may utilise
			 * this knowledge here.
			 */
			putnext(q, mp);
			break;
		}
		break;
	case M_FLUSH:

		tilog("timodwproc: Got M_FLUSH\n", 0);

		if (*mp->b_rptr & FLUSHW) {
			if (*mp->b_rptr & FLUSHBAND)
				flushband(q, *(mp->b_rptr + 1), FLUSHDATA);
			else
				flushq(q, FLUSHDATA);
		}
		putnext(q, mp);
		break;
	}

	return (0);
}

static void
tilog(char *str, t_scalar_t arg)
{
	if (dotilog) {
		if (dotilog & 2)
			cmn_err(CE_CONT, str, arg);
		if (dotilog & 4)
			(void) strlog(TIMOD_ID, -1, 0, SL_TRACE | SL_ERROR,
			    str, arg);
		else
			(void) strlog(TIMOD_ID, -1, 0, SL_TRACE, str, arg);
	}
}

static void
tilogp(char *str, uintptr_t arg)
{
	if (dotilog) {
		if (dotilog & 2)
			cmn_err(CE_CONT, str, arg);
		if (dotilog & 4)
			(void) strlog(TIMOD_ID, -1, 0, SL_TRACE | SL_ERROR,
			    str, arg);
		else
			(void) strlog(TIMOD_ID, -1, 0, SL_TRACE, str, arg);
	}
}


/*
 * Process the TI_GETNAME ioctl.  If no name exists, return len = 0
 * in strbuf structures.  The state transitions are determined by what
 * is hung of cq_private (cp_private) in the copyresp (copyreq) structure.
 * The high-level steps in the ioctl processing are as follows:
 *
 * 1) we recieve an transparent M_IOCTL with the arg in the second message
 *	block of the message.
 * 2) we send up an M_COPYIN request for the strbuf structure pointed to
 *	by arg.  The block containing arg is hung off cq_private.
 * 3) we receive an M_IOCDATA response with cp->cp_private->b_cont == NULL.
 *	This means that the strbuf structure is found in the message block
 *	mp->b_cont.
 * 4) we send up an M_COPYOUT request with the strbuf message hung off
 *	cq_private->b_cont.  The address we are copying to is strbuf.buf.
 *	we set strbuf.len to 0 to indicate that we should copy the strbuf
 *	structure the next time.  The message mp->b_cont contains the
 *	address info.
 * 5) we receive an M_IOCDATA with cp_private->b_cont != NULL and
 *	strbuf.len == 0.  Restore strbuf.len to either tp->tim_mylen or
 *	tp->tim_peerlen.
 * 6) we send up an M_COPYOUT request with a copy of the strbuf message
 *	hung off mp->b_cont.  In the strbuf structure in the message hung
 *	off cq_private->b_cont, we set strbuf.len to 0 and strbuf.maxlen
 *	to 0.  This means that the next step is to ACK the ioctl.
 * 7) we receive an M_IOCDATA message with cp_private->b_cont != NULL and
 *	strbuf.len == 0 and strbuf.maxlen == 0.  Free up cp->private and
 *	send an M_IOCACK upstream, and we are done.
 *
 */
static int
ti_doname(
	queue_t *q,		/* queue message arrived at */
	mblk_t *mp)		/* M_IOCTL or M_IOCDATA message only */
{
	struct iocblk *iocp;
	struct copyreq *cqp;
	STRUCT_HANDLE(strbuf, sb);
	struct copyresp *csp;
	int ret;
	mblk_t *bp;
	struct tim_tim *tp = q->q_ptr;
	boolean_t getpeer;

	switch (mp->b_datap->db_type) {
	case M_IOCTL:
		iocp = (struct iocblk *)mp->b_rptr;
		if ((iocp->ioc_cmd != TI_GETMYNAME) &&
		    (iocp->ioc_cmd != TI_GETPEERNAME)) {
			tilog("ti_doname: bad M_IOCTL command\n", 0);
			miocnak(q, mp, 0, EINVAL);
			ret = DONAME_FAIL;
			break;
		}
		if ((iocp->ioc_count != TRANSPARENT)) {
			miocnak(q, mp, 0, EINVAL);
			ret = DONAME_FAIL;
			break;
		}

		cqp = (struct copyreq *)mp->b_rptr;
		cqp->cq_private = mp->b_cont;
		cqp->cq_addr = (caddr_t)*(intptr_t *)mp->b_cont->b_rptr;
		mp->b_cont = NULL;
		cqp->cq_size = SIZEOF_STRUCT(strbuf, iocp->ioc_flag);
		cqp->cq_flag = 0;
		mp->b_datap->db_type = M_COPYIN;
		mp->b_wptr = mp->b_rptr + sizeof (struct copyreq);
		qreply(q, mp);
		ret = DONAME_CONT;
		break;

	case M_IOCDATA:
		csp = (struct copyresp *)mp->b_rptr;
		iocp = (struct iocblk *)mp->b_rptr;
		cqp = (struct copyreq *)mp->b_rptr;
		if ((csp->cp_cmd != TI_GETMYNAME) &&
		    (csp->cp_cmd != TI_GETPEERNAME)) {
			cmn_err(CE_WARN, "ti_doname: bad M_IOCDATA command\n");
			miocnak(q, mp, 0, EINVAL);
			ret = DONAME_FAIL;
			break;
		}
		if (csp->cp_rval) {	/* error */
			freemsg(csp->cp_private);
			freemsg(mp);
			ret = DONAME_FAIL;
			break;
		}
		ASSERT(csp->cp_private != NULL);
		getpeer = csp->cp_cmd == TI_GETPEERNAME;
		if (getpeer)
			mutex_enter(&tp->tim_mutex);
		if (csp->cp_private->b_cont == NULL) {	/* got strbuf */
			ASSERT(mp->b_cont);
			STRUCT_SET_HANDLE(sb, iocp->ioc_flag,
			    (void *)mp->b_cont->b_rptr);
			if (getpeer) {
				if (tp->tim_peerlen == 0) {
					/* copy just strbuf */
					STRUCT_FSET(sb, len, 0);
				} else if (tp->tim_peerlen >
				    STRUCT_FGET(sb, maxlen)) {
					mutex_exit(&tp->tim_mutex);
					miocnak(q, mp, 0, ENAMETOOLONG);
					ret = DONAME_FAIL;
					break;
				} else {
					/* copy buffer */
					STRUCT_FSET(sb, len, tp->tim_peerlen);
				}
			} else {
				if (tp->tim_mylen == 0) {
					/* copy just strbuf */
					STRUCT_FSET(sb, len, 0);
				} else if (tp->tim_mylen >
				    STRUCT_FGET(sb, maxlen)) {
					freemsg(csp->cp_private);
					miocnak(q, mp, 0, ENAMETOOLONG);
					ret = DONAME_FAIL;
					break;
				} else {
					/* copy buffer */
					STRUCT_FSET(sb, len, tp->tim_mylen);
				}
			}
			csp->cp_private->b_cont = mp->b_cont;
			mp->b_cont = NULL;
		}
		STRUCT_SET_HANDLE(sb, iocp->ioc_flag,
		    (void *)csp->cp_private->b_cont->b_rptr);
		if (STRUCT_FGET(sb, len) == 0) {
			/*
			 * restore strbuf.len
			 */
			if (getpeer)
				STRUCT_FSET(sb, len, tp->tim_peerlen);
			else
				STRUCT_FSET(sb, len, tp->tim_mylen);

			if (getpeer)
				mutex_exit(&tp->tim_mutex);
			if (STRUCT_FGET(sb, maxlen) == 0) {

				/*
				 * ack the ioctl
				 */
				freemsg(csp->cp_private);
				tim_ioctl_send_reply(q, mp, NULL);
				ret = DONAME_DONE;
				break;
			}

			if ((bp = allocb(STRUCT_SIZE(sb), BPRI_MED)) == NULL) {

				tilog(
			"ti_doname: allocb failed no recovery attempt\n", 0);

				freemsg(csp->cp_private);
				miocnak(q, mp, 0, EAGAIN);
				ret = DONAME_FAIL;
				break;
			}
			bp->b_wptr += STRUCT_SIZE(sb);
			bcopy(STRUCT_BUF(sb), bp->b_rptr, STRUCT_SIZE(sb));
			cqp->cq_addr =
			    (caddr_t)*(intptr_t *)csp->cp_private->b_rptr;
			cqp->cq_size = STRUCT_SIZE(sb);
			cqp->cq_flag = 0;
			mp->b_datap->db_type = M_COPYOUT;
			mp->b_cont = bp;
			STRUCT_FSET(sb, len, 0);
			STRUCT_FSET(sb, maxlen, 0); /* ack next time around */
			qreply(q, mp);
			ret = DONAME_CONT;
			break;
		}

		/*
		 * copy the address to the user
		 */
		if ((bp = allocb((size_t)STRUCT_FGET(sb, len), BPRI_MED))
		    == NULL) {
			if (getpeer)
				mutex_exit(&tp->tim_mutex);

			tilog("ti_doname: allocb failed no recovery attempt\n",
			    0);

			freemsg(csp->cp_private);
			miocnak(q, mp, 0, EAGAIN);
			ret = DONAME_FAIL;
			break;
		}
		bp->b_wptr += STRUCT_FGET(sb, len);
		if (getpeer) {
			bcopy(tp->tim_peername, bp->b_rptr,
			    STRUCT_FGET(sb, len));
			mutex_exit(&tp->tim_mutex);
		} else {
			bcopy(tp->tim_myname, bp->b_rptr, STRUCT_FGET(sb, len));
		}
		cqp->cq_addr = (caddr_t)STRUCT_FGETP(sb, buf);
		cqp->cq_size = STRUCT_FGET(sb, len);
		cqp->cq_flag = 0;
		mp->b_datap->db_type = M_COPYOUT;
		mp->b_cont = bp;
		STRUCT_FSET(sb, len, 0); /* copy the strbuf next time around */
		qreply(q, mp);
		ret = DONAME_CONT;
		break;

	default:
		tilog("ti_doname: freeing bad message type = %d\n",
		    mp->b_datap->db_type);
		freemsg(mp);
		ret = DONAME_FAIL;
		break;
	}
	return (ret);
}


/*
 * Fill in the address of a connectionless data packet if a connect
 * had been done on this endpoint.
 */
static mblk_t *
tim_filladdr(queue_t *q, mblk_t *mp, boolean_t dorecover)
{
	mblk_t *bp;
	struct tim_tim *tp;
	struct T_unitdata_req *up;
	struct T_unitdata_req *nup;
	size_t plen;

	tp = (struct tim_tim *)q->q_ptr;
	if (mp->b_datap->db_type == M_DATA) {
		mutex_enter(&tp->tim_mutex);
		bp = allocb(sizeof (struct T_unitdata_req) + tp->tim_peerlen,
		    BPRI_MED);
		if (bp != NULL) {
			bp->b_datap->db_type = M_PROTO;
			up = (struct T_unitdata_req *)bp->b_rptr;
			up->PRIM_type = T_UNITDATA_REQ;
			up->DEST_length = tp->tim_peerlen;
			bp->b_wptr += sizeof (struct T_unitdata_req);
			up->DEST_offset = sizeof (struct T_unitdata_req);
			up->OPT_length = 0;
			up->OPT_offset = 0;
			if (tp->tim_peerlen > 0) {
				bcopy(tp->tim_peername, bp->b_wptr,
				    tp->tim_peerlen);
				bp->b_wptr += tp->tim_peerlen;
			}
			bp->b_cont = mp;
		}
	} else {
		ASSERT(mp->b_datap->db_type == M_PROTO);
		up = (struct T_unitdata_req *)mp->b_rptr;
		ASSERT(up->PRIM_type == T_UNITDATA_REQ);
		if (up->DEST_length != 0)
			return (mp);
		mutex_enter(&tp->tim_mutex);
		bp = allocb(sizeof (struct T_unitdata_req) + up->OPT_length +
		    tp->tim_peerlen, BPRI_MED);
		if (bp != NULL) {
			bp->b_datap->db_type = M_PROTO;
			nup = (struct T_unitdata_req *)bp->b_rptr;
			nup->PRIM_type = T_UNITDATA_REQ;
			nup->DEST_length = plen = tp->tim_peerlen;
			bp->b_wptr += sizeof (struct T_unitdata_req);
			nup->DEST_offset = sizeof (struct T_unitdata_req);
			if (plen > 0) {
				bcopy(tp->tim_peername, bp->b_wptr, plen);
				bp->b_wptr += plen;
			}
			mutex_exit(&tp->tim_mutex);
			if (up->OPT_length == 0) {
				nup->OPT_length = 0;
				nup->OPT_offset = 0;
			} else {
				nup->OPT_length = up->OPT_length;
				nup->OPT_offset =
				    sizeof (struct T_unitdata_req) + plen;
				bcopy((mp->b_wptr + up->OPT_offset), bp->b_wptr,
				    up->OPT_length);
				bp->b_wptr += up->OPT_length;
			}
			bp->b_cont = mp->b_cont;
			mp->b_cont = NULL;
			freeb(mp);
			return (bp);
		}
	}
	ASSERT(MUTEX_HELD(&tp->tim_mutex));
	if (bp == NULL && dorecover) {
		tim_recover(q, mp,
		    sizeof (struct T_unitdata_req) + tp->tim_peerlen);
	}
	mutex_exit(&tp->tim_mutex);
	return (bp);
}

static void
tim_addlink(struct tim_tim *tp)
{
	struct tim_tim **tpp;
	struct tim_tim	*next;

	tpp = &tim_hash[TIM_HASH(tp->tim_acceptor)];
	rw_enter(&tim_list_rwlock, RW_WRITER);

	if ((next = *tpp) != NULL)
		next->tim_ptpn = &tp->tim_next;
	tp->tim_next = next;
	tp->tim_ptpn = tpp;
	*tpp = tp;

	tim_cnt++;

	rw_exit(&tim_list_rwlock);
}

static void
tim_dellink(struct tim_tim *tp)
{
	struct tim_tim	*next;

	rw_enter(&tim_list_rwlock, RW_WRITER);

	if ((next = tp->tim_next) != NULL)
		next->tim_ptpn = tp->tim_ptpn;
	*(tp->tim_ptpn) = next;

	tim_cnt--;

	rw_exit(&tim_list_rwlock);
}

static struct tim_tim *
tim_findlink(t_uscalar_t id)
{
	struct tim_tim	*tp;

	ASSERT(rw_lock_held(&tim_list_rwlock));

	for (tp = tim_hash[TIM_HASH(id)]; tp != NULL; tp = tp->tim_next) {
		if (tp->tim_acceptor == id) {
			break;
		}
	}
	return (tp);
}

static void
tim_recover(queue_t *q, mblk_t *mp, t_scalar_t size)
{
	struct tim_tim	*tp;
	bufcall_id_t	bid;
	timeout_id_t	tid;

	tp = (struct tim_tim *)q->q_ptr;

	/*
	 * Avoid re-enabling the queue.
	 */
	if (mp->b_datap->db_type == M_PCPROTO)
		mp->b_datap->db_type = M_PROTO;
	noenable(q);
	(void) putbq(q, mp);

	/*
	 * Make sure there is at most one outstanding request per queue.
	 */
	if (q->q_flag & QREADR) {
		if (tp->tim_rtimoutid || tp->tim_rbufcid)
			return;
	} else {
		if (tp->tim_wtimoutid || tp->tim_wbufcid)
			return;
	}
	if (!(bid = qbufcall(RD(q), (size_t)size, BPRI_MED, tim_buffer, q))) {
		tid = qtimeout(RD(q), tim_timer, q, TIMWAIT);
		if (q->q_flag & QREADR)
			tp->tim_rtimoutid = tid;
		else
			tp->tim_wtimoutid = tid;
	} else	{
		if (q->q_flag & QREADR)
			tp->tim_rbufcid = bid;
		else
			tp->tim_wbufcid = bid;
	}
}

/*
 * Timod is waiting on a downstream ioctl reply, come back soon
 * to reschedule the write side service routine, which will check
 * if the ioctl is done and another can proceed.
 */
static void
tim_ioctl_retry(queue_t *q)
{
	struct tim_tim  *tp;

	tp = (struct tim_tim *)q->q_ptr;

	/*
	 * Make sure there is at most one outstanding request per wqueue.
	 */
	if (tp->tim_wtimoutid || tp->tim_wbufcid)
		return;

	tp->tim_wtimoutid = qtimeout(RD(q), tim_timer, q, TIMIOCWAIT);
}

/*
 * Inspect the data on read queues starting from read queues passed as
 * paramter (timod read queue) and traverse until
 * q_next is NULL (stream head). Look for a TPI T_EXDATA_IND message
 * reutrn 1 if found, 0 if not found.
 */
static int
ti_expind_on_rdqueues(queue_t *rq)
{
	mblk_t *bp;
	queue_t *q;

	q = rq;
	/*
	 * We are going to walk q_next, so protect stream from plumbing
	 * changes.
	 */
	claimstr(q);
	do {
		/*
		 * Hold QLOCK while referencing data on queues
		 */
		mutex_enter(QLOCK(rq));
		bp = rq->q_first;
		while (bp != NULL) {
			/*
			 * Walk the messages on the queue looking
			 * for a possible T_EXDATA_IND
			 */
			if ((bp->b_datap->db_type == M_PROTO) &&
			    ((bp->b_wptr - bp->b_rptr) >=
			    sizeof (struct T_exdata_ind)) &&
			    (((struct T_exdata_ind *)bp->b_rptr)->PRIM_type
			    == T_EXDATA_IND)) {
				/* bp is T_EXDATA_IND */
				mutex_exit(QLOCK(rq));
				releasestr(q); /* decrement sd_refcnt  */
				return (1); /* expdata is on a read queue */
			}
			bp = bp->b_next; /* next message */
		}
		mutex_exit(QLOCK(rq));
		rq = rq->q_next;	/* next upstream queue */
	} while (rq != NULL);
	releasestr(q);
	return (0);		/* no expdata on read queues */
}

static void
tim_tcap_timer(void *q_ptr)
{
	queue_t *q = (queue_t *)q_ptr;
	struct tim_tim *tp = (struct tim_tim *)q->q_ptr;

	ASSERT(tp != NULL && tp->tim_tcap_timoutid != 0);
	ASSERT((tp->tim_flags & TI_CAP_RECVD) != 0);

	tp->tim_tcap_timoutid = 0;
	TILOG("tim_tcap_timer: fired\n", 0);
	tim_tcap_genreply(q, tp);
}

/*
 * tim_tcap_genreply() is called either from timeout routine or when
 * T_ERROR_ACK is received. In both cases it means that underlying
 * transport doesn't provide T_CAPABILITY_REQ.
 */
static void
tim_tcap_genreply(queue_t *q, struct tim_tim *tp)
{
	mblk_t		*mp = tp->tim_iocsave;
	struct iocblk	*iocbp;

	TILOG("timodrproc: tim_tcap_genreply\n", 0);

	ASSERT(tp == (struct tim_tim *)q->q_ptr);
	ASSERT(mp != NULL);

	iocbp = (struct iocblk *)mp->b_rptr;
	ASSERT(iocbp != NULL);
	ASSERT(MBLKL(mp) == sizeof (struct iocblk));
	ASSERT(iocbp->ioc_cmd == TI_CAPABILITY);
	ASSERT(mp->b_cont == NULL);

	/* Save this information permanently in the module */
	PI_PROVLOCK(tp->tim_provinfo);
	if (tp->tim_provinfo->tpi_capability == PI_DONTKNOW)
		tp->tim_provinfo->tpi_capability = PI_NO;
	PI_PROVUNLOCK(tp->tim_provinfo);

	if (tp->tim_tcap_timoutid != 0) {
		(void) quntimeout(q, tp->tim_tcap_timoutid);
		tp->tim_tcap_timoutid = 0;
	}

	if ((tp->tim_flags & CAP_WANTS_INFO) != 0) {
		/* Send T_INFO_REQ down */
		mblk_t *tirmp = tpi_ack_alloc(NULL,
		    sizeof (struct T_info_req), M_PCPROTO, T_INFO_REQ);

		if (tirmp != NULL) {
			/* Emulate TC1_INFO */
			TILOG("emulate_tcap_ioc_req: sending T_INFO_REQ\n", 0);
			tp->tim_flags |= WAIT_IOCINFOACK;
			putnext(WR(q), tirmp);
		} else {
			tilog("emulate_tcap_req: allocb fail, "
			    "no recovery attmpt\n", 0);
			tp->tim_iocsave = NULL;
			tp->tim_saved_prim = -1;
			tp->tim_flags &= ~(TI_CAP_RECVD | WAITIOCACK |
			    CAP_WANTS_INFO | WAIT_IOCINFOACK);
			miocnak(q, mp, 0, ENOMEM);
		}
	} else {
		/* Reply immediately */
		mblk_t *ackmp = tpi_ack_alloc(NULL,
		    sizeof (struct T_capability_ack), M_PCPROTO,
		    T_CAPABILITY_ACK);

		mp->b_cont = ackmp;

		if (ackmp != NULL) {
			((struct T_capability_ack *)
			    ackmp->b_rptr)->CAP_bits1 = 0;
			tim_ioctl_send_reply(q, mp, ackmp);
			tp->tim_iocsave = NULL;
			tp->tim_saved_prim = -1;
			tp->tim_flags &= ~(WAITIOCACK | WAIT_IOCINFOACK |
			    TI_CAP_RECVD | CAP_WANTS_INFO);
		} else {
			tilog("timodwproc:allocb failed no "
			    "recovery attempt\n", 0);
			tp->tim_iocsave = NULL;
			tp->tim_saved_prim = -1;
			tp->tim_flags &= ~(TI_CAP_RECVD | WAITIOCACK |
			    CAP_WANTS_INFO | WAIT_IOCINFOACK);
			miocnak(q, mp, 0, ENOMEM);
		}
	}
}


static void
tim_ioctl_send_reply(queue_t *q, mblk_t *ioc_mp, mblk_t *mp)
{
	struct iocblk	*iocbp;

	ASSERT(q != NULL && ioc_mp != NULL);

	ioc_mp->b_datap->db_type = M_IOCACK;
	if (mp != NULL)
		mp->b_datap->db_type = M_DATA;

	if (ioc_mp->b_cont != mp) {
		/* It is safe to call freemsg for NULL pointers */
		freemsg(ioc_mp->b_cont);
		ioc_mp->b_cont = mp;
	}
	iocbp = (struct iocblk *)ioc_mp->b_rptr;
	iocbp->ioc_error = 0;
	iocbp->ioc_rval = 0;
	/*
	 * All ioctl's may return more data than was specified by
	 * count arg. For TI_CAPABILITY count is treated as maximum data size.
	 */
	if (mp == NULL)
		iocbp->ioc_count = 0;
	else if (iocbp->ioc_cmd != TI_CAPABILITY)
		iocbp->ioc_count = msgsize(mp);
	else {
		iocbp->ioc_count = MIN(MBLKL(mp), iocbp->ioc_count);
		/* Truncate message if too large */
		mp->b_wptr = mp->b_rptr + iocbp->ioc_count;
	}

	TILOG("iosendreply: ioc_cmd = %d, ", iocbp->ioc_cmd);
	putnext(RD(q), ioc_mp);
}

/*
 * Send M_IOCACK for errors.
 */
static void
tim_send_ioc_error_ack(queue_t *q, struct tim_tim *tp, mblk_t *mp)
{
	struct T_error_ack *tea = (struct T_error_ack *)mp->b_rptr;
	t_scalar_t error_prim;

	mp->b_wptr = mp->b_rptr + sizeof (struct T_error_ack);
	ASSERT(mp->b_wptr <= mp->b_datap->db_lim);
	error_prim = tea->ERROR_prim;

	ASSERT(tp->tim_iocsave != NULL);
	ASSERT(tp->tim_iocsave->b_cont != mp);

	/* Always send this to the read side of the queue */
	q = RD(q);

	TILOG("tim_send_ioc_error_ack: prim = %d\n", tp->tim_saved_prim);

	if (tp->tim_saved_prim != error_prim) {
		putnext(q, mp);
	} else if (error_prim == T_CAPABILITY_REQ) {
		TILOG("timodrproc: T_ERROR_ACK/T_CAPABILITY_REQ\n", 0);
		ASSERT(tp->tim_iocsave->b_cont == NULL);

		tim_tcap_genreply(q, tp);
		freemsg(mp);
	} else {
		struct iocblk *iocbp = (struct iocblk *)tp->tim_iocsave->b_rptr;

		TILOG("tim_send_ioc_error_ack: T_ERROR_ACK: prim %d\n",
		    error_prim);
		ASSERT(tp->tim_iocsave->b_cont == NULL);

		switch (error_prim) {
		default:
			TILOG("timodrproc: Unknown T_ERROR_ACK:  tlierror %d\n",
			    tea->TLI_error);

			putnext(q, mp);
			break;

		case T_INFO_REQ:
		case T_SVR4_OPTMGMT_REQ:
		case T_OPTMGMT_REQ:
		case O_T_BIND_REQ:
		case T_BIND_REQ:
		case T_UNBIND_REQ:
		case T_ADDR_REQ:
		case T_CAPABILITY_REQ:

			TILOG("ioc_err_ack: T_ERROR_ACK: tlierror %x\n",
			    tea->TLI_error);

			/* get saved ioctl msg and set values */
			iocbp->ioc_count = 0;
			iocbp->ioc_error = 0;
			iocbp->ioc_rval = tea->TLI_error;
			if (iocbp->ioc_rval == TSYSERR)
				iocbp->ioc_rval |= tea->UNIX_error << 8;
			tp->tim_iocsave->b_datap->db_type = M_IOCACK;
			freemsg(mp);
			putnext(q, tp->tim_iocsave);
			tp->tim_iocsave = NULL;
			tp->tim_saved_prim = -1;
			tp->tim_flags &= ~(WAITIOCACK | TI_CAP_RECVD |
			    CAP_WANTS_INFO | WAIT_IOCINFOACK);
			break;
		}
	}
}

/*
 * Send reply to a usual message or ioctl message upstream.
 * Should be called from the read side only.
 */
static void
tim_send_reply(queue_t *q, mblk_t *mp, struct tim_tim *tp, t_scalar_t prim)
{
	ASSERT(mp != NULL && q != NULL && tp != NULL);
	ASSERT(q == RD(q));

	/* Restore db_type - recover() might have changed it */
	mp->b_datap->db_type = M_PCPROTO;

	if (((tp->tim_flags & WAITIOCACK) == 0) || (tp->tim_saved_prim != prim))
		putnext(q, mp);
	else {
		ASSERT(tp->tim_iocsave != NULL);
		tim_ioctl_send_reply(q, tp->tim_iocsave, mp);
		tp->tim_iocsave = NULL;
		tp->tim_saved_prim = -1;
		tp->tim_flags &= ~(WAITIOCACK | WAIT_IOCINFOACK |
		    TI_CAP_RECVD | CAP_WANTS_INFO);
	}
}

/*
 * Reply to TI_SYNC reequest without sending anything downstream.
 */
static void
tim_answer_ti_sync(queue_t *q, mblk_t *mp, struct tim_tim *tp,
    mblk_t *ackmp, uint32_t tsr_flags)
{
	struct ti_sync_ack *tsap;

	ASSERT(q != NULL && q == WR(q) && ackmp != NULL);

	tsap = (struct ti_sync_ack *)ackmp->b_rptr;
	bzero(tsap, sizeof (struct ti_sync_ack));
	ackmp->b_wptr = ackmp->b_rptr + sizeof (struct ti_sync_ack);

	if (tsr_flags == 0 ||
	    (tsr_flags & ~(TSRF_QLEN_REQ | TSRF_IS_EXP_IN_RCVBUF)) != 0) {
		/*
		 * unsupported/bad flag setting
		 * or no flag set.
		 */
		TILOG("timodwproc: unsupported/bad flag setting %x\n",
		    tsr_flags);
		freemsg(ackmp);
		miocnak(q, mp, 0, EINVAL);
		return;
	}

	if ((tsr_flags & TSRF_QLEN_REQ) != 0)
		tsap->tsa_qlen = tp->tim_backlog;

	if ((tsr_flags & TSRF_IS_EXP_IN_RCVBUF) != 0 &&
	    ti_expind_on_rdqueues(RD(q))) {
		/*
		 * Expedited data is queued on
		 * the stream read side
		 */
		tsap->tsa_flags |= TSAF_EXP_QUEUED;
	}

	tim_ioctl_send_reply(q, mp, ackmp);
	tp->tim_iocsave = NULL;
	tp->tim_saved_prim = -1;
	tp->tim_flags &= ~(WAITIOCACK | WAIT_IOCINFOACK |
	    TI_CAP_RECVD | CAP_WANTS_INFO);
}

/*
 * Send TPI message from IOCTL message, ssave original ioctl header and TPI
 * message type. Should be called from write side only.
 */
static void
tim_send_ioctl_tpi_msg(queue_t *q, mblk_t *mp, struct tim_tim *tp,
	struct iocblk *iocb)
{
	mblk_t *tmp;
	int ioc_cmd = iocb->ioc_cmd;

	ASSERT(q != NULL && mp != NULL && tp != NULL);
	ASSERT(q == WR(q));
	ASSERT(mp->b_cont != NULL);

	tp->tim_iocsave = mp;
	tmp = mp->b_cont;

	mp->b_cont = NULL;
	tp->tim_flags |= WAITIOCACK;
	tp->tim_saved_prim = ((union T_primitives *)tmp->b_rptr)->type;

	/*
	 * For TI_GETINFO, the attached message is a T_INFO_REQ
	 * For TI_SYNC, we generate the T_INFO_REQ message above
	 * For TI_CAPABILITY the attached message is either
	 * T_CAPABILITY_REQ or T_INFO_REQ.
	 * Among TPI request messages possible,
	 *	T_INFO_REQ/T_CAPABILITY_ACK messages are a M_PCPROTO, rest
	 *	are M_PROTO
	 */
	if (ioc_cmd == TI_GETINFO || ioc_cmd == TI_SYNC ||
	    ioc_cmd == TI_CAPABILITY) {
		tmp->b_datap->db_type = M_PCPROTO;
	} else {
		tmp->b_datap->db_type = M_PROTO;
	}

	/* Verify credentials in STREAM */
	ASSERT(iocb->ioc_cr == NULL || iocb->ioc_cr == DB_CRED(tmp));

	ASSERT(DB_CRED(tmp) != NULL);

	TILOG("timodwproc: sending down %d\n", tp->tim_saved_prim);
	putnext(q, tmp);
}

static void
tim_clear_peer(struct tim_tim *tp)
{
	mutex_enter(&tp->tim_mutex);
	if (tp->tim_peercred != NULL) {
		crfree(tp->tim_peercred);
		tp->tim_peercred = NULL;
	}
	tp->tim_peerlen = 0;
	mutex_exit(&tp->tim_mutex);
}
