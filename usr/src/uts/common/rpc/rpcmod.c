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
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */
/* Copyright (c) 1990 Mentat Inc. */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Kernel RPC filtering module
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <sys/tiuser.h>
#include <sys/debug.h>
#include <sys/signal.h>
#include <sys/pcb.h>
#include <sys/user.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/policy.h>
#include <sys/inline.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/file.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/t_lock.h>
#include <sys/ddi.h>
#include <sys/vtrace.h>
#include <sys/callb.h>
#include <sys/strsun.h>

#include <sys/strlog.h>
#include <rpc/rpc_com.h>
#include <inet/common.h>
#include <rpc/types.h>
#include <sys/time.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <rpc/rpc_msg.h>
#include <rpc/clnt.h>
#include <rpc/svc.h>
#include <rpc/rpcsys.h>
#include <rpc/rpc_rdma.h>

/*
 * This is the loadable module wrapper.
 */
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/syscall.h>

extern struct streamtab rpcinfo;

static struct fmodsw fsw = {
	"rpcmod",
	&rpcinfo,
	D_NEW|D_MP,
};

/*
 * Module linkage information for the kernel.
 */

static struct modlstrmod modlstrmod = {
	&mod_strmodops, "rpc interface str mod", &fsw
};

/*
 * For the RPC system call.
 */
static struct sysent rpcsysent = {
	2,
	SE_32RVAL1 | SE_ARGC | SE_NOUNLOAD,
	rpcsys
};

static struct modlsys modlsys = {
	&mod_syscallops,
	"RPC syscall",
	&rpcsysent
};

#ifdef _SYSCALL32_IMPL
static struct modlsys modlsys32 = {
	&mod_syscallops32,
	"32-bit RPC syscall",
	&rpcsysent
};
#endif /* _SYSCALL32_IMPL */

static struct modlinkage modlinkage = {
	MODREV_1,
	{
		&modlsys,
#ifdef _SYSCALL32_IMPL
		&modlsys32,
#endif
		&modlstrmod,
		NULL
	}
};

int
_init(void)
{
	int error = 0;
	callb_id_t cid;
	int status;

	svc_init();
	clnt_init();
	cid = callb_add(connmgr_cpr_reset, 0, CB_CL_CPR_RPC, "rpc");

	if (error = mod_install(&modlinkage)) {
		/*
		 * Could not install module, cleanup previous
		 * initialization work.
		 */
		clnt_fini();
		if (cid != NULL)
			(void) callb_delete(cid);

		return (error);
	}

	/*
	 * Load up the RDMA plugins and initialize the stats. Even if the
	 * plugins loadup fails, but rpcmod was successfully installed the
	 * counters still get initialized.
	 */
	rw_init(&rdma_lock, NULL, RW_DEFAULT, NULL);
	mutex_init(&rdma_modload_lock, NULL, MUTEX_DEFAULT, NULL);

	cv_init(&rdma_wait.svc_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&rdma_wait.svc_lock, NULL, MUTEX_DEFAULT, NULL);

	mt_kstat_init();

	/*
	 * Get our identification into ldi.  This is used for loading
	 * other modules, e.g. rpcib.
	 */
	status = ldi_ident_from_mod(&modlinkage, &rpcmod_li);
	if (status != 0) {
		cmn_err(CE_WARN, "ldi_ident_from_mod fails with %d", status);
		rpcmod_li = NULL;
	}

	return (error);
}

/*
 * The unload entry point fails, because we advertise entry points into
 * rpcmod from the rest of kRPC: rpcmod_release().
 */
int
_fini(void)
{
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

extern int nulldev();

#define	RPCMOD_ID	2049

int rmm_open(queue_t *, dev_t *, int, int, cred_t *);
int rmm_close(queue_t *, int, cred_t *);

/*
 * To save instructions, since STREAMS ignores the return value
 * from these functions, they are defined as void here. Kind of icky, but...
 */
void rmm_rput(queue_t *, mblk_t *);
void rmm_wput(queue_t *, mblk_t *);
void rmm_rsrv(queue_t *);
void rmm_wsrv(queue_t *);

int rpcmodopen(queue_t *, dev_t *, int, int, cred_t *);
int rpcmodclose(queue_t *, int, cred_t *);
void rpcmodrput(queue_t *, mblk_t *);
void rpcmodwput(queue_t *, mblk_t *);
void rpcmodrsrv();
void rpcmodwsrv(queue_t *);

static	void	rpcmodwput_other(queue_t *, mblk_t *);
static	int	mir_close(queue_t *q);
static	int	mir_open(queue_t *q, dev_t *devp, int flag, int sflag,
		    cred_t *credp);
static	void	mir_rput(queue_t *q, mblk_t *mp);
static	void	mir_rsrv(queue_t *q);
static	void	mir_wput(queue_t *q, mblk_t *mp);
static	void	mir_wsrv(queue_t *q);

static struct module_info rpcmod_info =
	{RPCMOD_ID, "rpcmod", 0, INFPSZ, 256*1024, 1024};

static struct qinit rpcmodrinit = {
	(int (*)())rmm_rput,
	(int (*)())rmm_rsrv,
	rmm_open,
	rmm_close,
	nulldev,
	&rpcmod_info,
	NULL
};

/*
 * The write put procedure is simply putnext to conserve stack space.
 * The write service procedure is not used to queue data, but instead to
 * synchronize with flow control.
 */
static struct qinit rpcmodwinit = {
	(int (*)())rmm_wput,
	(int (*)())rmm_wsrv,
	rmm_open,
	rmm_close,
	nulldev,
	&rpcmod_info,
	NULL
};
struct streamtab rpcinfo = { &rpcmodrinit, &rpcmodwinit, NULL, NULL };

struct xprt_style_ops {
	int (*xo_open)();
	int (*xo_close)();
	void (*xo_wput)();
	void (*xo_wsrv)();
	void (*xo_rput)();
	void (*xo_rsrv)();
};

/*
 * Read side has no service procedure.
 */
static struct xprt_style_ops xprt_clts_ops = {
	rpcmodopen,
	rpcmodclose,
	rpcmodwput,
	rpcmodwsrv,
	rpcmodrput,
	NULL
};

static struct xprt_style_ops xprt_cots_ops = {
	mir_open,
	mir_close,
	mir_wput,
	mir_wsrv,
	mir_rput,
	mir_rsrv
};

/*
 * Per rpcmod "slot" data structure. q->q_ptr points to one of these.
 */
struct rpcm {
	void		*rm_krpc_cell;	/* Reserved for use by kRPC */
	struct		xprt_style_ops	*rm_ops;
	int		rm_type;	/* Client or server side stream */
#define	RM_CLOSING	0x1		/* somebody is trying to close slot */
	uint_t		rm_state;	/* state of the slot. see above */
	uint_t		rm_ref;		/* cnt of external references to slot */
	kmutex_t	rm_lock;	/* mutex protecting above fields */
	kcondvar_t	rm_cwait;	/* condition for closing */
	zoneid_t	rm_zoneid;	/* zone which pushed rpcmod */
};

struct temp_slot {
	void *cell;
	struct xprt_style_ops *ops;
	int type;
	mblk_t *info_ack;
	kmutex_t lock;
	kcondvar_t wait;
};

typedef struct mir_s {
	void	*mir_krpc_cell;	/* Reserved for kRPC use. This field */
					/* must be first in the structure. */
	struct xprt_style_ops	*rm_ops;
	int	mir_type;		/* Client or server side stream */

	mblk_t	*mir_head_mp;		/* RPC msg in progress */
		/*
		 * mir_head_mp points the first mblk being collected in
		 * the current RPC message.  Record headers are removed
		 * before data is linked into mir_head_mp.
		 */
	mblk_t	*mir_tail_mp;		/* Last mblk in mir_head_mp */
		/*
		 * mir_tail_mp points to the last mblk in the message
		 * chain starting at mir_head_mp.  It is only valid
		 * if mir_head_mp is non-NULL and is used to add new
		 * data blocks to the end of chain quickly.
		 */

	int32_t	mir_frag_len;		/* Bytes seen in the current frag */
		/*
		 * mir_frag_len starts at -4 for beginning of each fragment.
		 * When this length is negative, it indicates the number of
		 * bytes that rpcmod needs to complete the record marker
		 * header.  When it is positive or zero, it holds the number
		 * of bytes that have arrived for the current fragment and
		 * are held in mir_header_mp.
		 */

	int32_t	mir_frag_header;
		/*
		 * Fragment header as collected for the current fragment.
		 * It holds the last-fragment indicator and the number
		 * of bytes in the fragment.
		 */

	unsigned int
		mir_ordrel_pending : 1,	/* Sent T_ORDREL_REQ */
		mir_hold_inbound : 1,	/* Hold inbound messages on server */
					/* side until outbound flow control */
					/* is relieved. */
		mir_closing : 1,	/* The stream is being closed */
		mir_inrservice : 1,	/* data queued or rd srv proc running */
		mir_inwservice : 1,	/* data queued or wr srv proc running */
		mir_inwflushdata : 1,	/* flush M_DATAs when srv runs */
		/*
		 * On client streams, mir_clntreq is 0 or 1; it is set
		 * to 1 whenever a new request is sent out (mir_wput)
		 * and cleared when the timer fires (mir_timer).  If
		 * the timer fires with this value equal to 0, then the
		 * stream is considered idle and kRPC is notified.
		 */
		mir_clntreq : 1,
		/*
		 * On server streams, stop accepting messages
		 */
		mir_svc_no_more_msgs : 1,
		mir_listen_stream : 1,	/* listen end point */
		mir_unused : 1,	/* no longer used */
		mir_timer_call : 1,
		mir_junk_fill_thru_bit_31 : 21;

	int	mir_setup_complete;	/* server has initialized everything */
	timeout_id_t mir_timer_id;	/* Timer for idle checks */
	clock_t	mir_idle_timeout;	/* Allowed idle time before shutdown */
		/*
		 * This value is copied from clnt_idle_timeout or
		 * svc_idle_timeout during the appropriate ioctl.
		 * Kept in milliseconds
		 */
	clock_t	mir_use_timestamp;	/* updated on client with each use */
		/*
		 * This value is set to lbolt
		 * every time a client stream sends or receives data.
		 * Even if the timer message arrives, we don't shutdown
		 * client unless:
		 *    lbolt >= MSEC_TO_TICK(mir_idle_timeout)+mir_use_timestamp.
		 * This value is kept in HZ.
		 */

	uint_t	*mir_max_msg_sizep;	/* Reference to sanity check size */
		/*
		 * This pointer is set to &clnt_max_msg_size or
		 * &svc_max_msg_size during the appropriate ioctl.
		 */
	zoneid_t mir_zoneid;	/* zone which pushed rpcmod */
	/* Server-side fields. */
	int	mir_ref_cnt;		/* Reference count: server side only */
					/* counts the number of references */
					/* that a kernel RPC server thread */
					/* (see svc_run()) has on this rpcmod */
					/* slot. Effectively, it is the */
					/* number of unprocessed messages */
					/* that have been passed up to the */
					/* kRPC layer */

	mblk_t	*mir_svc_pend_mp;	/* Pending T_ORDREL_IND or */
					/* T_DISCON_IND */

	/*
	 * these fields are for both client and server, but for debugging,
	 * it is easier to have these last in the structure.
	 */
	kmutex_t	mir_mutex;	/* Mutex and condvar for close */
	kcondvar_t	mir_condvar;	/* synchronization. */
	kcondvar_t	mir_timer_cv;	/* Timer routine sync. */
} mir_t;

void tmp_rput(queue_t *q, mblk_t *mp);

struct xprt_style_ops tmpops = {
	NULL,
	NULL,
	putnext,
	NULL,
	tmp_rput,
	NULL
};

void
tmp_rput(queue_t *q, mblk_t *mp)
{
	struct temp_slot *t = (struct temp_slot *)(q->q_ptr);
	struct T_info_ack *pptr;

	switch (mp->b_datap->db_type) {
	case M_PCPROTO:
		pptr = (struct T_info_ack *)mp->b_rptr;
		switch (pptr->PRIM_type) {
		case T_INFO_ACK:
			mutex_enter(&t->lock);
			t->info_ack = mp;
			cv_signal(&t->wait);
			mutex_exit(&t->lock);
			return;
		default:
			break;
		}
	default:
		break;
	}

	/*
	 * Not an info-ack, so free it. This is ok because we should
	 * not be receiving data until the open finishes: rpcmod
	 * is pushed well before the end-point is bound to an address.
	 */
	freemsg(mp);
}

int
rmm_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *crp)
{
	mblk_t *bp;
	struct temp_slot ts, *t;
	struct T_info_ack *pptr;
	int error = 0;

	ASSERT(q != NULL);
	/*
	 * Check for re-opens.
	 */
	if (q->q_ptr) {
		TRACE_1(TR_FAC_KRPC, TR_RPCMODOPEN_END,
		    "rpcmodopen_end:(%s)", "q->qptr");
		return (0);
	}

	t = &ts;
	bzero(t, sizeof (*t));
	q->q_ptr = (void *)t;
	WR(q)->q_ptr = (void *)t;

	/*
	 * Allocate the required messages upfront.
	 */
	if ((bp = allocb_cred(sizeof (struct T_info_req) +
	    sizeof (struct T_info_ack), crp, curproc->p_pid)) == NULL) {
		return (ENOBUFS);
	}

	mutex_init(&t->lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&t->wait, NULL, CV_DEFAULT, NULL);

	t->ops = &tmpops;

	qprocson(q);
	bp->b_datap->db_type = M_PCPROTO;
	*(int32_t *)bp->b_wptr = (int32_t)T_INFO_REQ;
	bp->b_wptr += sizeof (struct T_info_req);
	putnext(WR(q), bp);

	mutex_enter(&t->lock);
	while (t->info_ack == NULL) {
		if (cv_wait_sig(&t->wait, &t->lock) == 0) {
			error = EINTR;
			break;
		}
	}
	mutex_exit(&t->lock);

	if (error)
		goto out;

	pptr = (struct T_info_ack *)t->info_ack->b_rptr;

	if (pptr->SERV_type == T_CLTS) {
		if ((error = rpcmodopen(q, devp, flag, sflag, crp)) == 0)
			((struct rpcm *)q->q_ptr)->rm_ops = &xprt_clts_ops;
	} else {
		if ((error = mir_open(q, devp, flag, sflag, crp)) == 0)
			((mir_t *)q->q_ptr)->rm_ops = &xprt_cots_ops;
	}

out:
	if (error)
		qprocsoff(q);

	freemsg(t->info_ack);
	mutex_destroy(&t->lock);
	cv_destroy(&t->wait);

	return (error);
}

void
rmm_rput(queue_t *q, mblk_t  *mp)
{
	(*((struct temp_slot *)q->q_ptr)->ops->xo_rput)(q, mp);
}

void
rmm_rsrv(queue_t *q)
{
	(*((struct temp_slot *)q->q_ptr)->ops->xo_rsrv)(q);
}

void
rmm_wput(queue_t *q, mblk_t *mp)
{
	(*((struct temp_slot *)q->q_ptr)->ops->xo_wput)(q, mp);
}

void
rmm_wsrv(queue_t *q)
{
	(*((struct temp_slot *)q->q_ptr)->ops->xo_wsrv)(q);
}

int
rmm_close(queue_t *q, int flag, cred_t *crp)
{
	return ((*((struct temp_slot *)q->q_ptr)->ops->xo_close)(q, flag, crp));
}

static void rpcmod_release(queue_t *, mblk_t *, bool_t);
/*
 * rpcmodopen -	open routine gets called when the module gets pushed
 *		onto the stream.
 */
/*ARGSUSED*/
int
rpcmodopen(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *crp)
{
	struct rpcm *rmp;

	extern void (*rpc_rele)(queue_t *, mblk_t *, bool_t);

	TRACE_0(TR_FAC_KRPC, TR_RPCMODOPEN_START, "rpcmodopen_start:");

	/*
	 * Initialize entry points to release a rpcmod slot (and an input
	 * message if supplied) and to send an output message to the module
	 * below rpcmod.
	 */
	if (rpc_rele == NULL)
		rpc_rele = rpcmod_release;

	/*
	 * Only sufficiently privileged users can use this module, and it
	 * is assumed that they will use this module properly, and NOT send
	 * bulk data from downstream.
	 */
	if (secpolicy_rpcmod_open(crp) != 0)
		return (EPERM);

	/*
	 * Allocate slot data structure.
	 */
	rmp = kmem_zalloc(sizeof (*rmp), KM_SLEEP);

	mutex_init(&rmp->rm_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&rmp->rm_cwait, NULL, CV_DEFAULT, NULL);
	rmp->rm_zoneid = rpc_zoneid();
	/*
	 * slot type will be set by kRPC client and server ioctl's
	 */
	rmp->rm_type = 0;

	q->q_ptr = (void *)rmp;
	WR(q)->q_ptr = (void *)rmp;

	TRACE_1(TR_FAC_KRPC, TR_RPCMODOPEN_END, "rpcmodopen_end:(%s)", "end");
	return (0);
}

/*
 * rpcmodclose - This routine gets called when the module gets popped
 * off of the stream.
 */
/*ARGSUSED*/
int
rpcmodclose(queue_t *q, int flag, cred_t *crp)
{
	struct rpcm *rmp;

	ASSERT(q != NULL);
	rmp = (struct rpcm *)q->q_ptr;

	/*
	 * Mark our state as closing.
	 */
	mutex_enter(&rmp->rm_lock);
	rmp->rm_state |= RM_CLOSING;

	/*
	 * Check and see if there are any messages on the queue.  If so, send
	 * the messages, regardless whether the downstream module is ready to
	 * accept data.
	 */
	if (rmp->rm_type == RPC_SERVER) {
		flushq(q, FLUSHDATA);

		qenable(WR(q));

		if (rmp->rm_ref) {
			mutex_exit(&rmp->rm_lock);
			/*
			 * call into SVC to clean the queue
			 */
			svc_queueclean(q);
			mutex_enter(&rmp->rm_lock);

			/*
			 * Block while there are kRPC threads with a reference
			 * to this message.
			 */
			while (rmp->rm_ref)
				cv_wait(&rmp->rm_cwait, &rmp->rm_lock);
		}

		mutex_exit(&rmp->rm_lock);

		/*
		 * It is now safe to remove this queue from the stream. No kRPC
		 * threads have a reference to the stream, and none ever will,
		 * because RM_CLOSING is set.
		 */
		qprocsoff(q);

		/* Notify kRPC that this stream is going away. */
		svc_queueclose(q);
	} else {
		mutex_exit(&rmp->rm_lock);
		qprocsoff(q);
	}

	q->q_ptr = NULL;
	WR(q)->q_ptr = NULL;
	mutex_destroy(&rmp->rm_lock);
	cv_destroy(&rmp->rm_cwait);
	kmem_free(rmp, sizeof (*rmp));
	return (0);
}

/*
 * rpcmodrput -	Module read put procedure.  This is called from
 *		the module, driver, or stream head downstream.
 */
void
rpcmodrput(queue_t *q, mblk_t *mp)
{
	struct rpcm *rmp;
	union T_primitives *pptr;
	int hdrsz;

	TRACE_0(TR_FAC_KRPC, TR_RPCMODRPUT_START, "rpcmodrput_start:");

	ASSERT(q != NULL);
	rmp = (struct rpcm *)q->q_ptr;

	if (rmp->rm_type == 0) {
		freemsg(mp);
		return;
	}

	switch (mp->b_datap->db_type) {
	default:
		putnext(q, mp);
		break;

	case M_PROTO:
	case M_PCPROTO:
		ASSERT((mp->b_wptr - mp->b_rptr) >= sizeof (int32_t));
		pptr = (union T_primitives *)mp->b_rptr;

		/*
		 * Forward this message to kRPC if it is data.
		 */
		if (pptr->type == T_UNITDATA_IND) {
			/*
			 * Check if the module is being popped.
			 */
			mutex_enter(&rmp->rm_lock);
			if (rmp->rm_state & RM_CLOSING) {
				mutex_exit(&rmp->rm_lock);
				putnext(q, mp);
				break;
			}

			switch (rmp->rm_type) {
			case RPC_CLIENT:
				mutex_exit(&rmp->rm_lock);
				hdrsz = mp->b_wptr - mp->b_rptr;

				/*
				 * Make sure the header is sane.
				 */
				if (hdrsz < TUNITDATAINDSZ ||
				    hdrsz < (pptr->unitdata_ind.OPT_length +
				    pptr->unitdata_ind.OPT_offset) ||
				    hdrsz < (pptr->unitdata_ind.SRC_length +
				    pptr->unitdata_ind.SRC_offset)) {
					freemsg(mp);
					return;
				}

				/*
				 * Call clnt_clts_dispatch_notify, so that it
				 * can pass the message to the proper caller.
				 * Don't discard the header just yet since the
				 * client may need the sender's address.
				 */
				clnt_clts_dispatch_notify(mp, hdrsz,
				    rmp->rm_zoneid);
				return;
			case RPC_SERVER:
				/*
				 * rm_krpc_cell is exclusively used by the kRPC
				 * CLTS server. Try to submit the message to
				 * kRPC. Since this is an unreliable channel, we
				 * can just free the message in case the kRPC
				 * does not accept new messages.
				 */
				if (rmp->rm_krpc_cell &&
				    svc_queuereq(q, mp, TRUE)) {
					/*
					 * Raise the reference count on this
					 * module to prevent it from being
					 * popped before kRPC generates the
					 * reply.
					 */
					rmp->rm_ref++;
					mutex_exit(&rmp->rm_lock);
				} else {
					mutex_exit(&rmp->rm_lock);
					freemsg(mp);
				}
				return;
			default:
				mutex_exit(&rmp->rm_lock);
				freemsg(mp);
				return;
			} /* end switch(rmp->rm_type) */
		} else if (pptr->type == T_UDERROR_IND) {
			mutex_enter(&rmp->rm_lock);
			hdrsz = mp->b_wptr - mp->b_rptr;

			/*
			 * Make sure the header is sane
			 */
			if (hdrsz < TUDERRORINDSZ ||
			    hdrsz < (pptr->uderror_ind.OPT_length +
			    pptr->uderror_ind.OPT_offset) ||
			    hdrsz < (pptr->uderror_ind.DEST_length +
			    pptr->uderror_ind.DEST_offset)) {
				mutex_exit(&rmp->rm_lock);
				freemsg(mp);
				return;
			}

			/*
			 * In the case where a unit data error has been
			 * received, all we need to do is clear the message from
			 * the queue.
			 */
			mutex_exit(&rmp->rm_lock);
			freemsg(mp);
			RPCLOG(32, "rpcmodrput: unitdata error received at "
			    "%ld\n", gethrestime_sec());
			return;
		} /* end else if (pptr->type == T_UDERROR_IND) */

		putnext(q, mp);
		break;
	} /* end switch (mp->b_datap->db_type) */

	TRACE_0(TR_FAC_KRPC, TR_RPCMODRPUT_END,
	    "rpcmodrput_end:");
	/*
	 * Return codes are not looked at by the STREAMS framework.
	 */
}

/*
 * write put procedure
 */
void
rpcmodwput(queue_t *q, mblk_t *mp)
{
	struct rpcm	*rmp;

	ASSERT(q != NULL);

	switch (mp->b_datap->db_type) {
		case M_PROTO:
		case M_PCPROTO:
			break;
		default:
			rpcmodwput_other(q, mp);
			return;
	}

	/*
	 * Check to see if we can send the message downstream.
	 */
	if (canputnext(q)) {
		putnext(q, mp);
		return;
	}

	rmp = (struct rpcm *)q->q_ptr;
	ASSERT(rmp != NULL);

	/*
	 * The first canputnext failed.  Try again except this time with the
	 * lock held, so that we can check the state of the stream to see if
	 * it is closing.  If either of these conditions evaluate to true
	 * then send the meesage.
	 */
	mutex_enter(&rmp->rm_lock);
	if (canputnext(q) || (rmp->rm_state & RM_CLOSING)) {
		mutex_exit(&rmp->rm_lock);
		putnext(q, mp);
	} else {
		/*
		 * canputnext failed again and the stream is not closing.
		 * Place the message on the queue and let the service
		 * procedure handle the message.
		 */
		mutex_exit(&rmp->rm_lock);
		(void) putq(q, mp);
	}
}

static void
rpcmodwput_other(queue_t *q, mblk_t *mp)
{
	struct rpcm	*rmp;
	struct iocblk	*iocp;

	rmp = (struct rpcm *)q->q_ptr;
	ASSERT(rmp != NULL);

	switch (mp->b_datap->db_type) {
		case M_IOCTL:
			iocp = (struct iocblk *)mp->b_rptr;
			ASSERT(iocp != NULL);
			switch (iocp->ioc_cmd) {
				case RPC_CLIENT:
				case RPC_SERVER:
					mutex_enter(&rmp->rm_lock);
					rmp->rm_type = iocp->ioc_cmd;
					mutex_exit(&rmp->rm_lock);
					mp->b_datap->db_type = M_IOCACK;
					qreply(q, mp);
					return;
				default:
				/*
				 * pass the ioctl downstream and hope someone
				 * down there knows how to handle it.
				 */
					putnext(q, mp);
					return;
			}
		default:
			break;
	}
	/*
	 * This is something we definitely do not know how to handle, just
	 * pass the message downstream
	 */
	putnext(q, mp);
}

/*
 * Module write service procedure. This is called by downstream modules
 * for back enabling during flow control.
 */
void
rpcmodwsrv(queue_t *q)
{
	struct rpcm	*rmp;
	mblk_t		*mp = NULL;

	rmp = (struct rpcm *)q->q_ptr;
	ASSERT(rmp != NULL);

	/*
	 * Get messages that may be queued and send them down stream
	 */
	while ((mp = getq(q)) != NULL) {
		/*
		 * Optimize the service procedure for the server-side, by
		 * avoiding a call to canputnext().
		 */
		if (rmp->rm_type == RPC_SERVER || canputnext(q)) {
			putnext(q, mp);
			continue;
		}
		(void) putbq(q, mp);
		return;
	}
}

/* ARGSUSED */
static void
rpcmod_release(queue_t *q, mblk_t *bp, bool_t enable)
{
	struct rpcm *rmp;

	/*
	 * For now, just free the message.
	 */
	if (bp)
		freemsg(bp);
	rmp = (struct rpcm *)q->q_ptr;

	mutex_enter(&rmp->rm_lock);
	rmp->rm_ref--;

	if (rmp->rm_ref == 0 && (rmp->rm_state & RM_CLOSING)) {
		cv_broadcast(&rmp->rm_cwait);
	}

	mutex_exit(&rmp->rm_lock);
}

/*
 * This part of rpcmod is pushed on a connection-oriented transport for use
 * by RPC.  It serves to bypass the Stream head, implements
 * the record marking protocol, and dispatches incoming RPC messages.
 */

/* Default idle timer values */
#define	MIR_CLNT_IDLE_TIMEOUT	(5 * (60 * 1000L))	/* 5 minutes */
#define	MIR_SVC_IDLE_TIMEOUT	(6 * (60 * 1000L))	/* 6 minutes */
#define	MIR_SVC_ORDREL_TIMEOUT	(10 * (60 * 1000L))	/* 10 minutes */
#define	MIR_LASTFRAG	0x80000000	/* Record marker */

#define	MIR_SVC_QUIESCED(mir)	\
	(mir->mir_ref_cnt == 0 && mir->mir_inrservice == 0)

#define	MIR_CLEAR_INRSRV(mir_ptr)	{	\
	(mir_ptr)->mir_inrservice = 0;	\
	if ((mir_ptr)->mir_type == RPC_SERVER &&	\
		(mir_ptr)->mir_closing)	\
		cv_signal(&(mir_ptr)->mir_condvar);	\
}

/*
 * Don't block service procedure (and mir_close) if
 * we are in the process of closing.
 */
#define	MIR_WCANPUTNEXT(mir_ptr, write_q)	\
	(canputnext(write_q) || ((mir_ptr)->mir_svc_no_more_msgs == 1))

static int	mir_clnt_dup_request(queue_t *q, mblk_t *mp);
static void	mir_rput_proto(queue_t *q, mblk_t *mp);
static int	mir_svc_policy_notify(queue_t *q, int event);
static void	mir_svc_release(queue_t *wq, mblk_t *mp, bool_t);
static void	mir_svc_start(queue_t *wq);
static void	mir_svc_idle_start(queue_t *, mir_t *);
static void	mir_svc_idle_stop(queue_t *, mir_t *);
static void	mir_svc_start_close(queue_t *, mir_t *);
static void	mir_clnt_idle_do_stop(queue_t *);
static void	mir_clnt_idle_stop(queue_t *, mir_t *);
static void	mir_clnt_idle_start(queue_t *, mir_t *);
static void	mir_wput(queue_t *q, mblk_t *mp);
static void	mir_wput_other(queue_t *q, mblk_t *mp);
static void	mir_wsrv(queue_t *q);
static	void	mir_disconnect(queue_t *, mir_t *ir);
static	int	mir_check_len(queue_t *, mblk_t *);
static	void	mir_timer(void *);

extern void	(*mir_rele)(queue_t *, mblk_t *, bool_t);
extern void	(*mir_start)(queue_t *);
extern void	(*clnt_stop_idle)(queue_t *);

clock_t	clnt_idle_timeout = MIR_CLNT_IDLE_TIMEOUT;
clock_t	svc_idle_timeout = MIR_SVC_IDLE_TIMEOUT;

/*
 * Timeout for subsequent notifications of idle connection.  This is
 * typically used to clean up after a wedged orderly release.
 */
clock_t	svc_ordrel_timeout = MIR_SVC_ORDREL_TIMEOUT; /* milliseconds */

extern	uint_t	*clnt_max_msg_sizep;
extern	uint_t	*svc_max_msg_sizep;
uint_t	clnt_max_msg_size = RPC_MAXDATASIZE;
uint_t	svc_max_msg_size = RPC_MAXDATASIZE;
uint_t	mir_krpc_cell_null;

static void
mir_timer_stop(mir_t *mir)
{
	timeout_id_t tid;

	ASSERT(MUTEX_HELD(&mir->mir_mutex));

	/*
	 * Since the mir_mutex lock needs to be released to call
	 * untimeout(), we need to make sure that no other thread
	 * can start/stop the timer (changing mir_timer_id) during
	 * that time.  The mir_timer_call bit and the mir_timer_cv
	 * condition variable are used to synchronize this.  Setting
	 * mir_timer_call also tells mir_timer() (refer to the comments
	 * in mir_timer()) that it does not need to do anything.
	 */
	while (mir->mir_timer_call)
		cv_wait(&mir->mir_timer_cv, &mir->mir_mutex);
	mir->mir_timer_call = B_TRUE;

	if ((tid = mir->mir_timer_id) != 0) {
		mir->mir_timer_id = 0;
		mutex_exit(&mir->mir_mutex);
		(void) untimeout(tid);
		mutex_enter(&mir->mir_mutex);
	}
	mir->mir_timer_call = B_FALSE;
	cv_broadcast(&mir->mir_timer_cv);
}

static void
mir_timer_start(queue_t *q, mir_t *mir, clock_t intrvl)
{
	timeout_id_t tid;

	ASSERT(MUTEX_HELD(&mir->mir_mutex));

	while (mir->mir_timer_call)
		cv_wait(&mir->mir_timer_cv, &mir->mir_mutex);
	mir->mir_timer_call = B_TRUE;

	if ((tid = mir->mir_timer_id) != 0) {
		mutex_exit(&mir->mir_mutex);
		(void) untimeout(tid);
		mutex_enter(&mir->mir_mutex);
	}
	/* Only start the timer when it is not closing. */
	if (!mir->mir_closing) {
		mir->mir_timer_id = timeout(mir_timer, q,
		    MSEC_TO_TICK(intrvl));
	}
	mir->mir_timer_call = B_FALSE;
	cv_broadcast(&mir->mir_timer_cv);
}

static int
mir_clnt_dup_request(queue_t *q, mblk_t *mp)
{
	mblk_t  *mp1;
	uint32_t  new_xid;
	uint32_t  old_xid;

	ASSERT(MUTEX_HELD(&((mir_t *)q->q_ptr)->mir_mutex));
	new_xid = BE32_TO_U32(&mp->b_rptr[4]);
	/*
	 * This loop is a bit tacky -- it walks the STREAMS list of
	 * flow-controlled messages.
	 */
	if ((mp1 = q->q_first) != NULL) {
		do {
			old_xid = BE32_TO_U32(&mp1->b_rptr[4]);
			if (new_xid == old_xid)
				return (1);
		} while ((mp1 = mp1->b_next) != NULL);
	}
	return (0);
}

static int
mir_close(queue_t *q)
{
	mir_t	*mir = q->q_ptr;
	mblk_t	*mp;
	bool_t queue_cleaned = FALSE;

	RPCLOG(32, "rpcmod: mir_close of q 0x%p\n", (void *)q);
	ASSERT(MUTEX_NOT_HELD(&mir->mir_mutex));
	mutex_enter(&mir->mir_mutex);
	if ((mp = mir->mir_head_mp) != NULL) {
		mir->mir_head_mp = NULL;
		mir->mir_tail_mp = NULL;
		freemsg(mp);
	}
	/*
	 * Set mir_closing so we get notified when MIR_SVC_QUIESCED()
	 * is TRUE.  And mir_timer_start() won't start the timer again.
	 */
	mir->mir_closing = B_TRUE;
	mir_timer_stop(mir);

	if (mir->mir_type == RPC_SERVER) {
		flushq(q, FLUSHDATA);	/* Ditch anything waiting on read q */

		/*
		 * This will prevent more requests from arriving and
		 * will force rpcmod to ignore flow control.
		 */
		mir_svc_start_close(WR(q), mir);

		while ((!MIR_SVC_QUIESCED(mir)) || mir->mir_inwservice == 1) {

			if (mir->mir_ref_cnt && !mir->mir_inrservice &&
			    (queue_cleaned == FALSE)) {
				/*
				 * call into SVC to clean the queue
				 */
				mutex_exit(&mir->mir_mutex);
				svc_queueclean(q);
				queue_cleaned = TRUE;
				mutex_enter(&mir->mir_mutex);
				continue;
			}

			/*
			 * Bugid 1253810 - Force the write service
			 * procedure to send its messages, regardless
			 * whether the downstream  module is ready
			 * to accept data.
			 */
			if (mir->mir_inwservice == 1)
				qenable(WR(q));

			cv_wait(&mir->mir_condvar, &mir->mir_mutex);
		}

		mutex_exit(&mir->mir_mutex);
		qprocsoff(q);

		/* Notify kRPC that this stream is going away. */
		svc_queueclose(q);
	} else {
		mutex_exit(&mir->mir_mutex);
		qprocsoff(q);
	}

	mutex_destroy(&mir->mir_mutex);
	cv_destroy(&mir->mir_condvar);
	cv_destroy(&mir->mir_timer_cv);
	kmem_free(mir, sizeof (mir_t));
	return (0);
}

/*
 * This is server side only (RPC_SERVER).
 *
 * Exit idle mode.
 */
static void
mir_svc_idle_stop(queue_t *q, mir_t *mir)
{
	ASSERT(MUTEX_HELD(&mir->mir_mutex));
	ASSERT((q->q_flag & QREADR) == 0);
	ASSERT(mir->mir_type == RPC_SERVER);
	RPCLOG(16, "rpcmod: mir_svc_idle_stop of q 0x%p\n", (void *)q);

	mir_timer_stop(mir);
}

/*
 * This is server side only (RPC_SERVER).
 *
 * Start idle processing, which will include setting idle timer if the
 * stream is not being closed.
 */
static void
mir_svc_idle_start(queue_t *q, mir_t *mir)
{
	ASSERT(MUTEX_HELD(&mir->mir_mutex));
	ASSERT((q->q_flag & QREADR) == 0);
	ASSERT(mir->mir_type == RPC_SERVER);
	RPCLOG(16, "rpcmod: mir_svc_idle_start q 0x%p\n", (void *)q);

	/*
	 * Don't re-start idle timer if we are closing queues.
	 */
	if (mir->mir_closing) {
		RPCLOG(16, "mir_svc_idle_start - closing: 0x%p\n",
		    (void *)q);

		/*
		 * We will call mir_svc_idle_start() whenever MIR_SVC_QUIESCED()
		 * is true.  When it is true, and we are in the process of
		 * closing the stream, signal any thread waiting in
		 * mir_close().
		 */
		if (mir->mir_inwservice == 0)
			cv_signal(&mir->mir_condvar);

	} else {
		RPCLOG(16, "mir_svc_idle_start - reset %s timer\n",
		    mir->mir_ordrel_pending ? "ordrel" : "normal");
		/*
		 * Normal condition, start the idle timer.  If an orderly
		 * release has been sent, set the timeout to wait for the
		 * client to close its side of the connection.  Otherwise,
		 * use the normal idle timeout.
		 */
		mir_timer_start(q, mir, mir->mir_ordrel_pending ?
		    svc_ordrel_timeout : mir->mir_idle_timeout);
	}
}

/* ARGSUSED */
static int
mir_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	mir_t	*mir;

	RPCLOG(32, "rpcmod: mir_open of q 0x%p\n", (void *)q);
	/* Set variables used directly by kRPC. */
	if (!mir_rele)
		mir_rele = mir_svc_release;
	if (!mir_start)
		mir_start = mir_svc_start;
	if (!clnt_stop_idle)
		clnt_stop_idle = mir_clnt_idle_do_stop;
	if (!clnt_max_msg_sizep)
		clnt_max_msg_sizep = &clnt_max_msg_size;
	if (!svc_max_msg_sizep)
		svc_max_msg_sizep = &svc_max_msg_size;

	/* Allocate a zero'ed out mir structure for this stream. */
	mir = kmem_zalloc(sizeof (mir_t), KM_SLEEP);

	/*
	 * We set hold inbound here so that incoming messages will
	 * be held on the read-side queue until the stream is completely
	 * initialized with a RPC_CLIENT or RPC_SERVER ioctl.  During
	 * the ioctl processing, the flag is cleared and any messages that
	 * arrived between the open and the ioctl are delivered to kRPC.
	 *
	 * Early data should never arrive on a client stream since
	 * servers only respond to our requests and we do not send any.
	 * until after the stream is initialized.  Early data is
	 * very common on a server stream where the client will start
	 * sending data as soon as the connection is made (and this
	 * is especially true with TCP where the protocol accepts the
	 * connection before nfsd or kRPC is notified about it).
	 */

	mir->mir_hold_inbound = 1;

	/*
	 * Start the record marker looking for a 4-byte header.  When
	 * this length is negative, it indicates that rpcmod is looking
	 * for bytes to consume for the record marker header.  When it
	 * is positive, it holds the number of bytes that have arrived
	 * for the current fragment and are being held in mir_header_mp.
	 */

	mir->mir_frag_len = -(int32_t)sizeof (uint32_t);

	mir->mir_zoneid = rpc_zoneid();
	mutex_init(&mir->mir_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&mir->mir_condvar, NULL, CV_DRIVER, NULL);
	cv_init(&mir->mir_timer_cv, NULL, CV_DRIVER, NULL);

	q->q_ptr = (char *)mir;
	WR(q)->q_ptr = (char *)mir;

	/*
	 * We noenable the read-side queue because we don't want it
	 * automatically enabled by putq.  We enable it explicitly
	 * in mir_wsrv when appropriate. (See additional comments on
	 * flow control at the beginning of mir_rsrv.)
	 */
	noenable(q);

	qprocson(q);
	return (0);
}

/*
 * Read-side put routine for both the client and server side.  Does the
 * record marking for incoming RPC messages, and when complete, dispatches
 * the message to either the client or server.
 */
static void
mir_rput(queue_t *q, mblk_t *mp)
{
	int	excess;
	int32_t	frag_len, frag_header;
	mblk_t	*cont_mp, *head_mp, *tail_mp, *mp1;
	mir_t	*mir = q->q_ptr;
	boolean_t stop_timer = B_FALSE;

	ASSERT(mir != NULL);

	/*
	 * If the stream has not been set up as a RPC_CLIENT or RPC_SERVER
	 * with the corresponding ioctl, then don't accept
	 * any inbound data.  This should never happen for streams
	 * created by nfsd or client-side kRPC because they are careful
	 * to set the mode of the stream before doing anything else.
	 */
	if (mir->mir_type == 0) {
		freemsg(mp);
		return;
	}

	ASSERT(MUTEX_NOT_HELD(&mir->mir_mutex));

	switch (mp->b_datap->db_type) {
	case M_DATA:
		break;
	case M_PROTO:
	case M_PCPROTO:
		if (MBLKL(mp) < sizeof (t_scalar_t)) {
			RPCLOG(1, "mir_rput: runt TPI message (%d bytes)\n",
			    (int)MBLKL(mp));
			freemsg(mp);
			return;
		}
		if (((union T_primitives *)mp->b_rptr)->type != T_DATA_IND) {
			mir_rput_proto(q, mp);
			return;
		}

		/* Throw away the T_DATA_IND block and continue with data. */
		mp1 = mp;
		mp = mp->b_cont;
		freeb(mp1);
		break;
	case M_SETOPTS:
		/*
		 * If a module on the stream is trying set the Stream head's
		 * high water mark, then set our hiwater to the requested
		 * value.  We are the "stream head" for all inbound
		 * data messages since messages are passed directly to kRPC.
		 */
		if (MBLKL(mp) >= sizeof (struct stroptions)) {
			struct stroptions	*stropts;

			stropts = (struct stroptions *)mp->b_rptr;
			if ((stropts->so_flags & SO_HIWAT) &&
			    !(stropts->so_flags & SO_BAND)) {
				(void) strqset(q, QHIWAT, 0, stropts->so_hiwat);
			}
		}
		putnext(q, mp);
		return;
	case M_FLUSH:
		RPCLOG(32, "mir_rput: ignoring M_FLUSH %x ", *mp->b_rptr);
		RPCLOG(32, "on q 0x%p\n", (void *)q);
		putnext(q, mp);
		return;
	default:
		putnext(q, mp);
		return;
	}

	mutex_enter(&mir->mir_mutex);

	/*
	 * If this connection is closing, don't accept any new messages.
	 */
	if (mir->mir_svc_no_more_msgs) {
		ASSERT(mir->mir_type == RPC_SERVER);
		mutex_exit(&mir->mir_mutex);
		freemsg(mp);
		return;
	}

	/* Get local copies for quicker access. */
	frag_len = mir->mir_frag_len;
	frag_header = mir->mir_frag_header;
	head_mp = mir->mir_head_mp;
	tail_mp = mir->mir_tail_mp;

	/* Loop, processing each message block in the mp chain separately. */
	do {
		cont_mp = mp->b_cont;
		mp->b_cont = NULL;

		/*
		 * Drop zero-length mblks to prevent unbounded kernel memory
		 * consumption.
		 */
		if (MBLKL(mp) == 0) {
			freeb(mp);
			continue;
		}

		/*
		 * If frag_len is negative, we're still in the process of
		 * building frag_header -- try to complete it with this mblk.
		 */
		while (frag_len < 0 && mp->b_rptr < mp->b_wptr) {
			frag_len++;
			frag_header <<= 8;
			frag_header += *mp->b_rptr++;
		}

		if (MBLKL(mp) == 0 && frag_len < 0) {
			/*
			 * We consumed this mblk while trying to complete the
			 * fragment header.  Free it and move on.
			 */
			freeb(mp);
			continue;
		}

		ASSERT(frag_len >= 0);

		/*
		 * Now frag_header has the number of bytes in this fragment
		 * and we're just waiting to collect them all.  Chain our
		 * latest mblk onto the list and see if we now have enough
		 * bytes to complete the fragment.
		 */
		if (head_mp == NULL) {
			ASSERT(tail_mp == NULL);
			head_mp = tail_mp = mp;
		} else {
			tail_mp->b_cont = mp;
			tail_mp = mp;
		}

		frag_len += MBLKL(mp);
		excess = frag_len - (frag_header & ~MIR_LASTFRAG);
		if (excess < 0) {
			/*
			 * We still haven't received enough data to complete
			 * the fragment, so continue on to the next mblk.
			 */
			continue;
		}

		/*
		 * We've got a complete fragment.  If there are excess bytes,
		 * then they're part of the next fragment's header (of either
		 * this RPC message or the next RPC message).  Split that part
		 * into its own mblk so that we can safely freeb() it when
		 * building frag_header above.
		 */
		if (excess > 0) {
			if ((mp1 = dupb(mp)) == NULL &&
			    (mp1 = copyb(mp)) == NULL) {
				freemsg(head_mp);
				freemsg(cont_mp);
				RPCLOG0(1, "mir_rput: dupb/copyb failed\n");
				mir->mir_frag_header = 0;
				mir->mir_frag_len = -(int32_t)sizeof (uint32_t);
				mir->mir_head_mp = NULL;
				mir->mir_tail_mp = NULL;
				mir_disconnect(q, mir);	/* drops mir_mutex */
				return;
			}

			/*
			 * Relink the message chain so that the next mblk is
			 * the next fragment header, followed by the rest of
			 * the message chain.
			 */
			mp1->b_cont = cont_mp;
			cont_mp = mp1;

			/*
			 * Data in the new mblk begins at the next fragment,
			 * and data in the old mblk ends at the next fragment.
			 */
			mp1->b_rptr = mp1->b_wptr - excess;
			mp->b_wptr -= excess;
		}

		/*
		 * Reset frag_len and frag_header for the next fragment.
		 */
		frag_len = -(int32_t)sizeof (uint32_t);
		if (!(frag_header & MIR_LASTFRAG)) {
			/*
			 * The current fragment is complete, but more
			 * fragments need to be processed before we can
			 * pass along the RPC message headed at head_mp.
			 */
			frag_header = 0;
			continue;
		}
		frag_header = 0;

		/*
		 * We've got a complete RPC message; pass it to the
		 * appropriate consumer.
		 */
		switch (mir->mir_type) {
		case RPC_CLIENT:
			if (clnt_dispatch_notify(head_mp, mir->mir_zoneid)) {
				/*
				 * Mark this stream as active.  This marker
				 * is used in mir_timer().
				 */
				mir->mir_clntreq = 1;
				mir->mir_use_timestamp = ddi_get_lbolt();
			} else {
				freemsg(head_mp);
			}
			break;

		case RPC_SERVER:
			/*
			 * Check for flow control before passing the
			 * message to kRPC.
			 */
			if (!mir->mir_hold_inbound) {
				if (mir->mir_krpc_cell) {

					if (mir_check_len(q, head_mp))
						return;

					if (q->q_first == NULL &&
					    svc_queuereq(q, head_mp, TRUE)) {
						/*
						 * If the reference count is 0
						 * (not including this
						 * request), then the stream is
						 * transitioning from idle to
						 * non-idle.  In this case, we
						 * cancel the idle timer.
						 */
						if (mir->mir_ref_cnt++ == 0)
							stop_timer = B_TRUE;
					} else {
						(void) putq(q, head_mp);
						mir->mir_inrservice = B_TRUE;
					}
				} else {
					/*
					 * Count # of times this happens. Should
					 * be never, but experience shows
					 * otherwise.
					 */
					mir_krpc_cell_null++;
					freemsg(head_mp);
				}
			} else {
				/*
				 * If the outbound side of the stream is
				 * flow controlled, then hold this message
				 * until client catches up. mir_hold_inbound
				 * is set in mir_wput and cleared in mir_wsrv.
				 */
				(void) putq(q, head_mp);
				mir->mir_inrservice = B_TRUE;
			}
			break;
		default:
			RPCLOG(1, "mir_rput: unknown mir_type %d\n",
			    mir->mir_type);
			freemsg(head_mp);
			break;
		}

		/*
		 * Reset the chain since we're starting on a new RPC message.
		 */
		head_mp = tail_mp = NULL;
	} while ((mp = cont_mp) != NULL);

	/*
	 * Sanity check the message length; if it's too large mir_check_len()
	 * will shutdown the connection, drop mir_mutex, and return non-zero.
	 */
	if (head_mp != NULL && mir->mir_setup_complete &&
	    mir_check_len(q, head_mp))
		return;

	/* Save our local copies back in the mir structure. */
	mir->mir_frag_header = frag_header;
	mir->mir_frag_len = frag_len;
	mir->mir_head_mp = head_mp;
	mir->mir_tail_mp = tail_mp;

	/*
	 * The timer is stopped after the whole message chain is processed.
	 * The reason is that stopping the timer releases the mir_mutex
	 * lock temporarily.  This means that the request can be serviced
	 * while we are still processing the message chain.  This is not
	 * good.  So we stop the timer here instead.
	 *
	 * Note that if the timer fires before we stop it, it will not
	 * do any harm as MIR_SVC_QUIESCED() is false and mir_timer()
	 * will just return.
	 */
	if (stop_timer) {
		RPCLOG(16, "mir_rput: stopping idle timer on 0x%p because "
		    "ref cnt going to non zero\n", (void *)WR(q));
		mir_svc_idle_stop(WR(q), mir);
	}
	mutex_exit(&mir->mir_mutex);
}

static void
mir_rput_proto(queue_t *q, mblk_t *mp)
{
	mir_t	*mir = (mir_t *)q->q_ptr;
	uint32_t	type;
	uint32_t reason = 0;

	ASSERT(MUTEX_NOT_HELD(&mir->mir_mutex));

	type = ((union T_primitives *)mp->b_rptr)->type;
	switch (mir->mir_type) {
	case RPC_CLIENT:
		switch (type) {
		case T_DISCON_IND:
			reason = ((struct T_discon_ind *)
			    (mp->b_rptr))->DISCON_reason;
			/*FALLTHROUGH*/
		case T_ORDREL_IND:
			mutex_enter(&mir->mir_mutex);
			if (mir->mir_head_mp) {
				freemsg(mir->mir_head_mp);
				mir->mir_head_mp = (mblk_t *)0;
				mir->mir_tail_mp = (mblk_t *)0;
			}
			/*
			 * We are disconnecting, but not necessarily
			 * closing. By not closing, we will fail to
			 * pick up a possibly changed global timeout value,
			 * unless we store it now.
			 */
			mir->mir_idle_timeout = clnt_idle_timeout;
			mir_clnt_idle_stop(WR(q), mir);

			/*
			 * Even though we are unconnected, we still
			 * leave the idle timer going on the client. The
			 * reason for is that if we've disconnected due
			 * to a server-side disconnect, reset, or connection
			 * timeout, there is a possibility the client may
			 * retry the RPC request. This retry needs to done on
			 * the same bound address for the server to interpret
			 * it as such. However, we don't want
			 * to wait forever for that possibility. If the
			 * end-point stays unconnected for mir_idle_timeout
			 * units of time, then that is a signal to the
			 * connection manager to give up waiting for the
			 * application (eg. NFS) to send a retry.
			 */
			mir_clnt_idle_start(WR(q), mir);
			mutex_exit(&mir->mir_mutex);
			clnt_dispatch_notifyall(WR(q), type, reason);
			freemsg(mp);
			return;
		case T_ERROR_ACK:
		{
			struct T_error_ack	*terror;

			terror = (struct T_error_ack *)mp->b_rptr;
			RPCLOG(1, "mir_rput_proto T_ERROR_ACK for queue 0x%p",
			    (void *)q);
			RPCLOG(1, " ERROR_prim: %s,",
			    rpc_tpiprim2name(terror->ERROR_prim));
			RPCLOG(1, " TLI_error: %s,",
			    rpc_tpierr2name(terror->TLI_error));
			RPCLOG(1, " UNIX_error: %d\n", terror->UNIX_error);
			if (terror->ERROR_prim == T_DISCON_REQ)  {
				clnt_dispatch_notifyall(WR(q), type, reason);
				freemsg(mp);
				return;
			} else {
				if (clnt_dispatch_notifyconn(WR(q), mp))
					return;
			}
			break;
		}
		case T_OK_ACK:
		{
			struct T_ok_ack	*tok = (struct T_ok_ack *)mp->b_rptr;

			if (tok->CORRECT_prim == T_DISCON_REQ) {
				clnt_dispatch_notifyall(WR(q), type, reason);
				freemsg(mp);
				return;
			} else {
				if (clnt_dispatch_notifyconn(WR(q), mp))
					return;
			}
			break;
		}
		case T_CONN_CON:
		case T_INFO_ACK:
		case T_OPTMGMT_ACK:
			if (clnt_dispatch_notifyconn(WR(q), mp))
				return;
			break;
		case T_BIND_ACK:
			break;
		default:
			RPCLOG(1, "mir_rput: unexpected message %d "
			    "for kRPC client\n",
			    ((union T_primitives *)mp->b_rptr)->type);
			break;
		}
		break;

	case RPC_SERVER:
		switch (type) {
		case T_BIND_ACK:
		{
			struct T_bind_ack	*tbind;

			/*
			 * If this is a listening stream, then shut
			 * off the idle timer.
			 */
			tbind = (struct T_bind_ack *)mp->b_rptr;
			if (tbind->CONIND_number > 0) {
				mutex_enter(&mir->mir_mutex);
				mir_svc_idle_stop(WR(q), mir);

				/*
				 * mark this as a listen endpoint
				 * for special handling.
				 */

				mir->mir_listen_stream = 1;
				mutex_exit(&mir->mir_mutex);
			}
			break;
		}
		case T_DISCON_IND:
		case T_ORDREL_IND:
			RPCLOG(16, "mir_rput_proto: got %s indication\n",
			    type == T_DISCON_IND ? "disconnect"
			    : "orderly release");

			/*
			 * For listen endpoint just pass
			 * on the message.
			 */

			if (mir->mir_listen_stream)
				break;

			mutex_enter(&mir->mir_mutex);

			/*
			 * If client wants to break off connection, record
			 * that fact.
			 */
			mir_svc_start_close(WR(q), mir);

			/*
			 * If we are idle, then send the orderly release
			 * or disconnect indication to nfsd.
			 */
			if (MIR_SVC_QUIESCED(mir)) {
				mutex_exit(&mir->mir_mutex);
				break;
			}

			RPCLOG(16, "mir_rput_proto: not idle, so "
			    "disconnect/ord rel indication not passed "
			    "upstream on 0x%p\n", (void *)q);

			/*
			 * Hold the indication until we get idle
			 * If there already is an indication stored,
			 * replace it if the new one is a disconnect. The
			 * reasoning is that disconnection takes less time
			 * to process, and once a client decides to
			 * disconnect, we should do that.
			 */
			if (mir->mir_svc_pend_mp) {
				if (type == T_DISCON_IND) {
					RPCLOG(16, "mir_rput_proto: replacing"
					    " held disconnect/ord rel"
					    " indication with disconnect on"
					    " 0x%p\n", (void *)q);

					freemsg(mir->mir_svc_pend_mp);
					mir->mir_svc_pend_mp = mp;
				} else {
					RPCLOG(16, "mir_rput_proto: already "
					    "held a disconnect/ord rel "
					    "indication. freeing ord rel "
					    "ind on 0x%p\n", (void *)q);
					freemsg(mp);
				}
			} else
				mir->mir_svc_pend_mp = mp;

			mutex_exit(&mir->mir_mutex);
			return;

		default:
			/* nfsd handles server-side non-data messages. */
			break;
		}
		break;

	default:
		break;
	}

	putnext(q, mp);
}

/*
 * The server-side read queues are used to hold inbound messages while
 * outbound flow control is exerted.  When outbound flow control is
 * relieved, mir_wsrv qenables the read-side queue.  Read-side queues
 * are not enabled by STREAMS and are explicitly noenable'ed in mir_open.
 */
static void
mir_rsrv(queue_t *q)
{
	mir_t	*mir;
	mblk_t	*mp;
	boolean_t stop_timer = B_FALSE;

	mir = (mir_t *)q->q_ptr;
	mutex_enter(&mir->mir_mutex);

	mp = NULL;
	switch (mir->mir_type) {
	case RPC_SERVER:
		if (mir->mir_ref_cnt == 0)
			mir->mir_hold_inbound = 0;
		if (mir->mir_hold_inbound)
			break;

		while (mp = getq(q)) {
			if (mir->mir_krpc_cell &&
			    (mir->mir_svc_no_more_msgs == 0)) {

				if (mir_check_len(q, mp))
					return;

				if (svc_queuereq(q, mp, TRUE)) {
					/*
					 * If we were idle, turn off idle timer
					 * since we aren't idle any more.
					 */
					if (mir->mir_ref_cnt++ == 0)
						stop_timer = B_TRUE;
				} else {
					(void) putbq(q, mp);
					break;
				}
			} else {
				/*
				 * Count # of times this happens. Should be
				 * never, but experience shows otherwise.
				 */
				if (mir->mir_krpc_cell == NULL)
					mir_krpc_cell_null++;
				freemsg(mp);
			}
		}
		break;
	case RPC_CLIENT:
		break;
	default:
		RPCLOG(1, "mir_rsrv: unexpected mir_type %d\n", mir->mir_type);

		if (q->q_first == NULL)
			MIR_CLEAR_INRSRV(mir);

		mutex_exit(&mir->mir_mutex);

		return;
	}

	/*
	 * The timer is stopped after all the messages are processed.
	 * The reason is that stopping the timer releases the mir_mutex
	 * lock temporarily.  This means that the request can be serviced
	 * while we are still processing the message queue.  This is not
	 * good.  So we stop the timer here instead.
	 */
	if (stop_timer)  {
		RPCLOG(16, "mir_rsrv stopping idle timer on 0x%p because ref "
		    "cnt going to non zero\n", (void *)WR(q));
		mir_svc_idle_stop(WR(q), mir);
	}

	if (q->q_first == NULL) {
		mblk_t	*cmp = NULL;

		MIR_CLEAR_INRSRV(mir);

		if (mir->mir_type == RPC_SERVER && MIR_SVC_QUIESCED(mir)) {
			cmp = mir->mir_svc_pend_mp;
			mir->mir_svc_pend_mp = NULL;
		}

		mutex_exit(&mir->mir_mutex);

		if (cmp != NULL) {
			RPCLOG(16, "mir_rsrv: line %d: sending a held "
			    "disconnect/ord rel indication upstream\n",
			    __LINE__);
			putnext(q, cmp);
		}

		return;
	}
	mutex_exit(&mir->mir_mutex);
}

static int mir_svc_policy_fails;

/*
 * Called to send an event code to nfsd/lockd so that it initiates
 * connection close.
 */
static int
mir_svc_policy_notify(queue_t *q, int event)
{
	mblk_t	*mp;
#ifdef DEBUG
	mir_t *mir = (mir_t *)q->q_ptr;
	ASSERT(MUTEX_NOT_HELD(&mir->mir_mutex));
#endif
	ASSERT(q->q_flag & QREADR);

	/*
	 * Create an M_DATA message with the event code and pass it to the
	 * Stream head (nfsd or whoever created the stream will consume it).
	 */
	mp = allocb(sizeof (int), BPRI_HI);

	if (!mp) {

		mir_svc_policy_fails++;
		RPCLOG(16, "mir_svc_policy_notify: could not allocate event "
		    "%d\n", event);
		return (ENOMEM);
	}

	U32_TO_BE32(event, mp->b_rptr);
	mp->b_wptr = mp->b_rptr + sizeof (int);
	putnext(q, mp);
	return (0);
}

/*
 * Server side: start the close phase. We want to get this rpcmod slot in an
 * idle state before mir_close() is called.
 */
static void
mir_svc_start_close(queue_t *wq, mir_t *mir)
{
	ASSERT(MUTEX_HELD(&mir->mir_mutex));
	ASSERT((wq->q_flag & QREADR) == 0);
	ASSERT(mir->mir_type == RPC_SERVER);

	/*
	 * Do not accept any more messages.
	 */
	mir->mir_svc_no_more_msgs = 1;

	/*
	 * Next two statements will make the read service procedure
	 * free everything stuck in the streams read queue.
	 * It's not necessary because enabling the write queue will
	 * have the same effect, but why not speed the process along?
	 */
	mir->mir_hold_inbound = 0;
	qenable(RD(wq));

	/*
	 * Meanwhile force the write service procedure to send the
	 * responses downstream, regardless of flow control.
	 */
	qenable(wq);
}

/*
 * This routine is called directly by kRPC after a request is completed,
 * whether a reply was sent or the request was dropped.
 */
static void
mir_svc_release(queue_t *wq, mblk_t *mp, bool_t enable)
{
	mir_t   *mir = (mir_t *)wq->q_ptr;
	mblk_t	*cmp = NULL;

	ASSERT((wq->q_flag & QREADR) == 0);
	if (mp)
		freemsg(mp);

	if (enable)
		qenable(RD(wq));

	mutex_enter(&mir->mir_mutex);

	/*
	 * Start idle processing if this is the last reference.
	 */
	if ((mir->mir_ref_cnt == 1) && (mir->mir_inrservice == 0)) {
		cmp = mir->mir_svc_pend_mp;
		mir->mir_svc_pend_mp = NULL;
	}

	if (cmp) {
		RPCLOG(16, "mir_svc_release: sending a held "
		    "disconnect/ord rel indication upstream on queue 0x%p\n",
		    (void *)RD(wq));

		mutex_exit(&mir->mir_mutex);

		putnext(RD(wq), cmp);

		mutex_enter(&mir->mir_mutex);
	}

	/*
	 * Start idle processing if this is the last reference.
	 */
	if (mir->mir_ref_cnt == 1 && mir->mir_inrservice == 0) {

		RPCLOG(16, "mir_svc_release starting idle timer on 0x%p "
		    "because ref cnt is zero\n", (void *) wq);

		mir_svc_idle_start(wq, mir);
	}

	mir->mir_ref_cnt--;
	ASSERT(mir->mir_ref_cnt >= 0);

	/*
	 * Wake up the thread waiting to close.
	 */

	if ((mir->mir_ref_cnt == 0) && mir->mir_closing)
		cv_signal(&mir->mir_condvar);

	mutex_exit(&mir->mir_mutex);
}

/*
 * This routine is called by server-side kRPC when it is ready to
 * handle inbound messages on the stream.
 */
static void
mir_svc_start(queue_t *wq)
{
	mir_t   *mir = (mir_t *)wq->q_ptr;

	/*
	 * no longer need to take the mir_mutex because the
	 * mir_setup_complete field has been moved out of
	 * the binary field protected by the mir_mutex.
	 */

	mir->mir_setup_complete = 1;
	qenable(RD(wq));
}

/*
 * client side wrapper for stopping timer with normal idle timeout.
 */
static void
mir_clnt_idle_stop(queue_t *wq, mir_t *mir)
{
	ASSERT(MUTEX_HELD(&mir->mir_mutex));
	ASSERT((wq->q_flag & QREADR) == 0);
	ASSERT(mir->mir_type == RPC_CLIENT);

	mir_timer_stop(mir);
}

/*
 * client side wrapper for stopping timer with normal idle timeout.
 */
static void
mir_clnt_idle_start(queue_t *wq, mir_t *mir)
{
	ASSERT(MUTEX_HELD(&mir->mir_mutex));
	ASSERT((wq->q_flag & QREADR) == 0);
	ASSERT(mir->mir_type == RPC_CLIENT);

	mir_timer_start(wq, mir, mir->mir_idle_timeout);
}

/*
 * client side only. Forces rpcmod to stop sending T_ORDREL_REQs on
 * end-points that aren't connected.
 */
static void
mir_clnt_idle_do_stop(queue_t *wq)
{
	mir_t   *mir = (mir_t *)wq->q_ptr;

	RPCLOG(1, "mir_clnt_idle_do_stop: wq 0x%p\n", (void *)wq);
	ASSERT(MUTEX_NOT_HELD(&mir->mir_mutex));
	mutex_enter(&mir->mir_mutex);
	mir_clnt_idle_stop(wq, mir);
	mutex_exit(&mir->mir_mutex);
}

/*
 * Timer handler.  It handles idle timeout and memory shortage problem.
 */
static void
mir_timer(void *arg)
{
	queue_t *wq = (queue_t *)arg;
	mir_t *mir = (mir_t *)wq->q_ptr;
	boolean_t notify;
	clock_t now;

	mutex_enter(&mir->mir_mutex);

	/*
	 * mir_timer_call is set only when either mir_timer_[start|stop]
	 * is progressing.  And mir_timer() can only be run while they
	 * are progressing if the timer is being stopped.  So just
	 * return.
	 */
	if (mir->mir_timer_call) {
		mutex_exit(&mir->mir_mutex);
		return;
	}
	mir->mir_timer_id = 0;

	switch (mir->mir_type) {
	case RPC_CLIENT:

		/*
		 * For clients, the timer fires at clnt_idle_timeout
		 * intervals.  If the activity marker (mir_clntreq) is
		 * zero, then the stream has been idle since the last
		 * timer event and we notify kRPC.  If mir_clntreq is
		 * non-zero, then the stream is active and we just
		 * restart the timer for another interval.  mir_clntreq
		 * is set to 1 in mir_wput for every request passed
		 * downstream.
		 *
		 * If this was a memory shortage timer reset the idle
		 * timeout regardless; the mir_clntreq will not be a
		 * valid indicator.
		 *
		 * The timer is initially started in mir_wput during
		 * RPC_CLIENT ioctl processing.
		 *
		 * The timer interval can be changed for individual
		 * streams with the ND variable "mir_idle_timeout".
		 */
		now = ddi_get_lbolt();
		if (mir->mir_clntreq > 0 && mir->mir_use_timestamp +
		    MSEC_TO_TICK(mir->mir_idle_timeout) - now >= 0) {
			clock_t tout;

			tout = mir->mir_idle_timeout -
			    TICK_TO_MSEC(now - mir->mir_use_timestamp);
			if (tout < 0)
				tout = 1000;
#if 0
			printf("mir_timer[%d < %d + %d]: reset client timer "
			    "to %d (ms)\n", TICK_TO_MSEC(now),
			    TICK_TO_MSEC(mir->mir_use_timestamp),
			    mir->mir_idle_timeout, tout);
#endif
			mir->mir_clntreq = 0;
			mir_timer_start(wq, mir, tout);
			mutex_exit(&mir->mir_mutex);
			return;
		}
#if 0
printf("mir_timer[%d]: doing client timeout\n", now / hz);
#endif
		/*
		 * We are disconnecting, but not necessarily
		 * closing. By not closing, we will fail to
		 * pick up a possibly changed global timeout value,
		 * unless we store it now.
		 */
		mir->mir_idle_timeout = clnt_idle_timeout;
		mir_clnt_idle_start(wq, mir);

		mutex_exit(&mir->mir_mutex);
		/*
		 * We pass T_ORDREL_REQ as an integer value
		 * to kRPC as the indication that the stream
		 * is idle.  This is not a T_ORDREL_REQ message,
		 * it is just a convenient value since we call
		 * the same kRPC routine for T_ORDREL_INDs and
		 * T_DISCON_INDs.
		 */
		clnt_dispatch_notifyall(wq, T_ORDREL_REQ, 0);
		return;

	case RPC_SERVER:

		/*
		 * For servers, the timer is only running when the stream
		 * is really idle or memory is short.  The timer is started
		 * by mir_wput when mir_type is set to RPC_SERVER and
		 * by mir_svc_idle_start whenever the stream goes idle
		 * (mir_ref_cnt == 0).  The timer is cancelled in
		 * mir_rput whenever a new inbound request is passed to kRPC
		 * and the stream was previously idle.
		 *
		 * The timer interval can be changed for individual
		 * streams with the ND variable "mir_idle_timeout".
		 *
		 * If the stream is not idle do nothing.
		 */
		if (!MIR_SVC_QUIESCED(mir)) {
			mutex_exit(&mir->mir_mutex);
			return;
		}

		notify = !mir->mir_inrservice;
		mutex_exit(&mir->mir_mutex);

		/*
		 * If there is no packet queued up in read queue, the stream
		 * is really idle so notify nfsd to close it.
		 */
		if (notify) {
			RPCLOG(16, "mir_timer: telling stream head listener "
			    "to close stream (0x%p)\n", (void *) RD(wq));
			(void) mir_svc_policy_notify(RD(wq), 1);
		}
		return;
	default:
		RPCLOG(1, "mir_timer: unexpected mir_type %d\n",
		    mir->mir_type);
		mutex_exit(&mir->mir_mutex);
		return;
	}
}

/*
 * Called by the RPC package to send either a call or a return, or a
 * transport connection request.  Adds the record marking header.
 */
static void
mir_wput(queue_t *q, mblk_t *mp)
{
	uint_t	frag_header;
	mir_t	*mir = (mir_t *)q->q_ptr;
	uchar_t	*rptr = mp->b_rptr;

	if (!mir) {
		freemsg(mp);
		return;
	}

	if (mp->b_datap->db_type != M_DATA) {
		mir_wput_other(q, mp);
		return;
	}

	if (mir->mir_ordrel_pending == 1) {
		freemsg(mp);
		RPCLOG(16, "mir_wput wq 0x%p: got data after T_ORDREL_REQ\n",
		    (void *)q);
		return;
	}

	frag_header = (uint_t)DLEN(mp);
	frag_header |= MIR_LASTFRAG;

	/* Stick in the 4 byte record marking header. */
	if ((rptr - mp->b_datap->db_base) < sizeof (uint32_t) ||
	    !IS_P2ALIGNED(mp->b_rptr, sizeof (uint32_t))) {
		/*
		 * Since we know that M_DATA messages are created exclusively
		 * by kRPC, we expect that kRPC will leave room for our header
		 * and 4 byte align which is normal for XDR.
		 * If kRPC (or someone else) does not cooperate, then we
		 * just throw away the message.
		 */
		RPCLOG(1, "mir_wput: kRPC did not leave space for record "
		    "fragment header (%d bytes left)\n",
		    (int)(rptr - mp->b_datap->db_base));
		freemsg(mp);
		return;
	}
	rptr -= sizeof (uint32_t);
	*(uint32_t *)rptr = htonl(frag_header);
	mp->b_rptr = rptr;

	mutex_enter(&mir->mir_mutex);
	if (mir->mir_type == RPC_CLIENT) {
		/*
		 * For the client, set mir_clntreq to indicate that the
		 * connection is active.
		 */
		mir->mir_clntreq = 1;
		mir->mir_use_timestamp = ddi_get_lbolt();
	}

	/*
	 * If we haven't already queued some data and the downstream module
	 * can accept more data, send it on, otherwise we queue the message
	 * and take other actions depending on mir_type.
	 */
	if (!mir->mir_inwservice && MIR_WCANPUTNEXT(mir, q)) {
		mutex_exit(&mir->mir_mutex);

		/*
		 * Now we pass the RPC message downstream.
		 */
		putnext(q, mp);
		return;
	}

	switch (mir->mir_type) {
	case RPC_CLIENT:
		/*
		 * Check for a previous duplicate request on the
		 * queue.  If there is one, then we throw away
		 * the current message and let the previous one
		 * go through.  If we can't find a duplicate, then
		 * send this one.  This tap dance is an effort
		 * to reduce traffic and processing requirements
		 * under load conditions.
		 */
		if (mir_clnt_dup_request(q, mp)) {
			mutex_exit(&mir->mir_mutex);
			freemsg(mp);
			return;
		}
		break;
	case RPC_SERVER:
		/*
		 * Set mir_hold_inbound so that new inbound RPC
		 * messages will be held until the client catches
		 * up on the earlier replies.  This flag is cleared
		 * in mir_wsrv after flow control is relieved;
		 * the read-side queue is also enabled at that time.
		 */
		mir->mir_hold_inbound = 1;
		break;
	default:
		RPCLOG(1, "mir_wput: unexpected mir_type %d\n", mir->mir_type);
		break;
	}
	mir->mir_inwservice = 1;
	(void) putq(q, mp);
	mutex_exit(&mir->mir_mutex);
}

static void
mir_wput_other(queue_t *q, mblk_t *mp)
{
	mir_t	*mir = (mir_t *)q->q_ptr;
	struct iocblk	*iocp;
	uchar_t	*rptr = mp->b_rptr;
	bool_t	flush_in_svc = FALSE;

	ASSERT(MUTEX_NOT_HELD(&mir->mir_mutex));
	switch (mp->b_datap->db_type) {
	case M_IOCTL:
		iocp = (struct iocblk *)rptr;
		switch (iocp->ioc_cmd) {
		case RPC_CLIENT:
			mutex_enter(&mir->mir_mutex);
			if (mir->mir_type != 0 &&
			    mir->mir_type != iocp->ioc_cmd) {
ioc_eperm:
				mutex_exit(&mir->mir_mutex);
				iocp->ioc_error = EPERM;
				iocp->ioc_count = 0;
				mp->b_datap->db_type = M_IOCACK;
				qreply(q, mp);
				return;
			}

			mir->mir_type = iocp->ioc_cmd;

			/*
			 * Clear mir_hold_inbound which was set to 1 by
			 * mir_open.  This flag is not used on client
			 * streams.
			 */
			mir->mir_hold_inbound = 0;
			mir->mir_max_msg_sizep = &clnt_max_msg_size;

			/*
			 * Start the idle timer.  See mir_timer() for more
			 * information on how client timers work.
			 */
			mir->mir_idle_timeout = clnt_idle_timeout;
			mir_clnt_idle_start(q, mir);
			mutex_exit(&mir->mir_mutex);

			mp->b_datap->db_type = M_IOCACK;
			qreply(q, mp);
			return;
		case RPC_SERVER:
			mutex_enter(&mir->mir_mutex);
			if (mir->mir_type != 0 &&
			    mir->mir_type != iocp->ioc_cmd)
				goto ioc_eperm;

			/*
			 * We don't clear mir_hold_inbound here because
			 * mir_hold_inbound is used in the flow control
			 * model. If we cleared it here, then we'd commit
			 * a small violation to the model where the transport
			 * might immediately block downstream flow.
			 */

			mir->mir_type = iocp->ioc_cmd;
			mir->mir_max_msg_sizep = &svc_max_msg_size;

			/*
			 * Start the idle timer.  See mir_timer() for more
			 * information on how server timers work.
			 *
			 * Note that it is important to start the idle timer
			 * here so that connections time out even if we
			 * never receive any data on them.
			 */
			mir->mir_idle_timeout = svc_idle_timeout;
			RPCLOG(16, "mir_wput_other starting idle timer on 0x%p "
			    "because we got RPC_SERVER ioctl\n", (void *)q);
			mir_svc_idle_start(q, mir);
			mutex_exit(&mir->mir_mutex);

			mp->b_datap->db_type = M_IOCACK;
			qreply(q, mp);
			return;
		default:
			break;
		}
		break;

	case M_PROTO:
		if (mir->mir_type == RPC_CLIENT) {
			/*
			 * We are likely being called from the context of a
			 * service procedure. So we need to enqueue. However
			 * enqueing may put our message behind data messages.
			 * So flush the data first.
			 */
			flush_in_svc = TRUE;
		}
		if ((mp->b_wptr - rptr) < sizeof (uint32_t) ||
		    !IS_P2ALIGNED(rptr, sizeof (uint32_t)))
			break;

		switch (((union T_primitives *)rptr)->type) {
		case T_DATA_REQ:
			/* Don't pass T_DATA_REQ messages downstream. */
			freemsg(mp);
			return;
		case T_ORDREL_REQ:
			RPCLOG(8, "mir_wput_other wq 0x%p: got T_ORDREL_REQ\n",
			    (void *)q);
			mutex_enter(&mir->mir_mutex);
			if (mir->mir_type != RPC_SERVER) {
				/*
				 * We are likely being called from
				 * clnt_dispatch_notifyall(). Sending
				 * a T_ORDREL_REQ will result in
				 * a some kind of _IND message being sent,
				 * will be another call to
				 * clnt_dispatch_notifyall(). To keep the stack
				 * lean, queue this message.
				 */
				mir->mir_inwservice = 1;
				(void) putq(q, mp);
				mutex_exit(&mir->mir_mutex);
				return;
			}

			/*
			 * Mark the structure such that we don't accept any
			 * more requests from client. We could defer this
			 * until we actually send the orderly release
			 * request downstream, but all that does is delay
			 * the closing of this stream.
			 */
			RPCLOG(16, "mir_wput_other wq 0x%p: got T_ORDREL_REQ "
			    " so calling mir_svc_start_close\n", (void *)q);

			mir_svc_start_close(q, mir);

			/*
			 * If we have sent down a T_ORDREL_REQ, don't send
			 * any more.
			 */
			if (mir->mir_ordrel_pending) {
				freemsg(mp);
				mutex_exit(&mir->mir_mutex);
				return;
			}

			/*
			 * If the stream is not idle, then we hold the
			 * orderly release until it becomes idle.  This
			 * ensures that kRPC will be able to reply to
			 * all requests that we have passed to it.
			 *
			 * We also queue the request if there is data already
			 * queued, because we cannot allow the T_ORDREL_REQ
			 * to go before data. When we had a separate reply
			 * count, this was not a problem, because the
			 * reply count was reconciled when mir_wsrv()
			 * completed.
			 */
			if (!MIR_SVC_QUIESCED(mir) ||
			    mir->mir_inwservice == 1) {
				mir->mir_inwservice = 1;
				(void) putq(q, mp);

				RPCLOG(16, "mir_wput_other: queuing "
				    "T_ORDREL_REQ on 0x%p\n", (void *)q);

				mutex_exit(&mir->mir_mutex);
				return;
			}

			/*
			 * Mark the structure so that we know we sent
			 * an orderly release request, and reset the idle timer.
			 */
			mir->mir_ordrel_pending = 1;

			RPCLOG(16, "mir_wput_other: calling mir_svc_idle_start"
			    " on 0x%p because we got T_ORDREL_REQ\n",
			    (void *)q);

			mir_svc_idle_start(q, mir);
			mutex_exit(&mir->mir_mutex);

			/*
			 * When we break, we will putnext the T_ORDREL_REQ.
			 */
			break;

		case T_CONN_REQ:
			mutex_enter(&mir->mir_mutex);
			if (mir->mir_head_mp != NULL) {
				freemsg(mir->mir_head_mp);
				mir->mir_head_mp = NULL;
				mir->mir_tail_mp = NULL;
			}
			mir->mir_frag_len = -(int32_t)sizeof (uint32_t);
			/*
			 * Restart timer in case mir_clnt_idle_do_stop() was
			 * called.
			 */
			mir->mir_idle_timeout = clnt_idle_timeout;
			mir_clnt_idle_stop(q, mir);
			mir_clnt_idle_start(q, mir);
			mutex_exit(&mir->mir_mutex);
			break;

		default:
			/*
			 * T_DISCON_REQ is one of the interesting default
			 * cases here. Ideally, an M_FLUSH is done before
			 * T_DISCON_REQ is done. However, that is somewhat
			 * cumbersome for clnt_cots.c to do. So we queue
			 * T_DISCON_REQ, and let the service procedure
			 * flush all M_DATA.
			 */
			break;
		}
		/* fallthru */;
	default:
		if (mp->b_datap->db_type >= QPCTL) {
			if (mp->b_datap->db_type == M_FLUSH) {
				if (mir->mir_type == RPC_CLIENT &&
				    *mp->b_rptr & FLUSHW) {
					RPCLOG(32, "mir_wput_other: flushing "
					    "wq 0x%p\n", (void *)q);
					if (*mp->b_rptr & FLUSHBAND) {
						flushband(q, *(mp->b_rptr + 1),
						    FLUSHDATA);
					} else {
						flushq(q, FLUSHDATA);
					}
				} else {
					RPCLOG(32, "mir_wput_other: ignoring "
					    "M_FLUSH on wq 0x%p\n", (void *)q);
				}
			}
			break;
		}

		mutex_enter(&mir->mir_mutex);
		if (mir->mir_inwservice == 0 && MIR_WCANPUTNEXT(mir, q)) {
			mutex_exit(&mir->mir_mutex);
			break;
		}
		mir->mir_inwservice = 1;
		mir->mir_inwflushdata = flush_in_svc;
		(void) putq(q, mp);
		mutex_exit(&mir->mir_mutex);
		qenable(q);

		return;
	}
	putnext(q, mp);
}

static void
mir_wsrv(queue_t *q)
{
	mblk_t	*mp;
	mir_t	*mir;
	bool_t flushdata;

	mir = (mir_t *)q->q_ptr;
	mutex_enter(&mir->mir_mutex);

	flushdata = mir->mir_inwflushdata;
	mir->mir_inwflushdata = 0;

	while (mp = getq(q)) {
		if (mp->b_datap->db_type == M_DATA) {
			/*
			 * Do not send any more data if we have sent
			 * a T_ORDREL_REQ.
			 */
			if (flushdata || mir->mir_ordrel_pending == 1) {
				freemsg(mp);
				continue;
			}

			/*
			 * Make sure that the stream can really handle more
			 * data.
			 */
			if (!MIR_WCANPUTNEXT(mir, q)) {
				(void) putbq(q, mp);
				mutex_exit(&mir->mir_mutex);
				return;
			}

			/*
			 * Now we pass the RPC message downstream.
			 */
			mutex_exit(&mir->mir_mutex);
			putnext(q, mp);
			mutex_enter(&mir->mir_mutex);
			continue;
		}

		/*
		 * This is not an RPC message, pass it downstream
		 * (ignoring flow control) if the server side is not sending a
		 * T_ORDREL_REQ downstream.
		 */
		if (mir->mir_type != RPC_SERVER ||
		    ((union T_primitives *)mp->b_rptr)->type !=
		    T_ORDREL_REQ) {
			mutex_exit(&mir->mir_mutex);
			putnext(q, mp);
			mutex_enter(&mir->mir_mutex);
			continue;
		}

		if (mir->mir_ordrel_pending == 1) {
			/*
			 * Don't send two T_ORDRELs
			 */
			freemsg(mp);
			continue;
		}

		/*
		 * Mark the structure so that we know we sent an orderly
		 * release request.  We will check to see slot is idle at the
		 * end of this routine, and if so, reset the idle timer to
		 * handle orderly release timeouts.
		 */
		mir->mir_ordrel_pending = 1;
		RPCLOG(16, "mir_wsrv: sending ordrel req on q 0x%p\n",
		    (void *)q);
		/*
		 * Send the orderly release downstream. If there are other
		 * pending replies we won't be able to send them.  However,
		 * the only reason we should send the orderly release is if
		 * we were idle, or if an unusual event occurred.
		 */
		mutex_exit(&mir->mir_mutex);
		putnext(q, mp);
		mutex_enter(&mir->mir_mutex);
	}

	if (q->q_first == NULL)
		/*
		 * If we call mir_svc_idle_start() below, then
		 * clearing mir_inwservice here will also result in
		 * any thread waiting in mir_close() to be signaled.
		 */
		mir->mir_inwservice = 0;

	if (mir->mir_type != RPC_SERVER) {
		mutex_exit(&mir->mir_mutex);
		return;
	}

	/*
	 * If idle we call mir_svc_idle_start to start the timer (or wakeup
	 * a close). Also make sure not to start the idle timer on the
	 * listener stream. This can cause nfsd to send an orderly release
	 * command on the listener stream.
	 */
	if (MIR_SVC_QUIESCED(mir) && !(mir->mir_listen_stream)) {
		RPCLOG(16, "mir_wsrv: calling mir_svc_idle_start on 0x%p "
		    "because mir slot is idle\n", (void *)q);
		mir_svc_idle_start(q, mir);
	}

	/*
	 * If outbound flow control has been relieved, then allow new
	 * inbound requests to be processed.
	 */
	if (mir->mir_hold_inbound) {
		mir->mir_hold_inbound = 0;
		qenable(RD(q));
	}
	mutex_exit(&mir->mir_mutex);
}

static void
mir_disconnect(queue_t *q, mir_t *mir)
{
	ASSERT(MUTEX_HELD(&mir->mir_mutex));

	switch (mir->mir_type) {
	case RPC_CLIENT:
		/*
		 * We are disconnecting, but not necessarily
		 * closing. By not closing, we will fail to
		 * pick up a possibly changed global timeout value,
		 * unless we store it now.
		 */
		mir->mir_idle_timeout = clnt_idle_timeout;
		mir_clnt_idle_start(WR(q), mir);
		mutex_exit(&mir->mir_mutex);

		/*
		 * T_DISCON_REQ is passed to kRPC as an integer value
		 * (this is not a TPI message).  It is used as a
		 * convenient value to indicate a sanity check
		 * failure -- the same kRPC routine is also called
		 * for T_DISCON_INDs and T_ORDREL_INDs.
		 */
		clnt_dispatch_notifyall(WR(q), T_DISCON_REQ, 0);
		break;

	case RPC_SERVER:
		mir->mir_svc_no_more_msgs = 1;
		mir_svc_idle_stop(WR(q), mir);
		mutex_exit(&mir->mir_mutex);
		RPCLOG(16, "mir_disconnect: telling "
		    "stream head listener to disconnect stream "
		    "(0x%p)\n", (void *) q);
		(void) mir_svc_policy_notify(q, 2);
		break;

	default:
		mutex_exit(&mir->mir_mutex);
		break;
	}
}

/*
 * Sanity check the message length, and if it's too large, shutdown the
 * connection.  Returns 1 if the connection is shutdown; 0 otherwise.
 */
static int
mir_check_len(queue_t *q, mblk_t *head_mp)
{
	mir_t *mir = q->q_ptr;
	uint_t maxsize = 0;
	size_t msg_len = msgdsize(head_mp);

	if (mir->mir_max_msg_sizep != NULL)
		maxsize = *mir->mir_max_msg_sizep;

	if (maxsize == 0 || msg_len <= maxsize)
		return (0);

	freemsg(head_mp);
	mir->mir_head_mp = NULL;
	mir->mir_tail_mp = NULL;
	mir->mir_frag_header = 0;
	mir->mir_frag_len = -(int32_t)sizeof (uint32_t);
	if (mir->mir_type != RPC_SERVER || mir->mir_setup_complete) {
		cmn_err(CE_NOTE,
		    "kRPC: record fragment from %s of size(%lu) exceeds "
		    "maximum (%u). Disconnecting",
		    (mir->mir_type == RPC_CLIENT) ? "server" :
		    (mir->mir_type == RPC_SERVER) ? "client" :
		    "test tool", msg_len, maxsize);
	}

	mir_disconnect(q, mir);
	return (1);
}
