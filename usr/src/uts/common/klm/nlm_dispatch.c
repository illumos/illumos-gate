/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy is of the CDDL is also available via the Internet
 * at http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * NFS Lock Manager, server-side dispatch tables and
 * dispatch programs: nlm_prog_3, nlm_prog4
 *
 * These are called by RPC framework after the RPC service
 * endpoints setup done in nlm_impl.c: nlm_svc_add_ep().
 *
 * Originally from rpcgen, then reduced.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sdt.h>
#include <rpcsvc/nlm_prot.h>
#include "nlm_impl.h"

/*
 * Dispatch entry function pointers.
 */
typedef bool_t (*nlm_svc_func_t)(void *, void *, struct svc_req *);
typedef void (*nlm_freeres_func_t)(void *);

/*
 * Entries in the dispatch tables below.
 */
struct dispatch_entry {
	nlm_svc_func_t		de_svc;		/* service routine function */
	xdrproc_t		de_xargs;	/* XDR args decode function */
	xdrproc_t		de_xres;	/* XDR res encode function */
	nlm_freeres_func_t	de_resfree;	/* free res function */
	int			de_ressz;	/* size of result */
	uint_t			de_flags;	/* flags */
};

/* Flag bits in de_flags */
#define	NLM_DISP_NOREMOTE	1	/* Local calls only */

/*
 * Cast macros for dispatch table function pointers.
 */
#define	NLM_SVC_FUNC(func)	(nlm_svc_func_t)func
#define	NLM_FREERES_FUNC(func)	(nlm_freeres_func_t)func

/* ARGSUSED */
static bool_t
nlm_null_svc(void *args, void *resp, struct svc_req *sr)
{
	return (TRUE);
}

/*
 * The common NLM service dispatch function, used by
 * both: nlm_prog_3, nlm_prog_4
 */
void
nlm_dispatch(
	struct svc_req *rqstp,
	SVCXPRT *transp,
	const struct dispatch_entry *de)
{
	union {
		/* All the arg types */
		nlm_cancargs	au_cancargs;
		nlm_lockargs	au_lockargs;
		nlm_notify	au_notify;
		nlm_res		au_res;
		nlm_shareargs	au_shareargs;
		nlm_sm_status	au_sm_status;
		nlm_testargs	au_testargs;
		nlm_testres	au_testres;
		nlm_unlockargs	au_unlockargs;
		nlm4_cancargs	au_cancargs4;
		nlm4_lockargs	au_lockargs4;
		nlm4_notify	au_notify4;
		nlm4_res	au_res4;
		nlm4_shareargs	au_shareargs4;
		nlm4_testargs	au_testargs4;
		nlm4_testres	au_testres4;
		nlm4_unlockargs	au_unlockargs4;
	} argu;
	void *args = &argu;
	union {
		/* All the ret types */
		int		ru_int;
		nlm_res		ru_res;
		nlm_shareres	ru_shareres;
		nlm_testres	ru_testres;
		nlm4_res	ru_res4;
		nlm4_shareres	ru_shareres4;
		nlm4_testres	ru_testres4;

	} resu;
	void *res = &resu;
	nlm_svc_func_t func;
	bool_t do_reply = FALSE;
	bool_t dupcached = FALSE;
	struct dupreq *dr;
	int dupstat;

	if ((func = de->de_svc) == NULL) {
		svcerr_noproc(transp);
		return;
	}

	if ((de->de_flags & NLM_DISP_NOREMOTE) &&
	    !nlm_caller_is_local(transp)) {
		svcerr_noproc(transp);
		return;
	}

	/*
	 * This section from rpcgen, and then modified slightly.
	 *
	 * Dispatch entries that should _never_ send a response
	 * (i.e. all the _MSG and _RES entries) put NULL in the
	 * de_xres field to indicate that.  For such entries, we
	 * will NOT call svc_sendreply nor xdr_free().  Normal
	 * dispatch entries skip svc_sendreply if the dispatch
	 * function returns zero, but always call xdr_free().
	 *
	 * There are more complex cases where some dispatch
	 * functions need to send their own reply.  We chose
	 * to indicate those by returning false from the
	 * service routine.
	 */
	bzero(&argu, sizeof (argu));
	if (!SVC_GETARGS(transp, de->de_xargs, args)) {
		svcerr_decode(transp);
		return;
	}

	/*
	 * Duplicate request cache.
	 *
	 * Since none of the NLM replies are very large we have simplified the
	 * DRC by not distinguishing between idempotent and non-idempotent
	 * requests.
	 */
	dupstat = SVC_DUP_EXT(transp, rqstp, res, de->de_ressz, &dr,
	    &dupcached);

	switch (dupstat) {
	case DUP_ERROR:
		svcerr_systemerr(transp);
		break;
	case DUP_INPROGRESS:
		break;
	case DUP_NEW:
	case DUP_DROP:
		/*
		 * When UFS is quiescing it uses lockfs to block vnode
		 * operations until it has finished quiescing.  Set the
		 * thread's T_DONTPEND flag to prevent the service routine
		 * from blocking due to a lockfs lock. (See ufs_check_lockfs)
		 */
		curthread->t_flag |= T_DONTPEND;

		bzero(&resu, sizeof (resu));
		do_reply = (*func)(args, res, rqstp);

		curthread->t_flag &= ~T_DONTPEND;
		if (curthread->t_flag & T_WOULDBLOCK) {
			curthread->t_flag &= ~T_WOULDBLOCK;
			SVC_DUPDONE_EXT(transp, dr, res, NULL,
			    de->de_ressz, DUP_DROP);
			do_reply = FALSE;
			break;
		}
		SVC_DUPDONE_EXT(transp, dr, res, de->de_resfree,
		    de->de_ressz, DUP_DONE);
		dupcached = TRUE;
		break;
	case DUP_DONE:
		/*
		 * The service routine may have been responsible for sending
		 * the reply for the original request but for a re-xmitted
		 * request we don't invoke the service routine so we must
		 * re-xmit the reply from the dispatch function.
		 *
		 * If de_xres is NULL this is a one-way message so no reply is
		 * needed.
		 */
		if (de->de_xres != NULL_xdrproc_t) {
			do_reply = TRUE;
		}
		break;
	}

	if (do_reply) {
		ASSERT(de->de_xres != NULL_xdrproc_t);
		DTRACE_PROBE3(sendreply, struct svc_req *, rqstp,
		    SVCXPRT *, transp, struct dispatch_entry *, de);

		if (!svc_sendreply(transp, de->de_xres, res)) {
			svcerr_systemerr(transp);
			NLM_ERR("nlm_dispatch(): svc_sendreply() failed!\n");
		}

		if (!dupcached) {
			xdr_free(de->de_xres, res);
		}
	}

	if (!SVC_FREEARGS(transp, de->de_xargs, args))
		NLM_WARN("nlm_dispatch(): unable to free arguments");
}

/*
 * Result free functions.  The functions are called by the RPC duplicate
 * request cache code when an entry is being evicted from the cache.
 */
static void
nlm_res_free(nlm_res *resp)
{
	xdr_free(xdr_nlm_res, (char *)resp);
}

static void
nlm_shareres_free(nlm_shareres *resp)
{
	xdr_free(xdr_nlm_shareres, (char *)resp);
}

static void
nlm_testres_free(nlm_testres *resp)
{
	xdr_free(xdr_nlm_testres, (char *)resp);
}

static void
nlm4_res_free(nlm4_res *resp)
{
	xdr_free(xdr_nlm4_res, (char *)resp);
}

static void
nlm4_shareres_free(nlm4_shareres *resp)
{
	xdr_free(xdr_nlm4_shareres, (char *)resp);
}

static void
nlm4_testres_free(nlm4_testres *resp)
{
	xdr_free(xdr_nlm4_testres, (char *)resp);
}

/*
 * Dispatch tables for each program version.
 *
 * The tables here were all originally from rpcgen,
 * but then arg/resp sizes removed, flags added.
 */

/*
 * Dispatch table for versions 1, 2, 3
 * (NLM_VERS, NLM_SM, NLM_VERSX)
 */
static const struct dispatch_entry
nlm_prog_3_dtable[] = {

	/*
	 * Version 1 (NLM_VERS) entries.
	 */

	{ /* 0: NULLPROC */
	NLM_SVC_FUNC(nlm_null_svc),
	(xdrproc_t)xdr_void,
	(xdrproc_t)xdr_void,
	NULL,
	0,
	0 },

	{ /* 1: NLM_TEST */
	NLM_SVC_FUNC(nlm_test_1_svc),
	(xdrproc_t)xdr_nlm_testargs,
	(xdrproc_t)xdr_nlm_testres,
	NLM_FREERES_FUNC(nlm_testres_free),
	sizeof (nlm_testres),
	0 },

	{ /* 2: NLM_LOCK */
	NLM_SVC_FUNC(nlm_lock_1_svc),
	(xdrproc_t)xdr_nlm_lockargs,
	(xdrproc_t)xdr_nlm_res,
	NLM_FREERES_FUNC(nlm_res_free),
	sizeof (nlm_res),
	0 },

	{ /* 3: NLM_CANCEL */
	NLM_SVC_FUNC(nlm_cancel_1_svc),
	(xdrproc_t)xdr_nlm_cancargs,
	(xdrproc_t)xdr_nlm_res,
	NLM_FREERES_FUNC(nlm_res_free),
	sizeof (nlm_res),
	0 },

	{ /* 4: NLM_UNLOCK */
	NLM_SVC_FUNC(nlm_unlock_1_svc),
	(xdrproc_t)xdr_nlm_unlockargs,
	(xdrproc_t)xdr_nlm_res,
	NLM_FREERES_FUNC(nlm_res_free),
	sizeof (nlm_res),
	0 },

	{ /* 5: NLM_GRANTED */
	NLM_SVC_FUNC(nlm_granted_1_svc),
	(xdrproc_t)xdr_nlm_testargs,
	(xdrproc_t)xdr_nlm_res,
	NLM_FREERES_FUNC(nlm_res_free),
	sizeof (nlm_res),
	0 },

	/*
	 * All the _MSG and _RES entries are "one way" calls that
	 * skip the usual RPC reply.  We give them a null xdr_res
	 * function so the dispatcher will not send a reply.
	 */

	{ /* 6: NLM_TEST_MSG */
	NLM_SVC_FUNC(nlm_test_msg_1_svc),
	(xdrproc_t)xdr_nlm_testargs,
	(xdrproc_t)0,
	NULL,
	0,
	0 },

	{ /* 7: NLM_LOCK_MSG */
	NLM_SVC_FUNC(nlm_lock_msg_1_svc),
	(xdrproc_t)xdr_nlm_lockargs,
	(xdrproc_t)0,
	NULL,
	0,
	0 },

	{ /* 8: NLM_CANCEL_MSG */
	NLM_SVC_FUNC(nlm_cancel_msg_1_svc),
	(xdrproc_t)xdr_nlm_cancargs,
	(xdrproc_t)0,
	NULL,
	0,
	0 },

	{ /* 9: NLM_UNLOCK_MSG */
	NLM_SVC_FUNC(nlm_unlock_msg_1_svc),
	(xdrproc_t)xdr_nlm_unlockargs,
	(xdrproc_t)0,
	NULL,
	0,
	0 },

	{ /* 10: NLM_GRANTED_MSG */
	NLM_SVC_FUNC(nlm_granted_msg_1_svc),
	(xdrproc_t)xdr_nlm_testargs,
	(xdrproc_t)0,
	NULL,
	0,
	0 },

	{ /* 11: NLM_TEST_RES */
	NLM_SVC_FUNC(nlm_test_res_1_svc),
	(xdrproc_t)xdr_nlm_testres,
	(xdrproc_t)0,
	NULL,
	0,
	0 },

	{ /* 12: NLM_LOCK_RES */
	NLM_SVC_FUNC(nlm_lock_res_1_svc),
	(xdrproc_t)xdr_nlm_res,
	(xdrproc_t)0,
	NULL,
	0,
	0 },

	{ /* 13: NLM_CANCEL_RES */
	NLM_SVC_FUNC(nlm_cancel_res_1_svc),
	(xdrproc_t)xdr_nlm_res,
	(xdrproc_t)0,
	NULL,
	0,
	0 },

	{ /* 14: NLM_UNLOCK_RES */
	NLM_SVC_FUNC(nlm_unlock_res_1_svc),
	(xdrproc_t)xdr_nlm_res,
	(xdrproc_t)0,
	NULL,
	0,
	0 },

	{ /* 15: NLM_GRANTED_RES */
	NLM_SVC_FUNC(nlm_granted_res_1_svc),
	(xdrproc_t)xdr_nlm_res,
	(xdrproc_t)0,
	NULL,
	0,
	0 },

	{ /* 16: not used */
	NLM_SVC_FUNC(0),
	(xdrproc_t)0,
	(xdrproc_t)0,
	NULL,
	0,
	0 },

	{ /* 17: NLM_SM_NOTIFY1 */
	NLM_SVC_FUNC(nlm_sm_notify1_2_svc),
	(xdrproc_t)xdr_nlm_sm_status,
	(xdrproc_t)xdr_void,
	NULL,
	0,
	NLM_DISP_NOREMOTE },

	{ /* 18: NLM_SM_NOTIFY2 */
	NLM_SVC_FUNC(nlm_sm_notify2_2_svc),
	(xdrproc_t)xdr_nlm_sm_status,
	(xdrproc_t)xdr_void,
	NULL,
	0,
	NLM_DISP_NOREMOTE },

	/*
	 * Version 3 (NLM_VERSX) entries.
	 */

	{ /* 19: not used */
	NLM_SVC_FUNC(0),
	(xdrproc_t)0,
	(xdrproc_t)0,
	NULL,
	0,
	0 },

	{ /* 20: NLM_SHARE */
	NLM_SVC_FUNC(nlm_share_3_svc),
	(xdrproc_t)xdr_nlm_shareargs,
	(xdrproc_t)xdr_nlm_shareres,
	NLM_FREERES_FUNC(nlm_shareres_free),
	sizeof (nlm_shareres),
	0 },

	{ /* 21: NLM_UNSHARE */
	NLM_SVC_FUNC(nlm_unshare_3_svc),
	(xdrproc_t)xdr_nlm_shareargs,
	(xdrproc_t)xdr_nlm_shareres,
	NLM_FREERES_FUNC(nlm_shareres_free),
	sizeof (nlm_shareres),
	0 },

	{ /* 22: NLM_NM_LOCK */
	NLM_SVC_FUNC(nlm_nm_lock_3_svc),
	(xdrproc_t)xdr_nlm_lockargs,
	(xdrproc_t)xdr_nlm_res,
	NLM_FREERES_FUNC(nlm_res_free),
	sizeof (nlm_res),
	0 },

	{ /* 23: NLM_FREE_ALL */
	NLM_SVC_FUNC(nlm_free_all_3_svc),
	(xdrproc_t)xdr_nlm_notify,
	(xdrproc_t)xdr_void,
	NULL,
	0,
	0 },
};
static int nlm_prog_3_dtsize =
	sizeof (nlm_prog_3_dtable) /
	sizeof (nlm_prog_3_dtable[0]);

/*
 * RPC dispatch function for nlm_prot versions: 1,2,3
 */
void
nlm_prog_3(struct svc_req *rqstp, register SVCXPRT *transp)
{
	const struct dispatch_entry *de;
	rpcproc_t max_proc;

	switch (rqstp->rq_vers) {
	case NLM_VERS:
		max_proc = NLM_GRANTED_RES;
		break;
	case NLM_SM:
		max_proc = NLM_SM_NOTIFY2;
		break;
	case NLM_VERSX:
		max_proc = NLM_FREE_ALL;
		break;
	default:
		/* Our svc registration should prevent this. */
		ASSERT(0); /* paranoid */
		svcerr_noprog(transp);
		return;
	}
	ASSERT(max_proc < nlm_prog_3_dtsize);

	if (rqstp->rq_proc > max_proc) {
		svcerr_noproc(transp);
		return;
	}

	de = &nlm_prog_3_dtable[rqstp->rq_proc];

	nlm_dispatch(rqstp, transp, de);
}

/*
 * Dispatch table for version 4 (NLM4_VERS)
 */
static const struct dispatch_entry
nlm_prog_4_dtable[] = {

	{ /* 0: NULLPROC */
	NLM_SVC_FUNC(nlm_null_svc),
	(xdrproc_t)xdr_void,
	(xdrproc_t)xdr_void,
	NULL,
	0,
	0 },

	{ /* 1: NLM4_TEST */
	NLM_SVC_FUNC(nlm4_test_4_svc),
	(xdrproc_t)xdr_nlm4_testargs,
	(xdrproc_t)xdr_nlm4_testres,
	NLM_FREERES_FUNC(nlm4_testres_free),
	sizeof (nlm4_testres),
	0 },

	{ /* 2: NLM4_LOCK */
	NLM_SVC_FUNC(nlm4_lock_4_svc),
	(xdrproc_t)xdr_nlm4_lockargs,
	(xdrproc_t)xdr_nlm4_res,
	NLM_FREERES_FUNC(nlm4_res_free),
	sizeof (nlm4_res),
	0 },

	{ /* 3: NLM4_CANCEL */
	NLM_SVC_FUNC(nlm4_cancel_4_svc),
	(xdrproc_t)xdr_nlm4_cancargs,
	(xdrproc_t)xdr_nlm4_res,
	NLM_FREERES_FUNC(nlm4_res_free),
	sizeof (nlm4_res),
	0 },

	{ /* 4: NLM4_UNLOCK */
	NLM_SVC_FUNC(nlm4_unlock_4_svc),
	(xdrproc_t)xdr_nlm4_unlockargs,
	(xdrproc_t)xdr_nlm4_res,
	NLM_FREERES_FUNC(nlm4_res_free),
	sizeof (nlm4_res),
	0 },

	{ /* 5: NLM4_GRANTED */
	NLM_SVC_FUNC(nlm4_granted_4_svc),
	(xdrproc_t)xdr_nlm4_testargs,
	(xdrproc_t)xdr_nlm4_res,
	NLM_FREERES_FUNC(nlm4_res_free),
	sizeof (nlm4_res),
	0 },

	/*
	 * All the _MSG and _RES entries are "one way" calls that
	 * skip the usual RPC reply.  We give them a null xdr_res
	 * function so the dispatcher will not send a reply.
	 */

	{ /* 6: NLM4_TEST_MSG */
	NLM_SVC_FUNC(nlm4_test_msg_4_svc),
	(xdrproc_t)xdr_nlm4_testargs,
	(xdrproc_t)0,
	NULL,
	0,
	0 },

	{ /* 7: NLM4_LOCK_MSG */
	NLM_SVC_FUNC(nlm4_lock_msg_4_svc),
	(xdrproc_t)xdr_nlm4_lockargs,
	(xdrproc_t)0,
	NULL,
	0,
	0 },

	{ /* 8: NLM4_CANCEL_MSG */
	NLM_SVC_FUNC(nlm4_cancel_msg_4_svc),
	(xdrproc_t)xdr_nlm4_cancargs,
	(xdrproc_t)0,
	NULL,
	0,
	0 },

	{ /* 9: NLM4_UNLOCK_MSG */
	NLM_SVC_FUNC(nlm4_unlock_msg_4_svc),
	(xdrproc_t)xdr_nlm4_unlockargs,
	(xdrproc_t)0,
	NULL,
	0,
	0 },

	{ /* 10: NLM4_GRANTED_MSG */
	NLM_SVC_FUNC(nlm4_granted_msg_4_svc),
	(xdrproc_t)xdr_nlm4_testargs,
	(xdrproc_t)0,
	NULL,
	0,
	0 },

	{ /* 11: NLM4_TEST_RES */
	NLM_SVC_FUNC(nlm4_test_res_4_svc),
	(xdrproc_t)xdr_nlm4_testres,
	(xdrproc_t)0,
	NULL,
	0,
	0 },

	{ /* 12: NLM4_LOCK_RES */
	NLM_SVC_FUNC(nlm4_lock_res_4_svc),
	(xdrproc_t)xdr_nlm4_res,
	(xdrproc_t)0,
	NULL,
	0,
	0 },

	{ /* 13: NLM4_CANCEL_RES */
	NLM_SVC_FUNC(nlm4_cancel_res_4_svc),
	(xdrproc_t)xdr_nlm4_res,
	(xdrproc_t)0,
	NULL,
	0,
	0 },

	{ /* 14: NLM4_UNLOCK_RES */
	NLM_SVC_FUNC(nlm4_unlock_res_4_svc),
	(xdrproc_t)xdr_nlm4_res,
	(xdrproc_t)0,
	NULL,
	0,
	0 },

	{ /* 15: NLM4_GRANTED_RES */
	NLM_SVC_FUNC(nlm4_granted_res_4_svc),
	(xdrproc_t)xdr_nlm4_res,
	(xdrproc_t)0,
	NULL,
	0,
	0 },

	{ /* 16: not used */
	NLM_SVC_FUNC(0),
	(xdrproc_t)0,
	(xdrproc_t)0,
	NULL,
	0,
	0 },

	{ /* 17: NLM_SM_NOTIFY1 (not in v4) */
	NLM_SVC_FUNC(0),
	(xdrproc_t)0,
	(xdrproc_t)0,
	NULL,
	0,
	0 },

	{ /* 18: NLM_SM_NOTIFY2 (not in v4) */
	NLM_SVC_FUNC(0),
	(xdrproc_t)0,
	(xdrproc_t)0,
	NULL,
	0,
	0 },

	{ /* 19: not used */
	NLM_SVC_FUNC(0),
	(xdrproc_t)0,
	(xdrproc_t)0,
	NULL,
	0,
	0 },

	{ /* 20: NLM4_SHARE */
	NLM_SVC_FUNC(nlm4_share_4_svc),
	(xdrproc_t)xdr_nlm4_shareargs,
	(xdrproc_t)xdr_nlm4_shareres,
	NLM_FREERES_FUNC(nlm4_shareres_free),
	sizeof (nlm4_shareres),
	0 },

	{ /* 21: NLM4_UNSHARE */
	NLM_SVC_FUNC(nlm4_unshare_4_svc),
	(xdrproc_t)xdr_nlm4_shareargs,
	(xdrproc_t)xdr_nlm4_shareres,
	NLM_FREERES_FUNC(nlm4_shareres_free),
	sizeof (nlm4_shareres),
	0 },

	{ /* 22: NLM4_NM_LOCK */
	NLM_SVC_FUNC(nlm4_nm_lock_4_svc),
	(xdrproc_t)xdr_nlm4_lockargs,
	(xdrproc_t)xdr_nlm4_res,
	NLM_FREERES_FUNC(nlm4_res_free),
	sizeof (nlm4_res),
	0 },

	{ /* 23: NLM4_FREE_ALL */
	NLM_SVC_FUNC(nlm4_free_all_4_svc),
	(xdrproc_t)xdr_nlm4_notify,
	(xdrproc_t)xdr_void,
	NULL,
	0,
	0 },
};
static int nlm_prog_4_dtsize =
	sizeof (nlm_prog_4_dtable) /
	sizeof (nlm_prog_4_dtable[0]);

/*
 * RPC dispatch function for nlm_prot version 4.
 */
void
nlm_prog_4(struct svc_req *rqstp, register SVCXPRT *transp)
{
	const struct dispatch_entry *de;

	if (rqstp->rq_vers != NLM4_VERS) {
		/* Our svc registration should prevent this. */
		ASSERT(0); /* paranoid */
		svcerr_noprog(transp);
		return;
	}

	if (rqstp->rq_proc >= nlm_prog_4_dtsize) {
		svcerr_noproc(transp);
		return;
	}

	de = &nlm_prog_4_dtable[rqstp->rq_proc];

	nlm_dispatch(rqstp, transp, de);
}
