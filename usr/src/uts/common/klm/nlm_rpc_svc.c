/*
 * Copyright (c) 2008 Isilon Inc http://www.isilon.com/
 * Authors: Doug Rabson <dfr@rabson.org>
 * Developed with Red Inc: Alfred Perlstein <alfred@freebsd.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2012 by Delphix. All rights reserved.
 */

/*
 * NFS Lock Manager, RPC service functions (nlm_..._svc)
 * Called via nlm_dispatch.c tables.
 *
 * Source code derived from FreeBSD nlm_prot_server.c
 *
 * The real service functions all use nlm4_... args and return
 * data types.  These wrappers convert older forms to and from
 * the new forms and call the nlm_do_... service functions.
 */

#include <sys/param.h>
#include <sys/systm.h>

#include <rpcsvc/nlm_prot.h>
#include "nlm_impl.h"

/*
 * Convert between various versions of the protocol structures.
 */

/*
 * Down-convert, for granted_1 call
 *
 * This converts a 64-bit lock to 32-bit form for our granted
 * call-back when we're dealing with a 32-bit NLM client.
 * Our NLM_LOCK handler ensures that any lock we grant to a
 * 32-bit client can be represented in 32-bits.  If the
 * ASSERTs here fire, then the call to nlm_init_flock in
 * nlm_do_lock has failed to restrict a 32-bit client to
 * 32-bit lock ranges.
 */
static void
nlm_convert_to_nlm_lock(struct nlm_lock *dst, struct nlm4_lock *src)
{
	dst->caller_name = src->caller_name;
	dst->fh = src->fh;
	dst->oh = src->oh;
	dst->svid = src->svid;
	ASSERT(src->l_offset <= MAX_UOFF32);
	dst->l_offset = (uint32_t)src->l_offset;
	ASSERT(src->l_len <= MAX_UOFF32);
	dst->l_len = (uint32_t)src->l_len;
}

/*
 * Up-convert for v1 svc functions with a 32-bit lock range arg.
 * Note that lock range checks (like overflow) are done later,
 * in nlm_init_flock().
 */
static void
nlm_convert_to_nlm4_lock(struct nlm4_lock *dst, struct nlm_lock *src)
{

	dst->caller_name = src->caller_name;
	dst->fh = src->fh;
	dst->oh = src->oh;
	dst->svid = src->svid;
	dst->l_offset = src->l_offset;
	dst->l_len = src->l_len;
}

static void
nlm_convert_to_nlm4_share(struct nlm4_share *dst, struct nlm_share *src)
{

	dst->caller_name = src->caller_name;
	dst->fh = src->fh;
	dst->oh = src->oh;
	dst->mode = src->mode;
	dst->access = src->access;
}

/*
 * Down-convert for v1 NLM_TEST or NLM_TEST_MSG response.
 * Note that nlm_do_test is careful to give us lock ranges
 * that can be represented with 32-bit values.  If the
 * ASSERTs here fire, then the code in nlm_do_test that
 * builds an nlm4_holder for a 32-bit client has failed to
 * restrict the reported conflicting lock range so it's a
 * valid 32-bit lock range.
 */
static void
nlm_convert_to_nlm_holder(struct nlm_holder *dst, struct nlm4_holder *src)
{
	dst->exclusive = src->exclusive;
	dst->svid = src->svid;
	dst->oh = src->oh;
	ASSERT(src->l_offset <= MAX_UOFF32);
	dst->l_offset = (uint32_t)src->l_offset;
	ASSERT(src->l_len <= MAX_UOFF32);
	dst->l_len = (uint32_t)src->l_len;
}

static enum nlm_stats
nlm_convert_to_nlm_stats(enum nlm4_stats src)
{
	if (src > nlm4_deadlck)
		return (nlm_denied);
	return ((enum nlm_stats)src);
}

static void
nlm_convert_to_nlm_res(struct nlm_res *dst, struct nlm4_res *src)
{
	dst->cookie = src->cookie;
	dst->stat.stat = nlm_convert_to_nlm_stats(src->stat.stat);
}

/* ******************************************************************** */

/*
 * Version 1 svc functions
 */

bool_t
nlm_test_1_svc(struct nlm_testargs *argp, nlm_testres *resp,
    struct svc_req *sr)
{
	nlm4_testargs args4;
	nlm4_testres res4;

	bzero(&args4, sizeof (args4));
	bzero(&res4, sizeof (res4));

	args4.cookie = argp->cookie;
	args4.exclusive = argp->exclusive;
	nlm_convert_to_nlm4_lock(&args4.alock, &argp->alock);

	nlm_do_test(&args4, &res4, sr, NULL);

	resp->cookie = res4.cookie;
	resp->stat.stat = nlm_convert_to_nlm_stats(res4.stat.stat);
	if (resp->stat.stat == nlm_denied)
		nlm_convert_to_nlm_holder(
		    &resp->stat.nlm_testrply_u.holder,
		    &res4.stat.nlm4_testrply_u.holder);

	return (TRUE);
}

/*
 * Callback functions for nlm_lock_1_svc
 */
static bool_t nlm_lock_1_reply(SVCXPRT *, nlm4_res *);
static enum clnt_stat nlm_granted_1_cb(nlm4_testargs *, void *, CLIENT *);

bool_t
nlm_lock_1_svc(nlm_lockargs *argp, nlm_res *resp,
    struct svc_req *sr)
{
	nlm4_lockargs args4;
	nlm4_res res4;

	bzero(&res4, sizeof (res4));

	args4.cookie = argp->cookie;
	args4.block = argp->block;
	args4.exclusive = argp->exclusive;
	nlm_convert_to_nlm4_lock(&args4.alock, &argp->alock);
	args4.reclaim = argp->reclaim;
	args4.state = argp->state;

	/* NLM_LOCK */
	nlm_do_lock(&args4, &res4, sr,
	    nlm_lock_1_reply, NULL,
	    nlm_granted_1_cb);

	/* for freeresult */
	nlm_convert_to_nlm_res(resp, &res4);

	/* above does its own reply */
	return (FALSE);
}

static bool_t
nlm_lock_1_reply(SVCXPRT *transp, nlm4_res *resp)
{
	nlm_res res1;

	nlm_convert_to_nlm_res(&res1, resp);
	return (svc_sendreply(transp, xdr_nlm_res, (char *)&res1));
}

static enum clnt_stat
nlm_granted_1_cb(nlm4_testargs *argp, void *resp, CLIENT *clnt)
{
	nlm_testargs args1;
	nlm_res res1;
	int rv;

	bzero(&res1, sizeof (res1));

	args1.cookie = argp->cookie;
	args1.exclusive = argp->exclusive;
	nlm_convert_to_nlm_lock(&args1.alock, &argp->alock);

	rv = nlm_granted_1(&args1, &res1, clnt);

	/* NB: We have a result our caller will not free. */
	xdr_free((xdrproc_t)xdr_nlm_res, (void *)&res1);
	(void) resp;

	return (rv);
}

bool_t
nlm_cancel_1_svc(struct nlm_cancargs *argp, nlm_res *resp,
    struct svc_req *sr)
{
	nlm4_cancargs args4;
	nlm4_res res4;

	bzero(&res4, sizeof (res4));

	args4.cookie = argp->cookie;
	args4.block = argp->block;
	args4.exclusive = argp->exclusive;
	nlm_convert_to_nlm4_lock(&args4.alock, &argp->alock);

	nlm_do_cancel(&args4, &res4, sr, NULL);

	nlm_convert_to_nlm_res(resp, &res4);

	return (TRUE);
}

bool_t
nlm_unlock_1_svc(struct nlm_unlockargs *argp, nlm_res *resp,
    struct svc_req *sr)
{
	nlm4_unlockargs args4;
	nlm4_res res4;

	bzero(&res4, sizeof (res4));

	args4.cookie = argp->cookie;
	nlm_convert_to_nlm4_lock(&args4.alock, &argp->alock);

	nlm_do_unlock(&args4, &res4, sr, NULL);

	nlm_convert_to_nlm_res(resp, &res4);

	return (TRUE);
}

bool_t
nlm_granted_1_svc(struct nlm_testargs *argp, nlm_res *resp,
    struct svc_req *sr)
{
	nlm4_testargs args4;
	nlm4_res res4;

	bzero(&res4, sizeof (res4));

	args4.cookie = argp->cookie;
	args4.exclusive = argp->exclusive;
	nlm_convert_to_nlm4_lock(&args4.alock, &argp->alock);

	nlm_do_granted(&args4, &res4, sr, NULL);

	nlm_convert_to_nlm_res(resp, &res4);

	return (TRUE);
}

/*
 * The _msg_ calls get no reply.  Instead, these callers
 * expect an RPC call to the corresponding _res function.
 * We pass this callback function to nlm_do_test so it will
 * use it to do the RPC callback, with the correct res type.
 *
 * The callback functions have nearly the same arg signature
 * as the client call functions so that many of those can be
 * optimized to nothing by the compiler.  Also, passing the
 * null result arg for these just to reduce warnings.
 *
 * See similar callbacks for other _msg functions below.
 */

static enum clnt_stat nlm_test_res_1_cb(nlm4_testres *, void *, CLIENT *);

bool_t
nlm_test_msg_1_svc(struct nlm_testargs *argp, void *resp,
    struct svc_req *sr)
{
	nlm4_testargs args4;
	nlm4_testres res4;

	bzero(&res4, sizeof (res4));

	args4.cookie = argp->cookie;
	args4.exclusive = argp->exclusive;
	nlm_convert_to_nlm4_lock(&args4.alock, &argp->alock);

	nlm_do_test(&args4, &res4, sr,
	    nlm_test_res_1_cb);

	/* NB: We have a result our caller will not free. */
	xdr_free((xdrproc_t)xdr_nlm4_testres, (void *)&res4);
	(void) resp;

	/* The _msg_ calls get no reply. */
	return (FALSE);
}

static enum clnt_stat
nlm_test_res_1_cb(nlm4_testres *res4, void *null, CLIENT *clnt)
{
	nlm_testres res1;

	res1.cookie = res4->cookie;
	res1.stat.stat = nlm_convert_to_nlm_stats(res4->stat.stat);
	if (res1.stat.stat == nlm_denied)
		nlm_convert_to_nlm_holder(
		    &res1.stat.nlm_testrply_u.holder,
		    &res4->stat.nlm4_testrply_u.holder);

	return (nlm_test_res_1(&res1, null, clnt));
}

/*
 * Callback functions for nlm_lock_msg_1_svc
 */
static enum clnt_stat nlm_lock_res_1_cb(nlm4_res *, void *, CLIENT *);
static enum clnt_stat nlm_granted_msg_1_cb(nlm4_testargs *, void *, CLIENT *);

bool_t
nlm_lock_msg_1_svc(nlm_lockargs *argp, void *resp,
    struct svc_req *sr)
{
	nlm4_lockargs args4;
	nlm4_res res4;

	bzero(&res4, sizeof (res4));

	args4.cookie = argp->cookie;
	args4.block = argp->block;
	args4.exclusive = argp->exclusive;
	nlm_convert_to_nlm4_lock(&args4.alock, &argp->alock);
	args4.reclaim = argp->reclaim;
	args4.state = argp->state;

	/* NLM_LOCK_MSG */
	nlm_do_lock(&args4, &res4, sr,
	    NULL, nlm_lock_res_1_cb,
	    nlm_granted_msg_1_cb);

	/* NB: We have a result our caller will not free. */
	xdr_free((xdrproc_t)xdr_nlm4_res, (void *)&res4);
	(void) resp;

	/* The _msg_ calls get no reply. */
	return (FALSE);
}

static enum clnt_stat
nlm_lock_res_1_cb(nlm4_res *resp, void *null, CLIENT *clnt)
{
	nlm_res res1;

	nlm_convert_to_nlm_res(&res1, resp);
	return (nlm_lock_res_1(&res1, null, clnt));
}

static enum clnt_stat
nlm_granted_msg_1_cb(nlm4_testargs *argp, void *null, CLIENT *clnt)
{
	nlm_testargs args1;

	args1.cookie = argp->cookie;
	args1.exclusive = argp->exclusive;
	nlm_convert_to_nlm_lock(&args1.alock, &argp->alock);

	return (nlm_granted_msg_1(&args1, null, clnt));

}


static enum clnt_stat nlm_cancel_res_1_cb(nlm4_res *, void *, CLIENT *);

bool_t
nlm_cancel_msg_1_svc(struct nlm_cancargs *argp, void *resp,
    struct svc_req *sr)
{
	nlm4_cancargs args4;
	nlm4_res res4;

	bzero(&res4, sizeof (res4));

	args4.cookie = argp->cookie;
	args4.block = argp->block;
	args4.exclusive = argp->exclusive;
	nlm_convert_to_nlm4_lock(&args4.alock, &argp->alock);

	nlm_do_cancel(&args4, &res4, sr,
	    nlm_cancel_res_1_cb);

	/* NB: We have a result our caller will not free. */
	xdr_free((xdrproc_t)xdr_nlm4_res, (void *)&res4);
	(void) resp;

	/* The _msg_ calls get no reply. */
	return (FALSE);
}

static enum clnt_stat
nlm_cancel_res_1_cb(nlm4_res *res4, void *null, CLIENT *clnt)
{
	nlm_res res1;

	nlm_convert_to_nlm_res(&res1, res4);
	return (nlm_cancel_res_1(&res1, null, clnt));
}


static enum clnt_stat nlm_unlock_res_1_cb(nlm4_res *, void *, CLIENT *);

bool_t
nlm_unlock_msg_1_svc(struct nlm_unlockargs *argp, void *resp,
    struct svc_req *sr)
{
	nlm4_unlockargs args4;
	nlm4_res res4;

	bzero(&res4, sizeof (res4));

	args4.cookie = argp->cookie;
	nlm_convert_to_nlm4_lock(&args4.alock, &argp->alock);

	nlm_do_unlock(&args4, &res4, sr,
	    nlm_unlock_res_1_cb);

	/* NB: We have a result our caller will not free. */
	xdr_free((xdrproc_t)xdr_nlm4_res, (void *)&res4);
	(void) resp;

	/* The _msg_ calls get no reply. */
	return (FALSE);
}

static enum clnt_stat
nlm_unlock_res_1_cb(nlm4_res *res4, void *null, CLIENT *clnt)
{
	nlm_res res1;

	nlm_convert_to_nlm_res(&res1, res4);
	return (nlm_unlock_res_1(&res1, null, clnt));
}


static enum clnt_stat nlm_granted_res_1_cb(nlm4_res *, void *, CLIENT *);

bool_t
nlm_granted_msg_1_svc(struct nlm_testargs *argp, void *resp,
    struct svc_req *sr)
{
	nlm4_testargs args4;
	nlm4_res res4;

	bzero(&res4, sizeof (res4));

	args4.cookie = argp->cookie;
	args4.exclusive = argp->exclusive;
	nlm_convert_to_nlm4_lock(&args4.alock, &argp->alock);

	nlm_do_granted(&args4, &res4, sr,
	    nlm_granted_res_1_cb);

	/* NB: We have a result our caller will not free. */
	xdr_free((xdrproc_t)xdr_nlm4_res, (void *)&res4);
	(void) resp;

	/* The _msg_ calls get no reply. */
	return (FALSE);
}

static enum clnt_stat
nlm_granted_res_1_cb(nlm4_res *res4, void *null, CLIENT *clnt)
{
	nlm_res res1;

	nlm_convert_to_nlm_res(&res1, res4);
	return (nlm_granted_res_1(&res1, null, clnt));
}

/*
 * The _res_ calls get no reply.  These RPC calls are
 * "call backs" in response to RPC _msg_ calls.
 * We don't care about these responses.
 */

/* ARGSUSED */
bool_t
nlm_test_res_1_svc(nlm_testres *argp, void *resp, struct svc_req *sr)
{
	/* The _res_ calls get no reply. */
	return (FALSE);
}

/* ARGSUSED */
bool_t
nlm_lock_res_1_svc(nlm_res *argp, void *resp, struct svc_req *sr)
{
	/* The _res_ calls get no reply. */
	return (FALSE);
}

/* ARGSUSED */
bool_t
nlm_cancel_res_1_svc(nlm_res *argp, void *resp, struct svc_req *sr)
{
	/* The _res_ calls get no reply. */
	return (FALSE);
}

/* ARGSUSED */
bool_t
nlm_unlock_res_1_svc(nlm_res *argp, void *resp, struct svc_req *sr)
{
	/* The _res_ calls get no reply. */
	return (FALSE);
}

/* ARGSUSED */
bool_t
nlm_granted_res_1_svc(nlm_res *argp, void *resp, struct svc_req *sr)
{
	/* The _res_ calls get no reply. */
	return (FALSE);
}

/*
 * Version 2 svc functions (used by local statd)
 */

bool_t
nlm_sm_notify1_2_svc(struct nlm_sm_status *argp, void *resp,
    struct svc_req *sr)
{
	nlm_do_notify1(argp, resp, sr);
	return (TRUE);
}

bool_t
nlm_sm_notify2_2_svc(struct nlm_sm_status *argp, void *resp,
    struct svc_req *sr)
{
	nlm_do_notify2(argp, resp, sr);
	return (TRUE);
}

/*
 * Version 3 svc functions
 */

bool_t
nlm_share_3_svc(nlm_shareargs *argp, nlm_shareres *resp,
    struct svc_req *sr)
{
	nlm4_shareargs args4;
	nlm4_shareres res4;

	bzero(&res4, sizeof (res4));

	args4.cookie = argp->cookie;
	nlm_convert_to_nlm4_share(&args4.share, &argp->share);
	args4.reclaim = argp->reclaim;

	nlm_do_share(&args4, &res4, sr);

	resp->cookie = res4.cookie;
	resp->stat = nlm_convert_to_nlm_stats(res4.stat);
	resp->sequence = res4.sequence;

	return (TRUE);
}

bool_t
nlm_unshare_3_svc(nlm_shareargs *argp, nlm_shareres *resp,
    struct svc_req *sr)
{
	nlm4_shareargs args4;
	nlm4_shareres res4;

	bzero(&res4, sizeof (res4));

	args4.cookie = argp->cookie;
	nlm_convert_to_nlm4_share(&args4.share, &argp->share);
	args4.reclaim = argp->reclaim;

	nlm_do_unshare(&args4, &res4, sr);

	resp->cookie = res4.cookie;
	resp->stat = nlm_convert_to_nlm_stats(res4.stat);
	resp->sequence = res4.sequence;

	return (TRUE);
}

bool_t
nlm_nm_lock_3_svc(nlm_lockargs *argp, nlm_res *resp, struct svc_req *sr)
{
	nlm4_lockargs args4;
	nlm4_res res4;

	bzero(&res4, sizeof (res4));

	args4.cookie = argp->cookie;
	args4.block = argp->block;
	args4.exclusive = argp->exclusive;
	nlm_convert_to_nlm4_lock(&args4.alock, &argp->alock);
	args4.reclaim = argp->reclaim;
	args4.state = argp->state;

	/*
	 * Don't allow blocking for non-monitored (nm_lock) calls.
	 * These clients don't handle any callbacks, including
	 * the granted call we make after a blocking lock.
	 * Same reply callback as nlm_lock_1_svc
	 */
	args4.block = FALSE;

	/* NLM_NM_LOCK */
	nlm_do_lock(&args4, &res4, sr,
	    nlm_lock_1_reply, NULL,
	    NULL); /* indicates non-monitored */

	/* for freeresult */
	nlm_convert_to_nlm_res(resp, &res4);

	/* above does its own reply */
	return (FALSE);
}

bool_t
nlm_free_all_3_svc(nlm_notify *argp, void *resp, struct svc_req *sr)
{
	struct nlm4_notify args4;

	args4.name = argp->name;
	args4.state = argp->state;

	nlm_do_free_all(&args4, resp, sr);

	return (TRUE);
}

/*
 * Version 4 svc functions
 */

bool_t
nlm4_test_4_svc(nlm4_testargs *argp, nlm4_testres *resp, struct svc_req *sr)
{
	nlm_do_test(argp, resp, sr, NULL);
	return (TRUE);
}

/*
 * Callback functions for nlm4_lock_4_svc
 */
static bool_t nlm4_lock_4_reply(SVCXPRT *, nlm4_res *);
static enum clnt_stat nlm4_granted_4_cb(nlm4_testargs *, void *, CLIENT *);

bool_t
nlm4_lock_4_svc(nlm4_lockargs *argp, nlm4_res *resp,
    struct svc_req *sr)
{

	/* NLM4_LOCK */
	nlm_do_lock(argp, resp, sr,
	    nlm4_lock_4_reply, NULL,
	    nlm4_granted_4_cb);

	/* above does its own reply */
	return (FALSE);
}

static bool_t
nlm4_lock_4_reply(SVCXPRT *transp, nlm4_res *resp)
{
	return (svc_sendreply(transp, xdr_nlm4_res, (char *)resp));
}

static enum clnt_stat
nlm4_granted_4_cb(nlm4_testargs *argp, void *resp, CLIENT *clnt)
{
	nlm4_res res4;
	int rv;

	bzero(&res4, sizeof (res4));
	rv = nlm4_granted_4(argp, &res4, clnt);

	/* NB: We have a result our caller will not free. */
	xdr_free((xdrproc_t)xdr_nlm4_res, (void *)&res4);
	(void) resp;

	return (rv);
}

bool_t
nlm4_cancel_4_svc(nlm4_cancargs *argp, nlm4_res *resp, struct svc_req *sr)
{
	nlm_do_cancel(argp, resp, sr, NULL);
	return (TRUE);
}

bool_t
nlm4_unlock_4_svc(nlm4_unlockargs *argp, nlm4_res *resp, struct svc_req *sr)
{
	nlm_do_unlock(argp, resp, sr, NULL);
	return (TRUE);
}

bool_t
nlm4_granted_4_svc(nlm4_testargs *argp, nlm4_res *resp, struct svc_req *sr)
{
	nlm_do_granted(argp, resp, sr, NULL);
	return (TRUE);
}

bool_t
nlm4_test_msg_4_svc(nlm4_testargs *argp, void *resp, struct svc_req *sr)
{
	nlm4_testres res4;

	bzero(&res4, sizeof (res4));
	nlm_do_test(argp, &res4, sr,
	    nlm4_test_res_4);

	/* NB: We have a result our caller will not free. */
	xdr_free((xdrproc_t)xdr_nlm4_testres, (void *)&res4);
	(void) resp;

	/* The _msg_ calls get no reply. */
	return (FALSE);
}

/*
 * Callback functions for nlm4_lock_msg_4_svc
 * (using the RPC client stubs directly)
 */

bool_t
nlm4_lock_msg_4_svc(nlm4_lockargs *argp, void *resp,
    struct svc_req *sr)
{
	nlm4_res res4;

	/* NLM4_LOCK_MSG */
	bzero(&res4, sizeof (res4));
	nlm_do_lock(argp, &res4, sr,
	    NULL, nlm4_lock_res_4,
	    nlm4_granted_msg_4);

	/* NB: We have a result our caller will not free. */
	xdr_free((xdrproc_t)xdr_nlm4_res, (void *)&res4);
	(void) resp;

	/* The _msg_ calls get no reply. */
	return (FALSE);
}

bool_t
nlm4_cancel_msg_4_svc(nlm4_cancargs *argp, void *resp, struct svc_req *sr)
{
	nlm4_res res4;

	bzero(&res4, sizeof (res4));
	nlm_do_cancel(argp, &res4, sr,
	    nlm4_cancel_res_4);

	/* NB: We have a result our caller will not free. */
	xdr_free((xdrproc_t)xdr_nlm4_res, (void *)&res4);
	(void) resp;

	/* The _msg_ calls get no reply. */
	return (FALSE);
}

bool_t
nlm4_unlock_msg_4_svc(nlm4_unlockargs *argp, void *resp, struct svc_req *sr)
{
	nlm4_res res4;

	bzero(&res4, sizeof (res4));
	nlm_do_unlock(argp, &res4, sr,
	    nlm4_unlock_res_4);

	/* NB: We have a result our caller will not free. */
	xdr_free((xdrproc_t)xdr_nlm4_res, (void *)&res4);
	(void) resp;

	/* The _msg_ calls get no reply. */
	return (FALSE);
}

bool_t
nlm4_granted_msg_4_svc(nlm4_testargs *argp, void *resp, struct svc_req *sr)
{
	nlm4_res res4;

	bzero(&res4, sizeof (res4));
	nlm_do_granted(argp, &res4, sr,
	    nlm4_granted_res_4);

	/* NB: We have a result our caller will not free. */
	xdr_free((xdrproc_t)xdr_nlm4_res, (void *)&res4);
	(void) resp;

	/* The _msg_ calls get no reply. */
	return (FALSE);
}

/* ARGSUSED */
bool_t
nlm4_test_res_4_svc(nlm4_testres *argp, void *resp, struct svc_req *sr)
{
	/* The _res_ calls get no reply. */
	return (FALSE);
}

/* ARGSUSED */
bool_t
nlm4_lock_res_4_svc(nlm4_res *argp, void *resp, struct svc_req *sr)
{
	/* The _res_ calls get no reply. */
	return (FALSE);
}

/* ARGSUSED */
bool_t
nlm4_cancel_res_4_svc(nlm4_res *argp, void *resp, struct svc_req *sr)
{
	/* The _res_ calls get no reply. */
	return (FALSE);
}

/* ARGSUSED */
bool_t
nlm4_unlock_res_4_svc(nlm4_res *argp, void *resp, struct svc_req *sr)
{
	/* The _res_ calls get no reply. */
	return (FALSE);
}

/* ARGSUSED */
bool_t
nlm4_granted_res_4_svc(nlm4_res *argp, void *resp, struct svc_req *sr)
{
	/* The _res_ calls get no reply. */
	return (FALSE);
}

/* ARGSUSED */
bool_t
nlm4_share_4_svc(nlm4_shareargs *argp, nlm4_shareres *resp,
    struct svc_req *sr)
{
	nlm_do_share(argp, resp, sr);
	return (TRUE);
}

/* ARGSUSED */
bool_t
nlm4_unshare_4_svc(nlm4_shareargs *argp, nlm4_shareres *resp,
    struct svc_req *sr)
{
	nlm_do_unshare(argp, resp, sr);
	return (TRUE);
}

bool_t
nlm4_nm_lock_4_svc(nlm4_lockargs *argp, nlm4_res *resp, struct svc_req *sr)
{

	/*
	 * Don't allow blocking for non-monitored (nm_lock) calls.
	 * These clients don't handle any callbacks, including
	 * the granted call we make after a blocking lock.
	 * Same reply callback as nlm4_lock_4_svc
	 */
	argp->block = FALSE;

	/* NLM4_NM_LOCK */
	nlm_do_lock(argp, resp, sr,
	    nlm4_lock_4_reply, NULL,
	    NULL); /* indicates non-monitored */

	/* above does its own reply */
	return (FALSE);
}

bool_t
nlm4_free_all_4_svc(nlm4_notify *argp, void *resp, struct svc_req *sr)
{
	nlm_do_free_all(argp, resp, sr);
	return (TRUE);
}
