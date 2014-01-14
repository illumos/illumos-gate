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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2012 by Delphix. All rights reserved.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/unistd.h>
#include <sys/queue.h>
#include <sys/sdt.h>
#include <netinet/in.h>

#include <rpc/rpc.h>
#include <rpc/xdr.h>
#include <rpc/pmap_prot.h>
#include <rpc/pmap_clnt.h>
#include <rpc/rpcb_prot.h>

#include <rpcsvc/nlm_prot.h>
#include <rpcsvc/sm_inter.h>

#include "nlm_impl.h"

/*
 * The following errors codes from nlm_null_rpc indicate that the port we have
 * cached for the client's NLM service is stale and that we need to establish
 * a new RPC client.
 */
#define	NLM_STALE_CLNT(_status)			\
	((_status) == RPC_PROGUNAVAIL ||	\
	(_status) == RPC_PROGVERSMISMATCH ||	\
	(_status) == RPC_PROCUNAVAIL ||		\
	(_status) == RPC_CANTCONNECT ||		\
	(_status) == RPC_XPRTFAILED)

static struct kmem_cache *nlm_rpch_cache = NULL;

static int nlm_rpch_ctor(void *, void *, int);
static void nlm_rpch_dtor(void *, void *);
static void destroy_rpch(nlm_rpc_t *);
static nlm_rpc_t *get_nlm_rpc_fromcache(struct nlm_host *, int);
static void update_host_rpcbinding(struct nlm_host *, int);
static int refresh_nlm_rpc(struct nlm_host *, nlm_rpc_t *);
static void nlm_host_rele_rpc_locked(struct nlm_host *, nlm_rpc_t *);

static nlm_rpc_t *
get_nlm_rpc_fromcache(struct nlm_host *hostp, int vers)
{
	nlm_rpc_t *rpcp;
	bool_t found = FALSE;

	ASSERT(MUTEX_HELD(&hostp->nh_lock));
	if (TAILQ_EMPTY(&hostp->nh_rpchc))
		return (NULL);

	TAILQ_FOREACH(rpcp, &hostp->nh_rpchc, nr_link) {
		if (rpcp->nr_vers == vers) {
			found = TRUE;
			break;
		}
	}

	if (!found)
		return (NULL);

	TAILQ_REMOVE(&hostp->nh_rpchc, rpcp, nr_link);
	return (rpcp);
}

/*
 * Update host's RPC binding (host->nh_addr).
 * The function is executed by only one thread at time.
 */
static void
update_host_rpcbinding(struct nlm_host *hostp, int vers)
{
	enum clnt_stat stat;

	ASSERT(MUTEX_HELD(&hostp->nh_lock));

	/*
	 * Mark RPC binding state as "update in progress" in order
	 * to say other threads that they need to wait until binding
	 * is fully updated.
	 */
	hostp->nh_rpcb_state = NRPCB_UPDATE_INPROGRESS;
	hostp->nh_rpcb_ustat = RPC_SUCCESS;
	mutex_exit(&hostp->nh_lock);

	stat = rpcbind_getaddr(&hostp->nh_knc, NLM_PROG, vers, &hostp->nh_addr);
	mutex_enter(&hostp->nh_lock);

	hostp->nh_rpcb_state = ((stat == RPC_SUCCESS) ?
	    NRPCB_UPDATED : NRPCB_NEED_UPDATE);

	hostp->nh_rpcb_ustat = stat;
	cv_broadcast(&hostp->nh_rpcb_cv);
}

/*
 * Refresh RPC handle taken from host handles cache.
 * This function is called when an RPC handle is either
 * uninitialized or was initialized using a binding that's
 * no longer current.
 */
static int
refresh_nlm_rpc(struct nlm_host *hostp, nlm_rpc_t *rpcp)
{
	int ret;

	if (rpcp->nr_handle == NULL) {
		bool_t clset = TRUE;

		ret = clnt_tli_kcreate(&hostp->nh_knc, &hostp->nh_addr,
		    NLM_PROG, rpcp->nr_vers, 0, NLM_RPC_RETRIES,
		    CRED(), &rpcp->nr_handle);

		/*
		 * Set the client's CLSET_NODELAYONERR option to true. The
		 * RPC clnt_call interface creates an artificial delay for
		 * certain call errors in order to prevent RPC consumers
		 * from getting into tight retry loops. Since this function is
		 * called by the NLM service routines we would like to avoid
		 * this artificial delay when possible. We do not retry if the
		 * NULL request fails so it is safe for us to turn this option
		 * on.
		 */
		if (clnt_control(rpcp->nr_handle, CLSET_NODELAYONERR,
		    (char *)&clset) == FALSE) {
			NLM_ERR("Unable to set CLSET_NODELAYONERR\n");
		}
	} else {
		ret = clnt_tli_kinit(rpcp->nr_handle, &hostp->nh_knc,
		    &hostp->nh_addr, 0, NLM_RPC_RETRIES, CRED());
		if (ret == 0) {
			enum clnt_stat stat;

			/*
			 * Check whether host's RPC binding is still
			 * fresh, i.e. if remote program is still sits
			 * on the same port we assume. Call NULL proc
			 * to do it.
			 *
			 * Note: Even though we set no delay on error on the
			 * client handle the call to nlm_null_rpc can still
			 * delay for 10 seconds before returning an error. For
			 * example the no delay on error option is not honored
			 * for RPC_XPRTFAILED errors (see clnt_cots_kcallit).
			 */
			stat = nlm_null_rpc(rpcp->nr_handle, rpcp->nr_vers);
			if (NLM_STALE_CLNT(stat)) {
				ret = ESTALE;
			}
		}
	}

	return (ret);
}

/*
 * Get RPC handle that can be used to talk to the NLM
 * of given version running on given host.
 * Saves obtained RPC handle to rpcpp argument.
 *
 * If error occures, return nonzero error code.
 */
int
nlm_host_get_rpc(struct nlm_host *hostp, int vers, nlm_rpc_t **rpcpp)
{
	nlm_rpc_t *rpcp = NULL;
	int rc;

	mutex_enter(&hostp->nh_lock);

	/*
	 * If this handle is either uninitialized, or was
	 * initialized using binding that's now stale
	 * do the init or re-init.
	 * See comments to enum nlm_rpcb_state for more
	 * details.
	 */
again:
	while (hostp->nh_rpcb_state != NRPCB_UPDATED) {
		if (hostp->nh_rpcb_state == NRPCB_UPDATE_INPROGRESS) {
			rc = cv_wait_sig(&hostp->nh_rpcb_cv, &hostp->nh_lock);
			if (rc == 0) {
				mutex_exit(&hostp->nh_lock);
				return (EINTR);
			}
		}

		/*
		 * Check if RPC binding was marked for update.
		 * If so, start RPC binding update operation.
		 * NOTE: the operation can be executed by only
		 * one thread at time.
		 */
		if (hostp->nh_rpcb_state == NRPCB_NEED_UPDATE)
			update_host_rpcbinding(hostp, vers);

		/*
		 * Check if RPC error occured during RPC binding
		 * update operation. If so, report a correspoding
		 * error.
		 */
		if (hostp->nh_rpcb_ustat != RPC_SUCCESS) {
			mutex_exit(&hostp->nh_lock);
			return (ENOENT);
		}
	}

	rpcp = get_nlm_rpc_fromcache(hostp, vers);
	mutex_exit(&hostp->nh_lock);
	if (rpcp == NULL) {
		/*
		 * There weren't any RPC handles in a host
		 * cache. No luck, just create a new one.
		 */
		rpcp = kmem_cache_alloc(nlm_rpch_cache, KM_SLEEP);
		rpcp->nr_vers = vers;
	}

	/*
	 * Refresh RPC binding
	 */
	rc = refresh_nlm_rpc(hostp, rpcp);
	if (rc != 0) {
		if (rc == ESTALE) {
			/*
			 * Host's RPC binding is stale, we have
			 * to update it. Put the RPC handle back
			 * to the cache and mark the host as
			 * "need update".
			 */
			mutex_enter(&hostp->nh_lock);
			hostp->nh_rpcb_state = NRPCB_NEED_UPDATE;
			nlm_host_rele_rpc_locked(hostp, rpcp);
			goto again;
		}

		destroy_rpch(rpcp);
		return (rc);
	}

	DTRACE_PROBE2(end, struct nlm_host *, hostp,
	    nlm_rpc_t *, rpcp);

	*rpcpp = rpcp;
	return (0);
}

void
nlm_host_rele_rpc(struct nlm_host *hostp, nlm_rpc_t *rpcp)
{
	mutex_enter(&hostp->nh_lock);
	nlm_host_rele_rpc_locked(hostp, rpcp);
	mutex_exit(&hostp->nh_lock);
}

static void
nlm_host_rele_rpc_locked(struct nlm_host *hostp, nlm_rpc_t *rpcp)
{
	ASSERT(mutex_owned(&hostp->nh_lock));
	TAILQ_INSERT_HEAD(&hostp->nh_rpchc, rpcp, nr_link);
}

/*
 * The function invalidates host's RPC binding by marking it
 * as not fresh. In this case another time thread tries to
 * get RPC handle from host's handles cache, host's RPC binding
 * will be updated.
 *
 * The function should be executed when RPC call invoked via
 * handle taken from RPC cache returns RPC_PROCUNAVAIL.
 */
void
nlm_host_invalidate_binding(struct nlm_host *hostp)
{
	mutex_enter(&hostp->nh_lock);
	hostp->nh_rpcb_state = NRPCB_NEED_UPDATE;
	mutex_exit(&hostp->nh_lock);
}

void
nlm_rpc_init(void)
{
	nlm_rpch_cache = kmem_cache_create("nlm_rpch_cache",
	    sizeof (nlm_rpc_t), 0, nlm_rpch_ctor, nlm_rpch_dtor,
	    NULL, NULL, NULL, 0);
}

void
nlm_rpc_cache_destroy(struct nlm_host *hostp)
{
	nlm_rpc_t *rpcp;

	/*
	 * There's no need to lock host's mutex here,
	 * nlm_rpc_cache_destroy() should be called from
	 * only one place: nlm_host_destroy, when all
	 * resources host owns are already cleaned up.
	 * So there shouldn't be any raises.
	 */
	while ((rpcp = TAILQ_FIRST(&hostp->nh_rpchc)) != NULL) {
		TAILQ_REMOVE(&hostp->nh_rpchc, rpcp, nr_link);
		destroy_rpch(rpcp);
	}
}

/* ARGSUSED */
static int
nlm_rpch_ctor(void *datap, void *cdrarg, int kmflags)
{
	nlm_rpc_t *rpcp = (nlm_rpc_t *)datap;

	bzero(rpcp, sizeof (*rpcp));
	return (0);
}

/* ARGSUSED */
static void
nlm_rpch_dtor(void *datap, void *cdrarg)
{
	nlm_rpc_t *rpcp = (nlm_rpc_t *)datap;
	ASSERT(rpcp->nr_handle == NULL);
}

static void
destroy_rpch(nlm_rpc_t *rpcp)
{
	if (rpcp->nr_handle != NULL) {
		AUTH_DESTROY(rpcp->nr_handle->cl_auth);
		CLNT_DESTROY(rpcp->nr_handle);
		rpcp->nr_handle = NULL;
	}

	kmem_cache_free(nlm_rpch_cache, rpcp);
}
