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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Utility routines
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <libintl.h>
#include <assert.h>
#include <ucontext.h>
#include <pthread.h>
#include "idmap_impl.h"

#define	_UDT_SIZE_INCR	1

#define	_GET_IDS_SIZE_INCR	1

static struct timeval TIMEOUT = { 25, 0 };

struct idmap_handle {
	CLIENT		*client;
	boolean_t	failed;
	rwlock_t	lock;
};

static struct idmap_handle idmap_handle = {
	NULL,		/* client */
	B_TRUE,		/* failed */
	DEFAULTRWLOCK,	/* lock */
};

static idmap_stat _idmap_clnt_connect(void);
static void _idmap_clnt_disconnect(void);

idmap_retcode
_udt_extend_batch(idmap_udt_handle_t *udthandle)
{
	idmap_update_op	*tmplist;
	size_t		nsize;

	if (udthandle->next >= udthandle->batch.idmap_update_batch_len) {
		nsize = (udthandle->batch.idmap_update_batch_len +
		    _UDT_SIZE_INCR) * sizeof (*tmplist);
		tmplist = realloc(
		    udthandle->batch.idmap_update_batch_val, nsize);
		if (tmplist == NULL)
			return (IDMAP_ERR_MEMORY);
		(void) memset((uchar_t *)tmplist +
		    (udthandle->batch.idmap_update_batch_len *
		    sizeof (*tmplist)), 0,
		    _UDT_SIZE_INCR * sizeof (*tmplist));
		udthandle->batch.idmap_update_batch_val = tmplist;
		udthandle->batch.idmap_update_batch_len += _UDT_SIZE_INCR;
	}
	udthandle->batch.idmap_update_batch_val[udthandle->next].opnum =
	    OP_NONE;
	return (IDMAP_SUCCESS);
}

idmap_retcode
_get_ids_extend_batch(idmap_get_handle_t *gh)
{
	idmap_mapping	*t1;
	idmap_get_res_t	*t2;
	size_t		nsize, len;

	len = gh->batch.idmap_mapping_batch_len;
	if (gh->next >= len) {
		/* extend the request array */
		nsize = (len + _GET_IDS_SIZE_INCR) * sizeof (*t1);
		t1 = realloc(gh->batch.idmap_mapping_batch_val, nsize);
		if (t1 == NULL)
			return (IDMAP_ERR_MEMORY);
		(void) memset((uchar_t *)t1 + (len * sizeof (*t1)), 0,
		    _GET_IDS_SIZE_INCR * sizeof (*t1));
		gh->batch.idmap_mapping_batch_val = t1;

		/* extend the return list */
		nsize = (len + _GET_IDS_SIZE_INCR) * sizeof (*t2);
		t2 = realloc(gh->retlist, nsize);
		if (t2 == NULL)
			return (IDMAP_ERR_MEMORY);
		(void) memset((uchar_t *)t2 + (len * sizeof (*t2)), 0,
		    _GET_IDS_SIZE_INCR * sizeof (*t2));
		gh->retlist = t2;

		gh->batch.idmap_mapping_batch_len += _GET_IDS_SIZE_INCR;
	}
	return (IDMAP_SUCCESS);
}

idmap_stat
_iter_get_next_list(int type, idmap_iter_t *iter,
		void *arg, uchar_t **list, size_t valsize,
		xdrproc_t xdr_arg_proc, xdrproc_t xdr_res_proc)
{
	idmap_stat rc;

	iter->next = 0;
	iter->retlist = NULL;

	/* init the result */
	if (*list) {
		xdr_free(xdr_res_proc, (caddr_t)*list);
	} else {
		if ((*list = malloc(valsize)) == NULL) {
			errno = ENOMEM;
			return (IDMAP_ERR_MEMORY);
		}
	}
	(void) memset(*list, 0, valsize);

	rc = _idmap_clnt_call(type,
	    xdr_arg_proc, (caddr_t)arg,
	    xdr_res_proc, (caddr_t)*list,
	    TIMEOUT);
	if (rc != IDMAP_SUCCESS) {
		free(*list);
		return (rc);
	}
	iter->retlist = *list;
	return (IDMAP_SUCCESS);
}

/*
 * Convert the return values from an RPC request into an idmap return code.
 * Set errno on error.
 */
static
idmap_stat
_idmap_rpc2stat(enum clnt_stat clntstat, CLIENT *clnt)
{
	/*
	 * We only deal with door_call(3C) errors here. We look at
	 * r_err.re_errno instead of r_err.re_status because we need
	 * to differentiate between RPC failures caused by bad door fd
	 * and others.
	 */
	struct rpc_err r_err;

	if (clntstat == RPC_SUCCESS)
		return (IDMAP_SUCCESS);

	clnt_geterr(clnt, &r_err);
	errno = r_err.re_errno;
	switch (r_err.re_errno) {
	case ENOMEM:
		return (IDMAP_ERR_MEMORY);
	case EBADF:
		return (IDMAP_ERR_RPC_HANDLE);
	default:
		return (IDMAP_ERR_RPC);
	}
}

/*
 * Management of the connection to idmapd.
 *
 * The intent is that connections to idmapd are automatically maintained,
 * reconnecting if necessary.  No attempt is made to retry connnection
 * attempts; a failure to connect yields an immediate error return.
 *
 * State of the connection is maintained through the "client" and "failed"
 * elements of the handle structure:
 *
 * client   failed
 * NULL     true     Failed on a previous request and was not recovered.
 * NULL     false    Should never happen.
 * nonNULL  true     Structure exists, but an error has occurred.  Waiting
 *                   for a chance to attempt to reconnect.
 * nonNULL  false    Connection is good.
 *
 * Note that the initial state is NULL/true, so that the first request
 * will establish the initial connection.
 *
 * Concurrency is managed through the rw lock "lock".  Only the writer is
 * allowed to connect or disconnect, and thus only the writer can set
 * "failed" to "false".  Readers are allowed to use the "client" pointer,
 * and to set "failed" to "true", indicating that they have encountered a
 * failure.  The "client" pointer is only valid while one holds a reader
 * lock.  Once "failed" has been set to "true", all requests (including
 * the retry of the failing request) will attempt to gain the writer lock.
 * When they succeed, indicating that there are no requests in flight and
 * thus no outstanding references to the CLIENT structure, they check
 * again to see if the connection is still failed (since another thread
 * might have fixed it), and then if it is still failed they disconnect
 * and reconnect.
 */

/*
 * Make an RPC call.  Automatically reconnect if the connection to idmapd
 * fails.  Convert RPC results to idmap return codes.
 */
idmap_stat
_idmap_clnt_call(
    const rpcproc_t procnum,
    const xdrproc_t inproc,
    const caddr_t in,
    const xdrproc_t outproc,
    caddr_t out,
    const struct timeval tout)
{
	enum clnt_stat	clntstat;
	idmap_stat rc;

	(void) rw_rdlock(&idmap_handle.lock);
	for (;;) {
		if (idmap_handle.failed) {
			/* No connection.  Bid to see if we should fix it. */
			(void) rw_unlock(&idmap_handle.lock);
			/* Somebody else might fix it here. */
			(void) rw_wrlock(&idmap_handle.lock);
			/*
			 * At this point, everybody else is asleep waiting
			 * for us.  Check to see if somebody else has already
			 * fixed the problem.
			 */
			if (idmap_handle.failed) {
				/* It's our job to fix. */
				_idmap_clnt_disconnect();
				rc = _idmap_clnt_connect();
				if (rc != IDMAP_SUCCESS) {
					/* We couldn't fix it. */
					assert(idmap_handle.failed);
					assert(idmap_handle.client == NULL);
					break;
				}
				/* We fixed it. */
				idmap_handle.failed = B_FALSE;
			}

			/* It's fixed now. */
			(void) rw_unlock(&idmap_handle.lock);
			/*
			 * Starting here, somebody might declare it failed
			 * again.
			 */
			(void) rw_rdlock(&idmap_handle.lock);
			continue;
		}

		clntstat = clnt_call(idmap_handle.client, procnum, inproc, in,
		    outproc, out, tout);
		rc = _idmap_rpc2stat(clntstat, idmap_handle.client);
		if (rc == IDMAP_ERR_RPC_HANDLE) {
			/* Failed.  Needs to be reconnected. */
			idmap_handle.failed = B_TRUE;
			continue;
		}

		/* Success or unrecoverable failure. */
		break;
	}
	(void) rw_unlock(&idmap_handle.lock);
	return (rc);
}

#define	MIN_STACK_NEEDS	65536

/*
 * Connect to idmapd.
 * Must be single-threaded through rw_wrlock(&idmap_handle.lock).
 */
static
idmap_stat
_idmap_clnt_connect(void)
{
	uint_t			sendsz = 0;
	stack_t			st;

	/*
	 * clnt_door_call() alloca()s sendsz bytes (twice too, once for
	 * the call args buffer and once for the call result buffer), so
	 * we want to pick a sendsz that will be large enough, but not
	 * too large.
	 */
	if (stack_getbounds(&st) == 0) {
		/*
		 * Estimate how much stack space is left;
		 * st.ss_sp is the top of stack.
		 */
		if ((char *)&sendsz < (char *)st.ss_sp)
			/* stack grows up */
			sendsz = ((char *)st.ss_sp - (char *)&sendsz);
		else
			/* stack grows down */
			sendsz = ((char *)&sendsz - (char *)st.ss_sp);

		if (sendsz <= MIN_STACK_NEEDS) {
			sendsz = 0;	/* RPC call may fail */
		} else {
			/* Leave 64Kb (just a guess) for our needs */
			sendsz -= MIN_STACK_NEEDS;

			/* Divide the stack space left by two */
			sendsz = RNDUP(sendsz / 2);

			/* Limit sendsz to 256KB */
			if (sendsz > IDMAP_MAX_DOOR_RPC)
				sendsz = IDMAP_MAX_DOOR_RPC;
		}
	}

	idmap_handle.client = clnt_door_create(IDMAP_PROG, IDMAP_V1, sendsz);
	if (idmap_handle.client == NULL)
		return (IDMAP_ERR_RPC);

	return (IDMAP_SUCCESS);
}

/*
 * Disconnect from idmapd, if we're connected.
 */
static
void
_idmap_clnt_disconnect(void)
{
	CLIENT *clnt;

	clnt = idmap_handle.client;
	if (clnt != NULL) {
		if (clnt->cl_auth)
			auth_destroy(clnt->cl_auth);
		clnt_destroy(clnt);
		idmap_handle.client = NULL;
	}
}
