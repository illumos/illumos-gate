/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This module contains just the core lookup functions.
 */
#include "mt.h"
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>
#include "nis_clnt.h"
#include "nis_local.h"

static enum clnt_stat do_list(CLIENT *, ib_request *, nis_result *,
	int (*)(), void *, nis_call_state *);
static enum clnt_stat do_lookup(CLIENT *, ib_request *, nis_result *,
	nis_call_state *);

unsigned __nis_max_hard_lookup_time = 300;

extern int __nis_debug_rpc;

/*
 * NOTE : Binding bug : due to the implementation of the
 *	NIS+ service, when you want to list a directory you
 *	need to bind not to a server that serves the directory
 *	object, but to a server that serves the directory itself.
 *	This will often be different machines.
 *
 *	However, we can mitigate the impact of always trying to
 *	bind to the table if we're searching a table by checking
 *	for search criteria. (listing directories can't have a
 *	search criteria). So if we're a list, and we don't have
 *	a search criteria, bind to the "name" passed first. Otherwise
 *	attempt to bind to domain_of(name) first.
 */
nis_result *
__nis_remote_lookup(
	ib_request	*req,		/* name parameters		*/
	uint_t		flags,		/* user flags			*/
	int		list_op,	/* list semantics 		*/
	void		*cbdata,	/* Callback data		*/
	int		(*cback)())	/* Callback (for list calls) 	*/
{
	CLIENT *clnt;
	enum clnt_stat st;
	ib_request local_req;
	int times_thru;
	int sec;
	int linknum = 0;
	nis_result *res;
	nis_result *link_res = 0;
	nis_object *lobj;
	nis_call_state state;
	uint32_t zticks = 0;
	uint32_t dticks = 0;
	uint32_t aticks = 0;

	/*
	 *  Allocate a result structure.  We also make a local
	 *  copy of the request so that we can reuse it while
	 *  following links (without clobbering the callers copy).
	 */
	res = malloc(sizeof (nis_result));
	if (res == NULL)
		return (NULL);
	local_req = *req;

follow_link:
	/*
	 *  Loop until we can't make any more progress on getting
	 *  a good server (or indefinitely if HARDLOOKUP is set).
	 */
	times_thru = 0;
	for (;;) {
		/* set state for this lookup */
		__nis_init_call_state(&state);
		state.name = local_req.ibr_name;
		state.flags = flags;
		if (list_op && local_req.ibr_srch.ibr_srch_len == 0)
			state.parent_first = 0;
		else
			state.parent_first = 1;

		/*
		 *  Loop until we get a response from a server or
		 *  until we can no longer get a client handle.
		 */
		for (;;) {
			(void) memset((char *)res, 0, sizeof (nis_result));
			clnt = __nis_get_server(&state);
			if (clnt == NULL) {
				res->status = state.niserror;
				if ((flags & HARD_LOOKUP) == 0 ||
				    res->status == NIS_NOSUCHNAME ||
				    res->status == NIS_NOSUCHTABLE ||
				    res->status == NIS_BADNAME ||
				    res->status == NIS_COLDSTART_ERR ||
				    res->status == NIS_SRVAUTH ||
				    res->status == NIS_NOMEMORY) {
					goto call_done;
				}
				break;
			} else {
				/*
				 *  If there is an error in do_list() or
				 *  do_lookup(), they will set res->status.
				 */
				if (list_op)
					st = do_list(clnt, &local_req, res,
							cback, cbdata, &state);
				else
					st = do_lookup(clnt, &local_req, res,
							&state);
				/*
				 *  If we get NIS_NOT_ME or NIS_NOTMASTER,
				 *  then we are talking to a server that
				 *  is not up-to-date and we need to try
				 *  a different server.  In essence,
				 *  it is equivalent to getting no
				 *  response at all, so we treat it
				 *  as such.  __nis_release_server()
				 *  will believe that we got an RPC
				 *  error and will avoid using the
				 *  server.
				 */
				if (st == RPC_SUCCESS &&
				    (res->status == NIS_NOT_ME ||
				    res->status == NIS_NOTMASTER)) {
					xdr_free(xdr_nis_result, (char *)res);
					st = RPC_TIMEDOUT;
				}

				__nis_release_server(&state, clnt, st);
				if (st == RPC_SUCCESS)
					goto call_done;
			}
		}

		/*
		 * We did not have any luck with the current
		 * binding, we we need to try to get a different
		 * one.
		 *
		 * We have to practice an exponential backoff
		 * to keep this code from abusing the network
		 * when we run with HARD_LOOKUP enabled.
		 * __nis_max_hard_lookup_time is max time to
		 * wait (currently 5 minutes)
		 *
		 * Yes this code could be better but it should
		 * not be called very often either.  If it is
		 * efficiency is the least of your problems.
		 */
		syslog(LOG_WARNING,
			"NIS+ server for %s not responding, still trying",
			state.name);
		times_thru++;
		sec = 2 << times_thru;
		if (sec > __nis_max_hard_lookup_time) {
			sec = __nis_max_hard_lookup_time;
			--times_thru;
		}
		(void) sleep(sec);
		__nis_reset_call_state(&state);
	}
call_done:

	/* accumulate ticks */
	zticks += res->zticks;
	dticks += res->dticks;
	aticks += state.aticks;

	__nis_reset_call_state(&state);

	/*
	 *  We have a response from a server.  If we got a link,
	 *  then follow it (if the FOLLOW_LINKS flag is set).
	 */
	if ((flags & FOLLOW_LINKS) != 0 && res->objects.objects_len != 0 &&
	    __type_of(res->objects.objects_val) == NIS_LINK_OBJ) {
		linknum++;
		if (linknum > NIS_MAXLINKS) {
			res->status = NIS_LINKNAMEERROR;
		} else {
			if (link_res) {
				nis_freeresult(link_res);
			}
			link_res = res;
			res = malloc(sizeof (nis_result));
			if (res == NULL) {
				nis_freeresult(link_res);
				return (NULL);
			}
			lobj = link_res->objects.objects_val;
			local_req = *req;
			local_req.ibr_name = lobj->LI_data.li_name;
			if (lobj->LI_data.li_attrs.li_attrs_len) {
				local_req.ibr_srch.ibr_srch_len =
				    lobj->LI_data.li_attrs.li_attrs_len;
				local_req.ibr_srch.ibr_srch_val =
				    lobj->LI_data.li_attrs.li_attrs_val;
			}
			if (local_req.ibr_srch.ibr_srch_len)
				list_op = 1;
			goto follow_link;
		}
	}
	/*
	 *  If we failed following a link, return the link result (but
	 *  set the status to the actual failure.
	 */
	if (res->status != NIS_SUCCESS && res->status != NIS_S_SUCCESS &&
		res->status != NIS_PARTIAL) {
		if (link_res) {
			link_res->status = res->status;
			nis_freeresult(res);
			res = link_res;
		}
	} else if (link_res != 0) {
		nis_freeresult(link_res);
	}
	res->zticks = zticks;
	res->dticks = dticks;
	res->aticks = aticks;
	return (res);
}

/*
 *  The rpc.nisd program has a local copy of this function.
 *  The server tries to resolve lookups in its own data base.
 *  If it can't, then it goes ahead and calls __nis_remote_lookup().
 */
nis_result *
__nis_core_lookup(
	ib_request	*req,		/* name parameters		*/
	uint_t		flags,		/* user flags			*/
	int		list_op,	/* list semantics 		*/
	void		*cbdata,	/* Callback data		*/
	int		(*cback)())	/* Callback (for list calls) 	*/
{
	return (__nis_remote_lookup(req, flags, list_op, cbdata, cback));
}

fd_result *
__nis_finddirectory_remote(nis_bound_directory **binding, char *dname)
{
	enum clnt_stat status;
	CLIENT *clnt;
	fd_args req;
	fd_result *res;
	nis_call_state state;

	res = calloc(1, sizeof (fd_result));
	if (res == NULL)
		return (NULL);

	req.dir_name = dname;
	req.requester = nis_local_host();

	__nis_init_call_state(&state);
	state.name = NULL;
	state.srv = NULL;
	state.nsrv = NULL;
	state.binding = *binding;
	state.flags = USE_DGRAM;
	state.timeout.tv_sec = NIS_FINDDIR_TIMEOUT;

	for (;;) {
		clnt = __nis_get_server(&state);
		if (clnt == NULL) {
			res->status = state.niserror;
			break;
		}
		if (__nis_debug_rpc)
			__nis_print_call(clnt, NIS_FINDDIRECTORY);
		if (__nis_debug_rpc >= 2)
			__nis_print_fdreq(&req);
		(void) memset((char *)res, 0, sizeof (fd_result));
		status = clnt_call(clnt, NIS_FINDDIRECTORY,
			xdr_fd_args, (char *)&req,
			xdr_fd_result, (char *)res, state.timeout);
		if (__nis_debug_rpc)
			__nis_print_rpc_result(status);
		__nis_release_server(&state, clnt, status);
		if (status == RPC_SUCCESS)
			break;
		res->status = NIS_RPCERROR;
	}
	*binding = state.binding;
	return (res);
}

fd_result *
__nis_finddirectory(nis_bound_directory **binding, char *dname)
{
	return (__nis_finddirectory_remote(binding, dname));
}

fd_result *
nis_finddirectory(directory_obj *dobj, nis_name name)
{
	nis_error err;
	fd_result *res;
	nis_bound_directory *binding;

	err = __nis_CacheBindDir(dobj->do_name, &binding, 0);
	if (err != NIS_SUCCESS)
		return (NULL);
	res = __nis_finddirectory(&binding, name);
	nis_free_binding(binding);
	return (res);
}

static
enum clnt_stat
do_list(CLIENT *clnt, ib_request *req, nis_result *res,
	int (*cback)(), void *cbdata, nis_call_state *state)
{
	enum clnt_stat stat;
	int err;

	if (cback) {
		req->ibr_cbhost.ibr_cbhost_val =
			__nis_init_callback(clnt, cback, cbdata);
		if (req->ibr_cbhost.ibr_cbhost_val == NULL) {
			res->status = NIS_NOCALLBACK;
			return (RPC_SUCCESS);
		}
		req->ibr_cbhost.ibr_cbhost_len = 1;
	}

	(void) memset((char *)res, 0, sizeof (nis_result));

	if (__nis_debug_rpc)
		__nis_print_call(clnt, NIS_IBLIST);
	if (__nis_debug_rpc >= 2)
		__nis_print_req(req);

	stat = clnt_call(clnt, NIS_IBLIST,
		xdr_ib_request, (char *)req,
		xdr_nis_result, (char *)res, state->timeout);

	if (__nis_debug_rpc)
		__nis_print_rpc_result(stat);
	if (__nis_debug_rpc >= 2)
		__nis_print_result(res);

	if (stat == RPC_SUCCESS) {
		if (res->status == NIS_CBRESULTS) {
			err = __nis_run_callback(&NIS_RES_COOKIE(res),
				NIS_CALLBACK, 0, clnt);
			if (err < 0)
				res->status = -err;
		}
		/*
		 * XXX need to check for and handle NIS_NOCALLBACK
		 * XXX and refresh callback address.
		 */
	}

	return (stat);
}

static
enum clnt_stat
do_lookup(CLIENT *clnt, ib_request *req, nis_result *res, nis_call_state *state)
{
	ns_request nsr;
	enum clnt_stat stat;

	(void) memset((char *)&nsr, 0, sizeof (nsr));
	(void) memset((char *)res, 0, sizeof (nis_result));
	nsr.ns_name = req->ibr_name;
	if (__nis_debug_rpc)
		__nis_print_call(clnt, NIS_LOOKUP);
	if (__nis_debug_rpc >= 2)
		__nis_print_nsreq(&nsr);

	stat = clnt_call(clnt, NIS_LOOKUP,
		xdr_ns_request, (char *)&nsr,
		xdr_nis_result, (char *)res, state->timeout);

	if (__nis_debug_rpc)
		__nis_print_rpc_result(stat);
	if (__nis_debug_rpc >= 2)
		__nis_print_result(res);

	return (stat);
}
