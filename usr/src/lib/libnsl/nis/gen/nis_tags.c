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
 * This module contains the library functions that manipulate the
 * server state and statistics. It also includes the implementations
 * nis_getservlist and nis_freeservlist
 */

#include "mt.h"
#include <string.h>
#include <malloc.h>
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>
#include "nis_clnt.h"
#include "nis_local.h"

extern void __free_nis_server(nis_server *server);

/*
 * nis_freeservlist(list)
 *
 * This function will free all of the memory allocated (or partially
 * allocated) for a nis server list.
 */
void
nis_freeservlist(nis_server **servers)
{
	nis_server	**list;

	list = servers;
	if (! list)
		return;

	for (; *list; list++)
		__free_nis_server(*list);
	free(servers);
}

/*
 * nis_getservlist(name)
 *
 * This function will return list of servers for the indicated domain.
 * the first server in the list is the master for that domain, subsequent
 * servers are replicas. The results of this call should be freed with
 * a call to nis_freeservlist().
 */

nis_server **
nis_getservlist(nis_name name)
{
	directory_obj	slist;
	nis_server	**res;
	int		ns;	/* Number of servers 	*/
	nis_server	*srvs;	/* Array of servers 	*/
	int		nep;	/* Number of endpoints	*/
	endpoint	*eps;	/* Array of endpoints	*/
	int		i, k;
	nis_error	err;

	err = __nis_CacheBind(name, &slist);
	if (err != NIS_SUCCESS) {
		xdr_free(xdr_directory_obj, (char *)&slist);
		return (NULL);
	}

	ns = slist.do_servers.do_servers_len;
	srvs = slist.do_servers.do_servers_val;

	res = (nis_server **)calloc(ns+1, sizeof (nis_server *));
	if (! res) {
		xdr_free(xdr_directory_obj, (char *)&slist);
		return (NULL);
	}

	for (i = 0; i < ns; i++) {
		res[i] = (nis_server *)calloc(1, sizeof (nis_server));
		if (! res[i]) {
			nis_freeservlist(res);
			xdr_free(xdr_directory_obj, (char *)&slist);
			return (NULL);
		}
		res[i]->name = strdup(srvs[i].name);
		if (! res[i]->name) {
			xdr_free(xdr_directory_obj, (char *)&slist);
			nis_freeservlist(res);
			return (NULL);
		}
		if ((srvs[i].key_type != NIS_PK_NONE) && (srvs[i].pkey.n_len)) {
			res[i]->pkey.n_bytes =
				(char *)malloc(srvs[i].pkey.n_len);
			if (!(res[i]->pkey.n_bytes)) {
				nis_freeservlist(res);
				xdr_free(xdr_directory_obj, (char *)&slist);
				return (NULL);
			}
			(void) memcpy(res[i]->pkey.n_bytes,
			    srvs[i].pkey.n_bytes, srvs[i].pkey.n_len);
			res[i]->pkey.n_len = srvs[i].pkey.n_len;
			res[i]->key_type = srvs[i].key_type;
		}

		nep = srvs[i].ep.ep_len;
		eps = srvs[i].ep.ep_val;
		res[i]->ep.ep_len = nep;
		res[i]->ep.ep_val = (endpoint *)calloc(nep, sizeof (endpoint));
		if (! res[i]->ep.ep_val) {
			nis_freeservlist(res);
			xdr_free(xdr_directory_obj, (char *)&slist);
			return (NULL);
		}
		for (k = 0; k < nep; k++) {
			res[i]->ep.ep_val[k].uaddr = strdup(eps[k].uaddr);
			if (! res[i]->ep.ep_val[k].uaddr) {
				nis_freeservlist(res);
				xdr_free(xdr_directory_obj, (char *)&slist);
				return (NULL);
			}
			res[i]->ep.ep_val[k].family = strdup(eps[k].family);
			if (! res[i]->ep.ep_val[k].family) {
				nis_freeservlist(res);
				xdr_free(xdr_directory_obj, (char *)&slist);
				return (NULL);
			}
			res[i]->ep.ep_val[k].proto = strdup(eps[k].proto);
			if (! res[i]->ep.ep_val[k].proto) {
				nis_freeservlist(res);
				xdr_free(xdr_directory_obj, (char *)&slist);
				return (NULL);
			}
		}
	}
	xdr_free(xdr_directory_obj, (char *)&slist);
	return (res);
}

/*
 * nis_tagproc(server, proc, tags, num);
 *
 * This internal function can call either of the tag list functions.
 * Both nis_status and nis_servstate call it with a different procedure
 * number.
 */
static nis_error
__nis_tagproc(
	nis_server	*srv,	/* Server to talk to 	*/
	rpcproc_t	proc,	/* Procedure to call 	*/
	nis_tag		*tags,	/* Tags to send		*/
	int		ntags,	/* The number available	*/
	nis_tag		**result) /* the resulting tags */
{
	nis_error err;
	nis_call_state state;
	nis_taglist	tlist, tresult;

	__nis_init_call_state(&state);
	state.srv = srv;
	state.nsrv = 1;
	state.timeout.tv_sec = NIS_TAG_TIMEOUT;

	tlist.tags.tags_len = ntags;
	tlist.tags.tags_val = tags;
	(void) memset((char *)&tresult, 0, sizeof (tresult));
	err = nis_call(&state, proc,
			(xdrproc_t)xdr_nis_taglist, (char *)&tlist,
			(xdrproc_t)xdr_nis_taglist, (char *)&tresult);
	__nis_reset_call_state(&state);

	if (err == NIS_SUCCESS)
		*result = tresult.tags.tags_val;
	else
		*result = NULL;

	return (err);
}

/*
 * nis_status(server, tags, num);
 *
 * This function is used to retrieve statistics from the NIS server.
 * The variable 'server' contains a pointer to a struct nis_server
 * which has the name of the server one wishes to gather statistics
 * from.
 */
nis_error
nis_stats(nis_server *srv, nis_tag *tags, int ntags, nis_tag **result)
{
	return (__nis_tagproc(srv, NIS_STATUS, tags, ntags, result));
}

/*
 * nis_servstate(server, tags, num);
 *
 * This function is used to set state variables on a particular server
 * The variable 'server' contains a pointer to a struct nis_server
 * which has the name of the server one wishes to gather statistics
 * from.
 */
nis_error
nis_servstate(nis_server *srv, nis_tag *tags, int ntags, nis_tag **result)
{
	return (__nis_tagproc(srv, NIS_SERVSTATE, tags, ntags, result));
}

/*
 * nis_freetags()
 *
 * This function frees up memory associated with the result of a tag
 * based call. It must be called to free a taglist returned by nis_stats
 * or nis_servstate;
 */

void
nis_freetags(nis_tag *tags, int ntags)
{
	int	i;

	if (! tags)
		return;
	for (i = 0; i < ntags; i++) {
		if (tags[i].tag_val)
			free(tags[i].tag_val);
	}
	free(tags);
}
