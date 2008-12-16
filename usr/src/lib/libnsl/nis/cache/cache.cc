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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "mt.h"
#include <stdio.h>
#include <ctype.h>
#include <malloc.h>
#include <string.h>
#include <values.h>
#include <syslog.h>
#include "cache.h"
#include "cold_start.h"
#include "nis_cache.h"

int __nis_debuglevel = 0;
extern char *__nis_server;

extern "C" {
static int compare(const void *, const void *);
}

NisCache::NisCache()
{
	mutex_init(&gen_lock, USYNC_THREAD, NULL);
	gen = 0;
	cold_start_dir = nis_domain_of(nis_local_host());
}

NisCache::~NisCache()
{
}

nis_error
NisCache::bindReplica(char *dname, nis_bound_directory **binding)
{
	nis_error err;

	/* see if directory is already in cache */
	err = searchDir(dname, binding, 0);
	if (err == NIS_SUCCESS)
		return (err);

	if (err == NIS_CACHEEXPIRED && *binding != 0) {
		/* Exists in local cache, but has expired; refresh it */
		refreshBinding(*binding);
		nis_free_binding(*binding);
		err = searchDir(dname, binding, 0);
		/*
		 * If we're still getting NIS_CACHEEXPIRED, we'll
		 * continue using the expired object until the next
		 * refresh attempt.
		 */
		if (err == NIS_CACHEEXPIRED)
			return (NIS_SUCCESS);
	}

	/* get directory object */
	err = loadDirectory(dname);
	if (err != NIS_SUCCESS)
		return (err);

	/* lookup directory again (it should be there) */
	err = searchDir(dname, binding, 0);
	return (err);
}

nis_error
NisCache::bindMaster(char *dname, nis_bound_directory **ret)
{
	int i;
	nis_error err;
	nis_server *srv;
	nis_bound_directory *binding;

	/*
	 *  See if the directory is in the cache and, if not,
	 *  load it.
	 */
	err = searchDir(dname, &binding, 0);
	if (err == NIS_CACHEEXPIRED && binding != 0) {
		/* Exists in local cache, but has expired; refresh it */
		refreshBinding(binding);
		nis_free_binding(binding);
		err = searchDir(dname, &binding, 0);
		/*
		 * If we're still getting NIS_CACHEEXPIRED, we'll
		 * continue using the expired object until the next
		 * refresh attempt.
		 */
		if (err == NIS_CACHEEXPIRED)
			err = NIS_SUCCESS;
	}
	if (err != NIS_SUCCESS) {
		/* directory is not in the cache, load it */
		err = loadDirectory(dname);
		if (err != NIS_SUCCESS)
			return (err);
		err = searchDir(dname, &binding, 0);
		if (err != NIS_SUCCESS)
			return (err);
	}

	/* see if we have a binding to the master server */
	for (i = 0; i < binding->bep_len; i++) {
		if (binding->bep_val[i].hostnum == 0)
			break;
	}
	if (i < binding->bep_len) {
		*ret = binding;
		return (NIS_SUCCESS);
	}

	/* we have the directory, but not the master server */
	srv = binding->dobj.do_servers.do_servers_val;
	err = pingServers(srv, 1, 1);	/* ping the master server */
	nis_free_binding(binding);
	if (err != NIS_SUCCESS)
		return (err);

	/*
	 *  Search for the directory again.  It should be there and
	 *  should have a binding for the master server.
	 */
	err = searchDir(dname, &binding, 0);
	if (err == NIS_SUCCESS)
		*ret = binding;
	return (err);
}

nis_error
NisCache::bindServer(nis_server *srv, int nsrv, nis_bound_directory **ret)
{
	nis_error err;
	nis_bound_directory *binding;
	directory_obj dobj;

	(void) memset((char *)&dobj, 0, sizeof (directory_obj));
	dobj.do_servers.do_servers_val = srv;
	dobj.do_servers.do_servers_len = nsrv;

	binding = (nis_bound_directory *)
			calloc(1, sizeof (nis_bound_directory));
	if (binding == 0)
		return (NIS_NOMEMORY);
	if (!__nis_xdr_dup((xdrproc_t)xdr_directory_obj,
			(char *)&dobj, (char *)&binding->dobj)) {
		free((void *)binding);
		return (NIS_NOMEMORY);
	}

	/* check to see if we already have a binding to the server */
	addAddresses(binding);

	if (binding->bep_len > 0) {
		*ret = binding;
		return (NIS_SUCCESS);
	}
	nis_free_binding(binding);

	/* we don't have a binding, ping the server */
	err = pingServers(srv, nsrv, 1);
	if (err != NIS_SUCCESS)
		return (err);

	binding = (nis_bound_directory *)
			calloc(1, sizeof (nis_bound_directory));
	if (binding == 0)
		return (NIS_NOMEMORY);
	if (!__nis_xdr_dup((xdrproc_t)xdr_directory_obj,
			(char *)&dobj, (char *)&binding->dobj)) {
		free((void *)binding);
		return (NIS_NOMEMORY);
	}

	addAddresses(binding);

	*ret = binding;
	return (NIS_SUCCESS);
}

nis_error
NisCache::loadDirectory(char *dname)
{
	return (loadDirectory(dname, 0));
}

nis_error
NisCache::loadDirectory(char *dname, int force_finddir)
{
	int i;
	int length;
	char **names;
	int home_refreshed = 0;
	int *refreshed;
	nis_error err;
	nis_bound_directory *binding = NULL;
	nis_bound_directory *new_binding = NULL;
	fd_result *fdres = NULL;

	/* get list of names between coldstart directory and target */
	err = __nis_path(coldStartDir(), dname, &length, &names);
	if (err != NIS_SUCCESS)
		return (err);
	refreshed = (int *)calloc((size_t)length, sizeof (int));
	if (refreshed == NULL) {
		__nis_path_free(names, length);
		return (NIS_NOMEMORY);
	}

again:
	/* get binding for coldstart directory */
	err = searchDir(coldStartDir(), &binding, 0);
	if (err != NIS_SUCCESS) {
		if (err == NIS_CACHEEXPIRED) {
			nis_free_binding(binding);
			binding = NULL;
		}
		/* need to reload cold start */
		if (!readColdStart()) {
			return (NIS_COLDSTART_ERR);
		} else {
			err = searchDir(coldStartDir(), &binding, 0);
			if (err == NIS_CACHEEXPIRED) {
				nis_free_binding(binding);
				binding = NULL;
			}
			if (err != NIS_SUCCESS)
				return (err);
		}
	}

	if (length == 0 && force_finddir) {
		/*
		 * It's the cold start directory, and we really want to
		 * retrieve a new copy from the NIS+ server.
		 */
		fdres = __nis_finddirectory(&binding, coldStartDir());
		if (fdres == NULL) {
			err = NIS_NOMEMORY;
			/* We now expect to just skip the for-loop below */
		} else if (fdres->status != NIS_SUCCESS) {
			err = fdres->status;
			__free_fdresult(fdres);
			fdres = NULL;
			/* Still skipping for-loop */
		} else {
			err = createBinding(fdres);
			fdres = NULL;
		}
	}

	for (i = 0; i < length; i++) {
		err = searchDir(names[i], &new_binding, 0);
		if (err == NIS_SUCCESS) {
			if (binding != NULL)
				nis_free_binding(binding);
			binding = new_binding;
		} else {
			if (err == NIS_CACHEEXPIRED) {
				nis_free_binding(new_binding);
				new_binding = NULL;
			}
			fdres = __nis_finddirectory(&binding, names[i]);
			if (fdres == NULL) {
				err = NIS_NOMEMORY;
				break;
			} else if (fdres->status == NIS_RPCERROR ||
				    fdres->status == NIS_NAMEUNREACHABLE) {
				if (i == 0 && home_refreshed ||
				    i != 0 && refreshed[i-1]) {
					err = fdres->status;
					__free_fdresult(fdres);
					fdres = NULL;
					break;
				}
				if (binding != NULL) {
					removeBinding(binding);
					nis_free_binding(binding);
					binding = NULL;
				}
				if (i == 0)
					home_refreshed = 1;
				else
					refreshed[i-1] = 1;
				__free_fdresult(fdres);
				fdres = NULL;
				goto again;
			} else if (fdres->status != NIS_SUCCESS) {
				err = fdres->status;
				__free_fdresult(fdres);
				fdres = NULL;
				break;
			} else {
				if (binding != NULL) {
					nis_free_binding(binding);
					binding = NULL;
				}
				err = createBinding(fdres);
				fdres = NULL;
				if (err != NIS_SUCCESS)
					break;
			}
			/* get the newly stored binding */
			err = searchDir(names[i], &binding, 0);
			if (err != NIS_SUCCESS)
				break;
		}
	}
	
	if (binding != NULL)
		nis_free_binding(binding);

	__nis_path_free(names, length);
	free((void *)refreshed);
	return (err);
}

nis_error
NisCache::pingServers(nis_server *srv, int nsrv, int quick)
{
	int i;
	int j;
	int n;
	int rank;
	int bound;
	int count;
	int generation;
	nis_error err;
	nis_bound_directory binding;
	endpoint *ep;
	int nep;
	void *local_interfaces;
	int optimal_rank = -1;
	int min_rank = -1;
	int max_rank = -1;

	/*
	 *  If we are rpc.nisd, then we want to make calls into
	 *  our own data base.  Check to see if we are listed.
	 */

	if (__nis_host_is_server(srv, nsrv))
		return (NIS_SUCCESS);

	binding.dobj.do_servers.do_servers_val = srv;
	binding.dobj.do_servers.do_servers_len = nsrv;
	count = 0;
	for (i = 0; i < nsrv; i++)
		count += srv[i].ep.ep_len;
	binding.bep_len = count;
	binding.bep_val = (nis_bound_endpoint *)
			malloc(count * sizeof (nis_bound_endpoint));
	if (binding.bep_val == 0)
		return (NIS_NOMEMORY);

	generation = nextGeneration();

	local_interfaces = __inet_get_local_interfaces();
	n = 0;
	for (i = 0; i < nsrv; i++) {
		ep = srv[i].ep.ep_val;
		nep = srv[i].ep.ep_len;
		for (j = 0; j < nep; j++) {
			rank = rankServer(&srv[i], &ep[j], local_interfaces);
			bound = activeCheck(&ep[j]);
			(void) __endpoint_dup(&ep[j], &binding.bep_val[n].ep);
			binding.bep_val[n].generation = generation;
			binding.bep_val[n].flags = 0;
			if (bound)
				binding.bep_val[n].flags |= NIS_BOUND;
			binding.bep_val[n].rank = rank;
			binding.bep_val[n].hostnum = i;
			binding.bep_val[n].epnum = j;
			binding.bep_val[n].uaddr = NULL;
			binding.bep_val[n].cbep.family = NULL;
			binding.bep_val[n].cbep.proto = NULL;
			binding.bep_val[n].cbep.uaddr = NULL;

			if (optimal_rank == -1 || rank < optimal_rank)
				optimal_rank = rank;
			if (max_rank == -1 || rank > max_rank)
				max_rank = rank;
			if (bound && (min_rank == -1 || rank < min_rank))
				min_rank = rank;

			n++;
		}
	}
	__inet_free_local_interfaces(local_interfaces);

	sortServers(&binding);

	/*
	 *  If we already have an optimal server (min_rank == optimal_rank),
	 *  then we only want to ping other optimal servers.  This gives
	 *  us load balancing among optimal servers.
	 *
	 *  If we already have a server (min_rank != -1), but it is not
	 *  an optimal server, then we only want to ping servers that
	 *  have a better ranking than our current server.  We don't
	 *  want to do load balancing on non-optimal servers.
	 */
	if (min_rank == optimal_rank) {
		max_rank = optimal_rank;
	} else if (min_rank != -1 && optimal_rank < min_rank) {
		max_rank = min_rank - 1;
	}
	binding.optimal_rank = optimal_rank;

	/*
	 *  If pref_option is PREF_ONLY_VAL, then we only want to
	 *  ping servers that have a preference set (rank != MAXINT).
	 *  However, if we don't have any preferred servers at all
	 *  (optimal_rank == MAXINT), then we ignore the pref_option
	 *  because that would prevent us from being able to talk
	 *  to any servers at all.
	 *
	 *  If __nis_server is specified, then we want to behave as
	 *  if PREF_ONLY_VAL is set so that we are guaranteed to
	 *  use the given server if it serves the directory.
	 */
	if ((prefer.pref_option == PREF_ONLY_VAL || __nis_server) &&
	    max_rank == MAXINT && optimal_rank != MAXINT)
		max_rank = MAXINT - 1;

	err = __nis_ping_servers(&binding, max_rank, quick);
	if (err == NIS_SUCCESS) {
		/* extractAddress will free binding.bep_val for us */
		extractAddresses(&binding);
	} else if (binding.bep_val) {
		for (i=0; i < binding.bep_len; i++) {
			ep = &binding.bep_val[i].ep;
			xdr_free((xdrproc_t)xdr_nis_bound_endpoint, (char *)ep);
		}
		free(binding.bep_val);
	}

	return (err);
}

int
NisCache::refreshBinding(nis_bound_directory *binding)
{
	int generation;
	nis_error err;
	directory_obj *dobj;
	nis_bound_directory *check = NULL;

	err = searchDir(binding->dobj.do_name, &check, 0);
	if (err == NIS_SUCCESS) {
		generation = check->generation;
		nis_free_binding(check);
		check = NULL;
		if (binding->generation != generation)
			return (1);	/* someone else did the work */
	} else if (err == NIS_CACHEEXPIRED) {
		nis_free_binding(check);
		check = NULL;
	}

	/*
	 * If this is the cold start directory, then the normal bindReplica()
	 * path through the code will re-load from the cold start file without
	 * going to the NIS+ server. So, we short-circuit by forcing a read
	 * from the wire.
	 */
	if (nis_dir_cmp(binding->dobj.do_name, coldStartDir()) == SAME_NAME) {
		err = loadDirectory(binding->dobj.do_name, 1);
		/*
		 * Temporary problem (?); no need to put back old binding,
		 * since we never removed it in the first place.
		 */
		if (err != NIS_SUCCESS) {
			return (0);
		}
	} else {
		removeBinding(binding);
		err = bindReplica(binding->dobj.do_name, &check);
	}
	if (err != NIS_SUCCESS && err != NIS_NOSUCHNAME && err != NIS_BADNAME &&
		err != NIS_BADOBJECT) {
		/*
		 *  Temporary problem (?); put back the old binding.
		 *  The createBinding()
		 *  routine expects an allocated directory object,
		 *  so we copy the directory object.  We also clear
		 *  the directory object in the binding so that
		 *  it is not freed in nis_free_binding().
		 */
		dobj = (directory_obj *)malloc(sizeof (directory_obj));
		if (dobj) {
			*dobj = binding->dobj;    /* structure copy */
			(void) memset((char *)&binding->dobj, 0,
					sizeof (directory_obj));
			(void) createBinding(dobj);
		}
		return (0);
	}

	if (check != NULL)
		nis_free_binding(check);

	return (1);
}

int
NisCache::refreshAddress(nis_bound_endpoint *bep)
{
	activeRemove(&bep->ep, 1);
	return (0);	/* can't refresh */
#ifdef NOTYET
/*
 *  This code does not work yet.
 */
	struct netconfig *nc;
	endpoint *ep;
	nis_active_endpoint *act;

	ep = &bep->ep;
	if (!activeGet(ep, &act)) {
		return (0);	/* can't refresh */
	}

	if (act->uaddr_generation != bep->generation) {
		/* someone else did the work already */
		free(bep->uaddr);
		bep->uaddr = strdup(act->uaddr);
		bep->generation = act->uaddr_generation;
		activeFree(act);
		return (1);
	}

	/* get new server address */
	free((void *)act->uaddr);
	nc = __nis_get_netconfig(ep);
	free(bep->uaddr);
	bep->uaddr = __nis_get_server_address(nc, ep);
	if (bep->uaddr == NULL) {
		activeRemove(ep, 1);
		return (0);	/* can't refresh */
	}

	act->uaddr_generation = nextGeneration();
	act->uaddr = strdup(bep->uaddr);
	activeRemove(ep, 0);	/* remove old */
	activeAdd(act);		/* add new */
	bep->generation = act->uaddr_generation;

	return (1);
#endif /* NOTYET */
}

int
NisCache::refreshCallback(nis_bound_endpoint *bep)
{
	bep = bep;
	return (0);
#ifdef NOTYET
	/* XXX STILL NEED TO DO THIS CODE XXX */
#endif /* NOTYET */
}

bool_t
NisCache::readColdStart()
{
	directory_obj *dobj;
	nis_error err;

	dobj = (directory_obj *)malloc(sizeof (directory_obj));
	if (dobj == NULL)
		return (0);

	if (!readColdStartFile(COLD_START_FILE, dobj)) {
		free((void *)dobj);
		return (0);
	}

	err = createBinding(dobj);
	if (err != NIS_SUCCESS)
		return (0);
	return (1);
}


bool_t
NisCache::readServerColdStart(uint32_t *exp_time)
{
	directory_obj *dobj;
	nis_error err;
	uint32_t ul;

	/* set default to 1 hour */
	*exp_time = expireTime(ONE_HOUR);

	dobj = (directory_obj *)malloc(sizeof (directory_obj));
	if (dobj == NULL)
		return (0);

	if (!readColdStartFile(COLD_START_FILE, dobj)) {
		free((void *)dobj);
		return (0);
	}

	ul = loadPreferredServers();
	if (ul > 0)
		*exp_time = ul;

	err = createBinding(dobj);
	if (err != NIS_SUCCESS)
		return (0);
	return (1);
}

nis_error
NisCache::createBinding(fd_result *res)
{
	int st;
	XDR xdrs;
	directory_obj *dobj;

	dobj = (directory_obj *)calloc(1, sizeof (directory_obj));
	if (dobj == 0) {
		__free_fdresult(res);
		return (NIS_NOMEMORY);
	}

	xdrmem_create(&xdrs,
		(char *)res->dir_data.dir_data_val,
		res->dir_data.dir_data_len, XDR_DECODE);
	st = xdr_directory_obj(&xdrs, dobj);
	__free_fdresult(res);

	if (!st) {
		free((void *)dobj);
		return (NIS_SYSTEMERROR);
	}

	return (createBinding(dobj));
}

extern "C" void __nis_cache_server_pkeys(directory_obj *);

nis_error
NisCache::createBinding(directory_obj *dobj)
{
	nis_error err;
	nis_bound_directory *binding;
	int nsrv;
	nis_server *srv;

	srv = dobj->do_servers.do_servers_val;
	nsrv = dobj->do_servers.do_servers_len;
	err = pingServers(srv, nsrv, 1);
	if (err != NIS_SUCCESS) {
		xdr_free((xdrproc_t)xdr_directory_obj, (char*)dobj);
		free(dobj);
		return (err);
	}

	binding = (nis_bound_directory *)
			calloc(1, sizeof (nis_bound_directory));
	if (binding == NULL) {
		xdr_free((xdrproc_t)xdr_directory_obj, (char*)dobj);
		free(dobj);
		return (NIS_NOMEMORY);
	}

	/*
	 * Record any new or modified public keys from this directory.
	 * Note that by doing this after the pingServers() above, we're
	 * implicitly assuming that the server ping can proceed without
	 * public keys. That's true right now, but caveat emptor.
	 */
	__nis_cache_server_pkeys(dobj);

	/* set generation and copy directory object into binding */
	binding->generation = nextGeneration();
	binding->dobj = *dobj;	/* structure copy */
	free(dobj);

	addAddresses(binding);
	addBinding(binding);
	nis_free_binding(binding);
	return (NIS_SUCCESS);
}

void
NisCache::printBinding(nis_bound_directory *binding)
{
	if (binding == NULL)
		return;
	if (__nis_debuglevel == 6) {
		printDirectorySpecial(&binding->dobj);
	} else {
		if (__nis_debuglevel)
			nis_print_directory(&binding->dobj);
	}
}

extern "C" void __nis_print_directory_exptime(directory_obj *, uint32_t);

void
NisCache::printBinding_exptime(nis_bound_directory *binding, uint32_t exptime)
{
	if (binding == NULL)
		return;
	if (__nis_debuglevel == 6) {
		printDirectorySpecial(&binding->dobj);
	} else {
		if (__nis_debuglevel)
			__nis_print_directory_exptime(&binding->dobj, exptime);
	}
}

void
NisCache::printActive(nis_active_endpoint *act)
{
	if (act == NULL)
		return;
	(void) printf("\t%s %s %s", act->hostname, act->ep.family,
	    act->ep.proto);
	if (act->uaddr)
		(void) printf(" %s", act->uaddr);
	else
		(void) printf(" %s", act->ep.uaddr);
	if (act->rank == 0)
		(void) printf(" local");
	else if (act->rank == MAXINT)
		(void) printf(" remote");
	else if (act->rank > MAXINT/2)
		(void) printf(" remote(%d)",
		    act->rank - MAXINT);  /* negative rank */
	else
		(void) printf(" remote(%d)", act->rank);
	(void) printf("\n");
}


nis_active_endpoint *
NisCache::activeDup(nis_active_endpoint *src)
{
	nis_active_endpoint *act;

	act = (nis_active_endpoint *)calloc(1, sizeof (nis_active_endpoint));
	if (act == NULL)
		return (NULL);

	(void) __endpoint_dup(&src->ep, &act->ep);
	act->hostname = strdup(src->hostname);
	act->rank = src->rank;
	act->uaddr_generation = src->uaddr_generation;
	act->uaddr = src->uaddr?strdup(src->uaddr):0;
	act->cbep_generation = src->cbep_generation;
	(void) __endpoint_dup(&src->cbep, &act->cbep);

	return (act);
}

void
NisCache::activeFree(nis_active_endpoint *act)
{
	if (act) {
		free((void *)act->ep.family);
		free((void *)act->ep.proto);
		free((void *)act->ep.uaddr);
		free((void *)act->hostname);
		free((void *)act->uaddr);
		free((void *)act->cbep.family);
		free((void *)act->cbep.proto);
		free((void *)act->cbep.uaddr);
	}
	free((void *)act);
}

void *
NisCache::packBinding(nis_bound_directory *binding, int *len)
{
	int status;
	uint_t size;
	void *data;
	XDR xdrs;

	size = xdr_sizeof((xdrproc_t)xdr_nis_bound_directory,
					(char *)binding);
	data = malloc(size);
	if (data == NULL)
		return (NULL);

	xdrmem_create(&xdrs, (char *)data, size, XDR_ENCODE);
	status = xdr_nis_bound_directory(&xdrs, binding);
	if (!status) {
		free(data);
		return (NULL);
	}

	*len = size;
	return (data);
}

nis_bound_directory *
NisCache::unpackBinding(void *data, int len)
{
	XDR xdrs;
	nis_bound_directory *binding;

	binding = (nis_bound_directory *)
		calloc(1, sizeof (nis_bound_directory));
	if (binding == 0)
		return (NULL);

	xdrmem_create(&xdrs, (char *)data, len, XDR_DECODE);

	if (!xdr_nis_bound_directory(&xdrs, binding)) {
		free(binding);
		return (NULL);
	}

	return (binding);
}

void *
NisCache::packActive(nis_active_endpoint *act, int *len)
{
	int status;
	uint_t size;
	void *data;
	XDR xdrs;

	size = xdr_sizeof((xdrproc_t)xdr_nis_active_endpoint,
					(char *)act);
	data = malloc(size);
	if (data == NULL)
		return (NULL);

	xdrmem_create(&xdrs, (char *)data, size, XDR_ENCODE);
	status = xdr_nis_active_endpoint(&xdrs, act);
	if (!status) {
		free(data);
		return (NULL);
	}

	*len = size;
	return (data);
}

nis_active_endpoint *
NisCache::unpackActive(void *data, int len)
{
	XDR xdrs;
	nis_active_endpoint *act;

	act = (nis_active_endpoint *)calloc(1, sizeof (nis_active_endpoint));
	if (act == 0)
		return (NULL);

	xdrmem_create(&xdrs, (char *)data, len, XDR_DECODE);

	if (!xdr_nis_active_endpoint(&xdrs, act)) {
		free(act);
		return (NULL);
	}

	return (act);
}

uint32_t
NisCache::expireTime(uint32_t ttl)
{
	struct timeval now;

	(void) gettimeofday(&now, NULL);
	return (ttl + (uint32_t)now.tv_sec);
}

int
NisCache::nextGeneration()
{
	int n;

	mutex_lock(&gen_lock);
	n = gen++;
	mutex_unlock(&gen_lock);
	return (n);
}

void
NisCache::printDirectorySpecial(directory_obj *dobj)
{
	int i;
	char *name;

	name = dobj->do_name;
	(void) printf("'%s':", name?name:"");
	switch (dobj->do_type) {
		case NIS :
			(void) printf("NIS:");
			break;
		case SUNYP :
			(void) printf("YP:");
			break;
		case DNS :
			(void) printf("DNS:");
			break;
		default :
			(void) printf("%d:", dobj->do_type);
			break;
	}
	(void) printf("\"%d:%d:%d\"",
		dobj->do_ttl/3600,
		(dobj->do_ttl - (dobj->do_ttl/3600)*3600)/60,
		(dobj->do_ttl % 60));
	for (i = 0; i < dobj->do_servers.do_servers_len; i++) {
		if (i == 0)
			(void) printf(":");
		else
			(void) printf(",");
		name = dobj->do_servers.do_servers_val[i].name;
		(void) printf("%s", name?name:"");
	}
	(void) printf("\n");
}

int
NisCache::rankServer(nis_server *srv, endpoint *ep, void *local_interfaces)
{
	int nlen;
	int rank;

	/*
	 *  If __nis_server is specified, then we want that server to
	 *  have the best ranking and all other server to have the
	 *  worst ranking.
	 */
	if (__nis_server) {
		nlen = strlen(__nis_server);
		if (strncasecmp(__nis_server, srv->name, nlen) == 0 &&
		    (srv->name[nlen] == '.' || srv->name[nlen] == '\0')) {
			return (0);
		}
		return (MAXINT);
	}

	if (prefer.matchHost(srv->name, ep->uaddr, &rank))
		return (rank);

	if (__nis_server_is_local(ep, local_interfaces))
		return (0);

	return (MAXINT);
}

void
NisCache::sortServers(nis_bound_directory *binding)
{
	qsort(binding->bep_val, binding->bep_len,
		sizeof (nis_bound_endpoint), compare);
}

extern "C" {
static
int
compare(const void *e1, const void *e2)
{
	nis_bound_endpoint *bep1 = (nis_bound_endpoint *)e1;
	nis_bound_endpoint *bep2 = (nis_bound_endpoint *)e2;

	return (bep1->rank - bep2->rank);
}
}


void
NisCache::restorePreference()
{
	prefer.restoreList();
}


void
NisCache::backupPreference()
{
	prefer.backupList();
}


void
NisCache::delBackupPref()
{
	prefer.deleteBackupList();
}


void
NisCache::resetPreference()
{
	prefer.~HostList();
}


void
NisCache::writePreference(FILE *fp)
{
	(void) prefer.dumpList(fp);
	prefer.dumpOption(fp);
}


void
NisCache::mergeOption(const char *value)
{
	if (value && *value) {
		if (strcasecmp(value, PREF_ALL) == 0) {
			prefer.addOption(PREF_ALL_VAL);
		} else if (strcasecmp(value, PREF_ONLY) == 0) {
			prefer.addOption(PREF_ONLY_VAL);
		}
	}
}


void
NisCache::mergePreference(char *value)
{
	int rank;
	int sign;
	char *host = NULL;
	char *interface;

	if (value == NULL || *value == '\0')
		return;

	while (*value) {
		interface = NULL;
		rank = 0;
		while (isspace(*value))
			value++;
		if (*value == '\0')
			break;

		/* server info */
		host = value;
		while (*value && !isspace(*value) &&
			*value != ',' && *value != '(' && *value != ':' &&
			*value != '/')
			value++;

		/* interface info */
		if (*value == ':' || *value == '/') {
			*value++ = '\0';
			interface = value;
			while (*value && !isspace(*value) &&
				*value != ',' && *value != '(')
				value ++;
		}

		/* weight info */
		if (*value == '(') {
			*value++ = '\0';
			if (*value == '-') {
				value++;
				sign = -1;
			} else {
				if (*value == '+')
					value++;
				sign = 1;
			}
			rank = 0;
			while (isdigit(*value)) {
				rank = 10 * rank + *value - '0';
				value++;
			}
			if (*value == ')')
				value++;
			rank = sign * rank;
		}

		while (*value == ',' || isspace(*value))
			*value++ = '\0';

		if (rank < 0)
			prefer.addHost(host, interface, MAXINT + rank);
		else
			prefer.addHost(host, interface, rank);
	}
}

/*
 *  Create active server entries for each bound endpoint and then
 *  free the list of bound endpoints.  This allows us to pack
 *  a bound directory without the bound endpoints, which saves
 *  space.
 */
void
NisCache::extractAddresses(nis_bound_directory *binding)
{
	int i;
	nis_server *srv;
	endpoint *ep;
	int next_gen;
	nis_bound_endpoint *bep = binding->bep_val;
	int nbep = binding->bep_len;
	nis_active_endpoint *act;

	next_gen = nextGeneration();
	for (i = 0; i < nbep; i++) {
		if ((bep[i].flags & NIS_BOUND) == 0) {
			xdr_free((xdrproc_t)xdr_nis_bound_endpoint,
					(char *)&bep[i]);
			continue;
		}

		srv = binding->dobj.do_servers.do_servers_val;
		ep = &srv[bep[i].hostnum].ep.ep_val[bep[i].epnum];

		if (activeCheck(ep)) {
			xdr_free((xdrproc_t)xdr_nis_bound_endpoint,
					(char *)&bep[i]);
			continue;
		}

		act = (nis_active_endpoint *)
			calloc(1, sizeof (nis_active_endpoint));
		if (act == NULL) {
			xdr_free((xdrproc_t)xdr_nis_bound_endpoint,
					(char *)&bep[i]);
			continue;
		}

		(void) __endpoint_dup(ep, &act->ep);
		act->hostname = strdup(srv[bep[i].hostnum].name);
		act->rank = bep[i].rank;
		act->uaddr_generation = next_gen;
		if (bep[i].uaddr)
			act->uaddr = strdup(bep[i].uaddr);
		else
			act->uaddr = 0;
		act->cbep_generation = next_gen;
		act->cbep.family = 0;
		act->cbep.proto = 0;
		act->cbep.uaddr = 0;

		activeRemove(ep, 0);
		activeAdd(act);

		xdr_free((xdrproc_t)xdr_nis_bound_endpoint, (char *)&bep[i]);
	}

	free(binding->bep_val);
	binding->bep_val = 0;
	binding->bep_len = 0;
}

/*
 *  Create a bound endpoint for every active server for a directory.
 */
void
NisCache::addAddresses(nis_bound_directory *binding)
{
	int i;
	int j;
	int n;
	nis_server *srv;
	int nsrv;
	endpoint *ep;
	int nep;
	nis_bound_endpoint *bep;
	int nbep = 0;
	nis_active_endpoint *act;
	directory_obj *dobj;
	int min_rank = -1;

	for (i = 0; i < binding->bep_len; i++) {
		xdr_free((xdrproc_t)xdr_nis_bound_endpoint,
			(char *)&binding->bep_val[i]);
	}
	free((void *)binding->bep_val);
	binding->bep_len = 0;
	binding->bep_val = NULL;

	srv = binding->dobj.do_servers.do_servers_val;
	nsrv = binding->dobj.do_servers.do_servers_len;

	/* count the number of bound endpoints */
	for (i = 0; i < nsrv; i++) {
		ep = srv[i].ep.ep_val;
		nep = srv[i].ep.ep_len;
		for (j = 0; j < nep; j++) {
			if (activeCheck(&ep[j]))
				nbep++;
		}
	}

	if (nbep == 0) {
		return;
	}

	bep = (nis_bound_endpoint *)calloc(nbep, sizeof (nis_bound_endpoint));
	if (bep == NULL) {
		return;
	}

	/* fill in list of bound endpoints */
	n = 0;
	for (i = 0; i < nsrv; i++) {
		ep = srv[i].ep.ep_val;
		nep = srv[i].ep.ep_len;
		for (j = 0; j < nep; j++) {
			if (!activeGet(&ep[j], &act))
				continue;

			/*
			 *  Another thread could have changed
			 *  the list of active servers.
			 */
			if (n >= nbep)
				break;

			(void) __endpoint_dup(&ep[j], &bep[n].ep);
			bep[n].generation = act->uaddr_generation;
			bep[n].rank = act->rank;
			bep[n].flags = NIS_BOUND;
			bep[n].hostnum = i;
			bep[n].epnum = j;
			bep[n].uaddr = act->uaddr?strdup(act->uaddr):NULL;
			(void) __endpoint_dup(&act->cbep, &bep[n].cbep);
			activeFree(act);

			if (min_rank == -1 || bep[n].rank < min_rank)
				min_rank = bep[n].rank;

			n++;
		}
	}

	binding->min_rank = min_rank;
	binding->bep_val = bep;
	binding->bep_len = n;
	sortServers(binding);

	/*
	 *  If we only want to talk to preferred servers, remove
	 *  non-preferred servers (rank == MAXINT).  If the directory
	 *  is not served by a preferred server at all, then we
	 *  ignore the option.
	 */
	dobj = &binding->dobj;
	if (prefer.pref_option == PREF_ONLY_VAL && prefer.serves(dobj)) {
		for (i = 0; i < n; i++) {
			if (bep[i].rank == MAXINT) {
				binding->bep_len = i;
				break;
			}
		}
	}
}

void
NisCache::rerankServers()
{
	int i;
	int n;
	int rank;
	nis_server srv;
	nis_active_endpoint **actlist;
	void *local_interfaces = __inet_get_local_interfaces();

	n = getAllActive(&actlist);
	for (i = 0; i < n; i++) {
		srv.name = actlist[i]->hostname;
		rank = rankServer(&srv, &actlist[i]->ep, local_interfaces);
		if (actlist[i]->rank != rank) {
			activeRemove(&actlist[i]->ep, 0);
			actlist[i]->rank = rank;
			activeAdd(actlist[i]);
		} else {
			activeFree(actlist[i]);
		}
	}
	free((void *)actlist);
	__inet_free_local_interfaces(local_interfaces);
}

/*
 *  These are stubs so that we can avoid using pure virtual functions
 *  in the NisCache class.  If we use pure virtual functions, then
 *  applications would have to link with -lC.
 */
int
NisCache::okay()
{
	return (1);
}


/*
 * Dot File routines.  Dot file format:
 *	line 1: TTL "%u"
 *	line 2: [optional] server list separated by comma "%s/%s(%d)"
 *	line 3: [optional] preference type "%s"
 *
 * Load from dot file.  If file exists and TTL has not expired, load the
 * information.  Otherwise, don't bother.
 */

uint32_t
NisCache::loadDotFile()
{
	FILE *fp;
	char *p, buf[2048];
	size_t l;
	uint32_t exptime;
	struct timeval now;

	fp = fopen(DOT_FILE, "rF");
	if (fp == NULL)
		return (0);

	/*
	 * read TTL: TTL must be the first line in this file
	 * unless the file is empty.
	 */
	if ((p = fgets(buf, sizeof (buf), fp)) == NULL) {
		/* empty file */
		(void) fclose(fp);
		return (0);
	}
	if (!isdigit(*p)) {
		/* invalid TTL */
		syslog(LOG_ERR, "invalid TTL in %s", DOT_FILE);
		(void) fclose(fp);
		return (0);
	}
	exptime = (uint32_t)atol(p);
	(void) gettimeofday(&now, NULL);
	if (exptime < now.tv_sec) {
		/* TTL expired */
		(void) fclose(fp);
		return (0);
	}

	/*
	 * read preferred server list
	 * This line can be empty
	 */
	if ((p = fgets(buf, sizeof (buf), fp)) == NULL) {
		/* file without any preferred info */
		(void) fclose(fp);
		return (exptime);
	}
	l = strlen(p) - 1;
	if (p[l] == '\n')
		p[l] = '\0';
	mergePreference(p);

	/*
	 * read options: valid options are "all" and
	 * "pref_only".  Default is "all".
	 */
	if ((p = fgets(buf, sizeof (buf), fp)) == NULL) {
		/* file without any preferred info */
		(void) fclose(fp);
		mergeOption(PREF_ALL);
		return (exptime);
	}
	l = strlen(p) - 1;
	if (p[l] == '\n')
		p[l] = '\0';
	if (l != 0)
		mergeOption(p);
	else
		mergeOption(PREF_ALL);

	/* ignore the rest of the file */
	(void) fclose(fp);
	return (exptime);
}


uint32_t
NisCache::loadPreferredServers()
{
	return (0);
}

uint32_t
NisCache::refreshCache()
{
	return (0);
}

int
NisCache::checkUp()
{
	return (1);
}

nis_error
NisCache::searchDir(char *, nis_bound_directory **binding, int)
{
	*binding = NULL;

	return (NIS_SYSTEMERROR);
}

void
NisCache::print()
{
}

void
NisCache::addBinding(nis_bound_directory *)
{
}

void
NisCache::removeBinding(nis_bound_directory *)
{
}

int
NisCache::getStaleEntries(nis_bound_directory ***)
{
	return (0);
}

int
NisCache::getAllEntries(nis_bound_directory ***)
{
	return (0);
}

int
NisCache::getAllActive(nis_active_endpoint ***)
{
	return (0);
}

void
NisCache::activeAdd(nis_active_endpoint *)
{
}

void
NisCache::activeRemove(endpoint *, int)
{
}

int
NisCache::activeCheck(endpoint *)
{
	return (0);
}

int
NisCache::activeGet(endpoint *, nis_active_endpoint **)
{
	return (0);
}

char *
NisCache::coldStartDir()
{
	return (cold_start_dir);
}

int
NisCache::resetBinding(nis_bound_directory *binding) {
	return (refreshBinding(binding));
}

/*
 *  HostList Routines.
 */

HostList::HostList()
{
	entries = NULL;
	pref_option = PREF_ALL_VAL;
}

HostList::~HostList()
{
	HostEnt *del;

	while (entries) {
		del = entries;
		entries = entries->next;
		if (del->name)
			free(del->name);
		if (del->interface)
			free(del->interface);
		free((void *)del);
	}
	entries = NULL;
	pref_option = PREF_ALL_VAL;
}


void
HostList::deleteList()
{
	HostEnt *del;

	while (entries) {
		del = entries;
		entries = entries->next;
		if (del->name)
			free(del->name);
		if (del->interface)
			free(del->interface);
		free((void *)del);
	}
	entries = NULL;
	pref_option = PREF_ALL_VAL;
}


void
HostList::deleteBackupList()
{
	HostEnt *del;

	while (old_entries) {
		del = old_entries;
		old_entries = old_entries->next;
		if (del->name)
			free(del->name);
		if (del->interface)
			free(del->interface);
		free((void *)del);
	}
	old_entries = NULL;
	old_pref_option = PREF_ALL_VAL;
}


void
HostList::backupList()
{
	if (old_entries)
		deleteBackupList();
	old_entries = entries;
	entries = NULL;
	old_pref_option = pref_option;
}


void
HostList::restoreList()
{
	if (entries)
		deleteList();
	entries = old_entries;
	old_entries = NULL;
	pref_option = old_pref_option;
}


void
HostList::addHost(char *srv, char *interface, int rank)
{
	int dummy;
	HostEnt *ent;
	HostEnt *prev;
	HostEnt *scan;

	if (srv == NULL || *srv == '\0')
		return;

	/* don't add value again if it is already there */
	if (checkHost(srv, interface, &dummy))
		return;

	ent = (HostEnt *)malloc(sizeof (HostEnt));
	if (ent == NULL)
		return;

	if (srv) {
		ent->name = strdup(srv);
		if (ent->name == NULL) {
			free((void *)ent);
			return;
		}
	} else
		ent->name = NULL;

	if (interface && *interface) {
		ent->interface = strdup(interface);
		if (ent->interface == NULL) {
			if (ent->name != NULL)
				free(ent->name);
			free((void *)ent);
			return;
		}
	} else
		ent->interface = NULL;
	ent->rank = rank;
	ent->next = NULL;
	prev = NULL;
	scan = entries;
	while (scan) {
		prev = scan;
		scan = scan->next;
	}
	if (prev)
		prev->next = ent;
	else
		entries = ent;
}

int
HostList::checkHost(char *check, char *interface, int *rank)
{
	HostEnt *scan;

	for (scan = entries; scan; scan = scan->next) {
		if (strcasecmp(check, scan->name) == 0) {
			if (interface) {
				if (scan->interface &&
					strcasecmp(scan->interface, interface)
									== 0) {
					*rank = scan->rank;
					return (1);
				}
			} else {
				/*
				 * To match: both interfaces must
				 * be NULL.
				 */
				if (!scan->interface) {
					*rank = scan->rank;
					return (1);
				}
			}
		}
	}
	return (0);
}

/*
 * NOTE: uaddr and name must always have a value.
 *
 * Matching criteria:
 *	1. name argument and scan->name must match
 *	2. a) find entry with interface matching the uaddr (IP
 *	      address portion).
 *	   b) if a) is not found, find entry with NO interface defined
 *	      (wildcard).
 */

int
HostList::matchHost(char *name, char *uaddr, int *rank)
{
	int nlen, ulen, found;
	HostEnt *scan;

	found = 0;
	ulen = strlen(uaddr);
	for (ulen--; ulen > 0 && uaddr[ulen] != '.'; )
		ulen--;
	for (ulen--; ulen > 0 && uaddr[ulen] != '.'; )
		ulen--;

	for (scan = entries; scan; scan = scan->next) {
		nlen = strlen(scan->name);
		if (strncasecmp(scan->name, name, nlen) == 0 &&
		    (name[nlen] == '.' || name[nlen] == '\0')) {
			if (!scan->interface || *(scan->interface) == '\0') {
				if (!found) {
					found = 1;
					*rank = scan->rank;
				}
			} else {
				if (strncasecmp(scan->interface, uaddr, ulen)
								== 0) {
					found = 1;
					*rank = scan->rank;
					break;
				}
			}
		}
	}
	return (found);
}

/*
 *  Check to see if a directory object is served by a preferred
 *  server (rank != MAXINT).
 */
int
HostList::serves(directory_obj *dobj)
{
	int i;
	int j;
	int rank;
	endpoint *ep;
	int nep;
	nis_server *srv;
	int nsrv;

	srv = dobj->do_servers.do_servers_val;
	nsrv = dobj->do_servers.do_servers_len;
	for (i = 0; i < nsrv; i++) {
		ep = srv[i].ep.ep_val;
		nep = srv[i].ep.ep_len;
		for (j = 0; j < nep; j++) {
			if (matchHost(srv[i].name, ep[j].uaddr, &rank)) {
				if (rank != MAXINT)
					return (1);
			}
		}
	}
	return (0);
}


int
HostList::dumpList(FILE *fp)
{
	HostEnt *scan;
	int     n = 0;

	for (scan = entries; scan; scan = scan->next) {
		if (n++)
			(void) fprintf(fp, ",");
		(void) fprintf(fp, "%s", scan->name);
		if (scan->interface && *scan->interface)
			(void) fprintf(fp, "/%s", scan->interface);
		(void) fprintf(fp, "(%d)", scan->rank);
	}
	(void) fprintf(fp, "\n");
	return (n);
}


void
HostList::addOption(int value)
{
	pref_option = value;
}


void
HostList::dumpOption(FILE *fp)
{
	switch (pref_option) {
		case PREF_ALL_VAL:
			(void) fprintf(fp, "%s\n", PREF_ALL);
			break;
		case PREF_ONLY_VAL:
			(void) fprintf(fp, "%s\n", PREF_ONLY);
			break;
	}
}
