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

#include "mt.h"
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include "client_cache.h"
#include "nis_cache.h"

NisClientCache::NisClientCache(nis_error &err)
	: NisMappedCache(err, 0, 0)
{
	mgr_clnt = NULL;
	ticlts = NULL;
	curUaddr = NULL;
	cache_is_bad = 0;
	if (!checkUp())
		err = NIS_RPCERROR;
}

NisClientCache::~NisClientCache()
{
}

int
NisClientCache::okay()
{
	return (cache_is_bad == 0);
}

nis_error
NisClientCache::bindReplica(char *dname, nis_bound_directory **binding)
{
	nis_error err;
	nis_error *errp;
	CLIENT *clnt;

	err = searchDir(dname, binding, 0);
	if (err != NIS_SUCCESS) {
		clnt = clientHandle();
		if (clnt == NULL) {
			err = NIS_RPCERROR;
			cacheIsBad();
		} else {
			errp = nis_cache_bind_replica_2(&dname, clnt);
			if (errp == NULL) {
				err = NIS_RPCERROR;
				cacheIsBad();
			} else {
				err = *errp;
			}
		}
		/* cache manager should have loaded it */
		if (err == NIS_SUCCESS)
			err = searchDir(dname, binding, 0);
	}
	return (err);
}

nis_error
NisClientCache::bindMaster(char *dname, nis_bound_directory **ret)
{
	int i;
	nis_error err;
	nis_bound_directory *binding;
	nis_error *errp;
	CLIENT *clnt;

	/* check to see if we already have a binding to the master server */
	err = bindReplica(dname, &binding);
	if (err != NIS_SUCCESS)
		return (err);
	for (i = 0; i < binding->bep_len; i++) {
		if (binding->bep_val[i].hostnum == 0) {
			*ret = binding;
			return (NIS_SUCCESS);
		}
	}
	nis_free_binding(binding);

	clnt = clientHandle();
	if (clnt == NULL) {
		err = NIS_RPCERROR;
		cacheIsBad();
	} else {
		errp = nis_cache_bind_master_2(&dname, clnt);
		if (errp == NULL) {
			err = NIS_RPCERROR;
			cacheIsBad();
		} else {
			err = *errp;
		}
	}
	/* cache manager should have loaded it and found master server */
	if (err == NIS_SUCCESS)
		err = searchDir(dname, &binding, 0);
	if (err == NIS_SUCCESS)
		*ret = binding;
	return (err);
}

nis_error
NisClientCache::bindServer(nis_server *srv, int nsrv, nis_bound_directory **ret)
{
	int i;
	nis_error err;
	nis_bound_directory *binding;
	bind_server_arg req;
	nis_error *errp;
	CLIENT *clnt;
	directory_obj dobj;

	(void) memset((char *)&dobj, 0, sizeof (directory_obj));
	dobj.do_servers.do_servers_val = srv;
	dobj.do_servers.do_servers_len = nsrv;

	binding = (nis_bound_directory *)
		    calloc(1, sizeof (nis_bound_directory));
	if (binding == NULL)
		return (NIS_NOMEMORY);
	if (!__nis_xdr_dup((xdrproc_t)xdr_directory_obj,
			    (char *)&dobj, (char *)&binding->dobj)) {
		free((void *)binding);
		return (NIS_NOMEMORY);
	}


	addAddresses(binding);
	for (i = 0; i < binding->bep_len; i++) {
		if (binding->bep_val[i].flags & NIS_BOUND) {
			*ret = binding;
			return (NIS_SUCCESS);
		}
	}

	/* this is no good for us */
	free(binding->bep_val);

	clnt = clientHandle();
	if (clnt == NULL) {
		err = NIS_RPCERROR;
		cacheIsBad();
	} else {
		req.srv = srv;
		req.nsrv = nsrv;
		errp = nis_cache_bind_server_2(&req, clnt);
		if (errp == NULL) {
			err = NIS_RPCERROR;
			cacheIsBad();
		} else {
			err = *errp;
		}
	}
	if (err == NIS_SUCCESS) {
		addAddresses(binding);
		*ret = binding;
	} else {
		free((void *)binding);
	}
	return (err);
}

int
NisClientCache::refreshBinding(nis_bound_directory *binding)
{
	CLIENT *clnt;
	refresh_res *res;

	clnt = clientHandle();
	if (clnt == NULL) {
		cacheIsBad();
		return (0);
	}
	res = nis_cache_refresh_binding_2(binding, clnt);
	if (res == NULL) {
		cacheIsBad();
		return (0);
	}
	if (res->changed == 0) {
		xdr_free((xdrproc_t)xdr_refresh_res, (char *)res);
		return (0);
	}
	xdr_free((xdrproc_t)xdr_refresh_res, (char *)res);
	return (1);
}

int
NisClientCache::refreshAddress(nis_bound_endpoint *bep)
{
	CLIENT *clnt;
	refresh_res *res;

	clnt = clientHandle();
	if (clnt == NULL) {
		cacheIsBad();
		return (0);
	}
	res = nis_cache_refresh_address_2(bep, clnt);
	if (res == NULL) {
		cacheIsBad();
		return (0);
	}
	if (res->changed == 0) {
		xdr_free((xdrproc_t)xdr_refresh_res, (char *)res);
		return (0);
	}
	free(bep->uaddr);
	bep->uaddr = strdup(res->ep.uaddr);
	xdr_free((xdrproc_t)xdr_refresh_res, (char *)res);
	return (1);
}

int
NisClientCache::refreshCallback(nis_bound_endpoint *bep)
{
	CLIENT *clnt;
	refresh_res *res;

	clnt = clientHandle();
	if (clnt == NULL) {
		cacheIsBad();
		return (0);
	}
	res = nis_cache_refresh_callback_2(bep, clnt);
	if (res == NULL) {
		cacheIsBad();
		return (0);
	}
	if (res->changed == 0) {
		xdr_free((xdrproc_t)xdr_refresh_res, (char *)res);
		return (0);
	}
	bep->cbep = res->ep;	/* structure copy */
	/* don't xdr_free result because we are using pointers */
	return (1);
}

bool_t
NisClientCache::readColdStart()
{
	void *res;
	CLIENT *clnt;

	clnt = clientHandle();
	if (clnt == NULL) {
		cacheIsBad();
		return (0);
	}
	res = nis_cache_read_coldstart_2(NULL, clnt);
	if (res == NULL) {
		cacheIsBad();
		return (0);
	}
	return (1);
}

CLIENT *
NisClientCache::clientHandle()
{
	struct netbuf *svcaddr;
	struct timeval tv;

	if (!checkUp()) {
		return (NULL);
	}
	if (mgr_clnt != NULL) {
		if (checkClntState())
			return (mgr_clnt);
		/* client handle is no longer valid */
		clnt_destroy(mgr_clnt);
		mgr_clnt = NULL;
	}

	/*
	 * We cache this so that we only have to get it once.
	 * It never changes.
	 */
	if (ticlts == NULL) {
		ticlts = getnetconfigent("ticlts");
		if (ticlts == NULL)
			return (NULL);
	}

	free((void *)curUaddr);
	curUaddr = getUaddr();
	if (curUaddr == NULL)
		return (NULL);
	svcaddr = uaddr2taddr(ticlts, curUaddr);
	if (svcaddr == NULL)
		return (NULL);
	mgr_clnt = clnt_tli_create(RPC_ANYFD, ticlts, svcaddr,
		CACHEPROG, CACHE_VER_2, 0, 0);
	if (mgr_clnt == NULL)
		return (NULL);
	netdir_free((void *)svcaddr, ND_ADDR);
	(void) clnt_control(mgr_clnt, CLSET_FD_CLOSE, (char *)NULL);
	tv.tv_sec = 60 * 60;	/* 1 hour (approximately infinite) */
	tv.tv_usec = 0;
	(void) clnt_control(mgr_clnt, CLSET_TIMEOUT, (char *)&tv);
	if (clnt_control(mgr_clnt, CLGET_FD, (char *)&curFd))
		(void) fcntl(curFd, F_SETFD, 1);	/* close on exec */

	setClntState();

	return (mgr_clnt);
}

void
NisClientCache::setClntState()
{
	struct stat stbuf;

	if (clnt_control(mgr_clnt, CLGET_FD, (char *)&curFd) != TRUE ||
	    fstat(curFd, &stbuf) == -1) {
	    syslog(LOG_DEBUG, "NIS+ cache client: can't get rdev");
		    curRdev = (dev_t)-1L;
	} else {
		curRdev = stbuf.st_rdev;
	}

	curPid = getpid();
}

int
NisClientCache::checkClntState()
{
	char *uaddr;
	struct stat stbuf;

	/* check rdev of connection file descriptor */
	/* do this first so that CLSET_FD_NCLOSE flag will be set if needed */
	if (curRdev != (dev_t)-1L) {
		if (fstat(curFd, &stbuf) == -1) {
			/* probably because file descriptor was closed */
			syslog(LOG_DEBUG,
				"NIS+ cache client:  can't stat %d", curFd);
			/* it's not our fd, so don't try to close it */
			(void) clnt_control(mgr_clnt, CLSET_FD_NCLOSE,
			    (char *)NULL);
			return (0);
		}
		if (curRdev != stbuf.st_rdev) {
			syslog(LOG_DEBUG,
		"NIS+ cache client:  fd %d changed, old=0x%lx, new=0x%lx",
				curFd, curRdev, stbuf.st_rdev);
			/* it's not our fd, so don't try to close it */
			(void) clnt_control(mgr_clnt, CLSET_FD_NCLOSE,
			    (char *)NULL);
			return (0);
		}
	}

	/* check uaddr of cache manager */
	uaddr = getUaddr();
	if (uaddr == NULL || curUaddr == NULL || strcmp(uaddr, curUaddr) != 0) {
		if (curUaddr != NULL)
			free(curUaddr);
		curUaddr = uaddr;
		return (0);
	}
	free(uaddr);

	/* check pid */
	if (curPid != getpid())
		return (0);

	/* it appears to be okay */
	return (1);
}

void
NisClientCache::cacheIsBad()
{
	cache_is_bad = 1;
}
