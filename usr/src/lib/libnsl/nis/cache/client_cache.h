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
 *	Copyright (c) 1996, by Sun Microsystems, Inc.
 *	All rights reserved.
 */

#ifndef	__CLIENT_CACHE_H
#define	__CLIENT_CACHE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <netdir.h>
#include <netconfig.h>
#include "mapped_cache.h"

class NisClientCache : public NisMappedCache {
    public:
	NisClientCache(nis_error &error);
	~NisClientCache();

	int okay();
	nis_error bindReplica(char *dname, nis_bound_directory **binding);
	nis_error bindMaster(char *dname, nis_bound_directory **binding);
	nis_error bindServer(nis_server *srv, int nsrv,
			nis_bound_directory **binding);
	int refreshBinding(nis_bound_directory *binding);
	int refreshAddress(nis_bound_endpoint *bep);
	int refreshCallback(nis_bound_endpoint *bep);
	bool_t readColdStart();

    private:
	CLIENT *mgr_clnt;	/* rpc handle connected to cache manager */
	netconfig *ticlts;	/* cached netconfig entry for ticlts */
	char *curUaddr;		/* uaddr of cache manager */
	int curFd;		/* fd in mgr_clnt */
	dev_t curRdev;
	pid_t curPid;
	int cache_is_bad;

	CLIENT *clientHandle();
	void setClntState();
	int checkClntState();
	void cacheIsBad();
};

#endif	/* __CLIENT_CACHE_H */
