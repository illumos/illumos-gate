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
 * nis_cache.x
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

%#pragma ident	"%Z%%M%	%I%	%E% SMI"


#ifdef RPC_HDR
%#define	NIS_DIRECTORY		"/var/nis"
%#define	CACHE_FILE		"/var/nis/NIS_SHARED_DIRCACHE"
%#define	PRIVATE_CACHE_FILE	"/var/nis/.NIS_PRIVATE_DIRCACHE"
%#define	TMP_CACHE_FILE		"/var/nis/.NIS_TEMPORARY_DIRCACHE"
%#define	COLD_START_FILE		"/var/nis/NIS_COLD_START"
%#define	DOT_FILE		"/var/nis/.pref_servers"
%#include <rpc/types.h>
%#include <rpcsvc/nis.h>
%#include "nis_clnt.h"
#endif

struct bind_server_arg {
	nis_server *srv;
	int nsrv;
};

struct refresh_res {
	int changed;
	endpoint ep;
};

program CACHEPROG {
	version CACHE_VER_2 {
		void NIS_CACHE_ADD_ENTRY(fd_result) = 1;
		void NIS_CACHE_REMOVE_ENTRY(directory_obj) = 2;
		void NIS_CACHE_READ_COLDSTART(void) = 3;
		void NIS_CACHE_REFRESH_ENTRY(string<>) = 4;

		nis_error NIS_CACHE_BIND_REPLICA(string<>) = 5;
		nis_error NIS_CACHE_BIND_MASTER(string<>) = 6;
		nis_error NIS_CACHE_BIND_SERVER(bind_server_arg) = 7;
		refresh_res NIS_CACHE_REFRESH_BINDING(nis_bound_directory) = 8;
		refresh_res NIS_CACHE_REFRESH_ADDRESS(nis_bound_endpoint) = 9;
		refresh_res NIS_CACHE_REFRESH_CALLBACK(nis_bound_endpoint) = 10;
	} = 2;
} = 100301;
