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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * RPC shims for directory lookup.  Originally generated using rpcgen.
 */

#include <memory.h> /* for memset */
#include <rpcsvc/idmap_prot.h>
#ifndef _KERNEL
#include <stdio.h>
#include <stdlib.h> /* getenv, exit */
#endif /* !_KERNEL */

/* Default timeout can be changed using clnt_control() */
static struct timeval TIMEOUT = { 25, 0 };

enum clnt_stat
directory_get_common_1(
    idmap_utf8str_list ids,
    idmap_utf8str types,
    idmap_utf8str_list attrs,
    directory_results_rpc *clnt_res,
    CLIENT *clnt)
{
	directory_get_common_1_argument arg;
	arg.ids = ids;
	arg.attrs = attrs;
	arg.types = types;
	return (clnt_call(clnt, DIRECTORY_GET_COMMON,
	    (xdrproc_t)xdr_directory_get_common_1_argument, (caddr_t)&arg,
	    (xdrproc_t)xdr_directory_results_rpc, (caddr_t)clnt_res,
	    TIMEOUT));
}
