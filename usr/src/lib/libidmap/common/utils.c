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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Utility routines
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <libintl.h>
#include "idmap_impl.h"

#define	_UDT_SIZE_INCR	1

#define	_GET_IDS_SIZE_INCR	1

static struct timeval TIMEOUT = { 25, 0 };

extern int __idmap_verbose;

idmap_retcode
_udt_extend_batch(idmap_udt_handle_t *udthandle, int opnum) {
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
		opnum;
	return (IDMAP_SUCCESS);
}

idmap_retcode
_get_ids_extend_batch(idmap_get_handle_t *gh) {
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
		xdrproc_t xdr_arg_proc, xdrproc_t xdr_res_proc) {

	CLIENT		*clnt;
	enum clnt_stat	clntstat;
	const char	*me = "_iter_get_next_list";

	if (__idmap_verbose)
		(void) fprintf(stdout, "%s\n", me);

	iter->next = 0;
	iter->retlist = NULL;
	_IDMAP_GET_CLIENT_HANDLE(iter->ih, clnt);

	/* init the result */
	if (*list) {
		xdr_free(xdr_res_proc, (caddr_t)*list);
	} else {
		if ((*list = malloc(valsize)) == NULL) {
			(void) fprintf(stderr, gettext("Out of memory\n"));
			errno = ENOMEM;
			return (IDMAP_ERR_MEMORY);
		}
	}
	(void) memset(*list, 0, valsize);

	clntstat = clnt_call(clnt, type,
		xdr_arg_proc, (caddr_t)arg,
		xdr_res_proc, (caddr_t)*list,
		TIMEOUT);
	if (clntstat != RPC_SUCCESS) {
		free(*list);
		if (__idmap_verbose)
			clnt_perror(clnt, me);
		return (IDMAP_ERR_RPC);
	}
	iter->retlist = *list;
	return (IDMAP_SUCCESS);
}
