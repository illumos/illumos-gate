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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * RPC service routines
 * It was initially generated using rpcgen.
 */

#include "idmapd.h"
#include "idmap_prot.h"
#include <stdlib.h>
#include <signal.h>
#include <rpc/xdr.h>
#include <rpc/rpc.h>
#include <string.h>
#include <thread.h>
#include <synch.h>


/* ARGSUSED */
int
_idmap_null_1(void  *argp, void *result, struct svc_req *rqstp)
{
	return (idmap_null_1_svc(result, rqstp));
}

int
_idmap_get_mapped_ids_1(idmap_mapping_batch  *argp, idmap_ids_res *result,
		struct svc_req *rqstp)
{
	return (idmap_get_mapped_ids_1_svc(*argp, result, rqstp));
}

int
_idmap_list_mappings_1(idmap_list_mappings_1_argument *argp,
		idmap_mappings_res *result, struct svc_req *rqstp)
{
	return (idmap_list_mappings_1_svc(argp->lastrowid,
	    argp->limit, argp->flag, result, rqstp));
}

int
_idmap_list_namerules_1(idmap_list_namerules_1_argument *argp,
		idmap_namerules_res *result, struct svc_req *rqstp)
{
	return (idmap_list_namerules_1_svc(argp->rule, argp->lastrowid,
	    argp->limit, result, rqstp));
}

int
_idmap_update_1(idmap_update_batch  *argp, idmap_update_res *res,
		struct svc_req *rqstp)
{
	return (idmap_update_1_svc(*argp, res, rqstp));
}

int
_idmap_get_mapped_id_by_name_1(idmap_mapping  *argp,
		idmap_mappings_res *result, struct svc_req *rqstp)
{
	return (idmap_get_mapped_id_by_name_1_svc(*argp, result, rqstp));
}

int
_idmap_get_prop_1(idmap_prop_type  *argp,
		idmap_prop_res *result, struct svc_req *rqstp)
{
	return (idmap_get_prop_1_svc(*argp, result, rqstp));
}



void
idmap_prog_1(struct svc_req *rqstp, register SVCXPRT *transp)
{
	union {
		idmap_mapping_batch idmap_get_mapped_ids_1_arg;
		idmap_list_mappings_1_argument idmap_list_mappings_1_arg;
		idmap_list_namerules_1_argument idmap_list_namerules_1_arg;
		idmap_update_batch idmap_update_1_arg;
		idmap_mapping idmap_get_mapped_id_by_name_1_arg;
		idmap_prop_type idmap_get_prop_1_arg;
	} argument;
	union {
		idmap_ids_res idmap_get_mapped_ids_1_res;
		idmap_mappings_res idmap_list_mappings_1_res;
		idmap_namerules_res idmap_list_namerules_1_res;
		idmap_update_res idmap_update_1_res;
		idmap_mappings_res idmap_get_mapped_id_by_name_1_res;
		idmap_prop_res idmap_get_prop_1_res;
	} result;
	bool_t retval;
	xdrproc_t _xdr_argument, _xdr_result;
	bool_t (*local)(char *, void *, struct svc_req *);

	(void) mutex_lock(&_svcstate_lock);
	_rpcsvccount++;
	(void) mutex_unlock(&_svcstate_lock);
	switch (rqstp->rq_proc) {
	case IDMAP_NULL:
		_xdr_argument = (xdrproc_t)xdr_void;
		_xdr_result = (xdrproc_t)xdr_void;
		local = (bool_t (*) (char *,  void *,  struct svc_req *))
		    _idmap_null_1;
		break;

	case IDMAP_GET_MAPPED_IDS:
		_xdr_argument = (xdrproc_t)xdr_idmap_mapping_batch;
		_xdr_result = (xdrproc_t)xdr_idmap_ids_res;
		local = (bool_t (*) (char *,  void *,  struct svc_req *))
		    _idmap_get_mapped_ids_1;
		break;

	case IDMAP_LIST_MAPPINGS:
		_xdr_argument = (xdrproc_t)xdr_idmap_list_mappings_1_argument;
		_xdr_result = (xdrproc_t)xdr_idmap_mappings_res;
		local = (bool_t (*) (char *,  void *,  struct svc_req *))
		    _idmap_list_mappings_1;
		break;

	case IDMAP_LIST_NAMERULES:
		_xdr_argument = (xdrproc_t)xdr_idmap_list_namerules_1_argument;
		_xdr_result = (xdrproc_t)xdr_idmap_namerules_res;
		local = (bool_t (*) (char *,  void *,  struct svc_req *))
		    _idmap_list_namerules_1;
		break;

	case IDMAP_UPDATE:
		_xdr_argument = (xdrproc_t)xdr_idmap_update_batch;
		_xdr_result = (xdrproc_t)xdr_idmap_update_res;
		local = (bool_t (*) (char *,  void *,  struct svc_req *))
		    _idmap_update_1;
		break;

	case IDMAP_GET_MAPPED_ID_BY_NAME:
		_xdr_argument = (xdrproc_t)xdr_idmap_mapping;
		_xdr_result = (xdrproc_t)xdr_idmap_mappings_res;
		local = (bool_t (*) (char *,  void *,  struct svc_req *))
		    _idmap_get_mapped_id_by_name_1;
		break;

	case IDMAP_GET_PROP:
		_xdr_argument = (xdrproc_t)xdr_idmap_prop_type;
		_xdr_result = (xdrproc_t)xdr_idmap_prop_res;
		local = (bool_t (*) (char *,  void *,  struct svc_req *))
		    _idmap_get_prop_1;
		break;

	default:
		svcerr_noproc(transp);
		(void) mutex_lock(&_svcstate_lock);
		_rpcsvccount--;
		_rpcsvcstate = _SERVED;
		(void) mutex_unlock(&_svcstate_lock);
		return;
	}
	(void) memset((char *)&argument, 0, sizeof (argument));
	if (!svc_getargs(transp, _xdr_argument, (caddr_t)&argument)) {
		svcerr_decode(transp);
		(void) mutex_lock(&_svcstate_lock);
		_rpcsvccount--;
		_rpcsvcstate = _SERVED;
		(void) mutex_unlock(&_svcstate_lock);
		return;
	}
	retval = (bool_t)(*local)((char *)&argument, (void *)&result, rqstp);
	if (_xdr_result && retval > 0 && !svc_sendreply(transp, _xdr_result,
	    (char *)&result)) {
		svcerr_systemerr(transp);
	}
	if (!svc_freeargs(transp, _xdr_argument, (caddr_t)&argument)) {
		idmapdlog(LOG_ERR,
		    "unable to free RPC arguments");
		exit(1);
	}
	if (_xdr_result != NULL) {
		if (!idmap_prog_1_freeresult(transp, _xdr_result,
		    (caddr_t)&result))
			idmapdlog(LOG_ERR,
			    "unable to free RPC results");

	}
	(void) mutex_lock(&_svcstate_lock);
	_rpcsvccount--;
	_rpcsvcstate = _SERVED;
	(void) mutex_unlock(&_svcstate_lock);
}
