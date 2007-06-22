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
 * libidmap API
 */

#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <strings.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <libintl.h>
#include "idmap_impl.h"

static struct timeval TIMEOUT = { 25, 0 };

static int idmap_stat2errno(idmap_stat);

int __idmap_verbose;

#define	__ITER_CREATE(itera, argu, handl, ityp)\
	if (handl == NULL) {\
		errno = EINVAL;\
		return (IDMAP_ERR_ARG);\
	}\
	itera = calloc(1, sizeof (*itera));\
	if (itera == NULL) {\
		if (__idmap_verbose)\
			(void) fprintf(stderr, gettext("Out of memory\n"));\
		errno = ENOMEM;\
		return (IDMAP_ERR_MEMORY);\
	}\
	argu = calloc(1, sizeof (*argu));\
	if (argu == NULL) {\
		free(itera);\
		if (__idmap_verbose)\
			(void) fprintf(stderr, gettext("Out of memory\n"));\
		errno = ENOMEM;\
		return (IDMAP_ERR_MEMORY);\
	}\
	itera->ih = handl;\
	itera->type = ityp;\
	itera->retcode = IDMAP_NEXT;\
	itera->limit = 1024;\
	itera->arg = argu;


#define	__ITER_ERR_RETURN(itera, argu, xdr_argu, iretcod)\
	if (argu) {\
		xdr_free(xdr_argu, (caddr_t)argu);\
		free(argu);\
	}\
	if (itera)\
		free(itera);\
	return (iretcod);


#define	__ITER_CHECK(itera, ityp)\
	if (itera == NULL) {\
		if (__idmap_verbose)\
			(void) fprintf(stderr,\
				gettext("%s: Iterator is null\n"), me);\
		errno = EINVAL;\
		return (IDMAP_ERR_ARG);\
	}\
	if (itera->type != ityp) {\
		if (__idmap_verbose)\
			(void) fprintf(stderr,\
				gettext("%s: Invalid iterator\n"), me);\
		errno = EINVAL;\
		return (IDMAP_ERR_ARG);\
	}


/*
 * Free memory allocated by libidmap API
 *
 * Input:
 * ptr - memory to be freed
 */
void
idmap_free(void *ptr) {
	free(ptr);
}


/*
 * Verbose on/off switch (Private)
 *
 * Input:
 * on - TRUE=on, FALSE=off
 */
void
idmap_set_verbose(boolean_t on) {
	__idmap_verbose = (on == B_TRUE)?1:0;
}


/*
 * Create and Initialize idmap client handle for rpc/doors
 *
 * Output:
 * handle - idmap handle
 */
idmap_stat
idmap_init(idmap_handle_t **handle) {
	CLIENT			*clnt = NULL;
	struct idmap_handle	*hptr;

	*handle = NULL;
	hptr = (struct idmap_handle *)calloc(1, sizeof (*hptr));
	if (hptr == NULL)
		return (IDMAP_ERR_MEMORY);

	clnt = clnt_door_create(IDMAP_PROG, IDMAP_V1, 0);
	if (clnt == NULL) {
		if (__idmap_verbose)
			clnt_pcreateerror("clnt_door_create");
		free(hptr);
		return (IDMAP_ERR_RPC);
	}
	hptr->type = _IDMAP_HANDLE_RPC_DOORS;
	hptr->privhandle = clnt;
	*handle = hptr;
	return (IDMAP_SUCCESS);
}


/*
 * Finalize idmap handle
 *
 * Input:
 * handle - idmap handle
 */
idmap_stat
idmap_fini(idmap_handle_t *handle) {
	CLIENT			*clnt;
	struct idmap_handle	*hptr;

	if (handle == NULL)
		return (IDMAP_SUCCESS);

	hptr = (struct idmap_handle *)handle;

	switch (hptr->type) {
	case _IDMAP_HANDLE_RPC_DOORS:
		clnt = (CLIENT *)hptr->privhandle;
		if (clnt) {
			if (clnt->cl_auth)
				auth_destroy(clnt->cl_auth);
			clnt_destroy(clnt);
		}
		break;
	default:
		break;
	}
	free(hptr);
	return (IDMAP_SUCCESS);
}



/*
 * Create/Initialize handle for updates
 *
 * Output:
 * udthandle - update handle
 */
idmap_stat
idmap_udt_create(idmap_handle_t *handle, idmap_udt_handle_t **udthandle) {
	idmap_udt_handle_t	*tmp;
	const char		*me = "idmap_udt_create";

	if (handle == NULL || udthandle == NULL) {
		errno = EINVAL;
		return (IDMAP_ERR_ARG);
	}
	if ((tmp = calloc(1, sizeof (*tmp))) == NULL) {
		if (__idmap_verbose)
			(void) fprintf(stderr,
				gettext("%s: Out of memory\n"), me);
		errno = ENOMEM;
		return (IDMAP_ERR_MEMORY);
	}

	tmp->ih = handle;
	*udthandle = tmp;
	return (IDMAP_SUCCESS);
}


/*
 * All the updates specified by the update handle are committed
 * in a single transaction. i.e either all succeed or none.
 *
 * Input:
 * udthandle - update handle with the update requests
 *
 * Return value:
 * Status of the commit
 */
idmap_stat
idmap_udt_commit(idmap_udt_handle_t *udthandle) {
	CLIENT			*clnt;
	enum clnt_stat		clntstat;
	idmap_retcode		retcode;
	const char		*me = "idmap_udt_commit";

	if (udthandle == NULL) {
		if (__idmap_verbose)
			(void) fprintf(stderr,
				gettext("%s: Invalid handle\n"), me);
		errno = EINVAL;
		return (IDMAP_ERR_ARG);
	}
	_IDMAP_GET_CLIENT_HANDLE(udthandle->ih, clnt);
	clntstat = clnt_call(clnt, IDMAP_UPDATE,
		(xdrproc_t)xdr_idmap_update_batch, (caddr_t)&udthandle->batch,
		(xdrproc_t)xdr_idmap_retcode, (caddr_t)&retcode,
		TIMEOUT);
	if (clntstat != RPC_SUCCESS) {
		if (__idmap_verbose)
			clnt_perror(clnt, "IDMAP_UPDATE");
		return (IDMAP_ERR_RPC);
	}
	if (retcode != IDMAP_SUCCESS)
		errno = idmap_stat2errno(retcode);
	return (retcode);
}


/*
 * Destroy the update handle
 */
void
idmap_udt_destroy(idmap_udt_handle_t *udthandle) {
	if (udthandle == NULL)
		return;
	(void) xdr_free(xdr_idmap_update_batch, (caddr_t)&udthandle->batch);
	free(udthandle);
}


idmap_stat
idmap_udt_add_namerule(idmap_udt_handle_t *udthandle, const char *windomain,
		boolean_t is_user, const char *winname, const char *unixname,
		boolean_t is_nt4, int direction) {
	idmap_retcode	retcode;
	idmap_namerule	*rule;
	idmap_utf8str	*str;

	retcode = _udt_extend_batch(udthandle, OP_ADD_NAMERULE);
	if (retcode != IDMAP_SUCCESS)
		goto errout;

	rule = &udthandle->batch.
		idmap_update_batch_val[udthandle->next].
		idmap_update_op_u.rule;
	rule->is_user = is_user;
	rule->direction = direction;
	rule->is_nt4 = is_nt4;
	if (windomain) {
		str = &rule->windomain;
		retcode = idmap_str2utf8(&str, windomain, 0);
		if (retcode != IDMAP_SUCCESS)
			goto errout;
	}
	if (winname) {
		str = &rule->winname;
		retcode = idmap_str2utf8(&str, winname, 0);
		if (retcode != IDMAP_SUCCESS)
			goto errout;
	}
	if (unixname) {
		str = &rule->unixname;
		retcode = idmap_str2utf8(&str, unixname, 0);
		if (retcode != IDMAP_SUCCESS)
			goto errout;
	}
	udthandle->next++;
	return (IDMAP_SUCCESS);

errout:
	(void) xdr_free(xdr_idmap_update_batch, (caddr_t)&udthandle->batch);
	errno = idmap_stat2errno(retcode);
	return (retcode);
}


/* ARGSUSED */
idmap_stat
idmap_udt_rm_namerule(idmap_udt_handle_t *udthandle, boolean_t is_user,
		const char *windomain, const char *winname,
		const char *unixname, int direction) {
	idmap_retcode	retcode;
	idmap_namerule	*rule;
	idmap_utf8str	*str;

	retcode = _udt_extend_batch(udthandle, OP_RM_NAMERULE);
	if (retcode != IDMAP_SUCCESS)
		goto errout;

	rule = &udthandle->batch.
		idmap_update_batch_val[udthandle->next].
		idmap_update_op_u.rule;
	rule->is_user = is_user;
	rule->direction = direction;
	if (windomain) {
		str = &rule->windomain;
		retcode = idmap_str2utf8(&str, windomain, 0);
		if (retcode != IDMAP_SUCCESS)
			goto errout;
	}
	if (winname) {
		str = &rule->winname;
		retcode = idmap_str2utf8(&str, winname, 0);
		if (retcode != IDMAP_SUCCESS)
			goto errout;
	}
	if (unixname) {
		str = &rule->unixname;
		retcode = idmap_str2utf8(&str, unixname, 0);
		if (retcode != IDMAP_SUCCESS)
			goto errout;
	}
	udthandle->next++;
	return (IDMAP_SUCCESS);

errout:
	(void) xdr_free(xdr_idmap_update_batch, (caddr_t)&udthandle->batch);
	errno = idmap_stat2errno(retcode);
	return (retcode);
}


/* ARGSUSED */
idmap_stat
idmap_udt_flush_namerules(idmap_udt_handle_t *udthandle, boolean_t is_user) {
	idmap_retcode	retcode;

	retcode = _udt_extend_batch(udthandle, OP_FLUSH_NAMERULES);
	if (retcode != IDMAP_SUCCESS)
		goto errout;

	udthandle->batch.idmap_update_batch_val[udthandle->next].
		idmap_update_op_u.is_user = is_user;

	udthandle->next++;
	return (IDMAP_SUCCESS);

errout:
	(void) xdr_free(xdr_idmap_update_batch, (caddr_t)&udthandle->batch);
	errno = idmap_stat2errno(retcode);
	return (retcode);
}


/*
 * Set the number of entries requested per batch by the iterator
 *
 * Input:
 * iter  - iterator
 * limit - number of entries requested per batch
 */
idmap_stat
idmap_iter_set_limit(idmap_iter_t *iter, uint64_t limit) {
	if (iter == NULL) {
		errno = EINVAL;
		return (IDMAP_ERR_ARG);
	}
	iter->limit = limit;
	return (IDMAP_SUCCESS);
}


/*
 * Create iterator to get name-based mapping rules
 *
 * Input:
 * windomain - Windows domain
 * is_user   - user or group rules
 * winname   - Windows user or group name
 * unixname  - Unix user or group name
 *
 * Output:
 * iter - iterator
 */
idmap_stat
idmap_iter_namerules(idmap_handle_t *handle, const char *windomain,
		boolean_t is_user, const char *winname,
		const char *unixname, idmap_iter_t **iter) {

	idmap_iter_t			*tmpiter;
	idmap_list_namerules_1_argument	*arg = NULL;
	idmap_namerule			*rule;
	idmap_utf8str			*str;
	idmap_retcode			retcode;

	__ITER_CREATE(tmpiter, arg, handle, IDMAP_LIST_NAMERULES);

	rule = &arg->rule;
	rule->is_user = is_user;
	rule->direction = -1;
	if (windomain) {
		str = &rule->windomain;
		retcode = idmap_str2utf8(&str, windomain, 0);
		if (retcode != IDMAP_SUCCESS) {
			errno = ENOMEM;
			goto errout;
		}
	}
	if (winname) {
		str = &rule->winname;
		retcode = idmap_str2utf8(&str, winname, 0);
		if (retcode != IDMAP_SUCCESS) {
			errno = ENOMEM;
			goto errout;
		}
	}
	if (unixname) {
		str = &rule->unixname;
		retcode = idmap_str2utf8(&str, unixname, 0);
		if (retcode != IDMAP_SUCCESS) {
			errno = ENOMEM;
			goto errout;
		}
	}

	*iter = tmpiter;
	return (IDMAP_SUCCESS);

errout:
	__ITER_ERR_RETURN(tmpiter, arg,
		xdr_idmap_list_namerules_1_argument, retcode);
}


/*
 * Iterate through the name-based mapping rules
 *
 * Input:
 * iter - iterator
 *
 * Output:
 * windomain - Windows domain
 * winname   - Windows user or group name
 * unixname  - Unix user or group name
 * is_nt4    - NT4 or AD
 * direction - bi(0), win2unix(1), unix2win(2)
 *
 * Return value:
 * 0   - done
 * 1   - more results available
 * < 0 - error
 */
idmap_stat
idmap_iter_next_namerule(idmap_iter_t *iter, char **windomain,
		char **winname, char **unixname, boolean_t *is_nt4,
		int *direction) {
	idmap_namerules_res		*namerules;
	idmap_list_namerules_1_argument	*arg;
	idmap_retcode			retcode;
	const char			*me = "idmap_iter_next_namerule";

	if (windomain)
		*windomain = NULL;
	if (winname)
		*winname = NULL;
	if (unixname)
		*unixname = NULL;
	if (is_nt4)
		*is_nt4 = 0;
	if (direction)
		*direction = -1;

	__ITER_CHECK(iter, IDMAP_LIST_NAMERULES);

	namerules = (idmap_namerules_res *)iter->retlist;
	if (iter->retcode == IDMAP_NEXT && (namerules == NULL ||
			iter->next >= namerules->rules.rules_len)) {

		if ((arg = iter->arg) == NULL) {
			errno = EINVAL;
			return (IDMAP_ERR_ARG);
		}
		arg->limit = iter->limit;

		retcode = _iter_get_next_list(IDMAP_LIST_NAMERULES,
			iter, arg,
			(uchar_t **)&namerules, sizeof (*namerules),
			(xdrproc_t)xdr_idmap_list_namerules_1_argument,
			(xdrproc_t)xdr_idmap_namerules_res);
		if (retcode != IDMAP_SUCCESS)
			return (retcode);

		if (IDMAP_ERROR(namerules->retcode)) {
			retcode  = namerules->retcode;
			if (__idmap_verbose)
				(void) fprintf(stderr,
				gettext("Server returned failure\n"));
			xdr_free(xdr_idmap_namerules_res, (caddr_t)namerules);
			free(namerules);
			iter->retlist = NULL;
			return (retcode);
		}
		iter->retcode = namerules->retcode;
		arg->lastrowid = namerules->lastrowid;
	}

	if (namerules == NULL || namerules->rules.rules_len == 0)
		return (IDMAP_SUCCESS);

	if (iter->next >= namerules->rules.rules_len) {
		if (__idmap_verbose)
			(void) fprintf(stderr,
				gettext("%s: Invalid result\n"), me);
		return (IDMAP_ERR_ARG);
	}

	if (windomain) {
		retcode = idmap_utf82str(windomain, 0,
			&namerules->rules.rules_val[iter->next].windomain);
		if (retcode != IDMAP_SUCCESS)
			goto errout;
	}
	if (winname) {
		retcode = idmap_utf82str(winname, 0,
			&namerules->rules.rules_val[iter->next].winname);
		if (retcode != IDMAP_SUCCESS)
			goto errout;
	}
	if (unixname) {
		retcode = idmap_utf82str(unixname, 0,
			&namerules->rules.rules_val[iter->next].unixname);
		if (retcode != IDMAP_SUCCESS)
			goto errout;
	}
	if (is_nt4)
		*is_nt4 = namerules->rules.rules_val[iter->next].is_nt4;
	if (direction)
		*direction = namerules->rules.rules_val[iter->next].direction;
	iter->next++;

	if (iter->next == namerules->rules.rules_len)
		return (iter->retcode);
	else
		return (IDMAP_NEXT);

errout:
	if (windomain && *windomain)
		free(*windomain);
	if (winname && *winname)
		free(*winname);
	if (unixname && *unixname)
		free(*unixname);
	return (retcode);
}


/*
 * Create iterator to get SID to UID/GID mappings
 *
 * Input:
 * is_user - user or group
 *
 * Output:
 * iter - iterator
 */
idmap_stat
idmap_iter_mappings(idmap_handle_t *handle, boolean_t is_user,
		idmap_iter_t **iter) {
	idmap_iter_t			*tmpiter;
	idmap_list_mappings_1_argument	*arg = NULL;

	__ITER_CREATE(tmpiter, arg, handle, IDMAP_LIST_MAPPINGS);

	arg->is_user = is_user;
	*iter = tmpiter;
	return (IDMAP_SUCCESS);
}


/*
 * Iterate through the SID to UID/GID mappings
 *
 * Input:
 * iter - iterator
 *
 * Output:
 * sid - SID in canonical form
 * pid - UID or GID
 *
 * Return value:
 * 0   - done
 * 1   - more results available
 * < 0 - error
 */
idmap_stat
idmap_iter_next_mapping(idmap_iter_t *iter, char **sidprefix,
		idmap_rid_t *rid, uid_t *pid, char **winname,
		char **windomain, char **unixname, int *direction) {
	idmap_mappings_res		*mappings;
	idmap_list_mappings_1_argument	*arg;
	idmap_retcode			retcode;
	char				*str;
	const char			*me = "idmap_iter_next_mapping";

	if (sidprefix)
		*sidprefix = NULL;
	if (rid)
		*rid = UINT32_MAX;
	if (winname)
		*winname = NULL;
	if (windomain)
		*windomain = NULL;
	if (unixname)
		*unixname = NULL;
	if (pid)
		*pid = UINT32_MAX;
	if (direction)
		*direction = -1;

	__ITER_CHECK(iter, IDMAP_LIST_MAPPINGS);

	mappings = (idmap_mappings_res *)iter->retlist;
	if (iter->retcode == IDMAP_NEXT && (mappings == NULL ||
			iter->next >= mappings->mappings.mappings_len)) {

		if ((arg = iter->arg) == NULL) {
			errno = EINVAL;
			return (IDMAP_ERR_ARG);
		}
		arg->limit = iter->limit;

		retcode = _iter_get_next_list(IDMAP_LIST_MAPPINGS,
			iter, arg,
			(uchar_t **)&mappings, sizeof (*mappings),
			(xdrproc_t)xdr_idmap_list_mappings_1_argument,
			(xdrproc_t)xdr_idmap_mappings_res);
		if (retcode != IDMAP_SUCCESS)
			return (retcode);

		if (IDMAP_ERROR(mappings->retcode)) {
			retcode  = mappings->retcode;
			if (__idmap_verbose)
				(void) fprintf(stderr,
				gettext("Server returned failure\n"));
			xdr_free(xdr_idmap_mappings_res, (caddr_t)mappings);
			free(mappings);
			iter->retlist = NULL;
			return (retcode);
		}
		iter->retcode = mappings->retcode;
		arg->lastrowid = mappings->lastrowid;
	}

	if (mappings == NULL || mappings->mappings.mappings_len == 0)
		return (IDMAP_SUCCESS);

	if (iter->next >= mappings->mappings.mappings_len) {
		if (__idmap_verbose)
			(void) fprintf(stderr,
				gettext("%s: Invalid result\n"), me);
		return (IDMAP_ERR_ARG);
	}

	if (sidprefix) {
		str = mappings->mappings.mappings_val[iter->next].id1.
			idmap_id_u.sid.prefix;
		if (str)
			*sidprefix = strdup(str);
		else
			*sidprefix = strdup("<sidprefix missing>");
		if (*sidprefix == NULL) {
			retcode = IDMAP_ERR_MEMORY;
			goto errout;
		}
	}
	if (rid)
		*rid = mappings->mappings.mappings_val[iter->next].id1.
			idmap_id_u.sid.rid;
	if (winname) {
		retcode = idmap_utf82str(winname, 0,
		    &mappings->mappings.mappings_val[iter->next].id1name);
		if (retcode != IDMAP_SUCCESS)
			goto errout;
	}
	if (windomain) {
		retcode = idmap_utf82str(windomain, 0,
		    &mappings->mappings.mappings_val[iter->next].id1domain);
		if (retcode != IDMAP_SUCCESS)
			goto errout;
	}
	if (unixname) {
		retcode = idmap_utf82str(unixname, 0,
		    &mappings->mappings.mappings_val[iter->next].id2name);
		if (retcode != IDMAP_SUCCESS)
			goto errout;
	}
	if (pid)
		*pid = mappings->mappings.mappings_val[iter->next].id2.
			idmap_id_u.uid;
	if (direction)
		*direction = mappings->mappings.mappings_val[iter->next].
			direction;
	iter->next++;

	if (iter->next == mappings->mappings.mappings_len)
		return (iter->retcode);
	else
		return (IDMAP_NEXT);

errout:
	if (sidprefix && *sidprefix)
		free(*sidprefix);
	if (winname && *winname)
		free(*winname);
	if (windomain && *windomain)
		free(*windomain);
	if (unixname && *unixname)
		free(*unixname);
	return (retcode);
}


/*
 * Destroy the iterator
 */
void
idmap_iter_destroy(idmap_iter_t *iter) {
	xdrproc_t _xdr_argument, _xdr_result;

	if (iter == NULL)
		return;

	switch (iter->type) {
	case IDMAP_LIST_NAMERULES:
		_xdr_argument = (xdrproc_t)xdr_idmap_list_namerules_1_argument;
		_xdr_result = (xdrproc_t)xdr_idmap_namerules_res;
		break;
	case IDMAP_LIST_MAPPINGS:
		_xdr_argument = (xdrproc_t)xdr_idmap_list_mappings_1_argument;
		_xdr_result = (xdrproc_t)xdr_idmap_mappings_res;
		break;
	default:
		free(iter);
		return;
	};

	if (iter->arg) {
		xdr_free(_xdr_argument, (caddr_t)iter->arg);
		free(iter->arg);
	}
	if (iter->retlist) {
		xdr_free(_xdr_result, (caddr_t)iter->retlist);
		free(iter->retlist);
	}
	free(iter);
}


/*
 * Create handle to get SID to UID/GID mapping entries
 *
 * Input:
 * gh - "get mapping" handle
 */
idmap_stat
idmap_get_create(idmap_handle_t *handle, idmap_get_handle_t **gh) {
	idmap_get_handle_t	*tmp;
	const char		*me = "idmap_get_create";

	/* sanity checks */
	if (handle == NULL || gh == NULL) {
		errno = EINVAL;
		return (IDMAP_ERR_ARG);
	}

	/* allocate the handle */
	if ((tmp = calloc(1, sizeof (*tmp))) == NULL) {
		if (__idmap_verbose)
			(void) fprintf(stderr,
				gettext("%s: Out of memory\n"), me);
		errno = ENOMEM;
		return (IDMAP_ERR_MEMORY);
	}

	tmp->ih = handle;
	*gh = tmp;
	return (IDMAP_SUCCESS);
}


/*
 * Given SID, get UID
 *
 * Input:
 * sidprefix  - SID prefix
 * rid        - RID
 * flag       - flag
 *
 * Output:
 * stat - status of the get request
 * uid  - POSIX UID if stat = 0
 *
 * Note: The output parameters will be set by idmap_get_mappings()
 */
idmap_stat
idmap_get_uidbysid(idmap_get_handle_t *gh, char *sidprefix, idmap_rid_t rid,
		int flag, uid_t *uid, idmap_stat *stat) {

	idmap_retcode	retcode;
	idmap_mapping	*mapping;

	/* sanity checks */
	if (gh == NULL)
		return (IDMAP_ERR_ARG);
	if (uid == NULL || sidprefix == NULL)
		return (IDMAP_ERR_ARG);

	/* Extend the request array and the return list */
	if ((retcode = _get_ids_extend_batch(gh)) != IDMAP_SUCCESS)
		goto errout;

	/* Setup the request */
	mapping = &gh->batch.idmap_mapping_batch_val[gh->next];
	mapping->flag = flag;
	mapping->id1.idtype = IDMAP_SID;
	mapping->id1.idmap_id_u.sid.rid = rid;
	if ((mapping->id1.idmap_id_u.sid.prefix = strdup(sidprefix)) == NULL) {
		retcode = IDMAP_ERR_MEMORY;
		goto errout;
	}
	mapping->id2.idtype = IDMAP_UID;

	/* Setup pointers for the result */
	gh->retlist[gh->next].idtype = IDMAP_UID;
	gh->retlist[gh->next].uid = uid;
	gh->retlist[gh->next].stat = stat;

	gh->next++;
	return (IDMAP_SUCCESS);

errout:
	(void) xdr_free(xdr_idmap_mapping_batch, (caddr_t)&gh->batch);
	free(gh->retlist);
	gh->retlist = NULL;
	gh->next = 0;
	errno = idmap_stat2errno(retcode);
	return (retcode);
}


/*
 * Given SID, get GID
 *
 * Input:
 * sidprefix  - SID prefix
 * rid        - rid
 * flag       - flag
 *
 * Output:
 * stat - status of the get request
 * gid  - POSIX GID if stat = 0
 *
 * Note: The output parameters will be set by idmap_get_mappings()
 */
idmap_stat
idmap_get_gidbysid(idmap_get_handle_t *gh, char *sidprefix, idmap_rid_t rid,
		int flag, gid_t *gid, idmap_stat *stat) {

	idmap_retcode	retcode;
	idmap_mapping	*mapping;

	/* sanity checks */
	if (gh == NULL)
		return (IDMAP_ERR_ARG);
	if (gid == NULL || sidprefix == NULL)
		return (IDMAP_ERR_ARG);

	/* Extend the request array and the return list */
	if ((retcode = _get_ids_extend_batch(gh)) != IDMAP_SUCCESS)
		goto errout;

	/* Setup the request */
	mapping = &gh->batch.idmap_mapping_batch_val[gh->next];
	mapping->flag = flag;
	mapping->id1.idtype = IDMAP_SID;
	mapping->id1.idmap_id_u.sid.rid = rid;
	if ((mapping->id1.idmap_id_u.sid.prefix = strdup(sidprefix)) == NULL) {
		retcode = IDMAP_ERR_MEMORY;
		goto errout;
	}
	mapping->id2.idtype = IDMAP_GID;

	/* Setup pointers for the result */
	gh->retlist[gh->next].idtype = IDMAP_GID;
	gh->retlist[gh->next].gid = gid;
	gh->retlist[gh->next].stat = stat;

	gh->next++;
	return (IDMAP_SUCCESS);

errout:
	(void) xdr_free(xdr_idmap_mapping_batch, (caddr_t)&gh->batch);
	free(gh->retlist);
	gh->retlist = NULL;
	gh->next = 0;
	errno = idmap_stat2errno(retcode);
	return (retcode);
}


/*
 * Given SID, get POSIX ID i.e. UID/GID
 *
 * Input:
 * sidprefix  - SID prefix
 * rid        - rid
 * flag       - flag
 *
 * Output:
 * stat    - status of the get request
 * is_user - user or group
 * pid     - POSIX UID if stat = 0 and is_user = 1
 *           POSIX GID if stat = 0 and is_user = 0
 *
 * Note: The output parameters will be set by idmap_get_mappings()
 */
idmap_stat
idmap_get_pidbysid(idmap_get_handle_t *gh, char *sidprefix, idmap_rid_t rid,
		int flag, uid_t *pid, int *is_user, idmap_stat *stat) {
	idmap_retcode	retcode;
	idmap_mapping	*mapping;

	/* sanity checks */
	if (gh == NULL)
		return (IDMAP_ERR_ARG);
	if (pid == NULL || sidprefix == NULL || is_user == NULL)
		return (IDMAP_ERR_ARG);

	/* Extend the request array and the return list */
	if ((retcode = _get_ids_extend_batch(gh)) != IDMAP_SUCCESS)
		goto errout;

	/* Setup the request */
	mapping = &gh->batch.idmap_mapping_batch_val[gh->next];
	mapping->flag = flag;
	mapping->id1.idtype = IDMAP_SID;
	mapping->id1.idmap_id_u.sid.rid = rid;
	if ((mapping->id1.idmap_id_u.sid.prefix = strdup(sidprefix)) == NULL) {
		retcode = IDMAP_ERR_MEMORY;
		goto errout;
	}
	mapping->id2.idtype = IDMAP_POSIXID;

	/* Setup pointers for the result */
	gh->retlist[gh->next].idtype = IDMAP_POSIXID;
	gh->retlist[gh->next].uid = pid;
	gh->retlist[gh->next].gid = pid;
	gh->retlist[gh->next].is_user = is_user;
	gh->retlist[gh->next].stat = stat;

	gh->next++;
	return (IDMAP_SUCCESS);

errout:
	(void) xdr_free(xdr_idmap_mapping_batch, (caddr_t)&gh->batch);
	free(gh->retlist);
	gh->retlist = NULL;
	gh->next = 0;
	errno = idmap_stat2errno(retcode);
	return (retcode);
}


/*
 * Given UID, get SID
 *
 * Input:
 * uid  - POSIX UID
 * flag - flag
 *
 * Output:
 * stat - status of the get request
 * sid  - SID prefix (if stat == 0)
 * rid  - rid
 *
 * Note: The output parameters will be set by idmap_get_mappings()
 */
idmap_stat
idmap_get_sidbyuid(idmap_get_handle_t *gh, uid_t uid, int flag,
		char **sidprefix, idmap_rid_t *rid, idmap_stat *stat) {

	idmap_retcode	retcode;
	idmap_mapping	*mapping;

	/* sanity checks */
	if (gh == NULL)
		return (IDMAP_ERR_ARG);
	if (sidprefix == NULL)
		return (IDMAP_ERR_ARG);

	/* Extend the request array and the return list */
	if ((retcode = _get_ids_extend_batch(gh)) != IDMAP_SUCCESS)
		goto errout;

	/* Setup the request */
	mapping = &gh->batch.idmap_mapping_batch_val[gh->next];
	mapping->flag = flag;
	mapping->id1.idtype = IDMAP_UID;
	mapping->id1.idmap_id_u.uid = uid;
	mapping->id2.idtype = IDMAP_SID;

	/* Setup pointers for the result */
	gh->retlist[gh->next].idtype = IDMAP_SID;
	gh->retlist[gh->next].sidprefix = sidprefix;
	gh->retlist[gh->next].rid = rid;
	gh->retlist[gh->next].stat = stat;

	gh->next++;
	return (IDMAP_SUCCESS);

errout:
	(void) xdr_free(xdr_idmap_mapping_batch, (caddr_t)&gh->batch);
	free(gh->retlist);
	gh->retlist = NULL;
	gh->next = 0;
	errno = idmap_stat2errno(retcode);
	return (retcode);
}


/*
 * Given GID, get SID
 *
 * Input:
 * gid  - POSIX GID
 * flag - flag
 *
 * Output:
 * stat       - status of the get request
 * sidprefix  - SID prefix (if stat == 0)
 * rid        - rid
 *
 * Note: The output parameters will be set by idmap_get_mappings()
 */
idmap_stat
idmap_get_sidbygid(idmap_get_handle_t *gh, gid_t gid, int flag,
		char **sidprefix, idmap_rid_t *rid, idmap_stat *stat) {

	idmap_retcode	retcode;
	idmap_mapping	*mapping;

	/* sanity checks */
	if (gh == NULL)
		return (IDMAP_ERR_ARG);
	if (sidprefix == NULL)
		return (IDMAP_ERR_ARG);

	/* Extend the request array and the return list */
	if ((retcode = _get_ids_extend_batch(gh)) != IDMAP_SUCCESS)
		goto errout;

	/* Setup the request */
	mapping = &gh->batch.idmap_mapping_batch_val[gh->next];
	mapping->flag = flag;
	mapping->id1.idtype = IDMAP_GID;
	mapping->id1.idmap_id_u.gid = gid;
	mapping->id2.idtype = IDMAP_SID;

	/* Setup pointers for the result */
	gh->retlist[gh->next].idtype = IDMAP_SID;
	gh->retlist[gh->next].sidprefix = sidprefix;
	gh->retlist[gh->next].rid = rid;
	gh->retlist[gh->next].stat = stat;

	gh->next++;
	return (IDMAP_SUCCESS);

errout:
	(void) xdr_free(xdr_idmap_mapping_batch, (caddr_t)&gh->batch);
	free(gh->retlist);
	gh->retlist = NULL;
	gh->next = 0;
	errno = idmap_stat2errno(retcode);
	return (retcode);
}


/*
 * Process the batched "get mapping" requests. The results (i.e.
 * status and identity) will be available in the data areas
 * provided by individual requests.
 */
idmap_stat
idmap_get_mappings(idmap_get_handle_t *gh) {
	CLIENT		*clnt;
	enum clnt_stat	clntstat;
	idmap_retcode	retcode;
	idmap_ids_res	res;
	idmap_id	*id;
	int		i;

	if (gh == NULL) {
		errno = EINVAL;
		return (IDMAP_ERR_ARG);
	}
	_IDMAP_GET_CLIENT_HANDLE(gh->ih, clnt);

	(void) memset(&res, 0, sizeof (idmap_ids_res));
	clntstat = clnt_call(clnt, IDMAP_GET_MAPPED_IDS,
		(xdrproc_t)xdr_idmap_mapping_batch,
		(caddr_t)&gh->batch,
		(xdrproc_t)xdr_idmap_ids_res,
		(caddr_t)&res,
		TIMEOUT);
	if (clntstat != RPC_SUCCESS) {
		if (__idmap_verbose)
			clnt_perror(clnt, "IDMAP_GET_MAPPED_IDS");
		retcode = IDMAP_ERR_RPC;
		goto out;
	}
	if (res.retcode != IDMAP_SUCCESS) {
		retcode = res.retcode;
		goto out;
	}
	for (i = 0; i < gh->next; i++) {
		if (i >= res.ids.ids_len) {
			*gh->retlist[i].stat = IDMAP_ERR_NORESULT;
			continue;
		}
		*gh->retlist[i].stat = res.ids.ids_val[i].retcode;
		id = &res.ids.ids_val[i].id;
		switch (id->idtype) {
		case IDMAP_UID:
			if (gh->retlist[i].uid)
				*gh->retlist[i].uid = id->idmap_id_u.uid;
			if (gh->retlist[i].is_user)
				*gh->retlist[i].is_user = 1;
			break;
		case IDMAP_GID:
			if (gh->retlist[i].gid)
				*gh->retlist[i].gid = id->idmap_id_u.gid;
			if (gh->retlist[i].is_user)
				*gh->retlist[i].is_user = 0;
			break;
		case IDMAP_SID:
			if (gh->retlist[i].rid)
				*gh->retlist[i].rid = id->idmap_id_u.sid.rid;
			if (gh->retlist[i].sidprefix) {
				if (id->idmap_id_u.sid.prefix == NULL) {
					*gh->retlist[i].sidprefix = NULL;
					break;
				}
				*gh->retlist[i].sidprefix =
					strdup(id->idmap_id_u.sid.prefix);
				if (*gh->retlist[i].sidprefix == NULL)
					*gh->retlist[i].stat =
						IDMAP_ERR_MEMORY;
			}
			break;
		case IDMAP_NONE:
			break;
		default:
			*gh->retlist[i].stat = IDMAP_ERR_NORESULT;
			break;
		}
	}
	retcode = IDMAP_SUCCESS;

out:
	(void) xdr_free(xdr_idmap_mapping_batch, (caddr_t)&gh->batch);
	free(gh->retlist);
	gh->retlist = NULL;
	gh->next = 0;
	(void) xdr_free(xdr_idmap_ids_res, (caddr_t)&res);
	errno = idmap_stat2errno(retcode);
	return (retcode);
}


/*
 * Destroy the "get mapping" handle
 */
void
idmap_get_destroy(idmap_get_handle_t *gh) {
	if (gh == NULL)
		return;
	(void) xdr_free(xdr_idmap_mapping_batch, (caddr_t)&gh->batch);
	if (gh->retlist)
		free(gh->retlist);
	free(gh);
}


/*
 * Get windows to unix mapping
 */
idmap_stat
idmap_get_w2u_mapping(idmap_handle_t *handle,
		const char *sidprefix, idmap_rid_t *rid,
		const char *winname, const char *windomain,
		int flag, int *is_user,
		uid_t *pid, char **unixname, int *direction) {
	CLIENT			*clnt;
	enum clnt_stat		clntstat;
	idmap_mapping		request, *mapping;
	idmap_mappings_res	result;
	idmap_retcode		retcode, rc;
	idmap_utf8str		*str;
	const char		*me = "idmap_get_w2u_mapping";

	if (handle == NULL) {
		if (__idmap_verbose)
			(void) fprintf(stderr,
				gettext("%s: Invalid handle\n"), me);
		errno = EINVAL;
		return (IDMAP_ERR_ARG);
	}

	_IDMAP_GET_CLIENT_HANDLE(handle, clnt);

	(void) memset(&request, 0, sizeof (request));
	(void) memset(&result, 0, sizeof (result));

	if (pid)
		*pid = UINT32_MAX;
	if (unixname)
		*unixname = NULL;
	if (direction)
		*direction = -1;

	request.flag = flag;
	request.id1.idtype = IDMAP_SID;
	if (sidprefix && rid) {
		request.id1.idmap_id_u.sid.prefix = (char *)sidprefix;
		request.id1.idmap_id_u.sid.rid = *rid;
	} else if (winname) {
		str = &request.id1name;
		retcode = idmap_str2utf8(&str, winname, 1);
		if (retcode != IDMAP_SUCCESS)
			goto out;
		if (windomain) {
			str = &request.id1domain;
			retcode = idmap_str2utf8(&str, windomain, 1);
			if (retcode != IDMAP_SUCCESS)
				return (retcode);
		}
		request.id1.idmap_id_u.sid.prefix = NULL;
	} else {
		errno = EINVAL;
		return (IDMAP_ERR_ARG);
	}

	if (is_user == NULL)
		request.id2.idtype = IDMAP_POSIXID;
	else if (*is_user == 1)
		request.id2.idtype = IDMAP_UID;
	else if (*is_user == 0)
		request.id2.idtype = IDMAP_GID;
	else
		request.id2.idtype = IDMAP_POSIXID;

	clntstat = clnt_call(clnt, IDMAP_GET_MAPPED_ID_BY_NAME,
		(xdrproc_t)xdr_idmap_mapping, (caddr_t)&request,
		(xdrproc_t)xdr_idmap_mappings_res, (caddr_t)&result,
		TIMEOUT);

	if (clntstat != RPC_SUCCESS) {
		if (__idmap_verbose)
			clnt_perror(clnt, "IDMAP_GET_MAPPED_ID_BY_NAME");
		return (IDMAP_ERR_RPC);
	}

	retcode = result.retcode;

	if ((mapping = result.mappings.mappings_val) == NULL) {
		if (retcode == IDMAP_SUCCESS)
			retcode = IDMAP_ERR_NORESULT;
		goto out;
	}

	if (is_user)
		*is_user = (mapping->id2.idtype == IDMAP_UID)?1:0;
	if (direction)
		*direction = mapping->direction;
	if (pid)
		*pid = mapping->id2.idmap_id_u.uid;
	if (unixname) {
		rc = idmap_utf82str(unixname, 0, &mapping->id2name);
		if (rc != IDMAP_SUCCESS)
			retcode = rc;
	}

out:
	xdr_free(xdr_idmap_mappings_res, (caddr_t)&result);
	if (retcode != IDMAP_SUCCESS)
		errno = idmap_stat2errno(retcode);
	return (retcode);
}


/*
 * Get unix to windows mapping
 */
idmap_stat
idmap_get_u2w_mapping(idmap_handle_t *handle,
		uid_t *pid, const char *unixname,
		int flag, int is_user,
		char **sidprefix, idmap_rid_t *rid,
		char **winname, char **windomain,
		int *direction) {
	CLIENT			*clnt;
	enum clnt_stat		clntstat;
	idmap_mapping		request, *mapping;
	idmap_mappings_res	result;
	idmap_retcode		retcode, rc;
	idmap_utf8str		*str;
	const char		*me = "idmap_get_u2w_mapping";

	if (handle == NULL) {
		if (__idmap_verbose)
			(void) fprintf(stderr,
				gettext("%s: Invalid handle\n"), me);
		errno = EINVAL;
		return (IDMAP_ERR_ARG);
	}

	_IDMAP_GET_CLIENT_HANDLE(handle, clnt);

	if (sidprefix)
		*sidprefix = NULL;
	if (winname)
		*winname = NULL;
	if (windomain)
		*windomain = NULL;
	if (rid)
		*rid = UINT32_MAX;
	if (direction)
		*direction = -1;

	(void) memset(&request, 0, sizeof (request));
	(void) memset(&result, 0, sizeof (result));

	request.flag = flag;
	request.id1.idtype = is_user?IDMAP_UID:IDMAP_GID;

	if (pid && *pid != UINT32_MAX) {
		request.id1.idmap_id_u.uid = *pid;
	} else if (unixname) {
		str = &request.id1name;
		retcode = idmap_str2utf8(&str, unixname, 1);
		if (retcode != IDMAP_SUCCESS)
			goto out;
		request.id1.idmap_id_u.uid = UINT32_MAX;
	} else {
		errno = EINVAL;
		return (IDMAP_ERR_ARG);
	}

	request.id2.idtype = IDMAP_SID;

	clntstat = clnt_call(clnt, IDMAP_GET_MAPPED_ID_BY_NAME,
		(xdrproc_t)xdr_idmap_mapping, (caddr_t)&request,
		(xdrproc_t)xdr_idmap_mappings_res, (caddr_t)&result,
		TIMEOUT);

	if (clntstat != RPC_SUCCESS) {
		if (__idmap_verbose)
			clnt_perror(clnt, "IDMAP_GET_MAPPED_ID_BY_NAME");
		return (IDMAP_ERR_RPC);
	}

	retcode = result.retcode;

	if ((mapping = result.mappings.mappings_val) == NULL) {
		if (retcode == IDMAP_SUCCESS)
			retcode = IDMAP_ERR_NORESULT;
		goto out;
	}

	if (direction)
		*direction = mapping->direction;
	if (sidprefix) {
		*sidprefix = strdup(mapping->id2.idmap_id_u.sid.prefix);
		if (*sidprefix == NULL) {
			retcode = IDMAP_ERR_MEMORY;
			goto errout;
		}
	}
	if (rid)
		*rid = mapping->id2.idmap_id_u.sid.rid;
	if (winname) {
		rc = idmap_utf82str(winname, 0, &mapping->id2name);
		if (rc != IDMAP_SUCCESS) {
			retcode = rc;
			goto errout;
		}
	}
	if (windomain) {
		rc = idmap_utf82str(windomain, 0, &mapping->id2domain);
		if (rc != IDMAP_SUCCESS) {
			retcode = rc;
			goto errout;
		}
	}

	goto out;

errout:
	if (sidprefix && *sidprefix) {
		free(*sidprefix);
		*sidprefix = NULL;
	}
	if (winname && *winname) {
		free(*winname);
		*winname = NULL;
	}
	if (windomain && *windomain) {
		free(*windomain);
		*windomain = NULL;
	}

out:
	xdr_free(xdr_idmap_mappings_res, (caddr_t)&result);
	if (retcode != IDMAP_SUCCESS)
		errno = idmap_stat2errno(retcode);
	return (retcode);
}


/*
 * utf8str to string
 */
idmap_stat
idmap_utf82str(char **out, size_t outsize, idmap_utf8str *in) {
	int len;

	if (in == NULL || out == NULL)
		return (IDMAP_ERR_ARG);

	if (outsize == 0) {
		*out = NULL;
		if ((len = in->idmap_utf8str_len) == 0)
			return (IDMAP_SUCCESS);
		if (in->idmap_utf8str_val == NULL)
			return (IDMAP_ERR_ARG);
		if (in->idmap_utf8str_val[len - 1] != 0)
			len++;
		*out = calloc(1, len);
		if (*out == NULL)
			return (IDMAP_ERR_MEMORY);
	} else {
		if (*out == NULL)
			return (IDMAP_ERR_ARG);
		(void) memset(*out, 0, outsize);
		if ((len = in->idmap_utf8str_len) == 0)
			return (IDMAP_SUCCESS);
		if (in->idmap_utf8str_val == NULL)
			return (IDMAP_ERR_ARG);
		if (in->idmap_utf8str_val[len - 1] != 0)
			len++;
		if (outsize < len)
			return (IDMAP_ERR_ARG);
	}
	(void) memcpy(*out, in->idmap_utf8str_val, in->idmap_utf8str_len);
	return (IDMAP_SUCCESS);
}


/*
 * string to utf8str
 */
idmap_stat
idmap_str2utf8(idmap_utf8str **out, const char *in, int flag) {
	idmap_utf8str	*tmp;

	if (out == NULL)
		return (IDMAP_ERR_ARG);
	else if (*out == NULL) {
		tmp = malloc(sizeof (idmap_utf8str));
		if (tmp == NULL)
			return (IDMAP_ERR_MEMORY);
	} else {
		tmp = *out;
	}

	if (in == NULL) {
		tmp->idmap_utf8str_len = 0;
		tmp->idmap_utf8str_val = NULL;
		if (*out == NULL)
			*out = tmp;
		return (IDMAP_SUCCESS);
	}

	/* include the null terminator */
	tmp->idmap_utf8str_len = strlen(in) + 1;

	if (flag == 1) {
		/* Don't malloc, simply assign */
		tmp->idmap_utf8str_val = (char *)in;
		if (*out == NULL)
			*out = tmp;
		return (IDMAP_SUCCESS);
	}

	tmp->idmap_utf8str_val = malloc(tmp->idmap_utf8str_len);
	if (tmp->idmap_utf8str_val == NULL) {
		tmp->idmap_utf8str_len = 0;
		if (*out == NULL)
			free(tmp);
		return (IDMAP_ERR_MEMORY);
	}
	(void) memcpy(tmp->idmap_utf8str_val, in, tmp->idmap_utf8str_len);
	if (*out == NULL)
		*out = tmp;
	return (IDMAP_SUCCESS);
}


#define	gettext(s)	s
static stat_table_t stattable[] = {
	{IDMAP_SUCCESS, gettext("Success"), 0},
	{IDMAP_NEXT, gettext("More results available"), 0},
	{IDMAP_ERR_OTHER, gettext("Undefined error"), EINVAL},
	{IDMAP_ERR_INTERNAL, gettext("Internal error"), EINVAL},
	{IDMAP_ERR_MEMORY, gettext("Out of memory"), ENOMEM},
	{IDMAP_ERR_NORESULT, gettext("No results available"), EINVAL},
	{IDMAP_ERR_NOTUSER, gettext("Not a user"), EINVAL},
	{IDMAP_ERR_NOTGROUP, gettext("Not a group"), EINVAL},
	{IDMAP_ERR_NOTSUPPORTED, gettext("Operation not supported"), EINVAL},
	{IDMAP_ERR_W2U_NAMERULE,
		gettext("Invalid Windows to UNIX name-based rule"), EINVAL},
	{IDMAP_ERR_U2W_NAMERULE,
		gettext("Invalid UNIX to Windows name-based rule"), EINVAL},
	{IDMAP_ERR_CACHE, gettext("Invalid cache"), EINVAL},
	{IDMAP_ERR_DB, gettext("Invalid database"), EINVAL},
	{IDMAP_ERR_ARG, gettext("Invalid argument"), EINVAL},
	{IDMAP_ERR_SID, gettext("Invalid SID"), EINVAL},
	{IDMAP_ERR_IDTYPE, gettext("Invalid identity type"), EINVAL},
	{IDMAP_ERR_RPC_HANDLE, gettext("Bad RPC handle"), EINVAL},
	{IDMAP_ERR_RPC, gettext("RPC error"), EINVAL},
	{IDMAP_ERR_CLIENT_HANDLE, gettext("Bad client handle"), EINVAL},
	{IDMAP_ERR_BUSY, gettext("Server is busy"), EINVAL},
	{IDMAP_ERR_PERMISSION_DENIED, gettext("Permisssion denied"), EINVAL},
	{IDMAP_ERR_NOMAPPING,
		gettext("Mapping not found or inhibited"), EINVAL},
	{IDMAP_ERR_NEW_ID_ALLOC_REQD,
		gettext("New mapping needs to be created"), EINVAL},
	{IDMAP_ERR_DOMAIN, gettext("Invalid domain"), EINVAL},
	{IDMAP_ERR_SECURITY, gettext("Security issue"), EINVAL},
	{IDMAP_ERR_NOTFOUND, gettext("Not found"), EINVAL},
	{IDMAP_ERR_DOMAIN_NOTFOUND, gettext("Domain not found"), EINVAL},
	{IDMAP_ERR_UPDATE_NOTALLOWED, gettext("Update not allowed"), EINVAL},
	{IDMAP_ERR_CFG, gettext("Configuration error"), EINVAL},
	{IDMAP_ERR_CFG_CHANGE, gettext("Invalid configuration change"), EINVAL},
	{IDMAP_ERR_NOTMAPPED_WELLKNOWN,
		gettext("No mapping for well-known SID"), EINVAL},
	{IDMAP_ERR_RETRIABLE_NET_ERR,
		gettext("Network error"), EINVAL},
	{-1, NULL, 0}
};
#undef	gettext


/*
 * Get description of status code
 *
 * Input:
 * status - Status code returned by libidmap API call
 *
 * Return Value:
 * human-readable localized description of idmap_stat
 */
/* ARGSUSED */
const char *
idmap_stat2string(idmap_handle_t *handle, idmap_stat status) {
	int i;

	for (i = 0; stattable[i].msg; i++) {
		if (stattable[i].retcode == status)
			return (stattable[i].msg);
	}
	return (gettext("Unknown error"));
}


static int
idmap_stat2errno(idmap_stat stat) {
	int i;
	for (i = 0; stattable[i].msg; i++) {
		if (stattable[i].retcode == stat)
			return (stattable[i].errnum);
	}
	return (EINVAL);
}


/*
 * Get status code from string
 */
idmap_stat
idmap_string2stat(const char *str) {
	if (str == NULL)
		return (IDMAP_ERR_INTERNAL);

#define	return_cmp(a) \
	if (0 == strcmp(str, "IDMAP_ERR_" #a)) \
		return (IDMAP_ERR_ ## a);

	return_cmp(OTHER);
	return_cmp(INTERNAL);
	return_cmp(MEMORY);
	return_cmp(NORESULT);
	return_cmp(NOTUSER);
	return_cmp(NOTGROUP);
	return_cmp(NOTSUPPORTED);
	return_cmp(W2U_NAMERULE);
	return_cmp(U2W_NAMERULE);
	return_cmp(CACHE);
	return_cmp(DB);
	return_cmp(ARG);
	return_cmp(SID);
	return_cmp(IDTYPE);
	return_cmp(RPC_HANDLE);
	return_cmp(RPC);
	return_cmp(CLIENT_HANDLE);
	return_cmp(BUSY);
	return_cmp(PERMISSION_DENIED);
	return_cmp(NOMAPPING);
	return_cmp(NEW_ID_ALLOC_REQD);
	return_cmp(DOMAIN);
	return_cmp(SECURITY);
	return_cmp(NOTFOUND);
	return_cmp(DOMAIN_NOTFOUND);
	return_cmp(MEMORY);
	return_cmp(UPDATE_NOTALLOWED);
	return_cmp(CFG);
	return_cmp(CFG_CHANGE);
	return_cmp(NOTMAPPED_WELLKNOWN);
	return_cmp(RETRIABLE_NET_ERR);
#undef return_cmp

	return (IDMAP_ERR_OTHER);
}


/*
 * Map the given status to one that can be returned by the protocol
 */
idmap_stat
idmap_stat4prot(idmap_stat status) {
	switch (status) {
	case IDMAP_ERR_MEMORY:
	case IDMAP_ERR_CACHE:
		return (IDMAP_ERR_INTERNAL);
	}
	return (status);
}
