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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright Milan Jurik 2012. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2015 Joyent, Inc.
 */


/*
 * libidmap API
 */

#include <stdlib.h>
#include <sys/varargs.h>
#include <inttypes.h>
#include <errno.h>
#include <strings.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <libintl.h>
#include <syslog.h>
#include <assert.h>
#include "idmap_impl.h"
#include "idmap_cache.h"

static struct timeval TIMEOUT = { 25, 0 };

static int idmap_stat2errno(idmap_stat);
static idmap_stat	idmap_strdupnull(char **, const char *);

#define	__ITER_CREATE(itera, argu, ityp)\
	itera = calloc(1, sizeof (*itera));\
	if (itera == NULL) {\
		errno = ENOMEM;\
		return (IDMAP_ERR_MEMORY);\
	}\
	argu = calloc(1, sizeof (*argu));\
	if (argu == NULL) {\
		free(itera);\
		errno = ENOMEM;\
		return (IDMAP_ERR_MEMORY);\
	}\
	itera->type = ityp;\
	itera->retcode = IDMAP_NEXT;\
	itera->limit = 1024;\
	itera->arg = argu;

#define	__ITER_CHECK(itera, ityp)\
	if (itera == NULL) {\
		errno = EINVAL;\
		return (IDMAP_ERR_ARG);\
	}\
	if (itera->type != ityp) {\
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
idmap_free(void *ptr)
{
	free(ptr);
}


static idmap_stat
idmap_get_prop(idmap_prop_type pr, idmap_prop_res *res)
{
	idmap_stat retcode;

	(void) memset(res, 0, sizeof (*res));

	retcode = _idmap_clnt_call(IDMAP_GET_PROP,
	    (xdrproc_t)xdr_idmap_prop_type, (caddr_t)&pr,
	    (xdrproc_t)xdr_idmap_prop_res, (caddr_t)res, TIMEOUT);
	if (retcode != IDMAP_SUCCESS)
		return (retcode);

	return (res->retcode); /* This might not be IDMAP_SUCCESS! */
}


idmap_stat
idmap_get_prop_ds(idmap_prop_type pr, idmap_ad_disc_ds_t *dc)
{
	idmap_prop_res res;
	idmap_stat rc = IDMAP_SUCCESS;

	rc = idmap_get_prop(pr, &res);
	if (rc < 0)
		return (rc);

	dc->port = res.value.idmap_prop_val_u.dsval.port;
	(void) strlcpy(dc->host, res.value.idmap_prop_val_u.dsval.host,
	    AD_DISC_MAXHOSTNAME);

	/* xdr doesn't guarantee 0-termination of char[]: */
	dc->host[AD_DISC_MAXHOSTNAME - 1] = '\0';

	return (rc);
}


/*
 * Sometimes the property is not set. In that case, str is set to NULL but
 * otherwise IDMAP_SUCCESS is returned.
 */
idmap_stat
idmap_get_prop_str(idmap_prop_type pr, char **str)
{
	idmap_prop_res res;
	idmap_stat rc = IDMAP_SUCCESS;

	rc = idmap_get_prop(pr, &res);
	if (rc < 0)
		return (rc);

	rc = idmap_strdupnull(str, res.value.idmap_prop_val_u.utf8val);
	return (rc);
}

/*
 * Create/Initialize handle for updates
 *
 * Output:
 * udthandle - update handle
 */
idmap_stat
idmap_udt_create(idmap_udt_handle_t **udthandle)
{
	idmap_udt_handle_t	*tmp;

	if (udthandle == NULL) {
		errno = EINVAL;
		return (IDMAP_ERR_ARG);
	}
	if ((tmp = calloc(1, sizeof (*tmp))) == NULL) {
		errno = ENOMEM;
		return (IDMAP_ERR_MEMORY);
	}

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
idmap_udt_commit(idmap_udt_handle_t *udthandle)
{
	idmap_update_res	res;
	idmap_stat		retcode;

	if (udthandle == NULL) {
		errno = EINVAL;
		return (IDMAP_ERR_ARG);
	}

	(void) memset(&res, 0, sizeof (res));

	retcode = _idmap_clnt_call(IDMAP_UPDATE,
	    (xdrproc_t)xdr_idmap_update_batch, (caddr_t)&udthandle->batch,
	    (xdrproc_t)xdr_idmap_update_res, (caddr_t)&res,
	    TIMEOUT);
	if (retcode != IDMAP_SUCCESS)
		goto out;

	retcode = udthandle->commit_stat = res.retcode;
	udthandle->error_index = res.error_index;

	if (retcode != IDMAP_SUCCESS) {

		if (udthandle->error_index < 0)
			goto out;

		retcode = idmap_namerule_cpy(&udthandle->error_rule,
		    &res.error_rule);
		if (retcode != IDMAP_SUCCESS) {
			udthandle->error_index = -2;
			goto out;
		}

		retcode = idmap_namerule_cpy(&udthandle->conflict_rule,
		    &res.conflict_rule);
		if (retcode != IDMAP_SUCCESS) {
			udthandle->error_index = -2;
			goto out;
		}
	}

	retcode = res.retcode;


out:
	/* reset handle so that it can be used again */
	if (retcode == IDMAP_SUCCESS) {
		_IDMAP_RESET_UDT_HANDLE(udthandle);
	}

	xdr_free(xdr_idmap_update_res, (caddr_t)&res);
	errno = idmap_stat2errno(retcode);
	return (retcode);
}


static void
idmap_namerule_parts_clear(char **windomain, char **winname,
    char **unixname, boolean_t *is_user, boolean_t *is_wuser,
    boolean_t *is_nt4, int *direction)
{
	if (windomain)
		*windomain = NULL;
	if (winname)
		*winname = NULL;
	if (unixname)
		*unixname = NULL;

	if (is_nt4)
		*is_nt4 = 0;
	if (is_user)
		*is_user = -1;
	if (is_wuser)
		*is_wuser = -1;
	if (direction)
		*direction = IDMAP_DIRECTION_UNDEF;
}

static idmap_stat
idmap_namerule2parts(idmap_namerule *rule,
    char **windomain, char **winname,
    char **unixname, boolean_t *is_user, boolean_t *is_wuser,
    boolean_t *is_nt4, int *direction)
{
	idmap_stat retcode;

	if (EMPTY_STRING(rule->winname) && EMPTY_STRING(rule->unixname))
		return (IDMAP_ERR_NORESULT);


	retcode = idmap_strdupnull(windomain, rule->windomain);
	if (retcode != IDMAP_SUCCESS)
		goto errout;

	retcode = idmap_strdupnull(winname, rule->winname);
	if (retcode != IDMAP_SUCCESS)
		goto errout;

	retcode = idmap_strdupnull(unixname, rule->unixname);
	if (retcode != IDMAP_SUCCESS)
		goto errout;


	if (is_user)
		*is_user = rule->is_user;
	if (is_wuser)
		*is_wuser = rule->is_wuser;
	if (is_nt4)
		*is_nt4 = rule->is_nt4;
	if (direction)
		*direction = rule->direction;


	return (IDMAP_SUCCESS);

errout:
	if (windomain && *windomain)
		free(*windomain);
	if (winname && *winname)
		free(*winname);
	if (unixname && *unixname)
		free(*unixname);

	idmap_namerule_parts_clear(windomain, winname,
	    unixname, is_user, is_wuser, is_nt4, direction);

	return (retcode);

}

/*
 * Retrieve the index of the failed batch element. error_index == -1
 * indicates failure at the beginning, -2 at the end.
 *
 * If idmap_udt_commit didn't return error, the returned value is undefined.
 *
 * Return value:
 * IDMAP_SUCCESS
 */

idmap_stat
idmap_udt_get_error_index(idmap_udt_handle_t *udthandle,
    int64_t *error_index)
{
	if (error_index)
		*error_index = udthandle->error_index;

	return (IDMAP_SUCCESS);
}


/*
 * Retrieve the rule which caused the batch to fail. If
 * idmap_udt_commit didn't return error or if error_index is < 0, the
 * retrieved rule is undefined.
 *
 * Return value:
 * IDMAP_ERR_NORESULT if there is no error rule.
 * IDMAP_SUCCESS if the rule was obtained OK.
 * other error code (IDMAP_ERR_NOMEMORY etc)
 */

idmap_stat
idmap_udt_get_error_rule(idmap_udt_handle_t *udthandle,
    char **windomain, char **winname,
    char **unixname, boolean_t *is_user, boolean_t *is_wuser,
    boolean_t *is_nt4, int *direction)
{
	idmap_namerule_parts_clear(windomain, winname,
	    unixname, is_user, is_wuser, is_nt4, direction);

	if (udthandle->commit_stat == IDMAP_SUCCESS ||
	    udthandle->error_index < 0)
		return (IDMAP_ERR_NORESULT);

	return (idmap_namerule2parts(
	    &udthandle->error_rule,
	    windomain,
	    winname,
	    unixname,
	    is_user,
	    is_wuser,
	    is_nt4,
	    direction));
}

/*
 * Retrieve the rule with which there was a conflict. TODO: retrieve
 * the value.
 *
 * Return value:
 * IDMAP_ERR_NORESULT if there is no error rule.
 * IDMAP_SUCCESS if the rule was obtained OK.
 * other error code (IDMAP_ERR_NOMEMORY etc)
 */

idmap_stat
idmap_udt_get_conflict_rule(idmap_udt_handle_t *udthandle,
    char **windomain, char **winname,
    char **unixname, boolean_t *is_user, boolean_t *is_wuser,
    boolean_t *is_nt4, int *direction)
{
	idmap_namerule_parts_clear(windomain, winname,
	    unixname, is_user, is_wuser, is_nt4, direction);

	if (udthandle->commit_stat != IDMAP_ERR_W2U_NAMERULE_CONFLICT &&
	    udthandle->commit_stat != IDMAP_ERR_U2W_NAMERULE_CONFLICT) {
		return (IDMAP_ERR_NORESULT);
	}

	return (idmap_namerule2parts(
	    &udthandle->conflict_rule,
	    windomain,
	    winname,
	    unixname,
	    is_user,
	    is_wuser,
	    is_nt4,
	    direction));
}


/*
 * Destroy the update handle
 */
void
idmap_udt_destroy(idmap_udt_handle_t *udthandle)
{
	if (udthandle == NULL)
		return;
	xdr_free(xdr_idmap_update_batch, (caddr_t)&udthandle->batch);
	xdr_free(xdr_idmap_namerule, (caddr_t)&udthandle->error_rule);
	xdr_free(xdr_idmap_namerule, (caddr_t)&udthandle->conflict_rule);
	free(udthandle);
}


idmap_stat
idmap_udt_add_namerule(idmap_udt_handle_t *udthandle, const char *windomain,
    boolean_t is_user, boolean_t is_wuser, const char *winname,
    const char *unixname, boolean_t is_nt4, int direction)
{
	idmap_retcode	retcode;
	idmap_namerule	*rule = NULL;

	retcode = _udt_extend_batch(udthandle);
	if (retcode != IDMAP_SUCCESS)
		goto errout;

	rule = &udthandle->batch.
	    idmap_update_batch_val[udthandle->next].
	    idmap_update_op_u.rule;
	rule->is_user = is_user;
	rule->is_wuser = is_wuser;
	rule->direction = direction;
	rule->is_nt4 = is_nt4;

	retcode = idmap_strdupnull(&rule->windomain, windomain);
	if (retcode != IDMAP_SUCCESS)
		goto errout;

	retcode = idmap_strdupnull(&rule->winname, winname);
	if (retcode != IDMAP_SUCCESS)
		goto errout;

	retcode = idmap_strdupnull(&rule->unixname, unixname);
	if (retcode != IDMAP_SUCCESS)
		goto errout;

	udthandle->batch.idmap_update_batch_val[udthandle->next].opnum =
	    OP_ADD_NAMERULE;
	udthandle->next++;
	return (IDMAP_SUCCESS);

errout:
	/* The batch should still be usable */
	if (rule)
		xdr_free(xdr_idmap_namerule, (caddr_t)rule);
	errno = idmap_stat2errno(retcode);
	return (retcode);
}


/* ARGSUSED */
idmap_stat
idmap_udt_rm_namerule(idmap_udt_handle_t *udthandle, boolean_t is_user,
    boolean_t is_wuser,	const char *windomain, const char *winname,
    const char *unixname, int direction)
{
	idmap_retcode	retcode;
	idmap_namerule	*rule = NULL;

	retcode = _udt_extend_batch(udthandle);
	if (retcode != IDMAP_SUCCESS)
		goto errout;

	rule = &udthandle->batch.
	    idmap_update_batch_val[udthandle->next].
	    idmap_update_op_u.rule;
	rule->is_user = is_user;
	rule->is_wuser = is_wuser;
	rule->direction = direction;

	retcode = idmap_strdupnull(&rule->windomain, windomain);
	if (retcode != IDMAP_SUCCESS)
		goto errout;

	retcode = idmap_strdupnull(&rule->winname, winname);
	if (retcode != IDMAP_SUCCESS)
		goto errout;

	retcode = idmap_strdupnull(&rule->unixname, unixname);
	if (retcode != IDMAP_SUCCESS)
		goto errout;

	udthandle->batch.idmap_update_batch_val[udthandle->next].opnum =
	    OP_RM_NAMERULE;
	udthandle->next++;
	return (IDMAP_SUCCESS);

errout:
	if (rule)
		xdr_free(xdr_idmap_namerule, (caddr_t)rule);
	errno = idmap_stat2errno(retcode);
	return (retcode);
}


/* ARGSUSED */
idmap_stat
idmap_udt_flush_namerules(idmap_udt_handle_t *udthandle)
{
	idmap_retcode	retcode;

	retcode = _udt_extend_batch(udthandle);
	if (retcode != IDMAP_SUCCESS)
		goto errout;

	udthandle->batch.idmap_update_batch_val[udthandle->next].opnum =
	    OP_FLUSH_NAMERULES;
	udthandle->next++;
	return (IDMAP_SUCCESS);

errout:
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
idmap_iter_set_limit(idmap_iter_t *iter, uint64_t limit)
{
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
idmap_iter_namerules(const char *windomain, boolean_t is_user,
    boolean_t is_wuser, const char *winname, const char *unixname,
    idmap_iter_t **iter)
{

	idmap_iter_t			*tmpiter;
	idmap_list_namerules_1_argument	*arg = NULL;
	idmap_namerule			*rule;
	idmap_retcode			retcode;

	__ITER_CREATE(tmpiter, arg, IDMAP_LIST_NAMERULES);

	rule = &arg->rule;
	rule->is_user = is_user;
	rule->is_wuser = is_wuser;
	rule->direction = IDMAP_DIRECTION_UNDEF;

	retcode = idmap_strdupnull(&rule->windomain, windomain);
	if (retcode != IDMAP_SUCCESS)
		goto errout;

	retcode = idmap_strdupnull(&rule->winname, winname);
	if (retcode != IDMAP_SUCCESS)
		goto errout;

	retcode = idmap_strdupnull(&rule->unixname, unixname);
	if (retcode != IDMAP_SUCCESS)
		goto errout;

	*iter = tmpiter;
	return (IDMAP_SUCCESS);

errout:
	if (arg) {
		xdr_free(xdr_idmap_list_namerules_1_argument, (char *)arg);
		free(arg);
	}
	if (tmpiter)
		free(tmpiter);

	return (retcode);
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
    char **winname, char **unixname,  boolean_t *is_user,
    boolean_t *is_wuser, boolean_t *is_nt4, int *direction)
{
	idmap_namerules_res		*namerules;
	idmap_list_namerules_1_argument	*arg;
	idmap_retcode			retcode;

	idmap_namerule_parts_clear(windomain, winname,
	    unixname, is_user, is_wuser, is_nt4, direction);


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
		return (IDMAP_ERR_ARG);
	}

	retcode = idmap_strdupnull(windomain,
	    namerules->rules.rules_val[iter->next].windomain);
	if (retcode != IDMAP_SUCCESS)
		goto errout;

	retcode = idmap_strdupnull(winname,
	    namerules->rules.rules_val[iter->next].winname);
	if (retcode != IDMAP_SUCCESS)
		goto errout;

	retcode = idmap_strdupnull(unixname,
	    namerules->rules.rules_val[iter->next].unixname);
	if (retcode != IDMAP_SUCCESS)
		goto errout;

	if (is_nt4)
		*is_nt4 = namerules->rules.rules_val[iter->next].is_nt4;
	if (is_user)
		*is_user = namerules->rules.rules_val[iter->next].is_user;
	if (is_wuser)
		*is_wuser = namerules->rules.rules_val[iter->next].is_wuser;
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
 * Output:
 * iter - iterator
 */
idmap_stat
idmap_iter_mappings(idmap_iter_t **iter, int flag)
{
	idmap_iter_t			*tmpiter;
	idmap_list_mappings_1_argument	*arg = NULL;

	__ITER_CREATE(tmpiter, arg, IDMAP_LIST_MAPPINGS);

	arg->flag = flag;
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
    char **windomain, char **unixname, boolean_t *is_user,
    boolean_t *is_wuser, int *direction, idmap_info *info)
{
	idmap_mappings_res		*mappings;
	idmap_list_mappings_1_argument	*arg;
	idmap_retcode			retcode;
	char				*str;

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
	if (is_user)
		*is_user = -1;
	if (is_wuser)
		*is_wuser = -1;
	if (direction)
		*direction = IDMAP_DIRECTION_UNDEF;

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
		return (IDMAP_ERR_ARG);
	}

	if (sidprefix) {
		str = mappings->mappings.mappings_val[iter->next].id1.
		    idmap_id_u.sid.prefix;
		if (str && *str != '\0') {
			*sidprefix = strdup(str);
			if (*sidprefix == NULL) {
				retcode = IDMAP_ERR_MEMORY;
				goto errout;
			}
		}
	}
	if (rid)
		*rid = mappings->mappings.mappings_val[iter->next].id1.
		    idmap_id_u.sid.rid;

	retcode = idmap_strdupnull(windomain,
	    mappings->mappings.mappings_val[iter->next].id1domain);
	if (retcode != IDMAP_SUCCESS)
		goto errout;

	retcode = idmap_strdupnull(winname,
	    mappings->mappings.mappings_val[iter->next].id1name);
	if (retcode != IDMAP_SUCCESS)
		goto errout;

	retcode = idmap_strdupnull(unixname,
	    mappings->mappings.mappings_val[iter->next].id2name);
	if (retcode != IDMAP_SUCCESS)
		goto errout;


	if (pid)
		*pid = mappings->mappings.mappings_val[iter->next].id2.
		    idmap_id_u.uid;
	if (direction)
		*direction = mappings->mappings.mappings_val[iter->next].
		    direction;
	if (is_user)
		*is_user = (mappings->mappings.mappings_val[iter->next].id2
		    .idtype == IDMAP_UID)?1:0;
	if (is_wuser)
		*is_wuser = (mappings->mappings.mappings_val[iter->next].id1
		    .idtype == IDMAP_USID)?1:0;

	if (info) {
		idmap_info_mov(info,
		    &mappings->mappings.mappings_val[iter->next].info);
	}
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
idmap_iter_destroy(idmap_iter_t *iter)
{
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
idmap_get_create(idmap_get_handle_t **gh)
{
	idmap_get_handle_t	*tmp;

	/* allocate the handle */
	if ((tmp = calloc(1, sizeof (*tmp))) == NULL) {
		errno = ENOMEM;
		return (IDMAP_ERR_MEMORY);
	}

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
    int flag, uid_t *uid, idmap_stat *stat)
{
	return (idmap_getext_uidbysid(gh, sidprefix, rid, flag, uid,
	    NULL, stat));
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
 * how  - mapping type if stat = 0
 *
 * Note: The output parameters will be set by idmap_get_mappings()
 */

idmap_stat
idmap_getext_uidbysid(idmap_get_handle_t *gh, char *sidprefix, idmap_rid_t rid,
    int flag, uid_t *uid, idmap_info *info, idmap_stat *stat)
{
	idmap_retcode	retcode;
	idmap_mapping	*mapping = NULL;

	/* sanity checks */
	if (gh == NULL)
		return (IDMAP_ERR_ARG);
	if (uid == NULL || sidprefix == NULL)
		return (IDMAP_ERR_ARG);

	if ((flag & IDMAP_REQ_FLG_USE_CACHE) &&
	    !(flag & IDMAP_REQ_FLG_MAPPING_INFO)) {
		retcode = idmap_cache_lookup_uidbysid(sidprefix, rid, uid);
		if (retcode  == IDMAP_SUCCESS || retcode == IDMAP_ERR_MEMORY) {
			*stat = retcode;
			return (retcode);
		}
	}

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
	gh->retlist[gh->next].info = info;
	gh->retlist[gh->next].cache_res = flag & IDMAP_REQ_FLG_USE_CACHE;

	gh->next++;
	return (IDMAP_SUCCESS);

errout:
	/* Batch created so far should still be usable */
	if (mapping)
		(void) memset(mapping, 0, sizeof (*mapping));
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
    int flag, gid_t *gid, idmap_stat *stat)
{
	return (idmap_getext_gidbysid(gh, sidprefix, rid, flag, gid,
	    NULL, stat));
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
 * how  - mapping type if stat = 0
 *
 * Note: The output parameters will be set by idmap_get_mappings()
 */
idmap_stat
idmap_getext_gidbysid(idmap_get_handle_t *gh, char *sidprefix, idmap_rid_t rid,
    int flag, gid_t *gid, idmap_info *info, idmap_stat *stat)
{

	idmap_retcode	retcode;
	idmap_mapping	*mapping = NULL;

	/* sanity checks */
	if (gh == NULL)
		return (IDMAP_ERR_ARG);
	if (gid == NULL || sidprefix == NULL)
		return (IDMAP_ERR_ARG);

	if ((flag & IDMAP_REQ_FLG_USE_CACHE) &&
	    !(flag & IDMAP_REQ_FLG_MAPPING_INFO)) {
		retcode = idmap_cache_lookup_gidbysid(sidprefix, rid, gid);
		if (retcode == IDMAP_SUCCESS || retcode == IDMAP_ERR_MEMORY) {
			*stat = retcode;
			return (retcode);
		}
	}

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
	gh->retlist[gh->next].info = info;
	gh->retlist[gh->next].cache_res = flag & IDMAP_REQ_FLG_USE_CACHE;

	gh->next++;
	return (IDMAP_SUCCESS);

errout:
	if (mapping)
		(void) memset(mapping, 0, sizeof (*mapping));
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
    int flag, uid_t *pid, int *is_user, idmap_stat *stat)
{
	return (idmap_getext_pidbysid(gh, sidprefix, rid, flag, pid, is_user,
	    NULL, stat));
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
 * how     - mapping type if stat = 0
 *
 * Note: The output parameters will be set by idmap_get_mappings()
 */
idmap_stat
idmap_getext_pidbysid(idmap_get_handle_t *gh, char *sidprefix, idmap_rid_t rid,
    int flag, uid_t *pid, int *is_user, idmap_info *info, idmap_stat *stat)
{
	idmap_retcode	retcode;
	idmap_mapping	*mapping = NULL;

	/* sanity checks */
	if (gh == NULL)
		return (IDMAP_ERR_ARG);
	if (pid == NULL || sidprefix == NULL || is_user == NULL)
		return (IDMAP_ERR_ARG);

	if ((flag & IDMAP_REQ_FLG_USE_CACHE) &&
	    !(flag & IDMAP_REQ_FLG_MAPPING_INFO)) {
		retcode = idmap_cache_lookup_pidbysid(sidprefix, rid, pid,
		    is_user);
		if (retcode  == IDMAP_SUCCESS || retcode == IDMAP_ERR_MEMORY) {
			*stat = retcode;
			return (retcode);
		}
	}

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
	gh->retlist[gh->next].info = info;
	gh->retlist[gh->next].cache_res = flag & IDMAP_REQ_FLG_USE_CACHE;

	gh->next++;
	return (IDMAP_SUCCESS);

errout:
	if (mapping)
		(void) memset(mapping, 0, sizeof (*mapping));
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
    char **sidprefix, idmap_rid_t *rid, idmap_stat *stat)
{
	return (idmap_getext_sidbyuid(gh, uid, flag, sidprefix, rid,
	    NULL, stat));
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
 * how  - mapping type if stat = 0
 *
 * Note: The output parameters will be set by idmap_get_mappings()
 */
idmap_stat
idmap_getext_sidbyuid(idmap_get_handle_t *gh, uid_t uid, int flag,
    char **sidprefix, idmap_rid_t *rid, idmap_info *info, idmap_stat *stat)
{

	idmap_retcode	retcode;
	idmap_mapping	*mapping = NULL;

	/* sanity checks */
	if (gh == NULL)
		return (IDMAP_ERR_ARG);
	if (sidprefix == NULL)
		return (IDMAP_ERR_ARG);

	if ((flag & IDMAP_REQ_FLG_USE_CACHE) &&
	    !(flag & IDMAP_REQ_FLG_MAPPING_INFO)) {
		retcode = idmap_cache_lookup_sidbyuid(sidprefix, rid, uid);
		if (retcode  == IDMAP_SUCCESS || retcode == IDMAP_ERR_MEMORY) {
			*stat = retcode;
			return (retcode);
		}
	}

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
	gh->retlist[gh->next].info = info;
	gh->retlist[gh->next].cache_res = flag & IDMAP_REQ_FLG_USE_CACHE;

	gh->next++;
	return (IDMAP_SUCCESS);

errout:
	if (mapping)
		(void) memset(mapping, 0, sizeof (*mapping));
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
    char **sidprefix, idmap_rid_t *rid, idmap_stat *stat)
{
	return (idmap_getext_sidbygid(gh, gid, flag, sidprefix, rid,
	    NULL, stat));
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
 * how        - mapping type if stat = 0
 *
 * Note: The output parameters will be set by idmap_get_mappings()
 */
idmap_stat
idmap_getext_sidbygid(idmap_get_handle_t *gh, gid_t gid, int flag,
    char **sidprefix, idmap_rid_t *rid, idmap_info *info, idmap_stat *stat)
{

	idmap_retcode	retcode;
	idmap_mapping	*mapping = NULL;

	/* sanity checks */
	if (gh == NULL)
		return (IDMAP_ERR_ARG);
	if (sidprefix == NULL)
		return (IDMAP_ERR_ARG);

	if ((flag & IDMAP_REQ_FLG_USE_CACHE) &&
	    !(flag & IDMAP_REQ_FLG_MAPPING_INFO)) {
		retcode = idmap_cache_lookup_sidbygid(sidprefix, rid, gid);
		if (retcode  == IDMAP_SUCCESS || retcode == IDMAP_ERR_MEMORY) {
			*stat = retcode;
			return (retcode);
		}
	}

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
	gh->retlist[gh->next].info = info;
	gh->retlist[gh->next].cache_res = flag & IDMAP_REQ_FLG_USE_CACHE;

	gh->next++;
	return (IDMAP_SUCCESS);

errout:
	if (mapping)
		(void) memset(mapping, 0, sizeof (*mapping));
	errno = idmap_stat2errno(retcode);
	return (retcode);
}


/*
 * Process the batched "get mapping" requests. The results (i.e.
 * status and identity) will be available in the data areas
 * provided by individual requests.
 */
idmap_stat
idmap_get_mappings(idmap_get_handle_t *gh)
{
	idmap_retcode	retcode;
	idmap_ids_res	res;
	idmap_id	*res_id;
	int		i;
	idmap_id	*req_id;
	int		direction;

	if (gh == NULL) {
		errno = EINVAL;
		return (IDMAP_ERR_ARG);
	}

	(void) memset(&res, 0, sizeof (idmap_ids_res));
	retcode = _idmap_clnt_call(IDMAP_GET_MAPPED_IDS,
	    (xdrproc_t)xdr_idmap_mapping_batch,
	    (caddr_t)&gh->batch,
	    (xdrproc_t)xdr_idmap_ids_res,
	    (caddr_t)&res,
	    TIMEOUT);
	if (retcode != IDMAP_SUCCESS) {
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
		res_id = &res.ids.ids_val[i].id;
		direction = res.ids.ids_val[i].direction;
		req_id = &gh->batch.idmap_mapping_batch_val[i].id1;
		switch (res_id->idtype) {
		case IDMAP_UID:
			if (gh->retlist[i].uid)
				*gh->retlist[i].uid = res_id->idmap_id_u.uid;
			if (gh->retlist[i].is_user)
				*gh->retlist[i].is_user = 1;

			if (res.ids.ids_val[i].retcode == IDMAP_SUCCESS &&
			    gh->retlist[i].cache_res) {
				if (gh->retlist[i].is_user != NULL)
					idmap_cache_add_sid2pid(
					    req_id->idmap_id_u.sid.prefix,
					    req_id->idmap_id_u.sid.rid,
					    res_id->idmap_id_u.uid, 1,
					    direction);
				else
					idmap_cache_add_sid2uid(
					    req_id->idmap_id_u.sid.prefix,
					    req_id->idmap_id_u.sid.rid,
					    res_id->idmap_id_u.uid,
					    direction);
			}
			break;

		case IDMAP_GID:
			if (gh->retlist[i].gid)
				*gh->retlist[i].gid = res_id->idmap_id_u.gid;
			if (gh->retlist[i].is_user)
				*gh->retlist[i].is_user = 0;

			if (res.ids.ids_val[i].retcode == IDMAP_SUCCESS &&
			    gh->retlist[i].cache_res) {
				if (gh->retlist[i].is_user != NULL)
					idmap_cache_add_sid2pid(
					    req_id->idmap_id_u.sid.prefix,
					    req_id->idmap_id_u.sid.rid,
					    res_id->idmap_id_u.gid, 0,
					    direction);
				else
					idmap_cache_add_sid2gid(
					    req_id->idmap_id_u.sid.prefix,
					    req_id->idmap_id_u.sid.rid,
					    res_id->idmap_id_u.gid,
					    direction);
			}
			break;

		case IDMAP_POSIXID:
			if (gh->retlist[i].uid)
				*gh->retlist[i].uid = 60001;
			if (gh->retlist[i].is_user)
				*gh->retlist[i].is_user = -1;
			break;

		case IDMAP_SID:
		case IDMAP_USID:
		case IDMAP_GSID:
			if (gh->retlist[i].rid)
				*gh->retlist[i].rid =
				    res_id->idmap_id_u.sid.rid;
			if (gh->retlist[i].sidprefix) {
				if (res_id->idmap_id_u.sid.prefix == NULL ||
				    *res_id->idmap_id_u.sid.prefix == '\0') {
					*gh->retlist[i].sidprefix = NULL;
					break;
				}
				*gh->retlist[i].sidprefix =
				    strdup(res_id->idmap_id_u.sid.prefix);
				if (*gh->retlist[i].sidprefix == NULL)
					*gh->retlist[i].stat =
					    IDMAP_ERR_MEMORY;
			}
			if (res.ids.ids_val[i].retcode == IDMAP_SUCCESS &&
			    gh->retlist[i].cache_res) {
				if (req_id->idtype == IDMAP_UID)
					idmap_cache_add_sid2uid(
					    res_id->idmap_id_u.sid.prefix,
					    res_id->idmap_id_u.sid.rid,
					    req_id->idmap_id_u.uid,
					    direction);
				else /* req_id->idtype == IDMAP_GID */
					idmap_cache_add_sid2gid(
					    res_id->idmap_id_u.sid.prefix,
					    res_id->idmap_id_u.sid.rid,
					    req_id->idmap_id_u.gid,
					    direction);
			}
			break;

		case IDMAP_NONE:
			break;

		default:
			*gh->retlist[i].stat = IDMAP_ERR_NORESULT;
			break;
		}
		if (gh->retlist[i].info != NULL) {
			idmap_info_mov(gh->retlist[i].info,
			    &res.ids.ids_val[i].info);
		}
	}
	retcode = IDMAP_SUCCESS;

out:
	_IDMAP_RESET_GET_HANDLE(gh);
	xdr_free(xdr_idmap_ids_res, (caddr_t)&res);
	errno = idmap_stat2errno(retcode);
	return (retcode);
}


/*
 * Destroy the "get mapping" handle
 */
void
idmap_get_destroy(idmap_get_handle_t *gh)
{
	if (gh == NULL)
		return;
	xdr_free(xdr_idmap_mapping_batch, (caddr_t)&gh->batch);
	if (gh->retlist)
		free(gh->retlist);
	free(gh);
}


/*
 * Get windows to unix mapping
 */
idmap_stat
idmap_get_w2u_mapping(
		const char *sidprefix, idmap_rid_t *rid,
		const char *winname, const char *windomain,
		int flag, int *is_user, int *is_wuser,
		uid_t *pid, char **unixname, int *direction, idmap_info *info)
{
	idmap_mapping		request, *mapping;
	idmap_mappings_res	result;
	idmap_retcode		retcode, rc;

	(void) memset(&request, 0, sizeof (request));
	(void) memset(&result, 0, sizeof (result));

	if (pid)
		*pid = UINT32_MAX;
	if (unixname)
		*unixname = NULL;
	if (direction)
		*direction = IDMAP_DIRECTION_UNDEF;

	request.flag = flag;
	request.id1.idtype = IDMAP_SID;
	if (sidprefix && rid) {
		request.id1.idmap_id_u.sid.prefix = (char *)sidprefix;
		request.id1.idmap_id_u.sid.rid = *rid;
	} else if (winname) {
		retcode = idmap_strdupnull(&request.id1name, winname);
		if (retcode != IDMAP_SUCCESS)
			goto out;

		retcode = idmap_strdupnull(&request.id1domain, windomain);
		if (retcode != IDMAP_SUCCESS)
			goto out;

		request.id1.idmap_id_u.sid.prefix = NULL;
	} else {
		errno = EINVAL;
		return (IDMAP_ERR_ARG);
	}

	if (*is_user == 1)
		request.id2.idtype = IDMAP_UID;
	else if (*is_user == 0)
		request.id2.idtype = IDMAP_GID;
	else
		request.id2.idtype = IDMAP_POSIXID;

	if (*is_wuser == 1)
		request.id1.idtype = IDMAP_USID;
	else if (*is_wuser == 0)
		request.id1.idtype = IDMAP_GSID;
	else
		request.id1.idtype = IDMAP_SID;

	retcode = _idmap_clnt_call(IDMAP_GET_MAPPED_ID_BY_NAME,
	    (xdrproc_t)xdr_idmap_mapping, (caddr_t)&request,
	    (xdrproc_t)xdr_idmap_mappings_res, (caddr_t)&result,
	    TIMEOUT);

	if (retcode != IDMAP_SUCCESS)
		goto out;

	retcode = result.retcode;

	if ((mapping = result.mappings.mappings_val) == NULL) {
		if (retcode == IDMAP_SUCCESS)
			retcode = IDMAP_ERR_NORESULT;
		goto out;
	}

	if (info != NULL)
		idmap_info_mov(info, &mapping->info);

	if (mapping->id2.idtype == IDMAP_UID) {
		*is_user = 1;
	} else if (mapping->id2.idtype == IDMAP_GID) {
		*is_user = 0;
	} else {
		goto out;
	}

	if (mapping->id1.idtype == IDMAP_USID) {
		*is_wuser = 1;
	} else if (mapping->id1.idtype == IDMAP_GSID) {
		*is_wuser = 0;
	} else {
		goto out;
	}

	if (direction)
		*direction = mapping->direction;
	if (pid)
		*pid = mapping->id2.idmap_id_u.uid;

	rc = idmap_strdupnull(unixname, mapping->id2name);
	if (rc != IDMAP_SUCCESS)
		retcode = rc;

out:
	if (request.id1name != NULL)
		free(request.id1name);
	if (request.id1domain != NULL)
		free(request.id1domain);
	xdr_free(xdr_idmap_mappings_res, (caddr_t)&result);
	if (retcode != IDMAP_SUCCESS)
		errno = idmap_stat2errno(retcode);
	return (retcode);
}


/*
 * Get unix to windows mapping
 */
idmap_stat
idmap_get_u2w_mapping(
		uid_t *pid, const char *unixname,
		int flag, int is_user, int *is_wuser,
		char **sidprefix, idmap_rid_t *rid,
		char **winname, char **windomain,
		int *direction, idmap_info *info)
{
	idmap_mapping		request, *mapping;
	idmap_mappings_res	result;
	idmap_retcode		retcode, rc;

	if (sidprefix)
		*sidprefix = NULL;
	if (winname)
		*winname = NULL;
	if (windomain)
		*windomain = NULL;
	if (rid)
		*rid = UINT32_MAX;
	if (direction)
		*direction = IDMAP_DIRECTION_UNDEF;

	(void) memset(&request, 0, sizeof (request));
	(void) memset(&result, 0, sizeof (result));

	request.flag = flag;
	request.id1.idtype = is_user?IDMAP_UID:IDMAP_GID;

	if (pid && *pid != UINT32_MAX) {
		request.id1.idmap_id_u.uid = *pid;
	} else if (unixname) {
		request.id1name = (char *)unixname;
		request.id1.idmap_id_u.uid = UINT32_MAX;
	} else {
		errno = EINVAL;
		return (IDMAP_ERR_ARG);
	}

	if (is_wuser == NULL)
		request.id2.idtype = IDMAP_SID;
	else if (*is_wuser == -1)
		request.id2.idtype = IDMAP_SID;
	else if (*is_wuser == 0)
		request.id2.idtype = IDMAP_GSID;
	else if (*is_wuser == 1)
		request.id2.idtype = IDMAP_USID;

	retcode = _idmap_clnt_call(IDMAP_GET_MAPPED_ID_BY_NAME,
	    (xdrproc_t)xdr_idmap_mapping, (caddr_t)&request,
	    (xdrproc_t)xdr_idmap_mappings_res, (caddr_t)&result,
	    TIMEOUT);

	if (retcode != IDMAP_SUCCESS)
		return (retcode);

	retcode = result.retcode;

	if ((mapping = result.mappings.mappings_val) == NULL) {
		if (retcode == IDMAP_SUCCESS)
			retcode = IDMAP_ERR_NORESULT;
		goto out;
	}

	if (info != NULL)
		idmap_info_mov(info, &mapping->info);

	if (direction != NULL)
		*direction = mapping->direction;

	if (is_wuser != NULL) {
		if (mapping->id2.idtype == IDMAP_USID)
			*is_wuser = 1;
		else if (mapping->id2.idtype == IDMAP_GSID)
			*is_wuser = 0;
		else
			*is_wuser = -1;
	}

	if (sidprefix && mapping->id2.idmap_id_u.sid.prefix &&
	    *mapping->id2.idmap_id_u.sid.prefix != '\0') {
		*sidprefix = strdup(mapping->id2.idmap_id_u.sid.prefix);
		if (*sidprefix == NULL) {
			retcode = IDMAP_ERR_MEMORY;
			goto errout;
		}
	}
	if (rid)
		*rid = mapping->id2.idmap_id_u.sid.rid;

	rc = idmap_strdupnull(winname, mapping->id2name);
	if (rc != IDMAP_SUCCESS)
		retcode = rc;

	rc = idmap_strdupnull(windomain, mapping->id2domain);
	if (rc != IDMAP_SUCCESS)
		retcode = rc;

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
	{IDMAP_ERR_NOTSUPPORTED, gettext("Operation not supported"), ENOTSUP},
	{IDMAP_ERR_W2U_NAMERULE,
		gettext("Invalid Windows to UNIX name-based rule"), EINVAL},
	{IDMAP_ERR_U2W_NAMERULE,
		gettext("Invalid UNIX to Windows name-based rule"), EINVAL},
	{IDMAP_ERR_CACHE, gettext("Invalid cache"), EINVAL},
	{IDMAP_ERR_DB, gettext("Invalid database"), EINVAL},
	{IDMAP_ERR_ARG, gettext("Invalid argument"), EINVAL},
	{IDMAP_ERR_SID, gettext("Invalid SID"), EINVAL},
	{IDMAP_ERR_IDTYPE, gettext("Invalid identity type"), EINVAL},
	{IDMAP_ERR_RPC_HANDLE, gettext("Bad RPC handle"), EBADF},
	{IDMAP_ERR_RPC, gettext("RPC error"), EINVAL},
	{IDMAP_ERR_CLIENT_HANDLE, gettext("Bad client handle"), EINVAL},
	{IDMAP_ERR_BUSY, gettext("Server is busy"), EBUSY},
	{IDMAP_ERR_PERMISSION_DENIED, gettext("Permission denied"), EACCES},
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
		gettext("Windows lookup failed"), EINVAL},
	{IDMAP_ERR_W2U_NAMERULE_CONFLICT,
		gettext("Duplicate rule or conflicts with an existing "
		"Windows to UNIX name-based rule"), EINVAL},
	{IDMAP_ERR_U2W_NAMERULE_CONFLICT,
		gettext("Duplicate rule or conflicts with an existing "
		"Unix to Windows name-based rule"), EINVAL},
	{IDMAP_ERR_BAD_UTF8,
		gettext("Invalid or illegal UTF-8 sequence found in "
		"a given Windows entity name or domain name"), EINVAL},
	{IDMAP_ERR_NONE_GENERATED,
		gettext("Mapping not found and none created (see -c option)"),
		EINVAL},
	{IDMAP_ERR_PROP_UNKNOWN,
		gettext("Undefined property"),
		EINVAL},
	{IDMAP_ERR_NS_LDAP_CFG,
		gettext("Native LDAP configuration error"), EINVAL},
	{IDMAP_ERR_NS_LDAP_PARTIAL,
		gettext("Partial result from Native LDAP"), EINVAL},
	{IDMAP_ERR_NS_LDAP_OP_FAILED,
		gettext("Native LDAP operation failed"), EINVAL},
	{IDMAP_ERR_NS_LDAP_BAD_WINNAME,
		gettext("Improper winname form found in Native LDAP"), EINVAL},
	{IDMAP_ERR_NO_ACTIVEDIRECTORY,
		gettext("No AD servers"),
		EINVAL},
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
const char *
idmap_stat2string(idmap_stat status)
{
	int i;

	for (i = 0; stattable[i].msg; i++) {
		if (stattable[i].retcode == status)
			return (dgettext(TEXT_DOMAIN, stattable[i].msg));
	}
	return (dgettext(TEXT_DOMAIN, "Unknown error"));
}


static int
idmap_stat2errno(idmap_stat stat)
{
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
idmap_string2stat(const char *str)
{
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
	return_cmp(W2U_NAMERULE_CONFLICT);
	return_cmp(U2W_NAMERULE_CONFLICT);
	return_cmp(BAD_UTF8);
	return_cmp(NONE_GENERATED);
	return_cmp(PROP_UNKNOWN);
	return_cmp(NS_LDAP_CFG);
	return_cmp(NS_LDAP_PARTIAL);
	return_cmp(NS_LDAP_OP_FAILED);
	return_cmp(NS_LDAP_BAD_WINNAME);
	return_cmp(NO_ACTIVEDIRECTORY);
#undef return_cmp

	return (IDMAP_ERR_OTHER);
}


/*
 * Map the given status to one that can be returned by the protocol
 */
idmap_stat
idmap_stat4prot(idmap_stat status)
{
	switch (status) {
	case IDMAP_ERR_MEMORY:
	case IDMAP_ERR_CACHE:
		return (IDMAP_ERR_INTERNAL);
	}
	return (status);
}


/*
 * This is a convenience routine which duplicates a string after
 * checking for NULL pointers. This function will return success if
 * either the 'to' OR 'from' pointers are NULL.
 */
static idmap_stat
idmap_strdupnull(char **to, const char *from)
{
	if (to == NULL)
		return (IDMAP_SUCCESS);

	if (from == NULL || *from == '\0') {
		*to = NULL;
		return (IDMAP_SUCCESS);
	}

	*to = strdup(from);
	if (*to == NULL)
		return (IDMAP_ERR_MEMORY);
	return (IDMAP_SUCCESS);
}


idmap_stat
idmap_namerule_cpy(idmap_namerule *to, idmap_namerule *from)
{
	idmap_stat retval;

	if (to == NULL)
		return (IDMAP_SUCCESS);

	(void) memcpy(to, from, sizeof (idmap_namerule));
	to->windomain = NULL;
	to->winname = NULL;
	to->unixname = NULL;

	retval = idmap_strdupnull(&to->windomain, from->windomain);
	if (retval != IDMAP_SUCCESS)
		return (retval);

	retval = idmap_strdupnull(&to->winname, from->winname);
	if (retval != IDMAP_SUCCESS) {
		free(to->windomain);
		to->windomain = NULL;
		return (retval);
	}

	retval = idmap_strdupnull(&to->unixname, from->unixname);
	if (retval != IDMAP_SUCCESS) {
		free(to->windomain);
		to->windomain = NULL;
		free(to->winname);
		to->winname = NULL;
		return (retval);
	}

	return (retval);
}


/*
 * Move the contents of the "info" structure from "from" to "to".
 */
void
idmap_info_mov(idmap_info *to, idmap_info *from)
{
	(void) memcpy(to, from, sizeof (idmap_info));
	(void) memset(from, 0, sizeof (idmap_info));
}


void
idmap_info_free(idmap_info *info)
{
	if (info == NULL)
		return;

	xdr_free(xdr_idmap_info, (caddr_t)info);
	(void) memset(info, 0, sizeof (idmap_info));
}


void
idmap_how_clear(idmap_how *how)
{
	xdr_free(xdr_idmap_how, (caddr_t)how);
	(void) memset(how, 0, sizeof (*how));
}


/*
 * Get uid given Windows name
 */
idmap_stat
idmap_getuidbywinname(const char *name, const char *domain, int flag,
    uid_t *uid)
{
	idmap_retcode	rc;
	int		is_user = 1;
	int		is_wuser = -1;
	int 		direction;

	if (uid == NULL)
		return (IDMAP_ERR_ARG);

	if (flag & IDMAP_REQ_FLG_USE_CACHE) {
		rc = idmap_cache_lookup_uidbywinname(name, domain, uid);
		if (rc == IDMAP_SUCCESS || rc == IDMAP_ERR_MEMORY)
			return (rc);
	}
	/* Get mapping */
	rc = idmap_get_w2u_mapping(NULL, NULL, name, domain, flag,
	    &is_user, &is_wuser, uid, NULL, &direction, NULL);

	if (rc == IDMAP_SUCCESS && (flag & IDMAP_REQ_FLG_USE_CACHE)) {
		/* If we have not got the domain don't store UID to winname */
		if (domain == NULL)
			direction = IDMAP_DIRECTION_W2U;
		idmap_cache_add_winname2uid(name, domain, *uid, direction);
	}

	return (rc);
}


/*
 * Get gid given Windows name
 */
idmap_stat
idmap_getgidbywinname(const char *name, const char *domain, int flag,
    gid_t *gid)
{
	idmap_retcode	rc;
	int		is_user = 0;
	int		is_wuser = -1;
	int		direction;

	if (gid == NULL)
		return (IDMAP_ERR_ARG);

	if (flag & IDMAP_REQ_FLG_USE_CACHE) {
		rc = idmap_cache_lookup_gidbywinname(name, domain, gid);
		if (rc == IDMAP_SUCCESS || rc == IDMAP_ERR_MEMORY)
			return (rc);
	}

	/* Get mapping */
	rc = idmap_get_w2u_mapping(NULL, NULL, name, domain, flag,
	    &is_user, &is_wuser, gid, NULL, &direction, NULL);

	if (rc == IDMAP_SUCCESS && (flag & IDMAP_REQ_FLG_USE_CACHE)) {
		/* If we have not got the domain don't store GID to winname */
		if (domain == NULL)
			direction = IDMAP_DIRECTION_W2U;
		idmap_cache_add_winname2gid(name, domain, *gid, direction);
	}

	return (rc);
}


/*
 * Get winname given pid
 */
idmap_stat
idmap_getwinnamebypid(uid_t pid, int is_user, int flag, char **name,
    char **domain)
{
	idmap_retcode	rc;
	int		len;
	char		*winname, *windomain;
	int		direction;

	if (name == NULL)
		return (IDMAP_ERR_ARG);

	if (flag & IDMAP_REQ_FLG_USE_CACHE) {
		if (is_user)
			rc = idmap_cache_lookup_winnamebyuid(&winname,
			    &windomain, pid);
		else
			rc = idmap_cache_lookup_winnamebygid(&winname,
			    &windomain, pid);
		if (rc == IDMAP_SUCCESS)
			goto out;
		if (rc == IDMAP_ERR_MEMORY)
			return (rc);
	}

	/* Get mapping */
	rc = idmap_get_u2w_mapping(&pid, NULL, flag, is_user, NULL,
	    NULL, NULL, &winname, &windomain, &direction, NULL);

	/* Return on error */
	if (rc != IDMAP_SUCCESS)
		return (rc);

	/*
	 * The given PID may have been mapped to a locally
	 * generated SID in which case there isn't any
	 * Windows name
	 */
	if (winname == NULL) {
		idmap_free(windomain);
		return (IDMAP_ERR_NORESULT);
	}

	if (flag & IDMAP_REQ_FLG_USE_CACHE) {
		if (is_user)
			idmap_cache_add_winname2uid(winname, windomain,
			    pid, direction);
		else
			idmap_cache_add_winname2gid(winname, windomain,
			    pid, direction);
	}

out:
	if (domain != NULL) {
		*name = winname;
		*domain = windomain;
	} else {
		char *wd = windomain != NULL ? windomain : "";
		len = snprintf(NULL, 0, "%s@%s", winname, wd) + 1;
		if ((*name = malloc(len)) != NULL)
			(void) snprintf(*name, len, "%s@%s", winname, wd);
		else
			rc = IDMAP_ERR_MEMORY;
		idmap_free(winname);
		idmap_free(windomain);
	}

	return (rc);
}


/*
 * Get winname given uid
 */
idmap_stat
idmap_getwinnamebyuid(uid_t uid, int flag, char **name, char **domain)
{
	return (idmap_getwinnamebypid(uid, 1, flag, name, domain));
}


/*
 * Get winname given gid
 */
idmap_stat
idmap_getwinnamebygid(gid_t gid, int flag, char **name, char **domain)
{
	return (idmap_getwinnamebypid(gid, 0, flag, name, domain));
}

idmap_stat
idmap_flush(idmap_flush_op op)
{
	idmap_retcode		rc1, rc2;

	rc1 = _idmap_clnt_call(IDMAP_FLUSH,
	    (xdrproc_t)xdr_idmap_flush_op, (caddr_t)&op,
	    (xdrproc_t)xdr_idmap_retcode, (caddr_t)&rc2, TIMEOUT);

	if (rc1 != IDMAP_SUCCESS)
		return (rc1);
	return (rc2);
}


/*
 * syslog is the default logger.
 * It can be overwritten by supplying a logger
 * with  idmap_set_logger()
 */
idmap_logger_t logger = syslog;


void
idmap_set_logger(idmap_logger_t funct)
{
	logger = funct;
}

/*
 * Helper functions that concatenate two parts of a name and then
 * look up a value, so that the same set of functions can be used to
 * process both "in" and "out" parameters.
 */
static
boolean_t
idmap_trace_get_str(nvlist_t *entry, char *n1, char *n2, char **ret)
{
	char name[IDMAP_TRACE_NAME_MAX+1];	/* Max used is about 11 */
	int err;

	(void) strlcpy(name, n1, sizeof (name));
	if (n2 != NULL)
		(void) strlcat(name, n2, sizeof (name));

	err = nvlist_lookup_string(entry, name, ret);
	return (err == 0);
}

static
boolean_t
idmap_trace_get_int(nvlist_t *entry, char *n1, char *n2, int64_t *ret)
{
	char name[IDMAP_TRACE_NAME_MAX+1];	/* Max used is about 11 */
	int err;

	(void) strlcpy(name, n1, sizeof (name));
	if (n2 != NULL)
		(void) strlcat(name, n2, sizeof (name));

	err = nvlist_lookup_int64(entry, name, ret);
	return (err == 0);
}

static
void
idmap_trace_print_id(FILE *out, nvlist_t *entry, char *fromto)
{
	char *s;
	int64_t i64;

	if (idmap_trace_get_int(entry, fromto, IDMAP_TRACE_TYPE, &i64)) {
		switch (i64) {
		case IDMAP_POSIXID:
			(void) fprintf(out, "unixname ");
			break;
		case IDMAP_UID:
			(void) fprintf(out, "unixuser ");
			break;
		case IDMAP_GID:
			(void) fprintf(out, "unixgroup ");
			break;
		case IDMAP_SID:
			(void) fprintf(out, "winname ");
			break;
		case IDMAP_USID:
			(void) fprintf(out, "winuser ");
			break;
		case IDMAP_GSID:
			(void) fprintf(out, "wingroup ");
			break;
		case IDMAP_NONE:
			(void) fprintf(out, gettext("unknown "));
			break;
		default:
			(void) fprintf(out, gettext("bad %d "), (int)i64);
			break;
		}
	}

	if (idmap_trace_get_str(entry, fromto, IDMAP_TRACE_NAME, &s))
		(void) fprintf(out, "%s ", s);

	if (idmap_trace_get_str(entry, fromto, IDMAP_TRACE_SID, &s))
		(void) fprintf(out, "%s ", s);

	if (idmap_trace_get_int(entry, fromto, IDMAP_TRACE_UNIXID, &i64))
		(void) fprintf(out, "%u ", (uid_t)i64);
}

void
idmap_trace_print_1(FILE *out, char *prefix, nvlist_t *entry)
{
	char *s;
	int64_t i64;

	(void) fprintf(out, "%s", prefix);
	idmap_trace_print_id(out, entry, "from");
	(void) fprintf(out, "-> ");
	idmap_trace_print_id(out, entry, "to");
	if (idmap_trace_get_int(entry, IDMAP_TRACE_ERROR, NULL, &i64))
		(void) fprintf(out, gettext("Error %d "), (int)i64);
	(void) fprintf(out, "-");
	if (idmap_trace_get_str(entry, IDMAP_TRACE_MESSAGE, NULL, &s))
		(void) fprintf(out, " %s", s);
	(void) fprintf(out, "\n");
}

void
idmap_trace_print(FILE *out, char *prefix, nvlist_t *trace)
{
	nvpair_t *nvp;

	for (nvp = nvlist_next_nvpair(trace, NULL);
	    nvp != NULL;
	    nvp = nvlist_next_nvpair(trace, nvp)) {
		nvlist_t *entry;
		int err;

		err = nvpair_value_nvlist(nvp, &entry);
		assert(err == 0);

		idmap_trace_print_1(out, prefix, entry);
	}
}
