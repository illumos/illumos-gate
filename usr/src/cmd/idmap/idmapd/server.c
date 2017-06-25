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
 */


/*
 * Service routines
 */

#include "idmapd.h"
#include "idmap_priv.h"
#include "nldaputils.h"
#include <signal.h>
#include <thread.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sid.h>
#include <ucred.h>
#include <pwd.h>
#include <auth_attr.h>
#include <secdb.h>
#include <sys/u8_textprep.h>
#include <note.h>

#define	_VALIDATE_LIST_CB_DATA(col, val, siz)\
	retcode = validate_list_cb_data(cb_data, argc, argv, col,\
			(uchar_t **)val, siz);\
	if (retcode == IDMAP_NEXT) {\
		result->retcode = IDMAP_NEXT;\
		return (0);\
	} else if (retcode < 0) {\
		result->retcode = retcode;\
		return (1);\
	}

#define	PROCESS_LIST_SVC_SQL(rcode, db, dbname, sql, limit, flag, cb, res, len)\
	rcode = process_list_svc_sql(db, dbname, sql, limit, flag, cb, res);\
	if (rcode == IDMAP_ERR_BUSY)\
		res->retcode = IDMAP_ERR_BUSY;\
	else if (rcode == IDMAP_SUCCESS && len == 0)\
		res->retcode = IDMAP_ERR_NOTFOUND;


#define	STRDUP_OR_FAIL(to, from) \
	if ((from) == NULL) \
		to = NULL; \
	else { \
		if ((to = strdup(from)) == NULL) \
			return (1); \
	}

#define	STRDUP_CHECK(to, from) \
	if ((from) != NULL) { \
		to = strdup(from); \
		if (to == NULL) { \
			result->retcode = IDMAP_ERR_MEMORY; \
			goto out; \
		} \
	}

/* ARGSUSED */
bool_t
idmap_null_1_svc(void *result, struct svc_req *rqstp)
{
	return (TRUE);
}

/*
 * RPC layer allocates empty strings to replace NULL char *.
 * This utility function frees these empty strings.
 */
static
void
sanitize_mapping_request(idmap_mapping *req)
{
	if (EMPTY_STRING(req->id1name)) {
		free(req->id1name);
		req->id1name = NULL;
	}
	if (EMPTY_STRING(req->id1domain)) {
		free(req->id1domain);
		req->id1domain = NULL;
	}
	if (EMPTY_STRING(req->id2name)) {
		free(req->id2name);
		req->id2name = NULL;
	}
	if (EMPTY_STRING(req->id2domain)) {
		free(req->id2domain);
		req->id2domain = NULL;
	}
	req->direction = _IDMAP_F_DONE;
}

static
int
validate_mapped_id_by_name_req(idmap_mapping *req)
{
	int e;

	if (IS_ID_UID(req->id1) || IS_ID_GID(req->id1))
		return (IDMAP_SUCCESS);

	if (IS_ID_SID(req->id1)) {
		if (!EMPTY_STRING(req->id1name) &&
		    u8_validate(req->id1name, strlen(req->id1name),
		    NULL, U8_VALIDATE_ENTIRE, &e) < 0)
			return (IDMAP_ERR_BAD_UTF8);
		if (!EMPTY_STRING(req->id1domain) &&
		    u8_validate(req->id1domain, strlen(req->id1domain),
		    NULL, U8_VALIDATE_ENTIRE, &e) < 0)
			return (IDMAP_ERR_BAD_UTF8);
	}

	return (IDMAP_SUCCESS);
}

static
int
validate_rule(idmap_namerule *rule)
{
	int e;

	if (!EMPTY_STRING(rule->winname) &&
	    u8_validate(rule->winname, strlen(rule->winname),
	    NULL, U8_VALIDATE_ENTIRE, &e) < 0)
		return (IDMAP_ERR_BAD_UTF8);

	if (!EMPTY_STRING(rule->windomain) &&
	    u8_validate(rule->windomain, strlen(rule->windomain),
	    NULL, U8_VALIDATE_ENTIRE, &e) < 0)
		return (IDMAP_ERR_BAD_UTF8);

	return (IDMAP_SUCCESS);

}

static
bool_t
validate_rules(idmap_update_batch *batch)
{
	idmap_update_op	*up;
	int i;

	for (i = 0; i < batch->idmap_update_batch_len; i++) {
		up = &(batch->idmap_update_batch_val[i]);
		if (validate_rule(&(up->idmap_update_op_u.rule))
		    != IDMAP_SUCCESS)
			return (IDMAP_ERR_BAD_UTF8);
	}

	return (IDMAP_SUCCESS);
}

/* ARGSUSED */
bool_t
idmap_get_mapped_ids_1_svc(idmap_mapping_batch batch,
    idmap_ids_res *result, struct svc_req *rqstp)
{
	sqlite		*cache = NULL, *db = NULL;
	lookup_state_t	state;
	idmap_retcode	retcode;
	uint_t		i;
	idmap_mapping	*req;
	idmap_id_res	*res;
	boolean_t	any_tracing;

	/* Init */
	(void) memset(result, 0, sizeof (*result));
	(void) memset(&state, 0, sizeof (state));

	/* Return success if nothing was requested */
	if (batch.idmap_mapping_batch_len < 1)
		goto out;

	/* Get cache handle */
	result->retcode = get_cache_handle(&cache);
	if (result->retcode != IDMAP_SUCCESS)
		goto out;
	state.cache = cache;

	/* Get db handle */
	result->retcode = get_db_handle(&db);
	if (result->retcode != IDMAP_SUCCESS)
		goto out;
	state.db = db;

	/* Allocate result array */
	result->ids.ids_val = calloc(batch.idmap_mapping_batch_len,
	    sizeof (idmap_id_res));
	if (result->ids.ids_val == NULL) {
		idmapdlog(LOG_ERR, "Out of memory");
		result->retcode = IDMAP_ERR_MEMORY;
		goto out;
	}
	result->ids.ids_len = batch.idmap_mapping_batch_len;

	/* Allocate hash table to check for duplicate sids */
	state.sid_history = calloc(batch.idmap_mapping_batch_len,
	    sizeof (*state.sid_history));
	if (state.sid_history == NULL) {
		idmapdlog(LOG_ERR, "Out of memory");
		result->retcode = IDMAP_ERR_MEMORY;
		goto out;
	}
	state.sid_history_size = batch.idmap_mapping_batch_len;
	for (i = 0; i < state.sid_history_size; i++) {
		state.sid_history[i].key = state.sid_history_size;
		state.sid_history[i].next = state.sid_history_size;
	}
	state.batch = &batch;
	state.result = result;

	/* Get directory-based name mapping info */
	result->retcode = load_cfg_in_state(&state);
	if (result->retcode != IDMAP_SUCCESS)
		goto out;

	/* Init our 'done' flags */
	state.sid2pid_done = state.pid2sid_done = TRUE;

	any_tracing = B_FALSE;

	/* First stage */
	for (i = 0; i < batch.idmap_mapping_batch_len; i++) {
		req = &batch.idmap_mapping_batch_val[i];
		res = &result->ids.ids_val[i];
		if (TRACING(req))
			any_tracing = B_TRUE;
		state.curpos = i;
		(void) sanitize_mapping_request(req);
		TRACE(req, res, "Start mapping");
		if (IS_ID_SID(req->id1)) {
			retcode = sid2pid_first_pass(
			    &state,
			    req,
			    res);
		} else if (IS_ID_UID(req->id1)) {
			retcode = pid2sid_first_pass(
			    &state,
			    req,
			    res, 1);
		} else if (IS_ID_GID(req->id1)) {
			retcode = pid2sid_first_pass(
			    &state,
			    req,
			    res, 0);
		} else {
			res->retcode = IDMAP_ERR_IDTYPE;
			continue;
		}
		if (IDMAP_FATAL_ERROR(retcode)) {
			result->retcode = retcode;
			goto out;
		}
	}

	/* Check if we are done */
	if (state.sid2pid_done == TRUE && state.pid2sid_done == TRUE)
		goto out;

	/*
	 * native LDAP lookups:
	 *  pid2sid:
	 *	- nldap or mixed mode. Lookup nldap by pid or unixname to get
	 *	  winname.
	 *  sid2pid:
	 *	- nldap mode. Got winname and sid (either given or found in
	 *	  name_cache). Lookup nldap by winname to get pid and
	 *	  unixname.
	 */
	if (state.nldap_nqueries) {
		retcode = nldap_lookup_batch(&state, &batch, result);
		if (IDMAP_FATAL_ERROR(retcode)) {
			TRACE(req, res, "Native LDAP lookup error=%d", retcode);
			result->retcode = retcode;
			goto out;
		}
		if (any_tracing) {
			for (i = 0; i < batch.idmap_mapping_batch_len; i++) {
				res = &result->ids.ids_val[i];
				req = &batch.idmap_mapping_batch_val[i];
				if (IDMAP_ERROR(res->retcode)) {
					TRACE(req, res,
					    "Native LDAP lookup error=%d",
					    res->retcode);
				} else {
					TRACE(req, res, "Native LDAP lookup");
				}
			}
		}
	}

	/*
	 * AD lookups:
	 *  pid2sid:
	 *	- nldap or mixed mode. Got winname from nldap lookup.
	 *	  winname2sid could not be resolved locally. Lookup AD
	 *	  by winname to get sid.
	 *	- ad mode. Got unixname. Lookup AD by unixname to get
	 *	  winname and sid.
	 *  sid2pid:
	 *	- ad or mixed mode. Lookup AD by sid or winname to get
	 *	  winname, sid and unixname.
	 *	- any mode. Got either sid or winname but not both. Lookup
	 *	  AD by sid or winname to get winname, sid.
	 */
	if (state.ad_nqueries) {
		retcode = ad_lookup_batch(&state, &batch, result);
		if (IDMAP_FATAL_ERROR(retcode)) {
			TRACE(req, res, "AD lookup error=%d", retcode);
			result->retcode = retcode;
			goto out;
		}
		for (i = 0; i < batch.idmap_mapping_batch_len; i++) {
			res = &result->ids.ids_val[i];
			req = &batch.idmap_mapping_batch_val[i];
			if (res->retcode == IDMAP_ERR_DOMAIN_NOTFOUND &&
			    req->id1.idmap_id_u.sid.prefix != NULL &&
			    req->id1name != NULL) {
				/*
				 * If AD lookup failed Domain Not Found but
				 * we have a winname and SID, it means that
				 * - LSA succeeded
				 * - it's a request a cross-forest trust
				 * and
				 * - we were looking for directory-based
				 *   mapping information.
				 * In that case, we're OK, just go on.
				 *
				 * If this seems more convoluted than it
				 * should be, it is - really, we probably
				 * shouldn't even be attempting AD lookups
				 * in this situation, but that's a more
				 * intricate cleanup that will have to wait
				 * for later.
				 */
				res->retcode = IDMAP_SUCCESS;
				TRACE(req, res,
				    "AD lookup - domain not found (ignored)");
				continue;
			}
		}
	}

	/*
	 * native LDAP lookups:
	 *  sid2pid:
	 *	- nldap mode. Got winname and sid from AD lookup. Lookup nldap
	 *	  by winname to get pid and unixname.
	 */
	if (state.nldap_nqueries) {
		retcode = nldap_lookup_batch(&state, &batch, result);
		if (IDMAP_FATAL_ERROR(retcode)) {
			TRACE(req, res, "Native LDAP lookup error=%d", retcode);
			result->retcode = retcode;
			goto out;
		}
		if (any_tracing) {
			for (i = 0; i < batch.idmap_mapping_batch_len; i++) {
				res = &result->ids.ids_val[i];
				req = &batch.idmap_mapping_batch_val[i];
				TRACE(req, res, "Native LDAP lookup");
			}
		}
	}

	/* Reset 'done' flags */
	state.sid2pid_done = state.pid2sid_done = TRUE;

	/* Second stage */
	for (i = 0; i < batch.idmap_mapping_batch_len; i++) {
		req = &batch.idmap_mapping_batch_val[i];
		res = &result->ids.ids_val[i];
		state.curpos = i;
		if (IS_ID_SID(req->id1)) {
			retcode = sid2pid_second_pass(
			    &state,
			    req,
			    res);
		} else if (IS_ID_UID(req->id1)) {
			retcode = pid2sid_second_pass(
			    &state,
			    req,
			    res, 1);
		} else if (IS_ID_GID(req->id1)) {
			retcode = pid2sid_second_pass(
			    &state,
			    req,
			    res, 0);
		} else {
			/* First stage has already set the error */
			continue;
		}
		if (IDMAP_FATAL_ERROR(retcode)) {
			result->retcode = retcode;
			goto out;
		}
	}

	/* Check if we are done */
	if (state.sid2pid_done == TRUE && state.pid2sid_done == TRUE)
		goto out;

	/* Reset our 'done' flags */
	state.sid2pid_done = state.pid2sid_done = TRUE;

	/* Update cache in a single transaction */
	if (sql_exec_no_cb(cache, IDMAP_CACHENAME, "BEGIN TRANSACTION;")
	    != IDMAP_SUCCESS)
		goto out;

	for (i = 0; i < batch.idmap_mapping_batch_len; i++) {
		req = &batch.idmap_mapping_batch_val[i];
		res = &result->ids.ids_val[i];
		state.curpos = i;
		if (IS_ID_SID(req->id1)) {
			(void) update_cache_sid2pid(
			    &state,
			    req,
			    res);
		} else if ((IS_ID_UID(req->id1)) ||
		    (IS_ID_GID(req->id1))) {
			(void) update_cache_pid2sid(
			    &state,
			    req,
			    res);
		}
	}

	/* Commit if we have at least one successful update */
	if (state.sid2pid_done == FALSE || state.pid2sid_done == FALSE)
		(void) sql_exec_no_cb(cache, IDMAP_CACHENAME,
		    "COMMIT TRANSACTION;");
	else
		(void) sql_exec_no_cb(cache, IDMAP_CACHENAME,
		    "END TRANSACTION;");

out:
	cleanup_lookup_state(&state);
	if (IDMAP_ERROR(result->retcode)) {
		if (any_tracing) {
			for (i = 0; i < batch.idmap_mapping_batch_len; i++) {
				req = &batch.idmap_mapping_batch_val[i];
				res = &result->ids.ids_val[i];
				TRACE(req, res,
				    "Failure code %d", result->retcode);
			}
		}
		xdr_free(xdr_idmap_ids_res, (caddr_t)result);
		result->ids.ids_len = 0;
		result->ids.ids_val = NULL;
	} else {
		if (any_tracing) {
			for (i = 0; i < batch.idmap_mapping_batch_len; i++) {
				req = &batch.idmap_mapping_batch_val[i];
				res = &result->ids.ids_val[i];
				TRACE(req, res, "Done");
			}
		}
	}
	result->retcode = idmap_stat4prot(result->retcode);

	for (i = 0; i < result->ids.ids_len; i++) {
		req = &batch.idmap_mapping_batch_val[i];
		res = &result->ids.ids_val[i];

		if (!(req->flag & IDMAP_REQ_FLG_MAPPING_INFO) &&
		    res->retcode == IDMAP_SUCCESS)
			idmap_how_clear(&res->info.how);
	}
	return (TRUE);
}


/* ARGSUSED */
static
int
list_mappings_cb(void *parg, int argc, char **argv, char **colnames)
{
	list_cb_data_t		*cb_data;
	char			*str;
	idmap_mappings_res	*result;
	idmap_retcode		retcode;
	int			w2u, u2w;
	char			*end;
	static int		validated_column_names = 0;
	idmap_how		*how;

	cb_data = (list_cb_data_t *)parg;

	if (!validated_column_names) {
		assert(strcmp(colnames[0], "rowid") == 0);
		assert(strcmp(colnames[1], "sidprefix") == 0);
		assert(strcmp(colnames[2], "rid") == 0);
		assert(strcmp(colnames[3], "pid") == 0);
		assert(strcmp(colnames[4], "w2u") == 0);
		assert(strcmp(colnames[5], "u2w") == 0);
		assert(strcmp(colnames[6], "windomain") == 0);
		assert(strcmp(colnames[7], "canon_winname") == 0);
		assert(strcmp(colnames[8], "unixname") == 0);
		assert(strcmp(colnames[9], "is_user") == 0);
		assert(strcmp(colnames[10], "is_wuser") == 0);
		assert(strcmp(colnames[11], "map_type") == 0);
		assert(strcmp(colnames[12], "map_dn") == 0);
		assert(strcmp(colnames[13], "map_attr") == 0);
		assert(strcmp(colnames[14], "map_value") == 0);
		assert(strcmp(colnames[15], "map_windomain") == 0);
		assert(strcmp(colnames[16], "map_winname") == 0);
		assert(strcmp(colnames[17], "map_unixname") == 0);
		assert(strcmp(colnames[18], "map_is_nt4") == 0);
		validated_column_names = 1;
	}

	result = (idmap_mappings_res *)cb_data->result;

	_VALIDATE_LIST_CB_DATA(19, &result->mappings.mappings_val,
	    sizeof (idmap_mapping));

	result->mappings.mappings_len++;

	if ((str = strdup(argv[1])) == NULL)
		return (1);
	result->mappings.mappings_val[cb_data->next].id1.idmap_id_u.sid.prefix =
	    str;
	result->mappings.mappings_val[cb_data->next].id1.idmap_id_u.sid.rid =
	    strtoul(argv[2], &end, 10);
	result->mappings.mappings_val[cb_data->next].id1.idtype =
	    strtol(argv[10], &end, 10) ? IDMAP_USID : IDMAP_GSID;

	result->mappings.mappings_val[cb_data->next].id2.idmap_id_u.uid =
	    strtoul(argv[3], &end, 10);
	result->mappings.mappings_val[cb_data->next].id2.idtype =
	    strtol(argv[9], &end, 10) ? IDMAP_UID : IDMAP_GID;

	w2u = argv[4] ? strtol(argv[4], &end, 10) : 0;
	u2w = argv[5] ? strtol(argv[5], &end, 10) : 0;

	if (w2u > 0 && u2w == 0)
		result->mappings.mappings_val[cb_data->next].direction =
		    IDMAP_DIRECTION_W2U;
	else if (w2u == 0 && u2w > 0)
		result->mappings.mappings_val[cb_data->next].direction =
		    IDMAP_DIRECTION_U2W;
	else
		result->mappings.mappings_val[cb_data->next].direction =
		    IDMAP_DIRECTION_BI;

	STRDUP_OR_FAIL(result->mappings.mappings_val[cb_data->next].id1domain,
	    argv[6]);

	STRDUP_OR_FAIL(result->mappings.mappings_val[cb_data->next].id1name,
	    argv[7]);

	STRDUP_OR_FAIL(result->mappings.mappings_val[cb_data->next].id2name,
	    argv[8]);

	if (cb_data->flag & IDMAP_REQ_FLG_MAPPING_INFO) {
		how = &result->mappings.mappings_val[cb_data->next].info.how;
		how->map_type = strtoul(argv[11], &end, 10);
		switch (how->map_type) {
		case IDMAP_MAP_TYPE_DS_AD:
			how->idmap_how_u.ad.dn =
			    strdup(argv[12]);
			how->idmap_how_u.ad.attr =
			    strdup(argv[13]);
			how->idmap_how_u.ad.value =
			    strdup(argv[14]);
			break;

		case IDMAP_MAP_TYPE_DS_NLDAP:
			how->idmap_how_u.nldap.dn =
			    strdup(argv[12]);
			how->idmap_how_u.nldap.attr =
			    strdup(argv[13]);
			how->idmap_how_u.nldap.value =
			    strdup(argv[14]);
			break;

		case IDMAP_MAP_TYPE_RULE_BASED:
			how->idmap_how_u.rule.windomain =
			    strdup(argv[15]);
			how->idmap_how_u.rule.winname =
			    strdup(argv[16]);
			how->idmap_how_u.rule.unixname =
			    strdup(argv[17]);
			how->idmap_how_u.rule.is_nt4 =
			    strtoul(argv[18], &end, 10);
			how->idmap_how_u.rule.is_user =
			    strtol(argv[9], &end, 10);
			how->idmap_how_u.rule.is_wuser =
			    strtol(argv[10], &end, 10);
			break;

		case IDMAP_MAP_TYPE_EPHEMERAL:
			break;

		case IDMAP_MAP_TYPE_LOCAL_SID:
			break;

		case IDMAP_MAP_TYPE_IDMU:
			how->idmap_how_u.idmu.dn =
			    strdup(argv[12]);
			how->idmap_how_u.idmu.attr =
			    strdup(argv[13]);
			how->idmap_how_u.idmu.value =
			    strdup(argv[14]);
			break;

		default:
			/* Unknown mapping type */
			assert(FALSE);
		}

	}

	result->lastrowid = strtoll(argv[0], &end, 10);
	cb_data->next++;
	result->retcode = IDMAP_SUCCESS;
	return (0);
}


/* ARGSUSED */
bool_t
idmap_list_mappings_1_svc(int64_t lastrowid, uint64_t limit, int32_t flag,
    idmap_mappings_res *result, struct svc_req *rqstp)
{
	sqlite		*cache = NULL;
	char		lbuf[30], rbuf[30];
	uint64_t	maxlimit;
	idmap_retcode	retcode;
	char		*sql = NULL;
	time_t		curtime;

	(void) memset(result, 0, sizeof (*result));

	/* Current time */
	errno = 0;
	if ((curtime = time(NULL)) == (time_t)-1) {
		idmapdlog(LOG_ERR, "Failed to get current time (%s)",
		    strerror(errno));
		retcode = IDMAP_ERR_INTERNAL;
		goto out;
	}

	RDLOCK_CONFIG();
	maxlimit = _idmapdstate.cfg->pgcfg.list_size_limit;
	UNLOCK_CONFIG();

	/* Get cache handle */
	result->retcode = get_cache_handle(&cache);
	if (result->retcode != IDMAP_SUCCESS)
		goto out;

	result->retcode = IDMAP_ERR_INTERNAL;

	/* Create LIMIT expression. */
	if (limit == 0 || (maxlimit > 0 && maxlimit < limit))
		limit = maxlimit;
	if (limit > 0)
		(void) snprintf(lbuf, sizeof (lbuf),
		    "LIMIT %" PRIu64, limit + 1ULL);
	else
		lbuf[0] = '\0';

	(void) snprintf(rbuf, sizeof (rbuf), "rowid > %" PRIu64, lastrowid);

	/*
	 * Combine all the above into a giant SELECT statement that
	 * will return the requested mappings
	 */

	sql = sqlite_mprintf("SELECT rowid, sidprefix, rid, pid, w2u, "
	    "u2w, windomain, canon_winname, unixname, is_user, is_wuser, "
	    "map_type, map_dn, map_attr, map_value, map_windomain, "
	    "map_winname, map_unixname, map_is_nt4 "
	    "FROM idmap_cache WHERE %s AND "
	    "(pid >= 2147483648 OR (expiration = 0 OR "
	    "expiration ISNULL  OR expiration > %d)) "
	    "%s;",
	    rbuf, curtime, lbuf);
	if (sql == NULL) {
		result->retcode = IDMAP_ERR_MEMORY;
		idmapdlog(LOG_ERR, "Out of memory");
		goto out;
	}

	/* Execute the SQL statement and update the return buffer */
	PROCESS_LIST_SVC_SQL(retcode, cache, IDMAP_CACHENAME, sql, limit,
	    flag, list_mappings_cb, result, result->mappings.mappings_len);

out:
	if (sql)
		sqlite_freemem(sql);
	if (IDMAP_ERROR(result->retcode))
		xdr_free(xdr_idmap_mappings_res, (caddr_t)result);
	result->retcode = idmap_stat4prot(result->retcode);
	return (TRUE);
}


/* ARGSUSED */
static
int
list_namerules_cb(void *parg, int argc, char **argv, char **colnames)
{
	list_cb_data_t		*cb_data;
	idmap_namerules_res	*result;
	idmap_retcode		retcode;
	int			w2u_order, u2w_order;
	char			*end;
	static int		validated_column_names = 0;

	if (!validated_column_names) {
		assert(strcmp(colnames[0], "rowid") == 0);
		assert(strcmp(colnames[1], "is_user") == 0);
		assert(strcmp(colnames[2], "is_wuser") == 0);
		assert(strcmp(colnames[3], "windomain") == 0);
		assert(strcmp(colnames[4], "winname_display") == 0);
		assert(strcmp(colnames[5], "is_nt4") == 0);
		assert(strcmp(colnames[6], "unixname") == 0);
		assert(strcmp(colnames[7], "w2u_order") == 0);
		assert(strcmp(colnames[8], "u2w_order") == 0);
		validated_column_names = 1;
	}

	cb_data = (list_cb_data_t *)parg;
	result = (idmap_namerules_res *)cb_data->result;

	_VALIDATE_LIST_CB_DATA(9, &result->rules.rules_val,
	    sizeof (idmap_namerule));

	result->rules.rules_len++;

	result->rules.rules_val[cb_data->next].is_user =
	    strtol(argv[1], &end, 10);

	result->rules.rules_val[cb_data->next].is_wuser =
	    strtol(argv[2], &end, 10);

	STRDUP_OR_FAIL(result->rules.rules_val[cb_data->next].windomain,
	    argv[3]);

	STRDUP_OR_FAIL(result->rules.rules_val[cb_data->next].winname,
	    argv[4]);

	result->rules.rules_val[cb_data->next].is_nt4 =
	    strtol(argv[5], &end, 10);

	STRDUP_OR_FAIL(result->rules.rules_val[cb_data->next].unixname,
	    argv[6]);

	w2u_order = argv[7] ? strtol(argv[7], &end, 10) : 0;
	u2w_order = argv[8] ? strtol(argv[8], &end, 10) : 0;

	if (w2u_order > 0 && u2w_order == 0)
		result->rules.rules_val[cb_data->next].direction =
		    IDMAP_DIRECTION_W2U;
	else if (w2u_order == 0 && u2w_order > 0)
		result->rules.rules_val[cb_data->next].direction =
		    IDMAP_DIRECTION_U2W;
	else
		result->rules.rules_val[cb_data->next].direction =
		    IDMAP_DIRECTION_BI;

	result->lastrowid = strtoll(argv[0], &end, 10);
	cb_data->next++;
	result->retcode = IDMAP_SUCCESS;
	return (0);
}


/* ARGSUSED */
bool_t
idmap_list_namerules_1_svc(idmap_namerule rule, uint64_t lastrowid,
    uint64_t limit, idmap_namerules_res *result, struct svc_req *rqstp)
{

	sqlite		*db = NULL;
	char		lbuf[30], rbuf[30];
	char		*sql = NULL;
	char		*expr = NULL;
	uint64_t	maxlimit;
	idmap_retcode	retcode;

	(void) memset(result, 0, sizeof (*result));

	result->retcode = validate_rule(&rule);
	if (result->retcode != IDMAP_SUCCESS)
		goto out;

	RDLOCK_CONFIG();
	maxlimit = _idmapdstate.cfg->pgcfg.list_size_limit;
	UNLOCK_CONFIG();

	/* Get db handle */
	result->retcode = get_db_handle(&db);
	if (result->retcode != IDMAP_SUCCESS)
		goto out;

	result->retcode = gen_sql_expr_from_rule(&rule, &expr);
	if (result->retcode != IDMAP_SUCCESS)
		goto out;

	/* Create LIMIT expression. */
	if (limit == 0 || (maxlimit > 0 && maxlimit < limit))
		limit = maxlimit;
	if (limit > 0)
		(void) snprintf(lbuf, sizeof (lbuf),
		    "LIMIT %" PRIu64, limit + 1ULL);
	else
		lbuf[0] = '\0';

	(void) snprintf(rbuf, sizeof (rbuf), "rowid > %" PRIu64, lastrowid);

	/*
	 * Combine all the above into a giant SELECT statement that
	 * will return the requested rules
	 */
	sql = sqlite_mprintf("SELECT rowid, is_user, is_wuser, windomain, "
	    "winname_display, is_nt4, unixname, w2u_order, u2w_order "
	    "FROM namerules WHERE "
	    " %s %s %s;",
	    rbuf, expr, lbuf);

	if (sql == NULL) {
		result->retcode = IDMAP_ERR_MEMORY;
		idmapdlog(LOG_ERR, "Out of memory");
		goto out;
	}

	/* Execute the SQL statement and update the return buffer */
	PROCESS_LIST_SVC_SQL(retcode, db, IDMAP_DBNAME, sql, limit,
	    0, list_namerules_cb, result, result->rules.rules_len);

out:
	if (expr)
		sqlite_freemem(expr);
	if (sql)
		sqlite_freemem(sql);
	if (IDMAP_ERROR(result->retcode))
		xdr_free(xdr_idmap_namerules_res, (caddr_t)result);
	result->retcode = idmap_stat4prot(result->retcode);
	return (TRUE);
}

#define	IDMAP_RULES_AUTH	"solaris.admin.idmap.rules"
static int
verify_rules_auth(struct svc_req *rqstp)
{
	ucred_t		*uc = NULL;
	uid_t		uid;
	char		buf[1024];
	struct passwd	pwd;

	if (svc_getcallerucred(rqstp->rq_xprt, &uc) != 0) {
		idmapdlog(LOG_ERR, "svc_getcallerucred failed during "
		    "authorization (%s)", strerror(errno));
		return (-1);
	}

	uid = ucred_geteuid(uc);
	if (uid == (uid_t)-1) {
		idmapdlog(LOG_ERR, "ucred_geteuid failed during "
		    "authorization (%s)", strerror(errno));
		ucred_free(uc);
		return (-1);
	}

	if (getpwuid_r(uid, &pwd, buf, sizeof (buf)) == NULL) {
		idmapdlog(LOG_ERR, "getpwuid_r(%u) failed during "
		    "authorization (%s)", uid, strerror(errno));
		ucred_free(uc);
		return (-1);
	}

	if (chkauthattr(IDMAP_RULES_AUTH, pwd.pw_name) != 1) {
		idmapdlog(LOG_INFO, "%s is not authorized (%s)",
		    pwd.pw_name, IDMAP_RULES_AUTH);
		ucred_free(uc);
		return (-1);
	}

	ucred_free(uc);
	return (1);
}

/*
 * Meaning of the return values is the following: For retcode ==
 * IDMAP_SUCCESS, everything went OK and error_index is
 * undefined. Otherwise, error_index >=0 shows the failed batch
 * element. errro_index == -1 indicates failure at the beginning,
 * error_index == -2 at the end.
 */

/* ARGSUSED */
bool_t
idmap_update_1_svc(idmap_update_batch batch, idmap_update_res *res,
    struct svc_req *rqstp)
{
	sqlite		*db = NULL;
	idmap_update_op	*up;
	int		i;
	int		trans = FALSE;

	res->error_index = -1;
	(void) memset(&res->error_rule, 0, sizeof (res->error_rule));
	(void) memset(&res->conflict_rule, 0, sizeof (res->conflict_rule));

	if (verify_rules_auth(rqstp) < 0) {
		res->retcode = IDMAP_ERR_PERMISSION_DENIED;
		goto out;
	}

	if (batch.idmap_update_batch_len == 0 ||
	    batch.idmap_update_batch_val == NULL) {
		res->retcode = IDMAP_SUCCESS;
		goto out;
	}

	res->retcode = validate_rules(&batch);
	if (res->retcode != IDMAP_SUCCESS)
		goto out;

	/* Get db handle */
	res->retcode = get_db_handle(&db);
	if (res->retcode != IDMAP_SUCCESS)
		goto out;

	res->retcode = sql_exec_no_cb(db, IDMAP_DBNAME, "BEGIN TRANSACTION;");
	if (res->retcode != IDMAP_SUCCESS)
		goto out;
	trans = TRUE;

	for (i = 0; i < batch.idmap_update_batch_len; i++) {
		up = &batch.idmap_update_batch_val[i];
		switch (up->opnum) {
		case OP_NONE:
			res->retcode = IDMAP_SUCCESS;
			break;
		case OP_ADD_NAMERULE:
			res->retcode = add_namerule(db,
			    &up->idmap_update_op_u.rule);
			break;
		case OP_RM_NAMERULE:
			res->retcode = rm_namerule(db,
			    &up->idmap_update_op_u.rule);
			break;
		case OP_FLUSH_NAMERULES:
			res->retcode = flush_namerules(db);
			break;
		default:
			res->retcode = IDMAP_ERR_NOTSUPPORTED;
			break;
		};

		if (res->retcode != IDMAP_SUCCESS) {
			res->error_index = i;
			if (up->opnum == OP_ADD_NAMERULE ||
			    up->opnum == OP_RM_NAMERULE) {
				idmap_stat r2 =
				    idmap_namerule_cpy(&res->error_rule,
				    &up->idmap_update_op_u.rule);
				if (r2 != IDMAP_SUCCESS)
					res->retcode = r2;
			}
			goto out;
		}
	}

out:
	if (trans) {
		if (res->retcode == IDMAP_SUCCESS) {
			res->retcode =
			    sql_exec_no_cb(db, IDMAP_DBNAME,
			    "COMMIT TRANSACTION;");
			if (res->retcode ==  IDMAP_SUCCESS) {
				/*
				 * We've updated the rules.  Expire the cache
				 * so that existing mappings will be
				 * reconsidered.
				 */
				res->retcode =
				    idmap_cache_flush(IDMAP_FLUSH_EXPIRE);
			} else {
				res->error_index = -2;
			}
		}
		else
			(void) sql_exec_no_cb(db, IDMAP_DBNAME,
			    "ROLLBACK TRANSACTION;");
	}

	res->retcode = idmap_stat4prot(res->retcode);

	return (TRUE);
}

static
int
copy_string(char **to, char *from)
{
	if (EMPTY_STRING(from)) {
		*to = NULL;
	} else {
		*to = strdup(from);
		if (*to == NULL) {
			idmapdlog(LOG_ERR, "Out of memory");
			return (IDMAP_ERR_MEMORY);
		}
	}
	return (IDMAP_SUCCESS);
}

static
int
copy_id(idmap_id *to, idmap_id *from)
{
	(void) memset(to, 0, sizeof (*to));

	to->idtype = from->idtype;
	if (IS_ID_SID(*from)) {
		idmap_retcode retcode;

		to->idmap_id_u.sid.rid = from->idmap_id_u.sid.rid;
		retcode = copy_string(&to->idmap_id_u.sid.prefix,
		    from->idmap_id_u.sid.prefix);

		return (retcode);
	} else {
		to->idmap_id_u.uid = from->idmap_id_u.uid;
		return (IDMAP_SUCCESS);
	}
}

static
int
copy_mapping(idmap_mapping *mapping, idmap_mapping *request)
{
	idmap_retcode retcode;

	(void) memset(mapping, 0, sizeof (*mapping));

	mapping->flag = request->flag;
	mapping->direction = _IDMAP_F_DONE;

	retcode = copy_id(&mapping->id1, &request->id1);
	if (retcode != IDMAP_SUCCESS)
		goto errout;

	retcode = copy_string(&mapping->id1domain, request->id1domain);
	if (retcode != IDMAP_SUCCESS)
		goto errout;

	retcode = copy_string(&mapping->id1name, request->id1name);
	if (retcode != IDMAP_SUCCESS)
		goto errout;

	retcode = copy_id(&mapping->id2, &request->id2);
	if (retcode != IDMAP_SUCCESS)
		goto errout;

	retcode = copy_string(&mapping->id2domain, request->id2domain);
	if (retcode != IDMAP_SUCCESS)
		goto errout;
	retcode = copy_string(&mapping->id2name, request->id2name);
	if (retcode != IDMAP_SUCCESS)
		goto errout;

	return (IDMAP_SUCCESS);

errout:
	if (IS_ID_SID(mapping->id1))
		free(mapping->id1.idmap_id_u.sid.prefix);
	free(mapping->id1domain);
	free(mapping->id1name);
	if (IS_ID_SID(mapping->id2))
		free(mapping->id2.idmap_id_u.sid.prefix);
	free(mapping->id2domain);
	free(mapping->id2name);

	(void) memset(mapping, 0, sizeof (*mapping));
	return (retcode);
}


/* ARGSUSED */
bool_t
idmap_get_mapped_id_by_name_1_svc(idmap_mapping request,
    idmap_mappings_res *result, struct svc_req *rqstp)
{
	idmap_mapping_batch batch_request;
	idmap_ids_res batch_result;
	idmap_mapping *map;

	/* Clear out things we might want to xdr_free on error */
	(void) memset(&batch_result, 0, sizeof (batch_result));
	(void) memset(result, 0, sizeof (*result));

	result->retcode = validate_mapped_id_by_name_req(&request);
	if (result->retcode != IDMAP_SUCCESS)
		goto out;

	/*
	 * Copy the request.  We need to modify it, and
	 * what we have is a shallow copy.  Freeing pointers from
	 * our copy will lead to problems, since the RPC framework
	 * has its own copy of those pointers.  Besides, we need
	 * a copy to return.
	 */
	map = calloc(1, sizeof (idmap_mapping));
	if (map == NULL) {
		idmapdlog(LOG_ERR, "Out of memory");
		result->retcode = IDMAP_ERR_MEMORY;
		goto out;
	}

	/*
	 * Set up to return the filled-in mapping structure.
	 * Note that we xdr_free result on error, and that'll take
	 * care of freeing the mapping structure.
	 */
	result->mappings.mappings_val = map;
	result->mappings.mappings_len = 1;

	result->retcode = copy_mapping(map, &request);
	if (result->retcode != IDMAP_SUCCESS)
		goto out;

	/* Set up for the request to the batch API */
	batch_request.idmap_mapping_batch_val = map;
	batch_request.idmap_mapping_batch_len = 1;

	/* Do the real work. */
	(void) idmap_get_mapped_ids_1_svc(batch_request,
	    &batch_result, rqstp);

	/* Copy what we need out of the batch response */

	if (batch_result.retcode != IDMAP_SUCCESS) {
		result->retcode = batch_result.retcode;
		goto out;
	}

	result->retcode = copy_id(&map->id2, &batch_result.ids.ids_val[0].id);
	if (result->retcode != IDMAP_SUCCESS)
		goto out;

	map->direction = batch_result.ids.ids_val[0].direction;

	result->retcode = batch_result.ids.ids_val[0].retcode;

	idmap_info_mov(&map->info, &batch_result.ids.ids_val[0].info);

out:
	if (IDMAP_FATAL_ERROR(result->retcode)) {
		xdr_free(xdr_idmap_mappings_res, (caddr_t)result);
		result->mappings.mappings_len = 0;
		result->mappings.mappings_val = NULL;
	}
	result->retcode = idmap_stat4prot(result->retcode);

	xdr_free(xdr_idmap_ids_res, (char *)&batch_result);

	return (TRUE);
}

/* ARGSUSED */
bool_t
idmap_get_prop_1_svc(idmap_prop_type request,
    idmap_prop_res *result, struct svc_req *rqstp)
{
	idmap_pg_config_t *pgcfg;

	/* Init */
	(void) memset(result, 0, sizeof (*result));
	result->retcode = IDMAP_SUCCESS;
	result->value.prop = request;

	RDLOCK_CONFIG();

	/* Just shortcuts: */
	pgcfg = &_idmapdstate.cfg->pgcfg;


	switch (request) {
	case PROP_LIST_SIZE_LIMIT:
		result->value.idmap_prop_val_u.intval = pgcfg->list_size_limit;
		result->auto_discovered = FALSE;
		break;
	case PROP_DEFAULT_DOMAIN:
		result->auto_discovered = FALSE;
		STRDUP_CHECK(result->value.idmap_prop_val_u.utf8val,
		    pgcfg->default_domain);
		break;
	case PROP_DOMAIN_NAME:
		STRDUP_CHECK(result->value.idmap_prop_val_u.utf8val,
		    pgcfg->domain_name);
		result->auto_discovered =
		    pgcfg->domain_name_auto_disc;
		break;
	case PROP_MACHINE_SID:
		result->auto_discovered = FALSE;
		STRDUP_CHECK(result->value.idmap_prop_val_u.utf8val,
		    pgcfg->machine_sid);
		break;
	case PROP_DOMAIN_CONTROLLER:
		if (pgcfg->domain_controller != NULL) {
			(void) memcpy(&result->value.idmap_prop_val_u.dsval,
			    pgcfg->domain_controller,
			    sizeof (idmap_ad_disc_ds_t));
		}
		result->auto_discovered = pgcfg->domain_controller_auto_disc;
		break;
	case PROP_FOREST_NAME:
		STRDUP_CHECK(result->value.idmap_prop_val_u.utf8val,
		    pgcfg->forest_name);
		result->auto_discovered = pgcfg->forest_name_auto_disc;
		break;
	case PROP_SITE_NAME:
		STRDUP_CHECK(result->value.idmap_prop_val_u.utf8val,
		    pgcfg->site_name);
		result->auto_discovered = pgcfg->site_name_auto_disc;
		break;
	case PROP_GLOBAL_CATALOG:
		if (pgcfg->global_catalog != NULL) {
			(void) memcpy(&result->value.idmap_prop_val_u.dsval,
			    pgcfg->global_catalog, sizeof (idmap_ad_disc_ds_t));
		}
		result->auto_discovered = pgcfg->global_catalog_auto_disc;
		break;
	case PROP_AD_UNIXUSER_ATTR:
		STRDUP_CHECK(result->value.idmap_prop_val_u.utf8val,
		    pgcfg->ad_unixuser_attr);
		result->auto_discovered = FALSE;
		break;
	case PROP_AD_UNIXGROUP_ATTR:
		STRDUP_CHECK(result->value.idmap_prop_val_u.utf8val,
		    pgcfg->ad_unixgroup_attr);
		result->auto_discovered = FALSE;
		break;
	case PROP_NLDAP_WINNAME_ATTR:
		STRDUP_CHECK(result->value.idmap_prop_val_u.utf8val,
		    pgcfg->nldap_winname_attr);
		result->auto_discovered = FALSE;
		break;
	case PROP_DIRECTORY_BASED_MAPPING:
		STRDUP_CHECK(result->value.idmap_prop_val_u.utf8val,
		    enum_lookup(pgcfg->directory_based_mapping,
		    directory_mapping_map));
		result->auto_discovered = FALSE;
		break;
	default:
		result->retcode = IDMAP_ERR_PROP_UNKNOWN;
		break;
	}

out:
	UNLOCK_CONFIG();
	if (IDMAP_FATAL_ERROR(result->retcode)) {
		xdr_free(xdr_idmap_prop_res, (caddr_t)result);
		result->value.prop = PROP_UNKNOWN;
	}
	result->retcode = idmap_stat4prot(result->retcode);
	return (TRUE);
}

int
idmap_flush_1_svc(
    idmap_flush_op  op,
    idmap_retcode *result,
    struct svc_req *rqstp)
{
	NOTE(ARGUNUSED(rqstp))
	if (verify_rules_auth(rqstp) < 0) {
		*result = IDMAP_ERR_PERMISSION_DENIED;
		return (TRUE);
	}

	*result = idmap_cache_flush(op);

	return (TRUE);
}

/* ARGSUSED */
int
idmap_prog_1_freeresult(SVCXPRT *transp, xdrproc_t xdr_result,
    caddr_t result)
{
	xdr_free(xdr_result, result);
	return (TRUE);
}

/*
 * This function is called by rpc_svc.c when it encounters an error.
 */
NOTE(PRINTFLIKE(1))
void
idmap_rpc_msgout(const char *fmt, ...)
{
	va_list va;
	char buf[1000];

	va_start(va, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, va);
	va_end(va);

	idmapdlog(LOG_ERR, "idmap RPC:  %s", buf);
}
