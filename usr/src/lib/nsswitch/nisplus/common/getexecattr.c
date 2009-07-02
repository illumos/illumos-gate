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

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <exec_attr.h>
#include "nisplus_common.h"
#include "nisplus_tables.h"


extern nis_result *__nis_list_localcb(nis_name, uint_t, int (*) (), void *);
/* externs from libnsl */
extern int _doexeclist(nss_XbyY_args_t *);
extern char *_exec_wild_id(char *, const char *);
extern void _exec_cleanup(nss_status_t, nss_XbyY_args_t *);


#define	POLICY_LEN	128


typedef struct __exec_nisplus_args {
	int			check_policy;
	nss_status_t		*resp;
	nss_XbyY_args_t		*argp;
	nisplus_backend_t	*be;
} _exec_nisplus_args;


#ifdef	DEBUG
static void
_print_execstr(execstr_t *exec)
{

	(void) fprintf(stdout, "      exec-name: [%s]\n", exec->name);
	if (exec->policy != (char *)NULL) {
		(void) fprintf(stdout, "      policy: [%s]\n", exec->policy);
	}
	if (exec->type != (char *)NULL) {
		(void) fprintf(stdout, "      type: [%s]\n", exec->type);
	}
	if (exec->res1 != (char *)NULL) {
		(void) fprintf(stdout, "      res1: [%s]\n", exec->res1);
	}
	if (exec->res2 != (char *)NULL) {
		(void) fprintf(stdout, "      res2: [%s]\n", exec->res2);
	}
	if (exec->id != (char *)NULL) {
		(void) fprintf(stdout, "      id: [%s]\n", exec->id);
	}
	if (exec->attr != (char *)NULL) {
		(void) fprintf(stdout, "      attr: [%s]\n", exec->attr);
	}
	if (exec->next != (execstr_t *)NULL) {
		(void) fprintf(stdout, "      next: [%s]\n", exec->next->name);
		(void) fprintf(stdout, "\n");
		_print_execstr(exec->next);
	}
}
#endif	/* DEBUG */


static nss_status_t
_exec_process_val(_exec_nisplus_args * eargp, nis_object * obj)
{
	int			parsestat;
	nss_XbyY_args_t		*argp = eargp->argp;
	nisplus_backend_t	*be = eargp->be;
	_priv_execattr *_priv_exec = (_priv_execattr *)(argp->key.attrp);

#ifdef	DEBUG
	(void) fprintf(stdout, "\n[getexecattr.c: _exec_process_val]\n");
#endif	/* DEBUG */

	/* passing one obj */
	parsestat = (be->obj2str) (1, obj, be, argp);
	if (parsestat != NSS_STR_PARSE_SUCCESS)
		goto fail;

	/*
	 * If caller is nscd's switch engine, the data
	 * will be in argp->buf.buffer. nscd does not
	 * support GET_ALL at this time so return
	 * success from here.
	 */
	if (argp->buf.result == NULL && be->buffer == NULL) {
		argp->returnval = argp->buf.buffer;
		if (argp->buf.buffer != NULL)
			argp->returnlen = strlen(argp->buf.buffer);
		return (NSS_SUCCESS);
	}

	/*
	 * If the data is in be->buffer it needs
	 * to be marshalled.
	 */
	if (argp->str2ent == NULL) {
		parsestat = NSS_STR_PARSE_PARSE;
		goto fail;
	}
	parsestat = (*argp->str2ent)(be->buffer, be->buflen, argp->buf.result,
	    argp->buf.buffer, argp->buf.buflen);
	if (parsestat == NSS_STR_PARSE_SUCCESS) {
		if (be->buffer != NULL) {
			free(be->buffer);
			be->buffer = NULL;
			be->buflen = 0;
		}
		argp->returnval = argp->buf.result;
		if (argp->buf.result != NULL)
			argp->returnlen = 1;
		else if (argp->buf.buffer != NULL) {
			argp->returnval = argp->buf.buffer;
			argp->returnlen = strlen(argp->buf.buffer);
		}
		if (IS_GET_ALL(_priv_exec->search_flag))
			if (_doexeclist(argp) == 0)
				return (NSS_UNAVAIL);
		return (NSS_SUCCESS);
	}

fail:
	if (be->buffer != NULL) {
		free(be->buffer);
		be->buffer = NULL;
		be->buflen = 0;
	}
	if (parsestat == NSS_STR_PARSE_ERANGE) {
		argp->erange = 1;
		/* We won't find this otherwise, anyway */
		return (NSS_NOTFOUND);
	} else if (parsestat == NSS_STR_PARSE_PARSE) {
		return (NSS_NOTFOUND);
	}
	return (NSS_UNAVAIL);
}


/*
 * check_match: returns 1 if -  matching entry found and no more entries needed,
 *				entry cannot be found because of error;
 *		returns 0 if -  no matching entry found,
 *				matching entry found and next match needed.
 */
/*ARGSUSED*/
static int
check_match(nis_name table, nis_object * obj, void *eargs)
{
	int			len, status = 0;
	char			*val;
	struct entry_col	*ecol;
	nss_status_t		res;
	_exec_nisplus_args	*eargp = (_exec_nisplus_args *)eargs;
	nss_XbyY_args_t		*argp = eargp->argp;
	_priv_execattr *_priv_exec = (_priv_execattr *)(argp->key.attrp);
	const char		*type = _priv_exec->type;
	const char		*policy = _priv_exec->policy;

#ifdef	DEBUG
	(void) fprintf(stdout, "\n[getexecattr.c: check_match]\n");
#endif	/* DEBUG */

	if (obj->zo_data.zo_type != NIS_ENTRY_OBJ ||
	    obj->EN_data.en_cols.en_cols_len < EXECATTR_COL) {
		/*
		 * found one bad entry. try the next one.
		 */
		return (0);
	}
	ecol = obj->EN_data.en_cols.en_cols_val;

	/*
	 * NSS_DBOP_EXECATTR_BYNAME searched for name, NSS_DBOP_EXECATTR_BYID
	 * searched for id and NSS_DBOP_EXECATTR_BYNAMEID searched for name
	 * and id in _exec_nisplus_lookup already.
	 * If we're talking to pre-Solaris9 nisplus servers, check policy,
	 * as policy was not a searchable column then.
	 */
	if (policy && eargp->check_policy) {
		/*
		 * check policy; it was not a searchable column in old servers.
		 */
		EC_SET(ecol, EXECATTR_NDX_POLICY, len, val);
		if ((len == 0) || (strcmp(val, policy) != 0)) {
			return (0);
		}
	}

	if (type) {
		/*
		 * check type
		 */
		EC_SET(ecol, EXECATTR_NDX_TYPE, len, val);
		if ((len == 0) || (strcmp(val, type) != 0)) {
			return (0);
		}
	}

	res = _exec_process_val(eargp, obj);

	*(eargp->resp) = res;
	switch (res) {
	case NSS_SUCCESS:
		status = IS_GET_ONE(_priv_exec->search_flag);
		break;
	case NSS_UNAVAIL:
		status = 1;
		break;
	default:
		status = 0;
		break;
	}

	return (status);
}


static nss_status_t
_exec_nisplus_lookup(nisplus_backend_t *be,
    nss_XbyY_args_t *argp,
    int getby_flag)
{
	char			key[MAX_INPUT];
	char			policy_key[POLICY_LEN];
	const char		*column1, *key1, *column2, *key2;
	nis_result		*r = NULL;
	nss_status_t		res = NSS_NOTFOUND;
	_exec_nisplus_args	eargs;
	_priv_execattr *_priv_exec = (_priv_execattr *)(argp->key.attrp);

	eargs.check_policy = 0;
	eargs.argp = argp;
	eargs.be = be;
	eargs.resp = &res;

#ifdef	DEBUG
	(void) fprintf(stdout, "\n[getexecattr.c: _exec_nisplus_lookup]\n");
#endif	/* DEBUG */

	switch (getby_flag) {
	case NSS_DBOP_EXECATTR_BYNAME:
		column1 = EXECATTR_TAG_NAME;
		key1 = _priv_exec->name;
		column2 = key2 = NULL;
		break;
	case NSS_DBOP_EXECATTR_BYID:
		column1 = EXECATTR_TAG_ID;
		key1 = _priv_exec->id;
		column2 = key2 = NULL;
		break;
	case NSS_DBOP_EXECATTR_BYNAMEID:
		column1 = EXECATTR_TAG_NAME;
		key1 = _priv_exec->name;
		column2 = EXECATTR_TAG_ID;
		key2 = _priv_exec->id;
		break;
	default:
		return (NSS_NOTFOUND);
	}

	if (snprintf(policy_key, POLICY_LEN, "%s=%s", EXECATTR_TAG_POLICY,
	    _priv_exec->policy) >= POLICY_LEN)
		return (NSS_NOTFOUND);

	/*
	 * Try using policy as part of search key. If that fails,
	 * (it will, in case of pre-Solaris9 nis server where policy
	 * was not searchable), try again without using policy.
	 */
	if (((column2 == NULL) && (snprintf(key, MAX_INPUT, "[%s=%s,%s]%s",
	    column1, key1, policy_key, be->table_name) >= MAX_INPUT)) ||
	    ((column2 != NULL) &&
	    (snprintf(key, MAX_INPUT, "[%s=%s,%s,%s=%s]%s",
	    column1, key1, policy_key, column2, key2,
	    be->table_name) >= MAX_INPUT)))
		return (NSS_NOTFOUND);

	do {
		r = __nis_list_localcb(key, NIS_LIST_COMMON, check_match,
		    (void *)&eargs);
		if ((eargs.check_policy == 0) &&
		    (r != NULL) && (r->status == NIS_BADATTRIBUTE)) {
			nis_freeresult(r);
			if (column2 == NULL)
				(void) snprintf(key, MAX_INPUT, "[%s=%s]%s",
				    column1, key1, be->table_name);
			else
				(void) snprintf(key, MAX_INPUT,
				    "[%s=%s,%s=%s]%s", column1, key1, column2,
				    key2, be->table_name);
			eargs.check_policy = 1;
		} else {
			if (r != NULL)
				nis_freeresult(r);
			key[0] = '\0';
			break;
		}
	} while (key[0]);


	return (res);
}


/*
 * If search for exact match for id failed, get_wild checks if we have
 * a wild-card entry for that id.
 */
static nss_status_t
get_wild(nisplus_backend_ptr_t be, nss_XbyY_args_t *argp, int getby_flag)
{
	const char	*orig_id = NULL;
	char		*old_id = NULL;
	char		*wild_id = NULL;
	nss_status_t	res = NSS_NOTFOUND;
	_priv_execattr	*_priv_exec = (_priv_execattr *)(argp->key.attrp);

	orig_id = _priv_exec->id;
	old_id = strdup(_priv_exec->id);
	wild_id = old_id;
	while ((wild_id = _exec_wild_id(wild_id, _priv_exec->type)) != NULL) {
		_priv_exec->id = wild_id;
		res = _exec_nisplus_lookup(be, argp, getby_flag);
		if (res == NSS_SUCCESS)
			break;
	}
	_priv_exec->id = orig_id;
	if (old_id)
		free(old_id);

	return (res);
}


static nss_status_t
getbynam(nisplus_backend_ptr_t be, void *a)
{
	nss_status_t	res;
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;

#ifdef	DEBUG
	(void) fprintf(stdout, "\n[getexecattr.c: getbyname]\n");
#endif	/* DEBUG */

	res = _exec_nisplus_lookup(be, argp, NSS_DBOP_EXECATTR_BYNAME);

	_exec_cleanup(res, argp);

	return (res);
}


static nss_status_t
getbyid(nisplus_backend_ptr_t be, void *a)
{
	nss_status_t	res;
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;

#ifdef	DEBUG
	(void) fprintf(stdout, "\n[getexecattr.c: getbyid]\n");
#endif	/* DEBUG */

	res = _exec_nisplus_lookup(be, argp, NSS_DBOP_EXECATTR_BYID);

	if (res != NSS_SUCCESS)
		res = get_wild(be, argp, NSS_DBOP_EXECATTR_BYID);

	_exec_cleanup(res, argp);

	return (res);
}


static nss_status_t
getbynameid(nisplus_backend_ptr_t be, void *a)
{
	nss_status_t	res;
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;

#ifdef	DEBUG
	(void) fprintf(stdout, "\n[getexecattr.c: getbynameid]\n");
#endif	/* DEBUG */

	res = _exec_nisplus_lookup(be, argp, NSS_DBOP_EXECATTR_BYNAMEID);

	if (res != NSS_SUCCESS)
		res = get_wild(be, argp, NSS_DBOP_EXECATTR_BYNAMEID);

	_exec_cleanup(res, argp);

	return (res);
}


/*
 * Returns NSS_STR_PARSE_{SUCCESS, ERANGE, PARSE}
 */
/*ARGSUSED*/
static int
nis_object2execstr(int nobj, nis_object *obj,
		nisplus_backend_ptr_t be,
		nss_XbyY_args_t *argp)
{
	char			*buffer, *name, *type, *policy;
	char			*res1, *res2, *id, *attr;
	int			buflen, namelen, typelen, policylen;
	int			res1len, res2len, idlen, attrlen;
	struct entry_col	*ecol;

	/*
	 * If we got more than one nis_object, we just ignore object(s) except
	 * the first. Although it should never have happened.
	 *
	 * ASSUMPTION: All the columns in the NIS+ tables are null terminated.
	 */
	if (obj->zo_data.zo_type != ENTRY_OBJ ||
	    obj->EN_data.en_cols.en_cols_len < EXECATTR_COL) {
		/* namespace/table/object is curdled */
		return (NSS_STR_PARSE_PARSE);
	}
	ecol = obj->EN_data.en_cols.en_cols_val;

	/* profile name */
	__NISPLUS_GETCOL_OR_RETURN(ecol, EXECATTR_NDX_NAME, namelen, name);

	/* exec type */
	__NISPLUS_GETCOL_OR_EMPTY(ecol, EXECATTR_NDX_TYPE, typelen, type);

	/* policy */
	__NISPLUS_GETCOL_OR_EMPTY(ecol, EXECATTR_NDX_POLICY, policylen, policy);

	/* reserved field 1 */
	__NISPLUS_GETCOL_OR_EMPTY(ecol, EXECATTR_NDX_RES1, res1len, res1);

	/* reserved field 2 */
	__NISPLUS_GETCOL_OR_EMPTY(ecol, EXECATTR_NDX_RES2, res2len, res2);

	/* unique id */
	__NISPLUS_GETCOL_OR_EMPTY(ecol, EXECATTR_NDX_ID, idlen, id);

	/* key-value pairs of attributes */
	__NISPLUS_GETCOL_OR_EMPTY(ecol, EXECATTR_NDX_ATTR, attrlen, attr);

	buflen = namelen + policylen + typelen + res1len + res2len +
	    idlen + attrlen + 7;
	if (argp->buf.result != NULL) {
		if ((be->buffer = calloc(1, buflen)) == NULL)
			return (NSS_STR_PARSE_PARSE);
		/* exclude trailing null from length */
		be->buflen = buflen - 1;
		buffer = be->buffer;
	} else {
		if (buflen > argp->buf.buflen)
			return (NSS_STR_PARSE_ERANGE);
		buflen = argp->buf.buflen;
		buffer = argp->buf.buffer;
		(void) memset(buffer, 0, buflen);
	}
	(void) snprintf(buffer, buflen, "%s:%s:%s:%s:%s:%s:%s",
	    name, policy, type, res1, res2, id, attr);
#ifdef DEBUG
	(void) fprintf(stdout, "execattr [%s]\n", buffer);
	(void) fflush(stdout);
#endif  /* DEBUG */
	return (NSS_STR_PARSE_SUCCESS);
}

static nisplus_backend_op_t execattr_ops[] = {
	_nss_nisplus_destr,
	_nss_nisplus_endent,
	_nss_nisplus_setent,
	_nss_nisplus_getent,
	getbynam,
	getbyid,
	getbynameid
};

/*ARGSUSED*/
nss_backend_t  *
_nss_nisplus_exec_attr_constr(const char *dummy1,
    const char *dummy2,
    const char *dummy3,
    const char *dummy4,
    const char *dummy5,
    const char *dummy6,
    const char *dummy7)
{
	return (_nss_nisplus_constr(execattr_ops,
	    sizeof (execattr_ops)/sizeof (execattr_ops[0]),
	    EXECATTR_TBLNAME, nis_object2execstr));
}
