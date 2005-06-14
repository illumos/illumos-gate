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
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
	int			parse_stat;
	nss_status_t		res;
	nss_XbyY_args_t		*argp = eargp->argp;
	nisplus_backend_t	*be = eargp->be;
	_priv_execattr *_priv_exec = (_priv_execattr *)(argp->key.attrp);

#ifdef	DEBUG
	(void) fprintf(stdout, "\n[getexecattr.c: _exec_process_val]\n");
#endif	/* DEBUG */

	parse_stat = (be->obj2ent) (1, obj, argp);	/* passing one obj */
	switch (parse_stat) {
	case NSS_STR_PARSE_SUCCESS:
		argp->returnval = argp->buf.result;
		res = NSS_SUCCESS;
		if (_priv_exec->search_flag == GET_ALL) {
			if (_doexeclist(argp) == 0) {
				res = NSS_UNAVAIL;
			}
		}
		break;
	case NSS_STR_PARSE_ERANGE:
		argp->erange = 1;
		res = NSS_NOTFOUND; /* We won't find this otherwise, anyway */
		break;
	case NSS_STR_PARSE_PARSE:
		res = NSS_NOTFOUND;
		break;
	default:
		res = NSS_UNAVAIL;
		break;
	}

	return (res);
}


/*
 * check_match: returns 1 if -  matching entry found and no more entries needed,
 *				entry cannot be found because of error;
 *		returns 0 if -  no matching entry found,
 *				matching entry found and next match needed.
 */
static int
check_match(nis_name table, nis_object * obj, void *eargs)
{
	int			len;
	int			status = 0;
	char			*p, *val;
	struct entry_col	*ecol;
	nss_status_t		res;
	_exec_nisplus_args	*eargp = (_exec_nisplus_args *)eargs;
	nss_XbyY_args_t		*argp = eargp->argp;
	nisplus_backend_t	*be = eargp->be;
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
		if ((len == NULL) || (strcmp(val, policy) != 0)) {
			return (0);
		}
	}

	if (type) {
		/*
		 * check type
		 */
		EC_SET(ecol, EXECATTR_NDX_TYPE, len, val);
		if ((len == NULL) || (strcmp(val, type) != 0)) {
			return (0);
		}
	}

	res = _exec_process_val(eargp, obj);

	*(eargp->resp) = res;
	switch (res) {
	case NSS_SUCCESS:
		status = (_priv_exec->search_flag == GET_ONE);
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
	int			status;
	char			key[MAX_INPUT];
	char			policy_key[POLICY_LEN];
	const char		*column1, *key1, *column2, *key2;
	nis_object		*obj;
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
	char		*orig_id = NULL;
	char		*old_id = NULL;
	char		*wild_id = NULL;
	nss_status_t	res = NSS_NOTFOUND;
	_priv_execattr	*_priv_exec = (_priv_execattr *)(argp->key.attrp);

	orig_id = strdup(_priv_exec->id);
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
	_priv_execattr	*_priv_exec = (_priv_execattr *)(argp->key.attrp);

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
	_priv_execattr	*_priv_exec = (_priv_execattr *)(argp->key.attrp);

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
 * place the results from the nis_object structure into argp->buf.result
 * Returns NSS_STR_PARSE_{SUCCESS, ERANGE, PARSE}
 */
static int
nis_object2execstr(int nobj, nis_object *obj, nss_XbyY_args_t *argp)
{
	int			len;
	int			buflen = argp->buf.buflen;
	char			*limit, *val, *endnum, *nullstring;
	char			*buffer = NULL;
	char			*empty = "";
	execstr_t		*exec = NULL;
	struct entry_col	*ecol;

	limit = argp->buf.buffer + buflen;
	exec = (execstr_t *)argp->buf.result;
	buffer = argp->buf.buffer;

	if ((buffer == NULL) || (exec == NULL)) {
		return (NSS_STR_PARSE_PARSE);
	}

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

	/*
	 * execstr->name: profile name
	 */
	EC_SET(ecol, EXECATTR_NDX_NAME, len, val);
	if (len < 1 || (*val == '\0')) {
		val = empty;
	}
	exec->name = buffer;
	buffer += len;
	if (buffer >= limit) {
		return (NSS_STR_PARSE_ERANGE);
	}
	strcpy(exec->name, val);
	nullstring = (buffer - 1);

	/*
	 * execstr->type: exec type
	 */
	EC_SET(ecol, EXECATTR_NDX_TYPE, len, val);
	if (len < 1 || (*val == '\0')) {
		val = empty;
	}
	exec->type = buffer;
	buffer += len;
	if (buffer >= limit) {
		return (NSS_STR_PARSE_ERANGE);
	}
	strcpy(exec->type, val);
	nullstring = (buffer - 1);

	/*
	 * execstr->policy
	 */
	EC_SET(ecol, EXECATTR_NDX_POLICY, len, val);
	if (len < 1 || (*val == '\0')) {
		val = empty;
	}
	exec->policy = buffer;
	buffer += len;
	if (buffer >= limit) {
		return (NSS_STR_PARSE_ERANGE);
	}
	strcpy(exec->policy, val);
	nullstring = (buffer - 1);

	/*
	 * execstr->res1: reserved field 1
	 */
	EC_SET(ecol, EXECATTR_NDX_RES1, len, val);
	if (len < 1 || (*val == '\0')) {
		val = empty;
	}
	exec->res1 = buffer;
	buffer += len;
	if (buffer >= limit) {
		return (NSS_STR_PARSE_ERANGE);
	}
	strcpy(exec->res1, val);
	nullstring = (buffer - 1);

	/*
	 * execstr->res2: reserved field 2
	 */
	EC_SET(ecol, EXECATTR_NDX_RES2, len, val);
	if (len < 1 || (*val == '\0')) {
		val = empty;
	}
	exec->res2 = buffer;
	buffer += len;
	if (buffer >= limit) {
		return (NSS_STR_PARSE_ERANGE);
	}
	strcpy(exec->res2, val);
	nullstring = (buffer - 1);

	/*
	 * execstr->id: unique id
	 */
	EC_SET(ecol, EXECATTR_NDX_ID, len, val);
	if (len < 1 || (*val == '\0')) {
		val = empty;
	}
	exec->id = buffer;
	buffer += len;
	if (buffer >= limit) {
		return (NSS_STR_PARSE_ERANGE);
	}
	strcpy(exec->id, val);
	nullstring = (buffer - 1);

	/*
	 * execstr->attrs: key-value pairs of attributes
	 */
	EC_SET(ecol, EXECATTR_NDX_ATTR, len, val);
	if (len < 1 || (*val == '\0')) {
		val = empty;
	}
	exec->attr = buffer;
	buffer += len;
	if (buffer >= limit) {
		return (NSS_STR_PARSE_ERANGE);
	}
	strcpy(exec->attr, val);
	nullstring = (buffer - 1);

	exec->next = (execstr_t *)NULL;

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
		EXECATTR_TBLNAME,
		nis_object2execstr));
}
