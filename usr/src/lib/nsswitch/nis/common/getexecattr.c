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
#include <rpcsvc/ypclnt.h>
#include <rpcsvc/yp_prot.h>
#include "nis_common.h"


/* extern from nis_common.c */
extern void massage_netdb(const char **, int *);
/* externs from libnsl */
extern int _doexeclist(nss_XbyY_args_t *);
extern char *_exec_wild_id(char *, const char *);
extern void _exec_cleanup(nss_status_t, nss_XbyY_args_t *);
extern char *_strtok_escape(char *, char *, char **);

typedef struct __exec_nis_args {
	int		*yp_status;
	nss_XbyY_args_t	*argp;
} _exec_nis_args;


/*
 * check_match: returns 1 if -  matching entry found and no more entries needed,
 *				or, entry cannot be found because of error;
 *		returns 0 if -  no matching entry found, or,
 *				matching entry found and next match needed.
 */
static int
check_match(nss_XbyY_args_t *argp, int check_policy)
{
	execstr_t	*exec = (execstr_t *)(argp->returnval);
	_priv_execattr	*_priv_exec = (_priv_execattr *)(argp->key.attrp);
	const char	*name = _priv_exec->name;
	const char	*type = _priv_exec->type;
	const char	*id = _priv_exec->id;
	const char	*policy = _priv_exec->policy;

	if (name && id) {
		/*
		 * NSS_DBOP_EXECATTR_BYNAMEID searched for name and id in
		 * _exec_nis_lookup already.
		 * If we're talking to pre-Solaris9 nis servers, check policy,
		 * as policy was not a searchable column then.
		 */
		if ((check_policy && policy &&
		    (strcmp(policy, exec->policy) != 0)) ||
		    (type && (strcmp(type, exec->type) != 0))) {
			return (0);
		}
	} else if ((policy && exec->policy &&
	    (strcmp(policy, exec->policy) != 0)) ||
	    (name && exec->name && (strcmp(name, exec->name) != 0)) ||
	    (type && exec->type && (strcmp(type, exec->type) != 0)) ||
	    (id && exec->id && (strcmp(id, exec->id) != 0))) {
		return (0);
	}

	return (1);
}

/*
 * check_match_strbuf: set up the data needed by check_match()
 * and call it to match exec_attr data in strbuf and argp->key.attrp
 */
static int
check_match_strbuf(nss_XbyY_args_t *argp, char *strbuf, int check_policy)
{
	char		*last = NULL;
	char		*sep = KV_TOKEN_DELIMIT;
	execstr_t	exec;
	execstr_t	*execp = &exec;
	void		*sp;
	int		rc;

	/*
	 * Remove newline that yp_match puts at the
	 * end of the entry it retrieves from the map.
	 */
	if (strbuf[argp->returnlen] == '\n') {
		strbuf[argp->returnlen] = '\0';
	}

	execp->name = _strtok_escape(strbuf, sep, &last);
	execp->policy = _strtok_escape(NULL, sep, &last);
	execp->type = _strtok_escape(NULL, sep, &last);
	execp->res1 = _strtok_escape(NULL, sep, &last);
	execp->res2 = _strtok_escape(NULL, sep, &last);
	execp->id = _strtok_escape(NULL, sep, &last);

	sp = argp->returnval;
	argp->returnval = execp;
	rc = check_match(argp, check_policy);
	argp->returnval = sp;
	free(strbuf);

	return (rc);
}

static  nss_status_t
_exec_nis_parse(const char *instr,
    int instr_len,
    nss_XbyY_args_t *argp,
    int check_policy)
{
	int		parse_stat;
	nss_status_t	res;
	_priv_execattr	*_priv_exec = (_priv_execattr *)(argp->key.attrp);
	char		*strbuf;
	int		check_matched;

	argp->returnval = NULL;
	argp->returnlen = 0;
	parse_stat = (*argp->str2ent)(instr, instr_len, argp->buf.result,
	    argp->buf.buffer, argp->buf.buflen);
	switch (parse_stat) {
	case NSS_STR_PARSE_SUCCESS:
		argp->returnlen = instr_len;
		/* if exec_attr file format requested */
		if (argp->buf.result == NULL) {
			argp->returnval = argp->buf.buffer;
			if ((strbuf = strdup(instr)) == NULL)
				res = NSS_UNAVAIL;
			check_matched = check_match_strbuf(argp,
			    strbuf, check_policy);
		} else {
			argp->returnval = argp->buf.result;
			check_matched = check_match(argp, check_policy);
		}
		if (check_matched) {
			res = NSS_SUCCESS;
			if (IS_GET_ALL(_priv_exec->search_flag)) {
				if (_doexeclist(argp) == 0) {
					res = NSS_UNAVAIL;
				}
			}
		} else {
			res = NSS_NOTFOUND;
		}
		break;
	case NSS_STR_PARSE_ERANGE:
		argp->erange = 1;
		res = NSS_NOTFOUND;
		break;
	default:
		res = NSS_UNAVAIL;
		break;
	}

	return (res);
}

/*
 * This is the callback for yp_all. It returns 0 to indicate that it wants to
 * be called again for further key-value pairs, or returns non-zero to stop the
 * flow of key-value pairs. If it returns a non-zero value, it is not called
 * again. The functional value of yp_all is then 0.
 */
/*ARGSUSED*/
static int
_exec_nis_cb(int instatus,
    char *inkey,
    int inkeylen,
    char *inval,
    int invallen,
    void *indata)
{
	int		check_policy = 1; /* always check policy for yp_all */
	int		stop_cb;
	const char	*filter;
	nss_status_t	res;
	_exec_nis_args	*eargp = (_exec_nis_args *)indata;
	nss_XbyY_args_t	*argp = eargp->argp;
	_priv_execattr	*_priv_exec = (_priv_execattr *)(argp->key.attrp);

	if (instatus != YP_TRUE) {
		/*
		 * If we have no more data to look at, we want to
		 * keep yp_status from previous key/value pair
		 * that we processed.
		 * If this is the 1st time we enter this callback,
		 * yp_status is already set to YPERR_YPERR
		 * (see _exec_nis_lookup() for when this callback
		 * and arguments are set initially).
		 */
		if (instatus != YP_NOMORE) {
			*(eargp->yp_status) = YPERR_YPERR;
		}
		return (0);	/* yp_all may decide otherwise... */
	}

	filter = (_priv_exec->name) ? _priv_exec->name : _priv_exec->id;

	/*
	 * yp_all does not null terminate the entry it retrieves from the
	 * map, unlike yp_match. so we do it explicitly here.
	 */
	inval[invallen] = '\0';

	/*
	 * Optimization:  if the entry doesn't contain the filter string then
	 * it can't be the entry we want, so don't bother looking more closely
	 * at it.
	 */
	if ((_priv_exec->policy &&
	    (strstr(inval, _priv_exec->policy) == NULL)) ||
	    (strstr(inval, filter) == NULL)) {
		*(eargp->yp_status) = YPERR_KEY;
		return (0);
	}

	res = _exec_nis_parse(inval, invallen, argp, check_policy);

	switch (res) {
	case NSS_SUCCESS:
		*(eargp->yp_status) = 0;
		stop_cb = IS_GET_ONE(_priv_exec->search_flag);
		break;
	case NSS_UNAVAIL:
		*(eargp->yp_status) = YPERR_KEY;
		stop_cb = 1;
		break;
	default:
		*(eargp->yp_status) = YPERR_YPERR;
		stop_cb = 0;
		break;
	}

	return (stop_cb);
}

static nss_status_t
_exec_nis_lookup(nis_backend_ptr_t be, nss_XbyY_args_t *argp, int getby_flag)
{
	int		ypstatus;
	nss_status_t	res = NSS_SUCCESS;
	nss_status_t	ypres;
	_priv_execattr	*_priv_exec = (_priv_execattr *)(argp->key.attrp);

	if (getby_flag == NSS_DBOP_EXECATTR_BYNAMEID) {
		int		check_policy = 0;
		int		vallen;
		char		*val;
		char		key[MAX_INPUT];

		/*
		 * Try using policy as part of search key. If that fails,
		 * (it will, in case of pre-Solaris9 nis server where policy
		 * was not searchable), try again without using policy.
		 */
		if (snprintf(key, MAX_INPUT, "%s%s%s%s%s", _priv_exec->name,
		    KV_TOKEN_DELIMIT, _priv_exec->policy, KV_TOKEN_DELIMIT,
		    _priv_exec->id) >= MAX_INPUT)
			return (NSS_NOTFOUND);
		do {
			ypres = _nss_nis_ypmatch(be->domain, NIS_MAP_EXECATTR,
			    key, &val, &vallen, &ypstatus);
			if ((check_policy == 0) && (ypstatus == YPERR_KEY)) {
				(void) snprintf(key, MAX_INPUT, "%s%s%s",
				    _priv_exec->name, KV_TOKEN_DELIMIT,
				    _priv_exec->id);
				check_policy = 1;
				continue;
			} else if (ypres != NSS_SUCCESS) {
				res = ypres;
				break;
			} else {
				char *val_save = val;

				massage_netdb((const char **)&val, &vallen);
				res = _exec_nis_parse((const char *)val,
				    vallen, argp, check_policy);
				free(val_save);
				break;
			}
		} while (res == NSS_SUCCESS);
	} else {
		int			ypstat = YPERR_YPERR;
		struct ypall_callback	cback;
		_exec_nis_args		eargs;

		eargs.yp_status = &ypstat;
		eargs.argp = argp;

		cback.foreach = _exec_nis_cb;
		cback.data = (void *)&eargs;

		/*
		 * Instead of calling yp_all() doing hard lookup, we use
		 * the alternative function, __yp_all_cflookup(), to
		 * perform soft lookup when binding to nis servers with
		 * time-out control. Other than that, these two functions
		 * do exactly the same thing.
		 */
		ypstatus = __yp_all_cflookup((char *)(be->domain),
		    (char *)(be->enum_map), &cback, 0);

		/*
		 * For GET_ALL, check if we found anything at all.
		 */
		if (_priv_exec->head_exec != NULL)
			return (NSS_SUCCESS);

		switch (ypstat) {
		case 0:
			res = NSS_SUCCESS;
			break;
		case YPERR_BUSY:
			res = NSS_TRYAGAIN;
			break;
		case YPERR_KEY:
			/*
			 * If no such key, return NSS_NOTFOUND
			 * as this looks more relevant; it will
			 * also help libnsl to try with another
			 * policy (see _getexecprof()).
			 */
			res = NSS_NOTFOUND;
			break;
		default:
			res = NSS_UNAVAIL;
			break;
		}

	}

	return (res);
}

/*
 * If search for exact match for id failed, get_wild checks if we have
 * a wild-card entry for that id.
 */
static  nss_status_t
get_wild(nis_backend_ptr_t be, nss_XbyY_args_t *argp, int getby_flag)
{
	const char	*orig_id;
	char		*old_id = NULL;
	char		*wild_id = NULL;
	nss_status_t	res = NSS_NOTFOUND;
	_priv_execattr	*_priv_exec = (_priv_execattr *)(argp->key.attrp);

	orig_id = _priv_exec->id;
	old_id = strdup(_priv_exec->id);
	wild_id = old_id;
	while ((wild_id = _exec_wild_id(wild_id, _priv_exec->type)) != NULL) {
		_priv_exec->id = wild_id;
		res = _exec_nis_lookup(be, argp, getby_flag);
		if (res == NSS_SUCCESS)
			break;
	}
	_priv_exec->id = orig_id;
	if (old_id)
		free(old_id);

	return (res);
}


static  nss_status_t
getbynam(nis_backend_ptr_t be, void *a)
{
	nss_status_t	res;
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;

	res = _exec_nis_lookup(be, argp, NSS_DBOP_EXECATTR_BYNAME);

	_exec_cleanup(res, argp);

	return (res);
}

static  nss_status_t
getbyid(nis_backend_ptr_t be, void *a)
{
	nss_status_t	res;
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	/*LINTED*/
	_priv_execattr	*_priv_exec = (_priv_execattr *)(argp->key.attrp);

	res = _exec_nis_lookup(be, argp, NSS_DBOP_EXECATTR_BYID);

	if (res != NSS_SUCCESS)
		res = get_wild(be, argp, NSS_DBOP_EXECATTR_BYID);

	_exec_cleanup(res, argp);

	return (res);
}


static  nss_status_t
getbynameid(nis_backend_ptr_t be, void *a)
{
	nss_status_t	res;
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	/*LINTED*/
	_priv_execattr	*_priv_exec = (_priv_execattr *)(argp->key.attrp);

	res = _exec_nis_lookup(be, argp, NSS_DBOP_EXECATTR_BYNAMEID);

	if (res != NSS_SUCCESS)
		res = get_wild(be, argp, NSS_DBOP_EXECATTR_BYNAMEID);

	_exec_cleanup(res, argp);

	return (res);
}


static nis_backend_op_t execattr_ops[] = {
	_nss_nis_destr,
	_nss_nis_endent,
	_nss_nis_setent,
	_nss_nis_getent_netdb,
	getbynam,
	getbyid,
	getbynameid
};

/*ARGSUSED*/
nss_backend_t *
_nss_nis_exec_attr_constr(const char *dummy1,
    const char *dummy2,
    const char *dummy3,
    const char *dummy4,
    const char *dummy5,
    const char *dummy6,
    const char *dummy7)
{
	return (_nss_nis_constr(execattr_ops,
	    sizeof (execattr_ops)/sizeof (execattr_ops[0]),
	    NIS_MAP_EXECATTR));
}
