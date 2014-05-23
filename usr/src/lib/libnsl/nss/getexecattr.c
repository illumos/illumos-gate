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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include "mt.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <nss_dbdefs.h>
#include <string.h>
#include <strings.h>
#include <sys/systeminfo.h>
#include <thread.h>
#include <synch.h>
#include <nsswitch.h>
#include <prof_attr.h>
#include <exec_attr.h>

/* externs from libc */
extern void _nss_db_state_destr(struct nss_db_state *);

/* externs from parse.c */
extern char *_strtok_escape(char *, char *, char **);
extern char *_strdup_null(char *);
/* extern from getprofattr.c */
extern int str2profattr(const char *, int, void *, char *, int);

char *_exec_wild_id(char *, const char *);
execstr_t *_dup_execstr(execstr_t *);
void _free_execstr(execstr_t *);

static char *_nsw_search_path = NULL;

/*
 * Unsynchronized, but it affects only efficiency, not correctness
 */

static DEFINE_NSS_DB_ROOT(exec_root);
static DEFINE_NSS_GETENT(context);

void
_nss_initf_execattr(nss_db_params_t *p)
{
	p->name = NSS_DBNAM_EXECATTR;
	p->config_name    = NSS_DBNAM_PROFATTR; /* use config for "prof_attr" */
}

void
_nsw_initf_execattr(nss_db_params_t *p)
{
	p->name = NSS_DBNAM_EXECATTR;
	p->flags |= NSS_USE_DEFAULT_CONFIG;
	p->default_config = _nsw_search_path;
}

void
_nsw_initf_profattr(nss_db_params_t *p)
{
	p->name = NSS_DBNAM_PROFATTR;
	p->flags |= NSS_USE_DEFAULT_CONFIG;
	p->default_config = _nsw_search_path;
}

/*
 * Return values: 0 = success, 1 = parse error, 2 = erange ... The structure
 * pointer passed in is a structure in the caller's space wherein the field
 * pointers would be set to areas in the buffer if need be. instring and buffer
 * should be separate areas.
 */
int
str2execattr(const char *instr, int lenstr, void *ent, char *buffer, int buflen)
{
	char		*last = NULL;
	char		*sep = KV_TOKEN_DELIMIT;
	execstr_t	*exec = (execstr_t *)ent;

	if (lenstr >= buflen)
		return (NSS_STR_PARSE_ERANGE);

	if (instr != buffer)
		(void) strncpy(buffer, instr, buflen);

	/*
	 * Remove newline that nis (yp_match) puts at the
	 * end of the entry it retrieves from the map.
	 */
	if (buffer[lenstr] == '\n') {
		buffer[lenstr] = '\0';
	}

	/* quick exit do not entry fill if not needed */
	if (ent == (void *)NULL)
		return (NSS_STR_PARSE_SUCCESS);

	exec->name = _strtok_escape(buffer, sep, &last);
	exec->policy = _strtok_escape(NULL, sep, &last);
	exec->type = _strtok_escape(NULL, sep, &last);
	exec->res1 = _strtok_escape(NULL, sep, &last);
	exec->res2 = _strtok_escape(NULL, sep, &last);
	exec->id = _strtok_escape(NULL, sep, &last);
	exec->attr = _strtok_escape(NULL, sep, &last);
	exec->next = NULL;

	return (NSS_STR_PARSE_SUCCESS);
}


void
_setexecattr(void)
{
	nss_setent(&exec_root, _nss_initf_execattr, &context);
}


void
_endexecattr(void)
{
	nss_endent(&exec_root, _nss_initf_execattr, &context);
	nss_delete(&exec_root);
}


execstr_t *
_getexecattr(execstr_t *result, char *buffer, int buflen, int *errnop)
{
	nss_status_t    res;
	nss_XbyY_args_t arg;

	NSS_XbyY_INIT(&arg, result, buffer, buflen, str2execattr);
	res = nss_getent(&exec_root, _nss_initf_execattr, &context, &arg);
	arg.status = res;
	*errnop = arg.h_errno;

	return ((execstr_t *)NSS_XbyY_FINI(&arg));
}

execstr_t *
_getexecprof(char *name,
    char *type,
    char *id,
    int search_flag,
    execstr_t *result,
    char *buffer,
    int buflen,
    int *errnop)
{
	int		getby_flag;
	char		policy_buf[BUFSIZ];
	nss_status_t	res = NSS_NOTFOUND;
	nss_XbyY_args_t	arg;
	_priv_execattr	_priv_exec;
	static mutex_t	_nsw_exec_lock = DEFAULTMUTEX;

	if ((name != NULL) && (id != NULL)) {
		getby_flag = NSS_DBOP_EXECATTR_BYNAMEID;
	} else if (name != NULL) {
		getby_flag = NSS_DBOP_EXECATTR_BYNAME;
	} else if (id != NULL) {
		getby_flag = NSS_DBOP_EXECATTR_BYID;
	} else {
		return (NULL);
	}

	NSS_XbyY_INIT(&arg, result, buffer, buflen, str2execattr);

	_priv_exec.name = name;
	_priv_exec.type = type;
	_priv_exec.id = id;
#ifdef SI_SECPOLICY
	if (sysinfo(SI_SECPOLICY, policy_buf, BUFSIZ) == -1)
#endif	/* SI_SECPOLICY */
	(void) strncpy(policy_buf, DEFAULT_POLICY, BUFSIZ);

retry_policy:
	_priv_exec.policy = IS_SEARCH_ALL(search_flag) ? NULL : policy_buf;
	_priv_exec.search_flag = search_flag;
	_priv_exec.head_exec = NULL;
	_priv_exec.prev_exec = NULL;

	arg.key.attrp = &(_priv_exec);

	switch (getby_flag) {
	case NSS_DBOP_EXECATTR_BYID:
		res = nss_search(&exec_root, _nss_initf_execattr, getby_flag,
		    &arg);
		break;
	case NSS_DBOP_EXECATTR_BYNAMEID:
	case NSS_DBOP_EXECATTR_BYNAME:
		{
			char			pbuf[NSS_BUFLEN_PROFATTR];
			profstr_t		prof;
			nss_status_t		pres;
			nss_XbyY_args_t		parg;
			enum __nsw_parse_err	pserr;
			struct __nsw_lookup	*lookups = NULL;
			struct __nsw_switchconfig *conf = NULL;

			if (conf = __nsw_getconfig(NSS_DBNAM_PROFATTR, &pserr))
				if ((lookups = conf->lookups) == NULL)
					goto out;
			NSS_XbyY_INIT(&parg, &prof, pbuf, NSS_BUFLEN_PROFATTR,
			    str2profattr);
			parg.key.name = name;
			do {
				/*
				 * search the exec_attr entry only in the scope
				 * that we find the profile in.
				 * if conf = NULL, search in local files only,
				 * as we were not able to read nsswitch.conf.
				 */
				DEFINE_NSS_DB_ROOT(prof_root);
				if (mutex_lock(&_nsw_exec_lock) != 0)
					goto out;
				_nsw_search_path = (conf == NULL)
				    ? NSS_FILES_ONLY
				    : lookups->service_name;
				pres = nss_search(&prof_root,
				    _nsw_initf_profattr,
				    NSS_DBOP_PROFATTR_BYNAME, &parg);
				if (pres == NSS_SUCCESS) {
					DEFINE_NSS_DB_ROOT(pexec_root);
					res = nss_search(&pexec_root,
					    _nsw_initf_execattr, getby_flag,
					    &arg);
					if (pexec_root.s != NULL)
						_nss_db_state_destr(
						    pexec_root.s);
				}
				if (prof_root.s != NULL)
					_nss_db_state_destr(prof_root.s);
				(void) mutex_unlock(&_nsw_exec_lock);
				if ((pres == NSS_SUCCESS) || (conf == NULL))
					break;
			} while (lookups && (lookups = lookups->next));
		}
		break;
	default:
		break;
	}

out:
	/*
	 * If we can't find an entry for the current default policy
	 * fall back to the old "suser" policy.  The nameservice is
	 * shared between different OS releases.
	 */
	if (!IS_SEARCH_ALL(search_flag) &&
	    (res == NSS_NOTFOUND && strcmp(policy_buf, DEFAULT_POLICY) == 0)) {
		(void) strlcpy(policy_buf, SUSER_POLICY, BUFSIZ);
		goto retry_policy;
	}

	arg.status = res;
	*errnop = res;
	return ((execstr_t *)NSS_XbyY_FINI(&arg));
}


int
_doexeclist(nss_XbyY_args_t *argp)
{
	int		status = 1;
	_priv_execattr	*_priv_exec = (_priv_execattr *)(argp->key.attrp);
	execstr_t	*exec = (execstr_t *)((argp->buf.result));

	if (_priv_exec->head_exec == NULL) {
		if (_priv_exec->head_exec = _dup_execstr(exec))
			_priv_exec->prev_exec = _priv_exec->head_exec;
		else
			status = 0;
	} else {
		if (_priv_exec->prev_exec->next = _dup_execstr(exec))
			_priv_exec->prev_exec = _priv_exec->prev_exec->next;
		else
			status = 0;
	}
	(void) memset(argp->buf.buffer, NULL, argp->buf.buflen);

	return (status);

}


/*
 * Converts id to a wildcard string. e.g.:
 *   For type = KV_COMMAND: /usr/ccs/bin/what ---> /usr/ccs/bin/\* ---> \*
 *   For type = KV_ACTION: Dtfile;*;*;*;0 ---> *;*;*;*;*
 *
 * Returns NULL if id is already a wild-card.
 */
char *
_exec_wild_id(char *id, const char *type)
{
	char	c_id = '/';
	char	*pchar = NULL;

	if ((id == NULL) || (type == NULL))
		return (NULL);

	if (strcmp(type, KV_ACTION) == 0) {
		return ((strcmp(id, KV_ACTION_WILDCARD) == 0) ? NULL :
		    KV_ACTION_WILDCARD);
	} else if (strcmp(type, KV_COMMAND) == 0) {
		if ((pchar = rindex(id, c_id)) == NULL)
			/*
			 * id = \*
			 */
			return (NULL);
		else if (*(++pchar) == KV_WILDCHAR)
			/*
			 * id = /usr/ccs/bin/\*
			 */
			return (pchar);
		/*
		 * id = /usr/ccs/bin/what
		 */
		(void) strcpy(pchar, KV_WILDCARD);
		return (id);
	}

	return (NULL);

}


execstr_t *
_dup_execstr(execstr_t *old_exec)
{
	execstr_t *new_exec = NULL;

	if (old_exec == NULL)
		return (NULL);
	if ((new_exec = malloc(sizeof (execstr_t))) != NULL) {
		new_exec->name = _strdup_null(old_exec->name);
		new_exec->type = _strdup_null(old_exec->type);
		new_exec->policy = _strdup_null(old_exec->policy);
		new_exec->res1 = _strdup_null(old_exec->res1);
		new_exec->res2 = _strdup_null(old_exec->res2);
		new_exec->id = _strdup_null(old_exec->id);
		new_exec->attr = _strdup_null(old_exec->attr);
		new_exec->next = old_exec->next;
	}
	return (new_exec);
}

void
_free_execstr(execstr_t *exec)
{
	if (exec != NULL) {
		free(exec->name);
		free(exec->type);
		free(exec->policy);
		free(exec->res1);
		free(exec->res2);
		free(exec->id);
		free(exec->attr);
		_free_execstr(exec->next);
		free(exec);
	}
}

void
_exec_cleanup(nss_status_t res, nss_XbyY_args_t *argp)
{
	_priv_execattr	*_priv_exec = (_priv_execattr *)(argp->key.attrp);

	if (res == NSS_SUCCESS) {
		if (_priv_exec->head_exec != NULL) {
			argp->buf.result = _priv_exec->head_exec;
			argp->returnval = argp->buf.result;
		}
	} else {
		if (_priv_exec->head_exec != NULL)
			_free_execstr(_priv_exec->head_exec);
		argp->returnval = NULL;
	}
}
