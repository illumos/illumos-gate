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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <nss_dbdefs.h>
#include <deflt.h>
#include <exec_attr.h>
#include <user_attr.h>
#include <auth_attr.h>
#include <prof_attr.h>
#include <getxby_door.h>
#include <sys/mman.h>


/* Externs from libnsl */
extern execstr_t *_getexecattr(execstr_t *, char *, int, int *);
extern void _setexecattr(void);
extern void _endexecattr(void);
extern execstr_t *_getexecprof(const char *, const char *, const char *, int,
    execstr_t *, char *, int, int *);
extern userstr_t *_getusernam(const char *, userstr_t *, char *, int, int *);
extern userstr_t *_getuserattr(userstr_t *, char *, int, int *);
extern char *_strtok_escape(char *, char *, char **);
extern char *_strdup_null(char *);

static execattr_t *userprof(const char *, const char *, const char *, int);
static execattr_t *get_tail(execattr_t *);
static execattr_t *execstr2attr(execstr_t *);

execattr_t *
getexecattr()
{
	int		err = 0;
	char		buf[NSS_BUFLEN_EXECATTR];
	execstr_t	exec;
	execstr_t	*tmp;

	tmp = _getexecattr(&exec, buf, NSS_BUFLEN_EXECATTR, &err);

	return (execstr2attr(tmp));
}


execattr_t *
getexecprof(const char *name, const char *type, const char *id, int search_flag)
{
	int		err = 0;
	char		unique[NSS_BUFLEN_EXECATTR];
	char		buf[NSS_BUFLEN_EXECATTR];
	execattr_t	*head = NULL;
	execattr_t	*prev = NULL;
	execstr_t	exec;
	execstr_t	*tmp;

	(void) memset(unique, 0, NSS_BUFLEN_EXECATTR);
	(void) memset(&exec, 0, sizeof (execstr_t));

	if (!IS_GET_ONE(search_flag) && !IS_GET_ALL(search_flag)) {
		return (NULL);
	}

	if ((name == NULL) && (type == NULL) && (id == NULL)) {
		setexecattr();
		if (IS_GET_ONE(search_flag)) {
			head = getexecattr();
		} else if (IS_GET_ALL(search_flag)) {
			head = getexecattr();
			prev = head;
			while (prev != NULL) {
				prev->next = getexecattr();
				prev = prev->next;
			};
		} else {
			head = NULL;
		}
		endexecattr();
		return (head);
	}

	tmp = _getexecprof(name,
	    type,
	    id,
	    search_flag,
	    &exec,
	    buf,
	    NSS_BUFLEN_EXECATTR,
	    &err);

	return (execstr2attr(tmp));
}

execattr_t *
getexecuser(const char *username, const char *type, const char *id,
    int search_flag)
{
	int		err = 0;
	char		buf[NSS_BUFLEN_USERATTR];
	userstr_t	user;
	userstr_t	*utmp;
	execattr_t	*head = NULL;
	execattr_t	*prev =  NULL;
	execattr_t	*new = NULL;

	if (!IS_GET_ONE(search_flag) && !IS_GET_ALL(search_flag)) {
		return (NULL);
	}

	if (username == NULL) {
		setuserattr();
		/* avoid userstr2attr mallocs by calling libnsl directly */
		utmp = _getuserattr(&user, buf, NSS_BUFLEN_USERATTR, &err);
		if (utmp == NULL) {
			return (head);
		}
		if (IS_GET_ONE(search_flag)) {
			head = userprof((const char *)(utmp->name), type, id,
			    search_flag);
		} else if (IS_GET_ALL(search_flag)) {
			head = userprof((const char *)(utmp->name), type, id,
			    search_flag);
			if (head != NULL) {
				prev = get_tail(head);
			}
			while ((utmp = _getuserattr(&user,
			    buf, NSS_BUFLEN_USERATTR, &err)) != NULL) {
				if ((new =
				    userprof((const char *)(utmp->name),
				    type, id, search_flag)) != NULL) {
					if (prev != NULL) {
						prev->next = new;
						prev = get_tail(prev->next);
					} else {
						head = new;
						prev = get_tail(head);
					}
				}
			}
		} else {
			head = NULL;
		}
		enduserattr();
	} else {
		head = userprof(username, type, id, search_flag);
	}

	return (head);
}


execattr_t *
match_execattr(execattr_t *exec, const char *profname, const char *type,
    const char *id)
{
	execattr_t	*execp = NULL;

	for (execp = exec; execp != NULL; execp = execp->next) {
		if ((profname && execp->name &&
		    (strcmp(profname, execp->name) != 0)) ||
		    (type && execp->type && (strcmp(type, execp->type) != 0)) ||
		    (id && execp->id && (strcmp(id, execp->id) != 0)))
			continue;
	}

	return (execp);
}


void
setexecattr()
{
	_setexecattr();
}


void
endexecattr()
{
	_endexecattr();
}


void
free_execattr(execattr_t *exec)
{
	if (exec != NULL) {
		free(exec->name);
		free(exec->type);
		free(exec->policy);
		free(exec->res1);
		free(exec->res2);
		free(exec->id);
		_kva_free(exec->attr);
		free_execattr(exec->next);
		free(exec);
	}
}

typedef struct call {
	const char	*type;
	const char	*id;
	int		sflag;
} call;

typedef struct result {
	execattr_t *head;
	execattr_t *prev;
} result;

/*ARGSUSED*/
static int
findexecattr(const char *prof, kva_t *kva, void *ctxt, void *res)
{
	execattr_t *exec;
	call *c = ctxt;
	result *r = res;

	if ((exec = getexecprof(prof, c->type, c->id, c->sflag)) != NULL) {
		if (IS_GET_ONE(c->sflag)) {
			r->head = exec;
			return (1);
		} else if (IS_GET_ALL(c->sflag)) {
			if (r->head == NULL) {
				r->head = exec;
				r->prev = get_tail(r->head);
			} else {
				r->prev->next = exec;
				r->prev = get_tail(exec);
			}
		}
	}
	return (0);
}


static execattr_t *
userprof(const char *username, const char *type, const char *id,
    int search_flag)
{

	char		pwdb[NSS_BUFLEN_PASSWD];
	struct passwd	pwd;
	call		call;
	result		result;

	/*
	 * Check if specified username is valid user
	 */
	if (getpwnam_r(username, &pwd, pwdb, sizeof (pwdb)) == NULL) {
		return (NULL);
	}

	result.head = result.prev = NULL;
	call.type = type;
	call.id = id;
	call.sflag = search_flag;

	(void) _enum_profs(username, findexecattr, &call, &result);

	return (result.head);
}


static execattr_t *
get_tail(execattr_t *exec)
{
	execattr_t *i_exec = NULL;
	execattr_t *j_exec = NULL;

	if (exec != NULL) {
		if (exec->next == NULL) {
			j_exec = exec;
		} else {
			for (i_exec = exec->next; i_exec != NULL;
			    i_exec = i_exec->next) {
				j_exec = i_exec;
			}
		}
	}

	return (j_exec);
}


static execattr_t *
execstr2attr(execstr_t *es)
{
	execattr_t	*newexec;

	if (es == NULL) {
		return (NULL);
	}
	if ((newexec = malloc(sizeof (execattr_t))) == NULL) {
		return (NULL);
	}

	newexec->name = _do_unescape(es->name);
	newexec->policy = _do_unescape(es->policy);
	newexec->type = _do_unescape(es->type);
	newexec->res1 =  _do_unescape(es->res1);
	newexec->res2 = _do_unescape(es->res2);
	newexec->id = _do_unescape(es->id);
	newexec->attr = _str2kva(es->attr, KV_ASSIGN, KV_DELIMITER);
	if (es->next) {
		newexec->next = execstr2attr((execstr_t *)(es->next));
	} else {
		newexec->next = NULL;
	}
	return (newexec);
}

#ifdef DEBUG
void
print_execattr(execattr_t *exec)
{
	extern void print_kva(kva_t *);
	char *empty = "empty";

	if (exec != NULL) {
		printf("name=%s\n", exec->name ? exec->name : empty);
		printf("policy=%s\n", exec->policy ? exec->policy : empty);
		printf("type=%s\n", exec->type ? exec->type : empty);
		printf("res1=%s\n", exec->res1 ? exec->res1 : empty);
		printf("res2=%s\n", exec->res2 ? exec->res2 : empty);
		printf("id=%s\n", exec->id ? exec->id : empty);
		printf("attr=\n");
		print_kva(exec->attr);
		fflush(stdout);
		if (exec->next) {
			print_execattr(exec->next);
		}
	} else {
		printf("NULL\n");
	}
}
#endif  /* DEBUG */
