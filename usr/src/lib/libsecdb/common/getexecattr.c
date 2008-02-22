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

	if ((search_flag != GET_ONE) && (search_flag != GET_ALL)) {
		return (NULL);
	}

	if ((name == NULL) && (type == NULL) && (id == NULL)) {
		setexecattr();
		switch (search_flag) {
		case GET_ONE:
			head = getexecattr();
			break;
		case GET_ALL:
			head = getexecattr();
			prev = head;
			while (prev != NULL) {
				prev->next = getexecattr();
				prev = prev->next;
			};
			break;
		default:
			head = NULL;
			break;
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

	if ((search_flag != GET_ONE) && (search_flag != GET_ALL)) {
		return (NULL);
	}

	if (username == NULL) {
		setuserattr();
		/* avoid userstr2attr mallocs by calling libnsl directly */
		utmp = _getuserattr(&user, buf, NSS_BUFLEN_USERATTR, &err);
		if (utmp == NULL) {
			return (head);
		}
		switch (search_flag) {
		case GET_ONE:
			head = userprof((const char *)(utmp->name), type, id,
			    search_flag);
			break;
		case GET_ALL:
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
			break;
		default:
			head = NULL;
			break;
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


static execattr_t *
userprof(const char *username, const char *type, const char *id,
    int search_flag)
{

	int		err = 0;
	char		*last;
	char		*sep = ",";
	char		*proflist = NULL;
	char		*profname = NULL;
	char		buf[NSS_BUFLEN_USERATTR];
	char		pwdb[NSS_BUFLEN_PASSWD];
	kva_t		*user_attr;
	userstr_t	user;
	userstr_t	*utmp;
	execattr_t	*exec;
	execattr_t	*head = NULL;
	execattr_t	*prev = NULL;
	struct passwd	pwd;

	char		*profArray[MAXPROFS];
	int		profcnt = 0;
	int		i;

	/*
	 * Check if specified username is valid user
	 */
	if (getpwnam_r(username, &pwd, pwdb, sizeof (pwdb)) == NULL) {
		return (head);
	}

	utmp = _getusernam(username, &user, buf, NSS_BUFLEN_USERATTR, &err);
	if (utmp != NULL) {
		user_attr = _str2kva(user.attr, KV_ASSIGN, KV_DELIMITER);
		if ((proflist = kva_match(user_attr, "profiles")) != NULL) {
			/* Get the list of profiles for this user */
			for (profname = _strtok_escape(proflist, sep, &last);
			    profname != NULL;
			    profname = _strtok_escape(NULL, sep, &last)) {
				getproflist(profname, profArray, &profcnt);
			}
		}
	}

	/* Get the list of default profiles */
	proflist = NULL;
	(void) _get_user_defs(username, NULL, &proflist);
	if (proflist != NULL) {
		for (profname = _strtok_escape(proflist, sep, &last);
		    profname != NULL;
		    profname = _strtok_escape(NULL, sep, &last)) {
			getproflist(profname, profArray, &profcnt);
		}
		_free_user_defs(NULL, proflist);
	}

	if (profcnt == 0) {
		return (head);
	}

	/* Get execs from the list of profiles */
	for (i = 0; i < profcnt; i++) {
		profname = profArray[i];
		if ((exec = getexecprof(profname, type, id, search_flag)) !=
		    NULL) {
			if (search_flag == GET_ONE) {
				head = exec;
				break;
			} else if (search_flag == GET_ALL) {
				if (head == NULL) {
					head = exec;
					prev = get_tail(head);
				} else {
					prev->next = exec;
					prev = get_tail(exec);
				}
			}
		}
	}
	free_proflist(profArray, profcnt);
	return (head);
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
