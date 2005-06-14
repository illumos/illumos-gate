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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
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
static execstr_t *process_getexec(execstr_t *, char *, int, nsc_data_t *);

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
	int		len_unique;
	int		err = 0;
	int		ndata = 0;
	int		adata = 0;
	char		unique[NSS_BUFLEN_EXECATTR];
	char		buf[NSS_BUFLEN_EXECATTR];
	execattr_t	*head = (execattr_t *)NULL;
	execattr_t	*prev = (execattr_t *)NULL;
	execstr_t	exec;
	execstr_t	*tmp;
	execstr_t	*resptr = (execstr_t *)NULL;
	nsc_data_t	*sptr = (nsc_data_t *)NULL;
	union {
		nsc_data_t 	s_d;
		char		s_b[NSS_BUFLEN_EXECATTR];
	} space;

	(void) memset(unique, 0, NSS_BUFLEN_EXECATTR);
	(void) memset(&exec, 0, sizeof (execstr_t));
	(void) memset(&space, 0, sizeof (space));

	if ((search_flag != GET_ONE) && (search_flag != GET_ALL)) {
		return ((execattr_t *)NULL);
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
			head = (execattr_t *)NULL;
			break;
		}
		endexecattr();
		return (head);
	}

#ifdef PIC
	/*
	 * If the search criteria is completely specified
	 * and we only want a single entry,
	 * then attempt to look up the entry using the nscd.
	 * Only commands are cached.
	 */
	if (name && type && (strcmp(type, KV_COMMAND) == 0) && id &&
	    (search_flag == GET_ONE)) {
		if (snprintf(unique, NSS_BUFLEN_EXECATTR, "%s:%s:%s",
		    name, type, id) >= NSS_BUFLEN_EXECATTR) {
			errno = ERANGE;
			return ((execattr_t *)NULL);
		}
		len_unique = strlen(unique);
		if ((len_unique >= (sizeof (space) - sizeof (nsc_data_t)))) {
			errno = ERANGE;
			return ((execattr_t *)NULL);
		}
		ndata = sizeof (space);
		adata = len_unique + sizeof (nsc_call_t) + 1;
		space.s_d.nsc_call.nsc_callnumber = GETEXECID;
		(void) strcpy(space.s_d.nsc_call.nsc_u.name, unique);
		sptr = &space.s_d;

		switch (_nsc_trydoorcall(&sptr, &ndata, &adata)) {
		case SUCCESS:	/* positive cache hit */
			break;
		case NOTFOUND:	/* negative cache hit */
			return ((execattr_t *)NULL);
		default:
			resptr = _getexecprof(name, type, id, search_flag,
			    &exec, buf, NSS_BUFLEN_EXECATTR, &err);
			return (execstr2attr(resptr));
		}
		resptr = process_getexec(&exec, buf, NSS_BUFLEN_EXECATTR,
		    sptr);

		/*
		 * check if doors reallocated the memory underneath us
		 * if they did munmap it or suffer a memory leak
		 */
		if (sptr != &space.s_d)
			(void) munmap((void *)sptr, ndata);

		return (execstr2attr(resptr));
	} /* end if (name && type && id && search_flag == GET_ONE) */
#endif	/* PIC */

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
	execattr_t	*head = (execattr_t *)NULL;
	execattr_t	*prev = (execattr_t *)NULL;
	execattr_t	*new = (execattr_t *)NULL;

	if ((search_flag != GET_ONE) && (search_flag != GET_ALL)) {
		return ((execattr_t *)NULL);
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
			head = (execattr_t *)NULL;
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
	execattr_t	*execp = (execattr_t *)NULL;

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
	if (exec != (execattr_t *)NULL) {
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
	char		*proflist = (char *)NULL;
	char		*profname = (char *)NULL;
	char		buf[NSS_BUFLEN_USERATTR];
	char		pwdb[NSS_BUFLEN_PASSWD];
	kva_t		*user_attr;
	userstr_t	user;
	userstr_t	*utmp;
	execattr_t	*exec;
	execattr_t	*head = (execattr_t *)NULL;
	execattr_t	*prev = (execattr_t *)NULL;
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
		proflist = NULL;
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
	if (defopen(AUTH_POLICY) == NULL) {
		proflist = defread(DEF_PROF);
		(void) defopen(NULL);
	}
	if (proflist != NULL) {
		for (profname = _strtok_escape(proflist, sep, &last);
		    profname != NULL;
		    profname = _strtok_escape(NULL, sep, &last)) {
			getproflist(profname, profArray, &profcnt);
		}
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
	execattr_t *i_exec = (execattr_t *)NULL;
	execattr_t *j_exec = (execattr_t *)NULL;

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
		return ((execattr_t *)NULL);
	}
	if ((newexec = (execattr_t *)malloc(sizeof (execattr_t))) == NULL) {
		return ((execattr_t *)NULL);
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
		newexec->next = (execattr_t *)NULL;
	}
	return (newexec);
}


static execstr_t *
process_getexec(
	execstr_t *result,
	char *buffer,
	int buflen,
	nsc_data_t *sptr)
{
	char *fixed;
#ifdef	_LP64
	execstr_t exec64;

	fixed = (char *)(((uintptr_t)buffer + 7) & ~7);
#else
	fixed = (char *)(((uintptr_t)buffer + 3) & ~3);
#endif
	buflen -= fixed - buffer;
	buffer = fixed;

	if (sptr->nsc_ret.nsc_return_code != SUCCESS)
		return ((execstr_t *)NULL);

#ifdef	_LP64
	if (sptr->nsc_ret.nsc_bufferbytesused - (int)sizeof (execstr32_t)
	    > buflen)
#else
	if (sptr->nsc_ret.nsc_bufferbytesused - (int)sizeof (execstr_t)
	    > buflen)
#endif
	{
		errno = ERANGE;
		return ((execstr_t *)NULL);
	}

#ifdef	_LP64
	(void) memcpy(buffer, (sptr->nsc_ret.nsc_u.buff + sizeof (execstr32_t)),
	    (sptr->nsc_ret.nsc_bufferbytesused - sizeof (execstr32_t)));
	exec64.name = (char *)(sptr->nsc_ret.nsc_u.exec.name +
	    (uintptr_t)buffer);
	exec64.type = (char *)(sptr->nsc_ret.nsc_u.exec.type +
	    (uintptr_t)buffer);
	exec64.policy = (char *)(sptr->nsc_ret.nsc_u.exec.policy +
	    (uintptr_t)buffer);
	exec64.res1 = (char *)(sptr->nsc_ret.nsc_u.exec.res1 +
	    (uintptr_t)buffer);
	exec64.res2 = (char *)(sptr->nsc_ret.nsc_u.exec.res2 +
	    (uintptr_t)buffer);
	exec64.id = (char *)(sptr->nsc_ret.nsc_u.exec.id +
	    (uintptr_t)buffer);
	exec64.attr = (char *)(sptr->nsc_ret.nsc_u.exec.attr +
	    (uintptr_t)buffer);
	exec64.next = (execstr_t *)NULL;
	*result = exec64;
#else
	sptr->nsc_ret.nsc_u.exec.name += (uintptr_t)buffer;
	sptr->nsc_ret.nsc_u.exec.type += (uintptr_t)buffer;
	sptr->nsc_ret.nsc_u.exec.policy += (uintptr_t)buffer;
	sptr->nsc_ret.nsc_u.exec.res1 += (uintptr_t)buffer;
	sptr->nsc_ret.nsc_u.exec.res2 += (uintptr_t)buffer;
	sptr->nsc_ret.nsc_u.exec.id += (uintptr_t)buffer;
	sptr->nsc_ret.nsc_u.exec.attr += (uintptr_t)buffer;
	sptr->nsc_ret.nsc_u.exec.next = (execstr_t *)NULL;
	*result = sptr->nsc_ret.nsc_u.exec;
	(void) memcpy(buffer, (sptr->nsc_ret.nsc_u.buff + sizeof (execstr_t)),
	    (sptr->nsc_ret.nsc_bufferbytesused - sizeof (execstr_t)));
#endif
	return (result);
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
