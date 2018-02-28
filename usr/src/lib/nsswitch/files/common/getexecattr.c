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
 * Copyright (c) 2017, Joyent, Inc.
 */

#include <stdlib.h>
#include "files_common.h"
#include <time.h>
#include <exec_attr.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <ctype.h>
#include <synch.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

/*
 * files/getexecattr.c -- "files" backend for nsswitch "exec_attr" database
 *
 * _execattr_files_read_line and _execattr_files_XY_all code based on
 * nss_files_read_line and nss_files_XY_all respectively, from files_common.c
 */


/* externs from libnsl */
extern int _doexeclist(nss_XbyY_args_t *);
extern int _readbufline(char *, int, char *, int, int *);
extern char *_exec_wild_id(char *, const char *);
extern void _exec_cleanup(nss_status_t, nss_XbyY_args_t *);

/*
 * _exec_files_XY_all wants to cache data from the attribute file.
 */
static char *exec_f_buf;
static time_t exec_read_time;

void
getexecattr_fini(void)
{
	free(exec_f_buf);
	exec_f_buf = NULL;
}


/*
 * check_match: returns 1 if matching entry found, else returns 0.
 */
static int
check_match(nss_XbyY_args_t *argp, const char *line, int linelen)
{
	const char	*limit, *linep, *keyp;
	_priv_execattr	*_priv_exec = (_priv_execattr *)(argp->key.attrp);
	const char	*exec_field[6];
	int		i;

	exec_field[0] = _priv_exec->name;	/* name */
	exec_field[1] = _priv_exec->policy;	/* policy */
	exec_field[2] = _priv_exec->type;	/* type */
	exec_field[3] = NULL;			/* res1 */
	exec_field[4] = NULL;			/* res2 */
	exec_field[5] = _priv_exec->id;		/* id */
	/* No need to check attr field */

	linep = line;
	limit = line + linelen;

	for (i = 0; i < 6; i++) {
		keyp = exec_field[i];
		if (keyp) {
			/* compare field */
			while (*keyp && linep < limit &&
			    *linep != ':' && *keyp == *linep) {
				keyp++;
				linep++;
			}
			if (*keyp || linep == limit || *linep != ':')
				return (0);
		} else {
			/* skip field */
			while (linep < limit && *linep != ':')
				linep++;
		}
		linep++;
	}
	return (1);
}


static nss_status_t
_exec_files_XY_all(files_backend_ptr_t be,
    nss_XbyY_args_t *argp,
    int getby_flag)
{
	int		parse_stat = 0;
	int		lastlen = 0;
	int		exec_fd = 0;
	int		f_size = 0;
	time_t		f_time = 0;
	char		*first;
	char		*last;
	struct stat	f_stat;
	nss_status_t	res = NSS_NOTFOUND;
	_priv_execattr	*_priv_exec = (_priv_execattr *)(argp->key.attrp);
	static rwlock_t	exec_lock;

	if (((be->buf == NULL) &&
	    ((be->buf = (char *)calloc(1, be->minbuf)) == NULL)) ||
	    (be->filename == NULL) ||
	    (rw_rdlock(&exec_lock) != 0)) {
		return (NSS_UNAVAIL);
	}

	/*
	 * check the size and the time stamp on the file
	 */
	if (stat(be->filename, &f_stat) != 0) {
		(void) _nss_files_endent(be, 0);
		(void) rw_unlock(&exec_lock);
		return (NSS_UNAVAIL);
	}

	f_size = f_stat.st_size;
	f_time = f_stat.st_mtime;

	while (f_time > exec_read_time || exec_f_buf == NULL) {
		/*
		 * file has been modified since we last read it
		 * or we never read it or memory allocation
		 * failed before.
		 * read it into the buffer with rw lock.
		 */
		(void) rw_unlock(&exec_lock);
		if (rw_wrlock(&exec_lock) != 0) {
			(void) _nss_files_endent(be, 0);
			return (NSS_UNAVAIL);
		}
		if ((be->f = fopen(be->filename, "rF")) == 0) {
			(void) _nss_files_endent(be, 0);
			(void) rw_unlock(&exec_lock);
			return (NSS_UNAVAIL);
		}
		exec_fd = fileno(be->f);
		if (exec_f_buf != NULL)
			free(exec_f_buf);
		if ((exec_f_buf = malloc(f_size)) == NULL) {
			(void) _nss_files_endent(be, 0);
			(void) rw_unlock(&exec_lock);
			return (NSS_UNAVAIL);
		}
		if (read(exec_fd, exec_f_buf, f_size) < f_size) {
			free(exec_f_buf);
			exec_f_buf = NULL;
			(void) _nss_files_endent(be, 0);
			(void) rw_unlock(&exec_lock);
			return (NSS_UNAVAIL);
		}
		exec_read_time = f_time;
		(void) rw_unlock(&exec_lock);
		/*
		 * verify that the file did not change after
		 * we read it.
		 */
		if (rw_rdlock(&exec_lock) != 0) {
			free(exec_f_buf);
			exec_f_buf = NULL;
			(void) _nss_files_endent(be, 0);
			return (NSS_UNAVAIL);
		}
		if (stat(be->filename, &f_stat) != 0) {
			free(exec_f_buf);
			exec_f_buf = NULL;
			(void) _nss_files_endent(be, 0);
			(void) rw_unlock(&exec_lock);
			return (NSS_UNAVAIL);
		}
		f_size = f_stat.st_size;
		f_time = f_stat.st_mtime;
	}

	res = NSS_NOTFOUND;
	/*CONSTCOND*/
	while (1) {
		int	linelen = 0;
		char	*instr = be->buf;

		linelen = _readbufline(exec_f_buf, f_size, instr, be->minbuf,
		    &lastlen);
		if (linelen < 0) {
			/* End of file */
			break;
		}

		/*
		 * If the entry doesn't contain the filter string then
		 * it can't be the entry we want, so don't bother looking
		 * more closely at it.
		 */
		switch (getby_flag) {
		case NSS_DBOP_EXECATTR_BYNAME:
			if (strstr(instr, _priv_exec->name) == NULL)
				continue;
			break;
		case NSS_DBOP_EXECATTR_BYID:
			if (strstr(instr, _priv_exec->id) == NULL)
				continue;
			break;
		case NSS_DBOP_EXECATTR_BYNAMEID:
			if ((strstr(instr, _priv_exec->name) == NULL) ||
			    (strstr(instr, _priv_exec->id) == NULL))
				continue;
			break;
		default:
			break;
		}
		if (((_priv_exec->policy != NULL) &&
		    (strstr(instr, _priv_exec->policy) == NULL)) ||
		    ((_priv_exec->type != NULL) &&
		    (strstr(instr, _priv_exec->type) == NULL)))
				continue;

		/*
		 * Get rid of white spaces, comments etc.
		 */
		if ((last = strchr(instr, '#')) == NULL)
			last = instr + linelen;
		*last-- = '\0';	/* Nuke '\n' or #comment */
		/*
		 * Skip leading whitespace.  Normally there isn't any,
		 * so it's not worth calling strspn().
		 */
		for (first = instr; isspace(*first); first++)
			;
		if (*first == '\0')
			continue;
		/*
		 * Found something non-blank on the line.  Skip back
		 * over any trailing whitespace;  since we know there's
		 * non-whitespace earlier in the line, checking for
		 * termination is easy.
		 */
		while (isspace(*last))
			--last;
		linelen = last - first + 1;
		if (first != instr)
			instr = first;

		/* Check the entry */
		argp->returnval = NULL;
		argp->returnlen = 0;
		if (check_match(argp, instr, linelen) == 0)
			continue;

		/* Marshall the data */
		parse_stat = (*argp->str2ent)(instr, linelen, argp->buf.result,
		    argp->buf.buffer, argp->buf.buflen);
		if (parse_stat == NSS_STR_PARSE_SUCCESS) {
			argp->returnval = (argp->buf.result != NULL)?
			    argp->buf.result : argp->buf.buffer;
			argp->returnlen = linelen;
			res = NSS_SUCCESS;
			if (IS_GET_ONE(_priv_exec->search_flag)) {
				break;
			} else if (_doexeclist(argp) == 0) {
				res = NSS_UNAVAIL;
				break;
			}
		} else if (parse_stat == NSS_STR_PARSE_ERANGE) {
			argp->erange = 1;
			break;
		} /* else if (parse_stat == NSS_STR_PARSE_PARSE) don't care ! */
	}

	(void) _nss_files_endent(be, 0);
	(void) rw_unlock(&exec_lock);

	return (res);
}


/*
 * If search for exact match for id failed, get_wild checks if we have
 * a wild-card entry for that id.
 */
static nss_status_t
get_wild(files_backend_ptr_t be, nss_XbyY_args_t *argp, int getby_flag)
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
		res = _exec_files_XY_all(be, argp, getby_flag);
		if (res == NSS_SUCCESS)
			break;
	}
	_priv_exec->id = orig_id;
	if (old_id)
		free(old_id);

	return (res);
}


static nss_status_t
getbynam(files_backend_ptr_t be, void *a)
{
	nss_status_t	res;
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;

	res =  _exec_files_XY_all(be, argp, NSS_DBOP_EXECATTR_BYNAME);

	_exec_cleanup(res, argp);

	return (res);
}


static nss_status_t
getbyid(files_backend_ptr_t be, void *a)
{
	nss_status_t	res;
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	/*LINTED*/
	_priv_execattr	*_priv_exec = (_priv_execattr *)(argp->key.attrp);

	res = _exec_files_XY_all(be, argp, NSS_DBOP_EXECATTR_BYID);

	if (res != NSS_SUCCESS)
		res = get_wild(be, argp, NSS_DBOP_EXECATTR_BYID);

	_exec_cleanup(res, argp);

	return (res);
}


static nss_status_t
getbynameid(files_backend_ptr_t be, void *a)
{
	nss_status_t	res;
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	/*LINTED*/
	_priv_execattr	*_priv_exec = (_priv_execattr *)(argp->key.attrp);

	res = _exec_files_XY_all(be, argp, NSS_DBOP_EXECATTR_BYNAMEID);

	if (res != NSS_SUCCESS)
		res = get_wild(be, argp, NSS_DBOP_EXECATTR_BYNAMEID);

	_exec_cleanup(res, argp);

	return (res);
}


static files_backend_op_t execattr_ops[] = {
	_nss_files_destr,
	_nss_files_endent,
	_nss_files_setent,
	_nss_files_getent_netdb,
	getbynam,
	getbyid,
	getbynameid
};

/*ARGSUSED*/
nss_backend_t  *
_nss_files_exec_attr_constr(const char *dummy1,
    const char *dummy2,
    const char *dummy3,
    const char *dummy4,
    const char *dummy5,
    const char *dummy6,
    const char *dummy7)
{
	return (_nss_files_constr(execattr_ops,
	    sizeof (execattr_ops)/sizeof (execattr_ops[0]),
	    EXECATTR_FILENAME, NSS_LINELEN_EXECATTR, NULL));
}
