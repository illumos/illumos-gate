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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * "user" backend for nsswitch "printers" database.  This module implements
 * the ${HOME}/.printers naming support.  This file provides users with a
 * convenient method of aliasing and specifying an interest list.
 */

#pragma weak _nss_user__printers_constr = _nss_user_printers_constr

#include <nss_dbdefs.h>
#include "user_common.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

static nss_status_t
_nss_user_printers_convert(char *entry, nss_XbyY_args_t *args)
{
	nss_status_t		res = NSS_NOTFOUND;
	char 			*namelist = entry;
	char			*key = NULL;
	char			*value = NULL;
	int			length = 0;

	if ((value = strpbrk(entry, "\t ")) != NULL) {
		*value = '\0';
		value++;

		while ((*value != '\0') && (isspace(*value) != 0))
			value++;

		if ((key = strpbrk(value, "\n\t ")) != NULL)
			*key = '\0';
	}

	args->buf.buffer[0] = '\0';
	if ((value == NULL) || (*value == '\0')) {	/* bad value */
		args->erange = 1;
		return (res);
	}

	if (strcmp(namelist, "_all") == 0)
		key = "all";
	else
		key = "use";

	length = snprintf(args->buf.buffer, args->buf.buflen, "%s:%s=",
			namelist, key);

	/* append the value  ':' must be escaped for posix style names */
	while ((length < args->buf.buflen) && (*value != '\0')) {
		if (*value == ':')
			args->buf.buffer[length++] = '\\';
		args->buf.buffer[length++] = *value++;
	}

	if (length >= args->buf.buflen) {	/* the value was too big */
		args->erange = 1;
		return (res);
	}

	args->buf.buffer[length] = '\0';	/* terminate, just in case */
	args->returnval = args->buf.result;
	res = NSS_SUCCESS;

	return (res);
}

/*
 * printers has the hostname as part of the data in the file, but the other
 * backends don't include it in the data passed to the backend.  For this
 * reason, we process everything here and don't bother calling the backend.
 */
/*ARGSUSED*/
static nss_status_t
_nss_user_XY_printers(be, args, filter)
	user_backend_ptr_t	be;
	nss_XbyY_args_t		*args;
	const char		*filter;
			/*
			 * filter not useful here since the key
			 * we are looking for is the first "word"
			 * on the line and we can be fast enough.
			 */
{
	nss_status_t		res;
	int namelen;

	if (be->buf == 0 &&
		(be->buf = (char *)malloc(be->minbuf)) == 0) {
		(void) _nss_user_endent(be, 0);
		return (NSS_UNAVAIL); /* really panic, malloc failed */
	}

	res = NSS_NOTFOUND;
	namelen = strlen(args->key.name);

	/*CONSTCOND*/
	while (1) {
		char		*instr	= be->buf;
		char		*p, *limit;
		int		linelen;
		int		found = 0;

		/*
		 * _nss_user_read_line does process the '\' that are used
		 * in /etc/printers.conf for continuation and gives one long
		 * buffer.
		 *
		 * linelen counts the characters up to but excluding the '\n'
		 */
		if ((linelen = _nss_user_read_line(be->f, instr,
		    be->minbuf)) < 0) {
			/* End of file */
			args->returnval = 0;
			args->erange    = 0;
			break;
		}
		p = instr;

		if (*p == '#')					/* comment */
			continue;

		/*
		 * find the name in the namelist a|b|c...:
		 */
		if ((limit = strpbrk(instr, "\t ")) == NULL)	/* bad line */
			continue;
		while ((p < limit) && (found == 0)) {
			if ((strncmp(p, args->key.name, namelen) == 0) &&
			    ((*(p+namelen) == '|') ||
			    (isspace(*(p+namelen)) != 0)))
				found++;
			else {
				if ((p = strchr(p, '|')) == NULL)
					p = limit;
				else	/* skip the '|' */
					p++;
			}
		}
		if (found == 0)
			continue;

		if ((res = _nss_user_printers_convert(be->buf, args))
		    == NSS_SUCCESS)
			break;
	}
	(void) _nss_user_endent(be, 0);
	return (res);
}

static nss_status_t
getent(be, a)
	user_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*args = (nss_XbyY_args_t *)a;
	nss_status_t		res = NSS_UNAVAIL;

	if (be->buf == 0 &&
		(be->buf = (char *)malloc(be->minbuf)) == 0) {
		return (NSS_UNAVAIL); /* really panic, malloc failed */
	}

	if (be->f == 0) {
		if ((res = _nss_user_setent(be, 0)) != NSS_SUCCESS) {
			return (res);
		}
	}

	res = NSS_NOTFOUND;

	/*CONSTCOND*/
	while (1) {
		char	*instr  = be->buf;
		int	linelen;

		if ((linelen = _nss_user_read_line(be->f, instr,
		    be->minbuf)) < 0) {
			/* End of file */
			args->returnval = 0;
			args->erange    = 0;
			break;
		}

		if (*(be->buf) == '#')				/* comment */
			continue;

		if ((res = _nss_user_printers_convert(be->buf, args))
		    == NSS_SUCCESS)
			break;
	}
	return (res);
}


static nss_status_t
getbyname(be, a)
	user_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	nss_status_t		res;

	/* printers_getbyname() has not set/endent; rewind on each call */
	if ((res = _nss_user_setent(be, 0)) != NSS_SUCCESS) {
		return (res);
	}
	return (_nss_user_XY_printers(be, argp, argp->key.name));
}

static user_backend_op_t printers_ops[] = {
	_nss_user_destr,
	_nss_user_endent,
	_nss_user_setent,
	getent,
	getbyname
};

/*ARGSUSED*/
nss_backend_t *
_nss_user_printers_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	char path[MAXPATHLEN], *home;

	if ((home = getenv("HOME")) == NULL)
		home = "";
	(void) snprintf(path, sizeof (path), "%s/.printers", home);

	return (_nss_user_constr(printers_ops,
		sizeof (printers_ops) / sizeof (printers_ops[0]),
		path, NSS_LINELEN_PRINTERS));
}
