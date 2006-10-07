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
 *	files/printers_getbyname.c -- "files" backend for
 *	nsswitch "printers" database.
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

static const char *printers = "/etc/printers.conf";

#pragma weak _nss_files__printers_constr = _nss_files_printers_constr

#include "files_common.h"
#include <stdlib.h>
#include <strings.h>
#include <ctype.h>

static int
check_name(nss_XbyY_args_t *argp, const char *line, int linelen)
{

	const char	*limit, *linep;
	const char	*keyp = argp->key.name;
	int		klen = strlen(keyp);

	linep = line;
	limit = line + linelen;

	/*
	 * find the name in the namelist a|b|c...:
	 */
	while (linep+klen < limit && *linep != '|' && *linep != ':') {
		if ((strncmp(linep, keyp, klen) == 0) &&
		    ((*(linep + klen) == '|') || (*(linep + klen) == ':'))) {
			return (1);
		} else {
			while (linep < limit && *linep != '|' && *linep != ':')
				linep++;
			if (linep >= limit || *linep == ':')
				return (0);
			if (*linep == '|')
				linep++;
		}
	}
	return (0);
}

nss_status_t
_nss_files_XY_printer(be, args, filter, check)
	files_backend_ptr_t	be;
	nss_XbyY_args_t		*args;
	const char		*filter;	/* advisory, to speed up */
						/* string search */
	files_XY_check_func	check;	/* NULL means one-shot, for getXXent */
{
	nss_status_t		res;
	int	parsestat;
	int (*func)();

	if (filter != NULL && *filter == '\0')
		return (NSS_NOTFOUND);
	if (be->buf == 0 &&
		(be->buf = malloc(be->minbuf)) == 0) {
		return (NSS_UNAVAIL); /* really panic, malloc failed */
	}

	if (check != 0 || be->f == 0) {
		if ((res = _nss_files_setent(be, 0)) != NSS_SUCCESS) {
			return (res);
		}
	}

	res = NSS_NOTFOUND;

	/*CONSTCOND*/
	while (1) {
		char		*instr	= be->buf;
		int		linelen;

		if ((linelen = _nss_files_read_line(be->f, instr,
		    be->minbuf)) < 0) {
			/* End of file */
			args->returnval = 0;
			args->returnlen = 0;
			break;
		}

		/* begin at the first non-blank character */
		while (isspace(*instr)) {
			instr++;
			linelen--;
		}

		/* comment line, skip it. */
		if (*instr == '#')
			continue;

		/* blank line, skip it */
		if ((*instr == '\n') || (*instr == '\0'))
			continue;

		if (filter != 0 && strstr(instr, filter) == 0) {
			/*
			 * Optimization:  if the entry doesn't contain the
			 *   filter string then it can't be the entry we want,
			 *   so don't bother looking more closely at it.
			 */
			continue;
		}

		args->returnval = 0;
		args->returnlen = 0;

		if (check != NULL && (*check)(args, instr, linelen) == 0)
			continue;

		func = args->str2ent;
		parsestat = (*func)(instr, linelen, args->buf.result,
					args->buf.buffer, args->buf.buflen);

		if (parsestat == NSS_STR_PARSE_SUCCESS) {
			args->returnval = (args->buf.result != NULL)?
					args->buf.result : args->buf.buffer;
			args->returnlen = linelen;
			res = NSS_SUCCESS;
			break;
		} else if (parsestat == NSS_STR_PARSE_ERANGE) {
			args->erange = 1;
			break;
		} else if (parsestat == NSS_STR_PARSE_PARSE)
			continue;
	}

	/*
	 * stayopen is set to 0 by default in order to close the opened
	 * file.  Some applications may break if it is set to 1.
	 */
	if (check != 0 && !args->stayopen) {
		(void) _nss_files_endent(be, 0);
	}

	return (res);
}

static nss_status_t
getent(be, a)
	files_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;

	return (_nss_files_XY_printer(be, argp, (const char *)0,
					(files_XY_check_func)0));
}

static nss_status_t
getbyname(be, a)
	files_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;

	return (_nss_files_XY_printer(be, argp, argp->key.name, check_name));
}

static files_backend_op_t printers_ops[] = {
	_nss_files_destr,
	_nss_files_endent,
	_nss_files_setent,
	getent,
	getbyname
};

/*ARGSUSED*/
nss_backend_t *
_nss_files_printers_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_files_constr(printers_ops,
			sizeof (printers_ops) / sizeof (printers_ops[0]),
			printers,
			NSS_LINELEN_PRINTERS,
			NULL));
}
