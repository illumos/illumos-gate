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

static nss_status_t _nss_files_XY_printers(files_backend_ptr_t,
	nss_XbyY_args_t *, const char *);


static nss_status_t
getent(be, a)
	files_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t	 *args = (nss_XbyY_args_t *)a;

	return (_nss_files_XY_all(be, args, 0, 0, 0));
}


static nss_status_t
getbyname(be, a)
	files_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	nss_status_t		res;

	/* printers_getbyname() has not set/endent; rewind on each call */
	if ((res = _nss_files_setent(be, 0)) != NSS_SUCCESS) {
		return (res);
	}
	return (_nss_files_XY_printers(be, argp, argp->key.name));
}

static files_backend_op_t printers_ops[] = {
	_nss_files_destr,
	_nss_files_endent,
	_nss_files_setent,
	getent,
	getbyname
};

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

/*
 * printers has the hostname as part of the data in the file, but the other
 * backends don't include it in the data passed to the backend.  For this
 * reason, we process everything here and don't bother calling the backend.
 */
static nss_status_t
_nss_files_XY_printers(be, args, filter)
	files_backend_ptr_t	be;
	nss_XbyY_args_t		*args;
	const char		*filter;
			/*
			 * filter not useful here since the key
			 * we are looking for is the first "word"
			 * on the line and we can be fast enough.
			 */
{
	nss_status_t		res;
	int	parsestat;
	int namelen;

	if (be->buf == 0 &&
		(be->buf = (char *)malloc(be->minbuf)) == 0) {
		(void) _nss_files_endent(be, 0);
		return (NSS_UNAVAIL); /* really panic, malloc failed */
	}

	res = NSS_NOTFOUND;
	namelen = strlen(args->key.name);

	while (1) {
		char		*instr	= be->buf;
		char		*p, *limit;
		int		linelen;
		int		found = 0;

		/*
		 * _nss_files_read_line does process the '\' that are used
		 * in /etc/printers.conf for continuation and gives one long
		 * buffer.
		 *
		 * linelen counts the characters up to but excluding the '\n'
		 */
		if ((linelen = _nss_files_read_line(be->f, instr,
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
		if ((limit = strchr(instr, ':')) == NULL)	/* bad line */
			continue;
		while ((p < limit) && (found == 0)) {
			if ((strncmp(p, args->key.name, namelen) == 0) &&
			    ((*(p+namelen) == '|') || (*(p+namelen) == ':')))
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

		p = instr;

		if (args->buf.buflen <= linelen) {	/* not enough buffer */
			args->erange = 1;
			break;
		}
		(void) memcpy(args->buf.buffer, p, linelen);
		args->buf.buffer[linelen] = '\0';
		args->returnval = args->buf.result;
		res = NSS_SUCCESS;
		break;
	}
	(void) _nss_files_endent(be, 0);
	return (res);
}
