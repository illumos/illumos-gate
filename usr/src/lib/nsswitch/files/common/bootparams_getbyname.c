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
 *	files/bootparams_getbyname.c -- "files" backend for
 *	nsswitch "bootparams" database.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

static const char *bootparams = "/etc/bootparams";

#include "files_common.h"
#include <stdlib.h>
#include <ctype.h>
#include <strings.h>

static nss_status_t _nss_files_XY_bootparams(files_backend_ptr_t,
	nss_XbyY_args_t *, const char *);

static nss_status_t
getbyname(be, a)
	files_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	nss_status_t		res;

	/* bootparams_getbyname() has not set/endent; rewind on each call */
	if ((res = _nss_files_setent(be, 0)) != NSS_SUCCESS) {
		return (res);
	}
	return (_nss_files_XY_bootparams(be, argp, argp->key.name));
}

static files_backend_op_t bootparams_ops[] = {
	_nss_files_destr,
	getbyname
};

/*ARGSUSED*/
nss_backend_t *
_nss_files_bootparams_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_files_constr(bootparams_ops,
		sizeof (bootparams_ops) / sizeof (bootparams_ops[0]),
		bootparams,
		NSS_LINELEN_BOOTPARAMS,
		NULL));
}

/*
 * bootparams has the hostname as part of the data in the file, but the other
 * backends don't include it in the data passed to the backend.  For this
 * reason, we process everything here and don't bother calling the backend.
 */
/*ARGSUSED*/
static nss_status_t
_nss_files_XY_bootparams(be, args, filter)
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

	if (be->buf == 0 &&
		(be->buf = (char *)malloc(be->minbuf)) == 0) {
		(void) _nss_files_endent(be, 0);
		return (NSS_UNAVAIL); /* really panic, malloc failed */
	}

	res = NSS_NOTFOUND;

	/*CONSTCOND*/
	while (1) {
		char		*instr	= be->buf;
		char		*p, *host, *limit;
		int		linelen;

		/*
		 * _nss_files_read_line does process the '\' that are used
		 * in /etc/bootparams for continuation and gives one long
		 * buffer.
		 *
		 * linelen counts the characters up to but excluding the '\n'
		 */
		if ((linelen = _nss_files_read_line(be->f, instr,
		    be->minbuf)) < 0) {
			/* End of file */
			args->returnval = 0;
			args->returnlen = 0;
			break;
		}

		/*
		 * we need to strip off the host name before returning it.
		 */
		p = instr;
		limit = p + linelen;

		/* Skip over leading whitespace */
		while (p < limit && isspace(*p)) {
			p++;
		}
		host = p;

		/* Skip over the hostname */
		while (p < limit && !isspace(*p)) {
			p++;
		}
		*p++ = '\0';

		if (strcasecmp(args->key.name, host) != 0) {
			continue;
		}

		/* Skip over whitespace between name and first datum */
		while (p < limit && isspace(*p)) {
			p++;
		}
		if (p >= limit) {
			/* Syntax error -- no data! Just skip it. */
			continue;
		}

		linelen -= (p - instr);
		if (args->buf.buflen <= linelen) {	/* not enough buffer */
			args->erange = 1;
			break;
		}
		(void) memcpy(args->buf.buffer, p, linelen);
		args->buf.buffer[linelen] = '\0';
		args->returnval = args->buf.result;
		args->returnlen = linelen;
		res = NSS_SUCCESS;
		break;
	}
	(void) _nss_files_endent(be, 0);
	return (res);
}
