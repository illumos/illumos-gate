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
 * Common code and structures used by name-service-switch "user" backends.
 * Much of this was taken directly from the files_common.c source.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * An implementation that used mmap() sensibly would be a wonderful thing,
 *   but this here is just yer standard fgets() thang.
 */

#include "user_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>

/*ARGSUSED*/
nss_status_t
_nss_user_setent(be, dummy)
	user_backend_ptr_t	be;
	void			*dummy;
{
	if (be->f == 0) {
		if (be->filename == 0) {
			/* Backend isn't initialized properly? */
			return (NSS_UNAVAIL);
		}
		if ((be->f = fopen(be->filename, "rF")) == 0) {
			return (NSS_UNAVAIL);
		}
	} else {
		rewind(be->f);
	}
	return (NSS_SUCCESS);
}

/*ARGSUSED*/
nss_status_t
_nss_user_endent(be, dummy)
	user_backend_ptr_t	be;
	void			*dummy;
{
	if (be->f != 0) {
		(void) fclose(be->f);
		be->f = 0;
	}
	if (be->buf != 0) {
		free(be->buf);
		be->buf = 0;
	}
	return (NSS_SUCCESS);
}

/*
 * This routine reads a line, including the processing of continuation
 * characters.  It always leaves (or inserts) \n\0 at the end of the line.
 * It returns the length of the line read, excluding the \n\0.  Who's idea
 * was this?
 * Returns -1 on EOF.
 *
 * Note that since each concurrent call to _nss_user_read_line has
 * it's own FILE pointer, we can use getc_unlocked w/o difficulties,
 * a substantial performance win.
 */
int
_nss_user_read_line(f, buffer, buflen)
	FILE			*f;
	char			*buffer;
	int			buflen;
{
	int			linelen;	/* 1st unused slot in buffer */
	int			c;

	/*CONSTCOND*/
	while (1) {
		linelen = 0;
		while (linelen < buflen - 1) {	/* "- 1" saves room for \n\0 */
			switch (c = getc_unlocked(f)) {
			case EOF:
				if (linelen == 0 ||
				    buffer[linelen - 1] == '\\') {
					return (-1);
				} else {
					buffer[linelen    ] = '\n';
					buffer[linelen + 1] = '\0';
					return (linelen);
				}
			case '\n':
				if (linelen > 0 &&
				    buffer[linelen - 1] == '\\') {
					--linelen;  /* remove the '\\' */
				} else {
					buffer[linelen    ] = '\n';
					buffer[linelen + 1] = '\0';
					return (linelen);
				}
				break;
			default:
				buffer[linelen++] = c;
			}
		}
		/* Buffer overflow -- eat rest of line and loop again */
		/* ===> Should syslog() */
		do {
			c = getc_unlocked(f);
			if (c == EOF) {
				return (-1);
			}
		} while (c != '\n');
	}
	/*NOTREACHED*/
}


/*
 * Could implement this as an iterator function on top of _nss_user_do_all(),
 *   but the shared code is small enough that it'd be pretty silly.
 */
nss_status_t
_nss_user_XY_all(be, args, netdb, filter, check)
	user_backend_ptr_t	be;
	nss_XbyY_args_t		*args;
	int			netdb;		/* whether it uses netdb */
						/* format or not */
	const char		*filter;	/* advisory, to speed up */
						/* string search */
	user_XY_check_func	check;	/* NULL means one-shot, for getXXent */
{
	nss_status_t		res;
	int	parsestat;

	if (be->buf == 0 &&
		(be->buf = malloc(be->minbuf)) == 0) {
		return (NSS_UNAVAIL); /* really panic, malloc failed */
	}

	if (check != 0 || be->f == 0) {
		if ((res = _nss_user_setent(be, 0)) != NSS_SUCCESS) {
			return (res);
		}
	}

	res = NSS_NOTFOUND;

	/*CONSTCOND*/
	while (1) {
		char		*instr	= be->buf;
		int		linelen;

		if ((linelen = _nss_user_read_line(be->f, instr,
		    be->minbuf)) < 0) {
			/* End of file */
			args->returnval = 0;
			args->erange    = 0;
			break;
		}
		if (filter != 0 && strstr(instr, filter) == 0) {
			/*
			 * Optimization:  if the entry doesn't contain the
			 *   filter string then it can't be the entry we want,
			 *   so don't bother looking more closely at it.
			 */
			continue;
		}
		if (netdb) {
			char		*first;
			char		*last;

			if ((last = strchr(instr, '#')) == 0) {
				last = instr + linelen;
			}
			*last-- = '\0';		/* Nuke '\n' or #comment */

			/*
			 * Skip leading whitespace.  Normally there isn't
			 *   any, so it's not worth calling strspn().
			 */
			for (first = instr;  isspace(*first);  first++) {
				;
			}
			if (*first == '\0') {
				continue;
			}
			/*
			 * Found something non-blank on the line.  Skip back
			 * over any trailing whitespace;  since we know
			 * there's non-whitespace earlier in the line,
			 * checking for termination is easy.
			 */
			while (isspace(*last)) {
				--last;
			}

			linelen = last - first + 1;
			if (first != instr) {
					instr = first;
			}
		}

		args->returnval = 0;
		parsestat = (*args->str2ent)(instr, linelen, args->buf.result,
				args->buf.buffer, args->buf.buflen);

		if (parsestat == NSS_STR_PARSE_SUCCESS) {
			args->returnval = args->buf.result;
			if (check == 0 || (*check)(args)) {
				res = NSS_SUCCESS;
				break;
			}
		} else if (parsestat == NSS_STR_PARSE_ERANGE) {
			args->erange = 1;	/* should we just skip this */
						/* one long line ?? */
		} /* else if (parsestat == NSS_STR_PARSE_PARSE) don't care ! */
	}

	/*
	 * stayopen is set to 0 by default in order to close the opened
	 * file.  Some applications may break if it is set to 1.
	 */
	if (check != 0 && !args->stayopen) {
		(void) _nss_user_endent(be, 0);
	}

	return (res);
}


/*ARGSUSED*/
nss_status_t
_nss_user_destr(be, dummy)
	user_backend_ptr_t	be;
	void			*dummy;
{
	if (be != 0) {
		if (be->f != 0) {
			(void) _nss_user_endent(be, 0);
		}
		free((char *)be->filename);
		free(be);
	}
	return (NSS_SUCCESS);	/* In case anyone is dumb enough to check */
}

nss_backend_t *
_nss_user_constr(ops, n_ops, filename, min_bufsize)
	user_backend_op_t	ops[];
	int			n_ops;
	const char		*filename;
	int			min_bufsize;
{
	user_backend_ptr_t	be;

	if ((be = (user_backend_ptr_t)malloc(sizeof (*be))) == 0) {
		return (0);
	}
	be->ops		= ops;
	be->n_ops	= n_ops;
	if ((be->filename = strdup(filename)) == NULL) {
		free(be);
		return (NULL);
	}
	be->minbuf	= min_bufsize;
	be->f		= 0;
	be->buf		= 0;

	return ((nss_backend_t *)be);
}
