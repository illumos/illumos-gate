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
 * Module:	pkgerr.c
 * Description:
 *	Module for handling error messages that come from libpkg libraries.
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <locale.h>
#include <libintl.h>
#include <stdlib.h>
#include <sys/varargs.h>
#include "pkgerr.h"

/* max length of any formatted error message */
#define	MAX_ERRMSGLEN	1024

/* private structures (not visible outside this file) */
struct _pkg_err_struct {
    int			nerrs;
    char		**msgs;
    PKG_ERR_CODE	*errs;
};

/* ---------------------- public functions ----------------------- */

PKG_ERR
*pkgerr_new()
{
	PKG_ERR	*newerr;

	newerr = (PKG_ERR *)malloc(sizeof (PKG_ERR));
	newerr->nerrs = 0;
	newerr->msgs = NULL;
	newerr->errs = NULL;
	return (newerr);
}

void
pkgerr_add(PKG_ERR *err, PKG_ERR_CODE code, char *fmt, ...)
{
	char		errmsgbuf[1024];
	va_list		ap;

	va_start(ap, fmt);
	(void) vsnprintf(errmsgbuf, MAX_ERRMSGLEN, fmt, ap);
	va_end(ap);

	err->nerrs++;

	err->msgs = (char **)realloc(err->msgs,
	    err->nerrs * sizeof (char *));
	err->errs = (PKG_ERR_CODE *)realloc(err->errs,
	    err->nerrs * sizeof (PKG_ERR_CODE));
	err->msgs[err->nerrs - 1] = strdup(errmsgbuf);
	err->errs[err->nerrs - 1] = code;
}

void
pkgerr_clear(PKG_ERR *err)
{
	int i;

	for (i = 0; i < err->nerrs; i++) {
		free(err->msgs[i]);
	}

	free(err->msgs);
	free(err->errs);
	err->msgs = NULL;
	err->errs = NULL;
	err->nerrs = 0;
}

int
pkgerr_dump(PKG_ERR *err, FILE *fp)
{
	int i;

	for (i = 0; i < err->nerrs; i++) {
		(void) fprintf(fp, err->msgs[i]);
	}
	return (0);
}

int
pkgerr_num(PKG_ERR *err)
{
	return (err->nerrs);
}

char
*pkgerr_get(PKG_ERR *err, int pos)
{
	if (pos < 0 || pos > (err->nerrs - 1)) {
		return (NULL);
	}

	return (err->msgs[pos]);
}

void
pkgerr_free(PKG_ERR *err)
{
	pkgerr_clear(err);
	free(err);
}
