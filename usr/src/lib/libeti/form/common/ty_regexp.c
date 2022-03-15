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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*LINTLIBRARY*/

#include <sys/types.h>
#include <stdlib.h>
#include "utility.h"

/*
 *	TYPE_REGEXP standard type
 *
 *	usage:
 *		set_field_type(f, TYPE_REGEXP, expression);
 *
 *		char * expression;	regular expression regcmp(3C)
 */
extern char *libform_regcmp(char *, char *);
extern char *libform_regex(char *, char *, char *);
static char *make_rexp(va_list *);
static char *copy_rexp(char *);
static void free_rexp(char *);
static int fcheck_rexp(FIELD *, char *);

static FIELDTYPE typeREGEXP =
{
				ARGS,			/* status	*/
				1,			/* ref		*/
				(FIELDTYPE *) 0,	/* left		*/
				(FIELDTYPE *) 0,	/* right	*/
				make_rexp,		/* makearg	*/
				copy_rexp,		/* copyarg	*/
				free_rexp,		/* freearg	*/
				fcheck_rexp,		/* fcheck	*/
				(PTF_int) 0,		/* ccheck	*/
				(PTF_int) 0,		/* next		*/
				(PTF_int) 0,		/* prev		*/
};

FIELDTYPE * TYPE_REGEXP = &typeREGEXP;

static char *
make_rexp(va_list *ap)
{
	return (libform_regcmp(va_arg(*ap, char *), NULL));
					/* (...)$n will dump core */
}

static char *
copy_rexp(char *arg)
{
	char *rexp;

	if (arrayAlloc(rexp, (strlen(arg) + 1), char))
		(void) strcpy(rexp, arg);
	return (rexp);
}

static void
free_rexp(char *arg)
{
	Free(arg);
}

static int
fcheck_rexp(FIELD *f, char *arg)
{
	return (libform_regex(arg, field_buffer(f, 0), NULL) ? TRUE : FALSE);
}
