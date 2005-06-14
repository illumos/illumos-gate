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
 *      Copyright (c) 1997, by Sun Microsystems, Inc.
 *      All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI" /* SVr4.0 1.1 */

/*LINTLIBRARY*/

#include <sys/types.h>
#include <stdlib.h>
#include "utility.h"

/*
 *	TYPE_ALPHA standard type
 *
 *	usage:
 *		set_field_type(f, TYPE_ALPHA, width);
 *
 *		int width;	minimum token width
 */
static char *make_alpha(va_list *);
static char *copy_alpha(char *);
static void free_alpha(char *);
static int fcheck_alpha(FIELD *, char *);
static int ccheck_alpha(int, char *);

static FIELDTYPE typeALPHA =
{
				ARGS,			/* status	*/
				1,			/* ref		*/
				(FIELDTYPE *) 0,	/* left		*/
				(FIELDTYPE *) 0,	/* right	*/
				make_alpha,		/* makearg	*/
				copy_alpha,		/* copyarg	*/
				free_alpha,		/* freearg	*/
				fcheck_alpha,		/* fcheck	*/
				ccheck_alpha,		/* ccheck	*/
				(PTF_int) 0,		/* next		*/
				(PTF_int) 0,		/* prev		*/
};

FIELDTYPE * TYPE_ALPHA = &typeALPHA;

static char *
make_alpha(va_list *ap)
{
	int * width;

	if (Alloc(width, int))
		*width = va_arg(*ap, int);
	return ((char *) width);
}

static char *
copy_alpha(char *arg)
{
	int * width;

	if (Alloc(width, int))
		*width = *((int *) arg);
	return ((char *) width);
}

static void
free_alpha(char *arg)
{
	Free(arg);
}

static int
fcheck_alpha(FIELD *f, char *arg)
{
	int	width	= *((int *) arg);
	int	n	= 0;
	char *	v	= field_buffer(f, 0);

	while (*v && *v == ' ')
		++v;
	if (*v) {
		char * vbeg = v;
		while (*v && isalpha(*v))
			++v;
		n = v - vbeg;
		while (*v && *v == ' ')
			++v;
	}
	return (*v || n < width ? FALSE : TRUE);
}

/*ARGSUSED*/

static int
ccheck_alpha(int c, char *arg)
{
	return (isalpha(c));
}
