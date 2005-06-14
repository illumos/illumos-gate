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

#pragma ident	"%Z%%M%	%I%	%E% SMI" /* SVr4.0 1.2 */

/*LINTLIBRARY*/

#include <sys/types.h>
#include <stdlib.h>
#include "utility.h"

/*
 *	TYPE_INTEGER standard type
 *
 *	usage:
 *		set_field_type(f, TYPE_INTEGER, precision, vmin, vmax);
 *
 *		int precision;	for padding with leading zeros
 *		double vmin;	minimum acceptable value
 *		double vmax;	maximum acceptable value
 */
static char *make_int(va_list *);
static char *copy_int(char *);
static void free_int(char *);
static int fcheck_int(FIELD *, char *);
static int ccheck_int(int, char *);

typedef struct {

	int	prec;
	long	vmin;
	long	vmax;
} INTEGER;

static FIELDTYPE typeINTEGER =
{
				ARGS,			/* status	*/
				1,			/* ref		*/
				(FIELDTYPE *) 0,	/* left		*/
				(FIELDTYPE *) 0,	/* right	*/
				make_int,		/* makearg	*/
				copy_int,		/* copyarg	*/
				free_int,		/* freearg	*/
				fcheck_int,		/* fcheck	*/
				ccheck_int,		/* ccheck	*/
				(PTF_int) 0,		/* next		*/
				(PTF_int) 0,		/* prev		*/
};

FIELDTYPE * TYPE_INTEGER = &typeINTEGER;

static char *
make_int(va_list *ap)
{
	INTEGER * n;

	if (Alloc(n, INTEGER)) {
		n -> prec = va_arg(*ap, int);
		n -> vmin = va_arg(*ap, long);
		n -> vmax = va_arg(*ap, long);
	}
	return ((char *) n);
}

static char *
copy_int(char *arg)
{
	INTEGER *n;

	if (Alloc(n, INTEGER))
		*n = *((INTEGER *) arg);
	return ((char *) n);
}

static void
free_int(char *arg)
{
	Free(arg);
}

static int
fcheck_int(FIELD *f, char *arg)
{
	INTEGER *	n = (INTEGER *) arg;
	long		vmin = n -> vmin;
	long		vmax = n -> vmax;
	int		prec = n -> prec;
	char *		x = field_buffer(f, 0);
	char		buf[80];

	while (*x && *x == ' ')
		++x;
	if (*x) {
		char * t = x;

		if (*x == '-')
			++x;
		while (*x && isdigit(*x))
			++x;
		while (*x && *x == ' ')
			++x;
		if (! *x) {
			long v = atol(t);

			if (vmin >= vmax || (v >= vmin && v <= vmax)) {
				(void) sprintf(buf, "%.*ld", prec, v);
				(void) set_field_buffer(f, 0, buf);
				return (TRUE);
			}
		}
	}
	return (FALSE);
}

#define	charok(c)	(isdigit(c) || c == '-')

/*ARGSUSED*/

static int
ccheck_int(int c, char *arg)
{
	return (charok(c));
}
