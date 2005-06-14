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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2	*/

/*LINTLIBRARY*/

#include <sys/types.h>
#include <stdlib.h>
#include "utility.h"

/*
 *	TYPE_ENUM standard type
 *
 *	usage:
 *		set_field_type(f, TYPE_ENUM, list, checkcase, checkuniq);
 *
 *		char ** list;	list of acceptable strings
 *		int checkcase;	TRUE - upper/lower case is significant
 *		int checkuniq;	TRUE - unique match required
 *
 */
typedef struct {

	char **	list;
	int	checkcase;
	int	checkuniq;
	int	count;
} ENUM;

static char * make_enum(va_list *);
static char * copy_enum(char *);
static void free_enum(char *);
static int fcheck_enum(FIELD *, char *);
static int next_enum(FIELD *, char *);
static int prev_enum(FIELD *, char *);

static FIELDTYPE typeENUM =
{
				ARGS | CHOICE,		/* status	*/
				1,			/* ref		*/
				(FIELDTYPE *) 0,	/* left		*/
				(FIELDTYPE *) 0,	/* right	*/
				make_enum,		/* makearg	*/
				copy_enum,		/* copyarg	*/
				free_enum,		/* freearg	*/
				fcheck_enum,		/* fcheck	*/
				(PTF_int) 0,		/* ccheck	*/
				next_enum,		/* next		*/
				prev_enum,		/* prev		*/
};

FIELDTYPE * TYPE_ENUM = &typeENUM;

static char *
make_enum(va_list *ap)
{
	ENUM * n;

	if (Alloc(n, ENUM)) {
		char **		v;

		n -> list	= va_arg(*ap, char **);
		n -> checkcase	= va_arg(*ap, int);
		n -> checkuniq	= va_arg(*ap, int);

		for (v = n -> list; *v; ++v)
			;
		n -> count = (int) (v - n -> list);
	}
	return ((char *) n);
}

static char *
copy_enum(char *arg)
{
	ENUM * n;

	if (Alloc(n, ENUM))
		*n = *((ENUM *) arg);
	return ((char *) n);
}

static void
free_enum(char *arg)
{
	Free(arg);
}

#define	NO_MATCH		0
#define	PARTIAL_MATCH		1
#define	EXACT_MATCH		2

static int
cmp(char *x, char *v, int checkcase)
{
	while (*v && *v == ' ')			/* remove leading blanks */
		++v;
	while (*x && *x == ' ')			/* remove leading blanks */
		++x;

	if (*v == '\0')
		return (*x == '\0' ? EXACT_MATCH : NO_MATCH);

	if (checkcase) {			/* case is significant */
		while (*x++ == *v)
			if (*v++ == '\0')
				return (EXACT_MATCH);
	} else {				/* ignore case */
		while (toupper (*x++) == toupper (*v))
			if (*v++ == '\0')
				return (EXACT_MATCH);
	}
	while (*v && *v == ' ')			/* remove trailing blanks */
		++v;
	if (*v)
		return (NO_MATCH);
	else
		return (*--x ? PARTIAL_MATCH : EXACT_MATCH);
}

static int
fcheck_enum(FIELD *f, char *arg)
{
	ENUM *		n		= (ENUM *) arg;
	char **		list		= n -> list;
	int		checkcase	= n -> checkcase;
	int		checkuniq	= n -> checkuniq;
	int		m;
	char *		v		= field_buffer(f, 0);
	char *		x;

	while (x = *list++)
		if (m = cmp(x, v, checkcase)) {
			char * value = x;

			if (checkuniq && m != EXACT_MATCH)
				while (x = *list++)
					if (m = cmp(x, v, checkcase)) {
						if (m == EXACT_MATCH) {
							value = x;
							break;
						}
						else
							value = (char *) 0;
					}
			if (! value)
				return (FALSE);

			(void) set_field_buffer(f, 0, value);
			return (TRUE);
		}

	return (FALSE);
}

static int
next_enum(FIELD *f, char *arg)
{
	ENUM *		n		= (ENUM *) arg;
	char **		list		= n -> list;
	int		checkcase	= n -> checkcase;
	int		count		= n -> count;
	char *		v		= field_buffer(f, 0);

	while (count--)
		if (cmp(*list++, v, checkcase) == EXACT_MATCH)
			break;
	if (count <= 0)
		list = n -> list;

	if (count >= 0 || cmp("", v, checkcase) == EXACT_MATCH) {
		(void) set_field_buffer(f, 0, *list);
		return (TRUE);
	}
	return (FALSE);
}

static int
prev_enum(FIELD *f, char *arg)
{
	ENUM *		n		= (ENUM *) arg;
	char **		list		= n -> list + n -> count - 1;
	int		checkcase	= n -> checkcase;
	int		count		= n -> count;
	char *		v		= field_buffer(f, 0);

	while (count--)
		if (cmp(*list--, v, checkcase) == EXACT_MATCH)
			break;
	if (count <= 0)
		list = n -> list + n -> count - 1;

	if (count >= 0 || cmp("", v, checkcase) == EXACT_MATCH) {
		(void) set_field_buffer(f, 0, *list);
		return (TRUE);
	}
	return (FALSE);
}
