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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	cscope - interactive C symbol cross-reference
 *
 *	keyword look-up routine for the C symbol scanner
 */

#include "global.h"

/* keyword text for fast testing of keywords in the scanner */
char	externtext[] = "extern";
char	typedeftext[] = "typedef";

/*
 * This keyword table is also used for keyword text compression.  Keywords
 * with an index less than the numeric value of a space are replaced with the
 * control character corresponding to the index, so they cannot be moved
 * without changing the database file version and adding compatibility code
 * for old databases.
 */
struct	keystruct keyword[] = {
	{ "#define",	' ',	MISC,	NULL },	/* must be table entry 0 */
						/* for old databases */
	{ "#include",	' ',	MISC,	NULL },	/* must be table entry 1 */
	{ "break",	'\0',	FLOW,	NULL },	/* rarely in cross-reference */
	{ "case",	' ',	FLOW,	NULL },
	{ "char",	' ',	DECL,	NULL },
	{ "continue",	'\0',	FLOW,	NULL },	/* rarely in cross-reference */
	{ "default",	'\0',	FLOW,	NULL },	/* rarely in cross-reference */
	{ "#define",	' ',	MISC,	NULL },	/* must be table entry 7 */
	{ "double",	' ',	DECL,	NULL },
	{ "\t",		'\0',	MISC,	NULL },	/* must be table entry 9 */
	{ "\n",		'\0',	MISC,	NULL },	/* must be table entry 10 */
	{ "else",	' ',	FLOW,	NULL },
	{ "enum",	' ',	DECL,	NULL },
	{ externtext,	' ',	DECL,	NULL },
	{ "float",	' ',	DECL,	NULL },
	{ "for",	'(',	FLOW,	NULL },
	{ "goto",	' ',	FLOW,	NULL },
	{ "if",		'(',	FLOW,	NULL },
	{ "int",	' ',	DECL,	NULL },
	{ "long",	' ',	DECL,	NULL },
	{ "register",	' ',	DECL,	NULL },
	{ "return",	'\0',	FLOW,	NULL },
	{ "short",	' ',	DECL,	NULL },
	{ "sizeof",	'\0',	MISC,	NULL },
	{ "static",	' ',	DECL,	NULL },
	{ "struct",	' ',	DECL,	NULL },
	{ "switch",	'(',	FLOW,	NULL },
	{ typedeftext,	' ',	DECL,	NULL },
	{ "union",	' ',	DECL,	NULL },
	{ "unsigned",	' ',	DECL,	NULL },
	{ "void",	' ',	DECL,	NULL },
	{ "while",	'(',	FLOW,	NULL },

	/* these keywords are not compressed */
	{ "auto",	' ',	DECL,	NULL },
	{ "do",		' ',	FLOW,	NULL },
	{ "fortran",	' ',	DECL,	NULL },
	{ "const",	' ',	DECL,	NULL },
	{ "signed",	' ',	DECL,	NULL },
	{ "volatile",	' ',	DECL,	NULL },
};

#define	KEYWORDS	(sizeof (keyword) / sizeof (struct keystruct))

#define	HASHMOD	(KEYWORDS * 2 + 1)

static	struct	keystruct *hashtab[HASHMOD]; /* pointer table */

/* put the keywords into the symbol table */

void
initsymtab(void)
{
	int	i, j;
	struct	keystruct *p;

	for (i = 1; i < KEYWORDS; ++i) {
		p = &keyword[i];
		j = hash(p->text) % HASHMOD;
		p->next = hashtab[j];
		hashtab[j] = p;
	}
}

/* see if this identifier is a keyword */

struct keystruct *
lookup(char *ident)
{
	struct	keystruct *p;
	int	c;

	/* look up the identifier in the keyword table */
	for (p = hashtab[hash(ident) % HASHMOD]; p != NULL; p = p->next) {
		if (strequal(ident, p->text)) {
			if (compress == YES && (c = p - keyword) < ' ') {
				ident[0] = c;	/* compress the keyword */
			}
			return (p);
		}
	}
	/* this is an identifier */
	return (NULL);
}

/* form hash value for string */

int
hash(char *s)
{
	unsigned i;

	for (i = 0; *s != '\0'; )
		i += *s++;	/* += is faster than <<= for cscope */
	return (i);
}
