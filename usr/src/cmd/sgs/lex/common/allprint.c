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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <sys/euc.h>
#include <ctype.h>
#include <widec.h>
#include <wctype.h>

#pragma weak yyout
extern FILE *yyout;

#ifndef JLSLEX
#define	CHR    char
#endif

#ifdef WOPTION
#define	CHR	wchar_t
#define	sprint	sprint_w
#endif

#ifdef EOPTION
#define	CHR	wchar_t
#endif

void
allprint(CHR c)
{
	switch (c) {
	case '\n':
		(void) fprintf(yyout, "\\n");
		break;
	case '\t':
		(void) fprintf(yyout, "\\t");
		break;
	case '\b':
		(void) fprintf(yyout, "\\b");
		break;
	case ' ':
		(void) fprintf(yyout, "\\_");
		break;
	default:
		if (!iswprint(c))
			(void) fprintf(yyout, "\\x%-2x", c);
		else
			(void) putwc(c, yyout);
		break;
	}
}

void
sprint(s)
CHR *s;
{
	while (*s)
		allprint(*s++);
}
