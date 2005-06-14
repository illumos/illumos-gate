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
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * regerror: map error number to text string
 *
 * Copyright 1985, 1992 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */
/*
 * static char rcsID[] = "$Header: /u/rd/src/libc/regex/rcs/regerror.c "
 * "1.28 1994/11/07 14:40:06 jeffhe Exp $";
 */

#ifndef	_REGERROR_MSG_H
#define	_REGERROR_MSG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This string array holds the error message strings for
 * the regerror() function.  The method function implemented in
 * libc_i18n strongly depends on this array.  Do not modify this
 * array without synchronizing with the method function.
 * Also, the _MSG macro is used to extract the message strings
 * for the gettext() messaging by the makelibccatalog.sh script.
 */
static const char *regerrors[] = {
	_MSG("success"),			/*  0: REG_OK */
	_MSG("failed to match"),		/*  1: REG_NOMATCH */
	_MSG("invalid collation element"),	/*  2: REG_ECOLLATE */
	_MSG("trailing \\ in pattern"),		/*  3: REG_EESCAPE */
	_MSG("newline found before end of pattern"),
						/*  4: REG_ENEWLINE */
	"",					/*  5: REG_ENSUB (OBS) */
	_MSG("number in \\[0-9] invalid"),	/*  6: REG_ESUBREG */
	_MSG("[ ] imbalance or syntax error"),	/*  7: REG_EBRACK */
	_MSG("( ) or \\( \\) imbalance"),	/*  8: REG_EPAREN */
	_MSG("{ } or \\{ \\} imbalance"),	/*  9: REG_EBRACE */
	_MSG("invalid endpoint in range"),	/* 10: REG_ERANGE */
	_MSG("out of memory"),			/* 11: REG_ESPACE */
	_MSG("?, *, +, or { } not preceded by valid regular expression"),
						/* 12: REG_BADRPT */
	_MSG("invalid character class type"),	/* 13: REG_ECTYPE */
	_MSG("syntax error"),			/* 14: REG_BADPAT */
	_MSG("contents of { } or \\{ \\} invalid"),
						/* 15: REG_BADBR */
	_MSG("internal error"),			/* 16: REG_EFATAL */
	_MSG("invalid multibyte character"),	/* 17: REG_ECHAR */
	_MSG("backtrack stack overflow: expression generates too many "
	    "alternatives"),			/* 18: REG_STACK */
	_MSG("function not supported"),		/* 19: REG_ENOSYS */
	_MSG("unknown regex error"),		/* 20: (reserved) */
	_MSG("^ anchor not at beginning of pattern"),
						/* 21: REG_EBOL */
	_MSG("$ anchor not at end of pattern"),	/* 22: REG_EEOL */
};

#endif /* _REGERROR_MSG_H */
