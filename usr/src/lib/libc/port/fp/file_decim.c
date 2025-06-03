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

#include "lint.h"
#include "file64.h"
#include "mtlib.h"
#include <sys/types.h>
#include <ctype.h>
#include <stdio.h>
#include "base_conversion.h"
#include <xlocale.h>
#include <locale.h>
#include <thread.h>
#include <synch.h>
#include "stdiom.h"
#include "libc.h"

/* if the _IOWRT flag is set, this must be a call from sscanf */
#define	mygetc(iop)	((iop->_flag & _IOWRT) ? \
				((*iop->_ptr == '\0') ? EOF : *iop->_ptr++) : \
				GETC(iop))

#define	myungetc(x, iop)	((iop->_flag & _IOWRT) ? *(--iop->_ptr) : \
					UNGETC(x, iop))


void
file_to_decimal(char **ppc, int nmax, int fortran_conventions,
    decimal_record *pd, enum decimal_string_form *pform,
    char **pechar, FILE *pf, int *pnread)
{
	char	*cp = *ppc - 1;	/* last character seen */
	char	*good = cp;	/* last character accepted */
	int	current;	/* *cp or EOF */
	int	nread = 0;	/* number of characters read so far */
	locale_t loc = uselocale(NULL);

/* if the _IOWRT flag is set, this must be a call from sscanf */
#define	NEXT \
	if (nread < nmax) { \
		current = ((pf->_flag & _IOWRT) ? \
		    ((*pf->_ptr == '\0') ? EOF : *pf->_ptr++) : \
		    GETC(pf)); \
		if (current != EOF) { \
			*++cp = (char)current; \
			nread++; \
		} \
	} else { \
		current = EOF; \
	}

	NEXT;

#include "char_to_decimal.h"

	/*
	 * If we read any characters beyond the end of the accepted
	 * token, try to push them back.
	 */
	if (fortran_conventions < 0) {
		/* in C99 mode, push back at most one character */
		if (cp >= *ppc && current != EOF && myungetc(current, pf)
		    != EOF) {
			cp--;
			nread--;
		}
	} else {
		while (cp >= *ppc) {
			if (myungetc((int)(unsigned char)*cp, pf) == EOF)
				break;
			cp--;
			nread--;
		}
	}

	*++cp = '\0';
	*pnread = nread;
}
