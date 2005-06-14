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
 * Copyright 1993 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2	*/
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "sys/types.h"

#include "lp.h"
#include "form.h"

struct {
	char			*v;
	short			len;
	short			infile;
}			formheadings[FO_MAX] = {

#define	ENTRY(X)	X, sizeof(X)-1

	ENTRY("page length:"),		1,	/* FO_PLEN */
	ENTRY("page width:"),		1,	/* FO_PWID */
	ENTRY("number of pages:"),	1,	/* FO_NP */
	ENTRY("line pitch:"),		1,	/* FO_LPI */
	ENTRY("character pitch:"),	1,	/* FO_CPI */
	ENTRY("character set choice:"),	1,	/* FO_CHSET */
	ENTRY("ribbon color:"),		1,	/* FO_RCOLOR */
	ENTRY("comment:"),		0,	/* FO_CMT */
	ENTRY("alignment pattern:"),	1,	/* FO_ALIGN */
	ENTRY("paper:"),		1,	/* FO_PAPER */

#undef	ENTRY

};

/**
 ** _search_fheading()
 **/

int
#if	defined(__STDC__)
_search_fheading (
	char *			buf
)
#else
_search_fheading (buf)
	char *			buf;
#endif
{
	int			fld;


	for (fld = 0; fld < FO_MAX; fld++)
		if (
			formheadings[fld].v
		     && formheadings[fld].len
		     && CS_STRNEQU(
				buf,
				formheadings[fld].v,
				formheadings[fld].len
			)
		)
			break;

	return (fld);
}
