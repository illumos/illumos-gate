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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include	<sys/types.h>
#include	<string.h>
#include	<unistd.h>
#include	"curses_inc.h"

/*
 * Set a soft label.
 *
 * n:	label number
 * lab:	the string
 * f:	0, 1, 2 for left, center, right-justification
 */

int
slk_set(int n, char *lab, int f)
{
	SLK_MAP	*slk = SP->slk;
	int	len, slklen = slk->_len, left;
	char		*cp, nlab[LABLEN + 1];

	if ((slk == NULL) || f < 0 || f > 2 || n < 1 || n > slk->_num)
		return (ERR);

	/* 0-indexing internally */
	n--;

	if (lab == NULL) {
		lab = "";

	} else {
		/* chop lengthy label */
		/* LINTED */
		if ((len = (int) strlen(lab)) > slklen)
			lab[len = slklen] = '\0';
	}

	/* make the new display label */
	for (cp = nlab + slklen - 1; cp >= nlab; cp--)
		*cp = ' ';
	nlab[slklen] = '\0';
	if (f == 0)
		left = 0;
	else
		left = (slklen - len) / ((f == 1) ? 2 : 1);

	(void) memcpy(nlab + left, lab, len);

	if (strcmp(slk->_ldis[n], nlab) != 0) {
		(void) memcpy(slk->_lval[n], lab, len + 1);
		(void) memcpy(slk->_ldis[n], nlab, slklen + 1);
		slk->_changed = slk->_lch[n] = TRUE;
	}

	return (OK);
}
