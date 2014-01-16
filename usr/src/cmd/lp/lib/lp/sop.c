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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.9	*/
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "stdio.h"
#include "string.h"
#include "errno.h"
#include "stdlib.h"

#include "lp.h"

/**
 ** sop_up_rest() - READ REST OF FILE INTO STRING
 **/
char *
sop_up_rest(int fd, char *endsop)
{
	register int		size,
				add_size,
				lenendsop;

	register char		*str;

	char			buf[BUFSIZ];


	str = 0;
	size = 0;
	if (endsop)
		lenendsop = strlen(endsop);

	errno = 0;
	while (fdgets(buf, BUFSIZ, fd)) {
		if (endsop && STRNEQU(endsop, buf, lenendsop))
			break;
		add_size = strlen(buf);
		if (str)
			str = Realloc(str, size + add_size + 1);
		else
			str = Malloc(size + add_size + 1);
		if (!str) {
			errno = ENOMEM;
			return (0);
		}
		strcpy (str + size, buf);
		size += add_size;
	}
	if (errno != 0) {
		Free (str);
		return (0);
	}
	return (str);
}
