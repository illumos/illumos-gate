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

/*	Copyright (c) 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <curses.h>
#include <malloc.h>
#include "token.h"
#include "winp.h"
#include "fmacs.h"
#include "terror.h"
#include "attrs.h"

#define	FSIZE(x)	(x->rows * (x->cols + 1))

int
setfieldflags(fld, flags)
register ifield *fld;
register int flags;
{
	fld->flags = (flags & I_CHANGEABLE) | (fld->flags & ~(I_CHANGEABLE));
	if (fld->flags & I_INVISIBLE)
	{
		if (fld->value)
		free(fld->value);	/* abs */
		if ((fld->value = (char *)malloc(FSIZE(fld))) == NULL)
			fatal(NOMEM, "");
		fld->valptr = fld->value;
	}
	fld->fieldattr = (fld->flags & I_FILL ? Attr_underline: Attr_normal);
	return (0);
}
