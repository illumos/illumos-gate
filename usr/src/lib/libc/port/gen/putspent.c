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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * format a shadow file entry
 *
 * This code used to live in getspent.c
 */

#include "lint.h"
#include <stdio.h>
#include <shadow.h>

int
putspent(const struct spwd *p, FILE *f)
{
	(void) fprintf(f, "%s:%s:", p->sp_namp,
	    p->sp_pwdp ? p->sp_pwdp : "");
		/* pwdp could be null for +/- entries */
	if (p->sp_lstchg >= 0)
		(void) fprintf(f, "%d:", p->sp_lstchg);
	else
		(void) fprintf(f, ":");
	if (p->sp_min >= 0)
		(void) fprintf(f, "%d:", p->sp_min);
	else
		(void) fprintf(f, ":");
	if (p->sp_max >= 0)
		(void) fprintf(f, "%d:", p->sp_max);
	else
		(void) fprintf(f, ":");
	if (p->sp_warn > 0)
		(void) fprintf(f, "%d:", p->sp_warn);
	else
		(void) fprintf(f, ":");
	if (p->sp_inact > 0)
		(void) fprintf(f, "%d:", p->sp_inact);
	else
		(void) fprintf(f, ":");
	if (p->sp_expire > 0)
		(void) fprintf(f, "%d:", p->sp_expire);
	else
		(void) fprintf(f, ":");
	if (p->sp_flag != 0)
		(void) fprintf(f, "%d\n", p->sp_flag);
	else
		(void) fprintf(f, "\n");

	(void) fflush(f);
	return (ferror(f));
}
