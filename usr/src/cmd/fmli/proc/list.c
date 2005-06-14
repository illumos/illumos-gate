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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright  (c) 1985 AT&T
 *	All Rights Reserved
 */

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/types.h>	/* EFT abs k16 */
#include "wish.h"
#include "token.h"
#include "slk.h"
#include "actrec.h"
#include "proc.h"
#include "procdefs.h"
#include "terror.h"
#include "ctl.h"
#include "menudefs.h"

extern struct proc_rec PR_all[];


struct actrec *
menline_to_proc(n)
int n;
{
	register int i, l;

	for (i = l = 0; i < MAX_PROCS; i++) {
		if (PR_all[i].name)
			if (++l == n)
				return(PR_all[i].ar);
	}
	return(NULL);
}

struct menu_line
proc_menudisp(n, ptr)
int n;
char *ptr;
{
	struct menu_line m;
	struct actrec *a;

	m.highlight = m.description = NULL;
	m.flags = 0;
	if ((a = menline_to_proc(n)) != NULL)
		ar_ctl(a, CTGETITLE, &m.highlight, NULL, NULL, NULL, NULL, NULL);
	return(m);
}
