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

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.4 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>		/* EFT abs k16 */
#include "but.h"
#include "wish.h"
#include "typetab.h"
#include "ifuncdefs.h"
#include "optabdefs.h"
#include "partabdefs.h"

extern bool No_operations;

struct opt_entry *
obj_to_opt(objtype)
char *objtype;
{
	register int i;
	extern struct opt_entry Partab[MAX_TYPES];

	for (i = 0; i < MAX_TYPES && Partab[i].objtype; i++) {
		if (strcmp(objtype, Partab[i].objtype) == 0) {
			if (i != MAX_TYPES-1 || No_operations == FALSE)
				return(Partab + i);
		}
	}

#ifdef _DEBUG
	_debug(stderr, "Object %s Not Found, searching external\n",objtype);
#endif

	if (ootread(objtype) == O_FAIL) {
#ifdef _DEBUG
		_debug(stderr, "Failed to find extern\n");
#endif
		return(NULL);
	} else {
#ifdef _DEBUG
		_debug(stderr, "Found object extern\n");
#endif
		No_operations = FALSE;
		return(Partab + MAX_TYPES - 1);
	}
}
