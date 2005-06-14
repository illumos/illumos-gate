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

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.6 */

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
extern int Vflag;

/* functions pertaining to the object operations table (oot) and object parts
 * table (opt).
 */

struct operation **
oot_get()
{
	extern struct operation *Optab[MAX_TYPES][MAX_OPERS];
	void fcn_init();

	fcn_init();
	odftread();
	return((struct operation **)Optab);
}

struct operation **
obj_to_oot(objtype)
char *objtype;
{
	register int i;
	extern struct operation *Optab[MAX_TYPES][MAX_OPERS];
	extern struct opt_entry Partab[MAX_TYPES];

	for (i = 0; i < MAX_TYPES && Partab[i].objtype; i++) {
		if (strcmp(objtype, Partab[i].objtype) == 0 ) {
			if (!Vflag && !(Partab[i].int_class & CL_FMLI))
				return(NULL);
			if (i != MAX_TYPES-1 || No_operations == FALSE)
				return(Optab[i]);
		}
	}

	if (ootread(objtype) == O_FAIL) {
		return(NULL);
	} else {
		_debug(stderr, "External read of %s succeeded\n", objtype);
		No_operations = FALSE;
		return(Optab[MAX_TYPES - 1]);
	}
}
