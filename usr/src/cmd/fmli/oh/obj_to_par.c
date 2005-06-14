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

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.5 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>		/* EFT abs k16 */
#include "but.h"
#include "wish.h"
#include "typetab.h"
#include "ifuncdefs.h"
#include "partabdefs.h"
#include "optabdefs.h"

/* Obj_to_parts should be used instead of obj_to_opt in those executables
 * that do not need access to the object operations table.  It only
 * reads the global flags and parts information for an object.
 */

/* The No_operations flag is set to TRUE if the externally read object
 * has not had its operations read.
 */
bool No_operations;

struct opt_entry *
obj_to_parts(objtype)
char *objtype;
{
	register int i;
	FILE *fp;
	extern struct opt_entry Partab[MAX_TYPES];
	extern char *externoot();

	for (i = 0; i < MAX_TYPES && Partab[i].objtype; i++) {
		if (strcmp(objtype, Partab[i].objtype) == 0 )
			return(Partab + i);
	}

	/* read in the external object table for this object, but
	 * only read in the parts information.
	 */

	if ((fp = fopen(externoot(objtype), "r")) == NULL)
		return(NULL);

	if (read_parts(fp, objtype) == O_FAIL) {
#ifdef _DEBUG
		_debug(stderr, "External Object not found\n");
#endif
		fclose(fp);
		return(NULL);
	} else {
#ifdef _DEBUG
		_debug(stderr, "External Object %s found\n", objtype);
#endif
		No_operations = TRUE;
		fclose(fp);
		return(Partab + MAX_TYPES - 1);
	}
}
