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

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.3 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>		/* EFT abs k16 */
#include "but.h"
#include "wish.h"
#include "sizes.h"
#include "typetab.h"
#include "ifuncdefs.h"
#include "optabdefs.h"
#include "partabdefs.h"

bool
opt_rename(entry, newbase, allnames)
struct ott_entry *entry[MAXOBJPARTS+1];
char *newbase;
char allnames[MAXOBJPARTS][FILE_NAME_SIZ];
{
	char *part_construct();
	register int i = 0, n = 0;
	struct opt_entry *partab;
	int part_offset;
	char *base, *p;
	extern struct one_part  Parts[MAXPARTS];
	struct opt_entry *obj_to_parts();
	char *part_match();
	

	if ((partab = obj_to_parts(entry[0]->objtype)) == NULL)
		return(O_FAIL);
	part_offset = partab->part_offset;

	if (base = part_match(entry[0]->name, Parts[part_offset].part_template)) {
		strcpy(allnames[n++], 
			part_construct(newbase, Parts[part_offset+i].part_template));
		if (++entry == NULL)
			return(O_OK);
	} else
		return(O_FAIL);

	for (i = 1; i < partab->numparts; i++) {
		p = part_construct(base, Parts[part_offset+i].part_template);
		if (strcmp(entry[0]->name, p) == 0) {
			strcpy(allnames[n++], 
				part_construct(newbase, Parts[part_offset+i].part_template));
			if (++entry == NULL)
				return(O_OK);
		} else if (!(Parts[part_offset+i].part_flags & PRT_OPT) ) {
			return(O_FAIL);
		}
	}
	return(O_OK);
}
