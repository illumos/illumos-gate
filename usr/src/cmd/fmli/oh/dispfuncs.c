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
#include <sys/types.h>		/* EFT abs k16 */
#include "wish.h"
#include "typetab.h"
#include "partabdefs.h"
#include "var_arrays.h"
#include "terror.h"
#include	"moremacros.h"

#define START_OBJS	20

static char **All_objtypes;
static char **All_displays;

char *
def_display(objtype)
char *objtype;
{
	register int i, size;
	struct opt_entry *opt, *obj_to_parts();

	if (!All_objtypes) {
		All_objtypes = (char **)array_create(sizeof(char *), START_OBJS);
		All_displays = (char **)array_create(sizeof(char *), START_OBJS);
	}
	size = array_len(All_objtypes);
	for (i = 0; i < size; i++)
		if (strcmp(All_objtypes[i], objtype) == 0)
			return(All_displays[i]);

	/* not found, append new */
	All_objtypes = (char **)array_append(All_objtypes, NULL);

	All_objtypes[size] = strsave(objtype);

	if (opt = obj_to_parts(objtype)) {
		All_displays = (char **)array_append(All_displays, NULL);
		All_displays[size] = strsave(opt->objdisp);
	} else {
		All_displays = (char **)array_append(All_displays, NULL);
		All_displays[size] = "Data file";
	}

	return(All_displays[size]);
}

char *
def_objtype(objtype)
char *objtype;
{
	register int i, size;
	struct opt_entry *opt, *obj_to_parts();

	if (!All_objtypes) {
		All_objtypes = (char **)array_create(sizeof(char *), START_OBJS);
		All_displays = (char **)array_create(sizeof(char *), START_OBJS);
	}

	size = array_len(All_objtypes);

	for (i = 0; i < size; i++)
		if (strcmp(All_objtypes[i], objtype) == 0)
			return(All_objtypes[i]);

	/* not found, append new */

	All_objtypes = (char **)array_append(All_objtypes, NULL);
	/* ehr 3
	if (All_objtypes[size])
		free(All_objtypes[size]);
	*/
	All_objtypes[size] = strsave(objtype);

	if (opt = obj_to_parts(objtype)) {
		All_displays = (char **)array_append(All_displays, NULL);
		/* ehr3
		if (All_objtypes[size])
			free(All_objtypes[size]);
		*/
		All_displays[size] = strsave(opt->objdisp);
	} else {
		All_displays = (char **)array_append(All_displays, NULL);
		All_displays[size] = "Data file";
	}

	return(All_objtypes[size]);
}
