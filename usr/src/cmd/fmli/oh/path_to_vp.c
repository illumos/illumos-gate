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
#include <sys/types.h>		/* EFT abs k16 */
#include "wish.h"
#include "typetab.h"
#include "optabdefs.h"
#include "obj.h"
#include "sizes.h"

extern struct operation Ascii_cv, Unknown_cv, Illeg_op, No_op;
static char Holdpath[PATHSIZ];

char *
path_to_vpath(path)
char *path;
{
	struct ott_entry *entry;
	extern char *Oasys;
	static char *viewdir = "/info/OH/view/";
	struct operation **obj_to_oot();
	struct operation *convert;
	struct ott_entry *path_to_ott();

	if ((entry = path_to_ott(path)) == NULL)
		return(NULL);
	convert = obj_to_oot(entry->objtype)[OF_MV];

	if (entry->objmask & M_EN) {
		strcpy(Holdpath, Oasys);
		strcat(Holdpath, viewdir);
		strcat(Holdpath, "scram.view");
	} else if (convert == &Ascii_cv)		/* ascii convert uses file itself*/
		return(path);
	else if (convert == &Unknown_cv)	/* unknown convert uses object type*/
		sprintf(Holdpath, "%s%sv.%s", Oasys, viewdir, entry->objtype);
	else if (convert == &Illeg_op || convert == &No_op)
		return(NULL);
	else
		sprintf(Holdpath, "%s/.v%s", entry->dirpath, entry->name);

	return(Holdpath);
}
