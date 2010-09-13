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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1997, by Sun Mircrosystems, Inc.
 * All rights reserved.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.6	*/

/*LINTLIBRARY*/

#include <sys/types.h>
#include "menu.h"

MENU _Default_Menu = {
	16,				/* height */
	1,				/* width */
	16,				/* rows */
	1,				/* cols */
	16,				/* frows */
	1,				/* fcols */
	0,				/* namelen */
	0,				/* desclen */
	1,				/* marklen */
	1,				/* itemlen */
	(char *) NULL,			/* pattern */
	0,				/* pindex */
	(WINDOW *) NULL,		/* win */
	(WINDOW *) NULL,		/* sub */
	(WINDOW *) NULL,		/* userwin */
	(WINDOW *) NULL,		/* usersub */
	(ITEM **) NULL,			/* items */
	0,				/* nitems */
	(ITEM *) NULL,			/* curitem */
	0,				/* toprow */
	' ',				/* pad */
	A_STANDOUT,			/* fore */
	A_NORMAL,			/* back */
	A_UNDERLINE,			/* grey */
	(PTF_void) NULL,		/* menuinit */
	(PTF_void) NULL,		/* menuterm */
	(PTF_void) NULL,		/* iteminit */
	(PTF_void) NULL,		/* itemterm */
	(char *) NULL,			/* userptr */
	"-",				/* mark */
	O_ONEVALUE|O_SHOWDESC|
	O_ROWMAJOR|O_IGNORECASE|
	O_SHOWMATCH|O_NONCYCLIC,	/* opt */
	0				/* status */
};

ITEM _Default_Item = {
	(char *) NULL,			/* name.str */
	0,				/* name.length */
	(char *) NULL,			/* description.str */
	0,				/* description.length */
	0,				/* index */
	0,				/* imenu */
	FALSE,				/* value */
	(char *) NULL,			/* userptr */
	O_SELECTABLE,			/* opt */
	0,				/* status */
	0,				/* y */
	0,				/* x */
	0,				/* up */
	0,				/* down */
	0,				/* left */
	0				/* right */
};
