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

/* Note: this file created with tabstops set to 4.
 *
 * Definition of the Object Parts Table (OPT).
 *
 */

#include <stdio.h>
#include <sys/types.h>		/* EFT abs k16 */
#include "wish.h"
#include "but.h"
#include "typetab.h"
#include "ifuncdefs.h"
#include "optabdefs.h"
#include "partabdefs.h"


/*** NOTE: the ordering of the objects in this table must be the same
 *** as the order in the object operations table (In optab.c), as this table is
 *** used as an index into that table.
 ***/

struct opt_entry Partab[MAX_TYPES] =
{
	{ "DIRECTORY",	"File folder",	CL_DIR,  "?", "?", "?", "?", "?", 0, 2},
	{ "ASCII",	"Standard file",CL_DOC,	 "?", "?", "?", "?", "?", 2, 1},
	{ "MENU",	"Menu",	CL_DYN | CL_FMLI,"?", "?", "?", "?", "?", 3, 1},
	{ "FORM",	"Form",		CL_FMLI, "?", "?", "?", "?", "?", 4, 1},
	{ "TEXT",	"Text",		CL_FMLI, "?", "?", "?", "?", "?", 5, 1},
	{ "EXECUTABLE",	"Executable",	CL_FMLI, "?", "?", "?", "?", "?", 7, 1},
	{ "TRANSFER",	"Foreign file",	CL_OEU,  "?", "?", "?", "?", "?", 6, 1},
	{ "UNKNOWN",	"Data file",	NOCLASS, "?", "?", "?", "?", "?", 7, 1},
	{ "", 		"", 	   NOCLASS, NULL, NULL, NULL, NULL, NULL, 0, 0}
};

/* the "magic" numbers in the "%.ns" below (2nd field) are based on 
 * a max file name size of 255.
 */
struct one_part Parts[MAXPARTS] = 
{
        {"1",	"%.255s", 	PRT_DIR},	/* 0  DIRECTORY */
	{"2",	"%.249s/.pref",	PRT_FILE|PRT_OPT}, /* 1            */
	{"1",	"%.255s", 	PRT_FILE},	/* 2  ASCII     */
	{"1",   "Menu.%.250s", 	PRT_FILE},	/* 3  MENU      */
	{"1",   "Form.%.250s", 	PRT_FILE},	/* 4  FORM      */
	{"1",   "Text.%.250s", 	PRT_FILE},	/* 5  TEXT      */
	{"1",	"%.255s",	PRT_FILE|PRT_BIN}, /* 6  TRANSFER  */
	{"1",	"%.255s", 	PRT_FILE|PRT_BIN}, /* 7  UNKNOWN/EXEC*/
	{"",	"",		0}
};
