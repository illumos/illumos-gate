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


/* Copyright (c) 1981 Regents of the University of California */

/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ex.h"
#include "ex_tty.h"

/*
 * Initialization of option values.
 * The option #defines in ex_vars.h are made
 * from this file by the script makeoptions.
 *
 * These initializations are done char by char instead of as strings
 * to confuse xstr so it will leave them alone.
 */
unsigned char	direct[ONMSZ] =
	{'/', 'v', 'a', 'r', '/', 't', 'm', 'p'}; 
unsigned char	paragraphs[ONMSZ] = {
#ifdef XPG4
	'I', 'P', 'L', 'P', 'P', 'P', 'Q', 'P',		/* -ms macros */
	'P', ' ', 'L', 'I',				/* -mm macros */
	'p', 'p', 'l', 'p', 'i', 'p',			/* -me macros */
	'b', 'p'					/* bare nroff */
#else /* ! XPG4 */
	'I', 'P', 'L', 'P', 'P', 'P', 'Q', 'P',		/* -ms macros */
	'P', ' ', 'L', 'I',				/* -mm macros */
	'p', 'p', 'l', 'p', 'i', 'p', 'n', 'p',		/* -me macros */
	'p', 'p', 'l', 'p', 'i', 'p',			/* -me macros */
	'b', 'p'					/* bare nroff */
#endif
};
unsigned char	sections[ONMSZ] = {
#ifdef XPG4
	'N', 'H', 'S', 'H',				/* -ms macros */
	'H', ' ', 'H', 'U',				/* -mm macros */
	'u', 'h', 's', 'h'				/* -me macros */
#else /* ! XPG4 */
	'N', 'H', 'S', 'H',				/* -ms macros */
	'H', ' ', 'H', 'U',				/* -mm macros */
	'u', 'h', 's', 'h', '+', 'c'			/* -me macros */
#endif
};
unsigned char	shell[ONMSZ] = {
#ifdef XPG4
	'/', 'u', 's', 'r', '/', 'x', 'p', 'g', '4', '/',
	'b', 'i', 'n', '/', 's', 'h'
};
#else /* ! XPG4 */
	'/', 'b', 'i', 'n', '/', 's', 'h'
};
#endif /* XPG4 */
unsigned char	tags[ONMSZ] = {
	't', 'a', 'g', 's', ' ',
	'/', 'u', 's', 'r', '/', 'l', 'i', 'b', '/', 't', 'a', 'g', 's'
};
unsigned char termtype[ONMSZ];

struct	option options[vi_NOPTS + 1] = {
	(unsigned char *)"autoindent",	(unsigned char *)"ai",	ONOFF,		0,	0,	0,
	(unsigned char *)"autoprint",	(unsigned char *)"ap",	ONOFF,		1,	1,	0,
	(unsigned char *)"autowrite",	(unsigned char *)"aw",	ONOFF,		0,	0,	0,
	(unsigned char *)"beautify",	(unsigned char *)"bf",	ONOFF,		0,	0,	0,
	(unsigned char *)"directory",	(unsigned char *)"dir",	STRING,		0,	0,	direct,
	(unsigned char *)"edcompatible",	(unsigned char *)"ed",	ONOFF,		0,	0,	0,
	(unsigned char *)"errorbells",	(unsigned char *)"eb",	ONOFF,		0,	0,	0,
	(unsigned char *)"exrc",	(unsigned char *)"ex",	ONOFF,		0,	0,	0,
	(unsigned char *)"flash",	(unsigned char *)"fl",	ONOFF,		1,	1,	0,
	(unsigned char *)"hardtabs",	(unsigned char *)"ht",	NUMERIC,	8,	8,	0,
	(unsigned char *)"ignorecase",	(unsigned char *)"ic",	ONOFF,		0,	0,	0,
	(unsigned char *)"lisp",		0,	ONOFF,		0,	0,	0,
	(unsigned char *)"list",		0,	ONOFF,		0,	0,	0,
	(unsigned char *)"magic",	0,	ONOFF,		1,	1,	0,
	(unsigned char *)"mesg",		0,	ONOFF,		1,	1,	0,
	(unsigned char *)"modelines",	(unsigned char *)"ml",	ONOFF,		0,	0,	0,
	(unsigned char *)"number",	(unsigned char *)"nu",	ONOFF,		0,	0,	0,
	(unsigned char *)"novice",	0,	ONOFF,		0,	0,	0,
	(unsigned char *)"optimize",	(unsigned char *)"opt",	ONOFF,		0,	0,	0,
	(unsigned char *)"paragraphs",	(unsigned char *)"para",	STRING,		0,	0,	paragraphs,
	(unsigned char *)"prompt",	0,	ONOFF,		1,	1,	0,
	(unsigned char *)"readonly",	(unsigned char *)"ro",	ONOFF,		0,	0,	0,
	(unsigned char *)"redraw",	0,	ONOFF,		0,	0,	0,
	(unsigned char *)"remap",	0,	ONOFF,		1,	1,	0,
	(unsigned char *)"report",	0,	NUMERIC,	5,	5,	0,
	(unsigned char *)"scroll",	(unsigned char *)"scr",	NUMERIC,	12,	12,	0,
	(unsigned char *)"sections",	(unsigned char *)"sect",	STRING,		0,	0,	sections,
	(unsigned char *)"shell",	(unsigned char *)"sh",	STRING,		0,	0,	shell,
	(unsigned char *)"shiftwidth",	(unsigned char *)"sw",	NUMERIC,	TABS,	TABS,	0,
	(unsigned char *)"showmatch",	(unsigned char *)"sm",	ONOFF,		0,	0,	0,
	(unsigned char *)"showmode",	(unsigned char *)"smd",	ONOFF,		0,	0,	0,
	(unsigned char *)"slowopen",	(unsigned char *)"slow",	ONOFF,		0,	0,	0,
	(unsigned char *)"tabstop",	(unsigned char *)"ts",	NUMERIC,	TABS,	TABS,	0,
	(unsigned char *)"taglength",	(unsigned char *)"tl",	NUMERIC,	0,	0,	0,
	(unsigned char *)"tags",		(unsigned char *)"tag",	STRING,		0,	0,	tags,
#ifdef TAG_STACK
        (unsigned char *)"tagstack",     (unsigned char *)"tgst", ONOFF,          1,      1,      0,
#endif
	(unsigned char *)"term",		0,	OTERM,		0,	0,	termtype,
	(unsigned char *)"terse",	0,	ONOFF,		0,	0,	0,
	(unsigned char *)"timeout",	(unsigned char *)"to",	ONOFF,		1,	1,	0,
	(unsigned char *)"ttytype",	(unsigned char *)"tty",	OTERM,		0,	0,	termtype,
	(unsigned char *)"warn",		0,	ONOFF,		1,	1,	0,
	(unsigned char *)"window",	(unsigned char *)"wi",	NUMERIC,	23,	23,	0,
	(unsigned char *)"wrapscan",	(unsigned char *)"ws",	ONOFF,		1,	1,	0,
	(unsigned char *)"wrapmargin",	(unsigned char *)"wm",	NUMERIC,	0,	0,	0,
	(unsigned char *)"writeany",	(unsigned char *)"wa",	ONOFF,		0,	0,	0,
	0,		0,	0,		0,	0,	0,
};
