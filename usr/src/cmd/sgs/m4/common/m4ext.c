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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	"m4.h"


/* storage params */
int	hshsize 	= 199;		/* hash table size (prime) */
int	bufsize 	= 4096;		/* pushback & arg text buffers */
int	stksize 	= 100;		/* call stack */
int	toksize 	= 512;		/* biggest word ([a-z_][a-z0-9_]*) */


/* pushback buffer */
wchar_t	*ibuf;				/* buffer */
wchar_t	*ibuflm;			/* highest buffer addr */
wchar_t	*ip;				/* current position */
wchar_t	*ipflr;				/* buffer floor */
wchar_t 	*ipstk[10];			/* stack for "ipflr"s */


/* arg collection buffer */
wchar_t	*obuf;				/* buffer */
wchar_t	*obuflm;			/* high address */
wchar_t	*op;				/* current position */


/* call stack */
struct call	*callst;		/* stack */
struct call	*Cp 	= NULL;		/* position */


/* token storage */
wchar_t	*token;				/* buffer */
wchar_t	*toklm;				/* high addr */


/* file name and current line storage for line sync and diagnostics */
char	*fname[11];			/* file name ptr stack */
int	fline[10];			/* current line nbr stack */


/* input file stuff for "include"s */
FILE	*ifile[10] 	= {stdin};	/* stack */
int	ifx;				/* stack index */
ibuf_t	ibuffer[11];			/* input buffer */

/* stuff for output diversions */
FILE	*cf 	= stdout;		/* current output file */
FILE	*ofile[11] 	= {stdout};	/* output file stack */
int	ofx;				/* stack index */


/* comment markers */
wchar_t	lcom[MAXSYM+1] 	= L"#";
wchar_t	rcom[MAXSYM+1] 	= L"\n";


/* quote markers */
wchar_t	lquote[MAXSYM+1]  = L"`";
wchar_t	rquote[MAXSYM+1]  = L"\'";


/* argument ptr stack */
wchar_t	**argstk;
wchar_t	*astklm;			/* high address */
wchar_t	**Ap;				/* current position */


/* symbol table */
struct nlist	**hshtab;		/* hash table */
unsigned int	hshval;			/* last hash val */


/* misc */
char	*procnam;			/* argv[0] */
char	*tempfile;			/* used for diversion files */
struct	Wrap *wrapstart = NULL;	/* first entry in of list of "m4wrap" strings */
wchar_t	nullstr[] 	= {0};
int	nflag 	= 1;			/* name flag, used for line sync code */
int	sflag;				/* line sync flag */
int	sysrval;			/* return val from syscmd */
int	trace;				/* global trace flag */
int	exitstat = OK;			/* global exit status */
int	wide;				/* multi-byte locale */
