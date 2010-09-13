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
/*
 * Copyright 1992 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define	vi_AUTOINDENT		0
#define	vi_AUTOPRINT		1
#define	vi_AUTOWRITE		2
#define	vi_BEAUTIFY		3
#define	vi_DIRECTORY		4
#define	vi_EDCOMPATIBLE		5
#define	vi_ERRORBELLS		6
#define	vi_EXRC			7
#define	vi_FLASH		8
#define	vi_HARDTABS		9
#define	vi_IGNORECASE		10
#define	vi_LISP			11
#define	vi_LIST			12
#define	vi_MAGIC		13
#define	vi_MESG			14
#define	vi_MODELINES		15
#define	vi_NUMBER		16
#define	vi_NOVICE		17
#define	vi_OPTIMIZE		18
#define	vi_PARAGRAPHS		19
#define	vi_PROMPT		20
#define	vi_READONLY		21
#define	vi_REDRAW		22
#define	vi_REMAP		23
#define	vi_REPORT		24
#define	vi_SCROLL		25
#define	vi_SECTIONS		26
#define	vi_SHELL		27
#define	vi_SHIFTWIDTH		28
#define	vi_SHOWMATCH		29
#define	vi_SHOWMODE		30
#define	vi_SLOWOPEN		31
#define	vi_TABSTOP		32
#define	vi_TAGLENGTH		33
#define	vi_TAGS			34
#ifdef TAG_STACK
#define vi_TAGSTACK             35
#define vi_TERM                 36
#define vi_TERSE                37
#define vi_TIMEOUT              38
#define vi_TTYTYPE              39
#define vi_WARN                 40
#define vi_WINDOW               41
#define vi_WRAPSCAN             42
#define vi_WRAPMARGIN           43
#define vi_WRITEANY             44
 
#define vi_NOPTS        45
#else
#define vi_TERM                 35
#define vi_TERSE                36
#define vi_TIMEOUT              37
#define vi_TTYTYPE              38
#define vi_WARN                 39
#define vi_WINDOW               40
#define vi_WRAPSCAN             41
#define vi_WRAPMARGIN           42
#define vi_WRITEANY             43
 
#define vi_NOPTS        44
#endif

