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
#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.6	*/
/*
 * The current implementation of the argument list is poor,
 * using an argv even for internally done "next" commands.
 * It is not hard to see that this is restrictive and a waste of
 * space.  The statically allocated glob structure could be replaced
 * by a dynamically allocated argument area space.
 */
var unsigned char	**argv;
var unsigned char	**argv0;
var unsigned char	*args;
var unsigned char	*args0;
var short	argc;
var short	argc0;
var short	morargc;		/* Used with "More files to edit..." */

var int	firstln;		/* From +lineno */
var unsigned char	*firstpat;		/* From +/pat	*/

struct	glob {
	short	argc;			/* Index of current file in argv */
	short	argc0;			/* Number of arguments in argv */
	unsigned char	*argv[NARGS + 1];	/* WHAT A WASTE! */
	unsigned char	argspac[NCARGS + sizeof (int)];
};
var struct	glob frob;
