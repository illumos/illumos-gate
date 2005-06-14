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

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.1 */

/* Note: this file created with tabstops set to 4.
 *
 * Definitions for the Object Detection Function Table (ODFT, pronounced
 * "oddfoot").  On of these will exist per system, and it defines a set
 * of functions which can be used to detect objects on the system.
 */

#define MAXMAGIC	256			/* max num of magic numbers detectable*/
#define MAXODFT		50			/* max detect functions */

#define IDF_ZLASC	0
#define IDF_ASC		1
#define IDF_PCTRANS	2
#define IDF_TRANS	3
#define IDF_CORE	4
#define IDF_ARCH	5
#define IDF_ENCRYPT	6
/* 7 is not used now */
#define IDF_UNKNOWN	8
#define IDF_MAIL_IN	9
#define IDF_MAIL_OUT	10

struct odft_entry {
	char objtype[OTYPESIZ];			/* the object this detects */
	char *defodi;					/* default odi */
	long defmask;					/* addition to the mask when detected*/
	int	 func_type;					/* what kind of function */
	int  intern_func;				/* index into internal function table*/
	char *extern_func;				/* name of a unix program to detect */
	long *magic_offset;				/* offset into file of magic number*/
	char *magic_bytes;				/* byte of the magic number */
};
