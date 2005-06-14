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
 * Definitions for the Object Operations Table (OOT).  One exists
 * per system, and it defines all the available object operations by
 * OEH number.
 */

#define OPERNAMESIZ	15			/* size of an operation's name */

#define MAX_TYPES	12		/* maximum number of object types in-core */
#define MAX_OPERS	22		/* maximum number of operations per object */

#define NOBUT		-1		/* function not on a label */

/* The following defines are for the func_type field */

#define F_NOP	0x01		/* no operation required */
#define F_ILL	0x02		/* illegal operation */
#define F_NULL	0x03		/* null operation, end of operations */
#define F_INT	0x04		/* internal operation */
#define F_SHELL	0x05		/* fork with shell */
#define F_EXEC  0x06		/* fork with no shell */
#define	F_PARTS	0x07		/* internal parts function (for heuristics) */
#define F_DPARTS	0x08	/* internal directory parts function (ditto) */
#define F_MAGIC	0x09		/* magic number detection (ditto) */

/* the following defines are for the op_type field */

#define OP_SNG	0x01		/* single argument */
#define OP_NEW	0x02		/* new object name */
#define OP_BUT  0x04		/* last label the user selected */
#define OP_DIR	0x08		/* existing directory name */
#define OP_OLD	0x10		/* existing file */
#define OP_CUR	0x20		/* existing item in CURRENT dir */

struct operation {
	char *opername;				/* operation name */
	int  but;					/* label it goes on */
	int  func_type;				/* kind of function */
	int	 intern_func;			/* internal function index */
	char *extern_func;			/* external function name */
	int  op_type;				/* operation type */
	bool multiple;				/* true/false value */
	long all_mask;				/* function available only if all present*/
	long none_mask;				/* function available only if none present*/
	char *perms;				/* permissions */
};
