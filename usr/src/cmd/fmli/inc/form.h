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
 *
 */

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.4 */

typedef struct {
	char *name;		/* contents of "name" descriptor */
	char *value;		/* contents of "value" descriptor */
	int frow;		/* contents of "frow" descriptor */
	int fcol;		/* contents of "fcol" descriptor */
	int nrow;		/* contents of "nrow" descriptor */
	int ncol;		/* contents of "ncol" descriptor */
	int rows;		/* contents of "rows" descriptor */
	int cols;		/* contents of "cols" descriptor */
	int flags;		/* flags set according to the values of
				   "field related" boolean descriptors
				   (scroll, edit, etc. see winp.h) */
	char **ptr;		/* object dependent pointer to low 
				   level field structure (ifield) */ 
} formfield;

struct form {
	formfield (*display)();	/* display function of object */
	char *	  argptr;	/* (object dependent) arg passed "display" */
	vt_id	  vid;		/* virtual terminal number */
	int	  curfldnum;	/* current field num */
	int	  flags;	/* misc. flags (listed below) */
	int	  rows;		/* number of rows in form */
	int	  cols;		/* number of columns in form */
};

#define FORM_USED	1
#define FORM_DIRTY	2	/* contents of form changed */
#define FORM_ALLDIRTY	4	/* form has been reshaped or moved */

extern form_id		FORM_curid;
extern struct form	*FORM_array;
