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
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.4 */

typedef struct {
	int flags;
	int curpage;		/* current form page */
	int lastpage;		/* last page of the form */
	int curfield;		/* current field number */
	int numactive;		/* number of active fields */
	char **holdptrs;	/* array of low-level field structures */
	char **mulvals;		/* field specific variables (F1, F2, etc.) */
	struct fm_mn fm_mn;	/* main structure for form descriptors */
	int *visible;		/* list of active/visible fields */
	int *slks;		/* list of SLKS specific to this form */ 
} forminfo;
