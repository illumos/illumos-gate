/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The old LP Spooler would take a job destined for a class of printers
 * if the class was accepting, regardless of the acceptance status of
 * the printers. This sounds a bit silly, so we thought we'd change it.
 * Well, that's not compatible. So YOU decide. Define the following if
 * you want compatibility, don't define it if you want to require BOTH
 * the printers (at least one) and the class to be accepting.
 */
#define CLASS_ACCEPT_PRINTERS_REJECT_SOWHAT 1	/* */

/*
 * Define the following if we should stop examing a list of printers
 * on the first one that meets all the needs of the request.
 * Currently this is done because to continue wouldn't matter. However,
 * you may add additional code that considers other factors (e.g. size
 * of queue for printer, size of file under consideration.)
 */
#define FILTER_EARLY_OUT 1			/* */

typedef struct candidate {
	PSTATUS *		pps;
	char *			slow;
	char *			fast;
	char **			printer_types;
	char *			printer_type;
	char *			output_type;
	unsigned short		flags;
	unsigned short		weight;
}			CANDIDATE;

#define WEIGHT_NOFILTER	 1
#define WEIGHT_FREE	 2
#define	WEIGHT_ENABLED	 4
#define	WEIGHT_MOUNTED	 8
#define WEIGHT_SELECTS	16
#define	WEIGHT_MAX	( \
				WEIGHT_NOFILTER \
			      + WEIGHT_FREE \
			      + WEIGHT_ENABLED \
			      + 2 * WEIGHT_MOUNTED \
			      + WEIGHT_SELECTS \
			)

extern int		pick_filter();

extern char		*o_cpi,
			*o_lpi,
			*o_width,
			*o_length;
