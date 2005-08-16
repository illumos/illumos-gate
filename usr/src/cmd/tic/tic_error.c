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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
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

/*
 *			COPYRIGHT NOTICE
 *
 *	This software is copyright(C) 1982 by Pavel Curtis
 *
 *	Permission is granted to reproduce and distribute
 *	this file by any means so long as no fee is charged
 *	above a nominal handling fee and so long as this
 *	notice is always included in the copies.
 *
 *	Other rights are reserved except as explicitly granted
 *	by written permission of the author.
 *		Pavel Curtis
 *		Computer Science Dept.
 *		405 Upson Hall
 *		Cornell University
 *		Ithaca, NY 14853
 *
 *		Ph- (607) 256-4934
 *
 *		Pavel.Cornell@Udel-Relay(ARPAnet)
 *		decvax!cornell!pavel(UUCPnet)
 */

/*
 *	tic_error.c -- Error message routines
 *
 *  $Log:	RCS/tic_error.v $
 * Revision 2.1  82/10/25  14:45:31  pavel
 * Added Copyright Notice
 *
 * Revision 2.0  82/10/24  15:16:32  pavel
 * Beta-one Test Release
 *
 * Revision 1.3  82/08/23  22:29:31  pavel
 * The REAL Alpha-one Release Version
 *
 * Revision 1.2  82/08/19  19:09:44  pavel
 * Alpha Test Release One
 *
 * Revision 1.1  82/08/12  18:36:02  pavel
 * Initial revision
 *
 *
 */

#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>

#include "compiler.h"

extern char *string_table;
extern short term_names;
extern char *progname;

/* VARARGS1 */
void
warning(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	fprintf(stderr, "%s: Warning: near line %d: ", progname, curr_line);
	if (string_table != NULL) {
		fprintf(stderr, "terminal '%s', ", string_table+term_names);
	}
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
	va_end(args);
}


/* VARARGS1 */
void
err_abort(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	fprintf(stderr, "%s: Line %d: ", progname, curr_line);
	if (string_table != NULL) {
		fprintf(stderr, "terminal '%s', ", string_table+term_names);
	}
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
	va_end(args);
	exit(1);
}


/* VARARGS1 */
void
syserr_abort(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	fprintf(stderr, "PROGRAM ERROR: Line %d: ", curr_line);
	if (string_table != NULL) {
		fprintf(stderr, "terminal '%s', ", string_table+term_names);
	}
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
	fprintf(stderr, "*** Possibly corrupted terminfo file ***\n");
	va_end(args);
	exit(1);
}
