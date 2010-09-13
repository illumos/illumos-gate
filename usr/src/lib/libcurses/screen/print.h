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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */


#ifndef	_PRINT_H
#define	_PRINT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* externs from iexpand.c, cexpand.c */
extern void tpr(FILE *, char *);
extern int cpr(FILE *, char *);
extern char *cexpand(char *), *iexpand(char *),
		*cconvert(char *), *rmpadding(char *, char *, int *);

/* externs from print.c */
enum printtypes
	{
    pr_none,
    pr_terminfo,		/* print terminfo listing */
    pr_cap,			/* print termcap listing */
    pr_longnames		/* print C variable name listing */
};

extern void pr_onecolumn(int);
extern void pr_caprestrict(int);
extern void pr_width(int);
extern void pr_init(enum printtypes);
extern void pr_heading(char *, char *);
extern void pr_bheading(void);
extern void pr_boolean(char *, char *, char *, int);
extern void pr_bfooting(void);
extern void pr_nheading(void);
extern void pr_number(char *, char *, char *, int);
extern void pr_nfooting(void);
extern void pr_sheading(void);
extern void pr_string(char *, char *, char *, char *);
extern void pr_sfooting(void);
extern char *progname;

#ifdef	__cplusplus
}
#endif

#endif	/* _PRINT_H */
