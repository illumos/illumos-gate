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
 * Copyright 1991 Sun Microsystems, Inc.  All rights reserved.
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

/*
 * Declarations and constants specific to an installation.
 */

/*
 * mailx -- a modified version of a University of California at Berkeley
 *	mail program
 */

#define	LOCAL		EMPTYID		/* Dynamically determined local host */
#ifdef preSVr4
# define	MAIL	"/bin/rmail"	/* Mail delivery agent */
#else
# define	MAIL	"/usr/bin/rmail"/* Mail delivery agent */
#endif
#define SENDMAIL	"/usr/lib/sendmail"
					/* Name of classy mail deliverer */
#define	EDITOR		"ed"		/* Name of text editor */
#define	VISUAL		"vi"		/* Name of display editor */
#define	PG		(value("PAGER") ? value("PAGER") : \
			    (value("bsdcompat") ? "more" : "pg -e"))
					/* Standard output pager */
#define	MORE		PG
#define	LS		(value("LISTER") ? value("LISTER") : "ls")
					/* Name of directory listing prog*/
#ifdef preSVr4
# define	SHELL	"/bin/sh"	/* Standard shell */
#else
# define	SHELL	"/usr/bin/sh"	/* Standard shell */
#endif
#define	HELPFILE	helppath("mailx.help")
					/* Name of casual help file */
#define	THELPFILE	helppath("mailx.help.~")
					/* Name of casual tilde help */
#ifdef preSVr4
# define	MASTER	(value("bsdcompat") ? libpath("Mail.rc") : \
			    libpath("mailx.rc")
#else
# define	MASTER	(value("bsdcompat") ? "/etc/mail/Mail.rc" : \
			    "/etc/mail/mailx.rc")
#endif
#define	APPEND				/* New mail goes to end of mailbox */
#define CANLOCK				/* Locking protocol actually works */
#define	UTIME				/* System implements utime(2) */
