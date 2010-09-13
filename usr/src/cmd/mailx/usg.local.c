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
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
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
 * mailx -- a modified version of a University of California at Berkeley
 *	mail program
 *
 * Local routines that are installation dependent.
 */

#include "rcv.h"

static	int ismailbox(char *file);

/*
 * Locate the user's mailbox file (ie, the place where new, unread
 * mail is queued).  In SVr4 UNIX, it is in /var/mail/name.
 * In preSVr4 UNIX, it is in either /usr/mail/name or /usr/spool/mail/name.
 */
void 
findmail(char *name)
{
	register char *cp;

	if (name != NOSTR) {
		copy(name, copy(maildir, mailname));
		issysmbox = 1;	/* it's a system mailbox */
	} else if ((cp = getenv("MAIL")) != NULL) {
		/* if $MAIL is set, use it */
		nstrcpy(mailname, PATHSIZE, cp);
		issysmbox = ismailbox(mailname);
		/* XXX - should warn that there's no locking? */
	} else {
		copy(myname, copy(maildir, mailname));
		issysmbox = 1;
	}
	if (issysmbox)
		lockname = strrchr(mailname, '/') + 1;
}

/*
 * Make sure file matches (/usr|/var)(/spool)?/mail/.
 * If is does, it's a "system mailbox", return true.
 */
static int
ismailbox(char *file)
{
#ifdef preSVr4
	return (strncmp(file, maildir, strlen(maildir)) == 0);
#else
	if (strncmp(file, "/var", 4) != 0
	    && strncmp(file, "/usr", 4) != 0
	    )
		return (0);
	file += 4;
	if (strncmp(file, "/spool", 6) == 0)
		file += 6;
	return (strncmp(file, "/mail/", 6) == 0);
#endif
}
