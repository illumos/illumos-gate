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
 * Copyright (c) 1985-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

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

#include "rcv.h"
#include <pwd.h>
#include <locale.h>

#ifdef preSVr4
extern struct passwd *getpwnam();
extern struct passwd *getpwuid();
#endif

/*
 * mailx -- a modified version of a University of California at Berkeley
 *	mail program
 *
 * Give names to all the temporary files that we will need.
 */

void
tinit(void)
{
	register pid_t pid = mypid;
	struct passwd *pwd;


	snprintf(tempMail, TMPSIZ, "/tmp/Rs%-ld", pid);
	snprintf(tempQuit, TMPSIZ, "/tmp/Rm%-ld", pid);
	snprintf(tempEdit, TMPSIZ, "/tmp/Re%-ld", pid);
	snprintf(tempMesg, TMPSIZ, "/tmp/Rx%-ld", pid);
	snprintf(tempZedit, TMPSIZ, "/tmp/Rz%-ld", pid);

	/* get the name associated with this uid */
	pwd = getpwuid(uid = myruid);
	if (!pwd) {
		printf(gettext("Error looking up username for uid=%d\n"), uid);
		exit(1);
	}
	else
		copy(pwd->pw_name, myname);
	endpwent();

	nstrcpy(homedir, PATHSIZE, Getf("HOME"));
	findmail(NULL);
	assign("MBOX", Getf("MBOX"));
	assign("MAILRC", Getf("MAILRC"));
	assign("DEAD", Getf("DEAD"));
	assign("save", "");
	assign("asksub", "");
	assign("header", "");
	assign("prompt", "? ");
	assign("pipeignore", "");
	assign("replyall", "");
	assign("from", "");
	assign("fcc", "");
}
