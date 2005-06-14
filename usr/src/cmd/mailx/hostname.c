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
 * Code to figure out what host we are on.
 */

#include "rcv.h"
#include "configdefs.h"
#include <sys/utsname.h>
#include <locale.h>

#define	MAILCNFG	"/etc/mail/mailcnfg"

char host[64];
char domain[128];
/*
 * Initialize the network name of the current host.
 */
void 
inithost(void)
{
	register struct netmach *np;
	struct utsname name;
	char *fp;

	xsetenv(MAILCNFG);
	if (fp = xgetenv("CLUSTER")) {
		nstrcpy(host, sizeof (host), fp);
	} else {
		uname(&name);
		nstrcpy(host, sizeof (host), name.nodename);
	}
	snprintf(domain, sizeof (domain), "%s%s", host, maildomain());
	for (np = netmach; np->nt_machine != 0; np++)
		if (strcmp(np->nt_machine, EMPTY) == 0)
			break;
	if (np->nt_machine == 0) {
		printf(
		    gettext("Cannot find empty slot for dynamic host entry\n"));
		exit(1);
	}
	np->nt_machine = host;
	np++;
	np->nt_machine = domain;
	if (debug) fprintf(stderr, "host '%s', domain '%s'\n", host, domain);
}
