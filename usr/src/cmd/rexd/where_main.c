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
 *
 * Copyright 1992 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/param.h>

static char **Argv;		/* saved argument vector (for ps) */
static char *LastArgv;		/* saved end-of-argument vector */

int child = 0;			/* pid of the executed process */
int ChildDied = 0;		/* true when above is valid */
int HasHelper = 0;		/* must kill helpers (interactive mode) */


int	Debug = 0;


void
main(argc, argv)
	char **argv;
{
	char host[MAXPATHLEN];
	char fsname[MAXPATHLEN];
	char within[MAXPATHLEN];
	char *pn;
	int many;

	/*
	 * argv start and extent for setproctitle()
	 */
	Argv = argv;
	if (argc > 0)
		LastArgv = argv[argc-1] + strlen(argv[argc-1]);
	else
		LastArgv = NULL;

	many = argc > 2;
	while (--argc > 0) {

		if ( strcmp( "-d", *argv ) == 0 )
		{
			Debug = 1;
			argv++;
			continue;
		}
		pn = *++argv;
		where(pn, host, fsname, within);
		if (many)
			printf("%s:\t", pn);
		printf("%s:%s%s\n", host, fsname, within);
	}
	exit(0);
	/* NOTREACHED */
}

/*
 *  SETPROCTITLE -- set the title of this process for "ps"
 *
 *	Does nothing if there were not enough arguments on the command
 * 	line for the information.
 *
 *	Side Effects:
 *		Clobbers argv[] of our main procedure.
 */
void
setproctitle(user, host)
	char *user, *host;
{
	register char *tohere;

	tohere = Argv[0];
	if (LastArgv == NULL || 
			strlen(user)+strlen(host)+3 > (LastArgv - tohere))
		return;
	*tohere++ = '-';		/* So ps prints (rpc.rexd)	*/
	sprintf(tohere, "%s@%s", user, host);
	while (*tohere++)		/* Skip to end of printf output	*/
		;
	while (tohere < LastArgv)	/* Avoid confusing ps		*/
		*tohere++ = ' ';
}
