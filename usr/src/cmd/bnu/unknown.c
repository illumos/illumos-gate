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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 *	logs attempts by unknown remote machines to run uucico in FOREIGN
 *	("/var/uucp/.Admin/Foreign").  if anything goes wrong,
 *	sends mail to login MAILTO ("uucp").  the executable should be 
 *	placed in /usr/lib/uucp/remote.unknown, and should run setuid-uucp.
 */

#include	<stdio.h>
#include	<sys/types.h>
#include	<time.h>
#include	<errno.h>
#include	"uucp.h"

#define	FOREIGN	"/var/uucp/.Admin/Foreign"
#define	MAILTO	"uucp"
#define	LOGLEN	256

void fall_on_sword();

int
main(argc, argv)
int	argc;
char	*argv[];
{
	char		buf[LOGLEN], *ctoday, *logname, tmpbuf[MAXBASENAME+1];
	FILE		*fp;
	time_t		today;
	extern char	*ctime();
	extern FILE	*fopen();

	if ( argc != 2 ) {
		(void) fprintf(stderr, "USAGE: %s remotename\n", argv[0]);
		exit(101);
	}

	if ( time(&today) != -1 ) {
		ctoday = ctime(&today);
		*(ctoday + strlen(ctoday) - 1) = '\0';	/* no ending \n */
	} else
		ctoday = "NO DATE";

	logname = cuserid((char *) NULL);
	(void) strncpy(tmpbuf, argv[1], MAXBASENAME);
	tmpbuf[MAXBASENAME] = '\0';
	(void) snprintf(buf, sizeof(buf), "%s: call from system %s login %s\n",
		ctoday, tmpbuf, (logname == NULL ? "<unknown>" : logname));

	errno = 0;
	if ( (fp = fopen(FOREIGN, "a+")) == (FILE *)NULL )
		fall_on_sword("cannot open", buf);
	if ( fputs(buf, fp) == EOF )
		fall_on_sword("cannot write", buf);
	if ( fclose(fp) != 0 )
		fall_on_sword("cannot close", buf);

	return (0);
}

/* don't return from here */
void
fall_on_sword(errmsg, logmsg)
char	*errmsg, *logmsg;
{
	char		ebuf[BUFSIZ+1];
	int		fds[2];
	size_t		sz;

	(void) snprintf(ebuf, BUFSIZ,
		"To: %s\nSubject: %s %s\n\n%s %s:\t%s (%d)\nlog msg:\t%s",
		MAILTO, errmsg, FOREIGN, errmsg, FOREIGN,
		strerror(errno), errno, logmsg);
	sz = strlen(ebuf);
	if (ebuf[sz-1] != '\n') {
		ebuf[sz] = '\n';
		ebuf[sz+1] = '\0';
	}

	/* reset to real uid. get a pipe. put error message on	*/
	/* "write end" of pipe, close it. dup "read end" to	*/
	/* stdin and then execl mail (which will read the error	*/
	/* message we just wrote).				*/

	if ( setuid(getuid()) == -1 || pipe(fds) != 0 
	|| write(fds[1], ebuf, strlen(ebuf)) != strlen(ebuf)
	|| close(fds[1]) != 0 )
		exit(errno);

	if ( fds[0] != 0 ) {
		close(0);
		if ( dup(fds[0]) != 0 )
			exit(errno);
	}

	execl("/usr/bin/mail", "mail", MAILTO, (char *) 0);
	exit(errno);	/* shouldn't get here */
}
