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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#include "libmail.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <utmpx.h>
#include <syslog.h>
#if !defined(__cplusplus) && !defined(c_plusplus)
typedef void (*SIG_PF) (int);
#endif
#include <unistd.h>
#include <signal.h>

static void
catcher(int arg __unused)
{
	/* do nothing, but allow the write() to break */
}

void
notify(char *user, char *msg, int check_mesg_y, char *etcdir)
{
	/* search the utmp file for this user */
	SIG_PF old;
	unsigned int oldalarm;
	struct utmpx utmpx, *putmpx = &utmpx;

	setutxent();

	/* grab the tty name */
	while ((putmpx = getutxent()) != NULL) {
		if (strncmp(user, utmpx.ut_name,
		    sizeof (utmpx.ut_name)) == 0) {
			char tty[sizeof (utmpx.ut_line)+1];
			char dev[MAXFILENAME];
			FILE *port;
			size_t i;
			int fd;

			for (i = 0; i < sizeof (utmpx.ut_line); i++)
				tty[i] = utmpx.ut_line[i];
			tty[i] = '\0';

			/* stick /dev/ in front */
			(void) sprintf(dev, "%s/dev/%s", etcdir, tty);

			/* break out if write() to the tty hangs */
			old = (SIG_PF)signal(SIGALRM, catcher);
			oldalarm = alarm(300);

			/* check if device is really a tty */
			if ((fd = open(dev, O_WRONLY|O_NOCTTY)) == -1) {
				(void) fprintf(stderr,
				    "Cannot open %s.\n", dev);
				continue;
			} else {
				if (!isatty(fd)) {
					(void) fprintf(stderr, "%s in utmpx is "
					    "not a tty\n", tty);
					openlog("mail", 0, LOG_AUTH);
					syslog(LOG_CRIT, "%s in utmp is "
					    "not a tty\n", tty);
					closelog();
					(void) close(fd);
					continue;
				}
			}
			(void) close(fd);

			/* write to the tty */
			port = fopen(dev, "w");
			if (port != 0) {
				(void) fprintf(port, "\r\n%s\r\n", msg);
				(void) fclose(port);
			}

			/* clean up our alarm */
			(void) alarm(0);
			(void) signal(SIGALRM, old);
			(void) alarm(oldalarm);
		}
	}
	endutxent();
}
