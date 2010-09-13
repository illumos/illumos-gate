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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<ctype.h>
#include	<string.h>
#include	<stdio.h>
#include	<signal.h>
#include	<sys/wait.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<time.h>
#include	<utmpx.h>
#include	<pwd.h>
#include	<fcntl.h>
#include	<stdarg.h>
#include	<locale.h>
#include	<stdlib.h>
#include	<limits.h>
#include	<wctype.h>
#include	<errno.h>
#include	<syslog.h>

#define		TRUE	1
#define		FALSE	0
#define		FAILURE	-1
/*
 *	DATE-TIME format
 *  %a	abbreviated weekday name
 *  %b  abbreviated month name
 *  %e  day of month
 *  %H  hour - 24 hour clock
 *  %M  minute
 *  %S  second
 *
 */

extern char myhostname[];
extern char progname[];


static void openfail(int);
static void eof(void);
static void setsignals(void (*)());

static FILE	*fp;	/* File pointer for receipient's terminal */
static char *rterm; /* Pointer to receipient's terminal */

int
warn_send(char *receipient, char *msg)
{
	register struct utmpx *ubuf;
	static char rterminal[] = "/dev/\0 2345678901";
	extern FILE *fp;
	time_t tod;
	char time_buf[40];
	register int bad = 0;
	char	*rcp1, *rcp2, *rcp3;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);


/*	Set "rterm" to location where receipient's terminal will go.	*/

	rterm = &rterminal[sizeof ("/dev/") - 1];

/*
 * strip any realm or instance from principal so we can match against unix
 * userid.
 */
	rcp1 = strdup(receipient);
	rcp2 = strtok(rcp1, "@");
	rcp3 = strtok(rcp2, "/");

/*
 *	Scan through the "utmpx" file for the
 *	entry for the person we want to send to.
 */

	setutxent();
	while ((ubuf = getutxent()) != NULL) {
		if (ubuf->ut_type == USER_PROCESS) {
			if (strncmp(rcp3, ubuf->ut_user,
				sizeof (ubuf->ut_user)) == 0) {
				strncpy(rterm, &ubuf->ut_line[0],
					sizeof (ubuf->ut_line)+1);

/*	Try to open up the line to the receipient's terminal.		*/

				signal(SIGALRM, openfail);
				alarm(5);
				fp = fopen(&rterminal[0], "w");
				alarm(0);

/*	Catch signals SIGHUP, SIGINT, SIGQUIT, and SIGTERM, and send	*/
/*	<EOT> message to receipient.			*/

				setsignals(eof);

/*	Get the time of day, convert it to a string and throw away the	*/
/*	year information at the end of the string.			*/

				time(&tod);
				cftime(time_buf, "%c", &tod);
				(void) fprintf(fp, gettext(
	    "\r\n\007\007\007\tMessage from %s@%s [ %s ] ...\r\n"),
					    progname, myhostname, time_buf);
				sleep(1);
				fprintf(fp, gettext("\r\nMessage to %s"), msg);
				fflush(fp);

/*	Since "end of file" received, send <EOT> message to receipient.	*/

				eof();
				fclose(fp);
			}
		}
	}
	free(rcp1);


/*	Did we find a place to talk to?  If we were looking for a */
/*	specific spot and didn't find it, complain and log it. */

	if (*rterm == '\0')
		if (bad > 0) {
			(void) syslog(LOG_ERR, gettext("no place to send.\n"));
			return (1);
		}

	endutxent();
	return (0);
}

static void
setsignals(catch)
void (*catch)();
{
	signal(SIGHUP, catch);
	signal(SIGINT, catch);
	signal(SIGQUIT, catch);
	signal(SIGTERM, catch);
}
static void
openfail(int i)
{
	extern char *rterm;
#if 0
	(void) fprintf(stderr,
		gettext("Timeout trying to open line(%s).\n"),
			rterm);
#endif
	syslog(LOG_ERR, gettext("Timeout trying to open line(%s).\n"),
			rterm ? rterm : "");
	exit(1);
}

static void
eof(void)
{
	extern FILE *fp;

	(void) fprintf(fp, "%s\r\n", gettext("<EOT>"));
}
