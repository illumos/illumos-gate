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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<ctype.h>
#include	<string.h>
#include	<stdio.h>
#include	<signal.h>
#include	<sys/wait.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/utsname.h>
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
#define		DATE_FMT	"%a %b %e %H:%M:%S"
#define		UTMP_HACK  /* work around until utmpx is world writable */
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

static int permit1(int);
static int permit(char *);
static int readcsi(int, char *, int);
static void setsignals();
static void shellcmd(char *);
static void openfail();
static void eof();

static struct	utsname utsn;

static FILE	*fp;	/* File pointer for receipient's terminal */
static char *rterm, *receipient; /* Pointer to receipient's terminal & name */
static char *thissys;

int
main(int argc, char **argv)
{
	int i;
	struct utmpx *ubuf;
	static struct utmpx self;
	char ownname[sizeof (self.ut_user) + 1];
	static char rterminal[sizeof ("/dev/") + sizeof (self.ut_line)] =
	    "/dev/";
	extern char *rterm, *receipient;
	char *terminal, *ownterminal, *oterminal;
	short count;
	extern FILE *fp;
	char input[134+MB_LEN_MAX];
	char *ptr;
	time_t tod;
	char time_buf[40];
	struct passwd *passptr;
	char badterm[20][20];
	int bad = 0;
	uid_t	myuid;
	char *bp;
	int n;
	wchar_t wc;
	int c;
	int newline;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "")) != EOF)
		switch (c) {
			case '?':
				(void) fprintf(stderr, "Usage: write %s\n",
				gettext("user_name [terminal]"));
				exit(2);
		}
	myuid = geteuid();
	uname(&utsn);
	thissys = utsn.nodename;

/*	Set "rterm" to location where receipient's terminal will go.	*/

	rterm = &rterminal[sizeof ("/dev/") - 1];
	terminal = NULL;

	if (--argc <= 0) {
	    (void) fprintf(stderr, "Usage: write %s\n",
		gettext("user_name [terminal]"));
	    exit(1);
	    }
	else
	    {
	    receipient = *++argv;
	    }

/*	Was a terminal name supplied?  If so, save it.			*/

	if (--argc > 1) {
	    (void) fprintf(stderr, "Usage: write %s\n",
		gettext("user_name [terminal]"));
	    exit(1);
	} else {
	    terminal = *++argv;
	}

/*	One of the standard file descriptors must be attached to a	*/
/*	terminal in "/dev".						*/

	if ((ownterminal = ttyname(fileno(stdin))) == NULL &&
	    (ownterminal = ttyname(fileno(stdout))) == NULL &&
	    (ownterminal = ttyname(fileno(stderr))) == NULL) {
		(void) fprintf(stderr,
			gettext("I cannot determine your terminal name."
					" No reply possible.\n"));
		ownterminal = "/dev/???";
	}

	/*
	 * Set "ownterminal" past the "/dev/" at the beginning of
	 * the device name.
	 */
	oterminal = ownterminal + sizeof ("/dev/")-1;

	/*
	 * Scan through the "utmpx" file for your own entry and the
	 * entry for the person we want to send to.
	 */
	for (self.ut_pid = 0, count = 0; (ubuf = getutxent()) != NULL; ) {
	/* Is this a USER_PROCESS entry? */

	    if (ubuf->ut_type == USER_PROCESS) {
/*	Is it our entry?  (ie.  The line matches ours?)			*/

		if (strncmp(&ubuf->ut_line[0], oterminal,
		    sizeof (ubuf->ut_line)) == 0) self = *ubuf;

/*	Is this the person we want to send to?				*/

		if (strncmp(receipient, &ubuf->ut_user[0],
		    sizeof (ubuf->ut_user)) == 0) {
/*	If a terminal name was supplied, is this login at the correct	*/
/*	terminal?  If not, ignore.  If it is right place, copy over the	*/
/*	name.								*/

		    if (terminal != NULL) {
			if (strncmp(terminal, &ubuf->ut_line[0],
			    sizeof (ubuf->ut_line)) == 0) {
			    strlcpy(rterm, &ubuf->ut_line[0],
				sizeof (rterminal) - (rterm - rterminal));
			    if (myuid && !permit(rterminal)) {
				bad++;
				rterm[0] = '\0';
			    }
			    }
		    }

/*	If no terminal was supplied, then take this terminal if no	*/
/*	other terminal has been encountered already.			*/

		    else
		    {
/*	If this is the first encounter, copy the string into		*/
/*	"rterminal".							*/

			if (*rterm == '\0') {
			    strlcpy(rterm, &ubuf->ut_line[0],
				sizeof (rterminal) - (rterm - rterminal));
			    if (myuid && !permit(rterminal)) {
				if (bad < 20) {
					strlcpy(badterm[bad++], rterm,
					    sizeof (badterm[bad++]));
				}
				rterm[0] = '\0';
			    } else if (bad > 0) {
				(void) fprintf(stderr,
				gettext(
				"%s is logged on more than one place.\n"
	"You are connected to \"%s\".\nOther locations are:\n"),
				    receipient, rterm);
				for (i = 0; i < bad; i++)
				    (void) fprintf(stderr, "%s\n", badterm[i]);
			    }
			}

/*	If this is the second terminal, print out the first.  In all	*/
/*	cases of multiple terminals, list out all the other terminals	*/
/*	so the user can restart knowing what their choices are.		*/

			else if (terminal == NULL) {
			    if (count == 1 && bad == 0) {
				(void) fprintf(stderr,
				gettext(
				"%s is logged on more than one place.\n"
	"You are connected to \"%s\".\nOther locations are:\n"),
				    receipient, rterm);
			    }
			    fwrite(&ubuf->ut_line[0], sizeof (ubuf->ut_line),
				1, stderr);
			    (void) fprintf(stderr, "\n");
			    }

			count++;
		    }			/* End of "else" */
		    }			/* End of "else if (strncmp" */
	    }			/* End of "if (USER_PROCESS" */
	    }		/* End of "for(count=0" */

/*	Did we find a place to talk to?  If we were looking for a	*/
/*	specific spot and didn't find it, complain and quit.		*/

	if (terminal != NULL && *rterm == '\0') {
	    if (bad > 0) {
		(void) fprintf(stderr, gettext("Permission denied.\n"));
		exit(1);
		} else {
#ifdef UTMP_HACK
		if (strlcat(rterminal, terminal, sizeof (rterminal)) >=
		    sizeof (rterminal)) {
			(void) fprintf(stderr,
			    gettext("Terminal name too long.\n"));
			exit(1);
		}
		if (self.ut_pid == 0) {
			if ((passptr = getpwuid(getuid())) == NULL) {
			    (void) fprintf(stderr,
				gettext("Cannot determine who you are.\n"));
			    exit(1);
		    }
		    (void) strlcpy(&ownname[0], &passptr->pw_name[0],
			sizeof (ownname));
		} else {
			(void) strlcpy(&ownname[0], self.ut_user,
			    sizeof (self.ut_user));
		}
		if (!permit(rterminal)) {
			(void) fprintf(stderr,
				gettext("%s permission denied\n"), terminal);
			exit(1);
		}
#else
		(void) fprintf(stderr, gettext("%s is not at \"%s\".\n"),
			receipient, terminal);
		exit(1);
#endif	/* UTMP_HACK */
	    }
	    }

/*	If we were just looking for anyplace to talk and didn't find	*/
/*	one, complain and quit.						*/
/*	If permissions prevent us from sending to this person - exit	*/

	else if (*rterm == '\0') {
	    if (bad > 0)
		(void) fprintf(stderr, gettext("Permission denied.\n"));
	    else
		(void) fprintf(stderr,
			gettext("%s is not logged on.\n"), receipient);
	    exit(1);
	    }

/*	Did we find our own entry?					*/

	else if (self.ut_pid == 0) {
/*	Use the user id instead of utmp name if the entry in the	*/
/*	utmp file couldn't be found.					*/

	    if ((passptr = getpwuid(getuid())) == (struct passwd *)NULL) {
		(void) fprintf(stderr,
			gettext("Cannot determine who you are.\n"));
		exit(1);
	    }
	    strncpy(&ownname[0], &passptr->pw_name[0], sizeof (ownname));
	    }
	else
	    {
	    strncpy(&ownname[0], self.ut_user, sizeof (self.ut_user));
	    }
	ownname[sizeof (ownname)-1] = '\0';

	if (!permit1(1))
		(void) fprintf(stderr,
		gettext("Warning: You have your terminal set to \"mesg -n\"."
		    " No reply possible.\n"));
/*	Close the utmpx files.						*/

	endutxent();

/*	Try to open up the line to the receipient's terminal.		*/

	signal(SIGALRM, openfail);
	alarm(5);
	fp = fopen(&rterminal[0], "w");
	alarm(0);

/*	Make sure executed subshell doesn't inherit this fd - close-on-exec */

	if (fcntl(fileno(fp), F_SETFD, FD_CLOEXEC) < 0)  {
		perror("fcntl(F_SETFD)");
		exit(1);
	}

/*	Catch signals SIGHUP, SIGINT, SIGQUIT, and SIGTERM, and send	*/
/*	<EOT> message to receipient before dying away.			*/

	setsignals(eof);

/*	Get the time of day, convert it to a string and throw away the	*/
/*	year information at the end of the string.			*/

	time(&tod);
	(void) strftime(time_buf, sizeof (time_buf),
	    dcgettext(NULL, DATE_FMT, LC_TIME), localtime(&tod));

	(void) fprintf(fp,
	gettext("\n\007\007\007\tMessage from %s on %s (%s) [ %s ] ...\n"),
	    &ownname[0], thissys, oterminal, time_buf);
	fflush(fp);
	(void) fprintf(stderr, "\007\007");

/*	Get input from user and send to receipient unless it begins	*/
/*	with a !, when it is to be a shell command.			*/
	newline = 1;
	while ((i = readcsi(0, &input[0], sizeof (input))) > 0) {
		ptr = &input[0];
/*	Is this a shell command?					*/

		if ((newline) && (*ptr == '!'))
			shellcmd(++ptr);

/*	Send line to the receipient.					*/

		else {
			if (myuid && !permit1(fileno(fp))) {
				(void) fprintf(stderr,
			gettext("Can no longer write to %s\n"), rterminal);
				break;
			}

/*
 * All non-printable characters are displayed using a special notation:
 * Control characters  shall be displayed using the two character
 * sequence of ^ (carat) and the ASCII character - decimal 64 greater
 * that the character being encoded - eg., a \003 is displayed ^C.
 * Characters with the eighth bit set shall be displayed using
 * the three or four character meta notation - e.g., \372 is
 * displayed M-z and \203 is displayed M-^C.
 */

			newline = 0;
			for (bp = &input[0]; --i >= 0; bp++) {
			if (*bp == '\n') {
				newline = 1;
				putc('\r', fp);
			}
			if (*bp == ' ' ||
				 *bp == '\t' || *bp == '\n' ||
				 *bp == '\r' || *bp == '\013' ||
				 *bp == '\007') {
					putc(*bp, fp);
			} else if (((n = mbtowc(&wc, bp, MB_CUR_MAX)) > 0) &&
				iswprint(wc)) {
				for (; n > 0; --n, --i, ++bp)
					putc(*bp, fp);
				bp--, ++i;
			} else {
				if (!isascii(*bp)) {
					fputs("M-", fp);
					*bp = toascii(*bp);
				}
				if (iscntrl(*bp)) {
					putc('^', fp);
/*	add decimal 64 to the control character			*/
					putc(*bp + 0100, fp);
				}
				else
					putc(*bp, fp);
			}
			if (*bp == '\n')
				fflush(fp);
			if (ferror(fp) || feof(fp)) {
				printf(gettext(
				"\n\007Write failed (%s logged out?)\n"),
				receipient);
				exit(1);
			}
			} /* for */
			fflush(fp);
	} /* else */
	} /* while */

/*	Since "end of file" received, send <EOT> message to receipient.	*/

	eof();
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
shellcmd(command)
char *command;
{
	register pid_t child;
	extern void eof();

	if ((child = fork()) == (pid_t)FAILURE)
	    {
	    (void) fprintf(stderr,
	    gettext("Unable to fork.  Try again later.\n"));
	    return;
	    } else if (child == (pid_t)0) {
/*	Reset the signals to the default actions and exec a shell.	*/

	    if (setgid(getgid()) < 0)
		exit(1);
	    execl("/usr/bin/sh", "sh", "-c", command, 0);
	    exit(0);
	    }
	else
	    {
/*	Allow user to type <del> and <quit> without dying during	*/
/*	commands.							*/

	    signal(SIGINT, SIG_IGN);
	    signal(SIGQUIT, SIG_IGN);

/*	As parent wait around for user to finish spunoff command.	*/

	    while (wait(NULL) != child);

/*	Reset the signals to their normal state.			*/

	    setsignals(eof);
	    }
	(void) fprintf(stdout, "!\n");
}

static void
openfail()
{
	extern char *rterm, *receipient;

	(void) fprintf(stderr,
		gettext("Timeout trying to open %s's line(%s).\n"),
	    receipient, rterm);
	exit(1);
}

static void
eof()
{
	extern FILE *fp;

	(void) fprintf(fp, "%s\n", gettext("<EOT>"));
	exit(0);
}

/*
 * permit: check mode of terminal - if not writable by all disallow writing to
 * (even the user cannot therefore write to their own tty)
 */

static int
permit(term)
char *term;
{
	struct stat buf;
	int fildes;

	if ((fildes = open(term, O_WRONLY|O_NOCTTY)) < 0)
		return (0);
	/* check if the device really is a tty */
	if (!isatty(fildes)) {
		(void) fprintf(stderr,
		    gettext("%s in utmpx is not a tty\n"), term);
		openlog("write", 0, LOG_AUTH);
		syslog(LOG_CRIT, "%s in utmpx is not a tty\n", term);
		closelog();
		close(fildes);
		return (0);
	}
	fstat(fildes, &buf);
	close(fildes);
	return (buf.st_mode & (S_IWGRP|S_IWOTH));
}



/*
 * permit1: check mode of terminal - if not writable by all disallow writing
 * to (even the user themself cannot therefore write to their own tty)
 */

/* this is used with fstat (which is faster than stat) where possible */

static int
permit1(fildes)
int fildes;
{
	struct stat buf;

	fstat(fildes, &buf);
	return (buf.st_mode & (S_IWGRP|S_IWOTH));
}


/*
 * Read a string of multi-byte characters from specified file.
 * The requested # of bytes are attempted to read.
 * readcsi() tries to complete the last multibyte character
 * by calling mbtowc(), if the leftovers form mbtowc(),
 * left the last char imcomplete, moves into delta_spool to use later,
 * next called. The caller must reserve
 * nbytereq+MB_LEN_MAX bytes for the buffer.  When the attempt
 * is failed, it truncate the last char.
 * Returns the number of bytes that constitutes the valid multi-byte characters.
 */


static int readcsi(d, buf, nbytereq)
int	d;
char	*buf;
int	nbytereq;
{
	static char	delta_pool[MB_LEN_MAX * 2];
	static char	delta_size;
	char	*cp, *nextp, *lastp;
	int	n;
	int	r_size;

	if (delta_size) {
		memcpy(buf, delta_pool, delta_size);
		cp = buf + delta_size;
		r_size = nbytereq - delta_size;
	} else {
		cp = buf;
		r_size = nbytereq;
	}

	if ((r_size = read(d, cp, r_size)) < 0)
		r_size = 0;
	if ((n = delta_size + r_size) <= 0)
		return (n);

	/* Scan the result to test the completeness of each EUC characters. */
	nextp = buf;
	lastp = buf + n; /* Lastp points to the first junk byte. */
	while (nextp < lastp) {
		if ((n = (lastp - nextp)) > (unsigned int)MB_CUR_MAX)
			n = (unsigned int)MB_CUR_MAX;
		if ((n = mbtowc((wchar_t *)0, nextp, n)) <= 0) {
			if ((lastp - nextp) < (unsigned int)MB_CUR_MAX)
				break;
			n = 1;
		}
		nextp += n;
	}
	/* How many bytes needed to complete the last char? */
	delta_size = lastp - nextp;
	if (delta_size > 0) {
		if (nextp[delta_size - 1] != '\n') {
			/* the remnants store into delta_pool */
			memcpy(delta_pool, nextp, delta_size);
		} else
			nextp = lastp;
	}
	*nextp = '\0';
	return (nextp-buf); /* Return # of bytes. */
}
