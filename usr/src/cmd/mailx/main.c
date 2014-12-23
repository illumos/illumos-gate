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

#include "rcv.h"
#ifndef preSVr4
#include <locale.h>
#endif

/*
 * mailx -- a modified version of a University of California at Berkeley
 *	mail program
 *
 * Startup -- interface with user.
 */

static void		hdrstop(int);

static jmp_buf	hdrjmp;

const char *const version = "mailx version 5.0";

/*
 * Find out who the user is, copy his mail file (if exists) into
 * /tmp/Rxxxxx and set up the message pointers.  Then, print out the
 * message headers and read user commands.
 *
 * Command line syntax:
 *	mailx [ -i ] [ -r address ] [ -h number ] [ -f [ name ] ]
 * or:
 *	mailx [ -i ] [ -r address ] [ -h number ] people ...
 *
 * and a bunch of other options.
 */

int 
main(int argc, char **argv)
{
	register char *ef;
	register int argp;
	int mustsend, f, goerr = 0;
	void (*prevint)(int);
	int loaded = 0;
	struct termio tbuf;
	struct termios tbufs;
	int c;
	char *cwd, *mf;

	/*
	 * Set up a reasonable environment.
	 * Figure out whether we are being run interactively, set up
	 * all the temporary files, buffer standard output, and so forth.
	 */

#ifndef preSVr4
	(void)setlocale(LC_ALL, "");
#endif
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

#ifdef SIGCONT
	sigset(SIGCONT, SIG_DFL);
#endif
	rpterr = 0;	/* initialize; set when we output to stderr */
	progname = argv[0];
	if (progname[strlen(progname) - 1] != 'x') {
		assign("bsdcompat", "");
	}
	myegid = getegid();
	myrgid = getgid();
	myeuid = geteuid();
	myruid = getuid();
	mypid = getpid();
	setgid(myrgid);
	setuid(myruid);
	inithost();
	intty = isatty(0);
	if (ioctl(1, TCGETS, &tbufs) < 0) {
		if (ioctl(1, TCGETA, &tbuf)==0) {
			outtty = 1;
			baud = tbuf.c_cflag & CBAUD;
		} else
			baud = B9600;
	} else {
		outtty = 1;
		baud = cfgetospeed(&tbufs);
	}
	image = -1;

	/*
	 * Now, determine how we are being used.
	 * We successively pick off instances of -r, -h, -f, and -i.
	 * If called as "rmail" we note this fact for letter sending.
	 * If there is anything left, it is the base of the list
	 * of users to mail to.  Argp will be set to point to the
	 * first of these users.
	 */

	ef = NOSTR;
	argp = -1;
	mustsend = 0;
	if (argc > 0 && **argv == 'r')
		rmail++;
	while ((c = getopt(argc, argv, "b:Bc:defFh:HiInNr:s:u:UtT:vV~")) != EOF)
		switch (c) {
		case 'e':
			/*
			 * exit status only
			 */
			exitflg++;
			break;

		case 'r':
			/*
			 * Next argument is address to be sent along
			 * to the mailer.
			 */
			mustsend++;
			rflag = optarg;
			break;

		case 'T':
			/*
			 * Next argument is temp file to write which
			 * articles have been read/deleted for netnews.
			 */
			Tflag = optarg;
			if ((f = creat(Tflag, TEMPPERM)) < 0) {
				perror(Tflag);
				exit(1);
			}
			close(f);
			/* fall through for -I too */
			/* FALLTHROUGH */

		case 'I':
			/*
			 * print newsgroup in header summary
			 */
			newsflg++;
			break;

		case 'u':
			/*
			 * Next argument is person's mailbox to use.
			 * Treated the same as "-f /var/mail/user".
			 */
			{
			static char u[PATHSIZE];
			snprintf(u, sizeof (u), "%s%s", maildir, optarg);
			ef = u;
			break;
			}

		case 'i':
			/*
			 * User wants to ignore interrupts.
			 * Set the variable "ignore"
			 */
			assign("ignore", "");
			break;

		case 'U':
			UnUUCP++;
			break;

		case 'd':
			assign("debug", "");
			break;

		case 'h':
			/*
			 * Specified sequence number for network.
			 * This is the number of "hops" made so
			 * far (count of times message has been
			 * forwarded) to help avoid infinite mail loops.
			 */
			mustsend++;
			hflag = atoi(optarg);
			if (hflag == 0) {
				fprintf(stderr,
				    gettext("-h needs non-zero number\n"));
				goerr++;
			}
			break;

		case 's':
			/*
			 * Give a subject field for sending from
			 * non terminal
			 */
			mustsend++;
			sflag = optarg;
			break;

		case 'c':	/* Cc: from command line */
			mustsend++;
			cflag = optarg;
			break;

		case 'b':	/* Bcc: from command line */
			mustsend++;
			bflag = optarg;
			break;

		case 'f':
			/*
			 * User is specifying file to "edit" with mailx,
			 * as opposed to reading system mailbox.
			 * If no argument is given after -f, we read his/her
			 * $MBOX file or mbox in his/her home directory.
			 */
			ef = (argc == optind || *argv[optind] == '-')
				? "" : argv[optind++];
			if (*ef && *ef != '/' && *ef != '+')
				cwd = getcwd(NOSTR, PATHSIZE);
			break;

		case 'F':
			Fflag++;
			mustsend++;
			break;

		case 'n':
			/*
			 * User doesn't want to source
			 *	/etc/mail/mailx.rc
			 */
			nosrc++;
			break;

		case 'N':
			/*
			 * Avoid initial header printing.
			 */
			noheader++;
			break;

		case 'H':
			/*
			 * Print headers and exit
			 */
			Hflag++;
			break;

		case 'V':
			puts(version);
			return 0;

		case '~':
			/*
			 * Permit tildas no matter where
			 * the input is coming from.
			 */
			assign("escapeok", "");
			break;

		case 'v':
			/*
			 * Send mailer verbose flag
			 */
			assign("verbose", "");
			break;

		case 'B':
			/*
			 * Don't buffer output
			 * (Line buffered is good enough)
			 */
			setvbuf(stdout, NULL, _IOLBF, BUFSIZ);
			setvbuf(stderr, NULL, _IOLBF, BUFSIZ);
			break;

		case 't':
			/*
			 * Like sendmail -t, read headers from text
			 */
			tflag++;
			mustsend++;
			break;

		case '?':
		default:
			goerr++;
			break;
		}

	if (optind != argc)
		argp = optind;

	/*
	 * Check for inconsistent arguments.
	 */

	if (newsflg && ef==NOSTR) {
		fprintf(stderr, gettext("Need -f with -I flag\n"));
		goerr++;
	}
	if (ef != NOSTR && argp != -1) {
		fprintf(stderr,
		    gettext("Cannot give -f and people to send to.\n"));
		goerr++;
	}
	if (exitflg && (mustsend || argp != -1))
		exit(1);	/* nonsense flags involving -e simply exit */
	if (tflag && argp != -1) {
		fprintf(stderr,
		    gettext("Ignoring recipients on command line with -t\n"));
		argp = -1;
	} else if (!tflag && mustsend && argp == -1) {
		fprintf(stderr,
	    gettext("The flags you gave are used only when sending mail.\n"));
		goerr++;
	}
	if (goerr) {
		fprintf(stderr,
gettext("Usage: %s -eiIUdFntBNHvV~ -T FILE -u USER -h hops -r address\n"),
		    progname);
		fprintf(stderr,
		    gettext("\t\t-s SUBJECT -f FILE users\n"));
		exit(1);
	}
	tinit();
	input = stdin;
	rcvmode = !tflag && argp == -1;
	if (!nosrc)
		load(MASTER);

	if (!rcvmode) {
		load(Getf("MAILRC"));
		if (tflag)
			tmail();
		else
			mail(&argv[argp]);
		exit(senderr ? senderr : rpterr);
	}

	/*
	 * Ok, we are reading mail.
	 * Decide whether we are editing a mailbox or reading
	 * the system mailbox, and open up the right stuff.
	 *
	 * Do this before sourcing the MAILRC, because there might be
	 * a 'chdir' there that breaks the -f option.  But if the
	 * file specified with -f is a folder name, go ahead and
	 * source the MAILRC anyway so that "folder" will be defined.
	 */

	nstrcpy(origname, PATHSIZE, mailname);
	editfile = mailname;

	if (ef != NOSTR) {
		if (ef == NOSTR || *ef == '\0' || *ef == '+') {
			load(Getf("MAILRC"));
			loaded++;
		}
		ef = *ef ? safeexpand(ef) : Getf("MBOX");
		nstrcpy(origname, PATHSIZE, ef);
		if (ef[0] != '/') {
			if (cwd == NOSTR)
				cwd = getcwd(NOSTR, PATHSIZE);
			nstrcat(cwd, PATHSIZE, "/");
			nstrcat(cwd, PATHSIZE, ef);
			ef = cwd;
		}
		editfile = ef;
		edit++;
	}

	if (setfile(editfile, edit) < 0)
		exit(1);

	if (!loaded)
		load(Getf("MAILRC"));
	if (msgCount > 0 && !noheader && value("header") != NOSTR) {
		if (setjmp(hdrjmp) == 0) {
			if ((prevint = sigset(SIGINT, SIG_IGN)) != SIG_IGN)
				sigset(SIGINT, hdrstop);
			announce();
			fflush(stdout);
			sigset(SIGINT, prevint);
		}
	}
	if (Hflag || (!edit && msgCount == 0)) {
		if (!Hflag) {
			fprintf(stderr, gettext("No mail for %s\n"), myname);
			Verhogen();
		}
		fflush(stdout);
		exit(rpterr);
	}
	commands();
	sigset(SIGHUP, SIG_IGN);
	sigset(SIGINT, SIG_IGN);
	sigset(SIGQUIT, SIG_IGN);
	if (!outtty)
		sigset(SIGPIPE, SIG_IGN);
	if (edit)
		edstop(0);
	else {
		quit(0);
		Verhogen();
	}
	return (rpterr);
}

/*
 * Interrupt printing of the headers.
 */
static void 
#ifdef	__cplusplus
hdrstop(int)
#else
/* ARGSUSED */
hdrstop(int s)
#endif
{

	fflush(stdout);
	fprintf(stderr, gettext("\nInterrupt\n"));
# ifdef OLD_BSD_SIGS
	sigrelse(SIGINT);
# endif
	longjmp(hdrjmp, 1);
}
