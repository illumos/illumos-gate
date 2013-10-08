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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 2013 Gary Mills
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	This program analyzes information found in /var/adm/utmpx
 *
 *	Additionally information is gathered from /etc/inittab
 *	if requested.
 *
 *
 *	Syntax:
 *
 *		who am i	Displays info on yourself
 *
 *		who -a		Displays information about All
 *				entries in /var/adm/utmpx
 *
 *		who -b		Displays info on last boot
 *
 *		who -d		Displays info on DEAD PROCESSES
 *
 *		who -H		Displays HEADERS for output
 *
 *		who -l 		Displays info on LOGIN entries
 *
 *		who -m 		Same as who am i
 *
 *		who -p 		Displays info on PROCESSES spawned by init
 *
 *		who -q		Displays short information on
 *				current users who LOGGED ON
 *
 *		who -r		Displays info of current run-level
 *
 *		who -s		Displays requested info in SHORT form
 *
 *		who -t		Displays info on TIME changes
 *
 *		who -T		Displays writeability of each user
 *				(+ writeable, - non-writeable, ? hung)
 *
 *		who -u		Displays LONG info on users
 *				who have LOGGED ON
 */

#define		DATE_FMT	"%b %e %H:%M"

/*
 *  %b	Abbreviated month name
 *  %e	Day of month
 *  %H	hour (24-hour clock)
 *  %M  minute
 */
#include	<errno.h>
#include	<fcntl.h>
#include	<stdio.h>
#include	<string.h>
#include	<sys/types.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<sys/stat.h>
#include	<time.h>
#include	<utmpx.h>
#include	<locale.h>
#include	<pwd.h>
#include	<limits.h>

static void process(void);
static void ck_file(char *);
static void dump(void);

static struct	utmpx *utmpp;	/* pointer for getutxent()	*/

/*
 * Use the full lengths from utmpx for user and line.
 */
#define	NMAX	(sizeof (utmpp->ut_user))
#define	LMAX	(sizeof (utmpp->ut_line))

/* Print minimum field widths. */
#define	LOGIN_WIDTH	8
#define	LINE_WIDTH	12

static char	comment[BUFSIZ]; /* holds inittab comment	*/
static char	errmsg[BUFSIZ];	/* used in snprintf for errors	*/
static int	fildes;		/* file descriptor for inittab	*/
static int	Hopt = 0;	/* 1 = who -H			*/
static char	*inittab;	/* ptr to inittab contents	*/
static char	*iinit;		/* index into inittab		*/
static int	justme = 0;	/* 1 = who am i			*/
static struct	tm *lptr;	/* holds user login time	*/
static char	*myname;	/* pointer to invoker's name 	*/
static char	*mytty;		/* holds device user is on	*/
static char	nameval[sizeof (utmpp->ut_user) + 1]; /*  invoker's name */
static int	number = 8;	/* number of users per -q line	*/
static int	optcnt = 0;	/* keeps count of options	*/
static char	outbuf[BUFSIZ];	/* buffer for output		*/
static char	*program;	/* holds name of this program	*/
#ifdef	XPG4
static int	aopt = 0;	/* 1 = who -a			*/
static int	dopt = 0;	/* 1 = who -d			*/
#endif	/* XPG4 */
static int	qopt = 0;	/* 1 = who -q			*/
static int	sopt = 0;	/* 1 = who -s			*/
static struct	stat stbuf;	/* area for stat buffer		*/
static struct	stat *stbufp;	/* ptr to structure		*/
static int	terse = 1;	/* 1 = print terse msgs		*/
static int	Topt = 0;	/* 1 = who -T			*/
static time_t	timnow;		/* holds current time		*/
static int	totlusrs = 0;	/* cntr for users on system	*/
static int	uopt = 0;	/* 1 = who -u			*/
static char	user[sizeof (utmpp->ut_user) + 1]; /* holds user name */
static int	validtype[UTMAXTYPE+1];	/* holds valid types	*/
static int	wrap;		/* flag to indicate wrap	*/
static char	time_buf[128];	/* holds date and time string	*/
static char	*end;		/* used in strtol for end pointer */

int
main(int argc, char **argv)
{
	int	goerr = 0;	/* non-zero indicates cmd error	*/
	int	i;
	int	optsw;		/* switch for while of getopt()	*/

	(void) setlocale(LC_ALL, "");

#if	!defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	validtype[USER_PROCESS] = 1;
	validtype[EMPTY] = 0;
	stbufp = &stbuf;

	/*
	 *	Strip off path name of this command
	 */
	for (i = strlen(argv[0]); i >= 0 && argv[0][i] != '/'; --i)
		;
	if (i >= 0)
		argv[0] += i+1;
	program = argv[0];

	/*
	 *	Buffer stdout for speed
	 */
	setbuf(stdout, outbuf);

	/*
	 *	Retrieve options specified on command line
	 *	XCU4 - add -m option
	 */
	while ((optsw = getopt(argc, argv, "abdHlmn:pqrstTu")) != EOF) {
		optcnt++;
		switch (optsw) {

		case 'a':
			optcnt += 7;
			validtype[BOOT_TIME] = 1;
			validtype[DEAD_PROCESS] = 1;
			validtype[LOGIN_PROCESS] = 1;
			validtype[INIT_PROCESS] = 1;
			validtype[RUN_LVL] = 1;
			validtype[OLD_TIME] = 1;
			validtype[NEW_TIME] = 1;
			validtype[USER_PROCESS] = 1;
#ifdef	XPG4
			aopt = 1;
#endif	/* XPG4 */
			uopt = 1;
			Topt = 1;
			if (!sopt) terse = 0;
			break;

		case 'b':
			validtype[BOOT_TIME] = 1;
			if (!uopt) validtype[USER_PROCESS] = 0;
			break;

		case 'd':
			validtype[DEAD_PROCESS] = 1;
			if (!uopt) validtype[USER_PROCESS] = 0;
#ifdef	XPG4
			dopt = 1;
#endif	/* XPG4 */
			break;

		case 'H':
			optcnt--; /* Don't count Header */
			Hopt = 1;
			break;

		case 'l':
			validtype[LOGIN_PROCESS] = 1;
			if (!uopt) validtype[USER_PROCESS] = 0;
			terse = 0;
			break;
		case 'm':		/* New XCU4 option */
			justme = 1;
			break;

		case 'n':
			errno = 0;
			number = strtol(optarg, &end, 10);
			if (errno != 0 || *end != '\0') {
				(void) fprintf(stderr, gettext(
				    "%s: Invalid numeric argument\n"),
				    program);
				exit(1);
			}
			if (number < 1) {
				(void) fprintf(stderr, gettext(
				    "%s: Number of users per line must "
				    "be at least 1\n"), program);
				exit(1);
			}
			break;

		case 'p':
			validtype[INIT_PROCESS] = 1;
			if (!uopt) validtype[USER_PROCESS] = 0;
			break;

		case 'q':
			qopt = 1;
			break;

		case 'r':
			validtype[RUN_LVL] = 1;
			terse = 0;
			if (!uopt) validtype[USER_PROCESS] = 0;
			break;

		case 's':
			sopt = 1;
			terse = 1;
			break;

		case 't':
			validtype[OLD_TIME] = 1;
			validtype[NEW_TIME] = 1;
			if (!uopt) validtype[USER_PROCESS] = 0;
			break;

		case 'T':
			Topt = 1;
#ifdef	XPG4
			terse = 1;	/* XPG4 requires -T */
#else	/* XPG4 */
			terse = 0;
#endif	/* XPG4 */
			break;

		case 'u':
			uopt = 1;
			validtype[USER_PROCESS] = 1;
			if (!sopt) terse = 0;
			break;

		case '?':
			goerr++;
			break;
		default:
			break;
		}
	}
#ifdef	XPG4
	/*
	 * XCU4 changes - check for illegal sopt, Topt & aopt combination
	 */
	if (sopt == 1) {
		terse = 1;
		if (Topt == 1 || aopt == 1)
		goerr++;
	}
#endif	/* XPG4 */

	if (goerr > 0) {
#ifdef	XPG4
		/*
		 * XCU4 - slightly different usage with -s -a & -T
		 */
		(void) fprintf(stderr, gettext("\nUsage:\t%s"), program);
		(void) fprintf(stderr,
		    gettext(" -s [-bdHlmpqrtu] [utmpx_like_file]\n"));

		(void) fprintf(stderr, gettext(
		    "\t%s [-abdHlmpqrtTu] [utmpx_like_file]\n"), program);
#else	/* XPG4 */
		(void) fprintf(stderr, gettext(
		    "\nUsage:\t%s [-abdHlmpqrstTu] [utmpx_like_file]\n"),
		    program);
#endif	/* XPG4 */
		(void) fprintf(stderr,
		    gettext("\t%s -q [-n x] [utmpx_like_file]\n"), program);
		(void) fprintf(stderr, gettext("\t%s [am i]\n"), program);
		/*
		 * XCU4 changes - be explicit with "am i" options
		 */
		(void) fprintf(stderr, gettext("\t%s [am I]\n"), program);
		(void) fprintf(stderr, gettext(
		    "a\tall (bdlprtu options)\n"));
		(void) fprintf(stderr, gettext("b\tboot time\n"));
		(void) fprintf(stderr, gettext("d\tdead processes\n"));
		(void) fprintf(stderr, gettext("H\tprint header\n"));
		(void) fprintf(stderr, gettext("l\tlogin processes\n"));
		(void) fprintf(stderr, gettext(
		    "n #\tspecify number of users per line for -q\n"));
		(void) fprintf(stderr,
		    gettext("p\tprocesses other than getty or users\n"));
		(void) fprintf(stderr, gettext("q\tquick %s\n"), program);
		(void) fprintf(stderr, gettext("r\trun level\n"));
		(void) fprintf(stderr, gettext(
		"s\tshort form of %s (no time since last output or pid)\n"),
		    program);
		(void) fprintf(stderr, gettext("t\ttime changes\n"));
		(void) fprintf(stderr, gettext(
		    "T\tstatus of tty (+ writable, - not writable, "
		    "? hung)\n"));
		(void) fprintf(stderr, gettext("u\tuseful information\n"));
		(void) fprintf(stderr,
		    gettext("m\tinformation only about current terminal\n"));
		(void) fprintf(stderr, gettext(
		    "am i\tinformation about current terminal "
		    "(same as -m)\n"));
		(void) fprintf(stderr, gettext(
		    "am I\tinformation about current terminal "
		    "(same as -m)\n"));
		exit(1);
	}

	/*
	 * XCU4: If -q option ignore all other options
	 */
	if (qopt == 1) {
		Hopt = 0;
		sopt = 0;
		Topt = 0;
		uopt = 0;
		justme = 0;
		validtype[ACCOUNTING] = 0;
		validtype[BOOT_TIME] = 0;
		validtype[DEAD_PROCESS] = 0;
		validtype[LOGIN_PROCESS] = 0;
		validtype[INIT_PROCESS] = 0;
		validtype[RUN_LVL] = 0;
		validtype[OLD_TIME] = 0;
		validtype[NEW_TIME] = 0;
		validtype[USER_PROCESS] = 1;
	}

	if (argc == optind + 1) {
		optcnt++;
		ck_file(argv[optind]);
		(void) utmpxname(argv[optind]);
	}

	/*
	 *	Test for 'who am i' or 'who am I'
	 *	XCU4 - check if justme was already set by -m option
	 */
	if (justme == 1 || (argc == 3 && strcmp(argv[1], "am") == 0 &&
	    ((argv[2][0] == 'i' || argv[2][0] == 'I') &&
	    argv[2][1] == '\0'))) {
		justme = 1;
		myname = nameval;
		(void) cuserid(myname);
		if ((mytty = ttyname(fileno(stdin))) == NULL &&
		    (mytty = ttyname(fileno(stdout))) == NULL &&
		    (mytty = ttyname(fileno(stderr))) == NULL) {
			(void) fprintf(stderr, gettext(
			"Must be attached to terminal for 'am I' option\n"));
			(void) fflush(stderr);
			exit(1);
		} else
			mytty += 5; /* bump past "/dev/" */
	}

	if (!terse) {
		if (Hopt)
			(void) printf(gettext(
	"NAME       LINE         TIME          IDLE    PID  COMMENTS\n"));

		timnow = time(0);

		if ((fildes = open("/etc/inittab",
		    O_NONBLOCK|O_RDONLY)) == -1) {
			(void) snprintf(errmsg, sizeof (errmsg),
			    gettext("%s: Cannot open /etc/inittab"), program);
			perror(errmsg);
			exit(errno);
		}

		if (fstat(fildes, stbufp) == -1) {
			(void) snprintf(errmsg, sizeof (errmsg),
			    gettext("%s: Cannot stat /etc/inittab"), program);
			perror(errmsg);
			exit(errno);
		}

		if ((inittab = malloc(stbufp->st_size + 1)) == NULL) {
			(void) snprintf(errmsg, sizeof (errmsg),
			    gettext("%s: Cannot allocate %ld bytes"),
			    program, stbufp->st_size);
			perror(errmsg);
			exit(errno);
		}

		if (read(fildes, inittab, stbufp->st_size)
		    != stbufp->st_size) {
			(void) snprintf(errmsg, sizeof (errmsg),
			    gettext("%s: Error reading /etc/inittab"),
			    program);
			perror(errmsg);
			exit(errno);
		}

		inittab[stbufp->st_size] = '\0';
		iinit = inittab;
	} else {
		if (Hopt) {
#ifdef	XPG4
			if (dopt) {
				(void) printf(gettext(
			"NAME       LINE         TIME		COMMENTS\n"));
			} else {
				(void) printf(
				    gettext("NAME       LINE         TIME\n"));
			}
#else	/* XPG4 */
			(void) printf(
			    gettext("NAME       LINE         TIME\n"));
#endif	/* XPG4 */
		}
	}
	process();

	/*
	 *	'who -q' requires EOL upon exit,
	 *	followed by total line
	 */
	if (qopt)
		(void) printf(gettext("\n# users=%d\n"), totlusrs);
	return (0);
}

static void
dump()
{
	char	device[sizeof (utmpp->ut_line) + 1];
	time_t hr;
	time_t	idle;
	time_t min;
	char	path[sizeof (utmpp->ut_line) + 6];
	int	pexit;
	int	pterm;
	int	rc;
	char	w;	/* writeability indicator */

	/*
	 * Get and check user name
	 */
	if (utmpp->ut_user[0] == '\0')
		(void) strcpy(user, "   .");
	else {
		(void) strncpy(user, utmpp->ut_user, sizeof (user));
		user[sizeof (user) - 1] = '\0';
	}
	totlusrs++;

	/*
	 * Do print in 'who -q' format
	 */
	if (qopt) {
		/*
		 * XCU4 - Use non user macro for correct user count
		 */
		if (((totlusrs - 1) % number) == 0 && totlusrs > 1)
			(void) printf("\n");
		(void) printf("%-*.*s ", LOGIN_WIDTH, NMAX, user);
		return;
	}


	pexit = (int)' ';
	pterm = (int)' ';

	/*
	 *	Get exit info if applicable
	 */
	if (utmpp->ut_type == RUN_LVL || utmpp->ut_type == DEAD_PROCESS) {
		pterm = utmpp->ut_exit.e_termination;
		pexit = utmpp->ut_exit.e_exit;
	}

	/*
	 *	Massage ut_xtime field
	 */
	lptr = localtime(&utmpp->ut_xtime);
	(void) strftime(time_buf, sizeof (time_buf),
	    dcgettext(NULL, DATE_FMT, LC_TIME), lptr);

	/*
	 *	Get and massage device
	 */
	if (utmpp->ut_line[0] == '\0')
		(void) strcpy(device, "     .");
	else {
		(void) strncpy(device, utmpp->ut_line,
		    sizeof (utmpp->ut_line));
		device[sizeof (utmpp->ut_line)] = '\0';
	}

	/*
	 *	Get writeability if requested
	 *	XCU4 - only print + or - for user processes
	 */
	if (Topt && (utmpp->ut_type == USER_PROCESS)) {
		w = '-';
		(void) strcpy(path, "/dev/");
		(void) strncpy(path + 5, utmpp->ut_line,
		    sizeof (utmpp->ut_line));
		path[5 + sizeof (utmpp->ut_line)] = '\0';

		if ((rc = stat(path, stbufp)) == -1) w = '?';
		else if ((stbufp->st_mode & S_IWOTH) ||
		    (stbufp->st_mode & S_IWGRP))  /* Check group & other */
			w = '+';

	} else
		w = ' ';

	/*
	 *	Print the TERSE portion of the output
	 */
	(void) printf("%-*.*s %c %-12s %s", LOGIN_WIDTH, NMAX, user,
	    w, device, time_buf);

	if (!terse) {
		/*
		 *	Stat device for idle time
		 *	(Don't complain if you can't)
		 */
		rc = -1;
		if (utmpp->ut_type == USER_PROCESS) {
			(void) strcpy(path, "/dev/");
			(void) strncpy(path + 5, utmpp->ut_line,
			    sizeof (utmpp->ut_line));
			path[5 + sizeof (utmpp->ut_line)] = '\0';
			rc = stat(path, stbufp);
		}
		if (rc != -1) {
			idle = timnow - stbufp->st_mtime;
			hr = idle/3600;
			min = (unsigned)(idle/60)%60;
			if (hr == 0 && min == 0)
				(void) printf(gettext("   .  "));
			else {
				if (hr < 24)
					(void) printf(" %2d:%2.2d", (int)hr,
					    (int)min);
				else
					(void) printf(gettext("  old "));
			}
		}

		/*
		 *	Add PID for verbose output
		 */
		if (utmpp->ut_type != BOOT_TIME &&
		    utmpp->ut_type != RUN_LVL &&
		    utmpp->ut_type != ACCOUNTING)
			(void) printf("  %5ld", utmpp->ut_pid);

		/*
		 *	Handle /etc/inittab comment
		 */
		if (utmpp->ut_type == DEAD_PROCESS) {
			(void) printf(gettext("  id=%4.4s "),
			    utmpp->ut_id);
			(void) printf(gettext("term=%-3d "), pterm);
			(void) printf(gettext("exit=%d  "), pexit);
		} else if (utmpp->ut_type != INIT_PROCESS) {
			/*
			 *	Search for each entry in inittab
			 *	string. Keep our place from
			 *	search to search to try and
			 *	minimize the work. Wrap once if needed
			 *	for each entry.
			 */
			wrap = 0;
			/*
			 *	Look for a line beginning with
			 *	utmpp->ut_id
			 */
			while ((rc = strncmp(utmpp->ut_id, iinit,
			    strcspn(iinit, ":"))) != 0) {
				for (; *iinit != '\n'; iinit++)
					;
				iinit++;

				/*
				 *	Wrap once if necessary to
				 *	find entry in inittab
				 */
				if (*iinit == '\0') {
					if (!wrap) {
						iinit = inittab;
						wrap = 1;
					}
				}
			}

			if (*iinit != '\0') {
				/*
				 *	We found our entry
				 */
				for (iinit++; *iinit != '#' &&
				    *iinit != '\n'; iinit++)
					;
				if (*iinit == '#') {
					for (iinit++; *iinit == ' ' ||
					    *iinit == '\t'; iinit++)
						;
					for (rc = 0; *iinit != '\n'; iinit++)
						comment[rc++] = *iinit;
					comment[rc] = '\0';
				} else
					(void) strcpy(comment, " ");

				(void) printf("  %s", comment);
			} else
				iinit = inittab;	/* Reset pointer */
		}
		if (utmpp->ut_type == INIT_PROCESS)
			(void) printf(gettext("  id=%4.4s"), utmpp->ut_id);
	}
#ifdef	XPG4
	else
		if (dopt && utmpp->ut_type == DEAD_PROCESS) {
			(void) printf(gettext("\tterm=%-3d "), pterm);
			(void) printf(gettext("exit=%d  "), pexit);
		}
#endif	/* XPG4 */


	/*
	 *	Handle RUN_LVL process - If no alt. file - Only one!
	 */
	if (utmpp->ut_type == RUN_LVL) {
		(void) printf("     %c  %5ld  %c", pterm, utmpp->ut_pid,
		    pexit);
		if (optcnt == 1 && !validtype[USER_PROCESS]) {
			(void) printf("\n");
			exit(0);
		}
	}

	/*
	 *	Handle BOOT_TIME process -  If no alt. file - Only one!
	 */
	if (utmpp->ut_type == BOOT_TIME) {
		if (optcnt == 1 && !validtype[USER_PROCESS]) {
			(void) printf("\n");
			exit(0);
		}
	}

	/*
	 *	Get remote host from utmpx structure
	 */
	if (utmpp && utmpp->ut_host[0])
		(void) printf("\t(%.*s)", sizeof (utmpp->ut_host),
		    utmpp->ut_host);

	/*
	 *	Now, put on the trailing EOL
	 */
	(void) printf("\n");
}

static void
process()
{
	struct passwd *pwp;
	int i = 0;
	char *ttname;

	/*
	 *	Loop over each entry in /var/adm/utmpx
	 */

	setutxent();
	while ((utmpp = getutxent()) != NULL) {
#ifdef DEBUG
	(void) printf(
	    "ut_user '%s'\nut_id '%s'\nut_line '%s'\nut_type '%d'\n\n",
	    utmpp->ut_user, utmpp->ut_id, utmpp->ut_line, utmpp->ut_type);
#endif
		if (utmpp->ut_type <= UTMAXTYPE) {
			/*
			 *	Handle "am i"
			 */
			if (justme) {
				if (strncmp(myname, utmpp->ut_user,
				    sizeof (utmpp->ut_user)) == 0 &&
				    strncmp(mytty, utmpp->ut_line,
				    sizeof (utmpp->ut_line)) == 0 &&
				    utmpp->ut_type == USER_PROCESS) {
					/*
					 * we have have found ourselves
					 * in the utmp file and the entry
					 * is a user process, this is not
					 * meaningful otherwise
					 *
					 */

					dump();
					exit(0);
				}
				continue;
			}

			/*
			 *	Print the line if we want it
			 */
			if (validtype[utmpp->ut_type]) {
#ifdef	XPG4
				if (utmpp->ut_type == LOGIN_PROCESS) {
					if ((utmpp->ut_line[0] == '\0') ||
					    (strcmp(utmpp->ut_user,
					    "LOGIN") != 0))
						continue;
				}
#endif	/* XPG4 */
				dump();
			}
		} else {
			(void) fprintf(stderr,
			    gettext("%s: Error --- entry has ut_type "
			    "of %d\n"), program, utmpp->ut_type);
			(void) fprintf(stderr,
			    gettext(" when maximum is %d\n"), UTMAXTYPE);
		}
	}

	/*
	 * If justme is set at this point than the utmp entry
	 * was not found.
	 */
	if (justme) {
		static struct utmpx utmpt;

		pwp = getpwuid(geteuid());
		if (pwp != NULL)
			while (i < (int)sizeof (utmpt.ut_user) &&
			    *pwp->pw_name != 0)
				utmpt.ut_user[i++] = *pwp->pw_name++;

		ttname = ttyname(1);

		i = 0;
		if (ttname != NULL)
			while (i < (int)sizeof (utmpt.ut_line) &&
			    *ttname != 0)
				utmpt.ut_line[i++] = *ttname++;

		utmpt.ut_id[0] = 0;
		utmpt.ut_pid = getpid();
		utmpt.ut_type = USER_PROCESS;
		(void) time(&utmpt.ut_xtime);
		utmpp = &utmpt;
		dump();
		exit(0);
	}
}

/*
 *	This routine checks the following:
 *
 *	1.	File exists
 *
 *	2.	We have read permissions
 *
 *	3.	It is a multiple of utmp entries in size
 *
 *	Failing any of these conditions causes who(1) to
 *	abort processing.
 *
 *	4.	If file is empty we exit right away as there
 *		is no info to report on.
 *
 *	This routine does not check utmpx files.
 */
static void
ck_file(char *name)
{
	struct	stat sbuf;
	int	rc;

	/*
	 *	Does file exist? Do stat to check, and save structure
	 *	so that we can check on the file's size later on.
	 */
	if ((rc = stat(name, &sbuf)) == -1) {
		(void) snprintf(errmsg, sizeof (errmsg),
		    gettext("%s: Cannot stat file '%s'"), program, name);
		perror(errmsg);
		exit(1);
	}

	/*
	 *	The only real way we can be sure we can access the
	 *	file is to try. If we succeed then we close it.
	 */
	if (access(name, R_OK) < 0) {
		(void) snprintf(errmsg, sizeof (errmsg),
		    gettext("%s: Cannot open file '%s'"), program, name);
		perror(errmsg);
		exit(1);
	}

	/*
	 *	If the file is empty, we are all done.
	 */
	if (!sbuf.st_size)
		exit(0);

	/*
	 *	Make sure the file is a utmp file.
	 *	We can only check for size being a multiple of
	 *	utmp structures in length.
	 */
	rc = sbuf.st_size % (int)sizeof (struct utmpx);
	if (rc) {
		(void) fprintf(stderr, gettext("%s: File '%s' is not "
		    "a utmpx file\n"), program, name);
		exit(1);
	}
}
