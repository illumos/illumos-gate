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
 * Copyright (c) 2017 Olaf Bohlen
 *
 * Copyright (c) 2013 Gary Mills
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
 *	  All Rights Reserved
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

/*
 * last
 */
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <signal.h>
#include <sys/stat.h>
#include <pwd.h>
#include <fcntl.h>
#include <utmpx.h>
#include <locale.h>
#include <ctype.h>

/*
 * Use the full lengths from utmpx for NMAX, LMAX and HMAX .
 */
#define	NMAX	(sizeof (((struct utmpx *)0)->ut_user))
#define	LMAX	(sizeof (((struct utmpx *)0)->ut_line))
#define	HMAX	(sizeof (((struct utmpx *)0)->ut_host))

/* Print minimum field widths. */
#define	LOGIN_WIDTH	8
#define	LINE_WIDTH	12

#define	SECDAY	(24*60*60)
#define	CHUNK_SIZE 256

#define	lineq(a, b)	(strncmp(a, b, LMAX) == 0)
#define	nameq(a, b)	(strncmp(a, b, NMAX) == 0)
#define	hosteq(a, b)	(strncmp(a, b, HMAX) == 0)
#define	linehostnameq(a, b, c, d) \
	    (lineq(a, b)&&hosteq(a+LMAX+1, c)&&nameq(a+LMAX+HMAX+2, d))

#define	USAGE	"usage: last [-n number] [-f filename] [-a ] [ -l ] [name |\
 tty] ...\n"

/* Beware: These are set in main() to exclude the executable name.  */
static char	**argv;
static int	argc;
static char	**names;
static int	names_num;

static struct	utmpx buf[128];

/*
 * ttnames and logouts are allocated in the blocks of
 * CHUNK_SIZE lines whenever needed. The count of the
 * current size is maintained in the variable "lines"
 * The variable bootxtime is used to hold the time of
 * the last BOOT_TIME
 * All elements of the logouts are initialised to bootxtime
 * everytime the buffer is reallocated.
 */

static char	**ttnames;
static time_t	*logouts;
static time_t	bootxtime;
static int	lines;
static char	timef[128];
static char	hostf[HMAX + 1];

static char *strspl(char *, char *);
static void onintr(int);
static void reallocate_buffer();
static void memory_alloc(int);
static int want(struct utmpx *, char **, char **);
static void record_time(time_t *, int *, int, struct utmpx *);

int
main(int ac, char **av)
{
	int i, j;
	int aflag = 0;
	int lflag = 0;  /* parameter -l, long format with seconds and years */
	int fpos;	/* current position in time format buffer */
	int chrcnt;	/* # of chars formatted by current sprintf */
	int bl, wtmp;
	char *ct;
	char *ut_host;
	char *ut_user;
	struct utmpx *bp;
	time_t otime;
	struct stat stb;
	int print = 0;
	char *crmsg = (char *)0;
	long outrec = 0;
	long maxrec = 0x7fffffffL;
	char *wtmpfile = "/var/adm/wtmpx";
	size_t hostf_len;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)		/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"		/* Use this only if it weren't. */
#endif
	(void) textdomain(TEXT_DOMAIN);

	(void) time(&buf[0].ut_xtime);
	ac--, av++;
	argc = ac;
	argv = av;
	names = malloc(argc * sizeof (char *));
	if (names == NULL) {
		perror("last");
		exit(2);
	}
	names_num = 0;
	for (i = 0; i < argc; i++) {
		if (argv[i][0] == '-') {

			/* -[0-9]*   sets max # records to print */
			if (isdigit(argv[i][1])) {
				maxrec = atoi(argv[i]+1);
				continue;
			}

			for (j = 1; argv[i][j] != '\0'; ++j) {
				switch (argv[i][j]) {

				/* -f name sets filename of wtmp file */
				case 'f':
					if (argv[i][j+1] != '\0') {
						wtmpfile = &argv[i][j+1];
					} else if (i+1 < argc) {
						wtmpfile = argv[++i];
					} else {
						(void) fprintf(stderr,
						    gettext("last: argument to "
						    "-f is missing\n"));
						(void) fprintf(stderr,
						    gettext(USAGE));
						exit(1);
					}
					goto next_word;

				/* -n number sets max # records to print */
				case 'n': {
					char *arg;

					if (argv[i][j+1] != '\0') {
						arg = &argv[i][j+1];
					} else if (i+1 < argc) {
						arg = argv[++i];
					} else {
						(void) fprintf(stderr,
						    gettext("last: argument to "
						    "-n is missing\n"));
						(void) fprintf(stderr,
						    gettext(USAGE));
						exit(1);
					}

					if (!isdigit(*arg)) {
						(void) fprintf(stderr,
						    gettext("last: argument to "
						    "-n is not a number\n"));
						(void) fprintf(stderr,
						    gettext(USAGE));
						exit(1);
					}
					maxrec = atoi(arg);
					goto next_word;
				}

				/* -a displays hostname last on the line */
				case 'a':
					aflag++;
					break;

				/* -l turns on long dates and times */
				case 'l':
					lflag++;
					break;

				default:
					(void) fprintf(stderr, gettext(USAGE));
					exit(1);
				}
			}

next_word:
			continue;
		}

		if (strlen(argv[i]) > 2 || strcmp(argv[i], "~") == 0 ||
		    getpwnam(argv[i]) != NULL) {
			/* Not a tty number. */
			names[names_num] = argv[i];
			++names_num;
		} else {
			/* tty number.  Prepend "tty". */
			names[names_num] = strspl("tty", argv[i]);
			++names_num;
		}
	}

	wtmp = open(wtmpfile, 0);
	if (wtmp < 0) {
		perror(wtmpfile);
		exit(1);
	}
	(void) fstat(wtmp, &stb);
	bl = (stb.st_size + sizeof (buf)-1) / sizeof (buf);
	if (signal(SIGINT, SIG_IGN) != SIG_IGN) {
		(void) signal(SIGINT, onintr);
		(void) signal(SIGQUIT, onintr);
	}
	lines = CHUNK_SIZE;
	ttnames = calloc(lines, sizeof (char *));
	logouts = calloc(lines, sizeof (time_t));
	if (ttnames == NULL || logouts == NULL) {
		(void) fprintf(stderr, gettext("Out of memory \n "));
		exit(2);
	}
		for (bl--; bl >= 0; bl--) {
		(void) lseek(wtmp, (off_t)(bl * sizeof (buf)), 0);
		bp = &buf[read(wtmp, buf, sizeof (buf)) / sizeof (buf[0]) - 1];
		for (; bp >= buf; bp--) {
			if (want(bp, &ut_host, &ut_user)) {
				for (i = 0; i <= lines; i++) {
				if (i == lines)
					reallocate_buffer();
				if (ttnames[i] == NULL) {
					memory_alloc(i);
					/*
					 * LMAX+HMAX+NMAX+3 bytes have been
					 * allocated for ttnames[i].
					 * If bp->ut_line is longer than LMAX,
					 * ut_host is longer than HMAX,
					 * and ut_user is longer than NMAX,
					 * truncate it to fit ttnames[i].
					 */
					(void) strlcpy(ttnames[i], bp->ut_line,
					    LMAX+1);
					(void) strlcpy(ttnames[i]+LMAX+1,
					    ut_host, HMAX+1);
					(void) strlcpy(ttnames[i]+LMAX+HMAX+2,
					    ut_user, NMAX+1);
						record_time(&otime, &print,
						    i, bp);
						break;
					} else if (linehostnameq(ttnames[i],
					    bp->ut_line, ut_host, ut_user)) {
						record_time(&otime,
						    &print, i, bp);
						break;
					}
				}
			}
			if (print) {
				if (strncmp(bp->ut_line, "ftp", 3) == 0)
					bp->ut_line[3] = '\0';
				if (strncmp(bp->ut_line, "uucp", 4) == 0)
					bp->ut_line[4] = '\0';

				ct = ctime(&bp->ut_xtime);
				(void) printf(gettext("%-*.*s  %-*.*s "),
				    LOGIN_WIDTH, NMAX, bp->ut_name,
				    LINE_WIDTH, LMAX, bp->ut_line);
				hostf_len = strlen(bp->ut_host);
				(void) snprintf(hostf, sizeof (hostf),
				    "%-*.*s", hostf_len, hostf_len,
				    bp->ut_host);
				/* write seconds and year if -l specified */
				if (lflag > 0) {
					fpos = snprintf(timef, sizeof (timef),
					    "%10.10s %13.13s ",
					    ct, 11 + ct);
				} else {
					fpos = snprintf(timef, sizeof (timef),
					    "%10.10s %5.5s ",
					    ct, 11 + ct);
				}

				if (!lineq(bp->ut_line, "system boot") &&
				    !lineq(bp->ut_line, "system down")) {
					if (otime == 0 &&
					    bp->ut_type == USER_PROCESS) {

	if (fpos < sizeof (timef)) {
		/* timef still has room */
		(void) snprintf(timef + fpos, sizeof (timef) - fpos,
		    gettext("  still logged in"));
	}

					} else {
					time_t delta;
					if (otime < 0) {
						otime = -otime;
						/*
						 * TRANSLATION_NOTE
						 * See other notes on "down"
						 * and "- %5.5s".
						 * "-" means "until".  This
						 * is displayed after the
						 * starting time as in:
						 * 	16:20 - down
						 * You probably don't want to
						 * translate this.  Should you
						 * decide to translate this,
						 * translate "- %5.5s" too.
						 */

	if (fpos < sizeof (timef)) {
		/* timef still has room */
		chrcnt = snprintf(timef + fpos, sizeof (timef) - fpos,
		    gettext("- %s"), crmsg);
		fpos += chrcnt;
	}

					} else {

	if (fpos < sizeof (timef)) {
		/* timef still has room */
		if (lflag > 0) {
			chrcnt = snprintf(timef + fpos, sizeof (timef) - fpos,
			    gettext("- %8.8s"), ctime(&otime) + 11);
		} else {
			chrcnt = snprintf(timef + fpos, sizeof (timef) - fpos,
			    gettext("- %5.5s"), ctime(&otime) + 11);
		}
		fpos += chrcnt;
	}

					}
					delta = otime - bp->ut_xtime;
					if (delta < SECDAY) {

	if (fpos < sizeof (timef)) {
		/* timef still has room */
		if (lflag > 0) {
			(void) snprintf(timef + fpos, sizeof (timef) - fpos,
			    gettext("  (%8.8s)"), asctime(gmtime(&delta)) + 11);
		} else {
			(void) snprintf(timef + fpos, sizeof (timef) - fpos,
			    gettext("  (%5.5s)"), asctime(gmtime(&delta)) + 11);
		}

	}

					} else {

	if (fpos < sizeof (timef)) {
		/* timef still has room */
		if (lflag > 0) {
			(void) snprintf(timef + fpos, sizeof (timef) - fpos,
			    gettext(" (%ld+%8.8s)"), delta / SECDAY,
			    asctime(gmtime(&delta)) + 11);
		} else {
			(void) snprintf(timef + fpos, sizeof (timef) - fpos,
			    gettext(" (%ld+%5.5s)"), delta / SECDAY,
			    asctime(gmtime(&delta)) + 11);
		}
	}

					}
					}
				}
				if (lflag > 0) {
					if (aflag)
						(void) printf("%-.*s %-.*s\n",
						    strlen(timef), timef,
						    strlen(hostf), hostf);
					else
						(void) printf(
						    "%-16.16s %-.*s\n", hostf,
						    strlen(timef), timef);
				} else {
					if (aflag)
						(void) printf(
						    "%-35.35s %-.*s\n", timef,
						    strlen(hostf), hostf);
					else
						(void) printf(
						    "%-16.16s %-.35s\n", hostf,
						    timef);
				}
				(void) fflush(stdout);
				if (++outrec >= maxrec)
					exit(0);
			}
			/*
			 * when the system is down or crashed.
			 */
			if (bp->ut_type == BOOT_TIME) {
				for (i = 0; i < lines; i++)
					logouts[i] = -bp->ut_xtime;
				bootxtime = -bp->ut_xtime;
				/*
				 * TRANSLATION_NOTE
				 * Translation of this "down " will replace
				 * the %s in "- %s".  "down" is used instead
				 * of the real time session was ended, probably
				 * because the session ended by a sudden crash.
				 */
				crmsg = gettext("down ");
			}
			print = 0;	/* reset the print flag */
		}
	}
	ct = ctime(&buf[0].ut_xtime);
	if (lflag > 0) {
		(void) printf(gettext("\nwtmp begins %10.10s %13.13s \n"), ct,
		    ct + 11);
	} else {
		(void) printf(gettext("\nwtmp begins %10.10s %5.5s \n"), ct,
		    ct + 11);
	}

	/* free() called to prevent lint warning about names */
	free(names);

	return (0);
}

static void
reallocate_buffer()
{
	int j;
	static char	**tmpttnames;
	static time_t	*tmplogouts;

	lines += CHUNK_SIZE;
	tmpttnames = realloc(ttnames, sizeof (char *)*lines);
	tmplogouts = realloc(logouts, sizeof (time_t)*lines);
	if (tmpttnames == NULL || tmplogouts == NULL) {
		(void) fprintf(stderr, gettext("Out of memory \n"));
		exit(2);
	} else {
		ttnames = tmpttnames;
		logouts = tmplogouts;
	}
	for (j = lines-CHUNK_SIZE; j < lines; j++) {
		ttnames[j] = NULL;
		logouts[j] = bootxtime;
	}
}

static void
memory_alloc(int i)
{
	ttnames[i] = (char *)malloc(LMAX + HMAX + NMAX + 3);
	if (ttnames[i] == NULL) {
		(void) fprintf(stderr, gettext("Out of memory \n "));
		exit(2);
	}
}

static void
onintr(int signo)
{
	char *ct;

	if (signo == SIGQUIT)
		(void) signal(SIGQUIT, (void(*)())onintr);
	ct = ctime(&buf[0].ut_xtime);
	(void) printf(gettext("\ninterrupted %10.10s %5.5s \n"), ct, ct + 11);
	(void) fflush(stdout);
	if (signo == SIGINT)
		exit(1);
}

static int
want(struct utmpx *bp, char **host, char **user)
{
	char **name;
	int i;
	char *zerostr = "\0";

	*host = zerostr; *user = zerostr;

		/* if ut_line = dtremote for the users who did dtremote login */
	if (strncmp(bp->ut_line, "dtremote", 8) == 0) {
		*host = bp->ut_host;
		*user = bp->ut_user;
	}
		/* if ut_line = dtlocal for the users who did a dtlocal login */
	else if (strncmp(bp->ut_line, "dtlocal", 7) == 0) {
		*host = bp->ut_host;
		*user = bp->ut_user;
	}
		/*
		 * Both dtremote and dtlocal can have multiple entries in
		 * /var/adm/wtmpx with these values, so the user and host
		 * entries are also checked
		 */
	if ((bp->ut_type == BOOT_TIME) || (bp->ut_type == DOWN_TIME))
		(void) strcpy(bp->ut_user, "reboot");

	if (bp->ut_type != USER_PROCESS && bp->ut_type != DEAD_PROCESS &&
	    bp->ut_type != BOOT_TIME && bp->ut_type != DOWN_TIME)
		return (0);

	if (bp->ut_user[0] == '.')
		return (0);

	if (names_num == 0) {
		if (bp->ut_line[0] != '\0')
			return (1);
	} else {
		name = names;
		for (i = 0; i < names_num; i++, name++) {
			if (nameq(*name, bp->ut_name) ||
			    lineq(*name, bp->ut_line) ||
			    (lineq(*name, "ftp") &&
			    (strncmp(bp->ut_line, "ftp", 3) == 0))) {
				return (1);
			}
		}
	}
	return (0);
}

static char *
strspl(char *left, char *right)
{
	size_t ressize = strlen(left) + strlen(right) + 1;

	char *res = malloc(ressize);

	if (res == NULL) {
		perror("last");
		exit(2);
	}
	(void) strlcpy(res, left, ressize);
	(void) strlcat(res, right, ressize);
	return (res);
}

static void
record_time(time_t *otime, int *print, int i, struct utmpx *bp)
{
	*otime = logouts[i];
	logouts[i] = bp->ut_xtime;
	if ((bp->ut_type == USER_PROCESS && bp->ut_user[0] != '\0') ||
	    (bp->ut_type == BOOT_TIME) || (bp->ut_type == DOWN_TIME))
		*print = 1;
	else
		*print = 0;
}
