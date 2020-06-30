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
 * Copyright (c) 2013 Gary Mills
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2020 Joyent, Inc.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

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
 * This is the new w command which takes advantage of
 * the /proc interface to gain access to the information
 * of all the processes currently on the system.
 *
 * This program also implements 'uptime'.
 *
 * Maintenance note:
 *
 * Much of this code is replicated in whodo.c.  If you're
 * fixing bugs here, then you should probably fix 'em there too.
 */

#include <sys/types.h>
#include <sys/loadavg.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <locale.h>
#include <priv_utils.h>
#include <procfs.h>		/* /proc header file */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <utmpx.h>

/*
 * Use the full lengths from utmpx for user and line.
 */
static struct utmpx dummy;
#define	NMAX		(sizeof (dummy.ut_user))
#define	LMAX		(sizeof (dummy.ut_line))

/* Print minimum field widths. */
#define	LOGIN_WIDTH	8
#define	LINE_WIDTH	8

#define	DIV60(t)	((t+30)/60)	/* x/60 rounded */

#define	PROCDIR		"/proc"
#define	PRINTF(a)	if (printf a < 0) { \
		perror((gettext("%s: printf failed"), prog)); \
		exit(1); }

struct uproc {
	pid_t	p_upid;			/* process id */
	dev_t   p_ttyd;			/* controlling tty of process */
	time_t  p_time;			/* seconds of user & system time */
	time_t	p_ctime;		/* seconds of child user & sys time */
	int	p_igintr;		/* 1 = ignores SIGQUIT and SIGINT */
	char    p_comm[PRARGSZ+1];	/* command */
	char    p_args[PRARGSZ+1];	/* command line arguments */
	STAILQ_ENTRY(uproc) uprocs;
};
STAILQ_HEAD(uprochead, uproc) uphead;

static time_t	findidle(char *);
static void	clnarglist(char *);
static void	prttime(time_t, int);
static void	prtat(time_t *time);

static int	priv_proc_open(const char *, int);
static int	priv_proc_openat(int, const char *, int);
static boolean_t do_proc_read(int, void *, size_t);

static char	*prog;		/* pointer to invocation name */
static int	header = 1;	/* true if -h flag: don't print heading */
static int	lflag = 1;	/* set if -l flag; 0 for -s flag: short form */
static char	*sel_user;	/* login of particular user selected */
static char	firstchar;	/* first char of name of prog invoked as */
static int	login;		/* true if invoked as login shell */
static time_t	now;		/* current time of day */
static time_t	uptime;		/* time of last reboot & elapsed time since */
static int	nusers;		/* number of users logged in now */

/*
 * Basic privs we never need and can drop. This is likely not exhaustive,
 * but should significantly reduce any potential attack surfaces.
 */
static const char *drop_privs[] = {
	PRIV_FILE_WRITE,
	PRIV_NET_ACCESS,
	PRIV_PROC_EXEC,
	PRIV_PROC_FORK,
	PRIV_FILE_LINK_ANY
};

#if SIGQUIT > SIGINT
#define	ACTSIZE	SIGQUIT
#else
#define	ACTSIZE	SIGINT
#endif

int
main(int argc, char *argv[])
{
	struct utmpx	*ut;
	struct utmpx	*utmpbegin;
	struct utmpx	*utmpend;
	struct utmpx	*utp;
	struct uproc	*up;
	struct psinfo	info;
	struct sigaction actinfo[ACTSIZE];
	struct pstatus	statinfo;
	struct stat	sbuf;
	DIR		*dirp;
	struct dirent	*dp;
	char		pname[PATH_MAX];
	int		procfd;
	int		dirfd;
	char		*cp;
	int		i;
	int		days, hrs, mins;
	int		entries;
	double		loadavg[3];
	priv_set_t	*pset;

	if (__init_suid_priv(PU_CLEARLIMITSET, PRIV_PROC_OWNER, NULL) != 0) {
		err(EXIT_FAILURE, "failed to enable privilege bracketing");
	}

	/*
	 * After setting up privilege bracketing, we can further reduce the
	 * privileges in use. The effective set is set to the basic set minus
	 * the privs in drop_privs. The permitted set is the effective set
	 * plus PRIV_PROC_OWNER (i.e. the privilege being bracketed).
	 */
	pset = priv_allocset();
	if (pset == NULL)
		err(EXIT_FAILURE, "priv_allocset failed");

	priv_basicset(pset);
	for (i = 0; i < ARRAY_SIZE(drop_privs); i++) {
		if (priv_delset(pset, drop_privs[i]) != 0) {
			err(EXIT_FAILURE,
			    "failed to remove %s privilege from privilege set",
			    drop_privs[i]);
		}
	}

	if (setppriv(PRIV_SET, PRIV_EFFECTIVE, pset) < 0)
		err(EXIT_FAILURE, "failed setting effective privilege set");

	if (priv_addset(pset, PRIV_PROC_OWNER) != 0) {
		err(EXIT_FAILURE,
		    "failed to add PRIV_PROC_OWNER privilege to privilege set");
	}

	if (setppriv(PRIV_SET, PRIV_PERMITTED, pset) < 0)
		err(EXIT_FAILURE, "failed to set permitted privilege set");

	/*
	 * Unfortunately, when run as root, privilege bracketing is a no-op,
	 * so we have to add PRIV_PROC_OWNER into our effective set for things
	 * to work.
	 */
	if (getuid() == 0 && setppriv(PRIV_SET, PRIV_EFFECTIVE, pset) < 0) {
		err(EXIT_FAILURE, "failed to set effective privilege set");
	}

	priv_freeset(pset);
	pset = NULL;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	login = (argv[0][0] == '-');
	cp = strrchr(argv[0], '/');
	firstchar = login ? argv[0][1] : (cp == 0) ? argv[0][0] : cp[1];
	prog = argv[0];

	while (argc > 1) {
		if (argv[1][0] == '-') {
			for (i = 1; argv[1][i]; i++) {
				switch (argv[1][i]) {

				case 'h':
					header = 0;
					break;

				case 'l':
					lflag++;
					break;
				case 's':
					lflag = 0;
					break;

				case 'u':
				case 'w':
					firstchar = argv[1][i];
					break;

				default:
					(void) fprintf(stderr, gettext(
					    "%s: bad flag %s\n"),
					    prog, argv[1]);
					exit(1);
				}
			}
		} else {
			if (!isalnum(argv[1][0]) || argc > 2) {
				(void) fprintf(stderr, gettext(
				    "usage: %s [ -hlsuw ] [ user ]\n"), prog);
				exit(1);
			} else
				sel_user = argv[1];
		}
		argc--; argv++;
	}

	/*
	 * read the UTMPX_FILE (contains information about each logged in user)
	 */
	if (stat(UTMPX_FILE, &sbuf) < 0)
		err(EXIT_FAILURE, gettext("stat error of %s"), UTMPX_FILE);

	entries = sbuf.st_size / sizeof (struct futmpx);
	if ((ut = calloc(entries, sizeof (struct utmpx))) == NULL)
		err(EXIT_FAILURE, gettext("calloc error of %s"), UTMPX_FILE);

	(void) utmpxname(UTMPX_FILE);

	utmpbegin = ut;
	utmpend = utmpbegin + entries;

	setutxent();
	while ((ut < utmpend) && ((utp = getutxent()) != NULL))
		(void) memcpy(ut++, utp, sizeof (*ut));
	endutxent();

	(void) time(&now);	/* get current time */

	if (header) {	/* print a header */
		prtat(&now);
		for (ut = utmpbegin; ut < utmpend; ut++) {
			if (ut->ut_type == USER_PROCESS) {
				if (!nonuserx(*ut))
					nusers++;
			} else if (ut->ut_type == BOOT_TIME) {
				uptime = now - ut->ut_xtime;
				uptime += 30;
				days = uptime / (60*60*24);
				uptime %= (60*60*24);
				hrs = uptime / (60*60);
				uptime %= (60*60);
				mins = uptime / 60;

				PRINTF((gettext("up")));
				if (days > 0)
					PRINTF((gettext(
					    " %d day(s),"), days));
				if (hrs > 0 && mins > 0) {
					PRINTF((" %2d:%02d,", hrs, mins));
				} else {
					if (hrs > 0)
						PRINTF((gettext(
						    " %d hr(s),"), hrs));
					if (mins > 0)
						PRINTF((gettext(
						    " %d min(s),"), mins));
				}
			}
		}

		ut = utmpbegin;	/* rewind utmp data */
		PRINTF((((nusers == 1) ?
		    gettext("  %d user") : gettext("  %d users")), nusers));
		/*
		 * Print 1, 5, and 15 minute load averages.
		 */
		(void) getloadavg(loadavg, 3);
		PRINTF((gettext(",  load average: %.2f, %.2f, %.2f\n"),
		    loadavg[LOADAVG_1MIN], loadavg[LOADAVG_5MIN],
		    loadavg[LOADAVG_15MIN]));

		if (firstchar == 'u')	/* uptime command */
			exit(0);

		if (lflag) {
			PRINTF((dcgettext(NULL, "User     tty      "
			    "login@         idle    JCPU    PCPU what\n",
			    LC_TIME)));
		} else {
			PRINTF((dcgettext(NULL,
			    "User     tty         idle what\n",
			    LC_TIME)));
		}

		if (fflush(stdout) == EOF) {
			err(EXIT_FAILURE, "fflush failed");
		}
	}

	/* Loop through /proc, reading info about each process */
	if ((dirp = opendir(PROCDIR)) == NULL)
		err(EXIT_FAILURE, gettext("could not open %s"), PROCDIR);

	STAILQ_INIT(&uphead);
	while ((dp = readdir(dirp)) != NULL) {
		if (dp->d_name[0] == '.')
			continue;

		if (snprintf(pname, sizeof (pname), "%s/%s", PROCDIR,
		    dp->d_name) > sizeof (pname))
			continue;

		dirfd = priv_proc_open(pname, O_RDONLY | O_DIRECTORY);
		if (dirfd < 0)
			continue;

		procfd = priv_proc_openat(dirfd, "psinfo", O_RDONLY);
		if (procfd < 0) {
			(void) close(dirfd);
			continue;
		}
		if (!do_proc_read(procfd, &info, sizeof (info))) {
			warn(gettext("failed to read %s"), pname);
			(void) close(dirfd);
			continue;
		}
		(void) close(procfd);

		/* Not interested in zombies */
		if (info.pr_nlwp == 0)
			continue;
		/* Not interested in processes without a terminal */
		if (info.pr_ttydev == NODEV)
			continue;

		procfd = priv_proc_openat(dirfd, "status", O_RDONLY);
		if (procfd < 0) {
			(void) close(dirfd);
			continue;
		}
		if (!do_proc_read(procfd, &statinfo, sizeof (statinfo))) {
			warn(gettext("failed to read %s/status"), pname);
			(void) close(procfd);
			(void) close(dirfd);
			continue;
		}
		(void) close(procfd);

		procfd = priv_proc_openat(dirfd, "sigact", O_RDONLY);
		if (procfd < 0) {
			(void) close(dirfd);
			continue;
		}
		if (!do_proc_read(procfd, actinfo, sizeof (actinfo))) {
			warn(gettext("failed to read %s/sigact"), pname);
			(void) close(procfd);
			(void) close(dirfd);
			continue;
		}
		(void) close(procfd);
		(void) close(dirfd);

		up = calloc(1, sizeof (*up));
		if (up == NULL)
			err(EXIT_FAILURE, "calloc");
		up->p_upid = info.pr_pid;
		up->p_ttyd = info.pr_ttydev;
		up->p_time =
		    statinfo.pr_utime.tv_sec +
		    statinfo.pr_stime.tv_sec;
		up->p_ctime =
		    statinfo.pr_cutime.tv_sec +
		    statinfo.pr_cstime.tv_sec;
		up->p_igintr =
		    actinfo[SIGINT-1].sa_handler == SIG_IGN &&
		    actinfo[SIGQUIT-1].sa_handler == SIG_IGN;
		(void) strlcpy(up->p_comm, info.pr_fname, sizeof (up->p_comm));
		/* Process args */
		clnarglist(info.pr_psargs);
		(void) strlcpy(up->p_args, info.pr_psargs, sizeof (up->p_args));
		if (up->p_args[0] == 0 || up->p_args[0] == '?' ||
		    (up->p_args[0] == '-' && up->p_args[1] <= ' ')) {
			(void) strlcat(up->p_args, " (", sizeof (up->p_args));
			(void) strlcat(up->p_args, up->p_comm,
			    sizeof (up->p_args));
			(void) strlcat(up->p_args, ")", sizeof (up->p_args));
		}
		STAILQ_INSERT_TAIL(&uphead, up, uprocs);
	}

	/* revert to non-privileged user after opening */
	__priv_relinquish();
	if (getuid() == 0) {
		/*
		 * Since the privilege bracketing functions are effectively
		 * no-ops when running as root, we must explicitly
		 * relinquish PRIV_PROC_OWNER ourselves.
		 */
		pset = priv_allocset();
		if (pset == NULL) {
			err(EXIT_FAILURE,
			    gettext("failed to allocate privilege set"));
		}

		priv_emptyset(pset);

		if (priv_addset(pset, PRIV_PROC_OWNER) != 0) {
			err(EXIT_FAILURE, gettext("failed to add "
			    "PRIV_PROC_OWNER to privilege set"));
		}

		if (setppriv(PRIV_OFF, PRIV_PERMITTED, pset) != 0) {
			err(EXIT_FAILURE,
			    gettext("failed to set permitted privilege set"));
		}

		priv_freeset(pset);
		pset = NULL;
	}

	(void) closedir(dirp);
	(void) time(&now);	/* get current time */

	/*
	 * loop through utmpx file, printing process info
	 * about each logged in user
	 */
	for (ut = utmpbegin; ut < utmpend; ut++) {
		struct uproc *upt;
		char linedev[PATH_MAX];
		char what[1024];
		time_t idle, jobtime, proctime;
		pid_t curpid;

		if (ut->ut_type != USER_PROCESS)
			continue;
		if (sel_user != NULL &&
		    strncmp(ut->ut_name, sel_user, NMAX) != 0)
			continue;

		/* print login name of the user */
		PRINTF(("%-*.*s ", LOGIN_WIDTH, NMAX, ut->ut_name));

		/* print tty user is on */
		if (lflag) {
			PRINTF(("%-*.*s ", LINE_WIDTH, LMAX, ut->ut_line));
		} else {
			if (strncmp(ut->ut_line, "pts/", strlen("pts/")) == 0) {
				PRINTF(("%-*.*s ", LINE_WIDTH, LMAX,
				    &ut->ut_line[4]));
			} else {
				PRINTF(("%-*.*s ", LINE_WIDTH, LMAX,
				    ut->ut_line));
			}
		}

		/* print when the user logged in */
		if (lflag) {
			time_t tim = ut->ut_xtime;
			prtat(&tim);
		}

		/* print idle time */
		idle = findidle(ut->ut_line);
		prttime(idle, 8);

		/*
		 * Go through the list of processes for this terminal,
		 * calculating job/process times, and look for the
		 * "most interesting" process.
		 */
		jobtime = 0;
		proctime = 0;
		curpid = -1;
		(void) strlcpy(what, "-", sizeof (what));

		(void) snprintf(linedev, sizeof (linedev), "/dev/%s",
		    ut->ut_line);
		if (stat(linedev, &sbuf) == -1 ||
		    (sbuf.st_mode & S_IFMT) != S_IFCHR ||
		    sbuf.st_rdev == NODEV)
			goto skip;

		STAILQ_FOREACH_SAFE(up, &uphead, uprocs, upt) {
			if (up->p_ttyd != sbuf.st_rdev)
				continue;
			jobtime += up->p_time + up->p_ctime;
			proctime += up->p_time;
			/*
			 * Check for "most interesting" process, currently
			 * the one having the highest PID.
			 */
			if (up->p_upid > curpid && !up->p_igintr) {
				curpid = up->p_upid;
				if (lflag) {
					(void) strlcpy(what, up->p_args,
					    sizeof (what));
				} else {
					(void) strlcpy(what, up->p_comm,
					    sizeof (what));
				}
			}
			STAILQ_REMOVE(&uphead, up, uproc, uprocs);
			free(up);
		}

skip:
		if (lflag) {
			/* Print CPU time for all processes & children */
			prttime(jobtime, 8);
			/* Print cpu time for interesting process */
			prttime(proctime, 8);
		}
		/* "Most interesting" process */
		PRINTF(("%-.32s\n", what));
	}

	if (fclose(stdout) == EOF)
		err(EXIT_FAILURE, gettext("fclose failed"));

	return (0);
}

#define	HR	(60 * 60)
#define	DAY	(24 * HR)
#define	MON	(30 * DAY)

/*
 * Prttime prints an elapsed time in hours, minutes, or seconds,
 * right-justified with the rightmost column always blank.
 * The second argument is the minimum field width.
 */
static void
prttime(time_t tim, int width)
{
	char value[36];

	if (tim >= 36 * 60) {
		(void) snprintf(value, sizeof (value), "%d:%02d:%02d",
		    (int)tim / HR, (int)(tim % HR) / 60, (int)tim % 60);
	} else if (tim >= 60) {
		(void) snprintf(value, sizeof (value), "%d:%02d",
		    (int)tim / 60, (int)tim % 60);
	} else if (tim > 0) {
		(void) snprintf(value, sizeof (value), "%d", (int)tim);
	} else {
		(void) strlcpy(value, "0", sizeof (value));
	}
	width = (width > 2) ? width - 1 : 1;
	PRINTF(("%*s ", width, value));
}

/*
 * Prints the ISO date or time given a pointer to a time of day,
 * left-justfied in a 12-character expanding field with the
 * rightmost column always blank.
 * Includes a dcgettext() override in case a message catalog is needed.
 */
static void
prtat(time_t *time)
{
	struct tm	*p;

	p = localtime(time);
	if (now - *time <= 18 * HR) {
		char timestr[50];

		(void) strftime(timestr, sizeof (timestr),
		    dcgettext(NULL, "%T", LC_TIME), p);
		PRINTF(("%-11s ", timestr));
	} else if (now - *time <= 7 * DAY) {
		char weekdaytime[20];

		(void) strftime(weekdaytime, sizeof (weekdaytime),
		    dcgettext(NULL, "%a %H:%M", LC_TIME), p);
		PRINTF(("%-11s ", weekdaytime));
	} else {
		char monthtime[20];

		(void) strftime(monthtime, sizeof (monthtime),
		    dcgettext(NULL, "%F", LC_TIME), p);
		PRINTF(("%-11s ", monthtime));
	}
}

/*
 * find & return number of minutes current tty has been idle
 */
static time_t
findidle(char *devname)
{
	struct stat stbuf;
	time_t lastaction, diff;
	char ttyname[64];

	(void) strlcpy(ttyname, "/dev/", sizeof (ttyname));
	(void) strlcat(ttyname, devname, sizeof (ttyname));
	if (stat(ttyname, &stbuf) != -1) {
		lastaction = stbuf.st_atime;
		diff = now - lastaction;
		diff = DIV60(diff);
		if (diff < 0)
			diff = 0;
	} else
		diff = 0;
	return (diff);
}

/*
 * given a pointer to the argument string get rid of unsavory characters.
 */
static void
clnarglist(char *arglist)
{
	char	*c;
	int	err = 0;

	/* get rid of unsavory characters */
	for (c = arglist; *c != '\0'; c++) {
		if ((*c < ' ') || (*c > 0176)) {
			if (err++ > 5) {
				*arglist = '\0';
				break;
			}
			*c = '?';
		}
	}
}

static int
priv_proc_open(const char *path, int oflag)
{
	int fd, errsave = 0;

	if (__priv_bracket(PRIV_ON) != 0)
		err(EXIT_FAILURE, gettext("privilege bracketing failed"));

	do {
		fd = open(path, oflag);
		if (fd < 0)
			errsave = errno;
	} while (fd < 0 && errno == EAGAIN);

	if (__priv_bracket(PRIV_OFF) != 0)
		err(EXIT_FAILURE, gettext("privilege bracketing failed"));

	if (fd < 0)
		errno = errsave;

	return (fd);
}

static int
priv_proc_openat(int dfd, const char *path, int mode)
{
	int fd, errsave = 0;

	if (__priv_bracket(PRIV_ON) != 0)
		err(EXIT_FAILURE, gettext("privilege bracketing failed"));

	do {
		fd = openat(dfd, path, mode);
		if (fd < 0)
			errsave = errno;
	} while (fd < 0 && errno == EAGAIN);

	if (__priv_bracket(PRIV_OFF) != 0)
		err(EXIT_FAILURE, gettext("privilege bracketing failed"));

	if (fd < 0)
		errno = errsave;

	return (fd);
}

static boolean_t
do_proc_read(int fd, void *buf, size_t bufsize)
{
	ssize_t n;

	do {
		n = pread(fd, buf, bufsize, 0);
		if (n == bufsize)
			return (B_TRUE);
		/*
		 * Retry on a partial read or EAGAIN, otherwise fail
		 */
	} while (n >= 0 || errno == EAGAIN);

	return (B_FALSE);
}
