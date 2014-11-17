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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012, Joyent, Inc.  All rights reserved.
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
 * ps -- print things about processes.
 */

#define	_SYSCALL32

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <dirent.h>
#include <procfs.h>
#include <sys/param.h>
#include <sys/ttold.h>
#include <libelf.h>
#include <gelf.h>
#include <locale.h>
#include <wctype.h>
#include <stdarg.h>
#include <sys/proc.h>
#include <priv_utils.h>
#include <zone.h>

#define	NTTYS	2	/* max ttys that can be specified with the -t option */
			/* only one tty can be specified with SunOS ps */
#define	SIZ	30	/* max processes that can be specified with -p and -g */
#define	ARGSIZ	30	/* size of buffer holding args for -t, -p, -u options */

#define	FSTYPE_MAX	8

struct psent {
	psinfo_t *psinfo;
	char *psargs;
	int found;
};

static	int	tplen, maxlen, twidth;
static	char	hdr[81];
static	struct	winsize win;

static	int	retcode = 1;
static	int	lflg;	/* long format */
static	int	uflg;	/* user-oriented output */
static	int	aflg;	/* Display all processes */
static	int	eflg;	/* Display environment as well as arguments */
static	int	gflg;	/* Display process group leaders */
static	int	tflg;	/* Processes running on specific terminals */
static	int	rflg;	/* Running processes only flag */
static	int	Sflg;	/* Accumulated time plus all reaped children */
static	int	xflg;	/* Include processes with no controlling tty */
static	int	cflg;	/* Display command name */
static	int	vflg;	/* Virtual memory-oriented output */
static	int	nflg;	/* Numerical output */
static	int	pflg;	/* Specific process id passed as argument */
static	int	Uflg;	/* Update private database, ups_data */
static	int	errflg;

static	char	*gettty();
static	char	argbuf[ARGSIZ];
static	char	*parg;
static	char	*p1;		/* points to successive option arguments */
static	uid_t	my_uid;
static char	stdbuf[BUFSIZ];

static	int	ndev;		/* number of devices */
static	int	maxdev;		/* number of devl structures allocated */

#define	DNINCR	100
#define	DNSIZE	14
static	struct devl {		/* device list	 */
	char	dname[DNSIZE];	/* device name	 */
	dev_t	ddev;		/* device number */
} *devl;

static	struct tty {
	char *tname;
	dev_t tdev;
} tty[NTTYS];			/* for t option */
static	int	ntty = 0;
static	pid_t	pidsave;
static	int	pidwidth;

static	char	*procdir = "/proc";	/* standard /proc directory */
static	void	usage();		/* print usage message and quit */
static	void	getarg(void);
static	void	prtime(timestruc_t st);
static	void	przom(psinfo_t *psinfo);
static	int	num(char *);
static	int	preadargs(int, psinfo_t *, char *);
static	int	preadenvs(int, psinfo_t *, char *);
static	int	prcom(int, psinfo_t *, char *);
static	int	namencnt(char *, int, int);
static	int	pscompare(const void *, const void *);
static	char	*err_string(int);

extern int	scrwidth(wchar_t);	/* header file? */

int
ucbmain(int argc, char **argv)
{
	psinfo_t info;		/* process information structure from /proc */
	char *psargs = NULL;	/* pointer to buffer for -w and -ww options */
	char *svpsargs = NULL;
	struct psent *psent;
	int entsize;
	int nent;
	pid_t maxpid;

	struct tty *ttyp = tty;
	char	*tmp;
	char	*p;
	int	c;
	pid_t	pid;		/* pid: process id */
	pid_t	ppid;		/* ppid: parent process id */
	int	i, found;

	size_t	size;

	DIR *dirp;
	struct dirent *dentp;
	char	psname[100];
	char	asname[100];
	int	pdlen;
	size_t  len;

	(void) setlocale(LC_ALL, "");

	my_uid = getuid();

	/*
	 * This program needs the proc_owner privilege
	 */
	(void) __init_suid_priv(PU_CLEARLIMITSET, PRIV_PROC_OWNER,
	    (char *)NULL);

	/*
	 * calculate width of pid fields based on configured MAXPID
	 * (must be at least 5 to retain output format compatibility)
	 */
	maxpid = (pid_t)sysconf(_SC_MAXPID);
	pidwidth = 1;
	while ((maxpid /= 10) > 0)
		++pidwidth;
	pidwidth = pidwidth < 5 ? 5 : pidwidth;

	if (ioctl(1, TIOCGWINSZ, &win) == -1)
		twidth = 80;
	else
		twidth = (win.ws_col == 0 ? 80 : win.ws_col);

	/* add the '-' for BSD compatibility */
	if (argc > 1) {
		if (argv[1][0] != '-' && !isdigit(argv[1][0])) {
			len = strlen(argv[1]) + 2;
			tmp = malloc(len);
			if (tmp != NULL) {
				(void) snprintf(tmp, len, "%s%s", "-", argv[1]);
				argv[1] = tmp;
			}
		}
	}

	setbuf(stdout, stdbuf);
	while ((c = getopt(argc, argv, "lcaengrSt:xuvwU")) != EOF)
		switch (c) {
		case 'g':
			gflg++;	/* include process group leaders */
			break;
		case 'c':	/* display internal command name */
			cflg++;
			break;
		case 'r':	/* restrict output to running processes */
			rflg++;
			break;
		case 'S': /* display time by process and all reaped children */
			Sflg++;
			break;
		case 'x':	/* process w/o controlling tty */
			xflg++;
			break;
		case 'l':	/* long listing */
			lflg++;
			uflg = vflg = 0;
			break;
		case 'u':	/* user-oriented output */
			uflg++;
			lflg = vflg = 0;
			break;
		case 'U':	/* update private database ups_data */
			Uflg++;
			break;
		case 'w':	/* increase display width */
			if (twidth < 132)
				twidth = 132;
			else	/* second w option */
				twidth = NCARGS;
			break;
		case 'v':	/* display virtual memory format */
			vflg++;
			lflg = uflg = 0;
			break;
		case 'a':
			/*
			 * display all processes except process group
			 * leaders and processes w/o controlling tty
			 */
			aflg++;
			gflg++;
			break;
		case 'e':
			/* Display environment along with aguments. */
			eflg++;
			break;
		case 'n':	/* Display numerical output */
			nflg++;
			break;
		case 't':	/* restrict output to named terminal */
#define	TSZ	30
			tflg++;
			gflg++;
			xflg = 0;

			p1 = optarg;
			do {	/* only loop through once (NTTYS = 2) */
				parg = argbuf;
				if (ntty >= NTTYS-1)
					break;
				getarg();
				if ((p = malloc(TSZ+1)) == NULL) {
					(void) fprintf(stderr,
					    "ps: no memory\n");
					exit(1);
				}
				p[0] = '\0';
				size = TSZ;
				if (isdigit(*parg)) {
					(void) strcpy(p, "tty");
					size -= 3;
				}

				(void) strncat(p, parg, size);
				ttyp->tdev = PRNODEV;
				if (parg && *parg == '?')
					xflg++;
				else {
					char nambuf[TSZ+6]; /* for /dev/+\0 */
					struct stat64 s;
					(void) strcpy(nambuf, "/dev/");
					(void) strcat(nambuf, p);
					if (stat64(nambuf, &s) == 0)
						ttyp->tdev = s.st_rdev;
				}
				ttyp++->tname = p;
				ntty++;
			} while (*p1);
			break;
		default:			/* error on ? */
			errflg++;
			break;
		}

	if (errflg)
		usage();

	if (optind + 1 < argc) { /* more than one additional argument */
		(void) fprintf(stderr, "ps: too many arguments\n");
		usage();
	}

	/*
	 * The -U option is obsolete.  Attempts to use it cause ps to exit
	 * without printing anything.
	 */
	if (Uflg)
		exit(0);

	if (optind < argc) { /* user specified a specific proc id */
		pflg++;
		p1 = argv[optind];
		parg = argbuf;
		getarg();
		if (!num(parg)) {
			(void) fprintf(stderr,
	"ps: %s is an invalid non-numeric argument for a process id\n", parg);
			usage();
		}
		pidsave = (pid_t)atol(parg);
		aflg = rflg = xflg = 0;
		gflg++;
	}

	if (tflg)
		ttyp->tname = NULL;

	/* allocate an initial guess for the number of processes */
	entsize = 1024;
	psent = malloc(entsize * sizeof (struct psent));
	if (psent == NULL) {
		(void) fprintf(stderr, "ps: no memory\n");
		exit(1);
	}
	nent = 0;	/* no active entries yet */

	if (lflg) {
		(void) sprintf(hdr,
		    " F   UID%*s%*s %%C PRI NI   SZ  RSS    "
		    "WCHAN S TT        TIME COMMAND", pidwidth + 1, "PID",
		    pidwidth + 1, "PPID");
	} else if (uflg) {
		if (nflg)
			(void) sprintf(hdr,
			    "   UID%*s %%CPU %%MEM   SZ  RSS "
			    "TT       S    START  TIME COMMAND",
			    pidwidth + 1, "PID");
		else
			(void) sprintf(hdr,
			    "USER    %*s %%CPU %%MEM   SZ  RSS "
			    "TT       S    START  TIME COMMAND",
			    pidwidth + 1, "PID");
	} else if (vflg) {
		(void) sprintf(hdr,
		    "%*s TT       S  TIME SIZE  RSS %%CPU %%MEM "
		    "COMMAND", pidwidth + 1, "PID");
	} else
		(void) sprintf(hdr, "%*s TT       S  TIME COMMAND",
		    pidwidth + 1, "PID");

	twidth = twidth - strlen(hdr) + 6;
	(void) printf("%s\n", hdr);

	if (twidth > PRARGSZ && (psargs = malloc(twidth)) == NULL) {
		(void) fprintf(stderr, "ps: no memory\n");
		exit(1);
	}
	svpsargs = psargs;

	/*
	 * Determine which processes to print info about by searching
	 * the /proc directory and looking at each process.
	 */
	if ((dirp = opendir(procdir)) == NULL) {
		(void) fprintf(stderr, "ps: cannot open PROC directory %s\n",
		    procdir);
		exit(1);
	}

	(void) strcpy(psname, procdir);
	pdlen = strlen(psname);
	psname[pdlen++] = '/';

	/* for each active process --- */
	while ((dentp = readdir(dirp)) != NULL) {
		int	psfd;	/* file descriptor for /proc/nnnnn/psinfo */
		int	asfd;	/* file descriptor for /proc/nnnnn/as */

		if (dentp->d_name[0] == '.')		/* skip . and .. */
			continue;
		(void) strcpy(psname + pdlen, dentp->d_name);
		(void) strcpy(asname, psname);
		(void) strcat(psname, "/psinfo");
		(void) strcat(asname, "/as");
retry:
		if ((psfd = open(psname, O_RDONLY)) == -1)
			continue;
		asfd = -1;
		if (psargs != NULL || eflg) {

			/* now we need the proc_owner privilege */
			(void) __priv_bracket(PRIV_ON);

			asfd = open(asname, O_RDONLY);

			/* drop proc_owner privilege after open */
			(void) __priv_bracket(PRIV_OFF);
		}

		/*
		 * Get the info structure for the process
		 */
		if (read(psfd, &info, sizeof (info)) != sizeof (info)) {
			int	saverr = errno;

			(void) close(psfd);
			if (asfd > 0)
				(void) close(asfd);
			if (saverr == EAGAIN)
				goto retry;
			if (saverr != ENOENT)
				(void) fprintf(stderr, "ps: read() on %s: %s\n",
				    psname, err_string(saverr));
			continue;
		}
		(void) close(psfd);

		found = 0;
		if (info.pr_lwp.pr_state == 0)		/* can't happen? */
			goto closeit;
		pid = info.pr_pid;
		ppid = info.pr_ppid;

		/* Display only process from command line */
		if (pflg) {	/* pid in arg list */
			if (pidsave == pid)
				found++;
			else
				goto closeit;
		}

		/*
		 * Omit "uninteresting" processes unless 'g' option.
		 */
		if ((ppid == 1) && !(gflg))
			goto closeit;

		/*
		 * Omit non-running processes for 'r' option
		 */
		if (rflg &&
		    !(info.pr_lwp.pr_sname == 'O' ||
		    info.pr_lwp.pr_sname == 'R'))
			goto closeit;

		if (!found && !tflg && !aflg && info.pr_euid != my_uid)
			goto closeit;

		/*
		 * Read the args for the -w and -ww cases
		 */
		if (asfd > 0) {
			if ((psargs != NULL &&
			    preadargs(asfd, &info, psargs) == -1) ||
			    (eflg && preadenvs(asfd, &info, psargs) == -1)) {
				int	saverr = errno;

				(void) close(asfd);
				if (saverr == EAGAIN)
					goto retry;
				if (saverr != ENOENT)
					(void) fprintf(stderr,
					    "ps: read() on %s: %s\n",
					    asname, err_string(saverr));
				continue;
			}
		} else {
			psargs = info.pr_psargs;
		}

		if (nent >= entsize) {
			entsize *= 2;
			psent = (struct psent *)realloc((char *)psent,
			    entsize * sizeof (struct psent));
			if (psent == NULL) {
				(void) fprintf(stderr, "ps: no memory\n");
				exit(1);
			}
		}
		if ((psent[nent].psinfo = malloc(sizeof (psinfo_t)))
		    == NULL) {
			(void) fprintf(stderr, "ps: no memory\n");
			exit(1);
		}
		*psent[nent].psinfo = info;
		if (psargs == NULL)
			psent[nent].psargs = NULL;
		else {
			if ((psent[nent].psargs = malloc(strlen(psargs)+1))
			    == NULL) {
				(void) fprintf(stderr, "ps: no memory\n");
				exit(1);
			}
			(void) strcpy(psent[nent].psargs, psargs);
		}
		psent[nent].found = found;
		nent++;
closeit:
		if (asfd > 0)
			(void) close(asfd);
		psargs = svpsargs;
	}

	/* revert to non-privileged user */
	(void) __priv_relinquish();

	(void) closedir(dirp);

	qsort((char *)psent, nent, sizeof (psent[0]), pscompare);

	for (i = 0; i < nent; i++) {
		struct psent *pp = &psent[i];
		if (prcom(pp->found, pp->psinfo, pp->psargs)) {
			(void) printf("\n");
			retcode = 0;
		}
	}

	return (retcode);
}

static void
usage()		/* print usage message and quit */
{
	static char usage1[] = "ps [ -aceglnrSuUvwx ] [ -t term ] [ num ]";

	(void) fprintf(stderr, "usage: %s\n", usage1);
	exit(1);
}

/*
 * Read the process arguments from the process.
 * This allows >PRARGSZ characters of arguments to be displayed but,
 * unlike pr_psargs[], the process may have changed them.
 */
#define	NARG	100
static int
preadargs(int pfd, psinfo_t *psinfo, char *psargs)
{
	off_t argvoff = (off_t)psinfo->pr_argv;
	size_t len;
	char *psa = psargs;
	int bsize = twidth;
	int narg = NARG;
	off_t argv[NARG];
	off_t argoff;
	off_t nextargoff;
	int i;
#ifdef _LP64
	caddr32_t argv32[NARG];
	int is32 = (psinfo->pr_dmodel != PR_MODEL_LP64);
#endif

	if (psinfo->pr_nlwp == 0 ||
	    strcmp(psinfo->pr_lwp.pr_clname, "SYS") == 0)
		goto out;

	(void) memset(psa, 0, bsize--);
	nextargoff = 0;
	errno = EIO;
	while (bsize > 0) {
		if (narg == NARG) {
			(void) memset(argv, 0, sizeof (argv));
#ifdef _LP64
			if (is32) {
				if ((i = pread(pfd, argv32, sizeof (argv32),
				    argvoff)) <= 0) {
					if (i == 0 || errno == EIO)
						break;
					return (-1);
				}
				for (i = 0; i < NARG; i++)
					argv[i] = argv32[i];
			} else
#endif
				if ((i = pread(pfd, argv, sizeof (argv),
				    argvoff)) <= 0) {
					if (i == 0 || errno == EIO)
						break;
					return (-1);
				}
			narg = 0;
		}
		if ((argoff = argv[narg++]) == 0)
			break;
		if (argoff != nextargoff &&
		    (i = pread(pfd, psa, bsize, argoff)) <= 0) {
			if (i == 0 || errno == EIO)
				break;
			return (-1);
		}
		len = strlen(psa);
		psa += len;
		*psa++ = ' ';
		bsize -= len + 1;
		nextargoff = argoff + len + 1;
#ifdef _LP64
		argvoff += is32? sizeof (caddr32_t) : sizeof (caddr_t);
#else
		argvoff += sizeof (caddr_t);
#endif
	}
	while (psa > psargs && isspace(*(psa-1)))
		psa--;

out:
	*psa = '\0';
	if (strlen(psinfo->pr_psargs) > strlen(psargs))
		(void) strcpy(psargs, psinfo->pr_psargs);

	return (0);
}

/*
 * Read environment variables from the process.
 * Append them to psargs if there is room.
 */
static int
preadenvs(int pfd, psinfo_t *psinfo, char *psargs)
{
	off_t envpoff = (off_t)psinfo->pr_envp;
	int len;
	char *psa;
	char *psainit;
	int bsize;
	int nenv = NARG;
	off_t envp[NARG];
	off_t envoff;
	off_t nextenvoff;
	int i;
#ifdef _LP64
	caddr32_t envp32[NARG];
	int is32 = (psinfo->pr_dmodel != PR_MODEL_LP64);
#endif

	psainit = psa = (psargs != NULL)? psargs : psinfo->pr_psargs;
	len = strlen(psa);
	psa += len;
	bsize = twidth - len - 1;

	if (bsize <= 0 || psinfo->pr_nlwp == 0 ||
	    strcmp(psinfo->pr_lwp.pr_clname, "SYS") == 0)
		return (0);

	nextenvoff = 0;
	errno = EIO;
	while (bsize > 0) {
		if (nenv == NARG) {
			(void) memset(envp, 0, sizeof (envp));
#ifdef _LP64
			if (is32) {
				if ((i = pread(pfd, envp32, sizeof (envp32),
				    envpoff)) <= 0) {
					if (i == 0 || errno == EIO)
						break;
					return (-1);
				}
				for (i = 0; i < NARG; i++)
					envp[i] = envp32[i];
			} else
#endif
				if ((i = pread(pfd, envp, sizeof (envp),
				    envpoff)) <= 0) {
					if (i == 0 || errno == EIO)
						break;
					return (-1);
				}
			nenv = 0;
		}
		if ((envoff = envp[nenv++]) == 0)
			break;
		if (envoff != nextenvoff &&
		    (i = pread(pfd, psa+1, bsize, envoff)) <= 0) {
			if (i == 0 || errno == EIO)
				break;
			return (-1);
		}
		*psa++ = ' ';
		len = strlen(psa);
		psa += len;
		bsize -= len + 1;
		nextenvoff = envoff + len + 1;
#ifdef _LP64
		envpoff += is32? sizeof (caddr32_t) : sizeof (caddr_t);
#else
		envpoff += sizeof (caddr_t);
#endif
	}
	while (psa > psainit && isspace(*(psa-1)))
		psa--;
	*psa = '\0';

	return (0);
}

/*
 * getarg() finds the next argument in list and copies arg into argbuf.
 * p1 first pts to arg passed back from getopt routine.  p1 is then
 * bumped to next character that is not a comma or blank -- p1 NULL
 * indicates end of list.
 */

static void
getarg()
{
	char	*parga;
	int c;

	while ((c = *p1) != '\0' && (c == ',' || isspace(c)))
		p1++;

	parga = argbuf;
	while ((c = *p1) != '\0' && c != ',' && !isspace(c)) {
		if (parga < argbuf + ARGSIZ - 1)
			*parga++ = c;
		p1++;
	}
	*parga = '\0';

	while ((c = *p1) != '\0' && (c == ',' || isspace(c)))
		p1++;
}

static char *
devlookup(dev_t ddev)
{
	struct devl *dp;
	int i;

	for (dp = devl, i = 0; i < ndev; dp++, i++) {
		if (dp->ddev == ddev)
			return (dp->dname);
	}
	return (NULL);
}

static char *
devadd(char *name, dev_t ddev)
{
	struct devl *dp;
	int leng, start, i;

	if (ndev == maxdev) {
		maxdev += DNINCR;
		devl = realloc(devl, maxdev * sizeof (struct devl));
		if (devl == NULL) {
			(void) fprintf(stderr,
			    "ps: not enough memory for %d devices\n", maxdev);
			exit(1);
		}
	}
	dp = &devl[ndev++];

	dp->ddev = ddev;
	if (name == NULL) {
		(void) strcpy(dp->dname, "??");
		return (dp->dname);
	}

	leng = strlen(name);
	/* Strip off /dev/ */
	if (leng < DNSIZE + 4)
		(void) strcpy(dp->dname, &name[5]);
	else {
		start = leng - (DNSIZE - 1);

		for (i = start; i < leng && name[i] != '/'; i++)
				;
		if (i == leng)
			(void) strlcpy(dp->dname, &name[start], DNSIZE);
		else
			(void) strlcpy(dp->dname, &name[i+1], DNSIZE);
	}
	return (dp->dname);
}

/*
 * gettty returns the user's tty number or ? if none.
 */
static char *
gettty(psinfo_t *psinfo)
{
	extern char *_ttyname_dev(dev_t, char *, size_t);
	static zoneid_t zid = -1;
	char devname[TTYNAME_MAX];
	char *retval;

	if (zid == -1)
		zid = getzoneid();

	if (psinfo->pr_ttydev == PRNODEV || psinfo->pr_zoneid != zid)
		return ("?");

	if ((retval = devlookup(psinfo->pr_ttydev)) != NULL)
		return (retval);

	retval = _ttyname_dev(psinfo->pr_ttydev, devname, sizeof (devname));

	return (devadd(retval, psinfo->pr_ttydev));
}

/*
 * Print percent from 16-bit binary fraction [0 .. 1]
 * Round up .01 to .1 to indicate some small percentage (the 0x7000 below).
 */
static void
prtpct(ushort_t pct)
{
	uint_t value = pct;	/* need 32 bits to compute with */

	value = ((value * 1000) + 0x7000) >> 15;	/* [0 .. 1000] */
	(void) printf("%3u.%u", value / 10, value % 10);
}

/*
 * Print info about the process.
 */
static int
prcom(int found, psinfo_t *psinfo, char *psargs)
{
	char	*cp;
	char	*tp;
	char	*psa;
	long	tm;
	int	i, wcnt, length;
	wchar_t	wchar;
	struct tty *ttyp;

	/*
	 * If process is zombie, call print routine and return.
	 */
	if (psinfo->pr_nlwp == 0) {
		if (tflg && !found)
			return (0);
		else {
			przom(psinfo);
			return (1);
		}
	}

	/*
	 * Get current terminal.  If none ("?") and 'a' is set, don't print
	 * info.  If 't' is set, check if term is in list of desired terminals
	 * and print it if it is.
	 */
	i = 0;
	tp = gettty(psinfo);

	if (*tp == '?' && !found && !xflg)
		return (0);

	if (!(*tp == '?' && aflg) && tflg && !found) {
		int match = 0;
		char *other = NULL;
		for (ttyp = tty; ttyp->tname != NULL; ttyp++) {
			/*
			 * Look for a name match
			 */
			if (strcmp(tp, ttyp->tname) == 0) {
				match = 1;
				break;
			}
			/*
			 * Look for same device under different names.
			 */
			if ((other == NULL) &&
			    (psinfo->pr_ttydev == ttyp->tdev))
				other = ttyp->tname;
		}
		if (!match) {
			if (other == NULL)
				return (0);
			tp = other;
		}
	}

	if (lflg)
		(void) printf("%2x", psinfo->pr_flag & 0377);
	if (uflg) {
		if (!nflg) {
			struct passwd *pwd;

			if ((pwd = getpwuid(psinfo->pr_euid)) != NULL)
								/* USER */
				(void) printf("%-8.8s", pwd->pw_name);
			else
								/* UID */
				(void) printf(" %7.7d", (int)psinfo->pr_euid);
		} else {
			(void) printf(" %5d", (int)psinfo->pr_euid); /* UID */
		}
	} else if (lflg)
		(void) printf(" %5d", (int)psinfo->pr_euid);	/* UID */

	(void) printf("%*d", pidwidth + 1, (int)psinfo->pr_pid); /* PID */
	if (lflg)
		(void) printf("%*d", pidwidth + 1,
		    (int)psinfo->pr_ppid); /* PPID */
	if (lflg)
		(void) printf("%3d", psinfo->pr_lwp.pr_cpu & 0377); /* CP */
	if (uflg) {
		prtpct(psinfo->pr_pctcpu);			/* %CPU */
		prtpct(psinfo->pr_pctmem);			/* %MEM */
	}
	if (lflg) {
		(void) printf("%4d", psinfo->pr_lwp.pr_pri);	/* PRI */
		(void) printf("%3d", psinfo->pr_lwp.pr_nice);	/* NICE */
	}
	if (lflg || uflg) {
		if (psinfo->pr_flag & SSYS)			/* SZ */
			(void) printf("    0");
		else if (psinfo->pr_size)
			(void) printf(" %4lu", (ulong_t)psinfo->pr_size);
		else
			(void) printf("    ?");
		if (psinfo->pr_flag & SSYS)			/* RSS */
			(void) printf("    0");
		else if (psinfo->pr_rssize)
			(void) printf(" %4lu", (ulong_t)psinfo->pr_rssize);
		else
			(void) printf("    ?");
	}
	if (lflg) {						/* WCHAN */
		if (psinfo->pr_lwp.pr_sname != 'S') {
			(void) printf("         ");
		} else if (psinfo->pr_lwp.pr_wchan) {
			(void) printf(" %+8.8lx",
			    (ulong_t)psinfo->pr_lwp.pr_wchan);
		} else {
			(void) printf("        ?");
		}
	}
	if ((tplen = strlen(tp)) > 9)
		maxlen = twidth - tplen + 9;
	else
		maxlen = twidth;

	if (!lflg)
		(void) printf(" %-8.14s", tp);			/* TTY */
	(void) printf(" %c", psinfo->pr_lwp.pr_sname);		/* STATE */
	if (lflg)
		(void) printf(" %-8.14s", tp);			/* TTY */
	if (uflg)
		prtime(psinfo->pr_start);			/* START */

	/* time just for process */
	tm = psinfo->pr_time.tv_sec;
	if (Sflg) {	/* calculate time for process and all reaped children */
		tm += psinfo->pr_ctime.tv_sec;
		if (psinfo->pr_time.tv_nsec + psinfo->pr_ctime.tv_nsec
		    >= 1000000000)
			tm += 1;
	}

	(void) printf(" %2ld:%.2ld", tm / 60, tm % 60);		/* TIME */

	if (vflg) {
		if (psinfo->pr_flag & SSYS)			/* SZ */
			(void) printf("    0");
		else if (psinfo->pr_size)
			(void) printf("%5lu", (ulong_t)psinfo->pr_size);
		else
			(void) printf("    ?");
		if (psinfo->pr_flag & SSYS)			/* SZ */
			(void) printf("    0");
		else if (psinfo->pr_rssize)
			(void) printf("%5lu", (ulong_t)psinfo->pr_rssize);
		else
			(void) printf("    ?");
		prtpct(psinfo->pr_pctcpu);			/* %CPU */
		prtpct(psinfo->pr_pctmem);			/* %MEM */
	}
	if (cflg) {						/* CMD */
		wcnt = namencnt(psinfo->pr_fname, 16, maxlen);
		(void) printf(" %.*s", wcnt, psinfo->pr_fname);
		return (1);
	}
	/*
	 * PRARGSZ == length of cmd arg string.
	 */
	if (psargs == NULL) {
		psa = &psinfo->pr_psargs[0];
		i = PRARGSZ;
		tp = &psinfo->pr_psargs[PRARGSZ];
	} else {
		psa = psargs;
		i = strlen(psargs);
		tp = psa + i;
	}

	for (cp = psa; cp < tp; /* empty */) {
		if (*cp == 0)
			break;
		length = mbtowc(&wchar, cp, MB_LEN_MAX);
		if (length < 0 || !iswprint(wchar)) {
			(void) printf(" [ %.16s ]", psinfo->pr_fname);
			return (1);
		}
		cp += length;
	}
	wcnt = namencnt(psa, i, maxlen);
#if 0
	/* dumps core on really long strings */
	(void) printf(" %.*s", wcnt, psa);
#else
	(void) putchar(' ');
	(void) fwrite(psa, 1, wcnt, stdout);
#endif
	return (1);
}

/*
 * Print starting time of process unless process started more than 24 hours
 * ago, in which case the date is printed.
 */
static void
prtime(timestruc_t st)
{
	char sttim[26];
	static time_t tim = 0L;
	time_t starttime;

	if (tim == 0L)
		tim = time((time_t *)0);
	starttime = st.tv_sec;
	if (tim - starttime > 24*60*60) {
		(void) strftime(sttim, sizeof (sttim), "%b %d",
		    localtime(&starttime));
	} else {
		(void) strftime(sttim, sizeof (sttim), "%H:%M:%S",
		    localtime(&starttime));
	}
	(void) printf("%9.9s", sttim);
}

static void
przom(psinfo_t *psinfo)
{
	long	tm;

	if (lflg)
		(void) printf("%2x", psinfo->pr_flag & 0377);
	if (uflg) {
		struct passwd *pwd;

		if ((pwd = getpwuid(psinfo->pr_euid)) != NULL)
			(void) printf("%-8.8s", pwd->pw_name);	/* USER */
		else
			(void) printf(" %7.7d", (int)psinfo->pr_euid); /* UID */
	} else if (lflg)
		(void) printf(" %5d", (int)psinfo->pr_euid);	/* UID */

	(void) printf("%*d", pidwidth + 1, (int)psinfo->pr_pid); /* PID */
	if (lflg)
		(void) printf("%*d", pidwidth + 1,
		    (int)psinfo->pr_ppid); /* PPID */
	if (lflg)
		(void) printf("  0");				/* CP */
	if (uflg) {
		prtpct(0);					/* %CPU */
		prtpct(0);					/* %MEM */
	}
	if (lflg) {
		(void) printf("%4d", psinfo->pr_lwp.pr_pri);	/* PRI */
		(void) printf("   ");				/* NICE */
	}
	if (lflg || uflg) {
		(void) printf("    0");				/* SZ */
		(void) printf("    0");				/* RSS */
	}
	if (lflg)
		(void) printf("         ");			/* WCHAN */
	(void) printf("          ");				/* TTY */
	(void) printf("%c", psinfo->pr_lwp.pr_sname);		/* STATE */
	if (uflg)
		(void) printf("         ");			/* START */

	/* time just for process */
	tm = psinfo->pr_time.tv_sec;
	if (Sflg) {	/* calculate time for process and all reaped children */
		tm += psinfo->pr_ctime.tv_sec;
		if (psinfo->pr_time.tv_nsec + psinfo->pr_ctime.tv_nsec
		    >= 1000000000)
			tm += 1;
	}
	(void) printf(" %2ld:%.2ld", tm / 60, tm % 60);		/* TIME */

	if (vflg) {
		(void) printf("    0");				/* SZ */
		(void) printf("    0");				/* RSS */
		prtpct(0);					/* %CPU */
		prtpct(0);					/* %MEM */
	}
	(void) printf(" %.*s", maxlen, " <defunct>");
}

/*
 * Returns true iff string is all numeric.
 */
static int
num(char *s)
{
	int c;

	if (s == NULL)
		return (0);
	c = *s;
	do {
		if (!isdigit(c))
			return (0);
	} while ((c = *++s) != '\0');
	return (1);
}

/*
 * Function to compute the number of printable bytes in a multibyte
 * command string ("internationalization").
 */
static int
namencnt(char *cmd, int eucsize, int scrsize)
{
	int eucwcnt = 0, scrwcnt = 0;
	int neucsz, nscrsz;
	wchar_t	wchar;

	while (*cmd != '\0') {
		if ((neucsz = mbtowc(&wchar, cmd, MB_LEN_MAX)) < 0)
			return (8); /* default to use for illegal chars */
		if ((nscrsz = scrwidth(wchar)) == 0)
			return (8);
		if (eucwcnt + neucsz > eucsize || scrwcnt + nscrsz > scrsize)
			break;
		eucwcnt += neucsz;
		scrwcnt += nscrsz;
		cmd += neucsz;
	}
	return (eucwcnt);
}

static int
pscompare(const void *v1, const void *v2)
{
	const struct psent *p1 = v1;
	const struct psent *p2 = v2;
	int i;

	if (uflg)
		i = p2->psinfo->pr_pctcpu - p1->psinfo->pr_pctcpu;
	else if (vflg)
		i = p2->psinfo->pr_rssize - p1->psinfo->pr_rssize;
	else
		i = p1->psinfo->pr_ttydev - p2->psinfo->pr_ttydev;
	if (i == 0)
		i = p1->psinfo->pr_pid - p2->psinfo->pr_pid;
	return (i);
}

static char *
err_string(int err)
{
	static char buf[32];
	char *str = strerror(err);

	if (str == NULL)
		(void) sprintf(str = buf, "Errno #%d", err);

	return (str);
}
