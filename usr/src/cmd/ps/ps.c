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
 */

/*
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * ps -- print things about processes.
 */
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <dirent.h>
#include <sys/signal.h>
#include <sys/fault.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <procfs.h>
#include <locale.h>
#include <wctype.h>
#include <wchar.h>
#include <libw.h>
#include <stdarg.h>
#include <sys/proc.h>
#include <sys/pset.h>
#include <project.h>
#include <zone.h>

#define	min(a, b)	((a) > (b) ? (b) : (a))
#define	max(a, b)	((a) < (b) ? (b) : (a))

#define	NTTYS	20	/* initial size of table for -t option  */
#define	SIZ	30	/* initial size of tables for -p, -s, -g, -h and -z */

/*
 * Size of buffer holding args for t, p, s, g, u, U, G, z options.
 * Set to ZONENAME_MAX, the minimum value needed to allow any
 * zone to be specified.
 */
#define	ARGSIZ ZONENAME_MAX

/* Max chars in a user/group name or printed u/g id */
#define	MAXUGNAME (LOGNAME_MAX+2)

/* Structure for storing user or group info */
struct ugdata {
	id_t	id;			/* numeric user-id or group-id */
	char	name[MAXUGNAME+1];	/* user/group name, null terminated */
};

struct ughead {
	size_t	size;		/* number of ugdata structs allocated */
	size_t	nent;		/* number of active entries */
	struct ugdata *ent;	/* pointer to array of actual entries */
};

enum fname {	/* enumeration of field names */
	F_USER,		/* effective user of the process */
	F_RUSER,	/* real user of the process */
	F_GROUP,	/* effective group of the process */
	F_RGROUP,	/* real group of the process */
	F_UID,		/* numeric effective uid of the process */
	F_RUID,		/* numeric real uid of the process */
	F_GID,		/* numeric effective gid of the process */
	F_RGID,		/* numeric real gid of the process */
	F_PID,		/* process id */
	F_PPID,		/* parent process id */
	F_PGID,		/* process group id */
	F_SID,		/* session id */
	F_PSR,		/* bound processor */
	F_LWP,		/* lwp-id */
	F_NLWP,		/* number of lwps */
	F_OPRI,		/* old priority (obsolete) */
	F_PRI,		/* new priority */
	F_F,		/* process flags */
	F_S,		/* letter indicating the state */
	F_C,		/* processor utilization (obsolete) */
	F_PCPU,		/* percent of recently used cpu time */
	F_PMEM,		/* percent of physical memory used (rss) */
	F_OSZ,		/* virtual size of the process in pages */
	F_VSZ,		/* virtual size of the process in kilobytes */
	F_RSS,		/* resident set size of the process in kilobytes */
	F_NICE,		/* "nice" value of the process */
	F_CLASS,	/* scheduler class */
	F_STIME,	/* start time of the process, hh:mm:ss or Month Day */
	F_ETIME,	/* elapsed time of the process, [[dd-]hh:]mm:ss */
	F_TIME,		/* cpu time of the process, [[dd-]hh:]mm:ss */
	F_TTY,		/* name of the controlling terminal */
	F_ADDR,		/* address of the process (obsolete) */
	F_WCHAN,	/* wait channel (sleep condition variable) */
	F_FNAME,	/* file name of command */
	F_COMM,		/* name of command (argv[0] value) */
	F_ARGS,		/* name of command plus all its arguments */
	F_TASKID,	/* task id */
	F_PROJID,	/* project id */
	F_PROJECT,	/* project name of the process */
	F_PSET,		/* bound processor set */
	F_ZONE,		/* zone name */
	F_ZONEID,	/* zone id */
	F_CTID,		/* process contract id */
	F_LGRP,		/* process home lgroup */
	F_DMODEL	/* process data model */
};

struct field {
	struct field	*next;		/* linked list */
	int		fname;		/* field index */
	const char	*header;	/* header to use */
	int		width;		/* width of field */
};

static	struct field *fields = NULL;	/* fields selected via -o */
static	struct field *last_field = NULL;
static	int do_header = 0;
static	struct timeval now;

/* array of defined fields, in fname order */
struct def_field {
	const char *fname;
	const char *header;
	int width;
	int minwidth;
};

static struct def_field fname[] = {
	/* fname	header		width	minwidth */
	{ "user",	"USER",		8,	8	},
	{ "ruser",	"RUSER",	8,	8	},
	{ "group",	"GROUP",	8,	8	},
	{ "rgroup",	"RGROUP",	8,	8	},
	{ "uid",	"UID",		5,	5	},
	{ "ruid",	"RUID",		5,	5	},
	{ "gid",	"GID",		5,	5	},
	{ "rgid",	"RGID",		5,	5	},
	{ "pid",	"PID",		5,	5	},
	{ "ppid",	"PPID",		5,	5	},
	{ "pgid",	"PGID",		5,	5	},
	{ "sid",	"SID",		5,	5	},
	{ "psr",	"PSR",		3,	2	},
	{ "lwp",	"LWP",		6,	2	},
	{ "nlwp",	"NLWP",		4,	2	},
	{ "opri",	"PRI",		3,	2	},
	{ "pri",	"PRI",		3,	2	},
	{ "f",		"F",		2,	2	},
	{ "s",		"S",		1,	1	},
	{ "c",		"C",		2,	2	},
	{ "pcpu",	"%CPU",		4,	4	},
	{ "pmem",	"%MEM",		4,	4	},
	{ "osz",	"SZ",		4,	4	},
	{ "vsz",	"VSZ",		4,	4	},
	{ "rss",	"RSS",		4,	4	},
	{ "nice",	"NI",		2,	2	},
	{ "class",	"CLS",		4,	2	},
	{ "stime",	"STIME",	8,	8	},
	{ "etime",	"ELAPSED",	11,	7	},
	{ "time",	"TIME",		11,	5	},
	{ "tty",	"TT",		7,	7	},
#ifdef _LP64
	{ "addr",	"ADDR",		16,	8	},
	{ "wchan",	"WCHAN",	16,	8	},
#else
	{ "addr",	"ADDR",		8,	8	},
	{ "wchan",	"WCHAN",	8,	8	},
#endif
	{ "fname",	"COMMAND",	8,	8	},
	{ "comm",	"COMMAND",	80,	8	},
	{ "args",	"COMMAND",	80,	80	},
	{ "taskid",	"TASKID",	5,	5	},
	{ "projid",	"PROJID",	5,	5	},
	{ "project",	"PROJECT",	8,	8	},
	{ "pset",	"PSET",		3,	3	},
	{ "zone",	"ZONE",		8,	8	},
	{ "zoneid",	"ZONEID",	5,	5	},
	{ "ctid",	"CTID",		5,	5	},
	{ "lgrp",	"LGRP",		4,	2 	},
	{ "dmodel",	"DMODEL",	6,	6 	},
};

#define	NFIELDS	(sizeof (fname) / sizeof (fname[0]))

static	int	retcode = 1;
static	int	lflg;
static	int	Aflg;
static	int	uflg;
static	int	Uflg;
static	int	Gflg;
static	int	aflg;
static	int	dflg;
static	int	Lflg;
static	int	Pflg;
static	int	Wflg;
static	int	yflg;
static	int	pflg;
static	int	fflg;
static	int	cflg;
static	int	jflg;
static	int	gflg;
static	int	sflg;
static	int	tflg;
static	int	zflg;
static	int	Zflg;
static	int	hflg;
static	int	Hflg;
static	uid_t	tuid = (uid_t)-1;
static	int	errflg;

static	int	ndev;		/* number of devices */
static	int	maxdev;		/* number of devl structures allocated */

#define	DNINCR	100
#define	DNSIZE	14
static struct devl {		/* device list   */
	char	dname[DNSIZE];	/* device name   */
	dev_t	ddev;		/* device number */
} *devl;

static	struct tty {
	char *tname;
	dev_t tdev;
} *tty = NULL;			/* for t option */
static	size_t	ttysz = 0;
static	int	ntty = 0;

static	pid_t	*pid = NULL;	/* for p option */
static	size_t	pidsz = 0;
static	size_t	npid = 0;

static	int	*lgrps = NULL;	/* list of lgroup IDs for for h option */
static	size_t	lgrps_size = 0;	/* size of the lgrps list */
static	size_t	nlgrps = 0;	/* number elements in the list */

/* Maximum possible lgroup ID value */
#define	MAX_LGRP_ID 256

static	pid_t	*grpid = NULL;	/* for g option */
static	size_t	grpidsz = 0;
static	int	ngrpid = 0;

static	pid_t	*sessid = NULL;	/* for s option */
static	size_t	sessidsz = 0;
static	int	nsessid = 0;

static	zoneid_t *zoneid = NULL; /* for z option */
static	size_t	zoneidsz = 0;
static	int	nzoneid = 0;

static	int	kbytes_per_page;
static	int	pidwidth;

static	char	*procdir = "/proc";	/* standard /proc directory */

static struct ughead	euid_tbl;	/* table to store selected euid's */
static struct ughead	ruid_tbl;	/* table to store selected real uid's */
static struct ughead	egid_tbl;	/* table to store selected egid's */
static struct ughead	rgid_tbl;	/* table to store selected real gid's */
static prheader_t *lpsinfobuf;		/* buffer to contain lpsinfo */
static size_t	lpbufsize;

/*
 * This constant defines the sentinal number of process IDs below which we
 * only examine individual entries in /proc rather than scanning through
 * /proc. This optimization is a huge win in the common case.
 */
#define	PTHRESHOLD	40

#define	UCB_OPTS	"-aceglnrtuvwxSU"

static	void	usage(void);
static	char	*getarg(char **);
static	char	*parse_format(char *);
static	char	*gettty(psinfo_t *);
static	int	prfind(int, psinfo_t *, char **);
static	void	prcom(psinfo_t *, char *);
static	void	prtpct(ushort_t, int);
static	void	print_time(time_t, int);
static	void	print_field(psinfo_t *, struct field *, const char *);
static	void	print_zombie_field(psinfo_t *, struct field *, const char *);
static	void	pr_fields(psinfo_t *, const char *,
		void (*print_fld)(psinfo_t *, struct field *, const char *));
static	int	search(pid_t *, int, pid_t);
static	void	add_ugentry(struct ughead *, char *);
static	int	uconv(struct ughead *);
static	int	gconv(struct ughead *);
static	int	ugfind(id_t, struct ughead *);
static	void	prtime(timestruc_t, int, int);
static	void	przom(psinfo_t *);
static	int	namencnt(char *, int, int);
static	char	*err_string(int);
static	int	print_proc(char *pname);
static	time_t	delta_secs(const timestruc_t *);
static	int	str2id(const char *, pid_t *, long, long);
static	int	str2uid(const char *,  uid_t *, unsigned long, unsigned long);
static	void	*Realloc(void *, size_t);
static	int	pidcmp(const void *p1, const void *p2);

extern	int	ucbmain(int, char **);
static	int	stdmain(int, char **);

int
main(int argc, char **argv)
{
	const char *me;

	/*
	 * The original two ps'es are linked in a single binary;
	 * their main()s are renamed to stdmain for /usr/bin/ps and
	 * ucbmain for /usr/ucb/ps.
	 * We try to figure out which instance of ps the user wants to run.
	 * Traditionally, the UCB variant doesn't require the flag argument
	 * start with a "-".  If the first argument doesn't start with a
	 * "-", we call "ucbmain".
	 * If there's a first argument and it starts with a "-", we check
	 * whether any of the options isn't acceptable to "ucbmain"; in that
	 * case we run "stdmain".
	 * If we can't tell from the options which main to call, we check
	 * the binary we are running.  We default to "stdmain" but
	 * any mention in the executable name of "ucb" causes us to call
	 * ucbmain.
	 */
	if (argv[1] != NULL) {
		if (argv[1][0] != '-')
			return (ucbmain(argc, argv));
		else if (argv[1][strspn(argv[1], UCB_OPTS)] != '\0')
			return (stdmain(argc, argv));
	}

	me = getexecname();

	if (me != NULL && strstr(me, "ucb") != NULL)
		return (ucbmain(argc, argv));
	else
		return (stdmain(argc, argv));
}

static int
stdmain(int argc, char **argv)
{
	char	*p;
	char	*p1;
	char	*parg;
	int	c;
	int	i;
	int	pgerrflg = 0;	/* err flg: non-numeric arg w/p & g options */
	size_t	size, len;
	DIR	*dirp;
	struct dirent *dentp;
	pid_t	maxpid;
	pid_t	id;
	int	ret;
	char	loc_stime_str[32];

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	(void) memset(&euid_tbl, 0, sizeof (euid_tbl));
	(void) memset(&ruid_tbl, 0, sizeof (ruid_tbl));
	(void) memset(&egid_tbl, 0, sizeof (egid_tbl));
	(void) memset(&rgid_tbl, 0, sizeof (rgid_tbl));

	kbytes_per_page = sysconf(_SC_PAGESIZE) / 1024;

	(void) gettimeofday(&now, NULL);

	/*
	 * calculate width of pid fields based on configured MAXPID
	 * (must be at least 5 to retain output format compatibility)
	 */
	id = maxpid = (pid_t)sysconf(_SC_MAXPID);
	pidwidth = 1;
	while ((id /= 10) > 0)
		++pidwidth;
	pidwidth = pidwidth < 5 ? 5 : pidwidth;

	fname[F_PID].width = fname[F_PPID].width = pidwidth;
	fname[F_PGID].width = fname[F_SID].width = pidwidth;

	/*
	 * TRANSLATION_NOTE
	 * Specify the printf format with width and precision for
	 * the STIME field.
	 */
	len = snprintf(loc_stime_str, sizeof (loc_stime_str),
	    dcgettext(NULL, "%8.8s", LC_TIME), "STIME");
	if (len >= sizeof (loc_stime_str))
		len = sizeof (loc_stime_str) - 1;

	fname[F_STIME].width = fname[F_STIME].minwidth = len;

	while ((c = getopt(argc, argv, "jlfceAadLPWyZHh:t:p:g:u:U:G:n:s:o:z:"))
	    != EOF)
		switch (c) {
		case 'H':		/* Show home lgroups */
			Hflg++;
			break;
		case 'h':
			/*
			 * Show processes/threads with given home lgroups
			 */
			hflg++;
			p1 = optarg;
			do {
				int id;

				/*
				 * Get all IDs in the list, verify for
				 * correctness and place in lgrps array.
				 */
				parg = getarg(&p1);
				/* Convert string to integer */
				ret = str2id(parg, (pid_t *)&id, 0,
				    MAX_LGRP_ID);
				/* Complain if ID didn't parse correctly */
				if (ret != 0) {
					pgerrflg++;
					(void) fprintf(stderr,
					    gettext("ps: %s "), parg);
					if (ret == EINVAL)
						(void) fprintf(stderr,
						    gettext("is an invalid "
						    "non-numeric argument"));
					else
						(void) fprintf(stderr,
						    gettext("exceeds valid "
						    "range"));
					(void) fprintf(stderr,
					    gettext(" for -h option\n"));
					continue;
				}

				/* Extend lgrps array if needed */
				if (nlgrps == lgrps_size) {
					/* Double the size of the lgrps array */
					if (lgrps_size == 0)
						lgrps_size = SIZ;
					lgrps_size *= 2;
					lgrps = Realloc(lgrps,
					    lgrps_size * sizeof (int));
				}
				/* place the id in the lgrps table */
				lgrps[nlgrps++] = id;
			} while (*p1);
			break;
		case 'l':		/* long listing */
			lflg++;
			break;
		case 'f':		/* full listing */
			fflg++;
			break;
		case 'j':
			jflg++;
			break;
		case 'c':
			/*
			 * Format output to reflect scheduler changes:
			 * high numbers for high priorities and don't
			 * print nice or p_cpu values.  'c' option only
			 * effective when used with 'l' or 'f' options.
			 */
			cflg++;
			break;
		case 'A':		/* list every process */
		case 'e':		/* (obsolete) list every process */
			Aflg++;
			tflg = Gflg = Uflg = uflg = pflg = gflg = sflg = 0;
			zflg = hflg = 0;
			break;
		case 'a':
			/*
			 * Same as 'e' except no session group leaders
			 * and no non-terminal processes.
			 */
			aflg++;
			break;
		case 'd':	/* same as e except no session leaders */
			dflg++;
			break;
		case 'L':	/* show lwps */
			Lflg++;
			break;
		case 'P':	/* show bound processor */
			Pflg++;
			break;
		case 'W':	/* truncate long names */
			Wflg++;
			break;
		case 'y':	/* omit F & ADDR, report RSS & SZ in Kby */
			yflg++;
			break;
		case 'n':	/* no longer needed; retain as no-op */
			(void) fprintf(stderr,
			    gettext("ps: warning: -n option ignored\n"));
			break;
		case 't':		/* terminals */
#define	TSZ	30
			tflg++;
			p1 = optarg;
			do {
				char nambuf[TSZ+6];	/* for "/dev/" + '\0' */
				struct stat64 s;
				parg = getarg(&p1);
				p = Realloc(NULL, TSZ+1);	/* for '\0' */
				/* zero the buffer before using it */
				p[0] = '\0';
				size = TSZ;
				if (isdigit(*parg)) {
					(void) strcpy(p, "tty");
					size -= 3;
				}
				(void) strncat(p, parg, size);
				if (ntty == ttysz) {
					if ((ttysz *= 2) == 0)
						ttysz = NTTYS;
					tty = Realloc(tty,
					    (ttysz + 1) * sizeof (struct tty));
				}
				tty[ntty].tdev = PRNODEV;
				(void) strcpy(nambuf, "/dev/");
				(void) strcat(nambuf, p);
				if (stat64(nambuf, &s) == 0)
					tty[ntty].tdev = s.st_rdev;
				tty[ntty++].tname = p;
			} while (*p1);
			break;
		case 'p':		/* proc ids */
			pflg++;
			p1 = optarg;
			do {
				pid_t id;

				parg = getarg(&p1);
				if ((ret = str2id(parg, &id, 0, maxpid)) != 0) {
					pgerrflg++;
					(void) fprintf(stderr,
					    gettext("ps: %s "), parg);
					if (ret == EINVAL)
						(void) fprintf(stderr,
						    gettext("is an invalid "
						    "non-numeric argument"));
					else
						(void) fprintf(stderr,
						    gettext("exceeds valid "
						    "range"));
					(void) fprintf(stderr,
					    gettext(" for -p option\n"));
					continue;
				}

				if (npid == pidsz) {
					if ((pidsz *= 2) == 0)
						pidsz = SIZ;
					pid = Realloc(pid,
					    pidsz * sizeof (pid_t));
				}
				pid[npid++] = id;
			} while (*p1);
			break;
		case 's':		/* session */
			sflg++;
			p1 = optarg;
			do {
				pid_t id;

				parg = getarg(&p1);
				if ((ret = str2id(parg, &id, 0, maxpid)) != 0) {
					pgerrflg++;
					(void) fprintf(stderr,
					    gettext("ps: %s "), parg);
					if (ret == EINVAL)
						(void) fprintf(stderr,
						    gettext("is an invalid "
						    "non-numeric argument"));
					else
						(void) fprintf(stderr,
						    gettext("exceeds valid "
						    "range"));
					(void) fprintf(stderr,
					    gettext(" for -s option\n"));
					continue;
				}

				if (nsessid == sessidsz) {
					if ((sessidsz *= 2) == 0)
						sessidsz = SIZ;
					sessid = Realloc(sessid,
					    sessidsz * sizeof (pid_t));
				}
				sessid[nsessid++] = id;
			} while (*p1);
			break;
		case 'g':		/* proc group */
			gflg++;
			p1 = optarg;
			do {
				pid_t id;

				parg = getarg(&p1);
				if ((ret = str2id(parg, &id, 0, maxpid)) != 0) {
					pgerrflg++;
					(void) fprintf(stderr,
					    gettext("ps: %s "), parg);
					if (ret == EINVAL)
						(void) fprintf(stderr,
						    gettext("is an invalid "
						    "non-numeric argument"));
					else
						(void) fprintf(stderr,
						    gettext("exceeds valid "
						    "range"));
					(void) fprintf(stderr,
					    gettext(" for -g option\n"));
					continue;
				}

				if (ngrpid == grpidsz) {
					if ((grpidsz *= 2) == 0)
						grpidsz = SIZ;
					grpid = Realloc(grpid,
					    grpidsz * sizeof (pid_t));
				}
				grpid[ngrpid++] = id;
			} while (*p1);
			break;
		case 'u':		/* effective user name or number */
			uflg++;
			p1 = optarg;
			do {
				parg = getarg(&p1);
				add_ugentry(&euid_tbl, parg);
			} while (*p1);
			break;
		case 'U':		/* real user name or number */
			Uflg++;
			p1 = optarg;
			do {
				parg = getarg(&p1);
				add_ugentry(&ruid_tbl, parg);
			} while (*p1);
			break;
		case 'G':		/* real group name or number */
			Gflg++;
			p1 = optarg;
			do {
				parg = getarg(&p1);
				add_ugentry(&rgid_tbl, parg);
			} while (*p1);
			break;
		case 'o':		/* output format */
			p = optarg;
			while ((p = parse_format(p)) != NULL)
				;
			break;
		case 'z':		/* zone name or number */
			zflg++;
			p1 = optarg;
			do {
				zoneid_t id;

				parg = getarg(&p1);
				if (zone_get_id(parg, &id) != 0) {
					pgerrflg++;
					(void) fprintf(stderr,
					    gettext("ps: unknown zone %s\n"),
					    parg);
					continue;
				}

				if (nzoneid == zoneidsz) {
					if ((zoneidsz *= 2) == 0)
						zoneidsz = SIZ;
					zoneid = Realloc(zoneid,
					    zoneidsz * sizeof (zoneid_t));
				}
				zoneid[nzoneid++] = id;
			} while (*p1);
			break;
		case 'Z':		/* show zone name */
			Zflg++;
			break;
		default:			/* error on ? */
			errflg++;
			break;
		}

	if (errflg || optind < argc || pgerrflg)
		usage();

	if (tflg)
		tty[ntty].tname = NULL;
	/*
	 * If an appropriate option has not been specified, use the
	 * current terminal and effective uid as the default.
	 */
	if (!(aflg|Aflg|dflg|Gflg|hflg|Uflg|uflg|tflg|pflg|gflg|sflg|zflg)) {
		psinfo_t info;
		int procfd;
		char *name;
		char pname[100];

		/* get our own controlling tty name using /proc */
		(void) snprintf(pname, sizeof (pname),
		    "%s/self/psinfo", procdir);
		if ((procfd = open(pname, O_RDONLY)) < 0 ||
		    read(procfd, (char *)&info, sizeof (info)) < 0 ||
		    info.pr_ttydev == PRNODEV) {
			(void) fprintf(stderr,
			    gettext("ps: no controlling terminal\n"));
			exit(1);
		}
		(void) close(procfd);

		i = 0;
		name = gettty(&info);
		if (*name == '?') {
			(void) fprintf(stderr,
			    gettext("ps: can't find controlling terminal\n"));
			exit(1);
		}
		if (ntty == ttysz) {
			if ((ttysz *= 2) == 0)
				ttysz = NTTYS;
			tty = Realloc(tty, (ttysz + 1) * sizeof (struct tty));
		}
		tty[ntty].tdev = info.pr_ttydev;
		tty[ntty++].tname = name;
		tty[ntty].tname = NULL;
		tflg++;
		tuid = getuid();
	}
	if (Aflg) {
		Gflg = Uflg = uflg = pflg = sflg = gflg = aflg = dflg = 0;
		zflg = hflg = 0;
	}
	if (Aflg | aflg | dflg)
		tflg = 0;

	i = 0;		/* prepare to exit on name lookup errors */
	i += uconv(&euid_tbl);
	i += uconv(&ruid_tbl);
	i += gconv(&egid_tbl);
	i += gconv(&rgid_tbl);
	if (i)
		exit(1);

	/* allocate a buffer for lwpsinfo structures */
	lpbufsize = 4096;
	if (Lflg && (lpsinfobuf = malloc(lpbufsize)) == NULL) {
		(void) fprintf(stderr,
		    gettext("ps: no memory\n"));
		exit(1);
	}

	if (fields) {	/* print user-specified header */
		if (do_header) {
			struct field *f;

			for (f = fields; f != NULL; f = f->next) {
				if (f != fields)
					(void) printf(" ");
				switch (f->fname) {
				case F_TTY:
					(void) printf("%-*s",
					    f->width, f->header);
					break;
				case F_FNAME:
				case F_COMM:
				case F_ARGS:
					/*
					 * Print these headers full width
					 * unless they appear at the end.
					 */
					if (f->next != NULL) {
						(void) printf("%-*s",
						    f->width, f->header);
					} else {
						(void) printf("%s",
						    f->header);
					}
					break;
				default:
					(void) printf("%*s",
					    f->width, f->header);
					break;
				}
			}
			(void) printf("\n");
		}
	} else {	/* print standard header */
		/*
		 * All fields before 'PID' are printed with a trailing space
		 * as a separator and that is how we print the headers too.
		 */
		if (lflg) {
			if (yflg)
				(void) printf("S ");
			else
				(void) printf(" F S ");
		}
		if (Zflg)
			(void) printf("    ZONE ");
		if (fflg) {
			(void) printf("     UID ");
		} else if (lflg)
			(void) printf("   UID ");

		(void) printf("%*s", pidwidth,  "PID");
		if (lflg || fflg)
			(void) printf(" %*s", pidwidth, "PPID");
		if (jflg)
			(void) printf(" %*s %*s", pidwidth, "PGID",
			    pidwidth, "SID");
		if (Lflg)
			(void) printf("   LWP");
		if (Pflg)
			(void) printf(" PSR");
		if (Lflg && fflg)
			(void) printf("  NLWP");
		if (cflg)
			(void) printf("  CLS PRI");
		else if (lflg || fflg) {
			(void) printf("   C");
			if (lflg)
				(void) printf(" PRI NI");
		}
		if (lflg) {
			if (yflg)
				(void) printf("   RSS     SZ    WCHAN");
			else
				(void) printf("     ADDR     SZ    WCHAN");
		}
		if (fflg)
			(void) printf(" %s", loc_stime_str);
		if (Hflg)
			(void) printf(" LGRP");
		if (Lflg)
			(void) printf(" TTY        LTIME CMD\n");
		else
			(void) printf(" TTY         TIME CMD\n");
	}


	if (pflg && !(aflg|Aflg|dflg|Gflg|Uflg|uflg|hflg|tflg|gflg|sflg|zflg) &&
	    npid <= PTHRESHOLD) {
		/*
		 * If we are looking at specific processes go straight
		 * to their /proc entries and don't scan /proc.
		 */
		int i;

		(void) qsort(pid, npid, sizeof (pid_t), pidcmp);
		for (i = 0; i < npid; i++) {
			char pname[12];

			if (i >= 1 && pid[i] == pid[i - 1])
				continue;
			(void) sprintf(pname, "%d", (int)pid[i]);
			if (print_proc(pname) == 0)
				retcode = 0;
		}
	} else {
		/*
		 * Determine which processes to print info about by searching
		 * the /proc directory and looking at each process.
		 */
		if ((dirp = opendir(procdir)) == NULL) {
			(void) fprintf(stderr,
			    gettext("ps: cannot open PROC directory %s\n"),
			    procdir);
			exit(1);
		}

		/* for each active process --- */
		while ((dentp = readdir(dirp)) != NULL) {
			if (dentp->d_name[0] == '.')    /* skip . and .. */
				continue;
			if (print_proc(dentp->d_name) == 0)
				retcode = 0;
		}

		(void) closedir(dirp);
	}
	return (retcode);
}


int
print_proc(char *pid_name)
{
	char	pname[PATH_MAX];
	int	pdlen;
	int	found;
	int	procfd; /* filedescriptor for /proc/nnnnn/psinfo */
	char	*tp;    /* ptr to ttyname,  if any */
	psinfo_t info;  /* process information from /proc */
	lwpsinfo_t *lwpsinfo;   /* array of lwpsinfo structs */

	pdlen = snprintf(pname, sizeof (pname), "%s/%s/", procdir, pid_name);
	if (pdlen >= sizeof (pname) - 10)
		return (1);
retry:
	(void) strcpy(&pname[pdlen], "psinfo");
	if ((procfd = open(pname, O_RDONLY)) == -1) {
		/* Process may have exited meanwhile. */
		return (1);
	}
	/*
	 * Get the info structure for the process and close quickly.
	 */
	if (read(procfd, (char *)&info, sizeof (info)) < 0) {
		int	saverr = errno;

		(void) close(procfd);
		if (saverr == EAGAIN)
			goto retry;
		if (saverr != ENOENT)
			(void) fprintf(stderr,
			    gettext("ps: read() on %s: %s\n"),
			    pname, err_string(saverr));
		return (1);
	}
	(void) close(procfd);

	found = 0;
	if (info.pr_lwp.pr_state == 0)	/* can't happen? */
		return (1);

	/*
	 * Omit session group leaders for 'a' and 'd' options.
	 */
	if ((info.pr_pid == info.pr_sid) && (dflg || aflg))
		return (1);
	if (Aflg || dflg)
		found++;
	else if (pflg && search(pid, npid, info.pr_pid))
		found++;	/* ppid in p option arg list */
	else if (uflg && ugfind((id_t)info.pr_euid, &euid_tbl))
		found++;	/* puid in u option arg list */
	else if (Uflg && ugfind((id_t)info.pr_uid, &ruid_tbl))
		found++;	/* puid in U option arg list */
#ifdef NOT_YET
	else if (gflg && ugfind((id_t)info.pr_egid, &egid_tbl))
		found++;	/* pgid in g option arg list */
#endif	/* NOT_YET */
	else if (Gflg && ugfind((id_t)info.pr_gid, &rgid_tbl))
		found++;	/* pgid in G option arg list */
	else if (gflg && search(grpid, ngrpid, info.pr_pgid))
		found++;	/* grpid in g option arg list */
	else if (sflg && search(sessid, nsessid, info.pr_sid))
		found++;	/* sessid in s option arg list */
	else if (zflg && search(zoneid, nzoneid, info.pr_zoneid))
		found++;	/* zoneid in z option arg list */
	else if (hflg && search((pid_t *)lgrps, nlgrps, info.pr_lwp.pr_lgrp))
		found++;	/* home lgroup in h option arg list */
	if (!found && !tflg && !aflg)
		return (1);
	if (!prfind(found, &info, &tp))
		return (1);
	if (Lflg && (info.pr_nlwp + info.pr_nzomb) > 1) {
		ssize_t prsz;

		(void) strcpy(&pname[pdlen], "lpsinfo");
		if ((procfd = open(pname, O_RDONLY)) == -1)
			return (1);
		/*
		 * Get the info structures for the lwps.
		 */
		prsz = read(procfd, lpsinfobuf, lpbufsize);
		if (prsz == -1) {
			int	saverr = errno;

			(void) close(procfd);
			if (saverr == EAGAIN)
				goto retry;
			if (saverr != ENOENT)
				(void) fprintf(stderr,
				    gettext("ps: read() on %s: %s\n"),
				    pname, err_string(saverr));
			return (1);
		}
		(void) close(procfd);
		if (prsz == lpbufsize) {
			/*
			 * buffer overflow. Realloc new buffer.
			 * Error handling is done in Realloc().
			 */
			lpbufsize *= 2;
			lpsinfobuf = Realloc(lpsinfobuf, lpbufsize);
			goto retry;
		}
		if (lpsinfobuf->pr_nent != (info.pr_nlwp + info.pr_nzomb))
			goto retry;
		lwpsinfo = (lwpsinfo_t *)(lpsinfobuf + 1);
	}
	if (!Lflg || (info.pr_nlwp + info.pr_nzomb) <= 1) {
		prcom(&info, tp);
	} else {
		int nlwp = 0;

		do {
			info.pr_lwp = *lwpsinfo;
			prcom(&info, tp);
			/* LINTED improper alignment */
			lwpsinfo = (lwpsinfo_t *)((char *)lwpsinfo +
			    lpsinfobuf->pr_entsize);
		} while (++nlwp < lpsinfobuf->pr_nent);
	}
	return (0);
}

static int
field_cmp(const void *l, const void *r)
{
	struct def_field *lhs = *((struct def_field **)l);
	struct def_field *rhs = *((struct def_field **)r);

	return (strcmp(lhs->fname, rhs->fname));
}

static void
usage(void)		/* print usage message and quit */
{
	struct def_field *df, *sorted[NFIELDS];
	int pos = 80, i = 0;

	static char usage1[] =
	    "ps [ -aAdefHlcjLPWyZ ] [ -o format ] [ -t termlist ]";
	static char usage2[] =
	    "\t[ -u userlist ] [ -U userlist ] [ -G grouplist ]";
	static char usage3[] =
	    "\t[ -p proclist ] [ -g pgrplist ] [ -s sidlist ]";
	static char usage4[] =
	    "\t[ -z zonelist ] [-h lgrplist]";
	static char usage5[] =
	    "  'format' is one or more of:";

	(void) fprintf(stderr,
	    gettext("usage: %s\n%s\n%s\n%s\n%s"),
	    gettext(usage1), gettext(usage2), gettext(usage3),
	    gettext(usage4), gettext(usage5));

	/*
	 * Now print out the possible output formats such that they neatly fit
	 * into eighty columns.  Note that the fact that we are determining
	 * this output programmatically means that a gettext() is impossible --
	 * but it would be a mistake to localize the output formats anyway as
	 * they are tokens for input, not output themselves.
	 */
	for (df = &fname[0]; df < &fname[NFIELDS]; df++)
		sorted[i++] = df;

	(void) qsort(sorted, NFIELDS, sizeof (void *), field_cmp);

	for (i = 0; i < NFIELDS; i++) {
		if (pos + strlen((df = sorted[i])->fname) + 1 >= 80) {
			(void) fprintf(stderr, "\n\t");
			pos = 8;
		}

		(void) fprintf(stderr, "%s%s", pos > 8 ? " " : "", df->fname);
		pos += strlen(df->fname) + 1;
	}

	(void) fprintf(stderr, "\n");

	exit(1);
}

/*
 * getarg() finds the next argument in list and copies arg into argbuf.
 * p1 first pts to arg passed back from getopt routine.  p1 is then
 * bumped to next character that is not a comma or blank -- p1 NULL
 * indicates end of list.
 */
static char *
getarg(char **pp1)
{
	static char argbuf[ARGSIZ];
	char *p1 = *pp1;
	char *parga = argbuf;
	int c;

	while ((c = *p1) != '\0' && (c == ',' || isspace(c)))
		p1++;

	while ((c = *p1) != '\0' && c != ',' && !isspace(c)) {
		if (parga < argbuf + ARGSIZ - 1)
			*parga++ = c;
		p1++;
	}
	*parga = '\0';

	while ((c = *p1) != '\0' && (c == ',' || isspace(c)))
		p1++;

	*pp1 = p1;

	return (argbuf);
}

/*
 * parse_format() takes the argument to the -o option,
 * sets up the next output field structure, and returns
 * a pointer to any further output field specifier(s).
 * As a side-effect, it increments errflg if encounters a format error.
 */
static char *
parse_format(char *arg)
{
	int c;
	char *name;
	char *header = NULL;
	int width = 0;
	struct def_field *df;
	struct field *f;

	while ((c = *arg) != '\0' && (c == ',' || isspace(c)))
		arg++;
	if (c == '\0')
		return (NULL);
	name = arg;
	arg = strpbrk(arg, " \t\r\v\f\n,=");
	if (arg != NULL) {
		c = *arg;
		*arg++ = '\0';
		if (c == '=') {
			char *s;

			header = arg;
			arg = NULL;
			width = strlen(header);
			s = header + width;
			while (s > header && isspace(*--s))
				*s = '\0';
			while (isspace(*header))
				header++;
		}
	}
	for (df = &fname[0]; df < &fname[NFIELDS]; df++)
		if (strcmp(name, df->fname) == 0) {
			if (strcmp(name, "lwp") == 0)
				Lflg++;
			break;
		}
	if (df >= &fname[NFIELDS]) {
		(void) fprintf(stderr,
		    gettext("ps: unknown output format: -o %s\n"),
		    name);
		errflg++;
		return (arg);
	}
	if ((f = malloc(sizeof (*f))) == NULL) {
		(void) fprintf(stderr,
		    gettext("ps: malloc() for output format failed, %s\n"),
		    err_string(errno));
		exit(1);
	}
	f->next = NULL;
	f->fname = df - &fname[0];
	f->header = header? header : df->header;
	if (width == 0)
		width = df->width;
	if (*f->header != '\0')
		do_header = 1;
	f->width = max(width, df->minwidth);

	if (fields == NULL)
		fields = last_field = f;
	else {
		last_field->next = f;
		last_field = f;
	}

	return (arg);
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
		devl = Realloc(devl, maxdev * sizeof (struct devl));
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
		start = leng - DNSIZE - 1;

		for (i = start; i < leng && name[i] != '/'; i++)
				;
		if (i == leng)
			(void) strncpy(dp->dname, &name[start], DNSIZE);
		else
			(void) strncpy(dp->dname, &name[i+1], DNSIZE);
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
 * Find the process's tty and return 1 if process is to be printed.
 */
static int
prfind(int found, psinfo_t *psinfo, char **tpp)
{
	char	*tp;
	struct tty *ttyp;

	if (psinfo->pr_nlwp == 0) {
		/* process is a zombie */
		*tpp = "?";
		if (tflg && !found)
			return (0);
		return (1);
	}

	/*
	 * Get current terminal.  If none ("?") and 'a' is set, don't print
	 * info.  If 't' is set, check if term is in list of desired terminals
	 * and print it if it is.
	 */
	tp = gettty(psinfo);
	if (aflg && *tp == '?') {
		*tpp = tp;
		return (0);
	}
	if (tflg && !found) {
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
			    (ttyp->tdev != PRNODEV) &&
			    (psinfo->pr_ttydev == ttyp->tdev))
				other = ttyp->tname;
		}
		if (!match && (other != NULL)) {
			/*
			 * found under a different name
			 */
			match = 1;
			tp = other;
		}
		if (!match || (tuid != (uid_t)-1 && tuid != psinfo->pr_euid)) {
			/*
			 * not found OR not matching euid
			 */
			*tpp = tp;
			return (0);
		}
	}
	*tpp = tp;
	return (1);
}

/*
 * Print info about the process.
 */
static void
prcom(psinfo_t *psinfo, char *ttyp)
{
	char	*cp;
	long	tm;
	int	bytesleft;
	int	wcnt, length;
	wchar_t	wchar;
	struct passwd *pwd;
	int	zombie_lwp;
	char	zonename[ZONENAME_MAX];

	/*
	 * If process is zombie, call zombie print routine and return.
	 */
	if (psinfo->pr_nlwp == 0) {
		if (fields != NULL)
			pr_fields(psinfo, ttyp, print_zombie_field);
		else
			przom(psinfo);
		return;
	}

	zombie_lwp = (Lflg && psinfo->pr_lwp.pr_sname == 'Z');

	/*
	 * If user specified '-o format', print requested fields and return.
	 */
	if (fields != NULL) {
		pr_fields(psinfo, ttyp, print_field);
		return;
	}

	/*
	 * All fields before 'PID' are printed with a trailing space as a
	 * separator, rather than keeping track of which column is first.  All
	 * other fields are printed with a leading space.
	 */
	if (lflg) {
		if (!yflg)
			(void) printf("%2x ", psinfo->pr_flag & 0377); /* F */
		(void) printf("%c ", psinfo->pr_lwp.pr_sname);	/* S */
	}

	if (Zflg) {						/* ZONE */
		if (getzonenamebyid(psinfo->pr_zoneid, zonename,
		    sizeof (zonename)) < 0) {
			if (snprintf(NULL, 0, "%d",
			    ((int)psinfo->pr_zoneid)) > 7)
				(void) printf(" %6.6d%c ",
				    ((int)psinfo->pr_zoneid), '*');
			else
				(void) printf(" %7.7d ",
				    ((int)psinfo->pr_zoneid));
		} else {
			size_t nw;

			nw = mbstowcs(NULL, zonename, 0);
			if (nw == (size_t)-1)
				(void) printf("%8.8s ", "ERROR");
			else if (nw > 8)
				(void) wprintf(L"%7.7s%c ", zonename, '*');
			else
				(void) wprintf(L"%8.8s ", zonename);
		}
	}

	if (fflg) {						/* UID */
		if ((pwd = getpwuid(psinfo->pr_euid)) != NULL) {
			size_t nw;

			nw = mbstowcs(NULL, pwd->pw_name, 0);
			if (nw == (size_t)-1)
				(void) printf("%8.8s ", "ERROR");
			else if (nw > 8)
				(void) wprintf(L"%7.7s%c ", pwd->pw_name, '*');
			else
				(void) wprintf(L"%8.8s ", pwd->pw_name);
		} else {
			if (snprintf(NULL, 0, "%u",
			    (psinfo->pr_euid)) > 7)
				(void) printf(" %6.6u%c ", psinfo->pr_euid,
				    '*');
			else
				(void) printf(" %7.7u ", psinfo->pr_euid);
		}
	} else if (lflg) {
		if (snprintf(NULL, 0, "%u", (psinfo->pr_euid)) > 6)
			(void) printf("%5.5u%c ", psinfo->pr_euid, '*');
		else
			(void) printf("%6u ", psinfo->pr_euid);
	}
	(void) printf("%*d", pidwidth, (int)psinfo->pr_pid); /* PID */
	if (lflg || fflg)
		(void) printf(" %*d", pidwidth,
		    (int)psinfo->pr_ppid); /* PPID */
	if (jflg) {
		(void) printf(" %*d", pidwidth,
		    (int)psinfo->pr_pgid);	/* PGID */
		(void) printf(" %*d", pidwidth,
		    (int)psinfo->pr_sid);	/* SID  */
	}
	if (Lflg)
		(void) printf(" %5d", (int)psinfo->pr_lwp.pr_lwpid); /* LWP */
	if (Pflg) {
		if (psinfo->pr_lwp.pr_bindpro == PBIND_NONE)	/* PSR */
			(void) printf("   -");
		else
			(void) printf(" %3d", psinfo->pr_lwp.pr_bindpro);
	}
	if (Lflg && fflg)					/* NLWP */
		(void) printf(" %5d", psinfo->pr_nlwp + psinfo->pr_nzomb);
	if (cflg) {
		if (zombie_lwp)					/* CLS */
			(void) printf("     ");
		else
			(void) printf(" %4s", psinfo->pr_lwp.pr_clname);
		(void) printf(" %3d", psinfo->pr_lwp.pr_pri);	/* PRI */
	} else if (lflg || fflg) {
		(void) printf(" %3d", psinfo->pr_lwp.pr_cpu & 0377); /* C   */
		if (lflg) {					    /* PRI NI */
			/*
			 * Print priorities the old way (lower numbers
			 * mean higher priority) and print nice value
			 * for time sharing procs.
			 */
			(void) printf(" %3d", psinfo->pr_lwp.pr_oldpri);
			if (psinfo->pr_lwp.pr_oldpri != 0)
				(void) printf(" %2d", psinfo->pr_lwp.pr_nice);
			else
				(void) printf(" %2.2s",
				    psinfo->pr_lwp.pr_clname);
		}
	}
	if (lflg) {
		if (yflg) {
			if (psinfo->pr_flag & SSYS)		/* RSS */
				(void) printf("     0");
			else if (psinfo->pr_rssize)
				(void) printf(" %5lu",
				    (ulong_t)psinfo->pr_rssize);
			else
				(void) printf("     ?");
			if (psinfo->pr_flag & SSYS)		/* SZ */
				(void) printf("      0");
			else if (psinfo->pr_size)
				(void) printf(" %6lu",
				    (ulong_t)psinfo->pr_size);
			else
				(void) printf("      ?");
		} else {
#ifndef _LP64
			if (psinfo->pr_addr)			/* ADDR */
				(void) printf(" %8lx",
				    (ulong_t)psinfo->pr_addr);
			else
#endif
				(void) printf("        ?");
			if (psinfo->pr_flag & SSYS)		/* SZ */
				(void) printf("      0");
			else if (psinfo->pr_size)
				(void) printf(" %6lu",
				    (ulong_t)psinfo->pr_size / kbytes_per_page);
			else
				(void) printf("      ?");
		}
		if (psinfo->pr_lwp.pr_sname != 'S')		/* WCHAN */
			(void) printf("         ");
#ifndef _LP64
		else if (psinfo->pr_lwp.pr_wchan)
			(void) printf(" %8lx",
			    (ulong_t)psinfo->pr_lwp.pr_wchan);
#endif
		else
			(void) printf("        ?");
	}
	if (fflg) {						/* STIME */
		int width = fname[F_STIME].width;
		if (Lflg)
			prtime(psinfo->pr_lwp.pr_start, width + 1, 1);
		else
			prtime(psinfo->pr_start, width + 1, 1);
	}

	if (Hflg) {
		/* Display home lgroup */
		(void) printf(" %4d", (int)psinfo->pr_lwp.pr_lgrp);
	}

	(void) printf(" %-8.14s", ttyp);			/* TTY */
	if (Lflg) {
		tm = psinfo->pr_lwp.pr_time.tv_sec;
		if (psinfo->pr_lwp.pr_time.tv_nsec > 500000000)
			tm++;
	} else {
		tm = psinfo->pr_time.tv_sec;
		if (psinfo->pr_time.tv_nsec > 500000000)
			tm++;
	}
	(void) printf(" %4ld:%.2ld", tm / 60, tm % 60);		/* [L]TIME */

	if (zombie_lwp) {
		(void) printf(" <defunct>\n");
		return;
	}

	if (!fflg) {						/* CMD */
		wcnt = namencnt(psinfo->pr_fname, 16, 8);
		(void) printf(" %.*s\n", wcnt, psinfo->pr_fname);
		return;
	}


	/*
	 * PRARGSZ == length of cmd arg string.
	 */
	psinfo->pr_psargs[PRARGSZ-1] = '\0';
	bytesleft = PRARGSZ;
	for (cp = psinfo->pr_psargs; *cp != '\0'; cp += length) {
		length = mbtowc(&wchar, cp, MB_LEN_MAX);
		if (length == 0)
			break;
		if (length < 0 || !iswprint(wchar)) {
			if (length < 0)
				length = 1;
			if (bytesleft <= length) {
				*cp = '\0';
				break;
			}
			/* omit the unprintable character */
			(void) memmove(cp, cp+length, bytesleft-length);
			length = 0;
		}
		bytesleft -= length;
	}
	wcnt = namencnt(psinfo->pr_psargs, PRARGSZ, lflg ? 35 : PRARGSZ);
	(void) printf(" %.*s\n", wcnt, psinfo->pr_psargs);
}

/*
 * Print percent from 16-bit binary fraction [0 .. 1]
 * Round up .01 to .1 to indicate some small percentage (the 0x7000 below).
 */
static void
prtpct(ushort_t pct, int width)
{
	uint_t value = pct;	/* need 32 bits to compute with */

	value = ((value * 1000) + 0x7000) >> 15;	/* [0 .. 1000] */
	if (value >= 1000)
		value = 999;
	if ((width -= 2) < 2)
		width = 2;
	(void) printf("%*u.%u", width, value / 10, value % 10);
}

static void
print_time(time_t tim, int width)
{
	char buf[30];
	time_t seconds;
	time_t minutes;
	time_t hours;
	time_t days;

	if (tim < 0) {
		(void) printf("%*s", width, "-");
		return;
	}

	seconds = tim % 60;
	tim /= 60;
	minutes = tim % 60;
	tim /= 60;
	hours = tim % 24;
	days = tim / 24;

	if (days > 0) {
		(void) snprintf(buf, sizeof (buf), "%ld-%2.2ld:%2.2ld:%2.2ld",
		    days, hours, minutes, seconds);
	} else if (hours > 0) {
		(void) snprintf(buf, sizeof (buf), "%2.2ld:%2.2ld:%2.2ld",
		    hours, minutes, seconds);
	} else {
		(void) snprintf(buf, sizeof (buf), "%2.2ld:%2.2ld",
		    minutes, seconds);
	}

	(void) printf("%*s", width, buf);
}

static void
print_field(psinfo_t *psinfo, struct field *f, const char *ttyp)
{
	int width = f->width;
	struct passwd *pwd;
	struct group *grp;
	time_t cputime;
	int bytesleft;
	int wcnt;
	wchar_t	wchar;
	char *cp;
	int length;
	ulong_t mask;
	char c = '\0', *csave = NULL;
	int zombie_lwp;

	zombie_lwp = (Lflg && psinfo->pr_lwp.pr_sname == 'Z');

	switch (f->fname) {
	case F_RUSER:
		if ((pwd = getpwuid(psinfo->pr_uid)) != NULL) {
			size_t nw;

			nw = mbstowcs(NULL, pwd->pw_name, 0);
			if (nw == (size_t)-1)
				(void) printf("%*s ", width, "ERROR");
			else if (Wflg && nw > width)
				(void) wprintf(L"%.*s%c", width - 1,
				    pwd->pw_name, '*');
			else
				(void) wprintf(L"%*s", width, pwd->pw_name);
		} else {
			if (Wflg && snprintf(NULL, 0, "%u",
			    (psinfo->pr_uid)) > width)

				(void) printf("%*u%c", width - 1,
				    psinfo->pr_uid, '*');
			else
				(void) printf("%*u", width, psinfo->pr_uid);
		}
		break;
	case F_USER:
		if ((pwd = getpwuid(psinfo->pr_euid)) != NULL) {
			size_t nw;

			nw = mbstowcs(NULL, pwd->pw_name, 0);
			if (nw == (size_t)-1)
				(void) printf("%*s ", width, "ERROR");
			else if (Wflg && nw > width)
				(void) wprintf(L"%.*s%c", width - 1,
				    pwd->pw_name, '*');
			else
				(void) wprintf(L"%*s", width, pwd->pw_name);
		} else {
			if (Wflg && snprintf(NULL, 0, "%u",
			    (psinfo->pr_euid)) > width)

				(void) printf("%*u%c", width - 1,
				    psinfo->pr_euid, '*');
			else
				(void) printf("%*u", width, psinfo->pr_euid);
		}
		break;
	case F_RGROUP:
		if ((grp = getgrgid(psinfo->pr_gid)) != NULL)
			(void) printf("%*s", width, grp->gr_name);
		else
			(void) printf("%*u", width, psinfo->pr_gid);
		break;
	case F_GROUP:
		if ((grp = getgrgid(psinfo->pr_egid)) != NULL)
			(void) printf("%*s", width, grp->gr_name);
		else
			(void) printf("%*u", width, psinfo->pr_egid);
		break;
	case F_RUID:
		(void) printf("%*u", width, psinfo->pr_uid);
		break;
	case F_UID:
		(void) printf("%*u", width, psinfo->pr_euid);
		break;
	case F_RGID:
		(void) printf("%*u", width, psinfo->pr_gid);
		break;
	case F_GID:
		(void) printf("%*u", width, psinfo->pr_egid);
		break;
	case F_PID:
		(void) printf("%*d", width, (int)psinfo->pr_pid);
		break;
	case F_PPID:
		(void) printf("%*d", width, (int)psinfo->pr_ppid);
		break;
	case F_PGID:
		(void) printf("%*d", width, (int)psinfo->pr_pgid);
		break;
	case F_SID:
		(void) printf("%*d", width, (int)psinfo->pr_sid);
		break;
	case F_PSR:
		if (zombie_lwp || psinfo->pr_lwp.pr_bindpro == PBIND_NONE)
			(void) printf("%*s", width, "-");
		else
			(void) printf("%*d", width, psinfo->pr_lwp.pr_bindpro);
		break;
	case F_LWP:
		(void) printf("%*d", width, (int)psinfo->pr_lwp.pr_lwpid);
		break;
	case F_NLWP:
		(void) printf("%*d", width, psinfo->pr_nlwp + psinfo->pr_nzomb);
		break;
	case F_OPRI:
		if (zombie_lwp)
			(void) printf("%*s", width, "-");
		else
			(void) printf("%*d", width, psinfo->pr_lwp.pr_oldpri);
		break;
	case F_PRI:
		if (zombie_lwp)
			(void) printf("%*s", width, "-");
		else
			(void) printf("%*d", width, psinfo->pr_lwp.pr_pri);
		break;
	case F_F:
		mask = 0xffffffffUL;
		if (width < 8)
			mask >>= (8 - width) * 4;
		(void) printf("%*lx", width, psinfo->pr_flag & mask);
		break;
	case F_S:
		(void) printf("%*c", width, psinfo->pr_lwp.pr_sname);
		break;
	case F_C:
		if (zombie_lwp)
			(void) printf("%*s", width, "-");
		else
			(void) printf("%*d", width, psinfo->pr_lwp.pr_cpu);
		break;
	case F_PCPU:
		if (zombie_lwp)
			(void) printf("%*s", width, "-");
		else if (Lflg)
			prtpct(psinfo->pr_lwp.pr_pctcpu, width);
		else
			prtpct(psinfo->pr_pctcpu, width);
		break;
	case F_PMEM:
		prtpct(psinfo->pr_pctmem, width);
		break;
	case F_OSZ:
		(void) printf("%*lu", width,
		    (ulong_t)psinfo->pr_size / kbytes_per_page);
		break;
	case F_VSZ:
		(void) printf("%*lu", width, (ulong_t)psinfo->pr_size);
		break;
	case F_RSS:
		(void) printf("%*lu", width, (ulong_t)psinfo->pr_rssize);
		break;
	case F_NICE:
		/* if pr_oldpri is zero, then this class has no nice */
		if (zombie_lwp)
			(void) printf("%*s", width, "-");
		else if (psinfo->pr_lwp.pr_oldpri != 0)
			(void) printf("%*d", width, psinfo->pr_lwp.pr_nice);
		else
			(void) printf("%*.*s", width, width,
			    psinfo->pr_lwp.pr_clname);
		break;
	case F_CLASS:
		if (zombie_lwp)
			(void) printf("%*s", width, "-");
		else
			(void) printf("%*.*s", width, width,
			    psinfo->pr_lwp.pr_clname);
		break;
	case F_STIME:
		if (Lflg)
			prtime(psinfo->pr_lwp.pr_start, width, 0);
		else
			prtime(psinfo->pr_start, width, 0);
		break;
	case F_ETIME:
		if (Lflg)
			print_time(delta_secs(&psinfo->pr_lwp.pr_start),
			    width);
		else
			print_time(delta_secs(&psinfo->pr_start), width);
		break;
	case F_TIME:
		if (Lflg) {
			cputime = psinfo->pr_lwp.pr_time.tv_sec;
			if (psinfo->pr_lwp.pr_time.tv_nsec > 500000000)
				cputime++;
		} else {
			cputime = psinfo->pr_time.tv_sec;
			if (psinfo->pr_time.tv_nsec > 500000000)
				cputime++;
		}
		print_time(cputime, width);
		break;
	case F_TTY:
		(void) printf("%-*s", width, ttyp);
		break;
	case F_ADDR:
		if (zombie_lwp)
			(void) printf("%*s", width, "-");
		else if (Lflg)
			(void) printf("%*lx", width,
			    (long)psinfo->pr_lwp.pr_addr);
		else
			(void) printf("%*lx", width, (long)psinfo->pr_addr);
		break;
	case F_WCHAN:
		if (!zombie_lwp && psinfo->pr_lwp.pr_wchan)
			(void) printf("%*lx", width,
			    (long)psinfo->pr_lwp.pr_wchan);
		else
			(void) printf("%*.*s", width, width, "-");
		break;
	case F_FNAME:
		/*
		 * Print full width unless this is the last output format.
		 */
		if (zombie_lwp) {
			if (f->next != NULL)
				(void) printf("%-*s", width, "<defunct>");
			else
				(void) printf("%s", "<defunct>");
			break;
		}
		wcnt = namencnt(psinfo->pr_fname, 16, width);
		if (f->next != NULL)
			(void) printf("%-*.*s", width, wcnt, psinfo->pr_fname);
		else
			(void) printf("%-.*s", wcnt, psinfo->pr_fname);
		break;
	case F_COMM:
		if (zombie_lwp) {
			if (f->next != NULL)
				(void) printf("%-*s", width, "<defunct>");
			else
				(void) printf("%s", "<defunct>");
			break;
		}
		csave = strpbrk(psinfo->pr_psargs, " \t\r\v\f\n");
		if (csave) {
			c = *csave;
			*csave = '\0';
		}
		/* FALLTHROUGH */
	case F_ARGS:
		/*
		 * PRARGSZ == length of cmd arg string.
		 */
		if (zombie_lwp) {
			(void) printf("%-*s", width, "<defunct>");
			break;
		}
		psinfo->pr_psargs[PRARGSZ-1] = '\0';
		bytesleft = PRARGSZ;
		for (cp = psinfo->pr_psargs; *cp != '\0'; cp += length) {
			length = mbtowc(&wchar, cp, MB_LEN_MAX);
			if (length == 0)
				break;
			if (length < 0 || !iswprint(wchar)) {
				if (length < 0)
					length = 1;
				if (bytesleft <= length) {
					*cp = '\0';
					break;
				}
				/* omit the unprintable character */
				(void) memmove(cp, cp+length, bytesleft-length);
				length = 0;
			}
			bytesleft -= length;
		}
		wcnt = namencnt(psinfo->pr_psargs, PRARGSZ, width);
		/*
		 * Print full width unless this is the last format.
		 */
		if (f->next != NULL)
			(void) printf("%-*.*s", width, wcnt,
			    psinfo->pr_psargs);
		else
			(void) printf("%-.*s", wcnt,
			    psinfo->pr_psargs);
		if (f->fname == F_COMM && csave)
			*csave = c;
		break;
	case F_TASKID:
		(void) printf("%*d", width, (int)psinfo->pr_taskid);
		break;
	case F_PROJID:
		(void) printf("%*d", width, (int)psinfo->pr_projid);
		break;
	case F_PROJECT:
		{
			struct project cproj;
			char proj_buf[PROJECT_BUFSZ];

			if ((getprojbyid(psinfo->pr_projid, &cproj,
			    (void *)&proj_buf, PROJECT_BUFSZ)) == NULL) {
				if (Wflg && snprintf(NULL, 0, "%d",
				    ((int)psinfo->pr_projid)) > width)
					(void) printf("%.*d%c", width - 1,
					    ((int)psinfo->pr_projid), '*');
				else
					(void) printf("%*d", width,
					    (int)psinfo->pr_projid);
			} else {
				size_t nw;

				if (cproj.pj_name != NULL)
					nw = mbstowcs(NULL, cproj.pj_name, 0);
				if (cproj.pj_name == NULL)
					(void) printf("%*s ", width, "---");
				else if (nw == (size_t)-1)
					(void) printf("%*s ", width, "ERROR");
				else if (Wflg && nw > width)
					(void) wprintf(L"%.*s%c", width - 1,
					    cproj.pj_name, '*');
				else
					(void) wprintf(L"%*s", width,
					    cproj.pj_name);
			}
		}
		break;
	case F_PSET:
		if (zombie_lwp || psinfo->pr_lwp.pr_bindpset == PS_NONE)
			(void) printf("%*s", width, "-");
		else
			(void) printf("%*d", width, psinfo->pr_lwp.pr_bindpset);
		break;
	case F_ZONEID:
		(void) printf("%*d", width, (int)psinfo->pr_zoneid);
		break;
	case F_ZONE:
		{
			char zonename[ZONENAME_MAX];

			if (getzonenamebyid(psinfo->pr_zoneid, zonename,
			    sizeof (zonename)) < 0) {
				if (Wflg && snprintf(NULL, 0, "%d",
				    ((int)psinfo->pr_zoneid)) > width)
					(void) printf("%.*d%c", width - 1,
					    ((int)psinfo->pr_zoneid), '*');
				else
					(void) printf("%*d", width,
					    (int)psinfo->pr_zoneid);
			} else {
				size_t nw;

				nw = mbstowcs(NULL, zonename, 0);
				if (nw == (size_t)-1)
					(void) printf("%*s ", width, "ERROR");
				else if (Wflg && nw > width)
					(void) wprintf(L"%.*s%c", width - 1,
					    zonename, '*');
				else
					(void) wprintf(L"%*s", width, zonename);
			}
		}
		break;
	case F_CTID:
		if (psinfo->pr_contract == -1)
			(void) printf("%*s", width, "-");
		else
			(void) printf("%*ld", width, (long)psinfo->pr_contract);
		break;
	case F_LGRP:
		/* Display home lgroup */
		(void) printf("%*d", width, (int)psinfo->pr_lwp.pr_lgrp);
		break;

	case F_DMODEL:
		(void) printf("%*s", width,
		    psinfo->pr_dmodel == PR_MODEL_LP64 ? "_LP64" : "_ILP32");
		break;
	}
}

static void
print_zombie_field(psinfo_t *psinfo, struct field *f, const char *ttyp)
{
	int wcnt;
	int width = f->width;

	switch (f->fname) {
	case F_FNAME:
	case F_COMM:
	case F_ARGS:
		/*
		 * Print full width unless this is the last output format.
		 */
		wcnt = min(width, sizeof ("<defunct>"));
		if (f->next != NULL)
			(void) printf("%-*.*s", width, wcnt, "<defunct>");
		else
			(void) printf("%-.*s", wcnt, "<defunct>");
		break;

	case F_PSR:
	case F_PCPU:
	case F_PMEM:
	case F_NICE:
	case F_CLASS:
	case F_STIME:
	case F_ETIME:
	case F_WCHAN:
	case F_PSET:
		(void) printf("%*s", width, "-");
		break;

	case F_OPRI:
	case F_PRI:
	case F_OSZ:
	case F_VSZ:
	case F_RSS:
		(void) printf("%*d", width, 0);
		break;

	default:
		print_field(psinfo, f, ttyp);
		break;
	}
}

static void
pr_fields(psinfo_t *psinfo, const char *ttyp,
	void (*print_fld)(psinfo_t *, struct field *, const char *))
{
	struct field *f;

	for (f = fields; f != NULL; f = f->next) {
		print_fld(psinfo, f, ttyp);
		if (f->next != NULL)
			(void) printf(" ");
	}
	(void) printf("\n");
}

/*
 * Returns 1 if arg is found in array arr, of length num; 0 otherwise.
 */
static int
search(pid_t *arr, int number, pid_t arg)
{
	int i;

	for (i = 0; i < number; i++)
		if (arg == arr[i])
			return (1);
	return (0);
}

/*
 * Add an entry (user, group) to the specified table.
 */
static void
add_ugentry(struct ughead *tbl, char *name)
{
	struct ugdata *entp;

	if (tbl->size == tbl->nent) {	/* reallocate the table entries */
		if ((tbl->size *= 2) == 0)
			tbl->size = 32;		/* first time */
		tbl->ent = Realloc(tbl->ent, tbl->size*sizeof (struct ugdata));
	}
	entp = &tbl->ent[tbl->nent++];
	entp->id = 0;
	(void) strncpy(entp->name, name, MAXUGNAME);
	entp->name[MAXUGNAME] = '\0';
}

static int
uconv(struct ughead *uhead)
{
	struct ugdata *utbl = uhead->ent;
	int n = uhead->nent;
	struct passwd *pwd;
	int i;
	int fnd = 0;
	uid_t uid;

	/*
	 * Ask the name service for names.
	 */
	for (i = 0; i < n; i++) {
		/*
		 * If name is numeric, ask for numeric id
		 */
		if (str2uid(utbl[i].name, &uid, 0, MAXEPHUID) == 0)
			pwd = getpwuid(uid);
		else
			pwd = getpwnam(utbl[i].name);

		/*
		 * If found, enter found index into tbl array.
		 */
		if (pwd == NULL) {
			(void) fprintf(stderr,
			    gettext("ps: unknown user %s\n"), utbl[i].name);
			continue;
		}

		utbl[fnd].id = pwd->pw_uid;
		(void) strncpy(utbl[fnd].name, pwd->pw_name, MAXUGNAME);
		fnd++;
	}

	uhead->nent = fnd;	/* in case it changed */
	return (n - fnd);
}

static int
gconv(struct ughead *ghead)
{
	struct ugdata *gtbl = ghead->ent;
	int n = ghead->nent;
	struct group *grp;
	gid_t gid;
	int i;
	int fnd = 0;

	/*
	 * Ask the name service for names.
	 */
	for (i = 0; i < n; i++) {
		/*
		 * If name is numeric, ask for numeric id
		 */
		if (str2uid(gtbl[i].name, (uid_t *)&gid, 0, MAXEPHUID) == 0)
			grp = getgrgid(gid);
		else
			grp = getgrnam(gtbl[i].name);
		/*
		 * If found, enter found index into tbl array.
		 */
		if (grp == NULL) {
			(void) fprintf(stderr,
			    gettext("ps: unknown group %s\n"), gtbl[i].name);
			continue;
		}

		gtbl[fnd].id = grp->gr_gid;
		(void) strncpy(gtbl[fnd].name, grp->gr_name, MAXUGNAME);
		fnd++;
	}

	ghead->nent = fnd;	/* in case it changed */
	return (n - fnd);
}

/*
 * Return 1 if puid is in table, otherwise 0.
 */
static int
ugfind(id_t id, struct ughead *ughead)
{
	struct ugdata *utbl = ughead->ent;
	int n = ughead->nent;
	int i;

	for (i = 0; i < n; i++)
		if (utbl[i].id == id)
			return (1);
	return (0);
}

/*
 * Print starting time of process unless process started more than 24 hours
 * ago, in which case the date is printed.  The date is printed in the form
 * "MMM dd" if old format, else the blank is replaced with an '_' so
 * it appears as a single word (for parseability).
 */
static void
prtime(timestruc_t st, int width, int old)
{
	char sttim[26];
	time_t starttime;

	starttime = st.tv_sec;
	if (st.tv_nsec > 500000000)
		starttime++;
	if ((now.tv_sec - starttime) >= 24*60*60) {
		(void) strftime(sttim, sizeof (sttim), old?
		/*
		 * TRANSLATION_NOTE
		 * This time format is used by STIME field when -f option
		 * is specified.  Used for processes that begun more than
		 * 24 hours.
		 */
		    dcgettext(NULL, "%b %d", LC_TIME) :
		/*
		 * TRANSLATION_NOTE
		 * This time format is used by STIME field when -o option
		 * is specified.  Used for processes that begun more than
		 * 24 hours.
		 */
		    dcgettext(NULL, "%b_%d", LC_TIME), localtime(&starttime));
	} else {
		/*
		 * TRANSLATION_NOTE
		 * This time format is used by STIME field when -f or -o option
		 * is specified.  Used for processes that begun less than
		 * 24 hours.
		 */
		(void) strftime(sttim, sizeof (sttim),
		    dcgettext(NULL, "%H:%M:%S", LC_TIME),
		    localtime(&starttime));
	}
	(void) printf("%*.*s", width, width, sttim);
}

static void
przom(psinfo_t *psinfo)
{
	long	tm;
	struct passwd *pwd;
	char zonename[ZONENAME_MAX];

	/*
	 * All fields before 'PID' are printed with a trailing space as a
	 * spearator, rather than keeping track of which column is first.  All
	 * other fields are printed with a leading space.
	 */
	if (lflg) {	/* F S */
		if (!yflg)
			(void) printf("%2x ", psinfo->pr_flag & 0377); /* F */
		(void) printf("%c ", psinfo->pr_lwp.pr_sname);	/* S */
	}
	if (Zflg) {
		if (getzonenamebyid(psinfo->pr_zoneid, zonename,
		    sizeof (zonename)) < 0) {
			if (snprintf(NULL, 0, "%d",
			    ((int)psinfo->pr_zoneid)) > 7)
				(void) printf(" %6.6d%c ",
				    ((int)psinfo->pr_zoneid), '*');
			else
				(void) printf(" %7.7d ",
				    ((int)psinfo->pr_zoneid));
		} else {
			size_t nw;

			nw = mbstowcs(NULL, zonename, 0);
			if (nw == (size_t)-1)
				(void) printf("%8.8s ", "ERROR");
			else if (nw > 8)
				(void) wprintf(L"%7.7s%c ", zonename, '*');
			else
				(void) wprintf(L"%8.8s ", zonename);
		}
	}
	if (Hflg) {
		/* Display home lgroup */
		(void) printf(" %6d", (int)psinfo->pr_lwp.pr_lgrp); /* LGRP */
	}
	if (fflg) {
		if ((pwd = getpwuid(psinfo->pr_euid)) != NULL) {
			size_t nw;

			nw = mbstowcs(NULL, pwd->pw_name, 0);
			if (nw == (size_t)-1)
				(void) printf("%8.8s ", "ERROR");
			else if (nw > 8)
				(void) wprintf(L"%7.7s%c ", pwd->pw_name, '*');
			else
				(void) wprintf(L"%8.8s ", pwd->pw_name);
		} else {
			if (snprintf(NULL, 0, "%u",
			    (psinfo->pr_euid)) > 7)
				(void) printf(" %6.6u%c ", psinfo->pr_euid,
				    '*');
			else
				(void) printf(" %7.7u ", psinfo->pr_euid);
		}
	} else if (lflg) {
		if (snprintf(NULL, 0, "%u", (psinfo->pr_euid)) > 6)
			(void) printf("%5.5u%c ", psinfo->pr_euid, '*');
		else
			(void) printf("%6u ", psinfo->pr_euid);
	}

	(void) printf("%*d", pidwidth, (int)psinfo->pr_pid);	/* PID */
	if (lflg || fflg)
		(void) printf(" %*d", pidwidth,
		    (int)psinfo->pr_ppid);			/* PPID */

	if (jflg) {
		(void) printf(" %*d", pidwidth,
		    (int)psinfo->pr_pgid);			/* PGID */
		(void) printf(" %*d", pidwidth,
		    (int)psinfo->pr_sid);			/* SID  */
	}

	if (Lflg)
		(void) printf(" %5d", 0);			/* LWP */
	if (Pflg)
		(void) printf("   -");				/* PSR */
	if (Lflg && fflg)
		(void) printf(" %5d", 0);			/* NLWP */

	if (cflg) {
		(void) printf(" %4s", "-");	/* zombies have no class */
		(void) printf(" %3d", psinfo->pr_lwp.pr_pri);	/* PRI	*/
	} else if (lflg || fflg) {
		(void) printf(" %3d", psinfo->pr_lwp.pr_cpu & 0377); /* C   */
		if (lflg)
			(void) printf(" %3d %2s",
			    psinfo->pr_lwp.pr_oldpri, "-");	/* PRI NI */
	}
	if (lflg) {
		if (yflg)				/* RSS SZ WCHAN */
			(void) printf(" %5d %6d %8s", 0, 0, "-");
		else					/* ADDR SZ WCHAN */
			(void) printf(" %8s %6d %8s", "-", 0, "-");
	}
	if (fflg) {
		int width = fname[F_STIME].width;
		(void) printf(" %*.*s", width, width, "-"); 	/* STIME */
	}
	(void) printf(" %-8.14s", "?");				/* TTY */

	tm = psinfo->pr_time.tv_sec;
	if (psinfo->pr_time.tv_nsec > 500000000)
		tm++;
	(void) printf(" %4ld:%.2ld", tm / 60, tm % 60);	/* TIME */
	(void) printf(" <defunct>\n");
}

/*
 * Function to compute the number of printable bytes in a multibyte
 * command string ("internationalization").
 */
static int
namencnt(char *cmd, int csisize, int scrsize)
{
	int csiwcnt = 0, scrwcnt = 0;
	int ncsisz, nscrsz;
	wchar_t  wchar;
	int	 len;

	while (*cmd != '\0') {
		if ((len = csisize - csiwcnt) > (int)MB_CUR_MAX)
			len = MB_CUR_MAX;
		if ((ncsisz = mbtowc(&wchar, cmd, len)) < 0)
			return (8); /* default to use for illegal chars */
		if ((nscrsz = wcwidth(wchar)) <= 0)
			return (8);
		if (csiwcnt + ncsisz > csisize || scrwcnt + nscrsz > scrsize)
			break;
		csiwcnt += ncsisz;
		scrwcnt += nscrsz;
		cmd += ncsisz;
	}
	return (csiwcnt);
}

static char *
err_string(int err)
{
	static char buf[32];
	char *str = strerror(err);

	if (str == NULL)
		(void) snprintf(str = buf, sizeof (buf), "Errno #%d", err);

	return (str);
}

/* If allocation fails, die */
static void *
Realloc(void *ptr, size_t size)
{
	ptr = realloc(ptr, size);
	if (ptr == NULL) {
		(void) fprintf(stderr, gettext("ps: no memory\n"));
		exit(1);
	}
	return (ptr);
}

static time_t
delta_secs(const timestruc_t *start)
{
	time_t seconds = now.tv_sec - start->tv_sec;
	long nanosecs = now.tv_usec * 1000 - start->tv_nsec;

	if (nanosecs >= (NANOSEC / 2))
		seconds++;
	else if (nanosecs < -(NANOSEC / 2))
		seconds--;

	return (seconds);
}

/*
 * Returns the following:
 *
 * 	0	No error
 * 	EINVAL	Invalid number
 * 	ERANGE	Value exceeds (min, max) range
 */
static int
str2id(const char *p, pid_t *val, long min, long max)
{
	char *q;
	long number;
	int error;

	errno = 0;
	number = strtol(p, &q, 10);

	if (errno != 0 || q == p || *q != '\0') {
		if ((error = errno) == 0) {
			/*
			 * strtol() can fail without setting errno, or it can
			 * set it to EINVAL or ERANGE.  In the case errno is
			 * still zero, return EINVAL.
			 */
			error = EINVAL;
		}
	} else if (number < min || number > max) {
		error = ERANGE;
	} else {
		error = 0;
	}

	*val = number;

	return (error);
}

/*
 * Returns the following:
 *
 * 	0	No error
 * 	EINVAL	Invalid number
 * 	ERANGE	Value exceeds (min, max) range
 */
static int
str2uid(const char *p, uid_t *val, unsigned long min, unsigned long max)
{
	char *q;
	unsigned long number;
	int error;

	errno = 0;
	number = strtoul(p, &q, 10);

	if (errno != 0 || q == p || *q != '\0') {
		if ((error = errno) == 0) {
			/*
			 * strtoul() can fail without setting errno, or it can
			 * set it to EINVAL or ERANGE.  In the case errno is
			 * still zero, return EINVAL.
			 */
			error = EINVAL;
		}
	} else if (number < min || number > max) {
		error = ERANGE;
	} else {
		error = 0;
	}

	*val = number;

	return (error);
}

static int
pidcmp(const void *p1, const void *p2)
{
	pid_t i = *((pid_t *)p1);
	pid_t j = *((pid_t *)p2);

	return (i - j);
}
