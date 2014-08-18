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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 */

/*
 * ptree -- print family tree of processes
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/termios.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <pwd.h>
#include <libproc.h>
#include <libzonecfg.h>
#include <limits.h>
#include <libcontract.h>
#include <sys/contract.h>
#include <sys/ctfs.h>
#include <libcontract_priv.h>
#include <sys/stat.h>
#include "ptools_common.h"

#define	FAKEDPID0(p)	(p->pid == 0 && p->psargs[0] == '\0')

typedef struct ps {
	int	done;
	uid_t	uid;
	uid_t	gid;
	pid_t	pid;		/* pid == -1 indicates this is a contract */
	pid_t	ppid;
	pid_t	pgrp;
	pid_t	sid;
	zoneid_t zoneid;
	ctid_t	ctid;
	timestruc_t start;
	char	psargs[PRARGSZ];
	struct ps *pp;		/* parent */
	struct ps *sp;		/* sibling */
	struct ps *cp;		/* child */
} ps_t;

static	ps_t	**ps;		/* array of ps_t's */
static	unsigned psize;		/* size of array */
static	int	nps;		/* number of ps_t's */
static	ps_t	**ctps;		/* array of contract ps_t's */
static	unsigned ctsize;	/* size of contract array */
static	int	nctps;		/* number of contract ps_t's */
static	ps_t	*proc0;		/* process 0 */
static	ps_t	*proc1;		/* process 1 */

static	char	*command;

static	int	aflag = 0;
static	int	cflag = 0;
static	int	zflag = 0;
static	zoneid_t zoneid;
static	int	columns = 80;

static void markprocs(ps_t *p);
static int printone(ps_t *p, int level);
static void insertchild(ps_t *, ps_t *);
static void prsort(ps_t *p);
static void printsubtree(ps_t *p, int level);
static zoneid_t getzone(char *arg);
static ps_t *fakepid0(void);

int
main(int argc, char **argv)
{
	psinfo_t info;	/* process information structure from /proc */
	int opt;
	int errflg = 0;
	struct winsize winsize;
	char *s;
	int n;
	int retc = 0;
	char ppath[PATH_MAX];

	DIR *dirp;
	struct dirent *dentp;
	char	pname[PATH_MAX];
	int	pdlen;

	ps_t *p;

	if ((command = strrchr(argv[0], '/')) == NULL)
		command = argv[0];
	else
		command++;

	/* options */
	while ((opt = getopt(argc, argv, "acz:")) != EOF) {
		switch (opt) {
		case 'a':		/* include children of process 0 */
			aflag = 1;
			break;
		case 'c':		/* display contract ownership */
			aflag = cflag = 1;
			break;
		case 'z':		/* only processes in given zone */
			zflag = 1;
			zoneid = getzone(optarg);
			break;
		default:
			errflg = 1;
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (errflg) {
		(void) fprintf(stderr,
		    "usage:\t%s [-ac] [-z zone] [ {pid|user} ... ]\n",
		    command);
		(void) fprintf(stderr,
		    "  (show process trees)\n");
		(void) fprintf(stderr,
		    "  list can include process-ids and user names\n");
		(void) fprintf(stderr,
		    "  -a : include children of process 0\n");
		(void) fprintf(stderr,
		    "  -c : show contract ownership\n");
		(void) fprintf(stderr,
		    "  -z : print only processes in given zone\n");
		return (2);
	}

	/*
	 * Kind of a hack to determine the width of the output...
	 */
	if ((s = getenv("COLUMNS")) != NULL && (n = atoi(s)) > 0)
		columns = n;
	else if (isatty(fileno(stdout)) &&
	    ioctl(fileno(stdout), TIOCGWINSZ, &winsize) == 0 &&
	    winsize.ws_col != 0)
		columns = winsize.ws_col;

	nps = 0;
	psize = 0;
	ps = NULL;

	(void) proc_snprintf(ppath, sizeof (ppath), "/proc");

	/*
	 * Search the /proc directory for all processes.
	 */
	if ((dirp = opendir(ppath)) == NULL) {
		(void) fprintf(stderr, "%s: cannot open %s directory\n",
		    command, ppath);
		return (1);
	}

	(void) strcpy(pname, ppath);
	pdlen = strlen(pname);
	pname[pdlen++] = '/';

	/* for each active process --- */
	while (dentp = readdir(dirp)) {
		int	procfd;	/* filedescriptor for /proc/nnnnn/psinfo */

		if (dentp->d_name[0] == '.')		/* skip . and .. */
			continue;
		(void) strcpy(pname + pdlen, dentp->d_name);
		(void) strcpy(pname + strlen(pname), "/psinfo");
retry:
		if ((procfd = open(pname, O_RDONLY)) == -1)
			continue;

		/*
		 * Get the info structure for the process and close quickly.
		 */
		if (read(procfd, &info, sizeof (info)) != sizeof (info)) {
			int	saverr = errno;

			(void) close(procfd);
			if (saverr == EAGAIN)
				goto retry;
			if (saverr != ENOENT)
				perror(pname);
			continue;
		}
		(void) close(procfd);

		/*
		 * We make sure there's always a free slot in the table
		 * in case we need to add a fake p0.
		 */
		if (nps + 1 >= psize) {
			if ((psize *= 2) == 0)
				psize = 20;
			if ((ps = realloc(ps, psize*sizeof (ps_t *))) == NULL) {
				perror("realloc()");
				return (1);
			}
		}
		if ((p = malloc(sizeof (ps_t))) == NULL) {
			perror("malloc()");
			return (1);
		}
		ps[nps++] = p;
		p->done = 0;
		p->uid = info.pr_uid;
		p->gid = info.pr_gid;
		p->pid = info.pr_pid;
		p->ppid = info.pr_ppid;
		p->pgrp = info.pr_pgid;
		p->sid = info.pr_sid;
		p->zoneid = info.pr_zoneid;
		p->ctid = info.pr_contract;
		p->start = info.pr_start;
		proc_unctrl_psinfo(&info);
		if (info.pr_nlwp == 0)
			(void) strcpy(p->psargs, "<defunct>");
		else if (info.pr_psargs[0] == '\0')
			(void) strncpy(p->psargs, info.pr_fname,
			    sizeof (p->psargs));
		else
			(void) strncpy(p->psargs, info.pr_psargs,
			    sizeof (p->psargs));
		p->psargs[sizeof (p->psargs)-1] = '\0';
		p->pp = NULL;
		p->sp = NULL;
		p->cp = NULL;
		if (p->pid == p->ppid)
			proc0 = p;
		if (p->pid == 1)
			proc1 = p;
	}

	(void) closedir(dirp);
	if (proc0 == NULL)
		proc0 = fakepid0();
	if (proc1 == NULL)
		proc1 = proc0;

	for (n = 0; n < nps; n++) {
		p = ps[n];
		if (p->pp == NULL)
			prsort(p);
	}

	if (cflag)
		/* Parent all orphan contracts to process 0. */
		for (n = 0; n < nctps; n++) {
			p = ctps[n];
			if (p->pp == NULL)
				insertchild(proc0, p);
		}

	if (argc == 0) {
		for (p = aflag ? proc0->cp : proc1->cp; p != NULL; p = p->sp) {
			markprocs(p);
			printsubtree(p, 0);
		}
		return (0);
	}

	/*
	 * Initially, assume we're not going to find any processes.  If we do
	 * mark any, then set this to 0 to indicate no error.
	 */
	errflg = 1;

	while (argc-- > 0) {
		char *arg;
		char *next;
		pid_t pid;
		uid_t uid;
		int n;

		/* in case some silly person said 'ptree /proc/[0-9]*' */
		arg = strrchr(*argv, '/');
		if (arg++ == NULL)
			arg = *argv;
		argv++;
		uid = (uid_t)-1;
		errno = 0;
		pid = strtoul(arg, &next, 10);
		if (errno != 0 || *next != '\0') {
			struct passwd *pw = getpwnam(arg);
			if (pw == NULL) {
				(void) fprintf(stderr,
				    "%s: invalid username: %s\n",
				    command, arg);
				retc = 1;
				continue;
			}
			uid = pw->pw_uid;
			pid = -1;
		}

		for (n = 0; n < nps; n++) {
			ps_t *p = ps[n];

			/*
			 * A match on pid causes the subtree starting at pid
			 * to be printed, regardless of the -a flag.
			 * For uid matches, we never include pid 0 and only
			 * include the children of pid 0 if -a was specified.
			 */
			if (p->pid == pid || (p->uid == uid && p->pid != 0 &&
			    (p->ppid != 0 || aflag))) {
				errflg = 0;
				markprocs(p);
				if (p->pid != 0)
					for (p = p->pp; p != NULL &&
					    p->done != 1 && p->pid != 0;
					    p = p->pp)
						if ((p->ppid != 0 || aflag) &&
						    (!zflag ||
						    p->zoneid == zoneid))
							p->done = 1;
				if (uid == (uid_t)-1)
					break;
			}
		}
	}

	printsubtree(proc0, 0);
	/*
	 * retc = 1 if an invalid username was supplied.
	 * errflg = 1 if no matching processes were found.
	 */
	return (retc || errflg);
}

#define	PIDWIDTH	5

static int
printone(ps_t *p, int level)
{
	int n, indent;

	if (p->done && !FAKEDPID0(p)) {
		indent = level * 2;
		if ((n = columns - PIDWIDTH - indent - 2) < 0)
			n = 0;
		if (p->pid >= 0) {
			(void) printf("%*.*s%-*d %.*s\n", indent, indent, " ",
			    PIDWIDTH, (int)p->pid, n, p->psargs);
		} else {
			assert(cflag != 0);
			(void) printf("%*.*s[process contract %d]\n",
			    indent, indent, " ", (int)p->ctid);
		}
		return (1);
	}
	return (0);
}

static void
insertchild(ps_t *pp, ps_t *cp)
{
	/* insert as child process of p */
	ps_t **here;
	ps_t *sp;

	/* sort by start time */
	for (here = &pp->cp, sp = pp->cp;
	    sp != NULL;
	    here = &sp->sp, sp = sp->sp) {
		if (cp->start.tv_sec < sp->start.tv_sec)
			break;
		if (cp->start.tv_sec == sp->start.tv_sec &&
		    cp->start.tv_nsec < sp->start.tv_nsec)
			break;
	}
	cp->pp = pp;
	cp->sp = sp;
	*here = cp;
}

static void
ctsort(ctid_t ctid, ps_t *p)
{
	ps_t *pp;
	int fd, n;
	ct_stathdl_t hdl;
	struct stat64 st;

	for (n = 0; n < nctps; n++)
		if (ctps[n]->ctid == ctid) {
			insertchild(ctps[n], p);
			return;
		}

	if ((fd = contract_open(ctid, "process", "status", O_RDONLY)) == -1)
		return;
	if (fstat64(fd, &st) == -1 || ct_status_read(fd, CTD_COMMON, &hdl)) {
		(void) close(fd);
		return;
	}
	(void) close(fd);

	if (nctps >= ctsize) {
		if ((ctsize *= 2) == 0)
			ctsize = 20;
		if ((ctps = realloc(ctps, ctsize * sizeof (ps_t *))) == NULL) {
			perror("realloc()");
			exit(1);
		}
	}
	pp = calloc(sizeof (ps_t), 1);
	if (pp == NULL) {
		perror("calloc()");
		exit(1);
	}
	ctps[nctps++] = pp;

	pp->pid = -1;
	pp->ctid = ctid;
	pp->start.tv_sec = st.st_ctime;
	insertchild(pp, p);

	pp->zoneid = ct_status_get_zoneid(hdl);
	/*
	 * In a zlogin <zonename>, the contract belongs to the
	 * global zone and the shell opened belongs to <zonename>.
	 * If the -c and -z zonename flags are used together, then
	 * we need to adjust the zoneid in the contract's ps_t as
	 * follows:
	 *
	 * ptree -c -z <zonename> --> zoneid == p->zoneid
	 * ptree -c -z global	  --> zoneid == pp->zoneid
	 *
	 * The approach assumes that no tool can create processes in
	 * different zones under the same contract. If this is
	 * possible, ptree will need to refactor how it builds
	 * its internal tree of ps_t's
	 */
	if (zflag && p->zoneid != pp->zoneid &&
	    (zoneid == p->zoneid || zoneid == pp->zoneid))
		pp->zoneid = p->zoneid;
	if (ct_status_get_state(hdl) == CTS_OWNED) {
		pp->ppid = ct_status_get_holder(hdl);
		prsort(pp);
	} else if (ct_status_get_state(hdl) == CTS_INHERITED) {
		ctsort(ct_status_get_holder(hdl), pp);
	}
	ct_status_free(hdl);
}

static void
prsort(ps_t *p)
{
	int n;
	ps_t *pp;

	/* If this node already has a parent, it's sorted */
	if (p->pp != NULL)
		return;

	for (n = 0; n < nps; n++) {
		pp = ps[n];

		if (pp != NULL && p != pp && p->ppid == pp->pid) {
			if (cflag && p->pid >= 0 &&
			    p->ctid != -1 && p->ctid != pp->ctid) {
				ctsort(p->ctid, p);
			} else {
				insertchild(pp, p);
				prsort(pp);
			}
			return;
		}
	}

	/* File parentless processes under their contracts */
	if (cflag && p->pid >= 0)
		ctsort(p->ctid, p);
}

static void
printsubtree(ps_t *p, int level)
{
	int printed;

	printed = printone(p, level);
	if (level != 0 || printed == 1)
		level++;
	for (p = p->cp; p != NULL; p = p->sp)
		printsubtree(p, level);
}

static void
markprocs(ps_t *p)
{
	if (!zflag || p->zoneid == zoneid)
		p->done = 1;
	for (p = p->cp; p != NULL; p = p->sp)
		markprocs(p);
}

/*
 * If there's no "top" process, we fake one; it will be the parent of
 * all orphans.
 */
static ps_t *
fakepid0(void)
{
	ps_t *p0, *p;
	int n;

	if ((p0 = malloc(sizeof (ps_t))) == NULL) {
		perror("malloc()");
		exit(1);
	}
	(void) memset(p0, '\0', sizeof (ps_t));

	/* First build all partial process trees. */
	for (n = 0; n < nps; n++) {
		p = ps[n];
		if (p->pp == NULL)
			prsort(p);
	}

	/* Then adopt all orphans. */
	for (n = 0; n < nps; n++) {
		p = ps[n];
		if (p->pp == NULL)
			insertchild(p0, p);
	}

	/* We've made sure earlier there's room for this. */
	ps[nps++] = p0;
	return (p0);
}

/* convert string containing zone name or id to a numeric id */
static zoneid_t
getzone(char *arg)
{
	zoneid_t zoneid;

	if (zone_get_id(arg, &zoneid) != 0) {
		(void) fprintf(stderr, "%s: unknown zone: %s\n", command, arg);
		exit(1);
	}
	return (zoneid);
}
