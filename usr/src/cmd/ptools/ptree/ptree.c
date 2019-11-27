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
 * Copyright 2019 Joyent, Inc.
 */

/*
 * ptree -- print family tree of processes
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <sys/debug.h>
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
#include <locale.h>
#include <sys/contract.h>
#include <sys/ctfs.h>
#include <libcontract_priv.h>
#include <sys/stat.h>
#include <stdbool.h>

#define	COLUMN_DEFAULT	80
#define	CHUNK_SIZE	256 /* Arbitrary amount */
#define	FAKEDPID0(p)	(p->pid == 0 && p->psargs[0] == '\0')
#define	HAS_SIBLING(p)	((p)->sp != NULL && (p)->sp->done != 0)

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
	char *svc_fmri;
	timestruc_t start;
	char	psargs[PRARGSZ];
	struct ps *pp;		/* parent */
	struct ps *sp;		/* sibling */
	struct ps *cp;		/* child */
} ps_t;

enum { DASH = 0, BAR, CORNER, VRIGHT };

static	ps_t	**ps;		/* array of ps_t's */
static	unsigned psize;		/* size of array */
static	int	nps;		/* number of ps_t's */
static	ps_t	**ctps;		/* array of contract ps_t's */
static	unsigned ctsize;	/* size of contract array */
static	int	nctps;		/* number of contract ps_t's */
static	ps_t	*proc0;		/* process 0 */
static	ps_t	*proc1;		/* process 1 */

static	int	aflag = 0;
static	int	cflag = 0;
static	int	gflag = 0;
static	int	sflag = 0;
static	int	wflag = 0;
static	int	zflag = 0;
static	zoneid_t zoneid;
static	char *match_svc;
static	char *match_inst;
static	int	columns;

static const char *box_ascii[] = {
	[DASH] =	"-",
	[BAR] =		"|",
	[CORNER] =	"`",
	[VRIGHT] =	"+"
};

static const char *box_utf8[] = {
	[DASH] =	"\xe2\x94\x80", /* \u2500 */
	[BAR] =		"\xe2\x94\x82", /* \u2502 */
	[CORNER] =	"\xe2\x94\x94", /* \u2514 */
	[VRIGHT] =	"\xe2\x94\x9c", /* \u251c */
};

static const char **box;

static size_t get_termwidth(void);
static const char **get_boxchars(void);
static int add_proc(psinfo_t *, lwpsinfo_t *, void *);
static bool match_proc(ps_t *);
static void markprocs(ps_t *);
static int printone(ps_t *, int);
static void insertchild(ps_t *, ps_t *);
static void prsort(ps_t *);
static void printsubtree(ps_t *, int);
static void p_get_svc_fmri(ps_t *, ct_stathdl_t);
static char *parse_svc(const char *, char **);
static zoneid_t getzone(const char *);
static ps_t *fakepid0(void);

static void *zalloc(size_t);
static void *xreallocarray(void *, size_t, size_t);
static char *xstrdup(const char *);

static void __NORETURN
usage(void)
{
	(void) fprintf(stderr,
	    "usage:\t%s [-ac] [-s svc] [-z zone] [ {pid|user} ... ]\n",
	    getprogname());
	(void) fprintf(stderr,
	    "  (show process trees)\n");
	(void) fprintf(stderr,
	    "  list can include process-ids and user names\n");
	(void) fprintf(stderr,
	    "  -a : include children of process 0\n");
	(void) fprintf(stderr,
	    "  -c : show contracts\n");
	(void) fprintf(stderr,
	    "  -g : use line drawing characters in output\n");
	(void) fprintf(stderr,
	    "  -s : print only processes with given service FMRI\n");
	(void) fprintf(stderr,
	    "  -w : allow lines to wrap instead of truncating\n");
	(void) fprintf(stderr,
	    "  -z : print only processes in given zone\n");
	exit(2);
}

int
main(int argc, char **argv)
{
	int opt;
	int errflg = 0;
	int n;
	int retc = 0;

	ps_t *p;

	/* options */
	while ((opt = getopt(argc, argv, "acgs:wz:")) != EOF) {
		switch (opt) {
		case 'a':		/* include children of process 0 */
			aflag = 1;
			break;
		case 'c':		/* display contract ownership */
			aflag = cflag = 1;
			break;
		case 'g':
			gflag = 1;
			box = get_boxchars();
			break;
		case 's':
			sflag = 1;
			match_svc = parse_svc(optarg, &match_inst);
			break;
		case 'w':
			wflag = 1;
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

	if (errflg)
		usage();

	if (!wflag) {
		columns = get_termwidth();
		VERIFY3S(columns, >, 0);
	}

	nps = 0;
	psize = 0;
	ps = NULL;

	/* Currently, this can only fail if the 3rd argument is invalid */
	VERIFY0(proc_walk(add_proc, NULL, PR_WALK_PROC|PR_WALK_INCLUDE_SYS));

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
				warnx("invalid username: %s", arg);
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
						    match_proc(p))
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


#define	PIDWIDTH	6

static void
printlines(ps_t *p, int level)
{
	if (level == 0)
		return;

	if (!gflag) {
		(void) printf("%*s", level * 2, "");
		return;
	}

	for (int i = 1; i < level; i++) {
		ps_t *ancestor = p;

		/* Find our ancestor at depth 'i' */
		for (int j = i; j < level; j++)
			ancestor = ancestor->pp;

		(void) printf("%s ", HAS_SIBLING(ancestor) ? box[BAR] : " ");
	}

	(void) printf("%s%s", HAS_SIBLING(p) ? box[VRIGHT] : box[CORNER],
	    box[DASH]);
}

static int
printone(ps_t *p, int level)
{
	int n, indent;

	if (p->done && !FAKEDPID0(p)) {
		indent = level * 2;

		if (wflag) {
			n = strlen(p->psargs);
		} else {
			if ((n = columns - PIDWIDTH - indent - 2) < 0)
				n = 0;
		}

		printlines(p, level);
		if (p->pid >= 0) {
			(void) printf("%-*d %.*s\n", PIDWIDTH, (int)p->pid, n,
			    p->psargs);
		} else {
			assert(cflag != 0);
			(void) printf("[process contract %d: %s]\n",
			    (int)p->ctid,
			    p->svc_fmri == NULL ? "?" : p->svc_fmri);
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

static ct_stathdl_t
ct_status_open(ctid_t ctid, struct stat64 *stp)
{
	ct_stathdl_t hdl;
	int fd;

	if ((fd = contract_open(ctid, "process", "status", O_RDONLY)) == -1)
		return (NULL);

	if (fstat64(fd, stp) == -1 || ct_status_read(fd, CTD_FIXED, &hdl)) {
		(void) close(fd);
		return (NULL);
	}

	(void) close(fd);

	return (hdl);
}

/*
 * strdup() failure is OK - better to report something than fail totally.
 */
static void
p_get_svc_fmri(ps_t *p, ct_stathdl_t inhdl)
{
	ct_stathdl_t hdl = inhdl;
	struct stat64 st;
	char *fmri;

	if (hdl == NULL && (hdl = ct_status_open(p->ctid, &st)) == NULL)
		return;

	if (ct_pr_status_get_svc_fmri(hdl, &fmri) == 0)
		p->svc_fmri = strdup(fmri);

	if (inhdl == NULL)
		ct_status_free(hdl);
}

static void
ctsort(ctid_t ctid, ps_t *p)
{
	ps_t *pp;
	int n;
	ct_stathdl_t hdl;
	struct stat64 st;

	for (n = 0; n < nctps; n++)
		if (ctps[n]->ctid == ctid) {
			insertchild(ctps[n], p);
			return;
		}

	if ((hdl = ct_status_open(ctid, &st)) == NULL)
		return;

	if (nctps >= ctsize) {
		ctsize += CHUNK_SIZE;
		ctps = xreallocarray(ctps, ctsize, sizeof (ps_t *));
	}
	pp = zalloc(sizeof (*pp));
	ctps[nctps++] = pp;

	pp->pid = -1;
	pp->ctid = ctid;

	p_get_svc_fmri(pp, hdl);

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

/*
 * Match against the service name (and just the final component), and any
 * specified instance name.
 */
static bool
match_proc(ps_t *p)
{
	bool matched = false;
	const char *cp;
	char *p_inst;
	char *p_svc;

	if (zflag && p->zoneid != zoneid)
		return (false);

	if (!sflag)
		return (true);

	if (p->svc_fmri == NULL)
		return (false);

	p_svc = parse_svc(p->svc_fmri, &p_inst);

	if (strcmp(p_svc, match_svc) != 0 &&
	    ((cp = strrchr(p_svc, '/')) == NULL ||
	    strcmp(cp + 1, match_svc) != 0)) {
		goto out;
	}

	if (strlen(match_inst) == 0 ||
	    strcmp(p_inst, match_inst) == 0)
		matched = true;

out:
	free(p_svc);
	free(p_inst);
	return (matched);
}

static void
markprocs(ps_t *p)
{
	if (match_proc(p))
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

	p0 = zalloc(sizeof (*p0));

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
getzone(const char *arg)
{
	zoneid_t zoneid;

	if (zone_get_id(arg, &zoneid) != 0)
		err(EXIT_FAILURE, "unknown zone: %s", arg);

	return (zoneid);
}

/* svc:/mysvc:default ->  mysvc, default */
static char *
parse_svc(const char *arg, char **instp)
{
	const char *p = arg;
	char *ret;
	char *cp;

	if (strncmp(p, "svc:/", strlen("svc:/")) == 0)
		p += strlen("svc:/");

	ret = xstrdup(p);

	if ((cp = strrchr(ret, ':')) != NULL) {
		*cp = '\0';
		cp++;
	} else {
		cp = "";
	}

	*instp = xstrdup(cp);
	return (ret);
}

static int
add_proc(psinfo_t *info, lwpsinfo_t *lwp __unused, void *arg __unused)
{
	ps_t *p;

	/*
	 * We make sure there is always a free slot in the table
	 * in case we need to add a fake p0;
	 */
	if (nps + 1 >= psize) {
		psize += CHUNK_SIZE;
		ps = xreallocarray(ps, psize, sizeof (ps_t));
	}

	p = zalloc(sizeof (*p));
	ps[nps++] = p;
	p->done = 0;
	p->uid = info->pr_uid;
	p->gid = info->pr_gid;
	p->pid = info->pr_pid;
	p->ppid = info->pr_ppid;
	p->pgrp = info->pr_pgid;
	p->sid = info->pr_sid;
	p->zoneid = info->pr_zoneid;
	p->ctid = info->pr_contract;
	p->start = info->pr_start;
	proc_unctrl_psinfo(info);
	if (info->pr_nlwp == 0)
		(void) strcpy(p->psargs, "<defunct>");
	else if (info->pr_psargs[0] == '\0')
		(void) strncpy(p->psargs, info->pr_fname,
		    sizeof (p->psargs));
	else
		(void) strncpy(p->psargs, info->pr_psargs,
		    sizeof (p->psargs));
	p->psargs[sizeof (p->psargs)-1] = '\0';
	p->pp = NULL;
	p->sp = NULL;

	if (sflag)
		p_get_svc_fmri(p, NULL);

	if (p->pid == p->ppid)
		proc0 = p;
	if (p->pid == 1)
		proc1 = p;

	return (0);
}


static size_t
get_termwidth(void)
{
	char *s;

	if ((s = getenv("COLUMNS")) != NULL) {
		unsigned long n;

		errno = 0;
		n = strtoul(s, NULL, 10);
		if (n != 0 && errno == 0) {
			/* Sanity check on the range */
			if (n > INT_MAX)
				n = COLUMN_DEFAULT;
			return (n);
		}
	}

	struct winsize winsize;

	if (isatty(STDOUT_FILENO) &&
	    ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize) == 0 &&
	    winsize.ws_col != 0) {
		return (winsize.ws_col);
	}

	return (COLUMN_DEFAULT);
}

static const char **
get_boxchars(void)
{
	char *loc = setlocale(LC_ALL, "");

	if (loc == NULL)
		return (box_ascii);

	const char *p = strstr(loc, "UTF-8");

	/*
	 * Only use the UTF-8 box drawing characters if the locale ends
	 * with "UTF-8".
	 */
	if (p != NULL && p[5] == '\0')
		return (box_utf8);

	return (box_ascii);
}

static void *
zalloc(size_t len)
{
	void *p = calloc(1, len);

	if (p == NULL)
		err(EXIT_FAILURE, "calloc");
	return (p);
}

static void *
xreallocarray(void *ptr, size_t nelem, size_t elsize)
{
	void *p = reallocarray(ptr, nelem, elsize);

	if (p == NULL)
		err(EXIT_FAILURE, "reallocarray");
	return (p);
}

static char *
xstrdup(const char *s)
{
	char *news = strdup(s);

	if (news == NULL)
		err(EXIT_FAILURE, "strdup");
	return (news);
}
