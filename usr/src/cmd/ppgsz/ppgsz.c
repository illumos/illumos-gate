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
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <libproc.h>
#include <sys/sysmacros.h>
#include <libgen.h>
#include <thread.h>

#ifndef TRUE
#define	TRUE	1
#endif
#ifndef FALSE
#define	FALSE	0
#endif

static struct	ps_prochandle *Pr;
static char	*command;
static volatile int interrupt;
static int	Fflag;
static int	cflag = 1;

static void	intr(int);
static int	setpgsz(struct ps_prochandle *, int, size_t *);
static int	setpgsz_anon(struct ps_prochandle *, size_t, int);
static caddr_t	setup_mha(uint_t, size_t, int);
static size_t	discover_optimal_pagesize(struct ps_prochandle *,
		uint_t, pid_t);
static void	usage();

#define	INVPGSZ		3

/* subopt */

static char	*suboptstr[] = {
	"heap",
	"stack",
	"anon",
	NULL
};

enum	suboptenum {
	E_HEAP,
	E_STACK,
	E_ANON
};

static size_t
atosz(char *optarg)
{
	size_t		sz = 0;
	char		*endptr;

	if (optarg == NULL || optarg[0] == '\0')
		return (INVPGSZ);

	sz = strtoll(optarg, &endptr, 0);

	switch (*endptr) {
	case 'T':
	case 't':
		sz *= 1024;
	/*FALLTHRU*/
	case 'G':
	case 'g':
		sz *= 1024;
	/*FALLTHRU*/
	case 'M':
	case 'm':
		sz *= 1024;
	/*FALLTHRU*/
	case 'K':
	case 'k':
		sz *= 1024;
	/*FALLTHRU*/
	case 'B':
	case 'b':
	default:
		break;
	}
	return (sz);
}

/* pgsz array sufficient for max page sizes */

static size_t	pgsza[8 * sizeof (void *)];
static int	nelem;

static void
getpgsz()
{
	if ((nelem = getpagesizes(NULL, 0)) == 0) {
		(void) fprintf(stderr, "%s: cannot determine system page"
		    " sizes\n", command);
		exit(125);
	}

	(void) getpagesizes(pgsza, nelem);
}

static size_t
cnvpgsz(char *optarg)
{
	size_t		pgsz = atosz(optarg);
	int		i;

	if (!ISP2(pgsz) || ((pgsz < pgsza[0]) && pgsz != 0)) {
		pgsz = INVPGSZ;
	} else {
		for (i = nelem - 1; i >= 0; i--) {
			if (pgsz == pgsza[i])
				break;
			if (pgsz > pgsza[i]) {
				pgsz = INVPGSZ;
				break;
			}
		}
	}
	if (pgsz == INVPGSZ) {
		if (optarg != NULL) {
			(void) fprintf(stderr,
			    "%s: invalid page size specified (%s)\n",
			    command, optarg);
		} else {
			usage();
		}
		exit(125);
	}
	return (pgsz);
}

static void
usage()
{
	(void) fprintf(stderr,
	    "usage:\t%s -o option[,option] [-F] cmd | -p pid ...\n"
	    "    (set preferred page size of cmd or each process)\n"
	    "    -o option[,option]: options are\n"
	    "         stack=sz\n"
	    "         heap=sz\n"
	    "         anon=sz		(sz: valid page size or 0 (zero))\n"
	    "    -F: force grabbing of the target process(es)\n"
	    "    cmd: launch command\n"
	    "    -p pid ...: process id list\n",
	    command);
	exit(125);
}

int
main(int argc, char *argv[])
{
	int		rc, err = 0;
	int		opt, subopt;
	int		errflg = 0;
	char		*options, *value;
	size_t		pgsz[] = {INVPGSZ, INVPGSZ, INVPGSZ};
	pid_t		pid;
	int		status;

	if ((command = strrchr(argv[0], '/')) != NULL)
		command++;
	else
		command = argv[0];

	getpgsz();

	/* options */
	while ((opt = getopt(argc, argv, "o:Fp")) != EOF) {
		switch (opt) {
		case 'o':		/* options */
			options = optarg;
			while (*options != '\0') {
				subopt = getsubopt(&options, suboptstr, &value);
				switch (subopt) {
				case E_HEAP:
				case E_STACK:
				case E_ANON:
					pgsz[subopt] = cnvpgsz(value);
					break;
				default:
					errflg = 1;
					break;
				}
			}
			break;
		case 'F':		/* force grabbing (no O_EXCL) */
			Fflag = PGRAB_FORCE;
			break;
		case 'p':
			cflag = 0;
			break;
		default:
			errflg = 1;
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if ((pgsz[E_HEAP] == INVPGSZ && pgsz[E_STACK] == INVPGSZ &&
	    pgsz[E_ANON] == INVPGSZ) || errflg || argc <= 0) {
		usage();
	}

	/* catch signals from terminal */
	if (sigset(SIGHUP, SIG_IGN) == SIG_DFL)
		(void) sigset(SIGHUP, intr);
	if (sigset(SIGINT, SIG_IGN) == SIG_DFL)
		(void) sigset(SIGINT, intr);
	if (sigset(SIGQUIT, SIG_IGN) == SIG_DFL)
		(void) sigset(SIGQUIT, intr);
	(void) sigset(SIGTERM, intr);

	if (cflag && !interrupt) {		/* command */
		int		err;
		char		path[PATH_MAX];

		Pr = Pcreate(argv[0], &argv[0], &err, path, sizeof (path));
		if (Pr == NULL) {
			switch (err) {
			case C_PERM:
				(void) fprintf(stderr,
				    "%s: cannot control set-id or "
				    "unreadable object file: %s\n",
				    command, path);
				break;
			case C_LP64:
				(void) fprintf(stderr,
				    "%s: cannot control _LP64 "
				    "program: %s\n", command, path);
				break;
			case C_NOEXEC:
				(void) fprintf(stderr, "%s: cannot execute "
				    "program: %s\n", command, argv[0]);
				exit(126);
				break;
			case C_NOENT:
				(void) fprintf(stderr, "%s: cannot find "
				    "program: %s\n", command, argv[0]);
				exit(127);
				break;
			case C_STRANGE:
				break;
			default:
				(void) fprintf(stderr,
				    "%s: %s\n", command, Pcreate_error(err));
				break;
			}
			exit(125);
		}

		if ((rc = setpgsz(Pr, Pstatus(Pr)->pr_dmodel, pgsz)) != 0) {
			(void) fprintf(stderr, "%s: set page size "
			    "failed for program: %s\n", command, argv[0]);
			(void) pr_exit(Pr, 1);
			exit(125);
		}

		/*
		 * release the command to run, wait for it and
		 * return it's exit status if we can.
		 */
		Prelease(Pr, 0);
		do {
			pid = wait(&status);
		} while (pid == -1 && errno == EINTR);

		if (pid == -1) {
			(void) fprintf(stderr, "%s: wait() error: %s\n",
			    command, strerror(errno));
			exit(125);
		}

		/*
		 * Pass thru the child's exit value.
		 */
		if (WIFEXITED(status))
			exit(WEXITSTATUS(status));
		exit(status | WCOREFLG);
	}

	/* process pids */

	while (--argc >= 0 && !interrupt) {
		char *arg;
		psinfo_t psinfo;
		int gret;

		(void) fflush(stdout);	/* line-at-a-time */

		/* get the specified pid and the psinfo struct */
		arg = *argv++;
		pid = proc_arg_psinfo(arg, PR_ARG_PIDS, &psinfo, &gret);

		if (pid == -1) {
			(void) fprintf(stderr, "%s: cannot examine pid %s:"
			    " %s\n", command, arg, Pgrab_error(gret));
			if (!isdigit(arg[0]) && strncmp(arg, "/proc/", 6)) {
				(void) fprintf(stderr,
				    "\tdo not use -p option"
				    " to launch a command\n");
			}
			err++;
		} else if ((Pr = Pgrab(pid, Fflag, &gret)) != NULL) {
			rc = setpgsz(Pr, Pstatus(Pr)->pr_dmodel, pgsz);
			if (rc != 0) {
				(void) fprintf(stderr, "%s: set page size "
				    "failed for pid: %d\n", command, (int)pid);
				err++;
			}
			Prelease(Pr, 0);
			Pr = NULL;
		} else {
			switch (gret) {
			case G_SYS:
				proc_unctrl_psinfo(&psinfo);
				(void) fprintf(stderr, "%s: cannot set page "
				    "size for system process: %d [ %s ]\n",
				    command, (int)pid, psinfo.pr_psargs);
				err++;
				break;
			case G_SELF:
				/* do it to own self */
				rc = setpgsz(NULL, psinfo.pr_dmodel, pgsz);
				if (rc != 0) {
					(void) fprintf(stderr, "%s: set page"
					    "size failed for self: %d\n",
					    command, (int)pid);
					err++;
				}
				break;
			default:
				(void) fprintf(stderr, "%s: %s: %d\n",
				    command, Pgrab_error(gret), (int)pid);
				err++;
				break;
			}
		}
	}

	if (interrupt || err)
		exit(125);

	return (0);
}

/* ARGSUSED */
static void
intr(int sig)
{
	interrupt = 1;
}

/* ------ begin specific code ------ */

/* set process page size */
/*ARGSUSED*/
static int
setpgsz(struct	ps_prochandle *Pr, int dmodel, size_t pgsz[])
{
	int			rc;
	int			err = 0;
	caddr_t			mpss;
	int			i;
	static uint_t	pgszcmd[] =
	{MHA_MAPSIZE_BSSBRK, MHA_MAPSIZE_STACK, MHA_MAPSIZE_VA};

	for (i = E_HEAP; i <= E_ANON; i++) {
		if (pgsz[i] == INVPGSZ)
			continue;

		if (i == E_ANON)
			rc = setpgsz_anon(Pr, pgsz[i], dmodel);
		else {
			mpss = setup_mha(pgszcmd[i], pgsz[i], dmodel);
			rc = pr_memcntl(Pr, NULL, 0, MC_HAT_ADVISE, mpss, 0, 0);
		}

		if (rc < 0) {
			(void) fprintf(stderr, "%s: warning: set %s page size "
			    "failed (%s) for pid %d\n", command, suboptstr[i],
			    strerror(errno), (int)Pstatus(Pr)->pr_pid);
			err++;
		}
	}
	return (err);
}


/*
 * Walk through the process' address space segments.  Set all anonymous
 * segments to the new page size.
 */
static int
setpgsz_anon(struct ps_prochandle *Pr, size_t pgsz, int dmodel)
{
	caddr_t		mpss;
	prmap_t		map;
	uintptr_t	addr;
	size_t		size;
	const psinfo_t	*psinfo;
	const pstatus_t	*pstatus;
	int		fd;
	int		rc;
	char		path[PATH_MAX];

	/*
	 * Setting the page size for anonymous segments on a process before it
	 * has run will have no effect, since it has not configured anonymous
	 * memory and the page size setting is not "sticky" inside the kernel.
	 * Any anonymous memory subsequently mapped will have the default page
	 * size.
	 */
	if (cflag)
		return (0);

	if ((psinfo = Ppsinfo(Pr)) == NULL)
		return (-1);
	if ((pstatus = Pstatus(Pr)) == NULL)
		return (-1);

	if (pgsz == 0)
		pgsz = discover_optimal_pagesize(Pr, dmodel, psinfo->pr_pid);

	mpss = setup_mha(MHA_MAPSIZE_VA, pgsz, dmodel);

	(void) snprintf(path, PATH_MAX, "/proc/%d/map", (int)psinfo->pr_pid);
	if ((fd = open(path, O_RDONLY)) < 0)
		return (-1);

	while (read(fd, &map, sizeof (map)) == sizeof (map)) {
		if ((map.pr_mflags & MA_ANON) == 0) {
			/* Not anon. */
			continue;
		} else if (map.pr_mflags & MA_SHARED) {
			/* Can't change pagesize for shared mappings. */
			continue;
		} else if (map.pr_vaddr + map.pr_size >
		    pstatus->pr_brkbase &&
		    map.pr_vaddr <
		    pstatus->pr_brkbase + pstatus->pr_brksize) {
			/* Heap. */
			continue;
		} else if (map.pr_vaddr >= pstatus->pr_stkbase &&
		    map.pr_vaddr + map.pr_size <=
		    pstatus->pr_stkbase + pstatus->pr_stksize) {
			/* Stack. */
			continue;
		} else if (map.pr_size < pgsz) {
			/* Too small. */
			continue;
		}

		/*
		 * Find the first address in the segment that is page-aligned.
		 */
		if (pgsz == 0 || ((map.pr_vaddr % pgsz) == 0))
			addr = map.pr_vaddr;
		else
			addr = map.pr_vaddr + (pgsz - (map.pr_vaddr % pgsz));

		/*
		 * Calculate how many pages will fit in the segment.
		 */
		if (pgsz == 0)
			size = map.pr_size;
		else
			size = map.pr_size - (addr % map.pr_vaddr) -
			    ((map.pr_vaddr + map.pr_size) % pgsz);

		/*
		 * If no aligned pages fit in the segment, ignore it.
		 */
		if (size < pgsz) {
			continue;
		}

		rc = pr_memcntl(Pr, (caddr_t)addr, size,
		    MC_HAT_ADVISE, mpss, 0, 0);

		/*
		 * If an error occurs on any segment, report the error here and
		 * then go on to try setting the page size for the remaining
		 * segments.
		 */
		if (rc < 0) {
			(void) fprintf(stderr, "%s: warning: set page size "
			    "failed (%s) for pid %d for anon segment at "
			    "address: %p\n", command, strerror(errno),
			    (int)psinfo->pr_pid, (void *)map.pr_vaddr);
		}
	}

	(void) close(fd);
	return (0);
}

/*
 * Discover the optimal page size for the process.
 * Do this by creating a 4M segment in the target process, set its pagesize
 * to 0, and read the map file to discover the page size selected by the system.
 */
static size_t
discover_optimal_pagesize(struct ps_prochandle *Pr, uint_t dmodel, pid_t pid)
{
	size_t			size = 0;
	size_t			len = pgsza[nelem - 1];
	prxmap_t		xmap;
	caddr_t			mha;
	void			*addr;
	int			fd = -1;
	char			path[PATH_MAX];

	(void) snprintf(path, PATH_MAX, "/proc/%d/xmap", (int)pid);
	if ((fd = open(path, O_RDONLY)) < 0)
		return (size);

	if ((addr = pr_mmap(Pr, (void *)len, len, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANON | MAP_ALIGN, -1, 0)) == MAP_FAILED) {
		goto err;
	}

	mha = setup_mha(MHA_MAPSIZE_VA, 0, dmodel);
	if (pr_memcntl(Pr, addr, len, MC_HAT_ADVISE, mha, 0, 0) < 0) {
		goto err;
	}

	/*
	 * Touch a page in the segment so the hat mapping gets created.
	 */
	(void) Pwrite(Pr, &len, sizeof (len), (uintptr_t)addr);

	/*
	 * Read through the address map looking for our segment.
	 */

	while (read(fd, &xmap, sizeof (xmap)) == sizeof (xmap)) {
		if (xmap.pr_vaddr == (uintptr_t)addr)
			break;
	}
	if (xmap.pr_vaddr != (uintptr_t)addr)
		goto err;

	size = xmap.pr_hatpagesize;

err:
	if (addr != MAP_FAILED) {
		if (pr_munmap(Pr, addr, len) == -1) {
			(void) fprintf(stderr,
			    "%s: couldn't delete segment at %p\n",
			    command, addr);
		}
	}
	if (fd != -1)
		(void) close(fd);

	return (size);
}

static struct memcntl_mha	gmha;
#ifdef _LP64
static struct memcntl_mha32	gmha32;
#endif

static caddr_t
/* ARGSUSED */
setup_mha(uint_t command, size_t pagesize, int dmodel)
{
#ifdef _LP64
	if (dmodel == PR_MODEL_ILP32) {
		gmha32.mha_cmd = command;
		gmha32.mha_flags = 0;
		gmha32.mha_pagesize = pagesize;
		return ((caddr_t)&gmha32);
	}
#endif
	gmha.mha_cmd = command;
	gmha.mha_flags = 0;
	gmha.mha_pagesize = pagesize;
	return ((caddr_t)&gmha);
}
