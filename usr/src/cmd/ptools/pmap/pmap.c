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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 */

#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <limits.h>
#include <link.h>
#include <libelf.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <sys/mman.h>
#include <sys/lgrp_user.h>
#include <libproc.h>
#include "ptools_common.h"

#include "pmap_common.h"

#define	KILOBYTE	1024
#define	MEGABYTE	(KILOBYTE * KILOBYTE)
#define	GIGABYTE	(KILOBYTE * KILOBYTE * KILOBYTE)

/*
 * Round up the value to the nearest kilobyte
 */
#define	ROUNDUP_KB(x)	(((x) + (KILOBYTE - 1)) / KILOBYTE)

/*
 * The alignment should be a power of 2.
 */
#define	P2ALIGN(x, align)		((x) & -(align))

#define	INVALID_ADDRESS			(uintptr_t)(-1)

struct totals {
	ulong_t total_size;
	ulong_t total_swap;
	ulong_t total_rss;
	ulong_t total_anon;
	ulong_t total_locked;
};

/*
 * -L option requires per-page information. The information is presented in an
 * array of page_descr structures.
 */
typedef struct page_descr {
	uintptr_t	pd_start;	/* start address of a page */
	size_t		pd_pagesize;	/* page size in bytes */
	lgrp_id_t	pd_lgrp;	/* lgroup of memory backing the page */
	int		pd_valid;	/* valid page description if non-zero */
} page_descr_t;

/*
 * Per-page information for a memory chunk.
 * The meminfo(2) system call accepts up to MAX_MEMINFO_CNT pages at once.
 * When we need to scan larger ranges we divide them in MAX_MEMINFO_CNT sized
 * chunks. The chunk information is stored in the memory_chunk structure.
 */
typedef struct memory_chunk {
	page_descr_t	page_info[MAX_MEMINFO_CNT];
	uintptr_t	end_addr;
	uintptr_t	chunk_start;	/* Starting address */
	uintptr_t	chunk_end;	/* chunk_end is always <= end_addr */
	size_t		page_size;
	int		page_index;	/* Current page */
	int		page_count;	/* Number of pages */
} memory_chunk_t;

static volatile int interrupt;

typedef int proc_xmap_f(void *, const prxmap_t *, const char *, int, int);

static	int	xmapping_iter(struct ps_prochandle *, proc_xmap_f *, void *,
    int);
static	int	rmapping_iter(struct ps_prochandle *, proc_map_f *, void *);

static	int	look_map(void *, const prmap_t *, const char *);
static	int	look_smap(void *, const prxmap_t *, const char *, int, int);
static	int	look_xmap(void *, const prxmap_t *, const char *, int, int);
static	int	look_xmap_nopgsz(void *, const prxmap_t *, const char *,
    int, int);

static int gather_map(void *, const prmap_t *, const char *);
static int gather_xmap(void *, const prxmap_t *, const char *, int, int);
static int iter_map(proc_map_f *, void *);
static int iter_xmap(proc_xmap_f *, void *);
static int parse_addr_range(char *, uintptr_t *, uintptr_t *);
static void mem_chunk_init(memory_chunk_t *, uintptr_t, size_t);

static	int	perr(char *);
static	void	printK(long, int);
static	char	*mflags(uint_t);

static size_t get_contiguous_region(memory_chunk_t *, uintptr_t,
    uintptr_t, size_t, lgrp_id_t *);
static void	mem_chunk_get(memory_chunk_t *, uintptr_t);
static lgrp_id_t addr_to_lgrp(memory_chunk_t *, uintptr_t, size_t *);
static char	*lgrp2str(lgrp_id_t);

static int	address_in_range(uintptr_t, uintptr_t, size_t);
static size_t	adjust_addr_range(uintptr_t, uintptr_t, size_t,
    uintptr_t *, uintptr_t *);

static	int	lflag = 0;
static	int	Lflag = 0;
static	int	aflag = 0;

/*
 * The -A address range is represented as a pair of addresses
 * <start_addr, end_addr>. Either one of these may be unspecified (set to
 * INVALID_ADDRESS). If both are unspecified, no address range restrictions are
 * in place.
 */
static  uintptr_t start_addr = INVALID_ADDRESS;
static	uintptr_t end_addr = INVALID_ADDRESS;

static	int	addr_width, size_width;
static	char	*command;
static	char	*procname;
static	struct ps_prochandle *Pr;

static void intr(int);

typedef struct {
	prxmap_t	md_xmap;
	prmap_t		md_map;
	char		*md_objname;
	boolean_t	md_last;
	int		md_doswap;
} mapdata_t;

static	mapdata_t	*maps;
static	int		map_count;
static	int		map_alloc;

static	lwpstack_t *stacks = NULL;
static	uint_t	nstacks = 0;

#define	MAX_TRIES	5

static int
getstack(void *data, const lwpstatus_t *lsp)
{
	int *np = (int *)data;

	if (Plwp_alt_stack(Pr, lsp->pr_lwpid, &stacks[*np].lwps_stack) == 0) {
		stacks[*np].lwps_stack.ss_flags |= SS_ONSTACK;
		stacks[*np].lwps_lwpid = lsp->pr_lwpid;
		(*np)++;
	}

	if (Plwp_main_stack(Pr, lsp->pr_lwpid, &stacks[*np].lwps_stack) == 0) {
		stacks[*np].lwps_lwpid = lsp->pr_lwpid;
		(*np)++;
	}

	return (0);
}

int
main(int argc, char **argv)
{
	int rflag = 0, sflag = 0, xflag = 0, Fflag = 0;
	int errflg = 0, Sflag = 0;
	int rc = 0;
	int opt;
	const char *bar8 = "-------";
	const char *bar16 = "----------";
	const char *bar;
	struct rlimit rlim;
	struct stat64 statbuf;
	char buf[PATH_MAX];
	int mapfd;
	int prg_gflags = PGRAB_RDONLY;
	int prr_flags = 0;
	boolean_t use_agent_lwp = B_FALSE;

	if ((command = strrchr(argv[0], '/')) != NULL)
		command++;
	else
		command = argv[0];

	while ((opt = getopt(argc, argv, "arsxSlLFA:")) != EOF) {
		switch (opt) {
		case 'a':		/* include shared mappings in -[xS] */
			aflag = 1;
			break;
		case 'r':		/* show reserved mappings */
			rflag = 1;
			break;
		case 's':		/* show hardware page sizes */
			sflag = 1;
			break;
		case 'S':		/* show swap reservations */
			Sflag = 1;
			break;
		case 'x':		/* show extended mappings */
			xflag = 1;
			break;
		case 'l':		/* show unresolved link map names */
			lflag = 1;
			break;
		case 'L':		/* show lgroup information */
			Lflag = 1;
			use_agent_lwp = B_TRUE;
			break;
		case 'F':		/* force grabbing (no O_EXCL) */
			Fflag = PGRAB_FORCE;
			break;
		case 'A':
			if (parse_addr_range(optarg, &start_addr, &end_addr)
			    != 0)
				errflg++;
			break;
		default:
			errflg = 1;
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if ((Sflag && (xflag || rflag || sflag)) || (xflag && rflag) ||
	    (aflag && (!xflag && !Sflag)) ||
	    (Lflag && (xflag || Sflag))) {
		errflg = 1;
	}

	if (errflg || argc <= 0) {
		(void) fprintf(stderr,
		    "usage:\t%s [-rslF] [-A start[,end]] { pid | core } ...\n",
		    command);
		(void) fprintf(stderr,
		    "\t\t(report process address maps)\n");
		(void) fprintf(stderr,
		    "\t%s -L [-rslF] [-A start[,end]] pid ...\n", command);
		(void) fprintf(stderr,
		    "\t\t(report process address maps lgroups mappings)\n");
		(void) fprintf(stderr,
		    "\t%s -x [-aslF] [-A start[,end]] pid ...\n", command);
		(void) fprintf(stderr,
		    "\t\t(show resident/anon/locked mapping details)\n");
		(void) fprintf(stderr,
		    "\t%s -S [-alF] [-A start[,end]] { pid | core } ...\n",
		    command);
		(void) fprintf(stderr,
		    "\t\t(show swap reservations)\n\n");
		(void) fprintf(stderr,
		    "\t-a: include shared mappings in -[xS] summary\n");
		(void) fprintf(stderr,
		    "\t-r: show reserved address maps\n");
		(void) fprintf(stderr,
		    "\t-s: show hardware page sizes\n");
		(void) fprintf(stderr,
		    "\t-l: show unresolved dynamic linker map names\n");
		(void) fprintf(stderr,
		    "\t-F: force grabbing of the target process\n");
		(void) fprintf(stderr,
		    "\t-L: show lgroup mappings\n");
		(void) fprintf(stderr,
		    "\t-A start,end: limit output to the specified range\n");
		return (2);
	}

	/*
	 * Make sure we'll have enough file descriptors to handle a target
	 * that has many many mappings.
	 */
	if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
		rlim.rlim_cur = rlim.rlim_max;
		(void) setrlimit(RLIMIT_NOFILE, &rlim);
		(void) enable_extended_FILE_stdio(-1, -1);
	}

	/*
	 * The implementation of -L option creates an agent LWP in the target
	 * process address space. The agent LWP issues meminfo(2) system calls
	 * on behalf of the target process. If we are interrupted prematurely,
	 * the target process remains in the stopped state with the agent still
	 * attached to it. To prevent such situation we catch signals from
	 * terminal and terminate gracefully.
	 */
	if (use_agent_lwp) {
		/*
		 * Buffer output to stdout, stderr while process is grabbed.
		 * Prevents infamous deadlocks due to pmap `pgrep xterm` and
		 * other variants.
		 */
		(void) proc_initstdio();

		prg_gflags = PGRAB_RETAIN | Fflag;
		prr_flags = PRELEASE_RETAIN;

		if (sigset(SIGHUP, SIG_IGN) == SIG_DFL)
			(void) sigset(SIGHUP, intr);
		if (sigset(SIGINT, SIG_IGN) == SIG_DFL)
			(void) sigset(SIGINT, intr);
		if (sigset(SIGQUIT, SIG_IGN) == SIG_DFL)
			(void) sigset(SIGQUIT, intr);
		(void) sigset(SIGPIPE, intr);
		(void) sigset(SIGTERM, intr);
	}

	while (argc-- > 0) {
		char *arg;
		int gcode;
		psinfo_t psinfo;
		int tries = 0;

		if (use_agent_lwp)
			(void) proc_flushstdio();

		if ((Pr = proc_arg_grab(arg = *argv++, PR_ARG_ANY,
		    prg_gflags, &gcode)) == NULL) {
			(void) fprintf(stderr, "%s: cannot examine %s: %s\n",
			    command, arg, Pgrab_error(gcode));
			rc++;
			continue;
		}

		procname = arg;		/* for perr() */

		addr_width = (Pstatus(Pr)->pr_dmodel == PR_MODEL_LP64) ? 16 : 8;
		size_width = (Pstatus(Pr)->pr_dmodel == PR_MODEL_LP64) ? 11 : 8;
		bar = addr_width == 8 ? bar8 : bar16;
		(void) memcpy(&psinfo, Ppsinfo(Pr), sizeof (psinfo_t));
		proc_unctrl_psinfo(&psinfo);

		if (Pstate(Pr) != PS_DEAD) {
			(void) proc_snprintf(buf, sizeof (buf),
			    "/proc/%d/map", (int)psinfo.pr_pid);
			if ((mapfd = open(buf, O_RDONLY)) < 0) {
				(void) fprintf(stderr, "%s: cannot "
				    "examine %s: lost control of "
				    "process\n", command, arg);
				rc++;
				Prelease(Pr, prr_flags);
				continue;
			}
		} else {
			mapfd = -1;
		}

again:
		map_count = 0;

		if (Pstate(Pr) == PS_DEAD) {
			(void) printf("core '%s' of %d:\t%.70s\n",
			    arg, (int)psinfo.pr_pid, psinfo.pr_psargs);

			if (rflag || sflag || xflag || Sflag || Lflag) {
				(void) printf("  -%c option is not compatible "
				    "with core files\n", xflag ? 'x' :
				    sflag ? 's' : rflag ? 'r' :
				    Lflag ? 'L' : 'S');
				Prelease(Pr, prr_flags);
				rc++;
				continue;
			}

		} else {
			(void) printf("%d:\t%.70s\n",
			    (int)psinfo.pr_pid, psinfo.pr_psargs);
		}

		if (!(Pstatus(Pr)->pr_flags & PR_ISSYS)) {
			struct totals t;

			/*
			 * Since we're grabbing the process readonly, we need
			 * to make sure the address space doesn't change during
			 * execution.
			 */
			if (Pstate(Pr) != PS_DEAD) {
				if (tries++ == MAX_TRIES) {
					Prelease(Pr, prr_flags);
					(void) close(mapfd);
					(void) fprintf(stderr, "%s: cannot "
					    "examine %s: address space is "
					    "changing\n", command, arg);
					continue;
				}

				if (fstat64(mapfd, &statbuf) != 0) {
					Prelease(Pr, prr_flags);
					(void) close(mapfd);
					(void) fprintf(stderr, "%s: cannot "
					    "examine %s: lost control of "
					    "process\n", command, arg);
					continue;
				}
			}

			nstacks = psinfo.pr_nlwp * 2;
			stacks = calloc(nstacks, sizeof (stacks[0]));
			if (stacks != NULL) {
				int n = 0;
				(void) Plwp_iter(Pr, getstack, &n);
				qsort(stacks, nstacks, sizeof (stacks[0]),
				    cmpstacks);
			}

			(void) memset(&t, 0, sizeof (t));

			if (Pgetauxval(Pr, AT_BASE) != -1L &&
			    Prd_agent(Pr) == NULL) {
				(void) fprintf(stderr, "%s: warning: "
				    "librtld_db failed to initialize; "
				    "shared library information will not be "
				    "available\n", command);
			}

			/*
			 * Gather data
			 */
			if (xflag)
				rc += xmapping_iter(Pr, gather_xmap, NULL, 0);
			else if (Sflag)
				rc += xmapping_iter(Pr, gather_xmap, NULL, 1);
			else {
				if (rflag)
					rc += rmapping_iter(Pr, gather_map,
					    NULL);
				else if (sflag)
					rc += xmapping_iter(Pr, gather_xmap,
					    NULL, 0);
				else if (lflag)
					rc += Pmapping_iter(Pr,
					    gather_map, NULL);
				else
					rc += Pmapping_iter_resolved(Pr,
					    gather_map, NULL);
			}

			/*
			 * Ensure mappings are consistent.
			 */
			if (Pstate(Pr) != PS_DEAD) {
				struct stat64 newbuf;

				if (fstat64(mapfd, &newbuf) != 0 ||
				    memcmp(&newbuf.st_mtim, &statbuf.st_mtim,
				    sizeof (newbuf.st_mtim)) != 0) {
					if (stacks != NULL) {
						free(stacks);
						stacks = NULL;
					}
					goto again;
				}
			}

			/*
			 * Display data.
			 */
			if (xflag) {
				(void) printf("%*s%*s%*s%*s%*s "
				    "%sMode   Mapped File\n",
				    addr_width, "Address",
				    size_width, "Kbytes",
				    size_width, "RSS",
				    size_width, "Anon",
				    size_width, "Locked",
				    sflag ? "Pgsz " : "");

				rc += iter_xmap(sflag ?  look_xmap :
				    look_xmap_nopgsz, &t);

				(void) printf("%s%s %s %s %s %s\n",
				    addr_width == 8 ? "-" : "------",
				    bar, bar, bar, bar, bar);

				(void) printf("%stotal Kb", addr_width == 16 ?
				    "        " : "");

				printK(t.total_size, size_width);
				printK(t.total_rss, size_width);
				printK(t.total_anon, size_width);
				printK(t.total_locked, size_width);

				(void) printf("\n");

			} else if (Sflag) {
				(void) printf("%*s%*s%*s Mode"
				    " Mapped File\n",
				    addr_width, "Address",
				    size_width, "Kbytes",
				    size_width, "Swap");

				rc += iter_xmap(look_xmap_nopgsz, &t);

				(void) printf("%s%s %s %s\n",
				    addr_width == 8 ? "-" : "------",
				    bar, bar, bar);

				(void) printf("%stotal Kb", addr_width == 16 ?
				    "        " : "");

				printK(t.total_size, size_width);
				printK(t.total_swap, size_width);

				(void) printf("\n");

			} else {

				if (rflag) {
					rc += iter_map(look_map, &t);
				} else if (sflag) {
					if (Lflag) {
						(void) printf("%*s %*s %4s"
						    " %-6s %s %s\n",
						    addr_width, "Address",
						    size_width,
						    "Bytes", "Pgsz", "Mode ",
						    "Lgrp", "Mapped File");
						rc += iter_xmap(look_smap, &t);
					} else {
						(void) printf("%*s %*s %4s"
						    " %-6s %s\n",
						    addr_width, "Address",
						    size_width,
						    "Bytes", "Pgsz", "Mode ",
						    "Mapped File");
						rc += iter_xmap(look_smap, &t);
					}
				} else {
					rc += iter_map(look_map, &t);
				}

				(void) printf(" %stotal  %*luK\n",
				    addr_width == 16 ?
				    "        " : "",
				    size_width, t.total_size);
			}

			if (stacks != NULL) {
				free(stacks);
				stacks = NULL;
			}

		}

		Prelease(Pr, prr_flags);
		if (mapfd != -1)
			(void) close(mapfd);
	}

	if (use_agent_lwp)
		(void) proc_finistdio();

	return (rc);
}

static int
rmapping_iter(struct ps_prochandle *Pr, proc_map_f *func, void *cd)
{
	char mapname[PATH_MAX];
	int mapfd, nmap, i, rc;
	struct stat st;
	prmap_t *prmapp, *pmp;
	ssize_t n;

	(void) proc_snprintf(mapname, sizeof (mapname),
	    "/proc/%d/rmap", (int)Pstatus(Pr)->pr_pid);

	if ((mapfd = open(mapname, O_RDONLY)) < 0 || fstat(mapfd, &st) != 0) {
		if (mapfd >= 0)
			(void) close(mapfd);
		return (perr(mapname));
	}

	nmap = st.st_size / sizeof (prmap_t);
	prmapp = malloc((nmap + 1) * sizeof (prmap_t));

	if ((n = pread(mapfd, prmapp, (nmap + 1) * sizeof (prmap_t), 0L)) < 0) {
		(void) close(mapfd);
		free(prmapp);
		return (perr("read rmap"));
	}

	(void) close(mapfd);
	nmap = n / sizeof (prmap_t);

	for (i = 0, pmp = prmapp; i < nmap; i++, pmp++) {
		if ((rc = func(cd, pmp, NULL)) != 0) {
			free(prmapp);
			return (rc);
		}
	}

	free(prmapp);
	return (0);
}

static int
xmapping_iter(struct ps_prochandle *Pr, proc_xmap_f *func, void *cd, int doswap)
{
	char mapname[PATH_MAX];
	int mapfd, nmap, i, rc;
	struct stat st;
	prxmap_t *prmapp, *pmp;
	ssize_t n;

	(void) proc_snprintf(mapname, sizeof (mapname),
	    "/proc/%d/xmap", (int)Pstatus(Pr)->pr_pid);

	if ((mapfd = open(mapname, O_RDONLY)) < 0 || fstat(mapfd, &st) != 0) {
		if (mapfd >= 0)
			(void) close(mapfd);
		return (perr(mapname));
	}

	nmap = st.st_size / sizeof (prxmap_t);
	nmap *= 2;
again:
	prmapp = malloc((nmap + 1) * sizeof (prxmap_t));

	if ((n = pread(mapfd, prmapp, (nmap + 1) * sizeof (prxmap_t), 0)) < 0) {
		(void) close(mapfd);
		free(prmapp);
		return (perr("read xmap"));
	}

	if (nmap < n / sizeof (prxmap_t)) {
		free(prmapp);
		nmap *= 2;
		goto again;
	}

	(void) close(mapfd);
	nmap = n / sizeof (prxmap_t);

	for (i = 0, pmp = prmapp; i < nmap; i++, pmp++) {
		if ((rc = func(cd, pmp, NULL, i == nmap - 1, doswap)) != 0) {
			free(prmapp);
			return (rc);
		}
	}

	/*
	 * Mark the last element.
	 */
	if (map_count > 0)
		maps[map_count - 1].md_last = B_TRUE;

	free(prmapp);
	return (0);
}

/*ARGSUSED*/
static int
look_map(void *data, const prmap_t *pmp, const char *object_name)
{
	struct totals *t = data;
	const pstatus_t *Psp = Pstatus(Pr);
	size_t size;
	char mname[PATH_MAX];
	char *lname = NULL;
	size_t	psz = pmp->pr_pagesize;
	uintptr_t vaddr = pmp->pr_vaddr;
	uintptr_t segment_end = vaddr + pmp->pr_size;
	lgrp_id_t lgrp;
	memory_chunk_t mchunk;

	/*
	 * If the mapping is not anon or not part of the heap, make a name
	 * for it.  We don't want to report the heap as a.out's data.
	 */
	if (!(pmp->pr_mflags & MA_ANON) ||
	    segment_end <= Psp->pr_brkbase ||
	    pmp->pr_vaddr >= Psp->pr_brkbase + Psp->pr_brksize) {
		lname = make_name(Pr, lflag, pmp->pr_vaddr, pmp->pr_mapname,
		    mname, sizeof (mname));
	}

	if (lname == NULL &&
	    ((pmp->pr_mflags & MA_ANON) || Pstate(Pr) == PS_DEAD)) {
		lname = anon_name(mname, Psp, stacks, nstacks, pmp->pr_vaddr,
		    pmp->pr_size, pmp->pr_mflags, pmp->pr_shmid, NULL);
	}

	/*
	 * Adjust the address range if -A is specified.
	 */
	size = adjust_addr_range(pmp->pr_vaddr, segment_end, psz,
	    &vaddr, &segment_end);

	if (size == 0)
		return (0);

	if (!Lflag) {
		/*
		 * Display the whole mapping
		 */
		size = ROUNDUP_KB(size);

		(void) printf(lname ?
		    "%.*lX %*luK %-6s %s\n" :
		    "%.*lX %*luK %s\n",
		    addr_width, vaddr,
		    size_width - 1, size, mflags(pmp->pr_mflags), lname);

		t->total_size += size;
		return (0);
	}

	/*
	 * We need to display lgroups backing physical memory, so we break the
	 * segment into individual pages and coalesce pages with the same lgroup
	 * into one "segment".
	 */

	/*
	 * Initialize address descriptions for the mapping.
	 */
	mem_chunk_init(&mchunk, segment_end, psz);
	size = 0;

	/*
	 * Walk mapping (page by page) and display contiguous ranges of memory
	 * allocated to same lgroup.
	 */
	do {
		size_t		size_contig;

		/*
		 * Get contiguous region of memory starting from vaddr allocated
		 * from the same lgroup.
		 */
		size_contig = get_contiguous_region(&mchunk, vaddr,
		    segment_end, pmp->pr_pagesize, &lgrp);

		(void) printf(lname ? "%.*lX %*luK %-6s%s %s\n" :
		    "%.*lX %*luK %s %s\n",
		    addr_width, vaddr,
		    size_width - 1, size_contig / KILOBYTE,
		    mflags(pmp->pr_mflags),
		    lgrp2str(lgrp), lname);

		vaddr += size_contig;
		size += size_contig;
	} while (vaddr < segment_end && !interrupt);

	/* Update the total size */
	t->total_size += ROUNDUP_KB(size);
	return (0);
}

static void
printK(long value, int width)
{
	if (value == 0)
		(void) printf(width == 8 ? "       -" : "          -");
	else
		(void) printf(" %*lu", width - 1, value);
}

static const char *
pagesize(const prxmap_t *pmp)
{
	int pagesize = pmp->pr_hatpagesize;
	static char buf[32];

	if (pagesize == 0) {
		return ("-"); /* no underlying HAT mapping */
	}

	if (pagesize >= KILOBYTE && (pagesize % KILOBYTE) == 0) {
		if ((pagesize % GIGABYTE) == 0)
			(void) snprintf(buf, sizeof (buf), "%dG",
			    pagesize / GIGABYTE);
		else if ((pagesize % MEGABYTE) == 0)
			(void) snprintf(buf, sizeof (buf), "%dM",
			    pagesize / MEGABYTE);
		else
			(void) snprintf(buf, sizeof (buf), "%dK",
			    pagesize / KILOBYTE);
	} else
		(void) snprintf(buf, sizeof (buf), "%db", pagesize);

	return (buf);
}

/*ARGSUSED*/
static int
look_smap(void *data,
	const prxmap_t *pmp,
	const char *object_name,
	int last, int doswap)
{
	struct totals *t = data;
	const pstatus_t *Psp = Pstatus(Pr);
	size_t size;
	char mname[PATH_MAX];
	char *lname = NULL;
	const char *format;
	size_t	psz = pmp->pr_pagesize;
	uintptr_t vaddr = pmp->pr_vaddr;
	uintptr_t segment_end = vaddr + pmp->pr_size;
	lgrp_id_t lgrp;
	memory_chunk_t mchunk;

	/*
	 * If the mapping is not anon or not part of the heap, make a name
	 * for it.  We don't want to report the heap as a.out's data.
	 */
	if (!(pmp->pr_mflags & MA_ANON) ||
	    pmp->pr_vaddr + pmp->pr_size <= Psp->pr_brkbase ||
	    pmp->pr_vaddr >= Psp->pr_brkbase + Psp->pr_brksize) {
		lname = make_name(Pr, lflag, pmp->pr_vaddr, pmp->pr_mapname,
		    mname, sizeof (mname));
	}

	if (lname == NULL &&
	    ((pmp->pr_mflags & MA_ANON) || Pstate(Pr) == PS_DEAD)) {
		lname = anon_name(mname, Psp, stacks, nstacks, pmp->pr_vaddr,
		    pmp->pr_size, pmp->pr_mflags, pmp->pr_shmid, NULL);
	}

	/*
	 * Adjust the address range if -A is specified.
	 */
	size = adjust_addr_range(pmp->pr_vaddr, segment_end, psz,
	    &vaddr, &segment_end);

	if (size == 0)
		return (0);

	if (!Lflag) {
		/*
		 * Display the whole mapping
		 */
		if (lname != NULL)
			format = "%.*lX %*luK %4s %-6s %s\n";
		else
			format = "%.*lX %*luK %4s %s\n";

		size = ROUNDUP_KB(size);

		(void) printf(format, addr_width, vaddr, size_width - 1, size,
		    pagesize(pmp), mflags(pmp->pr_mflags), lname);

		t->total_size += size;
		return (0);
	}

	if (lname != NULL)
		format = "%.*lX %*luK %4s %-6s%s %s\n";
	else
		format = "%.*lX %*luK %4s%s %s\n";

	/*
	 * We need to display lgroups backing physical memory, so we break the
	 * segment into individual pages and coalesce pages with the same lgroup
	 * into one "segment".
	 */

	/*
	 * Initialize address descriptions for the mapping.
	 */
	mem_chunk_init(&mchunk, segment_end, psz);
	size = 0;

	/*
	 * Walk mapping (page by page) and display contiguous ranges of memory
	 * allocated to same lgroup.
	 */
	do {
		size_t		size_contig;

		/*
		 * Get contiguous region of memory starting from vaddr allocated
		 * from the same lgroup.
		 */
		size_contig = get_contiguous_region(&mchunk, vaddr,
		    segment_end, pmp->pr_pagesize, &lgrp);

		(void) printf(format, addr_width, vaddr,
		    size_width - 1, size_contig / KILOBYTE,
		    pagesize(pmp), mflags(pmp->pr_mflags),
		    lgrp2str(lgrp), lname);

		vaddr += size_contig;
		size += size_contig;
	} while (vaddr < segment_end && !interrupt);

	t->total_size += ROUNDUP_KB(size);
	return (0);
}

#define	ANON(x)	((aflag || (((x)->pr_mflags & MA_SHARED) == 0)) ? \
	    ((x)->pr_anon) : 0)

/*ARGSUSED*/
static int
look_xmap(void *data,
	const prxmap_t *pmp,
	const char *object_name,
	int last, int doswap)
{
	struct totals *t = data;
	const pstatus_t *Psp = Pstatus(Pr);
	char mname[PATH_MAX];
	char *lname = NULL;
	char *ln;

	/*
	 * If the mapping is not anon or not part of the heap, make a name
	 * for it.  We don't want to report the heap as a.out's data.
	 */
	if (!(pmp->pr_mflags & MA_ANON) ||
	    pmp->pr_vaddr + pmp->pr_size <= Psp->pr_brkbase ||
	    pmp->pr_vaddr >= Psp->pr_brkbase + Psp->pr_brksize) {
		lname = make_name(Pr, lflag, pmp->pr_vaddr, pmp->pr_mapname,
		    mname, sizeof (mname));
	}

	if (lname != NULL) {
		if ((ln = strrchr(lname, '/')) != NULL)
			lname = ln + 1;
	} else if ((pmp->pr_mflags & MA_ANON) || Pstate(Pr) == PS_DEAD) {
		lname = anon_name(mname, Psp, stacks, nstacks, pmp->pr_vaddr,
		    pmp->pr_size, pmp->pr_mflags, pmp->pr_shmid, NULL);
	}

	(void) printf("%.*lX", addr_width, (ulong_t)pmp->pr_vaddr);

	printK(ROUNDUP_KB(pmp->pr_size), size_width);
	printK(pmp->pr_rss * (pmp->pr_pagesize / KILOBYTE), size_width);
	printK(ANON(pmp) * (pmp->pr_pagesize / KILOBYTE), size_width);
	printK(pmp->pr_locked * (pmp->pr_pagesize / KILOBYTE), size_width);
	(void) printf(lname ? " %4s %-6s %s\n" : " %4s %s\n",
	    pagesize(pmp), mflags(pmp->pr_mflags), lname);

	t->total_size += ROUNDUP_KB(pmp->pr_size);
	t->total_rss += pmp->pr_rss * (pmp->pr_pagesize / KILOBYTE);
	t->total_anon += ANON(pmp) * (pmp->pr_pagesize / KILOBYTE);
	t->total_locked += (pmp->pr_locked * (pmp->pr_pagesize / KILOBYTE));

	return (0);
}

/*ARGSUSED*/
static int
look_xmap_nopgsz(void *data,
	const prxmap_t *pmp,
	const char *object_name,
	int last, int doswap)
{
	struct totals *t = data;
	const pstatus_t *Psp = Pstatus(Pr);
	char mname[PATH_MAX];
	char *lname = NULL;
	char *ln;
	static uintptr_t prev_vaddr;
	static size_t prev_size;
	static offset_t prev_offset;
	static int prev_mflags;
	static char *prev_lname;
	static char prev_mname[PATH_MAX];
	static ulong_t prev_rss;
	static ulong_t prev_anon;
	static ulong_t prev_locked;
	static ulong_t prev_swap;
	int merged = 0;
	static int first = 1;
	ulong_t swap = 0;
	int kperpage;

	/*
	 * Calculate swap reservations
	 */
	if (pmp->pr_mflags & MA_SHARED) {
		if (aflag && (pmp->pr_mflags & MA_NORESERVE) == 0) {
			/* Swap reserved for entire non-ism SHM */
			swap = pmp->pr_size / pmp->pr_pagesize;
		}
	} else if (pmp->pr_mflags & MA_NORESERVE) {
		/* Swap reserved on fault for each anon page */
		swap = pmp->pr_anon;
	} else if (pmp->pr_mflags & MA_WRITE) {
		/* Swap reserve for entire writable segment */
		swap = pmp->pr_size / pmp->pr_pagesize;
	}

	/*
	 * If the mapping is not anon or not part of the heap, make a name
	 * for it.  We don't want to report the heap as a.out's data.
	 */
	if (!(pmp->pr_mflags & MA_ANON) ||
	    pmp->pr_vaddr + pmp->pr_size <= Psp->pr_brkbase ||
	    pmp->pr_vaddr >= Psp->pr_brkbase + Psp->pr_brksize) {
		lname = make_name(Pr, lflag, pmp->pr_vaddr, pmp->pr_mapname,
		    mname, sizeof (mname));
	}

	if (lname != NULL) {
		if ((ln = strrchr(lname, '/')) != NULL)
			lname = ln + 1;
	} else if ((pmp->pr_mflags & MA_ANON) || Pstate(Pr) == PS_DEAD) {
		lname = anon_name(mname, Psp, stacks, nstacks, pmp->pr_vaddr,
		    pmp->pr_size, pmp->pr_mflags, pmp->pr_shmid, NULL);
	}

	kperpage = pmp->pr_pagesize / KILOBYTE;

	t->total_size += ROUNDUP_KB(pmp->pr_size);
	t->total_rss += pmp->pr_rss * kperpage;
	t->total_anon += ANON(pmp) * kperpage;
	t->total_locked += pmp->pr_locked * kperpage;
	t->total_swap += swap * kperpage;

	if (first == 1) {
		first = 0;
		prev_vaddr = pmp->pr_vaddr;
		prev_size = pmp->pr_size;
		prev_offset = pmp->pr_offset;
		prev_mflags = pmp->pr_mflags;
		if (lname == NULL) {
			prev_lname = NULL;
		} else {
			(void) strcpy(prev_mname, lname);
			prev_lname = prev_mname;
		}
		prev_rss = pmp->pr_rss * kperpage;
		prev_anon = ANON(pmp) * kperpage;
		prev_locked = pmp->pr_locked * kperpage;
		prev_swap = swap * kperpage;
		if (last == 0) {
			return (0);
		}
		merged = 1;
	} else if (prev_vaddr + prev_size == pmp->pr_vaddr &&
	    prev_mflags == pmp->pr_mflags &&
	    ((prev_mflags & MA_ISM) ||
	    prev_offset + prev_size == pmp->pr_offset) &&
	    ((lname == NULL && prev_lname == NULL) ||
	    (lname != NULL && prev_lname != NULL &&
	    strcmp(lname, prev_lname) == 0))) {
		prev_size += pmp->pr_size;
		prev_rss += pmp->pr_rss * kperpage;
		prev_anon += ANON(pmp) * kperpage;
		prev_locked += pmp->pr_locked * kperpage;
		prev_swap += swap * kperpage;
		if (last == 0) {
			return (0);
		}
		merged = 1;
	}

	(void) printf("%.*lX", addr_width, (ulong_t)prev_vaddr);
	printK(ROUNDUP_KB(prev_size), size_width);

	if (doswap)
		printK(prev_swap, size_width);
	else {
		printK(prev_rss, size_width);
		printK(prev_anon, size_width);
		printK(prev_locked, size_width);
	}
	(void) printf(prev_lname ? " %-6s %s\n" : "%s\n",
	    mflags(prev_mflags), prev_lname);

	if (last == 0) {
		prev_vaddr = pmp->pr_vaddr;
		prev_size = pmp->pr_size;
		prev_offset = pmp->pr_offset;
		prev_mflags = pmp->pr_mflags;
		if (lname == NULL) {
			prev_lname = NULL;
		} else {
			(void) strcpy(prev_mname, lname);
			prev_lname = prev_mname;
		}
		prev_rss = pmp->pr_rss * kperpage;
		prev_anon = ANON(pmp) * kperpage;
		prev_locked = pmp->pr_locked * kperpage;
		prev_swap = swap * kperpage;
	} else if (merged == 0) {
		(void) printf("%.*lX", addr_width, (ulong_t)pmp->pr_vaddr);
		printK(ROUNDUP_KB(pmp->pr_size), size_width);
		if (doswap)
			printK(swap * kperpage, size_width);
		else {
			printK(pmp->pr_rss * kperpage, size_width);
			printK(ANON(pmp) * kperpage, size_width);
			printK(pmp->pr_locked * kperpage, size_width);
		}
		(void) printf(lname ? " %-6s %s\n" : " %s\n",
		    mflags(pmp->pr_mflags), lname);
	}

	if (last != 0)
		first = 1;

	return (0);
}

static int
perr(char *s)
{
	if (s)
		(void) fprintf(stderr, "%s: ", procname);
	else
		s = procname;
	perror(s);
	return (1);
}

static char *
mflags(uint_t arg)
{
	static char code_buf[80];
	char *str = code_buf;

	/*
	 * rwxsR
	 *
	 * r - segment is readable
	 * w - segment is writable
	 * x - segment is executable
	 * s - segment is shared
	 * R - segment is mapped MAP_NORESERVE
	 *
	 */
	(void) sprintf(str, "%c%c%c%c%c%c",
	    arg & MA_READ ? 'r' : '-',
	    arg & MA_WRITE ? 'w' : '-',
	    arg & MA_EXEC ? 'x' : '-',
	    arg & MA_SHARED ? 's' : '-',
	    arg & MA_NORESERVE ? 'R' : '-',
	    arg & MA_RESERVED1 ? '*' : ' ');

	return (str);
}

static mapdata_t *
nextmap(void)
{
	mapdata_t *newmaps;
	int next;

	if (map_count == map_alloc) {
		if (map_alloc == 0)
			next = 16;
		else
			next = map_alloc * 2;

		newmaps = realloc(maps, next * sizeof (mapdata_t));
		if (newmaps == NULL) {
			(void) perr("failed to allocate maps");
			exit(1);
		}
		(void) memset(newmaps + map_alloc, '\0',
		    (next - map_alloc) * sizeof (mapdata_t));

		map_alloc = next;
		maps = newmaps;
	}

	return (&maps[map_count++]);
}

/*ARGSUSED*/
static int
gather_map(void *ignored, const prmap_t *map, const char *objname)
{
	mapdata_t *data;

	/* Skip mappings which are outside the range specified by -A */
	if (!address_in_range(map->pr_vaddr,
	    map->pr_vaddr + map->pr_size, map->pr_pagesize))
		return (0);

	data = nextmap();
	data->md_map = *map;
	if (data->md_objname != NULL)
		free(data->md_objname);
	data->md_objname = objname ? strdup(objname) : NULL;

	return (0);
}

/*ARGSUSED*/
static int
gather_xmap(void *ignored, const prxmap_t *xmap, const char *objname,
    int last, int doswap)
{
	mapdata_t *data;

	/* Skip mappings which are outside the range specified by -A */
	if (!address_in_range(xmap->pr_vaddr,
	    xmap->pr_vaddr + xmap->pr_size, xmap->pr_pagesize))
		return (0);

	data = nextmap();
	data->md_xmap = *xmap;
	if (data->md_objname != NULL)
		free(data->md_objname);
	data->md_objname = objname ? strdup(objname) : NULL;
	data->md_last = last;
	data->md_doswap = doswap;

	return (0);
}

static int
iter_map(proc_map_f *func, void *data)
{
	int i;
	int ret;

	for (i = 0; i < map_count; i++) {
		if (interrupt)
			break;
		if ((ret = func(data, &maps[i].md_map,
		    maps[i].md_objname)) != 0)
			return (ret);
	}

	return (0);
}

static int
iter_xmap(proc_xmap_f *func, void *data)
{
	int i;
	int ret;

	for (i = 0; i < map_count; i++) {
		if (interrupt)
			break;
		if ((ret = func(data, &maps[i].md_xmap, maps[i].md_objname,
		    maps[i].md_last, maps[i].md_doswap)) != 0)
			return (ret);
	}

	return (0);
}

/*
 * Convert lgroup ID to string.
 * returns dash when lgroup ID is invalid.
 */
static char *
lgrp2str(lgrp_id_t lgrp)
{
	static char lgrp_buf[20];
	char *str = lgrp_buf;

	(void) sprintf(str, lgrp == LGRP_NONE ? "   -" : "%4d", lgrp);
	return (str);
}

/*
 * Parse address range specification for -A option.
 * The address range may have the following forms:
 *
 * address
 *	start and end is set to address
 * address,
 *	start is set to address, end is set to INVALID_ADDRESS
 * ,address
 *	start is set to 0, end is set to address
 * address1,address2
 *	start is set to address1, end is set to address2
 *
 */
static int
parse_addr_range(char *input_str, uintptr_t *start, uintptr_t *end)
{
	char *startp = input_str;
	char *endp = strchr(input_str, ',');
	ulong_t	s = (ulong_t)INVALID_ADDRESS;
	ulong_t e = (ulong_t)INVALID_ADDRESS;

	if (endp != NULL) {
		/*
		 * Comma is present. If there is nothing after comma, the end
		 * remains set at INVALID_ADDRESS. Otherwise it is set to the
		 * value after comma.
		 */
		*endp = '\0';
		endp++;

		if ((*endp != '\0') && sscanf(endp, "%lx", &e) != 1)
			return (1);
	}

	if (startp != NULL) {
		/*
		 * Read the start address, if it is specified. If the address is
		 * missing, start will be set to INVALID_ADDRESS.
		 */
		if ((*startp != '\0') && sscanf(startp, "%lx", &s) != 1)
			return (1);
	}

	/* If there is no comma, end becomes equal to start */
	if (endp == NULL)
		e = s;

	/*
	 * ,end implies 0..end range
	 */
	if (e != INVALID_ADDRESS && s == INVALID_ADDRESS)
		s = 0;

	*start = (uintptr_t)s;
	*end = (uintptr_t)e;

	/* Return error if neither start nor end address were specified */
	return (! (s != INVALID_ADDRESS || e != INVALID_ADDRESS));
}

/*
 * Check whether any portion of [start, end] segment is within the
 * [start_addr, end_addr] range.
 *
 * Return values:
 *   0 - address is outside the range
 *   1 - address is within the range
 */
static int
address_in_range(uintptr_t start, uintptr_t end, size_t psz)
{
	int rc = 1;

	/*
	 *  Nothing to do if there is no address range specified with -A
	 */
	if (start_addr != INVALID_ADDRESS || end_addr != INVALID_ADDRESS) {
		/* The segment end is below the range start */
		if ((start_addr != INVALID_ADDRESS) &&
		    (end < P2ALIGN(start_addr, psz)))
			rc = 0;

		/* The segment start is above the range end */
		if ((end_addr != INVALID_ADDRESS) &&
		    (start > P2ALIGN(end_addr + psz, psz)))
			rc = 0;
	}
	return (rc);
}

/*
 * Returns an intersection of the [start, end] interval and the range specified
 * by -A flag [start_addr, end_addr]. Unspecified parts of the address range
 * have value INVALID_ADDRESS.
 *
 * The start_addr address is rounded down to the beginning of page and end_addr
 * is rounded up to the end of page.
 *
 * Returns the size of the resulting interval or zero if the interval is empty
 * or invalid.
 */
static size_t
adjust_addr_range(uintptr_t start, uintptr_t end, size_t psz,
    uintptr_t *new_start, uintptr_t *new_end)
{
	uintptr_t from;		/* start_addr rounded down */
	uintptr_t to;		/* end_addr rounded up */

	/*
	 * Round down the lower address of the range to the beginning of page.
	 */
	if (start_addr == INVALID_ADDRESS) {
		/*
		 * No start_addr specified by -A, the lower part of the interval
		 * does not change.
		 */
		*new_start = start;
	} else {
		from = P2ALIGN(start_addr, psz);
		/*
		 * If end address is outside the range, return an empty
		 * interval
		 */
		if (end <  from) {
			*new_start = *new_end = 0;
			return (0);
		}
		/*
		 * The adjusted start address is the maximum of requested start
		 * and the aligned start_addr of the -A range.
		 */
		*new_start = start < from ? from : start;
	}

	/*
	 * Round up the higher address of the range to the end of page.
	 */
	if (end_addr == INVALID_ADDRESS) {
		/*
		 * No end_addr specified by -A, the upper part of the interval
		 * does not change.
		 */
		*new_end = end;
	} else {
		/*
		 * If only one address is specified and it is the beginning of a
		 * segment, get information about the whole segment. This
		 * function is called once per segment and the 'end' argument is
		 * always the end of a segment, so just use the 'end' value.
		 */
		to = (end_addr == start_addr && start == start_addr) ?
		    end :
		    P2ALIGN(end_addr + psz, psz);
		/*
		 * If start address is outside the range, return an empty
		 * interval
		 */
		if (start > to) {
			*new_start = *new_end = 0;
			return (0);
		}
		/*
		 * The adjusted end address is the minimum of requested end
		 * and the aligned end_addr of the -A range.
		 */
		*new_end = end > to ? to : end;
	}

	/*
	 * Make sure that the resulting interval is legal.
	 */
	if (*new_end < *new_start)
			*new_start = *new_end = 0;

	/* Return the size of the interval */
	return (*new_end - *new_start);
}

/*
 * Initialize memory_info data structure with information about a new segment.
 */
static void
mem_chunk_init(memory_chunk_t *chunk, uintptr_t end, size_t psz)
{
	chunk->end_addr = end;
	chunk->page_size = psz;
	chunk->page_index = 0;
	chunk->chunk_start = chunk->chunk_end = 0;
}

/*
 * Create a new chunk of addresses starting from vaddr.
 * Pass the whole chunk to pr_meminfo to collect lgroup and page size
 * information for each page in the chunk.
 */
static void
mem_chunk_get(memory_chunk_t *chunk, uintptr_t vaddr)
{
	page_descr_t	*pdp = chunk->page_info;
	size_t		psz = chunk->page_size;
	uintptr_t	addr = vaddr;
	uint64_t	inaddr[MAX_MEMINFO_CNT];
	uint64_t	outdata[2 * MAX_MEMINFO_CNT];
	uint_t		info[2] = { MEMINFO_VLGRP, MEMINFO_VPAGESIZE };
	uint_t		validity[MAX_MEMINFO_CNT];
	uint64_t	*dataptr = inaddr;
	uint64_t	*outptr = outdata;
	uint_t		*valptr = validity;
	int 		i, j, rc;

	chunk->chunk_start = vaddr;
	chunk->page_index = 0;	/* reset index for the new chunk */

	/*
	 * Fill in MAX_MEMINFO_CNT wotrh of pages starting from vaddr. Also,
	 * copy starting address of each page to inaddr array for pr_meminfo.
	 */
	for (i = 0, pdp = chunk->page_info;
	    (i < MAX_MEMINFO_CNT) && (addr <= chunk->end_addr);
	    i++, pdp++, dataptr++, addr += psz) {
		*dataptr = (uint64_t)addr;
		pdp->pd_start = addr;
		pdp->pd_lgrp = LGRP_NONE;
		pdp->pd_valid = 0;
		pdp->pd_pagesize = 0;
	}

	/* Mark the number of entries in the chunk and the last address */
	chunk->page_count = i;
	chunk->chunk_end = addr - psz;

	if (interrupt)
		return;

	/* Call meminfo for all collected addresses */
	rc = pr_meminfo(Pr, inaddr, i, info, 2, outdata, validity);
	if (rc < 0) {
		(void) perr("can not get memory information");
		return;
	}

	/* Verify validity of each result and fill in the addrs array */
	pdp = chunk->page_info;
	for (j = 0; j < i; j++, pdp++, valptr++, outptr += 2) {
		/* Skip invalid address pointers */
		if ((*valptr & 1) == 0) {
			continue;
		}

		/* Is lgroup information available? */
		if ((*valptr & 2) != 0) {
			pdp->pd_lgrp = (lgrp_id_t)*outptr;
			pdp->pd_valid = 1;
		}

		/* Is page size informaion available? */
		if ((*valptr & 4) != 0) {
			pdp->pd_pagesize = *(outptr + 1);
		}
	}
}

/*
 * Starting from address 'vaddr' find the region with pages allocated from the
 * same lgroup.
 *
 * Arguments:
 *	mchunk		Initialized memory chunk structure
 *	vaddr		Starting address of the region
 *	maxaddr		Upper bound of the region
 *	pagesize	Default page size to use
 *	ret_lgrp	On exit contains the lgroup ID of all pages in the
 *			region.
 *
 * Returns:
 *	Size of the contiguous region in bytes
 *	The lgroup ID of all pages in the region in ret_lgrp argument.
 */
static size_t
get_contiguous_region(memory_chunk_t *mchunk, uintptr_t vaddr,
    uintptr_t maxaddr, size_t pagesize, lgrp_id_t *ret_lgrp)
{
	size_t		size_contig = 0;
	lgrp_id_t	lgrp;		/* Lgroup of the region start */
	lgrp_id_t	curr_lgrp;	/* Lgroup of the current page */
	size_t		psz = pagesize;	/* Pagesize to use */

	/* Set both lgroup IDs to the lgroup of the first page */
	curr_lgrp = lgrp = addr_to_lgrp(mchunk, vaddr, &psz);

	/*
	 * Starting from vaddr, walk page by page until either the end
	 * of the segment is reached or a page is allocated from a different
	 * lgroup. Also stop if interrupted from keyboard.
	 */
	while ((vaddr < maxaddr) && (curr_lgrp == lgrp) && !interrupt) {
		/*
		 * Get lgroup ID and the page size of the current page.
		 */
		curr_lgrp = addr_to_lgrp(mchunk, vaddr, &psz);
		/* If there is no page size information, use the default */
		if (psz == 0)
			psz = pagesize;

		if (curr_lgrp == lgrp) {
			/*
			 * This page belongs to the contiguous region.
			 * Increase the region size and advance to the new page.
			 */
			size_contig += psz;
			vaddr += psz;
		}
	}

	/* Return the region lgroup ID and the size */
	*ret_lgrp = lgrp;
	return (size_contig);
}

/*
 * Given a virtual address, return its lgroup and page size. If there is meminfo
 * information for an address, use it, otherwise shift the chunk window to the
 * vaddr and create a new chunk with known meminfo information.
 */
static lgrp_id_t
addr_to_lgrp(memory_chunk_t *chunk, uintptr_t vaddr, size_t *psz)
{
	page_descr_t *pdp;
	lgrp_id_t lgrp = LGRP_NONE;
	int i;

	*psz = chunk->page_size;

	if (interrupt)
		return (0);

	/*
	 * Is there information about this address? If not, create a new chunk
	 * starting from vaddr and apply pr_meminfo() to the whole chunk.
	 */
	if (vaddr < chunk->chunk_start || vaddr > chunk->chunk_end) {
		/*
		 * This address is outside the chunk, get the new chunk and
		 * collect meminfo information for it.
		 */
		mem_chunk_get(chunk, vaddr);
	}

	/*
	 * Find information about the address.
	 */
	pdp = &chunk->page_info[chunk->page_index];
	for (i = chunk->page_index; i < chunk->page_count; i++, pdp++) {
		if (pdp->pd_start == vaddr) {
			if (pdp->pd_valid) {
				lgrp = pdp->pd_lgrp;
				/*
				 * Override page size information if it is
				 * present.
				 */
				if (pdp->pd_pagesize > 0)
					*psz = pdp->pd_pagesize;
			}
			break;
		}
	}
	/*
	 * Remember where we ended - the next search will start here.
	 * We can query for the lgrp for the same address again, so do not
	 * advance index past the current value.
	 */
	chunk->page_index = i;

	return (lgrp);
}

/* ARGSUSED */
static void
intr(int sig)
{
	interrupt = 1;
}
