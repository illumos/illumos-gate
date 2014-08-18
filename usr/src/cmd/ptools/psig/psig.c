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
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 */

#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libproc.h>
#include "ptools_common.h"

/* evil knowledge of libc internals */
#include "../../../lib/libc/inc/thr_uberdata.h"

#define	MAX_SYMNAMLEN	1024	/* Recommended max symbol name length */

static	char	*sigflags(int, int);
static	int	look(char *);
static	void	perr(char *);
static	int	usage(void);
static	uintptr_t deinterpose(int, void *, psinfo_t *, struct sigaction *);

static	char	*command;
static	char	*procname;
static	int	all_flag = 0;
static	int	lookuphandlers_flag = 1;

int
main(int argc, char **argv)
{
	int rc = 0;
	int c;
	struct rlimit rlim;

	if ((command = strrchr(argv[0], '/')) != NULL)
		command++;
	else
		command = argv[0];

	while ((c = getopt(argc, argv, "an")) != EOF) {
		switch (c) {
		case 'a':
			all_flag = 1;
			break;
		case 'n':
			lookuphandlers_flag = 0;
			break;
		default:
			return (usage());
		}
	}

	if (argc - optind < 1) {
		return (usage());
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

	for (; optind != argc; optind++) {
		rc += look(argv[optind]);
	}

	return (rc);
}

static int
usage(void)
{
	(void) fprintf(stderr, "usage:\t%s [-n] pid ...\n", command);
	(void) fprintf(stderr, "  (report process signal actions)\n");

	return (2);
}

static uintptr_t
uberdata_addr(struct ps_prochandle *Pr, char dmodel)
{
	GElf_Sym sym;

	if (Plookup_by_name(Pr, "libc.so", "_tdb_bootstrap", &sym) < 0)
		return (NULL);
#ifdef _LP64
	if (dmodel != PR_MODEL_NATIVE) {
		caddr32_t uaddr;
		caddr32_t addr;

		if (Pread(Pr, &addr, sizeof (addr), sym.st_value)
		    == sizeof (addr) &&
		    addr != 0 &&
		    Pread(Pr, &uaddr, sizeof (uaddr), (uintptr_t)addr)
		    == sizeof (uaddr) &&
		    uaddr != 0)
			return ((uintptr_t)uaddr);
	}
#endif
	if (dmodel == PR_MODEL_NATIVE) {
		uintptr_t uaddr;
		uintptr_t addr;

		if (Pread(Pr, &addr, sizeof (addr), sym.st_value)
		    == sizeof (addr) &&
		    addr != 0 &&
		    Pread(Pr, &uaddr, sizeof (uaddr), addr)
		    == sizeof (uaddr) &&
		    uaddr != 0)
			return (uaddr);
	}
	if (Plookup_by_name(Pr, "libc.so", "_uberdata", &sym) < 0)
		return (0);
	return (sym.st_value);
}

/*
 * Iterator function used to generate the process sigmask
 * from the individual lwp sigmasks.
 */
static int
lwp_iter(void *cd, const lwpstatus_t *lwpstatus)
{
	sigset_t *ssp = cd;

	ssp->__sigbits[0] &= lwpstatus->pr_lwphold.__sigbits[0];
	ssp->__sigbits[1] &= lwpstatus->pr_lwphold.__sigbits[1];
	ssp->__sigbits[2] &= lwpstatus->pr_lwphold.__sigbits[2];
	ssp->__sigbits[3] &= lwpstatus->pr_lwphold.__sigbits[3];

	/*
	 * Return non-zero to terminate the iteration
	 * if the sigmask has become all zeros.
	 */
	return ((ssp->__sigbits[0] | ssp->__sigbits[1] |
	    ssp->__sigbits[2] | ssp->__sigbits[3]) == 0);
}

static int
look(char *arg)
{
	char pathname[PATH_MAX];
	struct stat statb;
	int fd = -1;
	int sig, gcode;
	sigset_t holdmask;
	int maxsig;
	struct sigaction *action = NULL;
	psinfo_t psinfo;
	const psinfo_t *psinfop;
	struct ps_prochandle *Pr = NULL;
	uintptr_t uberaddr;
	uintptr_t aharraddr;
	uintptr_t intfnaddr;
	size_t aharrlen;
	void *aharr = NULL;
	int error = 1;

	procname = arg;		/* for perr() */
	if ((Pr = proc_arg_grab(arg, PR_ARG_PIDS, PGRAB_RDONLY|PGRAB_FORCE,
	    &gcode)) == NULL || (psinfop = Ppsinfo(Pr)) == NULL) {
		(void) fprintf(stderr, "%s: cannot examine %s: %s\n",
		    command, arg, Pgrab_error(gcode));
		goto look_error;
	}
	(void) memcpy(&psinfo, psinfop, sizeof (psinfo_t));
	proc_unctrl_psinfo(&psinfo);

	(void) proc_snprintf(pathname, sizeof (pathname), "/proc/%d/sigact",
	    (int)psinfo.pr_pid);
	if ((fd = open(pathname, O_RDONLY)) < 0) {
		perr("open sigact");
		goto look_error;
	}

	if (fstat(fd, &statb) != 0) {
		perr("fstat sigact");
		goto look_error;
	}
	maxsig = statb.st_size / sizeof (struct sigaction);
	action = malloc(maxsig * sizeof (struct sigaction));
	if (action == NULL) {
		(void) fprintf(stderr,
		    "%s: cannot malloc() space for %d sigaction structures\n",
		    command, maxsig);
		goto look_error;
	}
	if (read(fd, (char *)action, maxsig * sizeof (struct sigaction)) !=
	    maxsig * sizeof (struct sigaction)) {
		perr("read sigact");
		goto look_error;
	}
	(void) close(fd);
	fd = -1;

	(void) printf("%d:\t%.70s\n", (int)psinfo.pr_pid, psinfo.pr_psargs);

	(void) sigfillset(&holdmask);
	(void) Plwp_iter(Pr, lwp_iter, &holdmask);

	if ((uberaddr = uberdata_addr(Pr, psinfo.pr_dmodel)) == 0) {
		aharraddr = 0;
		aharrlen = 0;
		intfnaddr = 0;
	} else {
#ifdef _LP64
		if (psinfo.pr_dmodel != PR_MODEL_NATIVE) {
			caddr32_t addr;
			aharraddr = uberaddr +
			    offsetof(uberdata32_t, siguaction);
			aharrlen = sizeof (siguaction32_t) * NSIG;
			(void) Pread(Pr, &addr, sizeof (addr),
			    uberaddr + offsetof(uberdata32_t, sigacthandler));
			intfnaddr = (uintptr_t)addr;
		} else
#endif
		{
			aharraddr = uberaddr +
			    offsetof(uberdata_t, siguaction);
			aharrlen = sizeof (siguaction_t) * NSIG;
			(void) Pread(Pr, &intfnaddr, sizeof (intfnaddr),
			    uberaddr + offsetof(uberdata_t, sigacthandler));
		}
	}

	if (aharraddr) {
		aharr = malloc(aharrlen);
		if (aharr == NULL) {
			(void) fprintf(stderr,
			"%s: cannot malloc() space for actual handler array\n",
			    command);
			goto look_error;
		}

		if (Pread(Pr, aharr, aharrlen, aharraddr) != aharrlen) {
			(void) fprintf(stderr,
			    "%s: signal handler data at %p cannot be read.\n",
			    command, (void *)aharraddr);
			free(aharr);
			aharr = NULL;
		}
	}

	for (sig = 1; sig <= maxsig; sig++) {
		struct sigaction *sp = &action[sig - 1];
		int caught = 0;
		char buf[SIG2STR_MAX];
		char *s;

		/* proc_signame() returns "SIG..."; skip the "SIG" part */
		(void) printf("%s\t", proc_signame(sig, buf, sizeof (buf)) + 3);

		if (prismember(&holdmask, sig))
			(void) printf("blocked,");

		if (sp->sa_handler == SIG_DFL)
			(void) printf("default");
		else if (sp->sa_handler == SIG_IGN)
			(void) printf("ignored");
		else
			caught = 1;

		if (caught || all_flag) {
			uintptr_t haddr;
			GElf_Sym hsym;
			char hname[MAX_SYMNAMLEN];
			char buf[PRSIGBUFSZ];

			haddr = (uintptr_t)sp->sa_handler;

			if (aharr && intfnaddr && haddr == intfnaddr)
				haddr = deinterpose(sig, aharr, &psinfo, sp);

			if (haddr == (uintptr_t)SIG_DFL) {
				if (caught)
					(void) printf("default");
				caught = 0;
			} else if (haddr == (uintptr_t)SIG_IGN) {
				if (caught)
					(void) printf("ignored");
				caught = 0;
			} else {
				if (caught)
					(void) printf("caught");
			}

			if (caught || all_flag) {
				if (lookuphandlers_flag && haddr > 1 &&
				    Plookup_by_addr(Pr, haddr, hname,
				    sizeof (hname), &hsym) == 0)
					(void) printf("\t%-8s", hname);
				else
					(void) printf("\t0x%-8lx",
					    (ulong_t)haddr);

				s = sigflags(sig, sp->sa_flags);
				(void) printf("%s", (*s != '\0')? s : "\t0");
				(void) proc_sigset2str(&sp->sa_mask, ",", 1,
				    buf, sizeof (buf));
				if (buf[0] != '\0')
					(void) printf("\t%s", buf);
			}
		} else if (sig == SIGCLD) {
			s = sigflags(sig,
			    sp->sa_flags & (SA_NOCLDWAIT|SA_NOCLDSTOP));
			if (*s != '\0')
				(void) printf("\t\t%s", s);
		}
		(void) printf("\n");
	}

	error = 0;

look_error:
	if (fd >= 0)
		(void) close(fd);
	if (aharr)
		free(aharr);
	if (action)
		free(action);
	if (Pr)
		Prelease(Pr, 0);
	return (error);
}

static void
perr(char *s)
{
	if (s)
		(void) fprintf(stderr, "%s: ", procname);
	else
		s = procname;
	perror(s);
}

static char *
sigflags(int sig, int flags)
{
	static char code_buf[100];
	char *str = code_buf;
	int flagmask =
	    (SA_ONSTACK|SA_RESETHAND|SA_RESTART|SA_SIGINFO|SA_NODEFER);

	if (sig == SIGCLD)
		flagmask |= (SA_NOCLDSTOP|SA_NOCLDWAIT);

	*str = '\0';
	if (flags & ~flagmask)
		(void) sprintf(str, ",0x%x,", flags & ~flagmask);
	else if (flags == 0)
		return (str);

	if (flags & SA_RESTART)
		(void) strcat(str, ",RESTART");
	if (flags & SA_RESETHAND)
		(void) strcat(str, ",RESETHAND");
	if (flags & SA_ONSTACK)
		(void) strcat(str, ",ONSTACK");
	if (flags & SA_SIGINFO)
		(void) strcat(str, ",SIGINFO");
	if (flags & SA_NODEFER)
		(void) strcat(str, ",NODEFER");

	if (sig == SIGCLD) {
		if (flags & SA_NOCLDWAIT)
			(void) strcat(str, ",NOCLDWAIT");
		if (flags & SA_NOCLDSTOP)
			(void) strcat(str, ",NOCLDSTOP");
	}

	*str = '\t';

	return (str);
}

/*ARGSUSED2*/
static uintptr_t
deinterpose(int sig, void *aharr, psinfo_t *psinfo, struct sigaction *sp)
{
	if (sp->sa_handler == SIG_DFL || sp->sa_handler == SIG_IGN)
		return ((uintptr_t)sp->sa_handler);
#ifdef _LP64
	if (psinfo->pr_dmodel != PR_MODEL_NATIVE) {
		struct sigaction32 *sa32 = (struct sigaction32 *)
		    ((uintptr_t)aharr + sig * sizeof (siguaction32_t) +
		    offsetof(siguaction32_t, sig_uaction));

		sp->sa_flags = sa32->sa_flags;
		sp->sa_handler = (void (*)())(uintptr_t)sa32->sa_handler;
		(void) memcpy(&sp->sa_mask, &sa32->sa_mask,
		    sizeof (sp->sa_mask));
	} else
#endif
	{
		struct sigaction *sa = (struct sigaction *)
		    ((uintptr_t)aharr + sig * sizeof (siguaction_t) +
		    offsetof(siguaction_t, sig_uaction));

		sp->sa_flags = sa->sa_flags;
		sp->sa_handler = sa->sa_handler;
		sp->sa_mask = sa->sa_mask;
	}
	return ((uintptr_t)sp->sa_handler);
}
