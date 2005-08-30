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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <assert.h>
#include <dtrace.h>
#include <limits.h>
#include <link.h>
#include <priv.h>
#include <signal.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/wait.h>
#include <libproc.h>

static char *g_pname;
static dtrace_hdl_t *g_dtp;
struct ps_prochandle *g_pr;

#define	E_SUCCESS	0
#define	E_ERROR		1
#define	E_USAGE		2

/*
 * For hold times we use a global associative array since for mutexes, in
 * user-land, it's not invalid to release a sychonization primitive that
 * another thread acquired; rwlocks require a thread-local associative array
 * since multiple thread can hold the same lock for reading. Note that we
 * ignore recursive mutex acquisitions and releases as they don't truly
 * affect lock contention.
 */
static const char *g_hold_init =
"plockstat$target:::rw-acquire\n"
"{\n"
"	self->rwhold[arg0] = timestamp;\n"
"}\n"
"plockstat$target:::mutex-acquire\n"
"/arg1 == 0/\n"
"{\n"
"	mtxhold[arg0] = timestamp;\n"
"}\n";

static const char *g_hold_histogram =
"plockstat$target:::rw-release\n"
"/self->rwhold[arg0] && arg1 == 1/\n"
"{\n"
"	@rw_w_hold[arg0, ustack()] =\n"
"	    quantize(timestamp - self->rwhold[arg0]);\n"
"	self->rwhold[arg0] = 0;\n"
"}\n"
"plockstat$target:::rw-release\n"
"/self->rwhold[arg0]/\n"
"{\n"
"	@rw_r_hold[arg0, ustack()] =\n"
"	    quantize(timestamp - self->rwhold[arg0]);\n"
"	self->rwhold[arg0] = 0;\n"
"}\n"
"plockstat$target:::mutex-release\n"
"/mtxhold[arg0] && arg1 == 0/\n"
"{\n"
"	@mtx_hold[arg0, ustack()] = quantize(timestamp - mtxhold[arg0]);\n"
"	mtxhold[arg0] = 0;\n"
"}\n";

static const char *g_hold_times =
"plockstat$target:::rw-release\n"
"/self->rwhold[arg0] && arg1 == 1/\n"
"{\n"
"	@rw_w_hold[arg0, ustack(5)] = avg(timestamp - self->rwhold[arg0]);\n"
"	self->rwhold[arg0] = 0;\n"
"}\n"
"plockstat$target:::rw-release\n"
"/self->rwhold[arg0]/\n"
"{\n"
"	@rw_r_hold[arg0, ustack(5)] = avg(timestamp - self->rwhold[arg0]);\n"
"	self->rwhold[arg0] = 0;\n"
"}\n"
"plockstat$target:::mutex-release\n"
"/mtxhold[arg0] && arg1 == 0/\n"
"{\n"
"	@mtx_hold[arg0, ustack(5)] = avg(timestamp - mtxhold[arg0]);\n"
"	mtxhold[arg0] = 0;\n"
"}\n";


/*
 * For contention, we use thread-local associative arrays since we're tracing
 * a single thread's activity in libc and multiple threads can be blocking or
 * spinning on the same sychonization primitive.
 */
static const char *g_ctnd_init =
"plockstat$target:::rw-block\n"
"{\n"
"	self->rwblock[arg0] = timestamp;\n"
"}\n"
"plockstat$target:::mutex-block\n"
"{\n"
"	self->mtxblock[arg0] = timestamp;\n"
"}\n"
"plockstat$target:::mutex-spin\n"
"{\n"
"	self->mtxspin[arg0] = timestamp;\n"
"}\n";

static const char *g_ctnd_histogram =
"plockstat$target:::rw-blocked\n"
"/self->rwblock[arg0] && arg1 == 1 && arg2 != 0/\n"
"{\n"
"	@rw_w_block[arg0, ustack()] =\n"
"	    quantize(timestamp - self->rwblock[arg0]);\n"
"	self->rwblock[arg0] = 0;\n"
"}\n"
"plockstat$target:::rw-blocked\n"
"/self->rwblock[arg0] && arg2 != 0/\n"
"{\n"
"	@rw_r_block[arg0, ustack()] =\n"
"	    quantize(timestamp - self->rwblock[arg0]);\n"
"	self->rwblock[arg0] = 0;\n"
"}\n"
"plockstat$target:::rw-blocked\n"
"/self->rwblock[arg0]/\n"
"{\n"
"	self->rwblock[arg0] = 0;\n"
"}\n"
"plockstat$target:::mutex-spun\n"
"/self->mtxspin[arg0] && arg1 != 0/\n"
"{\n"
"	@mtx_spin[arg0, ustack()] =\n"
"	    quantize(timestamp - self->mtxspin[arg0]);\n"
"	self->mtxspin[arg0] = 0;\n"
"}\n"
"plockstat$target:::mutex-spun\n"
"/self->mtxspin[arg0]/\n"
"{\n"
"	@mtx_vain_spin[arg0, ustack()] =\n"
"	    quantize(timestamp - self->mtxspin[arg0]);\n"
"	self->mtxspin[arg0] = 0;\n"
"}\n"
"plockstat$target:::mutex-blocked\n"
"/self->mtxblock[arg0] && arg1 != 0/\n"
"{\n"
"	@mtx_block[arg0, ustack()] =\n"
"	    quantize(timestamp - self->mtxblock[arg0]);\n"
"	self->mtxblock[arg0] = 0;\n"
"}\n"
"plockstat$target:::mutex-blocked\n"
"/self->mtxblock[arg0]/\n"
"{\n"
"	self->mtxblock[arg0] = 0;\n"
"}\n";


static const char *g_ctnd_times =
"plockstat$target:::rw-blocked\n"
"/self->rwblock[arg0] && arg1 == 1 && arg2 != 0/\n"
"{\n"
"	@rw_w_block[arg0, ustack(5)] =\n"
"	    avg(timestamp - self->rwblock[arg0]);\n"
"	self->rwblock[arg0] = 0;\n"
"}\n"
"plockstat$target:::rw-blocked\n"
"/self->rwblock[arg0] && arg2 != 0/\n"
"{\n"
"	@rw_r_block[arg0, ustack(5)] =\n"
"	    avg(timestamp - self->rwblock[arg0]);\n"
"	self->rwblock[arg0] = 0;\n"
"}\n"
"plockstat$target:::rw-blocked\n"
"/self->rwblock[arg0]/\n"
"{\n"
"	self->rwblock[arg0] = 0;\n"
"}\n"
"plockstat$target:::mutex-spun\n"
"/self->mtxspin[arg0] && arg1 != 0/\n"
"{\n"
"	@mtx_spin[arg0, ustack(5)] =\n"
"	    avg(timestamp - self->mtxspin[arg0]);\n"
"	self->mtxspin[arg0] = 0;\n"
"}\n"
"plockstat$target:::mutex-spun\n"
"/self->mtxspin[arg0]/\n"
"{\n"
"	@mtx_vain_spin[arg0, ustack(5)] =\n"
"	    avg(timestamp - self->mtxspin[arg0]);\n"
"	self->mtxspin[arg0] = 0;\n"
"}\n"
"plockstat$target:::mutex-blocked\n"
"/self->mtxblock[arg0] && arg1 != 0/\n"
"{\n"
"	@mtx_block[arg0, ustack(5)] =\n"
"	    avg(timestamp - self->mtxblock[arg0]);\n"
"	self->mtxblock[arg0] = 0;\n"
"}\n"
"plockstat$target:::mutex-blocked\n"
"/self->mtxblock[arg0]/\n"
"{\n"
"	self->mtxblock[arg0] = 0;\n"
"}\n";

static char g_prog[2048];
static size_t g_proglen;
static int g_opt_V, g_opt_s;
static int g_intr;
static dtrace_optval_t g_nframes;
static ulong_t g_nent = ULONG_MAX;

#define	PLOCKSTAT_OPTSTR	"n:ps:e:vx:ACHV"

static void
usage(void)
{
	(void) fprintf(stderr, "Usage:\n"
	    "\t%s [-vACHV] [-n count] [-s depth] [-e secs] [-x opt[=val]]\n"
	    "\t    command [arg...]\n"
	    "\t%s [-vACHV] [-n count] [-s depth] [-e secs] [-x opt[=val]]\n"
	    "\t    -p pid\n", g_pname, g_pname);

	exit(E_USAGE);
}

static void
verror(const char *fmt, va_list ap)
{
	int error = errno;

	(void) fprintf(stderr, "%s: ", g_pname);
	(void) vfprintf(stderr, fmt, ap);

	if (fmt[strlen(fmt) - 1] != '\n')
		(void) fprintf(stderr, ": %s\n", strerror(error));
}

/*PRINTFLIKE1*/
static void
fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	verror(fmt, ap);
	va_end(ap);

	if (g_pr != NULL && g_dtp != NULL)
		dtrace_proc_release(g_dtp, g_pr);

	exit(E_ERROR);
}

/*PRINTFLIKE1*/
static void
dfatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	(void) fprintf(stderr, "%s: ", g_pname);
	if (fmt != NULL)
		(void) vfprintf(stderr, fmt, ap);

	va_end(ap);

	if (fmt != NULL && fmt[strlen(fmt) - 1] != '\n') {
		(void) fprintf(stderr, ": %s\n",
		    dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)));
	} else if (fmt == NULL) {
		(void) fprintf(stderr, "%s\n",
		    dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)));
	}

	if (g_pr != NULL) {
		dtrace_proc_continue(g_dtp, g_pr);
		dtrace_proc_release(g_dtp, g_pr);
	}

	exit(E_ERROR);
}

/*PRINTFLIKE1*/
static void
notice(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	verror(fmt, ap);
	va_end(ap);
}

static void
dprog_add(const char *prog)
{
	size_t len = strlen(prog);
	bcopy(prog, g_prog + g_proglen, len + 1);
	g_proglen += len;
}

static void
dprog_compile(void)
{
	dtrace_prog_t *prog;
	dtrace_proginfo_t info;

	if (g_opt_V) {
		(void) fprintf(stderr, "%s: vvvv D program vvvv\n", g_pname);
		(void) fputs(g_prog, stderr);
		(void) fprintf(stderr, "%s: ^^^^ D program ^^^^\n", g_pname);
	}

	if ((prog = dtrace_program_strcompile(g_dtp, g_prog,
	    DTRACE_PROBESPEC_NAME, 0, 0, NULL)) == NULL)
		dfatal("failed to compile program");

	if (dtrace_program_exec(g_dtp, prog, &info) == -1)
		dfatal("failed to enable probes");
}

static void
print_header(const char *aggname)
{
	if (strcmp(aggname, "mtx_hold") == 0) {
		(void) printf("\nMutex hold\n\n");
	} else if (strcmp(aggname, "mtx_block") == 0) {
		(void) printf("\nMutex block\n\n");
	} else if (strcmp(aggname, "mtx_spin") == 0) {
		(void) printf("\nMutex spin\n\n");
	} else if (strcmp(aggname, "mtx_vain_spin") == 0) {
		(void) printf("\nMutex unsuccessful spin\n\n");
	} else if (strcmp(aggname, "rw_r_hold") == 0) {
		(void) printf("\nR/W reader hold\n\n");
	} else if (strcmp(aggname, "rw_w_hold") == 0) {
		(void) printf("\nR/W writer hold\n\n");
	} else if (strcmp(aggname, "rw_r_block") == 0) {
		(void) printf("\nR/W reader block\n\n");
	} else if (strcmp(aggname, "rw_w_block") == 0) {
		(void) printf("\nR/W writer block\n\n");
	}
}

void
print_legend(void)
{
	(void) printf("%5s %8s %-28s %s\n", "Count", "nsec", "Lock", "Caller");
}

void
print_bar(void)
{
	(void) printf("---------------------------------------"
	    "----------------------------------------\n");
}

void
print_histogram_header(void)
{
	(void) printf("\n%10s ---- Time Distribution --- %5s %s\n",
	    "nsec", "count", "Stack");
}

/*
 * Convert an address to a symbolic string or a numeric string. If nolocks
 * is set, we return an error code if this symbol appears to be a mutex- or
 * rwlock-related symbol in libc so the caller has a chance to find a more
 * helpful symbol.
 */
static int
getsym(struct ps_prochandle *P, uintptr_t addr, char *buf, size_t size,
    int nolocks)
{
	char name[256];
	GElf_Sym sym;
	prsyminfo_t info;
	size_t len;

	if (P == NULL || Pxlookup_by_addr(P, addr, name, sizeof (name),
	    &sym, &info) != 0) {
		(void) snprintf(buf, size, "%#lx", addr);
		return (0);
	}

	if (info.prs_lmid != LM_ID_BASE) {
		len = snprintf(buf, size, "LM%lu`", info.prs_lmid);
		buf += len;
		size -= len;
	}

	len = snprintf(buf, size, "%s`%s", info.prs_object, info.prs_name);
	buf += len;
	size -= len;

	if (sym.st_value != addr)
		len = snprintf(buf, size, "+%#lx", addr - sym.st_value);

	if (nolocks && strcmp("libc.so.1", info.prs_object) == 0 &&
	    (strstr("mutex", info.prs_name) == 0 ||
	    strstr("rw", info.prs_name) == 0))
		return (-1);

	return (0);
}

/*ARGSUSED*/
static int
process_aggregate(const dtrace_aggdata_t *agg, void *arg)
{
	static dtrace_aggid_t last = DTRACE_AGGIDNONE;
	static uint_t nent;
	const dtrace_aggdesc_t *aggdesc = agg->dtada_desc;
	caddr_t data = agg->dtada_data;
	const dtrace_recdesc_t *rec;
	uint64_t *a, count, avg;
	char buf[256];
	uintptr_t lock;
	pid_t pid;
	uint64_t *stack;
	struct ps_prochandle *P;
	int i, j;

	if (aggdesc->dtagd_id != last) {
		print_header(aggdesc->dtagd_name);
		nent = 0;
	}
	if (nent >= g_nent)
		goto out;
	nent++;

	rec = aggdesc->dtagd_rec;

	/*LINTED - alignment*/
	lock = (uintptr_t)*(uint64_t *)(data + rec[1].dtrd_offset);
	/*LINTED - alignment*/
	stack = (uint64_t *)(data + rec[2].dtrd_offset);
	/*LINTED - alignment*/
	a = (uint64_t *)(data + rec[aggdesc->dtagd_nrecs - 1].dtrd_offset);

	if (!g_opt_s) {
		if (aggdesc->dtagd_id != last) {
			print_legend();
			print_bar();
		}

		count = a[0];
		avg = a[1] / a[0];
	} else {
		print_bar();
		print_legend();
		count = avg = 0;

		for (i = DTRACE_QUANTIZE_ZEROBUCKET, j = 0;
		    i < DTRACE_QUANTIZE_NBUCKETS; i++, j++) {
			count += a[i];
			avg += a[i] << (j - 64);
		}

		avg /= count;
	}

	(void) printf("%5llu %8llu ", (u_longlong_t)count, (u_longlong_t)avg);

	pid = stack[0];
	P = dtrace_proc_grab(g_dtp, pid, PGRAB_RDONLY);

	(void) getsym(P, lock, buf, sizeof (buf), 0);
	(void) printf("%-28s ", buf);

	for (i = 2; i <= 5; i++) {
		if (getsym(P, stack[i], buf, sizeof (buf), 1) == 0)
			break;
	}
	(void) printf("%s\n", buf);

	if (g_opt_s) {
		int stack_done = 0;
		int quant_done = 0;
		int first_bin, last_bin;
		uint64_t bin_size;

		print_histogram_header();

		for (first_bin = DTRACE_QUANTIZE_ZEROBUCKET;
		    a[first_bin] == 0; first_bin++)
			continue;
		for (last_bin = DTRACE_QUANTIZE_ZEROBUCKET + 63;
		    a[last_bin] == 0; last_bin--)
			continue;

		for (i = 0; !stack_done || !quant_done; i++) {
			if (!stack_done) {
				(void) getsym(P, stack[i + 2], buf,
				    sizeof (buf), 0);
			} else {
				buf[0] = '\0';
			}

			if (!quant_done) {
				bin_size = a[first_bin];

				(void) printf("%10llu |%-24.*s| %5llu %s\n",
				    1ULL <<
				    (first_bin - DTRACE_QUANTIZE_ZEROBUCKET),
				    (int)(24.0 * bin_size / count),
				    "@@@@@@@@@@@@@@@@@@@@@@@@@@",
				    (u_longlong_t)bin_size, buf);
			} else {
				(void) printf("%43s %s\n", "", buf);
			}

			if (i + 1 >= g_nframes || stack[i + 3] == 0)
				stack_done = 1;

			if (first_bin++ == last_bin)
				quant_done = 1;
		}
	}

	dtrace_proc_release(g_dtp, P);

out:
	last = aggdesc->dtagd_id;

	return (DTRACE_AGGWALK_NEXT);
}

static int
prochandler(struct ps_prochandle *P)
{
	const psinfo_t *prp = Ppsinfo(P);
	int pid = Pstatus(P)->pr_pid;
	char name[SIG2STR_MAX];

	switch (Pstate(P)) {
	case PS_UNDEAD:
		/*
		 * Ideally we would like to always report pr_wstat here, but it
		 * isn't possible given current /proc semantics.  If we grabbed
		 * the process, Ppsinfo() will either fail or return a zeroed
		 * psinfo_t depending on how far the parent is in reaping it.
		 * When /proc provides a stable pr_wstat in the status file,
		 * this code can be improved by examining this new pr_wstat.
		 */
		if (prp != NULL && WIFSIGNALED(prp->pr_wstat)) {
			notice("pid %d terminated by %s\n", pid,
			    proc_signame(WTERMSIG(prp->pr_wstat),
			    name, sizeof (name)));
		} else if (prp != NULL && WEXITSTATUS(prp->pr_wstat) != 0) {
			notice("pid %d exited with status %d\n",
			    pid, WEXITSTATUS(prp->pr_wstat));
		} else {
			notice("pid %d has exited\n", pid);
		}
		return (1);

	case PS_LOST:
		notice("pid %d exec'd a set-id or unobservable program\n", pid);
		return (1);
	}

	return (0);
}

/*ARGSUSED*/
static void
intr(int signo)
{
	g_intr = 1;
}

int
main(int argc, char **argv)
{
	ucred_t *ucp;
	int err;
	int opt_C = 0, opt_H = 0, opt_p = 0, opt_v = 0;
	char c, *p, *end;
	struct sigaction act;
	int done = 0;

	if ((g_pname = strrchr(argv[0], '/')) == NULL)
		g_pname = argv[0];
	else
		argv[0] = ++g_pname;		/* for getopt() */

	/*
	 * Make sure we have the required dtrace_proc privilege.
	 */
	if ((ucp = ucred_get(getpid())) != NULL) {
		const priv_set_t *psp;
		if ((psp = ucred_getprivset(ucp, PRIV_EFFECTIVE)) != NULL &&
		    !priv_ismember(psp, PRIV_DTRACE_PROC)) {
			fatal("dtrace_proc privilege required\n");
		}

		ucred_free(ucp);
	}

	while ((c = getopt(argc, argv, PLOCKSTAT_OPTSTR)) != EOF) {
		switch (c) {
		case 'n':
			errno = 0;
			g_nent = strtoul(optarg, &end, 10);
			if (*end != '\0' || errno != 0) {
				(void) fprintf(stderr, "%s: invalid count "
				    "'%s'\n", g_pname, optarg);
				usage();
			}
			break;

		case 'p':
			opt_p = 1;
			break;

		case 'v':
			opt_v = 1;
			break;

		case 'A':
			opt_C = opt_H = 1;
			break;

		case 'C':
			opt_C = 1;
			break;

		case 'H':
			opt_H = 1;
			break;

		case 'V':
			g_opt_V = 1;
			break;

		default:
			if (strchr(PLOCKSTAT_OPTSTR, c) == NULL)
				usage();
		}
	}

	/*
	 * We need a command or at least one pid.
	 */
	if (argc == optind)
		usage();

	if (opt_C == 0 && opt_H == 0)
		opt_C = 1;

	if ((g_dtp = dtrace_open(DTRACE_VERSION, 0, &err)) == NULL)
		fatal("failed to initialize dtrace: %s\n",
		    dtrace_errmsg(NULL, err));

	if (dtrace_setopt(g_dtp, "aggsize", "256k") == -1)
		dfatal("failed to set 'aggsize'");

	if (dtrace_setopt(g_dtp, "aggrate", "1sec") == -1)
		dfatal("failed to set 'aggrate'");

	/*
	 * Take a second pass through to look for options that set options now
	 * that we have an open dtrace handle.
	 */
	optind = 1;
	while ((c = getopt(argc, argv, PLOCKSTAT_OPTSTR)) != EOF) {
		switch (c) {
		case 's':
			g_opt_s = 1;
			if (dtrace_setopt(g_dtp, "ustackframes", optarg) == -1)
				dfatal("failed to set 'ustackframes'");
			break;

		case 'x':
			if ((p = strchr(optarg, '=')) != NULL)
				*p++ = '\0';

			if (dtrace_setopt(g_dtp, optarg, p) != 0)
				dfatal("failed to set -x %s", optarg);
			break;

		case 'e':
			errno = 0;
			(void) strtoul(optarg, &end, 10);
			if (*optarg == '-' || *end != '\0' || errno != 0) {
				(void) fprintf(stderr, "%s: invalid timeout "
				    "'%s'\n", g_pname, optarg);
				usage();
			}

			/*
			 * Construct a DTrace enabling that will exit after
			 * the specified number of seconds.
			 */
			dprog_add("BEGIN\n{\n\tend = timestamp + ");
			dprog_add(optarg);
			dprog_add(" * 1000000000;\n}\n");
			dprog_add("tick-10hz\n/timestamp >= end/\n");
			dprog_add("{\n\texit(0);\n}\n");
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (opt_H) {
		dprog_add(g_hold_init);
		if (g_opt_s == NULL)
			dprog_add(g_hold_times);
		else
			dprog_add(g_hold_histogram);
	}

	if (opt_C) {
		dprog_add(g_ctnd_init);
		if (g_opt_s == NULL)
			dprog_add(g_ctnd_times);
		else
			dprog_add(g_ctnd_histogram);
	}

	if (opt_p) {
		ulong_t pid;

		if (argc > 1) {
			(void) fprintf(stderr, "%s: only one pid is allowed\n",
			    g_pname);
			usage();
		}

		errno = 0;
		pid = strtoul(argv[0], &end, 10);
		if (*end != '\0' || errno != 0 || (pid_t)pid != pid) {
			(void) fprintf(stderr, "%s: invalid pid '%s'\n",
			    g_pname, argv[0]);
			usage();
		}

		if ((g_pr = dtrace_proc_grab(g_dtp, (pid_t)pid, 0)) == NULL)
			dfatal(NULL);
	} else {
		if ((g_pr = dtrace_proc_create(g_dtp, argv[0], argv)) == NULL)
			dfatal(NULL);
	}

	dprog_compile();

	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = intr;
	(void) sigaction(SIGINT, &act, NULL);
	(void) sigaction(SIGTERM, &act, NULL);

	if (dtrace_go(g_dtp) != 0)
		dfatal("dtrace_go()");

	if (dtrace_getopt(g_dtp, "ustackframes", &g_nframes) != 0)
		dfatal("failed to get 'ustackframes'");

	dtrace_proc_continue(g_dtp, g_pr);

	if (opt_v)
		(void) printf("%s: tracing enabled for pid %d\n", g_pname,
		    (int)Pstatus(g_pr)->pr_pid);

	while (!done) {
		(void) sleep(1);

		if (dtrace_status(g_dtp) == DTRACE_STATUS_EXITED)
			done = 1;

		/* Done if the user hits control-C. */
		if (g_intr)
			done = 1;

		if (prochandler(g_pr) == 1)
			done = 1;

		if (dtrace_aggregate_snap(g_dtp) != 0)
			dfatal("failed to add to aggregate");
	}

	if (dtrace_aggregate_snap(g_dtp) != 0)
		dfatal("failed to add to aggregate");

	if (dtrace_aggregate_walk_valrevsorted(g_dtp,
	    process_aggregate, NULL) != 0)
		dfatal("failed to print aggregations");

	dtrace_close(g_dtp);

	return (0);
}
