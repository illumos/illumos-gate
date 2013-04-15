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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */

#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <strings.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/int_fmtio.h>
#include <libproc.h>

typedef struct look_arg {
	int pflags;
	const char *lwps;
	int count;
} look_arg_t;

static	int	look(char *);
static	int	lwplook(look_arg_t *, const lwpstatus_t *, const lwpsinfo_t *);
static	char	*prflags(int);
static	char	*prwhy(int);
static	char	*prwhat(int, int);
static	void	dumpregs(const prgregset_t, int);
#if defined(__sparc) && defined(_ILP32)
static	void	dumpregs_v8p(const prgregset_t, const prxregset_t *, int);
#endif

static	char	*command;
static	struct	ps_prochandle *Pr;

static	int	is64;	/* Is current process 64-bit? */
static	int	rflag;	/* Show registers? */

#define	LWPFLAGS	\
	(PR_STOPPED|PR_ISTOP|PR_DSTOP|PR_ASLEEP|PR_PCINVAL|PR_STEP \
	|PR_AGENT|PR_DETACH|PR_DAEMON)

#define	PROCFLAGS	\
	(PR_ISSYS|PR_VFORKP|PR_ORPHAN|PR_NOSIGCHLD|PR_WAITPID \
	|PR_FORK|PR_RLC|PR_KLC|PR_ASYNC|PR_BPTADJ|PR_MSACCT|PR_MSFORK|PR_PTRACE)

#define	ALLFLAGS	(LWPFLAGS|PROCFLAGS)

int
main(int argc, char **argv)
{
	int rc = 0;
	int errflg = 0;
	int opt;
	struct rlimit rlim;

	if ((command = strrchr(argv[0], '/')) != NULL)
		command++;
	else
		command = argv[0];

	/* options */
	while ((opt = getopt(argc, argv, "r")) != EOF) {
		switch (opt) {
		case 'r':		/* show registers */
			rflag = 1;
			break;
		default:
			errflg = 1;
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (errflg || argc <= 0) {
		(void) fprintf(stderr,
		    "usage:\t%s [-r] { pid | core }[/lwps] ...\n", command);
		(void) fprintf(stderr, "  (report process status flags)\n");
		(void) fprintf(stderr, "  -r : report registers\n");
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

	while (argc-- > 0)
		rc += look(*argv++);

	return (rc);
}

static int
look(char *arg)
{
	int gcode;
	int gcode2;
	pstatus_t pstatus;
	psinfo_t psinfo;
	int flags;
	sigset_t sigmask;
	fltset_t fltmask;
	sysset_t entryset;
	sysset_t exitset;
	uint32_t sigtrace, sigtrace1, sigtrace2, fltbits;
	uint32_t sigpend, sigpend1, sigpend2;
	uint32_t *bits;
	char buf[PRSIGBUFSZ];
	look_arg_t lookarg;

	if ((Pr = proc_arg_xgrab(arg, NULL, PR_ARG_ANY,
	    PGRAB_RETAIN | PGRAB_FORCE | PGRAB_RDONLY | PGRAB_NOSTOP, &gcode,
	    &lookarg.lwps)) == NULL) {
		if (gcode == G_NOPROC &&
		    proc_arg_psinfo(arg, PR_ARG_PIDS, &psinfo, &gcode2) > 0 &&
		    psinfo.pr_nlwp == 0) {
			(void) printf("%d:\t<defunct>\n\n", (int)psinfo.pr_pid);
			return (0);
		}
		(void) fprintf(stderr, "%s: cannot examine %s: %s\n",
		    command, arg, Pgrab_error(gcode));
		return (1);
	}

	(void) memcpy(&pstatus, Pstatus(Pr), sizeof (pstatus_t));
	(void) memcpy(&psinfo, Ppsinfo(Pr), sizeof (psinfo_t));
	proc_unctrl_psinfo(&psinfo);

	if (psinfo.pr_nlwp == 0) {
		(void) printf("%d:\t<defunct>\n\n", (int)psinfo.pr_pid);
		Prelease(Pr, PRELEASE_RETAIN);
		return (0);
	}

	is64 = (pstatus.pr_dmodel == PR_MODEL_LP64);

	sigmask = pstatus.pr_sigtrace;
	fltmask = pstatus.pr_flttrace;
	entryset = pstatus.pr_sysentry;
	exitset = pstatus.pr_sysexit;

	if (Pstate(Pr) == PS_DEAD) {
		(void) printf("core '%s' of %d:\t%.70s\n",
		    arg, (int)psinfo.pr_pid, psinfo.pr_psargs);
	} else {
		(void) printf("%d:\t%.70s\n",
		    (int)psinfo.pr_pid, psinfo.pr_psargs);
	}

	(void) printf("\tdata model = %s", is64? "_LP64" : "_ILP32");
	if ((flags = (pstatus.pr_flags & PROCFLAGS)) != 0)
		(void) printf("  flags = %s", prflags(flags));
	(void) printf("\n");

	fltbits = *((uint32_t *)&fltmask);
	if (fltbits)
		(void) printf("\tflttrace = 0x%.8x\n", fltbits);

#if (MAXSIG > 2 * 32) && (MAXSIG <= 3 * 32)	/* assumption */
	sigtrace = *((uint32_t *)&sigmask);
	sigtrace1 = *((uint32_t *)&sigmask + 1);
	sigtrace2 = *((uint32_t *)&sigmask + 2);
#else
#error "fix me: MAXSIG out of bounds"
#endif
	if (sigtrace | sigtrace1 | sigtrace2)
		(void) printf("\tsigtrace = 0x%.8x 0x%.8x 0x%.8x\n\t    %s\n",
		    sigtrace, sigtrace1, sigtrace2,
		    proc_sigset2str(&sigmask, "|", 1, buf, sizeof (buf)));

	bits = ((uint32_t *)&entryset);
	if (bits[0] | bits[1] | bits[2] | bits[3] |
	    bits[4] | bits[5] | bits[6] | bits[7])
		(void) printf(
		    "\tentryset = "
		    "0x%.8x 0x%.8x 0x%.8x 0x%.8x\n"
		    "\t           "
		    "0x%.8x 0x%.8x 0x%.8x 0x%.8x\n",
		    bits[0], bits[1], bits[2], bits[3],
		    bits[4], bits[5], bits[6], bits[7]);

	bits = ((uint32_t *)&exitset);
	if (bits[0] | bits[1] | bits[2] | bits[3] |
	    bits[4] | bits[5] | bits[6] | bits[7])
		(void) printf(
		    "\texitset  = "
		    "0x%.8x 0x%.8x 0x%.8x 0x%.8x\n"
		    "\t           "
		    "0x%.8x 0x%.8x 0x%.8x 0x%.8x\n",
		    bits[0], bits[1], bits[2], bits[3],
		    bits[4], bits[5], bits[6], bits[7]);

#if (MAXSIG > 2 * 32) && (MAXSIG <= 3 * 32)	/* assumption */
	sigpend  = *((uint32_t *)&pstatus.pr_sigpend);
	sigpend1 = *((uint32_t *)&pstatus.pr_sigpend + 1);
	sigpend2 = *((uint32_t *)&pstatus.pr_sigpend + 2);
#else
#error "fix me: MAXSIG out of bounds"
#endif
	if (sigpend | sigpend1 | sigpend2)
		(void) printf("\tsigpend = 0x%.8x,0x%.8x,0x%.8x\n",
		    sigpend, sigpend1, sigpend2);

	lookarg.pflags = pstatus.pr_flags;
	lookarg.count = 0;
	(void) Plwp_iter_all(Pr, (proc_lwp_all_f *)lwplook, &lookarg);

	if (lookarg.count == 0)
		(void) printf("No matching lwps found");

	(void) printf("\n");
	Prelease(Pr, PRELEASE_RETAIN);

	return (0);
}

static int
lwplook_zombie(const lwpsinfo_t *pip)
{
	(void) printf(" /%d:\t<defunct>\n", (int)pip->pr_lwpid);
	return (0);
}

static int
lwplook(look_arg_t *arg, const lwpstatus_t *psp, const lwpsinfo_t *pip)
{
	int flags;
	uint32_t sighold, sighold1, sighold2;
	uint32_t sigpend, sigpend1, sigpend2;
	psinfo_t ps;
	int cursig;
	char buf[32];

	if (!proc_lwp_in_set(arg->lwps, pip->pr_lwpid))
		return (0);

	arg->count++;

	if (psp == NULL)
		return (lwplook_zombie(pip));

	/*
	 * PR_PCINVAL is just noise if the lwp is not stopped.
	 * Don't bother reporting it unless the lwp is stopped.
	 */
	flags = psp->pr_flags & LWPFLAGS;
	if (!(flags & PR_STOPPED))
		flags &= ~PR_PCINVAL;

	(void) printf(" /%d:\tflags = %s", (int)psp->pr_lwpid, prflags(flags));
	if ((flags & PR_ASLEEP) || (psp->pr_syscall &&
	    !(arg->pflags & PR_ISSYS))) {
		if (flags & PR_ASLEEP) {
			if ((flags & ~PR_ASLEEP) != 0)
				(void) printf("|");
			(void) printf("ASLEEP");
		}
		if (psp->pr_syscall && !(arg->pflags & PR_ISSYS)) {
			uint_t i;

			(void) printf("  %s(",
			    proc_sysname(psp->pr_syscall, buf, sizeof (buf)));
			for (i = 0; i < psp->pr_nsysarg; i++) {
				if (i != 0)
					(void) printf(",");
				(void) printf("0x%lx", psp->pr_sysarg[i]);
			}
			(void) printf(")");
		}
	}
	(void) printf("\n");

	if (flags & PR_STOPPED) {
		(void) printf("\twhy = %s", prwhy(psp->pr_why));
		if (psp->pr_why != PR_REQUESTED &&
		    psp->pr_why != PR_SUSPENDED)
			(void) printf("  what = %s",
			    prwhat(psp->pr_why, psp->pr_what));
		(void) printf("\n");
	}

#if (MAXSIG > 2 * 32) && (MAXSIG <= 3 * 32)	/* assumption */
	sighold  = *((uint32_t *)&psp->pr_lwphold);
	sighold1 = *((uint32_t *)&psp->pr_lwphold + 1);
	sighold2 = *((uint32_t *)&psp->pr_lwphold + 2);
	sigpend  = *((uint32_t *)&psp->pr_lwppend);
	sigpend1 = *((uint32_t *)&psp->pr_lwppend + 1);
	sigpend2 = *((uint32_t *)&psp->pr_lwppend + 2);
#else
#error "fix me: MAXSIG out of bounds"
#endif
	cursig   = psp->pr_cursig;

	if (sighold | sighold1 | sighold2)
		(void) printf("\tsigmask = 0x%.8x,0x%.8x,0x%.8x\n",
		    sighold, sighold1, sighold2);
	if (sigpend | sigpend1 | sigpend2)
		(void) printf("\tlwppend = 0x%.8x,0x%.8x,0x%.8x\n",
		    sigpend, sigpend1, sigpend2);
	if (cursig)
		(void) printf("\tcursig = %s\n",
		    proc_signame(cursig, buf, sizeof (buf)));

	if ((flags & PR_AGENT) &&
	    Plwp_getspymaster(Pr, pip->pr_lwpid, &ps) == 0) {
		time_t time = ps.pr_time.tv_sec;
		char t[64];

		(void) strftime(t, sizeof (t), "%F:%H.%M.%S", localtime(&time));

		(void) printf("\tspymaster = pid %d, \"%s\" at %s\n",
		    (int)ps.pr_pid, ps.pr_psargs, t);
	}

	if (rflag) {
		if (Pstate(Pr) == PS_DEAD || (arg->pflags & PR_STOPPED)) {
#if defined(__sparc) && defined(_ILP32)
			/*
			 * If we're SPARC/32-bit, see if we can get extra
			 * register state for this lwp.  If it's a v8plus
			 * program, print the 64-bit register values.
			 */
			prxregset_t prx;

			if (Plwp_getxregs(Pr, psp->pr_lwpid, &prx) == 0 &&
			    prx.pr_type == XR_TYPE_V8P)
				dumpregs_v8p(psp->pr_reg, &prx, is64);
			else
#endif	/* __sparc && _ILP32 */
				dumpregs(psp->pr_reg, is64);
		} else
			(void) printf("\tNot stopped, can't show registers\n");
	}

	return (0);
}

static char *
prflags(int arg)
{
	static char code_buf[200];
	char *str = code_buf;

	if (arg == 0)
		return ("0");

	if (arg & ~ALLFLAGS)
		(void) sprintf(str, "0x%x", arg & ~ALLFLAGS);
	else
		*str = '\0';

	/*
	 * Display the semi-permanent lwp flags first.
	 */
	if (arg & PR_DAEMON)		/* daemons are always detached so */
		(void) strcat(str, "|DAEMON");
	else if (arg & PR_DETACH)	/* report detach only if non-daemon */
		(void) strcat(str, "|DETACH");

	if (arg & PR_STOPPED)
		(void) strcat(str, "|STOPPED");
	if (arg & PR_ISTOP)
		(void) strcat(str, "|ISTOP");
	if (arg & PR_DSTOP)
		(void) strcat(str, "|DSTOP");
#if 0		/* displayed elsewhere */
	if (arg & PR_ASLEEP)
		(void) strcat(str, "|ASLEEP");
#endif
	if (arg & PR_PCINVAL)
		(void) strcat(str, "|PCINVAL");
	if (arg & PR_STEP)
		(void) strcat(str, "|STEP");
	if (arg & PR_AGENT)
		(void) strcat(str, "|AGENT");
	if (arg & PR_ISSYS)
		(void) strcat(str, "|ISSYS");
	if (arg & PR_VFORKP)
		(void) strcat(str, "|VFORKP");
	if (arg & PR_ORPHAN)
		(void) strcat(str, "|ORPHAN");
	if (arg & PR_NOSIGCHLD)
		(void) strcat(str, "|NOSIGCHLD");
	if (arg & PR_WAITPID)
		(void) strcat(str, "|WAITPID");
	if (arg & PR_FORK)
		(void) strcat(str, "|FORK");
	if (arg & PR_RLC)
		(void) strcat(str, "|RLC");
	if (arg & PR_KLC)
		(void) strcat(str, "|KLC");
	if (arg & PR_ASYNC)
		(void) strcat(str, "|ASYNC");
	if (arg & PR_BPTADJ)
		(void) strcat(str, "|BPTADJ");
	if (arg & PR_MSACCT)
		(void) strcat(str, "|MSACCT");
	if (arg & PR_MSFORK)
		(void) strcat(str, "|MSFORK");
	if (arg & PR_PTRACE)
		(void) strcat(str, "|PTRACE");

	if (*str == '|')
		str++;

	return (str);
}

static char *
prwhy(int why)
{
	static char buf[20];
	char *str;

	switch (why) {
	case PR_REQUESTED:
		str = "PR_REQUESTED";
		break;
	case PR_SIGNALLED:
		str = "PR_SIGNALLED";
		break;
	case PR_SYSENTRY:
		str = "PR_SYSENTRY";
		break;
	case PR_SYSEXIT:
		str = "PR_SYSEXIT";
		break;
	case PR_JOBCONTROL:
		str = "PR_JOBCONTROL";
		break;
	case PR_FAULTED:
		str = "PR_FAULTED";
		break;
	case PR_SUSPENDED:
		str = "PR_SUSPENDED";
		break;
	default:
		str = buf;
		(void) sprintf(str, "%d", why);
		break;
	}

	return (str);
}

static char *
prwhat(int why, int what)
{
	static char buf[32];
	char *str;

	switch (why) {
	case PR_SIGNALLED:
	case PR_JOBCONTROL:
		str = proc_signame(what, buf, sizeof (buf));
		break;
	case PR_SYSENTRY:
	case PR_SYSEXIT:
		str = proc_sysname(what, buf, sizeof (buf));
		break;
	case PR_FAULTED:
		str = proc_fltname(what, buf, sizeof (buf));
		break;
	default:
		(void) sprintf(str = buf, "%d", what);
		break;
	}

	return (str);
}

#if defined(__sparc)
static const char * const regname[NPRGREG] = {
	" %g0", " %g1", " %g2", " %g3", " %g4", " %g5", " %g6", " %g7",
	" %o0", " %o1", " %o2", " %o3", " %o4", " %o5", " %sp", " %o7",
	" %l0", " %l1", " %l2", " %l3", " %l4", " %l5", " %l6", " %l7",
	" %i0", " %i1", " %i2", " %i3", " %i4", " %i5", " %fp", " %i7",
#ifdef __sparcv9
	"%ccr", " %pc", "%npc", "  %y", "%asi", "%fprs"
#else
	"%psr", " %pc", "%npc", "  %y", "%wim", "%tbr"
#endif
};
#endif	/* __sparc */

#if defined(__amd64)
static const char * const regname[NPRGREG] = {
	"%r15", "%r14", "%r13", "%r12", "%r11", "%r10", " %r9", " %r8",
	"%rdi", "%rsi", "%rbp", "%rbx", "%rdx", "%rcx", "%rax", "%trapno",
	"%err", "%rip", " %cs", "%rfl", "%rsp", " %ss", " %fs", " %gs",
	" %es", " %ds", "%fsbase", "%gsbase"
};

static const char * const regname32[NPRGREG32] = {
	" %gs", " %fs", " %es", " %ds", "%edi", "%esi", "%ebp", "%esp",
	"%ebx", "%edx", "%ecx", "%eax", "%trapno", "%err", "%eip", " %cs",
	"%efl", "%uesp", " %ss"
};

/* XX64 Do we want to expose this through libproc */
void
prgregset_n_to_32(const prgreg_t *src, prgreg32_t *dst)
{
	bzero(dst, NPRGREG32 * sizeof (prgreg32_t));
	dst[GS] = src[REG_GS];
	dst[FS] = src[REG_FS];
	dst[DS] = src[REG_DS];
	dst[ES] = src[REG_ES];
	dst[EDI] = src[REG_RDI];
	dst[ESI] = src[REG_RSI];
	dst[EBP] = src[REG_RBP];
	dst[EBX] = src[REG_RBX];
	dst[EDX] = src[REG_RDX];
	dst[ECX] = src[REG_RCX];
	dst[EAX] = src[REG_RAX];
	dst[TRAPNO] = src[REG_TRAPNO];
	dst[ERR] = src[REG_ERR];
	dst[EIP] = src[REG_RIP];
	dst[CS] = src[REG_CS];
	dst[EFL] = src[REG_RFL];
	dst[UESP] = src[REG_RSP];
	dst[SS] = src[REG_SS];
}

#elif defined(__i386)
static const char * const regname[NPRGREG] = {
	" %gs", " %fs", " %es", " %ds", "%edi", "%esi", "%ebp", "%esp",
	"%ebx", "%edx", "%ecx", "%eax", "%trapno", "%err", "%eip", " %cs",
	"%efl", "%uesp", " %ss"
};
#endif /* __i386 */

#if defined(__amd64) && defined(_LP64)
static void
dumpregs32(const prgregset_t reg)
{
	prgregset32_t reg32;
	int i;

	prgregset_n_to_32(reg, reg32);

	for (i = 0; i < NPRGREG32; i++) {
		(void) printf("  %s = 0x%.8X",
		    regname32[i], reg32[i]);
		if ((i+1) % 4 == 0)
			(void) putchar('\n');
	}
	if (i % 4 != 0)
		(void) putchar('\n');
}
#endif

static void
dumpregs(const prgregset_t reg, int is64)
{
	int width = is64? 16 : 8;
	int cols = is64? 2 : 4;
	int i;

#if defined(__amd64) && defined(_LP64)
	if (!is64) {
		dumpregs32(reg);
		return;
	}
#endif

	for (i = 0; i < NPRGREG; i++) {
		(void) printf("  %s = 0x%.*lX",
		    regname[i], width, (long)reg[i]);
		if ((i+1) % cols == 0)
			(void) putchar('\n');
	}
	if (i % cols != 0)
		(void) putchar('\n');
}

#if defined(__sparc) && defined(_ILP32)
static void
dumpregs_v8p(const prgregset_t reg, const prxregset_t *xreg, int is64)
{
	static const uint32_t zero[8] = { 0 };
	int gr, xr, cols = 2;
	uint64_t xval;

	if (memcmp(xreg->pr_un.pr_v8p.pr_xg, zero, sizeof (zero)) == 0 &&
	    memcmp(xreg->pr_un.pr_v8p.pr_xo, zero, sizeof (zero)) == 0) {
		dumpregs(reg, is64);
		return;
	}

	for (gr = R_G0, xr = XR_G0; gr <= R_G7; gr++, xr++) {
		xval = (uint64_t)xreg->pr_un.pr_v8p.pr_xg[xr] << 32 |
		    (uint64_t)(uint32_t)reg[gr];
		(void) printf("  %s = 0x%.16" PRIX64, regname[gr], xval);
		if ((gr + 1) % cols == 0)
			(void) putchar('\n');
	}

	for (gr = R_O0, xr = XR_O0; gr <= R_O7; gr++, xr++) {
		xval = (uint64_t)xreg->pr_un.pr_v8p.pr_xo[xr] << 32 |
		    (uint64_t)(uint32_t)reg[gr];
		(void) printf("  %s = 0x%.16" PRIX64, regname[gr], xval);
		if ((gr + 1) % cols == 0)
			(void) putchar('\n');
	}

	for (gr = R_L0; gr < NPRGREG; gr++) {
		(void) printf("  %s =         0x%.8lX",
		    regname[gr], (long)reg[gr]);
		if ((gr + 1) % cols == 0)
			(void) putchar('\n');
	}

	if (gr % cols != 0)
		(void) putchar('\n');
}
#endif	/* __sparc && _ILP32 */
