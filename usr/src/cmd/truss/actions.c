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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <memory.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stack.h>
#include <signal.h>
#include <sys/isa_defs.h>
#include <libproc.h>
#include <priv.h>
#include "ramdata.h"
#include "systable.h"
#include "print.h"
#include "proto.h"

/*
 * Actions to take when process stops.
 */

/*
 * Function prototypes for static routines in this module.
 */
int	stopsig(private_t *);
void	showpaths(private_t *, const struct systable *);
void	showargs(private_t *, int);
void	dumpargs(private_t *, long, const char *);

/*
 * Report an lwp to be sleeping (if true).
 */
void
report_sleeping(private_t *pri, int dotrace)
{
	const lwpstatus_t *Lsp = pri->lwpstat;
	int sys = Lsp->pr_syscall;

	if (!prismember(&trace, sys) || !dotrace ||
	    !(Lsp->pr_flags & (PR_ASLEEP|PR_VFORKP))) {
		/* Make sure we catch sysexit even if we're not tracing it. */
		(void) Psysexit(Proc, sys, TRUE);
		return;
	}

	pri->length = 0;
	pri->Errno = 0;
	pri->ErrPriv = PRIV_NONE;
	pri->Rval1 = pri->Rval2 = 0;
	(void) sysentry(pri, dotrace);
	make_pname(pri, 0);
	putpname(pri);
	timestamp(pri);
	pri->length += printf("%s", pri->sys_string);
	pri->sys_leng = 0;
	*pri->sys_string = '\0';
	pri->length >>= 3;
	if (Lsp->pr_flags & PR_VFORKP)
		pri->length += 2;
	if (pri->length >= 4)
		(void) fputc(' ', stdout);
	for (; pri->length < 4; pri->length++)
		(void) fputc('\t', stdout);
	if (Lsp->pr_flags & PR_VFORKP)
		(void) fputs("(waiting for child to exit()/exec()...)\n",
		    stdout);
	else
		(void) fputs("(sleeping...)\n", stdout);
	pri->length = 0;
	if (prismember(&verbose, sys)) {
		int raw = prismember(&rawout, sys);
		pri->Errno = 1;
		expound(pri, 0, raw);
		pri->Errno = 0;
	}
	Flush();
}

/*
 * requested() gets called for these reasons:
 *	flag == JOBSIG:		report nothing; change state to JOBSTOP
 *	flag == JOBSTOP:	report "Continued ..."
 *	default:		report sleeping system call
 *
 * It returns a new flag:  JOBSTOP or SLEEPING or 0.
 */
int
requested(private_t *pri, int flag, int dotrace)
{
	const lwpstatus_t *Lsp = pri->lwpstat;
	int sig = Lsp->pr_cursig;
	int newflag = 0;

	switch (flag) {
	case JOBSIG:
		return (JOBSTOP);

	case JOBSTOP:
		if (dotrace && !cflag && prismember(&signals, sig)) {
			pri->length = 0;
			putpname(pri);
			timestamp(pri);
			(void) printf("    Continued with signal #%d, %s",
			    sig, signame(pri, sig));
			if (Lsp->pr_action.sa_handler == SIG_DFL)
				(void) printf(" [default]");
			else if (Lsp->pr_action.sa_handler == SIG_IGN)
				(void) printf(" [ignored]");
			else
				(void) printf(" [caught]");
			(void) fputc('\n', stdout);
			Flush();
		}
		newflag = 0;
		break;

	default:
		newflag = SLEEPING;
		if (!cflag)
			report_sleeping(pri, dotrace);
		break;
	}

	return (newflag);
}

int
jobcontrol(private_t *pri, int dotrace)
{
	const lwpstatus_t *Lsp = pri->lwpstat;
	int sig = stopsig(pri);

	if (sig == 0)
		return (0);

	if (dotrace && !cflag &&		/* not just counting */
	    prismember(&signals, sig)) {	/* tracing this signal */
		int sys;

		pri->length = 0;
		putpname(pri);
		timestamp(pri);
		(void) printf("    Stopped by signal #%d, %s",
		    sig, signame(pri, sig));
		if ((Lsp->pr_flags & PR_ASLEEP) &&
		    (sys = Lsp->pr_syscall) > 0 && sys <= PRMAXSYS)
			(void) printf(", in %s()",
			    sysname(pri, sys, getsubcode(pri)));
		(void) fputc('\n', stdout);
		Flush();
	}

	return (JOBSTOP);
}

/*
 * Return the signal the process stopped on iff process is already stopped on
 * PR_JOBCONTROL or is stopped on PR_SIGNALLED or PR_REQUESTED with a current
 * signal that will cause a JOBCONTROL stop when the process is set running.
 */
int
stopsig(private_t *pri)
{
	const lwpstatus_t *Lsp = pri->lwpstat;
	int sig = 0;

	if (Lsp->pr_flags & PR_STOPPED) {
		switch (Lsp->pr_why) {
		case PR_JOBCONTROL:
			sig = Lsp->pr_what;
			if (sig < 0 || sig > PRMAXSIG)
				sig = 0;
			break;
		case PR_SIGNALLED:
		case PR_REQUESTED:
			if (Lsp->pr_action.sa_handler == SIG_DFL) {
				switch (Lsp->pr_cursig) {
				case SIGSTOP:
					sig = SIGSTOP;
					break;
				case SIGTSTP:
				case SIGTTIN:
				case SIGTTOU:
					if (!(Lsp->pr_flags & PR_ORPHAN))
						sig = Lsp->pr_cursig;
					break;
				}
			}
			break;
		}
	}

	return (sig);
}

int
signalled(private_t *pri, int flag, int dotrace)
{
	const lwpstatus_t *Lsp = pri->lwpstat;
	int sig = Lsp->pr_what;

	if (sig <= 0 || sig > PRMAXSIG)	/* check bounds */
		return (0);

	if (dotrace && cflag) {			/* just counting */
		(void) mutex_lock(&count_lock);
		Cp->sigcount[sig]++;
		(void) mutex_unlock(&count_lock);
	}

	if (sig == SIGCONT && (flag == JOBSIG || flag == JOBSTOP))
		flag = requested(pri, JOBSTOP, dotrace);
	else if ((flag = jobcontrol(pri, dotrace)) == 0 &&
	    !cflag && dotrace &&
	    prismember(&signals, sig)) {
		int sys;

		pri->length = 0;
		putpname(pri);
		timestamp(pri);
		(void) printf("    Received signal #%d, %s",
		    sig, signame(pri, sig));
		if ((Lsp->pr_flags & PR_ASLEEP) &&
		    (sys = Lsp->pr_syscall) > 0 && sys <= PRMAXSYS)
			(void) printf(", in %s()",
			    sysname(pri, sys, getsubcode(pri)));
		if (Lsp->pr_action.sa_handler == SIG_DFL)
			(void) printf(" [default]");
		else if (Lsp->pr_action.sa_handler == SIG_IGN)
			(void) printf(" [ignored]");
		else
			(void) printf(" [caught]");
		(void) fputc('\n', stdout);
		if (Lsp->pr_info.si_code != 0 ||
		    Lsp->pr_info.si_pid != 0)
			print_siginfo(pri, &Lsp->pr_info);
		Flush();
	}

	if (flag == JOBSTOP)
		flag = JOBSIG;
	return (flag);
}

int
faulted(private_t *pri, int dotrace)
{
	const lwpstatus_t *Lsp = pri->lwpstat;
	int flt = Lsp->pr_what;

	if ((uint_t)flt > PRMAXFAULT || !prismember(&faults, flt) || !dotrace)
		return (0);

	(void) mutex_lock(&count_lock);
	Cp->fltcount[flt]++;
	(void) mutex_unlock(&count_lock);

	if (cflag)		/* just counting */
		return (1);

	pri->length = 0;
	putpname(pri);
	timestamp(pri);

	(void) printf("    Incurred fault #%d, %s  %%pc = 0x%.8lX",
	    flt, proc_fltname(flt, pri->flt_name, sizeof (pri->flt_name)),
	    (long)Lsp->pr_reg[R_PC]);

	if (flt == FLTPAGE)
		(void) printf("  addr = 0x%.8lX",
		    (long)Lsp->pr_info.si_addr);
	(void) fputc('\n', stdout);
	if (Lsp->pr_info.si_signo != 0)
		print_siginfo(pri, &Lsp->pr_info);
	Flush();
	return (1);
}

/*
 * Set up pri->sys_nargs and pri->sys_args[] (syscall args).
 */
void
setupsysargs(private_t *pri, int what)
{
	const lwpstatus_t *Lsp = pri->lwpstat;
	int nargs;
	int i;

#if sparc
	/* determine whether syscall is indirect */
	pri->sys_indirect = (Lsp->pr_reg[R_G1] == SYS_syscall)? 1 : 0;
#else
	pri->sys_indirect = 0;
#endif

	(void) memset(pri->sys_args, 0, sizeof (pri->sys_args));
	if (what != Lsp->pr_syscall) {	/* assertion */
		(void) printf("%s\t*** Inconsistent syscall: %d vs %d ***\n",
		    pri->pname, what, Lsp->pr_syscall);
	}
	nargs = Lsp->pr_nsysarg;
	for (i = 0;
	    i < nargs && i < sizeof (pri->sys_args) / sizeof (pri->sys_args[0]);
	    i++)
		pri->sys_args[i] = Lsp->pr_sysarg[i];
	pri->sys_nargs = nargs;
}

#define	ISREAD(code) \
	((code) == SYS_read || (code) == SYS_pread || \
	(code) == SYS_pread64 || (code) == SYS_readv || \
	(code) == SYS_recv || (code) == SYS_recvfrom)
#define	ISWRITE(code) \
	((code) == SYS_write || (code) == SYS_pwrite || \
	(code) == SYS_pwrite64 || (code) == SYS_writev || \
	(code) == SYS_send || (code) == SYS_sendto)

/*
 * Return TRUE iff syscall is being traced.
 */
int
sysentry(private_t *pri, int dotrace)
{
	pid_t pid = Pstatus(Proc)->pr_pid;
	const lwpstatus_t *Lsp = pri->lwpstat;
	long arg;
	int nargs;
	int i;
	int x;
	int len;
	char *s;
	const struct systable *stp;
	int what = Lsp->pr_what;
	int subcode;
	int istraced;
	int raw;

	/* for reporting sleeping system calls */
	if (what == 0 && (Lsp->pr_flags & (PR_ASLEEP|PR_VFORKP)))
		what = Lsp->pr_syscall;

	/* protect ourself from operating system error */
	if (what <= 0 || what > PRMAXSYS)
		what = 0;

	/*
	 * Set up the system call arguments (pri->sys_nargs & pri->sys_args[]).
	 */
	setupsysargs(pri, what);
	nargs = pri->sys_nargs;

	/* get systable entry for this syscall */
	subcode = getsubcode(pri);
	stp = subsys(what, subcode);

	if (nargs > stp->nargs)
		nargs = stp->nargs;
	pri->sys_nargs = nargs;

	/*
	 * Fetch and remember first argument if it's a string,
	 * or second argument if SYS_openat or SYS_openat64.
	 */
	pri->sys_valid = FALSE;
	if ((nargs > 0 && stp->arg[0] == STG) ||
	    (nargs > 1 && (what == SYS_openat || what == SYS_openat64))) {
		long offset;
		uint32_t offset32;

		/*
		 * Special case for exit from exec().
		 * The address in pri->sys_args[0] refers to the old process
		 * image.  We must fetch the string from the new image.
		 */
		if (Lsp->pr_why == PR_SYSEXIT && what == SYS_execve) {
			psinfo_t psinfo;
			long argv;
			auxv_t auxv[32];
			int naux;

			offset = 0;
			naux = proc_get_auxv(pid, auxv, 32);
			for (i = 0; i < naux; i++) {
				if (auxv[i].a_type == AT_SUN_EXECNAME) {
					offset = (long)auxv[i].a_un.a_ptr;
					break;
				}
			}
			if (offset == 0 &&
			    proc_get_psinfo(pid, &psinfo) == 0) {
				argv = (long)psinfo.pr_argv;
				if (data_model == PR_MODEL_LP64)
					(void) Pread(Proc, &offset,
					    sizeof (offset), argv);
				else {
					offset32 = 0;
					(void) Pread(Proc, &offset32,
					    sizeof (offset32), argv);
					offset = offset32;
				}
			}
		} else if (stp->arg[0] == STG) {
			offset = pri->sys_args[0];
		} else {
			offset = pri->sys_args[1];
		}
		if ((s = fetchstring(pri, offset, PATH_MAX)) != NULL) {
			pri->sys_valid = TRUE;
			len = strlen(s);
			/* reallocate if necessary */
			while (len >= pri->sys_psize) {
				free(pri->sys_path);
				pri->sys_path = my_malloc(pri->sys_psize *= 2,
				    "pathname buffer");
			}
			(void) strcpy(pri->sys_path, s); /* remember pathname */
		}
	}

	istraced = dotrace && prismember(&trace, what);
	raw = prismember(&rawout, what);

	/* force tracing of read/write buffer dump syscalls */
	if (!istraced && nargs > 2) {
		int fdp1 = (int)pri->sys_args[0] + 1;

		if (ISREAD(what)) {
			if (prismember(&readfd, fdp1))
				istraced = TRUE;
		} else if (ISWRITE(what)) {
			if (prismember(&writefd, fdp1))
				istraced = TRUE;
		}
	}

	pri->sys_leng = 0;
	if (cflag || !istraced)		/* just counting */
		*pri->sys_string = 0;
	else {
		int argprinted = FALSE;
		const char *name;

		name = sysname(pri, what, raw? -1 : subcode);
		grow(pri, strlen(name) + 1);
		pri->sys_leng = snprintf(pri->sys_string, pri->sys_ssize,
		    "%s(", name);
		for (i = 0; i < nargs; i++) {
			arg = pri->sys_args[i];
			x = stp->arg[i];

			if (!raw && pri->sys_valid &&
			    ((i == 0 && x == STG) ||
			    (i == 1 && (what == SYS_openat ||
			    what == SYS_openat64)))) {	/* already fetched */
				if (argprinted)
					outstring(pri, ", ");
				escape_string(pri, pri->sys_path);
				argprinted = TRUE;
			} else if (x != NOV && (x != HID || raw)) {
				if (argprinted)
					outstring(pri, ", ");
				if (x == LLO)
					(*Print[x])(pri, raw, arg,
					    pri->sys_args[++i]);
				else
					(*Print[x])(pri, raw, arg);
				argprinted = TRUE;
			}
		}
		outstring(pri, ")");
	}

	return (istraced);
}
#undef	ISREAD
#undef	ISWRITE

/*
 * sysexit() returns non-zero if anything was printed.
 */
int
sysexit(private_t *pri, int dotrace)
{
	const lwpstatus_t *Lsp = pri->lwpstat;
	int what = Lsp->pr_what;
	struct syscount *scp;
	const struct systable *stp;
	int subcode;
	int istraced;
	int raw;

	/* protect ourself from operating system error */
	if (what <= 0 || what > PRMAXSYS)
		return (0);

	/*
	 * If we aren't supposed to be tracing this one, then
	 * delete it from the traced signal set.  We got here
	 * because the process was sleeping in an untraced syscall.
	 */
	if (!prismember(&traceeven, what)) {
		(void) Psysexit(Proc, what, FALSE);
		return (0);
	}

	/* pick up registers & set pri->Errno before anything else */
	pri->Errno = Lsp->pr_errno;
	pri->ErrPriv = Lsp->pr_errpriv;
	pri->Rval1 = Lsp->pr_rval1;
	pri->Rval2 = Lsp->pr_rval2;

	switch (what) {
	case SYS_exit:		/* these are traced on entry */
	case SYS_lwp_exit:
	case SYS_context:
		istraced = dotrace && prismember(&trace, what);
		break;
	case SYS_execve:	/* this is normally traced on entry */
		istraced = dotrace && prismember(&trace, what);
		if (pri->exec_string && *pri->exec_string) {
			if (!cflag && istraced) { /* print exec() string now */
				if (pri->exec_pname[0] != '\0')
					(void) fputs(pri->exec_pname, stdout);
				timestamp(pri);
				(void) fputs(pri->exec_string, stdout);
			}
			pri->exec_pname[0] = '\0';
			pri->exec_string[0] = '\0';
			break;
		}
		/* FALLTHROUGH */
	default:
		/* we called sysentry() in main() for these */
		if (what == SYS_openat || what == SYS_openat64 ||
		    what == SYS_open || what == SYS_open64)
			istraced = dotrace && prismember(&trace, what);
		else
			istraced = sysentry(pri, dotrace) && dotrace;
		pri->length = 0;
		if (!cflag && istraced) {
			putpname(pri);
			timestamp(pri);
			pri->length += printf("%s", pri->sys_string);
		}
		pri->sys_leng = 0;
		*pri->sys_string = '\0';
		break;
	}

	/* get systable entry for this syscall */
	subcode = getsubcode(pri);
	stp = subsys(what, subcode);

	if (cflag && istraced) {
		(void) mutex_lock(&count_lock);
		scp = Cp->syscount[what];
		if (what == SYS_forksys && subcode >= 3)
			scp += subcode - 3;
		else if (subcode != -1 &&
		    (what != SYS_openat && what != SYS_openat64 &&
		    what != SYS_open && what != SYS_open64 &&
		    what != SYS_lwp_create))
			scp += subcode;
		scp->count++;
		accumulate(&scp->stime, &Lsp->pr_stime, &pri->syslast);
		accumulate(&Cp->usrtotal, &Lsp->pr_utime, &pri->usrlast);
		pri->syslast = Lsp->pr_stime;
		pri->usrlast = Lsp->pr_utime;
		(void) mutex_unlock(&count_lock);
	}

	raw = prismember(&rawout, what);

	if (!cflag && istraced) {
		if ((what == SYS_vfork || what == SYS_forksys) &&
		    pri->Errno == 0 && pri->Rval2 != 0) {
			pri->length &= ~07;
			if (strlen(sysname(pri, what, raw? -1 : subcode)) < 6) {
				(void) fputc('\t', stdout);
				pri->length += 8;
			}
			pri->length +=
			    7 + printf("\t(returning as child ...)");
		}
		if (what == SYS_lwp_create &&
		    pri->Errno == 0 && pri->Rval1 == 0) {
			pri->length &= ~07;
			pri->length +=
			    7 + printf("\t(returning as new lwp ...)");
		}
		if (pri->Errno != 0 || what != SYS_execve) {
			/* prepare to print the return code */
			pri->length >>= 3;
			if (pri->length >= 6)
				(void) fputc(' ', stdout);
			for (; pri->length < 6; pri->length++)
				(void) fputc('\t', stdout);
		}
	}
	pri->length = 0;

	if (pri->Errno != 0) {		/* error in syscall */
		if (istraced) {
			if (cflag)
				scp->error++;
			else {
				const char *ename = errname(pri->Errno);
				const char *privname;

				(void) printf("Err#%d", pri->Errno);
				if (ename != NULL) {
					(void) fputc(' ', stdout);
					(void) fputs(ename, stdout);
				}
				switch (pri->ErrPriv) {
				case PRIV_NONE:
					privname = NULL;
					break;
				case PRIV_ALL:
					privname = "ALL";
					break;
				case PRIV_MULTIPLE:
					privname = "MULTIPLE";
					break;
				case PRIV_ALLZONE:
					privname = "ZONE";
					break;
				default:
					privname = priv_getbynum(pri->ErrPriv);
					break;
				}
				if (privname != NULL)
					(void) printf(" [%s]", privname);

				(void) fputc('\n', stdout);
			}
		}
	} else {
		/* show arguments on successful exec */
		if (what == SYS_execve) {
			if (!cflag && istraced)
				showargs(pri, raw);
		} else if (!cflag && istraced) {
			const char *fmt = NULL;
			long rv1 = pri->Rval1;
			long rv2 = pri->Rval2;

			/*
			 * 32-bit system calls return 32-bit values. We
			 * later mask out the upper bits if we want to
			 * print these as unsigned values.
			 */
			if (data_model == PR_MODEL_ILP32) {
				rv1 = (int)rv1;
				rv2 = (int)rv2;
			}

			switch (what) {
			case SYS_llseek:
				rv1 &= 0xffffffff;
				rv2 &= 0xffffffff;
#ifdef _LONG_LONG_LTOH	/* first long of a longlong is the low order */
				if (rv2 != 0) {
					long temp = rv1;
					fmt = "= 0x%lX%.8lX";
					rv1 = rv2;
					rv2 = temp;
					break;
				}
#else	/* the other way around */
				if (rv1 != 0) {
					fmt = "= 0x%lX%.8lX";
					break;
				}
				rv1 = rv2;	/* ugly */
#endif
				/* FALLTHROUGH */
			case SYS_lseek:
			case SYS_ulimit:
				if (rv1 & 0xff000000) {
					if (data_model == PR_MODEL_ILP32)
						rv1 &= 0xffffffff;
					fmt = "= 0x%.8lX";
				}
				break;
			case SYS_sigtimedwait:
				if (raw)
					/* EMPTY */;
				else if ((fmt = rawsigname(pri, rv1)) != NULL) {
					rv1 = (long)fmt;	/* filthy */
					fmt = "= %s";
				}
				break;
			case SYS_port:
				if (data_model == PR_MODEL_LP64) {
					rv2 = rv1 & 0xffffffff;
					rv1 = rv1 >> 32;
				}
				break;
			}

			if (fmt == NULL) {
				switch (stp->rval[0]) {
				case HEX:
					if (data_model == PR_MODEL_ILP32)
						rv1 &= 0xffffffff;
					fmt = "= 0x%.8lX";
					break;
				case HHX:
					if (data_model == PR_MODEL_ILP32)
						rv1 &= 0xffffffff;
					fmt = "= 0x%.4lX";
					break;
				case OCT:
					if (data_model == PR_MODEL_ILP32)
						rv1 &= 0xffffffff;
					fmt = "= %#lo";
					break;
				case UNS:
					if (data_model == PR_MODEL_ILP32)
						rv1 &= 0xffffffff;
					fmt = "= %lu";
					break;
				default:
					fmt = "= %ld";
					break;
				}
			}

			(void) printf(fmt, rv1, rv2);

			switch (stp->rval[1]) {
			case NOV:
				fmt = NULL;
				break;
			case HEX:
				if (data_model == PR_MODEL_ILP32)
					rv2 &= 0xffffffff;
				fmt = " [0x%.8lX]";
				break;
			case HHX:
				if (data_model == PR_MODEL_ILP32)
					rv2 &= 0xffffffff;
				fmt = " [0x%.4lX]";
				break;
			case OCT:
				if (data_model == PR_MODEL_ILP32)
					rv2 &= 0xffffffff;
				fmt = " [%#lo]";
				break;
			case UNS:
				if (data_model == PR_MODEL_ILP32)
					rv2 &= 0xffffffff;
				fmt = " [%lu]";
				break;
			default:
				fmt = " [%ld]";
				break;
			}

			if (fmt != NULL)
				(void) printf(fmt, rv2);
			(void) fputc('\n', stdout);
		}

		if (what == SYS_vfork || what == SYS_forksys) {
			if (pri->Rval2 == 0)		/* child was created */
				pri->child = pri->Rval1;
			else if (cflag && istraced)	/* this is the child */
				scp->count--;
		}
		if (what == SYS_lwp_create && pri->Rval1 == 0 &&
		    cflag && istraced)		/* this is the created lwp */
			scp->count--;
	}

#define	ISREAD(code) \
	((code) == SYS_read || (code) == SYS_pread || (code) == SYS_pread64 || \
	(code) == SYS_recv || (code) == SYS_recvfrom)
#define	ISWRITE(code) \
	((code) == SYS_write || (code) == SYS_pwrite || \
	(code) == SYS_pwrite64 || (code) == SYS_send || (code) == SYS_sendto)

	if (!cflag && istraced) {
		int fdp1 = (int)pri->sys_args[0] + 1; /* filedescriptor + 1 */

		if (raw) {
			if (what != SYS_execve)
				showpaths(pri, stp);
			if (ISREAD(what) || ISWRITE(what)) {
				if (pri->iob_buf[0] != '\0')
					(void) printf("%s     0x%.8lX: %s\n",
					    pri->pname, pri->sys_args[1],
					    pri->iob_buf);
			}
		}

		/*
		 * Show buffer contents for read()/pread() or write()/pwrite().
		 * IOBSIZE bytes have already been shown;
		 * don't show them again unless there's more.
		 */
		if ((ISREAD(what) && pri->Errno == 0 &&
		    prismember(&readfd, fdp1)) ||
		    (ISWRITE(what) && prismember(&writefd, fdp1))) {
			long nb = ISWRITE(what) ? pri->sys_args[2] : pri->Rval1;

			if (nb > IOBSIZE) {
				/* enter region of lengthy output */
				if (nb > MYBUFSIZ / 4)
					Eserialize();

				showbuffer(pri, pri->sys_args[1], nb);

				/* exit region of lengthy output */
				if (nb > MYBUFSIZ / 4)
					Xserialize();
			}
		}
#undef	ISREAD
#undef	ISWRITE
		/*
		 * Do verbose interpretation if requested.
		 * If buffer contents for read or write have been requested and
		 * this is a readv() or writev(), force verbose interpretation.
		 */
		if (prismember(&verbose, what) ||
		    ((what == SYS_readv || what == SYS_recvmsg) &&
		    pri->Errno == 0 && prismember(&readfd, fdp1)) ||
		    ((what == SYS_writev || what == SYS_sendfilev ||
		    what == SYS_sendmsg) &&
		    prismember(&writefd, fdp1)))
			expound(pri, pri->Rval1, raw);
	}

	return (!cflag && istraced);
}

void
showpaths(private_t *pri, const struct systable *stp)
{
	int what = pri->lwpstat->pr_what;
	int i;

	for (i = 0; i < pri->sys_nargs; i++) {
		if (stp->arg[i] == ATC && (int)pri->sys_args[i] == AT_FDCWD) {
			(void) printf("%s     0x%.8X: AT_FDCWD\n",
			    pri->pname, AT_FDCWD);
		} else if ((stp->arg[i] == STG) ||
		    (stp->arg[i] == RST && !pri->Errno) ||
		    (stp->arg[i] == RLK && !pri->Errno && pri->Rval1 > 0)) {
			long addr = pri->sys_args[i];
			int maxleng =
			    (stp->arg[i] == RLK)? (int)pri->Rval1 : PATH_MAX;
			char *s;

			if (pri->sys_valid &&
			    ((i == 0 && stp->arg[0] == STG) ||
			    (i == 1 && (what == SYS_openat ||
			    what == SYS_openat64))))	/* already fetched */
				s = pri->sys_path;
			else
				s = fetchstring(pri, addr,
				    maxleng > PATH_MAX ? PATH_MAX : maxleng);

			if (s != (char *)NULL)
				(void) printf("%s     0x%.8lX: \"%s\"\n",
				    pri->pname, addr, s);
		}
	}
}

/*
 * Display arguments to successful exec().
 */
void
showargs(private_t *pri, int raw)
{
	const lwpstatus_t *Lsp = pri->lwpstat;
	int nargs;
	long ap;
	int ptrsize;
	int fail;

	pri->length = 0;
	ptrsize = (data_model == PR_MODEL_LP64)? 8 : 4;

#if defined(__i386) || defined(__amd64)	/* XX64 */
	ap = (long)Lsp->pr_reg[R_SP];
	fail = (Pread(Proc, &nargs, sizeof (nargs), ap) != sizeof (nargs));
	ap += ptrsize;
#endif /* i386 */

#if sparc
	if (data_model == PR_MODEL_LP64) {
		int64_t xnargs;
		ap = (long)(Lsp->pr_reg[R_SP]) + 16 * sizeof (int64_t)
		    + STACK_BIAS;
		fail = (Pread(Proc, &xnargs, sizeof (xnargs), ap) !=
		    sizeof (xnargs));
		nargs = (int)xnargs;
	} else {
		ap = (long)(Lsp->pr_reg[R_SP]) + 16 * sizeof (int32_t);
		fail = (Pread(Proc, &nargs, sizeof (nargs), ap) !=
		    sizeof (nargs));
	}
	ap += ptrsize;
#endif /* sparc */

	if (fail) {
		(void) printf("\n%s\t*** Bad argument list? ***\n", pri->pname);
		return;
	}

	(void) printf("  argc = %d\n", nargs);
	if (raw)
		showpaths(pri, &systable[SYS_execve]);

	show_cred(pri, FALSE, FALSE);

	if (aflag || eflag) {		/* dump args or environment */

		/* enter region of (potentially) lengthy output */
		Eserialize();

		if (aflag)		/* dump the argument list */
			dumpargs(pri, ap, "argv:");
		ap += (nargs+1) * ptrsize;
		if (eflag)		/* dump the environment */
			dumpargs(pri, ap, "envp:");

		/* exit region of lengthy output */
		Xserialize();
	}
}

void
dumpargs(private_t *pri, long ap, const char *str)
{
	char *string;
	unsigned int leng = 0;
	int ptrsize;
	long arg = 0;
	char *argaddr;
	char badaddr[32];

	if (interrupt)
		return;

	if (data_model == PR_MODEL_LP64) {
		argaddr = (char *)&arg;
		ptrsize = 8;
	} else {
#if defined(_LITTLE_ENDIAN)
		argaddr = (char *)&arg;
#else
		argaddr = (char *)&arg + 4;
#endif
		ptrsize = 4;
	}
	putpname(pri);
	(void) fputc(' ', stdout);
	(void) fputs(str, stdout);
	leng += 1 + strlen(str);

	while (!interrupt) {
		if (Pread(Proc, argaddr, ptrsize, ap) != ptrsize) {
			(void) printf("\n%s\t*** Bad argument list? ***\n",
			    pri->pname);
			return;
		}
		ap += ptrsize;

		if (arg == 0)
			break;
		string = fetchstring(pri, arg, PATH_MAX);
		if (string == NULL) {
			(void) sprintf(badaddr, "BadAddress:0x%.8lX", arg);
			string = badaddr;
		}
		if ((leng += strlen(string)) < 63) {
			(void) fputc(' ', stdout);
			leng++;
		} else {
			(void) fputc('\n', stdout);
			leng = 0;
			putpname(pri);
			(void) fputs("  ", stdout);
			leng += 2 + strlen(string);
		}
		(void) fputs(string, stdout);
	}
	(void) fputc('\n', stdout);
}

/*
 * Display contents of read() or write() buffer.
 */
void
showbuffer(private_t *pri, long offset, long count)
{
	char buffer[320];
	int nbytes;
	char *buf;
	int n;

	while (count > 0 && !interrupt) {
		nbytes = (count < sizeof (buffer))? count : sizeof (buffer);
		if ((nbytes = Pread(Proc, buffer, nbytes, offset)) <= 0)
			break;
		count -= nbytes;
		offset += nbytes;
		buf = buffer;
		while (nbytes > 0 && !interrupt) {
			char obuf[65];

			n = (nbytes < 32)? nbytes : 32;
			showbytes(buf, n, obuf);

			putpname(pri);
			(void) fputs("  ", stdout);
			(void) fputs(obuf, stdout);
			(void) fputc('\n', stdout);
			nbytes -= n;
			buf += n;
		}
	}
}

void
showbytes(const char *buf, int n, char *obuf)
{
	int c;

	while (--n >= 0) {
		int c1 = '\\';
		int c2;

		switch (c = (*buf++ & 0xff)) {
		case '\0':
			c2 = '0';
			break;
		case '\b':
			c2 = 'b';
			break;
		case '\t':
			c2 = 't';
			break;
		case '\n':
			c2 = 'n';
			break;
		case '\v':
			c2 = 'v';
			break;
		case '\f':
			c2 = 'f';
			break;
		case '\r':
			c2 = 'r';
			break;
		default:
			if (isprint(c)) {
				c1 = ' ';
				c2 = c;
			} else {
				c1 = c>>4;
				c1 += (c1 < 10)? '0' : 'A'-10;
				c2 = c&0xf;
				c2 += (c2 < 10)? '0' : 'A'-10;
			}
			break;
		}
		*obuf++ = (char)c1;
		*obuf++ = (char)c2;
	}

	*obuf = '\0';
}
