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
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file provides a general purpose mechanism
 * for a user thread to walk its own call stack,
 * calling a user-specified iterator function for each
 * stack frame.  Special handling is provided to indicate
 * kernel-constructed signal handler frames.
 *
 * Adapted from usr/src/lib/libproc/common/Pstack.c:
 *
 * A signal handler frame is essentially a set of data pushed on to the user
 * stack by the kernel prior to returning to the user program in one of the
 * pre-defined signal handlers.  The signal handler itself receives the signal
 * number, an optional pointer to a siginfo_t, and a pointer to the interrupted
 * ucontext as arguments.
 *
 * When performing a stack backtrace, we would like to
 * detect these frames so that we can correctly return the interrupted program
 * counter and frame pointer as a separate frame.
 *
 * The stack layout for a signal handler frame is as follows:
 *
 * SPARC v7/v9:                           Intel ia32:
 * +--------------+ -        high         +--------------+ -
 * |  struct fq   | ^        addrs        |  siginfo_t   | optional
 * +--------------+ |          ^          +--------------+ -
 * |  gwindows_t  |            |          |  ucontext_t  | ^
 * +--------------+ optional              +--------------+ |
 * |  siginfo_t   |                       | ucontext_t * | |
 * +--------------+ |          |          +--------------+
 * |  xregs data  | v          v          |  siginfo_t * | mandatory
 * +--------------+ -         low         +--------------+
 * |  ucontext_t  | ^        addrs        |  int (signo) | |
 * +--------------+ mandatory             +--------------+ |
 * | struct frame | v                     | struct frame | v
 * +--------------+ - <- %sp on resume    +--------------+ - <- %esp on resume
 *
 * amd64 (64-bit)
 * +--------------+ -
 * |  siginfo_t   | optional
 * +--------------+ -
 * |  ucontext_t  | ^
 * +--------------+ |
 * |  siginfo_t * |
 * +--------------+ mandatory
 * |  int (signo) |
 * +--------------+ |
 * | struct frame | v
 * +--------------+ - <- %rsp on resume
 *
 * The bottom-most struct frame is actually constructed by the kernel by
 * copying the previous stack frame, allowing naive backtrace code to simply
 * skip over the interrupted frame.  The copied frame is never really used,
 * since it is presumed the libc or libthread signal handler wrapper function
 * will explicitly setcontext(2) to the interrupted context if the user
 * program's handler returns.  If we detect a signal handler frame, we simply
 * read the interrupted context structure from the stack, use its embedded
 * gregs to construct the register set for the interrupted frame, and then
 * continue our backtrace.  Detecting the frame itself is easy according to
 * the diagram ("oldcontext" represents any element in the uc_link chain):
 *
 * On SPARC v7 or v9:
 * %fp + sizeof (struct frame) == oldcontext
 *
 * On i386:
 * %ebp + sizeof (struct frame) + (3 words) == oldcontext
 *
 * On amd64:
 * %rbp + sizeof (struct frame) + (2 words) == oldcontext
 *
 * Since we want to provide the signal number that generated a signal stack
 * frame and on sparc this information isn't written to the stack by the kernel
 * the way it's done on i386, we're forced to read the signo from the stack as
 * one of the arguments to the signal handler.  What we hope is that no one has
 * used __sigaction directly; if we're not linked with libthread
 * (_thr_sighndlrinfo is NULL) then we attempt to read the signo directly from
 * the register window. Otherwise we use the _thr_sighndlrinfo interface to find
 * the correct frame.
 *
 */

#pragma weak walkcontext = _walkcontext
#pragma weak printstack = _printstack

#include "synonyms.h"
#include <assert.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <procfs.h>
#include <strings.h>
#include <signal.h>
#include <sys/frame.h>
#include <sys/regset.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <thread.h>
#include <ucontext.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/stack.h>
#include <errno.h>
#include <stdio.h>
#include <alloca.h>
#include <limits.h>

#ifdef _LP64
#define	_ELF64
#endif

#include <sys/machelf.h>


#if defined(__sparc)
#define	FRAME_PTR_REGISTER REG_SP
#define	PC_REGISTER REG_PC
#define	CHECK_FOR_SIGFRAME(fp, oldctx) ((fp) + SA(sizeof (struct frame)) \
	== (oldctx))

#elif defined(__amd64)
#define	FRAME_PTR_REGISTER	REG_RBP
#define	PC_REGISTER		REG_RIP
#define	CHECK_FOR_SIGFRAME(fp, oldctx) ((((fp) + sizeof (struct frame)) + \
	2 * sizeof (long) == (oldctx)) && \
	(((struct frame *)fp)->fr_savpc == (greg_t)-1))

#elif defined(__i386)
#define	FRAME_PTR_REGISTER EBP
#define	PC_REGISTER EIP
#define	CHECK_FOR_SIGFRAME(fp, oldctx) ((((fp) + sizeof (struct frame)) + \
	3 * sizeof (int) == (oldctx)) && \
	(((struct frame *)fp)->fr_savpc == (greg_t)-1))
#else
#error no arch defined
#endif


/*
 * use /proc/self/as to safely dereference pointers so we don't
 * die in the case of a stack smash
 */

static int
read_safe(int fd, struct frame *fp, struct frame **savefp, uintptr_t *savepc)
{

	uintptr_t newfp;

	if ((uintptr_t)fp & (sizeof (void *) - 1))
		return (-1); /* misaligned */

	if ((pread(fd, (void *)&newfp, sizeof (fp->fr_savfp),
	    (off_t)&fp->fr_savfp) != sizeof (fp->fr_savfp)) ||
	    pread(fd, (void *)savepc, sizeof (fp->fr_savpc),
	    (off_t)&fp->fr_savpc) != sizeof (fp->fr_savpc))
		return (-1);

	/*
	 * handle stack bias on sparcv9
	 */

	if (newfp != 0)
		newfp += STACK_BIAS;

	*savefp = (struct frame *)newfp;

	return (0);
}

int
walkcontext(const ucontext_t *uptr, int (*operate_func)(uintptr_t, int, void *),
    void *usrarg)
{
	ucontext_t *oldctx = uptr->uc_link;

	int	fd;
	int 	sig;
#if defined(__sparc)
	int 	signo = 0;
#endif

	struct frame *savefp;
	uintptr_t savepc;

	/*
	 * snag frame point from ucontext... we'll see caller of
	 * getucontext since we'll start by working up the call
	 * stack by one
	 */

	struct frame *fp = (struct frame *)
	    ((uintptr_t)uptr->uc_mcontext.gregs[FRAME_PTR_REGISTER] +
	    STACK_BIAS);

	/*
	 * Since we don't write signo to the stack on sparc, we need
	 * to extract signo from the stack frames.  This is problematic
	 * in the case of libthread (libc has deterministic behavior)
	 * since we're not sure where we can do that safely.  An awkward
	 * interface was provided for this purpose in libthread:
	 * _thr_sighndlrinfo; this is documented in
	 * /shared/sac/PSARC/1999/024.  When called, this function
	 * returns the PC of a special function (and its size) that
	 * will be present in the stack frame if a signal was
	 * delivered and will have the following signature
	 * __sighndlr(int sig, siginfo_t *si, ucontex_t *uc,
	 *	void (*hndlr)())
	 * Since this function is written in assembler and doesn't
	 * perturb its registers, we can then read sig out of arg0
	 * when the saved pc is inside this function.
	 *
	 */
#if defined(__sparc)

	uintptr_t special_pc = NULL;
	int special_size = 0;

	extern void _thr_sighndlrinfo(void (**func)(), int *funcsize);

#pragma weak _thr_sighndlrinfo

	if (_thr_sighndlrinfo != NULL) {
		_thr_sighndlrinfo((void (**)())&special_pc, &special_size);
	}
#endif /* sparc */


	if ((fd = open("/proc/self/as", O_RDONLY)) < 0)
		return (-1);

	while (fp != NULL) {

		sig = 0;

		/*
		 * get value of saved fp and pc w/o crashing
		 */

		if (read_safe(fd, fp, &savefp, &savepc) != 0) {
			(void) close(fd);
			return (-1);
		}

		if (savefp == NULL)
			break;

		/*
		 * note that the following checks to see if we've got a
		 * special signal stack frame present; this allows us to
		 * detect signals and pass that info to the user stack walker
		 */

		if (oldctx != NULL &&
		    CHECK_FOR_SIGFRAME((uintptr_t)savefp, (uintptr_t)oldctx)) {

#if defined(__i386) || defined(__amd64)
			/*
			 * i386 and amd64 store signo on stack;
			 * simple to detect and use
			 */
			sig = *((int *)(savefp + 1));
#endif

#if defined(__sparc)
			/*
			 * with sparc we need to handle
			 * single and multi-threaded cases
			 * separately
			 * If we're single threaded, the trampoline
			 * in libc will have the signo as the first
			 * argumment; we can snag that directly.
			 * In the case of threads, since there are multiple
			 * complex routines between kernel and user handler,
			 * we need to figure out where we can read signal from
			 * using _thr_sighndlrinfo - which we've already done
			 * for this signal, since it appeared on the stack
			 * before the signal frame.... sigh.
			 */

			if (_thr_sighndlrinfo == NULL) /* single threaded */
				sig = fp->fr_arg[0];
			else
				sig = signo; /* already read - see below */
#endif
			/*
			 * this is the special signal frame, so cons up
			 * the saved fp & pc to pass to user's function
			 */

			savefp = (struct frame *)
			    ((uintptr_t)oldctx->
			    uc_mcontext.gregs[FRAME_PTR_REGISTER] +
			    STACK_BIAS);
			savepc = oldctx->uc_mcontext.gregs[PC_REGISTER];

			oldctx = oldctx->uc_link; /* handle nested signals */
		}
#if defined(__sparc)

		/*
		 * lookahead code to find right spot to read signo from...
		 */

		if (_thr_sighndlrinfo &&
		    savepc >= special_pc && savepc <
		    (special_pc + special_size))
			signo = fp->fr_arg[0];
#endif

		/*
		 * call user-supplied function and quit if non-zero return.
		 */

		if (operate_func((uintptr_t)savepc, sig, usrarg) != 0)
			break;

		fp = savefp; /* up one in the call stack */
	}

	(void) close(fd);
	return (0);
}

static size_t
ulongtos(char *buffer, unsigned long x, int base)
{
	char local[80];
	static const char digits[] = "0123456789abcdef";

	unsigned int n = sizeof (local) - 1;
	unsigned long rem;
	unsigned int  mod;

	local[n] = 0;

	rem = x;

	do {
		switch (base) {
		case 10:
			mod = rem % 10;
			rem = rem / 10;
			break;

		case 16:
			mod = rem & 15;
			rem = rem >> 4;
			break;
		default:
			return (0);
		}
		local[--n] = digits[mod];
	} while (rem != 0);

	(void) strcpy(buffer, local + n);

	return (sizeof (local) - n - 1);
}

static void
async_filenoprintf(int filenum, const char *format, ...)
{
	const char *src = format;
	va_list ap;
	long i;
	struct iovec *iov;
	int cnt;
	int iter = 0;

	/*
	 * count # of %'s.. max # of iovs is 2n + 1
	 */

	for (cnt = i = 0; src[i] != '\0'; i++)
		if (src[i] == '%')
			cnt++;

	iov = alloca((2 * cnt + 1) * sizeof (struct iovec));

	va_start(ap, format);


	while (*src) {

		iov[iter].iov_base = (char *)src;
		iov[iter].iov_len = 0;

		while (*src && *src != '%') {
			iov[iter].iov_len++;
			src++;
		}

		if (iov[iter].iov_len != 0)
			iter++;

		if (*src == '%') {
			switch (*++src) {
			case 's':
				iov[iter].iov_base = va_arg(ap, char *);
				iov[iter].iov_len = strlen(iov[iter].iov_base);
				iter++;
				break;
			case 'd':
				iov[iter].iov_base = alloca(24);

				i = va_arg(ap, long);
				if (i < 0) {
					*iov[iter].iov_base = '-';
					iov[iter].iov_len =
					    ulongtos(iov[iter].iov_base + 1,
					    -i, 10) + 1;
				} else
					iov[iter].iov_len =
					    ulongtos(iov[iter].iov_base,
					    i, 10);
				iter++;
				break;
			case 'x':
				iov[iter].iov_base = alloca(24);
				iov[iter].iov_len = ulongtos(iov[iter].iov_base,
				    va_arg(ap, unsigned long), 16);
				iter++;
				break;

			case '%':
				iov[iter].iov_base = (char *)src;
				iov[iter].iov_len = 1;
				iter++;
				break;
			}
			src++;
		}
	}
	va_end(ap);

	(void) writev(filenum, iov, iter);

}

static int
display_stack_info(uintptr_t pc, int signo, void *arg)
{
	Dl_info info;

	char sigbuf[SIG2STR_MAX];

	Sym *sym;

	int filenum = (intptr_t)arg;

	if (signo) {
		if (sig2str(signo, sigbuf) != 0)
			(void) strcpy(sigbuf, "?");
	}

	if (dladdr1((void *) pc, &info, (void**) &sym, RTLD_DL_SYMENT) == 0) {
		/* no info at all */
		if (signo == 0)
			async_filenoprintf(filenum, "0x%x\n", pc);
		else
			async_filenoprintf(filenum,
			    "0x%x [ Signal %d (%s)]\n", pc,
			    (ulong_t)signo, sigbuf);

	} else if ((pc - (unsigned long)info.dli_saddr) <
	    sym->st_size) {
		/* found a global symbol */
		if (signo == 0)
			async_filenoprintf(filenum, "%s:%s+0x%x\n",
			    info.dli_fname,
			    info.dli_sname,
			    pc - (unsigned long)info.dli_saddr);
		else
			async_filenoprintf(filenum,
			    "%s:%s+0x%x [ Signal %d (%s)]\n",
			    info.dli_fname,
			    info.dli_sname,
			    pc - (unsigned long)info.dli_saddr,
			    (ulong_t)signo, sigbuf);
	} else {
		/* found a static symbol */
		if (signo == 0)
			async_filenoprintf(filenum, "%s:0x%x\n",
			    info.dli_fname,
			    pc - (unsigned long)info.dli_fbase);
		else
			async_filenoprintf(filenum,
			    "%s:0x%x [ Signal %d (%s)]\n",
			    info.dli_fname,
			    pc - (unsigned long)info.dli_fbase,
			    (ulong_t)signo, sigbuf);
	}

	return (0);
}

int
printstack(int dofd)
{
	ucontext_t u;

	if (getcontext(&u) < 0)
		return (-1);

	return (walkcontext(&u, display_stack_info, (void*)(intptr_t)dofd));
}
