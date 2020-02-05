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
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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
 * since it is presumed the signal handler wrapper function
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
 * one of the arguments to the signal handler.  We use the thr_sighndlrinfo
 * interface to find the correct frame.
 */

#include "lint.h"
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
#include <stdlib.h>

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

#define	MAX_LINE 2048 /* arbitrary large value */

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
	int	sig;
#if defined(__sparc)
	int	signo = 0;
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
	 * to extract signo from the stack frames.
	 * An awkward interface is provided for this purpose:
	 * thr_sighndlrinfo; this is documented in
	 * /shared/sac/PSARC/1999/024.  When called, this function
	 * returns the PC of a special function (and its size) that
	 * will be present in the stack frame if a signal was
	 * delivered and will have the following signature
	 * __sighndlr(int sig, siginfo_t *si, ucontex_t *uc,
	 *	void (*hndlr)())
	 * Since this function is written in assembler and doesn't
	 * perturb its registers, we can then read sig out of arg0
	 * when the saved pc is inside this function.
	 */
#if defined(__sparc)

	uintptr_t special_pc = (uintptr_t)NULL;
	int special_size = 0;

	extern void thr_sighndlrinfo(void (**func)(), int *funcsize);

	thr_sighndlrinfo((void (**)())&special_pc, &special_size);
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
			 * In the case of threads, since there are multiple
			 * complex routines between kernel and user handler,
			 * we need to figure out where we can read signal from
			 * using thr_sighndlrinfo - which we've already done
			 * for this signal, since it appeared on the stack
			 * before the signal frame.... sigh.
			 */
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

		if (savepc >= special_pc && savepc <
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

/*
 * async safe version of fprintf
 */

static void
async_filenoprintf(int filenum, const char *format, ...)
{
	va_list ap;
	char buffer[MAX_LINE];

	va_start(ap, format);
	(void) vsnprintf(buffer, sizeof (buffer), format, ap);
	va_end(ap);

	(void) write(filenum, buffer, strlen(buffer));

}

/*
 *  print out stack frame info
 */

static int
display_stack_info(uintptr_t pc, int signo, void *arg)
{

	char buffer[MAX_LINE];
	char sigbuf[SIG2STR_MAX];


	int filenum = (intptr_t)arg;

	(void) addrtosymstr((void *)pc, buffer, sizeof (buffer));

	if (signo) {
		sigbuf[0] = '?';
		sigbuf[1] = 0;

		(void) sig2str(signo, sigbuf);

		async_filenoprintf(filenum, "%s [Signal %d (%s)]\n",
		    buffer, (ulong_t)signo, sigbuf);
	} else
		async_filenoprintf(filenum, "%s\n", buffer);

	return (0);
}

/*
 * walk current thread stack, writing symbolic stack trace to specified fd
 */

int
printstack(int dofd)
{
	ucontext_t u;

	if (getcontext(&u) < 0)
		return (-1);

	return (walkcontext(&u, display_stack_info, (void*)(intptr_t)dofd));
}

/*
 * Some routines for better opensource compatibility w/ glibc.
 */

typedef struct backtrace {
	void	**bt_buffer;
	int	bt_maxcount;
	int	bt_actcount;
} backtrace_t;

/* ARGSUSED */
static int
callback(uintptr_t pc, int signo, void *arg)
{
	backtrace_t *bt = (backtrace_t *)arg;

	if (bt->bt_actcount >= bt->bt_maxcount)
		return (-1);

	bt->bt_buffer[bt->bt_actcount++] = (void *)pc;

	return (0);
}

/*
 * dump stack trace up to length count into buffer
 */

int
backtrace(void **buffer, int count)
{
	backtrace_t	bt;
	ucontext_t	u;

	bt.bt_buffer = buffer;
	bt.bt_maxcount = count;
	bt.bt_actcount = 0;

	if (getcontext(&u) < 0)
		return (0);

	(void) walkcontext(&u, callback, &bt);

	return (bt.bt_actcount);
}

/*
 * format backtrace string
 */

int
addrtosymstr(void *pc, char *buffer, int size)
{
	Dl_info info;
	Sym *sym;

	if (dladdr1(pc, &info, (void **)&sym,
	    RTLD_DL_SYMENT) == 0) {
		return (snprintf(buffer, size, "[0x%p]", pc));
	}

	if ((info.dli_fname != NULL && info.dli_sname != NULL) &&
	    ((uintptr_t)pc - (uintptr_t)info.dli_saddr < sym->st_size)) {
		/*
		 * we have containing symbol info
		 */
		return (snprintf(buffer, size, "%s'%s+0x%x [0x%p]",
		    info.dli_fname,
		    info.dli_sname,
		    (unsigned long)pc - (unsigned long)info.dli_saddr,
		    pc));
	} else {
		/*
		 * no local symbol info
		 */
		return (snprintf(buffer, size, "%s'0x%p [0x%p]",
		    info.dli_fname,
		    (unsigned long)pc - (unsigned long)info.dli_fbase,
		    pc));
	}
}

/*
 * This function returns the symbolic representation of stack trace; calls
 * malloc so it is NOT async safe!  A rather mis-designed and certainly misused
 * interface.
 */

char **
backtrace_symbols(void *const *array, int size)
{
	int bufferlen, len;
	char **ret_buffer;
	char **ret;
	char linebuffer[MAX_LINE];
	int i;

	bufferlen = size * sizeof (char *);

	/*
	 *  tmp buffer to hold strings while finding all symbol names
	 */

	ret_buffer = (char **)alloca(bufferlen);

	for (i = 0; i < size; i++) {
		(void) addrtosymstr(array[i], linebuffer, sizeof (linebuffer));
		ret_buffer[i] = strcpy(alloca(len = strlen(linebuffer) + 1),
		    linebuffer);
		bufferlen += len;
	}

	/*
	 * allocate total amount of storage required and copy strings
	 */

	if ((ret = (char **)malloc(bufferlen)) == NULL)
		return (NULL);


	for (len = i = 0; i < size; i++) {
		ret[i] = (char *)ret + size * sizeof (char *) + len;
		(void) strcpy(ret[i], ret_buffer[i]);
		len += strlen(ret_buffer[i]) + 1;
	}

	return (ret);
}

/*
 * Write out symbolic stack trace in an async-safe way.
 */

void
backtrace_symbols_fd(void *const *array, int size, int fd)
{
	char linebuffer[MAX_LINE];
	int i;
	int len;

	for (i = 0; i < size; i++) {
		len = addrtosymstr(array[i], linebuffer,
		    sizeof (linebuffer) - 1);
		if (len >= sizeof (linebuffer))
			len = sizeof (linebuffer) - 1;
		linebuffer[len] = '\n';
		(void) write(fd, linebuffer, len + 1);
	}
}
