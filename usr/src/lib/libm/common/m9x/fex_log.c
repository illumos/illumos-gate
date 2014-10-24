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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma weak __fex_get_log = fex_get_log
#pragma weak __fex_set_log = fex_set_log
#pragma weak __fex_get_log_depth = fex_get_log_depth
#pragma weak __fex_set_log_depth = fex_set_log_depth
#pragma weak __fex_log_entry = fex_log_entry

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>
#include <sys/frame.h>
#include <fenv.h>
#include <sys/ieeefp.h>
#include <thread.h>
#include "fex_handler.h"

#if !defined(PC)
#if defined(REG_PC)
#define	PC	REG_PC
#else
#error Neither PC nor REG_PC is defined!
#endif
#endif

static FILE *log_fp = NULL;
static mutex_t log_lock = DEFAULTMUTEX;
static int log_depth = 100;

FILE *fex_get_log(void)
{
	FILE	*fp;

	mutex_lock(&log_lock);
	fp = log_fp;
	mutex_unlock(&log_lock);
	return fp;
}

int fex_set_log(FILE *fp)
{
	mutex_lock(&log_lock);
	log_fp = fp;
	mutex_unlock(&log_lock);
	__fex_update_te();
	return 1;
}

int fex_get_log_depth(void)
{
	int	d;

	mutex_lock(&log_lock);
	d = log_depth;
	mutex_unlock(&log_lock);
	return d;
}

int fex_set_log_depth(int d)
{
	if (d < 0)
		return 0;
	mutex_lock(&log_lock);
	log_depth = d;
	mutex_unlock(&log_lock);
	return 1;
}

static struct exc_list {
	struct exc_list		*next;
	char			*addr;
	unsigned long		code;
	int			nstack;
	char			*stack[1]; /* actual length is max(1,nstack) */
} *list = NULL;

#ifdef __sparcv9
#define FRAMEP(X)	(struct frame *)((char*)(X)+(((long)(X)&1)?2047:0))
#else
#define FRAMEP(X)	(struct frame *)(X)
#endif

#ifdef _LP64
#define PDIG		"16"
#else
#define PDIG		"8"
#endif

/* look for a matching exc_list; return 1 if one is found,
   otherwise add this one to the list and return 0 */
static int check_exc_list(char *addr, unsigned long code, char *stk,
    struct frame *fp)
{
	struct exc_list	*l, *ll = NULL;
	struct frame	*f;
	int		i, n;

	if (list) {
		for (l = list; l; ll = l, l = l->next) {
			if (l->addr != addr || l->code != code)
				continue;
			if (log_depth < 1 || l->nstack < 1)
				return 1;
			if (l->stack[0] != stk)
				continue;
			n = 1;
			for (i = 1, f = fp; i < log_depth && i < l->nstack &&
			    f && f->fr_savpc; i++, f = FRAMEP(f->fr_savfp))
				if (l->stack[i] != (char *)f->fr_savpc) {
					n = 0;
					break;
				}
			if (n)
				return 1;
		}
	}

	/* create a new exc_list structure and tack it on the list */
	for (n = 1, f = fp; n < log_depth && f && f->fr_savpc;
	    n++, f = FRAMEP(f->fr_savfp)) ;
	if ((l = (struct exc_list *)malloc(sizeof(struct exc_list) +
	    (n - 1) * sizeof(char *))) != NULL) {
		l->next = NULL;
		l->addr = addr;
		l->code = code;
		l->nstack = ((log_depth < 1)? 0 : n);
		l->stack[0] = stk;
		for (i = 1; i < n; i++) {
			l->stack[i] = (char *)fp->fr_savpc;
			fp = FRAMEP(fp->fr_savfp);
		}
		if (list)
			ll->next = l;
		else
			list = l;
	}
	return 0;
}

/*
* Warning: cleverness ahead
*
* In the following code, the use of sprintf+write rather than fprintf
* to send output to the log file is intentional.  The reason is that
* fprintf is not async-signal-safe.  "But," you protest, "SIGFPE is
* not an asynchronous signal!  It's always handled by the same thread
* that executed the fpop that provoked it."  That's true, but a prob-
* lem arises because (i) base conversion in fprintf can cause a fp
* exception and (ii) my signal handler acquires a mutex lock before
* sending output to the log file (so that outputs for entries from
* different threads aren't interspersed).  Therefore, if the code
* were to use fprintf, a deadlock could occur as follows:
*
*	Thread A			Thread B
*
*	Incurs a fp exception,		Calls fprintf,
*	acquires log_lock		acquires file rmutex lock
*
*	Calls fprintf,			Incurs a fp exception,
*	waits for file rmutex lock	waits for log_lock
*
* (I could just verify that fprintf doesn't hold the rmutex lock while
* it's doing the base conversion, but since efficiency is of little
* concern here, I opted for the safe and dumb route.)
*/

static void print_stack(int fd, char *addr, struct frame *fp)
{
	int	i;
	char	*name, buf[30];

	for (i = 0; i < log_depth && addr != NULL; i++) {
		if (__fex_sym(addr, &name) != NULL) {
			write(fd, buf, sprintf(buf, "  0x%0" PDIG "lx  ",
			    (long)addr));
			write(fd, name, strlen(name));
			write(fd, "\n", 1);
			if (!strcmp(name, "main"))
				break;
		} else {
			write(fd, buf, sprintf(buf, "  0x%0" PDIG "lx\n",
			    (long)addr));
		}
		if (fp == NULL)
			break;
		addr = (char *)fp->fr_savpc;
		fp = FRAMEP(fp->fr_savfp);
	}
}

void fex_log_entry(const char *msg)
{
	ucontext_t	uc;
	struct frame	*fp;
	char		*stk;
	int		fd;

	/* if logging is disabled, just return */
	mutex_lock(&log_lock);
	if (log_fp == NULL) {
		mutex_unlock(&log_lock);
		return;
	}

	/* get the frame pointer from the current context and
	   pop our own frame */
	getcontext(&uc);
#if defined(__sparc) || defined(__amd64)
	fp = FRAMEP(uc.uc_mcontext.gregs[REG_SP]);
#elif defined(__i386)	/* !defined(__amd64) */
	fp = FRAMEP(uc.uc_mcontext.gregs[EBP]);
#else
#error Unknown architecture
#endif
	if (fp == NULL) {
		mutex_unlock(&log_lock);
		return;
	}
	stk = (char *)fp->fr_savpc;
	fp = FRAMEP(fp->fr_savfp);

	/* if we've already logged this message here, don't make an entry */
	if (check_exc_list(stk, (unsigned long)msg, stk, fp)) {
		mutex_unlock(&log_lock);
		return;
	}

	/* make an entry */
	fd = fileno(log_fp);
	write(fd, "fex_log_entry: ", 15);
	write(fd, msg, strlen(msg));
	write(fd, "\n", 1);
	__fex_sym_init();
	print_stack(fd, stk, fp);
	mutex_unlock(&log_lock);
}

static const char *exception[FEX_NUM_EXC] = {
	"inexact result",
	"division by zero",
	"underflow",
	"overflow",
	"invalid operation (0/0)",
	"invalid operation (inf/inf)",
	"invalid operation (inf-inf)",
	"invalid operation (0*inf)",
	"invalid operation (sqrt)",
	"invalid operation (snan)",
	"invalid operation (int)",
	"invalid operation (cmp)"
};

void
__fex_mklog(ucontext_t *uap, char *addr, int f, enum fex_exception e,
    int m, void *p)
{
	struct	frame	*fp;
	char		*stk, *name, buf[30];
	int		fd;

	/* if logging is disabled, just return */
	mutex_lock(&log_lock);
	if (log_fp == NULL) {
		mutex_unlock(&log_lock);
		return;
	}

	/* get stack info */
#if defined(__sparc)
	stk = (char*)uap->uc_mcontext.gregs[REG_PC];
	fp = FRAMEP(uap->uc_mcontext.gregs[REG_SP]);
#elif defined(__amd64)
	stk = (char*)uap->uc_mcontext.gregs[REG_PC];
	fp = FRAMEP(uap->uc_mcontext.gregs[REG_RBP]);
#elif defined(__i386)	/* !defined(__amd64) */
	stk = (char*)uap->uc_mcontext.gregs[PC];
	fp = FRAMEP(uap->uc_mcontext.gregs[EBP]);
#else
#error Unknown architecture
#endif

	/* if the handling mode is the default and this exception's
	   flag is already raised, don't make an entry */
	if (m == FEX_NONSTOP) {
		switch (e) {
		case fex_inexact:
			if (f & FE_INEXACT) {
				mutex_unlock(&log_lock);
				return;
			}
			break;
		case fex_underflow:
			if (f & FE_UNDERFLOW) {
				mutex_unlock(&log_lock);
				return;
			}
			break;
		case fex_overflow:
			if (f & FE_OVERFLOW) {
				mutex_unlock(&log_lock);
				return;
			}
			break;
		case fex_division:
			if (f & FE_DIVBYZERO) {
				mutex_unlock(&log_lock);
				return;
			}
			break;
		default:
			if (f & FE_INVALID) {
				mutex_unlock(&log_lock);
				return;
			}
			break;
		}
	}

	/* if we've already logged this exception at this address,
	   don't make an entry */
	if (check_exc_list(addr, (unsigned long)e, stk, fp)) {
		mutex_unlock(&log_lock);
		return;
	}

	/* make an entry */
	fd = fileno(log_fp);
	write(fd, "Floating point ", 15);
	write(fd, exception[e], strlen(exception[e]));
	write(fd, buf, sprintf(buf, " at 0x%0" PDIG "lx", (long)addr));
	__fex_sym_init();
	if (__fex_sym(addr, &name) != NULL) {
		write(fd, " ", 1);
		write(fd, name, strlen(name));
	}
	switch (m) {
	case FEX_NONSTOP:
		write(fd, ", nonstop mode\n", 15);
		break;

	case FEX_ABORT:
		write(fd, ", abort\n", 8);
		break;

	case FEX_NOHANDLER:
		if (p == (void *)SIG_DFL) {
			write(fd, ", handler: SIG_DFL\n", 19);
			break;
		}
		else if (p == (void *)SIG_IGN) {
			write(fd, ", handler: SIG_IGN\n", 19);
			break;
		}
		/* fall through*/
	default:
		write(fd, ", handler: ", 11);
		if (__fex_sym((char *)p, &name) != NULL) {
			write(fd, name, strlen(name));
			write(fd, "\n", 1);
		} else {
			write(fd, buf, sprintf(buf, "0x%0" PDIG "lx\n",
			    (long)p));
		}
		break;
	}
	print_stack(fd, stk, fp);
	mutex_unlock(&log_lock);
}
