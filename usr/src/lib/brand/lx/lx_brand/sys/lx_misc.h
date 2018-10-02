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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2018 Joyent, Inc.
 */

#ifndef _SYS_LX_H
#define	_SYS_LX_H

#include <stdio.h>
#include <alloca.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/lwp.h>

#include <sys/lx_brand.h>
#include <sys/lx_thread.h>

#include <lx_errno.h>

#ifdef __cplusplus
extern "C" {
#endif

extern char lx_release[LX_KERN_RELEASE_MAX];
extern char lx_cmd_name[MAXNAMLEN];
extern pid_t zoneinit_pid;
extern int lx_is_vforked;
extern boolean_t lx_no_abort_handler;

/*
 * Values Linux expects for init
 */
#define	LX_INIT_PID	1

/*
 * the maximum length of messages to be output with lx_msg(), lx_err(),
 * lx_debug(), or lx_unsupported().
 */
#define	LX_MSG_MAXLEN			(128 + MAXPATHLEN)

/*
 * Linux scheduler priority ranges.
 */
#define	LX_SCHED_PRIORITY_MIN_OTHER	0
#define	LX_SCHED_PRIORITY_MAX_OTHER	0
#define	LX_SCHED_PRIORITY_MIN_RRFIFO	1
#define	LX_SCHED_PRIORITY_MAX_RRFIFO	99

/*
 * Based on code from brand_misc.h, but use of that is incompatible with the
 * lx brand.
 *
 * These macros invoke a brandsys subcommand, B_TRUSS_POINT, which makes it
 * easy to debug with DTrace.
 */
#define	B_TRUSS_POINT	6

#define	B_TRACE_POINT_5(a0, a1, a2, a3, a4) \
	(void) syscall(SYS_brand, B_TRUSS_POINT, (a0), (a1), (a2), (a3), (a4))

#define	B_TRACE_POINT_4(a0, a1, a2, a3) \
	B_TRACE_POINT_5((a0), (a1), (a2), (a3), 0)

#define	B_TRACE_POINT_3(a0, a1, a2) \
	B_TRACE_POINT_5((a0), (a1), (a2), 0, 0)

#define	B_TRACE_POINT_2(a0, a1) \
	B_TRACE_POINT_5((a0), (a1), 0, 0, 0)

#define	B_TRACE_POINT_1(a0) \
	B_TRACE_POINT_5((a0), 0, 0, 0, 0)

#define	B_TRACE_POINT_0() \
	B_TRACE_POINT_5(0, 0, 0, 0, 0)

/*
 * Macros to access register state within a ucontext_t:
 */
#define	LX_REG(ucp, r)	((ucp)->uc_mcontext.gregs[(r)])

/*
 * normally we never want to write to stderr or stdout because it's unsafe
 * to make assumptions about the underlying file descriptors.  to protect
 * against writes to these file descriptors we go ahead and close them
 * our brand process initalization code.  but there are still occasions
 * where we are willing to make assumptions about our file descriptors
 * and write to them.  at thes times we should use one lx_msg() or
 * lx_msg_error()
 */
extern void lx_msg(char *, ...);
extern void lx_err(char *, ...);
extern void lx_err_fatal(char *, ...);
extern void lx_unsupported(char *, ...);

struct ucontext;

extern ucontext_t *lx_syscall_regs(void);
extern uintptr_t lx_find_brand_sp(void);
extern const ucontext_t *lx_find_brand_uc(void);

extern void lx_jump_to_linux(ucontext_t *) __NORETURN;

extern char *lx_fd_to_path(int fd, char *buf, int buf_size);
extern int lx_lpid_to_spair(pid_t, pid_t *, lwpid_t *);
extern int lx_lpid_to_spid(pid_t, pid_t *);

extern void lx_ptrace_init();
extern int lx_ptrace_wait(siginfo_t *);
extern void lx_ptrace_fork(void);
extern void lx_ptrace_stop_if_option(int, boolean_t, ulong_t msg, ucontext_t *);
extern void lx_ptrace_clone_begin(int, boolean_t, int);

extern int lx_check_alloca(size_t);
#define	SAFE_ALLOCA(sz)	(lx_check_alloca(sz) ? alloca(sz) : NULL)

extern void lx_init_tsd(lx_tsd_t *);
extern int lx_alloc_stack(void **, size_t *);
extern void lx_install_stack(void *, size_t, lx_tsd_t *);
extern void lx_free_stack(void);
extern void lx_free_other_stacks(void);
extern void lx_stack_prefork(void);
extern void lx_stack_postfork(void);

extern void lx_block_all_signals();
extern void lx_unblock_all_signals();
extern int lx_all_signals_blocked();

/*
 * NO_UUCOPY disables calls to the uucopy* system calls to help with
 * debugging brand library accesses to linux application memory.
 */
#ifdef NO_UUCOPY

int uucopy_unsafe(const void *src, void *dst, size_t n);
int uucopystr_unsafe(const void *src, void *dst, size_t n);

#define	uucopy(src, dst, n)	uucopy_unsafe((src), (dst), (n))
#define	uucopystr(src, dst, n)	uucopystr_unsafe((src), (dst), (n))

#endif /* NO_UUCOPY */

/*
 * We use these Private libc interfaces to defer signals during critical
 * sections.
 */
extern void _sigon(void);
extern void _sigoff(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LX_H */
