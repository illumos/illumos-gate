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

#ifndef _SYS_LX_H
#define	_SYS_LX_H

#include <stdio.h>
#include <alloca.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/lwp.h>

#include <sys/lx_brand.h>

#ifdef __cplusplus
extern "C" {
#endif

extern char lx_release[128];
extern pid_t zoneinit_pid;

/*
 * Support for the unfortunate RPM race condition workaround.
 */
extern int lx_rpm_delay;
extern boolean_t lx_is_rpm;

/*
 * Values Linux expects for init
 */
#define	LX_INIT_PGID	0
#define	LX_INIT_SID	0
#define	LX_INIT_PID	1

/*
 * Codes to reboot(2).
 */
#define	LINUX_REBOOT_MAGIC1		0xfee1dead
#define	LINUX_REBOOT_MAGIC2		672274793
#define	LINUX_REBOOT_MAGIC2A		85072278
#define	LINUX_REBOOT_MAGIC2B		369367448
#define	LINUX_REBOOT_MAGIC2C		537993216

/*
 * This was observed as coming from Red Hat's init process, but it's not in
 * their reboot(2) man page.
 */
#define	LINUX_REBOOT_MAGIC2D		0x28121969

#define	LINUX_REBOOT_CMD_RESTART	0x1234567
#define	LINUX_REBOOT_CMD_HALT		0xcdef0123
#define	LINUX_REBOOT_CMD_POWER_OFF	0x4321fedc
#define	LINUX_REBOOT_CMD_RESTART2	0xa1b2c3d4
#define	LINUX_REBOOT_CMD_CAD_ON		0x89abcdef
#define	LINUX_REBOOT_CMD_CAD_OFF	0

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
 * Constants to indicate who getrusage() should return information about.
 */
#define	LX_RUSAGE_SELF		0
#define	LX_RUSAGE_CHILDREN	(-1)

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

extern void lx_handler_table(void);
extern void lx_handler_trace_table(void);
extern void lx_emulate_done(void);
extern lx_regs_t *lx_syscall_regs(void);

extern char *lx_fd_to_path(int fd, char *buf, int buf_size);
extern int lx_lpid_to_spair(pid_t, pid_t *, lwpid_t *);
extern int lx_lpid_to_spid(pid_t, pid_t *);

extern int lx_ptrace_wait(siginfo_t *);
extern void lx_ptrace_fork(void);

extern int lx_get_kern_version(void);

extern int lx_check_alloca(size_t);
#define	SAFE_ALLOCA(sz)	(lx_check_alloca(sz) ? alloca(sz) : NULL)

extern int ltos_at_flag(int lflag, int allow);

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

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LX_H */
