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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _S10_MISC_H
#define	_S10_MISC_H

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(_ASM)

/*
 * From s10_deleted.c
 */
extern int s10_stat();
extern int s10_lstat();
extern int s10_fstat();
extern int s10_stat64();
extern int s10_lstat64();
extern int s10_fstat64();
extern int s10_open();
extern int s10_open64();
extern int s10_chown();
extern int s10_lchown();
extern int s10_fchown();
extern int s10_unlink();
extern int s10_rmdir();
extern int s10_rename();
extern int s10_access();
extern int s10_creat();
extern int s10_creat64();
extern int s10_fork1();
extern int s10_forkall();
extern int s10_dup();
extern int s10_poll();
extern int s10_lwp_mutex_lock();
extern int s10_lwp_sema_wait();
extern int s10_utime();
extern int s10_utimes();
extern int s10_xstat();
extern int s10_lxstat();
extern int s10_fxstat();
extern int s10_xmknod();
extern int s10_fsat();
extern int s10_umount();

/*
 * From s10_signal.c
 */
extern int s10sigset_to_native(const sigset_t *, sigset_t *);

extern int s10_kill();
extern int s10_lwp_create();
extern int s10_lwp_kill();
extern int s10_lwp_sigmask();
extern int s10_sigaction();
extern int s10_signotify();
extern int s10_sigpending();
extern int s10_sigprocmask();
extern int s10_sigqueue();
extern int s10_sigsendsys();
extern int s10_sigsuspend();
extern int s10_sigtimedwait();
extern int s10_wait();
extern int s10_waitid();

#endif	/* !_ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _S10_MISC_H */
