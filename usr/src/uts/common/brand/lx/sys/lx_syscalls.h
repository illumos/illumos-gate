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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#ifndef _SYS_LINUX_SYSCALLS_H
#define	_SYS_LINUX_SYSCALLS_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

extern long lx_arch_prctl();
extern long lx_brk();
extern long lx_getpid();
extern long lx_getppid();
extern long lx_clone();
extern long lx_kill();
extern long lx_tkill();
extern long lx_tgkill();
extern long lx_modify_ldt();
extern long lx_pipe();
extern long lx_pipe2();
extern long lx_read();
extern long lx_gettid();
extern long lx_futex();
extern long lx_get_thread_area();
extern long lx_sched_getparam();
extern long lx_sched_getscheduler();
extern long lx_sched_rr_get_interval();
extern long lx_sched_setparam();
extern long lx_sched_setscheduler();
extern long lx_set_thread_area();
extern long lx_set_tid_address();
extern long lx_setresgid();
extern long lx_setresgid16();
extern long lx_setresuid();
extern long lx_setresuid16();
extern long lx_sysinfo();
extern long lx_setgroups();
extern long lx_rt_sigqueueinfo();
extern long lx_rt_tgsigqueueinfo();

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LINUX_SYSCALLS_H */
