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
 * Copyright 2016 Joyent, Inc.
 */

#ifndef _SYS_LINUX_SYSCALLS_H
#define	_SYS_LINUX_SYSCALLS_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

extern long lx_accept();
extern long lx_accept4();
extern long lx_access();
extern long lx_alarm();
extern long lx_arch_prctl();
extern long lx_bind();
extern long lx_brk();
extern long lx_chdir();
extern long lx_chmod();
extern long lx_chown();
extern long lx_chown16();
extern long lx_chroot();
extern long lx_clock_getres();
extern long lx_clock_gettime();
extern long lx_clock_settime();
extern long lx_close();
extern long lx_connect();
extern long lx_creat();
extern long lx_dup();
extern long lx_dup2();
extern long lx_dup3();
extern long lx_epoll_create();
extern long lx_epoll_create1();
extern long lx_epoll_ctl();
extern long lx_epoll_pwait();
extern long lx_epoll_wait();
extern long lx_faccessat();
extern long lx_fadvise64();
extern long lx_fadvise64_32();
extern long lx_fadvise64_64();
extern long lx_fallocate();
extern long lx_fallocate32();
extern long lx_fchdir();
extern long lx_fchmod();
extern long lx_fchmodat();
extern long lx_fchown();
extern long lx_fchown16();
extern long lx_fchownat();
extern long lx_fcntl();
extern long lx_fcntl64();
extern long lx_fgetxattr();
extern long lx_flistxattr();
extern long lx_fremovexattr();
extern long lx_fsetxattr();
extern long lx_fstat32();
extern long lx_fstat64();
extern long lx_fstatat64();
extern long lx_futex();
extern long lx_get_robust_list();
extern long lx_get_thread_area();
extern long lx_getcpu();
extern long lx_getcwd();
extern long lx_getdents_32();
extern long lx_getdents_64();
extern long lx_getdents64();
extern long lx_getegid();
extern long lx_getegid16();
extern long lx_geteuid();
extern long lx_geteuid16();
extern long lx_getgid();
extern long lx_getgid16();
extern long lx_getitimer();
extern long lx_getpeername();
extern long lx_getpgid();
extern long lx_getpgrp();
extern long lx_getsockname();
extern long lx_getpid();
extern long lx_getppid();
extern long lx_getpriority();
extern long lx_getrandom();
extern long lx_getresgid();
extern long lx_getresgid16();
extern long lx_getresuid();
extern long lx_getresuid16();
extern long lx_getrlimit();
extern long lx_getrusage();
extern long lx_getsid();
extern long lx_getsockopt();
extern long lx_gettid();
extern long lx_gettimeofday();
extern long lx_getuid();
extern long lx_getuid16();
extern long lx_getxattr();
extern long lx_io_setup();
extern long lx_ioctl();
extern long lx_ioprio_get();
extern long lx_ioprio_set();
extern long lx_kill();
extern long lx_lchown();
extern long lx_lchown16();
extern long lx_lgetxattr();
extern long lx_link();
extern long lx_linkat();
extern long lx_listen();
extern long lx_llistxattr();
extern long lx_llseek();
extern long lx_lremovexattr();
extern long lx_lseek32();
extern long lx_lseek64();
extern long lx_lsetxattr();
extern long lx_lstat32();
extern long lx_lstat64();
extern long lx_listxattr();
extern long lx_mincore();
extern long lx_mkdir();
extern long lx_mkdirat();
extern long lx_modify_ldt();
extern long lx_mount();
extern long lx_munmap();
extern long lx_nanosleep();
extern long lx_nice();
extern long lx_oldgetrlimit();
extern long lx_open();
extern long lx_openat();
extern long lx_pause();
extern long lx_personality();
extern long lx_pipe();
extern long lx_pipe2();
extern long lx_poll();
extern long lx_ppoll();
extern long lx_pread();
extern long lx_pread32();
extern long lx_preadv();
extern long lx_preadv32();
extern long lx_prctl();
extern long lx_prlimit64();
extern long lx_pselect();
extern long lx_ptrace();
extern long lx_pwrite();
extern long lx_pwrite32();
extern long lx_pwritev();
extern long lx_pwritev32();
extern long lx_read();
extern long lx_readlink();
extern long lx_readlinkat();
extern long lx_readv();
extern long lx_reboot();
extern long lx_recv();
extern long lx_recvmsg();
extern long lx_recvfrom();
extern long lx_rename();
extern long lx_renameat();
extern long lx_sched_getaffinity();
extern long lx_sched_getparam();
extern long lx_sched_getscheduler();
extern long lx_sched_getattr();
extern long lx_sched_get_priority_max();
extern long lx_sched_get_priority_min();
extern long lx_sched_rr_get_interval();
extern long lx_sched_setaffinity();
extern long lx_sched_setattr();
extern long lx_sched_setparam();
extern long lx_sched_setscheduler();
extern long lx_sched_yield();
extern long lx_select();
extern long lx_send();
extern long lx_sendmsg();
extern long lx_sendto();
extern long lx_set_robust_list();
extern long lx_set_thread_area();
extern long lx_set_tid_address();
extern long lx_setdomainname();
extern long lx_setfsuid();
extern long lx_setfsuid16();
extern long lx_setfsgid();
extern long lx_setfsgid16();
extern long lx_setgid();
extern long lx_setgid16();
extern long lx_sethostname();
extern long lx_setpgid();
extern long lx_setpriority();
extern long lx_setregid();
extern long lx_setregid16();
extern long lx_setresgid();
extern long lx_setresgid16();
extern long lx_setresuid();
extern long lx_setresuid16();
extern long lx_setreuid();
extern long lx_setreuid16();
extern long lx_setrlimit();
extern long lx_setsid();
extern long lx_setuid();
extern long lx_setuid16();
extern long lx_setxattr();
extern long lx_setsockopt();
extern long lx_symlink();
extern long lx_symlinkat();
extern long lx_shutdown();
extern long lx_socket();
extern long lx_socketcall();
extern long lx_socketpair();
extern long lx_stat32();
extern long lx_stat64();
extern long lx_stime();
extern long lx_sync();
extern long lx_sync_file_range();
extern long lx_syncfs();
extern long lx_sysinfo32();
extern long lx_sysinfo64();
extern long lx_syslog();
extern long lx_removexattr();
extern long lx_tgkill();
extern long lx_time();
extern long lx_timer_create();
extern long lx_tkill();
extern long lx_umask();
extern long lx_umount();
extern long lx_umount2();
extern long lx_uname();
extern long lx_unlink();
extern long lx_unlinkat();
extern long lx_vhangup();
extern long lx_wait4();
extern long lx_waitid();
extern long lx_waitpid();
extern long lx_write();
extern long lx_writev();

#if defined(_LP64)
/*
 * Linux vsyscall addresses:
 */
#define	LX_VSYS_gettimeofday	(uintptr_t)0xffffffffff600000
#define	LX_VSYS_time		(uintptr_t)0xffffffffff600400
#define	LX_VSYS_getcpu		(uintptr_t)0xffffffffff600800

#define	LX_VSYSCALL_ADDR		(uintptr_t)0xffffffffff600000
#define	LX_VSYSCALL_SIZE		(uintptr_t)0x1000
#endif

#endif	/* _KERNEL */

/*
 * System call numbers for revectoring:
 */

#if defined(__amd64)
#define	LX_SYS_close		3
#define	LX_SYS_gettimeofday	96
#define	LX_SYS_mount		165
#define	LX_SYS_time		201
#define	LX_SYS_io_setup		206
#define	LX_SYS_clock_gettime	228
#define	LX_SYS_getcpu		309

#define	LX_SYS32_close		6
#define	LX_SYS32_gettimeofday	78
#define	LX_SYS32_time		13
#define	LX_SYS32_mount		21
#define	LX_SYS32_clock_gettime	265
#define	LX_SYS32_io_setup	245
#define	LX_SYS32_getcpu		318
#elif defined(__i386)
#define	LX_SYS_close		6
#define	LX_SYS_mount		21
#define	LX_SYS_gettimeofday	78
#define	LX_SYS_time		13
#define	LX_SYS_clock_gettime	265
#define	LX_SYS_io_setup		245
#define	LX_SYS_getcpu		318
#else
#error "Architecture not supported"
#endif /* defined(__amd64) */

/*
 * The current code in the VDSO operates under the expectation that it will be
 * mapped at a fixed offset from the comm page.  This simplifies the act of
 * locating said page without any other reference.  The VDSO must fit within
 * this offset, matching the same value as COMM_PAGE_ALIGN.
 * See: uts/i86pc/sys/comm_page.h
 */
#define	LX_VDSO_SIZE		0x4000
#define	LX_VDSO_ADDR_MASK	~(LX_VDSO_SIZE - 1)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LINUX_SYSCALLS_H */
