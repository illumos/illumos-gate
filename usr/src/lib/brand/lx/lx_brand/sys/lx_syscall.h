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
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
 */

#ifndef _SYS_LX_SYSCALL_H
#define	_SYS_LX_SYSCALL_H

#if !defined(_ASM)

#include <sys/types.h>
#include <sys/procset.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int lx_install;

extern int lx_openat(uintptr_t, uintptr_t, uintptr_t, uintptr_t);
extern int lx_mkdirat(uintptr_t, uintptr_t, uintptr_t);
extern int lx_mknodat(uintptr_t, uintptr_t, uintptr_t, uintptr_t);
extern int lx_fchownat(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
extern int lx_futimesat(uintptr_t, uintptr_t, uintptr_t);
extern int lx_utimensat(uintptr_t, uintptr_t, uintptr_t, uintptr_t);
extern int lx_fstatat64(uintptr_t, uintptr_t, uintptr_t, uintptr_t);
extern int lx_unlinkat(uintptr_t, uintptr_t, uintptr_t);
extern int lx_renameat(uintptr_t, uintptr_t, uintptr_t, uintptr_t);
extern int lx_linkat(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
extern int lx_symlinkat(uintptr_t, uintptr_t, uintptr_t);
extern int lx_readlinkat(uintptr_t, uintptr_t, uintptr_t, uintptr_t);
extern int lx_fchmodat(uintptr_t, uintptr_t, uintptr_t, uintptr_t);
extern int lx_access(uintptr_t, uintptr_t);
extern int lx_faccessat(uintptr_t, uintptr_t, uintptr_t, uintptr_t);

extern int lx_stat(uintptr_t, uintptr_t);
extern int lx_fstat(uintptr_t, uintptr_t);
extern int lx_lstat(uintptr_t, uintptr_t);
extern int lx_stat64(uintptr_t, uintptr_t);
extern int lx_fstat64(uintptr_t, uintptr_t);
extern int lx_lstat64(uintptr_t, uintptr_t);
extern int lx_fcntl(uintptr_t, uintptr_t, uintptr_t);
extern int lx_fcntl64(uintptr_t, uintptr_t, uintptr_t);
extern int lx_flock(uintptr_t, uintptr_t);
extern int lx_open(uintptr_t, uintptr_t, uintptr_t);
extern int lx_readdir(uintptr_t, uintptr_t, uintptr_t);
extern int lx_getdents(uintptr_t, uintptr_t, uintptr_t);
extern int lx_getdents64(uintptr_t, uintptr_t, uintptr_t);
extern int lx_getpid(void);
extern int lx_execve(uintptr_t, uintptr_t, uintptr_t);
extern int lx_dup2(uintptr_t, uintptr_t);
extern int lx_dup3(uintptr_t, uintptr_t, uintptr_t);
extern int lx_ioctl(uintptr_t, uintptr_t, uintptr_t);
extern int lx_vhangup(void);
extern int lx_fadvise64(uintptr_t, uintptr_t, uintptr_t, uintptr_t);
extern int lx_fadvise64_64(uintptr_t, off64_t, off64_t, uintptr_t);

extern int lx_read(uintptr_t, uintptr_t, uintptr_t);
extern int lx_readv(uintptr_t, uintptr_t, uintptr_t);
extern int lx_writev(uintptr_t, uintptr_t, uintptr_t);
extern int lx_pread64(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
extern int lx_pwrite64(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);

extern int lx_socketcall(uintptr_t, uintptr_t);
extern int lx_select(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
extern int lx_pselect6(uintptr_t, uintptr_t, uintptr_t, uintptr_t,
    uintptr_t, uintptr_t);
extern int lx_poll(uintptr_t, uintptr_t, uintptr_t);
extern int lx_oldgetrlimit(uintptr_t, uintptr_t);
extern int lx_getrlimit(uintptr_t, uintptr_t);
extern int lx_setrlimit(uintptr_t, uintptr_t);
extern int lx_prlimit64(uintptr_t, uintptr_t, uintptr_t, uintptr_t);
extern int lx_gettimeofday(uintptr_t, uintptr_t);
extern int lx_settimeofday(uintptr_t, uintptr_t);
extern int lx_getrusage(uintptr_t, uintptr_t);
extern int lx_mknod(uintptr_t, uintptr_t, uintptr_t);

extern int lx_getpgrp(void);
extern int lx_getpgid(uintptr_t);
extern int lx_setpgid(uintptr_t, uintptr_t);
extern int lx_getsid(uintptr_t);
extern int lx_setsid(void);
extern int lx_setgroups(uintptr_t, uintptr_t);


extern int lx_waitpid(uintptr_t, uintptr_t, uintptr_t);
extern int lx_waitid(uintptr_t, uintptr_t, uintptr_t, uintptr_t);
extern int lx_wait4(uintptr_t, uintptr_t, uintptr_t, uintptr_t);

extern int lx_getuid16(void);
extern int lx_getgid16(void);
extern int lx_geteuid16(void);
extern int lx_getegid16(void);
extern int lx_geteuid(void);
extern int lx_getegid(void);
extern int lx_getresuid16(uintptr_t, uintptr_t, uintptr_t);
extern int lx_getresgid16(uintptr_t, uintptr_t, uintptr_t);
extern int lx_getresuid(uintptr_t, uintptr_t, uintptr_t);
extern int lx_getresgid(uintptr_t, uintptr_t, uintptr_t);
extern int lx_capget(uintptr_t, uintptr_t);
extern int lx_capset(uintptr_t, uintptr_t);

extern int lx_setuid16(uintptr_t);
extern int lx_setreuid16(uintptr_t, uintptr_t);
extern int lx_setregid16(uintptr_t, uintptr_t);
extern int lx_setgid16(uintptr_t);
extern int lx_setfsuid16(uintptr_t);
extern int lx_setfsgid16(uintptr_t);

extern int lx_setfsuid(uintptr_t);
extern int lx_setfsgid(uintptr_t);

extern int lx_clock_settime(int, struct timespec *);
extern int lx_clock_gettime(int, struct timespec *);
extern int lx_clock_getres(int, struct timespec *);
extern int lx_clock_nanosleep(int, int flags, struct timespec *,
    struct timespec *);

extern int lx_truncate(uintptr_t, uintptr_t);
extern int lx_ftruncate(uintptr_t, uintptr_t);
extern int lx_truncate64(uintptr_t, uintptr_t, uintptr_t);
extern int lx_ftruncate64(uintptr_t, uintptr_t, uintptr_t);

extern int lx_sysctl(uintptr_t);
extern int lx_fsync(uintptr_t);
extern int lx_fdatasync(uintptr_t);
extern int lx_pipe(uintptr_t);
extern int lx_pipe2(uintptr_t, uintptr_t);
extern int lx_link(uintptr_t, uintptr_t);
extern int lx_unlink(uintptr_t);
extern int lx_rmdir(uintptr_t);
extern int lx_chown16(uintptr_t, uintptr_t, uintptr_t);
extern int lx_fchown16(uintptr_t, uintptr_t, uintptr_t);
extern int lx_lchown16(uintptr_t, uintptr_t, uintptr_t);
extern int lx_chown(uintptr_t, uintptr_t, uintptr_t);
extern int lx_fchown(uintptr_t, uintptr_t, uintptr_t);
extern int lx_chmod(uintptr_t, uintptr_t);
extern int lx_rename(uintptr_t, uintptr_t);
extern int lx_utime(uintptr_t, uintptr_t);
extern int lx_llseek(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
extern int lx_lseek(uintptr_t, uintptr_t, uintptr_t);
extern int lx_sysfs(uintptr_t, uintptr_t, uintptr_t);

extern int lx_getcwd(uintptr_t, uintptr_t);
extern int lx_uname(uintptr_t);
extern int lx_reboot(uintptr_t, uintptr_t, uintptr_t, uintptr_t);
extern int lx_getgroups16(uintptr_t, uintptr_t);
extern int lx_setgroups16(uintptr_t, uintptr_t);
extern int lx_personality(uintptr_t);

extern int lx_query_module(uintptr_t, uintptr_t, uintptr_t, uintptr_t,
    uintptr_t);

extern int lx_time(uintptr_t);
extern int lx_times(uintptr_t);
extern int lx_setitimer(uintptr_t, uintptr_t, uintptr_t);

extern int lx_clone(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
extern int lx_exit(uintptr_t);
extern int lx_group_exit(uintptr_t);

extern int lx_mlock(uintptr_t, uintptr_t);
extern int lx_mlockall(uintptr_t);
extern int lx_munlock(uintptr_t, uintptr_t);
extern int lx_munlockall(void);
extern int lx_msync(uintptr_t, uintptr_t, uintptr_t);
extern int lx_madvise(uintptr_t, uintptr_t, uintptr_t);
extern int lx_mprotect(uintptr_t, uintptr_t, uintptr_t);
extern int lx_mmap(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t,
    uintptr_t);
extern int lx_mmap2(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t,
    uintptr_t);

extern int lx_mount(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
extern int lx_umount(uintptr_t);
extern int lx_umount2(uintptr_t, uintptr_t);

extern int lx_statfs(uintptr_t, uintptr_t);
extern int lx_fstatfs(uintptr_t, uintptr_t);
extern int lx_statfs64(uintptr_t, uintptr_t, uintptr_t);
extern int lx_fstatfs64(uintptr_t, uintptr_t, uintptr_t);

extern int lx_sigreturn(void);
extern int lx_rt_sigreturn(void);
extern int lx_signal(uintptr_t, uintptr_t);
extern int lx_sigaction(uintptr_t, uintptr_t, uintptr_t);
extern int lx_rt_sigaction(uintptr_t, uintptr_t, uintptr_t, uintptr_t);
extern int lx_sigaltstack(uintptr_t, uintptr_t);
extern int lx_sigpending(uintptr_t);
extern int lx_rt_sigpending(uintptr_t, uintptr_t);
extern int lx_sigprocmask(uintptr_t, uintptr_t, uintptr_t);
extern int lx_rt_sigprocmask(uintptr_t, uintptr_t, uintptr_t, uintptr_t);
extern int lx_sigsuspend(uintptr_t);
extern int lx_rt_sigsuspend(uintptr_t, uintptr_t);
extern int lx_sigwaitinfo(uintptr_t, uintptr_t);
extern int lx_rt_sigwaitinfo(uintptr_t, uintptr_t, uintptr_t);
extern int lx_sigtimedwait(uintptr_t, uintptr_t, uintptr_t);
extern int lx_rt_sigtimedwait(uintptr_t, uintptr_t, uintptr_t, uintptr_t);

extern int lx_sync(void);

extern int lx_futex(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t,
    uintptr_t);

extern int lx_tkill(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t,
    uintptr_t);
extern int lx_tgkill(uintptr_t, uintptr_t, uintptr_t);

extern int lx_sethostname(uintptr_t, uintptr_t);
extern int lx_setdomainname(uintptr_t, uintptr_t);

extern int lx_sendfile(uintptr_t, uintptr_t, uintptr_t, uintptr_t);
extern int lx_sendfile64(uintptr_t, uintptr_t, uintptr_t, uintptr_t);

extern int lx_fork(void);
extern int lx_vfork(void);
extern int lx_exec(uintptr_t, uintptr_t, uintptr_t);

extern int lx_getpriority(uintptr_t, uintptr_t);
extern int lx_setpriority(uintptr_t, uintptr_t, uintptr_t);

extern int lx_ptrace(uintptr_t, uintptr_t, uintptr_t, uintptr_t);

extern int lx_sched_getaffinity(uintptr_t, uintptr_t, uintptr_t);
extern int lx_sched_setaffinity(uintptr_t, uintptr_t, uintptr_t);
extern int lx_sched_getparam(uintptr_t, uintptr_t);
extern int lx_sched_setparam(uintptr_t, uintptr_t);
extern int lx_sched_rr_get_interval(uintptr_t pid, uintptr_t);
extern int lx_sched_getscheduler(uintptr_t);
extern int lx_sched_setscheduler(uintptr_t, uintptr_t, uintptr_t);
extern int lx_sched_get_priority_min(uintptr_t);
extern int lx_sched_get_priority_max(uintptr_t);

extern int lx_xattr2(uintptr_t, uintptr_t);
extern int lx_xattr3(uintptr_t, uintptr_t, uintptr_t);
extern int lx_xattr4(uintptr_t, uintptr_t, uintptr_t, uintptr_t);

extern int lx_keyctl(void);

extern int lx_ipc(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);

extern int lx_prctl(int, uintptr_t, uintptr_t, uintptr_t, uintptr_t);

#endif	/* !defined(_ASM) */

#define	EBP_HAS_ARG6		0x01

/*
 * Linux syscall numbers
 */
#define	LX_SYS_exit		  1
#define	LX_SYS_fork		  2
#define	LX_SYS_read		  3
#define	LX_SYS_write		  4
#define	LX_SYS_open		  5
#define	LX_SYS_close		  6
#define	LX_SYS_waitpid		  7
#define	LX_SYS_creat		  8
#define	LX_SYS_link		  9
#define	LX_SYS_unlink		 10
#define	LX_SYS_execve		 11
#define	LX_SYS_chdir		 12
#define	LX_SYS_time		 13
#define	LX_SYS_mknod		 14
#define	LX_SYS_chmod		 15
#define	LX_SYS_lchown		 16
#define	LX_SYS_break		 17
#define	LX_SYS_oldstat		 18
#define	LX_SYS_lseek		 19
#define	LX_SYS_getpid		 20
#define	LX_SYS_mount		 21
#define	LX_SYS_umount		 22
#define	LX_SYS_setuid		 23
#define	LX_SYS_getuid		 24
#define	LX_SYS_stime		 25
#define	LX_SYS_ptrace		 26
#define	LX_SYS_alarm		 27
#define	LX_SYS_oldfstat		 28
#define	LX_SYS_pause		 29
#define	LX_SYS_utime		 30
#define	LX_SYS_stty		 31
#define	LX_SYS_gtty		 32
#define	LX_SYS_access		 33
#define	LX_SYS_nice		 34
#define	LX_SYS_ftime		 35
#define	LX_SYS_sync		 36
#define	LX_SYS_kill		 37
#define	LX_SYS_rename		 38
#define	LX_SYS_mkdir		 39
#define	LX_SYS_rmdir		 40
#define	LX_SYS_dup		 41
#define	LX_SYS_pipe		 42
#define	LX_SYS_times		 43
#define	LX_SYS_prof		 44
#define	LX_SYS_brk		 45
#define	LX_SYS_setgid		 46
#define	LX_SYS_getgid		 47
#define	LX_SYS_signal		 48
#define	LX_SYS_geteuid		 49
#define	LX_SYS_getegid		 50
#define	LX_SYS_acct		 51
#define	LX_SYS_umount2		 52
#define	LX_SYS_lock		 53
#define	LX_SYS_ioctl		 54
#define	LX_SYS_fcntl		 55
#define	LX_SYS_mpx		 56
#define	LX_SYS_setpgid		 57
#define	LX_SYS_ulimit		 58
#define	LX_SYS_oldolduname	 59
#define	LX_SYS_umask		 60
#define	LX_SYS_chroot		 61
#define	LX_SYS_ustat		 62
#define	LX_SYS_dup2		 63
#define	LX_SYS_getppid		 64
#define	LX_SYS_getpgrp		 65
#define	LX_SYS_setsid		 66
#define	LX_SYS_sigaction	 67
#define	LX_SYS_sgetmask		 68
#define	LX_SYS_ssetmask		 69
#define	LX_SYS_setreuid		 70
#define	LX_SYS_setregid		 71
#define	LX_SYS_sigsuspend	 72
#define	LX_SYS_sigpending	 73
#define	LX_SYS_sethostname	 74
#define	LX_SYS_setrlimit	 75
#define	LX_SYS_getrlimit	 76
#define	LX_SYS_getrusage	 77
#define	LX_SYS_gettimeofday	 78
#define	LX_SYS_settimeofday	 79
#define	LX_SYS_getgroups	 80
#define	LX_SYS_setgroups	 81
#define	LX_SYS_select		 82
#define	LX_SYS_symlink		 83
#define	LX_SYS_oldlstat		 84
#define	LX_SYS_readlink		 85
#define	LX_SYS_uselib		 86
#define	LX_SYS_swapon		 87
#define	LX_SYS_reboot		 88
#define	LX_SYS_readdir		 89
#define	LX_SYS_mmap		 90
#define	LX_SYS_munmap		 91
#define	LX_SYS_truncate		 92
#define	LX_SYS_ftruncate	 93
#define	LX_SYS_fchmod		 94
#define	LX_SYS_fchown		 95
#define	LX_SYS_getpriority	 96
#define	LX_SYS_setpriority	 97
#define	LX_SYS_profil		 98
#define	LX_SYS_statfs		 99
#define	LX_SYS_fstatfs		100
#define	LX_SYS_ioperm		101
#define	LX_SYS_socketcall	102
#define	LX_SYS_syslog		103
#define	LX_SYS_setitimer	104
#define	LX_SYS_getitimer	105
#define	LX_SYS_stat		106
#define	LX_SYS_lstat		107
#define	LX_SYS_fstat		108
#define	LX_SYS_olduname		109
#define	LX_SYS_iopl		110
#define	LX_SYS_vhangup		111
#define	LX_SYS_idle		112
#define	LX_SYS_vm86old		113
#define	LX_SYS_wait4		114
#define	LX_SYS_swapoff		115
#define	LX_SYS_sysinfo		116
#define	LX_SYS_ipc		117
#define	LX_SYS_fsync		118
#define	LX_SYS_sigreturn	119
#define	LX_SYS_clone		120
#define	LX_SYS_setdomainname	121
#define	LX_SYS_uname		122
#define	LX_SYS_modify_ldt	123
#define	LX_SYS_adjtimex		124
#define	LX_SYS_mprotect		125
#define	LX_SYS_sigprocmask	126
#define	LX_SYS_create_module	127
#define	LX_SYS_init_module	128
#define	LX_SYS_delete_module	129
#define	LX_SYS_get_kernel_syms	130
#define	LX_SYS_quotactl		131
#define	LX_SYS_getpgid		132
#define	LX_SYS_fchdir		133
#define	LX_SYS_sysfs		135
#define	LX_SYS_setfsuid		138
#define	LX_SYS_setfsgid		139
#define	LX_SYS_llseek		140
#define	LX_SYS_getdents		141
#define	LX_SYS_newselect	142
#define	LX_SYS_flock		143
#define	LX_SYS_msync		144
#define	LX_SYS_readv		145
#define	LX_SYS_writev		146
#define	LX_SYS_getsid		147
#define	LX_SYS_fdatasync	148
#define	LX_SYS_sysctl		149
#define	LX_SYS_mlock		150
#define	LX_SYS_munlock		151
#define	LX_SYS_mlockall		152
#define	LX_SYS_munlockall		153
#define	LX_SYS_sched_setparam		154
#define	LX_SYS_sched_getparam		155
#define	LX_SYS_sched_setscheduler	156
#define	LX_SYS_sched_getscheduler	157
#define	LX_SYS_sched_yield		158
#define	LX_SYS_sched_get_priority_max	159
#define	LX_SYS_sched_get_priority_min	160
#define	LX_SYS_sched_rr_get_interval	161
#define	LX_SYS_nanosleep	162
#define	LX_SYS_mremap		163
#define	LX_SYS_setresuid	164
#define	LX_SYS_getresuid	165
#define	LX_SYS_poll		168
#define	LX_SYS_setresgid	170
#define	LX_SYS_getresgid	171
#define	LX_SYS_prctl		172
#define	LX_SYS_rt_sigreturn	173
#define	LX_SYS_rt_sigaction	174
#define	LX_SYS_rt_sigprocmask	175
#define	LX_SYS_rt_sigpending	176
#define	LX_SYS_rt_sigtimedwait	177
#define	LX_SYS_rt_sigqueueinfo	178
#define	LX_SYS_rt_sigsuspend	179
#define	LX_SYS_pread		180
#define	LX_SYS_pwrite		181
#define	LX_SYS_chown		182
#define	LX_SYS_getcwd		183
#define	LX_SYS_capget		184
#define	LX_SYS_capset		185
#define	LX_SYS_sigaltstack	186
#define	LX_SYS_sendfile		187
#define	LX_SYS_getpmsg		188
#define	LX_SYS_putpmsg		189
#define	LX_SYS_vfork		190
#define	LX_SYS_ugetrlimit	191
#define	LX_SYS_mmap2		192
#define	LX_SYS_truncate64	193
#define	LX_SYS_ftruncate64	194
#define	LX_SYS_stat64		195
#define	LX_SYS_lstat64		196
#define	LX_SYS_fstat64		197
#define	LX_SYS_lchown32		198
#define	LX_SYS_getuid32		199
#define	LX_SYS_getgid32		200
#define	LX_SYS_geteuid32	201
#define	LX_SYS_getegid32	202
#define	LX_SYS_setreuid32	203
#define	LX_SYS_setregid32	204
#define	LX_SYS_getgroups32	205
#define	LX_SYS_setgroups32	206
#define	LX_SYS_fchown32		207
#define	LX_SYS_setresuid32	208
#define	LX_SYS_getresuid32	209
#define	LX_SYS_setresgid32	210
#define	LX_SYS_getresgid32	211
#define	LX_SYS_chown32		212
#define	LX_SYS_setuid32		213
#define	LX_SYS_setgid32		214
#define	LX_SYS_setfsuid32	215
#define	LX_SYS_setfsgid32	216
#define	LX_SYS_mincore		218
#define	LX_SYS_madvise		219
#define	LX_SYS_getdents64	220
#define	LX_SYS_fcntl64		221
#define	LX_SYS_gettid		224
#define	LX_SYS_readahead	225
#define	LX_SYS_setxattr		226
#define	LX_SYS_lsetxattr	227
#define	LX_SYS_fsetxattr	228
#define	LX_SYS_getxattr		229
#define	LX_SYS_lgetxattr	230
#define	LX_SYS_fgetxattr	231
#define	LX_SYS_listxattr	232
#define	LX_SYS_llistxattr	233
#define	LX_SYS_flistxattr	234
#define	LX_SYS_removexattr	235
#define	LX_SYS_lremovexattr	236
#define	LX_SYS_fremovexattr	237
#define	LX_SYS_tkill		238
#define	LX_SYS_sendfile64	239
#define	LX_SYS_futex		240
#define	LX_SYS_sched_setaffinity	241
#define	LX_SYS_sched_getaffinity	242
#define	LX_SYS_set_thread_area 	243
#define	LX_SYS_get_thread_area	244
#define	LX_SYS_fadvise64	250
#define	LX_SYS_exit_group	252
#define	LX_SYS_remap_file_pages	257
#define	LX_SYS_set_tid_address	258
#define	LX_SYS_timer_create	259
#define	LX_SYS_timer_settime	260
#define	LX_SYS_timer_gettime	261
#define	LX_SYS_timer_getoverrun	262
#define	LX_SYS_timer_delete	263
#define	LX_SYS_clock_settime	264
#define	LX_SYS_clock_gettime	265
#define	LX_SYS_clock_getres	266
#define	LX_SYS_clock_nanosleep	267
#define	LX_SYS_tgkill		270
/* the following syscalls are for 2.6 and later kernels */
#define	LX_SYS_utimes		271
#define	LX_SYS_fadvise64_64	272
#define	LX_SYS_vserver		273
#define	LX_SYS_mbind		274
#define	LX_SYS_get_mempolicyd	275
#define	LX_SYS_set_mempolicy	276
#define	LX_SYS_mq_open		277
#define	LX_SYS_mq_unlink	278
#define	LX_SYS_mq_timedsend	279
#define	LX_SYS_mq_timedreceive	280
#define	LX_SYS_mq_notify	281
#define	LX_SYS_mq_getsetattr	282
#define	LX_SYS_kexec_load	283
#define	LX_SYS_waitid		284
#define	LX_SYS_setaltroot	285
#define	LX_SYS_add_key		286
#define	LX_SYS_request_key	287
#define	LX_SYS_keyctl		288
#define	LX_SYS_ioprio_set	289
#define	LX_SYS_ioprio_get	290
#define	LX_SYS_inotify_init	291
#define	LX_SYS_inotify_add_watch	292
#define	LX_SYS_inotify_rm_watch	293
#define	LX_SYS_migrate_pages	294
#define	LX_SYS_openat		295
#define	LX_SYS_mkdirat		296
#define	LX_SYS_mknodat		297
#define	LX_SYS_fchownat		298
#define	LX_SYS_futimesat	299
#define	LX_SYS_fstatat64	300
#define	LX_SYS_unlinkat		301
#define	LX_SYS_renameat		302
#define	LX_SYS_linkat		303
#define	LX_SYS_symlinkat	304
#define	LX_SYS_readlinkat	305
#define	LX_SYS_fchmodat		306
#define	LX_SYS_faccessat	307
#define	LX_SYS_pselect6		308
#define	LX_SYS_ppoll		309
#define	LX_SYS_unshare		310
#define	LX_SYS_set_robust_list	311
#define	LX_SYS_get_robust_list	312
#define	LX_SYS_splice		313
#define	LX_SYS_sync_file_range	314
#define	LX_SYS_tee		315
#define	LX_SYS_vmsplice		316
#define	LX_SYS_move_pages	317
#define	LX_SYS_getcpu		318
#define	LX_SYS_epoll_pwait	319
#define	LX_SYS_utimensat	320
#define	LX_SYS_signalfd		321
#define	LX_SYS_timerfd_create	322
#define	LX_SYS_eventfd		323
#define	LX_SYS_fallocate	324
#define	LX_SYS_timerfd_settime	325
#define	LX_SYS_timerfd_gettime	326
#define	LX_SYS_signalfd4	327
#define	LX_SYS_eventfd2		328
#define	LX_SYS_epoll_create1	329
#define	LX_SYS_dup3		330
#define	LX_SYS_pipe2		331
#define	LX_SYS_inotify_init1	332
#define	LX_SYS_preadv		333
#define	LX_SYS_pwritev		334
#define	LX_SYS_rt_tgsigqueueinfo	335
#define	LX_SYS_perf_event_open	336
#define	LX_SYS_recvmmsg		337
#define	LX_SYS_fanotify_init	338
#define	LX_SYS_fanotify_mark	339
#define	LX_SYS_prlimit64	340
#define	LX_SYS_name_to_handle_at	341
#define	LX_SYS_open_by_handle_at	342
#define	LX_SYS_clock_adjtime	343
#define	LX_SYS_syncfs		344
#define	LX_SYS_sendmmsg		345
#define	LX_SYS_setns		346
#define	LX_SYS_process_vm_readv	347
#define	LX_SYS_process_vm_writev	348
#define	LX_SYS_kcmp		349
#define	LX_SYS_finit_module	350
#define	LX_SYS_sched_setattr	351
#define	LX_SYS_sched_getattr	352

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LX_SYSCALL_H */
