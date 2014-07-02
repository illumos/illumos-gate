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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/thread.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/proc.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/model.h>
#include <sys/brand.h>
#include <sys/machbrand.h>
#include <sys/lx_syscalls.h>
#include <sys/lx_brand.h>
#include <sys/lx_impl.h>

/*
 * Some system calls return either a 32-bit or a 64-bit value, depending
 * on the datamodel.
 */
#ifdef	_LP64
#define	V_RVAL	SE_64RVAL
#else
#define	V_RVAL	SE_32RVAL1
#endif

/*
 * Define system calls that return a native 'long' quantity i.e. a 32-bit
 * or 64-bit integer - depending on how the kernel is itself compiled
 * e.g. read(2) returns 'ssize_t' in the kernel and in userland.
 */
#define	LX_CL(name, call, narg)      \
	{ V_RVAL, (name), (llfcn_t)(call), (narg) }

/*
 * Returns a 32 bit quantity regardless of datamodel
 */
#define	LX_CI(name, call, narg)      \
	{ SE_32RVAL1, (name), (llfcn_t)(call), (narg) }

extern longlong_t lx_nosys(void);
#define	LX_NOSYS(name)			\
	{SE_64RVAL, (name), (llfcn_t)lx_nosys, 0}

lx_sysent_t lx_sysent[] =
{
	LX_NOSYS("lx_nosys"),					/* 0 */
	LX_NOSYS("exit"),					/* 0 */
	LX_NOSYS("lx_fork"),
	LX_NOSYS("read"),
	LX_NOSYS("write"),
	LX_NOSYS("open"),
	LX_NOSYS("close"),
	LX_NOSYS("waitpid"),
	LX_NOSYS("creat"),
	LX_NOSYS("link"),
	LX_NOSYS("unlink"),					/* 10 */
	LX_NOSYS("exec"),
	LX_NOSYS("chdir"),
	LX_NOSYS("gtime"),
	LX_NOSYS("mknod"),
	LX_NOSYS("chmod"),
	LX_NOSYS("lchown16"),
	LX_NOSYS("break"),
	LX_NOSYS("stat"),
	LX_NOSYS("lseek"),
	LX_CL("getpid",	lx_getpid,	0),			/* 20 */
	LX_NOSYS("mount"),
	LX_NOSYS("umount"),
	LX_NOSYS("setuid16"),
	LX_NOSYS("getuid16"),
	LX_NOSYS("stime"),
	LX_NOSYS("ptrace"),
	LX_NOSYS("alarm"),
	LX_NOSYS("fstat"),
	LX_NOSYS("pause"),
	LX_NOSYS("utime"),					/* 30 */
	LX_NOSYS("stty"),
	LX_NOSYS("gtty"),
	LX_NOSYS("access"),
	LX_NOSYS("nice"),
	LX_NOSYS("ftime"),
	LX_NOSYS("sync"),
	LX_CL("kill",		lx_kill,		2),
	LX_NOSYS("rename"),
	LX_NOSYS("mkdir"),
	LX_NOSYS("rmdir"),					/* 40 */
	LX_NOSYS("dup"),
	LX_CL("pipe",	lx_pipe,	1),
	LX_NOSYS("times"),
	LX_NOSYS("prof"),
	LX_CL("brk",	lx_brk,		1),
	LX_NOSYS("setgid16"),
	LX_NOSYS("getgid16"),
	LX_NOSYS("signal"),
	LX_NOSYS("geteuid16"),
	LX_NOSYS("getegid16"),					/* 50 */
	LX_NOSYS("sysacct"),
	LX_NOSYS("umount2"),
	LX_NOSYS("lock"),
	LX_NOSYS("ioctl"),
	LX_NOSYS("fcntl"),
	LX_NOSYS("mpx"),
	LX_NOSYS("setpgid"),
	LX_NOSYS("ulimit"),
	LX_NOSYS("olduname"),
	LX_NOSYS("umask"),					/* 60 */
	LX_NOSYS("chroot"),
	LX_NOSYS("ustat"),
	LX_NOSYS("dup2"),
	LX_CL("getppid",	lx_getppid,	0),
	LX_NOSYS("pgrp"),
	LX_NOSYS("setsid"),
	LX_NOSYS("sigaction"),
	LX_NOSYS("sgetmask"),
	LX_NOSYS("ssetmask"),
	LX_NOSYS("setreuid16"),					/* 70 */
	LX_NOSYS("setregid16"),
	LX_NOSYS("sigsuspend"),
	LX_NOSYS("sigpending"),
	LX_NOSYS("sethostname"),
	LX_NOSYS("setrlimit"),
	LX_NOSYS("old_getrlimit"),
	LX_NOSYS("getrusage"),
	LX_NOSYS("gettimeofday"),
	LX_NOSYS("settimeofday"),
	LX_NOSYS("getgroups16"),				/* 80 */
	LX_NOSYS("setgroups16"),
	LX_NOSYS("old_select"),
	LX_NOSYS("symlink"),
	LX_NOSYS("oldlstat"),
	LX_NOSYS("readlink"),
	LX_NOSYS("uselib"),
	LX_NOSYS("swapon"),
	LX_NOSYS("reboot"),
	LX_NOSYS("old_readdir"),
	LX_NOSYS("old_mmap"),					/* 90 */
	LX_NOSYS("munmap"),
	LX_NOSYS("truncate"),
	LX_NOSYS("ftruncate"),
	LX_NOSYS("fchmod"),
	LX_NOSYS("fchown16"),
	LX_NOSYS("getpriority"),
	LX_NOSYS("setpriority"),
	LX_NOSYS("profil"),
	LX_NOSYS("statfs"),
	LX_NOSYS("fstatfs"),					/* 100 */
	LX_NOSYS("ioperm"),
	LX_NOSYS("socketcall"),
	LX_NOSYS("syslog"),
	LX_NOSYS("setitimer"),
	LX_NOSYS("getitimer"),
	LX_NOSYS("newstat"),
	LX_NOSYS("newsltat"),
	LX_NOSYS("newsftat"),
	LX_NOSYS("uname"),
	LX_NOSYS("oldiopl"),					/* 110 */
	LX_NOSYS("oldvhangup"),
	LX_NOSYS("idle"),
	LX_NOSYS("vm86old"),
	LX_NOSYS("wait4"),
	LX_NOSYS("swapoff"),
	LX_CL("sysinfo", lx_sysinfo,	1),
	LX_NOSYS("ipc"),
	LX_NOSYS("fsync"),
	LX_NOSYS("sigreturn"),
	LX_CL("clone",	lx_clone,	5),			/* 120 */
	LX_NOSYS("setdomainname"),
	LX_NOSYS("newuname"),
	LX_CL("modify_ldt",	lx_modify_ldt,	3),
	LX_NOSYS("adjtimex"),
	LX_NOSYS("mprotect"),
	LX_NOSYS("sigprocmask"),
	LX_NOSYS("create_module"),
	LX_NOSYS("init_module"),
	LX_NOSYS("delete_module"),
	LX_NOSYS("get_kernel_syms"),				/* 130 */
	LX_NOSYS("quotactl"),
	LX_NOSYS("getpgid"),
	LX_NOSYS("fchdir"),
	LX_NOSYS("bdflush"),
	LX_NOSYS("sysfs"),
	LX_NOSYS("personality"),
	LX_NOSYS("afs_syscall"),
	LX_NOSYS("setfsuid16"),
	LX_NOSYS("setfsgid16"),
	LX_NOSYS("llseek"),					/* 140 */
	LX_NOSYS("getdents"),
	LX_NOSYS("select"),
	LX_NOSYS("flock"),
	LX_NOSYS("msync"),
	LX_NOSYS("readv"),
	LX_NOSYS("writev"),
	LX_NOSYS("getsid"),
	LX_NOSYS("fdatasync"),
	LX_NOSYS("sysctl"),
	LX_NOSYS("mlock"),					/* 150 */
	LX_NOSYS("munlock"),
	LX_NOSYS("mlockall"),
	LX_NOSYS("munlockall"),
	LX_CL("sched_setparam",	lx_sched_setparam, 2),
	LX_CL("sched_getparam",	lx_sched_getparam, 2),
	LX_NOSYS("sched_setscheduler"),
	LX_NOSYS("sched_getscheduler"),
	LX_NOSYS("yield"),
	LX_NOSYS("sched_get_priority_max"),
	LX_NOSYS("sched_get_priority_min"),			/* 160 */
	LX_CL("sched_rr_get_interval", lx_sched_rr_get_interval, 2),
	LX_NOSYS("nanosleep"),
	LX_NOSYS("mremap"),
	LX_CL("setresuid16",		lx_setresuid16,	3),
	LX_NOSYS("getresuid16"),
	LX_NOSYS("vm86"),
	LX_NOSYS("query_module"),
	LX_NOSYS("poll"),
	LX_NOSYS("nfsserctl"),
	LX_CL("setresgid16",		lx_setresgid16, 3),	/* 170 */
	LX_NOSYS("getresgid16"),
	LX_NOSYS("prctl"),
	LX_NOSYS("rt_sigreturn"),
	LX_NOSYS("rt_sigaction"),
	LX_NOSYS("rt_sigprocmask"),
	LX_NOSYS("rt_sigpending"),
	LX_NOSYS("rt_sigtimedwait"),
	LX_NOSYS("rt_sigqueueinfo"),
	LX_NOSYS("rt_sigsuspend"),
	LX_NOSYS("pread64"),					/* 180 */
	LX_NOSYS("pwrite64"),
	LX_NOSYS("chown16"),
	LX_NOSYS("getcwd"),
	LX_NOSYS("capget"),
	LX_NOSYS("capset"),
	LX_NOSYS("sigaltstack"),
	LX_NOSYS("sendfile"),
	LX_NOSYS("getpmsg"),
	LX_NOSYS("putpmsg"),
	LX_NOSYS("vfork"),					/* 190 */
	LX_NOSYS("getrlimit"),
	LX_NOSYS("mmap2"),
	LX_NOSYS("truncate64"),
	LX_NOSYS("ftruncate64"),
	LX_NOSYS("stat64"),
	LX_NOSYS("lstat64"),
	LX_NOSYS("fstat64"),
	LX_NOSYS("lchown"),
	LX_NOSYS("getuid"),
	LX_NOSYS("getgid"),					/* 200 */
	LX_NOSYS("geteuid"),
	LX_NOSYS("getegid"),
	LX_NOSYS("setreuid"),
	LX_NOSYS("setregid"),
	LX_NOSYS("getgroups"),
	LX_CL("setgroups",	lx_setgroups,	2),
	LX_NOSYS("fchown"),
	LX_CL("setresuid",	lx_setresuid,	3),
	LX_NOSYS("getresuid"),
	LX_CL("setresgid",	lx_setresgid,	3),		/* 210 */
	LX_NOSYS("getresgid"),
	LX_NOSYS("chown"),
	LX_NOSYS("setuid"),
	LX_NOSYS("setgid"),
	LX_NOSYS("setfsuid"),
	LX_NOSYS("setfsgid"),
	LX_NOSYS("pivot_root"),
	LX_NOSYS("mincore"),
	LX_NOSYS("madvise"),
	LX_NOSYS("getdents64"),					/* 220 */
	LX_NOSYS("fcntl64"),
	LX_NOSYS("lx_nosys"),
	LX_NOSYS("security"),
	LX_CL("gettid",	lx_gettid,	0),
	LX_NOSYS("readahead"),
	LX_NOSYS("setxattr"),
	LX_NOSYS("lsetxattr"),
	LX_NOSYS("fsetxattr"),
	LX_NOSYS("getxattr"),
	LX_NOSYS("lgetxattr"),					/* 230 */
	LX_NOSYS("fgetxattr"),
	LX_NOSYS("listxattr"),
	LX_NOSYS("llistxattr"),
	LX_NOSYS("flistxattr"),
	LX_NOSYS("removexattr"),
	LX_NOSYS("lremovexattr"),
	LX_NOSYS("fremovexattr"),
	LX_CL("tkill",		lx_tkill,		2),
	LX_NOSYS("sendfile64"),
	LX_CL("futex",		lx_futex,		6), 	/* 240 */
	LX_NOSYS("sched_setaffinity"),
	LX_NOSYS("sched_getaffinity"),
	LX_CL("set_thread_area",	lx_set_thread_area,	1),
	LX_CL("get_thread_area",	lx_get_thread_area,	1),
	LX_NOSYS("io_setup"),
	LX_NOSYS("io_destroy"),
	LX_NOSYS("io_getevents"),
	LX_NOSYS("io_submit"),
	LX_NOSYS("io_cancel"),
	LX_NOSYS("fadvise64"),					/* 250 */
	LX_NOSYS("lx_nosys"),
	LX_NOSYS("exit_group"),
	LX_NOSYS("lookup_dcookie"),
	LX_NOSYS("epoll_create"),
	LX_NOSYS("epoll_ctl"),
	LX_NOSYS("epoll_wait"),
	LX_NOSYS("remap_file_pages"),
	LX_CL("set_tid_address",	lx_set_tid_address,	1),
	LX_NOSYS("timer_create"),
	LX_NOSYS("timer_settime"),				/* 260 */
	LX_NOSYS("timer_gettime"),
	LX_NOSYS("timer_getoverrun"),
	LX_NOSYS("timer_delete"),
	LX_NOSYS("clock_settime"),
	LX_NOSYS("clock_gettime"),
	LX_NOSYS("clock_getres"),
	LX_NOSYS("clock_nanosleep"),
	LX_NOSYS("statfs64"),
	LX_NOSYS("fstatfs64"),
	LX_NOSYS("tgkill"),					/* 270 */
	/* The following are Linux 2.6 system calls */
	LX_NOSYS("utimes"),
	LX_NOSYS("fadvise64_64"),
	LX_NOSYS("vserver"),
	LX_NOSYS("mbind"),
	LX_NOSYS("get_mempolicy"),
	LX_NOSYS("set_mempolicy"),
	LX_NOSYS("mq_open"),
	LX_NOSYS("mq_unlink"),
	LX_NOSYS("mq_timedsend"),
	LX_NOSYS("mq_timedreceive"),				/* 280 */
	LX_NOSYS("mq_notify"),
	LX_NOSYS("mq_getsetattr"),
	LX_NOSYS("kexec_load"),
	LX_NOSYS("waitid"),
	LX_NOSYS("sys_setaltroot"),
	LX_NOSYS("add_key"),
	LX_NOSYS("request_key"),
	LX_NOSYS("keyctl"),
	LX_NOSYS("ioprio_set"),
	LX_NOSYS("ioprio_get"),					/* 290 */
	LX_NOSYS("inotify_init"),
	LX_NOSYS("inotify_add_watch"),
	LX_NOSYS("inotify_rm_watch"),
	LX_NOSYS("migrate_pages"),
	LX_NOSYS("openat"),
	LX_NOSYS("mkdirat"),
	LX_NOSYS("mknodat"),
	LX_NOSYS("fchownat"),
	LX_NOSYS("futimesat"),
	LX_NOSYS("fstatat64"),					/* 300 */
	LX_NOSYS("unlinkat"),
	LX_NOSYS("renameat"),
	LX_NOSYS("linkat"),
	LX_NOSYS("syslinkat"),
	LX_NOSYS("readlinkat"),
	LX_NOSYS("fchmodat"),
	LX_NOSYS("faccessat"),
	LX_NOSYS("pselect6"),
	LX_NOSYS("ppoll"),
	LX_NOSYS("unshare"),					/* 310 */
	LX_NOSYS("set_robust_list"),
	LX_NOSYS("get_robust_list"),
	LX_NOSYS("splice"),
	LX_NOSYS("sync_file_range"),
	LX_NOSYS("tee"),
	LX_NOSYS("vmsplice"),
	LX_NOSYS("move_pages"),
	LX_NOSYS("getcpu"),
	LX_NOSYS("epoll_pwait"),
	LX_NOSYS("utimensat"),					/* 320 */
	LX_NOSYS("signalfd"),
	LX_NOSYS("timerfd_create"),
	LX_NOSYS("eventfd"),
	LX_NOSYS("fallocate"),
	LX_NOSYS("timerfd_settime"),
	LX_NOSYS("timerfd_gettime"),
	LX_NOSYS("signalfd4"),
	LX_NOSYS("eventfd2"),
	LX_NOSYS("epoll_create1"),
	LX_NOSYS("dup3"),					/* 330 */
	LX_CL("pipe2",	lx_pipe2,	2),
	LX_NOSYS("inotify_init1"),
	LX_NOSYS("preadv"),
	LX_NOSYS("pwritev"),
	LX_NOSYS("rt_tgsigqueueinfo"),
	LX_NOSYS("perf_event_open"),
	LX_NOSYS("recvmmsg"),
	LX_NOSYS("fanotify_init"),
	LX_NOSYS("fanotify_mark"),
	LX_NOSYS("prlimit64"),					/* 340 */
	LX_NOSYS("name_to_handle_at"),
	LX_NOSYS("open_by_handle_at"),
	LX_NOSYS("clock_adjtime"),
	LX_NOSYS("syncfs"),
	LX_NOSYS("sendmmsg"),
	LX_NOSYS("setns"),
	LX_NOSYS("process_vm_readv"),
	LX_NOSYS("process_vm_writev"),
	LX_NOSYS("kcmp"),
	LX_NOSYS("finit_module"),				/* 350 */
	LX_NOSYS("sched_setattr"),
	LX_NOSYS("sched_getattr"),
	NULL	/* NULL-termination is required for lx_systrace */
};

int64_t
lx_emulate_syscall(int num, uintptr_t arg1, uintptr_t arg2,
    uintptr_t arg3, uintptr_t arg4, uintptr_t arg5, uintptr_t arg6)
{
	struct lx_sysent *jsp;
	int64_t rval;

	rval = (int64_t)0;

	jsp = &(lx_sysent[num]);

	switch (jsp->sy_narg) {
	case 0: {
		lx_print("--> %s()\n", jsp->sy_name);
		rval = (int64_t)jsp->sy_callc();
		break;
	}
	case 1: {
		lx_print("--> %s(0x%lx)\n", jsp->sy_name, arg1);
		rval = (int64_t)jsp->sy_callc(arg1);
		break;
	}
	case 2: {
		lx_print("--> %s(0x%lx, 0x%lx)\n", jsp->sy_name, arg1, arg2);
		rval = (int64_t)jsp->sy_callc(arg1, arg2);
		break;
	}
	case 3: {
		lx_print("--> %s(0x%lx, 0x%lx, 0x%lx)\n",
		    jsp->sy_name, arg1, arg2, arg3);
		rval = (int64_t)jsp->sy_callc(arg1, arg2, arg3);
		break;
	}
	case 4: {
		lx_print("--> %s(0x%lx, 0x%lx, 0x%lx, 0x%lx)\n",
		    jsp->sy_name, arg1, arg2, arg3, arg4);
		rval = (int64_t)jsp->sy_callc(arg1, arg2, arg3, arg4);
		break;
	}
	case 5: {
		lx_print("--> %s(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)\n",
		    jsp->sy_name, arg1, arg2, arg3, arg4, arg5);
		rval = (int64_t)jsp->sy_callc(arg1, arg2, arg3, arg4, arg5);
		break;
	}
	case 6: {
		lx_print("--> %s(0x%lx, 0x%lx, 0x%lx, 0x%lx,"
		    " 0x%lx, 0x%lx)\n",
		    jsp->sy_name, arg1, arg2, arg3, arg4, arg5, arg6);
		rval = (int64_t)jsp->sy_callc(arg1, arg2, arg3, arg4, arg5,
		    arg6);
		break;
	}
	default:
		panic("Invalid syscall entry: #%d at 0x%p\n", num, (void *)jsp);
	}
	lx_print("----------> return  (0x%llx)\n", (long long)rval);
	return (rval);
}
