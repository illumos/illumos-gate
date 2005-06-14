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
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _SYS_SYSCALL_H
#define _SYS_SYSCALL_H

#ident	"%Z%%M%	%I%	%E% SMI"	/* from SVr4.0 1.17 */

/*
 *	system call numbers
 *		syscall(SYS_xxxx, ...)
 */

	/* syscall enumeration MUST begin with 1 */
	/* SunOS/SPARC uses 0 for the indirect system call SYS_syscall */
#define SYS_syscall	0
#define	SYS_exit	1
#define	SYS_fork	2
#define	SYS_read	3
#define	SYS_write	4
#define	SYS_open	5
#define	SYS_close	6
#define	SYS_wait	7
#define	SYS_creat	8
#define	SYS_link	9
#define	SYS_unlink	10
#define	SYS_exec	11
#define	SYS_chdir	12
#define	SYS_time	13
#define	SYS_mknod	14
#define	SYS_chmod	15
#define	SYS_chown	16
#define	SYS_brk		17
#define	SYS_stat	18
#define	SYS_lseek	19
#define	SYS_getpid	20
#define	SYS_mount	21
#define	SYS_umount	22
#define	SYS_setuid	23
#define	SYS_getuid	24
#define	SYS_stime	25
#define	SYS_ptrace	26
#define	SYS_alarm	27
#define	SYS_fstat	28
#define	SYS_pause	29
#define	SYS_utime	30
#define	SYS_stty	31
#define	SYS_gtty	32
#define	SYS_access	33
#define	SYS_nice	34
#define	SYS_statfs	35
#define	SYS_sync	36
#define	SYS_kill	37
#define	SYS_fstatfs	38
#define	SYS_pgrpsys	39
	/* subcodes:
	 *	getpgrp()         :: syscall(39,0)
	 *	setpgrp()         :: syscall(39,1)
	 *	getsid(pid)       :: syscall(39,2,pid)
	 *	setsid()          :: syscall(39,3)
	 *	getpgid(pid)      :: syscall(39,4,pid)
	 *	setpgid(pid,pgid) :: syscall(39,5,pid,pgid)
	 */
#define	SYS_xenix	40
	/* subcodes:
	 *	syscall(40, code, ...)
	 */
#define	SYS_dup		41
#define	SYS_pipe	42
#define	SYS_times	43
#define	SYS_profil	44
#define	SYS_plock	45
#define	SYS_setgid	46
#define	SYS_getgid	47
#define	SYS_signal	48
	/* subcodes:
	 *	signal(sig, f) :: signal(sig, f)    ((sig&SIGNO_MASK) == sig)
	 *	sigset(sig, f) :: signal(sig|SIGDEFER, f)
	 *	sighold(sig)   :: signal(sig|SIGHOLD)
	 *	sigrelse(sig)  :: signal(sig|SIGRELSE)
	 *	sigignore(sig) :: signal(sig|SIGIGNORE)
	 *	sigpause(sig)  :: signal(sig|SIGPAUSE)
	 *	see <sys/signal.h>
	 */
#define	SYS_msgsys	49
	/* subcodes:
	 *	msgget(...) :: msgsys(0, ...)
	 *	msgctl(...) :: msgsys(1, ...)
	 *	msgrcv(...) :: msgsys(2, ...)
	 *	msgsnd(...) :: msgsys(3, ...)
	 *	see <sys/msg.h>
	 */
#define	SYS_syssun	50
	/* subcodes:
	 *	syssun(code, ...)
	 *	see <sys/sys3b.h>
	 */
#define	SYS_acct	51
#define	SYS_shmsys	52
	/* subcodes:
	 *	shmat (...) :: shmsys(0, ...)
	 *	shmctl(...) :: shmsys(1, ...)
	 *	shmdt (...) :: shmsys(2, ...)
	 *	shmget(...) :: shmsys(3, ...)
	 *	see <sys/shm.h>
	 */
#define	SYS_semsys	53
	/* subcodes:
	 *	semctl(...) :: semsys(0, ...)
	 *	semget(...) :: semsys(1, ...)
	 *	semop (...) :: semsys(2, ...)
	 *	see <sys/sem.h>
	 */
#define	SYS_ioctl	54
#define	SYS_uadmin	55
				/* 56 reserved for exch() */
#define	SYS_utssys	57
	/* subcodes (third argument):
	 *	uname(obuf)  (obsolete)   :: syscall(57, obuf, ign, 0)
	 *					subcode 1 unused
	 *	ustat(dev, obuf)          :: syscall(57, obuf, dev, 2)
	 *	fusers(path, flags, obuf) :: syscall(57, path, flags, 3, obuf)
	 *	see <sys/utssys.h>
	 */
#define	SYS_fsync	58
#define	SYS_execve	59
#define	SYS_umask	60
#define	SYS_chroot	61
#define	SYS_fcntl	62
#define	SYS_ulimit	63
				/* 64-69 reserved for UNIX PC */
				/* 70 not used, was advfs */
				/* 71 not used, was unadvfs */
				/* 72 not used, was rmount */
				/* 73 not used, was rumount */
				/* 74 not used, was rfstart */
				/* 75 not used, was sigret(SunOS) */
				/* 76 not used, was rdebug */
				/* 77 not used, was rfstop */
				/* 78 not used, was rfsys */
#define	SYS_rmdir	79
#define	SYS_mkdir	80
#define	SYS_getdents	81
				/* 82 not used, was libattach */
				/* 83 not used, was libdetach */
#define	SYS_sysfs	84
	/* subcodes:
	 *	sysfs(code, ...)
	 *	see <sys/fstyp.h>
	 */
#define	SYS_getmsg	85
#define	SYS_putmsg	86
#define	SYS_poll	87

#define	SYS_lstat	88
#define	SYS_symlink	89
#define	SYS_readlink	90
#define	SYS_setgroups	91
#define	SYS_getgroups	92
#define	SYS_fchmod	93
#define	SYS_fchown	94
#define	SYS_sigprocmask	95
#define	SYS_sigsuspend	96
#define	SYS_sigaltstack	97
#define	SYS_sigaction	98
#define	SYS_sigpending	99
	/* subcodes:
	 *			subcode 0 unused
	 *	sigpending(...) :: syscall(99, 1, ...)
	 *	sigfillset(...) :: syscall(99, 2, ...)
	 */
#define	SYS_context	100
	/* subcodes:
	 *	getcontext(...) :: syscall(100, 0, ...)
	 *	setcontext(...) :: syscall(100, 1, ...)
	 */
#define	SYS_evsys	101
#define	SYS_evtrapret	102
#define	SYS_statvfs	103
#define	SYS_fstatvfs	104
				/* 105 reserved */
#define	SYS_nfssys	106
#define	SYS_waitsys	107
#define	SYS_sigsendsys	108
#define	SYS_hrtsys	109
#define	SYS_acancel	110
#define	SYS_async	111
#define	SYS_priocntlsys	112
#define	SYS_pathconf	113
#define	SYS_mincore	114
#define	SYS_mmap	115
#define	SYS_mprotect	116
#define	SYS_munmap	117
#define	SYS_fpathconf	118
#define	SYS_vfork	119
#define	SYS_fchdir	120
#define	SYS_readv	121
#define	SYS_writev	122
#define	SYS_xstat	123
#define	SYS_lxstat	124
#define	SYS_fxstat	125
#define	SYS_xmknod	126
#define	SYS_clocal	127
#define	SYS_setrlimit	128
#define	SYS_getrlimit	129
#define	SYS_lchown	130
#define	SYS_memcntl	131
#define	SYS_getpmsg	132
#define	SYS_putpmsg	133
#define	SYS_rename	134
#define	SYS_uname	135
#define	SYS_setegid	136
#define	SYS_sysconfig	137
#define	SYS_adjtime	138
#define	SYS_systeminfo	139
#define	SYS_seteuid	141
#define	SYS_fchroot	153
#define	SYS_utimes	154
#define	SYS_vhangup	155
#define	SYS_gettimeofday	156
#define	SYS_getitimer	157
#define	SYS_setitimer	158
#define	SYS_flock	159

#ifndef _SYS_SYS_S

typedef struct {		/* syscall set type */
	unsigned long	word[16];
} sysset_t;

#endif	/* _SYS_SYS_S */

#endif	/* _SYS_SYSCALL_H */
