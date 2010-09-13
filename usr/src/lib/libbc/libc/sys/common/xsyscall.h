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
 *
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	from UCB 4.11 06/09/83	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	__sys_syscall_h
#define	__sys_syscall_h

/* List of SunOS 4.1 system call numbers. All SYS_* have been
 * renamed to XSYS_* to avoid confusion with the new SunOS/SVR4
 * numbers used in other routines in libbc. */

#define	XSYS_exit	1
#define	XSYS_fork	2
#define	XSYS_read	3
#define	XSYS_write	4
#define	XSYS_open	5
#define	XSYS_close	6
#define	XSYS_wait4	7
#define	XSYS_creat	8
#define	XSYS_link	9
#define	XSYS_unlink	10
#define	XSYS_execv	11
#define	XSYS_chdir	12
				/* 13 is old: time */
#define	XSYS_mknod	14
#define	XSYS_chmod	15
#define	XSYS_chown	16
				/* 17 is old: sbreak */
				/* 18 is old: stat */
#define	XSYS_lseek	19
#define	XSYS_getpid	20
				/* 21 is old: mount */
				/* 22 is old: umount */
				/* 23 is old: setuid */
#define	XSYS_getuid	24
				/* 25 is old: stime */
#define	XSYS_ptrace	26
				/* 27 is old: alarm */
				/* 28 is old: fstat */
				/* 29 is old: pause */
				/* 30 is old: utime */
				/* 31 is old: stty */
				/* 32 is old: gtty */
#define	XSYS_access	33
				/* 34 is old: nice */
				/* 35 is old: ftime */
#define	XSYS_sync	36
#define	XSYS_kill	37
#define	XSYS_stat	38
				/* 39 is old: setpgrp */
#define	XSYS_lstat	40
#define	XSYS_dup		41
#define	XSYS_pipe	42
				/* 43 is old: times */
#define	XSYS_profil	44
				/* 45 is unused */
				/* 46 is old: setgid */
#define	XSYS_getgid	47
				/* 48 is old: sigsys */
				/* 49 is unused */
				/* 50 is unused */
#define	XSYS_acct	51
				/* 52 is old: phys */
#define	XSYS_mctl	53
#define	XSYS_ioctl	54
#define	XSYS_reboot	55
				/* 56 is old: mpxchan */
#define	XSYS_symlink	57
#define	XSYS_readlink	58
#define	XSYS_execve	59
#define	XSYS_umask	60
#define	XSYS_chroot	61
#define	XSYS_fstat	62
				/* 63 is unused */
#define	XSYS_getpagesize 64
#define	XSYS_msync	65
				/* 66 is old: vfork */
				/* 67 is old: vread */
				/* 68 is old: vwrite */
#define	XSYS_sbrk	69
#define	XSYS_sstk	70
#define	XSYS_mmap	71
#define	XSYS_vadvise	72
#define	XSYS_munmap	73
#define	XSYS_mprotect	74
#define	XSYS_madvise	75
#define	XSYS_vhangup	76
				/* 77 is old: vlimit */
#define	XSYS_mincore	78
#define	XSYS_getgroups	79
#define	XSYS_setgroups	80
#define	XSYS_getpgrp	81
#define	XSYS_setpgrp	82
#define	XSYS_setitimer	83
				/* 84 is old: wait & wait3 */
#define	XSYS_swapon	85
#define	XSYS_getitimer	86
#define	XSYS_gethostname	87
#define	XSYS_sethostname	88
#define	XSYS_getdtablesize 89
#define	XSYS_dup2	90
#define	XSYS_getdopt	91
#define	XSYS_fcntl	92
#define	XSYS_select	93
#define	XSYS_setdopt	94
#define	XSYS_fsync	95
#define	XSYS_setpriority	96
#define	XSYS_socket	97
#define	XSYS_connect	98
#define	XSYS_accept	99
#define	XSYS_getpriority	100
#define	XSYS_send	101
#define	XSYS_recv	102
				/* 103 was socketaddr */
#define	XSYS_bind	104
#define	XSYS_setsockopt	105
#define	XSYS_listen	106
				/* 107 was vtimes */
#define	XSYS_sigvec	108
#define	XSYS_sigblock	109
#define	XSYS_sigsetmask	110
#define	XSYS_sigpause	111
#define	XSYS_sigstack	112
#define	XSYS_recvmsg	113
#define	XSYS_sendmsg	114
#define	XSYS_vtrace	115
#define	XSYS_gettimeofday 116
#define	XSYS_getrusage	117
#define	XSYS_getsockopt	118
				/* 119 is old resuba */
#define	XSYS_readv	120
#define	XSYS_writev	121
#define	XSYS_settimeofday 122
#define	XSYS_fchown	123
#define	XSYS_fchmod	124
#define	XSYS_recvfrom	125
#define	XSYS_setreuid	126
#define	XSYS_setregid	127
#define	XSYS_rename	128
#define	XSYS_truncate	129
#define	XSYS_ftruncate	130
#define	XSYS_flock	131
				/* 132 is unused */
#define	XSYS_sendto	133
#define	XSYS_shutdown	134
#define	XSYS_socketpair	135
#define	XSYS_mkdir	136
#define	XSYS_rmdir	137
#define	XSYS_utimes	138
				/* 139 is unused */
#define	XSYS_adjtime	140
#define	XSYS_getpeername	141
#define	XSYS_gethostid	142
				/* 143 is old: sethostid */
#define	XSYS_getrlimit	144
#define	XSYS_setrlimit	145
#define	XSYS_killpg	146
				/* 147 is unused */
				/* 148 is old: setquota */
				/* 149 is old: quota */
#define	XSYS_getsockname	150
#define	XSYS_getmsg	151
#define	XSYS_putmsg	152
#define	XSYS_poll	153
				/* 154 is old: nfs_mount */
#define	XSYS_nfssvc	155
#define	XSYS_getdirentries 156
#define	XSYS_statfs	157
#define	XSYS_fstatfs	158
#define	XSYS_unmount	159
#define	XSYS_async_daemon 160
#define	XSYS_getfh	161
#define	XSYS_getdomainname 162
#define	XSYS_setdomainname 163
				/* 164 is old: pcfs_mount */
#define	XSYS_quotactl	165
#define	XSYS_exportfs	166
#define	XSYS_mount	167
#define	XSYS_ustat	168
#define	XSYS_semsys	169
#define	XSYS_msgsys	170
#define	XSYS_shmsys	171
#define	XSYS_auditsys	172
				/* 173 is old: rfsys */
#define	XSYS_getdents	174
#define	XSYS_setsid	175
#define	XSYS_fchdir	176
#define	XSYS_fchroot	177
#define	XSYS_vpixsys	178

#define	XSYS_aioread	179
#define	XSYS_aiowrite	180
#define	XSYS_aiowait	181
#define	XSYS_aiocancel	182

#define	XSYS_sigpending	183
				/* 184 is available */
#define	XSYS_setpgid	185
#define	XSYS_pathconf	186
#define	XSYS_fpathconf	187
#define	XSYS_sysconf	188

#define	XSYS_uname	189

#endif	/* !__sys_syscall_h */
