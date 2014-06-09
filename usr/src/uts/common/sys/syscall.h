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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 * Copyright (c) 2015, Joyent, Inc.  All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef	_SYS_SYSCALL_H
#define	_SYS_SYSCALL_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *	system call numbers
 *		syscall(SYS_xxxx, ...)
 */

	/* syscall enumeration MUST begin with 1 */

	/*
	 * SunOS/SPARC uses 0 for the indirect system call SYS_syscall
	 * but this doesn't count because it is just another way
	 * to specify the real system call number.
	 */

#define	SYS_syscall	0
#define	SYS_exit	1
#define	SYS_read	3
#define	SYS_write	4
#define	SYS_open	5
#define	SYS_close	6
#define	SYS_linkat	7
#define	SYS_link	9
#define	SYS_unlink	10
#define	SYS_symlinkat	11
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
#define	SYS_readlinkat	22
#define	SYS_setuid	23
#define	SYS_getuid	24
#define	SYS_stime	25
#define	SYS_pcsample	26
#define	SYS_alarm	27
#define	SYS_fstat	28
#define	SYS_pause	29
#define	SYS_stty	31
#define	SYS_gtty	32
#define	SYS_access	33
#define	SYS_nice	34
#define	SYS_statfs	35
#define	SYS_sync	36
#define	SYS_kill	37
#define	SYS_fstatfs	38
#define	SYS_pgrpsys	39
	/*
	 * subcodes:
	 *	getpgrp()	  :: syscall(39,0)
	 *	setpgrp()	  :: syscall(39,1)
	 *	getsid(pid)	  :: syscall(39,2,pid)
	 *	setsid()	  :: syscall(39,3)
	 *	getpgid(pid)	  :: syscall(39,4,pid)
	 *	setpgid(pid,pgid) :: syscall(39,5,pid,pgid)
	 */
#define	SYS_uucopystr	40
#define	SYS_pipe	42
#define	SYS_times	43
#define	SYS_profil	44
#define	SYS_faccessat	45
#define	SYS_setgid	46
#define	SYS_getgid	47
#define	SYS_mknodat	48
#define	SYS_msgsys	49
	/*
	 * subcodes:
	 *	msgget(...)  :: msgsys(0, ...)
	 *	msgctl(...)  :: msgsys(1, ...)
	 *	msgrcv(...)  :: msgsys(2, ...)
	 *	msgsnd(...)  :: msgsys(3, ...)
	 *	msgids(...)  :: msgsys(4, ...)
	 *	msgsnap(...) :: msgsys(5, ...)
	 *	see <sys/msg.h>
	 */
#define	SYS_sysi86	50
	/*
	 * subcodes:
	 *	sysi86(code, ...)
	 */
#define	SYS_acct	51
#define	SYS_shmsys	52
	/*
	 * subcodes:
	 *	shmat (...) :: shmsys(0, ...)
	 *	shmctl(...) :: shmsys(1, ...)
	 *	shmdt (...) :: shmsys(2, ...)
	 *	shmget(...) :: shmsys(3, ...)
	 *	shmids(...) :: shmsys(4, ...)
	 *	see <sys/shm.h>
	 */
#define	SYS_semsys	53
	/*
	 * subcodes:
	 *	semctl(...) :: semsys(0, ...)
	 *	semget(...) :: semsys(1, ...)
	 *	semop (...) :: semsys(2, ...)
	 *	semids(...) :: semsys(3, ...)
	 *	semtimedop(...) :: semsys(4, ...)
	 *	see <sys/sem.h>
	 */
#define	SYS_ioctl	54
#define	SYS_uadmin	55
#define	SYS_fchownat	56
#define	SYS_utssys	57
	/*
	 * subcodes (third argument):
	 *	uname(obuf)  (obsolete)   :: syscall(57, obuf, ign, 0)
	 *					subcode 1 unused
	 *	ustat(dev, obuf)	  :: syscall(57, obuf, dev, 2)
	 *	fusers(path, flags, obuf) :: syscall(57, path, flags, 3, obuf)
	 *	see <sys/utssys.h>
	 */
#define	SYS_fdsync	58
#define	SYS_execve	59
#define	SYS_umask	60
#define	SYS_chroot	61
#define	SYS_fcntl	62
#define	SYS_ulimit	63
#define	SYS_renameat	64
#define	SYS_unlinkat	65
#define	SYS_fstatat	66
#define	SYS_fstatat64	67
#define	SYS_openat	68
#define	SYS_openat64	69
#define	SYS_tasksys	70
	/*
	 * subcodes:
	 * 	settaskid(...) :: tasksys(0, ...)
	 * 	gettaskid(...) :: tasksys(1, ...)
	 * 	getprojid(...) :: tasksys(2, ...)
	 */
#define	SYS_acctctl	71
#define	SYS_exacctsys	72
	/*
	 * subcodes:
	 * 	getacct(...) :: exacct(0, ...)
	 * 	putacct(...) :: exacct(1, ...)
	 * 	wracct(...) :: exacct(2, ...)
	 */
#define	SYS_getpagesizes	73
	/*
	 * subcodes:
	 *	getpagesizes2(...)	:: getpagesizes(0, ...)
	 * 	getpagesizes(...)	:: getpagesizes(1, ...) legacy
	 */
#define	SYS_rctlsys	74
	/*
	 * subcodes:
	 * 	getrctl(...) :: rctlsys(0, ...)
	 * 	setrctl(...) :: rctlsys(1, ...)
	 * 	rctllist(...) :: rctlsys(2, ...)
	 * 	rctlctl(...) :: rctlsys(3, ...)
	 */
#define	SYS_sidsys	75
	/*
	 * subcodes:
	 * 	allocids(...)		:: sidsys(0, ...)
	 * 	idmap_reg(...)		:: sidsys(1, ...)
	 * 	idmap_unreg(...)	:: sidsys(2, ...)
	 */
#define	SYS_lwp_park	77
	/*
	 * subcodes:
	 *	_lwp_park(timespec_t *, lwpid_t)	:: syslwp_park(0, ...)
	 *	_lwp_unpark(lwpid_t, int)		:: syslwp_park(1, ...)
	 *	_lwp_unpark_all(lwpid_t *, int)		:: syslwp_park(2, ...)
	 *	_lwp_unpark_cancel(lwpid_t *, int)	:: syslwp_park(3, ...)
	 *	_lwp_set_park(lwpid_t *, int)		:: syslwp_park(4, ...)
	 */
#define	SYS_sendfilev	78
	/*
	 * subcodes :
	 * 	sendfilev()   :: sendfilev(0, ...)
	 * 	sendfilev64() :: sendfilev(1, ...)
	 */
#define	SYS_rmdir	79
#define	SYS_mkdir	80
#define	SYS_getdents	81
#define	SYS_privsys	82
	/*
	 * subcodes:
	 * 	setppriv(...)		:: privsys(0, ...)
	 * 	getppriv(...)		:: privsys(1, ...)
	 * 	getimplinfo(...)	:: privsys(2, ...)
	 * 	setpflags(...) 		:: privsys(3, ...)
	 * 	getpflags(...) 		:: privsys(4, ...)
	 *	issetugid();		:: privsys(5)
	 */
#define	SYS_ucredsys	83
	/*
	 * subcodes:
	 *	ucred_get(...)		:: ucredsys(0, ...)
	 *	getpeerucred(...)	:: ucredsys(1, ...)
	 */
#define	SYS_sysfs	84
	/*
	 * subcodes:
	 *	sysfs(code, ...)
	 *	see <sys/fstyp.h>
	 */
#define	SYS_getmsg	85
#define	SYS_putmsg	86
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
	/*
	 * subcodes:
	 *			subcode 0 unused
	 *	sigpending(...) :: syscall(99, 1, ...)
	 *	sigfillset(...) :: syscall(99, 2, ...)
	 */
#define	SYS_context	100
	/*
	 * subcodes:
	 *	getcontext(...) :: syscall(100, 0, ...)
	 *	setcontext(...) :: syscall(100, 1, ...)
	 */
#define	SYS_fchmodat	101
#define	SYS_mkdirat	102
#define	SYS_statvfs	103
#define	SYS_fstatvfs	104
#define	SYS_getloadavg	105
#define	SYS_nfssys	106
#define	SYS_waitid	107
#define	SYS_waitsys	SYS_waitid	/* historical */
#define	SYS_sigsendsys	108
#define	SYS_hrtsys	109
#define	SYS_utimesys	110
	/*
	 * subcodes:
	 *	futimens(...)	:: syscall(110, 0, ...)
	 *	utimensat(...)	:: syscall(110, 1, ...)
	 */
#define	SYS_sigresend	111
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
#define	SYS_preadv	123
#define	SYS_pwritev	124
#define	SYS_mmapobj	127
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
#define	SYS_sharefs	140
#define	SYS_seteuid	141
#define	SYS_forksys	142
	/*
	 * subcodes:
	 *	forkx(flags)    :: forksys(0, flags)
	 *	forkallx(flags) :: forksys(1, flags)
	 *	vforkx(flags)   :: forksys(2, flags)
	 */
#define	SYS_sigtimedwait	144
#define	SYS_lwp_info	145
#define	SYS_yield	146
#define	SYS_lwp_sema_post	148
#define	SYS_lwp_sema_trywait	149
#define	SYS_lwp_detach	150
#define	SYS_corectl	151
#define	SYS_modctl	152
#define	SYS_fchroot	153
#define	SYS_vhangup	155
#define	SYS_gettimeofday	156
#define	SYS_getitimer		157
#define	SYS_setitimer		158
#define	SYS_lwp_create		159
#define	SYS_lwp_exit		160
#define	SYS_lwp_suspend		161
#define	SYS_lwp_continue	162
#define	SYS_lwp_kill		163
#define	SYS_lwp_self		164
#define	SYS_lwp_sigmask		165
#define	SYS_lwp_private		166
#define	SYS_lwp_wait		167
#define	SYS_lwp_mutex_wakeup	168
#define	SYS_lwp_cond_wait	170
#define	SYS_lwp_cond_signal	171
#define	SYS_lwp_cond_broadcast	172
#define	SYS_pread		173
#define	SYS_pwrite		174
#define	SYS_llseek		175
#define	SYS_inst_sync		176
#define	SYS_brand		177
#define	SYS_kaio		178
	/*
	 * subcodes:
	 *	aioread(...)	:: kaio(AIOREAD, ...)
	 *	aiowrite(...)	:: kaio(AIOWRITE, ...)
	 *	aiowait(...)	:: kaio(AIOWAIT, ...)
	 *	aiocancel(...)	:: kaio(AIOCANCEL, ...)
	 *	aionotify()	:: kaio(AIONOTIFY)
	 *	aioinit()	:: kaio(AIOINIT)
	 *	aiostart()	:: kaio(AIOSTART)
	 *	see <sys/aio.h>
	 */
#define	SYS_cpc			179
#define	SYS_lgrpsys		180
#define	SYS_meminfosys		SYS_lgrpsys
	/*
	 * subcodes:
	 * 	meminfo(...) :: meminfosys(MISYS_MEMINFO, ...)
	 */
#define	SYS_rusagesys		181
	/*
	 * subcodes:
	 *	getrusage(...) :: rusagesys(RUSAGESYS_GETRUSAGE, ...)
	 *	getvmusage(...)    :: rusagesys(RUSAGESYS_GETVMUSAGE, ...)
	 */
#define	SYS_port		182
	/*
	 * subcodes:
	 *	port_create(...) :: portfs(PORT_CREATE, ...)
	 *	port_associate(...) :: portfs(PORT_ASSOCIATE, ...)
	 *	port_dissociate(...) :: portfs(PORT_DISSOCIATE, ...)
	 *	port_send(...) :: portfs(PORT_SEND, ...)
	 *	port_sendn(...) :: portfs(PORT_SENDN, ...)
	 *	port_get(...) :: portfs(PORT_GET, ...)
	 *	port_getn(...) :: portfs(PORT_GETN, ...)
	 *	port_alert(...) :: portfs(PORT_ALERT, ...)
	 *	port_dispatch(...) :: portfs(PORT_DISPATCH, ...)
	 */
#define	SYS_pollsys		183
#define	SYS_labelsys		184
#define	SYS_acl			185
#define	SYS_auditsys		186
#define	SYS_processor_bind	187
#define	SYS_processor_info	188
#define	SYS_p_online		189
#define	SYS_sigqueue		190
#define	SYS_clock_gettime	191
#define	SYS_clock_settime	192
#define	SYS_clock_getres	193
#define	SYS_timer_create	194
#define	SYS_timer_delete	195
#define	SYS_timer_settime	196
#define	SYS_timer_gettime	197
#define	SYS_timer_getoverrun	198
#define	SYS_nanosleep		199
#define	SYS_facl		200
#define	SYS_door		201
	/*
	 * Door Subcodes:
	 *	0	door_create
	 *	1	door_revoke
	 *	2	door_info
	 *	3	door_call
	 *	4	door_return
	 */
#define	SYS_setreuid		202
#define	SYS_setregid		203
#define	SYS_install_utrap	204
#define	SYS_signotify		205
#define	SYS_schedctl		206
#define	SYS_pset		207
#define	SYS_sparc_utrap_install	208
#define	SYS_resolvepath		209
#define	SYS_lwp_mutex_timedlock	210
#define	SYS_lwp_sema_timedwait	211
#define	SYS_lwp_rwlock_sys	212
	/*
	 * subcodes:
	 *	lwp_rwlock_rdlock(...)    :: syscall(212, 0, ...)
	 *	lwp_rwlock_wrlock(...)    :: syscall(212, 1, ...)
	 *	lwp_rwlock_tryrdlock(...) :: syscall(212, 2, ...)
	 *	lwp_rwlock_trywrlock(...) :: syscall(212, 3, ...)
	 *	lwp_rwlock_unlock(...)    :: syscall(212, 4, ...)
	 */
/* system calls for large file ( > 2 gigabyte) support */
#define	SYS_getdents64		213
#define	SYS_mmap64		214
#define	SYS_stat64		215
#define	SYS_lstat64		216
#define	SYS_fstat64		217
#define	SYS_statvfs64		218
#define	SYS_fstatvfs64		219
#define	SYS_setrlimit64		220
#define	SYS_getrlimit64		221
#define	SYS_pread64		222
#define	SYS_pwrite64		223
#define	SYS_open64		225
#define	SYS_rpcsys		226
#define	SYS_zone		227
	/*
	 * subcodes:
	 *	zone_create(...) :: zone(ZONE_CREATE, ...)
	 *	zone_destroy(...) :: zone(ZONE_DESTROY, ...)
	 *	zone_getattr(...) :: zone(ZONE_GETATTR, ...)
	 *	zone_enter(...) :: zone(ZONE_ENTER, ...)
	 *	zone_list(...) :: zone(ZONE_LIST, ...)
	 *	zone_shutdown(...) :: zone(ZONE_SHUTDOWN, ...)
	 *	zone_lookup(...) :: zone(ZONE_LOOKUP, ...)
	 *	zone_boot(...) :: zone(ZONE_BOOT, ...)
	 *	zone_version(...) :: zone(ZONE_VERSION, ...)
	 *	zone_setattr(...) :: zone(ZONE_SETATTR, ...)
	 *	zone_add_datalink(...) :: zone(ZONE_ADD_DATALINK, ...)
	 *	zone_remove_datalink(...) :: zone(ZONE_DEL_DATALINK, ...)
	 *	zone_check_datalink(...) :: zone(ZONE_CHECK_DATALINK, ...)
	 *	zone_list_datalink(...) :: zone(ZONE_LIST_DATALINK, ...)
	 */
#define	SYS_autofssys		228
#define	SYS_getcwd		229
#define	SYS_so_socket		230
#define	SYS_so_socketpair	231
#define	SYS_bind		232
#define	SYS_listen		233
#define	SYS_accept		234
#define	SYS_connect		235
#define	SYS_shutdown		236
#define	SYS_recv		237
#define	SYS_recvfrom		238
#define	SYS_recvmsg		239
#define	SYS_send		240
#define	SYS_sendmsg		241
#define	SYS_sendto		242
#define	SYS_getpeername		243
#define	SYS_getsockname		244
#define	SYS_getsockopt		245
#define	SYS_setsockopt		246
#define	SYS_sockconfig		247
	/*
	 * NTP codes
	 */
#define	SYS_ntp_gettime		248
#define	SYS_ntp_adjtime		249
#define	SYS_lwp_mutex_unlock	250
#define	SYS_lwp_mutex_trylock	251
#define	SYS_lwp_mutex_register	252
#define	SYS_cladm		253
#define	SYS_uucopy		254
#define	SYS_umount2		255

#ifndef	_ASM

typedef struct {		/* syscall set type */
	unsigned int	word[16];
} sysset_t;

typedef struct {	/* return values from system call */
	long	sys_rval1;	/* primary return value from system call */
	long	sys_rval2;	/* second return value from system call */
} sysret_t;

#if !defined(_KERNEL)

extern int	syscall(int, ...);
extern int	__systemcall(sysret_t *, int, ...);
extern int	__set_errno(int);

#endif	/* _KERNEL */

#endif	/* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SYSCALL_H */
