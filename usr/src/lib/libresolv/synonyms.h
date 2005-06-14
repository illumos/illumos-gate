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
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef	_LIBRESOLV_SYNONYMS_H
#define	_LIBRESOLV_SYNONYMS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__STDC__)

/* external data */
#define	altzone		_altzone
#define	daylight	_daylight
#define	lone		_lone
#define	lten		_lten
#define	lzero		_lzero
#define	timezone	_timezone
#define	tzname		_tzname

/* functions */
#define	Msgdb		_Msgdb
#define	a64l		_a64l
#define	access		_access
#define	acct		_acct
#define	acl		_acl
#define	addseverity	_addseverity
#define	adjtime		_adjtime
#define	alarm		_alarm
#define	ascftime	_ascftime
#define	basename	_basename
#define	brk		_brk
#define	brkbase		_brkbase
#define	bsd_signal	_bsd_signal
#define	catclose	_catclose
#define	catgets		_catgets
#define	catopen		_catopen
#define	cfgetispeed	_cfgetispeed
#define	cfgetospeed	_cfgetospeed
#define	cfree		_cfree
#define	cfsetispeed	_cfsetispeed
#define	cfsetospeed	_cfsetospeed
#define	cftime		_cftime
#define	chdir		_chdir
#define	chmod		_chmod
#define	chown		_chown
#define	chroot		_chroot
#define	close		_close
#define	closedir	_closedir
#define	closelog	_closelog
#define	countbase	_countbase
#define	creat		_creat
#define	crypt		_crypt
#define	ctermid		_ctermid
#define	cuserid		_cuserid
#define	dial		_dial
#define	dirname		_dirname
#define	door_bind		_door_bind
#define	door_call		_door_call
#define	door_create		_door_create
#define	door_cred		_door_cred
#define	door_getparam		_door_getparam
#define	door_info		_door_info
#define	door_return		_door_return
#define	door_revoke		_door_revoke
#define	door_setparam		_door_setparam
#define	door_server_create	_door_server_create
#define	door_ucred		_door_ucred
#define	door_unbind		_door_unbind
#define	drand48		_drand48
#define	dup		_dup
#define	dup2		_dup2
#define	ecvt		_ecvt
#define	edata		_edata
#define	encrypt		_encrypt
#define	end		_end
#define	endgrent	_endgrent
#define	endpwent	_endpwent
#define	endspent	_endspent
#define	endutent	_endutent
#define	endutxent	_endutxent
#define	environ		_environ
#define	erand48		_erand48
#define	etext		_etext
#define	execl		_execl
#define	execle		_execle
#define	execlp		_execlp
#define	execv		_execv
#define	execve		_execve
#define	execvp		_execvp
#define	exportfs	_exportfs
#define	facl		_facl
#define	fattach		_fattach
#define	fchdir		_fchdir
#define	fchmod		_fchmod
#define	fchown		_fchown
#define	fchroot		_fchroot
#define	fcntl		_fcntl
#define	fcvt		_fcvt
#define	fdetach		_fdetach
#define	fdopen		_fdopen
#define	ffs		_ffs
#define	fgetgrent	_fgetgrent
#define	fgetgrent_r	_fgetgrent_r
#define	fgetpwent	_fgetpwent
#define	fgetpwent_r	_fgetpwent_r
#define	fgetspent	_fgetspent
#define	fgetspent_r	_fgetspent_r
#define	finite		_finite
#define	fmtmsg		_fmtmsg
#define	fork		_fork
#define	fork1		_fork1
#define	fpathconf	_fpathconf
#define	fpclass		_fpclass
#define	fpgetmask	_fpgetmask
#define	fpgetround	_fpgetround
#define	fpgetsticky	_fpgetsticky
#define	fprintf		_fprintf
#define	fpsetmask	_fpsetmask
#define	fpsetround	_fpsetround
#define	fpsetsticky	_fpsetsticky
#define	fstat		_fstat
#define	fstatfs		_fstatfs
#define	fstatvfs	_fstatvfs
#define	fsync		_fsync
#define	ftell		_ftell
#define	ftello		_ftello
#define	fseek		_fseek
#define	fseeko		_fseeko
#define	ftok		_ftok
#define	ftruncate	_ftruncate
#define	gcvt		_gcvt
#define	getcontext	_getcontext
#define	getcwd		_getcwd
#define	getdate		_getdate
#if !defined(_REENTRANT)
#define	getdate_err	_getdate_err
#else	/* defined(_REENTRANT) */
#define	_getdate_err	getdate_err
#endif	/* !defined(_REENTRANT) */
#define	getdents	_getdents
#define	getegid		_getegid
#define	geteuid		_geteuid
#define	getgid		_getgid
#define	getgrent	_getgrent
#define	getgrent_r	_getgrent_r
#define	getgrgid	_getgrgid
#define	getgrgid_r	_getgrgid_r
#define	getgrnam	_getgrnam
#define	getgrnam_r	_getgrnam_r
#define	getgroups	_getgroups
#define	gethz		_gethz
#define	getitimer	_getitimer
#define	getlogin	_getlogin
#define	getmntany	_getmntany
#define	getmntent	_getmntent
#define	getmsg		_getmsg
#define	getopt		_getopt
#define	getpass		_getpass
#define	getpassphrase	_getpassphrase
#define	getpgid		_getpgid
#define	getpgrp		_getpgrp
#define	getpid		_getpid
#define	getpmsg		_getpmsg
#define	getppid		_getppid
#define	getpw		_getpw
#define	getpwent	_getpwent
#define	getpwent_r	_getpwent_r
#define	getpwnam	_getpwnam
#define	getpwnam_r	_getpwnam_r
#define	getpwuid	_getpwuid
#define	getpwuid_r	_getpwuid_r
#define	getrlimit	_getrlimit
#define	getsid		_getsid
#define	getspent	_getspent
#define	getspent_r	_getspent_r
#define	getspnam	_getspnam
#define	getspnam_r	_getspnam_r
#define	getsubopt	_getsubopt
#define	gettimeofday	_gettimeofday
#define	gettxt		_gettxt
#define	getuid		_getuid
#define	getutent	_getutent
#define	getutid		_getutid
#define	getutline	_getutline
#define	getutmp		_getutmp
#define	getutmpx	_getutmpx
#define	getutxent	_getutxent
#define	getutxid	_getutxid
#define	getutxline	_getutxline
#define	getvfsany	_getvfsany
#define	getvfsent	_getvfsent
#define	getvfsfile	_getvfsfile
#define	getvfsspec	_getvfsspec
#define	getw		_getw
#define	grantpt		_grantpt
#define	gsignal		_gsignal
#define	gtty		_gtty
#define	hasmntopt	_hasmntopt
#define	hcreate		_hcreate
#define	hdestroy	_hdestroy
#define	hsearch		_hsearch
#define	id2str		_id2str
#define	initgroups	_initgroups
#define	insque		_insque
#define	install_utrap	_install_utrap
#define	ioctl		_ioctl
#define	isastream	_isastream
#define	isatty		_isatty
#define	jrand48		_jrand48
#define	kaio		_kaio
#define	kill		_kill
#define	l64a		_l64a
#define	ladd		_ladd
#define	lchown		_lchown
#define	lckpwdf		_lckpwdf
#define	lcong48		_lcong48
#define	ldivide		_ldivide
#define	lexp10		_lexp10
#define	lfind		_lfind
#define	link		_link
#define	llog10		_llog10
#define	llseek		_llseek
#define	lmul		_lmul
#define	lockf		_lockf
#define	longjmp		_longjmp
#define	lrand48		_lrand48
#define	lsearch		_lsearch
#define	lseek		_lseek
#define	lshiftl		_lshiftl
#define	lsign		_lsign
#define	lstat		_lstat
#define	lsub		_lsub
#define	ltol3		_ltol3
#define	madvise		_madvise
#define	makecontext	_makecontext
#define	makeut		_makeut
#define	makeutx		_makeutx
#define	memalign	_memalign
#define	memccpy		_memccpy
#define	memcntl		_memcntl
#define	memcmp		_memcmp
#define	memcpy		_memcpy
#define	memmove		_memmove
#define	memset		_memset
#define	mincore		_mincore
#define	mkdir		_mkdir
#define	mkfifo		_mkfifo
#define	mknod		_mknod
#define	mktemp		_mktemp
#define	mkstemp		_mkstemp
#define	mlock		_mlock
#define	mlockall	_mlockall
#define	mmap		_mmap
#define	modut		_modut
#define	modutx		_modutx
#define	monitor		_monitor
#define	mount		_mount
#define	mprotect	_mprotect
#define	mrand48		_mrand48
#define	msgctl		_msgctl
#define	msgget		_msgget
#define	msgrcv		_msgrcv
#define	msgsnd		_msgsnd
#define	msync		_msync
#define	munlock		_munlock
#define	munlockall	_munlockall
#define	munmap		_munmap
#define	nfs_getfh	_nfs_getfh
#define	nfssvc		_nfssvc
#define	nftw		_nftw
#define	nice		_nice
#define	nrand48		_nrand48
#define	nss_delete	_nss_delete
#define	nss_endent	_nss_endent
#define	nss_getent	_nss_getent
#define	nss_search	_nss_search
#define	nss_setent	_nss_setent
#define	open		_open
#define	opendir		_opendir
#define	openlog		_openlog
#define	pathconf	_pathconf
#define	pause		_pause
#define	pclose		_pclose
#define	pipe		_pipe
#define	plock		_plock
#define	poll		_poll
#define	popen		_popen
#define	pread		_pread
#define	pset_create	_pset_create
#define	pset_destroy	_pset_destroy
#define	pset_assign	_pset_assign
#define	pset_info	_pset_info
#define	pset_bind	_pset_bind
#define	profil		_profil
#define	psiginfo	_psiginfo
#define	psignal		_psignal
#define	ptrace		_ptrace
#define	ptsname		_ptsname
#define	pwrite		_pwrite
#define	putenv		_putenv
#define	putmsg		_putmsg
#define	putpmsg		_putpmsg
#define	putpwent	_putpwent
#define	putspent	_putspent
#define	pututline	_pututline
#define	pututxline	_pututxline
#define	putw		_putw
#define	read		_read
#define	readdir		_readdir
#define	readdir_r	_readdir_r
#define	readlink	_readlink
#define	readv		_readv
#define	realpath	_realpath
#define	regcmp		_regcmp
#define	regex		_regex
#define	remque		_remque
#define	rmdir		_rmdir
#define	sbrk		_sbrk
#define	seed48		_seed48
#define	seekdir		_seekdir
#define	select		_select
#define	semctl		_semctl
#define	semget		_semget
#define	semop		_semop
#define	setcontext	_setcontext
#define	setegid		_setegid
#define	seteuid		_seteuid
#define	setgid		_setgid
#define	setgrent	_setgrent
#define	setgroups	_setgroups
#define	setitimer	_setitimer
#define	setjmp		_setjmp
#define	setkey		_setkey
#define	setlocale	_setlocale
#define	setlogmask	_setlogmask
#define	setpgid		_setpgid
#define	setpgrp		_setpgrp
#define	setpwent	_setpwent
#define	setregid	_setregid
#define	setreuid	_setreuid
#define	setrlimit	_setrlimit
#define	setsid		_setsid
#define	setspent	_setspent
#define	settimeofday	_settimeofday
#define	setuid		_setuid
#define	setutent	_setutent
#define	setutxent	_setutxent
#define	shmat		_shmat
#define	shmctl		_shmctl
#define	shmdt		_shmdt
#define	shmget		_shmget
#define	sig2str		_sig2str
#define	sigaction	_sigaction
#define	sigaddset	_sigaddset
#define	sigaltstack	_sigaltstack
#define	sigdelset	_sigdelset
#define	sigemptyset	_sigemptyset
#define	sigfillset	_sigfillset
#define	sigflag		_sigflag
#define	sigfpe		_sigfpe
#define	sighold		_sighold
#define	sigignore	_sigignore
#define	siginterrupt	_siginterrupt
#define	sigismember	_sigismember
#define	siglongjmp	_siglongjmp
#define	sigpause	_sigpause
#define	sigpending	_sigpending
#define	sigprocmask	_sigprocmask
#define	sigrelse	_sigrelse
#define	sigsend		_sigsend
#define	sigsendset	_sigsendset
#define	sigset		_sigset
#define	signal		_signal
#define	sigsetjmp	_sigsetjmp
#define	sigsuspend	_sigsuspend
#define	sigwait		_sigwait
#define	sleep		_sleep
#define	srand48		_srand48
#define	ssignal		_ssignal
#define	stat		_stat
#define	statfs		_statfs
#define	statvfs		_statvfs
#define	stime		_stime
#define	str2id		_str2id
#define	str2sig		_str2sig
#define	strdup		_strdup
#define	stty		_stty
#define	swab		_swab
#define	swapcontext	_swapcontext
#define	swapctl		_swapctl
#define	symlink		_symlink
#define	sync		_sync
#define	synchutmp	_synchutmp
#define	syssun		_syssun
#define	sys_errlist	_sys_errlist
#define	sys_nerr	_sys_nerr
#define	syscall		_syscall
#define	sysconf		_sysconf
#define	sysfs		_sysfs
#define	sysinfo		_sysinfo
#define	syslog		_syslog
#define	tcdrain		_tcdrain
#define	tcflow		_tcflow
#define	tcflush		_tcflush
#define	tcgetattr	_tcgetattr
#define	tcgetpgrp	_tcgetpgrp
#define	tcgetsid	_tcgetsid
#define	tcsendbreak	_tcsendbreak
#define	tcsetattr	_tcsetattr
#define	tcsetpgrp	_tcsetpgrp
#define	tdelete		_tdelete
#define	tell		_tell
#define	telldir		_telldir
#define	tempnam		_tempnam
#define	tfind		_tfind
#define	time		_time
#define	times		_times
#define	truncate	_truncate
#define	tsearch		_tsearch
#define	ttyname		_ttyname
#define	ttyslot		_ttyslot
#define	twalk		_twalk
#define	tzname		_tzname
#define	tzset		_tzset
#define	uadmin		_uadmin
#define	ulckpwdf	_ulckpwdf
#define	ulimit		_ulimit
#define	umask		_umask
#define	umount		_umount
#define	uname		_uname
#define	undial		_undial
#define	unlink		_unlink
#define	unlockpt	_unlockpt
#define	unordered	_unordered
#define	updutfile	_updutfile
#define	updutxfile	_updutxfile
#define	updutmp		_updutmp
#define	updutmpx	_updutmpx
#define	updwtmp		_updwtmp
#define	updwtmpx	_updwtmpx
#define	ustat		_ustat
#define	utime		_utime
#define	utimes		_utimes
#define	utmpname	_utmpname
#define	utmpxname	_utmpxname
#define	utssys		_utssys
#define	valloc		_valloc
#define	vfork		_vfork
#define	vhangup		_vhangup
#define	vsyslog		_vsyslog
#define	wait		_wait
#define	waitid		_waitid
#define	waitpid		_waitpid
#define	write		_write
#define	writev		_writev
#define	yield		_yield
#define	_assert		__assert
#define	_ctype		__ctype
#define	_filbuf		__filbuf
#define	_flsbuf		__flsbuf
#define	_iob		__iob

/* fp and ll functions */
#define	decimal_to_double	_decimal_to_double
#define	decimal_to_extended	_decimal_to_extended
#define	decimal_to_quadruple	_decimal_to_quadruple
#define	decimal_to_single	_decimal_to_single
#define	double_to_decimal	_double_to_decimal
#define	econvert		_econvert
#define	extended_to_decimal	_extended_to_decimal
#define	fconvert		_fconvert
#define	file_to_decimal		_file_to_decimal
#define	func_to_decimal		_func_to_decimal
#define	gconvert		_gconvert
#define	qeconvert		_qeconvert
#define	qecvt			_qecvt
#define	qfconvert		_qfconvert
#define	qfcvt			_qfcvt
#define	qgconvert		_qgconvert
#define	qgcvt			_qgcvt
#define	quadruple_to_decimal	_quadruple_to_decimal
#define	seconvert		_seconvert
#define	sfconvert		_sfconvert
#define	sgconvert		_sgconvert
#define	single_to_decimal	_single_to_decimal
#define	string_to_decimal	_string_to_decimal
#define	atoll			_atoll
#define	llabs			_llabs
#define	lldiv			_lldiv
#define	lltostr			_lltostr
#define	strtoll			_strtoll
#define	strtoull		_strtoull
#define	ulltostr		_ulltostr

#if !defined(_LP64)
/* transitional large file interfaces */
#define	creat64		_creat64
#define	ftello64	_ftello64
#define	fseeko64	_fseeko64
#define	fstat64		_fstat64
#define	ftw64		_ftw64
#define	fstatvfs64	_fstatvfs64
#define	ftruncate64	_ftruncate64
#define	getdents64	_getdents64
#define	getrlimit64	_getrlimit64
#define	lockf64		_lockf64
#define	lseek64		_lseek64
#define	lstat64		_lstat64
#define	mkstemp64	_mkstemp64
#define	mmap64		_mmap64
#define	nftw64		_nftw64
#define	open64		_open64
#define	pread64		_pread64
#define	pwrite64	_pwrite64
#define	readdir64	_readdir64
#define	readdir64_r	_readdir64_r
#define	seekdir64	_seekdir64
#define	telldir64	_telldir64
#define	setrlimit64	_setrlimit64
#define	stat64		_stat64
#define	statvfs64	_statvfs64
#define	truncate64	_truncate64
#endif	/* !_LP64 */

#else  /* !defined(__STDC__) */

#if !defined(_ASM)
#define	const

#if !defined(_SIZE_T)
#define	_SIZE_T
typedef unsigned int	size_t;
#endif /* !defined(_SIZE_T) */
#endif /* !defined(_ASM) */

#endif /* defined(__STDC__) */

#ifdef __cplusplus
}
#endif

#endif	/* _LIBRESOLV_SYNONYMS_H */
