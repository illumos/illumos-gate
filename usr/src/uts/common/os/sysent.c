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
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved.
 * Copyright (c) 2015, Joyent, Inc.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/systrace.h>
#include <sys/procfs.h>
#include <sys/mman.h>
#include <sys/int_types.h>
#include <c2/audit.h>
#include <sys/stat.h>
#include <sys/times.h>
#include <sys/statfs.h>
#include <sys/stropts.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <sys/timex.h>
#include <sys/socket.h>
#include <sys/sendfile.h>

struct hrtsysa;
struct mmaplf32a;

/*
 * This table is the switch used to transfer to the appropriate
 * routine for processing a system call.  Each row contains the
 * number of arguments expected, a switch that tells systrap()
 * in trap.c whether a setjmp() is not necessary, and a pointer
 * to the routine.
 */

int	access(char *, int);
int	alarm(int);
int	auditsys(struct auditcalls *, rval_t *);
int64_t	brandsys(int, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t,
    uintptr_t);
int	brk(caddr_t);
int	chdir(char *);
int	chmod(char *, int);
int	chown(char *, uid_t, gid_t);
int	chroot(char *);
int	cladm(int, int, void *);
int	close(int);
int	exece(const char *, const char **, const char **);
int	faccessat(int, char *, int, int);
int	fchmodat(int, char *, int, int);
int	fchownat(int, char *, uid_t, gid_t, int);
int	fcntl(int, int, intptr_t);
int64_t	vfork();
int64_t	forksys(int, int);
int	fstat(int, struct stat *);
int	fdsync(int, int);
int64_t	getgid();
int	ucredsys(int, int, void *);
int64_t	getpid();
int64_t	getuid();
time_t	gtime();
int	getloadavg(int *, int);
int	rusagesys(int, void *, void *, void *, void *);
int	getpagesizes(int, size_t *, int);
int	gtty(int, intptr_t);
#if defined(__i386) || defined(__amd64)
int	hrtsys(struct hrtsysa *, rval_t *);
#endif /* __i386 || __amd64 */
int	ioctl(int, int, intptr_t);
int	kill();
int	labelsys(int, void *, void *, void *, void *, void *);
int	link(char *, char *);
int	linkat(int, char *, int, char *, int);
off32_t	lseek32(int32_t, off32_t, int32_t);
off_t	lseek64(int, off_t, int);
int	lgrpsys(int, long, void *);
int	mmapobjsys(int, uint_t, mmapobj_result_t *, uint_t *, void *);
int	mknod(char *, mode_t, dev_t);
int	mknodat(int, char *, mode_t, dev_t);
int	mount(long *, rval_t *);
int	nice(int);
int	nullsys();
int	open(char *, int, int);
int	openat(int, char *, int, int);
int	pause();
long	pcsample(void *, long);
int	privsys(int, priv_op_t, priv_ptype_t, void *, size_t, int);
int	profil(unsigned short *, size_t, ulong_t, uint_t);
ssize_t	pread(int, void *, size_t, off_t);
ssize_t	pwrite(int, void *, size_t, off_t);
ssize_t	read(int, void *, size_t);
int	rename(char *, char *);
int	renameat(int, char *, int, char *);
void	rexit(int);
int	semsys();
int	setgid(gid_t);
int	setpgrp(int, int, int);
int	setuid(uid_t);
uintptr_t	shmsys();
uint64_t	sidsys(int, int, int, int);
int	sigprocmask(int, sigset_t *, sigset_t *);
int	sigsuspend(sigset_t);
int	sigaltstack(struct sigaltstack *, struct sigaltstack *);
int	sigaction(int, struct sigaction *, struct sigaction *);
int	sigpending(int, sigset_t *);
int	sigresend(int, siginfo_t *, sigset_t *);
int	sigtimedwait(sigset_t *, siginfo_t *, timespec_t *);
int	getsetcontext(int, void *);
int	stat(char *, struct stat *);
int	fstatat(int, char *, struct stat *, int);
int	stime(time_t);
int	stty(int, intptr_t);
int	syssync();
int	sysacct(char *);
clock_t	times(struct tms *);
long	ulimit(int, long);
int	getrlimit32(int, struct rlimit32 *);
int	setrlimit32(int, struct rlimit32 *);
int	umask(int);
int	umount2(char *, int);
int	unlink(char *);
int	unlinkat(int, char *, int);
int	utimesys(int, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
int64_t	utssys32(void *, int, int, void *);
int64_t	utssys64(void *, long, int, void *);
int	uucopy(const void *, void *, size_t);
ssize_t	uucopystr(const char *, char *, size_t);
ssize_t	write(int, void *, size_t);
ssize_t	readv(int, struct iovec *, int);
ssize_t	writev(int, struct iovec *, int);
ssize_t	preadv(int, struct iovec *, int, off_t, off_t);
ssize_t	pwritev(int, struct iovec *, int, off_t, off_t);
int	syslwp_park(int, uintptr_t, uintptr_t);
int	rmdir(char *);
int	mkdir(char *, int);
int	mkdirat(int, char *, int);
int	getdents32(int, void *, size_t);
int	statfs32(char *, struct statfs32 *, int32_t, int32_t);
int	fstatfs32(int32_t, struct statfs32 *, int32_t, int32_t);
int	sysfs(int, long, long);
int	getmsg(int, struct strbuf *, struct strbuf *, int *);
int	pollsys(pollfd_t *, nfds_t, timespec_t *, sigset_t *);
int	putmsg(int, struct strbuf *, struct strbuf *, int);
int	uadmin();
int	lstat(char *, struct stat *);
int	symlink(char *, char *);
int	symlinkat(char *, int, char *);
ssize_t	readlink(char *, char *, size_t);
ssize_t	readlinkat(int, char *, char *, size_t);
int	resolvepath(char *, char *, size_t);
int	setgroups(int, gid_t *);
int	getgroups(int, gid_t *);
int	fchdir(int);
int	fchown(int, uid_t, uid_t);
int	fchmod(int, int);
int	getcwd(char *, size_t);
int	statvfs(char *, struct statvfs *);
int	fstatvfs(int, struct statvfs *);
offset_t llseek32(int32_t, uint32_t, uint32_t, int);

#if (defined(__i386) && !defined(__amd64)) || defined(__i386_COMPAT)
int	sysi86(short, uintptr_t, uintptr_t, uintptr_t);
#endif

int	acl(const char *, int, int, void *);
int	facl(int, int, int, void *);
long	priocntlsys(int, procset_t *, int, caddr_t, caddr_t);
int	waitsys(idtype_t, id_t, siginfo_t *, int);
int	sigsendsys(procset_t *, int);
int	mincore(caddr_t, size_t, char *);
caddr_t	smmap64(caddr_t, size_t, int, int, int, off_t);
caddr_t smmap32(caddr32_t, size32_t, int, int, int, off32_t);
int	smmaplf32(struct mmaplf32a *, rval_t *);
int	mprotect(caddr_t, size_t, int);
int	munmap(caddr_t, size_t);
int	uname(struct utsname *);
int	lchown(char *, uid_t, gid_t);
int	getpmsg(int, struct strbuf *, struct strbuf *, int *, int *);
int	putpmsg(int, struct strbuf *, struct strbuf *, int, int);
int	memcntl(caddr_t, size_t, int, caddr_t, int, int);
long	sysconfig(int);
int	adjtime(struct timeval *, struct timeval *);
long	systeminfo(int, char *, long);
int	setegid(gid_t);
int	seteuid(uid_t);

int	setreuid(uid_t, uid_t);
int	setregid(gid_t, gid_t);
int	install_utrap(utrap_entry_t type, utrap_handler_t, utrap_handler_t *);
#ifdef __sparc
int	sparc_utrap_install(utrap_entry_t type, utrap_handler_t,
    utrap_handler_t, utrap_handler_t *, utrap_handler_t *);
#endif

int	syslwp_create(ucontext_t *, int, id_t *);
void	syslwp_exit();
int	syslwp_suspend(id_t);
int	syslwp_continue(id_t);
int	syslwp_private(int, int, uintptr_t);
int	lwp_detach(id_t);
int	lwp_info(timestruc_t *);
int	lwp_kill(id_t, int);
int	lwp_self();
int64_t	lwp_sigmask(int, uint_t, uint_t, uint_t, uint_t);
int	yield();
int	lwp_wait(id_t, id_t *);
int	lwp_mutex_timedlock(lwp_mutex_t *, timespec_t *, uintptr_t);
int	lwp_mutex_wakeup(lwp_mutex_t *, int);
int	lwp_mutex_unlock(lwp_mutex_t *);
int	lwp_mutex_trylock(lwp_mutex_t *, uintptr_t);
int	lwp_mutex_register(lwp_mutex_t *, caddr_t);
int	lwp_rwlock_sys(int, lwp_rwlock_t *, timespec_t *);
int	lwp_sema_post(lwp_sema_t *);
int	lwp_sema_timedwait(lwp_sema_t *, timespec_t *, int);
int	lwp_sema_trywait(lwp_sema_t *);
int	lwp_cond_wait(lwp_cond_t *, lwp_mutex_t *, timespec_t *, int);
int	lwp_cond_signal(lwp_cond_t *);
int	lwp_cond_broadcast(lwp_cond_t *);
caddr_t	schedctl();

long	pathconf(char *, int);
long	fpathconf(int, int);
int	processor_bind(idtype_t, id_t, processorid_t, processorid_t *);
int	processor_info(processorid_t, processor_info_t *);
int	p_online(processorid_t, int);

/*
 *	POSIX .4 system calls *
 */
int	clock_gettime(clockid_t, timespec_t *);
int	clock_settime(clockid_t, timespec_t *);
int	clock_getres(clockid_t, timespec_t *);
int	timer_create(clockid_t, struct sigevent *, timer_t *);
int	timer_delete(timer_t);
int	timer_settime(timer_t, int, itimerspec_t *, itimerspec_t *);
int	timer_gettime(timer_t, itimerspec_t *);
int	timer_getoverrun(timer_t);
int	nanosleep(timespec_t *, timespec_t *);
int	sigqueue(pid_t, int, void *, int, int);
int	signotify(int, siginfo_t *, signotify_id_t *);

int	getdents64(int, void *, size_t);
int	stat64(char *, struct stat64 *);
int	lstat64(char *, struct stat64 *);
int	fstatat64(int, char *, struct stat64 *, int);
int	fstat64(int, struct stat64 *);
int	statvfs64(char *, struct statvfs64 *);
int	fstatvfs64(int, struct statvfs64 *);
int	setrlimit64(int, struct rlimit64 *);
int	getrlimit64(int, struct rlimit64 *);
int	pread64(int, void *, size32_t, uint32_t, uint32_t);
int	pwrite64(int, void *, size32_t, uint32_t, uint32_t);
int	open64(char *, int, int);
int	openat64(int, char *, int, int);

/*
 * NTP syscalls
 */

int ntp_gettime(struct ntptimeval *);
int ntp_adjtime(struct timex *);

/*
 *	++++++++++++++++++++++++
 *	++  SunOS4.1 Buyback  ++
 *	++++++++++++++++++++++++
 *
 *	fchroot, vhangup, gettimeofday
 */

int	fchroot(int);
int	vhangup();
int	gettimeofday(struct timeval *);
int	getitimer(uint_t, struct itimerval *);
int	setitimer(uint_t, struct itimerval *, struct itimerval *);

int	corectl(int, uintptr_t, uintptr_t, uintptr_t);
int	modctl(int, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
int64_t loadable_syscall();
int64_t indir();

long	tasksys(int, projid_t, uint_t, void *, size_t);
long	rctlsys(int, char *, void *, void *, size_t, int);

long	zone();

int	so_socket(int, int, int, char *, int);
int	so_socketpair(int[2]);
int	bind(int, struct sockaddr *, socklen_t, int);
int	listen(int, int, int);
int	accept(int, struct sockaddr *, socklen_t *, int, int);
int	connect(int, struct sockaddr *, socklen_t, int);
int	shutdown(int, int, int);
ssize_t	recv(int, void *, size_t, int);
ssize_t	recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *);
ssize_t	recvmsg(int, struct nmsghdr *, int);
ssize_t	send(int, void *, size_t, int);
ssize_t	sendmsg(int, struct nmsghdr *, int);
ssize_t	sendto(int, void *, size_t, int, struct sockaddr *, socklen_t);
int	getpeername(int, struct sockaddr *, socklen_t *, int);
int	getsockname(int, struct sockaddr *, socklen_t *, int);
int	getsockopt(int, int, int, void *, socklen_t *, int);
int	setsockopt(int, int, int, void *, socklen_t *, int);
int	sockconfig(int, void *, void *, void *, void *);
ssize_t	sendfilev(int, int, const struct sendfilevec *, int, size_t *);

typedef int64_t	(*llfcn_t)();	/* for casting one-word returns */

/*
 * Sysent initialization macros.
 * 	These take the name string of the system call even though that isn't
 *	currently used in the sysent entry.  This might be useful someday.
 *
 * Initialization macro for system calls which take their args in the C style.
 * These system calls return the longlong_t return value and must call
 * set_errno() to return an error.  For SPARC, narg must be at most six.
 * For more args, use the SYSENT_AP() routine.
 *
 * We are able to return two distinct values to userland via the rval_t.
 * At this time, that corresponds to one 64-bit quantity, or two 32-bit
 * quantities.  The kernel does not currently need to return two 64-bit
 * values, or one 128 bit value(!), but we may do one day, so the calling
 * sequence between userland and the kernel should permit it.
 *
 * The interpretation of rval_t is provided by the sy_flags field
 * which is used to determine how to arrange the results in registers
 * (or on the stack) for return userland.
 */
	/* returns a 64-bit quantity for both ABIs */
#define	SYSENT_C(name, call, narg)	\
	{ (narg), SE_64RVAL, NULL, NULL, (llfcn_t)(call) }

	/* returns one 32-bit value for both ABIs: r_val1 */
#define	SYSENT_CI(name, call, narg)	\
	{ (narg), SE_32RVAL1, NULL, NULL, (llfcn_t)(call) }

	/* returns 2 32-bit values: r_val1 & r_val2 */
#define	SYSENT_2CI(name, call, narg)	\
	{ (narg), SE_32RVAL1|SE_32RVAL2, NULL, NULL, (llfcn_t)(call) }

/*
 * Initialization macro for system calls which take their args in the standard
 * Unix style of a pointer to the arg structure and a pointer to the rval_t.
 *
 * Deprecated wherever possible (slower on some architectures, and trickier
 * to maintain two flavours).
 */
#define	SYSENT_AP(name, call, narg)	\
	{ (narg), SE_64RVAL, (call), NULL, syscall_ap }

/*
 * Conditional constructors to build the tables without #ifdef clutter
 */
#if defined(_LP64)
#define	IF_LP64(true, false)	true
#else
#define	IF_LP64(true, false)	false
#endif

#if defined(__sparc)
#define	IF_sparc(true, false)	true
#else
#define	IF_sparc(true, false)	false
#endif

#if defined(__i386) && !defined(__amd64)
#define	IF_i386(true, false)	true
#else
#define	IF_i386(true, false)	false
#endif

#if defined(__i386) || defined(__amd64)
#define	IF_x86(true, false)	true
#else
#define	IF_x86(true, false)	false
#endif

#if (defined(__i386) && !defined(__amd64)) || defined(__i386_COMPAT)
#define	IF_386_ABI(true, false)	true
#else
#define	IF_386_ABI(true, false)	false
#endif

/*
 * Define system calls that return a native 'long' quantity i.e. a 32-bit
 * or 64-bit integer - depending on how the kernel is itself compiled
 * e.g. read(2) returns 'ssize_t' in the kernel and in userland.
 */
#define	SYSENT_CL(name, call, narg)	\
	IF_LP64(SYSENT_C(name, call, narg), SYSENT_CI(name, call, narg))

/*
 * Initialization macro for loadable native system calls.
 */
#define	SYSENT_LOADABLE()	\
	{ 0, SE_LOADABLE, (int (*)())nosys, NULL, loadable_syscall }

/*
 * Initialization macro for loadable 32-bit compatibility system calls.
 */
#define	SYSENT_LOADABLE32()	SYSENT_LOADABLE()

#define	SYSENT_NOSYS()		SYSENT_C("nosys", nosys, 0)

struct sysent nosys_ent = SYSENT_NOSYS();

/*
 * Native sysent table.
 */
struct sysent sysent[NSYSCALL] =
{
	/*  0 */ IF_LP64(
			SYSENT_NOSYS(),
			SYSENT_C("indir",	indir,		1)),
	/*  1 */ SYSENT_CI("exit",		rexit,		1),
	/*  2 */ SYSENT_LOADABLE(),			/* (was forkall) */
	/*  3 */ SYSENT_CL("read",		read,		3),
	/*  4 */ SYSENT_CL("write",		write,		3),
	/*  5 */ SYSENT_CI("open",		open,		3),
	/*  6 */ SYSENT_CI("close",		close,		1),
	/*  7 */ SYSENT_CI("linkat",		linkat,		5),
	/*  8 */ SYSENT_LOADABLE(),			/* (was creat) */
	/*  9 */ SYSENT_CI("link",		link,		2),
	/* 10 */ SYSENT_CI("unlink",		unlink,		1),
	/* 11 */ SYSENT_CI("symlinkat",		symlinkat,	3),
	/* 12 */ SYSENT_CI("chdir",		chdir,		1),
	/* 13 */ SYSENT_CL("time",		gtime,		0),
	/* 14 */ SYSENT_CI("mknod",		mknod,		3),
	/* 15 */ SYSENT_CI("chmod",		chmod,		2),
	/* 16 */ SYSENT_CI("chown",		chown,		3),
	/* 17 */ SYSENT_CI("brk",		brk,		1),
	/* 18 */ SYSENT_CI("stat",		stat,		2),
	/* 19 */ IF_LP64(
			SYSENT_CL("lseek",	lseek64,	3),
			SYSENT_CL("lseek",	lseek32,	3)),
	/* 20 */ SYSENT_2CI("getpid",		getpid,		0),
	/* 21 */ SYSENT_AP("mount",		mount,		8),
	/* 22 */ SYSENT_CL("readlinkat",	readlinkat,	4),
	/* 23 */ SYSENT_CI("setuid",		setuid,		1),
	/* 24 */ SYSENT_2CI("getuid",		getuid,		0),
	/* 25 */ SYSENT_CI("stime",		stime,		1),
	/* 26 */ SYSENT_CL("pcsample",		pcsample,	2),
	/* 27 */ SYSENT_CI("alarm",		alarm,		1),
	/* 28 */ SYSENT_CI("fstat",		fstat,		2),
	/* 29 */ SYSENT_CI("pause",		pause,		0),
	/* 30 */ SYSENT_LOADABLE(),			/* (was utime) */
	/* 31 */ SYSENT_CI("stty",		stty,		2),
	/* 32 */ SYSENT_CI("gtty",		gtty,		2),
	/* 33 */ SYSENT_CI("access",		access,		2),
	/* 34 */ SYSENT_CI("nice",		nice,		1),
	/* 35 */ IF_LP64(
			SYSENT_NOSYS(),
			SYSENT_CI("statfs",	statfs32,	4)),
	/* 36 */ SYSENT_CI("sync",		syssync,	0),
	/* 37 */ SYSENT_CI("kill",		kill,		2),
	/* 38 */ IF_LP64(
			SYSENT_NOSYS(),
			SYSENT_CI("fstatfs",	fstatfs32,	4)),
	/* 39 */ SYSENT_CI("setpgrp",		setpgrp,	3),
	/* 40 */ SYSENT_CI("uucopystr",		uucopystr,	3),
	/* 41 */ SYSENT_LOADABLE(),			/* (was dup) */
	/* 42 */ SYSENT_LOADABLE(),			/* pipe */
	/* 43 */ SYSENT_CL("times",		times,		1),
	/* 44 */ SYSENT_CI("prof",		profil,		4),
	/* 45 */ SYSENT_CI("faccessat",		faccessat,	4),
	/* 46 */ SYSENT_CI("setgid",		setgid,		1),
	/* 47 */ SYSENT_2CI("getgid",		getgid,		0),
	/* 48 */ SYSENT_CI("mknodat",		mknodat,	4),
	/* 49 */ SYSENT_LOADABLE(),			/* msgsys */
	/* 50 */ IF_x86(
			SYSENT_CI("sysi86",	sysi86,		4),
			SYSENT_LOADABLE()),		/* (was sys3b) */
	/* 51 */ SYSENT_LOADABLE(),			/* sysacct */
	/* 52 */ SYSENT_LOADABLE(),			/* shmsys */
	/* 53 */ SYSENT_LOADABLE(),			/* semsys */
	/* 54 */ SYSENT_CI("ioctl",		ioctl,		3),
	/* 55 */ SYSENT_CI("uadmin",		uadmin,		3),
	/* 56 */ SYSENT_CI("fchownat",		fchownat,	5),
	/* 57 */ IF_LP64(
			SYSENT_2CI("utssys",	utssys64,	4),
			SYSENT_2CI("utssys",	utssys32,	4)),
	/* 58 */ SYSENT_CI("fdsync",		fdsync,		2),
	/* 59 */ SYSENT_CI("exece",		exece,		3),
	/* 60 */ SYSENT_CI("umask",		umask,		1),
	/* 61 */ SYSENT_CI("chroot",		chroot,		1),
	/* 62 */ SYSENT_CI("fcntl",		fcntl,		3),
	/* 63 */ SYSENT_CI("ulimit",		ulimit,		2),
	/* 64 */ SYSENT_CI("renameat",		renameat,	4),
	/* 65 */ SYSENT_CI("unlinkat",		unlinkat,	3),
	/* 66 */ SYSENT_CI("fstatat",		fstatat,	4),
	/* 67 */ IF_LP64(
			SYSENT_NOSYS(),
			SYSENT_CI("fstatat64",	fstatat64, 	4)),
	/* 68 */ SYSENT_CI("openat",		openat,		4),
	/* 69 */ IF_LP64(
			SYSENT_NOSYS(),
			SYSENT_CI("openat64",	openat64,	4)),
	/* 70 */ SYSENT_CI("tasksys",		tasksys,	5),
	/* 71 */ SYSENT_LOADABLE(),		/* acctctl */
	/* 72 */ SYSENT_LOADABLE(),		/* exacct */
	/* 73 */ SYSENT_CI("getpagesizes",	getpagesizes,	3),
	/* 74 */ SYSENT_CI("rctlsys",		rctlsys,	6),
	/* 75 */ SYSENT_2CI("sidsys",		sidsys,		4),
	/* 76 */ SYSENT_LOADABLE(),			/* (was fsat) */
	/* 77 */ SYSENT_CI("lwp_park",		syslwp_park,	3),
	/* 78 */ SYSENT_CL("sendfilev",		sendfilev,	5),
	/* 79 */ SYSENT_CI("rmdir",		rmdir,		1),
	/* 80 */ SYSENT_CI("mkdir",		mkdir,		2),
	/* 81 */ IF_LP64(
			SYSENT_CI("getdents",	getdents64,	3),
			SYSENT_CI("getdents",	getdents32,	3)),
	/* 82 */ SYSENT_CI("privsys",		privsys,	6),
	/* 83 */ SYSENT_CI("ucredsys",		ucredsys,	3),
	/* 84 */ SYSENT_CI("sysfs",		sysfs,		3),
	/* 85 */ SYSENT_CI("getmsg",		getmsg,		4),
	/* 86 */ SYSENT_CI("putmsg",		putmsg,		4),
	/* 87 */ SYSENT_LOADABLE(),			/* (was poll) */
	/* 88 */ SYSENT_CI("lstat",		lstat,		2),
	/* 89 */ SYSENT_CI("symlink",		symlink,	2),
	/* 90 */ SYSENT_CL("readlink",		readlink,	3),
	/* 91 */ SYSENT_CI("setgroups",		setgroups,	2),
	/* 92 */ SYSENT_CI("getgroups",		getgroups,	2),
	/* 93 */ SYSENT_CI("fchmod",		fchmod,		2),
	/* 94 */ SYSENT_CI("fchown",		fchown,		3),
	/* 95 */ SYSENT_CI("sigprocmask",	sigprocmask,	3),
	/* 96 */ SYSENT_CI("sigsuspend",	sigsuspend,	1),
	/* 97 */ SYSENT_CI("sigaltstack",	sigaltstack,	2),
	/* 98 */ SYSENT_CI("sigaction",		sigaction,	3),
	/* 99 */ SYSENT_CI("sigpending",	sigpending,	2),
	/* 100 */ SYSENT_CI("getsetcontext",	getsetcontext,	2),
	/* 101 */ SYSENT_CI("fchmodat",		fchmodat,	4),
	/* 102 */ SYSENT_CI("mkdirat",		mkdirat,	3),
	/* 103 */ SYSENT_CI("statvfs",		statvfs,	2),
	/* 104 */ SYSENT_CI("fstatvfs",		fstatvfs,	2),
	/* 105 */ SYSENT_CI("getloadavg",	getloadavg,	2),
	/* 106 */ SYSENT_LOADABLE(),		/* nfssys */
	/* 107 */ SYSENT_CI("waitsys",		waitsys,	4),
	/* 108 */ SYSENT_CI("sigsendset",	sigsendsys,	2),
	/* 109 */ IF_x86(
			SYSENT_AP("hrtsys",	hrtsys,		5),
			SYSENT_LOADABLE()),
	/* 110 */ SYSENT_CI("utimesys",		utimesys,	5),
	/* 111 */ SYSENT_CI("sigresend",	sigresend,	3),
	/* 112 */ SYSENT_CL("priocntlsys",	priocntlsys,	5),
	/* 113 */ SYSENT_CL("pathconf",		pathconf,	2),
	/* 114 */ SYSENT_CI("mincore",		mincore,	3),
	/* 115 */ IF_LP64(
			SYSENT_CL("mmap",	smmap64,	6),
			SYSENT_CL("mmap",	smmap32,	6)),
	/* 116 */ SYSENT_CI("mprotect",		mprotect,	3),
	/* 117 */ SYSENT_CI("munmap",		munmap,		2),
	/* 118 */ SYSENT_CL("fpathconf",	fpathconf,	2),
	/* 119 */ SYSENT_2CI("vfork",		vfork,		0),
	/* 120 */ SYSENT_CI("fchdir",		fchdir,		1),
	/* 121 */ SYSENT_CL("readv",		readv,		3),
	/* 122 */ SYSENT_CL("writev",		writev,		3),
	/* 123 */ SYSENT_CL("preadv",		preadv,		5),
	/* 124 */ SYSENT_CL("pwritev",		pwritev,	5),
	/* 125 */ SYSENT_LOADABLE(),			/* (was fxstat) */
	/* 126 */ SYSENT_LOADABLE(),			/* (was xmknod) */
	/* 127 */ SYSENT_CI("mmapobj",		mmapobjsys,	5),
	/* 128 */ IF_LP64(
			SYSENT_CI("setrlimit",	setrlimit64,	2),
			SYSENT_CI("setrlimit",	setrlimit32,	2)),
	/* 129 */ IF_LP64(
			SYSENT_CI("getrlimit",	getrlimit64,	2),
			SYSENT_CI("getrlimit",	getrlimit32,	2)),
	/* 130 */ SYSENT_CI("lchown",		lchown,		3),
	/* 131 */ SYSENT_CI("memcntl",		memcntl,	6),
	/* 132 */ SYSENT_CI("getpmsg",		getpmsg,	5),
	/* 133 */ SYSENT_CI("putpmsg",		putpmsg,	5),
	/* 134 */ SYSENT_CI("rename",		rename,		2),
	/* 135 */ SYSENT_CI("uname",		uname,		1),
	/* 136 */ SYSENT_CI("setegid",		setegid,	1),
	/* 137 */ SYSENT_CL("sysconfig",	sysconfig,	1),
	/* 138 */ SYSENT_CI("adjtime",		adjtime,	2),
	/* 139 */ SYSENT_CL("systeminfo",	systeminfo,	3),
	/* 140 */ SYSENT_LOADABLE(),		/* sharefs */
	/* 141 */ SYSENT_CI("seteuid",		seteuid,	1),
	/* 142 */ SYSENT_2CI("forksys",		forksys,	2),
	/* 143 */ SYSENT_LOADABLE(),			/* (was fork1) */
	/* 144 */ SYSENT_CI("sigtimedwait",	sigtimedwait,	3),
	/* 145 */ SYSENT_CI("lwp_info",		lwp_info,	1),
	/* 146 */ SYSENT_CI("yield",		yield,		0),
	/* 147 */ SYSENT_LOADABLE(),		    /* (was lwp_sema_wait) */
	/* 148 */ SYSENT_CI("lwp_sema_post",	lwp_sema_post,	1),
	/* 149 */ SYSENT_CI("lwp_sema_trywait",	lwp_sema_trywait, 1),
	/* 150 */ SYSENT_CI("lwp_detach",	lwp_detach,	1),
	/* 151 */ SYSENT_CI("corectl",		corectl,	4),
	/* 152 */ SYSENT_CI("modctl",		modctl,		6),
	/* 153 */ SYSENT_CI("fchroot",		fchroot,	1),
	/* 154 */ SYSENT_LOADABLE(),			/* (was utimes) */
	/* 155 */ SYSENT_CI("vhangup",		vhangup,	0),
	/* 156 */ SYSENT_CI("gettimeofday",	gettimeofday,	1),
	/* 157 */ SYSENT_CI("getitimer",	getitimer,	2),
	/* 158 */ SYSENT_CI("setitimer",	setitimer,	3),
	/* 159 */ SYSENT_CI("lwp_create",	syslwp_create,	3),
	/* 160 */ SYSENT_CI("lwp_exit",	(int (*)())syslwp_exit,	0),
	/* 161 */ SYSENT_CI("lwp_suspend",	syslwp_suspend,	1),
	/* 162 */ SYSENT_CI("lwp_continue",	syslwp_continue, 1),
	/* 163 */ SYSENT_CI("lwp_kill",		lwp_kill,	2),
	/* 164 */ SYSENT_CI("lwp_self",		lwp_self,	0),
	/* 165 */ SYSENT_2CI("lwp_sigmask",	lwp_sigmask,	5),
	/* 166 */ IF_x86(
			SYSENT_CI("lwp_private", syslwp_private, 3),
			SYSENT_NOSYS()),
	/* 167 */ SYSENT_CI("lwp_wait",		lwp_wait,	2),
	/* 168 */ SYSENT_CI("lwp_mutex_wakeup",	lwp_mutex_wakeup,	2),
	/* 169 */ SYSENT_LOADABLE(),		    /* (was lwp_mutex_lock) */
	/* 170 */ SYSENT_CI("lwp_cond_wait",	lwp_cond_wait,		4),
	/* 171 */ SYSENT_CI("lwp_cond_signal",	lwp_cond_signal,	1),
	/* 172 */ SYSENT_CI("lwp_cond_broadcast", lwp_cond_broadcast,	1),
	/* 173 */ SYSENT_CL("pread",		pread,		4),
	/* 174 */ SYSENT_CL("pwrite ",		pwrite,		4),
	/*
	 * The 64-bit C library maps llseek() to lseek(), so this
	 * is needed as a native syscall only on the 32-bit kernel.
	 */
	/* 175 */ IF_LP64(
			SYSENT_NOSYS(),
			SYSENT_C("llseek",	llseek32,	4)),
	/* 176 */ SYSENT_LOADABLE(),		/* inst_sync */
	/* 177 */ SYSENT_CI("brandsys",		brandsys,	6),
	/* 178 */ SYSENT_LOADABLE(),		/* kaio */
	/* 179 */ SYSENT_LOADABLE(),		/* cpc */
	/* 180 */ SYSENT_CI("lgrpsys",		lgrpsys,	3),
	/* 181 */ SYSENT_CI("rusagesys",	rusagesys, 	5),
	/* 182 */ SYSENT_LOADABLE(),		/* portfs */
	/* 183 */ SYSENT_CI("pollsys",		pollsys,	4),
	/* 184 */ SYSENT_CI("labelsys",		labelsys,	5),
	/* 185 */ SYSENT_CI("acl",		acl,		4),
	/* 186 */ SYSENT_AP("auditsys",		auditsys,	6),
	/* 187 */ SYSENT_CI("processor_bind",	processor_bind,	4),
	/* 188 */ SYSENT_CI("processor_info",	processor_info,	2),
	/* 189 */ SYSENT_CI("p_online",		p_online,	2),
	/* 190 */ SYSENT_CI("sigqueue",		sigqueue,	5),
	/* 191 */ SYSENT_CI("clock_gettime",	clock_gettime,	2),
	/* 192 */ SYSENT_CI("clock_settime",	clock_settime,	2),
	/* 193 */ SYSENT_CI("clock_getres",	clock_getres,	2),
	/* 194 */ SYSENT_CI("timer_create",	timer_create,	3),
	/* 195 */ SYSENT_CI("timer_delete",	timer_delete,	1),
	/* 196 */ SYSENT_CI("timer_settime",	timer_settime,	4),
	/* 197 */ SYSENT_CI("timer_gettime",	timer_gettime,	2),
	/* 198 */ SYSENT_CI("timer_getoverrun",	timer_getoverrun, 1),
	/* 199 */ SYSENT_CI("nanosleep",	nanosleep,	2),
	/* 200 */ SYSENT_CI("facl",		facl,		4),
	/* 201 */ SYSENT_LOADABLE(),		/* door */
	/* 202 */ SYSENT_CI("setreuid",		setreuid,	2),
	/* 203 */ SYSENT_CI("setregid",		setregid,	2),
	/* 204 */ SYSENT_CI("install_utrap",	install_utrap,	3),
	/* 205 */ SYSENT_CI("signotify",	signotify,	3),
	/* 206 */ SYSENT_CL("schedctl",		schedctl,	0),
	/* 207 */ SYSENT_LOADABLE(),		/* pset */
	/* 208 */ IF_sparc(
		SYSENT_CI("sparc_utrap_install", sparc_utrap_install, 5),
		SYSENT_NOSYS()),
	/* 209 */ SYSENT_CI("resolvepath",	resolvepath,	3),
	/* 210 */ SYSENT_CI("lwp_mutex_timedlock", lwp_mutex_timedlock,	3),
	/* 211 */ SYSENT_CI("lwp_sema_timedwait", lwp_sema_timedwait,	3),
	/* 212 */ SYSENT_CI("lwp_rwlock_sys",	lwp_rwlock_sys,	3),
	/*
	 * Syscalls 213-225: 32-bit system call support for large files.
	 *
	 * (The 64-bit C library transparently maps these system calls
	 * back to their native versions, so almost all of them are only
	 * needed as native syscalls on the 32-bit kernel).
	 */
	/* 213 */ IF_LP64(
			SYSENT_NOSYS(),
			SYSENT_CI("getdents64",	getdents64,	3)),
	/* 214 */ IF_LP64(
			SYSENT_NOSYS(),
			SYSENT_AP("smmaplf32",	smmaplf32,	7)),
	/* 215 */ IF_LP64(
			SYSENT_NOSYS(),
			SYSENT_CI("stat64",	stat64, 	2)),
	/* 216 */ IF_LP64(
			SYSENT_NOSYS(),
			SYSENT_CI("lstat64",	lstat64,	2)),
	/* 217 */ IF_LP64(
			SYSENT_NOSYS(),
			SYSENT_CI("fstat64", 	fstat64, 	2)),
	/* 218 */ IF_LP64(
			SYSENT_NOSYS(),
			SYSENT_CI("statvfs64", 	statvfs64, 	2)),
	/* 219 */ IF_LP64(
			SYSENT_NOSYS(),
			SYSENT_CI("fstatvfs64",	fstatvfs64, 	2)),
	/* 220 */ IF_LP64(
			SYSENT_NOSYS(),
			SYSENT_CI("setrlimit64", setrlimit64, 	2)),
	/* 221 */ IF_LP64(
			SYSENT_NOSYS(),
			SYSENT_CI("getrlimit64", getrlimit64, 	2)),
	/* 222 */ IF_LP64(
			SYSENT_NOSYS(),
			SYSENT_CI("pread64",	pread64, 	5)),
	/* 223 */ IF_LP64(
			SYSENT_NOSYS(),
			SYSENT_CI("pwrite64", 	pwrite64, 	5)),
	/* 224 */ SYSENT_LOADABLE(),			/* (was creat64) */
	/* 225 */ IF_LP64(
			SYSENT_NOSYS(),
			SYSENT_CI("open64",	open64,		3)),
	/* 226 */ SYSENT_LOADABLE(),		/* rpcsys */
	/* 227 */ SYSENT_CL("zone",		zone,		5),
	/* 228 */ SYSENT_LOADABLE(),		/* autofssys */
	/* 229 */ SYSENT_CI("getcwd",		getcwd,		2),
	/* 230 */ SYSENT_CI("so_socket",	so_socket,	5),
	/* 231 */ SYSENT_CI("so_socketpair",	so_socketpair,	1),
	/* 232 */ SYSENT_CI("bind",		bind,		4),
	/* 233 */ SYSENT_CI("listen",		listen,		3),
	/* 234 */ SYSENT_CI("accept",		accept,		5),
	/* 235 */ SYSENT_CI("connect",		connect,	4),
	/* 236 */ SYSENT_CI("shutdown",		shutdown,	3),
	/* 237 */ SYSENT_CL("recv",		recv,		4),
	/* 238 */ SYSENT_CL("recvfrom",		recvfrom,	6),
	/* 239 */ SYSENT_CL("recvmsg",		recvmsg,	3),
	/* 240 */ SYSENT_CL("send",		send,		4),
	/* 241 */ SYSENT_CL("sendmsg",		sendmsg,	3),
	/* 242 */ SYSENT_CL("sendto",		sendto,		6),
	/* 243 */ SYSENT_CI("getpeername",	getpeername,	4),
	/* 244 */ SYSENT_CI("getsockname",	getsockname,	4),
	/* 245 */ SYSENT_CI("getsockopt",	getsockopt,	6),
	/* 246 */ SYSENT_CI("setsockopt",	setsockopt,	6),
	/* 247 */ SYSENT_CI("sockconfig",	sockconfig,	5),
	/* 248 */ SYSENT_CI("ntp_gettime",	ntp_gettime,	1),
	/* 249 */ SYSENT_CI("ntp_adjtime",	ntp_adjtime,	1),
	/* 250 */ SYSENT_CI("lwp_mutex_unlock",	lwp_mutex_unlock,	1),
	/* 251 */ SYSENT_CI("lwp_mutex_trylock", lwp_mutex_trylock,	2),
	/* 252 */ SYSENT_CI("lwp_mutex_register", lwp_mutex_register,	2),
	/* 253 */ SYSENT_CI("cladm",		cladm,		3),
	/* 254 */ SYSENT_CI("uucopy",		uucopy,		3),
	/* 255 */ SYSENT_CI("umount2",		umount2,	2)
};


#ifdef _SYSCALL32_IMPL

extern int ulimit32(int, int);
extern ssize_t read32(int32_t, caddr32_t, size32_t);
extern ssize_t write32(int32_t, caddr32_t, size32_t);
extern ssize_t pread32(int32_t, caddr32_t, size32_t, off32_t);
extern ssize_t pwrite32(int32_t, caddr32_t, size32_t, off32_t);
extern ssize_t readv32(int32_t, caddr32_t, int32_t);
extern ssize_t writev32(int32_t, caddr32_t, int32_t);
extern ssize_t readlink32(caddr32_t, caddr32_t, size32_t);
extern ssize_t readlinkat32(int, caddr32_t, caddr32_t, size32_t);
extern int open32(char *, int, int);
extern int openat32(int, char *, int, int);
extern int stat32(char *, struct stat32 *);
extern int fstatat32(int, char *, struct stat32 *, int);
extern int lstat32(char *, struct stat32 *);
extern int fstat32(int, struct stat32 *);
extern int fstatat64_32(int, char *, struct stat64_32 *, int);
extern int stat64_32(char *, struct stat64_32 *);
extern int lstat64_32(char *, struct stat64_32 *);
extern int fstat64_32(int, struct stat64_32 *);
extern int getmsg32(int, struct strbuf32 *, struct strbuf32 *, int32_t *);
extern int putmsg32(int, struct strbuf32 *, struct strbuf32 *, int32_t *);
extern int getpmsg32(int, struct strbuf32 *, struct strbuf32 *, int32_t *,
    int32_t *);
extern int putpmsg32(int, struct strbuf32 *, struct strbuf32 *, int32_t,
    int32_t);
extern int getsetcontext32(int, void *);
extern int statvfs32(char *, struct statvfs32 *);
extern int fstatvfs32(int, struct statvfs32 *);
extern int statvfs64_32(char *, struct statvfs64_32 *);
extern int fstatvfs64_32(int, struct statvfs64_32 *);
extern int sigaction32(int, struct sigaction32 *, struct sigaction32 *);
extern clock32_t times32(struct tms32 *);
extern int stime32(time32_t);
extern int getpagesizes32(int, size32_t *, int);
extern int sigaltstack32(struct sigaltstack32 *, struct sigaltstack32 *);
extern int sigqueue32(pid_t, int, caddr32_t, int, int);
extern offset_t	llseek32(int32_t, uint32_t, uint32_t, int);
extern int waitsys32(idtype_t, id_t, siginfo_t *, int);

extern ssize_t recv32(int32_t, caddr32_t, size32_t, int32_t);
extern ssize_t recvfrom32(int32_t, caddr32_t, size32_t, int32_t, caddr32_t,
    caddr32_t);
extern ssize_t send32(int32_t, caddr32_t, size32_t, int32_t);
extern ssize_t sendto32(int32_t, caddr32_t, size32_t, int32_t, caddr32_t,
    socklen_t);

extern int privsys32(int, priv_op_t, priv_ptype_t, caddr32_t, size32_t, int);
extern int ucredsys32(int, int, caddr32_t);

/*
 * sysent table for ILP32 processes running on
 * a LP64 kernel.
 */
struct sysent sysent32[NSYSCALL] =
{
	/*  0 */ SYSENT_C("indir",		indir,		1),
	/*  1 */ SYSENT_CI("exit",	(int (*)())rexit,	1),
	/*  2 */ SYSENT_LOADABLE32(),			/* (was forkall) */
	/*  3 */ SYSENT_CI("read",		read32,		3),
	/*  4 */ SYSENT_CI("write",		write32,	3),
	/*  5 */ SYSENT_CI("open",		open32,		3),
	/*  6 */ SYSENT_CI("close",		close,		1),
	/*  7 */ SYSENT_CI("linkat",		linkat,		5),
	/*  8 */ SYSENT_LOADABLE32(),			/* (was creat32) */
	/*  9 */ SYSENT_CI("link",		link,		2),
	/* 10 */ SYSENT_CI("unlink",		unlink,		1),
	/* 11 */ SYSENT_CI("symlinkat",		symlinkat,	3),
	/* 12 */ SYSENT_CI("chdir",		chdir,		1),
	/* 13 */ SYSENT_CI("time",		gtime,		0),
	/* 14 */ SYSENT_CI("mknod",		mknod,		3),
	/* 15 */ SYSENT_CI("chmod",		chmod,		2),
	/* 16 */ SYSENT_CI("chown",		chown,		3),
	/* 17 */ SYSENT_CI("brk",		brk,		1),
	/* 18 */ SYSENT_CI("stat",		stat32,		2),
	/* 19 */ SYSENT_CI("lseek",		lseek32,	3),
	/* 20 */ SYSENT_2CI("getpid",		getpid,		0),
	/* 21 */ SYSENT_AP("mount",		mount,		8),
	/* 22 */ SYSENT_CI("readlinkat",	readlinkat32,	4),
	/* 23 */ SYSENT_CI("setuid",		setuid,		1),
	/* 24 */ SYSENT_2CI("getuid",		getuid,		0),
	/* 25 */ SYSENT_CI("stime",		stime32,	1),
	/* 26 */ SYSENT_CI("pcsample",		pcsample,	2),
	/* 27 */ SYSENT_CI("alarm",		alarm,		1),
	/* 28 */ SYSENT_CI("fstat",		fstat32,	2),
	/* 29 */ SYSENT_CI("pause",		pause,		0),
	/* 30 */ SYSENT_LOADABLE32(),			/* (was utime) */
	/* 31 */ SYSENT_CI("stty",		stty,		2),
	/* 32 */ SYSENT_CI("gtty",		gtty,		2),
	/* 33 */ SYSENT_CI("access",		access,		2),
	/* 34 */ SYSENT_CI("nice",		nice,		1),
	/* 35 */ SYSENT_CI("statfs",		statfs32,	4),
	/* 36 */ SYSENT_CI("sync",		syssync,	0),
	/* 37 */ SYSENT_CI("kill",		kill,		2),
	/* 38 */ SYSENT_CI("fstatfs",		fstatfs32,	4),
	/* 39 */ SYSENT_CI("setpgrp",		setpgrp,	3),
	/* 40 */ SYSENT_CI("uucopystr",		uucopystr,	3),
	/* 41 */ SYSENT_LOADABLE32(),			/* (was dup) */
	/* 42 */ SYSENT_LOADABLE32(),			/* pipe */
	/* 43 */ SYSENT_CI("times",		times32,	1),
	/* 44 */ SYSENT_CI("prof",		profil,		4),
	/* 45 */ SYSENT_CI("faccessat",		faccessat,	4),
	/* 46 */ SYSENT_CI("setgid",		setgid,		1),
	/* 47 */ SYSENT_2CI("getgid",		getgid,		0),
	/* 48 */ SYSENT_CI("mknodat",		mknodat,	4),
	/* 49 */ SYSENT_LOADABLE32(),			/* msgsys */
	/* 50 */ IF_386_ABI(
			SYSENT_CI("sysi86",	sysi86,		4),
			SYSENT_LOADABLE32()),		/* (was sys3b) */
	/* 51 */ SYSENT_LOADABLE32(),			/* sysacct */
	/* 52 */ SYSENT_LOADABLE32(),			/* shmsys */
	/* 53 */ SYSENT_LOADABLE32(),			/* semsys */
	/* 54 */ SYSENT_CI("ioctl",		ioctl,		3),
	/* 55 */ SYSENT_CI("uadmin",		uadmin,		3),
	/* 56 */ SYSENT_CI("fchownat",		fchownat,	5),
	/* 57 */ SYSENT_2CI("utssys",		utssys32,	4),
	/* 58 */ SYSENT_CI("fdsync",		fdsync,		2),
	/* 59 */ SYSENT_CI("exece",		exece,		3),
	/* 60 */ SYSENT_CI("umask",		umask,		1),
	/* 61 */ SYSENT_CI("chroot",		chroot,		1),
	/* 62 */ SYSENT_CI("fcntl",		fcntl,		3),
	/* 63 */ SYSENT_CI("ulimit",		ulimit32,	2),
	/* 64 */ SYSENT_CI("renameat",		renameat,	4),
	/* 65 */ SYSENT_CI("unlinkat",		unlinkat,	3),
	/* 66 */ SYSENT_CI("fstatat",		fstatat32,	4),
	/* 67 */ SYSENT_CI("fstatat64", 	fstatat64_32, 	4),
	/* 68 */ SYSENT_CI("openat",		openat32,	4),
	/* 69 */ SYSENT_CI("openat64",		openat64,	4),
	/* 70 */ SYSENT_CI("tasksys",		tasksys,	5),
	/* 71 */ SYSENT_LOADABLE32(),		/* acctctl */
	/* 72 */ SYSENT_LOADABLE32(),		/* exacct */
	/* 73 */ SYSENT_CI("getpagesizes",	getpagesizes32,	3),
	/* 74 */ SYSENT_CI("rctlsys",		rctlsys,	6),
	/* 75 */ SYSENT_2CI("sidsys",		sidsys,		4),
	/* 76 */ SYSENT_LOADABLE32(),			/* (was fsat) */
	/* 77 */ SYSENT_CI("lwp_park",		syslwp_park,	3),
	/* 78 */ SYSENT_CI("sendfilev",		sendfilev,	5),
	/* 79 */ SYSENT_CI("rmdir",		rmdir,		1),
	/* 80 */ SYSENT_CI("mkdir",		mkdir,		2),
	/* 81 */ SYSENT_CI("getdents",		getdents32,	3),
	/* 82 */ SYSENT_CI("privsys",		privsys32,	6),
	/* 83 */ SYSENT_CI("ucredsys",		ucredsys32,	3),
	/* 84 */ SYSENT_CI("sysfs",		sysfs,		3),
	/* 85 */ SYSENT_CI("getmsg",		getmsg32,	4),
	/* 86 */ SYSENT_CI("putmsg",		putmsg32,	4),
	/* 87 */ SYSENT_LOADABLE32(),			/* (was poll) */
	/* 88 */ SYSENT_CI("lstat",		lstat32,	2),
	/* 89 */ SYSENT_CI("symlink",		symlink,	2),
	/* 90 */ SYSENT_CI("readlink",		readlink32,	3),
	/* 91 */ SYSENT_CI("setgroups",		setgroups,	2),
	/* 92 */ SYSENT_CI("getgroups",		getgroups,	2),
	/* 93 */ SYSENT_CI("fchmod",		fchmod,		2),
	/* 94 */ SYSENT_CI("fchown",		fchown,		3),
	/* 95 */ SYSENT_CI("sigprocmask",	sigprocmask,	3),
	/* 96 */ SYSENT_CI("sigsuspend",	sigsuspend,	1),
	/* 97 */ SYSENT_CI("sigaltstack",	sigaltstack32,	2),
	/* 98 */ SYSENT_CI("sigaction",		sigaction32,	3),
	/* 99 */ SYSENT_CI("sigpending",	sigpending,	2),
	/* 100 */ SYSENT_CI("getsetcontext",	getsetcontext32, 2),
	/* 101 */ SYSENT_CI("fchmodat",		fchmodat,	4),
	/* 102 */ SYSENT_CI("mkdirat",		mkdirat,	3),
	/* 103 */ SYSENT_CI("statvfs",		statvfs32,	2),
	/* 104 */ SYSENT_CI("fstatvfs",		fstatvfs32,	2),
	/* 105 */ SYSENT_CI("getloadavg",	getloadavg,	2),
	/* 106 */ SYSENT_LOADABLE32(),		/* nfssys */
	/* 107 */ SYSENT_CI("waitsys",		waitsys32,	4),
	/* 108 */ SYSENT_CI("sigsendset",	sigsendsys,	2),
	/* 109 */ IF_x86(
			SYSENT_AP("hrtsys",	hrtsys,		5),
			SYSENT_LOADABLE32()),
	/* 110 */ SYSENT_CI("utimesys",		utimesys,	5),
	/* 111 */ SYSENT_CI("sigresend",	sigresend,	3),
	/* 112 */ SYSENT_CI("priocntlsys",	priocntlsys,	5),
	/* 113 */ SYSENT_CI("pathconf",		pathconf,	2),
	/* 114 */ SYSENT_CI("mincore",		mincore,	3),
	/* 115 */ SYSENT_CI("mmap",		smmap32,	6),
	/* 116 */ SYSENT_CI("mprotect",		mprotect,	3),
	/* 117 */ SYSENT_CI("munmap",		munmap,		2),
	/* 118 */ SYSENT_CI("fpathconf",	fpathconf,	2),
	/* 119 */ SYSENT_2CI("vfork",		vfork,		0),
	/* 120 */ SYSENT_CI("fchdir",		fchdir,		1),
	/* 121 */ SYSENT_CI("readv",		readv32,	3),
	/* 122 */ SYSENT_CI("writev",		writev32,	3),
	/* 123 */ SYSENT_CI("preadv",		preadv,		5),
	/* 124 */ SYSENT_CI("pwritev",		pwritev,	5),
	/* 125 */ SYSENT_LOADABLE32(),		/*	was fxstat32	*/
	/* 126 */ SYSENT_LOADABLE32(),		/*	was xmknod	*/
	/* 127 */ SYSENT_CI("mmapobj",		mmapobjsys,	5),
	/* 128 */ SYSENT_CI("setrlimit",	setrlimit32,	2),
	/* 129 */ SYSENT_CI("getrlimit",	getrlimit32,	2),
	/* 130 */ SYSENT_CI("lchown",		lchown,		3),
	/* 131 */ SYSENT_CI("memcntl",		memcntl,	6),
	/* 132 */ SYSENT_CI("getpmsg",		getpmsg32,	5),
	/* 133 */ SYSENT_CI("putpmsg",		putpmsg32,	5),
	/* 134 */ SYSENT_CI("rename",		rename,		2),
	/* 135 */ SYSENT_CI("uname",		uname,		1),
	/* 136 */ SYSENT_CI("setegid",		setegid,	1),
	/* 137 */ SYSENT_CI("sysconfig",	sysconfig,	1),
	/* 138 */ SYSENT_CI("adjtime",		adjtime,	2),
	/* 139 */ SYSENT_CI("systeminfo",	systeminfo,	3),
	/* 140 */ SYSENT_LOADABLE32(),		/* sharefs */
	/* 141 */ SYSENT_CI("seteuid",		seteuid,	1),
	/* 142 */ SYSENT_2CI("forksys",		forksys,	2),
	/* 143 */ SYSENT_LOADABLE32(),			/* (was fork1) */
	/* 144 */ SYSENT_CI("sigtimedwait",	sigtimedwait,	3),
	/* 145 */ SYSENT_CI("lwp_info",		lwp_info,	1),
	/* 146 */ SYSENT_CI("yield",		yield,		0),
	/* 147 */ SYSENT_LOADABLE32(),		    /* (was lwp_sema_wait) */
	/* 148 */ SYSENT_CI("lwp_sema_post",	lwp_sema_post,	1),
	/* 149 */ SYSENT_CI("lwp_sema_trywait",	lwp_sema_trywait, 1),
	/* 150 */ SYSENT_CI("lwp_detach",	lwp_detach,	1),
	/* 151 */ SYSENT_CI("corectl",		corectl,	4),
	/* 152 */ SYSENT_CI("modctl",		modctl,		6),
	/* 153 */ SYSENT_CI("fchroot",		fchroot,	1),
	/* 154 */ SYSENT_LOADABLE32(),			/* (was utimes) */
	/* 155 */ SYSENT_CI("vhangup",		vhangup,	0),
	/* 156 */ SYSENT_CI("gettimeofday",	gettimeofday,	1),
	/* 157 */ SYSENT_CI("getitimer",	getitimer,	2),
	/* 158 */ SYSENT_CI("setitimer",	setitimer,	3),
	/* 159 */ SYSENT_CI("lwp_create",	syslwp_create,	3),
	/* 160 */ SYSENT_CI("lwp_exit",	(int (*)())syslwp_exit,	0),
	/* 161 */ SYSENT_CI("lwp_suspend",	syslwp_suspend,	1),
	/* 162 */ SYSENT_CI("lwp_continue",	syslwp_continue, 1),
	/* 163 */ SYSENT_CI("lwp_kill",		lwp_kill,	2),
	/* 164 */ SYSENT_CI("lwp_self",		lwp_self,	0),
	/* 165 */ SYSENT_2CI("lwp_sigmask",	lwp_sigmask,	5),
	/* 166 */ IF_x86(
			SYSENT_CI("lwp_private", syslwp_private, 3),
			SYSENT_NOSYS()),
	/* 167 */ SYSENT_CI("lwp_wait",		lwp_wait,	2),
	/* 168 */ SYSENT_CI("lwp_mutex_wakeup",	lwp_mutex_wakeup,	2),
	/* 169 */ SYSENT_LOADABLE32(),		    /* (was lwp_mutex_lock) */
	/* 170 */ SYSENT_CI("lwp_cond_wait",	lwp_cond_wait,		4),
	/* 171 */ SYSENT_CI("lwp_cond_signal",	lwp_cond_signal,	1),
	/* 172 */ SYSENT_CI("lwp_cond_broadcast", lwp_cond_broadcast,	1),
	/* 173 */ SYSENT_CI("pread",		pread32,		4),
	/* 174 */ SYSENT_CI("pwrite",		pwrite32,		4),
	/* 175 */ SYSENT_C("llseek",		llseek32,	4),
	/* 176 */ SYSENT_LOADABLE32(),		/* inst_sync */
	/* 177 */ SYSENT_CI("brandsys",		brandsys,	6),
	/* 178 */ SYSENT_LOADABLE32(),		/* kaio */
	/* 179 */ SYSENT_LOADABLE32(),		/* cpc */
	/* 180 */ SYSENT_CI("lgrpsys",		lgrpsys,	3),
	/* 181 */ SYSENT_CI("rusagesys",	rusagesys,	5),
	/* 182 */ SYSENT_LOADABLE32(),		/* portfs */
	/* 183 */ SYSENT_CI("pollsys",		pollsys,	4),
	/* 184 */ SYSENT_CI("labelsys",		labelsys,	5),
	/* 185 */ SYSENT_CI("acl",		acl,		4),
	/* 186 */ SYSENT_AP("auditsys",		auditsys,	6),
	/* 187 */ SYSENT_CI("processor_bind",	processor_bind,	4),
	/* 188 */ SYSENT_CI("processor_info",	processor_info,	2),
	/* 189 */ SYSENT_CI("p_online",		p_online,	2),
	/* 190 */ SYSENT_CI("sigqueue",		sigqueue32,	5),
	/* 191 */ SYSENT_CI("clock_gettime",	clock_gettime,	2),
	/* 192 */ SYSENT_CI("clock_settime",	clock_settime,	2),
	/* 193 */ SYSENT_CI("clock_getres",	clock_getres,	2),
	/* 194 */ SYSENT_CI("timer_create",	timer_create,	3),
	/* 195 */ SYSENT_CI("timer_delete",	timer_delete,	1),
	/* 196 */ SYSENT_CI("timer_settime",	timer_settime,	4),
	/* 197 */ SYSENT_CI("timer_gettime",	timer_gettime,	2),
	/* 198 */ SYSENT_CI("timer_getoverrun",	timer_getoverrun, 1),
	/* 199 */ SYSENT_CI("nanosleep",	nanosleep,	2),
	/* 200 */ SYSENT_CI("facl",		facl,		4),
	/* 201 */ SYSENT_LOADABLE32(),		/* door */
	/* 202 */ SYSENT_CI("setreuid",		setreuid,	2),
	/* 203 */ SYSENT_CI("setregid",		setregid,	2),
	/* 204 */ SYSENT_CI("install_utrap",	install_utrap,	3),
	/* 205 */ SYSENT_CI("signotify",	signotify,	3),
	/* 206 */ SYSENT_CI("schedctl",		schedctl,	0),
	/* 207 */ SYSENT_LOADABLE32(),		/* pset */
	/* 208 */ SYSENT_LOADABLE32(),
	/* 209 */ SYSENT_CI("resolvepath",	resolvepath,	3),
	/* 210 */ SYSENT_CI("lwp_mutex_timedlock", lwp_mutex_timedlock, 3),
	/* 211 */ SYSENT_CI("lwp_sema_timedwait", lwp_sema_timedwait,	3),
	/* 212 */ SYSENT_CI("lwp_rwlock_sys",	lwp_rwlock_sys,	3),
	/*
	 * Syscalls 213-225: 32-bit system call support for large files.
	 */
	/* 213 */ SYSENT_CI("getdents64",	getdents64,	3),
	/* 214 */ SYSENT_AP("smmaplf32", 	smmaplf32, 	7),
	/* 215 */ SYSENT_CI("stat64", 		stat64_32, 	2),
	/* 216 */ SYSENT_CI("lstat64", 		lstat64_32,	2),
	/* 217 */ SYSENT_CI("fstat64", 		fstat64_32, 	2),
	/* 218 */ SYSENT_CI("statvfs64", 	statvfs64_32, 	2),
	/* 219 */ SYSENT_CI("fstatvfs64", 	fstatvfs64_32, 	2),
	/* 220 */ SYSENT_CI("setrlimit64", 	setrlimit64, 	2),
	/* 221 */ SYSENT_CI("getrlimit64", 	getrlimit64, 	2),
	/* 222 */ SYSENT_CI("pread64", 		pread64, 	5),
	/* 223 */ SYSENT_CI("pwrite64", 	pwrite64, 	5),
	/* 224 */ SYSENT_LOADABLE32(),			/* (was creat64) */
	/* 225 */ SYSENT_CI("open64",		open64,		3),
	/* 226 */ SYSENT_LOADABLE32(),		/* rpcsys */
	/* 227 */ SYSENT_CI("zone",		zone,		6),
	/* 228 */ SYSENT_LOADABLE32(),		/* autofssys */
	/* 229 */ SYSENT_CI("getcwd",		getcwd,		2),
	/* 230 */ SYSENT_CI("so_socket",	so_socket,	5),
	/* 231 */ SYSENT_CI("so_socketpair",	so_socketpair,	1),
	/* 232 */ SYSENT_CI("bind",		bind,		4),
	/* 233 */ SYSENT_CI("listen",		listen,		3),
	/* 234 */ SYSENT_CI("accept",		accept,		5),
	/* 235 */ SYSENT_CI("connect",		connect,	4),
	/* 236 */ SYSENT_CI("shutdown",		shutdown,	3),
	/* 237 */ SYSENT_CI("recv",		recv32,		4),
	/* 238 */ SYSENT_CI("recvfrom",		recvfrom32,	6),
	/* 239 */ SYSENT_CI("recvmsg",		recvmsg,	3),
	/* 240 */ SYSENT_CI("send",		send32,		4),
	/* 241 */ SYSENT_CI("sendmsg",		sendmsg,	3),
	/* 242 */ SYSENT_CI("sendto",		sendto32,	6),
	/* 243 */ SYSENT_CI("getpeername",	getpeername,	4),
	/* 244 */ SYSENT_CI("getsockname",	getsockname,	4),
	/* 245 */ SYSENT_CI("getsockopt",	getsockopt,	6),
	/* 246 */ SYSENT_CI("setsockopt",	setsockopt,	6),
	/* 247 */ SYSENT_CI("sockconfig",	sockconfig,	5),
	/* 248 */ SYSENT_CI("ntp_gettime",	ntp_gettime,	1),
	/* 249 */ SYSENT_CI("ntp_adjtime",	ntp_adjtime,	1),
	/* 250 */ SYSENT_CI("lwp_mutex_unlock",	lwp_mutex_unlock,	1),
	/* 251 */ SYSENT_CI("lwp_mutex_trylock", lwp_mutex_trylock,	2),
	/* 252 */ SYSENT_CI("lwp_mutex_register", lwp_mutex_register,	2),
	/* 253 */ SYSENT_CI("cladm",		cladm,		3),
	/* 254 */ SYSENT_CI("uucopy",		uucopy,		3),
	/* 255 */ SYSENT_CI("umount2",		umount2,	2)
};
#endif /* _SYSCALL32_IMPL */

/*
 * Space allocated and initialized in init_syscallnames().
 */
char **syscallnames;

systrace_sysent_t *systrace_sysent;
void (*systrace_probe)(dtrace_id_t, uintptr_t, uintptr_t,
    uintptr_t, uintptr_t, uintptr_t, uintptr_t);

/*ARGSUSED*/
void
systrace_stub(dtrace_id_t id, uintptr_t arg0, uintptr_t arg1,
    uintptr_t arg2, uintptr_t arg3, uintptr_t arg4, uintptr_t arg5)
{}

/*ARGSUSED*/
int64_t
dtrace_systrace_syscall(uintptr_t arg0, uintptr_t arg1, uintptr_t arg2,
    uintptr_t arg3, uintptr_t arg4, uintptr_t arg5)
{
	systrace_sysent_t *sy = &systrace_sysent[curthread->t_sysnum];
	dtrace_id_t id;
	int64_t rval;
	proc_t *p;

	if ((id = sy->stsy_entry) != DTRACE_IDNONE)
		(*systrace_probe)(id, arg0, arg1, arg2, arg3, arg4, arg5);

	/*
	 * We want to explicitly allow DTrace consumers to stop a process
	 * before it actually executes the meat of the syscall.
	 */
	p = ttoproc(curthread);
	mutex_enter(&p->p_lock);
	if (curthread->t_dtrace_stop && !curthread->t_lwp->lwp_nostop) {
		curthread->t_dtrace_stop = 0;
		stop(PR_REQUESTED, 0);
	}
	mutex_exit(&p->p_lock);

	rval = (*sy->stsy_underlying)(arg0, arg1, arg2, arg3, arg4, arg5);

	if (ttolwp(curthread)->lwp_errno != 0)
		rval = -1;

	if ((id = sy->stsy_return) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)rval, (uintptr_t)rval,
		    (uintptr_t)((int64_t)rval >> 32), 0, 0, 0);

	return (rval);
}

#ifdef _SYSCALL32_IMPL

systrace_sysent_t *systrace_sysent32;

/*ARGSUSED*/
int64_t
dtrace_systrace_syscall32(uintptr_t arg0, uintptr_t arg1, uintptr_t arg2,
    uintptr_t arg3, uintptr_t arg4, uintptr_t arg5)
{
	systrace_sysent_t *sy = &systrace_sysent32[curthread->t_sysnum];
	dtrace_id_t id;
	int64_t rval;
	proc_t *p;

	if ((id = sy->stsy_entry) != DTRACE_IDNONE)
		(*systrace_probe)(id, arg0, arg1, arg2, arg3, arg4, arg5);

	/*
	 * We want to explicitly allow DTrace consumers to stop a process
	 * before it actually executes the meat of the syscall.
	 */
	p = ttoproc(curthread);
	mutex_enter(&p->p_lock);
	if (curthread->t_dtrace_stop && !curthread->t_lwp->lwp_nostop) {
		curthread->t_dtrace_stop = 0;
		stop(PR_REQUESTED, 0);
	}
	mutex_exit(&p->p_lock);

	rval = (*sy->stsy_underlying)(arg0, arg1, arg2, arg3, arg4, arg5);

	if (ttolwp(curthread)->lwp_errno != 0)
		rval = -1;

	if ((id = sy->stsy_return) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)rval, (uintptr_t)rval,
		    (uintptr_t)((uint64_t)rval >> 32), 0, 0, 0);

	return (rval);
}

#endif

void
dtrace_systrace_rtt(void)
{
	systrace_sysent_t *sy;
	dtrace_id_t id;

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (systrace_sysent == NULL)
			return;

		sy = &systrace_sysent[curthread->t_sysnum];
#ifdef _SYSCALL32_IMPL
	} else {
		if (systrace_sysent32 == NULL)
			return;

		sy = &systrace_sysent32[curthread->t_sysnum];
#endif
	}

	if ((id = sy->stsy_return) != DTRACE_IDNONE)
		(*systrace_probe)(id, 0, 0, 0, 0, 0, 0);
}
