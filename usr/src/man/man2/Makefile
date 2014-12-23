#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#

#
# Copyright 2011, Richard Lowe
# Copyright 2013, OmniTI Computer Consulting, Inc
# Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
#

include		$(SRC)/Makefile.master

MANSECT= 	2

MANFILES=	Intro.2			\
	 	__sparc_utrap_install.2 \
	 	_lwp_cond_signal.2	\
	 	_lwp_cond_wait.2	\
	 	_lwp_info.2		\
	 	_lwp_kill.2		\
	 	_lwp_mutex_lock.2	\
	 	_lwp_self.2		\
	 	_lwp_sema_wait.2	\
	 	_lwp_suspend.2		\
	 	access.2		\
	 	acct.2			\
	 	acl.2			\
	 	adjtime.2		\
	 	alarm.2			\
	 	audit.2			\
	 	auditon.2		\
	 	brk.2			\
	 	chdir.2			\
	 	chmod.2			\
	 	chown.2			\
	 	chroot.2		\
	 	close.2			\
	 	creat.2			\
	 	dup.2			\
	 	exec.2			\
	 	exit.2			\
	 	fcntl.2			\
	 	fork.2			\
	 	fpathconf.2		\
	 	getacct.2		\
	 	getaudit.2		\
	 	getauid.2		\
	 	getcontext.2		\
	 	getdents.2		\
	 	getgroups.2		\
	 	getisax.2		\
	 	getitimer.2		\
	 	getlabel.2		\
	 	getmsg.2		\
	 	getpflags.2		\
	 	getpid.2		\
	 	getppriv.2		\
	 	getrlimit.2		\
	 	getsid.2		\
	 	getuid.2		\
	 	getustack.2		\
	 	ioctl.2			\
	 	issetugid.2		\
	 	kill.2			\
	 	link.2			\
	 	llseek.2		\
	 	lseek.2			\
	 	memcntl.2		\
	 	meminfo.2		\
	 	mincore.2		\
	 	mkdir.2			\
	 	mknod.2			\
	 	mmap.2			\
	 	mmapobj.2		\
	 	mount.2			\
	 	mprotect.2		\
	 	msgctl.2		\
	 	msgget.2		\
	 	msgids.2		\
	 	msgrcv.2		\
	 	msgsnap.2		\
	 	msgsnd.2		\
	 	munmap.2		\
	 	nice.2			\
	 	ntp_adjtime.2		\
	 	ntp_gettime.2		\
	 	open.2			\
	 	p_online.2		\
	 	pause.2			\
	 	pcsample.2		\
	 	pipe.2			\
	 	poll.2			\
	 	priocntl.2		\
	 	priocntlset.2		\
	 	processor_bind.2	\
	 	processor_info.2	\
	 	profil.2		\
	 	pset_bind.2		\
	 	pset_create.2		\
	 	pset_info.2		\
	 	pset_list.2		\
	 	pset_setattr.2		\
	 	putmsg.2		\
	 	read.2			\
	 	readlink.2		\
	 	rename.2		\
	 	resolvepath.2		\
	 	rmdir.2			\
	 	semctl.2		\
	 	semget.2		\
	 	semids.2		\
	 	semop.2			\
	 	setpgid.2		\
	 	setpgrp.2		\
	 	setrctl.2		\
	 	setregid.2		\
	 	setreuid.2		\
	 	setsid.2		\
	 	settaskid.2		\
	 	setuid.2		\
	 	shmctl.2		\
	 	shmget.2		\
	 	shmids.2		\
	 	shmop.2			\
	 	sigaction.2		\
	 	sigaltstack.2		\
	 	sigpending.2		\
	 	sigprocmask.2		\
	 	sigsend.2		\
	 	sigsuspend.2		\
	 	sigwait.2		\
	 	stat.2			\
	 	statvfs.2		\
	 	stime.2			\
	 	swapctl.2		\
	 	symlink.2		\
	 	sync.2			\
	 	sysfs.2			\
	 	sysinfo.2		\
	 	time.2			\
	 	times.2			\
	 	uadmin.2		\
	 	ulimit.2		\
	 	umask.2			\
	 	umount.2		\
	 	uname.2			\
	 	unlink.2		\
	 	ustat.2			\
	 	utime.2			\
	 	utimes.2		\
	 	uucopy.2		\
	 	vfork.2			\
	 	vhangup.2		\
	 	waitid.2		\
	 	write.2			\
	 	yield.2			\

MANLINKS=	_Exit.2				\
	 	_exit.2				\
	 	_lwp_cond_broadcast.2		\
	 	_lwp_cond_reltimedwait.2	\
	 	_lwp_cond_timedwait.2		\
	 	_lwp_continue.2			\
	 	_lwp_mutex_trylock.2		\
	 	_lwp_mutex_unlock.2		\
	 	_lwp_sema_init.2		\
	 	_lwp_sema_post.2		\
	 	_lwp_sema_trywait.2		\
	 	execl.2				\
	 	execle.2			\
	 	execlp.2			\
	 	execv.2				\
	 	execve.2			\
	 	execvp.2			\
	 	faccessat.2			\
	 	facl.2				\
	 	fchdir.2			\
	 	fchmod.2			\
	 	fchmodat.2			\
	 	fchown.2			\
	 	fchownat.2			\
	 	fchroot.2			\
	 	fgetlabel.2			\
	 	fork1.2				\
	 	forkall.2			\
	 	forkallx.2			\
	 	forkx.2				\
	 	fstat.2				\
	 	fstatat.2			\
	 	fstatvfs.2			\
	 	futimesat.2			\
		futimens.2			\
	 	getaudit_addr.2			\
	 	getegid.2			\
	 	geteuid.2			\
	 	getgid.2			\
	 	getpgid.2			\
	 	getpgrp.2			\
	 	getpmsg.2			\
	 	getppid.2			\
	 	getprojid.2			\
	 	getrctl.2			\
	 	gettaskid.2			\
	 	intro.2				\
	 	lchown.2			\
		linkat.2			\
	 	lstat.2				\
		mkdirat.2			\
		mknodat.2			\
	 	openat.2			\
	 	pathconf.2			\
		pipe2.2				\
		ppoll.2				\
	 	pread.2				\
	 	pset_assign.2			\
	 	pset_destroy.2			\
	 	pset_getattr.2			\
	 	putacct.2			\
	 	putpmsg.2			\
	 	pwrite.2			\
		readlinkat.2			\
	 	readv.2				\
	 	renameat.2			\
	 	sbrk.2				\
	 	semtimedop.2			\
	 	setaudit.2			\
	 	setaudit_addr.2			\
	 	setauid.2			\
	 	setcontext.2			\
	 	setegid.2			\
	 	seteuid.2			\
	 	setgid.2			\
	 	setgroups.2			\
	 	setitimer.2			\
	 	setpflags.2			\
	 	setppriv.2			\
	 	setrlimit.2			\
	 	setustack.2			\
	 	shmat.2				\
	 	shmdt.2				\
	 	sigsendset.2			\
		symlinkat.2			\
	 	umount2.2			\
	 	unlinkat.2			\
		utimensat.2			\
	 	vforkx.2			\
	 	wracct.2			\
	 	writev.2

intro.2				:= LINKSRC = Intro.2

_lwp_cond_broadcast.2		:= LINKSRC = _lwp_cond_signal.2

_lwp_cond_reltimedwait.2	:= LINKSRC = _lwp_cond_wait.2
_lwp_cond_timedwait.2		:= LINKSRC = _lwp_cond_wait.2

_lwp_mutex_trylock.2		:= LINKSRC = _lwp_mutex_lock.2
_lwp_mutex_unlock.2		:= LINKSRC = _lwp_mutex_lock.2

_lwp_sema_init.2		:= LINKSRC = _lwp_sema_wait.2
_lwp_sema_post.2		:= LINKSRC = _lwp_sema_wait.2
_lwp_sema_trywait.2		:= LINKSRC = _lwp_sema_wait.2

_lwp_continue.2			:= LINKSRC = _lwp_suspend.2

faccessat.2			:= LINKSRC = access.2

facl.2				:= LINKSRC = acl.2

sbrk.2				:= LINKSRC = brk.2

fchdir.2			:= LINKSRC = chdir.2

fchmod.2			:= LINKSRC = chmod.2
fchmodat.2			:= LINKSRC = chmod.2

fchown.2			:= LINKSRC = chown.2
fchownat.2			:= LINKSRC = chown.2
lchown.2			:= LINKSRC = chown.2

fchroot.2			:= LINKSRC = chroot.2

execl.2				:= LINKSRC = exec.2
execle.2			:= LINKSRC = exec.2
execlp.2			:= LINKSRC = exec.2
execv.2				:= LINKSRC = exec.2
execve.2			:= LINKSRC = exec.2
execvp.2			:= LINKSRC = exec.2

_Exit.2				:= LINKSRC = exit.2
_exit.2				:= LINKSRC = exit.2

fork1.2				:= LINKSRC = fork.2
forkall.2			:= LINKSRC = fork.2
forkallx.2			:= LINKSRC = fork.2
forkx.2				:= LINKSRC = fork.2

pathconf.2			:= LINKSRC = fpathconf.2

putacct.2			:= LINKSRC = getacct.2
wracct.2			:= LINKSRC = getacct.2

getaudit_addr.2			:= LINKSRC = getaudit.2
setaudit.2			:= LINKSRC = getaudit.2
setaudit_addr.2			:= LINKSRC = getaudit.2

setauid.2			:= LINKSRC = getauid.2

setcontext.2			:= LINKSRC = getcontext.2

setgroups.2			:= LINKSRC = getgroups.2

setitimer.2			:= LINKSRC = getitimer.2

fgetlabel.2			:= LINKSRC = getlabel.2

getpmsg.2			:= LINKSRC = getmsg.2

setpflags.2			:= LINKSRC = getpflags.2

getpgid.2			:= LINKSRC = getpid.2
getpgrp.2			:= LINKSRC = getpid.2
getppid.2			:= LINKSRC = getpid.2

setppriv.2			:= LINKSRC = getppriv.2

setrlimit.2			:= LINKSRC = getrlimit.2

getegid.2			:= LINKSRC = getuid.2
geteuid.2			:= LINKSRC = getuid.2
getgid.2			:= LINKSRC = getuid.2

setustack.2			:= LINKSRC = getustack.2

linkat.2			:= LINKSRC = link.2

mkdirat.2			:= LINKSRC = mkdir.2

mknodat.2			:= LINKSRC = mknod.2

openat.2			:= LINKSRC = open.2

pipe2.2				:= LINKSRC = pipe.2

ppoll.2				:= LINKSRC = poll.2

pset_assign.2			:= LINKSRC = pset_create.2
pset_destroy.2			:= LINKSRC = pset_create.2

pset_getattr.2			:= LINKSRC = pset_setattr.2

putpmsg.2			:= LINKSRC = putmsg.2

pread.2				:= LINKSRC = read.2
readv.2				:= LINKSRC = read.2

readlinkat.2			:= LINKSRC = readlink.2

renameat.2			:= LINKSRC = rename.2

semtimedop.2			:= LINKSRC = semop.2

getrctl.2			:= LINKSRC = setrctl.2

getprojid.2			:= LINKSRC = settaskid.2
gettaskid.2			:= LINKSRC = settaskid.2

setegid.2			:= LINKSRC = setuid.2
seteuid.2			:= LINKSRC = setuid.2
setgid.2			:= LINKSRC = setuid.2

shmat.2				:= LINKSRC = shmop.2
shmdt.2				:= LINKSRC = shmop.2

sigsendset.2			:= LINKSRC = sigsend.2

symlinkat.2			:= LINKSRC = symlink.2

fstat.2				:= LINKSRC = stat.2
fstatat.2			:= LINKSRC = stat.2
lstat.2				:= LINKSRC = stat.2

fstatvfs.2			:= LINKSRC = statvfs.2

umount2.2			:= LINKSRC = umount.2

unlinkat.2			:= LINKSRC = unlink.2

futimens.2			:= LINKSRC = utimes.2
futimesat.2			:= LINKSRC = utimes.2
utimensat.2			:= LINKSRC = utimes.2

vforkx.2			:= LINKSRC = vfork.2

pwrite.2			:= LINKSRC = write.2
writev.2			:= LINKSRC = write.2

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
