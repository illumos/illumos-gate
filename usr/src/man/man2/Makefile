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
# Copyright (c) 2018, Joyent, Inc.  All rights reserved.
# Copyright 2017 Peter Tribble
# Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
#

include		$(SRC)/Makefile.master

MANSECT=	2

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
		execvex.2		\
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
		getmsg.2		\
		getpflags.2		\
		getpid.2		\
		getppriv.2		\
		getrandom.2		\
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
		upanic.2		\
		ustat.2			\
		utime.2			\
		utimes.2		\
		uucopy.2		\
		vfork.2			\
		vhangup.2		\
		waitid.2		\
		write.2			\
		yield.2			\

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(MANLINK_SRCS)
	$(MANLINK_INSTALL)
