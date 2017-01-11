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
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/syscall.h>
#include "xsyscall.h"

/*
 * Array of SVR4 system call numbers. The 4.1 numbers are mapped
 * to their SVR4/5.0 equivalents before trapping into the kernel.
 */

int syscallnum[190] = {	SYS_syscall,	SYS_exit,	-1 /*fork1*/,
	SYS_read,	SYS_write,	-1 /*open*/,	SYS_close,
        -1,		-1 /*creat*/,	-1 /*link*/,	-1 /*unlink*/,
	-1,		SYS_chdir,	0,		-1 /*mknod*/,
        -1 /*chmod*/,	-1 /*lchown*/,	0,		0,
        SYS_lseek,	SYS_getpid,	0,		0,
	0,		SYS_getuid,	0,		0,
	0,		0,		0,		0,
	0,		0,		-1 /*access*/, 	0,
	0,		SYS_sync,	SYS_kill,	-1 /*stat*/,
	0,		-1 /*lstat*/,	-1 /*dup*/,	SYS_pipe,
	0,		SYS_profil,	0,		0,
	SYS_getgid,	0,		0,		0,
	SYS_acct,	0,		-1,		SYS_ioctl,
	-1 /*reboot*/,	0,		-1 /*symlink*/,	-1 /*readlink*/,
	SYS_execve,	SYS_umask,	SYS_chroot,	-1 /*fstat*/,
	0,		-1/*getpagesize*/,-1,		0,
	0,		0,		-1,		-1,
	SYS_mmap,	-1,		SYS_munmap,	SYS_mprotect,
	-1 /*advise*/,	SYS_vhangup,	0,		SYS_mincore,
	SYS_getgroups,	SYS_setgroups,	-1 /*getpgrp*/,	-1 /*setpgrp*/,
	SYS_setitimer,	0,		-1 /*swapon*/,	SYS_getitimer,
	-1/*gethostname*/,-1/*sethostname*/,-1/*getdtablesize*/,-1/*dup2*/,
	-1/*getdopt*/,	SYS_fcntl,	-1 /*select*/,	-1 /*setdopt*/,
	SYS_fdsync,	-1 /*setprio*/,	-1 /*socket*/,	-1 /*connect*/,
	-1 /*accept*/,	-1 /*getprio*/,	-1 /*send*/,	-1 /*recv*/,
	0,		-1 /*bind*/,	-1 /*setsockopt*/,-1 /*listen*/,
	0,		-1 /*sigvec*/,	-1 /*sigblock*/, -1 /*sigsetmask*/,
	-1 /*sigpause*/, -1 /*sigstack*/, -1 /*recvmsg*/, -1 /*sendmsg*/,
	-1 /*vtrace*/,	SYS_gettimeofday, -1 /*getrusage*/, -1 /*getsockopt*/,
	0,		SYS_readv,	SYS_writev,	-1 /*settimeofday*/,
	-1 /*fchown*/,	-1 /*fchmod*/,	-1 /*recvfrom*/, -1 /*setreuid*/,
	-1 /*getregid*/, -1 /*rename*/,	-1 /*truncate*/, -1 /*ftruncate*/,
	-1 /*flock*/,	0,		-1 /*sendto*/,	-1 /*shutdown*/,
	-1 /*socketpair*/, -1 /*mkdir*/, -1 /*rmdir*/,	-1 /*utimes*/,
	0,		SYS_adjtime,	-1 /*getpeername*/,-1 /*gethostid*/,
	0,		SYS_getrlimit,	SYS_setrlimit,	-1 /*killpg*/,
	0,		0,		0,		-1/*getsockname*/,
	SYS_getmsg,	SYS_putmsg,	-1 /*poll*/,	0,
	-1/*nfssvc*/,	-1 /*getdirentries*/, SYS_statfs, SYS_fstatfs,
	-1/*SYS_umount*/, -1 /*async_daemmon*/ -1 /*getfh*/, -1/*getdomain*/,
	-1/*setdomain*/, 0,		-1 /*quotactl*/, -1 /*exportfs*/,
	SYS_mount,	-1/*ustat*/,	SYS_semsys,	SYS_msgsys,
	SYS_shmsys,	-1 /*auditsys*/, -1 /*rfsys*/,	SYS_getdents,
	-1 /*setsid*/,	SYS_fchdir,	SYS_fchroot,	-1 /*vpixsys*/,
	-1 /*aioread*/,	-1 /*aiowrite*/, -1 /*aiocancel*/, SYS_sigpending,
	0,		-1 /*setpgid*/, SYS_pathconf,	SYS_uname,
};

long
syscall(int sysnum, ...)
{
	va_list ap;
	int i1, i2, i3, i4;
	char *c1, *c2, *c3, *c4;
	int	ret_val;

	va_start(ap, sysnum);
	switch(sysnum) {
		case XSYS_read:
			i1 = va_arg(ap, int);
			c1 = va_arg(ap, char *);
			i2 = va_arg(ap, int);
			va_end(ap);
			return (bc_read(i1, c1, i2));
		case XSYS_write:
			i1 = va_arg(ap, int);
			c1 = va_arg(ap, char *);
			i2 = va_arg(ap, int);
			va_end(ap);
			return (bc_write(i1, c1, i2));
		case XSYS_readv:
			i1 = va_arg(ap, int);
			c1 = va_arg(ap, char *);
			i2 = va_arg(ap, int);
			va_end(ap);
			return (bc_readv(i1, c1, i2));
		case XSYS_writev:
			i1 = va_arg(ap, int);
			c1 = va_arg(ap, char *);
			i2 = va_arg(ap, int);
			va_end(ap);
			return (bc_writev(i1, c1, i2));
		case XSYS_open:
			c1 = va_arg(ap, char *);
			i1 = va_arg(ap, int);
			i2 = va_arg(ap, int);
			va_end(ap);
			if (i2)
				return (bc_open(c1, i1, i2));
			else
				return (bc_open(c1, i1));
		case XSYS_close:
			i1 = va_arg(ap, int);
			va_end(ap);
			return (bc_close(i1));
		case XSYS_fcntl:
			i1 = va_arg(ap, int);
			i2 = va_arg(ap, int);
			i3 = va_arg(ap, int);
			va_end(ap);
			return (bc_fcntl(i1, i2, i3));
		case XSYS_select:
			i1 = va_arg(ap, int);
			c1 = va_arg(ap, char *);
			c2 = va_arg(ap, char *);
			c3 = va_arg(ap, char *);
			c4 = va_arg(ap, char *);
			va_end(ap);
			return (select(i1, c1, c2, c3, c4));
		case XSYS_ioctl :
			i1 = va_arg(ap, int);
			i2 = va_arg(ap, int);
			c1 = va_arg(ap, char *);
			va_end(ap);
			return (bc_ioctl(i1, i2, c1));
		case XSYS_stat:
			c1 = va_arg(ap, char *);
			c2 = va_arg(ap, char *);
			va_end(ap);
			return (bc_stat(c1, c2));
		case XSYS_lstat:
			c1 = va_arg(ap, char *);
			c2 = va_arg(ap, char *);
			va_end(ap);
			return (bc_lstat(c1, c2));
		case XSYS_fstat:
			i1 = va_arg(ap, int);
			c1 = va_arg(ap, char *);
			va_end(ap);
			return (bc_fstat(i1, c1));
        	case XSYS_getdents:
			i1 = va_arg(ap, int);
			c1 = va_arg(ap, char *);
			i2 = va_arg(ap, int);
			va_end(ap);
			return (bc_getdents(i1, c1, i2));
		case XSYS_kill:
			i1 = va_arg(ap, int);
			i2 = va_arg(ap, int);
			va_end(ap);
			return (bc_kill(i1, i2));
		case XSYS_mount:
			c1 = va_arg(ap, char *);
			c2 = va_arg(ap, char *);
			i1 = va_arg(ap, int);
			c3 = va_arg(ap, char *);
			va_end(ap);
			return (mount(c1, c2, i1, c3));
		case XSYS_getrlimit:
			i1 = va_arg(ap, int);
			c1 = va_arg(ap, char *);
			va_end(ap);
			return (bc_getrlimit(i1, c1));
		case XSYS_setrlimit:
			i1 = va_arg(ap, int);
			c1 = va_arg(ap, char *);
			va_end(ap);
			return (bc_setrlimit(i1, c1));
		case XSYS_uname:
			c1 = va_arg(ap, char *);
			va_end(ap);
			return (bc_uname(c1));
		case XSYS_creat:
			c1 = va_arg(ap, char *);
			i1 = va_arg(ap, int);
			va_end(ap);
			return (creat(c1, i1));
		case XSYS_unmount:
			c1 = va_arg(ap, char *);
			va_end(ap);
			return (umount(c1));
		case XSYS_link:
			c1 = va_arg(ap, char *);
			c2 = va_arg(ap, char *);
			va_end(ap);
			return (link(c1, c2));
		case XSYS_unlink:
			c1 = va_arg(ap, char *);
			va_end(ap);
			return (unlink(c1));
		case XSYS_chdir:
			c1 = va_arg(ap, char *);
			va_end(ap);
			return (chdir(c1));
		case XSYS_mknod:
			c1 = va_arg(ap, char *);
			i1 = va_arg(ap, int);
			i2 = va_arg(ap, int);
			va_end(ap);
			return (mknod(c1, i1, i2));
		case XSYS_chmod:
			c1 = va_arg(ap, char *);
			i1 = va_arg(ap, int);
			va_end(ap);
			return (chmod(c1, i1));
		case XSYS_chown:
			c1 = va_arg(ap, char *);
			i1 = va_arg(ap, int);
			i2 = va_arg(ap, int);
			va_end(ap);
			return (chown(c1, i1, i2));
		case XSYS_lseek:
			i1 = va_arg(ap, int);
			i2 = va_arg(ap, int);
			i3 = va_arg(ap, int);
			va_end(ap);
			return (lseek(i1, i2, i3));
		case XSYS_access:
			c1 = va_arg(ap, char *);
			i1 = va_arg(ap, int);
			va_end(ap);
			return (access(c1, i1));
        	case XSYS_dup:
			i1 = va_arg(ap, int);
			va_end(ap);
			return (dup(i1));
		case XSYS_dup2:
			i1 = va_arg(ap, int);
			i2 = va_arg(ap, int);
			va_end(ap);
			return (dup2(i1, i2));
		case XSYS_pipe:
			c1 = (char *)va_arg(ap, int *);
			va_end(ap);
			return (pipe(c1));
		case XSYS_symlink:
			c1 = va_arg(ap, char *);
			c2 = va_arg(ap, char *);
			va_end(ap);
			return (symlink(c1, c2));
		case XSYS_readlink:
			c1 = va_arg(ap, char *);
			c2 = va_arg(ap, char *);
			i1 = va_arg(ap, int);
			va_end(ap);
			return (readlink(c1, c2, i1));
		case XSYS_execve:
			c1 = va_arg(ap, char *);
			c2 = (char *)va_arg(ap, char **);
			c3 = (char *)va_arg(ap, char **);
			va_end(ap);
			return (execve(c1, c2, c3));
		case XSYS_chroot:
			c1 = va_arg(ap, char *);
			va_end(ap);
			return (chroot(c1));
		case XSYS_getgroups:
			i1 = va_arg(ap, int);
			c1 = (char *)va_arg(ap, int *);
			va_end(ap);
			return (getgroups(i1, c1));
		case XSYS_setgroups:
			i1 = va_arg(ap, int);
			c1 = (char *)va_arg(ap, int *);
			va_end(ap);
			return (setgroups(i1, c1));
		case XSYS_fsync:
			i1 = va_arg(ap, int);
			va_end(ap);
			return (fsync(i1));
		case XSYS_gettimeofday:
			c1 = va_arg(ap, char *);
			c2 = va_arg(ap, char *);
			va_end(ap);
			return (gettimeofday(c1, c2));
		case XSYS_settimeofday:
			c1 = va_arg(ap, char *);
			c2 = va_arg(ap, char *);
			va_end(ap);
			return (settimeofday(c1, c2));
		case XSYS_rename:
			c1 = va_arg(ap, char *);
			c2 = va_arg(ap, char *);
			va_end(ap);
			return (rename(c1, c2));
		case XSYS_mkdir:
			c1 = va_arg(ap, char *);
			i1 = va_arg(ap, int);
			va_end(ap);
			return (mkdir(c1, i1));
		case XSYS_rmdir:
			c1 = va_arg(ap, char *);
			va_end(ap);
			return (rmdir(c1));
        	case XSYS_statfs:
			c1 = va_arg(ap, char *);
			c2 = va_arg(ap, char *);
			va_end(ap);
			return (statfs(c1, c2));
		case XSYS_fstatfs:
			i1 = va_arg(ap, int);
			c1 = va_arg(ap, char *);
			va_end(ap);
			return (fstatfs(i1, c1));
		case XSYS_getpagesize:
			va_end(ap);
			return (getpagesize());
		case XSYS_gethostid:
			va_end(ap);
			return (gethostid());
		case XSYS_getdtablesize:
			va_end(ap);
			return (getdtablesize());
		case XSYS_pathconf:
			c1 = va_arg(ap, char *);
			i1 = va_arg(ap, int);
			va_end(ap);
			return (pathconf(c1, i1));
		case XSYS_gethostname:
			c1 = va_arg(ap, char *);
			i1 = va_arg(ap, int);
			va_end(ap);
			return (gethostname(c1, i1));
		case XSYS_sethostname:
			c1 = va_arg(ap, char *);
			i1 = va_arg(ap, int);
			va_end(ap);
			return (sethostname(c1, i1));
		case XSYS_setreuid:
			i1 = va_arg(ap, int);
			i2 = va_arg(ap, int);
			va_end(ap);
			return (setreuid(i1, i2));
		case XSYS_setregid:
			i1 = va_arg(ap, int);
			i2 = va_arg(ap, int);
			va_end(ap);
			return (setregid(i1, i2));
		case XSYS_getpriority:
			i1 = va_arg(ap, int);
			i2 = va_arg(ap, int);
			va_end(ap);
			return (getpriority(i1, i2));
		case XSYS_setpriority:
			i1 = va_arg(ap, int);
			i2 = va_arg(ap, int);
			i3 = va_arg(ap, int);
			va_end(ap);
			return (setpriority(i1, i2, i3));
		case XSYS_sigvec:
			i1 = va_arg(ap, int);
			c1 = va_arg(ap, char *);
			c2 = va_arg(ap, char *);
			va_end(ap);
			return (sigvec(i1, c1, c2));
		case XSYS_sigblock:
			i1 = va_arg(ap, int);
			va_end(ap);
			return (sigblock(i1));
		case XSYS_sigpending:
			c1 = va_arg(ap, char *);
			va_end(ap);
			return (sigpending(c1));
		case XSYS_sigsetmask:
			i1 = va_arg(ap, int);
			va_end(ap);
			return (sigsetmask(i1));
		case XSYS_sigpause:
			c1 = va_arg(ap, char *);
			va_end(ap);
			return (sigpause(c1));
		case XSYS_sigstack:
			c1 = va_arg(ap, char *);
			c2 = va_arg(ap, char *);
			va_end(ap);
			return (sigstack(c1, c2));
		case XSYS_truncate:
			c1 = va_arg(ap, char *);
			i1 = va_arg(ap, int);
			va_end(ap);
			return (truncate(c1, i1));
		case XSYS_ftruncate:
			i1 = va_arg(ap, int);
			i2 = va_arg(ap, int);
			va_end(ap);
			return (ftruncate(i1, i2));
		case XSYS_killpg:
			i1 = va_arg(ap, int);
			i2 = va_arg(ap, int);
			va_end(ap);
			return (killpg(i1, i2));
		case XSYS_setpgid:
			i1 = va_arg(ap, int);
			i2 = va_arg(ap, int);
			va_end(ap);
			return (setpgid(i1, i2));
		case XSYS_ptrace:
			i1 = va_arg(ap, int);
			i2 = va_arg(ap, int);
			i3 = va_arg(ap, int);
			c1 = va_arg(ap, char *);
			i4 = va_arg(ap, int);
			c2 = va_arg(ap, char *);
			va_end(ap);
			return (ptrace(i1, i2, i3, c1, i4, c2));
#ifdef S5EMUL
		case XSYS_getpgrp:
			va_end(ap);
			return (getpgrp());
		case XSYS_setpgrp:
			va_end(ap);
			return (setpgrp());
#else
		case XSYS_getpgrp:
			i1 = va_arg(ap, int);
			va_end(ap);
			return (getpgrp(i1));
		case XSYS_setpgrp:
			i1 = va_arg(ap, int);
			i2 = va_arg(ap, int);
			va_end(ap);
			return (setpgrp(i1, i2));
#endif
		case XSYS_getrusage:
			i1 = va_arg(ap, int);
			c1 = va_arg(ap, char *);
			va_end(ap);
			return (getrusage(i1, c1));
		case XSYS_setsid:
			va_end(ap);
			return (setsid());

		case XSYS_flock:
			i1 = va_arg(ap, int);
			i2 = va_arg(ap, int);
			va_end(ap);
			return (flock(i1, i2));
		case XSYS_utimes:
			c1 = va_arg(ap, char *);
			c2 = va_arg(ap, char *);
			va_end(ap);
			return (utimes(c1, c2));
		case XSYS_poll:
			c1 = va_arg(ap, char *);
			i2 = va_arg(ap, int);
			i3 = va_arg(ap, int);
			va_end(ap);
			return (poll(c1, i2, i3));
		case XSYS_fchmod:
			i1 = va_arg(ap, int);
			i2 = va_arg(ap, int);
			va_end(ap);
			return (fchmod(i1, i2));
		case XSYS_fchown:
			i1 = va_arg(ap, int);
			i2 = va_arg(ap, int);
			i3 = va_arg(ap, int);
			va_end(ap);
			return (fchown(i1, i2, i3));
		case XSYS_fork:
			va_end(ap);
			return (fork1());

		/* the following system calls are now implemented in
		 * libsocket */
		case XSYS_accept:
			i1 = va_arg(ap, int);
			c1 = va_arg(ap, char *);
			c2 = (char *)va_arg(ap, int *);
			va_end(ap);
			return (_accept(i1, c1, c2));
		case XSYS_bind:
			i1 = va_arg(ap, int);
			c1 = va_arg(ap, char *);
			i2 = va_arg(ap, int);
			va_end(ap);
			return (_bind(i1, c1, i2));
		case XSYS_connect:
			i1 = va_arg(ap, int);
			c1 = va_arg(ap, char *);
			i2 = va_arg(ap, int);
			va_end(ap);
			return (_connect(i1, c1, i2));
		case XSYS_getsockopt:
			i1 = va_arg(ap, int);
			i2 = va_arg(ap, int);
			i3 = va_arg(ap, int);
			c1 = va_arg(ap, char *);
			c2 = va_arg(ap, char *);
			va_end(ap);
			return (_getsockopt(i1, i2, i3, c1, c2));
		case XSYS_getpeername:
			i1 = va_arg(ap, int);
			c1 = va_arg(ap, char *);
			c2 = va_arg(ap, char *);
			va_end(ap);
			return (_getpeername(i1, c1, c2));
		case XSYS_getsockname:
			i1 = va_arg(ap, int);
			c1 = va_arg(ap, char *);
			c2 = va_arg(ap, char *);
			va_end(ap);
			return (_getsockname(i1, c1, c2));
		case XSYS_getdomainname:
			c1 = va_arg(ap, char *);
			i1 = va_arg(ap, int);
			va_end(ap);
			return (getdomainname(c1, i1));
		case XSYS_listen:
			i1 = va_arg(ap, int);
			i2 = va_arg(ap, int);
			va_end(ap);
			return (_listen(i1, i2));
		case XSYS_recv:
			i1 = va_arg(ap, int);
			c1 = va_arg(ap, char *);
			i2 = va_arg(ap, int);
			i3 = va_arg(ap, int);
			va_end(ap);
			return (_recv(i1, c1, i2, i3));
		case XSYS_recvfrom:
			i1 = va_arg(ap, int);
			c1 = va_arg(ap, char *);
			i2 = va_arg(ap, int);
			i3 = va_arg(ap, int);
			c2 = va_arg(ap, char *);
			c3 = va_arg(ap, char *);
			va_end(ap);
			return (_recvfrom(i1, c1, i2, i3, c2, c3));
		case XSYS_recvmsg:
			i1 = va_arg(ap, int);
			c1 = va_arg(ap, char *);
			i2 = va_arg(ap, int);
			va_end(ap);
			return (_recvmsg(i1, c1, i2));
		case XSYS_send:
			i1 = va_arg(ap, int);
			c1 = va_arg(ap, char *);
			i2 = va_arg(ap, int);
			i3 = va_arg(ap, int);
			va_end(ap);
			return (_send(i1, c1, i2, i3));
		case XSYS_sendto:
			i1 = va_arg(ap, int);
			c1 = va_arg(ap, char *);
			i2 = va_arg(ap, int);
			i3 = va_arg(ap, int);
			c2 = va_arg(ap, char *);
			i4 = va_arg(ap, int);
			va_end(ap);
			return (_sendto(i1, c1, i2, i3, c2, i4));
		case XSYS_sendmsg:
			i1 = va_arg(ap, int);
			c1 = va_arg(ap, char *);
			i2 = va_arg(ap, int);
			va_end(ap);
			return (_sendmsg(i1, c1, i2));
		case XSYS_setdomainname:
			c1 = va_arg(ap, char *);
			i1 = va_arg(ap, int);
			va_end(ap);
			return (setdomainname(c1 ,i1));
		case XSYS_setsockopt:
			i1 = va_arg(ap, int);
			i2 = va_arg(ap, int);
			i3 = va_arg(ap, int);
			c1 = va_arg(ap, char *);
			i4 = va_arg(ap, int);
			va_end(ap);
			return (_setsockopt(i1, i2, i3, c1, i4));
		case XSYS_shutdown:
			i1 = va_arg(ap, int);
			i2 = va_arg(ap, int);
			va_end(ap);
			return (_shutdown(i1, i2));
		case XSYS_socket:
			i1 = va_arg(ap, int);
			i2 = va_arg(ap, int);
			i3 = va_arg(ap, int);
			va_end(ap);
			return (_socket(i1, i2, i3));
		case XSYS_socketpair:
			i1 = va_arg(ap, int);
			i2 = va_arg(ap, int);
			i3 = va_arg(ap, int);
			c1 = va_arg(ap, char *);
			va_end(ap);
			return (_socketpair(i1, i2, i3, c1));


		/* The following can directly go through syscall */
		case XSYS_acct:
		case XSYS_adjtime:
		case XSYS_exit:
		case XSYS_fchdir:
		case XSYS_fchroot:
		case XSYS_getgid:
		case XSYS_getitimer:
		case XSYS_getmsg:
		case XSYS_getpid:
		case XSYS_getuid:
		case XSYS_mincore:
		case XSYS_mprotect:
		case XSYS_munmap:
		case XSYS_putmsg:
		case XSYS_profil:
		case XSYS_setitimer:
		case XSYS_sync:
		case XSYS_umask:
		case XSYS_semsys:
		case XSYS_msgsys:
		case XSYS_shmsys:
		case XSYS_mmap:
		case XSYS_vhangup:
			ret_val = _syscall(syscallnum[sysnum], ap);
			va_end(ap);
			return (ret_val);

		case XSYS_aioread:
		case XSYS_aiowrite:
		case XSYS_aiocancel:
		case XSYS_swapon:
		case XSYS_async_daemon:
		case XSYS_getfh:
		case XSYS_nfssvc:
		case XSYS_exportfs:
		case XSYS_auditsys:
        	case XSYS_vpixsys:
		case XSYS_quotactl:
		case XSYS_getdopt:
		case XSYS_setdopt:
		case XSYS_ustat:
		case XSYS_vtrace:
		case XSYS_reboot:
		case XSYS_madvise:
		case XSYS_vadvise:
		case XSYS_getdirentries:
			va_end(ap);
			fprintf(stderr,"system call not supported\n");
			return(-1);
	}
	va_end(ap);
	return (-1);
}
