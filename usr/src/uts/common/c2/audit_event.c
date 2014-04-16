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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2011 Bayard G. Bell. All rights reserved.
 */

/*
 * This file contains the audit event table used to control the production
 * of audit records for each system call.
 */

#include <sys/policy.h>
#include <sys/cred.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/systeminfo.h>	/* for sysinfo auditing */
#include <sys/utsname.h>	/* for sysinfo auditing */
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/mman.h>		/* for mmap(2) auditing etc. */
#include <sys/fcntl.h>
#include <sys/modctl.h>		/* for modctl auditing */
#include <sys/vnode.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/processor.h>
#include <sys/procset.h>
#include <sys/acl.h>
#include <sys/ipc.h>
#include <sys/door.h>
#include <sys/sem.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/kmem.h>
#include <sys/file.h>		/* for accept */
#include <sys/utssys.h>		/* for fuser */
#include <sys/tsol/label.h>
#include <sys/tsol/tndb.h>
#include <sys/tsol/tsyscall.h>
#include <c2/audit.h>
#include <c2/audit_kernel.h>
#include <c2/audit_kevents.h>
#include <c2/audit_record.h>
#include <sys/procset.h>
#include <nfs/mount.h>
#include <sys/param.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/stropts.h>
#include <sys/tihdr.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/vfs_opreg.h>
#include <fs/sockfs/sockcommon.h>
#include <netinet/in.h>
#include <sys/ddi.h>
#include <sys/port_impl.h>
#include <sys/secflags.h>

static au_event_t	aui_fchownat(au_event_t);
static au_event_t	aui_fchmodat(au_event_t);
static au_event_t	aui_open(au_event_t);
static au_event_t	aui_openat(au_event_t);
static au_event_t	aui_unlinkat(au_event_t);
static au_event_t	aui_fstatat(au_event_t);
static au_event_t	aui_msgsys(au_event_t);
static au_event_t	aui_shmsys(au_event_t);
static au_event_t	aui_semsys(au_event_t);
static au_event_t	aui_utssys(au_event_t);
static au_event_t	aui_fcntl(au_event_t);
static au_event_t	aui_execve(au_event_t);
static au_event_t	aui_memcntl(au_event_t);
static au_event_t	aui_sysinfo(au_event_t);
static au_event_t	aui_portfs(au_event_t);
static au_event_t	aui_auditsys(au_event_t);
static au_event_t	aui_modctl(au_event_t);
static au_event_t	aui_acl(au_event_t);
static au_event_t	aui_doorfs(au_event_t);
static au_event_t	aui_privsys(au_event_t);
static au_event_t	aui_forksys(au_event_t);
static au_event_t	aui_labelsys(au_event_t);
static au_event_t	aui_setpgrp(au_event_t);


static void	aus_exit(struct t_audit_data *);
static void	aus_open(struct t_audit_data *);
static void	aus_openat(struct t_audit_data *);
static void	aus_acl(struct t_audit_data *);
static void	aus_acct(struct t_audit_data *);
static void	aus_chown(struct t_audit_data *);
static void	aus_fchown(struct t_audit_data *);
static void	aus_lchown(struct t_audit_data *);
static void	aus_fchownat(struct t_audit_data *);
static void	aus_chmod(struct t_audit_data *);
static void	aus_facl(struct t_audit_data *);
static void	aus_fchmod(struct t_audit_data *);
static void	aus_fchmodat(struct t_audit_data *);
static void	aus_fcntl(struct t_audit_data *);
static void	aus_mkdir(struct t_audit_data *);
static void	aus_mkdirat(struct t_audit_data *);
static void	aus_mknod(struct t_audit_data *);
static void	aus_mknodat(struct t_audit_data *);
static void	aus_mount(struct t_audit_data *);
static void	aus_umount2(struct t_audit_data *);
static void	aus_msgsys(struct t_audit_data *);
static void	aus_semsys(struct t_audit_data *);
static void	aus_close(struct t_audit_data *);
static void	aus_fstatfs(struct t_audit_data *);
static void	aus_setgid(struct t_audit_data *);
static void	aus_setpgrp(struct t_audit_data *);
static void	aus_setuid(struct t_audit_data *);
static void	aus_shmsys(struct t_audit_data *);
static void	aus_doorfs(struct t_audit_data *);
static void	aus_ioctl(struct t_audit_data *);
static void	aus_memcntl(struct t_audit_data *);
static void	aus_mmap(struct t_audit_data *);
static void	aus_munmap(struct t_audit_data *);
static void	aus_priocntlsys(struct t_audit_data *);
static void	aus_setegid(struct t_audit_data *);
static void	aus_setgroups(struct t_audit_data *);
static void	aus_seteuid(struct t_audit_data *);
static void	aus_putmsg(struct t_audit_data *);
static void	aus_putpmsg(struct t_audit_data *);
static void	aus_getmsg(struct t_audit_data *);
static void	aus_getpmsg(struct t_audit_data *);
static void	aus_auditsys(struct t_audit_data *);
static void	aus_sysinfo(struct t_audit_data *);
static void	aus_modctl(struct t_audit_data *);
static void	aus_kill(struct t_audit_data *);
static void	aus_setregid(struct t_audit_data *);
static void	aus_setreuid(struct t_audit_data *);
static void	aus_labelsys(struct t_audit_data *);

static void	auf_mknod(struct t_audit_data *, int, rval_t *);
static void	auf_mknodat(struct t_audit_data *, int, rval_t *);
static void	auf_msgsys(struct t_audit_data *, int, rval_t *);
static void	auf_semsys(struct t_audit_data *, int, rval_t *);
static void	auf_shmsys(struct t_audit_data *, int, rval_t *);
static void	auf_read(struct t_audit_data *, int, rval_t *);
static void	auf_write(struct t_audit_data *, int, rval_t *);

static void	aus_sigqueue(struct t_audit_data *);
static void	aus_p_online(struct t_audit_data *);
static void	aus_processor_bind(struct t_audit_data *);
static void	aus_inst_sync(struct t_audit_data *);
static void	aus_brandsys(struct t_audit_data *);

static void	auf_accept(struct t_audit_data *, int, rval_t *);

static void	auf_bind(struct t_audit_data *, int, rval_t *);
static void	auf_connect(struct t_audit_data *, int, rval_t *);
static void	aus_shutdown(struct t_audit_data *);
static void	auf_setsockopt(struct t_audit_data *, int, rval_t *);
static void	aus_sockconfig(struct t_audit_data *);
static void	auf_recv(struct t_audit_data *, int, rval_t *);
static void	auf_recvmsg(struct t_audit_data *, int, rval_t *);
static void	auf_send(struct t_audit_data *, int, rval_t *);
static void	auf_sendmsg(struct t_audit_data *, int, rval_t *);
static void	auf_recvfrom(struct t_audit_data *, int, rval_t *);
static void	auf_sendto(struct t_audit_data *, int, rval_t *);
static void	aus_socket(struct t_audit_data *);
/*
 * This table contains mapping information for converting system call numbers
 * to audit event IDs. In several cases it is necessary to map a single system
 * call to several events.
 */

#define	aui_null	NULL	/* NULL initialize function */
#define	aus_null	NULL	/* NULL start function */
#define	auf_null	NULL	/* NULL finish function */

struct audit_s2e audit_s2e[] =
{
/*
 * ----------	---------- 	----------	----------
 * INITIAL	AUDIT		START		SYSTEM
 * PROCESSING	EVENT		PROCESSING	CALL
 * ----------	----------	----------	-----------
 *		FINISH		EVENT
 *		PROCESSING	CONTROL
 * ----------------------------------------------------------
 */
aui_null,	AUE_NULL,	aus_null,	/* 0 unused (indirect) */
		auf_null,	0,
aui_null,	AUE_EXIT,	aus_exit,	/* 1 exit */
		auf_null,	S2E_NPT,
aui_null,	AUE_PSECFLAGS,	aus_null,	/* 2 psecflags */
		auf_null,	0,
aui_null,	AUE_READ,	aus_null,	/* 3 read */
		auf_read,	S2E_PUB,
aui_null,	AUE_WRITE,	aus_null,	/* 4 write */
		auf_write,	0,
aui_open,	AUE_OPEN,	aus_open,	/* 5 open */
		auf_null,	S2E_SP,
aui_null,	AUE_CLOSE,	aus_close,	/* 6 close */
		auf_null,	0,
aui_null,	AUE_LINK,	aus_null,	/* 7 linkat */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 8 (loadable) was creat */
		auf_null,	0,
aui_null,	AUE_LINK,	aus_null,	/* 9 link */
		auf_null,	0,
aui_null,	AUE_UNLINK,	aus_null,	/* 10 unlink */
		auf_null,	0,
aui_null,	AUE_SYMLINK,	aus_null,	/* 11 symlinkat */
		auf_null,	0,
aui_null,	AUE_CHDIR,	aus_null,	/* 12 chdir */
		auf_null,	S2E_SP,
aui_null,	AUE_NULL,	aus_null,	/* 13 time */
		auf_null,	0,
aui_null,	AUE_MKNOD,	aus_mknod,	/* 14 mknod */
		auf_mknod,	S2E_MLD,
aui_null,	AUE_CHMOD,	aus_chmod,	/* 15 chmod */
		auf_null,	0,
aui_null,	AUE_CHOWN,	aus_chown,	/* 16 chown */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 17 brk */
		auf_null,	0,
aui_null,	AUE_STAT,	aus_null,	/* 18 stat */
		auf_null,	S2E_PUB,
aui_null,	AUE_NULL,	aus_null,	/* 19 lseek */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 20 getpid */
		auf_null,	0,
aui_null,	AUE_MOUNT,	aus_mount,	/* 21 mount */
		auf_null,	S2E_MLD,
aui_null,	AUE_READLINK,	aus_null,	/* 22 readlinkat */
		auf_null,	S2E_PUB,
aui_null,	AUE_SETUID,	aus_setuid,	/* 23 setuid */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 24 getuid */
		auf_null,	0,
aui_null,	AUE_STIME,	aus_null,	/* 25 stime */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 26 pcsample */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 27 alarm */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 28 fstat */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 29 pause */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 30 (loadable) was utime */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 31 stty (TIOCSETP-audit?) */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 32 gtty */
		auf_null,	0,
aui_null,	AUE_ACCESS,	aus_null,	/* 33 access */
		auf_null,	S2E_PUB,
aui_null,	AUE_NICE,	aus_null,	/* 34 nice */
		auf_null,	0,
aui_null,	AUE_STATFS,	aus_null,	/* 35 statfs */
		auf_null,	S2E_PUB,
aui_null,	AUE_NULL,	aus_null,	/* 36 sync */
		auf_null,	0,
aui_null,	AUE_KILL,	aus_kill,	/* 37 kill */
		auf_null,	0,
aui_null,	AUE_FSTATFS,	aus_fstatfs,	/* 38 fstatfs */
		auf_null,	S2E_PUB,
aui_setpgrp,	AUE_SETPGRP,	aus_setpgrp,	/* 39 setpgrp */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 40 uucopystr */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 41 (loadable) was dup */
		auf_null,	0,
aui_null,	AUE_PIPE,	aus_null,	/* 42 (loadable) pipe */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 43 times */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 44 profil */
		auf_null,	0,
aui_null,	AUE_ACCESS,	aus_null,	/* 45 faccessat */
		auf_null,	S2E_PUB,
aui_null,	AUE_SETGID,	aus_setgid,	/* 46 setgid */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 47 getgid */
		auf_null,	0,
aui_null,	AUE_MKNOD,	aus_mknodat,	/* 48 mknodat */
		auf_mknodat,	S2E_MLD,
aui_msgsys,	AUE_MSGSYS,	aus_msgsys,	/* 49 (loadable) msgsys */
		auf_msgsys,	0,
#if defined(__x86)
aui_null,	AUE_NULL,	aus_null,	/* 50 sysi86 */
		auf_null,	0,
#else
aui_null,	AUE_NULL,	aus_null,	/* 50 (loadable) was sys3b */
		auf_null,	0,
#endif /* __x86 */
aui_null,	AUE_ACCT,	aus_acct,	/* 51 (loadable) sysacct */
		auf_null,	0,
aui_shmsys,	AUE_SHMSYS,	aus_shmsys,	/* 52 (loadable) shmsys */
		auf_shmsys,	0,
aui_semsys,	AUE_SEMSYS,	aus_semsys,	/* 53 (loadable) semsys */
		auf_semsys,	0,
aui_null,	AUE_IOCTL,	aus_ioctl,	/* 54 ioctl */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 55 uadmin */
		auf_null,	0,
aui_fchownat,	AUE_NULL,	aus_fchownat,	/* 56 fchownat */
		auf_null,	0,
aui_utssys,	AUE_FUSERS,	aus_null,	/* 57 utssys */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 58 fsync */
		auf_null,	0,
aui_execve,	AUE_EXECVE,	aus_null,	/* 59 exece */
		auf_null,	S2E_MLD,
aui_null,	AUE_NULL,	aus_null,	/* 60 umask */
		auf_null,	0,
aui_null,	AUE_CHROOT,	aus_null,	/* 61 chroot */
		auf_null,	S2E_SP,
aui_fcntl,	AUE_FCNTL,	aus_fcntl,	/* 62 fcntl */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 63 ulimit */
		auf_null,	0,
aui_null,	AUE_RENAME,	aus_null,	/* 64 renameat */
		auf_null,	0,
aui_unlinkat,	AUE_NULL,	aus_null,	/* 65 unlinkat */
		auf_null,	0,
aui_fstatat,	AUE_NULL,	aus_null,	/* 66 fstatat */
		auf_null,	S2E_PUB,
aui_fstatat,	AUE_NULL,	aus_null,	/* 67 fstatat64 */
		auf_null,	S2E_PUB,
aui_openat,	AUE_OPEN,	aus_openat,	/* 68 openat */
		auf_null,	S2E_SP,
aui_openat,	AUE_OPEN,	aus_openat,	/* 69 openat64 */
		auf_null,	S2E_SP,
aui_null,	AUE_NULL,	aus_null,	/* 70 tasksys */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 71 (loadable) acctctl */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 72 (loadable) exacct */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 73 getpagesizes */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 74 rctlsys */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 75 sidsys */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 76 (loadable) was fsat */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 77 syslwp_park */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 78 sendfilev */
		auf_null,	0,
aui_null,	AUE_RMDIR,	aus_null,	/* 79 rmdir */
		auf_null,	0,
aui_null,	AUE_MKDIR,	aus_mkdir,	/* 80 mkdir */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 81 getdents */
		auf_null,	0,
aui_privsys,	AUE_NULL,	aus_null,	/* 82 privsys */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 83 ucredsys */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 84 sysfs */
		auf_null,	0,
aui_null,	AUE_GETMSG,	aus_getmsg,	/* 85 getmsg */
		auf_null,	0,
aui_null,	AUE_PUTMSG,	aus_putmsg,	/* 86 putmsg */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 87 (loadable) was poll */
		auf_null,	0,
aui_null,	AUE_LSTAT,	aus_null,	/* 88 lstat */
		auf_null,	S2E_PUB,
aui_null,	AUE_SYMLINK,	aus_null,	/* 89 symlink */
		auf_null,	0,
aui_null,	AUE_READLINK,	aus_null,	/* 90 readlink */
		auf_null,	S2E_PUB,
aui_null,	AUE_SETGROUPS,	aus_setgroups,	/* 91 setgroups */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 92 getgroups */
		auf_null,	0,
aui_null,	AUE_FCHMOD,	aus_fchmod,	/* 93 fchmod */
		auf_null,	0,
aui_null,	AUE_FCHOWN,	aus_fchown,	/* 94 fchown */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 95 sigprocmask */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 96 sigsuspend */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 97 sigaltstack */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 98 sigaction */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 99 sigpending */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 100 setcontext */
		auf_null,	0,
aui_fchmodat,	AUE_NULL,	aus_fchmodat,	/* 101 fchmodat */
		auf_null,	0,
aui_null,	AUE_MKDIR,	aus_mkdirat,	/* 102 mkdirat */
		auf_null,	0,
aui_null,	AUE_STATVFS,	aus_null,	/* 103 statvfs */
		auf_null,	S2E_PUB,
aui_null,	AUE_NULL,	aus_null,	/* 104 fstatvfs */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 105 getloadavg */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 106 nfssys */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 107 waitsys */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 108 sigsendsys */
		auf_null,	0,
#if defined(__x86)
aui_null,	AUE_NULL,	aus_null,	/* 109 hrtsys */
		auf_null,	0,
#else
aui_null,	AUE_NULL,	aus_null,	/* 109 (loadable) */
		auf_null,	0,
#endif /* __x86 */
aui_null,	AUE_UTIMES,	aus_null,	/* 110 utimesys */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 111 sigresend */
		auf_null,	0,
aui_null,	AUE_PRIOCNTLSYS, aus_priocntlsys, /* 112 priocntlsys */
		auf_null,	0,
aui_null,	AUE_PATHCONF,	aus_null,	/* 113 pathconf */
		auf_null,	S2E_PUB,
aui_null,	AUE_NULL,	aus_null,	/* 114 mincore */
		auf_null,	0,
aui_null,	AUE_MMAP,	aus_mmap,	/* 115 mmap */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 116 mprotect */
		auf_null,	0,
aui_null,	AUE_MUNMAP,	aus_munmap,	/* 117 munmap */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 118 fpathconf */
		auf_null,	0,
aui_null,	AUE_VFORK,	aus_null,	/* 119 vfork */
		auf_null,	0,
aui_null,	AUE_FCHDIR,	aus_null,	/* 120 fchdir */
		auf_null,	0,
aui_null,	AUE_READ,	aus_null,	/* 121 readv */
		auf_read,	S2E_PUB,
aui_null,	AUE_WRITE,	aus_null,	/* 122 writev */
		auf_write,	0,
aui_null,	AUE_NULL,	aus_null,	/* 123 (loadable) was xstat */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 124 (loadable) was lxstat */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 125 (loadable) was fxstat */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 126 (loadable) was xmknod */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 127 mmapobj */
		auf_null,	0,
aui_null,	AUE_SETRLIMIT,	aus_null,	/* 128 setrlimit */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 129 getrlimit */
		auf_null,	0,
aui_null,	AUE_LCHOWN,	aus_lchown,	/* 130 lchown */
		auf_null,	0,
aui_memcntl,	AUE_MEMCNTL,	aus_memcntl,	/* 131 memcntl */
		auf_null,	0,
aui_null,	AUE_GETPMSG,	aus_getpmsg,	/* 132 getpmsg */
		auf_null,	0,
aui_null,	AUE_PUTPMSG,	aus_putpmsg,	/* 133 putpmsg */
		auf_null,	0,
aui_null,	AUE_RENAME,	aus_null,	/* 134 rename */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 135 uname */
		auf_null,	0,
aui_null,	AUE_SETEGID,	aus_setegid,	/* 136 setegid */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 137 sysconfig */
		auf_null,	0,
aui_null,	AUE_ADJTIME,	aus_null,	/* 138 adjtime */
		auf_null,	0,
aui_sysinfo,	AUE_SYSINFO,	aus_sysinfo,	/* 139 systeminfo */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 140 (loadable) sharefs */
		auf_null,	0,
aui_null,	AUE_SETEUID,	aus_seteuid,	/* 141 seteuid */
		auf_null,	0,
aui_forksys,	AUE_NULL,	aus_null,	/* 142 forksys */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 143 (loadable) was fork1 */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 144 sigwait */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 145 lwp_info */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 146 yield */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 147 (loadable) */
						/*	was lwp_sema_wait */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 148 lwp_sema_post */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 149 lwp_sema_trywait */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 150 lwp_detach */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 151 corectl */
		auf_null,	0,
aui_modctl,	AUE_MODCTL,	aus_modctl,	/* 152 modctl */
		auf_null,	0,
aui_null,	AUE_FCHROOT,	aus_null,	/* 153 fchroot */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 154 (loadable) was utimes */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 155 vhangup */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 156 gettimeofday */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 157 getitimer */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 158 setitimer */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 159 lwp_create */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 160 lwp_exit */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 161 lwp_suspend */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 162 lwp_continue */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 163 lwp_kill */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 164 lwp_self */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 165 lwp_sigmask */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 166 lwp_private */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 167 lwp_wait */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 168 lwp_mutex_wakeup  */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 169 (loadable) */
						/*	was lwp_mutex_lock */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 170 lwp_cond_wait */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 171 lwp_cond_signal */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 172 lwp_cond_broadcast */
		auf_null,	0,
aui_null,	AUE_READ,	aus_null,	/* 173 pread */
		auf_read,	S2E_PUB,
aui_null,	AUE_WRITE,	aus_null,	/* 174 pwrite */
		auf_write,	0,
aui_null,	AUE_NULL,	aus_null,	/* 175 llseek */
		auf_null,	0,
aui_null,	AUE_INST_SYNC,	aus_inst_sync,  /* 176 (loadable) inst_sync */
		auf_null,	0,
aui_null,	AUE_BRANDSYS,	aus_brandsys,	/* 177 brandsys */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 178 (loadable) kaio */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 179 (loadable) cpc */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 180 lgrpsys */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 181 rusagesys */
		auf_null,	0,
aui_portfs,	AUE_PORTFS,	aus_null,	/* 182 (loadable) portfs */
		auf_null,	S2E_MLD,
aui_null,	AUE_NULL,	aus_null,	/* 183 pollsys */
		auf_null,	0,
aui_labelsys,	AUE_NULL,	aus_labelsys,	/* 184 labelsys */
		auf_null,	0,
aui_acl,	AUE_ACLSET,	aus_acl,	/* 185 acl */
		auf_null,	0,
aui_auditsys,	AUE_AUDITSYS,	aus_auditsys,	/* 186 auditsys  */
		auf_null,	0,
aui_null,	AUE_PROCESSOR_BIND, aus_processor_bind, /* 187 processor_bind */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 188 processor_info */
		auf_null,	0,
aui_null,	AUE_P_ONLINE,	aus_p_online,	/* 189 p_online */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_sigqueue,	/* 190 sigqueue */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 191 clock_gettime */
		auf_null,	0,
aui_null,	AUE_CLOCK_SETTIME,	aus_null,	/* 192 clock_settime */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 193 clock_getres */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 194 timer_create */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 195 timer_delete */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 196 timer_settime */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 197 timer_gettime */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 198 timer_getoverrun */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 199 nanosleep */
		auf_null,	0,
aui_acl,	AUE_FACLSET,	aus_facl,	/* 200 facl */
		auf_null,	0,
aui_doorfs,	AUE_DOORFS,	aus_doorfs,	/* 201 (loadable) doorfs */
		auf_null,	0,
aui_null,	AUE_SETREUID,	aus_setreuid,	/* 202 setreuid */
		auf_null,	0,
aui_null,	AUE_SETREGID,	aus_setregid,	/* 203 setregid */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 204 install_utrap */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 205 signotify */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 206 schedctl */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 207 (loadable) pset */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 208 sparc_utrap_install */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 209 resolvepath */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 210 lwp_mutex_timedlock */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 211 lwp_sema_timedwait */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 212 lwp_rwlock_sys */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 213 getdents64 */
		auf_null,	0,
aui_null,	AUE_MMAP,	aus_mmap,	/* 214 mmap64 */
		auf_null,	0,
aui_null,	AUE_STAT,	aus_null,	/* 215 stat64 */
		auf_null,	S2E_PUB,
aui_null,	AUE_LSTAT,	aus_null,	/* 216 lstat64 */
		auf_null,	S2E_PUB,
aui_null,	AUE_NULL,	aus_null,	/* 217 fstat64 */
		auf_null,	0,
aui_null,	AUE_STATVFS,	aus_null,	/* 218 statvfs64 */
		auf_null,	S2E_PUB,
aui_null,	AUE_NULL,	aus_null,	/* 219 fstatvfs64 */
		auf_null,	0,
aui_null,	AUE_SETRLIMIT,	aus_null,	/* 220 setrlimit64 */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 221 getrlimit64 */
		auf_null,	0,
aui_null,	AUE_READ,	aus_null,	/* 222 pread64  */
		auf_read,	S2E_PUB,
aui_null,	AUE_WRITE,	aus_null,	/* 223 pwrite64 */
		auf_write,	0,
aui_null,	AUE_NULL,	aus_null,	/* 224 (loadable) was creat64 */
		auf_null,	0,
aui_open,	AUE_OPEN,	aus_open,	/* 225 open64 */
		auf_null,	S2E_SP,
aui_null,	AUE_NULL,	aus_null,	/* 226 (loadable) rpcsys */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 227 zone */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 228 (loadable) autofssys */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 229 getcwd */
		auf_null,	0,
aui_null,	AUE_SOCKET,	aus_socket,	/* 230 so_socket */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 231 so_socketpair */
		auf_null,	0,
aui_null,	AUE_BIND,	aus_null,	/* 232 bind */
		auf_bind,	0,
aui_null,	AUE_NULL,	aus_null,	/* 233 listen */
		auf_null,	0,
aui_null,	AUE_ACCEPT,	aus_null,	/* 234 accept */
		auf_accept,	0,
aui_null,	AUE_CONNECT,	aus_null,	/* 235 connect */
		auf_connect,	0,
aui_null,	AUE_SHUTDOWN,	aus_shutdown,	/* 236 shutdown */
		auf_null,	0,
aui_null,	AUE_READ,	aus_null,	/* 237 recv */
		auf_recv,	0,
aui_null,	AUE_RECVFROM,	aus_null,	/* 238 recvfrom */
		auf_recvfrom,	0,
aui_null,	AUE_RECVMSG,	aus_null,	/* 239 recvmsg */
		auf_recvmsg,	0,
aui_null,	AUE_WRITE,	aus_null,	/* 240 send */
		auf_send,	0,
aui_null,	AUE_SENDMSG,	aus_null,	/* 241 sendmsg */
		auf_sendmsg,	0,
aui_null,	AUE_SENDTO,	aus_null,	/* 242 sendto */
		auf_sendto,	0,
aui_null,	AUE_NULL,	aus_null,	/* 243 getpeername */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 244 getsockname */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 245 getsockopt */
		auf_null,	0,
aui_null,	AUE_SETSOCKOPT,	aus_null,	/* 246 setsockopt */
		auf_setsockopt,	0,
aui_null,	AUE_SOCKCONFIG,	aus_sockconfig,	/* 247 sockconfig */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 248 ntp_gettime */
		auf_null,	0,
aui_null,	AUE_NTP_ADJTIME, aus_null,	/* 249 ntp_adjtime */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 250 lwp_mutex_unlock */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 251 lwp_mutex_trylock */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 252 lwp_mutex_register */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 253 cladm */
		auf_null,	0,
aui_null,	AUE_NULL,	aus_null,	/* 254 uucopy */
		auf_null,	0,
aui_null,	AUE_UMOUNT2,	aus_umount2,	/* 255 umount2 */
		auf_null,	0
};

uint_t num_syscall = sizeof (audit_s2e) / sizeof (struct audit_s2e);


/* exit start function */
/*ARGSUSED*/
static void
aus_exit(struct t_audit_data *tad)
{
	uint32_t rval;
	struct a {
		long rval;
	} *uap = (struct a *)ttolwp(curthread)->lwp_ap;

	rval = (uint32_t)uap->rval;
	au_uwrite(au_to_arg32(1, "exit status", rval));
}


/* acct start function */
/*ARGSUSED*/
static void
aus_acct(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uintptr_t fname;

	struct a {
		long	fname;		/* char * */
	} *uap = (struct a *)clwp->lwp_ap;

	fname = (uintptr_t)uap->fname;

	if (fname == 0)
		au_uwrite(au_to_arg32(1, "accounting off", (uint32_t)0));
}

/* chown start function */
/*ARGSUSED*/
static void
aus_chown(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t uid, gid;

	struct a {
		long	fname;		/* char * */
		long	uid;
		long	gid;
	} *uap = (struct a *)clwp->lwp_ap;

	uid = (uint32_t)uap->uid;
	gid = (uint32_t)uap->gid;

	au_uwrite(au_to_arg32(2, "new file uid", uid));
	au_uwrite(au_to_arg32(3, "new file gid", gid));
}

/* fchown start function */
/*ARGSUSED*/
static void
aus_fchown(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t uid, gid, fd;
	struct file  *fp;
	struct vnode *vp;
	struct f_audit_data *fad;

	struct a {
		long fd;
		long uid;
		long gid;
	} *uap = (struct a *)clwp->lwp_ap;

	fd  = (uint32_t)uap->fd;
	uid = (uint32_t)uap->uid;
	gid = (uint32_t)uap->gid;

	au_uwrite(au_to_arg32(2, "new file uid", uid));
	au_uwrite(au_to_arg32(3, "new file gid", gid));

		/*
		 * convert file pointer to file descriptor
		 *   Note: fd ref count incremented here.
		 */
	if ((fp = getf(fd)) == NULL)
		return;

	/* get path from file struct here */
	fad = F2A(fp);
	if (fad->fad_aupath != NULL) {
		au_uwrite(au_to_path(fad->fad_aupath));
	} else {
		au_uwrite(au_to_arg32(1, "no path: fd", fd));
	}

	vp = fp->f_vnode;
	audit_attributes(vp);

	/* decrement file descriptor reference count */
	releasef(fd);
}

/*ARGSUSED*/
static void
aus_lchown(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t uid, gid;


	struct a {
		long	fname;		/* char	* */
		long	uid;
		long	gid;
	} *uap = (struct a *)clwp->lwp_ap;

	uid = (uint32_t)uap->uid;
	gid = (uint32_t)uap->gid;

	au_uwrite(au_to_arg32(2, "new file uid", uid));
	au_uwrite(au_to_arg32(3, "new file gid", gid));
}

static au_event_t
aui_fchownat(au_event_t e)
{
	klwp_t *clwp = ttolwp(curthread);

	struct a {
		long	fd;
		long	fname;		/* char * */
		long	uid;
		long	gid;
		long	flags;
	} *uap = (struct a *)clwp->lwp_ap;

	if (uap->fname == NULL)
		e = AUE_FCHOWN;
	else if (uap->flags & AT_SYMLINK_NOFOLLOW)
		e = AUE_LCHOWN;
	else
		e = AUE_CHOWN;

	return (e);
}

/*ARGSUSED*/
static void
aus_fchownat(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t uid, gid;

	struct a {
		long	fd;
		long	fname;		/* char * */
		long	uid;
		long	gid;
		long	flags;
	} *uap = (struct a *)clwp->lwp_ap;

	uid = (uint32_t)uap->uid;
	gid = (uint32_t)uap->gid;

	au_uwrite(au_to_arg32(3, "new file uid", uid));
	au_uwrite(au_to_arg32(4, "new file gid", gid));
}

/*ARGSUSED*/
static void
aus_chmod(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t fmode;

	struct a {
		long	fname;		/* char	* */
		long	fmode;
	} *uap = (struct a *)clwp->lwp_ap;

	fmode = (uint32_t)uap->fmode;

	au_uwrite(au_to_arg32(2, "new file mode", fmode&07777));
}

/*ARGSUSED*/
static void
aus_fchmod(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t fmode, fd;
	struct file  *fp;
	struct vnode *vp;
	struct f_audit_data *fad;

	struct a {
		long	fd;
		long	fmode;
	} *uap = (struct a *)clwp->lwp_ap;

	fd = (uint32_t)uap->fd;
	fmode = (uint32_t)uap->fmode;

	au_uwrite(au_to_arg32(2, "new file mode", fmode&07777));

	/*
	 * convert file pointer to file descriptor
	 *   Note: fd ref count incremented here.
	 */
	if ((fp = getf(fd)) == NULL)
		return;

	/* get path from file struct here */
	fad = F2A(fp);
	if (fad->fad_aupath != NULL) {
		au_uwrite(au_to_path(fad->fad_aupath));
	} else {
		au_uwrite(au_to_arg32(1, "no path: fd", fd));
	}

	vp = fp->f_vnode;
	audit_attributes(vp);

	/* decrement file descriptor reference count */
	releasef(fd);
}

static au_event_t
aui_fchmodat(au_event_t e)
{
	klwp_t *clwp = ttolwp(curthread);

	struct a {
		long	fd;
		long	fname;		/* char	* */
		long	fmode;
		long	flag;
	} *uap = (struct a *)clwp->lwp_ap;

	if (uap->fname == NULL)
		e = AUE_FCHMOD;
	else
		e = AUE_CHMOD;

	return (e);
}

/*ARGSUSED*/
static void
aus_fchmodat(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t fmode;
	uint32_t fd;
	struct file  *fp;
	struct vnode *vp;
	struct f_audit_data *fad;

	struct a {
		long	fd;
		long	fname;		/* char	* */
		long	fmode;
		long	flag;
	} *uap = (struct a *)clwp->lwp_ap;

	fd = (uint32_t)uap->fd;
	fmode = (uint32_t)uap->fmode;

	au_uwrite(au_to_arg32(2, "new file mode", fmode&07777));

	if (fd == AT_FDCWD || uap->fname != NULL)	/* same as chmod() */
		return;

	/*
	 * convert file pointer to file descriptor
	 *   Note: fd ref count incremented here.
	 */
	if ((fp = getf(fd)) == NULL)
		return;

	/* get path from file struct here */
	fad = F2A(fp);
	if (fad->fad_aupath != NULL) {
		au_uwrite(au_to_path(fad->fad_aupath));
	} else {
		au_uwrite(au_to_arg32(1, "no path: fd", fd));
	}

	vp = fp->f_vnode;
	audit_attributes(vp);

	/* decrement file descriptor reference count */
	releasef(fd);
}

/*
 * convert open mode to appropriate open event
 */
au_event_t
open_event(uint_t fm)
{
	au_event_t e;

	switch (fm & (O_ACCMODE | O_CREAT | O_TRUNC)) {
	case O_RDONLY:
		e = AUE_OPEN_R;
		break;
	case O_RDONLY | O_CREAT:
		e = AUE_OPEN_RC;
		break;
	case O_RDONLY | O_TRUNC:
		e = AUE_OPEN_RT;
		break;
	case O_RDONLY | O_TRUNC | O_CREAT:
		e = AUE_OPEN_RTC;
		break;
	case O_WRONLY:
		e = AUE_OPEN_W;
		break;
	case O_WRONLY | O_CREAT:
		e = AUE_OPEN_WC;
		break;
	case O_WRONLY | O_TRUNC:
		e = AUE_OPEN_WT;
		break;
	case O_WRONLY | O_TRUNC | O_CREAT:
		e = AUE_OPEN_WTC;
		break;
	case O_RDWR:
		e = AUE_OPEN_RW;
		break;
	case O_RDWR | O_CREAT:
		e = AUE_OPEN_RWC;
		break;
	case O_RDWR | O_TRUNC:
		e = AUE_OPEN_RWT;
		break;
	case O_RDWR | O_TRUNC | O_CREAT:
		e = AUE_OPEN_RWTC;
		break;
	case O_SEARCH:
		e = AUE_OPEN_S;
		break;
	case O_EXEC:
		e = AUE_OPEN_E;
		break;
	default:
		e = AUE_NULL;
		break;
	}

	return (e);
}

/* ARGSUSED */
static au_event_t
aui_open(au_event_t e)
{
	klwp_t *clwp = ttolwp(curthread);
	uint_t fm;

	struct a {
		long	fnamep;		/* char	* */
		long	fmode;
		long	cmode;
	} *uap = (struct a *)clwp->lwp_ap;

	fm = (uint_t)uap->fmode;

	return (open_event(fm));
}

static void
aus_open(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint_t fm;

	struct a {
		long	fnamep;		/* char	* */
		long	fmode;
		long	cmode;
	} *uap = (struct a *)clwp->lwp_ap;

	fm = (uint_t)uap->fmode;

	/* If no write, create, or trunc modes, mark as a public op */
	if ((fm & (O_RDONLY|O_WRONLY|O_RDWR|O_CREAT|O_TRUNC)) == O_RDONLY)
		tad->tad_ctrl |= TAD_PUBLIC_EV;
}

/* ARGSUSED */
static au_event_t
aui_openat(au_event_t e)
{
	t_audit_data_t *tad = T2A(curthread);
	klwp_t *clwp = ttolwp(curthread);
	uint_t fm;

	struct a {
		long	filedes;
		long	fnamep;		/* char	* */
		long	fmode;
		long	cmode;
	} *uap = (struct a *)clwp->lwp_ap;

	fm = (uint_t)uap->fmode;

	/*
	 * __openattrdirat() does an extra pathname lookup in order to
	 * enter the extended system attribute namespace of the referenced
	 * extended attribute filename.
	 */
	if (fm & FXATTRDIROPEN)
		tad->tad_ctrl |= TAD_MLD;

	return (open_event(fm));
}

static void
aus_openat(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint_t fm;

	struct a {
		long	filedes;
		long	fnamep;		/* char	* */
		long	fmode;
		long	cmode;
	} *uap = (struct a *)clwp->lwp_ap;

	fm = (uint_t)uap->fmode;

	/* If no write, create, or trunc modes, mark as a public op */
	if ((fm & (O_RDONLY|O_WRONLY|O_RDWR|O_CREAT|O_TRUNC)) == O_RDONLY)
		tad->tad_ctrl |= TAD_PUBLIC_EV;
}

static au_event_t
aui_unlinkat(au_event_t e)
{
	klwp_t *clwp = ttolwp(curthread);

	struct a {
		long	filedes;
		long	fnamep;		/* char	* */
		long	flags;
	} *uap = (struct a *)clwp->lwp_ap;

	if (uap->flags & AT_REMOVEDIR)
		e = AUE_RMDIR;
	else
		e = AUE_UNLINK;

	return (e);
}

static au_event_t
aui_fstatat(au_event_t e)
{
	klwp_t *clwp = ttolwp(curthread);

	struct a {
		long	filedes;
		long	fnamep;		/* char	* */
		long	statb;
		long	flags;
	} *uap = (struct a *)clwp->lwp_ap;

	if (uap->fnamep == NULL)
		e = AUE_FSTAT;
	else if (uap->flags & AT_SYMLINK_NOFOLLOW)
		e = AUE_LSTAT;
	else
		e = AUE_STAT;

	return (e);
}

/* msgsys */
static au_event_t
aui_msgsys(au_event_t e)
{
	klwp_t *clwp = ttolwp(curthread);
	uint_t fm;

	struct a {
		long	id;	/* function code id */
		long	ap;	/* arg pointer for recvmsg */
	} *uap = (struct a *)clwp->lwp_ap;

	struct b {
		long	msgid;
		long	cmd;
		long	buf;	/* struct msqid_ds * */
	} *uap1 = (struct b *)&clwp->lwp_ap[1];

	fm  = (uint_t)uap->id;

	switch (fm) {
	case 0:		/* msgget */
		e = AUE_MSGGET;
		break;
	case 1:		/* msgctl */
		switch ((uint_t)uap1->cmd) {
		case IPC_RMID:
			e = AUE_MSGCTL_RMID;
			break;
		case IPC_SET:
			e = AUE_MSGCTL_SET;
			break;
		case IPC_STAT:
			e = AUE_MSGCTL_STAT;
			break;
		default:
			e = AUE_MSGCTL;
			break;
		}
		break;
	case 2:		/* msgrcv */
		e = AUE_MSGRCV;
		break;
	case 3:		/* msgsnd */
		e = AUE_MSGSND;
		break;
	default:	/* illegal system call */
		e = AUE_NULL;
		break;
	}

	return (e);
}


/* shmsys */
static au_event_t
aui_shmsys(au_event_t e)
{
	klwp_t *clwp = ttolwp(curthread);
	int fm;

	struct a {		/* shmsys */
		long	id;	/* function code id */
	} *uap = (struct a *)clwp->lwp_ap;

	struct b {		/* ctrl */
		long	shmid;
		long	cmd;
		long	arg;		/* struct shmid_ds * */
	} *uap1 = (struct b *)&clwp->lwp_ap[1];
	fm  = (uint_t)uap->id;

	switch (fm) {
	case 0:		/* shmat */
		e = AUE_SHMAT;
		break;
	case 1:		/* shmctl */
		switch ((uint_t)uap1->cmd) {
		case IPC_RMID:
			e = AUE_SHMCTL_RMID;
			break;
		case IPC_SET:
			e = AUE_SHMCTL_SET;
			break;
		case IPC_STAT:
			e = AUE_SHMCTL_STAT;
			break;
		default:
			e = AUE_SHMCTL;
			break;
		}
		break;
	case 2:		/* shmdt */
		e = AUE_SHMDT;
		break;
	case 3:		/* shmget */
		e = AUE_SHMGET;
		break;
	default:	/* illegal system call */
		e = AUE_NULL;
		break;
	}

	return (e);
}


/* semsys */
static au_event_t
aui_semsys(au_event_t e)
{
	klwp_t *clwp = ttolwp(curthread);
	uint_t fm;

	struct a {		/* semsys */
		long	id;
	} *uap = (struct a *)clwp->lwp_ap;

	struct b {		/* ctrl */
		long	semid;
		long	semnum;
		long	cmd;
		long	arg;
	} *uap1 = (struct b *)&clwp->lwp_ap[1];

	fm = (uint_t)uap->id;

	switch (fm) {
	case 0:		/* semctl */
		switch ((uint_t)uap1->cmd) {
		case IPC_RMID:
			e = AUE_SEMCTL_RMID;
			break;
		case IPC_SET:
			e = AUE_SEMCTL_SET;
			break;
		case IPC_STAT:
			e = AUE_SEMCTL_STAT;
			break;
		case GETNCNT:
			e = AUE_SEMCTL_GETNCNT;
			break;
		case GETPID:
			e = AUE_SEMCTL_GETPID;
			break;
		case GETVAL:
			e = AUE_SEMCTL_GETVAL;
			break;
		case GETALL:
			e = AUE_SEMCTL_GETALL;
			break;
		case GETZCNT:
			e = AUE_SEMCTL_GETZCNT;
			break;
		case SETVAL:
			e = AUE_SEMCTL_SETVAL;
			break;
		case SETALL:
			e = AUE_SEMCTL_SETALL;
			break;
		default:
			e = AUE_SEMCTL;
			break;
		}
		break;
	case 1:		/* semget */
		e = AUE_SEMGET;
		break;
	case 2:		/* semop */
		e = AUE_SEMOP;
		break;
	default:	/* illegal system call */
		e = AUE_NULL;
		break;
	}

	return (e);
}

/* utssys - uname(2), ustat(2), fusers(2) */
static au_event_t
aui_utssys(au_event_t e)
{
	klwp_t *clwp = ttolwp(curthread);
	uint_t type;

	struct a {
		union {
			long	cbuf;		/* char * */
			long	ubuf;		/* struct stat * */
		} ub;
		union {
			long	mv;	/* for USTAT */
			long	flags;	/* for FUSERS */
		} un;
		long	type;
		long	outbp;		/* char * for FUSERS */
	} *uap = (struct a *)clwp->lwp_ap;

	type = (uint_t)uap->type;

	if (type == UTS_FUSERS)
		return (e);
	else
		return ((au_event_t)AUE_NULL);
}

static au_event_t
aui_fcntl(au_event_t e)
{
	klwp_t *clwp = ttolwp(curthread);
	uint_t cmd;

	struct a {
		long	fdes;
		long	cmd;
		long	arg;
	} *uap = (struct a *)clwp->lwp_ap;

	cmd = (uint_t)uap->cmd;

	switch (cmd) {
	case F_GETLK:
	case F_SETLK:
	case F_SETLKW:
		break;
	case F_SETFL:
	case F_GETFL:
	case F_GETFD:
		break;
	default:
		e = (au_event_t)AUE_NULL;
		break;
	}
	return ((au_event_t)e);
}

/* null function for now */
static au_event_t
aui_execve(au_event_t e)
{
	return (e);
}

/*ARGSUSED*/
static void
aus_fcntl(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t cmd, fd, flags;
	struct file  *fp;
	struct vnode *vp;
	struct f_audit_data *fad;

	struct a {
		long	fd;
		long	cmd;
		long	arg;
	} *uap = (struct a *)clwp->lwp_ap;

	cmd	= (uint32_t)uap->cmd;
	fd	= (uint32_t)uap->fd;
	flags	= (uint32_t)uap->arg;

	au_uwrite(au_to_arg32(2, "cmd", cmd));

	if (cmd == F_SETFL)
		au_uwrite(au_to_arg32(3, "flags", flags));

		/*
		 * convert file pointer to file descriptor
		 *   Note: fd ref count incremented here.
		 */
	if ((fp = getf(fd)) == NULL)
		return;

	/* get path from file struct here */
	fad = F2A(fp);
	if (fad->fad_aupath != NULL) {
		au_uwrite(au_to_path(fad->fad_aupath));
	} else {
		au_uwrite(au_to_arg32(1, "no path: fd", fd));
	}

	vp = fp->f_vnode;
	audit_attributes(vp);

	/* decrement file descriptor reference count */
	releasef(fd);
}

/*ARGSUSED*/
static void
aus_kill(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	struct proc *p;
	uint32_t signo;
	uid_t uid, ruid;
	gid_t gid, rgid;
	pid_t pid;
	const auditinfo_addr_t *ainfo;
	cred_t *cr;

	struct a {
		long	pid;
		long	signo;
	} *uap = (struct a *)clwp->lwp_ap;

	pid   = (pid_t)uap->pid;
	signo = (uint32_t)uap->signo;

	au_uwrite(au_to_arg32(2, "signal", signo));
	if (pid > 0) {
		mutex_enter(&pidlock);
		if (((p = prfind(pid)) == (struct proc *)0) ||
		    (p->p_stat == SIDL)) {
			mutex_exit(&pidlock);
			au_uwrite(au_to_arg32(1, "process", (uint32_t)pid));
			return;
		}
		mutex_enter(&p->p_lock); /* so process doesn't go away */
		mutex_exit(&pidlock);

		mutex_enter(&p->p_crlock);
		crhold(cr = p->p_cred);
		mutex_exit(&p->p_crlock);
		mutex_exit(&p->p_lock);

		ainfo = crgetauinfo(cr);
		if (ainfo == NULL) {
			crfree(cr);
			au_uwrite(au_to_arg32(1, "process", (uint32_t)pid));
			return;
		}

		uid  = crgetuid(cr);
		gid  = crgetgid(cr);
		ruid = crgetruid(cr);
		rgid = crgetrgid(cr);
		au_uwrite(au_to_process(uid, gid, ruid, rgid, pid,
		    ainfo->ai_auid, ainfo->ai_asid, &ainfo->ai_termid));

		if (is_system_labeled())
			au_uwrite(au_to_label(CR_SL(cr)));

		crfree(cr);
	}
	else
		au_uwrite(au_to_arg32(1, "process", (uint32_t)pid));
}

/*ARGSUSED*/
static void
aus_mkdir(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t dmode;

	struct a {
		long	dirnamep;		/* char * */
		long	dmode;
	} *uap = (struct a *)clwp->lwp_ap;

	dmode = (uint32_t)uap->dmode;

	au_uwrite(au_to_arg32(2, "mode", dmode));
}

/*ARGSUSED*/
static void
aus_mkdirat(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t dmode;

	struct a {
		long	fd;
		long	dirnamep;		/* char * */
		long	dmode;
	} *uap = (struct a *)clwp->lwp_ap;

	dmode = (uint32_t)uap->dmode;

	au_uwrite(au_to_arg32(2, "mode", dmode));
}

/*ARGSUSED*/
static void
aus_mknod(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t fmode;
	dev_t dev;

	struct a {
		long	pnamep;		/* char * */
		long	fmode;
		long	dev;
	} *uap = (struct a *)clwp->lwp_ap;

	fmode = (uint32_t)uap->fmode;
	dev   = (dev_t)uap->dev;

	au_uwrite(au_to_arg32(2, "mode", fmode));
#ifdef _LP64
	au_uwrite(au_to_arg64(3, "dev", dev));
#else
	au_uwrite(au_to_arg32(3, "dev", dev));
#endif
}

/*ARGSUSED*/
static void
auf_mknod(struct t_audit_data *tad, int error, rval_t *rval)
{
	klwp_t *clwp = ttolwp(curthread);
	vnode_t	*dvp;
	caddr_t pnamep;

	struct a {
		long	pnamep;		/* char * */
		long	fmode;
		long	dev;
	} *uap = (struct a *)clwp->lwp_ap;

	/* no error, then already path token in audit record */
	if (error != EPERM && error != EINVAL)
		return;

	/* do the lookup to force generation of path token */
	pnamep = (caddr_t)uap->pnamep;
	tad->tad_ctrl |= TAD_NOATTRB;
	error = lookupname(pnamep, UIO_USERSPACE, NO_FOLLOW, &dvp, NULLVPP);
	if (error == 0)
		VN_RELE(dvp);
}

/*ARGSUSED*/
static void
aus_mknodat(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t fmode;
	dev_t dev;

	struct a {
		long	fd;
		long	pnamep;		/* char * */
		long	fmode;
		long	dev;
	} *uap = (struct a *)clwp->lwp_ap;

	fmode = (uint32_t)uap->fmode;
	dev   = (dev_t)uap->dev;

	au_uwrite(au_to_arg32(2, "mode", fmode));
#ifdef _LP64
	au_uwrite(au_to_arg64(3, "dev", dev));
#else
	au_uwrite(au_to_arg32(3, "dev", dev));
#endif
}

/*ARGSUSED*/
static void
auf_mknodat(struct t_audit_data *tad, int error, rval_t *rval)
{
	klwp_t *clwp = ttolwp(curthread);
	vnode_t	*startvp;
	vnode_t	*dvp;
	caddr_t pnamep;
	int fd;

	struct a {
		long	fd;
		long	pnamep;		/* char * */
		long	fmode;
		long	dev;
	} *uap = (struct a *)clwp->lwp_ap;

	/* no error, then already path token in audit record */
	if (error != EPERM && error != EINVAL)
		return;

	/* do the lookup to force generation of path token */
	fd = (int)uap->fd;
	pnamep = (caddr_t)uap->pnamep;
	if (pnamep == NULL ||
	    fgetstartvp(fd, pnamep, &startvp) != 0)
		return;
	tad->tad_ctrl |= TAD_NOATTRB;
	error = lookupnameat(pnamep, UIO_USERSPACE, NO_FOLLOW, &dvp, NULLVPP,
	    startvp);
	if (error == 0)
		VN_RELE(dvp);
	if (startvp != NULL)
		VN_RELE(startvp);
}

/*ARGSUSED*/
static void
aus_mount(struct t_audit_data *tad)
{	/* AUS_START */
	klwp_t *clwp = ttolwp(curthread);
	uint32_t flags;
	uintptr_t u_fstype, dataptr;
	STRUCT_DECL(nfs_args, nfsargs);
	size_t len;
	char *fstype, *hostname;

	struct a {
		long	spec;		/* char    * */
		long	dir;		/* char    * */
		long	flags;
		long	fstype;		/* char    * */
		long	dataptr;	/* char    * */
		long	datalen;
	} *uap = (struct a *)clwp->lwp_ap;

	u_fstype = (uintptr_t)uap->fstype;
	flags    = (uint32_t)uap->flags;
	dataptr  = (uintptr_t)uap->dataptr;

	fstype = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	if (copyinstr((caddr_t)u_fstype, (caddr_t)fstype, MAXNAMELEN, &len))
		goto mount_free_fstype;

	au_uwrite(au_to_arg32(3, "flags", flags));
	au_uwrite(au_to_text(fstype));

	if (strncmp(fstype, "nfs", 3) == 0) {

		STRUCT_INIT(nfsargs, get_udatamodel());
		bzero(STRUCT_BUF(nfsargs), STRUCT_SIZE(nfsargs));

		if (copyin((caddr_t)dataptr,
				STRUCT_BUF(nfsargs),
				MIN(uap->datalen, STRUCT_SIZE(nfsargs)))) {
			/* DEBUG debug_enter((char *)NULL); */
			goto mount_free_fstype;
		}
		hostname = kmem_alloc(MAXNAMELEN, KM_SLEEP);
		if (copyinstr(STRUCT_FGETP(nfsargs, hostname),
				(caddr_t)hostname,
				MAXNAMELEN, &len)) {
			goto mount_free_hostname;
		}
		au_uwrite(au_to_text(hostname));
		au_uwrite(au_to_arg32(3, "internal flags",
			(uint_t)STRUCT_FGET(nfsargs, flags)));

mount_free_hostname:
		kmem_free(hostname, MAXNAMELEN);
	}

mount_free_fstype:
	kmem_free(fstype, MAXNAMELEN);
}	/* AUS_MOUNT */

static void
aus_umount_path(caddr_t umount_dir)
{
	char			*dir_path;
	struct audit_path	*path;
	size_t			path_len, dir_len;

	/* length alloc'd for two string pointers */
	path_len = sizeof (struct audit_path) + sizeof (char *);
	path = kmem_alloc(path_len, KM_SLEEP);
	dir_path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

	if (copyinstr(umount_dir, (caddr_t)dir_path,
	    MAXPATHLEN, &dir_len))
		goto umount2_free_dir;

	/*
	 * the audit_path struct assumes that the buffer pointed to
	 * by audp_sect[n] contains string 0 immediatedly followed
	 * by string 1.
	 */
	path->audp_sect[0] = dir_path;
	path->audp_sect[1] = dir_path + strlen(dir_path) + 1;
	path->audp_size = path_len;
	path->audp_ref = 1;		/* not used */
	path->audp_cnt = 1;		/* one path string */

	au_uwrite(au_to_path(path));

umount2_free_dir:
	kmem_free(dir_path, MAXPATHLEN);
	kmem_free(path, path_len);
}

/*ARGSUSED*/
static void
aus_umount2(struct t_audit_data *tad)
{
	klwp_t			*clwp = ttolwp(curthread);
	struct a {
		long	dir;		/* char    * */
		long	flags;
	} *uap = (struct a *)clwp->lwp_ap;

	aus_umount_path((caddr_t)uap->dir);

	au_uwrite(au_to_arg32(2, "flags", (uint32_t)uap->flags));
}

static void
aus_msgsys(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t msgid;

	struct b {
		long	msgid;
		long	cmd;
		long	buf;		/* struct msqid_ds * */
	} *uap1 = (struct b *)&clwp->lwp_ap[1];

	msgid = (uint32_t)uap1->msgid;


	switch (tad->tad_event) {
	case AUE_MSGGET:		/* msgget */
		au_uwrite(au_to_arg32(1, "msg key", msgid));
		break;
	case AUE_MSGCTL:		/* msgctl */
	case AUE_MSGCTL_RMID:		/* msgctl */
	case AUE_MSGCTL_SET:		/* msgctl */
	case AUE_MSGCTL_STAT:		/* msgctl */
	case AUE_MSGRCV:		/* msgrcv */
	case AUE_MSGSND:		/* msgsnd */
		au_uwrite(au_to_arg32(1, "msg ID", msgid));
		break;
	}
}

/*ARGSUSED*/
static void
auf_msgsys(struct t_audit_data *tad, int error, rval_t *rval)
{
	int id;

	if (error != 0)
		return;
	if (tad->tad_event == AUE_MSGGET) {
		uint32_t scid;
		uint32_t sy_flags;

		/* need to determine type of executing binary */
		scid = tad->tad_scid;
#ifdef _SYSCALL32_IMPL
		if (lwp_getdatamodel(ttolwp(curthread)) == DATAMODEL_NATIVE)
			sy_flags = sysent[scid].sy_flags & SE_RVAL_MASK;
		else
			sy_flags = sysent32[scid].sy_flags & SE_RVAL_MASK;
#else
		sy_flags = sysent[scid].sy_flags & SE_RVAL_MASK;
#endif
		if (sy_flags == SE_32RVAL1)
			id = rval->r_val1;
		if (sy_flags == (SE_32RVAL2|SE_32RVAL1))
			id = rval->r_val1;
		if (sy_flags == SE_64RVAL)
			id = (int)rval->r_vals;

		au_uwrite(au_to_ipc(AT_IPC_MSG, id));
	}
}

static void
aus_semsys(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t semid;

	struct b {		/* ctrl */
		long	semid;
		long	semnum;
		long	cmd;
		long	arg;
	} *uap1 = (struct b *)&clwp->lwp_ap[1];

	semid = (uint32_t)uap1->semid;

	switch (tad->tad_event) {
	case AUE_SEMCTL_RMID:
	case AUE_SEMCTL_STAT:
	case AUE_SEMCTL_GETNCNT:
	case AUE_SEMCTL_GETPID:
	case AUE_SEMCTL_GETVAL:
	case AUE_SEMCTL_GETALL:
	case AUE_SEMCTL_GETZCNT:
	case AUE_SEMCTL_SET:
	case AUE_SEMCTL_SETVAL:
	case AUE_SEMCTL_SETALL:
	case AUE_SEMCTL:
	case AUE_SEMOP:
		au_uwrite(au_to_arg32(1, "sem ID", semid));
		break;
	case AUE_SEMGET:
		au_uwrite(au_to_arg32(1, "sem key", semid));
		break;
	}
}

/*ARGSUSED*/
static void
auf_semsys(struct t_audit_data *tad, int error, rval_t *rval)
{
	int id;

	if (error != 0)
		return;
	if (tad->tad_event == AUE_SEMGET) {
		uint32_t scid;
		uint32_t sy_flags;

		/* need to determine type of executing binary */
		scid = tad->tad_scid;
#ifdef _SYSCALL32_IMPL
		if (lwp_getdatamodel(ttolwp(curthread)) == DATAMODEL_NATIVE)
			sy_flags = sysent[scid].sy_flags & SE_RVAL_MASK;
		else
			sy_flags = sysent32[scid].sy_flags & SE_RVAL_MASK;
#else
		sy_flags = sysent[scid].sy_flags & SE_RVAL_MASK;
#endif
		if (sy_flags == SE_32RVAL1)
			id = rval->r_val1;
		if (sy_flags == (SE_32RVAL2|SE_32RVAL1))
			id = rval->r_val1;
		if (sy_flags == SE_64RVAL)
			id = (int)rval->r_vals;

		au_uwrite(au_to_ipc(AT_IPC_SEM, id));
	}
}

/*ARGSUSED*/
static void
aus_close(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t fd;
	struct file *fp;
	struct f_audit_data *fad;
	struct vnode *vp;
	struct vattr attr;
	au_kcontext_t	*kctx = GET_KCTX_PZ;

	struct a {
		long	i;
	} *uap = (struct a *)clwp->lwp_ap;

	fd = (uint32_t)uap->i;

	attr.va_mask = 0;
	au_uwrite(au_to_arg32(1, "fd", fd));

		/*
		 * convert file pointer to file descriptor
		 *   Note: fd ref count incremented here.
		 */
	if ((fp = getf(fd)) == NULL)
		return;

	fad = F2A(fp);
	tad->tad_evmod = (au_emod_t)fad->fad_flags;
	if (fad->fad_aupath != NULL) {
		au_uwrite(au_to_path(fad->fad_aupath));
		if ((vp = fp->f_vnode) != NULL) {
			attr.va_mask = AT_ALL;
			if (VOP_GETATTR(vp, &attr, 0, CRED(), NULL) == 0) {
				/*
				 * When write was not used and the file can be
				 * considered public, skip the audit.
				 */
				if (((fp->f_flag & FWRITE) == 0) &&
				    object_is_public(&attr)) {
					tad->tad_flag = 0;
					tad->tad_evmod = 0;
					/* free any residual audit data */
					au_close(kctx, &(u_ad), 0, 0, 0, NULL);
					releasef(fd);
					return;
				}
				au_uwrite(au_to_attr(&attr));
				audit_sec_attributes(&(u_ad), vp);
			}
		}
	}

	/* decrement file descriptor reference count */
	releasef(fd);
}

/*ARGSUSED*/
static void
aus_fstatfs(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t fd;
	struct file  *fp;
	struct vnode *vp;
	struct f_audit_data *fad;

	struct a {
		long	fd;
		long	buf;		/* struct statfs * */
	} *uap = (struct a *)clwp->lwp_ap;

	fd = (uint_t)uap->fd;

		/*
		 * convert file pointer to file descriptor
		 *   Note: fd ref count incremented here.
		 */
	if ((fp = getf(fd)) == NULL)
		return;

		/* get path from file struct here */
	fad = F2A(fp);
	if (fad->fad_aupath != NULL) {
		au_uwrite(au_to_path(fad->fad_aupath));
	} else {
		au_uwrite(au_to_arg32(1, "no path: fd", fd));
	}

	vp = fp->f_vnode;
	audit_attributes(vp);

	/* decrement file descriptor reference count */
	releasef(fd);
}

static au_event_t
aui_setpgrp(au_event_t e)
{
	klwp_t *clwp = ttolwp(curthread);
	int flag;

	struct a {
		long	flag;
		long	pid;
		long	pgid;
	} *uap = (struct a *)clwp->lwp_ap;

	flag = (int)uap->flag;


	switch (flag) {

	case 1:	/* setpgrp() */
		e = AUE_SETPGRP;
		break;

	case 3: /* setsid() */
		e = AUE_SETSID;
		break;

	case 5: /* setpgid() */
		e = AUE_SETPGID;
		break;

	case 0: /* getpgrp()	- not security relevant */
	case 2: /* getsid()	- not security relevant */
	case 4: /* getpgid() 	- not security relevant */
		e = AUE_NULL;
		break;

	default:
		e = AUE_NULL;
		break;
	}

	return (e);
}

/*ARGSUSED*/
static void
aus_setpgrp(struct t_audit_data *tad)
{
	klwp_t		*clwp = ttolwp(curthread);
	pid_t		pgid;
	struct proc	*p;
	uid_t		uid, ruid;
	gid_t		gid, rgid;
	pid_t		pid;
	cred_t		*cr;
	int		flag;
	const auditinfo_addr_t	*ainfo;

	struct a {
		long	flag;
		long	pid;
		long	pgid;
	} *uap = (struct a *)clwp->lwp_ap;

	flag = (int)uap->flag;
	pid  = (pid_t)uap->pid;
	pgid = (pid_t)uap->pgid;


	switch (flag) {

	case 0: /* getpgrp() */
	case 1: /* setpgrp() */
	case 2: /* getsid() */
	case 3: /* setsid() */
	case 4: /* getpgid() */
		break;

	case 5: /* setpgid() */

		/* current process? */
		if (pid == 0) {
			return;
		}

		mutex_enter(&pidlock);
		p = prfind(pid);
		if (p == NULL || p->p_as == &kas ||
		    p->p_stat == SIDL || p->p_stat == SZOMB) {
			mutex_exit(&pidlock);
			return;
		}
		mutex_enter(&p->p_lock);	/* so process doesn't go away */
		mutex_exit(&pidlock);

		mutex_enter(&p->p_crlock);
		crhold(cr = p->p_cred);
		mutex_exit(&p->p_crlock);
		mutex_exit(&p->p_lock);

		ainfo = crgetauinfo(cr);
		if (ainfo == NULL) {
			crfree(cr);
			return;
		}

		uid  = crgetuid(cr);
		gid  = crgetgid(cr);
		ruid = crgetruid(cr);
		rgid = crgetrgid(cr);
		au_uwrite(au_to_process(uid, gid, ruid, rgid, pid,
		    ainfo->ai_auid, ainfo->ai_asid, &ainfo->ai_termid));
		crfree(cr);
		au_uwrite(au_to_arg32(2, "pgid", pgid));
		break;

	default:
		break;
	}
}


/*ARGSUSED*/
static void
aus_setregid(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t rgid, egid;

	struct a {
		long	 rgid;
		long	 egid;
	} *uap = (struct a *)clwp->lwp_ap;

	rgid  = (uint32_t)uap->rgid;
	egid  = (uint32_t)uap->egid;

	au_uwrite(au_to_arg32(1, "rgid", rgid));
	au_uwrite(au_to_arg32(2, "egid", egid));
}

/*ARGSUSED*/
static void
aus_setgid(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t gid;

	struct a {
		long	gid;
	} *uap = (struct a *)clwp->lwp_ap;

	gid = (uint32_t)uap->gid;

	au_uwrite(au_to_arg32(1, "gid", gid));
}


/*ARGSUSED*/
static void
aus_setreuid(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t ruid, euid;

	struct a {
		long	ruid;
		long	euid;
	} *uap = (struct a *)clwp->lwp_ap;

	ruid = (uint32_t)uap->ruid;
	euid  = (uint32_t)uap->euid;

	au_uwrite(au_to_arg32(1, "ruid", ruid));
	au_uwrite(au_to_arg32(2, "euid", euid));
}


/*ARGSUSED*/
static void
aus_setuid(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t uid;

	struct a {
		long	uid;
	} *uap = (struct a *)clwp->lwp_ap;

	uid = (uint32_t)uap->uid;

	au_uwrite(au_to_arg32(1, "uid", uid));
}

/*ARGSUSED*/
static void
aus_shmsys(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t id, cmd;

	struct b {
		long	id;
		long	cmd;
		long	buf;		/* struct shmid_ds * */
	} *uap1 = (struct b *)&clwp->lwp_ap[1];

	id  = (uint32_t)uap1->id;
	cmd = (uint32_t)uap1->cmd;

	switch (tad->tad_event) {
	case AUE_SHMGET:			/* shmget */
		au_uwrite(au_to_arg32(1, "shm key", id));
		break;
	case AUE_SHMCTL:			/* shmctl */
	case AUE_SHMCTL_RMID:			/* shmctl */
	case AUE_SHMCTL_STAT:			/* shmctl */
	case AUE_SHMCTL_SET:			/* shmctl */
		au_uwrite(au_to_arg32(1, "shm ID", id));
		break;
	case AUE_SHMDT:				/* shmdt */
		au_uwrite(au_to_arg32(1, "shm adr", id));
		break;
	case AUE_SHMAT:				/* shmat */
		au_uwrite(au_to_arg32(1, "shm ID", id));
		au_uwrite(au_to_arg32(2, "shm adr", cmd));
		break;
	}
}

/*ARGSUSED*/
static void
auf_shmsys(struct t_audit_data *tad, int error, rval_t *rval)
{
	int id;

	if (error != 0)
		return;
	if (tad->tad_event == AUE_SHMGET) {
		uint32_t scid;
		uint32_t sy_flags;

		/* need to determine type of executing binary */
		scid = tad->tad_scid;
#ifdef _SYSCALL32_IMPL
		if (lwp_getdatamodel(ttolwp(curthread)) == DATAMODEL_NATIVE)
			sy_flags = sysent[scid].sy_flags & SE_RVAL_MASK;
		else
			sy_flags = sysent32[scid].sy_flags & SE_RVAL_MASK;
#else
		sy_flags = sysent[scid].sy_flags & SE_RVAL_MASK;
#endif
		if (sy_flags == SE_32RVAL1)
			id = rval->r_val1;
		if (sy_flags == (SE_32RVAL2|SE_32RVAL1))
			id = rval->r_val1;
		if (sy_flags == SE_64RVAL)
			id = (int)rval->r_vals;
		au_uwrite(au_to_ipc(AT_IPC_SHM, id));
	}
}


/*ARGSUSED*/
static void
aus_ioctl(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	struct file *fp;
	struct vnode *vp;
	struct f_audit_data *fad;
	uint32_t fd, cmd;
	uintptr_t cmarg;

	/* XX64 */
	struct a {
		long	fd;
		long	cmd;
		long	cmarg;		/* caddr_t */
	} *uap = (struct a *)clwp->lwp_ap;

	fd    = (uint32_t)uap->fd;
	cmd   = (uint32_t)uap->cmd;
	cmarg = (uintptr_t)uap->cmarg;

		/*
		 * convert file pointer to file descriptor
		 *   Note: fd ref count incremented here.
		 */
	if ((fp = getf(fd)) == NULL) {
		au_uwrite(au_to_arg32(1, "fd", fd));
		au_uwrite(au_to_arg32(2, "cmd", cmd));
#ifndef _LP64
			au_uwrite(au_to_arg32(3, "arg", (uint32_t)cmarg));
#else
			au_uwrite(au_to_arg64(3, "arg", (uint64_t)cmarg));
#endif
		return;
	}

	/* get path from file struct here */
	fad = F2A(fp);
	if (fad->fad_aupath != NULL) {
		au_uwrite(au_to_path(fad->fad_aupath));
	} else {
		au_uwrite(au_to_arg32(1, "no path: fd", fd));
	}

	vp = fp->f_vnode;
	audit_attributes(vp);

	/* decrement file descriptor reference count */
	releasef(fd);

	au_uwrite(au_to_arg32(2, "cmd", cmd));
#ifndef _LP64
		au_uwrite(au_to_arg32(3, "arg", (uint32_t)cmarg));
#else
		au_uwrite(au_to_arg64(3, "arg", (uint64_t)cmarg));
#endif
}

/*
 * null function for memcntl for now. We might want to limit memcntl()
 * auditing to commands: MC_LOCKAS, MC_LOCK, MC_UNLOCKAS, MC_UNLOCK which
 * require privileges.
 */
static au_event_t
aui_memcntl(au_event_t e)
{
	return (e);
}

/*ARGSUSED*/
static au_event_t
aui_privsys(au_event_t e)
{
	klwp_t *clwp = ttolwp(curthread);

	struct a {
		long	opcode;
	} *uap = (struct a *)clwp->lwp_ap;

	switch (uap->opcode) {
	case PRIVSYS_SETPPRIV:
		return (AUE_SETPPRIV);
	default:
		return (AUE_NULL);
	}
}

/*ARGSUSED*/
static void
aus_memcntl(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);

	struct a {
		long	addr;
		long	len;
		long	cmd;
		long	arg;
		long	attr;
		long	mask;
	} *uap = (struct a *)clwp->lwp_ap;

#ifdef _LP64
	au_uwrite(au_to_arg64(1, "base", (uint64_t)uap->addr));
	au_uwrite(au_to_arg64(2, "len", (uint64_t)uap->len));
#else
	au_uwrite(au_to_arg32(1, "base", (uint32_t)uap->addr));
	au_uwrite(au_to_arg32(2, "len", (uint32_t)uap->len));
#endif
	au_uwrite(au_to_arg32(3, "cmd", (uint_t)uap->cmd));
#ifdef _LP64
	au_uwrite(au_to_arg64(4, "arg", (uint64_t)uap->arg));
#else
	au_uwrite(au_to_arg32(4, "arg", (uint32_t)uap->arg));
#endif
	au_uwrite(au_to_arg32(5, "attr", (uint_t)uap->attr));
	au_uwrite(au_to_arg32(6, "mask", (uint_t)uap->mask));
}

/*ARGSUSED*/
static void
aus_mmap(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	struct file *fp;
	struct f_audit_data *fad;
	struct vnode *vp;
	uint32_t fd;

	struct a {
		long	addr;
		long	len;
		long	prot;
		long	flags;
		long	fd;
		long	pos;
	} *uap = (struct a *)clwp->lwp_ap;

	fd = (uint32_t)uap->fd;

#ifdef _LP64
	au_uwrite(au_to_arg64(1, "addr", (uint64_t)uap->addr));
	au_uwrite(au_to_arg64(2, "len", (uint64_t)uap->len));
#else
	au_uwrite(au_to_arg32(1, "addr", (uint32_t)uap->addr));
	au_uwrite(au_to_arg32(2, "len", (uint32_t)uap->len));
#endif

	if ((fp = getf(fd)) == NULL) {
		au_uwrite(au_to_arg32(5, "fd", (uint32_t)uap->fd));
		return;
	}

	/*
	 * Mark in the tad if write access is NOT requested... if
	 * this is later detected (in audit_attributes) to be a
	 * public object, the mmap event may be discarded.
	 */
	if (((uap->prot) & PROT_WRITE) == 0) {
		tad->tad_ctrl |= TAD_PUBLIC_EV;
	}

	fad = F2A(fp);
	if (fad->fad_aupath != NULL) {
		au_uwrite(au_to_path(fad->fad_aupath));
	} else {
		au_uwrite(au_to_arg32(1, "no path: fd", fd));
	}

	vp = (struct vnode *)fp->f_vnode;
	audit_attributes(vp);

	/* mark READ/WRITE since we can't predict access */
	if (uap->prot & PROT_READ)
		fad->fad_flags |= FAD_READ;
	if (uap->prot & PROT_WRITE)
		fad->fad_flags |= FAD_WRITE;

	/* decrement file descriptor reference count */
	releasef(fd);

}	/* AUS_MMAP */




/*ARGSUSED*/
static void
aus_munmap(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);

	struct a {
		long	addr;
		long	len;
	} *uap = (struct a *)clwp->lwp_ap;

#ifdef _LP64
	au_uwrite(au_to_arg64(1, "addr", (uint64_t)uap->addr));
	au_uwrite(au_to_arg64(2, "len", (uint64_t)uap->len));
#else
	au_uwrite(au_to_arg32(1, "addr", (uint32_t)uap->addr));
	au_uwrite(au_to_arg32(2, "len", (uint32_t)uap->len));
#endif

}	/* AUS_MUNMAP */







/*ARGSUSED*/
static void
aus_priocntlsys(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);

	struct a {
		long	pc_version;
		long	psp;		/* procset_t */
		long	cmd;
		long	arg;
	} *uap = (struct a *)clwp->lwp_ap;

	au_uwrite(au_to_arg32(1, "pc_version", (uint32_t)uap->pc_version));
	au_uwrite(au_to_arg32(3, "cmd", (uint32_t)uap->cmd));

}	/* AUS_PRIOCNTLSYS */


/*ARGSUSED*/
static void
aus_setegid(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t gid;

	struct a {
		long	gid;
	} *uap = (struct a *)clwp->lwp_ap;

	gid = (uint32_t)uap->gid;

	au_uwrite(au_to_arg32(1, "gid", gid));
}	/* AUS_SETEGID */




/*ARGSUSED*/
static void
aus_setgroups(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	int i;
	int gidsetsize;
	uintptr_t gidset;
	gid_t *gidlist;

	struct a {
		long	gidsetsize;
		long	gidset;
	} *uap = (struct a *)clwp->lwp_ap;

	gidsetsize = (uint_t)uap->gidsetsize;
	gidset = (uintptr_t)uap->gidset;

	if ((gidsetsize > NGROUPS_MAX_DEFAULT) || (gidsetsize < 0))
		return;
	if (gidsetsize != 0) {
		gidlist = kmem_alloc(gidsetsize * sizeof (gid_t),
		    KM_SLEEP);
		if (copyin((caddr_t)gidset, gidlist,
		    gidsetsize * sizeof (gid_t)) == 0)
			for (i = 0; i < gidsetsize; i++)
				au_uwrite(au_to_arg32(1, "setgroups",
				    (uint32_t)gidlist[i]));
		kmem_free(gidlist, gidsetsize * sizeof (gid_t));
	} else
		au_uwrite(au_to_arg32(1, "setgroups", (uint32_t)0));

}	/* AUS_SETGROUPS */





/*ARGSUSED*/
static void
aus_seteuid(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t uid;

	struct a {
		long	uid;
	} *uap = (struct a *)clwp->lwp_ap;

	uid = (uint32_t)uap->uid;

	au_uwrite(au_to_arg32(1, "euid", uid));

}	/* AUS_SETEUID */

/*ARGSUSED*/
static void
aus_putmsg(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t fd, pri;
	struct file *fp;
	struct f_audit_data *fad;

	struct a {
		long	fdes;
		long	ctl;		/* struct strbuf * */
		long	data;		/* struct strbuf * */
		long	pri;
	} *uap = (struct a *)clwp->lwp_ap;

	fd  = (uint32_t)uap->fdes;
	pri = (uint32_t)uap->pri;

	au_uwrite(au_to_arg32(1, "fd", fd));

	if ((fp = getf(fd)) != NULL) {
		fad = F2A(fp);

		fad->fad_flags |= FAD_WRITE;

		/* add path name to audit record */
		if (fad->fad_aupath != NULL) {
			au_uwrite(au_to_path(fad->fad_aupath));
		}
		audit_attributes(fp->f_vnode);

		releasef(fd);
	}

	au_uwrite(au_to_arg32(4, "pri", pri));
}

/*ARGSUSED*/
static void
aus_putpmsg(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t fd, pri, flags;
	struct file *fp;
	struct f_audit_data *fad;

	struct a {
		long	fdes;
		long	ctl;		/* struct strbuf * */
		long	data;		/* struct strbuf * */
		long	pri;
		long	flags;
	} *uap = (struct a *)clwp->lwp_ap;

	fd = (uint32_t)uap->fdes;
	pri  = (uint32_t)uap->pri;
	flags  = (uint32_t)uap->flags;

	au_uwrite(au_to_arg32(1, "fd", fd));

	if ((fp = getf(fd)) != NULL) {
		fad = F2A(fp);

		fad->fad_flags |= FAD_WRITE;

		/* add path name to audit record */
		if (fad->fad_aupath != NULL) {
			au_uwrite(au_to_path(fad->fad_aupath));
		}
		audit_attributes(fp->f_vnode);

		releasef(fd);
	}


	au_uwrite(au_to_arg32(4, "pri", pri));
	au_uwrite(au_to_arg32(5, "flags", flags));
}

/*ARGSUSED*/
static void
aus_getmsg(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t fd, pri;
	struct file *fp;
	struct f_audit_data *fad;

	struct a {
		long	fdes;
		long	ctl;		/* struct strbuf * */
		long	data;		/* struct strbuf * */
		long	pri;
	} *uap = (struct a *)clwp->lwp_ap;

	fd  = (uint32_t)uap->fdes;
	pri = (uint32_t)uap->pri;

	au_uwrite(au_to_arg32(1, "fd", fd));

	if ((fp = getf(fd)) != NULL) {
		fad = F2A(fp);

		/*
		 * read operation on this object
		 */
		fad->fad_flags |= FAD_READ;

		/* add path name to audit record */
		if (fad->fad_aupath != NULL) {
			au_uwrite(au_to_path(fad->fad_aupath));
		}
		audit_attributes(fp->f_vnode);

		releasef(fd);
	}

	au_uwrite(au_to_arg32(4, "pri", pri));
}

/*ARGSUSED*/
static void
aus_getpmsg(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t fd;
	struct file *fp;
	struct f_audit_data *fad;

	struct a {
		long	fdes;
		long	ctl;		/* struct strbuf * */
		long	data;		/* struct strbuf * */
		long	pri;
		long	flags;
	} *uap = (struct a *)clwp->lwp_ap;

	fd = (uint32_t)uap->fdes;

	au_uwrite(au_to_arg32(1, "fd", fd));

	if ((fp = getf(fd)) != NULL) {
		fad = F2A(fp);

		/*
		 * read operation on this object
		 */
		fad->fad_flags |= FAD_READ;

		/* add path name to audit record */
		if (fad->fad_aupath != NULL) {
			au_uwrite(au_to_path(fad->fad_aupath));
		}
		audit_attributes(fp->f_vnode);

		releasef(fd);
	}
}

static au_event_t
aui_labelsys(au_event_t e)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t code;
	uint32_t cmd;

	struct a {
		long	code;
		long	cmd;
	} *uap = (struct a *)clwp->lwp_ap;

	code = (uint32_t)uap->code;
	cmd = (uint32_t)uap->cmd;

	/* not security relevant if not changing kernel cache */
	if (cmd == TNDB_GET)
		return (AUE_NULL);

	switch (code) {
	case TSOL_TNRH:
		e = AUE_LABELSYS_TNRH;
		break;
	case TSOL_TNRHTP:
		e = AUE_LABELSYS_TNRHTP;
		break;
	case TSOL_TNMLP:
		e = AUE_LABELSYS_TNMLP;
		break;
	default:
		e = AUE_NULL;
		break;
	}

	return (e);

}

static void
aus_labelsys(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t cmd;
	uintptr_t a2;

	struct a {
		long	code;
		long	cmd;
		long	a2;
	} *uap = (struct a *)clwp->lwp_ap;

	cmd = (uint32_t)uap->cmd;
	a2 = (uintptr_t)uap->a2;

	switch (tad->tad_event) {
	case AUE_LABELSYS_TNRH:
	{
		tsol_rhent_t	*rhent;
		tnaddr_t	*rh_addr;

		au_uwrite(au_to_arg32(1, "cmd", cmd));

		/* Remaining args don't apply for FLUSH, so skip */
		if (cmd == TNDB_FLUSH)
			break;

		rhent = kmem_alloc(sizeof (tsol_rhent_t), KM_SLEEP);
		if (copyin((caddr_t)a2, rhent, sizeof (tsol_rhent_t))) {
			kmem_free(rhent, sizeof (tsol_rhent_t));
			return;
		}

		rh_addr = &rhent->rh_address;
		if (rh_addr->ta_family == AF_INET) {
			struct in_addr	*ipaddr;

			ipaddr = &(rh_addr->ta_addr_v4);
			au_uwrite(au_to_in_addr(ipaddr));
		} else if (rh_addr->ta_family == AF_INET6) {
			int32_t		*ipaddr;

			ipaddr = (int32_t *)&(rh_addr->ta_addr_v6);
			au_uwrite(au_to_in_addr_ex(ipaddr));
		}
		au_uwrite(au_to_arg32(2, "prefix len", rhent->rh_prefix));

		kmem_free(rhent, sizeof (tsol_rhent_t));

		break;
	}
	case AUE_LABELSYS_TNRHTP:
	{
		tsol_tpent_t	*tpent;

		au_uwrite(au_to_arg32(1, "cmd", cmd));

		/* Remaining args don't apply for FLUSH, so skip */
		if (cmd == TNDB_FLUSH)
			break;

		tpent = kmem_alloc(sizeof (tsol_tpent_t), KM_SLEEP);
		if (copyin((caddr_t)a2, tpent, sizeof (tsol_tpent_t))) {
			kmem_free(tpent, sizeof (tsol_tpent_t));
			return;
		}

		/* Make sure that the template name is null-terminated. */
		*(tpent->name + TNTNAMSIZ - 1) = '\0';

		au_uwrite(au_to_text(tpent->name));
		kmem_free(tpent, sizeof (tsol_tpent_t));

		break;
	}
	case AUE_LABELSYS_TNMLP:
	{
		tsol_mlpent_t	*mlpent;

		au_uwrite(au_to_arg32(1, "cmd", cmd));

		mlpent = kmem_alloc(sizeof (tsol_mlpent_t), KM_SLEEP);
		if (copyin((caddr_t)a2, mlpent, sizeof (tsol_mlpent_t))) {
			kmem_free(mlpent, sizeof (tsol_mlpent_t));
			return;
		}

		if (mlpent->tsme_flags & TSOL_MEF_SHARED) {
			au_uwrite(au_to_text("shared"));
		} else {
			zone_t	*zone;

			zone = zone_find_by_id(mlpent->tsme_zoneid);
			if (zone != NULL) {
				au_uwrite(au_to_text(zone->zone_name));
				zone_rele(zone);
			}
		}

		/* Remaining args don't apply for FLUSH, so skip */
		if (cmd == TNDB_FLUSH) {
			kmem_free(mlpent, sizeof (tsol_mlpent_t));
			break;
		}

		au_uwrite(au_to_arg32(2, "proto num",
		    (uint32_t)mlpent->tsme_mlp.mlp_ipp));
		au_uwrite(au_to_arg32(2, "mlp_port",
		    (uint32_t)mlpent->tsme_mlp.mlp_port));

		if (mlpent->tsme_mlp.mlp_port_upper != 0)
			au_uwrite(au_to_arg32(2, "mlp_port_upper",
			    (uint32_t)mlpent->tsme_mlp.mlp_port_upper));

		kmem_free(mlpent, sizeof (tsol_mlpent_t));

		break;
	}
	default:
		break;
	}
}


static au_event_t
aui_auditsys(au_event_t e)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t code;

	struct a {
		long	code;
		long	a1;
		long	a2;
		long	a3;
		long	a4;
		long	a5;
		long	a6;
		long	a7;
	} *uap = (struct a *)clwp->lwp_ap;

	code = (uint32_t)uap->code;

	switch (code) {

	case BSM_GETAUID:
		e = AUE_GETAUID;
		break;
	case BSM_SETAUID:
		e = AUE_SETAUID;
		break;
	case BSM_GETAUDIT:
		e = AUE_GETAUDIT;
		break;
	case BSM_GETAUDIT_ADDR:
		e = AUE_GETAUDIT_ADDR;
		break;
	case BSM_SETAUDIT:
		e = AUE_SETAUDIT;
		break;
	case BSM_SETAUDIT_ADDR:
		e = AUE_SETAUDIT_ADDR;
		break;
	case BSM_AUDIT:
		e = AUE_AUDIT;
		break;
	case BSM_AUDITCTL:
		switch ((uint_t)uap->a1) {

		case A_GETPOLICY:
			e = AUE_AUDITON_GPOLICY;
			break;
		case A_SETPOLICY:
			e = AUE_AUDITON_SPOLICY;
			break;
		case A_GETAMASK:
			e = AUE_AUDITON_GETAMASK;
			break;
		case A_SETAMASK:
			e = AUE_AUDITON_SETAMASK;
			break;
		case A_GETKMASK:
			e = AUE_AUDITON_GETKMASK;
			break;
		case A_SETKMASK:
			e = AUE_AUDITON_SETKMASK;
			break;
		case A_GETQCTRL:
			e = AUE_AUDITON_GQCTRL;
			break;
		case A_SETQCTRL:
			e = AUE_AUDITON_SQCTRL;
			break;
		case A_GETCWD:
			e = AUE_AUDITON_GETCWD;
			break;
		case A_GETCAR:
			e = AUE_AUDITON_GETCAR;
			break;
		case A_GETSTAT:
			e = AUE_AUDITON_GETSTAT;
			break;
		case A_SETSTAT:
			e = AUE_AUDITON_SETSTAT;
			break;
		case A_SETUMASK:
			e = AUE_AUDITON_SETUMASK;
			break;
		case A_SETSMASK:
			e = AUE_AUDITON_SETSMASK;
			break;
		case A_GETCOND:
			e = AUE_AUDITON_GETCOND;
			break;
		case A_SETCOND:
			e = AUE_AUDITON_SETCOND;
			break;
		case A_GETCLASS:
			e = AUE_AUDITON_GETCLASS;
			break;
		case A_SETCLASS:
			e = AUE_AUDITON_SETCLASS;
			break;
		default:
			e = AUE_NULL;
			break;
		}
		break;
	default:
		e = AUE_NULL;
		break;
	}

	return (e);

}	/* AUI_AUDITSYS */


static void
aus_auditsys(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uintptr_t a1, a2;
	STRUCT_DECL(auditinfo, ainfo);
	STRUCT_DECL(auditinfo_addr, ainfo_addr);
	au_evclass_map_t event;
	au_mask_t mask;
	int auditstate, policy;
	au_id_t auid;


	struct a {
		long	code;
		long	a1;
		long	a2;
		long	a3;
		long	a4;
		long	a5;
		long	a6;
		long	a7;
	} *uap = (struct a *)clwp->lwp_ap;

	a1   = (uintptr_t)uap->a1;
	a2   = (uintptr_t)uap->a2;

	switch (tad->tad_event) {
	case AUE_SETAUID:
		if (copyin((caddr_t)a1, &auid, sizeof (au_id_t)))
				return;
		au_uwrite(au_to_arg32(2, "setauid", auid));
		break;
	case AUE_SETAUDIT:
		STRUCT_INIT(ainfo, get_udatamodel());
		if (copyin((caddr_t)a1, STRUCT_BUF(ainfo),
		    STRUCT_SIZE(ainfo))) {
				return;
		}
		au_uwrite(au_to_arg32((char)1, "setaudit:auid",
		    (uint32_t)STRUCT_FGET(ainfo, ai_auid)));
#ifdef _LP64
		au_uwrite(au_to_arg64((char)1, "setaudit:port",
		    (uint64_t)STRUCT_FGET(ainfo, ai_termid.port)));
#else
		au_uwrite(au_to_arg32((char)1, "setaudit:port",
		    (uint32_t)STRUCT_FGET(ainfo, ai_termid.port)));
#endif
		au_uwrite(au_to_arg32((char)1, "setaudit:machine",
		    (uint32_t)STRUCT_FGET(ainfo, ai_termid.machine)));
		au_uwrite(au_to_arg32((char)1, "setaudit:as_success",
		    (uint32_t)STRUCT_FGET(ainfo, ai_mask.as_success)));
		au_uwrite(au_to_arg32((char)1, "setaudit:as_failure",
		    (uint32_t)STRUCT_FGET(ainfo, ai_mask.as_failure)));
		au_uwrite(au_to_arg32((char)1, "setaudit:asid",
		    (uint32_t)STRUCT_FGET(ainfo, ai_asid)));
		break;
	case AUE_SETAUDIT_ADDR:
		STRUCT_INIT(ainfo_addr, get_udatamodel());
		if (copyin((caddr_t)a1, STRUCT_BUF(ainfo_addr),
		    STRUCT_SIZE(ainfo_addr))) {
				return;
		}
		au_uwrite(au_to_arg32((char)1, "auid",
		    (uint32_t)STRUCT_FGET(ainfo_addr, ai_auid)));
#ifdef _LP64
		au_uwrite(au_to_arg64((char)1, "port",
		    (uint64_t)STRUCT_FGET(ainfo_addr, ai_termid.at_port)));
#else
		au_uwrite(au_to_arg32((char)1, "port",
		    (uint32_t)STRUCT_FGET(ainfo_addr, ai_termid.at_port)));
#endif
		au_uwrite(au_to_arg32((char)1, "type",
		    (uint32_t)STRUCT_FGET(ainfo_addr, ai_termid.at_type)));
		if ((uint32_t)STRUCT_FGET(ainfo_addr, ai_termid.at_type) ==
		    AU_IPv4) {
			au_uwrite(au_to_in_addr(
			    (struct in_addr *)STRUCT_FGETP(ainfo_addr,
			    ai_termid.at_addr)));
		} else {
			au_uwrite(au_to_in_addr_ex(
			    (int32_t *)STRUCT_FGETP(ainfo_addr,
			    ai_termid.at_addr)));
		}
		au_uwrite(au_to_arg32((char)1, "as_success",
		    (uint32_t)STRUCT_FGET(ainfo_addr, ai_mask.as_success)));
		au_uwrite(au_to_arg32((char)1, "as_failure",
		    (uint32_t)STRUCT_FGET(ainfo_addr, ai_mask.as_failure)));
		au_uwrite(au_to_arg32((char)1, "asid",
		    (uint32_t)STRUCT_FGET(ainfo_addr, ai_asid)));
		break;
	case AUE_AUDITON_SETAMASK:
		if (copyin((caddr_t)a2, &mask, sizeof (au_mask_t)))
				return;
		au_uwrite(au_to_arg32(
		    2, "setamask:as_success", (uint32_t)mask.as_success));
		au_uwrite(au_to_arg32(
		    2, "setamask:as_failure", (uint32_t)mask.as_failure));
		break;
	case AUE_AUDITON_SETKMASK:
		if (copyin((caddr_t)a2, &mask, sizeof (au_mask_t)))
				return;
		au_uwrite(au_to_arg32(
		    2, "setkmask:as_success", (uint32_t)mask.as_success));
		au_uwrite(au_to_arg32(
		    2, "setkmask:as_failure", (uint32_t)mask.as_failure));
		break;
	case AUE_AUDITON_SPOLICY:
		if (copyin((caddr_t)a2, &policy, sizeof (int)))
			return;
		au_uwrite(au_to_arg32(3, "setpolicy", (uint32_t)policy));
		break;
	case AUE_AUDITON_SQCTRL: {
		STRUCT_DECL(au_qctrl, qctrl);
		model_t model;

		model = get_udatamodel();
		STRUCT_INIT(qctrl, model);
		if (copyin((caddr_t)a2, STRUCT_BUF(qctrl), STRUCT_SIZE(qctrl)))
				return;
		if (model == DATAMODEL_ILP32) {
			au_uwrite(au_to_arg32(
			    3, "setqctrl:aq_hiwater",
			    (uint32_t)STRUCT_FGET(qctrl, aq_hiwater)));
			au_uwrite(au_to_arg32(
			    3, "setqctrl:aq_lowater",
			    (uint32_t)STRUCT_FGET(qctrl, aq_lowater)));
			au_uwrite(au_to_arg32(
			    3, "setqctrl:aq_bufsz",
			    (uint32_t)STRUCT_FGET(qctrl, aq_bufsz)));
			au_uwrite(au_to_arg32(
			    3, "setqctrl:aq_delay",
			    (uint32_t)STRUCT_FGET(qctrl, aq_delay)));
		} else {
			au_uwrite(au_to_arg64(
			    3, "setqctrl:aq_hiwater",
			    (uint64_t)STRUCT_FGET(qctrl, aq_hiwater)));
			au_uwrite(au_to_arg64(
			    3, "setqctrl:aq_lowater",
			    (uint64_t)STRUCT_FGET(qctrl, aq_lowater)));
			au_uwrite(au_to_arg64(
			    3, "setqctrl:aq_bufsz",
			    (uint64_t)STRUCT_FGET(qctrl, aq_bufsz)));
			au_uwrite(au_to_arg64(
			    3, "setqctrl:aq_delay",
			    (uint64_t)STRUCT_FGET(qctrl, aq_delay)));
		}
		break;
	}
	case AUE_AUDITON_SETUMASK:
		STRUCT_INIT(ainfo, get_udatamodel());
		if (copyin((caddr_t)uap->a2, STRUCT_BUF(ainfo),
		    STRUCT_SIZE(ainfo))) {
			return;
		}
		au_uwrite(au_to_arg32(3, "setumask:as_success",
		    (uint32_t)STRUCT_FGET(ainfo, ai_mask.as_success)));
		au_uwrite(au_to_arg32(3, "setumask:as_failure",
		    (uint32_t)STRUCT_FGET(ainfo, ai_mask.as_failure)));
		break;
	case AUE_AUDITON_SETSMASK:
		STRUCT_INIT(ainfo, get_udatamodel());
		if (copyin((caddr_t)uap->a2, STRUCT_BUF(ainfo),
		    STRUCT_SIZE(ainfo))) {
			return;
		}
		au_uwrite(au_to_arg32(3, "setsmask:as_success",
		    (uint32_t)STRUCT_FGET(ainfo, ai_mask.as_success)));
		au_uwrite(au_to_arg32(3, "setsmask:as_failure",
		    (uint32_t)STRUCT_FGET(ainfo, ai_mask.as_failure)));
		break;
	case AUE_AUDITON_SETCOND:
		if (copyin((caddr_t)a2, &auditstate, sizeof (int)))
			return;
		au_uwrite(au_to_arg32(3, "setcond", (uint32_t)auditstate));
		break;
	case AUE_AUDITON_SETCLASS:
		if (copyin((caddr_t)a2, &event, sizeof (au_evclass_map_t)))
			return;
		au_uwrite(au_to_arg32(
		    2, "setclass:ec_event", (uint32_t)event.ec_number));
		au_uwrite(au_to_arg32(
		    3, "setclass:ec_class", (uint32_t)event.ec_class));
		break;
	case AUE_GETAUID:
	case AUE_GETAUDIT:
	case AUE_GETAUDIT_ADDR:
	case AUE_AUDIT:
	case AUE_AUDITON_GPOLICY:
	case AUE_AUDITON_GQCTRL:
	case AUE_AUDITON_GETAMASK:
	case AUE_AUDITON_GETKMASK:
	case AUE_AUDITON_GETCWD:
	case AUE_AUDITON_GETCAR:
	case AUE_AUDITON_GETSTAT:
	case AUE_AUDITON_SETSTAT:
	case AUE_AUDITON_GETCOND:
	case AUE_AUDITON_GETCLASS:
		break;
	default:
		break;
	}

}	/* AUS_AUDITSYS */


/* only audit privileged operations for systeminfo(2) system call */
static au_event_t
aui_sysinfo(au_event_t e)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t command;

	struct a {
		long	command;
		long	buf;		/* char * */
		long	count;
	} *uap = (struct a *)clwp->lwp_ap;

	command = (uint32_t)uap->command;

	switch (command) {
	case SI_SET_HOSTNAME:
	case SI_SET_SRPC_DOMAIN:
		e = (au_event_t)AUE_SYSINFO;
		break;
	default:
		e = (au_event_t)AUE_NULL;
		break;
	}
	return (e);
}

/*ARGSUSED*/
static void
aus_sysinfo(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	uint32_t command;
	size_t len, maxlen;
	char *name;
	uintptr_t buf;

	struct a {
		long	command;
		long	buf;		/* char * */
		long	count;
	} *uap = (struct a *)clwp->lwp_ap;

	command = (uint32_t)uap->command;
	buf = (uintptr_t)uap->buf;

	au_uwrite(au_to_arg32(1, "cmd", command));

	switch (command) {
	case SI_SET_HOSTNAME:
	{
		if (secpolicy_sys_config(CRED(), B_TRUE) != 0)
			return;

		maxlen = SYS_NMLN;
		name = kmem_alloc(maxlen, KM_SLEEP);
		if (copyinstr((caddr_t)buf, name, SYS_NMLN, &len))
			break;

		/*
		 * Must be non-NULL string and string
		 * must be less than SYS_NMLN chars.
		 */
		if (len < 2 || (len == SYS_NMLN && name[SYS_NMLN - 1] != '\0'))
			break;

		au_uwrite(au_to_text(name));
		break;
	}

	case SI_SET_SRPC_DOMAIN:
	{
		if (secpolicy_sys_config(CRED(), B_TRUE) != 0)
			return;

		maxlen = SYS_NMLN;
		name = kmem_alloc(maxlen, KM_SLEEP);
		if (copyinstr((caddr_t)buf, name, SYS_NMLN, &len))
			break;

		/*
		 * If string passed in is longer than length
		 * allowed for domain name, fail.
		 */
		if (len == SYS_NMLN && name[SYS_NMLN - 1] != '\0')
			break;

		au_uwrite(au_to_text(name));
		break;
	}

	default:
		return;
	}

	kmem_free(name, maxlen);
}

static au_event_t
aui_modctl(au_event_t e)
{
	klwp_t *clwp = ttolwp(curthread);
	uint_t cmd;

	struct a {
		long	cmd;
	} *uap = (struct a *)clwp->lwp_ap;

	cmd = (uint_t)uap->cmd;

	switch (cmd) {
	case MODLOAD:
		e = AUE_MODLOAD;
		break;
	case MODUNLOAD:
		e = AUE_MODUNLOAD;
		break;
	case MODADDMAJBIND:
		e = AUE_MODADDMAJ;
		break;
	case MODSETDEVPOLICY:
		e = AUE_MODDEVPLCY;
		break;
	case MODALLOCPRIV:
		e = AUE_MODADDPRIV;
		break;
	default:
		e = AUE_NULL;
		break;
	}
	return (e);
}


/*ARGSUSED*/
static void
aus_modctl(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);
	void *a	= clwp->lwp_ap;
	uint_t use_path;

	switch (tad->tad_event) {
	case AUE_MODLOAD: {
		typedef struct {
			long	cmd;
			long	use_path;
			long	filename;		/* char * */
		} modloada_t;

		char *filenamep;
		uintptr_t fname;
		extern char *default_path;

		fname = (uintptr_t)((modloada_t *)a)->filename;
		use_path = (uint_t)((modloada_t *)a)->use_path;

			/* space to hold path */
		filenamep = kmem_alloc(MOD_MAXPATH, KM_SLEEP);
			/* get string */
		if (copyinstr((caddr_t)fname, filenamep, MOD_MAXPATH, 0)) {
				/* free allocated path */
			kmem_free(filenamep, MOD_MAXPATH);
			return;
		}
			/* ensure it's null terminated */
		filenamep[MOD_MAXPATH - 1] = 0;

		if (use_path)
			au_uwrite(au_to_text(default_path));
		au_uwrite(au_to_text(filenamep));

			/* release temporary memory */
		kmem_free(filenamep, MOD_MAXPATH);
		break;
	}
	case AUE_MODUNLOAD: {
		typedef struct {
			long	cmd;
			long	id;
		} modunloada_t;

		uint32_t id = (uint32_t)((modunloada_t *)a)->id;

		au_uwrite(au_to_arg32(1, "id", id));
		break;
	}
	case AUE_MODADDMAJ: {
		STRUCT_DECL(modconfig, mc);
		typedef struct {
			long	cmd;
			long	subcmd;
			long	data;		/* int * */
		} modconfiga_t;

		STRUCT_DECL(aliases, alias);
		caddr_t ap;
		int i, num_aliases;
		char *drvname, *mc_drvname;
		char *name;
		extern char *ddi_major_to_name(major_t);
		model_t model;

		uintptr_t data = (uintptr_t)((modconfiga_t *)a)->data;

		model = get_udatamodel();
		STRUCT_INIT(mc, model);
			/* sanitize buffer */
		bzero((caddr_t)STRUCT_BUF(mc), STRUCT_SIZE(mc));
			/* get user arguments */
		if (copyin((caddr_t)data, (caddr_t)STRUCT_BUF(mc),
		    STRUCT_SIZE(mc)) != 0)
			return;

		mc_drvname = STRUCT_FGET(mc, drvname);
		if ((drvname = ddi_major_to_name(
		    (major_t)STRUCT_FGET(mc, major))) != NULL &&
		    strncmp(drvname, mc_drvname, MAXMODCONFNAME) != 0) {
				/* safety */
			if (mc_drvname[0] != '\0') {
				mc_drvname[MAXMODCONFNAME-1] = '\0';
				au_uwrite(au_to_text(mc_drvname));
			}
				/* drvname != NULL from test above */
			au_uwrite(au_to_text(drvname));
			return;
		}

		if (mc_drvname[0] != '\0') {
				/* safety */
			mc_drvname[MAXMODCONFNAME-1] = '\0';
			au_uwrite(au_to_text(mc_drvname));
		} else
			au_uwrite(au_to_text("no drvname"));

		num_aliases = STRUCT_FGET(mc, num_aliases);
		au_uwrite(au_to_arg32(5, "", (uint32_t)num_aliases));
		ap = (caddr_t)STRUCT_FGETP(mc, ap);
		name = kmem_alloc(MAXMODCONFNAME, KM_SLEEP);
		STRUCT_INIT(alias, model);
		for (i = 0; i < num_aliases; i++) {
			bzero((caddr_t)STRUCT_BUF(alias),
			    STRUCT_SIZE(alias));
			if (copyin((caddr_t)ap, (caddr_t)STRUCT_BUF(alias),
			    STRUCT_SIZE(alias)) != 0)
				break;
			if (copyinstr(STRUCT_FGETP(alias, a_name), name,
			    MAXMODCONFNAME, NULL) != 0) {
				break;
			}

			au_uwrite(au_to_text(name));
			ap = (caddr_t)STRUCT_FGETP(alias, a_next);
		}
		kmem_free(name, MAXMODCONFNAME);
		break;
	}
	default:
		break;
	}
}


/*ARGSUSED*/
static void
auf_accept(
	struct t_audit_data *tad,
	int	error,
	rval_t	*rval)
{
	uint32_t scid;
	uint32_t sy_flags;
	int fd;
	struct sonode *so;
	char so_laddr[sizeof (struct sockaddr_in6)];
	char so_faddr[sizeof (struct sockaddr_in6)];
	int err;
	short so_family, so_type;
	int add_sock_token = 0;

	/* need to determine type of executing binary */
	scid = tad->tad_scid;
#ifdef _SYSCALL32_IMPL
	if (lwp_getdatamodel(ttolwp(curthread)) == DATAMODEL_NATIVE)
		sy_flags = sysent[scid].sy_flags & SE_RVAL_MASK;
	else
		sy_flags = sysent32[scid].sy_flags & SE_RVAL_MASK;
#else
	sy_flags = sysent[scid].sy_flags & SE_RVAL_MASK;
#endif
	switch (sy_flags) {
	case SE_32RVAL1:
		/* FALLTHRU */
	case SE_32RVAL2|SE_32RVAL1:
		fd = rval->r_val1;
		break;
	case SE_64RVAL:
		fd = (int)rval->r_vals;
		break;
	default:
		/*
		 * should never happen, seems to be an internal error
		 * in sysent => no fd, nothing to audit here, returning
		 */
		return;
	}

	if (error) {
		/* can't trust socket contents. Just return */
		au_uwrite(au_to_arg32(1, "so", (uint32_t)fd));
		return;
	}

	if ((so = getsonode(fd, &err, NULL)) == NULL) {
		/*
		 * not security relevant if doing a accept from non socket
		 * so no extra tokens. Should probably turn off audit record
		 * generation here.
		 */
		return;
	}

	so_family = so->so_family;
	so_type   = so->so_type;

	switch (so_family) {
	case AF_INET:
	case AF_INET6:
		/*
		 * XXX - what about other socket types for AF_INET (e.g. DGRAM)
		 */
		if (so->so_type == SOCK_STREAM) {
			socklen_t len;

			bzero((void *)so_laddr, sizeof (so_laddr));
			bzero((void *)so_faddr, sizeof (so_faddr));

			len = sizeof (so_laddr);
			(void) socket_getsockname(so,
			    (struct sockaddr *)so_laddr, &len, CRED());
			len = sizeof (so_faddr);
			(void) socket_getpeername(so,
			    (struct sockaddr *)so_faddr, &len, B_FALSE, CRED());

			add_sock_token = 1;
		}
		break;

	default:
		/* AF_UNIX, AF_ROUTE, AF_KEY do not support accept */
		break;
	}

	releasef(fd);

	au_uwrite(au_to_arg32(1, "so", (uint32_t)fd));

	if (add_sock_token == 0) {
		au_uwrite(au_to_arg32(0, "family", (uint32_t)(so_family)));
		au_uwrite(au_to_arg32(0, "type", (uint32_t)(so_type)));
		return;
	}

	au_uwrite(au_to_socket_ex(so_family, so_type, so_laddr, so_faddr));

}

/*ARGSUSED*/
static void
auf_bind(struct t_audit_data *tad, int error, rval_t *rvp)
{
	struct a {
		long	fd;
		long	addr;
		long	len;
	} *uap = (struct a *)ttolwp(curthread)->lwp_ap;

	struct sonode *so;
	char so_laddr[sizeof (struct sockaddr_in6)];
	char so_faddr[sizeof (struct sockaddr_in6)];
	int err, fd;
	socklen_t len;
	short so_family, so_type;
	int add_sock_token = 0;

	fd = (int)uap->fd;

	/*
	 * bind failed, then nothing extra to add to audit record.
	 */
	if (error) {
		au_uwrite(au_to_arg32(1, "so", (uint32_t)fd));
		/* XXX may want to add failed address some day */
		return;
	}

	if ((so = getsonode(fd, &err, NULL)) == NULL) {
		/*
		 * not security relevant if doing a bind from non socket
		 * so no extra tokens. Should probably turn off audit record
		 * generation here.
		 */
		return;
	}

	so_family = so->so_family;
	so_type   = so->so_type;

	switch (so_family) {
	case AF_INET:
	case AF_INET6:

		bzero(so_faddr, sizeof (so_faddr));
		len = sizeof (so_faddr);

		(void) socket_getpeername(so,
		    (struct sockaddr *)so_faddr, &len, B_FALSE, CRED());
		add_sock_token = 1;

		break;

	case AF_UNIX:
		/* token added by lookup */
		break;
	default:
		/* AF_ROUTE, AF_KEY do not support accept */
		break;
	}

	releasef(fd);

	au_uwrite(au_to_arg32(1, "so", (uint32_t)fd));

	if (add_sock_token == 0) {
		au_uwrite(au_to_arg32(1, "family", (uint32_t)(so_family)));
		au_uwrite(au_to_arg32(1, "type", (uint32_t)(so_type)));
		return;
	}

	au_uwrite(au_to_socket_ex(so_family, so_type, so_laddr, so_faddr));

}

/*ARGSUSED*/
static void
auf_connect(struct t_audit_data *tad, int error, rval_t *rval)
{
	struct a {
		long	fd;
		long	addr;
		long	len;
	} *uap = (struct a *)ttolwp(curthread)->lwp_ap;

	struct sonode *so;
	char so_laddr[sizeof (struct sockaddr_in6)];
	char so_faddr[sizeof (struct sockaddr_in6)];
	int err, fd;
	socklen_t len;
	short so_family, so_type;
	int add_sock_token = 0;

	fd = (int)uap->fd;


	if ((so = getsonode(fd, &err, NULL)) == NULL) {
		/*
		 * not security relevant if doing a connect from non socket
		 * so no extra tokens. Should probably turn off audit record
		 * generation here.
		 */
		return;
	}

	so_family = so->so_family;
	so_type   = so->so_type;

	switch (so_family) {
	case AF_INET:
	case AF_INET6:

		bzero(so_laddr, sizeof (so_laddr));
		bzero(so_faddr, sizeof (so_faddr));

		len = sizeof (so_laddr);
		(void) socket_getsockname(so, (struct sockaddr *)so_laddr,
		    &len, CRED());
		if (error) {
			if (uap->addr == NULL)
				break;
			if (uap->len <= 0)
				break;
			len = min(uap->len, sizeof (so_faddr));
			if (copyin((caddr_t)(uap->addr), so_faddr, len) != 0)
				break;
#ifdef NOTYET
			au_uwrite(au_to_data(AUP_HEX, AUR_CHAR, len, so_faddr));
#endif
		} else {
			/* sanity check on length */
			len = sizeof (so_faddr);
			(void) socket_getpeername(so,
			    (struct sockaddr *)so_faddr, &len, B_FALSE, CRED());
		}

		add_sock_token = 1;

		break;

	case AF_UNIX:
		/* does a lookup on name */
		break;

	default:
		/* AF_ROUTE, AF_KEY do not support accept */
		break;
	}

	releasef(fd);

	au_uwrite(au_to_arg32(1, "so", (uint32_t)fd));

	if (add_sock_token == 0) {
		au_uwrite(au_to_arg32(1, "family", (uint32_t)(so_family)));
		au_uwrite(au_to_arg32(1, "type", (uint32_t)(so_type)));
		return;
	}

	au_uwrite(au_to_socket_ex(so_family, so_type, so_laddr, so_faddr));

}

/*ARGSUSED*/
static void
aus_shutdown(struct t_audit_data *tad)
{
	struct a {
		long	fd;
		long	how;
	} *uap = (struct a *)ttolwp(curthread)->lwp_ap;

	struct sonode *so;
	char so_laddr[sizeof (struct sockaddr_in6)];
	char so_faddr[sizeof (struct sockaddr_in6)];
	int err, fd;
	socklen_t len;
	short so_family, so_type;
	int add_sock_token = 0;
	file_t *fp;				/* unix domain sockets */
	struct f_audit_data *fad;		/* unix domain sockets */

	fd = (int)uap->fd;

	if ((so = getsonode(fd, &err, &fp)) == NULL) {
		/*
		 * not security relevant if doing a shutdown using non socket
		 * so no extra tokens. Should probably turn off audit record
		 * generation here.
		 */
		return;
	}

	so_family = so->so_family;
	so_type   = so->so_type;

	switch (so_family) {
	case AF_INET:
	case AF_INET6:

		bzero(so_laddr, sizeof (so_laddr));
		bzero(so_faddr, sizeof (so_faddr));

		len = sizeof (so_laddr);
		(void) socket_getsockname(so,
		    (struct sockaddr *)so_laddr, &len, CRED());
		len = sizeof (so_faddr);
		(void) socket_getpeername(so,
		    (struct sockaddr *)so_faddr, &len, B_FALSE, CRED());

		add_sock_token = 1;

		break;

	case AF_UNIX:

		/* get path from file struct here */
		fad = F2A(fp);
		ASSERT(fad);

		if (fad->fad_aupath != NULL) {
			au_uwrite(au_to_path(fad->fad_aupath));
		} else {
			au_uwrite(au_to_arg32(1, "no path: fd", fd));
		}

		audit_attributes(fp->f_vnode);

		break;

	default:
		/*
		 * AF_KEY and AF_ROUTE support shutdown. No socket token
		 * added.
		 */
		break;
	}

	releasef(fd);

	au_uwrite(au_to_arg32(1, "so", (uint32_t)fd));

	if (add_sock_token == 0) {
		au_uwrite(au_to_arg32(1, "family", (uint32_t)(so_family)));
		au_uwrite(au_to_arg32(1, "type", (uint32_t)(so_type)));
		au_uwrite(au_to_arg32(2, "how", (uint32_t)(uap->how)));
		return;
	}

	au_uwrite(au_to_arg32(2, "how", (uint32_t)(uap->how)));

	au_uwrite(au_to_socket_ex(so_family, so_type, so_laddr, so_faddr));

}

/*ARGSUSED*/
static void
auf_setsockopt(struct t_audit_data *tad, int error, rval_t *rval)
{
	struct a {
		long	fd;
		long	level;
		long	optname;
		long	*optval;
		long	optlen;
	} *uap = (struct a *)ttolwp(curthread)->lwp_ap;

	struct sonode	*so;
	char so_laddr[sizeof (struct sockaddr_in6)];
	char so_faddr[sizeof (struct sockaddr_in6)];
	char		val[AU_BUFSIZE];
	int		err, fd;
	socklen_t	len;
	short so_family, so_type;
	int		add_sock_token = 0;
	file_t *fp;				/* unix domain sockets */
	struct f_audit_data *fad;		/* unix domain sockets */

	fd = (int)uap->fd;

	if (error) {
		au_uwrite(au_to_arg32(1, "so", (uint32_t)fd));
		au_uwrite(au_to_arg32(2, "level", (uint32_t)uap->level));
		/* XXX may want to include other arguments */
		return;
	}

	if ((so = getsonode(fd, &err, &fp)) == NULL) {
		/*
		 * not security relevant if doing a setsockopt from non socket
		 * so no extra tokens. Should probably turn off audit record
		 * generation here.
		 */
		return;
	}

	so_family = so->so_family;
	so_type   = so->so_type;

	switch (so_family) {
	case AF_INET:
	case AF_INET6:
		bzero((void *)so_laddr, sizeof (so_laddr));
		bzero((void *)so_faddr, sizeof (so_faddr));

		/* get local and foreign addresses */
		len = sizeof (so_laddr);
		(void) socket_getsockname(so, (struct sockaddr *)so_laddr,
		    &len, CRED());
		len = sizeof (so_faddr);
		(void) socket_getpeername(so, (struct sockaddr *)so_faddr,
		    &len, B_FALSE, CRED());

		add_sock_token = 1;

		break;

	case AF_UNIX:

		/* get path from file struct here */
		fad = F2A(fp);
		ASSERT(fad);

		if (fad->fad_aupath != NULL) {
			au_uwrite(au_to_path(fad->fad_aupath));
		} else {
			au_uwrite(au_to_arg32(1, "no path: fd", fd));
		}

		audit_attributes(fp->f_vnode);

		break;

	default:
		/*
		 * AF_KEY and AF_ROUTE support setsockopt. No socket token
		 * added.
		 */
		break;
	}

	releasef(fd);

	au_uwrite(au_to_arg32(1, "so", (uint32_t)fd));

	if (add_sock_token == 0) {
		au_uwrite(au_to_arg32(1, "family", (uint32_t)(so_family)));
		au_uwrite(au_to_arg32(1, "type", (uint32_t)(so_type)));
	}
	au_uwrite(au_to_arg32(2, "level", (uint32_t)(uap->level)));
	au_uwrite(au_to_arg32(3, "optname", (uint32_t)(uap->optname)));

	bzero(val, sizeof (val));
	len = min(uap->optlen, sizeof (val));
	if ((len > 0) &&
	    (copyin((caddr_t)(uap->optval), (caddr_t)val, len) == 0)) {
		au_uwrite(au_to_arg32(5, "optlen", (uint32_t)(uap->optlen)));
		au_uwrite(au_to_data(AUP_HEX, AUR_BYTE, len, val));
	}

	if (add_sock_token == 0)
		return;

	au_uwrite(au_to_socket_ex(so_family, so_type, so_laddr, so_faddr));

}

/*ARGSUSED*/
static void
aus_sockconfig(tad)
	struct t_audit_data *tad;
{
	struct a {
		long	cmd;
		long	arg1;
		long	arg2;
		long	arg3;
		long	arg4;
	} *uap = (struct a *)ttolwp(curthread)->lwp_ap;

	char	*buf;
	int	buflen;
	size_t	size;

	au_uwrite(au_to_arg32(1, "cmd", (uint_t)uap->cmd));
	switch (uap->cmd) {
	case SOCKCONFIG_ADD_SOCK:
	case SOCKCONFIG_REMOVE_SOCK:
		au_uwrite(au_to_arg32(2, "domain", (uint32_t)uap->arg1));
		au_uwrite(au_to_arg32(3, "type", (uint32_t)uap->arg2));
		au_uwrite(au_to_arg32(4, "protocol", (uint32_t)uap->arg3));

		if (uap->arg4 == 0) {
			au_uwrite(au_to_arg32(5, "devpath", (uint32_t)0));
		} else {
			buflen = MAXPATHLEN + 1;
			buf = kmem_alloc(buflen, KM_SLEEP);
			if (copyinstr((caddr_t)uap->arg4, buf, buflen,
			    &size)) {
				kmem_free(buf, buflen);
				return;
			}

			if (size > MAXPATHLEN) {
				kmem_free(buf, buflen);
				return;
			}

			au_uwrite(au_to_text(buf));
			kmem_free(buf, buflen);
		}
		break;
	case SOCKCONFIG_ADD_FILTER:
	case SOCKCONFIG_REMOVE_FILTER:
		buflen = FILNAME_MAX;
		buf = kmem_alloc(buflen, KM_SLEEP);

		if (copyinstr((caddr_t)uap->arg1, buf, buflen, &size)) {
			kmem_free(buf, buflen);
			return;
		}

		au_uwrite(au_to_text(buf));
		kmem_free(buf, buflen);
		break;
	default:
		break;
	}
}

/*
 * only audit recvmsg when the system call represents the creation of a new
 * circuit. This effectively occurs for all UDP packets and may occur for
 * special TCP situations where the local host has not set a local address
 * in the socket structure.
 */
/*ARGSUSED*/
static void
auf_recvmsg(
	struct t_audit_data *tad,
	int error,
	rval_t *rvp)
{
	struct a {
		long	fd;
		long	msg;	/* struct msghdr */
		long	flags;
	} *uap = (struct a *)ttolwp(curthread)->lwp_ap;

	struct sonode	*so;
	STRUCT_DECL(msghdr, msg);
	caddr_t msg_name;
	socklen_t msg_namelen;
	int fd;
	int err;
	char so_laddr[sizeof (struct sockaddr_in6)];
	char so_faddr[sizeof (struct sockaddr_in6)];
	socklen_t len;
	file_t *fp;				/* unix domain sockets */
	struct f_audit_data *fad;		/* unix domain sockets */
	short so_family, so_type;
	int add_sock_token = 0;
	au_kcontext_t	*kctx = GET_KCTX_PZ;

	fd = (int)uap->fd;

	/* bail if an error */
	if (error) {
		au_uwrite(au_to_arg32(1, "so", (uint32_t)fd));
		au_uwrite(au_to_arg32(3, "flags", (uint32_t)(uap->flags)));
		return;
	}

	if ((so = getsonode(fd, &err, &fp)) == NULL) {
		/*
		 * not security relevant if doing a recvmsg from non socket
		 * so no extra tokens. Should probably turn off audit record
		 * generation here.
		 */
		return;
	}

	so_family = so->so_family;
	so_type   = so->so_type;

	/*
	 * only putout SOCKET_EX token if INET/INET6 family.
	 * XXX - what do we do about other families?
	 */

	switch (so_family) {
	case AF_INET:
	case AF_INET6:

		/*
		 * if datagram type socket, then just use what is in
		 * socket structure for local address.
		 * XXX - what do we do for other types?
		 */
		if ((so->so_type == SOCK_DGRAM) ||
		    (so->so_type == SOCK_RAW)) {
			add_sock_token = 1;

			bzero((void *)so_laddr, sizeof (so_laddr));
			bzero((void *)so_faddr, sizeof (so_faddr));

			/* get local address */
			len = sizeof (so_laddr);
			(void) socket_getsockname(so,
			    (struct sockaddr *)so_laddr, &len, CRED());

			/* get peer address */
			STRUCT_INIT(msg, get_udatamodel());

			if (copyin((caddr_t)(uap->msg),
			    (caddr_t)STRUCT_BUF(msg), STRUCT_SIZE(msg)) != 0) {
				break;
			}
			msg_name = (caddr_t)STRUCT_FGETP(msg, msg_name);
			if (msg_name == NULL) {
				break;
			}

			/* length is value from recvmsg - sanity check */
			msg_namelen = (socklen_t)STRUCT_FGET(msg, msg_namelen);
			if (msg_namelen == 0) {
				break;
			}
			if (copyin(msg_name, so_faddr,
			    sizeof (so_faddr)) != 0) {
				break;
			}

		} else if (so->so_type == SOCK_STREAM) {

			/* get path from file struct here */
			fad = F2A(fp);
			ASSERT(fad);

			/*
			 * already processed this file for read attempt
			 */
			if (fad->fad_flags & FAD_READ) {
				/* don't want to audit every recvmsg attempt */
				tad->tad_flag = 0;
				/* free any residual audit data */
				au_close(kctx, &(u_ad), 0, 0, 0, NULL);
				releasef(fd);
				return;
			}
			/*
			 * mark things so we know what happened and don't
			 * repeat things
			 */
			fad->fad_flags |= FAD_READ;

			bzero((void *)so_laddr, sizeof (so_laddr));
			bzero((void *)so_faddr, sizeof (so_faddr));

			/* get local and foreign addresses */
			len = sizeof (so_laddr);
			(void) socket_getsockname(so,
			    (struct sockaddr *)so_laddr, &len, CRED());
			len = sizeof (so_faddr);
			(void) socket_getpeername(so,
			    (struct sockaddr *)so_faddr, &len, B_FALSE, CRED());

			add_sock_token = 1;
		}

		/* XXX - what about SOCK_RDM/SOCK_SEQPACKET ??? */

		break;

	case AF_UNIX:
		/*
		 * first check if this is first time through. Too much
		 * duplicate code to put this in an aui_ routine.
		 */

		/* get path from file struct here */
		fad = F2A(fp);
		ASSERT(fad);

		/*
		 * already processed this file for read attempt
		 */
		if (fad->fad_flags & FAD_READ) {
			releasef(fd);
			/* don't want to audit every recvmsg attempt */
			tad->tad_flag = 0;
			/* free any residual audit data */
			au_close(kctx, &(u_ad), 0, 0, 0, NULL);
			return;
		}
		/*
		 * mark things so we know what happened and don't
		 * repeat things
		 */
		fad->fad_flags |= FAD_READ;

		if (fad->fad_aupath != NULL) {
			au_uwrite(au_to_path(fad->fad_aupath));
		} else {
			au_uwrite(au_to_arg32(1, "no path: fd", fd));
		}

		audit_attributes(fp->f_vnode);

		releasef(fd);

		return;

	default:
		break;

	}

	releasef(fd);

	au_uwrite(au_to_arg32(1, "so", (uint32_t)fd));

	if (add_sock_token == 0) {
		au_uwrite(au_to_arg32(1, "family", (uint32_t)so_family));
		au_uwrite(au_to_arg32(1, "type", (uint32_t)so_type));
		au_uwrite(au_to_arg32(3, "flags", (uint32_t)(uap->flags)));
		return;
	}

	au_uwrite(au_to_arg32(3, "flags", (uint32_t)(uap->flags)));

	au_uwrite(au_to_socket_ex(so_family, so_type, so_laddr, so_faddr));

}

/*ARGSUSED*/
static void
auf_recvfrom(
	struct t_audit_data *tad,
	int error,
	rval_t *rvp)
{

	struct a {
		long	fd;
		long	msg;	/* char */
		long	len;
		long	flags;
		long	from;	/* struct sockaddr */
		long	fromlen;
	} *uap = (struct a *)ttolwp(curthread)->lwp_ap;

	socklen_t	fromlen;
	struct sonode	*so;
	char so_laddr[sizeof (struct sockaddr_in6)];
	char so_faddr[sizeof (struct sockaddr_in6)];
	int		fd;
	short so_family, so_type;
	int add_sock_token = 0;
	socklen_t len;
	int err;
	struct file *fp;
	struct f_audit_data *fad;		/* unix domain sockets */
	au_kcontext_t	*kctx = GET_KCTX_PZ;

	fd = (int)uap->fd;

	/* bail if an error */
	if (error) {
		au_uwrite(au_to_arg32(1, "so", (uint32_t)fd));
		au_uwrite(au_to_arg32(3, "flags", (uint32_t)(uap->flags)));
		return;
	}

	if ((so = getsonode(fd, &err, &fp)) == NULL) {
		/*
		 * not security relevant if doing a recvmsg from non socket
		 * so no extra tokens. Should probably turn off audit record
		 * generation here.
		 */
		return;
	}

	so_family = so->so_family;
	so_type   = so->so_type;

	/*
	 * only putout SOCKET_EX token if INET/INET6 family.
	 * XXX - what do we do about other families?
	 */

	switch (so_family) {
	case AF_INET:
	case AF_INET6:

		/*
		 * if datagram type socket, then just use what is in
		 * socket structure for local address.
		 * XXX - what do we do for other types?
		 */
		if ((so->so_type == SOCK_DGRAM) ||
		    (so->so_type == SOCK_RAW)) {
			add_sock_token = 1;

			/* get local address */
			len = sizeof (so_laddr);
			(void) socket_getsockname(so,
			    (struct sockaddr *)so_laddr, &len, CRED());

			/* get peer address */
			bzero((void *)so_faddr, sizeof (so_faddr));

			/* sanity check */
			if (uap->from == NULL)
				break;

			/* sanity checks */
			if (uap->fromlen == 0)
				break;

			if (copyin((caddr_t)(uap->fromlen), (caddr_t)&fromlen,
			    sizeof (fromlen)) != 0)
				break;

			if (fromlen == 0)
				break;

			/* enforce maximum size */
			if (fromlen > sizeof (so_faddr))
				fromlen = sizeof (so_faddr);

			if (copyin((caddr_t)(uap->from), so_faddr,
			    fromlen) != 0)
				break;

		} else if (so->so_type == SOCK_STREAM) {

			/* get path from file struct here */
			fad = F2A(fp);
			ASSERT(fad);

			/*
			 * already processed this file for read attempt
			 */
			if (fad->fad_flags & FAD_READ) {
				/* don't want to audit every recvfrom attempt */
				tad->tad_flag = 0;
				/* free any residual audit data */
				au_close(kctx, &(u_ad), 0, 0, 0, NULL);
				releasef(fd);
				return;
			}
			/*
			 * mark things so we know what happened and don't
			 * repeat things
			 */
			fad->fad_flags |= FAD_READ;

			bzero((void *)so_laddr, sizeof (so_laddr));
			bzero((void *)so_faddr, sizeof (so_faddr));

			/* get local and foreign addresses */
			len = sizeof (so_laddr);
			(void) socket_getsockname(so,
			    (struct sockaddr *)so_laddr, &len, CRED());
			len = sizeof (so_faddr);
			(void) socket_getpeername(so,
			    (struct sockaddr *)so_faddr, &len, B_FALSE, CRED());

			add_sock_token = 1;
		}

		/* XXX - what about SOCK_RDM/SOCK_SEQPACKET ??? */

		break;

	case AF_UNIX:
		/*
		 * first check if this is first time through. Too much
		 * duplicate code to put this in an aui_ routine.
		 */

		/* get path from file struct here */
		fad = F2A(fp);
		ASSERT(fad);

		/*
		 * already processed this file for read attempt
		 */
		if (fad->fad_flags & FAD_READ) {
			/* don't want to audit every recvfrom attempt */
			tad->tad_flag = 0;
			/* free any residual audit data */
			au_close(kctx, &(u_ad), 0, 0, 0, NULL);
			releasef(fd);
			return;
		}
		/*
		 * mark things so we know what happened and don't
		 * repeat things
		 */
		fad->fad_flags |= FAD_READ;

		if (fad->fad_aupath != NULL) {
			au_uwrite(au_to_path(fad->fad_aupath));
		} else {
			au_uwrite(au_to_arg32(1, "no path: fd", fd));
		}

		audit_attributes(fp->f_vnode);

		releasef(fd);

		return;

	default:
		break;

	}

	releasef(fd);

	au_uwrite(au_to_arg32(1, "so", (uint32_t)fd));

	if (add_sock_token == 0) {
		au_uwrite(au_to_arg32(1, "family", (uint32_t)so_family));
		au_uwrite(au_to_arg32(1, "type", (uint32_t)so_type));
		au_uwrite(au_to_arg32(3, "flags", (uint32_t)(uap->flags)));
		return;
	}

	au_uwrite(au_to_arg32(3, "flags", (uint32_t)(uap->flags)));

	au_uwrite(au_to_socket_ex(so_family, so_type, so_laddr, so_faddr));
}

/*ARGSUSED*/
static void
auf_sendmsg(struct t_audit_data *tad, int error, rval_t *rval)
{
	struct a {
		long	fd;
		long	msg;	/* struct msghdr */
		long	flags;
	} *uap = (struct a *)ttolwp(curthread)->lwp_ap;

	struct sonode	*so;
	char so_laddr[sizeof (struct sockaddr_in6)];
	char so_faddr[sizeof (struct sockaddr_in6)];
	int		err;
	int		fd;
	short so_family, so_type;
	int		add_sock_token = 0;
	socklen_t	len;
	struct file	*fp;
	struct f_audit_data *fad;
	caddr_t		msg_name;
	socklen_t	msg_namelen;
	STRUCT_DECL(msghdr, msg);
	au_kcontext_t	*kctx = GET_KCTX_PZ;

	fd = (int)uap->fd;

	/* bail if an error */
	if (error) {
		/* XXX include destination address from system call arguments */
		au_uwrite(au_to_arg32(1, "so", (uint32_t)fd));
		au_uwrite(au_to_arg32(3, "flags", (uint32_t)(uap->flags)));
		return;
	}

	if ((so = getsonode(fd, &err, &fp)) == NULL) {
		/*
		 * not security relevant if doing a sendmsg from non socket
		 * so no extra tokens. Should probably turn off audit record
		 * generation here.
		 */
		return;
	}

	so_family = so->so_family;
	so_type   = so->so_type;

	switch (so_family) {
	case AF_INET:
	case AF_INET6:
		/*
		 * if datagram type socket, then just use what is in
		 * socket structure for local address.
		 * XXX - what do we do for other types?
		 */
		if ((so->so_type == SOCK_DGRAM) ||
		    (so->so_type == SOCK_RAW)) {

			bzero((void *)so_laddr, sizeof (so_laddr));
			bzero((void *)so_faddr, sizeof (so_faddr));

			/* get local address */
			len = sizeof (so_laddr);
			(void) socket_getsockname(so,
			    (struct sockaddr *)so_laddr, &len, CRED());

			/* get peer address */
			STRUCT_INIT(msg, get_udatamodel());

			if (copyin((caddr_t)(uap->msg),
			    (caddr_t)STRUCT_BUF(msg), STRUCT_SIZE(msg)) != 0) {
				break;
			}
			msg_name = (caddr_t)STRUCT_FGETP(msg, msg_name);
			if (msg_name == NULL)
				break;

			msg_namelen = (socklen_t)STRUCT_FGET(msg, msg_namelen);
			/* length is value from recvmsg - sanity check */
			if (msg_namelen == 0)
				break;

			if (copyin(msg_name, so_faddr,
			    sizeof (so_faddr)) != 0)
				break;

			add_sock_token = 1;

		} else if (so->so_type == SOCK_STREAM) {

			/* get path from file struct here */
			fad = F2A(fp);
			ASSERT(fad);

			/*
			 * already processed this file for write attempt
			 */
			if (fad->fad_flags & FAD_WRITE) {
				releasef(fd);
				/* don't want to audit every sendmsg attempt */
				tad->tad_flag = 0;
				/* free any residual audit data */
				au_close(kctx, &(u_ad), 0, 0, 0, NULL);
				return;
			}

			/*
			 * mark things so we know what happened and don't
			 * repeat things
			 */
			fad->fad_flags |= FAD_WRITE;

			bzero((void *)so_laddr, sizeof (so_laddr));
			bzero((void *)so_faddr, sizeof (so_faddr));

			/* get local and foreign addresses */
			len = sizeof (so_laddr);
			(void) socket_getsockname(so,
			    (struct sockaddr *)so_laddr, &len, CRED());
			len = sizeof (so_faddr);
			(void) socket_getpeername(so,
			    (struct sockaddr *)so_faddr, &len, B_FALSE, CRED());

			add_sock_token = 1;
		}

		/* XXX - what about SOCK_RAW/SOCK_RDM/SOCK_SEQPACKET ??? */

		break;

	case AF_UNIX:
		/*
		 * first check if this is first time through. Too much
		 * duplicate code to put this in an aui_ routine.
		 */

		/* get path from file struct here */
		fad = F2A(fp);
		ASSERT(fad);

		/*
		 * already processed this file for write attempt
		 */
		if (fad->fad_flags & FAD_WRITE) {
			releasef(fd);
			/* don't want to audit every sendmsg attempt */
			tad->tad_flag = 0;
			/* free any residual audit data */
			au_close(kctx, &(u_ad), 0, 0, 0, NULL);
			return;
		}
		/*
		 * mark things so we know what happened and don't
		 * repeat things
		 */
		fad->fad_flags |= FAD_WRITE;

		if (fad->fad_aupath != NULL) {
			au_uwrite(au_to_path(fad->fad_aupath));
		} else {
			au_uwrite(au_to_arg32(1, "no path: fd", fd));
		}

		audit_attributes(fp->f_vnode);

		releasef(fd);

		return;

	default:
		break;
	}

	releasef(fd);

	au_uwrite(au_to_arg32(1, "so", (uint32_t)fd));

	if (add_sock_token == 0) {
		au_uwrite(au_to_arg32(1, "family", (uint32_t)so_family));
		au_uwrite(au_to_arg32(1, "type", (uint32_t)so_type));
		au_uwrite(au_to_arg32(3, "flags", (uint32_t)(uap->flags)));
		return;
	}

	au_uwrite(au_to_arg32(3, "flags", (uint32_t)(uap->flags)));

	au_uwrite(au_to_socket_ex(so_family, so_type, so_laddr, so_faddr));
}

/*ARGSUSED*/
static void
auf_sendto(struct t_audit_data *tad, int error, rval_t *rval)
{
	struct a {
		long	fd;
		long	msg;	/* char */
		long	len;
		long	flags;
		long	to;	/* struct sockaddr */
		long	tolen;
	} *uap = (struct a *)ttolwp(curthread)->lwp_ap;

	struct sonode	*so;
	char so_laddr[sizeof (struct sockaddr_in6)];
	char so_faddr[sizeof (struct sockaddr_in6)];
	socklen_t	tolen;
	int		err;
	int		fd;
	socklen_t	len;
	short so_family, so_type;
	int		add_sock_token = 0;
	struct file	*fp;
	struct f_audit_data *fad;
	au_kcontext_t	*kctx = GET_KCTX_PZ;

	fd = (int)uap->fd;

	/* bail if an error */
	if (error) {
		au_uwrite(au_to_arg32(1, "so", (uint32_t)fd));
		au_uwrite(au_to_arg32(3, "flags", (uint32_t)(uap->flags)));
		/* XXX include destination address from system call arguments */
		return;
	}

	if ((so = getsonode(fd, &err, &fp)) == NULL) {
		/*
		 * not security relevant if doing a sendto using non socket
		 * so no extra tokens. Should probably turn off audit record
		 * generation here.
		 */
		return;
	}

	so_family = so->so_family;
	so_type   = so->so_type;

	/*
	 * only putout SOCKET_EX token if INET/INET6 family.
	 * XXX - what do we do about other families?
	 */

	switch (so_family) {
	case AF_INET:
	case AF_INET6:

		/*
		 * if datagram type socket, then just use what is in
		 * socket structure for local address.
		 * XXX - what do we do for other types?
		 */
		if ((so->so_type == SOCK_DGRAM) ||
		    (so->so_type == SOCK_RAW)) {

			bzero((void *)so_laddr, sizeof (so_laddr));
			bzero((void *)so_faddr, sizeof (so_faddr));

			/* get local address */
			len = sizeof (so_laddr);
			(void) socket_getsockname(so,
			    (struct sockaddr *)so_laddr, &len, CRED());

			/* get peer address */

			/* sanity check */
			if (uap->to == NULL)
				break;

			/* sanity checks */
			if (uap->tolen == 0)
				break;

			tolen = (socklen_t)uap->tolen;

			/* enforce maximum size */
			if (tolen > sizeof (so_faddr))
				tolen = sizeof (so_faddr);

			if (copyin((caddr_t)(uap->to), so_faddr, tolen) != 0)
				break;

			add_sock_token = 1;
		} else {
			/*
			 * check if this is first time through.
			 */

			/* get path from file struct here */
			fad = F2A(fp);
			ASSERT(fad);

			/*
			 * already processed this file for write attempt
			 */
			if (fad->fad_flags & FAD_WRITE) {
				/* don't want to audit every sendto attempt */
				tad->tad_flag = 0;
				/* free any residual audit data */
				au_close(kctx, &(u_ad), 0, 0, 0, NULL);
				releasef(fd);
				return;
			}
			/*
			 * mark things so we know what happened and don't
			 * repeat things
			 */
			fad->fad_flags |= FAD_WRITE;

			bzero((void *)so_laddr, sizeof (so_laddr));
			bzero((void *)so_faddr, sizeof (so_faddr));

			/* get local and foreign addresses */
			len = sizeof (so_laddr);
			(void) socket_getsockname(so,
			    (struct sockaddr *)so_laddr, &len, CRED());
			len = sizeof (so_faddr);
			(void) socket_getpeername(so,
			    (struct sockaddr *)so_faddr, &len, B_FALSE, CRED());

			add_sock_token = 1;
		}

		/* XXX - what about SOCK_RDM/SOCK_SEQPACKET ??? */

		break;

	case AF_UNIX:
		/*
		 * first check if this is first time through. Too much
		 * duplicate code to put this in an aui_ routine.
		 */

		/* get path from file struct here */
		fad = F2A(fp);
		ASSERT(fad);

		/*
		 * already processed this file for write attempt
		 */
		if (fad->fad_flags & FAD_WRITE) {
			/* don't want to audit every sendto attempt */
			tad->tad_flag = 0;
			/* free any residual audit data */
			au_close(kctx, &(u_ad), 0, 0, 0, NULL);
			releasef(fd);
			return;
		}
		/*
		 * mark things so we know what happened and don't
		 * repeat things
		 */
		fad->fad_flags |= FAD_WRITE;

		if (fad->fad_aupath != NULL) {
			au_uwrite(au_to_path(fad->fad_aupath));
		} else {
			au_uwrite(au_to_arg32(1, "no path: fd", fd));
		}

		audit_attributes(fp->f_vnode);

		releasef(fd);

		return;

	default:
		break;

	}

	releasef(fd);

	au_uwrite(au_to_arg32(1, "so", (uint32_t)fd));

	if (add_sock_token == 0) {
		au_uwrite(au_to_arg32(1, "family", (uint32_t)so_family));
		au_uwrite(au_to_arg32(1, "type", (uint32_t)so_type));
		au_uwrite(au_to_arg32(3, "flags", (uint32_t)(uap->flags)));
		return;
	}

	au_uwrite(au_to_arg32(3, "flags", (uint32_t)(uap->flags)));

	au_uwrite(au_to_socket_ex(so_family, so_type, so_laddr, so_faddr));

}

/*
 * XXX socket(2) may be equivalent to open(2) on a unix domain
 * socket. This needs investigation.
 */

/*ARGSUSED*/
static void
aus_socket(struct t_audit_data *tad)
{
	struct a {
		long	domain;
		long	type;
		long	protocol;
	} *uap = (struct a *)ttolwp(curthread)->lwp_ap;

	au_uwrite(au_to_arg32(1, "domain", (uint32_t)uap->domain));
	au_uwrite(au_to_arg32(2, "type", (uint32_t)uap->type));
	au_uwrite(au_to_arg32(3, "protocol", (uint32_t)uap->protocol));
}

/*ARGSUSED*/
static void
aus_sigqueue(struct t_audit_data *tad)
{
	struct a {
		long	pid;
		long	signo;
		long	*val;
	} *uap = (struct a *)ttolwp(curthread)->lwp_ap;
	struct proc *p;
	uid_t uid, ruid;
	gid_t gid, rgid;
	pid_t pid;
	const auditinfo_addr_t *ainfo;
	cred_t *cr;

	pid = (pid_t)uap->pid;

	au_uwrite(au_to_arg32(2, "signal", (uint32_t)uap->signo));
	if (pid > 0) {
		mutex_enter(&pidlock);
		if ((p = prfind(pid)) == (struct proc *)0) {
			mutex_exit(&pidlock);
			return;
		}
		mutex_enter(&p->p_lock); /* so process doesn't go away */
		mutex_exit(&pidlock);

		mutex_enter(&p->p_crlock);
		crhold(cr = p->p_cred);
		mutex_exit(&p->p_crlock);
		mutex_exit(&p->p_lock);

		ainfo = crgetauinfo(cr);
		if (ainfo == NULL) {
			crfree(cr);
			return;
		}

		uid  = crgetuid(cr);
		gid  = crgetgid(cr);
		ruid = crgetruid(cr);
		rgid = crgetrgid(cr);
		au_uwrite(au_to_process(uid, gid, ruid, rgid, pid,
		    ainfo->ai_auid, ainfo->ai_asid, &ainfo->ai_termid));
		crfree(cr);
	}
	else
		au_uwrite(au_to_arg32(1, "process ID", (uint32_t)pid));
}

/*ARGSUSED*/
static void
aus_inst_sync(struct t_audit_data *tad)
{
	struct a {
		long	name;	/* char */
		long	flags;
	} *uap = (struct a *)ttolwp(curthread)->lwp_ap;

	au_uwrite(au_to_arg32(2, "flags", (uint32_t)uap->flags));
}

/*ARGSUSED*/
static void
aus_brandsys(struct t_audit_data *tad)
{
	klwp_t *clwp = ttolwp(curthread);

	struct a {
		long	cmd;
		long	arg1;
		long	arg2;
		long	arg3;
		long	arg4;
		long	arg5;
		long	arg6;
	} *uap = (struct a *)clwp->lwp_ap;

	au_uwrite(au_to_arg32(1, "cmd", (uint_t)uap->cmd));
#ifdef _LP64
	au_uwrite(au_to_arg64(2, "arg1", (uint64_t)uap->arg1));
	au_uwrite(au_to_arg64(3, "arg2", (uint64_t)uap->arg2));
	au_uwrite(au_to_arg64(4, "arg3", (uint64_t)uap->arg3));
	au_uwrite(au_to_arg64(5, "arg4", (uint64_t)uap->arg4));
	au_uwrite(au_to_arg64(6, "arg5", (uint64_t)uap->arg5));
	au_uwrite(au_to_arg64(7, "arg6", (uint64_t)uap->arg6));
#else
	au_uwrite(au_to_arg32(2, "arg1", (uint32_t)uap->arg1));
	au_uwrite(au_to_arg32(3, "arg2", (uint32_t)uap->arg2));
	au_uwrite(au_to_arg32(4, "arg3", (uint32_t)uap->arg3));
	au_uwrite(au_to_arg32(5, "arg4", (uint32_t)uap->arg4));
	au_uwrite(au_to_arg32(6, "arg5", (uint32_t)uap->arg5));
	au_uwrite(au_to_arg32(7, "arg6", (uint32_t)uap->arg6));
#endif
}

/*ARGSUSED*/
static void
aus_p_online(struct t_audit_data *tad)
{
	struct a {
		long	processor_id;
		long	flag;
	} *uap = (struct a *)ttolwp(curthread)->lwp_ap;

	struct flags {
			int	flag;
			char	*cflag;
	} aflags[6] = {
			{ P_ONLINE, "P_ONLINE"},
			{ P_OFFLINE, "P_OFFLINE"},
			{ P_NOINTR, "P_NOINTR"},
			{ P_SPARE, "P_SPARE"},
			{ P_FAULTED, "P_FAULTED"},
			{ P_STATUS, "P_STATUS"}
	};
	int i;
	char *cflag;

	au_uwrite(au_to_arg32(1, "processor ID", (uint32_t)uap->processor_id));
	au_uwrite(au_to_arg32(2, "flag", (uint32_t)uap->flag));

	for (i = 0; i < 6; i++) {
		if (aflags[i].flag == uap->flag)
			break;
	}
	cflag = (i == 6) ? "bad flag":aflags[i].cflag;

	au_uwrite(au_to_text(cflag));
}

/*ARGSUSED*/
static void
aus_processor_bind(struct t_audit_data *tad)
{
	struct a {
		long	id_type;
		long	id;
		long	processor_id;
		long	obind;
	} *uap = (struct a *)ttolwp(curthread)->lwp_ap;

	struct proc *p;
	int lwpcnt;
	uid_t uid, ruid;
	gid_t gid, rgid;
	pid_t pid;
	const auditinfo_addr_t *ainfo;
	cred_t *cr;

	au_uwrite(au_to_arg32(1, "ID type", (uint32_t)uap->id_type));
	au_uwrite(au_to_arg32(2, "ID", (uint32_t)uap->id));
	if (uap->processor_id == PBIND_NONE)
		au_uwrite(au_to_text("PBIND_NONE"));
	else
		au_uwrite(au_to_arg32(3, "processor_id",
		    (uint32_t)uap->processor_id));

	switch (uap->id_type) {
	case P_MYID:
	case P_LWPID:
		mutex_enter(&pidlock);
		p = ttoproc(curthread);
		if (p == NULL || p->p_as == &kas) {
			mutex_exit(&pidlock);
			return;
		}
		mutex_enter(&p->p_lock);
		mutex_exit(&pidlock);
		lwpcnt = p->p_lwpcnt;
		pid  = p->p_pid;

		mutex_enter(&p->p_crlock);
		crhold(cr = p->p_cred);
		mutex_exit(&p->p_crlock);
		mutex_exit(&p->p_lock);

		ainfo = crgetauinfo(cr);
		if (ainfo == NULL) {
			crfree(cr);
			return;
		}

		uid  = crgetuid(cr);
		gid  = crgetgid(cr);
		ruid = crgetruid(cr);
		rgid = crgetrgid(cr);
		au_uwrite(au_to_process(uid, gid, ruid, rgid, pid,
		    ainfo->ai_auid, ainfo->ai_asid, &ainfo->ai_termid));
		crfree(cr);
		break;
	case P_PID:
		mutex_enter(&pidlock);
		p = prfind(uap->id);
		if (p == NULL || p->p_as == &kas) {
			mutex_exit(&pidlock);
			return;
		}
		mutex_enter(&p->p_lock);
		mutex_exit(&pidlock);
		lwpcnt = p->p_lwpcnt;
		pid  = p->p_pid;

		mutex_enter(&p->p_crlock);
		crhold(cr = p->p_cred);
		mutex_exit(&p->p_crlock);
		mutex_exit(&p->p_lock);

		ainfo = crgetauinfo(cr);
		if (ainfo == NULL) {
			crfree(cr);
			return;
		}

		uid  = crgetuid(cr);
		gid  = crgetgid(cr);
		ruid = crgetruid(cr);
		rgid = crgetrgid(cr);
		au_uwrite(au_to_process(uid, gid, ruid, rgid, pid,
		    ainfo->ai_auid, ainfo->ai_asid, &ainfo->ai_termid));
		crfree(cr);

		break;
	default:
		return;
	}

	if (uap->processor_id == PBIND_NONE &&
	    (!(uap->id_type == P_LWPID && lwpcnt > 1)))
		au_uwrite(au_to_text("PBIND_NONE for process"));
	else
		au_uwrite(au_to_arg32(3, "processor_id",
		    (uint32_t)uap->processor_id));
}

/*ARGSUSED*/
static au_event_t
aui_doorfs(au_event_t e)
{
	uint32_t code;

	struct a {		/* doorfs */
		long	a1;
		long	a2;
		long	a3;
		long	a4;
		long	a5;
		long	code;
	} *uap = (struct a *)ttolwp(curthread)->lwp_ap;

	/*
	 *	audit formats for several of the
	 *	door calls have not yet been determined
	 */
	code = (uint32_t)uap->code;
	switch (code) {
	case DOOR_CALL:
		e = AUE_DOORFS_DOOR_CALL;
		break;
	case DOOR_RETURN:
		e = AUE_NULL;
		break;
	case DOOR_CREATE:
		e = AUE_DOORFS_DOOR_CREATE;
		break;
	case DOOR_REVOKE:
		e = AUE_DOORFS_DOOR_REVOKE;
		break;
	case DOOR_INFO:
		e = AUE_NULL;
		break;
	case DOOR_UCRED:
		e = AUE_NULL;
		break;
	case DOOR_BIND:
		e = AUE_NULL;
		break;
	case DOOR_UNBIND:
		e = AUE_NULL;
		break;
	case DOOR_GETPARAM:
		e = AUE_NULL;
		break;
	case DOOR_SETPARAM:
		e = AUE_NULL;
		break;
	default:	/* illegal system call */
		e = AUE_NULL;
		break;
	}

	return (e);
}

static door_node_t *
au_door_lookup(int did)
{
	vnode_t	*vp;
	file_t *fp;

	if ((fp = getf(did)) == NULL)
		return (NULL);
	/*
	 * Use the underlying vnode (we may be namefs mounted)
	 */
	if (VOP_REALVP(fp->f_vnode, &vp, NULL))
		vp = fp->f_vnode;

	if (vp == NULL || vp->v_type != VDOOR) {
		releasef(did);
		return (NULL);
	}

	return (VTOD(vp));
}

/*ARGSUSED*/
static void
aus_doorfs(struct t_audit_data *tad)
{

	struct a {		/* doorfs */
		long	a1;
		long	a2;
		long	a3;
		long	a4;
		long	a5;
		long	code;
	} *uap = (struct a *)ttolwp(curthread)->lwp_ap;

	door_node_t	*dp;
	struct proc	*p;
	uint32_t	did;
	uid_t uid, ruid;
	gid_t gid, rgid;
	pid_t pid;
	const auditinfo_addr_t *ainfo;
	cred_t *cr;

	did = (uint32_t)uap->a1;

	switch (tad->tad_event) {
	case AUE_DOORFS_DOOR_CALL:
		au_uwrite(au_to_arg32(1, "door ID", (uint32_t)did));
		if ((dp = au_door_lookup(did)) == NULL)
			break;

		if (DOOR_INVALID(dp)) {
			releasef(did);
			break;
		}

		if ((p = dp->door_target) == NULL) {
			releasef(did);
			break;
		}
		mutex_enter(&p->p_lock);
		releasef(did);

		pid  = p->p_pid;

		mutex_enter(&p->p_crlock);
		crhold(cr = p->p_cred);
		mutex_exit(&p->p_crlock);
		mutex_exit(&p->p_lock);

		ainfo = crgetauinfo(cr);
		if (ainfo == NULL) {
			crfree(cr);
			return;
		}
		uid  = crgetuid(cr);
		gid  = crgetgid(cr);
		ruid = crgetruid(cr);
		rgid = crgetrgid(cr);
		au_uwrite(au_to_process(uid, gid, ruid, rgid, pid,
		    ainfo->ai_auid, ainfo->ai_asid, &ainfo->ai_termid));
		crfree(cr);
		break;
	case AUE_DOORFS_DOOR_RETURN:
		/*
		 * We may want to write information about
		 * all doors (if any) which will be copied
		 * by this call to the user space
		 */
		break;
	case AUE_DOORFS_DOOR_CREATE:
		au_uwrite(au_to_arg32(3, "door attr", (uint32_t)uap->a3));
		break;
	case AUE_DOORFS_DOOR_REVOKE:
		au_uwrite(au_to_arg32(1, "door ID", (uint32_t)did));
		break;
	case AUE_DOORFS_DOOR_INFO:
		break;
	case AUE_DOORFS_DOOR_CRED:
		break;
	case AUE_DOORFS_DOOR_BIND:
		break;
	case AUE_DOORFS_DOOR_UNBIND: {
		break;
	}
	default:	/* illegal system call */
		break;
	}
}

/*ARGSUSED*/
static au_event_t
aui_acl(au_event_t e)
{
	struct a {
		union {
			long	name;	/* char */
			long	fd;
		}		obj;

		long		cmd;
		long		nentries;
		long		arg;	/* aclent_t */
	} *uap = (struct a *)ttolwp(curthread)->lwp_ap;

	switch (uap->cmd) {
	case SETACL:
	case ACE_SETACL:
		/*
		 * acl(SETACL/ACE_SETACL, ...) and facl(SETACL/ACE_SETACL, ...)
		 * are expected.
		 */
		break;
	case GETACL:
	case GETACLCNT:
	case ACE_GETACL:
	case ACE_GETACLCNT:
		/* do nothing for these four values. */
		e = AUE_NULL;
		break;
	default:
		/* illegal system call */
		break;
	}

	return (e);
}

static void
au_acl(int cmd, int nentries, caddr_t bufp)
{
	size_t		a_size;
	aclent_t	*aclbufp;
	ace_t		*acebufp;
	int		i;

	switch (cmd) {
	case GETACL:
	case GETACLCNT:
		break;
	case SETACL:
		if (nentries < 3)
			break;

		a_size = nentries * sizeof (aclent_t);

		if ((aclbufp = kmem_alloc(a_size, KM_SLEEP)) == NULL)
			break;
		if (copyin(bufp, aclbufp, a_size)) {
			kmem_free(aclbufp, a_size);
			break;
		}
		for (i = 0; i < nentries; i++) {
			au_uwrite(au_to_acl(aclbufp + i));
		}
		kmem_free(aclbufp, a_size);
		break;

	case ACE_SETACL:
		if (nentries < 1 || nentries > MAX_ACL_ENTRIES)
			break;

		a_size = nentries * sizeof (ace_t);
		if ((acebufp = kmem_alloc(a_size, KM_SLEEP)) == NULL)
			break;
		if (copyin(bufp, acebufp, a_size)) {
			kmem_free(acebufp, a_size);
			break;
		}
		for (i = 0; i < nentries; i++) {
			au_uwrite(au_to_ace(acebufp + i));
		}
		kmem_free(acebufp, a_size);
		break;
	default:
		break;
	}
}

/*ARGSUSED*/
static void
aus_acl(struct t_audit_data *tad)
{
	struct a {
		long	fname;
		long	cmd;
		long	nentries;
		long	aclbufp;
	} *uap = (struct a *)ttolwp(curthread)->lwp_ap;

	au_uwrite(au_to_arg32(2, "cmd", (uint32_t)uap->cmd));
	au_uwrite(au_to_arg32(3, "nentries", (uint32_t)uap->nentries));

	au_acl(uap->cmd, uap->nentries, (caddr_t)uap->aclbufp);
}

/*ARGSUSED*/
static void
aus_facl(struct t_audit_data *tad)
{
	struct a {
		long	fd;
		long	cmd;
		long	nentries;
		long	aclbufp;
	} *uap = (struct a *)ttolwp(curthread)->lwp_ap;
	struct file  *fp;
	struct vnode *vp;
	struct f_audit_data *fad;
	int fd;

	au_uwrite(au_to_arg32(2, "cmd", (uint32_t)uap->cmd));
	au_uwrite(au_to_arg32(3, "nentries", (uint32_t)uap->nentries));

	fd = (int)uap->fd;

	if ((fp = getf(fd)) == NULL)
		return;

	/* get path from file struct here */
	fad = F2A(fp);
	if (fad->fad_aupath != NULL) {
		au_uwrite(au_to_path(fad->fad_aupath));
	} else {
		au_uwrite(au_to_arg32(1, "no path: fd", (uint32_t)fd));
	}

	vp = fp->f_vnode;
	audit_attributes(vp);

	/* decrement file descriptor reference count */
	releasef(fd);

	au_acl(uap->cmd, uap->nentries, (caddr_t)uap->aclbufp);
}

/*ARGSUSED*/
static void
auf_read(tad, error, rval)
	struct t_audit_data *tad;
	int error;
	rval_t *rval;
{
	struct file *fp;
	struct f_audit_data *fad;
	int fd;
	register struct a {
		long	fd;
	} *uap = (struct a *)ttolwp(curthread)->lwp_ap;
	au_kcontext_t	*kctx = GET_KCTX_PZ;

	fd = (int)uap->fd;

	/*
	 * convert file pointer to file descriptor
	 *   Note: fd ref count incremented here.
	 */
	if ((fp = getf(fd)) == NULL)
		return;

	/* get path from file struct here */
	fad = F2A(fp);
	ASSERT(fad);

	/*
	 * already processed this file for read attempt
	 *
	 * XXX might be better to turn off auditing in a aui_read() routine.
	 */
	if (fad->fad_flags & FAD_READ) {
		/* don't really want to audit every read attempt */
		tad->tad_flag = 0;
		/* free any residual audit data */
		au_close(kctx, &(u_ad), 0, 0, 0, NULL);
		releasef(fd);
		return;
	}
	/* mark things so we know what happened and don't repeat things */
	fad->fad_flags |= FAD_READ;

	if (fad->fad_aupath != NULL) {
		au_uwrite(au_to_path(fad->fad_aupath));
	} else {
		au_uwrite(au_to_arg32(1, "no path: fd", (uint32_t)fd));
	}

	/* include attributes */
	audit_attributes(fp->f_vnode);

	/* decrement file descriptor reference count */
	releasef(fd);
}

/*ARGSUSED*/
static void
auf_write(tad, error, rval)
	struct t_audit_data *tad;
	int error;
	rval_t *rval;
{
	struct file *fp;
	struct f_audit_data *fad;
	int fd;
	register struct a {
		long	fd;
	} *uap = (struct a *)ttolwp(curthread)->lwp_ap;
	au_kcontext_t	*kctx = GET_KCTX_PZ;

	fd = (int)uap->fd;

	/*
	 * convert file pointer to file descriptor
	 *   Note: fd ref count incremented here.
	 */
	if ((fp = getf(fd)) == NULL)
		return;

	/* get path from file struct here */
	fad = F2A(fp);
	ASSERT(fad);

	/*
	 * already processed this file for write attempt
	 *
	 * XXX might be better to turn off auditing in a aus_write() routine.
	 */
	if (fad->fad_flags & FAD_WRITE) {
		/* don't really want to audit every write attempt */
		tad->tad_flag = 0;
		/* free any residual audit data */
		au_close(kctx, &(u_ad), 0, 0, 0, NULL);
		releasef(fd);
		return;
	}
	/* mark things so we know what happened and don't repeat things */
	fad->fad_flags |= FAD_WRITE;

	if (fad->fad_aupath != NULL) {
		au_uwrite(au_to_path(fad->fad_aupath));
	} else {
		au_uwrite(au_to_arg32(1, "no path: fd", (uint32_t)fd));
	}

	/* include attributes */
	audit_attributes(fp->f_vnode);

	/* decrement file descriptor reference count */
	releasef(fd);
}

/*ARGSUSED*/
static void
auf_recv(tad, error, rval)
	struct t_audit_data *tad;
	int error;
	rval_t *rval;
{
	struct sonode *so;
	char so_laddr[sizeof (struct sockaddr_in6)];
	char so_faddr[sizeof (struct sockaddr_in6)];
	struct file *fp;
	struct f_audit_data *fad;
	int fd;
	int err;
	socklen_t len;
	short so_family, so_type;
	register struct a {
		long	fd;
	} *uap = (struct a *)ttolwp(curthread)->lwp_ap;
	au_kcontext_t	*kctx = GET_KCTX_PZ;

	/*
	 * If there was an error, then nothing to do. Only generate
	 * audit record on first successful recv.
	 */
	if (error) {
		/* Turn off audit record generation here. */
		tad->tad_flag = 0;
		/* free any residual audit data */
		au_close(kctx, &(u_ad), 0, 0, 0, NULL);
		return;
	}

	fd = (int)uap->fd;

	if ((so = getsonode(fd, &err, &fp)) == NULL) {
		/* Turn off audit record generation here. */
		tad->tad_flag = 0;
		/* free any residual audit data */
		au_close(kctx, &(u_ad), 0, 0, 0, NULL);
		return;
	}

	/* get path from file struct here */
	fad = F2A(fp);
	ASSERT(fad);

	/*
	 * already processed this file for read attempt
	 */
	if (fad->fad_flags & FAD_READ) {
		releasef(fd);
		/* don't really want to audit every recv call */
		tad->tad_flag = 0;
		/* free any residual audit data */
		au_close(kctx, &(u_ad), 0, 0, 0, NULL);
		return;
	}

	/* mark things so we know what happened and don't repeat things */
	fad->fad_flags |= FAD_READ;

	so_family = so->so_family;
	so_type   = so->so_type;

	switch (so_family) {
	case AF_INET:
	case AF_INET6:
		/*
		 * Only for connections.
		 * XXX - do we need to worry about SOCK_DGRAM or other types???
		 */
		if (so->so_state & SS_ISBOUND) {

			bzero((void *)so_laddr, sizeof (so_laddr));
			bzero((void *)so_faddr, sizeof (so_faddr));

			/* get local and foreign addresses */
			len = sizeof (so_laddr);
			(void) socket_getsockname(so,
			    (struct sockaddr *)so_laddr, &len, CRED());
			len = sizeof (so_faddr);
			(void) socket_getpeername(so,
			    (struct sockaddr *)so_faddr, &len, B_FALSE, CRED());

			/*
			 * only way to drop out of switch. Note that we
			 * we release fd below.
			 */

			break;
		}

		releasef(fd);

		/* don't really want to audit every recv call */
		tad->tad_flag = 0;
		/* free any residual audit data */
		au_close(kctx, &(u_ad), 0, 0, 0, NULL);

		return;

	case AF_UNIX:

		if (fad->fad_aupath != NULL) {
			au_uwrite(au_to_path(fad->fad_aupath));
		} else {
			au_uwrite(au_to_arg32(1, "no path: fd", fd));
		}

		audit_attributes(fp->f_vnode);

		releasef(fd);

		return;

	default:
		releasef(fd);

		au_uwrite(au_to_arg32(1, "so", (uint32_t)fd));
		au_uwrite(au_to_arg32(1, "family", (uint32_t)so_family));
		au_uwrite(au_to_arg32(1, "type", (uint32_t)so_type));

		return;
	}

	releasef(fd);

	au_uwrite(au_to_arg32(1, "so", (uint32_t)fd));

	au_uwrite(au_to_socket_ex(so_family, so_type, so_laddr, so_faddr));

}

/*ARGSUSED*/
static void
auf_send(tad, error, rval)
	struct t_audit_data *tad;
	int error;
	rval_t *rval;
{
	struct sonode *so;
	char so_laddr[sizeof (struct sockaddr_in6)];
	char so_faddr[sizeof (struct sockaddr_in6)];
	struct file *fp;
	struct f_audit_data *fad;
	int fd;
	int err;
	socklen_t len;
	short so_family, so_type;
	register struct a {
		long	fd;
	} *uap = (struct a *)ttolwp(curthread)->lwp_ap;
	au_kcontext_t	*kctx = GET_KCTX_PZ;

	fd = (int)uap->fd;

	/*
	 * If there was an error, then nothing to do. Only generate
	 * audit record on first successful send.
	 */
	if (error != 0) {
		/* Turn off audit record generation here. */
		tad->tad_flag = 0;
		/* free any residual audit data */
		au_close(kctx, &(u_ad), 0, 0, 0, NULL);
		return;
	}

	fd = (int)uap->fd;

	if ((so = getsonode(fd, &err, &fp)) == NULL) {
		/* Turn off audit record generation here. */
		tad->tad_flag = 0;
		/* free any residual audit data */
		au_close(kctx, &(u_ad), 0, 0, 0, NULL);
		return;
	}

	/* get path from file struct here */
	fad = F2A(fp);
	ASSERT(fad);

	/*
	 * already processed this file for write attempt
	 */
	if (fad->fad_flags & FAD_WRITE) {
		releasef(fd);
		/* don't really want to audit every send call */
		tad->tad_flag = 0;
		/* free any residual audit data */
		au_close(kctx, &(u_ad), 0, 0, 0, NULL);
		return;
	}

	/* mark things so we know what happened and don't repeat things */
	fad->fad_flags |= FAD_WRITE;

	so_family = so->so_family;
	so_type   = so->so_type;

	switch (so_family) {
	case AF_INET:
	case AF_INET6:
		/*
		 * Only for connections.
		 * XXX - do we need to worry about SOCK_DGRAM or other types???
		 */
		if (so->so_state & SS_ISBOUND) {

			bzero((void *)so_laddr, sizeof (so_laddr));
			bzero((void *)so_faddr, sizeof (so_faddr));

			/* get local and foreign addresses */
			len = sizeof (so_laddr);
			(void) socket_getsockname(so,
			    (struct sockaddr *)so_laddr, &len, CRED());
			len = sizeof (so_faddr);
			(void) socket_getpeername(so,
			    (struct sockaddr *)so_faddr, &len, B_FALSE, CRED());

			/*
			 * only way to drop out of switch. Note that we
			 * we release fd below.
			 */

			break;
		}

		releasef(fd);
		/* don't really want to audit every send call */
		tad->tad_flag = 0;
		/* free any residual audit data */
		au_close(kctx, &(u_ad), 0, 0, 0, NULL);

		return;

	case AF_UNIX:

		if (fad->fad_aupath != NULL) {
			au_uwrite(au_to_path(fad->fad_aupath));
		} else {
			au_uwrite(au_to_arg32(1, "no path: fd", fd));
		}

		audit_attributes(fp->f_vnode);

		releasef(fd);

		return;

	default:
		releasef(fd);

		au_uwrite(au_to_arg32(1, "so", (uint32_t)fd));
		au_uwrite(au_to_arg32(1, "family", (uint32_t)so_family));
		au_uwrite(au_to_arg32(1, "type", (uint32_t)so_type));

		return;
	}

	releasef(fd);

	au_uwrite(au_to_arg32(1, "so", (uint32_t)fd));

	au_uwrite(au_to_socket_ex(so_family, so_type, so_laddr, so_faddr));
}

static au_event_t
aui_forksys(au_event_t e)
{
	struct a {
		long	subcode;
		long	flags;
	} *uap = (struct a *)ttolwp(curthread)->lwp_ap;

	switch ((uint_t)uap->subcode) {
	case 0:
		e = AUE_FORK1;
		break;
	case 1:
		e = AUE_FORKALL;
		break;
	case 2:
		e = AUE_VFORK;
		break;
	default:
		e = AUE_NULL;
		break;
	}

	return (e);
}

/*ARGSUSED*/
static au_event_t
aui_portfs(au_event_t e)
{
	struct a {		/* portfs */
		long	a1;
		long	a2;
		long	a3;
	} *uap = (struct a *)ttolwp(curthread)->lwp_ap;

	/*
	 * check opcode
	 */
	switch (((uint_t)uap->a1) & PORT_CODE_MASK) {
	case PORT_ASSOCIATE:
		/* check source */
		if (((uint_t)uap->a3 == PORT_SOURCE_FILE) ||
		    ((uint_t)uap->a3 == PORT_SOURCE_FD)) {
			e = AUE_PORTFS_ASSOCIATE;
		} else {
			e = AUE_NULL;
		}
		break;
	case PORT_DISSOCIATE:
		/* check source */
		if (((uint_t)uap->a3 == PORT_SOURCE_FILE) ||
		    ((uint_t)uap->a3 == PORT_SOURCE_FD)) {
			e = AUE_PORTFS_DISSOCIATE;
		} else {
			e = AUE_NULL;
		}
		break;
	default:
		e = AUE_NULL;
	}
	return (e);
}
