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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2012 DEY Storage Systems, Inc.  All rights reserved.
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
 */

/*
 * String conversion routines the system structs found in
 * Solaris core file note sections. These items are not
 * ELF constructs. However, elfdump contains code for decoding
 * them, and therefore requires formatting support.
 */
#include	<stdio.h>
#include	<procfs.h>
#include	<sys/corectl.h>
#include	<string.h>
#include	<_conv.h>
#include	<corenote_msg.h>

const char *
conv_cnote_type(Word type, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	static const Msg	types[] = {
		MSG_NT_PRSTATUS,	MSG_NT_PRFPREG,
		MSG_NT_PRPSINFO,	MSG_NT_PRXREG,
		MSG_NT_PLATFORM,	MSG_NT_AUXV,
		MSG_NT_GWINDOWS,	MSG_NT_ASRS,
		MSG_NT_LDT,		MSG_NT_PSTATUS,
		0,			0,
		MSG_NT_PSINFO,		MSG_NT_PRCRED,
		MSG_NT_UTSNAME,		MSG_NT_LWPSTATUS,
		MSG_NT_LWPSINFO,	MSG_NT_PRPRIV,
		MSG_NT_PRPRIVINFO,	MSG_NT_CONTENT,
		MSG_NT_ZONENAME,	MSG_NT_FDINFO,
		MSG_NT_SPYMASTER
	};
#if NT_NUM != NT_SPYMASTER
#error "NT_NUM has grown. Update core note types[]"
#endif
	static const conv_ds_msg_t ds_types = {
	    CONV_DS_MSG_INIT(NT_PRSTATUS, types) };
	static const conv_ds_t	*ds[] = { CONV_DS_ADDR(ds_types), NULL };


	return (conv_map_ds(ELFOSABI_NONE, EM_NONE, type, ds, fmt_flags,
	    inv_buf));
}


const char *
conv_cnote_auxv_type(Word type, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	static const Msg	types_0_25[] = {
		MSG_AUXV_AT_NULL,		MSG_AUXV_AT_IGNORE,
		MSG_AUXV_AT_EXECFD,		MSG_AUXV_AT_PHDR,
		MSG_AUXV_AT_PHENT,		MSG_AUXV_AT_PHNUM,
		MSG_AUXV_AT_PAGESZ,		MSG_AUXV_AT_BASE,
		MSG_AUXV_AT_FLAGS,		MSG_AUXV_AT_ENTRY,
		MSG_AUXV_AT_NOTELF,		MSG_AUXV_AT_UID,
		MSG_AUXV_AT_EUID,		MSG_AUXV_AT_GID,
		MSG_AUXV_AT_EGID,		MSG_AUXV_AT_PLATFORM,
		MSG_AUXV_AT_HWCAP,		MSG_AUXV_AT_CLKTCK,
		MSG_AUXV_AT_FPUCW,		MSG_AUXV_AT_DCACHEBSIZE,
		MSG_AUXV_AT_ICACHEBSIZE,	MSG_AUXV_AT_UCACHEBSIZE,
		MSG_AUXV_AT_IGNOREPPC,		MSG_AUXV_AT_SECURE,
		MSG_AUXV_AT_BASE_PLATFORM,	MSG_AUXV_AT_RANDOM
	};
	static const conv_ds_msg_t ds_types_0_25 = {
	    CONV_DS_MSG_INIT(0, types_0_25) };

	static const Msg	types_2000_2011[] = {
		MSG_AUXV_AT_SUN_UID,		MSG_AUXV_AT_SUN_RUID,
		MSG_AUXV_AT_SUN_GID,		MSG_AUXV_AT_SUN_RGID,
		MSG_AUXV_AT_SUN_LDELF,		MSG_AUXV_AT_SUN_LDSHDR,
		MSG_AUXV_AT_SUN_LDNAME,		MSG_AUXV_AT_SUN_LPAGESZ,
		MSG_AUXV_AT_SUN_PLATFORM,	MSG_AUXV_AT_SUN_HWCAP,
		MSG_AUXV_AT_SUN_IFLUSH,		MSG_AUXV_AT_SUN_CPU
	};
	static const conv_ds_msg_t ds_types_2000_2011 = {
	    CONV_DS_MSG_INIT(2000, types_2000_2011) };

	static const Msg	types_2014_2024[] = {
		MSG_AUXV_AT_SUN_EXECNAME,	MSG_AUXV_AT_SUN_MMU,
		MSG_AUXV_AT_SUN_LDDATA,		MSG_AUXV_AT_SUN_AUXFLAGS,
		MSG_AUXV_AT_SUN_EMULATOR,	MSG_AUXV_AT_SUN_BRANDNAME,
		MSG_AUXV_AT_SUN_BRAND_AUX1,	MSG_AUXV_AT_SUN_BRAND_AUX2,
		MSG_AUXV_AT_SUN_BRAND_AUX3,	MSG_AUXV_AT_SUN_HWCAP2,
		MSG_AUXV_AT_SUN_BRAND_NROOT
	};
	static const conv_ds_msg_t ds_types_2014_2024 = {
	    CONV_DS_MSG_INIT(2014, types_2014_2024) };

	static const conv_ds_t	*ds[] = {
		CONV_DS_ADDR(ds_types_0_25), CONV_DS_ADDR(ds_types_2000_2011),
		CONV_DS_ADDR(ds_types_2014_2024), NULL };

	return (conv_map_ds(ELFOSABI_NONE, EM_NONE, type, ds, fmt_flags,
	    inv_buf));
}


const char *
conv_cnote_signal(Word sig, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	static const Msg	sigarr[] = {
		MSG_SIGHUP,		MSG_SIGINT,
		MSG_SIGQUIT,		MSG_SIGILL,
		MSG_SIGTRAP,		MSG_SIGABRT,
		MSG_SIGEMT,		MSG_SIGFPE,
		MSG_SIGKILL,		MSG_SIGBUS,
		MSG_SIGSEGV,		MSG_SIGSYS,
		MSG_SIGPIPE,		MSG_SIGALRM,
		MSG_SIGTERM,		MSG_SIGUSR1,
		MSG_SIGUSR2,		MSG_SIGCHLD,
		MSG_SIGPWR,		MSG_SIGWINCH,
		MSG_SIGURG,		MSG_SIGPOLL,
		MSG_SIGSTOP,		MSG_SIGTSTP,
		MSG_SIGCONT,		MSG_SIGTTIN,
		MSG_SIGTTOU,		MSG_SIGVTALRM,
		MSG_SIGPROF,		MSG_SIGXCPU,
		MSG_SIGXFSZ,		MSG_SIGWAITING,
		MSG_SIGLWP,		MSG_SIGFREEZE,
		MSG_SIGTHAW,		MSG_SIGCANCEL,
		MSG_SIGLOST,		MSG_SIGXRES,
		MSG_SIGJVM1,		MSG_SIGJVM2,
	};
	static const conv_ds_msg_t ds_sigarr = {
	    CONV_DS_MSG_INIT(SIGHUP, sigarr) };

	static const conv_ds_t	*ds[] = { CONV_DS_ADDR(ds_sigarr), NULL };

	return (conv_map_ds(ELFOSABI_NONE, EM_NONE, sig, ds, fmt_flags,
	    inv_buf));
}


const char *
conv_cnote_fault(Word flt, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	static const Msg	fltarr[] = {
		MSG_FLTILL,		MSG_FLTPRIV,
		MSG_FLTBPT,		MSG_FLTTRACE,
		MSG_FLTACCESS,		MSG_FLTBOUNDS,
		MSG_FLTIOVF,		MSG_FLTIZDIV,
		MSG_FLTFPE,		MSG_FLTSTACK,
		MSG_FLTPAGE,		MSG_FLTWATCH,
		MSG_FLTCPCOVF

	};
	static const conv_ds_msg_t ds_fltarr = {
	    CONV_DS_MSG_INIT(FLTILL, fltarr) };

	static const conv_ds_t	*ds[] = { CONV_DS_ADDR(ds_fltarr), NULL };

	return (conv_map_ds(ELFOSABI_NONE, EM_NONE, flt, ds, fmt_flags,
	    inv_buf));
}


const char *
conv_cnote_syscall(Word sysnum, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	static const Msg	sysnumarr[] = {
		MSG_SYS_EXIT,			MSG_SYS_2,
		MSG_SYS_READ,			MSG_SYS_WRITE,
		MSG_SYS_OPEN,			MSG_SYS_CLOSE,
		MSG_SYS_7,			MSG_SYS_8,
		MSG_SYS_LINK,			MSG_SYS_UNLINK,
		MSG_SYS_11,			MSG_SYS_CHDIR,
		MSG_SYS_TIME,			MSG_SYS_MKNOD,
		MSG_SYS_CHMOD,			MSG_SYS_CHOWN,
		MSG_SYS_BRK,			MSG_SYS_STAT,
		MSG_SYS_LSEEK,			MSG_SYS_GETPID,
		MSG_SYS_MOUNT,			MSG_SYS_22,
		MSG_SYS_SETUID,			MSG_SYS_GETUID,
		MSG_SYS_STIME,			MSG_SYS_PCSAMPLE,
		MSG_SYS_ALARM,			MSG_SYS_FSTAT,
		MSG_SYS_PAUSE,			MSG_SYS_30,
		MSG_SYS_STTY,			MSG_SYS_GTTY,
		MSG_SYS_ACCESS,			MSG_SYS_NICE,
		MSG_SYS_STATFS,			MSG_SYS_SYNC,
		MSG_SYS_KILL,			MSG_SYS_FSTATFS,
		MSG_SYS_PGRPSYS,		MSG_SYS_UUCOPYSTR,
		MSG_SYS_41,			MSG_SYS_PIPE,
		MSG_SYS_TIMES,			MSG_SYS_PROFIL,
		MSG_SYS_FACCESSAT,		MSG_SYS_SETGID,
		MSG_SYS_GETGID,			MSG_SYS_48,
		MSG_SYS_MSGSYS,			MSG_SYS_SYSI86,
		MSG_SYS_ACCT,			MSG_SYS_SHMSYS,
		MSG_SYS_SEMSYS,			MSG_SYS_IOCTL,
		MSG_SYS_UADMIN,			MSG_SYS_FCHOWNAT,
		MSG_SYS_UTSSYS,			MSG_SYS_FDSYNC,
		MSG_SYS_EXECVE,			MSG_SYS_UMASK,
		MSG_SYS_CHROOT,			MSG_SYS_FCNTL,
		MSG_SYS_ULIMIT,			MSG_SYS_RENAMEAT,
		MSG_SYS_UNLINKAT,		MSG_SYS_FSTATAT,
		MSG_SYS_FSTATAT64,		MSG_SYS_OPENAT,
		MSG_SYS_OPENAT64,		MSG_SYS_TASKSYS,
		MSG_SYS_ACCTCTL,		MSG_SYS_EXACCTSYS,
		MSG_SYS_GETPAGESIZES,		MSG_SYS_RCTLSYS,
		MSG_SYS_SIDSYS,			MSG_SYS_76,
		MSG_SYS_LWP_PARK,		MSG_SYS_SENDFILEV,
		MSG_SYS_RMDIR,			MSG_SYS_MKDIR,
		MSG_SYS_GETDENTS,		MSG_SYS_PRIVSYS,
		MSG_SYS_UCREDSYS,		MSG_SYS_SYSFS,
		MSG_SYS_GETMSG,			MSG_SYS_PUTMSG,
		MSG_SYS_87,			MSG_SYS_LSTAT,
		MSG_SYS_SYMLINK,		MSG_SYS_READLINK,
		MSG_SYS_SETGROUPS,		MSG_SYS_GETGROUPS,
		MSG_SYS_FCHMOD,			MSG_SYS_FCHOWN,
		MSG_SYS_SIGPROCMASK,		MSG_SYS_SIGSUSPEND,
		MSG_SYS_SIGALTSTACK,		MSG_SYS_SIGACTION,
		MSG_SYS_SIGPENDING,		MSG_SYS_CONTEXT,
		MSG_SYS_101,			MSG_SYS_102,
		MSG_SYS_STATVFS,		MSG_SYS_FSTATVFS,
		MSG_SYS_GETLOADAVG,		MSG_SYS_NFSSYS,
		MSG_SYS_WAITID,			MSG_SYS_SIGSENDSYS,
		MSG_SYS_HRTSYS,			MSG_SYS_UTIMESYS,
		MSG_SYS_SIGRESEND,		MSG_SYS_PRIOCNTLSYS,
		MSG_SYS_PATHCONF,		MSG_SYS_MINCORE,
		MSG_SYS_MMAP,			MSG_SYS_MPROTECT,
		MSG_SYS_MUNMAP,			MSG_SYS_FPATHCONF,
		MSG_SYS_VFORK,			MSG_SYS_FCHDIR,
		MSG_SYS_READV,			MSG_SYS_WRITEV,
		MSG_SYS_123,			MSG_SYS_124,
		MSG_SYS_125,			MSG_SYS_126,
		MSG_SYS_MMAPOBJ,		MSG_SYS_SETRLIMIT,
		MSG_SYS_GETRLIMIT,		MSG_SYS_LCHOWN,
		MSG_SYS_MEMCNTL,		MSG_SYS_GETPMSG,
		MSG_SYS_PUTPMSG,		MSG_SYS_RENAME,
		MSG_SYS_UNAME,			MSG_SYS_SETEGID,
		MSG_SYS_SYSCONFIG,		MSG_SYS_ADJTIME,
		MSG_SYS_SYSTEMINFO,		MSG_SYS_SHAREFS,
		MSG_SYS_SETEUID,		MSG_SYS_FORKSYS,
		MSG_SYS_143,			MSG_SYS_SIGTIMEDWAIT,
		MSG_SYS_LWP_INFO,		MSG_SYS_YIELD,
		MSG_SYS_147,			MSG_SYS_LWP_SEMA_POST,
		MSG_SYS_LWP_SEMA_TRYWAIT,	MSG_SYS_LWP_DETACH,
		MSG_SYS_CORECTL,		MSG_SYS_MODCTL,
		MSG_SYS_FCHROOT,		MSG_SYS_154,
		MSG_SYS_VHANGUP,		MSG_SYS_GETTIMEOFDAY,
		MSG_SYS_GETITIMER,		MSG_SYS_SETITIMER,
		MSG_SYS_LWP_CREATE,		MSG_SYS_LWP_EXIT,
		MSG_SYS_LWP_SUSPEND,		MSG_SYS_LWP_CONTINUE,
		MSG_SYS_LWP_KILL,		MSG_SYS_LWP_SELF,
		MSG_SYS_LWP_SIGMASK,		MSG_SYS_LWP_PRIVATE,
		MSG_SYS_LWP_WAIT,		MSG_SYS_LWP_MUTEX_WAKEUP,
		MSG_SYS_169,			MSG_SYS_LWP_COND_WAIT,
		MSG_SYS_LWP_COND_SIGNAL,	MSG_SYS_LWP_COND_BROADCAST,
		MSG_SYS_PREAD,			MSG_SYS_PWRITE,
		MSG_SYS_LLSEEK,			MSG_SYS_INST_SYNC,
		MSG_SYS_BRAND,			MSG_SYS_KAIO,
		MSG_SYS_CPC,			MSG_SYS_LGRPSYS,
		MSG_SYS_RUSAGESYS,		MSG_SYS_PORT,
		MSG_SYS_POLLSYS,		MSG_SYS_LABELSYS,
		MSG_SYS_ACL,			MSG_SYS_AUDITSYS,
		MSG_SYS_PROCESSOR_BIND,		MSG_SYS_PROCESSOR_INFO,
		MSG_SYS_P_ONLINE,		MSG_SYS_SIGQUEUE,
		MSG_SYS_CLOCK_GETTIME,		MSG_SYS_CLOCK_SETTIME,
		MSG_SYS_CLOCK_GETRES,		MSG_SYS_TIMER_CREATE,
		MSG_SYS_TIMER_DELETE,		MSG_SYS_TIMER_SETTIME,
		MSG_SYS_TIMER_GETTIME,		MSG_SYS_TIMER_GETOVERRUN,
		MSG_SYS_NANOSLEEP,		MSG_SYS_FACL,
		MSG_SYS_DOOR,			MSG_SYS_SETREUID,
		MSG_SYS_SETREGID,		MSG_SYS_INSTALL_UTRAP,
		MSG_SYS_SIGNOTIFY,		MSG_SYS_SCHEDCTL,
		MSG_SYS_PSET,			MSG_SYS_SPARC_UTRAP_INSTALL,
		MSG_SYS_RESOLVEPATH,		MSG_SYS_LWP_MUTEX_TIMEDLOCK,
		MSG_SYS_LWP_SEMA_TIMEDWAIT,	MSG_SYS_LWP_RWLOCK_SYS,
		MSG_SYS_GETDENTS64,		MSG_SYS_MMAP64,
		MSG_SYS_STAT64,			MSG_SYS_LSTAT64,
		MSG_SYS_FSTAT64,		MSG_SYS_STATVFS64,
		MSG_SYS_FSTATVFS64,		MSG_SYS_SETRLIMIT64,
		MSG_SYS_GETRLIMIT64,		MSG_SYS_PREAD64,
		MSG_SYS_PWRITE64,		MSG_SYS_224,
		MSG_SYS_OPEN64,			MSG_SYS_RPCSYS,
		MSG_SYS_ZONE,			MSG_SYS_AUTOFSSYS,
		MSG_SYS_GETCWD,			MSG_SYS_SO_SOCKET,
		MSG_SYS_SO_SOCKETPAIR,		MSG_SYS_BIND,
		MSG_SYS_LISTEN,			MSG_SYS_ACCEPT,
		MSG_SYS_CONNECT,		MSG_SYS_SHUTDOWN,
		MSG_SYS_RECV,			MSG_SYS_RECVFROM,
		MSG_SYS_RECVMSG,		MSG_SYS_SEND,
		MSG_SYS_SENDMSG,		MSG_SYS_SENDTO,
		MSG_SYS_GETPEERNAME,		MSG_SYS_GETSOCKNAME,
		MSG_SYS_GETSOCKOPT,		MSG_SYS_SETSOCKOPT,
		MSG_SYS_SOCKCONFIG,		MSG_SYS_NTP_GETTIME,
		MSG_SYS_NTP_ADJTIME,		MSG_SYS_LWP_MUTEX_UNLOCK,
		MSG_SYS_LWP_MUTEX_TRYLOCK,	MSG_SYS_LWP_MUTEX_REGISTER,
		MSG_SYS_CLADM,			MSG_SYS_UUCOPY,
		MSG_SYS_UMOUNT2
	};
	static const conv_ds_msg_t ds_sysnumarr = {
	    CONV_DS_MSG_INIT(1, sysnumarr) };

	static const conv_ds_t	*ds[] = { CONV_DS_ADDR(ds_sysnumarr), NULL };

	int	use_num = 0;

	/*
	 * Range check, and handle the unused values in the middle
	 * of the range. Although the missing values have strings,
	 * we still prefer to format them, because those strings are
	 * decimal, and the default behavior, unless the CONV_FMT_DECIMAL
	 * flag is set, is to display such things in hex.
	 */
	switch (sysnum) {
	case 0:
	case 2:
	case 7:
	case 8:
	case 11:
	case 22:
	case 30:
	case 41:
	case 48:
	case 76:
	case 87:
	case 101:
	case 102:
	case 123:
	case 124:
	case 125:
	case 126:
	case 143:
	case 147:
	case 154:
	case 169:
	case 224:
		use_num = 1;
		break;
	default:
		use_num = (sysnum > SYS_umount2);
		break;
	}
	if (use_num)
		return (conv_invalid_val(inv_buf, sysnum, fmt_flags));

	return (conv_map_ds(ELFOSABI_NONE, EM_NONE, sysnum, ds, fmt_flags,
	    inv_buf));
}


const char *
conv_cnote_errno(int errno_val, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	static const Msg	errarr_1_74[74] = {
		MSG_ERRNO_EPERM,		MSG_ERRNO_ENOENT,
		MSG_ERRNO_ESRCH,		MSG_ERRNO_EINTR,
		MSG_ERRNO_EIO,			MSG_ERRNO_ENXIO,
		MSG_ERRNO_E2BIG,		MSG_ERRNO_ENOEXEC,
		MSG_ERRNO_EBADF,		MSG_ERRNO_ECHILD,
		MSG_ERRNO_EAGAIN,		MSG_ERRNO_ENOMEM,
		MSG_ERRNO_EACCES,		MSG_ERRNO_EFAULT,
		MSG_ERRNO_ENOTBLK,		MSG_ERRNO_EBUSY,
		MSG_ERRNO_EEXIST,		MSG_ERRNO_EXDEV,
		MSG_ERRNO_ENODEV,		MSG_ERRNO_ENOTDIR,
		MSG_ERRNO_EISDIR,		MSG_ERRNO_EINVAL,
		MSG_ERRNO_ENFILE,		MSG_ERRNO_EMFILE,
		MSG_ERRNO_ENOTTY,		MSG_ERRNO_ETXTBSY,
		MSG_ERRNO_EFBIG,		MSG_ERRNO_ENOSPC,
		MSG_ERRNO_ESPIPE,		MSG_ERRNO_EROFS,
		MSG_ERRNO_EMLINK,		MSG_ERRNO_EPIPE,
		MSG_ERRNO_EDOM,			MSG_ERRNO_ERANGE,
		MSG_ERRNO_ENOMSG,		MSG_ERRNO_EIDRM,
		MSG_ERRNO_ECHRNG,		MSG_ERRNO_EL2NSYNC,
		MSG_ERRNO_EL3HLT,		MSG_ERRNO_EL3RST,
		MSG_ERRNO_ELNRNG,		MSG_ERRNO_EUNATCH,
		MSG_ERRNO_ENOCSI,		MSG_ERRNO_EL2HLT,
		MSG_ERRNO_EDEADLK,		MSG_ERRNO_ENOLCK,
		MSG_ERRNO_ECANCELED,		MSG_ERRNO_ENOTSUP,
		MSG_ERRNO_EDQUOT,		MSG_ERRNO_EBADE,
		MSG_ERRNO_EBADR,		MSG_ERRNO_EXFULL,
		MSG_ERRNO_ENOANO,		MSG_ERRNO_EBADRQC,
		MSG_ERRNO_EBADSLT,		MSG_ERRNO_EDEADLOCK,
		MSG_ERRNO_EBFONT,		MSG_ERRNO_EOWNERDEAD,
		MSG_ERRNO_ENOTRECOVERABLE,	MSG_ERRNO_ENOSTR,
		MSG_ERRNO_ENODATA,		MSG_ERRNO_ETIME,
		MSG_ERRNO_ENOSR,		MSG_ERRNO_ENONET,
		MSG_ERRNO_ENOPKG,		MSG_ERRNO_EREMOTE,
		MSG_ERRNO_ENOLINK,		MSG_ERRNO_EADV,
		MSG_ERRNO_ESRMNT,		MSG_ERRNO_ECOMM,
		MSG_ERRNO_EPROTO,		MSG_ERRNO_ELOCKUNMAPPED,
		MSG_ERRNO_ENOTACTIVE,		MSG_ERRNO_EMULTIHOP
	};
	static const conv_ds_msg_t ds_errarr_1_74 = {
	    CONV_DS_MSG_INIT(1, errarr_1_74) };

	static const Msg	errarr_77_99[23] = {
		MSG_ERRNO_EBADMSG,		MSG_ERRNO_ENAMETOOLONG,
		MSG_ERRNO_EOVERFLOW,		MSG_ERRNO_ENOTUNIQ,
		MSG_ERRNO_EBADFD,		MSG_ERRNO_EREMCHG,
		MSG_ERRNO_ELIBACC,		MSG_ERRNO_ELIBBAD,
		MSG_ERRNO_ELIBSCN,		MSG_ERRNO_ELIBMAX,
		MSG_ERRNO_ELIBEXEC,		MSG_ERRNO_EILSEQ,
		MSG_ERRNO_ENOSYS,		MSG_ERRNO_ELOOP,
		MSG_ERRNO_ERESTART,		MSG_ERRNO_ESTRPIPE,
		MSG_ERRNO_ENOTEMPTY,		MSG_ERRNO_EUSERS,
		MSG_ERRNO_ENOTSOCK,		MSG_ERRNO_EDESTADDRREQ,
		MSG_ERRNO_EMSGSIZE,		MSG_ERRNO_EPROTOTYPE,
		MSG_ERRNO_ENOPROTOOPT
	};
	static const conv_ds_msg_t ds_errarr_77_99 = {
	    CONV_DS_MSG_INIT(77, errarr_77_99) };

	static const Msg	errarr_120_134[15] = {
		MSG_ERRNO_EPROTONOSUPPORT,	MSG_ERRNO_ESOCKTNOSUPPORT,
		MSG_ERRNO_EOPNOTSUPP,		MSG_ERRNO_EPFNOSUPPORT,
		MSG_ERRNO_EAFNOSUPPORT,		MSG_ERRNO_EADDRINUSE,
		MSG_ERRNO_EADDRNOTAVAIL,	MSG_ERRNO_ENETDOWN,
		MSG_ERRNO_ENETUNREACH,		MSG_ERRNO_ENETRESET,
		MSG_ERRNO_ECONNABORTED,		MSG_ERRNO_ECONNRESET,
		MSG_ERRNO_ENOBUFS,		MSG_ERRNO_EISCONN,
		MSG_ERRNO_ENOTCONN
	};
	static const conv_ds_msg_t ds_errarr_120_134 = {
	    CONV_DS_MSG_INIT(120, errarr_120_134) };

	static const Msg	errarr_143_151[9] = {
		MSG_ERRNO_ESHUTDOWN,		MSG_ERRNO_ETOOMANYREFS,
		MSG_ERRNO_ETIMEDOUT,		MSG_ERRNO_ECONNREFUSED,
		MSG_ERRNO_EHOSTDOWN,		MSG_ERRNO_EHOSTUNREACH,
		MSG_ERRNO_EALREADY,		MSG_ERRNO_EINPROGRESS,
		MSG_ERRNO_ESTALE
	};
	static const conv_ds_msg_t ds_errarr_143_151 = {
	    CONV_DS_MSG_INIT(143, errarr_143_151) };

	static const conv_ds_t	*ds[] = { CONV_DS_ADDR(ds_errarr_1_74),
		CONV_DS_ADDR(ds_errarr_77_99), CONV_DS_ADDR(ds_errarr_120_134),
		CONV_DS_ADDR(ds_errarr_143_151), NULL };


	return (conv_map_ds(ELFOSABI_NONE, EM_NONE, errno_val, ds, fmt_flags,
	    inv_buf));
}


const char *
conv_cnote_pr_dmodel(Word dmodel, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	static const Msg	models[] = {
		MSG_PR_MODEL_UNKNOWN,
		MSG_PR_MODEL_ILP32,
		MSG_PR_MODEL_LP64
	};
	static const conv_ds_msg_t ds_models = {
	    CONV_DS_MSG_INIT(PR_MODEL_UNKNOWN, models) };
	static const conv_ds_t	*ds[] = { CONV_DS_ADDR(ds_models), NULL };

	return (conv_map_ds(ELFOSABI_NONE, EM_NONE, dmodel, ds, fmt_flags,
	    inv_buf));
}


const char *
conv_cnote_pr_why(short why, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	static const Msg	why_arr[] = {
		MSG_PR_WHY_REQUESTED,
		MSG_PR_WHY_SIGNALLED,
		MSG_PR_WHY_SYSENTRY,
		MSG_PR_WHY_SYSEXIT,
		MSG_PR_WHY_JOBCONTROL,
		MSG_PR_WHY_FAULTED,
		MSG_PR_WHY_SUSPENDED,
		MSG_PR_WHY_CHECKPOINT
	};
	static const conv_ds_msg_t ds_why_arr = {
	    CONV_DS_MSG_INIT(1, why_arr) };
	static const conv_ds_t	*ds[] = { CONV_DS_ADDR(ds_why_arr), NULL };

	return (conv_map_ds(ELFOSABI_NONE, EM_NONE, why, ds, fmt_flags,
	    inv_buf));
}


const char *
conv_cnote_pr_what(short why, short what, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	/*
	 * The meaning of pr_what depends on the corresponding
	 * value of pr_why, as discussed in the proc(4) manpage.
	 */
	switch (why) {
	case PR_SIGNALLED:
	case PR_JOBCONTROL:
		return (conv_cnote_signal(what, fmt_flags, inv_buf));
	case PR_SYSENTRY:
	case PR_SYSEXIT:
		return (conv_cnote_syscall(what, fmt_flags, inv_buf));
	case PR_FAULTED:
		return (conv_cnote_fault(what, fmt_flags, inv_buf));
	};

	return (conv_invalid_val(inv_buf, what, fmt_flags));
}


/*
 * Return the name of the general purpose register indexed by
 * regno in the pr_reg array of lwpstatus_t (<sys/procfs.h>).
 */
const char *
conv_cnote_pr_regname(Half mach, int regno, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	static const Msg	sparc_gen_reg[32] = {
		MSG_REG_SPARC_G0,		MSG_REG_SPARC_G1,
		MSG_REG_SPARC_G2,		MSG_REG_SPARC_G3,
		MSG_REG_SPARC_G4,		MSG_REG_SPARC_G5,
		MSG_REG_SPARC_G6,		MSG_REG_SPARC_G7,
		MSG_REG_SPARC_O0,		MSG_REG_SPARC_O1,
		MSG_REG_SPARC_O2,		MSG_REG_SPARC_O3,
		MSG_REG_SPARC_O4,		MSG_REG_SPARC_O5,
		MSG_REG_SPARC_O6,		MSG_REG_SPARC_O7,
		MSG_REG_SPARC_L0,		MSG_REG_SPARC_L1,
		MSG_REG_SPARC_L2,		MSG_REG_SPARC_L3,
		MSG_REG_SPARC_L4,		MSG_REG_SPARC_L5,
		MSG_REG_SPARC_L6,		MSG_REG_SPARC_L7,
		MSG_REG_SPARC_I0,		MSG_REG_SPARC_I1,
		MSG_REG_SPARC_I2,		MSG_REG_SPARC_I3,
		MSG_REG_SPARC_I4,		MSG_REG_SPARC_I5,
		MSG_REG_SPARC_I6,		MSG_REG_SPARC_I7
	};
	static const conv_ds_msg_t ds_sparc_gen_reg = {
	    CONV_DS_MSG_INIT(0, sparc_gen_reg) };

	static const Msg	sparc_32_37_reg[6] = {
		MSG_REG_SPARC_PSR,		MSG_REG_SPARC_PC,
		MSG_REG_SPARC_nPC,		MSG_REG_SPARC_Y,
		MSG_REG_SPARC_WIM,		MSG_REG_SPARC_TBR
	};
	static const conv_ds_msg_t ds_sparc_32_37_reg = {
	    CONV_DS_MSG_INIT(32, sparc_32_37_reg) };

	static const Msg	sparcv9_32_37_reg[6] = {
		MSG_REG_SPARC_CCR,		MSG_REG_SPARC_PC,
		MSG_REG_SPARC_nPC,		MSG_REG_SPARC_Y,
		MSG_REG_SPARC_ASI,		MSG_REG_SPARC_FPRS
	};
	static const conv_ds_msg_t ds_sparcv9_32_37_reg = {
	    CONV_DS_MSG_INIT(32, sparcv9_32_37_reg) };

	static const Msg	amd64_reg[28] = {
		MSG_REG_AMD64_R15,		MSG_REG_AMD64_R14,
		MSG_REG_AMD64_R13,		MSG_REG_AMD64_R12,
		MSG_REG_AMD64_R11,		MSG_REG_AMD64_R10,
		MSG_REG_AMD64_R9,		MSG_REG_AMD64_R8,
		MSG_REG_AMD64_RDI,		MSG_REG_AMD64_RSI,
		MSG_REG_AMD64_RBP,		MSG_REG_AMD64_RBX,
		MSG_REG_AMD64_RDX,		MSG_REG_AMD64_RCX,
		MSG_REG_AMD64_RAX,		MSG_REG_AMD64_TRAPNO,
		MSG_REG_AMD64_ERR,		MSG_REG_AMD64_RIP,
		MSG_REG_AMD64_CS,		MSG_REG_AMD64_RFL,
		MSG_REG_AMD64_RSP,		MSG_REG_AMD64_SS,
		MSG_REG_AMD64_FS,		MSG_REG_AMD64_GS,
		MSG_REG_AMD64_ES,		MSG_REG_AMD64_DS,
		MSG_REG_AMD64_FSBASE,		MSG_REG_AMD64_GSBASE
	};
	static const conv_ds_msg_t ds_amd64_reg = {
	    CONV_DS_MSG_INIT(0, amd64_reg) };

	static const Msg	i86_reg[19] = {
		MSG_REG_I86_GS,			MSG_REG_I86_FS,
		MSG_REG_I86_ES,			MSG_REG_I86_DS,
		MSG_REG_I86_EDI,		MSG_REG_I86_ESI,
		MSG_REG_I86_EBP,		MSG_REG_I86_ESP,
		MSG_REG_I86_EBX,		MSG_REG_I86_EDX,
		MSG_REG_I86_ECX,		MSG_REG_I86_EAX,
		MSG_REG_I86_TRAPNO,		MSG_REG_I86_ERR,
		MSG_REG_I86_EIP,		MSG_REG_I86_CS,
		MSG_REG_I86_EFL,		MSG_REG_I86_UESP,
		MSG_REG_I86_SS
	};
	static const conv_ds_msg_t ds_i86_reg = {
	    CONV_DS_MSG_INIT(0, i86_reg) };


	static const conv_ds_t	*ds_sparc[] = {
		CONV_DS_ADDR(ds_sparc_gen_reg),
		CONV_DS_ADDR(ds_sparc_32_37_reg),
		NULL
	};
	static const conv_ds_t	*ds_sparcv9[] = {
		CONV_DS_ADDR(ds_sparc_gen_reg),
		CONV_DS_ADDR(ds_sparcv9_32_37_reg),
		NULL
	};
	static const conv_ds_t	*ds_amd64[] = {
		CONV_DS_ADDR(ds_amd64_reg), NULL };
	static const conv_ds_t	*ds_i86[] = {
		CONV_DS_ADDR(ds_i86_reg), NULL };

	const conv_ds_t **ds;

	switch (mach) {
	case EM_386:
		ds = ds_i86;
		break;

	case EM_AMD64:
		ds = ds_amd64;
		break;

	case EM_SPARC:
	case EM_SPARC32PLUS:
		ds = ds_sparc;
		break;

	case EM_SPARCV9:
		ds = ds_sparcv9;
		break;

	default:
		return (conv_invalid_val(inv_buf, regno, fmt_flags));
	}

	return (conv_map_ds(ELFOSABI_NONE, mach, regno, ds, fmt_flags,
	    inv_buf));
}

const char *
conv_cnote_pr_stype(Word stype, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	static const Msg	types[] = {
		MSG_SOBJ_NONE,		MSG_SOBJ_MUTEX,
		MSG_SOBJ_RWLOCK,	MSG_SOBJ_CV,
		MSG_SOBJ_SEMA,		MSG_SOBJ_USER,
		MSG_SOBJ_USER_PI,	MSG_SOBJ_SHUTTLE
	};
	static const conv_ds_msg_t ds_types = { CONV_DS_MSG_INIT(0, types) };
	static const conv_ds_t	*ds[] = { CONV_DS_ADDR(ds_types), NULL };


	return (conv_map_ds(ELFOSABI_NONE, EM_NONE, stype, ds, fmt_flags,
	    inv_buf));
}


const char *
conv_cnote_priv(int priv, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	const char *fmt;

	/*
	 * The PRIV_ constants defined in <sys/priv.h> are unusual
	 * in that they are negative values. The libconv code is all
	 * built around the Word type, which is unsigned. Rather than
	 * modify libconv for this one case, we simply handle
	 * these constants differently that the usual approach,
	 * and stay away from conv_invalid_val() and conv_map_ds().
	 */
	switch (priv) {
	case PRIV_ALL:
		return (MSG_ORIG(MSG_PRIV_ALL));
	case PRIV_MULTIPLE:
		return (MSG_ORIG(MSG_PRIV_MULTIPLE));
	case PRIV_NONE:
		return (MSG_ORIG(MSG_PRIV_NONE));
	case PRIV_ALLZONE:
		return (MSG_ORIG(MSG_PRIV_ALLZONE));
	case PRIV_GLOBAL:
		return (MSG_ORIG(MSG_PRIV_GLOBAL));
	}

	fmt = (fmt_flags & CONV_FMT_DECIMAL) ?
	    MSG_ORIG(MSG_FMT_INT) : MSG_ORIG(MSG_FMT_HEXINT);
	(void) snprintf(inv_buf->buf, sizeof (inv_buf->buf), fmt, priv);
	return (inv_buf->buf);
}


const char *
conv_cnote_psetid(int id, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	const char *fmt;

	/*
	 * The PS_ constants defined in <sys/pset.h> are unusual
	 * in that they are negative values. The libconv code is all
	 * built around the Word type, which is unsigned. Rather than
	 * modify libconv for this one case, we simply handle
	 * these constants differently that the usual approach,
	 * and stay away from conv_invalid_val() and conv_map_ds().
	 */
	switch (id) {
	case PS_NONE:
		return (MSG_ORIG(MSG_PS_NONE));
	case PS_QUERY:
		return (MSG_ORIG(MSG_PS_QUERY));
	case PS_MYID:
		return (MSG_ORIG(MSG_PS_MYID));
	case PS_SOFT:
		return (MSG_ORIG(MSG_PS_SOFT));
	case PS_HARD:
		return (MSG_ORIG(MSG_PS_HARD));
	case PS_QUERY_TYPE:
		return (MSG_ORIG(MSG_PS_QUERY_TYPE));
	}

	fmt = (fmt_flags & CONV_FMT_DECIMAL) ?
	    MSG_ORIG(MSG_FMT_INT) : MSG_ORIG(MSG_FMT_HEXINT);
	(void) snprintf(inv_buf->buf, sizeof (inv_buf->buf), fmt, id);
	return (inv_buf->buf);
}


/*
 * Return a string describing the si_code field of
 * the siginfo_t struct.
 *
 * The meaning of si_code is dependent on both the target
 * machine (mach) as well as the signal (sig).
 */
const char *
conv_cnote_si_code(Half mach, int sig, int si_code,
    Conv_fmt_flags_t fmt_flags, Conv_inv_buf_t *inv_buf)
{

	/* Values of si_code for user generated signals */
	static const Msg	user_arr[6] = {
		MSG_SI_USER,		MSG_SI_LWP,
		MSG_SI_QUEUE,		MSG_SI_TIMER,
		MSG_SI_ASYNCIO,		MSG_SI_MESGQ
	};
	static const conv_ds_msg_t ds_msg_user_arr = {
	    CONV_DS_MSG_INIT(0, user_arr) };
	static const conv_ds_t	*ds_user_arr[] = {
		CONV_DS_ADDR(ds_msg_user_arr), NULL };


	/*
	 * Architecture dependent system generated signals. All
	 * versions of Solaris use the same set of these values.
	 */
	static const Msg	trap_arr[6] = {
		MSG_SI_TRAP_BRKPT,	MSG_SI_TRAP_TRACE,
		MSG_SI_TRAP_RWATCH,	MSG_SI_TRAP_WWATCH,
		MSG_SI_TRAP_XWATCH,	MSG_SI_TRAP_DTRACE
	};
	static const conv_ds_msg_t ds_msg_trap_arr = {
	    CONV_DS_MSG_INIT(1, trap_arr) };
	static const conv_ds_t	*ds_trap_arr[] = {
		CONV_DS_ADDR(ds_msg_trap_arr), NULL };

	static const Msg	cld_arr[6] = {
		MSG_SI_CLD_EXITED,	MSG_SI_CLD_KILLED,
		MSG_SI_CLD_DUMPED,	MSG_SI_CLD_TRAPPED,
		MSG_SI_CLD_STOPPED,	MSG_SI_CLD_CONTINUED
	};
	static const conv_ds_msg_t ds_msg_cld_arr = {
	    CONV_DS_MSG_INIT(1, cld_arr) };
	static const conv_ds_t	*ds_cld_arr[] = {
		CONV_DS_ADDR(ds_msg_cld_arr), NULL };

	static const Msg	poll_arr[6] = {
		MSG_SI_POLL_IN,		MSG_SI_POLL_OUT,
		MSG_SI_POLL_MSG,	MSG_SI_POLL_ERR,
		MSG_SI_POLL_PRI,	MSG_SI_POLL_HUP
	};
	static const conv_ds_msg_t ds_msg_poll_arr = {
	    CONV_DS_MSG_INIT(1, poll_arr) };
	static const conv_ds_t	*ds_poll_arr[] = {
		CONV_DS_ADDR(ds_msg_poll_arr), NULL };

	/*
	 * Architecture dependent system generated signals.
	 * These items (ILL, EMT, FPE, SEGV, BUS) are platform
	 * dependent. Some architectures have extra codes.
	 * The same name may have a different integer value.
	 * Multiple arrays are used when they differ, and one
	 * array when all the architectures agree.
	 */

	/* ILL */
	static const Msg	ill_arr[8] = {
		MSG_SI_ILL_ILLOPC,	MSG_SI_ILL_ILLOPN,
		MSG_SI_ILL_ILLADR,	MSG_SI_ILL_ILLTRP,
		MSG_SI_ILL_PRVOPC,	MSG_SI_ILL_PRVREG,
		MSG_SI_ILL_COPROC,	MSG_SI_ILL_BADSTK
	};
	static const conv_ds_msg_t ds_msg_ill_arr = {
	    CONV_DS_MSG_INIT(1, ill_arr) };
	static const conv_ds_t	*ds_ill_arr[] = {
		CONV_DS_ADDR(ds_msg_ill_arr), NULL };

	/* EMT */
	static const Msg	emt_arr_sparc[2] = {
		MSG_SI_EMT_TAGOVF,	MSG_SI_EMT_CPCOVF
	};
	static const conv_ds_msg_t ds_msg_emt_arr_sparc = {
	    CONV_DS_MSG_INIT(1, emt_arr_sparc) };
	static const conv_ds_t	*ds_emt_arr_sparc[] = {
		CONV_DS_ADDR(ds_msg_emt_arr_sparc), NULL };

	static const Msg	emt_arr_x86[1] = {
		MSG_SI_EMT_CPCOVF
	};
	static const conv_ds_msg_t ds_msg_emt_arr_x86 = {
	    CONV_DS_MSG_INIT(1, emt_arr_x86) };
	static const conv_ds_t	*ds_emt_arr_x86[] = {
		CONV_DS_ADDR(ds_msg_emt_arr_x86), NULL };


	/* FPE */
	static const Msg	fpe_arr_sparc[8] = {
		MSG_SI_FPE_INTDIV,	MSG_SI_FPE_INTOVF,
		MSG_SI_FPE_FLTDIV,	MSG_SI_FPE_FLTOVF,
		MSG_SI_FPE_FLTUND,	MSG_SI_FPE_FLTRES,
		MSG_SI_FPE_FLTINV,	MSG_SI_FPE_FLTSUB
	};
	static const conv_ds_msg_t ds_msg_fpe_arr_sparc = {
	    CONV_DS_MSG_INIT(1, fpe_arr_sparc) };
	static const conv_ds_t	*ds_fpe_arr_sparc[] = {
		CONV_DS_ADDR(ds_msg_fpe_arr_sparc), NULL };

	static const Msg	fpe_arr_x86[9] = {
		MSG_SI_FPE_INTDIV,	MSG_SI_FPE_INTOVF,
		MSG_SI_FPE_FLTDIV,	MSG_SI_FPE_FLTOVF,
		MSG_SI_FPE_FLTUND,	MSG_SI_FPE_FLTRES,
		MSG_SI_FPE_FLTINV,	MSG_SI_FPE_FLTSUB,
		MSG_SI_FPE_FLTDEN
	};
	static const conv_ds_msg_t ds_msg_fpe_arr_x86 = {
	    CONV_DS_MSG_INIT(1, fpe_arr_x86) };
	static const conv_ds_t	*ds_fpe_arr_x86[] = {
		CONV_DS_ADDR(ds_msg_fpe_arr_x86), NULL };

	/* SEGV */
	static const Msg	segv_arr[2] = {
		MSG_SI_SEGV_MAPERR,	MSG_SI_SEGV_ACCERR
	};
	static const conv_ds_msg_t ds_msg_segv_arr = {
	    CONV_DS_MSG_INIT(1, segv_arr) };
	static const conv_ds_t	*ds_segv_arr[] = {
		CONV_DS_ADDR(ds_msg_segv_arr), NULL };

	/* BUS */
	static const Msg	bus_arr[3] = {
		MSG_SI_BUS_ADRALN,	MSG_SI_BUS_ADRERR,
		MSG_SI_BUS_OBJERR
	};
	static const conv_ds_msg_t ds_msg_bus_arr = {
	    CONV_DS_MSG_INIT(1, bus_arr) };
	static const conv_ds_t	*ds_bus_arr[] = {
		CONV_DS_ADDR(ds_msg_bus_arr), NULL };

	enum { ARCH_NONE, ARCH_X86, ARCH_SPARC } arch;


	/* Handle the si_code values that do not depend on the signal */
	switch (si_code) {
	case SI_NOINFO:
		return (MSG_ORIG(MSG_SI_NOINFO));
	case SI_DTRACE:
		return (MSG_ORIG(MSG_SI_DTRACE));
	case SI_RCTL:
		return (MSG_ORIG(MSG_SI_RCTL));
	default:
		/* User generated signal codes are <= 0 */
		if (si_code <= 0) {
			int ndx = -si_code;

			/*
			 * If no signal was delivered, and si_code is
			 * 0, return "0" rather than "SI_USER".
			 */
			if ((si_code == 0) && (sig == 0))
				return (MSG_ORIG(MSG_GBL_ZERO));

			if (ndx >= ARRAY_NELTS(user_arr)) {
				const char *fmt;

				fmt = (fmt_flags & CONV_FMT_DECIMAL) ?
				    MSG_ORIG(MSG_FMT_INT) :
				    MSG_ORIG(MSG_FMT_HEXINT);

				(void) snprintf(inv_buf->buf,
				    sizeof (inv_buf->buf), fmt, si_code);
				return (inv_buf->buf);
			}
			return (conv_map_ds(ELFOSABI_NONE, EM_NONE, ndx,
			    ds_user_arr, fmt_flags, inv_buf));
		}
	}

	/*
	 * If we didn't return above, then this is a
	 * system generated signal, and the meaning of si_code
	 * depends on the signal that was delivered, and possibly
	 * on the target architecture.
	 */
	switch (mach) {
	case EM_386:
	case EM_AMD64:
		arch = ARCH_X86;
		break;

	case EM_SPARC:
	case EM_SPARC32PLUS:
	case EM_SPARCV9:
		arch = ARCH_X86;
		break;

	default:
		arch = ARCH_NONE;
		break;
	}

	switch (sig) {
	case SIGTRAP:
		return (conv_map_ds(ELFOSABI_NONE, EM_NONE, si_code,
		    ds_trap_arr, fmt_flags, inv_buf));

	case SIGCLD:
		return (conv_map_ds(ELFOSABI_NONE, EM_NONE, si_code,
		    ds_cld_arr, fmt_flags, inv_buf));

	case SIGPOLL:
		return (conv_map_ds(ELFOSABI_NONE, EM_NONE, si_code,
		    ds_poll_arr, fmt_flags, inv_buf));

	case SIGILL:
		return (conv_map_ds(ELFOSABI_NONE, EM_NONE, si_code,
		    ds_ill_arr, fmt_flags, inv_buf));

	case SIGEMT:
		switch (arch) {
		case ARCH_SPARC:
			return (conv_map_ds(ELFOSABI_NONE, EM_NONE, si_code,
			    ds_emt_arr_sparc, fmt_flags, inv_buf));
		case ARCH_X86:
			return (conv_map_ds(ELFOSABI_NONE, EM_NONE, si_code,
			    ds_emt_arr_x86, fmt_flags, inv_buf));
		}
		break;

	case SIGFPE:
		switch (arch) {
		case ARCH_SPARC:
			return (conv_map_ds(ELFOSABI_NONE, EM_NONE, si_code,
			    ds_fpe_arr_sparc, fmt_flags, inv_buf));
		case ARCH_X86:
			return (conv_map_ds(ELFOSABI_NONE, EM_NONE, si_code,
			    ds_fpe_arr_x86, fmt_flags, inv_buf));
		}
		break;

	case SIGSEGV:
		return (conv_map_ds(ELFOSABI_NONE, EM_NONE, si_code,
		    ds_segv_arr, fmt_flags, inv_buf));

	case SIGBUS:
		return (conv_map_ds(ELFOSABI_NONE, EM_NONE, si_code,
		    ds_bus_arr, fmt_flags, inv_buf));
	}

	/* If not recognized, format as a number */
	return (conv_invalid_val(inv_buf, si_code, fmt_flags));

}


#define	AUXAFFLGSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
	MSG_AUXV_AF_SUN_SETUGID_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_AUXV_AF_SUN_HWCAPVERIFY_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_AUXV_AF_SUN_NOPLM_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	CONV_INV_BUFSIZE		+ CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_cnote_auxv_af_buf_t is large enough:
 *
 * AUXAFFLGSZ is the real minimum size of the buffer required by
 * conv_cnote_auxv_af(). However, Conv_cnote_auxv_af_buf_t
 * uses CONV_CNOTE_AUXV_AF_BUFSIZE to set the buffer size. We do
 * things this way because the definition of AUXAFFLGSZ uses information
 * that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_CNOTE_AUXV_AF_BUFSIZE != AUXAFFLGSZ) && !defined(__lint)
#define	REPORT_BUFSIZE AUXAFFLGSZ
#include "report_bufsize.h"
#error "CONV_CNOTE_AUXV_AF_BUFSIZE does not match AUXAFFLGSZ"
#endif

const char *
conv_cnote_auxv_af(Word flags, Conv_fmt_flags_t fmt_flags,
    Conv_cnote_auxv_af_buf_t *cnote_auxv_af_buf)
{
	static const Val_desc vda[] = {
		{ AF_SUN_SETUGID,	MSG_AUXV_AF_SUN_SETUGID },
		{ AF_SUN_HWCAPVERIFY,	MSG_AUXV_AF_SUN_HWCAPVERIFY },
		{ AF_SUN_NOPLM,		MSG_AUXV_AF_SUN_NOPLM },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (cnote_auxv_af_buf->buf) };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	conv_arg.buf = cnote_auxv_af_buf->buf;
	conv_arg.oflags = conv_arg.rflags = flags;
	(void) conv_expn_field(&conv_arg, vda, fmt_flags);

	return ((const char *)cnote_auxv_af_buf->buf);
}


#define	CCFLGSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
	MSG_CC_CONTENT_STACK_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_CC_CONTENT_HEAP_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_CC_CONTENT_SHFILE_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_CC_CONTENT_SHANON_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_CC_CONTENT_TEXT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_CC_CONTENT_DATA_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_CC_CONTENT_RODATA_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_CC_CONTENT_ANON_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_CC_CONTENT_SHM_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_CC_CONTENT_ISM_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_CC_CONTENT_DISM_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_CC_CONTENT_CTF_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_CC_CONTENT_SYMTAB_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	CONV_INV_BUFSIZE		+ CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_cnote_cc_content_buf_t is large enough:
 *
 * CCFLGSZ is the real minimum size of the buffer required by
 * conv_cnote_cc_content(). However, Conv_cnote_cc_content_buf_t
 * uses CONV_CNOTE_CC_CONTENT_BUFSIZE to set the buffer size. We do
 * things this way because the definition of CCFLGSZ uses information
 * that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_CNOTE_CC_CONTENT_BUFSIZE != CCFLGSZ) && !defined(__lint)
#define	REPORT_BUFSIZE CCFLGSZ
#include "report_bufsize.h"
#error "CONV_CNOTE_CC_CONTENT_BUFSIZE does not match CCFLGSZ"
#endif

const char *
conv_cnote_cc_content(Lword flags, Conv_fmt_flags_t fmt_flags,
    Conv_cnote_cc_content_buf_t *cnote_cc_content_buf)
{
	/*
	 * Note: core_content_t is a 64-bit integer value, but our
	 * conv_expn_field() logic is all built around 32-bit
	 * Word values. This will probably need changing someday,
	 * but for now, we make do with the 32-bit engine. This works
	 * because the number of bits actually assigned in
	 * the core_content_t data type (<sys/corectl.h>) bits within
	 * 32-bits.
	 *
	 * The downside is that any bits set in the upper half of
	 * the flags will be ignored. At the time of this writing,
	 * that can only occur via core file corruption, which presumably
	 * would be evident in other ways.
	 */
	static const Val_desc vda[] = {
		{ (Word) CC_CONTENT_STACK,	MSG_CC_CONTENT_STACK },
		{ (Word) CC_CONTENT_HEAP,	MSG_CC_CONTENT_HEAP },
		{ (Word) CC_CONTENT_SHFILE,	MSG_CC_CONTENT_SHFILE },
		{ (Word) CC_CONTENT_SHANON,	MSG_CC_CONTENT_SHANON },
		{ (Word) CC_CONTENT_TEXT,	MSG_CC_CONTENT_TEXT },
		{ (Word) CC_CONTENT_DATA,	MSG_CC_CONTENT_DATA },
		{ (Word) CC_CONTENT_RODATA,	MSG_CC_CONTENT_RODATA },
		{ (Word) CC_CONTENT_ANON,	MSG_CC_CONTENT_ANON },
		{ (Word) CC_CONTENT_SHM,	MSG_CC_CONTENT_SHM },
		{ (Word) CC_CONTENT_ISM,	MSG_CC_CONTENT_ISM },
		{ (Word) CC_CONTENT_DISM,	MSG_CC_CONTENT_DISM },
		{ (Word) CC_CONTENT_CTF,	MSG_CC_CONTENT_CTF },
		{ (Word) CC_CONTENT_SYMTAB,	MSG_CC_CONTENT_SYMTAB },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (cnote_cc_content_buf->buf) };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	conv_arg.buf = cnote_cc_content_buf->buf;
	conv_arg.oflags = conv_arg.rflags = flags;
	(void) conv_expn_field(&conv_arg, vda, fmt_flags);

	return ((const char *)cnote_cc_content_buf->buf);
}


#define	PRFLGSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
	MSG_PR_FLAGS_STOPPED_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_ISTOP_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_DSTOP_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_STEP_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_ASLEEP_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_PCINVAL_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_ASLWP_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_AGENT_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_DETACH_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_DAEMON_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_IDLE_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_ISSYS_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_VFORKP_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_ORPHAN_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_NOSIGCHLD_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_WAITPID_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_FORK_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_RLC_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_KLC_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_ASYNC_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_MSACCT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_BPTADJ_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_PTRACE_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_MSFORK_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	CONV_INV_BUFSIZE		+ CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_cnote_pr_flags_buf_t is large enough:
 *
 * PRFLGSZ is the real minimum size of the buffer required by
 * conv_cnote_pr_flags(). However, Conv_cnote_pr_flags_buf_t
 * uses CONV_CNOTE_PR_FLAGS_BUFSIZE to set the buffer size. We do
 * things this way because the definition of PRFLGSZ uses information
 * that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_CNOTE_PR_FLAGS_BUFSIZE != PRFLGSZ) && !defined(__lint)
#define	REPORT_BUFSIZE PRFLGSZ
#include "report_bufsize.h"
#error "CONV_CNOTE_PR_FLAGS_BUFSIZE does not match PRFLGSZ"
#endif

const char *
conv_cnote_pr_flags(int flags, Conv_fmt_flags_t fmt_flags,
    Conv_cnote_pr_flags_buf_t *cnote_pr_flags_buf)
{
	static const Val_desc vda[] = {
		{ PR_STOPPED, 		MSG_PR_FLAGS_STOPPED },
		{ PR_ISTOP,		MSG_PR_FLAGS_ISTOP },
		{ PR_DSTOP,		MSG_PR_FLAGS_DSTOP },
		{ PR_STEP,		MSG_PR_FLAGS_STEP },
		{ PR_ASLEEP,		MSG_PR_FLAGS_ASLEEP },
		{ PR_PCINVAL,		MSG_PR_FLAGS_PCINVAL },
		{ PR_ASLWP,		MSG_PR_FLAGS_ASLWP },
		{ PR_AGENT,		MSG_PR_FLAGS_AGENT },
		{ PR_DETACH,		MSG_PR_FLAGS_DETACH },
		{ PR_DAEMON,		MSG_PR_FLAGS_DAEMON },
		{ PR_IDLE,		MSG_PR_FLAGS_IDLE },
		{ PR_ISSYS,		MSG_PR_FLAGS_ISSYS },
		{ PR_VFORKP,		MSG_PR_FLAGS_VFORKP },
		{ PR_ORPHAN,		MSG_PR_FLAGS_ORPHAN },
		{ PR_NOSIGCHLD,		MSG_PR_FLAGS_NOSIGCHLD },
		{ PR_WAITPID,		MSG_PR_FLAGS_WAITPID },
		{ PR_FORK,		MSG_PR_FLAGS_FORK },
		{ PR_RLC,		MSG_PR_FLAGS_RLC },
		{ PR_KLC,		MSG_PR_FLAGS_KLC },
		{ PR_ASYNC,		MSG_PR_FLAGS_ASYNC },
		{ PR_MSACCT,		MSG_PR_FLAGS_MSACCT },
		{ PR_BPTADJ,		MSG_PR_FLAGS_BPTADJ },
		{ PR_PTRACE,		MSG_PR_FLAGS_PTRACE },
		{ PR_MSFORK,		MSG_PR_FLAGS_MSFORK },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (cnote_pr_flags_buf->buf) };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	conv_arg.buf = cnote_pr_flags_buf->buf;
	conv_arg.oflags = conv_arg.rflags = flags;
	(void) conv_expn_field(&conv_arg, vda, fmt_flags);

	return ((const char *)cnote_pr_flags_buf->buf);
}


#define	OLDPRFLGSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
	MSG_PR_FLAGS_STOPPED_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_ISTOP_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_DSTOP_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_ASLEEP_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_FORK_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_RLC_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_PTRACE_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_PCINVAL_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_ISSYS_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_STEP_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_KLC_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_ASYNC_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_PCOMPAT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_MSACCT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_BPTADJ_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PR_FLAGS_ASLWP_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	CONV_INV_BUFSIZE		+ CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_cnote_old_pr_flags_buf_t is large enough:
 *
 * OLDPRFLGSZ is the real minimum size of the buffer required by
 * conv_cnote_old_pr_flags(). However, Conv_cnote_old_pr_flags_buf_t
 * uses CONV_CNOTE_OLD_PR_FLAGS_BUFSIZE to set the buffer size. We do
 * things this way because the definition of OLDPRFLGSZ uses information
 * that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_CNOTE_OLD_PR_FLAGS_BUFSIZE != OLDPRFLGSZ) && !defined(__lint)
#define	REPORT_BUFSIZE OLDPRFLGSZ
#include "report_bufsize.h"
#error "CONV_CNOTE_OLD_PR_FLAGS_BUFSIZE does not match OLDPRFLGSZ"
#endif

const char *
conv_cnote_old_pr_flags(int flags, Conv_fmt_flags_t fmt_flags,
    Conv_cnote_old_pr_flags_buf_t *cnote_old_pr_flags_buf)
{
	/*
	 * <sys/old_procfs.h> defines names for many of these flags
	 * that are also defined in <sys/procfs.h>, but with different
	 * values. To avoid confusion, we don't include <sys/old_procfs.h>,
	 * and specify the values directly.
	 */
	static const Val_desc vda[] = {
		{ 0x0001,		MSG_PR_FLAGS_STOPPED },
		{ 0x0002,		MSG_PR_FLAGS_ISTOP },
		{ 0x0004,		MSG_PR_FLAGS_DSTOP },
		{ 0x0008,		MSG_PR_FLAGS_ASLEEP },
		{ 0x0010,		MSG_PR_FLAGS_FORK },
		{ 0x0020,		MSG_PR_FLAGS_RLC },
		{ 0x0040,		MSG_PR_FLAGS_PTRACE },
		{ 0x0080,		MSG_PR_FLAGS_PCINVAL },
		{ 0x0100,		MSG_PR_FLAGS_ISSYS },
		{ 0x0200,		MSG_PR_FLAGS_STEP },
		{ 0x0400,		MSG_PR_FLAGS_KLC },
		{ 0x0800,		MSG_PR_FLAGS_ASYNC },
		{ 0x1000,		MSG_PR_FLAGS_PCOMPAT },
		{ 0x2000,		MSG_PR_FLAGS_MSACCT },
		{ 0x4000,		MSG_PR_FLAGS_BPTADJ },
		{ 0x8000,		MSG_PR_FLAGS_ASLWP },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (cnote_old_pr_flags_buf->buf) };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	conv_arg.buf = cnote_old_pr_flags_buf->buf;
	conv_arg.oflags = conv_arg.rflags = flags;
	(void) conv_expn_field(&conv_arg, vda, fmt_flags);

	return ((const char *)cnote_old_pr_flags_buf->buf);
}


#define	PROCFLGSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
	MSG_PROC_FLAG_SSYS_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_PROC_FLAG_SMSACCT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	CONV_INV_BUFSIZE		+ CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_cnote_proc_flag_buf_t is large enough:
 *
 * PROCFLGSZ is the real minimum size of the buffer required by
 * conv_cnote_proc_flag(). However, Conv_cnote_proc_flag_buf_t
 * uses CONV_CNOTE_PROC_FLAG_BUFSIZE to set the buffer size. We do
 * things this way because the definition of PROCFLGSZ uses information
 * that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_CNOTE_PROC_FLAG_BUFSIZE != PROCFLGSZ) && !defined(__lint)
#define	REPORT_BUFSIZE PROCFLGSZ
#include "report_bufsize.h"
#error "CONV_CNOTE_PROC_FLAG_BUFSIZE does not match PROCFLGSZ"
#endif

const char *
conv_cnote_proc_flag(int flags, Conv_fmt_flags_t fmt_flags,
    Conv_cnote_proc_flag_buf_t *cnote_proc_flag_buf)
{
	/*
	 * Most of the proc flags are implementation dependant, and can
	 * change between releases. As such, we do not attempt to translate
	 * them to symbolic form, but simply report them in hex form.
	 * However, SMSACCT and SSYS are special, and their bit values
	 * are maintained between releases so they can be used in the
	 * psinfo_t.p_flag field. We therefore translate these items.
	 *
	 * See <system/proc.h>
	 *
	 * Note: We don't want to include <sys/proc.h> in this file, because
	 * it redefines 'struct list', which we have defined in sgs.h. As
	 * SMSACCT and SSYS are stable public values, we simply use
	 * their numeric value.
	 */
	static const Val_desc vda[] = {
		{ 0x00000001, 		MSG_PROC_FLAG_SSYS },
		{ 0x02000000,		MSG_PROC_FLAG_SMSACCT },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (cnote_proc_flag_buf->buf) };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	conv_arg.buf = cnote_proc_flag_buf->buf;
	conv_arg.oflags = conv_arg.rflags = flags;
	(void) conv_expn_field(&conv_arg, vda, fmt_flags);

	return ((const char *)cnote_proc_flag_buf->buf);
}


#define	SAFLGSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
	MSG_SA_ONSTACK_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SA_RESETHAND_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SA_RESTART_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SA_SIGINFO_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SA_NODEFER_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SA_NOCLDWAIT_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SA_NOCLDSTOP_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	CONV_INV_BUFSIZE		+ CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_cnote_sa_flags_buf_t is large enough:
 *
 * SAFLGSZ is the real minimum size of the buffer required by
 * conv_cnote_sa_flags(). However, Conv_cnote_sa_flags_buf_t
 * uses CONV_CNOTE_SA_FLAGS_BUFSIZE to set the buffer size. We do
 * things this way because the definition of SAFLGSZ uses information
 * that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_CNOTE_SA_FLAGS_BUFSIZE != SAFLGSZ) && !defined(__lint)
#define	REPORT_BUFSIZE SAFLGSZ
#include "report_bufsize.h"
#error "CONV_CNOTE_SA_FLAGS_BUFSIZE does not match SAFLGSZ"
#endif

const char *
conv_cnote_sa_flags(int flags, Conv_fmt_flags_t fmt_flags,
    Conv_cnote_sa_flags_buf_t *cnote_sa_flags_buf)
{
	static const Val_desc vda[] = {
		{ SA_ONSTACK,		MSG_SA_ONSTACK },
		{ SA_RESETHAND,		MSG_SA_RESETHAND },
		{ SA_RESTART,		MSG_SA_RESTART },
		{ SA_SIGINFO,		MSG_SA_SIGINFO },
		{ SA_NODEFER,		MSG_SA_NODEFER },
		{ SA_NOCLDWAIT,		MSG_SA_NOCLDWAIT },
		{ SA_NOCLDSTOP,		MSG_SA_NOCLDSTOP },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (cnote_sa_flags_buf->buf) };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	conv_arg.buf = cnote_sa_flags_buf->buf;
	conv_arg.oflags = conv_arg.rflags = flags;
	(void) conv_expn_field(&conv_arg, vda, fmt_flags);

	return ((const char *)cnote_sa_flags_buf->buf);
}


#define	SSFLGSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
	MSG_SS_ONSTACK_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SS_DISABLE_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	CONV_INV_BUFSIZE		+ CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_cnote_ss_flags_buf_t is large enough:
 *
 * SSFLGSZ is the real minimum size of the buffer required by
 * conv_cnote_ss_flags(). However, Conv_cnote_ss_flags_buf_t
 * uses CONV_CNOTE_SS_FLAGS_BUFSIZE to set the buffer size. We do
 * things this way because the definition of SSFLGSZ uses information
 * that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_CNOTE_SS_FLAGS_BUFSIZE != SSFLGSZ) && !defined(__lint)
#define	REPORT_BUFSIZE SSFLGSZ
#include "report_bufsize.h"
#error "CONV_CNOTE_SS_FLAGS_BUFSIZE does not match SSFLGSZ"
#endif

const char *
conv_cnote_ss_flags(int flags, Conv_fmt_flags_t fmt_flags,
    Conv_cnote_ss_flags_buf_t *cnote_ss_flags_buf)
{
	static const Val_desc vda[] = {
		{ SS_ONSTACK,		MSG_SS_ONSTACK },
		{ SS_DISABLE,		MSG_SS_DISABLE },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (cnote_ss_flags_buf->buf) };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	conv_arg.buf = cnote_ss_flags_buf->buf;
	conv_arg.oflags = conv_arg.rflags = flags;
	(void) conv_expn_field(&conv_arg, vda, fmt_flags);

	return ((const char *)cnote_ss_flags_buf->buf);
}


/*
 * Solaris has a variety of types that use bitmasks to represent
 * sets of things like signals (sigset_t), faults (fltset_t), and
 * system calls (sysset_t). These types use arrays of unsigned 32-bit
 * integers to represent the set. These are public types that
 * cannot be changed, so they are generously oversized to allow
 * for future growth. Hence, there are usually unused bits.
 *
 * conv_bitmaskset() generalizes the process of displaying these items.
 */

typedef struct {
	const Val_desc	*vdp;		/* NULL, or bitmask description */
	uint32_t	unused_bits;	/* Mask of undefined bits */
} conv_bitmaskset_desc_t;

/*
 * entry:
 *	n_mask - # of 32-bit masks that make up this bitmask type.
 *	maskarr - Array of n_mask 32-bit mask values
 *	bitmask_descarr - Array of n_mask bitmask_desc_t descriptors,
 *		one for each mask, specifying the bitmask names, and
 *		a mask of the bits that are not defined by the system.
 *	fmt_flags - CONV_FMT_* values, used to specify formatting details.
 *	conv_buf - Buffer to receive formatted results
 *	conv_buf_size - Size of conv_buf, including room for NULL termination
 */
static const char *
conv_bitmaskset(uint32_t *maskarr, int n_mask,
    const conv_bitmaskset_desc_t *bitmask_descarr, Conv_fmt_flags_t fmt_flags,
    char *conv_buf, size_t conv_buf_size)
{
	CONV_EXPN_FIELD_ARG	conv_arg;
	int	i, need_sep = 0;

	/* If every bit of every mask is 0, return 0 as the result */
	for (i = 0; i < n_mask; i++)
		if (maskarr[i] != 0)
			break;
	if (i == n_mask)
		return (MSG_ORIG(MSG_GBL_ZERO));

	/*
	 * At least one bit is non-zero. Move through the masks
	 * and process each one.
	 */
	(void) memset(&conv_arg, 0, sizeof (conv_arg));
	conv_arg.bufsize = conv_buf_size;
	conv_arg.buf = conv_buf;
	if ((fmt_flags & CONV_FMT_NOBKT) == 0) {
		*conv_arg.buf++ = '[';
		*conv_arg.buf++ = ' ';
		conv_arg.bufsize -= 2;
	}

	/*
	 * conv_expn_field() orders its output with the most significant
	 * bits on the left. To preserve this ordering across the
	 * subwords or our "virtual bitmask", we need to process
	 * the sub-words in the same order, from most significant down
	 * to least significant. Since unassigned bits tend to be at
	 * the MSB end of the word, we process the unused bits first.
	 *
	 * One implication of this is that the caller should not use
	 * the unassigned bits for "abandoned" bits in the middle of
	 * a used range, but should instead define the string for
	 * that bit as being the string representation of that decimal
	 * value (i.e. "65"). That will cause the bit to be properly
	 * sorted among the named bits to either side of it.
	 */
	for (i = 0; i < n_mask; i++) {
		size_t		n;
		uint32_t	mask, unused_bits;
		const int	bits_per_mask = sizeof (mask) * 8;

		mask = maskarr[i];
		unused_bits = mask & bitmask_descarr[i].unused_bits;
		mask &= ~unused_bits;

		if (mask != 0) {

			conv_arg.oflags = conv_arg.rflags = mask;
			if (need_sep) {
				*conv_arg.buf++ = ' ';
				conv_arg.bufsize--;
			}
			need_sep = 1;
			(void) conv_expn_field(&conv_arg,
			    bitmask_descarr[i].vdp, fmt_flags | CONV_FMT_NOBKT);
			n = strlen(conv_arg.buf);
			conv_arg.bufsize -= n;
			conv_arg.buf += n;
		}

		if (unused_bits != 0) {
			uint32_t	bit = 0x00000001;
			int		j;

			for (j = 1; j <= bits_per_mask; j++, bit *= 2) {
				if ((unused_bits & bit) == 0)
					continue;

				if (need_sep) {
					*conv_arg.buf++ = ' ';
					conv_arg.bufsize--;
				}
				need_sep = 1;
				n = snprintf(conv_arg.buf, conv_arg.bufsize,
				    MSG_ORIG(MSG_FMT_WORD),
				    EC_WORD(j + (bits_per_mask * i)));
				conv_arg.buf += n;
				conv_arg.bufsize -= n;
			}
		}
	}
	if ((fmt_flags & CONV_FMT_NOBKT) == 0) {
		*conv_arg.buf++ = ' ';
		*conv_arg.buf++ = ']';
	}
	*conv_arg.buf = '\0';

	return ((const char *) conv_buf);
}


#define	SIGSET_FLAGSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
	/* sigset_t [0] - Signals [1 - 32] */ \
	MSG_SIGHUP_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGINT_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGQUIT_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGILL_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGTRAP_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGABRT_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGEMT_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGFPE_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGKILL_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGBUS_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGSEGV_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGSYS_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGPIPE_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGALRM_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGTERM_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGUSR1_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGUSR2_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGCHLD_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGPWR_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGWINCH_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGURG_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGPOLL_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGSTOP_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGTSTP_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGCONT_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGTTIN_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGTTOU_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGVTALRM_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGPROF_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGXCPU_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGXFSZ_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGWAITING_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	\
	/* \
	 * sigset_t [1] - Signals [33 - 64] \
	 * There are 24 unused bits, each of which needs two \
	 * characters plus a separator. \
	 */ \
	MSG_SIGLWP_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGFREEZE_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGTHAW_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGCANCEL_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGLOST_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGXRES_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGJVM1_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SIGJVM2_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	(24 * (2 + CONV_EXPN_FIELD_DEF_SEP_SIZE)) + \
	\
	/* \
	 * sigset_t [2] - Signals [65 - 96] \
	 * There are 32 unused bits, each of which needs two \
	 * characters plus a separator. \
	 */ \
	(32 * (2 + CONV_EXPN_FIELD_DEF_SEP_SIZE)) + \
	\
	/* \
	 * sigset_t [2] - Signals [97 - 128] \
	 * There are 32 unused bits. Three of these need two \
	 * characters, and 29 need 3. Each one needs a separator. \
	 */ \
	(3 * (2 + CONV_EXPN_FIELD_DEF_SEP_SIZE)) + \
	(29 * (3 + CONV_EXPN_FIELD_DEF_SEP_SIZE)) + \
	\
	CONV_INV_BUFSIZE	+ CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_cnote_sigset_buf_t is large enough:
 *
 * SIGSET_FLAGSZ is the real minimum size of the buffer required by
 * conv_cnote_sigset(). However, Conv_cnote_sigset_buf_t
 * uses CONV_CNOTE_SIGSET_BUFSIZE to set the buffer size. We do
 * things this way because the definition of SIGSET_FLAGSZ uses information
 * that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_CNOTE_SIGSET_BUFSIZE != SIGSET_FLAGSZ) && !defined(__lint)
#define	REPORT_BUFSIZE SIGSET_FLAGSZ
#include "report_bufsize.h"
#error "CONV_CNOTE_SIGSET_BUFSIZE does not match SIGSET_FLAGSZ"
#endif

const char *
conv_cnote_sigset(uint32_t *maskarr, int n_mask,
    Conv_fmt_flags_t fmt_flags, Conv_cnote_sigset_buf_t *cnote_sigset_buf)
{
#define	N_MASK 4

	static const Val_desc vda0[] = {
		{ 0x00000001,		MSG_SIGHUP_ALT },
		{ 0x00000002,		MSG_SIGINT_ALT },
		{ 0x00000004,		MSG_SIGQUIT_ALT },
		{ 0x00000008,		MSG_SIGILL_ALT },
		{ 0x00000010,		MSG_SIGTRAP_ALT },
		{ 0x00000020,		MSG_SIGABRT_ALT },
		{ 0x00000040,		MSG_SIGEMT_ALT },
		{ 0x00000080,		MSG_SIGFPE_ALT },
		{ 0x00000100,		MSG_SIGKILL_ALT },
		{ 0x00000200,		MSG_SIGBUS_ALT },
		{ 0x00000400,		MSG_SIGSEGV_ALT },
		{ 0x00000800,		MSG_SIGSYS_ALT },
		{ 0x00001000,		MSG_SIGPIPE_ALT },
		{ 0x00002000,		MSG_SIGALRM_ALT },
		{ 0x00004000,		MSG_SIGTERM_ALT },
		{ 0x00008000,		MSG_SIGUSR1_ALT },
		{ 0x00010000,		MSG_SIGUSR2_ALT },
		{ 0x00020000,		MSG_SIGCHLD_ALT },
		{ 0x00040000,		MSG_SIGPWR_ALT },
		{ 0x00080000,		MSG_SIGWINCH_ALT },
		{ 0x00100000,		MSG_SIGURG_ALT },
		{ 0x00200000,		MSG_SIGPOLL_ALT },
		{ 0x00400000,		MSG_SIGSTOP_ALT },
		{ 0x00800000,		MSG_SIGTSTP_ALT },
		{ 0x01000000,		MSG_SIGCONT_ALT },
		{ 0x02000000,		MSG_SIGTTIN_ALT },
		{ 0x04000000,		MSG_SIGTTOU_ALT },
		{ 0x08000000,		MSG_SIGVTALRM_ALT },
		{ 0x10000000,		MSG_SIGPROF_ALT },
		{ 0x20000000,		MSG_SIGXCPU_ALT },
		{ 0x40000000,		MSG_SIGXFSZ_ALT },
		{ 0x80000000,		MSG_SIGWAITING_ALT },
		{ 0,			0 }
	};
	static const Val_desc vda1[] = {
		{ 0x00000001,		MSG_SIGLWP_ALT },
		{ 0x00000002,		MSG_SIGFREEZE_ALT },
		{ 0x00000004,		MSG_SIGTHAW_ALT },
		{ 0x00000008,		MSG_SIGCANCEL_ALT },
		{ 0x00000010,		MSG_SIGLOST_ALT },
		{ 0x00000020,		MSG_SIGXRES_ALT },
		{ 0x00000040,		MSG_SIGJVM1_ALT },
		{ 0x00000080,		MSG_SIGJVM2_ALT },
		{ 0,			0 }
	};
	static const conv_bitmaskset_desc_t bitmask_desc[N_MASK] = {
		{ vda0, 0 },
		{ vda1, 0xffffff00 },
		{ NULL, 0xffffffff },
		{ NULL, 0xffffffff }
	};

	if (n_mask > N_MASK)
		n_mask = N_MASK;
	return (conv_bitmaskset(maskarr, n_mask, bitmask_desc, fmt_flags,
	    cnote_sigset_buf->buf, CONV_CNOTE_SIGSET_BUFSIZE));

#undef N_MASK
}


#define	FLTSET_FLAGSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
	/* \
	 * fltset_t[0] - Faults [1 - 32] \
	 * There are 19 unused bits, each of which needs two \
	 * characters plus a separator. \
	 */ \
	MSG_FLTILL_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_FLTPRIV_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_FLTBPT_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_FLTTRACE_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_FLTACCESS_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_FLTBOUNDS_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_FLTIOVF_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_FLTIZDIV_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_FLTFPE_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_FLTSTACK_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_FLTPAGE_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_FLTWATCH_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_FLTCPCOVF_ALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	(19 * (2 + CONV_EXPN_FIELD_DEF_SEP_SIZE)) + \
	/* \
	 * fltset_t [1] - Faults [33 - 64] \
	 * There are 32 unused bits, each of which needs two \
	 * characters plus a separator. \
	 */ \
	(32 * (2 + CONV_EXPN_FIELD_DEF_SEP_SIZE)) + \
	/* \
	 * fltset_t [2] - Faults [65 - 96] \
	 * There are 32 unused bits, each of which needs two \
	 * characters plus a separator. \
	 */ \
	(32 * (2 + CONV_EXPN_FIELD_DEF_SEP_SIZE)) + \
	/* \
	 * fltset_t [3] - Faults [97 - 128] \
	 * There are 32 unused bits. Three of these need two \
	 * characters, and 29 need 3. Each one needs a separator. \
	 */ \
	(3 * (2 + CONV_EXPN_FIELD_DEF_SEP_SIZE)) + \
	(29 * (3 + CONV_EXPN_FIELD_DEF_SEP_SIZE)) + \
	\
	CONV_INV_BUFSIZE	+ CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_cnote_fltset_buf_t is large enough:
 *
 * FLTSET_FLAGSZ is the real minimum size of the buffer required by
 * conv_cnote_fltset(). However, Conv_cnote_fltset_buf_t
 * uses CONV_CNOTE_FLTSET_BUFSIZE to set the buffer size. We do
 * things this way because the definition of FLTSET_FLAGSZ uses information
 * that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_CNOTE_FLTSET_BUFSIZE != FLTSET_FLAGSZ) && !defined(__lint)
#define	REPORT_BUFSIZE FLTSET_FLAGSZ
#include "report_bufsize.h"
#error "CONV_CNOTE_FLTSET_BUFSIZE does not match FLTSET_FLAGSZ"
#endif

const char *
conv_cnote_fltset(uint32_t *maskarr, int n_mask,
    Conv_fmt_flags_t fmt_flags, Conv_cnote_fltset_buf_t *cnote_fltset_buf)
{
#define	N_MASK 4

	static const Val_desc vda0[] = {
		{ 0x00000001,		MSG_FLTILL_ALT },
		{ 0x00000002,		MSG_FLTPRIV_ALT },
		{ 0x00000004,		MSG_FLTBPT_ALT },
		{ 0x00000008,		MSG_FLTTRACE_ALT },
		{ 0x00000010,		MSG_FLTACCESS_ALT },
		{ 0x00000020,		MSG_FLTBOUNDS_ALT },
		{ 0x00000040,		MSG_FLTIOVF_ALT },
		{ 0x00000080,		MSG_FLTIZDIV_ALT },
		{ 0x00000100,		MSG_FLTFPE_ALT },
		{ 0x00000200,		MSG_FLTSTACK_ALT },
		{ 0x00000400,		MSG_FLTPAGE_ALT },
		{ 0x00000800,		MSG_FLTWATCH_ALT },
		{ 0x00001000,		MSG_FLTCPCOVF_ALT },
		{ 0,			0 }
	};
	static const conv_bitmaskset_desc_t bitmask_desc[N_MASK] = {
		{ vda0, 0xffffe000 },
		{ NULL, 0xffffffff },
		{ NULL, 0xffffffff },
		{ NULL, 0xffffffff }
	};

	if (n_mask > N_MASK)
		n_mask = N_MASK;
	return (conv_bitmaskset(maskarr, n_mask, bitmask_desc, fmt_flags,
	    cnote_fltset_buf->buf, CONV_CNOTE_FLTSET_BUFSIZE));

#undef N_MASK
}



#define	SYSSET_FLAGSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
	(512 * CONV_EXPN_FIELD_DEF_SEP_SIZE) + \
	\
	/* sysset_t[0] - System Calls [1 - 32] */ \
	MSG_SYS_EXIT_ALT_SIZE			/* 1 */ + \
	MSG_SYS_2_SIZE				/* 2 (unused) */ + \
	MSG_SYS_READ_ALT_SIZE			/* 3 */ + \
	MSG_SYS_WRITE_ALT_SIZE			/* 4 */ + \
	MSG_SYS_OPEN_ALT_SIZE			/* 5 */ + \
	MSG_SYS_CLOSE_ALT_SIZE			/* 6 */ + \
	MSG_SYS_7_SIZE				/* 7 (unused) */ + \
	MSG_SYS_8_SIZE				/* 8 (unused) */ + \
	MSG_SYS_LINK_ALT_SIZE			/* 9 */ + \
	MSG_SYS_UNLINK_ALT_SIZE			/* 10 */ + \
	MSG_SYS_11_SIZE				/* 11 (unused) */ + \
	MSG_SYS_CHDIR_ALT_SIZE			/* 12 */ + \
	MSG_SYS_TIME_ALT_SIZE			/* 13 */ + \
	MSG_SYS_MKNOD_ALT_SIZE			/* 14 */ + \
	MSG_SYS_CHMOD_ALT_SIZE			/* 15 */ + \
	MSG_SYS_CHOWN_ALT_SIZE			/* 16 */ + \
	MSG_SYS_BRK_ALT_SIZE			/* 17 */ + \
	MSG_SYS_STAT_ALT_SIZE			/* 18 */ + \
	MSG_SYS_LSEEK_ALT_SIZE			/* 19 */ + \
	MSG_SYS_GETPID_ALT_SIZE			/* 20 */ + \
	MSG_SYS_MOUNT_ALT_SIZE			/* 21 */ + \
	MSG_SYS_22_SIZE				/* 22 (unused) */ + \
	MSG_SYS_SETUID_ALT_SIZE			/* 23 */ + \
	MSG_SYS_GETUID_ALT_SIZE			/* 24 */ + \
	MSG_SYS_STIME_ALT_SIZE			/* 25 */ + \
	MSG_SYS_PCSAMPLE_ALT_SIZE		/* 26 */ + \
	MSG_SYS_ALARM_ALT_SIZE			/* 27 */ + \
	MSG_SYS_FSTAT_ALT_SIZE			/* 28 */ + \
	MSG_SYS_PAUSE_ALT_SIZE			/* 29 */ + \
	MSG_SYS_30_SIZE				/* 30 (unused) */ + \
	MSG_SYS_STTY_ALT_SIZE			/* 31 */ + \
	MSG_SYS_GTTY_ALT_SIZE			/* 32 */ + \
	\
	/* sysset_t[1] - System Calls [33 - 64] */ \
	MSG_SYS_ACCESS_ALT_SIZE			/* 33 */ + \
	MSG_SYS_NICE_ALT_SIZE			/* 34 */ + \
	MSG_SYS_STATFS_ALT_SIZE			/* 35 */ + \
	MSG_SYS_SYNC_ALT_SIZE			/* 36 */ + \
	MSG_SYS_KILL_ALT_SIZE			/* 37 */ + \
	MSG_SYS_FSTATFS_ALT_SIZE		/* 38 */ + \
	MSG_SYS_PGRPSYS_ALT_SIZE		/* 39 */ + \
	MSG_SYS_UUCOPYSTR_ALT_SIZE		/* 40 */ + \
	MSG_SYS_41_SIZE				/* 41 (unused) */ + \
	MSG_SYS_PIPE_ALT_SIZE			/* 42 */ + \
	MSG_SYS_TIMES_ALT_SIZE			/* 43 */ + \
	MSG_SYS_PROFIL_ALT_SIZE			/* 44 */ + \
	MSG_SYS_FACCESSAT_ALT_SIZE		/* 45 */ + \
	MSG_SYS_SETGID_ALT_SIZE			/* 46 */ + \
	MSG_SYS_GETGID_ALT_SIZE			/* 47 */ + \
	MSG_SYS_48_SIZE				/* 48 (unused) */ + \
	MSG_SYS_MSGSYS_ALT_SIZE			/* 49 */ + \
	MSG_SYS_SYSI86_ALT_SIZE			/* 50 */ + \
	MSG_SYS_ACCT_ALT_SIZE			/* 51 */ + \
	MSG_SYS_SHMSYS_ALT_SIZE			/* 52 */ + \
	MSG_SYS_SEMSYS_ALT_SIZE			/* 53 */ + \
	MSG_SYS_IOCTL_ALT_SIZE			/* 54 */ + \
	MSG_SYS_UADMIN_ALT_SIZE			/* 55 */ + \
	MSG_SYS_FCHOWNAT_ALT_SIZE		/* 56 */ + \
	MSG_SYS_UTSSYS_ALT_SIZE			/* 57 */ + \
	MSG_SYS_FDSYNC_ALT_SIZE			/* 58 */ + \
	MSG_SYS_EXECVE_ALT_SIZE			/* 59 */ + \
	MSG_SYS_UMASK_ALT_SIZE			/* 60 */ + \
	MSG_SYS_CHROOT_ALT_SIZE			/* 61 */ + \
	MSG_SYS_FCNTL_ALT_SIZE			/* 62 */ + \
	MSG_SYS_ULIMIT_ALT_SIZE			/* 63 */ + \
	MSG_SYS_RENAMEAT_ALT_SIZE		/* 64 */ + \
	\
	/* sysset_t[2] - System Calls [65 - 96] */ \
	MSG_SYS_UNLINKAT_ALT_SIZE		/* 65 */ + \
	MSG_SYS_FSTATAT_ALT_SIZE		/* 66 */ + \
	MSG_SYS_FSTATAT64_ALT_SIZE		/* 67 */ + \
	MSG_SYS_OPENAT_ALT_SIZE			/* 68 */ + \
	MSG_SYS_OPENAT64_ALT_SIZE		/* 69 */ + \
	MSG_SYS_TASKSYS_ALT_SIZE		/* 70 */ + \
	MSG_SYS_ACCTCTL_ALT_SIZE		/* 71 */ + \
	MSG_SYS_EXACCTSYS_ALT_SIZE		/* 72 */ + \
	MSG_SYS_GETPAGESIZES_ALT_SIZE		/* 73 */ + \
	MSG_SYS_RCTLSYS_ALT_SIZE		/* 74 */ + \
	MSG_SYS_SIDSYS_ALT_SIZE			/* 75 */ + \
	MSG_SYS_76_SIZE				/* 76 (unused) */ + \
	MSG_SYS_LWP_PARK_ALT_SIZE		/* 77 */ + \
	MSG_SYS_SENDFILEV_ALT_SIZE		/* 78 */ + \
	MSG_SYS_RMDIR_ALT_SIZE			/* 79 */ + \
	MSG_SYS_MKDIR_ALT_SIZE			/* 80 */ + \
	MSG_SYS_GETDENTS_ALT_SIZE		/* 81 */ + \
	MSG_SYS_PRIVSYS_ALT_SIZE		/* 82 */ + \
	MSG_SYS_UCREDSYS_ALT_SIZE		/* 83 */ + \
	MSG_SYS_SYSFS_ALT_SIZE			/* 84 */ + \
	MSG_SYS_GETMSG_ALT_SIZE			/* 85 */ + \
	MSG_SYS_PUTMSG_ALT_SIZE			/* 86 */ + \
	MSG_SYS_87_SIZE				/* 87 (unused) */ + \
	MSG_SYS_LSTAT_ALT_SIZE			/* 88 */ + \
	MSG_SYS_SYMLINK_ALT_SIZE		/* 89 */ + \
	MSG_SYS_READLINK_ALT_SIZE		/* 90 */ + \
	MSG_SYS_SETGROUPS_ALT_SIZE		/* 91 */ + \
	MSG_SYS_GETGROUPS_ALT_SIZE		/* 92 */ + \
	MSG_SYS_FCHMOD_ALT_SIZE			/* 93 */ + \
	MSG_SYS_FCHOWN_ALT_SIZE			/* 94 */ + \
	MSG_SYS_SIGPROCMASK_ALT_SIZE		/* 95 */ + \
	MSG_SYS_SIGSUSPEND_ALT_SIZE		/* 96 */ + \
	\
	/* sysset_t[3] - System Calls [97 - 128] */ \
	MSG_SYS_SIGALTSTACK_ALT_SIZE		/* 97 */ + \
	MSG_SYS_SIGACTION_ALT_SIZE		/* 98 */ + \
	MSG_SYS_SIGPENDING_ALT_SIZE		/* 99 */ + \
	MSG_SYS_CONTEXT_ALT_SIZE		/* 100 */ + \
	MSG_SYS_101_SIZE			/* 101 (unused) */ + \
	MSG_SYS_102_SIZE			/* 102 (unused) */ + \
	MSG_SYS_STATVFS_ALT_SIZE		/* 103 */ + \
	MSG_SYS_FSTATVFS_ALT_SIZE		/* 104 */ + \
	MSG_SYS_GETLOADAVG_ALT_SIZE		/* 105 */ + \
	MSG_SYS_NFSSYS_ALT_SIZE			/* 106 */ + \
	MSG_SYS_WAITID_ALT_SIZE			/* 107 */ + \
	MSG_SYS_SIGSENDSYS_ALT_SIZE		/* 108 */ + \
	MSG_SYS_HRTSYS_ALT_SIZE			/* 109 */ + \
	MSG_SYS_UTIMESYS_ALT_SIZE		/* 110 */ + \
	MSG_SYS_SIGRESEND_ALT_SIZE		/* 111 */ + \
	MSG_SYS_PRIOCNTLSYS_ALT_SIZE		/* 112 */ + \
	MSG_SYS_PATHCONF_ALT_SIZE		/* 113 */ + \
	MSG_SYS_MINCORE_ALT_SIZE		/* 114 */ + \
	MSG_SYS_MMAP_ALT_SIZE			/* 115 */ + \
	MSG_SYS_MPROTECT_ALT_SIZE		/* 116 */ + \
	MSG_SYS_MUNMAP_ALT_SIZE			/* 117 */ + \
	MSG_SYS_FPATHCONF_ALT_SIZE		/* 118 */ + \
	MSG_SYS_VFORK_ALT_SIZE			/* 119 */ + \
	MSG_SYS_FCHDIR_ALT_SIZE			/* 120 */ + \
	MSG_SYS_READV_ALT_SIZE			/* 121 */ + \
	MSG_SYS_WRITEV_ALT_SIZE			/* 122 */ + \
	MSG_SYS_123_SIZE			/* 123 (unused) */ + \
	MSG_SYS_124_SIZE			/* 124 (unused) */ + \
	MSG_SYS_125_SIZE			/* 125 (unused) */ + \
	MSG_SYS_126_SIZE			/* 126 (unused) */ + \
	MSG_SYS_MMAPOBJ_ALT_SIZE		/* 127 */ + \
	MSG_SYS_SETRLIMIT_ALT_SIZE		/* 128 */ + \
	\
	/* sysset_t[4] - System Calls [129 - 160] */ \
	MSG_SYS_GETRLIMIT_ALT_SIZE		/* 129 */ + \
	MSG_SYS_LCHOWN_ALT_SIZE			/* 130 */ + \
	MSG_SYS_MEMCNTL_ALT_SIZE		/* 131 */ + \
	MSG_SYS_GETPMSG_ALT_SIZE		/* 132 */ + \
	MSG_SYS_PUTPMSG_ALT_SIZE		/* 133 */ + \
	MSG_SYS_RENAME_ALT_SIZE			/* 134 */ + \
	MSG_SYS_UNAME_ALT_SIZE			/* 135 */ + \
	MSG_SYS_SETEGID_ALT_SIZE		/* 136 */ + \
	MSG_SYS_SYSCONFIG_ALT_SIZE		/* 137 */ + \
	MSG_SYS_ADJTIME_ALT_SIZE		/* 138 */ + \
	MSG_SYS_SYSTEMINFO_ALT_SIZE		/* 139 */ + \
	MSG_SYS_SHAREFS_ALT_SIZE		/* 140 */ + \
	MSG_SYS_SETEUID_ALT_SIZE		/* 141 */ + \
	MSG_SYS_FORKSYS_ALT_SIZE		/* 142 */ + \
	MSG_SYS_143_SIZE			/* 143 (unused) */ + \
	MSG_SYS_SIGTIMEDWAIT_ALT_SIZE		/* 144 */ + \
	MSG_SYS_LWP_INFO_ALT_SIZE		/* 145 */ + \
	MSG_SYS_YIELD_ALT_SIZE			/* 146 */ + \
	MSG_SYS_147_SIZE			/* 147 (unused) */ + \
	MSG_SYS_LWP_SEMA_POST_ALT_SIZE		/* 148 */ + \
	MSG_SYS_LWP_SEMA_TRYWAIT_ALT_SIZE	/* 149 */ + \
	MSG_SYS_LWP_DETACH_ALT_SIZE		/* 150 */ + \
	MSG_SYS_CORECTL_ALT_SIZE		/* 151 */ + \
	MSG_SYS_MODCTL_ALT_SIZE			/* 152 */ + \
	MSG_SYS_FCHROOT_ALT_SIZE		/* 153 */ + \
	MSG_SYS_154_SIZE			/* 154 (unused) */ + \
	MSG_SYS_VHANGUP_ALT_SIZE		/* 155 */ + \
	MSG_SYS_GETTIMEOFDAY_ALT_SIZE		/* 156 */ + \
	MSG_SYS_GETITIMER_ALT_SIZE		/* 157 */ + \
	MSG_SYS_SETITIMER_ALT_SIZE		/* 158 */ + \
	MSG_SYS_LWP_CREATE_ALT_SIZE		/* 159 */ + \
	MSG_SYS_LWP_EXIT_ALT_SIZE		/* 160 */ + \
	\
	/* sysset_t[5] - System Calls [161 - 192] */ \
	MSG_SYS_LWP_SUSPEND_ALT_SIZE		/* 161 */ + \
	MSG_SYS_LWP_CONTINUE_ALT_SIZE		/* 162 */ + \
	MSG_SYS_LWP_KILL_ALT_SIZE		/* 163 */ + \
	MSG_SYS_LWP_SELF_ALT_SIZE		/* 164 */ + \
	MSG_SYS_LWP_SIGMASK_ALT_SIZE		/* 165 */ + \
	MSG_SYS_LWP_PRIVATE_ALT_SIZE		/* 166 */ + \
	MSG_SYS_LWP_WAIT_ALT_SIZE		/* 167 */ + \
	MSG_SYS_LWP_MUTEX_WAKEUP_ALT_SIZE	/* 168 */ + \
	MSG_SYS_169_SIZE			/* 169 (unused) */ + \
	MSG_SYS_LWP_COND_WAIT_ALT_SIZE		/* 170 */ + \
	MSG_SYS_LWP_COND_SIGNAL_ALT_SIZE	/* 171 */ + \
	MSG_SYS_LWP_COND_BROADCAST_ALT_SIZE	/* 172 */ + \
	MSG_SYS_PREAD_ALT_SIZE			/* 173 */ + \
	MSG_SYS_PWRITE_ALT_SIZE			/* 174 */ + \
	MSG_SYS_LLSEEK_ALT_SIZE			/* 175 */ + \
	MSG_SYS_INST_SYNC_ALT_SIZE		/* 176 */ + \
	MSG_SYS_BRAND_ALT_SIZE			/* 177 */ + \
	MSG_SYS_KAIO_ALT_SIZE			/* 178 */ + \
	MSG_SYS_CPC_ALT_SIZE			/* 179 */ + \
	MSG_SYS_LGRPSYS_ALT_SIZE		/* 180 */ + \
	MSG_SYS_RUSAGESYS_ALT_SIZE		/* 181 */ + \
	MSG_SYS_PORT_ALT_SIZE			/* 182 */ + \
	MSG_SYS_POLLSYS_ALT_SIZE		/* 183 */ + \
	MSG_SYS_LABELSYS_ALT_SIZE		/* 184 */ + \
	MSG_SYS_ACL_ALT_SIZE			/* 185 */ + \
	MSG_SYS_AUDITSYS_ALT_SIZE		/* 186 */ + \
	MSG_SYS_PROCESSOR_BIND_ALT_SIZE		/* 187 */ + \
	MSG_SYS_PROCESSOR_INFO_ALT_SIZE		/* 188 */ + \
	MSG_SYS_P_ONLINE_ALT_SIZE		/* 189 */ + \
	MSG_SYS_SIGQUEUE_ALT_SIZE		/* 190 */ + \
	MSG_SYS_CLOCK_GETTIME_ALT_SIZE		/* 191 */ + \
	MSG_SYS_CLOCK_SETTIME_ALT_SIZE		/* 192 */ + \
	\
	/* sysset_t[6] - System Calls [193 - 224] */ \
	MSG_SYS_CLOCK_GETRES_ALT_SIZE		/* 193 */ + \
	MSG_SYS_TIMER_CREATE_ALT_SIZE		/* 194 */ + \
	MSG_SYS_TIMER_DELETE_ALT_SIZE		/* 195 */ + \
	MSG_SYS_TIMER_SETTIME_ALT_SIZE		/* 196 */ + \
	MSG_SYS_TIMER_GETTIME_ALT_SIZE		/* 197 */ + \
	MSG_SYS_TIMER_GETOVERRUN_ALT_SIZE	/* 198 */ + \
	MSG_SYS_NANOSLEEP_ALT_SIZE		/* 199 */ + \
	MSG_SYS_FACL_ALT_SIZE			/* 200 */ + \
	MSG_SYS_DOOR_ALT_SIZE			/* 201 */ + \
	MSG_SYS_SETREUID_ALT_SIZE		/* 202 */ + \
	MSG_SYS_SETREGID_ALT_SIZE		/* 203 */ + \
	MSG_SYS_INSTALL_UTRAP_ALT_SIZE		/* 204 */ + \
	MSG_SYS_SIGNOTIFY_ALT_SIZE		/* 205 */ + \
	MSG_SYS_SCHEDCTL_ALT_SIZE		/* 206 */ + \
	MSG_SYS_PSET_ALT_SIZE			/* 207 */ + \
	MSG_SYS_SPARC_UTRAP_INSTALL_ALT_SIZE	/* 208 */ + \
	MSG_SYS_RESOLVEPATH_ALT_SIZE		/* 209 */ + \
	MSG_SYS_LWP_MUTEX_TIMEDLOCK_ALT_SIZE	/* 210 */ + \
	MSG_SYS_LWP_SEMA_TIMEDWAIT_ALT_SIZE	/* 211 */ + \
	MSG_SYS_LWP_RWLOCK_SYS_ALT_SIZE		/* 212 */ + \
	MSG_SYS_GETDENTS64_ALT_SIZE		/* 213 */ + \
	MSG_SYS_MMAP64_ALT_SIZE			/* 214 */ + \
	MSG_SYS_STAT64_ALT_SIZE			/* 215 */ + \
	MSG_SYS_LSTAT64_ALT_SIZE		/* 216 */ + \
	MSG_SYS_FSTAT64_ALT_SIZE		/* 217 */ + \
	MSG_SYS_STATVFS64_ALT_SIZE		/* 218 */ + \
	MSG_SYS_FSTATVFS64_ALT_SIZE		/* 219 */ + \
	MSG_SYS_SETRLIMIT64_ALT_SIZE		/* 220 */ + \
	MSG_SYS_GETRLIMIT64_ALT_SIZE		/* 221 */ + \
	MSG_SYS_PREAD64_ALT_SIZE		/* 222 */ + \
	MSG_SYS_PWRITE64_ALT_SIZE		/* 223 */ + \
	MSG_SYS_224_SIZE			/* 224 (unused) */ + \
	\
	/* sysset_t[7] - System Calls [225 - 256] */ \
	MSG_SYS_OPEN64_ALT_SIZE			/* 225 */ + \
	MSG_SYS_RPCSYS_ALT_SIZE			/* 226 */ + \
	MSG_SYS_ZONE_ALT_SIZE			/* 227 */ + \
	MSG_SYS_AUTOFSSYS_ALT_SIZE		/* 228 */ + \
	MSG_SYS_GETCWD_ALT_SIZE			/* 229 */ + \
	MSG_SYS_SO_SOCKET_ALT_SIZE		/* 230 */ + \
	MSG_SYS_SO_SOCKETPAIR_ALT_SIZE		/* 231 */ + \
	MSG_SYS_BIND_ALT_SIZE			/* 232 */ + \
	MSG_SYS_LISTEN_ALT_SIZE			/* 233 */ + \
	MSG_SYS_ACCEPT_ALT_SIZE			/* 234 */ + \
	MSG_SYS_CONNECT_ALT_SIZE		/* 235 */ + \
	MSG_SYS_SHUTDOWN_ALT_SIZE		/* 236 */ + \
	MSG_SYS_RECV_ALT_SIZE			/* 237 */ + \
	MSG_SYS_RECVFROM_ALT_SIZE		/* 238 */ + \
	MSG_SYS_RECVMSG_ALT_SIZE		/* 239 */ + \
	MSG_SYS_SEND_ALT_SIZE			/* 240 */ + \
	MSG_SYS_SENDMSG_ALT_SIZE		/* 241 */ + \
	MSG_SYS_SENDTO_ALT_SIZE			/* 242 */ + \
	MSG_SYS_GETPEERNAME_ALT_SIZE		/* 243 */ + \
	MSG_SYS_GETSOCKNAME_ALT_SIZE		/* 244 */ + \
	MSG_SYS_GETSOCKOPT_ALT_SIZE		/* 245 */ + \
	MSG_SYS_SETSOCKOPT_ALT_SIZE		/* 246 */ + \
	MSG_SYS_SOCKCONFIG_ALT_SIZE		/* 247 */ + \
	MSG_SYS_NTP_GETTIME_ALT_SIZE		/* 248 */ + \
	MSG_SYS_NTP_ADJTIME_ALT_SIZE		/* 249 */ + \
	MSG_SYS_LWP_MUTEX_UNLOCK_ALT_SIZE	/* 250 */ + \
	MSG_SYS_LWP_MUTEX_TRYLOCK_ALT_SIZE	/* 251 */ + \
	MSG_SYS_LWP_MUTEX_REGISTER_ALT_SIZE	/* 252 */ + \
	MSG_SYS_CLADM_ALT_SIZE			/* 253 */ + \
	MSG_SYS_UUCOPY_ALT_SIZE			/* 254 */ + \
	MSG_SYS_UMOUNT2_ALT_SIZE		/* 255 */ + \
	3					/* 256 (unused) */ + \
	\
	/* sysset_t[8] - System Calls [257 - 288] */ \
	(32 * 3)				/* 257 - 288 (unused) */ + \
	\
	/* sysset_t[9] - System Calls [289 - 320] */ \
	(32 * 3)				/* 289 - 320 (unused) */ + \
	\
	/* sysset_t[10] - System Calls [321 - 352] */ \
	(32 * 3)				/* 321 - 352 (unused) */ + \
	\
	/* sysset_t[11] - System Calls [353 - 384] */ \
	(32 * 3)				/* 353 - 384 (unused) */ + \
	\
	/* sysset_t[12] - System Calls [385 - 416] */ \
	(32 * 3)				/* 385 - 416 (unused) */ + \
	\
	/* sysset_t[13] - System Calls [417 - 448] */ \
	(32 * 3)				/* 417 - 448 (unused) */ + \
	\
	/* sysset_t[14] - System Calls [449 - 480] */ \
	(32 * 3)				/* 449 - 480 (unused) */ + \
	\
	/* sysset_t[15] - System Calls [481 - 512] */ \
	(32 * 3)				/* 481 - 512 (unused) */ + \
	\
	CONV_INV_BUFSIZE	+ CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_cnote_sysset_buf_t is large enough:
 *
 * SYSSET_FLAGSZ is the real minimum size of the buffer required by
 * conv_cnote_sysset(). However, Conv_cnote_sysset_buf_t
 * uses CONV_CNOTE_SYSSET_BUFSIZE to set the buffer size. We do
 * things this way because the definition of SYSSET_FLAGSZ uses information
 * that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_CNOTE_SYSSET_BUFSIZE != SYSSET_FLAGSZ) && !defined(__lint)
#define	REPORT_BUFSIZE SYSSET_FLAGSZ
#include "report_bufsize.h"
#error "CONV_CNOTE_SYSSET_BUFSIZE does not match SYSSET_FLAGSZ"
#endif

const char *
conv_cnote_sysset(uint32_t *maskarr, int n_mask,
    Conv_fmt_flags_t fmt_flags, Conv_cnote_sysset_buf_t *cnote_sysset_buf)
{
#define	N_MASK 16

	static const Val_desc vda0[] = {	/* System Calls [1 - 32] */
		{ 0x00000001,	MSG_SYS_EXIT_ALT },
		{ 0x00000002,	MSG_SYS_2 },
		{ 0x00000004,	MSG_SYS_READ_ALT },
		{ 0x00000008,	MSG_SYS_WRITE_ALT },
		{ 0x00000010,	MSG_SYS_OPEN_ALT },
		{ 0x00000020,	MSG_SYS_CLOSE_ALT },
		{ 0x00000040,	MSG_SYS_7 },
		{ 0x00000080,	MSG_SYS_8 },
		{ 0x00000100,	MSG_SYS_LINK_ALT },
		{ 0x00000200,	MSG_SYS_UNLINK_ALT },
		{ 0x00000400,	MSG_SYS_11 },
		{ 0x00000800,	MSG_SYS_CHDIR_ALT },
		{ 0x00001000,	MSG_SYS_TIME_ALT },
		{ 0x00002000,	MSG_SYS_MKNOD_ALT },
		{ 0x00004000,	MSG_SYS_CHMOD_ALT },
		{ 0x00008000,	MSG_SYS_CHOWN_ALT },
		{ 0x00010000,	MSG_SYS_BRK_ALT },
		{ 0x00020000,	MSG_SYS_STAT_ALT },
		{ 0x00040000,	MSG_SYS_LSEEK_ALT },
		{ 0x00080000,	MSG_SYS_GETPID_ALT },
		{ 0x00100000,	MSG_SYS_MOUNT_ALT },
		{ 0x00200000,	MSG_SYS_22 },
		{ 0x00400000,	MSG_SYS_SETUID_ALT },
		{ 0x00800000,	MSG_SYS_GETUID_ALT },
		{ 0x01000000,	MSG_SYS_STIME_ALT },
		{ 0x02000000,	MSG_SYS_PCSAMPLE_ALT },
		{ 0x04000000,	MSG_SYS_ALARM_ALT },
		{ 0x08000000,	MSG_SYS_FSTAT_ALT },
		{ 0x10000000,	MSG_SYS_PAUSE_ALT },
		{ 0x20000000,	MSG_SYS_30 },
		{ 0x40000000,	MSG_SYS_STTY_ALT },
		{ 0x80000000,	MSG_SYS_GTTY_ALT },
		{ 0,		0 }
	};
	static const Val_desc vda1[] = {	/* System Calls [33 - 64] */
		{ 0x00000001,	MSG_SYS_ACCESS_ALT },
		{ 0x00000002,	MSG_SYS_NICE_ALT },
		{ 0x00000004,	MSG_SYS_STATFS_ALT },
		{ 0x00000008,	MSG_SYS_SYNC_ALT },
		{ 0x00000010,	MSG_SYS_KILL_ALT },
		{ 0x00000020,	MSG_SYS_FSTATFS_ALT },
		{ 0x00000040,	MSG_SYS_PGRPSYS_ALT },
		{ 0x00000080,	MSG_SYS_UUCOPYSTR_ALT },
		{ 0x00000100,	MSG_SYS_41 },
		{ 0x00000200,	MSG_SYS_PIPE_ALT },
		{ 0x00000400,	MSG_SYS_TIMES_ALT },
		{ 0x00000800,	MSG_SYS_PROFIL_ALT },
		{ 0x00001000,	MSG_SYS_FACCESSAT_ALT },
		{ 0x00002000,	MSG_SYS_SETGID_ALT },
		{ 0x00004000,	MSG_SYS_GETGID_ALT },
		{ 0x00008000,	MSG_SYS_48 },
		{ 0x00010000,	MSG_SYS_MSGSYS_ALT },
		{ 0x00020000,	MSG_SYS_SYSI86_ALT },
		{ 0x00040000,	MSG_SYS_ACCT_ALT },
		{ 0x00080000,	MSG_SYS_SHMSYS_ALT },
		{ 0x00100000,	MSG_SYS_SEMSYS_ALT },
		{ 0x00200000,	MSG_SYS_IOCTL_ALT },
		{ 0x00400000,	MSG_SYS_UADMIN_ALT },
		{ 0x00800000,	MSG_SYS_FCHOWNAT_ALT },
		{ 0x01000000,	MSG_SYS_UTSSYS_ALT },
		{ 0x0200000,	MSG_SYS_FDSYNC_ALT },
		{ 0x04000000,	MSG_SYS_EXECVE_ALT },
		{ 0x08000000,	MSG_SYS_UMASK_ALT },
		{ 0x10000000,	MSG_SYS_CHROOT_ALT },
		{ 0x20000000,	MSG_SYS_FCNTL_ALT },
		{ 0x40000000,	MSG_SYS_ULIMIT_ALT },
		{ 0x80000000,	MSG_SYS_RENAMEAT_ALT },
		{ 0,		0 }
	};
	static const Val_desc vda2[] = {	/* System Calls [65 - 96] */
		{ 0x00000001,	MSG_SYS_UNLINKAT_ALT },
		{ 0x00000002,	MSG_SYS_FSTATAT_ALT },
		{ 0x00000004,	MSG_SYS_FSTATAT64_ALT },
		{ 0x00000008,	MSG_SYS_OPENAT_ALT },
		{ 0x00000010,	MSG_SYS_OPENAT64_ALT },
		{ 0x00000020,	MSG_SYS_TASKSYS_ALT },
		{ 0x00000040,	MSG_SYS_ACCTCTL_ALT },
		{ 0x00000080,	MSG_SYS_EXACCTSYS_ALT },
		{ 0x00000100,	MSG_SYS_GETPAGESIZES_ALT },
		{ 0x00000200,	MSG_SYS_RCTLSYS_ALT },
		{ 0x00000400,	MSG_SYS_SIDSYS_ALT },
		{ 0x00000800,	MSG_SYS_76 },
		{ 0x00001000,	MSG_SYS_LWP_PARK_ALT },
		{ 0x00002000,	MSG_SYS_SENDFILEV_ALT },
		{ 0x00004000,	MSG_SYS_RMDIR_ALT },
		{ 0x00008000,	MSG_SYS_MKDIR_ALT },
		{ 0x00010000,	MSG_SYS_GETDENTS_ALT },
		{ 0x00020000,	MSG_SYS_PRIVSYS_ALT },
		{ 0x00040000,	MSG_SYS_UCREDSYS_ALT },
		{ 0x00080000,	MSG_SYS_SYSFS_ALT },
		{ 0x00100000,	MSG_SYS_GETMSG_ALT },
		{ 0x00200000,	MSG_SYS_PUTMSG_ALT },
		{ 0x00400000,	MSG_SYS_87 },
		{ 0x00800000,	MSG_SYS_LSTAT_ALT },
		{ 0x01000000,	MSG_SYS_SYMLINK_ALT },
		{ 0x02000000,	MSG_SYS_READLINK_ALT },
		{ 0x04000000,	MSG_SYS_SETGROUPS_ALT },
		{ 0x08000000,	MSG_SYS_GETGROUPS_ALT },
		{ 0x10000000,	MSG_SYS_FCHMOD_ALT },
		{ 0x20000000,	MSG_SYS_FCHOWN_ALT },
		{ 0x40000000,	MSG_SYS_SIGPROCMASK_ALT },
		{ 0x80000000,	MSG_SYS_SIGSUSPEND_ALT },
		{ 0,		0 }
	};
	static const Val_desc vda3[] = {	/* System Calls [97 - 128] */
		{ 0x00000001,	MSG_SYS_SIGALTSTACK_ALT },
		{ 0x00000002,	MSG_SYS_SIGACTION_ALT },
		{ 0x00000004,	MSG_SYS_SIGPENDING_ALT },
		{ 0x00000008,	MSG_SYS_CONTEXT_ALT },
		{ 0x00000010,	MSG_SYS_101 },
		{ 0x00000020,	MSG_SYS_102 },
		{ 0x00000040,	MSG_SYS_STATVFS_ALT },
		{ 0x00000080,	MSG_SYS_FSTATVFS_ALT },
		{ 0x00000100,	MSG_SYS_GETLOADAVG_ALT },
		{ 0x00000200,	MSG_SYS_NFSSYS_ALT },
		{ 0x00000400,	MSG_SYS_WAITID_ALT },
		{ 0x00000800,	MSG_SYS_SIGSENDSYS_ALT },
		{ 0x00001000,	MSG_SYS_HRTSYS_ALT },
		{ 0x00002000,	MSG_SYS_UTIMESYS_ALT },
		{ 0x00004000,	MSG_SYS_SIGRESEND_ALT },
		{ 0x00008000,	MSG_SYS_PRIOCNTLSYS_ALT },
		{ 0x00010000,	MSG_SYS_PATHCONF_ALT },
		{ 0x00020000,	MSG_SYS_MINCORE_ALT },
		{ 0x00040000,	MSG_SYS_MMAP_ALT },
		{ 0x00080000,	MSG_SYS_MPROTECT_ALT },
		{ 0x00100000,	MSG_SYS_MUNMAP_ALT },
		{ 0x00200000,	MSG_SYS_FPATHCONF_ALT },
		{ 0x00400000,	MSG_SYS_VFORK_ALT },
		{ 0x00800000,	MSG_SYS_FCHDIR_ALT },
		{ 0x01000000,	MSG_SYS_READV_ALT },
		{ 0x02000000,	MSG_SYS_WRITEV_ALT },
		{ 0x04000000,	MSG_SYS_123 },
		{ 0x08000000,	MSG_SYS_124 },
		{ 0x10000000,	MSG_SYS_125 },
		{ 0x20000000,	MSG_SYS_126 },
		{ 0x40000000,	MSG_SYS_MMAPOBJ_ALT },
		{ 0x80000000,	MSG_SYS_SETRLIMIT_ALT },
		{ 0,			0 }
	};
	static const Val_desc vda4[] = {	/* System Calls [129 - 160] */
		{ 0x00000001,	MSG_SYS_GETRLIMIT_ALT },
		{ 0x00000002,	MSG_SYS_LCHOWN_ALT },
		{ 0x00000004,	MSG_SYS_MEMCNTL_ALT },
		{ 0x00000008,	MSG_SYS_GETPMSG_ALT },
		{ 0x00000010,	MSG_SYS_PUTPMSG_ALT },
		{ 0x00000020,	MSG_SYS_RENAME_ALT },
		{ 0x00000040,	MSG_SYS_UNAME_ALT },
		{ 0x00000080,	MSG_SYS_SETEGID_ALT },
		{ 0x00000100,	MSG_SYS_SYSCONFIG_ALT },
		{ 0x00000200,	MSG_SYS_ADJTIME_ALT },
		{ 0x00000400,	MSG_SYS_SYSTEMINFO_ALT },
		{ 0x00000800,	MSG_SYS_SHAREFS_ALT },
		{ 0x00001000,	MSG_SYS_SETEUID_ALT },
		{ 0x00002000,	MSG_SYS_FORKSYS_ALT },
		{ 0x00004000,	MSG_SYS_143 },
		{ 0x00008000,	MSG_SYS_SIGTIMEDWAIT_ALT },
		{ 0x00010000,	MSG_SYS_LWP_INFO_ALT },
		{ 0x00020000,	MSG_SYS_YIELD_ALT },
		{ 0x00040000,	MSG_SYS_147 },
		{ 0x00080000,	MSG_SYS_LWP_SEMA_POST_ALT },
		{ 0x00100000,	MSG_SYS_LWP_SEMA_TRYWAIT_ALT },
		{ 0x00200000,	MSG_SYS_LWP_DETACH_ALT },
		{ 0x00400000,	MSG_SYS_CORECTL_ALT },
		{ 0x00800000,	MSG_SYS_MODCTL_ALT },
		{ 0x01000000,	MSG_SYS_FCHROOT_ALT },
		{ 0x02000000,	MSG_SYS_154 },
		{ 0x04000000,	MSG_SYS_VHANGUP_ALT },
		{ 0x08000000,	MSG_SYS_GETTIMEOFDAY_ALT },
		{ 0x10000000,	MSG_SYS_GETITIMER_ALT },
		{ 0x20000000,	MSG_SYS_SETITIMER_ALT },
		{ 0x40000000,	MSG_SYS_LWP_CREATE_ALT },
		{ 0x80000000,	MSG_SYS_LWP_EXIT_ALT },
		{ 0,		0 }
	};
	static const Val_desc vda5[] = {	/* System Calls [161 - 192] */
		{ 0x00000001,	MSG_SYS_LWP_SUSPEND_ALT },
		{ 0x00000002,	MSG_SYS_LWP_CONTINUE_ALT },
		{ 0x00000004,	MSG_SYS_LWP_KILL_ALT },
		{ 0x00000008,	MSG_SYS_LWP_SELF_ALT },
		{ 0x00000010,	MSG_SYS_LWP_SIGMASK_ALT },
		{ 0x00000020,	MSG_SYS_LWP_PRIVATE_ALT },
		{ 0x00000040,	MSG_SYS_LWP_WAIT_ALT },
		{ 0x00000080,	MSG_SYS_LWP_MUTEX_WAKEUP_ALT },
		{ 0x00000100,	MSG_SYS_169 },
		{ 0x00000200,	MSG_SYS_LWP_COND_WAIT_ALT },
		{ 0x00000400,	MSG_SYS_LWP_COND_SIGNAL_ALT },
		{ 0x00000800,	MSG_SYS_LWP_COND_BROADCAST_ALT },
		{ 0x00001000,	MSG_SYS_PREAD_ALT },
		{ 0x00002000,	MSG_SYS_PWRITE_ALT },
		{ 0x00004000,	MSG_SYS_LLSEEK_ALT },
		{ 0x00008000,	MSG_SYS_INST_SYNC_ALT },
		{ 0x00010000,	MSG_SYS_BRAND_ALT },
		{ 0x00020000,	MSG_SYS_KAIO_ALT },
		{ 0x00040000,	MSG_SYS_CPC_ALT },
		{ 0x00080000,	MSG_SYS_LGRPSYS_ALT },
		{ 0x00100000,	MSG_SYS_RUSAGESYS_ALT },
		{ 0x00200000,	MSG_SYS_PORT_ALT },
		{ 0x00400000,	MSG_SYS_POLLSYS_ALT },
		{ 0x00800000,	MSG_SYS_LABELSYS_ALT },
		{ 0x01000000,	MSG_SYS_ACL_ALT },
		{ 0x02000000,	MSG_SYS_AUDITSYS_ALT },
		{ 0x04000000,	MSG_SYS_PROCESSOR_BIND_ALT },
		{ 0x08000000,	MSG_SYS_PROCESSOR_INFO_ALT },
		{ 0x10000000,	MSG_SYS_P_ONLINE_ALT },
		{ 0x20000000,	MSG_SYS_SIGQUEUE_ALT },
		{ 0x40000000,	MSG_SYS_CLOCK_GETTIME_ALT },
		{ 0x80000000,	MSG_SYS_CLOCK_SETTIME_ALT },
		{ 0,		0 }
	};
	static const Val_desc vda6[] = {	/* System Calls [193 - 224] */
		{ 0x00000001,	MSG_SYS_CLOCK_GETRES_ALT },
		{ 0x00000002,	MSG_SYS_TIMER_CREATE_ALT },
		{ 0x00000004,	MSG_SYS_TIMER_DELETE_ALT },
		{ 0x00000008,	MSG_SYS_TIMER_SETTIME_ALT },
		{ 0x00000010,	MSG_SYS_TIMER_GETTIME_ALT },
		{ 0x00000020,	MSG_SYS_TIMER_GETOVERRUN_ALT },
		{ 0x00000040,	MSG_SYS_NANOSLEEP_ALT },
		{ 0x00000080,	MSG_SYS_FACL_ALT },
		{ 0x00000100,	MSG_SYS_DOOR_ALT },
		{ 0x00000200,	MSG_SYS_SETREUID_ALT },
		{ 0x00000400,	MSG_SYS_SETREGID_ALT },
		{ 0x00000800,	MSG_SYS_INSTALL_UTRAP_ALT },
		{ 0x00001000,	MSG_SYS_SIGNOTIFY_ALT },
		{ 0x00002000,	MSG_SYS_SCHEDCTL_ALT },
		{ 0x00004000,	MSG_SYS_PSET_ALT },
		{ 0x00008000,	MSG_SYS_SPARC_UTRAP_INSTALL_ALT },
		{ 0x00010000,	MSG_SYS_RESOLVEPATH_ALT },
		{ 0x00020000,	MSG_SYS_LWP_MUTEX_TIMEDLOCK_ALT },
		{ 0x00040000,	MSG_SYS_LWP_SEMA_TIMEDWAIT_ALT },
		{ 0x00080000,	MSG_SYS_LWP_RWLOCK_SYS_ALT },
		{ 0x00100000,	MSG_SYS_GETDENTS64_ALT },
		{ 0x00200000,	MSG_SYS_MMAP64_ALT },
		{ 0x00400000,	MSG_SYS_STAT64_ALT },
		{ 0x00800000,	MSG_SYS_LSTAT64_ALT },
		{ 0x01000000,	MSG_SYS_FSTAT64_ALT },
		{ 0x02000000,	MSG_SYS_STATVFS64_ALT },
		{ 0x04000000,	MSG_SYS_FSTATVFS64_ALT },
		{ 0x08000000,	MSG_SYS_SETRLIMIT64_ALT },
		{ 0x10000000,	MSG_SYS_GETRLIMIT64_ALT },
		{ 0x20000000,	MSG_SYS_PREAD64_ALT },
		{ 0x40000000,	MSG_SYS_PWRITE64_ALT },
		{ 0x80000000,	MSG_SYS_224 },
		{ 0,			0 }
	};
	static const Val_desc vda7[] = {	/* System Calls [225 - 256] */
		{ 0x00000001,	MSG_SYS_OPEN64_ALT },
		{ 0x00000002,	MSG_SYS_RPCSYS_ALT },
		{ 0x00000004,	MSG_SYS_ZONE_ALT },
		{ 0x00000008,	MSG_SYS_AUTOFSSYS_ALT },
		{ 0x00000010,	MSG_SYS_GETCWD_ALT },
		{ 0x00000020,	MSG_SYS_SO_SOCKET_ALT },
		{ 0x00000040,	MSG_SYS_SO_SOCKETPAIR_ALT },
		{ 0x00000080,	MSG_SYS_BIND_ALT },
		{ 0x00000100,	MSG_SYS_LISTEN_ALT },
		{ 0x00000200,	MSG_SYS_ACCEPT_ALT },
		{ 0x00000400,	MSG_SYS_CONNECT_ALT },
		{ 0x00000800,	MSG_SYS_SHUTDOWN_ALT },
		{ 0x00001000,	MSG_SYS_RECV_ALT },
		{ 0x00002000,	MSG_SYS_RECVFROM_ALT },
		{ 0x00004000,	MSG_SYS_RECVMSG_ALT },
		{ 0x00008000,	MSG_SYS_SEND_ALT },
		{ 0x00010000,	MSG_SYS_SENDMSG_ALT },
		{ 0x00020000,	MSG_SYS_SENDTO_ALT },
		{ 0x00040000,	MSG_SYS_GETPEERNAME_ALT },
		{ 0x00080000,	MSG_SYS_GETSOCKNAME_ALT },
		{ 0x00100000,	MSG_SYS_GETSOCKOPT_ALT },
		{ 0x00200000,	MSG_SYS_SETSOCKOPT_ALT },
		{ 0x00400000,	MSG_SYS_SOCKCONFIG_ALT },
		{ 0x00800000,	MSG_SYS_NTP_GETTIME_ALT },
		{ 0x01000000,	MSG_SYS_NTP_ADJTIME_ALT },
		{ 0x02000000,	MSG_SYS_LWP_MUTEX_UNLOCK_ALT },
		{ 0x04000000,	MSG_SYS_LWP_MUTEX_TRYLOCK_ALT },
		{ 0x08000000,	MSG_SYS_LWP_MUTEX_REGISTER_ALT },
		{ 0x10000000,	MSG_SYS_CLADM_ALT },
		{ 0x20000000,	MSG_SYS_UUCOPY_ALT },
		{ 0x40000000,	MSG_SYS_UMOUNT2_ALT },
		/* 256 (unused) */
		{ 0,		0 }
	};
	static const conv_bitmaskset_desc_t bitmask_desc[N_MASK] = {
		{ vda0, 0x00000000 },
		{ vda1, 0x00000000 },
		{ vda2, 0x00000000 },
		{ vda3, 0x00000000 },
		{ vda4, 0x00000000 },
		{ vda5, 0x00000000 },
		{ vda6, 0x00000000 },
		{ vda7, 0x80000000 },
		{ NULL, 0xffffffff },
		{ NULL, 0xffffffff },
		{ NULL, 0xffffffff },
		{ NULL, 0xffffffff },
		{ NULL, 0xffffffff },
		{ NULL, 0xffffffff },
		{ NULL, 0xffffffff },
		{ NULL, 0xffffffff }
	};

	if (n_mask > N_MASK)
		n_mask = N_MASK;
	return (conv_bitmaskset(maskarr, n_mask, bitmask_desc, fmt_flags,
	    cnote_sysset_buf->buf, CONV_CNOTE_SYSSET_BUFSIZE));

#undef N_MASK
}

const char *
conv_cnote_fileflags(uint32_t fileflags, Conv_fmt_flags_t fmt_flags,
    char *buf, size_t bufsize)
{
	CONV_EXPN_FIELD_ARG arg = { 0 };

	Val_desc vda[] = {
		{ 0x0001,	MSG_PR_O_WRONLY },
		{ 0x0002,	MSG_PR_O_RDONLY },
		{ 0x200000,	MSG_PR_O_SEARCH },
		{ 0x400000,	MSG_PR_O_EXEC },
		{ 0x0004,	MSG_PR_O_NDELAY },
		{ 0x0008,	MSG_PR_O_APPEND },
		{ 0x0010,	MSG_PR_O_SYNC },
		{ 0x0040,	MSG_PR_O_DSYNC },
		{ 0x0080,	MSG_PR_O_NONBLOCK },
		{ 0x0100,	MSG_PR_O_CREAT },
		{ 0x0200,	MSG_PR_O_TRUNC },
		{ 0x0400,	MSG_PR_O_EXCL },
		{ 0x0800,	MSG_PR_O_NOCTTY },
		{ 0x4000,	MSG_PR_O_XATTR },
		{ 0x8000,	MSG_PR_O_RSYNC },
		{ 0x2000,	MSG_PR_O_LARGEFILE },
		{ 0x20000,	MSG_PR_O_NOFOLLOW },
		{ 0x40000,	MSG_PR_O_NOLINKS },
		{ 0, NULL },
	};

	arg.oflags = arg.rflags = fileflags;
	arg.buf = buf;
	arg.bufsize = bufsize;

	switch (fileflags & (0x600003)) {
	case 0:	/* RDONLY */
		vda[0].v_msg = MSG_PR_O_RDONLY;
		arg.oflags |= 1;
		arg.rflags |= 1;
		break;
	case 1:	/* WRONLY */
	case 2:	/* RDWR */
	case 0x200000:	/* SEARCH */
	case 0x400000:
		/* In isolate, treat these as normal bits */
		break;
	default:
		/* More than one bit set in this group, emit numerically */
		arg.oflags &= ~(fileflags & 0x600003);
	}

	if (fileflags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	(void) conv_expn_field(&arg, vda, fmt_flags);
	return (buf);
}

const char *
conv_cnote_filemode(uint32_t mode, Conv_fmt_flags_t fmt_flags,
    char *buf, size_t bufsize)
{
	CONV_EXPN_FIELD_ARG arg = { 0 };
	Msg s;

	Val_desc vda[] = {
		{ 0x1000,	MSG_S_IFIFO },
		{ 0x800,	MSG_S_ISUID },
		{ 0x400,	MSG_S_ISGID },
		{ 0x200,	MSG_S_ISVTX },
		{ 0400,		MSG_S_IRUSR },
		{ 0200,		MSG_S_IWUSR },
		{ 0100,		MSG_S_IXUSR },
		{ 0040,		MSG_S_IRGRP },
		{ 0020,		MSG_S_IWGRP },
		{ 0010,		MSG_S_IXGRP },
		{ 0004,		MSG_S_IROTH },
		{ 0002,		MSG_S_IWOTH },
		{ 0001,		MSG_S_IXOTH },
		{ 0, NULL },
	};

	arg.oflags = arg.rflags = mode & ~(0xf000);
	arg.buf = buf;
	arg.bufsize = bufsize;

	switch (mode & (0xf000)) {
	case 0x1000:
		s = MSG_S_IFIFO;
		break;
	case 0x2000:
		s = MSG_S_IFCHR;
		break;
	case 0x4000:
		s = MSG_S_IFDIR;
		break;
	case 0x5000:
		s = MSG_S_IFNAM;
		break;
	case 0x6000:
		s = MSG_S_IFBLK;
		break;
	case 0x8000:
		s = MSG_S_IFREG;
		break;
	case 0xA000:
		s = MSG_S_IFLNK;
		break;
	case 0xc000:
		s = MSG_S_IFSOCK;
		break;
	case 0xd000:
		s = MSG_S_IFDOOR;
		break;
	case 0xe000:
		s = MSG_S_IFPORT;
		break;
	default:
		s = NULL;
		break;
	}

	if (s) {
		arg.oflags |= 0x1000;
		arg.rflags |= 0x1000;
		vda[0].v_msg = s;
	} else {
		arg.rflags = mode;
	}

	if (mode == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	(void) conv_expn_field(&arg, vda, fmt_flags);
	return (buf);
}
