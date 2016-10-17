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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Portions Copyright 2007 Chad Mynhier
 * Copyright 2012 DEY Storage Systems, Inc.  All rights reserved.
 * Copyright 2015, Joyent, Inc.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

/*
 * Interfaces available from the process control library, libproc.
 */

#ifndef	_LIBPROC_H
#define	_LIBPROC_H

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <nlist.h>
#include <door.h>
#include <gelf.h>
#include <proc_service.h>
#include <rtld_db.h>
#include <procfs.h>
#include <ucred.h>
#include <rctl.h>
#include <libctf.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/auxv.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <sys/corectl.h>
#include <sys/secflags.h>
#if defined(__i386) || defined(__amd64)
#include <sys/sysi86.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Opaque structure tag reference to a process control structure.
 * Clients of libproc cannot look inside the process control structure.
 * The implementation of struct ps_prochandle can change w/o affecting clients.
 */
struct ps_prochandle;

/*
 * Opaque structure tag reference to an lwp control structure.
 */
struct ps_lwphandle;

extern	int	_libproc_debug;	/* set non-zero to enable debugging fprintfs */
extern	int	_libproc_no_qsort;	/* set non-zero to inhibit sorting */
					/* of symbol tables */
extern	int	_libproc_incore_elf;	/* only use in-core elf data */

#if defined(__sparc)
#define	R_RVAL1	R_O0		/* register holding a function return value */
#define	R_RVAL2	R_O1		/* 32 more bits for a 64-bit return value */
#endif	/* __sparc */

#if defined(__amd64)
#define	R_PC	REG_RIP
#define	R_SP	REG_RSP
#define	R_RVAL1	REG_RAX		/* register holding a function return value */
#define	R_RVAL2	REG_RDX		/* 32 more bits for a 64-bit return value */
#elif defined(__i386)
#define	R_PC	EIP
#define	R_SP	UESP
#define	R_RVAL1	EAX		/* register holding a function return value */
#define	R_RVAL2	EDX		/* 32 more bits for a 64-bit return value */
#endif	/* __amd64 || __i386 */

#define	R_RVAL	R_RVAL1		/* simple function return value register */

/* maximum sizes of things */
#define	PRMAXSIG	(32 * sizeof (sigset_t) / sizeof (uint32_t))
#define	PRMAXFAULT	(32 * sizeof (fltset_t) / sizeof (uint32_t))
#define	PRMAXSYS	(32 * sizeof (sysset_t) / sizeof (uint32_t))

/* State values returned by Pstate() */
#define	PS_RUN		1	/* process is running */
#define	PS_STOP		2	/* process is stopped */
#define	PS_LOST		3	/* process is lost to control (EAGAIN) */
#define	PS_UNDEAD	4	/* process is terminated (zombie) */
#define	PS_DEAD		5	/* process is terminated (core file) */
#define	PS_IDLE		6	/* process has not been run */

/* Flags accepted by Pgrab() */
#define	PGRAB_RETAIN	0x01	/* Retain tracing flags, else clear flags */
#define	PGRAB_FORCE	0x02	/* Open the process w/o O_EXCL */
#define	PGRAB_RDONLY	0x04	/* Open the process or core w/ O_RDONLY */
#define	PGRAB_NOSTOP	0x08	/* Open the process but do not stop it */
#define	PGRAB_INCORE	0x10	/* Use in-core data to build symbol tables */

/* Error codes from Pcreate() */
#define	C_STRANGE	-1	/* Unanticipated error, errno is meaningful */
#define	C_FORK		1	/* Unable to fork */
#define	C_PERM		2	/* No permission (file set-id or unreadable) */
#define	C_NOEXEC	3	/* Cannot execute file */
#define	C_INTR		4	/* Interrupt received while creating */
#define	C_LP64		5	/* Program is _LP64, self is _ILP32 */
#define	C_NOENT		6	/* Cannot find executable file */

/* Error codes from Pgrab(), Pfgrab_core(), and Pgrab_core() */
#define	G_STRANGE	-1	/* Unanticipated error, errno is meaningful */
#define	G_NOPROC	1	/* No such process */
#define	G_NOCORE	2	/* No such core file */
#define	G_NOPROCORCORE	3	/* No such proc or core (for proc_arg_grab) */
#define	G_NOEXEC	4	/* Cannot locate executable file */
#define	G_ZOMB		5	/* Zombie process */
#define	G_PERM		6	/* No permission */
#define	G_BUSY		7	/* Another process has control */
#define	G_SYS		8	/* System process */
#define	G_SELF		9	/* Process is self */
#define	G_INTR		10	/* Interrupt received while grabbing */
#define	G_LP64		11	/* Process is _LP64, self is ILP32 */
#define	G_FORMAT	12	/* File is not an ELF format core file */
#define	G_ELF		13	/* Libelf error, elf_errno() is meaningful */
#define	G_NOTE		14	/* Required PT_NOTE Phdr not present in core */
#define	G_ISAINVAL	15	/* Wrong ELF machine type */
#define	G_BADLWPS	16	/* Bad '/lwps' specification */
#define	G_NOFD		17	/* No more file descriptors */


/* Flags accepted by Prelease */
#define	PRELEASE_CLEAR	0x10	/* Clear all tracing flags */
#define	PRELEASE_RETAIN	0x20	/* Retain final tracing flags */
#define	PRELEASE_HANG	0x40	/* Leave the process stopped */
#define	PRELEASE_KILL	0x80	/* Terminate the process */

typedef	struct {	/* argument descriptor for system call (Psyscall) */
	long	arg_value;	/* value of argument given to system call */
	void	*arg_object;	/* pointer to object in controlling process */
	char	arg_type;	/* AT_BYVAL, AT_BYREF */
	char	arg_inout;	/* AI_INPUT, AI_OUTPUT, AI_INOUT */
	ushort_t arg_size;	/* if AT_BYREF, size of object in bytes */
} argdes_t;

/* values for type */
#define	AT_BYVAL	1
#define	AT_BYREF	2

/* values for inout */
#define	AI_INPUT	1
#define	AI_OUTPUT	2
#define	AI_INOUT	3

/* maximum number of syscall arguments */
#define	MAXARGS		8

/* maximum size in bytes of a BYREF argument */
#define	MAXARGL		(4*1024)

/*
 * Ops vector definition for the Pgrab_ops().
 */
typedef ssize_t (*pop_pread_t)(struct ps_prochandle *, void *, size_t,
    uintptr_t, void *);
typedef ssize_t (*pop_pwrite_t)(struct ps_prochandle *, const void *, size_t,
    uintptr_t, void *);
typedef int (*pop_read_maps_t)(struct ps_prochandle *, prmap_t **, ssize_t *,
    void *);
typedef void (*pop_read_aux_t)(struct ps_prochandle *, auxv_t **, int *,
    void *);
typedef int (*pop_cred_t)(struct ps_prochandle *, prcred_t *, int,
    void *);
typedef int (*pop_priv_t)(struct ps_prochandle *, prpriv_t **, void *);
typedef int (*pop_secflags_t)(struct ps_prochandle *, prsecflags_t **, void *);
typedef const psinfo_t *(*pop_psinfo_t)(struct ps_prochandle *, psinfo_t *,
    void *);
typedef void (*pop_status_t)(struct ps_prochandle *, pstatus_t *, void *);
typedef prheader_t *(*pop_lstatus_t)(struct ps_prochandle *, void *);
typedef prheader_t *(*pop_lpsinfo_t)(struct ps_prochandle *, void *);
typedef void (*pop_fini_t)(struct ps_prochandle *, void *);
typedef char *(*pop_platform_t)(struct ps_prochandle *, char *, size_t, void *);
typedef int (*pop_uname_t)(struct ps_prochandle *, struct utsname *, void *);
typedef char *(*pop_zonename_t)(struct ps_prochandle *, char *, size_t, void *);
typedef char *(*pop_execname_t)(struct ps_prochandle *, char *, size_t, void *);
#if defined(__i386) || defined(__amd64)
typedef int (*pop_ldt_t)(struct ps_prochandle *, struct ssd *, int, void *);
#endif

typedef struct ps_ops {
	pop_pread_t		pop_pread;
	pop_pwrite_t		pop_pwrite;
	pop_read_maps_t		pop_read_maps;
	pop_read_aux_t		pop_read_aux;
	pop_cred_t		pop_cred;
	pop_priv_t		pop_priv;
	pop_psinfo_t		pop_psinfo;
	pop_status_t		pop_status;
	pop_lstatus_t		pop_lstatus;
	pop_lpsinfo_t		pop_lpsinfo;
	pop_fini_t		pop_fini;
	pop_platform_t		pop_platform;
	pop_uname_t		pop_uname;
	pop_zonename_t		pop_zonename;
	pop_execname_t		pop_execname;
	pop_secflags_t		pop_secflags;
#if defined(__i386) || defined(__amd64)
	pop_ldt_t		pop_ldt;
#endif
} ps_ops_t;

/*
 * Function prototypes for routines in the process control package.
 */
extern struct ps_prochandle *Pcreate(const char *, char *const *,
    int *, char *, size_t);
extern struct ps_prochandle *Pxcreate(const char *, char *const *,
    char *const *, int *, char *, size_t);

extern const char *Pcreate_error(int);

extern struct ps_prochandle *Pgrab(pid_t, int, int *);
extern struct ps_prochandle *Pgrab_core(const char *, const char *, int, int *);
extern struct ps_prochandle *Pfgrab_core(int, const char *, int *);
extern struct ps_prochandle *Pgrab_file(const char *, int *);
extern struct ps_prochandle *Pgrab_ops(pid_t, void *, const ps_ops_t *, int);
extern const char *Pgrab_error(int);

extern	int	Preopen(struct ps_prochandle *);
extern	void	Prelease(struct ps_prochandle *, int);
extern	void	Pfree(struct ps_prochandle *);

extern	int	Pasfd(struct ps_prochandle *);
extern	char   *Pbrandname(struct ps_prochandle *, char *, size_t);
extern	int	Pctlfd(struct ps_prochandle *);
extern	int	Pcreate_agent(struct ps_prochandle *);
extern	void	Pdestroy_agent(struct ps_prochandle *);
extern	int	Pstopstatus(struct ps_prochandle *, long, uint_t);
extern	int	Pwait(struct ps_prochandle *, uint_t);
extern	int	Pstop(struct ps_prochandle *, uint_t);
extern	int	Pdstop(struct ps_prochandle *);
extern	int	Pstate(struct ps_prochandle *);
extern	const psinfo_t *Ppsinfo(struct ps_prochandle *);
extern	const pstatus_t *Pstatus(struct ps_prochandle *);
extern	int	Pcred(struct ps_prochandle *, prcred_t *, int);
extern	int	Psetcred(struct ps_prochandle *, const prcred_t *);
extern	int	Ppriv(struct ps_prochandle *, prpriv_t **);
extern	void	Ppriv_free(struct ps_prochandle *, prpriv_t *);
extern	int	Psetpriv(struct ps_prochandle *, prpriv_t *);
extern	void   *Pprivinfo(struct ps_prochandle *);
extern	int	Psetzoneid(struct ps_prochandle *, zoneid_t);
extern	int	Pgetareg(struct ps_prochandle *, int, prgreg_t *);
extern	int	Pputareg(struct ps_prochandle *, int, prgreg_t);
extern	int	Psetrun(struct ps_prochandle *, int, int);
extern	int	Psecflags(struct ps_prochandle *, prsecflags_t **);
extern	void	Psecflags_free(prsecflags_t *);
extern	ssize_t	Pread(struct ps_prochandle *, void *, size_t, uintptr_t);
extern	ssize_t Pread_string(struct ps_prochandle *, char *, size_t, uintptr_t);
extern	ssize_t	Pwrite(struct ps_prochandle *, const void *, size_t, uintptr_t);
extern	int	Pclearsig(struct ps_prochandle *);
extern	int	Pclearfault(struct ps_prochandle *);
extern	int	Psetbkpt(struct ps_prochandle *, uintptr_t, ulong_t *);
extern	int	Pdelbkpt(struct ps_prochandle *, uintptr_t, ulong_t);
extern	int	Pxecbkpt(struct ps_prochandle *, ulong_t);
extern	int	Psetwapt(struct ps_prochandle *, const prwatch_t *);
extern	int	Pdelwapt(struct ps_prochandle *, const prwatch_t *);
extern	int	Pxecwapt(struct ps_prochandle *, const prwatch_t *);
extern	int	Psetflags(struct ps_prochandle *, long);
extern	int	Punsetflags(struct ps_prochandle *, long);
extern	int	Psignal(struct ps_prochandle *, int, int);
extern	int	Pfault(struct ps_prochandle *, int, int);
extern	int	Psysentry(struct ps_prochandle *, int, int);
extern	int	Psysexit(struct ps_prochandle *, int, int);
extern	void	Psetsignal(struct ps_prochandle *, const sigset_t *);
extern	void	Psetfault(struct ps_prochandle *, const fltset_t *);
extern	void	Psetsysentry(struct ps_prochandle *, const sysset_t *);
extern	void	Psetsysexit(struct ps_prochandle *, const sysset_t *);

extern	void	Psync(struct ps_prochandle *);
extern	int	Psyscall(struct ps_prochandle *, sysret_t *,
			int, uint_t, argdes_t *);
extern	int	Pisprocdir(struct ps_prochandle *, const char *);

/*
 * Function prototypes for lwp-specific operations.
 */
extern	struct ps_lwphandle *Lgrab(struct ps_prochandle *, lwpid_t, int *);
extern	const char *Lgrab_error(int);

extern	struct ps_prochandle *Lprochandle(struct ps_lwphandle *);
extern	void	Lfree(struct ps_lwphandle *);

extern	int	Lctlfd(struct ps_lwphandle *);
extern	int	Lwait(struct ps_lwphandle *, uint_t);
extern	int	Lstop(struct ps_lwphandle *, uint_t);
extern	int	Ldstop(struct ps_lwphandle *);
extern	int	Lstate(struct ps_lwphandle *);
extern	const lwpsinfo_t *Lpsinfo(struct ps_lwphandle *);
extern	const lwpstatus_t *Lstatus(struct ps_lwphandle *);
extern	int	Lgetareg(struct ps_lwphandle *, int, prgreg_t *);
extern	int	Lputareg(struct ps_lwphandle *, int, prgreg_t);
extern	int	Lsetrun(struct ps_lwphandle *, int, int);
extern	int	Lclearsig(struct ps_lwphandle *);
extern	int	Lclearfault(struct ps_lwphandle *);
extern	int	Lxecbkpt(struct ps_lwphandle *, ulong_t);
extern	int	Lxecwapt(struct ps_lwphandle *, const prwatch_t *);
extern	void	Lsync(struct ps_lwphandle *);

extern	int	Lstack(struct ps_lwphandle *, stack_t *);
extern	int	Lmain_stack(struct ps_lwphandle *, stack_t *);
extern	int	Lalt_stack(struct ps_lwphandle *, stack_t *);

/*
 * Function prototypes for system calls forced on the victim process.
 */
extern	int	pr_open(struct ps_prochandle *, const char *, int, mode_t);
extern	int	pr_creat(struct ps_prochandle *, const char *, mode_t);
extern	int	pr_close(struct ps_prochandle *, int);
extern	int	pr_access(struct ps_prochandle *, const char *, int);
extern	int	pr_door_info(struct ps_prochandle *, int, struct door_info *);
extern	void	*pr_mmap(struct ps_prochandle *,
			void *, size_t, int, int, int, off_t);
extern	void	*pr_zmap(struct ps_prochandle *,
			void *, size_t, int, int);
extern	int	pr_munmap(struct ps_prochandle *, void *, size_t);
extern	int	pr_memcntl(struct ps_prochandle *,
			caddr_t, size_t, int, caddr_t, int, int);
extern	int	pr_meminfo(struct ps_prochandle *, const uint64_t *addrs,
			int addr_count, const uint_t *info, int info_count,
			uint64_t *outdata, uint_t *validity);
extern	int	pr_sigaction(struct ps_prochandle *,
			int, const struct sigaction *, struct sigaction *);
extern	int	pr_getitimer(struct ps_prochandle *,
			int, struct itimerval *);
extern	int	pr_setitimer(struct ps_prochandle *,
			int, const struct itimerval *, struct itimerval *);
extern	int	pr_ioctl(struct ps_prochandle *, int, int, void *, size_t);
extern	int	pr_fcntl(struct ps_prochandle *, int, int, void *);
extern	int	pr_stat(struct ps_prochandle *, const char *, struct stat *);
extern	int	pr_lstat(struct ps_prochandle *, const char *, struct stat *);
extern	int	pr_fstat(struct ps_prochandle *, int, struct stat *);
extern	int	pr_stat64(struct ps_prochandle *, const char *,
			struct stat64 *);
extern	int	pr_lstat64(struct ps_prochandle *, const char *,
			struct stat64 *);
extern	int	pr_fstat64(struct ps_prochandle *, int, struct stat64 *);
extern	int	pr_statvfs(struct ps_prochandle *, const char *, statvfs_t *);
extern	int	pr_fstatvfs(struct ps_prochandle *, int, statvfs_t *);
extern	projid_t pr_getprojid(struct ps_prochandle *Pr);
extern	taskid_t pr_gettaskid(struct ps_prochandle *Pr);
extern	taskid_t pr_settaskid(struct ps_prochandle *Pr, projid_t project,
			int flags);
extern	zoneid_t pr_getzoneid(struct ps_prochandle *Pr);
extern	int	pr_getrctl(struct ps_prochandle *,
			const char *, rctlblk_t *, rctlblk_t *, int);
extern	int	pr_setrctl(struct ps_prochandle *,
			const char *, rctlblk_t *, rctlblk_t *, int);
extern	int	pr_getrlimit(struct ps_prochandle *,
			int, struct rlimit *);
extern	int	pr_setrlimit(struct ps_prochandle *,
			int, const struct rlimit *);
extern	int	pr_setprojrctl(struct ps_prochandle *, const char *,
			rctlblk_t *, size_t, int);
#if defined(_LARGEFILE64_SOURCE)
extern	int	pr_getrlimit64(struct ps_prochandle *,
			int, struct rlimit64 *);
extern	int	pr_setrlimit64(struct ps_prochandle *,
			int, const struct rlimit64 *);
#endif	/* _LARGEFILE64_SOURCE */
extern	int	pr_lwp_exit(struct ps_prochandle *);
extern	int	pr_exit(struct ps_prochandle *, int);
extern	int	pr_waitid(struct ps_prochandle *,
			idtype_t, id_t, siginfo_t *, int);
extern	off_t	pr_lseek(struct ps_prochandle *, int, off_t, int);
extern	offset_t pr_llseek(struct ps_prochandle *, int, offset_t, int);
extern	int	pr_rename(struct ps_prochandle *, const char *, const char *);
extern	int	pr_link(struct ps_prochandle *, const char *, const char *);
extern	int	pr_unlink(struct ps_prochandle *, const char *);
extern	int	pr_getpeerucred(struct ps_prochandle *, int, ucred_t **);
extern	int	pr_getpeername(struct ps_prochandle *,
			int, struct sockaddr *, socklen_t *);
extern	int	pr_getsockname(struct ps_prochandle *,
			int, struct sockaddr *, socklen_t *);
extern	int	pr_getsockopt(struct ps_prochandle *,
			int, int, int, void *, int *);
extern	int	pr_processor_bind(struct ps_prochandle *,
			idtype_t, id_t, int, int *);

/*
 * Function prototypes for accessing per-LWP register information.
 */
extern int Plwp_getregs(struct ps_prochandle *, lwpid_t, prgregset_t);
extern int Plwp_setregs(struct ps_prochandle *, lwpid_t, const prgregset_t);

extern int Plwp_getfpregs(struct ps_prochandle *, lwpid_t, prfpregset_t *);
extern int Plwp_setfpregs(struct ps_prochandle *, lwpid_t,
    const prfpregset_t *);

#if defined(__sparc)

extern int Plwp_getxregs(struct ps_prochandle *, lwpid_t, prxregset_t *);
extern int Plwp_setxregs(struct ps_prochandle *, lwpid_t, const prxregset_t *);

extern int Plwp_getgwindows(struct ps_prochandle *, lwpid_t, gwindows_t *);

#if defined(__sparcv9)
extern int Plwp_getasrs(struct ps_prochandle *, lwpid_t, asrset_t);
extern int Plwp_setasrs(struct ps_prochandle *, lwpid_t, const asrset_t);
#endif	/* __sparcv9 */

#endif	/* __sparc */

#if defined(__i386) || defined(__amd64)
extern	int	Pldt(struct ps_prochandle *, struct ssd *, int);
extern	int	proc_get_ldt(pid_t, struct ssd *, int);
#endif	/* __i386 || __amd64 */

extern int Plwp_getpsinfo(struct ps_prochandle *, lwpid_t, lwpsinfo_t *);
extern int Plwp_getspymaster(struct ps_prochandle *, lwpid_t, psinfo_t *);

extern int Plwp_stack(struct ps_prochandle *, lwpid_t, stack_t *);
extern int Plwp_main_stack(struct ps_prochandle *, lwpid_t, stack_t *);
extern int Plwp_alt_stack(struct ps_prochandle *, lwpid_t, stack_t *);

/*
 * LWP iteration interface; iterate over all active LWPs.
 */
typedef int proc_lwp_f(void *, const lwpstatus_t *);
extern int Plwp_iter(struct ps_prochandle *, proc_lwp_f *, void *);

/*
 * LWP iteration interface; iterate over all LWPs, active and zombie.
 */
typedef int proc_lwp_all_f(void *, const lwpstatus_t *, const lwpsinfo_t *);
extern int Plwp_iter_all(struct ps_prochandle *, proc_lwp_all_f *, void *);

/*
 * Process iteration interface; iterate over all non-system processes.
 */
typedef int proc_walk_f(psinfo_t *, lwpsinfo_t *, void *);
extern int proc_walk(proc_walk_f *, void *, int);

#define	PR_WALK_PROC	0		/* walk processes only */
#define	PR_WALK_LWP	1		/* walk all lwps */

/*
 * Determine if an lwp is in a set as returned from proc_arg_xgrab().
 */
extern int proc_lwp_in_set(const char *, lwpid_t);
extern int proc_lwp_range_valid(const char *);

/*
 * Symbol table interfaces.
 */

/*
 * Pseudo-names passed to Plookup_by_name() for well-known load objects.
 * NOTE: It is required that PR_OBJ_EXEC and PR_OBJ_LDSO exactly match
 * the definitions of PS_OBJ_EXEC and PS_OBJ_LDSO from <proc_service.h>.
 */
#define	PR_OBJ_EXEC	((const char *)0)	/* search the executable file */
#define	PR_OBJ_LDSO	((const char *)1)	/* search ld.so.1 */
#define	PR_OBJ_EVERY	((const char *)-1)	/* search every load object */

/*
 * Special Lmid_t passed to Plookup_by_lmid() to search all link maps.  The
 * special values LM_ID_BASE and LM_ID_LDSO from <link.h> may also be used.
 * If PR_OBJ_EXEC is used as the object name, the lmid must be PR_LMID_EVERY
 * or LM_ID_BASE in order to return a match.  If PR_OBJ_LDSO is used as the
 * object name, the lmid must be PR_LMID_EVERY or LM_ID_LDSO to return a match.
 */
#define	PR_LMID_EVERY	((Lmid_t)-1UL)		/* search every link map */

/*
 * 'object_name' is the name of a load object obtained from an
 * iteration over the process's address space mappings (Pmapping_iter),
 * or an iteration over the process's mapped objects (Pobject_iter),
 * or else it is one of the special PR_OBJ_* values above.
 */
extern int Plookup_by_name(struct ps_prochandle *,
    const char *, const char *, GElf_Sym *);

extern int Plookup_by_addr(struct ps_prochandle *,
    uintptr_t, char *, size_t, GElf_Sym *);

typedef struct prsyminfo {
	const char	*prs_object;		/* object name */
	const char	*prs_name;		/* symbol name */
	Lmid_t		prs_lmid;		/* link map id */
	uint_t		prs_id;			/* symbol id */
	uint_t		prs_table;		/* symbol table id */
} prsyminfo_t;

extern int Pxlookup_by_name(struct ps_prochandle *,
    Lmid_t, const char *, const char *, GElf_Sym *, prsyminfo_t *);

extern int Pxlookup_by_addr(struct ps_prochandle *,
    uintptr_t, char *, size_t, GElf_Sym *, prsyminfo_t *);
extern int Pxlookup_by_addr_resolved(struct ps_prochandle *,
    uintptr_t, char *, size_t, GElf_Sym *, prsyminfo_t *);

typedef int proc_map_f(void *, const prmap_t *, const char *);

extern int Pmapping_iter(struct ps_prochandle *, proc_map_f *, void *);
extern int Pmapping_iter_resolved(struct ps_prochandle *, proc_map_f *, void *);
extern int Pobject_iter(struct ps_prochandle *, proc_map_f *, void *);
extern int Pobject_iter_resolved(struct ps_prochandle *, proc_map_f *, void *);

extern const prmap_t *Paddr_to_map(struct ps_prochandle *, uintptr_t);
extern const prmap_t *Paddr_to_text_map(struct ps_prochandle *, uintptr_t);
extern const prmap_t *Pname_to_map(struct ps_prochandle *, const char *);
extern const prmap_t *Plmid_to_map(struct ps_prochandle *,
    Lmid_t, const char *);

extern const rd_loadobj_t *Paddr_to_loadobj(struct ps_prochandle *, uintptr_t);
extern const rd_loadobj_t *Pname_to_loadobj(struct ps_prochandle *,
    const char *);
extern const rd_loadobj_t *Plmid_to_loadobj(struct ps_prochandle *,
    Lmid_t, const char *);

extern ctf_file_t *Paddr_to_ctf(struct ps_prochandle *, uintptr_t);
extern ctf_file_t *Pname_to_ctf(struct ps_prochandle *, const char *);

extern char *Pplatform(struct ps_prochandle *, char *, size_t);
extern int Puname(struct ps_prochandle *, struct utsname *);
extern char *Pzonename(struct ps_prochandle *, char *, size_t);
extern char *Pfindobj(struct ps_prochandle *, const char *, char *, size_t);

extern char *Pexecname(struct ps_prochandle *, char *, size_t);
extern char *Pobjname(struct ps_prochandle *, uintptr_t, char *, size_t);
extern char *Pobjname_resolved(struct ps_prochandle *, uintptr_t, char *,
    size_t);
extern int Plmid(struct ps_prochandle *, uintptr_t, Lmid_t *);

typedef int proc_env_f(void *, struct ps_prochandle *, uintptr_t, const char *);
extern	int Penv_iter(struct ps_prochandle *, proc_env_f *, void *);
extern char *Pgetenv(struct ps_prochandle *, const char *, char *, size_t);
extern long Pgetauxval(struct ps_prochandle *, int);
extern const auxv_t *Pgetauxvec(struct ps_prochandle *);

extern void Pset_procfs_path(const char *);

/*
 * Symbol table iteration interface.  The special lmid constants LM_ID_BASE,
 * LM_ID_LDSO, and PR_LMID_EVERY may be used with Psymbol_iter_by_lmid.
 */
typedef int proc_sym_f(void *, const GElf_Sym *, const char *);
typedef int proc_xsym_f(void *, const GElf_Sym *, const char *,
    const prsyminfo_t *);

extern int Psymbol_iter(struct ps_prochandle *,
    const char *, int, int, proc_sym_f *, void *);
extern int Psymbol_iter_by_addr(struct ps_prochandle *,
    const char *, int, int, proc_sym_f *, void *);
extern int Psymbol_iter_by_name(struct ps_prochandle *,
    const char *, int, int, proc_sym_f *, void *);

extern int Psymbol_iter_by_lmid(struct ps_prochandle *,
    Lmid_t, const char *, int, int, proc_sym_f *, void *);

extern int Pxsymbol_iter(struct ps_prochandle *,
    Lmid_t, const char *, int, int, proc_xsym_f *, void *);

/*
 * 'which' selects which symbol table and can be one of the following.
 */
#define	PR_SYMTAB	1
#define	PR_DYNSYM	2
/*
 * 'type' selects the symbols of interest by binding and type.  It is a bit-
 * mask of one or more of the following flags, whose order MUST match the
 * order of STB and STT constants in <sys/elf.h>.
 */
#define	BIND_LOCAL	0x0001
#define	BIND_GLOBAL	0x0002
#define	BIND_WEAK	0x0004
#define	BIND_ANY (BIND_LOCAL|BIND_GLOBAL|BIND_WEAK)
#define	TYPE_NOTYPE	0x0100
#define	TYPE_OBJECT	0x0200
#define	TYPE_FUNC	0x0400
#define	TYPE_SECTION	0x0800
#define	TYPE_FILE	0x1000
#define	TYPE_ANY (TYPE_NOTYPE|TYPE_OBJECT|TYPE_FUNC|TYPE_SECTION|TYPE_FILE)

/*
 * This returns the rtld_db agent handle for the process.
 * The handle will become invalid at the next successful exec() and
 * must not be used beyond that point (see Preset_maps(), below).
 */
extern rd_agent_t *Prd_agent(struct ps_prochandle *);

/*
 * This should be called when an RD_DLACTIVITY event with the
 * RD_CONSISTENT state occurs via librtld_db's event mechanism.
 * This makes libproc's address space mappings and symbol tables current.
 * The variant Pupdate_syms() can be used to preload all symbol tables as well.
 */
extern void Pupdate_maps(struct ps_prochandle *);
extern void Pupdate_syms(struct ps_prochandle *);

/*
 * This must be called after the victim process performs a successful
 * exec() if any of the symbol table interface functions have been called
 * prior to that point.  This is essential because an exec() invalidates
 * all previous symbol table and address space mapping information.
 * It is always safe to call, but if it is called other than after an
 * exec() by the victim process it just causes unnecessary overhead.
 *
 * The rtld_db agent handle obtained from a previous call to Prd_agent() is
 * made invalid by Preset_maps() and Prd_agent() must be called again to get
 * the new handle.
 */
extern void Preset_maps(struct ps_prochandle *);

/*
 * Given an address, Ppltdest() determines if this is part of a PLT, and if
 * so returns a pointer to the symbol name that will be used for resolution.
 * If the specified address is not part of a PLT, the function returns NULL.
 */
extern const char *Ppltdest(struct ps_prochandle *, uintptr_t);

/*
 * See comments for Pissyscall(), in Pisadep.h
 */
extern int Pissyscall_prev(struct ps_prochandle *, uintptr_t, uintptr_t *);

/*
 * Stack frame iteration interface.
 */
typedef int proc_stack_f(void *, prgregset_t, uint_t, const long *);

extern int Pstack_iter(struct ps_prochandle *,
    const prgregset_t, proc_stack_f *, void *);

/*
 * The following functions define a set of passive interfaces: libproc provides
 * default, empty definitions that are called internally.  If a client wishes
 * to override these definitions, it can simply provide its own version with
 * the same signature that interposes on the libproc definition.
 *
 * If the client program wishes to report additional error information, it
 * can provide its own version of Perror_printf.
 *
 * If the client program wishes to receive a callback after Pcreate forks
 * but before it execs, it can provide its own version of Pcreate_callback.
 */
extern void Perror_printf(struct ps_prochandle *P, const char *format, ...);
extern void Pcreate_callback(struct ps_prochandle *);

/*
 * Remove unprintable characters from psinfo.pr_psargs and replace with
 * whitespace characters so it is safe for printing.
 */
extern void proc_unctrl_psinfo(psinfo_t *);

/*
 * Utility functions for processing arguments which should be /proc files,
 * pids, and/or core files.  The returned error code can be passed to
 * Pgrab_error() in order to convert it to an error string.
 */
#define	PR_ARG_PIDS	0x1	/* Allow pid and /proc file arguments */
#define	PR_ARG_CORES	0x2	/* Allow core file arguments */

#define	PR_ARG_ANY	(PR_ARG_PIDS | PR_ARG_CORES)

extern struct ps_prochandle *proc_arg_grab(const char *, int, int, int *);
extern struct ps_prochandle *proc_arg_xgrab(const char *, const char *, int,
    int, int *, const char **);
extern pid_t proc_arg_psinfo(const char *, int, psinfo_t *, int *);
extern pid_t proc_arg_xpsinfo(const char *, int, psinfo_t *, int *,
    const char **);

/*
 * Utility functions for obtaining information via /proc without actually
 * performing a Pcreate() or Pgrab():
 */
extern int proc_get_auxv(pid_t, auxv_t *, int);
extern int proc_get_cred(pid_t, prcred_t *, int);
extern prpriv_t *proc_get_priv(pid_t);
extern void proc_free_priv(prpriv_t *);
extern int proc_get_psinfo(pid_t, psinfo_t *);
extern int proc_get_status(pid_t, pstatus_t *);
extern int proc_get_secflags(pid_t, prsecflags_t **);

/*
 * Utility functions for debugging tools to convert numeric fault,
 * signal, and system call numbers to symbolic names:
 */
#define	FLT2STR_MAX 32	/* max. string length of faults (like SIG2STR_MAX) */
#define	SYS2STR_MAX 32	/* max. string length of syscalls (like SIG2STR_MAX) */

extern char *proc_fltname(int, char *, size_t);
extern char *proc_signame(int, char *, size_t);
extern char *proc_sysname(int, char *, size_t);

/*
 * Utility functions for debugging tools to convert fault, signal, and system
 * call names back to the numeric constants:
 */
extern int proc_str2flt(const char *, int *);
extern int proc_str2sig(const char *, int *);
extern int proc_str2sys(const char *, int *);

/*
 * Utility functions for debugging tools to convert a fault, signal or system
 * call set to a string representation (e.g. "BUS,SEGV" or "open,close,read").
 */
#define	PRSIGBUFSZ	1024	/* buffer size for proc_sigset2str() */

extern char *proc_fltset2str(const fltset_t *, const char *, int,
    char *, size_t);
extern char *proc_sigset2str(const sigset_t *, const char *, int,
    char *, size_t);
extern char *proc_sysset2str(const sysset_t *, const char *, int,
    char *, size_t);

extern int Pgcore(struct ps_prochandle *, const char *, core_content_t);
extern int Pfgcore(struct ps_prochandle *, int, core_content_t);
extern core_content_t Pcontent(struct ps_prochandle *);

/*
 * Utility functions for debugging tools to convert a string representation of
 * a fault, signal or system call set back to the numeric value of the
 * corresponding set type.
 */
extern char *proc_str2fltset(const char *, const char *, int, fltset_t *);
extern char *proc_str2sigset(const char *, const char *, int, sigset_t *);
extern char *proc_str2sysset(const char *, const char *, int, sysset_t *);

/*
 * Utility functions for converting between strings and core_content_t.
 */
#define	PRCONTENTBUFSZ	80	/* buffer size for proc_content2str() */

extern int proc_str2content(const char *, core_content_t *);
extern int proc_content2str(core_content_t, char *, size_t);

/*
 * Utility functions for buffering output to stdout, stderr while
 * process is grabbed.  Prevents deadlocks due to pfiles `pgrep xterm`
 * and other varients.
 */
extern int proc_initstdio(void);
extern int proc_flushstdio(void);
extern int proc_finistdio(void);

/*
 * Iterate over all open files.
 */
typedef int proc_fdinfo_f(void *, prfdinfo_t *);
extern int Pfdinfo_iter(struct ps_prochandle *, proc_fdinfo_f *, void *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBPROC_H */
