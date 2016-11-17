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
 * Copyright 2016 Joyent, Inc.
 */

#ifndef _LX_BRAND_H
#define	_LX_BRAND_H

#ifndef _ASM
#include <sys/types.h>
#include <sys/cpuvar.h>
#include <sys/zone.h>
#include <sys/ksocket.h>
#include <sys/vfs.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/cpuvar.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#define	LX_BRANDNAME	"lx"

/*
 * Brand uname info
 */
#define	LX_UNAME_SYSNAME	"Linux"
#define	LX_UNAME_RELEASE_2_6	"2.6.18"
#define	LX_UNAME_RELEASE_2_4	"2.4.21"
#define	LX_UNAME_VERSION	"BrandZ virtual linux"
#define	LX_UNAME_MACHINE32	"i686"
#define	LX_UNAME_MACHINE64	"x86_64"

#define	LX_LIB_PATH32	"/native/usr/lib/lx_brand.so.1"
#define	LX_LIB_PATH64	"/native/usr/lib/amd64/lx_brand.so.1"

#define	LX_VDSO_PATH32	"/native/usr/lib/brand/lx/lx_vdso.so.1"
#define	LX_VDSO_PATH64	"/native/usr/lib/brand/lx/amd64/lx_vdso.so.1"

#if defined(_LP64)
#define	LX_LIB_PATH		LX_LIB_PATH64
#define	LX_UNAME_MACHINE	LX_UNAME_MACHINE64
#define	LX_VDSO_PATH		LX_VDSO_PATH64
#else
#define	LX_LIB_PATH		LX_LIB_PATH32
#define	LX_UNAME_MACHINE	LX_UNAME_MACHINE32
#define	LX_VDSO_PATH		LX_VDSO_PATH32
#endif

/*
 * This must be large enough for both the 32-bit table and 64-bit table.
 */
#define	LX_NSYSCALLS		358

/* Highest capability we know about */
#define	LX_CAP_MAX_VALID	36

/* sched attr flag values */
#define	LX_SCHED_FLAG_RESET_ON_FORK	0x1
/*
 * brand(2) subcommands
 *
 * Everything >= 128 is a brand-specific subcommand.
 * > 192 is reserved for in-kernel emulated system calls.
 */
#define	B_LPID_TO_SPAIR		128
#define	B_GET_CURRENT_CONTEXT	129
#define	B_EMULATION_DONE	130
/* formerly B_PTRACE_KERNEL	131 */
/* formerly B_SET_AFFINITY_MASK	132 */
/* formerly B_GET_AFFINITY_MASK	133 */
#define	B_PTRACE_CLONE_BEGIN	134
#define	B_PTRACE_STOP_FOR_OPT	135
#define	B_UNSUPPORTED		136
#define	B_STORE_ARGS		137
#define	B_GETPID		138
#define	B_JUMP_TO_LINUX		139
/* formerly B_SET_THUNK_PID	140 */
#define	B_EXIT_AS_SIG		141
/* formerly B_HELPER_WAITID	142 */
#define	B_HELPER_CLONE		143
#define	B_HELPER_SETGROUPS	144
#define	B_HELPER_SIGQUEUE	145
#define	B_HELPER_TGSIGQUEUE	146
#define	B_SET_NATIVE_STACK	147
/* formerly B_SIGEV_THREAD_ID	148 */
#define	B_OVERRIDE_KERN_VER	149
#define	B_PTRACE_SIG_RETURN	150
#define	B_GET_PERSONALITY	151

#ifndef _ASM
/*
 * Support for Linux PTRACE_SETOPTIONS handling.
 */
typedef enum lx_ptrace_options {
	LX_PTRACE_O_TRACESYSGOOD =	0x0001,
	LX_PTRACE_O_TRACEFORK =		0x0002,
	LX_PTRACE_O_TRACEVFORK =	0x0004,
	LX_PTRACE_O_TRACECLONE =	0x0008,
	LX_PTRACE_O_TRACEEXEC =		0x0010,
	LX_PTRACE_O_TRACEVFORKDONE =	0x0020,
	LX_PTRACE_O_TRACEEXIT =		0x0040,
	LX_PTRACE_O_TRACESECCOMP =	0x0080
} lx_ptrace_options_t;

#define	LX_PTRACE_O_ALL							\
	(LX_PTRACE_O_TRACESYSGOOD | LX_PTRACE_O_TRACEFORK | 		\
	LX_PTRACE_O_TRACEVFORK | LX_PTRACE_O_TRACECLONE | 		\
	LX_PTRACE_O_TRACEEXEC | LX_PTRACE_O_TRACEVFORKDONE |		\
	LX_PTRACE_O_TRACEEXIT | LX_PTRACE_O_TRACESECCOMP)
#endif /* !_ASM */

/* siginfo si_status for traced events */
#define	LX_PTRACE_EVENT_FORK		0x100
#define	LX_PTRACE_EVENT_VFORK		0x200
#define	LX_PTRACE_EVENT_CLONE		0x300
#define	LX_PTRACE_EVENT_EXEC		0x400
#define	LX_PTRACE_EVENT_VFORK_DONE	0x500
#define	LX_PTRACE_EVENT_EXIT		0x600
#define	LX_PTRACE_EVENT_SECCOMP		0x700

/*
 * Brand-private values for the "pr_what" member of lwpstatus, for use with the
 * PR_BRAND stop reason.  These reasons are validated in lx_stop_notify();
 * update it if you add new reasons here.
 */
#define	LX_PR_SYSENTRY		1
#define	LX_PR_SYSEXIT		2
#define	LX_PR_SIGNALLED		3
#define	LX_PR_EVENT		4


#define	LX_VERSION_1		1
#define	LX_VERSION		LX_VERSION_1

#define	LX_ATTR_KERN_RELEASE	ZONE_ATTR_BRAND_ATTRS
#define	LX_ATTR_KERN_VERSION	(ZONE_ATTR_BRAND_ATTRS + 1)

/*
 * Aux vector containing phdr of Linux executable and ehdr of interpreter
 * (if any), both of which are used by lx_librtld_db to ascertain r_debug.
 * We repurpose the 3rd brand-specific aux vector slot for the Linux
 * AT_SYSINFO_EHDR entry (we modify the a_type in the brand library).
 */
#define	AT_SUN_BRAND_LX_PHDR		AT_SUN_BRAND_AUX1
#define	AT_SUN_BRAND_LX_INTERP		AT_SUN_BRAND_AUX2
#define	AT_SUN_BRAND_LX_CLKTCK		AT_SUN_BRAND_AUX3
#define	AT_SUN_BRAND_LX_SYSINFO_EHDR	AT_SUN_BRAND_AUX4

/* Aux vectors containing real/effective user/group IDs */
#define	AT_LX_UID		11
#define	AT_LX_EUID		12
#define	AT_LX_GID		13
#define	AT_LX_EGID		14
/* Aux vector containing hz value */
#define	AT_CLKTCK	17
/* Aux vector containing secure boolean */
#define	AT_SECURE	23
/* Aux vector containing vDSO addr */
#define	AT_SYSINFO_EHDR	33

/*
 * Usermode emulation routines are run on an alternate stack allocated by
 * the brand library.  Every LWP in a process will incur this overhead beyond
 * the regular thread stack:
 */
#define	LX_NATIVE_STACK_PAGE_COUNT	64

/*
 * When returning in a new child process created with vfork(2) (or CLONE_VFORK)
 * we discard some of the native stack to prevent corruption of the parent
 * emulation state.
 */
#define	LX_NATIVE_STACK_VFORK_GAP	0x3000

#ifndef	_ASM

extern struct brand lx_brand;

typedef struct lx_brand_registration {
	uint_t lxbr_version;		/* version number */
	void *lxbr_handler;		/* base address of handler */
	uint32_t lxbr_flags;		/* LX_PROC_* registration flags */
} lx_brand_registration_t;

typedef struct lx_brand_registration32 {
	uint_t lxbr_version;		/* version number */
	uint32_t lxbr_handler;		/* base address of handler */
	uint32_t lxbr_flags;		/* LX_PROC_* registration flags */
} lx_brand_registration32_t;

#endif /* _ASM */

/*
 * GDT usage
 */
#define	GDT_TLSMIN	(GDT_BRANDMIN)
#define	GDT_TLSMAX	(GDT_TLSMIN + 2)
#define	LX_TLSNUM	(GDT_TLSMAX - GDT_TLSMIN)

#ifndef _ASM

/*
 * Stores information needed by the lx linker to launch the main
 * lx executable.
 */
typedef struct lx_elf_data64 {
	uintptr_t	ed_phdr;
	uintptr_t	ed_phent;
	uintptr_t	ed_phnum;
	uintptr_t	ed_entry;
	uintptr_t	ed_base;
	uintptr_t	ed_ldentry;
} lx_elf_data64_t;

typedef struct lx_elf_data32 {
	uint32_t	ed_phdr;
	uint32_t	ed_phent;
	uint32_t	ed_phnum;
	uint32_t	ed_entry;
	uint32_t	ed_base;
	uint32_t	ed_ldentry;
} lx_elf_data32_t;

#if defined(_LP64)
typedef lx_elf_data64_t lx_elf_data_t;
#else
typedef lx_elf_data32_t lx_elf_data_t;
#endif

typedef enum lx_proc_flags {
	/* flags configurable via brandsys() and members of LX_PROC_ALL */
	LX_PROC_INSTALL_MODE	= 0x01,
	LX_PROC_STRICT_MODE	= 0x02,
	/* internal flags */
	LX_PROC_CHILD_DEATHSIG	= 0x04,
	LX_PROC_AIO_USED	= 0x08,
	LX_PROC_NO_DUMP		= 0x10	/* for lx_prctl LX_PR_[GS]ET_DUMPABLE */
} lx_proc_flags_t;

#define	LX_PROC_ALL	(LX_PROC_INSTALL_MODE | LX_PROC_STRICT_MODE)

/* Maximum length for fields of LX uname */
#define	LX_SYS_UTS_LN	65

/* Max. length of kernel release string */
#define	LX_KERN_RELEASE_MAX	LX_SYS_UTS_LN
#define	LX_KERN_VERSION_MAX	LX_SYS_UTS_LN

#ifdef	_KERNEL

/*
 * Entry points for cgroup integration.
 */
extern void (*lx_cgrp_initlwp)(vfs_t *, uint_t, id_t, pid_t);
extern void (*lx_cgrp_freelwp)(vfs_t *, uint_t, id_t, pid_t);

#define	LX_RLFAKE_LOCKS		0
#define	LX_RLFAKE_NICE		1
#define	LX_RLFAKE_RTPRIO	2
#define	LX_RLFAKE_RTTIME	3

#define	LX_RLFAKE_NLIMITS	4

#define	LX_RLIM64_INFINITY	(~0ULL)

typedef struct {
	uint64_t	rlim_cur;
	uint64_t	rlim_max;
} lx_rlimit64_t;

typedef struct lx_proc_data {
	uintptr_t l_handler;	/* address of user-space handler */
	pid_t l_ppid;		/* pid of originating parent proc */
	uid_t l_loginuid;	/* /proc/{pid}/loginuid */
	int64_t l_ptrace;	/* count of process lwps observed by ptrace */
	lx_elf_data_t l_elf_data; /* ELF data for linux executable */
	/* signal to deliver to parent when this thread group dies */
	int l_signal;
	/* native signal to deliver to process when parent dies */
	int l_parent_deathsig;
	lx_proc_flags_t l_flags;

	lx_rlimit64_t l_fake_limits[LX_RLFAKE_NLIMITS];

	/* original start/end bounds of arg/env string data */
	uintptr_t l_args_start;
	uintptr_t l_envs_start;
	uintptr_t l_envs_end;

	/* Override zone-wide settings for uname release and version */
	char l_uname_release[LX_KERN_RELEASE_MAX];
	char l_uname_version[LX_KERN_VERSION_MAX];

	/* Linux process personality */
	unsigned int l_personality;

	/* VDSO location */
	uintptr_t l_vdso;
} lx_proc_data_t;

#endif	/* _KERNEL */

/*
 * Linux process personality(2) flags stored in l_personality
 */
#define	LX_PER_UNAME26			0x0020000
#define	LX_PER_ADDR_NO_RANDOMIZE	0x0040000
#define	LX_PER_FDPIC_FUNCPTRS		0x0080000
#define	LX_PER_MMAP_PAGE_ZERO		0x0100000
#define	LX_PER_ADDR_COMPAT_LAYOUT	0x0200000
#define	LX_PER_READ_IMPLIES_EXEC	0x0400000
#define	LX_PER_ADDR_LIMIT_32BIT		0x0800000
#define	LX_PER_SHORT_INODE		0x1000000
#define	LX_PER_WHOLE_SECONDS		0x2000000
#define	LX_PER_STICKY_TIMEOUTS		0x4000000
#define	LX_PER_ADDR_LIMIT_3GB		0x8000000

#define	LX_PER_LINUX	0x00
#define	LX_PER_SUNOS	(0x06 | LX_PER_STICKY_TIMEOUTS)
#define	LX_PER_MASK	0xff

/*
 * A data type big enough to bitmap all Linux possible cpus.
 * The bitmap size is defined as 1024 cpus in the Linux 2.4 and 2.6 man pages
 * for sched_getaffinity() and sched_getaffinity().
 */
#define	LX_NCPU		(1024)
#define	LX_AFF_ULONGS	(LX_NCPU / (8 * sizeof (ulong_t)))
typedef ulong_t lx_affmask_t[LX_AFF_ULONGS];

/* Length of proc boot_id string */
#define	LX_BOOTID_LEN	37

/*
 * Flag values for uc_brand_data[0] in the ucontext_t:
 */
#define	LX_UC_STACK_NATIVE	0x00001
#define	LX_UC_STACK_BRAND	0x00002
#define	LX_UC_RESTORE_NATIVE_SP	0x00010
#define	LX_UC_FRAME_IS_SYSCALL	0x00100
#define	LX_UC_RESTART_SYSCALL	0x01000
#define	LX_UC_IGNORE_LINK	0x10000

#ifdef	_KERNEL

typedef struct lx_lwp_data lx_lwp_data_t;

/*
 * Flag values for "lxpa_flags" on a ptrace(2) accord.
 */
typedef enum lx_accord_flags {
	LX_ACC_TOMBSTONE = 0x01
} lx_accord_flags_t;

/*
 * Flags values for "br_ptrace_flags" in the LWP-specific data.
 */
typedef enum lx_ptrace_flags {
	LX_PTF_SYSCALL = 0x01,		/* handling syscall or a trap */
	LX_PTF_EXITING = 0x02,
	LX_PTF_STOPPING = 0x04,
	LX_PTF_INHERIT = 0x08,
	LX_PTF_STOPPED = 0x10,
	LX_PTF_PARENT_WAIT = 0x20,
	LX_PTF_CLDPEND = 0x40,
	LX_PTF_CLONING = 0x80,
	LX_PTF_WAITPEND = 0x100,
	LX_PTF_NOSTOP = 0x200,		/* disable syscall stop event */
	LX_PTF_INSYSCALL = 0x400	/* between syscall enter & exit */
} lx_ptrace_flags_t;

/*
 * A ptrace(2) accord represents the relationship between a tracer LWP and the
 * set of LWPs that it is tracing: the tracees.  This data structure belongs
 * primarily to the tracer, but is reference counted so that it may be freed by
 * whoever references it last.
 */
typedef struct lx_ptrace_accord {
	kmutex_t		lxpa_lock;
	uint_t			lxpa_refcnt;
	lx_accord_flags_t	lxpa_flags;

	/*
	 * The tracer must hold "pidlock" while clearing these fields for
	 * exclusion of waitid(), etc.
	 */
	lx_lwp_data_t		*lxpa_tracer;
	kcondvar_t		*lxpa_cvp;

	/*
	 * The "lxpa_tracees_lock" mutex protects the tracee list.
	 */
	kmutex_t		lxpa_tracees_lock;
	list_t			lxpa_tracees;
} lx_ptrace_accord_t;

/*
 * These values are stored in the per-LWP data for a tracee when it is attached
 * to a tracer.  They record the method that was used to attach.
 */
typedef enum lx_ptrace_attach {
	LX_PTA_NONE = 0x00,		/* not attached */
	LX_PTA_ATTACH = 0x01,		/* due to tracer using PTRACE_ATTACH */
	LX_PTA_TRACEME = 0x02,		/* due to child using PTRACE_TRACEME */
	LX_PTA_INHERIT_CLONE = 0x04,	/* due to PTRACE_CLONE clone(2) flag */
	LX_PTA_INHERIT_OPTIONS = 0x08	/* due to PTRACE_SETOPTIONS options */
} lx_ptrace_attach_t;

typedef enum lx_stack_mode {
	LX_STACK_MODE_PREINIT = 0,
	LX_STACK_MODE_INIT,
	LX_STACK_MODE_NATIVE,
	LX_STACK_MODE_BRAND
} lx_stack_mode_t;

struct lx_pid {
	pid_t		lxp_spid;	/* the SunOS pid and ... */
	id_t		lxp_stid;	/* ... tid pair */
	pid_t		lxp_lpid;	/* the corresponding linux pid */
	time_t		lxp_start;	/* birthday of this pid */
	struct pid	*lxp_pidp;	/* allocated pid struct */
	proc_t		*lxp_procp;	/* proc_t corresponding to lxp_spid */
	struct lx_pid	*lxp_stol_next;	/* link in stol hash table */
	struct lx_pid	*lxp_ltos_next;	/* link in ltos hash table */
};

/*
 * lx-specific data in the klwp_t
 */
struct lx_lwp_data {
	uint_t	br_lwp_flags;		/* misc. flags */
	klwp_t	*br_lwp;		/* back pointer to container lwp */
	int	br_signal;		/* signal to send to parent when */
					/* clone()'ed child terminates */
	int	br_exitwhy;		/* reason for thread (process) exit */
	int	br_exitwhat;		/* exit code / killing signal */
	cpuset_t *br_affinitymask;	/* bitmask of CPU sched affinities */
	struct user_desc br_tls[LX_TLSNUM];
			/* descriptors used by libc for TLS */
	ulong_t	br_lx_fsbase;		/* lx fsbase for 64-bit thread ptr */
	ulong_t	br_ntv_fsbase;		/* native fsbase 64-bit thread ptr */
	ulong_t	br_lx_gsbase;		/* lx user-land gsbase */
	ulong_t	br_ntv_gsbase;		/* native user-land gsbase */
	pid_t	br_pid;			/* converted pid for this thread */
	pid_t	br_tgid;		/* thread group ID for this thread */
	pid_t	br_ppid;		/* parent pid for this thread */
	id_t	br_ptid;		/* parent tid for this thread */
	void	*br_clear_ctidp;	/* clone thread id ptr */
	void	*br_set_ctidp;		/* clone thread id ptr */
	void	*br_robust_list;	/* robust lock list, if any */

	/*
	 * The following struct is used by some system calls to pass extra
	 * flags into the kernel without impinging on the namespace for
	 * illumos.
	 */
	void	*br_scall_args;
	int	br_args_size; /* size in bytes of br_scall_args */

	boolean_t br_waitid_emulate;
	int br_waitid_flags;

	lx_ptrace_flags_t br_ptrace_flags; /* ptrace flags for this LWP */
	lx_ptrace_options_t br_ptrace_options; /* PTRACE_SETOPTIONS options */
	lx_ptrace_options_t br_ptrace_clone_option; /* current clone(2) type */

	lx_ptrace_attach_t br_ptrace_attach; /* how did we get attached */
	lx_ptrace_accord_t *br_ptrace_accord; /* accord for this tracer LWP */
	lx_ptrace_accord_t *br_ptrace_tracer; /* accord tracing this LWP */
	list_node_t br_ptrace_linkage;	/* linkage for lxpa_tracees list */

	ushort_t br_ptrace_whystop; 	/* stop reason, 0 for no stop */
	ushort_t br_ptrace_whatstop;	/* stop sub-reason */

	int32_t br_ptrace_stopsig;	/* stop signal, 0 for no signal */
	/*
	 * Track the last (native) signal number processed by a ptrace.
	 * This allows the tracee to properly handle ignored signals after
	 * the tracer has been notified and the tracee restarted.
	 */
	int32_t br_ptrace_donesig;
	uintptr_t br_ptrace_stopucp;	/* usermode ucontext_t pointer */

	uint_t	br_ptrace_event;
	ulong_t	br_ptrace_eventmsg;

	int	br_syscall_num;		/* current system call number */
	boolean_t br_syscall_restart;	/* should restart on EINTR */

	/*
	 * Store the LX_STACK_MODE for this LWP, and the current extent of the
	 * native (emulation) stack.  This is similar, in principle, to the
	 * sigaltstack mechanism for signal handling.  We also use this mode
	 * flag to determine how to process system calls from this LWP.
	 */
	lx_stack_mode_t	br_stack_mode;
	uintptr_t br_ntv_stack;
	uintptr_t br_ntv_stack_current;

	/*
	 * If strict mode is enabled (via LX_STRICT in the environment), any
	 * call to lx_unsupported() will set this boolean to B_TRUE.  This will
	 * cause us to drop SIGSYS on the LWP as it attempts to return to
	 * usermode.
	 */
	boolean_t br_strict_failure;

	/*
	 * Some syscalls emulated in-kernel still call back out to the
	 * userspace emulation for certain functions.  When that is the case,
	 * the syscall_return logic must be bypassed at the end of the
	 * in-kernel syscall code.  The NORMALRETURN and JUSTRETURN constants
	 * are used to choose the behavior.
	 */
	char br_eosys;

	/*
	 * Hold a pre-allocated lx_pid structure to be used during lx_initlwp.
	 */
	struct lx_pid *br_lpid;

	/*
	 * ID of the cgroup this thread belongs to.
	 */
	uint_t br_cgroupid;

	/*
	 * When the zone is running under FSS (which is the common case) then
	 * we cannot change scheduling class, so we emulate that. By default
	 * Linux uses LX_SCHED_OTHER (which is 0) and that only supports a
	 * priority of 0, so no special initialization is needed.
	 */
	int	br_schd_class;		/* emulated scheduling class */
	int	br_schd_pri;		/* emulated scheduling priority */
	uint64_t br_schd_flags;		/* emulated [sg]et_attr flags */
	uint64_t br_schd_runtime;	/* emulated DEADLINE */
	uint64_t br_schd_deadline;	/* emulated DEADLINE */
	uint64_t br_schd_period;	/* emulated DEADLINE */
};

/*
 * Upper limit on br_args_size, low because this value can persist until
 * overridden with another value, and the size is given from userland.
 */
#define	LX_BR_ARGS_SIZE_MAX	(1024)

/*
 * brand specific data
 *
 * We currently only support a single cgroup mount in an lx zone so we only have
 * one ptr (lxzd_cgroup) but this could be changed to a list if cgroups is ever
 * enhanced to support different mounts with different subsystem controllers.
 */
typedef struct lx_zone_data {
	kmutex_t lxzd_lock;			/* protects all members */
	char lxzd_kernel_release[LX_KERN_RELEASE_MAX];
	char lxzd_kernel_version[LX_KERN_VERSION_MAX];
	ksocket_t lxzd_ioctl_sock;
	char lxzd_bootid[LX_BOOTID_LEN];	/* procfs boot_id */
	vfs_t *lxzd_cgroup;			/* cgroup for this zone */
	list_t *lxzd_vdisks;			/* virtual disks (zvols) */
	dev_t lxzd_zfs_dev;			/* major num for zfs */
} lx_zone_data_t;

#define	BR_CPU_BOUND	0x0001

#define	ttolxlwp(t)	((struct lx_lwp_data *)ttolwpbrand(t))
#define	lwptolxlwp(l)	((struct lx_lwp_data *)lwptolwpbrand(l))
#define	ttolxproc(t)	\
	(((t)->t_procp->p_brand == &lx_brand) ? \
	(struct lx_proc_data *)(t)->t_procp->p_brand_data : NULL)
#define	ptolxproc(p)	\
	(((p)->p_brand == &lx_brand) ? \
	(struct lx_proc_data *)(p)->p_brand_data : NULL)
#define	ztolxzd(z)		\
	(((z)->zone_brand == &lx_brand) ?  \
	(lx_zone_data_t *)(z)->zone_brand_data : NULL)

/* Macro for converting to system call arguments. */
#define	LX_ARGS(scall) ((struct lx_##scall##_args *)\
	(ttolxlwp(curthread)->br_scall_args))

typedef enum lx_virt_disk_type {
	LXVD_NONE,
	LXVD_ZFS_DS,
	LXVD_ZVOL
} lx_virt_disk_type_t;

typedef struct lx_virt_disk {
	list_node_t		lxvd_link;
	char			lxvd_name[MAXNAMELEN];
	lx_virt_disk_type_t	lxvd_type;
	dev_t			lxvd_emul_dev;
	dev_t			lxvd_real_dev;
	uint64_t		lxvd_volsize;
	uint64_t		lxvd_blksize;
	char			lxvd_real_name[MAXPATHLEN];
} lx_virt_disk_t;

/*
 * Determine the upper bound on the system call number:
 */
#if defined(_LP64)
#define	LX_MAX_SYSCALL(lwp)						\
	((lwp_getdatamodel(lwp) == DATAMODEL_NATIVE) ?			\
	    lx_nsysent64 : lx_nsysent32)
#else
#define	LX_MAX_SYSCALL(lwp)	lx_nsysent32
#endif

extern int lx_kern_release_cmp(zone_t *, const char *);

extern void lx_lwp_set_native_stack_current(lx_lwp_data_t *, uintptr_t);
extern void lx_divert(klwp_t *, uintptr_t);
extern int lx_runexe(klwp_t *, void *);
extern void lx_switch_to_native(klwp_t *);

extern int lx_syscall_enter(void);
extern void lx_syscall_return(klwp_t *, int, long);

extern void lx_trace_sysenter(int, uintptr_t *);
extern void lx_trace_sysreturn(int, long);

extern void lx_emulate_user(klwp_t *, int, uintptr_t *);
#if defined(_SYSCALL32_IMPL)
extern void lx_emulate_user32(klwp_t *, int, uintptr_t *);
#endif

extern int lx_debug;
#define	lx_print	if (lx_debug) printf

typedef enum {
	NO_PRLOCK,
	PRLOCK
} lx_pid_flag_t;

extern void lx_pid_assign(kthread_t *, struct lx_pid *);
extern void lx_pid_reassign(kthread_t *);
extern void lx_pid_rele(pid_t, id_t);
extern pid_t lx_lpid_to_spair(pid_t, pid_t *, id_t *);
extern int lx_lpid_lock(pid_t, zone_t *, lx_pid_flag_t, proc_t **,
    kthread_t **);
extern pid_t lx_lwp_ppid(klwp_t *, pid_t *, id_t *);
extern void lx_pid_init(void);
extern void lx_pid_fini(void);

/*
 * In-Kernel Linux System Call Description.
 */
typedef struct lx_sysent {
	char	*sy_name;
	long	(*sy_callc)();
	char	sy_flags;
	char	sy_narg;
} lx_sysent_t;

#if defined(_LP64)
extern lx_sysent_t lx_sysent64[LX_NSYSCALLS + 1];
extern int lx_nsysent64;
#endif
extern lx_sysent_t lx_sysent32[LX_NSYSCALLS + 1];
extern int lx_nsysent32;

#endif	/* _KERNEL */
#endif /* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _LX_BRAND_H */
