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
 * Copyright 2015 Joyent, Inc. All rights reserved.
 */

#ifndef _LX_BRAND_H
#define	_LX_BRAND_H

#ifndef _ASM
#include <sys/types.h>
#include <sys/cpuvar.h>
#include <sys/zone.h>
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

#if defined(_LP64)
#define	LX_LIB_PATH		LX_LIB_PATH64
#define	LX_UNAME_MACHINE	LX_UNAME_MACHINE64
#else
#define	LX_LIB_PATH		LX_LIB_PATH32
#define	LX_UNAME_MACHINE	LX_UNAME_MACHINE32
#endif

/*
 * This must be large enough for both the 32-bit table and 64-bit table.
 */
#define	LX_NSYSCALLS		352

/* The number of In-Kernel Emulation functions */
#define	LX_N_IKE_FUNCS		29

/*
 * brand(2) subcommands
 *
 * Everything >= 128 is a brand-specific subcommand.
 * > 192 is reserved for in-kernel emulated system calls.
 */
#define	B_LPID_TO_SPAIR		128
#define	B_SYSENTRY		129
#define	B_SYSRETURN		130
#define	B_PTRACE_KERNEL		131
#define	B_SET_AFFINITY_MASK	132
#define	B_GET_AFFINITY_MASK	133
#define	B_PTRACE_CLONE_BEGIN	134
#define	B_PTRACE_STOP_FOR_OPT	135
#define	B_UNSUPPORTED		136
#define	B_STORE_ARGS		137
#define	B_CLR_NTV_SYSC_FLAG	138
#define	B_SIGNAL_RETURN		139
#define	B_UNWIND_NTV_SYSC_FLAG	140
#define	B_EXIT_AS_SIG		141
#define	B_HELPER_WAITID		142

#define	B_IKE_SYSCALL		192

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

#define	LX_KERN_VERSION_NUM	ZONE_ATTR_BRAND_ATTRS

/*
 * Aux vector containing phdr of Linux executable and ehdr of interpreter
 * (if any), both of which are used by lx_librtld_db to ascertain r_debug.
 * We repurpose the 3rd brand-specific aux vector slot for the Linux
 * AT_SYSINFO_EHDR entry (we modify the a_type in the brand library).
 */
#define	AT_SUN_BRAND_LX_PHDR	AT_SUN_BRAND_AUX1
#define	AT_SUN_BRAND_LX_INTERP	AT_SUN_BRAND_AUX2
#define	AT_SUN_BRAND_LX_SYSINFO_EHDR	AT_SUN_BRAND_AUX3

/* Aux vector containing hz value */
#define	AT_CLKTCK	17
/* Aux vector containing vDSO addr */
#define	AT_SYSINFO_EHDR	33

#ifndef	_ASM

extern struct brand lx_brand;

typedef struct lx_brand_registration {
	uint_t lxbr_version;		/* version number */
	void *lxbr_handler;		/* base address of handler */
	void *lxbr_tracehandler;	/* base address of trace handler */
	void *lxbr_traceflag;		/* address of trace flag */
} lx_brand_registration_t;

typedef struct lx_brand_registration32 {
	uint_t lxbr_version;		/* version number */
	uint32_t lxbr_handler;		/* base address of handler */
	uint32_t lxbr_tracehandler;	/* base address of trace handler */
	uint32_t lxbr_traceflag;	/* address of trace flag */
} lx_brand_registration32_t;

#ifdef __amd64
typedef struct lx_regs {
	long lxr_fs;
	long lxr_rdi;
	long lxr_rsi;
	long lxr_rbp;
	long lxr_rsp;
	long lxr_rbx;
	long lxr_rdx;
	long lxr_rcx;
	long lxr_rax;
	long lxr_r8;
	long lxr_r9;
	long lxr_r10;
	long lxr_r11;
	long lxr_r12;
	long lxr_r13;
	long lxr_r14;
	long lxr_r15;
	long lxr_rip;

	long lxr_orig_rax;
} lx_regs_t;
#else /* ! __amd64 */
typedef struct lx_regs {
	long lxr_gs;
	long lxr_edi;
	long lxr_esi;
	long lxr_ebp;
	long lxr_esp;
	long lxr_ebx;
	long lxr_edx;
	long lxr_ecx;
	long lxr_eax;
	long lxr_eip;

	long lxr_orig_eax;
} lx_regs_t;
#endif /* __amd64 */

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
	int	ed_phdr;
	int	ed_phent;
	int	ed_phnum;
	int	ed_entry;
	int	ed_base;
	int	ed_ldentry;
} lx_elf_data32_t;

#if defined(_LP64)
typedef lx_elf_data64_t lx_elf_data_t;
#else
typedef lx_elf_data32_t lx_elf_data_t;
#endif

#ifdef	_KERNEL

typedef struct lx_proc_data {
	uintptr_t l_handler;	/* address of user-space handler */
	uintptr_t l_tracehandler; /* address of user-space traced handler */
	uintptr_t l_traceflag;	/* address of 32-bit tracing flag */
	pid_t l_ppid;		/* pid of originating parent proc */
	uint64_t l_ptrace;	/* process being observed with ptrace */
	lx_elf_data_t l_elf_data; /* ELF data for linux executable */
	int l_signal;		/* signal to deliver to parent when this */
				/* thread group dies */
} lx_proc_data_t;

#endif	/* _KERNEL */

/*
 * A data type big enough to bitmap all Linux possible cpus.
 * The bitmap size is defined as 1024 cpus in the Linux 2.4 and 2.6 man pages
 * for sched_getaffinity() and sched_getaffinity().
 */
#define	LX_NCPU		(1024)
#define	LX_AFF_ULONGS	(LX_NCPU / (8 * sizeof (ulong_t)))
typedef ulong_t lx_affmask_t[LX_AFF_ULONGS];

/* Max. length of kernel version string */
#define	LX_VERS_MAX	16

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
typedef enum lx_ptrace_state {
	LX_PTRACE_SYSCALL = 0x01,
	LX_PTRACE_EXITING = 0x02,
	LX_PTRACE_STOPPING = 0x04,
	LX_PTRACE_INHERIT = 0x08,
	LX_PTRACE_STOPPED = 0x10,
	LX_PTRACE_PARENT_WAIT = 0x20,
	LX_PTRACE_CLDPEND = 0x40,
	LX_PTRACE_CLONING = 0x80
} lx_ptrace_state_t;

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

/*
 * lx-specific data in the klwp_t
 */
struct lx_lwp_data {
	uint_t	br_ntv_syscall;		/* 1 = syscall from native libc */
	uint_t	br_lwp_flags;		/* misc. flags */
	klwp_t	*br_lwp;		/* back pointer to container lwp */
	int	br_signal;		/* signal to send to parent when */
					/* clone()'ed child terminates */
	int	br_exitwhy;		/* reason for thread (process) exit */
	int	br_exitwhat;		/* exit code / killing signal */
	lx_affmask_t br_affinitymask;	/* bitmask of CPU sched affinities */
	struct user_desc br_tls[LX_TLSNUM];
			/* descriptors used by libc for TLS */
	ulong_t	br_lx_fsbase;		/* lx fsbase for 64-bit thread ptr */
	ulong_t	br_ntv_fsbase;		/* native fsbase 64-bit thread ptr */
	/*
	 * 64-bit thread-specific syscall mode state "stack". Bits tracking the
	 * syscall mode are shifted on/off this int like a stack as we take
	 * signals and return.
	 */
	uint_t	br_scms;
	pid_t	br_pid;			/* converted pid for this thread */
	pid_t	br_tgid;		/* thread group ID for this thread */
	pid_t	br_ppid;		/* parent pid for this thread */
	id_t	br_ptid;		/* parent tid for this thread */
	void	*br_clear_ctidp;	/* clone thread id ptr */
	void	*br_set_ctidp;		/* clone thread id ptr */

	/*
	 * The following struct is used by some system calls to pass extra
	 * flags into the kernel without impinging on the namespace for
	 * illumos.
	 */
	void	*br_scall_args;
	int	br_args_size; /* size in bytes of br_scall_args */

	boolean_t br_waitid_emulate;
	int br_waitid_flags;

	lx_ptrace_state_t br_ptrace_flags; /* ptrace state for this LWP */
	lx_ptrace_options_t br_ptrace_options; /* PTRACE_SETOPTIONS options */
	lx_ptrace_options_t br_ptrace_clone_option; /* current clone(2) type */

	lx_ptrace_attach_t br_ptrace_attach; /* how did we get attached */
	lx_ptrace_accord_t *br_ptrace_accord; /* accord for this tracer LWP */
	lx_ptrace_accord_t *br_ptrace_tracer; /* accord tracing this LWP */
	list_node_t br_ptrace_linkage;	/* linkage for lxpa_tracees list */

	ushort_t br_ptrace_whystop; 	/* stop reason, 0 for no stop */
	ushort_t br_ptrace_whatstop;	/* stop sub-reason */

	int32_t br_ptrace_stopsig;	/* stop signal, 0 for no signal */

	uint_t	br_ptrace_event;
	ulong_t	br_ptrace_eventmsg;
};

/*
 * Upper limit on br_args_size, low because this value can persist until
 * overridden with another value, and the size is given from userland.
 */
#define	LX_BR_ARGS_SIZE_MAX	(1024)

/* brand specific data */
typedef struct lx_zone_data {
	char lxzd_kernel_version[LX_VERS_MAX];
	int lxzd_max_syscall;
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

/* Macro for converting to system call arguments. */
#define	LX_ARGS(scall) ((struct lx_##scall##_args *)\
	(ttolxlwp(curthread)->br_scall_args))

void	lx_brand_int80_callback(void);
void	lx_brand_syscall_callback(void);
int64_t	lx_emulate_syscall(int, uintptr_t, uintptr_t, uintptr_t, uintptr_t,
	uintptr_t, uintptr_t);

extern char *lx_get_zone_kern_version(zone_t *);

extern int lx_debug;
#define	lx_print	if (lx_debug) printf

#endif	/* _KERNEL */
#endif /* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _LX_BRAND_H */
