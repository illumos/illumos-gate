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
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
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
#define	LX_UNAME_VERSION	"BrandZ fake linux"
#define	LX_UNAME_MACHINE	"i686"

#define	LX_LINKER_NAME "ld-linux.so.2"
#define	LX_LINKER	"/lib/" LX_LINKER_NAME
#define	LX_LIBC_NAME	"libc.so.6"
#define	LIB_PATH	"/native/usr/lib/"
#define	LX_LIB		"lx_brand.so.1"
#define	LX_LIB_PATH	LIB_PATH LX_LIB

#define	LX_NSYSCALLS_2_4	270
#define	LX_NSYSCALLS_2_6	352
#define	LX_NSYSCALLS	LX_NSYSCALLS_2_6

/*
 * brand(2) subcommands
 *
 * Everything >= 128 is a brand-specific subcommand.
 * > 192 is reserved for in-kernel system calls, although most of that space is
 * unused.
 */
#define	B_LPID_TO_SPAIR		128
#define	B_SYSENTRY		129
#define	B_SYSRETURN		130
#define	B_PTRACE_SYSCALL	131
#define	B_SET_AFFINITY_MASK	132
#define	B_GET_AFFINITY_MASK	133
#define	B_PTRACE_EXT_OPTS	134
#define	B_PTRACE_STOP_FOR_OPT	135
#define	B_UNSUPPORTED		136

#define	B_EMULATE_SYSCALL	192

/* B_PTRACE_EXT_OPTS subcommands */
#define	 B_PTRACE_EXT_OPTS_SET	1
#define	 B_PTRACE_EXT_OPTS_GET	2
#define	 B_PTRACE_EXT_OPTS_EVT	3

/*
 * Support for Linux PTRACE_SETOPTIONS handling.
 */
#define	LX_PTRACE_O_TRACESYSGOOD	0x0001
#define	LX_PTRACE_O_TRACEFORK		0x0002
#define	LX_PTRACE_O_TRACEVFORK		0x0004
#define	LX_PTRACE_O_TRACECLONE		0x0008
#define	LX_PTRACE_O_TRACEEXEC		0x0010
#define	LX_PTRACE_O_TRACEVFORKDONE	0x0020
#define	LX_PTRACE_O_TRACEEXIT		0x0040
#define	LX_PTRACE_O_TRACESECCOMP	0x0080

/* siginfo si_status for traced events */
#define	LX_PTRACE_EVENT_FORK		0x100
#define	LX_PTRACE_EVENT_VFORK		0x200
#define	LX_PTRACE_EVENT_CLONE		0x300
#define	LX_PTRACE_EVENT_EXEC		0x400
#define	LX_PTRACE_EVENT_VFORK_DONE	0x500
#define	LX_PTRACE_EVENT_EXIT		0x600
#define	LX_PTRACE_EVENT_SECCOMP		0x700

#define	LX_VERSION_1		1
#define	LX_VERSION		LX_VERSION_1

#define	LX_ATTR_RESTART_INIT	ZONE_ATTR_BRAND_ATTRS
#define	LX_KERN_VERSION_NUM	(ZONE_ATTR_BRAND_ATTRS + 1)

/*
 * Aux vector containing phdr of Linux executable and ehdr of interpreter
 * (if any), both of which are used by lx_librtld_db to ascertain r_debug.
 */
#define	AT_SUN_BRAND_LX_PHDR	AT_SUN_BRAND_AUX1
#define	AT_SUN_BRAND_LX_INTERP	AT_SUN_BRAND_AUX2

/* Aux vector containing hz value */
#define	AT_CLKTCK	17

#ifndef	_ASM

typedef struct lx_brand_registration {
	uint_t lxbr_version;		/* version number */
	void *lxbr_handler;		/* base address of handler */
	void *lxbr_tracehandler;	/* base address of trace handler */
	void *lxbr_traceflag;		/* address of trace flag */
} lx_brand_registration_t;

#ifdef	_SYSCALL32
typedef struct lx_brand_registration32 {
	uint32_t lxbr_version;		/* version number */
	caddr32_t lxbr_handler;		/* base address of handler */
	caddr32_t lxbr_tracehandler;	/* base address of trace handler */
	caddr32_t lxbr_traceflag;	/* address of trace flag */
} lx_brand_registration32_t;
#endif

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
typedef struct lx_elf_data {
	int	ed_phdr;
	int	ed_phent;
	int	ed_phnum;
	int	ed_entry;
	int	ed_base;
	int	ed_ldentry;
} lx_elf_data_t;

#ifdef	_KERNEL

typedef struct lx_proc_data {
	uintptr_t l_handler;	/* address of user-space handler */
	uintptr_t l_tracehandler; /* address of user-space traced handler */
	uintptr_t l_traceflag;	/* address of 32-bit tracing flag */
	void (*l_sigrestorer[MAXSIG])(void); /* array of sigrestorer fns */
	pid_t l_ppid;		/* pid of originating parent proc */
	uint64_t l_ptrace;	/* process being observed with ptrace */
	uint_t l_ptrace_opts;	/* process's extended ptrace options */
	uint_t l_ptrace_event;	/* extended ptrace option trap event */
	lx_elf_data_t l_elf_data; /* ELF data for linux executable */
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

/*
 * lx-specific data in the klwp_t
 */
typedef struct lx_lwp_data {
	uint_t	br_lwp_flags;		/* misc. flags */
	klwp_t	*br_lwp;		/* back pointer to container lwp */
	int	br_signal;		/* signal to send to parent when */
					/* clone()'ed child terminates */
	int	br_exitwhy;		/* reason for thread (process) exit */
	int	br_exitwhat;		/* exit code / killing signal */
	lx_affmask_t br_affinitymask;	/* bitmask of CPU sched affinities */
	struct user_desc br_tls[LX_TLSNUM];
			/* descriptors used by libc for TLS */
	pid_t	br_pid;			/* converted pid for this thread */
	pid_t	br_tgid;		/* thread group ID for this thread */
	pid_t	br_ppid;		/* parent pid for this thread */
	id_t	br_ptid;		/* parent tid for this thread */
	void	*br_clear_ctidp;	/* clone thread id ptr */
	void	*br_set_ctidp;		/* clone thread id ptr */

	/*
	 * The following struct is used by lx_clone()
	 * to pass info into fork()
	 */
	void	 *br_clone_args;

	uint_t	br_ptrace;		/* ptrace is active for this LWP */
} lx_lwp_data_t;

/* brand specific data */
typedef struct lx_zone_data {
	char lxzd_kernel_version[LX_VERS_MAX];
	int lxzd_max_syscall;
} lx_zone_data_t;

#define	BR_CPU_BOUND	0x0001

#define	ttolxlwp(t)	((struct lx_lwp_data *)ttolwpbrand(t))
#define	lwptolxlwp(l)	((struct lx_lwp_data *)lwptolwpbrand(l))
#define	ttolxproc(t)	((struct lx_proc_data *)(t)->t_procp->p_brand_data)

void	lx_brand_int80_callback(void);
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
