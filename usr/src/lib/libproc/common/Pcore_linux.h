/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.
 */

#ifndef _PCORE_LINUX_H
#define	_PCORE_LINUX_H

/*
 * Note that these structures can end up in both a 32-bit and 64-bit libproc.
 * Therefore, one should generally avoid using types whose size change between
 * ILP32 and LP64 and instead use the correct fixed width type. eg. long should
 * be int32_t and int64_t as appropriate to whether it's a 32-bit or 64-bit
 * structure.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Process Information */
typedef struct lx_prpsinfo32 {
	uint8_t		pr_state;	/* Numeric process state */
	int8_t		pr_sname;	/* Char for pr_state */
	uint8_t		pr_zomb;	/* Zombie */
	int8_t		pr_nice;	/* Nice value */
	uint32_t	pr_flag;	/* Flags */
	uint16_t	pr_uid;		/* User ID */
	uint16_t	pr_gid;		/* Group ID */
	int32_t		pr_pid;		/* Process ID */
	int32_t		pr_ppid;	/* Parent's process ID */
	int32_t		pr_pgrp;	/* Group ID */
	int32_t		pr_sid;		/* Session ID */
	char		pr_fname[16];	/* Filename of executable */
	char		pr_psargs[80];	/* Initial part of arg list */
} lx_prpsinfo32_t;

typedef struct lx_prpsinfo64 {
	uint8_t		pr_state;	/* Numeric process state */
	int8_t		pr_sname;	/* Char for pr_state */
	uint8_t		pr_zomb;	/* Zombie */
	int8_t		pr_nice;	/* Nice value */
	uint64_t	pr_flag;	/* Flags */
	uint32_t	pr_uid;		/* User ID */
	uint32_t	pr_gid;		/* Group ID */
	int32_t		pr_pid;		/* Process ID */
	int32_t		pr_ppid;	/* Parent's process ID */
	int32_t		pr_pgrp;	/* Group ID */
	int32_t		pr_sid;		/* Session ID */
	char		pr_fname[16];	/* Filename of executable */
	char		pr_psargs[80];	/* Initial part of arg list */
} lx_prpsinfo64_t;

typedef struct lx_amd64_regs {
	uint64_t	lxr_r15;
	uint64_t	lxr_r14;
	uint64_t	lxr_r13;
	uint64_t	lxr_r12;
	uint64_t	lxr_rbp;
	uint64_t	lxr_rbx;
	uint64_t	lxr_r11;
	uint64_t	lxr_r10;
	uint64_t	lxr_r9;
	uint64_t	lxr_r8;
	uint64_t	lxr_rax;
	uint64_t	lxr_rcx;
	uint64_t	lxr_rdx;
	uint64_t	lxr_rsi;
	uint64_t	lxr_rdi;
	uint64_t	lxr_orig_rax;
	uint64_t	lxr_rip;
	uint64_t	lxr_cs;
	uint64_t	lxr_eflags;
	uint64_t	lxr_rsp;
	uint64_t	lxr_ss;
	uint64_t	lxr_fs_base;
	uint64_t	lxr_gs_base;
	uint64_t	lxr_ds;
	uint64_t	lxr_es;
	uint64_t	lxr_fs;
	uint64_t	lxr_gs;
} lx_amd64_regs_t;

typedef struct lx_ia32_regs {
	uint32_t	lxr_bx;
	uint32_t	lxr_cx;
	uint32_t	lxr_dx;
	uint32_t	lxr_si;
	uint32_t	lxr_di;
	uint32_t	lxr_bp;
	uint32_t	lxr_ax;
	uint32_t	lxr_ds;
	uint32_t	lxr_es;
	uint32_t	lxr_fs;
	uint32_t	lxr_gs;
	uint32_t	lxr_orig_ax;
	uint32_t	lxr_ip;
	uint32_t	lxr_cs;
	uint32_t	lxr_flags;
	uint32_t	lxr_sp;
	uint32_t	lxr_ss;
} lx_ia32_regs_t;

typedef struct lx_elf_siginfo {
	int32_t	si_signo;	/* Signal number */
	int32_t si_code;	/* Extra code */
	int32_t si_errno;	/* Errno */
} lx_elf_siginfo_t;

typedef struct lx_elf_timeval32 {
	int32_t tv_sec;		/* Seconds */
	int32_t tv_usec;	/* Microseconds */
} lx_elf_timeval32_t;

typedef struct lx_elf_timeval64 {
	int64_t tv_sec;		/* Seconds */
	int64_t tv_usec;	/* Microseconds */
} lx_elf_timeval64_t;

/* Thread Information */
typedef struct lx_prstatus32 {
	lx_elf_siginfo_t	pr_info;	/* Singal Info */
	uint16_t		pr_cursig;	/* Current signal */
	uint32_t		pr_sigpend;	/* Set of pending signals */
	uint32_t		pr_sighold;	/* Set of held signals */
	int32_t			pr_pid;		/* Process ID */
	int32_t			pr_ppid;	/* Parent's process ID */
	int32_t			pr_pgrp;	/* Group ID */
	int32_t			pr_sid;		/* Session ID */
	lx_elf_timeval32_t	pr_utime;	/* User time */
	lx_elf_timeval32_t	pr_stime;	/* System time */
	lx_elf_timeval32_t	pr_cutime;	/* Cumulative user time */
	lx_elf_timeval32_t	pr_cstime;	/* Cumulative system time */
	lx_ia32_regs_t		pr_reg;		/* CPU registers */
	uint32_t		pr_fpvalid;	/* True if we have fp state */
} lx_prstatus32_t;

typedef struct lx_prstatus64 {
	lx_elf_siginfo_t	pr_info;	/* Singal Info */
	uint16_t		pr_cursig;	/* Current signal */
	uint64_t		pr_sigpend;	/* Set of pending signals */
	uint64_t		pr_sighold;	/* Set of held signals */
	int32_t			pr_pid;		/* Process ID */
	int32_t			pr_ppid;	/* Parent's process ID */
	int32_t			pr_pgrp;	/* Group ID */
	int32_t			pr_sid;		/* Session ID */
	lx_elf_timeval64_t	pr_utime;	/* User time */
	lx_elf_timeval64_t	pr_stime;	/* System time */
	lx_elf_timeval64_t	pr_cutime;	/* Cumulative user time */
	lx_elf_timeval64_t	pr_cstime;	/* Cumulative system time */
	lx_amd64_regs_t		pr_reg;		/* CPU registers */
	uint32_t		pr_fpvalid;	/* True if we have fp state */
} lx_prstatus64_t;

#define	LTIME_TO_TIMESPEC(dst, src) \
	(dst).tv_sec = (src).tv_sec; \
	(dst).tv_nsec = (src).tv_usec * 1000;

#ifdef __cplusplus
}
#endif

#endif /* _PCORE_LINUX_H */
