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
 *	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
 *	  All Rights Reserved
 *
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * WARNING: This is an implementation-specific header,
 * its contents are not guaranteed. Applications
 * should include <unistd.h> and not this header.
 */

#ifndef _SYS_UNISTD_H
#define	_SYS_UNISTD_H

#include <sys/feature_tests.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* command names for confstr */

#define	_CS_PATH			65

/*
 * command names for large file configuration information
 */
/* large file compilation environment configuration */
#define	_CS_LFS_CFLAGS			68
#define	_CS_LFS_LDFLAGS			69
#define	_CS_LFS_LIBS			70
#define	_CS_LFS_LINTFLAGS		71
/* transitional large file interface configuration */
#define	_CS_LFS64_CFLAGS		72
#define	_CS_LFS64_LDFLAGS		73
#define	_CS_LFS64_LIBS			74
#define	_CS_LFS64_LINTFLAGS		75

/* UNIX 98 */
#define	_CS_XBS5_ILP32_OFF32_CFLAGS	700
#define	_CS_XBS5_ILP32_OFF32_LDFLAGS	701
#define	_CS_XBS5_ILP32_OFF32_LIBS	702
#define	_CS_XBS5_ILP32_OFF32_LINTFLAGS	703
#define	_CS_XBS5_ILP32_OFFBIG_CFLAGS	705
#define	_CS_XBS5_ILP32_OFFBIG_LDFLAGS	706
#define	_CS_XBS5_ILP32_OFFBIG_LIBS	707
#define	_CS_XBS5_ILP32_OFFBIG_LINTFLAGS	708
#define	_CS_XBS5_LP64_OFF64_CFLAGS	709
#define	_CS_XBS5_LP64_OFF64_LDFLAGS	710
#define	_CS_XBS5_LP64_OFF64_LIBS	711
#define	_CS_XBS5_LP64_OFF64_LINTFLAGS	712
#define	_CS_XBS5_LPBIG_OFFBIG_CFLAGS	713
#define	_CS_XBS5_LPBIG_OFFBIG_LDFLAGS	714
#define	_CS_XBS5_LPBIG_OFFBIG_LIBS	715
#define	_CS_XBS5_LPBIG_OFFBIG_LINTFLAGS	716

/* UNIX 03 */
#define	_CS_POSIX_V6_ILP32_OFF32_CFLAGS		800
#define	_CS_POSIX_V6_ILP32_OFF32_LDFLAGS	801
#define	_CS_POSIX_V6_ILP32_OFF32_LIBS		802
#define	_CS_POSIX_V6_ILP32_OFF32_LINTFLAGS	803
#define	_CS_POSIX_V6_ILP32_OFFBIG_CFLAGS	804
#define	_CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS	805
#define	_CS_POSIX_V6_ILP32_OFFBIG_LIBS		806
#define	_CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS	807
#define	_CS_POSIX_V6_LP64_OFF64_CFLAGS		808
#define	_CS_POSIX_V6_LP64_OFF64_LDFLAGS		809
#define	_CS_POSIX_V6_LP64_OFF64_LIBS		810
#define	_CS_POSIX_V6_LP64_OFF64_LINTFLAGS	811
#define	_CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS	812
#define	_CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS	813
#define	_CS_POSIX_V6_LPBIG_OFFBIG_LIBS		814
#define	_CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS	815
#define	_CS_POSIX_V6_WIDTH_RESTRICTED_ENVS	816

/* command names for POSIX sysconf */

/* POSIX.1 names */
#define	_SC_ARG_MAX			1
#define	_SC_CHILD_MAX			2
#define	_SC_CLK_TCK			3
#define	_SC_NGROUPS_MAX 		4
#define	_SC_OPEN_MAX			5
#define	_SC_JOB_CONTROL 		6
#define	_SC_SAVED_IDS			7
#define	_SC_VERSION			8
/* SVR4 names */
#define	_SC_PASS_MAX			9
#define	_SC_LOGNAME_MAX			10
#define	_SC_PAGESIZE			11
#define	_SC_XOPEN_VERSION		12
/* 13 reserved for SVr4-ES/MP _SC_NACLS_MAX */
#define	_SC_NPROCESSORS_CONF		14
#define	_SC_NPROCESSORS_ONLN		15
#define	_SC_STREAM_MAX			16
#define	_SC_TZNAME_MAX			17
/* POSIX.4 names */
#define	_SC_AIO_LISTIO_MAX		18
#define	_SC_AIO_MAX			19
#define	_SC_AIO_PRIO_DELTA_MAX		20
#define	_SC_ASYNCHRONOUS_IO		21
#define	_SC_DELAYTIMER_MAX		22
#define	_SC_FSYNC			23
#define	_SC_MAPPED_FILES		24
#define	_SC_MEMLOCK			25
#define	_SC_MEMLOCK_RANGE		26
#define	_SC_MEMORY_PROTECTION		27
#define	_SC_MESSAGE_PASSING		28
#define	_SC_MQ_OPEN_MAX			29
#define	_SC_MQ_PRIO_MAX			30
#define	_SC_PRIORITIZED_IO		31
#define	_SC_PRIORITY_SCHEDULING		32
#define	_SC_REALTIME_SIGNALS		33
#define	_SC_RTSIG_MAX			34
#define	_SC_SEMAPHORES			35
#define	_SC_SEM_NSEMS_MAX		36
#define	_SC_SEM_VALUE_MAX		37
#define	_SC_SHARED_MEMORY_OBJECTS	38
#define	_SC_SIGQUEUE_MAX		39
#define	_SC_SIGRT_MIN			40
#define	_SC_SIGRT_MAX			41
#define	_SC_SYNCHRONIZED_IO		42
#define	_SC_TIMERS			43
#define	_SC_TIMER_MAX			44
/* XPG4 names */
#define	_SC_2_C_BIND			45
#define	_SC_2_C_DEV    			46
#define	_SC_2_C_VERSION			47
#define	_SC_2_FORT_DEV 			48
#define	_SC_2_FORT_RUN 			49
#define	_SC_2_LOCALEDEF			50
#define	_SC_2_SW_DEV   			51
#define	_SC_2_UPE			52
#define	_SC_2_VERSION			53
#define	_SC_BC_BASE_MAX			54
#define	_SC_BC_DIM_MAX 			55
#define	_SC_BC_SCALE_MAX		56
#define	_SC_BC_STRING_MAX		57
#define	_SC_COLL_WEIGHTS_MAX		58
#define	_SC_EXPR_NEST_MAX		59
#define	_SC_LINE_MAX 			60
#define	_SC_RE_DUP_MAX			61
#define	_SC_XOPEN_CRYPT			62
#define	_SC_XOPEN_ENH_I18N		63
#define	_SC_XOPEN_SHM			64

/* additional XSH4/XCU4 command names for sysconf */
#define	_SC_2_CHAR_TERM			66
#define	_SC_XOPEN_XCU_VERSION		67

/* additional XPG4v2 (UNIX 95) command names */
#define	_SC_ATEXIT_MAX			76
#define	_SC_IOV_MAX			77
#define	_SC_XOPEN_UNIX			78
#define	_SC_PAGE_SIZE			_SC_PAGESIZE

/* defined for XTI (XNS Issue 5) */
#ifndef _SC_T_IOV_MAX
#define	_SC_T_IOV_MAX			79 /* Must be same in <xti.h> */
#endif					   /* T_IOV_MAX must be <= IOV_MAX */

#define	_SC_PHYS_PAGES			500
#define	_SC_AVPHYS_PAGES		501

/*
 * Hardware specific items
 * Note that not all items are supported on all architectures
 */
#define	_SC_COHER_BLKSZ		503	/* Coherence block size */
#define	_SC_SPLIT_CACHE		504	/* != 0 iff a split cache */
#define	_SC_ICACHE_SZ		505	/* Instruction cache size (bytes) */
#define	_SC_DCACHE_SZ		506	/* Data cache size (bytes) */
#define	_SC_ICACHE_LINESZ	507	/* Instruction cache line size */
#define	_SC_DCACHE_LINESZ	508	/* Data cache line size */
#define	_SC_ICACHE_BLKSZ	509	/* Block size invalidated for icache */
#define	_SC_DCACHE_BLKSZ	510	/* Block size for dcache */
#define	_SC_DCACHE_TBLKSZ	511	/* Block size for dcache prefetch */
#define	_SC_ICACHE_ASSOC	512	/* Icache associativity 1, 2, 3 etc */
#define	_SC_DCACHE_ASSOC	513	/* Dcache associativity 1, 2, 3 etc */

#define	_SC_MAXPID		514	/* maximum pid value */
#define	_SC_STACK_PROT		515	/* default stack protection */
#define	_SC_NPROCESSORS_MAX	516	/* maximum # of processors */
#define	_SC_CPUID_MAX		517	/* maximum CPU id */
#define	_SC_EPHID_MAX		518	/* maximum ephemeral id */

/*
 * POSIX.1c (pthreads) names. These values are defined above
 * the sub-500 range. See psarc case 1995/257.
 */
#define	_SC_THREAD_DESTRUCTOR_ITERATIONS 568
#define	_SC_GETGR_R_SIZE_MAX		569
#define	_SC_GETPW_R_SIZE_MAX		570
#define	_SC_LOGIN_NAME_MAX		571
#define	_SC_THREAD_KEYS_MAX		572
#define	_SC_THREAD_STACK_MIN		573
#define	_SC_THREAD_THREADS_MAX		574
#define	_SC_TTY_NAME_MAX		575
#define	_SC_THREADS			576
#define	_SC_THREAD_ATTR_STACKADDR	577
#define	_SC_THREAD_ATTR_STACKSIZE	578
#define	_SC_THREAD_PRIORITY_SCHEDULING	579
#define	_SC_THREAD_PRIO_INHERIT		580
#define	_SC_THREAD_PRIO_PROTECT		581
#define	_SC_THREAD_PROCESS_SHARED	582
#define	_SC_THREAD_SAFE_FUNCTIONS	583

/* UNIX 98 */
#define	_SC_XOPEN_LEGACY		717
#define	_SC_XOPEN_REALTIME		718
#define	_SC_XOPEN_REALTIME_THREADS	719
#define	_SC_XBS5_ILP32_OFF32		720
#define	_SC_XBS5_ILP32_OFFBIG		721
#define	_SC_XBS5_LP64_OFF64		722
#define	_SC_XBS5_LPBIG_OFFBIG		723

/* UNIX 03 */
#define	_SC_2_PBS			724
#define	_SC_2_PBS_ACCOUNTING		725
#define	_SC_2_PBS_CHECKPOINT		726
#define	_SC_2_PBS_LOCATE		728
#define	_SC_2_PBS_MESSAGE		729
#define	_SC_2_PBS_TRACK			730
#define	_SC_ADVISORY_INFO		731
#define	_SC_BARRIERS			732
#define	_SC_CLOCK_SELECTION		733
#define	_SC_CPUTIME			734
#define	_SC_HOST_NAME_MAX		735
#define	_SC_MONOTONIC_CLOCK		736
#define	_SC_READER_WRITER_LOCKS		737
#define	_SC_REGEXP			738
#define	_SC_SHELL			739
#define	_SC_SPAWN			740
#define	_SC_SPIN_LOCKS			741
#define	_SC_SPORADIC_SERVER		742
#define	_SC_SS_REPL_MAX			743
#define	_SC_SYMLOOP_MAX			744
#define	_SC_THREAD_CPUTIME		745
#define	_SC_THREAD_SPORADIC_SERVER	746
#define	_SC_TIMEOUTS			747
#define	_SC_TRACE			748
#define	_SC_TRACE_EVENT_FILTER		749
#define	_SC_TRACE_EVENT_NAME_MAX	750
#define	_SC_TRACE_INHERIT		751
#define	_SC_TRACE_LOG			752
#define	_SC_TRACE_NAME_MAX		753
#define	_SC_TRACE_SYS_MAX		754
#define	_SC_TRACE_USER_EVENT_MAX	755
#define	_SC_TYPED_MEMORY_OBJECTS	756
#define	_SC_V6_ILP32_OFF32		757
#define	_SC_V6_ILP32_OFFBIG		758
#define	_SC_V6_LP64_OFF64		759
#define	_SC_V6_LPBIG_OFFBIG		760
#define	_SC_XOPEN_STREAMS		761
#define	_SC_IPV6			762
#define	_SC_RAW_SOCKETS			763

/* command names for POSIX pathconf */

/* POSIX.1 names */
#define	_PC_LINK_MAX		1
#define	_PC_MAX_CANON		2
#define	_PC_MAX_INPUT		3
#define	_PC_NAME_MAX		4
#define	_PC_PATH_MAX		5
#define	_PC_PIPE_BUF		6
#define	_PC_NO_TRUNC		7
#define	_PC_VDISABLE		8
#define	_PC_CHOWN_RESTRICTED	9
/* POSIX.4 names */
#define	_PC_ASYNC_IO		10
#define	_PC_PRIO_IO		11
#define	_PC_SYNC_IO		12
/* UNIX 03 names */
#define	_PC_ALLOC_SIZE_MIN	13
#define	_PC_REC_INCR_XFER_SIZE	14
#define	_PC_REC_MAX_XFER_SIZE	15
#define	_PC_REC_MIN_XFER_SIZE	16
#define	_PC_REC_XFER_ALIGN	17
#define	_PC_SYMLINK_MAX		18
#define	_PC_2_SYMLINKS		19
#define	_PC_ACL_ENABLED		20
#define	_PC_MIN_HOLE_SIZE	21
#define	_PC_CASE_BEHAVIOR	22
#define	_PC_SATTR_ENABLED	23
#define	_PC_SATTR_EXISTS	24
#define	_PC_ACCESS_FILTERING	25
/* UNIX 08 names */
#define	_PC_TIMESTAMP_RESOLUTION 26

/*
 * Large File Summit names
 *
 * This value matches the MIPS ABI choice, but leaves a large gap in the
 * value space.
 */
#define	_PC_FILESIZEBITS	67

/*
 * Extended attributes
 */
#define	_PC_XATTR_ENABLED	100
#define	_PC_XATTR_EXISTS	101

/*
 * If you add a _PC define above 101, you must change _PC_LAST (and truss).
 */
#define	_PC_LAST		101

/*
 * Case sensitivity values (related to _PC_CASE_BEHAVIOR)
 */
#define	_CASE_SENSITIVE		0x1
#define	_CASE_INSENSITIVE	0x2

/*
 * The value of 0 is returned when
 * ACL's are not supported
 */
#define	_ACL_ACLENT_ENABLED	0x1
#define	_ACL_ACE_ENABLED	0x2

#ifndef	_POSIX_VERSION
#ifdef	_XPG6
#define	_POSIX_VERSION		200112L	/* Supports IEEE Std 1003.1-2001 */
#else
#define	_POSIX_VERSION		199506L /* Supports POSIX-1c DIS */
#endif
#endif /* _POSIX_VERSION */

#ifndef	_POSIX2_VERSION
#ifdef	_XPG6
#define	_POSIX2_VERSION		200112L	/* Supports IEEE Std 1003.1-2001 */
#else
#define	_POSIX2_VERSION		199209L /* Supports ISO POSIX-2 DIS */
#endif
#endif /* _POSIX2_VERSION */

/*
 * Marked LEGACY in SUSv2 and removed in SUSv3. Though SUSv3 applications
 * should not rely on this value, it has been aligned with the current
 * standard to avoid confusion if used.
 */
#ifndef	_POSIX2_C_VERSION
#ifdef	_XPG6
#define	_POSIX2_C_VERSION	200112L	/* Supports IEEE Std 1003.1-2001 */
#else
#define	_POSIX2_C_VERSION	199209L	/* Supports ISO POSIX-2 DIS */
#endif
#endif /* _POSIX2_C_VERSION */

#define	_XOPEN_XPG3			/* Supports XPG, Issue 3 */
#define	_XOPEN_XPG4			/* Supports XPG, Issue 4 */
#define	_XOPEN_UNIX		0	/* Supports X/Open System Interfaces */

#ifndef	_XOPEN_XCU_VERSION
#define	_XOPEN_XCU_VERSION	4	/* Supports XCU4 */
#endif

#define	_XOPEN_REALTIME		1	/* Supports Realtime */
#define	_XOPEN_ENH_I18N		1	/* Supports Enhanced International */
#define	_XOPEN_SHM		1	/* Supports Shared Memory Feature */
#define	_POSIX2_CHAR_TERM	1	/* Supports at least 1 terminal type */

#ifdef _XPG6
#define	_POSIX2_C_BIND	  200112L	/* Supports C Language Bindings */
#define	_POSIX2_C_DEV	  200112L	/* Supports C language dev utility */
#define	_POSIX2_FORT_RUN  200112L	/* Supports FORTRAN runtime */
#define	_POSIX2_LOCALEDEF 200112L	/* Supports creation of locales */
#define	_POSIX2_SW_DEV	  200112L	/* Supports S/W Development Utility */
#define	_POSIX2_UPE	  200112L 	/* Supports User Portability Utility */
#else
#define	_POSIX2_C_BIND		1	/* Supports C Language Bindings */
#define	_POSIX2_C_DEV		1	/* Supports C language dev utility */
#define	_POSIX2_FORT_RUN	1	/* Supports FORTRAN runtime */
#define	_POSIX2_LOCALEDEF	1	/* Supports creation of locales */
#define	_POSIX2_SW_DEV		1	/* Supports S/W Development Utility */
#define	_POSIX2_UPE		1 	/* Supports User Portability Utility */
#endif /* _XPG6 */

/* UNIX 03 names */
#define	_POSIX_REGEXP		1	/* Supports POSIX Regular Expressions */
#define	_POSIX_SHELL		1	/* Supports POSIX shell */
#define	_XOPEN_STREAMS		1	/* Supports XSI Streams Option Group */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_UNISTD_H */
