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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2016 Joyent, Inc.
 */

#ifndef _SYS_TYPES_H
#define	_SYS_TYPES_H

#include <sys/feature_tests.h>
#include <sys/isa_defs.h>

/*
 * Machine dependent definitions moved to <sys/machtypes.h>.
 */
#include <sys/machtypes.h>

/*
 * Include fixed width type declarations proposed by the ISO/JTC1/SC22/WG14 C
 * committee's working draft for the revision of the current ISO C standard,
 * ISO/IEC 9899:1990 Programming language - C.  These are not currently
 * required by any standard but constitute a useful, general purpose set
 * of type definitions which is namespace clean with respect to all standards.
 */
#ifdef	_KERNEL
#include <sys/inttypes.h>
#else	/* _KERNEL */
#include <sys/int_types.h>
#endif	/* _KERNEL */

#if defined(_KERNEL) || defined(_SYSCALL32)
#include <sys/types32.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Strictly conforming ANSI C environments prior to the 1999
 * revision of the C Standard (ISO/IEC 9899:1999) do not have
 * the long long data type.
 */
#if defined(_LONGLONG_TYPE)
typedef	long long		longlong_t;
typedef	unsigned long long	u_longlong_t;
#else
/* used to reserve space and generate alignment */
typedef union {
	double	_d;
	int32_t	_l[2];
} longlong_t;
typedef union {
	double		_d;
	uint32_t	_l[2];
} u_longlong_t;
#endif	/* defined(_LONGLONG_TYPE) */

/*
 * These types (t_{u}scalar_t) exist because the XTI/TPI/DLPI standards had
 * to use them instead of int32_t and uint32_t because DEC had
 * shipped 64-bit wide.
 */
#if defined(_LP64) || defined(_I32LPx)
typedef int32_t		t_scalar_t;
typedef uint32_t	t_uscalar_t;
#else
typedef long		t_scalar_t;	/* historical versions */
typedef unsigned long	t_uscalar_t;
#endif	/* defined(_LP64) || defined(_I32LPx) */

/*
 * POSIX Extensions
 */
typedef	unsigned char	uchar_t;
typedef	unsigned short	ushort_t;
typedef	unsigned int	uint_t;
typedef	unsigned long	ulong_t;

typedef	char		*caddr_t;	/* ?<core address> type */
typedef	long		daddr_t;	/* <disk address> type */
typedef	short		cnt_t;		/* ?<count> type */

#if !defined(_PTRDIFF_T) || __cplusplus >= 199711L
#define	_PTRDIFF_T
#if defined(_LP64) || defined(_I32LPx)
typedef	long	ptrdiff_t;		/* pointer difference */
#else
typedef	int	ptrdiff_t;		/* (historical version) */
#endif
#endif

/*
 * VM-related types
 */
typedef	ulong_t		pfn_t;		/* page frame number */
typedef	ulong_t		pgcnt_t;	/* number of pages */
typedef	long		spgcnt_t;	/* signed number of pages */

typedef	uchar_t		use_t;		/* use count for swap.  */
typedef	short		sysid_t;
typedef	short		index_t;
typedef void		*timeout_id_t;	/* opaque handle from timeout(9F) */
typedef void		*bufcall_id_t;	/* opaque handle from bufcall(9F) */

/*
 * The size of off_t and related types depends on the setting of
 * _FILE_OFFSET_BITS.  (Note that other system headers define other types
 * related to those defined here.)
 *
 * If _LARGEFILE64_SOURCE is defined, variants of these types that are
 * explicitly 64 bits wide become available.
 */
#ifndef _OFF_T
#define	_OFF_T

#if defined(_LP64) || _FILE_OFFSET_BITS == 32
typedef long		off_t;		/* offsets within files */
#elif _FILE_OFFSET_BITS == 64
typedef longlong_t	off_t;		/* offsets within files */
#endif

#if defined(_LARGEFILE64_SOURCE)
#ifdef _LP64
typedef	off_t		off64_t;	/* offsets within files */
#else
typedef longlong_t	off64_t;	/* offsets within files */
#endif
#endif	/* _LARGEFILE64_SOURCE */

#endif /* _OFF_T */

#if defined(_LP64) || _FILE_OFFSET_BITS == 32
typedef ulong_t		ino_t;		/* expanded inode type	*/
typedef long		blkcnt_t;	/* count of file blocks */
typedef ulong_t		fsblkcnt_t;	/* count of file system blocks */
typedef ulong_t		fsfilcnt_t;	/* count of files */
#elif _FILE_OFFSET_BITS == 64
typedef u_longlong_t	ino_t;		/* expanded inode type	*/
typedef longlong_t	blkcnt_t;	/* count of file blocks */
typedef u_longlong_t	fsblkcnt_t;	/* count of file system blocks */
typedef u_longlong_t	fsfilcnt_t;	/* count of files */
#endif

#if defined(_LARGEFILE64_SOURCE)
#ifdef _LP64
typedef	ino_t		ino64_t;	/* expanded inode type */
typedef	blkcnt_t	blkcnt64_t;	/* count of file blocks */
typedef	fsblkcnt_t	fsblkcnt64_t;	/* count of file system blocks */
typedef	fsfilcnt_t	fsfilcnt64_t;	/* count of files */
#else
typedef u_longlong_t	ino64_t;	/* expanded inode type	*/
typedef longlong_t	blkcnt64_t;	/* count of file blocks */
typedef u_longlong_t	fsblkcnt64_t;	/* count of file system blocks */
typedef u_longlong_t	fsfilcnt64_t;	/* count of files */
#endif
#endif	/* _LARGEFILE64_SOURCE */

#ifdef _LP64
typedef	int		blksize_t;	/* used for block sizes */
#else
typedef	long		blksize_t;	/* used for block sizes */
#endif

#if defined(__XOPEN_OR_POSIX)
typedef enum { _B_FALSE, _B_TRUE } boolean_t;
#else
typedef enum { B_FALSE, B_TRUE } boolean_t;
#ifdef _KERNEL
#define	VALID_BOOLEAN(x)	(((x) == B_FALSE) || ((x) == B_TRUE))
#define	VOID2BOOLEAN(x)		(((uintptr_t)(x) == 0) ? B_FALSE : B_TRUE)
#endif /* _KERNEL */
#endif /* defined(__XOPEN_OR_POSIX) */

#ifdef _KERNEL
#define	BOOLEAN2VOID(x)		((x) ? 1 : 0)
#endif /* _KERNEL */

/*
 * The {u,}pad64_t types can be used in structures such that those structures
 * may be accessed by code produced by compilation environments which don't
 * support a 64 bit integral datatype.  The intention is not to allow
 * use of these fields in such environments, but to maintain the alignment
 * and offsets of the structure.
 *
 * Similar comments for {u,}pad128_t.
 *
 * Note that these types do NOT generate any stronger alignment constraints
 * than those available in the underlying ABI.  See <sys/isa_defs.h>
 */
#if defined(_INT64_TYPE)
typedef int64_t		pad64_t;
typedef	uint64_t	upad64_t;
#else
typedef union {
	double   _d;
	int32_t  _l[2];
} pad64_t;

typedef union {
	double   _d;
	uint32_t _l[2];
} upad64_t;
#endif

typedef union {
	long double	_q;
	int32_t		_l[4];
} pad128_t;

typedef union {
	long double	_q;
	uint32_t	_l[4];
} upad128_t;

typedef	longlong_t	offset_t;
typedef	u_longlong_t	u_offset_t;
typedef u_longlong_t	len_t;
typedef	u_longlong_t	diskaddr_t;
#if (defined(_KERNEL) || defined(_KMEMUSER) || defined(_BOOT))
typedef	uint64_t	paddr_t;
#endif

/*
 * Definitions remaining from previous partial support for 64-bit file
 * offsets.  This partial support for devices greater than 2gb requires
 * compiler support for long long.
 */
#ifdef _LONG_LONG_LTOH
typedef union {
	offset_t	_f;	/* Full 64 bit offset value */
	struct {
		int32_t	_l;	/* lower 32 bits of offset value */
		int32_t	_u;	/* upper 32 bits of offset value */
	} _p;
} lloff_t;
#endif

#ifdef _LONG_LONG_HTOL
typedef union {
	offset_t	_f;	/* Full 64 bit offset value */
	struct {
		int32_t	_u;	/* upper 32 bits of offset value */
		int32_t	_l;	/* lower 32 bits of offset value */
	} _p;
} lloff_t;
#endif

#ifdef _LONG_LONG_LTOH
typedef union {
	longlong_t	_f;	/* Full 64 bit disk address value */
	struct {
		int32_t	_l;	/* lower 32 bits of disk address value */
		int32_t	_u;	/* upper 32 bits of disk address value */
	} _p;
} lldaddr_t;
#endif

#ifdef _LONG_LONG_HTOL
typedef union {
	longlong_t	_f;	/* Full 64 bit disk address value */
	struct {
		int32_t	_u;	/* upper 32 bits of disk address value */
		int32_t	_l;	/* lower 32 bits of disk address value */
	} _p;
} lldaddr_t;
#endif

typedef uint_t k_fltset_t;	/* kernel fault set type */

/*
 * The following type is for various kinds of identifiers.  The
 * actual type must be the same for all since some system calls
 * (such as sigsend) take arguments that may be any of these
 * types.  The enumeration type idtype_t defined in sys/procset.h
 * is used to indicate what type of id is being specified --
 * a process id, process group id, session id, scheduling class id,
 * user id, group id, project id, task id or zone id.
 */
#if defined(_LP64) || defined(_I32LPx)
typedef int		id_t;
#else
typedef	long		id_t;		/* (historical version) */
#endif

typedef id_t		lgrp_id_t;	/* lgroup ID */

/*
 * Type useconds_t is an unsigned integral type capable of storing
 * values at least in the range of zero to 1,000,000.
 */
typedef uint_t		useconds_t;	/* Time, in microseconds */

#ifndef	_SUSECONDS_T
#define	_SUSECONDS_T
typedef long	suseconds_t;	/* signed # of microseconds */
#endif	/* _SUSECONDS_T */

/*
 * Typedefs for dev_t components.
 */
#if defined(_LP64) || defined(_I32LPx)
typedef uint_t	major_t;	/* major part of device number */
typedef uint_t	minor_t;	/* minor part of device number */
#else
typedef ulong_t	major_t;	/* (historical version) */
typedef ulong_t	minor_t;	/* (historical version) */
#endif

/*
 * The data type of a thread priority.
 */
typedef short	pri_t;

/*
 * The data type for a CPU flags field.  (Can be extended to larger unsigned
 * types, if needed, limited by ability to update atomically.)
 */
typedef ushort_t	cpu_flag_t;

/*
 * For compatibility reasons the following typedefs (prefixed o_)
 * can't grow regardless of the EFT definition. Although,
 * applications should not explicitly use these typedefs
 * they may be included via a system header definition.
 * WARNING: These typedefs may be removed in a future
 * release.
 *		ex. the definitions in s5inode.h (now obsoleted)
 *			remained small to preserve compatibility
 *			in the S5 file system type.
 */
typedef	ushort_t o_mode_t;		/* old file attribute type */
typedef short	o_dev_t;		/* old device type	*/
typedef	ushort_t o_uid_t;		/* old UID type		*/
typedef	o_uid_t	o_gid_t;		/* old GID type		*/
typedef	short	o_nlink_t;		/* old file link type	*/
typedef short	o_pid_t;		/* old process id type	*/
typedef ushort_t o_ino_t;		/* old inode type	*/


/*
 * POSIX and XOPEN Declarations
 */
typedef	int	key_t;			/* IPC key type		*/
#if defined(_LP64) || defined(_I32LPx)
typedef	uint_t	mode_t;			/* file attribute type	*/
#else
typedef	ulong_t	mode_t;			/* (historical version) */
#endif

#ifndef	_UID_T
#define	_UID_T
typedef	unsigned int uid_t;		/* UID type		*/
#endif	/* _UID_T */

typedef	uid_t	gid_t;			/* GID type		*/

typedef uint32_t	datalink_id_t;
typedef	uint32_t	vrid_t;

typedef id_t    taskid_t;
typedef id_t    projid_t;
typedef	id_t	poolid_t;
typedef id_t	zoneid_t;
typedef id_t	ctid_t;

/*
 * POSIX definitions are same as defined in thread.h and synch.h.
 * Any changes made to here should be reflected in corresponding
 * files as described in comments.
 */
typedef	uint_t	pthread_t;	/* = thread_t in thread.h */
typedef	uint_t	pthread_key_t;	/* = thread_key_t in thread.h */

/* "Magic numbers" tagging synchronization object types */
#define	_MUTEX_MAGIC	0x4d58		/* "MX" */
#define	_SEMA_MAGIC	0x534d		/* "SM" */
#define	_COND_MAGIC	0x4356		/* "CV" */
#define	_RWL_MAGIC	0x5257		/* "RW" */

typedef	struct _pthread_mutex {		/* = mutex_t in synch.h */
	struct {
		uint16_t	__pthread_mutex_flag1;
		uint8_t		__pthread_mutex_flag2;
		uint8_t		__pthread_mutex_ceiling;
		uint16_t 	__pthread_mutex_type;
		uint16_t 	__pthread_mutex_magic;
	} __pthread_mutex_flags;
	union {
		struct {
			uint8_t	__pthread_mutex_pad[8];
		} __pthread_mutex_lock64;
		struct {
			uint32_t __pthread_ownerpid;
			uint32_t __pthread_lockword;
		} __pthread_mutex_lock32;
		upad64_t __pthread_mutex_owner64;
	} __pthread_mutex_lock;
	upad64_t __pthread_mutex_data;
} pthread_mutex_t;

typedef	struct _pthread_cond {		/* = cond_t in synch.h */
	struct {
		uint8_t		__pthread_cond_flag[4];
		uint16_t 	__pthread_cond_type;
		uint16_t 	__pthread_cond_magic;
	} __pthread_cond_flags;
	upad64_t __pthread_cond_data;
} pthread_cond_t;

/*
 * UNIX 98 Extension
 */
typedef	struct _pthread_rwlock {	/* = rwlock_t in synch.h */
	int32_t		__pthread_rwlock_readers;
	uint16_t	__pthread_rwlock_type;
	uint16_t	__pthread_rwlock_magic;
	pthread_mutex_t	__pthread_rwlock_mutex;
	pthread_cond_t	__pthread_rwlock_readercv;
	pthread_cond_t	__pthread_rwlock_writercv;
} pthread_rwlock_t;

/*
 * SUSV3
 */
typedef struct {
	uint32_t	__pthread_barrier_count;
	uint32_t	__pthread_barrier_current;
	upad64_t	__pthread_barrier_cycle;
	upad64_t	__pthread_barrier_reserved;
	pthread_mutex_t	__pthread_barrier_lock;
	pthread_cond_t	__pthread_barrier_cond;
} pthread_barrier_t;

typedef	pthread_mutex_t	pthread_spinlock_t;

/*
 * attributes for threads, dynamically allocated by library
 */
typedef struct _pthread_attr {
	void	*__pthread_attrp;
} pthread_attr_t;

/*
 * attributes for mutex, dynamically allocated by library
 */
typedef struct _pthread_mutexattr {
	void	*__pthread_mutexattrp;
} pthread_mutexattr_t;

/*
 * attributes for cond, dynamically allocated by library
 */
typedef struct _pthread_condattr {
	void	*__pthread_condattrp;
} pthread_condattr_t;

/*
 * pthread_once
 */
typedef	struct _once {
	upad64_t	__pthread_once_pad[4];
} pthread_once_t;

/*
 * UNIX 98 Extensions
 * attributes for rwlock, dynamically allocated by library
 */
typedef struct _pthread_rwlockattr {
	void	*__pthread_rwlockattrp;
} pthread_rwlockattr_t;

/*
 * SUSV3
 * attributes for pthread_barrier_t, dynamically allocated by library
 */
typedef struct {
	void	*__pthread_barrierattrp;
} pthread_barrierattr_t;

typedef ulong_t	dev_t;			/* expanded device type */

#if defined(_LP64) || defined(_I32LPx)
typedef	uint_t nlink_t;			/* file link type	*/
typedef int	pid_t;			/* process id type	*/
#else
typedef	ulong_t	nlink_t;		/* (historical version) */
typedef	long	pid_t;			/* (historical version) */
#endif

#if !defined(_SIZE_T) || __cplusplus >= 199711L
#define	_SIZE_T
#if defined(_LP64) || defined(_I32LPx)
typedef	ulong_t	size_t;		/* size of something in bytes */
#else
typedef	uint_t	size_t;		/* (historical version) */
#endif
#endif	/* _SIZE_T */

#ifndef _SSIZE_T
#define	_SSIZE_T
#if defined(_LP64) || defined(_I32LPx)
typedef long	ssize_t;	/* size of something in bytes or -1 */
#else
typedef int	ssize_t;	/* (historical version) */
#endif
#endif	/* _SSIZE_T */

#if !defined(_TIME_T) || __cplusplus >= 199711L
#define	_TIME_T
typedef	long		time_t;	/* time of day in seconds */
#endif	/* _TIME_T */

#if !defined(_CLOCK_T) || __cplusplus >= 199711L
#define	_CLOCK_T
typedef	long		clock_t; /* relative time in a specified resolution */
#endif	/* ifndef _CLOCK_T */

#ifndef _CLOCKID_T
#define	_CLOCKID_T
typedef	int	clockid_t;	/* clock identifier type */
#endif	/* ifndef _CLOCKID_T */

#ifndef _TIMER_T
#define	_TIMER_T
typedef	int	timer_t;	/* timer identifier type */
#endif	/* ifndef _TIMER_T */

#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)

/* BEGIN CSTYLED */
typedef	unsigned char	unchar;
typedef	unsigned short	ushort;
typedef	unsigned int	uint;
typedef	unsigned long	ulong;
/* END CSTYLED */

#if defined(_KERNEL) || defined(_FAKE_KERNEL)

#define	SHRT_MIN	(-32768)	/* min value of a "short int" */
#define	SHRT_MAX	32767		/* max value of a "short int" */
#define	USHRT_MAX	65535		/* max of "unsigned short int" */
#define	INT_MIN		(-2147483647-1) /* min value of an "int" */
#define	INT_MAX		2147483647	/* max value of an "int" */
#define	UINT_MAX	4294967295U	/* max value of an "unsigned int" */
#if defined(_LP64)
#define	LONG_MIN	(-9223372036854775807L-1L)
					/* min value of a "long int" */
#define	LONG_MAX	9223372036854775807L
					/* max value of a "long int" */
#define	ULONG_MAX	18446744073709551615UL
					/* max of "unsigned long int" */
#else /* _ILP32 */
#define	LONG_MIN	(-2147483647L-1L)
					/* min value of a "long int" */
#define	LONG_MAX	2147483647L	/* max value of a "long int" */
#define	ULONG_MAX	4294967295UL	/* max of "unsigned long int" */
#endif

#define	LLONG_MIN	(-9223372036854775807LL-1LL)
					/* min of "long long int" */
#define	LLONG_MAX	9223372036854775807LL
					/* max of "long long int" */
#define	ULLONG_MAX	18446744073709551615ULL
					/* max of "unsigned long long int" */

#if defined(_LP64) || _FILE_OFFSET_BITS == 32
#define	OFF_MIN		LONG_MIN
#define	OFF_MAX		LONG_MAX
#elif _FILE_OFFSET_BITS == 64
#define	OFF_MIN		LLONG_MIN
#define	OFF_MAX		LLONG_MAX
#endif	/* _LP64 || _FILE_OFFSET_BITS == 32 */

#endif	/* defined(_KERNEL) */

#define	P_MYPID	((pid_t)0)

/*
 * The following is the value of type id_t to use to indicate the
 * caller's current id.  See procset.h for the type idtype_t
 * which defines which kind of id is being specified.
 */
#define	P_MYID	(-1)
#define	NOPID (pid_t)(-1)

#ifndef NODEV
#define	NODEV	(dev_t)(-1l)
#ifdef _SYSCALL32
#define	NODEV32	(dev32_t)(-1)
#endif	/* _SYSCALL32 */
#endif	/* NODEV */

/*
 * The following value of type pfn_t is used to indicate
 * invalid page frame number.
 */
#define	PFN_INVALID	((pfn_t)-1)
#define	PFN_SUSPENDED	((pfn_t)-2)

/* BEGIN CSTYLED */
typedef unsigned char	u_char;
typedef unsigned short	u_short;
typedef unsigned int	u_int;
typedef unsigned long	u_long;
typedef struct _quad { int val[2]; } quad_t;	/* used by UFS */
typedef quad_t		quad;			/* used by UFS */
/* END CSTYLED */

/*
 * Nested include for BSD/sockets source compatibility.
 * (The select macros used to be defined here).
 */
#include <sys/select.h>

#endif	/* !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) */

/*
 * _VOID was defined to be either void or char but this is not
 * required because previous SunOS compilers have accepted the void
 * type. However, because many system header and source files use the
 * void keyword, the volatile keyword, and ANSI C function prototypes,
 * non-ANSI compilers cannot compile the system anyway. The _VOID macro
 * should therefore not be used and remains for source compatibility
 * only.
 */
/* CSTYLED */
#define	_VOID	void

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TYPES_H */
