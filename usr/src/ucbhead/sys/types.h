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
 */

/*
 *	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
 *	  All Rights Reserved
 */

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef	_SYS_TYPES_H
#define	_SYS_TYPES_H

/*
 * Include fixed width type declarations proposed by the ISO/JTC1/SC22/WG14 C
 * committee's working draft for the revision of the current ISO C standard,
 * ISO/IEC 9899:1990 Programming language - C.  These are not currently
 * required by any standard but constitute a useful, general purpose set
 * of type definitions which is namespace clean with respect to all standards.
 */

#include <sys/int_types.h>
#include <sys/feature_tests.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _ASM

/* From SunOS types.h */
#if defined(mc68000)
typedef	struct _physadr { short r[1]; } *physadr;
typedef	struct _label { int val[13]; } label_t;
#elif defined(__i386)
typedef	struct _physadr { short r[1]; } *physadr;
typedef	struct _label { int val[8]; } label_t;
#elif defined(__sparc)
typedef	struct _physadr { int r[1]; } *physadr;
typedef	struct _label { int val[2]; } label_t;
#else
typedef	struct _physadr { int r[1]; } *physadr;
typedef	struct _label { int val[10]; } label_t;
#endif

/* POSIX Extensions */

typedef unsigned char   uchar_t;
typedef unsigned short  ushort_t;
typedef unsigned int    uint_t;
typedef unsigned long   ulong_t;


/* For BSD compatibility */
typedef char 		*addr_t;	/* ?<core address> type */

typedef char 		*caddr_t;	/* ?<core address> type */
typedef long		daddr_t;	/* <disk address> type */
typedef short		cnt_t;		/* ?<count> type */
typedef ulong_t		pgcnt_t;	/* number of pages */

#ifdef _ILP32
typedef ulong_t 	paddr_t;	/* <physical address> type */
typedef	long		swblk_t;
#endif

typedef uchar_t 	use_t;		/* use count for swap.  */
typedef short		sysid_t;
typedef short		index_t;
typedef short		lock_t;		/* lock work for busy wait */
typedef enum boolean { B_FALSE, B_TRUE } boolean_t;
typedef ulong_t		l_dev_t;

/*
 * The following protects users who use other than Sun compilers
 * (eg, GNU C) that don't support long long, and need to include
 * this header file.
 */
#ifdef _LONGLONG_TYPE
typedef	long long		longlong_t;
typedef	unsigned long long	u_longlong_t;
#else
#ifdef GCC
typedef int64_t longlong_t;
typedef uint64_t u_longlong_t;
#else
/* used to reserve space and generate alignment */
typedef	union {
	int32_t	l[2];
	double	d;
} longlong_t;
typedef	union {
	uint32_t	l[2];
	double		d;
} u_longlong_t;
#endif	/* GCC */
#endif	/* _LONGLONG_TYPE */

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
 * than those available in the underlying ABI.  See <sys/isa_list.h>
 */
#ifdef _LONGLONG_TYPE
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
#endif /* _LONGLONG_TYPE */

typedef union {
	long double	_q;
	int32_t		_l[4];
} pad128_t;

typedef union {
	long double	_q;
	uint32_t	_l[4];
} upad128_t;

/*
 * attributes for threads, dynamically allocated by library
 */
typedef	struct {
	void	*__pthread_attrp;
} pthread_attr_t;

/* types related to file sizes, counts, offsets, etc. */
#if defined(_LP64) || _FILE_OFFSET_BITS == 32
typedef long		off_t;		/* ?<offset> type */
typedef long		blkcnt_t;	/* counts file blocks */
typedef ulong_t		fsblkcnt_t;	/* counts file system blocks */
typedef ulong_t		fsfilcnt_t;	/* counts files */
typedef ulong_t		ino_t;		/* expanded inode type	*/
#elif _FILE_OFFSET_BITS == 64
typedef longlong_t	off_t;		/* offsets within files */
typedef longlong_t	blkcnt_t;	/* count of file blocks */
typedef u_longlong_t	fsblkcnt_t;	/* count of file system blocks */
typedef u_longlong_t	fsfilcnt_t;	/* count of files */
typedef u_longlong_t	ino_t;		/* expanded inode type */
#endif

#ifdef _LP64
typedef	int		blksize_t;	/* used for block sizes */
#else
typedef	long		blksize_t;	/* used for block sizes */
#endif

#ifdef _LARGEFILE64_SOURCE
#ifdef _LP64
typedef off_t		off64_t;
typedef blkcnt_t	blkcnt64_t;
typedef fsblkcnt_t	fsblkcnt64_t;
typedef fsfilcnt_t	fsfilcnt64_t;
typedef ino_t		ino64_t;
#else
typedef longlong_t	off64_t;	/* ?<offset> type */
typedef longlong_t	blkcnt64_t;	/* counts file blocks */
typedef u_longlong_t	fsblkcnt64_t;	/* counts file system blocks */
typedef u_longlong_t	fsfilcnt64_t;	/* counts files */
typedef u_longlong_t	ino64_t;	/* expanded inode type	*/
#endif
#endif

/*
 * The following type is for various kinds of identifiers.  The
 * actual type must be the same for all since some system calls
 * (such as sigsend) take arguments that may be any of these
 * types.  The enumeration type idtype_t defined in sys/procset.h
 * is used to indicate what type of id is being specified.
 */

typedef	longlong_t	offset_t;
typedef	u_longlong_t	u_offset_t;
typedef	longlong_t	diskaddr_t;

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
 * Partial support for 64-bit file offset enclosed herein,
 * specifically used to access devices greater than 2gb.
 * However, support for devices greater than 2gb requires compiler
 * support for long long.
 */
#ifdef _LONG_LONG_LTOH
typedef union lloff {
	offset_t	_f;	/* Full 64 bit offset value */
	struct {
		int32_t _l;	/* lower 32 bits of offset value */
		int32_t _u;	/* upper 32 bits of offset value */
	} _p;
} lloff_t;
#endif

#ifdef _LONG_LONG_HTOL
typedef union lloff {
	offset_t	_f;	/* Full 64 bit offset value */
	struct {
		int32_t _u;	/* upper 32 bits of offset value */
		int32_t _l;	/* lower 32 bits of offset value */
	} _p;
} lloff_t;
#endif

#ifdef _LONG_LONG_LTOH
typedef union lldaddr {
	diskaddr_t	_f;	/* Full 64 bit disk address value */
	struct {
		int32_t _l;	/* lower 32 bits of disk address value */
		int32_t _u;	/* upper 32 bits of disk address value */
	} _p;
} lldaddr_t;
#endif

#ifdef _LONG_LONG_HTOL
typedef union lldaddr {
	diskaddr_t	_f;	/* Full 64 bit disk address value */
	struct {
		int32_t _u;	/* upper 32 bits of disk address value */
		int32_t _l;	/* lower 32 bits of disk address value */
	} _p;
} lldaddr_t;
#endif

typedef ulong_t k_fltset_t;	/* kernel fault set type */

#if defined(_LP64) || defined(_I32LPx)
typedef int		id_t;		/* A process id,	*/
					/* process group id,	*/
					/* session id,		*/
					/* scheduling class id, */
					/* user id or group id. */
#else
typedef long		id_t;
#endif

typedef void	*timeout_id_t;
typedef void	*bufcall_id_t;

/* Typedefs for dev_t components */

#if !defined(_LP64) && defined(__cplusplus)
typedef ulong_t major_t;	/* major part of device number */
typedef ulong_t minor_t;	/* minor part of device number */
#else
typedef uint_t major_t;
typedef uint_t minor_t;
#endif

typedef short	pri_t;

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
typedef ushort_t o_mode_t;		/* old file attribute type */
typedef short	o_dev_t;		/* old device type	*/
typedef ushort_t o_uid_t;		/* old UID type		*/
typedef o_uid_t	o_gid_t;		/* old GID type		*/
typedef short	o_nlink_t;		/* old file link type	*/
typedef short	o_pid_t;		/* old process id type	*/
typedef ushort_t o_ino_t;		/* old inode type	*/

/* POSIX and XOPEN Declarations */

typedef int	key_t;			/* IPC key type */
#if !defined(_LP64) && defined(__cplusplus)
typedef ulong_t	mode_t;			/* file attribute type  */
#else
typedef uint_t	mode_t;
#endif

#ifndef	_UID_T
#define	_UID_T
#if !defined(_LP64) && defined(__cplusplus)
typedef long	uid_t;			/* UID type		*/
#else
typedef int	uid_t;
#endif
#endif

typedef uid_t	gid_t;			/* GID type		*/
typedef id_t	taskid_t;		/* task ID type		*/
typedef id_t	projid_t;		/* project ID type	*/
typedef	id_t	poolid_t;		/* pool ID type		*/
typedef id_t	zoneid_t;		/* zone ID type		*/
typedef id_t	ctid_t;			/* contract ID type	*/

typedef uint32_t datalink_id_t;

typedef ulong_t	dev_t;			/* expanded device type	*/

#if !defined(_LP64) && defined(__cplusplus)
typedef ulong_t	nlink_t;		/* file link type	*/
typedef long	pid_t;			/* process id type	*/
#else
typedef uint_t	nlink_t;
typedef int	pid_t;
#endif

#ifndef	_SIZE_T
#define	_SIZE_T
#if !defined(_LP64) && defined(__cplusplus)
typedef uint_t	size_t;
#else
typedef ulong_t	size_t;
#endif
#endif

#ifndef	_SSIZE_T
#define	_SSIZE_T
#if !defined(_LP64) && defined(__cplusplus)
typedef int	ssize_t;
#else
typedef long	ssize_t;	/* used by functions which return a */
				/* count of bytes or an error indication */
#endif
#endif

#ifndef	_TIME_T
#define	_TIME_T
typedef long	time_t;		/* time of day in seconds */
#endif  /* _TIME_T */

#ifndef	_CLOCK_T
#define	_CLOCK_T
typedef long		clock_t; /* relative time in a specified resolution */
#endif	/* ifndef _CLOCK_T */

#if (defined(_KERNEL) || !defined(_POSIX_SOURCE))

/* BEGIN CSTYLED */
typedef unsigned char   unchar;
typedef unsigned int    uint;
typedef unsigned long   ulong;
/* END CSTYLED */

#if defined(_KERNEL)

#define	SHRT_MIN	-32768		/* min value of a "short int" */
#define	SHRT_MAX	32767		/* max value of a "short int" */
#define	USHRT_MAX	65535u		/* max value of "unsigned short int" */
#define	INT_MIN		(-2147483647-1)	/* min value of an "int" */
#define	INT_MAX		2147483647	/* max value of an "int" */
#define	UINT_MAX	4294967295u	/* max value of an "unsigned int" */
#if !defined(_LP64)
#define	LONG_MIN	(-2147483647L-1L)	/* min value of a "long int" */
#define	LONG_MAX	2147483647L	/* max value of a "long int" */
#define	ULONG_MAX	4294967295UL	/* max value of "unsigned long int" */
#else
#define	LONG_MIN	(-9223372036854775807L-1L)
#define	LONG_MAX	9223372036854775807L
#define	ULONG_MAX	18446744073709551615UL
#endif

#endif	/* defined(_KERNEL) */


#define	P_MYPID	((pid_t)0)

/*
 * The following is the value of type id_t to use to indicate the
 * caller's current id.  See procset.h for the type idtype_t
 * which defines which kind of id is being specified.
 */

#define	P_MYID	(-1)
#define	NOPID (pid_t)(-1)

#ifndef	NODEV
#define	NODEV (dev_t)(-1)
#endif

#ifdef _ILP32
/*
 * A host identifier is used to uniquely define a particular node
 * on an rfs network.  Its type is as follows.
 */

typedef	long	hostid_t;

/*
 * The following value of type hostid_t is used to indicate the
 * current host.  The actual hostid for each host is in the
 * kernel global variable rfs_hostid.
 */

#define	P_MYHOSTID	(-1)
#endif

#endif /* END (defined(_KERNEL) || !defined(_POSIX_SOURCE)) */

/* BEGIN CSTYLED */
typedef unsigned char	u_char;
typedef unsigned short	u_short;
typedef unsigned int	u_int;
typedef unsigned long	u_long;
typedef unsigned short	ushort;		/* sys III compat */
typedef struct _quad { int val[2]; } quad;	/* used by UFS */
/* END CSTYLED */

/*
 * These were added to allow non-ANSI compilers to compile the system.
 */

#ifdef	__STDC__

/* _VOID, const, volatile left in for source compatibility */

/* BEGIN CSTYLED */
#ifndef	_VOID
#define	_VOID	void
#endif

#else

#ifndef	_VOID
#define	_VOID	char
#endif

#ifndef	const
#define	const
#endif

#ifndef	volatile
#define	volatile
#endif
/* END CSTYLED */

#endif /* __STDC__ */

#endif /* _ASM */

/*
 * Nested include for BSD/sockets source compatibility.
 * (The select macros used to be defined here).
 */
#include <sys/select.h>
/*
 * Nested include for BSD compatibility.
 */

#define	AHZ 64

#include <sys/sysmacros.h>

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_TYPES_H */
