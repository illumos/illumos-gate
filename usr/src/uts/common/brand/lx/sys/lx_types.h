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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2016 Joyent, Inc.  All rights reserved.
 */

#ifndef _SYS_LX_TYPES_H
#define	_SYS_LX_TYPES_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	_KERNEL

#define	SHRT_MIN	(-32768)	/* min value of a "short int" */
#define	SHRT_MAX	32767		/* max value of a "short int" */
#define	USHRT_MAX	65535		/* max of "unsigned short int" */
#define	INT_MIN		(-2147483647-1) /* min value of an "int" */
#define	INT_MAX		2147483647	/* max value of an "int" */
#define	UINT_MAX	4294967295U	/* max value of an "unsigned int" */

#ifndef LLONG_MAX
#define	LLONG_MAX	9223372036854775807LL
#endif

#if defined(_LP64)
#define	LONG_MAX	9223372036854775807L
#define	ULONG_MAX	18446744073709551615UL
#else
#define	LONG_MAX	2147483647L	/* max value of a 32-bit "long int" */
#define	ULONG_MAX	4294967295UL	/* max value of a 32-bit "ulong int" */
#endif

#endif /* !_KERNEL */


typedef	uint64_t	lx_dev_t;
typedef	uint16_t	lx_dev16_t;
typedef	uint32_t	lx_ino_t;
typedef	uint64_t	lx_ino64_t;
typedef	uint32_t	lx_uid_t;
typedef	uint16_t	lx_uid16_t;
typedef	uint32_t	lx_gid_t;
typedef	uint16_t	lx_gid16_t;
typedef	uint32_t	lx_off_t;
typedef	uint64_t	lx_off64_t;
typedef	uint32_t	lx_blksize_t;
typedef	uint32_t	lx_blkcnt_t;
typedef	uint64_t	lx_blkcnt64_t;
typedef	uint32_t	lx_mode_t;
typedef	uint16_t	lx_mode16_t;

/*
 * Linux mangles major/minor numbers into dev_t differently than SunOS.
 */
#ifdef _LP64
#define	LX_MAKEDEVICE(maj, min) \
	(((min) & 0xff) | (((maj) & 0xfff) << 8) | \
	((uint64_t)((min) & ~0xff) << 12) | ((uint64_t)((maj) & ~0xfff) << 32))

#define	LX_GETMAJOR(lx_dev)	((((lx_dev) >> 8) & 0xfff) | \
	((((uint64_t)(lx_dev)) >> 32) & ~0xfff))

#else
#define	LX_MAKEDEVICE(maj, min) \
	(((min) & 0xff) | (((maj) & 0xfff) << 8) | (((min) & ~0xff) << 12))

#define	LX_GETMAJOR(lx_dev)	(((lx_dev) >> 8) & 0xfff)
#endif

#define	LX_GETMINOR(lx_dev)	(((lx_dev) & 0xff) | (((lx_dev) >> 12) & ~0xff))
/* Linux supports 20 bits for the minor, and 12 bits for the major number */
#define	LX_MAXMIN	0xfffff
#define	LX_MAXMAJ	0xfff

/*
 * Certain Linux tools care deeply about major/minor number mapping.
 * Map virtual disks (zfs datasets, zvols, etc) into a safe reserved range.
 */
#define	LX_MAJOR_DISK	203

/* LX ptm driver major/minor number */
#define	LX_PTM_MAJOR		5
#define	LX_PTM_MINOR		2

/* LX pts driver major number range */
#define	LX_PTS_MAJOR_MIN	136
#define	LX_PTS_MAJOR_MAX	143

/* LX tty/cons driver major number */
#define	LX_TTY_MAJOR		5

#define	LX_UID16_TO_UID32(uid16)	\
	(((uid16) == (lx_uid16_t)-1) ? ((lx_uid_t)-1) : (lx_uid_t)(uid16))

#define	LX_GID16_TO_GID32(gid16)     \
	(((gid16) == (lx_gid16_t)-1) ? ((lx_gid_t)-1) : (lx_gid_t)(gid16))

/* Overflow values default to NFS nobody. */

#define	UID16_OVERFLOW	((lx_uid16_t)65534)
#define	GID16_OVERFLOW	((lx_gid16_t)65534)

/*
 * All IDs with high word non-zero are converted to default overflow values to
 * avoid inadvertent truncation to zero (root) (!).
 */
#define	LX_UID32_TO_UID16(uid32)	\
	((((uid32) & 0xffff0000) == 0)  ? ((lx_uid16_t)(uid32)) : \
	    (((uid32) == ((lx_uid_t)-1)) ? ((lx_uid16_t)-1) : UID16_OVERFLOW))

#define	LX_GID32_TO_GID16(gid32)	\
	((((gid32) & 0xffff0000) == 0)  ? ((lx_gid16_t)(gid32)) : \
	    (((gid32) == ((lx_gid_t)-1)) ? ((lx_gid16_t)-1) : GID16_OVERFLOW))

#define	LX_32TO64(lo, hi)	\
	((uint64_t)((uint64_t)(lo) | ((uint64_t)(hi) << 32)))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LX_TYPES_H */
