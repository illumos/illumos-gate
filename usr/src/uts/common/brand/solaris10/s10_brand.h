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
 * Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved.
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _S10_BRAND_H
#define	_S10_BRAND_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/brand.h>

#define	S10_BRANDNAME		"solaris10"

#define	S10_VERSION_1		1
#define	S10_VERSION		S10_VERSION_1

#define	S10_LIB_NAME		"s10_brand.so.1"
#define	S10_LINKER_NAME		"ld.so.1"

#define	S10_LIB32		BRAND_NATIVE_DIR "usr/lib/" S10_LIB_NAME
#define	S10_LINKER32		"/lib/" S10_LINKER_NAME

#define	S10_LIB64		BRAND_NATIVE_DIR "usr/lib/64/" S10_LIB_NAME
#define	S10_LINKER64		"/lib/64/" S10_LINKER_NAME

#if defined(_LP64)
#define	S10_LIB		S10_LIB64
#define	S10_LINKER	S10_LINKER64
#else /* !_LP64 */
#define	S10_LIB		S10_LIB32
#define	S10_LINKER	S10_LINKER32
#endif /* !_LP64 */

/*
 * Solaris 10 value of _SIGRTMIN, _SIGRTMAX, MAXSIG, NSIG
 */
#define	S10_SIGRTMIN	41
#define	S10_SIGRTMAX	48
#define	S10_MAXSIG	48
#define	S10_NSIG	49

/*
 * Brand system call subcodes.  0-127 are reserved for generic subcodes.
 */
#define	B_S10_PIDINFO		128
#define	B_S10_NATIVE		130
#define	B_S10_FSREGCORRECTION	131
#define	B_S10_ISFDXATTRDIR	132

/*
 * Versioning flags
 *
 * The first enum value must be zero.  Place new enum values at the end of the
 * list but before S10_NUM_EMUL_FEATURES, which must always come last.
 * Enum values should start with "S10_FEATURE_" and be named after the
 * fixes/backports that they represent.  For example, an enum value representing
 * a backport that changes a MNTFS ioctl could be named
 * "S10_FEATURE_ALTERED_MNTFS_IOCTL".
 */
enum s10_emulated_features {
	S10_FEATURE_ALTERED_MNTFS_IOCTL,
	S10_FEATURE_U9_ZFS_IOCTL,	/* S10u9 ZFS ioctl changes */
	S10_NUM_EMUL_FEATURES		/* This must be the last entry! */
};

/*
 * This string constant represents the path of the Solaris 10 directory
 * containing emulation feature files.
 */
#define	S10_REQ_EMULATION_DIR	"/usr/lib/brand/solaris10"

/*
 * s10_brand_syscall_callback_common() needs to save 4 local registers so it
 * can free them up for its own use.
 */
#define	S10_CPU_REG_SAVE_SIZE	(sizeof (ulong_t) * 4)

/*
 * S10 system call codes for S10 traps that have been removed or reassigned,
 * or that are to be removed or reassigned after the dtrace syscall provider
 * has been reengineered to deal properly with syscall::open (for example).
 */
#define	S10_SYS_forkall		2
#define	S10_SYS_open		5
#define	S10_SYS_wait		7
#define	S10_SYS_creat		8
#define	S10_SYS_link		9
#define	S10_SYS_unlink		10
#define	S10_SYS_exec		11
#define	S10_SYS_mknod		14
#define	S10_SYS_chmod		15
#define	S10_SYS_chown		16
#define	S10_SYS_stat		18
#define	S10_SYS_umount		22
#define	S10_SYS_fstat		28
#define	S10_SYS_utime		30
#define	S10_SYS_access		33
#define	S10_SYS_dup		41
#define	S10_SYS_pipe		42
#define	S10_SYS_issetugid	75
#define	S10_SYS_fsat		76
#define	S10_SYS_rmdir		79
#define	S10_SYS_mkdir		80
#define	S10_SYS_poll		87
#define	S10_SYS_lstat		88
#define	S10_SYS_symlink		89
#define	S10_SYS_readlink	90
#define	S10_SYS_fchmod		93
#define	S10_SYS_fchown		94
#define	S10_SYS_xstat		123
#define	S10_SYS_lxstat		124
#define	S10_SYS_fxstat		125
#define	S10_SYS_xmknod		126
#define	S10_SYS_lchown		130
#define	S10_SYS_rename		134
#define	S10_SYS_fork1		143
#define	S10_SYS_lwp_sema_wait	147
#define	S10_SYS_utimes		154
#define	S10_SYS_lwp_mutex_lock	169
#define	S10_SYS_stat64		215
#define	S10_SYS_lstat64		216
#define	S10_SYS_fstat64		217
#define	S10_SYS_creat64		224
#define	S10_SYS_open64		225
#define	S10_SYS_so_socket	230
#define	S10_SYS_accept		234

/*
 * solaris10-brand-specific attributes
 * These must start at ZONE_ATTR_BRAND_ATTRS.
 */
#define	S10_EMUL_BITMAP		ZONE_ATTR_BRAND_ATTRS

/*
 * s10_emul_bitmap represents an emulation feature bitmap.  Each constant
 * in s10_emulated_features defines a bit index in this bitmap.  If a bit is
 * set, then the feature associated with the s10_emulated_features constant
 * whose value is the bit's index is present in the associated zone's hosted
 * Solaris 10 environment.
 *
 * NOTE: There must be at least one byte in the bitmap.
 *
 * We don't use the bitmap macros provided by usr/src/uts/common/sys/bitmap.h
 * because they operate on ulong_t arrays.  The size of a ulong_t depends on
 * the data model in which the code that declares the ulong_t is compiled:
 * four bytes on 32-bit architectures and eight bytes 64-bit architectures.
 * If the kernel is 64-bit and a 32-bit process executes in a solaris10-
 * branded zone, then if the process' emulation library, which is 32-bit,
 * queries the kernel for the zone's emulation bitmap, then the kernel will
 * refuse because the library will request a bitmap that's half as big
 * as the bitmap the kernel provides.  The 32-bit emulation library would need
 * its own macros to define and operate on bitmaps with 64-bit array elements.
 * Thus using the sys/bitmap.h macros is probably more troublesome than
 * defining and using our own constants and macros for bitmap manipulations.
 */
typedef uint8_t s10_emul_bitmap_t[(S10_NUM_EMUL_FEATURES >> 3) + 1];

#if defined(_KERNEL)

/* brand specific data */
typedef struct s10_zone_data {
	/*
	 * emul_bitmap specifies the features that are present in the
	 * associated zone.
	 */
	s10_emul_bitmap_t	emul_bitmap;
} s10_zone_data_t;

void s10_brand_syscall_callback(void);
void s10_brand_syscall32_callback(void);

#if !defined(sparc)
void s10_brand_sysenter_callback(void);
#endif /* !sparc */

#if defined(__amd64)
void s10_brand_int91_callback(void);
#endif /* __amd64 */
#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _S10_BRAND_H */
