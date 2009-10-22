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

#ifndef _S10_BRAND_H
#define	_S10_BRAND_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

#define	S10_BRANDNAME		"solaris10"

#define	S10_VERSION_1		1
#define	S10_VERSION		S10_VERSION_1

#define	S10_NATIVE_DIR		"/.SUNWnative/"
#define	S10_LIB_NAME		"s10_brand.so.1"
#define	S10_LINKER_NAME		"ld.so.1"

#define	S10_LIB32		S10_NATIVE_DIR "usr/lib/" S10_LIB_NAME
#define	S10_LINKER32		"/lib/" S10_LINKER_NAME
#define	S10_NATIVE_LINKER32	S10_NATIVE_DIR "lib/" S10_LINKER_NAME

#define	S10_LIB64		S10_NATIVE_DIR "usr/lib/64/" S10_LIB_NAME
#define	S10_LINKER64		"/lib/64/" S10_LINKER_NAME
#define	S10_NATIVE_LINKER64	S10_NATIVE_DIR "lib/64/" S10_LINKER_NAME

#if defined(_LP64)
#define	S10_LIB		S10_LIB64
#define	S10_LINKER	S10_LINKER64
#else /* !_LP64 */
#define	S10_LIB		S10_LIB32
#define	S10_LINKER	S10_LINKER32
#endif /* !_LP64 */

/*
 * Brand system call subcodes.  0-127 are reserved for generic subcodes.
 */
#define	B_S10_PIDINFO		128
#define	B_S10_TRUSS_POINT	129
#define	B_S10_NATIVE		130
#define	B_S10_FSREGCORRECTION	131

/*
 * s10_brand_syscall_callback_common() needs to save 4 local registers so it
 * can free them up for its own use.
 */
#define	S10_CPU_REG_SAVE_SIZE	(sizeof (ulong_t) * 4)

/*
 * Aux vector containing lddata pointer of brand library linkmap.
 * Used by s10_librtld_db.
 */
#define	AT_SUN_BRAND_S10_LDDATA		AT_SUN_BRAND_AUX1

/*
 * S10 system call codes for S10 traps that have been removed or
 * re-assigned.
 */
#define	S10_SYS_issetugid	75

/*
 * S10 brand emulation versions are used to trigger different behavior
 * based on the version of S10 installed in the zone.
 */
#define	S10_EMUL_UNDEF	-1

#define	S10_EMUL_VERSION_NUM	ZONE_ATTR_BRAND_ATTRS

/*
 * Information needed by the s10 library to launch an executable.
 */
typedef struct s10_elf_data {
	ulong_t		sed_phdr;
	ulong_t		sed_phent;
	ulong_t		sed_phnum;
	ulong_t		sed_entry;
	ulong_t		sed_base;
	ulong_t		sed_ldentry;
	ulong_t		sed_lddata;
} s10_elf_data_t;

/*
 * Structure used to register a branded processes
 */
typedef struct s10_brand_reg {
	uint_t		sbr_version;	/* version number */
	caddr_t		sbr_handler;	/* base address of handler */
} s10_brand_reg_t;

#if defined(_KERNEL)
#if defined(_SYSCALL32)
typedef struct s10_elf_data32 {
	uint32_t	sed_phdr;
	uint32_t	sed_phent;
	uint32_t	sed_phnum;
	uint32_t	sed_entry;
	uint32_t	sed_base;
	uint32_t	sed_ldentry;
	uint32_t	sed_lddata;
} s10_elf_data32_t;

typedef struct s10_brand_reg32 {
	uint32_t	sbr_version;	/* version number */
	caddr32_t	sbr_handler;	/* base address of handler */
} s10_brand_reg32_t;
#endif /* _SYSCALL32 */

/*
 * Information associated with all s10 branded processes
 */
typedef struct s10_proc_data {
	caddr_t		spd_handler;	/* address of user-space handler */
	s10_elf_data_t	spd_elf_data;	/* ELF data for s10 application */
} s10_proc_data_t;

/* brand specific data */
typedef struct s10_zone_data {
	int s10zd_emul_version;
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
