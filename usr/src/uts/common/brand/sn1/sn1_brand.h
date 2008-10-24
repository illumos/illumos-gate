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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SN1_BRAND_H
#define	_SN1_BRAND_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

#define	SN1_BRANDNAME		"sn1"

#define	SN1_VERSION_1		1
#define	SN1_VERSION		SN1_VERSION_1

#define	SN1_NATIVE_DIR		"/.SUNWnative/"
#define	SN1_LIB_NAME		"sn1_brand.so.1"
#define	SN1_LINKER_NAME		"ld.so.1"

#define	SN1_LIB32		SN1_NATIVE_DIR "usr/lib/" SN1_LIB_NAME
#define	SN1_LINKER32		"/lib/" SN1_LINKER_NAME

#define	SN1_LIB64		SN1_NATIVE_DIR "usr/lib/64/" SN1_LIB_NAME
#define	SN1_LINKER64		"/lib/64/" SN1_LINKER_NAME

#if defined(_LP64)
#define	SN1_LIB		SN1_LIB64
#define	SN1_LINKER	SN1_LINKER64
#else /* !_LP64 */
#define	SN1_LIB		SN1_LIB32
#define	SN1_LINKER	SN1_LINKER32
#endif /* !_LP64 */

/*
 * Aux vector containing lddata pointer of brand library linkmap.
 * Used by lx_librtld_db.
 */
#define	AT_SUN_BRAND_SN1_LDDATA		AT_SUN_BRAND_AUX1

/*
 * Information needed by the sn1 library to launch an executable.
 */
typedef struct sn1_elf_data {
	ulong_t		sed_phdr;
	ulong_t		sed_phent;
	ulong_t		sed_phnum;
	ulong_t		sed_entry;
	ulong_t		sed_base;
	ulong_t		sed_ldentry;
	ulong_t		sed_lddata;
} sn1_elf_data_t;

/*
 * Structure used to register a branded processes
 */
typedef struct sn1_brand_reg {
	uint_t		sbr_version;	/* version number */
	caddr_t		sbr_handler;	/* base address of handler */
} sn1_brand_reg_t;

#if defined(_KERNEL)
#if defined(_SYSCALL32)
typedef struct sn1_elf_data32 {
	uint32_t	sed_phdr;
	uint32_t	sed_phent;
	uint32_t	sed_phnum;
	uint32_t	sed_entry;
	uint32_t	sed_base;
	uint32_t	sed_ldentry;
	uint32_t	sed_lddata;
} sn1_elf_data32_t;

typedef struct sn1_brand_reg32 {
	uint32_t	sbr_version;	/* version number */
	caddr32_t	sbr_handler;	/* base address of handler */
} sn1_brand_reg32_t;
#endif /* _SYSCALL32 */

/*
 * Information associated with all sn1 branded processes
 */
typedef struct sn1_proc_data {
	caddr_t		spd_handler;	/* address of user-space handler */
	sn1_elf_data_t	spd_elf_data;	/* ELF data for sn1 application */
} sn1_proc_data_t;

void sn1_brand_syscall_callback(void);
void sn1_brand_syscall32_callback(void);

#if !defined(sparc)
void sn1_brand_sysenter_callback(void);
#endif /* !sparc */

#if defined(__amd64)
void sn1_brand_int91_callback(void);
#endif /* __amd64 */
#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SN1_BRAND_H */
