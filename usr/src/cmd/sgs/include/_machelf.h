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
 *
 * Wrapper around the <sys/machelf.h> header that adds
 * definitions used by SGS.
 */

#ifndef	_MACHELF_H
#define	_MACHELF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/machelf.h>
#include <string.h>		/* memcpy() */

/*
 * Make machine class dependent functions transparent to the common code
 */

/*
 * Note on ELF_R_TYPE: 64-bit sparc relocations require the use of
 * ELF64_R_TYPE_ID instead of the ELF64_R_TYPE macro used for all
 * other platforms. So our ELF_R_TYPE macro requires the caller to
 * supply the machine type.
 */


#if	defined(_ELF64)
#define	ELF_R_TYPE(_info, _mach)  \
	(((_mach) == EM_SPARCV9) ? ELF64_R_TYPE_ID(_info) : ELF64_R_TYPE(_info))
#define	ELF_R_INFO			ELF64_R_INFO
#define	ELF_R_SYM			ELF64_R_SYM
#define	ELF_R_TYPE_DATA(x)		ELF64_R_TYPE_DATA(x)
#define	ELF_R_TYPE_INFO(xoff, type)	ELF64_R_TYPE_INFO(xoff, type)
#define	ELF_ST_BIND			ELF64_ST_BIND
#define	ELF_ST_TYPE			ELF64_ST_TYPE
#define	ELF_ST_INFO			ELF64_ST_INFO
#define	ELF_ST_VISIBILITY		ELF64_ST_VISIBILITY
#define	ELF_M_SYM			ELF64_M_SYM
#define	ELF_M_SIZE			ELF64_M_SIZE
#define	ELF_M_INFO			ELF64_M_INFO
#define	elf_checksum			elf64_checksum
#define	elf_fsize			elf64_fsize
#define	elf_getehdr			elf64_getehdr
#define	elf_getphdr			elf64_getphdr
#define	elf_newehdr			elf64_newehdr
#define	elf_newphdr			elf64_newphdr
#define	elf_getshdr			elf64_getshdr
#define	elf_xlatetof			elf64_xlatetof
#define	elf_xlatetom			elf64_xlatetom
#else /* _ELF64 */
#define	ELF_R_TYPE(_info, _mach)	ELF32_R_TYPE(_info)
#define	ELF_R_INFO			ELF32_R_INFO
#define	ELF_R_SYM			ELF32_R_SYM
/* Elf64 can hide extra offset in r_info */
#define	ELF_R_TYPE_DATA(x)		(0)
#define	ELF_R_TYPE_INFO(xoff, type)	(type)
#define	ELF_ST_BIND			ELF32_ST_BIND
#define	ELF_ST_TYPE			ELF32_ST_TYPE
#define	ELF_ST_INFO			ELF32_ST_INFO
#define	ELF_ST_VISIBILITY		ELF32_ST_VISIBILITY
#define	ELF_M_SYM			ELF32_M_SYM
#define	ELF_M_SIZE			ELF32_M_SIZE
#define	ELF_M_INFO			ELF32_M_INFO
#define	elf_checksum			elf32_checksum
#define	elf_fsize			elf32_fsize
#define	elf_getehdr			elf32_getehdr
#define	elf_getphdr			elf32_getphdr
#define	elf_newehdr			elf32_newehdr
#define	elf_newphdr			elf32_newphdr
#define	elf_getshdr			elf32_getshdr
#define	elf_xlatetof			elf32_xlatetof
#define	elf_xlatetom			elf32_xlatetom
#endif	/* _ELF32 */


/*
 * Macros for swapping bytes. The type of the argument must
 * match the type given in the macro name.
 */
#define	BSWAP_HALF(_half) \
	(((_half) << 8) | ((_half) >> 8))

#define	BSWAP_WORD(_word) \
	((((_word) << 24) | (((_word) & 0xff00) << 8) | \
	(((_word) >> 8) & 0xff00) | ((_word) >> 24)))

#if	defined(_ELF64)
#define	BSWAP_XWORD(_xword) \
	(((_xword) << 56) | \
	(((_xword) & 0x0000ff00) << 40) | \
	(((_xword) & 0x00ff0000) << 24) | \
	(((_xword) & 0xff000000) << 8) | \
	(((_xword) >> 8)  & 0xff000000) | \
	(((_xword) >> 24) & 0x00ff0000) | \
	(((_xword) >> 40) & 0x0000ff00) | \
	((_xword) >> 56))	/* Xword is unsigned - 0 bits enter from left */
#else
#define	BSWAP_XWORD(_xword) BSWAP_WORD(_xword)
#endif

/*
 * Macros for assigning Half/Word/Xword items from one location to
 * another that are safe no matter what the data alignment rules of the
 * running platform are. Variants exist to swap the data byteorder
 * at the same time, or not.
 *
 * These macros are useful for code that accesses data that is aligned
 * for a different system architecture, as occurs in cross linking.
 *
 * All of these macros assume the arguments are passed as pointers to
 * bytes (signed or unsigned).
 */

#define	UL_ASSIGN_HALF(_dst, _src) (void) \
	((_dst)[0] = (_src)[0],	(_dst)[1] = (_src)[1])
#define	UL_ASSIGN_WORD(_dst, _src) (void) \
	((_dst)[0] = (_src)[0],	(_dst)[1] = (_src)[1], \
	(_dst)[2] = (_src)[2], 	(_dst)[3] = (_src)[3])
#if	defined(_ELF64)
#define	UL_ASSIGN_XWORD(_dst, _src) (void) memcpy(_dst, (_src), sizeof (Xword))
#else
#define	UL_ASSIGN_XWORD(_xword) UL_ASSIGN_WORD(_xword)
#endif

#define	UL_ASSIGN_BSWAP_HALF(_dst, _src) (void) \
	((_dst)[0] = (_src)[1],	(_dst)[1] = (_src)[0])
#define	UL_ASSIGN_BSWAP_WORD(_dst, _src) (void) \
	((_dst)[0] = (_src)[3],	(_dst)[1] = (_src)[2], \
	(_dst)[2] = (_src)[1],	(_dst)[3] = (_src)[0])
#if	defined(_ELF64)
#define	UL_ASSIGN_BSWAP_XWORD(_dst, _src) (void) \
	((_dst)[0] = (_src)[7],	(_dst)[1] = (_src)[6], \
	(_dst)[2] = (_src)[5],	(_dst)[3] = (_src)[4], \
	(_dst)[4] = (_src)[3],	(_dst)[5] = (_src)[2], \
	(_dst)[6] = (_src)[1],	(_dst)[7] = (_src)[0])
#else
#define	UL_ASSIGN_BSWAP_XWORD(_dst, _src) UL_ASSIGN_BSWAP_WORD(_dst, _src)
#endif


#endif /* _MACHELF_H */
