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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef WHO_DOT_H
#define	WHO_DOT_H

#include <link.h>
#include <sys/regset.h>
#include <sys/frame.h>
#include <sys/elf.h>

#if defined(__sparcv9)
#define	Elf_Ehdr	Elf64_Ehdr
#define	Elf_Phdr	Elf64_Phdr
#define	Elf_Shdr	Elf64_Shdr
#define	Elf_Sym		Elf64_Sym
#define	elf_getshdr	elf64_getshdr
#else
#define	Elf_Ehdr	Elf32_Ehdr
#define	Elf_Phdr	Elf32_Phdr
#define	Elf_Shdr	Elf32_Shdr
#define	Elf_Sym		Elf32_Sym
#define	elf_getshdr	elf32_getshdr
#endif


typedef struct objinfo {
	caddr_t			o_lpc;		/* low PC */
	caddr_t			o_hpc;		/* high PC */
	int			o_fd;		/* file descriptor */
	Elf 			*o_elf;		/* Elf pointer */
	Elf_Sym 		*o_syms;	/* symbol table */
	uint_t			o_symcnt;	/* # of symbols */
	const char 		*o_strs;	/* symbol string  table */
	Link_map 		*o_lmp;
	uint_t			o_flags;
	struct objinfo 		*o_next;
} Objinfo;

#define	FLG_OB_NOSYMS	0x0001		/* no symbols available for obj */
#define	FLG_OB_FIXED	0x0002		/* fixed address object */


#if defined(__sparc)
#if defined(__GNUC__)
#define	FLUSHWIN() __asm__("ta 3");
#else	/* !__GNUC__ */
#define	FLUSHWIN() asm("ta 3");
#endif
#endif

#if defined(__x86)
#define	FLUSHWIN()
#endif

#ifndef	STACK_BIAS
#define	STACK_BIAS	0
#endif

#endif /* WHO_DOT_H */
