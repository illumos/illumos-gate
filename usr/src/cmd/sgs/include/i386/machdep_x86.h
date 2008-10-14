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
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Global include file for all sgs ia32 based machine dependent macros,
 * constants and declarations.
 */

#ifndef	_MACHDEP_X86_H
#define	_MACHDEP_X86_H

#include <link.h>
#include <sys/machelf.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Elf header information.
 */
#define	M_MACH_32		EM_386
#define	M_MACH_64		EM_AMD64

#ifdef _ELF64
#define	M_MACH			EM_AMD64
#define	M_CLASS			ELFCLASS64
#else
#define	M_MACH			EM_386
#define	M_CLASS			ELFCLASS32
#endif

#define	M_MACHPLUS		M_MACH
#define	M_DATA			ELFDATA2LSB
#define	M_FLAGSPLUS		0

/*
 * Page boundary Macros: truncate to previous page boundary and round to
 * next page boundary (refer to generic macros in ../sgs.h also).
 */
#define	M_PTRUNC(X)	((X) & ~(syspagsz - 1))
#define	M_PROUND(X)	(((X) + syspagsz - 1) & ~(syspagsz - 1))

/*
 * Segment boundary macros: truncate to previous segment boundary and round
 * to next page boundary.
 */
#if	defined(_ELF64)
#define	M_SEGSIZE	ELF_AMD64_MAXPGSZ
#else
#define	M_SEGSIZE	ELF_386_MAXPGSZ
#endif

#define	M_STRUNC(X)	((X) & ~(M_SEGSIZE - 1))
#define	M_SROUND(X)	(((X) + M_SEGSIZE - 1) & ~(M_SEGSIZE - 1))

/*
 * TLS static segments must be rounded to the following requirements,
 * due to libthread stack allocation.
 */
#if	defined(_ELF64)
#define	M_TLSSTATALIGN	0x10
#else
#define	M_TLSSTATALIGN	0x08
#endif


/*
 * Other machine dependent entities
 */
#if	defined(_ELF64)
#define	M_SEGM_ALIGN	0x00010000
#else
#define	M_SEGM_ALIGN	ELF_386_MAXPGSZ
#endif

/*
 * Values for IA32 objects
 */

/*
 * Instruction encodings.
 */
#define	M_INST_JMP		0xe9
#define	M_INST_PUSHL		0x68
#define	M_SPECIAL_INST		0xff
#define	M_PUSHL_DISP		0x35
#define	M_PUSHL_REG_DISP	0xb3
#define	M_JMP_DISP_IND		0x25
#define	M_JMP_REG_DISP_IND	0xa3
#define	M_NOP			0x90

#define	M_BIND_ADJ	1		/* adjustment for end of */
					/*	elf_rtbndr() address */
#ifdef _ELF64
#define	M_WORD_ALIGN	8
#define	M_SEGM_ORIGIN	(Addr)0x00400000  /* default first segment offset */
#else

#define	M_WORD_ALIGN	4

#define	M_STACK_GAP	(0x08000000)
#define	M_STACK_PGS	(0x00048000)
#define	M_SEGM_ORIGIN	(Addr)(M_STACK_GAP + M_STACK_PGS)
#endif


/*
 * Plt and Got information; the first few .got and .plt entries are reserved
 *	PLT[0]	jump to dynamic linker
 *	GOT[0]	address of _DYNAMIC
 */
#define	M_PLT_ENTSIZE	16		/* plt entry size in bytes */
#define	M_PLT_ALIGN	M_WORD_ALIGN	/* alignment of .plt section */
#define	M_PLT_INSSIZE	6		/* single plt instruction size */
#define	M_PLT_RESERVSZ	M_PLT_ENTSIZE	/* PLT[0] reserved */

#define	M_GOT_XDYNAMIC	0		/* got index for _DYNAMIC */
#define	M_GOT_XLINKMAP	1		/* got index for link map */
#define	M_GOT_XRTLD	2		/* got index for rtbinder */
#define	M_GOT_XNumber	3		/* reserved no. of got entries */

#ifdef	_ELF64
#define	M_GOT_ENTSIZE	8		/* got entry size in bytes */
#else /* ELF32 */
#define	M_GOT_ENTSIZE	4		/* got entry size in bytes */
#endif

/*
 * Make common relocation information transparent to the common code
 */
#if	defined(_ELF64)
#define	M_REL_DT_TYPE	DT_RELA		/* .dynamic entry */
#define	M_REL_DT_SIZE	DT_RELASZ	/* .dynamic entry */
#define	M_REL_DT_ENT	DT_RELAENT	/* .dynamic entry */
#define	M_REL_DT_COUNT	DT_RELACOUNT	/* .dynamic entry */
#define	M_REL_SHT_TYPE	SHT_RELA	/* section header type */
#define	M_REL_ELF_TYPE	ELF_T_RELA	/* data buffer type */

#else /* _ELF32 */
#define	M_REL_DT_TYPE	DT_REL		/* .dynamic entry */
#define	M_REL_DT_SIZE	DT_RELSZ	/* .dynamic entry */
#define	M_REL_DT_ENT	DT_RELENT	/* .dynamic entry */
#define	M_REL_DT_COUNT	DT_RELCOUNT	/* .dynamic entry */
#define	M_REL_SHT_TYPE	SHT_REL		/* section header type */
#define	M_REL_ELF_TYPE	ELF_T_REL	/* data buffer type */

#endif /* ELF32 */

/*
 * Make common relocation types transparent to the common code
 */
#if	defined(_ELF64)
#define	M_R_NONE	R_AMD64_NONE
#define	M_R_GLOB_DAT	R_AMD64_GLOB_DAT
#define	M_R_COPY	R_AMD64_COPY
#define	M_R_RELATIVE	R_AMD64_RELATIVE
#define	M_R_JMP_SLOT	R_AMD64_JUMP_SLOT
#define	M_R_FPTR	R_AMD64_NONE
#define	M_R_ARRAYADDR	R_AMD64_GLOB_DAT
#define	M_R_NUM		R_AMD64_NUM
#else
#define	M_R_NONE	R_386_NONE
#define	M_R_GLOB_DAT	R_386_GLOB_DAT
#define	M_R_COPY	R_386_COPY
#define	M_R_RELATIVE	R_386_RELATIVE
#define	M_R_JMP_SLOT	R_386_JMP_SLOT
#define	M_R_FPTR	R_386_NONE
#define	M_R_ARRAYADDR	R_386_GLOB_DAT
#define	M_R_NUM		R_386_NUM
#endif

/*
 * The following are defined as M_R_NONE so that checks
 * for these relocations can be performed in common code - although
 * the checks are really only relevant to SPARC.
 */
#define	M_R_REGISTER	M_R_NONE

/*
 * DT_REGISTER is not valid on i386 or amd64
 */
#define	M_DT_REGISTER	0xffffffff

/*
 * Make plt section information transparent to the common code.
 */
#define	M_PLT_SHF_FLAGS	(SHF_ALLOC | SHF_EXECINSTR)

/*
 * Make data segment information transparent to the common code.
 */
#ifdef _ELF64
#define	M_DATASEG_PERM	(PF_R | PF_W)
#else
#define	M_DATASEG_PERM	(PF_R | PF_W | PF_X)
#endif

/*
 * Define a set of identifies for special sections.  These allow the sections
 * to be ordered within the output file image.  These values should be
 * maintained consistently, where appropriate, in each platform specific header
 * file.
 *
 *  o	null identifies that this section does not need to be added to the
 *	output image (ie. shared object sections or sections we're going to
 *	recreate (sym tables, string tables, relocations, etc.)).
 *
 *  o	any user defined section will be first in the associated segment.
 *
 *  o	interp and capabilities sections are next, as these are accessed
 *	immediately the first page of the image is mapped.
 *
 *  o	the syminfo, hash, dynsym, dynstr and rel's are grouped together as
 *	these will all be accessed first by ld.so.1 to perform relocations.
 *
 *  o	the got and dynamic are grouped together as these may also be
 *	accessed first by ld.so.1 to perform relocations, fill in DT_DEBUG
 *	(executables only), and .got[0].
 *
 *  o	unknown sections (stabs, comments, etc.) go at the end.
 *
 * Note that .tlsbss/.bss are given the largest identifiers.  This insures that
 * if any unknown sections become associated to the same segment as the .bss,
 * the .bss sections are always the last section in the segment.
 */
#define	M_ID_NULL	0x00
#define	M_ID_USER	0x01

#define	M_ID_INTERP	0x03			/* SHF_ALLOC */
#define	M_ID_CAP	0x04
#define	M_ID_UNWINDHDR	0x05
#define	M_ID_UNWIND	0x06
#define	M_ID_SYMINFO	0x07
#define	M_ID_HASH	0x08
#define	M_ID_LDYNSYM	0x09			/* always right before DYNSYM */
#define	M_ID_DYNSYM	0x0a
#define	M_ID_DYNSTR	0x0b
#define	M_ID_VERSION	0x0c
#define	M_ID_DYNSORT	0x0d
#define	M_ID_REL	0x0e
#define	M_ID_PLT	0x0f			/* SHF_ALLOC + SHF_EXECISNTR */
#define	M_ID_TEXT	0x10
#define	M_ID_DATA	0x20

/*	M_ID_USER	0x02			dual entry - listed above */
#define	M_ID_GOT	0x03			/* SHF_ALLOC + SHF_WRITE */
#define	M_ID_DYNAMIC	0x05
#define	M_ID_ARRAY	0x06

#define	M_ID_UNKNOWN	0xfb			/* just before TLS */

#define	M_ID_TLS	0xfc			/* just before bss */
#define	M_ID_TLSBSS	0xfd
#define	M_ID_BSS	0xfe
#define	M_ID_LBSS	0xff

#define	M_ID_SYMTAB_NDX	0x02			/* ! SHF_ALLOC */
#define	M_ID_SYMTAB	0x03
#define	M_ID_STRTAB	0x04
#define	M_ID_DYNSYM_NDX	0x05
#define	M_ID_NOTE	0x06


#ifdef	__cplusplus
}
#endif

#endif /* _MACHDEP_X86_H */
