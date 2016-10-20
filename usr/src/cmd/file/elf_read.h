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

#ifndef _ELF_READ_H
#define	_ELF_READ_H

#define	BUFSZ 128
typedef struct Elf_Info {
	boolean_t	dynamic;	/* dymanically linked? */
	unsigned	core_type;	/* core? what type of core? */
	unsigned	stripped;	/* symtab, debug info */
	unsigned	flags;		/* e_flags */
	unsigned	machine;	/* e_machine */
	unsigned	type;		/* e_type */
	int		elffd;		/* fd of file being processed */
	char		fname[PRFNSZ];	/* name of process that dumped core */
	char		cap_str[BUFSZ];	/* hw/sw capabilities */
	char		*file;		/* file being processed */
	boolean_t	kmod;
} Elf_Info;

/* values for Elf_Info.stripped */
#define	E_DBGINF	0x01
#define	E_SYMTAB	0x02
#define	E_NOSTRIP	0x03

/* values for Elf_Info.core_type; */
#define	EC_NOTCORE	0x0
#define	EC_OLDCORE	0x1
#define	EC_NEWCORE	0x2

/* elf file processing errors */
#define	ELF_ERR_ELFCAP1		gettext("%s: %s zero size or zero entry ELF " \
	"section - ELF capabilities ignored\n")
#define	ELF_ERR_ELFCAP2		gettext("%s: %s: can't read ELF capabilities " \
	"data - ELF capabilities ignored\n")
#define	ELF_ERR_DYNAMIC1	gettext("%s: %s zero size or zero entry ELF " \
	"section - ELF dynamic tags ignored\n")
#define	ELF_ERR_DYNAMIC2	gettext("%s: %s: can't read ELF dynamic " \
	"data - ELF dynamic tags ignored\n")

extern int is_in_list(char *str);

/* return status for elf_read and its helper functions */
#define	ELF_READ_OKAY 1
#define	ELF_READ_FAIL 0

#if defined(_ELF64)

#define	Elf_Ehdr	Elf64_Ehdr
#define	Elf_Shdr	Elf64_Shdr
#define	Elf_Phdr	Elf64_Phdr
#define	Elf_Cap		Elf64_Cap
#define	Elf_Nhdr	Elf64_Nhdr
#define	Elf_Word	Elf64_Word
#define	Elf_Dyn		Elf64_Dyn

#define	elf_read	elf_read64
#define	elf_xlatetom	elf64_xlatetom
#define	elf_fsize	elf64_fsize
#define	get_class	get_class64
#define	get_version	get_version64
#define	get_format	get_format64

#else

#define	Elf_Ehdr	Elf32_Ehdr
#define	Elf_Shdr	Elf32_Shdr
#define	Elf_Phdr	Elf32_Phdr
#define	Elf_Cap		Elf32_Cap
#define	Elf_Nhdr	Elf32_Nhdr
#define	Elf_Word	Elf32_Word
#define	Elf_Dyn		Elf32_Dyn

#define	elf_read	elf_read32
#define	elf_xlatetom	elf32_xlatetom
#define	elf_fsize	elf32_fsize
#define	get_class	get_class32
#define	get_version	get_version32
#define	get_format	get_format32

#endif

/* so lint can understand elf_read64 is defined */
#ifdef lint
#define	elf_read64	elf_read
#endif /* lint */

#endif /* _ELF_READ_H */
