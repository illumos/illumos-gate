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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LIBELF_H
#define	_LIBELF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.9	*/

#include <sys/types.h>
#include <sys/elf.h>


#ifdef	__cplusplus
extern "C" {
#endif


#if defined(_ILP32) && (_FILE_OFFSET_BITS != 32)
#error "large files are not supported by libelf"
#endif


#undef _
#ifdef __STDC__
typedef void		Elf_Void;
#define	_(a)		a
#else
typedef char		Elf_Void;
#define	_(a)		()
#undef const
#define	const
#endif


/*
 * Commands
 */
typedef enum {
	ELF_C_NULL = 0,	/* must be first, 0 */
	ELF_C_READ,
	ELF_C_WRITE,
	ELF_C_CLR,
	ELF_C_SET,
	ELF_C_FDDONE,
	ELF_C_FDREAD,
	ELF_C_RDWR,
	ELF_C_WRIMAGE,
	ELF_C_IMAGE,
	ELF_C_NUM	/* must be last */
} Elf_Cmd;


/*
 * Flags
 */
#define	ELF_F_DIRTY	0x1
#define	ELF_F_LAYOUT	0x4


/*
 * File types
 */
typedef enum {
	ELF_K_NONE = 0,	/* must be first, 0 */
	ELF_K_AR,
	ELF_K_COFF,
	ELF_K_ELF,
	ELF_K_NUM	/* must be last */
} Elf_Kind;


/*
 * Translation types
 */
typedef enum {
	ELF_T_BYTE = 0,	/* must be first, 0 */
	ELF_T_ADDR,
	ELF_T_DYN,
	ELF_T_EHDR,
	ELF_T_HALF,
	ELF_T_OFF,
	ELF_T_PHDR,
	ELF_T_RELA,
	ELF_T_REL,
	ELF_T_SHDR,
	ELF_T_SWORD,
	ELF_T_SYM,
	ELF_T_WORD,
	ELF_T_VDEF,
	ELF_T_VNEED,
	ELF_T_SXWORD,
	ELF_T_XWORD,
	ELF_T_SYMINFO,
	ELF_T_NOTE,
	ELF_T_MOVE,
	ELF_T_MOVEP,
	ELF_T_CAP,
	ELF_T_NUM	/* must be last */
} Elf_Type;


typedef struct Elf	Elf;
typedef struct Elf_Scn	Elf_Scn;


/*
 * Archive member header
 */
typedef struct {
	char		*ar_name;
	time_t		ar_date;
	uid_t		ar_uid;
	gid_t 		ar_gid;
	mode_t		ar_mode;
	off_t		ar_size;
	char 		*ar_rawname;
} Elf_Arhdr;


/*
 * Archive symbol table
 */
typedef struct {
	char		*as_name;
	size_t		as_off;
	unsigned long	as_hash;
} Elf_Arsym;


/*
 * Data descriptor
 */
typedef struct {
	Elf_Void	*d_buf;
	Elf_Type	d_type;
	size_t		d_size;
	off_t		d_off;		/* offset into section */
	size_t		d_align;	/* alignment in section */
	unsigned	d_version;	/* elf version */
} Elf_Data;


/*
 * Function declarations
 */
Elf		*elf_begin	_((int, Elf_Cmd, Elf *));
int		elf_cntl	_((Elf *, Elf_Cmd));
int		elf_end		_((Elf *));
const char	*elf_errmsg	_((int));
int		elf_errno	_((void));
void		elf_fill	_((int));
unsigned	elf_flagdata	_((Elf_Data *, Elf_Cmd, unsigned));
unsigned	elf_flagehdr	_((Elf *, Elf_Cmd,  unsigned));
unsigned	elf_flagelf	_((Elf *, Elf_Cmd, unsigned));
unsigned	elf_flagphdr	_((Elf *, Elf_Cmd, unsigned));
unsigned	elf_flagscn	_((Elf_Scn *, Elf_Cmd, unsigned));
unsigned	elf_flagshdr	_((Elf_Scn *, Elf_Cmd, unsigned));
size_t		elf32_fsize	_((Elf_Type, size_t, unsigned));
Elf_Arhdr	*elf_getarhdr	_((Elf *));
Elf_Arsym	*elf_getarsym	_((Elf *, size_t *));
off_t		elf_getbase	_((Elf *));
Elf_Data	*elf_getdata	_((Elf_Scn *, Elf_Data *));
Elf32_Ehdr	*elf32_getehdr	_((Elf *));
char		*elf_getident	_((Elf *, size_t *));
Elf32_Phdr	*elf32_getphdr	_((Elf *));
Elf_Scn		*elf_getscn	_((Elf *elf, size_t));
Elf32_Shdr	*elf32_getshdr	_((Elf_Scn *));
int		elf_getphnum	_((Elf *, size_t *));
int		elf_getshnum	_((Elf *, size_t *));
int		elf_getshstrndx	_((Elf *, size_t *));
unsigned long	elf_hash	_((const char *));
uint_t		elf_sys_encoding _((void));
long		elf32_checksum	_((Elf *));
Elf_Kind	elf_kind	_((Elf *));
Elf		*elf_memory	_((char *, size_t));
size_t		elf_ndxscn	_((Elf_Scn *));
Elf_Data	*elf_newdata	_((Elf_Scn *));
Elf32_Ehdr	*elf32_newehdr	_((Elf *));
Elf32_Phdr	*elf32_newphdr	_((Elf *, size_t));
Elf_Scn		*elf_newscn	_((Elf *));
Elf_Scn		*elf_nextscn	_((Elf *, Elf_Scn *));
Elf_Cmd		elf_next	_((Elf *));
size_t		elf_rand	_((Elf *, size_t));
Elf_Data	*elf_rawdata	_((Elf_Scn *, Elf_Data *));
char		*elf_rawfile	_((Elf *, size_t *));
char		*elf_strptr	_((Elf *, size_t, size_t));
off_t		elf_update	_((Elf *, Elf_Cmd));
unsigned	elf_version	_((unsigned));
Elf_Data	*elf32_xlatetof	_((Elf_Data *, const Elf_Data *, unsigned));
Elf_Data	*elf32_xlatetom	_((Elf_Data *, const Elf_Data *, unsigned));

#if defined(_LP64) || defined(_LONGLONG_TYPE)
size_t		elf64_fsize	_((Elf_Type, size_t, unsigned));
Elf64_Ehdr	*elf64_getehdr	_((Elf *));
Elf64_Phdr	*elf64_getphdr	_((Elf *));
Elf64_Shdr	*elf64_getshdr	_((Elf_Scn *));
long		elf64_checksum	_((Elf *));
Elf64_Ehdr	*elf64_newehdr	_((Elf *));
Elf64_Phdr	*elf64_newphdr	_((Elf *, size_t));
Elf_Data	*elf64_xlatetof	_((Elf_Data *, const Elf_Data *, unsigned));
Elf_Data	*elf64_xlatetom	_((Elf_Data *, const Elf_Data *, unsigned));
#endif /* (defined(_LP64) || defined(_LONGLONG_TYPE) */

#undef	_

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBELF_H */
