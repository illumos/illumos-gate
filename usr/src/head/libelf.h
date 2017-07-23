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
/*	  All Rights Reserved	*/

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2014 PALO, Richard. All rights reserved.
 */

#ifndef _LIBELF_H
#define	_LIBELF_H

#include <sys/types.h>
#include <sys/elf.h>


#ifdef	__cplusplus
extern "C" {
#endif


#if defined(_ILP32) && (_FILE_OFFSET_BITS != 32)
#error "large files are not supported by libelf"
#endif

typedef void	Elf_Void;

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
	gid_t		ar_gid;
	mode_t		ar_mode;
	off_t		ar_size;
	char		*ar_rawname;
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
Elf		*elf_begin(int, Elf_Cmd, Elf *);
int		elf_cntl(Elf *, Elf_Cmd);
int		elf_end(Elf *);
const char	*elf_errmsg(int);
int		elf_errno(void);
void		elf_fill(int);
unsigned	elf_flagdata(Elf_Data *, Elf_Cmd, unsigned);
unsigned	elf_flagehdr(Elf *, Elf_Cmd,  unsigned);
unsigned	elf_flagelf(Elf *, Elf_Cmd, unsigned);
unsigned	elf_flagphdr(Elf *, Elf_Cmd, unsigned);
unsigned	elf_flagscn(Elf_Scn *, Elf_Cmd, unsigned);
unsigned	elf_flagshdr(Elf_Scn *, Elf_Cmd, unsigned);
size_t		elf32_fsize(Elf_Type, size_t, unsigned);
Elf_Arhdr	*elf_getarhdr(Elf *);
Elf_Arsym	*elf_getarsym(Elf *, size_t *);
off_t		elf_getbase(Elf *);
Elf_Data	*elf_getdata(Elf_Scn *, Elf_Data *);
Elf32_Ehdr	*elf32_getehdr(Elf *);
char		*elf_getident(Elf *, size_t *);
Elf32_Phdr	*elf32_getphdr(Elf *);
Elf_Scn		*elf_getscn(Elf *elf, size_t);
Elf32_Shdr	*elf32_getshdr(Elf_Scn *);
int		elf_getphnum(Elf *, size_t *);
int		elf_getphdrnum(Elf *, size_t *);
int		elf_getshnum(Elf *, size_t *);
int		elf_getshdrnum(Elf *, size_t *);
int		elf_getshstrndx(Elf *, size_t *);
int		elf_getshdrstrndx(Elf *, size_t *);
unsigned long	elf_hash(const char *);
uint_t		elf_sys_encoding(void);
long		elf32_checksum(Elf *);
Elf_Kind	elf_kind(Elf *);
Elf		*elf_memory(char *, size_t);
size_t		elf_ndxscn(Elf_Scn *);
Elf_Data	*elf_newdata(Elf_Scn *);
Elf32_Ehdr	*elf32_newehdr(Elf *);
Elf32_Phdr	*elf32_newphdr(Elf *, size_t);
Elf_Scn		*elf_newscn(Elf *);
Elf_Scn		*elf_nextscn(Elf *, Elf_Scn *);
Elf_Cmd		elf_next(Elf *);
size_t		elf_rand(Elf *, size_t);
Elf_Data	*elf_rawdata(Elf_Scn *, Elf_Data *);
char		*elf_rawfile(Elf *, size_t *);
char		*elf_strptr(Elf *, size_t, size_t);
off_t		elf_update(Elf *, Elf_Cmd);
unsigned	elf_version(unsigned);
Elf_Data	*elf32_xlatetof(Elf_Data *, const Elf_Data *, unsigned);
Elf_Data	*elf32_xlatetom(Elf_Data *, const Elf_Data *, unsigned);

#if defined(_LP64) || defined(_LONGLONG_TYPE)
size_t		elf64_fsize(Elf_Type, size_t, unsigned);
Elf64_Ehdr	*elf64_getehdr(Elf *);
Elf64_Phdr	*elf64_getphdr(Elf *);
Elf64_Shdr	*elf64_getshdr(Elf_Scn *);
long		elf64_checksum(Elf *);
Elf64_Ehdr	*elf64_newehdr(Elf *);
Elf64_Phdr	*elf64_newphdr(Elf *, size_t);
Elf_Data	*elf64_xlatetof(Elf_Data *, const Elf_Data *, unsigned);
Elf_Data	*elf64_xlatetom(Elf_Data *, const Elf_Data *, unsigned);
#endif /* (defined(_LP64) || defined(_LONGLONG_TYPE) */

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBELF_H */
