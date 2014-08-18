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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _LINK_H
#define	_LINK_H

#include <sys/link.h>

#ifndef _ASM
#include <elf.h>
#include <sys/types.h>
#include <dlfcn.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _ASM
/*
 * ld support library calls.
 *
 * These cannot be used in a 32bit large file capable environment because
 * libelf is not large-file safe.  Only define these interfaces if we are not
 * 32bit, or not in the large file environment.
 */
#if !defined(_ILP32) || _FILE_OFFSET_BITS != 64
#include <libelf.h>
extern uint_t	ld_version(uint_t);
extern void	ld_input_done(uint_t *);

extern void	ld_start(const char *, const Elf32_Half, const char *);
extern void	ld_atexit(int);
extern void	ld_open(const char **, const char **, int *, int, Elf **,
			Elf *, size_t, const Elf_Kind);
extern void	ld_file(const char *, const Elf_Kind, int, Elf *);
extern void	ld_input_section(const char *, Elf32_Shdr **, Elf32_Word,
			Elf_Data *, Elf *, uint_t *);
extern void	ld_section(const char *, Elf32_Shdr *, Elf32_Word,
			Elf_Data *, Elf *);

#if defined(_LP64) || defined(_LONGLONG_TYPE)
extern void	ld_start64(const char *, const Elf64_Half, const char *);
extern void	ld_atexit64(int);
extern void	ld_open64(const char **, const char **, int *, int, Elf **,
			Elf *, size_t, const Elf_Kind);
extern void	ld_file64(const char *, const Elf_Kind, int, Elf *);
extern void	ld_input_section64(const char *, Elf64_Shdr **, Elf64_Word,
			Elf_Data *, Elf *, uint_t *);
extern void	ld_section64(const char *, Elf64_Shdr *, Elf64_Word,
			Elf_Data *, Elf *);

#endif /* (defined(_LP64) || defined(_LONGLONG_TYPE) */
#endif /* !defined(_ILP32) || _FILE_OFFSET_BITS != 64 */

/*
 * ld_version() version values.
 */
#define	LD_SUP_VNONE	0
#define	LD_SUP_VERSION1	1
#define	LD_SUP_VERSION2	2
#define	LD_SUP_VERSION3	3
#define	LD_SUP_VCURRENT	LD_SUP_VERSION3

/*
 * Flags passed to ld support calls.
 */
#define	LD_SUP_DERIVED		0x1	/* derived filename */
#define	LD_SUP_INHERITED	0x2	/* file inherited from .so DT_NEEDED */
#define	LD_SUP_EXTRACTED	0x4	/* file extracted from archive */
#endif

/*
 * Runtime link-map identifiers.
 */
#define	LM_ID_BASE		0x00
#define	LM_ID_LDSO		0x01
#define	LM_ID_NUM		2

#define	LM_ID_BRAND		0xfd	/* brand emulation linkmap objs */
#define	LM_ID_NONE		0xfe	/* no link map specified */
#define	LM_ID_NEWLM		0xff	/* create a new link-map */

/*
 * Runtime Link-Edit Auditing.
 */
#define	LAV_NONE		0
#define	LAV_VERSION1		1
#define	LAV_VERSION2		2
#define	LAV_VERSION3		3
#define	LAV_VERSION4		4
#define	LAV_VERSION5		5
#define	LAV_CURRENT		LAV_VERSION5
#define	LAV_NUM			6

/*
 * Flags that can be or'd into the la_objopen() return code
 */
#define	LA_FLG_BINDTO		0x0001	/* audit symbinds TO this object */
#define	LA_FLG_BINDFROM		0x0002	/* audit symbinding FROM this object */

/*
 * Flags that can be or'd into the 'flags' argument of la_symbind()
 */
#define	LA_SYMB_NOPLTENTER	0x0001	/* disable pltenter for this symbol */
#define	LA_SYMB_NOPLTEXIT	0x0002	/* disable pltexit for this symbol */
#define	LA_SYMB_STRUCTCALL	0x0004	/* this function call passes a */
					/*	structure as it's return code */
#define	LA_SYMB_DLSYM		0x0008	/* this symbol bindings is due to */
					/*	a call to dlsym() */
#define	LA_SYMB_ALTVALUE	0x0010	/* alternate symbol binding returned */
					/*	by la_symbind() */

/*
 * Flags that describe the object passed to la_objsearch()
 */
#define	LA_SER_ORIG		0x001	/* original (needed) name */
#define	LA_SER_LIBPATH		0x002	/* LD_LIBRARY_PATH entry prepended */
#define	LA_SER_RUNPATH		0x004	/* runpath entry prepended */
#define	LA_SER_CONFIG		0x008	/* configuration entry prepended */
#define	LA_SER_DEFAULT		0x040	/* default path prepended */
#define	LA_SER_SECURE		0x080	/* default (secure) path prepended */

#define	LA_SER_MASK		0xfff	/* mask of known flags */

/*
 * Flags that describe the la_activity()
 */
#define	LA_ACT_CONSISTENT	0x00	/* add/deletion of objects complete */
#define	LA_ACT_ADD		0x01	/* objects being added */
#define	LA_ACT_DELETE		0x02	/* objects being deleted */
#define	LA_ACT_MAX		3


#ifndef	_KERNEL
#ifndef	_ASM

#if defined(_LP64)
typedef long	lagreg_t;
#else
typedef int	lagreg_t;
#endif

struct _la_sparc_regs {
	lagreg_t	lr_rego0;
	lagreg_t	lr_rego1;
	lagreg_t	lr_rego2;
	lagreg_t	lr_rego3;
	lagreg_t	lr_rego4;
	lagreg_t	lr_rego5;
	lagreg_t	lr_rego6;
	lagreg_t	lr_rego7;
};

#if defined(_LP64)
typedef struct _la_sparc_regs	La_sparcv9_regs;
typedef struct {
	lagreg_t	lr_rsp;
	lagreg_t	lr_rbp;
	lagreg_t	lr_rdi;	    /* arg1 */
	lagreg_t	lr_rsi;	    /* arg2 */
	lagreg_t	lr_rdx;	    /* arg3 */
	lagreg_t	lr_rcx;	    /* arg4 */
	lagreg_t	lr_r8;	    /* arg5 */
	lagreg_t	lr_r9;	    /* arg6 */
} La_amd64_regs;
#else
typedef struct _la_sparc_regs	La_sparcv8_regs;
typedef struct {
	lagreg_t	lr_esp;
	lagreg_t	lr_ebp;
} La_i86_regs;
#endif

#if	!defined(_SYS_INT_TYPES_H)
#if	defined(_LP64) || defined(_I32LPx)
typedef unsigned long		uintptr_t;
#else
typedef	unsigned int		uintptr_t;
#endif
#endif


extern uint_t		la_version(uint_t);
extern void		la_activity(uintptr_t *, uint_t);
extern void		la_preinit(uintptr_t *);
extern char		*la_objsearch(const char *, uintptr_t *, uint_t);
extern uint_t		la_objopen(Link_map *, Lmid_t, uintptr_t *);
extern uint_t		la_objclose(uintptr_t *);
extern int		la_objfilter(uintptr_t *, const char *, uintptr_t *,
				uint_t);
#if	defined(_LP64)
extern uintptr_t	la_amd64_pltenter(Elf64_Sym *, uint_t, uintptr_t *,
				uintptr_t *, La_amd64_regs *,	uint_t *,
				const char *);
extern uintptr_t	la_symbind64(Elf64_Sym *, uint_t, uintptr_t *,
				uintptr_t *, uint_t *, const char *);
extern uintptr_t	la_sparcv9_pltenter(Elf64_Sym *, uint_t, uintptr_t *,
				uintptr_t *, La_sparcv9_regs *,	uint_t *,
				const char *);
extern uintptr_t	la_pltexit64(Elf64_Sym *, uint_t, uintptr_t *,
				uintptr_t *, uintptr_t, const char *);
#else  /* !defined(_LP64) */
extern uintptr_t	la_symbind32(Elf32_Sym *, uint_t, uintptr_t *,
				uintptr_t *, uint_t *);
extern uintptr_t	la_sparcv8_pltenter(Elf32_Sym *, uint_t, uintptr_t *,
				uintptr_t *, La_sparcv8_regs *, uint_t *);
extern uintptr_t	la_i86_pltenter(Elf32_Sym *, uint_t, uintptr_t *,
				uintptr_t *, La_i86_regs *, uint_t *);
extern uintptr_t	la_pltexit(Elf32_Sym *, uint_t, uintptr_t *,
				uintptr_t *, uintptr_t);
#endif /* _LP64 */

/*
 * The ElfW() macro is a GNU/Linux feature, provided as support for
 * the dl_phdr_info structure used by dl_phdr_iterate(), which also
 * originated under Linux. Given an ELF data type, without the ElfXX_
 * prefix, it supplies the appropriate prefix (Elf32_ or Elf64_) for
 * the ELFCLASS of the code being compiled.
 *
 * Note that ElfW() is not suitable in situations in which the ELFCLASS
 * of the code being compiled does not match that of the objects that
 * code is intended to operate on (e.g. a 32-bit link-editor building
 * a 64-bit object). The macros defined in <sys/machelf.h> are
 * recommended in such cases.
 */
#ifdef _LP64
#define	ElfW(type)	Elf64_ ## type
#else
#define	ElfW(type)	Elf32_ ## type
#endif

/*
 * The callback function to dl_interate_phdr() receives a pointer
 * to a structure of this type.
 *
 * dlpi_addr is defined such that the address of any segment in
 * the program header array can be calculated as:
 *
 *	addr == info->dlpi_addr + info->dlpi_phdr[x].p_vaddr;
 *
 * It is therefore 0 for ET_EXEC objects, and the base address at
 * which the object is mapped otherwise.
 */
struct dl_phdr_info {
	ElfW(Addr)		dlpi_addr;	/* Base address of object */
	const char		*dlpi_name;	/* Null-terminated obj name */
	const ElfW(Phdr)	*dlpi_phdr;	/* Ptr to ELF program hdr arr */
	ElfW(Half)		dlpi_phnum;	/* # of items in dlpi_phdr[] */

	/*
	 * Note: Following members were introduced after the first version
	 * of this structure was available.  The dl_iterate_phdr() callback
	 * function is passed a 'size' argument giving the size of the info
	 * structure, and must compare that size to the offset of these fields
	 * before accessing them to ensure that they are present.
	 */

	/* Incremented when a new object is mapped into the process */
	u_longlong_t		dlpi_adds;
	/* Incremented when an object is unmapped from the process */
	u_longlong_t		dlpi_subs;
};

extern  int dl_iterate_phdr(int (*)(struct dl_phdr_info *, size_t, void *),
	    void *);

#endif	/* _ASM */
#endif /* _KERNEL */


#ifdef __cplusplus
}
#endif

#endif	/* _LINK_H */
