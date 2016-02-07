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
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 */
#ifndef	_A_DOT_OUT_DOT_H
#define	_A_DOT_OUT_DOT_H

#include <sys/types.h>
#include <sys/null.h>
#include <sys/mman.h>
#include <a.out.h>
#include <_rtld.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	max(a, b)	((a) < (b) ? (b) : (a))

typedef struct link_dynamic	Link_dynamic;

/*
 * Extern functions for a.out format file class.
 */
extern	ulong_t	aout_bndr(caddr_t);
extern	int	aout_get_mmap(Lm_list *, mmapobj_result_t *);
extern	int	aout_lookup_sym(Slookup *, Sresult *, uint_t *, int *);
extern	Rt_map	*aout_new_lmp(Lm_list *, Aliste, Fdesc *, Addr, size_t, void *,
		    Rt_map *, int *);
extern	void	aout_plt_write(caddr_t, ulong_t);
extern	int	aout_reloc(Rt_map *, uint_t, int *, APlist **);
extern	void	aout_rtbndr(caddr_t);
extern	Fct	*aout_verify(caddr_t, size_t, Fdesc *, const char *,
		    Rej_desc *);

/*
 * Private data for an a.out format file class.
 */
typedef struct _rt_aout_private {
	struct link_dynamic	*lm_ld;		/* 4.x aout dynamic pointer */
	struct ld_private	*lm_lpd;	/* private aout object area */
} Rt_aoutp;

/*
 * Special defines for a.out format file class.
 */
#define	N_UNDF	0x0		/* undefined */
#define	N_ABS	0x2		/* absolute */
#define	N_COMM	0x12		/* common (internal to ld) */
#define	N_EXT	01		/* external bit, or'ed in */

/*
 * Format of a symbol table entry.
 */
struct	nlist {
	union {
		char	*n_name;		/* for use when in-core */
		long	n_strx;		/* index into file string table */
	} n_un;
	uchar_t 	n_type;		/* type flag (N_TEXT,..)  */
	char		n_other;	/* unused */
	short		n_desc;		/* see <stab.h> */
	ulong_t		n_value;	/* value of symbol (or sdb offset) */
};

/*
 * Link editor public definitions.
 */

#ifndef _link_h
#define	_link_h

/*
 * Structure describing logical name and requirements on an object
 * which is to be loaded dynamically.
 */
struct old_link_object {
	char	*lo_name;		/* name of object */
	int	lo_library : 1,		/* searched for by library rules */
		lo_unused : 31;
	short	lo_major;		/* major version number */
	short	lo_minor;		/* minor version number */
};

struct link_object {
	long	lo_name;		/* name (often relative) */
	int	lo_library : 1,		/* searched for by library rules */
		lo_unused : 31;
	short	lo_major;		/* major version number */
	short	lo_minor;		/* minor version number */
	long	lo_next;		/* next one (often relative) */
};
typedef	struct	link_object Lnk_obj;

/*
 * Structure describing name and placement of dynamically loaded
 * objects in a process' address space.
 */
typedef struct a_link_map	A_link_map;

struct a_link_map {
	caddr_t	lm_addr;		/* address at which object mapped */
	char	*lm_name;		/* full name of loaded object */
	struct	a_link_map *lm_next;	/* next object in map */
	struct	link_object *lm_lop;	/* link object that got us here */
	caddr_t lm_lob;			/* base address for said link object */
	int	lm_rwt : 1;		/* text is read/write */
	struct	link_dynamic *lm_ld;	/* dynamic structure */
	caddr_t	lm_lpd;			/* loader private data */
};

/*
 * Version 1 of dynamic linking information.  With the exception of
 * ld_loaded (determined at execution time) and ld_stab_hash (a special
 * case of relocation handled at execution time), the values in this
 * structure reflect offsets from the containing link_dynamic structure.
 */
struct link_dynamic_1 {
	struct	a_link_map *ld_loaded;	/* list of loaded objects */
	long	ld_need;		/* list of needed objects */
	long	ld_rules;		/* search rules for library objects */
	long	ld_got;			/* global offset table */
	long	ld_plt;			/* procedure linkage table */
	long	ld_rel;			/* relocation table */
	long	ld_hash;		/* symbol hash table */
	long	ld_stab;		/* symbol table itself */
	long	(*ld_stab_hash)();	/* "pointer" to symbol hash function */
	long	ld_buckets;		/* number of hash buckets */
	long	ld_symbols;		/* symbol strings */
	long	ld_symb_size;		/* size of symbol strings */
	long	ld_text;		/* size of text area */
};

struct link_dynamic_2 {
	struct	a_link_map *ld_loaded;	/* list of loaded objects */
	long	ld_need;		/* list of needed objects */
	long	ld_rules;		/* search rules for library objects */
	long	ld_got;			/* global offset table */
	long	ld_plt;			/* procedure linkage table */
	long	ld_rel;			/* relocation table */
	long	ld_hash;		/* symbol hash table */
	long	ld_stab;		/* symbol table itself */
	long	(*ld_stab_hash)();	/* "pointer" to symbol hash function */
	long	ld_buckets;		/* number of hash buckets */
	long	ld_symbols;		/* symbol strings */
	long	ld_symb_size;		/* size of symbol strings */
	long	ld_text;		/* size of text area */
	long	ld_plt_sz;		/* size of procedure linkage table */
};

/*
 * Structure pointing to run time allocated common symbols and
 * its string.
 */
struct rtc_symb {
	struct	nlist *rtc_sp;		/* symbol for common */
	struct	rtc_symb *rtc_next;	/* next common */
};

/*
 * Debugger interface structure.
 */
struct 	ld_debug {
	int	ldd_version;		/* version # of interface */
	int	ldd_in_debugger;	/* a debugger is running us */
	int	ldd_sym_loaded;		/* we loaded some symbols */
	char    *ldd_bp_addr;		/* place for ld-generated bpt */
	int	ldd_bp_inst;		/* instruction which was there */
	struct rtc_symb *ldd_cp;	/* commons we built */
};

/*
 * Structure associated with each object which may be or which requires
 * execution-time link editing.  Used by the run-time linkage editor to
 * identify needed objects and symbol definitions and references.
 */
struct 	old_link_dynamic {
	int	ld_version;		/* version # of this structure */
	union {
		struct link_dynamic_1 ld_1;
	} ld_un;

	int	in_debugging;
	int	sym_loaded;
	char    *bp_addr;
	int	bp_inst;
	struct rtc_symb *cp; 		/* pointer to an array of runtime */
					/* allocated common symbols. */
};

struct	link_dynamic {
	int	ld_version;		/* version # of this structure */
	struct 	ld_debug *ldd;
	union {
		struct link_dynamic_1 *ld_1;
		struct link_dynamic_2 *ld_2;
	} ld_un;
};


/*
 * Get size of relocations.
 */
#define	GETGOTSZ(x)	(x->ld_version < 2 ?				\
			((struct old_link_dynamic *)x)->v1.ld_plt -	\
			((struct old_link_dynamic *)x)->v1.ld_got :	\
			(x)->v2->ld_plt - (x)->v2->ld_got)

#define	GETPLTSZ(x)	(x->ld_version < 2 ?				\
			((struct old_link_dynamic *)x)->v1.ld_rel -	\
			((struct old_link_dynamic *)x)->v1.ld_plt :	\
			(x)->v2->ld_rel - (x)->v2->ld_plt)

#define	GETRELSZ(x)	(x->ld_version < 2 ?				\
			((struct old_link_dynamic *)x)->v1.ld_hash -	\
			((struct old_link_dynamic *)x)->v1.ld_rel :	\
			(x)->v2->ld_hash - (x)->v2->ld_rel)

#define	GETHASHSZ(x)	(x->ld_version < 2 ?				\
			((struct old_link_dynamic *)x)->v1.ld_stab -	\
			((struct old_link_dynamic *)x)->v1.ld_hash :	\
			(x)->v2->ld_stab - (x)->v2->ld_hash)

#define	GETSTABSZ(x)	(x->ld_version < 2 ?				\
			((struct old_link_dynamic *)x)->v1.ld_symbols -\
			((struct old_link_dynamic *)x)->v1.ld_stab :	\
			(x)->v2->ld_symbols - (x)->v2->ld_stab)

#undef v2
#undef v1

#endif /* !_link_h */

#define	MAIN_BASE 0x2000	/* base address of a.out in 4.x system */

/*
 * Macros for getting to linker a.out format private data.
 */
#define	AOUTPRV(X)	((X)->rt_priv)
#define	AOUTDYN(X)	(((Rt_aoutp *)(X)->rt_priv)->lm_ld)
#define	LM2LP(X)	((struct ld_private *)((Rt_aoutp *) \
				(X)->rt_priv)->lm_lpd)
#define	TEXTBASE(X)	(LM2LP(X)->lp_textbase)

/*
 * Most of the above macros are used from AOUT specific routines, however there
 * are a couple of instances where we need to ensure the file being processed
 * is AOUT before dereferencing the macro.
 */
#define	THIS_IS_AOUT(X)		(FCT(X) == &aout_fct)

/*
 * Code collapsing macros.
 */
#define	v2 ld_un.ld_2
#define	v1 ld_un.ld_1
#define	JMPOFF(x)	(x)->v2->ld_plt
#define	RELOCOFF(x)	(x)->v2->ld_rel
#define	HASHOFF(x)	(x)->v2->ld_hash
#define	SYMOFF(x)	(x)->v2->ld_stab
#define	STROFF(x)	(x)->v2->ld_symbols

struct jbind {
	int	jb_inst[3];	/* need 4 instructions for jump slot */
};

struct fshash {
	int	fssymbno;	/* ordinal symbol number */
	int	next;		/* index to the hash array pointed by fs_hash */
};

/*
 * Sparc relocation types.
 */
enum reloc_type
{
	RELOC_8,	RELOC_16,	RELOC_32,	/* simplest relocs */
	RELOC_DISP8,	RELOC_DISP16,	RELOC_DISP32,	/* Disp's (pc-rel) */
	RELOC_WDISP30,	RELOC_WDISP22,			/* SR word disp's */
	RELOC_HI22,	RELOC_22,			/* SR 22-bit relocs */
	RELOC_13,	RELOC_LO10,			/* SR 13&10-bit reloc */
	RELOC_SFA_BASE,	RELOC_SFA_OFF13,		/* SR S.F.A. relocs */
	RELOC_BASE10,	RELOC_BASE13,	RELOC_BASE22,	/* base_relative pic */
	RELOC_PC10,	RELOC_PC22,			/* special pc-rel pic */
	RELOC_JMP_TBL,					/* jmp_tbl_rel in pic */
	RELOC_SEGOFF16,					/* Shlib off-in-seg */
	RELOC_GLOB_DAT, RELOC_JMP_SLOT, RELOC_RELATIVE	/* rtld relocs */
};

/*
 * Format of a relocation datum.
 */
#define	r_symbolnum 	r_index

struct	relocation_info		/* used when header.a_machtype == M_SPARC */
{
	ulong_t		r_address;	/* relocation addr (offset in seg) */
	uint_t 		r_index   :24;	/* segment index or symbol index */
	uint_t 		r_extern  : 1;	/* if F, r_index==SEG#; if T, SYM idx */
	int			  : 2;	/* <unused> */
	enum reloc_type r_type    : 5;	/* type of relocation to perform */
	long		r_addend;	/* addend for relocation value */
};

struct ld_private {
	struct	jbind *lp_plt;		/* procedure linkage table */
	struct	relocation_info *lp_rp;	/* relocation table */
	struct	fshash *lp_hash;	/* hash table */
	struct	nlist *lp_symtab;	/* symbol table */
	char	*lp_symstr;		/* symbol strings */
	caddr_t	lp_textbase;		/* base address for text addressing */
	struct	nlist *(*lp_interp)();	/* link map interpreter */
	long	lp_refcnt;		/* reference count of link map */
	struct 	dl_object *lp_dlp;	/* pointer to a dlopen object */
	caddr_t	lp_symbol_base;		/* base address for symbols */
};


/*
 * Offsets of various sections of an object file.
 */
#define	PAGSIZ		0x02000
#define	SEGSIZ		PAGSIZ

#define	N_TXTOFF(x) \
	/* text segment */ \
	((x).a_magic == ZMAGIC ? 0 : sizeof (struct exec))

#define	N_SYMOFF(x) \
	/* symbol table */ \
	(N_TXTOFF(x) + (x).a_text + (x).a_data + (x).a_trsize + (x).a_drsize)

#define	SIZE(x) \
	/* round to segment size */ \
	(M_SROUND((x).a_text) + (x).a_data + (x).a_bss)

#ifdef	__cplusplus
}
#endif

#endif	/* _A_DOT_OUT_DOT_H */
