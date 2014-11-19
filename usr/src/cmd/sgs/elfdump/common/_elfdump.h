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

#ifndef	__ELFDUMP_H
#define	__ELFDUMP_H

#include	<_machelf.h>
#include	<debug.h>

/*
 * Local include file for elfdump.
 */
#ifdef	__cplusplus
extern "C" {
#endif

/*
 * flags: This is a bitmask that controls elfdump's operations. There
 * are three categories of flag:
 *
 *	SHOW - Specify categories of things in the ELF object to display.
 *	CALC - Compute something based on the contents of the ELF object.
 *	CTL - Control options specify general options that are not
 *		specific to any specific part of the ELF object, but
 *		which apply at a higher level.
 *
 * To simplify masking these categories, they are assigned bit ranges
 * as follows:
 *	SHOW: Bottom 24-bits
 *	CALC: Upper 2 bits of most significant byte
 *	CTL: Lower 6 bits of most significant byte
 */
#define	FLG_SHOW_DYNAMIC	0x00000001
#define	FLG_SHOW_EHDR		0x00000002
#define	FLG_SHOW_INTERP		0x00000004
#define	FLG_SHOW_SHDR		0x00000008
#define	FLG_SHOW_NOTE		0x00000010
#define	FLG_SHOW_PHDR		0x00000020
#define	FLG_SHOW_RELOC		0x00000040
#define	FLG_SHOW_SYMBOLS	0x00000080
#define	FLG_SHOW_VERSIONS	0x00000100
#define	FLG_SHOW_HASH		0x00000200
#define	FLG_SHOW_GOT		0x00000400
#define	FLG_SHOW_SYMINFO	0x00000800
#define	FLG_SHOW_MOVE		0x00001000
#define	FLG_SHOW_GROUP		0x00002000
#define	FLG_SHOW_CAP		0x00004000
#define	FLG_SHOW_UNWIND		0x00008000
#define	FLG_SHOW_SORT		0x00010000

#define	FLG_CTL_LONGNAME	0x01000000
#define	FLG_CTL_DEMANGLE	0x02000000
#define	FLG_CTL_FAKESHDR	0x04000000
#define	FLG_CTL_MATCH		0x08000000
#define	FLG_CTL_OSABI		0x10000000

#define	FLG_CALC_CHECKSUM	0x40000000

/* Bitmasks that isolate the parts of a flag value */
#define	FLG_MASK_SHOW		0x00ffffff
#define	FLG_MASK_CTL		0x3f000000
#define	FLG_MASK_CALC		0xc0000000

/*
 * Mask that selects the show flags that do not require the ELF
 * object to have a section header array.
 */
#define	FLG_MASK_SHOW_NOSHDR	(FLG_SHOW_EHDR | FLG_SHOW_PHDR)

/*
 * Masks to select the flags that require the ELF object to
 * have a section header array, within each flag type.
 */
#define	FLG_MASK_SHOW_SHDR	(FLG_MASK_SHOW & ~FLG_MASK_SHOW_NOSHDR)
#define	FLG_MASK_CALC_SHDR	FLG_CALC_CHECKSUM


/* Size of buffer used for formatting an index into textual representation */
#define	MAXNDXSIZE	10

typedef struct cache {
	Elf_Scn		*c_scn;
	Shdr		*c_shdr;
	Elf_Data	*c_data;
	char		*c_name;
	int		c_ndx;		/* Section index */
} Cache;

typedef struct got_info {
	Word		g_reltype;	/* it will never happen, but */
					/* support mixed relocations */
	void		*g_rel;
	const char	*g_symname;
} Got_info;

extern	const Cache	 cache_init;

extern	void		failure(const char *, const char *);
extern	const char	*demangle(const char *, uint_t);


/*
 * Flags for the match() function:
 *	MATCH_F_STRICT
 *		A strict match requires an explicit match to
 *		a user specified match (-I, -N, -T) option. A
 *		non-strict match also succeeds if the match
 *		list is empty.
 *
 *	MATCH_F_PHDR
 *		The match item is a program header. If this
 *		flag is not set, the match item is a section
 *		header.
 *
 *	MATCH_F_NAME
 *		The name parameter contains valid information.
 *
 *	MATCH_F_NDX
 *		The ndx argument contains valid information
 *
 *	MATCH_F_TYPE
 *		The type argument contains valid information
 */
typedef enum {
	MATCH_F_STRICT =	1,
	MATCH_F_PHDR =		2,
	MATCH_F_NAME =		4,
	MATCH_F_NDX =		8,
	MATCH_F_TYPE =		16
} match_flags_t;

/* It is common for calls to match() to specify all three arguments */
#define	MATCH_F_ALL	(MATCH_F_NAME | MATCH_F_NDX | MATCH_F_TYPE)

extern int	match(match_flags_t, const char *, uint_t, uint_t);

/*
 * Possible return values from corenote()
 */
typedef enum {
	CORENOTE_R_OK = 0,	/* Note data successfully displayed */
	CORENOTE_R_OK_DUMP = 1,	/* Note OK, but not handled. Display Hex dump */
	CORENOTE_R_BADDATA = 2,	/* Note data truncated or otherwise malformed */
	CORENOTE_R_BADARCH = 3,	/* core file note code does not contain */
				/*	support for given architecture */
	CORENOTE_R_BADTYPE = 4	/* Unknown note type */
} corenote_ret_t;

/*
 * Define various elfdump() functions into their 32-bit and 64-bit variants.
 */
#if	defined(_ELF64)
#define	cap			cap64
#define	checksum		checksum64
#define	dynamic			dynamic64
#define	fake_shdr_cache		fake_shdr_cache64
#define	fake_shdr_cache_free	fake_shdr_cache_free64
#define	got			got64
#define	group			group64
#define	hash			hash64
#define	interp			interp64
#define	move			move64
#define	note			note64
#define	note_entry		note_entry64
#define	regular			regular64
#define	reloc			reloc64
#define	sections		sections64
#define	string			string64
#define	symbols			symbols64
#define	syminfo			syminfo64
#define	symlookup		symlookup64
#define	unwind			unwind64
#define	versions		versions64
#define	version_def		version_def64
#define	version_need		version_need64
#else
#define	cap			cap32
#define	checksum		checksum32
#define	dynamic			dynamic32
#define	fake_shdr_cache		fake_shdr_cache32
#define	fake_shdr_cache_free	fake_shdr_cache_free32
#define	got			got32
#define	group			group32
#define	hash			hash32
#define	interp			interp32
#define	move			move32
#define	note			note32
#define	note_entry		note_entry32
#define	regular			regular32
#define	reloc			reloc32
#define	sections		sections32
#define	string			string32
#define	symbols			symbols32
#define	syminfo			syminfo32
#define	symlookup		symlookup32
#define	unwind			unwind32
#define	versions		versions32
#define	version_def		version_def32
#define	version_need		version_need32
#endif

extern	corenote_ret_t	corenote(Half, int, Word, const char *, Word);
extern	void	dump_eh_frame(const char *, char *, uchar_t *, size_t, uint64_t,
		    Half e_machine, uchar_t *e_ident, uint64_t gotaddr);
extern	void	dump_hex_bytes(const void *, size_t, int, int, int);

extern	int	fake_shdr_cache32(const char *, int, Elf *, Elf32_Ehdr *,
		    Cache **, size_t *);
extern	int	fake_shdr_cache64(const char *, int, Elf *, Elf64_Ehdr *,
		    Cache **, size_t *);

extern	void	fake_shdr_cache_free32(Cache *, size_t);
extern	void	fake_shdr_cache_free64(Cache *, size_t);

extern	int	regular32(const char *, int, Elf *, uint_t, const char *, int,
		    uchar_t);
extern	int	regular64(const char *, int, Elf *, uint_t, const char *, int,
		    uchar_t);

#ifdef	__cplusplus
}
#endif

#endif	/* __ELFDUMP_H */
