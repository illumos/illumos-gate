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

#ifndef	__ELFDUMP_H
#define	__ELFDUMP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<machelf.h>
#include	<debug.h>

/*
 * Local include file for elfdump.
 */
#ifdef	__cplusplus
extern "C" {
#endif

#define	FLG_DYNAMIC	0x00000001
#define	FLG_EHDR	0x00000002
#define	FLG_INTERP	0x00000004
#define	FLG_SHDR	0x00000008
#define	FLG_NOTE	0x00000010
#define	FLG_PHDR	0x00000020
#define	FLG_RELOC	0x00000040
#define	FLG_SYMBOLS	0x00000080
#define	FLG_VERSIONS	0x00000100
#define	FLG_HASH	0x00000200
#define	FLG_GOT		0x00000400
#define	FLG_SYMINFO	0x00000800
#define	FLG_MOVE	0x00001000
#define	FLG_GROUP	0x00002000
#define	FLG_CAP		0x00004000
#define	FLG_UNWIND	0x00008000
#define	FLG_SORT	0x00010000
#define	FLG_LONGNAME	0x00100000	/* not done by default */
#define	FLG_CHECKSUM	0x00200000	/* not done by default */
#define	FLG_DEMANGLE	0x00400000	/* not done by default */
#define	FLG_EVERYTHING	0x000fffff

#define	MAXNDXSIZE	10

typedef struct cache {
	Elf_Scn		*c_scn;
	Shdr		*c_shdr;
	Elf_Data	*c_data;
	char		*c_name;
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
 * Define various elfdump() functions into their 32-bit and 64-bit variants.
 */
#if	defined(_ELF64)
#define	cap			cap64
#define	checksum		checksum64
#define	dynamic			dynamic64
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

extern	void	regular32(const char *, Elf *, uint_t, char *, int);
extern	void	regular64(const char *, Elf *, uint_t, char *, int);

#ifdef	__cplusplus
}
#endif

#endif	/* __ELFDUMP_H */
