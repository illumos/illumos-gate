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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<memory.h>
#include	<debug.h>
#include	"msg.h"
#include	"_libld.h"


/*
 * The loader uses a `segment descriptor' list to describe the output
 * segments it can potentially create.   Additional segments may be added
 * using a map file.
 */
#if	defined(_ELF64)
/* Phdr packing changes under Elf64 */
static Sg_desc sg_desc[LD_NUM] = {
	{{PT_PHDR, PF_R + PF_X, 0, 0, 0, 0, 0, 0},
		MSG_ORIG(MSG_ENT_PHDR), 0, 0, NULL, NULL,
		(FLG_SG_TYPE | FLG_SG_FLAGS), NULL, 0, 0},
	{{PT_INTERP, PF_R, 0, 0, 0, 0, 0, 0},
		MSG_ORIG(MSG_ENT_INTERP), 0, 0, NULL, NULL,
		(FLG_SG_TYPE | FLG_SG_FLAGS), NULL, 0, 0},
	{{PT_SUNWCAP, PF_R, 0, 0, 0, 0, 0, 0},
		MSG_ORIG(MSG_ENT_SUNWCAP), 0, 0, NULL, NULL,
		(FLG_SG_TYPE | FLG_SG_FLAGS), NULL, 0, 0},
	{{PT_LOAD, PF_R + PF_X, 0, 0, 0, 0, 0, 0},
		MSG_ORIG(MSG_ENT_TEXT), 0, 0, NULL, NULL,
		(FLG_SG_TYPE | FLG_SG_FLAGS), NULL, 0, 0},
	{{PT_LOAD, M_DATASEG_PERM, 0, 0, 0, 0, 0, 0},
		MSG_ORIG(MSG_ENT_DATA), 0, 0, NULL, NULL,
		(FLG_SG_TYPE | FLG_SG_FLAGS), NULL, 0, 0},
	{{PT_LOAD, M_DATASEG_PERM, 0, 0, 0, 0, 0, 0},
		MSG_ORIG(MSG_ENT_BSS), 0, 0, NULL, NULL,
		(FLG_SG_TYPE | FLG_SG_FLAGS | FLG_SG_DISABLED), NULL, 0, 0},
#if	defined(__x86) && defined(_ELF64)
	{{PT_LOAD, PF_R, 0, 0, 0, 0, 0, 0},
		MSG_ORIG(MSG_ENT_LRODATA), 0, 0, NULL, NULL,
		(FLG_SG_TYPE | FLG_SG_FLAGS), NULL, 0, 0},
	{{PT_LOAD, M_DATASEG_PERM, 0, 0, 0, 0, 0, 0},
		MSG_ORIG(MSG_ENT_LDATA), 0, 0, NULL, NULL,
		(FLG_SG_TYPE | FLG_SG_FLAGS), NULL, 0, 0},
#endif
	{{PT_DYNAMIC, M_DATASEG_PERM, 0, 0, 0, 0, 0, 0},
		MSG_ORIG(MSG_ENT_DYNAMIC), 0, 0, NULL, NULL,
		(FLG_SG_TYPE | FLG_SG_FLAGS), NULL, 0, 0},
	{{PT_SUNWDTRACE, M_DATASEG_PERM | PF_X, 0, 0, 0, 0, 0, 0},
		MSG_ORIG(MSG_ENT_DTRACE), 0, 0, NULL, NULL,
		(FLG_SG_TYPE | FLG_SG_FLAGS), NULL, 0, 0},
	{{PT_SUNWBSS, 0, 0, 0, 0, 0, 0, 0},
		MSG_ORIG(MSG_ENT_SUNWBSS), 0, 0, NULL, NULL,
		FLG_SG_TYPE, NULL, 0, 0},
	{{PT_TLS, PF_R, 0, 0, 0, 0, 0, 0},
		MSG_ORIG(MSG_ENT_TLS), 0, 0, NULL, NULL,
		(FLG_SG_TYPE | FLG_SG_FLAGS), NULL, 0, 0},
#if	defined(__x86)
	{{PT_SUNW_UNWIND, PF_R, 0, 0, 0, 0, 0, 0},
		MSG_ORIG(MSG_ENT_UNWIND), 0, 0, NULL, NULL,
		(FLG_SG_TYPE | FLG_SG_FLAGS), NULL, 0, 0},
#endif
	{{PT_NOTE, 0, 0, 0, 0, 0, 0, 0},
		MSG_ORIG(MSG_ENT_NOTE), 0, 0, NULL, NULL,
		FLG_SG_TYPE, NULL, 0, 0},
	{{PT_NULL, 0, 0, 0, 0, 0, 0, 0},
		MSG_ORIG(MSG_STR_EMPTY), 0, 0, NULL, NULL,
		FLG_SG_TYPE, NULL, 0, 0}
};
#else  /* Elf32 */
static Sg_desc sg_desc[LD_NUM] = {
	{{PT_PHDR, 0, 0, 0, 0, 0, PF_R + PF_X, 0},
		MSG_ORIG(MSG_ENT_PHDR), 0, 0, NULL, NULL,
		(FLG_SG_TYPE | FLG_SG_FLAGS), NULL, 0, 0},
	{{PT_INTERP, 0, 0, 0, 0, 0, PF_R, 0},
		MSG_ORIG(MSG_ENT_INTERP), 0, 0, NULL, NULL,
		(FLG_SG_TYPE | FLG_SG_FLAGS), NULL, 0, 0},
	{{PT_SUNWCAP, 0, 0, 0, 0, 0, PF_R, 0},
		MSG_ORIG(MSG_ENT_SUNWCAP), 0, 0, NULL, NULL,
		(FLG_SG_TYPE | FLG_SG_FLAGS), NULL, 0, 0},
	{{PT_LOAD, 0, 0, 0, 0, 0, PF_R + PF_X, 0},
		MSG_ORIG(MSG_ENT_TEXT), 0, 0, NULL, NULL,
		(FLG_SG_TYPE | FLG_SG_FLAGS), NULL, 0, 0},
	{{PT_LOAD, 0, 0, 0, 0, 0, M_DATASEG_PERM, 0},
		MSG_ORIG(MSG_ENT_DATA), 0, 0, NULL, NULL,
		(FLG_SG_TYPE | FLG_SG_FLAGS), NULL, 0, 0},
	{{PT_LOAD, 0, 0, 0, 0, 0, M_DATASEG_PERM, 0},
		MSG_ORIG(MSG_ENT_BSS), 0, 0, NULL, NULL,
		(FLG_SG_TYPE | FLG_SG_FLAGS | FLG_SG_DISABLED), NULL, 0, 0},
	{{PT_DYNAMIC, 0, 0, 0, 0, 0, M_DATASEG_PERM, 0},
		MSG_ORIG(MSG_ENT_DYNAMIC), 0, 0, NULL, NULL,
		(FLG_SG_TYPE | FLG_SG_FLAGS), NULL, 0, 0},
	{{PT_SUNWDTRACE, 0, 0, 0, 0, 0, M_DATASEG_PERM, 0},
		MSG_ORIG(MSG_ENT_DTRACE), 0, 0, NULL, NULL,
		(FLG_SG_TYPE | FLG_SG_FLAGS), NULL, 0, 0},
	{{PT_SUNWBSS, 0, 0, 0, 0, 0, 0, 0},
		MSG_ORIG(MSG_ENT_SUNWBSS), 0, 0, NULL, NULL,
		FLG_SG_TYPE, NULL, 0, 0},
	{{PT_TLS, PF_R, 0, 0, 0, 0, 0, 0},
		MSG_ORIG(MSG_ENT_TLS), 0, 0, NULL, NULL,
		(FLG_SG_TYPE | FLG_SG_FLAGS), NULL, 0, 0},
	{{PT_NOTE, 0, 0, 0, 0, 0, 0, 0},
		MSG_ORIG(MSG_ENT_NOTE), 0, 0, NULL, NULL,
		FLG_SG_TYPE, NULL, 0, 0},
	{{PT_NULL, 0, 0, 0, 0, 0, 0, 0},
		MSG_ORIG(MSG_STR_EMPTY), 0, 0, NULL, NULL,
		FLG_SG_TYPE, NULL, 0, 0}
};
#endif /* Elfxx */


/*
 * The input processing of the loader involves matching the sections of its
 * input files to an `entrance descriptor definition'.  The entrance criteria
 * is different for either a static or dynamic linkage, and may even be
 * modified further using a map file.  Each entrance criteria is associated
 * with a segment descriptor, thus a mapping of input sections to output
 * segments is maintained.
 */
static const Ent_desc	ent_desc[] = {
	{{NULL, NULL}, MSG_ORIG(MSG_SCN_SUNWBSS), NULL,
		SHF_ALLOC + SHF_WRITE, SHF_ALLOC + SHF_WRITE,
		(Sg_desc *)LD_SUNWBSS, 0, FALSE},
	{{NULL, NULL}, NULL, SHT_NOTE, 0, 0,
		(Sg_desc *)LD_NOTE, 0, FALSE},
#if	defined(__x86) && defined(_ELF64)
	{{NULL, NULL}, MSG_ORIG(MSG_SCN_LRODATA), NULL,
		SHF_ALLOC + SHF_AMD64_LARGE, SHF_ALLOC + SHF_AMD64_LARGE,
		(Sg_desc *)LD_LRODATA, 0, FALSE},
#endif
	{{NULL, NULL}, NULL, NULL,
		SHF_ALLOC + SHF_WRITE, SHF_ALLOC,
		(Sg_desc *)LD_TEXT, 0, FALSE},
	{{NULL, NULL}, NULL, SHT_NOBITS,
		SHF_ALLOC + SHF_WRITE, SHF_ALLOC + SHF_WRITE,
		(Sg_desc *)LD_BSS, 0, FALSE},
#if	defined(__x86) && defined(_ELF64)
	{{NULL, NULL}, NULL, SHT_NOBITS,
		SHF_ALLOC + SHF_WRITE + SHF_AMD64_LARGE,
		SHF_ALLOC + SHF_WRITE + SHF_AMD64_LARGE,
		(Sg_desc *)LD_DATA, 0, FALSE},
	{{NULL, NULL}, NULL, NULL,
		SHF_ALLOC + SHF_WRITE + SHF_AMD64_LARGE,
		SHF_ALLOC + SHF_WRITE + SHF_AMD64_LARGE,
		(Sg_desc *)LD_LDATA, 0, FALSE},
#endif
	{{NULL, NULL}, NULL, NULL,
		SHF_ALLOC + SHF_WRITE, SHF_ALLOC + SHF_WRITE,
		(Sg_desc *)LD_DATA, 0, FALSE},
	{{NULL, NULL}, NULL, 0, 0, 0,
		(Sg_desc *)LD_EXTRA, 0, FALSE}
};

/*
 * Initialize new entrance and segment descriptors and add them as lists to
 * the output file descriptor.
 */
uintptr_t
ld_ent_setup(Ofl_desc *ofl, Xword segalign)
{
	Ent_desc	*enp;
	Sg_desc		*sgp;
	size_t		size;

	/*
	 * Initialize the elf library.
	 */
	if (elf_version(EV_CURRENT) == EV_NONE) {
		eprintf(ofl->ofl_lml, ERR_FATAL, MSG_INTL(MSG_ELF_LIBELF),
		    EV_CURRENT);
		return (S_ERROR);
	}

	/*
	 * Initialize internal Global Symbol Table AVL tree
	 */
	avl_create(&ofl->ofl_symavl, &ld_sym_avl_comp, sizeof (Sym_avlnode),
	    SGSOFFSETOF(Sym_avlnode, sav_node));

	/*
	 * The data segment permissions can differ depending on whether
	 * this object is built statically or dynamically.
	 */
	if (ofl->ofl_flags & FLG_OF_DYNAMIC) {
		sg_desc[LD_DATA].sg_phdr.p_flags = M_DATASEG_PERM;
		sg_desc[LD_SUNWBSS].sg_phdr.p_flags = M_DATASEG_PERM;
	} else {
		sg_desc[LD_DATA].sg_phdr.p_flags = M_DATASEG_PERM | PF_X;
	}

	/*
	 * Allocate and initialize writable copies of both the entrance and
	 * segment descriptors.
	 */
	if ((sgp = libld_malloc(sizeof (sg_desc))) == 0)
		return (S_ERROR);
	(void) memcpy(sgp, sg_desc, sizeof (sg_desc));
	if ((enp = libld_malloc(sizeof (ent_desc))) == 0)
		return (S_ERROR);
	(void) memcpy(enp, ent_desc, sizeof (ent_desc));

	/*
	 * Traverse the new entrance descriptor list converting the segment
	 * pointer entries to the absolute address within the new segment
	 * descriptor list.  Add each entrance descriptor to the output file
	 * list.
	 */
	for (size = 0; size < sizeof (ent_desc); size += sizeof (Ent_desc)) {
		enp->ec_segment = &sgp[(long)enp->ec_segment];
		if ((list_appendc(&ofl->ofl_ents, enp)) == 0)
			return (S_ERROR);
		enp++;
	}

	/*
	 * Traverse the new segment descriptor list adding each entry to the
	 * segment descriptor list.  For each loadable segment initialize
	 * a default alignment (ld(1) and ld.so.1 initialize this differently).
	 */
	for (size = 0; size < sizeof (sg_desc); size += sizeof (Sg_desc)) {
		Phdr	*phdr = &(sgp->sg_phdr);

		if ((list_appendc(&ofl->ofl_segs, sgp)) == 0)
			return (S_ERROR);
		if (phdr->p_type == PT_LOAD)
			phdr->p_align = segalign;

		sgp++;
	}
	return (1);
}
