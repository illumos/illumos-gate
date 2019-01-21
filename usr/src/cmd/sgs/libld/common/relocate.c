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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * set-up for relocations
 */

#define	ELF_TARGET_AMD64
#define	ELF_TARGET_SPARC

#include	<string.h>
#include	<stdio.h>
#include	<alloca.h>
#include	<debug.h>
#include	"msg.h"
#include	"_libld.h"

/*
 * Set up the relocation table flag test macros so that they use the
 * relocation table for the current target machine.
 */
#define	IS_PLT(X)	RELTAB_IS_PLT(X, ld_targ.t_mr.mr_reloc_table)
#define	IS_GOT_RELATIVE(X) \
	RELTAB_IS_GOT_RELATIVE(X, ld_targ.t_mr.mr_reloc_table)
#define	IS_GOT_PC(X)	RELTAB_IS_GOT_PC(X, ld_targ.t_mr.mr_reloc_table)
#define	IS_GOTPCREL(X)	RELTAB_IS_GOTPCREL(X, ld_targ.t_mr.mr_reloc_table)
#define	IS_GOT_BASED(X)	RELTAB_IS_GOT_BASED(X, ld_targ.t_mr.mr_reloc_table)
#define	IS_GOT_OPINS(X)	RELTAB_IS_GOT_OPINS(X, ld_targ.t_mr.mr_reloc_table)
#define	IS_GOT_REQUIRED(X) \
	RELTAB_IS_GOT_REQUIRED(X, ld_targ.t_mr.mr_reloc_table)
#define	IS_PC_RELATIVE(X) RELTAB_IS_PC_RELATIVE(X, ld_targ.t_mr.mr_reloc_table)
#define	IS_ADD_RELATIVE(X) \
	RELTAB_IS_ADD_RELATIVE(X, ld_targ.t_mr.mr_reloc_table)
#define	IS_REGISTER(X)	RELTAB_IS_REGISTER(X, ld_targ.t_mr.mr_reloc_table)
#define	IS_NOTSUP(X)	RELTAB_IS_NOTSUP(X, ld_targ.t_mr.mr_reloc_table)
#define	IS_SEG_RELATIVE(X) \
	RELTAB_IS_SEG_RELATIVE(X, ld_targ.t_mr.mr_reloc_table)
#define	IS_EXTOFFSET(X)	RELTAB_IS_EXTOFFSET(X, ld_targ.t_mr.mr_reloc_table)
#define	IS_SEC_RELATIVE(X) \
	RELTAB_IS_SEC_RELATIVE(X, ld_targ.t_mr.mr_reloc_table)
#define	IS_TLS_INS(X)	RELTAB_IS_TLS_INS(X, ld_targ.t_mr.mr_reloc_table)
#define	IS_TLS_GD(X)	RELTAB_IS_TLS_GD(X, ld_targ.t_mr.mr_reloc_table)
#define	IS_TLS_LD(X)	RELTAB_IS_TLS_LD(X, ld_targ.t_mr.mr_reloc_table)
#define	IS_TLS_IE(X)	RELTAB_IS_TLS_IE(X, ld_targ.t_mr.mr_reloc_table)
#define	IS_TLS_LE(X)	RELTAB_IS_TLS_LE(X, ld_targ.t_mr.mr_reloc_table)
#define	IS_LOCALBND(X)	RELTAB_IS_LOCALBND(X, ld_targ.t_mr.mr_reloc_table)
#define	IS_SIZE(X)	RELTAB_IS_SIZE(X, ld_targ.t_mr.mr_reloc_table)

/*
 * Structure to hold copy relocation items.
 */
typedef struct copy_rel {
	Sym_desc	*c_sdp;		/* symbol descriptor to be copied */
	Addr		c_val;		/* original symbol value */
} Copy_rel;

/*
 * For each copy relocation symbol, determine if the symbol is:
 *	1) to be *disp* relocated at runtime
 *	2) a reference symbol for *disp* relocation
 *	3) possibly *disp* relocated at ld time.
 *
 * The first and the second are serious errors.
 */
static void
is_disp_copied(Ofl_desc *ofl, Copy_rel *crp)
{
	Ifl_desc	*ifl = crp->c_sdp->sd_file;
	Sym_desc	*sdp = crp->c_sdp;
	Addr		symaddr = crp->c_val;
	Is_desc		*irel;
	Aliste		idx;
	Conv_inv_buf_t	inv_buf;

	/*
	 * This symbol may not be *disp* relocated at run time, but could
	 * already have been *disp* relocated when the shared object was
	 * created.  Warn the user.
	 */
	if ((ifl->ifl_flags & FLG_IF_DISPDONE) &&
	    (ofl->ofl_flags & FLG_OF_VERBOSE))
		ld_eprintf(ofl, ERR_WARNING, MSG_INTL(MSG_REL_DISPREL2),
		    conv_reloc_type(ifl->ifl_ehdr->e_machine,
		    ld_targ.t_m.m_r_copy, 0, &inv_buf),
		    ifl->ifl_name, demangle(sdp->sd_name));

	if ((ifl->ifl_flags & FLG_IF_DISPPEND) == 0)
		return;

	/*
	 * Traverse the input relocation sections.
	 */
	for (APLIST_TRAVERSE(ifl->ifl_relsect, idx, irel)) {
		Sym_desc	*rsdp;
		Is_desc		*trel;
		Rel		*rend, *reloc;
		Xword		rsize, entsize;

		trel = ifl->ifl_isdesc[irel->is_shdr->sh_info];
		rsize = irel->is_shdr->sh_size;
		entsize = irel->is_shdr->sh_entsize;
		reloc = (Rel *)irel->is_indata->d_buf;

		/*
		 * Decide entry size
		 */
		if ((entsize == 0) || (entsize > rsize)) {
			if (irel->is_shdr->sh_type == SHT_RELA)
				entsize = sizeof (Rela);
			else
				entsize = sizeof (Rel);
		}

		/*
		 * Traverse the relocation entries.
		 */
		for (rend = (Rel *)((uintptr_t)reloc + (uintptr_t)rsize);
		    reloc < rend;
		    reloc = (Rel *)((uintptr_t)reloc + (uintptr_t)entsize)) {
			const char	*str;
			Word		rstndx;

			if (IS_PC_RELATIVE(ELF_R_TYPE(reloc->r_info,
			    ld_targ.t_m.m_mach)) == 0)
				continue;

			/*
			 * Determine if symbol is referenced from a relocation.
			 */
			rstndx = (Word) ELF_R_SYM(reloc->r_info);
			rsdp = ifl->ifl_oldndx[rstndx];
			if (rsdp == sdp) {
				if ((str = demangle(rsdp->sd_name)) !=
				    rsdp->sd_name) {
					char	*_str = alloca(strlen(str) + 1);
					(void) strcpy(_str, str);
					str = (const char *)_str;
				}
				ld_eprintf(ofl, ERR_WARNING,
				    MSG_INTL(MSG_REL_DISPREL1),
				    conv_reloc_type(ifl->ifl_ehdr->e_machine,
				    (uint_t)ELF_R_TYPE(reloc->r_info,
				    ld_targ.t_m.m_mach),
				    0, &inv_buf), ifl->ifl_name, str,
				    MSG_INTL(MSG_STR_UNKNOWN),
				    EC_XWORD(reloc->r_offset),
				    demangle(sdp->sd_name));
			}

			/*
			 * Determine whether the relocation entry is relocating
			 * this symbol.
			 */
			if ((sdp->sd_isc != trel) ||
			    (reloc->r_offset < symaddr) ||
			    (reloc->r_offset >=
			    (symaddr + sdp->sd_sym->st_size)))
				continue;

			/*
			 * This symbol is truely *disp* relocated, so should
			 * really be fixed by user.
			 */
			if ((str = demangle(sdp->sd_name)) != sdp->sd_name) {
				char	*_str = alloca(strlen(str) + 1);
				(void) strcpy(_str, str);
				str = (const char *)_str;
			}
			ld_eprintf(ofl, ERR_WARNING, MSG_INTL(MSG_REL_DISPREL1),
			    conv_reloc_type(ifl->ifl_ehdr->e_machine,
			    (uint_t)ELF_R_TYPE(reloc->r_info,
			    ld_targ.t_m.m_mach), 0, &inv_buf),
			    ifl->ifl_name, demangle(rsdp->sd_name), str,
			    EC_XWORD(reloc->r_offset), str);
		}
	}
}

/*
 * The number of symbols provided by some objects can be very large.  Use a
 * binary search to match the associated value to a symbol table entry.
 */
static int
disp_bsearch(const void *key, const void *array)
{
	Addr		kvalue, avalue;
	Ssv_desc	*ssvp = (Ssv_desc *)array;

	kvalue = *((Addr *)key);
	avalue = ssvp->ssv_value;

	if (avalue > kvalue)
		return (-1);
	if ((avalue < kvalue) &&
	    ((avalue + ssvp->ssv_sdp->sd_sym->st_size) <= kvalue))
		return (1);
	return (0);
}

/*
 * Given a sorted list of symbols, look for a symbol in which the relocation
 * offset falls between the [sym.st_value - sym.st_value + sym.st_size].  Since
 * the symbol list is maintained in sorted order,  we can bail once the
 * relocation offset becomes less than the symbol values.  The symbol is
 * returned for use in error diagnostics.
 */
static Sym_desc *
disp_scansyms(Ifl_desc * ifl, Rel_desc *rld, Boolean rlocal, int inspect,
    Ofl_desc *ofl)
{
	Sym_desc	*tsdp, *rsdp;
	Sym		*rsym, *tsym;
	Ssv_desc	*ssvp;
	uchar_t		rtype, ttype;
	Addr		value;

	/*
	 * Sorted symbol values have been uniquified by adding their associated
	 * section offset.  Uniquify the relocation offset by adding its
	 * associated section offset, and search for the symbol.
	 */
	value = rld->rel_roffset;
	if (rld->rel_isdesc->is_shdr)
		value += rld->rel_isdesc->is_shdr->sh_offset;

	if ((ssvp = bsearch((void *)&value, (void *)ifl->ifl_sortsyms,
	    ifl->ifl_sortcnt, sizeof (Ssv_desc), &disp_bsearch)) != 0)
		tsdp = ssvp->ssv_sdp;
	else
		tsdp = 0;

	if (inspect)
		return (tsdp);

	/*
	 * Determine the relocation reference symbol and its type.
	 */
	rsdp = rld->rel_sym;
	rsym = rsdp->sd_sym;
	rtype = ELF_ST_TYPE(rsym->st_info);

	/*
	 * If there is no target symbol to match the relocation offset, then the
	 * offset is effectively local data.  If the relocation symbol is global
	 * data we have a potential for this displacement relocation to be
	 * invalidated should the global symbol be copied.
	 */
	if (tsdp == 0) {
		if ((rlocal == TRUE) ||
		    ((rtype != STT_OBJECT) && (rtype != STT_SECTION)))
		return (tsdp);
	} else {
		/*
		 * If both symbols are local, no copy relocations can occur to
		 * either symbol.  Note, this test is very similar to the test
		 * used in ld_sym_adjust_vis().
		 */
		if ((rlocal == TRUE) && (SYM_IS_HIDDEN(tsdp) ||
		    (ELF_ST_BIND(tsdp->sd_sym->st_info) != STB_GLOBAL) ||
		    ((ofl->ofl_flags & (FLG_OF_AUTOLCL | FLG_OF_AUTOELM)) &&
		    ((tsdp->sd_flags & MSK_SY_NOAUTO) == 0))))
			return (tsdp);

		/*
		 * Determine the relocation target symbols type.
		 */
		tsym = tsdp->sd_sym;
		ttype = ELF_ST_TYPE(tsym->st_info);

		/*
		 * If the reference symbol is local, and the target isn't a
		 * data element, then no copy relocations can occur to either
		 * symbol.  Note, this catches pc-relative relocations against
		 * the _GLOBAL_OFFSET_TABLE_, which is effectively treated as
		 * a local symbol.
		 */
		if ((rlocal == TRUE) && (ttype != STT_OBJECT) &&
		    (ttype != STT_SECTION))
			return (tsdp);

		/*
		 * Finally, one of the symbols must reference a data element.
		 */
		if ((rtype != STT_OBJECT) && (rtype != STT_SECTION) &&
		    (ttype != STT_OBJECT) && (ttype != STT_SECTION))
			return (tsdp);
	}

	/*
	 * We have two global symbols, at least one of which is a data item.
	 * The last case where a displacement relocation can be ignored, is
	 * if the reference symbol is included in the target symbol.
	 */
	value = rsym->st_value;
	if ((rld->rel_flags & FLG_REL_RELA) == FLG_REL_RELA)
		value += rld->rel_raddend;

	if ((rld->rel_roffset >= value) &&
	    (rld->rel_roffset < (value + rsym->st_size)))
		return (tsdp);

	/*
	 * We have a displacement relocation that could be compromised by a
	 * copy relocation of one of the associated data items.
	 */
	rld->rel_flags |= FLG_REL_DISP;
	return (tsdp);
}

void
ld_disp_errmsg(const char *msg, Rel_desc *rsp, Ofl_desc *ofl)
{
	Sym_desc	*sdp;
	const char	*str;
	Ifl_desc	*ifl = rsp->rel_isdesc->is_file;
	Conv_inv_buf_t	inv_buf;

	if ((sdp = disp_scansyms(ifl, rsp, 0, 1, ofl)) != 0)
		str = demangle(sdp->sd_name);
	else
		str = MSG_INTL(MSG_STR_UNKNOWN);

	ld_eprintf(ofl, ERR_WARNING, msg,
	    conv_reloc_type(ifl->ifl_ehdr->e_machine, rsp->rel_rtype,
	    0, &inv_buf), ifl->ifl_name, ld_reloc_sym_name(rsp), str,
	    EC_OFF(rsp->rel_roffset));
}

/*
 * qsort(3C) comparison routine used for the disp_sortsyms().
 */
static int
disp_qsort(const void * s1, const void * s2)
{
	Ssv_desc	*ssvp1 = ((Ssv_desc *)s1);
	Ssv_desc	*ssvp2 = ((Ssv_desc *)s2);
	Addr		val1 = ssvp1->ssv_value;
	Addr		val2 = ssvp2->ssv_value;

	if (val1 > val2)
		return (1);
	if (val1 < val2)
		return (-1);
	return (0);
}

/*
 * Determine whether a displacement relocation is between a local and global
 * symbol pair.  One symbol is used to perform the relocation, and the other
 * is the destination offset of the relocation.
 */
static uintptr_t
disp_inspect(Ofl_desc *ofl, Rel_desc *rld, Boolean rlocal)
{
	Is_desc		*isp = rld->rel_isdesc;
	Ifl_desc	*ifl = rld->rel_isdesc->is_file;

	/*
	 * If the input files symbols haven't been sorted yet, do so.
	 */
	if (ifl->ifl_sortsyms == 0) {
		Word	ondx, nndx;

		if ((ifl->ifl_sortsyms = libld_malloc((ifl->ifl_symscnt + 1) *
		    sizeof (Ssv_desc))) == 0)
			return (S_ERROR);

		for (ondx = 0, nndx = 0; ondx < ifl->ifl_symscnt; ondx++) {
			Sym_desc	*sdp;
			Addr		value;

			/*
			 * As symbol resolution has already occurred, various
			 * symbols from this object may have been satisfied
			 * from other objects.  Only select symbols from this
			 * object.  For the displacement test, we only really
			 * need to observe data definitions, however, later as
			 * part of providing warning disgnostics, relating the
			 * relocation offset to a symbol is desirable.  Thus,
			 * collect all symbols that define a memory area.
			 */
			if (((sdp = ifl->ifl_oldndx[ondx]) == 0) ||
			    (sdp->sd_sym->st_shndx == SHN_UNDEF) ||
			    (sdp->sd_sym->st_shndx >= SHN_LORESERVE) ||
			    (sdp->sd_ref != REF_REL_NEED) ||
			    (sdp->sd_file != ifl) ||
			    (sdp->sd_sym->st_size == 0))
				continue;

			/*
			 * As a further optimization for later checking, mark
			 * this section if this a global data definition.
			 */
			if (sdp->sd_isc && (ondx >= ifl->ifl_locscnt))
				sdp->sd_isc->is_flags |= FLG_IS_GDATADEF;

			/*
			 * Capture the symbol.  Within relocatable objects, a
			 * symbols value is its offset within its associated
			 * section.  Add the section offset to this value to
			 * uniquify the symbol.
			 */
			value = sdp->sd_sym->st_value;
			if (sdp->sd_isc && sdp->sd_isc->is_shdr)
				value += sdp->sd_isc->is_shdr->sh_offset;

			ifl->ifl_sortsyms[nndx].ssv_value = value;
			ifl->ifl_sortsyms[nndx].ssv_sdp = sdp;
			nndx++;
		}

		/*
		 * Sort the list based on the symbols value (address).
		 */
		if ((ifl->ifl_sortcnt = nndx) != 0)
			qsort(ifl->ifl_sortsyms, nndx, sizeof (Ssv_desc),
			    &disp_qsort);
	}

	/*
	 * If the reference symbol is local, and the section being relocated
	 * contains no global definitions, neither can be the target of a copy
	 * relocation.
	 */
	if ((rlocal == FALSE) && ((isp->is_flags & FLG_IS_GDATADEF) == 0))
		return (1);

	/*
	 * Otherwise determine whether this relocation symbol and its offset
	 * could be candidates for a copy relocation.
	 */
	if (ifl->ifl_sortcnt)
		(void) disp_scansyms(ifl, rld, rlocal, 0, ofl);
	return (1);
}

/*
 * Return a Rel_cachebuf with an available Rel_desc entry from the
 * specified cache, allocating a cache buffer if necessary.
 *
 * entry:
 *	ofl - Output file descriptor
 *	rcp - Relocation cache to allocate the descriptor from.
 *		One of &ofl->ofl_actrels or &ofl->ofl_outrels.
 *
 * exit:
 *	Returns the allocated descriptor, or NULL if the allocation fails.
 */
static Rel_cachebuf *
ld_add_rel_cache(Ofl_desc *ofl, Rel_cache *rcp)
{
	Rel_cachebuf	*rcbp;
	size_t		nelts, size, alloc_cnt;

	/*
	 * If there is space available in the present cache bucket, return the
	 * next free entry.
	 */
	alloc_cnt = aplist_nitems(rcp->rc_list);
	if (rcp->rc_list &&
	    ((rcbp = rcp->rc_list->apl_data[alloc_cnt - 1]) != NULL) &&
	    (rcbp->rc_free < rcbp->rc_end))
		return (rcbp);

	/*
	 * Allocate a new bucket. As we cannot know the number of relocations
	 * we'll have in the active and output cache until after the link is
	 * complete, the size of the bucket is a heuristic.
	 *
	 * In general, if the output object is an executable, or a sharable
	 * object, then the size of the active relocation list will be nearly
	 * the same as the number of input relocations, and the output
	 * relocation list will be very short. If the output object is a
	 * relocatable object, then the reverse is true. Therefore, the initial
	 * allocation for the appropriate list is sized to fit all the input
	 * allocations in a single shot.
	 *
	 * All other allocations are done in units of REL_CACHEBUF_ALLOC,
	 * which is chosen to be large enough to cover most common cases,
	 * but small enough that not using it fully is inconsequential.
	 *
	 * In an ideal scenario, this results in one allocation on each list.
	 */
	nelts = REL_CACHEBUF_ALLOC;
	if ((alloc_cnt == 0) && (ofl->ofl_relocincnt > REL_CACHEBUF_ALLOC)) {
		Boolean is_rel = (ofl->ofl_flags & FLG_OF_RELOBJ) != 0;

		if (((rcp == &ofl->ofl_actrels) && !is_rel) ||
		    ((rcp == &ofl->ofl_outrels) && is_rel))
			nelts = ofl->ofl_relocincnt;
	}

	/*
	 * Compute the total number of bytes to allocate. The first element
	 * of the array is built into the Rel_cachebuf header, so we subtract
	 * one from nelts.
	 */
	size = sizeof (Rel_cachebuf) + ((nelts - 1) * sizeof (Rel_desc));

	if (((rcbp = libld_malloc(size)) == NULL) ||
	    (aplist_append(&rcp->rc_list, rcbp, AL_CNT_OFL_RELS) == NULL))
		return (NULL);

	rcbp->rc_free = rcbp->rc_arr;
	rcbp->rc_end = rcbp->rc_arr + nelts;

	return (rcbp);
}

/*
 * Allocate a Rel_aux descriptor and attach it to the given Rel_desc,
 * allocating an auxiliary cache buffer if necessary.
 *
 * entry:
 *	ofl - Output file descriptor
 *	rdp - Rel_desc descriptor that requires an auxiliary block
 *
 * exit:
 *	Returns TRUE on success, and FALSE if the allocation fails.
 *	On success, the caller is responsible for initializing the
 *	auxiliary block properly.
 */
static Boolean
ld_add_rel_aux(Ofl_desc *ofl, Rel_desc *rdesc)
{
	Rel_aux_cachebuf	*racp = NULL;
	size_t			size;

	/*
	 * If there is space available in the present cache bucket, use it.
	 * Otherwise, allocate a new bucket.
	 */
	if (ofl->ofl_relaux) {
		racp = ofl->ofl_relaux->apl_data[
		    ofl->ofl_relaux->apl_nitems - 1];

		if (racp && (racp->rac_free >= racp->rac_end))
			racp = NULL;
	}
	if (racp == NULL) {
		/*
		 * Compute the total number of bytes to allocate. The first
		 * element of the array is built into the Rel_aux_cachebuf
		 * header, so we subtract one from the number of elements.
		 */
		size = sizeof (Rel_aux_cachebuf) +
		    ((RELAUX_CACHEBUF_ALLOC - 1) * sizeof (Rel_aux));
		if (((racp = libld_malloc(size)) == NULL) ||
		    (aplist_append(&ofl->ofl_relaux, racp, AL_CNT_OFL_RELS) ==
		    NULL))
			return (FALSE);

		racp->rac_free = racp->rac_arr;
		racp->rac_end = racp->rac_arr + RELAUX_CACHEBUF_ALLOC;
	}

	/* Take an auxiliary descriptor from the cache and add it to rdesc */
	rdesc->rel_aux = racp->rac_free++;

	return (TRUE);
}

/*
 * Enter a copy of the given Rel_desc relocation descriptor, and
 * any associated auxiliary Rel_aux it may reference, into the
 * specified relocation cache.
 *
 * entry:
 *	ofl - Output file descriptor
 *	rcp - Relocation descriptor cache to recieve relocation
 *	rdesc - Rel_desc image to be inserted
 *	flags - Flags to add to rdest->rel_flags in the inserted descriptor
 *
 * exit:
 *	Returns the pointer to the inserted descriptor on success.
 *	Returns NULL if an allocation error occurs.
 */
Rel_desc *
ld_reloc_enter(Ofl_desc *ofl, Rel_cache *rcp, Rel_desc *rdesc, Word flags)
{
	Rel_desc	*arsp;
	Rel_aux		*auxp;
	Rel_cachebuf	*rcbp;


	/*
	 * If no relocation cache structures are available, allocate a new
	 * one and link it to the buffer list.
	 */
	rcbp = ld_add_rel_cache(ofl, rcp);
	if (rcbp == NULL)
		return (NULL);
	arsp = rcbp->rc_free;

	/*
	 * If there is an auxiliary block on the original, allocate
	 * one for the clone. Save the pointer, because the struct copy
	 * below will crush it.
	 */
	if (rdesc->rel_aux != NULL) {
		if (!ld_add_rel_aux(ofl, arsp))
			return (NULL);
		auxp = arsp->rel_aux;
	}

	/* Copy contents of the original into the clone */
	*arsp = *rdesc;

	/*
	 * If there is an auxiliary block, restore the clone's pointer to
	 * it, and copy the auxiliary contents.
	 */
	if (rdesc->rel_aux != NULL) {
		arsp->rel_aux = auxp;
		*auxp = *rdesc->rel_aux;
	}
	arsp->rel_flags |= flags;

	rcbp->rc_free++;
	rcp->rc_cnt++;

	return (arsp);
}

/*
 * Initialize a relocation descriptor auxiliary block to default
 * values.
 *
 * entry:
 *	rdesc - Relocation descriptor, with a non-NULL rel_aux field
 *		pointing at the auxiliary block to be initialized.
 *
 * exit:
 *	Each field in rdesc->rel_aux has been set to its default value
 */
static void
ld_init_rel_aux(Rel_desc *rdesc)
{
	Rel_aux	*rap = rdesc->rel_aux;

	/*
	 * The default output section is the one the input section
	 * is assigned to, assuming that there is an input section.
	 * Failing that, NULL is the only possibility, and we expect
	 * that the caller will assign an explicit value.
	 */
	rap->ra_osdesc = (rdesc->rel_isdesc == NULL) ? NULL :
	    rdesc->rel_isdesc->is_osdesc;

	/* The ra_usym defaults to the value in rel_sym */
	rap->ra_usym = rdesc->rel_sym;

	/* Remaining fields are zeroed */
	rap->ra_move = NULL;
	rap->ra_typedata = 0;
}

/*
 * The ld_reloc_set_aux_XXX() functions are used to set the value of an
 * auxiliary relocation item on a relocation descriptor that exists in
 * the active or output relocation cache. These descriptors are created
 * via a call to ld_reloc_enter().
 *
 * These functions preserve the illusion that every relocation descriptor
 * has a non-NULL auxiliary block into which values can be set, while
 * only creating an auxiliary block if one is actually necessary, preventing
 * the large memory allocations that would otherwise occur. They operate
 * as follows:
 *
 * -	If an auxiliary block already exists, set the desired value and
 *	and return TRUE.
 *
 * -	If no auxiliary block exists, but the desired value is the default
 *	value for the specified item, then no auxiliary block is needed,
 *	and TRUE is returned.
 *
 * -	If no auxiliary block exists, and the desired value is not the
 *	default for the specified item, allocate an auxiliary block for
 *	the descriptor, initialize its contents to default values for all
 *	items, set the specified value, and return TRUE.
 *
 * -	If an auxiliary block needs to be added, but the allocation fails,
 *	an error is issued, and FALSE is returned.
 *
 * Note that we only provide an ld_reloc_set_aux_XXX() function for those
 * auxiliary items that libld actually modifies in Rel_desc descriptors
 * in the active or output caches. If another one is needed, add it here.
 *
 * The PROCESS_NULL_REL_AUX macro is used to provide a single implementation
 * for the logic that determines if an auxiliary block is needed or not,
 * and handles the details of allocating and initializing it. It accepts
 * one argument, _isdefault_predicate, which should be a call to the
 * RELAUX_ISDEFAULT_xxx() macro appropriate for the auxiliary item
 */

#define	PROCESS_NULL_REL_AUX(_isdefault_predicate) \
	if (rdesc->rel_aux == NULL) { \
		/* If requested value is the default, no need for aux block */ \
		if (_isdefault_predicate) \
			return (TRUE); \
		/* Allocate and attach an auxiliary block */ \
		if (!ld_add_rel_aux(ofl, rdesc)) \
			return (FALSE); \
		/* Initialize the auxiliary block with default values */ \
		ld_init_rel_aux(rdesc); \
	}

Boolean
ld_reloc_set_aux_osdesc(Ofl_desc *ofl, Rel_desc *rdesc, Os_desc *osp)
{
	PROCESS_NULL_REL_AUX(RELAUX_ISDEFAULT_OSDESC(rdesc, osp))
	rdesc->rel_aux->ra_osdesc = osp;
	return (TRUE);
}

Boolean
ld_reloc_set_aux_usym(Ofl_desc *ofl, Rel_desc *rdesc, Sym_desc *sdp)
{
	PROCESS_NULL_REL_AUX(RELAUX_ISDEFAULT_USYM(rdesc, sdp))
	rdesc->rel_aux->ra_usym = sdp;
	return (TRUE);
}

#undef PROCESS_NULL_REL_AUX

/*
 * Return a descriptive name for the symbol associated with the
 * given relocation descriptor. This will be the actual symbol
 * name if one exists, or a suitable alternative otherwise.
 *
 * entry:
 *	rsp - Relocation descriptor
 */
const char *
ld_reloc_sym_name(Rel_desc *rsp)
{
	Sym_desc	*sdp = rsp->rel_sym;

	if (sdp != NULL) {
		/* If the symbol has a valid name use it */
		if (sdp->sd_name && *sdp->sd_name)
			return (demangle(sdp->sd_name));

		/*
		 * If the symbol is STT_SECTION, and the corresponding
		 * section symbol has the specially prepared string intended
		 * for this use, use that string. The string is of the form
		 *	secname (section)
		 */
		if ((ELF_ST_TYPE(sdp->sd_sym->st_info) == STT_SECTION) &&
		    (sdp->sd_isc != NULL) && (sdp->sd_isc->is_sym_name != NULL))
			return (demangle(sdp->sd_isc->is_sym_name));
	} else {
		/*
		 * Use an empty name for a register relocation with
		 * no symbol.
		 */
		if (IS_REGISTER(rsp->rel_rtype))
			return (MSG_ORIG(MSG_STR_EMPTY));
	}

	/* If all else fails, report it as <unknown> */
	return (MSG_INTL(MSG_STR_UNKNOWN));
}

/*
 * Add an active relocation record.
 */
uintptr_t
ld_add_actrel(Word flags, Rel_desc *rsp, Ofl_desc *ofl)
{
	Rel_desc	*arsp;

	if ((arsp = ld_reloc_enter(ofl, &ofl->ofl_actrels, rsp, flags)) == NULL)
		return (S_ERROR);

	/*
	 * Any GOT relocation reference requires the creation of a .got table.
	 * Most references to a .got require a .got entry,  which is accounted
	 * for with the ofl_gotcnt counter.  However, some references are
	 * relative to the .got table, but require no .got entry.  This test
	 * insures a .got is created regardless of the type of reference.
	 */
	if (IS_GOT_REQUIRED(arsp->rel_rtype))
		ofl->ofl_flags |= FLG_OF_BLDGOT;

	/*
	 * If this is a displacement relocation generate a warning.
	 */
	if (arsp->rel_flags & FLG_REL_DISP) {
		ofl->ofl_dtflags_1 |= DF_1_DISPRELDNE;

		if (ofl->ofl_flags & FLG_OF_VERBOSE)
			ld_disp_errmsg(MSG_INTL(MSG_REL_DISPREL3), arsp, ofl);
	}

	DBG_CALL(Dbg_reloc_ars_entry(ofl->ofl_lml, ELF_DBG_LD,
	    arsp->rel_isdesc->is_shdr->sh_type, ld_targ.t_m.m_mach, arsp));
	return (1);
}

/*
 * In the platform specific machrel.XXX.c files, we sometimes write
 * a value directly into the got/plt. These function can be used when
 * the running linker has the opposite byte order of the object being
 * produced.
 */
Word
ld_bswap_Word(Word v)
{
	return (BSWAP_WORD(v));
}


Xword
ld_bswap_Xword(Xword v)
{
	return (BSWAP_XWORD(v));
}


uintptr_t
ld_reloc_GOT_relative(Boolean local, Rel_desc *rsp, Ofl_desc *ofl)
{
	Sym_desc	*sdp = rsp->rel_sym;
	ofl_flag_t	flags = ofl->ofl_flags;
	Gotndx		*gnp;

	/*
	 * If this is the first time we've seen this symbol in a GOT
	 * relocation we need to assign it a GOT token.  Once we've got
	 * all of the GOT's assigned we can assign the actual indexes.
	 */
	if ((gnp = (*ld_targ.t_mr.mr_find_got_ndx)(sdp->sd_GOTndxs,
	    GOT_REF_GENERIC, ofl, rsp)) == 0) {
		Word	rtype = rsp->rel_rtype;

		if ((*ld_targ.t_mr.mr_assign_got_ndx)(&(sdp->sd_GOTndxs), NULL,
		    GOT_REF_GENERIC, ofl, rsp, sdp) == S_ERROR)
			return (S_ERROR);

		/*
		 * Initialize the GOT table entry.
		 *
		 * For global symbols, we clear the GOT table entry and create
		 * a GLOB_DAT relocation against the symbol.
		 *
		 * For local symbols, we enter the symbol value into a GOT
		 * table entry and create a relative relocation if all of
		 * the following hold:
		 *
		 * -	Output is a shared object
		 * -	Symbol is not ABS
		 * -	Relocation is not against one of the special sections
		 *	(COMMON, ...)
		 * -	This is not one of the generated symbols we have
		 *	to update after the output object has been fully
		 *	laid out (_START_, _END_, ...)
		 *
		 * Local symbols that don't meet the above requirements
		 * are processed as is.
		 */
		if (local == TRUE) {
			if ((flags & FLG_OF_SHAROBJ) &&
			    (((sdp->sd_flags & FLG_SY_SPECSEC) == 0) ||
			    ((sdp->sd_sym->st_shndx != SHN_ABS)) ||
			    (sdp->sd_aux && sdp->sd_aux->sa_symspec))) {
				if (ld_add_actrel((FLG_REL_GOT | FLG_REL_GOTCL),
				    rsp, ofl) == S_ERROR)
					return (S_ERROR);

				rsp->rel_rtype = ld_targ.t_m.m_r_relative;

				if ((*ld_targ.t_mr.mr_add_outrel)
				    ((FLG_REL_GOT | FLG_REL_ADVAL),
				    rsp, ofl) == S_ERROR)
					return (S_ERROR);

				rsp->rel_rtype = rtype;
			} else {
				if (ld_add_actrel(FLG_REL_GOT, rsp,
				    ofl) == S_ERROR)
					return (S_ERROR);
			}
		} else {
			rsp->rel_rtype = ld_targ.t_m.m_r_glob_dat;
			if ((*ld_targ.t_mr.mr_add_outrel)(FLG_REL_GOT,
			    rsp, ofl) == S_ERROR)
				return (S_ERROR);
			rsp->rel_rtype = rtype;
		}
	} else {
		if ((*ld_targ.t_mr.mr_assign_got_ndx)(&(sdp->sd_GOTndxs), gnp,
		    GOT_REF_GENERIC, ofl, rsp, sdp) == S_ERROR)
			return (S_ERROR);
	}

	/*
	 * Perform relocation to GOT table entry.
	 */
	return (ld_add_actrel(0, rsp, ofl));
}

/*
 * Perform relocations for PLT's
 */
uintptr_t
ld_reloc_plt(Rel_desc *rsp, Ofl_desc *ofl)
{
	Sym_desc	*sdp = rsp->rel_sym;

	switch (ld_targ.t_m.m_mach) {
	case EM_AMD64:
		/*
		 * AMD64 TLS code sequences do not use a unique TLS
		 * relocation to reference the __tls_get_addr() function call.
		 */
		if ((ofl->ofl_flags & FLG_OF_EXEC) &&
		    (strcmp(sdp->sd_name, MSG_ORIG(MSG_SYM_TLSGETADDR_U)) ==
		    0))
			return (ld_add_actrel(FLG_REL_TLSFIX, rsp, ofl));
		break;

	case EM_386:
		/*
		 * GNUC IA32 TLS code sequences do not use a unique TLS
		 * relocation to reference the ___tls_get_addr() function call.
		 */
		if ((ofl->ofl_flags & FLG_OF_EXEC) &&
		    (strcmp(sdp->sd_name, MSG_ORIG(MSG_SYM_TLSGETADDR_UU)) ==
		    0))
			return (ld_add_actrel(FLG_REL_TLSFIX, rsp, ofl));
		break;
	}

	/*
	 * if (not PLT yet assigned)
	 * then
	 *	assign PLT index to symbol
	 *	build output JMP_SLOT relocation
	 * fi
	 */
	if (sdp->sd_aux->sa_PLTndx == 0) {
		Word	ortype = rsp->rel_rtype;

		(*ld_targ.t_mr.mr_assign_plt_ndx)(sdp, ofl);

		/*
		 * If this symbol is binding to a lazy loadable, or deferred
		 * dependency, then identify the symbol.
		 */
		if (sdp->sd_file) {
			if (sdp->sd_file->ifl_flags & FLG_IF_LAZYLD)
				sdp->sd_flags |= FLG_SY_LAZYLD;
			if (sdp->sd_file->ifl_flags & FLG_IF_DEFERRED)
				sdp->sd_flags |= FLG_SY_DEFERRED;
		}

		rsp->rel_rtype = ld_targ.t_m.m_r_jmp_slot;
		if ((*ld_targ.t_mr.mr_add_outrel)(FLG_REL_PLT, rsp, ofl) ==
		    S_ERROR)
			return (S_ERROR);
		rsp->rel_rtype = ortype;
	}

	/*
	 * Perform relocation to PLT table entry.
	 */
	if ((ofl->ofl_flags & FLG_OF_SHAROBJ) &&
	    IS_ADD_RELATIVE(rsp->rel_rtype)) {
		Word	ortype	= rsp->rel_rtype;

		rsp->rel_rtype = ld_targ.t_m.m_r_relative;
		if ((*ld_targ.t_mr.mr_add_outrel)(FLG_REL_ADVAL, rsp, ofl) ==
		    S_ERROR)
			return (S_ERROR);
		rsp->rel_rtype = ortype;
		return (1);
	} else
		return (ld_add_actrel(0, rsp, ofl));
}

/*
 * Round up to the next power of 2.  Used to ensure section alignments that can
 * be used for copy relocation symbol alignments are sane values.
 */
static Word
nlpo2(Word val)
{
	val--;
	val |= (val >> 1);
	val |= (val >> 2);
	val |= (val >> 4);
	val |= (val >> 8);
	val |= (val >> 16);
	return (++val);
}

/*
 * process GLOBAL undefined and ref_dyn_need symbols.
 */
static uintptr_t
reloc_exec(Rel_desc *rsp, Ofl_desc *ofl)
{
	Sym_desc	*_sdp, *sdp = rsp->rel_sym;
	Sym_aux		*sap = sdp->sd_aux;
	Sym		*sym = sdp->sd_sym;
	Addr		stval;

	/*
	 * Reference is to a function so simply create a plt entry for it.
	 */
	if (ELF_ST_TYPE(sym->st_info) == STT_FUNC)
		return (ld_reloc_plt(rsp, ofl));

	/*
	 * Catch absolutes - these may cause a text relocation.
	 */
	if ((sdp->sd_flags & FLG_SY_SPECSEC) && (sym->st_shndx == SHN_ABS)) {
		if ((ofl->ofl_flags1 & FLG_OF1_ABSEXEC) == 0)
			return ((*ld_targ.t_mr.mr_add_outrel)(0, rsp, ofl));

		/*
		 * If -zabsexec is set then promote the ABSOLUTE symbol to
		 * current the current object and perform the relocation now.
		 */
		sdp->sd_ref = REF_REL_NEED;
		return (ld_add_actrel(0, rsp, ofl));
	}

	/*
	 * If the relocation is against a writable section simply compute the
	 * necessary output relocation.  As an optimization, if the symbol has
	 * already been transformed into a copy relocation then we can perform
	 * the relocation directly (copy relocations should only be generated
	 * for references from the text segment and these relocations are
	 * normally carried out before we get to the data segment relocations).
	 */
	if ((ELF_ST_TYPE(sym->st_info) == STT_OBJECT) &&
	    (RELAUX_GET_OSDESC(rsp)->os_shdr->sh_flags & SHF_WRITE)) {
		if (sdp->sd_flags & FLG_SY_MVTOCOMM)
			return (ld_add_actrel(0, rsp, ofl));
		else
			return ((*ld_targ.t_mr.mr_add_outrel)(0, rsp, ofl));
	}

	/*
	 * If the reference isn't to an object (normally because a .type
	 * directive wasn't defined in some assembler source), then apply
	 * a generic relocation (this has a tendency to result in text
	 * relocations).
	 */
	if (ELF_ST_TYPE(sym->st_info) != STT_OBJECT) {
		Conv_inv_buf_t inv_buf;

		ld_eprintf(ofl, ERR_WARNING, MSG_INTL(MSG_REL_UNEXPSYM),
		    conv_sym_info_type(sdp->sd_file->ifl_ehdr->e_machine,
		    ELF_ST_TYPE(sym->st_info), 0, &inv_buf),
		    rsp->rel_isdesc->is_file->ifl_name,
		    ld_reloc_sym_name(rsp), sdp->sd_file->ifl_name);
		return ((*ld_targ.t_mr.mr_add_outrel)(0, rsp, ofl));
	}

	/*
	 * Prepare for generating a copy relocation.
	 *
	 * If this symbol is one of an alias pair, we need to ensure both
	 * symbols become part of the output (the strong symbol will be used to
	 * maintain the symbols state).  And, if we did raise the precedence of
	 * a symbol we need to check and see if this is a weak symbol.  If it is
	 * we want to use it's strong counter part.
	 *
	 * The results of this logic should be:
	 *	ra_usym: assigned to strong
	 *	rel_sym: assigned to symbol to perform
	 *		copy_reloc against (weak or strong).
	 */
	if (sap->sa_linkndx) {
		_sdp = sdp->sd_file->ifl_oldndx[sap->sa_linkndx];

		if (_sdp->sd_ref < sdp->sd_ref) {
			_sdp->sd_ref = sdp->sd_ref;
			_sdp->sd_flags |= FLG_SY_REFRSD;

			/*
			 * As we're going to replicate a symbol from a shared
			 * object, retain its correct binding status.
			 */
			if (ELF_ST_BIND(_sdp->sd_sym->st_info) == STB_GLOBAL)
				_sdp->sd_flags |= FLG_SY_GLOBREF;

		} else if (_sdp->sd_ref > sdp->sd_ref) {
			sdp->sd_ref = _sdp->sd_ref;
			sdp->sd_flags |= FLG_SY_REFRSD;

			/*
			 * As we're going to replicate a symbol from a shared
			 * object, retain its correct binding status.
			 */
			if (ELF_ST_BIND(sym->st_info) == STB_GLOBAL)
				sdp->sd_flags |= FLG_SY_GLOBREF;
		}

		/*
		 * If this is a weak symbol then we want to move the strong
		 * symbol into local .bss.  If there is a copy_reloc to be
		 * performed, that should still occur against the WEAK symbol.
		 */
		if (((ELF_ST_BIND(sdp->sd_sym->st_info) == STB_WEAK) ||
		    (sdp->sd_flags & FLG_SY_WEAKDEF)) &&
		    !ld_reloc_set_aux_usym(ofl, rsp, _sdp))
			return (S_ERROR);
	} else
		_sdp = 0;

	/*
	 * If the reference is to an object then allocate space for the object
	 * within the executables .bss.  Relocations will now be performed from
	 * this new location.  If the original shared objects data is
	 * initialized, then generate a copy relocation that will copy the data
	 * to the executables .bss at runtime.
	 */
	if (!(RELAUX_GET_USYM(rsp)->sd_flags & FLG_SY_MVTOCOMM)) {
		Word		rtype = rsp->rel_rtype, w2align;
		Copy_rel	cr;

		/*
		 * Diagnose the original copy reference, as this symbol
		 * information will be overridden with the new destination.
		 */
		DBG_CALL(Dbg_syms_copy_reloc(ofl, sdp, 0));

		/*
		 * Indicate that the symbol(s) against which we're relocating
		 * have been moved to the executables common.  Also, insure that
		 * the symbol(s) remain marked as global, as the shared object
		 * from which they are copied must be able to relocate to the
		 * new common location within the executable.
		 *
		 * Note that even though a new symbol has been generated in the
		 * output files' .bss, the symbol must remain REF_DYN_NEED and
		 * not be promoted to REF_REL_NEED.  sym_validate() still needs
		 * to carry out a number of checks against the symbols binding
		 * that are triggered by the REF_DYN_NEED state.
		 */
		sdp->sd_flags |=
		    (FLG_SY_MVTOCOMM | FLG_SY_DEFAULT | FLG_SY_EXPDEF);
		sdp->sd_flags &= ~MSK_SY_LOCAL;
		sdp->sd_sym->st_other &= ~MSK_SYM_VISIBILITY;
		if (_sdp) {
			_sdp->sd_flags |= (FLG_SY_MVTOCOMM |
			    FLG_SY_DEFAULT | FLG_SY_EXPDEF);
			_sdp->sd_flags &= ~MSK_SY_LOCAL;
			_sdp->sd_sym->st_other &= ~MSK_SYM_VISIBILITY;

			/*
			 * Make sure the symbol has a reference in case of any
			 * error diagnostics against it (perhaps this belongs
			 * to a version that isn't allowable for this build).
			 * The resulting diagnostic (see sym_undef_entry())
			 * might seem a little bogus, as the symbol hasn't
			 * really been referenced by this file, but has been
			 * promoted as a consequence of its alias reference.
			 */
			if (!(_sdp->sd_aux->sa_rfile))
				_sdp->sd_aux->sa_rfile = sdp->sd_aux->sa_rfile;
		}

		/*
		 * Assign the symbol to the bss.
		 */
		_sdp = RELAUX_GET_USYM(rsp);
		stval = _sdp->sd_sym->st_value;
		if (ld_sym_copy(_sdp) == S_ERROR)
			return (S_ERROR);
		_sdp->sd_shndx = _sdp->sd_sym->st_shndx = SHN_COMMON;
		_sdp->sd_flags |= FLG_SY_SPECSEC;

		/*
		 * Ensure the symbol has sufficient alignment.  The symbol
		 * definition has no alignment information that can be used,
		 * hence we use a heuristic.  Historically, twice the native
		 * word alignment was sufficient for any data type, however,
		 * the developer may have requested larger alignments (pragma
		 * align).  The most conservative approach is to use a power
		 * of two alignment, determined from the alignment of the
		 * section containing the symbol definition.  Note that this
		 * can result in some bloat to the .bss as the not every item
		 * of copied data might need the section alignment.
		 *
		 * COMMON symbols carry their alignment requirements in the
		 * symbols st_value field.  This alignment is applied to the
		 * symbol when it is eventually transformed into .bss.
		 */
		w2align = ld_targ.t_m.m_word_align * 2;
		if (_sdp->sd_sym->st_size < w2align)
			_sdp->sd_sym->st_value = ld_targ.t_m.m_word_align;
		else {
			Shdr	*shdr;
			Word	isalign;

			if (_sdp->sd_isc &&
			    ((shdr = _sdp->sd_isc->is_shdr) != NULL) &&
			    ((isalign = shdr->sh_addralign) != 0))
				_sdp->sd_sym->st_value = nlpo2(isalign);
			else
				_sdp->sd_sym->st_value = w2align;
		}

		/*
		 * Whether or not the symbol references initialized data we
		 * generate a copy relocation - this differs from the past
		 * where we would not create the COPY_RELOC if we were binding
		 * against .bss.  This is done for *two* reasons.
		 *
		 *  -	If the symbol in the shared object changes to a
		 *	initialized data - we need the COPY to pick it up.
		 *  -	Without the COPY RELOC we can't tell that the symbol
		 *	from the COPY'd object has been moved and all bindings
		 *	to it should bind here.
		 *
		 * Keep this symbol in the copy relocation list to check the
		 * validity later.
		 */
		cr.c_sdp = _sdp;
		cr.c_val = stval;
		if (alist_append(&ofl->ofl_copyrels, &cr, sizeof (Copy_rel),
		    AL_CNT_OFL_COPYRELS) == NULL)
			return (S_ERROR);

		rsp->rel_rtype = ld_targ.t_m.m_r_copy;
		if ((*ld_targ.t_mr.mr_add_outrel)(FLG_REL_BSS, rsp, ofl) ==
		    S_ERROR)
			return (S_ERROR);
		rsp->rel_rtype = rtype;

		/*
		 * If this symbol is a protected symbol, warn the user.  A
		 * potential issue exists as the copy relocated symbol within
		 * the executable can be visible to others, whereas the shared
		 * object that defined the original copy data symbol is pre-
		 * bound to reference it's own definition.  Any modification
		 * of the symbols data could lead to inconsistencies for the
		 * various users.
		 */
		if (_sdp->sd_flags & FLG_SY_PROT) {
			Conv_inv_buf_t inv_buf;

			ld_eprintf(ofl, ERR_WARNING, MSG_INTL(MSG_REL_COPY),
			    conv_reloc_type(_sdp->sd_file->ifl_ehdr->e_machine,
			    ld_targ.t_m.m_r_copy, 0, &inv_buf),
			    _sdp->sd_file->ifl_name, _sdp->sd_name);
		}
		DBG_CALL(Dbg_syms_copy_reloc(ofl, _sdp,
		    _sdp->sd_sym->st_value));
	}
	return (ld_add_actrel(0, rsp, ofl));
}

/*
 * All relocations should have been handled by the other routines.  This
 * routine is here as a catch all, if we do enter it we've goofed - but
 * we'll try and do the best we can.
 */
static uintptr_t
reloc_generic(Rel_desc *rsp, Ofl_desc *ofl)
{
	Ifl_desc	*ifl = rsp->rel_isdesc->is_file;
	Conv_inv_buf_t	inv_buf;

	ld_eprintf(ofl, ERR_WARNING, MSG_INTL(MSG_REL_UNEXPREL),
	    conv_reloc_type(ifl->ifl_ehdr->e_machine, rsp->rel_rtype,
	    0, &inv_buf), ifl->ifl_name, ld_reloc_sym_name(rsp));

	/*
	 * If building a shared object then put the relocation off
	 * until runtime.
	 */
	if (ofl->ofl_flags & FLG_OF_SHAROBJ)
		return ((*ld_targ.t_mr.mr_add_outrel)(0, rsp, ofl));

	/*
	 * Otherwise process relocation now.
	 */
	return (ld_add_actrel(0, rsp, ofl));
}

/*
 * Process relocations when building a relocatable object.  Typically, there
 * aren't many relocations that can be caught at this point, most are simply
 * passed through to the output relocatable object.
 */
static uintptr_t
reloc_relobj(Boolean local, Rel_desc *rsp, Ofl_desc *ofl)
{
	Word		rtype = rsp->rel_rtype;
	Sym_desc	*sdp = rsp->rel_sym;
	Is_desc		*isp = rsp->rel_isdesc;
	Word		oflags = 0;

	/*
	 * Determine if we can do any relocations at this point.  We can if:
	 *
	 *	this is local_symbol and a non-GOT relocation, and
	 *	the relocation is pc-relative, and
	 *	the relocation is against a symbol in same section
	 */
	if (local && !IS_GOT_RELATIVE(rtype) &&
	    !IS_GOT_BASED(rtype) && !IS_GOT_PC(rtype) &&
	    IS_PC_RELATIVE(rtype) &&
	    ((sdp->sd_isc) && (sdp->sd_isc->is_osdesc == isp->is_osdesc)))
		return (ld_add_actrel(0, rsp, ofl));

	/*
	 * If -zredlocsym is in effect, translate all local symbol relocations
	 * to be against section symbols, since section symbols are the only
	 * local symbols which will be added to the .symtab.
	 */
	if (local && (((ofl->ofl_flags & FLG_OF_REDLSYM) &&
	    (ELF_ST_BIND(sdp->sd_sym->st_info) == STB_LOCAL)) ||
	    ((sdp->sd_flags & FLG_SY_ELIM) &&
	    (ofl->ofl_flags & FLG_OF_PROCRED)))) {
		/*
		 * But if this is PIC code, don't allow it for now.
		 */
		if (IS_GOT_RELATIVE(rsp->rel_rtype)) {
			Ifl_desc	*ifl = rsp->rel_isdesc->is_file;
			Conv_inv_buf_t inv_buf;

			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_PICREDLOC),
			    ld_reloc_sym_name(rsp), ifl->ifl_name,
			    conv_reloc_type(ifl->ifl_ehdr->e_machine,
			    rsp->rel_rtype, 0, &inv_buf));
			return (S_ERROR);
		}

		/*
		 * Indicate that this relocation should be processed the same
		 * as a section symbol.  For RELA, indicate that the addend
		 * also needs to be applied to this relocation.
		 */
		if ((rsp->rel_flags & FLG_REL_RELA) == FLG_REL_RELA)
			oflags = FLG_REL_SCNNDX | FLG_REL_ADVAL;
		else
			oflags = FLG_REL_SCNNDX;
	}

	if ((rsp->rel_flags & FLG_REL_RELA) == 0) {
		/*
		 * Intel (Rel) relocations do not contain an addend.  Any
		 * addend is contained within the file at the location
		 * identified by the relocation offset.  Therefore, if we're
		 * processing a section symbol, or a -zredlocsym relocation
		 * (that basically transforms a local symbol reference into
		 * a section reference), perform an active relocation to
		 * propagate any addend.
		 */
		if ((ELF_ST_TYPE(sdp->sd_sym->st_info) == STT_SECTION) ||
		    (oflags == FLG_REL_SCNNDX))
			if (ld_add_actrel(0, rsp, ofl) == S_ERROR)
				return (S_ERROR);
	}
	return ((*ld_targ.t_mr.mr_add_outrel)(oflags, rsp, ofl));
}

/*
 * Perform any generic TLS validations before passing control to machine
 * specific routines.  At this point we know we are dealing with an executable
 * or shared object - relocatable objects have already been processed.
 */
static uintptr_t
reloc_TLS(Boolean local, Rel_desc *rsp, Ofl_desc *ofl)
{
	Word		rtype = rsp->rel_rtype;
	ofl_flag_t	flags = ofl->ofl_flags;
	Ifl_desc	*ifl = rsp->rel_isdesc->is_file;
	Half		mach = ifl->ifl_ehdr->e_machine;
	Sym_desc	*sdp = rsp->rel_sym;
	unsigned char	type;
	Conv_inv_buf_t	inv_buf1, inv_buf2;

	/*
	 * All TLS relocations are illegal in a static executable.
	 */
	if (OFL_IS_STATIC_EXEC(ofl)) {
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_TLSSTAT),
		    conv_reloc_type(mach, rtype, 0, &inv_buf1), ifl->ifl_name,
		    ld_reloc_sym_name(rsp));
		return (S_ERROR);
	}

	/*
	 * Any TLS relocation must be against a STT_TLS symbol, all others
	 * are illegal.
	 */
	if ((type = ELF_ST_TYPE(sdp->sd_sym->st_info)) != STT_TLS) {
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_TLSBADSYM),
		    conv_reloc_type(mach, rtype, 0, &inv_buf1), ifl->ifl_name,
		    ld_reloc_sym_name(rsp),
		    conv_sym_info_type(mach, type, 0, &inv_buf2));
		return (S_ERROR);
	}

	/*
	 * A dynamic executable can not use the LD or LE reference models to
	 * reference an external symbol.  A shared object can not use the LD
	 * reference model to reference an external symbol.
	 */
	if (!local && (IS_TLS_LD(rtype) ||
	    ((flags & FLG_OF_EXEC) && IS_TLS_LE(rtype)))) {
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_TLSBND),
		    conv_reloc_type(mach, rtype, 0, &inv_buf1), ifl->ifl_name,
		    ld_reloc_sym_name(rsp), sdp->sd_file->ifl_name);
		return (S_ERROR);
	}

	/*
	 * The TLS LE model is only allowed for dynamic executables.  The TLS IE
	 * model is allowed for shared objects, but this model has restrictions.
	 * This model can only be used freely in dependencies that are loaded
	 * immediately as part of process initialization.  However, during the
	 * initial runtime handshake with libc that establishes the thread
	 * pointer, a small backup TLS reservation is created.  This area can
	 * be used by objects that are loaded after threads are initialized.
	 * However, this area is limited in size and may have already been
	 * used.  This area is intended for specialized applications, and does
	 * not provide the degree of flexibility dynamic TLS can offer.  Under
	 * -z verbose indicate this restriction to the user.
	 */
	if ((flags & FLG_OF_EXEC) == 0) {
		if (IS_TLS_LE(rtype)) {
			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_TLSLE),
			    conv_reloc_type(mach, rtype, 0, &inv_buf1),
			    ifl->ifl_name, ld_reloc_sym_name(rsp));
			return (S_ERROR);

		} else if ((IS_TLS_IE(rtype)) &&
		    (flags & FLG_OF_VERBOSE)) {
			ld_eprintf(ofl, ERR_WARNING, MSG_INTL(MSG_REL_TLSIE),
			    conv_reloc_type(mach, rtype, 0, &inv_buf1),
			    ifl->ifl_name, ld_reloc_sym_name(rsp));
		}
	}

	return ((*ld_targ.t_mr.mr_reloc_TLS)(local, rsp, ofl));
}

uintptr_t
ld_process_sym_reloc(Ofl_desc *ofl, Rel_desc *reld, Rel *reloc, Is_desc *isp,
    const char *isname, Word isscnndx)
{
	Word		rtype = reld->rel_rtype;
	ofl_flag_t	flags = ofl->ofl_flags;
	Sym_desc	*sdp = reld->rel_sym;
	Sym_aux		*sap;
	Boolean		local;
	Conv_inv_buf_t	inv_buf;

	DBG_CALL(Dbg_reloc_in(ofl->ofl_lml, ELF_DBG_LD, ld_targ.t_m.m_mach,
	    ld_targ.t_m.m_rel_sht_type, (void *)reloc, isname, isscnndx,
	    ld_reloc_sym_name(reld)));

	/*
	 * Indicate this symbol is being used for relocation and therefore must
	 * have its output address updated accordingly (refer to update_osym()).
	 */
	sdp->sd_flags |= FLG_SY_UPREQD;

	/*
	 * Indicate the section this symbol is defined in has been referenced,
	 * therefor it *is not* a candidate for elimination.
	 */
	if (sdp->sd_isc) {
		sdp->sd_isc->is_flags |= FLG_IS_SECTREF;
		sdp->sd_isc->is_file->ifl_flags |= FLG_IF_FILEREF;
	}

	if (!ld_reloc_set_aux_usym(ofl, reld, sdp))
		return (S_ERROR);

	/*
	 * Determine if this symbol is actually an alias to another symbol.  If
	 * so, and the alias is not REF_DYN_SEEN, set ra_usym to point to the
	 * weak symbols strong counter-part.  The one exception is if the
	 * FLG_SY_MVTOCOMM flag is set on the weak symbol.  If this is the case,
	 * the strong is only here because of its promotion, and the weak symbol
	 * should still be used for the relocation reference (see reloc_exec()).
	 */
	sap = sdp->sd_aux;
	if (sap && sap->sa_linkndx &&
	    ((ELF_ST_BIND(sdp->sd_sym->st_info) == STB_WEAK) ||
	    (sdp->sd_flags & FLG_SY_WEAKDEF)) &&
	    (!(sdp->sd_flags & FLG_SY_MVTOCOMM))) {
		Sym_desc	*_sdp;

		_sdp = sdp->sd_file->ifl_oldndx[sap->sa_linkndx];
		if ((_sdp->sd_ref != REF_DYN_SEEN) &&
		    !ld_reloc_set_aux_usym(ofl, reld, _sdp))
			return (S_ERROR);
	}

	/*
	 * Determine whether this symbol should be bound locally or not.
	 * Symbols are bound locally if one of the following is true:
	 *
	 *  -	the symbol is of type STB_LOCAL.
	 *
	 *  -	the output image is not a relocatable object and the relocation
	 *	is relative to the .got.
	 *
	 *  -	the section being relocated is of type SHT_SUNW_dof.  These
	 *	sections must be bound to the functions in the containing
	 *	object and can not be interposed upon.
	 *
	 *  -	the symbol has been reduced (scoped to a local or symbolic) and
	 *	reductions are being processed.
	 *
	 *  -	the -Bsymbolic flag is in use when building a shared object,
	 *	and the symbol hasn't explicitly been defined as nodirect.
	 *
	 *  -	an executable (fixed address) is being created, and the symbol
	 *	is defined in the executable.
	 *
	 *  -	the relocation is against a segment which will not be loaded
	 *	into memory.  In this case, the relocation must be resolved
	 *	now, as ld.so.1 can not process relocations against unmapped
	 *	segments.
	 */
	local = FALSE;
	if (ELF_ST_BIND(sdp->sd_sym->st_info) == STB_LOCAL) {
		local = TRUE;
	} else if (!(reld->rel_flags & FLG_REL_LOAD)) {
		local = TRUE;
	} else if (sdp->sd_sym->st_shndx != SHN_UNDEF) {
		if (reld->rel_isdesc &&
		    reld->rel_isdesc->is_shdr->sh_type == SHT_SUNW_dof) {
			local = TRUE;
		} else if (!(flags & FLG_OF_RELOBJ) &&
		    (IS_LOCALBND(rtype) || IS_SEG_RELATIVE(rtype))) {
			local = TRUE;
		} else if ((sdp->sd_ref == REF_REL_NEED) &&
		    ((sdp->sd_flags & FLG_SY_CAP) == 0)) {
			/*
			 * Global symbols may have been individually reduced in
			 * scope.  If the whole object is to be self contained,
			 * such as when generating an executable or a symbolic
			 * shared object, make sure all relocation symbol
			 * references (sections too) are treated locally.  Note,
			 * explicit no-direct symbols should not be bound to
			 * locally.
			 */
			if ((sdp->sd_flags &
			    (FLG_SY_HIDDEN | FLG_SY_PROTECT)))
				local = TRUE;
			else if ((flags & FLG_OF_EXEC) ||
			    ((flags & FLG_OF_SYMBOLIC) &&
			    ((sdp->sd_flags & FLG_SY_NDIR) == 0))) {
				local = TRUE;
			}
		}
	}

	/*
	 * If this is a PC_RELATIVE relocation, the relocation could be
	 * compromised if the relocated address is later used as a copy
	 * relocated symbol (PSARC 1999/636, bugid 4187211).  Scan the input
	 * files symbol table to cross reference this relocation offset.
	 */
	if ((ofl->ofl_flags & FLG_OF_SHAROBJ) &&
	    IS_PC_RELATIVE(rtype) &&
	    (IS_GOT_PC(rtype) == 0) &&
	    (IS_PLT(rtype) == 0)) {
		if (disp_inspect(ofl, reld, local) == S_ERROR)
			return (S_ERROR);
	}

	/*
	 * GOT based relocations must bind to the object being built - since
	 * they are relevant to the current GOT.  If not building a relocatable
	 * object - give a appropriate error message.
	 */
	if (!local && !(flags & FLG_OF_RELOBJ) &&
	    IS_GOT_BASED(rtype)) {
		Ifl_desc	*ifl = reld->rel_isdesc->is_file;

		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_BADGOTBASED),
		    conv_reloc_type(ifl->ifl_ehdr->e_machine, rtype,
		    0, &inv_buf), ifl->ifl_name, demangle(sdp->sd_name));
		return (S_ERROR);
	}

	/*
	 * TLS symbols can only have TLS relocations.
	 */
	if ((ELF_ST_TYPE(sdp->sd_sym->st_info) == STT_TLS) &&
	    (IS_TLS_INS(rtype) == 0)) {
		/*
		 * The above test is relaxed if the target section is
		 * non-allocable.
		 */
		if (RELAUX_GET_OSDESC(reld)->os_shdr->sh_flags & SHF_ALLOC) {
			Ifl_desc	*ifl = reld->rel_isdesc->is_file;

			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_BADTLS),
			    conv_reloc_type(ifl->ifl_ehdr->e_machine,
			    rtype, 0, &inv_buf), ifl->ifl_name,
			    demangle(sdp->sd_name));
			return (S_ERROR);
		}
	}

	/*
	 * Select the relocation to perform.
	 */
	if (IS_REGISTER(rtype)) {
		if (ld_targ.t_mr.mr_reloc_register == NULL) {
			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_NOREG));
			return (S_ERROR);
		}
		return ((*ld_targ.t_mr.mr_reloc_register)(reld, isp, ofl));
	}

	if (flags & FLG_OF_RELOBJ)
		return (reloc_relobj(local, reld, ofl));

	if (IS_TLS_INS(rtype))
		return (reloc_TLS(local, reld, ofl));

	if (IS_GOT_OPINS(rtype)) {
		if (ld_targ.t_mr.mr_reloc_GOTOP == NULL) {
			assert(0);
			return (S_ERROR);
		}
		return ((*ld_targ.t_mr.mr_reloc_GOTOP)(local, reld, ofl));
	}

	if (IS_GOT_RELATIVE(rtype))
		return (ld_reloc_GOT_relative(local, reld, ofl));

	if (local)
		return ((*ld_targ.t_mr.mr_reloc_local)(reld, ofl));

	if ((IS_PLT(rtype) || ((sdp->sd_flags & FLG_SY_CAP) &&
	    (ELF_ST_TYPE(sdp->sd_sym->st_info) == STT_FUNC))) &&
	    ((flags & FLG_OF_BFLAG) == 0))
		return (ld_reloc_plt(reld, ofl));

	if ((sdp->sd_ref == REF_REL_NEED) ||
	    (flags & FLG_OF_BFLAG) || (flags & FLG_OF_SHAROBJ) ||
	    (ELF_ST_TYPE(sdp->sd_sym->st_info) == STT_NOTYPE))
		return ((*ld_targ.t_mr.mr_add_outrel)(0, reld, ofl));

	if (sdp->sd_ref == REF_DYN_NEED)
		return (reloc_exec(reld, ofl));

	/*
	 * IS_NOT_REL(rtype)
	 */
	return (reloc_generic(reld, ofl));
}

/*
 * Given a relocation that references a local symbol from a discarded COMDAT
 * section, replace the symbol with the corresponding symbol from the section
 * that was kept.
 *
 * entry:
 *	reld - Relocation
 *	sdp - Symbol to be replaced. Must be a local symbol (STB_LOCAL).
 *	reject - Address of variable to receive rejection code
 *		if no replacement symbol is found.
 *
 * exit:
 *	Returns address of replacement symbol descriptor if one was
 *	found, and NULL otherwise. The result is also cached in
 *	ofl->ofl_sr_cache as an optimization to speed following calls
 *	for the same value of sdp.
 *
 *	On success (non-NULL result), *reject is set to RLXREL_REJ_NONE.
 *	On failure (NULL result), *reject is filled in with a code
 *	describing the underlying reason.
 *
 * note:
 *	The word "COMDAT" is used to refer to actual COMDAT sections, COMDAT
 *	groups tied together with an SHF_GROUP section, and .gnu.linkonce
 *	sections which provide a simplified COMDAT requirement.  COMDAT
 *	sections are identified with the FLG_IS_COMDAT section flag.
 *
 *	In principle, this sort of sloppy relocation remapping is
 *	a questionable practice. All self-referential sections should
 *	be in a common SHF_GROUP so that they are all kept or removed
 *	together. The problem is that there is no way to ensure that the
 *	two sections are similar enough that the replacement section will
 *	really supply the correct information. However, we see a couple of
 *	situations where it is useful to do this: (1) Older Sun C compilers
 *	generated DWARF sections that would refer to one of the COMDAT
 *	sections, and (2) gcc, when its GNU linkonce COMDAT feature is enabled.
 *	It turns out that the GNU ld does these sloppy remappings.
 *
 *	The GNU ld takes an approach that hard wires special section
 *	names and treats them specially. We avoid that practice and
 *	try to get the necessary work done relying only on the ELF
 *	attributes of the sections and symbols involved. This means
 *	that our heuristic is somewhat different than theirs, but the
 *	end result is close enough to solve the same problem.
 *
 *	gcc is in the process of converting to SHF_GROUP. This will
 *	eventually phase out the need for sloppy relocations, and
 *	then this logic won't be needed. In the meantime, relaxed relocation
 *	processing allows us to interoperate.
 */
static Sym_desc *
sloppy_comdat_reloc(Ofl_desc *ofl, Rel_desc *reld, Sym_desc *sdp,
    Rlxrel_rej *reject)
{
	Is_desc		*rep_isp;
	Sym		*sym, *rep_sym;
	Is_desc		*isp;
	Ifl_desc	*ifl;
	Conv_inv_buf_t	inv_buf;
	Word		scnndx, symscnt;
	Sym_desc	**oldndx, *rep_sdp;
	const char	*is_name;


	/*
	 * Sloppy relocations are never applied to .eh_frame or
	 * .gcc_except_table sections. The entries in these sections
	 * for discarded sections are better left uninitialized.
	 *
	 * We match these sections by name, because on most platforms they
	 * are SHT_PROGBITS, and cannot be identified otherwise. On amd64
	 * architectures, .eh_frame is SHT_AMD64_UNWIND, but that is ambiguous
	 * (.eh_frame_hdr is also SHT_AMD64_UNWIND), so we still match it by
	 * name.
	 */
	is_name = reld->rel_isdesc->is_name;
	if (((is_name[1] == 'e') &&
	    (strcmp(is_name, MSG_ORIG(MSG_SCN_EHFRAME)) == 0)) ||
	    ((is_name[1] == 'g') &&
	    (strcmp(is_name, MSG_ORIG(MSG_SCN_GCC_X_TBL)) == 0))) {
		*reject = RLXREL_REJ_TARGET;
		return (NULL);
	}

	/*
	 * If we looked up the same symbol on the previous call, we can
	 * return the cached value.
	 */
	if (sdp == ofl->ofl_sr_cache.sr_osdp) {
		*reject = ofl->ofl_sr_cache.sr_rej;
		return (ofl->ofl_sr_cache.sr_rsdp);
	}

	ofl->ofl_sr_cache.sr_osdp = sdp;
	sym = sdp->sd_sym;
	isp = sdp->sd_isc;
	ifl = sdp->sd_file;

	/*
	 * When a COMDAT section is discarded in favor of another COMDAT
	 * section, the replacement is recorded in its section descriptor
	 * (is_comdatkeep). We must validate the replacement before using
	 * it. The replacement section must:
	 *	- Not have been discarded
	 *	- Have the same size (*)
	 *	- Have the same section type
	 *	- Have the same SHF_GROUP flag setting (either on or off)
	 *	- Must be a COMDAT section of one form or the other.
	 *
	 * (*) One might imagine that the replacement section could be
	 * larger than the original, rather than the exact size. However,
	 * we have verified that this is the same policy used by the GNU
	 * ld. If the sections are not the same size, the chance of them
	 * being interchangeable drops significantly.
	 */
	if (((rep_isp = isp->is_comdatkeep) == NULL) ||
	    ((rep_isp->is_flags & FLG_IS_DISCARD) != 0) ||
	    ((rep_isp->is_flags & FLG_IS_COMDAT) == 0) ||
	    (isp->is_indata->d_size != rep_isp->is_indata->d_size) ||
	    (isp->is_shdr->sh_type != rep_isp->is_shdr->sh_type) ||
	    ((isp->is_shdr->sh_flags & SHF_GROUP) !=
	    (rep_isp->is_shdr->sh_flags & SHF_GROUP))) {
		*reject = ofl->ofl_sr_cache.sr_rej = RLXREL_REJ_SECTION;
		return (ofl->ofl_sr_cache.sr_rsdp = NULL);
	}

	/*
	 * We found the kept COMDAT section. Now, look at all of the
	 * symbols from the input file that contains it to find the
	 * symbol that corresponds to the one we started with:
	 *	- Hasn't been discarded
	 *	- Has section index of kept section
	 *	- If one symbol has a name, the other must have
	 *		the same name. The st_name field of a symbol
	 *		is 0 if there is no name, and is a string
	 *		table offset otherwise. The string table
	 *		offsets may well not agree --- it is the
	 *		actual string that matters.
	 *	- Type and binding attributes match (st_info)
	 *	- Values match (st_value)
	 *	- Sizes match (st_size)
	 *	- Visibility matches (st_other)
	 */
	scnndx = rep_isp->is_scnndx;
	oldndx = rep_isp->is_file->ifl_oldndx;
	symscnt = rep_isp->is_file->ifl_symscnt;
	while (symscnt--) {
		rep_sdp = *oldndx++;
		if ((rep_sdp == NULL) || (rep_sdp->sd_flags & FLG_SY_ISDISC) ||
		    ((rep_sym = rep_sdp->sd_sym)->st_shndx != scnndx) ||
		    ((sym->st_name == 0) != (rep_sym->st_name == 0)) ||
		    ((sym->st_name != 0) &&
		    (strcmp(sdp->sd_name, rep_sdp->sd_name) != 0)) ||
		    (sym->st_info != rep_sym->st_info) ||
		    (sym->st_value != rep_sym->st_value) ||
		    (sym->st_size != rep_sym->st_size) ||
		    (sym->st_other != rep_sym->st_other))
			continue;


		if (ofl->ofl_flags & FLG_OF_VERBOSE) {
			if (sym->st_name != 0) {
				ld_eprintf(ofl, ERR_WARNING,
				    MSG_INTL(MSG_REL_SLOPCDATNAM),
				    conv_reloc_type(ifl->ifl_ehdr->e_machine,
				    reld->rel_rtype, 0, &inv_buf),
				    ifl->ifl_name,
				    EC_WORD(reld->rel_isdesc->is_scnndx),
				    reld->rel_isdesc->is_name,
				    rep_sdp->sd_name,
				    EC_WORD(isp->is_scnndx), isp->is_name,
				    rep_sdp->sd_file->ifl_name);
			} else {
				ld_eprintf(ofl, ERR_WARNING,
				    MSG_INTL(MSG_REL_SLOPCDATNONAM),
				    conv_reloc_type(ifl->ifl_ehdr->e_machine,
				    reld->rel_rtype, 0, &inv_buf),
				    ifl->ifl_name,
				    EC_WORD(reld->rel_isdesc->is_scnndx),
				    reld->rel_isdesc->is_name,
				    EC_WORD(isp->is_scnndx), isp->is_name,
				    rep_sdp->sd_file->ifl_name);
			}
		}
		DBG_CALL(Dbg_reloc_sloppycomdat(ofl->ofl_lml, rep_sdp));
		*reject = ofl->ofl_sr_cache.sr_rej = RLXREL_REJ_NONE;
		return (ofl->ofl_sr_cache.sr_rsdp = rep_sdp);
	}

	/* If didn't return above, we didn't find it */
	*reject = ofl->ofl_sr_cache.sr_rej = RLXREL_REJ_SYMBOL;
	return (ofl->ofl_sr_cache.sr_rsdp = NULL);
}

/*
 * Generate relocation descriptor and dispatch
 */
static uintptr_t
process_reld(Ofl_desc *ofl, Is_desc *isp, Rel_desc *reld, Word rsndx,
    Rel *reloc)
{
	Ifl_desc	*ifl = isp->is_file;
	Word		rtype = reld->rel_rtype;
	Sym_desc	*sdp;
	Conv_inv_buf_t	inv_buf;

	/*
	 * Make sure the relocation is in the valid range.
	 */
	if (rtype >= ld_targ.t_m.m_r_num) {
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_INVALRELT),
		    ifl->ifl_name, EC_WORD(isp->is_scnndx), isp->is_name,
		    rtype);
		return (S_ERROR);
	}

	ofl->ofl_entrelscnt++;

	/*
	 * Special case: a register symbol associated with symbol index 0 is
	 * initialized (i.e., relocated) to a constant from the r_addend field
	 * rather than from a symbol value.
	 */
	if (IS_REGISTER(rtype) && (rsndx == 0)) {
		reld->rel_sym = NULL;
		DBG_CALL(Dbg_reloc_in(ofl->ofl_lml, ELF_DBG_LD,
		    ld_targ.t_m.m_mach, isp->is_shdr->sh_type,
		    (void *)reloc, isp->is_name, isp->is_scnndx,
		    ld_reloc_sym_name(reld)));
		if (ld_targ.t_mr.mr_reloc_register == NULL) {
			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_NOREG));
			return (S_ERROR);
		}
		return ((*ld_targ.t_mr.mr_reloc_register)(reld, isp, ofl));
	}

	/*
	 * If this is a STT_SECTION symbol, make sure the associated
	 * section has a descriptive non-NULL is_sym_name field that can
	 * be accessed by ld_reloc_sym_name() to satisfy debugging output
	 * and errors.
	 *
	 * In principle, we could add this string to every input section
	 * as it is created, but we defer it until we see a relocation
	 * symbol that might need it. Not every section will have such
	 * a relocation, so we create fewer of them this way.
	 */
	sdp = reld->rel_sym = ifl->ifl_oldndx[rsndx];
	if ((sdp != NULL) &&
	    (ELF_ST_TYPE(sdp->sd_sym->st_info) == STT_SECTION) &&
	    (sdp->sd_isc != NULL) && (sdp->sd_isc->is_name != NULL) &&
	    (sdp->sd_isc->is_sym_name == NULL) &&
	    (ld_stt_section_sym_name(sdp->sd_isc) == NULL))
		return (S_ERROR);

	/*
	 * If for some reason we have a null relocation record issue a
	 * warning and continue (the compiler folks can get into this
	 * state some time).  Normal users should never see this error.
	 */
	if (rtype == ld_targ.t_m.m_r_none) {
		DBG_CALL(Dbg_reloc_in(ofl->ofl_lml, ELF_DBG_LD,
		    ld_targ.t_m.m_mach, ld_targ.t_m.m_rel_sht_type,
		    (void *)reloc, isp->is_name, isp->is_scnndx,
		    ld_reloc_sym_name(reld)));
		ld_eprintf(ofl, ERR_WARNING, MSG_INTL(MSG_REL_NULL),
		    ifl->ifl_name, EC_WORD(isp->is_scnndx), isp->is_name);
		return (1);
	}

	if (((ofl->ofl_flags & FLG_OF_RELOBJ) == 0) &&
	    IS_NOTSUP(rtype)) {
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_NOTSUP),
		    conv_reloc_type(ifl->ifl_ehdr->e_machine, rtype,
		    0, &inv_buf), ifl->ifl_name, EC_WORD(isp->is_scnndx),
		    isp->is_name);
		return (S_ERROR);
	}

	/*
	 * If we are here, we know that the relocation requires reference
	 * symbol. If no symbol is assigned, this is a fatal error.
	 */
	if (sdp == NULL) {
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_NOSYMBOL),
		    conv_reloc_type(ifl->ifl_ehdr->e_machine, rtype,
		    0, &inv_buf), ifl->ifl_name, EC_WORD(isp->is_scnndx),
		    isp->is_name, EC_XWORD(reloc->r_offset));
		return (S_ERROR);
	}

	if (sdp->sd_flags & FLG_SY_IGNORE)
		return (1);

	/*
	 * If this symbol is part of a DISCARDED section attempt to find another
	 * definition.
	 */
	if (sdp->sd_flags & FLG_SY_ISDISC) {
		Sym_desc	*nsdp = NULL;
		Rlxrel_rej	reject;

		if (ELF_ST_BIND(sdp->sd_sym->st_info) == STB_LOCAL) {
			/*
			 * If "-z relaxreloc", and the input section is COMDAT
			 * that has been assigned to an output section, then
			 * determine if this is a reference to a discarded
			 * COMDAT section that can be replaced with a COMDAT
			 * that has been kept.
			 */
			if ((ofl->ofl_flags1 & FLG_OF1_RLXREL) &&
			    sdp->sd_isc->is_osdesc &&
			    (sdp->sd_isc->is_flags & FLG_IS_COMDAT) &&
			    ((nsdp = sloppy_comdat_reloc(ofl, reld,
			    sdp, &reject)) == NULL)) {
				Shdr	*is_shdr = reld->rel_isdesc->is_shdr;

				/*
				 * A matching symbol was not found. We will
				 * ignore this relocation.  Determine whether
				 * or not to issue a warning.
				 * Warnings are always issued under -z verbose,
				 * but otherwise, we will follow the lead of
				 * the GNU ld and suppress them for certain
				 * cases:
				 *
				 *  -	It is a non-allocable debug section.
				 *	The GNU ld tests for these by name,
				 *	but we are willing to extend it to
				 *	any non-allocable section.
				 *  -	The target section is excluded from
				 *	sloppy relocations by policy.
				 */
				if (((ofl->ofl_flags & FLG_OF_VERBOSE) != 0) ||
				    ((is_shdr->sh_flags & SHF_ALLOC) &&
				    (reject != RLXREL_REJ_TARGET)))
					ld_eprintf(ofl, ERR_WARNING,
					    MSG_INTL(MSG_REL_SLOPCDATNOSYM),
					    conv_reloc_type(
					    ifl->ifl_ehdr->e_machine,
					    reld->rel_rtype, 0, &inv_buf),
					    ifl->ifl_name,
					    EC_WORD(isp->is_scnndx),
					    isp->is_name,
					    ld_reloc_sym_name(reld),
					    EC_WORD(sdp->sd_isc->is_scnndx),
					    sdp->sd_isc->is_name);
				return (1);
			}
		} else if ((sdp != NULL) && sdp->sd_name && *sdp->sd_name)
			nsdp = ld_sym_find(sdp->sd_name, SYM_NOHASH, NULL, ofl);

		if (nsdp == NULL) {
			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_SYMDISC),
			    conv_reloc_type(ifl->ifl_ehdr->e_machine,
			    reld->rel_rtype, 0, &inv_buf), ifl->ifl_name,
			    EC_WORD(isp->is_scnndx), isp->is_name,
			    ld_reloc_sym_name(reld),
			    EC_WORD(sdp->sd_isc->is_scnndx),
			    sdp->sd_isc->is_name);
			return (S_ERROR);
		}
		ifl->ifl_oldndx[rsndx] = sdp = nsdp;
		if ((ELF_ST_TYPE(sdp->sd_sym->st_info) == STT_SECTION) &&
		    (sdp->sd_isc != NULL) && (sdp->sd_isc->is_name != NULL) &&
		    (sdp->sd_isc->is_sym_name == NULL) &&
		    (ld_stt_section_sym_name(sdp->sd_isc) == NULL))
			return (S_ERROR);
	}

	/*
	 * If this is a global symbol, determine whether its visibility needs
	 * adjusting.
	 */
	if (sdp->sd_aux && ((sdp->sd_flags & FLG_SY_VISIBLE) == 0))
		ld_sym_adjust_vis(sdp, ofl);

	/*
	 * Ignore any relocation against a section that will not be in the
	 * output file (has been stripped).
	 */
	if ((sdp->sd_isc == 0) &&
	    (ELF_ST_TYPE(sdp->sd_sym->st_info) == STT_SECTION))
		return (1);

	/*
	 * If the input section exists, but the section has not been associated
	 * to an output section, then this is a little suspicious.
	 */
	if (sdp->sd_isc && (sdp->sd_isc->is_osdesc == 0) &&
	    (ELF_ST_TYPE(sdp->sd_sym->st_info) == STT_SECTION)) {
		ld_eprintf(ofl, ERR_WARNING, MSG_INTL(MSG_RELINVSEC),
		    conv_reloc_type(ifl->ifl_ehdr->e_machine, rtype,
		    0, &inv_buf), ifl->ifl_name, EC_WORD(isp->is_scnndx),
		    isp->is_name, EC_WORD(sdp->sd_isc->is_scnndx),
		    sdp->sd_isc->is_name);
		return (1);
	}

	/*
	 * If the symbol for this relocation is invalid (which should have
	 * generated a message during symbol processing), or the relocation
	 * record's symbol reference is in any other way invalid, then it's
	 * about time we gave up.
	 */
	if ((sdp->sd_flags & FLG_SY_INVALID) || (rsndx == 0) ||
	    (rsndx >= ifl->ifl_symscnt)) {
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_UNKNWSYM),
		    conv_reloc_type(ifl->ifl_ehdr->e_machine, rtype,
		    0, &inv_buf), ifl->ifl_name, EC_WORD(isp->is_scnndx),
		    isp->is_name, ld_reloc_sym_name(reld),
		    EC_XWORD(reloc->r_offset), EC_WORD(rsndx));
		return (S_ERROR);
	}

	/*
	 * Size relocations against section symbols are presently unsupported.
	 * There is a question as to whether the input section size, or output
	 * section size would be used.  Until an explicit requirement is
	 * established for either case, we'll punt.
	 */
	if (IS_SIZE(rtype) &&
	    (ELF_ST_TYPE(sdp->sd_sym->st_info) == STT_SECTION)) {
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_UNSUPSIZE),
		    conv_reloc_type(ifl->ifl_ehdr->e_machine, rtype,
		    0, &inv_buf), ifl->ifl_name, EC_WORD(isp->is_scnndx),
		    isp->is_name);
		return (S_ERROR);
	}

	reld->rel_sym = sdp;
	if (reld->rel_aux)
		reld->rel_aux->ra_usym = sdp;
	return (ld_process_sym_reloc(ofl, reld, reloc, isp, isp->is_name,
	    isp->is_scnndx));
}

static uintptr_t
reloc_section(Ofl_desc *ofl, Is_desc *isect, Is_desc *rsect, Os_desc *osect)
{
	Rel		*rend;		/* end of relocation section data */
	Rel		*reloc;		/* current relocation entry */
	Xword		rsize;		/* size of relocation section data */
	Xword		entsize;	/* size of relocation entry */
	Rel_desc	reld;		/* relocation descriptor */
	Rel_aux	rel_aux;
	Shdr *		shdr;
	Word		flags = 0;
	uintptr_t	ret = 1;

	shdr = rsect->is_shdr;
	rsize = shdr->sh_size;
	reloc = (Rel *)rsect->is_indata->d_buf;

	/*
	 * Decide entry size.
	 */
	if (((entsize = shdr->sh_entsize) == 0) || (entsize > rsize)) {
		if (shdr->sh_type == SHT_RELA)
			entsize = sizeof (Rela);
		else
			entsize = sizeof (Rel);
	}

	/*
	 * Build up the basic information in for the Rel_desc structure.
	 */
	reld.rel_isdesc = isect;
	reld.rel_aux = &rel_aux;
	ld_init_rel_aux(&reld);
	rel_aux.ra_osdesc = osect;

	if ((ofl->ofl_flags & FLG_OF_RELOBJ) ||
	    (osect && (osect->os_sgdesc->sg_phdr.p_type == PT_LOAD)))
		flags |= FLG_REL_LOAD;

	if (shdr->sh_info == 0)
		flags |= FLG_REL_NOINFO;

	DBG_CALL(Dbg_reloc_proc(ofl->ofl_lml, osect, isect, rsect));

	for (rend = (Rel *)((uintptr_t)reloc + (uintptr_t)rsize);
	    reloc < rend;
	    reloc = (Rel *)((uintptr_t)reloc + (uintptr_t)entsize)) {
		Word	rsndx;

		/*
		 * Initialize the relocation record information and process
		 * the individual relocation.  Reinitialize the flags to
		 * insure we don't carry any state over from the previous
		 * relocation records processing.
		 */
		reld.rel_flags = flags;
		rsndx = (*ld_targ.t_mr.mr_init_rel)(&reld,
		    &rel_aux.ra_typedata, (void *)reloc);

		/*
		 * Determine whether or not to pass an auxiliary block
		 * in with this Rel_desc. It is not needed if both the
		 * osdesc and typedata fields have default values.
		 */
		reld.rel_aux =
		    (RELAUX_ISDEFAULT_OSDESC(&reld, rel_aux.ra_osdesc) &&
		    RELAUX_ISDEFAULT_TYPEDATA(&reld, rel_aux.ra_typedata)) ?
		    NULL : &rel_aux;

		if (process_reld(ofl, rsect, &reld, rsndx, reloc) == S_ERROR)
			ret = S_ERROR;
	}
	return (ret);
}

static uintptr_t
reloc_segments(int wr_flag, Ofl_desc *ofl)
{
	Aliste		idx1;
	Sg_desc		*sgp;
	Is_desc		*isp;

	for (APLIST_TRAVERSE(ofl->ofl_segs, idx1, sgp)) {
		Os_desc	*osp;
		Aliste	idx2;

		if ((sgp->sg_phdr.p_flags & PF_W) != wr_flag)
			continue;

		for (APLIST_TRAVERSE(sgp->sg_osdescs, idx2, osp)) {
			Is_desc	*risp;
			Aliste	idx3;

			osp->os_szoutrels = 0;
			for (APLIST_TRAVERSE(osp->os_relisdescs, idx3, risp)) {
				Word	indx;

				/*
				 * Determine the input section that this
				 * relocation information refers to.
				 */
				indx = risp->is_shdr->sh_info;
				isp = risp->is_file->ifl_isdesc[indx];

				/*
				 * Do not process relocations against sections
				 * which are being discarded (COMDAT)
				 */
				if (isp->is_flags & FLG_IS_DISCARD)
					continue;

				if (reloc_section(ofl, isp, risp, osp) ==
				    S_ERROR)
					return (S_ERROR);
			}

			/*
			 * Check for relocations against non-writable
			 * allocatable sections.
			 */
			if (osp->os_szoutrels &&
			    (sgp->sg_phdr.p_type == PT_LOAD) &&
			    ((sgp->sg_phdr.p_flags & PF_W) == 0)) {
				ofl->ofl_flags |= FLG_OF_TEXTREL;
				ofl->ofl_dtflags |= DF_TEXTREL;
			}
		}
	}

	return (1);
}

/*
 * Move Section related function
 * Get move entry
 */
static Move *
get_move_entry(Is_desc *rsect, Xword roffset)
{
	Ifl_desc	*ifile = rsect->is_file;
	Shdr		*rshdr = rsect->is_shdr;
	Is_desc		*misp;
	Shdr		*mshdr;
	Xword		midx;
	Move		*mvp;

	/*
	 * Set info for the target move section
	 */
	misp = ifile->ifl_isdesc[rshdr->sh_info];
	mshdr = misp->is_shdr;

	if (mshdr->sh_entsize == 0)
		return (NULL);

	/*
	 * If this is an invalid entry, return NULL.
	 */
	midx = roffset / mshdr->sh_entsize;
	if ((midx * mshdr->sh_entsize) >= mshdr->sh_size)
		return (NULL);

	mvp = (Move *)misp->is_indata->d_buf;
	mvp += midx;
	return (mvp);
}

/*
 * Relocation against Move Table.
 */
static uintptr_t
process_movereloc(Ofl_desc *ofl, Is_desc *rsect)
{
	Ifl_desc	*file = rsect->is_file;
	Rel		*rend, *reloc;
	Xword		rsize, entsize;
	Rel_desc	reld;
	Rel_aux	rel_aux;

	rsize = rsect->is_shdr->sh_size;
	reloc = (Rel *)rsect->is_indata->d_buf;

	/*
	 * Decide entry size.
	 */
	entsize = rsect->is_shdr->sh_entsize;
	if ((entsize == 0) ||
	    (entsize > rsect->is_shdr->sh_size)) {
		if (rsect->is_shdr->sh_type == SHT_RELA)
			entsize = sizeof (Rela);
		else
			entsize = sizeof (Rel);
	}

	/*
	 * The requirement for move data ensures that we have to supply a
	 * Rel_aux auxiliary block.
	 */
	reld.rel_aux = &rel_aux;
	ld_init_rel_aux(&reld);

	/*
	 * Go through the relocation entries.
	 */
	for (rend = (Rel *)((uintptr_t)reloc + (uintptr_t)rsize);
	    reloc < rend;
	    reloc = (Rel *)((uintptr_t)reloc + (uintptr_t)entsize)) {
		Sym_desc	*psdp;
		Move		*mvp;
		Word		rsndx;

		/*
		 * Initialize the relocation record information.
		 */
		reld.rel_flags = FLG_REL_LOAD;
		rsndx = (*ld_targ.t_mr.mr_init_rel)(&reld,
		    &rel_aux.ra_typedata, (void *)reloc);

		if (((mvp = get_move_entry(rsect, reloc->r_offset)) == NULL) ||
		    ((rel_aux.ra_move =
		    libld_malloc(sizeof (Mv_reloc))) == NULL))
			return (S_ERROR);

		psdp = file->ifl_oldndx[ELF_M_SYM(mvp->m_info)];
		rel_aux.ra_move->mr_move = mvp;
		rel_aux.ra_move->mr_sym = psdp;

		if (psdp->sd_flags & FLG_SY_PAREXPN) {
			int	_num, num = mvp->m_repeat;

			rel_aux.ra_osdesc = ofl->ofl_isparexpn->is_osdesc;
			reld.rel_isdesc = ofl->ofl_isparexpn;
			reld.rel_roffset = mvp->m_poffset;

			for (_num = 0; _num < num; _num++) {
				reld.rel_roffset +=
				    /* LINTED */
				    (_num * ELF_M_SIZE(mvp->m_info));

				/*
				 * Generate Reld
				 */
				if (process_reld(ofl,
				    rsect, &reld, rsndx, reloc) == S_ERROR)
					return (S_ERROR);
			}
		} else {
			/*
			 * Generate Reld
			 */
			reld.rel_flags |= FLG_REL_MOVETAB;
			rel_aux.ra_osdesc = ofl->ofl_osmove;
			reld.rel_isdesc = ld_os_first_isdesc(ofl->ofl_osmove);

			if (process_reld(ofl,
			    rsect, &reld, rsndx, reloc) == S_ERROR)
				return (S_ERROR);
		}
	}
	return (1);
}

/*
 * This function is similar to reloc_init().
 *
 * This function is called when the SHT_SUNW_move table is expanded and there
 * are relocations against the SHT_SUNW_move section.
 */
static uintptr_t
reloc_movesections(Ofl_desc *ofl)
{
	Aliste		idx;
	Is_desc		*risp;
	uintptr_t	ret = 1;

	/*
	 * Generate/Expand relocation entries
	 */
	for (APLIST_TRAVERSE(ofl->ofl_ismoverel, idx, risp)) {
		if (process_movereloc(ofl, risp) == S_ERROR)
			ret = S_ERROR;
	}

	return (ret);
}

/*
 * Count the number of output relocation entries, global offset table entries,
 * and procedure linkage table entries.  This function searches the segment and
 * outsect lists and passes each input reloc section to process_reloc().
 * It allocates space for any output relocations needed.  And builds up
 * the relocation structures for later processing.
 */
uintptr_t
ld_reloc_init(Ofl_desc *ofl)
{
	Aliste		idx;
	Is_desc		*isp;
	Sym_desc	*sdp;

	DBG_CALL(Dbg_basic_collect(ofl->ofl_lml));

	/*
	 * At this point we have finished processing all input symbols.  Make
	 * sure we add any absolute (internal) symbols before continuing with
	 * any relocation processing.
	 */
	if (ld_sym_spec(ofl) == S_ERROR)
		return (S_ERROR);

	ofl->ofl_gotcnt = ld_targ.t_m.m_got_xnumber;

	/*
	 * Process all of the relocations against NON-writable segments
	 * followed by relocations against the writable segments.
	 *
	 * This separation is so that when the writable segments are processed
	 * we know whether or not a COPYRELOC will be produced for any symbols.
	 * If relocations aren't processed in this order, a COPYRELOC and a
	 * regular relocation can be produced against the same symbol.  The
	 * regular relocation would be redundant.
	 */
	if (reloc_segments(0, ofl) == S_ERROR)
		return (S_ERROR);

	if (reloc_segments(PF_W, ofl) == S_ERROR)
		return (S_ERROR);

	/*
	 * Process any extra relocations.  These are relocation sections that
	 * have a NULL sh_info.
	 */
	for (APLIST_TRAVERSE(ofl->ofl_extrarels, idx, isp)) {
		if (reloc_section(ofl, NULL, isp, NULL) == S_ERROR)
			return (S_ERROR);
	}

	/*
	 * If there were relocation against move table,
	 * process the relocation sections.
	 */
	if (reloc_movesections(ofl) == S_ERROR)
		return (S_ERROR);

	/*
	 * Now all the relocations are pre-processed,
	 * check the validity of copy relocations.
	 */
	if (ofl->ofl_copyrels) {
		Copy_rel	*crp;

		for (ALIST_TRAVERSE(ofl->ofl_copyrels, idx, crp)) {
			/*
			 * If there were no displacement relocation
			 * in this file, don't worry about it.
			 */
			if (crp->c_sdp->sd_file->ifl_flags &
			    (FLG_IF_DISPPEND | FLG_IF_DISPDONE))
				is_disp_copied(ofl, crp);
		}
	}

	/*
	 * GOT sections are created for dynamic executables and shared objects
	 * if the FLG_OF_BLDGOT is set, or explicit reference has been made to
	 * a GOT symbol.
	 */
	if (((ofl->ofl_flags & FLG_OF_RELOBJ) == 0) &&
	    ((ofl->ofl_flags & FLG_OF_BLDGOT) ||
	    ((((sdp = ld_sym_find(MSG_ORIG(MSG_SYM_GOFTBL),
	    SYM_NOHASH, NULL, ofl)) != NULL) ||
	    ((sdp = ld_sym_find(MSG_ORIG(MSG_SYM_GOFTBL_U),
	    SYM_NOHASH, NULL, ofl)) != NULL)) &&
	    (sdp->sd_ref != REF_DYN_SEEN)))) {
		if (ld_make_got(ofl) == S_ERROR)
			return (S_ERROR);

		/* Allocate the GOT if required by target */
		if ((ld_targ.t_mr.mr_allocate_got != NULL) &&
		    ((*ld_targ.t_mr.mr_allocate_got)(ofl) == S_ERROR))
			return (S_ERROR);
	}

	return (1);
}

/*
 * Simple comparison routine to be used by qsort() for
 * the sorting of the output relocation list.
 *
 * The reloc_compare() routine results in a relocation
 * table which is located on:
 *
 *	file referenced (NEEDED NDX)
 *	referenced symbol
 *	relocation offset
 *
 * This provides the most efficient traversal of the relocation
 * table at run-time.
 */
static int
reloc_compare(Reloc_list *i, Reloc_list *j)
{

	/*
	 * first - sort on neededndx
	 */
	if (i->rl_key1 > j->rl_key1)
		return (1);
	if (i->rl_key1 < j->rl_key1)
		return (-1);

	/*
	 * Then sort on symbol
	 */
	if ((uintptr_t)i->rl_key2 > (uintptr_t)j->rl_key2)
		return (1);
	if ((uintptr_t)i->rl_key2 < (uintptr_t)j->rl_key2)
		return (-1);

	/*
	 * i->key2 == j->key2
	 *
	 * At this point we fall back to key2 (offsets) to
	 * sort the output relocations.  Ideally this will
	 * make for the most efficient processing of these
	 * relocations at run-time.
	 */
	if (i->rl_key3 > j->rl_key3)
		return (1);
	if (i->rl_key3 < j->rl_key3)
		return (-1);
	return (0);
}

static uintptr_t
do_sorted_outrelocs(Ofl_desc *ofl)
{
	Rel_desc	*orsp;
	Rel_cachebuf	*rcbp;
	Aliste		idx;
	Reloc_list	*sorted_list;
	Word		index = 0;
	int		debug = 0;
	uintptr_t	error = 1;
	Boolean		remain_seen = FALSE;

	if ((sorted_list = libld_malloc((size_t)(sizeof (Reloc_list) *
	    ofl->ofl_reloccnt))) == NULL)
		return (S_ERROR);

	/*
	 * All but the PLT output relocations are sorted in the output file
	 * based upon their sym_desc.  By doing this multiple relocations
	 * against the same symbol are grouped together, thus when the object
	 * is later relocated by ld.so.1 it will take advantage of the symbol
	 * cache that ld.so.1 has.  This can significantly reduce the runtime
	 * relocation cost of a dynamic object.
	 *
	 * PLT relocations are not sorted because the order of the PLT
	 * relocations is used by ld.so.1 to determine what symbol a PLT
	 * relocation is against.
	 */
	REL_CACHE_TRAVERSE(&ofl->ofl_outrels, idx, rcbp, orsp) {
		if (debug == 0) {
			DBG_CALL(Dbg_reloc_dooutrel(ofl->ofl_lml,
			    ld_targ.t_m.m_rel_sht_type));
			debug = 1;
		}

		/*
		 * If it's a PLT relocation we output it now in the
		 * order that it was originally processed.
		 */
		if (orsp->rel_flags & FLG_REL_PLT) {
			if ((*ld_targ.t_mr.mr_perform_outreloc)
			    (orsp, ofl, &remain_seen) == S_ERROR)
				error = S_ERROR;
			continue;
		}

		if ((orsp->rel_rtype == ld_targ.t_m.m_r_relative) ||
		    (orsp->rel_rtype == ld_targ.t_m.m_r_register)) {
			sorted_list[index].rl_key1 = 0;
			sorted_list[index].rl_key2 =
			    /* LINTED */
			    (Sym_desc *)(uintptr_t)orsp->rel_rtype;
		} else {
			sorted_list[index].rl_key1 =
			    orsp->rel_sym->sd_file->ifl_neededndx;
			sorted_list[index].rl_key2 = orsp->rel_sym;
		}

		if (orsp->rel_flags & FLG_REL_GOT) {
			sorted_list[index].rl_key3 =
			    (*ld_targ.t_mr.mr_calc_got_offset)(orsp, ofl);
		} else {
			if (orsp->rel_rtype == ld_targ.t_m.m_r_register) {
					sorted_list[index].rl_key3 = 0;
			} else {
				sorted_list[index].rl_key3 = orsp->rel_roffset +
				    (Xword)_elf_getxoff(orsp->
				    rel_isdesc->is_indata) +
				    orsp->rel_isdesc->is_osdesc->
				    os_shdr->sh_addr;
			}
		}

		sorted_list[index++].rl_rsp = orsp;
	}

	qsort(sorted_list, (size_t)ofl->ofl_reloccnt, sizeof (Reloc_list),
	    (int (*)(const void *, const void *))reloc_compare);

	/*
	 * All output relocations have now been sorted, go through
	 * and process each relocation.
	 */
	for (index = 0; index < ofl->ofl_reloccnt; index++) {
		if ((*ld_targ.t_mr.mr_perform_outreloc)
		    (sorted_list[index].rl_rsp, ofl, &remain_seen) == S_ERROR)
			error = S_ERROR;
	}

	/* Guidance: Use -z text when building shared objects */
	if (remain_seen && OFL_GUIDANCE(ofl, FLG_OFG_NO_TEXT))
		ld_eprintf(ofl, ERR_GUIDANCE, MSG_INTL(MSG_GUIDE_TEXT));

	return (error);
}

/*
 * Process relocations.  Finds every input relocation section for each output
 * section and invokes reloc_section() to relocate that section.
 */
uintptr_t
ld_reloc_process(Ofl_desc *ofl)
{
	Sg_desc		*sgp;
	Os_desc		*osp;
	Word		ndx = 0;
	ofl_flag_t	flags = ofl->ofl_flags;
	Shdr		*shdr;

	DBG_CALL(Dbg_basic_relocate(ofl->ofl_lml));

	/*
	 * Determine the index of the symbol table that will be referenced by
	 * the relocation entries.
	 */
	if (OFL_ALLOW_DYNSYM(ofl))
		/* LINTED */
		ndx = (Word)elf_ndxscn(ofl->ofl_osdynsym->os_scn);
	else if (!(flags & FLG_OF_STRIP) || (flags & FLG_OF_RELOBJ))
		/* LINTED */
		ndx = (Word)elf_ndxscn(ofl->ofl_ossymtab->os_scn);

	/*
	 * Re-initialize counters. These are used to provide relocation
	 * offsets within the output buffers.
	 */
	ofl->ofl_relocpltsz = 0;
	ofl->ofl_relocgotsz = 0;
	ofl->ofl_relocbsssz = 0;

	/*
	 * Now that the output file is created and symbol update has occurred,
	 * process the relocations collected in process_reloc().
	 */
	if (do_sorted_outrelocs(ofl) == S_ERROR)
		return (S_ERROR);

	if ((*ld_targ.t_mr.mr_do_activerelocs)(ofl) == S_ERROR)
		return (S_ERROR);

	if ((flags & FLG_OF_COMREL) == 0) {
		Aliste	idx1;

		/*
		 * Process the relocation sections.  For each relocation
		 * section generated for the output image update its shdr
		 * information to reflect the symbol table it needs (sh_link)
		 * and the section to which the relocation must be applied
		 * (sh_info).
		 */
		for (APLIST_TRAVERSE(ofl->ofl_segs, idx1, sgp)) {
			Os_desc *osp;
			Aliste	idx2;

			for (APLIST_TRAVERSE(sgp->sg_osdescs, idx2, osp)) {
				if (osp->os_relosdesc == 0)
					continue;

				shdr = osp->os_relosdesc->os_shdr;
				shdr->sh_link = ndx;
				/* LINTED */
				shdr->sh_info = (Word)elf_ndxscn(osp->os_scn);
			}
		}

		/*
		 * Since the .rel[a] section is not tied to any specific
		 * section, we'd not have found it above.
		 */
		if ((osp = ofl->ofl_osrel) != NULL) {
			shdr = osp->os_shdr;
			shdr->sh_link = ndx;
			shdr->sh_info = 0;
		}
	} else {
		/*
		 * We only have two relocation sections here, (PLT's,
		 * coalesced) so just hit them directly instead of stepping
		 * over the output sections.
		 */
		if ((osp = ofl->ofl_osrelhead) != NULL) {
			shdr = osp->os_shdr;
			shdr->sh_link = ndx;
			shdr->sh_info = 0;
		}
		if (((osp = ofl->ofl_osplt) != NULL) && osp->os_relosdesc) {
			shdr = osp->os_relosdesc->os_shdr;
			shdr->sh_link = ndx;
			/* LINTED */
			shdr->sh_info = (Word)elf_ndxscn(osp->os_scn);
		}
	}

	/*
	 * If the -z text option was given, and we have output relocations
	 * against a non-writable, allocatable section, issue a diagnostic and
	 * return (the actual entries that caused this error would have been
	 * output during the relocating section phase).
	 */
	if ((flags & (FLG_OF_PURETXT | FLG_OF_TEXTREL)) ==
	    (FLG_OF_PURETXT | FLG_OF_TEXTREL)) {
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_REMAIN_3));
		return (S_ERROR);
	}

	/*
	 * Finally, initialize the first got entry with the address of the
	 * .dynamic section (_DYNAMIC).
	 */
	if (flags & FLG_OF_DYNAMIC) {
		if ((*ld_targ.t_mr.mr_fillin_gotplt)(ofl) == S_ERROR)
			return (S_ERROR);
	}

	/*
	 * Now that any GOT information has been written, display the debugging
	 * information if required.
	 */
	if ((osp = ofl->ofl_osgot) != NULL)
		DBG_CALL(Dbg_got_display(ofl, osp->os_shdr->sh_addr, 1,
		    ld_targ.t_m.m_got_xnumber, ld_targ.t_m.m_got_entsize));

	return (1);
}

/*
 * If the -z text option was given, and we have output relocations against a
 * non-writable, allocatable section, issue a diagnostic. Print offending
 * symbols in tabular form similar to the way undefined symbols are presented.
 * Called from reloc_count().  The actual fatal error condition is triggered on
 * in reloc_process() above.
 *
 * Note.  For historic reasons -ztext is not a default option (however all OS
 * shared object builds use this option).  It can be argued that this option
 * should also be default when generating an a.out (see 1163979).  However, if
 * an a.out contains text relocations it is either because the user is creating
 * something pretty weird (they've used the -b or -znodefs options), or because
 * the library against which they're building wasn't constructed correctly (ie.
 * a function has a NOTYPE type, in which case the a.out won't generate an
 * associated plt).  In the latter case the builder of the a.out can't do
 * anything to fix the error - thus we've chosen not to give the user an error,
 * or warning, for this case.
 */
void
ld_reloc_remain_entry(Rel_desc *orsp, Os_desc *osp, Ofl_desc *ofl,
    Boolean *remain_seen)
{

	/*
	 * -ztextoff
	 */
	if (ofl->ofl_flags1 & FLG_OF1_TEXTOFF)
		return;

	/*
	 * Only give relocation errors against loadable read-only segments.
	 */
	if ((orsp->rel_rtype == ld_targ.t_m.m_r_register) || (!osp) ||
	    (osp->os_sgdesc->sg_phdr.p_type != PT_LOAD) ||
	    (osp->os_sgdesc->sg_phdr.p_flags & PF_W))
		return;

	/*
	 * If we are in -ztextwarn mode, it's a silent error if a relocation is
	 * due to a 'WEAK REFERENCE'.  This is because if the symbol is not
	 * provided at run-time we will not perform a text-relocation.
	 */
	if (((ofl->ofl_flags & FLG_OF_PURETXT) == 0) &&
	    (ELF_ST_BIND(orsp->rel_sym->sd_sym->st_info) == STB_WEAK) &&
	    (orsp->rel_sym->sd_sym->st_shndx == SHN_UNDEF))
		return;

	if (*remain_seen == FALSE) {
		/*
		 * If building with '-ztext' then emit a fatal error.  If
		 * building a executable then only emit a 'warning'.
		 */
		const char *str1 = (ofl->ofl_flags & FLG_OF_PURETXT) ?
		    MSG_INTL(MSG_REL_RMN_ITM_11) : MSG_INTL(MSG_REL_RMN_ITM_13);

		ld_eprintf(ofl, ERR_NONE, MSG_INTL(MSG_REL_REMAIN_FMT_1), str1,
		    MSG_INTL(MSG_REL_RMN_ITM_31), MSG_INTL(MSG_REL_RMN_ITM_12),
		    MSG_INTL(MSG_REL_RMN_ITM_2), MSG_INTL(MSG_REL_RMN_ITM_32));

		*remain_seen = TRUE;
	}

	ld_eprintf(ofl, ERR_NONE, MSG_INTL(MSG_REL_REMAIN_2),
	    ld_reloc_sym_name(orsp), EC_OFF(orsp->rel_roffset),
	    orsp->rel_isdesc->is_file->ifl_name);
}

/*
 * Generic encapsulation for generating a TLS got index.
 */
uintptr_t
ld_assign_got_TLS(Boolean local, Rel_desc *rsp, Ofl_desc *ofl, Sym_desc *sdp,
    Gotndx *gnp, Gotref gref, Word rflag, Word ortype, Word rtype1, Word rtype2)
{
	Word	rflags;

	if ((*ld_targ.t_mr.mr_assign_got_ndx)(&(sdp->sd_GOTndxs), gnp,
	    gref, ofl, rsp, sdp) == S_ERROR)
		return (S_ERROR);

	rflags = FLG_REL_GOT | rflag;
	if (local)
		rflags |= FLG_REL_SCNNDX;
	rsp->rel_rtype = rtype1;

	if ((*ld_targ.t_mr.mr_add_outrel)(rflags, rsp, ofl) == S_ERROR)
		return (S_ERROR);

	if (local && (gref == GOT_REF_TLSIE)) {
		/*
		 * If this is a local LE TLS symbol, then the symbol won't be
		 * available at runtime.  The value of the local symbol will
		 * be placed in the associated got entry, and the got
		 * relocation is reassigned to a section symbol.
		 */
		if (ld_add_actrel(rflags, rsp, ofl) == S_ERROR)
			return (S_ERROR);
	}

	if (rtype2) {
		rflags = FLG_REL_GOT | rflag;
		rsp->rel_rtype = rtype2;

		if (local) {
			if (ld_add_actrel(rflags, rsp, ofl) == S_ERROR)
				return (S_ERROR);
		} else {
			if ((*ld_targ.t_mr.mr_add_outrel)(rflags, rsp, ofl) ==
			    S_ERROR)
				return (S_ERROR);
		}
	}

	rsp->rel_rtype = ortype;

	return (1);
}

/*
 * Move Section related function
 */
static void
newroffset_for_move(Sym_desc *sdp, Move *mvp, Xword offset1, Xword *offset2)
{
	Mv_desc		*mdp;
	Aliste		idx;

	/*
	 * Search for matching move entry.
	 */
	for (ALIST_TRAVERSE(sdp->sd_move, idx, mdp)) {
		if (mdp->md_move == mvp) {
			/*
			 * Update r_offset
			 */
			*offset2 = (Xword)((mdp->md_oidx - 1) * sizeof (Move) +
			    offset1 % sizeof (Move));
			return;
		}
	}
}

void
ld_adj_movereloc(Ofl_desc *ofl, Rel_desc *arsp)
{
	Move		*move = arsp->rel_aux->ra_move->mr_move;
	Sym_desc	*psdp = arsp->rel_aux->ra_move->mr_sym;
	Xword		newoffset;

	if (arsp->rel_flags & FLG_REL_MOVETAB) {
		/*
		 * We are relocating the move table itself.
		 */
		newroffset_for_move(psdp, move, arsp->rel_roffset,
		    &newoffset);
		DBG_CALL(Dbg_move_adjmovereloc(ofl->ofl_lml, arsp->rel_roffset,
		    newoffset, psdp->sd_name));
		arsp->rel_roffset = newoffset;
	} else {
		/*
		 * We are expanding the partial symbol.  So we are generating
		 * the relocation entry relocating the expanded partial symbol.
		 */
		arsp->rel_roffset += psdp->sd_sym->st_value -
		    ofl->ofl_isparexpn->is_osdesc->os_shdr->sh_addr;
		DBG_CALL(Dbg_move_adjexpandreloc(ofl->ofl_lml,
		    arsp->rel_roffset, psdp->sd_name));
	}
}

/*
 * Partially Initialized Symbol Handling routines
 * For RELA architecture, the second argument is reld->rel_raddend.  For REL
 * architecure, the second argument is the value stored at the relocation
 * target address.
 */
Sym_desc *
ld_am_I_partial(Rel_desc *reld, Xword val)
{
	Ifl_desc	*ifile = reld->rel_sym->sd_isc->is_file;
	int		nlocs = ifile->ifl_locscnt, i;

	for (i = 1; i < nlocs; i++) {
		Sym		*osym;
		Sym_desc	*symd = ifile->ifl_oldndx[i];

		if ((osym = symd->sd_osym) == 0)
			continue;
		if ((symd->sd_flags & FLG_SY_PAREXPN) == 0)
			continue;
		if ((osym->st_value <= val) &&
		    (osym->st_value + osym->st_size > val))
			return (symd);
	}
	return (NULL);
}

/*
 * Return True (1) if the code processing the given relocation
 * needs to perform byte swapping when accessing the section data.
 */
int
ld_swap_reloc_data(Ofl_desc *ofl, Rel_desc *rsp)
{
	/*
	 * In a cross-link situation where the linker host and target
	 * have opposite byte orders, it can be necessary to swap bytes
	 * when doing relocation processing. This is indicated by the
	 * presence of the FLG_OF1_ENCDIFF flag bit. However, swapping
	 * is only needed for the section types that libelf doesn't
	 * automatically xlate.
	 */
	if ((ofl->ofl_flags1 & FLG_OF1_ENCDIFF) != 0) {
		switch (RELAUX_GET_OSDESC(rsp)->os_shdr->sh_type) {
		case SHT_PROGBITS:
			return (1);

		case SHT_SPARC_GOTDATA:
			if (ld_targ.t_m.m_mach ==
			    LD_TARG_BYCLASS(EM_SPARC, EM_SPARCV9))
				return (1);
			break;

		case SHT_AMD64_UNWIND:
			if (ld_targ.t_m.m_mach == EM_AMD64)
				return (1);
			break;
		}
	}

	/*
	 * If FLG_OF1_ENCDIFF isn't set, or the section isn't
	 * progbits (or similar), then no swapping is needed.
	 */
	return (0);
}



/*
 * Obtain the current value at the given relocation target.
 *
 * entry:
 *	ofl - Output file descriptor
 *	rsp - Relocation record
 *	data - Pointer to relocation target
 *	value - Address of variable to recieve value
 *
 * exit:
 *	The value of the data at the relocation target has
 *	been stored in value.
 */
int
ld_reloc_targval_get(Ofl_desc *ofl, Rel_desc *rsp, uchar_t *data, Xword *value)
{
	const Rel_entry	*rep;

	rep = &ld_targ.t_mr.mr_reloc_table[rsp->rel_rtype];

	switch (rep->re_fsize) {
	case 1:
		/* LINTED */
		*value = (Xword) *((uchar_t *)data);
		break;
	case 2:
		{
			Half	v;
			uchar_t	*v_bytes = (uchar_t *)&v;

			if (OFL_SWAP_RELOC_DATA(ofl, rsp)) {
				UL_ASSIGN_BSWAP_HALF(v_bytes, data);
			} else {
				UL_ASSIGN_HALF(v_bytes, data);
			}
			*value = (Xword) v;
		}
		break;
	case 4:
		{
			Word	v;
			uchar_t	*v_bytes = (uchar_t *)&v;

			if (OFL_SWAP_RELOC_DATA(ofl, rsp)) {
				UL_ASSIGN_BSWAP_WORD(v_bytes, data);
			} else {
				UL_ASSIGN_WORD(v_bytes, data);
			}
			*value = (Xword) v;
		}
		break;
	default:
		{
			Conv_inv_buf_t inv_buf;
			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_UNSUPSZ),
			    conv_reloc_type(ld_targ.t_m.m_mach, rsp->rel_rtype,
			    0, &inv_buf), rsp->rel_isdesc->is_file->ifl_name,
			    ld_reloc_sym_name(rsp), (int)rep->re_fsize);
		}
		return (0);
	}
	return (1);
}


/*
 * Set the value at the given relocation target.
 *
 * entry:
 *	ofl - Output file descriptor
 *	rsp - Relocation record
 *	data - Pointer to relocation target
 *	value - Address of variable to recieve value
 *
 * exit:
 *	The value of the data at the relocation target has
 *	been stored in value.
 */
int
ld_reloc_targval_set(Ofl_desc *ofl, Rel_desc *rsp, uchar_t *data, Xword value)
{
	const Rel_entry	*rep;

	rep = &ld_targ.t_mr.mr_reloc_table[rsp->rel_rtype];

	switch (rep->re_fsize) {
	case 1:
		/* LINTED */
		*((uchar_t *)data) = (uchar_t)value;
		break;
	case 2:
		{
			Half	v = (Half)value;
			uchar_t	*v_bytes = (uchar_t *)&v;

			if (OFL_SWAP_RELOC_DATA(ofl, rsp)) {
				UL_ASSIGN_BSWAP_HALF(data, v_bytes);
			} else {
				UL_ASSIGN_HALF(data, v_bytes);
			}
		}
		break;
	case 4:
		{
			Word	v = (Word)value;
			uchar_t	*v_bytes = (uchar_t *)&v;

			if (OFL_SWAP_RELOC_DATA(ofl, rsp)) {
				UL_ASSIGN_BSWAP_WORD(data, v_bytes);
			} else {
				UL_ASSIGN_WORD(data, v_bytes);
			}
		}
		break;
	default:
		{
			Conv_inv_buf_t inv_buf;
			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_UNSUPSZ),
			    conv_reloc_type(ld_targ.t_m.m_mach, rsp->rel_rtype,
			    0, &inv_buf), rsp->rel_isdesc->is_file->ifl_name,
			    ld_reloc_sym_name(rsp), (int)rep->re_fsize);
		}
		return (0);
	}
	return (1);
}


/*
 * Because of the combinations of 32-bit lib providing 64-bit support, and
 * visa-versa, the use of krtld's dorelocs can result in differing message
 * requirements that make msg.c/msg.h creation and chkmsg "interesting".
 * Thus the actual message files contain a couple of entries to satisfy
 * each architectures build.  Here we add dummy calls to quieten chkmsg.
 *
 * chkmsg: MSG_INTL(MSG_REL_NOFIT)
 * chkmsg: MSG_INTL(MSG_REL_NONALIGN)
 */
