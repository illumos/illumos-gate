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
 */

/*
 * Library processing
 */
#include	<stdio.h>
#include	<string.h>
#include	<debug.h>
#include	"msg.h"
#include	"_libld.h"

/*
 * Archive members are typically extracted to resolve an existing undefined
 * reference.  However, other symbol definitions can cause archive members to
 * be processed to determine if the archive member provides a more appropriate
 * definition.  This routine processes the archive member to determine if the
 * member is really required.
 *
 *  i.	Tentative symbols may cause the extraction of an archive member.
 *	If the archive member has a strong defined symbol it will be used.
 *	If the archive member simply contains another tentative definition,
 *	or a defined function symbol, then it will not be used.
 *
 *  ii.	A symbol reference may define a hidden or protected visibility.  The
 *	reference can only be bound to a definition within a relocatable object
 *	for this restricted visibility to be satisfied.  If the archive member
 * 	provides a definition of the same symbol type, this definition is
 *	taken.  The visibility of the defined symbol is irrelevant, as the most
 *	restrictive visibility of the reference and the definition will be
 *	applied to the final symbol.
 */
static int
process_member(Ar_mem *amp, const char *name, Sym_desc *sdp, Ofl_desc *ofl)
{
	Sym	*syms, *osym = sdp->sd_sym;
	Xword	symn, cnt;
	char 	*strs;

	/*
	 * Find the first symbol table in the archive member, obtain its
	 * data buffer and determine the number of global symbols (Note,
	 * there must be a symbol table present otherwise the archive would
	 * never have been able to generate its own symbol entry for this
	 * member).
	 */
	if (amp->am_syms == 0) {
		Elf_Scn		*scn = NULL;
		Shdr		*shdr;
		Elf_Data	*data;

		while (scn = elf_nextscn(amp->am_elf, scn)) {
			if ((shdr = elf_getshdr(scn)) == NULL) {
				eprintf(ofl->ofl_lml, ERR_ELF,
				    MSG_INTL(MSG_ELF_GETSHDR), amp->am_path);
				ofl->ofl_flags |= FLG_OF_FATAL;
				return (0);
			}
			if ((shdr->sh_type == SHT_SYMTAB) ||
			    (shdr->sh_type == SHT_DYNSYM))
				break;
		}
		if ((data = elf_getdata(scn, NULL)) == NULL) {
			eprintf(ofl->ofl_lml, ERR_ELF,
			    MSG_INTL(MSG_ELF_GETDATA), amp->am_path);
			ofl->ofl_flags |= FLG_OF_FATAL;
			return (0);
		}
		syms = (Sym *)data->d_buf;
		syms += shdr->sh_info;
		symn = shdr->sh_size / shdr->sh_entsize;
		symn -= shdr->sh_info;

		/*
		 * Get the data for the associated string table.
		 */
		if ((scn = elf_getscn(amp->am_elf, (size_t)shdr->sh_link)) ==
		    NULL) {
			eprintf(ofl->ofl_lml, ERR_ELF,
			    MSG_INTL(MSG_ELF_GETSCN), amp->am_path);
			ofl->ofl_flags |= FLG_OF_FATAL;
			return (0);
		}
		if ((data = elf_getdata(scn, NULL)) == NULL) {
			eprintf(ofl->ofl_lml, ERR_ELF,
			    MSG_INTL(MSG_ELF_GETDATA), amp->am_path);
			ofl->ofl_flags |= FLG_OF_FATAL;
			return (0);
		}
		strs = data->d_buf;

		/*
		 * Initialize the archive member structure in case we have to
		 * come through here again.
		 */
		amp->am_syms = syms;
		amp->am_strs = strs;
		amp->am_symn = symn;
	} else {
		syms = amp->am_syms;
		strs = amp->am_strs;
		symn = amp->am_symn;
	}

	/*
	 * Loop through the symbol table entries looking for a match for the
	 * original symbol.
	 */
	for (cnt = 0; cnt < symn; syms++, cnt++) {
		Word	shndx;

		if ((shndx = syms->st_shndx) == SHN_UNDEF)
			continue;

		if (osym->st_shndx == SHN_COMMON) {
			/*
			 * Determine whether a tentative symbol definition
			 * should be overridden.
			 */
			if ((shndx == SHN_ABS) || (shndx == SHN_COMMON) ||
			    (ELF_ST_TYPE(syms->st_info) == STT_FUNC))
				continue;

			/*
			 * A historic detail requires that a weak definition
			 * within an archive will not override a strong
			 * definition (see sym_realtent() resolution and ABI
			 * symbol binding description - page 4-27).
			 */
			if ((ELF_ST_BIND(syms->st_info) == STB_WEAK) &&
			    (ELF_ST_BIND(osym->st_info) != STB_WEAK))
				continue;
		} else {
			/*
			 * Determine whether a restricted visibility reference
			 * should be overridden.  Don't worry about the
			 * visibility of the archive member definition, nor
			 * whether it is weak or global.  Any definition is
			 * better than a binding to an external shared object
			 * (which is the only event that must presently exist
			 * for us to be here looking for a better alternative).
			 */
			if (ELF_ST_TYPE(syms->st_info) !=
			    ELF_ST_TYPE(osym->st_info))
				continue;
		}

		if (strcmp(strs + syms->st_name, name) == NULL)
			return (1);
	}
	return (0);
}

/*
 * Create an archive descriptor.  By maintaining a list of archives any
 * duplicate occurrences of the same archive specified by the user enable us to
 * pick off where the last processing finished.
 */
Ar_desc *
ld_ar_setup(const char *name, Elf *elf, Ofl_desc *ofl)
{
	Ar_desc *	adp;
	size_t		number;
	Elf_Arsym *	start;

	/*
	 * Get the archive symbol table. If this fails, we will
	 * ignore this file with a warning message.
	 */
	if ((start = elf_getarsym(elf, &number)) == 0) {
		if (elf_errno()) {
			eprintf(ofl->ofl_lml, ERR_ELF,
			    MSG_INTL(MSG_ELF_GETARSYM), name);
			ofl->ofl_flags |= FLG_OF_FATAL;
		} else
			eprintf(ofl->ofl_lml, ERR_WARNING,
			    MSG_INTL(MSG_ELF_ARSYM), name);

		return (0);
	}

	/*
	 * As this is a new archive reference establish a new descriptor.
	 */
	if ((adp = libld_malloc(sizeof (Ar_desc))) == 0)
		return ((Ar_desc *)S_ERROR);
	adp->ad_name = name;
	adp->ad_elf = elf;
	adp->ad_start = start;
	if ((adp->ad_aux = libld_calloc(sizeof (Ar_aux), number)) == 0)
		return ((Ar_desc *)S_ERROR);

	/*
	 * Retain any command line options that are applicable to archive
	 * extraction in case we have to rescan this archive later.
	 */
	adp->ad_flags = ofl->ofl_flags1 & MSK_OF1_ARCHIVE;

	ofl->ofl_arscnt++;

	/*
	 * Add this new descriptor to the list of archives.
	 */
	if (list_appendc(&ofl->ofl_ars, adp) == 0)
		return ((Ar_desc *)S_ERROR);
	else
		return (adp);
}

/*
 * For each archive descriptor, maintain an `Ar_aux' table to parallel the
 * archive symbol table (returned from elf_getarsym(3e)).  Use this table to
 * hold a `Sym_desc' for each symbol (thus reducing the number of
 * ld_sym_find()'s), and to hold the `Ar_mem' pointer.  The `Ar_mem' element
 * can have one of three values indicating the state of the archive member
 * associated with the offset for this symbol table entry:
 *
 *  0		indicates that the member has not been processed.
 *
 *  FLG_ARMEM_PROC
 *		indicates that the member has been processed.
 *
 *  addr	indicates that the member has been investigated to determine if
 *		it contained a symbol definition we need, but was found not to
 *		be a candidate for extraction.  In this case the members
 *		structure is maintained for possible later use.
 *
 * Each time we process an archive member we use its offset value to scan this
 * `Ar_aux' list.  If the member has been extracted, each entry with the same
 * offset has its `Ar_mem' pointer set to FLG_ARMEM_PROC.  Thus if we cycle back
 * through the archive symbol table we will ignore these symbols as they will
 * have already been added to the output image.  If a member has been processed
 * but found not to contain a symbol we need, each entry with the same offset
 * has its `Ar_mem' pointer set to the member structures address.
 */
void
ld_ar_member(Ar_desc * adp, Elf_Arsym * arsym, Ar_aux * aup, Ar_mem * amp)
{
	Elf_Arsym *	_arsym = arsym;
	Ar_aux *	_aup = aup;
	size_t		_off = arsym->as_off;

	if (_arsym != adp->ad_start) {
		do {
			_arsym--;
			_aup--;
			if (_arsym->as_off != _off)
				break;
			_aup->au_mem = amp;
		} while (_arsym != adp->ad_start);
	}

	_arsym = arsym;
	_aup = aup;

	do {
		if (_arsym->as_off != _off)
			break;
		_aup->au_mem = amp;
		_arsym++;
		_aup++;
	} while (_arsym->as_name);
}

/*
 * Data structure to indicate whether a symbol is visible for the purpose
 * of archive extraction.
 */
static const Boolean
sym_vis[STV_NUM] = {
	TRUE,		/* STV_DEFAULT */
	FALSE,		/* STV_INTERNAL */
	FALSE,		/* STV_HIDDEN */
	FALSE,		/* STV_PROTECTED */
	TRUE,		/* STV_EXPORTED */
	TRUE,		/* STV_SINGLETON */
	FALSE		/* STV_ELIMINATE */
};
#if STV_NUM != (STV_ELIMINATE + 1)
#error "STV_NUM has grown. Update sym_vis[]."
#endif

/*
 * Read the archive symbol table.  For each symbol in the table, determine
 * whether that symbol satisfies an unresolved reference, tentative reference,
 * or a reference that expects hidden or protected visibility.  If so, the
 * corresponding object from the archive is processed.  The archive symbol
 * table is searched until we go through a complete pass without satisfying any
 * unresolved symbols
 */
uintptr_t
ld_process_archive(const char *name, int fd, Ar_desc *adp, Ofl_desc *ofl)
{
	Elf_Arsym *	arsym;
	Elf_Arhdr *	arhdr;
	Elf *		arelf;
	Ar_aux *	aup;
	Sym_desc *	sdp;
	char 		*arname, *arpath;
	Xword		ndx;
	int		found, again;
	int		allexrt = (ofl->ofl_flags1 & FLG_OF1_ALLEXRT) != 0;
	uintptr_t	err;
	Rej_desc	rej = { 0 };

	/*
	 * If a fatal error condition has been set there's really no point in
	 * processing the archive further.  Having got to this point we have at
	 * least established that the archive exists (thus verifying that the
	 * command line options that got us to this archive are correct).  Very
	 * large archives can take a significant time to process, therefore
	 * continuing on from here may significantly delay the fatal error
	 * message the user is already set to receive.
	 */
	if (ofl->ofl_flags & FLG_OF_FATAL)
		return (1);

	/*
	 * If this archive was processed with -z allextract, then all members
	 * have already been extracted.
	 */
	if (adp->ad_elf == NULL)
		return (1);

	/*
	 * Loop through archive symbol table until we make a complete pass
	 * without satisfying an unresolved reference.  For each archive
	 * symbol, see if there is a symbol with the same name in ld's
	 * symbol table.  If so, and if that symbol is still unresolved or
	 * tentative, process the corresponding archive member.
	 */
	found = again = 0;
	do {
		DBG_CALL(Dbg_file_ar(ofl->ofl_lml, name, again));
		DBG_CALL(Dbg_syms_ar_title(ofl->ofl_lml, name, again));

		ndx = again = 0;
		for (arsym = adp->ad_start, aup = adp->ad_aux; arsym->as_name;
		    ++arsym, ++aup, ndx++) {
			Rej_desc	_rej = { 0 };
			Ar_mem		*amp;
			Sym		*sym;
			Boolean		visible = TRUE;

			/*
			 * If the auxiliary members value indicates that this
			 * member has been processed then this symbol will have
			 * been added to the output file image already or the
			 * object was rejected in which case we don't want to
			 * process it again.
			 */
			if (aup->au_mem == FLG_ARMEM_PROC)
				continue;

			/*
			 * If the auxiliary symbol element is non-zero lookup
			 * the symbol from the internal symbol table.
			 * (But you skip this if allextract is specified.)
			 */
			if ((allexrt == 0) && ((sdp = aup->au_syms) == 0)) {
				if ((sdp = ld_sym_find(arsym->as_name,
				    /* LINTED */
				    (Word)arsym->as_hash, 0, ofl)) == 0) {
					DBG_CALL(Dbg_syms_ar_entry(ofl->ofl_lml,
					    ndx, arsym));
					continue;
				}
				aup->au_syms = sdp;
			}

			/*
			 * With '-z allextract', all members will be extracted.
			 *
			 * This archive member is a candidate for extraction if
			 * the internal symbol originates from an explicit file,
			 * and represents an undefined or tentative symbol.
			 *
			 * By default, weak references do not cause archive
			 * extraction, however the -zweakextract flag overrides
			 * this default.
			 *
			 * If this symbol has already been bound to a versioned
			 * shared object, but the shared objects version is not
			 * available, then a definition of this symbol from
			 * within the archive is a better candidate.  Similarly,
			 * if this symbol has been bound to a shared object, but
			 * the original reference expected hidden or protected
			 * visibility, then a definition of this symbol from
			 * within the archive is a better candidate.
			 */
			if (allexrt == 0) {
				Boolean		vers = TRUE;
				Ifl_desc	*ifl = sdp->sd_file;

				sym = sdp->sd_sym;

				if (sdp->sd_ref == REF_DYN_NEED) {
					uchar_t	vis;

					if (ifl->ifl_vercnt) {
						Word		vndx;
						Ver_index	*vip;

						vndx = sdp->sd_aux->sa_dverndx;
						vip = &ifl->ifl_verndx[vndx];
						if ((vip->vi_flags &
						    FLG_VER_AVAIL) == 0)
							vers = FALSE;
					}

					vis = ELF_ST_VISIBILITY(sym->st_other);
					visible = sym_vis[vis];
				}

				if (((ifl->ifl_flags & FLG_IF_NEEDED) == 0) ||
				    (visible && vers &&
				    (sym->st_shndx != SHN_UNDEF) &&
				    (sym->st_shndx != SHN_COMMON)) ||
				    ((ELF_ST_BIND(sym->st_info) == STB_WEAK) &&
				    (!(ofl->ofl_flags1 & FLG_OF1_WEAKEXT)))) {
					DBG_CALL(Dbg_syms_ar_entry(ofl->ofl_lml,
					    ndx, arsym));
					continue;
				}
			}

			/*
			 * Determine if we have already extracted this member,
			 * and if so reuse the Ar_mem information.
			 */
			if ((amp = aup->au_mem) != 0) {
				arelf = amp->am_elf;
				arname = amp->am_name;
				arpath = amp->am_path;
			} else {
				size_t	len;

				/*
				 * Set up a new elf descriptor for this member.
				 */
				if (elf_rand(adp->ad_elf, arsym->as_off) !=
				    arsym->as_off) {
					eprintf(ofl->ofl_lml, ERR_ELF,
					    MSG_INTL(MSG_ELF_ARMEM), name,
					    EC_WORD(arsym->as_off), ndx,
					    demangle(arsym->as_name));
					ofl->ofl_flags |= FLG_OF_FATAL;
					return (0);
				}

				if ((arelf = elf_begin(fd, ELF_C_READ,
				    adp->ad_elf)) == NULL) {
					eprintf(ofl->ofl_lml, ERR_ELF,
					    MSG_INTL(MSG_ELF_BEGIN), name);
					ofl->ofl_flags |= FLG_OF_FATAL;
					return (0);
				}

				/*
				 * Construct the member filename.
				 */
				if ((arhdr = elf_getarhdr(arelf)) == NULL) {
					eprintf(ofl->ofl_lml, ERR_ELF,
					    MSG_INTL(MSG_ELF_GETARHDR), name);
					ofl->ofl_flags |= FLG_OF_FATAL;
					return (0);
				}
				arname = arhdr->ar_name;

				/*
				 * Construct the members full pathname, using
				 * the format "%s(%s)".
				 */
				len = strlen(name) + strlen(arname) + 3;
				if ((arpath = libld_malloc(len)) == 0)
					return (S_ERROR);
				(void) snprintf(arpath, len,
				    MSG_ORIG(MSG_FMT_ARMEM), name, arname);

				/*
				 * Determine whether the support library wishes
				 * to process this open.  See comments in
				 * ld_process_open().
				 */
				ld_sup_open(ofl, (const char **)&arpath,
				    (const char **)&arname, &fd,
				    (FLG_IF_EXTRACT | FLG_IF_NEEDED),
				    &arelf, adp->ad_elf, arsym->as_off,
				    elf_kind(arelf));

				/*
				 * An ELF descriptor of zero indicates that
				 * the archive member should be ignored.
				 */
				if (arelf == NULL) {
					aup->au_mem = FLG_ARMEM_PROC;
					continue;
				}
			}

			/*
			 * The symbol for which this archive member is being
			 * processed may provide a better alternative to the
			 * symbol that is presently known.  Two cases are
			 * covered:
			 *
			 *  i.	The present symbol represents tentative data.
			 *	The archive member may provide a data
			 *	definition symbol.
			 *  ii.	The present symbol represents a reference that
			 *	has seen a definition within a shared object
			 *	dependency, but the reference expects to be
			 *	reduced to hidden or protected visibility.
			 */
			if ((allexrt == 0) &&
			    ((sym->st_shndx == SHN_COMMON) ||
			    (visible == FALSE))) {
				/*
				 * If we don't already have a member structure
				 * allocate one.
				 */
				if (!amp) {
					if ((amp = libld_calloc(sizeof (Ar_mem),
					    1)) == 0)
						return (S_ERROR);
					amp->am_elf = arelf;
					amp->am_name = arname;
					amp->am_path = arpath;
				}
				DBG_CALL(Dbg_syms_ar_checking(ofl->ofl_lml,
				    ndx, arsym, arname));
				if ((err = process_member(amp, arsym->as_name,
				    sdp, ofl)) == S_ERROR)
					return (S_ERROR);

				/*
				 * If it turns out that we don't need this
				 * member simply initialize all other auxiliary
				 * entries that match this offset with this
				 * members address.  In this way we can resuse
				 * this information if we recurse back to this
				 * symbol.
				 */
				if (err == 0) {
					if (aup->au_mem == 0)
						ld_ar_member(adp, arsym,
						    aup, amp);
					continue;
				}
			}

			/*
			 * Process the archive member.  Retain any error for
			 * return to the caller.
			 */
			DBG_CALL(Dbg_syms_ar_resolve(ofl->ofl_lml, ndx, arsym,
			    arname, allexrt));
			if ((err = (uintptr_t)ld_process_ifl(arpath, NULL, fd,
			    arelf, (FLG_IF_EXTRACT | FLG_IF_NEEDED), ofl,
			    &_rej)) == S_ERROR)
				return (S_ERROR);

			/*
			 * If this member is rejected maintain the first
			 * rejection error for possible later display.  Keep the
			 * member as extracted so that we don't try and process
			 * it again on a rescan.
			 */
			if (_rej.rej_type) {
				if (rej.rej_type == 0) {
					rej.rej_type = _rej.rej_type;
					rej.rej_info = _rej.rej_info;
					rej.rej_name = (const char *)arpath;
				}
				ld_ar_member(adp, arsym, aup, FLG_ARMEM_PROC);
				continue;
			}

			/*
			 * Indicate that the extracted member is in use.  This
			 * enables debugging diags, and indicates that a further
			 * rescan of all archives may be necessary.
			 */
			found = 1;
			ofl->ofl_flags1 |= FLG_OF1_EXTRACT;
			adp->ad_flags |= FLG_ARD_EXTRACT;

			/*
			 * If not under '-z allextract' signal the need to
			 * rescan this archive.
			 */
			if (allexrt == 0)
				again = 1;

			ld_ar_member(adp, arsym, aup, FLG_ARMEM_PROC);
			DBG_CALL(Dbg_util_nl(ofl->ofl_lml, DBG_NL_STD));
		}
	} while (again);

	/*
	 * If no objects have been found in the archive test for any rejections
	 * and if one had occurred issue a warning - its possible a user has
	 * pointed at an archive containing the wrong class of elf members.
	 */
	if ((found == 0) && rej.rej_type) {
		Conv_reject_desc_buf_t rej_buf;

		eprintf(ofl->ofl_lml, ERR_WARNING,
		    MSG_INTL(reject[rej.rej_type]),
		    rej.rej_name ? rej.rej_name : MSG_INTL(MSG_STR_UNKNOWN),
		    conv_reject_desc(&rej, &rej_buf, ld_targ.t_m.m_mach));
	}

	/*
	 * If this archive was extracted by -z allextract, the ar_aux table
	 * and elf descriptor can be freed.  Set ad_elf to NULL to mark the
	 * archive is completely processed.
	 */
	if (allexrt) {
		(void) elf_end(adp->ad_elf);
		adp->ad_elf = NULL;
	}

	return (1);
}
