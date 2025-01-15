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
 * Library processing
 */
#include	<stdio.h>
#include	<string.h>
#include	<errno.h>
#include	<ar.h>
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
 *  ii.	A symbol reference may define a hidden or protected visibility.	 The
 *	reference can only be bound to a definition within a relocatable object
 *	for this restricted visibility to be satisfied.	 If the archive member
 *	provides a definition of the same symbol type, this definition is
 *	taken.	The visibility of the defined symbol is irrelevant, as the most
 *	restrictive visibility of the reference and the definition will be
 *	applied to the final symbol.
 *
 * exit:
 *	Returns 1 if there is a match, 0 if no match is seen, and S_ERROR if an
 *	error occurred.
 */
static uintptr_t
process_member(Ar_mem *amp, const char *name, Sym_desc *sdp, Ofl_desc *ofl)
{
	Sym	*syms, *osym = sdp->sd_sym;
	Xword	symn, cnt;
	char	*strs;

	/*
	 * Find the first symbol table in the archive member, obtain its
	 * data buffer and determine the number of global symbols (Note,
	 * there must be a symbol table present otherwise the archive would
	 * never have been able to generate its own symbol entry for this
	 * member).
	 */
	if (amp->am_syms == NULL) {
		Elf_Scn		*scn = NULL;
		Shdr		*shdr;
		Elf_Data	*data;

		while (scn = elf_nextscn(amp->am_elf, scn)) {
			if ((shdr = elf_getshdr(scn)) == NULL) {
				ld_eprintf(ofl, ERR_ELF,
				    MSG_INTL(MSG_ELF_GETSHDR), amp->am_path);
				return (S_ERROR);
			}
			if ((shdr->sh_type == SHT_SYMTAB) ||
			    (shdr->sh_type == SHT_DYNSYM))
				break;
		}
		if ((data = elf_getdata(scn, NULL)) == NULL) {
			ld_eprintf(ofl, ERR_ELF, MSG_INTL(MSG_ELF_GETDATA),
			    amp->am_path);
			return (S_ERROR);
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
			ld_eprintf(ofl, ERR_ELF, MSG_INTL(MSG_ELF_GETSCN),
			    amp->am_path);
			return (S_ERROR);
		}
		if ((data = elf_getdata(scn, NULL)) == NULL) {
			ld_eprintf(ofl, ERR_ELF, MSG_INTL(MSG_ELF_GETDATA),
			    amp->am_path);
			return (S_ERROR);
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

		if (strcmp(strs + syms->st_name, name) == 0)
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
	 * Unless, -z allextract is specified, get the archive symbol table
	 * if one exists, and ignore the file with a warning message otherwise.
	 */
	if (ofl->ofl_flags1 & FLG_OF1_ALLEXRT) {
		start = NULL;
	} else  if ((start = elf_getarsym(elf, &number)) == NULL) {
		if (elf_errno())
			ld_eprintf(ofl, ERR_ELF, MSG_INTL(MSG_ELF_GETARSYM),
			    name);
		else
			ld_eprintf(ofl, ERR_WARNING, MSG_INTL(MSG_ELF_ARSYM),
			    name);
		return (0);
	}

	/*
	 * As this is a new archive reference establish a new descriptor.
	 */
	if ((adp = libld_malloc(sizeof (Ar_desc))) == NULL)
		return ((Ar_desc *)S_ERROR);
	adp->ad_name = name;
	adp->ad_elf = elf;
	adp->ad_start = start;
	adp->ad_allextract = FALSE;
	if (start) {
		adp->ad_aux = libld_calloc(number, sizeof (Ar_aux));
		if (adp->ad_aux == NULL)
			return ((Ar_desc *)S_ERROR);
	} else {
		adp->ad_aux = NULL;
	}

	/*
	 * Retain any command line options that are applicable to archive
	 * extraction in case we have to rescan this archive later.
	 */
	adp->ad_flags = ofl->ofl_flags1 & MSK_OF1_ARCHIVE;

	ofl->ofl_arscnt++;

	/*
	 * Add this new descriptor to the list of archives.
	 */
	if (aplist_append(&ofl->ofl_ars, adp, AL_CNT_OFL_LIBS) == NULL)
		return ((Ar_desc *)S_ERROR);
	else
		return (adp);
}

/*
 * For each archive descriptor, maintain an `Ar_aux' table to parallel the
 * archive symbol table (returned from elf_getarsym(3elf)).  Use this table to
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

	if (adp->ad_start == NULL)
		return;

	/*
	 * Note: This algorithm assumes that the archive symbol table is
	 * built from the member objects, in the same order as those
	 * members are found in the archive. As such, the symbols for a
	 * given member will all cluster together. If this is not true,
	 * we will fail to mark some symbols. In that case, archive
	 * processing may be less efficient than it would be otherwise.
	 */

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
 * Return the archive member's name.
 *
 * entry:
 *	name - Name of archive
 *	arelf - ELF descriptor for archive member.
 *	ofl - output descriptor
 *
 * exit:
 *	Returns pointer to archive member name on success, NULL on error.
 */
static const char *
ar_member_name(const char *name, Elf *arelf, Ofl_desc *ofl)
{
	Elf_Arhdr	*arhdr;

	if ((arhdr = elf_getarhdr(arelf)) == NULL) {
		ld_eprintf(ofl, ERR_ELF, MSG_INTL(MSG_ELF_GETARHDR), name);
		return (NULL);
	}
	return (arhdr->ar_name);
}

/*
 * Construct the member's full pathname, using the format "%s(%s)".
 *
 * entry:
 *	name - Name of archive
 *	arname - Name of archive member
 *	ofl - output descriptor
 * exit:
 *	Returns pointer to constructed pathname on success, NULL on error.
 */
static const char *
ar_member_path(const char *name, const char *arname, Ofl_desc *ofl)
{
	size_t		len;
	char		*path;

	len = strlen(name) + strlen(arname) + 3;
	if ((path = libld_malloc(len)) == NULL) {
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_SYS_MALLOC),
		    strerror(errno));
		return (NULL);
	}
	(void) snprintf(path, len, MSG_ORIG(MSG_FMT_ARMEM), name, arname);
	return (path);
}

/*
 * Input the specified archive member to the link.
 *
 * entry:
 *	fd - Open file descriptor for archive
 *	adp - Archive descriptor
 *	ofl - output descriptor
 *	arelf - ELF descriptor for archive member.
 *	arpath - Address of pointer to be set to constructed path name
 *		for object.
 *	rej - Rejection descriptor to pass to ld_process_ifl().
 *
 * exit:
 *	This routine can return one of the following:
 *	S_ERROR:  Fatal error encountered.
 *	0: Object was rejected, and should be ignored.
 *		rej will carry the rejection information.
 *	1: The archive member has been input to the link.
 */
static uintptr_t
ar_input(int fd, Ar_desc *adp, Ofl_desc *ofl, Elf *arelf,
    const char *arpath, Rej_desc *rej)
{
	Rej_desc	_rej = { 0 };

	switch (ld_process_ifl(arpath, NULL, fd, arelf,
	    (FLG_IF_EXTRACT | FLG_IF_NEEDED), ofl, &_rej, NULL)) {
	case S_ERROR:
		return (S_ERROR);
	case 0:
		/*
		 * If this member is rejected maintain the first rejection
		 * error for possible later display.
		 */
		if (_rej.rej_type) {
			if (rej->rej_type == 0) {
				rej->rej_type = _rej.rej_type;
				rej->rej_info = _rej.rej_info;
				rej->rej_name = arpath;
			}
			(void) elf_end(arelf);
			return (0);
		}
	}

	/*
	 * Indicate that the extracted member is in use.  This
	 * enables debugging diags, and indicates that a further
	 * rescan of all archives may be necessary.
	 */
	ofl->ofl_flags1 |= FLG_OF1_EXTRACT;
	adp->ad_flags |= FLG_ARD_EXTRACT;
	return (1);
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
 *
 * entry:
 *	name - Name of archive
 *	fd - Open file descriptor for archive
 *	adp - Archive descriptor
 *	ofl - output descriptor
 *	found - Address of variable to set to TRUE if any objects are extracted
 *	rej - Rejection descriptor to pass to ld_process_ifl().
 *
 * exit:
 *	Returns FALSE on fatal error. On success, *found will be TRUE
 *	if any object was extracted, rej will be set if any object
 *	was rejected, and TRUE is returned.
 */
static Boolean
ar_extract_bysym(const char *name, int fd, Ar_desc *adp,
    Ofl_desc *ofl, Boolean *found, Rej_desc *rej)
{
	Elf_Arsym *	arsym;
	Elf *		arelf;
	Ar_aux *	aup;
	Sym_desc *	sdp;
	const char	*arname, *arpath;
	Boolean		again = FALSE;
	uintptr_t	err;

	/*
	 * An archive without a symbol table should not reach this function,
	 * because it can only get past ld_ar_setup() in the case where
	 * the archive is first seen under the influence of '-z allextract'.
	 * That will cause the entire archive to be extracted, and any
	 * subsequent reference to the archive will be ignored by
	 * ld_process_archive().
	 */
	if (adp->ad_start == NULL) {
		assert(adp->ad_start != NULL);
		return (TRUE);
	}

	/*
	 * Loop through archive symbol table until we make a complete pass
	 * without satisfying an unresolved reference.  For each archive
	 * symbol, see if there is a symbol with the same name in ld's
	 * symbol table.  If so, and if that symbol is still unresolved or
	 * tentative, process the corresponding archive member.
	 */
	do {
		DBG_CALL(Dbg_file_ar(ofl->ofl_lml, name, again));
		DBG_CALL(Dbg_syms_ar_title(ofl->ofl_lml, name, again));
		again = FALSE;

		for (arsym = adp->ad_start, aup = adp->ad_aux; arsym->as_name;
		    ++arsym, ++aup) {
			Ar_mem		*amp;
			Sym		*sym;
			Boolean		visible = TRUE;
			Boolean		vers;
			Ifl_desc	*ifl;

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
			 */
			if ((sdp = aup->au_syms) == NULL) {
				if ((sdp = ld_sym_find(arsym->as_name,
				    /* LINTED */
				    (Word)arsym->as_hash, NULL, ofl)) == NULL) {
					DBG_CALL(Dbg_syms_ar_skip(ofl->ofl_lml,
					    name, arsym));
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
			vers = TRUE;
			ifl = sdp->sd_file;

			sym = sdp->sd_sym;

			if (sdp->sd_ref == REF_DYN_NEED) {
				uchar_t	vis;

				if (ifl->ifl_vercnt) {
					Word		vndx;
					Ver_index	*vip;

					vndx = sdp->sd_aux->sa_dverndx;
					vip = &ifl->ifl_verndx[vndx];
					if (!(vip->vi_flags & FLG_VER_AVAIL))
						vers = FALSE;
				}

				vis = ELF_ST_VISIBILITY(sym->st_other);
				visible = sym_vis[vis];
			}

			if (((ifl->ifl_flags & FLG_IF_NEEDED) == 0) ||
			    (visible && vers && (sym->st_shndx != SHN_UNDEF) &&
			    (sym->st_shndx != SHN_COMMON)) ||
			    ((ELF_ST_BIND(sym->st_info) == STB_WEAK) &&
			    (!(ofl->ofl_flags1 & FLG_OF1_WEAKEXT)))) {
				DBG_CALL(Dbg_syms_ar_skip(ofl->ofl_lml,
				    name, arsym));
				continue;
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
				/*
				 * Set up a new elf descriptor for this member.
				 */
				if (elf_rand(adp->ad_elf, arsym->as_off) !=
				    arsym->as_off) {
					ld_eprintf(ofl, ERR_ELF,
					    MSG_INTL(MSG_ELF_ARMEM), name,
					    EC_WORD(arsym->as_off),
					    demangle(arsym->as_name));
					return (FALSE);
				}

				if ((arelf = elf_begin(fd, ELF_C_READ,
				    adp->ad_elf)) == NULL) {
					ld_eprintf(ofl, ERR_ELF,
					    MSG_INTL(MSG_ELF_BEGIN), name);
					return (FALSE);
				}

				/* Get member filename */
				if ((arname = ar_member_name(name, arelf,
				    ofl)) == NULL)
					return (FALSE);

				/* Construct the member's full pathname */
				if ((arpath = ar_member_path(name, arname,
				    ofl)) == NULL)
					return (FALSE);

				/*
				 * Determine whether the support libraries wish
				 * to process this open. See comments in
				 * ld_process_open().
				 */
				ld_sup_open(ofl, &arpath, &arname, &fd,
				    (FLG_IF_EXTRACT | FLG_IF_NEEDED),
				    &arelf, adp->ad_elf, arsym->as_off,
				    elf_kind(arelf));
				if (arelf == NULL) {
					/* Ignore this archive member */
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
			if ((sym->st_shndx == SHN_COMMON) ||
			    (visible == FALSE)) {
				/*
				 * If we don't already have a member structure
				 * allocate one.
				 */
				if (!amp) {
					if ((amp = libld_calloc(1,
					    sizeof (Ar_mem))) == NULL)
						return (FALSE);
					amp->am_elf = arelf;
					amp->am_name = arname;
					amp->am_path = arpath;
				}
				DBG_CALL(Dbg_syms_ar_checking(ofl->ofl_lml,
				    name, arname, arsym));
				if ((err = process_member(amp, arsym->as_name,
				    sdp, ofl)) == S_ERROR)
					return (FALSE);

				/*
				 * If it turns out that we don't need this
				 * member simply initialize all other auxiliary
				 * entries that match this offset with this
				 * members address.  In this way we can resuse
				 * this information if we recurse back to this
				 * symbol.
				 */
				if (err == 0) {
					if (aup->au_mem == NULL)
						ld_ar_member(adp, arsym,
						    aup, amp);
					continue;
				}
			}

			/*
			 * Process the archive member.  Retain any error for
			 * return to the caller.
			 */
			DBG_CALL(Dbg_syms_ar_resolve(ofl->ofl_lml,
			    name, arname, arsym));
			switch (ar_input(fd, adp, ofl, arelf, arpath,
			    rej)) {
			case S_ERROR:
				return (FALSE);
			case 0:
				/*
				 * Mark the member as extracted so that we
				 * don't try and process it again on a rescan.
				 */
				ld_ar_member(adp, arsym, aup, FLG_ARMEM_PROC);
				continue;
			}

			/*
			 * Note that this archive has contributed something
			 * during this specific operation, and also signal
			 * the need to rescan the archive.
			 */
			*found = again = TRUE;

			ld_ar_member(adp, arsym, aup, FLG_ARMEM_PROC);
		}
	} while (again);

	return (TRUE);
}


/*
 * Extract every object in the given archive directly without going through
 * the symbol table.
 *
 * entry:
 *	name - Name of archive
 *	fd - Open file descriptor for archive
 *	adp - Archive descriptor
 *	ofl - output descriptor
 *	found - Address of variable to set to TRUE if any objects are extracted
 *	rej - Rejection descriptor to pass to ld_process_ifl().
 *
 * exit:
 *	Returns FALSE on fatal error. On success, *found will be TRUE
 *	if any object was extracted, rej will be set if any object
 *	was rejected, and TRUE is returned.
 */
static Boolean
ar_extract_all(const char *name, int fd, Ar_desc *adp, Ofl_desc *ofl,
    Boolean *found, Rej_desc *rej)
{
	Elf_Cmd		cmd = ELF_C_READ;
	Elf		*arelf;
	const char	*arname, *arpath;
	size_t		off, next_off;

	DBG_CALL(Dbg_file_ar(ofl->ofl_lml, name, FALSE));

	while ((arelf = elf_begin(fd, cmd, adp->ad_elf)) != NULL) {
		/*
		 * Call elf_next() so that the next call to elf_begin() will
		 * fetch the archive member following this one. We do this now
		 * because it simplifies the logic below, and because the
		 * support libraries called below can set our handle to NULL.
		 */
		cmd = elf_next(arelf);

		/* Get member filename */
		if ((arname = ar_member_name(name, arelf, ofl)) == NULL)
			return (FALSE);

		/*
		 * Skip the symbol table, string table, or any other special
		 * archive member. These all start with a '/' character.
		 */
		if (*arname == '/') {
			(void) elf_end(arelf);
			continue;
		}

		/* Obtain archive member offset within the file */
		off = _elf_getarhdrbase(arelf);

		/*
		 * ld_sup_open() will reset the current iteration point for
		 * the archive to point at this member rather than the next
		 * one for the benefit of the support libraries. Since
		 * this loop relies on the current position not changing
		 * underneath it, we save and restore the current
		 * position around the support library call.
		 */
		next_off = _elf_getnextoff(adp->ad_elf);

		/* Construct the member's full pathname */
		if ((arpath = ar_member_path(name, arname, ofl)) == NULL)
			return (FALSE);

		/*
		 * Determine whether the support libraries wish to process
		 * this open. See comments in ld_process_open().
		 */
		ld_sup_open(ofl, &arpath, &arname, &fd,
		    (FLG_IF_EXTRACT | FLG_IF_NEEDED), &arelf, adp->ad_elf,
		    off, elf_kind(arelf));
		(void) elf_rand(adp->ad_elf, next_off);
		if (arelf == NULL)
			continue;

		DBG_CALL(Dbg_syms_ar_force(ofl->ofl_lml, name, arname));
		switch (ar_input(fd, adp, ofl, arelf, arpath, rej)) {
		case S_ERROR:
			return (FALSE);
		case 0:
			continue;
		}

		*found = TRUE;
	}

	/*
	 * Mark this as having been completely processed, so we don't have do
	 * work harder than necessary.
	 */
	adp->ad_allextract = TRUE;

	return (TRUE);
}


/*
 * Process the given archive and extract objects for inclusion into
 * the link.
 *
 * entry:
 *	name - Name of archive
 *	fd - Open file descriptor for archive
 *	adp - Archive descriptor
 *	ofl - output descriptor
 *
 * exit:
 *	Returns FALSE on fatal error, TRUE otherwise.
 */
Boolean
ld_process_archive(const char *name, int fd, Ar_desc *adp, Ofl_desc *ofl)
{
	Boolean		found = FALSE;
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
		return (TRUE);

	/*
	 * If this archive was processed with -z allextract, then all members
	 * have already been extracted.
	 */
	if (adp->ad_allextract == TRUE)
		return (TRUE);

	if (ofl->ofl_flags1 & FLG_OF1_ALLEXRT) {
		if (!ar_extract_all(name, fd, adp, ofl, &found, &rej))
			return (FALSE);
	} else {
		if (!ar_extract_bysym(name, fd, adp, ofl, &found, &rej))
			return (FALSE);
	}

	/*
	 * If no objects have been found in the archive test for any rejections
	 * and if one had occurred issue a warning - its possible a user has
	 * pointed at an archive containing the wrong class of elf members.
	 */
	if ((found == 0) && rej.rej_type) {
		Conv_reject_desc_buf_t rej_buf;

		ld_eprintf(ofl, ERR_WARNING, MSG_INTL(reject[rej.rej_type]),
		    rej.rej_name ? rej.rej_name : MSG_INTL(MSG_STR_UNKNOWN),
		    conv_reject_desc(&rej, &rej_buf, ld_targ.t_m.m_mach));
	}

	return (TRUE);
}
