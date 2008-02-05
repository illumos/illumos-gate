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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Symbol table management routines
 */
#include	<stdio.h>
#include	<string.h>
#include	<debug.h>
#include	"msg.h"
#include	"_libld.h"

/*
 * AVL tree comparator function:
 *
 *	The primary key is the 'sa_hashval' with a secondary
 *	key of the symbol name itself.
 */
int
ld_sym_avl_comp(const void *elem1, const void *elem2)
{
	int	res;
	Sym_avlnode	*sav1 = (Sym_avlnode *)elem1;
	Sym_avlnode	*sav2 = (Sym_avlnode *)elem2;

	res = sav1->sav_hash - sav2->sav_hash;

	if (res < 0)
		return (-1);
	if (res > 0)
		return (1);

	/*
	 * Hash is equal - now compare name
	 */
	res = strcmp(sav1->sav_name, sav2->sav_name);
	if (res == 0)
		return (0);
	if (res > 0)
		return (1);
	return (-1);
}


/*
 * Focal point for verifying symbol names.
 */
inline static const char *
string(Ofl_desc *ofl, Ifl_desc *ifl, Sym *sym, const char *strs, size_t strsize,
    int symndx, Word shndx, const char *symsecname, const char *strsecname,
    Word *flags)
{
	const char	*regname;
	Word		name = sym->st_name;

	if (name) {
		if ((ifl->ifl_flags & FLG_IF_HSTRTAB) == 0) {
			eprintf(ofl->ofl_lml, ERR_FATAL,
			    MSG_INTL(MSG_FIL_NOSTRTABLE), ifl->ifl_name,
			    symsecname, symndx, EC_XWORD(name));
			return (0);
		}
		if (name >= (Word)strsize) {
			eprintf(ofl->ofl_lml, ERR_FATAL,
			    MSG_INTL(MSG_FIL_EXCSTRTABLE), ifl->ifl_name,
			    symsecname, symndx, EC_XWORD(name),
			    strsecname, EC_XWORD(strsize));
			return (0);
		}
	}

	/*
	 * Determine if we're dealing with a register and if so validate it.
	 * If it's a scratch register, a fabricated name will be returned.
	 */
	if ((regname = ld_is_regsym(ofl, ifl, sym, strs, symndx, shndx,
	    symsecname, flags)) == (const char *)S_ERROR) {
		return (0);
	}
	if (regname)
		return (regname);

	/*
	 * If this isn't a register, but we have a global symbol with a null
	 * name, we're not going to be able to hash this, search for it, or
	 * do anything interesting.  However, we've been accepting a symbol of
	 * this kind for ages now, so give the user a warning (rather than a
	 * fatal error), just in case this instance exists somewhere in the
	 * world and hasn't, as yet, been a problem.
	 */
	if ((name == 0) && (ELF_ST_BIND(sym->st_info) != STB_LOCAL)) {
		eprintf(ofl->ofl_lml, ERR_WARNING, MSG_INTL(MSG_FIL_NONAMESYM),
		    ifl->ifl_name, symsecname, symndx, EC_XWORD(name));
	}
	return (strs + name);
}

/*
 * Shared objects can be built that define specific symbols that can not be
 * directly bound to.  These objects have a syminfo section (and an associated
 * DF_1_NODIRECT dynamic flags entry).  Scan this table looking for symbols
 * that can't be bound to directly, and if this files symbol is presently
 * referenced, mark it so that we don't directly bind to it.
 */
uintptr_t
ld_sym_nodirect(Is_desc *isp, Ifl_desc *ifl, Ofl_desc *ofl)
{
	Shdr		*sifshdr, *symshdr;
	Syminfo		*sifdata;
	Sym		*symdata;
	char		*strdata;
	ulong_t		cnt, _cnt;

	/*
	 * Get the syminfo data, and determine the number of entries.
	 */
	sifshdr = isp->is_shdr;
	sifdata = (Syminfo *)isp->is_indata->d_buf;
	cnt =  sifshdr->sh_size / sifshdr->sh_entsize;

	/*
	 * Get the associated symbol table.
	 */
	symshdr = ifl->ifl_isdesc[sifshdr->sh_link]->is_shdr;
	symdata = ifl->ifl_isdesc[sifshdr->sh_link]->is_indata->d_buf;

	/*
	 * Get the string table associated with the symbol table.
	 */
	strdata = ifl->ifl_isdesc[symshdr->sh_link]->is_indata->d_buf;

	/*
	 * Traverse the syminfo data for symbols that can't be directly
	 * bound to.
	 */
	for (_cnt = 1, sifdata++; _cnt < cnt; _cnt++, sifdata++) {
		Sym		*sym;
		char		*str;
		Sym_desc	*sdp;

		if ((sifdata->si_flags & SYMINFO_FLG_NOEXTDIRECT) == 0)
			continue;

		sym = (Sym *)(symdata + _cnt);
		str = (char *)(strdata + sym->st_name);

		if (sdp = ld_sym_find(str, SYM_NOHASH, 0, ofl)) {
			if (ifl != sdp->sd_file)
				continue;

			sdp->sd_flags1 &= ~FLG_SY1_DIR;
			sdp->sd_flags1 |= FLG_SY1_NDIR;
		}
	}
	return (0);
}

/*
 * If, during symbol processing, it is necessary to update a local symbols
 * contents before we have generated the symbol tables in the output image,
 * create a new symbol structure and copy the original symbol contents.  While
 * we are processing the input files, their local symbols are part of the
 * read-only mapped image.  Commonly, these symbols are copied to the new output
 * file image and then updated to reflect their new address and any change in
 * attributes.  However, sometimes during relocation counting, it is necessary
 * to adjust the symbols information.  This routine provides for the generation
 * of a new symbol image so that this update can be performed.
 * All global symbols are copied to an internal symbol table to improve locality
 * of reference and hence performance, and thus this copying is not necessary.
 */
uintptr_t
ld_sym_copy(Sym_desc *sdp)
{
	Sym	*nsym;

	if (sdp->sd_flags & FLG_SY_CLEAN) {
		if ((nsym = libld_malloc(sizeof (Sym))) == 0)
			return (S_ERROR);
		*nsym = *(sdp->sd_sym);
		sdp->sd_sym = nsym;
		sdp->sd_flags &= ~FLG_SY_CLEAN;
	}
	return (1);
}

/*
 * Finds a given name in the link editors internal symbol table.  If no
 * hash value is specified it is calculated.  A pointer to the located
 * Sym_desc entry is returned, or NULL if the symbol is not found.
 */
Sym_desc *
ld_sym_find(const char *name, Word hash, avl_index_t *where, Ofl_desc *ofl)
{
	Sym_avlnode	qsav;
	Sym_avlnode	*sav;

	if (hash == SYM_NOHASH)
		/* LINTED */
		hash = (Word)elf_hash((const char *)name);
	qsav.sav_hash = hash;
	qsav.sav_name = name;

	/*
	 * Perform search for symbol in AVL tree.  Note that the 'where' field
	 * is passed in from the caller.  If a 'where' is present, it can be
	 * used in subsequent 'ld_sym_enter()' calls if required.
	 */
	sav = avl_find(&ofl->ofl_symavl, &qsav, where);

	/*
	 * If symbol was not found in the avl tree, return null to show that.
	 */
	if (sav == 0)
		return (0);

	/*
	 * Return symbol found.
	 */
	return (sav->sav_symdesc);
}


/*
 * Enter a new symbol into the link editors internal symbol table.
 * If the symbol is from an input file, information regarding the input file
 * and input section is also recorded.  Otherwise (file == NULL) the symbol
 * has been internally generated (ie. _etext, _edata, etc.).
 */
Sym_desc *
ld_sym_enter(const char *name, Sym *osym, Word hash, Ifl_desc *ifl,
    Ofl_desc *ofl, Word ndx, Word shndx, Word sdflags, Half sdflags1,
    avl_index_t *where)
{
	Sym_desc	*sdp;
	Sym_aux		*sap;
	Sym_avlnode	*savl;
	char		*_name;
	Sym		*nsym;
	Half		etype;
	uchar_t		vis;
	avl_index_t	_where;

	/*
	 * Establish the file type.
	 */
	if (ifl)
		etype = ifl->ifl_ehdr->e_type;
	else
		etype = ET_NONE;

	ofl->ofl_entercnt++;

	/*
	 * Allocate a Sym Descriptor, Auxiliary Descriptor, and a Sym AVLNode -
	 * contiguously.
	 */
	if ((savl = libld_calloc(sizeof (Sym_avlnode) + sizeof (Sym_desc) +
	    sizeof (Sym_aux), 1)) == 0)
		return ((Sym_desc *)S_ERROR);
	sdp = (Sym_desc *)((uintptr_t)savl + sizeof (Sym_avlnode));
	sap = (Sym_aux *)((uintptr_t)sdp + sizeof (Sym_desc));

	savl->sav_symdesc = sdp;
	sdp->sd_file = ifl;
	sdp->sd_aux = sap;
	savl->sav_hash = sap->sa_hash = hash;

	/*
	 * Copy the symbol table entry from the input file into the internal
	 * entry and have the symbol descriptor use it.
	 */
	sdp->sd_sym = nsym = &sap->sa_sym;
	*nsym = *osym;
	sdp->sd_shndx = shndx;
	sdp->sd_flags |= sdflags;
	sdp->sd_flags1 |= sdflags1;

	if ((_name = libld_malloc(strlen(name) + 1)) == 0)
		return ((Sym_desc *)S_ERROR);
	savl->sav_name = sdp->sd_name = (const char *)strcpy(_name, name);

	/*
	 * Enter Symbol in AVL tree.
	 */
	if (where == 0) {
		/* LINTED */
		Sym_avlnode	*_savl;
		/*
		 * If a previous ld_sym_find() hasn't initialized 'where' do it
		 * now.
		 */
		where = &_where;
		_savl = avl_find(&ofl->ofl_symavl, savl, where);
		assert(_savl == 0);
	}
	avl_insert(&ofl->ofl_symavl, savl, *where);

	/*
	 * Record the section index.  This is possible because the
	 * `ifl_isdesc' table is filled before we start symbol processing.
	 */
	if ((sdflags & FLG_SY_SPECSEC) || (nsym->st_shndx == SHN_UNDEF))
		sdp->sd_isc = NULL;
	else {
		sdp->sd_isc = ifl->ifl_isdesc[shndx];

		/*
		 * If this symbol is from a relocatable object, make sure that
		 * it is still associated with a section.  For example, an
		 * unknown section type (SHT_NULL) would have been rejected on
		 * input with a warning.  Here, we make the use of the symbol
		 * fatal.  A symbol descriptor is still returned, so that the
		 * caller can continue processing all symbols, and hence flush
		 * out as many error conditions as possible.
		 */
		if ((etype == ET_REL) && (sdp->sd_isc == 0)) {
			eprintf(ofl->ofl_lml, ERR_FATAL,
			    MSG_INTL(MSG_SYM_INVSEC), name, ifl->ifl_name,
			    EC_XWORD(shndx));
			ofl->ofl_flags |= FLG_OF_FATAL;
			return (sdp);
		}
	}

	/*
	 * Mark any COMMON symbols as 'tentative'.
	 */
	if (sdflags & FLG_SY_SPECSEC) {
		if (nsym->st_shndx == SHN_COMMON)
			sdp->sd_flags |= FLG_SY_TENTSYM;
#if	defined(__x86) && defined(_ELF64)
		else if (nsym->st_shndx == SHN_X86_64_LCOMMON)
			sdp->sd_flags |= FLG_SY_TENTSYM;
#endif
	}

	/*
	 * Establish the symbols visibility and reference.
	 */
	vis = ELF_ST_VISIBILITY(nsym->st_other);

	if ((etype == ET_NONE) || (etype == ET_REL)) {
		switch (vis) {
		case STV_DEFAULT:
			sdp->sd_flags1 |= FLG_SY1_DEFAULT;
			break;
		case STV_INTERNAL:
		case STV_HIDDEN:
			sdp->sd_flags1 |= FLG_SY1_HIDDEN;
			break;
		case STV_PROTECTED:
			sdp->sd_flags1 |= FLG_SY1_PROTECT;
			break;
		case STV_EXPORTED:
			sdp->sd_flags1 |= FLG_SY1_EXPORT;
			break;
		case STV_SINGLETON:
			sdp->sd_flags1 |= (FLG_SY1_SINGLE | FLG_SY1_NDIR);
			ofl->ofl_flags1 |= FLG_OF1_NDIRECT;
			break;
		case STV_ELIMINATE:
			sdp->sd_flags1 |= (FLG_SY1_HIDDEN | FLG_SY1_ELIM);
			break;
		default:
			assert(vis <= STV_ELIMINATE);
		}

		sdp->sd_ref = REF_REL_NEED;

		/*
		 * Under -Bnodirect, all exported interfaces that have not
		 * explicitly been defined protected or directly bound to, are
		 * tagged to prevent direct binding.
		 */
		if ((ofl->ofl_flags1 & FLG_OF1_ALNODIR) &&
		    ((sdp->sd_flags1 & (FLG_SY1_PROTECT | FLG_SY1_DIR)) == 0) &&
		    (nsym->st_shndx != SHN_UNDEF)) {
			sdp->sd_flags1 |= FLG_SY1_NDIR;
		}
	} else {
		sdp->sd_ref = REF_DYN_SEEN;

		/*
		 * Record the binding file for this symbol in the sa_bindto
		 * field.  If this symbol is ever overridden by a REF_REL_NEED
		 * definition, sa_bindto is used when building a 'translator'.
		 */
		if (nsym->st_shndx != SHN_UNDEF)
			sdp->sd_aux->sa_bindto = ifl;

		/*
		 * If this is a protected symbol, remember this.  Note, this
		 * state is different from the FLG_SY1_PROTECT used to establish
		 * a symbol definitions visibility.  This state is used to warn
		 * against possible copy relocations against this referenced
		 * symbol.
		 */
		if (vis == STV_PROTECTED)
			sdp->sd_flags |= FLG_SY_PROT;

		/*
		 * If this is a SINGLETON definition, then indicate the symbol
		 * can not be directly bound to, and retain the visibility.
		 * This visibility will be inherited by any references made to
		 * this symbol.
		 */
		if ((vis == STV_SINGLETON) && (nsym->st_shndx != SHN_UNDEF))
			sdp->sd_flags1 |= (FLG_SY1_SINGLE | FLG_SY1_NDIR);

		/*
		 * If the new symbol is from a shared library and is associated
		 * with a SHT_NOBITS section then this symbol originated from a
		 * tentative symbol.
		 */
		if (sdp->sd_isc &&
		    (sdp->sd_isc->is_shdr->sh_type == SHT_NOBITS))
			sdp->sd_flags |= FLG_SY_TENTSYM;
	}

	/*
	 * Reclassify any SHN_SUNW_IGNORE symbols to SHN_UNDEF so as to
	 * simplify future processing.
	 */
	if (nsym->st_shndx == SHN_SUNW_IGNORE) {
		sdp->sd_shndx = shndx = SHN_UNDEF;
		sdp->sd_flags |= FLG_SY_REDUCED;
		sdp->sd_flags1 |=
		    (FLG_SY1_HIDDEN | FLG_SY1_IGNORE | FLG_SY1_ELIM);
	}

	/*
	 * If this is an undefined, or common symbol from a relocatable object
	 * determine whether it is a global or weak reference (see build_osym(),
	 * where REF_DYN_NEED definitions are returned back to undefines).
	 */
	if ((etype == ET_REL) &&
	    (ELF_ST_BIND(nsym->st_info) == STB_GLOBAL) &&
	    ((nsym->st_shndx == SHN_UNDEF) || ((sdflags & FLG_SY_SPECSEC) &&
#if	defined(__x86) && defined(_ELF64)
	    ((nsym->st_shndx == SHN_COMMON) ||
	    (nsym->st_shndx == SHN_X86_64_LCOMMON)))))
#else
	/* BEGIN CSTYLED */
	    (nsym->st_shndx == SHN_COMMON))))
	/* END CSTYLED */
#endif
		sdp->sd_flags |= FLG_SY_GLOBREF;

	/*
	 * Record the input filename on the referenced or defined files list
	 * for possible later diagnostics.  The `sa_rfile' pointer contains the
	 * name of the file that first referenced this symbol and is used to
	 * generate undefined symbol diagnostics (refer to sym_undef_entry()).
	 * Note that this entry can be overridden if a reference from a
	 * relocatable object is found after a reference from a shared object
	 * (refer to sym_override()).
	 * The `sa_dfiles' list is used to maintain the list of files that
	 * define the same symbol.  This list can be used for two reasons:
	 *
	 *   o	To save the first definition of a symbol that is not available
	 *	for this link-edit.
	 *
	 *   o	To save all definitions of a symbol when the -m option is in
	 *	effect.  This is optional as it is used to list multiple
	 *	(interposed) definitions of a symbol (refer to ldmap_out()),
	 *	and can be quite expensive.
	 */
	if (nsym->st_shndx == SHN_UNDEF) {
		sap->sa_rfile = ifl->ifl_name;
	} else {
		if (sdp->sd_ref == REF_DYN_SEEN) {
			/*
			 * A symbol is determined to be unavailable if it
			 * belongs to a version of a shared object that this
			 * user does not wish to use, or if it belongs to an
			 * implicit shared object.
			 */
			if (ifl->ifl_vercnt) {
				Ver_index	*vip;
				Half		vndx = ifl->ifl_versym[ndx];

				sap->sa_dverndx = vndx;
				vip = &ifl->ifl_verndx[vndx];
				if (!(vip->vi_flags & FLG_VER_AVAIL)) {
					sdp->sd_flags |= FLG_SY_NOTAVAIL;
					sap->sa_vfile = ifl->ifl_name;
				}
			}
			if (!(ifl->ifl_flags & FLG_IF_NEEDED))
				sdp->sd_flags |= FLG_SY_NOTAVAIL;

		} else if (etype == ET_REL) {
			/*
			 * If this symbol has been obtained from a versioned
			 * input relocatable object then the new symbol must be
			 * promoted to the versioning of the output file.
			 */
			if (ifl->ifl_versym)
				ld_vers_promote(sdp, ndx, ifl, ofl);
		}

		if ((ofl->ofl_flags & FLG_OF_GENMAP) &&
		    ((sdflags & FLG_SY_SPECSEC) == 0))
			if (list_appendc(&sap->sa_dfiles, ifl->ifl_name) == 0)
				return ((Sym_desc *)S_ERROR);
	}

	/*
	 * Provided we're not processing a mapfile, diagnose the entered symbol.
	 * Mapfile processing requires the symbol to be updated with additional
	 * information, therefore the diagnosing of the symbol is deferred until
	 * later (see Dbg_map_symbol()).
	 */
	if ((ifl == 0) || ((ifl->ifl_flags & FLG_IF_MAPFILE) == 0))
		DBG_CALL(Dbg_syms_entered(ofl, nsym, sdp));
	return (sdp);
}

/*
 * Add a special symbol to the symbol table.  Takes special symbol name with
 * and without underscores.  This routine is called, after all other symbol
 * resolution has completed, to generate a reserved absolute symbol (the
 * underscore version).  Special symbols are updated with the appropriate
 * values in update_osym().  If the user has already defined this symbol
 * issue a warning and leave the symbol as is.  If the non-underscore symbol
 * is referenced then turn it into a weak alias of the underscored symbol.
 *
 * The bits in flags_u are OR'd into the flags field of the symbol
 * for the underscored symbol.
 *
 * If this is a global symbol, and it hasn't explicitly been defined as being
 * directly bound to, indicate that it can't be directly bound to.
 * Historically, most special symbols only have meaning to the object in which
 * they exist, however, they've always been global.  To ensure compatibility
 * with any unexpected use presently in effect, ensure these symbols don't get
 * directly bound to.  Note, that establishing this state here isn't sufficient
 * to create a syminfo table, only if a syminfo table is being created by some
 * other symbol directives will the nodirect binding be recorded.  This ensures
 * we don't create syminfo sections for all objects we create, as this might add
 * unnecessary bloat to users who haven't explicitly requested extra symbol
 * information.
 */
static uintptr_t
sym_add_spec(const char *name, const char *uname, Word sdaux_id,
    Word flags_u, Half flags1, Ofl_desc *ofl)
{
	Sym_desc	*sdp;
	Sym_desc 	*usdp;
	Sym		*sym;
	Word		hash;
	avl_index_t	where;

	/* LINTED */
	hash = (Word)elf_hash(uname);
	if (usdp = ld_sym_find(uname, hash, &where, ofl)) {
		/*
		 * If the underscore symbol exists and is undefined, or was
		 * defined in a shared library, convert it to a local symbol.
		 * Otherwise leave it as is and warn the user.
		 */
		if ((usdp->sd_shndx == SHN_UNDEF) ||
		    (usdp->sd_ref != REF_REL_NEED)) {
			usdp->sd_ref = REF_REL_NEED;
			usdp->sd_shndx = usdp->sd_sym->st_shndx = SHN_ABS;
			usdp->sd_flags |= FLG_SY_SPECSEC | flags_u;
			usdp->sd_sym->st_info =
			    ELF_ST_INFO(STB_GLOBAL, STT_OBJECT);
			usdp->sd_isc = NULL;
			usdp->sd_sym->st_size = 0;
			usdp->sd_sym->st_value = 0;
			/* LINTED */
			usdp->sd_aux->sa_symspec = (Half)sdaux_id;

			/*
			 * If a user hasn't specifically indicated that the
			 * scope of this symbol be made local, then leave it
			 * as global (ie. prevent automatic scoping).  The GOT
			 * should be defined protected, whereas all other
			 * special symbols are tagged as no-direct.
			 */
			if (((usdp->sd_flags1 & FLG_SY1_HIDDEN) == 0) &&
			    (flags1 & FLG_SY1_DEFAULT)) {
				usdp->sd_aux->sa_overndx = VER_NDX_GLOBAL;
				if (sdaux_id == SDAUX_ID_GOT) {
					usdp->sd_flags1 &= ~FLG_SY1_NDIR;
					usdp->sd_flags1 |= FLG_SY1_PROTECT;
					usdp->sd_sym->st_other = STV_PROTECTED;
				} else if (
				    ((usdp->sd_flags1 & FLG_SY1_DIR) == 0) &&
				    ((ofl->ofl_flags & FLG_OF_SYMBOLIC) == 0)) {
					usdp->sd_flags1 |= FLG_SY1_NDIR;
				}
			}
			usdp->sd_flags1 |= flags1;

			/*
			 * If the reference originated from a mapfile ensure
			 * we mark the symbol as used.
			 */
			if (usdp->sd_flags & FLG_SY_MAPREF)
				usdp->sd_flags |= FLG_SY_MAPUSED;

			DBG_CALL(Dbg_syms_updated(ofl, usdp, uname));
		} else
			eprintf(ofl->ofl_lml, ERR_WARNING,
			    MSG_INTL(MSG_SYM_RESERVE), uname,
			    usdp->sd_file->ifl_name);
	} else {
		/*
		 * If the symbol does not exist create it.
		 */
		if ((sym = libld_calloc(sizeof (Sym), 1)) == 0)
			return (S_ERROR);
		sym->st_shndx = SHN_ABS;
		sym->st_info = ELF_ST_INFO(STB_GLOBAL, STT_OBJECT);
		sym->st_size = 0;
		sym->st_value = 0;
		DBG_CALL(Dbg_syms_created(ofl->ofl_lml, uname));
		if ((usdp = ld_sym_enter(uname, sym, hash, (Ifl_desc *)NULL,
		    ofl, 0, SHN_ABS, FLG_SY_SPECSEC | flags_u, 0, &where)) ==
		    (Sym_desc *)S_ERROR)
			return (S_ERROR);
		usdp->sd_ref = REF_REL_NEED;
		/* LINTED */
		usdp->sd_aux->sa_symspec = (Half)sdaux_id;

		usdp->sd_aux->sa_overndx = VER_NDX_GLOBAL;

		if (sdaux_id == SDAUX_ID_GOT) {
			usdp->sd_flags1 |= FLG_SY1_PROTECT;
			usdp->sd_sym->st_other = STV_PROTECTED;
		} else if ((flags1 & FLG_SY1_DEFAULT) &&
		    ((ofl->ofl_flags & FLG_OF_SYMBOLIC) == 0)) {
			usdp->sd_flags1 |= FLG_SY1_NDIR;
		}
		usdp->sd_flags1 |= flags1;
	}

	if (name && (sdp = ld_sym_find(name, SYM_NOHASH, 0, ofl)) &&
	    (sdp->sd_sym->st_shndx == SHN_UNDEF)) {
		uchar_t	bind;

		/*
		 * If the non-underscore symbol exists and is undefined
		 * convert it to be a local.  If the underscore has
		 * sa_symspec set (ie. it was created above) then simulate this
		 * as a weak alias.
		 */
		sdp->sd_ref = REF_REL_NEED;
		sdp->sd_shndx = sdp->sd_sym->st_shndx = SHN_ABS;
		sdp->sd_flags |= FLG_SY_SPECSEC;
		sdp->sd_isc = NULL;
		sdp->sd_sym->st_size = 0;
		sdp->sd_sym->st_value = 0;
		/* LINTED */
		sdp->sd_aux->sa_symspec = (Half)sdaux_id;
		if (usdp->sd_aux->sa_symspec) {
			usdp->sd_aux->sa_linkndx = 0;
			sdp->sd_aux->sa_linkndx = 0;
			bind = STB_WEAK;
		} else
			bind = STB_GLOBAL;
		sdp->sd_sym->st_info = ELF_ST_INFO(bind, STT_OBJECT);

		/*
		 * If a user hasn't specifically indicated the scope of this
		 * symbol be made local then leave it as global (ie. prevent
		 * automatic scoping).  The GOT should be defined protected,
		 * whereas all other special symbols are tagged as no-direct.
		 */
		if (((sdp->sd_flags1 & FLG_SY1_HIDDEN) == 0) &&
		    (flags1 & FLG_SY1_DEFAULT)) {
			sdp->sd_aux->sa_overndx = VER_NDX_GLOBAL;
			if (sdaux_id == SDAUX_ID_GOT) {
				sdp->sd_flags1 &= ~FLG_SY1_NDIR;
				sdp->sd_flags1 |= FLG_SY1_PROTECT;
				sdp->sd_sym->st_other = STV_PROTECTED;
			} else if (((sdp->sd_flags1 & FLG_SY1_DIR) == 0) &&
			    ((ofl->ofl_flags & FLG_OF_SYMBOLIC) == 0)) {
				sdp->sd_flags1 |= FLG_SY1_NDIR;
			}
		}
		sdp->sd_flags1 |= flags1;

		/*
		 * If the reference originated from a mapfile ensure
		 * we mark the symbol as used.
		 */
		if (sdp->sd_flags & FLG_SY_MAPREF)
			sdp->sd_flags |= FLG_SY_MAPUSED;

		DBG_CALL(Dbg_syms_updated(ofl, sdp, name));
	}
	return (1);
}


/*
 * Print undefined symbols.
 */
static Boolean	undef_title = TRUE;

static void
sym_undef_title(Ofl_desc *ofl)
{
	eprintf(ofl->ofl_lml, ERR_NONE, MSG_INTL(MSG_SYM_FMT_UNDEF),
	    MSG_INTL(MSG_SYM_UNDEF_ITM_11),
	    MSG_INTL(MSG_SYM_UNDEF_ITM_21),
	    MSG_INTL(MSG_SYM_UNDEF_ITM_12),
	    MSG_INTL(MSG_SYM_UNDEF_ITM_22));

	undef_title = FALSE;
}

/*
 * Undefined symbols can fall into one of four types:
 *
 *  o	the symbol is really undefined (SHN_UNDEF).
 *
 *  o	versioning has been enabled, however this symbol has not been assigned
 *	to one of the defined versions.
 *
 *  o	the symbol has been defined by an implicitly supplied library, ie. one
 *	which was encounted because it was NEEDED by another library, rather
 * 	than from a command line supplied library which would become the only
 *	dependency of the output file being produced.
 *
 *  o	the symbol has been defined by a version of a shared object that is
 *	not permitted for this link-edit.
 *
 * In all cases the file who made the first reference to this symbol will have
 * been recorded via the `sa_rfile' pointer.
 */
typedef enum {
	UNDEF,		NOVERSION,	IMPLICIT,	NOTAVAIL,
	BNDLOCAL
} Type;

static const Msg format[] = {
	MSG_SYM_UND_UNDEF,		/* MSG_INTL(MSG_SYM_UND_UNDEF) */
	MSG_SYM_UND_NOVER,		/* MSG_INTL(MSG_SYM_UND_NOVER) */
	MSG_SYM_UND_IMPL,		/* MSG_INTL(MSG_SYM_UND_IMPL) */
	MSG_SYM_UND_NOTA,		/* MSG_INTL(MSG_SYM_UND_NOTA) */
	MSG_SYM_UND_BNDLOCAL		/* MSG_INTL(MSG_SYM_UND_BNDLOCAL) */
};

static void
sym_undef_entry(Ofl_desc *ofl, Sym_desc *sdp, Type type)
{
	const char	*name1, *name2, *name3;
	Ifl_desc	*ifl = sdp->sd_file;
	Sym_aux		*sap = sdp->sd_aux;

	if (undef_title)
		sym_undef_title(ofl);

	switch (type) {
	case UNDEF:
	case BNDLOCAL:
		name1 = sap->sa_rfile;
		break;
	case NOVERSION:
		name1 = ifl->ifl_name;
		break;
	case IMPLICIT:
		name1 = sap->sa_rfile;
		name2 = ifl->ifl_name;
		break;
	case NOTAVAIL:
		name1 = sap->sa_rfile;
		name2 = sap->sa_vfile;
		name3 = ifl->ifl_verndx[sap->sa_dverndx].vi_name;
		break;
	default:
		return;
	}

	eprintf(ofl->ofl_lml, ERR_NONE, MSG_INTL(format[type]),
	    demangle(sdp->sd_name), name1, name2, name3);
}

/*
 * At this point all symbol input processing has been completed, therefore
 * complete the symbol table entries by generating any necessary internal
 * symbols.
 */
uintptr_t
ld_sym_spec(Ofl_desc *ofl)
{
	Sym_desc	*sdp;

	if (ofl->ofl_flags & FLG_OF_RELOBJ)
		return (1);

	DBG_CALL(Dbg_syms_spec_title(ofl->ofl_lml));

	if (sym_add_spec(MSG_ORIG(MSG_SYM_ETEXT), MSG_ORIG(MSG_SYM_ETEXT_U),
	    SDAUX_ID_ETEXT, 0, (FLG_SY1_DEFAULT | FLG_SY1_EXPDEF),
	    ofl) == S_ERROR)
		return (S_ERROR);
	if (sym_add_spec(MSG_ORIG(MSG_SYM_EDATA), MSG_ORIG(MSG_SYM_EDATA_U),
	    SDAUX_ID_EDATA, 0, (FLG_SY1_DEFAULT | FLG_SY1_EXPDEF),
	    ofl) == S_ERROR)
		return (S_ERROR);
	if (sym_add_spec(MSG_ORIG(MSG_SYM_END), MSG_ORIG(MSG_SYM_END_U),
	    SDAUX_ID_END, FLG_SY_DYNSORT, (FLG_SY1_DEFAULT | FLG_SY1_EXPDEF),
	    ofl) == S_ERROR)
		return (S_ERROR);
	if (sym_add_spec(MSG_ORIG(MSG_SYM_L_END), MSG_ORIG(MSG_SYM_L_END_U),
	    SDAUX_ID_END, 0, FLG_SY1_HIDDEN, ofl) == S_ERROR)
		return (S_ERROR);
	if (sym_add_spec(MSG_ORIG(MSG_SYM_L_START), MSG_ORIG(MSG_SYM_L_START_U),
	    SDAUX_ID_START, 0, FLG_SY1_HIDDEN, ofl) == S_ERROR)
		return (S_ERROR);

	/*
	 * Historically we've always produced a _DYNAMIC symbol, even for
	 * static executables (in which case its value will be 0).
	 */
	if (sym_add_spec(MSG_ORIG(MSG_SYM_DYNAMIC), MSG_ORIG(MSG_SYM_DYNAMIC_U),
	    SDAUX_ID_DYN, FLG_SY_DYNSORT, (FLG_SY1_DEFAULT | FLG_SY1_EXPDEF),
	    ofl) == S_ERROR)
		return (S_ERROR);

	if (OFL_ALLOW_DYNSYM(ofl))
		if (sym_add_spec(MSG_ORIG(MSG_SYM_PLKTBL),
		    MSG_ORIG(MSG_SYM_PLKTBL_U), SDAUX_ID_PLT,
		    FLG_SY_DYNSORT, (FLG_SY1_DEFAULT | FLG_SY1_EXPDEF),
		    ofl) == S_ERROR)
			return (S_ERROR);

	/*
	 * A GOT reference will be accompanied by the associated GOT symbol.
	 * Make sure it gets assigned the appropriate special attributes.
	 */
	if (((sdp = ld_sym_find(MSG_ORIG(MSG_SYM_GOFTBL_U),
	    SYM_NOHASH, 0, ofl)) != 0) && (sdp->sd_ref != REF_DYN_SEEN)) {
		if (sym_add_spec(MSG_ORIG(MSG_SYM_GOFTBL),
		    MSG_ORIG(MSG_SYM_GOFTBL_U), SDAUX_ID_GOT, FLG_SY_DYNSORT,
		    (FLG_SY1_DEFAULT | FLG_SY1_EXPDEF), ofl) == S_ERROR)
			return (S_ERROR);
	}

	return (1);
}

/*
 * This routine checks to see if a symbols visibility needs to be reduced to
 * either SYMBOLIC or LOCAL.  This routine can be called from either
 * reloc_init() or sym_validate().
 */
void
ld_sym_adjust_vis(Sym_desc *sdp, Ofl_desc *ofl)
{
	Word	oflags = ofl->ofl_flags, oflags1 = ofl->ofl_flags1;
	Sym	*sym = sdp->sd_sym;

	if ((sdp->sd_ref == REF_REL_NEED) &&
	    (sdp->sd_sym->st_shndx != SHN_UNDEF)) {
		/*
		 * If auto-reduction/elimination is enabled, reduce any
		 * non-versioned global symbols.  This routine is called either
		 * from any initial relocation processing that references this
		 * symbol, or from the symbol validation processing.
		 *
		 * A symbol is a candidate for auto-reduction/elimination if:
		 *
		 *   .  the symbol wasn't explicitly defined within a mapfile
		 *	(in which case all the necessary state has been applied
		 *	to the symbol), or
		 *   .	the symbol isn't one of the family of reserved
		 *	special symbols (ie. _end, _etext, etc.), or
		 *   .	the symbol isn't a SINGLETON, or
		 *   .  the symbol wasn't explicitly defined within a version
		 *	definition associated with an input relocatable object.
		 *
		 * Indicate that the symbol has been reduced as it may be
		 * necessary to print these symbols later.
		 */
		if (((oflags & FLG_OF_AUTOLCL) ||
		    (oflags1 & FLG_OF1_AUTOELM)) &&
		    ((sdp->sd_flags1 & MSK_SY1_NOAUTO) == 0)) {
			if ((sdp->sd_flags1 & FLG_SY1_HIDDEN) == 0) {
				sdp->sd_flags |= FLG_SY_REDUCED;
				sdp->sd_flags1 |= FLG_SY1_HIDDEN;
			}

			if (ofl->ofl_flags1 &
			    (FLG_OF1_REDLSYM | FLG_OF1_AUTOELM)) {
				sdp->sd_flags1 |= FLG_SY1_ELIM;
				sym->st_other = STV_ELIMINATE |
				    (sym->st_other & ~MSK_SYM_VISIBILITY);
			} else if (ELF_ST_VISIBILITY(sym->st_other) !=
			    STV_INTERNAL)
				sym->st_other = STV_HIDDEN |
				    (sym->st_other & ~MSK_SYM_VISIBILITY);
		}

		/*
		 * If -Bsymbolic is in effect, and the symbol hasn't explicitly
		 * been defined nodirect (via a mapfile), then bind the global
		 * symbol symbolically and assign the STV_PROTECTED visibility
		 * attribute.
		 */
		if ((oflags & FLG_OF_SYMBOLIC) &&
		    ((sdp->sd_flags1 & (FLG_SY1_HIDDEN | FLG_SY1_NDIR)) == 0)) {
			sdp->sd_flags1 |= FLG_SY1_PROTECT;
			if (ELF_ST_VISIBILITY(sym->st_other) == STV_DEFAULT)
				sym->st_other = STV_PROTECTED |
				    (sym->st_other & ~MSK_SYM_VISIBILITY);
		}
	}

	/*
	 * Indicate that this symbol has had it's visibility checked so that
	 * we don't need to do this investigation again.
	 */
	sdp->sd_flags |= FLG_SY_VISIBLE;
}

/*
 * Make sure a symbol definition is local to the object being built.
 */
static int
ensure_sym_local(Ofl_desc *ofl, Sym_desc *sdp, const char *str)
{
	if (sdp->sd_sym->st_shndx == SHN_UNDEF) {
		if (str) {
			eprintf(ofl->ofl_lml, ERR_FATAL,
			    MSG_INTL(MSG_SYM_UNDEF), str,
			    demangle((char *)sdp->sd_name));
		}
		return (1);
	}
	if (sdp->sd_ref != REF_REL_NEED) {
		if (str) {
			eprintf(ofl->ofl_lml, ERR_FATAL,
			    MSG_INTL(MSG_SYM_EXTERN), str,
			    demangle((char *)sdp->sd_name),
			    sdp->sd_file->ifl_name);
		}
		return (1);
	}

	sdp->sd_flags |= FLG_SY_UPREQD;
	if (sdp->sd_isc) {
		sdp->sd_isc->is_flags |= FLG_IS_SECTREF;
		sdp->sd_isc->is_file->ifl_flags |= FLG_IF_FILEREF;
	}
	return (0);
}

/*
 * Make sure all the symbol definitions required for initarray, finiarray, or
 * preinitarray's are local to the object being built.
 */
static int
ensure_array_local(Ofl_desc *ofl, List *list, const char *str)
{
	Listnode	*lnp;
	Sym_desc	*sdp;
	int		ret = 0;

	for (LIST_TRAVERSE(list, lnp, sdp))
		ret += ensure_sym_local(ofl, sdp, str);

	return (ret);
}

/*
 * After all symbol table input processing has been finished, and all relocation
 * counting has been carried out (ie. no more symbols will be read, generated,
 * or modified), validate and count the relevant entries:
 *
 *	o	check and print any undefined symbols remaining.  Note that
 *		if a symbol has been defined by virtue of the inclusion of
 *		an implicit shared library, it is still classed as undefined.
 *
 * 	o	count the number of global needed symbols together with the
 *		size of their associated name strings (if scoping has been
 *		indicated these symbols may be reduced to locals).
 *
 *	o	establish the size and alignment requirements for the global
 *		.bss section (the alignment of this section is based on the
 *		first symbol that it will contain).
 */
uintptr_t
ld_sym_validate(Ofl_desc *ofl)
{
	Sym_avlnode	*sav;
	Sym_desc	*sdp;
	Sym		*sym;
	Word		oflags = ofl->ofl_flags;
	Word		undef = 0, needed = 0, verdesc = 0;
	Xword		bssalign = 0, tlsalign = 0;
	Xword		bsssize = 0, tlssize = 0;
#if	defined(__x86) && defined(_ELF64)
	Xword		lbssalign = 0, lbsssize = 0;
#endif
	int		ret;
	int		allow_ldynsym;
	uchar_t		type;

	/*
	 * If a symbol is undefined and this link-edit calls for no undefined
	 * symbols to remain (this is the default case when generating an
	 * executable but can be enforced for any object using -z defs), the
	 * symbol is classified as undefined and a fatal error condition will
	 * be indicated.
	 *
	 * If the symbol is undefined and we're creating a shared object with
	 * the -Bsymbolic flag, then the symbol is also classified as undefined
	 * and a warning condition will be indicated.
	 */
	if ((oflags & (FLG_OF_SHAROBJ | FLG_OF_SYMBOLIC)) ==
	    (FLG_OF_SHAROBJ | FLG_OF_SYMBOLIC))
		undef = FLG_OF_WARN;
	if (oflags & FLG_OF_NOUNDEF)
		undef = FLG_OF_FATAL;

	/*
	 * If the symbol is referenced from an implicitly included shared object
	 * (ie. it's not on the NEEDED list) then the symbol is also classified
	 * as undefined and a fatal error condition will be indicated.
	 */
	if ((oflags & FLG_OF_NOUNDEF) || !(oflags & FLG_OF_SHAROBJ))
		needed = FLG_OF_FATAL;

	/*
	 * If the output image is being versioned all symbol definitions must be
	 * associated with a version.  Any symbol that isn't is classified as
	 * undefined and a fatal error condition will be indicated.
	 */
	if ((oflags & FLG_OF_VERDEF) && (ofl->ofl_vercnt > VER_NDX_GLOBAL))
		verdesc = FLG_OF_FATAL;

	allow_ldynsym = OFL_ALLOW_LDYNSYM(ofl);

	if (allow_ldynsym) {
		/*
		 * Normally, we disallow symbols with 0 size from appearing
		 * in a dyn[sym|tls]sort section. However, there are some
		 * symbols that serve special purposes that we want to exempt
		 * from this rule. Look them up, and set their
		 * FLG_SY_DYNSORT flag.
		 */
		static const char *special[] = {
			MSG_ORIG(MSG_SYM_INIT_U),	/* _init */
			MSG_ORIG(MSG_SYM_FINI_U),	/* _fini */
			MSG_ORIG(MSG_SYM_START),	/* _start */
			NULL
		};
		int i;

		for (i = 0; special[i] != NULL; i++) {
			if (((sdp = ld_sym_find(special[i],
			    SYM_NOHASH, 0, ofl)) != NULL) &&
			    (sdp->sd_sym->st_size == 0)) {
				if (ld_sym_copy(sdp) == S_ERROR)
					return (S_ERROR);
				sdp->sd_flags |= FLG_SY_DYNSORT;
			}
		}
	}

	/*
	 * Collect and validate the globals from the internal symbol table.
	 */
	for (sav = avl_first(&ofl->ofl_symavl); sav;
	    sav = AVL_NEXT(&ofl->ofl_symavl, sav)) {
		Is_desc		*isp;
		int		undeferr = 0;
		uchar_t		vis;

		sdp = sav->sav_symdesc;

		/*
		 * If undefined symbols are allowed ignore any symbols that are
		 * not needed.
		 */
		if (!(oflags & FLG_OF_NOUNDEF) &&
		    (sdp->sd_ref == REF_DYN_SEEN))
			continue;

		/*
		 * If the symbol originates from an external or parent mapfile
		 * reference and hasn't been matched to a reference from a
		 * relocatable object, ignore it.
		 */
		if ((sdp->sd_flags & (FLG_SY_EXTERN | FLG_SY_PARENT)) &&
		    ((sdp->sd_flags & FLG_SY_MAPUSED) == 0)) {
			sdp->sd_flags |= FLG_SY_INVALID;
			continue;
		}

		sym = sdp->sd_sym;
		type = ELF_ST_TYPE(sym->st_info);

		/*
		 * Sanity check TLS.
		 */
		if ((type == STT_TLS) && (sym->st_size != 0) &&
		    (sym->st_shndx != SHN_UNDEF) &&
		    (sym->st_shndx != SHN_COMMON)) {
			Is_desc		*isp = sdp->sd_isc;
			Ifl_desc	*ifl = sdp->sd_file;

			if ((isp == 0) || (isp->is_shdr == 0) ||
			    ((isp->is_shdr->sh_flags & SHF_TLS) == 0)) {
				eprintf(ofl->ofl_lml, ERR_FATAL,
				    MSG_INTL(MSG_SYM_TLS),
				    demangle(sdp->sd_name), ifl->ifl_name);
				ofl->ofl_flags |= FLG_OF_FATAL;
				continue;
			}
		}

		if ((sdp->sd_flags & FLG_SY_VISIBLE) == 0)
			ld_sym_adjust_vis(sdp, ofl);

		if ((sdp->sd_flags & FLG_SY_REDUCED) &&
		    (oflags & FLG_OF_PROCRED)) {
			DBG_CALL(Dbg_syms_reduce(ofl, DBG_SYM_REDUCE_GLOBAL,
			    sdp, 0, 0));
		}

		/*
		 * Record any STV_SINGLETON existence.
		 */
		if ((vis = ELF_ST_VISIBILITY(sym->st_other)) == STV_SINGLETON)
			ofl->ofl_dtflags_1 |= DF_1_SINGLETON;

		/*
		 * If building a shared object or executable, and this is a
		 * non-weak UNDEF symbol with reduced visibility (STV_*), then
		 * give a fatal error.
		 */
		if (((oflags & FLG_OF_RELOBJ) == 0) &&
		    (sym->st_shndx == SHN_UNDEF) &&
		    (ELF_ST_BIND(sym->st_info) != STB_WEAK)) {
			if (vis && (vis != STV_SINGLETON)) {
				sym_undef_entry(ofl, sdp, BNDLOCAL);
				ofl->ofl_flags |= FLG_OF_FATAL;
				continue;
			}
		}

		/*
		 * If this symbol is defined in a non-allocatable section,
		 * reduce it to local symbol.
		 */
		if (((isp = sdp->sd_isc) != 0) && isp->is_shdr &&
		    ((isp->is_shdr->sh_flags & SHF_ALLOC) == 0)) {
			sdp->sd_flags |= FLG_SY_REDUCED;
			sdp->sd_flags1 |= FLG_SY1_HIDDEN;
		}

		/*
		 * If this symbol originated as a SHN_SUNW_IGNORE, it will have
		 * been processed as an SHN_UNDEF.  Return the symbol to its
		 * original index for validation, and propagation to the output
		 * file.
		 */
		if (sdp->sd_flags1 & FLG_SY1_IGNORE)
			sdp->sd_shndx = SHN_SUNW_IGNORE;

		if (undef) {
			/*
			 * If a non-weak reference remains undefined, or if a
			 * mapfile reference is not bound to the relocatable
			 * objects that make up the object being built, we have
			 * a fatal error.
			 *
			 * The exceptions are symbols which are defined to be
			 * found in the parent (FLG_SY_PARENT), which is really
			 * only meaningful for direct binding, or are defined
			 * external (FLG_SY_EXTERN) so as to suppress -zdefs
			 * errors.
			 *
			 * Register symbols are always allowed to be UNDEF.
			 *
			 * Note that we don't include references created via -u
			 * in the same shared object binding test.  This is for
			 * backward compatibility, in that a number of archive
			 * makefile rules used -u to cause archive extraction.
			 * These same rules have been cut and pasted to apply
			 * to shared objects, and thus although the -u reference
			 * is redundant, flagging it as fatal could cause some
			 * build to fail.  Also we have documented the use of
			 * -u as a mechanism to cause binding to weak version
			 * definitions, thus giving users an error condition
			 * would be incorrect.
			 */
			if (!(sdp->sd_flags & FLG_SY_REGSYM) &&
			    ((sym->st_shndx == SHN_UNDEF) &&
			    ((ELF_ST_BIND(sym->st_info) != STB_WEAK) &&
			    ((sdp->sd_flags &
			    (FLG_SY_PARENT | FLG_SY_EXTERN)) == 0)) ||
			    (((sdp->sd_flags &
			    (FLG_SY_MAPREF | FLG_SY_MAPUSED)) ==
			    FLG_SY_MAPREF) &&
			    ((sdp->sd_flags1 & (FLG_SY1_HIDDEN |
			    FLG_SY1_PROTECT)) == 0)))) {
				sym_undef_entry(ofl, sdp, UNDEF);
				ofl->ofl_flags |= undef;
				undeferr = 1;
			}

		} else {
			/*
			 * For building things like shared objects (or anything
			 * -znodefs), undefined symbols are allowed.
			 *
			 * If a mapfile reference remains undefined the user
			 * would probably like a warning at least (they've
			 * usually mis-spelt the reference).  Refer to the above
			 * comments for discussion on -u references, which
			 * are not tested for in the same manner.
			 */
			if ((sdp->sd_flags &
			    (FLG_SY_MAPREF | FLG_SY_MAPUSED)) ==
			    FLG_SY_MAPREF) {
				sym_undef_entry(ofl, sdp, UNDEF);
				ofl->ofl_flags |= FLG_OF_WARN;
				undeferr = 1;
			}
		}

		/*
		 * If this symbol comes from a dependency mark the dependency
		 * as required (-z ignore can result in unused dependencies
		 * being dropped).  If we need to record dependency versioning
		 * information indicate what version of the needed shared object
		 * this symbol is part of.  Flag the symbol as undefined if it
		 * has not been made available to us.
		 */
		if ((sdp->sd_ref == REF_DYN_NEED) &&
		    (!(sdp->sd_flags & FLG_SY_REFRSD))) {
			sdp->sd_file->ifl_flags |= FLG_IF_DEPREQD;

			/*
			 * Capture that we've bound to a symbol that doesn't
			 * allow being directly bound to.
			 */
			if (sdp->sd_flags1 & FLG_SY1_NDIR)
				ofl->ofl_flags1 |= FLG_OF1_NDIRECT;

			if (sdp->sd_file->ifl_vercnt) {
				int		vndx;
				Ver_index	*vip;

				vndx = sdp->sd_aux->sa_dverndx;
				vip = &sdp->sd_file->ifl_verndx[vndx];
				if (vip->vi_flags & FLG_VER_AVAIL) {
					vip->vi_flags |= FLG_VER_REFER;
				} else {
					sym_undef_entry(ofl, sdp, NOTAVAIL);
					ofl->ofl_flags |= FLG_OF_FATAL;
					continue;
				}
			}
		}

		/*
		 * Test that we do not bind to symbol supplied from an implicit
		 * shared object.  If a binding is from a weak reference it can
		 * be ignored.
		 */
		if (needed && !undeferr && (sdp->sd_flags & FLG_SY_GLOBREF) &&
		    (sdp->sd_ref == REF_DYN_NEED) &&
		    (sdp->sd_flags & FLG_SY_NOTAVAIL)) {
			sym_undef_entry(ofl, sdp, IMPLICIT);
			ofl->ofl_flags |= needed;
			continue;
		}

		/*
		 * Test that a symbol isn't going to be reduced to local scope
		 * which actually wants to bind to a shared object - if so it's
		 * a fatal error.
		 */
		if ((sdp->sd_ref == REF_DYN_NEED) &&
		    (sdp->sd_flags1 & (FLG_SY1_HIDDEN | FLG_SY1_PROTECT))) {
			sym_undef_entry(ofl, sdp, BNDLOCAL);
			ofl->ofl_flags |= FLG_OF_FATAL;
			continue;
		}

		/*
		 * If the output image is to be versioned then all symbol
		 * definitions must be associated with a version.
		 */
		if (verdesc && (sdp->sd_ref == REF_REL_NEED) &&
		    (sym->st_shndx != SHN_UNDEF) &&
		    (!(sdp->sd_flags1 & FLG_SY1_HIDDEN)) &&
		    (sdp->sd_aux->sa_overndx == 0)) {
			sym_undef_entry(ofl, sdp, NOVERSION);
			ofl->ofl_flags |= verdesc;
			continue;
		}

		/*
		 * If we don't need the symbol there's no need to process it
		 * any further.
		 */
		if (sdp->sd_ref == REF_DYN_SEEN)
			continue;

		/*
		 * Calculate the size and alignment requirements for the global
		 * .bss and .tls sections.  If we're building a relocatable
		 * object only account for scoped COMMON symbols (these will
		 * be converted to .bss references).
		 *
		 * For partially initialized symbol,
		 *  if it is expanded, it goes to sunwdata1.
		 *  if it is local, it goes to .bss.
		 *  if the output is shared object, it goes to .sunwbss.
		 *
		 * Also refer to make_mvsections() in sunwmove.c
		 */
		if ((sym->st_shndx == SHN_COMMON) &&
		    (((oflags & FLG_OF_RELOBJ) == 0) ||
		    ((sdp->sd_flags1 & FLG_SY1_HIDDEN) &&
		    (oflags & FLG_OF_PROCRED)))) {
			int countbss = 0;

			if (sdp->sd_psyminfo == 0) {
				countbss = 1;
			} else if ((sdp->sd_flags & FLG_SY_PAREXPN) != 0) {
				countbss = 0;
			} else if (ELF_ST_BIND(sym->st_info) == STB_LOCAL) {
				countbss = 1;
			} else if ((ofl->ofl_flags & FLG_OF_SHAROBJ) != 0) {
				countbss = 0;
			} else
				countbss = 1;

			if (countbss) {
				Xword * size, * align;

				if (type != STT_TLS) {
					size = &bsssize;
					align = &bssalign;
				} else {
					size = &tlssize;
					align = &tlsalign;
				}
				*size = (Xword)S_ROUND(*size, sym->st_value) +
				    sym->st_size;
				if (sym->st_value > *align)
					*align = sym->st_value;
			}
		}

#if	defined(__x86) && defined(_ELF64)
		/*
		 * Calculate the size and alignment requirement for the global
		 * .lbss. TLS or partially initialized symbols do not need to be
		 * considered yet.
		 */
		if (sym->st_shndx == SHN_X86_64_LCOMMON) {
			lbsssize = (Xword)S_ROUND(lbsssize, sym->st_value) +
			    sym->st_size;
			if (sym->st_value > lbssalign)
				lbssalign = sym->st_value;
		}
#endif

		/*
		 * If a symbol was referenced via the command line
		 * (ld -u <>, ...), then this counts as a reference against the
		 * symbol. Mark any section that symbol is defined in.
		 */
		if (((isp = sdp->sd_isc) != 0) &&
		    (sdp->sd_flags & FLG_SY_CMDREF)) {
			isp->is_flags |= FLG_IS_SECTREF;
			isp->is_file->ifl_flags |= FLG_IF_FILEREF;
		}

		/*
		 * Update the symbol count and the associated name string size.
		 */
		if ((sdp->sd_flags1 & FLG_SY1_HIDDEN) &&
		    (oflags & FLG_OF_PROCRED)) {
			/*
			 * If any reductions are being processed, keep a count
			 * of eliminated symbols, and if the symbol is being
			 * reduced to local, count it's size for the .symtab.
			 */
			if (sdp->sd_flags1 & FLG_SY1_ELIM) {
				ofl->ofl_elimcnt++;
			} else {
				ofl->ofl_scopecnt++;
				if ((((sdp->sd_flags & FLG_SY_REGSYM) == 0) ||
				    sym->st_name) && (st_insert(ofl->ofl_strtab,
				    sdp->sd_name) == -1))
					return (S_ERROR);
				if (allow_ldynsym && sym->st_name &&
				    ldynsym_symtype[type]) {
					ofl->ofl_dynscopecnt++;
					if (st_insert(ofl->ofl_dynstrtab,
					    sdp->sd_name) == -1)
						return (S_ERROR);
					/* Include it in sort section? */
					DYNSORT_COUNT(sdp, sym, type, ++);
				}
			}
		} else {
			ofl->ofl_globcnt++;

			/*
			 * Check to see if this global variable should
			 * go into a sort section. Sort sections require
			 * a .SUNW_ldynsym section, so, don't check
			 * unless a .SUNW_ldynsym is allowed.
			 */
			if (allow_ldynsym) {
				DYNSORT_COUNT(sdp, sym, type, ++);
			}

			/*
			 * If global direct bindings are in effect, or this
			 * symbol has bound to a dependency which was specified
			 * as requiring direct bindings, and it hasn't
			 * explicitly been defined as a non-direct binding
			 * symbol, mark it.
			 */
			if (((ofl->ofl_dtflags_1 & DF_1_DIRECT) || (isp &&
			    (isp->is_file->ifl_flags & FLG_IF_DIRECT))) &&
			    ((sdp->sd_flags1 & FLG_SY1_NDIR) == 0))
				sdp->sd_flags1 |= FLG_SY1_DIR;

			/*
			 * Insert the symbol name.
			 */
			if (((sdp->sd_flags & FLG_SY_REGSYM) == 0) ||
			    sym->st_name) {
				if (st_insert(ofl->ofl_strtab,
				    sdp->sd_name) == -1)
					return (S_ERROR);

				if (!(ofl->ofl_flags & FLG_OF_RELOBJ) &&
				    (st_insert(ofl->ofl_dynstrtab,
				    sdp->sd_name) == -1))
					return (S_ERROR);
			}

			/*
			 * If this section offers a global symbol - record that
			 * fact.
			 */
			if (isp) {
				isp->is_flags |= FLG_IS_SECTREF;
				isp->is_file->ifl_flags |= FLG_IF_FILEREF;
			}
		}
	}

	/*
	 * If we've encountered a fatal error during symbol validation then
	 * return now.
	 */
	if (ofl->ofl_flags & FLG_OF_FATAL)
		return (1);

	/*
	 * Now that symbol resolution is completed, scan any register symbols.
	 * From now on, we're only interested in those that contribute to the
	 * output file.
	 */
	if (ofl->ofl_regsyms) {
		int	ndx;

		for (ndx = 0; ndx < ofl->ofl_regsymsno; ndx++) {
			if ((sdp = ofl->ofl_regsyms[ndx]) == 0)
				continue;
			if (sdp->sd_ref != REF_REL_NEED) {
				ofl->ofl_regsyms[ndx] = 0;
				continue;
			}

			ofl->ofl_regsymcnt++;
			if (sdp->sd_sym->st_name == 0)
				sdp->sd_name = MSG_ORIG(MSG_STR_EMPTY);

			if ((sdp->sd_flags1 & FLG_SY1_HIDDEN) ||
			    (ELF_ST_BIND(sdp->sd_sym->st_info) == STB_LOCAL))
				ofl->ofl_lregsymcnt++;
		}
	}

	/*
	 * Generate the .bss section now that we know its size and alignment.
	 */
	if (bsssize || !(oflags & FLG_OF_RELOBJ)) {
		if (ld_make_bss(ofl, bsssize, bssalign, MAKE_BSS) == S_ERROR)
			return (S_ERROR);
	}
	if (tlssize) {
		if (ld_make_bss(ofl, tlssize, tlsalign, MAKE_TLS) == S_ERROR)
			return (S_ERROR);
	}
#if	defined(__x86) && defined(_ELF64)
	if (lbsssize && !(oflags & FLG_OF_RELOBJ)) {
		if (ld_make_bss(ofl, lbsssize, lbssalign, MAKE_LBSS) == S_ERROR)
			return (S_ERROR);
	}
#endif

	/*
	 * Determine what entry point symbol we need, and if found save its
	 * symbol descriptor so that we can update the ELF header entry with the
	 * symbols value later (see update_oehdr).  Make sure the symbol is
	 * tagged to ensure its update in case -s is in effect.  Use any -e
	 * option first, or the default entry points `_start' and `main'.
	 */
	ret = 0;
	if (ofl->ofl_entry) {
		if ((sdp =
		    ld_sym_find(ofl->ofl_entry, SYM_NOHASH, 0, ofl)) == NULL) {
			eprintf(ofl->ofl_lml, ERR_FATAL,
			    MSG_INTL(MSG_ARG_NOENTRY), ofl->ofl_entry);
			ret++;
		} else if (ensure_sym_local(ofl, sdp,
		    MSG_INTL(MSG_SYM_ENTRY)) != 0) {
			ret++;
		} else {
			ofl->ofl_entry = (void *)sdp;
		}
	} else if (((sdp = ld_sym_find(MSG_ORIG(MSG_SYM_START),
	    SYM_NOHASH, 0, ofl)) != NULL) && (ensure_sym_local(ofl,
	    sdp, 0) == 0)) {
		ofl->ofl_entry = (void *)sdp;

	} else if (((sdp = ld_sym_find(MSG_ORIG(MSG_SYM_MAIN),
	    SYM_NOHASH, 0, ofl)) != NULL) && (ensure_sym_local(ofl,
	    sdp, 0) == 0)) {
		ofl->ofl_entry = (void *)sdp;
	}

	/*
	 * If ld -zdtrace=<sym> was given, then validate that the symbol is
	 * defined within the current object being built.
	 */
	if ((sdp = ofl->ofl_dtracesym) != 0)
		ret += ensure_sym_local(ofl, sdp, MSG_ORIG(MSG_STR_DTRACE));

	/*
	 * If any initarray, finiarray or preinitarray functions have been
	 * requested, make sure they are defined within the current object
	 * being built.
	 */
	if (ofl->ofl_initarray.head) {
		ret += ensure_array_local(ofl, &ofl->ofl_initarray,
		    MSG_ORIG(MSG_SYM_INITARRAY));
	}
	if (ofl->ofl_finiarray.head) {
		ret += ensure_array_local(ofl, &ofl->ofl_finiarray,
		    MSG_ORIG(MSG_SYM_FINIARRAY));
	}
	if (ofl->ofl_preiarray.head) {
		ret += ensure_array_local(ofl, &ofl->ofl_preiarray,
		    MSG_ORIG(MSG_SYM_PREINITARRAY));
	}

	if (ret)
		return (S_ERROR);

	/*
	 * If we're required to record any needed dependencies versioning
	 * information calculate it now that all symbols have been validated.
	 */
	if ((oflags & (FLG_OF_VERNEED | FLG_OF_NOVERSEC)) == FLG_OF_VERNEED)
		return (ld_vers_check_need(ofl));
	else
		return (1);
}

/*
 * qsort(3c) comparison function.  As an optimization for associating weak
 * symbols to their strong counterparts sort global symbols according to their
 * address and binding.
 */
static int
compare(const void * sdpp1, const void * sdpp2)
{
	Sym_desc *	sdp1 = *((Sym_desc **)sdpp1);
	Sym_desc *	sdp2 = *((Sym_desc **)sdpp2);
	Sym *		sym1, * sym2;
	uchar_t		bind1, bind2;

	/*
	 * Symbol descriptors may be zero, move these to the front of the
	 * sorted array.
	 */
	if (sdp1 == 0)
		return (-1);
	if (sdp2 == 0)
		return (1);

	sym1 = sdp1->sd_sym;
	sym2 = sdp2->sd_sym;

	/*
	 * Compare the symbols value (address).
	 */
	if (sym1->st_value > sym2->st_value)
		return (1);
	if (sym1->st_value < sym2->st_value)
		return (-1);

	bind1 = ELF_ST_BIND(sym1->st_info);
	bind2 = ELF_ST_BIND(sym2->st_info);

	/*
	 * If two symbols have the same address place the weak symbol before
	 * any strong counterpart.
	 */
	if (bind1 > bind2)
		return (-1);
	if (bind1 < bind2)
		return (1);

	return (0);
}


/*
 * Issue a MSG_SYM_BADADDR error from ld_sym_process(). This error
 * is issued when a symbol address/size is not contained by the
 * target section.
 *
 * Such objects are at least partially corrupt, and the user would
 * be well advised to be skeptical of them, and to ask their compiler
 * supplier to fix the problem. However, a distinction needs to be
 * made between symbols that reference readonly text, and those that
 * access writable data. Other than throwing off profiling results,
 * the readonly section case is less serious. We have encountered
 * such objects in the field. In order to allow existing objects
 * to continue working, we issue a warning rather than a fatal error
 * if the symbol is against readonly text. Other cases are fatal.
 */
static void
issue_badaddr_msg(Ifl_desc *ifl, Ofl_desc *ofl, Sym_desc *sdp,
    Sym *sym, Word shndx)
{
	Lword	flag;
	Error	err;
	const char *msg;

	if ((sdp->sd_isc->is_shdr->sh_flags & (SHF_WRITE | SHF_ALLOC)) ==
	    SHF_ALLOC) {
		msg = MSG_INTL(MSG_SYM_BADADDR_ROTXT);
		flag = FLG_OF_WARN;
		err = ERR_WARNING;
	} else {
		msg = MSG_INTL(MSG_SYM_BADADDR);
		flag = FLG_OF_FATAL;
		err = ERR_FATAL;
	}

	eprintf(ofl->ofl_lml, err, msg, demangle(sdp->sd_name),
	    ifl->ifl_name, shndx, sdp->sd_isc->is_name,
	    EC_XWORD(sdp->sd_isc->is_shdr->sh_size),
	    EC_XWORD(sym->st_value), EC_XWORD(sym->st_size));
	ofl->ofl_flags |= flag;
}


/*
 * Process the symbol table for the specified input file.  At this point all
 * input sections from this input file have been assigned an input section
 * descriptor which is saved in the `ifl_isdesc' array.
 *
 *	o	local symbols are saved (as is) if the input file is a
 *		relocatable object
 *
 *	o	global symbols are added to the linkers internal symbol
 *		table if they are not already present, otherwise a symbol
 *		resolution function is called upon to resolve the conflict.
 */
uintptr_t
ld_sym_process(Is_desc *isc, Ifl_desc *ifl, Ofl_desc *ofl)
{
	/*
	 * This macro tests the given symbol to see if it is out of
	 * range relative to the section it references.
	 *
	 * entry:
	 *	- ifl is a relative object (ET_REL)
	 *	_sdp - Symbol descriptor
	 *	_sym - Symbol
	 *	_type - Symbol type
	 *
	 * The following are tested:
	 *	- Symbol length is non-zero
	 *	- Symbol type is a type that references code or data
	 *	- Referenced section is not 0 (indicates an UNDEF symbol)
	 *	  and is not in the range of special values above SHN_LORESERVE
	 *	  (excluding SHN_XINDEX, which is OK).
	 *	- We have a valid section header for the target section
	 *
	 * If the above are all true, and the symbol position is not
	 * contained by the target section, this macro evaluates to
	 * True (1). Otherwise, False(0).
	 */
#define	SYM_LOC_BADADDR(_sdp, _sym, _type) \
	(_sym->st_size && dynsymsort_symtype[_type] && \
	(_sym->st_shndx != SHN_UNDEF) && \
	((_sym->st_shndx < SHN_LORESERVE) || \
		(_sym->st_shndx == SHN_XINDEX)) && \
	_sdp->sd_isc && _sdp->sd_isc->is_shdr && \
	((_sym->st_value + _sym->st_size) > _sdp->sd_isc->is_shdr->sh_size))

	Conv_inv_buf_t	inv_buf;
	Sym		*sym = (Sym *)isc->is_indata->d_buf;
	Word		*symshndx = 0;
	Shdr		*shdr = isc->is_shdr;
	Sym_desc	*sdp;
	size_t		strsize;
	char		*strs;
	uchar_t		type, bind;
	Word		ndx, hash, local, total;
	Half		etype = ifl->ifl_ehdr->e_type;
	int		etype_rel;
	const char	*symsecname, *strsecname;
	avl_index_t	where;
	int		test_gnu_hidden_bit;

	/*
	 * Its possible that a file may contain more that one symbol table,
	 * ie. .dynsym and .symtab in a shared library.  Only process the first
	 * table (here, we assume .dynsym comes before .symtab).
	 */
	if (ifl->ifl_symscnt)
		return (1);

	if (isc->is_symshndx)
		symshndx = isc->is_symshndx->is_indata->d_buf;

	DBG_CALL(Dbg_syms_process(ofl->ofl_lml, ifl));

	if (isc->is_name)
		symsecname = isc->is_name;
	else
		symsecname = MSG_ORIG(MSG_STR_EMPTY);

	/*
	 * From the symbol tables section header information determine which
	 * strtab table is needed to locate the actual symbol names.
	 */
	if (ifl->ifl_flags & FLG_IF_HSTRTAB) {
		ndx = shdr->sh_link;
		if ((ndx == 0) || (ndx >= ifl->ifl_shnum)) {
			eprintf(ofl->ofl_lml, ERR_FATAL,
			    MSG_INTL(MSG_FIL_INVSHLINK),
			    ifl->ifl_name, symsecname, EC_XWORD(ndx));
			return (S_ERROR);
		}
		strsize = ifl->ifl_isdesc[ndx]->is_shdr->sh_size;
		strs = ifl->ifl_isdesc[ndx]->is_indata->d_buf;
		if (ifl->ifl_isdesc[ndx]->is_name)
			strsecname = ifl->ifl_isdesc[ndx]->is_name;
		else
			strsecname = MSG_ORIG(MSG_STR_EMPTY);
	} else {
		/*
		 * There is no string table section in this input file
		 * although there are symbols in this symbol table section.
		 * This means that these symbols do not have names.
		 * Currently, only scratch register symbols are allowed
		 * not to have names.
		 */
		strsize = 0;
		strs = (char *)MSG_ORIG(MSG_STR_EMPTY);
		strsecname = MSG_ORIG(MSG_STR_EMPTY);
	}

	/*
	 * Determine the number of local symbols together with the total
	 * number we have to process.
	 */
	total = (Word)(shdr->sh_size / shdr->sh_entsize);
	local = shdr->sh_info;

	/*
	 * Allocate a symbol table index array and a local symbol array
	 * (global symbols are processed and added to the ofl->ofl_symbkt[]
	 * array).  If we are dealing with a relocatable object, allocate the
	 * local symbol descriptors.  If this isn't a relocatable object we
	 * still have to process any shared object locals to determine if any
	 * register symbols exist.  Although these aren't added to the output
	 * image, they are used as part of symbol resolution.
	 */
	if ((ifl->ifl_oldndx = libld_malloc((size_t)(total *
	    sizeof (Sym_desc *)))) == 0)
		return (S_ERROR);
	etype_rel = (etype == ET_REL);
	if (etype_rel && local) {
		if ((ifl->ifl_locs =
		    libld_calloc(sizeof (Sym_desc), local)) == 0)
			return (S_ERROR);
		/* LINTED */
		ifl->ifl_locscnt = (Word)local;
	}
	ifl->ifl_symscnt = total;

	/*
	 * If there are local symbols to save add them to the symbol table
	 * index array.
	 */
	if (local) {
		int allow_ldynsym = OFL_ALLOW_LDYNSYM(ofl);
		for (sym++, ndx = 1; ndx < local; sym++, ndx++) {
			Word		shndx, sdflags = FLG_SY_CLEAN;
			const char	*name;
			Sym_desc	*rsdp;

			/*
			 * Determine the associated section index.
			 */
			if (symshndx && (sym->st_shndx == SHN_XINDEX))
				shndx = symshndx[ndx];
			else if ((shndx = sym->st_shndx) >= SHN_LORESERVE)
				sdflags |= FLG_SY_SPECSEC;

			/*
			 * Check if st_name has a valid value or not.
			 */
			if ((name = string(ofl, ifl, sym, strs, strsize, ndx,
			    shndx, symsecname, strsecname, &sdflags)) == 0) {
				ofl->ofl_flags |= FLG_OF_FATAL;
				continue;
			}

			/*
			 * If this local symbol table originates from a shared
			 * object, then we're only interested in recording
			 * register symbols.  As local symbol descriptors aren't
			 * allocated for shared objects, one will be allocated
			 * to associated with the register symbol.  This symbol
			 * won't become part of the output image, but we must
			 * process it to test for register conflicts.
			 */
			rsdp = sdp = 0;
			if (sdflags & FLG_SY_REGSYM) {
				if ((rsdp = ld_reg_find(sym, ofl)) != 0) {
					/*
					 * The fact that another register def-
					 * inition has been found is fatal.
					 * Call the verification routine to get
					 * the error message and move on.
					 */
					(void) ld_reg_check(rsdp, sym, name,
					    ifl, ofl);
					continue;
				}

				if (etype == ET_DYN) {
					if ((sdp = libld_calloc(
					    sizeof (Sym_desc), 1)) == 0)
						return (S_ERROR);
					sdp->sd_ref = REF_DYN_SEEN;
				}
			} else if (etype == ET_DYN)
				continue;

			/*
			 * Fill in the remaining symbol descriptor information.
			 */
			if (sdp == 0) {
				sdp = &(ifl->ifl_locs[ndx]);
				sdp->sd_ref = REF_REL_NEED;
			}
			if (rsdp == 0) {
				sdp->sd_name = name;
				sdp->sd_sym = sym;
				sdp->sd_shndx = shndx;
				sdp->sd_flags = sdflags;
				sdp->sd_file = ifl;
				ifl->ifl_oldndx[ndx] = sdp;
			}

			DBG_CALL(Dbg_syms_entry(ofl->ofl_lml, ndx, sdp));

			/*
			 * Reclassify any SHN_SUNW_IGNORE symbols to SHN_UNDEF
			 * so as to simplify future processing.
			 */
			if (sym->st_shndx == SHN_SUNW_IGNORE) {
				sdp->sd_shndx = shndx = SHN_UNDEF;
				sdp->sd_flags1 |=
				    (FLG_SY1_IGNORE | FLG_SY1_ELIM);
			}

			/*
			 * Process any register symbols.
			 */
			if (sdp->sd_flags & FLG_SY_REGSYM) {
				/*
				 * Add a diagnostic to indicate we've caught a
				 * register symbol, as this can be useful if a
				 * register conflict is later discovered.
				 */
				DBG_CALL(Dbg_syms_entered(ofl, sym, sdp));

				/*
				 * If this register symbol hasn't already been
				 * recorded, enter it now.
				 */
				if ((rsdp == 0) &&
				    (ld_reg_enter(sdp, ofl) == 0))
					return (S_ERROR);
			}

			/*
			 * Assign an input section.
			 */
			if ((sym->st_shndx != SHN_UNDEF) &&
			    ((sdp->sd_flags & FLG_SY_SPECSEC) == 0))
				sdp->sd_isc = ifl->ifl_isdesc[shndx];

			/*
			 * If this symbol falls within the range of a section
			 * being discarded, then discard the symbol itself.
			 * There is no reason to keep this local symbol.
			 */
			if (sdp->sd_isc &&
			    (sdp->sd_isc->is_flags & FLG_IS_DISCARD)) {
				sdp->sd_flags |= FLG_SY_ISDISC;
				DBG_CALL(Dbg_syms_discarded(ofl->ofl_lml, sdp));
				continue;
			}

			/*
			 * Skip any section symbols as new versions of these
			 * will be created.
			 */
			if ((type = ELF_ST_TYPE(sym->st_info)) == STT_SECTION) {
				if (sym->st_shndx == SHN_UNDEF) {
					eprintf(ofl->ofl_lml, ERR_WARNING,
					    MSG_INTL(MSG_SYM_INVSHNDX),
					    demangle(sdp->sd_name),
					    ifl->ifl_name,
					    conv_sym_shndx(sym->st_shndx,
					    &inv_buf));
				}
				continue;
			}

			/*
			 * For a relocatable object, if this symbol is defined
			 * and has non-zero length and references an address
			 * within an associated section, then check its extents
			 * to make sure the section boundaries encompass it.
			 * If they don't, the ELF file is corrupt.
			 */
			if (etype_rel && SYM_LOC_BADADDR(sdp, sym, type)) {
				issue_badaddr_msg(ifl, ofl, sdp, sym, shndx);
				continue;
			}

			/*
			 * Sanity check for TLS
			 */
			if ((sym->st_size != 0) && ((type == STT_TLS) &&
			    (sym->st_shndx != SHN_COMMON))) {
				Is_desc	*isp = sdp->sd_isc;

				if ((isp == 0) || (isp->is_shdr == 0) ||
				    ((isp->is_shdr->sh_flags & SHF_TLS) == 0)) {
					eprintf(ofl->ofl_lml, ERR_FATAL,
					    MSG_INTL(MSG_SYM_TLS),
					    demangle(sdp->sd_name),
					    ifl->ifl_name);
					ofl->ofl_flags |= FLG_OF_FATAL;
					continue;
				}
			}

			/*
			 * Carry our some basic sanity checks (these are just
			 * some of the erroneous symbol entries we've come
			 * across, there's probably a lot more).  The symbol
			 * will not be carried forward to the output file, which
			 * won't be a problem unless a relocation is required
			 * against it.
			 */
			if (((sdp->sd_flags & FLG_SY_SPECSEC) &&
			    ((sym->st_shndx == SHN_COMMON)) ||
			    ((type == STT_FILE) &&
			    (sym->st_shndx != SHN_ABS))) ||
			    (sdp->sd_isc && (sdp->sd_isc->is_osdesc == 0))) {
				eprintf(ofl->ofl_lml, ERR_WARNING,
				    MSG_INTL(MSG_SYM_INVSHNDX),
				    demangle(sdp->sd_name), ifl->ifl_name,
				    conv_sym_shndx(sym->st_shndx, &inv_buf));
				sdp->sd_isc = NULL;
				sdp->sd_flags |= FLG_SY_INVALID;
				continue;
			}

			/*
			 * As these local symbols will become part of the output
			 * image, record their number and name string size.
			 * Globals are counted after all input file processing
			 * (and hence symbol resolution) is complete during
			 * sym_validate().
			 */
			if (!(ofl->ofl_flags1 & FLG_OF1_REDLSYM)) {
				ofl->ofl_locscnt++;

				if ((((sdp->sd_flags & FLG_SY_REGSYM) == 0) ||
				    sym->st_name) && (st_insert(ofl->ofl_strtab,
				    sdp->sd_name) == -1))
					return (S_ERROR);

				if (allow_ldynsym && sym->st_name &&
				    ldynsym_symtype[type]) {
					ofl->ofl_dynlocscnt++;
					if (st_insert(ofl->ofl_dynstrtab,
					    sdp->sd_name) == -1)
						return (S_ERROR);
					/* Include it in sort section? */
					DYNSORT_COUNT(sdp, sym, type, ++);
				}
			}
		}
	}

	/*
	 * The GNU ld interprets the top bit of the 16-bit Versym value
	 * (0x8000) as the "hidden" bit. If this bit is set, the linker
	 * is supposed to act as if that symbol does not exist. The Solaris
	 * linker does not support this mechanism, or the model of interface
	 * evolution that it allows, but we honor it in GNU ld produced
	 * objects in order to interoperate with them.
	 *
	 * Determine if we should honor the GNU hidden bit for this file.
	 */
	test_gnu_hidden_bit = ((ifl->ifl_flags & FLG_IF_GNUVER) != 0) &&
	    (ifl->ifl_versym != NULL);

	/*
	 * Now scan the global symbols entering them in the internal symbol
	 * table or resolving them as necessary.
	 */
	sym = (Sym *)isc->is_indata->d_buf;
	sym += local;
	/* LINTED */
	for (ndx = (int)local; ndx < total; sym++, ndx++) {
		const char	*name;
		Word		shndx, sdflags = 0;

		/*
		 * Determine the associated section index.
		 */
		if (symshndx && (sym->st_shndx == SHN_XINDEX)) {
			shndx = symshndx[ndx];
		} else {
			shndx = sym->st_shndx;
			if (sym->st_shndx >= SHN_LORESERVE)
				sdflags |= FLG_SY_SPECSEC;
		}

		/*
		 * Check if st_name has a valid value or not.
		 */
		if ((name = string(ofl, ifl, sym, strs, strsize, ndx, shndx,
		    symsecname, strsecname, &sdflags)) == 0) {
			ofl->ofl_flags |= FLG_OF_FATAL;
			continue;
		}

		/*
		 * Test for the GNU hidden bit, and ignore symbols that
		 * have it set.
		 */
		if (test_gnu_hidden_bit &&
		    ((ifl->ifl_versym[ndx] & 0x8000) != 0))
			continue;

		/*
		 * The linker itself will generate symbols for _end, _etext,
		 * _edata, _DYNAMIC and _PROCEDURE_LINKAGE_TABLE_, so don't
		 * bother entering these symbols from shared objects.  This
		 * results in some wasted resolution processing, which is hard
		 * to feel, but if nothing else, pollutes diagnostic relocation
		 * output.
		 */
		if (name[0] && (etype == ET_DYN) && (sym->st_size == 0) &&
		    (ELF_ST_TYPE(sym->st_info) == STT_OBJECT) &&
		    (name[0] == '_') && ((name[1] == 'e') ||
		    (name[1] == 'D') || (name[1] == 'P')) &&
		    ((strcmp(name, MSG_ORIG(MSG_SYM_ETEXT_U)) == 0) ||
		    (strcmp(name, MSG_ORIG(MSG_SYM_EDATA_U)) == 0) ||
		    (strcmp(name, MSG_ORIG(MSG_SYM_END_U)) == 0) ||
		    (strcmp(name, MSG_ORIG(MSG_SYM_DYNAMIC_U)) == 0) ||
		    (strcmp(name, MSG_ORIG(MSG_SYM_PLKTBL_U)) == 0))) {
			ifl->ifl_oldndx[ndx] = 0;
			continue;
		}

		/*
		 * Determine and validate the symbols binding.
		 */
		bind = ELF_ST_BIND(sym->st_info);
		if ((bind != STB_GLOBAL) && (bind != STB_WEAK)) {
			eprintf(ofl->ofl_lml, ERR_WARNING,
			    MSG_INTL(MSG_SYM_NONGLOB), demangle(name),
			    ifl->ifl_name,
			    conv_sym_info_bind(bind, 0, &inv_buf));
			continue;
		}

		/*
		 * If this symbol falls within the range of a section being
		 * discarded, then discard the symbol itself.
		 */
		if (((sdflags & FLG_SY_SPECSEC) == 0) &&
		    (sym->st_shndx != SHN_UNDEF)) {
			Is_desc	*isp;

			if (shndx >= ifl->ifl_shnum) {
				/*
				 * Carry our some basic sanity checks
				 * The symbol will not be carried forward to
				 * the output file, which won't be a problem
				 * unless a relocation is required against it.
				 */
				eprintf(ofl->ofl_lml, ERR_WARNING,
				    MSG_INTL(MSG_SYM_INVSHNDX), demangle(name),
				    ifl->ifl_name,
				    conv_sym_shndx(sym->st_shndx, &inv_buf));
				continue;
			}

			isp = ifl->ifl_isdesc[shndx];
			if (isp && (isp->is_flags & FLG_IS_DISCARD)) {
				if ((sdp =
				    libld_calloc(sizeof (Sym_desc), 1)) == 0)
					return (S_ERROR);

				/*
				 * Create a dummy symbol entry so that if we
				 * find any references to this discarded symbol
				 * we can compensate.
				 */
				sdp->sd_name = name;
				sdp->sd_sym = sym;
				sdp->sd_file = ifl;
				sdp->sd_isc = isp;
				sdp->sd_flags = FLG_SY_ISDISC;
				ifl->ifl_oldndx[ndx] = sdp;

				DBG_CALL(Dbg_syms_discarded(ofl->ofl_lml, sdp));
				continue;
			}
		}

		/*
		 * If the symbol does not already exist in the internal symbol
		 * table add it, otherwise resolve the conflict.  If the symbol
		 * from this file is kept, retain its symbol table index for
		 * possible use in associating a global alias.
		 */
		/* LINTED */
		hash = (Word)elf_hash((const char *)name);
		if ((sdp = ld_sym_find(name, hash, &where, ofl)) == NULL) {
			DBG_CALL(Dbg_syms_global(ofl->ofl_lml, ndx, name));
			if ((sdp = ld_sym_enter(name, sym, hash, ifl, ofl, ndx,
			    shndx, sdflags, 0, &where)) == (Sym_desc *)S_ERROR)
				return (S_ERROR);

		} else if (ld_sym_resolve(sdp, sym, ifl, ofl, ndx, shndx,
		    sdflags) == S_ERROR)
			return (S_ERROR);

		/*
		 * After we've compared a defined symbol in one shared
		 * object, flag the symbol so we don't compare it again.
		 */
		if ((etype == ET_DYN) && (sym->st_shndx != SHN_UNDEF) &&
		    ((sdp->sd_flags & FLG_SY_SOFOUND) == 0))
			sdp->sd_flags |= FLG_SY_SOFOUND;

		/*
		 * If the symbol is accepted from this file retain the symbol
		 * index for possible use in aliasing.
		 */
		if (sdp->sd_file == ifl)
			sdp->sd_symndx = ndx;

		ifl->ifl_oldndx[ndx] = sdp;

		/*
		 * If we've accepted a register symbol, continue to validate
		 * it.
		 */
		if (sdp->sd_flags & FLG_SY_REGSYM) {
			Sym_desc	*rsdp;

			if ((rsdp = ld_reg_find(sdp->sd_sym, ofl)) == 0) {
				if (ld_reg_enter(sdp, ofl) == 0)
					return (S_ERROR);
			} else if (rsdp != sdp) {
				(void) ld_reg_check(rsdp, sdp->sd_sym,
				    sdp->sd_name, ifl, ofl);
			}
		}

		/*
		 * For a relocatable object, if this symbol is defined
		 * and has non-zero length and references an address
		 * within an associated section, then check its extents
		 * to make sure the section boundaries encompass it.
		 * If they don't, the ELF file is corrupt. Note that this
		 * global symbol may have come from another file to satisfy
		 * an UNDEF symbol of the same name from this one. In that
		 * case, we don't check it, because it was already checked
		 * as part of its own file.
		 */
		if (etype_rel && (sdp->sd_file == ifl)) {
			Sym *tsym = sdp->sd_sym;

			if (SYM_LOC_BADADDR(sdp, tsym,
			    ELF_ST_TYPE(tsym->st_info))) {
				issue_badaddr_msg(ifl, ofl, sdp,
				    tsym, tsym->st_shndx);
				continue;
			}
		}
	}

	/*
	 * If this is a shared object scan the globals one more time and
	 * associate any weak/global associations.  This association is needed
	 * should the weak definition satisfy a reference in the dynamic
	 * executable:
	 *
	 *  o	if the symbol is a data item it will be copied to the
	 *	executables address space, thus we must also reassociate the
	 *	alias symbol with its new location in the executable.
	 *
	 *  o	if the symbol is a function then we may need to promote	the
	 *	symbols binding from undefined weak to undefined, otherwise the
	 *	run-time linker will not generate the correct relocation error
	 *	should the symbol not be found.
	 *
	 * The true association between a weak/strong symbol pair is that both
	 * symbol entries are identical, thus first we created a sorted symbol
	 * list keyed off of the symbols value (if the value is the same chances
	 * are the rest of the symbols data is).  This list is then scanned for
	 * weak symbols, and if one is found then any strong association will
	 * exist in the following entries.  Thus we just have to scan one
	 * (typical single alias) or more (in the uncommon instance of multiple
	 * weak to strong associations) entries to determine if a match exists.
	 */
	if ((OFL_ALLOW_LDYNSYM(ofl) || (etype == ET_DYN)) &&
	    (total > local)) {
		Sym_desc **	sort;
		size_t		size = (total - local) * sizeof (Sym_desc *);

		if ((sort = libld_malloc(size)) == 0)
			return (S_ERROR);
		(void) memcpy((void *)sort, &ifl->ifl_oldndx[local], size);

		qsort(sort, (total - local), sizeof (Sym_desc *), compare);

		for (ndx = 0; ndx < (total - local); ndx++) {
			Sym_desc *	wsdp = sort[ndx];
			Sym *		wsym;
			int		sndx;

			if (wsdp == 0)
				continue;

			wsym = wsdp->sd_sym;

			if ((ELF_ST_BIND(wsym->st_info) != STB_WEAK) ||
			    (wsdp->sd_sym->st_shndx == SHN_UNDEF) ||
			    (wsdp->sd_flags & FLG_SY_SPECSEC))
				continue;

			/*
			 * We have a weak symbol, if it has a strong alias it
			 * will have been sorted to one of the following sort
			 * table entries.  Note that we could have multiple weak
			 * symbols aliased to one strong (if this occurs then
			 * the strong symbol only maintains one alias back to
			 * the last weak).
			 */
			for (sndx = ndx + 1; sndx < (total - local); sndx++) {
				Sym_desc *	ssdp = sort[sndx];
				Sym *		ssym;

				if (ssdp == 0)
					break;

				ssym = ssdp->sd_sym;

				if (wsym->st_value != ssym->st_value)
					break;

				if ((ssdp->sd_file == ifl) &&
				    (wsdp->sd_file == ifl) &&
				    (wsym->st_size == ssym->st_size) &&
				    (ssdp->sd_sym->st_shndx != SHN_UNDEF) &&
				    (ELF_ST_BIND(ssym->st_info) != STB_WEAK) &&
				    ((ssdp->sd_flags & FLG_SY_SPECSEC) == 0)) {
					int w_dynbits, s_dynbits;

					/*
					 * If a sharable object, set link
					 * fields so they reference each other
					 */
					if (etype == ET_DYN) {
						ssdp->sd_aux->sa_linkndx =
						    (Word)wsdp->sd_symndx;
						wsdp->sd_aux->sa_linkndx =
						    (Word)ssdp->sd_symndx;
					}
					/*
					 * Determine which of these two symbols
					 * go into the sort section. If the
					 * mapfile has made explicit settings
					 * of the FLG_SY_*DYNSORT flags for both
					 * symbols, then we do what they say.
					 * If one has the DYNSORT flags set,
					 * we set the NODYNSORT bit in the
					 * other. And if neither has an
					 * explicit setting, then we favor the
					 * weak symbol because they usually
					 * lack the leading underscore.
					 */
					w_dynbits = wsdp->sd_flags &
					    (FLG_SY_DYNSORT | FLG_SY_NODYNSORT);
					s_dynbits = ssdp->sd_flags &
					    (FLG_SY_DYNSORT | FLG_SY_NODYNSORT);
					if (!(w_dynbits && s_dynbits)) {
						if (s_dynbits) {
							if (s_dynbits ==
							    FLG_SY_DYNSORT)
							wsdp->sd_flags |=
							    FLG_SY_NODYNSORT;
						} else if (w_dynbits !=
						    FLG_SY_NODYNSORT) {
							ssdp->sd_flags |=
							    FLG_SY_NODYNSORT;
						}
					}
					break;
				}
			}
		}
	}
	return (1);

#undef SYM_LOC_BADADDR
}

/*
 * Add an undefined symbol to the symbol table.  The reference originates from
 * the location identifed by the message id (mid).  These references can
 * originate from command line options such as -e, -u, -initarray, etc.
 * (identified with MSG_INTL(MSG_STR_COMMAND)), or from internally generated
 * TLS relocation references (identified with MSG_INTL(MSG_STR_TLSREL)).
 */
Sym_desc *
ld_sym_add_u(const char *name, Ofl_desc *ofl, Msg mid)
{
	Sym		*sym;
	Ifl_desc	*ifl = 0, *_ifl;
	Sym_desc	*sdp;
	Word		hash;
	Listnode	*lnp;
	avl_index_t	where;
	const char	*reference = MSG_INTL(mid);

	/*
	 * As an optimization, determine whether we've already generated this
	 * reference.  If the symbol doesn't already exist we'll create it.
	 * Or if the symbol does exist from a different source, we'll resolve
	 * the conflict.
	 */
	/* LINTED */
	hash = (Word)elf_hash(name);
	if ((sdp = ld_sym_find(name, hash, &where, ofl)) != NULL) {
		if ((sdp->sd_sym->st_shndx == SHN_UNDEF) &&
		    (sdp->sd_file->ifl_name == reference))
			return (sdp);
	}

	/*
	 * Determine whether a pseudo input file descriptor exists to represent
	 * the command line, as any global symbol needs an input file descriptor
	 * during any symbol resolution (refer to map_ifl() which provides a
	 * similar method for adding symbols from mapfiles).
	 */
	for (LIST_TRAVERSE(&ofl->ofl_objs, lnp, _ifl))
		if (strcmp(_ifl->ifl_name, reference) == 0) {
			ifl = _ifl;
			break;
		}

	/*
	 * If no descriptor exists create one.
	 */
	if (ifl == 0) {
		if ((ifl = libld_calloc(sizeof (Ifl_desc), 1)) ==
		    (Ifl_desc *)0)
			return ((Sym_desc *)S_ERROR);
		ifl->ifl_name = reference;
		ifl->ifl_flags = FLG_IF_NEEDED | FLG_IF_FILEREF;
		if ((ifl->ifl_ehdr = libld_calloc(sizeof (Ehdr),
		    1)) == 0)
			return ((Sym_desc *)S_ERROR);
		ifl->ifl_ehdr->e_type = ET_REL;

		if (list_appendc(&ofl->ofl_objs, ifl) == 0)
			return ((Sym_desc *)S_ERROR);
	}

	/*
	 * Allocate a symbol structure and add it to the global symbol table.
	 */
	if ((sym = libld_calloc(sizeof (Sym), 1)) == 0)
		return ((Sym_desc *)S_ERROR);
	sym->st_info = ELF_ST_INFO(STB_GLOBAL, STT_NOTYPE);
	sym->st_shndx = SHN_UNDEF;

	DBG_CALL(Dbg_syms_process(ofl->ofl_lml, ifl));
	if (sdp == NULL) {
		DBG_CALL(Dbg_syms_global(ofl->ofl_lml, 0, name));
		if ((sdp = ld_sym_enter(name, sym, hash, ifl, ofl, 0, SHN_UNDEF,
		    0, 0, &where)) == (Sym_desc *)S_ERROR)
			return ((Sym_desc *)S_ERROR);
	} else if (ld_sym_resolve(sdp, sym, ifl, ofl, 0,
	    SHN_UNDEF, 0) == S_ERROR)
		return ((Sym_desc *)S_ERROR);

	sdp->sd_flags &= ~FLG_SY_CLEAN;
	sdp->sd_flags |= FLG_SY_CMDREF;

	return (sdp);
}
