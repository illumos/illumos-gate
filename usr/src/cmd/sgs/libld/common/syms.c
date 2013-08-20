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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Symbol table management routines
 */

#define	ELF_TARGET_AMD64

#include	<stdio.h>
#include	<string.h>
#include	<debug.h>
#include	"msg.h"
#include	"_libld.h"

/*
 * AVL tree comparator function:
 *
 * The primary key is the symbol name hash with a secondary key of the symbol
 * name itself.
 */
int
ld_sym_avl_comp(const void *elem1, const void *elem2)
{
	Sym_avlnode	*sav1 = (Sym_avlnode *)elem1;
	Sym_avlnode	*sav2 = (Sym_avlnode *)elem2;
	int		res;

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
    int symndx, Word shndx, Word symsecndx, const char *symsecname,
    const char *strsecname, sd_flag_t *flags)
{
	Word	name = sym->st_name;

	if (name) {
		if ((ifl->ifl_flags & FLG_IF_HSTRTAB) == 0) {
			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_FIL_NOSTRTABLE),
			    ifl->ifl_name, EC_WORD(symsecndx), symsecname,
			    symndx, EC_XWORD(name));
			return (NULL);
		}
		if (name >= (Word)strsize) {
			ld_eprintf(ofl, ERR_FATAL,
			    MSG_INTL(MSG_FIL_EXCSTRTABLE), ifl->ifl_name,
			    EC_WORD(symsecndx), symsecname, symndx,
			    EC_XWORD(name), strsecname, EC_XWORD(strsize));
			return (NULL);
		}
	}

	/*
	 * Determine if we're dealing with a register and if so validate it.
	 * If it's a scratch register, a fabricated name will be returned.
	 */
	if (ld_targ.t_ms.ms_is_regsym != NULL) {
		const char *regname = (*ld_targ.t_ms.ms_is_regsym)(ofl, ifl,
		    sym, strs, symndx, shndx, symsecname, flags);

		if (regname == (const char *)S_ERROR) {
			return (NULL);
		}
		if (regname)
			return (regname);
	}

	/*
	 * If this isn't a register, but we have a global symbol with a null
	 * name, we're not going to be able to hash this, search for it, or
	 * do anything interesting.  However, we've been accepting a symbol of
	 * this kind for ages now, so give the user a warning (rather than a
	 * fatal error), just in case this instance exists somewhere in the
	 * world and hasn't, as yet, been a problem.
	 */
	if ((name == 0) && (ELF_ST_BIND(sym->st_info) != STB_LOCAL)) {
		ld_eprintf(ofl, ERR_WARNING, MSG_INTL(MSG_FIL_NONAMESYM),
		    ifl->ifl_name, EC_WORD(symsecndx), symsecname, symndx,
		    EC_XWORD(name));
	}
	return (strs + name);
}

/*
 * For producing symbol names strings to use in error messages.
 * If the symbol has a non-null name, then the string returned by
 * this function is the output from demangle(), surrounded by
 * single quotes. For null names, a descriptive string giving
 * the symbol section and index is generated.
 *
 * This function uses an internal static buffer to hold the resulting
 * string. The value returned is usable by the caller until the next
 * call, at which point it is overwritten.
 */
static const char *
demangle_symname(const char *name, const char *symtab_name, Word symndx)
{
#define	INIT_BUFSIZE 256

	static char	*buf;
	static size_t	bufsize = 0;
	size_t		len;
	int		use_name;

	use_name = (name != NULL) && (*name != '\0');

	if (use_name) {
		name = demangle(name);
		len = strlen(name) + 2;   /* Include room for quotes */
	} else {
		name = MSG_ORIG(MSG_STR_EMPTY);
		len = strlen(symtab_name) + 2 + CONV_INV_BUFSIZE;
	}
	len++;			/* Null termination */

	/* If our buffer is too small, double it until it is big enough */
	if (len > bufsize) {
		size_t	new_bufsize = bufsize;
		char	*new_buf;

		if (new_bufsize == 0)
			new_bufsize = INIT_BUFSIZE;
		while (len > new_bufsize)
			new_bufsize *= 2;
		if ((new_buf = libld_malloc(new_bufsize)) == NULL)
			return (name);
		buf = new_buf;
		bufsize = new_bufsize;
	}

	if (use_name) {
		(void) snprintf(buf, bufsize, MSG_ORIG(MSG_FMT_SYMNAM), name);
	} else {
		(void) snprintf(buf, bufsize, MSG_ORIG(MSG_FMT_NULLSYMNAM),
		    symtab_name, EC_WORD(symndx));
	}

	return (buf);

#undef INIT_BUFSIZE
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
	if ((sifshdr->sh_link == 0) || (sifshdr->sh_link >= ifl->ifl_shnum)) {
		/*
		 * Broken input file
		 */
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_FIL_INVSHINFO),
		    ifl->ifl_name, isp->is_name, EC_XWORD(sifshdr->sh_link));
		return (0);
	}
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

		if ((sdp = ld_sym_find(str, SYM_NOHASH, NULL, ofl)) != NULL) {
			if (ifl != sdp->sd_file)
				continue;

			sdp->sd_flags &= ~FLG_SY_DIR;
			sdp->sd_flags |= FLG_SY_NDIR;
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
		if ((nsym = libld_malloc(sizeof (Sym))) == NULL)
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
	Sym_avlnode	qsav, *sav;

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
	if (sav == NULL)
		return (NULL);

	/*
	 * Return symbol found.
	 */
	return (sav->sav_sdp);
}

/*
 * Enter a new symbol into the link editors internal symbol table.
 * If the symbol is from an input file, information regarding the input file
 * and input section is also recorded.  Otherwise (file == NULL) the symbol
 * has been internally generated (ie. _etext, _edata, etc.).
 */
Sym_desc *
ld_sym_enter(const char *name, Sym *osym, Word hash, Ifl_desc *ifl,
    Ofl_desc *ofl, Word ndx, Word shndx, sd_flag_t sdflags, avl_index_t *where)
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
	if ((savl = libld_calloc(S_DROUND(sizeof (Sym_avlnode)) +
	    S_DROUND(sizeof (Sym_desc)) +
	    S_DROUND(sizeof (Sym_aux)), 1)) == NULL)
		return ((Sym_desc *)S_ERROR);
	sdp = (Sym_desc *)((uintptr_t)savl +
	    S_DROUND(sizeof (Sym_avlnode)));
	sap = (Sym_aux *)((uintptr_t)sdp +
	    S_DROUND(sizeof (Sym_desc)));

	savl->sav_sdp = sdp;
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

	if ((_name = libld_malloc(strlen(name) + 1)) == NULL)
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
		assert(_savl == NULL);
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
		if ((etype == ET_REL) && (sdp->sd_isc == NULL)) {
			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_SYM_INVSEC),
			    name, ifl->ifl_name, EC_XWORD(shndx));
			return (sdp);
		}
	}

	/*
	 * Mark any COMMON symbols as 'tentative'.
	 */
	if (sdflags & FLG_SY_SPECSEC) {
		if (nsym->st_shndx == SHN_COMMON)
			sdp->sd_flags |= FLG_SY_TENTSYM;
#if	defined(_ELF64)
		else if ((ld_targ.t_m.m_mach == EM_AMD64) &&
		    (nsym->st_shndx == SHN_X86_64_LCOMMON))
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
			sdp->sd_flags |= FLG_SY_DEFAULT;
			break;
		case STV_INTERNAL:
		case STV_HIDDEN:
			sdp->sd_flags |= FLG_SY_HIDDEN;
			break;
		case STV_PROTECTED:
			sdp->sd_flags |= FLG_SY_PROTECT;
			break;
		case STV_EXPORTED:
			sdp->sd_flags |= FLG_SY_EXPORT;
			break;
		case STV_SINGLETON:
			sdp->sd_flags |= (FLG_SY_SINGLE | FLG_SY_NDIR);
			ofl->ofl_flags1 |= (FLG_OF1_NDIRECT | FLG_OF1_NGLBDIR);
			break;
		case STV_ELIMINATE:
			sdp->sd_flags |= (FLG_SY_HIDDEN | FLG_SY_ELIM);
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
		    ((sdp->sd_flags & (FLG_SY_PROTECT | FLG_SY_DIR)) == 0) &&
		    (nsym->st_shndx != SHN_UNDEF)) {
			sdp->sd_flags |= FLG_SY_NDIR;
		}
	} else {
		sdp->sd_ref = REF_DYN_SEEN;

		/*
		 * If this is a protected symbol, remember this.  Note, this
		 * state is different from the FLG_SY_PROTECT used to establish
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
			sdp->sd_flags |= (FLG_SY_SINGLE | FLG_SY_NDIR);

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
		sdp->sd_flags |= (FLG_SY_REDUCED |
		    FLG_SY_HIDDEN | FLG_SY_IGNORE | FLG_SY_ELIM);
	}

	/*
	 * If this is an undefined, or common symbol from a relocatable object
	 * determine whether it is a global or weak reference (see build_osym(),
	 * where REF_DYN_NEED definitions are returned back to undefines).
	 */
	if ((etype == ET_REL) &&
	    (ELF_ST_BIND(nsym->st_info) == STB_GLOBAL) &&
	    ((nsym->st_shndx == SHN_UNDEF) || ((sdflags & FLG_SY_SPECSEC) &&
#if	defined(_ELF64)
	    ((nsym->st_shndx == SHN_COMMON) ||
	    ((ld_targ.t_m.m_mach == EM_AMD64) &&
	    (nsym->st_shndx == SHN_X86_64_LCOMMON))))))
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
	 *  -	To save the first definition of a symbol that is not available
	 *	for this link-edit.
	 *
	 *  -	To save all definitions of a symbol when the -m option is in
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
			if (aplist_append(&sap->sa_dfiles, ifl->ifl_name,
			    AL_CNT_SDP_DFILES) == NULL)
				return ((Sym_desc *)S_ERROR);
	}

	/*
	 * Provided we're not processing a mapfile, diagnose the entered symbol.
	 * Mapfile processing requires the symbol to be updated with additional
	 * information, therefore the diagnosing of the symbol is deferred until
	 * later (see Dbg_map_symbol()).
	 */
	if ((ifl == NULL) || ((ifl->ifl_flags & FLG_IF_MAPFILE) == 0))
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
 * The bits in sdflags_u are OR'd into the flags field of the symbol for the
 * underscored symbol.
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
    sd_flag_t sdflags_u, sd_flag_t sdflags, Ofl_desc *ofl)
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
			usdp->sd_flags |= FLG_SY_SPECSEC | sdflags_u;
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
			if (!SYM_IS_HIDDEN(usdp) &&
			    (sdflags & FLG_SY_DEFAULT)) {
				usdp->sd_aux->sa_overndx = VER_NDX_GLOBAL;
				if (sdaux_id == SDAUX_ID_GOT) {
					usdp->sd_flags &= ~FLG_SY_NDIR;
					usdp->sd_flags |= FLG_SY_PROTECT;
					usdp->sd_sym->st_other = STV_PROTECTED;
				} else if (
				    ((usdp->sd_flags & FLG_SY_DIR) == 0) &&
				    ((ofl->ofl_flags & FLG_OF_SYMBOLIC) == 0)) {
					usdp->sd_flags |= FLG_SY_NDIR;
				}
			}
			usdp->sd_flags |= sdflags;

			/*
			 * If the reference originated from a mapfile ensure
			 * we mark the symbol as used.
			 */
			if (usdp->sd_flags & FLG_SY_MAPREF)
				usdp->sd_flags |= FLG_SY_MAPUSED;

			DBG_CALL(Dbg_syms_updated(ofl, usdp, uname));
		} else
			ld_eprintf(ofl, ERR_WARNING, MSG_INTL(MSG_SYM_RESERVE),
			    uname, usdp->sd_file->ifl_name);
	} else {
		/*
		 * If the symbol does not exist create it.
		 */
		if ((sym = libld_calloc(sizeof (Sym), 1)) == NULL)
			return (S_ERROR);
		sym->st_shndx = SHN_ABS;
		sym->st_info = ELF_ST_INFO(STB_GLOBAL, STT_OBJECT);
		sym->st_size = 0;
		sym->st_value = 0;
		DBG_CALL(Dbg_syms_created(ofl->ofl_lml, uname));
		if ((usdp = ld_sym_enter(uname, sym, hash, (Ifl_desc *)NULL,
		    ofl, 0, SHN_ABS, (FLG_SY_SPECSEC | sdflags_u), &where)) ==
		    (Sym_desc *)S_ERROR)
			return (S_ERROR);
		usdp->sd_ref = REF_REL_NEED;
		/* LINTED */
		usdp->sd_aux->sa_symspec = (Half)sdaux_id;

		usdp->sd_aux->sa_overndx = VER_NDX_GLOBAL;

		if (sdaux_id == SDAUX_ID_GOT) {
			usdp->sd_flags |= FLG_SY_PROTECT;
			usdp->sd_sym->st_other = STV_PROTECTED;
		} else if ((sdflags & FLG_SY_DEFAULT) &&
		    ((ofl->ofl_flags & FLG_OF_SYMBOLIC) == 0)) {
			usdp->sd_flags |= FLG_SY_NDIR;
		}
		usdp->sd_flags |= sdflags;
	}

	if (name && (sdp = ld_sym_find(name, SYM_NOHASH, NULL, ofl)) &&
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
		if (!SYM_IS_HIDDEN(sdp) &&
		    (sdflags & FLG_SY_DEFAULT)) {
			sdp->sd_aux->sa_overndx = VER_NDX_GLOBAL;
			if (sdaux_id == SDAUX_ID_GOT) {
				sdp->sd_flags &= ~FLG_SY_NDIR;
				sdp->sd_flags |= FLG_SY_PROTECT;
				sdp->sd_sym->st_other = STV_PROTECTED;
			} else if (((sdp->sd_flags & FLG_SY_DIR) == 0) &&
			    ((ofl->ofl_flags & FLG_OF_SYMBOLIC) == 0)) {
				sdp->sd_flags |= FLG_SY_NDIR;
			}
		}
		sdp->sd_flags |= sdflags;

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
 * Undefined symbols can fall into one of four types:
 *
 *  -	the symbol is really undefined (SHN_UNDEF).
 *
 *  -	versioning has been enabled, however this symbol has not been assigned
 *	to one of the defined versions.
 *
 *  -	the symbol has been defined by an implicitly supplied library, ie. one
 *	which was encounted because it was NEEDED by another library, rather
 * 	than from a command line supplied library which would become the only
 *	dependency of the output file being produced.
 *
 *  -	the symbol has been defined by a version of a shared object that is
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

/*
 * Issue an undefined symbol message for the given symbol.
 *
 * entry:
 *	ofl - Output descriptor
 *	sdp - Undefined symbol to report
 *	type - Type of undefined symbol
 *	ofl_flag - One of 0, FLG_OF_FATAL, or FLG_OF_WARN.
 *	undef_state - Address of variable to be initialized to 0
 *		before the first call to sym_undef_entry, and passed
 *		to each subsequent call. A non-zero value for *undef_state
 *		indicates that this is not the first call in the series.
 *
 * exit:
 *	If *undef_state is 0, a title is issued.
 *
 *	A message for the undefined symbol is issued.
 *
 *	If ofl_flag is non-zero, its value is OR'd into *undef_state. Otherwise,
 *	all bits other than FLG_OF_FATAL and FLG_OF_WARN are set, in order to
 *	provide *undef_state with a non-zero value. These other bits have
 *	no meaning beyond that, and serve to ensure that *undef_state is
 *	non-zero if sym_undef_entry() has been called.
 */
static void
sym_undef_entry(Ofl_desc *ofl, Sym_desc *sdp, Type type, ofl_flag_t ofl_flag,
    ofl_flag_t *undef_state)
{
	const char	*name1, *name2, *name3;
	Ifl_desc	*ifl = sdp->sd_file;
	Sym_aux		*sap = sdp->sd_aux;

	if (*undef_state == 0)
		ld_eprintf(ofl, ERR_NONE, MSG_INTL(MSG_SYM_FMT_UNDEF),
		    MSG_INTL(MSG_SYM_UNDEF_ITM_11),
		    MSG_INTL(MSG_SYM_UNDEF_ITM_21),
		    MSG_INTL(MSG_SYM_UNDEF_ITM_12),
		    MSG_INTL(MSG_SYM_UNDEF_ITM_22));

	ofl->ofl_flags |= ofl_flag;
	*undef_state |= ofl_flag ? ofl_flag : ~(FLG_OF_FATAL | FLG_OF_WARN);

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

	ld_eprintf(ofl, ERR_NONE, MSG_INTL(format[type]),
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
	    SDAUX_ID_ETEXT, 0, (FLG_SY_DEFAULT | FLG_SY_EXPDEF),
	    ofl) == S_ERROR)
		return (S_ERROR);
	if (sym_add_spec(MSG_ORIG(MSG_SYM_EDATA), MSG_ORIG(MSG_SYM_EDATA_U),
	    SDAUX_ID_EDATA, 0, (FLG_SY_DEFAULT | FLG_SY_EXPDEF),
	    ofl) == S_ERROR)
		return (S_ERROR);
	if (sym_add_spec(MSG_ORIG(MSG_SYM_END), MSG_ORIG(MSG_SYM_END_U),
	    SDAUX_ID_END, FLG_SY_DYNSORT, (FLG_SY_DEFAULT | FLG_SY_EXPDEF),
	    ofl) == S_ERROR)
		return (S_ERROR);
	if (sym_add_spec(MSG_ORIG(MSG_SYM_L_END), MSG_ORIG(MSG_SYM_L_END_U),
	    SDAUX_ID_END, 0, FLG_SY_HIDDEN, ofl) == S_ERROR)
		return (S_ERROR);
	if (sym_add_spec(MSG_ORIG(MSG_SYM_L_START), MSG_ORIG(MSG_SYM_L_START_U),
	    SDAUX_ID_START, 0, FLG_SY_HIDDEN, ofl) == S_ERROR)
		return (S_ERROR);

	/*
	 * Historically we've always produced a _DYNAMIC symbol, even for
	 * static executables (in which case its value will be 0).
	 */
	if (sym_add_spec(MSG_ORIG(MSG_SYM_DYNAMIC), MSG_ORIG(MSG_SYM_DYNAMIC_U),
	    SDAUX_ID_DYN, FLG_SY_DYNSORT, (FLG_SY_DEFAULT | FLG_SY_EXPDEF),
	    ofl) == S_ERROR)
		return (S_ERROR);

	if (OFL_ALLOW_DYNSYM(ofl))
		if (sym_add_spec(MSG_ORIG(MSG_SYM_PLKTBL),
		    MSG_ORIG(MSG_SYM_PLKTBL_U), SDAUX_ID_PLT,
		    FLG_SY_DYNSORT, (FLG_SY_DEFAULT | FLG_SY_EXPDEF),
		    ofl) == S_ERROR)
			return (S_ERROR);

	/*
	 * A GOT reference will be accompanied by the associated GOT symbol.
	 * Make sure it gets assigned the appropriate special attributes.
	 */
	if (((sdp = ld_sym_find(MSG_ORIG(MSG_SYM_GOFTBL_U),
	    SYM_NOHASH, NULL, ofl)) != NULL) && (sdp->sd_ref != REF_DYN_SEEN)) {
		if (sym_add_spec(MSG_ORIG(MSG_SYM_GOFTBL),
		    MSG_ORIG(MSG_SYM_GOFTBL_U), SDAUX_ID_GOT, FLG_SY_DYNSORT,
		    (FLG_SY_DEFAULT | FLG_SY_EXPDEF), ofl) == S_ERROR)
			return (S_ERROR);
	}

	return (1);
}

/*
 * Determine a potential capability symbol's visibility.
 *
 * The -z symbolcap option transforms an object capabilities relocatable object
 * into a symbol capabilities relocatable object.  Any global function symbols,
 * or initialized global data symbols are candidates for transforming into local
 * symbol capabilities definitions.  However, if a user indicates that a symbol
 * should be demoted to local using a mapfile, then there is no need to
 * transform the associated global symbol.
 *
 * Normally, a symbol's visibility is determined after the symbol resolution
 * process, after all symbol state has been gathered and resolved.  However,
 * for -z symbolcap, this determination is too late.  When a global symbol is
 * read from an input file we need to determine it's visibility so as to decide
 * whether to create a local or not.
 *
 * If a user has explicitly defined this symbol as having local scope within a
 * mapfile, then a symbol of the same name already exists.  However, explicit
 * local definitions are uncommon, as most mapfiles define the global symbol
 * requirements together with an auto-reduction directive '*'.  If this state
 * has been defined, then we must make sure that the new symbol isn't a type
 * that can not be demoted to local.
 */
static int
sym_cap_vis(const char *name, Word hash, Sym *sym, Ofl_desc *ofl)
{
	Sym_desc	*sdp;
	uchar_t		vis;
	avl_index_t	where;
	sd_flag_t	sdflags = 0;

	/*
	 * Determine the visibility of the new symbol.
	 */
	vis = ELF_ST_VISIBILITY(sym->st_other);
	switch (vis) {
	case STV_EXPORTED:
		sdflags |= FLG_SY_EXPORT;
		break;
	case STV_SINGLETON:
		sdflags |= FLG_SY_SINGLE;
		break;
	}

	/*
	 * Determine whether a symbol definition already exists, and if so
	 * obtain the visibility.
	 */
	if ((sdp = ld_sym_find(name, hash, &where, ofl)) != NULL)
		sdflags |= sdp->sd_flags;

	/*
	 * Determine whether the symbol flags indicate this symbol should be
	 * hidden.
	 */
	if ((ofl->ofl_flags & (FLG_OF_AUTOLCL | FLG_OF_AUTOELM)) &&
	    ((sdflags & MSK_SY_NOAUTO) == 0))
		sdflags |= FLG_SY_HIDDEN;

	return ((sdflags & FLG_SY_HIDDEN) == 0);
}

/*
 * This routine checks to see if a symbols visibility needs to be reduced to
 * either SYMBOLIC or LOCAL.  This routine can be called from either
 * reloc_init() or sym_validate().
 */
void
ld_sym_adjust_vis(Sym_desc *sdp, Ofl_desc *ofl)
{
	ofl_flag_t	oflags = ofl->ofl_flags;
	Sym		*sym = sdp->sd_sym;

	if ((sdp->sd_ref == REF_REL_NEED) &&
	    (sdp->sd_sym->st_shndx != SHN_UNDEF)) {
		/*
		 * If auto-reduction/elimination is enabled, reduce any
		 * non-versioned, and non-local capabilities global symbols.
		 * A symbol is a candidate for auto-reduction/elimination if:
		 *
		 *  -	the symbol wasn't explicitly defined within a mapfile
		 *	(in which case all the necessary state has been applied
		 *	to the symbol), or
		 *  -	the symbol isn't one of the family of reserved
		 *	special symbols (ie. _end, _etext, etc.), or
		 *  -	the symbol isn't a SINGLETON, or
		 *  -	the symbol wasn't explicitly defined within a version
		 *	definition associated with an input relocatable object.
		 *
		 * Indicate that the symbol has been reduced as it may be
		 * necessary to print these symbols later.
		 */
		if ((oflags & (FLG_OF_AUTOLCL | FLG_OF_AUTOELM)) &&
		    ((sdp->sd_flags & MSK_SY_NOAUTO) == 0)) {
			if ((sdp->sd_flags & FLG_SY_HIDDEN) == 0) {
				sdp->sd_flags |=
				    (FLG_SY_REDUCED | FLG_SY_HIDDEN);
			}

			if (oflags & (FLG_OF_REDLSYM | FLG_OF_AUTOELM)) {
				sdp->sd_flags |= FLG_SY_ELIM;
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
		    ((sdp->sd_flags & (FLG_SY_HIDDEN | FLG_SY_NDIR)) == 0)) {
			sdp->sd_flags |= FLG_SY_PROTECT;
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
inline static int
ensure_sym_local(Ofl_desc *ofl, Sym_desc *sdp, const char *str)
{
	if (sdp->sd_sym->st_shndx == SHN_UNDEF) {
		if (str) {
			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_SYM_UNDEF),
			    str, demangle((char *)sdp->sd_name));
		}
		return (1);
	}
	if (sdp->sd_ref != REF_REL_NEED) {
		if (str) {
			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_SYM_EXTERN),
			    str, demangle((char *)sdp->sd_name),
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
ensure_array_local(Ofl_desc *ofl, APlist *apl, const char *str)
{
	Aliste		idx;
	Sym_desc	*sdp;
	int		ret = 0;

	for (APLIST_TRAVERSE(apl, idx, sdp))
		ret += ensure_sym_local(ofl, sdp, str);

	return (ret);
}

/*
 * After all symbol table input processing has been finished, and all relocation
 * counting has been carried out (ie. no more symbols will be read, generated,
 * or modified), validate and count the relevant entries:
 *
 *  -	check and print any undefined symbols remaining.  Note that if a symbol
 *	has been defined by virtue of the inclusion of 	an implicit shared
 *	library, it is still classed as undefined.
 *
 *  -	count the number of global needed symbols together with the size of
 *	their associated name strings (if scoping has been indicated these
 *	symbols may be reduced to locals).
 *
 *  -	establish the size and alignment requirements for the global .bss
 *	section (the alignment of this section is based on the 	first symbol
 *	that it will contain).
 */
uintptr_t
ld_sym_validate(Ofl_desc *ofl)
{
	Sym_avlnode	*sav;
	Sym_desc	*sdp;
	Sym		*sym;
	ofl_flag_t	oflags = ofl->ofl_flags;
	ofl_flag_t	undef = 0, needed = 0, verdesc = 0;
	Xword		bssalign = 0, tlsalign = 0;
	Boolean		need_bss, need_tlsbss;
	Xword		bsssize = 0, tlssize = 0;
#if	defined(_ELF64)
	Xword		lbssalign = 0, lbsssize = 0;
	Boolean		need_lbss;
#endif
	int		ret, allow_ldynsym;
	uchar_t		type;
	ofl_flag_t	undef_state = 0;

	DBG_CALL(Dbg_basic_validate(ofl->ofl_lml));

	/*
	 * The need_XXX booleans are used to determine whether we need to
	 * create each type of bss section. We used to create these sections
	 * if the sum of the required sizes for each type were non-zero.
	 * However, it is possible for a compiler to generate COMMON variables
	 * of zero-length and this tricks that logic --- even zero-length
	 * symbols need an output section.
	 */
	need_bss = need_tlsbss = FALSE;
#if	defined(_ELF64)
	need_lbss = FALSE;
#endif

	/*
	 * Determine how undefined symbols are handled:
	 *
	 * fatal:
	 *	If this link-edit calls for no undefined symbols to remain
	 *	(this is the default case when generating an executable but
	 *	can be enforced for any object using -z defs), a fatal error
	 *	condition will be indicated.
	 *
	 * warning:
	 *	If we're creating a shared object, and either the -Bsymbolic
	 *	flag is set, or the user has turned on the -z guidance feature,
	 *	then a non-fatal warning is issued for each symbol.
	 *
	 * ignore:
	 *	In all other cases, undefined symbols are quietly allowed.
	 */
	if (oflags & FLG_OF_NOUNDEF) {
		undef = FLG_OF_FATAL;
	} else if (oflags & FLG_OF_SHAROBJ) {
		if ((oflags & FLG_OF_SYMBOLIC) ||
		    OFL_GUIDANCE(ofl, FLG_OFG_NO_DEFS))
			undef = FLG_OF_WARN;
	}

	/*
	 * If the symbol is referenced from an implicitly included shared object
	 * (ie. it's not on the NEEDED list) then the symbol is also classified
	 * as undefined and a fatal error condition will be indicated.
	 */
	if ((oflags & FLG_OF_NOUNDEF) || !(oflags & FLG_OF_SHAROBJ))
		needed = FLG_OF_FATAL;
	else if ((oflags & FLG_OF_SHAROBJ) &&
	    OFL_GUIDANCE(ofl, FLG_OFG_NO_DEFS))
		needed = FLG_OF_WARN;

	/*
	 * If the output image is being versioned, then all symbol definitions
	 * must be associated with a version.  Any symbol that isn't associated
	 * with a version is classified as undefined, and a fatal error
	 * condition is indicated.
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
			    SYM_NOHASH, NULL, ofl)) != NULL) &&
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

		sdp = sav->sav_sdp;

		/*
		 * If undefined symbols are allowed, and we're not being
		 * asked to supply guidance, ignore any symbols that are
		 * not needed.
		 */
		if (!(oflags & FLG_OF_NOUNDEF) &&
		    !OFL_GUIDANCE(ofl, FLG_OFG_NO_DEFS) &&
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

			if ((isp == NULL) || (isp->is_shdr == NULL) ||
			    ((isp->is_shdr->sh_flags & SHF_TLS) == 0)) {
				ld_eprintf(ofl, ERR_FATAL,
				    MSG_INTL(MSG_SYM_TLS),
				    demangle(sdp->sd_name), ifl->ifl_name);
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
				sym_undef_entry(ofl, sdp, BNDLOCAL,
				    FLG_OF_FATAL, &undef_state);
				continue;
			}
		}

		/*
		 * If this symbol is defined in a non-allocatable section,
		 * reduce it to local symbol.
		 */
		if (((isp = sdp->sd_isc) != 0) && isp->is_shdr &&
		    ((isp->is_shdr->sh_flags & SHF_ALLOC) == 0)) {
			sdp->sd_flags |= (FLG_SY_REDUCED | FLG_SY_HIDDEN);
		}

		/*
		 * If this symbol originated as a SHN_SUNW_IGNORE, it will have
		 * been processed as an SHN_UNDEF.  Return the symbol to its
		 * original index for validation, and propagation to the output
		 * file.
		 */
		if (sdp->sd_flags & FLG_SY_IGNORE)
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
			    ((sdp->sd_flags &
			    (FLG_SY_MAPREF | FLG_SY_MAPUSED | FLG_SY_HIDDEN |
			    FLG_SY_PROTECT)) == FLG_SY_MAPREF))) {
				sym_undef_entry(ofl, sdp, UNDEF, undef,
				    &undef_state);
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
				sym_undef_entry(ofl, sdp, UNDEF, FLG_OF_WARN,
				    &undef_state);
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
			if (sdp->sd_flags & FLG_SY_NDIR)
				ofl->ofl_flags1 |= FLG_OF1_NGLBDIR;

			if (sdp->sd_file->ifl_vercnt) {
				int		vndx;
				Ver_index	*vip;

				vndx = sdp->sd_aux->sa_dverndx;
				vip = &sdp->sd_file->ifl_verndx[vndx];
				if (vip->vi_flags & FLG_VER_AVAIL) {
					vip->vi_flags |= FLG_VER_REFER;
				} else {
					sym_undef_entry(ofl, sdp, NOTAVAIL,
					    FLG_OF_FATAL, &undef_state);
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
			sym_undef_entry(ofl, sdp, IMPLICIT, needed,
			    &undef_state);
			if (needed == FLG_OF_FATAL)
				continue;
		}

		/*
		 * Test that a symbol isn't going to be reduced to local scope
		 * which actually wants to bind to a shared object - if so it's
		 * a fatal error.
		 */
		if ((sdp->sd_ref == REF_DYN_NEED) &&
		    (sdp->sd_flags & (FLG_SY_HIDDEN | FLG_SY_PROTECT))) {
			sym_undef_entry(ofl, sdp, BNDLOCAL, FLG_OF_FATAL,
			    &undef_state);
			continue;
		}

		/*
		 * If the output image is to be versioned then all symbol
		 * definitions must be associated with a version.  Remove any
		 * versioning that might be left associated with an undefined
		 * symbol.
		 */
		if (verdesc && (sdp->sd_ref == REF_REL_NEED)) {
			if (sym->st_shndx == SHN_UNDEF) {
				if (sdp->sd_aux && sdp->sd_aux->sa_overndx)
					sdp->sd_aux->sa_overndx = 0;
			} else {
				if (!SYM_IS_HIDDEN(sdp) && sdp->sd_aux &&
				    (sdp->sd_aux->sa_overndx == 0)) {
					sym_undef_entry(ofl, sdp, NOVERSION,
					    verdesc, &undef_state);
					continue;
				}
			}
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
		 * When -z nopartial is in effect, partially initialized
		 * symbols are directed to the special .data section
		 * created for that purpose (ofl->ofl_isparexpn).
		 * Otherwise, partially initialized symbols go to .bss.
		 *
		 * Also refer to make_mvsections() in sunwmove.c
		 */
		if ((sym->st_shndx == SHN_COMMON) &&
		    (((oflags & FLG_OF_RELOBJ) == 0) ||
		    (SYM_IS_HIDDEN(sdp) && (oflags & FLG_OF_PROCRED)))) {
			if ((sdp->sd_move == NULL) ||
			    ((sdp->sd_flags & FLG_SY_PAREXPN) == 0)) {
				if (type != STT_TLS) {
					need_bss = TRUE;
					bsssize = (Xword)S_ROUND(bsssize,
					    sym->st_value) + sym->st_size;
					if (sym->st_value > bssalign)
						bssalign = sym->st_value;
				} else {
					need_tlsbss = TRUE;
					tlssize = (Xword)S_ROUND(tlssize,
					    sym->st_value) + sym->st_size;
					if (sym->st_value > tlsalign)
						tlsalign = sym->st_value;
				}
			}
		}

#if	defined(_ELF64)
		/*
		 * Calculate the size and alignment requirement for the global
		 * .lbss. TLS or partially initialized symbols do not need to be
		 * considered yet.
		 */
		if ((ld_targ.t_m.m_mach == EM_AMD64) &&
		    (sym->st_shndx == SHN_X86_64_LCOMMON)) {
			need_lbss = TRUE;
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
		 * Note, a capabilities symbol must remain as visible as a
		 * global symbol.  However, the runtime linker recognizes the
		 * hidden requirement and ensures the symbol isn't made globally
		 * available at runtime.
		 */
		if (SYM_IS_HIDDEN(sdp) && (oflags & FLG_OF_PROCRED)) {
			/*
			 * If any reductions are being processed, keep a count
			 * of eliminated symbols, and if the symbol is being
			 * reduced to local, count it's size for the .symtab.
			 */
			if (sdp->sd_flags & FLG_SY_ELIM) {
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
			 * Check to see if this global variable should go into
			 * a sort section. Sort sections require a
			 * .SUNW_ldynsym section, so, don't check unless a
			 * .SUNW_ldynsym is allowed.
			 */
			if (allow_ldynsym)
				DYNSORT_COUNT(sdp, sym, type, ++);

			/*
			 * If global direct bindings are in effect, or this
			 * symbol has bound to a dependency which was specified
			 * as requiring direct bindings, and it hasn't
			 * explicitly been defined as a non-direct binding
			 * symbol, mark it.
			 */
			if (((ofl->ofl_dtflags_1 & DF_1_DIRECT) || (isp &&
			    (isp->is_file->ifl_flags & FLG_IF_DIRECT))) &&
			    ((sdp->sd_flags & FLG_SY_NDIR) == 0))
				sdp->sd_flags |= FLG_SY_DIR;

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
	 * Guidance: Use -z defs|nodefs when building shared objects.
	 *
	 * Our caller issues this, unless we mask it out here. So we mask it
	 * out unless we've issued at least one warnings or fatal error.
	 */
	if (!((oflags & FLG_OF_SHAROBJ) && OFL_GUIDANCE(ofl, FLG_OFG_NO_DEFS) &&
	    (undef_state & (FLG_OF_FATAL | FLG_OF_WARN))))
		ofl->ofl_guideflags |= FLG_OFG_NO_DEFS;

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
			if ((sdp = ofl->ofl_regsyms[ndx]) == NULL)
				continue;
			if (sdp->sd_ref != REF_REL_NEED) {
				ofl->ofl_regsyms[ndx] = NULL;
				continue;
			}

			ofl->ofl_regsymcnt++;
			if (sdp->sd_sym->st_name == 0)
				sdp->sd_name = MSG_ORIG(MSG_STR_EMPTY);

			if (SYM_IS_HIDDEN(sdp) ||
			    (ELF_ST_BIND(sdp->sd_sym->st_info) == STB_LOCAL))
				ofl->ofl_lregsymcnt++;
		}
	}

	/*
	 * Generate the .bss section now that we know its size and alignment.
	 */
	if (need_bss) {
		if (ld_make_bss(ofl, bsssize, bssalign,
		    ld_targ.t_id.id_bss) == S_ERROR)
			return (S_ERROR);
	}
	if (need_tlsbss) {
		if (ld_make_bss(ofl, tlssize, tlsalign,
		    ld_targ.t_id.id_tlsbss) == S_ERROR)
			return (S_ERROR);
	}
#if	defined(_ELF64)
	if ((ld_targ.t_m.m_mach == EM_AMD64) &&
	    need_lbss && !(oflags & FLG_OF_RELOBJ)) {
		if (ld_make_bss(ofl, lbsssize, lbssalign,
		    ld_targ.t_id.id_lbss) == S_ERROR)
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
		if ((sdp = ld_sym_find(ofl->ofl_entry, SYM_NOHASH,
		    NULL, ofl)) == NULL) {
			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_ARG_NOENTRY),
			    ofl->ofl_entry);
			ret++;
		} else if (ensure_sym_local(ofl, sdp,
		    MSG_INTL(MSG_SYM_ENTRY)) != 0) {
			ret++;
		} else {
			ofl->ofl_entry = (void *)sdp;
		}
	} else if (((sdp = ld_sym_find(MSG_ORIG(MSG_SYM_START),
	    SYM_NOHASH, NULL, ofl)) != NULL) && (ensure_sym_local(ofl,
	    sdp, 0) == 0)) {
		ofl->ofl_entry = (void *)sdp;

	} else if (((sdp = ld_sym_find(MSG_ORIG(MSG_SYM_MAIN),
	    SYM_NOHASH, NULL, ofl)) != NULL) && (ensure_sym_local(ofl,
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
	if (ofl->ofl_initarray) {
		ret += ensure_array_local(ofl, ofl->ofl_initarray,
		    MSG_ORIG(MSG_SYM_INITARRAY));
	}
	if (ofl->ofl_finiarray) {
		ret += ensure_array_local(ofl, ofl->ofl_finiarray,
		    MSG_ORIG(MSG_SYM_FINIARRAY));
	}
	if (ofl->ofl_preiarray) {
		ret += ensure_array_local(ofl, ofl->ofl_preiarray,
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
 * section index, address and binding.
 */
static int
compare(const void *sdpp1, const void *sdpp2)
{
	Sym_desc	*sdp1 = *((Sym_desc **)sdpp1);
	Sym_desc	*sdp2 = *((Sym_desc **)sdpp2);
	Sym		*sym1, *sym2;
	uchar_t		bind1, bind2;

	/*
	 * Symbol descriptors may be zero, move these to the front of the
	 * sorted array.
	 */
	if (sdp1 == NULL)
		return (-1);
	if (sdp2 == NULL)
		return (1);

	sym1 = sdp1->sd_sym;
	sym2 = sdp2->sd_sym;

	/*
	 * Compare the symbols section index.  This is important when sorting
	 * the symbol tables of relocatable objects.  In this case, a symbols
	 * value is the offset within the associated section, and thus many
	 * symbols can have the same value, but are effectively different
	 * addresses.
	 */
	if (sym1->st_shndx > sym2->st_shndx)
		return (1);
	if (sym1->st_shndx < sym2->st_shndx)
		return (-1);

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
	Error		err;
	const char	*msg;

	if ((sdp->sd_isc->is_shdr->sh_flags & (SHF_WRITE | SHF_ALLOC)) ==
	    SHF_ALLOC) {
		msg = MSG_INTL(MSG_SYM_BADADDR_ROTXT);
		err = ERR_WARNING;
	} else {
		msg = MSG_INTL(MSG_SYM_BADADDR);
		err = ERR_FATAL;
	}

	ld_eprintf(ofl, err, msg, demangle(sdp->sd_name),
	    ifl->ifl_name, shndx, sdp->sd_isc->is_name,
	    EC_XWORD(sdp->sd_isc->is_shdr->sh_size),
	    EC_XWORD(sym->st_value), EC_XWORD(sym->st_size));
}

/*
 * Global symbols that are candidates for translation to local capability
 * symbols under -z symbolcap, are maintained on a local symbol list.  Once
 * all symbols of a file are processed, this list is traversed to cull any
 * unnecessary weak symbol aliases.
 */
typedef struct {
	Sym_desc	*c_nsdp;	/* new lead symbol */
	Sym_desc	*c_osdp;	/* original symbol */
	Cap_group	*c_group;	/* symbol capability group */
	Word		c_ndx;		/* symbol index */
} Cap_pair;

/*
 * Process the symbol table for the specified input file.  At this point all
 * input sections from this input file have been assigned an input section
 * descriptor which is saved in the `ifl_isdesc' array.
 *
 *  -	local symbols are saved (as is) if the input file is a 	relocatable
 *	object
 *
 *  -	global symbols are added to the linkers internal symbol table if they
 *	are not already present, otherwise a symbol resolution function is
 *	called upon to resolve the conflict.
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
	Word		*symshndx = NULL;
	Shdr		*shdr = isc->is_shdr;
	Sym_desc	*sdp;
	size_t		strsize;
	char		*strs;
	uchar_t		type, bind;
	Word		ndx, hash, local, total;
	uchar_t		osabi = ifl->ifl_ehdr->e_ident[EI_OSABI];
	Half		mach = ifl->ifl_ehdr->e_machine;
	Half		etype = ifl->ifl_ehdr->e_type;
	int		etype_rel;
	const char	*symsecname, *strsecname;
	Word		symsecndx;
	avl_index_t	where;
	int		test_gnu_hidden_bit, weak;
	Cap_desc	*cdp = NULL;
	Alist		*cappairs = NULL;

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

	symsecndx = isc->is_scnndx;
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
			ld_eprintf(ofl, ERR_FATAL,
			    MSG_INTL(MSG_FIL_INVSHLINK), ifl->ifl_name,
			    EC_WORD(symsecndx), symsecname, EC_XWORD(ndx));
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
	    sizeof (Sym_desc *)))) == NULL)
		return (S_ERROR);
	etype_rel = (etype == ET_REL);
	if (etype_rel && local) {
		if ((ifl->ifl_locs =
		    libld_calloc(sizeof (Sym_desc), local)) == NULL)
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
		int		allow_ldynsym = OFL_ALLOW_LDYNSYM(ofl);
		Sym_desc	*last_file_sdp = NULL;
		int		last_file_ndx = 0;

		for (sym++, ndx = 1; ndx < local; sym++, ndx++) {
			sd_flag_t	sdflags = FLG_SY_CLEAN;
			Word		shndx;
			const char	*name;
			Sym_desc	*rsdp;
			int		shndx_bad = 0;
			int		symtab_enter = 1;

			/*
			 * Determine and validate the associated section index.
			 */
			if (symshndx && (sym->st_shndx == SHN_XINDEX)) {
				shndx = symshndx[ndx];
			} else if ((shndx = sym->st_shndx) >= SHN_LORESERVE) {
				sdflags |= FLG_SY_SPECSEC;
			} else if (shndx > ifl->ifl_shnum) {
				/* We need the name before we can issue error */
				shndx_bad = 1;
			}

			/*
			 * Check if st_name has a valid value or not.
			 */
			if ((name = string(ofl, ifl, sym, strs, strsize, ndx,
			    shndx, symsecndx, symsecname, strsecname,
			    &sdflags)) == NULL)
				continue;

			/*
			 * Now that we have the name, if the section index
			 * was bad, report it.
			 */
			if (shndx_bad) {
				ld_eprintf(ofl, ERR_WARNING,
				    MSG_INTL(MSG_SYM_INVSHNDX),
				    demangle_symname(name, symsecname, ndx),
				    ifl->ifl_name,
				    conv_sym_shndx(osabi, mach, sym->st_shndx,
				    CONV_FMT_DECIMAL, &inv_buf));
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
			rsdp = sdp = NULL;
			if (sdflags & FLG_SY_REGSYM) {
				/*
				 * The presence of FLG_SY_REGSYM means that
				 * the pointers in ld_targ.t_ms are non-NULL.
				 */
				rsdp = (*ld_targ.t_ms.ms_reg_find)(sym, ofl);
				if (rsdp != 0) {
					/*
					 * The fact that another register def-
					 * inition has been found is fatal.
					 * Call the verification routine to get
					 * the error message and move on.
					 */
					(void) (*ld_targ.t_ms.ms_reg_check)
					    (rsdp, sym, name, ifl, ofl);
					continue;
				}

				if (etype == ET_DYN) {
					if ((sdp = libld_calloc(
					    sizeof (Sym_desc), 1)) == NULL)
						return (S_ERROR);
					sdp->sd_ref = REF_DYN_SEEN;

					/* Will not appear in output object */
					symtab_enter = 0;
				}
			} else if (etype == ET_DYN)
				continue;

			/*
			 * Fill in the remaining symbol descriptor information.
			 */
			if (sdp == NULL) {
				sdp = &(ifl->ifl_locs[ndx]);
				sdp->sd_ref = REF_REL_NEED;
				sdp->sd_symndx = ndx;
			}
			if (rsdp == NULL) {
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
				sdp->sd_flags |= (FLG_SY_IGNORE | FLG_SY_ELIM);
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
				 *
				 * The presence of FLG_SY_REGSYM means that
				 * the pointers in ld_targ.t_ms are non-NULL.
				 */
				if ((rsdp == NULL) &&
				    ((*ld_targ.t_ms.ms_reg_enter)(sdp, ofl) ==
				    0))
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
					ld_eprintf(ofl, ERR_WARNING,
					    MSG_INTL(MSG_SYM_INVSHNDX),
					    demangle_symname(name, symsecname,
					    ndx), ifl->ifl_name,
					    conv_sym_shndx(osabi, mach,
					    sym->st_shndx, CONV_FMT_DECIMAL,
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
			if (etype_rel) {
				if (SYM_LOC_BADADDR(sdp, sym, type)) {
					issue_badaddr_msg(ifl, ofl, sdp,
					    sym, shndx);
					if (ofl->ofl_flags & FLG_OF_FATAL)
						continue;
				}

				/*
				 * We have observed relocatable objects
				 * containing identical adjacent STT_FILE
				 * symbols. Discard any other than the first,
				 * as they are all equivalent and the extras
				 * do not add information.
				 *
				 * For the purpose of this test, we assume
				 * that only the symbol type and the string
				 * table offset (st_name) matter.
				 */
				if (type == STT_FILE) {
					int toss = (last_file_sdp != NULL) &&
					    ((ndx - 1) == last_file_ndx) &&
					    (sym->st_name ==
					    last_file_sdp->sd_sym->st_name);

					last_file_sdp = sdp;
					last_file_ndx = ndx;
					if (toss) {
						sdp->sd_flags |= FLG_SY_INVALID;
						DBG_CALL(Dbg_syms_dup_discarded(
						    ofl->ofl_lml, ndx, sdp));
						continue;
					}
				}
			}


			/*
			 * Sanity check for TLS
			 */
			if ((sym->st_size != 0) && ((type == STT_TLS) &&
			    (sym->st_shndx != SHN_COMMON))) {
				Is_desc	*isp = sdp->sd_isc;

				if ((isp == NULL) || (isp->is_shdr == NULL) ||
				    ((isp->is_shdr->sh_flags & SHF_TLS) == 0)) {
					ld_eprintf(ofl, ERR_FATAL,
					    MSG_INTL(MSG_SYM_TLS),
					    demangle(sdp->sd_name),
					    ifl->ifl_name);
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
			    (sdp->sd_isc && (sdp->sd_isc->is_osdesc == NULL))) {
				ld_eprintf(ofl, ERR_WARNING,
				    MSG_INTL(MSG_SYM_INVSHNDX),
				    demangle_symname(name, symsecname, ndx),
				    ifl->ifl_name,
				    conv_sym_shndx(osabi, mach, sym->st_shndx,
				    CONV_FMT_DECIMAL, &inv_buf));
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
			if (!(ofl->ofl_flags & FLG_OF_REDLSYM) &&
			    symtab_enter) {
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
	 * Determine whether object capabilities for this file are being
	 * converted into symbol capabilities.  If so, global function symbols,
	 * and initialized global data symbols, need special translation and
	 * processing.
	 */
	if ((etype == ET_REL) && (ifl->ifl_flags & FLG_IF_OTOSCAP))
		cdp = ifl->ifl_caps;

	/*
	 * Now scan the global symbols entering them in the internal symbol
	 * table or resolving them as necessary.
	 */
	sym = (Sym *)isc->is_indata->d_buf;
	sym += local;
	weak = 0;
	/* LINTED */
	for (ndx = (int)local; ndx < total; sym++, ndx++) {
		const char	*name;
		sd_flag_t	sdflags = 0;
		Word		shndx;
		int		shndx_bad = 0;
		Sym		*nsym = sym;
		Cap_pair	*cpp = NULL;
		uchar_t		ntype;

		/*
		 * Determine and validate the associated section index.
		 */
		if (symshndx && (nsym->st_shndx == SHN_XINDEX)) {
			shndx = symshndx[ndx];
		} else if ((shndx = nsym->st_shndx) >= SHN_LORESERVE) {
			sdflags |= FLG_SY_SPECSEC;
		} else if (shndx > ifl->ifl_shnum) {
			/* We need the name before we can issue error */
			shndx_bad = 1;
		}

		/*
		 * Check if st_name has a valid value or not.
		 */
		if ((name = string(ofl, ifl, nsym, strs, strsize, ndx, shndx,
		    symsecndx, symsecname, strsecname, &sdflags)) == NULL)
			continue;

		/*
		 * Now that we have the name, report an erroneous section index.
		 */
		if (shndx_bad) {
			ld_eprintf(ofl, ERR_WARNING, MSG_INTL(MSG_SYM_INVSHNDX),
			    demangle_symname(name, symsecname, ndx),
			    ifl->ifl_name,
			    conv_sym_shndx(osabi, mach, nsym->st_shndx,
			    CONV_FMT_DECIMAL, &inv_buf));
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
		if (name[0] && (etype == ET_DYN) && (nsym->st_size == 0) &&
		    (ELF_ST_TYPE(nsym->st_info) == STT_OBJECT) &&
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
		 * The '-z wrap=XXX' option emulates the GNU ld --wrap=XXX
		 * option. When XXX is the symbol to be wrapped:
		 *
		 *  -	An undefined reference to XXX is converted to __wrap_XXX
		 *  -	An undefined reference to __real_XXX is converted to XXX
		 *
		 * The idea is that the user can supply a wrapper function
		 * __wrap_XXX that does some work, and then uses the name
		 * __real_XXX to pass the call on to the real function. The
		 * wrapper objects are linked with the original unmodified
		 * objects to produce a wrapped version of the output object.
		 */
		if (ofl->ofl_wrap && name[0] && (shndx == SHN_UNDEF)) {
			WrapSymNode wsn, *wsnp;

			/*
			 * If this is the __real_XXX form, advance the
			 * pointer to reference the wrapped name.
			 */
			wsn.wsn_name = name;
			if ((*name == '_') &&
			    (strncmp(name, MSG_ORIG(MSG_STR_UU_REAL_U),
			    MSG_STR_UU_REAL_U_SIZE) == 0))
				wsn.wsn_name += MSG_STR_UU_REAL_U_SIZE;

			/*
			 * Is this symbol in the wrap AVL tree? If so, map
			 * XXX to __wrap_XXX, and __real_XXX to XXX. Note that
			 * wsn.wsn_name will equal the current value of name
			 * if the __real_ prefix is not present.
			 */
			if ((wsnp = avl_find(ofl->ofl_wrap, &wsn, 0)) != NULL) {
				const char *old_name = name;

				name = (wsn.wsn_name == name) ?
				    wsnp->wsn_wrapname : wsn.wsn_name;
				DBG_CALL(Dbg_syms_wrap(ofl->ofl_lml, ndx,
				    old_name, name));
			}
		}

		/*
		 * Determine and validate the symbols binding.
		 */
		bind = ELF_ST_BIND(nsym->st_info);
		if ((bind != STB_GLOBAL) && (bind != STB_WEAK)) {
			ld_eprintf(ofl, ERR_WARNING, MSG_INTL(MSG_SYM_NONGLOB),
			    demangle_symname(name, symsecname, ndx),
			    ifl->ifl_name,
			    conv_sym_info_bind(bind, 0, &inv_buf));
			continue;
		}
		if (bind == STB_WEAK)
			weak++;

		/*
		 * If this symbol falls within the range of a section being
		 * discarded, then discard the symbol itself.
		 */
		if (((sdflags & FLG_SY_SPECSEC) == 0) &&
		    (nsym->st_shndx != SHN_UNDEF)) {
			Is_desc	*isp;

			if (shndx >= ifl->ifl_shnum) {
				/*
				 * Carry our some basic sanity checks
				 * The symbol will not be carried forward to
				 * the output file, which won't be a problem
				 * unless a relocation is required against it.
				 */
				ld_eprintf(ofl, ERR_WARNING,
				    MSG_INTL(MSG_SYM_INVSHNDX),
				    demangle_symname(name, symsecname, ndx),
				    ifl->ifl_name,
				    conv_sym_shndx(osabi, mach, nsym->st_shndx,
				    CONV_FMT_DECIMAL, &inv_buf));
				continue;
			}

			isp = ifl->ifl_isdesc[shndx];
			if (isp && (isp->is_flags & FLG_IS_DISCARD)) {
				if ((sdp =
				    libld_calloc(sizeof (Sym_desc), 1)) == NULL)
					return (S_ERROR);

				/*
				 * Create a dummy symbol entry so that if we
				 * find any references to this discarded symbol
				 * we can compensate.
				 */
				sdp->sd_name = name;
				sdp->sd_sym = nsym;
				sdp->sd_file = ifl;
				sdp->sd_isc = isp;
				sdp->sd_flags = FLG_SY_ISDISC;
				ifl->ifl_oldndx[ndx] = sdp;

				DBG_CALL(Dbg_syms_discarded(ofl->ofl_lml, sdp));
				continue;
			}
		}

		/*
		 * If object capabilities for this file are being converted
		 * into symbol capabilities, then:
		 *
		 *  -	Any global function, or initialized global data symbol
		 *	definitions (ie., those that are not associated with
		 *	special symbol types, ie., ABS, COMMON, etc.), and which
		 *	have not been reduced to locals, are converted to symbol
		 *	references (UNDEF).  This ensures that any reference to
		 *	the original symbol, for example from a relocation, get
		 *	associated to a capabilities family lead symbol, ie., a
		 *	generic instance.
		 *
		 *  -	For each global function, or object symbol definition,
		 *	a new local symbol is created.  The function or object
		 *	is renamed using the capabilities CA_SUNW_ID definition
		 *	(which might have been fabricated for this purpose -
		 *	see get_cap_group()).  The new symbol name is:
		 *
		 *	    <original name>%<capability group identifier>
		 *
		 *	This symbol is associated to the same location, and
		 *	becomes a capabilities family member.
		 */
		/* LINTED */
		hash = (Word)elf_hash(name);

		ntype = ELF_ST_TYPE(nsym->st_info);
		if (cdp && (nsym->st_shndx != SHN_UNDEF) &&
		    ((sdflags & FLG_SY_SPECSEC) == 0) &&
		    ((ntype == STT_FUNC) || (ntype == STT_OBJECT))) {
			/*
			 * Determine this symbol's visibility.  If a mapfile has
			 * indicated this symbol should be local, then there's
			 * no point in transforming this global symbol to a
			 * capabilities symbol.  Otherwise, create a symbol
			 * capability pair descriptor to record this symbol as
			 * a candidate for translation.
			 */
			if (sym_cap_vis(name, hash, sym, ofl) &&
			    ((cpp = alist_append(&cappairs, NULL,
			    sizeof (Cap_pair), AL_CNT_CAP_PAIRS)) == NULL))
				return (S_ERROR);
		}

		if (cpp) {
			Sym	*rsym;

			DBG_CALL(Dbg_syms_cap_convert(ofl, ndx, name, nsym));

			/*
			 * Allocate a new symbol descriptor to represent the
			 * transformed global symbol.  The descriptor points
			 * to the original symbol information (which might
			 * indicate a global or weak visibility).  The symbol
			 * information will be transformed into a local symbol
			 * later, after any weak aliases are culled.
			 */
			if ((cpp->c_osdp =
			    libld_malloc(sizeof (Sym_desc))) == NULL)
				return (S_ERROR);

			cpp->c_osdp->sd_name = name;
			cpp->c_osdp->sd_sym = nsym;
			cpp->c_osdp->sd_shndx = shndx;
			cpp->c_osdp->sd_file = ifl;
			cpp->c_osdp->sd_isc = ifl->ifl_isdesc[shndx];
			cpp->c_osdp->sd_ref = REF_REL_NEED;

			/*
			 * Save the capabilities group this symbol belongs to,
			 * and the original symbol index.
			 */
			cpp->c_group = cdp->ca_groups->apl_data[0];
			cpp->c_ndx = ndx;

			/*
			 * Replace the original symbol definition with a symbol
			 * reference.  Make sure this reference isn't left as a
			 * weak.
			 */
			if ((rsym = libld_malloc(sizeof (Sym))) == NULL)
				return (S_ERROR);

			*rsym = *nsym;

			rsym->st_info = ELF_ST_INFO(STB_GLOBAL, ntype);
			rsym->st_shndx = shndx = SHN_UNDEF;
			rsym->st_value = 0;
			rsym->st_size = 0;

			sdflags |= FLG_SY_CAP;

			nsym = rsym;
		}

		/*
		 * If the symbol does not already exist in the internal symbol
		 * table add it, otherwise resolve the conflict.  If the symbol
		 * from this file is kept, retain its symbol table index for
		 * possible use in associating a global alias.
		 */
		if ((sdp = ld_sym_find(name, hash, &where, ofl)) == NULL) {
			DBG_CALL(Dbg_syms_global(ofl->ofl_lml, ndx, name));
			if ((sdp = ld_sym_enter(name, nsym, hash, ifl, ofl, ndx,
			    shndx, sdflags, &where)) == (Sym_desc *)S_ERROR)
				return (S_ERROR);

		} else if (ld_sym_resolve(sdp, nsym, ifl, ofl, ndx, shndx,
		    sdflags) == S_ERROR)
			return (S_ERROR);

		/*
		 * Now that we have a symbol descriptor, retain the descriptor
		 * for later use by symbol capabilities processing.
		 */
		if (cpp)
			cpp->c_nsdp = sdp;

		/*
		 * After we've compared a defined symbol in one shared
		 * object, flag the symbol so we don't compare it again.
		 */
		if ((etype == ET_DYN) && (nsym->st_shndx != SHN_UNDEF) &&
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

			/*
			 * The presence of FLG_SY_REGSYM means that
			 * the pointers in ld_targ.t_ms are non-NULL.
			 */
			rsdp = (*ld_targ.t_ms.ms_reg_find)(sdp->sd_sym, ofl);
			if (rsdp == NULL) {
				if ((*ld_targ.t_ms.ms_reg_enter)(sdp, ofl) == 0)
					return (S_ERROR);
			} else if (rsdp != sdp) {
				(void) (*ld_targ.t_ms.ms_reg_check)(rsdp,
				    sdp->sd_sym, sdp->sd_name, ifl, ofl);
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
	DBG_CALL(Dbg_util_nl(ofl->ofl_lml, DBG_NL_STD));

	/*
	 * Associate weak (alias) symbols to their non-weak counterparts by
	 * scanning the global symbols one more time.
	 *
	 * This association is needed when processing the symbols from a shared
	 * object dependency when a a weak definition satisfies a reference:
	 *
	 *  -	When building a dynamic executable, if a referenced symbol is a
	 *	data item, the symbol data is copied to the executables address
	 *	space.  In this copy-relocation case, we must also reassociate
	 *	the alias symbol with its new location in the executable.
	 *
	 *  -	If the referenced symbol is a function then we may need to
	 *	promote the symbols binding from undefined weak to undefined,
	 *	otherwise the run-time linker will not generate the correct
	 *	relocation error should the symbol not be found.
	 *
	 * Weak alias association is also required when a local dynsym table
	 * is being created.  This table should only contain one instance of a
	 * symbol that is associated to a given address.
	 *
	 * The true association between a weak/strong symbol pair is that both
	 * symbol entries are identical, thus first we create a sorted symbol
	 * list keyed off of the symbols section index and value.  If the symbol
	 * belongs to the same section and has the same value, then the chances
	 * are that the rest of the symbols data is the same.  This list is then
	 * scanned for weak symbols, and if one is found then any strong
	 * association will exist in the entries that follow.  Thus we just have
	 * to scan one (typically a single alias) or more (in the uncommon
	 * instance of multiple weak to strong associations) entries to
	 * determine if a match exists.
	 */
	if (weak && (OFL_ALLOW_LDYNSYM(ofl) || (etype == ET_DYN)) &&
	    (total > local)) {
		static Sym_desc	**sort;
		static size_t	osize = 0;
		size_t		nsize = (total - local) * sizeof (Sym_desc *);

		/*
		 * As we might be processing many input files, and many symbols,
		 * try and reuse a static sort buffer.  Note, presently we're
		 * playing the game of never freeing any buffers as there's a
		 * belief this wastes time.
		 */
		if ((osize == 0) || (nsize > osize)) {
			if ((sort = libld_malloc(nsize)) == NULL)
				return (S_ERROR);
			osize = nsize;
		}
		(void) memcpy((void *)sort, &ifl->ifl_oldndx[local], nsize);

		qsort(sort, (total - local), sizeof (Sym_desc *), compare);

		for (ndx = 0; ndx < (total - local); ndx++) {
			Sym_desc	*wsdp = sort[ndx];
			Sym		*wsym;
			int		sndx;

			/*
			 * Ignore any empty symbol descriptor, or the case where
			 * the symbol has been resolved to a different file.
			 */
			if ((wsdp == NULL) || (wsdp->sd_file != ifl))
				continue;

			wsym = wsdp->sd_sym;

			if ((wsym->st_shndx == SHN_UNDEF) ||
			    (wsdp->sd_flags & FLG_SY_SPECSEC) ||
			    (ELF_ST_BIND(wsym->st_info) != STB_WEAK))
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
				Sym_desc	*ssdp = sort[sndx];
				Sym		*ssym;
				sd_flag_t	w_dynbits, s_dynbits;

				/*
				 * Ignore any empty symbol descriptor, or the
				 * case where the symbol has been resolved to a
				 * different file.
				 */
				if ((ssdp == NULL) || (ssdp->sd_file != ifl))
					continue;

				ssym = ssdp->sd_sym;

				if (ssym->st_shndx == SHN_UNDEF)
					continue;

				if ((ssym->st_shndx != wsym->st_shndx) ||
				    (ssym->st_value != wsym->st_value))
					break;

				if ((ssym->st_size != wsym->st_size) ||
				    (ssdp->sd_flags & FLG_SY_SPECSEC) ||
				    (ELF_ST_BIND(ssym->st_info) == STB_WEAK))
					continue;

				/*
				 * If a sharable object, set link fields so
				 * that they reference each other.`
				 */
				if (etype == ET_DYN) {
					ssdp->sd_aux->sa_linkndx =
					    (Word)wsdp->sd_symndx;
					wsdp->sd_aux->sa_linkndx =
					    (Word)ssdp->sd_symndx;
				}

				/*
				 * Determine which of these two symbols go into
				 * the sort section.  If a mapfile has made
				 * explicit settings of the FLG_SY_*DYNSORT
				 * flags for both symbols, then we do what they
				 * say.  If one has the DYNSORT flags set, we
				 * set the NODYNSORT bit in the other.  And if
				 * neither has an explicit setting, then we
				 * favor the weak symbol because they usually
				 * lack the leading underscore.
				 */
				w_dynbits = wsdp->sd_flags &
				    (FLG_SY_DYNSORT | FLG_SY_NODYNSORT);
				s_dynbits = ssdp->sd_flags &
				    (FLG_SY_DYNSORT | FLG_SY_NODYNSORT);
				if (!(w_dynbits && s_dynbits)) {
					if (s_dynbits) {
						if (s_dynbits == FLG_SY_DYNSORT)
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

	/*
	 * Having processed all symbols, under -z symbolcap, reprocess any
	 * symbols that are being translated from global to locals.  The symbol
	 * pair that has been collected defines the original symbol (c_osdp),
	 * which will become a local, and the new symbol (c_nsdp), which will
	 * become a reference (UNDEF) for the original.
	 *
	 * Scan these symbol pairs looking for weak symbols, which have non-weak
	 * aliases.  There is no need to translate both of these symbols to
	 * locals, only the global is necessary.
	 */
	if (cappairs) {
		Aliste		idx1;
		Cap_pair	*cpp1;

		for (ALIST_TRAVERSE(cappairs, idx1, cpp1)) {
			Sym_desc	*sdp1 = cpp1->c_osdp;
			Sym		*sym1 = sdp1->sd_sym;
			uchar_t		bind1 = ELF_ST_BIND(sym1->st_info);
			Aliste		idx2;
			Cap_pair	*cpp2;

			/*
			 * If this symbol isn't weak, it's capability member is
			 * retained for the creation of a local symbol.
			 */
			if (bind1 != STB_WEAK)
				continue;

			/*
			 * If this is a weak symbol, traverse the capabilities
			 * list again to determine if a corresponding non-weak
			 * symbol exists.
			 */
			for (ALIST_TRAVERSE(cappairs, idx2, cpp2)) {
				Sym_desc	*sdp2 = cpp2->c_osdp;
				Sym		*sym2 = sdp2->sd_sym;
				uchar_t		bind2 =
				    ELF_ST_BIND(sym2->st_info);

				if ((cpp1 == cpp2) ||
				    (cpp1->c_group != cpp2->c_group) ||
				    (sym1->st_value != sym2->st_value) ||
				    (bind2 == STB_WEAK))
					continue;

				/*
				 * The weak symbol (sym1) has a non-weak (sym2)
				 * counterpart.  There's no point in translating
				 * both of these equivalent symbols to locals.
				 * Add this symbol capability alias to the
				 * capabilities family information, and remove
				 * the weak symbol.
				 */
				if (ld_cap_add_family(ofl, cpp2->c_nsdp,
				    cpp1->c_nsdp, NULL, NULL) == S_ERROR)
					return (S_ERROR);

				free((void *)cpp1->c_osdp);
				(void) alist_delete(cappairs, &idx1);
			}
		}

		DBG_CALL(Dbg_util_nl(ofl->ofl_lml, DBG_NL_STD));

		/*
		 * The capability pairs information now represents all the
		 * global symbols that need transforming to locals.  These
		 * local symbols are renamed using their group identifiers.
		 */
		for (ALIST_TRAVERSE(cappairs, idx1, cpp1)) {
			Sym_desc	*osdp = cpp1->c_osdp;
			Objcapset	*capset;
			size_t		nsize, tsize;
			const char	*oname;
			char		*cname, *idstr;
			Sym		*csym;

			/*
			 * If the local symbol has not yet been translated
			 * convert it to a local symbol with a name.
			 */
			if ((osdp->sd_flags & FLG_SY_CAP) != 0)
				continue;

			/*
			 * As we're converting object capabilities to symbol
			 * capabilities, obtain the capabilities set for this
			 * object, so as to retrieve the CA_SUNW_ID value.
			 */
			capset = &cpp1->c_group->cg_set;

			/*
			 * Create a new name from the existing symbol and the
			 * capabilities group identifier.  Note, the delimiter
			 * between the symbol name and identifier name is hard-
			 * coded here (%), so that we establish a convention
			 * for transformed symbol names.
			 */
			oname = osdp->sd_name;

			idstr = capset->oc_id.cs_str;
			nsize = strlen(oname);
			tsize = nsize + 1 + strlen(idstr) + 1;
			if ((cname = libld_malloc(tsize)) == 0)
				return (S_ERROR);

			(void) strcpy(cname, oname);
			cname[nsize++] = '%';
			(void) strcpy(&cname[nsize], idstr);

			/*
			 * Allocate a new symbol table entry, transform this
			 * symbol to a local, and assign the new name.
			 */
			if ((csym = libld_malloc(sizeof (Sym))) == NULL)
				return (S_ERROR);

			*csym = *osdp->sd_sym;
			csym->st_info = ELF_ST_INFO(STB_LOCAL,
			    ELF_ST_TYPE(osdp->sd_sym->st_info));

			osdp->sd_name = cname;
			osdp->sd_sym = csym;
			osdp->sd_flags = FLG_SY_CAP;

			/*
			 * Keep track of this new local symbol.  As -z symbolcap
			 * can only be used to create a relocatable object, a
			 * dynamic symbol table can't exist.  Ensure there is
			 * space reserved in the string table.
			 */
			ofl->ofl_caploclcnt++;
			if (st_insert(ofl->ofl_strtab, cname) == -1)
				return (S_ERROR);

			DBG_CALL(Dbg_syms_cap_local(ofl, cpp1->c_ndx,
			    cname, csym, osdp));

			/*
			 * Establish this capability pair as a family.
			 */
			if (ld_cap_add_family(ofl, cpp1->c_nsdp, osdp,
			    cpp1->c_group, &ifl->ifl_caps->ca_syms) == S_ERROR)
				return (S_ERROR);
		}
	}

	return (1);

#undef SYM_LOC_BADADDR
}

/*
 * Add an undefined symbol to the symbol table.  The reference originates from
 * the location identified by the message id (mid).  These references can
 * originate from command line options such as -e, -u, -initarray, etc.
 * (identified with MSG_INTL(MSG_STR_COMMAND)), or from internally generated
 * TLS relocation references (identified with MSG_INTL(MSG_STR_TLSREL)).
 */
Sym_desc *
ld_sym_add_u(const char *name, Ofl_desc *ofl, Msg mid)
{
	Sym		*sym;
	Ifl_desc	*ifl = NULL, *_ifl;
	Sym_desc	*sdp;
	Word		hash;
	Aliste		idx;
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
	for (APLIST_TRAVERSE(ofl->ofl_objs, idx, _ifl))
		if (strcmp(_ifl->ifl_name, reference) == 0) {
			ifl = _ifl;
			break;
		}

	/*
	 * If no descriptor exists create one.
	 */
	if (ifl == NULL) {
		if ((ifl = libld_calloc(sizeof (Ifl_desc), 1)) == NULL)
			return ((Sym_desc *)S_ERROR);
		ifl->ifl_name = reference;
		ifl->ifl_flags = FLG_IF_NEEDED | FLG_IF_FILEREF;
		if ((ifl->ifl_ehdr = libld_calloc(sizeof (Ehdr), 1)) == NULL)
			return ((Sym_desc *)S_ERROR);
		ifl->ifl_ehdr->e_type = ET_REL;

		if (aplist_append(&ofl->ofl_objs, ifl, AL_CNT_OFL_OBJS) == NULL)
			return ((Sym_desc *)S_ERROR);
	}

	/*
	 * Allocate a symbol structure and add it to the global symbol table.
	 */
	if ((sym = libld_calloc(sizeof (Sym), 1)) == NULL)
		return ((Sym_desc *)S_ERROR);
	sym->st_info = ELF_ST_INFO(STB_GLOBAL, STT_NOTYPE);
	sym->st_shndx = SHN_UNDEF;

	DBG_CALL(Dbg_syms_process(ofl->ofl_lml, ifl));
	if (sdp == NULL) {
		DBG_CALL(Dbg_syms_global(ofl->ofl_lml, 0, name));
		if ((sdp = ld_sym_enter(name, sym, hash, ifl, ofl, 0, SHN_UNDEF,
		    0, &where)) == (Sym_desc *)S_ERROR)
			return ((Sym_desc *)S_ERROR);
	} else if (ld_sym_resolve(sdp, sym, ifl, ofl, 0,
	    SHN_UNDEF, 0) == S_ERROR)
		return ((Sym_desc *)S_ERROR);

	sdp->sd_flags &= ~FLG_SY_CLEAN;
	sdp->sd_flags |= FLG_SY_CMDREF;

	return (sdp);
}

/*
 * STT_SECTION symbols have their st_name field set to NULL, and consequently
 * have no name. Generate a name suitable for diagnostic use for such a symbol
 * and store it in the input section descriptor. The resulting name will be
 * of the form:
 *
 *	"XXX (section)"
 *
 * where XXX is the name of the section.
 *
 * entry:
 *	isc - Input section associated with the symbol.
 *	fmt - NULL, or format string to use.
 *
 * exit:
 *	Sets isp->is_sym_name to the allocated string. Returns the
 *	string pointer, or NULL on allocation failure.
 */
const const char *
ld_stt_section_sym_name(Is_desc *isp)
{
	const char	*fmt;
	char		*str;
	size_t		len;

	if ((isp == NULL) || (isp->is_name == NULL))
		return (NULL);

	if (isp->is_sym_name == NULL) {
		fmt = (isp->is_flags & FLG_IS_GNSTRMRG) ?
		    MSG_INTL(MSG_STR_SECTION_MSTR) : MSG_INTL(MSG_STR_SECTION);

		len = strlen(fmt) + strlen(isp->is_name) + 1;

		if ((str = libld_malloc(len)) == NULL)
			return (NULL);
		(void) snprintf(str, len, fmt, isp->is_name);
		isp->is_sym_name = str;
	}

	return (isp->is_sym_name);
}
