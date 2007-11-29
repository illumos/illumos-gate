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

/*
 * Update the new output file image, perform virtual address, offset and
 * displacement calculations on the program headers and sections headers,
 * and generate any new output section information.
 */
#include	<stdio.h>
#include	<string.h>
#include	<unistd.h>
#include	<debug.h>
#include	"msg.h"
#include	"_libld.h"

/*
 * Comparison routine used by qsort() for sorting of the global symbol list
 * based off of the hashbuckets the symbol will eventually be deposited in.
 */
static int
sym_hash_compare(Sym_s_list * s1, Sym_s_list * s2)
{
	return (s1->sl_hval - s2->sl_hval);
}

/*
 * Comparison routine used by qsort() for sorting of dyn[sym|tls]sort section
 * indices based on the address of the symbols they reference. The
 * use of the global dynsort_compare_syms variable is needed because
 * we need to examine the symbols the indices reference. It is safe, because
 * the linker is single threaded.
 */
Sym *dynsort_compare_syms;

static int
dynsort_compare(const void *idx1, const void *idx2)
{
	Sym *s1 = dynsort_compare_syms + *((const Word *) idx1);
	Sym *s2 = dynsort_compare_syms + *((const Word *) idx2);

	/*
	 * Note: the logical computation for this is
	 *	(st_value1 - st_value2)
	 * However, that is only correct if the address type is smaller
	 * than a pointer. Writing it this way makes it immune to the
	 * class (32 or 64-bit) of the linker.
	 */
	return ((s1->st_value < s2->st_value) ? -1 :
	    (s1->st_value > s2->st_value));
}


/*
 * Scan the sorted symbols, and issue warnings if there are any duplicate
 * values in the list. We only do this if -zverbose is set, or we are
 * running with LD_DEBUG defined
 *
 * entry:
 *	ofl - Output file descriptor
 *	ldynsym - Pointer to start of .SUNW_ldynsym section that the
 *		sort section indexes reference.
 *	symsort - Pointer to start of .SUNW_dynsymsort or .SUNW_dyntlssort
 *		section.
 *	n - # of indices in symsort array
 *	secname - Name of the symsort section.
 *
 * exit:
 *	If the symsort section contains indexes to more than one
 *	symbol with the same address value, a warning is issued.
 */
static void
dynsort_dupwarn(Ofl_desc *ofl, Sym *ldynsym, const char *str,
    Word *symsort, Word n, const char *secname)
{
	int zverbose = (ofl->ofl_flags & FLG_OF_VERBOSE) != 0;
	Word ndx, cmp_ndx;
	Addr addr, cmp_addr;

	/* Nothing to do if -zverbose or LD_DEBUG are not active */
	if (!(zverbose || DBG_ENABLED))
		return;

	cmp_ndx = 0;
	cmp_addr = ldynsym[symsort[cmp_ndx]].st_value;
	for (ndx = 1; ndx < n; ndx++) {
		addr = ldynsym[symsort[ndx]].st_value;
		if (cmp_addr == addr) {
			if (zverbose)
				eprintf(ofl->ofl_lml, ERR_WARNING,
				    MSG_INTL(MSG_SYM_DUPSORTADDR), secname,
				    str + ldynsym[symsort[cmp_ndx]].st_name,
				    str + ldynsym[symsort[ndx]].st_name,
				    EC_ADDR(addr));
			DBG_CALL(Dbg_syms_dup_sort_addr(ofl->ofl_lml, secname,
			    str + ldynsym[symsort[cmp_ndx]].st_name,
			    str + ldynsym[symsort[ndx]].st_name,
			    EC_ADDR(addr)));
		} else {	/* Not a dup. Move reference up */
			cmp_ndx = ndx;
			cmp_addr = addr;
		}
	}
}


/*
 * Build and update any output symbol tables.  Here we work on all the symbol
 * tables at once to reduce the duplication of symbol and string manipulation.
 * Symbols and their associated strings are copied from the read-only input
 * file images to the output image and their values and index's updated in the
 * output image.
 */
static Addr
update_osym(Ofl_desc *ofl)
{
	/*
	 * There are several places in this function where we wish
	 * to insert a symbol index to the combined .SUNW_ldynsym/.dynsym
	 * symbol table into one of the two sort sections (.SUNW_dynsymsort
	 * or .SUNW_dyntlssort), if that symbol has the right attributes.
	 * This macro is used to generate the necessary code from a single
	 * specification.
	 *
	 * entry:
	 *	_sdp, _sym, _type - As per DYNSORT_COUNT. See _libld.h
	 *	_sym_ndx - Index that _sym will have in the combined
	 *		.SUNW_ldynsym/.dynsym symbol table.
	 */
#define	ADD_TO_DYNSORT(_sdp, _sym, _type, _sym_ndx) \
	{ \
		Word *_dynsort_arr, *_dynsort_ndx; \
		\
		if (dynsymsort_symtype[_type]) { \
			_dynsort_arr = dynsymsort; \
			_dynsort_ndx = &dynsymsort_ndx; \
		} else if (_type == STT_TLS) { \
			_dynsort_arr = dyntlssort; \
			_dynsort_ndx = &dyntlssort_ndx; \
		} else { \
			_dynsort_arr = NULL; \
		} \
		if ((_dynsort_arr != NULL) && DYNSORT_TEST_ATTR(_sdp, _sym)) \
			_dynsort_arr[(*_dynsort_ndx)++] = _sym_ndx; \
	}


	Listnode	*lnp1;
	Sym_desc	*sdp;
	Sym_avlnode	*sav;
	Sg_desc		*sgp, *tsgp = 0, *dsgp = 0, *esgp = 0;
	Os_desc		*osp, *iosp = 0, *fosp = 0;
	Ifl_desc	*ifl;
	Word		bssndx, etext_ndx, edata_ndx = 0, end_ndx, start_ndx;
	Word		end_abs = 0, etext_abs = 0, edata_abs;
	Word		tlsbssndx = 0, sunwbssndx = 0, sunwdata1ndx;
#if	defined(__x86) && defined(_ELF64)
	Word		lbssndx = 0;
	Addr		lbssaddr = 0;
#endif
	Addr		bssaddr, etext = 0, edata = 0, end = 0, start = 0;
	Addr		tlsbssaddr = 0;
	Addr 		sunwbssaddr = 0, sunwdata1addr;
	int		start_set = 0;
	Sym		_sym = {0}, *sym, *symtab = 0;
	Sym		*dynsym = 0, *ldynsym = 0;
	Word		symtab_ndx = 0;	/* index into .symtab */
	Word		ldynsym_ndx = 0;	/* index into .SUNW_ldynsym */
	Word		dynsym_ndx = 0;		/* index into .dynsym */
	Word		scopesym_ndx = 0; /* index into scoped symbols */
	Word		ldynscopesym_ndx = 0; /* index to ldynsym scoped syms */
	Word		*dynsymsort = NULL; /* SUNW_dynsymsort index vector */
	Word		*dyntlssort = NULL; /* SUNW_dyntlssort index vector */
	Word		dynsymsort_ndx;		/* index dynsymsort array */
	Word		dyntlssort_ndx;		/* index dyntlssort array */
	Word		*symndx;	/* Symbol index (for relocation use) */
	Word		*symshndx = 0;	/* .symtab_shndx table */
	Word		*dynshndx = 0;	/* .dynsym_shndx table */
	Word		*ldynshndx = 0;	/* .SUNW_ldynsym_shndx table */
	Word		ldynsym_cnt = 0; /* # of items in .SUNW_ldynsym */
	Str_tbl		*shstrtab;
	Str_tbl		*strtab;
	Str_tbl		*dynstr;
	Word		*hashtab;	/* hash table pointer */
	Word		*hashbkt;	/* hash table bucket pointer */
	Word		*hashchain;	/* hash table chain pointer */
	Word		hashval;	/* value of hash function */
	Wk_desc		*wkp;
	List		weak = {NULL, NULL};
	Word		flags = ofl->ofl_flags;
	Word		dtflags_1 = ofl->ofl_dtflags_1;
	Versym		*versym;
	Gottable	*gottable;	/* used for display got debugging */
					/*	information */
	Syminfo		*syminfo;
	Sym_s_list	*sorted_syms;	/* table to hold sorted symbols */
	Word		ssndx;		/* global index into sorted_syms */
	Word		scndx;		/* scoped index into sorted_syms */
	uint_t		stoff;		/* string offset */

	/*
	 * Initialize pointers to the symbol table entries and the symbol
	 * table strings.  Skip the first symbol entry and the first string
	 * table byte.  Note that if we are not generating any output symbol
	 * tables we must still generate and update an internal copies so
	 * that the relocation phase has the correct information.
	 */
	if (!(flags & FLG_OF_STRIP) || (flags & FLG_OF_RELOBJ) ||
	    ((flags & FLG_OF_STATIC) && ofl->ofl_osversym)) {
		symtab = (Sym *)ofl->ofl_ossymtab->os_outdata->d_buf;
		symtab[symtab_ndx++] = _sym;
		if (ofl->ofl_ossymshndx)
			symshndx =
			    (Word *)ofl->ofl_ossymshndx->os_outdata->d_buf;
	}
	if (OFL_ALLOW_DYNSYM(ofl)) {
		dynsym = (Sym *)ofl->ofl_osdynsym->os_outdata->d_buf;
		dynsym[dynsym_ndx++] = _sym;
		/*
		 * If we are also constructing a .SUNW_ldynsym section
		 * to contain local function symbols, then set it up too.
		 */
		if (ofl->ofl_osldynsym) {
			ldynsym = (Sym *)ofl->ofl_osldynsym->os_outdata->d_buf;
			ldynsym[ldynsym_ndx++] = _sym;
			ldynsym_cnt = 1 + ofl->ofl_dynlocscnt +
			    ofl->ofl_dynscopecnt;

			/*
			 * If there is a SUNW_ldynsym, then there may also
			 * be a .SUNW_dynsymsort and/or .SUNW_dyntlssort
			 * sections, used to collect indices of function
			 * and data symbols sorted by address order.
			 */
			if (ofl->ofl_osdynsymsort) {	/* .SUNW_dynsymsort */
				dynsymsort = (Word *)
				    ofl->ofl_osdynsymsort->os_outdata->d_buf;
				dynsymsort_ndx = 0;
			}
			if (ofl->ofl_osdyntlssort) {	/* .SUNW_dyntlssort */
				dyntlssort = (Word *)
				    ofl->ofl_osdyntlssort->os_outdata->d_buf;
				dyntlssort_ndx = 0;
			}
		}

		/*
		 * Initialize the hash table.
		 */
		hashtab = (Word *)(ofl->ofl_oshash->os_outdata->d_buf);
		hashbkt = &hashtab[2];
		hashchain = &hashtab[2 + ofl->ofl_hashbkts];
		hashtab[0] = ofl->ofl_hashbkts;
		hashtab[1] = ofl->ofl_dynshdrcnt + ofl->ofl_globcnt +
		    ofl->ofl_lregsymcnt + 1;
		if (ofl->ofl_osdynshndx)
			dynshndx =
			    (Word *)ofl->ofl_osdynshndx->os_outdata->d_buf;
		if (ofl->ofl_osldynshndx)
			ldynshndx =
			    (Word *)ofl->ofl_osldynshndx->os_outdata->d_buf;
	}

	/*
	 * symndx is the symbol index to be used for relocation processing.  It
	 * points to the relevant symtab's (.dynsym or .symtab) symbol ndx.
	 */
	if (dynsym)
		symndx = &dynsym_ndx;
	else
		symndx = &symtab_ndx;

	/*
	 * If we have version definitions initialize the version symbol index
	 * table.  There is one entry for each symbol which contains the symbols
	 * version index.
	 */
	if ((flags & (FLG_OF_VERDEF | FLG_OF_NOVERSEC)) == FLG_OF_VERDEF) {
		versym = (Versym *)ofl->ofl_osversym->os_outdata->d_buf;
		versym[0] = 0;
	} else
		versym = 0;

	/*
	 * If syminfo section exists be prepared to fill it in.
	 */
	if (ofl->ofl_ossyminfo) {
		syminfo = ofl->ofl_ossyminfo->os_outdata->d_buf;
		syminfo[0].si_flags = SYMINFO_CURRENT;
	} else
		syminfo = 0;

	/*
	 * Setup our string tables.
	 */
	shstrtab = ofl->ofl_shdrsttab;
	strtab = ofl->ofl_strtab;
	dynstr = ofl->ofl_dynstrtab;

	DBG_CALL(Dbg_syms_sec_title(ofl->ofl_lml));

	/*
	 * Put output file name to the first .symtab and .SUNW_ldynsym symbol.
	 */
	if (symtab) {
		(void) st_setstring(strtab, ofl->ofl_name, &stoff);
		sym = &symtab[symtab_ndx++];
		/* LINTED */
		sym->st_name = stoff;
		sym->st_value = 0;
		sym->st_size = 0;
		sym->st_info = ELF_ST_INFO(STB_LOCAL, STT_FILE);
		sym->st_other = 0;
		sym->st_shndx = SHN_ABS;

		if (versym && !dynsym)
			versym[1] = 0;
	}
	if (ldynsym) {
		(void) st_setstring(dynstr, ofl->ofl_name, &stoff);
		sym = &ldynsym[ldynsym_ndx];
		/* LINTED */
		sym->st_name = stoff;
		sym->st_value = 0;
		sym->st_size = 0;
		sym->st_info = ELF_ST_INFO(STB_LOCAL, STT_FILE);
		sym->st_other = 0;
		sym->st_shndx = SHN_ABS;

		/* Scoped symbols get filled in global loop below */
		ldynscopesym_ndx = ldynsym_ndx + 1;
		ldynsym_ndx += ofl->ofl_dynscopecnt;
	}

	/*
	 * If we are to display GOT summary information, then allocate
	 * the buffer to 'cache' the GOT symbols into now.
	 */
	if (DBG_ENABLED) {
		if ((ofl->ofl_gottable = gottable =
		    libld_calloc(ofl->ofl_gotcnt, sizeof (Gottable))) == 0)
		return ((Addr)S_ERROR);
	}

	/*
	 * Traverse the program headers.  Determine the last executable segment
	 * and the last data segment so that we can update etext and edata. If
	 * we have empty segments (reservations) record them for setting _end.
	 */
	for (LIST_TRAVERSE(&ofl->ofl_segs, lnp1, sgp)) {
		Phdr	*phd = &(sgp->sg_phdr);
		Os_desc	**ospp;
		Aliste	off;

		if (phd->p_type == PT_LOAD) {
			if (sgp->sg_osdescs != NULL) {
				Word	_flags = phd->p_flags & (PF_W | PF_R);

				if (_flags == PF_R)
					tsgp = sgp;
				else if (_flags == (PF_W | PF_R))
					dsgp = sgp;
			} else if (sgp->sg_flags & FLG_SG_EMPTY)
				esgp = sgp;
		}

		/*
		 * Generate a section symbol for each output section.
		 */
		for (ALIST_TRAVERSE(sgp->sg_osdescs, off, ospp)) {
			Word	sectndx;

			osp = *ospp;

			sym = &_sym;
			sym->st_value = osp->os_shdr->sh_addr;
			sym->st_info = ELF_ST_INFO(STB_LOCAL, STT_SECTION);
			/* LINTED */
			sectndx = elf_ndxscn(osp->os_scn);

			if (symtab) {
				if (sectndx >= SHN_LORESERVE) {
					symshndx[symtab_ndx] = sectndx;
					sym->st_shndx = SHN_XINDEX;
				} else {
					/* LINTED */
					sym->st_shndx = (Half)sectndx;
				}
				symtab[symtab_ndx++] = *sym;
			}

			if (dynsym && (osp->os_flags & FLG_OS_OUTREL))
				dynsym[dynsym_ndx++] = *sym;

			if ((dynsym == 0) || (osp->os_flags & FLG_OS_OUTREL)) {
				if (versym)
					versym[*symndx - 1] = 0;
				osp->os_scnsymndx = *symndx - 1;
				DBG_CALL(Dbg_syms_sec_entry(ofl->ofl_lml,
				    osp->os_scnsymndx, sgp, osp));
			}

			/*
			 * Generate the .shstrtab for this section.
			 */
			(void) st_setstring(shstrtab, osp->os_name, &stoff);
			osp->os_shdr->sh_name = (Word)stoff;

			/*
			 * Find the section index for our special symbols.
			 */
			if (sgp == tsgp) {
				/* LINTED */
				etext_ndx = elf_ndxscn(osp->os_scn);
			} else if (dsgp == sgp) {
				if (osp->os_shdr->sh_type != SHT_NOBITS) {
					/* LINTED */
					edata_ndx = elf_ndxscn(osp->os_scn);
				}
			}

			if (start_set == 0) {
				start = sgp->sg_phdr.p_vaddr;
				/* LINTED */
				start_ndx = elf_ndxscn(osp->os_scn);
				start_set++;
			}

			/*
			 * While we're here, determine whether a .init or .fini
			 * section exist.
			 */
			if ((iosp == 0) && (strcmp(osp->os_name,
			    MSG_ORIG(MSG_SCN_INIT)) == 0))
				iosp = osp;
			if ((fosp == 0) && (strcmp(osp->os_name,
			    MSG_ORIG(MSG_SCN_FINI)) == 0))
				fosp = osp;
		}
	}

	/*
	 * Add local register symbols to the .dynsym.  These are required as
	 * DT_REGISTER .dynamic entries must have a symbol to reference.
	 */
	if (ofl->ofl_regsyms && dynsym) {
		int	ndx;

		for (ndx = 0; ndx < ofl->ofl_regsymsno; ndx++) {
			Sym_desc *	rsdp;

			if ((rsdp = ofl->ofl_regsyms[ndx]) == 0)
				continue;

			if (((rsdp->sd_flags1 & FLG_SY1_HIDDEN) == 0) &&
			    (ELF_ST_BIND(rsdp->sd_sym->st_info) != STB_LOCAL))
				continue;

			dynsym[dynsym_ndx] = *(rsdp->sd_sym);
			rsdp->sd_symndx = *symndx;

			if (dynsym[dynsym_ndx].st_name) {
				(void) st_setstring(dynstr, rsdp->sd_name,
				    &stoff);
				dynsym[dynsym_ndx].st_name = stoff;
			}
			dynsym_ndx++;
		}
	}

	/*
	 * Having traversed all the output segments, warn the user if the
	 * traditional text or data segments don't exist.  Otherwise from these
	 * segments establish the values for `etext', `edata', `end', `END',
	 * and `START'.
	 */
	if (!(flags & FLG_OF_RELOBJ)) {
		Sg_desc *	sgp;

		if (tsgp)
			etext = tsgp->sg_phdr.p_vaddr + tsgp->sg_phdr.p_filesz;
		else {
			etext = (Addr)0;
			etext_ndx = SHN_ABS;
			etext_abs = 1;
			if (ofl->ofl_flags & FLG_OF_VERBOSE)
				eprintf(ofl->ofl_lml, ERR_WARNING,
				    MSG_INTL(MSG_UPD_NOREADSEG));
		}
		if (dsgp) {
			edata = dsgp->sg_phdr.p_vaddr + dsgp->sg_phdr.p_filesz;
		} else {
			edata = (Addr)0;
			edata_ndx = SHN_ABS;
			edata_abs = 1;
			if (ofl->ofl_flags & FLG_OF_VERBOSE)
				eprintf(ofl->ofl_lml, ERR_WARNING,
				    MSG_INTL(MSG_UPD_NORDWRSEG));
		}

		if (dsgp == 0) {
			if (tsgp)
				sgp = tsgp;
			else
				sgp = 0;
		} else if (tsgp == 0)
			sgp = dsgp;
		else if (dsgp->sg_phdr.p_vaddr > tsgp->sg_phdr.p_vaddr)
			sgp = dsgp;
		else if (dsgp->sg_phdr.p_vaddr < tsgp->sg_phdr.p_vaddr)
			sgp = tsgp;
		else {
			/*
			 * One of the segments must be of zero size.
			 */
			if (tsgp->sg_phdr.p_memsz)
				sgp = tsgp;
			else
				sgp = dsgp;
		}

		if (esgp && (esgp->sg_phdr.p_vaddr > sgp->sg_phdr.p_vaddr))
			sgp = esgp;

		if (sgp) {
			end = sgp->sg_phdr.p_vaddr + sgp->sg_phdr.p_memsz;

			/*
			 * If the last loadable segment is a read-only segment,
			 * then the application which uses the symbol _end to
			 * find the beginning of writable heap area may cause
			 * segmentation violation. We adjust the value of the
			 * _end to skip to the next page boundary.
			 *
			 * 6401812 System interface which returs beginning
			 *	   heap would be nice.
			 * When the above RFE is implemented, the changes below
			 * could be changed in a better way.
			 */
			if ((sgp->sg_phdr.p_flags & PF_W) == 0)
				end = (Addr)S_ROUND(end, sysconf(_SC_PAGESIZE));

			/*
			 * If we're dealing with a memory reservation there are
			 * no sections to establish an index for _end, so assign
			 * it as an absolute.
			 */
			if (sgp->sg_osdescs != NULL) {
				Os_desc	**ospp;
				Alist	*alp = sgp->sg_osdescs;
				Aliste	last = alp->al_next - alp->al_size;

				/*
				 * Determine the last section for this segment.
				 */
				/* LINTED */
				ospp = (Os_desc **)((char *)alp + last);
				/* LINTED */
				end_ndx = elf_ndxscn((*ospp)->os_scn);
			} else {
				end_ndx = SHN_ABS;
				end_abs = 1;
			}
		} else {
			end = (Addr) 0;
			end_ndx = SHN_ABS;
			end_abs = 1;
			eprintf(ofl->ofl_lml, ERR_WARNING,
			    MSG_INTL(MSG_UPD_NOSEG));
		}
	}

	DBG_CALL(Dbg_syms_up_title(ofl->ofl_lml));

	/*
	 * Initialize the scoped symbol table entry point.  This is for all
	 * the global symbols that have been scoped to locals and will be
	 * filled in during global symbol processing so that we don't have
	 * to traverse the globals symbol hash array more than once.
	 */
	if (symtab) {
		scopesym_ndx = symtab_ndx;
		symtab_ndx += ofl->ofl_scopecnt;
	}

	/*
	 * Assign .sunwdata1 information
	 */
	if (ofl->ofl_issunwdata1) {
		osp = ofl->ofl_issunwdata1->is_osdesc;
		sunwdata1addr = (Addr)(osp->os_shdr->sh_addr +
		    ofl->ofl_issunwdata1->is_indata->d_off);
		/* LINTED */
		sunwdata1ndx = elf_ndxscn(osp->os_scn);
		ofl->ofl_sunwdata1ndx = osp->os_scnsymndx;
	}

	/*
	 * If we are generating a .symtab collect all the local symbols,
	 * assigning a new virtual address or displacement (value).
	 */
	for (LIST_TRAVERSE(&ofl->ofl_objs, lnp1, ifl)) {
		Xword		lndx, local;
		Is_desc *	isc;

		/*
		 * Check that we have local symbols to process.  If the user
		 * has indicated scoping then scan the global symbols also
		 * looking for entries from this file to reduce to locals.
		 */
		if ((local = ifl->ifl_locscnt) == 0)
			continue;

		for (lndx = 1; lndx < local; lndx++) {
			Listnode	*lnp2;
			Gotndx		*gnp;
			uchar_t		type;
			Word		*_symshndx;
			int		enter_in_symtab, enter_in_ldynsym;
			int		update_done;

			sdp = ifl->ifl_oldndx[lndx];
			sym = sdp->sd_sym;

#if	defined(__sparc)
			/*
			 * Assign a got offset if necessary.
			 */
			if (ld_assign_got(ofl, sdp) == S_ERROR)
				return ((Addr)S_ERROR);
#elif	defined(__x86)
/* nothing to do */
#else
#error Unknown architecture!
#endif
			if (DBG_ENABLED) {
				for (LIST_TRAVERSE(&sdp->sd_GOTndxs,
				    lnp2, gnp)) {
					gottable->gt_sym = sdp;
					gottable->gt_gndx.gn_gotndx =
					    gnp->gn_gotndx;
					gottable->gt_gndx.gn_addend =
					    gnp->gn_addend;
					gottable++;
				}
			}

			if ((type = ELF_ST_TYPE(sym->st_info)) == STT_SECTION)
				continue;

			/*
			 * Ignore any symbols that have been marked as invalid
			 * during input processing.  Providing these aren't used
			 * for relocation they'll just be dropped from the
			 * output image.
			 */
			if (sdp->sd_flags & FLG_SY_INVALID)
				continue;

			/*
			 * If the section that this symbol was associated
			 * with has been discarded - then we discard
			 * the local symbol along with it.
			 */
			if (sdp->sd_flags & FLG_SY_ISDISC)
				continue;

			/*
			 * Generate an output symbol to represent this input
			 * symbol.  Even if the symbol table is to be stripped
			 * we still need to update any local symbols that are
			 * used during relocation.
			 */
			enter_in_symtab = symtab &&
			    (!(ofl->ofl_flags1 & FLG_OF1_REDLSYM) ||
			    (sdp->sd_psyminfo));
			enter_in_ldynsym = ldynsym && sdp->sd_name &&
			    ldynsym_symtype[type] &&
			    !(ofl->ofl_flags1 & FLG_OF1_REDLSYM);
			_symshndx = 0;
			if (enter_in_symtab) {
				if (!dynsym)
					sdp->sd_symndx = *symndx;
				symtab[symtab_ndx] = *sym;
				/*
				 * Provided this isn't an unnamed register
				 * symbol, update its name.
				 */
				if (((sdp->sd_flags & FLG_SY_REGSYM) == 0) ||
				    symtab[symtab_ndx].st_name) {
					(void) st_setstring(strtab,
					    sdp->sd_name, &stoff);
					symtab[symtab_ndx].st_name = stoff;
				}
				sdp->sd_flags &= ~FLG_SY_CLEAN;
				if (symshndx)
					_symshndx = &symshndx[symtab_ndx];
				sdp->sd_sym = sym = &symtab[symtab_ndx++];

				if ((sdp->sd_flags & FLG_SY_SPECSEC) &&
				    (sym->st_shndx == SHN_ABS) &&
				    !enter_in_ldynsym)
					continue;
			} else if (enter_in_ldynsym) {
				/*
				 * Not using symtab, but we do have ldynsym
				 * available.
				 */
				ldynsym[ldynsym_ndx] = *sym;
				(void) st_setstring(dynstr, sdp->sd_name,
				    &stoff);
				ldynsym[ldynsym_ndx].st_name = stoff;

				sdp->sd_flags &= ~FLG_SY_CLEAN;
				if (ldynshndx)
					_symshndx = &ldynshndx[ldynsym_ndx];
				sdp->sd_sym = sym = &ldynsym[ldynsym_ndx];
				/* Add it to sort section if it qualifies */
				ADD_TO_DYNSORT(sdp, sym, type, ldynsym_ndx);
				ldynsym_ndx++;
			} else {	/* Not using symtab or ldynsym */
				/*
				 * If this symbol requires modifying to provide
				 * for a relocation or move table update, make
				 * a copy of it.
				 */
				if (!(sdp->sd_flags & FLG_SY_UPREQD) &&
				    !(sdp->sd_psyminfo))
					continue;
				if ((sdp->sd_flags & FLG_SY_SPECSEC) &&
				    (sym->st_shndx == SHN_ABS))
					continue;

				if (ld_sym_copy(sdp) == S_ERROR)
					return ((Addr)S_ERROR);
				sym = sdp->sd_sym;
			}

			/*
			 * Update the symbols contents if necessary.
			 */
			update_done = 0;
			if (type == STT_FILE) {
				sdp->sd_shndx = sym->st_shndx = SHN_ABS;
				sdp->sd_flags |= FLG_SY_SPECSEC;
				update_done = 1;
			}

			/*
			 * If we are expanding the locally bound partially
			 * initialized symbols, then update the address here.
			 */
			if (ofl->ofl_issunwdata1 &&
			    (sdp->sd_flags & FLG_SY_PAREXPN) && !update_done) {
				static	Addr	laddr = 0;

				sym->st_shndx = sunwdata1ndx;
				sdp->sd_isc = ofl->ofl_issunwdata1;
				if (ofl->ofl_flags & FLG_OF_RELOBJ) {
					sym->st_value = sunwdata1addr;
				} else {
					sym->st_value = laddr;
					laddr += sym->st_size;
				}
				sunwdata1addr += sym->st_size;
			}

			/*
			 * If this isn't an UNDEF symbol (ie. an input section
			 * is associated), update the symbols value and index.
			 */
			if (((isc = sdp->sd_isc) != 0) && !update_done) {
				Word	sectndx;

				osp = isc->is_osdesc;
				/* LINTED */
				sym->st_value +=
				    (Off)_elf_getxoff(isc->is_indata);
				if (!(flags & FLG_OF_RELOBJ)) {
					sym->st_value += osp->os_shdr->sh_addr;
					/*
					 * TLS symbols are relative to
					 * the TLS segment.
					 */
					if ((type == STT_TLS) &&
					    (ofl->ofl_tlsphdr)) {
						sym->st_value -=
						    ofl->ofl_tlsphdr->p_vaddr;
					}
				}
				/* LINTED */
				if ((sdp->sd_shndx = sectndx =
				    elf_ndxscn(osp->os_scn)) >= SHN_LORESERVE) {
					if (_symshndx) {
						*_symshndx = sectndx;
					}
					sym->st_shndx = SHN_XINDEX;
				} else {
					/* LINTED */
					sym->st_shndx = sectndx;
				}
			}

			/*
			 * If entering the symbol in both the symtab and the
			 * ldynsym, then the one in symtab needs to be
			 * copied to ldynsym. If it is only in the ldynsym,
			 * then the code above already set it up and we have
			 * nothing more to do here.
			 */
			if (enter_in_symtab && enter_in_ldynsym) {
				ldynsym[ldynsym_ndx] = *sym;
				(void) st_setstring(dynstr, sdp->sd_name,
				    &stoff);
				ldynsym[ldynsym_ndx].st_name = stoff;

				if (_symshndx && ldynshndx)
					ldynshndx[ldynsym_ndx] = *_symshndx;

				/* Add it to sort section if it qualifies */
				ADD_TO_DYNSORT(sdp, sym, type, ldynsym_ndx);

				ldynsym_ndx++;
			}
		}
	}

	/*
	 * Two special symbols are `_init' and `_fini'.  If these are supplied
	 * by crti.o then they are used to represent the total concatenation of
	 * the `.init' and `.fini' sections.
	 *
	 * First, determine whether any .init or .fini sections exist.  If these
	 * sections exist when a dynamic object is being built, but no `_init'
	 * or `_fini' symbols are found, then the user is probably building this
	 * object directly from ld(1) rather than using a compiler driver that
	 * provides the symbols via crt's.
	 *
	 * If the .init or .fini section exist, and their associated symbols,
	 * determine the size of the sections and updated the symbols value
	 * accordingly.
	 */
	if (((sdp = ld_sym_find(MSG_ORIG(MSG_SYM_INIT_U), SYM_NOHASH, 0,
	    ofl)) != NULL) && (sdp->sd_ref == REF_REL_NEED) && sdp->sd_isc &&
	    (sdp->sd_isc->is_osdesc == iosp)) {
		if (ld_sym_copy(sdp) == S_ERROR)
			return ((Addr)S_ERROR);
		sdp->sd_sym->st_size = sdp->sd_isc->is_osdesc->os_shdr->sh_size;

	} else if (iosp && !(flags & FLG_OF_RELOBJ)) {
		eprintf(ofl->ofl_lml, ERR_WARNING, MSG_INTL(MSG_SYM_NOCRT),
		    MSG_ORIG(MSG_SYM_INIT_U), MSG_ORIG(MSG_SCN_INIT));
	}

	if (((sdp = ld_sym_find(MSG_ORIG(MSG_SYM_FINI_U), SYM_NOHASH, 0,
	    ofl)) != NULL) && (sdp->sd_ref == REF_REL_NEED) && sdp->sd_isc &&
	    (sdp->sd_isc->is_osdesc == fosp)) {
		if (ld_sym_copy(sdp) == S_ERROR)
			return ((Addr)S_ERROR);
		sdp->sd_sym->st_size = sdp->sd_isc->is_osdesc->os_shdr->sh_size;

	} else if (fosp && !(flags & FLG_OF_RELOBJ)) {
		eprintf(ofl->ofl_lml, ERR_WARNING, MSG_INTL(MSG_SYM_NOCRT),
		    MSG_ORIG(MSG_SYM_FINI_U), MSG_ORIG(MSG_SCN_FINI));
	}

	/*
	 * Assign .bss information for use with updating COMMON symbols.
	 */
	if (ofl->ofl_isbss) {
		osp = ofl->ofl_isbss->is_osdesc;

		bssaddr = osp->os_shdr->sh_addr +
		    (Off)_elf_getxoff(ofl->ofl_isbss->is_indata);
		/* LINTED */
		bssndx = elf_ndxscn(osp->os_scn);
	}

#if	(defined(__i386) || defined(__amd64)) && defined(_ELF64)
	/*
	 * Assign .lbss information for use with updating LCOMMON symbols.
	 */
	if (ofl->ofl_islbss) {
		osp = ofl->ofl_islbss->is_osdesc;

		lbssaddr = osp->os_shdr->sh_addr +
		    (Off)_elf_getxoff(ofl->ofl_islbss->is_indata);
		/* LINTED */
		lbssndx = elf_ndxscn(osp->os_scn);
	}
#endif

	/*
	 * Assign .tlsbss information for use with updating COMMON symbols.
	 */
	if (ofl->ofl_istlsbss) {
		osp = ofl->ofl_istlsbss->is_osdesc;
		tlsbssaddr = osp->os_shdr->sh_addr +
		    (Off)_elf_getxoff(ofl->ofl_istlsbss->is_indata);
		/* LINTED */
		tlsbssndx = elf_ndxscn(osp->os_scn);
	}

	/*
	 * Assign .SUNW_bss information for use with updating COMMON symbols.
	 */
	if (ofl->ofl_issunwbss) {
		osp = ofl->ofl_issunwbss->is_osdesc;
		sunwbssaddr = (Addr)(osp->os_shdr->sh_addr +
		    ofl->ofl_issunwbss->is_indata->d_off);
		/* LINTED */
		sunwbssndx = elf_ndxscn(osp->os_scn);
	}


	if ((sorted_syms = libld_calloc(ofl->ofl_globcnt +
	    ofl->ofl_elimcnt + ofl->ofl_scopecnt, sizeof (*sorted_syms))) == 0)
		return ((Addr)S_ERROR);

	scndx = 0;
	ssndx = ofl->ofl_scopecnt + ofl->ofl_elimcnt;

	/*
	 * Traverse the internal symbol table updating information and
	 * allocating common.
	 */
	for (sav = avl_first(&ofl->ofl_symavl); sav;
	    sav = AVL_NEXT(&ofl->ofl_symavl, sav)) {
		Sym *	symptr;
		int	local;
		int	restore;

		sdp = sav->sav_symdesc;

		/*
		 * Ignore any symbols that have been marked as invalid during
		 * input processing.  Providing these aren't used for
		 * relocation, they will be dropped from the output image.
		 */
		if (sdp->sd_flags & FLG_SY_INVALID) {
			DBG_CALL(Dbg_syms_old(ofl, sdp));
			DBG_CALL(Dbg_syms_ignore(ofl, sdp));
			continue;
		}

		/*
		 * Only needed symbols are copied to the output symbol table.
		 */
		if (sdp->sd_ref == REF_DYN_SEEN)
			continue;

		if ((sdp->sd_flags1 & FLG_SY1_HIDDEN) &&
		    (flags & FLG_OF_PROCRED))
			local = 1;
		else
			local = 0;

		if (local || (ofl->ofl_hashbkts == 0)) {
			sorted_syms[scndx++].sl_sdp = sdp;
		} else {
			sorted_syms[ssndx].sl_hval = sdp->sd_aux->sa_hash %
			    ofl->ofl_hashbkts;
			sorted_syms[ssndx].sl_sdp = sdp;
			ssndx++;
		}

		/*
		 * Note - expand the COMMON symbols here because an address
		 * must be assigned to them in the same order that space was
		 * calculated in sym_validate().  If this ordering isn't
		 * followed differing alignment requirements can throw us all
		 * out of whack.
		 *
		 * The expanded .bss global symbol is handled here as well.
		 *
		 * The actual adding entries into the symbol table still occurs
		 * below in hashbucket order.
		 */
		symptr = sdp->sd_sym;
		restore = 0;
		if ((sdp->sd_flags & FLG_SY_PAREXPN) ||
		    ((sdp->sd_flags & FLG_SY_SPECSEC) &&
		    (sdp->sd_shndx = symptr->st_shndx) == SHN_COMMON)) {

			/*
			 * An expanded symbol goes to .sunwdata1.
			 *
			 * A partial initialized global symbol within a shared
			 * object goes to .sunwbss.
			 *
			 * Assign COMMON allocations to .bss.
			 *
			 * Otherwise leave it as is.
			 */
			if (sdp->sd_flags & FLG_SY_PAREXPN) {
				restore = 1;
				sdp->sd_shndx = sunwdata1ndx;
				sdp->sd_flags &= ~FLG_SY_SPECSEC;
				symptr->st_value = (Xword) S_ROUND(
				    sunwdata1addr, symptr->st_value);
				sunwdata1addr = symptr->st_value +
				    symptr->st_size;
				sdp->sd_isc = ofl->ofl_issunwdata1;
				sdp->sd_flags |= FLG_SY_COMMEXP;

			} else if ((sdp->sd_psyminfo != (Psym_info *)NULL) &&
			    (ofl->ofl_flags & FLG_OF_SHAROBJ) &&
			    (ELF_ST_BIND(symptr->st_info) != STB_LOCAL)) {
				restore = 1;
				sdp->sd_shndx = sunwbssndx;
				sdp->sd_flags &= ~FLG_SY_SPECSEC;
				symptr->st_value = (Xword)S_ROUND(sunwbssaddr,
				    symptr->st_value);
				sunwbssaddr = symptr->st_value +
				    symptr->st_size;
				sdp->sd_isc = ofl->ofl_issunwbss;
				sdp->sd_flags |= FLG_SY_COMMEXP;

			} else if (ELF_ST_TYPE(symptr->st_info) != STT_TLS &&
			    (local || !(flags & FLG_OF_RELOBJ))) {
				restore = 1;
				sdp->sd_shndx = bssndx;
				sdp->sd_flags &= ~FLG_SY_SPECSEC;
				symptr->st_value = (Xword)S_ROUND(bssaddr,
				    symptr->st_value);
				bssaddr = symptr->st_value + symptr->st_size;
				sdp->sd_isc = ofl->ofl_isbss;
				sdp->sd_flags |= FLG_SY_COMMEXP;

			} else if (ELF_ST_TYPE(symptr->st_info) == STT_TLS &&
			    (local || !(flags & FLG_OF_RELOBJ))) {
				restore = 1;
				sdp->sd_shndx = tlsbssndx;
				sdp->sd_flags &= ~FLG_SY_SPECSEC;
				symptr->st_value = (Xword)S_ROUND(tlsbssaddr,
				    symptr->st_value);
				tlsbssaddr = symptr->st_value + symptr->st_size;
				sdp->sd_isc = ofl->ofl_istlsbss;
				sdp->sd_flags |= FLG_SY_COMMEXP;
				/*
				 * TLS symbols are relative to the TLS segment.
				 */
				symptr->st_value -= ofl->ofl_tlsphdr->p_vaddr;
			}
#if	(defined(__i386) || defined(__amd64)) && defined(_ELF64)
		} else if ((sdp->sd_flags & FLG_SY_SPECSEC) &&
		    ((sdp->sd_shndx = symptr->st_shndx) ==
		    SHN_X86_64_LCOMMON) &&
		    ((local || !(flags & FLG_OF_RELOBJ)))) {
			restore = 1;
			sdp->sd_shndx = lbssndx;
			sdp->sd_flags &= ~FLG_SY_SPECSEC;
			symptr->st_value = (Xword)S_ROUND(lbssaddr,
			    symptr->st_value);
			lbssaddr = symptr->st_value + symptr->st_size;
			sdp->sd_isc = ofl->ofl_islbss;
			sdp->sd_flags |= FLG_SY_COMMEXP;
#endif
		}

		if (restore != 0) {
			uchar_t		type, bind;

			/*
			 * Make sure this COMMON symbol is returned to the same
			 * binding as was defined in the original relocatable
			 * object reference.
			 */
			type = ELF_ST_TYPE(symptr->st_info);
			if (sdp->sd_flags & FLG_SY_GLOBREF)
				bind = STB_GLOBAL;
			else
				bind = STB_WEAK;

			symptr->st_info = ELF_ST_INFO(bind, type);
		}
	}

	if (ofl->ofl_hashbkts) {
		qsort(sorted_syms + ofl->ofl_scopecnt + ofl->ofl_elimcnt,
		    ofl->ofl_globcnt, sizeof (Sym_s_list),
		    (int (*)(const void *, const void *))sym_hash_compare);
	}

	for (ssndx = 0; ssndx < (ofl->ofl_elimcnt + ofl->ofl_scopecnt +
	    ofl->ofl_globcnt); ssndx++) {
		const char	*name;
		Sym		*sym;
		Sym_aux		*sap;
		Half		spec;
		int		local = 0, dynlocal = 0, enter_in_symtab;
		Listnode	*lnp2;
		Gotndx		*gnp;
		Word		sectndx;

		sdp = sorted_syms[ssndx].sl_sdp;
		sectndx = 0;

		if (symtab)
			enter_in_symtab = 1;
		else
			enter_in_symtab = 0;

		/*
		 * Assign a got offset if necessary.
		 */
#if	defined(__sparc)
		if (ld_assign_got(ofl, sdp) == S_ERROR)
			return ((Addr)S_ERROR);
#elif	defined(__x86)
/* nothing to do */
#else
#error Unknown architecture!
#endif

		if (DBG_ENABLED) {
			for (LIST_TRAVERSE(&sdp->sd_GOTndxs, lnp2, gnp)) {
				gottable->gt_sym = sdp;
				gottable->gt_gndx.gn_gotndx = gnp->gn_gotndx;
				gottable->gt_gndx.gn_addend = gnp->gn_addend;
				gottable++;
			}

			if (sdp->sd_aux && sdp->sd_aux->sa_PLTGOTndx) {
				gottable->gt_sym = sdp;
				gottable->gt_gndx.gn_gotndx =
				    sdp->sd_aux->sa_PLTGOTndx;
				gottable++;
			}
		}


		/*
		 * If this symbol has been marked as being reduced to local
		 * scope then it will have to be placed in the scoped portion
		 * of the .symtab.  Retain the appropriate index for use in
		 * version symbol indexing and relocation.
		 */
		if ((sdp->sd_flags1 & (FLG_SY1_HIDDEN | FLG_SY1_ELIM)) &&
		    (flags & FLG_OF_PROCRED)) {
			local = 1;
			if (!(sdp->sd_flags1 & FLG_SY1_ELIM) && !dynsym)
				sdp->sd_symndx = scopesym_ndx;
			else
				sdp->sd_symndx = 0;

			if (sdp->sd_flags1 & FLG_SY1_ELIM) {
				enter_in_symtab = 0;
			} else if (ldynsym && sdp->sd_sym->st_name &&
			    ldynsym_symtype[
			    ELF_ST_TYPE(sdp->sd_sym->st_info)]) {
				dynlocal = 1;
			}
		} else {
			sdp->sd_symndx = *symndx;
		}

		/*
		 * Copy basic symbol and string information.
		 */
		name = sdp->sd_name;
		sap = sdp->sd_aux;

		/*
		 * If we require to record version symbol indexes, update the
		 * associated version symbol information for all defined
		 * symbols.  If a version definition is required any zero value
		 * symbol indexes would have been flagged as undefined symbol
		 * errors, however if we're just scoping these need to fall into
		 * the base of global symbols.
		 */
		if (sdp->sd_symndx && versym) {
			Half	vndx = 0;

			if (sdp->sd_flags & FLG_SY_MVTOCOMM)
				vndx = VER_NDX_GLOBAL;
			else if (sdp->sd_ref == REF_REL_NEED) {
				Half	symflags1 = sdp->sd_flags1;

				vndx = sap->sa_overndx;
				if ((vndx == 0) &&
				    (sdp->sd_sym->st_shndx != SHN_UNDEF)) {
					if (symflags1 & FLG_SY1_HIDDEN)
						vndx = VER_NDX_LOCAL;
					else
						vndx = VER_NDX_GLOBAL;
				}
			}
			versym[sdp->sd_symndx] = vndx;
		}

		/*
		 * If we are creating the .syminfo section then set per symbol
		 * flags here.
		 */
		if (sdp->sd_symndx && syminfo &&
		    !(sdp->sd_flags & FLG_SY_NOTAVAIL)) {
			int	ndx = sdp->sd_symndx;
			List	*sip = &(ofl->ofl_syminfsyms);

			if (sdp->sd_flags & FLG_SY_MVTOCOMM)
				/*
				 * Identify a copy relocation symbol.
				 */
				syminfo[ndx].si_flags |= SYMINFO_FLG_COPY;

			if (sdp->sd_ref == REF_DYN_NEED) {
				/*
				 * A reference is bound to a needed dependency.
				 * Save this symbol descriptor, as its boundto
				 * element will need updating after the .dynamic
				 * section has been created.  Flag whether this
				 * reference is lazy loadable, and if a direct
				 * binding is to be established.
				 */
				if (list_appendc(sip, sdp) == 0)
					return (0);

				syminfo[ndx].si_flags |= SYMINFO_FLG_DIRECT;
				if (sdp->sd_flags & FLG_SY_LAZYLD)
					syminfo[ndx].si_flags |=
					    SYMINFO_FLG_LAZYLOAD;

				/*
				 * Enable direct symbol bindings if:
				 *
				 *  .	Symbol was identified with the DIRECT
				 *	keyword in a mapfile.
				 *
				 *  .	Symbol reference has been bound to a
				 * 	dependency which was specified as
				 *	requiring direct bindings with -zdirect.
				 *
				 *  .	All symbol references are required to
				 *	use direct bindings via -Bdirect.
				 */
				if (sdp->sd_flags1 & FLG_SY1_DIR)
					syminfo[ndx].si_flags |=
					    SYMINFO_FLG_DIRECTBIND;

			} else if ((sdp->sd_flags & FLG_SY_EXTERN) &&
			    (sdp->sd_sym->st_shndx == SHN_UNDEF)) {
				/*
				 * If this symbol has been explicitly defined
				 * as external, and remains unresolved, mark
				 * it as external.
				 */
				syminfo[ndx].si_boundto = SYMINFO_BT_EXTERN;

			} else if ((sdp->sd_flags & FLG_SY_PARENT) &&
			    (sdp->sd_sym->st_shndx == SHN_UNDEF)) {
				/*
				 * If this symbol has been explicitly defined
				 * to be a reference to a parent object,
				 * indicate whether a direct binding should be
				 * established.
				 */
				syminfo[ndx].si_flags |= SYMINFO_FLG_DIRECT;
				syminfo[ndx].si_boundto = SYMINFO_BT_PARENT;
				if (sdp->sd_flags1 & FLG_SY1_DIR)
					syminfo[ndx].si_flags |=
					    SYMINFO_FLG_DIRECTBIND;

			} else if (sdp->sd_flags & FLG_SY_STDFLTR) {
				/*
				 * A filter definition.  Although this symbol
				 * can only be a stub, it might be necessary to
				 * prevent external direct bindings.
				 */
				syminfo[ndx].si_flags |= SYMINFO_FLG_FILTER;
				if (sdp->sd_flags1 & FLG_SY1_NDIR)
					syminfo[ndx].si_flags |=
					    SYMINFO_FLG_NOEXTDIRECT;

			} else if (sdp->sd_flags & FLG_SY_AUXFLTR) {
				/*
				 * An auxiliary filter definition.  By nature,
				 * this definition is direct, in that should the
				 * filtee lookup fail, we'll fall back to this
				 * object.  It may still be necesssary to
				 * prevent external direct bindings.
				 */
				syminfo[ndx].si_flags |= SYMINFO_FLG_AUXILIARY;
				if (sdp->sd_flags1 & FLG_SY1_NDIR)
					syminfo[ndx].si_flags |=
					    SYMINFO_FLG_NOEXTDIRECT;

			} else if ((sdp->sd_ref == REF_REL_NEED) &&
			    (sdp->sd_sym->st_shndx != SHN_UNDEF)) {

				/*
				 * This definition exists within the object
				 * being created.  Flag whether it is necessary
				 * to prevent external direct bindings.
				 */
				if (sdp->sd_flags1 & FLG_SY1_NDIR) {
					syminfo[ndx].si_boundto =
					    SYMINFO_BT_NONE;
					syminfo[ndx].si_flags |=
					    SYMINFO_FLG_NOEXTDIRECT;
				}

				/*
				 * Indicate that this symbol is acting as an
				 * individual interposer.
				 */
				if (sdp->sd_flags & FLG_SY_INTPOSE) {
					syminfo[ndx].si_flags |=
					    SYMINFO_FLG_INTERPOSE;
				}

				/*
				 * If external bindings are allowed, or this is
				 * a translator symbol, indicate the binding,
				 * and a direct binding if necessary.
				 */
				if (((sdp->sd_flags1 & FLG_SY1_NDIR) == 0) ||
				    ((dtflags_1 & DF_1_TRANS) && sdp->sd_aux &&
				    sdp->sd_aux->sa_bindto)) {

					syminfo[ndx].si_flags |=
					    SYMINFO_FLG_DIRECT;

					if (sdp->sd_flags1 & FLG_SY1_DIR)
						syminfo[ndx].si_flags |=
						    SYMINFO_FLG_DIRECTBIND;

					/*
					 * If this is a translator, the symbols
					 * boundto element will indicate the
					 * dependency to which it should resolve
					 * rather than itself.  Save this info
					 * for updating after the .dynamic
					 * section has been created.
					 */
					if ((dtflags_1 & DF_1_TRANS) &&
					    sdp->sd_aux &&
					    sdp->sd_aux->sa_bindto) {
						if (list_appendc(sip, sdp) == 0)
							return (0);
					} else {
						syminfo[ndx].si_boundto =
						    SYMINFO_BT_SELF;
					}
				}
			}
		}

		/*
		 * Note that the `sym' value is reset to be one of the new
		 * symbol table entries.  This symbol will be updated further
		 * depending on the type of the symbol.  Process the .symtab
		 * first, followed by the .dynsym, thus the `sym' value will
		 * remain as the .dynsym value when the .dynsym is present.
		 * This ensures that any versioning symbols st_name value will
		 * be appropriate for the string table used by version
		 * entries.
		 */
		if (enter_in_symtab) {
			Word	_symndx;

			if (local)
				_symndx = scopesym_ndx;
			else
				_symndx = symtab_ndx;

			symtab[_symndx] = *sdp->sd_sym;
			sdp->sd_sym = sym = &symtab[_symndx];
			(void) st_setstring(strtab, name, &stoff);
			sym->st_name = stoff;
		}
		if (dynlocal) {
			ldynsym[ldynscopesym_ndx] = *sdp->sd_sym;
			sdp->sd_sym = sym = &ldynsym[ldynscopesym_ndx];
			(void) st_setstring(dynstr, name, &stoff);
			ldynsym[ldynscopesym_ndx].st_name = stoff;
			/* Add it to sort section if it qualifies */
			ADD_TO_DYNSORT(sdp, sym, ELF_ST_TYPE(sym->st_info),
			    ldynscopesym_ndx);
		}

		if (dynsym && !local) {
			dynsym[dynsym_ndx] = *sdp->sd_sym;

			/*
			 * Provided this isn't an unnamed register symbol,
			 * update the symbols name and hash value.
			 */
			if (((sdp->sd_flags & FLG_SY_REGSYM) == 0) ||
			    dynsym[dynsym_ndx].st_name) {
				(void) st_setstring(dynstr, name, &stoff);
				dynsym[dynsym_ndx].st_name = stoff;

				if (stoff) {
					Word _hashndx;

					hashval =
					    sap->sa_hash % ofl->ofl_hashbkts;

					/* LINTED */
					if (_hashndx = hashbkt[hashval]) {
						while (hashchain[_hashndx]) {
							_hashndx =
							    hashchain[_hashndx];
						}
						hashchain[_hashndx] =
						    sdp->sd_symndx;
					} else {
						hashbkt[hashval] =
						    sdp->sd_symndx;
					}
				}
			}
			sdp->sd_sym = sym = &dynsym[dynsym_ndx];

			/*
			 * Add it to sort section if it qualifies.
			 * The indexes in that section are relative to the
			 * the adjacent SUNW_ldynsym/dymsym pair, so we
			 * add the number of items in SUNW_ldynsym to the
			 * dynsym index.
			 */
			ADD_TO_DYNSORT(sdp, sym, ELF_ST_TYPE(sym->st_info),
			    ldynsym_cnt + dynsym_ndx);
		}
		if (!enter_in_symtab && (!dynsym || (local && !dynlocal))) {
			if (!(sdp->sd_flags & FLG_SY_UPREQD))
				continue;
			sym = sdp->sd_sym;
		} else
			sdp->sd_flags &= ~FLG_SY_CLEAN;


		/*
		 * If we have a weak data symbol for which we need the real
		 * symbol also, save this processing until later.
		 *
		 * The exception to this is if the weak/strong have PLT's
		 * assigned to them.  In that case we don't do the post-weak
		 * processing because the PLT's must be maintained so that we
		 * can do 'interpositioning' on both of the symbols.
		 */
		if ((sap->sa_linkndx) &&
		    (ELF_ST_BIND(sym->st_info) == STB_WEAK) &&
		    (!sap->sa_PLTndx)) {
			Sym_desc *	_sdp =
			    sdp->sd_file->ifl_oldndx[sap->sa_linkndx];

			if (_sdp->sd_ref != REF_DYN_SEEN) {
				if ((wkp =
				    libld_calloc(sizeof (Wk_desc), 1)) == 0)
					return ((Addr)S_ERROR);

				if (enter_in_symtab) {
					if (local)
						wkp->wk_symtab =
						    &symtab[scopesym_ndx];
					else
						wkp->wk_symtab =
						    &symtab[symtab_ndx];
				}
				if (dynsym) {
					if (!local) {
						wkp->wk_dynsym =
						    &dynsym[dynsym_ndx];
					} else if (dynlocal) {
						wkp->wk_dynsym =
						    &ldynsym[ldynscopesym_ndx];
					}
				}
				wkp->wk_weak = sdp;
				wkp->wk_alias = _sdp;

				if (!(list_appendc(&weak, wkp)))
					return ((Addr)S_ERROR);

				if (enter_in_symtab)
					if (local)
						scopesym_ndx++;
					else
						symtab_ndx++;
				if (dynsym) {
					if (!local) {
						dynsym_ndx++;
					} else if (dynlocal) {
						ldynscopesym_ndx++;
					}
				}
				continue;
			}
		}

		DBG_CALL(Dbg_syms_old(ofl, sdp));

		spec = NULL;
		/*
		 * assign new symbol value.
		 */
		sectndx = sdp->sd_shndx;
		if (sectndx == SHN_UNDEF) {
			if (((sdp->sd_flags & FLG_SY_REGSYM) == 0) &&
			    (sym->st_value != 0)) {
				eprintf(ofl->ofl_lml, ERR_WARNING,
				    MSG_INTL(MSG_SYM_NOTNULL),
				    demangle(name), sdp->sd_file->ifl_name);
			}

			/*
			 * Undefined weak global, if we are generating a static
			 * executable, output as an absolute zero.  Otherwise
			 * leave it as is, ld.so.1 will skip symbols of this
			 * type (this technique allows applications and
			 * libraries to test for the existence of a symbol as an
			 * indication of the presence or absence of certain
			 * functionality).
			 */
			if (((flags & (FLG_OF_STATIC | FLG_OF_EXEC)) ==
			    (FLG_OF_STATIC | FLG_OF_EXEC)) &&
			    (ELF_ST_BIND(sym->st_info) == STB_WEAK)) {
				sdp->sd_flags |= FLG_SY_SPECSEC;
				sdp->sd_shndx = sectndx = SHN_ABS;
			}
		} else if ((sdp->sd_flags & FLG_SY_SPECSEC) &&
		    (sectndx == SHN_COMMON)) {
			/* COMMONs have already been processed */
			/* EMPTY */
			;
		} else {
			if ((sdp->sd_flags & FLG_SY_SPECSEC) &&
			    (sectndx == SHN_ABS))
				spec = sdp->sd_aux->sa_symspec;

			/* LINTED */
			if (sdp->sd_flags & FLG_SY_COMMEXP) {
				/*
				 * This is (or was) a COMMON symbol which was
				 * processed above - no processing
				 * required here.
				 */
				;
			} else if (sdp->sd_ref == REF_DYN_NEED) {
				uchar_t	type, bind;

				sectndx = SHN_UNDEF;
				sym->st_value = 0;
				sym->st_size = 0;

				/*
				 * Make sure this undefined symbol is returned
				 * to the same binding as was defined in the
				 * original relocatable object reference.
				 */
				type = ELF_ST_TYPE(sym-> st_info);
				if (sdp->sd_flags & FLG_SY_GLOBREF)
					bind = STB_GLOBAL;
				else
					bind = STB_WEAK;

				sym->st_info = ELF_ST_INFO(bind, type);

			} else if (((sdp->sd_flags & FLG_SY_SPECSEC) == 0) &&
			    (sdp->sd_ref == REF_REL_NEED)) {
				osp = sdp->sd_isc->is_osdesc;
				/* LINTED */
				sectndx = elf_ndxscn(osp->os_scn);

				/*
				 * In an executable, the new symbol value is the
				 * old value (offset into defining section) plus
				 * virtual address of defining section.  In a
				 * relocatable, the new value is the old value
				 * plus the displacement of the section within
				 * the file.
				 */
				/* LINTED */
				sym->st_value +=
				    (Off)_elf_getxoff(sdp->sd_isc->is_indata);

				if (!(flags & FLG_OF_RELOBJ)) {
					sym->st_value += osp->os_shdr->sh_addr;
					/*
					 * TLS symbols are relative to
					 * the TLS segment.
					 */
					if ((ELF_ST_TYPE(sym->st_info) ==
					    STT_TLS) && (ofl->ofl_tlsphdr))
						sym->st_value -=
						    ofl->ofl_tlsphdr->p_vaddr;
				}
			}
		}

		if (spec) {
			switch (spec) {
			case SDAUX_ID_ETEXT:
				sym->st_value = etext;
				sectndx = etext_ndx;
				if (etext_abs)
					sdp->sd_flags |= FLG_SY_SPECSEC;
				else
					sdp->sd_flags &= ~FLG_SY_SPECSEC;
				break;
			case SDAUX_ID_EDATA:
				sym->st_value = edata;
				sectndx = edata_ndx;
				if (edata_abs)
					sdp->sd_flags |= FLG_SY_SPECSEC;
				else
					sdp->sd_flags &= ~FLG_SY_SPECSEC;
				break;
			case SDAUX_ID_END:
				sym->st_value = end;
				sectndx = end_ndx;
				if (end_abs)
					sdp->sd_flags |= FLG_SY_SPECSEC;
				else
					sdp->sd_flags &= ~FLG_SY_SPECSEC;
				break;
			case SDAUX_ID_START:
				sym->st_value = start;
				sectndx = start_ndx;
				sdp->sd_flags &= ~FLG_SY_SPECSEC;
				break;
			case SDAUX_ID_DYN:
				if (flags & FLG_OF_DYNAMIC) {
					sym->st_value = ofl->
					    ofl_osdynamic->os_shdr->sh_addr;
					/* LINTED */
					sectndx = elf_ndxscn(
					    ofl->ofl_osdynamic->os_scn);
					sdp->sd_flags &= ~FLG_SY_SPECSEC;
				}
				break;
			case SDAUX_ID_PLT:
				if (ofl->ofl_osplt) {
					sym->st_value = ofl->
					    ofl_osplt->os_shdr->sh_addr;
					/* LINTED */
					sectndx = elf_ndxscn(
					    ofl->ofl_osplt->os_scn);
					sdp->sd_flags &= ~FLG_SY_SPECSEC;
				}
				break;
			case SDAUX_ID_GOT:
				/*
				 * Symbol bias for negative growing tables is
				 * stored in symbol's value during
				 * allocate_got().
				 */
				sym->st_value += ofl->
				    ofl_osgot->os_shdr->sh_addr;
				/* LINTED */
				sectndx = elf_ndxscn(ofl->
				    ofl_osgot->os_scn);
				sdp->sd_flags &= ~FLG_SY_SPECSEC;
				break;
			default:
				/* NOTHING */
				;
			}
		}

		/*
		 * If a plt index has been assigned to an undefined function,
		 * update the symbols value to the appropriate .plt address.
		 */
		if ((flags & FLG_OF_DYNAMIC) && (flags & FLG_OF_EXEC) &&
		    (sdp->sd_file) &&
		    (sdp->sd_file->ifl_ehdr->e_type == ET_DYN) &&
		    (ELF_ST_TYPE(sym->st_info) == STT_FUNC) &&
		    !(flags & FLG_OF_BFLAG)) {
			if (sap->sa_PLTndx)
				sym->st_value = ld_calc_plt_addr(sdp, ofl);
		}

		/*
		 * Finish updating the symbols.
		 */

		/*
		 * Sym Update: if scoped local - set local binding
		 */
		if (local)
			sym->st_info = ELF_ST_INFO(STB_LOCAL,
			    ELF_ST_TYPE(sym->st_info));

		/*
		 * Sym Updated: If both the .symtab and .dynsym
		 * are present then we've actually updated the information in
		 * the .dynsym, therefore copy this same information to the
		 * .symtab entry.
		 */
		sdp->sd_shndx = sectndx;
		if (enter_in_symtab && dynsym && (!local || dynlocal)) {
			Word _symndx = dynlocal ? scopesym_ndx : symtab_ndx;

			symtab[_symndx].st_value = sym->st_value;
			symtab[_symndx].st_size = sym->st_size;
			symtab[_symndx].st_info = sym->st_info;
			symtab[_symndx].st_other = sym->st_other;
		}


		if (enter_in_symtab) {
			Word	_symndx;

			if (local)
				_symndx = scopesym_ndx++;
			else
				_symndx = symtab_ndx++;
			if (((sdp->sd_flags & FLG_SY_SPECSEC) == 0) &&
			    (sectndx >= SHN_LORESERVE)) {
				assert(symshndx != 0);
				symshndx[_symndx] = sectndx;
				symtab[_symndx].st_shndx = SHN_XINDEX;
			} else {
				/* LINTED */
				symtab[_symndx].st_shndx = (Half)sectndx;
			}
		}

		if (dynsym && (!local || dynlocal)) {
			/*
			 * dynsym and ldynsym are distinct tables, so
			 * we use indirection to access the right one
			 * and the related extended section index array.
			 */
			Word	_symndx;
			Sym	*_dynsym;
			Word	*_dynshndx;

			if (!local) {
				_symndx = dynsym_ndx++;
				_dynsym = dynsym;
				_dynshndx = dynshndx;
			} else {
				_symndx = ldynscopesym_ndx++;
				_dynsym = ldynsym;
				_dynshndx = ldynshndx;
			}
			if (((sdp->sd_flags & FLG_SY_SPECSEC) == 0) &&
			    (sectndx >= SHN_LORESERVE)) {
				assert(_dynshndx != 0);
				_dynshndx[_symndx] = sectndx;
				_dynsym[_symndx].st_shndx = SHN_XINDEX;
			} else {
				/* LINTED */
				_dynsym[_symndx].st_shndx = (Half)sectndx;
			}
		}

		DBG_CALL(Dbg_syms_new(ofl, sym, sdp));
	}

	/*
	 * Now that all the symbols have been processed update any weak symbols
	 * information (ie. copy all information except `st_name').  As both
	 * symbols will be represented in the output, return the weak symbol to
	 * its correct type.
	 */
	for (LIST_TRAVERSE(&weak, lnp1, wkp)) {
		Sym_desc *	sdp, * _sdp;
		Sym *		sym, * _sym, * __sym;
		uchar_t		bind;

		sdp = wkp->wk_weak;
		_sdp = wkp->wk_alias;
		_sym = _sdp->sd_sym;

		sdp->sd_flags |= FLG_SY_WEAKDEF;

		/*
		 * If the symbol definition has been scoped then assign it to
		 * be local, otherwise if it's from a shared object then we need
		 * to maintain the binding of the original reference.
		 */
		if (sdp->sd_flags1 & FLG_SY1_HIDDEN) {
			if (flags & FLG_OF_PROCRED)
				bind = STB_LOCAL;
			else
				bind = STB_WEAK;
		} else if ((sdp->sd_ref == REF_DYN_NEED) &&
		    (sdp->sd_flags & FLG_SY_GLOBREF))
			bind = STB_GLOBAL;
		else
			bind = STB_WEAK;

		DBG_CALL(Dbg_syms_old(ofl, sdp));
		if ((sym = wkp->wk_symtab) != 0) {
			sym = wkp->wk_symtab;
			sym->st_value = _sym->st_value;
			sym->st_size = _sym->st_size;
			sym->st_other = _sym->st_other;
			sym->st_shndx = _sym->st_shndx;
			sym->st_info = ELF_ST_INFO(bind,
			    ELF_ST_TYPE(sym->st_info));
			__sym = sym;
		}
		if ((sym = wkp->wk_dynsym) != 0) {
			sym = wkp->wk_dynsym;
			sym->st_value = _sym->st_value;
			sym->st_size = _sym->st_size;
			sym->st_other = _sym->st_other;
			sym->st_shndx = _sym->st_shndx;
			sym->st_info = ELF_ST_INFO(bind,
			    ELF_ST_TYPE(sym->st_info));
			__sym = sym;
		}
		DBG_CALL(Dbg_syms_new(ofl, __sym, sdp));
	}

	/*
	 * Now display GOT debugging information if required.
	 */
	DBG_CALL(Dbg_got_display(ofl, 0, 0));

	/*
	 * Update the section headers information. sh_info is
	 * supposed to contain the offset at which the first
	 * global symbol resides in the symbol table, while
	 * sh_link contains the section index of the associated
	 * string table.
	 */
	if (symtab) {
		Shdr	*shdr = ofl->ofl_ossymtab->os_shdr;

		shdr->sh_info = ofl->ofl_shdrcnt + ofl->ofl_locscnt +
		    ofl->ofl_scopecnt + 2;
		/* LINTED */
		shdr->sh_link = (Word)elf_ndxscn(ofl->ofl_osstrtab->os_scn);
		if (symshndx) {
			shdr = ofl->ofl_ossymshndx->os_shdr;
			shdr->sh_link =
			    (Word)elf_ndxscn(ofl->ofl_ossymtab->os_scn);
		}
	}
	if (dynsym) {
		Shdr	*shdr = ofl->ofl_osdynsym->os_shdr;

		shdr->sh_info = 1 + ofl->ofl_dynshdrcnt + ofl->ofl_lregsymcnt;
		/* LINTED */
		shdr->sh_link = (Word)elf_ndxscn(ofl->ofl_osdynstr->os_scn);

		ofl->ofl_oshash->os_shdr->sh_link =
		    /* LINTED */
		    (Word)elf_ndxscn(ofl->ofl_osdynsym->os_scn);
		if (dynshndx) {
			shdr = ofl->ofl_osdynshndx->os_shdr;
			shdr->sh_link =
			    (Word)elf_ndxscn(ofl->ofl_osdynsym->os_scn);
		}
	}
	if (ldynsym) {
		Shdr	*shdr = ofl->ofl_osldynsym->os_shdr;

		/* ldynsym has no globals, so give index one past the end */
		shdr->sh_info = ldynsym_ndx;

		/*
		 * The ldynsym and dynsym must be adjacent. The
		 * idea is that rtld should be able to start with
		 * the ldynsym and march straight through the end
		 * of dynsym, seeing them as a single symbol table,
		 * despite the fact that they are in distinct sections.
		 * Ensure that this happened correctly.
		 *
		 * Note that I use ldynsym_ndx here instead of the
		 * computation I used to set the section size
		 * (found in ldynsym_cnt). The two will agree, unless
		 * we somehow miscounted symbols or failed to insert them
		 * all. Using ldynsym_ndx here catches that error in
		 * addition to checking for adjacency.
		 */
		assert(dynsym == (ldynsym + ldynsym_ndx));


		/* LINTED */
		shdr->sh_link = (Word)elf_ndxscn(ofl->ofl_osdynstr->os_scn);

		if (ldynshndx) {
			shdr = ofl->ofl_osldynshndx->os_shdr;
			shdr->sh_link =
			    (Word)elf_ndxscn(ofl->ofl_osldynsym->os_scn);
		}

		/*
		 * The presence of .SUNW_ldynsym means that there may be
		 * associated sort sections, one for regular symbols
		 * and the other for TLS. Each sort section needs the
		 * following done:
		 *	- Section header link references .SUNW_ldynsym
		 *	- Should have received the expected # of items
		 *	- Sorted by increasing address
		 */
		if (ofl->ofl_osdynsymsort) {	/* .SUNW_dynsymsort */
			ofl->ofl_osdynsymsort->os_shdr->sh_link =
			    (Word)elf_ndxscn(ofl->ofl_osldynsym->os_scn);
			assert(ofl->ofl_dynsymsortcnt == dynsymsort_ndx);

			if (dynsymsort_ndx > 1) {
				dynsort_compare_syms = ldynsym;
				qsort(dynsymsort, dynsymsort_ndx,
				    sizeof (*dynsymsort), dynsort_compare);
				dynsort_dupwarn(ofl, ldynsym,
				    st_getstrbuf(dynstr),
				    dynsymsort, dynsymsort_ndx,
				    MSG_ORIG(MSG_SCN_DYNSYMSORT));
			}
		}
		if (ofl->ofl_osdyntlssort) {	/* .SUNW_dyntlssort */
			ofl->ofl_osdyntlssort->os_shdr->sh_link =
			    (Word)elf_ndxscn(ofl->ofl_osldynsym->os_scn);
			assert(ofl->ofl_dyntlssortcnt == dyntlssort_ndx);

			if (dyntlssort_ndx > 1) {
				dynsort_compare_syms = ldynsym;
				qsort(dyntlssort, dyntlssort_ndx,
				    sizeof (*dyntlssort), dynsort_compare);
				dynsort_dupwarn(ofl, ldynsym,
				    st_getstrbuf(dynstr),
				    dyntlssort, dyntlssort_ndx,
				    MSG_ORIG(MSG_SCN_DYNTLSSORT));
			}
		}
	}

	/*
	 * Used by ld.so.1 only.
	 */
	return (etext);

#undef ADD_TO_DYNSORT
}

/*
 * Build the dynamic section.
 */
static int
update_odynamic(Ofl_desc *ofl)
{
	Listnode	*lnp;
	Ifl_desc	*ifl;
	Sym_desc	*sdp;
	Shdr		*shdr;
	Dyn		*_dyn = (Dyn *)ofl->ofl_osdynamic->os_outdata->d_buf;
	Dyn		*dyn;
	Str_tbl		*dynstr;
	uint_t		stoff;
	Word		flags = ofl->ofl_flags;
	Word		cnt;

	dynstr = ofl->ofl_dynstrtab;
	ofl->ofl_osdynamic->os_shdr->sh_link =
	    /* LINTED */
	    (Word)elf_ndxscn(ofl->ofl_osdynstr->os_scn);

	dyn = _dyn;

	for (LIST_TRAVERSE(&ofl->ofl_sos, lnp, ifl)) {
		if ((ifl->ifl_flags &
		    (FLG_IF_IGNORE | FLG_IF_DEPREQD)) == FLG_IF_IGNORE)
			continue;

		/*
		 * Create and set up the DT_POSFLAG_1 entry here if required.
		 */
		if ((ifl->ifl_flags & (FLG_IF_LAZYLD|FLG_IF_GRPPRM)) &&
		    (ifl->ifl_flags & (FLG_IF_NEEDED))) {
			dyn->d_tag = DT_POSFLAG_1;
			if (ifl->ifl_flags & FLG_IF_LAZYLD)
				dyn->d_un.d_val = DF_P1_LAZYLOAD;
			if (ifl->ifl_flags & FLG_IF_GRPPRM)
				dyn->d_un.d_val |= DF_P1_GROUPPERM;
			dyn++;
		}

		if (ifl->ifl_flags & (FLG_IF_NEEDED | FLG_IF_NEEDSTR))
			dyn->d_tag = DT_NEEDED;
		else
			continue;

		(void) st_setstring(dynstr, ifl->ifl_soname, &stoff);
		dyn->d_un.d_val = stoff;
		/* LINTED */
		ifl->ifl_neededndx = (Half)(((uintptr_t)dyn - (uintptr_t)_dyn) /
		    sizeof (Dyn));
		dyn++;
	}

	if (ofl->ofl_dtsfltrs) {
		Dfltr_desc *	dftp;
		Aliste		off;

		for (ALIST_TRAVERSE(ofl->ofl_dtsfltrs, off, dftp)) {
			if (dftp->dft_flag == FLG_SY_AUXFLTR)
				dyn->d_tag = DT_SUNW_AUXILIARY;
			else
				dyn->d_tag = DT_SUNW_FILTER;

			(void) st_setstring(dynstr, dftp->dft_str, &stoff);
			dyn->d_un.d_val = stoff;
			dftp->dft_ndx = (Half)(((uintptr_t)dyn -
			    (uintptr_t)_dyn) / sizeof (Dyn));
			dyn++;
		}
	}
	if (((sdp = ld_sym_find(MSG_ORIG(MSG_SYM_INIT_U),
	    SYM_NOHASH, 0, ofl)) != NULL) && (sdp->sd_ref == REF_REL_NEED) &&
	    (sdp->sd_sym->st_shndx != SHN_UNDEF)) {
		dyn->d_tag = DT_INIT;
		dyn->d_un.d_ptr = sdp->sd_sym->st_value;
		dyn++;
	}
	if (((sdp = ld_sym_find(MSG_ORIG(MSG_SYM_FINI_U),
	    SYM_NOHASH, 0, ofl)) != NULL) && (sdp->sd_ref == REF_REL_NEED) &&
	    (sdp->sd_sym->st_shndx != SHN_UNDEF)) {
		dyn->d_tag = DT_FINI;
		dyn->d_un.d_ptr = sdp->sd_sym->st_value;
		dyn++;
	}
	if (ofl->ofl_soname) {
		dyn->d_tag = DT_SONAME;
		(void) st_setstring(dynstr, ofl->ofl_soname, &stoff);
		dyn->d_un.d_val = stoff;
		dyn++;
	}
	if (ofl->ofl_filtees) {
		if (flags & FLG_OF_AUX) {
			dyn->d_tag = DT_AUXILIARY;
		} else {
			dyn->d_tag = DT_FILTER;
		}
		(void) st_setstring(dynstr, ofl->ofl_filtees, &stoff);
		dyn->d_un.d_val = stoff;
		dyn++;
	}
	if (ofl->ofl_rpath) {
		(void) st_setstring(dynstr, ofl->ofl_rpath, &stoff);
		dyn->d_tag = DT_RUNPATH;
		dyn->d_un.d_val = stoff;
		dyn++;
		dyn->d_tag = DT_RPATH;
		dyn->d_un.d_val = stoff;
		dyn++;
	}
	if (ofl->ofl_config) {
		dyn->d_tag = DT_CONFIG;
		(void) st_setstring(dynstr, ofl->ofl_config, &stoff);
		dyn->d_un.d_val = stoff;
		dyn++;
	}
	if (ofl->ofl_depaudit) {
		dyn->d_tag = DT_DEPAUDIT;
		(void) st_setstring(dynstr, ofl->ofl_depaudit, &stoff);
		dyn->d_un.d_val = stoff;
		dyn++;
	}
	if (ofl->ofl_audit) {
		dyn->d_tag = DT_AUDIT;
		(void) st_setstring(dynstr, ofl->ofl_audit, &stoff);
		dyn->d_un.d_val = stoff;
		dyn++;
	}

	/*
	 * The following DT_* entries do not apply to relocatable objects.
	 */
	if (!(flags & FLG_OF_RELOBJ)) {

		dyn->d_tag = DT_HASH;
		dyn->d_un.d_ptr = ofl->ofl_oshash->os_shdr->sh_addr;
		dyn++;

		shdr = ofl->ofl_osdynstr->os_shdr;
		dyn->d_tag = DT_STRTAB;
		dyn->d_un.d_ptr = shdr->sh_addr;
		dyn++;

		dyn->d_tag = DT_STRSZ;
		dyn->d_un.d_ptr = shdr->sh_size;
		dyn++;

		shdr = ofl->ofl_osdynsym->os_shdr;
		dyn->d_tag = DT_SYMTAB;
		dyn->d_un.d_ptr = shdr->sh_addr;
		dyn++;

		dyn->d_tag = DT_SYMENT;
		dyn->d_un.d_ptr = shdr->sh_entsize;
		dyn++;

		if (ofl->ofl_osldynsym) {
			/*
			 * We have arranged for the .SUNW_ldynsym data to be
			 * immediately in front of the .dynsym data.
			 * This means that you could start at the top
			 * of .SUNW_ldynsym and see the data for both tables
			 * without a break. This is the view we want to
			 * provide for DT_SUNW_SYMTAB, which is why we
			 * add the lengths together.
			 */
			Shdr *lshdr = ofl->ofl_osldynsym->os_shdr;
			dyn->d_tag = DT_SUNW_SYMTAB;
			dyn->d_un.d_ptr = lshdr->sh_addr;
			dyn++;

			dyn->d_tag = DT_SUNW_SYMSZ;
			dyn->d_un.d_val = lshdr->sh_size + shdr->sh_size;
			dyn++;
		}

		if (ofl->ofl_osdynsymsort || ofl->ofl_osdyntlssort) {
			dyn->d_tag = DT_SUNW_SORTENT;
			dyn->d_un.d_val = sizeof (Word);
			dyn++;
		}

		if (ofl->ofl_osdynsymsort) {
			dyn->d_tag = DT_SUNW_SYMSORT;
			dyn->d_un.d_ptr =
			    ofl->ofl_osdynsymsort->os_shdr->sh_addr;
			dyn++;

			dyn->d_tag = DT_SUNW_SYMSORTSZ;
			dyn->d_un.d_val =
			    ofl->ofl_osdynsymsort->os_shdr->sh_size;
			dyn++;
		}

		if (ofl->ofl_osdyntlssort) {
			dyn->d_tag = DT_SUNW_TLSSORT;
			dyn->d_un.d_ptr =
			    ofl->ofl_osdyntlssort->os_shdr->sh_addr;
			dyn++;

			dyn->d_tag = DT_SUNW_TLSSORTSZ;
			dyn->d_un.d_val =
			    ofl->ofl_osdyntlssort->os_shdr->sh_size;
			dyn++;
		}

		/*
		 * Reserve the DT_CHECKSUM entry.  Its value will be filled in
		 * after the complete image is built.
		 */
		dyn->d_tag = DT_CHECKSUM;
		ofl->ofl_checksum = &dyn->d_un.d_val;
		dyn++;

		/*
		 * Versioning sections: DT_VERDEF and DT_VERNEED.
		 *
		 * The Solaris ld does not produce DT_VERSYM, but the GNU ld
		 * does, in order to support their style of versioning, which
		 * differs from ours:
		 *
		 *	- The top bit of the 16-bit Versym index is
		 *		not part of the version, but is interpreted
		 *		as a "hidden bit".
		 *
		 *	- External (SHN_UNDEF) symbols can have non-zero
		 *		Versym values, which specify versions in
		 *		referenced objects, via the Verneed section.
		 *
		 *	- The vna_other field of the Vernaux structures
		 *		found in the Verneed section are not zero as
		 *		with Solaris, but instead contain the version
		 *		index to be used by Versym indices to reference
		 *		the given external version.
		 *
		 * The Solaris ld, rtld, and elfdump programs all interpret the
		 * presence of DT_VERSYM as meaning that GNU versioning rules
		 * apply to the given file. If DT_VERSYM is not present,
		 * then Solaris versioning rules apply. If we should ever need
		 * to change our ld so that it does issue DT_VERSYM, then
		 * this rule for detecting GNU versioning will no longer work.
		 * In that case, we will have to invent a way to explicitly
		 * specify the style of versioning in use, perhaps via a
		 * new dynamic entry named something like DT_SUNW_VERSIONSTYLE,
		 * where the d_un.d_val value specifies which style is to be
		 * used.
		 */
		if ((flags & (FLG_OF_VERDEF | FLG_OF_NOVERSEC)) ==
		    FLG_OF_VERDEF) {
			shdr = ofl->ofl_osverdef->os_shdr;
			dyn->d_tag = DT_VERDEF;
			dyn->d_un.d_ptr = shdr->sh_addr;
			dyn++;
			dyn->d_tag = DT_VERDEFNUM;
			dyn->d_un.d_ptr = shdr->sh_info;
			dyn++;
		}
		if ((flags & (FLG_OF_VERNEED | FLG_OF_NOVERSEC)) ==
		    FLG_OF_VERNEED) {
			shdr = ofl->ofl_osverneed->os_shdr;
			dyn->d_tag = DT_VERNEED;
			dyn->d_un.d_ptr = shdr->sh_addr;
			dyn++;
			dyn->d_tag = DT_VERNEEDNUM;
			dyn->d_un.d_ptr = shdr->sh_info;
			dyn++;
		}

		if ((ofl->ofl_flags1 & FLG_OF1_RELCNT) &&
		    ofl->ofl_relocrelcnt) {
			dyn->d_tag = M_REL_DT_COUNT;
			dyn->d_un.d_val = ofl->ofl_relocrelcnt;
			dyn++;
		}
		if (flags & FLG_OF_TEXTREL) {
			/*
			 * Only the presence of this entry is used in this
			 * implementation, not the value stored.
			 */
			dyn->d_tag = DT_TEXTREL;
			dyn->d_un.d_val = 0;
			dyn++;
		}

		if (ofl->ofl_osfiniarray) {
			shdr = ofl->ofl_osfiniarray->os_shdr;

			dyn->d_tag = DT_FINI_ARRAY;
			dyn->d_un.d_ptr = shdr->sh_addr;
			dyn++;

			dyn->d_tag = DT_FINI_ARRAYSZ;
			dyn->d_un.d_val = shdr->sh_size;
			dyn++;
		}

		if (ofl->ofl_osinitarray) {
			shdr = ofl->ofl_osinitarray->os_shdr;

			dyn->d_tag = DT_INIT_ARRAY;
			dyn->d_un.d_ptr = shdr->sh_addr;
			dyn++;

			dyn->d_tag = DT_INIT_ARRAYSZ;
			dyn->d_un.d_val = shdr->sh_size;
			dyn++;
		}

		if (ofl->ofl_ospreinitarray) {
			shdr = ofl->ofl_ospreinitarray->os_shdr;

			dyn->d_tag = DT_PREINIT_ARRAY;
			dyn->d_un.d_ptr = shdr->sh_addr;
			dyn++;

			dyn->d_tag = DT_PREINIT_ARRAYSZ;
			dyn->d_un.d_val = shdr->sh_size;
			dyn++;
		}

		if (ofl->ofl_pltcnt) {
			shdr =  ofl->ofl_osplt->os_relosdesc->os_shdr;

			dyn->d_tag = DT_PLTRELSZ;
			dyn->d_un.d_ptr = shdr->sh_size;
			dyn++;
			dyn->d_tag = DT_PLTREL;
			dyn->d_un.d_ptr = M_REL_DT_TYPE;
			dyn++;
			dyn->d_tag = DT_JMPREL;
			dyn->d_un.d_ptr = shdr->sh_addr;
			dyn++;
		}
		if (ofl->ofl_pltpad) {
			shdr =  ofl->ofl_osplt->os_shdr;

			dyn->d_tag = DT_PLTPAD;
			if (ofl->ofl_pltcnt) {
				dyn->d_un.d_ptr = shdr->sh_addr +
				    M_PLT_RESERVSZ +
				    ofl->ofl_pltcnt * M_PLT_ENTSIZE;
			} else
				dyn->d_un.d_ptr = shdr->sh_addr;
			dyn++;
			dyn->d_tag = DT_PLTPADSZ;
			dyn->d_un.d_val = ofl->ofl_pltpad * M_PLT_ENTSIZE;
			dyn++;
		}
		if (ofl->ofl_relocsz) {
			dyn->d_tag = M_REL_DT_TYPE;
			dyn->d_un.d_ptr = ofl->ofl_osrelhead->os_shdr->sh_addr;
			dyn++;
			dyn->d_tag = M_REL_DT_SIZE;
			dyn->d_un.d_ptr = ofl->ofl_relocsz;
			dyn++;
			dyn->d_tag = M_REL_DT_ENT;
			if (ofl->ofl_osrelhead->os_shdr->sh_type == SHT_REL)
				dyn->d_un.d_ptr = sizeof (Rel);
			else
				dyn->d_un.d_ptr = sizeof (Rela);
			dyn++;
		}
		if (ofl->ofl_ossyminfo) {
			shdr = ofl->ofl_ossyminfo->os_shdr;
			dyn->d_tag = DT_SYMINFO;
			dyn->d_un.d_ptr = shdr->sh_addr;
			dyn++;
			dyn->d_tag = DT_SYMINSZ;
			dyn->d_un.d_val = shdr->sh_size;
			dyn++;
			dyn->d_tag = DT_SYMINENT;
			dyn->d_un.d_val = sizeof (Syminfo);
			dyn++;
		}
		if (ofl->ofl_osmove) {
			Os_desc *	osp;

			dyn->d_tag = DT_MOVEENT;
			osp = ofl->ofl_osmove;
			dyn->d_un.d_val = osp->os_shdr->sh_entsize;
			dyn++;
			dyn->d_tag = DT_MOVESZ;
			dyn->d_un.d_val = osp->os_shdr->sh_size;
			dyn++;
			dyn->d_tag = DT_MOVETAB;
			dyn->d_un.d_val = osp->os_shdr->sh_addr;
			dyn++;
		}
		if (ofl->ofl_regsymcnt) {
			int	ndx;

			for (ndx = 0; ndx < ofl->ofl_regsymsno; ndx++) {
				if ((sdp = ofl->ofl_regsyms[ndx]) == 0)
					continue;

				dyn->d_tag = M_DT_REGISTER;
				dyn->d_un.d_val = sdp->sd_symndx;
				dyn++;
			}
		}

		for (LIST_TRAVERSE(&ofl->ofl_rtldinfo, lnp, sdp)) {
			dyn->d_tag = DT_SUNW_RTLDINF;
			dyn->d_un.d_ptr = sdp->sd_sym->st_value;
			dyn++;
		}

		if (ofl->ofl_osdynamic->os_sgdesc &&
		    (ofl->ofl_osdynamic->os_sgdesc->sg_phdr.p_flags & PF_W)) {
			if (ofl->ofl_osinterp) {
				dyn->d_tag = DT_DEBUG;
				dyn->d_un.d_ptr = 0;
				dyn++;
			}

			dyn->d_tag = DT_FEATURE_1;
			if (ofl->ofl_osmove)
				dyn->d_un.d_val = 0;
			else
				dyn->d_un.d_val = DTF_1_PARINIT;
			dyn++;
		}

		if (ofl->ofl_oscap) {
			dyn->d_tag = DT_SUNW_CAP;
			dyn->d_un.d_val = ofl->ofl_oscap->os_shdr->sh_addr;
			dyn++;
		}
	}

	if (flags & FLG_OF_SYMBOLIC) {
		dyn->d_tag = DT_SYMBOLIC;
		dyn->d_un.d_val = 0;
		dyn++;
	}
	dyn->d_tag = DT_FLAGS;
	dyn->d_un.d_val = ofl->ofl_dtflags;
	dyn++;

	/*
	 * If -Bdirect was specified, but some NODIRECT symbols were specified
	 * via a mapfile, or -znodirect was used on the command line, then
	 * clear the DF_1_DIRECT flag.  The resultant object will use per-symbol
	 * direct bindings rather than be enabled for global direct bindings.
	 */
	if (ofl->ofl_flags1 & FLG_OF1_NDIRECT) {
		ofl->ofl_dtflags_1 &= ~DF_1_DIRECT;
		ofl->ofl_dtflags_1 |= DF_1_NODIRECT;
	}

	dyn->d_tag = DT_FLAGS_1;
	dyn->d_un.d_val = ofl->ofl_dtflags_1;
	dyn++;

	dyn->d_tag = DT_SUNW_STRPAD;
	dyn->d_un.d_val = DYNSTR_EXTRA_PAD;
	dyn++;

	ld_mach_update_odynamic(ofl, &dyn);

	for (cnt = 1 + DYNAMIC_EXTRA_ELTS; cnt--; dyn++) {
		dyn->d_tag = DT_NULL;
		dyn->d_un.d_val = 0;
	}

	/*
	 * Ensure that we wrote the right number of entries. If not,
	 * we either miscounted in make_dynamic(), or we did something wrong
	 * in this function.
	 */
	assert((ofl->ofl_osdynamic->os_shdr->sh_size /
	    ofl->ofl_osdynamic->os_shdr->sh_entsize) ==
	    ((uintptr_t)dyn - (uintptr_t)_dyn) / sizeof (*dyn));

	return (1);
}

/*
 * Build the version definition section
 */
static int
update_overdef(Ofl_desc *ofl)
{
	Listnode	*lnp1, *lnp2;
	Ver_desc	*vdp, *_vdp;
	Verdef		*vdf, *_vdf;
	int		num = 0;
	Os_desc		*strosp, *symosp;

	/*
	 * Traverse the version descriptors and update the version structures
	 * to point to the dynstr name in preparation for building the version
	 * section structure.
	 */
	for (LIST_TRAVERSE(&ofl->ofl_verdesc, lnp1, vdp)) {
		Sym_desc *	sdp;

		if (vdp->vd_flags & VER_FLG_BASE) {
			const char	*name = vdp->vd_name;
			uint_t		stoff;

			/*
			 * Create a new string table entry to represent the base
			 * version name (there is no corresponding symbol for
			 * this).
			 */
			if (!(ofl->ofl_flags & FLG_OF_DYNAMIC)) {
				(void) st_setstring(ofl->ofl_strtab,
				    name, &stoff);
				/* LINTED */
				vdp->vd_name = (const char *)(uintptr_t)stoff;
			} else {
				(void) st_setstring(ofl->ofl_dynstrtab,
				    name, &stoff);
				/* LINTED */
				vdp->vd_name = (const char *)(uintptr_t)stoff;
			}
		} else {
			sdp = ld_sym_find(vdp->vd_name, vdp->vd_hash, 0, ofl);
			/* LINTED */
			vdp->vd_name = (const char *)
			    (uintptr_t)sdp->sd_sym->st_name;
		}
	}

	_vdf = vdf = (Verdef *)ofl->ofl_osverdef->os_outdata->d_buf;

	/*
	 * Traverse the version descriptors and update the version section to
	 * reflect each version and its associated dependencies.
	 */
	for (LIST_TRAVERSE(&ofl->ofl_verdesc, lnp1, vdp)) {
		Half		cnt = 1;
		Verdaux *	vdap, * _vdap;

		_vdap = vdap = (Verdaux *)(vdf + 1);

		vdf->vd_version = VER_DEF_CURRENT;
		vdf->vd_flags	= vdp->vd_flags & MSK_VER_USER;
		vdf->vd_ndx	= vdp->vd_ndx;
		vdf->vd_hash	= vdp->vd_hash;

		/* LINTED */
		vdap->vda_name = (uintptr_t)vdp->vd_name;
		vdap++;
		/* LINTED */
		_vdap->vda_next = (Word)((uintptr_t)vdap - (uintptr_t)_vdap);

		/*
		 * Traverse this versions dependency list generating the
		 * appropriate version dependency entries.
		 */
		for (LIST_TRAVERSE(&vdp->vd_deps, lnp2, _vdp)) {
			/* LINTED */
			vdap->vda_name = (uintptr_t)_vdp->vd_name;
			_vdap = vdap;
			vdap++, cnt++;
			/* LINTED */
			_vdap->vda_next = (Word)((uintptr_t)vdap -
			    (uintptr_t)_vdap);
		}
		_vdap->vda_next = 0;

		/*
		 * Record the versions auxiliary array offset and the associated
		 * dependency count.
		 */
		/* LINTED */
		vdf->vd_aux = (Word)((uintptr_t)(vdf + 1) - (uintptr_t)vdf);
		vdf->vd_cnt = cnt;

		/*
		 * Record the next versions offset and update the version
		 * pointer.  Remember the previous version offset as the very
		 * last structures next pointer should be null.
		 */
		_vdf = vdf;
		vdf = (Verdef *)vdap, num++;
		/* LINTED */
		_vdf->vd_next = (Word)((uintptr_t)vdf - (uintptr_t)_vdf);
	}
	_vdf->vd_next = 0;

	/*
	 * Record the string table association with the version definition
	 * section, and the symbol table associated with the version symbol
	 * table (the actual contents of the version symbol table are filled
	 * in during symbol update).
	 */
	if ((ofl->ofl_flags & FLG_OF_RELOBJ) ||
	    (ofl->ofl_flags & FLG_OF_STATIC)) {
		strosp = ofl->ofl_osstrtab;
		symosp = ofl->ofl_ossymtab;
	} else {
		strosp = ofl->ofl_osdynstr;
		symosp = ofl->ofl_osdynsym;
	}
	/* LINTED */
	ofl->ofl_osverdef->os_shdr->sh_link = (Word)elf_ndxscn(strosp->os_scn);
	/* LINTED */
	ofl->ofl_osversym->os_shdr->sh_link = (Word)elf_ndxscn(symosp->os_scn);

	/*
	 * The version definition sections `info' field is used to indicate the
	 * number of entries in this section.
	 */
	ofl->ofl_osverdef->os_shdr->sh_info = num;

	return (1);
}

/*
 * Build the version needed section
 */
static int
update_overneed(Ofl_desc *ofl)
{
	Listnode	*lnp;
	Ifl_desc	*ifl;
	Verneed		*vnd, *_vnd;
	Str_tbl		*dynstr;
	Word		num = 0, cnt = 0;

	dynstr = ofl->ofl_dynstrtab;
	_vnd = vnd = (Verneed *)ofl->ofl_osverneed->os_outdata->d_buf;

	/*
	 * Traverse the shared object list looking for dependencies that have
	 * versions defined within them.
	 */
	for (LIST_TRAVERSE(&ofl->ofl_sos, lnp, ifl)) {
		Half		_cnt;
		Vernaux		*_vnap, *vnap;
		Sdf_desc	*sdf = ifl->ifl_sdfdesc;
		uint_t		stoff;

		if (!(ifl->ifl_flags & FLG_IF_VERNEED))
			continue;

		vnd->vn_version = VER_NEED_CURRENT;

		(void) st_setstring(dynstr, ifl->ifl_soname, &stoff);
		vnd->vn_file = stoff;

		_vnap = vnap = (Vernaux *)(vnd + 1);

		if (sdf && (sdf->sdf_flags & FLG_SDF_SPECVER)) {
			Sdv_desc	*sdv;
			Listnode	*lnp2;

			/*
			 * If version needed definitions were specified in
			 * a mapfile ($VERSION=*) then record those
			 * definitions.
			 */
			for (LIST_TRAVERSE(&sdf->sdf_verneed, lnp2, sdv)) {
				(void) st_setstring(dynstr, sdv->sdv_name,
				    &stoff);
				vnap->vna_name = stoff;
				/* LINTED */
				vnap->vna_hash = (Word)elf_hash(sdv->sdv_name);
				vnap->vna_flags = 0;
				vnap->vna_other = 0;
				_vnap = vnap;
				vnap++;
				cnt++;
				/* LINTED */
				_vnap->vna_next = (Word)((uintptr_t)vnap -
				    (uintptr_t)_vnap);
			}
		} else {

			/*
			 * Traverse the version index list recording
			 * each version as a needed dependency.
			 */
			for (cnt = _cnt = 0; _cnt <= ifl->ifl_vercnt;
			    _cnt++) {
				Ver_index	*vip = &ifl->ifl_verndx[_cnt];

				if (vip->vi_flags & FLG_VER_REFER) {
					(void) st_setstring(dynstr,
					    vip->vi_name, &stoff);
					vnap->vna_name = stoff;

					if (vip->vi_desc) {
						vnap->vna_hash =
						    vip->vi_desc->vd_hash;
						vnap->vna_flags =
						    vip->vi_desc->vd_flags;
					} else {
						vnap->vna_hash = 0;
						vnap->vna_flags = 0;
					}
					vnap->vna_other = 0;

					_vnap = vnap;
					vnap++, cnt++;
					_vnap->vna_next =
					    /* LINTED */
					    (Word)((uintptr_t)vnap -
					    (uintptr_t)_vnap);
				}
			}
		}
		_vnap->vna_next = 0;

		/*
		 * Record the versions auxiliary array offset and
		 * the associated dependency count.
		 */
		/* LINTED */
		vnd->vn_aux = (Word)((uintptr_t)(vnd + 1) - (uintptr_t)vnd);
		/* LINTED */
		vnd->vn_cnt = (Half)cnt;

		/*
		 * Record the next versions offset and update the version
		 * pointer.  Remember the previous version offset as the very
		 * last structures next pointer should be null.
		 */
		_vnd = vnd;
		vnd = (Verneed *)vnap, num++;
		/* LINTED */
		_vnd->vn_next = (Word)((uintptr_t)vnd - (uintptr_t)_vnd);
	}
	_vnd->vn_next = 0;

	/*
	 * Record association on string table section and use the
	 * `info' field to indicate the number of entries in this
	 * section.
	 */
	ofl->ofl_osverneed->os_shdr->sh_link =
	    /* LINTED */
	    (Word)elf_ndxscn(ofl->ofl_osdynstr->os_scn);
	ofl->ofl_osverneed->os_shdr->sh_info = num;

	return (1);
}


/*
 * Update syminfo section.
 */
static uintptr_t
update_osyminfo(Ofl_desc * ofl)
{
	Os_desc *	symosp, * infosp = ofl->ofl_ossyminfo;
	Syminfo *	sip = infosp->os_outdata->d_buf;
	Shdr *		shdr = infosp->os_shdr;
	char		*strtab;
	Listnode *	lnp;
	Sym_desc *	sdp;
	Aliste		off;
	Sfltr_desc *	sftp;

	if (ofl->ofl_flags & FLG_OF_RELOBJ) {
		symosp = ofl->ofl_ossymtab;
		strtab = ofl->ofl_osstrtab->os_outdata->d_buf;
	} else {
		symosp = ofl->ofl_osdynsym;
		strtab = ofl->ofl_osdynstr->os_outdata->d_buf;
	}

	/* LINTED */
	infosp->os_shdr->sh_link = (Word)elf_ndxscn(symosp->os_scn);
	if (ofl->ofl_osdynamic)
		infosp->os_shdr->sh_info =
		    /* LINTED */
		    (Word)elf_ndxscn(ofl->ofl_osdynamic->os_scn);

	/*
	 * Update any references with the index into the dynamic table.
	 */
	for (LIST_TRAVERSE(&ofl->ofl_syminfsyms, lnp, sdp)) {
		Ifl_desc *	ifl;
		if (sdp->sd_aux && sdp->sd_aux->sa_bindto)
			ifl = sdp->sd_aux->sa_bindto;
		else
			ifl = sdp->sd_file;
		sip[sdp->sd_symndx].si_boundto = ifl->ifl_neededndx;
	}

	/*
	 * Update any filtee references with the index into the dynamic table.
	 */
	for (ALIST_TRAVERSE(ofl->ofl_symfltrs, off, sftp)) {
		Dfltr_desc *	dftp;

		/* LINTED */
		dftp = (Dfltr_desc *)((char *)ofl->ofl_dtsfltrs +
		    sftp->sft_off);
		sip[sftp->sft_sdp->sd_symndx].si_boundto = dftp->dft_ndx;
	}

	/*
	 * Display debugging information about section.
	 */
	DBG_CALL(Dbg_syminfo_title(ofl->ofl_lml));
	if (DBG_ENABLED) {
		Word	_cnt, cnt = shdr->sh_size / shdr->sh_entsize;
		Sym *	symtab = symosp->os_outdata->d_buf;
		Dyn *	dyn;

		if (ofl->ofl_osdynamic)
			dyn = ofl->ofl_osdynamic->os_outdata->d_buf;
		else
			dyn = 0;

		for (_cnt = 1; _cnt < cnt; _cnt++) {
			if (sip[_cnt].si_flags || sip[_cnt].si_boundto)
				/* LINTED */
				DBG_CALL(Dbg_syminfo_entry(ofl->ofl_lml, _cnt,
				    &sip[_cnt], &symtab[_cnt], strtab, dyn));
		}
	}
	return (1);
}

/*
 * Build the output elf header.
 */
static uintptr_t
update_oehdr(Ofl_desc * ofl)
{
	Ehdr	*ehdr = ofl->ofl_nehdr;

	/*
	 * If an entry point symbol has already been established (refer
	 * sym_validate()) simply update the elf header entry point with the
	 * symbols value.  If no entry point is defined it will have been filled
	 * with the start address of the first section within the text segment
	 * (refer update_outfile()).
	 */
	if (ofl->ofl_entry)
		ehdr->e_entry =
		    ((Sym_desc *)(ofl->ofl_entry))->sd_sym->st_value;

	/*
	 * Note. it may be necessary to update the `e_flags' field in the
	 * machine dependent section.
	 */
	ehdr->e_ident[EI_DATA] = M_DATA;
	ehdr->e_machine = ofl->ofl_dehdr->e_machine;
	ehdr->e_flags = ofl->ofl_dehdr->e_flags;
	ehdr->e_version = ofl->ofl_dehdr->e_version;

	if (ehdr->e_machine != M_MACH) {
		if (ehdr->e_machine != M_MACHPLUS)
			return (S_ERROR);
		if ((ehdr->e_flags & M_FLAGSPLUS) == 0)
			return (S_ERROR);
	}

	if (ofl->ofl_flags & FLG_OF_SHAROBJ)
		ehdr->e_type = ET_DYN;
	else if (ofl->ofl_flags & FLG_OF_RELOBJ)
		ehdr->e_type = ET_REL;
	else
		ehdr->e_type = ET_EXEC;

	return (1);
}

/*
 * Perform move table expansion.
 */
static uintptr_t
expand_move(Ofl_desc *ofl, Sym_desc *sdp, Move *u1)
{
	Move		*mv;
	Os_desc		*osp;
	unsigned char	*taddr, *taddr0;
	Sxword		offset;
	int		i;
	Addr		base1;
	unsigned int	stride;

	osp = ofl->ofl_issunwdata1->is_osdesc;
	base1 = (Addr)(osp->os_shdr->sh_addr +
	    ofl->ofl_issunwdata1->is_indata->d_off);
	taddr0 = taddr = osp->os_outdata->d_buf;
	mv = u1;

	offset = sdp->sd_sym->st_value - base1;
	taddr += offset;
	taddr = taddr + mv->m_poffset;
	for (i = 0; i < mv->m_repeat; i++) {
		/* LINTED */
		DBG_CALL(Dbg_move_expand(ofl->ofl_lml, mv,
		    (Addr)(taddr - taddr0)));
		stride = (unsigned int)mv->m_stride + 1;
		/* LINTED */
		switch (ELF_M_SIZE(mv->m_info)) {
		case 1:
			/* LINTED */
			*taddr = (unsigned char)mv->m_value;
			taddr += stride;
			break;
		case 2:
			/* LINTED */
			*((Half *)taddr) = (Half)mv->m_value;
			taddr += 2*stride;
			break;
		case 4:
			/* LINTED */
			*((Word *)taddr) = (Word)mv->m_value;
			taddr += 4*stride;
			break;
		case 8:
			/* LINTED */
			*((unsigned long long *)taddr) = mv->m_value;
			taddr += 8*stride;
			break;
		default:
			/*
			 * Should never come here since this is already
			 * checked at sunwmove_preprocess().
			 */
			return (S_ERROR);
		}
	}
	return (1);
}

/*
 * Update Move sections.
 */
static uintptr_t
update_move(Ofl_desc *ofl)
{
	Word		ndx = 0;
	Is_desc *	isp;
	Word		flags = ofl->ofl_flags;
	Move *		mv1, * mv2;
	Listnode *	lnp1;
	Psym_info *	psym;

	/*
	 * Determine the index of the symbol table that will be referenced by
	 * the relocation entries.
	 */
	if (OFL_ALLOW_DYNSYM(ofl))
		/* LINTED */
		ndx = (Word) elf_ndxscn(ofl->ofl_osdynsym->os_scn);
	else if (!(flags & FLG_OF_STRIP) || (flags & FLG_OF_RELOBJ))
		/* LINTED */
		ndx = (Word) elf_ndxscn(ofl->ofl_ossymtab->os_scn);

	/*
	 * update sh_link and mv pointer for updating move table.
	 */
	if (ofl->ofl_osmove) {
		ofl->ofl_osmove->os_shdr->sh_link = ndx;
		mv1 = (Move *) ofl->ofl_osmove->os_outdata->d_buf;
	}

	/*
	 * Update symbol entry index
	 */
	for (LIST_TRAVERSE(&ofl->ofl_parsym, lnp1, psym)) {
		Listnode *	lnp2;
		Mv_itm *	mvp;
		Sym_desc 	*sdp;

		/*
		 * Expand move table
		 */
		if (psym->psym_symd->sd_flags & FLG_SY_PAREXPN) {
			const char	*s;

			if (ofl->ofl_flags & FLG_OF_STATIC)
				s = MSG_INTL(MSG_PSYM_EXPREASON1);
			else if (ofl->ofl_flags1 & FLG_OF1_NOPARTI)
				s = MSG_INTL(MSG_PSYM_EXPREASON2);
			else
				s = MSG_INTL(MSG_PSYM_EXPREASON3);
			DBG_CALL(Dbg_move_parexpn(ofl->ofl_lml,
			    psym->psym_symd->sd_name, s));
			for (LIST_TRAVERSE(&(psym->psym_mvs), lnp2, mvp)) {
				if ((mvp->mv_flag & FLG_MV_OUTSECT) == 0)
					continue;
				mv2 = mvp->mv_ientry;
				sdp = psym->psym_symd;
				DBG_CALL(Dbg_move_entry1(ofl->ofl_lml, 0,
				    mv2, sdp));
				(void) expand_move(ofl, sdp, mv2);
			}
			continue;
		}

		/*
		 * Process move table
		 */
		DBG_CALL(Dbg_move_outmove(ofl->ofl_lml,
		    psym->psym_symd->sd_name));
		for (LIST_TRAVERSE(&(psym->psym_mvs), lnp2, mvp)) {
			int	idx = 1;
			Sym	*sym;

			if ((mvp->mv_flag & FLG_MV_OUTSECT) == 0)
				continue;

			isp = mvp->mv_isp;
			mv2 = mvp->mv_ientry;
			sdp = isp->is_file->ifl_oldndx[ELF_M_SYM(mv2->m_info)];
			sym = sdp->sd_sym;

			DBG_CALL(Dbg_move_entry1(ofl->ofl_lml, 0, mv2, sdp));

			*mv1 = *mv2;
			if ((ofl->ofl_flags & FLG_OF_RELOBJ) == 0) {
				if (ELF_ST_BIND(sym->st_info) == STB_LOCAL) {
					Half	symbssndx = ofl->ofl_isbss->
					    is_osdesc->os_scnsymndx;

					mv1->m_info =
					    /* LINTED */
					    ELF_M_INFO(symbssndx, mv2->m_info);

					if (ELF_ST_TYPE(sym->st_info) !=
					    STT_SECTION) {
						mv1->m_poffset = sym->st_value -
						    ofl->ofl_isbss->is_osdesc->
						    os_shdr->sh_addr +
						    mv2->m_poffset;
					}
				} else {
					mv1->m_info =
					    /* LINTED */
					    ELF_M_INFO(sdp->sd_symndx,
					    mv2->m_info);
				}
			} else {
				Boolean 	isredloc = FALSE;

				if ((ELF_ST_BIND(sym->st_info) == STB_LOCAL) &&
				    (ofl->ofl_flags1 & FLG_OF1_REDLSYM))
					isredloc = TRUE;

				if (isredloc && !(sdp->sd_psyminfo)) {
					Word	symndx = sdp->sd_isc->
					    is_osdesc->os_scnsymndx;

					mv1->m_info =
					    /* LINTED */
					    ELF_M_INFO(symndx, mv2->m_info);
					mv1->m_poffset += sym->st_value;
				} else {
					if (isredloc)
						DBG_CALL(Dbg_syms_reduce(ofl,
						    DBG_SYM_REDUCE_RETAIN, sdp,
						    idx,
						    ofl->ofl_osmove->os_name));

					mv1->m_info =
					    /* LINTED */
					    ELF_M_INFO(sdp->sd_symndx,
					    mv2->m_info);
				}
			}
			DBG_CALL(Dbg_move_entry1(ofl->ofl_lml, 1, mv1, sdp));
			mv1++;
			idx++;
		}
	}
	return (1);
}


/*
 * Scan through the SHT_GROUP output sections.  Update their
 * sh_link/sh_info fields as well as the section contents.
 */
static uintptr_t
update_ogroup(Ofl_desc * ofl)
{
	Listnode	*lnp;
	Os_desc		*osp;
	uintptr_t	error = 0;

	for (LIST_TRAVERSE(&ofl->ofl_osgroups, lnp, osp)) {
		Is_desc		*isp;
		Ifl_desc	*ifl;
		Shdr		*shdr = osp->os_shdr;
		Sym_desc	*sdp;
		Xword		i, grpcnt;
		Word		*gdata;

		/*
		 * Since input GROUP sections always create unique
		 * output GROUP sections - we know there is only one
		 * item on the list.
		 */
		isp = (Is_desc *)osp->os_isdescs.head->data;

		ifl = isp->is_file;
		sdp = ifl->ifl_oldndx[isp->is_shdr->sh_info];
		shdr->sh_link = (Word)elf_ndxscn(ofl->ofl_ossymtab->os_scn);
		shdr->sh_info = sdp->sd_symndx;

		/*
		 * Scan through the group data section and update
		 * all of the links to new values.
		 */
		grpcnt = shdr->sh_size / shdr->sh_entsize;
		gdata = (Word *)osp->os_outdata->d_buf;
		for (i = 1; i < grpcnt; i++) {
			Is_desc	*	_isp;
			Os_desc	*	_osp;

			/*
			 * Perform a sanity check that the section index
			 * stored in the SHT_GROUP section is valid
			 * for the file it came from.
			 */
			if (gdata[i] >= ifl->ifl_shnum) {
				eprintf(ofl->ofl_lml, ERR_FATAL,
				    MSG_INTL(MSG_GRP_INVALNDX), isp->is_name,
				    ifl->ifl_name, i, gdata[i]);
				error = S_ERROR;
				gdata[i] = 0;
				continue;
			}

			_isp = ifl->ifl_isdesc[gdata[i]];

			/*
			 * If the referenced section didn't make it to the
			 * output file - just zero out the entry.
			 */
			if ((_osp = _isp->is_osdesc) == 0)
				gdata[i] = 0;
			else
				gdata[i] = (Word)elf_ndxscn(_osp->os_scn);
		}
	}
	return (error);
}

static void
update_ostrtab(Os_desc *osp, Str_tbl *stp, uint_t extra)
{
	Elf_Data	*data;

	if (osp == 0)
		return;

	data = osp->os_outdata;
	assert(data->d_size == (st_getstrtab_sz(stp) + extra));
	(void) st_setstrbuf(stp, data->d_buf, (uint_t)data->d_size - extra);
	/* If leaving an extra hole at the end, zero it */
	if (extra > 0)
		(void) memset((char *)data->d_buf + data->d_size - extra,
		    0x0, extra);
}

/*
 * Translate the shdr->sh_{link, info} from its input section value to that
 * of the corresponding shdr->sh_{link, info} output section value.
 */
static Word
translate_link(Ofl_desc *ofl, Os_desc *osp, Word link, const char *msg)
{
	Is_desc *	isp;
	Ifl_desc *	ifl;

	/*
	 * Don't translate the special section numbers.
	 */
	if (link >= SHN_LORESERVE)
		return (link);

	/*
	 * Does this output section translate back to an input file.  If not
	 * then there is no translation to do.  In this case we will assume that
	 * if sh_link has a value, it's the right value.
	 */
	isp = (Is_desc *)osp->os_isdescs.head->data;
	if ((ifl = isp->is_file) == NULL)
		return (link);

	/*
	 * Sanity check to make sure that the sh_{link, info} value
	 * is within range for the input file.
	 */
	if (link >= ifl->ifl_shnum) {
		eprintf(ofl->ofl_lml, ERR_WARNING, msg, ifl->ifl_name,
		    isp->is_name, EC_XWORD(link));
		return (link);
	}

	/*
	 * Follow the link to the input section.
	 */
	if ((isp = ifl->ifl_isdesc[link]) == 0)
		return (0);
	if ((osp = isp->is_osdesc) == 0)
		return (0);

	/* LINTED */
	return ((Word)elf_ndxscn(osp->os_scn));
}

/*
 * Having created all of the necessary sections, segments, and associated
 * headers, fill in the program headers and update any other data in the
 * output image.  Some general rules:
 *
 *  o	If an interpreter is required always generate a PT_PHDR entry as
 *	well.  It is this entry that triggers the kernel into passing the
 *	interpreter an aux vector instead of just a file descriptor.
 *
 *  o	When generating an image that will be interpreted (ie. a dynamic
 *	executable, a shared object, or a static executable that has been
 *	provided with an interpreter - weird, but possible), make the initial
 *	loadable segment include both the ehdr and phdr[].  Both of these
 *	tables are used by the interpreter therefore it seems more intuitive
 *	to explicitly defined them as part of the mapped image rather than
 *	relying on page rounding by the interpreter to allow their access.
 *
 *  o	When generating a static image that does not require an interpreter
 *	have the first loadable segment indicate the address of the first
 *	.section as the start address (things like /kernel/unix and ufsboot
 *	expect this behavior).
 */
uintptr_t
ld_update_outfile(Ofl_desc *ofl)
{
	Addr		size, etext, vaddr = ofl->ofl_segorigin;
	Listnode	*lnp1, *lnp2;
	Sg_desc		*sgp, *dtracesgp = 0, *capsgp = 0;
	Os_desc		**ospp, *osp;
	int		phdrndx = 0, segndx = -1, secndx;
	int		dtracepndx, dtracesndx, cappndx, capsndx;
	Ehdr		*ehdr = ofl->ofl_nehdr;
	Shdr		*hshdr;
	Phdr		*_phdr = 0;
	Word		phdrsz = (ehdr->e_phnum * ehdr->e_phentsize), shscnndx;
	Word		flags = ofl->ofl_flags, ehdrsz = ehdr->e_ehsize;
	Boolean		nobits;
	Off		offset;
	Aliste		off;

	/*
	 * Loop through the segment descriptors and pick out what we need.
	 */
	DBG_CALL(Dbg_seg_title(ofl->ofl_lml));
	for (LIST_TRAVERSE(&ofl->ofl_segs, lnp1, sgp)) {
		Phdr	*phdr = &(sgp->sg_phdr);
		Xword 	p_align;

		segndx++;

		/*
		 * If an interpreter is required generate a PT_INTERP and
		 * PT_PHDR program header entry.  The PT_PHDR entry describes
		 * the program header table itself.  This information will be
		 * passed via the aux vector to the interpreter (ld.so.1).
		 * The program header array is actually part of the first
		 * loadable segment (and the PT_PHDR entry is the first entry),
		 * therefore its virtual address isn't known until the first
		 * loadable segment is processed.
		 */
		if (phdr->p_type == PT_PHDR) {
			if (ofl->ofl_osinterp) {
				phdr->p_offset = ehdr->e_phoff;
				phdr->p_filesz = phdr->p_memsz = phdrsz;

				DBG_CALL(Dbg_seg_entry(ofl, segndx, sgp));
				ofl->ofl_phdr[phdrndx++] = *phdr;
			}
			continue;
		}
		if (phdr->p_type == PT_INTERP) {
			if (ofl->ofl_osinterp) {
				Shdr	*shdr = ofl->ofl_osinterp->os_shdr;

				phdr->p_vaddr = phdr->p_memsz = 0;
				phdr->p_offset = shdr->sh_offset;
				phdr->p_filesz = shdr->sh_size;

				DBG_CALL(Dbg_seg_entry(ofl, segndx, sgp));
				ofl->ofl_phdr[phdrndx++] = *phdr;
			}
			continue;
		}

		/*
		 * If we are creating a PT_SUNWDTRACE segment, remember where
		 * the program header is.  The header values are assigned after
		 * update_osym() has completed and the symbol table addresses
		 * have been udpated.
		 */
		if (phdr->p_type == PT_SUNWDTRACE) {
			if ((ofl->ofl_dtracesym) &&
			    ((flags & FLG_OF_RELOBJ) == 0)) {
				dtracesgp = sgp;
				dtracesndx = segndx;
				dtracepndx = phdrndx++;
			}
			continue;
		}

		/*
		 * If a hardware/software capabilities section is required,
		 * generate the PT_SUNWCAP header.  Note, as this comes before
		 * the first loadable segment, we don't yet know its real
		 * virtual address.  This is updated later.
		 */
		if (phdr->p_type == PT_SUNWCAP) {
			if (ofl->ofl_oscap) {
				capsgp = sgp;
				capsndx = segndx;
				cappndx = phdrndx++;
			}
			continue;
		}

		/*
		 * As the dynamic program header occurs after the loadable
		 * headers in the segment descriptor table, all the address
		 * information for the .dynamic output section will have been
		 * figured out by now.
		 */
		if (phdr->p_type == PT_DYNAMIC) {
			if (OFL_ALLOW_DYNSYM(ofl)) {
				Shdr	*shdr = ofl->ofl_osdynamic->os_shdr;

				phdr->p_vaddr = shdr->sh_addr;
				phdr->p_offset = shdr->sh_offset;
				phdr->p_filesz = shdr->sh_size;
				phdr->p_flags = M_DATASEG_PERM;

				DBG_CALL(Dbg_seg_entry(ofl, segndx, sgp));
				ofl->ofl_phdr[phdrndx++] = *phdr;
			}
			continue;
		}

		/*
		 * As the AMD unwind program header occurs after the loadable
		 * headers in the segment descriptor table, all the address
		 * information for the .eh_frame output section will have been
		 * figured out by now.
		 */
#if	(defined(__i386) || defined(__amd64)) && defined(_ELF64)
		if (phdr->p_type == PT_SUNW_UNWIND) {
			Shdr	    *shdr;

			if (ofl->ofl_unwindhdr == 0)
				continue;

			shdr = ofl->ofl_unwindhdr->os_shdr;

			phdr->p_flags = PF_R;
			phdr->p_vaddr = shdr->sh_addr;
			phdr->p_memsz = shdr->sh_size;
			phdr->p_filesz = shdr->sh_size;
			phdr->p_offset = shdr->sh_offset;
			phdr->p_align = shdr->sh_addralign;
			phdr->p_paddr = 0;
			ofl->ofl_phdr[phdrndx++] = *phdr;
			continue;
		}
#endif
		/*
		 * As the TLS program header occurs after the loadable
		 * headers in the segment descriptor table, all the address
		 * information for the .tls output section will have been
		 * figured out by now.
		 */
		if (phdr->p_type == PT_TLS) {
			Os_desc	*tlsosp;
			Shdr	*firstshdr = 0, *lastfileshdr = 0, *lastshdr;

			if (ofl->ofl_ostlsseg.head == NULL)
				continue;

			/*
			 * Scan through the sections that have contributed TLS.
			 * Remember the first and last so as to determine the
			 * TLS memory size requirement.  Remember the last
			 * non-nobits section to determine the TLS data
			 * contribution, which determines the TLS file size.
			 */
			for (LIST_TRAVERSE(&ofl->ofl_ostlsseg, lnp2, tlsosp)) {
				Shdr	*tlsshdr = tlsosp->os_shdr;

				if (firstshdr == 0)
					firstshdr = tlsshdr;
				if (tlsshdr->sh_type != SHT_NOBITS)
					lastfileshdr = tlsshdr;
				lastshdr = tlsshdr;
			}

			phdr->p_flags = PF_R | PF_W;
			phdr->p_vaddr = firstshdr->sh_addr;
			phdr->p_offset = firstshdr->sh_offset;
			phdr->p_align = firstshdr->sh_addralign;

			if (lastfileshdr)
				phdr->p_filesz = lastfileshdr->sh_offset +
				    lastfileshdr->sh_size - phdr->p_offset;
			else
				phdr->p_filesz = 0;

			phdr->p_memsz = lastshdr->sh_offset +
			    lastshdr->sh_size - phdr->p_offset;

			DBG_CALL(Dbg_seg_entry(ofl, segndx, sgp));
			ofl->ofl_phdr[phdrndx] = *phdr;
			ofl->ofl_tlsphdr = &ofl->ofl_phdr[phdrndx++];
			continue;
		}

		/*
		 * If this is an empty segment declaration, it will occur after
		 * all other loadable segments.  As empty segments can be
		 * defind with fixed addresses, make sure that no loadable
		 * segments overlap.  This might occur as the object evolves
		 * and the loadable segments grow, thus encroaching upon an
		 * existing segment reservation.
		 *
		 * Segments are only created for dynamic objects, thus this
		 * checking can be skipped when building a relocatable object.
		 */
		if (!(ofl->ofl_flags & FLG_OF_RELOBJ) &&
		    (sgp->sg_flags & FLG_SG_EMPTY)) {
			int	i;
			Addr	v_e;

			vaddr = phdr->p_vaddr;
			phdr->p_memsz = sgp->sg_length;
			DBG_CALL(Dbg_seg_entry(ofl, segndx, sgp));
			ofl->ofl_phdr[phdrndx++] = *phdr;

			if (phdr->p_type != PT_LOAD)
				continue;

			v_e = vaddr + phdr->p_memsz;

			/*
			 * Check overlaps
			 */
			for (i = 0; i < phdrndx - 1; i++) {
				Addr 	p_s = (ofl->ofl_phdr[i]).p_vaddr;
				Addr 	p_e;

				if ((ofl->ofl_phdr[i]).p_type != PT_LOAD)
					continue;

				p_e = p_s + (ofl->ofl_phdr[i]).p_memsz;
				if (((p_s <= vaddr) && (p_e > vaddr)) ||
				    ((vaddr <= p_s) && (v_e > p_s)))
					eprintf(ofl->ofl_lml, ERR_WARNING,
					    MSG_INTL(MSG_UPD_SEGOVERLAP),
					    ofl->ofl_name, EC_ADDR(p_e),
					    sgp->sg_name, EC_ADDR(vaddr));
			}
			continue;
		}

		/*
		 * Having processed any of the special program headers any
		 * remaining headers will be built to express individual
		 * segments.  Segments are only built if they have output
		 * section descriptors associated with them (ie. some form of
		 * input section has been matched to this segment).
		 */
		if (sgp->sg_osdescs == NULL)
			continue;

		/*
		 * Determine the segments offset and size from the section
		 * information provided from elf_update().
		 * Allow for multiple NOBITS sections.
		 */
		osp = (Os_desc *)sgp->sg_osdescs->al_data[0];
		hshdr = osp->os_shdr;

		phdr->p_filesz = 0;
		phdr->p_memsz = 0;
		phdr->p_offset = offset = hshdr->sh_offset;

		nobits = ((hshdr->sh_type == SHT_NOBITS) &&
		    ((sgp->sg_flags & FLG_SG_PHREQ) == 0));

		for (ALIST_TRAVERSE(sgp->sg_osdescs, off, ospp)) {
			Shdr	*shdr;

			osp = *ospp;
			shdr = osp->os_shdr;

			p_align = 0;
			if (shdr->sh_addralign > p_align)
				p_align = shdr->sh_addralign;

			offset = (Off)S_ROUND(offset, shdr->sh_addralign);
			offset += shdr->sh_size;

			if (shdr->sh_type != SHT_NOBITS) {
				if (nobits) {
					eprintf(ofl->ofl_lml, ERR_FATAL,
					    MSG_INTL(MSG_UPD_NOBITS));
					return (S_ERROR);
				}
				phdr->p_filesz = offset - phdr->p_offset;
			} else if ((sgp->sg_flags & FLG_SG_PHREQ) == 0)
				nobits = TRUE;
		}
		phdr->p_memsz = offset - hshdr->sh_offset;

		/*
		 * If this is PT_SUNWBSS, set alignment
		 */
		if (phdr->p_type == PT_SUNWBSS)
			phdr->p_align = p_align;

		/*
		 * If this is the first loadable segment of a dynamic object,
		 * or an interpreter has been specified (a static object built
		 * with an interpreter will still be given a PT_HDR entry), then
		 * compensate for the elf header and program header array.  Both
		 * of these are actually part of the loadable segment as they
		 * may be inspected by the interpreter.  Adjust the segments
		 * size and offset accordingly.
		 */
		if ((_phdr == 0) && (phdr->p_type == PT_LOAD) &&
		    ((ofl->ofl_osinterp) || (flags & FLG_OF_DYNAMIC)) &&
		    (!(ofl->ofl_dtflags_1 & DF_1_NOHDR))) {
			size = (Addr)S_ROUND((phdrsz + ehdrsz),
			    hshdr->sh_addralign);
			phdr->p_offset -= size;
			phdr->p_filesz += size;
			phdr->p_memsz += size;
		}

		/*
		 * If a segment size symbol is required (specified via a
		 * mapfile) update its value.
		 */
		if (sgp->sg_sizesym != NULL)
			sgp->sg_sizesym->sd_sym->st_value = phdr->p_memsz;

		/*
		 * If no file content has been assigned to this segment (it
		 * only contains no-bits sections), then reset the offset for
		 * consistency.
		 */
		if (phdr->p_filesz == 0)
			phdr->p_offset = 0;

		/*
		 * If a virtual address has been specified for this segment
		 * (presumably from a map file) use it and make sure the
		 * previous segment does not run into this segment.
		 */
		if ((phdr->p_type == PT_LOAD) ||
		    (phdr->p_type == PT_SUNWBSS)) {
			if ((sgp->sg_flags & FLG_SG_VADDR)) {
				if (_phdr && (vaddr > phdr->p_vaddr) &&
				    (phdr->p_type == PT_LOAD))
					eprintf(ofl->ofl_lml, ERR_WARNING,
					    MSG_INTL(MSG_UPD_SEGOVERLAP),
					    ofl->ofl_name, EC_ADDR(vaddr),
					    sgp->sg_name,
					    EC_ADDR(phdr->p_vaddr));
				vaddr = phdr->p_vaddr;
				phdr->p_align = 0;
			} else {
				vaddr = phdr->p_vaddr =
				    (Addr)S_ROUND(vaddr, phdr->p_align);
			}
		}

		/*
		 * Adjust the address offset and p_align if needed.
		 */
		if (((sgp->sg_flags & FLG_SG_VADDR) == 0) &&
		    ((ofl->ofl_dtflags_1 & DF_1_NOHDR) == 0)) {
			if (phdr->p_align != 0)
				vaddr += phdr->p_offset % phdr->p_align;
			else
				vaddr += phdr->p_offset;
			phdr->p_vaddr = vaddr;
		}

		/*
		 * If an interpreter is required set the virtual address of the
		 * PT_PHDR program header now that we know the virtual address
		 * of the loadable segment that contains it.  Update the
		 * PT_SUNWCAP header similarly.
		 */
		if ((_phdr == 0) && (phdr->p_type == PT_LOAD)) {
			_phdr = phdr;

			if ((ofl->ofl_dtflags_1 & DF_1_NOHDR) == 0) {
				if (ofl->ofl_osinterp)
					ofl->ofl_phdr[0].p_vaddr =
					    vaddr + ehdrsz;

				/*
				 * Finally, if we're creating a dynamic object
				 * (or a static object in which an interpreter
				 * is specified) update the vaddr to reflect
				 * the address of the first section within this
				 * segment.
				 */
				if ((ofl->ofl_osinterp) ||
				    (flags & FLG_OF_DYNAMIC))
					vaddr += size;
			} else {
				/*
				 * If the DF_1_NOHDR flag was set, and an
				 * interpreter is being generated, the PT_PHDR
				 * will not be part of any loadable segment.
				 */
				if (ofl->ofl_osinterp) {
					ofl->ofl_phdr[0].p_vaddr = 0;
					ofl->ofl_phdr[0].p_memsz = 0;
					ofl->ofl_phdr[0].p_flags = 0;
				}
			}
		}

		/*
		 * Ensure the ELF entry point defaults to zero.  Typically, this
		 * value is overridden in update_oehdr() to one of the standard
		 * entry points.  Historically, this default was set to the
		 * address of first executable section, but this has since been
		 * found to be more confusing than it is helpful.
		 */
		ehdr->e_entry = 0;

		DBG_CALL(Dbg_seg_entry(ofl, segndx, sgp));

		/*
		 * Traverse the output section descriptors for this segment so
		 * that we can update the section headers addresses.  We've
		 * calculated the virtual address of the initial section within
		 * this segment, so each successive section can be calculated
		 * based on their offsets from each other.
		 */
		secndx = 0;
		hshdr = 0;
		for (ALIST_TRAVERSE(sgp->sg_osdescs, off, ospp)) {
			Shdr	*shdr;

			osp = *ospp;
			shdr = osp->os_shdr;

			if (shdr->sh_link)
				shdr->sh_link = translate_link(ofl, osp,
				    shdr->sh_link, MSG_INTL(MSG_FIL_INVSHLINK));

			if (shdr->sh_info && (shdr->sh_flags & SHF_INFO_LINK))
				shdr->sh_info = translate_link(ofl, osp,
				    shdr->sh_info, MSG_INTL(MSG_FIL_INVSHINFO));

			if (!(flags & FLG_OF_RELOBJ) &&
			    (phdr->p_type == PT_LOAD) ||
			    (phdr->p_type == PT_SUNWBSS)) {
				if (hshdr)
					vaddr += (shdr->sh_offset -
					    hshdr->sh_offset);

				shdr->sh_addr = vaddr;
				hshdr = shdr;
			}

			DBG_CALL(Dbg_seg_os(ofl, osp, secndx));
			secndx++;
		}

		/*
		 * Establish the virtual address of the end of the last section
		 * in this segment so that the next segments offset can be
		 * calculated from this.
		 */
		if (hshdr)
			vaddr += hshdr->sh_size;

		/*
		 * Output sections for this segment complete.  Adjust the
		 * virtual offset for the last sections size, and make sure we
		 * haven't exceeded any maximum segment length specification.
		 */
		if ((sgp->sg_length != 0) && (sgp->sg_length < phdr->p_memsz)) {
			eprintf(ofl->ofl_lml, ERR_FATAL,
			    MSG_INTL(MSG_UPD_LARGSIZE), ofl->ofl_name,
			    sgp->sg_name, EC_XWORD(phdr->p_memsz),
			    EC_XWORD(sgp->sg_length));
			return (S_ERROR);
		}

		if (phdr->p_type == PT_NOTE) {
			phdr->p_vaddr = 0;
			phdr->p_paddr = 0;
			phdr->p_align = 0;
			phdr->p_memsz = 0;
		}

		if ((phdr->p_type != PT_NULL) && !(flags & FLG_OF_RELOBJ))
			ofl->ofl_phdr[phdrndx++] = *phdr;
	}

	/*
	 * Update any new output sections.  When building the initial output
	 * image, a number of sections were created but left uninitialized (eg.
	 * .dynsym, .dynstr, .symtab, .symtab, etc.).  Here we update these
	 * sections with the appropriate data.  Other sections may still be
	 * modified via reloc_process().
	 *
	 * Copy the interpreter name into the .interp section.
	 */
	if (ofl->ofl_interp)
		(void) strcpy((char *)ofl->ofl_osinterp->os_outdata->d_buf,
		    ofl->ofl_interp);

	/*
	 * Update the .shstrtab, .strtab and .dynstr sections.
	 */
	update_ostrtab(ofl->ofl_osshstrtab, ofl->ofl_shdrsttab, 0);
	update_ostrtab(ofl->ofl_osstrtab, ofl->ofl_strtab, 0);
	update_ostrtab(ofl->ofl_osdynstr, ofl->ofl_dynstrtab, DYNSTR_EXTRA_PAD);

	/*
	 * Build any output symbol tables, the symbols information is copied
	 * and updated into the new output image.
	 */
	if ((etext = update_osym(ofl)) == (Addr)S_ERROR)
		return (S_ERROR);

	/*
	 * If we have a PT_SUNWDTRACE phdr, update it now with the address of
	 * the symbol.  It's only now been updated via update_sym().
	 */
	if (dtracesgp && ofl->ofl_dtracesym) {
		Phdr		*aphdr, *phdr = &(dtracesgp->sg_phdr);
		Sym_desc	*sdp = ofl->ofl_dtracesym;

		phdr->p_vaddr = sdp->sd_sym->st_value;
		phdr->p_memsz = sdp->sd_sym->st_size;

		/*
		 * Take permisions of the segment the symbol is associated with.
		 */
		aphdr = &sdp->sd_isc->is_osdesc->os_sgdesc->sg_phdr;
		assert(aphdr);
		phdr->p_flags = aphdr->p_flags;

		DBG_CALL(Dbg_seg_entry(ofl, dtracesndx, dtracesgp));
		ofl->ofl_phdr[dtracepndx] = *phdr;
	}

	/*
	 * If we have a PT_SUNWCAP phdr, update it now from the associated
	 * section information.
	 */
	if (capsgp && ofl->ofl_oscap) {
		Phdr	*phdr = &(capsgp->sg_phdr);
		Shdr	*shdr = ofl->ofl_oscap->os_shdr;

		phdr->p_vaddr = shdr->sh_addr;
		phdr->p_offset = shdr->sh_offset;
		phdr->p_filesz = shdr->sh_size;
		phdr->p_flags = PF_R;

		DBG_CALL(Dbg_seg_entry(ofl, capsndx, capsgp));
		ofl->ofl_phdr[cappndx] = *phdr;
	}

	/*
	 * Update the GROUP sections.
	 */
	if (update_ogroup(ofl) == S_ERROR)
		return (S_ERROR);

	/*
	 * Update Move Table.
	 */
	if (ofl->ofl_osmove || ofl->ofl_issunwdata1) {
		if (update_move(ofl) == S_ERROR)
			return (S_ERROR);
	}

	/*
	 * Build any output headers, version information, dynamic structure and
	 * syminfo structure.
	 */
	if (update_oehdr(ofl) == S_ERROR)
		return (S_ERROR);
	if ((flags & (FLG_OF_VERDEF | FLG_OF_NOVERSEC)) == FLG_OF_VERDEF)
		if (update_overdef(ofl) == S_ERROR)
			return (S_ERROR);
	if ((flags & (FLG_OF_VERNEED | FLG_OF_NOVERSEC)) == FLG_OF_VERNEED)
		if (update_overneed(ofl) == S_ERROR)
			return (S_ERROR);
	if (flags & FLG_OF_DYNAMIC) {
		if (update_odynamic(ofl) == S_ERROR)
			return (S_ERROR);
		if (ofl->ofl_ossyminfo)
			if (update_osyminfo(ofl) == S_ERROR)
				return (S_ERROR);
	}

	/*
	 * Emit Strtab diagnostics.
	 */
	DBG_CALL(Dbg_sec_strtab(ofl->ofl_lml, ofl->ofl_osshstrtab,
	    ofl->ofl_shdrsttab));
	DBG_CALL(Dbg_sec_strtab(ofl->ofl_lml, ofl->ofl_osstrtab,
	    ofl->ofl_strtab));
	DBG_CALL(Dbg_sec_strtab(ofl->ofl_lml, ofl->ofl_osdynstr,
	    ofl->ofl_dynstrtab));

	/*
	 * Initialize the section headers string table index within the elf
	 * header.
	 */
	/* LINTED */
	if ((shscnndx = elf_ndxscn(ofl->ofl_osshstrtab->os_scn)) <
	    SHN_LORESERVE) {
		ofl->ofl_nehdr->e_shstrndx =
		    /* LINTED */
		    (Half)shscnndx;
	} else {
		/*
		 * If the STRTAB section index doesn't fit into
		 * e_shstrndx, then we store it in 'shdr[0].st_link'.
		 */
		Elf_Scn	*scn;
		Shdr	*shdr0;

		if ((scn = elf_getscn(ofl->ofl_elf, 0)) == NULL) {
			eprintf(ofl->ofl_lml, ERR_ELF,
			    MSG_INTL(MSG_ELF_GETSCN), ofl->ofl_name);
			return (S_ERROR);
		}
		if ((shdr0 = elf_getshdr(scn)) == NULL) {
			eprintf(ofl->ofl_lml, ERR_ELF,
			    MSG_INTL(MSG_ELF_GETSHDR), ofl->ofl_name);
			return (S_ERROR);
		}
		ofl->ofl_nehdr->e_shstrndx = SHN_XINDEX;
		shdr0->sh_link = shscnndx;
	}

	return ((uintptr_t)etext);
}
