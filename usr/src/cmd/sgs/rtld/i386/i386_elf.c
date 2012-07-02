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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

/*
 * x86 machine dependent and ELF file class dependent functions.
 * Contains routines for performing function binding and symbol relocations.
 */

#include	<stdio.h>
#include	<sys/elf.h>
#include	<sys/elf_386.h>
#include	<sys/mman.h>
#include	<dlfcn.h>
#include	<synch.h>
#include	<string.h>
#include	<debug.h>
#include	<reloc.h>
#include	<conv.h>
#include	"_rtld.h"
#include	"_audit.h"
#include	"_elf.h"
#include	"_inline_gen.h"
#include	"_inline_reloc.h"
#include	"msg.h"

extern void	elf_rtbndr(Rt_map *, ulong_t, caddr_t);

int
elf_mach_flags_check(Rej_desc *rej, Ehdr *ehdr)
{
	/*
	 * Check machine type and flags.
	 */
	if (ehdr->e_flags != 0) {
		rej->rej_type = SGS_REJ_BADFLAG;
		rej->rej_info = (uint_t)ehdr->e_flags;
		return (0);
	}
	return (1);
}

void
ldso_plt_init(Rt_map *lmp)
{
	/*
	 * There is no need to analyze ld.so because we don't map in any of
	 * its dependencies.  However we may map these dependencies in later
	 * (as if ld.so had dlopened them), so initialize the plt and the
	 * permission information.
	 */
	if (PLTGOT(lmp))
		elf_plt_init((PLTGOT(lmp)), (caddr_t)lmp);
}

static const uchar_t dyn_plt_template[] = {
/* 0x00 */  0x55,				/* pushl %ebp */
/* 0x01 */  0x8b, 0xec,				/* movl %esp, %ebp */
/* 0x03 */  0x68, 0x00, 0x00, 0x00, 0x00,	/* pushl trace_fields */
/* 0x08 */  0xe9, 0xfc, 0xff, 0xff, 0xff, 0xff	/* jmp  elf_plt_trace */
};
int	dyn_plt_ent_size = sizeof (dyn_plt_template);

/*
 * the dynamic plt entry is:
 *
 *	pushl	%ebp
 *	movl	%esp, %ebp
 *	pushl	tfp
 *	jmp	elf_plt_trace
 * dyn_data:
 *	.align  4
 *	uintptr_t	reflmp
 *	uintptr_t	deflmp
 *	uint_t		symndx
 *	uint_t		sb_flags
 *	Sym		symdef
 */
static caddr_t
elf_plt_trace_write(uint_t roffset, Rt_map *rlmp, Rt_map *dlmp, Sym *sym,
    uint_t symndx, uint_t pltndx, caddr_t to, uint_t sb_flags, int *fail)
{
	extern int	elf_plt_trace();
	ulong_t		got_entry;
	uchar_t		*dyn_plt;
	uintptr_t	*dyndata;

	/*
	 * We only need to add the glue code if there is an auditing
	 * library that is interested in this binding.
	 */
	dyn_plt = (uchar_t *)((uintptr_t)AUDINFO(rlmp)->ai_dynplts +
	    (pltndx * dyn_plt_ent_size));

	/*
	 * Have we initialized this dynamic plt entry yet?  If we haven't do it
	 * now.  Otherwise this function has been called before, but from a
	 * different plt (ie. from another shared object).  In that case
	 * we just set the plt to point to the new dyn_plt.
	 */
	if (*dyn_plt == 0) {
		Sym	*symp;
		Word	symvalue;
		Lm_list	*lml = LIST(rlmp);

		(void) memcpy((void *)dyn_plt, dyn_plt_template,
		    sizeof (dyn_plt_template));
		dyndata = (uintptr_t *)((uintptr_t)dyn_plt +
		    ROUND(sizeof (dyn_plt_template), M_WORD_ALIGN));

		/*
		 * relocate:
		 *	pushl	dyn_data
		 */
		symvalue = (Word)dyndata;
		if (do_reloc_rtld(R_386_32, &dyn_plt[4], &symvalue,
		    MSG_ORIG(MSG_SYM_LADYNDATA),
		    MSG_ORIG(MSG_SPECFIL_DYNPLT), lml) == 0) {
			*fail = 1;
			return (0);
		}

		/*
		 * jmps are relative, so I need to figure out the relative
		 * address to elf_plt_trace.
		 *
		 * relocating:
		 *	jmp	elf_plt_trace
		 */
		symvalue = (ulong_t)(elf_plt_trace) - (ulong_t)(dyn_plt + 9);
		if (do_reloc_rtld(R_386_PC32, &dyn_plt[9], &symvalue,
		    MSG_ORIG(MSG_SYM_ELFPLTTRACE),
		    MSG_ORIG(MSG_SPECFIL_DYNPLT), lml) == 0) {
			*fail = 1;
			return (0);
		}

		*dyndata++ = (uintptr_t)rlmp;
		*dyndata++ = (uintptr_t)dlmp;
		*dyndata++ = (uint_t)symndx;
		*dyndata++ = (uint_t)sb_flags;
		symp = (Sym *)dyndata;
		*symp = *sym;
		symp->st_name += (Word)STRTAB(dlmp);
		symp->st_value = (Addr)to;
	}

	got_entry = (ulong_t)roffset;
	*(ulong_t *)got_entry = (ulong_t)dyn_plt;
	return ((caddr_t)dyn_plt);
}

/*
 * Function binding routine - invoked on the first call to a function through
 * the procedure linkage table;
 * passes first through an assembly language interface.
 *
 * Takes the offset into the relocation table of the associated
 * relocation entry and the address of the link map (rt_private_map struct)
 * for the entry.
 *
 * Returns the address of the function referenced after re-writing the PLT
 * entry to invoke the function directly.
 *
 * On error, causes process to terminate with a signal.
 */
ulong_t
elf_bndr(Rt_map *lmp, ulong_t reloff, caddr_t from)
{
	Rt_map		*nlmp, *llmp;
	ulong_t		addr, symval, rsymndx;
	char		*name;
	Rel		*rptr;
	Sym		*rsym, *nsym;
	uint_t		binfo, sb_flags = 0, dbg_class;
	Slookup		sl;
	Sresult		sr;
	int		entry, lmflags;
	Lm_list		*lml;

	/*
	 * For compatibility with libthread (TI_VERSION 1) we track the entry
	 * value.  A zero value indicates we have recursed into ld.so.1 to
	 * further process a locking request.  Under this recursion we disable
	 * tsort and cleanup activities.
	 */
	entry = enter(0);

	lml = LIST(lmp);
	if ((lmflags = lml->lm_flags) & LML_FLG_RTLDLM) {
		dbg_class = dbg_desc->d_class;
		dbg_desc->d_class = 0;
	}

	/*
	 * Perform some basic sanity checks.  If we didn't get a load map or
	 * the relocation offset is invalid then its possible someone has walked
	 * over the .got entries or jumped to plt0 out of the blue.
	 */
	if (!lmp || ((reloff % sizeof (Rel)) != 0)) {
		Conv_inv_buf_t inv_buf;

		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_REL_PLTREF),
		    conv_reloc_386_type(R_386_JMP_SLOT, 0, &inv_buf),
		    EC_NATPTR(lmp), EC_XWORD(reloff), EC_NATPTR(from));
		rtldexit(lml, 1);
	}

	/*
	 * Use relocation entry to get symbol table entry and symbol name.
	 */
	addr = (ulong_t)JMPREL(lmp);
	rptr = (Rel *)(addr + reloff);
	rsymndx = ELF_R_SYM(rptr->r_info);
	rsym = (Sym *)((ulong_t)SYMTAB(lmp) + (rsymndx * SYMENT(lmp)));
	name = (char *)(STRTAB(lmp) + rsym->st_name);

	/*
	 * Determine the last link-map of this list, this'll be the starting
	 * point for any tsort() processing.
	 */
	llmp = lml->lm_tail;

	/*
	 * Find definition for symbol.  Initialize the symbol lookup, and
	 * symbol result, data structures.
	 */
	SLOOKUP_INIT(sl, name, lmp, lml->lm_head, ld_entry_cnt, 0,
	    rsymndx, rsym, 0, LKUP_DEFT);
	SRESULT_INIT(sr, name);

	if (lookup_sym(&sl, &sr, &binfo, NULL) == 0) {
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_REL_NOSYM), NAME(lmp),
		    demangle(name));
		rtldexit(lml, 1);
	}

	name = (char *)sr.sr_name;
	nlmp = sr.sr_dmap;
	nsym = sr.sr_sym;

	symval = nsym->st_value;

	if (!(FLAGS(nlmp) & FLG_RT_FIXED) &&
	    (nsym->st_shndx != SHN_ABS))
		symval += ADDR(nlmp);
	if ((lmp != nlmp) && ((FLAGS1(nlmp) & FL1_RT_NOINIFIN) == 0)) {
		/*
		 * Record that this new link map is now bound to the caller.
		 */
		if (bind_one(lmp, nlmp, BND_REFER) == 0)
			rtldexit(lml, 1);
	}

	if ((lml->lm_tflags | AFLAGS(lmp) | AFLAGS(nlmp)) &
	    LML_TFLG_AUD_SYMBIND) {
		uint_t	symndx = (((uintptr_t)nsym -
		    (uintptr_t)SYMTAB(nlmp)) / SYMENT(nlmp));
		symval = audit_symbind(lmp, nlmp, nsym, symndx, symval,
		    &sb_flags);
	}

	if (!(rtld_flags & RT_FL_NOBIND)) {
		addr = rptr->r_offset;
		if (!(FLAGS(lmp) & FLG_RT_FIXED))
			addr += ADDR(lmp);
		if (((lml->lm_tflags | AFLAGS(lmp)) &
		    (LML_TFLG_AUD_PLTENTER | LML_TFLG_AUD_PLTEXIT)) &&
		    AUDINFO(lmp)->ai_dynplts) {
			int	fail = 0;
			uint_t	pltndx = reloff / sizeof (Rel);
			uint_t	symndx = (((uintptr_t)nsym -
			    (uintptr_t)SYMTAB(nlmp)) / SYMENT(nlmp));

			symval = (ulong_t)elf_plt_trace_write(addr, lmp, nlmp,
			    nsym, symndx, pltndx, (caddr_t)symval, sb_flags,
			    &fail);
			if (fail)
				rtldexit(lml, 1);
		} else {
			/*
			 * Write standard PLT entry to jump directly
			 * to newly bound function.
			 */
			*(ulong_t *)addr = symval;
		}
	}

	/*
	 * Print binding information and rebuild PLT entry.
	 */
	DBG_CALL(Dbg_bind_global(lmp, (Addr)from, (Off)(from - ADDR(lmp)),
	    (Xword)(reloff / sizeof (Rel)), PLT_T_FULL, nlmp, (Addr)symval,
	    nsym->st_value, name, binfo));

	/*
	 * Complete any processing for newly loaded objects.  Note we don't
	 * know exactly where any new objects are loaded (we know the object
	 * that supplied the symbol, but others may have been loaded lazily as
	 * we searched for the symbol), so sorting starts from the last
	 * link-map know on entry to this routine.
	 */
	if (entry)
		load_completion(llmp);

	/*
	 * Some operations like dldump() or dlopen()'ing a relocatable object
	 * result in objects being loaded on rtld's link-map, make sure these
	 * objects are initialized also.
	 */
	if ((LIST(nlmp)->lm_flags & LML_FLG_RTLDLM) && LIST(nlmp)->lm_init)
		load_completion(nlmp);

	/*
	 * Make sure the object to which we've bound has had it's .init fired.
	 * Cleanup before return to user code.
	 */
	if (entry) {
		is_dep_init(nlmp, lmp);
		leave(lml, 0);
	}

	if (lmflags & LML_FLG_RTLDLM)
		dbg_desc->d_class = dbg_class;

	return (symval);
}

/*
 * Read and process the relocations for one link object, we assume all
 * relocation sections for loadable segments are stored contiguously in
 * the file.
 */
int
elf_reloc(Rt_map *lmp, uint_t plt, int *in_nfavl, APlist **textrel)
{
	ulong_t		relbgn, relend, relsiz, basebgn, pltbgn, pltend;
	ulong_t		_pltbgn, _pltend;
	ulong_t		dsymndx, roffset, rsymndx, psymndx = 0;
	uchar_t		rtype;
	long		value, pvalue;
	Sym		*symref, *psymref, *symdef, *psymdef;
	Syminfo		*sip;
	char		*name, *pname;
	Rt_map		*_lmp, *plmp;
	int		ret = 1, noplt = 0;
	int		relacount = RELACOUNT(lmp), plthint = 0;
	Rel		*rel;
	uint_t		binfo, pbinfo;
	APlist		*bound = NULL;

	/*
	 * Although only necessary for lazy binding, initialize the first
	 * global offset entry to go to elf_rtbndr().  dbx(1) seems
	 * to find this useful.
	 */
	if ((plt == 0) && PLTGOT(lmp)) {
		mmapobj_result_t	*mpp;

		/*
		 * Make sure the segment is writable.
		 */
		if ((((mpp =
		    find_segment((caddr_t)PLTGOT(lmp), lmp)) != NULL) &&
		    ((mpp->mr_prot & PROT_WRITE) == 0)) &&
		    ((set_prot(lmp, mpp, 1) == 0) ||
		    (aplist_append(textrel, mpp, AL_CNT_TEXTREL) == NULL)))
			return (0);

		elf_plt_init(PLTGOT(lmp), (caddr_t)lmp);
	}

	/*
	 * Initialize the plt start and end addresses.
	 */
	if ((pltbgn = (ulong_t)JMPREL(lmp)) != 0)
		pltend = pltbgn + (ulong_t)(PLTRELSZ(lmp));

	relsiz = (ulong_t)(RELENT(lmp));
	basebgn = ADDR(lmp);

	if (PLTRELSZ(lmp))
		plthint = PLTRELSZ(lmp) / relsiz;

	/*
	 * If we've been called upon to promote an RTLD_LAZY object to an
	 * RTLD_NOW then we're only interested in scaning the .plt table.
	 * An uninitialized .plt is the case where the associated got entry
	 * points back to the plt itself.  Determine the range of the real .plt
	 * entries using the _PROCEDURE_LINKAGE_TABLE_ symbol.
	 */
	if (plt) {
		Slookup	sl;
		Sresult	sr;

		relbgn = pltbgn;
		relend = pltend;
		if (!relbgn || (relbgn == relend))
			return (1);

		/*
		 * Initialize the symbol lookup, and symbol result, data
		 * structures.
		 */
		SLOOKUP_INIT(sl, MSG_ORIG(MSG_SYM_PLT), lmp, lmp, ld_entry_cnt,
		    elf_hash(MSG_ORIG(MSG_SYM_PLT)), 0, 0, 0, LKUP_DEFT);
		SRESULT_INIT(sr, MSG_ORIG(MSG_SYM_PLT));

		if (elf_find_sym(&sl, &sr, &binfo, NULL) == 0)
			return (1);

		symdef = sr.sr_sym;
		_pltbgn = symdef->st_value;
		if (!(FLAGS(lmp) & FLG_RT_FIXED) &&
		    (symdef->st_shndx != SHN_ABS))
			_pltbgn += basebgn;
		_pltend = _pltbgn + (((PLTRELSZ(lmp) / relsiz)) *
		    M_PLT_ENTSIZE) + M_PLT_RESERVSZ;

	} else {
		/*
		 * The relocation sections appear to the run-time linker as a
		 * single table.  Determine the address of the beginning and end
		 * of this table.  There are two different interpretations of
		 * the ABI at this point:
		 *
		 *   o	The REL table and its associated RELSZ indicate the
		 *	concatenation of *all* relocation sections (this is the
		 *	model our link-editor constructs).
		 *
		 *   o	The REL table and its associated RELSZ indicate the
		 *	concatenation of all *but* the .plt relocations.  These
		 *	relocations are specified individually by the JMPREL and
		 *	PLTRELSZ entries.
		 *
		 * Determine from our knowledege of the relocation range and
		 * .plt range, the range of the total relocation table.  Note
		 * that one other ABI assumption seems to be that the .plt
		 * relocations always follow any other relocations, the
		 * following range checking drops that assumption.
		 */
		relbgn = (ulong_t)(REL(lmp));
		relend = relbgn + (ulong_t)(RELSZ(lmp));
		if (pltbgn) {
			if (!relbgn || (relbgn > pltbgn))
				relbgn = pltbgn;
			if (!relbgn || (relend < pltend))
				relend = pltend;
		}
	}
	if (!relbgn || (relbgn == relend)) {
		DBG_CALL(Dbg_reloc_run(lmp, 0, plt, DBG_REL_NONE));
		return (1);
	}
	DBG_CALL(Dbg_reloc_run(lmp, M_REL_SHT_TYPE, plt, DBG_REL_START));

	/*
	 * If we're processing a dynamic executable in lazy mode there is no
	 * need to scan the .rel.plt table, however if we're processing a shared
	 * object in lazy mode the .got addresses associated to each .plt must
	 * be relocated to reflect the location of the shared object.
	 */
	if (pltbgn && ((MODE(lmp) & RTLD_NOW) == 0) &&
	    (FLAGS(lmp) & FLG_RT_FIXED))
		noplt = 1;

	sip = SYMINFO(lmp);
	/*
	 * Loop through relocations.
	 */
	while (relbgn < relend) {
		mmapobj_result_t	*mpp;
		uint_t			sb_flags = 0;

		rtype = ELF_R_TYPE(((Rel *)relbgn)->r_info, M_MACH);

		/*
		 * If this is a RELATIVE relocation in a shared object (the
		 * common case), and if we are not debugging, then jump into a
		 * tighter relocation loop (elf_reloc_relative).
		 */
		if ((rtype == R_386_RELATIVE) &&
		    ((FLAGS(lmp) & FLG_RT_FIXED) == 0) && (DBG_ENABLED == 0)) {
			if (relacount) {
				relbgn = elf_reloc_relative_count(relbgn,
				    relacount, relsiz, basebgn, lmp,
				    textrel, 0);
				relacount = 0;
			} else {
				relbgn = elf_reloc_relative(relbgn, relend,
				    relsiz, basebgn, lmp, textrel, 0);
			}
			if (relbgn >= relend)
				break;
			rtype = ELF_R_TYPE(((Rel *)relbgn)->r_info, M_MACH);
		}

		roffset = ((Rel *)relbgn)->r_offset;

		/*
		 * If this is a shared object, add the base address to offset.
		 */
		if (!(FLAGS(lmp) & FLG_RT_FIXED)) {
			/*
			 * If we're processing lazy bindings, we have to step
			 * through the plt entries and add the base address
			 * to the corresponding got entry.
			 */
			if (plthint && (plt == 0) &&
			    (rtype == R_386_JMP_SLOT) &&
			    ((MODE(lmp) & RTLD_NOW) == 0)) {
				relbgn = elf_reloc_relative_count(relbgn,
				    plthint, relsiz, basebgn, lmp, textrel, 0);
				plthint = 0;
				continue;
			}
			roffset += basebgn;
		}

		rsymndx = ELF_R_SYM(((Rel *)relbgn)->r_info);
		rel = (Rel *)relbgn;
		relbgn += relsiz;

		/*
		 * Optimizations.
		 */
		if (rtype == R_386_NONE)
			continue;
		if (noplt && ((ulong_t)rel >= pltbgn) &&
		    ((ulong_t)rel < pltend)) {
			relbgn = pltend;
			continue;
		}

		/*
		 * If we're promoting plts, determine if this one has already
		 * been written.
		 */
		if (plt && ((*(ulong_t *)roffset < _pltbgn) ||
		    (*(ulong_t *)roffset > _pltend)))
			continue;

		/*
		 * If this relocation is not against part of the image
		 * mapped into memory we skip it.
		 */
		if ((mpp = find_segment((caddr_t)roffset, lmp)) == NULL) {
			elf_reloc_bad(lmp, (void *)rel, rtype, roffset,
			    rsymndx);
			continue;
		}

		binfo = 0;
		/*
		 * If a symbol index is specified then get the symbol table
		 * entry, locate the symbol definition, and determine its
		 * address.
		 */
		if (rsymndx) {
			/*
			 * If a Syminfo section is provided, determine if this
			 * symbol is deferred, and if so, skip this relocation.
			 */
			if (sip && is_sym_deferred((ulong_t)rel, basebgn, lmp,
			    textrel, sip, rsymndx))
				continue;

			/*
			 * Get the local symbol table entry.
			 */
			symref = (Sym *)((ulong_t)SYMTAB(lmp) +
			    (rsymndx * SYMENT(lmp)));

			/*
			 * If this is a local symbol, just use the base address.
			 * (we should have no local relocations in the
			 * executable).
			 */
			if (ELF_ST_BIND(symref->st_info) == STB_LOCAL) {
				value = basebgn;
				name = NULL;

				/*
				 * Special case TLS relocations.
				 */
				if (rtype == R_386_TLS_DTPMOD32) {
					/*
					 * Use the TLS modid.
					 */
					value = TLSMODID(lmp);

				} else if (rtype == R_386_TLS_TPOFF) {
					if ((value = elf_static_tls(lmp, symref,
					    rel, rtype, 0, roffset, 0)) == 0) {
						ret = 0;
						break;
					}
				}
			} else {
				/*
				 * If the symbol index is equal to the previous
				 * symbol index relocation we processed then
				 * reuse the previous values. (Note that there
				 * have been cases where a relocation exists
				 * against a copy relocation symbol, our ld(1)
				 * should optimize this away, but make sure we
				 * don't use the same symbol information should
				 * this case exist).
				 */
				if ((rsymndx == psymndx) &&
				    (rtype != R_386_COPY)) {
					/* LINTED */
					if (psymdef == 0) {
						DBG_CALL(Dbg_bind_weak(lmp,
						    (Addr)roffset, (Addr)
						    (roffset - basebgn), name));
						continue;
					}
					/* LINTED */
					value = pvalue;
					/* LINTED */
					name = pname;
					/* LINTED */
					symdef = psymdef;
					/* LINTED */
					symref = psymref;
					/* LINTED */
					_lmp = plmp;
					/* LINTED */
					binfo = pbinfo;

					if ((LIST(_lmp)->lm_tflags |
					    AFLAGS(_lmp)) &
					    LML_TFLG_AUD_SYMBIND) {
						value = audit_symbind(lmp, _lmp,
						    /* LINTED */
						    symdef, dsymndx, value,
						    &sb_flags);
					}
				} else {
					Slookup		sl;
					Sresult		sr;

					/*
					 * Lookup the symbol definition.
					 * Initialize the symbol lookup, and
					 * symbol result, data structures.
					 */
					name = (char *)(STRTAB(lmp) +
					    symref->st_name);

					SLOOKUP_INIT(sl, name, lmp, 0,
					    ld_entry_cnt, 0, rsymndx, symref,
					    rtype, LKUP_STDRELOC);
					SRESULT_INIT(sr, name);
					symdef = NULL;

					if (lookup_sym(&sl, &sr, &binfo,
					    in_nfavl)) {
						name = (char *)sr.sr_name;
						_lmp = sr.sr_dmap;
						symdef = sr.sr_sym;
					}

					/*
					 * If the symbol is not found and the
					 * reference was not to a weak symbol,
					 * report an error.  Weak references
					 * may be unresolved.
					 */
					/* BEGIN CSTYLED */
					if (symdef == 0) {
					    if (sl.sl_bind != STB_WEAK) {
						if (elf_reloc_error(lmp, name,
						    rel, binfo))
							continue;

					   	ret = 0;
						break;

					    } else {
						psymndx = rsymndx;
						psymdef = 0;

						DBG_CALL(Dbg_bind_weak(lmp,
						    (Addr)roffset, (Addr)
						    (roffset - basebgn), name));
						continue;
					    }
					}
					/* END CSTYLED */

					/*
					 * If symbol was found in an object
					 * other than the referencing object
					 * then record the binding.
					 */
					if ((lmp != _lmp) && ((FLAGS1(_lmp) &
					    FL1_RT_NOINIFIN) == 0)) {
						if (aplist_test(&bound, _lmp,
						    AL_CNT_RELBIND) == 0) {
							ret = 0;
							break;
						}
					}

					/*
					 * Calculate the location of definition;
					 * symbol value plus base address of
					 * containing shared object.
					 */
					if (IS_SIZE(rtype))
						value = symdef->st_size;
					else
						value = symdef->st_value;

					if (!(FLAGS(_lmp) & FLG_RT_FIXED) &&
					    !(IS_SIZE(rtype)) &&
					    (symdef->st_shndx != SHN_ABS) &&
					    (ELF_ST_TYPE(symdef->st_info) !=
					    STT_TLS))
						value += ADDR(_lmp);

					/*
					 * Retain this symbol index and the
					 * value in case it can be used for the
					 * subsequent relocations.
					 */
					if (rtype != R_386_COPY) {
						psymndx = rsymndx;
						pvalue = value;
						pname = name;
						psymdef = symdef;
						psymref = symref;
						plmp = _lmp;
						pbinfo = binfo;
					}
					if ((LIST(_lmp)->lm_tflags |
					    AFLAGS(_lmp)) &
					    LML_TFLG_AUD_SYMBIND) {
						dsymndx = (((uintptr_t)symdef -
						    (uintptr_t)SYMTAB(_lmp)) /
						    SYMENT(_lmp));
						value = audit_symbind(lmp, _lmp,
						    symdef, dsymndx, value,
						    &sb_flags);
					}
				}

				/*
				 * If relocation is PC-relative, subtract
				 * offset address.
				 */
				if (IS_PC_RELATIVE(rtype))
					value -= roffset;

				/*
				 * Special case TLS relocations.
				 */
				if (rtype == R_386_TLS_DTPMOD32) {
					/*
					 * Relocation value is the TLS modid.
					 */
					value = TLSMODID(_lmp);

				} else if (rtype == R_386_TLS_TPOFF) {
					if ((value = elf_static_tls(_lmp,
					    symdef, rel, rtype, name, roffset,
					    value)) == 0) {
						ret = 0;
						break;
					}
				}
			}
		} else {
			/*
			 * Special cases.
			 */
			if (rtype == R_386_TLS_DTPMOD32) {
				/*
				 * TLS relocation value is the TLS modid.
				 */
				value = TLSMODID(lmp);
			} else
				value = basebgn;

			name = NULL;
		}

		DBG_CALL(Dbg_reloc_in(LIST(lmp), ELF_DBG_RTLD, M_MACH,
		    M_REL_SHT_TYPE, rel, NULL, 0, name));

		/*
		 * Make sure the segment is writable.
		 */
		if (((mpp->mr_prot & PROT_WRITE) == 0) &&
		    ((set_prot(lmp, mpp, 1) == 0) ||
		    (aplist_append(textrel, mpp, AL_CNT_TEXTREL) == NULL))) {
			ret = 0;
			break;
		}

		/*
		 * Call relocation routine to perform required relocation.
		 */
		switch (rtype) {
		case R_386_COPY:
			if (elf_copy_reloc(name, symref, lmp, (void *)roffset,
			    symdef, _lmp, (const void *)value) == 0)
				ret = 0;
			break;
		case R_386_JMP_SLOT:
			if (((LIST(lmp)->lm_tflags | AFLAGS(lmp)) &
			    (LML_TFLG_AUD_PLTENTER | LML_TFLG_AUD_PLTEXIT)) &&
			    AUDINFO(lmp)->ai_dynplts) {
				int	fail = 0;
				int	pltndx = (((ulong_t)rel -
				    (uintptr_t)JMPREL(lmp)) / relsiz);
				int	symndx = (((uintptr_t)symdef -
				    (uintptr_t)SYMTAB(_lmp)) / SYMENT(_lmp));

				(void) elf_plt_trace_write(roffset, lmp, _lmp,
				    symdef, symndx, pltndx, (caddr_t)value,
				    sb_flags, &fail);
				if (fail)
					ret = 0;
			} else {
				/*
				 * Write standard PLT entry to jump directly
				 * to newly bound function.
				 */
				DBG_CALL(Dbg_reloc_apply_val(LIST(lmp),
				    ELF_DBG_RTLD, (Xword)roffset,
				    (Xword)value));
				*(ulong_t *)roffset = value;
			}
			break;
		default:
			/*
			 * Write the relocation out.
			 */
			if (do_reloc_rtld(rtype, (uchar_t *)roffset,
			    (Word *)&value, name, NAME(lmp), LIST(lmp)) == 0)
				ret = 0;

			DBG_CALL(Dbg_reloc_apply_val(LIST(lmp), ELF_DBG_RTLD,
			    (Xword)roffset, (Xword)value));
		}

		if ((ret == 0) &&
		    ((LIST(lmp)->lm_flags & LML_FLG_TRC_WARN) == 0))
			break;

		if (binfo) {
			DBG_CALL(Dbg_bind_global(lmp, (Addr)roffset,
			    (Off)(roffset - basebgn), (Xword)(-1), PLT_T_FULL,
			    _lmp, (Addr)value, symdef->st_value, name, binfo));
		}
	}

	return (relocate_finish(lmp, bound, ret));
}

/*
 * Initialize the first few got entries so that function calls go to
 * elf_rtbndr:
 *
 *	GOT[GOT_XLINKMAP] =	the address of the link map
 *	GOT[GOT_XRTLD] =	the address of rtbinder
 */
void
elf_plt_init(void *got, caddr_t l)
{
	uint_t		*_got;
	/* LINTED */
	Rt_map		*lmp = (Rt_map *)l;

	_got = (uint_t *)got + M_GOT_XLINKMAP;
	*_got = (uint_t)lmp;
	_got = (uint_t *)got + M_GOT_XRTLD;
	*_got = (uint_t)elf_rtbndr;
}

/*
 * For SVR4 Intel compatability.  USL uses /usr/lib/libc.so.1 as the run-time
 * linker, so the interpreter's address will differ from /usr/lib/ld.so.1.
 * Further, USL has special _iob[] and _ctype[] processing that makes up for the
 * fact that these arrays do not have associated copy relocations.  So we try
 * and make up for that here.  Any relocations found will be added to the global
 * copy relocation list and will be processed in setup().
 */
static int
_elf_copy_reloc(const char *name, Rt_map *rlmp, Rt_map *dlmp)
{
	Sym		*symref, *symdef;
	caddr_t 	ref, def;
	Rt_map		*_lmp;
	Rel		rel;
	Slookup		sl;
	Sresult		sr;
	uint_t		binfo;

	/*
	 * Determine if the special symbol exists as a reference in the dynamic
	 * executable, and that an associated definition exists in libc.so.1.
	 *
	 * Initialize the symbol lookup, and symbol result, data structures.
	 */
	SLOOKUP_INIT(sl, name, rlmp, rlmp, ld_entry_cnt, 0, 0, 0, 0,
	    LKUP_FIRST);
	SRESULT_INIT(sr, name);

	if (lookup_sym(&sl, &sr, &binfo, NULL) == 0)
		return (1);
	symref = sr.sr_sym;

	SLOOKUP_INIT(sl, name, rlmp, dlmp, ld_entry_cnt, 0, 0, 0, 0,
	    LKUP_DEFT);
	SRESULT_INIT(sr, name);

	if (lookup_sym(&sl, &sr, &binfo, NULL) == 0)
		return (1);

	_lmp = sr.sr_dmap;
	symdef = sr.sr_sym;

	if (strcmp(NAME(sr.sr_dmap), MSG_ORIG(MSG_PTH_LIBC)))
		return (1);

	/*
	 * Determine the reference and definition addresses.
	 */
	ref = (void *)(symref->st_value);
	if (!(FLAGS(rlmp) & FLG_RT_FIXED))
		ref += ADDR(rlmp);
	def = (void *)(symdef->st_value);
	if (!(FLAGS(sr.sr_dmap) & FLG_RT_FIXED))
		def += ADDR(_lmp);

	/*
	 * Set up a relocation entry for debugging and call the generic copy
	 * relocation function to provide symbol size error checking and to
	 * record the copy relocation that must be performed.
	 */
	rel.r_offset = (Addr)ref;
	rel.r_info = (Word)R_386_COPY;
	DBG_CALL(Dbg_reloc_in(LIST(rlmp), ELF_DBG_RTLD, M_MACH, M_REL_SHT_TYPE,
	    &rel, NULL, 0, name));

	return (elf_copy_reloc((char *)name, symref, rlmp, (void *)ref, symdef,
	    _lmp, (void *)def));
}

int
elf_copy_gen(Rt_map *lmp)
{
	if (interp && ((ulong_t)interp->i_faddr !=
	    r_debug.rtd_rdebug.r_ldbase) &&
	    !(strcmp(interp->i_name, MSG_ORIG(MSG_PTH_LIBC)))) {

		DBG_CALL(Dbg_reloc_run(lmp, M_REL_SHT_TYPE, 0,
		    DBG_REL_START));

		if (_elf_copy_reloc(MSG_ORIG(MSG_SYM_CTYPE), lmp,
		    (Rt_map *)NEXT(lmp)) == 0)
			return (0);
		if (_elf_copy_reloc(MSG_ORIG(MSG_SYM_IOB), lmp,
		    (Rt_map *)NEXT(lmp)) == 0)
			return (0);
	}
	return (1);
}

/*
 * Plt writing interface to allow debugging initialization to be generic.
 */
Pltbindtype
/* ARGSUSED1 */
elf_plt_write(uintptr_t addr, uintptr_t vaddr, void *rptr, uintptr_t symval,
	Xword pltndx)
{
	Rel		*rel = (Rel*)rptr;
	uintptr_t	pltaddr;

	pltaddr = addr + rel->r_offset;
	*(ulong_t *)pltaddr = (ulong_t)symval;
	DBG_CALL(pltcntfull++);
	return (PLT_T_FULL);
}

/*
 * Provide a machine specific interface to the conversion routine.  By calling
 * the machine specific version, rather than the generic version, we insure that
 * the data tables/strings for all known machine versions aren't dragged into
 * ld.so.1.
 */
const char *
_conv_reloc_type(uint_t rel)
{
	static Conv_inv_buf_t	inv_buf;

	return (conv_reloc_386_type(rel, 0, &inv_buf));
}
