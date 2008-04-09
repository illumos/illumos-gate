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
 *	All Rights Reserved
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * SPARC machine dependent and a.out format file class dependent functions.
 * Contains routines for performing function binding and symbol relocations.
 */
#include	"_synonyms.h"

#include	<stdio.h>
#include	<sys/types.h>
#include	<sys/mman.h>
#include	<synch.h>
#include	<dlfcn.h>
#include	<debug.h>
#include	"_a.out.h"
#include	"_rtld.h"
#include	"_audit.h"
#include	"msg.h"

extern void	iflush_range(caddr_t, size_t);

/*
 * Function binding routine - invoked on the first call to a function through
 * the procedure linkage table;
 * passes first through an assembly language interface.
 *
 * Takes the address of the PLT entry where the call originated,
 * the offset into the relocation table of the associated
 * relocation entry and the address of the link map (rt_private_map struct)
 * for the entry.
 *
 * Returns the address of the function referenced after re-writing the PLT
 * entry to invoke the function directly.
 *
 * On error, causes process to terminate with a signal.
 */
ulong_t
aout_bndr(caddr_t pc)
{
	Rt_map		*lmp, *nlmp, *llmp;
	struct relocation_info *rp;
	struct nlist	*sp;
	Sym		*sym;
	char		*name;
	int 		rndx, entry;
	ulong_t		symval;
	Slookup		sl;
	uint_t		binfo;
	Lm_list		*lml;

	/*
	 * For compatibility with libthread (TI_VERSION 1) we track the entry
	 * value.  A zero value indicates we have recursed into ld.so.1 to
	 * further process a locking request (see comments in completion()).
	 * Under this recursion we disable tsort and cleanup activities.
	 */
	entry = enter();

	for (lmp = lml_main.lm_head; lmp; lmp = (Rt_map *)NEXT(lmp)) {
		if (FCT(lmp) == &aout_fct) {
			if (pc > (caddr_t)(LM2LP(lmp)->lp_plt) &&
			    pc < (caddr_t)((int)LM2LP(lmp)->lp_plt +
			    AOUTDYN(lmp)->v2->ld_plt_sz))  {
				break;
			}
		}
	}

#define	LAST22BITS	0x3fffff

	/* LINTED */
	rndx = *(int *)(pc + (sizeof (ulong_t *) * 2)) & LAST22BITS;
	rp = &LM2LP(lmp)->lp_rp[rndx];
	sp = &LM2LP(lmp)->lp_symtab[rp->r_symbolnum];
	name = &LM2LP(lmp)->lp_symstr[sp->n_un.n_strx];

	/*
	 * Determine the last link-map of this list, this'll be the starting
	 * point for any tsort() processing.
	 */
	lml = LIST(lmp);
	llmp = lml->lm_tail;

	/*
	 * Find definition for symbol.  Initialize the symbol lookup data
	 * structure.
	 */
	SLOOKUP_INIT(sl, name, lmp, lml->lm_head, ld_entry_cnt, 0, 0, 0, 0,
	    LKUP_DEFT);

	if ((sym = aout_lookup_sym(&sl, &nlmp, &binfo, NULL)) == 0) {
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_REL_NOSYM), NAME(lmp),
		    demangle(name));
		rtldexit(lml, 1);
	}

	symval = sym->st_value;
	if (!(FLAGS(nlmp) & FLG_RT_FIXED) &&
	    (sym->st_shndx != SHN_ABS))
		symval += (int)(ADDR(nlmp));
	if ((lmp != nlmp) && ((FLAGS1(nlmp) & FL1_RT_NOINIFIN) == 0)) {
		/*
		 * Record that this new link map is now bound to the caller.
		 */
		if (bind_one(lmp, nlmp, BND_REFER) == 0)
			rtldexit(lml, 1);
	}

	/*
	 * Print binding information and rebuild PLT entry.
	 */
	DBG_CALL(Dbg_bind_global(lmp, (Addr)(ADDR(lmp) + rp->r_address),
	    (Off)rp->r_address, (Xword)(-1), PLT_T_NONE, nlmp,
	    (Addr)symval, sym->st_value, name, binfo));

	if (!(rtld_flags & RT_FL_NOBIND))
		aout_plt_write((caddr_t)(ADDR(lmp) + rp->r_address), symval);

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
	 * If the object we've bound to is in the process of being initialized
	 * by another thread, determine whether we should block.
	 */
	is_dep_ready(nlmp, lmp, DBG_WAIT_SYMBOL);

	/*
	 * Make sure the object to which we've bound has had it's .init fired.
	 * Cleanup before return to user code.
	 */
	if (entry) {
		is_dep_init(nlmp, lmp);
		leave(lml);
	}

	return (symval);
}


#define	IS_PC_RELATIVE(X) (pc_rel_type[(X)] == 1)

static const uchar_t pc_rel_type[] = {
	0,				/* RELOC_8 */
	0,				/* RELOC_16 */
	0,				/* RELOC_32 */
	1,				/* RELOC_DISP8 */
	1,				/* RELOC_DISP16 */
	1,				/* RELOC_DISP32 */
	1,				/* RELOC_WDISP30 */
	1,				/* RELOC_WDISP22 */
	0,				/* RELOC_HI22 */
	0,				/* RELOC_22 */
	0,				/* RELOC_13 */
	0,				/* RELOC_LO10 */
	0,				/* RELOC_SFA_BASE */
	0,				/* RELOC_SFA_OFF13 */
	0,				/* RELOC_BASE10 */
	0,				/* RELOC_BASE13 */
	0,				/* RELOC_BASE22 */
	0,				/* RELOC_PC10 */
	0,				/* RELOC_PC22 */
	0,				/* RELOC_JMP_TBL */
	0,				/* RELOC_SEGOFF16 */
	0,				/* RELOC_GLOB_DAT */
	0,				/* RELOC_JMP_SLOT */
	0				/* RELOC_RELATIVE */
};

int
aout_reloc(Rt_map * lmp, uint_t plt, int *in_nfavl)
{
	int		k;		/* loop temporary */
	int		nr;		/* number of relocations */
	char		*name;		/* symbol being searched for */
	long		*et;		/* cached _etext of object */
	long		value;		/* relocation temporary */
	long		*ra;		/* cached relocation address */
	struct relocation_info *rp;	/* current relocation */
	struct nlist	*sp;		/* symbol table of "symbol" */
	Rt_map *	_lmp;		/* lm which holds symbol definition */
	Sym *		sym;		/* symbol definition */
	int		textrel = 0, ret = 1;
	APlist		*bound = NULL;
	Lm_list		*lml = LIST(lmp);

	DBG_CALL(Dbg_reloc_run(lmp, SHT_RELA, plt, DBG_REL_START));

	/*
	 * If we've been called upon to promote an RTLD_LAZY object to an
	 * RTLD_NOW don't bother to do anything - a.out's are bound as if
	 * RTLD_NOW regardless.
	 */
	if (plt)
		return (1);

	rp = LM2LP(lmp)->lp_rp;
	et = (long *)ETEXT(lmp);
	nr = GETRELSZ(AOUTDYN(lmp)) / sizeof (struct relocation_info);

	/*
	 * Initialize _PLT_, if any.
	 */
	if (AOUTDYN(lmp)->v2->ld_plt_sz)
		aout_plt_write((caddr_t)LM2LP(lmp)->lp_plt->jb_inst,
		    (ulong_t)aout_rtbndr);

	/*
	 * Loop through relocations.
	 */
	for (k = 0; k < nr; k++, rp++) {
		/* LINTED */
		ra = (long *)&((char *)ADDR(lmp))[rp->r_address];

		/*
		 * Check to see if we're relocating in the text segment
		 * and turn off the write protect if necessary.
		 */
		if ((ra < et) && (textrel == 0)) {
			if (aout_set_prot(lmp, PROT_WRITE) == 0) {
				ret = 0;
				break;
			}
			textrel = 1;
		}

		/*
		 * Perform the relocation.
		 */
		if (rp->r_extern == 0) {
			name = (char *)0;
			value = ADDR(lmp);
		} else {
			Slookup		sl;
			uint_t		binfo;

			if (rp->r_type == RELOC_JMP_SLOT)
				continue;
			sp = &LM2LP(lmp)->lp_symtab[rp->r_symbolnum];
			name = &LM2LP(lmp)->lp_symstr[sp->n_un.n_strx];

			/*
			 * Locate symbol.  Initialize the symbol lookup data
			 * structure.
			 */
			SLOOKUP_INIT(sl, name, lmp, 0, ld_entry_cnt, 0, 0, 0, 0,
			    LKUP_STDRELOC);

			if ((sym = aout_lookup_sym(&sl, &_lmp,
			    &binfo, in_nfavl)) == 0) {
				if (lml->lm_flags & LML_FLG_TRC_WARN) {
					(void)
					    printf(MSG_INTL(MSG_LDD_SYM_NFOUND),
					    demangle(name), NAME(lmp));
					continue;
				} else {
					eprintf(lml, ERR_FATAL,
					    MSG_INTL(MSG_REL_NOSYM), NAME(lmp),
					    demangle(name));
					ret = 0;
					break;
				}
			}

			/*
			 * If symbol was found in an object other than the
			 * referencing object then record the binding.
			 */
			if ((lmp != _lmp) &&
			    ((FLAGS1(_lmp) & FL1_RT_NOINIFIN) == 0)) {
				if (aplist_test(&bound, _lmp,
				    AL_CNT_RELBIND) == 0) {
					ret = 0;
					break;
				}
			}

			value = sym->st_value + rp->r_addend;
			if (!(FLAGS(_lmp) & FLG_RT_FIXED) &&
			    (sym->st_shndx != SHN_COMMON) &&
			    (sym->st_shndx != SHN_ABS))
				value += ADDR(_lmp);

			if (IS_PC_RELATIVE(rp->r_type))
				value -= (long)ADDR(lmp);

			DBG_CALL(Dbg_bind_global(lmp, (Addr)ra,
			    (Off)(ra - ADDR(lmp)), (Xword)(-1), PLT_T_NONE,
			    _lmp, (Addr)value, sym->st_value, name, binfo));
		}

		/*
		 * Perform a specific relocation operation.
		 */
		switch (rp->r_type) {
		case RELOC_RELATIVE:
			value += *ra << (32-22);
			*(long *)ra = (*(long *)ra & ~S_MASK(22)) |
			    ((value >> (32 - 22)) & S_MASK(22));
			ra++;
			value += (*ra & S_MASK(10));
			*(long *)ra = (*(long *)ra & ~S_MASK(10)) |
			    (value & S_MASK(10));
			break;
		case RELOC_8:
		case RELOC_DISP8:
			value += *ra & S_MASK(8);
			if (!S_INRANGE(value, 8)) {
				eprintf(lml, ERR_FATAL,
				    MSG_INTL(MSG_REL_OVERFLOW), NAME(lmp),
				    (name ? demangle(name) :
				    MSG_INTL(MSG_STR_UNKNOWN)), (int)value, 8,
				    (uint_t)ra);
			}
			*ra = value;
			break;
		case RELOC_LO10:
		case RELOC_BASE10:
			value += *ra & S_MASK(10);
			*(long *)ra = (*(long *)ra & ~S_MASK(10)) |
			    (value & S_MASK(10));
			break;
		case RELOC_BASE13:
		case RELOC_13:
			value += *ra & S_MASK(13);
			*(long *)ra = (*(long *)ra & ~S_MASK(13)) |
			    (value & S_MASK(13));
			break;
		case RELOC_16:
		case RELOC_DISP16:
			value += *ra & S_MASK(16);
			if (!S_INRANGE(value, 16)) {
				eprintf(lml, ERR_FATAL,
				    MSG_INTL(MSG_REL_OVERFLOW), NAME(lmp),
				    (name ? demangle(name) :
				    MSG_INTL(MSG_STR_UNKNOWN)), (int)value, 16,
				    (uint_t)ra);
			}
			*(short *)ra = value;
			break;
		case RELOC_22:
		case RELOC_BASE22:
			value += *ra & S_MASK(22);
			if (!S_INRANGE(value, 22)) {
				eprintf(lml, ERR_FATAL,
				    MSG_INTL(MSG_REL_OVERFLOW), NAME(lmp),
				    (name ? demangle(name) :
				    MSG_INTL(MSG_STR_UNKNOWN)), (int)value, 22,
				    (uint_t)ra);
			}
			*(long *)ra = (*(long *)ra & ~S_MASK(22)) |
			    (value & S_MASK(22));
			break;
		case RELOC_HI22:
			value += (*ra & S_MASK(22)) << (32 - 22);
			*(long *)ra = (*(long *)ra & ~S_MASK(22)) |
			    ((value >> (32 - 22)) & S_MASK(22));
			break;
		case RELOC_WDISP22:
			value += *ra & S_MASK(22);
			value >>= 2;
			if (!S_INRANGE(value, 22)) {
				eprintf(lml, ERR_FATAL,
				    MSG_INTL(MSG_REL_OVERFLOW), NAME(lmp),
				    (name ? demangle(name) :
				    MSG_INTL(MSG_STR_UNKNOWN)), (int)value, 22,
				    (uint_t)ra);
			}
			*(long *)ra = (*(long *)ra & ~S_MASK(22)) |
			    (value & S_MASK(22));
			break;
		case RELOC_WDISP30:
			value += *ra & S_MASK(30);
			value >>= 2;
			*(long *)ra = (*(long *)ra & ~S_MASK(30)) |
			    (value & S_MASK(30));
			break;
		case RELOC_32:
		case RELOC_GLOB_DAT:
		case RELOC_DISP32:
			value += *ra;
			*(long *)ra = value;
			break;
		default:
			eprintf(lml, ERR_FATAL, MSG_INTL(MSG_REL_UNIMPL),
			    NAME(lmp), (name ? demangle(name) :
			    MSG_INTL(MSG_STR_UNKNOWN)), rp->r_type);
			ret = 0;
			break;
		}

		/*
		 * If this relocation is against a text segment we must make
		 * sure that the instruction cache is flushed.
		 */
		if (textrel) {
			if (rp->r_type == RELOC_RELATIVE)
				iflush_range((caddr_t)(ra - 1), 0x8);
			else
				iflush_range((caddr_t)ra, 0x4);
		}
	}

	return (relocate_finish(lmp, bound, textrel, ret));
}
