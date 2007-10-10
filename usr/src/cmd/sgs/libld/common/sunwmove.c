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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<string.h>
#include	<debug.h>
#include	"msg.h"
#include	"_libld.h"

/*
 *
 */
static uintptr_t
make_mvsections(Ofl_desc *ofl)
{
	Listnode *	lnp1;
	Psym_info *	psym;
	Word 		mv_nums = 0;
	Xword		align_sunwbss = 0;	/* Alignment for .sunwbss */
	Xword		align_sunwdata1 = 0;	/*   for .sunwdata1 */
	size_t		size_sunwbss = 0;	/* Size of .sunwbss */
	size_t		size_sunwdata1 = 0;	/* Size of .sunwdata1 */

	/*
	 * Compute the size of the output move section
	 */
	for (LIST_TRAVERSE(&ofl->ofl_parsym, lnp1, psym)) {
		Sym_desc *	symd = psym->psym_symd;
		Sym *		sym;
		Xword		align_val;

		sym = symd->sd_sym;
		if (sym->st_shndx == SHN_COMMON)
			align_val = sym->st_value;
		else
			align_val = 8;
		if (symd->sd_flags & FLG_SY_PAREXPN) {
			/*
			 * This global symbol goes to .sunwdata1
			 */
			size_sunwdata1 = (size_t)S_ROUND(size_sunwdata1,
			    sym->st_value) + sym->st_size;
			if (align_val > align_sunwdata1)
				align_sunwdata1 = align_val;

		} else {
			if ((ofl->ofl_flags & FLG_OF_SHAROBJ) &&
			    (symd->sd_flags & FLG_SY_TENTSYM) &&
			    (ELF_ST_BIND(sym->st_info) != STB_LOCAL)) {
				/*
				 * If output file is non-executable
				 * shared object, and this is a tentative symbol
				 * this symbol goes to .sunwbss
				 */
				size_sunwbss = (size_t)S_ROUND(size_sunwbss,
				    sym->st_value) + sym->st_size;
				if (align_val > align_sunwbss)
					align_sunwbss = align_val;
			}
			mv_nums += psym->psym_num;
		}
	}

	if (mv_nums != 0) {
		if (ld_make_sunwmove(ofl, mv_nums) == S_ERROR)
			return (S_ERROR);
	}

	/*
	 * Generate the .sunwbss section now that we know its size and
	 * alignment.
	 */
	if (size_sunwbss) {
		if (ld_make_sunwbss(ofl, size_sunwbss,
		    align_sunwbss) == S_ERROR)
			return (S_ERROR);
	}

	/*
	 * Add empty area for partially initialized symbols.
	 *
	 * The .SUNWDATA1 is to be created when '-z option' is in effect or
	 * there are any partially init. symbol which are to be expanded.
	 */
	if (size_sunwdata1) {
		/* LINTED */
		if (ld_make_sunwdata(ofl, size_sunwdata1,
		    align_sunwdata1) == S_ERROR)
			return (S_ERROR);
	}
	return (1);
}

/*
 * This function insert the Move_itm into the move list held by
 * psymp.
 */
static uintptr_t
insert_mvitm(Ofl_desc *ofl, Psym_info *psymp, Mv_itm *itm)
{
	Listnode *	lnpc, *lnpp, *new;
	Mv_itm *	mvp;

	/*
	 * If there is error on this symbol already,
	 * don't go any further.
	 */
	if ((psymp->psym_flag & FLG_PSYM_OVERLAP) != 0)
		return (1);

	if ((new = libld_calloc(sizeof (Listnode), 1)) == 0)
		return (S_ERROR);
	new->data = (void *) itm;
	lnpp = lnpc = psymp->psym_mvs.head;

	/*
	 * If this is the first, just update the
	 * head and tail.
	 */
	if (lnpc == (Listnode *) NULL) {
		psymp->psym_mvs.tail = psymp->psym_mvs.head = new;
		return (1);
	}

	for (LIST_TRAVERSE(&psymp->psym_mvs, lnpc, mvp)) {
		Mv_itm *	small, *large;

		/*
		 * Check overlapping
		 * If there is no overlapping so far,
		 * check overlapping.
		 */
		if (itm->mv_start > mvp->mv_start) {
			small = mvp;
			large = itm;
		} else {
			small = itm;
			large = mvp;
		}

		if ((itm->mv_start == mvp->mv_start) ||
		    (small->mv_start + small->mv_length > large->mv_start)) {
			eprintf(ofl->ofl_lml, ERR_FATAL,
			    MSG_INTL(MSG_PSYM_OVERLAP),
			    psymp->psym_symd->sd_file->ifl_name,
			    itm->mv_isp->is_name,
			    demangle(psymp->psym_symd->sd_name));
			psymp->psym_flag |= FLG_PSYM_OVERLAP;
			return (1);
		}

		/*
		 * If passed, insert
		 */
		if (mvp->mv_start > itm->mv_start) {
			new->next = lnpc;
			if (lnpc == psymp->psym_mvs.head) {
				psymp->psym_mvs.head = new;
			} else
				lnpp->next = new;
			return (1);
		}

		/*
		 * If lnpc is the end, add
		 */
		if (lnpc->next == NULL) {
			new->next = lnpc->next;
			lnpc->next = new;
			psymp->psym_mvs.tail = new;
			return (1);
		}

		/*
		 * Go next
		 */
		lnpp = lnpc;
	}
	return (1);
}

/*
 * Install the mv entry into the Psym_info
 *
 * Count coverage size
 *	If the coverage size meets the symbol size,
 *	mark that the symbol should be expanded.
 *	psymp->psym_symd->sd_flags |= FLG_SY_PAREXPN;
 *
 * Check overlapping
 *	If overlapping occurs, mark it at psymp->psym_flags
 */
static uintptr_t
install_mv(Ofl_desc *ofl, Psym_info *psymp, Move *mv, Is_desc *isp)
{
	Mv_itm *	mvitmp;
	int 		cnt = mv->m_repeat;
	int 		i;

	if ((mvitmp = libld_calloc(sizeof (Mv_itm), cnt)) == 0)
		return (S_ERROR);

	mvitmp->mv_flag |= FLG_MV_OUTSECT;
	psymp->psym_num += 1;
	for (i = 0; i < cnt; i++) {
		/* LINTED */
		mvitmp->mv_length = ELF_M_SIZE(mv->m_info);
		mvitmp->mv_start = mv->m_poffset + i *
		    ((mv->m_stride + 1) * mvitmp->mv_length);
		mvitmp->mv_ientry = mv;
		mvitmp->mv_isp = isp;		/* Mark input section */

		/*
		 * Insert the item
		 */
		if (insert_mvitm(ofl, psymp, mvitmp) == S_ERROR)
			return (S_ERROR);
		mvitmp++;
	}
	return (1);
}

/*
 * Insert the given psym_info
 */
static uintptr_t
insert_psym(Ofl_desc *ofl, Psym_info *p1)
{
	Listnode *	lnpc, *lnpp, *new;
	Psym_info *	p2;
	int		g1 = 0;

	if ((new = libld_calloc(sizeof (Listnode), 1)) == 0)
		return (S_ERROR);
	new->data = (void *) p1;
	lnpp = lnpc = ofl->ofl_parsym.head;
	if (ELF_ST_BIND(p1->psym_symd->sd_sym->st_info) != STB_LOCAL)
		g1 = 1;

	/*
	 * If this is the first, just update the
	 * head and tail.
	 */
	if (lnpc == (Listnode *) NULL) {
		ofl->ofl_parsym.tail = ofl->ofl_parsym.head = new;
		return (1);
	}

	for (LIST_TRAVERSE(&ofl->ofl_parsym, lnpc, p2)) {
		int cmp1, g2, cmp;

		if (ELF_ST_BIND(p2->psym_symd->sd_sym->st_info) != STB_LOCAL)
			g2 = 1;
		else
			g2 = 0;

		cmp1 = strcmp(p1->psym_symd->sd_name, p2->psym_symd->sd_name);

		/*
		 * Compute position
		 */
		if (g1 == g2)
			cmp = cmp1;
		else if (g1 == 0) {
			/*
			 * p1 is a local symbol.
			 * p2 is a global, so p1 passed.
			 */
			cmp = -1;
		} else {
			/*
			 * p1 is global
			 * p2 is still local.
			 * so try the next one.
			 *
			 * If lnpc is the end, add
			 */
			if (lnpc->next == NULL) {
				new->next = lnpc->next;
				lnpc->next = new;
				ofl->ofl_parsym.tail = new;
				break;
			}
			lnpp = lnpc;
			continue;
		}

		/*
		 * If same, just add after
		 */
		if (cmp == 0) {
			new->next = lnpc->next;
			if (lnpc == ofl->ofl_parsym.tail)
				ofl->ofl_parsym.tail = new;
			lnpc->next = new;
			break;
		}

		/*
		 * If passed, insert
		 */
		if (cmp < 0) {
			new->next = lnpc;
			if (lnpc == ofl->ofl_parsym.head) {
				ofl->ofl_parsym.head = new;
			} else
				lnpp->next = new;
			break;
		}

		/*
		 * If lnpc is the end, add
		 */
		if (lnpc->next == NULL) {
			new->next = lnpc->next;
			lnpc->next = new;
			ofl->ofl_parsym.tail = new;
			break;
		}

		/*
		 * Go next
		 */
		lnpp = lnpc;
	}
	return (1);
}

/*
 * Mark the symbols
 *
 * Check only the symbols which came from the relocatable
 * files.If partially initialized symbols come from
 * shared objects, they can be ignored here because
 * they are already processed when the shared object is
 * created.
 *
 */
uintptr_t
ld_sunwmove_preprocess(Ofl_desc *ofl)
{
	Listnode *	lnp;
	Is_desc *	isp;
	Sym_desc *	sdp;
	Move *		mv;
	Psym_info *	psym;
	int 		errcnt = 0;

	for (LIST_TRAVERSE(&ofl->ofl_ismove, lnp, isp)) {
		Ifl_desc *	ifile = isp->is_file;
		Xword		i, num;

		DBG_CALL(Dbg_move_input(ofl->ofl_lml, ifile->ifl_name));
		mv = (Move *) isp->is_indata->d_buf;

		if (isp->is_shdr->sh_entsize == 0) {
			eprintf(ofl->ofl_lml, ERR_FATAL,
			    MSG_INTL(MSG_FIL_INVSHENTSIZE),
			    isp->is_file->ifl_name, isp->is_name, EC_XWORD(0));
			return (S_ERROR);
		}
		num = isp->is_shdr->sh_size/isp->is_shdr->sh_entsize;
		for (i = 0; i < num; i++) {
			Xword 	ndx = ELF_M_SYM(mv->m_info);

			if ((ndx >= (Xword) isp->is_file->ifl_symscnt) ||
			    (ndx == 0)) {
				eprintf(ofl->ofl_lml, ERR_FATAL,
				    MSG_INTL(MSG_PSYM_INVMINFO1),
				    isp->is_file->ifl_name, isp->is_name, i,
				    EC_XWORD(mv->m_info));
				return (S_ERROR);
			}
			if (mv->m_repeat == 0) {
				eprintf(ofl->ofl_lml, ERR_FATAL,
				    MSG_INTL(MSG_PSYM_INVMREPEAT),
				    isp->is_file->ifl_name, isp->is_name, i,
				    EC_XWORD(mv->m_repeat));
				return (S_ERROR);
			}

			sdp = isp->is_file->ifl_oldndx[ndx];
			DBG_CALL(Dbg_move_entry1(ofl->ofl_lml, 0, mv, sdp));

			/*
			 * Check if this entry has a valid size of not
			 */
			/* LINTED */
			switch (ELF_M_SIZE(mv->m_info)) {
			case 1: case 2: case 4: case 8:
				break;
			default:
				eprintf(ofl->ofl_lml, ERR_FATAL,
				    MSG_INTL(MSG_PSYM_INVMINFO2),
				    isp->is_file->ifl_name, isp->is_name, i,
				    EC_XWORD(mv->m_info));
				return (S_ERROR);
			}

			/*
			 * If this is a global symbol, adjust the visibility.
			 */
			if (sdp->sd_aux &&
			    ((sdp->sd_flags & FLG_SY_VISIBLE) == 0))
				ld_sym_adjust_vis(sdp, ofl);

			if (sdp->sd_psyminfo == (Psym_info *)NULL) {
				/*
				 * Mark the symbol as partial, and install the
				 * symbol in the partial symbol list.
				 */
				if ((psym =
				    libld_calloc(sizeof (Psym_info), 1)) == 0)
					return (S_ERROR);
				psym->psym_symd = sdp;
				sdp->sd_psyminfo = psym;

				/*
				 * Even if the -zredlocsym is in effect, the
				 * local symbol used for partial initialization
				 * is kept.
				 */
				if ((ofl->ofl_flags1 & FLG_OF1_REDLSYM) &&
				    (ELF_ST_BIND(sdp->sd_sym->st_info) ==
				    STB_LOCAL) &&
				    (ELF_ST_TYPE(sdp->sd_sym->st_info) ==
				    STT_OBJECT)) {
					ofl->ofl_locscnt++;
					if (st_insert(ofl->ofl_strtab,
					    sdp->sd_name) == -1)
						return (S_ERROR);
				}
				if (insert_psym(ofl, psym) == 0)
					return (S_ERROR);

				/*
				 * Mark the input section which the partially
				 * initialized * symbol is defined.
				 * This is needed when the symbol
				 * the relocation entry uses symbol information
				 * not from the symbol entry.
				 *
				 * For executable, the following is
				 * needed only for expanded symbol. However,
				 * for shared object * any partially non
				 * expanded symbols are moved * from
				 * .bss/COMMON to .sunwbss. So the following are
				 * needed.
				 */
				if ((sdp->sd_sym->st_shndx != SHN_UNDEF) &&
				    (sdp->sd_sym->st_shndx < SHN_LOPROC)) {
					Is_desc * isym = ifile->ifl_isdesc[
					    sdp->sd_sym->st_shndx];
					isym->is_flags |= FLG_IS_RELUPD;
					if (sdp->sd_osym == (Sym *) 0) {
						if ((sdp->sd_osym =
						    libld_calloc(sizeof (Sym),
						    1)) == 0)
							return (S_ERROR);
						*(sdp->sd_osym) =
						    *(sdp->sd_sym);
					}
				}
			} else
				psym = sdp->sd_psyminfo;

			if (install_mv(ofl, psym, mv, isp) == S_ERROR)
				return (S_ERROR);
			if ((psym->psym_flag & FLG_PSYM_OVERLAP) != 0)
				errcnt++;

			/*
			 * If this symbol is marked to be
			 * expanded, go to the next moveentry.
			 */
			if (sdp->sd_flags & FLG_SY_PAREXPN) {
				mv++;
				continue;
			}

			/*
			 * Decide whether this partial symbol is to be expanded
			 * or not.
			 *
			 * The symbol will be expanded if:
			 *	a) '-z nopartial' is specified
			 *	b) move entries covered entire symbol
			 *
			 * To expand an move entry, size of the symbol to be
			 * expanded need to be known to generate a file space.
			 * (see make_movesections().)
			 *
			 * Therefore the move entry can not be expanded
			 * if the partial symbol is a section symbol.
			 * (The size of the symbol may be unknown.)
			 * This may happen, for example, when a local symbol is
			 * reduced by the -zredlocsym.
			 *
			 * The following two if statements checks the
			 * if the move entry can be expanded or not.
			 */
			if (((ofl->ofl_flags & FLG_OF_STATIC) != 0) &&
			    ((ofl->ofl_flags & FLG_OF_EXEC) != 0)) {
				if (ELF_ST_TYPE(sdp->sd_sym->st_info) ==
				    STT_SECTION) {
					errcnt++;
					eprintf(ofl->ofl_lml, ERR_FATAL,
					    MSG_INTL(MSG_PSYM_CANNOTEXPND),
					    psym->psym_symd->sd_file->ifl_name,
					    isp->is_name, i,
					    MSG_INTL(MSG_PSYM_NOSTATIC));
				} else {
					sdp->sd_flags |= FLG_SY_PAREXPN;
				}
			} else if ((ofl->ofl_flags1 & FLG_OF1_NOPARTI) != 0) {
				if (ELF_ST_TYPE(sdp->sd_sym->st_info) ==
				    STT_SECTION) {
					eprintf(ofl->ofl_lml, ERR_WARNING,
					    MSG_INTL(MSG_PSYM_CANNOTEXPND),
					    psym->psym_symd->sd_file->ifl_name,
					    isp->is_name, i,
					    MSG_ORIG(MSG_STR_EMPTY));
				} else {
					sdp->sd_flags |= FLG_SY_PAREXPN;
				}
			} else if (
			    ((Xword)((sizeof (Move)) * psym->psym_num) >
			    psym->psym_symd->sd_sym->st_size) &&
			    (ELF_ST_TYPE(sdp->sd_sym->st_info) == STT_OBJECT)) {
				sdp->sd_flags |= FLG_SY_PAREXPN;
			}

			/*
			 * If a move section exists that references .bss, make
			 * sure a section symbol for .bss is introduced into
			 * the .dynsym.
			 */
			if (((sdp->sd_flags & FLG_SY_PAREXPN) == 0) &&
			    ((ELF_ST_BIND(sdp->sd_sym->st_info) == STB_LOCAL) ||
			    ((sdp->sd_flags1 & FLG_SY1_HIDDEN) &&
			    (ofl->ofl_flags & FLG_OF_PROCRED)))) {
				ofl->ofl_flags1 |= FLG_OF1_BSSOREL;
			}
			mv++;
		}
	}

	if (errcnt != 0)
		return (S_ERROR);
	if (make_mvsections(ofl) == S_ERROR)
		return (S_ERROR);

	return (1);
}
