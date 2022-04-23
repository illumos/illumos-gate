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
 * Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include	<string.h>
#include	<debug.h>
#include	"msg.h"
#include	"_libld.h"

/*
 * Scan all partially initialized symbols to determine what output Move sections
 * or partially expanded data section, must be created.
 */
static uintptr_t
make_mvsections(Ofl_desc *ofl)
{
	Aliste		idx;
	Sym_desc	*sdp;
	Word		mv_nums = 0;
	Xword		align_parexpn = 0;	/* for -z nopartial .data sec */
	size_t		size_parexpn = 0;	/* size of parexpn section */

	/*
	 * Compute the size of the output move section
	 */
	for (APLIST_TRAVERSE(ofl->ofl_parsyms, idx, sdp)) {
		if (sdp->sd_flags & FLG_SY_PAREXPN) {
			Sym	*sym = sdp->sd_sym;
			Xword	align_val;

			if (sym->st_shndx == SHN_COMMON)
				align_val = sym->st_value;
			else
				align_val = 8;

			/*
			 * This global symbol is redirected to the special
			 * partial initialization .data section.
			 */
			size_parexpn = (size_t)S_ROUND(size_parexpn,
			    sym->st_value) + sym->st_size;
			if (align_val > align_parexpn)
				align_parexpn = align_val;

		} else {
			mv_nums += alist_nitems(sdp->sd_move);
		}
	}

	/*
	 * Generate a new Move section.
	 */
	if (mv_nums && (ld_make_sunwmove(ofl, mv_nums) == S_ERROR))
		return (S_ERROR);

	/*
	 * Add empty area for partially initialized symbols.
	 *
	 * A special .data section is created when the '-z nopartial'
	 * option is in effect in order to receive the expanded data.
	 */
	if (size_parexpn) {
		/* LINTED */
		if (ld_make_parexpn_data(ofl, size_parexpn,
		    align_parexpn) == S_ERROR)
			return (S_ERROR);
	}
	return (1);
}

/*
 * Assign move descriptors with the associated target symbol.
 */
static uintptr_t
append_move_desc(Ofl_desc *ofl, Sym_desc *sdp, Move *mvp, Is_desc *isp)
{
	int	i, cnt = mvp->m_repeat;

	for (i = 0; i < cnt; i++) {
		Aliste		idx;
		Mv_desc		*omdp, nmd;

		/* LINTED */
		nmd.md_len = ELF_M_SIZE(mvp->m_info);
		nmd.md_start = mvp->m_poffset + i *
		    ((mvp->m_stride + 1) * nmd.md_len);
		nmd.md_move = mvp;

		/*
		 * Verify that this move descriptor doesn't overlap any existing
		 * move descriptors.
		 */
		for (ALIST_TRAVERSE(sdp->sd_move, idx, omdp)) {
			Mv_desc	*smdp, *lmdp;

			if (nmd.md_start > omdp->md_start) {
				smdp = omdp;
				lmdp = &nmd;
			} else {
				smdp = &nmd;
				lmdp = omdp;
			}

			/*
			 * If this move entry is exactly the same as that of
			 * a symbol that has overridden this symbol (for example
			 * should two identical COMMON definitions be associated
			 * with the same move data), simply ignore this move
			 * element.
			 */
			if ((nmd.md_start == omdp->md_start) &&
			    ((nmd.md_len == smdp->md_len) &&
			    sdp->sd_file != isp->is_file))
				continue;

			if ((nmd.md_start != omdp->md_start) &&
			    ((smdp->md_start + smdp->md_len) <= lmdp->md_start))
				continue;

			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_MOVE_OVERLAP),
			    sdp->sd_file->ifl_name, EC_WORD(isp->is_scnndx),
			    isp->is_name, demangle(sdp->sd_name),
			    EC_XWORD(nmd.md_start), EC_XWORD(nmd.md_len),
			    EC_XWORD(omdp->md_start), EC_XWORD(omdp->md_len));

			/*
			 * Indicate that an error has occurred, so that
			 * processing can be terminated once all move errors
			 * are flushed out.
			 */
			sdp->sd_flags |= FLG_SY_OVERLAP;
			return (1);
		}

		if (alist_append(&sdp->sd_move, &nmd, sizeof (Mv_desc),
		    AL_CNT_SDP_MOVE) == NULL)
			return (S_ERROR);
	}
	return (1);
}

/*
 * Validate a SHT_SUNW_move section.  These are only processed from input
 * relocatable objects.  The move section entries are validated and any data
 * structures required for later processing are created.
 */
uintptr_t
ld_process_move(Ofl_desc *ofl)
{
	Aliste		idx;
	Is_desc		*isp;
	int		errcnt = 0;

	for (APLIST_TRAVERSE(ofl->ofl_ismove, idx, isp)) {
		Ifl_desc	*ifile = isp->is_file;
		Move		*mvp;
		Xword		i, num;

		DBG_CALL(Dbg_move_input(ofl->ofl_lml, ifile->ifl_name));
		mvp = (Move *)isp->is_indata->d_buf;

		if (isp->is_shdr->sh_entsize == 0) {
			ld_eprintf(ofl, ERR_FATAL,
			    MSG_INTL(MSG_FIL_INVSHENTSIZE),
			    isp->is_file->ifl_name, EC_WORD(isp->is_scnndx),
			    isp->is_name, EC_XWORD(0));
			return (S_ERROR);
		}
		num = isp->is_shdr->sh_size / isp->is_shdr->sh_entsize;

		for (i = 0; i < num; i++) {
			Xword		ndx = ELF_M_SYM(mvp->m_info);
			Sym_desc	*sdp;
			Sym		*sym;

			if ((ndx >= (Xword) isp->is_file->ifl_symscnt) ||
			    (ndx == 0)) {
				ld_eprintf(ofl, ERR_FATAL,
				    MSG_INTL(MSG_PSYM_INVMINFO1),
				    isp->is_file->ifl_name,
				    EC_WORD(isp->is_scnndx), isp->is_name, i,
				    EC_XWORD(mvp->m_info));
				return (S_ERROR);
			}
			if (mvp->m_repeat == 0) {
				ld_eprintf(ofl, ERR_FATAL,
				    MSG_INTL(MSG_PSYM_INVMREPEAT),
				    isp->is_file->ifl_name,
				    EC_WORD(isp->is_scnndx), isp->is_name, i,
				    EC_XWORD(mvp->m_repeat));
				return (S_ERROR);
			}

			sdp = isp->is_file->ifl_oldndx[ndx];
			DBG_CALL(Dbg_move_entry1(ofl->ofl_lml, 1, mvp, sdp));

			/*
			 * Validate that this entry has a valid size.
			 */
			/* LINTED */
			switch (ELF_M_SIZE(mvp->m_info)) {
			case 1: case 2: case 4: case 8:
				break;
			default:
				ld_eprintf(ofl, ERR_FATAL,
				    MSG_INTL(MSG_PSYM_INVMINFO2),
				    isp->is_file->ifl_name,
				    EC_WORD(isp->is_scnndx), isp->is_name, i,
				    EC_XWORD(mvp->m_info));
				return (S_ERROR);
			}

			/*
			 * If this is a global symbol, adjust the visibility.
			 */
			if (sdp->sd_aux &&
			    ((sdp->sd_flags & FLG_SY_VISIBLE) == 0))
				ld_sym_adjust_vis(sdp, ofl);

			sym = sdp->sd_sym;

			if (sdp->sd_move == NULL) {
				/*
				 * If this is the first move entry associated
				 * with this symbol, save the symbol on the
				 * partial symbol list, and initialize various
				 * state regarding this symbol.
				 */
				if (aplist_append(&ofl->ofl_parsyms, sdp,
				    AL_CNT_OFL_PARSYMS) == NULL)
					return (S_ERROR);

				/*
				 * Even if -zredlocsym is in effect, the local
				 * symbol used for partial initialization is
				 * kept.
				 */
				if ((ofl->ofl_flags & FLG_OF_REDLSYM) &&
				    (ELF_ST_BIND(sym->st_info) == STB_LOCAL) &&
				    (ELF_ST_TYPE(sym->st_info) == STT_OBJECT)) {
					ofl->ofl_locscnt++;
					if (st_insert(ofl->ofl_strtab,
					    sdp->sd_name) == -1)
						return (S_ERROR);
				}

				/*
				 * Mark the input section associated with this
				 * partially initialized symbol.
				 * This is needed when the symbol
				 * the relocation entry uses symbol information
				 * not from the symbol entry.
				 *
				 * For executable, the following is
				 * needed only for expanded symbol. However,
				 * for shared object any partially non
				 * expanded symbols are moved from
				 * .bss/COMMON to .sunwbss. So the following are
				 * needed.
				 */
				if ((sym->st_shndx != SHN_UNDEF) &&
				    (sym->st_shndx < SHN_LOPROC)) {
					Is_desc	*isc;

					isc = ifile->ifl_isdesc[ sym->st_shndx];
					isc->is_flags |= FLG_IS_RELUPD;

					if (sdp->sd_osym == NULL) {
						if ((sdp->sd_osym =
						    libld_calloc(1,
						    sizeof (Sym))) == NULL)
							return (S_ERROR);
						*(sdp->sd_osym) =
						    *(sdp->sd_sym);
					}
				}
			}

			if (append_move_desc(ofl, sdp, mvp, isp) == S_ERROR)
				return (S_ERROR);

			if (sdp->sd_flags & FLG_SY_OVERLAP)
				errcnt++;

			/*
			 * If this symbol is marked to be expanded, go to the
			 * next move entry.
			 */
			if (sdp->sd_flags & FLG_SY_PAREXPN) {
				mvp++;
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
			if (OFL_IS_STATIC_EXEC(ofl)) {
				if (ELF_ST_TYPE(sym->st_info) == STT_SECTION) {
					errcnt++;
					ld_eprintf(ofl, ERR_FATAL,
					    MSG_INTL(MSG_PSYM_CANNOTEXPND),
					    sdp->sd_file->ifl_name,
					    EC_WORD(isp->is_scnndx),
					    isp->is_name, i,
					    MSG_INTL(MSG_PSYM_NOSTATIC));
				} else {
					sdp->sd_flags |= FLG_SY_PAREXPN;
				}
			} else if ((ofl->ofl_flags1 & FLG_OF1_NOPARTI) != 0) {
				if (ELF_ST_TYPE(sym->st_info) == STT_SECTION) {
					ld_eprintf(ofl, ERR_WARNING,
					    MSG_INTL(MSG_PSYM_CANNOTEXPND),
					    sdp->sd_file->ifl_name,
					    EC_WORD(isp->is_scnndx),
					    isp->is_name, i,
					    MSG_ORIG(MSG_STR_EMPTY));
				} else {
					sdp->sd_flags |= FLG_SY_PAREXPN;
				}
			} else if (((Xword)((sizeof (Move)) *
			    alist_nitems(sdp->sd_move)) > sym->st_size) &&
			    (ELF_ST_TYPE(sym->st_info) == STT_OBJECT)) {
				sdp->sd_flags |= FLG_SY_PAREXPN;
			}

			/*
			 * If a move entry exists that references a local
			 * symbol, and this symbol reference will eventually
			 * be assigned to the associated section, make sure the
			 * section symbol is available for relocating against
			 * at runtime.
			 */
			if ((ELF_ST_BIND(sym->st_info) == STB_LOCAL) &&
			    (((ofl->ofl_flags & FLG_OF_RELOBJ) == 0) ||
			    (ofl->ofl_flags & FLG_OF_REDLSYM))) {
				Os_desc *osp = sdp->sd_isc->is_osdesc;

				if (osp &&
				    ((osp->os_flags & FLG_OS_OUTREL) == 0)) {
					ofl->ofl_dynshdrcnt++;
					osp->os_flags |= FLG_OS_OUTREL;
				} else if ((sdp->sd_flags &
				    FLG_SY_PAREXPN) == 0)
					ofl->ofl_flags1 |= FLG_OF1_BSSOREL;
			}
			mvp++;
		}
	}

	if (errcnt != 0)
		return (S_ERROR);
	if (make_mvsections(ofl) == S_ERROR)
		return (S_ERROR);

	return (1);
}
