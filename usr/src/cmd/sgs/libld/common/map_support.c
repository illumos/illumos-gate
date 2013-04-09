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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */

/*
 * Map file parsing (Shared Support Code).
 */
#include	<stdio.h>
#include	<errno.h>
#include	"msg.h"
#include	"_libld.h"
#include	"_map.h"

/*
 * Given a NULL terminated array of structures of arbitrary type, where
 * each struct contains (among other fields) a character pointer field
 * giving that struct a unique name, return the address of the struct
 * that matches the given name.
 *
 * entry:
 *	name - "Keyword" name to be found.
 *	array - Base address of array
 *	name_offset - Offset of the name field within the struct
 *		type used by this array, as generated via
 *		SGSOFFSETOF().
 *	elt_size - sizeof the basic array element type
 *
 * exit:
 *	Using a case insensitive comparison, name is compared to the
 *	name of each element of the array. The address of the first
 *	match found is returned. If the desired name is not found,
 *	NULL is returned.
 *
 * note:
 *	This routine is completely type-unsafe. The upside is that this
 *	single routine is able to search arrays of arbitrary type, leaving
 *	the caller free to structure their array in any way that is convenient
 *	to solve the problem at hand.
 */
#ifndef _ELF64
void *
ld_map_kwfind(const char *name, void *array, size_t name_offset,
    size_t elt_size)
{
	for (; ; array = elt_size + (char *)array) {
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		const char *arr_name = *((const char **)
		    (name_offset + (const char *) array));

		if (arr_name == NULL)
			return (NULL);

		if (strcasecmp(name, arr_name) == 0)
			return (array);
	}

	/*NOTREACHED*/
	assert(0);
	return (NULL);
}
#endif

/*
 * Given the same NULL terminated array accepted by ld_map_kwfind(), format
 * the strings into a comma separated list of names.
 *
 * entry:
 *	array - Base address of array
 *	name_offset - Offset of the name field within the struct
 *		type used by this array, as generated via
 *		SGSOFFSETOF().
 *	elt_size - sizeof the basic array element type
 *	buf - Buffer to receive output
 *	bufsize - sizeof(buf)
 *
 * exit:
 *	As many of the names as will fit are formatted into buf. If all the
 *	names do not fit, the remainder are quietly clipped. The caller must
 *	ensure that there is sufficient room. buf is returned, for convenience
 *	in using this function as an argument for printing.
 */
#ifndef _ELF64
char *
ld_map_kwnames(void *array, size_t name_offset, size_t elt_size, char *buf,
    size_t bufsize)
{
	size_t	cnt = 0;
	size_t	len;
	char	*str = buf;

	for (; bufsize > 1; array = elt_size + (char *)array, cnt++) {
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		const char *arr_name = *((const char **)
		    (name_offset + (const char *) array));

		if (arr_name == NULL)
			break;

		if (cnt > 0) {
			if (bufsize < 3)
				break;
			*str++ = ',';
			*str++ = ' ';
			bufsize -= 2;
			*(str + 1) = '\0';
		}

		len = strlcpy(str, arr_name, bufsize);
		if (len >= bufsize)
			break;
		str += len;
		bufsize -= len;
	}

	return (buf);
}
#endif

/*
 * Create a pseudo input file descriptor to represent the specified Mapfile.
 * An input descriptor is required any time a symbol is generated.
 *
 * entry:
 *	mf - Mapfile descriptor.
 *
 * exit:
 *	If an input descriptor was already created for this mapfile
 *	by a previous call, it is returned. Otherwise, a new descriptor
 *	is created, entered into the mapfile descriptor, and returned.
 *
 *	Success is indicated by a non-NULL return value, failure by NULL.
 */
Ifl_desc *
ld_map_ifl(Mapfile *mf)
{
	Ifl_desc	*ifl;

	/*
	 * If we've already created a pseudo input descriptor for this
	 * mapfile, reuse it.
	 */
	if (mf->mf_ifl != NULL)
		return (mf->mf_ifl);

	if ((ifl = libld_calloc(sizeof (Ifl_desc), 1)) == NULL)
		return (NULL);
	ifl->ifl_name = mf->mf_name;
	ifl->ifl_flags = (FLG_IF_MAPFILE | FLG_IF_NEEDED | FLG_IF_FILEREF);
	if ((ifl->ifl_ehdr = libld_calloc(sizeof (Ehdr), 1)) == NULL)
		return (NULL);
	ifl->ifl_ehdr->e_type = ET_REL;

	if (aplist_append(&mf->mf_ofl->ofl_objs, ifl, AL_CNT_OFL_OBJS) == NULL)
		return (NULL);

	mf->mf_ifl = ifl;
	return (mf->mf_ifl);
}

/*
 * Given a capability tag type, set the override bit in the output descriptor.
 * This prevents the use of capability values of that type from the input
 * objects.
 */
void
ld_map_cap_set_ovflag(Mapfile *mf, Word type)
{
	/*
	 * Map capability tag to the corresponding output descriptor
	 * override flag.
	 */
	static ofl_flag_t override_flag[CA_SUNW_NUM] = {
		0, 			/* CA_SUNW_NULL */
		FLG_OF1_OVHWCAP1,	/* CA_SUNW_HW_1 */
		FLG_OF1_OVSFCAP1,	/* CA_SUNW_SF_1 */
		FLG_OF1_OVHWCAP2,	/* CA_SUNW_HW_2 */
		FLG_OF1_OVPLATCAP,	/* CA_SUNW_PLAT */
		FLG_OF1_OVMACHCAP,	/* CA_SUNW_MACH */
		FLG_OF1_OVIDCAP		/* CA_SUNW_ID */
	};
#if CA_SUNW_NUM != (CA_SUNW_ID + 1)
#error "CA_SUNW_NUM has grown"
#endif
	mf->mf_ofl->ofl_flags1 |= override_flag[type];
}

/*
 * Sanity check the given capability bitmask.
 */
Boolean
ld_map_cap_sanitize(Mapfile *mf, Word type, Capmask *capmask)
{
	elfcap_mask_t	mask;

	switch (type) {
	case CA_SUNW_SF_1:
		/*
		 * Unlike hardware capabilities, we do not allow setting
		 * software capability bits that do not have known definitions.
		 * Software capability tokens have to be validated as a unit
		 * as the bits can affect each others meaning (see sf1_cap()
		 * in files.c).
		 */
		if ((mask = (capmask->cm_val & ~SF1_SUNW_MASK)) != 0) {
			mf_warn(mf, MSG_INTL(MSG_MAP_BADSF1),
			    EC_XWORD(mask));
			capmask->cm_val &= SF1_SUNW_MASK;
		}
		if ((capmask->cm_val &
		    (SF1_SUNW_FPKNWN | SF1_SUNW_FPUSED)) == SF1_SUNW_FPUSED) {
			mf_warn(mf, MSG_INTL(MSG_MAP_BADSF1),
			    EC_XWORD(SF1_SUNW_FPUSED));
			capmask->cm_val &= ~SF1_SUNW_FPUSED;
		}
#if	!defined(_ELF64)
		/*
		 * The SF1_SUNW_ADDR32 software capability is only meaningful
		 * when building a 64-bit object.  Warn the user, and remove the
		 * setting, if we're building a 32-bit object.
		 */
		if (capmask->cm_val & SF1_SUNW_ADDR32) {
			mf_warn0(mf, MSG_INTL(MSG_MAP_INADDR32SF1));
			capmask->cm_val &= ~SF1_SUNW_ADDR32;
		}
#endif
	}

	return (TRUE);
}

/*
 * Return the shared object control definition structure (ofl_socntl)
 * for the specified object, creating one if necessary.
 *
 * entry:
 *	mf - Mapfile descriptor
 *	obj_name - Name of object
 *
 * exit:
 *	Returns the pointer to the definition structure, or NULL on error.
 */
Sdf_desc *
ld_map_dv(Mapfile *mf, const char *obj_name)
{
	Sdf_desc	*sdf;

	/*
	 * If a shared object definition for this file already exists use it,
	 * otherwise allocate a new descriptor.
	 */
	if ((sdf = sdf_find(obj_name, mf->mf_ofl->ofl_socntl)) == NULL) {
		if ((sdf = sdf_add(obj_name, &mf->mf_ofl->ofl_socntl)) ==
		    (Sdf_desc *)S_ERROR)
			return (NULL);
		sdf->sdf_rfile = mf->mf_name;
	}

	DBG_CALL(Dbg_map_dv(mf->mf_ofl->ofl_lml, sdf->sdf_name,
	    mf->mf_lineno));
	return (sdf);
}


Boolean
ld_map_dv_entry(Mapfile *mf, Sdf_desc *sdf, Boolean require,
    const char *version)
{
	Sdv_desc	sdv;

	sdv.sdv_name = version;
	sdv.sdv_ref = mf->mf_name;
	sdv.sdv_flags = 0;


	if (require) {
		/*
		 * Add a VERNEED entry for the specified version
		 * from this object:
		 *
		 *	MapfileVersion	Syntax
		 *	----------------------------------------
		 *	1		obj - $ADDVERS=version;
		 *	2		DEPENDENCY obj { REQUIRE=version };
		 */
		sdf->sdf_flags |= FLG_SDF_ADDVER;

		if (alist_append(&sdf->sdf_verneed, &sdv, sizeof (Sdv_desc),
		    AL_CNT_SDF_VERSIONS) == NULL)
			return (FALSE);
	} else {		/* Allow */
		/*
		 * Allow linking to symbols found in this version, or
		 * from the versions it inherits from.
		 *
		 *	MapfileVersion	Syntax
		 *	----------------------------------------
		 *	1		obj - version;
		 *	2		DEPENDENCY obj { ALLOW=version };
		 */
		sdf->sdf_flags |= FLG_SDF_SELECT;

		if (alist_append(&sdf->sdf_vers, &sdv, sizeof (Sdv_desc),
		    AL_CNT_SDF_VERSIONS) == NULL)
			return (FALSE);
	}

	DBG_CALL(Dbg_map_dv_entry(mf->mf_ofl->ofl_lml, mf->mf_lineno,
	    require, version));

	return (TRUE);
}

/*
 * Given a segment descriptor, return its index.
 *
 * entry:
 *	mf - Mapfile descriptor
 *	sgp - Segment for which index is desired
 *
 * exit:
 *	Index of segment is returned.
 */
Xword
ld_map_seg_index(Mapfile *mf, Sg_desc *sgp)
{
	Aliste		idx;
	Sg_desc		*sgp2;
	Ofl_desc	*ofl = mf->mf_ofl;

	for (APLIST_TRAVERSE(ofl->ofl_segs, idx, sgp2))
		if (sgp == sgp2)
			break;

	return (idx);
}

/*
 * Add a section name to the output section sort list for the given
 * segment.
 *
 * entry:
 *	mf - Mapfile descriptor
 *	sgp - Segment in question
 *	sec_name - Name of section to be added.
 *
 * exit:
 *	Returns TRUE for success, FALSE for failure.
 */
Boolean
ld_map_seg_os_order_add(Mapfile *mf, Sg_desc *sgp, const char *sec_name)
{
	Aliste		idx;
	Sec_order	*scop;

	/*
	 * Make sure it's not already on the list
	 */
	for (ALIST_TRAVERSE(sgp->sg_os_order, idx, scop))
		if (strcmp(scop->sco_secname, sec_name) == 0) {
			mf_fatal(mf, MSG_INTL(MSG_MAP_DUP_OS_ORD), sec_name);
			return (FALSE);
		}


	scop = alist_append(&sgp->sg_os_order, NULL, sizeof (Sec_order),
	    AL_CNT_SG_SECORDER);
	if (scop == NULL)
		return (FALSE);

	scop->sco_secname = sec_name;

	DBG_CALL(Dbg_map_seg_os_order(mf->mf_ofl->ofl_lml, sgp, sec_name,
	    alist_nitems(sgp->sg_os_order), mf->mf_lineno));

	/*
	 * Output section ordering is a relatively expensive operation,
	 * and one that is generally not used. In order to avoid needless
	 * work, the FLG_OF_OS_ORDER must be set when it will be needed.
	 * The section we just added needs this flag to be set. However,
	 * it is possible that a subsequent mapfile directive may come
	 * along and clear the order list, making it unnecessary.
	 *
	 * Instead of setting it here, we do a final pass over the segments
	 * in ld_map_finalize() and set it there if a segment with sorting
	 * requirements is seen.
	 */

	return (TRUE);
}

/*
 * Add a size symbol to a segment
 *
 * entry:
 *	mf - Mapfile descriptor
 *	sgp - Segment descriptor
 *	eq_tol - Type of assignment: TK_EQUAL, or TK_PLUSEQ
 *	symname - Name of symbol. Must be in stable static storage
 *		that can be retained.
 *
 * exit:
 *	On success, the symbol has been added and TRUE is returned.
 *	Otherwise an error is reported and FALSE is returned.
 */
Boolean
ld_map_seg_size_symbol(Mapfile *mf, Sg_desc *sgp, Token eq_tok,
    const char *symname)
{
	Sym		*sym;		/* New symbol pointer */
	Sym_desc	*sdp;		/* New symbol node pointer */
	Ifl_desc	*ifl;		/* Dummy input file structure */
	avl_index_t	where;
	Ofl_desc	*ofl = mf->mf_ofl;

	/*
	 * We don't allow resetting the list of size symbols, so if the
	 * operator is TK_EQUAL and the list is not empty, issue an error.
	 *
	 * If we want to lift this restriction, we would have to save the
	 * size symbols and enter them from ld_map_post_process(). Doing that
	 * well would require a significant overhead in saved error reporting
	 * state, and interactions with the same symbols created by symbol
	 * directives. As size symbols are of little practical use, and are
	 * maintained primarily for backward compatibility with SysV, we have
	 * decided not to do that, but to create the symbols as the mapfiles
	 * are processed, and to disallow later attempts to remove them.
	 */
	if ((eq_tok == TK_EQUAL) && (aplist_nitems(sgp->sg_sizesym) > 0)) {
		mf_fatal(mf, MSG_INTL(MSG_MAP_SEGSIZE), sgp->sg_name);
		return (FALSE);
	}

	/*
	 * Make sure we have a pseudo file descriptor to associate to the
	 * symbol.
	 */
	if ((ifl = ld_map_ifl(mf)) == NULL)
		return (FALSE);

	/*
	 * Make sure the symbol doesn't already exist.  It is possible that the
	 * symbol has been scoped or versioned, in which case it does exist
	 * but we can freely update it here.
	 */
	if ((sdp = ld_sym_find(symname, SYM_NOHASH, &where, ofl)) == NULL) {
		Word hval;

		if ((sym = libld_calloc(sizeof (Sym), 1)) == NULL)
			return (FALSE);
		sym->st_shndx = SHN_ABS;
		sym->st_size = 0;
		sym->st_info = ELF_ST_INFO(STB_GLOBAL, STT_OBJECT);

		DBG_CALL(Dbg_map_size_new(ofl->ofl_lml, symname,
		    sgp->sg_name, mf->mf_lineno));
		/* LINTED */
		hval = (Word)elf_hash(symname);
		if ((sdp = ld_sym_enter(symname, sym, hval, ifl, ofl, 0,
		    SHN_ABS, (FLG_SY_SPECSEC | FLG_SY_GLOBREF), &where)) ==
		    (Sym_desc *)S_ERROR)
			return (FALSE);
		sdp->sd_flags &= ~FLG_SY_CLEAN;
		DBG_CALL(Dbg_map_symbol(ofl, sdp));
	} else {
		sym = sdp->sd_sym;

		if (sym->st_shndx == SHN_UNDEF) {
			sdp->sd_shndx = sym->st_shndx = SHN_ABS;
			sdp->sd_flags |= FLG_SY_SPECSEC;
			sym->st_size = 0;
			sym->st_info = ELF_ST_INFO(STB_GLOBAL, STT_OBJECT);

			sdp->sd_flags &= ~FLG_SY_MAPREF;

			DBG_CALL(Dbg_map_size_old(ofl, sdp,
			    sgp->sg_name, mf->mf_lineno));
		} else {
			mf_fatal(mf, MSG_INTL(MSG_MAP_SYMDEF1),
			    demangle(sdp->sd_name), sdp->sd_file->ifl_name,
			    MSG_INTL(MSG_MAP_DIFF_SYMMUL));
			return (FALSE);
		}
	}

	/*
	 * Assign the symbol to the segment.
	 */
	if (aplist_append(&sgp->sg_sizesym, sdp, AL_CNT_SG_SIZESYM) == NULL)
		return (FALSE);

	return (TRUE);
}

/*
 * Allocate a zeroed segment descriptor.
 *
 * exit:
 *	Returns pointer to the descriptor on success, NULL on failure.
 *	The contents of the returned descriptor have been zeroed.
 *	The returned descriptor is not added to the segment list
 *	(ofl_segs). That is done using ld_map_seg_insert().
 */
Sg_desc *
ld_map_seg_alloc(const char *name, Word p_type, sg_flags_t sg_flags)
{
	Sg_desc	*sgp;

	if ((sgp = libld_calloc(sizeof (Sg_desc), 1)) == NULL)
		return (NULL);
	sgp->sg_phdr.p_type = p_type;
	sgp->sg_name = name;
	sgp->sg_flags = sg_flags;

	return (sgp);
}

/*
 * Return the PT_SUNWSTACK segment descriptor from the ofl_segs list.
 * This segment is part of the default set and cannot be removed, so
 * this routine will always succeed.
 *
 * exit:
 *	The descriptor is located, a DBG_STATE_MOD_BEFORE debug
 *	message issued, the FLG_SG_DISABLED flag is cleared, and the
 *	descriptor pointer returned.
 */
Sg_desc *
ld_map_seg_stack(Mapfile *mf)
{
	Ofl_desc	*ofl = mf->mf_ofl;
	Sg_desc		*sgp;
	Aliste		idx;

	/*
	 * The stack is established by exec(), using the executable's program
	 * headers, before any sharable objects are loaded. If there is a
	 * PT_SUNWSTACK program header, exec() will act on it. As such, stack
	 * program headers are normally only applicable to executables.
	 *
	 * However, ELF allows a sharable object with an interpreter to
	 * be executed directly, and in this extremely rare case, the
	 * PT_SUNWSTACK program header would have meaning. Rather than
	 * second guess user intent, we simply create it on demand for any
	 * dynamic object, trusting that the user has a good reason for it.
	 */
	for (APLIST_TRAVERSE(ofl->ofl_segs, idx, sgp))
		if (sgp->sg_phdr.p_type == PT_SUNWSTACK) {
			DBG_CALL(Dbg_map_seg(mf->mf_ofl, DBG_STATE_MOD_BEFORE,
			    idx, sgp, mf->mf_lineno));
			sgp->sg_flags &= ~FLG_SG_DISABLED;
			return (sgp);
		}

	/*NOTREACHED*/
	return (NULL);
}

/*
 * Finish the initialization of a new segment descriptor allocated by
 * ld_map_seg_alloc(), and enter it into the segment list.
 *
 * entry:
 *	mf - Mapfile descriptor
 *	seg_type - One of DBG_SEG_NEW or DBG_SEG_NEW_IMPLICIT
 *	ins_head - If TRUE, the new segment goes at the front of
 *		others of its type. If FALSE, it goes at the end.
 *	sgp - Segment descriptor to enter.
 *	where - Insertion point, initialized by a previous (failed) call to
 *		ld_seg_lookup(). Ignored if the segment has a NULL sg_name.
 *
 * exit:
 *	On success, returns SEG_INS_OK. A non-fatal error is indicated with
 *	a return value of SEG_INS_SKIP, in which case the descriptor is
 *	not entered, but the user is expected to discard it and continue
 *	running. On failure, returns SEG_INS_FAIL.
 *
 * note:
 *	This routine will modify the contents of the descriptor referenced
 *	by sgp_tmpl before allocating the new descriptor. The caller must
 *	not expect it to be unmodified.
 */
ld_map_seg_ins_t
ld_map_seg_insert(Mapfile *mf, dbg_state_t dbg_state, Sg_desc *sgp,
    avl_index_t where)
{
	Ofl_desc	*ofl = mf->mf_ofl;
	Aliste		idx;
	Sg_desc		*sgp2;		/* temp segment descriptor pointer */
	int		ins_head;
	Xword		sg_ndx;

	/*
	 * If specific fields have not been supplied via
	 * map_equal(), make sure defaults are supplied.
	 */
	if (((sgp->sg_flags & FLG_SG_P_TYPE) == 0) &&
	    (sgp->sg_phdr.p_type == PT_NULL)) {
		/*
		 * Default to a loadable segment.
		 */
		sgp->sg_phdr.p_type = PT_LOAD;
		sgp->sg_flags |= FLG_SG_P_TYPE;
	}
	if (sgp->sg_phdr.p_type == PT_LOAD) {
		if ((sgp->sg_flags & FLG_SG_P_FLAGS) == 0) {
			/*
			 * Default to read/write and execute.
			 */
			sgp->sg_phdr.p_flags = PF_R + PF_W + PF_X;
			sgp->sg_flags |= FLG_SG_P_FLAGS;
		}
		if ((sgp->sg_flags & FLG_SG_P_ALIGN) == 0) {
			/*
			 * Default to segment alignment
			 */
			sgp->sg_phdr.p_align = ld_targ.t_m.m_segm_align;
			sgp->sg_flags |= FLG_SG_P_ALIGN;
		}
	}

	/*
	 * Determine where the new item should be inserted in
	 * the segment descriptor list.
	 */
	switch (sgp->sg_phdr.p_type) {
	case PT_LOAD:
		if (sgp->sg_flags & FLG_SG_EMPTY)
			sgp->sg_id = SGID_TEXT_EMPTY;
		else
			sgp->sg_id = SGID_TEXT;
		break;
	case PT_NULL:
		if (sgp->sg_flags & FLG_SG_EMPTY)
			sgp->sg_id = SGID_NULL_EMPTY;
		else
			sgp->sg_id = SGID_NULL;
		break;
	case PT_NOTE:
		sgp->sg_id = SGID_NOTE;
		break;
	default:
		mf_fatal(mf, MSG_INTL(MSG_MAP_UNKSEGTYP),
		    EC_WORD(sgp->sg_phdr.p_type));
		return (SEG_INS_FAIL);
	}

	/*
	 * Add the descriptor to the segment list. In the v1 syntax,
	 * new sections are added at the head of their type, while in
	 * the newer syntax, they go at the end of their type.
	 */
	sg_ndx = 0;
	ins_head = (mf->mf_version == MFV_SYSV);
	for (APLIST_TRAVERSE(ofl->ofl_segs, idx, sgp2)) {
		if (ins_head) {	/* Insert before the others of its type */
			if (sgp->sg_id > sgp2->sg_id) {
				sg_ndx++;
				continue;
			}
		} else {	/* Insert after the others of its type */
			if (sgp->sg_id >= sgp2->sg_id) {
				sg_ndx++;
				continue;
			}
		}
		break;
	}
	if (aplist_insert(&ofl->ofl_segs, sgp, AL_CNT_SEGMENTS, idx) == NULL)
		return (SEG_INS_FAIL);
	if (sgp->sg_name != NULL)
		avl_insert(&ofl->ofl_segs_avl, sgp, where);

	DBG_CALL(Dbg_map_seg(ofl, dbg_state, sg_ndx, sgp, mf->mf_lineno));
	return (SEG_INS_OK);
}

/*
 * Add an entrance criteria record for the specified segment
 *
 * entry:
 *	mf - Mapfile descriptor
 *	sgp - Segment for which a new entrance criteria record is needed
 *	name - NULL, or name by which the entrance criteria can be referenced.
 *
 * exit:
 *	On success, a pointer to the new entrace criteria record is
 *	returned, the contents of which have been zeroed. On failure,
 *	NULL is returned.
 */
Ent_desc *
ld_map_seg_ent_add(Mapfile *mf, Sg_desc *sgp, const char *name)
{
	Ent_desc	*enp;
	avl_index_t	where;
	Ofl_desc	*ofl = mf->mf_ofl;

	if ((name != NULL) &&
	    (ld_ent_lookup(mf->mf_ofl, name, &where) != NULL)) {
		mf_fatal(mf, MSG_INTL(MSG_MAP_DUPNAMENT), name);
		return (NULL);
	}

	/* Allocate and initialize the entrace criteria descriptor */
	if ((enp = libld_calloc(1, sizeof (*enp))) == NULL)
		return (NULL);
	enp->ec_name = name;
	enp->ec_segment = sgp;	 /* Tie criteria to segment */


	/*
	 * Insert into the APlist. The mf_ec_insndx field for each mapfile
	 * starts at 0, and is incremented with each insertion. This means
	 * that the entrance criteria for each mapfile go to the head of
	 * the list, but that within a single mapfile, they are inserted in
	 * the order they are seen.
	 */
	if (aplist_insert(&ofl->ofl_ents, enp, AL_CNT_OFL_ENTRANCE,
	    mf->mf_ec_insndx) == NULL)
		return (NULL);
	mf->mf_ec_insndx++;

	/*
	 * If the entrance criteria is named insert it into the AVL tree
	 * as well. This provides O(logN) lookups by name.
	 */
	if (name != NULL)
		avl_insert(&ofl->ofl_ents_avl, enp, where);

	return (enp);
}

Boolean
ld_map_seg_ent_files(Mapfile *mf, Ent_desc *enp, Word ecf_type, const char *str)
{
	Ent_desc_file	edf;

	/*
	 * The v1 sysv syntax can let an empty string get in, consisting of
	 * just a '*' where the '*' is interpreted as 'basename'.
	 */
	if (str[0] == '\0') {
		mf_fatal0(mf, MSG_INTL(MSG_MAP_MALFORM));
		return (FALSE);
	}

	/* Basename or objname string must not contain a path separator (/) */
	if ((ecf_type != TYP_ECF_PATH) && (strchr(str, '/') != NULL)) {
		const char *msg = (ecf_type == TYP_ECF_BASENAME) ?
		    MSG_INTL(MSG_MAP_BADBNAME) : MSG_INTL(MSG_MAP_BADONAME);

		mf_fatal(mf, msg, str);
		return (FALSE);
	}

	edf.edf_flags = ecf_type;
	edf.edf_name = str;
	edf.edf_name_len = strlen(edf.edf_name);

	/* Does it have an archive member suffix? */
	if ((edf.edf_name[edf.edf_name_len - 1] == ')') &&
	    (strrchr(edf.edf_name, '(') != NULL))
		edf.edf_flags |= FLG_ECF_ARMEMBER;

	if (alist_append(&enp->ec_files, &edf, sizeof (edf),
	    AL_CNT_EC_FILES) == NULL)
		return (FALSE);

	/*
	 * Note that an entrance criteria requiring file name matching exists
	 * in the system. This is used by ld_place_path_info_init() to
	 * skip Place_pathinfo initialization in cases where there are
	 * no entrance criteria that will use the results.
	 */
	mf->mf_ofl->ofl_flags |= FLG_OF_EC_FILES;

	return (TRUE);
}

/*
 * Prepare an ld_map_ver_t structure for a new mapfile defined version.
 *
 * exit:
 *	Returns TRUE for success, FALSE for failure.
 */
Boolean
ld_map_sym_ver_init(Mapfile *mf, char *name, ld_map_ver_t *mv)
{
	Word		hash;
	Ofl_desc	*ofl = mf->mf_ofl;

	mv->mv_name = name;
	mv->mv_scope = FLG_SCOPE_DFLT;
	mv->mv_errcnt = 0;

	/*
	 * If we're generating segments within the image then any symbol
	 * reductions will be processed (ie. applied to relocations and symbol
	 * table entries).  Otherwise (when creating a relocatable object) any
	 * versioning information is simply recorded for use in a later
	 * (segment generating) link-edit.
	 */
	if (ofl->ofl_flags & FLG_OF_RELOBJ)
		ofl->ofl_flags |= FLG_OF_VERDEF;

	/*
	 * If no version descriptors have yet been set up, initialize a base
	 * version to represent the output file itself.  This `base' version
	 * catches any internally generated symbols (_end, _etext, etc.) and
	 * serves to initialize the output version descriptor count.
	 */
	if (ofl->ofl_vercnt == 0) {
		if (ld_vers_base(ofl) == (Ver_desc *)S_ERROR)
			return (FALSE);
	}

	/*
	 * If this definition has an associated version name then generate a
	 * new version descriptor and an associated version symbol index table.
	 */
	if (name) {
		ofl->ofl_flags |= FLG_OF_VERDEF;

		/*
		 * Traverse the present version descriptor list to see if there
		 * is already one of the same name, otherwise create a new one.
		 */
		/* LINTED */
		hash = (Word)elf_hash(name);
		if (((mv->mv_vdp = ld_vers_find(name, hash,
		    ofl->ofl_verdesc)) == NULL) &&
		    ((mv->mv_vdp = ld_vers_desc(name, hash,
		    &ofl->ofl_verdesc)) == (Ver_desc *)S_ERROR))
			return (FALSE);

		/*
		 * Initialize any new version with an index, the file from
		 * which it was first referenced, and a WEAK flag (indicates
		 * that there are no symbols assigned to it yet).
		 */
		if (mv->mv_vdp->vd_ndx == 0) {
			/* LINTED */
			mv->mv_vdp->vd_ndx = (Half)++ofl->ofl_vercnt;
			mv->mv_vdp->vd_file = ld_map_ifl(mf);
			mv->mv_vdp->vd_flags = VER_FLG_WEAK;
		}
	} else {
		/*
		 * If a version definition hasn't been specified assign any
		 * symbols to the base version.
		 */
		mv->mv_vdp = (Ver_desc *)ofl->ofl_verdesc->apl_data[0];
	}

	return (TRUE);
}

/*
 * Change the current scope for the given version.
 *
 * entry:
 *	mf - Mapfile descriptor
 *	scope_name - Name for new scope
 *	mv - Information related to version being defined
 *
 * exit:
 *	On success, mv is updated to change the current scope.
 *	On failure, mv->errcnt is incremented, and mv is otherwise unaltered.
 */
void
ld_map_sym_scope(Mapfile *mf, const char *scope_name, ld_map_ver_t *mv)
{
	typedef struct {
		const char	*name;		/* scope keyword string */
		ld_map_scope_t	type;		/* Resulting type */
		ofl_flag_t	ofl_flags;	/* 0, or ofl flags to add */
	} scope_t;

	/*
	 * Valid symbol scope keywords
	 *
	 * All symbols added by a mapfile are actually global entries, and
	 * are assigned the scope that is presently in effect.
	 *
	 * If a protected/symbolic scope is detected, remember this. If
	 * a protected/symbolic scope is the only scope defined in this
	 * (or any other mapfiles), then the mode -Bsymbolic is established.
	 */
	static scope_t scope_list[] = {
		{ MSG_ORIG(MSG_MAPKW_DEFAULT), FLG_SCOPE_DFLT, FLG_OF_MAPGLOB },
		{ MSG_ORIG(MSG_MAPKW_ELIMINATE), FLG_SCOPE_ELIM, 0 },
		{ MSG_ORIG(MSG_MAPKW_EXPORTED), FLG_SCOPE_EXPT, 0 },
		{ MSG_ORIG(MSG_MAPKW_HIDDEN), FLG_SCOPE_HIDD, 0 },
		{ MSG_ORIG(MSG_MAPKW_GLOBAL), FLG_SCOPE_DFLT, FLG_OF_MAPGLOB },
		{ MSG_ORIG(MSG_MAPKW_LOCAL), FLG_SCOPE_HIDD, 0 },
		{ MSG_ORIG(MSG_MAPKW_PROTECTED),
		    FLG_SCOPE_PROT, FLG_OF_MAPSYMB },
		{ MSG_ORIG(MSG_MAPKW_SINGLETON),
		    FLG_SCOPE_SNGL, FLG_OF_MAPGLOB },
		{ MSG_ORIG(MSG_MAPKW_SYMBOLIC),
		    FLG_SCOPE_PROT, FLG_OF_MAPSYMB },

		/* List must be null terminated */
		{ 0 }
	};

	/*
	 * Size of buffer needed to format the names in scope_list[]. Must
	 * be kept in sync with scope_list.
	 */
	static size_t scope_list_bufsize =
	    KW_NAME_SIZE(MSG_MAPKW_DEFAULT) +
	    KW_NAME_SIZE(MSG_MAPKW_ELIMINATE) +
	    KW_NAME_SIZE(MSG_MAPKW_EXPORTED) +
	    KW_NAME_SIZE(MSG_MAPKW_HIDDEN) +
	    KW_NAME_SIZE(MSG_MAPKW_GLOBAL) +
	    KW_NAME_SIZE(MSG_MAPKW_LOCAL) +
	    KW_NAME_SIZE(MSG_MAPKW_PROTECTED) +
	    KW_NAME_SIZE(MSG_MAPKW_SINGLETON) +
	    KW_NAME_SIZE(MSG_MAPKW_SYMBOLIC);

	scope_t	*scope;

	scope = ld_map_kwfind(scope_name, scope_list,
	    SGSOFFSETOF(scope_t, name), sizeof (scope_list[0]));
	if (scope == NULL) {
		char buf[VLA_SIZE(scope_list_bufsize)];

		mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_SYMSCOPE),
		    ld_map_kwnames(scope_list, SGSOFFSETOF(scope_t, name),
		    sizeof (scope[0]), buf, scope_list_bufsize), scope_name);
		mv->mv_errcnt++;
		return;
	}

	mv->mv_scope = scope->type;
	mf->mf_ofl->ofl_flags |= scope->ofl_flags;
}

/*
 * Process the special auto-reduction directive ('*'). It can be specified
 * in hidden/local, and eliminate scope. This directive indicates that all
 * symbols processed that are not explicitly defined to be global are to be
 * reduced to hidden/local scope in, or eliminated from, the output image.
 *
 * An auto-reduction directive also implies that a version definition must
 * be created, as the user has effectively defined an interface.
 */
void
ld_map_sym_autoreduce(Mapfile *mf, ld_map_ver_t *mv)
{
	switch (mv->mv_scope) {
	case FLG_SCOPE_HIDD:
		mf->mf_ofl->ofl_flags |= (FLG_OF_VERDEF | FLG_OF_AUTOLCL);
		break;
	case FLG_SCOPE_ELIM:
		mf->mf_ofl->ofl_flags |= (FLG_OF_VERDEF | FLG_OF_AUTOELM);
		break;
	default:
		/*
		 * Auto reduction has been applied to a scope that doesn't
		 * support it. This should be a fatal error, but we limit
		 * it to a warning for version 1 mapfiles. For years, we
		 * quietly ignored this case, so there may be mapfiles in
		 * production use that we do not wish to break.
		 */
		if (mf->mf_version == 1) {
			mf_warn0(mf, MSG_INTL(MSG_MAP_BADAUTORED));
		} else {
			mf_fatal0(mf, MSG_INTL(MSG_MAP_BADAUTORED));
			mv->mv_errcnt++;
		}
	}
}

/*
 * Add a standard or auxiliary filter to the given symbol
 *
 * entry:
 *	mf - Mapfile descriptor
 *	mv - Information related to version being defined
 *	ms - Information related to symbol being defined
 *	dft_flag - One of FLG_SY_STDFLTR or FLG_SY_AUXFLTR,
 *		specifying the type of filter.
 *	filtee - String giving filtee to be added
 *
 * exit:
 *	On success, the filtee is added. On failure, mv->errcnt is
 *	incremented, and mv/ms are otherwise unaltered.
 */
void
ld_map_sym_filtee(Mapfile *mf, ld_map_ver_t *mv, ld_map_sym_t *ms,
    Word dft_flag, const char *filtee)
{
	/*
	 * A given symbol can only be tied to a single filter, be it
	 * a standard filter, or auxiliary.
	 */
	if (ms->ms_filtee) {
		mf_fatal0(mf, MSG_INTL(MSG_MAP_MULTFILTEE));
		mv->mv_errcnt++;
		return;
	}

	/* Symbol filtering is only for sharable objects */
	if (!(mf->mf_ofl->ofl_flags & FLG_OF_SHAROBJ)) {
		mf_fatal0(mf, MSG_INTL(MSG_MAP_FLTR_ONLYAVL));
		mv->mv_errcnt++;
		return;
	}

	ms->ms_filtee = filtee;
	ms->ms_dft_flag = dft_flag;
	ms->ms_sdflags |= dft_flag;
	mf->mf_ofl->ofl_flags |= FLG_OF_SYMINFO;
}

/*
 * Enter a mapfile defined symbol into the given version
 *
 * entry:
 *	mf - Mapfile descriptor
 *	ms - Information related to symbol being added to version
 *
 * exit:
 *	On success, returns TRUE. On failure that requires an immediate
 *	halt, returns FALSE.
 *
 *	On failure that requires eventual halt, but for which it would
 *	be OK to continue parsing in hopes of flushing out additional
 *	problems, increments mv->mv_errcnt, and returns TRUE.
 */
Boolean
ld_map_sym_enter(Mapfile *mf, ld_map_ver_t *mv, ld_map_sym_t *ms)
{
	Ofl_desc	*ofl = mf->mf_ofl;
	Word		hash;
	avl_index_t	where;
	Sym		*sym;
	Sym_desc	*sdp;
	const char	*conflict;

	/*
	 * Add the new symbol.  It should be noted that all
	 * symbols added by the mapfile start out with global
	 * scope, thus they will fall through the normal symbol
	 * resolution process.  Symbols defined as locals will
	 * be reduced in scope after all input file processing.
	 */
	/* LINTED */
	hash = (Word)elf_hash(ms->ms_name);
	DBG_CALL(Dbg_map_version(ofl->ofl_lml, mv->mv_name, ms->ms_name,
	    mv->mv_scope));

	/*
	 * Make sure that any parent or external declarations fall back to
	 * references.
	 */
	if (ms->ms_sdflags & (FLG_SY_PARENT | FLG_SY_EXTERN)) {
		/*
		 * Turn it into a reference by setting the section index
		 * to UNDEF.
		 */
		ms->ms_shndx = SHN_UNDEF;

		/*
		 * It is wrong to specify size or value for an external symbol.
		 */
		if (ms->ms_value_set || (ms->ms_size != 0)) {
			mf_fatal0(mf, MSG_INTL(MSG_MAP_NOEXVLSZ));
			mv->mv_errcnt++;
			return (TRUE);
		}
	}

	if ((sdp = ld_sym_find(ms->ms_name, hash, &where, ofl)) == NULL) {
		if ((sym = libld_calloc(sizeof (Sym), 1)) == NULL)
			return (FALSE);

		sym->st_shndx = (Half)ms->ms_shndx;
		sym->st_value = ms->ms_value;
		sym->st_size = ms->ms_size;
		sym->st_info = ELF_ST_INFO(STB_GLOBAL, ms->ms_type);

		if ((sdp = ld_sym_enter(ms->ms_name, sym, hash,
		    ld_map_ifl(mf), ofl, 0, ms->ms_shndx, ms->ms_sdflags,
		    &where)) == (Sym_desc *)S_ERROR)
			return (FALSE);

		sdp->sd_flags &= ~FLG_SY_CLEAN;

		/*
		 * Identify any references.  FLG_SY_MAPREF is
		 * turned off once a relocatable object with
		 * the same symbol is found, thus the existence
		 * of FLG_SY_MAPREF at symbol validation is
		 * used to flag undefined/misspelled entries.
		 */
		if (sym->st_shndx == SHN_UNDEF)
			sdp->sd_flags |= (FLG_SY_MAPREF | FLG_SY_GLOBREF);

	} else {
		conflict = NULL;
		sym = sdp->sd_sym;

		/*
		 * If this symbol already exists, make sure this
		 * definition doesn't conflict with the former.
		 * Provided it doesn't, multiple definitions
		 * from different mapfiles can augment each
		 * other.
		 */
		if (sym->st_value) {
			if (ms->ms_value && (sym->st_value != ms->ms_value))
				conflict = MSG_INTL(MSG_MAP_DIFF_SYMVAL);
		} else {
			sym->st_value = ms->ms_value;
		}
		if (sym->st_size) {
			if (ms->ms_size && (sym->st_size != ms->ms_size))
				conflict = MSG_INTL(MSG_MAP_DIFF_SYMSZ);
		} else {
			sym->st_size = ms->ms_size;
		}
		if (ELF_ST_TYPE(sym->st_info) != STT_NOTYPE) {
			if ((ms->ms_type != STT_NOTYPE) &&
			    (ELF_ST_TYPE(sym->st_info) != ms->ms_type))
				conflict = MSG_INTL(MSG_MAP_DIFF_SYMTYP);
		} else {
			sym->st_info = ELF_ST_INFO(STB_GLOBAL, ms->ms_type);
		}
		if (sym->st_shndx != SHN_UNDEF) {
			if ((ms->ms_shndx != SHN_UNDEF) &&
			    (sym->st_shndx != ms->ms_shndx))
				conflict = MSG_INTL(MSG_MAP_DIFF_SYMNDX);
		} else {
			sym->st_shndx = sdp->sd_shndx = ms->ms_shndx;
		}

		if ((sdp->sd_flags & MSK_SY_GLOBAL) &&
		    (sdp->sd_aux->sa_overndx != VER_NDX_GLOBAL) &&
		    (mv->mv_vdp->vd_ndx != VER_NDX_GLOBAL) &&
		    (sdp->sd_aux->sa_overndx != mv->mv_vdp->vd_ndx)) {
			conflict = MSG_INTL(MSG_MAP_DIFF_SYMVER);
		}

		if (conflict) {
			mf_fatal(mf, MSG_INTL(MSG_MAP_SYMDEF1),
			    demangle(ms->ms_name),
			    sdp->sd_file->ifl_name, conflict);
			mv->mv_errcnt++;
			return (TRUE);
		}

		/*
		 * If this mapfile entry supplies a definition,
		 * indicate that the symbol is now used.
		 */
		if (ms->ms_shndx != SHN_UNDEF)
			sdp->sd_flags |= FLG_SY_MAPUSED;
	}

	/*
	 * A symbol declaration that defines a size but no
	 * value is processed as a request to create an
	 * associated backing section.  The intent behind this
	 * functionality is to provide OBJT definitions within
	 * filters that are not ABS.  ABS symbols don't allow
	 * copy-relocations to be established to filter OBJT
	 * definitions.
	 */
	if ((ms->ms_shndx == SHN_ABS) && ms->ms_size && !ms->ms_value_set) {
		/* Create backing section if not there */
		if (sdp->sd_isc == NULL) {
			Is_desc	*isp;

			if (ms->ms_type == STT_OBJECT) {
				if ((isp = ld_make_data(ofl, ms->ms_size)) ==
				    (Is_desc *)S_ERROR)
					return (FALSE);
			} else {
				if ((isp = ld_make_text(ofl, ms->ms_size)) ==
				    (Is_desc *)S_ERROR)
					return (FALSE);
			}

			sdp->sd_isc = isp;
			isp->is_file = ld_map_ifl(mf);
		}

		/*
		 * Now that backing storage has been created,
		 * associate the symbol descriptor.  Remove the
		 * symbols special section tag so that it will
		 * be assigned the correct section index as part
		 * of update symbol processing.
		 */
		sdp->sd_flags &= ~FLG_SY_SPECSEC;
		ms->ms_sdflags &= ~FLG_SY_SPECSEC;
	}

	/*
	 * Indicate the new symbols scope.  Although the
	 * symbols st_other field will eventually be updated as
	 * part of writing out the final symbol, update the
	 * st_other field here to trigger better diagnostics
	 * during symbol validation (for example, undefined
	 * references that are defined symbolic in a mapfile).
	 */
	if (mv->mv_scope == FLG_SCOPE_HIDD) {
		/*
		 * This symbol needs to be reduced to local.
		 */
		if (ofl->ofl_flags & FLG_OF_REDLSYM) {
			sdp->sd_flags |= (FLG_SY_HIDDEN | FLG_SY_ELIM);
			sdp->sd_sym->st_other = STV_ELIMINATE;
		} else {
			sdp->sd_flags |= FLG_SY_HIDDEN;
			sdp->sd_sym->st_other = STV_HIDDEN;
		}
	} else if (mv->mv_scope == FLG_SCOPE_ELIM) {
		/*
		 * This symbol needs to be eliminated.  Note,
		 * the symbol is also tagged as local to trigger
		 * any necessary relocation processing prior
		 * to the symbol being eliminated.
		 */
		sdp->sd_flags |= (FLG_SY_HIDDEN | FLG_SY_ELIM);
		sdp->sd_sym->st_other = STV_ELIMINATE;

	} else {
		/*
		 * This symbol is explicitly defined to remain
		 * global.
		 */
		sdp->sd_flags |= ms->ms_sdflags;

		/*
		 * Qualify any global scope.
		 */
		if (mv->mv_scope == FLG_SCOPE_SNGL) {
			sdp->sd_flags |= (FLG_SY_SINGLE | FLG_SY_NDIR);
			sdp->sd_sym->st_other = STV_SINGLETON;
		} else if (mv->mv_scope == FLG_SCOPE_PROT) {
			sdp->sd_flags |= FLG_SY_PROTECT;
			sdp->sd_sym->st_other = STV_PROTECTED;
		} else if (mv->mv_scope == FLG_SCOPE_EXPT) {
			sdp->sd_flags |= FLG_SY_EXPORT;
			sdp->sd_sym->st_other = STV_EXPORTED;
		} else
			sdp->sd_flags |= FLG_SY_DEFAULT;

		/*
		 * Record the present version index for later
		 * potential versioning.
		 */
		if ((sdp->sd_aux->sa_overndx == 0) ||
		    (sdp->sd_aux->sa_overndx == VER_NDX_GLOBAL))
			sdp->sd_aux->sa_overndx = mv->mv_vdp->vd_ndx;
		mv->mv_vdp->vd_flags |= FLG_VER_REFER;
	}

	conflict = NULL;

	/*
	 * Carry out some validity checks to ensure incompatible
	 * symbol characteristics have not been defined.
	 * These checks are carried out after symbols are added
	 * or resolved, to catch single instance, and
	 * multi-instance definition inconsistencies.
	 */
	if ((sdp->sd_flags & (FLG_SY_HIDDEN | FLG_SY_ELIM)) &&
	    ((mv->mv_scope != FLG_SCOPE_HIDD) &&
	    (mv->mv_scope != FLG_SCOPE_ELIM))) {
		conflict = MSG_INTL(MSG_MAP_DIFF_SYMLCL);

	} else if ((sdp->sd_flags &
	    (FLG_SY_SINGLE | FLG_SY_EXPORT)) &&
	    ((mv->mv_scope != FLG_SCOPE_DFLT) &&
	    (mv->mv_scope != FLG_SCOPE_EXPT) &&
	    (mv->mv_scope != FLG_SCOPE_SNGL))) {
		conflict = MSG_INTL(MSG_MAP_DIFF_SYMGLOB);

	} else if ((sdp->sd_flags & FLG_SY_PROTECT) &&
	    ((mv->mv_scope != FLG_SCOPE_DFLT) &&
	    (mv->mv_scope != FLG_SCOPE_PROT))) {
		conflict = MSG_INTL(MSG_MAP_DIFF_SYMPROT);

	} else if ((sdp->sd_flags & FLG_SY_NDIR) &&
	    (mv->mv_scope == FLG_SCOPE_PROT)) {
		conflict = MSG_INTL(MSG_MAP_DIFF_PROTNDIR);

	} else if ((sdp->sd_flags & FLG_SY_DIR) &&
	    (mv->mv_scope == FLG_SCOPE_SNGL)) {
		conflict = MSG_INTL(MSG_MAP_DIFF_SNGLDIR);
	}

	if (conflict) {
		/*
		 * Select the conflict message from either a
		 * single instance or multi-instance definition.
		 */
		if (sdp->sd_file->ifl_name == mf->mf_name) {
			mf_fatal(mf, MSG_INTL(MSG_MAP_SYMDEF2),
			    demangle(ms->ms_name), conflict);
		} else {
			mf_fatal(mf, MSG_INTL(MSG_MAP_SYMDEF1),
			    demangle(ms->ms_name),
			    sdp->sd_file->ifl_name, conflict);
		}
		mv->mv_errcnt++;
		return (TRUE);
	}

	/*
	 * Indicate that this symbol has been explicitly
	 * contributed from a mapfile.
	 */
	sdp->sd_flags |= (FLG_SY_MAPFILE | FLG_SY_EXPDEF);

	/*
	 * If we've encountered a symbol definition simulate
	 * that an input file has been processed - this allows
	 * things like filters to be created purely from a
	 * mapfile.
	 */
	if (ms->ms_type != STT_NOTYPE)
		ofl->ofl_objscnt++;
	DBG_CALL(Dbg_map_symbol(ofl, sdp));

	/*
	 * If this symbol has an associated filtee, record the
	 * filtee string and associate the string index with the
	 * symbol.  This is used later to associate the syminfo
	 * information with the necessary .dynamic entry.
	 */
	if (ms->ms_filtee) {
		Dfltr_desc *	dftp;
		Sfltr_desc	sft;
		Aliste		idx, _idx, nitems;

		/*
		 * Make sure we don't duplicate any filtee
		 * strings, and create a new descriptor if
		 * necessary.
		 */
		idx = nitems = alist_nitems(ofl->ofl_dtsfltrs);
		for (ALIST_TRAVERSE(ofl->ofl_dtsfltrs, _idx, dftp)) {
			if ((ms->ms_dft_flag != dftp->dft_flag) ||
			    (strcmp(dftp->dft_str, ms->ms_filtee)))
				continue;
			idx = _idx;
			break;
		}
		if (idx == nitems) {
			Dfltr_desc	dft;

			dft.dft_str = ms->ms_filtee;
			dft.dft_flag = ms->ms_dft_flag;
			dft.dft_ndx = 0;

			/*
			 * The following append puts the new
			 * item at the offset contained in
			 * idx, because we know idx contains
			 * the index of the next available slot.
			 */
			if (alist_append(&ofl->ofl_dtsfltrs, &dft,
			    sizeof (Dfltr_desc), AL_CNT_OFL_DTSFLTRS) == NULL)
				return (FALSE);
		}

		/*
		 * Create a new filter descriptor for this
		 * symbol.
		 */
		sft.sft_sdp = sdp;
		sft.sft_idx = idx;

		if (alist_append(&ofl->ofl_symfltrs, &sft, sizeof (Sfltr_desc),
		    AL_CNT_OFL_SYMFLTRS) == NULL)
			return (FALSE);
	}

	return (TRUE);
}

/*
 * In both the version 1 and version 2 syntaxes, a version definition
 * can have 0 or more inherited versions following the closing '}',
 * terminated by a ';'.
 *
 * Add the inherited names, and return when the terminator is seen.
 */
Boolean
ld_map_sym_ver_fini(Mapfile *mf, ld_map_ver_t *mv)
{
	Token		tok;
	ld_map_tkval_t	tkv;		/* Value of token */
	Boolean		done = FALSE;
	Conv_inv_buf_t	inv_buf;
	const char	*name;
	Ver_desc	*vdp;
	Word		hash;

	/*
	 * Read version names until we encounter the ';' terminator.
	 */
	while (!done) {
		switch (tok = ld_map_gettoken(mf, 0, &tkv)) {
		case TK_ERROR:
			return (FALSE);

		case TK_STRING:
			name = tkv.tkv_str;

			/* The unnamed global scope can't inherit */
			if (mv->mv_vdp->vd_ndx == VER_NDX_GLOBAL) {
				mf_fatal(mf, MSG_INTL(MSG_MAP_UNEXINHERIT),
				    name);
				return (FALSE);
			}

			/*
			 * Generate a new version descriptor if it doesn't
			 * already exist.
			 */
			/* LINTED */
			hash = (Word)elf_hash(name);
			vdp = ld_vers_find(name, hash, mf->mf_ofl->ofl_verdesc);
			if ((vdp == NULL) && ((vdp = ld_vers_desc(name, hash,
			    &mf->mf_ofl->ofl_verdesc)) == (Ver_desc *)S_ERROR))
				return (FALSE);

			/*
			 * Add the new version descriptor to the parent version
			 * descriptors reference list.  Indicate the version
			 * descriptors first reference (used for error diags
			 * if undefined version dependencies remain).
			 */
			if (ld_vers_find(name, hash, mv->mv_vdp->vd_deps) ==
			    NULL)
				if (aplist_append(&mv->mv_vdp->vd_deps, vdp,
				    AL_CNT_VERDESCS) == NULL)
					return (FALSE);

			if (vdp->vd_ref == NULL)
				vdp->vd_ref = mv->mv_vdp;
			break;

		case TK_SEMICOLON:
			done = TRUE;
			break;

		default:
			mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_SYMEND),
			    ld_map_tokenstr(tok, &tkv, &inv_buf));
			return (FALSE);
		}
	}

	return (TRUE);
}
