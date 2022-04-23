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
 * Map file parsing (Original SysV syntax).
 */
#include	<string.h>
#include	<strings.h>
#include	<stdio.h>
#include	<unistd.h>
#include	<errno.h>
#include	<limits.h>
#include	<ctype.h>
#include	<elfcap.h>
#include	<debug.h>
#include	"msg.h"
#include	"_libld.h"
#include	"_map.h"

/*
 * Process a hardware/software capabilities segment declaration definition.
 *	hwcap_1	= val,... [ OVERRIDE ]
 *	sfcap_1	= val,... [ OVERRIDE ]
 *	hwcap_2	= val,... [ OVERRIDE ]
 *	platcap	= name,... [ OVERRIDE ]
 *	machcap	= name,... [ OVERRIDE ]
 *
 * The values can be defined as a list of machine specify tokens, or numerics.
 * Tokens are representations of the sys/auxv_$MACH.h capabilities, for example:
 *
 *	#define AV_386_FPU 0x0001	is represented as	FPU
 *	#define AV_386_TSC 0x0002	"    "	  "     "	TSC
 *
 * Or, the above two capabilities could be represented as V0x3.  Note, the
 * OVERRIDE flag is used to ensure that only those values provided via this
 * mapfile entry are recorded in the final image, ie. this overrides any
 * hardware capabilities that may be defined in the objects read as part of
 * this link-edit.  Specifying:
 *
 *	V0x0 OVERRIDE
 *
 * effectively removes any capabilities information from the final image.
 */
static Boolean
map_cap(Mapfile *mf, Word type, Capmask *capmask)
{
	Token		tok;		/* Current token. */
	Xword		number;
	int		used = 0;
	Ofl_desc	*ofl = mf->mf_ofl;
	ld_map_tkval_t	tkv;		/* Value of token */
	elfcap_mask_t	value = 0;

	if (DBG_ENABLED) {
		Dbg_cap_mapfile_title(ofl->ofl_lml, mf->mf_lineno);
		Dbg_cap_val_entry(ofl->ofl_lml, DBG_STATE_CURRENT, CA_SUNW_HW_1,
		    capmask->cm_val, ld_targ.t_m.m_mach);
	}

	while ((tok = ld_map_gettoken(mf, TK_F_STRLC, &tkv)) !=
	    TK_SEMICOLON) {
		if (tok != TK_STRING) {
			if (tok != TK_ERROR)
				mf_fatal0(mf, MSG_INTL(MSG_MAP_EXPSEGATT));
			return (FALSE);
		}

		/*
		 * First, determine if the token represents the reserved
		 * OVERRIDE keyword.
		 */
		if (strncmp(tkv.tkv_str, MSG_ORIG(MSG_MAP_OVERRIDE),
		    MSG_MAP_OVERRIDE_SIZE) == 0) {
			ld_map_cap_set_ovflag(mf, type);
			used++;
			continue;
		}

		/* Is the token a symbolic capability name? */
		if ((number = (Xword)elfcap_tag_from_str(ELFCAP_STYLE_LC,
		    type, tkv.tkv_str, ld_targ.t_m.m_mach)) != 0) {
			value |= number;
			used++;
			continue;
		}

		/*
		 * Is the token a numeric value?
		 */
		if (tkv.tkv_str[0] == 'v') {
			if (ld_map_strtoxword(&tkv.tkv_str[1], NULL,
			    &number) != STRTOXWORD_OK) {
				mf_fatal(mf, MSG_INTL(MSG_MAP_BADCAPVAL),
				    tkv.tkv_str);
				return (FALSE);
			}
			value |= number;
			used++;
			continue;
		}

		/*
		 * We have an unknown token.
		 */
		used++;
		mf_fatal(mf, MSG_INTL(MSG_MAP_UNKCAPATTR), tkv.tkv_str);
		return (FALSE);
	}

	/* Catch empty declarations */
	if (used == 0) {
		mf_warn0(mf, MSG_INTL(MSG_MAP_EMPTYCAP));
		return (TRUE);
	}

	DBG_CALL(Dbg_cap_val_entry(ofl->ofl_lml, DBG_STATE_NEW, type, value,
	    ld_targ.t_m.m_mach));
	capmask->cm_val |= value;

	/* Sanity check the resulting bits */
	if (!ld_map_cap_sanitize(mf, type, capmask))
		return (FALSE);

	return (TRUE);
}

/*
 * Parse the flags for a segment definition. Called by map_equal().
 *
 * entry:
 *	mf - Mapfile descriptor
 *	sgp - Segment being defined
 *	b_flags - Address of b_flags variable from map_equal().
 *		*bflags is TRUE if flags have already been seen in, the
 *		current segment definition directive, and FALSE otherwise.
 *	flag_tok - Flags string, starting with the '?' character.
 *
 * exit:
 *	On success, the flags have been parsed and the segment updated,
 *	*b_flags is set to TRUE, and TRUE is returned. On error, FALSE
 *	is returned.
 */
static Boolean
map_equal_flags(Mapfile *mf, Sg_desc *sgp, Boolean *b_flags,
    const char *flag_tok)
{
	Word	tmp_flags = 0;

	if (*b_flags) {
		mf_fatal(mf, MSG_INTL(MSG_MAP_MOREONCE),
		    MSG_INTL(MSG_MAP_SEGFLAG));
		return (FALSE);
	}

	/* Skip over the leading '?' character */
	flag_tok++;

	/*
	 * If ? has nothing following leave the flags cleared,
	 * otherwise OR in any flags specified.
	 */
	while (*flag_tok) {
		switch (*flag_tok) {
		case 'r':
			tmp_flags |= PF_R;
			break;
		case 'w':
			tmp_flags |= PF_W;
			break;
		case 'x':
			tmp_flags |= PF_X;
			break;
		case 'e':
			sgp->sg_flags |= FLG_SG_EMPTY;
			break;
		case 'o':
			/*
			 * The version 1 ?O option is incompatible with
			 * the version 2 SEGMENT IS_ORDER attribute.
			 */
			if (aplist_nitems(sgp->sg_is_order) > 0) {
				mf_fatal(mf, MSG_INTL(MSG_MAP_ISORDVER),
				    sgp->sg_name);
				return (FALSE);
			}

			/*
			 * Set FLG_SG_IS_ORDER to indicate that segment has
			 * had the ?O flag set by a version 1 mapfile.
			 */
			sgp->sg_flags |= FLG_SG_IS_ORDER;
			break;
		case 'n':
			/*
			 * If segment ends up as the first loadable segment,
			 * it will not include the the ELF and program headers.
			 */
			sgp->sg_flags |= FLG_SG_NOHDR;
			break;
		default:
			mf_fatal(mf, MSG_INTL(MSG_MAP_UNKSEGFLG), *flag_tok);
			return (FALSE);
		}
		flag_tok++;
	}

	/*
	 * Warn when changing flags except when we're adding or removing "X"
	 * from a RW PT_LOAD segment.
	 */
	if ((sgp->sg_flags & FLG_SG_P_FLAGS) &&
	    (sgp->sg_phdr.p_flags != tmp_flags) &&
	    !(sgp->sg_phdr.p_type == PT_LOAD &&
	    (tmp_flags & (PF_R|PF_W)) == (PF_R|PF_W) &&
	    (tmp_flags ^ sgp->sg_phdr.p_flags) == PF_X))
		mf_warn(mf, MSG_INTL(MSG_MAP_REDEFATT),
		    MSG_INTL(MSG_MAP_SEGFLAG), sgp->sg_name);

	sgp->sg_flags |= FLG_SG_P_FLAGS;
	sgp->sg_phdr.p_flags = tmp_flags;
	*b_flags = TRUE;

	return (TRUE);
}

/*
 * Read an address (value) or size Xword from a TK_STRING token value
 * where the first letter of the string is a letter ('v', 'l', 's', ...)
 * followed by the numeric value.
 *
 * entry:
 *	mf - Mapfile descriptor
 *	tkv - TK_STRING token to parse
 *	value - Address of variable to receive the resulting value.
 *
 * exit:
 *	Returns TRUE for success. On failure, issues an error message
 *	and returns FALSE.
 */
static Boolean
valuetoxword(Mapfile *mf, ld_map_tkval_t *tkv, Xword *value)
{
	switch (ld_map_strtoxword(&tkv->tkv_str[1], NULL, value)) {
	case STRTOXWORD_OK:
		return (TRUE);

	case STRTOXWORD_TOOBIG:
		mf_fatal(mf, MSG_INTL(MSG_MAP_SEGADDR), tkv->tkv_str,
		    MSG_INTL(MSG_MAP_EXCLIMIT));
		break;
	default:
		mf_fatal(mf, MSG_INTL(MSG_MAP_SEGADDR), tkv->tkv_str,
		    MSG_INTL(MSG_MAP_NOBADFRM));
		break;
	}

	return (FALSE);
}

/*
 * Process a mapfile segment declaration definition.
 *	segment_name	= segment_attribute;
 *	segment_attribute : segment_type  segment_flags	 virtual_addr
 *			    physical_addr  length alignment
 */
static Boolean
map_equal(Mapfile *mf, Sg_desc *sgp)
{
	/*
	 * Segment type.  Users are permitted to define PT_LOAD,
	 * PT_NOTE, PT_SUNWSTACK and PT_NULL segments.  Other segment
	 * types are only defined in seg_desc[].
	 */
	typedef struct {
		const char	*name;	/* Name for segment type  */
		Word		p_type;	/* PT_ constant corresponding to name */
		sg_flags_t	sg_flags; /* Seg descriptor flags to apply */
	} seg_types_t;

	static seg_types_t seg_type_arr[] = {
		{ MSG_ORIG(MSG_MAP_LOAD),	PT_LOAD,	FLG_SG_P_TYPE },
		{ MSG_ORIG(MSG_MAP_STACK),	PT_SUNWSTACK,
		    FLG_SG_P_TYPE | FLG_SG_EMPTY },
		{ MSG_ORIG(MSG_MAP_NULL),	PT_NULL,	FLG_SG_P_TYPE },
		{ MSG_ORIG(MSG_MAP_NOTE),	PT_NOTE,	FLG_SG_P_TYPE },

		/* Array must be NULL terminated */
		{ NULL }
	};


	seg_types_t	*seg_type;
	Token	tok;			/* Current token. */
	ld_map_tkval_t	tkv;		/* Value of token */
	Boolean	b_type  = FALSE;	/* True if seg types found. */
	Boolean	b_flags = FALSE;	/* True if seg flags found. */
	Boolean	b_len   = FALSE;	/* True if seg length found. */
	Boolean	b_round = FALSE;	/* True if seg rounding found. */
	Boolean	b_vaddr = FALSE;	/* True if seg virtual addr found. */
	Boolean	b_paddr = FALSE;	/* True if seg physical addr found. */
	Boolean	b_align = FALSE;	/* True if seg alignment found. */

	while ((tok = ld_map_gettoken(mf, TK_F_STRLC, &tkv)) !=
	    TK_SEMICOLON) {
		if (tok != TK_STRING) {
			if (tok != TK_ERROR)
				mf_fatal0(mf, MSG_INTL(MSG_MAP_EXPSEGATT));
			return (FALSE);
		}

		/*
		 * If it is the name of a segment type, set the type
		 * and flags fields in the descriptor.
		 */
		for (seg_type = seg_type_arr; seg_type->name; seg_type++) {
			if (strcmp(tkv.tkv_str, seg_type->name) == 0) {
				if (b_type) {
					mf_fatal(mf, MSG_INTL(MSG_MAP_MOREONCE),
					    MSG_INTL(MSG_MAP_SEGTYP));
					return (FALSE);
				}
				if ((sgp->sg_flags & FLG_SG_P_TYPE) &&
				    (sgp->sg_phdr.p_type != seg_type->p_type)) {
					mf_warn(mf, MSG_INTL(MSG_MAP_REDEFATT),
					    MSG_INTL(MSG_MAP_SEGTYP),
					    sgp->sg_name);
				}

				sgp->sg_phdr.p_type = seg_type->p_type;
				sgp->sg_flags |= seg_type->sg_flags;
				break;
			}
		}
		if (seg_type->name != NULL)	/* Matched segment type */
			continue;		/* next token */

		/* Segment Flags */
		if (*tkv.tkv_str == '?') {
			if (!map_equal_flags(mf, sgp, &b_flags, tkv.tkv_str))
				return (FALSE);
			continue;		/* next token */
		}


		/* Segment address, length, alignment or rounding number */
		if ((tkv.tkv_str[0] == 'l') || (tkv.tkv_str[0] == 'v') ||
		    (tkv.tkv_str[0] == 'a') || (tkv.tkv_str[0] == 'p') ||
		    (tkv.tkv_str[0] == 'r')) {
			Xword	number;

			if (!valuetoxword(mf, &tkv, &number))
				return (FALSE);

			switch (*tkv.tkv_str) {
			case 'l':
				if (b_len) {
					mf_fatal(mf,
					    MSG_INTL(MSG_MAP_MOREONCE),
					    MSG_INTL(MSG_MAP_SEGLEN));
					return (FALSE);
				}
				if ((sgp->sg_flags & FLG_SG_LENGTH) &&
				    (sgp->sg_length != number))
					mf_warn(mf,
					    MSG_INTL(MSG_MAP_REDEFATT),
					    MSG_INTL(MSG_MAP_SEGLEN),
					    sgp->sg_name);
				sgp->sg_length = number;
				sgp->sg_flags |= FLG_SG_LENGTH;
				b_len = TRUE;
				break;
			case 'r':
				if (b_round) {
					mf_fatal(mf,
					    MSG_INTL(MSG_MAP_MOREONCE),
					    MSG_INTL(MSG_MAP_SEGROUND));
					return (FALSE);
				}
				if ((sgp->sg_flags & FLG_SG_ROUND) &&
				    (sgp->sg_round != number))
					mf_warn(mf,
					    MSG_INTL(MSG_MAP_REDEFATT),
					    MSG_INTL(MSG_MAP_SEGROUND),
					    sgp->sg_name);
				sgp->sg_round = number;
				sgp->sg_flags |= FLG_SG_ROUND;
				b_round = TRUE;
				break;
			case 'v':
				if (b_vaddr) {
					mf_fatal(mf,
					    MSG_INTL(MSG_MAP_MOREONCE),
					    MSG_INTL(MSG_MAP_SEGVADDR));
					return (FALSE);
				}
				if ((sgp->sg_flags & FLG_SG_P_VADDR) &&
				    (sgp->sg_phdr.p_vaddr != number))
					mf_warn(mf,
					    MSG_INTL(MSG_MAP_REDEFATT),
					    MSG_INTL(MSG_MAP_SEGVADDR),
					    sgp->sg_name);
				/* LINTED */
				sgp->sg_phdr.p_vaddr = (Addr)number;
				sgp->sg_flags |= FLG_SG_P_VADDR;
				b_vaddr = TRUE;
				break;
			case 'p':
				if (b_paddr) {
					mf_fatal(mf,
					    MSG_INTL(MSG_MAP_MOREONCE),
					    MSG_INTL(MSG_MAP_SEGPHYS));
					return (FALSE);
				}
				if ((sgp->sg_flags & FLG_SG_P_PADDR) &&
				    (sgp->sg_phdr.p_paddr != number))
					mf_warn(mf,
					    MSG_INTL(MSG_MAP_REDEFATT),
					    MSG_INTL(MSG_MAP_SEGPHYS),
					    sgp->sg_name);
				/* LINTED */
				sgp->sg_phdr.p_paddr = (Addr)number;
				sgp->sg_flags |= FLG_SG_P_PADDR;
				b_paddr = TRUE;
				break;
			case 'a':
				if (b_align) {
					mf_fatal(mf,
					    MSG_INTL(MSG_MAP_MOREONCE),
					    MSG_INTL(MSG_MAP_SEGALIGN));
					return (FALSE);
				}
				if ((sgp->sg_flags & FLG_SG_P_ALIGN) &&
				    (sgp->sg_phdr.p_align != number))
					mf_warn(mf,
					    MSG_INTL(MSG_MAP_REDEFATT),
					    MSG_INTL(MSG_MAP_SEGALIGN),
					    sgp->sg_name);
				/* LINTED */
				sgp->sg_phdr.p_align = (Xword)number;
				sgp->sg_flags |= FLG_SG_P_ALIGN;
				b_align = TRUE;
				break;
			}

			continue;		/* next token */
		}

		/*
		 * If we reach the bottom of this loop, we have an
		 * unrecognized token.
		 */
		mf_fatal(mf, MSG_INTL(MSG_MAP_UNKSEGATT), tkv.tkv_str);
		return (FALSE);
	}

	/*
	 * Empty segments can be used to define PT_LOAD segment reservations, or
	 * to reserve PT_NULL program headers.
	 *
	 * PT_LOAD reservations are only allowed within executables, as the
	 * reservation must be established through exec() as part of initial
	 * process loading.  In addition, PT_LOAD reservations must have an
	 * associated address and size. Note: This is an obsolete feature,
	 * not supported by the newer mapfile syntax.
	 *
	 * PT_NULL program headers are established for later use by applications
	 * such as the post-optimizer.  PT_NULL headers should have no other
	 * attributes assigned.
	 */
	if ((sgp->sg_flags & FLG_SG_EMPTY) &&
	    (sgp->sg_phdr.p_type != PT_SUNWSTACK)) {

		/*
		 * Any style of empty segment should have no permissions.
		 */
		if (sgp->sg_phdr.p_flags != 0) {
			mf_fatal(mf, MSG_INTL(MSG_MAP_SEGEMNOPERM),
			    EC_WORD(sgp->sg_phdr.p_flags));
			return (FALSE);
		}

		if (sgp->sg_phdr.p_type == PT_LOAD) {
			if ((mf->mf_ofl->ofl_flags & FLG_OF_EXEC) == 0) {
				mf_fatal0(mf, MSG_INTL(MSG_MAP_SEGEMPEXE));
				return (FALSE);
			}
			if ((sgp->sg_flags &
			    (FLG_SG_LENGTH | FLG_SG_P_VADDR)) !=
			    (FLG_SG_LENGTH | FLG_SG_P_VADDR)) {
				mf_fatal0(mf, MSG_INTL(MSG_MAP_SEGEMPATT));
				return (FALSE);
			}
		} else if (sgp->sg_phdr.p_type == PT_NULL) {
			if ((sgp->sg_flags &
			    (FLG_SG_LENGTH | FLG_SG_P_VADDR)) &&
			    ((sgp->sg_length != 0) ||
			    (sgp->sg_phdr.p_vaddr != 0))) {
				mf_fatal0(mf, MSG_INTL(MSG_MAP_SEGEMPNOATT));
				return (FALSE);
			}
		} else {
			mf_warn0(mf, MSG_INTL(MSG_MAP_SEGEMPLOAD));
			sgp->sg_phdr.p_type = PT_LOAD;
		}
	}

	/*
	 * All segment attributes have now been scanned.  Certain flags do not
	 * make sense if this is not a loadable segment, fix if necessary.
	 * Note, if the segment is of type PT_NULL it must be new, and any
	 * defaults will be applied by ld_map_seg_insert(). When clearing an
	 * attribute leave the flag set as an indicator for later entries
	 * re-specifying the same segment.
	 */
	if ((sgp->sg_phdr.p_type != PT_NULL) &&
	    (sgp->sg_phdr.p_type != PT_LOAD)) {
		const char	*fmt;

		if (sgp->sg_phdr.p_type == PT_SUNWSTACK)
			fmt = MSG_INTL(MSG_MAP_NOSTACK1);
		else
			fmt = MSG_INTL(MSG_MAP_NONLOAD);

		if ((sgp->sg_flags & FLG_SG_P_FLAGS) &&
		    (sgp->sg_phdr.p_type != PT_SUNWSTACK)) {
			if (sgp->sg_phdr.p_flags != 0) {
				mf_warn(mf, MSG_INTL(MSG_MAP_NONLOAD),
				    MSG_INTL(MSG_MAP_SEGFLAG));
				sgp->sg_phdr.p_flags = 0;
			}
		}
		if (sgp->sg_flags & FLG_SG_LENGTH)
			if (sgp->sg_length != 0) {
				mf_warn(mf, fmt, MSG_INTL(MSG_MAP_SEGLEN));
				sgp->sg_length = 0;
			}
		if (sgp->sg_flags & FLG_SG_ROUND)
			if (sgp->sg_round != 0) {
				mf_warn(mf, fmt, MSG_INTL(MSG_MAP_SEGROUND));
				sgp->sg_round = 0;
			}
		if (sgp->sg_flags & FLG_SG_P_VADDR) {
			if (sgp->sg_phdr.p_vaddr != 0) {
				mf_warn(mf, fmt, MSG_INTL(MSG_MAP_SEGVADDR));
				sgp->sg_phdr.p_vaddr = 0;
			}
		}
		if (sgp->sg_flags & FLG_SG_P_PADDR)
			if (sgp->sg_phdr.p_paddr != 0) {
				mf_warn(mf, fmt, MSG_INTL(MSG_MAP_SEGPHYS));
				sgp->sg_phdr.p_paddr = 0;
			}
		if (sgp->sg_flags & FLG_SG_P_ALIGN)
			if (sgp->sg_phdr.p_align != 0) {
				mf_warn(mf, fmt, MSG_INTL(MSG_MAP_SEGALIGN));
				sgp->sg_phdr.p_align = 0;
			}
	}
	return (TRUE);
}


/*
 * Process a mapfile mapping directives definition.
 *
 *	segment_name : section_attribute [ : file_name ]
 *
 * Where segment_attribute is one of: section_name section_type section_flags;
 */
static Boolean
map_colon(Mapfile *mf, Ent_desc *enp)
{
	Token		tok;
	ld_map_tkval_t	tkv;
	Boolean		b_name = FALSE;
	Boolean		b_type = FALSE;
	Boolean		b_attr = FALSE;
	Boolean		b_bang = FALSE;


	/*
	 * Start out assuming that this entrance criteria will be empty,
	 * and therefore match anything. We clear the CATCHALL flag below
	 * if this turns out not to be the case.
	 */
	enp->ec_flags |= FLG_EC_CATCHALL;

	while (((tok = ld_map_gettoken(mf, 0, &tkv)) != TK_COLON) &&
	    (tok != TK_SEMICOLON)) {
		if (tok == TK_ERROR)
			return (FALSE);
		if (tok != TK_STRING) {
			mf_fatal0(mf, MSG_INTL(MSG_MAP_MALFORM));
			return (FALSE);
		}

		/* Segment type. */

		if (*tkv.tkv_str == '$') {
			if (b_type) {
				mf_fatal(mf, MSG_INTL(MSG_MAP_MOREONCE),
				    MSG_INTL(MSG_MAP_SECTYP));
				return (FALSE);
			}
			b_type = TRUE;
			tkv.tkv_str++;
			ld_map_lowercase(tkv.tkv_str);
			if (strcmp(tkv.tkv_str, MSG_ORIG(MSG_STR_PROGBITS)) ==
			    0)
				enp->ec_type = SHT_PROGBITS;
			else if (strcmp(tkv.tkv_str,
			    MSG_ORIG(MSG_STR_SYMTAB)) == 0)
				enp->ec_type = SHT_SYMTAB;
			else if (strcmp(tkv.tkv_str,
			    MSG_ORIG(MSG_STR_DYNSYM)) == 0)
				enp->ec_type = SHT_DYNSYM;
			else if (strcmp(tkv.tkv_str,
			    MSG_ORIG(MSG_STR_STRTAB)) == 0)
				enp->ec_type = SHT_STRTAB;
			else if ((strcmp(tkv.tkv_str,
			    MSG_ORIG(MSG_STR_REL)) == 0) ||
			    (strcmp(tkv.tkv_str, MSG_ORIG(MSG_STR_RELA)) == 0))
				enp->ec_type = ld_targ.t_m.m_rel_sht_type;
			else if (strcmp(tkv.tkv_str, MSG_ORIG(MSG_STR_HASH)) ==
			    0)
				enp->ec_type = SHT_HASH;
			else if (strcmp(tkv.tkv_str, MSG_ORIG(MSG_STR_LIB)) ==
			    0)
				enp->ec_type = SHT_SHLIB;
			else if (strcmp(tkv.tkv_str,
			    MSG_ORIG(MSG_STR_LD_DYNAMIC)) == 0)
				enp->ec_type = SHT_DYNAMIC;
			else if (strcmp(tkv.tkv_str, MSG_ORIG(MSG_STR_NOTE)) ==
			    0)
				enp->ec_type = SHT_NOTE;
			else if (strcmp(tkv.tkv_str,
			    MSG_ORIG(MSG_STR_NOBITS)) == 0)
				enp->ec_type = SHT_NOBITS;
			else {
				mf_fatal(mf, MSG_INTL(MSG_MAP_UNKSECTYP),
				    tkv.tkv_str);
				return (FALSE);
			}

			enp->ec_flags &= ~FLG_EC_CATCHALL;

		/*
		 * Segment flags.
		 * If a segment flag is specified then the appropriate bit is
		 * set in the ec_attrmask, the ec_attrbits fields determine
		 * whether the attrmask fields must be tested true or false
		 * ie.	for  ?A the attrmask is set and the attrbit is set,
		 *	for ?!A the attrmask is set and the attrbit is clear.
		 */
		} else if (*tkv.tkv_str == '?') {
			if (b_attr) {
				mf_fatal(mf, MSG_INTL(MSG_MAP_MOREONCE),
				    MSG_INTL(MSG_MAP_SECFLAG));
				return (FALSE);
			}
			b_attr = TRUE;
			b_bang = FALSE;
			tkv.tkv_str++;
			ld_map_lowercase(tkv.tkv_str);
			for (; *tkv.tkv_str != '\0'; tkv.tkv_str++)
				switch (*tkv.tkv_str) {
				case '!':
					if (b_bang) {
						mf_fatal(mf,
						    MSG_INTL(MSG_MAP_BADFLAG),
						    tkv.tkv_str);
						return (FALSE);
					}
					b_bang = TRUE;
					break;
				case 'a':
					if (enp->ec_attrmask & SHF_ALLOC) {
						mf_fatal(mf,
						    MSG_INTL(MSG_MAP_BADFLAG),
						    tkv.tkv_str);
						return (FALSE);
					}
					enp->ec_attrmask |= SHF_ALLOC;
					if (!b_bang)
						enp->ec_attrbits |= SHF_ALLOC;
					b_bang = FALSE;
					break;
				case 'w':
					if (enp->ec_attrmask & SHF_WRITE) {
						mf_fatal(mf,
						    MSG_INTL(MSG_MAP_BADFLAG),
						    tkv.tkv_str);
						return (FALSE);
					}
					enp->ec_attrmask |= SHF_WRITE;
					if (!b_bang)
						enp->ec_attrbits |= SHF_WRITE;
					b_bang = FALSE;
					break;
				case 'x':
					if (enp->ec_attrmask & SHF_EXECINSTR) {
						mf_fatal(mf,
						    MSG_INTL(MSG_MAP_BADFLAG),
						    tkv.tkv_str);
						return (FALSE);
					}
					enp->ec_attrmask |= SHF_EXECINSTR;
					if (!b_bang)
						enp->ec_attrbits |=
						    SHF_EXECINSTR;
					b_bang = FALSE;
					break;
				default:
					mf_fatal(mf,
					    MSG_INTL(MSG_MAP_BADFLAG),
					    tkv.tkv_str);
					return (FALSE);
				}
			if (enp->ec_attrmask != 0)
				enp->ec_flags &= ~FLG_EC_CATCHALL;

		/*
		 * Section name.
		 */
		} else {
			if (b_name) {
				mf_fatal(mf, MSG_INTL(MSG_MAP_MOREONCE),
				    MSG_INTL(MSG_MAP_SECNAME));
				return (FALSE);
			}
			b_name = TRUE;
			enp->ec_is_name = tkv.tkv_str;
			enp->ec_flags &= ~FLG_EC_CATCHALL;
		}
	}
	if (tok == TK_COLON) {
		/*
		 * File names.
		 */
		while ((tok = ld_map_gettoken(mf, 0, &tkv)) != TK_SEMICOLON) {
			Word	ecf_type;

			if (tok != TK_STRING) {
				if (tok != TK_ERROR)
					mf_fatal0(mf,
					    MSG_INTL(MSG_MAP_MALFORM));
				return (FALSE);
			}

			/*
			 * A leading '*' means that this should be a basename
			 * comparison rather than a full path. It's not a glob
			 * wildcard, although it looks like one.
			 */
			if (tkv.tkv_str[0] == '*') {
				ecf_type = TYP_ECF_BASENAME;
				tkv.tkv_str++;
			} else {
				ecf_type = TYP_ECF_PATH;
			}
			if (!ld_map_seg_ent_files(mf, enp, ecf_type,
			    tkv.tkv_str))
				return (FALSE);
			enp->ec_flags &= ~FLG_EC_CATCHALL;
		}
	}
	return (TRUE);
}

/*
 * Process a mapfile size symbol definition.
 *	segment_name @ symbol_name;
 */
static Boolean
map_atsign(Mapfile *mf, Sg_desc *sgp)
{
	Token		tok;		/* Current token. */
	ld_map_tkval_t	tkv;		/* Value of token */

	if ((tok = ld_map_gettoken(mf, 0, &tkv)) != TK_STRING) {
		if (tok != TK_ERROR)
			mf_fatal0(mf, MSG_INTL(MSG_MAP_EXPSYM_1));
		return (FALSE);
	}

	/* Add the symbol to the segment */
	if (!ld_map_seg_size_symbol(mf, sgp, TK_PLUSEQ, tkv.tkv_str))
		return (FALSE);


	if (ld_map_gettoken(mf, 0, &tkv) != TK_SEMICOLON) {
		if (tok != TK_ERROR)
			mf_fatal0(mf, MSG_INTL(MSG_MAP_EXPSCOL));
		return (FALSE);
	}

	return (TRUE);
}


static Boolean
map_pipe(Mapfile *mf, Sg_desc *sgp)
{
	Token		tok;		/* current token. */
	ld_map_tkval_t	tkv;		/* Value of token */

	if ((tok = ld_map_gettoken(mf, 0, &tkv)) != TK_STRING) {
		if (tok != TK_ERROR)
			mf_fatal0(mf, MSG_INTL(MSG_MAP_EXPSEC));
		return (FALSE);
	}

	if (!ld_map_seg_os_order_add(mf, sgp, tkv.tkv_str))
		return (FALSE);

	if ((tok = ld_map_gettoken(mf, 0, &tkv)) != TK_SEMICOLON) {
		if (tok != TK_ERROR)
			mf_fatal0(mf, MSG_INTL(MSG_MAP_EXPSCOL));
		return (FALSE);
	}

	return (TRUE);
}

/*
 * Process a mapfile library specification definition.
 *	shared_object_name - shared object definition
 *	shared object definition : [ shared object type [ = SONAME ]]
 *					[ versions ];
 */
static Boolean
map_dash(Mapfile *mf, char *name)
{
	Token		tok;
	Sdf_desc	*sdf;
	ld_map_tkval_t	tkv;		/* Value of token */
	enum {
	    MD_NONE = 0,
	    MD_ADDVERS,
	}		dolkey = MD_NONE;

	/* Get descriptor for dependency */
	if ((sdf = ld_map_dv(mf, name)) == NULL)
		return (FALSE);

	/*
	 * Get the shared object descriptor string.
	 */
	while ((tok = ld_map_gettoken(mf, 0, &tkv)) != TK_SEMICOLON) {
		if ((tok != TK_STRING) && (tok != TK_EQUAL)) {
			if (tok != TK_ERROR)
				mf_fatal0(mf, MSG_INTL(MSG_MAP_EXPSO));
			return (FALSE);
		}

		/*
		 * Determine if the library type is accompanied with a SONAME
		 * definition.
		 */
		if (tok == TK_EQUAL) {
			if ((tok = ld_map_gettoken(mf, 0, &tkv)) !=
			    TK_STRING) {
				if (tok != TK_ERROR)
					mf_fatal0(mf,
					    MSG_INTL(MSG_MAP_EXPSO));
				return (FALSE);
			}
			switch (dolkey) {
			case MD_ADDVERS:
				if (!ld_map_dv_entry(mf, sdf, TRUE,
				    tkv.tkv_str))
					return (FALSE);
				break;
			case MD_NONE:
				mf_fatal(mf, MSG_INTL(MSG_MAP_UNEXTOK), '=');
				return (FALSE);
			}
			dolkey = MD_NONE;
			continue;
		}

		/*
		 * A shared object type has been specified.  This may also be
		 * accompanied by an SONAME redefinition (see above).
		 */
		if (*tkv.tkv_str == '$') {
			if (dolkey != MD_NONE) {
				mf_fatal(mf, MSG_INTL(MSG_MAP_UNEXTOK), '$');
				return (FALSE);
			}
			tkv.tkv_str++;
			ld_map_lowercase(tkv.tkv_str);
			if (strcmp(tkv.tkv_str, MSG_ORIG(MSG_MAP_ADDVERS)) ==
			    0) {
				dolkey = MD_ADDVERS;
			} else {
				mf_fatal(mf, MSG_INTL(MSG_MAP_UNKSOTYP),
				    tkv.tkv_str);
				return (FALSE);
			}
			continue;
		}

		/*
		 * shared object version requirement.
		 */
		if (!ld_map_dv_entry(mf, sdf, FALSE, tkv.tkv_str))
			return (FALSE);
	}

	return (TRUE);
}


/*
 * Process a symbol definition.  Historically, this originated from processing
 * a version definition.  However, this has evolved into a generic means of
 * defining symbol references and definitions (see Defining Additional Symbols
 * in the Linker and Libraries guide for the complete syntax).
 *
 * [ name ] {
 *	scope:
 *		 symbol [ = [ type ] [ value ] [ size ] [ attribute ] ];
 * } [ dependency ];
 *
 */
static Boolean
map_version(Mapfile *mf, char *name)
{
	Token		tok;
	ld_map_tkval_t	tkv;		/* Value of token */
	ld_map_ver_t	mv;
	ld_map_sym_t	ms;
	Ofl_desc	*ofl = mf->mf_ofl;

	/* Establish the version descriptor and related data */
	if (!ld_map_sym_ver_init(mf, name, &mv))
		return (FALSE);

	/*
	 * Scan the mapfile entry picking out scoping and symbol definitions.
	 */
	while ((tok = ld_map_gettoken(mf, 0, &tkv)) != TK_RIGHTBKT) {
		uint_t		filter = 0;

		if (tok != TK_STRING) {
			if (tok == TK_ERROR) {
				mf_fatal0(mf, MSG_INTL(MSG_MAP_EXPSYM_2));
				return (FALSE);
			}
			mv.mv_errcnt++;
			continue;
		}

		/* The default value for all the symbol attributes is 0 */
		(void) memset(&ms, 0, sizeof (ms));
		ms.ms_name = tkv.tkv_str;

		tok = ld_map_gettoken(mf, 0, &tkv);
		if (tok == TK_ERROR) {
			mv.mv_errcnt++;
			continue;
		}

		/*
		 * Turn off the WEAK flag to indicate that definitions are
		 * associated with this version.  It would probably be more
		 * accurate to only remove this flag with the specification of
		 * global symbols, however setting it here allows enough slop
		 * to compensate for the various user inputs we've seen so far.
		 * Only if a closed version is specified (i.e., "SUNW_1.x {};")
		 * will a user get a weak version (which is how we document the
		 * creation of weak versions).
		 */
		mv.mv_vdp->vd_flags &= ~VER_FLG_WEAK;

		switch (tok) {
		case TK_COLON:
			ld_map_sym_scope(mf, ms.ms_name, &mv);
			continue;

		case TK_EQUAL:
			/*
			 * A full blown symbol definition follows.
			 * Determine the symbol type and any virtual address or
			 * alignment specified and then fall through to process
			 * the entire symbols information.
			 */
			while ((tok = ld_map_gettoken(mf, 0, &tkv)) !=
			    TK_SEMICOLON) {
				if (tok == TK_ERROR)
					return (FALSE);
				if (tok != TK_STRING) {
					mf_fatal0(mf,
					    MSG_INTL(MSG_MAP_MALFORM));
					return (FALSE);
				}

				/*
				 * If we had previously seen AUX or FILTER,
				 * the next string is the filtee itself.
				 * Add it, and clear the filter flag.
				 */
				if (filter) {
					ld_map_sym_filtee(mf, &mv, &ms,
					    filter, tkv.tkv_str);
					filter = 0;
					continue;
				}

				/*
				 * Determine any Value or Size attributes.
				 */
				ld_map_lowercase(tkv.tkv_str);

				if (tkv.tkv_str[0] == 'v' ||
				    tkv.tkv_str[0] == 's') {
					Xword	number;

					if (!valuetoxword(mf, &tkv, &number)) {
						mv.mv_errcnt++;
						return (FALSE);
					}

					switch (*tkv.tkv_str) {
					case 'v':
					    /* BEGIN CSTYLED */
					    if (ms.ms_value) {
						mf_fatal(mf,
						    MSG_INTL(MSG_MAP_MOREONCE),
						    MSG_INTL(MSG_MAP_SYMVAL));
						mv.mv_errcnt++;
						continue;
					    }
					    /* LINTED */
					    ms.ms_value = (Addr)number;
					    ms.ms_value_set = TRUE;
					    break;
					    /* END CSTYLED */
					case 's':
					    /* BEGIN CSTYLED */
					    if (ms.ms_size) {
						mf_fatal(mf,
						    MSG_INTL(MSG_MAP_MOREONCE),
						    MSG_INTL(MSG_MAP_SYMSIZE));
						mv.mv_errcnt++;
						continue;
					    }
					    /* LINTED */
					    ms.ms_size = (Addr)number;
					    ms.ms_size_set = TRUE;
					    break;
					    /* END CSTYLED */
					}

				} else if (strcmp(tkv.tkv_str,
				    MSG_ORIG(MSG_MAP_FUNCTION)) == 0) {
					ms.ms_shndx = SHN_ABS;
					ms.ms_sdflags |= FLG_SY_SPECSEC;
					ms.ms_type = STT_FUNC;
				} else if (strcmp(tkv.tkv_str,
				    MSG_ORIG(MSG_MAP_DATA)) == 0) {
					ms.ms_shndx = SHN_ABS;
					ms.ms_sdflags |= FLG_SY_SPECSEC;
					ms.ms_type = STT_OBJECT;
				} else if (strcmp(tkv.tkv_str,
				    MSG_ORIG(MSG_MAP_COMMON)) == 0) {
					ms.ms_shndx = SHN_COMMON;
					ms.ms_sdflags |= FLG_SY_SPECSEC;
					ms.ms_type = STT_OBJECT;
				} else if (strcmp(tkv.tkv_str,
				    MSG_ORIG(MSG_MAP_PARENT)) == 0) {
					ms.ms_sdflags |= FLG_SY_PARENT;
					ofl->ofl_flags |= FLG_OF_SYMINFO;
				} else if (strcmp(tkv.tkv_str,
				    MSG_ORIG(MSG_MAP_EXTERN)) == 0) {
					ms.ms_sdflags |= FLG_SY_EXTERN;
					ofl->ofl_flags |= FLG_OF_SYMINFO;
				} else if (strcmp(tkv.tkv_str,
				    MSG_ORIG(MSG_MAP_DIRECT)) == 0) {
					ms.ms_sdflags |= FLG_SY_DIR;
					ofl->ofl_flags |= FLG_OF_SYMINFO;
				} else if (strcmp(tkv.tkv_str,
				    MSG_ORIG(MSG_MAP_NODIRECT)) == 0) {
					ms.ms_sdflags |= FLG_SY_NDIR;
					ofl->ofl_flags |= FLG_OF_SYMINFO;
					ofl->ofl_flags1 |=
					    (FLG_OF1_NDIRECT | FLG_OF1_NGLBDIR);
				} else if (strcmp(tkv.tkv_str,
				    MSG_ORIG(MSG_MAP_FILTER)) == 0) {
					/* Next token is the filtee */
					filter = FLG_SY_STDFLTR;
					continue;
				} else if (strcmp(tkv.tkv_str,
				    MSG_ORIG(MSG_MAP_AUXILIARY)) == 0) {
					/* Next token is the filtee */
					filter = FLG_SY_AUXFLTR;
					continue;
				} else if (strcmp(tkv.tkv_str,
				    MSG_ORIG(MSG_MAP_INTERPOSE)) == 0) {
					/* BEGIN CSTYLED */
					if (!(ofl->ofl_flags & FLG_OF_EXEC)) {
					    mf_fatal0(mf,
						MSG_INTL(MSG_MAP_NOINTPOSE));
					    mv.mv_errcnt++;
					    break;
					}
					/* END CSTYLED */
					ms.ms_sdflags |= FLG_SY_INTPOSE;
					ofl->ofl_flags |= FLG_OF_SYMINFO;
					ofl->ofl_dtflags_1 |= DF_1_SYMINTPOSE;
					continue;
				} else if (strcmp(tkv.tkv_str,
				    MSG_ORIG(MSG_MAP_DYNSORT)) == 0) {
					ms.ms_sdflags |= FLG_SY_DYNSORT;
					ms.ms_sdflags &= ~FLG_SY_NODYNSORT;
					continue;
				} else if (strcmp(tkv.tkv_str,
				    MSG_ORIG(MSG_MAP_NODYNSORT)) == 0) {
					ms.ms_sdflags &= ~FLG_SY_DYNSORT;
					ms.ms_sdflags |= FLG_SY_NODYNSORT;
					continue;
				} else {
					mf_fatal(mf,
					    MSG_INTL(MSG_MAP_UNKSYMDEF),
					    tkv.tkv_str);
					mv.mv_errcnt++;
					continue;
				}
			}
			/* FALLTHROUGH */

		case TK_SEMICOLON:
			/* Auto-reduction directive ('*')? */
			if (*ms.ms_name == '*') {
				ld_map_sym_autoreduce(mf, &mv);
				continue;
			}

			/*
			 * Catch the error where the AUX or FILTER keyword
			 * was used, but the filtee wasn't supplied.
			 */
			if (filter && (ms.ms_filtee == NULL)) {
				mf_fatal(mf, MSG_INTL(MSG_MAP_NOFILTER),
				    ms.ms_name);
				mv.mv_errcnt++;
				continue;
			}

			/*
			 * Add the new symbol.  It should be noted that all
			 * symbols added by the mapfile start out with global
			 * scope, thus they will fall through the normal symbol
			 * resolution process.  Symbols defined as locals will
			 * be reduced in scope after all input file processing.
			 */
			if (!ld_map_sym_enter(mf, &mv, &ms, NULL))
				return (FALSE);
			break;

		default:
			mf_fatal0(mf, MSG_INTL(MSG_MAP_EXPSCOL));
			mv.mv_errcnt++;
			continue;
		}
	}

	if (mv.mv_errcnt)
		return (FALSE);

	/*
	 * Determine if any version references are provided after the close
	 * bracket, parsing up to the terminating ';'.
	 */
	if (!ld_map_sym_ver_fini(mf, &mv))
		return (FALSE);

	return (TRUE);
}

/*
 * Parse the mapfile --- Sysv syntax
 */
Boolean
ld_map_parse_v1(Mapfile *mf)
{
	Sg_desc		*sgp1;		/* seg descriptor being manipulated */
	Ent_desc	*enp;		/* segment entrance criteria. */
	Token		tok;		/* current token. */
	Boolean		new_segment;	/* If true, defines new segment */
	char		*name;
	Ofl_desc	*ofl = mf->mf_ofl;
	ld_map_tkval_t	tkv;		/* Value of token */
	avl_index_t	where;

	/*
	 * We now parse the mapfile until the gettoken routine returns EOF.
	 */
	while ((tok = ld_map_gettoken(mf, TK_F_EOFOK, &tkv)) != TK_EOF) {
		Xword	ndx;

		/*
		 * At this point we are at the beginning of a line, and the
		 * variable tkv.tkv_str points to the first string on the line.
		 * All mapfile entries start with some string token except it
		 * is possible for a scoping definition to start with `{'.
		 */
		if (tok == TK_LEFTBKT) {
			if (!map_version(mf, NULL))
				return (FALSE);
			continue;
		}
		if (tok != TK_STRING) {
			if (tok != TK_ERROR)
				mf_fatal0(mf, MSG_INTL(MSG_MAP_EXPSEGNAM));
			return (FALSE);
		}

		/*
		 * Save the initial token.
		 */
		name = tkv.tkv_str;

		/*
		 * Now check the second character on the line.  The special `-'
		 * and `{' characters do not involve any segment manipulation so
		 * we handle them first.
		 */
		tok = ld_map_gettoken(mf, 0, &tkv);
		if (tok == TK_ERROR)
			return (FALSE);
		if (tok == TK_DASH) {
			if (!map_dash(mf, name))
				return (FALSE);
			continue;
		}
		if (tok == TK_LEFTBKT) {
			if (!map_version(mf, name))
				return (FALSE);
			continue;
		}

		/*
		 * If we're here we need to interpret the first string as a
		 * segment name.  Is this an already known segment?
		 */
		sgp1 = ld_seg_lookup(mf->mf_ofl, name, &where);
		new_segment = sgp1 == NULL;
		if (!new_segment)
			sgp1->sg_flags &= ~FLG_SG_DISABLED;

		/*
		 * If the second token is a '|' then we had better have found a
		 * segment.  It is illegal to perform section within segment
		 * ordering before the segment has been declared.
		 */
		if (tok == TK_PIPE) {
			if (sgp1 == NULL) {
				mf_fatal(mf, MSG_INTL(MSG_MAP_SECINSEG),
				    name);
				return (FALSE);
			}
			if (!map_pipe(mf, sgp1))
				return (FALSE);
			continue;
		}

		/*
		 * If segment does not exist, allocate a descriptor with
		 * its values set to 0 so that map_equal() can detect
		 * changing attributes.
		 */
		if (new_segment &&
		    ((sgp1 = ld_map_seg_alloc(name, PT_NULL, 0)) == NULL))
			return (FALSE);

		/*
		 * Now check the second token from the input line.
		 */
		switch (tok) {
		case TK_EQUAL:		/* Create/modify segment */
			/*
			 * We use the same syntax for hardware/software
			 * capabilities as we do for segments. If the
			 * "segment name" matches one of these, then
			 * process the capabilities instead of treating it
			 * as a segment. Note that no dynamic memory has
			 * been allocated for the segment descriptor yet,
			 * so we can bail without leaking memory.
			 */
			if (strcmp(sgp1->sg_name,
			    MSG_ORIG(MSG_STR_HWCAP_1)) == 0) {
				if (!map_cap(mf, CA_SUNW_HW_1,
				    &ofl->ofl_ocapset.oc_hw_1))
					return (FALSE);
				continue;
			}
			if (strcmp(sgp1->sg_name,
			    MSG_ORIG(MSG_STR_SFCAP_1)) == 0) {
				if (!map_cap(mf, CA_SUNW_SF_1,
				    &ofl->ofl_ocapset.oc_sf_1))
					return (FALSE);
				continue;
			}

			/*
			 * If not a new segment, show the initial value
			 * before modifying it.
			 */
			if (!new_segment && DBG_ENABLED) {
				ndx = ld_map_seg_index(mf, sgp1);
				Dbg_map_seg(ofl, DBG_STATE_MOD_BEFORE,
				    ndx, sgp1, mf->mf_lineno);
			}

			/* Process the segment */
			if (!map_equal(mf, sgp1))
				return (FALSE);

			/*
			 * Special case for STACK "segments":
			 *
			 * The ability to modify the stack flags was added
			 * long after this sysv syntax was designed. It was
			 * fit into the existing syntax by treating it as a
			 * segment. However, there can only be one stack program
			 * header, while segment syntax requires user to supply
			 * a name. This is confusing, and it allows the user to
			 * attempt to create more than one stack segment. The
			 * original implementation had a test to catch this.
			 *
			 * If this is a stack segment, locate the real stack
			 * descriptor and transfer the flags to it. We then
			 * free the allocated descriptor without inserting it.
			 * The end result is that all stack segments simply
			 * alter the one stack descriptor, and the segment
			 * name is ignored.
			 */
			if (sgp1->sg_phdr.p_type == PT_SUNWSTACK) {
				Sg_desc	*stack = ld_map_seg_stack(mf);

				if (sgp1->sg_flags & FLG_SG_P_FLAGS)
					stack->sg_phdr.p_flags =
					    sgp1->sg_phdr.p_flags;

				DBG_CALL(Dbg_map_seg(ofl,
				    DBG_STATE_MOD_AFTER, ndx, sgp1,
				    mf->mf_lineno));

				free(sgp1);
				break;
			}

			/*
			 * If this is a new segment, finish its initialization
			 * and insert it into the segment list.
			 */
			if (new_segment) {
				switch (ld_map_seg_insert(mf, DBG_STATE_NEW,
				    sgp1, where)) {
				case SEG_INS_SKIP:
					continue;
				case SEG_INS_FAIL:
					return (FALSE);
				}
			} else {
				/* Not new. Show what's changed */
				DBG_CALL(Dbg_map_seg(ofl,
				    DBG_STATE_MOD_AFTER, ndx, sgp1,
				    mf->mf_lineno));
			}
			break;

		case TK_COLON:		/* Section to segment mapping */
			/*
			 * If this is a new segment, finish its initialization
			 * and insert it into the segment list.
			 *
			 * If it is not a new segment, ensure that it is
			 * not an empty segment reservation, as sections
			 * cannot be assigned to those.
			 */
			if (new_segment) {
				switch (ld_map_seg_insert(mf,
				    DBG_STATE_NEW_IMPLICIT, sgp1, where)) {
				case SEG_INS_SKIP:
					continue;
				case SEG_INS_FAIL:
					return (FALSE);
				}
			} else if (sgp1->sg_flags & FLG_SG_EMPTY) {
				mf_fatal0(mf, MSG_INTL(MSG_MAP_SEGEMPSEC));
				return (FALSE);
			}

			/*
			 * Create new entrance criteria descriptor, and
			 * process the mapping directive.
			 */
			enp = ld_map_seg_ent_add(mf, sgp1, NULL);
			if ((enp == NULL) || !map_colon(mf, enp))
				return (FALSE);
			DBG_CALL(Dbg_map_ent(ofl->ofl_lml, enp, ofl,
			    mf->mf_lineno));
			break;

		case TK_ATSIGN:		/* Section size symbol */
			/*
			 * If this is a new segment, finish its initialization
			 * and insert it into the segment list.
			 */
			if (new_segment) {
				switch (ld_map_seg_insert(mf,
				    DBG_STATE_NEW_IMPLICIT, sgp1, where)) {
				case SEG_INS_SKIP:
					continue;
				case SEG_INS_FAIL:
					return (FALSE);
				}
			}
			if (!map_atsign(mf, sgp1))
				return (FALSE);
			break;

		case TK_ERROR:
			return (FALSE);		/* Error was already issued */

		default:
			mf_fatal0(mf, MSG_INTL(MSG_MAP_EXPEQU));
			return (FALSE);
		}
	}

	return (TRUE);
}
