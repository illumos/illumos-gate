/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 *	Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"   /* SVR4 6.2/18.2 */

/*
 * Symbol table resolution
 */
#include	<stdio.h>
#include	"debug.h"
#include	"msg.h"
#include	"_libld.h"


/*
 * Categorize the symbol types that are applicable to the resolution process.
 */
typedef	enum {
	SYM_DEFINED,		/* Defined symbol (SHN_ABS or shndx != 0) */
	SYM_UNDEFINED,		/* Undefined symbol (SHN_UNDEF) */
	SYM_TENTATIVE,		/* Tentative symbol (SHN_COMMON) */
	SYM_NUM			/* the number of symbol types */
} Symtype;

/*
 * Do nothing.
 */
/* ARGSUSED0 */
static void
sym_null(Sym_desc *sdp, Sym *nsym, Ifl_desc *ifl, Ofl_desc *ofl,
	int ndx, Word nshndx, Word nsymflags)
{
}

/*
 * Check if two symbols types are compatible
 */
/*ARGSUSED4*/
static void
sym_typecheck(Sym_desc *sdp, Sym *nsym, Ifl_desc *ifl, Ofl_desc *ofl,
	int ndx, Word nshndx, Word nsymflags)
{
	unsigned char	otype = ELF_ST_TYPE(sdp->sd_sym->st_info);
	unsigned char	ntype = ELF_ST_TYPE(nsym->st_info);

	/*
	 * Perform any machine specific type checking.
	 */
	if (mach_sym_typecheck(sdp, nsym, ifl, ofl))
		return;

	/*
	 * STV_VISIBILITY rules say that you must take the most restrictive
	 * value for a symbols reference.  If we see a reference from two
	 * objects, even if a symbol isn't promoted/overridden, make sure that
	 * the more restrictive visibility is saved.
	 */
	if (ifl->ifl_ehdr->e_type == ET_REL) {
		Sym *	osym = sdp->sd_sym;
		Half	ovis = ELF_ST_VISIBILITY(osym->st_other);
		Half	nvis = ELF_ST_VISIBILITY(nsym->st_other);

		if ((nvis > STV_DEFAULT) &&
		    ((ovis == STV_DEFAULT) || (nvis < ovis))) {
			osym->st_other =
				(osym->st_other & ~MSK_SYM_VISIBILITY) | nvis;
		}
	}

	/*
	 * NOTYPE's can be combind with other types, only give an error if
	 * combining two differing types without NOTYPE
	 */
	if ((otype == ntype) || (otype == STT_NOTYPE) || (ntype == STT_NOTYPE))
		return;

	eprintf(ERR_WARNING, MSG_INTL(MSG_SYM_DIFFTYPE),
	    demangle(sdp->sd_name));
	eprintf(ERR_NONE, MSG_INTL(MSG_SYM_FILETYPES), sdp->sd_file->ifl_name,
	    conv_info_type_str(ofl->ofl_e_machine, otype), ifl->ifl_name,
	    conv_info_type_str(ofl->ofl_e_machine, ntype));
}

/*ARGSUSED4*/
static void
sym_mach_check(Sym_desc *sdp, Sym *nsym, Ifl_desc *ifl, Ofl_desc *ofl,
	int ndx, Word nshndx, Word nsymflags)
{
	/*
	 * Perform any machine specific type checking.
	 */
	(void) mach_sym_typecheck(sdp, nsym, ifl, ofl);
}

/*
 * Promote the symbols reference.
 */
static void
/* ARGSUSED4 */
sym_promote(Sym_desc *sdp, Sym *nsym, Ifl_desc *ifl, Ofl_desc *ofl,
	int ndx, Word nshndx, Word nsymflags)
{
	sym_typecheck(sdp, nsym, ifl, ofl, ndx, nshndx, nsymflags);

	/*
	 * If the old symbol is from a shared object and the new symbol is a
	 * reference from a relocatable object, promote the old symbols
	 * reference.
	 */
	if ((sdp->sd_ref == REF_DYN_SEEN) &&
	    (ifl->ifl_ehdr->e_type == ET_REL)) {
		sdp->sd_ref = REF_DYN_NEED;

		/*
		 * If this is an undefined symbol it must be a relocatable
		 * object overriding a shared object.  In this case also
		 * override the reference name so that any undefined symbol
		 * diagnostics will refer to the relocatable object name.
		 */
		if (nshndx == SHN_UNDEF)
			sdp->sd_aux->sa_rfile = ifl->ifl_name;

		/*
		 * If this symbol is an undefined, or common, determine whether
		 * it is a global or weak reference (see build_osym(), where
		 * REF_DYN_NEED definitions are returned back to undefines).
		 */
		if (((nshndx == SHN_UNDEF) ||
		    ((nsymflags & FLG_SY_SPECSEC) &&
		    (nshndx == SHN_COMMON))) &&
		    (ELF_ST_BIND(nsym->st_info) == STB_GLOBAL))
			sdp->sd_flags |= FLG_SY_GLOBREF;

	} else if ((nshndx != SHN_UNDEF) &&
	    (ofl->ofl_dtflags_1 & DF_1_TRANS) &&
	    !sdp->sd_aux->sa_bindto && (sdp->sd_ref == REF_REL_NEED) &&
	    (ifl->ifl_ehdr->e_type == ET_DYN)) {
		/*
		 * If building a translator then record the symbol
		 * we would 'bindto' with direct bindings.
		 */
		sdp->sd_aux->sa_bindto = ifl;
	}
}

/*
 * Override a symbol.
 */
static void
sym_override(Sym_desc *sdp, Sym *nsym, Ifl_desc *ifl, Ofl_desc *ofl,
	int ndx, Word nshndx, Word nsymflags)
{
	Sym		*osym = sdp->sd_sym;
	Half		ovis = ELF_ST_VISIBILITY(osym->st_other);
	Half		nvis = ELF_ST_VISIBILITY(nsym->st_other);
	Word		link;

	/*
	 * In the case of a WEAK UNDEF symbol don't let a symbol from an
	 * unavailable object override the symbol definition.  This is because
	 * this symbol *may* not be present in a future object and by promoting
	 * this symbol we are actually causing bindings (PLTS) to be formed
	 * to this symbol.  Instead let the 'generic' weak binding take place.
	 */
	if ((ELF_ST_BIND(osym->st_info) == STB_WEAK) &&
	    (sdp->sd_shndx == SHN_UNDEF) && !(ifl->ifl_flags & FLG_IF_NEEDED))
		return;

	sym_typecheck(sdp, nsym, ifl, ofl, ndx, nshndx, nsymflags);

	/*
	 * This symbol has already been compared to an SO definition,
	 * as per the runtime behavior, ignore extra definitions.
	 */
	if ((sdp->sd_flags & FLG_SY_SOFOUND) &&
	    (ifl->ifl_ehdr->e_type == ET_DYN))
		return;

	/*
	 * Mark the symbol as available and copy the new symbols contents.
	 */
	sdp->sd_flags &= ~FLG_SY_NOTAVAIL;
	*osym = *nsym;
	sdp->sd_shndx = nshndx;
	sdp->sd_flags &= ~FLG_SY_SPECSEC;
	sdp->sd_flags |= (nsymflags & (FLG_SY_SPECSEC | FLG_SY_TENTSYM));

	/*
	 * If the new symbol has PROTECTED visibility, mark it.  If a PROTECTED
	 * symbol is copy relocated, a warning message will be printed. See
	 * reloc_exec().
	 */
	if (ELF_ST_VISIBILITY(nsym->st_other) == STV_PROTECTED)
		sdp->sd_flags |= FLG_SY_PROT;
	else
		sdp->sd_flags &= ~FLG_SY_PROT;

	/*
	 * Establish the symbols reference.  If the new symbol originates from a
	 * relocatable object then this reference becomes needed, otherwise
	 * the new symbol must be from a shared object.  In this case only
	 * promote the symbol to needed if we presently have a reference from a
	 * relocatable object.
	 */
	if (ifl->ifl_ehdr->e_type == ET_REL) {
		/*
		 * Maintain the more restrictive visiblity
		 */
		if ((ovis > STV_DEFAULT) &&
		    ((nvis == STV_DEFAULT) || (ovis < nvis))) {
			osym->st_other =
				(osym->st_other & ~MSK_SYM_VISIBILITY) | ovis;
		}
		sdp->sd_ref = REF_REL_NEED;

		if (nshndx == SHN_UNDEF) {
			/*
			 * If this is an undefined symbol it must be a
			 * relocatable object overriding a shared object.  In
			 * this case also override the reference name so that
			 * any undefined symbol diagnostics will refer to the
			 * relocatable object name.
			 */
			sdp->sd_aux->sa_rfile = ifl->ifl_name;
		} else {
			/*
			 * Under -Bnodirect, all exported interfaces are tagged
			 * to prevent direct binding to them.
			 */
			if ((ofl->ofl_flags1 & FLG_OF1_ALNODIR) &&
			    ((sdp->sd_flags1 & FLG_SY1_DIR) == 0))
				sdp->sd_flags1 |= FLG_SY1_NDIR;
		}

		/*
		 * If this symbol is an undefined, or common, determine whether
		 * it is a global or weak reference (see build_osym(), where
		 * REF_DYN_NEED definitions are returned back to undefines).
		 */
		if (((nshndx == SHN_UNDEF) ||
		    ((nsymflags & FLG_SY_SPECSEC) && (nshndx == SHN_COMMON))) &&
		    (ELF_ST_BIND(nsym->st_info) == STB_GLOBAL))
			sdp->sd_flags |= FLG_SY_GLOBREF;
		else
			sdp->sd_flags &= ~FLG_SY_GLOBREF;
	} else {
		if (sdp->sd_ref == REF_REL_NEED)
			sdp->sd_ref = REF_DYN_NEED;

		/*
		 * Visibility from a DYN symbol does not override
		 * previous symbol visibility.
		 */
		osym->st_other = (osym->st_other & ~MSK_SYM_VISIBILITY) |
			ovis;

		/*
		 * Determine the symbols availability.  A symbol is determined
		 * to be unavailable if it belongs to a version of a shared
		 * object that this user does not wish to use, or if it belongs
		 * to an implicit shared object.
		 */
		if (ifl->ifl_vercnt) {
			Ver_index *	vip;
			Half		vndx = ifl->ifl_versym[ndx];

			sdp->sd_aux->sa_dverndx = vndx;
			vip = &ifl->ifl_verndx[vndx];
			if (!(vip->vi_flags & FLG_VER_AVAIL)) {
				sdp->sd_flags |= FLG_SY_NOTAVAIL;
				/*
				 * If this is the first occurance of an
				 * unavailable symbol record it for possible
				 * use in later error diagnostics
				 * (see sym_undef).
				 */
				if (!(sdp->sd_aux->sa_vfile))
					sdp->sd_aux->sa_vfile = ifl->ifl_name;
			}
		}
		if (!(ifl->ifl_flags & FLG_IF_NEEDED))
			sdp->sd_flags |= FLG_SY_NOTAVAIL;
	}

	/*
	 * Make sure any symbol association maintained by the original symbol
	 * is cleared and then update the symbols file reference.
	 */
	if ((link = sdp->sd_aux->sa_linkndx) != 0) {
		Sym_desc *	_sdp;

		_sdp = sdp->sd_file->ifl_oldndx[link];
		_sdp->sd_aux->sa_linkndx = 0;
		sdp->sd_aux->sa_linkndx = 0;
	}
	sdp->sd_file = ifl;

	/*
	 * Update the input section descriptor to that of the new input file
	 */
	if (((nsymflags & FLG_SY_SPECSEC) == 0) && (nshndx != SHN_UNDEF))
		if ((sdp->sd_isc = ifl->ifl_isdesc[nshndx]) == 0) {
			eprintf(ERR_FATAL, MSG_INTL(MSG_SYM_NOSECDEF),
			    demangle(sdp->sd_name), ifl->ifl_name);
			ofl->ofl_flags |= FLG_OF_FATAL;
		}
}


/*
 * Resolve two undefines (only called for two relocatable objects).
 */
static void
sym_twoundefs(Sym_desc *sdp, Sym *nsym, Ifl_desc *ifl, Ofl_desc *ofl,
	int ndx, Word nshndx, Word nsymflags)
{
	Sym		*osym = sdp->sd_sym;
	unsigned char	obind = ELF_ST_BIND(osym->st_info);
	unsigned char	nbind = ELF_ST_BIND(nsym->st_info);

	/*
	 * If two relocatable objects define a weak and non-weak undefined
	 * reference, take the non-weak definition.
	 *
	 *		-- or --
	 *
	 * If two relocatable objects define a NOTYPE & another, then
	 * take the other.
	 */
	if (((obind == STB_WEAK) && (nbind != STB_WEAK)) ||
	    (obind == STT_NOTYPE) && (nbind != STT_NOTYPE)) {
		sym_override(sdp, nsym, ifl, ofl, ndx, nshndx, nsymflags);
		return;
	}
	sym_typecheck(sdp, nsym, ifl, ofl, ndx, nshndx, nsymflags);
}

/*
 * Resolve two real definitions.
 */
static void
sym_tworeals(Sym_desc *sdp, Sym *nsym, Ifl_desc *ifl, Ofl_desc *ofl,
	int ndx, Word nshndx, Word nsymflags)
{
	Sym		*osym = sdp->sd_sym;
	unsigned char   otype = ELF_ST_TYPE(osym->st_info);
	unsigned char   obind = ELF_ST_BIND(osym->st_info);
	unsigned char   ntype = ELF_ST_TYPE(nsym->st_info);
	unsigned char   nbind = ELF_ST_BIND(nsym->st_info);
	Half		ofile = sdp->sd_file->ifl_ehdr->e_type;
	Half		nfile = ifl->ifl_ehdr->e_type;
	int		warn = 0;

	/*
	 * If both definitions are from relocatable objects, and have non-weak
	 * binding then this is a fatal condition.
	 */
	if ((ofile == ET_REL) && (nfile == ET_REL) && (obind != STB_WEAK) &&
	    (nbind != STB_WEAK) && (!(ofl->ofl_flags & FLG_OF_MULDEFS))) {
		eprintf(ERR_FATAL, MSG_INTL(MSG_SYM_MULDEF),
		    demangle(sdp->sd_name));
		eprintf(ERR_NONE, MSG_INTL(MSG_SYM_FILETYPES),
		    sdp->sd_file->ifl_name,
		    conv_info_type_str(ofl->ofl_e_machine, otype),
		    ifl->ifl_name,
		    conv_info_type_str(ofl->ofl_e_machine, ntype));
		ofl->ofl_flags |= FLG_OF_FATAL;
		return;
	}

	/*
	 * Perform any machine specific type checking.
	 */
	if (mach_sym_typecheck(sdp, nsym, ifl, ofl))
		return;

	/*
	 * Check the symbols type and size.
	 */
	if (otype != ntype) {
		eprintf(ERR_WARNING, MSG_INTL(MSG_SYM_DIFFTYPE),
		    demangle(sdp->sd_name));
		eprintf(ERR_NONE, MSG_INTL(MSG_SYM_FILETYPES),
		    sdp->sd_file->ifl_name,
		    conv_info_type_str(ofl->ofl_e_machine, otype),
		    ifl->ifl_name, conv_info_type_str(ofl->ofl_e_machine,
		    ntype));
		warn++;
	} else if ((otype == STT_OBJECT) && (osym->st_size != nsym->st_size)) {
		if (!(ofl->ofl_flags & FLG_OF_NOWARN)) {
			eprintf(ERR_WARNING, MSG_INTL(MSG_SYM_DIFFATTR),
			    demangle(sdp->sd_name), MSG_INTL(MSG_STR_SIZES),
			    sdp->sd_file->ifl_name, EC_XWORD(osym->st_size),
			    ifl->ifl_name, EC_XWORD(nsym->st_size));
			warn++;
		}
	}

	/*
	 * Having provided the user with any necessary warnings, take the
	 * appropriate symbol:
	 *
	 *  o	if one symbol is from a shared object and the other is from a
	 *	relocatable object, take the relocatable objects symbol (the
	 *	run-time linker is always going to find the relocatable object
	 *	symbol regardless of the binding), else
	 *
	 * o	if both symbols are from relocatable objects and one symbol is
	 *	weak take the non-weak symbol (two non-weak symbols would have
	 *	generated the fatal error condition above unless -z muldefs is
	 *	in effect), else
	 *
	 *  o	take the first symbol definition encountered.
	 */
	if ((sdp->sd_flags & FLG_SY_SOFOUND) && (nfile == ET_DYN)) {
		if (warn)
			eprintf(ERR_NONE, MSG_INTL(MSG_SYM_DEFTAKEN),
			    sdp->sd_file->ifl_name);
		return;
	} else if ((nfile == ET_REL) && ((ofile == ET_DYN) ||
	    ((obind == STB_WEAK) && (nbind != STB_WEAK)))) {
		if (warn)
			eprintf(ERR_NONE, MSG_INTL(MSG_SYM_DEFTAKEN),
			    ifl->ifl_name);
		sym_override(sdp, nsym, ifl, ofl, ndx, nshndx, nsymflags);
		return;
	} else {
		if (warn)
			eprintf(ERR_NONE, MSG_INTL(MSG_SYM_DEFTAKEN),
			    sdp->sd_file->ifl_name);
		sym_promote(sdp, nsym, ifl, ofl, ndx, nshndx, nsymflags);
		return;
	}
}

/*
 * Resolve a real and tentative definition.
 */
static void
sym_realtent(Sym_desc *sdp, Sym *nsym, Ifl_desc *ifl, Ofl_desc *ofl,
	int ndx, Word nshndx, Word nsymflags)
{
	Sym		*osym = sdp->sd_sym;
	unsigned char	otype = ELF_ST_TYPE(osym->st_info);
	unsigned char   obind = ELF_ST_BIND(osym->st_info);
	unsigned char	ntype = ELF_ST_TYPE(nsym->st_info);
	unsigned char   nbind = ELF_ST_BIND(nsym->st_info);
	Boolean		otent = FALSE, ntent = FALSE;
	Half		ofile = sdp->sd_file->ifl_ehdr->e_type;
	Half		nfile = ifl->ifl_ehdr->e_type;
	int		warn = 0;
	Word		osymvis = ELF_ST_VISIBILITY(osym->st_other);
	Word		nsymvis = ELF_ST_VISIBILITY(nsym->st_other);

	/*
	 * Special rules for functions.
	 *
	 *  o	If both definitions are from relocatable objects, have the same
	 *	binding (ie. two weaks or two non-weaks), and the real
	 *	definition is a function (the other must be tentative), treat
	 *	this as a multiply defined symbol error, else
	 *
	 *  o	if the real symbol definition is a function within a shared
	 *	library and the tentative symbol is a relocatable object, and
	 *	the tentative is not weak and the function real, then retain the
	 *	tentative definition.
	 */
	if ((ofile == ET_REL) && (nfile == ET_REL) && (obind == nbind) &&
	    ((otype == STT_FUNC) || (ntype == STT_FUNC))) {
		if (ofl->ofl_flags & FLG_OF_MULDEFS) {
			eprintf(ERR_WARNING, MSG_INTL(MSG_SYM_DIFFTYPE),
			    demangle(sdp->sd_name));
			sym_promote(sdp, nsym, ifl, ofl, ndx,
				nshndx, nsymflags);
		} else {
			eprintf(ERR_FATAL, MSG_INTL(MSG_SYM_MULDEF),
			    demangle(sdp->sd_name));
			ofl->ofl_flags |= FLG_OF_FATAL;
		}
		eprintf(ERR_NONE, MSG_INTL(MSG_SYM_FILETYPES),
		    sdp->sd_file->ifl_name,
		    conv_info_type_str(ofl->ofl_e_machine, otype),
		    ifl->ifl_name, conv_info_type_str(ofl->ofl_e_machine,
		    ntype));
		return;
	} else if (ofile != nfile) {


		if ((ofile == ET_DYN) && (otype == STT_FUNC)) {
			if ((otype != STB_WEAK) && (ntype == STB_WEAK))
				return;
			else {
				sym_override(sdp, nsym, ifl, ofl, ndx,
					nshndx, nsymflags);
				return;
			}
		}
		if ((nfile == ET_DYN) && (ntype == STT_FUNC)) {
			if ((ntype != STB_WEAK) && (otype == STB_WEAK)) {
				sym_override(sdp, nsym, ifl, ofl, ndx,
					nshndx, nsymflags);
				return;
			} else
				return;
		}
	}

	if (sdp->sd_flags & FLG_SY_TENTSYM)
		otent = TRUE;
	if (nsymflags & FLG_SY_TENTSYM)
		ntent = TRUE;


	/*
	 * Check the symbols type and size.
	 */
	if (otype != ntype) {
		eprintf(ERR_WARNING, MSG_INTL(MSG_SYM_DIFFTYPE),
		    demangle(sdp->sd_name));
		eprintf(ERR_NONE, MSG_INTL(MSG_SYM_FILETYPES),
		    sdp->sd_file->ifl_name,
		    conv_info_type_str(ofl->ofl_e_machine, otype),
		    ifl->ifl_name, conv_info_type_str(ofl->ofl_e_machine,
		    ntype));
		warn++;
	} else if (osym->st_size != nsym->st_size) {
		/*
		 * If both definitions are from relocatable objects we have a
		 * potential fatal error condition.  If the tentative is larger
		 * than the real definition treat this as a multiple definition.
		 * Note that if only one symbol is weak, the non-weak will be
		 * taken.
		 */
		if (((ofile == ET_REL) && (nfile == ET_REL) &&
		    (obind == nbind)) &&
		    ((otent && (osym->st_size > nsym->st_size)) ||
		    (ntent && (osym->st_size < nsym->st_size)))) {
			eprintf(ERR_FATAL, MSG_INTL(MSG_SYM_DIFFATTR),
			    demangle(sdp->sd_name), MSG_INTL(MSG_STR_SIZES),
			    sdp->sd_file->ifl_name, EC_XWORD(osym->st_size),
			    ifl->ifl_name, EC_XWORD(nsym->st_size));
			eprintf(ERR_NONE, MSG_INTL(MSG_SYM_TENTERR));
			ofl->ofl_flags |= FLG_OF_FATAL;
		} else {
			if (!(ofl->ofl_flags & FLG_OF_NOWARN)) {
				eprintf(ERR_WARNING, MSG_INTL(MSG_SYM_DIFFATTR),
				    demangle(sdp->sd_name),
				    MSG_INTL(MSG_STR_SIZES),
				    sdp->sd_file->ifl_name,
				    EC_XWORD(osym->st_size),
				    ifl->ifl_name, EC_XWORD(nsym->st_size));
				warn++;
			}
		}
	}

	/*
	 * Having provided the user with any necessary warnings, take the
	 * appropriate symbol:
	 *
	 *  o   if the original symbol is from relocatable file and it is
	 *	a protected tentative symbol, take the original one.
	 *
	 *  o 	if the original symbol is from shared object and the new
	 *	symbol is a protected tentative symbol from a relocatable file,
	 *	take the new one.
	 *
	 *  o	if the original symbol is tentative, and providing the original
	 *	symbol isn't strong and the new symbol weak, take the real
	 *	symbol, else
	 *
	 *  o	if the original symbol is weak and the new tentative symbol is
	 *	strong take the new symbol.
	 *
	 * Refer to the System V ABI Page 4-27 for a description of the binding
	 * requirements of tentative and weak symbols.
	 */
	if ((ofile == ET_REL) && (nfile == ET_DYN) && (otent == TRUE) &&
	    (osymvis == STV_PROTECTED)) {
		return;
	}

	if ((ofile == ET_DYN) && (nfile == ET_REL) && (ntent == TRUE) &&
	    (nsymvis == STV_PROTECTED)) {
		sym_override(sdp, nsym, ifl, ofl, ndx, nshndx, nsymflags);
		return;
	}

	if ((sdp->sd_flags & FLG_SY_SOFOUND) && (nfile == ET_DYN)) {
		if (warn)
			eprintf(ERR_NONE, MSG_INTL(MSG_SYM_DEFTAKEN),
			    sdp->sd_file->ifl_name);
		return;
	}

	if (((otent) && (!((obind != STB_WEAK) && (nbind == STB_WEAK)))) ||
	    ((obind == STB_WEAK) && (nbind != STB_WEAK))) {
		if (warn)
			eprintf(ERR_NONE, MSG_INTL(MSG_SYM_DEFTAKEN),
			    ifl->ifl_name);
		sym_override(sdp, nsym, ifl, ofl, ndx, nshndx, nsymflags);
		return;
	} else {
		if (warn)
			eprintf(ERR_NONE, MSG_INTL(MSG_SYM_DEFTAKEN),
			    sdp->sd_file->ifl_name);
		sym_promote(sdp, nsym, ifl, ofl, ndx, nshndx, nsymflags);
		return;
	}
}

/*
 * Resolve two tentative symbols.
 */
static void
sym_twotent(Sym_desc *sdp, Sym *nsym, Ifl_desc *ifl, Ofl_desc *ofl,
	int ndx, Word nshndx, Word nsymflags)
{
	Sym		*osym = sdp->sd_sym;
	unsigned char   obind = ELF_ST_BIND(osym->st_info);
	unsigned char   nbind = ELF_ST_BIND(nsym->st_info);
	Half		ofile = sdp->sd_file->ifl_ehdr->e_type;
	Half		nfile = ifl->ifl_ehdr->e_type;
	size_t		size = 0;
	Xword		value = 0;

	/*
	 * Check the alignment of the symbols.  This can only be tested for if
	 * the symbols are not real definitions to a SHT_NOBITS section (ie.
	 * they were originally tentative), as in this case the symbol would
	 * have a displacement value rather than an alignment.  In other words
	 * we can only test this for two relocatable objects.
	 */
	if ((osym->st_value != nsym->st_value) &&
	    ((sdp->sd_flags & FLG_SY_SPECSEC) &&
	    (sdp->sd_shndx == SHN_COMMON)) &&
	    ((nsymflags & FLG_SY_SPECSEC) &&
	    (nshndx == SHN_COMMON))) {
		const char	*emsg = MSG_INTL(MSG_SYM_DEFTAKEN);
		const char	*file;
		Xword		salign;
		Xword		balign;
		uint_t		alignscompliment;

		if (osym->st_value < nsym->st_value) {
			salign = osym->st_value;
			balign = nsym->st_value;
		} else {
			salign = nsym->st_value;
			balign = osym->st_value;
		}

		/*
		 * If the smaller alignment fits smoothly into the
		 * larger alignment - we take it with no warning.
		 */
		if (S_ALIGN(balign, salign) == balign)
			alignscompliment = 1;
		else
			alignscompliment = 0;

		if (!(ofl->ofl_flags & FLG_OF_NOWARN) && !alignscompliment)
			eprintf(ERR_WARNING, MSG_INTL(MSG_SYM_DIFFATTR),
			    demangle(sdp->sd_name),
			    MSG_INTL(MSG_STR_ALIGNMENTS),
			    sdp->sd_file->ifl_name, EC_XWORD(osym->st_value),
			    ifl->ifl_name, EC_XWORD(nsym->st_value));

		/*
		 * Having provided the necessary warning indicate which
		 * relocatable object we are going to take.
		 *
		 *  o	if one symbol is weak and the other is non-weak
		 *	take the non-weak symbol, else
		 *
		 *  o	take the largest alignment (as we still have to check
		 *	the symbols size simply save the largest value for
		 *	updating later).
		 */
		if ((obind == STB_WEAK) && (nbind != STB_WEAK))
			file = ifl->ifl_name;
		else if (obind != nbind)
			file = sdp->sd_file->ifl_name;
		else {
			emsg = MSG_INTL(MSG_SYM_LARGER);
			value = balign;
		}
		if (!(ofl->ofl_flags & FLG_OF_NOWARN) && !alignscompliment)
			eprintf(ERR_NONE, emsg, file);
	}

	/*
	 * Check the size of the symbols.
	 */
	if (osym->st_size != nsym->st_size) {
		const char	*emsg = MSG_INTL(MSG_SYM_DEFTAKEN);
		const char	*file;

		if (!(ofl->ofl_flags & FLG_OF_NOWARN))
			eprintf(ERR_WARNING, MSG_INTL(MSG_SYM_DIFFATTR),
			    demangle(sdp->sd_name), MSG_INTL(MSG_STR_SIZES),
			    sdp->sd_file->ifl_name, EC_XWORD(osym->st_size),
			    ifl->ifl_name, EC_XWORD(nsym->st_size));


		/*
		 * This symbol has already been compared to an SO definition,
		 * as per the runtime behavior, ignore extra definitions.
		 */
		if ((sdp->sd_flags & FLG_SY_SOFOUND) && (nfile == ET_DYN)) {
			if (!(ofl->ofl_flags & FLG_OF_NOWARN))
				eprintf(ERR_NONE, emsg,
				    sdp->sd_file->ifl_name);
			return;
		}

		/*
		 * Having provided the necessary warning indicate what course
		 * of action we are going to take.
		 *
		 *  o	if the file types differ, take the relocatable object
		 *	and apply the largest symbol size, else
		 *  o	if one symbol is weak and the other is non-weak, take
		 *	the non-weak symbol, else
		 *  o	simply take the largest symbol reference.
		 */
		if (nfile != ofile) {
			if (nfile == ET_REL) {
				file = ifl->ifl_name;
				if (osym->st_size > nsym->st_size) {
					size = (size_t)osym->st_size;
					emsg = MSG_INTL(MSG_SYM_DEFUPDATE);
				}
				sym_override(sdp, nsym, ifl, ofl, ndx,
				    nshndx, nsymflags);
			} else {
				file = sdp->sd_file->ifl_name;
				if (osym->st_size < nsym->st_size) {
					size = (size_t)nsym->st_size;
					emsg = MSG_INTL(MSG_SYM_DEFUPDATE);
				}
				sym_promote(sdp, nsym, ifl, ofl, ndx,
					nshndx, nsymflags);
			}
		} else if (obind != nbind) {
			if ((obind == STB_WEAK) && (nbind != STB_WEAK)) {
				sym_override(sdp, nsym, ifl, ofl, ndx,
					nshndx, nsymflags);
				file = ifl->ifl_name;
			} else
				file = sdp->sd_file->ifl_name;
		} else {
			if (osym->st_size < nsym->st_size) {
				sym_override(sdp, nsym, ifl, ofl, ndx,
					nshndx, nsymflags);
				file = ifl->ifl_name;
			} else
				file = sdp->sd_file->ifl_name;
		}
		if (!(ofl->ofl_flags & FLG_OF_NOWARN))
			eprintf(ERR_NONE, emsg, file);
		if (size)
			sdp->sd_sym->st_size = (Xword)size;
	} else {
		/*
		 * If the sizes are the same
		 *
		 *  o	if the file types differ, take the relocatable object,
		 *	else
		 *
		 *  o	if one symbol is weak and the other is non-weak, take
		 *	the non-weak symbol, else
		 *
		 *  o	take the first reference.
		 */
		if ((sdp->sd_flags & FLG_SY_SOFOUND) && (nfile == ET_DYN))
			return;
		else if (((ofile != nfile) && (nfile == ET_REL)) ||
		    (((obind == STB_WEAK) && (nbind != STB_WEAK)) &&
		    (!((ofile != nfile) && (ofile == ET_REL)))))
			sym_override(sdp, nsym, ifl, ofl, ndx,
				nshndx, nsymflags);
		else
			sym_promote(sdp, nsym, ifl, ofl, ndx,
				nshndx, nsymflags);
	}

	/*
	 * Enforce the largest alignment if necessary.
	 */
	if (value)
		sdp->sd_sym->st_value = value;
}

/*
 * Symbol resolution state table.  `Action' describes the required
 * procedure to be called (if any).
 */
static void (*Action[REF_NUM * SYM_NUM * 2][SYM_NUM])(Sym_desc *,
	Sym *, Ifl_desc *, Ofl_desc *, int, Word, Word) = {

/*				defined		undef		tent	*/
/*				ET_REL		ET_REL		ET_REL	*/

/*  0 defined REF_DYN_SEEN */	sym_tworeals,	sym_promote,	sym_realtent,
/*  1   undef REF_DYN_SEEN */	sym_override,	sym_override,	sym_override,
/*  2    tent REF_DYN_SEEN */	sym_realtent,	sym_promote,	sym_twotent,
/*  3 defined REF_DYN_NEED */	sym_tworeals,	sym_typecheck,	sym_realtent,
/*  4   undef REF_DYN_NEED */	sym_override,	sym_override,	sym_override,
/*  5    tent REF_DYN_NEED */	sym_realtent,	sym_typecheck,	sym_twotent,
/*  6 defined REF_REL_NEED */	sym_tworeals,	sym_typecheck,	sym_realtent,
/*  7   undef REF_REL_NEED */	sym_override,	sym_twoundefs,	sym_override,
/*  8    tent REF_REL_NEED */	sym_realtent,	sym_null,	sym_twotent,

/*				defined		undef		tent	*/
/*				ET_DYN		ET_DYN		ET_DYN	*/

/*  9 defined REF_DYN_SEEN */	sym_tworeals,	sym_null,	sym_realtent,
/* 10   undef REF_DYN_SEEN */	sym_override,	sym_mach_check,	sym_override,
/* 11    tent REF_DYN_SEEN */	sym_realtent,	sym_null,	sym_twotent,
/* 12 defined REF_DYN_NEED */	sym_tworeals,	sym_null,	sym_realtent,
/* 13   undef REF_DYN_NEED */	sym_override,	sym_null,	sym_override,
/* 14    tent REF_DYN_NEED */	sym_realtent,	sym_null,	sym_twotent,
/* 15 defined REF_REL_NEED */	sym_tworeals,	sym_null,	sym_realtent,
/* 16   undef REF_REL_NEED */	sym_override,	sym_mach_check,	sym_override,
/* 17    tent REF_REL_NEED */	sym_realtent,	sym_null,	sym_twotent

};

uintptr_t
sym_resolve(Sym_desc *sdp, Sym *nsym, Ifl_desc *ifl, Ofl_desc *ofl, int ndx,
	Word nshndx, Word nsymflags)
{
	int		row, column;		/* State table coordinates */
	Sym		*osym = sdp->sd_sym;
	Is_desc		*isp;
	Half		nfile = ifl->ifl_ehdr->e_type;

	/*
	 * Determine the original symbols definition (defines row in Action[]).
	 */
	if (sdp->sd_flags & FLG_SY_TENTSYM)
		row = SYM_TENTATIVE;
	else if (sdp->sd_shndx == SHN_UNDEF)
		row = SYM_UNDEFINED;
	else
		row = SYM_DEFINED;

	/*
	 * If the input file is an implicit shared object then we don't need
	 * to bind to any symbols within it other than to verify that any
	 * undefined references will be closed (implicit shared objects are only
	 * processed when no undefined symbols are required as a result of the
	 * link-edit (see process_dynamic())).
	 */
	if ((nfile == ET_DYN) && !(ifl->ifl_flags & FLG_IF_NEEDED) &&
	    (row != SYM_UNDEFINED))
		return (1);

	/*
	 * Finish computing the Action[] row by applying the symbols reference
	 * together with the input files type.
	 */
	row = row + (REF_NUM * sdp->sd_ref);
	if (nfile == ET_DYN)
		row += (REF_NUM * SYM_NUM);

	/*
	 * Determine the new symbols definition (defines column in Action[]).
	 */
	if ((nsymflags & FLG_SY_SPECSEC) &&
	    (nshndx == SHN_COMMON)) {
		column = SYM_TENTATIVE;
		nsymflags |= FLG_SY_TENTSYM;
	} else if ((nshndx == SHN_UNDEF) || (nshndx == SHN_SUNW_IGNORE)) {
		column = SYM_UNDEFINED;
		nshndx = SHN_UNDEF;
	} else {
		column = SYM_DEFINED;
		/*
		 * If the new symbol is from a shared library and it is
		 * associated with a SHT_NOBITS section then this symbol
		 * originated from a tentative symbol.
		 */
		if (((nsymflags & FLG_SY_SPECSEC) == 0) && (nfile == ET_DYN)) {
			isp = ifl->ifl_isdesc[nshndx];
			if (isp && (isp->is_shdr->sh_type == SHT_NOBITS)) {
				column = SYM_TENTATIVE;
				nsymflags |= FLG_SY_TENTSYM;
			}
		}
	}

	DBG_CALL(Dbg_syms_resolving1(ndx, sdp->sd_name, row, column));
	DBG_CALL(Dbg_syms_resolving2(ifl->ifl_ehdr, osym, nsym, sdp, ifl));

	/*
	 * Record the input filename on the defined files list for possible
	 * later diagnostics.  The `sa_dfiles' list is used to maintain the list
	 * of shared objects that define the same symbol.  This list is only
	 * generated when the -m option is in effect and is used to list
	 * multiple (interposed) definitions of a symbol (refer to ldmap_out()).
	 */
	if ((ofl->ofl_flags & FLG_OF_GENMAP) && (nshndx != SHN_UNDEF) &&
	    ((nsymflags & FLG_SY_SPECSEC) == 0))
		if (list_appendc(&sdp->sd_aux->sa_dfiles, ifl->ifl_name) == 0)
			return (S_ERROR);

	/*
	 * Perform the required resolution.
	 */
	Action[row][column](sdp, nsym, ifl, ofl, ndx, nshndx, nsymflags);

	/*
	 * If the symbol has been resolved to the new input file, and this is
	 * a versioned relocatable object, then the version information of the
	 * new symbol must be promoted to the versioning of the output file.
	 */
	if ((sdp->sd_file == ifl) && (nfile == ET_REL) && (ifl->ifl_versym) &&
	    (nshndx != SHN_UNDEF))
		vers_promote(sdp, ndx, ifl, ofl);

	/*
	 * Determine whether a mapfile reference has been satisfied.  Mapfile
	 * symbol references augment symbols that should be contributed from
	 * the relocatable objects used to build the output image.  If a
	 * relocatable object doesn't provide one of the mapfile symbol
	 * references then somethings amiss, and will be flagged during symbol
	 * validation.
	 */
	if ((nfile == ET_REL) && ((sdp->sd_flags &
	    (FLG_SY_MAPREF | FLG_SY_MAPUSED)) == FLG_SY_MAPREF)) {
		/*
		 * Extern and parent references are satisfied by references from
		 * a relocatable object.  Note that we let *any* symbol type
		 * satisfy this reference, to be as flexible as possible with
		 * user written mapfiles.  It could be questionable, for
		 * example, if what a user expects to be an extern reference is
		 * actually found to be a definition in a relocatable object.
		 *
		 * Any other mapfile reference (typically for versioning
		 * information) simply augments a relocatables definition.
		 */
		if ((sdp->sd_flags & (FLG_SY_EXTERN | FLG_SY_PARENT)) ||
		    ((sdp->sd_shndx != SHN_UNDEF) &&
		    (sdp->sd_ref == REF_REL_NEED)))
			sdp->sd_flags |= FLG_SY_MAPUSED;
	}

	DBG_CALL(Dbg_syms_resolved(ifl->ifl_ehdr, sdp));

	return (1);
}
