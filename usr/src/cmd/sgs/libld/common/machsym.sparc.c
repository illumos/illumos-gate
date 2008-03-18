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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define	ELF_TARGET_SPARC

#include	<stdio.h>
#include	<string.h>
#include	<alloca.h>
#include	<sys/types.h>
#include	<debug.h>
#include	"msg.h"
#include	"_libld.h"
#include	"machsym.sparc.h"

/*
 * Matrix of legal combinations of usage of a given register:
 *
 *	Obj1 \ Obj2      Scratch	Named
 *	Scratch          OK		NO
 *	Named            NO		*
 *
 * (*) OK if the symbols are identical, NO if they are not.  Two symbols
 * are identical if and only if one of the following is true:
 *   A. They are both global and have the same name.
 *   B. They are both local, have the same name, and are defined in the same
 *	object.  (Note that a local symbol in one object is never identical to
 *	a local symbol in another object, even if the name is the same.)
 *
 * Matrix of legal combinations of st_shndx for the same register symbol:
 *
 *	Obj1 \ Obj2      UNDEF		ABS
 *	UNDEF            OK		OK
 *	ABS              OK		NO
 *
 */
int
ld_reg_check_sparc(Sym_desc *sdp, Sym *nsym, const char *nname, Ifl_desc *ifl,
    Ofl_desc * ofl)
{
	Sym		*osym = sdp->sd_sym;
	const char	*oname = sdp->sd_name;
	Conv_inv_buf_t	inv_buf1, inv_buf2;

	/*
	 * Scratch register definitions are compatible.
	 */
	if ((osym->st_name == 0) && (nsym->st_name == 0))
		return (0);

	/*
	 * A local and a global, or another local is incompatible.
	 */
	if ((ELF_ST_BIND(osym->st_info) == STB_LOCAL) ||
	    (ELF_ST_BIND(nsym->st_info) == STB_LOCAL)) {
		if (osym->st_value == nsym->st_value) {

			eprintf(ofl->ofl_lml, ERR_FATAL,
			    MSG_INTL(MSG_SYM_INCOMPREG3),
			    conv_sym_SPARC_value(osym->st_value, 0, &inv_buf1),
			    sdp->sd_file->ifl_name, demangle(oname),
			    ifl->ifl_name, demangle(nname));
			ofl->ofl_flags |= FLG_OF_FATAL;
			return (1);
		}
		return (0);
	}

	if (osym->st_value == nsym->st_value) {
		/*
		 * A scratch register and a named register are incompatible.
		 * So are two different named registers.
		 */
		if (((osym->st_name == 0) || (nsym->st_name == 0)) ||
		    (strcmp(oname, nname) != 0)) {
			eprintf(ofl->ofl_lml, ERR_FATAL,
			    MSG_INTL(MSG_SYM_INCOMPREG1),
			    conv_sym_SPARC_value(osym->st_value, 0, &inv_buf1),
			    sdp->sd_file->ifl_name, demangle(oname),
			    ifl->ifl_name, demangle(nname));
			ofl->ofl_flags |= FLG_OF_FATAL;
			return (1);
		}

		/*
		 * A multiply initialized symbol is also illegal.
		 */
		if ((osym->st_shndx == SHN_ABS) &&
		    (nsym->st_shndx == SHN_ABS)) {
			eprintf(ofl->ofl_lml, ERR_FATAL,
			    MSG_INTL(MSG_SYM_MULTINIREG),
			    conv_sym_SPARC_value(osym->st_value, 0, &inv_buf1),
			    demangle(nname), sdp->sd_file->ifl_name,
			    ifl->ifl_name);
			ofl->ofl_flags |= FLG_OF_FATAL;
			return (1);
		}

	} else if (strcmp(oname, nname) == 0) {
		eprintf(ofl->ofl_lml, ERR_FATAL, MSG_INTL(MSG_SYM_INCOMPREG2),
		    demangle(sdp->sd_name), sdp->sd_file->ifl_name,
		    conv_sym_SPARC_value(osym->st_value, 0, &inv_buf1),
		    ifl->ifl_name,
		    conv_sym_SPARC_value(nsym->st_value, 0, &inv_buf2));
		ofl->ofl_flags |= FLG_OF_FATAL;
		return (1);
	}
	return (0);
}

int
ld_mach_sym_typecheck_sparc(Sym_desc *sdp, Sym *nsym, Ifl_desc *ifl,
    Ofl_desc *ofl)
{
	Conv_inv_buf_t	inv_buf1, inv_buf2;
	Sym		*osym = sdp->sd_sym;
	Byte		otype = ELF_ST_TYPE(osym->st_info);
	Byte		ntype = ELF_ST_TYPE(nsym->st_info);

	if (otype != ntype) {
		if ((otype == STT_SPARC_REGISTER) ||
		    (ntype == STT_SPARC_REGISTER)) {
			eprintf(ofl->ofl_lml, ERR_FATAL,
			    MSG_INTL(MSG_SYM_DIFFTYPE), demangle(sdp->sd_name));
			eprintf(ofl->ofl_lml, ERR_NONE,
			    MSG_INTL(MSG_SYM_FILETYPES),
			    sdp->sd_file->ifl_name, conv_sym_info_type(
			    sdp->sd_file->ifl_ehdr->e_machine, otype,
			    0, &inv_buf1), ifl->ifl_name,
			    conv_sym_info_type(ifl->ifl_ehdr->e_machine,
			    ntype, 0, &inv_buf2));
			ofl->ofl_flags |= FLG_OF_FATAL;
			return (1);
		}
	} else if (otype == STT_SPARC_REGISTER)
		return (ld_reg_check_sparc(sdp, nsym, sdp->sd_name, ifl, ofl));

	return (0);
}

static const char *registers[] = { 0,
	MSG_ORIG(MSG_STO_REGISTERG1),	MSG_ORIG(MSG_STO_REGISTERG2),
	MSG_ORIG(MSG_STO_REGISTERG3),	MSG_ORIG(MSG_STO_REGISTERG4),
	MSG_ORIG(MSG_STO_REGISTERG5),	MSG_ORIG(MSG_STO_REGISTERG6),
	MSG_ORIG(MSG_STO_REGISTERG7)
};

const char *
ld_is_regsym_sparc(Ofl_desc *ofl, Ifl_desc *ifl, Sym *sym, const char *strs,
    int symndx, Word shndx, const char *symsecname, Word * flags)
{
	const char	*name;

	/*
	 * Only do something if this is a register symbol.
	 */
	if (ELF_ST_TYPE(sym->st_info) != STT_SPARC_REGISTER)
		return (0);

	/*
	 * Check for bogus register number.
	 */
	if ((sym->st_value < STO_SPARC_REGISTER_G1) ||
	    (sym->st_value > STO_SPARC_REGISTER_G7)) {
		eprintf(ofl->ofl_lml, ERR_FATAL, MSG_INTL(MSG_SYM_BADREG),
		    ifl->ifl_name, symsecname, symndx, EC_XWORD(sym->st_value));
		return ((const char *)S_ERROR);
	}

	/*
	 * A register symbol can only be undefined or defined (absolute).
	 */
	if ((shndx != SHN_ABS) && (shndx != SHN_UNDEF)) {
		eprintf(ofl->ofl_lml, ERR_FATAL, MSG_INTL(MSG_SYM_BADREG),
		    ifl->ifl_name, symsecname, symndx, EC_XWORD(sym->st_value));
		return ((const char *)S_ERROR);
	}

	/*
	 * Determine whether this is a scratch (unnamed) definition.
	 */
	if (sym->st_name == 0) {
		/*
		 * Check for bogus scratch register definitions.
		 */
		if ((ELF_ST_BIND(sym->st_info) != STB_GLOBAL) ||
		    (shndx != SHN_UNDEF)) {
			Conv_inv_buf_t inv_buf;

			eprintf(ofl->ofl_lml, ERR_FATAL,
			    MSG_INTL(MSG_SYM_BADSCRATCH),
			    ifl->ifl_name, symsecname, symndx,
			    conv_sym_SPARC_value(sym->st_value, 0, &inv_buf));
			return ((const char *)S_ERROR);
		}

		/*
		 * Fabricate a name for this register so that this definition
		 * can be processed through the symbol resolution engine.
		 */
		name = registers[sym->st_value];
	} else
		name = strs + sym->st_name;

	/*
	 * Indicate we're dealing with a register and return its name.
	 */
	*flags |= FLG_SY_REGSYM;
	return (name);
}

Sym_desc *
ld_reg_find_sparc(Sym * sym, Ofl_desc * ofl)
{
	if (ofl->ofl_regsyms == 0)
		return (0);

	return (ofl->ofl_regsyms[sym->st_value]);
}

int
ld_reg_enter_sparc(Sym_desc * sdp, Ofl_desc * ofl)
{
	if (ofl->ofl_regsyms == 0) {
		ofl->ofl_regsymsno = STO_SPARC_REGISTER_G7 + 1;
		if ((ofl->ofl_regsyms = libld_calloc(sizeof (Sym_desc *),
		    ofl->ofl_regsymsno)) == 0) {
			ofl->ofl_flags |= FLG_OF_FATAL;
			return (0);
		}
	}

	ofl->ofl_regsyms[sdp->sd_sym->st_value] = sdp;
	return (1);
}
