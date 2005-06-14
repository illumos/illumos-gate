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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include	<sys/types.h>
#include	<string.h>
#include	"msg.h"
#include	"_debug.h"

void
Dbg_bind_plt_summary(Half mach, Word pltcnt21d, Word pltcnt24d, Word pltcntu32,
    Word pltcntu44, Word pltcntfull, Word pltcntfar)
{
	Word plttotal = pltcnt21d + pltcnt24d + pltcntu32 +
		pltcntu44 + pltcntfull + pltcntfar;

	if (DBG_NOTCLASS(DBG_BINDINGS))
		return;

	switch (mach) {
	case EM_SPARC:
		dbg_print(MSG_INTL(MSG_BND_PSUM_SPARC), EC_WORD(pltcnt21d),
		    EC_WORD(pltcnt24d), EC_WORD(pltcntfull), EC_WORD(plttotal));
		break;
	case EM_SPARCV9:
		dbg_print(MSG_INTL(MSG_BND_PSUM_SPARCV9), EC_WORD(pltcnt21d),
		    EC_WORD(pltcnt24d), EC_WORD(pltcntu32), EC_WORD(pltcntu44),
		    EC_WORD(pltcntfull), EC_WORD(pltcntfar), EC_WORD(plttotal));
		break;
	default:
		dbg_print(MSG_INTL(MSG_BND_PSUM_DEFAULT), EC_WORD(plttotal));
		break;
	};
}

static const char	*pltbindtypes[PLT_T_NUM] = {
	MSG_ORIG(MSG_STR_EMPTY),	/* PLT_T_NONE */
	MSG_ORIG(MSG_PLT_21D),		/* PLT_T_21D */
	MSG_ORIG(MSG_PLT_24D),		/* PLT_T_24D */
	MSG_ORIG(MSG_PLT_U32),		/* PLT_T_U32 */
	MSG_ORIG(MSG_PLT_U44),		/* PLT_T_U44 */
	MSG_ORIG(MSG_PLT_FULL),		/* PLT_T_FULL */
	MSG_ORIG(MSG_PLT_FAR)		/* PLT_T_FAR */
};

#define	BINFOSZ	MSG_BINFO_START_SIZE + \
		MSG_BINFO_DIRECT_SIZE + \
		MSG_BINFO_SEP_SIZE + \
		MSG_BINFO_COPYREF_SIZE + \
		MSG_BINFO_SEP_SIZE + \
		MSG_BINFO_FILTEE_SIZE + \
		MSG_BINFO_SEP_SIZE + \
		MSG_BINFO_PLTADDR_SIZE + \
		MSG_BINFO_END_SIZE + 1

/*
 * Normally we don't want to display any ld.so.1 bindings (i.e. the bindings
 * to these calls themselves). So, if a Dbg_bind_global() originates from
 * ld.so.1 don't print anything.  If we really want to see the ld.so.1 bindings,
 * simply give the run-time linker a different SONAME.
 */
void
Dbg_bind_global(const char *ffile, caddr_t fabs, caddr_t frel, Xword pltndx,
    Pltbindtype pbtype, const char *tfile, caddr_t tabs, caddr_t trel,
    const char *sym, uint_t binfo)
{
	const char	*rfile;
	char		binfostr[BINFOSZ];

	if (DBG_NOTCLASS(DBG_BINDINGS))
		return;

	if ((rfile = strrchr(ffile, '/')) == NULL)
		rfile = ffile;
	else
		rfile++;

	if (strcmp(rfile, MSG_ORIG(MSG_FIL_RTLD)) == 0)
		return;

	if (DBG_NOTDETAIL()) {
		dbg_print(MSG_INTL(MSG_BND_BASIC), ffile, tfile,
		    _Dbg_sym_dem(sym));
		return;
	}

	/*
	 * Determine if this binding has any associated information, such as
	 * and interposition, direct binding, copy-relocations, etc.
	 */
	binfo &= ~DBG_BINFO_FOUND;
	binfo &= DBG_BINFO_MSK;
	if (binfo) {
		int	_binfo = 0;

		(void) strcpy(binfostr, MSG_ORIG(MSG_BINFO_START));
		if (binfo & DBG_BINFO_DIRECT) {
			_binfo |= DBG_BINFO_DIRECT;
			(void) strcat(binfostr, MSG_ORIG(MSG_BINFO_DIRECT));
		}
		if (binfo & DBG_BINFO_INTERPOSE) {
			if (_binfo)
			    (void) strcat(binfostr, MSG_ORIG(MSG_BINFO_SEP));
			_binfo |= DBG_BINFO_INTERPOSE;
			(void) strcat(binfostr, MSG_ORIG(MSG_BINFO_INTERPOSE));
		}
		if (binfo & DBG_BINFO_COPYREF) {
			if (_binfo)
			    (void) strcat(binfostr, MSG_ORIG(MSG_BINFO_SEP));
			_binfo |= DBG_BINFO_COPYREF;
			(void) strcat(binfostr, MSG_ORIG(MSG_BINFO_COPYREF));
		}
		if (binfo & DBG_BINFO_FILTEE) {
			if (_binfo)
			    (void) strcat(binfostr, MSG_ORIG(MSG_BINFO_SEP));
			_binfo |= DBG_BINFO_FILTEE;
			(void) strcat(binfostr, MSG_ORIG(MSG_BINFO_FILTEE));
		}
		if (binfo & DBG_BINFO_PLTADDR) {
			if (_binfo)
			    (void) strcat(binfostr, MSG_ORIG(MSG_BINFO_SEP));
			_binfo |= DBG_BINFO_PLTADDR;
			(void) strcat(binfostr, MSG_ORIG(MSG_BINFO_PLTADDR));
		}
		if (binfo & ~_binfo) {
			size_t	len;

			if (_binfo)
			    (void) strcat(binfostr, MSG_ORIG(MSG_BINFO_SEP));

			len = strlen(binfostr);
			conv_invalid_str(&binfostr[len], (BINFOSZ - len),
			    (Lword)(binfo & ~_binfo), 0);
		}
		(void) strcat(binfostr, MSG_ORIG(MSG_BINFO_END));
	} else
		binfostr[0] = '\0';


	if (pltndx != (Xword)-1) {
		const char	*pltstring;

		if (pbtype < PLT_T_NUM)
			pltstring = pltbindtypes[pbtype];
		else
			pltstring = pltbindtypes[PLT_T_NONE];

		/*
		 * Called from a plt offset.
		 */
		dbg_print(MSG_INTL(MSG_BND_PLT), ffile, EC_ADDR(fabs),
		    EC_ADDR(frel), EC_WORD(pltndx), pltstring, tfile,
		    EC_ADDR(tabs), EC_ADDR(trel), _Dbg_sym_dem(sym), binfostr);

	} else if ((fabs == 0) && (frel == 0)) {
		/*
		 * Called from a dlsym().  We're not performing a relocation,
		 * but are handing the address of the symbol back to the user.
		 */
		dbg_print(MSG_INTL(MSG_BND_DLSYM), ffile, tfile, EC_ADDR(tabs),
		    EC_ADDR(trel), _Dbg_sym_dem(sym), binfostr);

	} else {
		/*
		 * Standard relocation.
		 */
		dbg_print(MSG_INTL(MSG_BND_DEFAULT), ffile, EC_ADDR(fabs),
		    EC_ADDR(frel), tfile, EC_ADDR(tabs), EC_ADDR(trel),
		    _Dbg_sym_dem(sym), binfostr);
	}
}

void
Dbg_bind_weak(const char *ffile, caddr_t fabs, caddr_t frel, const char *sym)
{
	if (DBG_NOTCLASS(DBG_BINDINGS))
		return;

	if (DBG_NOTDETAIL())
		dbg_print(MSG_INTL(MSG_BND_WEAK_1), ffile, _Dbg_sym_dem(sym));
	else
		dbg_print(MSG_INTL(MSG_BND_WEAK_2), ffile, EC_ADDR(fabs),
		    EC_ADDR(frel), _Dbg_sym_dem(sym));
}

void
Dbg_bind_profile(uint_t ndx, uint_t count)
{
	if (DBG_NOTCLASS(DBG_BINDINGS))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(MSG_INTL(MSG_BND_PROFILE), EC_WORD(ndx), EC_WORD(count));
}
