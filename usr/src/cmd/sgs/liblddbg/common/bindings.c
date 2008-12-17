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

#include	<sys/types.h>
#include	<string.h>
#include	<debug.h>
#include	<conv.h>
#include	"_debug.h"
#include	"msg.h"

void
Dbg_bind_plt_summary(Lm_list *lml, Half mach, Word pltcnt21d, Word pltcnt24d,
    Word pltcntu32, Word pltcntu44, Word pltcntfull, Word pltcntfar)
{
	Word plttotal = pltcnt21d + pltcnt24d + pltcntu32 +
	    pltcntu44 + pltcntfull + pltcntfar;

	if (DBG_NOTCLASS(DBG_C_BINDINGS))
		return;

	switch (mach) {
	case EM_SPARC:
		dbg_print(lml, MSG_INTL(MSG_BND_PSUM_SPARC), EC_WORD(pltcnt21d),
		    EC_WORD(pltcnt24d), EC_WORD(pltcntfull), EC_WORD(plttotal));
		break;
	case EM_SPARCV9:
		dbg_print(lml, MSG_INTL(MSG_BND_PSUM_SPARCV9),
		    EC_WORD(pltcnt21d), EC_WORD(pltcnt24d), EC_WORD(pltcntu32),
		    EC_WORD(pltcntu44), EC_WORD(pltcntfull), EC_WORD(pltcntfar),
		    EC_WORD(plttotal));
		break;
	default:
		dbg_print(lml, MSG_INTL(MSG_BND_PSUM_DEFAULT),
		    EC_WORD(plttotal));
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
		MSG_BINFO_DIRECT_SIZE +		MSG_BINFO_SEP_SIZE + \
		MSG_BINFO_INTERPOSE_SIZE +	MSG_BINFO_SEP_SIZE + \
		MSG_BINFO_COPYREF_SIZE +	MSG_BINFO_SEP_SIZE + \
		MSG_BINFO_FILTEE_SIZE +		MSG_BINFO_SEP_SIZE + \
		MSG_BINFO_PLTADDR_SIZE + \
		CONV_INV_BUFSIZE + MSG_BINFO_END_SIZE


void
Dbg_bind_global(Rt_map *flmp, Addr fabs, Off foff, Xword pltndx,
    Pltbindtype pbtype, Rt_map *tlmp, Addr tabs, Off toff,
    const char *sym, uint_t binfo)
{
	static char binfostr[BINFOSZ];
	static Val_desc vda[] = {
		{ DBG_BINFO_DIRECT,	MSG_ORIG(MSG_BINFO_DIRECT) },
		{ DBG_BINFO_INTERPOSE,	MSG_ORIG(MSG_BINFO_INTERPOSE) },
		{ DBG_BINFO_COPYREF,	MSG_ORIG(MSG_BINFO_COPYREF) },
		{ DBG_BINFO_FILTEE,	MSG_ORIG(MSG_BINFO_FILTEE) },
		{ DBG_BINFO_PLTADDR,	MSG_ORIG(MSG_BINFO_PLTADDR) },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = { binfostr, sizeof (binfostr),
		vda, NULL, 0, 0, MSG_ORIG(MSG_BINFO_START),
		MSG_ORIG(MSG_BINFO_SEP), MSG_ORIG(MSG_BINFO_END) };

	const char	*ffile = NAME(flmp);
	const char	*tfile = NAME(tlmp);
	Lm_list		*lml = LIST(flmp);

	if (DBG_NOTCLASS(DBG_C_BINDINGS))
		return;

	if (DBG_NOTDETAIL()) {
		dbg_print(lml, MSG_INTL(MSG_BND_BASIC), ffile, tfile,
		    Dbg_demangle_name(sym));
		return;
	}

	/*
	 * Determine if this binding has any associated information, such as
	 * interposition, direct binding, copy-relocations, etc.
	 */
	binfo &= ~DBG_BINFO_FOUND;
	binfo &= DBG_BINFO_MSK;
	if (binfo) {
		conv_arg.oflags = conv_arg.rflags = binfo;
		(void) conv_expn_field(&conv_arg, 0);
	} else {
		binfostr[0] = '\0';
	}

	if (pltndx != (Xword)-1) {
		const char	*pltstring;

		if (pbtype < PLT_T_NUM)
			pltstring = pltbindtypes[pbtype];
		else
			pltstring = pltbindtypes[PLT_T_NONE];

		/*
		 * Called from a plt offset.
		 */
		dbg_print(lml, MSG_INTL(MSG_BND_PLT), ffile, EC_ADDR(fabs),
		    EC_OFF(foff), EC_XWORD(pltndx), pltstring, tfile,
		    EC_ADDR(tabs), EC_OFF(toff), Dbg_demangle_name(sym),
		    binfostr);

	} else if ((fabs == 0) && (foff == 0)) {
		/*
		 * Called from a dlsym().  We're not performing a relocation,
		 * but are handing the address of the symbol back to the user.
		 */
		dbg_print(lml, MSG_INTL(MSG_BND_DLSYM), ffile, tfile,
		    EC_ADDR(tabs), EC_OFF(toff), Dbg_demangle_name(sym),
		    binfostr);
	} else {
		/*
		 * Standard relocation.
		 */
		dbg_print(lml, MSG_INTL(MSG_BND_DEFAULT), ffile, EC_ADDR(fabs),
		    EC_OFF(foff), tfile, EC_ADDR(tabs), EC_OFF(toff),
		    Dbg_demangle_name(sym), binfostr);
	}
}

void
Dbg_bind_reject(Rt_map *flmp, Rt_map *tlmp, const char *sym, int why)
{
	static Msg reason[DBG_BNDREJ_NUM + 1] = {
		MSG_BNDREJ_DIRECT,	/* MSG_INTL(MSG_BNDREJ_DIRECT) */
		MSG_BNDREJ_GROUP,	/* MSG_INTL(MSG_BNDREJ_GROUP) */
		MSG_BNDREJ_SINGLE	/* MSG_INTL(MSG_BNDREJ_SINGLE) */
	};

	if (DBG_NOTCLASS(DBG_C_BINDINGS))
		return;

	dbg_print(LIST(flmp), MSG_INTL(MSG_BND_REJECT), NAME(flmp), NAME(tlmp),
	    sym, MSG_INTL(reason[why]));
}

void
Dbg_bind_weak(Rt_map *flmp, Addr fabs, Addr frel, const char *sym)
{
	Lm_list		*lml = LIST(flmp);
	const char	*ffile = NAME(flmp);

	if (DBG_NOTCLASS(DBG_C_BINDINGS))
		return;

	if (DBG_NOTDETAIL())
		dbg_print(lml, MSG_INTL(MSG_BND_WEAK_1), ffile,
		    Dbg_demangle_name(sym));
	else
		dbg_print(lml, MSG_INTL(MSG_BND_WEAK_2), ffile, EC_ADDR(fabs),
		    EC_ADDR(frel), Dbg_demangle_name(sym));
}

#if	defined(_ELF64)

void
Dbg_bind_pltpad_to(Rt_map *lmp, Addr pltpad, const char *dfile,
    const char *sname)
{
	if (DBG_NOTCLASS(DBG_C_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(LIST(lmp), MSG_INTL(MSG_BND_PLTPAD_TO), EC_ADDR(pltpad),
	    NAME(lmp), dfile, sname);
}

void
Dbg_bind_pltpad_from(Rt_map *lmp, Addr pltpad, const char *sname)
{
	if (DBG_NOTCLASS(DBG_C_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(LIST(lmp), MSG_INTL(MSG_BND_PLTPAD_FROM), EC_ADDR(pltpad),
	    NAME(lmp), sname);
}

#endif
