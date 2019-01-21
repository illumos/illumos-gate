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
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <msg.h>
#include <_rtld.h>
#include <conv.h>
#include <sys/mdb_modapi.h>
#include <sys/param.h>
#include <stdlib.h>

/*
 * Data structure for walkers.
 */
typedef struct {
	uint_t	w_flags;
} W_desc;

/*
 * Flags values for dcmds
 */

#define	RTLD_FLG_VERBOSE	0x0001		/* verbose output */

static const mdb_bitmask_t rtflags_bits[] = {
	{ MSG_ORIG(MSG_FLG_ISMAIN), FLG_RT_ISMAIN, FLG_RT_ISMAIN},
	{ MSG_ORIG(MSG_FLG_IMGALLOC), FLG_RT_IMGALLOC, FLG_RT_IMGALLOC},
	{ MSG_ORIG(MSG_FLG_RELOCED), FLG_RT_RELOCED, FLG_RT_RELOCED},
	{ MSG_ORIG(MSG_FLG_SETGROUP), FLG_RT_SETGROUP, FLG_RT_SETGROUP},
	{ MSG_ORIG(MSG_FLG_CAP), FLG_RT_CAP, FLG_RT_CAP},
	{ MSG_ORIG(MSG_FLG_OBJECT), FLG_RT_OBJECT, FLG_RT_OBJECT},
	{ MSG_ORIG(MSG_FLG_NEWLOAD), FLG_RT_NEWLOAD, FLG_RT_NEWLOAD},
	{ MSG_ORIG(MSG_FLG_NODUMP), FLG_RT_NODUMP, FLG_RT_NODUMP},
	{ MSG_ORIG(MSG_FLG_DELETE), FLG_RT_DELETE, FLG_RT_DELETE},
	{ MSG_ORIG(MSG_FLG_ANALYZED), FLG_RT_ANALYZED, FLG_RT_ANALYZED},
	{ MSG_ORIG(MSG_FLG_INITDONE), FLG_RT_INITDONE, FLG_RT_INITDONE},
	{ MSG_ORIG(MSG_FLG_TRANS), FLG_RT_TRANS, FLG_RT_TRANS},
	{ MSG_ORIG(MSG_FLG_FIXED), FLG_RT_FIXED, FLG_RT_FIXED},
	{ MSG_ORIG(MSG_FLG_PRELOAD), FLG_RT_PRELOAD, FLG_RT_PRELOAD},
	{ MSG_ORIG(MSG_FLG_ALTER), FLG_RT_ALTER, FLG_RT_ALTER},
	{ MSG_ORIG(MSG_FLG_LOADFLTR), FLG_RT_LOADFLTR, FLG_RT_LOADFLTR},
	{ MSG_ORIG(MSG_FLG_AUDIT), FLG_RT_AUDIT, FLG_RT_AUDIT},
	{ MSG_ORIG(MSG_FLG_MODESET), FLG_RT_MODESET, FLG_RT_MODESET},
	{ MSG_ORIG(MSG_FLG_ANALZING), FLG_RT_ANALZING, FLG_RT_ANALZING},
	{ MSG_ORIG(MSG_FLG_INITFRST), FLG_RT_INITFRST, FLG_RT_INITFRST},
	{ MSG_ORIG(MSG_FLG_NOOPEN), FLG_RT_NOOPEN, FLG_RT_NOOPEN},
	{ MSG_ORIG(MSG_FLG_FINICLCT), FLG_RT_FINICLCT, FLG_RT_FINICLCT},
	{ MSG_ORIG(MSG_FLG_INITCALL), FLG_RT_INITCALL, FLG_RT_INITCALL},
	{ MSG_ORIG(MSG_FLG_OBJINTPO), FLG_RT_OBJINTPO, FLG_RT_OBJINTPO},
	{ MSG_ORIG(MSG_FLG_SYMINTPO), FLG_RT_SYMINTPO, FLG_RT_SYMINTPO},
	{ MSG_ORIG(MSG_FLG_MOVE), FLG_RT_MOVE, FLG_RT_MOVE},
	{ MSG_ORIG(MSG_FLG_RELOCING), FLG_RT_RELOCING, FLG_RT_RELOCING},
	{ MSG_ORIG(MSG_FLG_REGSYMS), FLG_RT_REGSYMS, FLG_RT_REGSYMS},
	{ MSG_ORIG(MSG_FLG_INITCLCT), FLG_RT_INITCLCT, FLG_RT_INITCLCT},
	{ MSG_ORIG(MSG_FLG_PUBHDL), FLG_RT_PUBHDL, FLG_RT_PUBHDL},
	{ MSG_ORIG(MSG_FLG_PRIHDL), FLG_RT_PRIHDL, FLG_RT_PRIHDL},
	{ NULL, 0, 0}
};

static const mdb_bitmask_t rtflags1_bits[] = {
	{ MSG_ORIG(MSG_FL1_COPYTOOK), FL1_RT_COPYTOOK, FL1_RT_COPYTOOK},
	{ MSG_ORIG(MSG_FL1_ALTCHECK), FL1_RT_ALTCHECK, FL1_RT_ALTCHECK},
	{ MSG_ORIG(MSG_FL1_ALTCAP), FL1_RT_ALTCAP, FL1_RT_ALTCAP},
	{ MSG_ORIG(MSG_FL1_CONFSET), FL1_RT_CONFSET, FL1_RT_CONFSET },
	{ MSG_ORIG(MSG_FL1_NODEFLIB), FL1_RT_NODEFLIB, FL1_RT_NODEFLIB },
	{ MSG_ORIG(MSG_FL1_ENDFILTE), FL1_RT_ENDFILTE, FL1_RT_ENDFILTE },
	{ MSG_ORIG(MSG_FL1_DISPREL), FL1_RT_DISPREL, FL1_RT_DISPREL },
	{ MSG_ORIG(MSG_FL1_DTFLAGS), FL1_RT_DTFLAGS, FL1_RT_DTFLAGS},
	{ MSG_ORIG(MSG_FL1_LDDSTUB), FL1_RT_LDDSTUB, FL1_RT_LDDSTUB},
	{ MSG_ORIG(MSG_FL1_NOINIFIN), FL1_RT_NOINIFIN, FL1_RT_NOINIFIN },
	{ MSG_ORIG(MSG_FL1_USED), FL1_RT_USED, FL1_RT_USED },
	{ MSG_ORIG(MSG_FL1_SYMBOLIC), FL1_RT_SYMBOLIC, FL1_RT_SYMBOLIC },
	{ MSG_ORIG(MSG_FL1_OBJSFLTR), FL1_RT_OBJSFLTR, FL1_RT_OBJSFLTR },
	{ MSG_ORIG(MSG_FL1_OBJAFLTR), FL1_RT_OBJAFLTR, FL1_RT_OBJAFLTR },
	{ MSG_ORIG(MSG_FL1_SYMSFLTR), FL1_RT_SYMSFLTR, FL1_RT_SYMSFLTR },
	{ MSG_ORIG(MSG_FL1_SYMAFLTR), FL1_RT_SYMAFLTR, FL1_RT_SYMAFLTR },
	{ MSG_ORIG(MSG_FL1_TLSADD), FL1_RT_TLSADD, FL1_RT_TLSADD },
	{ MSG_ORIG(MSG_FL1_TLSSTAT), FL1_RT_TLSSTAT, FL1_RT_TLSSTAT },
	{ MSG_ORIG(MSG_FL1_DIRECT), FL1_RT_DIRECT, FL1_RT_DIRECT},
	{ MSG_ORIG(MSG_FL1_GLOBAUD), FL1_RT_GLOBAUD, FL1_RT_GLOBAUD},
	{ MSG_ORIG(MSG_FL1_DEPAUD), FL1_RT_DEPAUD, FL1_RT_DEPAUD},
	{ NULL, 0, 0}
};

static const mdb_bitmask_t rtaflags_bits[] = {
	{ MSG_ORIG(MSG_LTFL_AUD_PREINIT), LML_TFLG_AUD_PREINIT,
	    LML_TFLG_AUD_PREINIT },
	{ MSG_ORIG(MSG_LTFL_AUD_OBJSEARCH), LML_TFLG_AUD_OBJSEARCH,
	    LML_TFLG_AUD_OBJSEARCH },
	{ MSG_ORIG(MSG_LTFL_AUD_OBJOPEN), LML_TFLG_AUD_OBJOPEN,
	    LML_TFLG_AUD_OBJOPEN },
	{ MSG_ORIG(MSG_LTFL_AUD_OBJFILTER), LML_TFLG_AUD_OBJFILTER,
	    LML_TFLG_AUD_OBJFILTER },
	{ MSG_ORIG(MSG_LTFL_AUD_OBJCLOSE), LML_TFLG_AUD_OBJCLOSE,
	    LML_TFLG_AUD_OBJCLOSE },
	{ MSG_ORIG(MSG_LTFL_AUD_SYMBIND), LML_TFLG_AUD_SYMBIND,
	    LML_TFLG_AUD_SYMBIND },
	{ MSG_ORIG(MSG_LTFL_AUD_PLTENTER), LML_TFLG_AUD_PLTENTER,
	    LML_TFLG_AUD_PLTENTER },
	{ MSG_ORIG(MSG_LTFL_AUD_PLTEXIT), LML_TFLG_AUD_PLTEXIT,
	    LML_TFLG_AUD_PLTEXIT },
	{ MSG_ORIG(MSG_LTFL_AUD_ACTIVITY), LML_TFLG_AUD_ACTIVITY,
	    LML_TFLG_AUD_ACTIVITY },
	{ NULL, 0, 0}
};

static const mdb_bitmask_t rtmode_bits[] = {
	{ MSG_ORIG(MSG_MODE_LAZY), RTLD_LAZY, RTLD_LAZY },
	{ MSG_ORIG(MSG_MODE_NOW), RTLD_NOW, RTLD_NOW },
	{ MSG_ORIG(MSG_MODE_NOLOAD), RTLD_NOLOAD, RTLD_NOLOAD },
	{ MSG_ORIG(MSG_MODE_GLOBAL), RTLD_GLOBAL, RTLD_GLOBAL },
	{ MSG_ORIG(MSG_MODE_PARENT), RTLD_PARENT, RTLD_PARENT },
	{ MSG_ORIG(MSG_MODE_GROUP), RTLD_GROUP, RTLD_GROUP },
	{ MSG_ORIG(MSG_MODE_WORLD), RTLD_WORLD, RTLD_WORLD },
	{ MSG_ORIG(MSG_MODE_NODELETE), RTLD_NODELETE, RTLD_NODELETE },
	{ MSG_ORIG(MSG_MODE_FIRST), RTLD_FIRST, RTLD_FIRST },
	{ MSG_ORIG(MSG_MODE_CONFGEN), RTLD_CONFGEN, RTLD_CONFGEN },
	{ NULL, 0, 0}
};

static const mdb_bitmask_t bndflags_bits[] = {
	{ MSG_ORIG(MSG_BFL_NEEDED), BND_NEEDED, BND_NEEDED },
	{ MSG_ORIG(MSG_BFL_REFER), BND_REFER, BND_REFER },
	{ MSG_ORIG(MSG_BFL_FILTER), BND_FILTER, BND_FILTER },
	{ NULL, 0, 0}
};

static const mdb_bitmask_t grhflags_bits[] = {
	{ MSG_ORIG(MSG_GPH_PUBLIC), GPH_PUBLIC, GPH_PUBLIC },
	{ MSG_ORIG(MSG_GPH_PRIVATE), GPH_PRIVATE, GPH_PRIVATE },
	{ MSG_ORIG(MSG_GPH_ZERO), GPH_ZERO, GPH_ZERO },
	{ MSG_ORIG(MSG_GPH_LDSO), GPH_LDSO, GPH_LDSO },
	{ MSG_ORIG(MSG_GPH_FIRST), GPH_FIRST, GPH_FIRST },
	{ MSG_ORIG(MSG_GPH_FILTEE), GPH_FILTEE, GPH_FILTEE },
	{ MSG_ORIG(MSG_GPH_INITIAL), GPH_INITIAL, GPH_INITIAL },
	{ NULL, 0, 0}
};

static const mdb_bitmask_t grdflags_bits[] = {
	{ MSG_ORIG(MSG_GPD_DLSYM), GPD_DLSYM, GPD_DLSYM },
	{ MSG_ORIG(MSG_GPD_RELOC), GPD_RELOC, GPD_RELOC },
	{ MSG_ORIG(MSG_GPD_ADDEPS), GPD_ADDEPS, GPD_ADDEPS },
	{ MSG_ORIG(MSG_GPD_PARENT), GPD_PARENT, GPD_PARENT },
	{ MSG_ORIG(MSG_GPD_FILTER), GPD_FILTER, GPD_FILTER },
	{ MSG_ORIG(MSG_GPD_REMOVE), GPD_REMOVE, GPD_REMOVE },
	{ NULL, 0, 0}
};

static const mdb_bitmask_t lmc_bits[] = {
	{ MSG_ORIG(MSG_LMC_ANALYZING), LMC_FLG_ANALYZING, LMC_FLG_ANALYZING},
	{ MSG_ORIG(MSG_LMC_RELOCATING), LMC_FLG_RELOCATING, LMC_FLG_RELOCATING},
	{ MSG_ORIG(MSG_LMC_REANALYZE), LMC_FLG_REANALYZE, LMC_FLG_REANALYZE},
	{ NULL, 0, 0}
};

/*
 * Obtain a string - typically a link-map name.
 */
static char *
String(uintptr_t addr, const char *name)
{
	static char	str[MAXPATHLEN];

	if (addr) {
		if (mdb_readstr(str, MAXPATHLEN, addr) == -1) {
			mdb_warn(MSG_ORIG(MSG_ERR_READ), name, addr);
			return (0);
		}
		return (str);
	}
	return ((char *)MSG_ORIG(MSG_STR_EMPTY));
}

/*
 * Obtain a link-map name.
 */
static char *
Rtmap_Name(uintptr_t addr)
{
	Rt_map	rtmap;

	if (addr) {
		if (mdb_vread(&rtmap, sizeof (Rt_map), addr) == -1) {
			mdb_warn(MSG_ORIG(MSG_ERR_READ),
			    MSG_ORIG(MSG_RTMAP_STR), addr);
			return (0);
		}
		return (String((uintptr_t)NAME(&rtmap),
		    MSG_ORIG(MSG_STR_NAME)));
	}
	return ((char *)MSG_ORIG(MSG_STR_EMPTY));
}

void
dcmd_Bind_help(void)
{
	mdb_printf(MSG_ORIG(MSG_BND_HELP));
}

static int
/* ARGSUSED2 */
dcmd_Bind(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	Bnd_desc	bnd;
	char		*str;

	/*
	 * Insure we have a valid address.
	 */
	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_warn(MSG_ORIG(MSG_ERR_NAS), MSG_ORIG(MSG_BND_STR));
		return (DCMD_USAGE);
	}

	/*
	 * Obtain the binding descriptor.
	 */
	if (mdb_vread(&bnd, sizeof (Bnd_desc), addr) == -1) {
		mdb_warn(MSG_ORIG(MSG_ERR_READ), MSG_ORIG(MSG_BND_STR), addr);
		return (DCMD_ERR);
	}
	mdb_printf(MSG_ORIG(MSG_BND_TITLE), addr);

	/*
	 * Establish the identity of the caller.
	 */
	if ((str = Rtmap_Name((uintptr_t)bnd.b_caller)) == 0)
		return (DCMD_ERR);
	mdb_printf(MSG_ORIG(MSG_BND_LINE1), bnd.b_caller, str);

	/*
	 * Establish the identity of the dependency.
	 */
	if ((str = Rtmap_Name((uintptr_t)bnd.b_depend)) == 0)
		return (DCMD_ERR);
	mdb_printf(MSG_ORIG(MSG_BND_LINE2), bnd.b_depend, str);

	/*
	 * Display any flags.
	 */
	mdb_printf(MSG_ORIG(MSG_BND_LINE3), bnd.b_flags, bnd.b_flags,
	    bndflags_bits);

	return (DCMD_OK);
}

static void
dcmd_Depends_help(void)
{
	mdb_printf(MSG_ORIG(MSG_DEPENDS_HELP));
}

static int
Depends(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv,
    uint_t flg, const char *msg)
{
	APlist		apl;
	uintptr_t	datap, nitems;
	Bnd_desc	*bdp;

	/*
	 * Obtain the APlist and determine its number of elements and those
	 * that are in use.
	 */
	if (mdb_vread(&apl, sizeof (APlist), addr) == -1) {
		mdb_warn(MSG_ORIG(MSG_ERR_READ), MSG_ORIG(MSG_STR_APLIST),
		    addr);
		return (DCMD_ERR);
	}

	mdb_printf(msg, addr, (size_t)apl.apl_nitems,
	    (size_t)apl.apl_arritems);

	if (((flg & RTLD_FLG_VERBOSE) == 0) || (apl.apl_nitems == 0))
		return (DCMD_OK);

	/*
	 * Under verbose mode print the name of each dependency.  An APlist can
	 * have a variable number of data items, so read each individual entry.
	 */
	datap = APLIST_OFF_DATA + (uintptr_t)addr;
	if (mdb_vread(&bdp, sizeof (Bnd_desc *), datap) == -1) {
		mdb_warn(MSG_ORIG(MSG_ERR_READ),
		    MSG_ORIG(MSG_BNDDESC_STR), datap);
		return (DCMD_ERR);
	}

	(void) mdb_inc_indent(4);
	mdb_printf(MSG_ORIG(MSG_STR_DASHES));

	if (dcmd_Bind((uintptr_t)bdp, flags, argc, argv) == DCMD_ERR) {
		(void) mdb_dec_indent(4);
		return (DCMD_ERR);
	}

	for (nitems = 1; nitems < apl.apl_nitems; nitems++) {
		datap += sizeof (void *);
		if (mdb_vread(&bdp, sizeof (Bnd_desc *), datap) == -1) {
			mdb_warn(MSG_ORIG(MSG_ERR_READ),
			    MSG_ORIG(MSG_BNDDESC_STR), datap);
			return (DCMD_ERR);
		}

		mdb_printf(MSG_ORIG(MSG_STR_DASHES));
		if (dcmd_Bind((uintptr_t)bdp, flags, argc, argv) == DCMD_ERR) {
			(void) mdb_dec_indent(4);
			return (DCMD_ERR);
		}
	}
	(void) mdb_dec_indent(4);
	return (DCMD_OK);
}

static int
dcmd_Depends(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	Rt_map		rtmap;
	char		*str;
	uint_t		flg = 0;

	/*
	 * Insure we have a valid address, and provide for a -v option.
	 */
	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_warn(MSG_ORIG(MSG_ERR_NAS), MSG_ORIG(MSG_DEPENDS_STR));
		return (DCMD_USAGE);
	}
	if (mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, RTLD_FLG_VERBOSE,
	    &flg, NULL) != argc)
		return (DCMD_USAGE);

	/*
	 * Read the Rt_map contents.
	 */
	if (mdb_vread(&rtmap, sizeof (Rt_map), addr) == -1) {
		mdb_warn(MSG_ORIG(MSG_ERR_READ), MSG_ORIG(MSG_RTMAP_STR), addr);
		return (DCMD_ERR);
	}
	if ((str = String((uintptr_t)NAME(&rtmap),
	    MSG_ORIG(MSG_STR_NAME))) == 0)
		return (DCMD_ERR);

	mdb_printf(MSG_ORIG(MSG_DEPENDS_LINE1), str);
	mdb_printf(MSG_ORIG(MSG_STR_DASHES));

	if (DEPENDS(&rtmap) == NULL)
		return (DCMD_OK);

	return (Depends((uintptr_t)DEPENDS(&rtmap), flags, argc, argv, flg,
	    MSG_ORIG(MSG_DEPENDS_LINE2)));
}

static void
dcmd_Callers_help(void)
{
	mdb_printf(MSG_ORIG(MSG_CALLERS_HELP));
}

static int
dcmd_Callers(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	Rt_map		rtmap;
	char		*str;
	uint_t		flg = 0;

	/*
	 * Insure we have a valid address, and provide for a -v option.
	 */
	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_warn(MSG_ORIG(MSG_ERR_NAS), MSG_ORIG(MSG_DEPENDS_STR));
		return (DCMD_USAGE);
	}
	if (mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, RTLD_FLG_VERBOSE,
	    &flg, NULL) != argc)
		return (DCMD_USAGE);

	/*
	 * Read the Rt_map contents.
	 */
	if (mdb_vread(&rtmap, sizeof (Rt_map), addr) == -1) {
		mdb_warn(MSG_ORIG(MSG_ERR_READ), MSG_ORIG(MSG_RTMAP_STR), addr);
		return (DCMD_ERR);
	}
	if ((str = String((uintptr_t)NAME(&rtmap),
	    MSG_ORIG(MSG_STR_NAME))) == 0)
		return (DCMD_ERR);

	mdb_printf(MSG_ORIG(MSG_CALLERS_LINE1), str);
	mdb_printf(MSG_ORIG(MSG_STR_DASHES));

	if (CALLERS(&rtmap) == NULL)
		return (DCMD_OK);

	return (Depends((uintptr_t)CALLERS(&rtmap), flags, argc, argv, flg,
	    MSG_ORIG(MSG_CALLERS_LINE2)));
}

void
dcmd_rtmap_help(void)
{
	mdb_printf(MSG_ORIG(MSG_RTMAP_HELP));
}

static int
/* ARGSUSED2 */
dcmd_rtmap(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	Rt_map		rtmap;
	char		*str;

	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_warn(MSG_ORIG(MSG_ERR_NAS), MSG_ORIG(MSG_RTMAP_STR));
		return (DCMD_USAGE);
	}

	if (mdb_vread(&rtmap, sizeof (Rt_map), addr) == -1) {
		mdb_warn(MSG_ORIG(MSG_ERR_READ), MSG_ORIG(MSG_RTMAP_STR), addr);
		return (DCMD_ERR);
	}

	mdb_printf(MSG_ORIG(MSG_RTMAP_TITLE), addr);
	mdb_printf(MSG_ORIG(MSG_STR_DASHES));

	/*
	 * Determine the objects name.  NAME() is the name by which the object
	 * has been opened, typically from adding a search path to a file name.
	 * PATHNAME() is the fully resolve name, which is displayed by the proc
	 * tools and debuggers.  If the two names differ, print the PATHNAME().
	 */
	if ((str = String((uintptr_t)NAME(&rtmap),
	    MSG_ORIG(MSG_STR_NAME))) == 0)
		return (DCMD_ERR);
	mdb_printf(MSG_ORIG(MSG_RTMAP_LINE1), str);
	if (NAME(&rtmap) != PATHNAME(&rtmap)) {
		if ((str = String((uintptr_t)PATHNAME(&rtmap),
		    MSG_ORIG(MSG_STR_PATHNAME))) == 0)
			return (DCMD_ERR);
		mdb_printf(MSG_ORIG(MSG_RTMAP_LINE2), str);
	}

	mdb_printf(MSG_ORIG(MSG_RTMAP_LINE3), ADDR(&rtmap), DYN(&rtmap));
	mdb_printf(MSG_ORIG(MSG_RTMAP_LINE4), NEXT(&rtmap), PREV(&rtmap));
	mdb_printf(MSG_ORIG(MSG_RTMAP_LINE5), rtmap.rt_fct, TLSMODID(&rtmap));
	mdb_printf(MSG_ORIG(MSG_RTMAP_LINE6), INIT(&rtmap), FINI(&rtmap));
	mdb_printf(MSG_ORIG(MSG_RTMAP_LINE7), GROUPS(&rtmap), HANDLES(&rtmap));
	mdb_printf(MSG_ORIG(MSG_RTMAP_LINE8), DEPENDS(&rtmap), CALLERS(&rtmap));

	if ((str = String((uintptr_t)REFNAME(&rtmap),
	    MSG_ORIG(MSG_STR_REFNAME))) == 0)
		return (DCMD_ERR);
	mdb_printf(MSG_ORIG(MSG_RTMAP_LINE9), DYNINFO(&rtmap), str);

	if ((str = String((uintptr_t)RPATH(&rtmap),
	    MSG_ORIG(MSG_STR_RPATH))) == 0)
		return (DCMD_ERR);
	mdb_printf(MSG_ORIG(MSG_RTMAP_LINE10), RLIST(&rtmap), str);

	mdb_printf(MSG_ORIG(MSG_RTMAP_LINE11), LIST(&rtmap), LIST(&rtmap));
	mdb_printf(MSG_ORIG(MSG_RTMAP_LINE12), FLAGS(&rtmap));
	mdb_printf(MSG_ORIG(MSG_RTMAP_LINE20), FLAGS(&rtmap), rtflags_bits);
	mdb_printf(MSG_ORIG(MSG_RTMAP_LINE13), FLAGS1(&rtmap));
	mdb_printf(MSG_ORIG(MSG_RTMAP_LINE20), FLAGS1(&rtmap), rtflags1_bits);
	if (AFLAGS(&rtmap)) {
		mdb_printf(MSG_ORIG(MSG_RTMAP_LINE14), AFLAGS(&rtmap));
		mdb_printf(MSG_ORIG(MSG_RTMAP_LINE20), AFLAGS(&rtmap),
		    rtaflags_bits);
	}
	mdb_printf(MSG_ORIG(MSG_RTMAP_LINE15), MODE(&rtmap));
	mdb_printf(MSG_ORIG(MSG_RTMAP_LINE20), MODE(&rtmap), rtmode_bits);

	return (DCMD_OK);
}

static int
rtmap_format(uintptr_t addr, const void *data, void *private)
{
	const Rt_map	*lmp = (const Rt_map *)data;
	W_desc		*wdp = (W_desc *)private;
	char		*str;

	if (wdp && (wdp->w_flags & RTLD_FLG_VERBOSE)) {
		mdb_printf(MSG_ORIG(MSG_STR_DASHES));
		(void) mdb_call_dcmd(
		    MSG_ORIG(MSG_RTMAP_STR), addr, DCMD_ADDRSPEC, 0, NULL);
		return (0);
	}

	if ((str = String((uintptr_t)NAME(lmp),
	    MSG_ORIG(MSG_STR_NAME))) == 0)
		return (DCMD_ERR);

	mdb_printf(MSG_ORIG(MSG_FMT_RT), CNTL(lmp), addr, ADDR(lmp), str);
	return (0);
}

void
dcmd_Rtmaps_help(void)
{
	mdb_printf(MSG_ORIG(MSG_RTMAPS_HELP));
}

static int
dcmd_Rtmaps(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t		flg = 0;
	GElf_Sym	gsym;
	APlist		*aplp, apl;
	uintptr_t	datap, nitems;
	const char	*str;
	W_desc		wdesc;

	/*
	 * '-v' - Verbose output of rtmap
	 */
	if (mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, RTLD_FLG_VERBOSE,
	    &flg, NULL) != argc)
		return (DCMD_USAGE);

	/*
	 * If an address was provided use it.
	 */
	if (flags & DCMD_ADDRSPEC) {
		if (((flags & DCMD_LOOPFIRST) || !(flags & DCMD_LOOP)) &&
		    !(flg & RTLD_FLG_VERBOSE)) {
			mdb_printf(MSG_ORIG(MSG_RTMAPS_TITLE0));
			mdb_printf(MSG_ORIG(MSG_STR_DASHES));
		}

		wdesc.w_flags = flg;
		if (mdb_pwalk(MSG_ORIG(MSG_RTMAPS_STR), rtmap_format,
		    (void *)&wdesc, addr) == -1)
			return (DCMD_ERR);
		return (DCMD_OK);
	}

	/*
	 * Otherwise traverse the dynlm_list and display each link-map.
	 */
	if (mdb_lookup_by_obj(MSG_ORIG(MSG_STR_LDSO1),
	    MSG_ORIG(MSG_STR_DYNLMLIST), &gsym) == -1) {
		mdb_warn(MSG_ORIG(MSG_ERR_SYMFAILED), MSG_ORIG(MSG_STR_LDSO1),
		    MSG_ORIG(MSG_STR_DYNLMLIST));
		return (DCMD_ERR);
	}
	if (mdb_vread(&aplp, sizeof (APlist *),
	    (uintptr_t)gsym.st_value) == -1) {
		mdb_warn(MSG_ORIG(MSG_ERR_READ), MSG_ORIG(MSG_STR_APLIST),
		    gsym.st_value);
		return (DCMD_ERR);
	}

	if (aplp == NULL) {
		mdb_printf(MSG_ORIG(MSG_LMLIST_TITLE0),
		    MSG_ORIG(MSG_STR_DYNLMLIST));
		return (DCMD_OK);
	}

	if (mdb_vread(&apl, sizeof (APlist), (uintptr_t)aplp) == -1) {
		mdb_warn(MSG_ORIG(MSG_ERR_READ), MSG_ORIG(MSG_STR_APLIST),
		    aplp);
	}
	mdb_printf(MSG_ORIG(MSG_LMLIST_TITLE1), MSG_ORIG(MSG_STR_DYNLMLIST),
	    aplp, (size_t)apl.apl_nitems, (size_t)apl.apl_arritems);
	mdb_printf(MSG_ORIG(MSG_STR_DASHES));

	flags |= (DCMD_LOOP | DCMD_LOOPFIRST);
	for (datap = (uintptr_t)aplp + APLIST_OFF_DATA, nitems = 0;
	    nitems < apl.apl_nitems; nitems++, datap += sizeof (void *)) {
		Lm_list	*lml, lm;

		if (mdb_vread(&lml, sizeof (Lm_list *), datap) == -1) {
			mdb_warn(MSG_ORIG(MSG_ERR_READ),
			    MSG_ORIG(MSG_LMLIST_STR), datap);
			return (DCMD_ERR);
		}
		if (mdb_vread(&lm, sizeof (Lm_list), (uintptr_t)lml) == -1) {
			mdb_warn(MSG_ORIG(MSG_ERR_READ),
			    MSG_ORIG(MSG_LMLIST_STR), lml);
			return (DCMD_ERR);
		}

		(void) mdb_inc_indent(2);
		if (lm.lm_flags & LML_FLG_BASELM)
			str = MSG_ORIG(MSG_LMLIST_BASE);
		else if (lm.lm_flags & LML_FLG_RTLDLM)
			str = MSG_ORIG(MSG_LMLIST_LDSO);
		else
			str = MSG_ORIG(MSG_LMLIST_NEWLM);

		if ((flags & DCMD_LOOP) && ((flags & DCMD_LOOPFIRST) == 0))
			mdb_printf(MSG_ORIG(MSG_STR_DASHES));

		mdb_printf(MSG_ORIG(MSG_LMLIST_TITLE2), datap, str);
		mdb_printf(MSG_ORIG(MSG_STR_DASHES));

		(void) mdb_inc_indent(2);

		if (((flags & DCMD_LOOPFIRST) || !(flags & DCMD_LOOP)) &&
		    !(flg & RTLD_FLG_VERBOSE)) {
			mdb_printf(MSG_ORIG(MSG_RTMAPS_TITLE0));
			mdb_printf(MSG_ORIG(MSG_STR_DASHES));
		}

		wdesc.w_flags = flg;
		if (mdb_pwalk(MSG_ORIG(MSG_RTMAPS_STR), rtmap_format,
		    (void *)&wdesc, (uintptr_t)lm.lm_head) == -1) {
			(void) mdb_dec_indent(4);
			return (DCMD_ERR);
		}
		(void) mdb_dec_indent(4);
		flags &= ~DCMD_LOOPFIRST;
	}
	return (DCMD_OK);
}

void
dcmd_Setenv_help(void)
{
	mdb_printf(MSG_ORIG(MSG_SETENV_HELP));
}

/*
 * As of s10, mdb provides its own setenv command.  This command allows the
 * environment of the process being controlled to be changed at any time.
 * Prior to this, ld.so.1 provided it's own, more primitive implementation.
 * This allowed for changing mdb's environment only, which if it was changed
 * before the application ws executed, would be copied to the applications
 * environment.  Thus, we could start mdb, set an LD_ variable within its
 * environment (which it's own ld.so.1 had already finished processing), and
 * have this setting be inherited by the application.
 */
static int
/* ARGSUSED */
dcmd_Setenv(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char	*str;

	if (mdb_call_dcmd(MSG_ORIG(MSG_STR_SETENV), addr, flags, argc,
	    argv) == 0)
		return (DCMD_OK);

	if (((flags & DCMD_ADDRSPEC) != 0) || (argc == 0) || (argc > 1) ||
	    (argv->a_type != MDB_TYPE_STRING))
		return (DCMD_USAGE);

	str = mdb_alloc((strlen(argv->a_un.a_str) + 1), UM_NOSLEEP);
	if (str == NULL)
		return (DCMD_ERR);

	(void) strcpy(str, argv->a_un.a_str);
	(void) putenv(str);
	return (DCMD_OK);
}

/*
 * Walk Rt_map lists
 */
static int
walk_rtmap_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		mdb_warn(MSG_ORIG(MSG_ERR_NAS), MSG_ORIG(MSG_RTMAP_STR));
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

static int
walk_rtmap_step(mdb_walk_state_t *wsp)
{
	int	status;
	Rt_map	lmp;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);
	if (mdb_vread(&lmp, sizeof (Rt_map), wsp->walk_addr) == -1) {
		mdb_warn(MSG_ORIG(MSG_ERR_READ),
		    MSG_ORIG(MSG_RTMAP_STR), wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, &lmp, wsp->walk_cbdata);
	wsp->walk_addr = (uintptr_t)(NEXT(&lmp));
	return (status);
}

static const mdb_bitmask_t lml_flags_bit[] = {
	{ MSG_ORIG(MSG_LFL_BASELM), LML_FLG_BASELM, LML_FLG_BASELM },
	{ MSG_ORIG(MSG_LFL_RTLDLM), LML_FLG_RTLDLM, LML_FLG_RTLDLM },
	{ MSG_ORIG(MSG_LFL_PLTREL), LML_FLG_PLTREL, LML_FLG_PLTREL },
	{ MSG_ORIG(MSG_LFL_HOLDLOCK), LML_FLG_HOLDLOCK, LML_FLG_HOLDLOCK },
	{ MSG_ORIG(MSG_LFL_ENVIRON), LML_FLG_ENVIRON, LML_FLG_ENVIRON },
	{ MSG_ORIG(MSG_LFL_INTRPOSE), LML_FLG_INTRPOSE, LML_FLG_INTRPOSE },
	{ MSG_ORIG(MSG_LFL_LOCAUDIT), LML_FLG_LOCAUDIT, LML_FLG_LOCAUDIT },
	{ MSG_ORIG(MSG_LFL_LOADAVAIL), LML_FLG_LOADAVAIL, LML_FLG_LOADAVAIL },
	{ MSG_ORIG(MSG_LFL_IGNRELERR), LML_FLG_IGNRELERR, LML_FLG_IGNRELERR },
	{ MSG_ORIG(MSG_LFL_STARTREL), LML_FLG_STARTREL, LML_FLG_STARTREL },
	{ MSG_ORIG(MSG_LFL_ATEXIT), LML_FLG_ATEXIT, LML_FLG_ATEXIT },
	{ MSG_ORIG(MSG_LFL_OBJADDED), LML_FLG_OBJADDED, LML_FLG_OBJADDED },
	{ MSG_ORIG(MSG_LFL_OBJDELETED), LML_FLG_OBJDELETED,
	    LML_FLG_OBJDELETED },
	{ MSG_ORIG(MSG_LFL_OBJREEVAL), LML_FLG_OBJREEVAL, LML_FLG_OBJREEVAL },
	{ MSG_ORIG(MSG_LFL_INTRPOSETSORT), LML_FLG_INTRPOSETSORT,
	    LML_FLG_INTRPOSETSORT },
	{ MSG_ORIG(MSG_LFL_AUDITNOTIFY), LML_FLG_AUDITNOTIFY,
	    LML_FLG_AUDITNOTIFY },
	{ MSG_ORIG(MSG_LFL_GROUPSEXIST), LML_FLG_GROUPSEXIST,
	    LML_FLG_GROUPSEXIST },

	{ MSG_ORIG(MSG_LFL_TRC_LDDSTUB), LML_FLG_TRC_LDDSTUB,
	    LML_FLG_TRC_LDDSTUB },
	{ MSG_ORIG(MSG_LFL_TRC_ENABLE), LML_FLG_TRC_ENABLE,
	    LML_FLG_TRC_ENABLE },
	{ MSG_ORIG(MSG_LFL_TRC_WARN), LML_FLG_TRC_WARN, LML_FLG_TRC_WARN },
	{ MSG_ORIG(MSG_LFL_TRC_VERBOSE), LML_FLG_TRC_VERBOSE,
	    LML_FLG_TRC_VERBOSE },
	{ MSG_ORIG(MSG_LFL_TRC_SEARCH), LML_FLG_TRC_SEARCH,
	    LML_FLG_TRC_SEARCH },
	{ MSG_ORIG(MSG_LFL_TRC_UNREF), LML_FLG_TRC_UNREF, LML_FLG_TRC_UNREF },
	{ MSG_ORIG(MSG_LFL_TRC_UNUSED), LML_FLG_TRC_UNUSED,
	    LML_FLG_TRC_UNUSED },
	{ MSG_ORIG(MSG_LFL_TRC_INIT), LML_FLG_TRC_INIT, LML_FLG_TRC_INIT },
	{ MSG_ORIG(MSG_LFL_TRC_NOUNRESWEAK), LML_FLG_TRC_NOUNRESWEAK,
	    LML_FLG_TRC_NOUNRESWEAK },
	{ MSG_ORIG(MSG_LFL_TRC_NOPAREXT), LML_FLG_TRC_NOPAREXT,
	    LML_FLG_TRC_NOPAREXT },
	{ NULL, 0, 0}
};

static const mdb_bitmask_t lml_tflags_bit[] = {
	{ MSG_ORIG(MSG_LTFL_NOLAZYLD), LML_TFLG_NOLAZYLD, LML_TFLG_NOLAZYLD },
	{ MSG_ORIG(MSG_LTFL_NODIRECT), LML_TFLG_NODIRECT, LML_TFLG_NODIRECT },
	{ MSG_ORIG(MSG_LTFL_NOAUDIT), LML_TFLG_NOAUDIT, LML_TFLG_NOAUDIT },
	{ MSG_ORIG(MSG_LTFL_LOADFLTR), LML_TFLG_LOADFLTR, LML_TFLG_LOADFLTR },

	{ MSG_ORIG(MSG_LTFL_AUD_PREINIT), LML_TFLG_AUD_PREINIT,
	    LML_TFLG_AUD_PREINIT },
	{ MSG_ORIG(MSG_LTFL_AUD_OBJSEARCH), LML_TFLG_AUD_OBJSEARCH,
	    LML_TFLG_AUD_OBJSEARCH },
	{ MSG_ORIG(MSG_LTFL_AUD_OBJOPEN), LML_TFLG_AUD_OBJOPEN,
	    LML_TFLG_AUD_OBJOPEN },
	{ MSG_ORIG(MSG_LTFL_AUD_OBJFILTER), LML_TFLG_AUD_OBJFILTER,
	    LML_TFLG_AUD_OBJFILTER },
	{ MSG_ORIG(MSG_LTFL_AUD_OBJCLOSE), LML_TFLG_AUD_OBJCLOSE,
	    LML_TFLG_AUD_OBJCLOSE },
	{ MSG_ORIG(MSG_LTFL_AUD_SYMBIND), LML_TFLG_AUD_SYMBIND,
	    LML_TFLG_AUD_SYMBIND },
	{ MSG_ORIG(MSG_LTFL_AUD_PLTENTER), LML_TFLG_AUD_PLTENTER,
	    LML_TFLG_AUD_PLTENTER },
	{ MSG_ORIG(MSG_LTFL_AUD_PLTEXIT), LML_TFLG_AUD_PLTEXIT,
	    LML_TFLG_AUD_PLTEXIT },
	{ MSG_ORIG(MSG_LTFL_AUD_ACTIVITY), LML_TFLG_AUD_ACTIVITY,
	    LML_TFLG_AUD_ACTIVITY },
	{ NULL, 0, 0}
};

void
dcmd_Lm_list_help(void)
{
	mdb_printf(MSG_ORIG(MSG_LMLIST_HELP));
}

static int
/* ARGSUSED1 */
_dcmd_Lm_list(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	Lm_list		lml;
	const char	*str;
	uint_t		flg = 0;

	if (mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, RTLD_FLG_VERBOSE,
	    &flg, NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_vread(&lml, sizeof (lml), addr) == -1) {
		mdb_warn(MSG_ORIG(MSG_ERR_READ), MSG_ORIG(MSG_LMLIST_STR),
		    addr);
		return (DCMD_ERR);
	}

	if (lml.lm_flags & LML_FLG_BASELM)
		str = MSG_ORIG(MSG_LMLIST_BASE);
	else if (lml.lm_flags & LML_FLG_RTLDLM)
		str = MSG_ORIG(MSG_LMLIST_LDSO);
	else
		str = MSG_ORIG(MSG_LMLIST_NEWLM);

	if ((flags & DCMD_LOOP) && ((flags & DCMD_LOOPFIRST) == 0))
		mdb_printf(MSG_ORIG(MSG_STR_DASHES));

	mdb_printf(MSG_ORIG(MSG_LMLIST_TITLE2), addr, str);
	mdb_printf(MSG_ORIG(MSG_STR_DASHES));

	if (lml.lm_lists) {
		Alist		al;
		Lm_cntl		lmc;
		uintptr_t	datap;

		addr = (uintptr_t)lml.lm_lists;
		if (mdb_vread(&al, sizeof (Alist), addr) == -1) {
			mdb_warn(MSG_ORIG(MSG_ERR_READ),
			    MSG_ORIG(MSG_STR_ALIST), addr);
			return (DCMD_ERR);
		}

		/*
		 * Determine whether the Alist has been populated.  Note, the
		 * implementation first reserves an alist entry, and initializes
		 * this element when the first link-map is processed.  Thus,
		 * there's a window when nitems is updated, but before the next
		 * element has been initialized.
		 */
		if (al.al_nitems && (flg & RTLD_FLG_VERBOSE)) {
			datap = ALIST_OFF_DATA + (uintptr_t)addr;

			if (mdb_vread(&lmc, sizeof (Lm_cntl),
			    datap) == -1) {
				mdb_warn(MSG_ORIG(MSG_ERR_READ),
				    MSG_ORIG(MSG_LMLIST_STR), datap);
				return (DCMD_ERR);
			}
		}

		mdb_printf(MSG_ORIG(MSG_LMLIST_LINE0), addr,
		    (size_t)al.al_nitems, (size_t)al.al_arritems);
		(void) mdb_inc_indent(2);
		mdb_printf(MSG_ORIG(MSG_STR_DASHES));

		if (al.al_nitems && (flg & RTLD_FLG_VERBOSE)) {
			uintptr_t	nitems;

			(void) mdb_inc_indent(2);
			mdb_printf(MSG_ORIG(MSG_LMC_LINE1), datap);
			mdb_printf(MSG_ORIG(MSG_LMC_LINE2), lmc.lc_head,
			    lmc.lc_tail);
			mdb_printf(MSG_ORIG(MSG_LMC_LINE3), lmc.lc_flags,
			    lmc.lc_now);
			mdb_printf(MSG_ORIG(MSG_LMC_LINE4), lmc.lc_flags,
			    lmc_bits);
			mdb_printf(MSG_ORIG(MSG_STR_DASHES));
			mdb_printf(MSG_ORIG(MSG_RTMAPS_TITLE0));
			mdb_printf(MSG_ORIG(MSG_STR_DASHES));

			if (lmc.lc_head) {
				if (mdb_pwalk(MSG_ORIG(MSG_RTMAPS_STR),
				    rtmap_format, (void *)0,
				    (uintptr_t)lmc.lc_head) == -1) {
					(void) mdb_dec_indent(4);
					return (DCMD_ERR);
				}
			} else
				mdb_printf(MSG_ORIG(MSG_FMT_RT), 0, 0, 0,
				    MSG_ORIG(MSG_STR_EMPTY));

			mdb_printf(MSG_ORIG(MSG_STR_DASHES));

			for (nitems = 1; nitems < al.al_nitems; nitems++) {
				datap += al.al_size;
				if (mdb_vread(&lmc, sizeof (Lm_cntl),
				    datap) == -1) {
					mdb_warn(MSG_ORIG(MSG_ERR_READ),
					    MSG_ORIG(MSG_LMLIST_STR), datap);
					(void) mdb_dec_indent(4);
					return (DCMD_ERR);
				}

				mdb_printf(MSG_ORIG(MSG_STR_DASHES));
				mdb_printf(MSG_ORIG(MSG_LMC_LINE1), datap);
				mdb_printf(MSG_ORIG(MSG_LMC_LINE2),
				    lmc.lc_head, lmc.lc_tail);
				mdb_printf(MSG_ORIG(MSG_LMC_LINE3),
				    lmc.lc_flags, lmc.lc_now);
				mdb_printf(MSG_ORIG(MSG_LMC_LINE4),
				    lmc.lc_flags, lmc_bits);
				mdb_printf(MSG_ORIG(MSG_STR_DASHES));
				mdb_printf(MSG_ORIG(MSG_RTMAPS_TITLE0));
				mdb_printf(MSG_ORIG(MSG_STR_DASHES));

				if (lmc.lc_head) {
					if (mdb_pwalk(MSG_ORIG(MSG_RTMAPS_STR),
					    rtmap_format, (void *)0,
					    (uintptr_t)lmc.lc_head) == -1) {
						(void) mdb_dec_indent(4);
						return (DCMD_ERR);
					}
				} else
					mdb_printf(MSG_ORIG(MSG_FMT_RT), 0, 0,
					    0, MSG_ORIG(MSG_STR_EMPTY));

				mdb_printf(MSG_ORIG(MSG_STR_DASHES));
			}
			(void) mdb_dec_indent(2);
		}
		(void) mdb_dec_indent(2);
	}

	mdb_printf(MSG_ORIG(MSG_LMLIST_LINE1), lml.lm_head, lml.lm_tail);
	mdb_printf(MSG_ORIG(MSG_LMLIST_LINE2), lml.lm_alp, lml.lm_rti);
	mdb_printf(MSG_ORIG(MSG_LMLIST_LINE3), lml.lm_handle, lml.lm_obj,
	    lml.lm_init, lml.lm_lazy);

	mdb_printf(MSG_ORIG(MSG_LMLIST_LINE4), lml.lm_flags);
	if (lml.lm_flags)
		mdb_printf(MSG_ORIG(MSG_LMLIST_LINE6), lml.lm_flags,
		    lml_flags_bit);

	mdb_printf(MSG_ORIG(MSG_LMLIST_LINE5), lml.lm_tflags);
	if (lml.lm_tflags)
		mdb_printf(MSG_ORIG(MSG_LMLIST_LINE6), lml.lm_tflags,
		    lml_tflags_bit);

	return (DCMD_OK);
}

static int
/* ARGSUSED2 */
dcmd_Lm_list(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	GElf_Sym	gsym;
	APlist		*aplp, apl;
	uintptr_t	datap, nitems;

	/*
	 * If an address was provided us it.
	 */
	if (flags & DCMD_ADDRSPEC)
		return (_dcmd_Lm_list(addr, flags, argc, argv));

	/*
	 * Otherwise traverse the dynlm_list and display each link-map list.
	 */
	if (mdb_lookup_by_obj(MSG_ORIG(MSG_STR_LDSO1),
	    MSG_ORIG(MSG_STR_DYNLMLIST), &gsym) == -1) {
		mdb_warn(MSG_ORIG(MSG_ERR_SYMFAILED), MSG_ORIG(MSG_STR_LDSO1),
		    MSG_ORIG(MSG_STR_DYNLMLIST));
		return (DCMD_ERR);
	}
	if (mdb_vread(&aplp, sizeof (APlist *),
	    (uintptr_t)gsym.st_value) == -1) {
		mdb_warn(MSG_ORIG(MSG_ERR_READ), MSG_ORIG(MSG_STR_APLIST),
		    gsym.st_value);
		return (DCMD_ERR);
	}
	if (aplp == NULL) {
		mdb_printf(MSG_ORIG(MSG_LMLIST_TITLE0),
		    MSG_ORIG(MSG_STR_DYNLMLIST));
		return (DCMD_OK);
	}

	if (mdb_vread(&apl, sizeof (APlist), (uintptr_t)aplp) == -1) {
		mdb_warn(MSG_ORIG(MSG_ERR_READ), MSG_ORIG(MSG_STR_APLIST),
		    aplp);
		return (DCMD_ERR);
	}

	mdb_printf(MSG_ORIG(MSG_LMLIST_TITLE1), MSG_ORIG(MSG_STR_DYNLMLIST),
	    aplp, (size_t)apl.apl_nitems, (size_t)apl.apl_arritems);
	mdb_printf(MSG_ORIG(MSG_STR_DASHES));

	flags |= (DCMD_LOOP | DCMD_LOOPFIRST);
	for (datap = (uintptr_t)aplp + APLIST_OFF_DATA, nitems = 0;
	    nitems < apl.apl_nitems; nitems++, datap += sizeof (void *)) {
		Lm_list	*lml;

		if (mdb_vread(&lml, sizeof (Lm_list *), datap) == -1) {
			mdb_warn(MSG_ORIG(MSG_ERR_READ),
			    MSG_ORIG(MSG_LMLIST_STR), datap);
			return (DCMD_ERR);
		}

		(void) mdb_inc_indent(2);
		if (_dcmd_Lm_list((uintptr_t)lml, flags, argc,
		    argv) == DCMD_ERR) {
			(void) mdb_dec_indent(2);
			return (DCMD_ERR);
		}
		(void) mdb_dec_indent(2);
		flags &= ~DCMD_LOOPFIRST;
	}
	return (DCMD_OK);
}

void
dcmd_GrpDesc_help(void)
{
	mdb_printf(MSG_ORIG(MSG_GRPDESC_HELP));
}

static int
/* ARGSUSED2 */
dcmd_GrpDesc(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	Grp_desc	gd;
	char		*str;

	/*
	 * Insure we have a valid address.
	 */
	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_warn(MSG_ORIG(MSG_ERR_NAS), MSG_ORIG(MSG_GRPDESC_STR));
		return (DCMD_USAGE);
	}

	mdb_printf(MSG_ORIG(MSG_GRPDESC_LINE1), addr);
	if (mdb_vread(&gd, sizeof (Grp_desc), addr) == -1) {
		mdb_warn(MSG_ORIG(MSG_ERR_READ), MSG_ORIG(MSG_GRPDESC_STR),
		    addr);
		return (DCMD_ERR);
	}

	if ((str = Rtmap_Name((uintptr_t)gd.gd_depend)) == 0)
		return (DCMD_ERR);

	mdb_printf(MSG_ORIG(MSG_GRPDESC_LINE2), gd.gd_depend, str);
	mdb_printf(MSG_ORIG(MSG_GRPDESC_LINE3), gd.gd_flags, gd.gd_flags,
	    grdflags_bits);

	return (DCMD_OK);
}

void
dcmd_GrpHdl_help(void)
{
	mdb_printf(MSG_ORIG(MSG_GRPHDL_HELP));
}

static int
/* ARGSUSED2 */
dcmd_GrpHdl(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	Grp_hdl		gh;
	Alist		al;
	uintptr_t	datap, listidx;
	char		*str;
	uint_t		flg = 0;

	/*
	 * Insure we have a valid address, and provide for a -v option.
	 */
	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_warn(MSG_ORIG(MSG_ERR_NAS), MSG_ORIG(MSG_GRPHDL_STR));
		return (DCMD_USAGE);
	}
	if (mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, RTLD_FLG_VERBOSE,
	    &flg, NULL) != argc)
		return (DCMD_USAGE);

	mdb_printf(MSG_ORIG(MSG_GRPHDL_LINE1), addr);
	mdb_printf(MSG_ORIG(MSG_STR_DASHES));

	if (mdb_vread(&gh, sizeof (Grp_hdl), addr) == -1) {
		mdb_warn(MSG_ORIG(MSG_ERR_READ), MSG_ORIG(MSG_GRPHDL_STR),
		    addr);
		return (DCMD_ERR);
	}

	/*
	 * Determine the handles owner.  Note that an orphaned handle may no
	 * longer contain its originating owner.
	 */
	if (gh.gh_ownlmp) {
		if ((str = Rtmap_Name((uintptr_t)gh.gh_ownlmp)) == 0)
			return (DCMD_ERR);
	} else
		str = (char *)MSG_ORIG(MSG_STR_ORPHANED);

	mdb_printf(MSG_ORIG(MSG_GRPHDL_LINE2), str);
	mdb_printf(MSG_ORIG(MSG_GRPHDL_LINE3), gh.gh_flags, gh.gh_flags,
	    grhflags_bits);

	if (gh.gh_depends == 0) {
		mdb_printf(MSG_ORIG(MSG_GRPHDL_LINE4), gh.gh_refcnt);
		return (DCMD_OK);
	}

	addr = (uintptr_t)gh.gh_depends;
	if (mdb_vread(&al, sizeof (Alist), addr) == -1) {
		mdb_warn(MSG_ORIG(MSG_ERR_READ), MSG_ORIG(MSG_STR_ALIST), addr);
		return (DCMD_ERR);
	}

	mdb_printf(MSG_ORIG(MSG_GRPHDL_LINE5), gh.gh_refcnt, addr,
	    (size_t)al.al_nitems, (size_t)al.al_arritems);

	if (((flg & RTLD_FLG_VERBOSE) == 0) || (al.al_nitems == 0))
		return (DCMD_OK);

	(void) mdb_inc_indent(4);
	mdb_printf(MSG_ORIG(MSG_STR_DASHES));

	/*
	 * Under verbose mode print the name of each dependency.  An Alist can
	 * have a variable number of data items, so read each individual entry.
	 */
	datap = ALIST_OFF_DATA + (uintptr_t)addr;
	if (dcmd_GrpDesc(datap, flags, argc, argv) == DCMD_ERR) {
		(void) mdb_dec_indent(4);
		return (DCMD_ERR);
	}

	for (listidx = 1; listidx < al.al_nitems; listidx++) {
		datap += al.al_size;
		mdb_printf(MSG_ORIG(MSG_STR_DASHES));
		if (dcmd_GrpDesc(datap, flags, argc, argv) == DCMD_ERR) {
			(void) mdb_dec_indent(4);
			return (DCMD_ERR);
		}
	}

	(void) mdb_dec_indent(4);
	return (DCMD_OK);
}

static void
dcmd_Handles_help(void)
{
	mdb_printf(MSG_ORIG(MSG_HANDLES_HELP));
}

static int
dcmd_Handles(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	Rt_map		rtmap;
	char		*str;
	uint_t		flg = 0;
	APlist		apl;
	uintptr_t	datap, nitems;
	Grp_hdl		*ghp;

	/*
	 * Insure we have a valid address, and provide for a -v option.
	 */
	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_warn(MSG_ORIG(MSG_ERR_NAS), MSG_ORIG(MSG_HANDLES_STR));
		return (DCMD_USAGE);
	}
	if (mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, RTLD_FLG_VERBOSE,
	    &flg, NULL) != argc)
		return (DCMD_USAGE);

	/*
	 * Read the Rt_map contents.
	 */
	if (mdb_vread(&rtmap, sizeof (Rt_map), addr) == -1) {
		mdb_warn(MSG_ORIG(MSG_ERR_READ), MSG_ORIG(MSG_RTMAP_STR), addr);
		return (DCMD_ERR);
	}
	if ((str = String((uintptr_t)NAME(&rtmap),
	    MSG_ORIG(MSG_STR_NAME))) == 0)
		return (DCMD_ERR);

	mdb_printf(MSG_ORIG(MSG_HANDLES_LINE1), str);
	mdb_printf(MSG_ORIG(MSG_STR_DASHES));

	if (HANDLES(&rtmap) == 0)
		return (DCMD_OK);

	addr = (uintptr_t)HANDLES(&rtmap);
	if (mdb_vread(&apl, sizeof (APlist), addr) == -1) {
		mdb_warn(MSG_ORIG(MSG_ERR_READ), MSG_ORIG(MSG_STR_APLIST),
		    addr);
		return (DCMD_ERR);
	}

	mdb_printf(MSG_ORIG(MSG_HANDLES_LINE2), addr, (size_t)apl.apl_nitems,
	    (size_t)apl.apl_arritems);

	if (((flg & RTLD_FLG_VERBOSE) == 0) || (apl.apl_nitems == 0))
		return (DCMD_OK);

	/*
	 * Under verbose mode print the name of each dependency.  An APlist can
	 * have a variable number of data items, so read each individual entry.
	 */
	datap = addr + APLIST_OFF_DATA;
	if (mdb_vread(&ghp, sizeof (Grp_hdl *), datap) == -1) {
		mdb_warn(MSG_ORIG(MSG_ERR_READ),
		    MSG_ORIG(MSG_GRPHDL_STR), datap);
		return (DCMD_ERR);
	}

	(void) mdb_inc_indent(4);
	mdb_printf(MSG_ORIG(MSG_STR_DASHES));

	if (dcmd_GrpHdl((uintptr_t)ghp, flags, argc, argv) == DCMD_ERR) {
		(void) mdb_dec_indent(4);
		return (DCMD_ERR);
	}

	nitems = 1;
	for (nitems = 1; nitems < apl.apl_nitems; nitems++) {
		datap += sizeof (void *);
		if (mdb_vread(&ghp, sizeof (Grp_hdl *), datap) == -1) {
			mdb_warn(MSG_ORIG(MSG_ERR_READ),
			    MSG_ORIG(MSG_GRPHDL_STR), datap);
			return (DCMD_ERR);
		}

		mdb_printf(MSG_ORIG(MSG_STR_DASHES));
		if (dcmd_GrpHdl((uintptr_t)ghp, flags, argc,
		    argv) == DCMD_ERR) {
			(void) mdb_dec_indent(4);
			return (DCMD_ERR);
		}
	}
	(void) mdb_dec_indent(4);
	return (DCMD_OK);
}

static void
dcmd_Groups_help(void)
{
	mdb_printf(MSG_ORIG(MSG_GROUPS_HELP));
}


static int
dcmd_Groups(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	Rt_map		rtmap;
	char		*str;
	APlist		apl;
	uint_t		flg = 0;
	uintptr_t	datap, nitems;
	Grp_hdl		*ghp;

	/*
	 * Insure we have a valid address, and provide for a -v option.
	 */
	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_warn(MSG_ORIG(MSG_ERR_NAS), MSG_ORIG(MSG_GROUPS_STR));
		return (DCMD_USAGE);
	}
	if (mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, RTLD_FLG_VERBOSE,
	    &flg, NULL) != argc)
		return (DCMD_USAGE);

	/*
	 * Read the Rt_map contents.
	 */
	if (mdb_vread(&rtmap, sizeof (Rt_map), addr) == -1) {
		mdb_warn(MSG_ORIG(MSG_ERR_READ), MSG_ORIG(MSG_RTMAP_STR), addr);
		return (DCMD_ERR);
	}
	if ((str = String((uintptr_t)NAME(&rtmap),
	    MSG_ORIG(MSG_STR_NAME))) == 0)
		return (DCMD_ERR);

	mdb_printf(MSG_ORIG(MSG_GROUPS_LINE1), str);
	mdb_printf(MSG_ORIG(MSG_STR_DASHES));

	if (GROUPS(&rtmap) == 0)
		return (DCMD_OK);

	addr = (uintptr_t)GROUPS(&rtmap);
	if (mdb_vread(&apl, sizeof (APlist), addr) == -1) {
		mdb_warn(MSG_ORIG(MSG_ERR_READ), MSG_ORIG(MSG_STR_APLIST),
		    addr);
		return (DCMD_ERR);
	}

	mdb_printf(MSG_ORIG(MSG_GROUPS_LINE2), addr, (size_t)apl.apl_nitems,
	    (size_t)apl.apl_arritems);

	if (((flg & RTLD_FLG_VERBOSE) == 0) || (apl.apl_nitems == 0))
		return (DCMD_OK);

	/*
	 * Under verbose mode print the name of each dependency.  An APlist can
	 * have a variable number of data items, so read each individual entry.
	 */
	datap = addr + APLIST_OFF_DATA;
	if (mdb_vread(&ghp, sizeof (Grp_hdl *), datap) == -1) {
		mdb_warn(MSG_ORIG(MSG_ERR_READ),
		    MSG_ORIG(MSG_GRPHDL_STR), datap);
		return (DCMD_ERR);
	}

	(void) mdb_inc_indent(4);
	mdb_printf(MSG_ORIG(MSG_STR_DASHES));

	if (dcmd_GrpHdl((uintptr_t)ghp, flags, argc, argv) == DCMD_ERR) {
		(void) mdb_dec_indent(4);
		return (DCMD_ERR);
	}

	for (nitems = 1; nitems < apl.apl_nitems; nitems++) {
		datap += sizeof (void *);
		if (mdb_vread(&ghp, sizeof (Grp_hdl *), datap) == -1) {
			mdb_warn(MSG_ORIG(MSG_ERR_READ),
			    MSG_ORIG(MSG_GRPHDL_STR), datap);
			return (DCMD_ERR);
		}

		mdb_printf(MSG_ORIG(MSG_STR_DASHES));
		if (dcmd_GrpHdl((uintptr_t)ghp, flags, argc,
		    argv) == DCMD_ERR) {
			(void) mdb_dec_indent(4);
			return (DCMD_ERR);
		}
	}
	(void) mdb_dec_indent(4);
	return (DCMD_OK);
}
static void
dcmd_ElfDyn_help(void)
{
	mdb_printf(MSG_ORIG(MSG_ELFDYN_HELP));
}

static int
/* ARGSUSED2 */
dcmd_ElfDyn(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	Dyn		dyn;
	const char	*dynstr;
	Conv_inv_buf_t	inv_buf;

	if ((flags & DCMD_ADDRSPEC) == 0)
		return (DCMD_USAGE);
	if (mdb_vread(&dyn, sizeof (dyn), addr) == -1) {
		mdb_warn(MSG_ORIG(MSG_ERR_READ), MSG_ORIG(MSG_ELFDYN_STR),
		    addr);
		return (DCMD_ERR);
	}

	mdb_printf(MSG_ORIG(MSG_ELFDYN_TITLE), addr);
	dynstr = conv_dyn_tag(dyn.d_tag, ELFOSABI_SOLARIS, M_MACH, 0, &inv_buf);
	mdb_printf(MSG_ORIG(MSG_ELFDYN_LINE1), addr, dynstr, dyn.d_un.d_ptr);

	mdb_set_dot(addr + sizeof (Dyn));

	return (DCMD_OK);
}

static void
dcmd_ElfEhdr_help(void)
{
	mdb_printf(MSG_ORIG(MSG_EHDR_HELP));
}

static int
/* ARGSUSED2 */
dcmd_ElfEhdr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	Ehdr			ehdr;
	Byte			*byte;
	const char		*flgs;
	Conv_inv_buf_t		inv_buf1, inv_buf2;
	Conv_ehdr_flags_buf_t	ehdr_flags_buf;


	if ((flags & DCMD_ADDRSPEC) == 0)
		return (DCMD_USAGE);

	if (mdb_vread(&ehdr, sizeof (ehdr), addr) == -1) {
		mdb_warn(MSG_ORIG(MSG_ERR_READ), MSG_ORIG(MSG_EHDR_STR),
		    addr);
		return (DCMD_ERR);
	}

	mdb_printf(MSG_ORIG(MSG_EHDR_TITLE), addr);
	byte = &ehdr.e_ident[0];
	mdb_printf(MSG_ORIG(MSG_EHDR_LINE1), byte[EI_MAG0],
	    (byte[EI_MAG1] ? byte[EI_MAG1] : '0'),
	    (byte[EI_MAG2] ? byte[EI_MAG2] : '0'),
	    (byte[EI_MAG3] ? byte[EI_MAG3] : '0'));
	mdb_printf(MSG_ORIG(MSG_EHDR_LINE2),
	    conv_ehdr_class(ehdr.e_ident[EI_CLASS], 0, &inv_buf1),
	    conv_ehdr_data(ehdr.e_ident[EI_DATA], 0, &inv_buf2));

	mdb_printf(MSG_ORIG(MSG_EHDR_LINE3),
	    conv_ehdr_mach(ehdr.e_machine, 0, &inv_buf1),
	    conv_ehdr_vers(ehdr.e_version, 0, &inv_buf2));
	mdb_printf(MSG_ORIG(MSG_EHDR_LINE4),
	    conv_ehdr_type(ehdr.e_ident[EI_OSABI], ehdr.e_type, 0, &inv_buf1));

	/*
	 * Line up the flags differently depending on whether we
	 * received a numeric (e.g. "0x200") or text representation
	 * (e.g. "[ EF_SPARC_SUN_US1 ]").
	 */
	flgs = conv_ehdr_flags(ehdr.e_machine, ehdr.e_flags,
	    0, &ehdr_flags_buf);
	if (flgs[0] == '[')
		mdb_printf(MSG_ORIG(MSG_EHDR_LINE5), flgs);
	else
		mdb_printf(MSG_ORIG(MSG_EHDR_LINE6), flgs);

	mdb_printf(MSG_ORIG(MSG_EHDR_LINE7), ehdr.e_entry, ehdr.e_ehsize,
	    ehdr.e_shstrndx);
	mdb_printf(MSG_ORIG(MSG_EHDR_LINE8), ehdr.e_shoff, ehdr.e_shentsize,
	    ehdr.e_shnum);
	mdb_printf(MSG_ORIG(MSG_EHDR_LINE9), ehdr.e_phoff, ehdr.e_phentsize,
	    ehdr.e_phnum);

	mdb_set_dot(addr + sizeof (Ehdr));

	return (DCMD_OK);
}

static void
dcmd_ElfPhdr_help(void)
{
	mdb_printf(MSG_ORIG(MSG_EPHDR_HELP));
}

static int
/* ARGSUSED2 */
dcmd_ElfPhdr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	Phdr			phdr;
	Conv_inv_buf_t		inv_buf;
	Conv_phdr_flags_buf_t	phdr_flags_buf;

	if ((flags & DCMD_ADDRSPEC) == 0)
		return (DCMD_USAGE);

	if (mdb_vread(&phdr, sizeof (phdr), addr) == -1) {
		mdb_warn(MSG_ORIG(MSG_ERR_READ), MSG_ORIG(MSG_EPHDR_STR),
		    addr);
		return (DCMD_ERR);
	}

	mdb_printf(MSG_ORIG(MSG_EPHDR_TITLE), addr);
	mdb_printf(MSG_ORIG(MSG_EPHDR_LINE1), phdr.p_vaddr,
	    conv_phdr_flags(ELFOSABI_SOLARIS, phdr.p_flags, 0,
	    &phdr_flags_buf));
	mdb_printf(MSG_ORIG(MSG_EPHDR_LINE2), phdr.p_paddr,
	    conv_phdr_type(ELFOSABI_SOLARIS, M_MACH, phdr.p_type, 0, &inv_buf));
	mdb_printf(MSG_ORIG(MSG_EPHDR_LINE3), phdr.p_filesz, phdr.p_memsz);
	mdb_printf(MSG_ORIG(MSG_EPHDR_LINE4), phdr.p_offset, phdr.p_align);

	mdb_set_dot(addr + sizeof (Phdr));

	return (DCMD_OK);
}


static const mdb_dcmd_t dcmds[] = {
	{ MSG_ORIG(MSG_BND_STR), MSG_ORIG(MSG_USG_ADDREQ_V),
		MSG_ORIG(MSG_BND_DCD),
		dcmd_Bind, dcmd_Bind_help},
	{ MSG_ORIG(MSG_DEPENDS_STR), MSG_ORIG(MSG_USG_ADDREQ_V),
		MSG_ORIG(MSG_DEPENDS_DCD),
		dcmd_Depends, dcmd_Depends_help},
	{ MSG_ORIG(MSG_CALLERS_STR), MSG_ORIG(MSG_USG_ADDREQ_V),
		MSG_ORIG(MSG_CALLERS_DCD),
		dcmd_Callers, dcmd_Callers_help},
	{ MSG_ORIG(MSG_GRPHDL_STR), MSG_ORIG(MSG_USG_ADDREQ_V),
		MSG_ORIG(MSG_GRPHDL_DCD),
		dcmd_GrpHdl, dcmd_GrpHdl_help},
	{ MSG_ORIG(MSG_GRPDESC_STR), MSG_ORIG(MSG_USG_ADDREQ_V),
		MSG_ORIG(MSG_GRPDESC_DCD),
		dcmd_GrpDesc, dcmd_GrpDesc_help},
	{ MSG_ORIG(MSG_HANDLES_STR), MSG_ORIG(MSG_USG_ADDREQ_V),
		MSG_ORIG(MSG_HANDLES_DCD),
		dcmd_Handles, dcmd_Handles_help},
	{ MSG_ORIG(MSG_GROUPS_STR), MSG_ORIG(MSG_USG_ADDREQ_V),
		MSG_ORIG(MSG_GROUPS_DCD),
		dcmd_Groups, dcmd_Groups_help},
	{ MSG_ORIG(MSG_ELFDYN_STR), MSG_ORIG(MSG_USG_ADDREQ),
		MSG_ORIG(MSG_ELFDYN_DCD),
		dcmd_ElfDyn, dcmd_ElfDyn_help},
	{ MSG_ORIG(MSG_EHDR_STR), MSG_ORIG(MSG_USG_ADDREQ),
		MSG_ORIG(MSG_EHDR_DCD),
		dcmd_ElfEhdr, dcmd_ElfEhdr_help},
	{ MSG_ORIG(MSG_EPHDR_STR), MSG_ORIG(MSG_USG_ADDREQ),
		MSG_ORIG(MSG_EPHDR_DCD),
		dcmd_ElfPhdr, dcmd_ElfPhdr_help},
	{ MSG_ORIG(MSG_LMLIST_STR), MSG_ORIG(MSG_USG_ADDREQ_V),
		MSG_ORIG(MSG_LMLIST_DCD),
		dcmd_Lm_list, dcmd_Lm_list_help},
	{ MSG_ORIG(MSG_RTMAPS_STR), MSG_ORIG(MSG_USG_ADDOPT_V),
		MSG_ORIG(MSG_RTMAPS_DCD),
		dcmd_Rtmaps, dcmd_Rtmaps_help},
	{ MSG_ORIG(MSG_RTMAP_STR), MSG_ORIG(MSG_USG_ADDREQ),
		MSG_ORIG(MSG_RTMAP_DCD),
		dcmd_rtmap, dcmd_rtmap_help},
	{ MSG_ORIG(MSG_SETENV_STR), MSG_ORIG(MSG_USG_SETENV),
		MSG_ORIG(MSG_SETENV_DCD),
		dcmd_Setenv, dcmd_Setenv_help},
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ MSG_ORIG(MSG_RTMAPS_STR), MSG_ORIG(MSG_WWD_RTMAP),
		walk_rtmap_init, walk_rtmap_step, NULL, NULL },
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, walkers
};

const	mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
