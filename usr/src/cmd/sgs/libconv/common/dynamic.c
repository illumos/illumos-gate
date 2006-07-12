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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * String conversion routine for .dynamic tag entries.
 */
#include	<stdio.h>
#include	<string.h>
#include	<sys/elf_SPARC.h>
#include	"rtld.h"
#include	"_conv.h"
#include	"dynamic_msg.h"

#define	POSSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
		MSG_DFP_LAZYLOAD_ALT_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DFP_GROUPPERM_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		CONV_INV_STRSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

const char *
conv_dyn_posflag1(Xword flags, int fmt_flags)
{
	static char	string[POSSZ];
	static Val_desc vda[] = {
		{ DF_P1_LAZYLOAD,	MSG_ORIG(MSG_DFP_LAZYLOAD) },
		{ DF_P1_GROUPPERM,	MSG_ORIG(MSG_DFP_GROUPPERM) },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = { string, sizeof (string), vda };
	static Val_desc vda_alt[] = {
		{ DF_P1_LAZYLOAD,	MSG_ORIG(MSG_DFP_LAZYLOAD_ALT) },
		{ DF_P1_GROUPPERM,	MSG_ORIG(MSG_DFP_GROUPPERM) },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg_alt = { string, sizeof (string),
		vda_alt, NULL, 0, 0, MSG_ORIG(MSG_STR_EMPTY), NULL,
		MSG_ORIG(MSG_STR_EMPTY) };

	CONV_EXPN_FIELD_ARG *arg;

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	arg = (fmt_flags & CONV_FMT_ALTDUMP) ? &conv_arg_alt : &conv_arg;
	arg->oflags = arg->rflags = flags;
	(void) conv_expn_field(arg);

	return ((const char *)string);
}

#define	FLAGSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
		MSG_DF_ORIGIN_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF_SYMBOLIC_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF_TEXTREL_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF_BIND_NOW_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF_STATIC_TLS_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		CONV_INV_STRSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

const char *
conv_dyn_flag(Xword flags, int fmt_flags)
{
	static char	string[FLAGSZ];
	static Val_desc vda[] = {
		{ DF_ORIGIN,		MSG_ORIG(MSG_DF_ORIGIN) },
		{ DF_SYMBOLIC,		MSG_ORIG(MSG_DF_SYMBOLIC) },
		{ DF_TEXTREL,		MSG_ORIG(MSG_DF_TEXTREL) },
		{ DF_BIND_NOW,		MSG_ORIG(MSG_DF_BIND_NOW) },
		{ DF_STATIC_TLS,	MSG_ORIG(MSG_DF_STATIC_TLS) },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = { string, sizeof (string), vda };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	conv_arg.oflags = conv_arg.rflags = flags;
	if (fmt_flags & CONV_FMT_ALTDUMP) {
		conv_arg.prefix = conv_arg.suffix = MSG_ORIG(MSG_STR_EMPTY);
	} else {
		conv_arg.prefix = conv_arg.suffix = NULL;
	}
	(void) conv_expn_field(&conv_arg);

	return ((const char *)string);
}

#define	FLAG1SZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
		MSG_DF1_NOW_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF1_GLOBAL_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF1_GROUP_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF1_NODELETE_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF1_LOADFLTR_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF1_INITFIRST_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF1_NOOPEN_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF1_ORIGIN_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF1_DIRECT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF1_TRANS_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF1_INTERPOSE_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF1_NODEFLIB_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF1_NODUMP_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF1_CONFALT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF1_ENDFILTEE_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF1_DISPRELPND_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF1_DISPRELDNE_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF1_NODIRECT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF1_IGNMULDEF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF1_NOKSYMS_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF1_NORELOC_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF1_NOHDR_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		CONV_INV_STRSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

const char *
conv_dyn_flag1(Xword flags)
{
	static char	string[FLAG1SZ];
	static Val_desc vda[] = {
		{ DF_1_NOW,		MSG_ORIG(MSG_DF1_NOW) },
		{ DF_1_GLOBAL,		MSG_ORIG(MSG_DF1_GLOBAL) },
		{ DF_1_GROUP,		MSG_ORIG(MSG_DF1_GROUP) },
		{ DF_1_NODELETE,	MSG_ORIG(MSG_DF1_NODELETE) },
		{ DF_1_LOADFLTR,	MSG_ORIG(MSG_DF1_LOADFLTR) },
		{ DF_1_INITFIRST,	MSG_ORIG(MSG_DF1_INITFIRST) },
		{ DF_1_NOOPEN,		MSG_ORIG(MSG_DF1_NOOPEN) },
		{ DF_1_ORIGIN,		MSG_ORIG(MSG_DF1_ORIGIN) },
		{ DF_1_DIRECT,		MSG_ORIG(MSG_DF1_DIRECT) },
		{ DF_1_TRANS,		MSG_ORIG(MSG_DF1_TRANS) },
		{ DF_1_INTERPOSE,	MSG_ORIG(MSG_DF1_INTERPOSE) },
		{ DF_1_NODEFLIB,	MSG_ORIG(MSG_DF1_NODEFLIB) },
		{ DF_1_NODUMP,		MSG_ORIG(MSG_DF1_NODUMP) },
		{ DF_1_CONFALT,		MSG_ORIG(MSG_DF1_CONFALT) },
		{ DF_1_ENDFILTEE,	MSG_ORIG(MSG_DF1_ENDFILTEE) },
		{ DF_1_DISPRELPND,	MSG_ORIG(MSG_DF1_DISPRELPND) },
		{ DF_1_DISPRELDNE,	MSG_ORIG(MSG_DF1_DISPRELDNE) },
		{ DF_1_NODIRECT,	MSG_ORIG(MSG_DF1_NODIRECT) },
		{ DF_1_IGNMULDEF,	MSG_ORIG(MSG_DF1_IGNMULDEF) },
		{ DF_1_NOKSYMS,		MSG_ORIG(MSG_DF1_NOKSYMS) },
		{ DF_1_NORELOC,		MSG_ORIG(MSG_DF1_NORELOC) },
		{ DF_1_NOHDR,		MSG_ORIG(MSG_DF1_NOHDR) },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = { string, sizeof (string), vda };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	conv_arg.oflags = conv_arg.rflags = flags;
	(void) conv_expn_field(&conv_arg);

	return ((const char *)string);
}

#define	FEATSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
		MSG_DTF_PARINIT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DTF_CONFEXP_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		CONV_INV_STRSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

const char *
conv_dyn_feature1(Xword flags, int fmt_flags)
{
	static char	string[FEATSZ];
	static Val_desc vda[] = {
		{ DTF_1_PARINIT,	MSG_ORIG(MSG_DTF_PARINIT) },
		{ DTF_1_CONFEXP,	MSG_ORIG(MSG_DTF_CONFEXP) },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = { string, sizeof (string), vda };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	conv_arg.oflags = conv_arg.rflags = flags;
	if (fmt_flags & CONV_FMT_ALTDUMP) {
		conv_arg.prefix = conv_arg.suffix = MSG_ORIG(MSG_STR_EMPTY);
	} else {
		conv_arg.prefix = conv_arg.suffix = NULL;
	}
	(void) conv_expn_field(&conv_arg);

	return ((const char *)string);
}

const char *
conv_dyn_tag(Xword tag, Half mach, int fmt_flags)
{
	static char		string[CONV_INV_STRSIZE];
	static const Msg	tags[DT_MAXPOSTAGS] = {
		MSG_DYN_NULL,		MSG_DYN_NEEDED,
		MSG_DYN_PLTRELSZ,	MSG_DYN_PLTGOT,
		MSG_DYN_HASH,		MSG_DYN_STRTAB,
		MSG_DYN_SYMTAB,		MSG_DYN_RELA,
		MSG_DYN_RELASZ,		MSG_DYN_RELAENT,
		MSG_DYN_STRSZ,		MSG_DYN_SYMENT,
		MSG_DYN_INIT,		MSG_DYN_FINI,
		MSG_DYN_SONAME,		MSG_DYN_RPATH,
		MSG_DYN_SYMBOLIC,	MSG_DYN_REL,
		MSG_DYN_RELSZ,		MSG_DYN_RELENT,
		MSG_DYN_PLTREL,		MSG_DYN_DEBUG,
		MSG_DYN_TEXTREL,	MSG_DYN_JMPREL,
		MSG_DYN_BIND_NOW,	MSG_DYN_INIT_ARRAY,
		MSG_DYN_FINI_ARRAY,	MSG_DYN_INIT_ARRAYSZ,
		MSG_DYN_FINI_ARRAYSZ,	MSG_DYN_RUNPATH,
		MSG_DYN_FLAGS,		MSG_DYN_NULL,
		MSG_DYN_PREINIT_ARRAY,	MSG_DYN_PREINIT_ARRAYSZ
	};
	static const Msg	tags_alt[DT_MAXPOSTAGS] = {
		MSG_DYN_NULL,		MSG_DYN_NEEDED,
		MSG_DYN_PLTRELSZ_ALT,	MSG_DYN_PLTGOT,
		MSG_DYN_HASH,		MSG_DYN_STRTAB,
		MSG_DYN_SYMTAB,		MSG_DYN_RELA,
		MSG_DYN_RELASZ,		MSG_DYN_RELAENT,
		MSG_DYN_STRSZ,		MSG_DYN_SYMENT,
		MSG_DYN_INIT,		MSG_DYN_FINI,
		MSG_DYN_SONAME,		MSG_DYN_RPATH,
		MSG_DYN_SYMBOLIC_ALT,	MSG_DYN_REL,
		MSG_DYN_RELSZ,		MSG_DYN_RELENT,
		MSG_DYN_PLTREL,		MSG_DYN_DEBUG,
		MSG_DYN_TEXTREL,	MSG_DYN_JMPREL,
		MSG_DYN_BIND_NOW,	MSG_DYN_INIT_ARRAY,
		MSG_DYN_FINI_ARRAY,	MSG_DYN_INIT_ARRAYSZ,
		MSG_DYN_FINI_ARRAYSZ,	MSG_DYN_RUNPATH,
		MSG_DYN_FLAGS,		MSG_DYN_NULL,
		MSG_DYN_PREINIT_ARRAY,	MSG_DYN_PREINIT_ARRAYSZ
	};

	if (tag < DT_MAXPOSTAGS) {
		/*
		 * Generic dynamic tags.
		 */
		return ((fmt_flags & CONV_FMTALTMASK)
			? MSG_ORIG(tags_alt[tag]) : MSG_ORIG(tags[tag]));
	} else {
		/*
		 * SUNW: DT_LOOS -> DT_HIOS range.
		 */
		if (tag == DT_SUNW_AUXILIARY)
			return (MSG_ORIG(MSG_DYN_SUNW_AUXILIARY));
		else if (tag == DT_SUNW_RTLDINF)
			return (MSG_ORIG(MSG_DYN_SUNW_RTLDINF));
		else if (tag == DT_SUNW_FILTER)
			return (MSG_ORIG(MSG_DYN_SUNW_FILTER));
		else if (tag == DT_SUNW_CAP)
			return (MSG_ORIG(MSG_DYN_SUNW_CAP));

		/*
		 * SUNW: DT_VALRNGLO - DT_VALRNGHI range.
		 */
		else if (tag == DT_CHECKSUM)
			return (MSG_ORIG(MSG_DYN_CHECKSUM));
		else if (tag == DT_PLTPADSZ)
			return (MSG_ORIG(MSG_DYN_PLTPADSZ));
		else if (tag == DT_MOVEENT)
			return (MSG_ORIG(MSG_DYN_MOVEENT));
		else if (tag == DT_MOVESZ)
			return (MSG_ORIG(MSG_DYN_MOVESZ));
		else if (tag == DT_FEATURE_1)
			return (MSG_ORIG(MSG_DYN_FEATURE_1));
		else if (tag == DT_POSFLAG_1)
			return (MSG_ORIG(MSG_DYN_POSFLAG_1));
		else if (tag == DT_SYMINSZ)
			return (MSG_ORIG(MSG_DYN_SYMINSZ));
		else if (tag == DT_SYMINENT)
			return (MSG_ORIG(MSG_DYN_SYMINENT));

		/*
		 * SUNW: DT_ADDRRNGLO - DT_ADDRRNGHI range.
		 */
		else if (tag == DT_CONFIG)
			return (MSG_ORIG(MSG_DYN_CONFIG));
		else if (tag == DT_DEPAUDIT)
			return (MSG_ORIG(MSG_DYN_DEPAUDIT));
		else if (tag == DT_AUDIT)
			return (MSG_ORIG(MSG_DYN_AUDIT));
		else if (tag == DT_PLTPAD)
			return (MSG_ORIG(MSG_DYN_PLTPAD));
		else if (tag == DT_MOVETAB)
			return (MSG_ORIG(MSG_DYN_MOVETAB));
		else if (tag == DT_SYMINFO)
			return (MSG_ORIG(MSG_DYN_SYMINFO));

		/*
		 * SUNW: generic range.
		 */
		else if (tag == DT_VERSYM)
			return (MSG_ORIG(MSG_DYN_VERSYM));
		else if (tag == DT_RELACOUNT)
			return (MSG_ORIG(MSG_DYN_RELACOUNT));
		else if (tag == DT_RELCOUNT)
			return (MSG_ORIG(MSG_DYN_RELCOUNT));
		else if (tag == DT_FLAGS_1)
			return (MSG_ORIG(MSG_DYN_FLAGS_1));
		else if (tag == DT_VERDEF)
			return (MSG_ORIG(MSG_DYN_VERDEF));
		else if (tag == DT_VERDEFNUM)
			return (MSG_ORIG(MSG_DYN_VERDEFNUM));
		else if (tag == DT_VERNEED)
			return (MSG_ORIG(MSG_DYN_VERNEED));
		else if (tag == DT_VERNEEDNUM)
			return (MSG_ORIG(MSG_DYN_VERNEEDNUM));
		else if (tag == DT_AUXILIARY)
			return (MSG_ORIG(MSG_DYN_AUXILIARY));
		else if (tag == DT_USED)
			return (MSG_ORIG(MSG_DYN_USED));
		else if (tag == DT_FILTER)
			return (MSG_ORIG(MSG_DYN_FILTER));

		/*
		 * SUNW: machine specific range.
		 */
		else if (((mach == EM_SPARC) || (mach == EM_SPARCV9) ||
		    (mach == EM_SPARC32PLUS)) && (tag == DT_SPARC_REGISTER))
			/* this is so x86 can display a sparc binary */
			return (MSG_ORIG(MSG_DYN_REGISTER));
		else if (tag == DT_DEPRECATED_SPARC_REGISTER)
			return (MSG_ORIG(MSG_DYN_REGISTER));
		else
			return (conv_invalid_val(string, CONV_INV_STRSIZE,
			    tag, fmt_flags));
	}
}

#define	BINDTSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
		MSG_BND_NEEDED_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_BND_REFER_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_BND_FILTER_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		CONV_INV_STRSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

const char *
conv_bnd_type(uint_t flags)
{
	static char	string[BINDTSZ];
	static Val_desc vda[] = {
		{ BND_NEEDED,		MSG_ORIG(MSG_BND_NEEDED) },
		{ BND_REFER,		MSG_ORIG(MSG_BND_REFER) },
		{ BND_FILTER,		MSG_ORIG(MSG_BND_FILTER) },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = { string, sizeof (string), vda };

	if (flags == 0)
		return (MSG_ORIG(MSG_STR_EMPTY));

	conv_arg.oflags = conv_arg.rflags = flags;
	(void) conv_expn_field(&conv_arg);

	return ((const char *)string);
}

/*
 * Note, conv_bnd_obj() is called with either:
 *	LML_FLG_OBJADDED (possibly with LML_FLG_OBJREEVAL added), or
 *	LML_FLG_OBJDELETED, or
 *	LML_FLG_ATEXIT.
 */
#define	BINDOSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
		MSG_BND_ADDED_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_BND_REEVAL_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		CONV_INV_STRSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

const char *
conv_bnd_obj(uint_t flags)
{
	static char	string[BINDOSZ];
	static Val_desc vda[] = {
		{ LML_FLG_OBJADDED,	MSG_ORIG(MSG_BND_ADDED) },
		{ LML_FLG_OBJREEVAL,	MSG_ORIG(MSG_BND_REEVAL) },
		{ LML_FLG_OBJDELETED,	MSG_ORIG(MSG_BND_DELETED) },
		{ LML_FLG_ATEXIT,	MSG_ORIG(MSG_BND_ATEXIT) },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = { string, sizeof (string), vda };

	if ((flags & (LML_FLG_OBJADDED | LML_FLG_OBJREEVAL |
	    LML_FLG_OBJDELETED | LML_FLG_ATEXIT)) == 0)
		return (MSG_ORIG(MSG_BND_REVISIT));

	/*
	 * Note, we're not worried about unknown flags for this family, only
	 * the selected flags are of interest, so we leave conv_arg.rflags
	 * set to 0.
	 */
	conv_arg.oflags = flags;
	(void) conv_expn_field(&conv_arg);

	return ((const char *)string);
}
