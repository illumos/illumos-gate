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

/*
 * String conversion routine for .dynamic tag entries.
 */
#include	<stdio.h>
#include	<string.h>
#include	<sys/elf_SPARC.h>
#include	"rtld.h"
#include	"_conv.h"
#include	"dynamic_msg.h"



/* Instantiate a local copy of conv_map2str() from _conv.h */
DEFINE_conv_map2str



#define	POSSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
		MSG_DFP_LAZYLOAD_ALT_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DFP_GROUPPERM_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_dyn_posflag1_buf_t is large enough:
 *
 * POSSZ is the real minimum size of the buffer required by conv_dyn_posflag1().
 * However, Conv_dyn_posflag1_buf_t uses CONV_DYN_POSFLAG1_BUFSIZE to set the
 * buffer size. We do things this way because the definition of POSSZ uses
 * information that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_DYN_POSFLAG1_BUFSIZE != POSSZ) && !defined(__lint)
#define	REPORT_BUFSIZE POSSZ
#include "report_bufsize.h"
#error "CONV_DYN_POSFLAG1_BUFSIZE does not match POSSZ"
#endif

const char *
conv_dyn_posflag1(Xword flags, Conv_fmt_flags_t fmt_flags,
    Conv_dyn_posflag1_buf_t *dyn_posflag1_buf)
{
	static Val_desc vda[] = {
		{ DF_P1_LAZYLOAD,	MSG_ORIG(MSG_DFP_LAZYLOAD) },
		{ DF_P1_GROUPPERM,	MSG_ORIG(MSG_DFP_GROUPPERM) },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (dyn_posflag1_buf->buf), vda };
	static Val_desc vda_alt[] = {
		{ DF_P1_LAZYLOAD,	MSG_ORIG(MSG_DFP_LAZYLOAD_ALT) },
		{ DF_P1_GROUPPERM,	MSG_ORIG(MSG_DFP_GROUPPERM) },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg_alt = {
	    NULL, sizeof (dyn_posflag1_buf->buf), vda_alt, NULL, 0, 0,
	    MSG_ORIG(MSG_STR_EMPTY), NULL, MSG_ORIG(MSG_STR_EMPTY) };

	CONV_EXPN_FIELD_ARG *arg;

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	arg = (CONV_TYPE_FMT_ALT(fmt_flags) == CONV_FMT_ALT_DUMP) ?
	    &conv_arg_alt : &conv_arg;
	arg->buf = dyn_posflag1_buf->buf;
	arg->oflags = arg->rflags = flags;
	(void) conv_expn_field(arg, fmt_flags);

	return ((const char *)dyn_posflag1_buf);
}

#define	FLAGSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
		MSG_DF_ORIGIN_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF_SYMBOLIC_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF_TEXTREL_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF_BIND_NOW_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF_STATIC_TLS_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_dyn_flag_buf_t is large enough:
 *
 * FLAGSZ is the real minimum size of the buffer required by conv_dyn_flag().
 * However, Conv_dyn_flag_buf_t uses CONV_DYN_FLAG_BUFSIZE to set the
 * buffer size. We do things this way because the definition of FLAGSZ uses
 * information that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_DYN_FLAG_BUFSIZE != FLAGSZ) && !defined(__lint)
#define	REPORT_BUFSIZE FLAGSZ
#include "report_bufsize.h"
#error "CONV_DYN_FLAG_BUFSIZE does not match FLAGSZ"
#endif
const char *
conv_dyn_flag(Xword flags, Conv_fmt_flags_t fmt_flags,
    Conv_dyn_flag_buf_t *dyn_flag_buf)
{
	static Val_desc vda[] = {
		{ DF_ORIGIN,		MSG_ORIG(MSG_DF_ORIGIN) },
		{ DF_SYMBOLIC,		MSG_ORIG(MSG_DF_SYMBOLIC) },
		{ DF_TEXTREL,		MSG_ORIG(MSG_DF_TEXTREL) },
		{ DF_BIND_NOW,		MSG_ORIG(MSG_DF_BIND_NOW) },
		{ DF_STATIC_TLS,	MSG_ORIG(MSG_DF_STATIC_TLS) },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (dyn_flag_buf->buf), vda };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	conv_arg.buf = dyn_flag_buf->buf;
	conv_arg.oflags = conv_arg.rflags = flags;
	if (CONV_TYPE_FMT_ALT(fmt_flags) == CONV_FMT_ALT_DUMP) {
		conv_arg.prefix = conv_arg.suffix = MSG_ORIG(MSG_STR_EMPTY);
	} else {
		conv_arg.prefix = conv_arg.suffix = NULL;
	}
	(void) conv_expn_field(&conv_arg, fmt_flags);

	return ((const char *)dyn_flag_buf->buf);
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
		MSG_DF1_NOHDR_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF1_NORELOC_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF1_SYMINTPOSE_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DF1_GLOBAUDIT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_dyn_flag1_buf_t is large enough:
 *
 * FLAG1SZ is the real minimum size of the buffer required by conv_dyn_flag1().
 * However, Conv_dyn_flag1_buf_t uses CONV_DYN_FLAG1_BUFSIZE to set the
 * buffer size. We do things this way because the definition of FLAG1SZ uses
 * information that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_DYN_FLAG1_BUFSIZE != FLAG1SZ) && !defined(__lint)
#define	REPORT_BUFSIZE FLAG1SZ
#include "report_bufsize.h"
#error "CONV_DYN_FLAG1_BUFSIZE does not match FLAG1SZ"
#endif

const char *
conv_dyn_flag1(Xword flags, Conv_fmt_flags_t fmt_flags,
    Conv_dyn_flag1_buf_t *dyn_flag1_buf)
{
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
		{ DF_1_DISPRELDNE,	MSG_ORIG(MSG_DF1_DISPRELDNE) },
		{ DF_1_DISPRELPND,	MSG_ORIG(MSG_DF1_DISPRELPND) },
		{ DF_1_NODIRECT,	MSG_ORIG(MSG_DF1_NODIRECT) },
		{ DF_1_IGNMULDEF,	MSG_ORIG(MSG_DF1_IGNMULDEF) },
		{ DF_1_NOKSYMS,		MSG_ORIG(MSG_DF1_NOKSYMS) },
		{ DF_1_NOHDR,		MSG_ORIG(MSG_DF1_NOHDR) },
		{ DF_1_EDITED,		MSG_ORIG(MSG_DF1_EDITED) },
		{ DF_1_NORELOC,		MSG_ORIG(MSG_DF1_NORELOC) },
		{ DF_1_SYMINTPOSE,	MSG_ORIG(MSG_DF1_SYMINTPOSE) },
		{ DF_1_GLOBAUDIT,	MSG_ORIG(MSG_DF1_GLOBAUDIT) },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (dyn_flag1_buf->buf), vda };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	conv_arg.oflags = conv_arg.rflags = flags;
	conv_arg.buf = dyn_flag1_buf->buf;
	(void) conv_expn_field(&conv_arg, fmt_flags);

	return ((const char *)dyn_flag1_buf->buf);
}

#define	FEATSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
		MSG_DTF_PARINIT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_DTF_CONFEXP_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_dyn_feature1_buf_t is large enough:
 *
 * FEATSZ is the real min size of the buffer required by conv_dyn_feature1().
 * However, Conv_dyn_feature1_buf_t uses CONV_DYN_FEATURE1_BUFSIZE to set the
 * buffer size. We do things this way because the definition of FEATSZ uses
 * information that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_DYN_FEATURE1_BUFSIZE != FEATSZ) && !defined(__lint)
#define	REPORT_BUFSIZE FEATSZ
#include "report_bufsize.h"
#error "CONV_DYN_FEATURE1_BUFSIZE does not match FEATSZ"
#endif

const char *
conv_dyn_feature1(Xword flags, Conv_fmt_flags_t fmt_flags,
    Conv_dyn_feature1_buf_t *dyn_feature1_buf)
{
	static Val_desc vda[] = {
		{ DTF_1_PARINIT,	MSG_ORIG(MSG_DTF_PARINIT) },
		{ DTF_1_CONFEXP,	MSG_ORIG(MSG_DTF_CONFEXP) },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (dyn_feature1_buf->buf), vda };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	conv_arg.buf = dyn_feature1_buf->buf;
	conv_arg.oflags = conv_arg.rflags = flags;
	if (CONV_TYPE_FMT_ALT(fmt_flags) == CONV_FMT_ALT_DUMP) {
		conv_arg.prefix = conv_arg.suffix = MSG_ORIG(MSG_STR_EMPTY);
	} else {
		conv_arg.prefix = conv_arg.suffix = NULL;
	}
	(void) conv_expn_field(&conv_arg, fmt_flags);

	return ((const char *)dyn_feature1_buf->buf);
}

const char *
conv_dyn_tag(Xword tag, Half mach, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	/*
	 * Dynamic tag values are sparse, cover a wide range, and have
	 * holes. To handle this efficiently, we fall through a series
	 * of tests below, in increasing tag order, returning at the first
	 * match.
	 *
	 * If we fall all the way to the end, the tag is unknown,
	 * and its numeric value is printed.
	 */

	/*
	 * Most of the tag values are clustered in contiguous ranges.
	 * Each contiguous range of defined values is handled with
	 * an array that contains the message index corresponding to
	 * each value in that range. The DYN_RANGE macro checks the
	 * tag value against range of values starting at _start_tag.
	 * If there is a match, the index of the appropriate name is
	 * pulled from _array and returned to the caller.
	 */
#define	DYN_RANGE(_start_tag, _array) \
	if ((tag >= _start_tag) && (tag < (_start_tag + ARRAY_NELTS(_array)))) \
		return (MSG_ORIG(_array[tag - _start_tag]));


	/*
	 * Generic dynamic tags:
	 *	- Note hole between DT_FLAGS and DT_PREINIT_ARRAY
	 *	- The first range has alternative names for dump,
	 *	  requiring a second array.
	 */
	static const Msg	tags_null[] = {
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
		MSG_DYN_FLAGS
	};
	static const Msg	tags_null_alt[] = {
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
		MSG_DYN_FLAGS
	};
	static const Msg	tags_preinit_array[] = {
		MSG_DYN_PREINIT_ARRAY,	MSG_DYN_PREINIT_ARRAYSZ
	};

	/*
	 * SUNW: DT_LOOS -> DT_HIOS range. Note hole between DT_SUNW_TLSSORTSZ
	 * and DT_SUNW_STRPAD. We handle DT_SUNW_STRPAD as a single value below.
	 */
	static const Msg	tags_sunw_auxiliary[] = {
		MSG_DYN_SUNW_AUXILIARY,	MSG_DYN_SUNW_RTLDINF,
		MSG_DYN_SUNW_FILTER,	MSG_DYN_SUNW_CAP,
		MSG_DYN_SUNW_SYMTAB,	MSG_DYN_SUNW_SYMSZ,
		MSG_DYN_SUNW_SORTENT,	MSG_DYN_SUNW_SYMSORT,
		MSG_DYN_SUNW_SYMSORTSZ,	MSG_DYN_SUNW_TLSSORT,
		MSG_DYN_SUNW_TLSSORTSZ
	};

	/*
	 * SUNW: DT_VALRNGLO - DT_VALRNGHI range.
	 */
	static const Msg	tags_checksum[] = {
		MSG_DYN_CHECKSUM,	MSG_DYN_PLTPADSZ,
		MSG_DYN_MOVEENT,	MSG_DYN_MOVESZ,
		MSG_DYN_FEATURE_1,	MSG_DYN_POSFLAG_1,
		MSG_DYN_SYMINSZ,	MSG_DYN_SYMINENT
	};

	/*
	 * SUNW: DT_ADDRRNGLO - DT_ADDRRNGHI range.
	 */
	static const Msg	tags_config[] = {
		MSG_DYN_CONFIG,		MSG_DYN_DEPAUDIT,
		MSG_DYN_AUDIT,		MSG_DYN_PLTPAD,
		MSG_DYN_MOVETAB,	MSG_DYN_SYMINFO
	};

	/*
	 * SUNW: generic range. Note hole between DT_VERSYM and DT_RELACOUNT.
	 * We handle DT_VERSYM as a single value below.
	 */
	static const Msg	tags_relacount[] = {
		MSG_DYN_RELACOUNT,	MSG_DYN_RELCOUNT,
		MSG_DYN_FLAGS_1,	MSG_DYN_VERDEF,
		MSG_DYN_VERDEFNUM,	MSG_DYN_VERNEED,
		MSG_DYN_VERNEEDNUM
	};

	/*
	 * DT_LOPROC - DT_HIPROC range.
	 */
	static const Msg	tags_auxiliary[] = {
		MSG_DYN_AUXILIARY,	MSG_DYN_USED,
		MSG_DYN_FILTER
	};




	if (tag <= DT_FLAGS) {
		/* use 'dump' style? */
		if (CONV_TYPE_FMT_ALT(fmt_flags) == CONV_FMT_ALT_DUMP)
			return (conv_map2str(inv_buf, tag, fmt_flags,
			    ARRAY_NELTS(tags_null_alt), tags_null_alt));
		/* Standard style */
		return (conv_map2str(inv_buf, tag, fmt_flags,
		    ARRAY_NELTS(tags_null), tags_null));
	}
	DYN_RANGE(DT_PREINIT_ARRAY, tags_preinit_array);
	DYN_RANGE(DT_SUNW_AUXILIARY, tags_sunw_auxiliary);
	if (tag == DT_SUNW_STRPAD)
		return (MSG_ORIG(MSG_DYN_SUNW_STRPAD));
	DYN_RANGE(DT_CHECKSUM, tags_checksum);
	DYN_RANGE(DT_CONFIG, tags_config);
	if (tag == DT_VERSYM)
		return (MSG_ORIG(MSG_DYN_VERSYM));
	DYN_RANGE(DT_RELACOUNT, tags_relacount);
	DYN_RANGE(DT_AUXILIARY, tags_auxiliary);

	/*
	 * SUNW: machine specific range.
	 */
	if (((mach == EM_SPARC) || (mach == EM_SPARCV9) ||
	    (mach == EM_SPARC32PLUS)) && (tag == DT_SPARC_REGISTER))
		/* this is so x86 can display a sparc binary */
		return (MSG_ORIG(MSG_DYN_REGISTER));

	if (tag == DT_DEPRECATED_SPARC_REGISTER)
		return (MSG_ORIG(MSG_DYN_REGISTER));

	/* Unknown item */
	return (conv_invalid_val(inv_buf, tag, fmt_flags));

#undef DYN_RANGE
}

#define	BINDTSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
		MSG_BND_NEEDED_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_BND_REFER_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_BND_FILTER_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_bnd_type_buf_t is large enough:
 *
 * BINDTSZ is the real minimum size of the buffer required by conv_bnd_type().
 * However, Conv_bnd_type_buf_t uses CONV_BND_TYPE_BUFSIZE to set the
 * buffer size. We do things this way because the definition of BINDTSZ uses
 * information that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_BND_TYPE_BUFSIZE != BINDTSZ) && !defined(__lint)
#define	REPORT_BUFSIZE BINDTSZ
#include "report_bufsize.h"
#error "CONV_BND_TYPE_BUFSIZE does not match BINDTSZ"
#endif

const char *
conv_bnd_type(uint_t flags, Conv_bnd_type_buf_t *bnd_type_buf)
{
	static Val_desc vda[] = {
		{ BND_NEEDED,		MSG_ORIG(MSG_BND_NEEDED) },
		{ BND_REFER,		MSG_ORIG(MSG_BND_REFER) },
		{ BND_FILTER,		MSG_ORIG(MSG_BND_FILTER) },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (bnd_type_buf->buf), vda };

	if (flags == 0)
		return (MSG_ORIG(MSG_STR_EMPTY));

	conv_arg.buf = bnd_type_buf->buf;
	conv_arg.oflags = conv_arg.rflags = flags;
	(void) conv_expn_field(&conv_arg, 0);

	return ((const char *)bnd_type_buf->buf);
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
		CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_bnd_obj_buf_t is large enough:
 *
 * BINDOSZ is the real minimum size of the buffer required by conv_bnd_obj().
 * However, Conv_bnd_obj_buf_t uses CONV_BND_OBJ_BUFSIZE to set the
 * buffer size. We do things this way because the definition of BINDOSZ uses
 * information that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_BND_OBJ_BUFSIZE != BINDOSZ) && !defined(__lint)
#define	REPORT_BUFSIZE BINDOSZ
#include "report_bufsize.h"
#error "CONV_BND_OBJ_BUFSIZE does not match BINDOSZ"
#endif

const char *
conv_bnd_obj(uint_t flags, Conv_bnd_obj_buf_t *bnd_obj_buf)
{
	static Val_desc vda[] = {
		{ LML_FLG_OBJADDED,	MSG_ORIG(MSG_BND_ADDED) },
		{ LML_FLG_OBJREEVAL,	MSG_ORIG(MSG_BND_REEVAL) },
		{ LML_FLG_OBJDELETED,	MSG_ORIG(MSG_BND_DELETED) },
		{ LML_FLG_ATEXIT,	MSG_ORIG(MSG_BND_ATEXIT) },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (bnd_obj_buf->buf), vda };

	if ((flags & (LML_FLG_OBJADDED | LML_FLG_OBJREEVAL |
	    LML_FLG_OBJDELETED | LML_FLG_ATEXIT)) == 0)
		return (MSG_ORIG(MSG_BND_REVISIT));

	/*
	 * Note, we're not worried about unknown flags for this family, only
	 * the selected flags are of interest, so we leave conv_arg.rflags
	 * set to 0.
	 */
	conv_arg.buf = bnd_obj_buf->buf;
	conv_arg.oflags = flags;
	(void) conv_expn_field(&conv_arg, 0);

	return ((const char *)bnd_obj_buf->buf);
}
